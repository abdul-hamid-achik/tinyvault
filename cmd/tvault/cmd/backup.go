package cmd

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var backupCmd = &cobra.Command{
	Use:   "backup [path]",
	Short: "Write a consistent, encrypted snapshot of the vault",
	Long: `Write a consistent snapshot of the vault database.

The snapshot is taken inside a read transaction, so it is never a torn copy
even if another tvault writes at the same moment, and it is verified before it
is kept. Secret payloads and key material stay encrypted — no unlock, and no
passphrase, is needed — while the database's operational metadata (project and
key names, audit entries) remains readable.

With a path, writes one snapshot there (gzip-compressed when the path ends in
.gz). Without one, writes a compressed, timestamped vault-YYYYMMDD-HHMMSS.db.gz
into --dir (or backup.dir in config.yaml) and deletes the oldest snapshots
beyond --keep. The audit log dominates a vault's size and compresses ~10x. --immutable sets the macOS/BSD user
immutable flag so an accidental 'rm -rf' cannot delete a snapshot (clear it
with 'chflags nouchg <file>'; tvault clears it itself when rotating).

When backup.dir is configured, destructive commands (delete, projects delete,
restore, and the MCP delete tools) take a snapshot first and refuse to run if
it fails.

Examples:
  tvault backup ~/backups/vault.db.bak
  tvault backup --dir ~/Backups/tvault --keep 30 --immutable
  tvault backup                     # uses backup.dir / keep / immutable from config.yaml`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBackup,
}

var (
	restoreYes      bool
	backupDirFlag   string
	backupKeepFlag  int
	backupImmutable bool
)

var restoreCmd = &cobra.Command{
	Use:   "restore <path>",
	Short: "Restore vault from a backup",
	Long: `Restore the vault database from a backup file.

Accepts a plain or gzip-compressed snapshot. The backup is verified before
anything is touched, the current vault is first
saved as a snapshot (into backup.dir when configured, else next to vault.db as
vault.db.pre-restore-<time>), and the database is then replaced atomically.

Examples:
  tvault restore ~/backups/vault.db.bak`,
	Args: cobra.ExactArgs(1),
	RunE: runRestore,
}

func init() {
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(restoreCmd)
	backupCmd.Flags().StringVar(&backupDirFlag, "dir", "", "Directory for timestamped, rotated snapshots (default: backup.dir in config.yaml)")
	backupCmd.Flags().IntVar(&backupKeepFlag, "keep", 0, "Number of snapshots to keep in --dir (default: backup.keep, else 30)")
	backupCmd.Flags().BoolVar(&backupImmutable, "immutable", false, "Mark snapshots immutable (macOS/BSD user flag) so rm cannot delete them")
	restoreCmd.Flags().BoolVarP(&restoreYes, "yes", "y", false, "Skip confirmation prompt")
}

// defaultBackupKeep is how many rotated snapshots survive when neither --keep
// nor backup.keep says otherwise.
const defaultBackupKeep = 30

// snapshotPrefix names rotated snapshots; rotation only ever touches files
// matching snapshotPrefix + "*" + snapshotSuffix in the backup directory.
const (
	snapshotPrefix = "vault-"
	snapshotSuffix = ".db"
)

// backupSettings is the effective backup configuration: flags over config.
type backupSettings struct {
	dir       string
	keep      int
	immutable bool
}

func resolveBackupSettings(cfg Config) backupSettings {
	s := backupSettings{
		dir:       expandHome(strings.TrimSpace(cfg.Backup.Dir)),
		keep:      cfg.Backup.Keep,
		immutable: cfg.Backup.Immutable,
	}
	if d := strings.TrimSpace(backupDirFlag); d != "" {
		s.dir = expandHome(d)
	}
	if backupKeepFlag > 0 {
		s.keep = backupKeepFlag
	}
	if backupImmutable {
		s.immutable = true
	}
	if s.keep <= 0 {
		s.keep = defaultBackupKeep
	}
	return s
}

func runBackup(_ *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath(), err)
	}
	settings := resolveBackupSettings(cfg)
	if len(args) == 0 && settings.dir == "" {
		return errors.New("give a destination path, pass --dir, or set backup.dir in config.yaml")
	}

	v, err := openVaultForSnapshot()
	if err != nil {
		return err
	}
	defer v.Close()

	if len(args) == 1 {
		dst := expandHome(args[0])
		n, serr := snapshotTo(v, dst)
		if serr != nil {
			return fmt.Errorf("backup failed: %w", serr)
		}
		if settings.immutable {
			if ierr := setImmutable(dst, true); ierr != nil {
				Warning("snapshot written but not marked immutable: %v", ierr)
			}
		}
		Success("Vault snapshot (%s) written to %s", humanBytes(n), dst)
		return nil
	}

	path, n, err := rotatedSnapshot(v, settings, "")
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	Success("Vault snapshot (%s) written to %s", humanBytes(n), path)
	return nil
}

// openVaultForSnapshot opens the vault without unlocking it, retrying briefly
// while another tvault holds bbolt's exclusive lock (commands hold it only for
// the duration of one operation, never for a `tvault run` child's lifetime).
func openVaultForSnapshot() (*vault.Vault, error) {
	dir := getVaultDir()
	deadline := time.Now().Add(15 * time.Second)
	for {
		v, err := vault.Open(dir)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, vault.ErrVaultBusy) || time.Now().After(deadline) {
			return nil, wrapVaultOpenErr(dir, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// snapshotTo writes a verified snapshot of v to dst atomically: into a
// private temporary file in the same directory, fsync'd and verified, then
// renamed over dst. A failed or interrupted backup never leaves a truncated
// file at dst. A dst ending in .gz is gzip-compressed after verification
// (the audit log dominates a vault and compresses ~10x).
func snapshotTo(v *vault.Vault, dst string) (int64, error) {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tvault-snapshot-*")
	if err != nil {
		return 0, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath) // already renamed away on success
	}()
	if cerr := tmp.Chmod(0o600); cerr != nil {
		return 0, cerr
	}
	n, err := v.Snapshot(tmp)
	if err != nil {
		return n, err
	}
	if err := tmp.Sync(); err != nil {
		return n, err
	}
	if err := tmp.Close(); err != nil {
		return n, err
	}
	if err := store.VerifySnapshot(tmpPath); err != nil {
		return n, err
	}
	final := tmpPath
	if strings.HasSuffix(dst, gzipSuffix) {
		gz, gerr := gzipFile(tmpPath, dir)
		if gerr != nil {
			return n, gerr
		}
		defer func() { _ = os.Remove(gz) }() // gone after a successful rename
		final = gz
	}
	if err := os.Rename(final, dst); err != nil {
		return n, err
	}
	return n, nil
}

const gzipSuffix = ".gz"

// gzipFile compresses src into a new private temporary file in dir and
// returns its path.
func gzipFile(src, dir string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp(dir, ".tvault-snapshot-gz-*")
	if err != nil {
		return "", err
	}
	path := out.Name()
	fail := func(e error) (string, error) {
		_ = out.Close()
		_ = os.Remove(path)
		return "", e
	}
	if err := out.Chmod(0o600); err != nil {
		return fail(err)
	}
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		return fail(err)
	}
	if err := zw.Close(); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// rotatedSnapshot writes vault-<timestamp>[-<reason>].db into the backup
// directory, optionally marks it immutable, and prunes the oldest snapshots
// beyond keep. Warnings go to stderr: under `tvault mcp` stdout is the
// protocol stream.
func rotatedSnapshot(v *vault.Vault, s backupSettings, reason string) (string, int64, error) {
	name := snapshotPrefix + time.Now().Format("20060102-150405.000")
	if reason != "" {
		name += "-" + reason
	}
	path := filepath.Join(s.dir, name+snapshotSuffix+gzipSuffix)
	n, err := snapshotTo(v, path)
	if err != nil {
		return "", n, err
	}
	if s.immutable {
		if ierr := setImmutable(path, true); ierr != nil {
			fmt.Fprintf(os.Stderr, "tvault: warning: snapshot written but not marked immutable: %v\n", ierr)
		}
	}
	if perr := pruneSnapshots(s.dir, s.keep); perr != nil {
		fmt.Fprintf(os.Stderr, "tvault: warning: snapshot written, but pruning old snapshots failed: %v\n", perr)
	}
	return path, n, nil
}

// listSnapshots returns the rotated snapshots in dir, oldest first. The
// timestamp in the name sorts chronologically.
func listSnapshots(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(name, snapshotPrefix) &&
			(strings.HasSuffix(name, snapshotSuffix) || strings.HasSuffix(name, snapshotSuffix+gzipSuffix)) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	sort.Strings(out)
	return out, nil
}

// pruneSnapshots deletes the oldest rotated snapshots beyond keep, clearing
// the immutable flag tvault set on them first. It never touches files that do
// not match the rotated-snapshot naming scheme.
func pruneSnapshots(dir string, keep int) error {
	snaps, err := listSnapshots(dir)
	if err != nil {
		return err
	}
	if len(snaps) <= keep {
		return nil
	}
	var errs []error
	for _, p := range snaps[:len(snaps)-keep] {
		if err := setImmutable(p, false); err != nil && !errors.Is(err, errImmutableUnsupported) {
			errs = append(errs, err)
			continue
		}
		if err := os.Remove(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// snapshotBeforeDestructive takes a rotated snapshot before an irreversible
// operation when backup.dir is configured. It returns nil (and does nothing)
// when backups are not configured. A configured backup that fails is an
// error: the caller must not proceed with the destructive operation.
func snapshotBeforeDestructive(v *vault.Vault, reason string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath(), err)
	}
	if strings.TrimSpace(cfg.Backup.Dir) == "" {
		return nil
	}
	s := resolveBackupSettings(cfg)
	path, _, err := rotatedSnapshot(v, s, reason)
	if err != nil {
		return fmt.Errorf("safety snapshot before %s failed (nothing was changed; fix backup.dir or remove it from %s): %w",
			reason, configPath(), err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "tvault: safety snapshot: %s\n", path)
	}
	return nil
}

func runRestore(_ *cobra.Command, args []string) error {
	src := expandHome(args[0])
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("backup file not found: %s", src)
	}
	dir := getVaultDir()
	dst := filepath.Join(dir, "vault.db")

	if !restoreYes {
		Warning("This will replace the current vault database (a snapshot of it is kept first).")
		if !PromptConfirm("Restore from backup?") {
			Info("Canceled")
			return nil
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Stage the backup next to vault.db so the final rename is atomic on the
	// same filesystem, and verify the staged copy too.
	staged, err := os.CreateTemp(dir, ".tvault-restore-*")
	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	stagedPath := staged.Name()
	_ = staged.Close()
	defer func() { _ = os.Remove(stagedPath) }() // gone after a successful rename
	if err = stageBackup(src, stagedPath); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	// Refuse anything that is not a vault before the current one is touched.
	if err = store.VerifySnapshot(stagedPath); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	// Keep the current vault first, holding its lock through the swap so no
	// other tvault writes to the old file in between.
	if _, statErr := os.Stat(dst); statErr == nil {
		v, oerr := openVaultForSnapshot()
		if oerr != nil {
			return fmt.Errorf("restore failed: %w", oerr)
		}
		defer v.Close()
		cfg, cerr := loadConfig()
		if cerr != nil {
			return fmt.Errorf("read %s: %w", configPath(), cerr)
		}
		var saved string
		if strings.TrimSpace(cfg.Backup.Dir) != "" {
			saved, _, err = rotatedSnapshot(v, resolveBackupSettings(cfg), "pre-restore")
		} else {
			saved = dst + ".pre-restore-" + time.Now().Format("20060102-150405")
			_, err = snapshotTo(v, saved)
		}
		if err != nil {
			return fmt.Errorf("restore aborted: could not save the current vault first: %w", err)
		}
		Info("Current vault saved to %s", saved)
	}

	if err := os.Rename(stagedPath, dst); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	Success("Vault restored from %s", src)
	return nil
}

// humanBytes renders a byte count for status lines.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// stageBackup copies src to dst, transparently decompressing a gzip snapshot
// (detected by its magic bytes, not its name).
func stageBackup(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	br := bufio.NewReader(in)
	var r io.Reader = br
	if magic, perr := br.Peek(2); perr == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, zerr := gzip.NewReader(br)
		if zerr != nil {
			return zerr
		}
		defer zr.Close()
		r = zr
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
