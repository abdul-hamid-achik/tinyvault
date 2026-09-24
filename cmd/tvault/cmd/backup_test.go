package cmd

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	ivault "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func resetBackupFlags(t *testing.T) {
	t.Helper()
	d, k, i, y := backupDirFlag, backupKeepFlag, backupImmutable, restoreYes
	t.Cleanup(func() { backupDirFlag, backupKeepFlag, backupImmutable, restoreYes = d, k, i, y })
	backupDirFlag, backupKeepFlag, backupImmutable, restoreYes = "", 0, false, false
}

func writeBackupConfig(t *testing.T, vaultPath, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(vaultPath, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// clearImmutableOnCleanup lets t.TempDir remove snapshots a test made immutable.
func clearImmutableOnCleanup(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() {
		snaps, _ := listSnapshots(dir)
		for _, p := range snaps {
			_ = setImmutable(p, false)
		}
	})
}

func TestSnapshotRoundTripsAndUnlocks(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "API_KEY", "sk-123")

	dst := filepath.Join(t.TempDir(), "snap.db")
	captureStdout(t, func() {
		if err := runBackup(nil, []string{dst}); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})
	if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot missing or not 0600: %v %v", info, err)
	}
	if err := store.VerifySnapshot(dst); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The snapshot is a complete vault: open it as one and read the secret.
	restored := t.TempDir()
	if err := stageBackup(dst, filepath.Join(restored, "vault.db")); err != nil {
		t.Fatal(err)
	}
	v, err := ivault.Open(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Unlock("test-passphrase"); err != nil {
		t.Fatalf("unlock snapshot: %v", err)
	}
	got, err := v.GetSecret("default", "API_KEY")
	if err != nil || got != "sk-123" {
		t.Fatalf("secret from snapshot = %q, %v", got, err)
	}
}

func TestVerifySnapshotRejectsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "junk.db")
	if err := os.WriteFile(p, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySnapshot(p); !errors.Is(err, store.ErrInvalidSnapshot) {
		t.Fatalf("VerifySnapshot(garbage) = %v, want ErrInvalidSnapshot", err)
	}
}

func TestRotatedSnapshotsPruneOnlyTheirOwnFiles(t *testing.T) {
	resetBackupFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	dir := t.TempDir()
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A hand-made vault-*.db must survive rotation too: only names rotation
	// itself produces are pruned.
	manual := filepath.Join(dir, "vault-before-migration.db")
	if err := os.WriteFile(manual, []byte("manual"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDirFlag, backupKeepFlag = dir, 2
	for range 4 {
		captureStdout(t, func() {
			if err := runBackup(nil, nil); err != nil {
				t.Fatalf("backup: %v", err)
			}
		})
	}
	snaps, err := listSnapshots(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("kept %d snapshots, want 2: %v", len(snaps), snaps)
	}
	for _, p := range []string{other, manual} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("rotation touched a file it does not own: %v", err)
		}
	}
}

func TestImmutableSnapshotsResistRemovalButRotate(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "freebsd", "netbsd", "openbsd", "dragonfly":
	default:
		t.Skip("user-immutable flag is BSD/macOS only")
	}
	resetBackupFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	dir := t.TempDir()
	clearImmutableOnCleanup(t, dir)
	backupDirFlag, backupKeepFlag, backupImmutable = dir, 1, true

	captureStdout(t, func() {
		if err := runBackup(nil, nil); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})
	snaps, _ := listSnapshots(dir)
	if len(snaps) != 1 {
		t.Fatalf("want 1 snapshot, got %v", snaps)
	}
	if err := os.Remove(snaps[0]); err == nil {
		t.Fatal("an immutable snapshot was removable")
	}
	// Rotation clears the flag on the snapshots it owns and prunes them.
	captureStdout(t, func() {
		if err := runBackup(nil, nil); err != nil {
			t.Fatalf("second backup: %v", err)
		}
	})
	after, _ := listSnapshots(dir)
	if len(after) != 1 || after[0] == snaps[0] {
		t.Fatalf("rotation did not replace the immutable snapshot: before %v after %v", snaps, after)
	}
}

func TestDeleteTakesSafetySnapshotWhenConfigured(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "GONE", "x")
	dir := t.TempDir()
	writeBackupConfig(t, vaultPath, "backup:\n  dir: "+dir+"\n")

	prev := deleteForce
	deleteForce = true
	t.Cleanup(func() { deleteForce = prev })
	captureStdout(t, func() {
		if err := runDelete(nil, []string{"GONE"}); err != nil {
			t.Fatalf("delete: %v", err)
		}
	})
	snaps, _ := listSnapshots(dir)
	if len(snaps) != 1 || !strings.Contains(snaps[0], "pre-delete") {
		t.Fatalf("want one pre-delete snapshot, got %v", snaps)
	}
}

// If the configured backup cannot be written, the destructive command must
// not run: the secret is still there afterwards.
func TestDeleteRefusedWhenSafetySnapshotFails(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "KEEP", "x")
	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeBackupConfig(t, vaultPath, "backup:\n  dir: "+filepath.Join(blocker, "sub")+"\n")

	prev := deleteForce
	deleteForce = true
	t.Cleanup(func() { deleteForce = prev })
	var err error
	captureStdout(t, func() { err = runDelete(nil, []string{"KEEP"}) })
	if err == nil || !strings.Contains(err.Error(), "safety snapshot") {
		t.Fatalf("delete should be refused, got %v", err)
	}
	v := openTestVault(t, vaultPath)
	defer v.Close()
	if got, gerr := v.GetSecret("default", "KEEP"); gerr != nil || got != "x" {
		t.Fatalf("secret changed despite refused delete: %q %v", got, gerr)
	}
}

func TestDeleteWithoutBackupConfigDoesNotSnapshot(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "GONE", "x")
	prev := deleteForce
	deleteForce = true
	t.Cleanup(func() { deleteForce = prev })
	captureStdout(t, func() {
		if err := runDelete(nil, []string{"GONE"}); err != nil {
			t.Fatalf("delete: %v", err)
		}
	})
	entries, _ := os.ReadDir(vaultPath)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), snapshotPrefix) {
			t.Fatalf("unexpected snapshot %s without backup.dir", e.Name())
		}
	}
}

func TestRestoreVerifiesSavesCurrentAndSwaps(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "WHICH", "old")
	snap := filepath.Join(t.TempDir(), "snap.db")
	captureStdout(t, func() {
		if err := runBackup(nil, []string{snap}); err != nil {
			t.Fatal(err)
		}
	})
	setVersionsForCLI(t, vaultPath, "WHICH", "new")

	junk := filepath.Join(t.TempDir(), "junk.db")
	if err := os.WriteFile(junk, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreYes = true
	if err := runRestore(nil, []string{junk}); !errors.Is(err, store.ErrInvalidSnapshot) {
		t.Fatalf("restore of garbage = %v, want ErrInvalidSnapshot", err)
	}

	captureStdout(t, func() {
		if err := runRestore(nil, []string{snap}); err != nil {
			t.Fatalf("restore: %v", err)
		}
	})
	v := openTestVault(t, vaultPath)
	got, err := v.GetSecret("default", "WHICH")
	v.Close()
	if err != nil || got != "old" {
		t.Fatalf("after restore WHICH = %q, %v; want old", got, err)
	}
	matches, _ := filepath.Glob(filepath.Join(vaultPath, "vault.db.pre-restore-*"))
	if len(matches) != 1 {
		t.Fatalf("want the pre-restore vault kept, got %v", matches)
	}
	if err := store.VerifySnapshot(matches[0]); err != nil {
		t.Fatalf("pre-restore copy is not a valid vault: %v", err)
	}
}

func TestRotatedSnapshotsAreCompressedAndRestorable(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "WHICH", "old")
	dir := t.TempDir()
	backupDirFlag = dir
	captureStdout(t, func() {
		if err := runBackup(nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	snaps, _ := listSnapshots(dir)
	if len(snaps) != 1 || !strings.HasSuffix(snaps[0], ".db.gz") {
		t.Fatalf("want one .db.gz snapshot, got %v", snaps)
	}
	raw, err := os.ReadFile(snaps[0])
	if err != nil || len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatalf("snapshot is not gzip data (err %v)", err)
	}

	setVersionsForCLI(t, vaultPath, "WHICH", "new")
	restoreYes = true
	captureStdout(t, func() {
		if err := runRestore(nil, []string{snaps[0]}); err != nil {
			t.Fatalf("restore from .gz: %v", err)
		}
	})
	v := openTestVault(t, vaultPath)
	defer v.Close()
	if got, err := v.GetSecret("default", "WHICH"); err != nil || got != "old" {
		t.Fatalf("after restore WHICH = %q, %v; want old", got, err)
	}
}

func TestBackupRejectsNegativeKeep(t *testing.T) {
	resetBackupFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	backupDirFlag, backupKeepFlag = t.TempDir(), -1
	if err := runBackup(nil, nil); err == nil || !strings.Contains(err.Error(), "keep") {
		t.Fatalf("negative --keep: err = %v", err)
	}
}

func TestSSHInjectScriptSkipsInvalidKeys(t *testing.T) {
	var script string
	stderr := captureStderr(t, func() {
		script = buildSSHInjectScript(map[string]string{"GOOD": "v", "BAD;id": "x"})
	})
	if strings.Contains(script, "BAD") || !strings.Contains(script, "export GOOD=v\n") {
		t.Fatalf("script = %q", script)
	}
	if !strings.Contains(string(stderr), `"BAD;id"`) {
		t.Fatalf("stderr = %q", stderr)
	}
}

// A crafted .gz expanding past the cap must be refused before it fills the
// disk, and the staged file must stop at the cap rather than keep copying.
func TestRestoreRefusesExpandingGzip(t *testing.T) {
	resetBackupFlags(t)
	old := maxRestoreBytes
	maxRestoreBytes = 4 * 1024
	t.Cleanup(func() { maxRestoreBytes = old })

	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	if _, err := zw.Write(make([]byte, 64*1024)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	bomb := filepath.Join(t.TempDir(), "bomb.db.gz")
	if err := os.WriteFile(bomb, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "staged.db")
	err := stageBackup(bomb, dst)
	if err == nil || !strings.Contains(err.Error(), "expands past") {
		t.Fatalf("oversized gzip = %v, want a refusal naming the cap", err)
	}
	if info, serr := os.Stat(dst); serr != nil || info.Size() > maxRestoreBytes+1 {
		t.Fatalf("staged file = %d bytes (%v); want it bounded by the cap", info.Size(), serr)
	}
}

// --keep 0 means "use the default" (defaultBackupKeep), not "keep nothing":
// a backup with --keep 0 must not prune existing snapshots.
func TestKeepZeroMeansDefaultNotZero(t *testing.T) {
	resetBackupFlags(t)
	_, restore := setupVaultForCommandTest(t)
	defer restore()
	dir := t.TempDir()
	backupDirFlag, backupKeepFlag = dir, 0
	for range 3 {
		captureStdout(t, func() {
			if err := runBackup(nil, nil); err != nil {
				t.Fatalf("backup: %v", err)
			}
		})
	}
	snaps, _ := listSnapshots(dir)
	if len(snaps) != 3 {
		t.Fatalf("--keep 0 pruned history: %d of 3 snapshots remain", len(snaps))
	}
}

// Two restores in quick succession must save two distinct pre-restore copies:
// fallback names carry milliseconds, so the second never overwrites the first.
func TestRestoreTwiceKeepsBothPreRestoreCopies(t *testing.T) {
	resetBackupFlags(t)
	vaultPath, restore := setupVaultForCommandTest(t)
	defer restore()
	setVersionsForCLI(t, vaultPath, "WHICH", "old")
	snapA := filepath.Join(t.TempDir(), "a.db")
	snapB := filepath.Join(t.TempDir(), "b.db")
	captureStdout(t, func() {
		if err := runBackup(nil, []string{snapA}); err != nil {
			t.Fatalf("backup A: %v", err)
		}
	})
	setVersionsForCLI(t, vaultPath, "WHICH", "mid")
	captureStdout(t, func() {
		if err := runBackup(nil, []string{snapB}); err != nil {
			t.Fatalf("backup B: %v", err)
		}
	})
	setVersionsForCLI(t, vaultPath, "WHICH", "new")
	restoreYes = true
	for _, snap := range []string{snapA, snapB} {
		captureStdout(t, func() {
			if err := runRestore(nil, []string{snap}); err != nil {
				t.Fatalf("restore %s: %v", snap, err)
			}
		})
	}
	matches, _ := filepath.Glob(filepath.Join(vaultPath, "vault.db.pre-restore-*"))
	if len(matches) != 2 {
		t.Fatalf("want 2 distinct pre-restore copies, got %v", matches)
	}
	for _, m := range matches {
		if err := store.VerifySnapshot(m); err != nil {
			t.Fatalf("%s is not a valid vault: %v", m, err)
		}
	}
}
