// Package logging builds the structured loggers used by long-running tvault
// surfaces (today the agent). It resolves where logs live, enforces
// secrets-adjacent file permissions, and caps file growth so an agent left
// running for months cannot fill a disk.
//
// # Never log a secret value
//
// Log records describe *what happened*, never *what was read*. Key names and
// project names are already recorded by the audit log, so they are fair game;
// decrypted values, passphrases, KEK/DEK bytes, identity private halves and
// capability tokens are not, and this package deliberately offers no helper
// that would make logging one convenient. Callers must keep that discipline —
// there is no redaction pass here, and a redaction pass would be a safety net
// rather than a control.
package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"charm.land/log/v2"
)

const (
	// dirPerm keeps the log directory owner-only: log records name projects and
	// keys, which is metadata worth protecting even though no value is written.
	dirPerm = 0o700
	// filePerm matches the vault's own 0600 posture.
	filePerm = 0o600

	// defaultMaxBytes caps a single log file. On overflow the file is rotated
	// to "<name>.1" (one generation, overwritten), so disk use is bounded at
	// roughly twice this figure per logger.
	defaultMaxBytes = 5 << 20 // 5 MiB
)

// Options configures a logger. The zero value is valid: it writes to the XDG
// state directory at info level with no stderr copy.
type Options struct {
	// Dir overrides the log directory. Empty means StateDir().
	Dir string
	// Level is one of debug, info, warn, error. Empty means info.
	Level string
	// Stderr additionally mirrors records to stderr. Useful for a foreground
	// `tvault agent start`, pointless under launchd/systemd (which capture
	// stderr into their own files and would double-write).
	Stderr bool
	// MaxBytes overrides the per-file size cap. Zero means defaultMaxBytes.
	MaxBytes int64
}

// StateDir returns the directory holding tvault's logs and other state that is
// neither configuration nor cached data.
//
// It follows the XDG Base Directory spec, under which logs belong in
// $XDG_STATE_HOME (not $XDG_CACHE_HOME, since logs must survive a cache purge,
// and not $XDG_CONFIG_HOME, since they are not user-edited configuration).
// Falls back to ~/.local/state/tvault when XDG_STATE_HOME is unset.
func StateDir() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); dir != "" {
		return filepath.Join(dir, "tvault")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// No home is pathological; fall back to the working directory rather
		// than writing to an absolute path the caller never chose.
		return ".tvault-state"
	}
	return filepath.Join(home, ".local", "state", "tvault")
}

// ParseLevel maps a config/flag string onto a log level. An empty string means
// info; anything unrecognized is an error so a typo in config.yaml surfaces
// instead of silently downgrading what gets recorded.
func ParseLevel(s string) (log.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return log.InfoLevel, nil
	case "debug":
		return log.DebugLevel, nil
	case "info":
		return log.InfoLevel, nil
	case "warn", "warning":
		return log.WarnLevel, nil
	case "error":
		return log.ErrorLevel, nil
	default:
		return log.InfoLevel, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
	}
}

// Path returns the file a logger with the given name and options writes to.
func Path(name string, opts Options) string {
	dir := opts.Dir
	if strings.TrimSpace(dir) == "" {
		dir = StateDir()
	}
	return filepath.Join(dir, name+".log")
}

// New opens the log file for name (e.g. "agent") and returns a logger plus a
// closer the caller must invoke on every exit path.
//
// The returned logger writes logfmt records with timestamps. Callers that also
// want a human-facing message on the terminal should print that separately
// rather than raising the log level.
func New(name string, opts Options) (*log.Logger, io.Closer, error) {
	level, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, nil, err
	}

	path := Path(name, opts)
	if mkErr := os.MkdirAll(filepath.Dir(path), dirPerm); mkErr != nil {
		return nil, nil, fmt.Errorf("create log directory %s: %w", filepath.Dir(path), mkErr)
	}

	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if rotErr := rotateIfLarge(path, maxBytes); rotErr != nil {
		return nil, nil, rotErr
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, filePerm)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %s: %w", path, err)
	}
	// An existing file may predate a umask change or have been created by an
	// older build; tighten it rather than trusting how it arrived.
	if err := f.Chmod(filePerm); err != nil && !errors.Is(err, os.ErrPermission) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("tighten log file permissions on %s: %w", path, err)
	}

	var w io.Writer = f
	closer := io.Closer(f)
	if opts.Stderr {
		w = io.MultiWriter(f, os.Stderr)
	}

	logger := log.NewWithOptions(w, log.Options{
		Level:           level,
		ReportTimestamp: true,
		Formatter:       log.LogfmtFormatter,
		Prefix:          name,
	})
	return logger, closer, nil
}

// rotateIfLarge moves path to path+".1" once it exceeds maxBytes, keeping a
// single previous generation. A missing file is not an error.
func rotateIfLarge(path string, maxBytes int64) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat log file %s: %w", path, err)
	}
	if info.Size() < maxBytes {
		return nil
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return fmt.Errorf("rotate log file %s: %w", path, err)
	}
	return nil
}

// Reset deletes the log file and its rotated generation for name. It is what
// backs an explicit "clear the logs" action; a missing file is not an error,
// so calling it on a fresh machine succeeds.
func Reset(name string, opts Options) error {
	path := Path(name, opts)
	for _, p := range []string{path, path + ".1"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}
