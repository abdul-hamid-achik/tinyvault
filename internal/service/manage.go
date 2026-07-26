package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// unitPerm is 0600 on the definition. It names a passphrase file path and a
	// vault directory — not secrets, but not worth publishing either, and
	// launchd's default 0644 in ~/Library/LaunchAgents is looser than needed.
	unitPerm = 0o600
	// unitDirPerm matches: the directory may already exist with other contents,
	// in which case MkdirAll leaves its mode alone.
	unitDirPerm = 0o700

	// commandTimeout bounds each launchctl/systemctl invocation. These are
	// local and fast; a hang means something is wrong with the service manager,
	// and blocking a CLI forever is worse than reporting the failure.
	commandTimeout = 20 * time.Second
)

// Write installs the definition at its canonical path, creating the parent
// directory. It returns the path written.
//
// An existing definition is overwritten: install is the way a user picks up a
// changed vault dir, log level, or binary location, so refusing would force a
// manual uninstall for every edit. Callers that must not clobber should check
// Installed first.
func Write(kind Kind, cfg Config) (string, error) {
	body, err := Render(kind, cfg)
	if err != nil {
		return "", err
	}
	path, err := UnitPath(kind)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), unitDirPerm); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), unitPerm); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile does not tighten an existing looser file; do it explicitly.
	if err := os.Chmod(path, unitPerm); err != nil {
		return "", fmt.Errorf("set permissions on %s: %w", path, err)
	}
	return path, nil
}

// Installed reports whether a definition exists on disk, and its path.
func Installed(kind Kind) (bool, string, error) {
	path, err := UnitPath(kind)
	if err != nil {
		return false, "", err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, path, nil
		}
		return false, path, fmt.Errorf("stat %s: %w", path, err)
	}
	return true, path, nil
}

// Remove deletes the definition. A missing file is not an error, so uninstall
// is idempotent and safe in a teardown script.
func Remove(kind Kind) (string, error) {
	path, err := UnitPath(kind)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return path, fmt.Errorf("remove %s: %w", path, err)
	}
	return path, nil
}

// run executes a service-manager command, returning its combined output so the
// caller can surface why the manager refused.
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return trimmed, fmt.Errorf("%s %s timed out after %s", name, strings.Join(args, " "), commandTimeout)
		}
		if trimmed != "" {
			return trimmed, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, trimmed)
		}
		return trimmed, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return trimmed, nil
}

// Load registers the definition with the service manager and starts it.
func Load(kind Kind) error {
	path, err := UnitPath(kind)
	if err != nil {
		return err
	}
	switch kind {
	case KindLaunchd:
		// `bootstrap` is the modern replacement for `load`. Bootout first so a
		// re-install picks up an edited plist; a not-loaded service makes bootout
		// fail, which is expected and ignored.
		target := fmt.Sprintf("gui/%d", os.Getuid())
		//nolint:errcheck // bootout fails when nothing is loaded; that is the desired pre-state
		_, _ = run("launchctl", "bootout", target+"/"+LaunchdLabel)
		if _, err := run("launchctl", "bootstrap", target, path); err != nil {
			return err
		}
		return nil
	case KindSystemd:
		if _, err := run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if _, err := run("systemctl", "--user", "enable", "--now", SystemdUnit); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown service kind %q", kind)
	}
}

// Unload stops the service and deregisters it. A service that is not loaded is
// not an error, keeping uninstall idempotent.
func Unload(kind Kind) error {
	switch kind {
	case KindLaunchd:
		target := fmt.Sprintf("gui/%d", os.Getuid())
		// bootout fails when nothing is loaded; that is the desired end state.
		//nolint:errcheck // an unloaded service is success for Unload
		_, _ = run("launchctl", "bootout", target+"/"+LaunchdLabel)
		return nil
	case KindSystemd:
		//nolint:errcheck // a disabled or absent unit is success for Unload
		_, _ = run("systemctl", "--user", "disable", "--now", SystemdUnit)
		//nolint:errcheck // reload is best effort after the unit is gone
		_, _ = run("systemctl", "--user", "daemon-reload")
		return nil
	default:
		return fmt.Errorf("unknown service kind %q", kind)
	}
}

// Loaded reports whether the service manager currently knows about the service.
// It is best-effort: a false result with a nil error means "not registered", and
// the manager being absent is reported as not-loaded rather than an error, so
// `status` still works on a host without launchctl/systemctl.
func Loaded(kind Kind) (bool, error) {
	switch kind {
	case KindLaunchd:
		out, err := run("launchctl", "list")
		if err != nil {
			return false, nil //nolint:nilerr // absent launchctl means "not loaded", not a failure
		}
		return strings.Contains(out, LaunchdLabel), nil
	case KindSystemd:
		// is-enabled exits non-zero for a disabled unit, so the output matters
		// more than the exit status.
		out, _ := run("systemctl", "--user", "is-enabled", SystemdUnit) //nolint:errcheck // a disabled unit exits non-zero; the output is the answer
		return strings.HasPrefix(out, "enabled"), nil
	default:
		return false, fmt.Errorf("unknown service kind %q", kind)
	}
}
