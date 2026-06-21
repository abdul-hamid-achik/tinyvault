package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	tvmcp "github.com/abdul-hamid-achik/tinyvault/internal/mcp"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// doctorCmd diagnoses a tvault setup without requiring the vault to be
// unlocked. It reads only metadata, so it is safe to run any time.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose your tvault setup (vault, config, policy, environment)",
	Long: `Run a series of read-only checks against your tvault setup and report
what is healthy, what to watch, and what is broken.

Doctor never unlocks the vault — it only reads metadata (directory
permissions, vault validity, project/secret counts, config and MCP policy
files, environment, terminal). Exit code is non-zero if any check FAILS
(warnings do not fail), so it is safe to gate scripts on it.

Examples:
  tvault doctor
  tvault doctor --json`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type doctorStatus string

const (
	statusOK   doctorStatus = "ok"
	statusWarn doctorStatus = "warn"
	statusFail doctorStatus = "fail"
	statusInfo doctorStatus = "info"
)

type doctorCheck struct {
	Name   string       `json:"name"`
	Status doctorStatus `json:"status"`
	Detail string       `json:"detail"`
}

func runDoctor(_ *cobra.Command, _ []string) error {
	dir := getVaultDir()
	checks := make([]doctorCheck, 0, 16)
	checks = append(checks, doctorCheck{Name: "version", Status: statusInfo, Detail: formatVersion()})
	checks = append(checks, checkVaultDir(dir)...)
	checks = append(checks, checkVault(dir)...)
	checks = append(checks, checkConfig(), checkPolicy(dir))
	checks = append(checks, checkEnvironment()...)
	checks = append(checks, checkTerminal())

	failed := 0
	for _, c := range checks {
		if c.Status == statusFail {
			failed++
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"healthy": failed == 0, "failed": failed, "checks": checks}); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stdout, "tvault doctor")
		fmt.Fprintln(os.Stdout, "-------------")
		for _, c := range checks {
			fmt.Fprintf(os.Stdout, "%s  %-16s %s\n", doctorIcon(c.Status), c.Name, c.Detail)
		}
		fmt.Fprintln(os.Stdout)
		if failed == 0 {
			Success("All checks passed.")
		} else {
			Error("%d check(s) failed.", failed)
		}
	}

	if failed > 0 {
		// Return a sentinel so the process exits non-zero without cobra
		// re-printing usage (SilenceUsage is set on root).
		return fmt.Errorf("doctor: %d check(s) failed", failed)
	}
	return nil
}

func doctorIcon(s doctorStatus) string {
	switch s {
	case statusOK:
		return SuccessIcon()
	case statusWarn:
		return WarningIcon()
	case statusFail:
		return ErrorIcon()
	default:
		return InfoIcon()
	}
}

func checkVaultDir(dir string) []doctorCheck {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []doctorCheck{{Name: "vault dir", Status: statusWarn, Detail: dir + " does not exist yet — run 'tvault init'"}}
		}
		return []doctorCheck{{Name: "vault dir", Status: statusFail, Detail: fmt.Sprintf("%s: %v", dir, err)}}
	}
	if !info.IsDir() {
		return []doctorCheck{{Name: "vault dir", Status: statusFail, Detail: dir + " is not a directory"}}
	}
	checks := []doctorCheck{{Name: "vault dir", Status: statusOK, Detail: dir}}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		checks = append(checks, doctorCheck{Name: "dir perms", Status: statusWarn,
			Detail: fmt.Sprintf("%#o is group/other-accessible; want 0700", perm)})
	} else {
		checks = append(checks, doctorCheck{Name: "dir perms", Status: statusOK, Detail: fmt.Sprintf("%#o", perm)})
	}
	return checks
}

func checkVault(dir string) []doctorCheck {
	v, err := vault.Open(dir)
	if err != nil {
		if errors.Is(err, vault.ErrVaultBusy) {
			// The db file exists but bbolt's lock is held elsewhere — don't
			// mis-report this as "not initialized" (the historical bug).
			return []doctorCheck{{Name: "vault", Status: statusWarn,
				Detail: "in use by another tvault process (db is open — e.g. a running 'tvault mcp' or 'tvault studio')"}}
		}
		return []doctorCheck{{Name: "vault", Status: statusWarn, Detail: "not initialized — run 'tvault init'"}}
	}
	defer v.Close()

	st := v.Status()
	checks := []doctorCheck{{Name: "vault", Status: statusOK, Detail: "initialized (id " + shortID(st.VaultID) + ", created " + st.CreatedAt + ")"}}

	lock := "locked"
	if st.IsUnlocked {
		lock = "unlocked"
	}
	checks = append(checks, doctorCheck{Name: "lock state", Status: statusInfo, Detail: lock})

	cur, _ := v.GetCurrentProject() //nolint:errcheck // empty is fine
	if cur == "" {
		cur = "(none)"
	}
	checks = append(checks, doctorCheck{Name: "current project", Status: statusInfo, Detail: cur})

	if snaps, serr := v.SnapshotProjects(); serr == nil {
		total := 0
		for _, s := range snaps {
			total += s.SecretCount
		}
		checks = append(checks, doctorCheck{Name: "contents", Status: statusOK,
			Detail: fmt.Sprintf("%d project(s), %d secret(s)", len(snaps), total)})
	}
	return checks
}

func checkConfig() doctorCheck {
	path := filepath.Join(getVaultDir(), "config.yaml")
	if _, err := os.Stat(path); err != nil {
		return doctorCheck{Name: "config", Status: statusInfo, Detail: "no config file (using defaults)"}
	}
	if _, err := loadConfig(); err != nil {
		return doctorCheck{Name: "config", Status: statusFail, Detail: fmt.Sprintf("%s: %v", path, err)}
	}
	return doctorCheck{Name: "config", Status: statusOK, Detail: path}
}

func checkPolicy(dir string) doctorCheck {
	path := filepath.Join(dir, "mcp-policy.yaml")
	if _, err := os.Stat(path); err != nil {
		return doctorCheck{Name: "mcp policy", Status: statusInfo, Detail: "no policy file (MCP uses the default policy)"}
	}
	if _, err := tvmcp.LoadPolicy(path); err != nil {
		return doctorCheck{Name: "mcp policy", Status: statusFail, Detail: fmt.Sprintf("%s: %v", path, err)}
	}
	return doctorCheck{Name: "mcp policy", Status: statusOK, Detail: path}
}

func checkEnvironment() []doctorCheck {
	var checks []doctorCheck
	for _, e := range []string{"TVAULT_DIR", "TVAULT_PROJECT", "TVAULT_CONFIG"} {
		if val := os.Getenv(e); val != "" {
			checks = append(checks, doctorCheck{Name: e, Status: statusInfo, Detail: val})
		}
	}
	// Never print the passphrase; only report whether it is set.
	if os.Getenv("TVAULT_PASSPHRASE") != "" {
		checks = append(checks, doctorCheck{Name: "TVAULT_PASSPHRASE", Status: statusInfo, Detail: "set (non-interactive unlock enabled)"})
	}
	return checks
}

func checkTerminal() doctorCheck {
	if os.Getenv("TERM") == "dumb" {
		return doctorCheck{Name: "terminal", Status: statusWarn, Detail: "TERM=dumb — 'tvault studio' will refuse to start"}
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return doctorCheck{Name: "terminal", Status: statusInfo, Detail: "not a TTY — 'tvault studio' needs an interactive terminal"}
	}
	return doctorCheck{Name: "terminal", Status: statusOK, Detail: "interactive TTY ('tvault studio' OK)"}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
