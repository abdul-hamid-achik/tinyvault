package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	studio "github.com/abdul-hamid-achik/tinyvault/cmd/tvault/cmd/studio"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	studioSinglePane bool
	studioNoAnim     bool
	studioAuditLimit int
	studioRW         bool
)

var studioCmd = &cobra.Command{
	Use:   "studio [project]",
	Short: "Open the interactive terminal UI (the vault studio)",
	Long: `Open an interactive, full-screen terminal UI for working in the vault.

Four panes — status, projects, secrets, and audit — with vim, arrow, and
mouse-wheel navigation, a live key filter, and reveal-on-demand (press
'r' to show a value, 'esc' to re-mask). READ-ONLY by default; pass --rw to
enable audited in-app edits (n new, e edit, d delete) that use the same
encryption path as the CLI. The MCP server remains the network surface.

If TVAULT_PASSPHRASE is set, it starts unlocked; otherwise it starts locked
and you can unlock in-app with 'u'. Browsing project/secret metadata works
while locked — only revealing or editing a value needs the key.

Aliased as 'browse' and 'ui' for backwards compatibility.

Examples:
  tvault studio
  tvault studio webapp
  tvault studio --rw                   # enable in-app new/edit/delete
  tvault studio --project staging --no-anim
  tvault studio --single-pane          # force single-pane (small terminals)
  tvault studio --audit-limit 200`,
	Aliases: []string{"browse", "ui"},
	Args:    cobra.MaximumNArgs(1),
	RunE:    runStudio,
}

func init() {
	rootCmd.AddCommand(studioCmd)
	studioCmd.Flags().BoolVar(&studioSinglePane, "single-pane", false, "Force single-pane mode (small terminals)")
	studioCmd.Flags().BoolVar(&studioNoAnim, "no-anim", false, "Disable animations (also via $TVAULT_NO_ANIM)")
	studioCmd.Flags().IntVar(&studioAuditLimit, "audit-limit", 100, "Number of recent audit entries to load")
	studioCmd.Flags().BoolVar(&studioRW, "rw", false, "Enable in-app edits (new/edit/delete secrets); read-only by default")
}

func runStudio(cmd *cobra.Command, args []string) error {
	// Config-file defaults (~/.tvault/config.yaml `browse:` block) fill in
	// any flag the user did not set explicitly; explicit flags always win.
	if cfg, err := loadConfig(); err == nil {
		if !cmd.Flags().Changed("no-anim") && cfg.Browse.NoAnim {
			studioNoAnim = true
		}
		if !cmd.Flags().Changed("single-pane") && cfg.Browse.SinglePane {
			studioSinglePane = true
		}
		if !cmd.Flags().Changed("audit-limit") && cfg.Browse.AuditLimit > 0 {
			studioAuditLimit = cfg.Browse.AuditLimit
		}
	}

	// The studio needs a real terminal. Refuse on piped/dumb terminals so
	// we fail fast with a clear message instead of producing garbage.
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("tvault studio requires an interactive terminal (stdin/stdout must be a TTY)")
	}
	if os.Getenv("TERM") == "dumb" {
		return fmt.Errorf("tvault studio does not support TERM=dumb; use the CLI commands instead")
	}

	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first", dir)
	}
	defer v.Close()

	// Unlock non-interactively if a passphrase is available; otherwise the
	// studio launches locked and the user unlocks in-app with 'u'.
	if pass := os.Getenv("TVAULT_PASSPHRASE"); pass != "" {
		_ = v.Unlock(pass) //nolint:errcheck // a wrong env passphrase just means "stay locked"
	}

	project := projectName
	if len(args) == 1 {
		project = args[0]
	}

	return studio.Run(v, studio.Options{
		Project:    project,
		SinglePane: studioSinglePane,
		NoAnim:     studioNoAnim,
		AuditLimit: studioAuditLimit,
		ReadWrite:  studioRW,
	})
}
