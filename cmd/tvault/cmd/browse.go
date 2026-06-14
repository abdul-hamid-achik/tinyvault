package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	browse "github.com/abdul-hamid-achik/tinyvault/cmd/tvault/cmd/browse"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	browseSinglePane bool
	browseNoAnim     bool
	browseAuditLimit int
)

var browseCmd = &cobra.Command{
	Use:   "browse [project]",
	Short: "Browse the vault in an interactive terminal UI",
	Long: `Open an interactive, full-screen terminal UI for browsing the vault.

Four panes — status, projects, secrets, and audit — with vim, arrow, and
mouse-wheel navigation, a live key filter, and reveal-on-demand (press
'r' to show a value, 'esc' to re-mask). It is READ-ONLY: every mutation
still goes through the CLI, and the MCP server remains the network surface.

If TVAULT_PASSPHRASE is set, it starts unlocked; otherwise it starts locked
and you can unlock in-app with 'u'. Browsing project/secret metadata works
while locked — only revealing a value needs the key.

Examples:
  tvault browse
  tvault browse webapp
  tvault browse --project staging --no-anim
  tvault browse --single-pane          # force single-pane (small terminals)
  tvault browse --audit-limit 200`,
	Aliases: []string{"ui"},
	Args:    cobra.MaximumNArgs(1),
	RunE:    runBrowse,
}

func init() {
	rootCmd.AddCommand(browseCmd)
	browseCmd.Flags().BoolVar(&browseSinglePane, "single-pane", false, "Force single-pane mode (small terminals)")
	browseCmd.Flags().BoolVar(&browseNoAnim, "no-anim", false, "Disable animations (also via $TVAULT_NO_ANIM)")
	browseCmd.Flags().IntVar(&browseAuditLimit, "audit-limit", 100, "Number of recent audit entries to load")
}

func runBrowse(_ *cobra.Command, args []string) error {
	// The browser needs a real terminal. Refuse on piped/dumb terminals so
	// we fail fast with a clear message instead of producing garbage.
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("tvault browse requires an interactive terminal (stdin/stdout must be a TTY)")
	}
	if os.Getenv("TERM") == "dumb" {
		return fmt.Errorf("tvault browse does not support TERM=dumb; use the CLI commands instead")
	}

	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first", dir)
	}
	defer v.Close()

	// Unlock non-interactively if a passphrase is available; otherwise the
	// browser launches locked and the user unlocks in-app with 'u'.
	if pass := os.Getenv("TVAULT_PASSPHRASE"); pass != "" {
		_ = v.Unlock(pass) //nolint:errcheck // a wrong env passphrase just means "stay locked"
	}

	project := projectName
	if len(args) == 1 {
		project = args[0]
	}

	return browse.Run(v, browse.Options{
		Project:    project,
		SinglePane: browseSinglePane,
		NoAnim:     browseNoAnim,
		AuditLimit: browseAuditLimit,
	})
}
