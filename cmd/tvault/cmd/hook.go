package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var hookCmd = &cobra.Command{
	Use:   "hook <shell>",
	Short: "Print a shell/direnv snippet for loading project secrets via the agent",
	Long: `Print a shell snippet that defines a tvault_load helper for loading a
project's secrets into your current shell. Paired with a running agent
(tvault agent start), loading is fast and prompt-free.

Supported shells: bash, zsh, fish, direnv.

The snippet sources the output of 'tvault env --format shell', which is
already safely quoted — secret values are never interpolated into the hook
text, so a value can't inject shell.

Examples:
  eval "$(tvault hook zsh)"        # add to ~/.zshrc
  eval "$(tvault hook bash)"       # add to ~/.bashrc
  tvault hook fish | source        # add to config.fish
  tvault hook direnv               # add to ~/.config/direnv/direnvrc`,
	Args: cobra.ExactArgs(1),
	RunE: runHook,
}

func init() {
	rootCmd.AddCommand(hookCmd)
}

func runHook(_ *cobra.Command, args []string) error {
	shell := strings.ToLower(args[0])
	snippet, ok := hookSnippets[shell]
	if !ok {
		valid := make([]string, 0, len(hookSnippets))
		for k := range hookSnippets {
			valid = append(valid, k)
		}
		sort.Strings(valid)
		return fmt.Errorf("unknown shell %q (supported: %s)", shell, strings.Join(valid, ", "))
	}
	fmt.Print(snippet)
	// Install hint to stderr so stdout stays clean for eval/source.
	fmt.Fprintln(os.Stderr, hookHints[shell])
	return nil
}

var hookSnippets = map[string]string{
	"bash": `# tvault shell hook (bash). Load a project's secrets into the current shell.
tvault_load() {
  local proj="${1:-}"
  if [ -n "$proj" ]; then
    eval "$(tvault env --format shell --project "$proj")"
  else
    eval "$(tvault env --format shell)"
  fi
}
`,
	"zsh": `# tvault shell hook (zsh). Load a project's secrets into the current shell.
tvault_load() {
  local proj="${1:-}"
  if [ -n "$proj" ]; then
    eval "$(tvault env --format shell --project "$proj")"
  else
    eval "$(tvault env --format shell)"
  fi
}
`,
	"fish": `# tvault shell hook (fish). Load a project's secrets into the current shell.
function tvault_load
  if test -n "$argv[1]"
    tvault env --format shell --project $argv[1] | source
  else
    tvault env --format shell | source
  end
end
`,
	"direnv": `# tvault direnv hook. Add to ~/.config/direnv/direnvrc, then in a project's
# .envrc:  use tvault [project]
use_tvault() {
  local proj="${1:-}"
  if [ -n "$proj" ]; then
    eval "$(tvault env --format shell --project "$proj")"
  else
    eval "$(tvault env --format shell)"
  fi
}
`,
}

var hookHints = map[string]string{
	"bash":   `# add to ~/.bashrc:  eval "$(tvault hook bash)"   then: tvault_load [project]`,
	"zsh":    `# add to ~/.zshrc:   eval "$(tvault hook zsh)"    then: tvault_load [project]`,
	"fish":   `# add to config.fish: tvault hook fish | source   then: tvault_load [project]`,
	"direnv": `# add to ~/.config/direnv/direnvrc: tvault hook direnv >> ~/.config/direnv/direnvrc`,
}
