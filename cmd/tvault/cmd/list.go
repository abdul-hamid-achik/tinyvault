package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var listPrefix string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secret keys in the current project",
	Long: `List secret keys in the current project.

If --prefix is supplied, only keys starting with that prefix are shown.
Use 'tvault get <key>' to retrieve a specific value, or 'tvault search'
for cross-project or relational queries.

Examples:
  tvault list
  tvault list --prefix STRIPE_
  tvault list -p staging --prefix DB_`,
	Aliases: []string{"ls"},
	RunE:    runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().StringVar(&listPrefix, "prefix", "", "Only show keys starting with this prefix")
}

func runList(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)

	var keys []string
	if listPrefix != "" {
		// Use the relational query path so we share semantics with
		// `tvault search` and the MCP tools.
		refs, serr := v.Search(vault.SecretSearchQuery{
			Project: project,
			Prefix:  listPrefix,
		})
		if serr != nil {
			return fmt.Errorf("failed to list secrets: %w", serr)
		}
		keys = make([]string, 0, len(refs))
		for _, r := range refs {
			keys = append(keys, r.Key)
		}
	} else {
		keys, err = v.ListSecrets(project)
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}
	}

	sort.Strings(keys)

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(keys)
	}

	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Add one with: tvault set KEY VALUE")
		return nil
	}

	for _, k := range keys {
		fmt.Println(k)
	}

	return nil
}
