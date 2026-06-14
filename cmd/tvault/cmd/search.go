package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var (
	searchProject    string
	searchPrefix     string
	searchNameLike   string
	searchSince      string
	searchUntil      string
	searchMinVersion int
	searchLimit      int
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search secret keys and project names against the vault",
	Long: `Search the vault's metadata (project names + secret key names) using
a relational query. Search is metadata-only: secret values are NEVER
decrypted or returned by this command. To use a value, follow up with
` + "`tvault run -- CMD`" + ` or ` + "`tvault get KEY`" + `.

By default search runs across all projects and returns every key.
Use --project, --prefix, --name-like, --since, --until, and --min-version
to narrow the result set.

Examples:
  tvault search --prefix STRIPE_
  tvault search --project production --name-like 'DB_*'
  tvault search --since 2026-01-01T00:00:00Z
  tvault search --project default --min-version 2`,
	RunE: runSearch,
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().StringVarP(&searchProject, "project", "p", "", "Restrict to a project (default: search all projects)")
	searchCmd.Flags().StringVar(&searchPrefix, "prefix", "", "Only return keys starting with this prefix")
	searchCmd.Flags().StringVar(&searchNameLike, "name-like", "", "SQL-like pattern with '*' wildcard (e.g. 'STRIPE_*')")
	searchCmd.Flags().StringVar(&searchSince, "since", "", "RFC3339 timestamp; only secrets updated at or after")
	searchCmd.Flags().StringVar(&searchUntil, "until", "", "RFC3339 timestamp; only secrets updated at or before")
	searchCmd.Flags().IntVar(&searchMinVersion, "min-version", 0, "Only secrets with Version >= this value")
	searchCmd.Flags().IntVar(&searchLimit, "limit", 200, "Maximum number of results")
}

func runSearch(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	q := vault.SecretSearchQuery{
		Project:    searchProject,
		Prefix:     searchPrefix,
		NameLike:   searchNameLike,
		MinVersion: searchMinVersion,
		Limit:      searchLimit,
	}
	if searchSince != "" {
		t, perr := time.Parse(time.RFC3339, searchSince)
		if perr != nil {
			return fmt.Errorf("invalid --since: %w", perr)
		}
		q.Since = t
	}
	if searchUntil != "" {
		t, perr := time.Parse(time.RFC3339, searchUntil)
		if perr != nil {
			return fmt.Errorf("invalid --until: %w", perr)
		}
		q.Until = t
	}

	refs, err := v.Search(q)
	if err != nil {
		return err
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"query":   q,
			"count":   len(refs),
			"results": refs,
		})
	}

	if len(refs) == 0 {
		fmt.Println("(no matches)")
		return nil
	}

	// Pretty table.
	for _, r := range refs {
		fmt.Printf("%s/%s\tv%d\t%s\n", r.Project, r.Key, r.Version, r.UpdatedAt.Format(time.RFC3339))
	}
	return nil
}
