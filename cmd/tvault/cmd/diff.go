package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/dotenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var diffValues bool

var diffCmd = &cobra.Command{
	Use:   "diff <file>",
	Short: "Show how the current project's secrets drift from a .env file",
	Long: `Compare the current project's secret keys against a dotenv file and
report which keys exist only in the vault, only in the file, or in both.

By default this is metadata-only: it reads key NAMES and never decrypts,
so it does not need an unlocked vault. With --values, keys present in both
are additionally compared by value and reported as "same" or "differs" —
the values themselves are never printed (only the verdict). --values
requires unlocking and audits each comparison as a secret.read.

Use it to answer "is my .env in sync with the vault?" before a deploy.

Examples:
  tvault diff .env
  tvault diff .env --values
  tvault diff .env --json`,
	Args: cobra.ExactArgs(1),
	RunE: runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().BoolVar(&diffValues, "values", false, "Also compare values of in-both keys (reports same/differs; never prints values)")
}

type diffResult struct {
	Project     string            `json:"project"`
	File        string            `json:"file"`
	OnlyInVault []string          `json:"only_in_vault"`
	OnlyInFile  []string          `json:"only_in_file"`
	InBoth      []string          `json:"in_both"`
	ValueDiffs  map[string]string `json:"value_diffs,omitempty"` // key -> same|differs
	InSync      bool              `json:"in_sync"`
}

func runDiff(_ *cobra.Command, args []string) error {
	path := args[0]
	parsed, err := dotenv.ParseFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	fileKeys := make(map[string]string, len(parsed.Entries))
	for _, e := range parsed.Entries {
		fileKeys[e.Key] = e.Value
	}

	// Metadata-only by default → no unlock needed. --values needs the key.
	var v *vault.Vault
	if diffValues {
		v, err = openAndUnlockVault()
	} else {
		dir := getVaultDir()
		v, err = vault.Open(dir)
		if err != nil {
			err = fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
		}
	}
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	vaultKeys, err := v.ListSecrets(project)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}
	vaultSet := make(map[string]bool, len(vaultKeys))
	for _, k := range vaultKeys {
		vaultSet[k] = true
	}

	res := diffResult{
		Project:     project,
		File:        path,
		OnlyInVault: []string{},
		OnlyInFile:  []string{},
		InBoth:      []string{},
	}
	for _, k := range vaultKeys {
		if _, ok := fileKeys[k]; ok {
			res.InBoth = append(res.InBoth, k)
		} else {
			res.OnlyInVault = append(res.OnlyInVault, k)
		}
	}
	for k := range fileKeys {
		if !vaultSet[k] {
			res.OnlyInFile = append(res.OnlyInFile, k)
		}
	}
	sort.Strings(res.OnlyInVault)
	sort.Strings(res.OnlyInFile)
	sort.Strings(res.InBoth)

	valueDrift := false
	if diffValues {
		res.ValueDiffs = make(map[string]string, len(res.InBoth))
		for _, k := range res.InBoth {
			vv, gerr := v.GetSecret(project, k)
			if gerr != nil {
				res.ValueDiffs[k] = "error"
				continue
			}
			recordAudit(v, "secret.read", "secret", k, map[string]any{"project": project, "source": "diff"})
			if vv == fileKeys[k] {
				res.ValueDiffs[k] = "same"
			} else {
				res.ValueDiffs[k] = "differs"
				valueDrift = true
			}
		}
	}
	res.InSync = len(res.OnlyInVault) == 0 && len(res.OnlyInFile) == 0 && !valueDrift

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	printDiff(res)
	return nil
}

func printDiff(res diffResult) {
	PrintKeyValue("Project", res.Project)
	PrintKeyValue("File", res.File)
	fmt.Fprintln(os.Stderr)

	emit := func(label string, keys []string) {
		fmt.Fprintf(os.Stderr, "%s (%d):\n", label, len(keys))
		for _, k := range keys {
			fmt.Fprintf(os.Stderr, "  %s\n", k)
		}
	}
	emit("Only in vault", res.OnlyInVault)
	emit("Only in file", res.OnlyInFile)

	if res.ValueDiffs != nil {
		differing := make([]string, 0)
		for _, k := range res.InBoth {
			if res.ValueDiffs[k] != "same" {
				differing = append(differing, fmt.Sprintf("%s (%s)", k, res.ValueDiffs[k]))
			}
		}
		emit("Values differ", differing)
	}

	fmt.Fprintln(os.Stderr)
	if res.InSync {
		Success("In sync.")
	} else {
		Warning("Out of sync (see above).")
	}
}
