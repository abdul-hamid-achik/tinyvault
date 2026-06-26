package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/encryptedenv"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// resolveAllWithInheritance resolves all secrets for an environment through
// the inheritance chain. It gets the child project's local secrets, then
// fills in missing keys from the base environment (if inheritance is
// configured). Returns the merged map and the effective project name.
func resolveAllWithInheritance(v *vault.Vault, groupName, envName string) (map[string]string, string, error) {
	group, err := v.GetEnvGroup(groupName)
	if err != nil {
		return nil, "", err
	}

	// Find the child project.
	childProject := ""
	for _, e := range group.Environments {
		if e.Name == envName {
			childProject = e.Project
			break
		}
	}
	if childProject == "" {
		return nil, "", fmt.Errorf("environment %q not found in group %q", envName, groupName)
	}

	// Get child secrets.
	childSecrets, err := v.GetAllSecrets(childProject)
	if err != nil {
		return nil, "", fmt.Errorf("get secrets for %s: %w", childProject, err)
	}

	// If inheritance is configured, fill in missing keys from the base.
	if group.Inheritance != nil {
		if inh, ok := group.Inheritance[envName]; ok {
			baseProject := ""
			for _, e := range group.Environments {
				if e.Name == inh.From {
					baseProject = e.Project
					break
				}
			}
			if baseProject != "" {
				baseSecrets, bErr := v.GetAllSecrets(baseProject)
				if bErr == nil {
					for k, val := range baseSecrets {
						if _, exists := childSecrets[k]; !exists {
							childSecrets[k] = val
						}
					}
				}
			}
		}
	}

	return childSecrets, childProject, nil
}

// --- env group create ---

var (
	envGroupDescription string
	envGroupEnvs        []string
	envGroupForce       bool
)

var envGroupCmd = &cobra.Command{
	Use:     "group",
	Aliases: []string{"groups"},
	Short:   "Manage environment groups",
}

var envGroupCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an environment group linking multiple projects",
	Long: `Create an environment group that links multiple projects as named
environments. Each project must already exist. Environment names must be
unique within the group.

Pass environments as --env name=project flags. The first --env is typically
production.

Examples:
  tvault env group create liftclub --description "LIFT Club" \
    --env production=liftclub --env preview=liftclub-preview`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvGroupCreate,
}

var envGroupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all environment groups",
	RunE:  runEnvGroupList,
}

var envGroupShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show group details (environments, drift, inheritance)",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvGroupShow,
}

var envGroupAddCmd = &cobra.Command{
	Use:   "add <env-name>",
	Short: "Add an environment to an existing group",
	Long: `Add an environment to an existing group. The project must already
exist and must not be in another group.

Example:
  tvault env group add staging --project liftclub-staging --group liftclub`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvGroupAdd,
}

var envGroupRemoveCmd = &cobra.Command{
	Use:   "remove <env-name>",
	Short: "Remove an environment from a group (does not delete the project)",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvGroupRemove,
}

var envGroupDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a group entirely (projects are untouched)",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvGroupDelete,
}

// --- env diff ---

var (
	envDiffValues   bool
	envDiffKeysOnly bool
)

var envDiffCmd = &cobra.Command{
	Use:   "diff <group>",
	Short: "Compare key sets across environments in a group",
	Long: `Compare key sets across all environments in a group. Reports
missing keys, extra keys, and (with --values) same/different values.
Values are never printed — only the verdict (same/different).

Exit codes:
  0  No drift (all environments have the same key set)
  1  Drift detected (missing or extra keys)
  2  Group not found
  3  Vault locked (only with --values)

Examples:
  tvault env diff liftclub
  tvault env diff liftclub --values
  tvault env diff liftclub --json`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvDiff,
}

// --- env promote ---

var (
	envPromoteFrom   string
	envPromoteTo     string
	envPromoteAll    bool
	envPromoteDryRun bool
	envPromoteYes    bool
)

var envPromoteCmd = &cobra.Command{
	Use:   "promote [keys...] --group <name> --from <env> --to <env>",
	Short: "Copy secret values from one environment to another",
	Long: `Copy secret values from one environment to another within a group.
The value is decrypted from the source project and re-encrypted into the
target project, creating a new version (the prior value is archived).
Each promoted key gets an audit entry: secret.promote.

Safety:
  - Promote always prompts unless --yes is passed.
  - --dry-run shows what would change without writing.
  - --all promotes all keys that differ.

Examples:
  tvault env promote DATABASE_URL --group liftclub --from preview --to production
  tvault env promote --all --group liftclub --from preview --to production --dry-run
  tvault env promote --all --group liftclub --from preview --to production --yes`,
	RunE: runEnvPromote,
}

// --- env inherit / pin / unpin / inherited ---

var (
	envInheritFrom string
)

var envInheritCmd = &cobra.Command{
	Use:   "inherit --group <name> --env <child> --from <base>",
	Short: "Configure key inheritance for an environment",
	Long: `Configure key inheritance so the child environment resolves
missing keys from the base environment at read time. Inheritance is
metadata-only — no values are copied.

Example:
  tvault env inherit --group liftclub --env preview --from production`,
	RunE: runEnvInherit,
}

var envPinCmd = &cobra.Command{
	Use:   "pin <key> --group <name> --env <child>",
	Short: "Pin a key (write the resolved value into the child, breaking inheritance)",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvPin,
}

var envUnpinCmd = &cobra.Command{
	Use:   "unpin <key> --group <name> --env <child>",
	Short: "Unpin a key (delete the pinned value, restoring inheritance)",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvUnpin,
}

var envInheritedCmd = &cobra.Command{
	Use:   "inherited --group <name> --env <child>",
	Short: "Show which keys are inherited vs. local (pinned)",
	RunE:  runEnvInherited,
}

// --- env seal ---

var (
	envSealRecipients []string
	envSealOut        string
	envSealKeys       []string
	envSealEnvs       []string
)

var envSealCmd = &cobra.Command{
	Use:   "seal --group <name> --recipient <tvault1…> [-o file]",
	Short: "Seal all environments of a group into a single recipient-sealed blob",
	Long: `Seal all environments of a group into a single .env.encrypted v2 blob
keyed by environment name. In CI, decrypt with --section <env> to extract
one environment's values.

The blob contains sections:
  --- tvault-env:production ---
  KEY=value
  --- tvault-env:preview ---
  KEY=value
  --- end ---

Secret values are NEVER returned. The output is ciphertext only.

Examples:
  tvault env seal --group liftclub --recipient tvault1ci… -o ci/migration.sealed
  tvault env seal --group liftclub --keys DATABASE_URL,STRIPE_SECRET_KEY --recipient tvault1ci…
  tvault env seal --group liftclub --envs production,preview --recipient tvault1ci…`,
	RunE: runEnvSeal,
}

// Shared flags for env commands that need group + env.
var (
	envGroupName        string
	envName             string
	envGroupProjectName string
)

func init() {
	// Add all subcommands to the existing envCmd (declared in env.go).
	envCmd.AddCommand(
		envGroupCmd,
		envDiffCmd,
		envPromoteCmd,
		envInheritCmd,
		envPinCmd,
		envUnpinCmd,
		envInheritedCmd,
		envSealCmd,
	)

	// env group
	envGroupCmd.AddCommand(envGroupCreateCmd, envGroupListCmd, envGroupShowCmd, envGroupAddCmd, envGroupRemoveCmd, envGroupDeleteCmd)

	envGroupCreateCmd.Flags().StringVarP(&envGroupDescription, "description", "d", "", "Group description")
	envGroupCreateCmd.Flags().StringArrayVar(&envGroupEnvs, "env", nil, "Environment in name=project format (repeatable)")
	envGroupCreateCmd.Flags().BoolVar(&envGroupForce, "force", false, "Overwrite existing group or re-link projects")

	envGroupAddCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envGroupAddCmd.Flags().StringVarP(&envGroupProjectName, "project", "p", "", "Project name")
	_ = envGroupAddCmd.MarkFlagRequired("group")   //nolint:errcheck // cobra API never fails in practice
	_ = envGroupAddCmd.MarkFlagRequired("project") //nolint:errcheck // cobra API never fails in practice

	envGroupRemoveCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	_ = envGroupRemoveCmd.MarkFlagRequired("group") //nolint:errcheck // cobra API never fails in practice

	envGroupDeleteCmd.Flags().BoolVarP(&envPromoteYes, "yes", "y", false, "Skip confirmation prompt")

	// env diff
	envDiffCmd.Flags().BoolVar(&envDiffValues, "values", false, "Also compare values (same/different; never prints values)")
	envDiffCmd.Flags().BoolVar(&envDiffKeysOnly, "keys-only", false, "Compare only key sets (fast, no decryption)")

	// env promote
	envPromoteCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envPromoteCmd.Flags().StringVar(&envPromoteFrom, "from", "", "Source environment name")
	envPromoteCmd.Flags().StringVar(&envPromoteTo, "to", "", "Target environment name")
	envPromoteCmd.Flags().BoolVar(&envPromoteAll, "all", false, "Promote all keys that differ")
	envPromoteCmd.Flags().BoolVar(&envPromoteDryRun, "dry-run", false, "Show what would change without writing")
	envPromoteCmd.Flags().BoolVarP(&envPromoteYes, "yes", "y", false, "Skip confirmation prompt")
	_ = envPromoteCmd.MarkFlagRequired("group") //nolint:errcheck // cobra API never fails in practice
	_ = envPromoteCmd.MarkFlagRequired("from")  //nolint:errcheck // cobra API never fails in practice
	_ = envPromoteCmd.MarkFlagRequired("to")    //nolint:errcheck // cobra API never fails in practice

	// env inherit / pin / unpin / inherited
	envInheritCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envInheritCmd.Flags().StringVar(&envName, "env", "", "Child environment name")
	envInheritCmd.Flags().StringVar(&envInheritFrom, "from", "", "Base environment to inherit from")
	_ = envInheritCmd.MarkFlagRequired("group") //nolint:errcheck // cobra API never fails in practice
	_ = envInheritCmd.MarkFlagRequired("env")   //nolint:errcheck // cobra API never fails in practice
	_ = envInheritCmd.MarkFlagRequired("from")  //nolint:errcheck // cobra API never fails in practice

	envPinCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envPinCmd.Flags().StringVar(&envName, "env", "", "Child environment name")
	_ = envPinCmd.MarkFlagRequired("group") //nolint:errcheck // cobra API never fails in practice
	_ = envPinCmd.MarkFlagRequired("env")   //nolint:errcheck // cobra API never fails in practice

	envUnpinCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envUnpinCmd.Flags().StringVar(&envName, "env", "", "Child environment name")
	_ = envUnpinCmd.MarkFlagRequired("group") //nolint:errcheck // cobra API never fails in practice
	_ = envUnpinCmd.MarkFlagRequired("env")   //nolint:errcheck // cobra API never fails in practice

	envInheritedCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envInheritedCmd.Flags().StringVar(&envName, "env", "", "Child environment name")
	_ = envInheritedCmd.MarkFlagRequired("group") //nolint:errcheck // cobra API never fails in practice
	_ = envInheritedCmd.MarkFlagRequired("env")   //nolint:errcheck // cobra API never fails in practice

	// env seal
	envSealCmd.Flags().StringVar(&envGroupName, "group", "", "Group name")
	envSealCmd.Flags().StringArrayVar(&envSealRecipients, "recipient", nil, "X25519 recipient (tvault1…); repeatable")
	envSealCmd.Flags().StringVarP(&envSealOut, "out", "o", "", "Output file (default: stdout)")
	envSealCmd.Flags().StringArrayVar(&envSealKeys, "keys", nil, "Specific keys to seal (comma-separated or repeatable)")
	envSealCmd.Flags().StringArrayVar(&envSealEnvs, "envs", nil, "Specific environments to include (comma-separated or repeatable)")
	_ = envSealCmd.MarkFlagRequired("group")     //nolint:errcheck // cobra API never fails in practice
	_ = envSealCmd.MarkFlagRequired("recipient") //nolint:errcheck // cobra API never fails in practice
}

// --- run functions ---

func runEnvGroupCreate(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	name := args[0]

	if len(envGroupEnvs) == 0 {
		return fmt.Errorf("at least one --env flag is required (format: name=project)")
	}

	environments := make([]vault.EnvGroupEntry, 0, len(envGroupEnvs))
	for _, e := range envGroupEnvs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid --env %q: expected name=project", e)
		}
		environments = append(environments, vault.EnvGroupEntry{
			Name:    parts[0],
			Project: parts[1],
		})
	}

	group, err := v.CreateEnvGroup(name, envGroupDescription, environments, envGroupForce)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	recordAudit(v, "env.group.create", "env_group", name, nil)

	if jsonOutput {
		return writeJSON(group)
	}

	Success("Group '%s' created with environments: %s", name, formatEnvList(group.Environments))
	return nil
}

func runEnvGroupList(_ *cobra.Command, _ []string) error {
	v, err := vault.Open(getVaultDir())
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", getVaultDir(), err)
	}
	defer v.Close()

	groups, err := v.ListEnvGroups()
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}

	if jsonOutput {
		if groups == nil {
			groups = []vault.EnvGroup{}
		}
		return writeJSON(groups)
	}

	if len(groups) == 0 {
		fmt.Fprintln(os.Stderr, "No environment groups found.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Create one with: tvault env group create <name> --env name=project")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tENVIRONMENTS\tDESCRIPTION")
	for _, g := range groups {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", g.Name, formatEnvList(g.Environments), g.Description)
	}
	_ = w.Flush()
	return nil
}

func runEnvGroupShow(_ *cobra.Command, args []string) error {
	v, err := vault.Open(getVaultDir())
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", getVaultDir(), err)
	}
	defer v.Close()

	name := args[0]
	group, err := v.GetEnvGroup(name)
	if err != nil {
		return fmt.Errorf("group %q: %w", name, err)
	}

	// Try drift detection (metadata-only, no unlock needed).
	diff, diffErr := v.DiffEnvironments(name, false)

	if jsonOutput {
		out := map[string]any{
			"group":       group,
			"diff_status": "unknown",
		}
		if diffErr == nil && diff != nil {
			out["diff_status"] = diff.Status
			out["diff_keys"] = diff.Keys
		}
		return writeJSON(out)
	}

	PrintKeyValue("Group", group.Name)
	PrintKeyValue("Description", group.Description)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Environments:")
	for _, e := range group.Environments {
		inh := ""
		if group.Inheritance != nil {
			if i, ok := group.Inheritance[e.Name]; ok {
				inh = fmt.Sprintf(" (inherits from %s)", i.From)
			}
		}
		fmt.Fprintf(os.Stderr, "  %s → %s%s\n", e.Name, e.Project, inh)
	}

	if diffErr == nil && diff != nil {
		fmt.Fprintln(os.Stderr)
		if diff.Status == "drift" {
			Warning("Drift detected — %d key(s) differ across environments", len(diff.Keys))
		} else {
			Success("No drift — all environments have the same key set")
		}
	}

	return nil
}

func runEnvGroupAdd(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	envN := args[0]
	group, err := v.AddEnvGroupEnvironment(envGroupName, envN, envGroupProjectName)
	if err != nil {
		return fmt.Errorf("failed to add environment: %w", err)
	}

	recordAudit(v, "env.group.add", "env_group", envGroupName, map[string]any{
		"env":     envN,
		"project": envGroupProjectName,
	})

	if jsonOutput {
		return writeJSON(group)
	}
	Success("Environment '%s' (project %s) added to group '%s'", envN, envGroupProjectName, envGroupName)
	return nil
}

func runEnvGroupRemove(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	envN := args[0]
	group, err := v.RemoveEnvGroupEnvironment(envGroupName, envN)
	if err != nil {
		return fmt.Errorf("failed to remove environment: %w", err)
	}

	recordAudit(v, "env.group.remove", "env_group", envGroupName, map[string]any{
		"env": envN,
	})

	if jsonOutput {
		return writeJSON(group)
	}
	Success("Environment '%s' removed from group '%s'", envN, envGroupName)
	return nil
}

func runEnvGroupDelete(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	name := args[0]

	if !envPromoteYes {
		Warning("This will delete the group '%s'. Projects are NOT deleted.", name)
		if !PromptConfirm(fmt.Sprintf("Delete group '%s'?", name)) {
			Info("Canceled")
			return nil
		}
	}

	if err := v.DeleteEnvGroup(name); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	recordAudit(v, "env.group.delete", "env_group", name, nil)
	Success("Group '%s' deleted", name)
	return nil
}

func runEnvDiff(_ *cobra.Command, args []string) error {
	groupName := args[0]

	// keys-only or default: metadata-only (no unlock needed).
	// --values: needs unlock.
	var v *vault.Vault
	var err error
	if envDiffValues && !envDiffKeysOnly {
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

	diff, err := v.DiffEnvironments(groupName, envDiffValues && !envDiffKeysOnly)
	if err != nil {
		if errors.Is(err, vault.ErrGroupNotFound) {
			if jsonOutput {
				return writeJSON(map[string]any{"error": "group not found", "code": 2})
			}
			return fmt.Errorf("group %q not found", groupName)
		}
		return fmt.Errorf("diff failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(diff)
	}

	// Table output.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// Get env names from the first key's entries (all keys have the same envs).
	var envNames []string
	for _, k := range diff.Keys {
		if len(k.Environments) > 0 {
			for _, e := range k.Environments {
				envNames = append(envNames, e.Env)
			}
			break
		}
	}
	header := "KEY"
	for _, envN := range envNames {
		header += "\t" + strings.ToUpper(envN)
	}
	header += "\tSTATUS"
	_, _ = fmt.Fprintln(w, header)

	for _, k := range diff.Keys {
		row := k.Key
		hasMissing := false
		hasDiff := false
		for _, e := range k.Environments {
			mark := "✓"
			if !e.Present {
				mark = "✗"
				hasMissing = true
			}
			if e.Status == "different" {
				hasDiff = true
			}
			row += "\t" + mark
		}
		status := "same"
		if hasMissing {
			status = "drift"
		} else if hasDiff {
			status = "different"
		}
		row += "\t" + status
		_, _ = fmt.Fprintln(w, row)
	}
	_ = w.Flush()

	fmt.Fprintln(os.Stderr)
	if diff.Status == "drift" {
		Warning("Drift detected")
	} else {
		Success("No drift")
	}
	return nil
}

func runEnvPromote(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	keys := args
	result, err := v.Promote(envGroupName, envPromoteFrom, envPromoteTo, keys, envPromoteAll, envPromoteDryRun)
	if err != nil {
		return fmt.Errorf("promote failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(result)
	}

	if envPromoteDryRun {
		fmt.Fprintln(os.Stderr, "Dry run — no changes written:")
	}

	if len(result.Promoted) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "KEY\tFROM_VER\tTO_VER")
		for _, p := range result.Promoted {
			toVer := fmt.Sprintf("%d", p.ToVersion)
			if envPromoteDryRun {
				toVer = "(dry-run)"
			}
			_, _ = fmt.Fprintf(w, "%s\t%d\t%s\n", p.Key, p.FromVersion, toVer)
		}
		_ = w.Flush()
	}

	if len(result.Skipped) > 0 {
		fmt.Fprintln(os.Stderr, "Skipped:")
		for _, s := range result.Skipped {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", s.Key, s.Reason)
		}
	}

	if len(result.Promoted) > 0 && !envPromoteDryRun {
		Success("Promoted %d key(s) from %s to %s", len(result.Promoted), envPromoteFrom, envPromoteTo)
	}
	return nil
}

func runEnvInherit(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	group, err := v.SetInheritance(envGroupName, envName, envInheritFrom)
	if err != nil {
		return fmt.Errorf("failed to set inheritance: %w", err)
	}

	if jsonOutput {
		return writeJSON(group)
	}
	Success("Environment '%s' in group '%s' now inherits from '%s'", envName, envGroupName, envInheritFrom)
	return nil
}

func runEnvPin(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	key := args[0]
	if err := v.PinKey(envGroupName, envName, key); err != nil {
		return fmt.Errorf("failed to pin %s: %w", key, err)
	}

	Success("Key '%s' pinned in %s/%s", key, envGroupName, envName)
	return nil
}

func runEnvUnpin(_ *cobra.Command, args []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	key := args[0]
	if err := v.UnpinKey(envGroupName, envName, key); err != nil {
		return fmt.Errorf("failed to unpin %s: %w", key, err)
	}

	Success("Key '%s' unpinned in %s/%s (inheritance restored)", key, envGroupName, envName)
	return nil
}

func runEnvInherited(_ *cobra.Command, _ []string) error {
	v, err := vault.Open(getVaultDir())
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", getVaultDir(), err)
	}
	defer v.Close()

	keys, err := v.ListInherited(envGroupName, envName)
	if err != nil {
		return fmt.Errorf("failed to list inherited: %w", err)
	}

	if jsonOutput {
		return writeJSON(keys)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "KEY\tINHERITED-FROM\tPINNED")
	for _, k := range keys {
		pinned := "no"
		if k.Pinned {
			pinned = "yes"
		}
		source := k.Source
		if source == "local" {
			source = "—"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", k.Key, source, pinned)
	}
	_ = w.Flush()
	return nil
}

func runEnvSeal(_ *cobra.Command, _ []string) error {
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	group, err := v.GetEnvGroup(envGroupName)
	if err != nil {
		return fmt.Errorf("group %q: %w", envGroupName, err)
	}

	// Parse comma-separated flags into slices.
	var keys []string
	for _, k := range envSealKeys {
		for _, part := range strings.Split(k, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				keys = append(keys, part)
			}
		}
	}
	var envs []string
	for _, e := range envSealEnvs {
		for _, part := range strings.Split(e, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				envs = append(envs, part)
			}
		}
	}
	sort.Strings(keys)
	sort.Strings(envs)

	// Build the multi-section dotenv body.
	var body strings.Builder
	includedEnvs := []string{}
	includedKeys := []string{}

	for _, e := range group.Environments {
		if len(envs) > 0 {
			found := false
			for _, w := range envs {
				if w == e.Name {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		secrets, gErr := v.GetAllSecrets(e.Project)
		if gErr != nil {
			return fmt.Errorf("get secrets for %s: %w", e.Project, gErr)
		}

		// Filter keys.
		filtered := make([]string, 0, len(secrets))
		for k := range secrets {
			if len(keys) > 0 {
				found := false
				for _, w := range keys {
					if w == k {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			filtered = append(filtered, k)
		}
		sort.Strings(filtered)

		if len(filtered) == 0 {
			continue
		}

		fmt.Fprintf(&body, "--- tvault-env:%s ---\n", e.Name)
		for _, k := range filtered {
			fmt.Fprintf(&body, "%s=%s\n", k, secrets[k])
			includedKeys = appendIfMissing(includedKeys, k)
		}
		includedEnvs = append(includedEnvs, e.Name)
	}
	body.WriteString("--- end ---\n")

	// Parse recipients.
	recipients := make([][]byte, 0, len(envSealRecipients))
	for _, r := range envSealRecipients {
		pub, derr := crypto.DecodeRecipient(r)
		if derr != nil {
			return fmt.Errorf("recipient %q: %w", r, derr)
		}
		recipients = append(recipients, pub)
	}

	// Seal with v2.
	sealed, err := encryptedenv.EncryptV2(recipients, []byte(body.String()))
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	// Write output.
	dest := envSealOut
	if dest == "" {
		_, err := os.Stdout.Write(sealed)
		if err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
	} else {
		if err := os.WriteFile(dest, sealed, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", dest, err)
		}
	}

	recordAudit(v, "env.seal", "env_group", envGroupName, map[string]any{
		"environments":    includedEnvs,
		"recipient_count": len(recipients),
	})

	if dest != "" {
		fmt.Fprintf(os.Stderr, "Wrote %d bytes to %s\n", len(sealed), dest)
		fmt.Fprintf(os.Stderr, "Environments: %s\n", strings.Join(includedEnvs, ", "))
		fmt.Fprintf(os.Stderr, "Keys: %d\n", len(includedKeys))
	}
	return nil
}

func formatEnvList(envs []vault.EnvGroupEntry) string {
	names := make([]string, len(envs))
	for i, e := range envs {
		names[i] = e.Name
	}
	return strings.Join(names, ", ")
}

func appendIfMissing(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
