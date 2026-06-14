package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

var projectShareCmd = &cobra.Command{
	Use:   "share <recipient>",
	Short: "Share a project with an X25519 recipient",
	Long: `Grant a recipient (a tvault1… public key) access to a project by
wrapping the project's data key to it. The recipient can then decrypt the
project with their private identity — without the vault passphrase
(e.g. 'tvault env --identity <name>').

The recipient string comes from 'tvault identity new' (yours or a
teammate's / CI's). Requires the vault unlocked.

Examples:
  tvault projects share tvault1abc…
  tvault projects share tvault1abc… -p webapp`,
	Args: cobra.ExactArgs(1),
	RunE: runProjectShare,
}

var projectUnshareCmd = &cobra.Command{
	Use:   "unshare <recipient>",
	Short: "Revoke a recipient's access to a project (rotates the key)",
	Long: `Revoke a recipient. Because the recipient already holds the project's
data key, this is a true revocation: the project key is rotated and every
secret re-encrypted, so the removed recipient can no longer decrypt
anything — even from an old copy of the vault. Remaining recipients keep
access. Requires the vault unlocked.`,
	Args: cobra.ExactArgs(1),
	RunE: runProjectUnshare,
}

var projectRecipientsCmd = &cobra.Command{
	Use:   "recipients",
	Short: "List the recipients a project is shared with",
	RunE:  runProjectRecipients,
}

func init() {
	projectsCmd.AddCommand(projectShareCmd, projectUnshareCmd, projectRecipientsCmd)
}

func runProjectShare(_ *cobra.Command, args []string) error {
	recipient, err := crypto.DecodeRecipient(args[0])
	if err != nil {
		return err
	}
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()
	project := resolveProject(v, projectName)
	if err := v.ShareProject(project, recipient); err != nil {
		return fmt.Errorf("failed to share project: %w", err)
	}
	recordAudit(v, "project.share", "project", project, map[string]any{"recipient": args[0]})
	Success("Shared project '%s' with %s", project, args[0])
	fmt.Fprintln(os.Stderr, "They can read it with: tvault env --identity <name>")
	return nil
}

func runProjectUnshare(_ *cobra.Command, args []string) error {
	recipient, err := crypto.DecodeRecipient(args[0])
	if err != nil {
		return err
	}
	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()
	project := resolveProject(v, projectName)
	if err := v.UnshareProject(project, recipient); err != nil {
		return fmt.Errorf("failed to unshare project: %w", err)
	}
	recordAudit(v, "project.unshare", "project", project, map[string]any{"recipient": args[0]})
	Success("Revoked %s from project '%s' (key rotated, secrets re-encrypted)", args[0], project)
	return nil
}

func runProjectRecipients(_ *cobra.Command, _ []string) error {
	// Read-only metadata: no unlock needed.
	dir := getVaultDir()
	v, err := vault.Open(dir)
	if err != nil {
		return fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
	}
	defer v.Close()
	project := resolveProject(v, projectName)
	recips, err := v.ProjectRecipients(project)
	if err != nil {
		return fmt.Errorf("failed to list recipients: %w", err)
	}
	encoded := make([]string, 0, len(recips))
	for _, r := range recips {
		encoded = append(encoded, crypto.EncodeRecipient(r))
	}
	if jsonOutput {
		return writeJSON(map[string]any{"project": project, "recipients": encoded})
	}
	if len(encoded) == 0 {
		fmt.Fprintf(os.Stderr, "Project '%s' is not shared with anyone.\n", project)
		return nil
	}
	for _, r := range encoded {
		fmt.Println(r)
	}
	return nil
}
