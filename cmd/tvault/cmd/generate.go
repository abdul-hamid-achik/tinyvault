package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

var (
	generateLength  int
	generateCharset string
)

var generateCmd = &cobra.Command{
	Use:   "generate <key>",
	Short: "Generate a random secret and store it (value is never printed)",
	Long: `Generate a cryptographically random secret, store it, and print only
metadata. The generated value is never written to stdout or stderr.

Default length is 32. Charset is one of alphanumeric (default), hex,
base64, or ascii. Maximum length is 256.

Examples:
  tvault generate SESSION_SECRET
  tvault generate API_KEY --length 48 --charset hex
  tvault generate TOKEN --json`,
	Args: cobra.ExactArgs(1),
	RunE: runGenerate,
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().IntVar(&generateLength, "length", 32, "Length of the generated secret (max 256)")
	generateCmd.Flags().StringVar(&generateCharset, "charset", "alphanumeric", "Charset: alphanumeric, hex, base64, or ascii")
}

func runGenerate(_ *cobra.Command, args []string) error {
	key := args[0]
	charset := generateCharset
	if charset == "" {
		charset = "alphanumeric"
	}
	length := generateLength
	if length <= 0 {
		length = 32
	}

	value, err := crypto.GenerateRandomString(length, charset)
	if err != nil {
		return fmt.Errorf("generate secret: %w", err)
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return err
	}
	defer v.Close()

	project := resolveProject(v, projectName)
	if err := v.SetSecret(project, key, value); err != nil {
		return fmt.Errorf("failed to store generated secret: %w", err)
	}
	recordAudit(v, "secret.generate", "secret", key, map[string]any{
		"project": project,
		"charset": charset,
		"length":  length,
	})

	if jsonOutput {
		return writeJSON(map[string]any{
			"key":     key,
			"length":  length,
			"charset": charset,
			"stored":  true,
		})
	}
	fmt.Fprintf(os.Stderr, "Generated and stored secret %q (%d %s)\n", key, length, charset)
	return nil
}
