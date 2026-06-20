package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/identity"
)

var (
	ciProvider string
	ciMode     string
	ciIdentity string
	ciOutput   string
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "CI/CD integration helpers",
	Long:  `Commands for integrating TinyVault with CI/CD pipelines.`,
}

var ciInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate CI/CD configuration files",
	Long: `Generate CI/CD configuration files for your pipeline.

Supported providers:
  github-actions  Generate GitHub Actions workflow
  gitlab          Generate GitLab CI configuration snippet

Two secret-transport modes:
  passphrase (default)  CI holds TVAULT_PASSPHRASE and reads the vault.
  identity              CI holds a per-context identity (TVAULT_IDENTITY_KEY)
                        and decrypts committed/recipient-sealed secrets with NO
                        passphrase. Provision it with 'tvault identity export'.

Examples:
  tvault ci init --provider=github-actions
  tvault ci init --provider=github-actions --mode=identity --identity=ci
  tvault ci init --provider=gitlab --mode=identity --output=-`,
	RunE: runCIInit,
}

func init() {
	rootCmd.AddCommand(ciCmd)
	ciCmd.AddCommand(ciInitCmd)
	ciInitCmd.Flags().StringVar(&ciProvider, "provider", "", "CI/CD provider (github-actions, gitlab)")
	ciInitCmd.Flags().StringVar(&ciMode, "mode", "passphrase", "Secret transport: passphrase | identity")
	ciInitCmd.Flags().StringVar(&ciIdentity, "identity", "default", "Identity name baked into the workflow (identity mode)")
	ciInitCmd.Flags().StringVar(&ciOutput, "output", "", "Write here; '-' prints to stdout (default: the provider's conventional path)")
	//nolint:errcheck
	ciInitCmd.MarkFlagRequired("provider")
}

func runCIInit(_ *cobra.Command, _ []string) error {
	switch ciMode {
	case "passphrase", "identity":
	default:
		return fmt.Errorf("unknown mode: %s (valid: passphrase, identity)", ciMode)
	}
	if ciMode == "identity" && !identity.ValidName(ciIdentity) {
		return fmt.Errorf("invalid identity name %q (use letters, digits, '-', '_')", ciIdentity)
	}

	switch ciProvider {
	case "github-actions":
		return generateGitHubActions()
	case "gitlab":
		return generateGitLabCI()
	default:
		return fmt.Errorf("unknown provider: %s (valid: github-actions, gitlab)", ciProvider)
	}
}

// emitCIArtifact writes content to ciOutput, or to defaultPath when ciOutput is
// empty, or to stdout when ciOutput is "-". File targets refuse to overwrite.
// nextSteps is printed to stderr after a file write (not for stdout).
func emitCIArtifact(defaultPath, content string, nextSteps []string) error {
	if ciOutput == "-" {
		fmt.Print(content)
		return nil
	}
	dest := ciOutput
	if dest == "" {
		dest = defaultPath
	}
	if dir := filepath.Dir(dest); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("file %s already exists. Remove it first to regenerate", dest)
	}
	if err := os.WriteFile(dest, []byte(content), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", dest, err)
	}
	fmt.Fprintf(os.Stderr, "Created %s\n", dest)
	if len(nextSteps) > 0 {
		fmt.Fprintln(os.Stderr, "\nNext steps:")
		for _, s := range nextSteps {
			fmt.Fprintf(os.Stderr, "  %s\n", s)
		}
	}
	return nil
}

func generateGitHubActions() error {
	if ciMode == "identity" {
		return emitCIArtifact(".github/workflows/tinyvault-secrets.yml",
			githubIdentityWorkflow(ciIdentity),
			[]string{
				"tvault identity new " + ciIdentity,
				"tvault projects share <recipient>   # or add it to .tvault-recipients",
				"tvault identity export " + ciIdentity + " --force | gh secret set TVAULT_IDENTITY_KEY",
				"commit .gitattributes / .tvault-recipients / encrypted files and this workflow",
			})
	}
	return emitCIArtifact(".github/workflows/tinyvault-secrets.yml",
		githubPassphraseWorkflow(),
		[]string{
			"Add TVAULT_PASSPHRASE to your repository secrets",
			"Reference this workflow from your main workflow",
			"Commit and push the workflow file",
		})
}

func generateGitLabCI() error {
	content := gitlabPassphraseSnippet()
	if ciMode == "identity" {
		content = gitlabIdentitySnippet(ciIdentity)
	}
	// GitLab's artifact is a snippet to paste; default to stdout.
	if ciOutput == "" {
		ciOutput = "-"
	}
	return emitCIArtifact(".gitlab-ci.tinyvault.yml", content, nil)
}

func githubPassphraseWorkflow() string {
	return `# TinyVault Secrets Workflow (passphrase mode)
# Injects secrets from a TinyVault into your CI/CD pipeline.
#
# Required secrets:
#   TVAULT_PASSPHRASE: Vault passphrase for decryption
#
# Setup:
#   1. Commit your vault file (.tvault/vault.db) to the repo or store it as artifact
#   2. Add TVAULT_PASSPHRASE to your repository secrets
#   3. Call this workflow from your main workflow

name: TinyVault Secrets

on:
  workflow_call:
    secrets:
      TVAULT_PASSPHRASE:
        required: true

jobs:
  load-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install TinyVault CLI
        run: |
          curl -fsSL https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault-linux-amd64 -o tvault
          chmod +x tvault
          sudo mv tvault /usr/local/bin/

      - name: Load secrets from TinyVault
        env:
          TVAULT_PASSPHRASE: ${{ secrets.TVAULT_PASSPHRASE }}
        run: |
          tvault env --format=shell --export=false >> $GITHUB_ENV
          echo "Secrets loaded successfully"
`
}

func githubIdentityWorkflow(identity string) string {
	return `# TinyVault Secrets Workflow (identity mode — NO passphrase)
# Decrypts committed / recipient-sealed secrets with a per-context identity.
#
# Required secrets:
#   TVAULT_IDENTITY_KEY: a private identity (tvault-key1…). The runner decrypts
#                        with it; the master passphrase never leaves your machine.
#
# One-time bootstrap:
#   1. tvault identity new ` + identity + `
#   2. add its recipient to .tvault-recipients (git-filter) or
#      tvault projects share <recipient> (vault-backed)
#   3. tvault identity export ` + identity + ` --force | gh secret set TVAULT_IDENTITY_KEY
#   4. commit .gitattributes / .tvault-recipients / your *.encrypted files and this workflow

name: TinyVault Secrets

on:
  workflow_call:
    secrets:
      TVAULT_IDENTITY_KEY:
        required: true

jobs:
  load-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install TinyVault CLI
        run: |
          curl -fsSL https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault-linux-amd64 -o tvault
          chmod +x tvault
          sudo mv tvault /usr/local/bin/

      - name: Decrypt secrets with the CI identity
        env:
          TVAULT_IDENTITY_KEY: ${{ secrets.TVAULT_IDENTITY_KEY }}
        run: |
          if [ -z "$TVAULT_IDENTITY_KEY" ]; then
            echo "TVAULT_IDENTITY_KEY is not set" >&2
            exit 1
          fi
          # Pick ONE of the following, matching how you committed your secrets:
          #
          # (a) git-filter — files tracked in .gitattributes auto-decrypt on
          #     checkout because TVAULT_IDENTITY_KEY is in the environment:
          # tvault git-filter checkout
          #
          # (b) a committed .env.encrypted (v2 / recipient-sealed):
          tvault decrypt-env --in .env.encrypted --out .env
          #
          # (c) a vault-backed shared project (no passphrase, identity read):
          # tvault env --format=shell --export=false --identity ` + identity + ` >> $GITHUB_ENV
          echo "Secrets decrypted successfully"
`
}

func gitlabPassphraseSnippet() string {
	return `# TinyVault GitLab CI Integration (passphrase mode)
#
# Add this to your .gitlab-ci.yml file
#
# Required CI/CD variables:
#   TVAULT_PASSPHRASE: Vault passphrase for decryption

.load_tinyvault_secrets:
  before_script:
    - |
      curl -fsSL https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault-linux-amd64 -o /usr/local/bin/tvault
      chmod +x /usr/local/bin/tvault
      eval $(tvault env --format=shell)
      echo "TinyVault secrets loaded"

# Example usage:
#
# build:
#   extends: .load_tinyvault_secrets
#   stage: build
#   script:
#     - echo "Building with DATABASE_URL=$DATABASE_URL"
#     - npm run build
`
}

func gitlabIdentitySnippet(identity string) string {
	return `# TinyVault GitLab CI Integration (identity mode — NO passphrase)
#
# Add this to your .gitlab-ci.yml file.
#
# Required (masked) CI/CD variable:
#   TVAULT_IDENTITY_KEY: a private identity (tvault-key1…). Decryption uses it;
#                        the master passphrase never leaves your machine.
#
# One-time bootstrap:
#   1. tvault identity new ` + identity + `
#   2. add its recipient to .tvault-recipients, or tvault projects share <recipient>
#   3. tvault identity export ` + identity + ` --force   # paste into the masked CI/CD variable
#   4. commit .gitattributes / .tvault-recipients / your *.encrypted files

.load_tinyvault_secrets:
  before_script:
    - |
      if [ -z "$TVAULT_IDENTITY_KEY" ]; then echo "TVAULT_IDENTITY_KEY is not set" >&2; exit 1; fi
      curl -fsSL https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault-linux-amd64 -o /usr/local/bin/tvault
      chmod +x /usr/local/bin/tvault
      # Pick ONE, matching how you committed your secrets:
      # tvault git-filter checkout                                   # (a) git-filter
      tvault decrypt-env --in .env.encrypted --out .env             # (b) committed v2 file
      # eval $(tvault env --format=shell --identity ` + identity + `)   # (c) shared project
      echo "TinyVault secrets decrypted"

# Example usage:
#
# build:
#   extends: .load_tinyvault_secrets
#   stage: build
#   script:
#     - npm run build
`
}
