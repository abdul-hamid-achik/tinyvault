package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	ciProvider string
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

Examples:
  tvault ci init --provider=github-actions
  tvault ci init --provider=gitlab`,
	RunE: runCIInit,
}

func init() {
	rootCmd.AddCommand(ciCmd)
	ciCmd.AddCommand(ciInitCmd)
	ciInitCmd.Flags().StringVar(&ciProvider, "provider", "", "CI/CD provider (github-actions, gitlab)")
	//nolint:errcheck
	ciInitCmd.MarkFlagRequired("provider")
}

func runCIInit(_ *cobra.Command, _ []string) error {
	switch ciProvider {
	case "github-actions":
		return generateGitHubActions()
	case "gitlab":
		return generateGitLabCI()
	default:
		return fmt.Errorf("unknown provider: %s (valid: github-actions, gitlab)", ciProvider)
	}
}

func generateGitHubActions() error {
	workflowsDir := ".github/workflows"
	if err := os.MkdirAll(workflowsDir, 0o750); err != nil {
		return fmt.Errorf("failed to create workflows directory: %w", err)
	}

	workflowPath := filepath.Join(workflowsDir, "tinyvault-secrets.yml")

	if _, err := os.Stat(workflowPath); err == nil {
		return fmt.Errorf("file %s already exists. Remove it first to regenerate", workflowPath)
	}

	workflow := `# TinyVault Secrets Workflow
# This workflow injects secrets from a local TinyVault into your CI/CD pipeline.
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

	if err := os.WriteFile(workflowPath, []byte(workflow), 0o600); err != nil {
		return fmt.Errorf("failed to write workflow file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Created %s\n", workflowPath)
	fmt.Fprintln(os.Stderr, "\nNext steps:")
	fmt.Fprintln(os.Stderr, "1. Add TVAULT_PASSPHRASE to your repository secrets")
	fmt.Fprintln(os.Stderr, "2. Reference this workflow from your main workflow")
	fmt.Fprintln(os.Stderr, "3. Commit and push the workflow file")

	return nil
}

func generateGitLabCI() error {
	snippet := `# TinyVault GitLab CI Integration
#
# Add this to your .gitlab-ci.yml file
#
# Required CI/CD variables:
#   TVAULT_PASSPHRASE: Vault passphrase for decryption

.load_tinyvault_secrets:
  before_script:
    - |
      # Install TinyVault CLI
      curl -fsSL https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault-linux-amd64 -o /usr/local/bin/tvault
      chmod +x /usr/local/bin/tvault

      # Load secrets into environment
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

	fmt.Println(snippet)
	fmt.Fprintln(os.Stderr, "\nNext steps:")
	fmt.Fprintln(os.Stderr, "1. Add the snippet above to your .gitlab-ci.yml file")
	fmt.Fprintln(os.Stderr, "2. Configure TVAULT_PASSPHRASE in GitLab CI/CD variables")
	fmt.Fprintln(os.Stderr, "3. Extend .load_tinyvault_secrets in jobs that need secrets")

	return nil
}
