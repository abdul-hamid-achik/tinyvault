// Package cmd provides the CLI commands for tvault.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	vaultDir    string
	projectName string
	jsonOutput  bool
	verbose     bool

	// Build-time metadata, set by main.go before Execute().
	// Default values are used during `go test`.
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetVersionInfo is called from main.go with build-time values
// (injected by goreleaser via -ldflags "-X main.version=...").
// It must be called before Execute().
func SetVersionInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
	rootCmd.Version = formatVersion()
}

// Version returns the build-time version string.
func Version() string { return buildVersion }

// formatVersion builds the "version (commit date)" string that
// `tvault --version` prints.
func formatVersion() string {
	return fmt.Sprintf("%s (commit %s, built %s)", buildVersion, buildCommit, buildDate)
}

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "tvault",
	Short: "TinyVault CLI - Dead simple local secrets management",
	Long: `TinyVault CLI (tvault) helps you manage secrets securely on your local machine.

Get started:
  tvault init              Initialize a new vault
  tvault set KEY VALUE     Set a secret
  tvault get KEY           Get a secret value
  tvault run -- CMD        Run command with secrets as env vars

For a long-form user manual (lifecycle, conventions, recipes, safety,
agent patterns, troubleshooting), see 'tvault help' or
'tvault help <topic>'.`,
	SilenceUsage: true,
	// Version is set at init() time below using the package-level
	// buildVersion default ("dev"); main.go calls SetVersionInfo
	// before Execute() to override it with build-time values.
	Version: formatVersion(),
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.tvault/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&vaultDir, "vault", "", "vault directory (default ~/.tvault)")
	rootCmd.PersistentFlags().StringVarP(&projectName, "project", "p", "", "project name")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	viper.BindPFlag("vault", rootCmd.PersistentFlags().Lookup("vault"))
	viper.BindPFlag("project", rootCmd.PersistentFlags().Lookup("project"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	// Replace cobra's auto-generated 'help' with our long-form manual.
	// Without this, 'tvault help' would just print the cobra command
	// listing; with it, the user gets the manual.
	rootCmd.SetHelpCommand(helpCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		configDir := filepath.Join(home, ".tvault")
		viper.AddConfigPath(configDir)
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.SetEnvPrefix("TVAULT")
	viper.AutomaticEnv()

	// Load config file if it exists.
	_ = viper.ReadInConfig()
}
