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
)

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

Examples:
  tvault init
  tvault set DATABASE_URL "postgres://..."
  tvault get DATABASE_URL
  tvault run -- npm start
  tvault env --format dotenv > .env`,
	SilenceUsage: true,
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

// isVerbose returns whether verbose mode is enabled.
func isVerbose() bool {
	if verbose {
		return true
	}
	return viper.GetBool("verbose")
}
