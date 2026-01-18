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
	cfgFile   string
	apiURL    string
	projectID string
	verbose   bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "tvault",
	Short: "TinyVault CLI - Dead simple secrets management",
	Long: `TinyVault CLI (tvault) helps you manage secrets securely.

Get started:
  tvault login        Authenticate with GitHub
  tvault projects     List your projects
  tvault get KEY      Get a secret value
  tvault set KEY VAL  Set a secret value
  tvault run CMD      Run command with secrets as env vars

Examples:
  tvault login
  tvault projects create my-app
  tvault use my-app
  tvault set DATABASE_URL "postgres://..."
  tvault get DATABASE_URL
  tvault run npm start`,
	SilenceUsage: true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default $HOME/.tvault.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "https://tinyvault.dev", "TinyVault API URL")
	rootCmd.PersistentFlags().StringVarP(&projectID, "project", "p", "", "Project ID or name")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output for debugging")

	viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
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

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".tvault")
	}

	viper.SetEnvPrefix("TVAULT")
	viper.AutomaticEnv()

	// Load config file if it exists
	_ = viper.ReadInConfig()
}

// getConfigPath returns the path to the config file
func getConfigPath() string {
	if cfgFile != "" {
		return cfgFile
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".tvault.yaml")
}

// getAPIURL returns the API URL
func getAPIURL() string {
	if url := viper.GetString("api_url"); url != "" {
		return url
	}
	return "https://tinyvault.dev"
}

// getToken returns the stored API token
func getToken() string {
	return viper.GetString("token")
}

// getProject returns the current project
func getProject() string {
	if projectID != "" {
		return projectID
	}
	return viper.GetString("project")
}

// isVerbose returns whether verbose mode is enabled
func isVerbose() bool {
	if verbose {
		return true
	}
	return viper.GetBool("verbose")
}
