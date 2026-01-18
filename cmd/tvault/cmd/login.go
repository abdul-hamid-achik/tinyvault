package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with TinyVault",
	Long: `Authenticate with TinyVault using an API token.

You can create an API token at https://tinyvault.dev/settings/tokens

The token will be stored in ~/.tvault.yaml`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	fmt.Println("TinyVault Login")
	fmt.Println("===============")
	fmt.Println()
	fmt.Println("Create an API token at: https://tinyvault.dev/settings/tokens")
	fmt.Println()
	fmt.Print("Enter your API token: ")

	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	// Validate the token by making a request
	client := NewClient(getAPIURL(), token)
	user, err := client.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	// Save the token
	viper.Set("token", token)
	configPath := getConfigPath()
	if err := viper.WriteConfigAs(configPath); err != nil {
		// Create the config file if it doesn't exist
		if err := viper.SafeWriteConfigAs(configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}
	// Set restrictive file permissions (owner read/write only)
	if err := os.Chmod(configPath, 0600); err != nil {
		return fmt.Errorf("failed to set config file permissions: %w", err)
	}

	fmt.Println()
	fmt.Printf("Logged in as %s (%s)\n", user.Username, user.Email)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  tvault projects list     List your projects")
	fmt.Println("  tvault projects create   Create a new project")
	fmt.Println("  tvault use <project>     Select a project")

	return nil
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of TinyVault",
	Long:  "Remove stored credentials from your machine.",
	RunE:  runLogout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

func runLogout(cmd *cobra.Command, args []string) error {
	viper.Set("token", "")
	viper.Set("project", "")

	if err := viper.WriteConfigAs(getConfigPath()); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("Logged out successfully")
	return nil
}
