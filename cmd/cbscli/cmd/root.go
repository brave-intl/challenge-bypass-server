package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	serverURL string
	authToken string
	outputFmt string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cbscli",
	Short: "Challenge Bypass Server CLI",
	Long: `cbscli is a command line interface for managing the Challenge Bypass Server.

It provides commands for managing issuers, keys, and other server resources.

Examples:
  # List all issuers
  cbscli issuer list

  # Get a specific issuer
  cbscli issuer get <issuer-id>

  # Create a new issuer
  cbscli issuer create --name "my-issuer" --cohort 1 --version 3`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags available to all commands
	rootCmd.PersistentFlags().StringVarP(&serverURL, "server", "s", getEnvOrDefault("CBS_SERVER_URL", "http://localhost:2416"), "Server URL")
	rootCmd.PersistentFlags().StringVarP(&authToken, "token", "t", os.Getenv("CBS_AUTH_TOKEN"), "Authentication token")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "Output format (table, json)")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// checkAuthToken validates that an auth token is provided
func checkAuthToken() error {
	if authToken == "" {
		return fmt.Errorf("authentication token is required. Set CBS_AUTH_TOKEN environment variable or use --token flag")
	}
	return nil
}
