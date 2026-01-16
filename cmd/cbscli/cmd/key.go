package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage issuer keys",
	Long:  `Commands for managing keys for issuers in the Challenge Bypass Server.`,
}

// Flags for key commands
var (
	keyIssuerID       string
	keyIncludeExpired bool
	keyStartAt        string
	keyEndAt          string
	keyRotateCount    int
)

// keyListCmd represents the key list command
var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys for an issuer",
	Long: `List all keys for a specific issuer.

Examples:
  # List active keys for an issuer
  cbscli key list --issuer <issuer-id>

  # List all keys including expired ones
  cbscli key list --issuer <issuer-id> --include-expired`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		if keyIssuerID == "" {
			return fmt.Errorf("--issuer is required")
		}

		client := NewClient(serverURL, authToken)
		result, err := client.ListKeys(keyIssuerID, keyIncludeExpired)
		if err != nil {
			return fmt.Errorf("failed to list keys: %w", err)
		}

		if outputFmt == "json" {
			return printJSON(result)
		}

		return printKeyTable(result.Keys)
	},
}

// keyGetCmd represents the key get command
var keyGetCmd = &cobra.Command{
	Use:   "get <key-id>",
	Short: "Get a key by ID",
	Long:  `Get detailed information about a specific key by its ID.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		if keyIssuerID == "" {
			return fmt.Errorf("--issuer is required")
		}

		keyID := args[0]
		client := NewClient(serverURL, authToken)
		result, err := client.GetKey(keyIssuerID, keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		if outputFmt == "json" {
			return printJSON(result)
		}

		return printKeyDetail(result)
	},
}

// keyCreateCmd represents the key create command
var keyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key for an issuer",
	Long: `Create a new signing key for an issuer.

For v3 issuers, you can specify start and end times for the key validity window.
For v1/v2 issuers, the key is created without time bounds.

Examples:
  # Create a key with default settings
  cbscli key create --issuer <issuer-id>

  # Create a key with specific time bounds
  cbscli key create --issuer <issuer-id> \
    --start-at "2024-01-01T00:00:00Z" \
    --end-at "2024-01-08T00:00:00Z"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		if keyIssuerID == "" {
			return fmt.Errorf("--issuer is required")
		}

		req := &CreateKeyRequest{}
		if keyStartAt != "" {
			req.StartAt = &keyStartAt
		}
		if keyEndAt != "" {
			req.EndAt = &keyEndAt
		}

		client := NewClient(serverURL, authToken)
		result, err := client.CreateKey(keyIssuerID, req)
		if err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		if outputFmt == "json" {
			return printJSON(result)
		}

		fmt.Println("Key created successfully")
		return printKeyDetail(result)
	},
}

// keyDeleteCmd represents the key delete command
var keyDeleteCmd = &cobra.Command{
	Use:   "delete <key-id>",
	Short: "Delete a key",
	Long: `Delete a specific key by its ID.

WARNING: Deleting a key will prevent redemption of tokens signed with that key.
Only delete keys that are no longer needed.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		if keyIssuerID == "" {
			return fmt.Errorf("--issuer is required")
		}

		keyID := args[0]
		client := NewClient(serverURL, authToken)
		if err := client.DeleteKey(keyIssuerID, keyID); err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}

		fmt.Printf("Key %s deleted successfully\n", keyID)
		return nil
	},
}

// keyRotateCmd represents the key rotate command
var keyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate keys for an issuer",
	Long: `Create new keys for an issuer, extending the key rotation schedule.

For v3 issuers, new keys are created with time windows that follow the existing keys.
The time windows are calculated based on the issuer's duration setting.

For v1/v2 issuers, a single new key is created without time bounds.

Examples:
  # Rotate with default settings (create 1 new key)
  cbscli key rotate --issuer <issuer-id>

  # Create multiple new keys
  cbscli key rotate --issuer <issuer-id> --count 3`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		if keyIssuerID == "" {
			return fmt.Errorf("--issuer is required")
		}

		count := keyRotateCount
		if count <= 0 {
			count = 1
		}

		client := NewClient(serverURL, authToken)
		result, err := client.RotateKeys(keyIssuerID, count)
		if err != nil {
			return fmt.Errorf("failed to rotate keys: %w", err)
		}

		if outputFmt == "json" {
			return printJSON(result)
		}

		fmt.Printf("%s\n", result.Message)
		fmt.Printf("Created %d new key(s):\n\n", len(result.CreatedKeys))
		return printKeyTable(result.CreatedKeys)
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)

	// Add subcommands to key
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyGetCmd)
	keyCmd.AddCommand(keyCreateCmd)
	keyCmd.AddCommand(keyDeleteCmd)
	keyCmd.AddCommand(keyRotateCmd)

	// Global flag for all key commands
	keyCmd.PersistentFlags().StringVar(&keyIssuerID, "issuer", "", "Issuer ID (required)")

	// Flags for list command
	keyListCmd.Flags().BoolVar(&keyIncludeExpired, "include-expired", false, "Include expired keys in the list")

	// Flags for create command
	keyCreateCmd.Flags().StringVar(&keyStartAt, "start-at", "", "Key validity start time (RFC3339 format)")
	keyCreateCmd.Flags().StringVar(&keyEndAt, "end-at", "", "Key validity end time (RFC3339 format)")

	// Flags for rotate command
	keyRotateCmd.Flags().IntVar(&keyRotateCount, "count", 1, "Number of new keys to create")
}

// printKeyTable prints keys in a table format
func printKeyTable(keys []IssuerKeyResponse) error {
	if len(keys) == 0 {
		fmt.Println("No keys found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tPUBLIC KEY\tSTART\tEND\tCREATED")
	fmt.Fprintln(w, "--\t----------\t-----\t---\t-------")

	for _, key := range keys {
		publicKey := key.PublicKey
		if len(publicKey) > 16 {
			publicKey = publicKey[:16] + "..."
		}

		startAt := "n/a"
		if key.StartAt != nil {
			if t, err := time.Parse(time.RFC3339, *key.StartAt); err == nil {
				startAt = t.Format("2006-01-02 15:04")
			}
		}

		endAt := "n/a"
		if key.EndAt != nil {
			if t, err := time.Parse(time.RFC3339, *key.EndAt); err == nil {
				endAt = t.Format("2006-01-02 15:04")
			}
		}

		createdAt := "n/a"
		if key.CreatedAt != nil {
			if t, err := time.Parse(time.RFC3339, *key.CreatedAt); err == nil {
				createdAt = t.Format("2006-01-02 15:04")
			}
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			key.ID,
			publicKey,
			startAt,
			endAt,
			createdAt,
		)
	}

	return w.Flush()
}

// printKeyDetail prints detailed key information
func printKeyDetail(key *IssuerKeyResponse) error {
	fmt.Printf("ID:         %s\n", key.ID)
	fmt.Printf("Public Key: %s\n", key.PublicKey)
	fmt.Printf("Cohort:     %d\n", key.Cohort)

	if key.StartAt != nil {
		fmt.Printf("Start At:   %s\n", *key.StartAt)
	} else {
		fmt.Println("Start At:   n/a")
	}

	if key.EndAt != nil {
		fmt.Printf("End At:     %s\n", *key.EndAt)
	} else {
		fmt.Println("End At:     n/a")
	}

	if key.CreatedAt != nil {
		fmt.Printf("Created At: %s\n", *key.CreatedAt)
	}

	return nil
}
