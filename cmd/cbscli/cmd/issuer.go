package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// issuerCmd represents the issuer command
var issuerCmd = &cobra.Command{
	Use:   "issuer",
	Short: "Manage issuers",
	Long:  `Commands for managing issuers in the Challenge Bypass Server.`,
}

// issuerListCmd represents the issuer list command
var issuerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all issuers",
	Long:  `List all issuers in the Challenge Bypass Server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		client := NewClient(serverURL, authToken)
		result, err := client.ListIssuers()
		if err != nil {
			return fmt.Errorf("failed to list issuers: %w", err)
		}

		if outputFmt == "json" {
			return printJSON(result)
		}

		return printIssuerTable(result.Issuers)
	},
}

// issuerGetCmd represents the issuer get command
var issuerGetCmd = &cobra.Command{
	Use:   "get <issuer-id>",
	Short: "Get an issuer by ID",
	Long:  `Get detailed information about a specific issuer by its ID.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		issuerID := args[0]
		client := NewClient(serverURL, authToken)
		result, err := client.GetIssuer(issuerID)
		if err != nil {
			return fmt.Errorf("failed to get issuer: %w", err)
		}

		if outputFmt == "json" {
			return printJSON(result)
		}

		return printIssuerDetail(result)
	},
}

// Flags for issuer create command
var (
	createName      string
	createCohort    int16
	createMaxTokens int
	createVersion   int
	createExpiresAt string
	createValidFrom string
	createDuration  string
	createBuffer    int
	createOverlap   int
)

// issuerCreateCmd represents the issuer create command
var issuerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new issuer",
	Long: `Create a new issuer in the Challenge Bypass Server.

Examples:
  # Create a v3 issuer with time-based keys
  cbscli issuer create --name "ads-issuer" --cohort 1 --version 3 \
    --buffer 2 --overlap 1 --duration "P7D" --expires-at "2030-01-01T00:00:00Z"

  # Create a v1/v2 issuer (simpler, single key)
  cbscli issuer create --name "simple-issuer" --cohort 1 --version 1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		if createName == "" {
			return fmt.Errorf("--name is required")
		}

		// Build the request
		req := &CreateIssuerRequest{
			Name:      createName,
			Cohort:    createCohort,
			MaxTokens: createMaxTokens,
			Version:   createVersion,
			Duration:  createDuration,
			Buffer:    createBuffer,
			Overlap:   createOverlap,
		}

		// Parse and set optional time fields
		if createExpiresAt != "" {
			req.ExpiresAt = &createExpiresAt
		}

		if createValidFrom != "" {
			req.ValidFrom = &createValidFrom
		}

		client := NewClient(serverURL, authToken)
		if err := client.CreateIssuer(req); err != nil {
			return fmt.Errorf("failed to create issuer: %w", err)
		}

		fmt.Println("Issuer created successfully")
		return nil
	},
}

// Flag for force delete
var forceDelete bool

// issuerDeleteCmd represents the issuer delete command
var issuerDeleteCmd = &cobra.Command{
	Use:   "delete <issuer-id>",
	Short: "Delete an issuer",
	Long: `Delete an issuer and all its associated keys by ID.

By default, deletion is prevented if the issuer has active keys that could
still be used for token signing or redemption. This protects against
accidentally invalidating tokens that are still in use.

To safely deprecate an issuer:
  1. Stop issuing new tokens with this issuer
  2. Set an expires_at time if not already set
  3. Wait for all keys to expire (past their end_at times)
  4. Then delete the issuer

Use --force to bypass these safety checks (use with caution).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkAuthToken(); err != nil {
			return err
		}

		issuerID := args[0]
		client := NewClient(serverURL, authToken)
		if err := client.DeleteIssuer(issuerID, forceDelete); err != nil {
			return fmt.Errorf("failed to delete issuer: %w", err)
		}

		fmt.Printf("Issuer %s deleted successfully\n", issuerID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(issuerCmd)

	// Add subcommands to issuer
	issuerCmd.AddCommand(issuerListCmd)
	issuerCmd.AddCommand(issuerGetCmd)
	issuerCmd.AddCommand(issuerCreateCmd)
	issuerCmd.AddCommand(issuerDeleteCmd)

	// Flags for create command
	issuerCreateCmd.Flags().StringVar(&createName, "name", "", "Issuer name/type (required)")
	issuerCreateCmd.Flags().Int16Var(&createCohort, "cohort", 0, "Issuer cohort")
	issuerCreateCmd.Flags().IntVar(&createMaxTokens, "max-tokens", 40, "Maximum tokens per request")
	issuerCreateCmd.Flags().IntVar(&createVersion, "version", 3, "Issuer version (1, 2, or 3)")
	issuerCreateCmd.Flags().StringVar(&createExpiresAt, "expires-at", "", "Expiration time (RFC3339 format)")
	issuerCreateCmd.Flags().StringVar(&createValidFrom, "valid-from", "", "Valid from time (RFC3339 format, v3 only)")
	issuerCreateCmd.Flags().StringVar(&createDuration, "duration", "", "Key duration (ISO 8601 format, e.g., P7D for 7 days, v3 only)")
	issuerCreateCmd.Flags().IntVar(&createBuffer, "buffer", 0, "Number of active keys to maintain (v3 only)")
	issuerCreateCmd.Flags().IntVar(&createOverlap, "overlap", 0, "Extra buffer keys for overlap (v3 only)")

	issuerCreateCmd.MarkFlagRequired("name")

	// Flags for delete command
	issuerDeleteCmd.Flags().BoolVar(&forceDelete, "force", false, "Force deletion even if issuer has active keys (dangerous)")
}

// printJSON outputs the result as formatted JSON
func printJSON(v interface{}) error {
	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// printIssuerTable prints issuers in a table format
func printIssuerTable(issuers []IssuerDetailResponse) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tCOHORT\tVERSION\tKEYS\tEXPIRES AT")
	fmt.Fprintln(w, "--\t----\t------\t-------\t----\t----------")

	for _, issuer := range issuers {
		expiresAt := "never"
		if issuer.ExpiresAt != nil {
			if t, err := time.Parse(time.RFC3339, *issuer.ExpiresAt); err == nil {
				expiresAt = t.Format("2006-01-02")
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n",
			issuer.ID,
			issuer.Name,
			issuer.Cohort,
			issuer.Version,
			len(issuer.Keys),
			expiresAt,
		)
	}

	return w.Flush()
}

// printIssuerDetail prints detailed issuer information
func printIssuerDetail(issuer *IssuerDetailResponse) error {
	fmt.Printf("ID:         %s\n", issuer.ID)
	fmt.Printf("Name:       %s\n", issuer.Name)
	fmt.Printf("Cohort:     %d\n", issuer.Cohort)
	fmt.Printf("Version:    %d\n", issuer.Version)
	fmt.Printf("Max Tokens: %d\n", issuer.MaxTokens)

	if issuer.ExpiresAt != nil {
		fmt.Printf("Expires At: %s\n", *issuer.ExpiresAt)
	}

	if issuer.CreatedAt != nil {
		fmt.Printf("Created At: %s\n", *issuer.CreatedAt)
	}

	if issuer.Version == 3 {
		fmt.Printf("Buffer:     %d\n", issuer.Buffer)
		fmt.Printf("Overlap:    %d\n", issuer.Overlap)
		if issuer.Duration != nil {
			fmt.Printf("Duration:   %s\n", *issuer.Duration)
		}
		if issuer.ValidFrom != nil {
			fmt.Printf("Valid From: %s\n", *issuer.ValidFrom)
		}
	}

	if len(issuer.Keys) > 0 {
		fmt.Printf("\nKeys (%d):\n", len(issuer.Keys))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  PUBLIC KEY\tSTART\tEND")
		fmt.Fprintln(w, "  ----------\t-----\t---")

		for _, key := range issuer.Keys {
			publicKey := key.PublicKey
			if len(publicKey) > 20 {
				publicKey = publicKey[:20] + "..."
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

			fmt.Fprintf(w, "  %s\t%s\t%s\n", publicKey, startAt, endAt)
		}
		w.Flush()
	}

	return nil
}
