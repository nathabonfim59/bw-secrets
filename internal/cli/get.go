package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/nathabonfim59/bw-secrets/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(getCmd)
}

var reveal bool

var getCmd = &cobra.Command{
	Use:   "get <uri>",
	Short: "Resolve a bw:// secret reference. Use --reveal to output the value.",
	Long: `Resolves a bw://VaultName/ItemName/FieldName reference.
By default, only metadata is shown. Use --reveal to output the actual value.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, creds, err := getClient()
		if err != nil {
			return err
		}

		symKey, err := getSymmetricKey(creds)
		if err != nil {
			return err
		}

		syncResp, err := client.Sync(context.Background())
		if err != nil {
			return fmt.Errorf("syncing vault: %w", err)
		}

		v := vault.New(syncResp, symKey)

		uri, err := vault.ParseURI(args[0])
		if err != nil {
			return err
		}

		value, vaultName, itemName, err := v.ResolveValue(uri, symKey)
		if err != nil {
			return err
		}

		if reveal {
			fmt.Println(value)
		} else {
			fmt.Fprintf(os.Stderr, "resolved: %s/%s/%s (use --reveal to output)\n",
				vaultName, itemName, uri.FieldName)
		}
		return nil
	},
}

func init() {
	getCmd.Flags().BoolVar(&reveal, "reveal", false, "Output the actual secret value")
}
