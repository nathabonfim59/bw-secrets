package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/nathabonfim59/bw-secrets/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listCmd)
}

var filterType string

var listCmd = &cobra.Command{
	Use:   "list [vault]",
	Short: "List items in your vault.",
	Long:  "Syncs the vault and lists all items, optionally filtered by vault name or item type.",
	Args:  cobra.MaximumNArgs(1),
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

		v := vault.New(syncResp, symKey, creds.Scope)

		vaultName := ""
		if len(args) > 0 {
			vaultName = args[0]
		}

		typeFilter := typeNameToInt(filterType)

		for _, dc := range v.Items() {
			if vaultName != "" && dc.VaultName != vaultName {
				continue
			}
			if typeFilter != 0 && dc.Cipher.Type != typeFilter {
				continue
			}
			fmt.Fprintf(os.Stderr, "[%s] %s\n", dc.VaultName, dc.Name)
		}
		return nil
	},
}

func init() {
	listCmd.Flags().StringVar(&filterType, "type", "", "Filter by type: login, note, card, identity")
}

func typeNameToInt(name string) int {
	switch name {
	case "login":
		return 1
	case "note":
		return 2
	case "card":
		return 3
	case "identity":
		return 4
	}
	return 0
}
