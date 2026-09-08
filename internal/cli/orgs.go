package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(orgsCmd)
}

var orgsCmd = &cobra.Command{
	Use:   "orgs",
	Short: "List available organizations.",
	Long:  "Syncs the vault and prints organizations you belong to.",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, _, err := getClient(cmd.Context())
		if err != nil {
			return err
		}

		syncResp, err := client.Sync(cmd.Context())
		if err != nil {
			return fmt.Errorf("syncing vault: %w", err)
		}

		if len(syncResp.Profile.Organizations) == 0 {
			fmt.Fprintln(os.Stderr, "No organizations")
			return nil
		}

		for _, org := range syncResp.Profile.Organizations {
			fmt.Fprintf(os.Stderr, "%s  (%s)\n", org.Name, org.ID)
		}
		return nil
	},
}
