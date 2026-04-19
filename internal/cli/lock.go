package cli

import (
	"fmt"
	"os"

	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(lockCmd)
}

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Remove stored credentials from the OS keyring.",
	Long:  "Clears all stored auth tokens and keys, locking the vault.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := keyring.Delete(); err != nil {
			return fmt.Errorf("clearing keyring: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Vault locked")
		return nil
	},
}
