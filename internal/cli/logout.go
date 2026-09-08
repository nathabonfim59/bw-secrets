package cli

import (
	"fmt"
	"os"

	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(logoutCmd)
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored credentials (same as lock).",
	Long:  "Removes stored auth tokens and keys for the selected profile.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := keyring.DeleteProfile(activeProfile.Name); err != nil {
			return fmt.Errorf("clearing keyring: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Logged out")
		return nil
	},
}
