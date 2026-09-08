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
	Short: "Clear stored auth tokens and keys, keeping remembered login details.",
	RunE: func(cmd *cobra.Command, args []string) error {
		creds, err := keyring.LoadProfile(activeProfile.Name)
		if err == nil && creds.Remember {
			creds.AccessToken, creds.RefreshToken, creds.EncKey = "", "", ""
			if err := keyring.SaveProfile(activeProfile.Name, creds); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Vault locked; login details remembered")
			return nil
		}
		if err := keyring.DeleteProfile(activeProfile.Name); err != nil {
			return fmt.Errorf("clearing keyring: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Vault locked")
		return nil
	},
}
