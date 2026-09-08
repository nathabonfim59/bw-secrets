package cli

import (
	"cmp"
	"fmt"
	"os"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/spf13/cobra"
)

func init() { rootCmd.AddCommand(unlockCmd) }

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Re-authenticate when tokens have expired.",
	Long: `Loads stored server URL and email from the keyring, prompts for the
master password, and re-authenticates to obtain fresh tokens.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		creds, err := keyring.LoadProfile(activeProfile.Name)
		if err != nil {
			return err
		}
		url := strings.TrimRight(cmp.Or(serverURL(), creds.ServerURL), "/")
		newCreds, _, err := authenticate(cmd.Context(), api.NewClient(url), url, creds.Email)
		if err != nil {
			return err
		}
		newCreds.Remember, newCreds.Scope = creds.Remember, creds.Scope
		if err := keyring.SaveProfile(activeProfile.Name, newCreds); err != nil {
			return fmt.Errorf("saving to keyring: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Vault unlocked")
		return nil
	},
}
