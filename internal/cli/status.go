package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show login status.",
	Long:  "Displays whether you are logged in, to which server, and token expiry.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(os.Stderr, "Profile: %s (%s)\n", activeProfile.Name, activeProfile.Source)
		if activeProfile.Directory != "" {
			fmt.Fprintf(os.Stderr, "Directory: %s\n", activeProfile.Directory)
		}
		creds, err := keyring.LoadProfile(activeProfile.Name)
		if err != nil {
			return err
		}

		expiresIn := tokenExpiry(creds.AccessToken)
		fmt.Fprintf(os.Stderr, "Logged in as %s on %s", creds.Email, creds.ServerURL)
		if expiresIn > 0 {
			fmt.Fprintf(os.Stderr, ". Token expires in %s", expiresIn.Round(time.Second))
		} else {
			fmt.Fprint(os.Stderr, ". Token expired — run 'bw-secrets login' to re-authenticate")
		}
		fmt.Fprintln(os.Stderr)
		if creds.Scope != nil {
			fmt.Fprintf(os.Stderr, "Scoped to %s: %s\n", creds.Scope.Type, creds.Scope.Name)
		}
		return nil
	},
}
