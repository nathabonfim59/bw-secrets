package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
		creds, err := keyring.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Not logged in — run 'bw-secrets login'")
			os.Exit(2)
			return nil
		}

		expiresIn := tokenExpiry(creds.AccessToken)
		fmt.Fprintf(os.Stderr, "Logged in as %s on %s", creds.Email, creds.ServerURL)
		if expiresIn > 0 {
			fmt.Fprintf(os.Stderr, ". Token expires in %s", expiresIn.Round(time.Second))
		} else {
			fmt.Fprint(os.Stderr, ". Token expired — run 'bw-secrets login' to re-authenticate")
		}
		fmt.Fprintln(os.Stderr)
		return nil
	},
}

func tokenExpiry(accessToken string) time.Duration {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return -1
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return -1
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return -1
	}
	if claims.Exp == 0 {
		return -1
	}
	return time.Until(time.Unix(claims.Exp, 0))
}
