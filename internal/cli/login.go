package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(loginCmd)
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Bitwarden and store credentials in the OS keyring.",
	Long: `Prompts for server URL, email, and master password, then authenticates
with the Bitwarden/Vaultwarden server and stores the resulting tokens
in the OS keyring for subsequent commands.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		reader := os.Stdin

		serverURL, err := prompt(reader, "Server URL", "https://vault.bitwarden.com")
		if err != nil {
			return fmt.Errorf("reading server URL: %w", err)
		}
		serverURL = strings.TrimRight(serverURL, "/")

		email, err := prompt(reader, "Email", "")
		if err != nil {
			return fmt.Errorf("reading email: %w", err)
		}

		fmt.Fprint(os.Stderr, "Master password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		password := string(passwordBytes)

		client := api.NewClient(serverURL)

		fmt.Fprintln(os.Stderr, "Authenticating...")
		prelogin, err := client.Prelogin(context.Background(), email)
		if err != nil {
			return fmt.Errorf("prelogin: %w", err)
		}

		masterKey, err := crypto.MakeMasterKey(password, email,
			prelogin.Kdf, prelogin.KdfIterations, prelogin.KdfMemory, prelogin.KdfParallelism)
		if err != nil {
			return fmt.Errorf("deriving master key: %w", err)
		}

		passwordHash := crypto.MakePasswordHash(masterKey, password)

		deviceID := newUUID()
		tokenResp, err := client.Login(context.Background(), email, passwordHash, deviceID)
		if err != nil {
			var twoFactor *api.TwoFactorError
			if errors.As(err, &twoFactor) {
				fmt.Fprint(os.Stderr, "TOTP code: ")
				totpBytes, terr := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if terr != nil {
					return fmt.Errorf("reading TOTP code: %w", terr)
				}
				totp := strings.TrimSpace(string(totpBytes))
				if totp == "" {
					return fmt.Errorf("TOTP code is required")
				}
				provider := "0"
				if len(twoFactor.Providers) > 0 {
					provider = twoFactor.Providers[0]
				}
				fmt.Fprintln(os.Stderr, "Verifying...")
				tokenResp, err = client.LoginWithTwoFactor(context.Background(), email, passwordHash, provider, totp, deviceID)
				if err != nil {
					return fmt.Errorf("login with 2FA: %w", err)
				}
			} else {
				return fmt.Errorf("login: %w", err)
			}
		}

		if tokenResp.Key == "" {
			return fmt.Errorf("server returned no encryption key")
		}

		symKey, err := crypto.ExtractSymmetricKey(tokenResp.Key, crypto.StretchKey(masterKey))
		if err != nil {
			return fmt.Errorf("decrypting symmetric key: %w", err)
		}

		rawKey := make([]byte, 64)
		copy(rawKey[0:32], symKey.EncryptionKey[:])
		copy(rawKey[32:64], symKey.MACKey[:])

		creds := &keyring.Credentials{
			ServerURL:    serverURL,
			Email:        email,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			EncKey:       base64.StdEncoding.EncodeToString(rawKey),
		}
		if err := keyring.Save(creds); err != nil {
			return fmt.Errorf("saving to keyring: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Logged in as %s on %s\n", email, serverURL)
		return nil
	},
}

func prompt(reader *os.File, label, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultVal)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	var input string
	_, err := fmt.Fscanln(reader, &input)
	if err != nil {
		if err.Error() == "unexpected newline" && defaultVal != "" {
			return defaultVal, nil
		}
		return "", err
	}
	return input, nil
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
