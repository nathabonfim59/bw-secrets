package cli

import (
	"context"
	"encoding/base64"
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
	rootCmd.AddCommand(unlockCmd)
}

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Re-authenticate when tokens have expired.",
	Long: `Loads stored server URL and email from the keyring, prompts for the
master password, and re-authenticates to obtain fresh tokens.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		creds, err := keyring.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Not logged in — run 'bw-secrets login'")
			os.Exit(2)
			return nil
		}

		fmt.Fprint(os.Stderr, "Master password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		password := string(passwordBytes)

		url := serverURL()
		if url == "" {
			url = creds.ServerURL
		}
		url = strings.TrimRight(url, "/")

		client := api.NewClient(url)

		fmt.Fprintln(os.Stderr, "Authenticating...")
		prelogin, err := client.Prelogin(context.Background(), creds.Email)
		if err != nil {
			return fmt.Errorf("prelogin: %w", err)
		}

		masterKey, err := crypto.MakeMasterKey(password, creds.Email,
			prelogin.Kdf, prelogin.KdfIterations, prelogin.KdfMemory, prelogin.KdfParallelism)
		if err != nil {
			return fmt.Errorf("deriving master key: %w", err)
		}

		passwordHash := crypto.MakePasswordHash(masterKey, password)

		deviceID := newUUID()
		tokenResp, err := client.Login(context.Background(), creds.Email, passwordHash, deviceID)
		if err != nil {
			return fmt.Errorf("login: %w", err)
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

		newCreds := &keyring.Credentials{
			ServerURL:    url,
			Email:        creds.Email,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			EncKey:       base64.StdEncoding.EncodeToString(rawKey),
		}
		if err := keyring.Save(newCreds); err != nil {
			return fmt.Errorf("saving to keyring: %w", err)
		}

		fmt.Fprintln(os.Stderr, "Vault unlocked")
		return nil
	},
}
