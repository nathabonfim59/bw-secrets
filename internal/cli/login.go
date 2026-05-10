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

var (
	loginFolder       string
	loginOrganization string
	loginCollection   string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Bitwarden and store credentials in the OS keyring.",
	Long: `Prompts for server URL, email, and master password, then authenticates
with the Bitwarden/Vaultwarden server and stores the resulting tokens
in the OS keyring for subsequent commands.

Use --folder to restrict the session to a single personal folder, or
--organization together with --collection to restrict to a collection.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loginFolder != "" && loginCollection != "" {
			return fmt.Errorf("--folder and --collection are mutually exclusive")
		}
		if loginCollection != "" && loginOrganization == "" {
			return fmt.Errorf("--organization is required when using --collection")
		}
		if loginOrganization != "" && loginCollection == "" {
			return fmt.Errorf("--collection is required when using --organization")
		}

		reader := os.Stdin

		serverURL := serverURL()
		if serverURL == "" {
			var err error
			serverURL, err = prompt(reader, "Server URL", "https://vault.bitwarden.com")
			if err != nil {
				return fmt.Errorf("reading server URL: %w", err)
			}
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

		if loginFolder != "" || loginCollection != "" {
			client.SetAccessToken(tokenResp.AccessToken)
			syncResp, err := client.Sync(context.Background())
			if err != nil {
				return fmt.Errorf("syncing vault for scope lookup: %w", err)
			}

			var scope *keyring.Scope

			if loginFolder != "" {
				scope, err = resolveFolderScope(syncResp, loginFolder, symKey)
				if err != nil {
					return err
				}
			}

			if loginCollection != "" {
				scope, err = resolveCollectionScope(syncResp, loginOrganization, loginCollection, symKey)
				if err != nil {
					return err
				}
			}

			creds.Scope = scope
			fmt.Fprintf(os.Stderr, "Scoped to %s: %s\n", scope.Type, scope.Name)
		}

		if err := keyring.Save(creds); err != nil {
			return fmt.Errorf("saving to keyring: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Logged in as %s on %s\n", email, serverURL)
		return nil
	},
}

func resolveFolderScope(syncResp *api.SyncResponse, folderName string, symKey *crypto.SymmetricKey) (*keyring.Scope, error) {
	lower := strings.ToLower(folderName)
	for _, f := range syncResp.Folders {
		name := f.Name
		if decrypted, err := crypto.ParseEncString(f.Name); err == nil {
			if val, derr := decrypted.Decrypt(symKey); derr == nil {
				name = val
			}
		}
		if strings.ToLower(name) == lower {
			return &keyring.Scope{Type: "folder", ID: f.ID, Name: name}, nil
		}
	}
	return nil, fmt.Errorf("folder %q not found", folderName)
}

func resolveCollectionScope(syncResp *api.SyncResponse, orgName, collectionName string, symKey *crypto.SymmetricKey) (*keyring.Scope, error) {
	lowerOrg := strings.ToLower(orgName)
	orgID := ""
	for _, org := range syncResp.Profile.Organizations {
		if strings.ToLower(org.Name) == lowerOrg {
			orgID = org.ID
			break
		}
	}
	if orgID == "" {
		return nil, fmt.Errorf("organization %q not found", orgName)
	}

	lowerColl := strings.ToLower(collectionName)
	for _, col := range syncResp.Collections {
		if col.OrganizationID != orgID {
			continue
		}
		name := col.Name
		if decrypted, err := crypto.ParseEncString(col.Name); err == nil {
			if val, derr := decrypted.Decrypt(symKey); derr == nil {
				name = val
			}
		}
		if strings.ToLower(name) == lowerColl {
			return &keyring.Scope{Type: "collection", ID: col.ID, Name: name}, nil
		}
	}
	return nil, fmt.Errorf("collection %q not found in organization %q", collectionName, orgName)
}

func init() {
	loginCmd.Flags().StringVar(&loginFolder, "folder", "", "Restrict session to this folder")
	loginCmd.Flags().StringVar(&loginOrganization, "organization", "", "Organization (required with --collection)")
	loginCmd.Flags().StringVar(&loginCollection, "collection", "", "Restrict session to this collection (requires --organization)")
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
