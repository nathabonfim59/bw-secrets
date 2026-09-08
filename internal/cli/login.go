package cli

import (
	"bufio"
	"cmp"
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
	"github.com/nathabonfim59/bw-secrets/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(loginCmd)
}

var readPassword = term.ReadPassword

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Bitwarden and store credentials in the OS keyring.",
	Args:  cobra.NoArgs,
	Long: `Prompts for server URL, email, and master password, then authenticates
with the Bitwarden/Vaultwarden server and stores the resulting tokens
in the OS keyring for subsequent commands.

Use --folder to restrict the session to a single personal folder, or
--organization together with --collection to restrict to a collection.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loginFolder, _ := cmd.Flags().GetString("folder")
		loginOrganization, _ := cmd.Flags().GetString("organization")
		loginCollection, _ := cmd.Flags().GetString("collection")
		all, _ := cmd.Flags().GetBool("all")
		edit, _ := cmd.Flags().GetBool("edit")
		rescope := cmd.Name() == "rescope"
		if all && (loginFolder != "" || loginCollection != "" || loginOrganization != "") {
			return fmt.Errorf("--all cannot be combined with scope selectors")
		}
		if rescope && !all && loginFolder == "" && loginCollection == "" {
			return fmt.Errorf("choose --folder, --organization with --collection, or --all")
		}

		reader := bufio.NewReader(os.Stdin)
		previous, err := keyring.LoadProfile(activeProfile.Name)
		if err != nil && (!errors.Is(err, keyring.ErrNotLoggedIn) || rescope) {
			return err
		}
		if previous == nil {
			previous = &keyring.Credentials{}
		}
		remember := previous.Remember

		serverURL := serverURL()
		if serverURL == "" && (rescope || remember && !edit) {
			serverURL = previous.ServerURL
		}
		if serverURL == "" {
			var err error
			serverURL, err = prompt(reader, "Server URL", cmp.Or(previous.ServerURL, "https://vault.bitwarden.com"))
			if err != nil {
				return fmt.Errorf("reading server URL: %w", err)
			}
		}
		serverURL = strings.TrimRight(serverURL, "/")

		email := previous.Email
		if !rescope && (!remember || edit) {
			email, err = prompt(reader, "Email", email)
			if err != nil {
				return fmt.Errorf("reading email: %w", err)
			}
		}

		client := api.NewClient(serverURL)
		creds, symKey, err := authenticate(cmd.Context(), client, serverURL, email)
		if err != nil {
			return err
		}
		creds.Remember = remember
		if !all && loginFolder == "" && loginCollection == "" && previous.ServerURL == serverURL && strings.EqualFold(previous.Email, email) {
			creds.Scope = previous.Scope
		}

		if loginFolder != "" || loginCollection != "" {
			syncResp, err := client.Sync(cmd.Context())
			if err != nil {
				return fmt.Errorf("syncing vault for scope lookup: %w", err)
			}
			if loginFolder != "" {
				creds.Scope, err = resolveFolderScope(syncResp, loginFolder, symKey)
			} else {
				creds.Scope, err = resolveCollectionScope(syncResp, loginOrganization, loginCollection, symKey)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Scoped to %s: %s\n", creds.Scope.Type, creds.Scope.Name)
		}

		if !rescope {
			if cmd.Flags().Changed("remember") {
				creds.Remember, _ = cmd.Flags().GetBool("remember")
			} else if !remember || edit {
				defaultAnswer := "n"
				if remember {
					defaultAnswer = "y"
				}
				answer, err := prompt(reader, "Remember server and email for password-only login? (y/n)", defaultAnswer)
				if err != nil {
					return err
				}
				switch strings.ToLower(answer) {
				case "y", "yes":
					creds.Remember = true
				case "n", "no":
					creds.Remember = false
				default:
					return fmt.Errorf("expected yes or no")
				}
			}
		}
		if err := keyring.SaveProfile(activeProfile.Name, creds); err != nil {
			return fmt.Errorf("saving to keyring: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Logged in as %s on %s\n", email, serverURL)
		return nil
	},
}

func authenticate(ctx context.Context, client *api.Client, serverURL, email string) (*keyring.Credentials, *crypto.SymmetricKey, error) {
	fmt.Fprint(os.Stderr, "Master password: ")
	passwordBytes, err := readPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, nil, fmt.Errorf("reading password: %w", err)
	}
	password := string(passwordBytes)

	fmt.Fprintln(os.Stderr, "Authenticating...")
	prelogin, err := client.Prelogin(ctx, email)
	if err != nil {
		return nil, nil, fmt.Errorf("prelogin: %w", err)
	}

	masterKey, err := crypto.MakeMasterKey(password, email,
		prelogin.Kdf, prelogin.KdfIterations, prelogin.KdfMemory, prelogin.KdfParallelism)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving master key: %w", err)
	}

	passwordHash := crypto.MakePasswordHash(masterKey, password)

	deviceID := newUUID()
	tokenResp, err := client.Login(ctx, email, passwordHash, deviceID)
	if err != nil {
		if twoFactor, ok := errors.AsType[*api.TwoFactorError](err); ok {
			fmt.Fprint(os.Stderr, "TOTP code: ")
			totpBytes, terr := readPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if terr != nil {
				return nil, nil, fmt.Errorf("reading TOTP code: %w", terr)
			}
			totp := strings.TrimSpace(string(totpBytes))
			if totp == "" {
				return nil, nil, fmt.Errorf("TOTP code is required")
			}
			provider := "0"
			if len(twoFactor.Providers) > 0 {
				provider = twoFactor.Providers[0]
			}
			fmt.Fprintln(os.Stderr, "Verifying...")
			tokenResp, err = client.LoginWithTwoFactor(ctx, email, passwordHash, provider, totp, deviceID)
			if err != nil {
				return nil, nil, fmt.Errorf("login with 2FA: %w", err)
			}
		} else {
			return nil, nil, fmt.Errorf("login: %w", err)
		}
	}

	if tokenResp.Key == "" {
		return nil, nil, fmt.Errorf("server returned no encryption key")
	}

	stretchedKey, err := crypto.StretchKey(masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("stretching master key: %w", err)
	}
	symKey, err := crypto.ExtractSymmetricKey(tokenResp.Key, stretchedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting symmetric key: %w", err)
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
	client.SetAccessToken(creds.AccessToken)
	return creds, symKey, nil
}

func resolveFolderScope(syncResp *api.SyncResponse, folderName string, symKey *crypto.SymmetricKey) (*keyring.Scope, error) {
	names := make(map[string]string)
	for _, f := range syncResp.Folders {
		name := f.Name
		if decrypted, err := crypto.ParseEncString(f.Name); err == nil {
			if val, derr := decrypted.Decrypt(symKey); derr == nil {
				name = val
			}
		}
		names[f.ID] = name
	}
	id, err := vault.SelectID(names, folderName)
	if err != nil {
		return nil, err
	}
	return &keyring.Scope{Type: "folder", ID: id, Name: names[id]}, nil
}

func resolveCollectionScope(syncResp *api.SyncResponse, orgName, collectionName string, symKey *crypto.SymmetricKey) (*keyring.Scope, error) {
	orgs := make(map[string]string)
	for _, org := range syncResp.Profile.Organizations {
		orgs[org.ID] = org.Name
	}
	orgID, err := vault.SelectID(orgs, orgName)
	if err != nil {
		return nil, err
	}

	names := make(map[string]string)
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
		names[col.ID] = name
	}
	id, err := vault.SelectID(names, collectionName)
	if err != nil {
		return nil, err
	}
	return &keyring.Scope{Type: "collection", ID: id, Name: names[id]}, nil
}

func init() {
	rescopeCmd := &cobra.Command{Use: "rescope", Short: "Re-authenticate and change the selected profile's scope", Args: cobra.NoArgs, RunE: loginCmd.RunE}
	rootCmd.AddCommand(rescopeCmd)
	for _, cmd := range []*cobra.Command{loginCmd, rescopeCmd} {
		cmd.Flags().String("folder", "", "Restrict session to this folder name or UUID")
		cmd.Flags().String("organization", "", "Organization name or UUID (required with --collection)")
		cmd.Flags().String("collection", "", "Restrict session to this collection name or UUID (requires --organization)")
		cmd.Flags().Bool("all", false, "Remove the saved scope")
		cmd.MarkFlagsMutuallyExclusive("folder", "collection")
		cmd.MarkFlagsRequiredTogether("organization", "collection")
	}
	loginCmd.Flags().Bool("remember", false, "Remember server and email; skip the end-of-login question")
	loginCmd.Flags().Bool("edit", false, "Review remembered server and email before login")
}

func prompt(reader *bufio.Reader, label, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultVal)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal, nil
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
