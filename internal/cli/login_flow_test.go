package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/spf13/pflag"
	oskeyring "github.com/zalando/go-keyring"
)

func TestRememberAndRescope(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("BW_SECRETS_SERVER", "")
	t.Chdir(t.TempDir())
	oskeyring.MockInit()
	oldRead := readPassword
	t.Cleanup(func() { readPassword = oldRead })
	readPassword = func(int) ([]byte, error) { return []byte("password"), nil }
	mk, err := crypto.MakeMasterKey("password", "me@example.com", 0, 1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	stretched, err := crypto.StretchKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(stretched[:32])
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	ct := append(make([]byte, 64), bytes.Repeat([]byte{16}, 16)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, ct)
	mac := hmac.New(sha256.New, stretched[32:])
	mac.Write(iv)
	mac.Write(ct)
	b64 := base64.StdEncoding.EncodeToString
	encKey := "2." + b64(iv) + "|" + b64(ct) + "|" + b64(mac.Sum(nil))
	userKey := make([]byte, 64)
	orgKey := bytes.Repeat([]byte{1}, 64)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	wrappedOrg, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &private.PublicKey, orgKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	synced := api.SyncResponse{
		Profile:     api.Profile{PrivateKey: encryptLoginFixture(t, der, userKey), Organizations: []api.Organization{{ID: "o1", Name: "Acme Corp", Key: "4." + b64(wrappedOrg)}}},
		Folders:     []api.Folder{{ID: "f1", Name: encryptLoginFixture(t, []byte("Work Folder"), userKey)}},
		Collections: []api.Collection{{ID: "c1", OrganizationID: "o1", Name: encryptLoginFixture(t, []byte("Team"), orgKey)}},
		Ciphers:     []api.Cipher{{ID: "i1", OrganizationID: new("o1"), CollectionIDs: []string{"c1"}, Type: 1, Name: encryptLoginFixture(t, []byte("Database"), orgKey), Login: &api.Login{Password: encryptLoginFixture(t, []byte("org-secret"), orgKey)}}},
	}
	failAuth := false
	failDecrypt := false
	twoFactor := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Kdf":0,"KdfIterations":1}`)
	})
	mux.HandleFunc("POST /identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		if failAuth {
			http.Error(w, "bad password", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if twoFactor && r.Form.Get("TwoFactorToken") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"TwoFactorProviders":["0"]}`)
			return
		}
		if twoFactor && r.Form.Get("TwoFactorToken") != "123456" {
			t.Error("wrong 2FA code")
		}
		if r.Form.Get("username") != "me@example.com" || r.Form.Get("password") != crypto.MakePasswordHash(mk, "password") {
			t.Error("wrong saved identity/password")
		}
		if err := json.NewEncoder(w).Encode(map[string]string{"access_token": "new-token", "refresh_token": "new-refresh", "Key": encKey}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("GET /api/sync", func(w http.ResponseWriter, r *http.Request) {
		response := synced
		if failDecrypt {
			response.Profile.PrivateKey = "2.invalid"
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	if err := keyring.SaveProfile("work", &keyring.Credentials{ServerURL: server.URL, Email: "me@example.com", Remember: true}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		args  []string
		fail  bool
		scope string
	}{
		{"remembered login", []string{"login"}, false, ""},
		{"folder", []string{"rescope", "--folder", "Work Folder"}, false, "f1"},
		{"missing folder", []string{"rescope", "--folder", "missing"}, true, "f1"},
		{"failed authentication", []string{"rescope", "--all"}, true, "f1"},
		{"rescope 2FA", []string{"rescope", "--folder", "f1"}, false, "f1"},
		{"unlock 2FA", []string{"unlock"}, false, "f1"},
		{"collection UUID", []string{"rescope", "--organization", "o1", "--collection", "c1"}, false, "c1"},
		{"collection name", []string{"rescope", "--organization", "Acme Corp", "--collection", "Team"}, false, "c1"},
		{"failed decryption", []string{"rescope", "--organization", "o1", "--collection", "c1"}, true, "c1"},
		{"clear scope", []string{"rescope", "--all"}, false, ""},
		{"lock remembers", []string{"lock"}, false, ""},
		{"login after lock", []string{"login"}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failAuth = tc.name == "failed authentication"
			failDecrypt = tc.name == "failed decryption"
			twoFactor = tc.name == "rescope 2FA" || tc.name == "unlock 2FA"
			reads := 0
			readPassword = func(int) ([]byte, error) {
				reads++
				if reads > 1 {
					return []byte("123456"), nil
				}
				return []byte("password"), nil
			}
			before, err := keyring.LoadProfile("work")
			if err != nil {
				t.Fatal(err)
			}
			cmd, _, err := rootCmd.Find(tc.args[:1])
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cmd.Flags().VisitAll(func(f *pflag.Flag) {
					if err := f.Value.Set(f.DefValue); err != nil {
						t.Error(err)
					}
					f.Changed = false
				})
			})
			_, err = executeProfileTest(t, append([]string{"--profile=work"}, tc.args...)...)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected error: %v", err)
			}
			after, err := keyring.LoadProfile("work")
			if err != nil {
				t.Fatal(err)
			}
			if tc.fail && !reflect.DeepEqual(before, after) {
				t.Fatal("failed authentication changed credentials")
			}
			if tc.name == "lock remembers" {
				if after.AccessToken != "" || after.RefreshToken != "" || after.EncKey != "" {
					t.Fatal("lock retained secrets")
				}
				if _, _, err := getClient(t.Context()); err == nil {
					t.Fatal("locked profile accepted")
				}
			}
			if !after.Remember || after.Email != "me@example.com" || after.ServerURL != server.URL {
				t.Fatal("lost saved login details")
			}
			got := ""
			if after.Scope != nil {
				got = after.Scope.ID
			}
			if got != tc.scope {
				t.Fatalf("scope %q want %q", got, tc.scope)
			}
			if got == "c1" && after.Scope.Name != "Team" {
				t.Fatalf("encrypted scope name: %q", after.Scope.Name)
			}
		})
	}
	t.Run("organization commands", func(t *testing.T) {
		out, err := executeProfileTest(t, "--profile=work", "list", "collections", "--organization", "Acme Corp")
		if err != nil || !strings.Contains(out, "Team") || strings.Contains(out, "2.") {
			t.Fatalf("collections: %q, %v", out, err)
		}
		listCmd.Flags().VisitAll(func(f *pflag.Flag) {
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Fatal(err)
			}
			f.Changed = false
		})
		uri := "bw://Acme Corp//Team/Database/password"
		output, err := os.CreateTemp(t.TempDir(), "stdout")
		if err != nil {
			t.Fatal(err)
		}
		defer output.Close()
		old := os.Stdout
		os.Stdout = output
		t.Cleanup(func() { os.Stdout = old })
		t.Cleanup(func() { reveal = false; getCmd.Flags().Lookup("reveal").Changed = false })
		if _, err := executeProfileTest(t, "--profile=work", "get", "--reveal", uri); err != nil {
			t.Fatal(err)
		}
		if _, err := output.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(output)
		if err != nil || strings.TrimSpace(string(got)) != "org-secret" {
			t.Fatalf("get: %q, %v", got, err)
		}
		input := filepath.Join(t.TempDir(), "template")
		if err := os.WriteFile(input, []byte("PASSWORD=bw://o1//c1/i1/password"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := output.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if _, err := output.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := executeProfileTest(t, "--profile=work", "inject", input); err != nil {
			t.Fatal(err)
		}
		if _, err := output.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		got, err = io.ReadAll(output)
		if err != nil || string(got) != "PASSWORD=org-secret" {
			t.Fatalf("inject: %q, %v", got, err)
		}
		if sh, err := exec.LookPath("sh"); err == nil {
			t.Setenv("ORG_TEST_PASSWORD", uri)
			if _, err := executeProfileTest(t, "--profile=work", "run", "--", sh, "-c", `test "$ORG_TEST_PASSWORD" = org-secret`); err != nil {
				t.Fatal(err)
			}
		}
	})
	readPassword = func(int) ([]byte, error) { return []byte("password"), nil }
	// A successful initial login asks whether to remember; existing details are defaults.
	creds, err := keyring.LoadProfile("work")
	if err != nil {
		t.Fatal(err)
	}
	creds.Remember = false
	if err := keyring.SaveProfile("work", creds); err != nil {
		t.Fatal(err)
	}
	in, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, err := in.WriteString("\n\ny\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = in
	t.Cleanup(func() { os.Stdin = oldStdin })
	if _, err := executeProfileTest(t, "--profile=work", "login"); err != nil {
		t.Fatal(err)
	}
	creds, err = keyring.LoadProfile("work")
	if err != nil {
		t.Fatal(err)
	}
	if !creds.Remember {
		t.Fatal("remember answer not saved")
	}
}

func encryptLoginFixture(t *testing.T, plain, key []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	ct := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, ct)
	mac := hmac.New(sha256.New, key[32:])
	mac.Write(iv)
	mac.Write(ct)
	b64 := base64.StdEncoding.EncodeToString
	return "2." + b64(iv) + "|" + b64(ct) + "|" + b64(mac.Sum(nil))
}
