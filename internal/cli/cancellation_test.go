package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/nathabonfim59/bw-secrets/internal/profile"
	"github.com/spf13/cobra"
	oskeyring "github.com/zalando/go-keyring"
)

func TestCancellationChild(t *testing.T) {
	endpoint := os.Getenv("BW_SECRETS_CANCELLATION_TEST_URL")
	if endpoint == "" {
		return
	}
	resp, err := http.Get(endpoint)
	if err != nil {
		os.Exit(3)
	}
	resp.Body.Close()
	time.Sleep(time.Minute)
	os.Exit(4)
}

func TestRunCancellation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("BW_SECRETS_SERVER", "")
	original := activeProfile
	activeProfile = profile.Selection{Name: "cancellation"}
	t.Cleanup(func() { activeProfile = original })
	oskeyring.MockInit()

	for _, stage := range []string{"refresh", "sync", "child"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
				}
				if stage == "child" {
					if r.URL.Path == "/api/sync" {
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprint(w, `{}`)
					} else if r.URL.Path == "/ready" {
						cancel()
					} else {
						t.Errorf("unexpected child request: %s", r.URL.Path)
					}
					return
				}
				want := "/api/sync"
				if stage == "refresh" {
					want = "/identity/connect/token"
				}
				if r.URL.Path != want {
					t.Errorf("request path = %q, want %q", r.URL.Path, want)
				}
				cancel()
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
					t.Error("request did not receive command cancellation")
				}
			}))
			defer server.Close()
			token := "unparseable-token"
			if stage == "refresh" {
				token = "header." + base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, time.Now().Add(time.Minute).Unix())) + ".signature"
			}
			if err := keyring.SaveProfile(activeProfile.Name, &keyring.Credentials{
				ServerURL: server.URL, AccessToken: token, RefreshToken: "unchanged",
				EncKey: base64.StdEncoding.EncodeToString(make([]byte, 64)),
			}); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(ctx)
			args := []string{"must-not-start"}
			if stage == "child" {
				t.Setenv("BW_SECRETS_CANCELLATION_TEST_URL", server.URL+"/ready")
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				args = []string{executable, "-test.run=^TestCancellationChild$"}
			}
			err := runCmd.RunE(cmd, args)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation from %s, got %v", stage, err)
			}
			creds, err := keyring.LoadProfile(activeProfile.Name)
			if err != nil {
				t.Fatal(err)
			}
			if creds.AccessToken != token || creds.RefreshToken != "unchanged" {
				t.Fatal("cancellation changed stored credentials")
			}
		})
	}
}
