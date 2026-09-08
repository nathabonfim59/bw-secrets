package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/nathabonfim59/bw-secrets/internal/profile"
	"github.com/nathabonfim59/bw-secrets/internal/vault"
	oskeyring "github.com/zalando/go-keyring"
)

func TestListOutput(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("BW_SECRETS_SERVER", "")
	oskeyring.MockInit()
	previous := activeProfile
	activeProfile = profile.Selection{Name: "listing"}
	t.Cleanup(func() { activeProfile = previous })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sync", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Ciphers":[{"Id":"item-id","Name":"Example Login","Type":1,"Login":{"Password":"never-print-this"}}]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	if err := keyring.SaveProfile("listing", &keyring.Credentials{ServerURL: server.URL, AccessToken: "token", EncKey: base64.StdEncoding.EncodeToString(make([]byte, 64))}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
		fail bool
	}{
		{[]string{"login"}, "Example Login", false},
		{[]string{"login", "-o", "text"}, "item-id\n", false},
		{[]string{"login", "-o", "json"}, `"id": "item-id"`, false},
		{[]string{"login", "-o", "template", "--template", `{{range .}}{{.Name}}:{{.ID}}{{end}}`}, "Example Login:item-id", false},
		{[]string{"login", "--search", "absent", "-o", "json"}, "[]\n", false},
		{[]string{"--format", "invalid"}, "", true},
		{[]string{"--type", "invalid"}, "", true},
		{[]string{"orgs", "--folder", "f"}, "", true},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			cmd := newListCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tc.args)
			err := cmd.ExecuteContext(t.Context())
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected error %v", err)
			}
			if !strings.Contains(out.String(), tc.want) || strings.Contains(out.String(), "never-print-this") {
				t.Fatalf("unexpected output %q", out.String())
			}
			if len(tc.args) > 2 && tc.args[2] == "json" && !tc.fail {
				var rows []vault.Entry
				if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
