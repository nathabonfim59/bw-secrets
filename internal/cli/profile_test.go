package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/bw-secrets/internal/keyring"
	"github.com/nathabonfim59/bw-secrets/internal/profile"
	oskeyring "github.com/zalando/go-keyring"
)

func executeProfileTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"--profile="}, args...))
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		profileFlag = ""
	})
	err := rootCmd.Execute()
	return out.String(), err
}

func TestProfileCommands(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(profile.Env, "work")
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	out, err := executeProfileTest(t, "profile", "use", "personal")
	if err != nil || out != "export BW_SECRETS_PROFILE=personal\n" {
		t.Fatalf("export: %q, %v", out, err)
	}
	if _, err := executeProfileTest(t, "profile", "bind", "personal"); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"profile", "current"}, "personal\n"},
		{[]string{"profile", "use"}, "export BW_SECRETS_PROFILE=personal\n"},
		{[]string{"--profile=explicit", "profile", "current"}, "explicit\n"},
	} {
		out, err := executeProfileTest(t, tt.args...)
		if err != nil || out != tt.want {
			t.Fatalf("%v: %q, %v", tt.args, out, err)
		}
	}
	if os.Getenv(profile.Env) != "work" {
		t.Fatal("directory resolution mutated inherited environment")
	}
	if _, err := executeProfileTest(t, "profile", "unbind", root); err != nil {
		t.Fatal(err)
	}
	out, err = executeProfileTest(t, "profile", "current")
	if err != nil || out != "work\n" {
		t.Fatalf("after unbind: %q, %v", out, err)
	}
	out, err = executeProfileTest(t, "profile", "use", "work;id")
	if err == nil || out != "" {
		t.Fatalf("unsafe export: %q, %v", out, err)
	}
}

func TestRunChildProfile(t *testing.T) {
	if os.Getenv("BW_SECRETS_TEST_CHILD") != "1" {
		return
	}
	if os.Getenv(profile.Env) != "work" {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestRunPropagatesProfileAndRefreshesOnlySelectedLogin(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(profile.Env, "personal")
	t.Setenv("BW_SECRETS_SERVER", "")
	t.Setenv("BW_SECRETS_TEST_CHILD", "1")
	t.Chdir(t.TempDir())
	oskeyring.MockInit()
	expired := "header." + base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, time.Now().Add(time.Minute).Unix())) + ".signature"
	mux := http.NewServeMux()
	mux.HandleFunc("POST /identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("refresh_token") != "work-refresh" {
			t.Error("refreshed wrong profile")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fresh-work","refresh_token":"new-refresh"}`)
	})
	mux.HandleFunc("GET /api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh-work" {
			t.Error("sync used wrong token")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	for _, name := range []string{"work", "personal"} {
		if err := keyring.SaveProfile(name, &keyring.Credentials{
			ServerURL: server.URL, AccessToken: expired, RefreshToken: name + "-refresh",
			EncKey: base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := executeProfileTest(t, "profile", "bind", "work"); err != nil {
		t.Fatal(err)
	}
	// An env file cannot override the profile selected for secret resolution.
	if err := os.WriteFile("test.env", []byte(profile.Env+"=incorrect\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runEnvFiles = nil })
	if out, err := executeProfileTest(t, "run", "--env-file=test.env", "--", executable, "-test.run=^TestRunChildProfile$"); err != nil {
		t.Fatalf("run: %s: %v", out, err)
	}
	work, err := keyring.LoadProfile("work")
	if err != nil || work.AccessToken != "fresh-work" || work.RefreshToken != "new-refresh" {
		t.Fatalf("work refresh not saved: %v", err)
	}
	personal, err := keyring.LoadProfile("personal")
	if err != nil || personal.AccessToken != expired {
		t.Fatalf("personal login changed: %v", err)
	}
	if os.Getenv(profile.Env) != "personal" {
		t.Fatal("run mutated parent context")
	}
	if _, err := executeProfileTest(t, "--profile=missing", "list"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing profile did not fail explicitly: %v", err)
	}
}
