package keyring

import (
	"errors"
	"path/filepath"
	"testing"

	oskeyring "github.com/zalando/go-keyring"
)

func TestProfileIsolation(t *testing.T) {
	for _, backend := range []string{"keyring", "file"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			if backend == "file" {
				oskeyring.MockInitWithError(errors.New("keyring unavailable"))
			} else {
				oskeyring.MockInit()
			}
			for _, name := range []string{"default", "work", "personal"} {
				if err := SaveProfile(name, &Credentials{Email: name, AccessToken: name}); err != nil {
					t.Fatal(err)
				}
			}
			if err := SaveProfile("work", &Credentials{Email: "work", AccessToken: "refreshed"}); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"default", "work", "personal"} {
				creds, err := LoadProfile(name)
				if err != nil {
					t.Fatal(err)
				}
				want := name
				if name == "work" {
					want = "refreshed"
				}
				if creds.Email != name || creds.AccessToken != want {
					t.Fatalf("profile %s loaded wrong credentials", name)
				}
			}
			// File deletion still happens if the keyring cannot be reached.
			if err := DeleteProfile("work"); err != nil && backend == "keyring" {
				t.Fatal(err)
			}
			if _, err := LoadProfile("work"); !errors.Is(err, ErrNotLoggedIn) {
				t.Fatalf("deleted profile: %v", err)
			}
			if _, err := LoadProfile("personal"); err != nil {
				t.Fatalf("logout affected other profile: %v", err)
			}
			if _, err := LoadProfile("missing"); !errors.Is(err, ErrNotLoggedIn) {
				t.Fatalf("missing profile fell back: %v", err)
			}
		})
	}
}

func TestLegacyProfileAndFallbackRecovery(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	oskeyring.MockInit()
	path, err := profileFilePath("default")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "credentials.json" || filepath.Base(filepath.Dir(path)) != "bw-secrets" {
		t.Fatalf("legacy path changed: %s", path)
	}
	if err := fileSaveProfile("default", `{"email":"legacy"}`); err != nil {
		t.Fatal(err)
	}
	creds, err := LoadProfile("default")
	if err != nil || creds.Email != "legacy" {
		t.Fatalf("legacy fallback: %v, %v", creds, err)
	}
	if err := SaveProfile("default", &Credentials{Email: "updated"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fileLoadProfile("default"); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("stale fallback remains: %v", err)
	}
	if _, err := LoadProfile("../default"); err == nil {
		t.Fatal("accepted traversal")
	}
}
