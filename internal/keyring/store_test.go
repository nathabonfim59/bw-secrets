package keyring

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileFallbackRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	creds := &Credentials{
		ServerURL:    "https://example.com",
		Email:        "test@example.com",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		EncKey:       "enc-key",
	}

	path := filepath.Join(tmpDir, "bw-secrets", "credentials.json")

	err := fileSaveProfile("default", `{"server_url":"https://example.com","email":"test@example.com","access_token":"access-token","refresh_token":"refresh-token","enc_key":"enc-key"}`)
	if err != nil {
		t.Fatalf("fileSave failed: %v", err)
	}

	data, err := fileLoadProfile("default")
	if err != nil {
		t.Fatalf("fileLoad failed: %v", err)
	}
	if data != `{"server_url":"https://example.com","email":"test@example.com","access_token":"access-token","refresh_token":"refresh-token","enc_key":"enc-key"}` {
		t.Errorf("data mismatch: %s", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}

	err = fileDeleteProfile("default")
	if err != nil {
		t.Fatalf("fileDelete failed: %v", err)
	}

	_, err = fileLoadProfile("default")
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("expected ErrNotLoggedIn, got %v", err)
	}

	_ = creds
}

func TestCredentialsScopeRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	creds := &Credentials{
		ServerURL:    "https://example.com",
		Email:        "test@example.com",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		EncKey:       "enc-key",
		Scope:        &Scope{Type: "folder", ID: "abc-123", Name: "Work"},
	}

	data, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}

	if err := fileSaveProfile("default", string(data)); err != nil {
		t.Fatal(err)
	}

	loadedData, err := fileLoadProfile("default")
	if err != nil {
		t.Fatal(err)
	}

	var loaded Credentials
	if err := json.Unmarshal([]byte(loadedData), &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Scope == nil {
		t.Fatal("Scope is nil after roundtrip")
	}
	if loaded.Scope.Type != "folder" {
		t.Errorf("Scope.Type = %q, want folder", loaded.Scope.Type)
	}
	if loaded.Scope.ID != "abc-123" {
		t.Errorf("Scope.ID = %q, want abc-123", loaded.Scope.ID)
	}
	if loaded.Scope.Name != "Work" {
		t.Errorf("Scope.Name = %q, want Work", loaded.Scope.Name)
	}
}

func TestCredentialsBackwardCompat(t *testing.T) {
	oldJSON := `{"server_url":"https://example.com","email":"test@example.com","access_token":"at","refresh_token":"rt","enc_key":"ek"}`
	var creds Credentials
	if err := json.Unmarshal([]byte(oldJSON), &creds); err != nil {
		t.Fatal(err)
	}
	if creds.Scope != nil {
		t.Error("Scope should be nil for old credentials JSON")
	}
	if creds.ServerURL != "https://example.com" {
		t.Errorf("ServerURL = %q", creds.ServerURL)
	}
}
