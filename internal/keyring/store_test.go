package keyring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileFallbackRoundtrip(t *testing.T) {
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	tmpDir := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	creds := &Credentials{
		ServerURL:    "https://example.com",
		Email:        "test@example.com",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		EncKey:       "enc-key",
	}

	path := filepath.Join(tmpDir, "bw-secrets", "credentials.json")

	err := fileSave(`{"server_url":"https://example.com","email":"test@example.com","access_token":"access-token","refresh_token":"refresh-token","enc_key":"enc-key"}`)
	if err != nil {
		t.Fatalf("fileSave failed: %v", err)
	}

	data, err := fileLoad()
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

	err = fileDelete()
	if err != nil {
		t.Fatalf("fileDelete failed: %v", err)
	}

	_, err = fileLoad()
	if err != ErrNotLoggedIn {
		t.Errorf("expected ErrNotLoggedIn, got %v", err)
	}

	_ = creds
}
