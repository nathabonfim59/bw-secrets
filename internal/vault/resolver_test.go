package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
)

func TestParseURI(t *testing.T) {
	uri, err := ParseURI("bw://Personal/Google/password")
	if err != nil {
		t.Fatal(err)
	}
	if uri.VaultName != "Personal" {
		t.Errorf("VaultName = %s, want Personal", uri.VaultName)
	}
	if uri.ItemName != "Google" {
		t.Errorf("ItemName = %s, want Google", uri.ItemName)
	}
	if uri.FieldName != "password" {
		t.Errorf("FieldName = %s, want password", uri.FieldName)
	}
}

func TestParseURIInvalid(t *testing.T) {
	cases := []string{
		"",
		"bw://",
		"bw://x",
		"bw://x/y",
		"bw://x/y/",
		"op://vault/item/field",
	}
	for _, c := range cases {
		_, err := ParseURI(c)
		if err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestVaultNew(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:       "item-1",
				Name:     encryptForTest("Google", symKey),
				Type:     1,
				FolderID: nil,
				Login: &api.Login{
					Username: encryptForTest("user@test.com", symKey),
					Password: encryptForTest("secret123", symKey),
				},
			},
			{
				ID:          "item-2-deleted",
				Name:        encryptForTest("Deleted", symKey),
				Type:        2,
				DeletedDate: strPtr("2024-01-01"),
			},
		},
	}
	v := New(syncResp, symKey)
	items := v.Items()
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 (deleted should be filtered)", len(items))
	}
	if items[0].Name != "Google" {
		t.Errorf("Name = %q, want Google", items[0].Name)
	}
	if items[0].VaultName != "No Folder" {
		t.Errorf("VaultName = %q, want No Folder", items[0].VaultName)
	}
}

func TestResolveLoginPassword(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Folders: []api.Folder{
			{ID: "folder-1", Name: encryptForTest("Personal", symKey)},
		},
		Ciphers: []api.Cipher{
			{
				ID:       "item-1",
				Name:     encryptForTest("Google", symKey),
				Type:     1,
				FolderID: strPtr("folder-1"),
				Login: &api.Login{
					Username: encryptForTest("user@test.com", symKey),
					Password: encryptForTest("secret123", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://Personal/Google/password")
	val, vault, item, err := v.ResolveValue(uri, symKey)
	if err != nil {
		t.Fatal(err)
	}
	if val != "secret123" {
		t.Errorf("value = %q, want secret123", val)
	}
	if vault != "Personal" {
		t.Errorf("vault = %q, want Personal", vault)
	}
	if item != "Google" {
		t.Errorf("item = %q, want Google", item)
	}
}

func TestResolveLoginUsername(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "item-1",
				Name: encryptForTest("Google", symKey),
				Type: 1,
				Login: &api.Login{
					Username: encryptForTest("user@test.com", symKey),
					Password: encryptForTest("pass", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/Google/username")
	val, _, _, err := v.ResolveValue(uri, symKey)
	if err != nil {
		t.Fatal(err)
	}
	if val != "user@test.com" {
		t.Errorf("value = %q, want user@test.com", val)
	}
}

func TestResolveSecureNote(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:    "note-1",
				Name:  encryptForTest("My Note", symKey),
				Type:  2,
				Notes: strPtr(encryptForTest("some note content", symKey)),
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/My Note/notes")
	val, _, _, err := v.ResolveValue(uri, symKey)
	if err != nil {
		t.Fatal(err)
	}
	if val != "some note content" {
		t.Errorf("value = %q, want some note content", val)
	}
}

func TestResolveCard(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "card-1",
				Name: encryptForTest("Visa", symKey),
				Type: 3,
				Card: &api.Card{
					CardholderName: encryptForTest("John Doe", symKey),
					Number:         encryptForTest("4111111111111111", symKey),
					Brand:          encryptForTest("Visa", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/Visa/number")
	val, _, _, err := v.ResolveValue(uri, symKey)
	if err != nil {
		t.Fatal(err)
	}
	if val != "4111111111111111" {
		t.Errorf("value = %q", val)
	}
}

func TestResolveIdentity(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "id-1",
				Name: encryptForTest("Me", symKey),
				Type: 4,
				Identity: &api.Identity{
					FirstName: encryptForTest("John", symKey),
					Email:     encryptForTest("john@test.com", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/Me/firstname")
	val, _, _, err := v.ResolveValue(uri, symKey)
	if err != nil {
		t.Fatal(err)
	}
	if val != "John" {
		t.Errorf("value = %q, want John", val)
	}
}

func TestResolveItemNotFound(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "item-1",
				Name: encryptForTest("Google", symKey),
				Type: 1,
				Login: &api.Login{
					Password: encryptForTest("pass", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://Personal/Facebook/password")
	_, _, _, err := v.ResolveValue(uri, symKey)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want 'not found'", err)
	}
}

func TestResolveFieldNotFound(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "item-1",
				Name: encryptForTest("Google", symKey),
				Type: 1,
				Login: &api.Login{
					Password: encryptForTest("pass", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/Google/nonexistent")
	_, _, _, err := v.ResolveValue(uri, symKey)
	if err == nil {
		t.Fatal("expected error")
	}
	fe, ok := err.(*FieldNotFoundError)
	if !ok {
		t.Fatalf("expected FieldNotFoundError, got %T: %v", err, err)
	}
	if fe.Field != "nonexistent" {
		t.Errorf("field = %q, want nonexistent", fe.Field)
	}
}

func TestResolveMultipleItems(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "item-1",
				Name: encryptForTest("Google", symKey),
				Type: 1,
				Login: &api.Login{
					Password: encryptForTest("pass1", symKey),
				},
			},
			{
				ID:   "item-2",
				Name: encryptForTest("Google", symKey),
				Type: 1,
				Login: &api.Login{
					Password: encryptForTest("pass2", symKey),
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/Google/password")
	_, _, _, err := v.ResolveValue(uri, symKey)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "multiple items") {
		t.Errorf("error = %v, want 'multiple items'", err)
	}
}

func TestResolveCustomField(t *testing.T) {
	symKey := testKey()
	syncResp := &api.SyncResponse{
		Ciphers: []api.Cipher{
			{
				ID:   "item-1",
				Name: encryptForTest("Server", symKey),
				Type: 1,
				Login: &api.Login{
					Username: encryptForTest("admin", symKey),
					Password: encryptForTest("pass", symKey),
				},
				Fields: []api.Field{
					{
						Name:  encryptForTest("API Key", symKey),
						Value: encryptForTest("sk-12345", symKey),
						Type:  1,
					},
				},
			},
		},
	}
	v := New(syncResp, symKey)

	uri, _ := ParseURI("bw://No Folder/Server/api key")
	val, _, _, err := v.ResolveValue(uri, symKey)
	if err != nil {
		t.Fatal(err)
	}
	if val != "sk-12345" {
		t.Errorf("value = %q, want sk-12345", val)
	}
}

func testKey() *crypto.SymmetricKey {
	sk, _ := crypto.NewSymmetricKey(make([]byte, 64))
	return sk
}

func encryptForTest(plaintext string, symKey *crypto.SymmetricKey) string {
	iv := make([]byte, 16)
	pt := []byte(plaintext)
	padLen := 16 - len(pt)%16
	if padLen == 0 {
		padLen = 16
	}
	padded := make([]byte, len(pt)+padLen)
	copy(padded, pt)
	for i := len(pt); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	block, err := aes.NewCipher(symKey.EncryptionKey[:])
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, symKey.MACKey[:])
	mac.Write(iv)
	mac.Write(ct)
	macSum := mac.Sum(nil)

	return fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(macSum))
}

func strPtr(s string) *string {
	return &s
}
