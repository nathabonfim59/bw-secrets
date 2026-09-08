package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"slices"
	"testing"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
)

func mustNew(t *testing.T, s *api.SyncResponse, key *crypto.SymmetricKey, scope *keyring.Scope) *Vault {
	t.Helper()
	v, err := New(s, key, scope)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func organizationProfile(t *testing.T, user, org *crypto.SymmetricKey, kind string) api.Profile {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var h hash.Hash = sha1.New()
	if kind == "3" {
		h = sha256.New()
	}
	raw := append(bytes.Clone(org.EncryptionKey[:]), org.MACKey[:]...)
	wrapped, err := rsa.EncryptOAEP(h, rand.Reader, &private.PublicKey, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return api.Profile{
		PrivateKey:    encryptForTest(string(der), user),
		Organizations: []api.Organization{{ID: "org-1", Name: "Acme", Key: kind + "." + base64.StdEncoding.EncodeToString(wrapped)}},
	}
}

func TestOrganizationKeyChain(t *testing.T) {
	for _, kind := range []string{"3", "4"} {
		t.Run(kind, func(t *testing.T) {
			user := testKey()
			org, err := crypto.NewSymmetricKey(bytes.Repeat([]byte{1}, 64))
			if err != nil {
				t.Fatal(err)
			}
			itemRaw := bytes.Repeat([]byte{2}, 64)
			item, err := crypto.NewSymmetricKey(itemRaw)
			if err != nil {
				t.Fatal(err)
			}
			s := &api.SyncResponse{
				Profile:     organizationProfile(t, user, org, kind),
				Collections: []api.Collection{{ID: "col", OrganizationID: "org-1", Name: encryptForTest("Team", org)}},
				Ciphers: []api.Cipher{
					{ID: "direct", OrganizationID: new("org-1"), CollectionIDs: []string{"col"}, Type: 1, Name: encryptForTest("Direct", org), Login: &api.Login{Password: encryptForTest("org-secret", org)}},
					{ID: "wrapped", OrganizationID: new("org-1"), CollectionIDs: []string{"col"}, Key: encryptForTest(string(itemRaw), org), Type: 1, Name: encryptForTest("Wrapped", item), Login: &api.Login{Password: encryptForTest("item-secret", item)}, Fields: []api.Field{{Name: encryptForTest("API Key", item), Value: encryptForTest("custom-secret", item)}}},
					{ID: "personal", Key: encryptForTest(string(itemRaw), user), Type: 1, Name: encryptForTest("Personal", item), Login: &api.Login{Password: encryptForTest("personal-secret", item)}},
				},
			}
			v := mustNew(t, s, user, nil)
			rows, err := v.List(ListOptions{Kind: "collections", Organization: "Acme"})
			if err != nil || len(rows) != 1 || rows[0].Name != "Team" {
				t.Fatalf("collections: %+v, %v", rows, err)
			}
			rows, err = v.List(ListOptions{Kind: "items", Organization: "Acme", Collection: "Team"})
			if err != nil || len(rows) != 2 {
				t.Fatalf("items: %+v, %v", rows, err)
			}
			for uri, want := range map[string]string{
				"bw://Acme//Team/Direct/password":  "org-secret",
				"bw://org-1//col/wrapped/password": "item-secret",
				"bw://Acme//Team/Wrapped/API Key":  "custom-secret",
				"bw://*/Personal/password":         "personal-secret",
			} {
				parsed, err := ParseURI(uri)
				if err != nil {
					t.Fatal(err)
				}
				got, _, _, err := v.ResolveValue(parsed)
				if err != nil || got != want {
					t.Fatalf("%s: got %q, %v", uri, got, err)
				}
			}
			for _, mutate := range []func(*api.SyncResponse){
				func(s *api.SyncResponse) { s.Profile.PrivateKey = "2.invalid" },
				func(s *api.SyncResponse) { s.Profile.Organizations[0].Key = "" },
				func(s *api.SyncResponse) { s.Profile.Organizations[0].Key = "4.invalid" },
				func(s *api.SyncResponse) { s.Collections[0].Name = encryptForTest("Wrong key", user) },
				func(s *api.SyncResponse) { s.Ciphers[1].Key = encryptForTest("short", org) },
				func(s *api.SyncResponse) { s.Ciphers[1].Name = encryptForTest("Wrong key", org) },
			} {
				copy := *s
				copy.Profile.Organizations = slices.Clone(s.Profile.Organizations)
				copy.Collections = slices.Clone(s.Collections)
				copy.Ciphers = slices.Clone(s.Ciphers)
				mutate(&copy)
				if _, err := New(&copy, user, nil); err == nil {
					t.Fatal("expected decryption error")
				}
			}
		})
	}
}
