package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestMakeMasterKeyPBKDF2(t *testing.T) {
	key, err := MakeMasterKey("password", "test@example.com", 0, 1000, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

func TestMakeMasterKeyArgon2id(t *testing.T) {
	key, err := MakeMasterKey("password", "test@example.com", 1, 3, 65536, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

func TestMakeMasterKeyUnknownKDF(t *testing.T) {
	_, err := MakeMasterKey("password", "test@example.com", 99, 1000, 0, 0)
	if err != ErrUnknownKDF {
		t.Errorf("expected ErrUnknownKDF, got %v", err)
	}
}

func TestMakePasswordHash(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	hash := MakePasswordHash(masterKey, "password")
	if hash == "" {
		t.Error("hash is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Fatal("not valid base64:", err)
	}
	if len(decoded) != 32 {
		t.Errorf("hash bytes = %d, want 32", len(decoded))
	}
}

func TestMakeMasterKeySaltLowercase(t *testing.T) {
	k1, _ := MakeMasterKey("password", "TEST@Example.COM", 0, 1, 0, 0)
	k2, _ := MakeMasterKey("password", "test@example.com", 0, 1, 0, 0)
	for i := range k1 {
		if k1[i] != k2[i] {
			t.Error("salt is not lowercased")
			return
		}
	}
}

func TestStretchKey(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	stretched, err := StretchKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	// Independently calculated RFC 5869 expand blocks for info "enc" and "mac".
	const want = "430a9d9e1d1a5d5bc8b184256c7fbadd33c27d1e6d276a801bdcd07c1c0003eac4b2c51ed7aa2f27c4b7e5dcf19f3950a2b3222b1d764d7b3f657e9e509add10"
	if got := hex.EncodeToString(stretched); got != want {
		t.Errorf("stretched key = %s, want %s", got, want)
	}
}

func TestStretchKeyRoundtrip(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte((i + 1) * 17 % 256)
	}

	plaintext := []byte("secret data to encrypt")
	encKey, err := StretchKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}

	encStr := encryptTestString(string(plaintext), encKey[0:32], encKey[32:64])

	es, _ := ParseEncString(encStr)
	decrypted, err := es.DecryptWithKey(encKey)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}
