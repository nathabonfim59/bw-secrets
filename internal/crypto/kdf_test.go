package crypto

import (
	"encoding/base64"
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
	stretched := StretchKey(masterKey)
	if len(stretched) != 64 {
		t.Fatalf("stretched key length = %d, want 64", len(stretched))
	}
	enc := stretched[0:32]
	mac := stretched[32:64]
	if string(enc) == string(mac) {
		t.Error("enc and mac halves should differ")
	}
	for _, b := range enc {
		if b != 0 {
			return // found non-zero byte, valid
		}
	}
	t.Error("enc key half is all zeros")
}

func TestStretchKeyRoundtrip(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte((i + 1) * 17 % 256)
	}

	plaintext := []byte("secret data to encrypt")
	encKey := StretchKey(masterKey)

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
