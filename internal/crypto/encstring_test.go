package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestNewSymmetricKey(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i)
	}
	sk, err := NewSymmetricKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if sk.EncryptionKey[i] != byte(i) {
			t.Errorf("EncryptionKey[%d] = %d, want %d", i, sk.EncryptionKey[i], i)
		}
		if sk.MACKey[i] != byte(i+32) {
			t.Errorf("MACKey[%d] = %d, want %d", i, sk.MACKey[i], i+32)
		}
	}
}

func TestNewSymmetricKeyBadLength(t *testing.T) {
	_, err := NewSymmetricKey(make([]byte, 32))
	if err != ErrKeyLength {
		t.Errorf("expected ErrKeyLength, got %v", err)
	}
}

func TestParseEncStringType2(t *testing.T) {
	encStr := encryptTestString("test", make([]byte, 32), make([]byte, 32))
	es, err := ParseEncString(encStr)
	if err != nil {
		t.Fatal(err)
	}
	if es.Type != 2 {
		t.Errorf("Type = %d, want 2", es.Type)
	}
	if len(es.IV) != 16 {
		t.Errorf("IV length = %d, want 16", len(es.IV))
	}
	if len(es.MAC) != 32 {
		t.Errorf("MAC length = %d, want 32", len(es.MAC))
	}
}

func TestParseEncStringInvalid(t *testing.T) {
	cases := []string{
		"",
		"xx",
		"2.bad|no mac",
	}
	for _, c := range cases {
		_, err := ParseEncString(c)
		if err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestParseEncStringUnknownType(t *testing.T) {
	_, err := ParseEncString("9.something")
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestEncStringDecryptType0Rejected(t *testing.T) {
	es := &EncString{Type: 0}
	sk := &SymmetricKey{}
	_, err := es.Decrypt(sk)
	if err != ErrUnauthenticated {
		t.Errorf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestPkcs7Unpad(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{"single byte pad", append([]byte("hello"), 1), "hello", false},
		{"16 byte pad", append([]byte("test"), 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16), "test", false},
		{"empty", nil, "", true},
		{"zero pad byte", append([]byte("data"), 0), "", true},
		{"pad too large", append([]byte("x"), 17), "", true},
		{"inconsistent padding", []byte{0x01, 0x02}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkcs7Unpad(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoundtripDecrypt(t *testing.T) {
	masterKey := make([]byte, 64)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}

	encKey := masterKey[0:32]
	macKey := masterKey[32:64]

	plaintext := "hello world"

	encStr := encryptTestString(plaintext, encKey, macKey)

	es, err := ParseEncString(encStr)
	if err != nil {
		t.Fatal("parse:", err)
	}
	sk, err := NewSymmetricKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := es.Decrypt(sk)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if decrypted != plaintext {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestMACVerificationFails(t *testing.T) {
	masterKey := make([]byte, 64)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	encKey := masterKey[0:32]
	macKey := masterKey[32:64]
	plaintext := "hello world"
	encStr := encryptTestString(plaintext, encKey, macKey)
	es, _ := ParseEncString(encStr)

	masterKey[63] ^= 0xFF
	sk, _ := NewSymmetricKey(masterKey)

	_, err := es.Decrypt(sk)
	if err != ErrMACMismatch {
		t.Errorf("expected ErrMACMismatch, got %v", err)
	}
}

func encryptTestString(plaintext string, encKey, macKey []byte) string {
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte((i + 1) * 7 % 256)
	}

	padded := pkcs7Pad([]byte(plaintext), 16)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ct)
	macSum := mac.Sum(nil)

	return "2." +
		base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct) + "|" +
		base64.StdEncoding.EncodeToString(macSum)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := make([]byte, padLen)
	for i := range pad {
		pad[i] = byte(padLen)
	}
	return append(data, pad...)
}
