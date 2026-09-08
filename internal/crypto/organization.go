package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
)

// DecryptPrivateKey unwraps the account's PKCS#8 RSA key with its user key.
func DecryptPrivateKey(encrypted string, key *SymmetricKey) (*rsa.PrivateKey, error) {
	es, err := ParseEncString(encrypted)
	if err != nil {
		return nil, err
	}
	der, err := es.Decrypt(key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey([]byte(der))
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("account private key is not RSA")
	}
	return private, nil
}

// DecryptOrganizationKey supports Bitwarden RSA-OAEP SHA-256 (3) and SHA-1 (4).
func DecryptOrganizationKey(encrypted string, private *rsa.PrivateKey) (*SymmetricKey, error) {
	kind, encoded, ok := strings.Cut(encrypted, ".")
	if !ok {
		return nil, ErrInvalidEncString
	}
	var h hash.Hash
	switch kind {
	case "3":
		h = sha256.New()
	case "4":
		h = sha1.New()
	default:
		return nil, ErrUnknownEncType
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidEncString
	}
	raw, err := rsa.DecryptOAEP(h, rand.Reader, private, data, nil)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(raw)
}
