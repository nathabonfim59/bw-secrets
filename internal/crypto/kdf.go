package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

func MakeMasterKey(password, email string, kdf, iterations, memoryKiB, parallelism int) ([]byte, error) {
	salt := strings.ToLower(strings.TrimSpace(email))
	switch kdf {
	case 0:
		return pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New), nil
	case 1:
		return argon2.IDKey([]byte(password), []byte(salt), uint32(iterations), uint32(memoryKiB), uint8(parallelism), 32), nil
	default:
		return nil, ErrUnknownKDF
	}
}

func MakePasswordHash(masterKey []byte, password string) string {
	hash := pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

func StretchKey(masterKey []byte) ([]byte, error) {
	enc, err := hkdf.Expand(sha256.New, masterKey, "enc", 32)
	if err != nil {
		return nil, err
	}
	mac, err := hkdf.Expand(sha256.New, masterKey, "mac", 32)
	if err != nil {
		return nil, err
	}
	return append(enc, mac...), nil
}
