package crypto

import (
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
