package crypto

import (
	"crypto/hmac"
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

func StretchKey(masterKey []byte) []byte {
	enc := hkdfExpand(masterKey, []byte("enc"), 32)
	mac := hkdfExpand(masterKey, []byte("mac"), 32)
	stretched := make([]byte, 64)
	copy(stretched[0:32], enc)
	copy(stretched[32:64], mac)
	return stretched
}

func hkdfExpand(prk, info []byte, size int) []byte {
	hashLen := 32
	result := make([]byte, size)
	var t []byte
	for i := byte(1); i <= byte((size+hashLen-1)/hashLen); i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		copy(result[(int(i)-1)*hashLen:], t)
	}
	return result
}
