package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

var (
	ErrUnknownKDF       = errors.New("unknown KDF type")
	ErrInvalidEncString = errors.New("invalid encrypted string format")
	ErrUnknownEncType   = errors.New("unknown encryption type")
	ErrUnauthenticated  = errors.New("decryption of unauthenticated type 0 is not allowed")
	ErrMACMismatch      = errors.New("MAC verification failed")
	ErrInvalidPadding   = errors.New("invalid PKCS#7 padding")
	ErrKeyLength        = errors.New("symmetric key must be exactly 64 bytes")
)

type SymmetricKey struct {
	EncryptionKey [32]byte
	MACKey        [32]byte
}

func NewSymmetricKey(raw []byte) (*SymmetricKey, error) {
	if len(raw) != 64 {
		return nil, ErrKeyLength
	}
	sk := &SymmetricKey{}
	copy(sk.EncryptionKey[:], raw[0:32])
	copy(sk.MACKey[:], raw[32:64])
	return sk, nil
}

type EncString struct {
	Type       int
	IV         []byte
	CipherText []byte
	MAC        []byte
}

func ParseEncString(s string) (*EncString, error) {
	if len(s) < 3 || s[1] != '.' {
		return nil, ErrInvalidEncString
	}
	es := &EncString{Type: int(s[0] - '0')}
	if es.Type < 0 || es.Type > 9 {
		return nil, ErrInvalidEncString
	}
	rest := s[2:]
	switch es.Type {
	case 2:
		parts := strings.SplitN(rest, "|", 3)
		if len(parts) != 3 {
			return nil, ErrInvalidEncString
		}
		var err error
		es.IV, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, ErrInvalidEncString
		}
		es.CipherText, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, ErrInvalidEncString
		}
		es.MAC, err = base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, ErrInvalidEncString
		}
	default:
		return nil, ErrUnknownEncType
	}
	return es, nil
}

func (e *EncString) Decrypt(key *SymmetricKey) (string, error) {
	switch e.Type {
	case 0:
		return "", ErrUnauthenticated
	case 2:
		return e.decryptAesCbc256Hmac(key)
	default:
		return "", ErrUnknownEncType
	}
}

func (e *EncString) DecryptWithKey(rawKey []byte) ([]byte, error) {
	switch e.Type {
	case 0:
		return nil, ErrUnauthenticated
	case 2:
		mac := hmac.New(sha256.New, rawKey[32:64])
		mac.Write(e.IV)
		mac.Write(e.CipherText)
		if !hmac.Equal(mac.Sum(nil), e.MAC) {
			return nil, ErrMACMismatch
		}
		block, err := aes.NewCipher(rawKey[0:32])
		if err != nil {
			return nil, err
		}
		if len(e.CipherText)%aes.BlockSize != 0 {
			return nil, errors.New("ciphertext is not a multiple of block size")
		}
		mode := cipher.NewCBCDecrypter(block, e.IV)
		plaintext := make([]byte, len(e.CipherText))
		mode.CryptBlocks(plaintext, e.CipherText)
		return pkcs7Unpad(plaintext)
	default:
		return nil, ErrUnknownEncType
	}
}

func (e *EncString) decryptAesCbc256Hmac(key *SymmetricKey) (string, error) {
	mac := hmac.New(sha256.New, key.MACKey[:])
	mac.Write(e.IV)
	mac.Write(e.CipherText)
	if !hmac.Equal(mac.Sum(nil), e.MAC) {
		return "", ErrMACMismatch
	}
	block, err := aes.NewCipher(key.EncryptionKey[:])
	if err != nil {
		return "", err
	}
	if len(e.CipherText)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of block size")
	}
	mode := cipher.NewCBCDecrypter(block, e.IV)
	plaintext := make([]byte, len(e.CipherText))
	mode.CryptBlocks(plaintext, e.CipherText)
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) || padLen > aes.BlockSize || padLen == 0 {
		return nil, ErrInvalidPadding
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, ErrInvalidPadding
		}
	}
	return data[:len(data)-padLen], nil
}

func ExtractSymmetricKey(encString string, masterKey []byte) (*SymmetricKey, error) {
	es, err := ParseEncString(encString)
	if err != nil {
		return nil, err
	}
	raw, err := es.DecryptWithKey(masterKey)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(raw)
}
