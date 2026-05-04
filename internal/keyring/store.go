package keyring

import (
	"encoding/json"
	"errors"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "bw-secrets"
	keyName     = "default"
)

var ErrNotLoggedIn = errors.New("not logged in — run 'bw-secrets login'")

type Credentials struct {
	ServerURL    string `json:"server_url"`
	Email        string `json:"email"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	EncKey       string `json:"enc_key"`
}

func Save(creds *Credentials) error {
	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	return keyring.Set(serviceName, keyName, string(data))
}

func Load() (*Credentials, error) {
	data, err := keyring.Get(serviceName, keyName)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	var creds Credentials
	if err := json.Unmarshal([]byte(data), &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func Delete() error {
	err := keyring.Delete(serviceName, keyName)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
