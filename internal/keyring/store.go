package keyring

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

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
	err = keyring.Set(serviceName, keyName, string(data))
	if err != nil {
		return fileSave(string(data))
	}
	return nil
}

func Load() (*Credentials, error) {
	data, err := keyring.Get(serviceName, keyName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotLoggedIn
		}
		data, err = fileLoad()
		if err != nil {
			return nil, err
		}
	}
	var creds Credentials
	if err := json.Unmarshal([]byte(data), &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func Delete() error {
	keyring.Delete(serviceName, keyName)
	return fileDelete()
}

func filePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "bw-secrets", "credentials.json"), nil
}

func fileSave(data string) error {
	path, err := filePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0600)
}

func fileLoad() (string, error) {
	path, err := filePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotLoggedIn
		}
		return "", err
	}
	return string(data), nil
}

func fileDelete() error {
	path, err := filePath()
	if err != nil {
		return err
	}
	os.Remove(path)
	return nil
}
