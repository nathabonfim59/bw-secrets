package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nathabonfim59/bw-secrets/internal/profile"
	"github.com/zalando/go-keyring"
)

const (
	serviceName = "bw-secrets"
	keyName     = "default"
)

var ErrNotLoggedIn = errors.New("not logged in — run 'bw-secrets login'")

type Scope struct {
	Type string `json:"type"` // "folder" or "collection"
	ID   string `json:"id"`   // folder UUID or collection UUID
	Name string `json:"name"` // human-readable name
}

type Credentials struct {
	ServerURL    string `json:"server_url"`
	Email        string `json:"email"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	EncKey       string `json:"enc_key"`
	Scope        *Scope `json:"scope,omitempty"`
}

func SaveProfile(name string, creds *Credentials) error {
	if err := profile.Validate(name); err != nil {
		return err
	}
	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	err = keyring.Set(serviceName, name, string(data))
	if err != nil {
		return fileSaveProfile(name, string(data))
	}
	return fileDeleteProfile(name)
}

func LoadProfile(name string) (*Credentials, error) {
	if err := profile.Validate(name); err != nil {
		return nil, err
	}
	data, err := keyring.Get(serviceName, name)
	if err != nil {
		data, err = fileLoadProfile(name)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
	}
	var creds Credentials
	if err := json.Unmarshal([]byte(data), &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func DeleteProfile(name string) error {
	if err := profile.Validate(name); err != nil {
		return err
	}
	err := keyring.Delete(serviceName, name)
	fileErr := fileDeleteProfile(name)
	// A missing key is expected when this profile uses file storage.
	if errors.Is(err, keyring.ErrNotFound) {
		err = nil
	}
	return errors.Join(err, fileErr)
}

func profileFilePath(name string) (string, error) {
	if err := profile.Validate(name); err != nil {
		return "", err
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if name == keyName {
		return filepath.Join(configDir, "bw-secrets", "credentials.json"), nil
	}
	return filepath.Join(configDir, "bw-secrets", "profiles", name, "credentials.json"), nil
}

func fileSaveProfile(name, data string) error {
	path, err := profileFilePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0600)
}

func fileLoadProfile(name string) (string, error) {
	path, err := profileFilePath(name)
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

func fileDeleteProfile(name string) error {
	path, err := profileFilePath(name)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
