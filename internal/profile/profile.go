// Package profile selects login profiles and persists local directory bindings.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const Env = "BW_SECRETS_PROFILE"

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func Validate(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid profile %q: use 1–64 letters, digits, underscores or hyphens, starting with a letter or digit", name)
	}
	return nil
}

type Selection struct {
	Name      string
	Source    string
	Directory string
}

type Config struct {
	Bindings map[string]string `json:"bindings"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "bw-secrets", "profiles.json"), nil
}

func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{Bindings: make(map[string]string)}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("reading profile bindings: %w", err)
	}
	if cfg.Bindings == nil {
		cfg.Bindings = make(map[string]string)
	}
	for dir, name := range cfg.Bindings {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return nil, fmt.Errorf("invalid binding directory %q", dir)
		}
		if err := Validate(name); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".profiles-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Directory uses physical paths so a symlink cannot accidentally bypass a binding.
func Directory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", path)
	}
	return abs, nil
}

// Resolve applies explicit flag > nearest directory binding > environment > default.
func Resolve(explicit, inherited, cwd string) (Selection, error) {
	if explicit != "" {
		return Selection{Name: explicit, Source: "flag"}, Validate(explicit)
	}
	cfg, err := Load()
	if err != nil {
		return Selection{}, err
	}
	dir, err := Directory(cwd)
	if err != nil {
		return Selection{}, err
	}
	for {
		if name, ok := cfg.Bindings[dir]; ok {
			return Selection{Name: name, Source: "directory", Directory: dir}, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if inherited != "" {
		return Selection{Name: inherited, Source: "environment"}, Validate(inherited)
	}
	return Selection{Name: "default", Source: "default"}, nil
}
