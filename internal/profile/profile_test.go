package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolution(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	project := filepath.Join(root, "project")
	nested := filepath.Join(project, "nested")
	child := filepath.Join(nested, "child")
	sibling := filepath.Join(root, "project-other")
	for _, dir := range []string{child, sibling} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bindings[project] = "work"
	cfg.Bindings[nested] = "personal"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, flag, env, dir, want, source string
	}{
		{"default", "", "", root, "default", "default"},
		{"environment", "", "shell", root, "shell", "environment"},
		{"binding", "", "shell", project, "work", "directory"},
		{"nested binding", "", "shell", nested, "personal", "directory"},
		{"descendant", "", "shell", child, "personal", "directory"},
		{"explicit override", "explicit", "shell", child, "explicit", "flag"},
		{"path boundary", "", "shell", sibling, "shell", "environment"},
		{"binding overrides invalid env", "", "../bad", project, "work", "directory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.flag, tt.env, tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tt.want || got.Source != tt.source {
				t.Fatalf("got %+v, want %s (%s)", got, tt.want, tt.source)
			}
		})
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve("", "shell", link)
	if err != nil || got.Name != "personal" {
		t.Fatalf("symlink: %+v, %v", got, err)
	}
	delete(cfg.Bindings, nested)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	got, err = Resolve("", "shell", child)
	if err != nil || got.Name != "work" {
		t.Fatalf("parent after unbind: %+v, %v", got, err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	for _, name := range []string{"../work", "a/b", "a\\b", "$(id)", "a;b", "-work", "a b"} {
		if _, err := Resolve(name, "", root); err == nil {
			t.Errorf("accepted invalid name %q", name)
		}
	}
	if _, err := Resolve("", "../bad", root); err == nil {
		t.Fatal("accepted invalid inherited profile")
	}
	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{broken`, `{"bindings":{"relative":"work"}}`, `{"bindings":{"/":"../bad"}}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Resolve("", "shell", root); err == nil {
			t.Fatalf("silently fell back for %s", data)
		}
	}
}
