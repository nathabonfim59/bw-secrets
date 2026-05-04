package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStripOuterQuotes(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`"hello"`, "hello"},
		{`'hello'`, "hello"},
		{`hello`, "hello"},
		{`"inner 'quote'"`, "inner 'quote'"},
		{`'inner "quote"'`, `inner "quote"`},
		{`"`, `"`},
		{``, ``},
		{`"value"`, "value"},
		{`"key = value"`, "key = value"},
		{`"$VAR not expanded"`, "$VAR not expanded"},
	}
	for _, tc := range cases {
		got := stripOuterQuotes(tc.input)
		if got != tc.want {
			t.Errorf("stripOuterQuotes(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.env")
	content := `# This is a comment
DB_HOST=localhost
DB_USER=admin
DB_PASS = secret123
EMPTY=
QUOTED="value with spaces"
SINGLE_QUOTED='single quoted'
# Another comment
INNER_QUOTES={"json":"value"}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	vars, err := parseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string]string{
		"DB_HOST":       "localhost",
		"DB_USER":       "admin",
		"DB_PASS":       "secret123",
		"EMPTY":         "",
		"QUOTED":        "value with spaces",
		"SINGLE_QUOTED": "single quoted",
		"INNER_QUOTES":  `{"json":"value"}`,
	}
	for k, want := range checks {
		if got := vars[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	if _, ok := vars["# This is a comment"]; ok {
		t.Error("comment parsed as variable")
	}
	if _, ok := vars["# Another comment"]; ok {
		t.Error("comment parsed as variable")
	}
}

func TestParseEnvFileVariableExpansion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expand.env")
	content := `HOST=localhost
PORT=8080
URL=http://${HOST}:${PORT}/api
REFER=$HOST
MIXED=http://${HOST}:$PORT`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	vars, err := parseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if vars["URL"] != "http://localhost:8080/api" {
		t.Errorf("URL = %q", vars["URL"])
	}
	if vars["REFER"] != "localhost" {
		t.Errorf("REFER = %q", vars["REFER"])
	}
	if vars["MIXED"] != "http://localhost:8080" {
		t.Errorf("MIXED = %q", vars["MIXED"])
	}
}

func TestParseEnvFileEnvExpansion(t *testing.T) {
	os.Setenv("TEST_ENV_VAR", "from-env")
	defer os.Unsetenv("TEST_ENV_VAR")

	dir := t.TempDir()
	path := filepath.Join(dir, "env-expand.env")
	content := `VALUE=$TEST_ENV_VAR`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	vars, err := parseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if vars["VALUE"] != "from-env" {
		t.Errorf("VALUE = %q, want 'from-env'", vars["VALUE"])
	}
}

func TestParseEnvFileSingleQuotesNoExpansion(t *testing.T) {
	os.Setenv("VAR", "expanded")
	defer os.Unsetenv("VAR")

	dir := t.TempDir()
	path := filepath.Join(dir, "noexpand.env")
	content := `KEY='$VAR'`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	vars, err := parseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if vars["KEY"] != "$VAR" {
		t.Errorf("KEY = %q, want '$VAR' (should NOT expand in single quotes)", vars["KEY"])
	}
}

func TestParseEnvFileMissing(t *testing.T) {
	_, err := parseEnvFile("/tmp/nonexistent-file-12345.env")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
