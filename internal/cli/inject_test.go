package cli

import (
	"os"
	"testing"
)

func TestExpandEnvTemplate(t *testing.T) {
	os.Setenv("MY_VAULT", "Production")
	os.Setenv("MY_ITEM", "MySQL")
	defer os.Unsetenv("MY_VAULT")
	defer os.Unsetenv("MY_ITEM")

	cases := []struct {
		input string
		want  string
	}{
		{"bw://$MY_VAULT/item/password", "bw://Production/item/password"},
		{"bw://${MY_VAULT}/item/password", "bw://Production/item/password"},
		{"bw://$MY_VAULT/$MY_ITEM/password", "bw://Production/MySQL/password"},
		{"no vars here", "no vars here"},
		{"$UNDEFINED", ""},
	}
	for _, tc := range cases {
		got := expandEnvTemplate(tc.input)
		if got != tc.want {
			t.Errorf("expandEnvTemplate(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestDedupeURIs(t *testing.T) {
	uris := []string{
		"bw://vault/item/pass",
		"bw://vault/item/user",
		"bw://vault/item/pass",
		"bw://vault2/item/pass",
	}
	got := dedupeURIs(uris)
	if len(got) != 3 {
		t.Errorf("got %d URIs, want 3: %v", len(got), got)
	}
	seen := make(map[string]bool)
	for _, u := range got {
		if seen[u] {
			t.Errorf("duplicate URI in result: %s", u)
		}
		seen[u] = true
	}
}

func TestExpandEnvTemplateNoMatch(t *testing.T) {
	result := expandEnvTemplate("hello world")
	if result != "hello world" {
		t.Errorf("got %q, want 'hello world'", result)
	}
}
