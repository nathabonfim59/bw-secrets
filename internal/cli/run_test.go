package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaskWriter(t *testing.T) {
	var buf bytes.Buffer
	mw := newMaskWriter(&buf, []string{"secret123", "token-abc"})

	n, err := mw.Write([]byte("use secret123 and token-abc here"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Errorf("wrote %d bytes, want 32", n)
	}

	output := buf.String()
	if strings.Contains(output, "secret123") {
		t.Error("output contains secret123, should be masked")
	}
	if strings.Contains(output, "token-abc") {
		t.Error("output contains token-abc, should be masked")
	}
	if !strings.Contains(output, "***") {
		t.Error("output does not contain ***")
	}
}

func TestMaskWriterNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	mw := newMaskWriter(&buf, nil)

	input := "hello world"
	n, err := mw.Write([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(input) {
		t.Errorf("wrote %d bytes, want %d", n, len(input))
	}
	if buf.String() != "hello world" {
		t.Errorf("output = %q, want 'hello world'", buf.String())
	}
}

func TestMaskWriterEmptySecret(t *testing.T) {
	var buf bytes.Buffer
	mw := newMaskWriter(&buf, []string{""})

	n, err := mw.Write([]byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Errorf("wrote %d bytes, want 11", n)
	}
	if buf.String() != "hello world" {
		t.Errorf("output = %q", buf.String())
	}
}

func TestMaskWriterMultiWrite(t *testing.T) {
	var buf bytes.Buffer
	mw := newMaskWriter(&buf, []string{"secret"})

	mw.Write([]byte("first secret "))
	mw.Write([]byte("more secret end"))

	output := buf.String()
	if strings.Contains(output, "secret") {
		t.Errorf("output contains 'secret', should be masked: %q", output)
	}
	expected := "first *** more *** end"
	if output != expected {
		t.Errorf("output = %q, want %q", output, expected)
	}
}
