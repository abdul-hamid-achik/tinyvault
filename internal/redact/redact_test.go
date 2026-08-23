package redact

import (
	"bytes"
	"testing"
)

func TestLiteral(t *testing.T) {
	secrets := map[string]string{
		"DATABASE_URL": "postgres://user:pass@host:5432/db",
		"API_KEY":      "sk-abc123xyz",
	}
	output := "Connected to postgres://user:pass@host:5432/db using key sk-abc123xyz"
	got := Literal(output, secrets)
	want := "Connected to [REDACTED:DATABASE_URL] using key [REDACTED:API_KEY]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLiteralShortValues(t *testing.T) {
	secrets := map[string]string{
		"SHORT": "ab",
		"EXACT": "abc",
		"LONG":  "abcd",
	}
	got := Literal("values: ab abc abcd", secrets)
	want := "values: ab abc [REDACTED:LONG]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriterReportsOriginalLength(t *testing.T) {
	secrets := map[string]string{"K": "supersecretvalue"}
	var buf bytes.Buffer
	n, err := Writer(&buf, secrets).Write([]byte("token=supersecretvalue\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("token=supersecretvalue\n") {
		t.Errorf("Write n = %d, want original length", n)
	}
	if got := buf.String(); got != "token=[REDACTED:K]\n" {
		t.Errorf("wrote %q", got)
	}
}
