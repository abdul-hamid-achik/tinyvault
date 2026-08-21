package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalJSONControlBytesAndHTML(t *testing.T) {
	in := map[string]string{
		"Z_LAST":  "z",
		"A_FIRST": "a",
		"CTRL":    "line1\r\nline2\tend\x00nul",
		"AMP":     "postgres://u:p@h/db?sslmode=disable&foo=1",
	}
	raw, err := marshalJSON(in)
	if err != nil {
		t.Fatalf("marshalJSON: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	for k, want := range in {
		if out[k] != want {
			t.Errorf("%s: got %q, want %q", k, out[k], want)
		}
	}
	body := string(raw)
	if strings.Contains(body, `\u0026`) {
		t.Errorf("HTML-escaped ampersand:\n%s", body)
	}
	if !strings.Contains(body, "&foo=1") {
		t.Errorf("literal & missing:\n%s", body)
	}
	// encoding/json sorts map keys lexicographically ("AMP" < "A_FIRST"
	// because 'M' < '_').
	wantOrder := []string{`"AMP"`, `"A_FIRST"`, `"CTRL"`, `"Z_LAST"`}
	pos := 0
	for _, key := range wantOrder {
		i := strings.Index(body[pos:], key)
		if i < 0 {
			t.Fatalf("key %s not found after position %d in:\n%s", key, pos, body)
		}
		pos += i + len(key)
	}
}
