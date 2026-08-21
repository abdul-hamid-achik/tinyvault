package crypto

import (
	"strings"
	"testing"
	"unicode"
)

func TestGenerateRandomStringLengthAndCharset(t *testing.T) {
	cases := []struct {
		charset string
		length  int
		ok      func(string) bool
	}{
		{"alphanumeric", 32, func(s string) bool {
			for _, r := range s {
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
					return false
				}
			}
			return true
		}},
		{"hex", 24, func(s string) bool {
			for _, r := range s {
				if !strings.ContainsRune("0123456789abcdef", r) {
					return false
				}
			}
			return true
		}},
		{"base64", 40, func(s string) bool {
			return len(s) == 40
		}},
		{"ascii", 16, func(s string) bool {
			return len(s) == 16
		}},
	}
	for _, tc := range cases {
		t.Run(tc.charset, func(t *testing.T) {
			got, err := GenerateRandomString(tc.length, tc.charset)
			if err != nil {
				t.Fatalf("GenerateRandomString: %v", err)
			}
			if len(got) != tc.length {
				t.Fatalf("len = %d, want %d", len(got), tc.length)
			}
			if !tc.ok(got) {
				t.Fatalf("value not in charset %s", tc.charset)
			}
		})
	}
}

func TestGenerateRandomStringRejectsBadInput(t *testing.T) {
	if _, err := GenerateRandomString(0, "alphanumeric"); err == nil {
		t.Fatal("expected error for length 0")
	}
	if _, err := GenerateRandomString(MaxGeneratedSecretLength+1, "alphanumeric"); err == nil {
		t.Fatal("expected error for oversize length")
	}
	if _, err := GenerateRandomString(8, "emoji"); err == nil {
		t.Fatal("expected error for unknown charset")
	}
}

func TestGenerateRandomStringNotConstant(t *testing.T) {
	a, err := GenerateRandomString(32, "alphanumeric")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateRandomString(32, "alphanumeric")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two draws produced the same string")
	}
}
