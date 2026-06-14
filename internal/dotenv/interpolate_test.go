package dotenv

import (
	"errors"
	"testing"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		in        string
		want      Ref
		wantErr   bool
		errSubstr string
	}{
		{"tvault://DATABASE_URL", Ref{Project: "", Key: "DATABASE_URL"}, false, ""},
		{"tvault:///DATABASE_URL", Ref{Project: "", Key: "DATABASE_URL"}, false, ""}, // same as above
		{"tvault://current/STRIPE_KEY", Ref{Project: "current", Key: "STRIPE_KEY"}, false, ""},
		{"tvault://production/DATABASE_URL", Ref{Project: "production", Key: "DATABASE_URL"}, false, ""},
		{"", Ref{}, true, "missing"},
		{"DATABASE_URL", Ref{}, true, "missing"},
		{"tvault://", Ref{}, true, "empty"},
		{"tvault://production/", Ref{}, true, "missing key"},
		{"tvault://proj/sub/key", Ref{}, true, "single segment"},
		{"tvault://with space/KEY", Ref{}, true, "whitespace"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseRef(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (parsed as %+v)", got)
				}
				var ire *ErrInvalidRef
				if !errors.As(err, &ire) {
					t.Fatalf("expected ErrInvalidRef, got %T", err)
				}
				if tt.errSubstr != "" && !contains(ire.Reason, tt.errSubstr) && !contains(ire.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain %q", ire.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRefsExtraction(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"plain value", nil},
		{"${tvault://KEY}", []string{"tvault://KEY"}},
		{"${tvault://production/DB}", []string{"tvault://production/DB"}},
		{"prefix ${tvault://A} middle ${tvault://B} suffix", []string{"tvault://A", "tvault://B"}},
		{"${VAULT:NOT_A_REFERENCE}", nil},                                         // different scheme
		{"${tvault://KEY", nil},                                                   // unterminated
		{"https://example.com/${not_ours}", nil},                                  // not a tvault:// scheme
		{"${tvault://X} and ${tvault://X}", []string{"tvault://X", "tvault://X"}}, // duplicates preserved
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Refs(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d refs (%v), want %d (%v)", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ref[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestResolve(t *testing.T) {
	// Resolver that just echoes back the key.
	lookup := map[Ref]string{
		{Key: "DATABASE_URL"}:                   "postgres://localhost/x",
		{Project: "production", Key: "DB"}:      "postgres://prod/x",
		{Project: "current", Key: "STRIPE_KEY"}: "sk_live_abc",
	}
	resolver := func(r Ref) (string, error) {
		v, ok := lookup[r]
		if !ok {
			return "", errors.New("not found: " + r.String())
		}
		return v, nil
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"single", "${tvault://DATABASE_URL}", "postgres://localhost/x"},
		{"project-qualified", "${tvault://production/DB}", "postgres://prod/x"},
		{"current", "${tvault://current/STRIPE_KEY}", "sk_live_abc"},
		{"wrapped", "url=${tvault://DATABASE_URL}&ok=1", "url=postgres://localhost/x&ok=1"},
		{"multiple", "${tvault://DATABASE_URL}/${tvault://current/STRIPE_KEY}", "postgres://localhost/x/sk_live_abc"},
		{"url-with-tvault-literal", "https://example.com/${not_ours}", "https://example.com/${not_ours}"},
		{"unterminated", "${tvault://KEY no_close", "${tvault://KEY no_close"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.in, resolver)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveErrorPropagates(t *testing.T) {
	resolver := func(r Ref) (string, error) {
		return "", errors.New("nope")
	}
	_, err := Resolve("${tvault://MISSING}", resolver)
	if err == nil {
		t.Fatal("expected error from resolver")
	}
}

func TestResolveInvalidReferenceIsError(t *testing.T) {
	resolver := func(r Ref) (string, error) { return "x", nil }
	_, err := Resolve("${tvault://}", resolver)
	if err == nil {
		t.Fatal("expected error for malformed reference")
	}
}

func TestHasRef(t *testing.T) {
	if HasRef("plain value") {
		t.Error("plain value should not have a ref")
	}
	if !HasRef("${tvault://KEY}") {
		t.Error("expected ref detected")
	}
	if HasRef("${VAULT:NOT_TVAULT}") {
		t.Error("non-tvault ref should not be detected")
	}
}

func TestParseBytesRespectsInterpolation(t *testing.T) {
	// The dotenv parser preserves tvault:// references verbatim; the
	// caller is expected to invoke Resolve at run time.
	parsed, err := ParseBytes("test.env", []byte("DATABASE_URL=${tvault://DATABASE_URL}\n"))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(parsed.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(parsed.Entries))
	}
	if parsed.Entries[0].Value != "${tvault://DATABASE_URL}" {
		t.Errorf("expected verbatim placeholder, got %q", parsed.Entries[0].Value)
	}
}

func contains(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
