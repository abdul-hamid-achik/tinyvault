package cmd

import (
	"strings"
	"testing"
)

func TestHookSnippets(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "direnv"} {
		out := captureStdout(t, func() {
			if err := runHook(nil, []string{shell}); err != nil {
				t.Fatalf("hook %s: %v", shell, err)
			}
		})
		s := string(out)
		if !strings.Contains(s, "tvault env") {
			t.Errorf("%s snippet should invoke `tvault env`, got: %s", shell, s)
		}
		// The snippet must not contain a bare unescaped secret-injection vector:
		// it sources `tvault env` output, never interpolates a value.
		if strings.Contains(s, "$(eval") {
			t.Errorf("%s snippet looks unsafe: %s", shell, s)
		}
	}
}

func TestHookUnknownShell(t *testing.T) {
	if err := runHook(nil, []string{"powershell"}); err == nil {
		t.Fatal("unknown shell should error")
	}
}

func TestHookCaseInsensitive(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runHook(nil, []string{"ZSH"}); err != nil {
			t.Fatalf("hook ZSH: %v", err)
		}
	})
	if !strings.Contains(string(out), "tvault_load") {
		t.Error("uppercase shell name should resolve")
	}
}
