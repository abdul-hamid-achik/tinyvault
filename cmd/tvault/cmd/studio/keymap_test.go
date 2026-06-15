package studio

import (
	"testing"

	key "charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

func TestKeyMapBindings(t *testing.T) {
	km := newKeyMap()
	cases := []struct {
		name    string
		binding key.Binding
		press   string
	}{
		{"quit", km.Quit, "q"},
		{"help", km.Help, "?"},
		{"filter", km.Filter, "/"},
		{"reveal", km.Reveal, "r"},
		{"copy", km.Copy, "c"},
		{"unlock", km.Unlock, "u"},
		{"pane1", km.Pane1, "1"},
		{"pane3", km.Pane3, "3"},
		{"down", km.Down, "j"},
		{"up", km.Up, "k"},
	}
	for _, tc := range cases {
		if !key.Matches(keyPress(tc.press), tc.binding) {
			t.Errorf("%s: key %q did not match its binding (keys=%v)", tc.name, tc.press, tc.binding.Keys())
		}
	}
}

func TestKeyMapNoCollisions(t *testing.T) {
	km := newKeyMap()
	// Single-key bindings used in normal mode must be unique so a press is
	// unambiguous. (Arrow aliases and modifiers are exempt.)
	single := map[string]string{}
	for name, b := range map[string]key.Binding{
		"Filter": km.Filter, "Reveal": km.Reveal, "RevealAll": km.RevealAll,
		"Copy": km.Copy, "Unlock": km.Unlock, "Lock": km.Lock, "Help": km.Help,
		"Pane1": km.Pane1, "Pane2": km.Pane2, "Pane3": km.Pane3, "Pane4": km.Pane4,
	} {
		for _, k := range b.Keys() {
			if len(k) != 1 {
				continue
			}
			if prev, ok := single[k]; ok {
				t.Errorf("key %q bound to both %s and %s", k, prev, name)
			}
			single[k] = name
		}
	}
}

func TestKeyMapHelpImplemented(t *testing.T) {
	km := newKeyMap()
	if len(km.ShortHelp()) == 0 {
		t.Error("ShortHelp should list bindings")
	}
	if len(km.FullHelp()) == 0 {
		t.Error("FullHelp should list binding groups")
	}
}

func TestNamedKeysMatch(t *testing.T) {
	km := newKeyMap()
	if !key.Matches(keyPress("enter"), km.Enter) {
		t.Error("enter should match Enter binding")
	}
	if !key.Matches(keyPress("esc"), km.Escape) {
		t.Error("esc should match Escape binding")
	}
	if !key.Matches(keyPress("tab"), km.NextPane) {
		t.Error("tab should match NextPane binding")
	}
	// sanity: a KeyPressMsg stringifies to the expected token.
	if got := (tea.KeyPressMsg{Code: tea.KeyEnter}).String(); got != "enter" {
		t.Errorf("KeyEnter.String() = %q, want enter", got)
	}
}
