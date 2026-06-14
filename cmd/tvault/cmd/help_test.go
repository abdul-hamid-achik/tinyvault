package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestEmitHelpText verifies the human-readable default output.
func TestEmitHelpText(t *testing.T) {
	out := &bytes.Buffer{}
	if err := emitHelp(out, "", false); err != nil {
		t.Fatalf("emitHelp: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "tvault - the CLI user manual") {
		t.Errorf("missing title; first 200 bytes: %q", body[:min200(len(body))])
	}
	for _, want := range []string{"Lifecycle", "Conventions", "Output formats", "Safety", "Recipes", "Agent guide", "Troubleshooting", "Topics"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing section %q in default help output", want)
		}
	}
}

// min200 returns min(n, 200) without pulling in the generic
// builtin (which is only available in newer Go versions).
func min200(n int) int {
	if n < 200 {
		return n
	}
	return 200
}

// TestEmitHelpJSON verifies the JSON output is well-formed.
func TestEmitHelpJSON(t *testing.T) {
	var doc map[string]any
	out := &bytes.Buffer{}
	if err := emitHelp(out, "", true); err != nil {
		t.Fatalf("emitHelp --json: %v", err)
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, out)
	}
	for _, k := range []string{
		"overview", "lifecycle", "conventions", "output", "safety",
		"recipes", "agent_guide", "troubleshooting", "browse", "topics",
	} {
		if _, ok := doc[k]; !ok {
			t.Errorf("JSON manifest missing top-level key %q", k)
		}
	}
	if got, want := len(doc["lifecycle"].([]any)), 6; got != want {
		t.Errorf("lifecycle has %d entries, want %d", got, want)
	}
	if got, want := len(doc["recipes"].([]any)), 13; got != want {
		t.Errorf("recipes has %d entries, want %d", got, want)
	}
	if got, want := len(doc["topics"].([]any)), 7; got != want {
		t.Errorf("topics has %d entries, want %d", got, want)
	}
	if got, want := len(doc["troubleshooting"].([]any)), 8; got != want {
		t.Errorf("troubleshooting has %d entries, want %d", got, want)
	}
}

// TestEmitHelpTopicText verifies each topic produces non-empty text.
func TestEmitHelpTopicText(t *testing.T) {
	topics := []string{"workflow", "safety", "recipes", "output", "agent", "troubleshooting", "browse", "topics"}
	for _, topic := range topics {
		t.Run(topic, func(t *testing.T) {
			out := &bytes.Buffer{}
			if err := emitHelp(out, topic, false); err != nil {
				t.Fatalf("emitHelp %s: %v", topic, err)
			}
			if out.Len() == 0 {
				t.Errorf("topic %q produced empty output", topic)
			}
		})
	}
}

// TestEmitHelpTopicJSON verifies each topic JSON shape.
//
// Some topics (workflow, safety, output, agent) emit a wrapped
// JSON object; others (recipes, troubleshooting, topics) emit a
// top-level JSON array because the underlying data is naturally
// a list. This test handles both shapes.
func TestEmitHelpTopicJSON(t *testing.T) {
	cases := []struct {
		topic        string
		shapeIsArray bool
		wantKeys     []string // for object shape: required top-level keys
		firstItemKey string   // for array shape: required key in each element
	}{
		{topic: "workflow", shapeIsArray: false, wantKeys: []string{"topic", "lifecycle"}},
		{topic: "safety", shapeIsArray: false, wantKeys: []string{"encryption", "key_hierarchy", "redaction", "agent_safety", "never_do_this", "encrypted_env_note"}},
		{topic: "recipes", shapeIsArray: true, firstItemKey: "name"},
		{topic: "output", shapeIsArray: false, wantKeys: []string{"json_usage", "env_formats", "golden_rule"}},
		{topic: "agent", shapeIsArray: false, wantKeys: []string{"discover", "preferred_order", "anti_patterns", "when_to_ask_for_help"}},
		{topic: "troubleshooting", shapeIsArray: true, firstItemKey: "problem"},
		{topic: "browse", shapeIsArray: false, wantKeys: []string{"what_it_is", "what_it_is_not", "panes", "keys", "when_to_use", "security"}},
		{topic: "topics", shapeIsArray: true, firstItemKey: "slug"},
	}
	for _, tc := range cases {
		t.Run(tc.topic, func(t *testing.T) {
			out := &bytes.Buffer{}
			if err := emitHelp(out, tc.topic, true); err != nil {
				t.Fatalf("emitHelp %s --json: %v", tc.topic, err)
			}
			if tc.shapeIsArray {
				var arr []map[string]any
				if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
					t.Fatalf("unmarshal array: %v\nbody: %s", err, out)
				}
				if len(arr) == 0 {
					t.Fatalf("topic %q array is empty", tc.topic)
				}
				if _, ok := arr[0][tc.firstItemKey]; !ok {
					t.Errorf("topic %q array[0] missing key %q (have: %v)", tc.topic, tc.firstItemKey, arr[0])
				}
				return
			}
			var doc map[string]any
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("unmarshal object: %v\nbody: %s", err, out)
			}
			for _, k := range tc.wantKeys {
				if _, ok := doc[k]; !ok {
					t.Errorf("topic %q object missing key %q (have: %v)", tc.topic, k, doc)
				}
			}
		})
	}
}

// TestEmitHelpUnknownTopic verifies an unknown topic returns an error.
func TestEmitHelpUnknownTopic(t *testing.T) {
	err := emitHelp(&bytes.Buffer{}, "nonexistent", false)
	if err == nil {
		t.Error("expected error for unknown topic")
	}
	if !strings.Contains(err.Error(), "unknown topic") {
		t.Errorf("expected 'unknown topic' in error, got %v", err)
	}

	err = emitHelp(&bytes.Buffer{}, "nonexistent", true)
	if err == nil {
		t.Error("expected error for unknown topic in JSON mode")
	}
}

// TestRunHelpIsCobraWired verifies that 'tvault help' produces our
// manual, not cobra's auto-generated help. runHelp writes to
// os.Stdout, so we capture it.
func TestRunHelpIsCobraWired(t *testing.T) {
	body := captureStdout(t, func() {
		if err := runHelp(nil, nil); err != nil {
			t.Fatalf("runHelp: %v", err)
		}
	})
	if !strings.Contains(string(body), "tvault - the CLI user manual") {
		t.Errorf("runHelp did not print our manual; first 200 bytes: %q",
			string(body)[:min200(len(body))])
	}
}

// TestHelpContentStableTopicCount guards against the JSON manifest
// silently changing shape (which would break agents that rely on it).
func TestHelpContentStableTopicCount(t *testing.T) {
	c := helpContent()
	if got, want := len(c.Topics), 7; got != want {
		t.Errorf("Topics has %d entries, want %d (this is part of the agent contract)", got, want)
	}
}
