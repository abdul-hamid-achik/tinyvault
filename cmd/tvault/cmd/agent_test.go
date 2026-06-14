//go:build unix

package cmd

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
)

func TestAgentStatusCommandRunning(t *testing.T) {
	dir := shortAgentVault(t, "K", "v")
	stop := startTestAgentForCmd(t, dir)
	defer stop()

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out := captureStdout(t, func() {
		if err := runAgentStatus(nil, nil); err != nil {
			t.Fatalf("agent status: %v", err)
		}
	})
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	if doc["running"] != true {
		t.Errorf("status should report running, got %v", doc)
	}
}

func TestAgentStatusCommandNotRunning(t *testing.T) {
	shortAgentVault(t, "K", "v") // no agent started
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	out := captureStdout(t, func() {
		if err := runAgentStatus(nil, nil); err != nil {
			t.Fatalf("agent status: %v", err)
		}
	})
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	if doc["running"] != false {
		t.Errorf("status should report not running, got %v", doc)
	}
}

func TestAgentStopCommand(t *testing.T) {
	dir := shortAgentVault(t, "K", "v")
	stop := startTestAgentForCmd(t, dir)
	defer stop() // drains the agent goroutine even if runAgentStop fails

	if err := runAgentStop(nil, nil); err != nil {
		t.Fatalf("agent stop: %v", err)
	}
}

func TestAgentStopNotRunning(t *testing.T) {
	shortAgentVault(t, "K", "v") // no agent
	err := runAgentStop(nil, nil)
	if !errors.Is(err, agent.ErrAgentNotRunning) {
		t.Errorf("stop with no agent should be ErrAgentNotRunning, got %v", err)
	}
}
