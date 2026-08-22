package cmd

import "testing"

func TestParseMCPConnect(t *testing.T) {
	tests := []struct {
		in, mode, socket string
		ok               bool
	}{
		{"", "auto", "", true},
		{"auto", "auto", "", true},
		{" none ", "none", "", true},
		{"unix:///tmp/agent.sock", "unix", "/tmp/agent.sock", true},
		{"unix://", "", "", false},
		{"tcp://localhost:1", "", "", false},
		{"unix:", "", "", false},
	}
	for _, tt := range tests {
		mode, socket, err := parseMCPConnect(tt.in)
		if tt.ok {
			if err != nil {
				t.Errorf("parseMCPConnect(%q): %v", tt.in, err)
				continue
			}
			if mode != tt.mode || socket != tt.socket {
				t.Errorf("parseMCPConnect(%q) = %q %q, want %q %q", tt.in, mode, socket, tt.mode, tt.socket)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseMCPConnect(%q) succeeded, want error", tt.in)
		}
	}
}
