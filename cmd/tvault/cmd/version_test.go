package cmd

import (
	"strings"
	"testing"
)

func TestSetVersionInfo(t *testing.T) {
	// Default values.
	if Version() != "dev" {
		t.Errorf("default Version() = %q, want %q", Version(), "dev")
	}

	// Override.
	SetVersionInfo("v1.2.3", "abc1234", "2026-06-13T18:00:00Z")
	if Version() != "v1.2.3" {
		t.Errorf("after SetVersionInfo, Version() = %q, want %q", Version(), "v1.2.3")
	}
	if !strings.Contains(rootCmd.Version, "v1.2.3") {
		t.Errorf("rootCmd.Version = %q, expected to contain v1.2.3", rootCmd.Version)
	}
	if !strings.Contains(rootCmd.Version, "abc1234") {
		t.Errorf("rootCmd.Version = %q, expected to contain abc1234", rootCmd.Version)
	}
	if !strings.Contains(rootCmd.Version, "2026-06-13T18:00:00Z") {
		t.Errorf("rootCmd.Version = %q, expected to contain the build date", rootCmd.Version)
	}

	// Restore default for other tests.
	SetVersionInfo("dev", "none", "unknown")
}
