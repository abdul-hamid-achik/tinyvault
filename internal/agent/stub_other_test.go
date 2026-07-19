//go:build !unix

package agent

import (
	"testing"
	"time"
)

func TestStubFailsClosed(t *testing.T) {
	if Supported() {
		t.Error("Supported should be false off unix")
	}
	if err := Start(Options{}); err != ErrUnsupportedPlatform {
		t.Errorf("Start = %v, want ErrUnsupportedPlatform", err)
	}
	if _, err := Dial("/x", time.Second); err != ErrUnsupportedPlatform {
		t.Errorf("Dial = %v, want ErrUnsupportedPlatform", err)
	}
	c := &Client{}
	if _, err := c.StatusForProject("default"); err != ErrUnsupportedPlatform {
		t.Errorf("StatusForProject = %v, want ErrUnsupportedPlatform", err)
	}
}
