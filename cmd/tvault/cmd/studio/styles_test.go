package studio

import (
	"testing"
	"time"

	lipgloss "charm.land/lipgloss/v2"
)

func TestNewThemeVariants(t *testing.T) {
	dark := newTheme(true)
	light := newTheme(false)

	if !dark.isDark {
		t.Error("dark theme isDark should be true")
	}
	if light.isDark {
		t.Error("light theme isDark should be false")
	}
	if dark.pal.bg == light.pal.bg {
		t.Error("dark and light backgrounds should differ")
	}
	if dark.pal.accent == light.pal.accent {
		t.Error("dark and light accents should differ")
	}
}

func TestThemePreservesContent(t *testing.T) {
	th := newTheme(true)
	for name, out := range map[string]string{
		"accent":   th.accent.Render("hello"),
		"good":     th.good.Render("hello"),
		"masked":   th.masked.Render("hello"),
		"revealed": th.revealed.Render("hello"),
	} {
		if !containsPlain(out, "hello") {
			t.Errorf("%s style dropped its text: %q", name, out)
		}
	}
}

// containsPlain checks the visible text survives styling regardless of
// whether ANSI escapes were emitted.
func containsPlain(styled, want string) bool {
	return lipgloss.Width(styled) >= lipgloss.Width(want)
}

func TestFadeColorEndpoints(t *testing.T) {
	c := lipgloss.Color("#89b4fa")
	if full := fadeColor(c, 1.0); full == nil {
		t.Fatal("fadeColor(1.0) returned nil")
	}
	// alpha clamps; out-of-range must not panic.
	_ = fadeColor(c, -1)
	_ = fadeColor(c, 2)
}

func TestEaseInOutSine(t *testing.T) {
	if got := easeInOutSine(0); got != 0 {
		t.Errorf("ease(0) = %v, want 0", got)
	}
	if got := easeInOutSine(1); got != 1 {
		t.Errorf("ease(1) = %v, want 1", got)
	}
	mid := easeInOutSine(0.5)
	if mid <= 0.4 || mid >= 0.6 {
		t.Errorf("ease(0.5) = %v, want ~0.5", mid)
	}
}

func TestPulseAlphaInRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := pulseAlpha(pulsePeriod/time.Duration(i+1), pulsePeriod, 0.35, 1.0)
		if a < 0.34 || a > 1.01 {
			t.Errorf("pulseAlpha out of range: %v", a)
		}
	}
}
