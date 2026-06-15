package studio

import (
	"image/color"
	"math"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
)

// frameInterval is the animation tick cadence. ~60ms ≈ 16fps, which is
// smooth enough for the gentle fades/pulses here without being a CPU hog.
const frameInterval = 60 * time.Millisecond

// frameMsg is emitted by the animation ticker. The model only schedules
// the next tick while something is actually animating, so an idle TUI
// burns no cycles.
type frameMsg time.Time

// frameTick schedules the next animation frame.
func frameTick() tea.Cmd {
	return tea.Tick(frameInterval, func(t time.Time) tea.Msg { return frameMsg(t) })
}

// animEnabled reports whether animations should run, honoring the
// --no-anim flag, $TVAULT_NO_ANIM, and remote-session heuristics
// ($SSH_CONNECTION / $WT_SESSION). Screen-reader and SSH users get a
// calm, static UI.
func animEnabled(noAnimFlag bool) bool {
	if noAnimFlag {
		return false
	}
	if os.Getenv("TVAULT_NO_ANIM") != "" {
		return false
	}
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}
	return true
}

// easeInOutSine maps t in [0,1] to a smooth 0→1 curve. Used for the
// reveal flash decay and the locked-header pulse.
func easeInOutSine(t float64) float64 {
	if t <= 0 {
		return 0
	}
	if t >= 1 {
		return 1
	}
	return -(math.Cos(math.Pi*t) - 1) / 2
}

// pulseAlpha returns an alpha in [lo,hi] oscillating with period seconds,
// derived from the elapsed time. Drives the locked-lock-icon pulse.
func pulseAlpha(elapsed, period time.Duration, lo, hi float64) float64 {
	if period <= 0 {
		return hi
	}
	phase := math.Mod(float64(elapsed)/float64(period), 1.0)
	// triangle-ish wave via sine, 0→1→0 across the period.
	wave := (math.Sin(2*math.Pi*phase-math.Pi/2) + 1) / 2
	return lo + (hi-lo)*wave
}

// fadeColor returns c at the given alpha (1 = full color, 0 = fully
// transparent / blended into the background). lipgloss.Alpha gives a
// perceptual blend; the result feeds straight back into styles, which
// accept color.Color.
func fadeColor(c color.Color, alpha float64) color.Color {
	return lipgloss.Alpha(c, clamp01(alpha))
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
