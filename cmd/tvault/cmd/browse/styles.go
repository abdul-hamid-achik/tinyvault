package browse

import (
	"image/color"

	lipgloss "charm.land/lipgloss/v2"
)

// palette holds the raw theme colors. Two variants exist — dark
// (catppuccin mocha) and light (catppuccin latte) — picked at runtime
// from the terminal background color reported by Bubble Tea.
type palette struct {
	bg       color.Color
	fg       color.Color
	muted    color.Color
	accent   color.Color
	good     color.Color
	warn     color.Color
	bad      color.Color
	border   color.Color
	selected color.Color
	reveal   color.Color // warm accent: "you are showing a secret value"
}

// darkPalette is catppuccin mocha. It is the default.
var darkPalette = palette{
	bg:       lipgloss.Color("#1e1e2e"),
	fg:       lipgloss.Color("#cdd6f4"),
	muted:    lipgloss.Color("#6c7086"),
	accent:   lipgloss.Color("#89b4fa"),
	good:     lipgloss.Color("#a6e3a1"),
	warn:     lipgloss.Color("#f9e2af"),
	bad:      lipgloss.Color("#f38ba8"),
	border:   lipgloss.Color("#45475a"),
	selected: lipgloss.Color("#313244"),
	reveal:   lipgloss.Color("#fab387"),
}

// lightPalette is catppuccin latte.
var lightPalette = palette{
	bg:       lipgloss.Color("#eff1f5"),
	fg:       lipgloss.Color("#4c4f69"),
	muted:    lipgloss.Color("#8c8fa1"),
	accent:   lipgloss.Color("#1e66f5"),
	good:     lipgloss.Color("#40a02b"),
	warn:     lipgloss.Color("#df8e1d"),
	bad:      lipgloss.Color("#d20f39"),
	border:   lipgloss.Color("#bcc0cc"),
	selected: lipgloss.Color("#dce0e8"),
	reveal:   lipgloss.Color("#fe640b"),
}

// themeStyles is the set of pre-built lipgloss styles for one theme.
// It is computed once (on theme change) and passed by value into every
// render. There are no global styles.
type themeStyles struct {
	isDark bool
	pal    palette

	// Header.
	wordmark   lipgloss.Style
	headerMeta lipgloss.Style
	headerSep  lipgloss.Style

	// Panes.
	pane       lipgloss.Style // inactive pane frame
	paneActive lipgloss.Style // focused pane frame
	title      lipgloss.Style // inactive pane title
	titleHot   lipgloss.Style // focused pane title

	// Generic text roles.
	muted  lipgloss.Style
	good   lipgloss.Style
	warn   lipgloss.Style
	bad    lipgloss.Style
	accent lipgloss.Style
	bold   lipgloss.Style

	// List/table rows.
	row    lipgloss.Style
	rowSel lipgloss.Style // selected row in the focused pane
	rowCur lipgloss.Style // selected row in an unfocused pane

	// Secret value masking.
	masked   lipgloss.Style
	revealed lipgloss.Style

	// Footer + filter.
	footer      lipgloss.Style
	filterLabel lipgloss.Style

	// Tab strip (single-pane mode).
	tab    lipgloss.Style
	tabHot lipgloss.Style

	// Overlay (help / unlock modal).
	overlay lipgloss.Style
}

// newTheme builds the full style set for the given background mode.
func newTheme(isDark bool) themeStyles {
	pal := darkPalette
	if !isDark {
		pal = lightPalette
	}

	base := lipgloss.NewStyle().Foreground(pal.fg)

	return themeStyles{
		isDark: isDark,
		pal:    pal,

		wordmark: lipgloss.NewStyle().
			Foreground(pal.accent).
			Bold(true),
		headerMeta: lipgloss.NewStyle().Foreground(pal.fg),
		headerSep:  lipgloss.NewStyle().Foreground(pal.muted),

		pane: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pal.border),
		paneActive: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pal.accent),
		title: lipgloss.NewStyle().
			Foreground(pal.muted).
			Bold(true),
		titleHot: lipgloss.NewStyle().
			Foreground(pal.accent).
			Bold(true),

		muted:  lipgloss.NewStyle().Foreground(pal.muted),
		good:   lipgloss.NewStyle().Foreground(pal.good),
		warn:   lipgloss.NewStyle().Foreground(pal.warn),
		bad:    lipgloss.NewStyle().Foreground(pal.bad),
		accent: lipgloss.NewStyle().Foreground(pal.accent),
		bold:   base.Bold(true),

		row: base,
		rowSel: lipgloss.NewStyle().
			Foreground(pal.fg).
			Background(pal.selected).
			Bold(true),
		rowCur: lipgloss.NewStyle().
			Foreground(pal.accent),

		masked: lipgloss.NewStyle().Foreground(pal.muted),
		revealed: lipgloss.NewStyle().
			Foreground(pal.reveal).
			Bold(true),

		footer: lipgloss.NewStyle().Foreground(pal.muted),
		filterLabel: lipgloss.NewStyle().
			Foreground(pal.bg).
			Background(pal.accent).
			Bold(true).
			Padding(0, 1),

		tab: lipgloss.NewStyle().
			Foreground(pal.muted).
			Padding(0, 2),
		tabHot: lipgloss.NewStyle().
			Foreground(pal.bg).
			Background(pal.accent).
			Bold(true).
			Padding(0, 2),

		overlay: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pal.accent).
			Padding(1, 3),
	}
}
