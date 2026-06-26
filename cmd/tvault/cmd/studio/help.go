package studio

import (
	glamour "charm.land/glamour/v2"
	"charm.land/glamour/v2/styles"
)

// helpMarkdown is the in-app help shown when the user presses `?`. It is
// the curated, studio-specific cheat sheet — the long-form CLI manual
// lives in `tvault help studio`, and both are kept close in wording.
const helpMarkdown = `# tvault studio — keys & concepts

A window into your vault, **read-only by default**. Use it to *see* your
secrets, *filter* them, and *reveal* a value behind a key press without
leaking it to scrollback. Launch with ` + "`--rw`" + ` to enable audited
in-app edits (new / edit / delete).

**Panes**

| # | Pane     | Shows |
|---|----------|-------|
| 1 | Status   | lock state, current project, counts, vault id |
| 2 | Projects | every project + its secret count |
| 3 | Secrets  | the selected project's keys (the main view) |
| 4 | Audit    | the most recent audit-log entries |

**Navigation**

- ` + "`↑/↓`" + ` or ` + "`j/k`" + ` — move within the focused pane
- ` + "`←/→`" + ` or ` + "`h/l`" + ` — move between panes
- ` + "`1` `2` `3` `4`" + ` — jump straight to a pane
- ` + "`tab` / `⇧tab`" + ` — cycle panes
- mouse wheel — scroll the selection in the focused pane
- ` + "`⏎`" + ` — on a project, load its secrets into the Secrets pane

**Secrets**

- ` + "`/`" + ` — live-filter the current project's keys
- ` + "`r`" + ` — reveal the selected value (warm orange = a secret is showing)
- ` + "`R`" + ` — reveal every value in the pane
- ` + "`esc`" + ` — re-mask everything (also clears on pane change & quit)
- ` + "`c`" + ` — copy the selected value to the clipboard
- ` + "`←`" + ` — before a key = inherited from a base env (see groups)

**Environment groups**

- ` + "`g`" + ` — cycle to the next environment in the current project's group
- ` + "`D`" + ` — show env drift (key-set diff across all environments)
- ` + "`G`" + ` — list all env groups (environments, inheritance, projects)
- ` + "`◈`" + ` — before a key = pinned (local value, inheritance broken for this key)

**Edit** (only with ` + "`--rw`" + `)

- ` + "`n`" + ` — new secret (enter a key, then a value)
- ` + "`e`" + ` — edit the selected secret's value
- ` + "`d`" + ` — delete the selected secret (asks to confirm)

These use the same encryption path as the CLI and are written to the audit
log, exactly like ` + "`tvault set`" + ` / ` + "`tvault delete`" + `.

**Vault**

- ` + "`u`" + ` — unlock (prompts for the passphrase, in-app)
- ` + "`L`" + ` — lock again (zeroes the key in memory)
- ` + "`^r`" + ` — reload everything from disk
- ` + "`^l`" + ` — redraw the screen

**Safety**

Revealed values live only in memory and only while shown. They are wiped
on ` + "`esc`" + `, when you switch panes, and on quit. Without ` + "`--rw`" + ` the studio
never writes to the vault; the only thing it records is a reveal (` + "`r`" + `),
which the audit log treats exactly like ` + "`tvault get`" + `. With ` + "`--rw`" + `, your
new/edit/delete actions are written and audited like the matching CLI command.

Press ` + "`?`" + ` again to close this help.`

// renderHelp renders the in-app help markdown to ANSI at the given
// width. It falls back to the raw markdown if glamour fails (e.g. width
// too small), so the help pane is never blank.
func renderHelp(width int, isDark bool) string {
	if width < 20 {
		width = 20
	}
	style := styles.DarkStyle
	if !isDark {
		style = styles.LightStyle
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle(style),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		return helpMarkdown
	}
	out, err := r.Render(helpMarkdown)
	if err != nil {
		return helpMarkdown
	}
	return out
}
