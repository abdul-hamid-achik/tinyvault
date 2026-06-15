# glyphrun specs — `tvault studio` end-to-end PTY tests

These [glyphrun](https://github.com/abdul-hamid-achik/glyphrun) specs exercise
the interactive studio UI (`tvault studio` — `browse`/`ui` remain aliases — the
Bubble Tea v2 TUI in `cmd/tvault/cmd/studio/`) **end-to-end in a real PTY**.
They complement — they do not replace — the fast model-only Go tests in
`cmd/tvault/cmd/studio/*_test.go` (which assert `View()` output and `Update`
logic without a terminal). The specs prove the whole thing renders and drives
correctly when keystrokes go through a real terminal.

## Running

```bash
go build -o ./bin/tvault ./cmd/tvault          # specs also build this themselves
glyph run specs/glyphrun/studio_reveal.yml --format md
# …or the whole suite:
for f in specs/glyphrun/*.yml; do glyph run "$f" --format md; done
```

Runtime config (terminal size, env, passphrase redaction) lives in
`glyphrun.config.yml` at the repo root. Artifacts land in `.glyphrun/runs/`
(gitignored); throwaway vaults live under `.glyphrun/tmp/` (gitignored). The
`glyph` CLI is glyphrun's binary; see `glyph agent --format md` for the
agent-facing workflow guide.

## The specs

| Spec | Flow it proves |
|------|----------------|
| `studio_reveal.yml`        | open unlocked → reveal one value (`r`) → re-mask (`esc`) → quit |
| `studio_reveal_all.yml`    | `R` reveals every value at once → `esc` re-masks all |
| `studio_copy.yml`          | `c` copies the selected value (footer "copied KEY to clipboard") |
| `studio_filter.yml`        | focus Secrets → `/` live-filter narrows the key list (`(1/2)`) → `esc` restores |
| `studio_filter_no_match.yml` | `/` + non-matching text → "no keys match filter" + `(0/N)` |
| `studio_panes.yml`         | number keys `1`–`4` move focus; the footer hint tracks the active pane |
| `studio_tab_cycle.yml`     | `tab` / `shift+tab` cycle focus around all four panes |
| `studio_vim_nav.yml`       | vim `j`/`k` move the selection, `h`/`l` cycle panes |
| `studio_project_open.yml`  | Projects pane → navigate → `enter` opens another project's secrets |
| `studio_single_pane.yml`   | `--single-pane`: tab strip + one pane; numbers switch the visible pane |
| `studio_unlock.yml`        | locked start → in-app unlock (`u` + passphrase) → reveal works |
| `studio_lock.yml`          | `L` locks an unlocked vault; reveal is then blocked |
| `studio_rw_edit.yml`       | `--rw`: create (`n`) then delete (`d`/`y`) a secret through the real vault |
| `studio_edit_existing.yml` | `--rw`: `e` edits an existing value; the new value reveals |
| `studio_delete_cancel.yml` | `--rw`: `d` then `esc` cancels — the secret survives |
| `studio_help.yml`          | `?` opens the help overlay, `esc` closes it |
| `studio_too_small.yml`     | a sub-minimum terminal shows the "terminal too small" guard |
| `studio_quit_ctrlc.yml`    | `ctrl+c` quits cleanly (exit 0), like `q` |

## Two glyphrun behaviors worth knowing

These shaped how the specs are written; keep them in mind when editing.

1. **The config passphrase is injected into every target.** `glyphrun.config.yml`
   sets `TVAULT_PASSPHRASE: glyphpass` for the `local` environment, so `studio`
   launches **unlocked** by default (that is what most specs want). A spec's
   `target.env` only overrides the keys it names. `studio_unlock.yml` needs a
   *locked* start, so it overrides `TVAULT_PASSPHRASE` with a deliberately wrong
   value — `studio` ignores a failed non-interactive unlock and starts locked,
   which is exactly the state the in-app `u` flow needs.

2. **Centered modals and single-cell updates don't always repaint.** glyphrun's
   terminal emulator does not fully apply Bubble Tea v2's cell-diff repaint when
   a centered overlay opens over the multi-pane body (stale border cells linger),
   and it can drop a lone changed cell such as a pane-title count digit
   (`(2)` → `(3)`). The model itself renders a correct full-`width`×`height`
   frame — verified by `layout_test.go` (`assertExactGrid`) and a model-level
   dump — so this is an emulator limitation, not a `tvault` bug. Two consequences
   for these specs:
   - Overlay flows (`unlock`, `rw_edit`) are driven **blind**: keystrokes reach
     the model regardless of render, so we press/type through the modal, settling
     on `wait: { idle: … }` between inputs, and assert only on the **clean
     multi-pane state the flow returns to**.
   - Assertions target strings that repaint reliably as whole tokens — the header
     lock badge (`● locked` / `● unlocked`), a revealed value, a new key's row,
     a footer status line (`set API_TOKEN`) — rather than a single mutated digit.

   The modal/overlay *contents* themselves are covered by the model tests
   (`model_test.go`, `mutations_test.go`).
