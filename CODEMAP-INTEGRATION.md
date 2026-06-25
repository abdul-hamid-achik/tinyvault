# tinyvault ⇄ codemap — Secret-Impact Integration

> **Status:** validated design (2026-06-25). Authored from a cross-repo investigate→design→critique
> workflow against the actual code of both tools. Slice 0 + Slice 1 (EI.12) **shipped** on codemap `main`.
> **One line:** give every secret a *code blast radius* — "if I rotate `STRIPE_KEY`, what code and which
> tests break?" — by joining tinyvault's value-free **key-name inventory** to codemap's **call graph**.

## Clean boundary
- **tinyvault** = the *key-name + lineage authority*: which keys exist, versions, recipients, freshness.
  It has, by design, **no notion of code location and never emits secret VALUES** (the list/search/prefix
  tools are value-free by construction).
- **codemap** = the *code-location + blast-radius authority*: where a string appears, the enclosing
  symbol, the call graph, covering tests. It has **no notion of secrets**.
- **The seam carries key NAMES only, one hop, CLI `--json`** (never MCP→MCP — the vecgrep rule). A key
  name like `STRIPE_KEY` is not a secret; the *value* never enters codemap. **Security win:** a rotation
  blast-radius report is safe to paste into a PR/ticket/LLM context — code symbols + key names, zero
  credential material.

## The KEY→code join (the crux)
A secret is referenced in code as a **string literal** (`os.Getenv("KEY")`, `os.environ["KEY"]`,
`process.env.KEY`) — which codemap indexes by *symbol*, not by literal. So the join is:

```
key "STRIPE_KEY"
  └─▶ literal scan over g.IndexedFiles(projectID)   ← the only NET-NEW primitive
        word-boundary (\b + QuoteMeta), all indexed files → []{file, line}
  └─▶ Service.SymbolAt(file, line)                  ← EXISTS (the file:line→symbol resolver)
  └─▶ Service.Impact(symbol, depth)                 ← EXISTS (blast radius + covering tests)
```

The scanner is codemap's existing `heuristicTestCoverage` primitive generalized (arbitrary literal, all
indexed files). The other join mechanisms were rejected: `find` is symbol-column-only (misses the bare
literal in `os.Getenv`); `semantic` can't deterministically enumerate usages; first-class env-read nodes
need work in 3 backends (deferred to Slice 5).

### ⚠️ MUST-FIX before the flagship is trustworthy (the critique's blocking finding)
A literal scan + `SymbolAt.resolution` **cannot tell a real read from a mention**: `os.Getenv("STRIPE_KEY")`,
`// STRIPE_KEY rotated quarterly`, `log.Info("refreshing STRIPE_KEY")`, and `if name == "STRIPE_KEY"` all
resolve as `enclosing` and would inflate the blast radius — a security-relevant lie for a "rotation" verb.
**The scanner MUST filter hits to string-literal/call-argument context, not raw byte offsets** (e.g. Go
`go/scanner` token kind: is the offset inside a `STRING` vs `COMMENT`/identifier). At minimum, drop hits
inside comments / not inside quotes. Until this lands, `confidence:"string-literal"` is unverifiable —
frame the flagship as **"candidate usage + impact (precise requires the extractor upgrade)"**, surface
`precise:false`/`stale:true` *loudly*, and never gate a destructive rotation on it as authoritative.

## Build order

- [x] **Slice 0** — add `tinyvault` to codemap's annotation `--source` enum (shipped, codemap 0fc71ae).
- [x] **Slice 1 (EI.12) — `codemap index --via-vault <project>`** (shipped, codemap 0fc71ae). Re-execs the
  index inside `tvault run -p <project>` so the language servers inherit private-registry creds. The genuine
  zero-new-code first slice: **both tinyvault deps verified done** (`vault_run_with_secrets` injects+redacts).
  **Hard-allowlisted** to the `run` verb only — `tvault get` is unreachable, so values can't enter codemap.
  LookPath-guarded; degrades to a normal index when tvault is absent. Live-verified (tvault injected
  GOPRIVATE; the index ran through the re-exec). Proves the bidirectional CLI seam + graceful degradation.
- [x] **Slice 2 — the scanner primitive** (codemap f2d0591) (`scanIndexedFiles(projectID, literal)` generalizing
  `heuristicTestCoverage`) **WITH the string-context filter above folded in — not optional.** The one real
  cost center; isolate it like EI.1's file:line resolver was. v1 may shell `ripgrep` + feed `SymbolAt`.
- [x] **Slice 3 — `codemap secret-impact` flagship (EI.11)** (codemap f2d0591, live-verified): scanner → `SymbolAt` → `Impact`. Default to
  agent-supplied `keys[]` (value-blind, no tvault); then `--via-vault`/`--prefix` fetch the inventory via
  the value-free `tvault list/search --json`. Output `{key, used_by[], blast_radius, covering_tests,
  untested, unresolved[], precise, stale}`. Add the value-leak assertion test (output JSON never contains a
  value; emit `file:line`, never line *content* — a tested invariant). `untested:true` = "rotating a key
  with zero test coverage" (the genuinely useful signal).
  - Keep `orphan_keys` = `vaultKeys \ keysWithHits` but **label "no code usages found (verify before
    treating as dead)"** — never "rotate-safe" (dynamic `os.Getenv(prefix+name)` is invisible to the scan).
  - **CUT `unmanaged_keys` from v1** — it needs the inverse (enumerate all env-reads), which doesn't exist
    until Slice 5; a false "unmanaged" is worse than none.
- [x] **EI.13 (least-priv seal), read-side** — DONE (codemap) — `codemap callees <entrypoint> --keys` → `required_keys[]`
  for `vault_seal_for_recipients` / `vault_export_env{keys}` / `tvault seal --key` (all filter + error
  loudly on a typo'd key — tinyvault side verified done). **Rides Slice 2's scanner** (required_keys = keys
  read by the transitive callee set), so it is NOT in the zero-new-code first slice. CLI `tvault export` has
  no `--keys` (MCP-only filtering) — emit toward `seal`/`vault_export_env`.
- [ ] *(deferred)* Slice 4 annotations enrichment; Slice 5 first-class env-read extractor nodes (v2 — the
  precise answer that retires the scan heuristic).

## Channel + degradation
Fallback ladder for the flagship: **agent-supplied `keys[]`** (default, value-blind, no tvault) → `tvault`
on `$PATH` (`--via-vault` fetches the inventory via list/search) → tvault absent (degrade to "supply keys",
non-fatal). Hard-allowlist the codemap-side exec wrapper to `tvault list|search|run` only — make `tvault
get` unreachable by construction, not convention. In `--via-vault` audits, fetch the inventory in ONE
`tvault list --json` call (avoid tinyvault's single-writer `vaultMu` contention).
