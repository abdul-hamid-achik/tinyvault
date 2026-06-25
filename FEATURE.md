# FEATURE.md — codemap Integration

## Overview

codemap and tinyvault are siblings in a local-first agent ecosystem. codemap is the
**structural code graph** (who calls what, blast radius, test coverage); tinyvault is
the **local secret store** (AES-256-GCM, X25519 recipient sharing, agent-safe MCP).
Their integration is **strictly value-free** — only secret *key names* cross the seam,
never secret *values*. tinyvault is the key-name authority; codemap is the code-usage
authority. Together they answer: "if I rotate this key, what code breaks, and what's
the least-privilege key set for this entrypoint?"

## Live Integration Points

### EI.11 — `codemap annotate --source tinyvault`

tinyvault is in the `annotate --source` enum (`note`, `vecgrep`, `tinyvault`, `fcheap`,
`vidtrace`, `cairntrace`, `glyphrun`, `mongosh`, `postgres`). An agent can pin a note
or opaque data payload to a code symbol and attribute it to tinyvault — e.g. "this
function reads a key from tinyvault project `payments`." The annotation persists in
codemap's `annotations` table (schema v2) and survives reindex.

```
codemap annotate --source tinyvault --note "reads STRIPE_KEY from payments project" Checkout
```

### EI.12 — `codemap index --via-vault <project>`

Re-execs `codemap index` inside `tvault run -p <project>` so that registry credentials
(`GOPRIVATE`, `NPM_TOKEN`, `PIP_INDEX_TOKEN`, …) reach the language servers (gopls,
typescript-language-server, pyright) spawned during the `--precise` pass. This matters
when the codebase imports private modules — the LSP server needs to resolve them to
build an accurate call graph.

**Security boundary:** codemap only ever invokes `tvault run` and `tvault list`/`search`
— never `tvault get`. The `--via-vault` flag is hard-allowlisted to the `run` subcommand.
Secret values are unreachable from codemap. When `tvault` is not on PATH, the flag
degrades to a warning and indexes without injected secrets.

```
codemap index --precise --via-vault payments
# internally: tvault run -p payments -- codemap index --precise
```

### EI.13 — `codemap required-keys <entrypoint>`

Computes the **least-privilege key set** for an entrypoint: which candidate secret keys
an entrypoint's transitive call tree actually reads (via `os.Getenv`, `process.env`,
`os.environ`). Output is one key name per line — pipe directly to `tvault seal` or
`tvault export-env --keys` to grant only what that code path needs.

```
codemap required-keys Checkout --via-vault payments | xargs -I{} tvault seal --key {}
codemap required-keys Checkout --keys STRIPE_KEY,DATABASE_URL --depth 5
```

With `--via-vault <project>`, the candidate keys are fetched from `tvault list/search
--json` (metadata only — key names, never values). With `--prefix STRIPE_`, only keys
with that prefix are tested.

### `codemap secret-impact [<KEY>...] [--via-vault <project>]`

Computes the **rotation blast radius** for secret keys: for each key name, which symbols
read it, the transitive callers affected, and which tests cover those paths
(`untested:true` is a loud warning that you're rotating a key no test reaches). Operates
on key *names* only — never reads or returns values.

```
codemap secret-impact STRIPE_KEY DATABASE_URL
codemap secret-impact --via-vault payments --prefix STRIPE_
```

## What codemap needs from tinyvault

### CLI commands used

| tvault command | Usage | Value-free? |
|----------------|-------|-------------|
| `tvault run -p <project> -- <cmd>` | Run a command with secrets injected as env vars | Yes (values in subprocess env only) |
| `tvault list --json` | List secret key names (metadata only) | Yes (never returns values) |
| `tvault search --json` | Relational search over secret key names | Yes (metadata only) |

codemap **never** calls `tvault get` — the value-reading verb is unreachable from
codemap's codebase.

### MCP tools used (by agents, not codemap directly)

| tinyvault MCP tool | Complement |
|---------------------|------------|
| `vault_run_with_secrets` | codemap's `--via-vault` is the CLI analog |
| `vault_list_secrets` | codemap's `--via-vault` fetches keys via the CLI |
| `vault_seal_for_recipients` | Pairs with `codemap required-keys` output |
| `vault_export_env` | Pairs with `codemap required-keys --keys` |

## What tinyvault gets from codemap

### Structural pre-filtering

tinyvault alone can't answer "which code reads `STRIPE_KEY`?" — it only knows the key
exists. codemap's graph traversal (`secret-impact`) finds every `os.Getenv("STRIPE_KEY")`
call site and walks the transitive callers, giving tinyvault users a code-aware rotation
plan.

### Least-privilege sealing

`codemap required-keys` outputs exactly the keys an entrypoint needs, so a tinyvault
user can seal/export only those keys to a recipient or CI — no over-granting.

## Cache interaction

codemap's fcheap index cache is **orthogonal** to the tinyvault integration. The cache
stores the code graph + vectors (structure + meaning); tinyvault stores secrets (values).
Cache restore preserves the graph that `secret-impact` and `required-keys` traverse, so
a cache hit means instant blast-radius analysis without reindexing — but the tinyvault
integration works identically whether the index came from a fresh index or a cache
restore.

The `--via-vault` flag only affects the *indexing* pass (injecting creds for the LSP
servers). A cache restore skips indexing entirely, so `--via-vault` is not needed when
restoring from cache.

## Future opportunities

- **tinyvault audit → codemap annotate**: when a secret is rotated, tinyvault writes an
  audit entry; codemap could auto-annotate the affected symbols with the rotation event
- **codemap `secret-impact --json` → tinyvault rotation planner**: a tinyvault command
  that shows "rotating STRIPE_KEY affects 12 callers, 3 untested" by calling codemap's
  JSON output
- **Shared MCP session**: an agent with both codemap and tinyvault MCP servers can
  chain `codemap_secret_impact` → `vault_seal_for_recipients` in one workflow