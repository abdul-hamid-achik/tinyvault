# glyphrun specs — `tvault` end-to-end PTY tests

These [glyphrun](https://github.com/abdul-hamid-achik/glyphrun) specs exercise
tinyvault **end-to-end in a real PTY**. They cover the CLI (`cli_*.yml` and
`env_*.yml`), run as the real built binary and asserted on stdout + exit code.

They complement — they do not replace — the fast Go tests; they prove the
actual binary behaves correctly in a real terminal.

## Running

```bash
go build -o ./bin/tvault ./cmd/tvault
glyph run specs/glyphrun/cli_core.yml --format md
# …or the whole suite:
for f in specs/glyphrun/*.yml; do glyph run "$f" --format md; done
```

Runtime config (terminal size, env, passphrase redaction) lives in
`glyphrun.config.yml` at the repo root. Artifacts land in `.glyphrun/runs/`
(gitignored); throwaway vaults live under `.glyphrun/tmp/` (gitignored). The
`glyph` CLI is glyphrun's binary; see `glyph agent --format md` for the
agent-facing workflow guide.

## CLI command specs

Each runs the real binary and asserts on observed output.

| Spec | Commands it exercises |
|------|-----------------------|
| `cli_core.yml`             | `init` · `set` · `get` · `list` · `status` · `audit` |
| `cli_delete.yml`           | `delete` (with `-y`) |
| `cli_projects.yml`         | `projects create/list/delete` · `use` |
| `cli_lock_unlock_agent.yml`| `lock` · `unlock` · `agent status` |
| `cli_env_run.yml`          | `env --format dotenv` · `run -- …` (env injection) |
| `cli_run_only_prefix.yml`  | `run --only` / `--prefix` (least-privilege subset injection) |
| `cli_env_pulumi.yml`       | `env --format pulumi-config --stack` (Pulumi config lines) |
| `cli_mcp_coexist.yml`      | `mcp` running + concurrent `get`/`run` (lock coexistence) |
| `cli_history_rollback.yml` | `history` · `rollback --to` · `get` |
| `cli_search.yml`           | `search --prefix` · `list --prefix` |
| `cli_identity.yml`         | `identity new/list/export` |
| `cli_seal_open.yml`        | `identity new` · `seal --recipient` · `open --identity` |
| `cli_encrypted_env.yml`    | `encrypt-env` · `decrypt-env` (v2 round-trip) |
| `cli_export_import.yml`    | `export` · `import` |
| `cli_backup_restore.yml`   | `backup` · `restore` |
| `cli_key_rotate.yml`       | `key rotate` (value still readable after) |
| `cli_k8s.yml`              | `seal --format k8s` · `k8s render` |
| `cli_diff_sync.yml`        | `diff` · `sync` |
| `cli_git_filter.yml`       | `git-filter install/status` (in a scratch git repo) |
| `cli_scaffold.yml`         | `ci init --provider` · `completion bash` · `doctor` · `hook zsh` |
| `env_group_show.yml`       | `env group create/show` |
| `env_group_diff.yml`       | `env group create` · `env diff` (drift matrix) |
| `env_json_diff.yml`        | `env diff --json` (machine-readable drift) |
| `env_promote.yml`          | `env promote` · `env diff` |
| `env_inherit_resolve.yml`  | `env inherit` · `get --group --env --show-source` |
| `env_seal_decrypt.yml`     | `identity new/list` · `env seal --recipient` · `decrypt-env --in` |

### Known gaps

These top-level commands have **no spec at all**: `docker`, `ssh`, `shell-init`,
`generate`, `docs`, and `self-update`. All six are substantial surfaces — `ssh`
and `shell-init` emit shell, `docker` has four subcommands, `generate` is the
never-print-the-value path, `docs` is the agent discovery manifest, and
`self-update` replaces the running binary.

`--json` is only covered by `env_json_diff.yml`; the newer `backup --json`,
`restore --json`, and `key rotate --json` shapes are asserted in Go
(`cmd/tvault/cmd/json_output_test.go`) but not in a PTY.

The desktop app is not a CLI surface and has no specs here; `ci-app.yml` runs its
contract test (`app/scripts/verify-contracts.ts`) instead.
