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

Each runs the real binary and asserts on observed output. Together they cover
every top-level command at least once.

| Spec | Commands it exercises |
|------|-----------------------|
| `cli_core.yml`             | `init` · `set` · `get` · `list` · `status` · `audit` |
| `cli_delete.yml`           | `delete` (with `-y`) |
| `cli_projects.yml`         | `projects create/list/delete` · `use` |
| `cli_env_run.yml`          | `env --format dotenv` · `run -- …` (env injection) |
| `cli_run_only_prefix.yml`  | `run --only` / `--prefix` (least-privilege subset injection) |
| `cli_env_pulumi.yml`       | `env --format pulumi-config --stack` (Pulumi config lines) |
| `cli_mcp_coexist.yml`      | `mcp` running + concurrent `get`/`run` (lock coexistence) |
| `cli_history_rollback.yml` | `history` · `rollback --to` · `get` |
| `cli_search.yml`           | `search --prefix` · `list --prefix` |
| `cli_seal_open.yml`        | `identity new` · `seal --recipient` · `open --identity` |
| `cli_encrypted_env.yml`    | `encrypt-env` · `decrypt-env` (v2 round-trip) |
| `cli_export_import.yml`    | `export` · `import` |
| `cli_backup_restore.yml`   | `backup` · `restore` |
| `cli_key_rotate.yml`       | `key rotate` (value still readable after) |
| `cli_k8s.yml`              | `seal --format k8s` · `k8s render` |
| `cli_diff_sync.yml`        | `diff` · `sync` |
| `cli_git_filter.yml`       | `git-filter install/status` (in a scratch git repo) |
