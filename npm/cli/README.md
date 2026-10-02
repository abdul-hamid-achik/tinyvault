# @thelacanians/tinyvault

Local-first secrets management CLI and MCP server. Single binary, no accounts,
no cloud — a passphrase-protected vault on your machine, with an MCP server for
AI agents.

This package is a thin launcher: it installs the `tvault` binary for your
platform (via per-platform optional dependencies) and runs it directly.

## Install

```bash
npm install -g @thelacanians/tinyvault
```

or run without installing:

```bash
npx -y @thelacanians/tinyvault --help
```

## Quickstart

```bash
tvault init                                   # create ~/.tvault
tvault set DATABASE_URL "postgres://..."      # store a secret
tvault run -- npm start                       # inject as env vars
```

## MCP server (AI agents)

```bash
TVAULT_PASSPHRASE=your-passphrase tvault mcp
```

MCP host configuration (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "tinyvault": {
      "command": "npx",
      "args": ["-y", "@thelacanians/tinyvault", "mcp"]
    }
  }
}
```

`tvault mcp` cannot prompt for a passphrase (stdin carries MCP messages), so it
unlocks in one of three ways:

- **A running `tvault agent`** — the default (`--connect auto`). Secret reads are
  served by the agent with no passphrase in the host config at all. Writes still
  need one; the agent is read-only.
- **A passphrase source in the environment** — `TVAULT_PASSPHRASE_FILE` (a `0600`
  env-style file) or `TVAULT_PASSPHRASE_COMMAND` (a 1Password, Keychain, or `pass`
  helper whose stdout is the passphrase).
- **`TVAULT_PASSPHRASE`** — the blunt option: it puts the passphrase itself in the
  host's configuration.

`--connect none` (or `--no-agent`) skips the agent and requires a passphrase
directly. Without `~/.tvault/mcp-policy.yaml`, the server starts fail-closed
(metadata only, no values, no writes). See
[Passphrase sources](https://tinyvault.dev/guide/passphrase-sources) and
[MCP server](https://tinyvault.dev/mcp/).

## Update

```bash
npm install -g @thelacanians/tinyvault@latest
```

## More

- Docs: https://tinyvault.dev
- Security model: https://tinyvault.dev/reference/security
- Source: https://github.com/abdul-hamid-achik/tinyvault
