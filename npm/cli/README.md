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

`tvault mcp` cannot prompt for a passphrase (stdin carries MCP messages) —
supply `TVAULT_PASSPHRASE` through the host's secret/environment controls.
Without `~/.tvault/mcp-policy.yaml`, the server starts fail-closed (metadata
only, no values, no writes).

## Update

```bash
npm install -g @thelacanians/tinyvault@latest
```

## More

- Docs: https://tinyvault.dev
- Security model: https://tinyvault.dev/reference/security
- Source: https://github.com/abdul-hamid-achik/tinyvault
