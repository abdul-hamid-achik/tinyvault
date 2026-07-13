---
title: Getting Started
description: Install TinyVault, create a local vault, store a value through standard input, list its key without unlocking, and inject it into a process.
---

# Getting started

This quickstart takes you from a new install to a child process using a vault secret. It uses a deliberately non-sensitive demo value and never prints that value back to the terminal.

## 1. Install TinyVault

Install the prebuilt binary with Homebrew:

```bash
brew install --cask abdul-hamid-achik/tap/tvault
```

You can instead download a binary from [GitHub Releases](https://github.com/abdul-hamid-achik/tinyvault/releases), or install from source with Go 1.26 or later:

```bash
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest
```

Confirm that `tvault` is on your `PATH`:

```bash
tvault --version
```

## 2. Create a vault

```bash
tvault init
```

TinyVault asks you to create and confirm a passphrase, creates the `default` project, and writes the vault database to `~/.tvault/vault.db`.

Secret values and key material in the database are encrypted. Names and operational metadata, including project names and secret key names, are not confidential.

::: danger Keep the passphrase
TinyVault has no hosted recovery service or recovery key. Keep the passphrase separately from a backup of the vault database. Losing either one removes the complete owner view; recipient identities configured later can recover only projects explicitly shared to them.
:::

## 3. Store a value through standard input

When a value arrives on standard input, TinyVault cannot use that same stream to prompt for the vault passphrase. In Bash or zsh, read the passphrase without echo, export it for this operation, and remove it immediately afterward:

```bash
printf 'Vault passphrase: ' >&2
read -rs TVAULT_PASSPHRASE
printf '\n' >&2
export TVAULT_PASSPHRASE

printf '%s' 'quickstart-demo-value' | tvault set API_TOKEN --stdin
unset TVAULT_PASSPHRASE
```

The value above is deliberately non-sensitive. For a real credential, pipe it from your password manager, credential generator, or another trusted source. Avoid putting it directly after the key because command arguments can be retained in shell history or exposed to other local tooling.

`set` reads the passphrase from `TVAULT_PASSPHRASE`, unlocks the vault for this command, stores the encrypted value, and closes the vault again.

## 4. List the key without decrypting values

```bash
tvault list --names-only
```

The output includes:

```text
API_TOKEN
```

`--names-only` does not ask for the passphrase and never decrypts a value. This works because key names are readable metadata in the database. The default `tvault list` path does unlock the vault; use `--names-only` when names are all you need.

## 5. Inject the value into a child process

Run a command with only `API_TOKEN` added to its environment:

```bash
tvault run --only API_TOKEN -- sh -c 'test -n "$API_TOKEN" && echo "API_TOKEN is available to the child process"'
```

TinyVault prompts for the passphrase, decrypts the selected value, and passes it to `sh`. The command confirms that the variable exists without printing it.

The `--only` flag narrows injection to an explicit key. The `--` separator is optional when there is no flag conflict, but using it consistently makes clear where TinyVault options end and the child command begins.

::: warning Trust the child command
The CLI does not redact a child process's terminal output or prevent it from writing files, logs, or network traffic. Run only commands you trust with the selected secrets.
:::

Use the same pattern with your application:

```bash
tvault run --only DATABASE_URL -- npm start
tvault run --prefix APP_ -- python manage.py runserver
```

## How unlocking works

TinyVault does not remain unlocked after a normal CLI command. Commands that need plaintext prompt for the passphrase, use the derived key for that invocation, and clear it when the command exits.

If repeated prompts interrupt your local workflow, the optional [local agent](/guide/agent) can hold the unlock key for a limited time on Unix.

## Choose your next step

- [Run and env](/guide/run-and-env) — select keys, combine a `.env` template, or render environment output.
- [Projects](/guide/projects) — separate applications and environments.
- [Dotenv workflows](/guide/dotenv) — import, diff, sync, and interpolate existing `.env` files.
- [Studio](/guide/studio) — browse the vault interactively.
- [MCP server](/mcp/) — connect an AI agent with a fail-closed policy.
- [Security and threat model](/reference/security) — understand metadata exposure and trust boundaries.
- [CLI reference](/cli/) — look up every command and flag.
