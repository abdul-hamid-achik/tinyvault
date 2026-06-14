package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// helpCmd is the human + agent user manual for the tvault CLI.
//
// `tvault help` (no args) prints a long-form tour of the CLI. It
// complements --help (cobra's stock listing) and `tvault docs` (the
// machine-readable feature manifest): this command explains how to
// actually use the tool -- conventions, recipes, format options,
// exit codes, error recovery, and the agent/MCP usage patterns.
//
// Like `tvault docs`, output defaults to human-readable text. With
// --json, it emits a structured manifest the same way. With a
// subcommand, it prints the relevant slice:
//
//	tvault help                  full tour
//	tvault help workflow         lifecycle + day-to-day usage
//	tvault help safety          encryption, redaction, .env safety
//	tvault help recipes         copy-pasteable command sequences
//	tvault help output           --json, --format, exit codes
//	tvault help agent           patterns for MCP-using agents
//	tvault help troubleshooting passphrase loss, locked vault, etc.
var helpCmd = &cobra.Command{
	Use:   "help [topic]",
	Short: "Read the CLI user manual (human + agent readable)",
	Long: `Print a long-form tour of how to use the tvault CLI.

Unlike --help (which is cobra's stock listing of every command) and
unlike 'tvault docs' (which is a feature manifest designed for AI
agents to discover what the vault can do), this command explains
how to *operate* the CLI: lifecycle, conventions, recipes, output
formats, exit codes, error recovery, and the patterns agents
should follow.

Topics:
  workflow         lifecycle: init, projects, set/get, run, sync
  safety           encryption, redaction, .env safety
  recipes          copy-pasteable command sequences
  output           --json, --format options, exit codes
  agent            patterns for MCP-using AI agents
  troubleshooting  passphrase loss, locked vault, migration
  browse           the interactive terminal UI

Without a topic, prints the full tour.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runHelp,
}

func init() {
	rootCmd.AddCommand(helpCmd)
	helpCmd.Flags().BoolVar(&jsonOutput, "json", false, "Emit the manual as a JSON manifest")
}

func runHelp(_ *cobra.Command, args []string) error {
	topic := ""
	if len(args) == 1 {
		topic = strings.ToLower(args[0])
	}
	return emitHelp(os.Stdout, topic, jsonOutput)
}

// HelpContent is the full structured manual. It is the single
// source of truth for both the human text and the JSON manifest.
type HelpContent struct {
	Overview     string       `json:"overview"`
	Lifecycle    []HelpStep   `json:"lifecycle"`
	Conventions  HelpRules    `json:"conventions"`
	Output       HelpOutput   `json:"output"`
	Safety       HelpSafety   `json:"safety"`
	Recipes      []HelpRecipe `json:"recipes"`
	AgentGuide   HelpAgent    `json:"agent_guide"`
	Troubleshoot []HelpItem   `json:"troubleshooting"`
	Browse       HelpBrowse   `json:"browse"`
	Topics       []HelpTopic  `json:"topics"`
}

// HelpBrowse documents the interactive terminal UI (tvault browse).
type HelpBrowse struct {
	WhatItIs    string   `json:"what_it_is"`
	WhatItIsNot string   `json:"what_it_is_not"`
	Panes       []string `json:"panes"`
	Keys        []string `json:"keys"`
	WhenToUse   string   `json:"when_to_use"`
	Security    string   `json:"security"`
}

// HelpStep is one step in the vault lifecycle.
type HelpStep struct {
	Step    string `json:"step"`
	Command string `json:"command"`
	Why     string `json:"why"`
}

// HelpRules is the set of CLI conventions.
type HelpRules struct {
	Flags      []string `json:"flags"`
	EnvVars    []string `json:"env_vars"`
	ExitCodes  []string `json:"exit_codes"`
	Filesystem []string `json:"filesystem"`
}

// HelpOutput documents the --json / --format flags.
type HelpOutput struct {
	JSONUsage  string   `json:"json_usage"`
	Formats    []string `json:"env_formats"`
	GoldenRule string   `json:"golden_rule"`
}

// HelpSafety documents the security model.
type HelpSafety struct {
	Encryption       string   `json:"encryption"`
	KeyHierarchy     string   `json:"key_hierarchy"`
	Redaction        string   `json:"redaction"`
	AgentSafety      string   `json:"agent_safety"`
	NeverDoThis      []string `json:"never_do_this"`
	EncryptedEnvNote string   `json:"encrypted_env_note"`
}

// HelpRecipe is one copy-pasteable command sequence.
type HelpRecipe struct {
	Name        string   `json:"name"`
	Commands    []string `json:"commands"`
	Description string   `json:"description"`
}

// HelpAgent documents the patterns AI agents should follow.
type HelpAgent struct {
	Discover         string   `json:"discover"`
	PreferredOrder   []string `json:"preferred_order"`
	AntiPatterns     []string `json:"anti_patterns"`
	WhenToAskForHelp string   `json:"when_to_ask_for_help"`
}

// HelpItem is a one-line troubleshooting entry.
type HelpItem struct {
	Problem  string `json:"problem"`
	Solution string `json:"solution"`
}

// HelpTopic is one entry in the topics list.
type HelpTopic struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// helpContent returns the full structured manual. This is the
// single source of truth for both the text and JSON emitters.
func helpContent() HelpContent {
	return HelpContent{
		Overview: "tvault is a single-binary CLI for storing secrets locally with strong encryption, " +
			"plus an MCP server for AI agents. The same vault file backs both surfaces. " +
			"There is no server, no cloud, no account -- the vault is a single file under " +
			"~/.tvault/vault.db. Encryption is AES-256-GCM with a per-project DEK derived " +
			"from an Argon2id-derived KEK. The CLI is the canonical interface; the MCP server " +
			"is a thin policy-and-redaction layer on top of the same vault.",

		Lifecycle: []HelpStep{
			{
				Step:    "1. Initialize",
				Command: "tvault init",
				Why: "Creates ~/.tvault/vault.db with a default project. You will be prompted for a passphrase; " +
					"in CI / scripts, set TVAULT_PASSPHRASE to skip the prompt.",
			},
			{
				Step:    "2. Store a secret",
				Command: "tvault set DATABASE_URL 'postgres://localhost/x'",
				Why: "Encrypts with the current project's DEK and writes to the vault. " +
					"Use --stdin, --from-file, or --from-env for non-interactive input.",
			},
			{
				Step:    "3. Organize with projects",
				Command: "tvault projects create staging && tvault use staging",
				Why: "Each project has its own DEK. A compromise of one project does not leak others. " +
					"Use --project or 'tvault use' to scope commands.",
			},
			{
				Step:    "4. Run a command with secrets",
				Command: "tvault run -- npm start",
				Why: "Injects the current project's secrets as environment variables. " +
					"Add --env-file .env to merge in a dotenv file with ${tvault://...} placeholders.",
			},
			{
				Step:    "5. Export for CI",
				Command: "tvault env --format=dotenv > .env",
				Why: "For systems that need a static .env, generate one from the vault. " +
					"Or use 'tvault env --format=shell' to eval directly into a shell.",
			},
			{
				Step:    "6. Back up",
				Command: "tvault backup ~/backups/vault.db.bak",
				Why: "The backup is a direct copy of the encrypted vault.db. The passphrase is required to " +
					"restore it. Passphrase rotation invalidates the backup only if the old passphrase " +
					"is forgotten -- a fresh backup is always safe.",
			},
		},

		Conventions: HelpRules{
			Flags: []string{
				"--vault <dir>   override ~/.tvault (or set TVAULT_DIR)",
				"--project <name>  override the current project (or set TVAULT_PROJECT)",
				"-p <name>        short for --project",
				"--json          emit machine-readable JSON output",
				"--verbose, -v   enable verbose logging on stderr",
				"--config <file>  override the config file path (or set TVAULT_CONFIG)",
				"--no-vault      (run only) skip vault secrets, use only --env-file values",
				"--yes, -y       (delete/restore) skip confirmation prompt",
			},
			EnvVars: []string{
				"TVAULT_PASSPHRASE     vault passphrase; skips the interactive prompt",
				"TVAULT_NO_AGENT       set to bypass a running `tvault agent` and unlock directly",
				"TVAULT_AGENT_TOKEN    capability token for a `tvault agent --require-token` (privilege separation for confined delegates)",
				"TVAULT_IDENTITY_KEY   a private identity (tvault-key1…) for passphrase-free decrypt in CI/ssh; a local identity file takes precedence",
				"TVAULT_IDENTITY       default identity name for git filters / recipient reads; default 'default'",
				"TVAULT_DIR            vault directory; default ~/.tvault",
				"TVAULT_PROJECT        default project; default 'default'",
				"TVAULT_CONFIG         config file path; default ~/.tvault/config.yaml",
			},
			ExitCodes: []string{
				"0   success",
				"1   generic failure (see stderr for the message)",
				"3   vault is locked",
				"4   secret or project not found",
				"5   vault not initialized (run 'tvault init')",
				"6   unlock failed (wrong passphrase)",
			},
			Filesystem: []string{
				"~/.tvault/vault.db                 encrypted bbolt vault (0600)",
				"~/.tvault/config.yaml             viper config (optional)",
				"~/.tvault/mcp-policy.yaml         MCP access policy (optional)",
				"~/.tvault/index.db                FTS5 search index (no longer shipped; kept for compat)",
				"~/.tvault/                         directory mode 0700",
			},
		},

		Output: HelpOutput{
			JSONUsage: "Most commands accept --json. The shape is the same as the type Go field names " +
				"in internal/mcp. The TVault command itself never prints secrets to stdout, " +
				"even with --json. Use 'tvault env' or 'tvault get' to read a value.",
			Formats: []string{
				"shell       export KEY=VALUE  (eval-able; default for 'tvault env')",
				"dotenv      KEY=VALUE         (one per line; safe for .env files)",
				"json        {\"KEY\":\"VALUE\"}    (object form)",
				"yaml        KEY: VALUE        (mapping)",
				"k8s-secret  apiVersion: v1, kind: Secret, data: {KEY: base64}",
			},
			GoldenRule: "Anything that prints a secret value goes through 'tvault get' or " +
				"'tvault env'. Everything else prints structure. If you are scripting, " +
				"always prefer 'tvault get KEY' or 'tvault env --format=... > file' " +
				"over trying to parse human text.",
		},

		Safety: HelpSafety{
			Encryption: "All secret values are AES-256-GCM encrypted at rest. Per-project DEKs " +
				"are wrapped by a master KEK derived from the user's passphrase via " +
				"Argon2id (64 MiB memory, 3 iterations, 4 threads).",
			KeyHierarchy: "passphrase -> Argon2id -> KEK -> AES-GCM(per-project DEK) -> AES-GCM(secret value). " +
				"Compromising one project's DEK does not leak any other project's data. " +
				"Compromising the KEK leaks every project's DEK but not the passphrase.",
			Redaction: "When 'tvault run' executes a child command, its stdout and stderr are " +
				"scanned for any secret value (longer than 3 chars) and replaced with " +
				"'[REDACTED:KEY]'. This is a safety net, not a guarantee -- if a subprocess " +
				"sends the secret over the network, redaction cannot help.",
			AgentSafety: "The MCP server is the safe interface for AI agents. Three rules: " +
				"(1) Never call vault_get_secret unless the value is needed; prefer vault_run_with_secrets. " +
				"(2) For batch lookups, use vault_search_secrets and vault_list_secrets_by_prefix " +
				"-- they return metadata, never values. " +
				"(3) The mcp-policy.yaml file controls which projects and secrets the agent " +
				"can access; the agent cannot modify it at runtime.",
			NeverDoThis: []string{
				"Commit ~/.tvault/vault.db to a public repo",
				"Print a passphrase to a log file or chat message",
				"Disable redaction by piping to 'cat -v' (it still scans)",
				"Trust redaction as a security boundary -- it is a safety net, not a control",
				"Run 'tvault unlock' and walk away from the terminal",
			},
			EncryptedEnvNote: ".env.encrypted files (tvault encrypt-env) are safe to commit. " +
				"v1 (default) is tied to the vault KEK, so passphrase rotation invalidates it. " +
				"For sharing across a team, use v2: `encrypt-env --recipient tvault1…` wraps " +
				"the file to X25519 recipients, so each holder of a matching identity decrypts " +
				"it with `decrypt-env --identity` (no passphrase) and rotation does not invalidate " +
				"it. `tvault git-filter` automates this on commit/checkout.",
		},

		Recipes: []HelpRecipe{
			{
				Name:        "Initialize a new dev vault",
				Commands:    []string{"TVAULT_PASSPHRASE=devpass tvault init"},
				Description: "Non-interactive init for scripts and CI.",
			},
			{
				Name:        "Set a secret from stdin",
				Commands:    []string{"echo \"$DB_PASSWORD\" | tvault set DB_PASSWORD --stdin"},
				Description: "Pipe a value into a secret without it appearing in shell history.",
			},
			{
				Name: "Use a templated .env (commit-safe)",
				Commands: []string{
					"# .env (committed):",
					"# DATABASE_URL=${tvault://DATABASE_URL}",
					"",
					"tvault run --env-file .env -- npm start",
				},
				Description: "The placeholder is resolved against the unlocked vault at run time. " +
					"The .env file never contains real secrets, only references.",
			},
			{
				Name:        "Run a command with secrets in env",
				Commands:    []string{"tvault run -- python manage.py runserver"},
				Description: "Project secrets become env vars. Vault wins on conflict with --env-file.",
			},
			{
				Name:        "Generate a random secret",
				Commands:    []string{"tvault generate 32 --charset base64 --key API_KEY"},
				Description: "Generated value is stored but never returned. Audit log records the action.",
			},
			{
				Name:        "Pull vault -> .env (CI artifact)",
				Commands:    []string{"tvault sync --direction pull --path .env"},
				Description: "For systems that want a static .env, this writes vault keys into the file.",
			},
			{
				Name:        "Push .env -> vault (bootstrap)",
				Commands:    []string{"tvault sync --direction push --path .env --overwrite"},
				Description: "First-time bootstrap: take an existing .env and put its keys into the vault.",
			},
			{
				Name:        "Search secret keys",
				Commands:    []string{"tvault search --prefix STRIPE_ --json"},
				Description: "Metadata-only query. Never decrypts; safe to call from agents.",
			},
			{
				Name:        "List project names matching a glob",
				Commands:    []string{"tvault projects list --json | jq -r '.[].name'"},
				Description: "Project listing with secret counts.",
			},
			{
				Name: "Encrypt a .env for committing (passphrase)",
				Commands: []string{
					"tvault encrypt-env --in .env --out .env.encrypted",
					"git add .env.encrypted",
				},
				Description: "v1 file, tied to the vault KEK. Anyone with the passphrase decrypts it.",
			},
			{
				Name: "Share a project without the passphrase",
				Commands: []string{
					"tvault identity new ci          # teammate/CI: prints a tvault1… recipient",
					"tvault projects share tvault1…  # owner: grant that recipient access",
					"tvault env --identity ci --format dotenv   # recipient reads it, no passphrase",
					"tvault projects unshare tvault1…           # revoke: rotates the key + re-encrypts",
				},
				Description: "X25519 recipients (age-style). Revocation truly removes access, even from an old vault copy.",
			},
			{
				Name: "Commit self-decrypting secrets (git filters)",
				Commands: []string{
					"tvault identity new",
					"tvault git-filter install --recipient tvault1…",
					"tvault git-filter track .env",
					"git add .gitattributes .tvault-recipients .env && git commit -m \"enable tvault\"",
				},
				Description: "Files are ciphertext in history, plaintext in the working tree for identity holders. " +
					"After cloning, run `tvault git-filter install` to decrypt the working tree.",
			},
			{
				Name: "Decrypt secrets in CI without the passphrase",
				Commands: []string{
					"tvault identity new ci",
					"tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY",
					"tvault ci init --provider=github-actions --mode=identity --identity=ci",
				},
				Description: "CI holds a per-context identity (TVAULT_IDENTITY_KEY), not the master " +
					"passphrase. decrypt-env / open / git-filter all use it automatically when no key file is present.",
			},
			{
				Name: "Inspect and roll back a secret's history",
				Commands: []string{
					"tvault history DATABASE_URL",
					"tvault get DATABASE_URL --version 2",
					"tvault rollback DATABASE_URL --to 2",
				},
				Description: "Every overwrite archives the prior value. history lists versions (no values), " +
					"get --version prints one, and rollback restores an earlier version as a new version " +
					"(non-destructive). History survives key rotation.",
			},
			{
				Name: "Unlock once for prompt-free daily use (agent + hook)",
				Commands: []string{
					"tvault agent start &",
					`eval "$(tvault hook zsh)"`,
					"tvault_load   # loads the current project's secrets, no prompt",
				},
				Description: "The agent (unix only) holds the vault unlocked over a private 0600 socket so " +
					"get/env/run skip the passphrase prompt and Argon2id. It auto-locks when idle; " +
					"use --no-agent to bypass it.",
			},
			{
				Name: "Commit-safe Kubernetes secrets (SealedSecret pattern)",
				Commands: []string{
					"tvault seal --format k8s --name app -p prod --recipient tvault1cluster… > sealed.yaml",
					"git add sealed.yaml",
					"tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -",
				},
				Description: "Seal a project into a SealedSecret manifest (encryptedData is ciphertext — safe to commit); " +
					"at deploy, render a real Secret with the cluster identity. No cluster controller needed.",
			},
			{
				Name:        "Audit log for the last hour",
				Commands:    []string{"tvault audit log --since 2026-06-13T18:00:00Z --json"},
				Description: "Find out which secret was read, when, and by which tool.",
			},
			{
				Name:     "Run the MCP server for an agent",
				Commands: []string{"TVAULT_PASSPHRASE=... tvault mcp-server"},
				Description: "Add to .claude/settings.local.json or your MCP host config. The server " +
					"speaks JSON-RPC over stdio; configure env={TVAULT_PASSPHRASE: ...}.",
			},
			{
				Name:     "Browse secrets interactively",
				Commands: []string{"tvault browse", "tvault browse --rw", "tvault browse --project webapp --no-anim"},
				Description: "Read-only by default — explore, filter, and reveal values " +
					"behind a key press without exposing them to the terminal scrollback. " +
					"Pass --rw for audited in-app new/edit/delete.",
			},
		},

		AgentGuide: HelpAgent{
			Discover: "Call 'tvault docs features' once at the start of a session. The output is a " +
				"JSON manifest of every feature, the commands that exercise it, and a " +
				"description. From there, drill into specific topics: 'tvault docs interpolate', " +
				"'tvault docs sync', etc.",
			PreferredOrder: []string{
				"1. 'tvault docs features' -- discover what is available",
				"2. 'tvault search' or 'vault_search_secrets' -- find the key you need",
				"3. 'tvault run' or 'vault_run_with_secrets' -- use the value without seeing it",
				"4. 'tvault audit log' -- confirm the action was recorded",
			},
			AntiPatterns: []string{
				"Do not call 'tvault get KEY' in a loop just to enumerate secrets; use 'tvault list'.",
				"Do not grep 'tvault env' output to find a key; use 'tvault search' or 'tvault get KEY'.",
				"Do not write secrets to a file in /tmp for the agent to read; use the subprocess " +
					"env var mechanism (vault_run_with_secrets).",
				"Do not 'unlock' the vault then 'lock' it around each operation; the vault is " +
					"unlocked for the lifetime of the process (the MCP server, the CLI invocation).",
			},
			WhenToAskForHelp: "If a command returns an error, read the message -- tvault is " +
				"opinionated about errors and they include the remediation. If you cannot " +
				"figure out the right flag, run 'tvault <cmd> --help'. If the user wants a " +
				"feature that is not in the manifest, run 'tvault docs features' and look " +
				"for a feature that covers the use case.",
		},

		Troubleshoot: []HelpItem{
			{
				Problem: "I forgot the passphrase.",
				Solution: "There is no recovery. The vault cannot be decrypted. This is intentional " +
					"(local-first, no escrow, no social recovery). You will need to re-init and " +
					"re-add every secret. If you have a recent backup that was created with the " +
					"same passphrase, you can restore it; otherwise the data is gone.",
			},
			{
				Problem: "'vault not found' error on any command.",
				Solution: "Run 'tvault init' first. The vault file must exist before any other " +
					"command. TVAULT_DIR controls where; default is ~/.tvault.",
			},
			{
				Problem: "'value cannot be empty' when running 'tvault set KEY'.",
				Solution: "Either pass the value as a second argument ('tvault set KEY value'), " +
					"use --stdin ('echo val | tvault set KEY --stdin'), use --from-file, or " +
					"use --from-env .env.",
			},
			{
				Problem: "'unknown shorthand flag: c in -c' when running 'tvault run'.",
				Solution: "Use '--' to separate tvault's flags from the command's own flags: " +
					"'tvault run -- sh -c \"echo $FOO\"'. Without '--', cobra tries to parse " +
					"the command's flags as tvault's flags.",
			},
			{
				Problem: "An MCP tool returned an error like 'not allowed by policy'.",
				Solution: "The agent does not have access to that project or secret per the " +
					"~/.tvault/mcp-policy.yaml file. Edit the file (or ask the user to) and " +
					"restart the MCP server. The agent cannot modify the policy at runtime.",
			},
			{
				Problem: "I want to commit my .env to the repo but it has real secrets.",
				Solution: "Either (1) use 'tvault encrypt-env' to make a commit-safe .env.encrypted, " +
					"or (2) replace the values with ${tvault://...} placeholders and use " +
					"'tvault run --env-file .env' to resolve them at run time.",
			},
			{
				Problem: "I set TVAULT_IDENTITY_KEY but tvault used a key file instead (or ignored it).",
				Solution: "A local ~/.tvault/identities/<name>.key takes precedence over the env key " +
					"(deterministic local dev) and tvault warns when it does — remove or rename the file " +
					"to force the env key. If it was ignored entirely, the value was empty or malformed " +
					"(the error never echoes the key); re-export it with 'tvault identity export <name> --force'.",
			},
			{
				Problem: "'tvault rotate' didn't ask for confirmation.",
				Solution: "It does not. Rotation is non-destructive: the old passphrase still " +
					"works on the in-memory vault; only the next 'tvault unlock' requires " +
					"the new passphrase. Encrypted .env files from the old passphrase are " +
					"permanently unreadable; rotate them, then re-encrypt.",
			},
			{
				Problem: "The MCP server is not responding.",
				Solution: "Check that the passphrase is set in the MCP host's env, that the vault " +
					"directory exists and is readable, and that the policy file (if any) is " +
					"valid YAML. 'tvault mcp-server' prints the JSON-RPC trace on stderr " +
					"in verbose mode.",
			},
		},

		Browse: HelpBrowse{
			WhatItIs: "tvault browse is a full-screen terminal UI for browsing the vault, read-only by " +
				"default. Four panes (status, projects, secrets, audit) give you vault health, the project " +
				"list with secret counts, the current project's keys, and recent audit activity — all " +
				"at once. It is built on the Bubble Tea v2 / Lip Gloss v2 (charm.land) stack with a " +
				"light/dark theme auto-detected from your terminal background.",
			WhatItIsNot: "By default it is NOT an editor — it only reads, so a stray keystroke can't change " +
				"anything. Pass --rw to enable in-app edits (n new, e edit, d delete); they use the SAME " +
				"encryption path as the CLI and are written to the audit log just like 'tvault set/delete'. " +
				"Rotation and project create/delete still go through the CLI. The only decryption the " +
				"browser performs is the on-demand reveal (and the prefill when editing), audited like 'tvault get'.",
			Panes: []string{
				"1 Status   — unlocked/locked, current project, secret + project counts, last write, vault id",
				"2 Projects — every project with its secret count; the vault's current project is marked",
				"3 Secrets  — the selected project's keys (the main view); values masked until revealed",
				"4 Audit    — the most recent audit-log entries, newest first",
			},
			Keys: []string{
				"↑/↓ or j/k     navigate within the focused pane (mouse wheel scrolls too)",
				"←/→ or h/l     move between panes (1/2/3/4 jump; tab/⇧tab cycle)",
				"⏎              open the highlighted project's secrets",
				"/              live-filter the current project's keys",
				"r              reveal the selected value (R reveals all)",
				"esc            re-mask every revealed value (also exits the filter)",
				"c              copy the selected value to the clipboard",
				"n / e / d      (--rw only) new / edit / delete a secret — audited",
				"u / L          unlock (in-app passphrase prompt) / lock the vault",
				"^r / ^l        reload from disk / redraw",
				"? / q          toggle in-app help / quit",
			},
			WhenToUse: "Use the browser when you want to SEE the vault — explore what's there, check which " +
				"project is current, filter keys, or peek at a value during a screen-share without it " +
				"hitting scrollback. Use the CLI (or MCP) for everything scripted or mutating: set, run, " +
				"sync, rotate, and anything an agent does.",
			Security: "Revealed values live only in memory, only while shown, and are wiped on esc, on " +
				"pane change, and on quit. They never touch disk and never appear in the audit log " +
				"(only the fact that a reveal happened is recorded). The warm-orange reveal color is a " +
				"deliberate 'a secret is showing' signal. Browsing metadata works while the vault is " +
				"locked; revealing a value requires unlocking first.",
		},

		Topics: []HelpTopic{
			{Slug: "browse", Title: "The interactive terminal UI",
				Description: "What the browser is and isn't, the four panes, the full keybinding cheat sheet, and the reveal security model."},
			{Slug: "workflow", Title: "Lifecycle and day-to-day usage",
				Description: "init -> set -> run, projects, sync, backup, rotate, MCP."},
			{Slug: "safety", Title: "Encryption, redaction, .env safety",
				Description: "The full safety story: at-rest encryption, output redaction, .env parsing guarantees, the policy file."},
			{Slug: "recipes", Title: "Copy-pasteable command sequences",
				Description: "The 12 most common workflows as a one-line command + one-line explanation."},
			{Slug: "output", Title: "--json, --format options, exit codes",
				Description: "Output format reference for humans and for scripts."},
			{Slug: "agent", Title: "Patterns for MCP-using AI agents",
				Description: "What to do on first contact, what to prefer, what to avoid."},
			{Slug: "troubleshooting", Title: "Passphrase loss, locked vault, migration",
				Description: "The 8 most common failure modes and how to recover."},
		},
	}
}

// emitHelp writes the manual for the given topic. If topic is
// empty, the full manual is written. If asJSON is true, a structured
// manifest is written; otherwise a human-readable text form.
func emitHelp(w io.Writer, topic string, asJSON bool) error {
	c := helpContent()

	if asJSON {
		// JSON: emit only the relevant slice, or the full content.
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if topic == "" {
			return enc.Encode(c)
		}
		switch topic {
		case "workflow":
			return enc.Encode(struct {
				Topic     string     `json:"topic"`
				Lifecycle []HelpStep `json:"lifecycle"`
			}{"workflow", c.Lifecycle})
		case "safety":
			return enc.Encode(c.Safety)
		case "recipes":
			return enc.Encode(c.Recipes)
		case "output":
			return enc.Encode(c.Output)
		case "agent":
			return enc.Encode(c.AgentGuide)
		case "troubleshooting":
			return enc.Encode(c.Troubleshoot)
		case "browse":
			return enc.Encode(c.Browse)
		case "topics":
			return enc.Encode(c.Topics)
		default:
			return fmt.Errorf("unknown topic %q (try: workflow, safety, recipes, output, agent, troubleshooting, browse, topics)", topic)
		}
	}

	// Text form.
	switch topic {
	case "":
		writeOverview(w, c)
		writeLifecycle(w, c)
		writeConventions(w, c)
		writeOutput(w, c)
		writeSafety(w, c)
		writeRecipes(w, c)
		writeAgentGuide(w, c)
		writeTroubleshoot(w, c)
		writeBrowse(w, c)
		writeTopicsList(w, c)
	case "browse":
		writeBrowse(w, c)
	case "workflow":
		writeLifecycle(w, c)
	case "safety":
		writeSafety(w, c)
	case "recipes":
		writeRecipes(w, c)
	case "output":
		writeOutput(w, c)
	case "agent":
		writeAgentGuide(w, c)
	case "troubleshooting":
		writeTroubleshoot(w, c)
	case "topics":
		writeTopicsList(w, c)
	default:
		return fmt.Errorf("unknown topic %q (try: workflow, safety, recipes, output, agent, troubleshooting, browse, topics)", topic)
	}
	return nil
}

func writeBrowse(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Interactive browser (tvault browse)")
	fmt.Fprintln(w, "----------------------------")
	fmt.Fprintf(w, "\n%s\n", c.Browse.WhatItIs)
	fmt.Fprintf(w, "\nWhat it is NOT:\n  %s\n", c.Browse.WhatItIsNot)
	fmt.Fprintln(w, "\nPanes:")
	for _, p := range c.Browse.Panes {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w, "\nKeys:")
	for _, k := range c.Browse.Keys {
		fmt.Fprintf(w, "  %s\n", k)
	}
	fmt.Fprintf(w, "\nWhen to use it:\n  %s\n", c.Browse.WhenToUse)
	fmt.Fprintf(w, "\nSecurity:\n  %s\n\n", c.Browse.Security)
}

func writeOverview(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "tvault - the CLI user manual")
	fmt.Fprintln(w, "=============================")
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Overview)
	fmt.Fprintln(w)
}

func writeLifecycle(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Lifecycle")
	fmt.Fprintln(w, "---------")
	for _, s := range c.Lifecycle {
		fmt.Fprintf(w, "%s\n", s.Step)
		fmt.Fprintf(w, "  $ %s\n", s.Command)
		fmt.Fprintf(w, "  %s\n\n", s.Why)
	}
}

func writeConventions(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Conventions")
	fmt.Fprintln(w, "-----------")
	writeBullets(w, "Flags", c.Conventions.Flags)
	writeBullets(w, "Environment variables", c.Conventions.EnvVars)
	writeBullets(w, "Exit codes", c.Conventions.ExitCodes)
	writeBullets(w, "Filesystem", c.Conventions.Filesystem)
	fmt.Fprintln(w)
}

func writeBullets(w io.Writer, title string, items []string) {
	fmt.Fprintf(w, "\n%s:\n", title)
	for _, item := range items {
		fmt.Fprintf(w, "  - %s\n", item)
	}
}

func writeOutput(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Output formats")
	fmt.Fprintln(w, "--------------")
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Output.JSONUsage)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "'tvault env' --format=... options:")
	for _, f := range c.Output.Formats {
		fmt.Fprintf(w, "  - %s\n", f)
	}
	fmt.Fprintf(w, "\nGolden rule: %s\n\n", c.Output.GoldenRule)
}

func writeSafety(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Safety")
	fmt.Fprintln(w, "------")
	fmt.Fprintf(w, "\nEncryption:\n  %s\n", c.Safety.Encryption)
	fmt.Fprintf(w, "\nKey hierarchy:\n  %s\n", c.Safety.KeyHierarchy)
	fmt.Fprintf(w, "\nOutput redaction:\n  %s\n", c.Safety.Redaction)
	fmt.Fprintf(w, "\nAgent safety:\n  %s\n", c.Safety.AgentSafety)
	fmt.Fprintln(w, "\nNever do this:")
	for _, n := range c.Safety.NeverDoThis {
		fmt.Fprintf(w, "  - %s\n", n)
	}
	fmt.Fprintf(w, "\nEncrypted .env note:\n  %s\n\n", c.Safety.EncryptedEnvNote)
}

func writeRecipes(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Recipes")
	fmt.Fprintln(w, "-------")
	for _, r := range c.Recipes {
		fmt.Fprintf(w, "\n%s\n", r.Name)
		fmt.Fprintln(w, strings.Repeat("-", len(r.Name)))
		for _, c := range r.Commands {
			fmt.Fprintf(w, "  %s\n", c)
		}
		fmt.Fprintf(w, "  %s\n", r.Description)
	}
	fmt.Fprintln(w)
}

func writeAgentGuide(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Agent guide (for AI agents using the MCP server)")
	fmt.Fprintln(w, "-------------------------------------------------")
	fmt.Fprintf(w, "\nDiscover:\n  %s\n", c.AgentGuide.Discover)
	fmt.Fprintln(w, "\nPreferred order of operations:")
	for i, op := range c.AgentGuide.PreferredOrder {
		fmt.Fprintf(w, "  %s\n", op)
		_ = i
	}
	fmt.Fprintln(w, "\nAnti-patterns to avoid:")
	for _, a := range c.AgentGuide.AntiPatterns {
		fmt.Fprintf(w, "  - %s\n", a)
	}
	fmt.Fprintf(w, "\nWhen to ask for help:\n  %s\n\n", c.AgentGuide.WhenToAskForHelp)
}

func writeTroubleshoot(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Troubleshooting")
	fmt.Fprintln(w, "--------------")
	// c.Troubleshoot is a slice in declared order; iterate directly.
	for _, t := range c.Troubleshoot {
		fmt.Fprintf(w, "\nQ: %s\n", t.Problem)
		fmt.Fprintf(w, "A: %s\n", t.Solution)
	}
	fmt.Fprintln(w)
}

func writeTopicsList(w io.Writer, c HelpContent) {
	fmt.Fprintln(w, "Topics")
	fmt.Fprintln(w, "------")
	for _, t := range c.Topics {
		fmt.Fprintf(w, "  %-15s  %s\n  %-15s  %s\n", t.Slug, t.Title, "", t.Description)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'tvault help <topic>' for a focused slice, or 'tvault help --json' for the full structure.")
}
