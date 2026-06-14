package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// docsCatalog is the structured set of topics tvault docs can return.
// It is intentionally machine-readable: an agent calls
// `tvault docs features` and gets a JSON manifest of every feature
// with name, summary, and the command(s) that exercise it. This is
// the "learning from running tv docs" entry point described in the
// product brief.
type docsCatalog struct {
	Features []docsFeature `json:"features"`
	Topics   []docsTopic   `json:"topics"`
}

type docsFeature struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Commands    []string `json:"commands"`
	SeeAlso     []string `json:"see_also,omitempty"`
	Description string   `json:"description,omitempty"`
}

type docsTopic struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Example     string `json:"example,omitempty"`
}

var docsCmd = &cobra.Command{
	Use:   "docs <topic>",
	Short: "Read documentation about tvault features (designed for agents)",
	Long: `Read machine-readable documentation about tvault's features,
topics, and workflows.

This command is the primary discovery surface for AI agents. Calling
` + "`tvault docs features`" + ` returns a JSON manifest describing every
feature tvault offers, the commands that exercise it, and short
descriptions. Agents should call this once at the start of a session
to learn what tvault can do.

Available subcommands:
  features         JSON manifest of all features
  topics           JSON manifest of all topics (with examples)
  run              How ` + "`tvault run`" + ` works (env vars, interpolation)
  mcp              How the MCP server integrates with AI agents
  interpolate      tvault:// reference syntax and resolution
  sync             Two-way sync between .env files and the vault
  encrypted-env    The .env.encrypted format (v1 passphrase, v2 recipient)
  committable-secrets  Commit secrets to a repo (git filters / v2 files)
  safety           Threat model and safety properties
  quickstart       Five-line getting-started
  browse           The interactive terminal UI

Any topic or feature can also be named directly, e.g.
` + "`tvault docs committable-secrets`" + `. If nothing is named, the full
catalog is printed.`,
	RunE: runDocs,
}

var (
	docsTopicFlag string
)

func init() {
	rootCmd.AddCommand(docsCmd)
	docsCmd.Flags().StringVarP(&docsTopicFlag, "topic", "t", "", "Topic to print (alias for the first positional argument)")
	docsCmd.AddCommand(docsFeaturesCmd, docsTopicsCmd, docsRunCmd, docsMCPCmd, docsInterpolateCmd, docsSyncCmd, docsEncryptedEnvCmd, docsSafetyCmd, docsQuickstartCmd, docsBrowseCmd)
}

func runDocs(_ *cobra.Command, args []string) error {
	cat := fullCatalog()

	// A topic/feature can be named positionally or via --topic. Resolve a
	// topic first, then fall back to a feature, before printing the full
	// catalog when nothing was requested.
	topic := docsTopicFlag
	if topic == "" && len(args) > 0 {
		topic = args[0]
	}
	if topic != "" {
		if printTopic(cat, topic) == nil {
			return nil
		}
		if f, ok := findFeature(cat, topic); ok {
			return printFeature(f)
		}
		return fmt.Errorf("no topic or feature %q; try `tvault docs topics` or `tvault docs features`", topic)
	}

	out, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(out); err != nil {
		return err
	}
	fmt.Println()
	return nil
}

func findFeature(cat docsCatalog, name string) (docsFeature, bool) {
	for _, f := range cat.Features {
		if f.Name == name {
			return f, true
		}
	}
	return docsFeature{}, false
}

func printFeature(f docsFeature) error {
	fmt.Printf("# %s\n\n%s\n", f.Name, f.Summary)
	if f.Description != "" {
		fmt.Printf("\n%s\n", f.Description)
	}
	if len(f.Commands) > 0 {
		fmt.Printf("\nCommands:\n")
		for _, c := range f.Commands {
			fmt.Printf("  %s\n", c)
		}
	}
	if len(f.SeeAlso) > 0 {
		fmt.Printf("\nSee also: %s\n", strings.Join(f.SeeAlso, ", "))
	}
	return nil
}

var docsFeaturesCmd = &cobra.Command{
	Use:   "features",
	Short: "JSON manifest of all features",
	RunE: func(_ *cobra.Command, _ []string) error {
		out, err := json.MarshalIndent(fullCatalog().Features, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

var docsTopicsCmd = &cobra.Command{
	Use:   "topics",
	Short: "JSON manifest of all topics (with examples)",
	RunE: func(_ *cobra.Command, _ []string) error {
		out, err := json.MarshalIndent(fullCatalog().Topics, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

var docsRunCmd = &cobra.Command{
	Use:   "run",
	Short: "How tvault run works",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "run")
	},
}

var docsMCPCmd = &cobra.Command{
	Use:   "mcp",
	Short: "How the MCP server integrates with AI agents",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "mcp")
	},
}

var docsInterpolateCmd = &cobra.Command{
	Use:   "interpolate",
	Short: "tvault:// reference syntax and resolution",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "interpolate")
	},
}

var docsSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Two-way sync between .env files and the vault",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "sync")
	},
}

var docsEncryptedEnvCmd = &cobra.Command{
	Use:   "encrypted-env",
	Short: "The .env.encrypted format",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "encrypted-env")
	},
}

var docsSafetyCmd = &cobra.Command{
	Use:   "safety",
	Short: "Threat model and safety properties",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "safety")
	},
}

var docsQuickstartCmd = &cobra.Command{
	Use:   "quickstart",
	Short: "Five-line getting-started",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "quickstart")
	},
}

var docsBrowseCmd = &cobra.Command{
	Use:   "browse",
	Short: "The interactive terminal UI",
	RunE: func(_ *cobra.Command, _ []string) error {
		return printTopic(fullCatalog(), "browse")
	},
}

func printTopic(cat docsCatalog, slug string) error {
	for _, t := range cat.Topics {
		if t.Slug == slug {
			fmt.Printf("# %s\n\n%s\n", t.Title, t.Description)
			if t.Example != "" {
				fmt.Printf("\nExample:\n%s\n", t.Example)
			}
			return nil
		}
	}
	return fmt.Errorf("topic %q not found; try `tvault docs topics`", slug)
}

func fullCatalog() docsCatalog {
	return docsCatalog{
		Features: []docsFeature{
			{
				Name:        "encrypted-storage",
				Summary:     "AES-256-GCM with two-tier key hierarchy (Argon2id KEK + per-project DEKs).",
				Commands:    []string{"tvault init", "tvault unlock", "tvault lock", "tvault key rotate"},
				Description: "All secret values are encrypted at rest. Each project gets its own DEK so a single project compromise does not leak others.",
			},
			{
				Name:        "dotenv-interpolation",
				Summary:     "Resolve ${tvault://project/key} references in .env files against the vault at run time.",
				Commands:    []string{"tvault run --env-file .env -- command"},
				Description: "Commit a templated .env that contains only placeholders, then resolve via the vault when running.",
			},
			{
				Name:        "two-way-sync",
				Summary:     "Pull (vault -> .env), push (.env -> vault), or mirror (with conflict reporting).",
				Commands:    []string{"tvault sync --direction pull|push|mirror --path .env"},
				Description: "Either side can be the source of truth. Conflicts are reported, not auto-resolved.",
			},
			{
				Name:        "encrypted-env-files",
				Summary:     "Commit-safe .env.encrypted files tied to the vault KEK.",
				Commands:    []string{"tvault encrypt-env", "tvault decrypt-env"},
				Description: "Format: tvault-encrypted-v1. Self-contained binary, AES-256-GCM, HKDF-derived per-file key. Rotating the vault passphrase invalidates prior files.",
			},
			{
				Name:        "mcp-server",
				Summary:     "MCP server over stdio with 21 tools, 2 prompts, 3 resources.",
				Commands:    []string{"tvault mcp-server"},
				Description: "Agents can manage secrets without the values ever entering the model context: vault_run_with_secrets injects env vars, vault_export_env writes to disk and returns the path, vault_generate_secret returns only {stored: true}.",
			},
			{
				Name:        "relational-search",
				Summary:     "Read-only relational search over secrets, projects, and audit log (values never indexed, never returned in search results).",
				Commands:    []string{"tvault search", "tvault audit", "tvault projects list"},
				Description: "Composable filters: key glob, project, tag, prefix, time window. Backed by the SQL-shaped tabular store (bbolt under the hood, no FTS, no derived index).",
			},
			{
				Name:        "agent-discoverability",
				Summary:     "tvault docs is a machine-readable manifest of every feature and topic.",
				Commands:    []string{"tvault docs", "tvault docs features", "tvault docs topics", "tvault docs <topic>"},
				Description: "Agents call this once at session start to learn what tvault can do, then drill into specific topics.",
			},
			{
				Name:        "ci-integration",
				Summary:     "Starter GitHub Actions and GitLab CI workflows.",
				Commands:    []string{"tvault ci init --provider=github-actions", "tvault ci init --provider=gitlab"},
				Description: "Downloads the binary, sets TVAULT_PASSPHRASE from secrets, runs tvault env to load secrets.",
			},
			{
				Name:        "multi-project",
				Summary:     "Isolated projects each with their own DEK.",
				Commands:    []string{"tvault projects create", "tvault use", "tvault projects list", "tvault projects delete"},
				Description: "Use --project (or -p) to scope any command. Default project is 'default'.",
			},
			{
				Name:        "passphrase-rotation",
				Summary:     "Re-encrypt every project DEK under a new KEK derived from a new passphrase.",
				Commands:    []string{"tvault key rotate"},
				Description: "Secret values are never re-encrypted; only the DEK wrapping changes. Old encrypted .env files are invalidated by design.",
			},
			{
				Name:        "interactive-browser",
				Summary:     "Full-screen terminal UI for browsing the vault (status, projects, secrets, audit); read-only by default, --rw for edits.",
				Commands:    []string{"tvault browse", "tvault browse --rw", "tvault browse --project webapp", "tvault browse --single-pane", "tvault browse --no-anim"},
				SeeAlso:     []string{"tvault help browse"},
				Description: "Built on the Bubble Tea v2 / Lip Gloss v2 (charm.land) stack. Read-only by default; pass --rw to enable audited in-app edits (n new, e edit, d delete) that use the same encryption path as the CLI. Browse project and secret metadata while locked; unlock in-app with 'u' to reveal a value behind a key press ('r'), which re-masks on 'esc' / pane change / quit. Vim + arrow + mouse-wheel navigation, live key filter, light/dark theme auto-detected from the terminal background. Animations disable on --no-anim, $TVAULT_NO_ANIM, or over SSH.",
			},
			{
				Name:        "secret-sharing",
				Summary:     "Share/commit secrets to X25519 recipients without sharing the passphrase (age-style).",
				Commands:    []string{"tvault identity new", "tvault projects share <recipient>", "tvault projects unshare <recipient>", "tvault env --identity <name>"},
				SeeAlso:     []string{"tvault identity list", "tvault projects recipients"},
				Description: "An identity is an X25519 keypair (tvault identity new) whose public 'recipient' (tvault1…) is safe to share/commit. `tvault projects share <recipient>` wraps the project's data key to that recipient; the holder of the matching private identity then reads the project with `tvault env --identity <name>` — no vault passphrase needed. `tvault projects unshare` truly revokes: it rotates the project key and re-encrypts every value, so a removed recipient loses access even from an old vault copy. The DEK wrapping is X25519 → HKDF-SHA256 → ChaCha20-Poly1305 (internal/crypto/recipient.go), with no new dependency.",
			},
			{
				Name:        "committable-secrets",
				Summary:     "Commit secrets to a repo encrypted to X25519 recipients; they decrypt themselves on checkout. No passphrase in the files.",
				Commands:    []string{"tvault seal --recipient tvault1… > .env.encrypted", "tvault open --in .env.encrypted --identity <name>", "tvault seal --format k8s --name app --recipient tvault1… > sealed.yaml", "tvault k8s render --in sealed.yaml --identity cluster", "tvault encrypt-env --in .env --recipient tvault1…", "tvault decrypt-env --in .env.encrypted --identity <name>", "tvault git-filter install --recipient tvault1…", "tvault git-filter track .env", "tvault git-filter status", "tvault identity export <name> --force | gh secret set TVAULT_IDENTITY_KEY", "tvault ci init --provider=github-actions --mode=identity"},
				SeeAlso:     []string{"tvault docs committable-secrets", "tvault docs secret-sharing"},
				Description: "Two layers, both keyed by the recipient layer so no passphrase ever touches the files. (1) Standalone: `encrypt-env --recipient` writes a self-contained v2 .env.encrypted that any holder of a matching identity opens with `decrypt-env --identity` — KEK-independent, so passphrase rotation does not invalidate it. (2) Transparent git filters: `git-filter install` registers clean/smudge filters and `git-filter track <pattern>` adds .gitattributes entries, so matched files are stored encrypted in history but appear as plaintext in the working tree for anyone holding a recipient identity. Recipients live in a committed .tvault-recipients file (public keys only) so the read-set travels with the repo. Without an identity, files stay 'locked' (ciphertext) rather than failing checkout; the clean filter re-emits unchanged blobs so git status stays quiet; identity resolution is $TVAULT_IDENTITY, then `git config tvault.identity`, then 'default'. Over MCP, an agent can produce the same v2 blob with the vault_seal_for_recipients tool (it returns ciphertext only, never plaintext). For CI / ssh / agents, supply a per-context identity via the TVAULT_IDENTITY_KEY environment variable (a tvault-key1… string) so decrypt-env / open / git-filter decrypt with NO passphrase and no key file; a local identity file takes precedence over the env key (and tvault warns when it does). Provision it with `tvault identity export <name> --force | gh secret set TVAULT_IDENTITY_KEY`, and scaffold a workflow with `tvault ci init --mode=identity`.",
			},
			{
				Name:        "diagnostics",
				Summary:     "Read-only setup diagnostics + a typed config file.",
				Commands:    []string{"tvault doctor", "tvault doctor --json"},
				Description: "`tvault doctor` checks the vault directory + permissions, vault validity, lock state, project/secret counts, the config and MCP-policy files, environment, and terminal — without unlocking. Exit code is non-zero if any check fails (warnings don't fail), so scripts can gate on it. Optional ~/.tvault/config.yaml supplies a `browse:` block (no_anim, single_pane, audit_limit) as defaults for the interactive browser; explicit flags win.",
			},
			{
				Name:        "agent-and-hooks",
				Summary:     "A local agent (unix) holds the vault unlocked so daily commands skip the prompt + Argon2id.",
				Commands:    []string{"tvault agent start", "tvault agent status", "tvault agent stop", "tvault hook zsh", "tvault get DATABASE_URL --no-agent"},
				SeeAlso:     []string{"tvault docs agent"},
				Description: "`tvault agent start` (foreground; background it with & / nohup / systemd) unlocks the vault once and serves secret reads over a private 0600 unix socket in the 0700 vault dir, accepting only same-uid peers. get/env/run route through it automatically — no passphrase prompt, no ~200ms Argon2id — and fall back to a direct unlock when no agent is running (or with --no-agent / TVAULT_NO_AGENT). The agent caches only the KEK (not an open database), so direct access keeps working between requests; it auto-locks after an idle period and zeros the KEK on stop/idle/signal. `tvault hook <bash|zsh|fish|direnv>` prints a shell snippet (tvault_load) for loading a project's secrets via the agent. Unix only; on Windows the command reports it is unsupported.",
			},
			{
				Name:        "secret-versioning",
				Summary:     "Every overwrite archives the prior value; inspect history and roll back.",
				Commands:    []string{"tvault history <key>", "tvault get <key> --version N", "tvault rollback <key> --to N"},
				SeeAlso:     []string{"tvault docs versioning"},
				Description: "Each `set` archives the prior value as a version in the secret_versions bucket. `tvault history` lists every version (metadata only — no values, no unlock); `tvault get --version N` prints a past value; `tvault rollback --to N` restores an earlier version as a NEW version (non-destructive — the replaced value is itself archived, and version numbers are never reused). History is encrypted with the project DEK, so it survives passphrase rotation and recipient revocation (the DEK rotates and every version is re-encrypted). `tvault delete` purges a key's history. Over MCP, vault_secret_history and vault_rollback_secret expose the same — neither ever returns a value.",
			},
		},
		Topics: []docsTopic{
			{
				Slug:        "agent",
				Title:       "tvault agent + hooks",
				Description: "A local agent (unix only) unlocks the vault once and serves secret reads over a private 0600 unix socket (same-uid peers only), so get/env/run skip the passphrase prompt and the ~200ms Argon2id. It caches only the KEK and reopens the vault per request, so direct CLI access keeps working; it auto-locks when idle and zeros the KEK on stop/idle/signal. Run it in the foreground and background it yourself (& / nohup / systemd Type=simple / launchd). Bypass with --no-agent or TVAULT_NO_AGENT. `tvault hook <shell>` prints a tvault_load snippet for bash/zsh/fish/direnv.",
				Example:     "  tvault agent start &\n  eval \"$(tvault hook zsh)\"\n  tvault_load              # loads current project, no prompt\n  tvault agent status\n  tvault agent stop",
			},
			{
				Slug:        "versioning",
				Title:       "Secret history & rollback",
				Description: "Every overwrite of a secret archives the prior value as a version (the secret_versions bucket), so values are recoverable. `tvault history KEY` lists versions (metadata only, no unlock); `tvault get KEY --version N` prints a past value; `tvault rollback KEY --to N` restores an earlier version as a new version (non-destructive; numbers never reused). History is encrypted with the project key and survives passphrase rotation and recipient revocation. MCP: vault_secret_history (no values) and vault_rollback_secret (version numbers only).",
				Example:     "  tvault set API_KEY v1 && tvault set API_KEY v2\n  tvault history API_KEY\n  tvault get API_KEY --version 1\n  tvault rollback API_KEY --to 1",
			},
			{
				Slug:        "run",
				Title:       "tvault run",
				Description: "Runs a command with project secrets injected as environment variables. Optionally merges a .env file with the vault, vault winning on conflict. Values containing ${tvault://...} references in the .env file are resolved against the vault at run time.",
				Example:     "  tvault run --env-file .env -- npm start\n  tvault run --env-file .env.production -- ./deploy.sh\n  tvault run --no-vault -- npm test    # use only .env values",
			},
			{
				Slug:        "mcp",
				Title:       "MCP server",
				Description: "Starts a Model Context Protocol server on stdio. Add to your MCP host config with command=tvault args=[mcp-server] env={TVAULT_PASSPHRASE:...}. The server exposes 21 tools, 2 prompts, and 3 resources. The model never needs to see secret values: prefer vault_run_with_secrets and vault_export_env over vault_get_secret. vault_secret_history and vault_rollback_secret manage version history without ever returning a value.",
			},
			{
				Slug:        "interpolate",
				Title:       "tvault:// references",
				Description: "Inside a .env file value, write ${tvault://PROJECT/KEY} or ${tvault://KEY} (current project). At run time the dotenv parser keeps the reference verbatim; tvault run resolves it against the unlocked vault. tvault://current/KEY is also accepted as an explicit form.",
				Example:     "DATABASE_URL=${tvault://DATABASE_URL}\nSTRIPE_KEY=${tvault://current/STRIPE_KEY}\n# In a multi-project file:\nDB_PROD=${tvault://production/DATABASE_URL}",
			},
			{
				Slug:        "sync",
				Title:       "tvault sync",
				Description: "Reconciles a .env file with the vault. Direction pull writes vault->.env (default). Direction push writes .env->vault. Direction mirror reconciles both and reports conflicts. The --overwrite flag controls whether existing keys are replaced on push/mirror.",
				Example:     "  tvault sync --direction pull --path .env\n  tvault sync --direction push --path .env --overwrite\n  tvault sync --direction mirror --path .env",
			},
			{
				Slug:        "encrypted-env",
				Title:       ".env.encrypted",
				Description: "Two formats share the 'tvault-encrypted' magic. v1 (default): AES-256-GCM with a per-file key derived via HKDF-SHA256 from the vault KEK — decryption needs the vault unlocked with the passphrase that was active at encryption time, and passphrase rotation invalidates it. v2 (encrypt-env --recipient): a random per-file key encrypts the body and is wrapped to one or more X25519 recipients, so any holder of a matching identity decrypts it with --identity, no passphrase, and rotation does not invalidate it. decrypt-env auto-detects the version.",
				Example:     "  tvault encrypt-env --in .env\n  tvault encrypt-env --in .env --recipient tvault1… --out .env.encrypted\n  tvault decrypt-env --in .env.encrypted --identity ci --out .env",
			},
			{
				Slug:        "k8s",
				Title:       "Kubernetes sealed secrets",
				Description: "Commit-safe Kubernetes secrets via the recipient layer (the SealedSecret pattern, no cluster controller). `tvault seal --format k8s --name <n> --recipient tvault1cluster…` emits a SealedSecret manifest whose encryptedData is a v2 ciphertext blob — safe to commit. At deploy, `tvault k8s render --in sealed.yaml --identity cluster` (or with TVAULT_IDENTITY_KEY) decrypts it into a real `kind: Secret` for `kubectl apply`. The rendered Secret is PLAINTEXT — pipe it to kubectl, never commit it.",
				Example:     "  tvault seal --format k8s --name app-secrets -p prod --recipient tvault1cluster… > sealed.yaml\n  git add sealed.yaml\n  tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -",
			},
			{
				Slug:        "committable-secrets",
				Title:       "Committing secrets to a repo",
				Description: "Keep secrets in the repo, encrypted in history, decrypting themselves on checkout. Either commit standalone v2 files (encrypt-env --recipient), or use transparent git clean/smudge filters: `git-filter install` configures the repo, `git-filter track <pattern>` marks files in .gitattributes, recipients go in a committed .tvault-recipients file. Matched files are ciphertext in history and plaintext in the working tree for anyone holding a recipient identity; everyone else sees ciphertext ('locked'). The clean filter re-emits unchanged blobs so git status stays quiet; `git-filter install` / `git-filter checkout` re-decrypt the working tree after a clone. In CI / ssh / agents, set TVAULT_IDENTITY_KEY (a tvault-key1… string) so decrypt-env / open / git-filter decrypt with NO passphrase and no key file; a local identity file takes precedence (and tvault warns). Provision it with `tvault identity export <name> --force` and scaffold a workflow with `tvault ci init --mode=identity`.",
				Example:     "  tvault identity new\n  tvault git-filter install --recipient tvault1…\n  tvault git-filter track .env 'secrets/*.env'\n  git add .gitattributes .tvault-recipients && git commit -m \"enable tvault\"\n  # after cloning elsewhere:\n  tvault git-filter install         # decrypts the working tree\n  # in CI (no passphrase):\n  tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY\n  tvault ci init --provider=github-actions --mode=identity --identity=ci",
			},
			{
				Slug:        "safety",
				Title:       "Safety properties",
				Description: "Secrets at rest are encrypted. The KEK is derived with Argon2id (64 MiB, 3 iter, 4 threads). All AES-GCM nonces are unique and random. Keys are zeroed after use. The MCP server redacts secret values from subprocess output. The FTS index never stores secret values. The dotenv parser does not perform shell expansion or command substitution.",
			},
			{
				Slug:        "quickstart",
				Title:       "Quickstart",
				Description: "Five-line getting-started.",
				Example:     "  tvault init\n  tvault set DATABASE_URL \"postgres://...\"\n  tvault run -- npm start\n  tvault encrypt-env --in .env       # commit .env.encrypted\n  tvault mcp-server                  # for AI agents",
			},
			{
				Slug:        "browse",
				Title:       "tvault browse",
				Description: "Launches a full-screen terminal UI for browsing the vault, read-only by default. Four panes — status, projects, secrets, audit — with vim/arrow/mouse-wheel navigation and a live key filter. Press 'r' to reveal the selected value (warm-orange = a secret is showing), 'esc' to re-mask; revealed values live only in memory and are wiped on esc, pane change, and quit. The vault can be browsed (metadata only) while locked; press 'u' to unlock in-app. Pass --rw to enable audited in-app new/edit/delete (n/e/d), using the same encryption path as the CLI. Built on Bubble Tea v2 / Lip Gloss v2.",
				Example:     "  tvault browse\n  tvault browse --rw                 # enable in-app new/edit/delete\n  tvault browse webapp               # open a specific project\n  tvault browse --single-pane        # small terminals\n  tvault browse --no-anim            # disable animations (SSH/screen-reader friendly)",
			},
		},
	}
}
