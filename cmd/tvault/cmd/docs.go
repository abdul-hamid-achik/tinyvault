package cmd

import (
	"encoding/json"
	"fmt"
	"os"

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
  encrypted-env    The .env.encrypted format
  safety           Threat model and safety properties
  quickstart       Five-line getting-started
  browse           The interactive terminal UI

If no subcommand is provided, the full catalog is printed.`,
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

func runDocs(cmd *cobra.Command, args []string) error {
	cat := fullCatalog()
	out, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return err
	}
	if len(args) > 0 {
		_ = cmd
	}
	_, err = os.Stdout.Write(out)
	if err != nil {
		return err
	}
	fmt.Println()
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
				Summary:     "MCP server over stdio with 18 tools, 2 prompts, 3 resources.",
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
				Summary:     "Full-screen, read-only terminal UI for browsing the vault (status, projects, secrets, audit).",
				Commands:    []string{"tvault browse", "tvault browse --project webapp", "tvault browse --single-pane", "tvault browse --no-anim"},
				SeeAlso:     []string{"tvault help browse"},
				Description: "Built on the Bubble Tea v2 / Lip Gloss v2 (charm.land) stack. The browser never writes — all mutations stay in the CLI. Browse project and secret metadata while locked; unlock in-app with 'u' to reveal a value behind a key press ('r'), which re-masks on 'esc' / pane change / quit. Vim + arrow + mouse-wheel navigation, live key filter, light/dark theme auto-detected from the terminal background. Animations disable on --no-anim, $TVAULT_NO_ANIM, or over SSH.",
			},
		},
		Topics: []docsTopic{
			{
				Slug:        "run",
				Title:       "tvault run",
				Description: "Runs a command with project secrets injected as environment variables. Optionally merges a .env file with the vault, vault winning on conflict. Values containing ${tvault://...} references in the .env file are resolved against the vault at run time.",
				Example:     "  tvault run --env-file .env -- npm start\n  tvault run --env-file .env.production -- ./deploy.sh\n  tvault run --no-vault -- npm test    # use only .env values",
			},
			{
				Slug:        "mcp",
				Title:       "MCP server",
				Description: "Starts a Model Context Protocol server on stdio. Add to your MCP host config with command=tvault args=[mcp-server] env={TVAULT_PASSPHRASE:...}. The server exposes 18 tools, 2 prompts, and 3 resources. The model never needs to see secret values: prefer vault_run_with_secrets and vault_export_env over vault_get_secret.",
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
				Description: "A .env file encrypted with AES-256-GCM using a per-file key derived via HKDF-SHA256 from the vault's KEK. The format magic is 'tvault-encrypted-v1'. Decryption requires the vault to be unlocked with the same passphrase that was active at encryption time. Passphrase rotation invalidates all previously encrypted files.",
				Example:     "  tvault encrypt-env --in .env\n  tvault encrypt-env --in .env.production --out config/secrets.encrypted\n  tvault decrypt-env --in .env.encrypted --out .env",
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
				Description: "Launches a full-screen, read-only terminal UI for browsing the vault. Four panes — status, projects, secrets, audit — with vim/arrow/mouse-wheel navigation and a live key filter. Press 'r' to reveal the selected value (warm-orange = a secret is showing), 'esc' to re-mask; revealed values live only in memory and are wiped on esc, pane change, and quit. The vault can be browsed (metadata only) while locked; press 'u' to unlock in-app. The browser never writes — use the CLI for mutations. Built on Bubble Tea v2 / Lip Gloss v2.",
				Example:     "  tvault browse\n  tvault browse webapp               # open a specific project\n  tvault browse --single-pane        # small terminals\n  tvault browse --no-anim            # disable animations (SSH/screen-reader friendly)",
			},
		},
	}
}
