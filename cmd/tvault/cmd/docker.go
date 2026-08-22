package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/abdul-hamid-achik/tinyvault/internal/processenv"
)

var (
	dockerOnly     []string
	dockerPrefix   string
	dockerIdentity string
	dockerGroup    string
	dockerEnvName  string
	dockerStrict   bool
)

var dockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Run Docker with vault secrets (BuildKit mounts, compose, run)",
	Long: `Wrap the Docker CLI so a project's secrets reach a build, compose
stack, or container without putting values on the docker command line
or writing a plaintext .env.

  tvault docker build    --secret id=KEY,env=KEY for each selected key
                         (BuildKit tmpfs mounts; Dockerfile uses
                         RUN --mount=type=secret,id=KEY)
  tvault docker compose  injects keys into the compose process so
                         ${KEY} interpolates; values stay off argv
  tvault docker run      docker run -e KEY (name only; value from env)
  tvault docker init     print Dockerfile and compose snippets

TinyVault flags stay before '--'. Everything after is passed to Docker.

Examples:
  tvault docker build --only NPM_TOKEN -- -t app .
  tvault docker compose --only DATABASE_URL -- up
  tvault docker run --only DATABASE_URL -- --rm alpine env
  tvault docker init`,
}

var dockerBuildCmd = &cobra.Command{
	Use:   "build [-- docker build args]",
	Short: "docker build with BuildKit secret mounts from the vault",
	Long: `Run 'docker build' with one BuildKit --secret id=KEY,env=KEY per
selected vault key. Values are in the docker process environment, not
on argv. The Dockerfile consumes them with:

  RUN --mount=type=secret,id=NPM_TOKEN \
      NPM_TOKEN="$(cat /run/secrets/NPM_TOKEN)" npm ci

DOCKER_BUILDKIT=1 is set on the child. Prefer --only / --prefix so the
build only sees the keys it mounts.`,
	RunE: runDockerBuild,
}

var dockerComposeCmd = &cobra.Command{
	Use:   "compose [-- docker compose args]",
	Short: "docker compose with vault secrets in the process environment",
	Long: `Run 'docker compose' with selected vault keys in its environment
so compose interpolates ${KEY} in the compose file. Values are not
passed as -e flags and do not appear on argv.

  services:
    app:
      environment:
        DATABASE_URL: ${DATABASE_URL}`,
	RunE: runDockerCompose,
}

var dockerRunCmd = &cobra.Command{
	Use:   "run [-- docker run args]",
	Short: "docker run with -e KEY (value taken from the client environment)",
	Long: `Run 'docker run' with '-e KEY' for each selected vault key (name
only). Docker reads the value from the client environment, so it does
not appear on argv. The container still has the value in its env —
the same residual risk as 'tvault run'.`,
	RunE: runDockerRun,
}

var dockerInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Print Dockerfile and compose snippets for TinyVault secrets",
	Long: `Print copy-paste snippets for BuildKit secret mounts and compose
environment interpolation. Does not write files and does not unlock
the vault.`,
	RunE: runDockerInit,
}

func init() {
	rootCmd.AddCommand(dockerCmd)
	dockerCmd.AddCommand(dockerBuildCmd, dockerComposeCmd, dockerRunCmd, dockerInitCmd)
	dockerCmd.PersistentFlags().StringSliceVar(&dockerOnly, "only", nil, "Inject only these secret keys (comma-separated allowlist)")
	dockerCmd.PersistentFlags().StringVar(&dockerPrefix, "prefix", "", "Inject only secret keys with this prefix")
	dockerCmd.PersistentFlags().StringVar(&dockerIdentity, "identity", "", "Decrypt a shared project with this X25519 identity instead of the passphrase")
	dockerCmd.PersistentFlags().StringVar(&dockerGroup, "group", "", "Resolve secrets through an environment group's inheritance chain")
	dockerCmd.PersistentFlags().StringVar(&dockerEnvName, "env", "", "Environment name within the group (requires --group)")
	dockerCmd.PersistentFlags().BoolVar(&dockerStrict, "strict", false, "Fail if any --only key is missing instead of warning")
}

func runDockerBuild(c *cobra.Command, args []string) error {
	return runDockerWrapped(c, "build", args)
}

func runDockerCompose(c *cobra.Command, args []string) error {
	return runDockerWrapped(c, "compose", args)
}

func runDockerRun(c *cobra.Command, args []string) error {
	return runDockerWrapped(c, "run", args)
}

func runDockerWrapped(c *cobra.Command, kind string, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	secrets, missing, err := loadSelectedSecrets(secretSelectOpts{
		identity: dockerIdentity,
		group:    dockerGroup,
		envName:  dockerEnvName,
		only:     dockerOnly,
		prefix:   dockerPrefix,
		via:      "docker",
	})
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		msg := fmt.Sprintf("--only key(s) not found: %s", strings.Join(missing, ", "))
		if dockerStrict {
			return fmt.Errorf("%s", msg)
		}
		fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
	}
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}
	return runForwardedCommand(cobraCommandContext(c), dockerPath, dockerArgv(kind, secrets, args), dockerChildEnv(kind, secrets))
}

func dockerArgv(kind string, secrets map[string]string, user []string) []string {
	keys := sortedMapKeys(secrets)
	switch kind {
	case "build":
		out := make([]string, 0, 1+2*len(keys)+len(user))
		out = append(out, "build")
		for _, k := range keys {
			out = append(out, "--secret", "id="+k+",env="+k)
		}
		return append(out, user...)
	case "compose":
		out := make([]string, 0, 1+len(user))
		out = append(out, "compose")
		return append(out, user...)
	case "run":
		out := make([]string, 0, 1+2*len(keys)+len(user))
		out = append(out, "run")
		for _, k := range keys {
			out = append(out, "-e", k)
		}
		return append(out, user...)
	default:
		return append([]string{kind}, user...)
	}
}

func dockerChildEnv(kind string, secrets map[string]string) []string {
	env := processenv.Sanitize(os.Environ())
	if kind == "build" {
		env = append(env, "DOCKER_BUILDKIT=1")
	}
	keys := sortedMapKeys(secrets)
	for _, k := range keys {
		env = append(env, k+"="+secrets[k])
	}
	return processenv.Sanitize(env)
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cobraCommandContext(c *cobra.Command) context.Context {
	if c != nil {
		if ctx := c.Context(); ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func runForwardedCommand(ctx context.Context, path string, args, env []string) error {
	execCmd := exec.CommandContext(ctx, path, args...)
	execCmd.Env = env
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", path, err)
	}
	go func() {
		sig := <-sigChan
		if execCmd.Process != nil {
			_ = execCmd.Process.Signal(sig)
		}
	}()
	if err := execCmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("%s failed: %w", path, err)
	}
	return nil
}

func runDockerInit(_ *cobra.Command, _ []string) error {
	fmt.Print(dockerInitSnippets())
	return nil
}

func dockerInitSnippets() string {
	return `# TinyVault + Docker
#
# tvault docker init     # print this
# tvault docker build --only NPM_TOKEN -- -t app .
# tvault docker compose --only DATABASE_URL -- up
# tvault docker run --only DATABASE_URL -- --rm alpine env

# --- Dockerfile (BuildKit secret mount) ---------------------------------
# Values live in a build tmpfs at /run/secrets/<id>. They are not
# stored in image layers if you only read them in the same RUN.
#
#   FROM node:22
#   WORKDIR /app
#   COPY package.json package-lock.json ./
#   RUN --mount=type=secret,id=NPM_TOKEN \
#       NPM_TOKEN="$(cat /run/secrets/NPM_TOKEN)" npm ci
#   COPY . .

# --- compose.yaml (env interpolation) -----------------------------------
# tvault docker compose injects keys into the compose process; ${KEY}
# expands from that environment. Prefer listing only the keys the
# service needs.
#
#   services:
#     app:
#       build: .
#       environment:
#         DATABASE_URL: ${DATABASE_URL}
#
# For a compose *build* secret, declare it from the same environment:
#
#   secrets:
#     npm_token:
#       environment: NPM_TOKEN
#   services:
#     app:
#       build:
#         secrets:
#           - npm_token
`
}
