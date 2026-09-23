package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// envPassphraseCommand names a command whose stdout is the vault passphrase.
//
// It is the password-manager counterpart of TVAULT_PASSPHRASE_FILE (compare
// restic's --password-command or borg's BORG_PASSCOMMAND): the passphrase can
// live in 1Password (`op read op://…`), the macOS keychain (`security
// find-generic-password -w …`), pass, or any helper, so it never has to sit
// in a plaintext file on disk. A password manager that demands Touch ID or a
// master password turns "any same-uid process can read the file" into "the
// human approves each unlock".
const envPassphraseCommand = "TVAULT_PASSPHRASE_COMMAND" //nolint:gosec // G101: a variable name, not a credential

// passphraseCommandTimeout bounds how long tvault waits for the helper. It is
// generous because the helper may be waiting on a human (Touch ID, a
// password-manager unlock dialog), but finite so a wedged helper cannot hang a
// daemon or an MCP host forever.
const passphraseCommandTimeout = 2 * time.Minute

// maxPassphraseOutput caps what tvault reads from the helper. A passphrase is
// short; anything larger is a misconfigured command (e.g. one that prints a
// whole item as JSON), and is refused rather than truncated.
const maxPassphraseOutput = 4096

// errPassphraseCommandUntrusted is returned when passphrase_command comes from
// a config file that another user could have written.
var errPassphraseCommandUntrusted = errors.New("config file is not safe to run passphrase_command from")

// passphraseCommand returns the configured helper argv and where it came from
// (the variable name or the config path, for error messages). It returns a nil
// argv when no command is configured. The environment variable wins over the
// config, matching TVAULT_PASSPHRASE_FILE vs agent.passphrase_file.
//
// A command from the config file is only honored when that file is owned by the
// current user and not writable by group or others: config.yaml would
// otherwise be a code-execution primitive for anyone who can write it.
func passphraseCommand(cfg Config) (argv []string, origin string, err error) {
	if raw := strings.TrimSpace(os.Getenv(envPassphraseCommand)); raw != "" {
		argv, err = splitCommandLine(raw)
		if err != nil {
			return nil, envPassphraseCommand, fmt.Errorf("parse %s: %w", envPassphraseCommand, err)
		}
		return argv, envPassphraseCommand, nil
	}
	if len(cfg.Agent.PassphraseCommand) == 0 {
		return nil, "", nil
	}
	path := configPath()
	if err := checkConfigTrusted(path); err != nil {
		return nil, path, err
	}
	return []string(cfg.Agent.PassphraseCommand), path, nil
}

// checkConfigTrusted refuses a config file that is group/world-writable or,
// on Unix, owned by another user. It is only consulted when the file asks
// tvault to execute something.
func checkConfigTrusted(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errPassphraseCommandUntrusted, path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others (mode %#o); tighten it with: chmod 600 %s",
			errPassphraseCommandUntrusted, path, perm, path)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("%w: %s is not owned by the current user", errPassphraseCommandUntrusted, path)
	}
	return nil
}

// runPassphraseCommand executes argv directly (no shell) and returns its
// stdout with trailing newlines removed.
//
// stdin is /dev/null: under `tvault mcp` stdin is the MCP protocol stream,
// and a helper must never consume it. stderr is inherited so a helper's own
// prompts and errors stay visible. Errors name only the program, its exit
// status and origin — never anything it printed on stdout.
func runPassphraseCommand(argv []string, origin string) (string, error) {
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return "", fmt.Errorf("passphrase command from %s is empty", origin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), passphraseCommandTimeout)
	defer cancel()

	// The argv is operator configuration (an env var the caller set, or a
	// config file checkConfigTrusted vetted), and it is exec'd without a shell.
	c := exec.CommandContext(ctx, expandHome(argv[0]), argv[1:]...) //nolint:gosec // G204: operator-configured helper, no shell
	c.Stdin = nil
	c.Stderr = os.Stderr
	var out limitedBuffer
	out.limit = maxPassphraseOutput
	c.Stdout = &out

	name := argv[0]
	if err := c.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("passphrase command %q (from %s) timed out after %s", name, origin, passphraseCommandTimeout)
		}
		// Check overflow before the exit status: once the pipe is closed on it,
		// the helper usually dies of SIGPIPE, which would mask the real cause.
		if out.overflow || errors.Is(err, errOutputTooLarge) {
			return "", fmt.Errorf("passphrase command %q (from %s) printed more than %d bytes; it must print only the passphrase",
				name, origin, maxPassphraseOutput)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("passphrase command %q (from %s) failed with exit status %d",
				name, origin, exitErr.ExitCode())
		}
		return "", fmt.Errorf("passphrase command %q (from %s): %w", name, origin, err)
	}
	if out.overflow {
		return "", fmt.Errorf("passphrase command %q (from %s) printed more than %d bytes; it must print only the passphrase",
			name, origin, maxPassphraseOutput)
	}
	pass := strings.TrimRight(out.String(), "\r\n")
	if pass == "" {
		return "", fmt.Errorf("passphrase command %q (from %s) printed nothing", name, origin)
	}
	return pass, nil
}

var errOutputTooLarge = errors.New("output too large")

// limitedBuffer is an io.Writer that keeps at most limit bytes and then
// fails, so a runaway helper cannot make tvault buffer unbounded output.
//
// The buffer is a named field, not embedded: an embedded bytes.Buffer would
// promote ReadFrom, which io.Copy (and so os/exec) prefers over Write — and
// that would bypass the limit entirely.
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		b.overflow = true
		return 0, errOutputTooLarge
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string { return b.buf.String() }

// splitCommandLine splits a command string into argv the way a user expects
// from a shell, without being one: whitespace separates words, and single or
// double quotes group them (inside double quotes a backslash escapes the next
// character). There is no variable, glob, or command expansion.
func splitCommandLine(s string) ([]string, error) {
	var (
		args    []string
		cur     strings.Builder
		inWord  bool
		quote   rune
		escaped bool
	)
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch r {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == '\\':
			escaped = true
			inWord = true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if escaped {
		return nil, errors.New("trailing backslash")
	}
	if inWord {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	return args, nil
}
