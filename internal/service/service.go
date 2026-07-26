// Package service renders and locates the per-user service definitions that
// keep `tvault agent` running: a launchd agent on macOS, a systemd user unit on
// Linux.
//
// # Why the passphrase is never in the unit
//
// A definition holds the *path* to a passphrase file, never the passphrase.
// launchd plists in ~/Library/LaunchAgents are world-readable by default and
// land in backups, and a systemd unit is no better a place for a secret. The
// agent reads the file itself and refuses one that is group- or world-readable
// (see the cmd package's readPassphraseFile), so protection stays with the file
// the user already guards.
//
// # Why rendering is not build-tagged
//
// Render takes the target Kind as a parameter rather than switching on
// runtime.GOOS, so a Linux CI host can test the launchd output and a macOS
// laptop can test the systemd unit. Only the actions that load and unload a
// definition are platform-gated.
package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"text/template"
	"time"
)

// Kind is a service manager.
type Kind string

const (
	// KindLaunchd is macOS launchd (a per-user LaunchAgent).
	KindLaunchd Kind = "launchd"
	// KindSystemd is a systemd user unit.
	KindSystemd Kind = "systemd"
)

const (
	// LaunchdLabel is the reverse-DNS label for the launchd agent, and the
	// basename of its plist.
	LaunchdLabel = "dev.tinyvault.agent"
	// SystemdUnit is the systemd user unit's filename.
	SystemdUnit = "tvault-agent.service"
)

// ErrUnsupportedPlatform is returned when the host has neither launchd nor
// systemd user units (e.g. Windows, where the agent itself is unsupported).
var ErrUnsupportedPlatform = fmt.Errorf("no supported service manager on %s/%s (launchd on darwin, systemd on linux)", runtime.GOOS, runtime.GOARCH)

// Config describes the service to render. Paths must be absolute: a service
// manager starts the process with an unspecified working directory, so a
// relative path would resolve somewhere the user never intended.
type Config struct {
	// Executable is the absolute path to the tvault binary.
	Executable string
	// VaultDir, when non-empty, is exported as TVAULT_DIR. Leave empty to let
	// the agent use its own default (~/.tvault).
	VaultDir string
	// PassphraseFile, when non-empty, is exported as TVAULT_PASSPHRASE_FILE.
	// Without it the agent cannot unlock under a service manager, since there
	// is no TTY to prompt at.
	PassphraseFile string
	// LogDir, when non-empty, is passed as --log-dir. Empty means the agent's
	// XDG default.
	LogDir string
	// LogLevel, when non-empty, is passed as --log-level.
	LogLevel string
	// Idle is the agent's auto-lock timeout. Zero means never auto-lock, which
	// keeps the KEK in memory for as long as the service runs.
	Idle time.Duration
}

// Validate reports whether the config can produce a working definition.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Executable) == "" {
		return fmt.Errorf("executable path is required")
	}
	for label, p := range map[string]string{
		"executable":      c.Executable,
		"vault dir":       c.VaultDir,
		"passphrase file": c.PassphraseFile,
		"log dir":         c.LogDir,
	} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, got %q", label, p)
		}
	}
	if c.Idle < 0 {
		return fmt.Errorf("idle must not be negative, got %s", c.Idle)
	}
	return nil
}

// ProgramPath extracts the executable a definition on disk will run.
//
// It exists so callers can catch the case that makes a service fail silently:
// the recorded binary no longer exists (a package upgrade moved it), which
// launchd reports only as exit status 78 while `launchctl bootstrap` still
// succeeds — so the service looks registered and simply never runs.
func ProgramPath(kind Kind) (string, error) {
	path, err := UnitPath(kind)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	body := string(data)

	switch kind {
	case KindLaunchd:
		// The first <string> inside ProgramArguments is the executable.
		i := strings.Index(body, "<key>ProgramArguments</key>")
		if i < 0 {
			return "", fmt.Errorf("%s has no ProgramArguments", path)
		}
		m := regexp.MustCompile(`<string>([^<]*)</string>`).FindStringSubmatch(body[i:])
		if m == nil {
			return "", fmt.Errorf("%s has an empty ProgramArguments", path)
		}
		return html.UnescapeString(m[1]), nil
	case KindSystemd:
		m := regexp.MustCompile(`(?m)^ExecStart=(?:"([^"]+)"|(\S+))`).FindStringSubmatch(body)
		if m == nil {
			return "", fmt.Errorf("%s has no ExecStart", path)
		}
		if m[1] != "" {
			return m[1], nil
		}
		return m[2], nil
	default:
		return "", fmt.Errorf("unknown service kind %q", kind)
	}
}

// VerifyProgram reports whether the installed definition's executable still
// exists, returning the path either way so callers can name it.
func VerifyProgram(kind Kind) (string, error) {
	exe, err := ProgramPath(kind)
	if err != nil {
		return "", err
	}
	if _, serr := os.Stat(exe); serr != nil {
		return exe, fmt.Errorf("the installed service points at %s, which no longer exists "+
			"(a package upgrade likely replaced it); re-run 'tvault agent install'", exe)
	}
	return exe, nil
}

// args returns the agent's command-line arguments, excluding the executable.
func (c Config) args() []string {
	args := []string{"agent", "start", "--idle", c.Idle.String()}
	if c.LogDir != "" {
		args = append(args, "--log-dir", c.LogDir)
	}
	if c.LogLevel != "" {
		args = append(args, "--log-level", c.LogLevel)
	}
	return args
}

// env returns the environment the service exports, as ordered key/value pairs
// so rendering is deterministic and diffable.
func (c Config) env() [][2]string {
	var out [][2]string
	if c.VaultDir != "" {
		out = append(out, [2]string{"TVAULT_DIR", c.VaultDir})
	}
	if c.PassphraseFile != "" {
		out = append(out, [2]string{"TVAULT_PASSPHRASE_FILE", c.PassphraseFile})
	}
	return out
}

// DefaultKind returns the service manager for the running host.
func DefaultKind() (Kind, error) {
	switch runtime.GOOS {
	case "darwin":
		return KindLaunchd, nil
	case "linux":
		return KindSystemd, nil
	default:
		return "", ErrUnsupportedPlatform
	}
}

// UnitPath returns where a definition of the given kind belongs for the current
// user.
func UnitPath(kind Kind) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	switch kind {
	case KindLaunchd:
		return filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist"), nil
	case KindSystemd:
		// Honor XDG_CONFIG_HOME: systemd itself reads user units from
		// $XDG_CONFIG_HOME/systemd/user, falling back to ~/.config.
		base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if base == "" {
			base = filepath.Join(home, ".config")
		}
		return filepath.Join(base, "systemd", "user", SystemdUnit), nil
	default:
		return "", fmt.Errorf("unknown service kind %q", kind)
	}
}

// Render produces the service definition's file contents.
func Render(kind Kind, cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	switch kind {
	case KindLaunchd:
		return renderLaunchd(cfg)
	case KindSystemd:
		return renderSystemd(cfg)
	default:
		return "", fmt.Errorf("unknown service kind %q", kind)
	}
}

// xmlString escapes a value for a plist <string> element. Home directories can
// contain & and other characters that would otherwise produce a malformed
// plist that launchd silently refuses to load.
func xmlString(s string) (string, error) {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return "", fmt.Errorf("escape %q for plist: %w", s, err)
	}
	return buf.String(), nil
}

// launchdTemplate is a per-user LaunchAgent.
//
// KeepAlive is deliberately conditional on SuccessfulExit=false: a crash is
// restarted, but the agent's clean exit after its idle timeout is respected.
// Restarting on a clean exit would defeat the idle auto-lock, whose whole point
// is to stop holding the KEK in memory. Once the agent has idled out, the next
// `tvault get` falls back to a direct unlock, which still needs no prompt when
// a passphrase file is configured — just the ~200ms Argon2id derivation.
var launchdTemplate = template.Must(template.New("launchd").Parse(
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
{{- range .Args}}
		<string>{{.}}</string>
{{- end}}
	</array>
{{- if .Env}}
	<key>EnvironmentVariables</key>
	<dict>
{{- range .Env}}
		<key>{{.Key}}</key>
		<string>{{.Value}}</string>
{{- end}}
	</dict>
{{- end}}
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>{{.StdoutPath}}</string>
	<key>StandardErrorPath</key>
	<string>{{.StderrPath}}</string>
</dict>
</plist>
`))

type launchdData struct {
	Label      string
	Args       []string
	Env        []kv
	StdoutPath string
	StderrPath string
}

type kv struct{ Key, Value string }

func renderLaunchd(cfg Config) (string, error) {
	if cfg.LogDir == "" {
		return "", fmt.Errorf("launchd needs an absolute log directory for StandardOutPath/StandardErrorPath")
	}

	args := append([]string{cfg.Executable}, cfg.args()...)
	escaped := make([]string, 0, len(args))
	for _, a := range args {
		e, err := xmlString(a)
		if err != nil {
			return "", err
		}
		escaped = append(escaped, e)
	}

	env := make([]kv, 0, len(cfg.env()))
	for _, pair := range cfg.env() {
		k, err := xmlString(pair[0])
		if err != nil {
			return "", err
		}
		v, err := xmlString(pair[1])
		if err != nil {
			return "", err
		}
		env = append(env, kv{Key: k, Value: v})
	}

	// launchd captures the process's own stdout/stderr. These are separate from
	// the agent's structured log (agent.log) and mostly hold the one-line
	// "listening" banner plus anything the runtime writes on a crash.
	stdout, err := xmlString(filepath.Join(cfg.LogDir, "agent.out.log"))
	if err != nil {
		return "", err
	}
	stderr, err := xmlString(filepath.Join(cfg.LogDir, "agent.err.log"))
	if err != nil {
		return "", err
	}
	label, err := xmlString(LaunchdLabel)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := launchdTemplate.Execute(&buf, launchdData{
		Label: label, Args: escaped, Env: env,
		StdoutPath: stdout, StderrPath: stderr,
	}); err != nil {
		return "", fmt.Errorf("render launchd plist: %w", err)
	}
	return buf.String(), nil
}

// systemdTemplate is a user unit.
//
// Type=simple matches the agent's deliberate refusal to daemonize (forking a
// live Go runtime is unsafe), so systemd owns the backgrounding. Restart is
// on-failure rather than always for the same reason launchd uses
// SuccessfulExit=false: a clean idle exit must not be undone.
var systemdTemplate = template.Must(template.New("systemd").Parse(
	`[Unit]
Description=TinyVault local agent (holds the vault unlocked for prompt-free reads)
Documentation=https://tinyvault.dev/guide/agent

[Service]
Type=simple
ExecStart={{.ExecStart}}
{{- range .Env}}
Environment={{.}}
{{- end}}
Restart=on-failure
RestartSec=5
# The agent holds key material in memory; keep it out of core dumps.
LimitCORE=0

[Install]
WantedBy=default.target
`))

type systemdData struct {
	ExecStart string
	Env       []string
}

// systemdQuote renders a value for ExecStart or Environment=. systemd splits
// ExecStart on whitespace, so any argument containing a space, a quote or a
// backslash must be double-quoted with those characters escaped.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func renderSystemd(cfg Config) (string, error) {
	parts := make([]string, 0, len(cfg.args())+1)
	parts = append(parts, systemdQuote(cfg.Executable))
	for _, a := range cfg.args() {
		parts = append(parts, systemdQuote(a))
	}

	env := make([]string, 0, len(cfg.env()))
	for _, pair := range cfg.env() {
		// Quote the whole KEY=VALUE so a value with spaces stays one assignment.
		env = append(env, systemdQuote(pair[0]+"="+pair[1]))
	}

	var buf bytes.Buffer
	if err := systemdTemplate.Execute(&buf, systemdData{
		ExecStart: strings.Join(parts, " "),
		Env:       env,
	}); err != nil {
		return "", fmt.Errorf("render systemd unit: %w", err)
	}
	return buf.String(), nil
}
