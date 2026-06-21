package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Update source. These are package-level (not flags or env) so the download
// origin cannot be redirected at runtime — a self-replacing binary must not let
// an attacker point it at a hostile server. Tests override them in-process.
var (
	updateAPIURL  = "https://api.github.com/repos/abdul-hamid-achik/tinyvault/releases/latest"
	updateBaseURL = "https://github.com/abdul-hamid-achik/tinyvault/releases/download"

	// resolveExecutableFn is a seam so tests can target a throwaway file instead
	// of replacing the running test binary.
	resolveExecutableFn = resolveExecutable
)

var (
	selfUpdateCheck   bool
	selfUpdateVersion string
)

var selfUpdateCmd = &cobra.Command{
	Use:     "self-update",
	Aliases: []string{"upgrade"},
	Short:   "Update tvault to the latest release in place",
	Long: `Download the latest tvault release for this OS/arch, verify its
SHA-256 checksum, and atomically replace the running binary.

Use --check to see whether an update is available without installing it, or
--version vX.Y.Z to install a specific release (e.g. to downgrade or pin).

The download source is fixed to the official GitHub releases and cannot be
overridden — the checksum is fetched from the same release and verified before
anything is written.

If you installed tvault via Homebrew or a system package (apt/dnf/apk), update
through that package manager instead so its bookkeeping stays correct.

Examples:
  tvault self-update
  tvault self-update --check
  tvault self-update --version v0.11.1`,
	RunE: runSelfUpdate,
}

func init() {
	rootCmd.AddCommand(selfUpdateCmd)
	selfUpdateCmd.Flags().BoolVarP(&selfUpdateCheck, "check", "c", false, "Only report whether an update is available; don't install")
	selfUpdateCmd.Flags().StringVar(&selfUpdateVersion, "version", "", "Install a specific release tag (e.g. v0.11.1) instead of the latest")
}

func runSelfUpdate(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	goos, goarch, err := updatePlatform()
	if err != nil {
		return err
	}

	target := selfUpdateVersion
	if target == "" {
		target, err = latestReleaseTag(ctx)
		if err != nil {
			return err
		}
	}
	target = ensureVTag(target)

	current := buildVersion
	if selfUpdateCheck {
		switch {
		case current == "dev" || current == "":
			fmt.Printf("current: dev (unversioned build)\nlatest:  %s\nrun 'tvault self-update' to install it\n", target)
		case compareVersions(current, target) >= 0:
			fmt.Printf("current: %s\nlatest:  %s\ntvault is up to date.\n", ensureVTag(current), target)
		default:
			fmt.Printf("current: %s\nlatest:  %s\nrun 'tvault self-update' to upgrade.\n", ensureVTag(current), target)
		}
		return nil
	}

	if current != "dev" && current != "" && compareVersions(current, target) >= 0 && selfUpdateVersion == "" {
		fmt.Printf("tvault is already up to date (%s).\n", ensureVTag(current))
		return nil
	}

	exe, err := resolveExecutableFn()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Updating tvault %s -> %s (%s/%s)...\n", current, target, goos, goarch)
	bin, err := downloadReleaseBinary(ctx, target, goos, goarch)
	if err != nil {
		return err
	}

	if err := replaceExecutable(exe, bin); err != nil {
		return err
	}

	fmt.Printf("✓ Updated to %s. Run 'tvault --version' to confirm.\n", target)
	return nil
}

// updatePlatform maps the runtime to release asset naming, rejecting platforms
// without a tar.gz asset.
func updatePlatform() (goos, goarch string, err error) {
	switch runtime.GOOS {
	case "linux", "darwin":
		goos = runtime.GOOS
	default:
		return "", "", fmt.Errorf("self-update supports linux and darwin; on %s use the installer for your platform", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
		goarch = runtime.GOARCH
	default:
		return "", "", fmt.Errorf("self-update supports amd64 and arm64, not %s", runtime.GOARCH)
	}
	return goos, goarch, nil
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

func latestReleaseTag(ctx context.Context) (string, error) {
	resp, err := httpGet(ctx, updateAPIURL)
	if err != nil {
		return "", fmt.Errorf("query latest release: %w", err)
	}
	defer resp.Body.Close()

	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode release metadata: %w", err)
	}
	if rel.TagName == "" {
		return "", errors.New("latest release has no tag_name")
	}
	return rel.TagName, nil
}

// downloadReleaseBinary fetches the tar.gz for tag/os/arch, verifies its SHA-256
// against the release checksums.txt, and returns the extracted tvault binary.
func downloadReleaseBinary(ctx context.Context, tag, goos, goarch string) ([]byte, error) {
	ver := strings.TrimPrefix(tag, "v")
	tarball := fmt.Sprintf("tvault_%s_%s_%s.tar.gz", ver, goos, goarch)
	tarURL := fmt.Sprintf("%s/%s/%s", updateBaseURL, tag, tarball)
	sumURL := fmt.Sprintf("%s/%s/checksums.txt", updateBaseURL, tag)

	archive, err := fetchBytes(ctx, tarURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", tarball, err)
	}
	sums, err := fetchBytes(ctx, sumURL)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}

	if err := verifyChecksum(archive, sums, tarball); err != nil {
		return nil, err
	}
	return extractBinary(archive)
}

func fetchBytes(ctx context.Context, url string) ([]byte, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 100<<20))
}

func verifyChecksum(archive, sums []byte, tarball string) error {
	var want string
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == tarball {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("no checksum entry for %s", tarball)
	}
	sum := sha256.Sum256(archive)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s (want %s, got %s)", tarball, want, got)
	}
	return nil
}

// extractBinary returns the "tvault" entry from a gzipped tar archive.
func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if filepath.Base(hdr.Name) == "tvault" && hdr.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(io.LimitReader(tr, 200<<20))
			if err != nil {
				return nil, fmt.Errorf("read tvault from archive: %w", err)
			}
			return data, nil
		}
	}
	return nil, errors.New("archive does not contain a tvault binary")
}

// resolveExecutable returns the real path of the running binary (symlinks
// resolved) so we replace the actual file, not a symlink.
func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate current binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// replaceExecutable atomically swaps the running binary for newBin by writing a
// temp file in the same directory and renaming over the target.
func replaceExecutable(exe string, newBin []byte) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".tvault-update-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s (try sudo, or update via your package manager): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(newBin); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close new binary: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil { //nolint:gosec // an executable must be 0755
		return fmt.Errorf("chmod new binary: %w", err)
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return fmt.Errorf("replace %s (try sudo, or update via your package manager): %w", exe, err)
	}
	return nil
}

func ensureVTag(v string) string {
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// compareVersions compares two vX.Y.Z strings numerically, returning -1, 0, or
// 1. Non-numeric or missing components compare as 0/lower so a malformed tag
// never blocks an update spuriously.
func compareVersions(a, b string) int {
	pa := splitVersion(a)
	pb := splitVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersion(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 { // drop pre-release / build metadata
		v = v[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			n = 0 // a non-numeric component never blocks an update spuriously
		}
		out[i] = n
	}
	return out
}
