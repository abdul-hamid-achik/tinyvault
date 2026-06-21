package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"1.2.3", "v1.2.3", 0}, // v-prefix optional
		{"v1.2.3", "v1.2.4", -1},
		{"v1.3.0", "v1.2.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v0.11.1", "v0.11.10", -1}, // numeric, not lexical
		{"v1.2.3-rc1", "v1.2.3", 0}, // pre-release metadata dropped
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVerifyChecksum(t *testing.T) {
	archive := []byte("fake tarball bytes")
	sum := sha256.Sum256(archive)
	good := fmt.Sprintf("%s  tvault_9.9.9_linux_amd64.tar.gz\nabc  other.tar.gz\n", hex.EncodeToString(sum[:]))

	if err := verifyChecksum(archive, []byte(good), "tvault_9.9.9_linux_amd64.tar.gz"); err != nil {
		t.Errorf("verifyChecksum (good) = %v, want nil", err)
	}
	if err := verifyChecksum([]byte("tampered"), []byte(good), "tvault_9.9.9_linux_amd64.tar.gz"); err == nil {
		t.Error("verifyChecksum should fail on a content mismatch")
	}
	if err := verifyChecksum(archive, []byte(good), "missing.tar.gz"); err == nil {
		t.Error("verifyChecksum should fail when the file has no checksum entry")
	}
}

// makeReleaseTarball returns a gzipped tar containing a `tvault` entry with the
// given content (plus a README, like the real release archive).
func makeReleaseTarball(t *testing.T, binary []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{
		{"README.md", []byte("readme")},
		{"tvault", binary},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractBinary(t *testing.T) {
	want := []byte("#!/fake/tvault-binary\x00\x01\x02")
	got, err := extractBinary(makeReleaseTarball(t, want))
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted binary = %q, want %q", got, want)
	}

	// An archive with no tvault entry is an error.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "README.md", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = gz.Close()
	if _, err := extractBinary(buf.Bytes()); err == nil {
		t.Error("extractBinary should fail when no tvault entry is present")
	}
}

// fakeReleaseServer serves a latest-release API doc, the tarball, and a
// checksums.txt for the host os/arch under tag v9.9.9. It returns the server,
// the tarball filename, and the binary content it will deliver.
func fakeReleaseServer(t *testing.T, corruptChecksum bool) (*httptest.Server, []byte) {
	t.Helper()
	ver := "9.9.9"
	tag := "v" + ver
	tarball := fmt.Sprintf("tvault_%s_%s_%s.tar.gz", ver, runtime.GOOS, runtime.GOARCH)
	binary := []byte("UPDATED-TVAULT-BINARY-" + runtime.GOOS)
	archive := makeReleaseTarball(t, binary)

	sum := sha256.Sum256(archive)
	checksumHex := hex.EncodeToString(sum[:])
	if corruptChecksum {
		checksumHex = strings.Repeat("0", 64)
	}
	checksums := fmt.Sprintf("%s  %s\n", checksumHex, tarball)

	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q}`, tag)
	})
	mux.HandleFunc("/dl/"+tag+"/"+tarball, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	})
	mux.HandleFunc("/dl/"+tag+"/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, binary
}

// withUpdateSeams points the package update source at srv and the target binary
// at exePath, restoring everything afterward.
func withUpdateSeams(t *testing.T, srv *httptest.Server, exePath string) {
	t.Helper()
	oa, ob, of := updateAPIURL, updateBaseURL, resolveExecutableFn
	oc, ov := selfUpdateCheck, selfUpdateVersion
	t.Cleanup(func() {
		updateAPIURL, updateBaseURL, resolveExecutableFn = oa, ob, of
		selfUpdateCheck, selfUpdateVersion = oc, ov
	})
	updateAPIURL = srv.URL + "/latest"
	updateBaseURL = srv.URL + "/dl"
	resolveExecutableFn = func() (string, error) { return exePath, nil }
	selfUpdateCheck, selfUpdateVersion = false, ""
}

func newSelfUpdateCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetContext(context.Background())
	return c
}

func TestSelfUpdate_ReplacesBinary(t *testing.T) {
	srv, newBinary := fakeReleaseServer(t, false)

	exePath := filepath.Join(t.TempDir(), "tvault")
	if err := os.WriteFile(exePath, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	withUpdateSeams(t, srv, exePath)

	if err := runSelfUpdate(newSelfUpdateCmd(), nil); err != nil {
		t.Fatalf("runSelfUpdate: %v", err)
	}

	got, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBinary) {
		t.Errorf("binary after update = %q, want %q", got, newBinary)
	}
	if info, _ := os.Stat(exePath); info != nil && info.Mode().Perm()&0o100 == 0 {
		t.Errorf("updated binary is not executable: %v", info.Mode())
	}
}

func TestSelfUpdate_ChecksumMismatchAborts(t *testing.T) {
	srv, _ := fakeReleaseServer(t, true) // serves a bogus checksum

	exePath := filepath.Join(t.TempDir(), "tvault")
	const original = "OLD-BINARY-UNCHANGED"
	if err := os.WriteFile(exePath, []byte(original), 0o755); err != nil {
		t.Fatal(err)
	}
	withUpdateSeams(t, srv, exePath)

	err := runSelfUpdate(newSelfUpdateCmd(), nil)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected a checksum mismatch error, got %v", err)
	}
	// The original binary must be untouched.
	got, _ := os.ReadFile(exePath)
	if string(got) != original {
		t.Errorf("binary was modified despite checksum failure: %q", got)
	}
}

func TestSelfUpdate_CheckDoesNotModify(t *testing.T) {
	srv, _ := fakeReleaseServer(t, false)

	exePath := filepath.Join(t.TempDir(), "tvault")
	const original = "OLD-BINARY"
	if err := os.WriteFile(exePath, []byte(original), 0o755); err != nil {
		t.Fatal(err)
	}
	withUpdateSeams(t, srv, exePath)
	selfUpdateCheck = true

	out := captureStdout(t, func() {
		if err := runSelfUpdate(newSelfUpdateCmd(), nil); err != nil {
			t.Fatalf("runSelfUpdate --check: %v", err)
		}
	})
	if !strings.Contains(string(out), "v9.9.9") {
		t.Errorf("--check output should mention the latest tag, got: %s", out)
	}
	got, _ := os.ReadFile(exePath)
	if string(got) != original {
		t.Errorf("--check modified the binary: %q", got)
	}
}
