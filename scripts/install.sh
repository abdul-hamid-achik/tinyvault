#!/bin/sh
# TinyVault installer — downloads the right release binary for this OS/arch,
# verifies its checksum, and installs `tvault` to a bin directory.
#
# Quick use (e.g. on a fresh DigitalOcean droplet over SSH):
#   curl -fsSL https://raw.githubusercontent.com/abdul-hamid-achik/tinyvault/main/scripts/install.sh | sh
#
# Knobs (environment variables):
#   TVAULT_VERSION       Tag or version to install (e.g. v0.11.1 or 0.11.1).
#                        Default: the latest GitHub release.
#   TVAULT_INSTALL_DIR   Target directory. Default: /usr/local/bin if writable
#                        (sudo if available), else ~/.local/bin.
#   TVAULT_OS            Override OS detection (linux | darwin).
#   TVAULT_ARCH          Override arch detection (amd64 | arm64).
#   TVAULT_BASE_URL      Override the release host (for mirrors/tests).
#   TVAULT_INSTALL_DRY_RUN=1
#                        Print the resolved plan and exit without downloading.
#
# POSIX sh only. Windows users: grab the .zip from the Releases page.
set -eu

OWNER="abdul-hamid-achik"
REPO="tinyvault"
BASE_URL="${TVAULT_BASE_URL:-https://github.com/${OWNER}/${REPO}/releases/download}"
API_URL="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"

fail() {
	echo "install: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

# --- detect OS ---------------------------------------------------------------
detect_os() {
	if [ -n "${TVAULT_OS:-}" ]; then
		printf '%s\n' "$TVAULT_OS"
		return
	fi
	case "$(uname -s)" in
	Linux) echo linux ;;
	Darwin) echo darwin ;;
	*) fail "unsupported OS $(uname -s); on Windows download the .zip from the Releases page" ;;
	esac
}

# --- detect arch -------------------------------------------------------------
detect_arch() {
	if [ -n "${TVAULT_ARCH:-}" ]; then
		printf '%s\n' "$TVAULT_ARCH"
		return
	fi
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) fail "unsupported arch $(uname -m); only amd64 and arm64 are released" ;;
	esac
}

# --- resolve version (tag like v1.2.3) --------------------------------------
resolve_version() {
	ver="${TVAULT_VERSION:-}"
	if [ -z "$ver" ]; then
		need curl
		ver="$(curl -fsSL "$API_URL" | grep '"tag_name"' | head -1 |
			sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
		[ -n "$ver" ] || fail "could not determine the latest version (set TVAULT_VERSION)"
	fi
	# Normalize to a v-prefixed tag.
	case "$ver" in
	v*) printf '%s\n' "$ver" ;;
	*) printf 'v%s\n' "$ver" ;;
	esac
}

# --- pick an install dir -----------------------------------------------------
choose_dir() {
	if [ -n "${TVAULT_INSTALL_DIR:-}" ]; then
		printf '%s\n' "$TVAULT_INSTALL_DIR"
		return
	fi
	if [ -w /usr/local/bin ] 2>/dev/null; then
		echo /usr/local/bin
	elif command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
		echo /usr/local/bin # will sudo install below
	elif [ "$(id -u)" -eq 0 ]; then
		echo /usr/local/bin
	else
		echo "${HOME}/.local/bin"
	fi
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
TAG="$(resolve_version)"
VER="${TAG#v}" # filename uses the bare version, the tag keeps the v
DIR="$(choose_dir)"

TARBALL="tvault_${VER}_${OS}_${ARCH}.tar.gz"
URL="${BASE_URL}/${TAG}/${TARBALL}"
CHECKSUM_URL="${BASE_URL}/${TAG}/checksums.txt"
TARGET="${DIR}/tvault"

if [ "${TVAULT_INSTALL_DRY_RUN:-0}" = "1" ]; then
	echo "os=${OS}"
	echo "arch=${ARCH}"
	echo "tag=${TAG}"
	echo "url=${URL}"
	echo "checksum_url=${CHECKSUM_URL}"
	echo "target=${TARGET}"
	exit 0
fi

need curl
need tar

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "install: downloading ${TARBALL} (${TAG})..."
curl -fsSL "$URL" -o "${tmp}/${TARBALL}" || fail "download failed: $URL"
curl -fsSL "$CHECKSUM_URL" -o "${tmp}/checksums.txt" || fail "checksum download failed: $CHECKSUM_URL"

# --- verify checksum ---------------------------------------------------------
verify_checksum() {
	want="$(grep " ${TARBALL}\$" "${tmp}/checksums.txt" | awk '{print $1}')"
	[ -n "$want" ] || fail "no checksum entry for ${TARBALL}"
	if command -v sha256sum >/dev/null 2>&1; then
		got="$(sha256sum "${tmp}/${TARBALL}" | awk '{print $1}')"
	elif command -v shasum >/dev/null 2>&1; then
		got="$(shasum -a 256 "${tmp}/${TARBALL}" | awk '{print $1}')"
	else
		echo "install: warning: no sha256 tool found, skipping checksum verification" >&2
		return
	fi
	[ "$want" = "$got" ] || fail "checksum mismatch for ${TARBALL} (want $want, got $got)"
	echo "install: checksum OK"
}
verify_checksum

tar -xzf "${tmp}/${TARBALL}" -C "$tmp" tvault || fail "could not extract tvault from ${TARBALL}"
chmod +x "${tmp}/tvault"

mkdir -p "$DIR" 2>/dev/null || true
if [ -w "$DIR" ]; then
	mv "${tmp}/tvault" "$TARGET"
elif command -v sudo >/dev/null 2>&1; then
	echo "install: ${DIR} is not writable; using sudo"
	sudo mkdir -p "$DIR"
	sudo mv "${tmp}/tvault" "$TARGET"
else
	fail "cannot write to ${DIR} and sudo is unavailable; set TVAULT_INSTALL_DIR to a writable path"
fi

echo "install: installed ${TARGET}"
"$TARGET" --version || true

case ":${PATH}:" in
*":${DIR}:"*) ;;
*) echo "install: note: ${DIR} is not on your PATH; add it with: export PATH=\"${DIR}:\$PATH\"" ;;
esac
