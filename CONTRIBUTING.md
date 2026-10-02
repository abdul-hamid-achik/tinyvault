# Contributing to TinyVault

Thank you for your interest in contributing to TinyVault!

## Development Guidelines

For detailed development standards, code organization, and security requirements, please refer to [AGENTS.md](AGENTS.md).

## Getting Started

1. Fork the repository
2. Clone your fork
3. Set up the development environment:
   ```bash
   go mod download
   ```
4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Before Submitting

Run the full check suite. These are the same four checks `ci.yml` runs (Test, Lint,
Security Scan, Build); CI's Build job is a six-way cross-compile with
`CGO_ENABLED=0`, so a clean `go build ./...` locally is necessary but not quite
sufficient:

```bash
go build ./...                 # builds successfully
go test -race ./...            # all tests pass (race detector)
golangci-lint run ./...        # 0 lint issues
govulncheck ./...              # no new vulnerabilities in our code path
```

CI pins `golangci-lint` to **v2.12.2** and `govulncheck` to **v1.4.0**. A newer
local linter can report findings CI does not (new rules land between versions), so
if `main` is green and your lint is red, compare versions before changing code.

CLI behavior can be exercised in a real PTY with
[glyphrun](https://github.com/abdul-hamid-achik/glyphrun). The specs invoke
`./bin/tvault`, so build it first:

```bash
go build -o ./bin/tvault ./cmd/tvault
glyph run specs/glyphrun/cli_core.yml --format md
```

## Desktop app changes

The Electron GUI in `app/` is a front end over `tvault mcp`. If you touch
`internal/mcp` output structs, the renderer's wire types in `app/src/shared/types.ts`
and its contract test both need to follow:

```bash
cd app
bun install
bun run typecheck                                # both tsconfig projects
bun run build                                    # main + preload + renderer
TVAULT_BIN=../bin/tvault bun run verify          # assertions vs a throwaway vault
```

`bun run verify` never touches `~/.tvault`: it builds a scratch vault in `$TMPDIR`
and asserts the shape of every tool the app calls plus the security properties the
UI depends on. `ci-app.yml` runs all three on changes under `app/**`.

## Pull Request Process

1. Update documentation if you're changing behavior
2. Add tests for new functionality
3. Ensure all checks pass
4. Submit a PR with a clear description of changes

## Releases

Tagging drives everything; there is no manual publish step.

- `v*` tag → `release.yml` runs GoReleaser: archives, `.deb`/`.rpm`/`.apk`, raw
  per-platform binaries, and `checksums.txt`.
- A successful Release triggers `npm-publish.yml`, which packs
  `@thelacanians/tinyvault` and the six `@thelacanians/tinyvault-<platform>`
  packages from those checksummed binaries (OIDC trusted publishing, `NPM_TOKEN`
  fallback) and smoke-tests the published launcher on macOS, Linux, and Windows.
- The Homebrew cask lives in a separate tap repository and is not published from
  here.
- `docs/` deploys to [tinyvault.dev](https://tinyvault.dev) on pushes to `main`
  (Vercel, root directory `docs/`). Feature branches do not create previews.
- The desktop app is built by `release-app.yml`, which runs after the Release
  workflow completes and attaches `TinyVault-*.dmg` / `.AppImage` / `.exe` to the
  same tag. It is **unsigned and unnotarized** — there is no signing certificate
  in this project, so do not add one to the config by accident.

## Reporting Issues

When reporting bugs, please include:
- Steps to reproduce
- Expected vs actual behavior
- Go version and OS
- Relevant logs (with sensitive data redacted)

## Security Vulnerabilities

For security issues, please email the maintainer directly instead of opening a public issue.

## Code of Conduct

Be respectful and constructive in all interactions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
