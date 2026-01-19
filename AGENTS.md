# AGENTS.md - Claude Code Instructions for TinyVault

## Primary Directive

**Write production-quality, secure code with comprehensive tests.**

Before marking ANY task complete:
1. `task lint` passes
2. `task test` passes
3. `task build:all` compiles
4. `govulncheck ./...` passes (no known vulnerabilities)
5. No hardcoded secrets
6. Security review for crypto/auth code

## Quick Reference

```bash
# First time
task setup

# Daily development
task dev

# Before committing
task check

# Run specific checks
task lint
task test
task test:crypto  # Security-critical tests
govulncheck ./... # Check for known vulnerabilities
```

## Security Rules (CRITICAL)

### Encryption
- **ALWAYS** use `crypto/rand` for random bytes (never `math/rand`)
- **ALWAYS** generate unique nonces for each encryption
- **NEVER** reuse nonces
- **NEVER** log secret values (even in debug mode)
- **NEVER** store plaintext secrets in database

### Authentication
- **ALWAYS** hash tokens before storage (SHA-256)
- **ALWAYS** use constant-time comparison for tokens
- **ALWAYS** validate and sanitize user input
- **NEVER** expose internal errors to users

### Database
- **ALWAYS** use SQLC parameterized queries
- **NEVER** concatenate user input into SQL
- **ALWAYS** use transactions for multi-step operations

### Example: Secure Secret Storage

```go
// CORRECT
func (s *SecretService) Create(ctx context.Context, key string, value []byte) error {
    // Get project's encryption key (already decrypted in memory)
    dek, err := s.getProjectDEK(ctx, projectID)
    if err != nil {
        return fmt.Errorf("failed to get encryption key: %w", err)
    }

    // Encrypt with unique nonce
    encrypted, err := crypto.Encrypt(dek, value)
    if err != nil {
        return fmt.Errorf("failed to encrypt: %w", err)
    }

    // Store encrypted value
    return s.db.CreateSecret(ctx, db.CreateSecretParams{
        Key:            key,
        EncryptedValue: encrypted,
    })
}

// WRONG - Never do this
func (s *SecretService) CreateBad(key string, value []byte) error {
    // WRONG: Storing plaintext
    return s.db.CreateSecret(ctx, db.CreateSecretParams{
        Key:   key,
        Value: value,  // NOT ENCRYPTED!
    })
}
```

## File Organization

### When Adding a Feature
1. `internal/database/migrations/` - Schema changes
2. `internal/database/queries/` - SQLC queries
3. `internal/services/` - Business logic
4. `internal/handlers/` - HTTP handlers
5. `internal/views/` - UI templates
6. `*_test.go` files alongside each

### Code Location Rules

| Type | Location |
|------|----------|
| Database queries | `internal/database/queries/*.sql` |
| Services | `internal/services/*.go` |
| HTTP handlers | `internal/handlers/*.go` |
| Middleware | `internal/middleware/*.go` |
| Encryption | `internal/crypto/*.go` |
| Templates | `internal/views/**/*.templ` |
| Static assets | `web/static/` |

## Testing Requirements

### Coverage Targets

| Package | Minimum |
|---------|---------|
| `internal/crypto` | 100% |
| `internal/services` | 80% |
| `internal/handlers` | 70% |

### Test Types

```bash
task test:unit        # Fast unit tests
task test:integration # With real DB
task test:crypto      # Security tests
task test:coverage    # HTML report
```

## Security Scanning (CRITICAL)

### govulncheck

**ALWAYS run govulncheck before pushing changes.** This tool detects known vulnerabilities in Go dependencies and standard library.

```bash
# Install (one-time)
go install golang.org/x/vuln/cmd/govulncheck@latest

# Run before pushing
govulncheck ./...
```

**Expected output when no issues found:**
```
No vulnerabilities found.
```

**If vulnerabilities are found:**
1. Check if the vulnerable code paths are actually used in the project
2. Update the affected dependency if a fix is available
3. If it's a standard library vulnerability, upgrade Go version
4. Document any false positives or accepted risks

### Why This Matters

govulncheck analyzes your code's call graph and only reports vulnerabilities that are actually reachable in your codebase. This avoids false positives from unused dependency code.

**CI Integration:** The CI pipeline runs govulncheck automatically. The build will fail if vulnerabilities are found.

### Writing Tests

```go
// Always test error cases
func TestEncrypt_InvalidKey(t *testing.T) {
    _, err := crypto.Encrypt([]byte("short"), []byte("data"))
    if err == nil {
        t.Error("expected error for short key")
    }
}

// Table-driven tests for crypto
func TestEncryptDecrypt(t *testing.T) {
    tests := []struct {
        name      string
        plaintext []byte
    }{
        {"empty", []byte{}},
        {"short", []byte("hello")},
        {"long", bytes.Repeat([]byte("x"), 10000)},
        {"unicode", []byte("Hello World")},
        {"binary", []byte{0x00, 0xFF, 0x00, 0xFF}},
    }

    key, _ := crypto.GenerateKey()

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            encrypted, err := crypto.Encrypt(key, tt.plaintext)
            require.NoError(t, err)

            decrypted, err := crypto.Decrypt(key, encrypted)
            require.NoError(t, err)

            assert.Equal(t, tt.plaintext, decrypted)
        })
    }
}
```

## Nord Theme Colors

Always use these CSS variables:

```css
/* Backgrounds */
bg-nord0    /* #2e3440 - main background */
bg-nord1    /* #3b4252 - elevated surface */
bg-nord2    /* #434c5e - selection */

/* Text */
text-nord4  /* #d8dee9 - primary text */
text-nord5  /* #e5e9f0 - secondary text */
text-nord6  /* #eceff4 - bright/headings */

/* Accents */
text-nord8  /* #88c0d0 - primary brand */
text-nord10 /* #5e81ac - links */

/* Semantic */
text-nord11 /* #bf616a - error */
text-nord14 /* #a3be8c - success */
text-nord13 /* #ebcb8b - warning */
```

## Commit Checklist

Before every commit:

- [ ] `task lint` passes
- [ ] `task test` passes
- [ ] `govulncheck ./...` passes (no known vulnerabilities)
- [ ] No `TODO` or `FIXME` without issue link
- [ ] No hardcoded secrets/credentials
- [ ] No `fmt.Println` (use `slog`)
- [ ] Error messages don't leak internal details
- [ ] New crypto code reviewed for security
- [ ] Tests added for new functionality

## Common Mistakes to Avoid

1. **Using `math/rand` for crypto** - Always use `crypto/rand`
2. **Logging secrets** - Never log secret values
3. **SQL concatenation** - Always use SQLC
4. **Reusing nonces** - Generate fresh nonce for each encrypt
5. **Missing error handling** - Always handle and wrap errors
6. **Exposing stack traces** - Return generic errors to users
7. **Skipping tests** - Run `task check` before every commit

## API Response Format

### Success Response
```json
{
  "data": { ... },
  "meta": {
    "request_id": "uuid"
  }
}
```

### Error Response
```json
{
  "error": {
    "code": "INVALID_INPUT",
    "message": "Human-readable message"
  },
  "meta": {
    "request_id": "uuid"
  }
}
```

## Logging Guidelines

### Using the Logging Package

TinyVault uses a dedicated `internal/logging` package for context-aware logging with automatic request ID propagation. This ensures all logs within a request can be correlated.

```go
import "github.com/abdul-hamid-achik/tinyvault/internal/logging"

func MyHandler(w http.ResponseWriter, r *http.Request) {
    log := logging.Logger(r.Context())  // Gets logger with request_id

    log.Info("operation_completed", "user_id", userID)
    // Output includes: request_id=abc-123 user_id=xyz-456 msg=operation_completed
}
```

### Security-First Logging (CRITICAL)

**NEVER log:**
- Passwords or password hashes
- OAuth tokens or authorization codes
- Session tokens
- API keys
- Secret values
- Encryption keys or nonces
- Full credit card numbers
- Social security numbers

**ALWAYS safe to log:**
- User IDs, email addresses, usernames
- Project IDs, resource IDs
- Secret keys (the identifier, NOT the value)
- Timestamps, IP addresses
- Request IDs, session IDs (the database ID, not the token)
- Error messages (but sanitize internal details)

```go
// CORRECT - logs key but not value
log.Info("secret_created", "project_id", projectID, "key", key, "user_id", userID)

// WRONG - never log secret values!
log.Info("secret_created", "key", key, "value", secretValue) // NEVER DO THIS
```

### Log Levels Guide

| Level | When to Use | Examples |
|-------|-------------|----------|
| Debug | Flow tracing, development details | `session_validated`, `oauth_token_exchanged`, `user_upserted` |
| Info | Business events, successful operations | `user_logged_in`, `project_created`, `secret_deleted` |
| Warn | Suspicious activity, recoverable issues | `account_locked`, `oauth_state_mismatch`, `invalid_credentials` |
| Error | Failures requiring attention | DB errors, API failures, token generation failures |

### Logging Patterns by Layer

**Handlers (highest level):**
```go
log := logging.Logger(r.Context())
// Log business events at Info level
log.Info("user_logged_in", "user_id", user.ID, "provider", "github")
// Log failures at Error level
log.Error("project_creation_failed", "user_id", user.ID, "error", err)
```

**Services (business logic):**
```go
log := logging.Logger(ctx)
// Log operations at Debug level
log.Debug("session_created", "session_id", session.ID, "user_id", userID)
// Log security events at Warn level
log.Warn("account_locked", "email", email, "failed_attempts", count)
```

**Database (infrastructure):**
```go
log := logging.Logger(ctx)
// Only log errors at this layer
log.Error("transaction_commit_failed", "error", err)
```

### Architecture Notes

The logging package (`internal/logging`) is kept separate from middleware to avoid import cycles:
- `internal/logging` - Core logger utilities, no dependencies
- `internal/middleware` - HTTP middleware, imports logging
- `internal/services` - Business logic, imports logging
- `internal/handlers` - HTTP handlers, can import either

This allows request IDs to propagate through all layers while keeping the dependency graph clean.

## Environment Configuration

Required environment variables:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `ENCRYPTION_KEY` - Master encryption key (base64, 32 bytes)
- `SESSION_SECRET` - Session signing key
- `GITHUB_CLIENT_ID` - OAuth client ID
- `GITHUB_CLIENT_SECRET` - OAuth client secret

Optional:
- `SERVER_HOST` - Bind address (default: 0.0.0.0)
- `SERVER_PORT` - Port (default: 8080)
- `LOG_LEVEL` - debug/info/warn/error (default: info)
