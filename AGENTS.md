# AGENTS.md - Claude Code Instructions for TinyVault

## Primary Directive

**Write production-quality, secure code with comprehensive tests.**

Before marking ANY task complete:
1. `task lint` passes
2. `task test` passes
3. `task build:all` compiles
4. No hardcoded secrets
5. Security review for crypto/auth code

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

```go
// Use structured logging
slog.Info("secret created",
    "project_id", projectID,
    "key", key,
    "user_id", userID,
)

// Never log sensitive data
// BAD: slog.Info("secret", "value", secretValue)
// BAD: slog.Info("auth", "token", token)

// Log at appropriate levels
slog.Debug("...")  // Development details
slog.Info("...")   // Normal operations
slog.Warn("...")   // Recoverable issues
slog.Error("...")  // Failures requiring attention
```

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
