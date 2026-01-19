# TinyVault Setup & Deployment Guide

This guide walks you through setting up TinyVault for local development and production deployment.

## Prerequisites

- Go 1.25+
- Docker & Docker Compose
- Node.js (for Tailwind CSS) or standalone Tailwind binary

## Quick Start (Local Development)

**Zero configuration required!** Just run:

```bash
# 1. Clone and enter the project
cd tinyvault

# 2. Run setup (creates .env, installs deps, starts DB, runs migrations)
task setup

# 3. Start development server
task dev
```

That's it! Visit http://localhost:8080 and register with email/password.

### Alternative: Docker-only Setup

```bash
# Start everything with Docker (builds app from source)
docker compose up -d

# Wait for healthy status
docker compose ps

# Visit http://localhost:8080
```

---

## Authentication

TinyVault supports two authentication methods:

### Email/Password (Default)
- No configuration needed
- Register at `/auth/register`
- Login at `/auth/login`
- Password hashing uses Argon2id

### GitHub OAuth (Optional)
If you want to enable "Sign in with GitHub":

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - Application name: TinyVault Dev
   - Homepage URL: http://localhost:8080
   - Authorization callback URL: http://localhost:8080/auth/callback
4. Add to `.env`:
   ```
   GITHUB_CLIENT_ID=your-client-id
   GITHUB_CLIENT_SECRET=your-client-secret
   ```
5. Restart the server

---

## Environment Variables

### Required for Production Only

| Variable | Description | Development Default |
|----------|-------------|---------------------|
| `ENCRYPTION_KEY` | 32-byte base64 key for encrypting secrets | Auto-generated |
| `GITHUB_CLIENT_ID` | GitHub OAuth Client ID | Not required |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth Secret | Not required |

### Optional (Have Defaults)

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | `postgres://tinyvault:tinyvault@localhost:5432/tinyvault` |
| `REDIS_URL` | Redis connection | `redis://localhost:6379/0` |
| `ENV` | Environment mode | `development` |
| `LOG_LEVEL` | Log level | `info` |
| `GITHUB_CALLBACK_URL` | OAuth callback URL | `http://localhost:8080/auth/callback` |

### Generate Encryption Key (Production)

```bash
openssl rand -base64 32
```

Example output: `K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=`

---

## Local Development

### Using Task (Recommended)

```bash
# First-time setup
task setup

# Start development server with hot reload
task dev

# Run tests
task test

# Run linter
task lint

# Build binaries
task build:all

# See all commands
task --list
```

### Manual Setup

```bash
# Install Go dependencies
go mod download

# Install tools
go install github.com/a-h/templ/cmd/templ@latest
go install github.com/air-verse/air@latest
go install github.com/pressly/goose/v3/cmd/goose@latest

# Start database
docker compose up -d postgres redis

# Run migrations
goose -dir internal/database/migrations postgres "$DATABASE_URL" up

# Generate templ files
templ generate

# Build CSS
npx tailwindcss -i web/static/css/input.css -o web/static/dist/styles.css

# Run server
go run ./cmd/server
```

---

## Database

### Migrations

```bash
# Run migrations
task db:migrate

# Create new migration
task db:migrate:create -- add_new_table

# Rollback last migration
task db:rollback

# Check migration status
task db:status

# Reset database (destructive!)
task db:reset
```

### Access Database

```bash
# PostgreSQL shell
task db:psql

# Redis CLI
task db:redis
```

---

## API Token Scopes

When creating API tokens, you can assign these scopes:

| Scope | Permissions |
|-------|-------------|
| `projects:read` | List and view projects |
| `projects:write` | Create projects |
| `projects:delete` | Delete projects |
| `secrets:read` | List, view, and export secrets |
| `secrets:write` | Create and update secrets |
| `secrets:delete` | Delete secrets |
| `*` | Full access (all permissions) |

---

## Production Deployment

### Option 1: Docker Compose

```bash
# 1. Create production .env file
cp .env.example .env.production

# 2. Edit with production values
# - Set ENCRYPTION_KEY (generate with: openssl rand -base64 32)
# - Set strong DB_PASSWORD
# - Set ENV=production
# - Configure GitHub OAuth (optional)

# 3. Start all services
docker compose --env-file .env.production up -d

# 4. Check logs
docker compose logs -f app
```

### Option 2: Manual Deployment

```bash
# 1. Build binaries
task build:all

# 2. Copy to server
scp bin/tinyvault user@server:/opt/tinyvault/

# 3. Set up systemd service (see example below)
```

Example systemd service:
```ini
[Unit]
Description=TinyVault Secrets Manager
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=tinyvault
Group=tinyvault
WorkingDirectory=/opt/tinyvault
ExecStart=/opt/tinyvault/tinyvault
Restart=always
RestartSec=5
EnvironmentFile=/opt/tinyvault/.env

[Install]
WantedBy=multi-user.target
```

### Option 3: Kubernetes / Cloud

```bash
# Build Docker image
docker build -t tinyvault:latest .

# Tag for registry
docker tag tinyvault:latest ghcr.io/your-org/tinyvault:latest

# Push to registry
docker push ghcr.io/your-org/tinyvault:latest
```

---

## Production Checklist

### Security

- [ ] Generate unique `ENCRYPTION_KEY` (never reuse!)
- [ ] Store `ENCRYPTION_KEY` in a secrets manager
- [ ] Use strong `DB_PASSWORD`
- [ ] Set `ENV=production`
- [ ] Enable HTTPS (use Caddy or nginx)
- [ ] Configure firewall (only expose 80/443)
- [ ] Restrict `/metrics` endpoint to internal network only (see [Security Considerations](#security-considerations))
- [ ] Set up database backups

### Authentication

- [ ] Create separate GitHub OAuth App for production (optional)
- [ ] Update callback URL to production domain
- [ ] Use production Client ID and Secret

### Database

- [ ] Use managed PostgreSQL (RDS, Cloud SQL, etc.)
- [ ] Enable SSL connections (`sslmode=require`)
- [ ] Set up automated backups
- [ ] Configure connection pooling

### Monitoring

- [ ] Set up health check monitoring (`/health`, `/ready`)
- [ ] Configure log aggregation
- [ ] Set up alerting for errors

---

## Backup & Recovery

### Backup Encryption Key

**CRITICAL**: Back up your `ENCRYPTION_KEY` securely. Without it, all secrets are unrecoverable.

```bash
# Store in a secure location (password manager, HSM, etc.)
echo $ENCRYPTION_KEY > /secure/backup/tinyvault-master-key.txt
```

### Backup Database

```bash
# Dump database
pg_dump $DATABASE_URL > backup-$(date +%Y%m%d).sql

# Restore database
psql $DATABASE_URL < backup-20240115.sql
```

---

## Security Considerations

### Metrics Endpoint

The `/metrics` endpoint exposes Prometheus metrics and is intentionally unauthenticated following standard Prometheus patterns. In production deployments:

- **Network Restriction**: Configure your firewall or load balancer to restrict `/metrics` access to internal monitoring systems only
- **Kubernetes**: Use NetworkPolicies to limit access to the Prometheus namespace
- **Cloud Providers**: Use security groups to allow `/metrics` only from your monitoring infrastructure
- **Reverse Proxy**: Configure nginx/Caddy to block external access:

```nginx
location /metrics {
    allow 10.0.0.0/8;      # Internal network
    allow 192.168.0.0/16;  # Private network
    deny all;
}
```

### Key Rotation

TinyVault uses a two-tier key hierarchy:
- **Master Key (KEK)**: The `ENCRYPTION_KEY` environment variable
- **Data Encryption Keys (DEK)**: Per-project keys encrypted by the master key

#### Manual Key Rotation Procedure

**Important**: Key rotation requires careful planning. Test in a non-production environment first.

1. **Prepare New Key**
   ```bash
   # Generate new master key
   NEW_KEY=$(openssl rand -base64 32)
   echo "New key: $NEW_KEY"
   ```

2. **Export All Secrets** (while using old key)
   ```bash
   # Use the API or tvault CLI to export all secrets
   tvault export --all > secrets-backup.json
   ```

3. **Update Master Key**
   ```bash
   # Stop the application
   # Update ENCRYPTION_KEY in your environment/secrets manager
   # Restart the application
   ```

4. **Re-encrypt Secrets**
   - Delete and recreate projects (DEKs are regenerated automatically)
   - Re-import secrets from backup
   ```bash
   tvault import < secrets-backup.json
   ```

5. **Verify**
   - Test secret retrieval for all projects
   - Verify audit logs show successful operations

#### Future Enhancement

Automated key rotation with zero downtime is planned for a future release. This would include:
- Online re-encryption of DEKs
- Key versioning
- Rollback capability

---

## Troubleshooting

### "encryption key is required in production"

Set `ENCRYPTION_KEY` environment variable with a valid 32-byte base64 key, or set `ENV=development`.

### "invalid ENCRYPTION_KEY: must be 32 bytes"

Your key is the wrong length. Generate a new one:
```bash
openssl rand -base64 32
```

### "no verified email found on GitHub account"

The GitHub account must have at least one verified email. Check GitHub email settings.

### "database URL is required"

Set `DATABASE_URL` with a valid PostgreSQL connection string.

### Rate limiting errors

Check Redis connection. Rate limiting requires Redis to be running.

### GitHub login not showing

GitHub OAuth is optional. If `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are not set, the GitHub login button won't appear.

---

## Support

- GitHub Issues: https://github.com/abdul-hamid-achik/tinyvault/issues
