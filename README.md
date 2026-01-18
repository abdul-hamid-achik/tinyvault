# TinyVault

Dead-simple secrets management for your applications.

[![CI](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml/badge.svg)](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/abdul-hamid-achik/tinyvault)](https://goreportcard.com/report/github.com/abdul-hamid-achik/tinyvault)

## Features

- **AES-256 Encryption** - Envelope encryption with per-project data encryption keys
- **Web Dashboard** - Clean UI for managing projects and secrets
- **CLI Tool** - `tvault` command for terminal workflows and CI/CD
- **Multiple Auth Methods** - Email/password and GitHub OAuth
- **Scope-based API Tokens** - Fine-grained access control (read/write/delete per resource)
- **Audit Logging** - Track who accessed what and when

## Quick Start

```bash
# Start with Docker Compose
docker compose up -d

# Visit http://localhost:8080 and register
```

Or for local development:

```bash
# Install task runner (https://taskfile.dev)
# Then run:
task setup
task dev
```

## CLI Usage

```bash
# Install CLI
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest

# Login and select a project
tvault login
tvault use my-project

# Manage secrets
tvault set DATABASE_URL "postgres://..."
tvault get DATABASE_URL
tvault list

# Run commands with secrets injected
tvault run -- npm start

# Export as environment variables
eval $(tvault env)
```

## API

Create an API token in the web dashboard, then:

```bash
# List projects
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/projects

# Get a secret
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/projects/{id}/secrets/{key}

# Set a secret
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -d '{"value": "secret-value"}' \
  http://localhost:8080/api/v1/projects/{id}/secrets/{key}
```

## Documentation

See [GUIDE.md](GUIDE.md) for:
- Detailed setup instructions
- Environment configuration
- Production deployment
- Database management
- Troubleshooting

## Security

- Secrets encrypted with AES-256-GCM
- Passwords hashed with Argon2id
- Session tokens use secure random generation
- CSRF protection on all forms
- Rate limiting on API endpoints

## Tech Stack

- **Backend**: Go, Chi, PostgreSQL, Redis
- **Frontend**: Templ, Tailwind CSS, HTMX
- **Auth**: Argon2id, GitHub OAuth
- **Deployment**: Docker, systemd

## License

MIT
