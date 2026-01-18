-- name: CreateUser :one
-- Creates a user from GitHub OAuth (github_id required)
INSERT INTO users (github_id, email, username, name, avatar_url, auth_provider, email_verified)
VALUES ($1, $2, $3, $4, $5, 'github', true)
RETURNING *;

-- name: CreateUserFromEmail :one
-- Creates a user from email/password registration
INSERT INTO users (email, username, password_hash, auth_provider, email_verified)
VALUES ($1, $2, $3, 'email', false)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByGitHubID :one
SELECT * FROM users WHERE github_id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByEmailForAuth :one
-- Gets user by email for authentication (email auth provider only)
SELECT * FROM users WHERE email = $1 AND auth_provider = 'email';

-- name: UpdateUser :one
UPDATE users
SET email = $2, username = $3, name = $4, avatar_url = $5
WHERE id = $1
RETURNING *;

-- name: UpdateUserEmailVerified :exec
UPDATE users SET email_verified = true WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: UpsertUser :one
-- Upsert for GitHub users (uses github_id as conflict key)
INSERT INTO users (github_id, email, username, name, avatar_url, auth_provider, email_verified)
VALUES ($1, $2, $3, $4, $5, 'github', true)
ON CONFLICT (github_id) DO UPDATE
SET email = EXCLUDED.email,
    username = EXCLUDED.username,
    name = EXCLUDED.name,
    avatar_url = EXCLUDED.avatar_url
WHERE users.github_id IS NOT NULL
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: CheckEmailExists :one
-- Check if email exists for a given auth provider
SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND auth_provider = $2) AS exists;
