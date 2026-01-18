-- name: CreateSession :one
INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = $1;

-- name: GetSessionByHash :one
SELECT * FROM sessions
WHERE token_hash = $1 AND expires_at > NOW();

-- name: GetSessionWithUser :one
SELECT
    s.*,
    u.id AS user_id,
    u.github_id,
    u.email,
    u.username,
    u.name,
    u.avatar_url
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.token_hash = $1 AND s.expires_at > NOW();

-- name: ListSessionsByUser :many
SELECT * FROM sessions
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListActiveSessionsByUser :many
SELECT * FROM sessions
WHERE user_id = $1 AND expires_at > NOW()
ORDER BY last_active_at DESC;

-- name: UpdateSessionActivity :exec
UPDATE sessions
SET last_active_at = NOW()
WHERE id = $1;

-- name: ExtendSession :exec
UPDATE sessions
SET expires_at = $2, last_active_at = NOW()
WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteSessionByHash :exec
DELETE FROM sessions WHERE token_hash = $1;

-- name: DeleteAllSessionsByUser :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < NOW();

-- name: CountActiveSessionsByUser :one
SELECT COUNT(*) FROM sessions
WHERE user_id = $1 AND expires_at > NOW();
