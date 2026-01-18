-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAPITokenByID :one
SELECT * FROM api_tokens WHERE id = $1;

-- name: GetAPITokenByHash :one
SELECT * FROM api_tokens
WHERE token_hash = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW());

-- name: GetAPITokenWithUser :one
SELECT
    t.*,
    u.id AS user_id,
    u.github_id,
    u.email,
    u.username,
    u.name,
    u.avatar_url
FROM api_tokens t
JOIN users u ON t.user_id = u.id
WHERE t.token_hash = $1
  AND t.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > NOW());

-- name: ListAPITokensByUser :many
SELECT * FROM api_tokens
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListActiveAPITokensByUser :many
SELECT * FROM api_tokens
WHERE user_id = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC;

-- name: UpdateAPITokenLastUsed :exec
UPDATE api_tokens
SET last_used_at = NOW()
WHERE id = $1;

-- name: RevokeAPIToken :exec
UPDATE api_tokens
SET revoked_at = NOW()
WHERE id = $1 AND user_id = $2;

-- name: RevokeAllAPITokensByUser :exec
UPDATE api_tokens
SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteAPIToken :exec
DELETE FROM api_tokens WHERE id = $1;

-- name: CountActiveAPITokensByUser :one
SELECT COUNT(*) FROM api_tokens
WHERE user_id = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW());
