-- name: CreateSecret :one
INSERT INTO secrets (project_id, key, encrypted_value)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSecretByID :one
SELECT * FROM secrets WHERE id = $1;

-- name: GetSecretByKey :one
SELECT * FROM secrets
WHERE project_id = $1 AND key = $2;

-- name: ListSecretsByProject :many
SELECT id, project_id, key, version, created_at, updated_at
FROM secrets
WHERE project_id = $1
ORDER BY key ASC
LIMIT $2 OFFSET $3;

-- name: ListSecretKeysByProject :many
SELECT key FROM secrets
WHERE project_id = $1
ORDER BY key ASC;

-- name: UpdateSecret :one
UPDATE secrets
SET encrypted_value = $3
WHERE project_id = $1 AND key = $2
RETURNING *;

-- name: UpsertSecret :one
INSERT INTO secrets (project_id, key, encrypted_value)
VALUES ($1, $2, $3)
ON CONFLICT (project_id, key) DO UPDATE
SET encrypted_value = EXCLUDED.encrypted_value
RETURNING *;

-- name: DeleteSecret :exec
DELETE FROM secrets
WHERE project_id = $1 AND key = $2;

-- name: DeleteSecretByID :exec
DELETE FROM secrets WHERE id = $1;

-- name: DeleteAllSecretsByProject :exec
DELETE FROM secrets WHERE project_id = $1;

-- name: CountSecretsByProject :one
SELECT COUNT(*) FROM secrets WHERE project_id = $1;

-- name: GetSecretWithValue :one
SELECT * FROM secrets
WHERE project_id = $1 AND key = $2;
