-- name: CreateProject :one
INSERT INTO projects (owner_id, name, description, encrypted_dek)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetProjectByID :one
SELECT * FROM projects
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetProjectByIDWithOwner :one
SELECT * FROM projects
WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL;

-- name: GetProjectByName :one
SELECT * FROM projects
WHERE owner_id = $1 AND name = $2 AND deleted_at IS NULL;

-- name: ListProjectsByOwner :many
SELECT * FROM projects
WHERE owner_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateProject :one
UPDATE projects
SET name = $2, description = $3
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: UpdateProjectDEK :exec
UPDATE projects
SET encrypted_dek = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: SoftDeleteProject :exec
UPDATE projects
SET deleted_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- name: HardDeleteProject :exec
DELETE FROM projects WHERE id = $1;

-- name: CountProjectsByOwner :one
SELECT COUNT(*) FROM projects
WHERE owner_id = $1 AND deleted_at IS NULL;

-- name: GetProjectDEK :one
SELECT encrypted_dek FROM projects
WHERE id = $1 AND deleted_at IS NULL;
