-- name: CountAllSecrets :one
-- Count all secrets for non-deleted projects
SELECT COUNT(*) FROM secrets s
INNER JOIN projects p ON s.project_id = p.id
WHERE p.deleted_at IS NULL;

-- name: CountAllProjects :one
-- Count all non-deleted projects
SELECT COUNT(*) FROM projects WHERE deleted_at IS NULL;

-- name: CountActiveSessions :one
-- Count all non-expired sessions
SELECT COUNT(*) FROM sessions WHERE expires_at > NOW();

-- name: CountActiveAPITokens :one
-- Count all non-revoked and non-expired API tokens
SELECT COUNT(*) FROM api_tokens
WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW());
