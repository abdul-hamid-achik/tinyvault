-- name: CreateAuditLog :one
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, resource_name, ip_address, user_agent, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetAuditLogByID :one
SELECT * FROM audit_logs WHERE id = $1;

-- name: ListAuditLogsByUser :many
SELECT * FROM audit_logs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogsByResource :many
SELECT * FROM audit_logs
WHERE resource_type = $1 AND resource_id = $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: ListAuditLogsByAction :many
SELECT * FROM audit_logs
WHERE action = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListRecentAuditLogs :many
SELECT * FROM audit_logs
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountAuditLogsByUser :one
SELECT COUNT(*) FROM audit_logs WHERE user_id = $1;

-- name: CountAuditLogsByUserSince :one
SELECT COUNT(*) FROM audit_logs WHERE user_id = $1 AND created_at > $2;

-- name: CountAuditLogsByUserActionSince :one
SELECT COUNT(*) FROM audit_logs WHERE user_id = $1 AND action = $2 AND created_at > $3;

-- name: DeleteOldAuditLogs :exec
DELETE FROM audit_logs
WHERE created_at < $1;
