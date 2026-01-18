-- name: RecordLoginAttempt :exec
INSERT INTO login_attempts (email, ip_address, success)
VALUES ($1, $2, $3);

-- name: CountRecentFailedAttempts :one
SELECT COUNT(*) FROM login_attempts
WHERE email = $1
  AND success = false
  AND created_at > $2;

-- name: GetLastSuccessfulLogin :one
SELECT * FROM login_attempts
WHERE email = $1 AND success = true
ORDER BY created_at DESC
LIMIT 1;

-- name: CleanupOldLoginAttempts :exec
DELETE FROM login_attempts
WHERE created_at < $1;
