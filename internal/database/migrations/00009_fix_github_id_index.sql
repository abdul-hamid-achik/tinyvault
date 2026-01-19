-- +goose Up
DROP INDEX IF EXISTS users_github_id_unique;
CREATE UNIQUE INDEX users_github_id_unique ON users(github_id);

-- +goose Down
DROP INDEX IF EXISTS users_github_id_unique;
CREATE UNIQUE INDEX users_github_id_unique ON users(github_id) WHERE github_id IS NOT NULL;
