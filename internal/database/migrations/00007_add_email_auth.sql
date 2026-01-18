-- +goose Up
-- +goose StatementBegin

-- Make github_id nullable (was NOT NULL UNIQUE)
ALTER TABLE users ALTER COLUMN github_id DROP NOT NULL;

-- Drop the unique constraint and index on github_id
DROP INDEX IF EXISTS idx_users_github_id;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_github_id_key;

-- Create a partial unique index for github_id (only for non-null values)
CREATE UNIQUE INDEX users_github_id_unique ON users(github_id) WHERE github_id IS NOT NULL;

-- Add email auth fields
ALTER TABLE users ADD COLUMN password_hash VARCHAR(255);
ALTER TABLE users ADD COLUMN auth_provider VARCHAR(50) NOT NULL DEFAULT 'github';
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT false;

-- Create partial unique index for email (only for email auth users)
CREATE UNIQUE INDEX users_email_auth_unique ON users(email) WHERE auth_provider = 'email';

-- Update existing users to have correct provider (they came from GitHub)
UPDATE users SET auth_provider = 'github', email_verified = true WHERE github_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Remove partial indexes
DROP INDEX IF EXISTS users_email_auth_unique;
DROP INDEX IF EXISTS users_github_id_unique;

-- Remove new columns
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
ALTER TABLE users DROP COLUMN IF EXISTS auth_provider;
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;

-- Restore github_id as NOT NULL UNIQUE
-- Note: This will fail if there are email-only users
ALTER TABLE users ALTER COLUMN github_id SET NOT NULL;
CREATE UNIQUE INDEX idx_users_github_id ON users(github_id);
ALTER TABLE users ADD CONSTRAINT users_github_id_key UNIQUE (github_id);

-- +goose StatementEnd
