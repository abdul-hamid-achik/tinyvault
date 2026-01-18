-- +goose Up
-- +goose StatementBegin
CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key VARCHAR(255) NOT NULL,
    encrypted_value BYTEA NOT NULL,  -- Encrypted with project's DEK
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_secret_key_per_project UNIQUE (project_id, key)
);

CREATE INDEX idx_secrets_project_id ON secrets(project_id);
CREATE INDEX idx_secrets_project_key ON secrets(project_id, key);

CREATE TRIGGER update_secrets_updated_at
    BEFORE UPDATE ON secrets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to auto-increment version on update
CREATE OR REPLACE FUNCTION increment_secret_version()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.encrypted_value IS DISTINCT FROM NEW.encrypted_value THEN
        NEW.version = OLD.version + 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER increment_secrets_version
    BEFORE UPDATE ON secrets
    FOR EACH ROW
    EXECUTE FUNCTION increment_secret_version();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS increment_secrets_version ON secrets;
DROP FUNCTION IF EXISTS increment_secret_version();
DROP TRIGGER IF EXISTS update_secrets_updated_at ON secrets;
DROP TABLE IF EXISTS secrets;
-- +goose StatementEnd
