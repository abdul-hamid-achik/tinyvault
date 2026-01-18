-- +goose Up
-- +goose StatementBegin
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,  -- e.g., 'secret.read', 'secret.create', 'project.delete'
    resource_type VARCHAR(50) NOT NULL,  -- e.g., 'secret', 'project', 'api_token'
    resource_id UUID,
    resource_name VARCHAR(255),  -- Human-readable name for reference
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,  -- Additional context
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Partition by month for better performance (optional, can be added later)
-- CREATE INDEX idx_audit_logs_created_at_brin ON audit_logs USING BRIN (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_logs;
-- +goose StatementEnd
