package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdul-hamid-achik/tinyvault/internal/database/db"
)

// AuditAction defines the types of actions that can be audited.
type AuditAction string

const (
	ActionSecretRead     AuditAction = "secret.read"
	ActionSecretCreate   AuditAction = "secret.create"
	ActionSecretUpdate   AuditAction = "secret.update"
	ActionSecretDelete   AuditAction = "secret.delete"
	ActionProjectCreate  AuditAction = "project.create"
	ActionProjectUpdate  AuditAction = "project.update"
	ActionProjectDelete  AuditAction = "project.delete"
	ActionTokenCreate    AuditAction = "token.create"
	ActionTokenRevoke    AuditAction = "token.revoke"
	ActionUserLogin      AuditAction = "user.login"
	ActionUserLogout     AuditAction = "user.logout"
	ActionUserCreate     AuditAction = "user.create"
	ActionProfileUpdate  AuditAction = "user.profile_update"
	ActionPasswordChange AuditAction = "user.password_change"
	ActionGitHubUnlink   AuditAction = "user.github_unlink"
	ActionSessionRevoke  AuditAction = "session.revoke"
)

// AuditResourceType defines the types of resources that can be audited.
type AuditResourceType string

const (
	ResourceSecret  AuditResourceType = "secret"
	ResourceProject AuditResourceType = "project"
	ResourceToken   AuditResourceType = "api_token"
	ResourceUser    AuditResourceType = "user"
	ResourceSession AuditResourceType = "session"
)

// AuditService handles audit logging.
type AuditService struct {
	queries *db.Queries
	pool    *pgxpool.Pool
}

// NewAuditService creates a new AuditService.
func NewAuditService(pool *pgxpool.Pool) *AuditService {
	return &AuditService{
		queries: db.New(pool),
		pool:    pool,
	}
}

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID           uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	ResourceName *string
	IPAddress    string
	UserAgent    string
	Metadata     map[string]any
	CreatedAt    time.Time
}

// LogParams contains parameters for creating an audit log.
type LogParams struct {
	UserID       *uuid.UUID
	Action       AuditAction
	ResourceType AuditResourceType
	ResourceID   *uuid.UUID
	ResourceName string
	IPAddress    string
	UserAgent    string
	Metadata     map[string]any
}

// Log creates a new audit log entry.
func (s *AuditService) Log(ctx context.Context, params LogParams) error {
	var ip *netip.Addr
	if params.IPAddress != "" {
		parsed, err := netip.ParseAddr(params.IPAddress)
		if err == nil {
			ip = &parsed
		}
	}

	var ua *string
	if params.UserAgent != "" {
		ua = &params.UserAgent
	}

	var resName *string
	if params.ResourceName != "" {
		resName = &params.ResourceName
	}

	var metadata []byte
	if params.Metadata != nil {
		var err error
		metadata, err = json.Marshal(params.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	// Convert *uuid.UUID to pgtype.UUID
	var userID pgtype.UUID
	if params.UserID != nil {
		userID = pgtype.UUID{Bytes: *params.UserID, Valid: true}
	}

	var resourceID pgtype.UUID
	if params.ResourceID != nil {
		resourceID = pgtype.UUID{Bytes: *params.ResourceID, Valid: true}
	}

	_, err := s.queries.CreateAuditLog(ctx, db.CreateAuditLogParams{
		UserID:       userID,
		Action:       string(params.Action),
		ResourceType: string(params.ResourceType),
		ResourceID:   resourceID,
		ResourceName: resName,
		IpAddress:    ip,
		UserAgent:    ua,
		Metadata:     metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// LogAsync creates an audit log entry asynchronously.
func (s *AuditService) LogAsync(params LogParams) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Log(ctx, params); err != nil {
			slog.Error("failed to create audit log", "action", params.Action, "error", err)
		}
	}()
}

// ListByUser retrieves audit logs for a user.
func (s *AuditService) ListByUser(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]*AuditLog, error) {
	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}
	dbLogs, err := s.queries.ListAuditLogsByUser(ctx, db.ListAuditLogsByUserParams{
		UserID: pgUserID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	logs := make([]*AuditLog, len(dbLogs))
	for i, log := range dbLogs {
		ipStr := ""
		if log.IpAddress != nil {
			ipStr = log.IpAddress.String()
		}

		uaStr := ""
		if log.UserAgent != nil {
			uaStr = *log.UserAgent
		}

		var metadata map[string]any
		if log.Metadata != nil {
			_ = json.Unmarshal(log.Metadata, &metadata)
		}

		var uid *uuid.UUID
		if log.UserID.Valid {
			id := uuid.UUID(log.UserID.Bytes)
			uid = &id
		}

		var rid *uuid.UUID
		if log.ResourceID.Valid {
			id := uuid.UUID(log.ResourceID.Bytes)
			rid = &id
		}

		logs[i] = &AuditLog{
			ID:           log.ID,
			UserID:       uid,
			Action:       log.Action,
			ResourceType: log.ResourceType,
			ResourceID:   rid,
			ResourceName: log.ResourceName,
			IPAddress:    ipStr,
			UserAgent:    uaStr,
			Metadata:     metadata,
			CreatedAt:    log.CreatedAt,
		}
	}

	return logs, nil
}

// ListByResource retrieves audit logs for a specific resource.
func (s *AuditService) ListByResource(ctx context.Context, resourceType AuditResourceType, resourceID uuid.UUID, limit, offset int32) ([]*AuditLog, error) {
	pgResourceID := pgtype.UUID{Bytes: resourceID, Valid: true}
	dbLogs, err := s.queries.ListAuditLogsByResource(ctx, db.ListAuditLogsByResourceParams{
		ResourceType: string(resourceType),
		ResourceID:   pgResourceID,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	logs := make([]*AuditLog, len(dbLogs))
	for i, log := range dbLogs {
		ipStr := ""
		if log.IpAddress != nil {
			ipStr = log.IpAddress.String()
		}

		uaStr := ""
		if log.UserAgent != nil {
			uaStr = *log.UserAgent
		}

		var metadata map[string]any
		if log.Metadata != nil {
			_ = json.Unmarshal(log.Metadata, &metadata)
		}

		var uid *uuid.UUID
		if log.UserID.Valid {
			id := uuid.UUID(log.UserID.Bytes)
			uid = &id
		}

		var rid *uuid.UUID
		if log.ResourceID.Valid {
			id := uuid.UUID(log.ResourceID.Bytes)
			rid = &id
		}

		logs[i] = &AuditLog{
			ID:           log.ID,
			UserID:       uid,
			Action:       log.Action,
			ResourceType: log.ResourceType,
			ResourceID:   rid,
			ResourceName: log.ResourceName,
			IPAddress:    ipStr,
			UserAgent:    uaStr,
			Metadata:     metadata,
			CreatedAt:    log.CreatedAt,
		}
	}

	return logs, nil
}

// Cleanup removes audit logs older than the specified duration.
func (s *AuditService) Cleanup(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	if err := s.queries.DeleteOldAuditLogs(ctx, cutoff); err != nil {
		return fmt.Errorf("failed to cleanup audit logs: %w", err)
	}
	return nil
}

// CountByUserSince counts audit logs for a user since a given time.
func (s *AuditService) CountByUserSince(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}
	count, err := s.queries.CountAuditLogsByUserSince(ctx, db.CountAuditLogsByUserSinceParams{
		UserID:    pgUserID,
		CreatedAt: since,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	return count, nil
}

// CountByUserActionSince counts audit logs for a user and specific action since a given time.
func (s *AuditService) CountByUserActionSince(ctx context.Context, userID uuid.UUID, action AuditAction, since time.Time) (int64, error) {
	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}
	count, err := s.queries.CountAuditLogsByUserActionSince(ctx, db.CountAuditLogsByUserActionSinceParams{
		UserID:    pgUserID,
		Action:    string(action),
		CreatedAt: since,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	return count, nil
}
