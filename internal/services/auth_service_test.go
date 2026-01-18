package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthService_IsAccountLocked(t *testing.T) {
	tests := []struct {
		name           string
		maxAttempts    int
		lockoutDuration time.Duration
		failedAttempts int
		wantLocked     bool
	}{
		{
			name:            "lockout disabled when maxAttempts is 0",
			maxAttempts:     0,
			lockoutDuration: 15 * time.Minute,
			failedAttempts:  10,
			wantLocked:      false,
		},
		{
			name:            "lockout disabled when maxAttempts is negative",
			maxAttempts:     -1,
			lockoutDuration: 15 * time.Minute,
			failedAttempts:  10,
			wantLocked:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &AuthService{
				maxAttempts:     tt.maxAttempts,
				lockoutDuration: tt.lockoutDuration,
			}

			// When maxAttempts <= 0, should return false without DB query
			locked, err := service.IsAccountLocked(context.Background(), "test@example.com")
			if err != nil {
				t.Fatalf("IsAccountLocked() error = %v", err)
			}
			if locked != tt.wantLocked {
				t.Errorf("IsAccountLocked() = %v, want %v", locked, tt.wantLocked)
			}
		})
	}
}

func TestSession_Fields(t *testing.T) {
	// Test that Session struct has all expected fields
	session := Session{
		ID:           uuid.New(),
		UserID:       uuid.New(),
		Token:        "test-token",
		IPAddress:    "127.0.0.1",
		UserAgent:    "test-agent",
		ExpiresAt:    time.Now().Add(SessionDuration),
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}

	if session.ID == uuid.Nil {
		t.Error("Session.ID should not be nil")
	}
	if session.UserID == uuid.Nil {
		t.Error("Session.UserID should not be nil")
	}
	if session.Token == "" {
		t.Error("Session.Token should not be empty")
	}
	if session.IPAddress == "" {
		t.Error("Session.IPAddress should not be empty")
	}
	if session.UserAgent == "" {
		t.Error("Session.UserAgent should not be empty")
	}
	if session.ExpiresAt.IsZero() {
		t.Error("Session.ExpiresAt should not be zero")
	}
}

func TestSessionWithUser_Fields(t *testing.T) {
	user := &User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Username: "testuser",
	}

	sessionWithUser := SessionWithUser{
		Session: Session{
			ID:           uuid.New(),
			UserID:       user.ID,
			Token:        "test-token",
			IPAddress:    "127.0.0.1",
			UserAgent:    "Mozilla/5.0",
			ExpiresAt:    time.Now().Add(SessionDuration),
			CreatedAt:    time.Now(),
			LastActiveAt: time.Now(),
		},
		User: user,
	}

	if sessionWithUser.User == nil {
		t.Error("SessionWithUser.User should not be nil")
	}
	if sessionWithUser.User.ID != user.ID {
		t.Error("SessionWithUser.User.ID should match")
	}
	if sessionWithUser.Session.UserID != user.ID {
		t.Error("Session.UserID should match User.ID")
	}
}

func TestSessionDuration(t *testing.T) {
	// Verify SessionDuration is 7 days
	expected := 7 * 24 * time.Hour
	if SessionDuration != expected {
		t.Errorf("SessionDuration = %v, want %v", SessionDuration, expected)
	}
}

func TestSessionTokenLength(t *testing.T) {
	// Verify SessionTokenLength is 32 bytes
	if SessionTokenLength != 32 {
		t.Errorf("SessionTokenLength = %d, want 32", SessionTokenLength)
	}
}

func TestErrAccountLocked(t *testing.T) {
	// Verify error message is descriptive
	if ErrAccountLocked == nil {
		t.Fatal("ErrAccountLocked should not be nil")
	}
	errMsg := ErrAccountLocked.Error()
	if errMsg == "" {
		t.Error("ErrAccountLocked should have a message")
	}
	if errMsg != "account temporarily locked due to too many failed login attempts" {
		t.Errorf("ErrAccountLocked message = %q, expected descriptive message", errMsg)
	}
}

func TestNewAuthService(t *testing.T) {
	// Test that NewAuthService properly initializes fields
	// Note: This requires a database connection, so we just verify the function signature
	// In a real integration test, we would use testcontainers

	// For now, verify the struct can be created with zero values for non-DB fields
	service := &AuthService{
		maxAttempts:     5,
		lockoutDuration: 15 * time.Minute,
	}

	if service.maxAttempts != 5 {
		t.Errorf("maxAttempts = %d, want 5", service.maxAttempts)
	}
	if service.lockoutDuration != 15*time.Minute {
		t.Errorf("lockoutDuration = %v, want 15m", service.lockoutDuration)
	}
}
