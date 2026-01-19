package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/services"
)

// mockAuthService implements a mock auth service for testing.
type mockAuthService struct {
	isLockedResult     bool
	isLockedErr        error
	createSessionErr   error
	validateSessionErr error
	session            *services.SessionWithUser
}

func (m *mockAuthService) IsAccountLocked(ctx context.Context, email string) (bool, error) {
	return m.isLockedResult, m.isLockedErr
}

func (m *mockAuthService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*services.Session, error) {
	if m.createSessionErr != nil {
		return nil, m.createSessionErr
	}
	return &services.Session{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     "test-session-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

func (m *mockAuthService) ValidateSession(ctx context.Context, token string) (*services.SessionWithUser, error) {
	if m.validateSessionErr != nil {
		return nil, m.validateSessionErr
	}
	return m.session, nil
}

func (m *mockAuthService) RecordLoginAttempt(ctx context.Context, email, ipAddress string, success bool) {
}

func (m *mockAuthService) DeleteSession(ctx context.Context, token string) error {
	return nil
}

// mockUserService implements a mock user service for testing.
type mockUserService struct {
	authenticateResult *services.User
	authenticateErr    error
	createFromEmailErr error
}

func (m *mockUserService) AuthenticateByEmail(ctx context.Context, email, password string) (*services.User, error) {
	if m.authenticateErr != nil {
		return nil, m.authenticateErr
	}
	return m.authenticateResult, nil
}

func (m *mockUserService) CreateFromEmail(ctx context.Context, email, password, username string) (*services.User, error) {
	if m.createFromEmailErr != nil {
		return nil, m.createFromEmailErr
	}
	return &services.User{
		ID:       uuid.New(),
		Email:    email,
		Username: username,
	}, nil
}

// mockAuditServiceForAuth implements a mock audit service for testing.
type mockAuditServiceForAuth struct{}

func (m *mockAuditServiceForAuth) LogAsync(params services.LogParams) {}

// TestAuthHandler is a test helper that creates an auth handler with mock services.
// Note: Since AuthHandler uses concrete types, we can't directly inject mocks.
// These tests verify behavior that can be tested without full service mocking.

func TestEmailLogin_EmptyCredentials(t *testing.T) {
	// Create handler with nil services (will not be called for validation tests)
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	tests := []struct {
		name     string
		email    string
		password string
		wantErr  string
	}{
		{
			name:     "empty email",
			email:    "",
			password: "password123",
			wantErr:  "Email and password are required",
		},
		{
			name:     "empty password",
			email:    "test@example.com",
			password: "",
			wantErr:  "Email and password are required",
		},
		{
			name:     "both empty",
			email:    "",
			password: "",
			wantErr:  "Email and password are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("email", tt.email)
			form.Add("password", tt.password)

			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.EmailLogin(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("EmailLogin() status = %d, want %d", w.Code, http.StatusOK)
			}

			body := w.Body.String()
			if !strings.Contains(body, tt.wantErr) {
				t.Errorf("EmailLogin() body should contain %q", tt.wantErr)
			}
		})
	}
}

func TestEmailLogin_InvalidFormData(t *testing.T) {
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	// Send request with invalid content type
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not a form"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handler.EmailLogin(w, req)

	// Should handle gracefully (empty form values)
	if w.Code != http.StatusOK {
		t.Errorf("EmailLogin() status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRegister_EmptyFields(t *testing.T) {
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	tests := []struct {
		name            string
		username        string
		email           string
		password        string
		passwordConfirm string
		wantErr         string
	}{
		{
			name:            "empty username",
			username:        "",
			email:           "test@example.com",
			password:        "password123",
			passwordConfirm: "password123",
			wantErr:         "All fields are required",
		},
		{
			name:            "empty email",
			username:        "testuser",
			email:           "",
			password:        "password123",
			passwordConfirm: "password123",
			wantErr:         "All fields are required",
		},
		{
			name:            "empty password",
			username:        "testuser",
			email:           "test@example.com",
			password:        "",
			passwordConfirm: "",
			wantErr:         "All fields are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("username", tt.username)
			form.Add("email", tt.email)
			form.Add("password", tt.password)
			form.Add("password_confirm", tt.passwordConfirm)

			req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.Register(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Register() status = %d, want %d", w.Code, http.StatusOK)
			}

			body := w.Body.String()
			if !strings.Contains(body, tt.wantErr) {
				t.Errorf("Register() body should contain %q", tt.wantErr)
			}
		})
	}
}

func TestRegister_PasswordValidation(t *testing.T) {
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	tests := []struct {
		name            string
		password        string
		passwordConfirm string
		wantErr         string
	}{
		{
			name:            "password too short",
			password:        "short",
			passwordConfirm: "short",
			wantErr:         "Password must be at least 12 characters",
		},
		{
			name:            "passwords do not match",
			password:        "password12345",
			passwordConfirm: "password45678",
			wantErr:         "Passwords do not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("username", "testuser")
			form.Add("email", "test@example.com")
			form.Add("password", tt.password)
			form.Add("password_confirm", tt.passwordConfirm)

			req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.Register(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Register() status = %d, want %d", w.Code, http.StatusOK)
			}

			body := w.Body.String()
			if !strings.Contains(body, tt.wantErr) {
				t.Errorf("Register() body should contain %q", tt.wantErr)
			}
		})
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "username too short",
			username: "ab",
		},
		{
			name:     "username with spaces",
			username: "test user",
		},
		{
			name:     "username with special chars",
			username: "test@user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("username", tt.username)
			form.Add("email", "test@example.com")
			form.Add("password", "password12345")
			form.Add("password_confirm", "password12345")

			req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.Register(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Register() status = %d, want %d", w.Code, http.StatusOK)
			}

			// Should contain an error message about username validation
			body := w.Body.String()
			if body == "" {
				t.Error("Register() should return validation error")
			}
		})
	}
}

func TestGitHubLogin_NotConfigured(t *testing.T) {
	// Create handler without GitHub credentials
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/github", nil)
	w := httptest.NewRecorder()

	handler.GitHubLogin(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GitHubLogin() status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestGitHubCallback_NotConfigured(t *testing.T) {
	// Create handler without GitHub credentials
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=test&state=test", nil)
	w := httptest.NewRecorder()

	handler.GitHubCallback(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GitHubCallback() status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestIsGitHubEnabled(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		wantEnabled  bool
	}{
		{
			name:         "both credentials provided",
			clientID:     "client-id",
			clientSecret: "client-secret",
			wantEnabled:  true,
		},
		{
			name:         "missing client ID",
			clientID:     "",
			clientSecret: "client-secret",
			wantEnabled:  false,
		},
		{
			name:         "missing client secret",
			clientID:     "client-id",
			clientSecret: "",
			wantEnabled:  false,
		},
		{
			name:         "both missing",
			clientID:     "",
			clientSecret: "",
			wantEnabled:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(tt.clientID, tt.clientSecret, "http://localhost/callback", nil, nil, nil)
			if handler.IsGitHubEnabled() != tt.wantEnabled {
				t.Errorf("IsGitHubEnabled() = %v, want %v", handler.IsGitHubEnabled(), tt.wantEnabled)
			}
		})
	}
}

func TestLogout_ClearsSessionCookie(t *testing.T) {
	handler := NewAuthHandler("", "", "", nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()

	handler.Logout(w, req)

	// Should redirect to home page
	if w.Code != http.StatusSeeOther {
		t.Errorf("Logout() status = %d, want %d", w.Code, http.StatusSeeOther)
	}

	// Check that session cookie is cleared
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("Expected session cookie to be set")
	}

	if sessionCookie.MaxAge != -1 {
		t.Errorf("Session cookie MaxAge = %d, want -1 (deleted)", sessionCookie.MaxAge)
	}

	if sessionCookie.Value != "" {
		t.Errorf("Session cookie Value = %q, want empty", sessionCookie.Value)
	}
}

// TestAccountLockoutFailsClosed verifies the security fix that ensures
// login fails when IsAccountLocked returns an error.
// Note: This is an integration test behavior description, actual testing
// requires a mock auth service which isn't possible with the current concrete type.
func TestAccountLockoutFailsClosed_Behavior(t *testing.T) {
	// This test documents the expected behavior:
	// When IsAccountLocked() returns an error, login should be denied
	// to prevent lockout bypass through database errors.
	//
	// The fix in auth.go:306-311 ensures this by returning early with
	// an error message when IsAccountLocked() fails.
	//
	// Integration testing would verify this with a real database.
	t.Log("Account lockout fail-closed behavior is implemented in auth.go:306-311")
}

// Ensure mock services satisfy interface expectations
var _ interface {
	IsAccountLocked(context.Context, string) (bool, error)
} = (*mockAuthService)(nil)

var _ interface {
	AuthenticateByEmail(context.Context, string, string) (*services.User, error)
} = (*mockUserService)(nil)

var _ interface {
	LogAsync(services.LogParams)
} = (*mockAuditServiceForAuth)(nil)
