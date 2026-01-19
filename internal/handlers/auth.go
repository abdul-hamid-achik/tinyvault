package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/middleware"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
	"github.com/abdul-hamid-achik/tinyvault/internal/views/pages"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	oauth2Config  *oauth2.Config
	userService   *services.UserService
	authService   *services.AuthService
	auditService  *services.AuditService
	githubEnabled bool
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(
	clientID, clientSecret, callbackURL string,
	userService *services.UserService,
	authService *services.AuthService,
	auditService *services.AuditService,
) *AuthHandler {
	githubEnabled := clientID != "" && clientSecret != ""

	var oauth2Cfg *oauth2.Config
	if githubEnabled {
		oauth2Cfg = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		}
	}

	return &AuthHandler{
		oauth2Config:  oauth2Cfg,
		userService:   userService,
		authService:   authService,
		auditService:  auditService,
		githubEnabled: githubEnabled,
	}
}

// IsGitHubEnabled returns true if GitHub OAuth is configured.
func (h *AuthHandler) IsGitHubEnabled() bool {
	return h.githubEnabled
}

// GitHubLogin redirects to GitHub OAuth.
func (h *AuthHandler) GitHubLogin(w http.ResponseWriter, r *http.Request) {
	log := middleware.Logger(r.Context())

	if !h.githubEnabled {
		http.Error(w, "GitHub authentication is not configured", http.StatusNotFound)
		return
	}

	log.Debug("oauth_flow_started", "provider", "github")

	// Generate cryptographically secure state for CSRF protection
	state, err := crypto.GenerateTokenString(32)
	if err != nil {
		log.Error("oauth_state_generation_failed", "error", err)
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GitHubCallback handles the GitHub OAuth callback.
func (h *AuthHandler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
	log := middleware.Logger(r.Context())

	if !h.githubEnabled {
		http.Error(w, "GitHub authentication is not configured", http.StatusNotFound)
		return
	}

	// Verify state using constant-time comparison
	stateCookie, err := r.Cookie("oauth_state")
	queryState := r.URL.Query().Get("state")
	if err != nil || !crypto.CompareTokens([]byte(stateCookie.Value), []byte(queryState)) {
		log.Warn("oauth_state_mismatch", "cookie_present", err == nil)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := h.oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Error("oauth_token_exchange_failed", "error", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	log.Debug("oauth_token_exchanged", "provider", "github")

	// Get user info from GitHub
	client := h.oauth2Config.Client(r.Context(), token)
	githubUser, err := h.getGitHubUser(r.Context(), client, log)
	if err != nil {
		log.Error("github_user_fetch_failed", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	log.Debug("github_user_fetched", "github_id", githubUser.ID)

	// Create or update user
	user, err := h.userService.CreateOrUpdate(r.Context(), githubUser)
	if err != nil {
		log.Error("user_creation_failed", "github_id", githubUser.ID, "error", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Create session
	session, err := h.authService.CreateSession(r.Context(), user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		log.Error("session_creation_failed", "user_id", user.ID, "error", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionUserLogin,
		ResourceType: services.ResourceUser,
		ResourceID:   &user.ID,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		MaxAge:   int(services.SessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	log.Info("user_logged_in", "user_id", user.ID, "provider", "github")

	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Logout handles user logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		// Get user before deleting session for audit log
		if user, err := h.authService.ValidateSession(r.Context(), cookie.Value); err == nil {
			// Audit log
			h.auditService.LogAsync(services.LogParams{
				UserID:       &user.ID,
				Action:       services.ActionUserLogout,
				ResourceType: services.ResourceUser,
				ResourceID:   &user.ID,
				IPAddress:    r.RemoteAddr,
				UserAgent:    r.UserAgent(),
			})
		}
		// Delete session from database
		if err := h.authService.DeleteSession(r.Context(), cookie.Value); err != nil {
			slog.Error("failed to delete session during logout", "error", err)
		}
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getGitHubUser fetches user data from GitHub API.
func (h *AuthHandler) getGitHubUser(ctx context.Context, client *http.Client, log *slog.Logger) (*services.GitHubUser, error) {
	// Get user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.Error("github_api_error", "endpoint", "/user", "status", resp.StatusCode)
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var userData struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, err
	}

	// If email is not public, fetch from emails endpoint
	if userData.Email == "" {
		log.Debug("github_email_not_public", "github_id", userData.ID)
		userData.Email = h.fetchGitHubEmail(ctx, client)
	}

	// Require an email address
	if userData.Email == "" {
		log.Warn("github_no_verified_email", "github_id", userData.ID)
		return nil, fmt.Errorf("no verified email found on GitHub account")
	}

	return &services.GitHubUser{
		ID:        userData.ID,
		Email:     userData.Email,
		Username:  userData.Login,
		Name:      userData.Name,
		AvatarURL: userData.AvatarURL,
	}, nil
}

// fetchGitHubEmail fetches the user's primary verified email from GitHub.
func (h *AuthHandler) fetchGitHubEmail(ctx context.Context, client *http.Client) string {
	emailReq, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return ""
	}
	emailResp, err := client.Do(emailReq)
	if err != nil {
		return ""
	}
	defer func() { _ = emailResp.Body.Close() }()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
		return ""
	}

	// First try to find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	// Fall back to any verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email
		}
	}
	return ""
}

// LoginPage renders the login page.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to dashboard
	cookie, err := r.Cookie("session")
	if err == nil {
		if _, err := h.authService.ValidateSession(r.Context(), cookie.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	render(w, r, pages.Login("", h.githubEnabled))
}

// EmailLogin handles email/password login.
func (h *AuthHandler) EmailLogin(w http.ResponseWriter, r *http.Request) {
	log := middleware.Logger(r.Context())

	if err := r.ParseForm(); err != nil {
		render(w, r, pages.Login("Invalid form data", h.githubEnabled))
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	if email == "" || password == "" {
		render(w, r, pages.Login("Email and password are required", h.githubEnabled))
		return
	}

	log.Debug("login_attempt", "email", email)

	// Check if account is locked - fail closed on error
	locked, err := h.authService.IsAccountLocked(r.Context(), email)
	if err != nil {
		log.Error("lockout_check_failed", "email", email, "error", err)
		render(w, r, pages.Login("An error occurred. Please try again later.", h.githubEnabled))
		return
	}
	if locked {
		log.Warn("login_account_locked", "email", email)
		render(w, r, pages.Login("Account temporarily locked due to too many failed login attempts. Please try again later.", h.githubEnabled))
		return
	}

	// Authenticate user
	user, err := h.userService.AuthenticateByEmail(r.Context(), email, password)
	if err != nil {
		// Record failed login attempt
		h.authService.RecordLoginAttempt(r.Context(), email, r.RemoteAddr, false)

		if errors.Is(err, services.ErrInvalidCredentials) {
			log.Warn("login_invalid_credentials", "email", email)
			render(w, r, pages.Login("Invalid email or password", h.githubEnabled))
			return
		}
		log.Error("login_auth_failed", "email", email, "error", err)
		render(w, r, pages.Login("An error occurred. Please try again.", h.githubEnabled))
		return
	}

	// Record successful login attempt
	h.authService.RecordLoginAttempt(r.Context(), email, r.RemoteAddr, true)

	// Create session
	session, err := h.authService.CreateSession(r.Context(), user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		log.Error("session_creation_failed", "user_id", user.ID, "error", err)
		render(w, r, pages.Login("An error occurred. Please try again.", h.githubEnabled))
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionUserLogin,
		ResourceType: services.ResourceUser,
		ResourceID:   &user.ID,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		MaxAge:   int(services.SessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	log.Info("user_logged_in", "user_id", user.ID, "provider", "email")

	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// RegisterPage renders the registration page.
func (h *AuthHandler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to dashboard
	cookie, err := r.Cookie("session")
	if err == nil {
		if _, err := h.authService.ValidateSession(r.Context(), cookie.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	render(w, r, pages.Register("", h.githubEnabled))
}

// Register handles user registration.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	log := middleware.Logger(r.Context())

	if err := r.ParseForm(); err != nil {
		render(w, r, pages.Register("Invalid form data", h.githubEnabled))
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	// Validation
	if username == "" || email == "" || password == "" {
		render(w, r, pages.Register("All fields are required", h.githubEnabled))
		return
	}

	if err := validation.Username(username); err != nil {
		render(w, r, pages.Register(err.Error(), h.githubEnabled))
		return
	}

	if err := validation.Email(email); err != nil {
		render(w, r, pages.Register(err.Error(), h.githubEnabled))
		return
	}

	if len(password) < 12 {
		render(w, r, pages.Register("Password must be at least 12 characters", h.githubEnabled))
		return
	}

	if password != passwordConfirm {
		render(w, r, pages.Register("Passwords do not match", h.githubEnabled))
		return
	}

	log.Debug("registration_attempt", "email", email, "username", username)

	// Create user
	user, err := h.userService.CreateFromEmail(r.Context(), email, password, username)
	if err != nil {
		if errors.Is(err, services.ErrEmailExists) {
			log.Warn("registration_email_exists", "email", email)
			render(w, r, pages.Register("An account with this email already exists", h.githubEnabled))
			return
		}
		log.Error("registration_failed", "email", email, "error", err)
		render(w, r, pages.Register("An error occurred. Please try again.", h.githubEnabled))
		return
	}

	// Create session
	session, err := h.authService.CreateSession(r.Context(), user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		log.Error("session_creation_failed", "user_id", user.ID, "error", err)
		// User was created but session failed - redirect to login
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionUserCreate,
		ResourceType: services.ResourceUser,
		ResourceID:   &user.ID,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		MaxAge:   int(services.SessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	log.Info("user_registered", "user_id", user.ID, "email", email)

	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
