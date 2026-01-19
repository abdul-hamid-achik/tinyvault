package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/middleware"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
	"github.com/abdul-hamid-achik/tinyvault/internal/views/pages"
)

// WebHandler handles web UI routes.
type WebHandler struct {
	projectService *services.ProjectService
	secretService  *services.SecretService
	tokenService   *services.TokenService
	auditService   *services.AuditService
	userService    *services.UserService
}

// NewWebHandler creates a new WebHandler.
func NewWebHandler(
	projectService *services.ProjectService,
	secretService *services.SecretService,
	tokenService *services.TokenService,
	auditService *services.AuditService,
	userService *services.UserService,
) *WebHandler {
	return &WebHandler{
		projectService: projectService,
		secretService:  secretService,
		tokenService:   tokenService,
		auditService:   auditService,
		userService:    userService,
	}
}

// RegisterRoutes registers web UI routes.
func (h *WebHandler) RegisterRoutes(r chi.Router, authMiddleware func(http.Handler) http.Handler) {
	// Public routes
	r.Get("/", h.Home)

	// Protected routes (require authentication)
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware)

		r.Get("/dashboard", h.Dashboard)
		r.Get("/projects", h.Projects)
		r.Get("/projects/new", h.NewProject)
		r.Post("/projects", h.CreateProject)
		r.Get("/projects/{id}", h.ProjectDetail)

		// HTMX partials for secrets
		r.Get("/projects/{id}/secrets/new", h.NewSecretModal)
		r.Get("/projects/{id}/secrets/{key}/edit", h.EditSecretModal)
		r.Get("/projects/{id}/secrets/{key}/reveal", h.RevealSecret)
		r.Put("/projects/{id}/secrets/{key}", h.UpdateSecret)
		r.Delete("/projects/{id}/secrets/{key}", h.DeleteSecret)

		// Settings
		r.Get("/settings", h.SettingsPage)
		r.Post("/settings/profile", h.UpdateProfile)
		r.Post("/settings/password", h.UpdatePassword)
		r.Get("/settings/link-github", h.LinkGitHubRedirect)
		r.Post("/settings/unlink-github", h.UnlinkGitHub)

		// Settings - API Tokens
		r.Get("/settings/tokens", h.TokensPage)
		r.Post("/settings/tokens", h.CreateToken)
		r.Delete("/settings/tokens/{id}", h.RevokeToken)
	})
}

// render is a helper to render templ components.
func render(w http.ResponseWriter, r *http.Request, component templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	component.Render(r.Context(), w)
}

// verifyProjectOwnership checks if the current user owns the project.
// Returns the project if owned, nil otherwise (also writes error response).
func (h *WebHandler) verifyProjectOwnership(w http.ResponseWriter, r *http.Request, projectID uuid.UUID) *services.Project {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	project, err := h.projectService.GetByID(r.Context(), projectID)
	if err != nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return nil
	}

	if project.OwnerID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}

	return project
}

// Home renders the landing page.
func (h *WebHandler) Home(w http.ResponseWriter, r *http.Request) {
	render(w, r, pages.Home())
}

// Dashboard renders the dashboard.
func (h *WebHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/github", http.StatusSeeOther)
		return
	}

	// Get projects for count
	projects, err := h.projectService.List(r.Context(), user.ID, 100, 0)
	if err != nil {
		slog.Error("failed to list projects for dashboard", "user_id", user.ID, "error", err)
		projects = nil // Continue with empty list
	}

	// Count total secrets across all projects
	secretCount := 0
	for _, p := range projects {
		secrets, err := h.secretService.List(r.Context(), p.ID, 1000, 0)
		if err != nil {
			slog.Error("failed to list secrets for project", "project_id", p.ID, "error", err)
			continue
		}
		secretCount += len(secrets)
	}

	// Get API call counts for last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	apiCallCount, err := h.auditService.CountByUserSince(r.Context(), user.ID, since)
	if err != nil {
		slog.Error("failed to count api calls for dashboard", "user_id", user.ID, "error", err)
		apiCallCount = 0
	}

	// Get secret reads count
	secretReads, err := h.auditService.CountByUserActionSince(r.Context(), user.ID, services.ActionSecretRead, since)
	if err != nil {
		slog.Error("failed to count secret reads for dashboard", "user_id", user.ID, "error", err)
		secretReads = 0
	}

	// Get secret writes count (create + update)
	secretCreates, err := h.auditService.CountByUserActionSince(r.Context(), user.ID, services.ActionSecretCreate, since)
	if err != nil {
		slog.Error("failed to count secret creates for dashboard", "user_id", user.ID, "error", err)
		secretCreates = 0
	}
	secretUpdates, err := h.auditService.CountByUserActionSince(r.Context(), user.ID, services.ActionSecretUpdate, since)
	if err != nil {
		slog.Error("failed to count secret updates for dashboard", "user_id", user.ID, "error", err)
		secretUpdates = 0
	}
	secretWrites := secretCreates + secretUpdates

	// Get active tokens count
	activeTokens, err := h.tokenService.ListActive(r.Context(), user.ID)
	if err != nil {
		slog.Error("failed to count active tokens for dashboard", "user_id", user.ID, "error", err)
		activeTokens = nil
	}

	// Get recent audit logs
	logs, err := h.auditService.ListByUser(r.Context(), user.ID, 10, 0)
	if err != nil {
		slog.Error("failed to list audit logs for dashboard", "user_id", user.ID, "error", err)
		logs = nil // Continue with empty list
	}
	recentLogs := make([]pages.AuditLogEntry, len(logs))
	for i, log := range logs {
		resourceName := ""
		if log.ResourceName != nil {
			resourceName = *log.ResourceName
		}
		recentLogs[i] = pages.AuditLogEntry{
			Action:       log.Action,
			ResourceName: resourceName,
			CreatedAt:    log.CreatedAt.Format("Jan 2, 15:04"),
		}
	}

	data := pages.DashboardData{
		Username:     user.Username,
		ProjectCount: len(projects),
		SecretCount:  secretCount,
		APICallCount: apiCallCount,
		SecretReads:  secretReads,
		SecretWrites: secretWrites,
		ActiveTokens: len(activeTokens),
		RecentLogs:   recentLogs,
	}

	render(w, r, pages.Dashboard(data))
}

// Projects renders the projects list.
func (h *WebHandler) Projects(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/github", http.StatusSeeOther)
		return
	}

	projects, err := h.projectService.List(r.Context(), user.ID, 100, 0)
	if err != nil {
		http.Error(w, "Failed to load projects", http.StatusInternalServerError)
		return
	}

	projectInfos := make([]pages.ProjectInfo, len(projects))
	for i, p := range projects {
		secretCount := 0
		secrets, err := h.secretService.List(r.Context(), p.ID, 1000, 0)
		if err != nil {
			slog.Error("failed to list secrets for project", "project_id", p.ID, "error", err)
		} else {
			secretCount = len(secrets)
		}
		desc := ""
		if p.Description != nil {
			desc = *p.Description
		}
		projectInfos[i] = pages.ProjectInfo{
			ID:          p.ID.String(),
			Name:        p.Name,
			Description: desc,
			SecretCount: secretCount,
			CreatedAt:   p.CreatedAt.Format("Jan 2, 2006"),
		}
	}

	render(w, r, pages.Projects(projectInfos))
}

// NewProject renders the new project form.
func (h *WebHandler) NewProject(w http.ResponseWriter, r *http.Request) {
	render(w, r, pages.NewProject())
}

// CreateProject handles project creation.
func (h *WebHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/github", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")

	project, err := h.projectService.Create(r.Context(), user.ID, name, description)
	if err != nil {
		http.Error(w, "Failed to create project", http.StatusInternalServerError)
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionProjectCreate,
		ResourceType: services.ResourceProject,
		ResourceID:   &project.ID,
		ResourceName: project.Name,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

// ProjectDetail renders the project detail page.
func (h *WebHandler) ProjectDetail(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/github", http.StatusSeeOther)
		return
	}

	projectIDStr := chi.URLParam(r, "id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	project, err := h.projectService.GetByID(r.Context(), projectID)
	if err != nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	// Verify ownership
	if project.OwnerID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	secrets, err := h.secretService.List(r.Context(), project.ID, 1000, 0)
	if err != nil {
		http.Error(w, "Failed to load secrets", http.StatusInternalServerError)
		return
	}

	secretInfos := make([]pages.SecretInfo, len(secrets))
	for i, s := range secrets {
		secretInfos[i] = pages.SecretInfo{
			Key:       s.Key,
			Version:   s.Version,
			UpdatedAt: s.UpdatedAt.Format("Jan 2, 15:04"),
		}
	}

	desc := ""
	if project.Description != nil {
		desc = *project.Description
	}

	data := pages.ProjectDetailData{
		ID:          project.ID.String(),
		Name:        project.Name,
		Description: desc,
		Secrets:     secretInfos,
	}

	render(w, r, pages.ProjectDetail(data))
}

// NewSecretModal renders the new secret modal.
func (h *WebHandler) NewSecretModal(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	if h.verifyProjectOwnership(w, r, projectID) == nil {
		return
	}

	render(w, r, pages.SecretModal(projectIDStr, "", "", false))
}

// EditSecretModal renders the edit secret modal.
func (h *WebHandler) EditSecretModal(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	if h.verifyProjectOwnership(w, r, projectID) == nil {
		return
	}

	key := chi.URLParam(r, "key")

	secret, err := h.secretService.Get(r.Context(), projectID, key)
	if err != nil {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	render(w, r, pages.SecretModal(projectIDStr, key, string(secret.Value), true))
}

// RevealSecret returns the secret value.
func (h *WebHandler) RevealSecret(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	if h.verifyProjectOwnership(w, r, projectID) == nil {
		return
	}

	key := chi.URLParam(r, "key")

	secret, err := h.secretService.Get(r.Context(), projectID, key)
	if err != nil {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	// Audit log
	user := middleware.GetUser(r.Context())
	if user != nil {
		h.auditService.LogAsync(services.LogParams{
			UserID:       &user.ID,
			Action:       services.ActionSecretRead,
			ResourceType: services.ResourceSecret,
			ResourceID:   &secret.ID,
			ResourceName: key,
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	render(w, r, pages.RevealedSecret(projectIDStr, key, string(secret.Value)))
}

// UpdateSecret creates or updates a secret.
func (h *WebHandler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	if h.verifyProjectOwnership(w, r, projectID) == nil {
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	key := r.FormValue("key")
	value := r.FormValue("value")

	secret, err := h.secretService.Upsert(r.Context(), projectID, key, []byte(value))
	if err != nil {
		http.Error(w, "Failed to save secret", http.StatusInternalServerError)
		return
	}

	// Audit log
	user := middleware.GetUser(r.Context())
	if user != nil {
		action := services.ActionSecretCreate
		if secret.Version > 1 {
			action = services.ActionSecretUpdate
		}
		h.auditService.LogAsync(services.LogParams{
			UserID:       &user.ID,
			Action:       action,
			ResourceType: services.ResourceSecret,
			ResourceID:   &secret.ID,
			ResourceName: key,
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	// Return empty to close modal and trigger refresh
	w.Header().Set("HX-Redirect", "/projects/"+projectIDStr)
	w.WriteHeader(http.StatusOK)
}

// DeleteSecret deletes a secret.
func (h *WebHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	if h.verifyProjectOwnership(w, r, projectID) == nil {
		return
	}

	key := chi.URLParam(r, "key")

	if err := h.secretService.Delete(r.Context(), projectID, key); err != nil {
		http.Error(w, "Failed to delete secret", http.StatusInternalServerError)
		return
	}

	// Audit log
	user := middleware.GetUser(r.Context())
	if user != nil {
		h.auditService.LogAsync(services.LogParams{
			UserID:       &user.ID,
			Action:       services.ActionSecretDelete,
			ResourceType: services.ResourceSecret,
			ResourceName: key,
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	// Return empty response to remove the row
	w.WriteHeader(http.StatusOK)
}

// TokensPage renders the API tokens settings page.
func (h *WebHandler) TokensPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/github", http.StatusSeeOther)
		return
	}

	tokens, err := h.tokenService.ListActive(r.Context(), user.ID)
	if err != nil {
		slog.Error("failed to list tokens", "user_id", user.ID, "error", err)
		http.Error(w, "Failed to load tokens", http.StatusInternalServerError)
		return
	}

	tokenInfos := make([]pages.TokenInfo, len(tokens))
	for i, t := range tokens {
		lastUsed := "Never"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format("Jan 2, 15:04")
		}
		expires := "Never"
		if t.ExpiresAt != nil {
			expires = t.ExpiresAt.Format("Jan 2, 2006")
		}
		tokenInfos[i] = pages.TokenInfo{
			ID:        t.ID.String(),
			Name:      t.Name,
			Scopes:    t.Scopes,
			LastUsed:  lastUsed,
			ExpiresAt: expires,
			CreatedAt: t.CreatedAt.Format("Jan 2, 2006"),
		}
	}

	data := pages.TokensPageData{
		Tokens:   tokenInfos,
		NewToken: "",
	}

	render(w, r, pages.TokensPage(data))
}

// CreateToken handles API token creation.
func (h *WebHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/github", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "Token name is required", http.StatusBadRequest)
		return
	}

	// Collect selected scopes
	scopes := r.Form["scopes"]
	if len(scopes) == 0 {
		http.Error(w, "At least one scope is required", http.StatusBadRequest)
		return
	}

	// Parse expiration
	var expiresAt *time.Time
	expiresIn := r.FormValue("expires_in")
	if expiresIn != "" && expiresIn != "never" {
		days, err := strconv.Atoi(expiresIn)
		if err == nil && days > 0 {
			t := time.Now().AddDate(0, 0, days)
			expiresAt = &t
		}
	}

	token, err := h.tokenService.Create(r.Context(), user.ID, name, scopes, expiresAt)
	if err != nil {
		slog.Error("failed to create token", "user_id", user.ID, "error", err)
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionTokenCreate,
		ResourceType: services.ResourceToken,
		ResourceID:   &token.ID,
		ResourceName: name,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Re-fetch tokens to show updated list
	tokens, err := h.tokenService.ListActive(r.Context(), user.ID)
	if err != nil {
		slog.Error("failed to list tokens after creation", "user_id", user.ID, "error", err)
		http.Error(w, "Failed to load tokens", http.StatusInternalServerError)
		return
	}

	tokenInfos := make([]pages.TokenInfo, len(tokens))
	for i, t := range tokens {
		lastUsed := "Never"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format("Jan 2, 15:04")
		}
		expires := "Never"
		if t.ExpiresAt != nil {
			expires = t.ExpiresAt.Format("Jan 2, 2006")
		}
		tokenInfos[i] = pages.TokenInfo{
			ID:        t.ID.String(),
			Name:      t.Name,
			Scopes:    t.Scopes,
			LastUsed:  lastUsed,
			ExpiresAt: expires,
			CreatedAt: t.CreatedAt.Format("Jan 2, 2006"),
		}
	}

	data := pages.TokensPageData{
		Tokens:   tokenInfos,
		NewToken: token.Token, // Show the token once
	}

	render(w, r, pages.TokensPage(data))
}

// RevokeToken handles API token revocation.
func (h *WebHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenIDStr := chi.URLParam(r, "id")
	tokenID, err := uuid.Parse(tokenIDStr)
	if err != nil {
		http.Error(w, "Invalid token ID", http.StatusBadRequest)
		return
	}

	if err := h.tokenService.Revoke(r.Context(), tokenID, user.ID); err != nil {
		slog.Error("failed to revoke token", "token_id", tokenID, "user_id", user.ID, "error", err)
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionTokenRevoke,
		ResourceType: services.ResourceToken,
		ResourceID:   &tokenID,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Return empty response to remove the row (HTMX)
	w.WriteHeader(http.StatusOK)
}

// SettingsPage renders the settings page.
func (h *WebHandler) SettingsPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	// Get the active tab
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "profile"
	}

	// Get message from query params (for redirects with messages)
	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")

	// Get the user's GitHub login if linked
	githubLogin := ""
	if user.GitHubID != nil {
		githubLogin = user.Username // For now, use the username
	}

	data := pages.SettingsData{
		Username:    user.Username,
		Email:       user.Email,
		HasPassword: h.userService.HasPassword(user),
		HasGitHub:   h.userService.HasGitHub(user),
		GitHubLogin: githubLogin,
		ActiveTab:   tab,
		Message:     message,
		MessageType: messageType,
		CSRFToken:   middleware.GetCSRFToken(r),
	}

	render(w, r, pages.Settings(data))
}

// UpdateProfile handles profile updates.
func (h *WebHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?tab=profile&message=Invalid+form+data&type=error", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))

	// Validate
	if err := validation.Username(username); err != nil {
		http.Redirect(w, r, "/settings?tab=profile&message="+url.QueryEscape(err.Error())+"&type=error", http.StatusSeeOther)
		return
	}

	if err := validation.Email(email); err != nil {
		http.Redirect(w, r, "/settings?tab=profile&message="+url.QueryEscape(err.Error())+"&type=error", http.StatusSeeOther)
		return
	}

	// Update profile
	if _, err := h.userService.UpdateProfile(r.Context(), user.ID, email, username); err != nil {
		slog.Error("failed to update profile", "user_id", user.ID, "error", err)
		if errors.Is(err, services.ErrEmailExists) {
			http.Redirect(w, r, "/settings?tab=profile&message=Email+is+already+in+use+by+another+account&type=error", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/settings?tab=profile&message=Failed+to+update+profile&type=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/settings?tab=profile&message=Profile+updated+successfully&type=success", http.StatusSeeOther)
}

// UpdatePassword handles password changes.
func (h *WebHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?tab=security&message=Invalid+form+data&type=error", http.StatusSeeOther)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate new password
	if len(newPassword) < 12 {
		http.Redirect(w, r, "/settings?tab=security&message=Password+must+be+at+least+12+characters&type=error", http.StatusSeeOther)
		return
	}

	if newPassword != confirmPassword {
		http.Redirect(w, r, "/settings?tab=security&message=Passwords+do+not+match&type=error", http.StatusSeeOther)
		return
	}

	// Update password
	if err := h.userService.UpdatePassword(r.Context(), user.ID, currentPassword, newPassword); err != nil {
		slog.Error("failed to update password", "user_id", user.ID, "error", err)
		if errors.Is(err, services.ErrInvalidCredentials) {
			http.Redirect(w, r, "/settings?tab=security&message=Current+password+is+incorrect&type=error", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/settings?tab=security&message=Failed+to+update+password&type=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/settings?tab=security&message=Password+updated+successfully&type=success", http.StatusSeeOther)
}

// LinkGitHubRedirect redirects to GitHub OAuth for account linking.
func (h *WebHandler) LinkGitHubRedirect(w http.ResponseWriter, r *http.Request) {
	// This will be handled by the AuthHandler with special state
	// Redirect to the GitHub OAuth flow with a "link" indicator
	http.Redirect(w, r, "/auth/github?link=true", http.StatusSeeOther)
}

// UnlinkGitHub removes GitHub account from user.
func (h *WebHandler) UnlinkGitHub(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	// Check if user can unlink (has password)
	if !h.userService.CanUnlinkGitHub(user) {
		http.Redirect(w, r, "/settings?tab=connected&message=Cannot+unlink+GitHub+without+a+password&type=error", http.StatusSeeOther)
		return
	}

	// Unlink GitHub
	if err := h.userService.UnlinkGitHub(r.Context(), user.ID); err != nil {
		slog.Error("failed to unlink github", "user_id", user.ID, "error", err)
		http.Redirect(w, r, "/settings?tab=connected&message=Failed+to+unlink+GitHub&type=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/settings?tab=connected&message=GitHub+account+unlinked+successfully&type=success", http.StatusSeeOther)
}
