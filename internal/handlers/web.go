package handlers

import (
	"log/slog"
	"net/http"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/middleware"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
	"github.com/abdul-hamid-achik/tinyvault/internal/views/pages"
)

// WebHandler handles web UI routes.
type WebHandler struct {
	projectService *services.ProjectService
	secretService  *services.SecretService
	auditService   *services.AuditService
}

// NewWebHandler creates a new WebHandler.
func NewWebHandler(
	projectService *services.ProjectService,
	secretService *services.SecretService,
	auditService *services.AuditService,
) *WebHandler {
	return &WebHandler{
		projectService: projectService,
		secretService:  secretService,
		auditService:   auditService,
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
