package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/logging"
	"github.com/abdul-hamid-achik/tinyvault/internal/middleware"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
)

// APIHandler handles REST API endpoints.
type APIHandler struct {
	projectService     *services.ProjectService
	secretService      *services.SecretService
	tokenService       *services.TokenService
	auditService       *services.AuditService
	maxRequestBodySize int64
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(
	projectService *services.ProjectService,
	secretService *services.SecretService,
	tokenService *services.TokenService,
	auditService *services.AuditService,
	maxRequestBodySize int64,
) *APIHandler {
	return &APIHandler{
		projectService:     projectService,
		secretService:      secretService,
		tokenService:       tokenService,
		auditService:       auditService,
		maxRequestBodySize: maxRequestBodySize,
	}
}

// Response helpers

type apiResponse struct {
	Data any            `json:"data,omitempty"`
	Meta map[string]any `json:"meta,omitempty"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Meta map[string]any `json:"meta,omitempty"`
}

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiResponse{Data: data})
}

func jsonError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := apiError{}
	resp.Error.Code = code
	resp.Error.Message = message
	json.NewEncoder(w).Encode(resp)
}

// Projects

// ListProjects handles GET /api/v1/projects
func (h *APIHandler) ListProjects(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projects, err := h.projectService.List(r.Context(), user.ID, 100, 0)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list projects")
		return
	}

	jsonResponse(w, http.StatusOK, projects)
}

// CreateProject handles POST /api/v1/projects
func (h *APIHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	log := logging.Logger(r.Context())

	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, h.maxRequestBodySize)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid request body")
		return
	}

	if err := validation.ProjectName(req.Name); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}
	if err := validation.ProjectDescription(req.Description); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	project, err := h.projectService.Create(r.Context(), user.ID, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, services.ErrDuplicateProjectName) {
			jsonError(w, http.StatusBadRequest, "DUPLICATE_NAME", "A project with this name already exists")
			return
		}
		log.Error("project_creation_failed", "user_id", user.ID, "name", req.Name, "error", err)
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create project")
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

	log.Info("project_created", "project_id", project.ID, "user_id", user.ID, "name", project.Name)

	jsonResponse(w, http.StatusCreated, project)
}

// GetProject handles GET /api/v1/projects/{id}
func (h *APIHandler) GetProject(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	project, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	jsonResponse(w, http.StatusOK, project)
}

// DeleteProject handles DELETE /api/v1/projects/{id}
func (h *APIHandler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	log := logging.Logger(r.Context())

	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	// Verify ownership
	project, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	if err := h.projectService.Delete(r.Context(), projectID); err != nil {
		log.Error("project_deletion_failed", "project_id", projectID, "user_id", user.ID, "error", err)
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete project")
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionProjectDelete,
		ResourceType: services.ResourceProject,
		ResourceID:   &projectID,
		ResourceName: project.Name,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	log.Info("project_deleted", "project_id", projectID, "user_id", user.ID, "name", project.Name)

	w.WriteHeader(http.StatusNoContent)
}

// UpdateProject handles PATCH /api/v1/projects/{id}
func (h *APIHandler) UpdateProject(w http.ResponseWriter, r *http.Request) {
	log := logging.Logger(r.Context())

	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	// Verify ownership
	existingProject, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, h.maxRequestBodySize)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid request body")
		return
	}

	// Use existing values if not provided
	name := existingProject.Name
	description := ""
	if existingProject.Description != nil {
		description = *existingProject.Description
	}

	if req.Name != nil {
		if err := validation.ProjectName(*req.Name); err != nil {
			jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		name = *req.Name
	}
	if req.Description != nil {
		if err := validation.ProjectDescription(*req.Description); err != nil {
			jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		description = *req.Description
	}

	project, err := h.projectService.Update(r.Context(), projectID, name, description)
	if err != nil {
		if errors.Is(err, services.ErrDuplicateProjectName) {
			jsonError(w, http.StatusBadRequest, "DUPLICATE_NAME", "A project with this name already exists")
			return
		}
		log.Error("project_update_failed", "project_id", projectID, "user_id", user.ID, "error", err)
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update project")
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionProjectUpdate,
		ResourceType: services.ResourceProject,
		ResourceID:   &project.ID,
		ResourceName: project.Name,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	log.Info("project_updated", "project_id", project.ID, "user_id", user.ID, "name", project.Name)

	jsonResponse(w, http.StatusOK, project)
}

// Secrets

// ListSecrets handles GET /api/v1/projects/{id}/secrets
func (h *APIHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	// Verify ownership
	if _, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID); err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	secrets, err := h.secretService.List(r.Context(), projectID, 1000, 0)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list secrets")
		return
	}

	jsonResponse(w, http.StatusOK, secrets)
}

// GetSecret handles GET /api/v1/projects/{id}/secrets/{key}
func (h *APIHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	key := chi.URLParam(r, "key")
	if err := validation.SecretKey(key); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Verify ownership
	if _, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID); err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	secret, err := h.secretService.Get(r.Context(), projectID, key)
	if err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Secret not found")
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionSecretRead,
		ResourceType: services.ResourceSecret,
		ResourceID:   &secret.ID,
		ResourceName: key,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Return secret with value as string for CLI compatibility
	type secretResponse struct {
		ID        string `json:"id"`
		Key       string `json:"key"`
		Value     string `json:"value"`
		Version   int32  `json:"version"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}

	jsonResponse(w, http.StatusOK, secretResponse{
		ID:        secret.ID.String(),
		Key:       secret.Key,
		Value:     string(secret.Value),
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: secret.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// SetSecret handles PUT /api/v1/projects/{id}/secrets/{key}
func (h *APIHandler) SetSecret(w http.ResponseWriter, r *http.Request) {
	log := logging.Logger(r.Context())

	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	key := chi.URLParam(r, "key")
	if err := validation.SecretKey(key); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Verify ownership
	if _, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID); err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, h.maxRequestBodySize)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid request body")
		return
	}

	if req.Value == "" {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Secret value is required")
		return
	}

	secret, err := h.secretService.Upsert(r.Context(), projectID, key, []byte(req.Value))
	if err != nil {
		log.Error("secret_upsert_failed", "project_id", projectID, "key", key, "user_id", user.ID, "error", err)
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to set secret")
		return
	}

	// Audit log
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

	if secret.Version == 1 {
		log.Info("secret_created", "project_id", projectID, "key", key, "user_id", user.ID)
	} else {
		log.Info("secret_updated", "project_id", projectID, "key", key, "version", secret.Version, "user_id", user.ID)
	}

	// Return secret with value as string for CLI compatibility
	type secretResponse struct {
		ID        string `json:"id"`
		Key       string `json:"key"`
		Value     string `json:"value"`
		Version   int32  `json:"version"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}

	jsonResponse(w, http.StatusOK, secretResponse{
		ID:        secret.ID.String(),
		Key:       secret.Key,
		Value:     req.Value,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: secret.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// DeleteSecret handles DELETE /api/v1/projects/{id}/secrets/{key}
func (h *APIHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	log := logging.Logger(r.Context())

	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	key := chi.URLParam(r, "key")
	if err := validation.SecretKey(key); err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Verify ownership
	if _, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID); err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	if err := h.secretService.Delete(r.Context(), projectID, key); err != nil {
		log.Error("secret_deletion_failed", "project_id", projectID, "key", key, "user_id", user.ID, "error", err)
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete secret")
		return
	}

	// Audit log
	h.auditService.LogAsync(services.LogParams{
		UserID:       &user.ID,
		Action:       services.ActionSecretDelete,
		ResourceType: services.ResourceSecret,
		ResourceName: key,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	log.Info("secret_deleted", "project_id", projectID, "key", key, "user_id", user.ID)

	w.WriteHeader(http.StatusNoContent)
}

// GetAllSecrets handles GET /api/v1/projects/{id}/secrets/export
func (h *APIHandler) GetAllSecrets(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid project ID")
		return
	}

	// Verify ownership
	if _, err := h.projectService.GetByIDWithOwner(r.Context(), projectID, user.ID); err != nil {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "Project not found")
		return
	}

	secrets, err := h.secretService.GetAll(r.Context(), projectID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get secrets")
		return
	}

	// Convert []byte values to strings
	result := make(map[string]string)
	for k, v := range secrets {
		result[k] = string(v)
	}

	jsonResponse(w, http.StatusOK, result)
}

// GetCurrentUser handles GET /api/v1/me
func (h *APIHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Return user info (excluding sensitive fields like password hash)
	type userResponse struct {
		ID       string  `json:"id"`
		Email    string  `json:"email"`
		Username string  `json:"username"`
		Name     *string `json:"name,omitempty"`
	}

	jsonResponse(w, http.StatusOK, userResponse{
		ID:       user.ID.String(),
		Email:    user.Email,
		Username: user.Username,
		Name:     user.Name,
	})
}
