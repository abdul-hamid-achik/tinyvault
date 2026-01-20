package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/abdul-hamid-achik/tinyvault/internal/middleware"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
)

// Note: Mock services for web tests are not needed since we test
// with nil services (which causes early returns for auth checks)
// and use the real handler validation logic.

// Helper function to create authenticated request context
func withAuthUser(r *http.Request, user *services.User) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserContextKey{}, user)
	return r.WithContext(ctx)
}

// Helper function to add chi URL params
func withChiParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// Test Home handler
func TestHome(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.Home(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Home() status = %d, want %d", w.Code, http.StatusOK)
	}

	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Home() Content-Type = %q, want text/html", w.Header().Get("Content-Type"))
	}
}

// Test Dashboard handler - unauthenticated redirect
func TestDashboard_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()

	handler.Dashboard(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("Dashboard() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}

	location := w.Header().Get("Location")
	if location != "/auth/github" {
		t.Errorf("Dashboard() redirect = %q, want /auth/github", location)
	}
}

// Test Projects handler - unauthenticated redirect
func TestProjects_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/projects", nil)
	w := httptest.NewRecorder()

	handler.Projects(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("Projects() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test CreateProject - unauthenticated redirect
func TestCreateProject_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	form := url.Values{}
	form.Add("name", "test-project")
	form.Add("description", "A test project")

	req := httptest.NewRequest(http.MethodPost, "/projects", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.CreateProject(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("CreateProject() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test ProjectDetail - unauthenticated redirect
func TestProjectDetail_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	projectID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/projects/"+projectID.String(), nil)
	req = withChiParams(req, map[string]string{"id": projectID.String()})
	w := httptest.NewRecorder()

	handler.ProjectDetail(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("ProjectDetail() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test ProjectDetail - invalid project ID
func TestProjectDetail_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	req := httptest.NewRequest(http.MethodGet, "/projects/invalid-uuid", nil)
	req = withAuthUser(req, user)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid"})
	w := httptest.NewRecorder()

	handler.ProjectDetail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ProjectDetail() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test DeleteProject - unauthenticated
func TestDeleteProject_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	projectID := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/projects/"+projectID.String(), nil)
	req = withChiParams(req, map[string]string{"id": projectID.String()})
	w := httptest.NewRecorder()

	handler.DeleteProject(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("DeleteProject() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// Test DeleteProject - invalid project ID
func TestDeleteProject_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	req := httptest.NewRequest(http.MethodDelete, "/projects/invalid-uuid", nil)
	req = withAuthUser(req, user)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid"})
	w := httptest.NewRecorder()

	handler.DeleteProject(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("DeleteProject() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test TokensPage - unauthenticated redirect
func TestTokensPage_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/settings/tokens", nil)
	w := httptest.NewRecorder()

	handler.TokensPage(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("TokensPage() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test CreateToken - unauthenticated redirect
func TestCreateToken_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	form := url.Values{}
	form.Add("name", "test-token")
	form.Add("scopes", "projects:read")
	form.Add("expires_in", "30")

	req := httptest.NewRequest(http.MethodPost, "/settings/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.CreateToken(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("CreateToken() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test CreateToken - missing name
func TestCreateToken_MissingName(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	form := url.Values{}
	form.Add("name", "")
	form.Add("scopes", "projects:read")

	req := httptest.NewRequest(http.MethodPost, "/settings/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthUser(req, user)
	w := httptest.NewRecorder()

	handler.CreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("CreateToken() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test CreateToken - missing scopes
func TestCreateToken_MissingScopes(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	form := url.Values{}
	form.Add("name", "test-token")

	req := httptest.NewRequest(http.MethodPost, "/settings/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthUser(req, user)
	w := httptest.NewRecorder()

	handler.CreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("CreateToken() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test RevokeToken - unauthenticated
func TestRevokeToken_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	tokenID := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/settings/tokens/"+tokenID.String(), nil)
	req = withChiParams(req, map[string]string{"id": tokenID.String()})
	w := httptest.NewRecorder()

	handler.RevokeToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("RevokeToken() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// Test RevokeToken - invalid token ID
func TestRevokeToken_InvalidTokenID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	req := httptest.NewRequest(http.MethodDelete, "/settings/tokens/invalid-uuid", nil)
	req = withAuthUser(req, user)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid"})
	w := httptest.NewRecorder()

	handler.RevokeToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("RevokeToken() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test SettingsPage - unauthenticated redirect
func TestSettingsPage_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	w := httptest.NewRecorder()

	handler.SettingsPage(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("SettingsPage() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test UpdateProfile - unauthenticated redirect
func TestUpdateProfile_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	form := url.Values{}
	form.Add("username", "newusername")
	form.Add("email", "new@example.com")

	req := httptest.NewRequest(http.MethodPost, "/settings/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("UpdateProfile() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test UpdatePassword - unauthenticated redirect
func TestUpdatePassword_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	form := url.Values{}
	form.Add("current_password", "oldpassword123")
	form.Add("new_password", "newpassword123")
	form.Add("confirm_password", "newpassword123")

	req := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.UpdatePassword(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("UpdatePassword() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test UpdatePassword - password too short
func TestUpdatePassword_PasswordTooShort(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	form := url.Values{}
	form.Add("current_password", "oldpassword123")
	form.Add("new_password", "short")
	form.Add("confirm_password", "short")

	req := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthUser(req, user)
	w := httptest.NewRecorder()

	handler.UpdatePassword(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("UpdatePassword() status = %d, want %d (redirect with error)", w.Code, http.StatusSeeOther)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "Password+must+be+at+least+12+characters") {
		t.Errorf("UpdatePassword() should redirect with password length error, got %s", location)
	}
}

// Test UpdatePassword - passwords don't match
func TestUpdatePassword_PasswordsMismatch(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	user := &services.User{ID: uuid.New(), Username: "testuser", Email: "test@example.com"}
	form := url.Values{}
	form.Add("current_password", "oldpassword123")
	form.Add("new_password", "newpassword123")
	form.Add("confirm_password", "differentpassword")

	req := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthUser(req, user)
	w := httptest.NewRecorder()

	handler.UpdatePassword(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("UpdatePassword() status = %d, want %d (redirect with error)", w.Code, http.StatusSeeOther)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "Passwords+do+not+match") {
		t.Errorf("UpdatePassword() should redirect with mismatch error, got %s", location)
	}
}

// Test UnlinkGitHub - unauthenticated redirect
func TestUnlinkGitHub_Unauthenticated(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/settings/unlink-github", nil)
	w := httptest.NewRecorder()

	handler.UnlinkGitHub(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("UnlinkGitHub() status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

// Test NewSecretModal - invalid project ID
func TestNewSecretModal_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/projects/invalid-uuid/secrets/new", nil)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid"})
	w := httptest.NewRecorder()

	handler.NewSecretModal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("NewSecretModal() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test EditSecretModal - invalid project ID
func TestEditSecretModal_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/projects/invalid-uuid/secrets/TEST_KEY/edit", nil)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid", "key": "TEST_KEY"})
	w := httptest.NewRecorder()

	handler.EditSecretModal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("EditSecretModal() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test RevealSecret - invalid project ID
func TestRevealSecret_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/projects/invalid-uuid/secrets/TEST_KEY/reveal", nil)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid", "key": "TEST_KEY"})
	w := httptest.NewRecorder()

	handler.RevealSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("RevealSecret() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test UpdateSecret - invalid project ID
func TestUpdateSecret_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	form := url.Values{}
	form.Add("key", "TEST_KEY")
	form.Add("value", "test-value")

	req := httptest.NewRequest(http.MethodPut, "/projects/invalid-uuid/secrets/TEST_KEY", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiParams(req, map[string]string{"id": "invalid-uuid", "key": "TEST_KEY"})
	w := httptest.NewRecorder()

	handler.UpdateSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("UpdateSecret() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test DeleteSecret - invalid project ID
func TestDeleteSecret_InvalidProjectID(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/projects/invalid-uuid/secrets/TEST_KEY", nil)
	req = withChiParams(req, map[string]string{"id": "invalid-uuid", "key": "TEST_KEY"})
	w := httptest.NewRecorder()

	handler.DeleteSecret(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("DeleteSecret() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// Test verifyProjectOwnership - unauthorized when no user
func TestVerifyProjectOwnership_NoUser(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	projectID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/projects/"+projectID.String(), nil)
	w := httptest.NewRecorder()

	result := handler.verifyProjectOwnership(w, req, projectID)

	if result != nil {
		t.Error("verifyProjectOwnership() should return nil when no user")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("verifyProjectOwnership() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// Test LinkGitHubRedirect
func TestLinkGitHubRedirect(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/settings/link-github", nil)
	w := httptest.NewRecorder()

	handler.LinkGitHubRedirect(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("LinkGitHubRedirect() status = %d, want %d", w.Code, http.StatusSeeOther)
	}

	location := w.Header().Get("Location")
	if location != "/auth/github?link=true" {
		t.Errorf("LinkGitHubRedirect() redirect = %q, want /auth/github?link=true", location)
	}
}

// Test NewProject renders form
func TestNewProject(t *testing.T) {
	handler := NewWebHandler(nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/projects/new", nil)
	w := httptest.NewRecorder()

	handler.NewProject(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("NewProject() status = %d, want %d", w.Code, http.StatusOK)
	}

	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("NewProject() Content-Type = %q, want text/html", w.Header().Get("Content-Type"))
	}
}
