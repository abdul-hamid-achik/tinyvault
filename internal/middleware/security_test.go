package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	tests := []struct {
		name         string
		isProduction bool
		wantHSTS     bool
	}{
		{
			name:         "development mode",
			isProduction: false,
			wantHSTS:     false,
		},
		{
			name:         "production mode",
			isProduction: true,
			wantHSTS:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := SecurityHeaders(tt.isProduction)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			// Check X-Frame-Options
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %s, want DENY", got)
			}

			// Check X-Content-Type-Options
			if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %s, want nosniff", got)
			}

			// Check X-XSS-Protection
			if got := w.Header().Get("X-XSS-Protection"); got != "1; mode=block" {
				t.Errorf("X-XSS-Protection = %s, want 1; mode=block", got)
			}

			// Check Referrer-Policy
			if got := w.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
				t.Errorf("Referrer-Policy = %s, want strict-origin-when-cross-origin", got)
			}

			// Check Content-Security-Policy
			csp := w.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Error("Content-Security-Policy header missing")
			}
			if !strings.Contains(csp, "default-src 'self'") {
				t.Error("CSP should contain default-src 'self'")
			}
			// Verify 'unsafe-inline' is NOT present
			if strings.Contains(csp, "'unsafe-inline'") {
				t.Error("CSP should not contain 'unsafe-inline'")
			}

			// Check HSTS
			hsts := w.Header().Get("Strict-Transport-Security")
			if tt.wantHSTS && hsts == "" {
				t.Error("HSTS header should be set in production")
			}
			if !tt.wantHSTS && hsts != "" {
				t.Error("HSTS header should not be set in development")
			}
		})
	}
}

func TestCSRFProtection_SafeMethods(t *testing.T) {
	safeMethods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}

	for _, method := range safeMethods {
		t.Run(method, func(t *testing.T) {
			handler := CSRFProtection()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("CSRF protection for %s returned %d, want %d", method, w.Code, http.StatusOK)
			}

			// Should have CSRF token in response header
			csrfToken := w.Header().Get("X-CSRF-Token")
			if csrfToken == "" {
				t.Errorf("CSRF token should be set in response for %s", method)
			}
		})
	}
}

func TestCSRFProtection_UnsafeMethods_MissingToken(t *testing.T) {
	unsafeMethods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range unsafeMethods {
		t.Run(method, func(t *testing.T) {
			handler := CSRFProtection()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("CSRF protection for %s without token returned %d, want %d", method, w.Code, http.StatusForbidden)
			}
		})
	}
}

func TestCSRFProtection_UnsafeMethods_ValidToken(t *testing.T) {
	// First, get a CSRF token
	getHandler := CSRFProtection()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	getHandler.ServeHTTP(getW, getReq)

	// Get the cookie
	cookies := getW.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Fatal("CSRF cookie not set")
	}

	// Now make a POST request with the token
	postHandler := CSRFProtection()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postReq.AddCookie(csrfCookie)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postW := httptest.NewRecorder()

	postHandler.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Errorf("CSRF protection for POST with valid token returned %d, want %d", postW.Code, http.StatusOK)
	}
}

func TestGetCSRFToken(t *testing.T) {
	// Request without cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token := GetCSRFToken(req)
	if token != "" {
		t.Errorf("GetCSRFToken without cookie returned %s, want empty string", token)
	}

	// Request with cookie
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-token"})
	token = GetCSRFToken(req)
	if token != "test-token" {
		t.Errorf("GetCSRFToken with cookie returned %s, want test-token", token)
	}
}
