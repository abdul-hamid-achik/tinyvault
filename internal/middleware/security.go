package middleware

import (
	"net/http"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// CSRFContextKey is the context key for CSRF token.
type CSRFContextKey struct{}

// SecurityHeaders returns middleware that adds security headers to responses.
func SecurityHeaders(isProduction bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1; mode=block") // Legacy but still useful
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			csp := "default-src 'self'; " +
				"script-src 'self' https://unpkg.com https://cdnjs.cloudflare.com; " +
				"style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
				"font-src 'self' https://fonts.gstatic.com; " +
				"img-src 'self' https://avatars.githubusercontent.com data:; " +
				"connect-src 'self'; " +
				"frame-ancestors 'none'; " +
				"base-uri 'self'; " +
				"form-action 'self'"
			w.Header().Set("Content-Security-Policy", csp)

			// HSTS (only in production with HTTPS)
			if isProduction {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfFormField  = "csrf_token"
	csrfTokenLen   = 32
)

// CSRFProtection returns middleware that provides CSRF protection.
// Uses double-submit cookie pattern compatible with HTMX.
func CSRFProtection() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get or generate CSRF token
			cookie, err := r.Cookie(csrfCookieName)
			var csrfToken string

			if err != nil || cookie.Value == "" {
				// Generate new token
				csrfToken, err = crypto.GenerateTokenString(csrfTokenLen)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				// Set cookie
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    csrfToken,
					Path:     "/",
					MaxAge:   86400, // 24 hours
					HttpOnly: false, // Must be readable by JS for HTMX
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				csrfToken = cookie.Value
			}

			// For safe methods, just continue
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				// Set header for HTMX to use in subsequent requests
				w.Header().Set("X-CSRF-Token", csrfToken)
				next.ServeHTTP(w, r)
				return
			}

			// For unsafe methods, validate CSRF token
			// Check header first (HTMX), then form field
			submittedToken := r.Header.Get(csrfHeaderName)
			if submittedToken == "" {
				// Try parsing form for traditional form submissions
				if err := r.ParseForm(); err == nil {
					submittedToken = r.FormValue(csrfFormField)
				}
			}

			// Validate token using constant-time comparison
			if !crypto.CompareTokens([]byte(csrfToken), []byte(submittedToken)) {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}

			// Set header for HTMX to use in subsequent requests
			w.Header().Set("X-CSRF-Token", csrfToken)
			next.ServeHTTP(w, r)
		})
	}
}

// GetCSRFToken retrieves the CSRF token from the request.
func GetCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
