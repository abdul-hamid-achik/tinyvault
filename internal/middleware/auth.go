package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/services"
)

// apiError represents a standardized API error response.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// jsonError writes a standardized JSON error response.
func jsonError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := apiError{}
	resp.Error.Code = code
	resp.Error.Message = message
	json.NewEncoder(w).Encode(resp)
}

// Context keys for auth data.
type (
	UserContextKey    struct{}
	SessionContextKey struct{}
	TokenContextKey   struct{}
)

// SessionAuth returns middleware that authenticates requests using session cookies.
func SessionAuth(authService *services.AuthService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session")
			if err != nil {
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}

			session, err := authService.ValidateSession(r.Context(), cookie.Value)
			if err != nil {
				// Clear invalid cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "session",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteLaxMode,
				})
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}

			// Add session and user to context
			ctx := context.WithValue(r.Context(), SessionContextKey{}, session)
			ctx = context.WithValue(ctx, UserContextKey{}, session.User)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIAuth returns middleware that authenticates API requests using Bearer tokens.
func APIAuth(tokenService *services.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid authorization header format")
				return
			}

			token, err := tokenService.Validate(r.Context(), parts[1])
			if err != nil {
				jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired token")
				return
			}

			// Add token and user to context
			ctx := context.WithValue(r.Context(), TokenContextKey{}, token)
			ctx = context.WithValue(ctx, UserContextKey{}, token.User)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth returns middleware that authenticates if credentials are provided.
func OptionalAuth(authService *services.AuthService, tokenService *services.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try Bearer token first
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					token, err := tokenService.Validate(r.Context(), parts[1])
					if err == nil {
						ctx := context.WithValue(r.Context(), TokenContextKey{}, token)
						ctx = context.WithValue(ctx, UserContextKey{}, token.User)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Try session cookie
			cookie, err := r.Cookie("session")
			if err == nil {
				session, err := authService.ValidateSession(r.Context(), cookie.Value)
				if err == nil {
					ctx := context.WithValue(r.Context(), SessionContextKey{}, session)
					ctx = context.WithValue(ctx, UserContextKey{}, session.User)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Continue without auth
			next.ServeHTTP(w, r)
		})
	}
}

// RequireScope returns middleware that checks if the token has the required scope.
func RequireScope(scope string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := r.Context().Value(TokenContextKey{}).(*services.APITokenWithUser)
			if !ok {
				jsonError(w, http.StatusUnauthorized, "UNAUTHORIZED", "API token required")
				return
			}

			if !services.HasScope(token.Scopes, scope) {
				jsonError(w, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions for scope: "+scope)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUser retrieves the authenticated user from the context.
func GetUser(ctx context.Context) *services.User {
	user, _ := ctx.Value(UserContextKey{}).(*services.User)
	return user
}

// GetSession retrieves the session from the context.
func GetSession(ctx context.Context) *services.SessionWithUser {
	session, _ := ctx.Value(SessionContextKey{}).(*services.SessionWithUser)
	return session
}

// GetToken retrieves the API token from the context.
func GetToken(ctx context.Context) *services.APITokenWithUser {
	token, _ := ctx.Value(TokenContextKey{}).(*services.APITokenWithUser)
	return token
}
