package handlers

import (
	"net/http"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/views/pages"
)

// NotFoundHandler handles 404 errors with custom error pages.
func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	// Return JSON for API requests
	if isAPIRequest(r) {
		jsonError(w, http.StatusNotFound, "NOT_FOUND", "The requested resource was not found")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	//nolint:errcheck // Error is from writing to response, handled by HTTP layer
	pages.Error404().Render(r.Context(), w)
}

// MethodNotAllowedHandler handles 405 errors.
func MethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	if isAPIRequest(r) {
		jsonError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "The requested method is not allowed for this resource")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusMethodNotAllowed)
	//nolint:errcheck // Error is from writing to response, handled by HTTP layer
	pages.Error(pages.ErrorData{
		StatusCode:  405,
		Title:       "Method Not Allowed",
		Message:     "The requested method is not allowed for this resource.",
		ShowHomeBtn: true,
	}).Render(r.Context(), w)
}

// RenderError renders an error page with the given status code.
func RenderError(w http.ResponseWriter, r *http.Request, statusCode int, title, message string) {
	if isAPIRequest(r) {
		var code string
		switch statusCode {
		case http.StatusNotFound:
			code = "NOT_FOUND"
		case http.StatusForbidden:
			code = "FORBIDDEN"
		case http.StatusUnauthorized:
			code = "UNAUTHORIZED"
		case http.StatusBadRequest:
			code = "INVALID_INPUT"
		default:
			code = "INTERNAL_ERROR"
		}
		jsonError(w, statusCode, code, message)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	//nolint:errcheck // Error is from writing to response, handled by HTTP layer
	pages.Error(pages.ErrorData{
		StatusCode:  statusCode,
		Title:       title,
		Message:     message,
		ShowHomeBtn: true,
	}).Render(r.Context(), w)
}

// RenderNotFound renders a 404 error page.
func RenderNotFound(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "The page you're looking for doesn't exist or has been moved."
	}
	RenderError(w, r, http.StatusNotFound, "Page Not Found", message)
}

// RenderForbidden renders a 403 error page.
func RenderForbidden(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "You don't have permission to access this resource."
	}
	RenderError(w, r, http.StatusForbidden, "Access Denied", message)
}

// RenderServerError renders a 500 error page.
func RenderServerError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Something went wrong on our end. Please try again later."
	}
	RenderError(w, r, http.StatusInternalServerError, "Server Error", message)
}

// isAPIRequest checks if the request is for the API.
func isAPIRequest(r *http.Request) bool {
	// Check URL path
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}

	// Check Accept header
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}

	// Check Content-Type header
	contentType := r.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}
