package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"github.com/abdul-hamid-achik/tinyvault/internal/config"
	"github.com/abdul-hamid-achik/tinyvault/internal/middleware"
	"github.com/abdul-hamid-achik/tinyvault/internal/services"
)

// Dependencies holds all the dependencies needed for handlers.
type Dependencies struct {
	Config         *config.Config
	DB             *pgxpool.Pool
	Redis          *redis.Client
	Logger         *slog.Logger
	UserService    *services.UserService
	ProjectService *services.ProjectService
	SecretService  *services.SecretService
	AuthService    *services.AuthService
	TokenService   *services.TokenService
	AuditService   *services.AuditService
}

// NewRouter creates and configures the HTTP router.
func NewRouter(deps *Dependencies) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.Metrics())
	r.Use(middleware.Logging(deps.Logger))
	r.Use(middleware.Recovery(deps.Logger))
	r.Use(chimiddleware.Timeout(deps.Config.Server.RequestTimeout))
	r.Use(middleware.SecurityHeaders(deps.Config.IsProduction()))

	// Rate limiter
	rateLimiter := middleware.NewRateLimiter(
		deps.Redis,
		deps.Config.RateLimit.Requests,
		deps.Config.RateLimit.Window,
	)

	// Create handlers
	healthHandler := NewHealthHandler(deps.DB, deps.Redis)
	authHandler := NewAuthHandler(
		deps.Config.GitHub.ClientID,
		deps.Config.GitHub.ClientSecret,
		deps.Config.GitHub.CallbackURL,
		deps.UserService,
		deps.AuthService,
		deps.AuditService,
	)
	apiHandler := NewAPIHandler(
		deps.ProjectService,
		deps.SecretService,
		deps.TokenService,
		deps.AuditService,
		deps.Config.Security.MaxRequestBodySize,
	)
	webHandler := NewWebHandler(
		deps.ProjectService,
		deps.SecretService,
		deps.TokenService,
		deps.AuditService,
		deps.UserService,
	)

	// Health checks and metrics (no auth, no rate limit)
	r.Get("/health", healthHandler.Liveness)
	r.Get("/ready", healthHandler.Readiness)
	r.Handle("/metrics", promhttp.Handler())

	// Static files (CSS, JS, images)
	fileServer := http.FileServer(http.Dir("web/static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// Auth routes (rate limited to prevent abuse)
	r.Route("/auth", func(r chi.Router) {
		r.Use(middleware.RateLimit(rateLimiter))
		r.Get("/login", authHandler.LoginPage)
		r.Post("/login", authHandler.EmailLogin)
		r.Get("/register", authHandler.RegisterPage)
		r.Post("/register", authHandler.Register)
		r.Get("/github", authHandler.GitHubLogin)
		r.Get("/callback", authHandler.GitHubCallback)
		r.Post("/logout", authHandler.Logout)
	})

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.RateLimitAPI(rateLimiter))
		r.Use(middleware.APIAuth(deps.TokenService))

		// Current user
		r.Get("/me", apiHandler.GetCurrentUser)

		// Projects
		r.Route("/projects", func(r chi.Router) {
			r.With(middleware.RequireScope("projects:read")).Get("/", apiHandler.ListProjects)
			r.With(middleware.RequireScope("projects:write")).Post("/", apiHandler.CreateProject)

			r.Route("/{id}", func(r chi.Router) {
				r.With(middleware.RequireScope("projects:read")).Get("/", apiHandler.GetProject)
				r.With(middleware.RequireScope("projects:delete")).Delete("/", apiHandler.DeleteProject)

				// Secrets
				r.Route("/secrets", func(r chi.Router) {
					r.With(middleware.RequireScope("secrets:read")).Get("/", apiHandler.ListSecrets)
					r.With(middleware.RequireScope("secrets:read")).Get("/export", apiHandler.GetAllSecrets)
					r.With(middleware.RequireScope("secrets:read")).Get("/{key}", apiHandler.GetSecret)
					r.With(middleware.RequireScope("secrets:write")).Put("/{key}", apiHandler.SetSecret)
					r.With(middleware.RequireScope("secrets:delete")).Delete("/{key}", apiHandler.DeleteSecret)
				})
			})
		})
	})

	// Web routes with templ templates
	r.Group(func(r chi.Router) {
		r.Use(middleware.RateLimit(rateLimiter))
		r.Use(middleware.CSRFProtection())

		// Session auth middleware for protected routes
		sessionAuth := middleware.SessionAuth(deps.AuthService)

		// Register web handler routes
		webHandler.RegisterRoutes(r, sessionAuth)
	})

	return r
}
