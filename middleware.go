package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "auth_claims"

// AuthMiddleware provides JWT-backed authentication middleware with API key fallback.
type AuthMiddleware struct {
	validator       *Validator
	apiKeyValidator *APIKeyValidator
}

// NewAuthMiddleware creates a new instance with JWT validator only.
func NewAuthMiddleware(validator *Validator) *AuthMiddleware {
	return &AuthMiddleware{validator: validator}
}

// NewAuthMiddlewareWithAPIKey creates a new instance with both JWT validator and API key validator.
func NewAuthMiddlewareWithAPIKey(validator *Validator, apiKeyValidator *APIKeyValidator) *AuthMiddleware {
	return &AuthMiddleware{
		validator:       validator,
		apiKeyValidator: apiKeyValidator,
	}
}

// RequireAuth ensures incoming requests possess a valid bearer token or API key.
func (a *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		// Try JWT Bearer token first
		if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			tokenStr := strings.TrimSpace(authHeader[7:])
			claims, err := a.validator.ValidateToken(tokenStr)
			if err == nil {
				ctx := context.WithValue(r.Context(), claimsContextKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Fallback to API key if JWT validation failed or no Bearer token
		if a.apiKeyValidator != nil {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "" {
				result, err := a.apiKeyValidator.ValidateAPIKeyFull(r.Context(), apiKey)
				if err == nil {
					// Convert API key result to Claims for consistent handling
					claims := result.ToClaims()
					// Store client_id in Subject for API keys
					claims.Subject = result.ClientID
					ctx := context.WithValue(r.Context(), claimsContextKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		writeAuthError(w, http.StatusUnauthorized, "missing bearer token or API key")
	})
}

// Middleware creates HTTP middleware that validates JWT tokens.
// Deprecated: Use AuthMiddleware.RequireAuth instead.
func Middleware(validator *Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				writeAuthError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}

			tokenStr := strings.TrimSpace(authHeader[7:])
			claims, err := validator.ValidateToken(tokenStr)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext extracts claims from request context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok && claims != nil
}

// ContextWithClaims returns a new context with the given claims attached.
// This is primarily useful for testing where you need to inject mock claims.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// RequireScope creates middleware that requires specific scopes.
func RequireScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if !claims.HasAnyScope(scopes...) {
				writeAuthError(w, http.StatusForbidden, "insufficient scopes")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllScopes creates middleware that requires all specified scopes.
func RequireAllScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if !claims.HasAllScopes(scopes...) {
				writeAuthError(w, http.StatusForbidden, "insufficient scopes")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": message,
		"code":  "unauthorized",
	})
}

// ============================================================================
// Role-Based Access Control Middleware
// ============================================================================

// RequireRole creates middleware that requires at least one of the specified roles.
// Superuser role always bypasses this check.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			// Superuser bypasses all role checks
			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.HasAnyRole(roles...) {
				writeAuthError(w, http.StatusForbidden, "insufficient role")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin creates middleware that requires admin or superuser role.
func RequireAdmin() func(http.Handler) http.Handler {
	return RequireRole("admin", "superuser")
}

// ============================================================================
// Permission-Based Access Control Middleware
// ============================================================================

// RequirePermission creates middleware that requires a specific permission code.
// Superuser and platform owner roles always bypass this check.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			// Superuser bypasses all permission checks
			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.HasPermission(permission) {
				writePermissionError(w, http.StatusForbidden, permission)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission creates middleware that requires at least one of the specified permissions.
// Superuser role always bypasses this check.
func RequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.HasAnyPermission(permissions...) {
				writePermissionError(w, http.StatusForbidden, strings.Join(permissions, " | "))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllPermissions creates middleware that requires all of the specified permissions.
// Superuser role always bypasses this check.
func RequireAllPermissions(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.HasAllPermissions(permissions...) {
				writePermissionError(w, http.StatusForbidden, strings.Join(permissions, " & "))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePlatformOwner creates middleware that requires the user to be a platform owner.
// Superuser role always bypasses this check.
func RequirePlatformOwner() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.IsPlatformOwner {
				writeAuthError(w, http.StatusForbidden, "platform owner access required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writePermissionError(w http.ResponseWriter, status int, required string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    "insufficient permissions",
		"code":     "permission_denied",
		"required": required,
	})
}

// ============================================================================
// Subscription Feature Gating Middleware
// ============================================================================

// RequireFeature creates middleware that requires a specific subscription feature.
// Returns 403 Forbidden with upgrade message if feature is not enabled.
func RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			// Superuser bypasses feature checks
			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			// Check subscription is active
			if !claims.IsSubscriptionActive() {
				writeFeatureError(w, http.StatusForbidden, "subscription_inactive", "Your subscription is not active")
				return
			}

			if !claims.HasFeature(feature) {
				writeFeatureError(w, http.StatusForbidden, "feature_not_available",
					"This feature requires an upgrade. Feature: "+feature)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyFeature creates middleware that requires at least one of the specified features.
func RequireAnyFeature(features ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.IsSubscriptionActive() {
				writeFeatureError(w, http.StatusForbidden, "subscription_inactive", "Your subscription is not active")
				return
			}

			if !claims.HasAnyFeature(features...) {
				writeFeatureError(w, http.StatusForbidden, "feature_not_available",
					"This feature requires an upgrade")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePlan creates middleware that requires at least the specified subscription plan.
func RequirePlan(plan string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.IsSubscriptionActive() {
				writeFeatureError(w, http.StatusForbidden, "subscription_inactive", "Your subscription is not active")
				return
			}

			if !claims.IsAtLeastPlan(plan) {
				writeFeatureError(w, http.StatusForbidden, "plan_upgrade_required",
					"This feature requires "+plan+" plan or higher")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveSubscription creates middleware that requires an active subscription.
func RequireActiveSubscription() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			if claims.IsSuperuser() {
				next.ServeHTTP(w, r)
				return
			}

			if !claims.IsSubscriptionActive() {
				writeFeatureError(w, http.StatusForbidden, "subscription_inactive",
					"Your subscription is not active. Please renew to continue.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveSubscriptionForMutations creates middleware that enforces active subscription
// only on mutation requests (POST, PUT, PATCH, DELETE). Read-only requests (GET, HEAD, OPTIONS)
// pass through unconditionally so users can still view data with an expired subscription.
// Superusers and platform owners always bypass.
func RequireActiveSubscriptionForMutations() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read-only methods always pass through
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// No claims = unauthenticated route or middleware ordering issue; let auth middleware handle it
				next.ServeHTTP(w, r)
				return
			}

			if claims.IsSuperuser() || claims.IsPlatformOwner || claims.IsSubscriptionActive() {
				next.ServeHTTP(w, r)
				return
			}

			writeFeatureError(w, http.StatusForbidden, "subscription_inactive",
				"Your subscription is not active. Please renew to continue.")
		})
	}
}

func writeFeatureError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   message,
		"code":    code,
		"upgrade": true,
	})
}
