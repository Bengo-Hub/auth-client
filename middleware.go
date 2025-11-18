package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "auth_claims"

// AuthMiddleware provides JWT-backed authentication middleware.
type AuthMiddleware struct {
	validator *Validator
}

// NewAuthMiddleware creates a new instance.
func NewAuthMiddleware(validator *Validator) *AuthMiddleware {
	return &AuthMiddleware{validator: validator}
}

// RequireAuth ensures incoming requests possess a valid bearer token.
func (a *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			writeAuthError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		tokenStr := strings.TrimSpace(authHeader[7:])
		claims, err := a.validator.ValidateToken(tokenStr)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
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

