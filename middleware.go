package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
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

			// Only the platform owner bypasses permission checks. A tenant superuser is a
			// tenant-level admin and must satisfy explicit permissions like any other user.
			if claims.IsPlatformOwner {
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
// Superuser and platform owner roles always bypass this check.
func RequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			// Only the platform owner bypasses permission checks. A tenant superuser is a
			// tenant-level admin and must satisfy explicit permissions like any other user.
			if claims.IsPlatformOwner {
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
// Superuser and platform owner roles always bypass this check.
func RequireAllPermissions(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}

			// Only the platform owner bypasses permission checks. A tenant superuser is a
			// tenant-level admin and must satisfy explicit permissions like any other user.
			if claims.IsPlatformOwner {
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

// RequirePlatformOwner creates middleware that requires the user to be a platform owner
// (a user of the platform's own operating tenant). A tenant superuser is NOT a platform
// owner and must never reach platform-level pages/configs through this gate.
func RequirePlatformOwner() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
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

			// Platform owner, explicitly-exempt tenants, demo and service-charge tenants bypass
			// feature checks. Tenant superusers do NOT bypass — they pay for features like anyone.
			if claims.IsGatingExempt() {
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

			if claims.IsGatingExempt() {
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

			if claims.IsGatingExempt() {
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

			if claims.IsGatingExempt() {
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
// Gating-exempt tokens (platform owner, exempt tenants, service-charge, demo) always bypass;
// tenant superusers do NOT.
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

			// IsSubscriptionActive() already returns true for gating-exempt tokens (platform
			// owner, exempt tenants, service-charge, demo). Tenant superusers are not exempt.
			if claims.IsSubscriptionActive() {
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

// ============================================================================
// Canonical feature-lock gate (shared fleet-wide)
// ============================================================================

// featureUpgradeURL is the default upgrade deep-link emitted in the canonical feature-lock body.
// Services may override it once at startup via SetFeatureUpgradeURL to point at their own
// settings/billing route (the frontend routes upgrades from the catalog, so this is informational).
var featureUpgradeURL = "/settings?tab=subscription"

// SetFeatureUpgradeURL overrides the default upgrade URL used by RequireFeatureCode/
// RequireAnyFeatureCode/WriteFeatureLocked. No-op for an empty string. Call once at service init.
func SetFeatureUpgradeURL(u string) {
	if u != "" {
		featureUpgradeURL = u
	}
}

// WriteFeatureLocked writes the ONE canonical 403 feature-lock response body used across every
// service. Frontends' isSubscriptionError() discriminates on `code`. Pass an empty upgradeURL to
// use the package default (SetFeatureUpgradeURL).
func WriteFeatureLocked(w http.ResponseWriter, code, upgradeURL string) {
	if upgradeURL == "" {
		upgradeURL = featureUpgradeURL
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":             "feature_not_available",
		"error":            "feature_not_available",
		"message":          "This feature is not available on your current plan.",
		"required_feature": code,
		"upgrade":          true,
		"upgrade_url":      upgradeURL,
	})
}

// RequireFeatureCode is the canonical feature-lock middleware every service delegates to. It
// checks ONLY entitlement (claims.FeatureEnabled: exempt || HasFeature) and does NOT check
// active-subscription — that is enforced separately by RequireActiveSubscriptionForMutations*, so
// feature-gated READS still pass for expired tenants ("reads always pass"). Missing claims pass
// through (the auth middleware owns authn). Rejections use the uniform WriteFeatureLocked body.
//
// This differs from RequireFeature (which bundles an active-subscription check): use
// RequireFeatureCode for the fleet-uniform feature gate; keep RequireFeature only where you
// deliberately want feature + active-sub in one middleware.
func RequireFeatureCode(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if claims.FeatureEnabled(feature) {
				next.ServeHTTP(w, r)
				return
			}
			WriteFeatureLocked(w, feature, "")
		})
	}
}

// RequireAnyFeatureCode passes when the tenant is entitled to ANY of the given feature codes
// (exempt tenants always pass). Same feature-only semantics as RequireFeatureCode.
func RequireAnyFeatureCode(features ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if claims.IsGatingExempt() || claims.HasAnyFeature(features...) {
				next.ServeHTTP(w, r)
				return
			}
			code := ""
			if len(features) > 0 {
				code = features[0]
			}
			WriteFeatureLocked(w, code, "")
		})
	}
}

// RequireMinTier gates a route on the tenant's plan TIER rank (from the sub_tier claim, via
// PlanTierOrder) rather than a specific feature. Exempt tenants pass; an inactive subscription is
// blocked (403 subscription_inactive); a below-tier tenant gets 403 plan_upgrade_required.
func RequireMinTier(minTier int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing claims")
				return
			}
			if claims.IsGatingExempt() {
				next.ServeHTTP(w, r)
				return
			}
			if !claims.IsSubscriptionActive() {
				writeFeatureError(w, http.StatusForbidden, "subscription_inactive", "Your subscription is not active")
				return
			}
			if claims.PlanTierOrder() < minTier {
				writeFeatureError(w, http.StatusForbidden, "plan_upgrade_required", "This feature requires a higher plan tier")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveSubscriptionForMutationsWithGrace is like RequireActiveSubscriptionForMutations but
// grants a post-expiry grace window (graceDays) during which an EXPIRED tenant may still mutate —
// making the pos/ordering 7-day grace uniform fleet-wide. While in grace it sets the
// X-Sub-Grace-Days-Left header so the UI can warn. Reads (GET/HEAD/OPTIONS) always pass; missing
// claims pass through; beyond grace → 403 subscription_inactive.
func RequireActiveSubscriptionForMutationsWithGrace(graceDays int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if claims.IsSubscriptionActive() {
				next.ServeHTTP(w, r)
				return
			}
			if left, inGrace := claims.GraceDaysLeft(graceDays); inGrace {
				w.Header().Set("X-Sub-Grace-Days-Left", strconv.Itoa(left))
				next.ServeHTTP(w, r)
				return
			}
			writeFeatureError(w, http.StatusForbidden, "subscription_inactive",
				"Your subscription is not active. Please renew to continue.")
		})
	}
}
