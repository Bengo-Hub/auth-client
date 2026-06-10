package authclient

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ExpiresAt converts the Unix timestamp subscription expiry to *time.Time.
func (c *Claims) ExpiresAt() *time.Time {
	if c.SubscriptionExpires == nil {
		return nil
	}
	t := time.Unix(*c.SubscriptionExpires, 0).UTC()
	return &t
}

// Claims represents JWT claims from auth-service.
// Supports both user authentication (JWT) and service authentication (API Key).
// Includes subscription data for feature gating without per-request lookups.
type Claims struct {
	// Core identity
	SessionID  string   `json:"sid"`
	TenantID   string   `json:"tenant_id,omitempty"`
	TenantSlug string   `json:"tenant_slug,omitempty"`
	Scope      []string `json:"scope,omitempty"`
	Email      string   `json:"email,omitempty"`
	IsPlatformOwner bool `json:"is_platform_owner,omitempty"`

	// Outlet / branch context — set when a single outlet is selected at login or via select-outlet.
	// Empty for HQ/admin users who can see all outlets and use X-Outlet-ID header instead.
	OutletID      string `json:"outlet_id,omitempty"`
	OutletCode    string `json:"outlet_code,omitempty"`
	OutletUseCase string `json:"outlet_use_case,omitempty"`
	IsHQUser      bool   `json:"is_hq_user,omitempty"`

	// RBAC - Global roles from auth-service
	Roles []string `json:"roles,omitempty"`

	// Subscription data - embedded at token issuance for zero-latency feature gating
	SubscriptionPlan     string         `json:"sub_plan,omitempty"`              // e.g., "STARTER", "GROWTH", "PROFESSIONAL"
	SubscriptionFeatures []string       `json:"subscription_features,omitempty"` // enabled feature codes (tag must match auth-api token minting + apikey.go)
	SubscriptionLimits   map[string]int `json:"sub_limits,omitempty"`            // usage limits per metric
	SubscriptionStatus   string         `json:"sub_status,omitempty"`            // "ACTIVE", "TRIAL", "EXPIRED", "CANCELLED"
	SubscriptionExpires  *int64         `json:"sub_expires,omitempty"`           // current period end as Unix timestamp

	// Billing model and demo flags — used for subscription gate bypass
	BillingMode  string `json:"billing_mode,omitempty"`      // "service_charge" bypasses subscription gating
	IsDemo       bool   `json:"is_demo,omitempty"`           // true for demo tenant/users, bypasses subscription gating
	AllowOverage bool   `json:"sub_allow_overage,omitempty"` // tenant opted in to pay-as-you-go extra usage

	// Service account identification (for API Key auth)
	ServiceName string `json:"service_name,omitempty"` // e.g., "ordering-service", "logistics-service"
	Permissions []string `json:"permissions,omitempty"` // Canonical permission codes
	IsService   bool     `json:"is_service,omitempty"`  // true if this is a service account, not a user

	jwt.RegisteredClaims
}

// UserID returns the user ID as UUID.
func (c *Claims) UserID() (uuid.UUID, error) {
	if c.Subject == "" {
		return uuid.Nil, jwt.ErrInvalidKey
	}
	return uuid.Parse(c.Subject)
}

// Valid implements jwt.Claims interface.
// In jwt/v5, validation is handled by the parser, so we just check basic requirements.
func (c *Claims) Valid() error {
	if c.Subject == "" {
		return jwt.ErrInvalidKey
	}
	// RegisteredClaims validation is handled by parser
	return nil
}

// TenantUUID returns the tenant ID as UUID if present.
func (c *Claims) TenantUUID() (*uuid.UUID, error) {
	if c.TenantID == "" {
		return nil, nil
	}
	id, err := uuid.Parse(c.TenantID)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// GetTenantSlug returns the tenant slug from claims, or empty string if not present.
func (c *Claims) GetTenantSlug() string {
	return c.TenantSlug
}

// GetOutletID returns the outlet ID from claims, or empty string if not set.
// HQ/admin users may have an empty OutletID; they use X-Outlet-ID header for drill-down.
func (c *Claims) GetOutletID() string {
	return c.OutletID
}

// CanAccessAllOutlets returns true when the user is not scoped to a single outlet.
// Platform owners, tenant admins, and is_hq_user users can access data across all outlets.
func (c *Claims) CanAccessAllOutlets() bool {
	return c.IsPlatformOwner || c.IsAdmin() || c.IsHQUser
}

// HasScope checks if the token has a specific scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scope {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has any of the provided scopes.
func (c *Claims) HasAnyScope(scopes ...string) bool {
	for _, required := range scopes {
		if c.HasScope(required) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the token has all of the provided scopes.
func (c *Claims) HasAllScopes(scopes ...string) bool {
	for _, required := range scopes {
		if !c.HasScope(required) {
			return false
		}
	}
	return true
}

// ============================================================================
// Permission Helpers
// ============================================================================

// HasPermission checks if the token has a specific permission code.
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the token has any of the provided permission codes.
func (c *Claims) HasAnyPermission(permissions ...string) bool {
	for _, required := range permissions {
		if c.HasPermission(required) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the token has all of the provided permission codes.
func (c *Claims) HasAllPermissions(permissions ...string) bool {
	for _, required := range permissions {
		if !c.HasPermission(required) {
			return false
		}
	}
	return true
}

// ============================================================================
// RBAC Role Helpers
// ============================================================================

// HasRole checks if the token has a specific role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the token has any of the provided roles.
func (c *Claims) HasAnyRole(roles ...string) bool {
	for _, required := range roles {
		if c.HasRole(required) {
			return true
		}
	}
	return false
}

// IsSuperuser checks if the token has the superuser role (bypasses all RBAC).
func (c *Claims) IsSuperuser() bool {
	return c.HasRole("superuser")
}

// IsAdmin checks if the token has the admin role.
func (c *Claims) IsAdmin() bool {
	return c.HasRole("admin") || c.IsSuperuser()
}

// ============================================================================
// Subscription Feature Helpers
// ============================================================================

// HasFeature checks if the subscription includes a specific feature.
func (c *Claims) HasFeature(feature string) bool {
	for _, f := range c.SubscriptionFeatures {
		if f == feature {
			return true
		}
	}
	return false
}

// HasAnyFeature checks if the subscription includes any of the provided features.
func (c *Claims) HasAnyFeature(features ...string) bool {
	for _, required := range features {
		if c.HasFeature(required) {
			return true
		}
	}
	return false
}

// HasAllFeatures checks if the subscription includes all of the provided features.
func (c *Claims) HasAllFeatures(features ...string) bool {
	for _, required := range features {
		if !c.HasFeature(required) {
			return false
		}
	}
	return true
}

// GetLimit returns the usage limit for a metric. Returns 0 if not set (unlimited or N/A).
func (c *Claims) GetLimit(metric string) int {
	if c.SubscriptionLimits == nil {
		return 0
	}
	return c.SubscriptionLimits[metric]
}

// IsGatingExempt reports whether this token bypasses ALL subscription gating
// (feature locks AND limit enforcement). Platform owners, superusers, demo
// tenants/users, and service-charge (pay-per-transaction) tenants are exempt.
// Every gate path should funnel through this single helper.
func (c *Claims) IsGatingExempt() bool {
	return c.IsPlatformOwner || c.IsSuperuser() || c.IsDemo || c.BillingMode == "service_charge"
}

// OverageEnabled reports whether the tenant has opted in to pay-as-you-go extra usage.
func (c *Claims) OverageEnabled() bool {
	return c.AllowOverage
}

// overageEligibleLimitKeys is the canonical set of metered throughput plan-limit keys
// that support pay-as-you-go overage. It mirrors subscription-service's billing
// overage-eligibility registry. Structural caps (max_outlets, max_devices, max_cashiers,
// max_tables, max_riders, inventory_max_*, max_wallets, max_currencies, max_admins,
// max_staff, max_suppliers) are intentionally absent — they hard-block and require upgrade.
var overageEligibleLimitKeys = map[string]struct{}{
	"max_orders_per_day":             {},
	"max_transactions_per_month":     {},
	"api_calls_per_month":            {},
	"sms_notifications_per_day":      {},
	"email_notifications_per_day":    {},
	"webhook_calls_per_day":          {},
	"live_tracking_requests_per_day": {},
	"routing_requests_per_day":       {},
}

// IsOverageEligibleLimit reports whether a plan-limit key is a metered throughput limit
// that may be exceeded via pay-as-you-go overage (vs a structural cap that hard-blocks).
func IsOverageEligibleLimit(limitKey string) bool {
	_, ok := overageEligibleLimitKeys[limitKey]
	return ok
}

// IsSubscriptionActive checks if the subscription is currently active.
// Service-charge tenants and demo tenants always bypass subscription gating.
func (c *Claims) IsSubscriptionActive() bool {
	if c.BillingMode == "service_charge" || c.IsDemo {
		return true
	}
	switch c.SubscriptionStatus {
	case "ACTIVE", "TRIAL":
		return true
	case "EXPIRED", "CANCELLED", "SUSPENDED":
		return false
	default:
		// If no subscription status, assume active (free tier or legacy)
		return true
	}
}

// IsTrialSubscription checks if the subscription is in trial period.
func (c *Claims) IsTrialSubscription() bool {
	return c.SubscriptionStatus == "TRIAL"
}

// ============================================================================
// Plan Tier Helpers
// ============================================================================

// PlanTier returns the subscription plan tier for comparison.
// Higher values = higher tier plans.
func (c *Claims) PlanTier() int {
	switch c.SubscriptionPlan {
	case "STARTER", "FREE":
		return 1
	case "GROWTH", "BASIC":
		return 2
	case "PROFESSIONAL", "PRO":
		return 3
	case "ENTERPRISE":
		return 4
	default:
		return 0 // Unknown plan
	}
}

// IsAtLeastPlan checks if the subscription is at least the specified plan tier.
func (c *Claims) IsAtLeastPlan(plan string) bool {
	requiredTier := (&Claims{SubscriptionPlan: plan}).PlanTier()
	return c.PlanTier() >= requiredTier
}
