package authclient

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents JWT claims from auth-service.
type Claims struct {
	SessionID string   `json:"sid"`
	TenantID  string   `json:"tenant_id,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	Email     string   `json:"email,omitempty"`
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
