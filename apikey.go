package authclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"
)

// APIKeyValidator validates API keys by checking them against auth-service.
// Supports both service-to-service authentication and external API access.
//
// Results are cached per pod in a bounded, thread-safe LRU keyed by a SHA-256 of the key, so
// raw keys are not kept in memory and the cache never grows past apiKeyCacheSize entries.
// Before v0.15.0 this was a plain map with no lock: two concurrent X-API-Key requests could
// crash the pod with "concurrent map writes", and every distinct key stayed in memory forever.
// Concurrent misses for one key share a single call to auth-service, and rejected keys are
// remembered briefly so a flood of bad keys cannot hammer auth-service.
type APIKeyValidator struct {
	authServiceURL string
	httpClient     *http.Client
	cache          *expirable.LRU[string, *APIKeyValidationResult]
	rejected       *expirable.LRU[string, int]
	flight         singleflight.Group
}

const (
	apiKeyCacheSize   = 5000
	apiKeyCacheTTL    = 2 * time.Minute
	apiKeyRejectedTTL = 30 * time.Second
)

// APIKeyValidationResult contains the full result of API key validation.
type APIKeyValidationResult struct {
	ClientID             string         `json:"client_id"`
	TenantID             string         `json:"tenant_id"`
	TenantSlug           string         `json:"tenant_slug"`
	Scopes               []string       `json:"scopes"`
	Roles                []string       `json:"roles"`
	Service              string         `json:"service"`
	SubscriptionPlan     string         `json:"subscription_plan"`
	SubscriptionFeatures []string       `json:"subscription_features"`
	SubscriptionLimits   map[string]int `json:"subscription_limits"`
	SubscriptionStatus   string         `json:"subscription_status"`
	// Environment is "sandbox" or "production" for a bng_app_* App credential (auth-api's
	// ValidateAPIKeyResponse.Environment); "production" for a plain bng_* APIKey, which has no
	// environment concept of its own.
	Environment string `json:"environment"`
}

// NewAPIKeyValidator creates a new API key validator.
func NewAPIKeyValidator(authServiceURL string, httpClient *http.Client) *APIKeyValidator {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	v := &APIKeyValidator{
		authServiceURL: strings.TrimSuffix(authServiceURL, "/"),
		httpClient:     httpClient,
		cache:          expirable.NewLRU[string, *APIKeyValidationResult](apiKeyCacheSize, nil, apiKeyCacheTTL),
		rejected:       expirable.NewLRU[string, int](apiKeyCacheSize, nil, apiKeyRejectedTTL),
	}
	validatorsMu.Lock()
	validators = append(validators, v)
	validatorsMu.Unlock()
	return v
}

// Every validator in the process, so one revocation message reaches all of them (a service
// typically builds several: auth middleware, docs gate, developer-key auth).
var (
	validatorsMu sync.Mutex
	validators   []*APIKeyValidator
)

// InvalidateAPIKeyHash drops a key from every APIKeyValidator in this process. Services call it
// from their subscription to auth-api's key-change broadcast (shared-events Broadcaster,
// namespace "auth", topic "apikey.changed", payload = the key hash):
//
//	b := events.NewBroadcaster(log, natsConn, "auth")
//	_ = b.Subscribe("apikey.changed", func(m events.BroadcastMessage) {
//		authclient.InvalidateAPIKeyHash(string(m.Data))
//	})
func InvalidateAPIKeyHash(hash string) {
	validatorsMu.Lock()
	vs := append([]*APIKeyValidator(nil), validators...)
	validatorsMu.Unlock()
	for _, v := range vs {
		v.InvalidateHash(hash)
	}
}

// Invalidate drops one key from this pod's cache. Wire it to a revocation broadcast so a
// revoked or downgraded key stops working on every pod at once instead of after the TTL.
func (v *APIKeyValidator) Invalidate(apiKey string) {
	v.InvalidateHash(HashAPIKey(apiKey))
}

// InvalidateHash drops a key by its HashAPIKey value (what a revocation event should carry,
// so the raw key never travels over the bus).
func (v *APIKeyValidator) InvalidateHash(hash string) {
	v.cache.Remove(hash)
	v.rejected.Remove(hash)
}

// InvalidateAll empties this pod's cache (e.g. on a tenant-wide key rotation event).
func (v *APIKeyValidator) InvalidateAll() {
	v.cache.Purge()
	v.rejected.Purge()
}

// ValidateAPIKey validates an API key by checking it against auth-service.
// Returns client_id, tenant_id, scopes, and service if valid.
// Deprecated: Use ValidateAPIKeyFull for complete subscription data.
func (v *APIKeyValidator) ValidateAPIKey(ctx context.Context, apiKey string) (clientID, tenantID string, scopes []string, service string, err error) {
	result, err := v.ValidateAPIKeyFull(ctx, apiKey)
	if err != nil {
		return "", "", nil, "", err
	}
	return result.ClientID, result.TenantID, result.Scopes, result.Service, nil
}

// ValidateAPIKeyFull validates an API key and returns complete information including subscription data.
func (v *APIKeyValidator) ValidateAPIKeyFull(ctx context.Context, apiKey string) (*APIKeyValidationResult, error) {
	h := HashAPIKey(apiKey)
	if res, ok := v.cache.Get(h); ok {
		return cloneResult(res), nil
	}
	if status, ok := v.rejected.Get(h); ok {
		return nil, fmt.Errorf("invalid API key: status %d", status)
	}

	out, err, _ := v.flight.Do(h, func() (any, error) {
		return v.fetch(context.WithoutCancel(ctx), h, apiKey)
	})
	if err != nil {
		return nil, err
	}
	return cloneResult(out.(*APIKeyValidationResult)), nil
}

func (v *APIKeyValidator) fetch(ctx context.Context, h, apiKey string) (*APIKeyValidationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.authServiceURL+"/api/v1/admin/api-keys/validate", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-API-Key", apiKey)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Only a definite rejection is remembered; a 5xx from auth-service is retried next time.
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			v.rejected.Add(h, resp.StatusCode)
		}
		return nil, fmt.Errorf("invalid API key: status %d", resp.StatusCode)
	}

	var result APIKeyValidationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	v.cache.Add(h, &result)
	return &result, nil
}

// HashAPIKey is the cache identity of an API key (hex SHA-256).
func HashAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// cloneResult returns a copy so callers cannot mutate the cached entry shared across requests.
func cloneResult(r *APIKeyValidationResult) *APIKeyValidationResult {
	c := *r
	c.Scopes = append([]string(nil), r.Scopes...)
	c.Roles = append([]string(nil), r.Roles...)
	c.SubscriptionFeatures = append([]string(nil), r.SubscriptionFeatures...)
	if r.SubscriptionLimits != nil {
		c.SubscriptionLimits = make(map[string]int, len(r.SubscriptionLimits))
		for k, val := range r.SubscriptionLimits {
			c.SubscriptionLimits[k] = val
		}
	}
	return &c
}

// ToClaims converts an API key validation result to Claims for consistent handling.
func (r *APIKeyValidationResult) ToClaims() *Claims {
	isPlatformOwner := false
	for _, role := range r.Roles {
		if role == "superuser" {
			isPlatformOwner = true
			break
		}
	}
	return &Claims{
		TenantID:             r.TenantID,
		TenantSlug:           r.TenantSlug,
		Scope:                r.Scopes,
		Roles:                r.Roles,
		ServiceName:          r.Service,
		IsService:            r.Service != "",
		IsPlatformOwner:      isPlatformOwner,
		SubscriptionPlan:     r.SubscriptionPlan,
		SubscriptionFeatures: r.SubscriptionFeatures,
		SubscriptionLimits:   r.SubscriptionLimits,
		SubscriptionStatus:   r.SubscriptionStatus,
	}
}
