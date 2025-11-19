package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// APIKeyValidator validates API keys by checking them against auth-service.
type APIKeyValidator struct {
	authServiceURL string
	httpClient     *http.Client
	cache          map[string]*apiKeyInfo
	cacheTTL       time.Duration
}

type apiKeyInfo struct {
	clientID  string
	tenantID  string
	scopes    []string
	service   string
	expiresAt time.Time
}

// NewAPIKeyValidator creates a new API key validator.
func NewAPIKeyValidator(authServiceURL string, httpClient *http.Client) *APIKeyValidator {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &APIKeyValidator{
		authServiceURL: strings.TrimSuffix(authServiceURL, "/"),
		httpClient:     httpClient,
		cache:          make(map[string]*apiKeyInfo),
		cacheTTL:       5 * time.Minute,
	}
}

// ValidateAPIKey validates an API key by checking it against auth-service.
// Returns client_id, tenant_id, scopes, and service if valid.
func (v *APIKeyValidator) ValidateAPIKey(ctx context.Context, apiKey string) (clientID, tenantID string, scopes []string, service string, err error) {
	// Check cache first
	if info, ok := v.cache[apiKey]; ok {
		if time.Now().Before(info.expiresAt) {
			return info.clientID, info.tenantID, info.scopes, info.service, nil
		}
		// Cache expired, remove it
		delete(v.cache, apiKey)
	}

	// Validate against auth-service
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/v1/admin/api-keys/validate", v.authServiceURL), nil)
	if err != nil {
		return "", "", nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-API-Key", apiKey)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", "", nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", nil, "", fmt.Errorf("invalid API key: status %d", resp.StatusCode)
	}

	var result struct {
		ClientID string   `json:"client_id"`
		TenantID string   `json:"tenant_id"`
		Scopes   []string `json:"scopes"`
		Service  string   `json:"service"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", nil, "", fmt.Errorf("decode response: %w", err)
	}

	// Cache the result
	v.cache[apiKey] = &apiKeyInfo{
		clientID:  result.ClientID,
		tenantID:  result.TenantID,
		scopes:    result.Scopes,
		service:   result.Service,
		expiresAt: time.Now().Add(v.cacheTTL),
	}

	return result.ClientID, result.TenantID, result.Scopes, result.Service, nil
}
