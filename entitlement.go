package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// EntitlementTTL bounds how long a tenant's entitlement snapshot is reused. 60s absorbs event
// bursts without hammering subscriptions-api while staying fresh enough for plan changes.
const EntitlementTTL = 60 * time.Second

// entitlementMaxEntries caps the in-process cache so a long-lived pod cannot grow without bound.
const entitlementMaxEntries = 4096

// Entitlements is the subset of subscriptions-api GET /api/v1/tenants/{id}/subscription that
// provisioning paths (tenant syncers, NATS consumers, JIT user creation) need to decide whether a
// tenant may hold data in a service at all.
type Entitlements struct {
	Status            string   `json:"status"`
	BillingMode       string   `json:"billing_mode"`
	IsDemoBypass      bool     `json:"is_demo_bypass"`
	Exempt            bool     `json:"exempt"`
	ActiveServiceTags []string `json:"active_service_tags"`
	// NotSubscribed is set when subscriptions-api answers 404: a real "no", not an outage.
	NotSubscribed bool `json:"-"`
}

// UsesService reports whether the snapshot covers serviceTag. Exempt, demo and service-charge
// tenants always do; a tenant with no subscription never does.
func (e *Entitlements) UsesService(serviceTag string) bool {
	if e == nil {
		return true
	}
	if e.NotSubscribed {
		return false
	}
	if e.IsDemoBypass || e.Exempt || e.BillingMode == "exempt" || e.BillingMode == "service_charge" {
		return true
	}
	for _, t := range e.ActiveServiceTags {
		if t == serviceTag {
			return true
		}
	}
	return false
}

// EntitlementClient answers "is service X part of tenant T's plan" for code paths that carry a
// tenant id but no user JWT. One implementation for every service; do not copy it per service.
type EntitlementClient struct {
	baseURL string
	apiKey  string
	http    *http.Client

	mu     sync.Mutex
	cache  map[string]entitlementEntry
	flight singleflight.Group
}

type entitlementEntry struct {
	ent     *Entitlements
	fetched time.Time
}

// NewEntitlementClient builds a client for subscriptions-api. A blank baseURL yields a client that
// always allows (not wired, for local development), matching the fail-open rule below.
func NewEntitlementClient(baseURL, apiKey string) *EntitlementClient {
	return &EntitlementClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 5 * time.Second},
		cache:   make(map[string]entitlementEntry),
	}
}

// UsesService reports whether tenantID's subscription covers serviceTag.
//
// It fails open (true) when the client is not wired or subscriptions-api cannot be reached, so an
// outage never strands legitimate data. A 404 (no subscription) is a real "no". Failures are not
// cached, so the next call retries.
func (c *EntitlementClient) UsesService(ctx context.Context, tenantID, serviceTag string) bool {
	if c == nil || c.baseURL == "" || tenantID == "" || serviceTag == "" {
		return true
	}
	return c.Get(ctx, tenantID).UsesService(serviceTag)
}

// Get returns the cached snapshot for the tenant, or nil when it could not be fetched.
func (c *EntitlementClient) Get(ctx context.Context, tenantID string) *Entitlements {
	if c == nil || c.baseURL == "" || tenantID == "" {
		return nil
	}
	c.mu.Lock()
	if hit, ok := c.cache[tenantID]; ok && time.Since(hit.fetched) < EntitlementTTL {
		c.mu.Unlock()
		return hit.ent
	}
	c.mu.Unlock()

	v, _, _ := c.flight.Do(tenantID, func() (any, error) {
		e := c.fetch(ctx, tenantID)
		if e != nil {
			c.mu.Lock()
			if len(c.cache) >= entitlementMaxEntries {
				c.evictLocked()
			}
			c.cache[tenantID] = entitlementEntry{ent: e, fetched: time.Now()}
			c.mu.Unlock()
		}
		return e, nil
	})
	e, _ := v.(*Entitlements)
	return e
}

// evictLocked drops expired entries and, when still full, an arbitrary half. Caller holds c.mu.
func (c *EntitlementClient) evictLocked() {
	now := time.Now()
	for k, v := range c.cache {
		if now.Sub(v.fetched) >= EntitlementTTL {
			delete(c.cache, k)
		}
	}
	if len(c.cache) < entitlementMaxEntries {
		return
	}
	n := len(c.cache) / 2
	for k := range c.cache {
		if n == 0 {
			break
		}
		delete(c.cache, k)
		n--
	}
}

func (c *EntitlementClient) fetch(ctx context.Context, tenantID string) *Entitlements {
	u := c.baseURL + "/api/v1/tenants/" + url.PathEscape(tenantID) + "/subscription?include_usage=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return &Entitlements{NotSubscribed: true}
	default:
		return nil
	}
	var e Entitlements
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		return nil
	}
	return &e
}

// Invalidate drops one tenant's cached snapshot (for plan-change broadcasts).
func (c *EntitlementClient) Invalidate(tenantID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.cache, tenantID)
	c.mu.Unlock()
}
