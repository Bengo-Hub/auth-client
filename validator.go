package authclient

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

// Config holds validator configuration.
type Config struct {
	JWKSUrl         string
	Issuer          string
	Audience        string
	CacheTTL        time.Duration // How long to cache JWKS
	RefreshInterval time.Duration // How often to refresh JWKS in background
	HTTPClient      *http.Client
	RedisClient     *redis.Client // Optional: Redis client for session caching
	SessionCacheTTL time.Duration // Duration to cache validated sessions
	// InitialFetchTimeout bounds how long NewValidator retries the first JWKS fetch, with
	// exponential backoff, before it returns without keys. Zero means
	// DefaultInitialFetchTimeout; a negative value means one attempt only. Keep it below
	// the time the service's liveness probe allows before the HTTP server is listening.
	InitialFetchTimeout time.Duration
	// Logf receives startup and recovery messages about the JWKS. Nil uses the standard
	// log package.
	Logf func(format string, args ...any)
}

// DefaultInitialFetchTimeout is how long NewValidator waits for auth-api's JWKS when
// Config.InitialFetchTimeout is zero. After a node reboot every service starts at once
// and auth-api is often not ready yet; past this wait the service starts anyway and
// loads the keys in the background. 30s stays inside the tightest liveness budget in the
// fleet (about 75s from container start, part of it spent on migrations).
const DefaultInitialFetchTimeout = 30 * time.Second

const (
	initialBackoff      = 1 * time.Second
	maxInitialBackoff   = 10 * time.Second
	recoveryBackoffBase = 2 * time.Second
	maxRecoveryBackoff  = 30 * time.Second
	// onDemandFetchGap throttles the fetch a request triggers while no keys are
	// loaded, so a burst of requests during an auth-api outage does not turn into a
	// burst of JWKS requests.
	onDemandFetchGap = 2 * time.Second
)

// ErrKeysUnavailable means the validator has no signing keys yet because the JWKS could
// not be fetched. Tokens are rejected until the background refresh loads the keys;
// the HTTP middleware answers 503 for it rather than 401.
var ErrKeysUnavailable = errors.New("JWKS signing keys not loaded yet")

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig(jwksURL, issuer, audience string) Config {
	return Config{
		JWKSUrl:         jwksURL,
		Issuer:          issuer,
		Audience:        audience,
		CacheTTL:        1 * time.Hour,
		RefreshInterval: 5 * time.Minute,
		HTTPClient:      &http.Client{Timeout: 10 * time.Second},
		SessionCacheTTL: 5 * time.Minute,
	}
}

// Validator validates JWT tokens using JWKS from auth-service.
type Validator struct {
	config      Config
	keys        map[string]*rsa.PublicKey
	keysMu      sync.RWMutex
	lastFetch   time.Time
	fetchGroup  singleflight.Group
	parser      *jwt.Parser
	stopRefresh chan struct{}
	stopOnce    sync.Once
	// lastOnDemand is the unix-nano time of the last request-triggered fetch made while
	// no keys were loaded (see onDemandFetchGap).
	lastOnDemand atomic.Int64
}

// NewValidator creates a new JWT validator.
//
// The first JWKS fetch is retried with exponential backoff for up to
// Config.InitialFetchTimeout. If auth-api still has not answered, NewValidator returns
// a working validator without keys instead of an error: tokens are rejected with
// ErrKeysUnavailable and a background loop keeps retrying until the keys load. A
// service therefore no longer exits at startup when auth-api is late, which after a
// node reboot left services in CrashLoopBackOff for minutes. The error return is kept
// for compatibility and is always nil.
func NewValidator(config Config) (*Validator, error) {
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 5 * time.Minute
	}
	if config.Logf == nil {
		config.Logf = log.Printf
	}

	v := &Validator{
		config:      config,
		keys:        make(map[string]*rsa.PublicKey),
		parser:      jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()})),
		stopRefresh: make(chan struct{}),
	}

	if err := v.initialFetch(); err != nil {
		v.config.Logf("authclient: JWKS from %s not available at startup (%v); starting without signing keys, tokens are rejected until a background retry loads them", v.config.JWKSUrl, err)
	}

	go v.refreshLoop()

	return v, nil
}

// KeysLoaded reports whether the validator holds at least one signing key. A service
// can use it in its readiness check so that it takes traffic only once tokens can be
// validated.
func (v *Validator) KeysLoaded() bool {
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()
	return len(v.keys) > 0
}

// initialFetch retries the first JWKS fetch with exponential backoff until it succeeds
// or the configured timeout runs out, and returns the last error in that case.
func (v *Validator) initialFetch() error {
	timeout := v.config.InitialFetchTimeout
	if timeout == 0 {
		timeout = DefaultInitialFetchTimeout
	}
	deadline := time.Now().Add(timeout)
	backoff := initialBackoff
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := v.fetchJWKS(ctx)
		cancel()
		if err == nil {
			if attempt > 1 {
				v.config.Logf("authclient: JWKS loaded on attempt %d", attempt)
			}
			return nil
		}
		remaining := time.Until(deadline)
		if timeout < 0 || remaining <= 0 {
			return err
		}
		wait := min(backoff, remaining)
		v.config.Logf("authclient: JWKS fetch attempt %d failed (%v), retrying in %s", attempt, err, wait)
		select {
		case <-time.After(wait):
		case <-v.stopRefresh:
			return err
		}
		backoff = min(backoff*2, maxInitialBackoff)
	}
}

// ValidateToken validates a JWT token string and returns claims.
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	// 1. Check Redis cache if configured
	if v.config.RedisClient != nil {
		claims, err := v.getCachedClaims(tokenString)
		if err == nil && claims != nil {
			return claims, nil
		}
	}

	// 2. Parse and validate token (CPU bound)
	token, err := v.parser.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		key := v.getKey(kid)
		if key == nil && !v.KeysLoaded() {
			// No keys at all: auth-api was not reachable at startup or since. Fetch once,
			// throttled, and report ErrKeysUnavailable so the caller answers 503.
			if !v.claimOnDemandFetch() {
				return nil, ErrKeysUnavailable
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := v.fetchJWKS(ctx)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
			}
			if !v.KeysLoaded() {
				return nil, ErrKeysUnavailable
			}
			key = v.getKey(kid)
		}
		if key == nil {
			// Try to refresh JWKS
			if err := v.fetchJWKS(context.Background()); err != nil {
				return nil, fmt.Errorf("key not found and JWKS refresh failed: %w", err)
			}
			key = v.getKey(kid)
			if key == nil {
				return nil, fmt.Errorf("key %s not found in JWKS", kid)
			}
		}

		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Validate issuer
	if v.config.Issuer != "" && claims.Issuer != v.config.Issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.config.Issuer, claims.Issuer)
	}

	// Validate audience
	if v.config.Audience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == v.config.Audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid audience: expected %s", v.config.Audience)
		}
	}

	// 3. Cache the validated claims if Redis is configured
	if v.config.RedisClient != nil {
		_ = v.cacheClaims(tokenString, claims)
	}

	return claims, nil
}

func (v *Validator) getCachedClaims(tokenString string) (*Claims, error) {
	tokenHash := sha256.Sum256([]byte(tokenString))
	key := fmt.Sprintf("session:%s", hex.EncodeToString(tokenHash[:]))

	data, err := v.config.RedisClient.Get(context.Background(), key).Bytes()
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func (v *Validator) cacheClaims(tokenString string, claims *Claims) error {
	tokenHash := sha256.Sum256([]byte(tokenString))
	key := fmt.Sprintf("session:%s", hex.EncodeToString(tokenHash[:]))

	data, err := json.Marshal(claims)
	if err != nil {
		return err
	}

	// Use Configured TTL or default
	ttl := v.config.SessionCacheTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	return v.config.RedisClient.Set(context.Background(), key, data, ttl).Err()
}

func (v *Validator) getKey(kid string) *rsa.PublicKey {
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()
	return v.keys[kid]
}

func (v *Validator) fetchJWKS(ctx context.Context) error {
	// Use singleflight to prevent concurrent fetches
	_, err, _ := v.fetchGroup.Do("jwks", func() (interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", v.config.JWKSUrl, nil)
		if err != nil {
			return nil, err
		}

		resp, err := v.config.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("JWKS fetch failed: status %d", resp.StatusCode)
		}

		var jwks struct {
			Keys []struct {
				Kty string `json:"kty"`
				Kid string `json:"kid"`
				Use string `json:"use"`
				Alg string `json:"alg"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			return nil, err
		}

		newKeys := make(map[string]*rsa.PublicKey)
		for _, jwk := range jwks.Keys {
			if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
				continue
			}

			nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
			if err != nil {
				continue
			}

			eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
			if err != nil {
				continue
			}

			var eInt int64
			for _, b := range eBytes {
				eInt = eInt<<8 | int64(b)
			}

			pubKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: int(eInt),
			}

			newKeys[jwk.Kid] = pubKey
		}

		v.keysMu.Lock()
		v.keys = newKeys
		v.lastFetch = time.Now()
		v.keysMu.Unlock()

		return nil, nil
	})

	return err
}

// claimOnDemandFetch reports whether a request may trigger a JWKS fetch now, allowing at
// most one per onDemandFetchGap while no keys are loaded.
func (v *Validator) claimOnDemandFetch() bool {
	now := time.Now().UnixNano()
	last := v.lastOnDemand.Load()
	if now-last < int64(onDemandFetchGap) {
		return false
	}
	return v.lastOnDemand.CompareAndSwap(last, now)
}

// refreshLoop refreshes the JWKS every RefreshInterval. While no keys are loaded it
// retries sooner, backing off from recoveryBackoffBase to maxRecoveryBackoff, so a
// validator that started without keys recovers soon after auth-api comes up.
func (v *Validator) refreshLoop() {
	retry := recoveryBackoffBase
	for {
		wait := v.config.RefreshInterval
		missing := !v.KeysLoaded()
		if missing {
			wait = retry
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := v.fetchJWKS(ctx)
			cancel()
			if missing {
				if err == nil && v.KeysLoaded() {
					v.config.Logf("authclient: JWKS loaded by background retry, tokens are accepted again")
					retry = recoveryBackoffBase
				} else {
					retry = min(retry*2, maxRecoveryBackoff)
				}
			}
		case <-v.stopRefresh:
			timer.Stop()
			return
		}
	}
}

// Stop stops the background refresh loop. It is safe to call more than once.
func (v *Validator) Stop() {
	v.stopOnce.Do(func() { close(v.stopRefresh) })
}
