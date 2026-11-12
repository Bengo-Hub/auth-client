package authclient

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer serves a JWKS for key once up is true and 503 before that, like auth-api
// behind a Service with no ready endpoints right after a node reboot.
func jwksServer(t *testing.T, key *rsa.PrivateKey, up *atomic.Bool) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func signedToken(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testConfig(url string) Config {
	cfg := DefaultConfig(url, "", "")
	cfg.Logf = func(string, ...any) {}
	return cfg
}

func TestNewValidatorRetriesUntilJWKSAnswers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var up atomic.Bool
	srv := jwksServer(t, key, &up)
	time.AfterFunc(1500*time.Millisecond, func() { up.Store(true) })

	cfg := testConfig(srv.URL)
	cfg.InitialFetchTimeout = 15 * time.Second
	v, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	defer v.Stop()
	if !v.KeysLoaded() {
		t.Fatal("keys should be loaded once the JWKS answered within the initial wait")
	}
	if _, err := v.ValidateToken(signedToken(t, key)); err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
}

func TestNewValidatorStartsWithoutKeysAndRecovers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var up atomic.Bool
	srv := jwksServer(t, key, &up)

	cfg := testConfig(srv.URL)
	cfg.InitialFetchTimeout = -1 // one attempt, do not wait
	v, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator must not fail when auth-api is down: %v", err)
	}
	defer v.Stop()
	if v.KeysLoaded() {
		t.Fatal("no keys expected while the JWKS answers 503")
	}

	token := signedToken(t, key)
	if _, err := v.ValidateToken(token); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("want ErrKeysUnavailable, got %v", err)
	}

	// The middleware answers 503, not 401, while keys are missing.
	mw := NewAuthMiddleware(v)
	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 while keys are missing, got %d", rec.Code)
	}

	up.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for !v.KeysLoaded() {
		if time.Now().After(deadline) {
			t.Fatal("background retry did not load the keys")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := v.ValidateToken(token); err != nil {
		t.Fatalf("ValidateToken after recovery: %v", err)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 after recovery, got %d", rec.Code)
	}
}

func TestStopIsIdempotent(t *testing.T) {
	var up atomic.Bool
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksServer(t, key, &up)
	cfg := testConfig(srv.URL)
	cfg.InitialFetchTimeout = -1
	v, _ := NewValidator(cfg)
	v.Stop()
	v.Stop()
}
