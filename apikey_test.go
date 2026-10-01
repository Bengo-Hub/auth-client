package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAPIKeyValidatorConcurrentAndCached(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("X-API-Key") == "bad" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"tenant_id":"t1","scopes":["a"],"subscription_limits":{"x":1}}`))
	}))
	defer srv.Close()
	v := NewAPIKeyValidator(srv.URL, nil)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "good"
			if i%2 == 0 {
				key = "bad"
			}
			res, err := v.ValidateAPIKeyFull(context.Background(), key)
			if key == "good" {
				if err != nil || res.TenantID != "t1" {
					t.Errorf("good key failed: %v", err)
					return
				}
				res.Scopes[0] = "mutated" // must not leak into the cache
			}
		}(i)
	}
	wg.Wait()
	if c := atomic.LoadInt32(&calls); c > 4 {
		t.Fatalf("expected a handful of upstream calls, got %d", c)
	}
	res, _ := v.ValidateAPIKeyFull(context.Background(), "good")
	if res.Scopes[0] != "a" {
		t.Fatal("cached entry was mutated by a caller")
	}

	v.Invalidate("good")
	before := atomic.LoadInt32(&calls)
	_, _ = v.ValidateAPIKeyFull(context.Background(), "good")
	if atomic.LoadInt32(&calls) != before+1 {
		t.Fatal("Invalidate must force a fresh lookup")
	}
}
