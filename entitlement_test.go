package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestEntitlementClientUsesService(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.Header.Get("X-Tenant-ID") {
		case "plan":
			_, _ = w.Write([]byte(`{"active_service_tags":["pos","erp"]}`))
		case "exempt":
			_, _ = w.Write([]byte(`{"billing_mode":"exempt"}`))
		case "payg":
			_, _ = w.Write([]byte(`{"billing_mode":"service_charge"}`))
		case "none":
			http.NotFound(w, r)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	c := NewEntitlementClient(srv.URL, "k")
	ctx := context.Background()

	cases := []struct {
		tenant, tag string
		want        bool
	}{
		{"plan", "erp", true},
		{"plan", "library", false},
		{"exempt", "library", true},
		{"payg", "maskani", true},
		{"none", "erp", false},
		{"outage", "erp", true},
	}
	for _, tc := range cases {
		if got := c.UsesService(ctx, tc.tenant, tc.tag); got != tc.want {
			t.Errorf("%s/%s = %v, want %v", tc.tenant, tc.tag, got, tc.want)
		}
	}

	before := atomic.LoadInt32(&hits)
	c.UsesService(ctx, "plan", "pos")
	c.UsesService(ctx, "plan", "pos")
	if atomic.LoadInt32(&hits) != before {
		t.Error("expected cached snapshot, got extra requests")
	}
	c.UsesService(ctx, "outage", "erp")
	if atomic.LoadInt32(&hits) != before+1 {
		t.Error("failures must not be cached")
	}
}

func TestEntitlementClientNotWiredAllows(t *testing.T) {
	var c *EntitlementClient
	if !c.UsesService(context.Background(), "t", "erp") {
		t.Error("nil client must allow")
	}
	if !NewEntitlementClient("", "").UsesService(context.Background(), "t", "erp") {
		t.Error("blank url must allow")
	}
}
