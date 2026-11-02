package authclient

import (
	"encoding/json"
	"testing"
)

func TestAllowsUserService(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
		want   bool
	}{
		{"no claim: not decided, allowed", &Claims{}, true},
		{"service account", &Claims{IsService: true, UserServices: []string{}}, true},
		{"listed", &Claims{UserServices: []string{"inventory", "pos"}}, true},
		{"every service", &Claims{UserServices: []string{AllServices}}, true},
		{"not listed", &Claims{UserServices: []string{"pos"}}, false},
		{"empty list: no services", &Claims{UserServices: []string{}}, false},
	}
	for _, tc := range cases {
		if got := tc.claims.AllowsUserService("inventory"); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Events arrive as decoded JSON, so the list is []any.
func TestEventAllowsService(t *testing.T) {
	decode := func(s string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if ok, known := EventAllowsService(decode(`{"user_id":"x"}`), "inventory"); !ok || known {
		t.Fatal("an event without services must keep today's behaviour")
	}
	if ok, known := EventAllowsService(decode(`{"services":["pos","ordering"]}`), "inventory"); ok || !known {
		t.Fatal("inventory is not among the member's services")
	}
	if ok, known := EventAllowsService(decode(`{"services":["*"]}`), "inventory"); !ok || !known {
		t.Fatal("* allows every service")
	}
	if ok, known := EventAllowsService(decode(`{"services":[]}`), "pos"); ok || !known {
		t.Fatal("an empty list is a decided 'no services'")
	}
	if ok, known := EventAllowsService(decode(`{"services":null}`), "pos"); !ok || known {
		t.Fatal("null means not decided")
	}
}
