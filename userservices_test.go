package authclient

import "testing"

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
