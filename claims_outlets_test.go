package authclient

import "testing"

// A limited manager is held to their outlets; everyone else is untouched, and an admin can never be
// limited, whatever the token says.
func TestOutletRestriction(t *testing.T) {
	limited := &Claims{Roles: []string{"manager"}, OutletIDs: []string{"a", "b"}, OutletID: "b", IsHQUser: true}
	if !limited.OutletRestricted() || limited.CanAccessAllOutlets() {
		t.Fatal("a limited manager must not see all outlets, even in an HQ session")
	}
	if !limited.AllowsOutlet("A") || limited.AllowsOutlet("c") {
		t.Fatal("a limited manager gets their outlets and only those")
	}
	if limited.RestrictedHomeOutlet() != "b" {
		t.Fatalf("home = %q, want the token's allowed outlet", limited.RestrictedHomeOutlet())
	}
	elsewhere := &Claims{Roles: []string{"manager"}, OutletIDs: []string{"a"}, OutletID: "z"}
	if elsewhere.RestrictedHomeOutlet() != "a" {
		t.Fatalf("home = %q, want the first assigned when the token's outlet is not allowed", elsewhere.RestrictedHomeOutlet())
	}

	open := &Claims{Roles: []string{"manager"}, IsHQUser: true}
	if open.OutletRestricted() || !open.AllowsOutlet("anything") || open.RestrictedHomeOutlet() != "" {
		t.Fatal("no list means no limit")
	}
	if !open.CanAccessAllOutlets() {
		t.Fatal("an HQ session with no list keeps all outlets")
	}

	owner := &Claims{IsPlatformOwner: true, OutletIDs: []string{"a"}}
	if owner.OutletRestricted() || !owner.CanAccessAllOutlets() {
		t.Fatal("a platform owner is never limited")
	}
}
