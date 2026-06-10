package authclient

import "testing"

func TestIsGatingExempt(t *testing.T) {
	cases := []struct {
		name string
		c    Claims
		want bool
	}{
		{"plain tenant user", Claims{SubscriptionStatus: "ACTIVE"}, false},
		{"admin is still gated", Claims{Roles: []string{"admin"}}, false},
		{"platform owner", Claims{IsPlatformOwner: true}, true},
		{"superuser role", Claims{Roles: []string{"superuser"}}, true},
		{"demo tenant", Claims{IsDemo: true}, true},
		{"service charge", Claims{BillingMode: "service_charge"}, true},
		{"recurring billing not exempt", Claims{BillingMode: "recurring"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.IsGatingExempt(); got != tc.want {
				t.Fatalf("IsGatingExempt() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOverageEnabled(t *testing.T) {
	off := Claims{}
	if off.OverageEnabled() {
		t.Fatal("default OverageEnabled() should be false")
	}
	on := Claims{AllowOverage: true}
	if !on.OverageEnabled() {
		t.Fatal("OverageEnabled() should reflect AllowOverage=true")
	}
}

func TestIsOverageEligibleLimit(t *testing.T) {
	metered := []string{
		"max_orders_per_day", "max_transactions_per_month", "api_calls_per_month",
		"sms_notifications_per_day", "live_tracking_requests_per_day", "routing_requests_per_day",
	}
	for _, k := range metered {
		if !IsOverageEligibleLimit(k) {
			t.Errorf("expected %q to be overage-eligible", k)
		}
	}
	structural := []string{
		"max_outlets", "max_devices", "max_cashiers", "max_tables", "max_riders",
		"inventory_max_warehouses", "max_wallets", "max_staff",
	}
	for _, k := range structural {
		if IsOverageEligibleLimit(k) {
			t.Errorf("expected structural cap %q to NOT be overage-eligible", k)
		}
	}
}
