package authclient

import (
	"encoding/json"
	"testing"
)

// The amr and mfa_enrollment_required claims auth-api issues decode into Claims, and HasMFA reads
// only the "mfa" method.
func TestClaimsDecodeAMRAndEnrollment(t *testing.T) {
	cases := []struct {
		raw        string
		mfa        bool
		enrollment bool
	}{
		{`{"amr":["pwd","totp","mfa"]}`, true, false},
		{`{"amr":["pwd"]}`, false, false},
		{`{"amr":["pwd"],"mfa_enrollment_required":true}`, false, true},
		{`{}`, false, false},
	}
	for _, c := range cases {
		var claims Claims
		if err := json.Unmarshal([]byte(c.raw), &claims); err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if claims.HasMFA() != c.mfa || claims.MFAEnrollmentRequired != c.enrollment {
			t.Fatalf("%s: mfa %v enrolment %v", c.raw, claims.HasMFA(), claims.MFAEnrollmentRequired)
		}
	}
	var nilClaims *Claims
	if nilClaims.HasMFA() {
		t.Fatal("nil claims have no mfa")
	}
}
