package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var memberOutletsHTTP = &http.Client{Timeout: 5 * time.Second}

// MemberOutletLimit reads the outlets a member is limited to from auth-api, for tokens a service mints
// itself (terminal PIN sessions) that never pass through auth. An empty list means no limit. On an
// error the caller decides; the terminal logins using this carry on with no limit, so an auth outage
// does not lock staff out of the till.
func MemberOutletLimit(ctx context.Context, authURL, apiKey, tenantID, userID string) ([]string, error) {
	authURL, apiKey = strings.TrimRight(strings.TrimSpace(authURL), "/"), strings.TrimSpace(apiKey)
	if authURL == "" || apiKey == "" || tenantID == "" || userID == "" {
		return nil, nil
	}
	endpoint := fmt.Sprintf("%s/api/v1/s2s/tenants/%s/members/%s/outlet-limit", authURL, url.PathEscape(tenantID), url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)
	resp, err := memberOutletsHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("member outlet limit: HTTP %d", resp.StatusCode)
	}
	var body struct {
		OutletIDs []string `json:"outlet_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.OutletIDs, nil
}
