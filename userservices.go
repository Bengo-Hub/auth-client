package authclient

// A service keeps a local copy of a user (its user table, roles, outlets, PIN) only when the user
// is meant to work in it. auth-api decides that once (platform admins and exempt tenants: every
// service; tenant admins: the plan's services; other members: the services a tenant admin
// assigned, backed by a role) and sends it as the `user_services` token claim and as `services`
// on auth.user created/updated/pin_set events. These helpers are the one reading of both; an
// absent list always means "not decided", never "no services", so a lookup failure in auth-api
// can never make a service drop its users.

// AllServices is the service list entry meaning every service.
const AllServices = "*"

// AllowsUserService reports whether the caller's token lets serviceTag keep a local user for it
// (just-in-time provisioning). Service accounts, and tokens without the claim, are allowed.
func (c *Claims) AllowsUserService(serviceTag string) bool {
	if c == nil || c.IsService || c.UserServices == nil {
		return true
	}
	return containsService(c.UserServices, serviceTag)
}

// EventUserServices reads `services` from an auth.user event payload. known=false when the
// payload has no list (older events, or auth-api could not decide).
func EventUserServices(data map[string]any) (services []string, known bool) {
	raw, ok := data["services"]
	if !ok || raw == nil {
		return nil, false
	}
	switch v := raw.(type) {
	case []string:
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, false
	}
}

// EventAllowsService reports whether an auth.user event lets serviceTag keep a local copy of the
// user. known=false (no list on the event) means: keep today's behaviour.
func EventAllowsService(data map[string]any, serviceTag string) (allowed, known bool) {
	services, known := EventUserServices(data)
	if !known {
		return true, false
	}
	return containsService(services, serviceTag), true
}

func containsService(services []string, serviceTag string) bool {
	for _, s := range services {
		if s == AllServices || s == serviceTag {
			return true
		}
	}
	return false
}
