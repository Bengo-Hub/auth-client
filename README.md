# Shared Auth Client Library

A Go library for validating JWT tokens issued by auth-service using JWKS. This library is shared across all BengoBox microservices for consistent authentication and authorization.

## Installation

### Local Development (Go Workspace)

The repository uses `go.work` at the root for local development. No additional setup needed:

```bash
# At repository root
go work use ./shared/auth-client
```

### Production (Private Go Module)

For production deployments, consume as a private Go module:

```go
require (
    github.com/bengobox/shared/auth-client v0.1.0
)
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment strategies and CI/CD configuration.

## Usage

### Chi Router

```go
import (
    "github.com/bengobox/shared/auth-client"
    authclient "github.com/bengobox/shared/auth-client"
)

// Initialize validator
config := authclient.DefaultConfig(
    "https://auth.bengobox.local/api/v1/.well-known/jwks.json",
    "https://auth.bengobox.local",
    "bengobox",
)
validator, err := authclient.NewValidator(config)
if err != nil {
    log.Fatal(err)
}
defer validator.Stop()

// Create middleware
authMiddleware := authclient.NewAuthMiddleware(validator)

// Apply to routes
router.Route("/api/v1", func(r chi.Router) {
    r.Use(authMiddleware.RequireAuth)
    // Protected routes...
})

// Extract claims in handler
claims, ok := authclient.ClaimsFromContext(r.Context())
if !ok {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}

userID, _ := claims.UserID()
tenantID, _ := claims.TenantUUID()
```

### Gin Router

```go
import (
    authclient "github.com/bengobox/shared/auth-client"
    "github.com/gin-gonic/gin"
)

// Initialize validator (same as above)
validator, _ := authclient.NewValidator(config)
authMiddleware := authclient.NewAuthMiddleware(validator)

// Apply middleware
router.Use(authclient.GinMiddleware(authMiddleware))

// Extract claims
claims, ok := authclient.ClaimsFromGinContext(c)
if !ok {
    c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
    return
}

// Require specific scopes
router.Use(authclient.GinRequireScope("read:orders", "write:orders"))
```

## Features

- ✅ JWKS fetching and caching with automatic refresh
- ✅ RS256 signature validation
- ✅ Issuer and audience validation
- ✅ Scope checking helpers (`HasScope`, `HasAnyScope`, `HasAllScopes`)
- ✅ HTTP middleware for chi and gin routers
- ✅ Production-ready with error handling and observability hooks
- ✅ Thread-safe key caching with singleflight deduplication

## Configuration

```go
config := authclient.Config{
    JWKSUrl:         "https://auth.bengobox.local/api/v1/.well-known/jwks.json",
    Issuer:          "https://auth.bengobox.local",
    Audience:        "bengobox",
    CacheTTL:        1 * time.Hour,        // How long to cache JWKS
    RefreshInterval: 5 * time.Minute,      // Background refresh interval
    HTTPClient:      &http.Client{Timeout: 10 * time.Second},
}
```

## Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for:
- Production deployment strategies
- CI/CD configuration examples
- Versioning strategy
- Troubleshooting guide

