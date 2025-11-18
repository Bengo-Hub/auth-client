# Production Deployment Guide

## Overview

The `shared/auth-client` library is used across all BengoBox microservices for JWT validation and authentication. This guide explains how to deploy and consume it in production environments.

## Module Structure

```
shared/auth-client/
├── go.mod                    # Module: github.com/bengobox/shared/auth-client
├── claims.go                 # JWT claims structure
├── validator.go              # JWKS-based token validation
├── middleware.go             # HTTP middleware (chi)
├── gin.go                    # Gin-specific middleware
└── README.md                 # Usage documentation
```

## Deployment Strategies

### Option 1: Go Workspace (Local Development) ✅ Recommended for Local

Use `go.work` at the repository root for local development:

```bash
# At repository root
go work init ./auth-service ./Cafe/cafe-backend ./notifications-app ./treasury-app ./shared/auth-client
```

**Pros:**
- No code changes needed
- Works seamlessly with `go build`, `go test`, `go run`
- All modules see each other automatically

**Cons:**
- Only works in monorepo structure
- Not suitable for separate deployments

### Option 2: Monorepo with Replace Directives ✅ Recommended for Monorepo

Since all services are in the same monorepo (BengoBox), use `replace` directives with tagged versions:

#### Setup Steps:

1. **Tag the repository** (tags the entire monorepo):
   ```bash
   # At repository root
   git tag shared-auth-client/v0.1.0
   git push origin shared-auth-client/v0.1.0
   ```

2. **Service go.mod** (keep replace, use tagged version):
   ```go
   replace github.com/bengobox/shared/auth-client => ../shared/auth-client
   
   require (
       github.com/bengobox/shared/auth-client v0.1.0
   )
   ```

3. **For local development**, `go.work` handles everything automatically.

4. **For CI/CD**, `replace` directives work seamlessly - no additional configuration needed.

**Note:** If you prefer to extract `shared/auth-client` to its own repository in the future:
- Create `github.com/Bengo-Hub/shared-auth-client` repository
- Move `shared/auth-client` contents to the new repo
- Tag as `v0.1.0`
- Update all services to remove `replace` and use: `github.com/Bengo-Hub/shared-auth-client v0.1.0`

### Option 3: Git Submodule (Alternative)

If services are in separate repositories:

```bash
# In each service repo
git submodule add https://github.com/bengobox/shared-auth-client.git shared/auth-client

# In go.mod
replace github.com/bengobox/shared/auth-client => ./shared/auth-client
```

### Option 4: Copy Library (Not Recommended)

Copy the library into each service (maintains duplication, not recommended).

## CI/CD Configuration

### GitHub Actions Example

```yaml
- name: Setup Go
  uses: actions/setup-go@v4
  with:
    go-version: '1.24'
  
- name: Configure private modules
  run: |
    git config --global url."https://${{ secrets.GITHUB_TOKEN }}@github.com/".insteadOf "https://github.com/"
    export GOPRIVATE=github.com/bengobox/*
    export GONOPROXY=github.com/bengobox/*
    export GONOSUMDB=github.com/bengobox/*

- name: Build
  run: go build ./cmd/api
```

### Dockerfile Example

```dockerfile
FROM golang:1.24-alpine AS builder

# Configure private modules
ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o api ./cmd/api

FROM alpine:latest
COPY --from=builder /app/api /api
CMD ["/api"]
```

## Versioning Strategy

- **Semantic Versioning**: Follow `v0.MAJOR.MINOR` for pre-1.0 releases
- **Breaking Changes**: Increment MAJOR version
- **New Features**: Increment MINOR version
- **Bug Fixes**: Increment PATCH version

Example:
- `v0.1.0` - Initial release
- `v0.1.1` - Bug fixes
- `v0.2.0` - New features (backward compatible)
- `v1.0.0` - Stable API

## Service Integration Checklist

Each service integrating `shared/auth-client` should:

- [ ] Remove local `replace` directive (for production)
- [ ] Add proper version constraint in `go.mod`
- [ ] Configure CI/CD for private module access
- [ ] Test authentication flow end-to-end
- [ ] Document auth-service URL and JWKS endpoint
- [ ] Set up monitoring for JWKS fetch failures
- [ ] Configure proper caching (JWKS cache TTL)

## Environment Variables

Each service needs these environment variables:

```bash
# Auth Service Configuration
AUTH_SERVICE_URL=https://auth.bengobox.local
AUTH_ISSUER=https://auth.bengobox.local
AUTH_AUDIENCE=bengobox
AUTH_JWKS_URL=https://auth.bengobox.local/api/v1/.well-known/jwks.json

# Optional: Cache configuration
AUTH_JWKS_CACHE_TTL=3600s
AUTH_JWKS_REFRESH_INTERVAL=300s
```

## Monitoring & Observability

Monitor these metrics:
- JWKS fetch success/failure rate
- JWKS cache hit/miss ratio
- Token validation latency
- Token validation failure reasons
- JWKS refresh interval compliance

## Troubleshooting

### Issue: `cannot find module providing package`
**Solution**: Ensure `GOPRIVATE` is set and git credentials are configured.

### Issue: `401 Unauthorized` when fetching JWKS
**Solution**: Verify auth-service is accessible and JWKS endpoint is public.

### Issue: `key not found in JWKS`
**Solution**: Check if auth-service has rotated keys. JWKS should auto-refresh, but verify refresh interval.

### Issue: `invalid issuer` or `invalid audience`
**Solution**: Verify `AUTH_ISSUER` and `AUTH_AUDIENCE` match token claims.

## Migration Path

### From Local Replace to Production Module

1. **Tag current version:**
   ```bash
   cd shared/auth-client
   git tag v0.1.0
   git push origin v0.1.0
   ```

2. **Update each service:**
   ```bash
   # Remove replace directive
   # Update require to use version
   go mod edit -require=github.com/bengobox/shared/auth-client@v0.1.0
   go mod edit -dropreplace=github.com/bengobox/shared/auth-client
   go mod tidy
   ```

3. **Test locally** (use go.work for development)

4. **Deploy** with CI/CD configured for private modules

## Best Practices

1. **Always use tagged versions** in production (never `@latest` or `@main`)
2. **Pin versions** in `go.mod` for reproducible builds
3. **Test locally** with `go.work` before deploying
4. **Monitor JWKS** fetch failures and cache performance
5. **Document breaking changes** in CHANGELOG.md
6. **Keep backward compatibility** within MAJOR versions

