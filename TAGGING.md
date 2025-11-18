# Tagging and Versioning Guide

## Current Approach: Monorepo with Replace Directives

Since `shared/auth-client` is part of the BengoBox monorepo, we use `replace` directives in all service `go.mod` files.

## Tagging the Library

### Step 1: Tag the Repository

Tag the entire BengoBox repository with a version tag:

```bash
# At repository root
git tag shared-auth-client/v0.1.0
git push origin shared-auth-client/v0.1.0
```

### Step 2: Update Service go.mod Files

All services already have:
```go
replace github.com/bengobox/shared/auth-client => ../shared/auth-client

require (
    github.com/bengobox/shared/auth-client v0.1.0
)
```

The `replace` directive ensures local development works, while the version (`v0.1.0`) documents which version is being used.

### Step 3: Verify

```bash
# In any service directory
go mod tidy
go build ./cmd/api
```

## Future: Extract to Separate Repository

If you want to extract `shared/auth-client` to its own repository:

1. **Create new repository**: `github.com/Bengo-Hub/shared-auth-client`
2. **Copy contents**: Move all files from `shared/auth-client/` to the new repo
3. **Tag**: `git tag v0.1.0 && git push origin v0.1.0`
4. **Update services**: Remove `replace` directives and use:
   ```go
   require (
       github.com/Bengo-Hub/shared-auth-client v0.1.0
   )
   ```

## Versioning Strategy

- **v0.MAJOR.MINOR** for pre-1.0 releases
- **v1.0.0** for stable API
- Increment MAJOR for breaking changes
- Increment MINOR for new features (backward compatible)
- Increment PATCH for bug fixes

## Current Version

**v0.1.0** - Initial release with JWKS validation, middleware, and production-ready features.

