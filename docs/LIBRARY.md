# Avaje OAuth2 Library Definition

Avaje OAuth2 is a small, dependency-light library for **verifying JWT access
tokens** issued by an OIDC identity provider (Cognito, Entra ID, or any other
standards-based issuer) and for driving the **Authorization Code + PKCE**
login flow against Cognito's Hosted UI or Microsoft's Entra ID v2.0 endpoints.
It provides ready-made HTTP filters for `avaje-jex` and Helidon SE.

It is deliberately **not** a full authorization framework (no `@RolesAllowed`,
no request-matcher DSL) - it verifies tokens and exposes their claims
(`scope`, `roles`, `sub`, etc.) so the host application's own router/framework
can make its own per-route authorization decisions.

## Identity

- **Name**: Avaje OAuth2
- **Package**: `io.avaje.oauth2.*`
- **Description**: JWT access token verification + OIDC Authorization
  Code/PKCE login flow, with ready-made filters for avaje-jex and Helidon SE
- **Category**: Security / Authentication
- **Repository**: https://github.com/avaje/avaje-oauth2
- **Issues**: https://github.com/avaje/avaje-oauth2/issues

## Version & Requirements

- **Latest Release**: 1.5 (on Maven Central) - note: this `docs/` tree also
  describes newer capabilities (multi-issuer support, `roles`/`hasRole`,
  `requireScope`, `nbf`/`aud` validation, JWKS cache hygiene) present in this
  checkout but **not yet published** as a release; check the actual installed
  version's javadoc/tests if something described here doesn't compile.
- **Minimum Java Version**: 21+
- **Build Tool**: Maven

## Modules

| Module | Artifact | Purpose |
|---|---|---|
| Core | `avaje-oauth2-core` | `JwtVerifier` / `MultiIssuerJwtVerifier` (JWT signature + claims verification), `AccessToken` (parsed claims), `BearerChallenge` (RFC 6750 `WWW-Authenticate`), `RequiredScopes`, `Pkce`, `SignedJwt` |
| Jex filter | `avaje-oauth2-jex-jwtfilter` | `JwtAuthFilter` - an `avaje-jex` `HttpFilter` enforcing JWT auth |
| Helidon filter | `avaje-oauth2-helidon-jwtfilter` | `JwtAuthFilter` - a Helidon SE `Filter` enforcing JWT auth |
| Cognito OIDC client | `avaje-oauth2-oidc-cognito` | `CognitoOidc` - Authorization Code + PKCE client for AWS Cognito's Hosted UI |
| Entra OIDC client | `avaje-oauth2-oidc-entra` | `EntraOidc` - Authorization Code + PKCE client for Microsoft Entra ID (v2.0 endpoints) |

A typical resource-server-only setup (an API validating bearer tokens minted
elsewhere) only needs **core** + one filter module. The OIDC client modules
are only needed if this same application also drives the browser login
redirect flow itself (e.g. a BFF/gateway).

## Core APIs

### Token verification (`avaje-oauth2-core`)

| Type | Purpose |
|---|---|
| `JwtVerifier` | Verifies a single-issuer JWT's signature + standard claims (`exp`, `iat`, `nbf`, `iss`, optional `aud`) against a JWKS |
| `JwtVerifier.Builder` | `.issuer(...)`, `.jwksUri(...)`, `.audience(...)`, `.clockSkew(...)`, `.jwksMinRefreshInterval(...)`, `.keySource(...)`, `.clock(...)` |
| `MultiIssuerJwtVerifier` | Dispatches to one of several per-issuer `JwtVerifier`s based on the token's `iss` claim - accept tokens from multiple trusted issuers at once |
| `AccessToken` | Record of all parsed claims: `sub`, `scope`, `roles`, `audience`, `notBefore`, `email`, `upn`, `clientId`, etc, plus `hasScope`/`hasAnyScope`/`hasRole`/`hasAnyRole` helpers |
| `BearerChallenge` | Builds RFC 6750-compliant `WWW-Authenticate` header values (`missingToken()`, `invalidToken(...)`, `insufficientScope(...)`) |
| `RequiredScopes` | Path-prefix → required-scope(s) matcher used by `requireScope(...)` on both filters |
| `Pkce` | Generates/derives PKCE `code_verifier`/`code_challenge` (S256) pairs for the Authorization Code flow |
| `SignedJwt` | Low-level parsed-but-unverified JWT (header/payload/signature parts) |

### HTTP filters (`avaje-oauth2-jex-jwtfilter` / `avaje-oauth2-helidon-jwtfilter`)

Both filters share the same builder shape:

| Method | Purpose |
|---|---|
| `.permit(pathPrefix)` | Allow requests under this path prefix through without requiring a token |
| `.verifier(jwtVerifier)` | The `JwtVerifier` (or `MultiIssuerJwtVerifier`) to validate tokens with |
| `.bearerAuthoriser(authoriser)` | Optionally accept non-JWT bearer tokens (e.g. shared-secret API keys) alongside JWTs |
| `.requireScope(pathPrefix, anyOfScopes...)` | Reject (403) JWT-authenticated requests under this path prefix lacking all of the given scopes |
| `.build()` | Build the filter |

On success, both filters expose the verified `AccessToken`, principal, scope,
and roles as request/context attributes for downstream handlers to use for
their own authorization decisions (see
[role-and-scope-authorization.md](guides/role-and-scope-authorization.md)).

### OIDC login clients (`avaje-oauth2-oidc-cognito` / `avaje-oauth2-oidc-entra`)

| Method | Purpose |
|---|---|
| `.loginUrl(nonce, state)` / `.loginUrl(nonce, state, codeChallenge)` | Build the Hosted UI / Entra authorize URL (with or without PKCE) |
| `.obtainTokens(code)` / `.obtainTokens(code, codeVerifier)` | Exchange the authorization code for tokens (with or without PKCE) |
| `.refreshAccessToken(refreshToken)` | Refresh an access token |

## Features

### ✅ Included

- RS256 JWT signature verification against a remote JWKS (auto-derived from
  `issuer` or explicitly set), or a static/custom `JwtKeySource`
- Standard time-based claim validation: `exp`, `iat`, `nbf` (always checked
  when present, per RFC 7519 §4.1.5)
- Optional `aud` (audience) validation - required for Entra ID (whose access
  tokens always carry `aud`); Cognito tokens don't carry `aud` at all
- JWKS cache hygiene: stale/rotated-out keys are evicted (not merged forever),
  and unknown-`kid`-triggered refetches are throttled (default 60s,
  configurable) to protect the IdP's JWKS endpoint from abuse
- RFC 6750-compliant `WWW-Authenticate` challenges on 401 (missing/invalid
  token) and 403 (insufficient scope)
- 401 vs 403 distinction via optional `requireScope(pathPrefix, scopes...)`
  path-prefix rules
- Unified `roles()`/`hasRole()`/`hasAnyRole()` across Entra ID's `roles` claim
  and Cognito's `cognito:groups` claim
- `scope()`/`hasScope()`/`hasAnyScope()` for delegated-permission scopes
  (`scope`/`scp` claim)
- Multi-issuer support via `MultiIssuerJwtVerifier` - accept tokens from
  multiple trusted issuers (e.g. both Cognito and Entra during a phased
  migration) behind one filter
- PKCE (RFC 7636) support for public clients doing the Authorization Code flow
- Ready-made filters for `avaje-jex` and Helidon SE

### ❌ Not Included (by design)

- **No full authorization/RBAC framework** - no `@RolesAllowed`, no
  request-matcher DSL, no HTTP-method-specific rule engine. `requireScope` is
  intentionally path-prefix-only; anything more granular is the host
  application's own routing's job, since it already has full path+method
  visibility and `AccessToken.hasRole()`/`hasAnyRole()` gives it everything it
  needs to make that decision itself
- **No session/cookie management** - this is a bearer-token verifier and an
  Authorization Code exchange client, not a full BFF session framework
- **No token storage/persistence** - callers are responsible for persisting
  tokens returned by `obtainTokens`/`refreshAccessToken`
- **No built-in support for other OAuth2 grant types** (client credentials,
  device code, etc.) - only Authorization Code (+ PKCE) is provided

## Use Cases

### ✅ Perfect For

- Resource servers (REST APIs) that need to verify bearer JWTs issued by
  Cognito or Entra ID
- Migrating an existing Cognito-backed API to Entra ID (or vice versa)
  without a hard cutover, via `MultiIssuerJwtVerifier`
- avaje-jex or Helidon SE services that want a drop-in JWT auth filter
- BFF/gateway apps that need to drive the browser login redirect flow
  (Authorization Code + PKCE) against Cognito's Hosted UI or Entra ID

### ❌ Not Recommended For

- Applications needing a full authorization/RBAC framework with declarative
  per-route rules - pair this library's claim data with your own
  framework/router instead
- Non-JWT opaque token introspection flows (RFC 7662) - not implemented;
  use `bearerAuthoriser` to plug in your own opaque-token check alongside JWT
  verification

## Quick Start

### Add to Project (Maven)

```xml
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-core</artifactId>
    <version>1.5</version>
</dependency>

<!-- pick one filter module for your web framework -->
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-jex-jwtfilter</artifactId>
    <version>1.5</version>
</dependency>
```

### Minimal Example (avaje-jex)

```java
String issuer = "https://cognito-idp.<region>.amazonaws.com/<region>_<poolId>";

JwtVerifier jwtVerifier = JwtVerifier.builder()
    .issuer(issuer)
    .build();

JwtAuthFilter filter = JwtAuthFilter.builder()
    .permit("/health")
    .verifier(jwtVerifier)
    .build();

Jex.create()
    .filter(filter)
    .port(8080)
    .start();
```

See [guides/getting-started.md](guides/getting-started.md) for the full
walkthrough (including Helidon SE and Entra ID variants).

## Common Tasks & Guides

| Task | Guide |
|---|---|
| Verify JWTs and wire up a filter for the first time | [getting-started.md](guides/getting-started.md) |
| Drive the browser login redirect flow (Authorization Code + PKCE) | [oidc-login-flow.md](guides/oidc-login-flow.md) |
| Enforce required scopes/roles per route | [role-and-scope-authorization.md](guides/role-and-scope-authorization.md) |
| Accept tokens from both Cognito and Entra during a migration | [multi-issuer-migration.md](guides/multi-issuer-migration.md) |
| Tune JWKS caching/refresh behaviour | [jwks-tuning.md](guides/jwks-tuning.md) |
| Understand Entra ID vs Cognito claim differences | [entra-vs-cognito-claims.md](guides/entra-vs-cognito-claims.md) |

**Full Guides Index**: See [guides/README.md](guides/README.md)

## Design Philosophy

1. **Verification, not authorization** - this library's job ends at "here is
   a verified `AccessToken` with these claims"; per-route authorization
   decisions belong to the host application's own router
2. **Small, explicit surface area** - no classpath scanning, no annotations
   driving security decisions, no hidden magic; every check is a plain method
   call you can read top-to-bottom
3. **Safe by default, tunable when needed** - e.g. `nbf`/`exp`/`iat` are
   always checked, but `clockSkew`/`jwksMinRefreshInterval` are tunable;
   `aud` validation is opt-in because Cognito tokens don't carry it
4. **Composition over configuration** - `MultiIssuerJwtVerifier` is a plain
   `JwtVerifier` built by composing other `JwtVerifier`s, not a special-cased
   mode baked into `DJwtVerifier`

## AI Agent Instructions

### For Claude, GPT-4, and Web-Based Agents

This `LIBRARY.md` file is your primary source of truth for Avaje OAuth2. When
answering questions about this library:

1. **Check this file first** for module boundaries, capabilities, and use cases
2. **Route to specific guides** in the "Common Tasks & Guides" table above
3. **Remember the design boundary**: this library verifies tokens and exposes
   claims; it does not do per-route authorization itself - don't invent a
   request-matcher DSL that doesn't exist
4. **Cognito vs Entra claim differences matter** - see
   [entra-vs-cognito-claims.md](guides/entra-vs-cognito-claims.md) before
   writing code that assumes a claim is always present (e.g. `aud`, `email`,
   `upn` are Entra-only or Entra-flavoured; `roles()` is sourced differently
   per provider)

**Key Facts to Remember**:
- Minimum Java: 21+
- `requireScope` is path-prefix only, not method-specific - by design
- `aud` validation is opt-in (`.audience(...)`) - required for Entra, unset
  for Cognito
- `nbf`/`exp`/`iat` are always validated when present, not opt-in
- `MultiIssuerJwtVerifier` is how you support more than one trusted issuer

---

## Notes for Library Maintainers

### When to Update This File

- ✅ New release (update version number)
- ✅ New major feature (add to features list + new guide)
- ✅ Breaking change to a public API described here
- ✅ New guide added (add to "Common Tasks & Guides" table)
- ❌ Don't update for every bug fix

### Linking This File

In the root `README.md`, add:

```markdown
## Documentation

- **Full Reference**: See [docs/LIBRARY.md](docs/LIBRARY.md)
- **Guides**: Step-by-step guides for common tasks in [docs/guides/README.md](docs/guides/README.md)
```

---

**Template Version**: 1.0 (adapted from avaje-nima's `docs/LIBRARY.md`)
**Last Updated**: 2026-07
