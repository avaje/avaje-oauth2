# AGENTS.md - avaje-oauth2

This project uses [avaje-oauth2](https://github.com/avaje/avaje-oauth2) for JWT access token verification and/or OIDC Authorization Code + PKCE login.

## AI Agent Instructions

Step-by-step guides for common tasks (JWT verification setup, role/scope authorization, multi-issuer migration, JWKS tuning) are at:

**https://github.com/avaje/avaje-oauth2/tree/HEAD/docs/guides/**

Key guides (fetch and follow when performing the relevant task):
- Getting started: https://raw.githubusercontent.com/avaje/avaje-oauth2/HEAD/docs/guides/getting-started.md
- OIDC login flow: https://raw.githubusercontent.com/avaje/avaje-oauth2/HEAD/docs/guides/oidc-login-flow.md
- Role and scope authorization: https://raw.githubusercontent.com/avaje/avaje-oauth2/HEAD/docs/guides/role-and-scope-authorization.md
- Multi-issuer migration: https://raw.githubusercontent.com/avaje/avaje-oauth2/HEAD/docs/guides/multi-issuer-migration.md
- JWKS tuning: https://raw.githubusercontent.com/avaje/avaje-oauth2/HEAD/docs/guides/jwks-tuning.md
- Entra ID vs Cognito claims: https://raw.githubusercontent.com/avaje/avaje-oauth2/HEAD/docs/guides/entra-vs-cognito-claims.md

## Key design boundary to remember

avaje-oauth2 verifies tokens and exposes claims (`AccessToken.hasRole()`,
`hasScope()`, etc) - it does **not** implement per-route authorization itself
beyond simple path-prefix `requireScope(...)` rules. Do not invent a
request-matcher/RBAC DSL that doesn't exist in this library; per-route
authorization decisions belong in the host application's own router.

Agents: Before performing any avaje-oauth2-related task, fetch and follow the relevant guide above.
