# Guides

**Recommended:** For all downstream projects, add an AGENTS.md at the project root. AGENTS.md should point both AI and human developers to the official agent/developer guides for all major frameworks used (e.g., Avaje OAuth2, Avaje Nima, Ebean ORM). This ensures fast, accurate onboarding and discoverability of best practices.

See: [how-to-add-AGENTS-md.md](how-to-add-AGENTS-md.md) for a step-by-step guide and template.

See also: [AGENTS.md](AGENTS.md) - a minimal template for AI agent onboarding and automation in avaje-oauth2 projects.

Step-by-step guides written as instructions for AI agents and developers working with
**avaje-oauth2**.

## Project context

**avaje-oauth2** verifies JWT access tokens (Cognito, Entra ID, or any
standards-based OIDC issuer) and drives the OAuth2 Authorization Code + PKCE
login flow. It provides ready-made filters for avaje-jex and Helidon SE. It
does **not** implement a full authorization/RBAC framework - see
[docs/LIBRARY.md](../LIBRARY.md) for the design boundary.

---

## Getting started

| Guide | Description |
|-------|-------------|
| [Getting started](getting-started.md) | Build a `JwtVerifier` for Cognito or Entra ID and wire it into the `avaje-jex` or Helidon SE `JwtAuthFilter` |
| [OIDC login flow](oidc-login-flow.md) | Drive the browser Authorization Code + PKCE redirect flow with `CognitoOidc`/`EntraOidc` |

## Authorization

| Guide | Description |
|-------|-------------|
| [Role and scope authorization](role-and-scope-authorization.md) | Use `AccessToken.hasScope`/`hasRole`, `requireScope(...)`, and the context attributes exposed by both filters to make per-route authorization decisions |

## Migration

| Guide | Description |
|-------|-------------|
| [Multi-issuer migration](multi-issuer-migration.md) | Accept tokens from two issuers at once (e.g. Cognito + Entra ID) with `MultiIssuerJwtVerifier`, for a phased cutover instead of a hard flag-day switch |
| [Entra ID vs Cognito claims](entra-vs-cognito-claims.md) | Claim-by-claim differences between the two providers (`aud`, `roles`/`cognito:groups`, `upn`/`email`) and what to watch for when migrating |

## Tuning

| Guide | Description |
|-------|-------------|
| [JWKS tuning](jwks-tuning.md) | Configure `jwksMinRefreshInterval`, `clockSkew`, and custom `JwtKeySource` implementations |

---

## Helping AI agents find these guides

### Agent Skills (recommended)

Pre-packaged skills for AI coding agents are available at:
[github.com/avaje/skills](https://github.com/avaje/skills)

```bash
git clone git@github.com:avaje/skills.git ~/.agents/avaje-skills
ln -sf ~/.agents/avaje-skills/avaje-oauth2 ~/.agents/skills/avaje-oauth2
```

Works with [pi](https://github.com/mariozechner/pi-coding-agent),
[Claude Code](https://docs.anthropic.com/en/docs/claude-code), and any
[Agent Skills](https://agentskills.io) compatible harness.

### Other approaches

AI coding agents can only follow these guides if they know they exist. The recommended approach is to add an AGENTS.md at the project root, pointing both AI and human developers to the official agent/developer guides for all major frameworks used.

See: [how-to-add-AGENTS-md.md](how-to-add-AGENTS-md.md) for a step-by-step guide and template.

### Project `AGENTS.md` (recommended)

```markdown
# AI Agent Instructions

This project uses [avaje-oauth2](https://github.com/avaje/avaje-oauth2) for JWT verification and OIDC login. Step-by-step guides (JWT verification setup, role/scope authorization, multi-issuer migration) are at:

**https://github.com/avaje/avaje-oauth2/tree/HEAD/docs/guides/**
```

### GitHub Copilot - `.github/copilot-instructions.md`

`docs/guides/README.md` (this file) is the single source of truth for AI agent
instructions in this repository. For **your project** that uses avaje-oauth2 as a
dependency, add the following to your `.github/copilot-instructions.md`:

```markdown
## avaje-oauth2

This project uses [avaje-oauth2](https://github.com/avaje/avaje-oauth2) for JWT
verification and OIDC login. Step-by-step guides are at:
https://github.com/avaje/avaje-oauth2/tree/main/docs/guides/

Key guides (fetch and follow these when performing the relevant task):
- Getting started: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/getting-started.md
- OIDC login flow: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/oidc-login-flow.md
- Role and scope authorization: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/role-and-scope-authorization.md
- Multi-issuer migration: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/multi-issuer-migration.md
- JWKS tuning: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/jwks-tuning.md
- Entra ID vs Cognito claims: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/entra-vs-cognito-claims.md
```

### Claude Code - `CLAUDE.md`

Same content as above - Claude Code reads `CLAUDE.md` at the project root.
