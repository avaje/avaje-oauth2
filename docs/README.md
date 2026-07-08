# avaje-oauth2 Documentation

This directory contains official guides and onboarding instructions for both AI agents and human developers working with avaje-oauth2.

- For a comprehensive capability reference, see [docs/LIBRARY.md](LIBRARY.md).
- For step-by-step task guides, see [docs/guides/](guides/).
- For AI agent onboarding, see [docs/guides/AGENTS.md](guides/AGENTS.md).

**Recommended for downstream projects:**
Add an AGENTS.md at your project root to guide both AI and human developers to the official avaje-oauth2 and other framework guides. This improves discoverability and onboarding for all contributors.

## Quick links

- Guide index: https://github.com/avaje/avaje-oauth2/tree/HEAD/docs/guides/
- How to add AGENTS.md: https://github.com/avaje/avaje-oauth2/blob/HEAD/docs/guides/how-to-add-AGENTS-md.md

## About avaje-oauth2

avaje-oauth2 is a small, dependency-light library for:
- Verifying JWT access tokens issued by Cognito, Entra ID, or any standards-based OIDC issuer
- Driving the OAuth2 Authorization Code + PKCE login flow against Cognito's Hosted UI or Entra ID
- Ready-made HTTP filters for [avaje-jex](https://avaje.io/jex/) and [Helidon SE](https://helidon.io/)

It is a verification/claims-exposure library, not a full authorization framework - see [docs/LIBRARY.md](LIBRARY.md) for the design philosophy.

---

For detailed guides, see [docs/guides/README.md](guides/README.md).
