[![Build](https://github.com/avaje/avaje-oauth2/actions/workflows/build.yml/badge.svg)](https://github.com/avaje/avaje-oauth2/actions/workflows/build.yml)
[![avaje-oauth2 EA](https://github.com/avaje/avaje-oauth2/actions/workflows/jdk-ea.yml/badge.svg)](https://github.com/avaje/avaje-oauth2/actions/workflows/jdk-ea.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.avaje/avaje-oauth2-core.svg?label=Maven%20Central)](https://mvnrepository.com/artifact/io.avaje/avaje-oauth2-core)

# avaje-oauth2

JWT access token verification (Cognito, Entra ID, or any standards-based OIDC
issuer) and OAuth2 Authorization Code + PKCE login, with ready-made HTTP
filters for [avaje-jex](https://avaje.io/jex/) and [Helidon SE](https://helidon.io/).

## Modules

| Module | Purpose |
|---|---|
| [avaje-oauth2-core](avaje-oauth2-core/README.md) | `JwtVerifier` / `MultiIssuerJwtVerifier`, `AccessToken`, `BearerChallenge`, `Pkce` |
| [avaje-oauth2-jex-jwtfilter](avaje-oauth2-jex-jwtfilter/README.md) | `JwtAuthFilter` for `avaje-jex` |
| [avaje-oauth2-helidon-jwtfilter](avaje-oauth2-helidon-jwtfilter/README.md) | `JwtAuthFilter` for Helidon SE |
| [avaje-oauth2-oidc-cognito](avaje-oauth2-oidc-cognito/README.md) | `CognitoOidc` - Authorization Code + PKCE client for AWS Cognito |
| [avaje-oauth2-oidc-entra](avaje-oauth2-oidc-entra/README.md) | `EntraOidc` - Authorization Code + PKCE client for Microsoft Entra ID |

## Documentation

- **Full Reference**: See [docs/LIBRARY.md](docs/LIBRARY.md) for a
  comprehensive capability reference, use cases, and AI agent guidance
- **Guides**: Step-by-step guides for common tasks in
  [docs/guides/README.md](docs/guides/README.md) (getting started, OIDC login
  flow, role/scope authorization, multi-issuer migration, JWKS tuning, Entra
  vs Cognito claim differences)
