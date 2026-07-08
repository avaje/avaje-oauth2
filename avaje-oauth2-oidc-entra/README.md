
# avaje-oauth2-oidc-entra

Provides `EntraOidc`, an OAuth2 Authorization Code (+ PKCE) client for
Microsoft Entra ID (Microsoft identity platform v2.0 endpoints).

This is a client for driving the browser-based login redirect flow (e.g. from
a CLI or a BFF/gateway) - for verifying already-issued bearer JWTs in a
resource server, see `avaje-oauth2-core`'s `JwtVerifier` instead.

### Typical use

```java
EntraOidc entraOidc = EntraOidc.builder()
    .tenantId(tenantId)              // derives domain, authorize + token endpoints
    .clientId(clientId)
    .redirectUri("http://localhost/callback")
    .scope("api://" + clientId + "/access_as_user")
    .build();

// 1. Build the login URL and open it in the user's browser
String loginUrl = entraOidc.loginUrl(nonce, state);

// 2. Entra redirects back to redirectUri with an authorization `code`

// 3. Exchange the code for tokens
OidcTokens tokens = entraOidc.obtainTokens(code);

// 4. Later, refresh the access token
OidcTokens refreshed = entraOidc.refreshAccessToken(tokens.refreshToken());
```

### PKCE (public clients - the common case for a CLI)

```java
Pkce pkce = Pkce.generate();

String loginUrl = entraOidc.loginUrl(nonce, state, pkce.challenge());
// ... user authenticates, authorization code returned ...
OidcTokens tokens = entraOidc.obtainTokens(code, pkce.verifier());
```

### ⚠️ Important: `openid`/`profile` scope alone will not work

Unlike Cognito, Microsoft identity platform only issues a **JWT access token
verifiable against your tenant's JWKS** when the requested scope is tied to
an API exposed by an app registration. Requesting only `openid`/`profile`
typically returns a Microsoft Graph token (or non-JWT token) instead.

For a self-referential app (same app registration acts as both the OIDC
client and the resource server), the app registration must:
- **Expose an API** (Application ID URI, default `api://<clientId>`) with a
  custom scope, e.g. `access_as_user`.
- Request `api://<clientId>/access_as_user` (or `.default`) as the scope.
- Have `accessTokenAcceptedVersion` set to `2` in its manifest if the server
  expects the v2.0 issuer format (`https://login.microsoftonline.com/<tenant>/v2.0`).

See [docs/guides/oidc-login-flow.md](../docs/guides/oidc-login-flow.md) and
[docs/guides/entra-vs-cognito-claims.md](../docs/guides/entra-vs-cognito-claims.md)
for the full details.

### Redirect URI note

Entra ignores the port for `localhost` redirect URIs (RFC 8252 §7.3/8.3) - a
single registration of `http://localhost/callback` under the "Mobile and
desktop applications" platform matches any port, so only one redirect URI
needs to be registered even if your app tries several ports.

## Dependency

```xml
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-oidc-entra</artifactId>
</dependency>
```
