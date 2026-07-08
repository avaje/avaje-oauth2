
# avaje-oauth2-oidc-cognito

Provides `CognitoOidc`, an OAuth2 Authorization Code (+ PKCE) client for AWS
Cognito's Hosted UI.

This is a client for driving the browser-based login redirect flow (e.g. from
a BFF/gateway) - for verifying already-issued bearer JWTs in a resource
server, see `avaje-oauth2-core`'s `JwtVerifier` instead.

### Typical use

```java
CognitoOidc cognitoOidc = CognitoOidc.builder()
    .userPoolId(userPoolId)
    .domain(cognitoDomain)          // the Hosted UI domain
    .clientId(clientId)
    .clientSecret(clientSecret)     // omit/null for a public client
    .redirectUri(redirectUri)
    .scope("openid profile email")
    .build();

// 1. Build the login URL and redirect the user's browser to it
String loginUrl = cognitoOidc.loginUrl(nonce, state);

// 2. Cognito redirects back to redirectUri with an authorization `code`

// 3. Exchange the code for tokens
OidcTokens tokens = cognitoOidc.obtainTokens(code);

// 4. Later, refresh the access token
OidcTokens refreshed = cognitoOidc.refreshAccessToken(tokens.refreshToken());
```

### PKCE (public clients)

For a public client (no client secret), use the PKCE-enabled overloads with
`io.avaje.oauth2.core.pkce.Pkce`:

```java
Pkce pkce = Pkce.generate();

String loginUrl = cognitoOidc.loginUrl(nonce, state, pkce.challenge());
// ... user authenticates, authorization code returned ...
OidcTokens tokens = cognitoOidc.obtainTokens(code, pkce.verifier());
```

See [docs/guides/oidc-login-flow.md](../docs/guides/oidc-login-flow.md) for
the full walkthrough.

## Dependency

```xml
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-oidc-cognito</artifactId>
</dependency>
```
