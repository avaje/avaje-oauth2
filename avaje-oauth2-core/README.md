# avaje-oauth2-core

Provides core OAuth2 features.


### JwtVerifier

JwtVerifier verifies a Signed JWT Access token is valid.

```java
String issuer = "https://cognito-idp.REGION.amazonaws.com/REGION_FOO";

JwtVerifier jwtVerifier = JwtVerifier.builder()
    .issuer(issuer)
    .build();

String rawAccessToken = ...;

try {
    // verify that the raw access token is valid, and return
    // the parsed AccessToken
    AccessToken accessToken = verifier.verifyAccessToken(rawAccessToken);
} catch (JwtVerifyException exception) {
    // invalid access token
}
```

Optionally validate the token's `aud` claim against an expected audience. This
is off by default — only set it for Entra ID verifiers, where the access
token's `aud` is the app's Application ID URI or client id. Cognito access
tokens don't carry an `aud` claim at all, so leave this unset for Cognito-only
verifiers.

```java
JwtVerifier jwtVerifier = JwtVerifier.builder()
    .issuer(issuer)
    .audience("api://my-app-client-id")
    .build();
```

The token's standard time-based claims are always validated (subject to
`clockSkew`, default 60 seconds): `exp` (expiry), `iat` (issued-at, must not be
in the future), and `nbf` (not-before, optional per RFC 7519 §4.1.5 — only
checked when present).

When using a remote JWKS (the default, based on `issuer`/`jwksUri`), an
unrecognized `kid` triggers a forced refresh of the JWKS. This refresh is
throttled to at most once per `jwksMinRefreshInterval` (default 60 seconds) so
that requests presenting a bogus/unknown `kid` can't force repeated remote
fetches against the identity provider's JWKS endpoint. Concurrent misses
within the throttle window are coalesced into a single fetch.

```java
JwtVerifier jwtVerifier = JwtVerifier.builder()
    .issuer(issuer)
    .jwksMinRefreshInterval(Duration.ofSeconds(60))
    .build();
```


### SignedJwt

Parse a SignedJwt.

```java
String rawToken = "eyJraWQiOiJqR3lQcEc4MDNTc1ZmSjRtZERkVktE...";
SignedJwt token = SignedJwt.parse(rawToken);

```