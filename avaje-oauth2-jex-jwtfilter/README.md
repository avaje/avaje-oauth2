
# avaje-oauth2-jex-jwtfilter

Provides an [avaje-jex](https://github.com/avaje/avaje-jex) `HttpFilter` that
ensures a valid signed JWT access token is supplied as an `Authorization`
`Bearer` http header.

This is the Jex equivalent of `avaje-oauth2-helidon-jwtfilter`.

### Typical use

- Build a `JwtVerifier`, typically using an issuer endpoint
- Build a `JwtAuthFilter`
- Register the `JwtAuthFilter` as a filter with the Jex server

```java
String issuer = "https://cognito-idp.REGION.amazonaws.com/REGION_FOO";

JwtVerifier jwtVerifier = JwtVerifier.builder()
    .issuer(issuer)
    .build();

JwtAuthFilter filter = JwtAuthFilter.builder()
    .permit("/health")
    .permit("/api/ingest")
    .verifier(jwtVerifier)
    .build();

Jex.create()
    .filter(filter)
    .port(8080)
    .start();
```

On a request, the filter:

- permits any request whose path starts with a configured `permit(...)` prefix
  (e.g. health checks) without requiring a token
- otherwise requires an `Authorization: Bearer <token>` header, verifies it with
  the `JwtVerifier`, and on success registers the following Jex context
  attributes for downstream handlers:
  - `security.accessToken` — the verified `AccessToken`
  - `security.principal` — the token `clientId` (subject)
  - `security.scope` — the token scope
- responds with `401` (via `HttpResponseException`) when the token is missing or
  invalid on a protected path

## Dependency

```xml
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-jex-jwtfilter</artifactId>
    <version>0.1</version>
</dependency>
```
