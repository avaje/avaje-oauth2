
# avaje-oauth2-helidon-jwtfilter

Provides a Helidon Filter that ensures a valid Signed JWT access token
is supplied as a `Authorization` `Bearer` http header.

### Typical use

- Build a JwtVerifier typically using an issuer endpoint
- Build a JwtAuthFilter 
- Register the JwtAuthFilter as a Filter with the Helidon Webserver

```java
String issuer = "https://cognito-idp.REGION.amazonaws.com/REGION_FOO";

JwtVerifier jwtVerifier = JwtVerifier.builder()
    .issuer(issuer)
    .build();

JwtAuthFilter filter = JwtAuthFilter.builder()
    .permit("/health")
    .permit("/ping")
    .verifier(jwtVerifier)
    .build();
```

On a request, the filter permits any request whose path starts with a
configured `permit(...)` prefix without requiring a token, and otherwise
responds with `401` (via `UnauthorizedException`) when the token is missing
or invalid, including a `WWW-Authenticate` challenge header per
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750#section-3) (`Bearer` when no
token was supplied, `Bearer error="invalid_token"` when verification failed).

## Dependency

```xml
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-helidon-jwtfilter</artifactId>
    <version>0.1</version>
</dependency>
```
