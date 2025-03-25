
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

## Dependency

```xml
<dependency>
    <groupId>io.avaje</groupId>
    <artifactId>avaje-oauth2-helidon-jwtfilter</artifactId>
    <version>0.1</version>
</dependency>
```
