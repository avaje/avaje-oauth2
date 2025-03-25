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


### SignedJwt

Parse a SignedJwt.

```java
String rawToken = "eyJraWQiOiJqR3lQcEc4MDNTc1ZmSjRtZERkVktE...";
SignedJwt token = SignedJwt.parse(rawToken);

```