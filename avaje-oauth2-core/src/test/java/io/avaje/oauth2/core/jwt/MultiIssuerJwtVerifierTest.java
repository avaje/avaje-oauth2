package io.avaje.oauth2.core.jwt;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MultiIssuerJwtVerifierTest {

    private static final Instant NOW = Instant.parse("2024-06-01T00:00:00Z");
    private static final String COGNITO_ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123";
    private static final String ENTRA_ISSUER = "https://login.microsoftonline.com/tenant-id/v2.0";

    private final TestJwtSigner cognitoSigner = new TestJwtSigner("cognito-kid");
    private final TestJwtSigner entraSigner = new TestJwtSigner("entra-kid");

    private JwtVerifier cognitoVerifier() {
        return JwtVerifier.builder()
                .issuer(COGNITO_ISSUER)
                .keySource(JwtKeySource.build(cognitoSigner.keySet()))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
    }

    private JwtVerifier entraVerifier() {
        return JwtVerifier.builder()
                .issuer(ENTRA_ISSUER)
                .keySource(JwtKeySource.build(entraSigner.keySet()))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
    }

    private JwtVerifier multiVerifier() {
        return MultiIssuerJwtVerifier.builder()
                .addIssuer(COGNITO_ISSUER, cognitoVerifier())
                .addIssuer(ENTRA_ISSUER, entraVerifier())
                .build();
    }

    private Map<String, Object> claims(String issuer) {
        var claims = new LinkedHashMap<String, Object>();
        claims.put("sub", "user1");
        claims.put("iss", issuer);
        claims.put("exp", NOW.plusSeconds(3600).getEpochSecond());
        claims.put("iat", NOW.minusSeconds(60).getEpochSecond());
        return claims;
    }

    @Test
    void verifyAccessToken_routesToCognitoDelegate_whenIssuerMatchesCognito() {
        String token = cognitoSigner.sign(claims(COGNITO_ISSUER));

        var accessToken = multiVerifier().verifyAccessToken(token);

        assertThat(accessToken.sub()).isEqualTo("user1");
        assertThat(accessToken.issuer()).isEqualTo(COGNITO_ISSUER);
    }

    @Test
    void verifyAccessToken_routesToEntraDelegate_whenIssuerMatchesEntra() {
        String token = entraSigner.sign(claims(ENTRA_ISSUER));

        var accessToken = multiVerifier().verifyAccessToken(token);

        assertThat(accessToken.sub()).isEqualTo("user1");
        assertThat(accessToken.issuer()).isEqualTo(ENTRA_ISSUER);
    }

    @Test
    void verifyAccessToken_unregisteredIssuer_throws() {
        String token = cognitoSigner.sign(claims("https://not-a-registered-issuer.example.com"));

        assertThatThrownBy(() -> multiVerifier().verifyAccessToken(token))
                .isInstanceOf(JwtVerifyException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void verifyAccessToken_issuerClaimMatchesButSignedByWrongKey_throws() {
        // signed with the cognito signer's key, but claims iss = Entra --
        // proves the iss claim alone doesn't grant trust, matching to the
        // Entra delegate still requires signature verification with Entra's
        // own registered keys, which will fail (Entra's JWKS doesn't have
        // the cognito signer's kid).
        String forgedToken = cognitoSigner.sign(claims(ENTRA_ISSUER));

        assertThatThrownBy(() -> multiVerifier().verifyAccessToken(forgedToken))
                .isInstanceOf(JwtVerifyException.class);
    }

    @Test
    void builder_withNoIssuersRegistered_throws() {
        assertThatThrownBy(() -> MultiIssuerJwtVerifier.builder().build())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void verify_signedJwt_routesToMatchingDelegate() {
        String token = cognitoSigner.sign(claims(COGNITO_ISSUER));
        SignedJwt jwt = SignedJwt.parse(token);

        // should not throw -- signature verifies fine against the cognito delegate
        multiVerifier().verify(jwt);
    }
}
