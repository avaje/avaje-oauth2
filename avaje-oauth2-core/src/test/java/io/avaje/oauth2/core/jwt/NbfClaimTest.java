package io.avaje.oauth2.core.jwt;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NbfClaimTest {

    private static final Instant NOW = Instant.parse("2024-06-01T00:00:00Z");

    private JwtVerifier verifierWith(TestJwtSigner signer) {
        return JwtVerifier.builder()
                .keySource(JwtKeySource.build(signer.keySet()))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
    }

    private Map<String, Object> baseClaims() {
        var claims = new LinkedHashMap<String, Object>();
        claims.put("sub", "user1");
        claims.put("exp", NOW.plusSeconds(3600).getEpochSecond());
        claims.put("iat", NOW.minusSeconds(60).getEpochSecond());
        return claims;
    }

    @Test
    void verifyAccessToken_nbfInFuture_throws() {
        TestJwtSigner signer = new TestJwtSigner("kid1");
        var claims = baseClaims();
        claims.put("nbf", NOW.plusSeconds(300).getEpochSecond());
        String token = signer.sign(claims);

        assertThatThrownBy(() -> verifierWith(signer).verifyAccessToken(token))
                .isInstanceOf(JwtVerifyException.class)
                .hasMessageContaining("nbf");
    }

    @Test
    void verifyAccessToken_nbfInPast_accepted() {
        TestJwtSigner signer = new TestJwtSigner("kid1");
        var claims = baseClaims();
        claims.put("nbf", NOW.minusSeconds(300).getEpochSecond());
        String token = signer.sign(claims);

        assertThat(verifierWith(signer).verifyAccessToken(token).sub()).isEqualTo("user1");
    }

    @Test
    void verifyAccessToken_nbfAbsent_notChecked() {
        TestJwtSigner signer = new TestJwtSigner("kid1");
        String token = signer.sign(baseClaims());

        assertThat(verifierWith(signer).verifyAccessToken(token).sub()).isEqualTo("user1");
    }

    @Test
    void verifyAccessToken_nbfJustWithinClockSkew_accepted() {
        TestJwtSigner signer = new TestJwtSigner("kid1");
        var claims = baseClaims();
        // 30s in the future, well within the default 60s clock skew allowance
        claims.put("nbf", NOW.plusSeconds(30).getEpochSecond());
        String token = signer.sign(claims);

        assertThat(verifierWith(signer).verifyAccessToken(token).sub()).isEqualTo("user1");
    }

    @Test
    void verifyAccessToken_nbfBeyondClockSkew_throws() {
        TestJwtSigner signer = new TestJwtSigner("kid1");
        var claims = baseClaims();
        claims.put("nbf", NOW.plusSeconds(90).getEpochSecond());
        String token = signer.sign(claims);

        JwtVerifier verifier = JwtVerifier.builder()
                .keySource(JwtKeySource.build(signer.keySet()))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .clockSkew(Duration.ofSeconds(60))
                .build();

        assertThatThrownBy(() -> verifier.verifyAccessToken(token))
                .isInstanceOf(JwtVerifyException.class)
                .hasMessageContaining("nbf");
    }
}
