package io.avaje.oauth2.core.pkce;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class PkceTest {

    @Test
    void generate_uniqueVerifiers() {
        Pkce one = Pkce.generate();
        Pkce two = Pkce.generate();
        assertThat(one.verifier()).isNotEqualTo(two.verifier());
        assertThat(one.challengeMethod()).isEqualTo("S256");
    }

    @Test
    void generate_verifierIsUrlSafeNoPadding() {
        Pkce pkce = Pkce.generate();
        // 32 random bytes -> 43 char base64url, no '=' padding, no '+' or '/'
        assertThat(pkce.verifier()).hasSize(43);
        assertThat(pkce.verifier()).doesNotContain("=", "+", "/");
    }

    @Test
    void challenge_isS256OfVerifier() throws Exception {
        Pkce pkce = Pkce.of("test-verifier-value");

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-verifier-value".getBytes(StandardCharsets.US_ASCII));
        String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        assertThat(pkce.challenge()).isEqualTo(expected);
    }

    @Test
    void of_deterministicChallenge() {
        assertThat(Pkce.of("abc").challenge()).isEqualTo(Pkce.of("abc").challenge());
    }
}
