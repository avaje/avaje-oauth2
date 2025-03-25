package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.jwt.JwtVerifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthFilterTest {

    @Test
    void build() {
        String issuer = "https://cognito-idp.<region>.amazonaws.com/<region>_<foo>";
        JwtVerifier jwtVerifier = JwtVerifier.builder()
                .issuer(issuer)
                .build();

        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .permit("/ping")
                .verifier(jwtVerifier)
                .build();

        assertThat(filter).isNotNull();
    }
}