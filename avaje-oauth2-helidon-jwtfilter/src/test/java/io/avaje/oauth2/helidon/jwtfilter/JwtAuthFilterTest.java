package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;
import io.avaje.oauth2.core.jwt.JwtKeySource;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthFilterTest {

    @Test
    void build() {
        InputStream is = JwtAuthFilterTest.class.getResourceAsStream("/keys.json");
        JsonDataMapper jsonMapper = JsonDataMapper.builder().build();
        KeySet keySet = jsonMapper.readKeySet(is);

        //String issuer = "https://cognito-idp.REGION.amazonaws.com/REGION_FOO";
        JwtVerifier jwtVerifier = JwtVerifier.builder()
                // .issuer(issuer)
                .addRS256()
                .keySource(JwtKeySource.build(keySet))
                .build();

        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .permit("/ping")
                .verifier(jwtVerifier)
                .build();

        assertThat(filter).isNotNull();
    }
}