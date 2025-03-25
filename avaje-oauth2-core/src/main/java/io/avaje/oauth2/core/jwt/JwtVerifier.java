package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.data.JsonDataMapper;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

public interface JwtVerifier {

    static Builder builder() {
        return DJwtVerifier.builder();
    }

    void verify(SignedJwt jwt) throws JwtVerifyException;

    AccessToken verifyAccessToken(String accessToken) throws JwtVerifyException;

    interface Builder {

        Builder addRS256();

        Builder add(String key, String algorithm);

        Builder keySource(JwtKeySource keySource);

        Builder jwksUri(String jwksUri);

        Builder jsonMapper(JsonDataMapper mapper);

        Builder httpClient(HttpClient httpClient);

        Builder issuer(String expectedIssuer);

        Builder clock(Clock clock);

        Builder clockSkew(Duration clockSkew);

        JwtVerifier build();
    }

}
