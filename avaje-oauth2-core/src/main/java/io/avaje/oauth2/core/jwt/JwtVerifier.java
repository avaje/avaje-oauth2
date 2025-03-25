package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.data.JsonDataMapper;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

/**
 * Verify that a JWT is valid.
 *
 * <pre>{@code
 *
 *   String issuer = "https://cognito-idp.<region>.amazonaws.com/<endpoint>"
 *
 *   JwtVerifier verifier =
 *     JwtVerifier.builder()
 *       .issuer(issuer)
 *       .build()
 *
 * }</pre>
 */
public interface JwtVerifier {

    /**
     * Create and return a builder for JwtVerifier.
     */
    static Builder builder() {
        return DJwtVerifier.builder();
    }

    /**
     * Verify that the SignedJwt is valid.
     */
    void verify(SignedJwt jwt) throws JwtVerifyException;

    /**
     * Parse and verify the accessToken.
     *
     * @param accessToken The raw JWT access token.
     * @return The verified AccessToken.
     * @throws JwtVerifyException When the access token is not valid.
     */
    AccessToken verifyAccessToken(String accessToken) throws JwtVerifyException;

    /**
     * Builder for JwtVerifier.
     */
    interface Builder {

        /**
         * Add RSA 256 algorithm signing.
         */
        Builder addRS256();

        /**
         * Add an algorithm that this verifier will support.
         *
         * @param key       The key for the algorithm
         * @param algorithm The algorithm
         */
        Builder add(String key, String algorithm);

        /**
         * Add a key source.
         */
        Builder keySource(JwtKeySource keySource);

        /**
         * Add a URI for remote JSON Web Key Set.
         */
        Builder jwksUri(String jwksUri);

        /**
         * Add a JsonDataMapper to parse the various json payloads.
         * <p>
         * A default is provided when a mapper is not explicitly specified.
         */
        Builder jsonMapper(JsonDataMapper mapper);

        /**
         * Add the HttpClient to use. Defaults to creating a new HttpClient.
         */
        Builder httpClient(HttpClient httpClient);

        /**
         * Specify the Issuer.
         * <p>
         * Cognito example: <code>https://cognito-idp.{region}.amazonaws.com/{endpoint}</code>
         */
        Builder issuer(String expectedIssuer);

        /**
         * Specify the Clock to use. Defaults to <code>Clock.systemDefaultZone()</code>
         */
        Builder clock(Clock clock);

        /**
         * Specify the Clock skew to use. Defaults to 60 seconds.
         */
        Builder clockSkew(Duration clockSkew);

        /**
         * Build and return the JwtVerifier.
         */
        JwtVerifier build();
    }

}
