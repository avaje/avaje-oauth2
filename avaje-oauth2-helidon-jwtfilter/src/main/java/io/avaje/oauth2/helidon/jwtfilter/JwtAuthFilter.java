package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.helidon.webserver.http.Filter;

/**
 * Filter that ensures a valid Signed JWT token is presented as a Authorization Bearer header.
 * <p>
 * The filter uses a JwtVerifier to verify the SignedJWT is valid.
 * <p>
 * The filter can allow some paths to not require a JWT token such as health endpoints.
 *
 * <pre>{@code
 *
 *   String issuer = "https://cognito-idp.<region>.amazonaws.com/<region>_<foo>";
 *
 *   JwtVerifier jwtVerifier = JwtVerifier.builder()
 *     .issuer(issuer)
 *     .build();
 *
 *   JwtAuthFilter filter = JwtAuthFilter.builder()
 *     .permit("/health")
 *     .permit("/ping")
 *     .verifier(jwtVerifier)
 *     .build();
 *
 * }</pre>
 */
public interface JwtAuthFilter extends Filter {

    /**
     * Return a builder for JwtAuthFilter.
     */
    static Builder builder() {
        return new AuthFilterBuilder();
    }

    /**
     * Builder for JwtAuthFilter.
     */
    interface Builder {

        /**
         * Permit paths starting with the given prefix to not require a JWT token.
         *
         * @param pathPrefix The path prefix that does not require a JWT token.
         */
        Builder permit(String pathPrefix);

        /**
         * Specify the JwtVerifier to use.
         */
        Builder verifier(JwtVerifier verifier);

        /**
         * Build and return the JwtAuthFilter.
         */
        JwtAuthFilter build();
    }
}
