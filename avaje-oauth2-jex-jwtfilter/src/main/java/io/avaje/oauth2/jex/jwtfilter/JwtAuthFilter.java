package io.avaje.oauth2.jex.jwtfilter;

import io.avaje.jex.http.HttpFilter;
import io.avaje.oauth2.core.jwt.BearerAuthoriser;
import io.avaje.oauth2.core.jwt.JwtVerifier;

/**
 * Jex {@link HttpFilter} that ensures a valid signed JWT is presented as an
 * {@code Authorization: Bearer} header.
 * <p>
 * The filter uses a {@link JwtVerifier} to verify the access token. Some paths
 * (such as health endpoints) can be permitted without a JWT token.
 * <p>
 * Optionally a {@link BearerAuthoriser} can be supplied to additionally accept
 * non-JWT bearer tokens (typically a shared-secret API key); when it authorises
 * a token, JWT verification is skipped. See
 * {@link Builder#bearerAuthoriser(BearerAuthoriser)}.
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
 *     .permit("/api/ingest")
 *     .verifier(jwtVerifier)
 *     .build();
 *
 *   Jex.create()
 *     .filter(filter)
 *     ...
 *
 * }</pre>
 */
public interface JwtAuthFilter extends HttpFilter {

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
         * Optionally supply a {@link BearerAuthoriser} consulted before JWT
         * verification for requests carrying an {@code Authorization: Bearer}
         * header. If it returns a non-null principal name the request is
         * authenticated and JWT verification is skipped; otherwise the filter
         * falls through to the JWT verify path.
         * <p>
         * Useful for accepting opaque shared-secret API keys (presented as a
         * bearer token) alongside JWTs.
         *
         * @param bearerAuthoriser The bearer token authoriser, or {@code null} to disable.
         */
        Builder bearerAuthoriser(BearerAuthoriser bearerAuthoriser);

        /**
         * Build and return the JwtAuthFilter.
         */
        JwtAuthFilter build();
    }
}
