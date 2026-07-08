package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;

/**
 * Builds a {@link JwtVerifier} that dispatches to one of several per-issuer
 * delegate verifiers based on the (unverified) {@code iss} claim of the
 * incoming token.
 * <p>
 * This supports accepting tokens from multiple trusted issuers at once — for
 * example, accepting both Cognito and Entra ID tokens during a phased
 * migration from one identity provider to another, or a multi-tenant setup
 * where different tenants use different issuers.
 * <p>
 * The {@code iss} claim is read from the token payload <b>before</b>
 * signature verification purely to select which delegate verifier to use.
 * This is safe — the selected delegate still performs full signature
 * verification against that issuer's own keys, so a forged/unexpected {@code
 * iss} claim only ever routes to a verifier that will then fail signature
 * verification (or straight up not be registered at all).
 *
 * <pre>{@code
 *
 *   JwtVerifier verifier = MultiIssuerJwtVerifier.builder()
 *       .addIssuer(cognitoIssuer, JwtVerifier.builder().issuer(cognitoIssuer).build())
 *       .addIssuer(entraIssuer, JwtVerifier.builder().issuer(entraIssuer).audience(entraAudience).build())
 *       .build();
 *
 * }</pre>
 */
public final class MultiIssuerJwtVerifier {

    private MultiIssuerJwtVerifier() {
    }

    /**
     * Create and return a builder for a multi-issuer JwtVerifier.
     */
    public static Builder builder() {
        return DMultiIssuerJwtVerifier.builder();
    }

    /**
     * Builder for a multi-issuer JwtVerifier.
     */
    public interface Builder {

        /**
         * Register a delegate verifier for the given issuer. The {@code
         * issuer} must exactly match the delegate verifier's expected {@code
         * iss} claim value.
         */
        Builder addIssuer(String issuer, JwtVerifier verifier);

        /**
         * Specify the JsonDataMapper used to read the (unverified) {@code
         * iss} claim used to select a delegate verifier.
         * <p>
         * A default is provided when a mapper is not explicitly specified.
         */
        Builder jsonMapper(JsonDataMapper mapper);

        /**
         * Build and return the multi-issuer JwtVerifier.
         */
        JwtVerifier build();
    }
}
