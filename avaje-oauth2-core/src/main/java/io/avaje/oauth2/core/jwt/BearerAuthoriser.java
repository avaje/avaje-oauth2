package io.avaje.oauth2.core.jwt;

/**
 * Optional pluggable authoriser for {@code Authorization: Bearer} tokens that
 * are not Cognito JWTs - typically a long-lived shared secret (API key).
 * <p>
 * When supplied to a {@code JwtAuthFilter} builder it is consulted for each
 * request carrying an {@code Authorization: Bearer} header, before JWT
 * verification. If it returns a non-null principal name the request is
 * authenticated and JWT verification is skipped. If it returns {@code null} the
 * filter falls through to the standard JWT verify path.
 * <p>
 * This enables hybrid authentication - for example a system that accepts both
 * Cognito JWTs (interactive users) and a long-lived shared secret (programmatic
 * clients such as CLIs or MCP servers), both presented as a bearer token.
 *
 * <pre>{@code
 *
 *   BearerAuthoriser apiKeys = token ->
 *       sharedSecrets.contains(token) ? "api-key" : null;
 *
 *   JwtAuthFilter filter = JwtAuthFilter.builder()
 *     .permit("/health")
 *     .verifier(jwtVerifier)
 *     .bearerAuthoriser(apiKeys)
 *     .build();
 *
 * }</pre>
 *
 * <p><b>Security:</b> implementations comparing the token against shared
 * secrets should use a constant-time comparison
 * ({@link java.security.MessageDigest#isEqual MessageDigest.isEqual}) to avoid
 * timing attacks.
 */
@FunctionalInterface
public interface BearerAuthoriser {

    /**
     * Authorise the bearer token.
     *
     * @param token The bearer token (the value after {@code Bearer }).
     * @return A non-null principal name when the token is accepted, or
     *         {@code null} to fall through to JWT verification.
     *
     * @implSpec Implementations should return {@code null} on a non-match rather
     * than throwing; a thrown exception propagates uncaught (it does not fall
     * through to JWT verification, but surfaces as a server error).
     */
    String authorise(String token);
}
