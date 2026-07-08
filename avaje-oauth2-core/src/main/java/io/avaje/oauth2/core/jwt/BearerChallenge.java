package io.avaje.oauth2.core.jwt;

/**
 * Builds {@code WWW-Authenticate} challenge header values for Bearer token
 * authentication, per <a href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 section 3</a>.
 */
public final class BearerChallenge {

    private BearerChallenge() {
    }

    /**
     * Challenge for a request with no (or a malformed) Authorization header.
     */
    public static String missingToken() {
        return "Bearer";
    }

    /**
     * Challenge for a request bearing a token that failed verification
     * (invalid signature, expired, wrong issuer/audience etc).
     */
    public static String invalidToken() {
        return "Bearer error=\"invalid_token\"";
    }

    /**
     * As per {@link #invalidToken()} but including an {@code error_description}
     * with details of why the token was rejected.
     */
    public static String invalidToken(String description) {
        if (description == null || description.isBlank()) {
            return invalidToken();
        }
        return "Bearer error=\"invalid_token\", error_description=\"" + escape(description) + "\"";
    }

    /**
     * Challenge for a request bearing a validly authenticated token that
     * lacks a required scope, per
     * <a href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 section 3.1</a>.
     *
     * @param anyOfScopes The scope(s) that would have satisfied the request (at least one of these was required).
     */
    public static String insufficientScope(String... anyOfScopes) {
        String scope = String.join(" ", anyOfScopes);
        return "Bearer error=\"insufficient_scope\", scope=\"" + escape(scope) + "\"";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
