package io.avaje.oauth2.core.data;

/**
 * @param clientId The OAuth2 client application id (Cognito {@code client_id},
 *   Entra ID {@code azp}/{@code appid}) — identifies which app requested the
 *   token, the same value for every user of that app. Not a per-user identity.
 * @param email The end user's email address, if present. Cognito access tokens
 *   don't carry this by default. For Entra ID it's only present when configured
 *   as an optional claim, and Microsoft documents it as unverified — prefer
 *   {@link #sub()} as the stable identity key and treat this as a display
 *   label only. Not the same as {@link #upn()} — may be {@code null} even
 *   when {@code upn} is present, and the two are not guaranteed to match
 *   (e.g. hybrid AD / guest / B2B accounts).
 * @param upn The end user's User Principal Name (Entra ID's login identifier).
 *   Often looks like an email address but is not guaranteed to be a
 *   deliverable mailbox. Populated from the {@code upn} claim (Entra v2.0
 *   tokens) or {@code unique_name} (Entra v1.0's equivalent claim). {@code
 *   null} for Cognito tokens.
 * @param audience The {@code aud} claim — identifies the intended recipient
 *   (resource/API) of the token. Entra ID access tokens always carry this as
 *   a single string value. Cognito access tokens don't carry an {@code aud}
 *   claim at all (Cognito uses {@link #clientId()} for that purpose instead),
 *   so this is {@code null} for Cognito tokens. Only validated by
 *   {@link io.avaje.oauth2.core.jwt.JwtVerifier} when an expected audience is
 *   explicitly configured via {@code JwtVerifier.Builder.audience(...)}.
 * @param notBefore The {@code nbf} claim (epoch seconds) — the token must not
 *   be accepted before this instant. Optional per RFC 7519 §4.1.5; {@code 0}
 *   when absent, in which case it is not validated.
 */
public record AccessToken(
        String sub,
        String tokenUse,
        String scope,
        long authTime,
        String issuer,
        long expiredAt,
        long issuedAt,
        int version,
        String jti,
        String clientId,
        String email,
        String upn,
        String audience,
        long notBefore) {

    /**
     * Return {@code true} if the space-delimited {@link #scope()} claim
     * contains the given scope as a whole token.
     */
    public boolean hasScope(String scope) {
        if (scope == null || scope.isEmpty() || this.scope == null) {
            return false;
        }
        for (String candidate : this.scope.split(" ")) {
            if (candidate.equals(scope)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return {@code true} if {@link #scope()} contains at least one of the
     * given scopes.
     */
    public boolean hasAnyScope(String... scopes) {
        for (String scope : scopes) {
            if (hasScope(scope)) {
                return true;
            }
        }
        return false;
    }
}
