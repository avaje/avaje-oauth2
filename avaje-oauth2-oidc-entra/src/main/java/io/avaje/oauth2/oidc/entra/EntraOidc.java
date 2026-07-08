package io.avaje.oauth2.oidc.entra;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.OidcTokens;

/**
 * OAuth2 Authorization Code (+ PKCE) client for Microsoft identity platform
 * (Entra ID), using the v2.0 authorize/token endpoints.
 * <p>
 * Note that requesting only the {@code openid}/{@code profile} scopes will
 * <b>not</b> yield a JWT access token that can be validated against the
 * tenant's own JWKS - the app registration must expose an API (an Application
 * ID URI + custom scope, e.g. {@code api://<clientId>/access_as_user}) and the
 * scope requested here must include that resource scope for the resulting
 * access token to be a verifiable JWT with {@code aud} == the client id.
 */
public interface EntraOidc {

    static Builder builder() {
        return new DEntraOidcBuilder();
    }

    String loginUrl(String nonce, String state);

    /**
     * Build the authorization (login) URL including a PKCE {@code code_challenge}
     * for a public client. Pair with {@link #obtainTokens(String, String)}.
     *
     * @param nonce         The OIDC nonce.
     * @param state         The OAuth2 state value.
     * @param codeChallenge The PKCE S256 code challenge (see
     *                      {@code io.avaje.oauth2.core.pkce.Pkce}).
     */
    String loginUrl(String nonce, String state, String codeChallenge);

    OidcTokens obtainTokens(String code);

    /**
     * Exchange the authorization code for tokens including the PKCE
     * {@code code_verifier} for a public client. Pair with
     * {@link #loginUrl(String, String, String)}.
     *
     * @param code         The authorization code.
     * @param codeVerifier The PKCE code verifier matching the challenge sent on
     *                     the authorization request.
     */
    OidcTokens obtainTokens(String code, String codeVerifier);

    OidcTokens refreshAccessToken(String refreshToken);

    interface Builder {

        /**
         * Derive the domain, authorize and token endpoints from the Entra Tenant Id.
         */
        Builder tenantId(String tenantId);

        Builder clientId(String clientId);

        Builder clientSecret(String clientSecret);

        Builder domain(String domain);

        Builder loginUri(String loginUri);

        Builder tokenUri(String tokenUri);

        Builder redirectUri(String redirectUri);

        Builder jsonMapper(JsonDataMapper mapper);

        Builder scope(String scope);

        EntraOidc build();
    }

}
