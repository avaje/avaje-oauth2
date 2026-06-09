package io.avaje.oauth2.oidc.cognito;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.OidcTokens;

public interface CognitoOidc {

    static Builder builder() {
        return new DCognitoOidcBuilder();
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

        Builder clientId(String clientId);

        Builder clientSecret(String clientSecret);

        Builder userPoolId(String userPoolId);

        Builder domain(String domain);

        Builder loginUri(String loginUri);

        Builder tokenUri(String tokenUri);

        Builder redirectUri(String redirectUri);

        Builder jsonMapper(JsonDataMapper mapper);

        Builder scope(String scope);

        CognitoOidc build();
    }

}
