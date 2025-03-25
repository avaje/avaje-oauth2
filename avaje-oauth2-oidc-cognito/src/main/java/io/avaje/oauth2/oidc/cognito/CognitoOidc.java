package io.avaje.oauth2.oidc.cognito;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.OidcTokens;

public interface CognitoOidc {

    static Builder builder() {
        return new DCognitoOidcBuilder();
    }

    String loginUrl(String nonce, String state);

    OidcTokens obtainTokens(String code);

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
