package io.avaje.oauth2.oidc.cognito;

import io.avaje.http.client.BasicAuthIntercept;
import io.avaje.http.client.HttpClient;
import io.avaje.http.client.UrlBuilder;
import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.OidcTokens;

import java.net.http.HttpResponse;

final class DCognitoOidc implements CognitoOidc {

    private final String loginUrl;
    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final JsonDataMapper mapper;
    private final String tokenEndpoint;
    private final HttpClient httpClient;

    DCognitoOidc(
            String loginUrl,
            String clientId,
            String clientSecret,
            String redirectUri,
            String scope,
            String tokenEndpoint,
            String domain,
            JsonDataMapper mapper) {

        this.loginUrl = loginUrl;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.tokenEndpoint = tokenEndpoint;
        this.mapper = mapper;
        this.httpClient = HttpClient.builder()
                .baseUrl(domain)
                .requestIntercept(new BasicAuthIntercept(clientId, clientSecret))
                .build();
    }

    @Override
    public String loginUrl(String nonce, String state) {
        return UrlBuilder.of(loginUrl)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("scope", scope)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("nonce", nonce)
                .queryParam("state", state)
                .build();
    }

    @Override
    public OidcTokens obtainTokens(String code) {
        String content = tokenContent(code);
        return mapper.readOidcTokens(content);
    }

    @Override
    public OidcTokens refreshAccessToken(String refreshToken) {
        String content = refreshContent(refreshToken);
        return mapper.readOidcTokens(content);
    }

    private String tokenContent(String code) {
        HttpResponse<String> res = httpClient.request()
                .url(tokenEndpoint)
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", redirectUri)
                .POST()
                .asString();

        return res.body();
    }

    private String refreshContent(String refreshToken) {
        HttpResponse<String> res = httpClient.request()
                .url(tokenEndpoint)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("redirect_uri", redirectUri)
                .POST()
                .asString();

        return res.body();
    }
}
