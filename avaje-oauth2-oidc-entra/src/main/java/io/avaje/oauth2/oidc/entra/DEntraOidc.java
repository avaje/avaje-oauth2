package io.avaje.oauth2.oidc.entra;

import io.avaje.http.client.HttpClient;
import io.avaje.http.client.HttpClientRequest;
import io.avaje.http.client.UrlBuilder;
import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.OidcTokens;

import java.net.http.HttpResponse;

final class DEntraOidc implements EntraOidc {

    private final String loginUrl;
    private final String clientId;
    private final String clientSecret;
    private final boolean publicClient;
    private final String redirectUri;
    private final String scope;
    private final JsonDataMapper mapper;
    private final String tokenEndpoint;
    private final HttpClient httpClient;

    DEntraOidc(
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
        this.clientSecret = clientSecret;
        this.publicClient = clientSecret == null || clientSecret.isBlank();
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.tokenEndpoint = tokenEndpoint;
        this.mapper = mapper;
        this.httpClient = HttpClient.builder().baseUrl(domain).build();
    }

    @Override
    public String loginUrl(String nonce, String state) {
        return loginUrlBuilder(nonce, state).build();
    }

    @Override
    public String loginUrl(String nonce, String state, String codeChallenge) {
        return loginUrlBuilder(nonce, state)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .build();
    }

    private UrlBuilder loginUrlBuilder(String nonce, String state) {
        return UrlBuilder.of(loginUrl)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("scope", scope)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("nonce", nonce)
                .queryParam("state", state);
    }

    @Override
    public OidcTokens obtainTokens(String code) {
        return obtainTokens(code, null);
    }

    @Override
    public OidcTokens obtainTokens(String code, String codeVerifier) {
        HttpClientRequest request = httpClient.request()
                .url(tokenEndpoint)
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", redirectUri);
        if (codeVerifier != null) {
            request.formParam("code_verifier", codeVerifier);
        }
        return readTokens(request);
    }

    @Override
    public OidcTokens refreshAccessToken(String refreshToken) {
        HttpClientRequest request = httpClient.request()
                .url(tokenEndpoint)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("redirect_uri", redirectUri)
                .formParam("scope", scope);
        return readTokens(request);
    }

    private OidcTokens readTokens(HttpClientRequest request) {
        if (publicClient) {
            request.formParam("client_id", clientId);
        } else {
            request.formParam("client_id", clientId)
                    .formParam("client_secret", clientSecret);
        }
        HttpResponse<String> res = request.POST().asString();
        if (res.statusCode() < 200 || res.statusCode() >= 300) {
            throw new IllegalStateException("OAuth token endpoint returned HTTP "
                    + res.statusCode() + ": " + responseBody(res.body()));
        }
        OidcTokens tokens = mapper.readOidcTokens(res.body());
        if (tokens == null || tokens.accessToken() == null || tokens.accessToken().isBlank()) {
            throw new IllegalStateException("OAuth token endpoint response did not contain access_token");
        }
        return tokens;
    }

    private String responseBody(String body) {
        if (body == null) {
            return "<empty response>";
        }
        String compact = body.replaceAll("\\s+", " ").trim();
        compact = compact.replaceAll(
                "(?i)(\"(?:access_token|refresh_token|id_token|client_secret)\"\\s*:\\s*\")[^\"]*(\")",
                "$1<redacted>$2");
        return compact.length() <= 1000 ? compact : compact.substring(0, 1000) + "...";
    }
}
