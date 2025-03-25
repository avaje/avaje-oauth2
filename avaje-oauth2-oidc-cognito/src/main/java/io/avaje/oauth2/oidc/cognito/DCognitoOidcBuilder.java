package io.avaje.oauth2.oidc.cognito;

import io.avaje.json.mapper.JsonMapper;
import io.avaje.oauth2.core.data.JsonDataMapper;

final class DCognitoOidcBuilder implements CognitoOidc.Builder {

    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String domain;
    private String loginUrl;
    private String tokenEndpoint;
    private String scope = "default/default";
    private JsonDataMapper mapper;
    private JsonMapper simpleMapper;

    @Override
    public CognitoOidc.Builder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @Override
    public CognitoOidc.Builder clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    @Override
    public CognitoOidc.Builder userPoolId(String userPoolId) {
        var cognitoUris = CognitoUris.of(userPoolId);
        if (domain == null) {
            domain(cognitoUris.domain());
        }
        return this;
    }

    @Override
    public CognitoOidc.Builder domain(String domain) {
        this.domain = domain;
        if (loginUrl == null) {
            loginUrl = domain + "/login";
        }
        if (tokenEndpoint == null) {
            tokenEndpoint = domain + "/oauth2/token";
        }
        return this;
    }

    @Override
    public CognitoOidc.Builder loginUri(String loginUri) {
        this.loginUrl = loginUri;
        return this;
    }

    @Override
    public CognitoOidc.Builder tokenUri(String tokenUri) {
        this.tokenEndpoint = tokenUri;
        return this;
    }

    @Override
    public CognitoOidc.Builder redirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    @Override
    public CognitoOidc.Builder jsonMapper(JsonDataMapper mapper) {
        this.mapper = mapper;
        return this;
    }

    @Override
    public CognitoOidc.Builder scope(String scope) {
        this.scope = scope;
        return this;
    }

    @Override
    public CognitoOidc build() {
        if (mapper == null) {
            if (simpleMapper == null) {
                simpleMapper = JsonMapper.builder().build();
            }
            mapper = JsonDataMapper.builder().jsonMapper(simpleMapper).build();
        }

        return new DCognitoOidc(
                loginUrl, clientId, clientSecret, redirectUri, scope,
                tokenEndpoint, domain, mapper);
    }
}
