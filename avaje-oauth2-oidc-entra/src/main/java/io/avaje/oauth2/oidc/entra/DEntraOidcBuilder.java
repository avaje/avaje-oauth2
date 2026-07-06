package io.avaje.oauth2.oidc.entra;

import io.avaje.json.mapper.JsonMapper;
import io.avaje.oauth2.core.data.JsonDataMapper;

final class DEntraOidcBuilder implements EntraOidc.Builder {

    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String domain;
    private String loginUrl;
    private String tokenEndpoint;
    // openid profile alone does not yield a verifiable JWT access token from
    // Entra — callers targeting a protected API should override with the
    // app's exposed scope, e.g. "api://<clientId>/access_as_user offline_access".
    private String scope = "openid profile offline_access";
    private JsonDataMapper mapper;
    private JsonMapper simpleMapper;

    @Override
    public EntraOidc.Builder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @Override
    public EntraOidc.Builder clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    @Override
    public EntraOidc.Builder tenantId(String tenantId) {
        var entraUris = EntraUris.of(tenantId);
        if (domain == null) {
            domain(entraUris.domain());
        }
        return this;
    }

    @Override
    public EntraOidc.Builder domain(String domain) {
        this.domain = domain;
        if (loginUrl == null) {
            loginUrl = domain + "/oauth2/v2.0/authorize";
        }
        if (tokenEndpoint == null) {
            tokenEndpoint = domain + "/oauth2/v2.0/token";
        }
        return this;
    }

    @Override
    public EntraOidc.Builder loginUri(String loginUri) {
        this.loginUrl = loginUri;
        return this;
    }

    @Override
    public EntraOidc.Builder tokenUri(String tokenUri) {
        this.tokenEndpoint = tokenUri;
        return this;
    }

    @Override
    public EntraOidc.Builder redirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    @Override
    public EntraOidc.Builder jsonMapper(JsonDataMapper mapper) {
        this.mapper = mapper;
        return this;
    }

    @Override
    public EntraOidc.Builder scope(String scope) {
        this.scope = scope;
        return this;
    }

    @Override
    public EntraOidc build() {
        if (mapper == null) {
            if (simpleMapper == null) {
                simpleMapper = JsonMapper.builder().build();
            }
            mapper = JsonDataMapper.builder().jsonMapper(simpleMapper).build();
        }

        return new DEntraOidc(
                loginUrl, clientId, clientSecret, redirectUri, scope,
                tokenEndpoint, domain, mapper);
    }
}
