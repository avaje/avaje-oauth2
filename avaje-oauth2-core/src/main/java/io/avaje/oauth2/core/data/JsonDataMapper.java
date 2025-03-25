package io.avaje.oauth2.core.data;

import io.avaje.json.mapper.JsonMapper;

import java.io.InputStream;

public interface JsonDataMapper {

    static Builder builder() {
        return DJsonMapper.builder();
    }

    IdClaims readIdClaims(String json);

    OidcTokens readOidcTokens(String json);

    KeySet readKeySet(String json);

    KeySet readKeySet(InputStream is);

    JwtHeader readJwtHeader(String jwtHeaderJson);

    AccessToken readAccessToken(String json);

    interface Builder {

        Builder jsonMapper(JsonMapper simpleMapper);

        JsonDataMapper build();
    }
}
