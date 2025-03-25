package io.avaje.oauth2.core.data;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class JsonDataMapperTest {

    final JsonDataMapper jsonDataMapper = JsonDataMapper.builder().build();

    @Test
    void accessToken() {
        String asd = """
            {
                "sub" : "mySub",
                "token_use" : "access",
                "scope" : "myScope",
                "auth_time" : 1738903492,
                "iss" : "myIssuer",
                "exp" : 1738907092,
                "iat" : 1738903492,
                "version" : 2,
                "jti" : "myJti",
                "client_id" : "myClientId",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(asd);

        assertThat(accessToken.sub()).isEqualTo("mySub");
        assertThat(accessToken.tokenUse()).isEqualTo("access");
        assertThat(accessToken.scope()).isEqualTo("myScope");
        assertThat(accessToken.authTime()).isEqualTo(1738903492);
        assertThat(accessToken.issuer()).isEqualTo("myIssuer");
        assertThat(accessToken.expiredAt()).isEqualTo(1738907092);
        assertThat(accessToken.issuedAt()).isEqualTo(1738903492);
        assertThat(accessToken.version()).isEqualTo(2);
        assertThat(accessToken.jti()).isEqualTo("myJti");
        assertThat(accessToken.clientId()).isEqualTo("myClientId");
    }
}