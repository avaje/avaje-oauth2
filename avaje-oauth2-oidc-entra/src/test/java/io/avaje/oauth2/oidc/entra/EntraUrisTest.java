package io.avaje.oauth2.oidc.entra;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EntraUrisTest {

    EntraUris entraUris = EntraUris.of("525d795f-834f-4a88-acc6-ede9f6c1779e");

    @Test
    void of() {
        assertThat(entraUris.domain()).isEqualTo("https://login.microsoftonline.com/525d795f-834f-4a88-acc6-ede9f6c1779e");
        assertThat(entraUris.issuer()).isEqualTo(entraUris.domain() + "/v2.0");
        assertThat(entraUris.loginUri()).isEqualTo(entraUris.domain() + "/oauth2/v2.0/authorize");
        assertThat(entraUris.tokenUri()).isEqualTo(entraUris.domain() + "/oauth2/v2.0/token");
        assertThat(entraUris.jwksUri()).isEqualTo(entraUris.domain() + "/discovery/v2.0/keys");
        assertThat(entraUris.deviceAuthorizationUri()).isEqualTo(entraUris.domain() + "/oauth2/v2.0/devicecode");
    }

    @Test
    void toIssuer() {
        var issuer = EntraUris.toIssuer("525d795f-834f-4a88-acc6-ede9f6c1779e");
        assertThat(issuer).isEqualTo(entraUris.issuer());
    }

    @Test
    void toJwksUri() {
        var jwksUri = EntraUris.toJwksUri("525d795f-834f-4a88-acc6-ede9f6c1779e");
        assertThat(jwksUri).isEqualTo(entraUris.jwksUri());
    }
}
