package io.avaje.oauth2.oidc.cognito;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CognitoUrisTest {

    CognitoUris cognitoUris = CognitoUris.of("ap-southeast-2_foo");

    @Test
    void of() {
        assertThat(cognitoUris.domain()).isEqualTo("https://ap-southeast-2foo.auth.ap-southeast-2.amazoncognito.com");
        assertThat(cognitoUris.loginUri()).isEqualTo(cognitoUris.domain() + "/login");
        assertThat(cognitoUris.tokenUri()).isEqualTo(cognitoUris.domain() + "/oauth2/token");
        assertThat(cognitoUris.jwksUri()).isEqualTo("https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_foo/.well-known/jwks.json");
    }

    @Test
    void toIssuer() {
        var issuer = CognitoUris.toIssuer("ap-southeast-2_foo");
        assertThat(issuer).isEqualTo(cognitoUris.issuer());
    }

    @Test
    void toJwksUri() {
        var jwksUri = CognitoUris.toJwksUri("ap-southeast-2_foo");
        assertThat(jwksUri).isEqualTo(cognitoUris.jwksUri());
    }
}