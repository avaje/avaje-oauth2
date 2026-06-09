package io.avaje.oauth2.oidc.cognito;

import io.avaje.oauth2.core.pkce.Pkce;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CognitoOidcLoginUrlTest {

    CognitoOidc oidc = CognitoOidc.builder()
            .clientId("client123")
            .userPoolId("ap-southeast-2_foo")
            .redirectUri("http://127.0.0.1:8765/callback")
            .scope("openid insight/read")
            .build();

    @Test
    void loginUrl_basic() {
        String url = oidc.loginUrl("nonce1", "state1");
        assertThat(url).startsWith("https://ap-southeast-2foo.auth.ap-southeast-2.amazoncognito.com/login");
        assertThat(url).contains("client_id=client123");
        assertThat(url).contains("response_type=code");
        assertThat(url).contains("nonce=nonce1");
        assertThat(url).contains("state=state1");
        assertThat(url).doesNotContain("code_challenge");
    }

    @Test
    void loginUrl_withPkce() {
        Pkce pkce = Pkce.of("verifier-abc");
        String url = oidc.loginUrl("nonce1", "state1", pkce.challenge());
        assertThat(url).contains("code_challenge=" + pkce.challenge());
        assertThat(url).contains("code_challenge_method=S256");
    }
}
