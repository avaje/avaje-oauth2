package io.avaje.oauth2.oidc.entra;

import io.avaje.oauth2.core.pkce.Pkce;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EntraOidcLoginUrlTest {

    EntraOidc oidc = EntraOidc.builder()
            .clientId("c7aa3211-b6b3-40af-878a-a66c5917d165")
            .tenantId("525d795f-834f-4a88-acc6-ede9f6c1779e")
            .redirectUri("http://127.0.0.1:8765/callback")
            .scope("api://c7aa3211-b6b3-40af-878a-a66c5917d165/access_as_user offline_access")
            .build();

    @Test
    void loginUrl_basic() {
        String url = oidc.loginUrl("nonce1", "state1");
        assertThat(url).startsWith("https://login.microsoftonline.com/525d795f-834f-4a88-acc6-ede9f6c1779e/oauth2/v2.0/authorize");
        assertThat(url).contains("client_id=c7aa3211-b6b3-40af-878a-a66c5917d165");
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
