package io.avaje.oauth2.core.jwt;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BearerChallengeTest {

    @Test
    void missingToken() {
        assertThat(BearerChallenge.missingToken()).isEqualTo("Bearer");
    }

    @Test
    void invalidToken_noDescription() {
        assertThat(BearerChallenge.invalidToken()).isEqualTo("Bearer error=\"invalid_token\"");
    }

    @Test
    void invalidToken_withDescription() {
        assertThat(BearerChallenge.invalidToken("token expired"))
                .isEqualTo("Bearer error=\"invalid_token\", error_description=\"token expired\"");
    }

    @Test
    void invalidToken_blankDescription_omitsDescription() {
        assertThat(BearerChallenge.invalidToken("  ")).isEqualTo(BearerChallenge.invalidToken());
        assertThat(BearerChallenge.invalidToken(null)).isEqualTo(BearerChallenge.invalidToken());
    }

    @Test
    void invalidToken_escapesQuotesAndBackslashes() {
        assertThat(BearerChallenge.invalidToken("bad \"value\" and \\ slash"))
                .isEqualTo("Bearer error=\"invalid_token\", error_description=\"bad \\\"value\\\" and \\\\ slash\"");
    }

    @Test
    void insufficientScope_singleScope() {
        assertThat(BearerChallenge.insufficientScope("insight/write"))
                .isEqualTo("Bearer error=\"insufficient_scope\", scope=\"insight/write\"");
    }

    @Test
    void insufficientScope_multipleScopes_spaceJoined() {
        assertThat(BearerChallenge.insufficientScope("insight/write", "insight/admin"))
                .isEqualTo("Bearer error=\"insufficient_scope\", scope=\"insight/write insight/admin\"");
    }
}
