package io.avaje.oauth2.core.data;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AccessTokenTest {

    private static AccessToken tokenWithScope(String scope) {
        return new AccessToken("sub1", "access", scope, 0L,
                "issuer", 0L, 0L, 1, "jti1", "client123", null, null, null, 0L);
    }

    @Test
    void hasScope_true_whenPresent() {
        assertThat(tokenWithScope("insight/read insight/write").hasScope("insight/write")).isTrue();
    }

    @Test
    void hasScope_false_whenAbsent() {
        assertThat(tokenWithScope("insight/read").hasScope("insight/write")).isFalse();
    }

    @Test
    void hasScope_false_whenScopeIsNull() {
        assertThat(tokenWithScope(null).hasScope("insight/read")).isFalse();
    }

    @Test
    void hasScope_false_whenArgIsNullOrEmpty() {
        AccessToken token = tokenWithScope("insight/read");
        assertThat(token.hasScope(null)).isFalse();
        assertThat(token.hasScope("")).isFalse();
    }

    @Test
    void hasScope_doesNotMatchPartialSubstring() {
        // "insight/read" must not match a scope of "insight/readonly" as a substring
        assertThat(tokenWithScope("insight/readonly").hasScope("insight/read")).isFalse();
    }

    @Test
    void hasAnyScope_true_whenOneMatches() {
        assertThat(tokenWithScope("insight/read").hasAnyScope("insight/write", "insight/read")).isTrue();
    }

    @Test
    void hasAnyScope_false_whenNoneMatch() {
        assertThat(tokenWithScope("insight/read").hasAnyScope("insight/write", "insight/admin")).isFalse();
    }
}
