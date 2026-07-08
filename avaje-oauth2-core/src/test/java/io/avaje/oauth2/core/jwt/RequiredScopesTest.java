package io.avaje.oauth2.core.jwt;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequiredScopesTest {

    @Test
    void isEmpty_whenNoRulesAdded() {
        assertThat(new RequiredScopes().isEmpty()).isTrue();
    }

    @Test
    void isEmpty_falseAfterAdd() {
        RequiredScopes rules = new RequiredScopes();
        rules.add("/v1/apps", "insight/read");
        assertThat(rules.isEmpty()).isFalse();
    }

    @Test
    void requiredScopes_returnsNull_whenNoRuleMatches() {
        RequiredScopes rules = new RequiredScopes();
        rules.add("/v1/admin", "insight/write");
        assertThat(rules.requiredScopes("/v1/apps")).isNull();
    }

    @Test
    void requiredScopes_returnsMatchingRuleScopes() {
        RequiredScopes rules = new RequiredScopes();
        rules.add("/v1/apps", "insight/read", "insight/admin");
        assertThat(rules.requiredScopes("/v1/apps/123")).containsExactly("insight/read", "insight/admin");
    }

    @Test
    void requiredScopes_firstMatchingPrefixWins() {
        RequiredScopes rules = new RequiredScopes();
        rules.add("/v1/apps/admin", "insight/admin");
        rules.add("/v1/apps", "insight/read");
        assertThat(rules.requiredScopes("/v1/apps/admin/123")).containsExactly("insight/admin");
        assertThat(rules.requiredScopes("/v1/apps/other")).containsExactly("insight/read");
    }
}
