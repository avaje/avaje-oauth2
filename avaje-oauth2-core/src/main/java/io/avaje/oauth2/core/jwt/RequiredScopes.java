package io.avaje.oauth2.core.jwt;

import java.util.ArrayList;
import java.util.List;

/**
 * Matches a request path against configured path-prefix-to-required-scope
 * rules, used by the jex and helidon {@code JwtAuthFilter} implementations to
 * support {@code Builder.requireScope(pathPrefix, anyOfScopes)}.
 * <p>
 * Rules are matched in the order added; the first matching path prefix wins
 * (same semantics as {@code Builder.permit(pathPrefix)}).
 */
public final class RequiredScopes {

    private final List<Rule> rules = new ArrayList<>();

    /**
     * Add a rule requiring at least one of the given scopes for paths
     * starting with the given prefix.
     */
    public void add(String pathPrefix, String... anyOfScopes) {
        rules.add(new Rule(pathPrefix, anyOfScopes));
    }

    /**
     * Return {@code true} if no rules have been configured.
     */
    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /**
     * Return the scopes required for the given path (the first matching
     * rule's scopes), or {@code null} if no rule matches.
     */
    public String[] requiredScopes(String path) {
        for (Rule rule : rules) {
            if (path.startsWith(rule.pathPrefix)) {
                return rule.anyOfScopes;
            }
        }
        return null;
    }

    private static final class Rule {
        private final String pathPrefix;
        private final String[] anyOfScopes;

        private Rule(String pathPrefix, String[] anyOfScopes) {
            this.pathPrefix = pathPrefix;
            this.anyOfScopes = anyOfScopes;
        }
    }
}
