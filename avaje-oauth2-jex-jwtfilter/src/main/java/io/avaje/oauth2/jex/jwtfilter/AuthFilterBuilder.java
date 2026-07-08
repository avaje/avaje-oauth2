package io.avaje.oauth2.jex.jwtfilter;

import io.avaje.oauth2.core.jwt.BearerAuthoriser;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.avaje.oauth2.core.jwt.RequiredScopes;

import java.util.ArrayList;
import java.util.List;

final class AuthFilterBuilder implements JwtAuthFilter.Builder {

    private final List<String> allowedPaths = new ArrayList<>();
    private final RequiredScopes requiredScopes = new RequiredScopes();
    private JwtVerifier verifier;
    private BearerAuthoriser bearerAuthoriser;

    @Override
    public JwtAuthFilter.Builder permit(String path) {
        allowedPaths.add(path);
        return this;
    }

    @Override
    public JwtAuthFilter.Builder verifier(JwtVerifier verifier) {
        this.verifier = verifier;
        return this;
    }

    @Override
    public JwtAuthFilter.Builder bearerAuthoriser(BearerAuthoriser bearerAuthoriser) {
        this.bearerAuthoriser = bearerAuthoriser;
        return this;
    }

    @Override
    public JwtAuthFilter.Builder requireScope(String pathPrefix, String... anyOfScopes) {
        requiredScopes.add(pathPrefix, anyOfScopes);
        return this;
    }

    @Override
    public JwtAuthFilter build() {
        if (verifier == null) {
            throw new IllegalStateException("JwtVerifier is required");
        }
        return new AuthFilter(verifier, allowedPaths, bearerAuthoriser, requiredScopes);
    }
}
