package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.jwt.JwtVerifier;

import java.util.ArrayList;
import java.util.List;

final class AuthFilterBuilder implements JwtAuthFilter.Builder {

    private final List<String> allowedPaths = new ArrayList<>();
    private JwtVerifier verifier;

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
    public JwtAuthFilter build() {
        return new AuthFilter(verifier, allowedPaths);
    }
}
