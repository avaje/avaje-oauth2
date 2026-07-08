package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.jwt.BearerAuthoriser;
import io.avaje.oauth2.core.jwt.BearerChallenge;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.avaje.oauth2.core.jwt.JwtVerifyException;
import io.avaje.oauth2.core.jwt.RequiredScopes;
import io.helidon.common.context.Context;
import io.helidon.http.ForbiddenException;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.UnauthorizedException;
import io.helidon.webserver.http.FilterChain;
import io.helidon.webserver.http.RoutingRequest;
import io.helidon.webserver.http.RoutingResponse;

import java.security.Principal;
import java.util.List;

final class AuthFilter implements JwtAuthFilter {

    private static final String BEARER_ = "Bearer ";
    private static final int BEARER_LENGTH = BEARER_.length();

    private final JwtVerifier verifier;
    private final String[] allowedPaths;
    private final BearerAuthoriser bearerAuthoriser;
    private final RequiredScopes requiredScopes;

    AuthFilter(JwtVerifier verifier, List<String> allowedPaths, BearerAuthoriser bearerAuthoriser, RequiredScopes requiredScopes) {
        this.verifier = verifier;
        this.allowedPaths = allowedPaths.toArray(new String[0]);
        this.bearerAuthoriser = bearerAuthoriser;
        this.requiredScopes = requiredScopes;
    }

    @Override
    public void filter(FilterChain filterChain, RoutingRequest routingRequest, RoutingResponse routingResponse) {
        final String path = routingRequest.path().path();
        for (String allowedPath : allowedPaths) {
            if (path.startsWith(allowedPath)) {
                filterChain.proceed();
                return;
            }
        }

        String header = routingRequest.headers().first(HeaderNames.AUTHORIZATION).orElse("");
        if (header.startsWith(BEARER_)) {
            String token = header.substring(BEARER_LENGTH);
            Context context = routingRequest.context();
            if (bearerAuthoriser != null) {
                String principal = bearerAuthoriser.authorise(token);
                if (principal != null) {
                    context.register("security.principal", new TokenPrincipal(principal));
                    filterChain.proceed();
                    return;
                }
            }
            AccessToken accessToken = verifyOrUnauthorized(token);
            if (!requiredScopes.isEmpty()) {
                String[] required = requiredScopes.requiredScopes(path);
                if (required != null && !accessToken.hasAnyScope(required)) {
                    throw new ForbiddenException("Forbidden")
                            .header(HeaderValues.create(HeaderNames.WWW_AUTHENTICATE, BearerChallenge.insufficientScope(required)));
                }
            }
            // sub is the stable per-user identifier
            context.register("security.principal", new TokenPrincipal(accessToken.sub()));
            context.register("security.roles", accessToken.scope());
            filterChain.proceed();
            return;
        }

        throw new UnauthorizedException("Unauthorized")
                .header(HeaderValues.create(HeaderNames.WWW_AUTHENTICATE, BearerChallenge.missingToken()));
    }

    private AccessToken verifyOrUnauthorized(String token) {
        try {
            return verifier.verifyAccessToken(token);
        } catch (JwtVerifyException e) {
            throw new UnauthorizedException("Unauthorized", e)
                    .header(HeaderValues.create(HeaderNames.WWW_AUTHENTICATE, BearerChallenge.invalidToken(e.getMessage())));
        }
    }

    private static final class TokenPrincipal implements Principal {

        private final String name;

        TokenPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }
}

