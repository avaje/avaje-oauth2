package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.jwt.BearerAuthoriser;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.helidon.common.context.Context;
import io.helidon.http.HeaderNames;
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

    AuthFilter(JwtVerifier verifier, List<String> allowedPaths, BearerAuthoriser bearerAuthoriser) {
        this.verifier = verifier;
        this.allowedPaths = allowedPaths.toArray(new String[0]);
        this.bearerAuthoriser = bearerAuthoriser;
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
            AccessToken accessToken = verifier.verifyAccessToken(token);
            context.register("security.principal", new TokenPrincipal(accessToken.clientId()));
            context.register("security.roles", accessToken.scope());
            filterChain.proceed();
            return;
        }

        throw new UnauthorizedException("Unauthorized");
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
