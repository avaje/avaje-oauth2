package io.avaje.oauth2.jex.jwtfilter;

import io.avaje.jex.http.Context;
import io.avaje.jex.http.HttpFilter;
import io.avaje.jex.http.HttpResponseException;
import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.avaje.oauth2.core.jwt.JwtVerifyException;

import java.util.List;

final class AuthFilter implements JwtAuthFilter {

    /** Context attribute key holding the verified {@link AccessToken}. */
    static final String ATTR_ACCESS_TOKEN = "security.accessToken";
    /** Context attribute key holding the token principal (clientId). */
    static final String ATTR_PRINCIPAL = "security.principal";
    /** Context attribute key holding the token scope. */
    static final String ATTR_SCOPE = "security.scope";

    private static final String BEARER_ = "Bearer ";
    private static final int BEARER_LENGTH = BEARER_.length();

    private final JwtVerifier verifier;
    private final String[] allowedPaths;

    AuthFilter(JwtVerifier verifier, List<String> allowedPaths) {
        this.verifier = verifier;
        this.allowedPaths = allowedPaths.toArray(new String[0]);
    }

    @Override
    public void filter(Context ctx, FilterChain chain) {
        String header = ctx.header("Authorization");
        if (header != null && header.startsWith(BEARER_)) {
            String token = header.substring(BEARER_LENGTH);
            AccessToken accessToken = verifyOrUnauthorized(token);
            ctx.attribute(ATTR_ACCESS_TOKEN, accessToken);
            ctx.attribute(ATTR_PRINCIPAL, accessToken.clientId());
            ctx.attribute(ATTR_SCOPE, accessToken.scope());
            chain.proceed();
            return;
        }

        final String path = ctx.path();
        for (String allowedPath : allowedPaths) {
            if (path.startsWith(allowedPath)) {
                chain.proceed();
                return;
            }
        }
        throw new HttpResponseException(401, "Unauthorized");
    }

    private AccessToken verifyOrUnauthorized(String token) {
        try {
            return verifier.verifyAccessToken(token);
        } catch (JwtVerifyException e) {
            throw new HttpResponseException(401, "Unauthorized");
        }
    }
}
