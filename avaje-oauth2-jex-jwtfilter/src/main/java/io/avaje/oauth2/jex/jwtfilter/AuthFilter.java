package io.avaje.oauth2.jex.jwtfilter;

import io.avaje.jex.http.Context;
import io.avaje.jex.http.HttpResponseException;
import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.jwt.BearerAuthoriser;
import io.avaje.oauth2.core.jwt.BearerChallenge;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.avaje.oauth2.core.jwt.JwtVerifyException;

import java.util.List;

final class AuthFilter implements JwtAuthFilter {

    /** Context attribute key holding the verified {@link AccessToken}. */
    static final String ATTR_ACCESS_TOKEN = "security.accessToken";
    /** Context attribute key holding the token principal (the {@code sub} claim). */
    static final String ATTR_PRINCIPAL = "security.principal";
    /** Context attribute key holding the token scope. */
    static final String ATTR_SCOPE = "security.scope";

    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
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
    public void filter(Context ctx, FilterChain chain) {
        final String path = ctx.path();
        for (String allowedPath : allowedPaths) {
            if (path.startsWith(allowedPath)) {
                chain.proceed();
                return;
            }
        }

        String header = ctx.header("Authorization");
        if (header != null && header.startsWith(BEARER_)) {
            String token = header.substring(BEARER_LENGTH);
            if (bearerAuthoriser != null) {
                String principal = bearerAuthoriser.authorise(token);
                if (principal != null) {
                    ctx.attribute(ATTR_PRINCIPAL, principal);
                    chain.proceed();
                    return;
                }
            }
            AccessToken accessToken = verifyOrUnauthorized(ctx, token);
            ctx.attribute(ATTR_ACCESS_TOKEN, accessToken);
            // sub is the stable per-user identifier
            ctx.attribute(ATTR_PRINCIPAL, accessToken.sub());
            ctx.attribute(ATTR_SCOPE, accessToken.scope());
            chain.proceed();
            return;
        }

        ctx.header(WWW_AUTHENTICATE, BearerChallenge.missingToken());
        throw new HttpResponseException(401, "Unauthorized");
    }

    private AccessToken verifyOrUnauthorized(Context ctx, String token) {
        try {
            return verifier.verifyAccessToken(token);
        } catch (JwtVerifyException e) {
            ctx.header(WWW_AUTHENTICATE, BearerChallenge.invalidToken(e.getMessage()));
            throw new HttpResponseException(401, "Unauthorized");
        }
    }
}

