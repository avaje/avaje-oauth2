package io.avaje.oauth2.core.jwt;

import io.avaje.json.mapper.JsonMapper;
import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.data.JsonDataMapper;

import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class DMultiIssuerJwtVerifier implements JwtVerifier {

    private final Map<String, JwtVerifier> byIssuer;
    private final JsonDataMapper mapper;

    private DMultiIssuerJwtVerifier(Map<String, JwtVerifier> byIssuer, JsonDataMapper mapper) {
        this.byIssuer = byIssuer;
        this.mapper = mapper;
    }

    static MultiIssuerJwtVerifier.Builder builder() {
        return new DBuilder();
    }

    @Override
    public void verify(SignedJwt jwt) {
        delegateFor(jwt).verify(jwt);
    }

    @Override
    public AccessToken verifyAccessToken(String accessToken) throws JwtVerifyException {
        SignedJwt jwt = SignedJwt.parse(accessToken);
        return delegateFor(jwt).verifyAccessToken(accessToken);
    }

    /**
     * Read the (unverified) {@code iss} claim to select which delegate
     * verifier should perform full signature + claims verification.
     */
    private JwtVerifier delegateFor(SignedJwt jwt) {
        String issuer;
        try {
            issuer = mapper.readAccessToken(jwt.payload()).issuer();
        } catch (RuntimeException e) {
            throw new JwtVerifyException("Unable to parse Jwt access token " + e);
        }
        JwtVerifier delegate = issuer != null ? byIssuer.get(issuer) : null;
        if (delegate == null) {
            throw new JwtVerifyException("Jwt unexpected issuer");
        }
        return delegate;
    }

    private static final class DBuilder implements MultiIssuerJwtVerifier.Builder {

        private final Map<String, JwtVerifier> byIssuer = new HashMap<>();
        private JsonDataMapper mapper;

        @Override
        public MultiIssuerJwtVerifier.Builder addIssuer(String issuer, JwtVerifier verifier) {
            byIssuer.put(
                    requireNonNull(issuer, "issuer is required"),
                    requireNonNull(verifier, "verifier is required"));
            return this;
        }

        @Override
        public MultiIssuerJwtVerifier.Builder jsonMapper(JsonDataMapper mapper) {
            this.mapper = mapper;
            return this;
        }

        @Override
        public JwtVerifier build() {
            if (byIssuer.isEmpty()) {
                throw new IllegalStateException("At least one issuer must be registered via addIssuer(...)");
            }
            JsonDataMapper actualMapper = mapper;
            if (actualMapper == null) {
                actualMapper = JsonDataMapper.builder().jsonMapper(JsonMapper.builder().build()).build();
            }
            return new DMultiIssuerJwtVerifier(Map.copyOf(byIssuer), actualMapper);
        }
    }
}
