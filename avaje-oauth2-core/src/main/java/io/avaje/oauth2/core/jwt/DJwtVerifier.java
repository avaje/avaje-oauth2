package io.avaje.oauth2.core.jwt;

import io.avaje.json.mapper.JsonMapper;
import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.JwtHeader;

import java.net.http.HttpClient;
import java.security.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

final class DJwtVerifier implements JwtVerifier {

    private final Map<String, AlgorithmVerifier> map;
    private final JwtKeySource keySource;
    private final JsonDataMapper mapper;
    private final String expectedIssuer;
    private final Duration clockSkew;
    private final Clock clock;

    private DJwtVerifier(
            Map<String, AlgorithmVerifier> map,
            JwtKeySource keySource,
            JsonDataMapper mapper,
            String expectedIssuer,
            Duration clockSkew,
            Clock clock) {
        this.map = map;
        this.keySource = keySource;
        this.mapper = mapper;
        this.expectedIssuer = expectedIssuer;
        this.clockSkew = clockSkew;
        this.clock = clock;
    }

    static JwtVerifier.Builder builder() {
        return new DBuilder();
    }

    @Override
    public AccessToken verifyAccessToken(String accessToken) throws JwtVerifyException {
        SignedJwt accessTokenJwt = SignedJwt.parse(accessToken);
        verify(accessTokenJwt);

        AccessToken accessTokenData;
        try {
            accessTokenData = mapper.readAccessToken(accessTokenJwt.payload());
        } catch (RuntimeException e) {
            throw new JwtVerifyException("Unable to parse Jwt access token " + e);
        }

        if (expectedIssuer != null && !expectedIssuer.equals(accessTokenData.issuer())) {
            throw new JwtVerifyException("Jwt unexpected issuer");
        }

        Instant now = Instant.now(clock);
        long expiredAt = accessTokenData.expiredAt();
        if (expiredAt > 0) {
            Instant expiry = Instant.ofEpochSecond(expiredAt);
            if (now.minus(clockSkew).isAfter(expiry)) {
                throw new JwtVerifyException("Jwt expired at " + expiry);
            }
        }

        long issuedAt = accessTokenData.issuedAt();
        if (issuedAt > 0) {
            Instant issAt = Instant.ofEpochSecond(issuedAt);
            if (now.plus(clockSkew).isBefore(issAt)) {
                throw new JwtVerifyException("Jwt invalid issuedAt " + issAt);
            }
        }
        return accessTokenData;
    }

    @Override
    public void verify(SignedJwt jwt) {
        JwtHeader jwtHeader;
        try {
            jwtHeader = mapper.readJwtHeader(jwt.header());
        } catch (RuntimeException e) {
            throw new JwtVerifyException("Unable to parse Jwt header " + e);
        }
        final String kid = jwtHeader.kid();
        final PublicKey publicKey = keySource.key(kid);
        if (publicKey == null) {
            throw new JwtVerifyException("Public key not found for kid " + kid);
        }

        final String alg = jwtHeader.alg();
        final AlgorithmVerifier verifier = map.get(alg);
        if (verifier == null) {
            throw new JwtVerifyException("Algorithm " + alg + " not supported");
        }

        if (!verifier.verify(publicKey, jwt.contentBytes(), jwt.signatureBytes())) {
            throw new JwtVerifyException("Signature verification failed");
        }
    }

    private static final class DBuilder implements JwtVerifier.Builder {

        private final Map<String, AlgorithmVerifier> map = new HashMap<>();
        private JwtKeySource keySource;
        private JsonDataMapper mapper;
        private String jwksUri;
        private HttpClient httpClient;
        private JsonMapper simpleMapper;
        private String expectedIssuer;
        private Duration clockSkew = Duration.of(60, ChronoUnit.SECONDS);
        private Clock clock = Clock.systemDefaultZone();

        @Override
        public JwtVerifier.Builder addRS256() {
            return add("RS256", "SHA256withRSA");
        }

        @Override
        public JwtVerifier.Builder add(String key, String algorithm) {
            map.put(key, new AlgorithmVerifier(new SignatureSupplier(algorithm)));
            return this;
        }

        @Override
        public Builder jwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        @Override
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        @Override
        public JwtVerifier.Builder keySource(JwtKeySource keySource) {
            this.keySource = keySource;
            return this;
        }

        @Override
        public JwtVerifier.Builder jsonMapper(JsonDataMapper mapper) {
            this.mapper = mapper;
            return this;
        }

        @Override
        public JwtVerifier.Builder issuer(String expectedIssuer) {
            this.expectedIssuer = expectedIssuer;
            if (jwksUri == null) {
                jwksUri = expectedIssuer + "/.well-known/jwks.json";
            }
            return this;
        }

        @Override
        public JwtVerifier.Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        @Override
        public JwtVerifier.Builder clockSkew(Duration clockSkew) {
            this.clockSkew = clockSkew;
            return this;
        }

        @Override
        public JwtVerifier build() {
            if (mapper == null) {
                if (simpleMapper == null) {
                    simpleMapper = JsonMapper.builder().build();
                }
                mapper = JsonDataMapper.builder().jsonMapper(simpleMapper).build();
            }
            if (keySource == null) {
                requireNonNull(jwksUri, "jwksUri is required");
                if (httpClient == null) {
                    httpClient = HttpClient.newHttpClient();
                }
                keySource = new RemoteKeySetSource(jwksUri, httpClient, mapper).build();
            }
            if (map.isEmpty()) {
                addRS256();
            }
            return new DJwtVerifier(map, keySource, mapper, expectedIssuer, clockSkew, clock);
        }
    }

    private static final class SignatureSupplier implements Supplier<Signature> {

        private final String algorithm;

        SignatureSupplier(String algorithm) {
            this.algorithm = algorithm;
        }

        @Override
        public Signature get() {
            try {
                return Signature.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new JwtVerifyException("Unsupported algorithm", e);
            }
        }
    }

    private static final class AlgorithmVerifier {

        private final Supplier<Signature> supplier;

        AlgorithmVerifier(Supplier<Signature> supplier) {
            this.supplier = supplier;
        }

        boolean verify(PublicKey publicKey, final byte[] content, final byte[] signature) {
            try {
                final Signature verifier = supplier.get();
                verifier.initVerify(publicKey);
                verifier.update(content);
                return verifier.verify(signature);
            } catch (InvalidKeyException e) {
                throw new JwtVerifyException("Invalid public key", e);
            } catch (SignatureException e) {
                return false;
            }
        }
    }
}
