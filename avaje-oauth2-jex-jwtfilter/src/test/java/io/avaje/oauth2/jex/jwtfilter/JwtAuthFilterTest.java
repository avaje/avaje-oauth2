package io.avaje.oauth2.jex.jwtfilter;

import io.avaje.jex.http.Context;
import io.avaje.jex.http.HttpFilter;
import io.avaje.jex.http.HttpResponseException;
import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;
import io.avaje.oauth2.core.jwt.JwtKeySource;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.avaje.oauth2.core.jwt.JwtVerifyException;
import io.avaje.oauth2.core.jwt.SignedJwt;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtAuthFilterTest {

    private static AccessToken accessToken() {
        return new AccessToken("sub1", "access", "insight/read", 0L,
                "issuer", 0L, 0L, 1, "jti1", "client123");
    }

    @Test
    void build() {
        InputStream is = JwtAuthFilterTest.class.getResourceAsStream("/keys.json");
        JsonDataMapper jsonMapper = JsonDataMapper.builder().build();
        KeySet keySet = jsonMapper.readKeySet(is);

        JwtVerifier jwtVerifier = JwtVerifier.builder()
                .addRS256()
                .keySource(JwtKeySource.build(keySet))
                .build();

        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .permit("/api/ingest")
                .verifier(jwtVerifier)
                .build();

        assertThat(filter).isNotNull().isInstanceOf(HttpFilter.class);
    }

    @Test
    void build_requiresVerifier() {
        assertThatThrownBy(() -> JwtAuthFilter.builder().permit("/health").build())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void validBearer_proceedsAndRegistersAttributes() {
        AccessToken token = accessToken();
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-token", token))
                .build();

        FakeContext ctx = new FakeContext("Bearer good-token", "/v1/apps");
        FakeChain chain = new FakeChain();

        filter.filter(ctx.asContext(), chain);

        assertThat(chain.proceeded).isTrue();
        assertThat(ctx.attributes.get(AuthFilter.ATTR_ACCESS_TOKEN)).isSameAs(token);
        assertThat(ctx.attributes.get(AuthFilter.ATTR_PRINCIPAL)).isEqualTo("client123");
        assertThat(ctx.attributes.get(AuthFilter.ATTR_SCOPE)).isEqualTo("insight/read");
    }

    @Test
    void invalidBearer_throws401() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-token", accessToken()))
                .build();

        FakeContext ctx = new FakeContext("Bearer bad", "/v1/apps");
        FakeChain chain = new FakeChain();

        assertThatThrownBy(() -> filter.filter(ctx.asContext(), chain))
                .isInstanceOf(HttpResponseException.class)
                .satisfies(e -> assertThat(((HttpResponseException) e).status()).isEqualTo(401));
        assertThat(chain.proceeded).isFalse();
    }

    @Test
    void noAuth_permittedPath_proceeds() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .verifier(new FakeVerifier("x", accessToken()))
                .build();

        FakeContext ctx = new FakeContext(null, "/health/liveness");
        FakeChain chain = new FakeChain();

        filter.filter(ctx.asContext(), chain);

        assertThat(chain.proceeded).isTrue();
    }

    @Test
    void noAuth_protectedPath_throws401() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .verifier(new FakeVerifier("x", accessToken()))
                .build();

        FakeContext ctx = new FakeContext(null, "/v1/apps");
        FakeChain chain = new FakeChain();

        assertThatThrownBy(() -> filter.filter(ctx.asContext(), chain))
                .isInstanceOf(HttpResponseException.class)
                .satisfies(e -> assertThat(((HttpResponseException) e).status()).isEqualTo(401));
        assertThat(chain.proceeded).isFalse();
    }

    @Test
    void bearerAuthoriser_acceptsApiKey_skipsJwt() {
        // ThrowingVerifier fails if the JWT path is taken -- proves authoriser precedence.
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new ThrowingVerifier())
                .bearerAuthoriser(token -> "secret-123".equals(token) ? "api-key" : null)
                .build();

        FakeContext ctx = new FakeContext("Bearer secret-123", "/v1/apps");
        FakeChain chain = new FakeChain();

        filter.filter(ctx.asContext(), chain);

        assertThat(chain.proceeded).isTrue();
        assertThat(ctx.attributes.get(AuthFilter.ATTR_PRINCIPAL)).isEqualTo("api-key");
        assertThat(ctx.attributes.get(AuthFilter.ATTR_ACCESS_TOKEN)).isNull();
        assertThat(ctx.attributes.get(AuthFilter.ATTR_SCOPE)).isNull();
    }

    @Test
    void bearerAuthoriser_returnsNull_fallsThroughToJwt() {
        AccessToken token = accessToken();
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-jwt", token))
                .bearerAuthoriser(t -> null)
                .build();

        FakeContext ctx = new FakeContext("Bearer good-jwt", "/v1/apps");
        FakeChain chain = new FakeChain();

        filter.filter(ctx.asContext(), chain);

        assertThat(chain.proceeded).isTrue();
        assertThat(ctx.attributes.get(AuthFilter.ATTR_ACCESS_TOKEN)).isSameAs(token);
        assertThat(ctx.attributes.get(AuthFilter.ATTR_PRINCIPAL)).isEqualTo("client123");
    }

    @Test
    void bearerAuthoriser_returnsNull_andJwtInvalid_throws401() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-jwt", accessToken()))
                .bearerAuthoriser(t -> null)
                .build();

        FakeContext ctx = new FakeContext("Bearer something-else", "/v1/apps");
        FakeChain chain = new FakeChain();

        assertThatThrownBy(() -> filter.filter(ctx.asContext(), chain))
                .isInstanceOf(HttpResponseException.class)
                .satisfies(e -> assertThat(((HttpResponseException) e).status()).isEqualTo(401));
        assertThat(chain.proceeded).isFalse();
    }

    @Test
    void permittedPath_ignoresAuth_evenWithInvalidBearer() {
        // permit is checked first: neither bearerAuthoriser nor JWT verify should run.
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .verifier(new ThrowingVerifier())
                .bearerAuthoriser(token -> {
                    throw new AssertionError("bearerAuthoriser should not run on permitted path");
                })
                .build();

        FakeContext ctx = new FakeContext("Bearer bad", "/health/liveness");
        FakeChain chain = new FakeChain();

        filter.filter(ctx.asContext(), chain);

        assertThat(chain.proceeded).isTrue();
    }

    /** JwtVerifier that returns a preset token only for an exact match, else 401. */
    private static final class FakeVerifier implements JwtVerifier {
        private final String validToken;
        private final AccessToken result;

        FakeVerifier(String validToken, AccessToken result) {
            this.validToken = validToken;
            this.result = result;
        }

        @Override
        public void verify(SignedJwt jwt) {
            throw new UnsupportedOperationException();
        }

        @Override
        public AccessToken verifyAccessToken(String accessToken) throws JwtVerifyException {
            if (!validToken.equals(accessToken)) {
                throw new JwtVerifyException("invalid token");
            }
            return result;
        }
    }

    /** JwtVerifier that fails the test if its verify path is reached. */
    private static final class ThrowingVerifier implements JwtVerifier {
        @Override
        public void verify(SignedJwt jwt) {
            throw new AssertionError("JWT verify should not be called");
        }

        @Override
        public AccessToken verifyAccessToken(String accessToken) {
            throw new AssertionError("JWT verifyAccessToken should not be called");
        }
    }

    private static final class FakeChain implements HttpFilter.FilterChain {
        boolean proceeded;

        @Override
        public void proceed() {
            proceeded = true;
        }
    }

    /**
     * Minimal {@link Context} via dynamic proxy handling only header/path/attribute
     * (Mockito cannot mock the Jex Context interface under JPMS on recent JDKs).
     */
    private static final class FakeContext {
        final Map<String, Object> attributes = new HashMap<>();
        private final Context proxy;

        FakeContext(String authHeader, String path) {
            InvocationHandler handler = (p, method, args) -> switch (method.getName()) {
                case "header" -> "Authorization".equals(args[0]) ? authHeader : null;
                case "path" -> path;
                case "attribute" -> {
                    attributes.put((String) args[0], args[1]);
                    yield p;
                }
                case "toString" -> "FakeContext";
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == args[0];
                default -> throw new UnsupportedOperationException("Unexpected Context call: " + method.getName());
            };
            this.proxy = (Context) Proxy.newProxyInstance(
                    Context.class.getClassLoader(), new Class<?>[]{Context.class}, handler);
        }

        Context asContext() {
            return proxy;
        }
    }
}
