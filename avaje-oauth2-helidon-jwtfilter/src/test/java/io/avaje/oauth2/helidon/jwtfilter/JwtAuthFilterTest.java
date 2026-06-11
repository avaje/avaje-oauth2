package io.avaje.oauth2.helidon.jwtfilter;

import io.avaje.oauth2.core.data.AccessToken;
import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;
import io.avaje.oauth2.core.jwt.JwtKeySource;
import io.avaje.oauth2.core.jwt.JwtVerifier;
import io.avaje.oauth2.core.jwt.JwtVerifyException;
import io.avaje.oauth2.core.jwt.SignedJwt;
import io.helidon.common.context.Context;
import io.helidon.http.HeaderName;
import io.helidon.http.UnauthorizedException;
import io.helidon.webserver.http.FilterChain;
import io.helidon.webserver.http.RoutingRequest;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.security.Principal;
import java.util.Optional;

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

        //String issuer = "https://cognito-idp.REGION.amazonaws.com/REGION_FOO";
        JwtVerifier jwtVerifier = JwtVerifier.builder()
                // .issuer(issuer)
                .addRS256()
                .keySource(JwtKeySource.build(keySet))
                .build();

        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .permit("/ping")
                .verifier(jwtVerifier)
                .build();

        assertThat(filter).isNotNull();
    }

    @Test
    void build_withBearerAuthoriser() {
        InputStream is = JwtAuthFilterTest.class.getResourceAsStream("/keys.json");
        JsonDataMapper jsonMapper = JsonDataMapper.builder().build();
        KeySet keySet = jsonMapper.readKeySet(is);

        JwtVerifier jwtVerifier = JwtVerifier.builder()
                .addRS256()
                .keySource(JwtKeySource.build(keySet))
                .build();

        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .verifier(jwtVerifier)
                .bearerAuthoriser(token -> "secret".equals(token) ? "api-key" : null)
                .build();

        assertThat(filter).isNotNull();
    }

    @Test
    void bearerAuthoriser_acceptsApiKey_skipsJwt() {
        // ThrowingVerifier fails if the JWT path is taken -- proves authoriser precedence.
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new ThrowingVerifier())
                .bearerAuthoriser(token -> "secret-123".equals(token) ? "api-key" : null)
                .build();

        Context context = Context.create();
        FakeChain chain = new FakeChain();

        filter.filter(chain, fakeRequest("Bearer secret-123", "/v1/apps", context), null);

        assertThat(chain.proceeded).isTrue();
        assertThat(principalName(context)).isEqualTo("api-key");
    }

    @Test
    void bearerAuthoriser_returnsNull_fallsThroughToJwt() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-jwt", accessToken()))
                .bearerAuthoriser(t -> null)
                .build();

        Context context = Context.create();
        FakeChain chain = new FakeChain();

        filter.filter(chain, fakeRequest("Bearer good-jwt", "/v1/apps", context), null);

        assertThat(chain.proceeded).isTrue();
        assertThat(principalName(context)).isEqualTo("client123");
        assertThat(context.get("security.roles", String.class)).contains("insight/read");
    }

    @Test
    void bearerAuthoriser_returnsNull_andJwtInvalid_propagatesAndDoesNotProceed() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-jwt", accessToken()))
                .bearerAuthoriser(t -> null)
                .build();

        Context context = Context.create();
        FakeChain chain = new FakeChain();

        // Helidon variant does not wrap JwtVerifier failures (unlike the Jex variant);
        // an invalid JWT surfaces the JwtVerifyException. Key assertion: it does not proceed.
        assertThatThrownBy(() -> filter.filter(chain, fakeRequest("Bearer something-else", "/v1/apps", context), null))
                .isInstanceOf(JwtVerifyException.class);
        assertThat(chain.proceeded).isFalse();
    }

    @Test
    void noBearerAuthoriser_validBearer_proceeds() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .verifier(new FakeVerifier("good-jwt", accessToken()))
                .build();

        Context context = Context.create();
        FakeChain chain = new FakeChain();

        filter.filter(chain, fakeRequest("Bearer good-jwt", "/v1/apps", context), null);

        assertThat(chain.proceeded).isTrue();
        assertThat(principalName(context)).isEqualTo("client123");
    }

    @Test
    void noBearer_protectedPath_throws401() {
        JwtAuthFilter filter = JwtAuthFilter.builder()
                .permit("/health")
                .verifier(new FakeVerifier("good-jwt", accessToken()))
                .bearerAuthoriser(t -> "x".equals(t) ? "api" : null)
                .build();

        Context context = Context.create();
        FakeChain chain = new FakeChain();

        assertThatThrownBy(() -> filter.filter(chain, fakeRequest(null, "/v1/apps", context), null))
                .isInstanceOf(UnauthorizedException.class);
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

        Context context = Context.create();
        FakeChain chain = new FakeChain();

        filter.filter(chain, fakeRequest("Bearer bad", "/health/liveness", context), null);

        assertThat(chain.proceeded).isTrue();
    }

    private static String principalName(Context context) {
        return context.get("security.principal", Principal.class)
                .map(Principal::getName)
                .orElse(null);
    }

    /** JwtVerifier returning a preset token only for an exact match, else throws. */
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

    private static final class FakeChain implements FilterChain {
        boolean proceeded;

        @Override
        public void proceed() {
            proceeded = true;
        }
    }

    /**
     * Minimal {@link RoutingRequest} via dynamic proxy handling only
     * headers()/context()/path(), each itself a thin proxy. Mockito cannot mock
     * these Helidon interfaces under JPMS on recent JDKs.
     */
    private static RoutingRequest fakeRequest(String authHeader, String path, Context context) {
        Object headersProxy = Proxy.newProxyInstance(
                JwtAuthFilterTest.class.getClassLoader(),
                new Class<?>[]{io.helidon.http.ServerRequestHeaders.class},
                (p, method, args) -> switch (method.getName()) {
                    case "first" -> "authorization".equals(((HeaderName) args[0]).lowerCase())
                            ? Optional.ofNullable(authHeader) : Optional.empty();
                    case "toString" -> "FakeHeaders";
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == args[0];
                    default -> throw new UnsupportedOperationException("headers." + method.getName());
                });

        Object routedPath = Proxy.newProxyInstance(
                JwtAuthFilterTest.class.getClassLoader(),
                new Class<?>[]{io.helidon.http.RoutedPath.class},
                (p, method, args) -> switch (method.getName()) {
                    case "path" -> path;
                    case "toString" -> "FakePath";
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == args[0];
                    default -> throw new UnsupportedOperationException("path." + method.getName());
                });

        InvocationHandler handler = (p, method, args) -> switch (method.getName()) {
            case "headers" -> headersProxy;
            case "context" -> context;
            case "path" -> routedPath;
            case "toString" -> "FakeRoutingRequest";
            case "hashCode" -> System.identityHashCode(p);
            case "equals" -> p == args[0];
            default -> throw new UnsupportedOperationException("request." + method.getName());
        };
        return (RoutingRequest) Proxy.newProxyInstance(
                JwtAuthFilterTest.class.getClassLoader(),
                new Class<?>[]{RoutingRequest.class}, handler);
    }
}
