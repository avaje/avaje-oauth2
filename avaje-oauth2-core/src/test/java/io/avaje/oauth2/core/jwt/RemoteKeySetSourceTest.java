package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteKeySetSourceTest {

    private static final String E = "AQAB";
    private static final String N = "5GSe0QejeIrhbhBPgJBOOfr_KIW6o3wpt6aoR4D_ft48ToLxAQKq6WLq-Ccb4lKIk-j1DbW3lju3DepugwR3IDtUuNO-zCi8--tAI2k_XgU-9oWoEifnz5RD0wlezjxBCjBMxxzhowD_EjcmyN5WUv0u4f3VMnKBsTSWxTkrShzYnmIoo8WEFk-UQKxw9AgDV_VtN4na8NnXiygJ8q0eD-S1tqOz-cvTZeh2qhkLOXyd_dguC7sdlPLb5-I-jszSYx1Ic88Os3UuPqHyLYccVuEd8Jb0dal6625bgD6fQuWVkmdit9xuySJAMKRWT-CSCTDXYcEBm9Vk-PCZOHhAtw";

    private static final String JWKS_ONLY_A = jwks("kid-a");
    private static final String JWKS_FULL = jwksTwo("kid-a", "kid-b");

    private static String jwks(String kid) {
        return "{\"keys\":[" + key(kid) + "]}";
    }

    private static String jwksTwo(String kidA, String kidB) {
        return "{\"keys\":[" + key(kidA) + "," + key(kidB) + "]}";
    }

    private static String key(String kid) {
        return "{\"alg\":\"RS256\",\"e\":\"" + E + "\",\"kid\":\"" + kid + "\",\"kty\":\"RSA\",\"n\":\"" + N + "\",\"use\":\"sig\"}";
    }

    /** A Clock whose instant can be advanced between test steps. */
    private static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** Minimal raw-socket HTTP/1.1 server (avoids the JDK-internal
     * {@code com.sun.net.httpserver} module which isn't readable from this
     * module without extra module config) - accepts one connection at a
     * time, always replies with the current {@link #body} and closes. */
    private ServerSocket serverSocket;
    private ExecutorService serverPool;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicInteger requestCount = new AtomicInteger();
    private volatile String body = JWKS_FULL;

    private String start() throws IOException {
        serverSocket = new ServerSocket(0);
        serverPool = Executors.newCachedThreadPool();
        serverPool.submit(this::acceptLoop);
        return "http://localhost:" + serverSocket.getLocalPort() + "/jwks";
    }

    private void acceptLoop() {
        while (running.get()) {
            try (Socket socket = serverSocket.accept()) {
                requestCount.incrementAndGet();
                consumeRequest(socket.getInputStream());
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                OutputStream out = socket.getOutputStream();
                out.write(("HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Content-Length: " + bytes.length + "\r\n"
                        + "Connection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
                out.write(bytes);
                out.flush();
            } catch (IOException e) {
                // socket closed on shutdown - stop looping
                return;
            }
        }
    }

    private void consumeRequest(InputStream in) throws IOException {
        // read (and discard) the request line + headers up to the blank line
        int prev = -1;
        int cur;
        int newlineRun = 0;
        while ((cur = in.read()) != -1) {
            if (cur == '\n' && prev == '\r') {
                newlineRun++;
                if (newlineRun == 2) {
                    return;
                }
            } else if (cur != '\r') {
                newlineRun = 0;
            }
            prev = cur;
        }
    }

    @AfterEach
    void shutdown() throws IOException {
        running.set(false);
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverPool != null) {
            serverPool.shutdownNow();
        }
    }

    private RemoteKeySetSource newSource(String jwksUri, Clock clock, Duration minRefreshInterval) {
        JsonDataMapper mapper = JsonDataMapper.builder().build();
        return (RemoteKeySetSource) new RemoteKeySetSource(jwksUri, HttpClient.newHttpClient(), mapper, clock, minRefreshInterval).build();
    }

    @Test
    void initialBuild_fetchesOnce_andResolvesKnownKid() throws Exception {
        body = JWKS_FULL;
        String uri = start();

        RemoteKeySetSource source = newSource(uri, Clock.systemUTC(), Duration.ofSeconds(60));

        assertThat(requestCount.get()).isEqualTo(1);
        assertThat(source.key("kid-a")).isNotNull();
        assertThat(source.key("kid-b")).isNotNull();
        // resolving known kids from cache must not trigger further fetches
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void unknownKid_withinThrottleWindow_failsFastWithoutRefetch() throws Exception {
        body = JWKS_ONLY_A;
        String uri = start();
        MutableClock clock = new MutableClock(Instant.parse("2024-01-01T00:00:00Z"));

        RemoteKeySetSource source = newSource(uri, clock, Duration.ofSeconds(60));
        assertThat(requestCount.get()).isEqualTo(1);

        assertThatThrownBy(() -> source.key("kid-unknown"))
                .isInstanceOf(JwtKeyException.class);
        // still within the throttle window since build() - no extra fetch
        assertThat(requestCount.get()).isEqualTo(1);

        clock.advance(Duration.ofSeconds(30));
        assertThatThrownBy(() -> source.key("kid-unknown"))
                .isInstanceOf(JwtKeyException.class);
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void unknownKid_afterThrottleWindowElapses_triggersExactlyOneReload() throws Exception {
        body = JWKS_ONLY_A;
        String uri = start();
        MutableClock clock = new MutableClock(Instant.parse("2024-01-01T00:00:00Z"));

        RemoteKeySetSource source = newSource(uri, clock, Duration.ofSeconds(60));
        assertThat(requestCount.get()).isEqualTo(1);

        // rotate in kid-b server-side, then let the throttle window elapse
        body = JWKS_FULL;
        clock.advance(Duration.ofSeconds(61));

        assertThat(source.key("kid-b")).isNotNull();
        assertThat(requestCount.get()).isEqualTo(2);

        // now resolvable from the refreshed cache without further fetches
        assertThat(source.key("kid-b")).isNotNull();
        assertThat(requestCount.get()).isEqualTo(2);
    }

    @Test
    void rotatedOutKey_isEvicted_afterAReloadOccurs() throws Exception {
        body = JWKS_FULL;
        String uri = start();
        MutableClock clock = new MutableClock(Instant.parse("2024-01-01T00:00:00Z"));

        RemoteKeySetSource source = newSource(uri, clock, Duration.ofSeconds(60));
        assertThat(source.key("kid-b")).isNotNull();
        assertThat(requestCount.get()).isEqualTo(1);

        // revoke kid-b server-side
        body = JWKS_ONLY_A;
        clock.advance(Duration.ofSeconds(61));

        // force a reload via an unrelated miss
        assertThatThrownBy(() -> source.key("kid-does-not-exist"))
                .isInstanceOf(JwtKeyException.class);
        assertThat(requestCount.get()).isEqualTo(2);

        // kid-b was evicted by the wholesale cache replacement - now also fails,
        // and (still within the throttle window from the reload just above) does
        // so without triggering yet another remote fetch.
        assertThatThrownBy(() -> source.key("kid-b"))
                .isInstanceOf(JwtKeyException.class);
        assertThat(requestCount.get()).isEqualTo(2);
    }

    @Test
    void concurrentMisses_coalesceIntoASingleReload() throws Exception {
        body = JWKS_ONLY_A;
        String uri = start();
        MutableClock clock = new MutableClock(Instant.parse("2024-01-01T00:00:00Z"));

        RemoteKeySetSource source = newSource(uri, clock, Duration.ofSeconds(60));
        assertThat(requestCount.get()).isEqualTo(1);

        clock.advance(Duration.ofSeconds(61));

        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        go.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    try {
                        source.key("kid-concurrent-unknown");
                    } catch (JwtKeyException expected) {
                        // expected - this kid never exists
                    }
                });
            }
            ready.await();
            go.countDown();
        } finally {
            pool.shutdown();
            pool.awaitTermination(10, TimeUnit.SECONDS);
        }

        // exactly one additional fetch, despite many concurrent misses
        assertThat(requestCount.get()).isEqualTo(2);
    }
}
