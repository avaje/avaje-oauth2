package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

final class RemoteKeySetSource implements JwtKeySource {

    private final HttpClient httpClient;
    private final URI jwksUri;
    private final JsonDataMapper jsonMapper;
    private final Clock clock;
    private final Duration minRefreshInterval;
    private final ReentrantLock reloadLock = new ReentrantLock();

    /** Immutable snapshot, fully replaced (not merged) on each reload so keys
     * rotated out of the upstream JWKS are evicted rather than trusted forever. */
    private volatile Map<String, PublicKey> publicKeys = Map.of();
    private volatile Instant lastReloadAt = Instant.EPOCH;

    RemoteKeySetSource(String jwksUri, HttpClient httpClient, JsonDataMapper jsonMapper, Clock clock, Duration minRefreshInterval) {
        this.httpClient = httpClient;
        this.jwksUri = URI.create(jwksUri);
        this.jsonMapper = jsonMapper;
        this.clock = clock;
        this.minRefreshInterval = minRefreshInterval;
    }

    JwtKeySource build() {
        reloadKeys();
        return this;
    }

    private void reloadKeys() {
        reloadLock.lock();
        try {
            // avoid a thundering herd of concurrent misses each hitting the JWKS
            // endpoint -- if another thread already refreshed while we were
            // waiting for the lock (or within the throttle window), skip.
            if (Instant.now(clock).isBefore(lastReloadAt.plus(minRefreshInterval))) {
                return;
            }
            Map<String, PublicKey> fresh = new HashMap<>();
            for (KeySet.KeyInfo key : readKeySet().keys()) {
                fresh.put(key.kid(), UtilRSA.createRsaKey(key));
            }
            publicKeys = Map.copyOf(fresh);
            lastReloadAt = Instant.now(clock);
        } finally {
            reloadLock.unlock();
        }
    }

    @Override
    public PublicKey key(String kid) throws JwtKeyException {
        final PublicKey publicKey = publicKeys.get(kid);
        if (publicKey != null) {
            return publicKey;
        }
        // Unknown kid - possibly legitimate key rotation, but throttle forced
        // reloads so a bogus/unknown kid can't force a remote JWKS fetch on
        // every single request (protects the IDP's JWKS endpoint).
        if (Instant.now(clock).isBefore(lastReloadAt.plus(minRefreshInterval))) {
            throw new JwtKeyException("Unable to provide key for " + kid);
        }
        reloadKeys();
        final PublicKey refreshedKey = publicKeys.get(kid);
        if (refreshedKey == null) {
            throw new JwtKeyException("Unable to provide key for " + kid);
        }
        return refreshedKey;
    }


    private KeySet readKeySet() {
        String body = readBody();
        return jsonMapper.readKeySet(body);
    }

    private String readBody() {
        try {
            HttpResponse<String> res = httpClient.send(request(), HttpResponse.BodyHandlers.ofString());
            int statusCode = res.statusCode();
            if (statusCode < 400) {
                return res.body();
            }
            throw new JwtKeyException("Unexpected status code " + res.statusCode() + " obtaining jwks json from " + jwksUri);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JwtKeyException("Error obtaining remote Key", e);
        } catch (IOException e) {
            throw new JwtKeyException("Error obtaining remote Key", e);
        }
    }

    private HttpRequest request() {
        return HttpRequest.newBuilder()
                .timeout(Duration.ofMillis(5000))
                .uri(jwksUri)
                .GET()
                .build();
    }
}
