package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

final class RemoteKeySetSource implements JwtKeySource {

    private final HttpClient httpClient;
    private final URI jwksUri;
    private final JsonDataMapper jsonMapper;
    private final ConcurrentHashMap<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

    RemoteKeySetSource(String jwksUri, HttpClient httpClient, JsonDataMapper jsonMapper) {
        this.httpClient = httpClient;
        this.jwksUri = URI.create(jwksUri);
        this.jsonMapper = jsonMapper;
    }

    JwtKeySource build() {
        reloadKeys();
        return this;
    }

    private void reloadKeys() {
        for (KeySet.KeyInfo key : readKeySet().keys()) {
            publicKeys.put(key.kid(), UtilRSA.createRsaKey(key));
        }
    }

    @Override
    public PublicKey key(String kid) {
        final PublicKey publicKey = publicKeys.get(kid);
        if (publicKey != null) {
            return publicKey;
        }
        // probably key rotation, so try to reload
        reloadKeys();
        final PublicKey refreshedKey = publicKeys.get(kid);
        if (refreshedKey == null) {
            throw new IllegalArgumentException("Unable to provide key for " + kid);
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
            throw new RuntimeException("Unexpected status code " + res.statusCode() + " obtaining jwks json from " + jwksUri);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
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
