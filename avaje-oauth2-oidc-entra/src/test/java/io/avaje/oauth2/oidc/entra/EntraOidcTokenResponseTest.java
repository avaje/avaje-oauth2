package io.avaje.oauth2.oidc.entra;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

class EntraOidcTokenResponseTest {

    @Test
    void confidentialClientSendsCredentialsInFormBody() throws IOException {
        AtomicReference<String> requestBody = new AtomicReference<>();
        AtomicReference<String> authorization = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/token", exchange -> {
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] body = "{\"access_token\":\"token\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
        try {
            EntraOidc oidc = EntraOidc.builder()
                    .clientId("client")
                    .clientSecret("secret")
                    .domain("http://127.0.0.1:" + server.getAddress().getPort())
                    .tokenUri("http://127.0.0.1:" + server.getAddress().getPort() + "/token")
                    .redirectUri("http://127.0.0.1/callback")
                    .build();

            oidc.obtainTokens("code", "verifier");

            assertThat(requestBody).hasValue(
                    "grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback"
                            + "&code_verifier=verifier&client_id=client&client_secret=secret");
            assertThat(authorization).hasValue(null);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void tokenEndpointErrorIncludesResponseBody() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/token", exchange -> {
            byte[] body = "{\"error\":\"invalid_client\",\"error_description\":\"client authentication failed\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
        try {
            EntraOidc oidc = EntraOidc.builder()
                    .clientId("client")
                    .domain("http://127.0.0.1:" + server.getAddress().getPort())
                    .tokenUri("http://127.0.0.1:" + server.getAddress().getPort() + "/token")
                    .redirectUri("http://127.0.0.1/callback")
                    .build();

            assertThatThrownBy(() -> oidc.obtainTokens("code"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("HTTP 401")
                    .hasMessageContaining("invalid_client")
                    .hasMessageContaining("client authentication failed");
        } finally {
            server.stop(0);
        }
    }
}
