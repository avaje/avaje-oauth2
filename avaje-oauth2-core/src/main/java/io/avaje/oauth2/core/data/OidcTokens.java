package io.avaje.oauth2.core.data;

public record OidcTokens(
        String idToken,
        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType) {
}
