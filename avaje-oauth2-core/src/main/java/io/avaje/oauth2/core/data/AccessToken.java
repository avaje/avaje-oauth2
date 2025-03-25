package io.avaje.oauth2.core.data;

public record AccessToken(
        String sub,
        String tokenUse,
        String scope,
        long authTime,
        String issuer,
        long expiredAt,
        long issuedAt,
        int version,
        String jti,
        String clientId) {
}

