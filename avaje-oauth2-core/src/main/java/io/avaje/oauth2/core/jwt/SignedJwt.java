
package io.avaje.oauth2.core.jwt;

public record SignedJwt(
        String header,
        String payload,
        byte[] contentBytes,
        byte[] signatureBytes) {

    public static SignedJwt parse(String rawToken) {
        return SignedJwtParser.parse(rawToken);
    }

}
