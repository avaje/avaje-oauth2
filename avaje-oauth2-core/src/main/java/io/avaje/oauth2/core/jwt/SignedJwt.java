package io.avaje.oauth2.core.jwt;

/**
 * Signed JWT.
 *
 * @param header         The raw header content.
 * @param payload        The raw payload content.
 * @param contentBytes   The content bytes used for verifying.
 * @param signatureBytes The signature bytes for verifying.
 */
public record SignedJwt(
        String header,
        String payload,
        byte[] contentBytes,
        byte[] signatureBytes) {

    /**
     * Parse the raw JWT content and return as SignedJwt.
     *
     * @throws JwtVerifyException When the token is not SignedJwt
     */
    public static SignedJwt parse(String rawToken) throws JwtVerifyException {
        return SignedJwtParser.parse(rawToken);
    }

}
