package io.avaje.oauth2.core.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

final class SignedJwtParser {

    static SignedJwt parse(String rawToken) throws JwtVerifyException {
        int first = rawToken.indexOf('.');
        int second = rawToken.indexOf('.', first + 1);
        int third = rawToken.indexOf('.', second + 1);
        if (third != -1) {
            throw new JwtVerifyException("Only signed jwt token supported");
        }

        String headerDecoded = decodeString(rawToken.substring(0, first));
        String payloadDecoded = decodeString(rawToken.substring(first + 1, second));
        byte[] contentBytes = rawToken.substring(0, second).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = decode(rawToken.substring(second + 1));

        return new SignedJwt(headerDecoded, payloadDecoded, contentBytes, signatureBytes);
    }

    private static byte[] decode(String base64Content) {
        return Base64.getUrlDecoder().decode(base64Content);
    }

    static String decodeString(String base64Content) {
        return new String(decode(base64Content), UTF_8);
    }
}
