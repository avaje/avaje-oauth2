package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.KeySet;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test-only helper that signs RS256 JWTs with an in-memory RSA keypair, so
 * tests can exercise {@link JwtVerifier} claim validation (audience, nbf,
 * expiry etc) with arbitrary custom claims rather than being limited to
 * pre-captured real tokens.
 */
final class TestJwtSigner {

    private final KeyPair keyPair;
    private final String kid;

    TestJwtSigner(String kid) {
        this.kid = kid;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    String kid() {
        return kid;
    }

    /** The JWKS containing this signer's public key, for use as a {@link JwtKeySource}. */
    KeySet keySet() {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String n = base64Url(publicKey.getModulus());
        String e = base64Url(publicKey.getPublicExponent());
        return new KeySet(List.of(new KeySet.KeyInfo("RS256", e, kid, "RSA", n, "sig")));
    }

    /** Sign the given claims as a compact RS256 JWT. */
    String sign(Map<String, Object> claims) {
        String header = base64UrlJson(Map.of("alg", "RS256", "kid", kid, "typ", "JWT"));
        String payload = base64UrlJson(claims);
        String signingInput = header + "." + payload;
        byte[] signature = sign(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }

    private byte[] sign(byte[] content) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(content);
            return signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64Url(BigInteger value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray());
    }

    private static String base64UrlJson(Map<String, ?> values) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toJson(values).getBytes(StandardCharsets.UTF_8));
    }

    /** Minimal JSON object serialization - only needs to support the simple
     * String/Number claim values used in tests. */
    private static String toJson(Map<String, ?> values) {
        var sb = new StringBuilder("{");
        var entries = new LinkedHashMap<>(values).entrySet();
        boolean first = true;
        for (var entry : entries) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(entry.getKey()).append("\":");
            appendValue(sb, entry.getValue());
        }
        return sb.append('}').toString();
    }

    private static void appendValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Number) {
            sb.append(value);
        } else {
            sb.append('"').append(value.toString().replace("\"", "\\\"")).append('"');
        }
    }
}
