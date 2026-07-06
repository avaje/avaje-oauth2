package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.KeySet;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

final class UtilRSA {

    static PublicKey createRsaKey(KeySet.KeyInfo key) {
        // The "alg" member is OPTIONAL per RFC 7517 — e.g. Microsoft Entra ID's
        // JWKS omits it (only kty/use/kid/n/e), while AWS Cognito includes it.
        // Only reject when an algorithm IS present and it's not the one we support.
        String algorithm = key.algorithm();
        if (algorithm != null && !"RS256".equals(algorithm)) {
            throw new JwtKeyException("Unsupported key algorithm: " + algorithm);
        }
        if (!"RSA".equals(key.kty())) {
            throw new JwtKeyException("Unsupported key type: " + key.kty());
        }
        return createRsaKey(key.exponent(), key.modulus());
    }

    static PublicKey createRsaKey(String exponentBase64, String modulusBase64) {
        try {
            BigInteger exponent = decodeToBigInteger(exponentBase64);
            BigInteger modulus = decodeToBigInteger(modulusBase64);

            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (Exception e) {
            throw new JwtKeyException("Unable to create PublicKey", e);
        }
    }

    private static BigInteger decodeToBigInteger(String base64Encoded) {
        byte[] eBytes = Base64.getUrlDecoder().decode(base64Encoded);
        return new BigInteger(1, eBytes);
    }
}
