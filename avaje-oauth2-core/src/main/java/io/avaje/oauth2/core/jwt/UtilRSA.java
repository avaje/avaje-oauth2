package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.KeySet;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

final class UtilRSA {

    static PublicKey createRsaKey(KeySet.KeyInfo key) {
        if (!"RS256".equals(key.algorithm())) {
            throw new IllegalArgumentException("Unsupported key algorithm: " + key.algorithm());
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
            throw new RuntimeException(e);
        }
    }

    private static BigInteger decodeToBigInteger(String base64Encoded) {
        byte[] eBytes = Base64.getUrlDecoder().decode(base64Encoded);
        return new BigInteger(1, eBytes);
    }
}
