package io.avaje.oauth2.core.data;

import java.util.List;

/**
 * JWK - Json well known key set.
 */
public record KeySet(List<KeyInfo> keys) {

    /**
     * JWK - Json well known key information.
     *
     * @param algorithm e.g. RS256
     * @param exponent
     * @param kid
     * @param kty
     * @param modulus
     * @param use
     */
    public record KeyInfo(
            String algorithm,
            String exponent,
            String kid,
            String kty,
            String modulus,
            String use) {
    }
}
