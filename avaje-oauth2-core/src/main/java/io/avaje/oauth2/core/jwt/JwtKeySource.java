package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.KeySet;

import java.security.PublicKey;

/**
 * Source of public keys used to verify signed JWT tokens.
 */
public interface JwtKeySource {

    /**
     * Return the public key for the given key id.
     */
    PublicKey key(String kid) throws JwtKeyException;

    /**
     * Build an immutable KeySource from the KeySet.
     */
    static JwtKeySource build(KeySet keySet) {
        return ImmutableKeySource.build(keySet);
    }
}
