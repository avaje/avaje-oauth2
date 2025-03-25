package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.KeySet;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class ImmutableKeySource implements JwtKeySource {

    private final Map<String, PublicKey> keyMap;

    private ImmutableKeySource(Map<String, PublicKey> keyMap) {
        this.keyMap = keyMap;
    }

    static ImmutableKeySource build(KeySet keySet) {
        Map<String, PublicKey> publicKeyMap = new HashMap<>();
        List<KeySet.KeyInfo> keys = keySet.keys();
        for (KeySet.KeyInfo key : keys) {
            publicKeyMap.put(key.kid(), UtilRSA.createRsaKey(key));
        }
        return new ImmutableKeySource(publicKeyMap);
    }

    @Override
    public PublicKey key(String kid) {
        return keyMap.get(kid);
    }

}
