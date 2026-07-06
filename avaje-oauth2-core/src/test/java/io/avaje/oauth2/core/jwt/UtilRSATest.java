package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.KeySet;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UtilRSATest {

    private static final String E = "AQAB";
    private static final String N = "5GSe0QejeIrhbhBPgJBOOfr_KIW6o3wpt6aoR4D_ft48ToLxAQKq6WLq-Ccb4lKIk-j1DbW3lju3DepugwR3IDtUuNO-zCi8--tAI2k_XgU-9oWoEifnz5RD0wlezjxBCjBMxxzhowD_EjcmyN5WUv0u4f3VMnKBsTSWxTkrShzYnmIoo8WEFk-UQKxw9AgDV_VtN4na8NnXiygJ8q0eD-S1tqOz-cvTZeh2qhkLOXyd_dguC7sdlPLb5-I-jszSYx1Ic88Os3UuPqHyLYccVuEd8Jb0dal6625bgD6fQuWVkmdit9xuySJAMKRWT-CSCTDXYcEBm9Vk-PCZOHhAtw";

    @Test
    void createRsaKey() {
        PublicKey pub = UtilRSA.createRsaKey(E, N);
        assertThat(pub).isNotNull();
    }

    @Test
    void createRsaKey_withRS256Algorithm_cognitoStyle() {
        var key = new KeySet.KeyInfo("RS256", E, "kid1", "RSA", N, "sig");
        assertThat(UtilRSA.createRsaKey(key)).isNotNull();
    }

    @Test
    void createRsaKey_withNullAlgorithm_entraStyle() {
        // Microsoft Entra ID's JWKS omits "alg" entirely — RFC 7517 says it's optional.
        var key = new KeySet.KeyInfo(null, E, "kid1", "RSA", N, "sig");
        assertThat(UtilRSA.createRsaKey(key)).isNotNull();
    }

    @Test
    void createRsaKey_withUnsupportedAlgorithm_throws() {
        var key = new KeySet.KeyInfo("ES256", E, "kid1", "RSA", N, "sig");
        assertThatThrownBy(() -> UtilRSA.createRsaKey(key))
                .isInstanceOf(JwtKeyException.class)
                .hasMessageContaining("ES256");
    }

    @Test
    void createRsaKey_withUnsupportedKeyType_throws() {
        var key = new KeySet.KeyInfo(null, E, "kid1", "EC", N, "sig");
        assertThatThrownBy(() -> UtilRSA.createRsaKey(key))
                .isInstanceOf(JwtKeyException.class)
                .hasMessageContaining("EC");
    }
}
