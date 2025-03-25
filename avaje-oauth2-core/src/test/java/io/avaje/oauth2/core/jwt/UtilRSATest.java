package io.avaje.oauth2.core.jwt;

import org.junit.jupiter.api.Test;

import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;

class UtilRSATest {

    @Test
    void createRsaKey() {
        String e = "AQAB";
        String n = "5GSe0QejeIrhbhBPgJBOOfr_KIW6o3wpt6aoR4D_ft48ToLxAQKq6WLq-Ccb4lKIk-j1DbW3lju3DepugwR3IDtUuNO-zCi8--tAI2k_XgU-9oWoEifnz5RD0wlezjxBCjBMxxzhowD_EjcmyN5WUv0u4f3VMnKBsTSWxTkrShzYnmIoo8WEFk-UQKxw9AgDV_VtN4na8NnXiygJ8q0eD-S1tqOz-cvTZeh2qhkLOXyd_dguC7sdlPLb5-I-jszSYx1Ic88Os3UuPqHyLYccVuEd8Jb0dal6625bgD6fQuWVkmdit9xuySJAMKRWT-CSCTDXYcEBm9Vk-PCZOHhAtw";

        PublicKey pub = UtilRSA.createRsaKey(e, n);
        assertThat(pub).isNotNull();
    }
}
