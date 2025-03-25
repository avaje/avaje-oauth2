package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WellKnownKeysMapperTest {

    @Test
    void read() {
        JsonDataMapper keyInfoMapper = JsonDataMapper.builder().build();
        InputStream is = WellKnownKeysMapperTest.class.getResourceAsStream("/keyinfo.json");
        KeySet keySet = keyInfoMapper.readKeySet(is);
        List<KeySet.KeyInfo> keys = keySet.keys();
        assertThat(keys).hasSize(2);

        KeySet.KeyInfo keyInfo = keys.get(0);
        assertThat(keyInfo.kid()).isEqualTo("Ydo2NcPgCy1bJWxWp4E9LZbSEO8fJUpA3IOOoDGK3kE=");
        assertThat(keyInfo.exponent()).isEqualTo("AQAB");
        assertThat(keyInfo.modulus()).isEqualTo("3gOV3HMljz3X2OeSzlCcrsP7k_FvHcRsPVKJkj2Xr_XwcsKDuODC32VvHTPMCSfdBix_x91X0RUzPeoVMca_axSaB91Feh-sA0wurTeWBrD4wfO879MfyuZc_ZzEETFWiHpJ8Y2MuRiJsmTjKCfLY-9576kxvCOUsxHH14Mg6KwhUoUr1WMZsi8Ye9tRFvX71PV9_mYe2v8F3QKmy_i0OO22BXYa3QyZYkd0EUrW_fTGIDp_1r2Ze1GId6aoT7HtaZcihQTevkGgtrvg6yYuah0r7ur1G9oPMbClxrYmmAHDmr91ySQmmHtCUpQaOvtp2QYB1rjfpSy-WnBUvP94Vw");
        assertThat(keyInfo.use()).isEqualTo("sig");
        assertThat(keyInfo.kty()).isEqualTo("RSA");
        assertThat(keyInfo.algorithm()).isEqualTo("RS256");
    }
}