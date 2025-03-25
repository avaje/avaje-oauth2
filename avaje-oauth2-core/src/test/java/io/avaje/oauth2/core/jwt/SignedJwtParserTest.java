package io.avaje.oauth2.core.jwt;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SignedJwtParserTest {

    @Test
    void decodeString() {
        String content = "eyJraWQiOiJqR3lQcEc4MDNTc1ZmSjRtZERkVktERDlVblFrN0dDQUtxTjJoM09mNmljPSIsImFsZyI6IlJTMjU2In0";
        String h0 = "eyJraWQiOiJqR3lQcEc4MDNTc1ZmSjRtZERkVktERDlVblFrN0dDQUtxTjJoM09mNmljPSIsImFsZyI6IlJTMjU2In0";
        String h1 = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ";

        assertThat(SignedJwtParser.decodeString(content)).isEqualTo("{\"kid\":\"jGyPpG803SsVfJ4mdDdVKDD9UnQk7GCAKqN2h3Of6ic=\",\"alg\":\"RS256\"}");
        assertThat(SignedJwtParser.decodeString(h0)).isEqualTo("{\"kid\":\"jGyPpG803SsVfJ4mdDdVKDD9UnQk7GCAKqN2h3Of6ic=\",\"alg\":\"RS256\"}");
        assertThat(SignedJwtParser.decodeString(h1)).isEqualTo("{\"cty\":\"JWT\",\"enc\":\"A256GCM\",\"alg\":\"RSA-OAEP\"}");
    }
}
