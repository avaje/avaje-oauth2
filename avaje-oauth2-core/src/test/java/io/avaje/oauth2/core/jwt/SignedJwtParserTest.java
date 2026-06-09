package io.avaje.oauth2.core.jwt;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignedJwtParserTest {

    @Test
    void parse_noDots_throwsJwtVerifyException() {
        assertThatThrownBy(() -> SignedJwtParser.parse("not-a-real-token"))
            .isInstanceOf(JwtVerifyException.class)
            .hasMessageContaining("Malformed jwt token");
    }

    @Test
    void parse_emptyToken_throwsJwtVerifyException() {
        assertThatThrownBy(() -> SignedJwtParser.parse(""))
            .isInstanceOf(JwtVerifyException.class)
            .hasMessageContaining("Malformed jwt token");
    }

    @Test
    void parse_onlyOneDot_throwsJwtVerifyException() {
        assertThatThrownBy(() -> SignedJwtParser.parse("header.payload"))
            .isInstanceOf(JwtVerifyException.class)
            .hasMessageContaining("Malformed jwt token");
    }

    @Test
    void parse_tooManySegments_throwsJwtVerifyException() {
        assertThatThrownBy(() -> SignedJwtParser.parse("a.b.c.d"))
            .isInstanceOf(JwtVerifyException.class)
            .hasMessageContaining("Only signed jwt token supported");
    }

    @Test
    void parse_invalidBase64_throwsJwtVerifyException() {
        assertThatThrownBy(() -> SignedJwtParser.parse("!!!.@@@.###"))
            .isInstanceOf(JwtVerifyException.class)
            .hasMessageContaining("Malformed jwt token");
    }

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
