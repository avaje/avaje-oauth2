package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.JwtHeader;
import io.avaje.oauth2.core.data.KeySet;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class JwtParseTest {

    @Test
    void test() {
        String rawToken = "eyJraWQiOiJqR3lQcEc4MDNTc1ZmSjRtZERkVktERDlVblFrN0dDQUtxTjJoM09mNmljPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiT1JvOFhfeHdPckRiUFRoTjdza0prQSIsInN1YiI6Ijc5MGU1NDY4LTUwYTEtNzBiOC01ZDUzLWYyYzc1YzYyYmQwMSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfWGpVSEo1SVV4IiwiY29nbml0bzp1c2VybmFtZSI6Ijc5MGU1NDY4LTUwYTEtNzBiOC01ZDUzLWYyYzc1YzYyYmQwMSIsIm5vbmNlIjoiNUQzTXA2VzhaWEhCMG5PRHQ3VzByTHVQMkhmVEdOeXNZZG9scjV6UjkyWSIsIm9yaWdpbl9qdGkiOiIyMGNiYTJhYy1iNTZlLTQ2ODQtOTc5Yi0wODE1OGJkNGU1ZjYiLCJhdWQiOiIxM21ycTNsa21pMTFyaDBrOWprdmxoM25nZSIsImV2ZW50X2lkIjoiNDU4N2U0OGEtNjUwOS00NDQyLWIyYWMtNjM5OGIwNzFkNGI1IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE3MzQ1Nzg1NDEsImV4cCI6MTczNDU4MjE0MSwiaWF0IjoxNzM0NTc4NTQxLCJqdGkiOiIzZGJlNjFjMi1iODdjLTQ4YWYtOTFhNS01NTE4MDcwMGZmYTMiLCJlbWFpbCI6InJvYmluLmJ5Z3JhdmVAZXJvYWQuY29tIn0.Vt0lKSUMXv0rIBSLAY2SKtwy_DaqBX8SNI_J6Ly2khKcXJw-Dy4IRzvHdn5nucHvX2mz6eV1g1EQ5LN3_T8ubf4KWHjyHstMlIV8r2MsMtKQbHn9XecuuWjhlzLPJS7-JeQhwvv7NOxIeOeJIZ8adiZqVjUvpAje3zoKGZLS_VlqK6G_fgcVUmHEZ5h1IZKqLTR3pyxWNaFN9gPEyjnqivnn_uScFm-Y8mXTUYinCW1ukRWYCoB1MuJgEHocixmprvk9oIihiPxWNo9US0gs1MTpfD0SDs-80nZq_3cGhWYedoj8iJ0Cu4GJzfjNTt2IYO2Ol78kcn-GcqWjmwXH-g";
        SignedJwt token = SignedJwt.parse(rawToken);

        assertThat(token.header()).isEqualTo("{\"kid\":\"jGyPpG803SsVfJ4mdDdVKDD9UnQk7GCAKqN2h3Of6ic=\",\"alg\":\"RS256\"}");
        assertThat(token.payload()).isEqualTo("{\"at_hash\":\"ORo8X_xwOrDbPThN7skJkA\",\"sub\":\"790e5468-50a1-70b8-5d53-f2c75c62bd01\",\"email_verified\":true,\"iss\":\"https:\\/\\/cognito-idp.ap-southeast-2.amazonaws.com\\/ap-southeast-2_XjUHJ5IUx\",\"cognito:username\":\"790e5468-50a1-70b8-5d53-f2c75c62bd01\",\"nonce\":\"5D3Mp6W8ZXHB0nODt7W0rLuP2HfTGNysYdolr5zR92Y\",\"origin_jti\":\"20cba2ac-b56e-4684-979b-08158bd4e5f6\",\"aud\":\"13mrq3lkmi11rh0k9jkvlh3nge\",\"event_id\":\"4587e48a-6509-4442-b2ac-6398b071d4b5\",\"token_use\":\"id\",\"auth_time\":1734578541,\"exp\":1734582141,\"iat\":1734578541,\"jti\":\"3dbe61c2-b87c-48af-91a5-55180700ffa3\",\"email\":\"robin.bygrave@eroad.com\"}");

        JsonDataMapper mapper = JsonDataMapper.builder().build();
        JwtHeader jwtHeader = mapper.readJwtHeader(token.header());
        assertThat(jwtHeader.kid()).isEqualTo("jGyPpG803SsVfJ4mdDdVKDD9UnQk7GCAKqN2h3Of6ic=");
        assertThat(jwtHeader.alg()).isEqualTo("RS256");

        InputStream is = JwtParseTest.class.getResourceAsStream("/keys.json");
        KeySet keySet = mapper.readKeySet(is);

        JwtKeySource keySource = JwtKeySource.build(keySet);
        PublicKey publicKey = keySource.key(jwtHeader.kid());
        assertThat(publicKey).isInstanceOf(RSAPublicKey.class);

        var signer = JwtVerifier.builder()
                .addRS256()
                .keySource(JwtKeySource.build(keySet))
                .build();

        assertThatNoException().isThrownBy(() -> signer.verify(token));
    }

}