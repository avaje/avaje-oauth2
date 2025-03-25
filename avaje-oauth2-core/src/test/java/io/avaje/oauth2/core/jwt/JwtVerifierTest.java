package io.avaje.oauth2.core.jwt;

import io.avaje.oauth2.core.data.JsonDataMapper;
import io.avaje.oauth2.core.data.KeySet;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.*;

class JwtVerifierTest {

    JsonDataMapper jsonMapper = JsonDataMapper.builder().build();
    InputStream is = JwtVerifierTest.class.getResourceAsStream("/keys.json");
    KeySet keySet = jsonMapper.readKeySet(is);

    JwtVerifier signer = JwtVerifier.builder()
            .addRS256()
            .keySource(JwtKeySource.build(keySet))
            .build();

    @Test
    void verify() {
        String idToken = "eyJraWQiOiJqR3lQcEc4MDNTc1ZmSjRtZERkVktERDlVblFrN0dDQUtxTjJoM09mNmljPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiT1JvOFhfeHdPckRiUFRoTjdza0prQSIsInN1YiI6Ijc5MGU1NDY4LTUwYTEtNzBiOC01ZDUzLWYyYzc1YzYyYmQwMSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfWGpVSEo1SVV4IiwiY29nbml0bzp1c2VybmFtZSI6Ijc5MGU1NDY4LTUwYTEtNzBiOC01ZDUzLWYyYzc1YzYyYmQwMSIsIm5vbmNlIjoiNUQzTXA2VzhaWEhCMG5PRHQ3VzByTHVQMkhmVEdOeXNZZG9scjV6UjkyWSIsIm9yaWdpbl9qdGkiOiIyMGNiYTJhYy1iNTZlLTQ2ODQtOTc5Yi0wODE1OGJkNGU1ZjYiLCJhdWQiOiIxM21ycTNsa21pMTFyaDBrOWprdmxoM25nZSIsImV2ZW50X2lkIjoiNDU4N2U0OGEtNjUwOS00NDQyLWIyYWMtNjM5OGIwNzFkNGI1IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE3MzQ1Nzg1NDEsImV4cCI6MTczNDU4MjE0MSwiaWF0IjoxNzM0NTc4NTQxLCJqdGkiOiIzZGJlNjFjMi1iODdjLTQ4YWYtOTFhNS01NTE4MDcwMGZmYTMiLCJlbWFpbCI6InJvYmluLmJ5Z3JhdmVAZXJvYWQuY29tIn0.Vt0lKSUMXv0rIBSLAY2SKtwy_DaqBX8SNI_J6Ly2khKcXJw-Dy4IRzvHdn5nucHvX2mz6eV1g1EQ5LN3_T8ubf4KWHjyHstMlIV8r2MsMtKQbHn9XecuuWjhlzLPJS7-JeQhwvv7NOxIeOeJIZ8adiZqVjUvpAje3zoKGZLS_VlqK6G_fgcVUmHEZ5h1IZKqLTR3pyxWNaFN9gPEyjnqivnn_uScFm-Y8mXTUYinCW1ukRWYCoB1MuJgEHocixmprvk9oIihiPxWNo9US0gs1MTpfD0SDs-80nZq_3cGhWYedoj8iJ0Cu4GJzfjNTt2IYO2Ol78kcn-GcqWjmwXH-g";
        assertThatNoException().isThrownBy(() -> signer.verify(SignedJwt.parse(idToken)));
    }

    @Test
    void verifyOtherToken() {
        String accessToken  = "eyJraWQiOiJpTTh6MmRTMXlJQTZQUlZkQThnc05YZ0ZsWkp3UlNNNVdleW5yTGhhbHFrPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3OTBlNTQ2OC01MGExLTcwYjgtNWQ1My1mMmM3NWM2MmJkMDEiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfWGpVSEo1SVV4IiwidmVyc2lvbiI6MiwiY2xpZW50X2lkIjoiMTNtcnEzbGttaTExcmgwazlqa3ZsaDNuZ2UiLCJvcmlnaW5fanRpIjoiMjcyNjBlYzItNDg5Mi00NWI0LWE0YTEtZGFkMDVmOWZkODM0IiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJwaG9uZSBvcGVuaWQgZW1haWwiLCJhdXRoX3RpbWUiOjE3MzQ0OTQ5NjksImV4cCI6MTczNDQ5ODU2OSwiaWF0IjoxNzM0NDk0OTY5LCJqdGkiOiI2YjA5Y2JlNS1jM2NmLTQ5MzEtYTY4MS02YzljMTNlNzk2NjkiLCJ1c2VybmFtZSI6Ijc5MGU1NDY4LTUwYTEtNzBiOC01ZDUzLWYyYzc1YzYyYmQwMSJ9.InCl755u-uUHMtI7HYEosf8yVp2FKX-6NAGKnmoVP78fvCxYTlxMcBBPc3GQm52Vgj_Is3Q1PKYyBrvkfHECwfn_SEpvrr5z3yS5kM6TI5gk5hgTWLgLu2Jf-AWujfKwvZ4iF9sXPTDW9bdlKnRizBh0tM6Bx0WC2JisRKNMXw_paN_BFCjCWsvQGco5K8ln4aPtIFfr0EPSSTqNETeX_eRfLXtWfMVI4LZW-458CjB9lJ2sZNLGRhs-uySTE1HAkLaLwUxbghopKPNTz7WsKOUcC21SNXEv2s7FnjtlmHJTJMNzvqowGfiP--sdEbZuGdpGLyaNoFaGq8TUDsppag";
        assertThatNoException().isThrownBy(() -> signer.verify(SignedJwt.parse(accessToken)));
    }

}