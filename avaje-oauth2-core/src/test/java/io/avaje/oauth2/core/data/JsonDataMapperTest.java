package io.avaje.oauth2.core.data;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class JsonDataMapperTest {

    final JsonDataMapper jsonDataMapper = JsonDataMapper.builder().build();

    @Test
    void accessToken() {
        String asd = """
            {
                "sub" : "mySub",
                "token_use" : "access",
                "scope" : "myScope",
                "auth_time" : 1738903492,
                "iss" : "myIssuer",
                "exp" : 1738907092,
                "iat" : 1738903492,
                "version" : 2,
                "jti" : "myJti",
                "client_id" : "myClientId",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(asd);

        assertThat(accessToken.sub()).isEqualTo("mySub");
        assertThat(accessToken.tokenUse()).isEqualTo("access");
        assertThat(accessToken.scope()).isEqualTo("myScope");
        assertThat(accessToken.authTime()).isEqualTo(1738903492);
        assertThat(accessToken.issuer()).isEqualTo("myIssuer");
        assertThat(accessToken.expiredAt()).isEqualTo(1738907092);
        assertThat(accessToken.issuedAt()).isEqualTo(1738903492);
        assertThat(accessToken.version()).isEqualTo(2);
        assertThat(accessToken.jti()).isEqualTo("myJti");
        assertThat(accessToken.clientId()).isEqualTo("myClientId");
        assertThat(accessToken.email()).isNull();
    }

    @Test
    void accessToken_entraStyle_fallsBackToScpAndAzp() {
        // Microsoft Entra ID tokens use scp/azp instead of Cognito's scope/client_id.
        String json = """
            {
                "sub" : "mySub",
                "iss" : "myIssuer",
                "exp" : 1738907092,
                "iat" : 1738903492,
                "scp" : "access_as_user",
                "azp" : "myAppClientId",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.sub()).isEqualTo("mySub");
        assertThat(accessToken.scope()).isEqualTo("access_as_user");
        assertThat(accessToken.clientId()).isEqualTo("myAppClientId");
    }

    @Test
    void accessToken_entraV1Style_fallsBackToAppid() {
        // Entra v1.0 tokens use appid rather than azp for the client id.
        String json = """
            {
                "sub" : "mySub",
                "iss" : "myIssuer",
                "exp" : 1738907092,
                "iat" : 1738903492,
                "scp" : "access_as_user",
                "appid" : "myAppClientId",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.clientId()).isEqualTo("myAppClientId");
    }

    @Test
    void accessToken_prefersCognitoClaimsWhenBothPresent() {
        String json = """
            {
                "sub" : "mySub",
                "scope" : "cognitoScope",
                "scp" : "entraScope",
                "client_id" : "cognitoClientId",
                "azp" : "entraClientId",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.scope()).isEqualTo("cognitoScope");
        assertThat(accessToken.clientId()).isEqualTo("cognitoClientId");
    }

    @Test
    void accessToken_email_isOnlyPopulatedFromEmailClaim() {
        // email and upn are distinct claims/fields — no fallback between them.
        String json = """
            {
                "sub" : "mySub",
                "email" : "robin.bygrave@eroad.com",
                "upn" : "different-upn@eroad.com",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.email()).isEqualTo("robin.bygrave@eroad.com");
        assertThat(accessToken.upn()).isEqualTo("different-upn@eroad.com");
    }

    @Test
    void accessToken_email_isNull_whenOnlyUpnPresent() {
        String json = """
            {
                "sub" : "mySub",
                "upn" : "robin.bygrave@eroad.com",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.email()).isNull();
        assertThat(accessToken.upn()).isEqualTo("robin.bygrave@eroad.com");
    }

    @Test
    void accessToken_upn_fallsBackToUniqueName_entraV1Style() {
        // Entra v1.0 tokens use unique_name rather than upn — same concept, different claim name.
        String json = """
            {
                "sub" : "mySub",
                "unique_name" : "robin.bygrave@eroad.com",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.upn()).isEqualTo("robin.bygrave@eroad.com");
    }

    @Test
    void accessToken_upn_prefersUpnOverUniqueName_whenBothPresent() {
        String json = """
            {
                "sub" : "mySub",
                "upn" : "v2-upn@eroad.com",
                "unique_name" : "v1-unique-name@eroad.com",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.upn()).isEqualTo("v2-upn@eroad.com");
    }

    @Test
    void accessToken_audience_isPopulatedFromAudClaim_entraStyle() {
        String json = """
            {
                "sub" : "mySub",
                "aud" : "api://my-app-client-id",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.audience()).isEqualTo("api://my-app-client-id");
    }

    @Test
    void accessToken_audience_isNull_whenAudClaimAbsent_cognitoStyle() {
        // Cognito access tokens don't carry an "aud" claim at all.
        String json = """
            {
                "sub" : "mySub",
                "client_id" : "cognitoClientId",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.audience()).isNull();
    }

    @Test
    void accessToken_notBefore_isPopulatedFromNbfClaim() {
        String json = """
            {
                "sub" : "mySub",
                "nbf" : 1738903492,
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.notBefore()).isEqualTo(1738903492L);
    }

    @Test
    void accessToken_notBefore_isZero_whenNbfClaimAbsent() {
        String json = """
            {
                "sub" : "mySub",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.notBefore()).isZero();
    }

    @Test
    void accessToken_roles_isPopulatedFromRolesClaim_entraStyle() {
        String json = """
            {
                "sub" : "mySub",
                "roles" : ["Admin", "Reader"],
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.roles()).containsExactly("Admin", "Reader");
    }

    @Test
    void accessToken_roles_isPopulatedFromCognitoGroupsClaim_cognitoStyle() {
        String json = """
            {
                "sub" : "mySub",
                "cognito:groups" : ["admins", "readers"],
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.roles()).containsExactly("admins", "readers");
    }

    @Test
    void accessToken_roles_prefersEntraRolesWhenBothPresent() {
        String json = """
            {
                "sub" : "mySub",
                "roles" : ["Admin"],
                "cognito:groups" : ["admins"],
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.roles()).containsExactly("Admin");
    }

    @Test
    void accessToken_roles_isEmpty_whenNeitherClaimPresent() {
        String json = """
            {
                "sub" : "mySub",
            }
            """;

        AccessToken accessToken = jsonDataMapper.readAccessToken(json);

        assertThat(accessToken.roles()).isEmpty();
    }
}