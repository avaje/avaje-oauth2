package io.avaje.oauth2.oidc.entra;

/**
 * Provides the Microsoft identity platform (Entra ID) v2.0 uris given a Tenant Id.
 * <p>
 * Unlike Cognito, Entra does not have a separate Hosted-UI "domain" - the
 * authorize, token and jwks endpoints all live under
 * {@code https://login.microsoftonline.com/<tenantId>}. Note also that the v2.0
 * jwks uri is <em>not</em> {@code <issuer>/.well-known/jwks.json} (Cognito's
 * shape) but {@code https://login.microsoftonline.com/<tenantId>/discovery/v2.0/keys}.
 */
public final class EntraUris {

    private final String tenantId;

    private EntraUris(String tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Return the EntraUris for the given Tenant Id.
     */
    public static EntraUris of(String tenantId) {
        return new EntraUris(tenantId);
    }

    /**
     * Return the jwks uri for the given tenant id.
     */
    public static String toJwksUri(String tenantId) {
        return of(tenantId).jwksUri();
    }

    /**
     * Return the issuer uri for the given tenant id.
     */
    public static String toIssuer(String tenantId) {
        return of(tenantId).issuer();
    }

    /**
     * Return the base domain (login.microsoftonline.com/&lt;tenantId&gt;), used as
     * the base for the authorize/token endpoints.
     */
    public String domain() {
        return "https://login.microsoftonline.com/%s".formatted(tenantId);
    }

    /**
     * Return the v2.0 issuer uri, e.g.
     * {@code https://login.microsoftonline.com/<tenantId>/v2.0}.
     */
    public String issuer() {
        return domain() + "/v2.0";
    }

    /**
     * Return the v2.0 jwks uri, e.g.
     * {@code https://login.microsoftonline.com/<tenantId>/discovery/v2.0/keys}.
     */
    public String jwksUri() {
        return domain() + "/discovery/v2.0/keys";
    }

    /**
     * Return the v2.0 authorize (login) uri.
     */
    public String loginUri() {
        return domain() + "/oauth2/v2.0/authorize";
    }

    /**
     * Return the v2.0 oauth2 token uri.
     */
    public String tokenUri() {
        return domain() + "/oauth2/v2.0/token";
    }

    /**
     * Return the v2.0 device authorization uri.
     */
    public String deviceAuthorizationUri() {
        return domain() + "/oauth2/v2.0/devicecode";
    }
}
