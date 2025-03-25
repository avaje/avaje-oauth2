package io.avaje.oauth2.oidc.cognito;

/**
 * Provides the Cognito uris given a User Pool Id.
 */
public final class CognitoUris {

    private final String userPoolId;
    private final String region;
    private final String id;

    private CognitoUris(String userPoolId, String region, String id) {
        this.userPoolId = userPoolId;
        this.region = region;
        this.id = id;
    }

    /**
     * Return the CognitoUris for the given User Pool Id.
     */
    public static CognitoUris of(String userPoolId) {
        int pos = userPoolId.indexOf('_');
        String region = userPoolId.substring(0, pos);
        String id = userPoolId.substring(pos + 1);
        return new CognitoUris(userPoolId, region, id);
    }

    /**
     * Return the jwks uri for the given user pool id.
     */
    public static String toJwksUri(String userPoolId) {
        return of(userPoolId).jwksUri();
    }

    /**
     * Return the issuer uri for the given user pool id.
     */
    public static String toIssuer(String userPoolId) {
        return of(userPoolId).issuer();
    }

    /**
     * Return the jwks uri.
     */
    public String jwksUri() {
        return "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json".formatted(region, userPoolId);
    }

    /**
     * Return the issuer uri.
     */
    public String issuer() {
        return "https://cognito-idp.%s.amazonaws.com/%s".formatted(region, userPoolId);
    }

    /**
     * Return the domain uri.
     */
    public String domain() {
        return  "https://%s%s.auth.%s.amazoncognito.com".formatted(region, id, region);
    }

    /**
     * Return the login uri.
     */
    public String loginUri() {
        return  domain() + "/login";
    }

    /**
     * Return the oauth2 token uri.
     */
    public String tokenUri() {
        return  domain() + "/oauth2/token";
    }

}
