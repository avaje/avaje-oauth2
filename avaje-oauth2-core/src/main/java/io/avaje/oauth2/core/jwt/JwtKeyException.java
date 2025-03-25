package io.avaje.oauth2.core.jwt;

/**
 * Exception when obtaining or building key used to verify a JWT.
 */
public class JwtKeyException extends JwtVerifyException {

    public JwtKeyException(String message) {
        super(message);
    }

    public JwtKeyException(String message, Exception e) {
        super(message, e);
    }
}
