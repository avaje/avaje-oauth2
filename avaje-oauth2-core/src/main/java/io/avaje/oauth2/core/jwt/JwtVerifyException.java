package io.avaje.oauth2.core.jwt;

/**
 * Verification of JWT failed.
 */
public class JwtVerifyException extends RuntimeException {

    public JwtVerifyException(String message) {
        super(message);
    }

    public JwtVerifyException(String message, Exception cause) {
        super(message, cause);
    }
}
