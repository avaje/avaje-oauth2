package io.avaje.oauth2.core.jwt;

public class JwtVerifyException extends RuntimeException {
    public JwtVerifyException(String message) {
        super(message);
    }
}
