package io.avaje.oauth2.core.pkce;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PKCE (Proof Key for Code Exchange, RFC 7636) parameters for the OAuth2
 * Authorization Code flow with a public client (no client secret).
 *
 * <p>Generate a fresh {@code Pkce} per login, send {@link #challenge()} (with
 * {@link #challengeMethod()}) on the authorization request, then send
 * {@link #verifier()} on the token exchange.
 *
 * <pre>{@code
 *
 *   Pkce pkce = Pkce.generate();
 *
 *   String loginUrl = cognitoOidc.loginUrl(nonce, state, pkce.challenge());
 *   // ... user authenticates, authorization code returned ...
 *   OidcTokens tokens = cognitoOidc.obtainTokens(code, pkce.verifier());
 *
 * }</pre>
 */
public final class Pkce {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

  private final String verifier;
  private final String challenge;

  private Pkce(String verifier, String challenge) {
    this.verifier = verifier;
    this.challenge = challenge;
  }

  /**
   * Generate a new {@code Pkce} with a cryptographically random verifier and its
   * derived S256 challenge.
   */
  public static Pkce generate() {
    byte[] randomBytes = new byte[32];
    RANDOM.nextBytes(randomBytes);
    String verifier = URL_ENCODER.encodeToString(randomBytes);
    return new Pkce(verifier, deriveChallenge(verifier));
  }

  /**
   * Create a {@code Pkce} from a known verifier, deriving the S256 challenge.
   */
  public static Pkce of(String verifier) {
    return new Pkce(verifier, deriveChallenge(verifier));
  }

  private static String deriveChallenge(String verifier) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return URL_ENCODER.encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }

  /** The code verifier, sent on the token exchange. */
  public String verifier() {
    return verifier;
  }

  /** The code challenge, sent on the authorization request. */
  public String challenge() {
    return challenge;
  }

  /** The code challenge method, always {@code S256}. */
  public String challengeMethod() {
    return "S256";
  }
}
