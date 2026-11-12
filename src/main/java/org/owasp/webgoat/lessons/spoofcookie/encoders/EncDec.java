/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Issues opaque, short-lived cookie values that are looked up server-side. */
public class EncDec {

  private static final int TOKEN_BYTES = 32;
  private static final int MAX_SESSIONS = 10_000;
  private static final long SESSION_LIFETIME_SECONDS = 30 * 60;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final ConcurrentMap<String, Session> SESSIONS = new ConcurrentHashMap<>();

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    cleanupExpiredSessions();
    byte[] tokenBytes = new byte[TOKEN_BYTES];
    SECURE_RANDOM.nextBytes(tokenBytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    SESSIONS.put(
        token,
        new Session(value.toLowerCase(Locale.ROOT), Instant.now().plusSeconds(SESSION_LIFETIME_SECONDS)));

    while (SESSIONS.size() > MAX_SESSIONS) {
      String oldestToken = SESSIONS.keySet().stream().findFirst().orElse(null);
      if (oldestToken == null) {
        break;
      }
      SESSIONS.remove(oldestToken);
    }
    return wrap(token);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    String token = unwrapOrNull(encodedValue);
    if (token == null || !token.matches("[A-Za-z0-9_-]{40,44}")) {
      throw new IllegalArgumentException("Invalid or expired cookie");
    }

    Session session = SESSIONS.get(token);
    if (session == null || !session.expiresAt().isAfter(Instant.now())) {
      SESSIONS.remove(token);
      throw new IllegalArgumentException("Invalid or expired cookie");
    }
    return session.username();
  }

  public static void invalidate(final String encodedValue) {
    String token = encodedValue == null ? null : unwrapOrNull(encodedValue);
    if (token != null) {
      SESSIONS.remove(token);
    }
  }

  // The cookie keeps the lesson's familiar base64(hex(reversed(...))) presentation, but the wrapped
  // content is only a random server-side session handle: it carries no username and no secret, so
  // decoding it reveals nothing that could be used to build a cookie for another user.
  private static String wrap(String token) {
    String reversed = new StringBuilder(token).reverse().toString();
    String hex = HexFormat.of().formatHex(reversed.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hex.getBytes(StandardCharsets.UTF_8));
  }

  private static String unwrapOrNull(String encoded) {
    if (encoded.length() > 256) {
      return null;
    }
    try {
      String hex = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
      String reversed = new String(HexFormat.of().parseHex(hex), StandardCharsets.UTF_8);
      return new StringBuilder(reversed).reverse().toString();
    } catch (RuntimeException e) {
      return null;
    }
  }

  private static void cleanupExpiredSessions() {
    Instant now = Instant.now();
    SESSIONS.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
  }

  private record Session(String username, Instant expiresAt) {}
}
