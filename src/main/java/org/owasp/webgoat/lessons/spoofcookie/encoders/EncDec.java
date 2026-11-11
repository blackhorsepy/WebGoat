/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
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
    return token;
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    if (encodedValue.length() > 64 || !encodedValue.matches("[A-Za-z0-9_-]{40,44}")) {
      throw new IllegalArgumentException("Invalid or expired cookie");
    }

    Session session = SESSIONS.get(encodedValue);
    if (session == null || !session.expiresAt().isAfter(Instant.now())) {
      SESSIONS.remove(encodedValue);
      throw new IllegalArgumentException("Invalid or expired cookie");
    }
    return session.username();
  }

  public static void invalidate(final String token) {
    if (token != null) {
      SESSIONS.remove(token);
    }
  }

  private static void cleanupExpiredSessions() {
    Instant now = Instant.now();
    SESSIONS.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
  }

  private record Session(String username, Instant expiresAt) {}
}
