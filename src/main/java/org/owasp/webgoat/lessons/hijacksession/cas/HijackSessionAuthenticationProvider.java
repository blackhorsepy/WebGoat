/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.security.SecureRandom;
import java.util.function.DoublePredicate;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * @author Angel Olle Blazquez
 */

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final long SESSION_LIFETIME_SECONDS = 30 * 60;
  private final Map<String, Instant> sessions = new ConcurrentHashMap<>();
  private final ConcurrentLinkedQueue<String> sessionOrder = new ConcurrentLinkedQueue<>();
  protected static final int MAX_SESSIONS = 50;

  private static final DoublePredicate PROBABILITY_DOUBLE_PREDICATE = pr -> pr < 0.75;
  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
        byte[] id = new byte[32];
        SECURE_RANDOM.nextBytes(id);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(id);
      };
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())) {
      Instant expiresAt = sessions.get(authentication.getId());
      if (expiresAt != null && expiresAt.isAfter(Instant.now())) {
        authentication.setAuthenticated(true);
      } else if (expiresAt != null) {
        sessions.remove(authentication.getId(), expiresAt);
      }
      return authentication;
    }

    authentication.setId(GENERATE_SESSION_ID.get());
    authorizedUserAutoLogin(authentication);

    return authentication;
  }

  protected void authorizedUserAutoLogin(Authentication authentication) {
    if (!PROBABILITY_DOUBLE_PREDICATE.test(ThreadLocalRandom.current().nextDouble())) {
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected boolean addSession(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return false;
    }
    sessions.put(sessionId, Instant.now().plusSeconds(SESSION_LIFETIME_SECONDS));
    sessionOrder.add(sessionId);
    while (sessions.size() > MAX_SESSIONS) {
      String oldestSession = sessionOrder.poll();
      if (oldestSession == null) {
        break;
      }
      sessions.remove(oldestSession);
    }
    return true;
  }

  protected int getSessionsSize() {
    Instant now = Instant.now();
    sessions.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    return sessions.size();
  }
}
