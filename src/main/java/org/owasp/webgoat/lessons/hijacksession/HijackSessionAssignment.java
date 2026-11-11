/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.hijacksession.cas.Authentication;
import org.owasp.webgoat.lessons.hijacksession.cas.HijackSessionAuthenticationProvider;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

@RestController
@AssignmentHints({
  "hijacksession.hints.1",
  "hijacksession.hints.2",
  "hijacksession.hints.3",
  "hijacksession.hints.4",
  "hijacksession.hints.5"
})
public class HijackSessionAssignment implements AssignmentEndpoint {
  private static final String COOKIE_NAME = "hijack_cookie";

  private final HijackSessionAuthenticationProvider provider;

  public HijackSessionAssignment(HijackSessionAuthenticationProvider provider) {
    this.provider = provider;
  }

  @PostMapping(path = "/HijackSession/login")
  @ResponseBody
  public AttackResult login(
      @CurrentUsername String currentUsername,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {

    if (StringUtils.isBlank(currentUsername)) {
      return failed(this).build();
    }

    Authentication authentication = null;
    if (StringUtils.isNotEmpty(cookieValue)) {
      authentication =
          provider.authenticate(
              Authentication.builder().name(currentUsername).id(cookieValue).build());
    }

    // Reuse a valid session owned by this WebGoat account. Invalid, expired, or another
    // account's cookie receives a fresh random session for the signed-in account.
    if (authentication == null || !authentication.isAuthenticated()) {
      authentication = provider.createAuthenticatedSession(currentUsername);
    }
    if (authentication == null) {
      return failed(this).build();
    }

    setCookie(response, authentication.getId());
    if (authentication.isAuthenticated()) {
      return success(this).build();
    }

    return failed(this).build();
  }

  private void setCookie(HttpServletResponse response, String cookieValue) {
    Cookie cookie = new Cookie(COOKIE_NAME, cookieValue);
    cookie.setPath("/WebGoat");
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
    cookie.setMaxAge(30 * 60);
    response.addCookie(cookie);
  }
}
