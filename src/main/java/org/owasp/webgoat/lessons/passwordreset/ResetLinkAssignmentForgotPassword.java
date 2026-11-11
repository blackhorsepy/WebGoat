/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final String EMAIL_DOMAIN = "@webgoat.org";
  private static final String GENERIC_RESPONSE =
      "If the address matches your account, a password reset link will be sent.";

  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatURL) {
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatURL = webGoatURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam(required = false) String email, @CurrentUsername String username) {
    if (isOwnEmail(email, username)) {
      String resetLink = newResetToken();
      ResetLinkAssignment.registerResetLink(resetLink, username);
      try {
        sendMail(username, resetLink);
      } catch (Exception e) {
        ResetLinkAssignment.removeResetLink(resetLink);
      }
    }
    return informationMessage(this).output(GENERIC_RESPONSE).build();
  }

  private boolean isOwnEmail(String email, String username) {
    return email != null
        && username != null
        && !username.isBlank()
        && email.trim().equalsIgnoreCase(username + EMAIL_DOMAIN);
  }

  private String newResetToken() {
    byte[] token = new byte[32];
    SECURE_RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }

  private void sendMail(String username, String resetLink) {
    String contents = String.format(ResetLinkAssignment.TEMPLATE, webGoatURL, resetLink);
    PasswordResetEmail mailEvent =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(contents)
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    restTemplate.postForEntity(
        webWolfMailURL, new HttpEntity<>(mailEvent, headers), Object.class);
  }
}
