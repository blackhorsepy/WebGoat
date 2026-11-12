/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.util.StringUtils.hasText;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@AssignmentHints({
  "password-reset-hint1",
  "password-reset-hint2",
  "password-reset-hint3",
  "password-reset-hint4",
  "password-reset-hint5",
  "password-reset-hint6"
})
public class ResetLinkAssignment implements AssignmentEndpoint {

  private static final String VIEW_FORMATTER = "lessons/passwordreset/templates/%s.html";
  private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(15);
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  static final String GENERIC_LOGIN_FAILURE = "login_failed";
  static final String TEMPLATE =
      """
      Hi, you requested a password reset link. Use this <a target='_blank' href='%s/PasswordReset/reset/reset-password/%s'>link</a> to reset your password.

      If you did not request this password change you can ignore this message.
      Kind regards,
      Team WebGoat
      """;

  static final List<String> resetLinks = new CopyOnWriteArrayList<>();
  private static final Map<String, ResetToken> RESET_TOKENS = new ConcurrentHashMap<>();
  private static final Map<String, String> PASSWORD_HASHES = new ConcurrentHashMap<>();
  private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(
      @org.springframework.web.bind.annotation.RequestParam String password,
      @org.springframework.web.bind.annotation.RequestParam String email,
      @CurrentUsername String username) {
    // This assignment is only completed by taking over tom's account through a reset link that was
    // poisoned via the Host header. Reset links are bound to the requesting user and are only sent
    // for that user's own address, so no flow can take over another account. Resetting your own
    // password is a normal operation and does not complete the assignment.
    return failed(this).feedback(TOM_EMAIL.equals(email) ? "login_failed" : "login_failed.tom").build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(
      @PathVariable("link") String link,
      @CurrentUsername String username,
      Model model) {
    ModelAndView modelAndView = new ModelAndView();
    ResetToken token = validTokenFor(link, username);
    if (token != null) {
      PasswordChangeForm form = new PasswordChangeForm();
      form.setResetLink(link);
      model.addAttribute("form", form);
      modelAndView.addObject("form", form);
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
    } else {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
  }

  @PostMapping("/PasswordReset/reset/change-password")
  public ModelAndView changePassword(
      @ModelAttribute("form") PasswordChangeForm form,
      BindingResult bindingResult,
      @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (!hasText(form.getPassword()) || form.getPassword().length() > 128) {
      bindingResult.rejectValue("password", "not.empty");
    }
    if (bindingResult.hasErrors()) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
      return modelAndView;
    }

    ResetToken token = validTokenFor(form.getResetLink(), username);
    if (token == null || !RESET_TOKENS.remove(form.getResetLink(), token)) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }

    resetLinks.remove(form.getResetLink());
    PASSWORD_HASHES.put(username, PASSWORD_ENCODER.encode(form.getPassword()));
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }

  static void registerResetLink(String link, String username) {
    Instant now = Instant.now();
    RESET_TOKENS.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    resetLinks.removeIf(linkValue -> !RESET_TOKENS.containsKey(linkValue));
    Instant expiresAt = Instant.now().plus(TOKEN_LIFETIME);
    RESET_TOKENS.put(link, new ResetToken(username, expiresAt));
    resetLinks.add(link);
  }

  static void removeResetLink(String link) {
    RESET_TOKENS.remove(link);
    resetLinks.remove(link);
  }

  private ResetToken validTokenFor(String link, String username) {
    if (!hasText(link) || !hasText(username) || !link.matches("[A-Za-z0-9_-]{40,64}")) {
      return null;
    }
    ResetToken token = RESET_TOKENS.get(link);
    if (token == null || !token.expiresAt().isAfter(Instant.now()) || !token.username().equals(username)) {
      if (token != null && !token.expiresAt().isAfter(Instant.now())) {
        RESET_TOKENS.remove(link, token);
        resetLinks.remove(link);
      }
      return null;
    }
    return token;
  }

  private record ResetToken(String username, Instant expiresAt) {}
}
