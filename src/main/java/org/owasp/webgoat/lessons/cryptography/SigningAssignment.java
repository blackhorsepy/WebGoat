/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  @RequestMapping(
      path = {"/crypto/signing/getprivate", "/crypto/signing/getpublic"},
      produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPublicKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null) {
      keyPair = CryptoUtil.generateKeyPair();
      request.getSession().setAttribute("keyPair", keyPair);
    }
    // The legacy /getprivate route is retained for the existing lesson client,
    // but it deliberately returns only the public key.
    return CryptoUtil.getPublicKeyInPEM(keyPair);
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus) {
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null || modulus == null) {
      return failed(this).feedback("crypto-signing.notok").build();
    }

    String submittedModulus = modulus.trim().toUpperCase(Locale.ROOT);
    if (!submittedModulus.matches("(?:00)?[0-9A-F]{512}")) {
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    if (submittedModulus.length() == 512) {
      submittedModulus = "00".concat(submittedModulus);
    }

    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    if (!DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray())
        .equals(submittedModulus)) {
      log.warn("public key modulus did not match the session key");
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    return success(this).feedback("crypto-signing.success").build();
  }
}
