/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.ByteArrayInputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;
import java.time.LocalDateTime;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "insecure-deserialization.hints.1",
  "insecure-deserialization.hints.2",
  "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask implements AssignmentEndpoint {

  private static final int MAX_TOKEN_LENGTH = 90_000;

  @PostMapping("/InsecureDeserialization/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String token) {
    if (token == null || token.length() > MAX_TOKEN_LENGTH) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    }
    String b64token;

    b64token = token.replace('-', '+').replace('_', '/');

    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
      ois.setObjectInputFilter(
          info -> {
            if (info.depth() > 5
                || info.references() > 16
                || info.streamBytes() > 64 * 1024
                || info.arrayLength() > 64) {
              return ObjectInputFilter.Status.REJECTED;
            }
            Class<?> serialClass = info.serialClass();
            if (serialClass == null) {
              return ObjectInputFilter.Status.UNDECIDED;
            }
            String className = serialClass.getName();
            if (serialClass == VulnerableTaskHolder.class
                || serialClass == String.class
                || serialClass == LocalDateTime.class
                || "java.time.Ser".equals(className)) {
              return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
          });
      Object o = ois.readObject();
      if (!(o instanceof VulnerableTaskHolder)) {
        if (o instanceof String) {
          return failed(this).feedback("insecure-deserialization.stringobject").build();
        }
        return failed(this).feedback("insecure-deserialization.wrongobject").build();
      }
      VulnerableTaskHolder task = (VulnerableTaskHolder) o;
      if (!task.isExpectedSafeDemo()) {
        return failed(this).feedback("insecure-deserialization.actionnotallowed").build();
      }
      return success(this).feedback("insecure-deserialization.safeaccepted").build();
    } catch (InvalidClassException e) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    } catch (IllegalArgumentException e) {
      return failed(this).feedback("insecure-deserialization.expired").build();
    } catch (Exception e) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    }

  }
}
