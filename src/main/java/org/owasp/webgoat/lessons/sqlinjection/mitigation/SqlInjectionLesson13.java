/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-mitigation-13-1",
      "SqlStringInjectionHint-mitigation-13-2",
      "SqlStringInjectionHint-mitigation-13-3",
      "SqlStringInjectionHint-mitigation-13-4"
    })
@Slf4j
public class SqlInjectionLesson13 implements AssignmentEndpoint {

  private static final Pattern IPV4_ADDRESS_PATTERN =
      Pattern.compile("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson13(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionMitigations/attack12a")
  @ResponseBody
  public AttackResult completed(@RequestParam("ip") String ip) {
    if (!isValidIpv4Address(ip)) {
      return failed(this).build();
    }

    try (Connection connection = dataSource.getConnection();
        PreparedStatement preparedStatement =
            connection.prepareStatement("select ip from servers where ip = ? and hostname = ?")) {
      preparedStatement.setString(1, ip);
      preparedStatement.setString(2, "webgoat-prd");
      ResultSet resultSet = preparedStatement.executeQuery();
      if (resultSet.next()) {
        return success(this).build();
      }
      return failed(this).build();
    } catch (SQLException e) {
      log.error("Failed", e);
      return failed(this).build();
    }
  }

  private boolean isValidIpv4Address(String address) {
    if (address == null
        || address.length() > 15
        || !IPV4_ADDRESS_PATTERN.matcher(address).matches()) {
      return false;
    }

    for (String octet : address.split("\\.")) {
      if (Integer.parseInt(octet) > 255) {
        return false;
      }
    }
    return true;
  }
}
