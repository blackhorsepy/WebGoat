/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint5a1"})
public class SqlInjectionLesson5a implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_LAST_NAMES = Set.of("Smith");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5a")
  @ResponseBody
  public AttackResult completed(@RequestParam String account) {
    return lookupAccount(account);
  }

  protected AttackResult lookupAccount(String lastName) {
    if (lastName == null || !ALLOWED_LAST_NAMES.contains(lastName)) {
      return failed(this).feedback("sql-injection.5a.no.results").build();
    }

    String query =
        "SELECT COUNT(*) FROM user_data WHERE first_name = 'John' AND last_name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(query)) {
      statement.setString(1, lastName);
      try (ResultSet results = statement.executeQuery()) {
        if (results.next()) {
          int matchingRecords = results.getInt(1);
          return success(this)
              .feedback("sql-injection.5a.success")
              .feedbackArgs(matchingRecords)
              .output("Matching non-sensitive records: " + matchingRecords)
              .build();
        }
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.5a.no.results").build();
    }
    return failed(this).feedback("sql-injection.5a.no.results").build();
  }

}
