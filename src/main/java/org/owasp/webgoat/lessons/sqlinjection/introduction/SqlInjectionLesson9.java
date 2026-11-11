/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
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
@AssignmentHints(
    value = {
      "SqlStringInjectionHint.9.1",
      "SqlStringInjectionHint.9.2",
      "SqlStringInjectionHint.9.3",
      "SqlStringInjectionHint.9.4",
      "SqlStringInjectionHint.9.5"
    })
public class SqlInjectionLesson9 implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_LAST_NAMES = Set.of("Smith");
  private static final Set<String> ALLOWED_ACTIONS = Set.of("request-review");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson9(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack9")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String name,
      @RequestParam String auth_tan,
      @RequestParam String salary_action) {
    return simulateSalaryReview(name, auth_tan, salary_action);
  }

  protected AttackResult simulateSalaryReview(String name, String authTan, String salaryAction) {
    if (name == null
        || !ALLOWED_LAST_NAMES.contains(name)
        || authTan == null
        || authTan.length() != 6
        || !ALLOWED_ACTIONS.contains(salaryAction)) {
      return failed(this).feedback("sql-injection.9.one").build();
    }

    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                "SELECT 1 FROM employees WHERE first_name = 'John'"
                    + " AND last_name = ? AND auth_tan = ?")) {
      statement.setString(1, name);
      statement.setString(2, authTan);
      try (ResultSet results = statement.executeQuery()) {
        if (results.next()) {
          SqlInjectionLesson8.log(connection, "Salary review simulation");
          return success(this)
              .feedback("sql-injection.9.success")
              .output("Salary change request simulated. No employee salary was changed.")
              .build();
        }
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.9.one").build();
    }
    return failed(this).feedback("sql-injection.9.one").build();
  }
}
