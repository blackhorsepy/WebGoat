/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.ResultSet;
import java.sql.SQLException;
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
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String lastName) {
    return lookupDepartment(lastName);
  }

  protected AttackResult lookupDepartment(String lastName) {
    if (lastName == null || lastName.isBlank() || lastName.length() > 20) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }

    try (var connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement(
                "SELECT department FROM employees WHERE first_name = 'Bob' AND last_name = ?")) {
      statement.setString(1, lastName);
      try (ResultSet results = statement.executeQuery()) {
        if (results.next()) {
          String department = results.getString("department");
          String output = "Department: " + department;
          if ("Franco".equalsIgnoreCase(lastName)) {
            return success(this)
                .feedback("sql-injection.2.success")
                .output(output)
                .build();
          }
          return failed(this).feedback("sql-injection.2.failed").output(output).build();
        }
        return failed(this).feedback("sql-injection.2.failed").build();
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
  }
}
