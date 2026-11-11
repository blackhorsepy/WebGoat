/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_DEPARTMENTS = Set.of("Sales");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String department) {
    return updateTobiBarnettDepartment(department);
  }

  protected AttackResult updateTobiBarnettDepartment(String department) {
    if (department == null || !ALLOWED_DEPARTMENTS.contains(department)) {
      return failed(this).feedback("sql-injection.3.failed").build();
    }

    try (Connection connection = dataSource.getConnection();
        PreparedStatement update =
            connection.prepareStatement(
                "UPDATE employees SET department = ? WHERE first_name = ? AND last_name = ?")) {
      update.setString(1, department);
      update.setString(2, "Tobi");
      update.setString(3, "Barnett");
      int rowsUpdated = update.executeUpdate();
      if (rowsUpdated == 1) {
        return success(this).feedback("sql-injection.3.success").build();
      }
      return failed(this).feedback("sql-injection.3.failed").build();
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.3.failed").build();
    }
  }
}
