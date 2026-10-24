// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_SQLITE_STATEMENT_H
#define UA_HISTORY_SQLITE_STATEMENT_H

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

struct sqlite3_stmt;

namespace ua::history
{

class SqliteConnection;

/// @ingroup history
/// RAII wrapper around a sqlite3_stmt* prepared statement.
class SqliteStatement
{
public:
  /// Prepare `sql` against `connection`. Throws `UaException` if the statement cannot be prepared.
  /// @param connection the open connection the statement is prepared against.
  /// @param sql the SQL text to compile into a prepared statement.
  SqliteStatement(SqliteConnection& connection, const char* sql);

  SqliteStatement(const SqliteStatement&) = delete;
  SqliteStatement& operator=(const SqliteStatement&) = delete;
  /// Move-constructible; ownership of the prepared `sqlite3_stmt*` transfers.
  SqliteStatement(SqliteStatement&&) noexcept = default;
  /// Move-assignable; ownership of the prepared `sqlite3_stmt*` transfers.
  /// @return reference to this statement.
  SqliteStatement& operator=(SqliteStatement&&) noexcept = default;
  ~SqliteStatement() = default;

  // Bind parameters (1-indexed per SQLite convention).
  /// Bind a text value to parameter `index`.
  /// @param index the 1-based parameter position to bind.
  /// @param value the text value to bind.
  void bind_text(int index, std::string_view value);
  /// Bind a 64-bit integer to parameter `index`.
  /// @param index the 1-based parameter position to bind.
  /// @param value the 64-bit integer value to bind.
  void bind_int64(int index, int64_t value);
  /// Bind a floating-point value to parameter `index`.
  /// @param index the 1-based parameter position to bind.
  /// @param value the floating-point value to bind.
  void bind_double(int index, double value);
  /// Bind a binary blob to parameter `index`.
  /// @param index the 1-based parameter position to bind.
  /// @param data the binary blob to bind.
  void bind_blob(int index, std::span<const uint8_t> data);
  /// Bind SQL NULL to parameter `index`.
  /// @param index the 1-based parameter position to set to SQL NULL.
  void bind_null(int index);

  /// Returns true if a row is available (SQLITE_ROW), false on SQLITE_DONE.
  /// Throws UaException on error.
  /// @return true if a row is available (SQLITE_ROW), false on SQLITE_DONE.
  bool step();

  /// Reset the statement and clear bindings for reuse.
  void reset();

  // Column accessors (0-indexed per SQLite convention).
  /// Read column `index` of the current row as a 64-bit integer.
  /// @param index the 0-based column position to read.
  /// @return the column value as a 64-bit integer.
  int64_t column_int64(int index) const;
  /// Read column `index` of the current row as a floating-point value.
  /// @param index the 0-based column position to read.
  /// @return the column value as a floating-point number.
  double column_double(int index) const;
  /// Read column `index` of the current row as text (valid until the next step/reset).
  /// @param index the 0-based column position to read.
  /// @return the column text, valid until the next step/reset.
  std::string_view column_text(int index) const;
  /// Read column `index` of the current row as a binary blob (valid until the next step/reset).
  /// @param index the 0-based column position to read.
  /// @return the column blob, valid until the next step/reset.
  std::span<const uint8_t> column_blob(int index) const;
  /// Byte length of column `index` in the current row.
  /// @param index the 0-based column position to measure.
  /// @return the byte length of the column value.
  int column_bytes(int index) const;
  /// Whether column `index` of the current row is SQL NULL.
  /// @param index the 0-based column position to test.
  /// @return true if the column value is SQL NULL.
  bool column_is_null(int index) const;

private:
  struct Deleter
  {
    void operator()(sqlite3_stmt* s) const noexcept;
  };

  std::unique_ptr<sqlite3_stmt, Deleter> mStmt;
};

/// @ingroup history
/// Ensures a SqliteStatement is reset on scope exit.
class StatementResetGuard
{
public:
  /// Capture `stmt`, resetting it on scope exit.
  /// @param stmt the statement to reset when this guard goes out of scope.
  explicit StatementResetGuard(SqliteStatement& stmt) : mStmt(stmt)
  {}

  ~StatementResetGuard()
  {
    mStmt.reset();
  }

  StatementResetGuard(const StatementResetGuard&) = delete;
  StatementResetGuard& operator=(const StatementResetGuard&) = delete;
  StatementResetGuard(StatementResetGuard&&) = delete;
  StatementResetGuard& operator=(StatementResetGuard&&) = delete;

private:
  SqliteStatement& mStmt;
};

}  // namespace ua::history

#endif  // !UA_HISTORY_SQLITE_STATEMENT_H
