// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_SQLITE_CONNECTION_H
#define UA_HISTORY_SQLITE_CONNECTION_H

#include "ua_result.h"

#include <memory>
#include <string>

struct sqlite3;

namespace ua::history
{

/// @ingroup history
/// RAII wrapper around a sqlite3* connection handle.
/// Opens or creates a SQLite database at the given path.
class SqliteConnection
{
public:
  /// Open (or create) the SQLite database at `dbPath`. Throws `UaException` if it cannot be opened.
  /// @param dbPath filesystem path of the SQLite database to open or create.
  explicit SqliteConnection(const std::string& dbPath);

  SqliteConnection(const SqliteConnection&) = delete;
  SqliteConnection& operator=(const SqliteConnection&) = delete;
  /// Move-constructible; ownership of the underlying `sqlite3*` handle transfers.
  SqliteConnection(SqliteConnection&&) noexcept = default;
  /// Move-assignable; ownership of the underlying `sqlite3*` handle transfers.
  /// @return reference to this connection.
  SqliteConnection& operator=(SqliteConnection&&) noexcept = default;
  ~SqliteConnection() = default;

  /// Execute a SQL statement that returns no results (CREATE TABLE, etc.).
  /// @param sql the SQL statement to run (expected to produce no result rows).
  /// @return a VoidResult that carries an error if the statement fails.
  ua::VoidResult execute(const char* sql);

  /// Access the raw handle for statement preparation.
  /// @return the underlying `sqlite3*` connection handle.
  sqlite3* handle() noexcept
  {
    return mDb.get();
  }

private:
  struct Deleter
  {
    void operator()(sqlite3* db) const noexcept;
  };

  std::unique_ptr<sqlite3, Deleter> mDb;
};

}  // namespace ua::history

#endif  // !UA_HISTORY_SQLITE_CONNECTION_H
