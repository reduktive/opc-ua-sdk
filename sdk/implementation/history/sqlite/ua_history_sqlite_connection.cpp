// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_sqlite_connection.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"

#include <sqlite3.h>

namespace ua::history
{

void SqliteConnection::Deleter::operator()(sqlite3* db) const noexcept
{
  sqlite3_close_v2(db);
}

SqliteConnection::SqliteConnection(const std::string& dbPath)
{
  sqlite3* raw = nullptr;
  int rc = sqlite3_open(dbPath.c_str(), &raw);
  mDb.reset(raw);  // Take ownership even on failure (sqlite3 docs require close on failed open).

  if (rc != SQLITE_OK)
  {
    const std::string message = raw ? sqlite3_errmsg(raw) : "unknown error";
    throw ua::UaException{ua::Status::BadInternalError,
      ua::ErrorDetail::build("SqliteOpenFailed", "Failed to open SQLite database", "SqliteConnection")
        .context(ua::ContextKeys::errorMessage, message)
        .context(ua::ContextKeys::filePath, dbPath)};
  }

  // Enable WAL mode for better concurrency.
  execute("PRAGMA journal_mode=WAL");
}

ua::VoidResult SqliteConnection::execute(const char* sql)
{
  char* errMsg = nullptr;
  int rc = sqlite3_exec(mDb.get(), sql, nullptr, nullptr, &errMsg);
  if (rc != SQLITE_OK)
  {
    std::string msg = errMsg ? errMsg : "unknown error";
    sqlite3_free(errMsg);
    return ua::VoidResult{ua::StatusCode{ua::Status::BadInternalError,
      ua::ErrorDetail::build("SqliteExecFailed", "SQLite statement execution failed", "SqliteConnection")
        .context(ua::ContextKeys::errorMessage, msg)}};
  }
  sqlite3_free(errMsg);
  return ua::VoidResult{};
}

}  // namespace ua::history
