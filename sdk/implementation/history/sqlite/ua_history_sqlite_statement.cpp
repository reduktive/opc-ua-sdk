// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_sqlite_statement.h"
#include "ua_history_sqlite_connection.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"

#include <sqlite3.h>

namespace ua::history
{

void SqliteStatement::Deleter::operator()(sqlite3_stmt* s) const noexcept
{
  sqlite3_finalize(s);
}

SqliteStatement::SqliteStatement(SqliteConnection& connection, const char* sql)
{
  sqlite3_stmt* raw = nullptr;
  int rc = sqlite3_prepare_v2(connection.handle(), sql, -1, &raw, nullptr);
  mStmt.reset(raw);

  if (rc != SQLITE_OK)
  {
    const std::string message = sqlite3_errmsg(connection.handle());
    throw ua::UaException{ua::Status::BadInternalError,
      ua::ErrorDetail::build("SqlitePrepareFailed", "Failed to prepare SQLite statement", "SqliteStatement")
        .context(ua::ContextKeys::errorMessage, message)};
  }
}

void SqliteStatement::bind_text(int index, std::string_view value)
{
  sqlite3_bind_text(mStmt.get(), index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

void SqliteStatement::bind_int64(int index, int64_t value)
{
  sqlite3_bind_int64(mStmt.get(), index, value);
}

void SqliteStatement::bind_double(int index, double value)
{
  sqlite3_bind_double(mStmt.get(), index, value);
}

void SqliteStatement::bind_blob(int index, std::span<const uint8_t> data)
{
  sqlite3_bind_blob(mStmt.get(), index, data.data(), static_cast<int>(data.size()), SQLITE_TRANSIENT);
}

void SqliteStatement::bind_null(int index)
{
  sqlite3_bind_null(mStmt.get(), index);
}

bool SqliteStatement::step()
{
  int rc = sqlite3_step(mStmt.get());
  if (rc == SQLITE_ROW)
    return true;
  if (rc == SQLITE_DONE)
    return false;

  const std::string message = sqlite3_errmsg(sqlite3_db_handle(mStmt.get()));
  throw ua::UaException{ua::Status::BadInternalError,
    ua::ErrorDetail::build("SqliteStepFailed", "SQLite statement step failed", "SqliteStatement")
      .context(ua::ContextKeys::errorMessage, message)};
}

void SqliteStatement::reset()
{
  sqlite3_reset(mStmt.get());
  sqlite3_clear_bindings(mStmt.get());
}

int64_t SqliteStatement::column_int64(int index) const
{
  return sqlite3_column_int64(mStmt.get(), index);
}

double SqliteStatement::column_double(int index) const
{
  return sqlite3_column_double(mStmt.get(), index);
}

std::string_view SqliteStatement::column_text(int index) const
{
  auto* text = reinterpret_cast<const char*>(sqlite3_column_text(mStmt.get(), index));
  if (!text)
    return {};
  return {text, static_cast<size_t>(sqlite3_column_bytes(mStmt.get(), index))};
}

std::span<const uint8_t> SqliteStatement::column_blob(int index) const
{
  auto* data = static_cast<const uint8_t*>(sqlite3_column_blob(mStmt.get(), index));
  if (!data)
    return {};
  return {data, static_cast<size_t>(sqlite3_column_bytes(mStmt.get(), index))};
}

int SqliteStatement::column_bytes(int index) const
{
  return sqlite3_column_bytes(mStmt.get(), index);
}

bool SqliteStatement::column_is_null(int index) const
{
  return sqlite3_column_type(mStmt.get(), index) == SQLITE_NULL;
}

}  // namespace ua::history
