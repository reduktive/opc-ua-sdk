// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_sqlite_store.h"

#include "ua_annotation.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <sqlite3.h>

#include <limits>

namespace ua::history
{

namespace
{

constexpr auto createSql = R"(
CREATE TABLE IF NOT EXISTS history_values (
  node_id     TEXT    NOT NULL,
  source_time INTEGER NOT NULL,
  value_data  BLOB    NOT NULL,
  PRIMARY KEY (node_id, source_time)
);
CREATE TABLE IF NOT EXISTS history_modifications (
  node_id     TEXT    NOT NULL,
  source_time INTEGER NOT NULL,
  update_type INTEGER NOT NULL,
  user_name   TEXT,
  mod_time    INTEGER,
  value_data  BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_modifications ON history_modifications (node_id, source_time);
CREATE TABLE IF NOT EXISTS history_events (
  event_pk   INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id    TEXT    NOT NULL,
  event_time INTEGER NOT NULL,
  event_id   BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events ON history_events (node_id, event_time);
CREATE TABLE IF NOT EXISTS history_event_fields (
  event_pk   INTEGER NOT NULL,
  field_key  TEXT    NOT NULL,
  value_blob BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_fields ON history_event_fields (event_pk);
CREATE TABLE IF NOT EXISTS history_annotations (
  node_id         TEXT    NOT NULL,
  source_time     INTEGER NOT NULL,
  message         TEXT,
  user_name       TEXT,
  annotation_time INTEGER,
  PRIMARY KEY (node_id, source_time)
);
)";

constexpr auto fetchWindowSql =
  "SELECT value_data FROM history_values WHERE node_id = ? AND source_time BETWEEN ? AND ? "
  "ORDER BY source_time ASC LIMIT ?";
constexpr auto fetchWindowNewestFirstSql =
  "SELECT value_data FROM history_values WHERE node_id = ? AND source_time BETWEEN ? AND ? "
  "ORDER BY source_time DESC LIMIT ?";
constexpr auto nearestBeforeSql =
  "SELECT value_data FROM history_values WHERE node_id = ? AND source_time <= ? "
  "ORDER BY source_time DESC LIMIT 1";
constexpr auto nearestAfterSql =
  "SELECT value_data FROM history_values WHERE node_id = ? AND source_time >= ? "
  "ORDER BY source_time ASC LIMIT 1";
constexpr auto valueAtSql =
  "SELECT value_data FROM history_values WHERE node_id = ? AND source_time = ? LIMIT 1";
constexpr auto putRawSql =
  "INSERT OR REPLACE INTO history_values (node_id, source_time, value_data) VALUES (?, ?, ?)";
constexpr auto eraseAtSql = "DELETE FROM history_values WHERE node_id = ? AND source_time = ?";
constexpr auto eraseRangeSql = "DELETE FROM history_values WHERE node_id = ? AND source_time BETWEEN ? AND ?";
constexpr auto addModificationSql =
  "INSERT INTO history_modifications (node_id, source_time, update_type, user_name, mod_time, value_data) "
  "VALUES (?, ?, ?, ?, ?, ?)";
constexpr auto queryModificationsSql =
  "SELECT source_time, update_type, user_name, mod_time, value_data FROM history_modifications "
  "WHERE node_id = ? AND source_time BETWEEN ? AND ? ORDER BY source_time ASC, rowid ASC LIMIT ?";
constexpr auto queryModificationsNewestFirstSql =
  "SELECT source_time, update_type, user_name, mod_time, value_data FROM history_modifications "
  "WHERE node_id = ? AND source_time BETWEEN ? AND ? ORDER BY source_time DESC, rowid DESC LIMIT ?";
constexpr auto hasModificationAtSql =
  "SELECT 1 FROM history_modifications WHERE node_id = ? AND source_time = ? LIMIT 1";
constexpr auto addEventSql = "INSERT INTO history_events (node_id, event_time, event_id) VALUES (?, ?, ?)";
constexpr auto addEventFieldSql =
  "INSERT INTO history_event_fields (event_pk, field_key, value_blob) VALUES (?, ?, ?)";
constexpr auto queryEventsSql =
  "SELECT event_pk, event_time, event_id FROM history_events WHERE node_id = ? AND event_time BETWEEN ? "
  "AND ? ORDER BY event_time ASC, event_pk ASC LIMIT ?";
constexpr auto queryEventsNewestFirstSql =
  "SELECT event_pk, event_time, event_id FROM history_events WHERE node_id = ? AND event_time BETWEEN ? "
  "AND ? ORDER BY event_time DESC, event_pk DESC LIMIT ?";
constexpr auto queryEventFieldsSql =
  "SELECT field_key, value_blob FROM history_event_fields WHERE event_pk = ?";
constexpr auto findEventSql =
  "SELECT event_pk, event_time, event_id FROM history_events WHERE node_id = ? AND event_id = ? LIMIT 1";
constexpr auto deleteEventFieldsSql =
  "DELETE FROM history_event_fields WHERE event_pk IN "
  "(SELECT event_pk FROM history_events WHERE node_id = ? AND event_id = ?)";
constexpr auto deleteEventSql = "DELETE FROM history_events WHERE node_id = ? AND event_id = ?";
constexpr auto putAnnotationSql =
  "INSERT OR REPLACE INTO history_annotations (node_id, source_time, message, user_name, annotation_time) "
  "VALUES (?, ?, ?, ?, ?)";
constexpr auto annotationAtSql =
  "SELECT message, user_name, annotation_time FROM history_annotations WHERE node_id = ? AND source_time "
  "= ? LIMIT 1";
constexpr auto eraseAnnotationSql = "DELETE FROM history_annotations WHERE node_id = ? AND source_time = ?";

// Map an exclusive lower bound to the equivalent inclusive integer-tick bound (one tick up), and an
// absent bound to the integer extreme, so a single BETWEEN query serves every inclusivity case.
int64_t lower_tick(std::optional<ua::DateTime> lower, bool inclusive)
{
  if (!lower)
    return std::numeric_limits<int64_t>::min();
  const int64_t ticks = lower->value().time_since_epoch().count();
  return inclusive ? ticks : ticks + 1;
}

int64_t upper_tick(std::optional<ua::DateTime> upper, bool inclusive)
{
  if (!upper)
    return std::numeric_limits<int64_t>::max();
  const int64_t ticks = upper->value().time_since_epoch().count();
  return inclusive ? ticks : ticks - 1;
}

int64_t limit_param(uint32_t limit)
{
  return limit == 0 ? -1 : static_cast<int64_t>(limit);  // SQLite LIMIT -1 == unlimited
}

}  // namespace

SqliteHistoryStore::SqliteHistoryStore(
  const std::string& dbPath, ua::shared_ptr<const ua::UaBinaryDataValueCodec> codec)
  : mConnection(dbPath), mSchemaInitialized(create_schema(mConnection)), mCodec(std::move(codec)),
    mFetchWindow(mConnection, fetchWindowSql),
    mFetchWindowNewestFirst(mConnection, fetchWindowNewestFirstSql),
    mNearestBefore(mConnection, nearestBeforeSql), mNearestAfter(mConnection, nearestAfterSql),
    mValueAt(mConnection, valueAtSql), mPutRaw(mConnection, putRawSql), mEraseAt(mConnection, eraseAtSql),
    mEraseRange(mConnection, eraseRangeSql), mAddModification(mConnection, addModificationSql),
    mQueryModifications(mConnection, queryModificationsSql),
    mQueryModificationsNewestFirst(mConnection, queryModificationsNewestFirstSql),
    mHasModificationAt(mConnection, hasModificationAtSql), mAddEvent(mConnection, addEventSql),
    mAddEventField(mConnection, addEventFieldSql), mQueryEvents(mConnection, queryEventsSql),
    mQueryEventsNewestFirst(mConnection, queryEventsNewestFirstSql),
    mQueryEventFields(mConnection, queryEventFieldsSql), mFindEvent(mConnection, findEventSql),
    mDeleteEventFields(mConnection, deleteEventFieldsSql), mDeleteEvent(mConnection, deleteEventSql),
    mPutAnnotation(mConnection, putAnnotationSql), mAnnotationAt(mConnection, annotationAtSql),
    mEraseAnnotation(mConnection, eraseAnnotationSql)
{}

bool SqliteHistoryStore::create_schema(SqliteConnection& connection)
{
  connection.execute(createSql).value();
  return true;
}

std::string SqliteHistoryStore::node_key(const ua::NodeId& node)
{
  return ua::to_string(node);
}

int64_t SqliteHistoryStore::to_ticks(ua::DateTime dt)
{
  return dt.value().time_since_epoch().count();
}

ua::DateTime SqliteHistoryStore::from_ticks(int64_t ticks)
{
  using namespace std::chrono;
  return ua::DateTime{
    sys_time<ua::datetime::OneHundredNanoSeconds>{ua::datetime::OneHundredNanoSeconds{ticks}}};
}

ua::DataValue SqliteHistoryStore::decode(std::span<const uint8_t> blob) const
{
  auto result =
    mCodec->decode(std::span<const ua::byte>(reinterpret_cast<const ua::byte*>(blob.data()), blob.size()));
  return result.is_good() ? std::move(result).value() : ua::DataValue{};
}

// Every public method body runs inside ua::detail::to_result, the single boundary that converts any
// internally-thrown ua::UaException (SQLite/codec failure) into an error Result carrying an ErrorDetail
//  -  the HistoryStore failure contract (history_store.h): these methods never throw.

ua::Result<std::vector<ua::DataValue>> SqliteHistoryStore::read_values(const ua::NodeId& node,
  std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
  bool upperInclusive, uint32_t limit, Direction order)
{
  return ua::detail::to_result(
    [&]
    {
      std::vector<ua::DataValue> out;
      const auto key = node_key(node);
      SqliteStatement& stmt = order == Direction::Before ? mFetchWindowNewestFirst : mFetchWindow;
      StatementResetGuard guard(stmt);
      stmt.bind_text(1, key);
      stmt.bind_int64(2, lower_tick(lower, lowerInclusive));
      stmt.bind_int64(3, upper_tick(upper, upperInclusive));
      stmt.bind_int64(4, limit_param(limit));
      while (stmt.step())
        out.push_back(decode(stmt.column_blob(0)));
      return out;
    });
}

ua::Result<std::optional<ua::DataValue>> SqliteHistoryStore::read_nearest_value(
  const ua::NodeId& node, ua::DateTime reference, Direction direction, bool inclusive)
{
  return ua::detail::to_result(
    [&]() -> std::optional<ua::DataValue>
    {
      const auto key = node_key(node);
      const int64_t ref = to_ticks(reference);
      SqliteStatement& stmt = direction == Direction::Before ? mNearestBefore : mNearestAfter;
      const int64_t bound =
        direction == Direction::Before ? (inclusive ? ref : ref - 1) : (inclusive ? ref : ref + 1);
      StatementResetGuard guard(stmt);
      stmt.bind_text(1, key);
      stmt.bind_int64(2, bound);
      if (stmt.step())
        return decode(stmt.column_blob(0));
      return std::nullopt;
    });
}

ua::Result<std::optional<ua::DataValue>> SqliteHistoryStore::read_value_at(
  const ua::NodeId& node, ua::DateTime timestamp)
{
  return ua::detail::to_result(
    [&]() -> std::optional<ua::DataValue>
    {
      const auto key = node_key(node);
      StatementResetGuard guard(mValueAt);
      mValueAt.bind_text(1, key);
      mValueAt.bind_int64(2, to_ticks(timestamp));
      if (mValueAt.step())
        return decode(mValueAt.column_blob(0));
      return std::nullopt;
    });
}

ua::VoidResult SqliteHistoryStore::insert_value(const ua::NodeId& node, const ua::DataValue& value)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      auto blob = mCodec->encode(value);
      StatementResetGuard guard(mPutRaw);
      mPutRaw.bind_text(1, key);
      mPutRaw.bind_int64(2, to_ticks(value.source_timestamp().value_or(ua::DateTime{})));
      mPutRaw.bind_blob(
        3, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(blob.data()), blob.size()));
      mPutRaw.step();
    });
}

ua::VoidResult SqliteHistoryStore::delete_value_at(const ua::NodeId& node, ua::DateTime timestamp)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      StatementResetGuard guard(mEraseAt);
      mEraseAt.bind_text(1, key);
      mEraseAt.bind_int64(2, to_ticks(timestamp));
      mEraseAt.step();
    });
}

ua::Result<std::size_t> SqliteHistoryStore::delete_values(
  const ua::NodeId& node, ua::DateTime start, ua::DateTime end)
{
  return ua::detail::to_result(
    [&]() -> std::size_t
    {
      const auto key = node_key(node);
      StatementResetGuard guard(mEraseRange);
      mEraseRange.bind_text(1, key);
      mEraseRange.bind_int64(2, to_ticks(start));
      mEraseRange.bind_int64(3, to_ticks(end));
      mEraseRange.step();
      const int changes = sqlite3_changes(mConnection.handle());
      return changes < 0 ? 0 : static_cast<std::size_t>(changes);
    });
}

ua::VoidResult SqliteHistoryStore::insert_modification(
  const ua::NodeId& node, const ua::DataValue& value, const ua::ModificationInfo& info)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      auto blob = mCodec->encode(value);
      StatementResetGuard guard(mAddModification);
      mAddModification.bind_text(1, key);
      mAddModification.bind_int64(2, to_ticks(value.source_timestamp().value_or(ua::DateTime{})));
      mAddModification.bind_int64(3, static_cast<int64_t>(info.update_type()));
      if (info.user_name().empty())
        mAddModification.bind_null(4);
      else
        mAddModification.bind_text(4, std::string_view{info.user_name()});
      if (info.modification_time().is_null())
        mAddModification.bind_null(5);
      else
        mAddModification.bind_int64(5, to_ticks(info.modification_time()));
      mAddModification.bind_blob(
        6, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(blob.data()), blob.size()));
      mAddModification.step();
    });
}

ua::Result<std::vector<ModifiedValue>> SqliteHistoryStore::read_modifications(const ua::NodeId& node,
  std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
  bool upperInclusive, uint32_t limit, Direction order)
{
  return ua::detail::to_result(
    [&]
    {
      std::vector<ModifiedValue> out;
      const auto key = node_key(node);
      SqliteStatement& stmt =
        order == Direction::Before ? mQueryModificationsNewestFirst : mQueryModifications;
      StatementResetGuard guard(stmt);
      stmt.bind_text(1, key);
      stmt.bind_int64(2, lower_tick(lower, lowerInclusive));
      stmt.bind_int64(3, upper_tick(upper, upperInclusive));
      stmt.bind_int64(4, limit_param(limit));
      while (stmt.step())
      {
        ua::ModificationInfo info;
        info.update_type() = static_cast<ua::HistoryUpdateType>(stmt.column_int64(1));
        if (!stmt.column_is_null(2))
          info.user_name() = ua::String{stmt.column_text(2)};
        if (!stmt.column_is_null(3))
          info.modification_time() = from_ticks(stmt.column_int64(3));
        out.push_back(ModifiedValue{decode(stmt.column_blob(4)), std::move(info)});
      }
      return out;
    });
}

ua::Result<bool> SqliteHistoryStore::has_modification_at(const ua::NodeId& node, ua::DateTime timestamp)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      StatementResetGuard guard(mHasModificationAt);
      mHasModificationAt.bind_text(1, key);
      mHasModificationAt.bind_int64(2, to_ticks(timestamp));
      return mHasModificationAt.step();
    });
}

void SqliteHistoryStore::load_event_fields(int64_t eventPk, std::map<std::string, ua::Variant>& out)
{
  StatementResetGuard guard(mQueryEventFields);
  mQueryEventFields.bind_int64(1, eventPk);
  while (mQueryEventFields.step())
  {
    std::string fieldKey{mQueryEventFields.column_text(0)};
    auto value = decode(mQueryEventFields.column_blob(1));
    out.emplace(std::move(fieldKey), value.value());
  }
}

ua::VoidResult SqliteHistoryStore::insert_event(const ua::NodeId& node, const StoredEvent& event)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      {
        StatementResetGuard guard(mAddEvent);
        mAddEvent.bind_text(1, key);
        mAddEvent.bind_int64(2, to_ticks(event.time));
        mAddEvent.bind_blob(3, std::span<const uint8_t>(event.eventId.data(), event.eventId.size()));
        mAddEvent.step();
      }
      const int64_t eventPk = sqlite3_last_insert_rowid(mConnection.handle());
      for (const auto& [fieldKey, value] : event.fields)
      {
        auto blob = mCodec->encode(ua::DataValue{value});
        StatementResetGuard guard(mAddEventField);
        mAddEventField.bind_int64(1, eventPk);
        mAddEventField.bind_text(2, fieldKey);
        mAddEventField.bind_blob(
          3, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(blob.data()), blob.size()));
        mAddEventField.step();
      }
    });
}

ua::Result<std::vector<StoredEvent>> SqliteHistoryStore::read_events(const ua::NodeId& node,
  std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
  bool upperInclusive, uint32_t limit, Direction order)
{
  return ua::detail::to_result(
    [&]
    {
      // First collect the event headers (the outer cursor must finish before per-event field queries
      // run on the same connection), then load each event's fields.
      struct Header
      {
        int64_t pk;
        ua::DateTime time;
        ua::ByteString eventId;
      };

      std::vector<Header> headers;
      {
        const auto key = node_key(node);
        SqliteStatement& stmt = order == Direction::Before ? mQueryEventsNewestFirst : mQueryEvents;
        StatementResetGuard guard(stmt);
        stmt.bind_text(1, key);
        stmt.bind_int64(2, lower_tick(lower, lowerInclusive));
        stmt.bind_int64(3, upper_tick(upper, upperInclusive));
        stmt.bind_int64(4, limit_param(limit));
        while (stmt.step())
        {
          Header header;
          header.pk = stmt.column_int64(0);
          header.time = from_ticks(stmt.column_int64(1));
          header.eventId = ua::ByteString{stmt.column_blob(2)};
          headers.push_back(std::move(header));
        }
      }

      std::vector<StoredEvent> out;
      out.reserve(headers.size());
      for (auto& header : headers)
      {
        StoredEvent event;
        event.time = header.time;
        event.eventId = std::move(header.eventId);
        load_event_fields(header.pk, event.fields);
        out.push_back(std::move(event));
      }
      return out;
    });
}

ua::Result<std::optional<StoredEvent>> SqliteHistoryStore::read_event(
  const ua::NodeId& node, const ua::ByteString& eventId)
{
  return ua::detail::to_result(
    [&]() -> std::optional<StoredEvent>
    {
      int64_t eventPk = 0;
      StoredEvent event;
      {
        const auto key = node_key(node);
        StatementResetGuard guard(mFindEvent);
        mFindEvent.bind_text(1, key);
        mFindEvent.bind_blob(2, std::span<const uint8_t>(eventId.data(), eventId.size()));
        if (!mFindEvent.step())
          return std::nullopt;
        eventPk = mFindEvent.column_int64(0);
        event.time = from_ticks(mFindEvent.column_int64(1));
        event.eventId = ua::ByteString{mFindEvent.column_blob(2)};
      }
      load_event_fields(eventPk, event.fields);
      return event;
    });
}

ua::Result<bool> SqliteHistoryStore::delete_event(const ua::NodeId& node, const ua::ByteString& eventId)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      const auto idSpan = std::span<const uint8_t>(eventId.data(), eventId.size());
      {
        StatementResetGuard guard(mDeleteEventFields);
        mDeleteEventFields.bind_text(1, key);
        mDeleteEventFields.bind_blob(2, idSpan);
        mDeleteEventFields.step();
      }
      StatementResetGuard guard(mDeleteEvent);
      mDeleteEvent.bind_text(1, key);
      mDeleteEvent.bind_blob(2, idSpan);
      mDeleteEvent.step();
      return sqlite3_changes(mConnection.handle()) > 0;
    });
}

ua::VoidResult SqliteHistoryStore::insert_annotation(const ua::NodeId& node, const ua::DataValue& annotation)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      const ua::Annotation* payload = annotation.value().try_as<ua::Annotation>();
      StatementResetGuard guard(mPutAnnotation);
      mPutAnnotation.bind_text(1, key);
      mPutAnnotation.bind_int64(2, to_ticks(annotation.source_timestamp().value_or(ua::DateTime{})));
      if (payload && !payload->message().empty())
        mPutAnnotation.bind_text(3, std::string_view{payload->message()});
      else
        mPutAnnotation.bind_null(3);
      if (payload && !payload->user_name().empty())
        mPutAnnotation.bind_text(4, std::string_view{payload->user_name()});
      else
        mPutAnnotation.bind_null(4);
      if (payload && !payload->annotation_time().is_null())
        mPutAnnotation.bind_int64(5, to_ticks(payload->annotation_time()));
      else
        mPutAnnotation.bind_null(5);
      mPutAnnotation.step();
    });
}

ua::Result<std::optional<ua::DataValue>> SqliteHistoryStore::read_annotation_at(
  const ua::NodeId& node, ua::DateTime timestamp)
{
  return ua::detail::to_result(
    [&]() -> std::optional<ua::DataValue>
    {
      const auto key = node_key(node);
      StatementResetGuard guard(mAnnotationAt);
      mAnnotationAt.bind_text(1, key);
      mAnnotationAt.bind_int64(2, to_ticks(timestamp));
      if (!mAnnotationAt.step())
        return std::nullopt;

      ua::Annotation payload;
      if (!mAnnotationAt.column_is_null(0))
        payload.message() = ua::String{mAnnotationAt.column_text(0)};
      if (!mAnnotationAt.column_is_null(1))
        payload.user_name() = ua::String{mAnnotationAt.column_text(1)};
      if (!mAnnotationAt.column_is_null(2))
        payload.annotation_time() = from_ticks(mAnnotationAt.column_int64(2));

      ua::DataValue result{ua::Variant{std::move(payload)}};
      result.source_timestamp() = timestamp;
      return result;
    });
}

ua::VoidResult SqliteHistoryStore::delete_annotation_at(const ua::NodeId& node, ua::DateTime timestamp)
{
  return ua::detail::to_result(
    [&]
    {
      const auto key = node_key(node);
      StatementResetGuard guard(mEraseAnnotation);
      mEraseAnnotation.bind_text(1, key);
      mEraseAnnotation.bind_int64(2, to_ticks(timestamp));
      mEraseAnnotation.step();
    });
}

}  // namespace ua::history
