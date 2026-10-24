// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_SQLITE_STORE_H
#define UA_HISTORY_SQLITE_STORE_H

#include "ua_history_store.h"
#include "ua_history_sqlite_connection.h"
#include "ua_history_sqlite_statement.h"

#include "ua_binary_data_value_codec.h"

#include <string>

namespace ua::history
{

/// @ingroup history
/// SQLite-backed `HistoryStore`  -  the real persistence layer for the reference Historical Access
/// implementation.
///
/// Raw values live in `history_values` keyed by (node_id, source_time); the full DataValue (value +
/// status + timestamps) is stored as a UA-Binary BLOB via the SDK codec. Modification records live
/// in `history_modifications`. Annotations are stored decomposed into their own fields rather than as
/// an encoded Variant, so no structure-resolving codec is required (this is a store-implementation
/// choice; the interface only requires that an annotation DataValue round-trips, see history_store.h).
/// All access is single-threaded (driven from the delegate's worker strand), so no internal
/// synchronisation is needed.
///
/// Per the `HistoryStore` failure contract, every method returns a `ua::Result` and never throws:
/// SQLite/codec errors raised internally as `ua::UaException` are caught at the interface boundary and
/// converted to an error Result carrying an `ErrorDetail`.
///
/// Range/bound queries map the engine's exclusive bounds to inclusive integer-tick bounds (+/-1 tick)
/// so a single prepared `BETWEEN` statement serves every inclusivity combination.
class SqliteHistoryStore final : public HistoryStore
{
public:
  /// Open (or create) the SQLite-backed store at `dbPath`, using `codec` to serialise and deserialise
  /// stored `DataValue`s. Throws `UaException` if the database cannot be opened or its schema created.
  /// @param dbPath filesystem path of the SQLite database to open or create.
  /// @param codec codec used to serialise and deserialise stored `DataValue`s.
  SqliteHistoryStore(const std::string& dbPath, ua::shared_ptr<const ua::UaBinaryDataValueCodec> codec);

  ua::Result<std::vector<ua::DataValue>> read_values(const ua::NodeId& node,
    std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
    bool upperInclusive, uint32_t limit, Direction order) override;

  ua::Result<std::optional<ua::DataValue>> read_nearest_value(
    const ua::NodeId& node, ua::DateTime reference, Direction direction, bool inclusive) override;

  ua::Result<std::optional<ua::DataValue>> read_value_at(
    const ua::NodeId& node, ua::DateTime timestamp) override;

  ua::VoidResult insert_value(const ua::NodeId& node, const ua::DataValue& value) override;
  ua::VoidResult delete_value_at(const ua::NodeId& node, ua::DateTime timestamp) override;
  ua::Result<std::size_t> delete_values(
    const ua::NodeId& node, ua::DateTime start, ua::DateTime end) override;

  ua::VoidResult insert_modification(
    const ua::NodeId& node, const ua::DataValue& value, const ua::ModificationInfo& info) override;
  ua::Result<std::vector<ModifiedValue>> read_modifications(const ua::NodeId& node,
    std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
    bool upperInclusive, uint32_t limit, Direction order) override;
  ua::Result<bool> has_modification_at(const ua::NodeId& node, ua::DateTime timestamp) override;

  ua::VoidResult insert_event(const ua::NodeId& node, const StoredEvent& event) override;
  ua::Result<std::vector<StoredEvent>> read_events(const ua::NodeId& node, std::optional<ua::DateTime> lower,
    bool lowerInclusive, std::optional<ua::DateTime> upper, bool upperInclusive, uint32_t limit,
    Direction order) override;
  ua::Result<std::optional<StoredEvent>> read_event(
    const ua::NodeId& node, const ua::ByteString& eventId) override;
  ua::Result<bool> delete_event(const ua::NodeId& node, const ua::ByteString& eventId) override;

  ua::VoidResult insert_annotation(const ua::NodeId& node, const ua::DataValue& annotation) override;
  ua::Result<std::optional<ua::DataValue>> read_annotation_at(
    const ua::NodeId& node, ua::DateTime timestamp) override;
  ua::VoidResult delete_annotation_at(const ua::NodeId& node, ua::DateTime timestamp) override;

private:
  static bool create_schema(SqliteConnection& connection);
  static std::string node_key(const ua::NodeId& node);
  static int64_t to_ticks(ua::DateTime dt);
  static ua::DateTime from_ticks(int64_t ticks);
  ua::DataValue decode(std::span<const uint8_t> blob) const;
  void load_event_fields(int64_t eventPk, std::map<std::string, ua::Variant>& out);

  SqliteConnection mConnection;
  // Creates the tables immediately after the connection opens. Declared (and therefore initialised)
  // before the prepared statements below, which would otherwise fail with "no such table".
  bool mSchemaInitialized;
  ua::shared_ptr<const ua::UaBinaryDataValueCodec> mCodec;

  SqliteStatement mFetchWindow;
  SqliteStatement mFetchWindowNewestFirst;
  SqliteStatement mNearestBefore;
  SqliteStatement mNearestAfter;
  SqliteStatement mValueAt;
  SqliteStatement mPutRaw;
  SqliteStatement mEraseAt;
  SqliteStatement mEraseRange;
  SqliteStatement mAddModification;
  SqliteStatement mQueryModifications;
  SqliteStatement mQueryModificationsNewestFirst;
  SqliteStatement mHasModificationAt;
  SqliteStatement mAddEvent;
  SqliteStatement mAddEventField;
  SqliteStatement mQueryEvents;
  SqliteStatement mQueryEventsNewestFirst;
  SqliteStatement mQueryEventFields;
  SqliteStatement mFindEvent;
  SqliteStatement mDeleteEventFields;
  SqliteStatement mDeleteEvent;
  SqliteStatement mPutAnnotation;
  SqliteStatement mAnnotationAt;
  SqliteStatement mEraseAnnotation;
};

}  // namespace ua::history

#endif  // !UA_HISTORY_SQLITE_STORE_H
