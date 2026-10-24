// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_STORE_H
#define UA_HISTORY_STORE_H

#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_modification_info.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_variant.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ua::history
{

/// @ingroup history
/// Direction of a nearest-value lookup relative to a reference timestamp.
enum class Direction
{
  Before,  ///< towards earlier timestamps
  After  ///< towards later timestamps
};

/// @ingroup history
/// A raw historical value together with the modification record that produced it.
/// Returned by `read_modifications` for ReadModified.
struct ModifiedValue
{
  ua::DataValue value;  ///< The historical value as stored.
  ua::ModificationInfo info;  ///< The modification record (update type, time, user) that produced it.
};

/// @ingroup history
/// A stored historical Event.
///
/// `fields` maps an **opaque field key** to that field's value. The key is a token the engine
/// assigns (see `HistoryEngine::field_key`); a store MUST persist and return keys byte-for-byte and
/// MUST NOT parse or interpret them. This lets a backend keep event fields in a generic key/value
/// table without understanding OPC UA browse paths, and lets the engine change the key format without
/// breaking any store.
///
/// `time` (the event's Time field) and `event_id` (its EventId field) are **derived views** the
/// store windows and identifies on: they are the canonical copy the store indexes by, and the engine
/// also keeps them inside `fields` so a read can project the Time/EventId select clauses. A store
/// reads `time`/`event_id` for ordering and lookup and round-trips `fields` opaquely.
struct StoredEvent
{
  ua::DateTime time;  ///< The event's Time field; the store windows and orders on this.
  ua::ByteString eventId;  ///< The event's EventId field; the store identifies the event by this.
  std::map<std::string, ua::Variant> fields;  ///< All event fields, keyed by the engine's opaque field key.
};

/// @ingroup history
/// Storage backend interface for the Historical Access reference implementation.
///
/// The Part-11 semantics (windowing, bounds, continuation, status fan-out, interpolation,
/// modification-record construction) live in `HistoryEngine`, which is storage-agnostic and drives
/// a `HistoryStore`. A customer plugs in their own backend (a historian, an RDBMS, a time-series DB)
/// by implementing this interface; `SqliteHistoryStore` is the bundled reference implementation, and
/// works against an in-memory SQLite database as well as a file.
///
/// **Failure contract.** Every method returns a `ua::Result<T>` / `ua::VoidResult` and **never
/// throws**: a storage failure is reported as an error Result carrying a StatusCode and an
/// `ErrorDetail`, which the engine forwards into the per-item history result. A *successful* read
/// that simply finds nothing is a *good* Result holding an empty `std::optional` / empty vector  -  it
/// is not an error. (This is why a lookup returns `Result<optional<...>>` rather than `optional<...>`.)
///
/// A store may answer a Good subcode (such as Good_LocalOverride) or an Uncertain code (such as
/// Uncertain_DataSubNormal) together with its data: `ua::Result<T>{data, code}`, or a `ua::VoidResult`
/// carrying the code for a write. The engine uses the data and passes the code on. The code goes on the
/// operation's result (the item's HistoryReadResult or HistoryUpdateResult status), combined by
/// `ua::detail::combined_status` with the codes of the other store answers the operation used (the worse
/// severity, else a code with a SubCode). An update or delete that answers one operationResults entry
/// per value, Event or timestamp puts the codes of the answers made for an entry on that entry instead,
/// in place of the engine's own Good_EntryInserted, Good_EntryReplaced or Good, which it gives only when
/// the store answered plain Good. An answer without data, Bad or Uncertain, is the operation's error
/// result as above; so is a Bad write, except in UpdateData, where a Bad write is that entry's
/// operationResult. The engine does not change the store on a read it is answered Uncertain: a read it
/// decides an update or a deletion on (whether an entry exists, the value a Replace records, the values a
/// delete removes) is refused when Uncertain, with or without data, before anything is written or deleted,
/// with `Bad_InternalError` (ErrorDetail `ReadAnswerUncertain`) whose cause is the store's code. The refusal
/// is that entry's operationResult, or the operation's error result for DeleteRaw.
///
/// All methods are invoked from the delegate's single worker strand, so implementations do not need
/// to be internally synchronised.
class HistoryStore
{
public:
  virtual ~HistoryStore() = default;

  // --- Raw value reads ---

  /// Raw values whose SourceTimestamp lies in the (lower, upper) interval with the given
  /// inclusivity, in @p order: `Direction::After` ascending by SourceTimestamp (ties broken by
  /// insertion order), `Direction::Before` the exact reverse, so `limit` takes the newest values. A
  /// null `lower`/`upper` means unbounded on that side. `limit == 0` means no limit.
  /// @param node The Variable node whose raw history is queried.
  /// @param lower Lower time bound, or `std::nullopt` for unbounded below.
  /// @param lowerInclusive Whether a value exactly at @p lower is included.
  /// @param upper Upper time bound, or `std::nullopt` for unbounded above.
  /// @param upperInclusive Whether a value exactly at @p upper is included.
  /// @param limit Maximum number of values to return; 0 means no limit.
  /// @param order `Direction::After` for oldest first, `Direction::Before` for newest first.
  /// @return The matching raw values in @p order, or an error Result on storage failure.
  virtual ua::Result<std::vector<ua::DataValue>> read_values(const ua::NodeId& node,
    std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
    bool upperInclusive, uint32_t limit, Direction order) = 0;

  /// The nearest raw value at/around `reference` in the given direction. When `inclusive` a value
  /// exactly at `reference` qualifies; otherwise the search is strict. A good Result holding
  /// `nullopt` means "no such value" (not an error).
  /// @param node The Variable node whose raw history is queried.
  /// @param reference Reference timestamp the search is relative to.
  /// @param direction Whether to search towards earlier (Before) or later (After) timestamps.
  /// @param inclusive Whether a value exactly at @p reference qualifies.
  /// @return The nearest matching value, a good empty optional if none exists, or an error Result on
  ///         storage failure.
  virtual ua::Result<std::optional<ua::DataValue>> read_nearest_value(
    const ua::NodeId& node, ua::DateTime reference, Direction direction, bool inclusive) = 0;

  /// The raw value whose SourceTimestamp exactly equals `timestamp`, if any (collision detection
  /// for Insert/Replace/Update and exact-match for AtTime / DeleteAtTime).
  /// @param node The Variable node whose raw history is queried.
  /// @param timestamp The exact SourceTimestamp to match.
  /// @return The value at @p timestamp, a good empty optional if none exists, or an error Result on
  ///         storage failure.
  virtual ua::Result<std::optional<ua::DataValue>> read_value_at(
    const ua::NodeId& node, ua::DateTime timestamp) = 0;

  // --- Raw value mutations ---

  /// Insert or overwrite the value at its SourceTimestamp. The caller (engine) has already decided,
  /// per Part-11 Insert/Replace/Update semantics, that the write is permitted.
  /// @param node The Variable node whose raw history is written.
  /// @param value The value to insert or overwrite, keyed by its SourceTimestamp.
  /// @return A good VoidResult on success, or an error carrying the storage failure.
  virtual ua::VoidResult insert_value(const ua::NodeId& node, const ua::DataValue& value) = 0;

  /// Remove the value whose SourceTimestamp exactly equals `timestamp`. No-op if none.
  /// @param node The Variable node whose raw history is modified.
  /// @param timestamp The exact SourceTimestamp of the value to remove.
  /// @return A good VoidResult on success, or an error carrying the storage failure.
  virtual ua::VoidResult delete_value_at(const ua::NodeId& node, ua::DateTime timestamp) = 0;

  /// Remove all values whose SourceTimestamp lies in the [start, end] closed interval. Returns the
  /// number of values removed.
  /// @param node The Variable node whose raw history is modified.
  /// @param start Inclusive start of the SourceTimestamp interval to delete.
  /// @param end Inclusive end of the SourceTimestamp interval to delete.
  /// @return The number of values removed, or an error Result on storage failure.
  virtual ua::Result<std::size_t> delete_values(
    const ua::NodeId& node, ua::DateTime start, ua::DateTime end) = 0;

  // --- Modification records (ReadModified + the Raw-read ExtraData bit) ---

  /// Record a modification (Insert/Replace/Update/Delete) of the value at its SourceTimestamp.
  /// @param node The Variable node whose modification history is written.
  /// @param value The value the modification applies to, keyed by its SourceTimestamp.
  /// @param info The modification record (update type, time, user) to store.
  /// @return A good VoidResult on success, or an error carrying the storage failure.
  virtual ua::VoidResult insert_modification(
    const ua::NodeId& node, const ua::DataValue& value, const ua::ModificationInfo& info) = 0;

  /// Modification records whose SourceTimestamp lies in (lower, upper) with the given inclusivity, in
  /// @p order: `Direction::After` ascending by SourceTimestamp (ties broken by modification order),
  /// `Direction::Before` the exact reverse. `limit == 0` = no limit.
  /// @param node The Variable node whose modification history is queried.
  /// @param lower Lower time bound, or `std::nullopt` for unbounded below.
  /// @param lowerInclusive Whether a record exactly at @p lower is included.
  /// @param upper Upper time bound, or `std::nullopt` for unbounded above.
  /// @param upperInclusive Whether a record exactly at @p upper is included.
  /// @param limit Maximum number of records to return; 0 means no limit.
  /// @param order `Direction::After` for oldest first, `Direction::Before` for newest first.
  /// @return The matching modification records in @p order, or an error Result on storage failure.
  virtual ua::Result<std::vector<ModifiedValue>> read_modifications(const ua::NodeId& node,
    std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
    bool upperInclusive, uint32_t limit, Direction order) = 0;

  /// Whether a modification record exists at exactly `timestamp` (drives the Raw-read ExtraData bit).
  /// @param node The Variable node whose modification history is queried.
  /// @param timestamp The exact SourceTimestamp to test.
  /// @return True if a modification record exists at @p timestamp, or an error Result on storage failure.
  virtual ua::Result<bool> has_modification_at(const ua::NodeId& node, ua::DateTime timestamp) = 0;

  // --- Historical Events ---

  /// Store a historical Event.
  /// @param node The notifier node the event is stored under.
  /// @param event The historical event to store.
  /// @return A good VoidResult on success, or an error carrying the storage failure.
  virtual ua::VoidResult insert_event(const ua::NodeId& node, const StoredEvent& event) = 0;

  /// Events whose Time lies in (lower, upper) with the given inclusivity, in @p order:
  /// `Direction::After` ascending by Time (ties broken by insertion order), `Direction::Before` the
  /// exact reverse. `limit == 0` = no limit.
  /// @param node The notifier node whose event history is queried.
  /// @param lower Lower time bound, or `std::nullopt` for unbounded below.
  /// @param lowerInclusive Whether an event exactly at @p lower is included.
  /// @param upper Upper time bound, or `std::nullopt` for unbounded above.
  /// @param upperInclusive Whether an event exactly at @p upper is included.
  /// @param limit Maximum number of events to return; 0 means no limit.
  /// @param order `Direction::After` for oldest first, `Direction::Before` for newest first.
  /// @return The matching events in @p order, or an error Result on storage failure.
  virtual ua::Result<std::vector<StoredEvent>> read_events(const ua::NodeId& node,
    std::optional<ua::DateTime> lower, bool lowerInclusive, std::optional<ua::DateTime> upper,
    bool upperInclusive, uint32_t limit, Direction order) = 0;

  /// The stored Event with the given EventId, if any (for Replace/Update).
  /// @param node The notifier node whose event history is queried.
  /// @param eventId The EventId identifying the stored event.
  /// @return The event with @p eventId, a good empty optional if none exists, or an error Result on
  ///         storage failure.
  virtual ua::Result<std::optional<StoredEvent>> read_event(
    const ua::NodeId& node, const ua::ByteString& eventId) = 0;

  /// Delete the Event with the given EventId. Returns true if an Event was removed.
  /// @param node The notifier node whose event history is modified.
  /// @param eventId The EventId identifying the event to delete.
  /// @return True if an event was removed, false if none matched, or an error Result on storage failure.
  virtual ua::Result<bool> delete_event(const ua::NodeId& node, const ua::ByteString& eventId) = 0;

  // --- Annotations ---
  //
  // An annotation is a DataValue whose Value is an `Annotation`, unique by the SourceTimestamp of the
  // data point it annotates. The persistence representation is the store's choice (the bundled SQLite
  // store, for instance, decomposes the Annotation into columns  -  see sqlite_history_store.h).

  /// Insert or overwrite the annotation at its SourceTimestamp.
  /// @param node The Variable node the annotation is stored under.
  /// @param annotation The annotation as a DataValue whose Value is an `Annotation`, keyed by its
  ///                   SourceTimestamp.
  /// @return A good VoidResult on success, or an error carrying the storage failure.
  virtual ua::VoidResult insert_annotation(const ua::NodeId& node, const ua::DataValue& annotation) = 0;

  /// The annotation at exactly `timestamp`, if any (as a DataValue whose Value is an `Annotation`).
  /// @param node The Variable node whose annotations are queried.
  /// @param timestamp The exact SourceTimestamp to match.
  /// @return The annotation at @p timestamp, a good empty optional if none exists, or an error Result
  ///         on storage failure.
  virtual ua::Result<std::optional<ua::DataValue>> read_annotation_at(
    const ua::NodeId& node, ua::DateTime timestamp) = 0;

  /// Remove the annotation at exactly `timestamp`. No-op if none.
  /// @param node The Variable node whose annotations are modified.
  /// @param timestamp The exact SourceTimestamp of the annotation to remove.
  /// @return A good VoidResult on success, or an error carrying the storage failure.
  virtual ua::VoidResult delete_annotation_at(const ua::NodeId& node, ua::DateTime timestamp) = 0;

protected:
  HistoryStore() = default;
  /// Defaulted memberwise copy construction.
  HistoryStore(const HistoryStore&) = default;
  /// Defaulted memberwise copy assignment.
  /// @return This object after assignment.
  HistoryStore& operator=(const HistoryStore&) = default;
  /// Defaulted memberwise move construction.
  HistoryStore(HistoryStore&&) = default;
  /// Defaulted memberwise move assignment.
  /// @return This object after assignment.
  HistoryStore& operator=(HistoryStore&&) = default;
};

}  // namespace ua::history

#endif  // !UA_HISTORY_STORE_H
