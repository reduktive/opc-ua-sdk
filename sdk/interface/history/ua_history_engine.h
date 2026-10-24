// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_ENGINE_H
#define UA_HISTORY_ENGINE_H

#include "ua_history_store.h"
#include "ua_namespace_history_delegate.h"

namespace ua::history
{

/// @ingroup history
/// Implementation detail of the continuation cursors of @ref HistoryEngine.
/// The part of a read's time window not yet returned, in the store's terms, and the order it is
/// walked in. A page is read from the store with a limit of one page, so a read holds at most one page
/// in memory whatever the size of the archive. Rows can share a time (modification records, events): when
/// a page ends part-way through the rows at one time, the walk resumes at that time inclusively and
/// `returnedAtNearEdge` counts the rows at it already returned, which are skipped. Otherwise the walk
/// resumes after the last time returned and the count is zero.
///
/// Each page reads the archive as it is then (OPC 10000-11 6.3 permits resuming from the last returned
/// timestamp): entries inserted into or deleted from the part of the window not yet returned are seen.
/// Known limitation: rows sharing a time are skipped by count, so deleting one of the tied rows already
/// returned between two pages skips one row not yet returned.
struct HistoryWindowWalk
{
  std::optional<ua::DateTime> lower;
  bool lowerInclusive{true};
  std::optional<ua::DateTime> upper;
  bool upperInclusive{false};
  Direction order{Direction::After};
  uint32_t returnedAtNearEdge{0};
};

/// @ingroup history
/// Storage-agnostic Historical Access semantics (OPC 10000-11 section 6.4 / section 6.8).
///
/// The engine implements the normative read/update behaviour  -  half-open windowing, returnBounds
/// with Bad_BoundNotFound placeholders, forward/reverse direction, the numValuesPerNode cap with
/// continuation points, single-instant reads, ReadModified, Insert/Replace/Update status fan-out,
/// Delete, modification-record creation  -  over an abstract `HistoryStore`. It performs no I/O and
/// owns no threads, so it is unit-tested directly against an in-memory store. The
/// `NamespaceHistoryDelegate` (see `history_delegate.h`) wraps the engine with a strand + worker
/// thread and a `HistoryStore` instance.
///
/// All methods are pure functions of (store, item): they are invoked one item at a time from the
/// delegate's worker, after the SDK service layer has already performed request-level validation.
///
/// **The store's codes.** A store may answer a Good subcode or an Uncertain code together with its data
/// (see the `HistoryStore` failure contract). The engine passes that code on and never answers plain
/// Good, or a Good code of its own, in its place: a read's code, and the code of a delete that answers no
/// entries, goes on the operation's result, combined by `ua::detail::combined_status` with the codes of
/// the other store answers the operation used, and on every page resumed from its continuation cursor; an
/// update or delete that answers one operationResults entry per value, Event or timestamp puts the codes
/// the store answered for an entry on that entry. The engine's own Good_EntryInserted,
/// Good_EntryReplaced or Good is an entry's answer only when the store answered plain Good for it. A read
/// the engine decides an update or a deletion on is acted on only when Good or a Good subcode: an Uncertain
/// one, with or without data, is refused before the store is changed, with `Bad_InternalError`
/// (`ReadAnswerUncertain`) whose cause is the store's code.
class HistoryEngine
{
public:
  /// Request item for a ReadRaw / ReadModified operation (re-exported from the delegate interface so callers
  /// can spell these types as `HistoryEngine::ReadRawItem`).
  using ReadRawItem = ua::NamespaceHistoryDelegate::ReadRawItem;
  /// Per-node result of a ReadRaw / ReadModified operation.
  using ReadRawItemResult = ua::NamespaceHistoryDelegate::ReadRawItemResult;
  /// Continuation cursor carried between paginated raw reads.
  using Cursor = ua::NamespaceHistoryDelegate::Cursor;

  /// Request item for a ReadAtTime operation.
  using ReadAtTimeItem = ua::NamespaceHistoryDelegate::ReadAtTimeItem;
  /// Per-node result of a ReadAtTime operation.
  using ReadAtTimeItemResult = ua::NamespaceHistoryDelegate::ReadAtTimeItemResult;
  /// Request item for a ReadEvents operation.
  using ReadEventsItem = ua::NamespaceHistoryDelegate::ReadEventsItem;
  /// Per-node result of a ReadEvents operation.
  using ReadEventsItemResult = ua::NamespaceHistoryDelegate::ReadEventsItemResult;
  /// Request item for a ReadAnnotationData operation.
  using ReadAnnotationItem = ua::NamespaceHistoryDelegate::ReadAnnotationItem;
  /// Per-node result of a ReadAnnotationData operation.
  using ReadAnnotationItemResult = ua::NamespaceHistoryDelegate::ReadAnnotationItemResult;
  /// Request item for an UpdateData (Insert / Replace / Update) operation.
  using UpdateDataItem = ua::NamespaceHistoryDelegate::UpdateDataItem;
  /// Per-node result of an UpdateData operation.
  using UpdateDataItemResult = ua::NamespaceHistoryDelegate::UpdateDataItemResult;
  /// Request item for an UpdateEvents operation.
  using UpdateEventsItem = ua::NamespaceHistoryDelegate::UpdateEventsItem;
  /// Per-node result of an UpdateEvents operation.
  using UpdateEventsItemResult = ua::NamespaceHistoryDelegate::UpdateEventsItemResult;
  /// Request item for an UpdateStructureData (Annotation) operation.
  using UpdateStructureDataItem = ua::NamespaceHistoryDelegate::UpdateStructureDataItem;
  /// Per-node result of an UpdateStructureData operation.
  using UpdateStructureDataItemResult = ua::NamespaceHistoryDelegate::UpdateStructureDataItemResult;
  /// Request item for a DeleteRaw operation.
  using DeleteRawItem = ua::NamespaceHistoryDelegate::DeleteRawItem;
  /// Request item for a DeleteAtTime operation.
  using DeleteAtTimeItem = ua::NamespaceHistoryDelegate::DeleteAtTimeItem;
  /// Request item for a DeleteEvents operation.
  using DeleteEventsItem = ua::NamespaceHistoryDelegate::DeleteEventsItem;
  /// Per-node result shared by the delete operations.
  using DeleteItemResult = ua::NamespaceHistoryDelegate::DeleteItemResult;

  /// Read raw or modified values for one operation (OPC 10000-11 section 6.4.3). Handles continuation,
  /// IndexRange-on-scalar, the modified+bounds error, half-open windowing, bounds and the
  /// numValuesPerNode cap / continuation-point emission. `Good_NoData` for an empty unbounded range
  /// is applied by the SDK service, not here. When the store answered a Good subcode or an Uncertain
  /// code with its data, the result carries that code, on the first page and on every page resumed from
  /// the continuation cursor; it is plain Good only when the store answered plain Good. Each page is read
  /// from the store with a limit of one page, so a read never holds more of the window than one page; a
  /// continuation cursor presented with a Node other than its own is Bad_ContinuationPointInvalid.
  /// @param store the history store queried for raw / modified values.
  /// @param item the ReadRaw / ReadModified operation; carries the request window and flags, and its
  ///        continuation cursor is updated in place when a page boundary is hit.
  /// @return the per-node result: the values (or modification infos) and a continuation point when
  ///         the numValuesPerNode cap is reached, with the store's code; an error result when a store
  ///         answer held no data.
  static ReadRawItemResult read_raw(HistoryStore& store, ReadRawItem& item);

  /// Read values at specific timestamps (OPC 10000-11 section 6.4.5). One DataValue per requested
  /// timestamp, in request order: an exact raw value when present, otherwise a value derived from
  /// the surrounding raw values  -  interpolated (sloped, for numeric data) between the bounding
  /// values, or held from the value at/before the timestamp when `use_simple_bounds` is set or only
  /// one side is available. Bad_NoData when the timestamp precedes all data. When the store answered a
  /// Good subcode or an Uncertain code with its data, the result carries that code.
  /// @param store the history store queried for exact and surrounding raw values.
  /// @param item the ReadAtTime operation; carries the requested timestamps and the
  ///        `use_simple_bounds` flag.
  /// @return the per-node result: one DataValue per requested timestamp, in request order, with the
  ///         store's code.
  static ReadAtTimeItemResult read_at_time(HistoryStore& store, const ReadAtTimeItem& item);

  /// Read historical Events for one operation (OPC 10000-11 section 6.4.2). Windows events by Time
  /// (forward [start,end) / reverse), applies the numValuesPerNode cap with a continuation point,
  /// and projects each event onto the filter's select clauses (one Variant per clause, in order;
  /// a field declared by the EventType model but unavailable in the stored event becomes
  /// Bad_NoData, while a field not declared by the model remains null). The field key for a select
  /// clause is the join of its browse-path names (e.g. "Time", "Severity"). When the store answered a
  /// Good subcode or an Uncertain code with its events, the result carries that code, on the first page
  /// and on every page resumed from the continuation cursor. Each page is read from the store with a
  /// limit of one page; a continuation cursor presented with a Node other than its own is
  /// Bad_ContinuationPointInvalid.
  /// @param store the history store queried for stored events.
  /// @param item the ReadEvents operation; carries the time window, the event filter select clauses,
  ///        and its continuation cursor is updated in place when a page boundary is hit.
  /// @return the per-node result: the projected event field lists, with a continuation point when
  ///         the numValuesPerNode cap is reached, with the store's code.
  static ReadEventsItemResult read_events(HistoryStore& store, ReadEventsItem& item);

  /// The storage field key for a select clause: its browse-path names joined with '/'.
  /// @param operand the select clause whose browse-path names form the key.
  /// @return the storage field key: the operand's browse-path names joined with '/'.
  static std::string field_key(const ua::SimpleAttributeOperand& operand);

  /// Insert / Replace / Update one operation's values (OPC 10000-11 section 6.8.2). Per-value status
  /// fan-out: Insert  to  Good_EntryInserted / Bad_EntryExists; Replace  to  Good_EntryReplaced /
  /// Bad_NoEntryExists; Update  to  Good_EntryInserted or Good_EntryReplaced (upsert). A null
  /// SourceTimestamp yields Bad_InvalidArgument. Good_EntryInserted and Good_EntryReplaced are a value's
  /// answer only when the store answered plain Good for it: a Good subcode or an Uncertain code the store
  /// answered for the value is its answer instead, and a write the store refuses is answered with the
  /// store's Bad code. A value whose existence read, or whose read of the value a Replace records, the
  /// store answered Uncertain is answered `Bad_InternalError` (`ReadAnswerUncertain`, the store's code as
  /// cause) and nothing is written for it. Replace/Update/Delete of existing data create a modification
  /// record (Insert of new data does not, per section 6.4.3.3). `userName` is recorded in each modification
  /// record's ModificationInfo (empty when no user identity is available).
  /// @param store the history store the values are written to.
  /// @param item the UpdateData operation; carries the Insert / Replace / Update mode and the values.
  /// @param userName identity recorded in each generated modification record's ModificationInfo;
  ///        empty when no user identity is available.
  /// @return the per-value operation results; an error result when a store read held no data.
  static UpdateDataItemResult update_data(
    HistoryStore& store, const UpdateDataItem& item, std::string_view userName = {});

  /// Delete raw values in the [startTime, endTime] interval (OPC 10000-11 section 6.8.5). Deleted values
  /// become Delete modification records (stamped with `userName`). Deleting an empty range is not an
  /// error. The result is plain Good when the store answered plain Good, and otherwise carries the
  /// store's Good subcode or Uncertain code. A read of the values to delete that the store answers
  /// Uncertain fails the operation with `Bad_InternalError` (`ReadAnswerUncertain`, the store's code as
  /// cause) before anything is deleted.
  /// @param store the history store the values are deleted from.
  /// @param item the DeleteRaw operation; carries the [startTime, endTime] interval to delete.
  /// @param userName identity stamped on the generated Delete modification records.
  /// @return the operation result: Good or the store's code; an error result when a store answer held
  ///         no data, a read of the values to delete was answered Uncertain, or a write was refused.
  static DeleteItemResult delete_raw(
    HistoryStore& store, const DeleteRawItem& item, std::string_view userName = {});

  /// Delete raw values at specific timestamps (OPC 10000-11 section 6.8.5). Per-timestamp status:
  /// Good when a value existed and was deleted, Bad_NoEntryExists otherwise. Deletions are recorded
  /// as modification records stamped with `userName`. Good is a timestamp's answer only when the store
  /// answered plain Good for it; a Good subcode or an Uncertain code it answered is the answer instead. A
  /// timestamp whose read the store answers Uncertain is answered `Bad_InternalError`
  /// (`ReadAnswerUncertain`, the store's code as cause) and nothing is deleted for it.
  /// @param store the history store the values are deleted from.
  /// @param item the DeleteAtTime operation; carries the specific timestamps to delete.
  /// @param userName identity stamped on the generated Delete modification records.
  /// @return the per-timestamp operation results (Good or the store's code when a value was deleted,
  ///         else Bad_NoEntryExists).
  static DeleteItemResult delete_at_time(
    HistoryStore& store, const DeleteAtTimeItem& item, std::string_view userName = {});

  /// Insert / Replace / Update historical events (OPC 10000-11 section 6.8.4). Per-event status: Insert of
  /// an EventId that already exists  to  Bad_EntryExists; Replace of a missing EventId  to Bad_NoEntryExists;
  /// Update upserts. A supplied EventId is honoured; otherwise the server generates one. Each event's
  /// fields are taken from the item's filter select clauses (Time drives ordering, EventId identifies).
  /// The engine's Good, Good_EntryInserted or Good_EntryReplaced is an event's answer only when the store
  /// answered plain Good for it; a Good subcode or an Uncertain code it answered is the answer instead. An
  /// event whose existence read the store answers Uncertain is answered `Bad_InternalError`
  /// (`ReadAnswerUncertain`, the store's code as cause) and nothing is written or deleted for it.
  /// @param store the history store the events are written to.
  /// @param item the UpdateEvents operation; carries the Insert / Replace / Update mode, the event
  ///        filter, and the event field values.
  /// @return the per-event operation results.
  static UpdateEventsItemResult update_events(HistoryStore& store, const UpdateEventsItem& item);

  /// Delete historical events by EventId (OPC 10000-11 section 6.8.5). Per-EventId status: Good when an
  /// event was deleted, Bad_NoEntryExists otherwise. Good is an EventId's answer only when the store
  /// answered plain Good for it; a Good subcode or an Uncertain code it answered is the answer instead.
  /// @param store the history store the events are deleted from.
  /// @param item the DeleteEvents operation; carries the EventIds to delete.
  /// @return the per-EventId operation results.
  static DeleteItemResult delete_events(HistoryStore& store, const DeleteEventsItem& item);

  /// Read history Annotations at specific timestamps (OPC 10000-11 section 6.4.6). One DataValue per
  /// requested timestamp, in request order: the stored Annotation when present, otherwise a Bad_NoData
  /// placeholder. When the store answered a Good subcode or an Uncertain code with its data, the result
  /// carries that code.
  /// @param store the history store queried for stored Annotations.
  /// @param item the ReadAnnotationData operation; carries the requested timestamps.
  /// @return the per-node result: one DataValue per requested timestamp, in request order.
  static ReadAnnotationItemResult read_annotations(HistoryStore& store, const ReadAnnotationItem& item);

  /// Insert / Replace / Update / Remove structured history  -  Annotations (OPC 10000-11 section 6.8.3).
  /// Per-entry status (uniqueness by timestamp): Insert to Good_EntryInserted/Bad_EntryExists;
  /// Replace to Good_EntryReplaced/Bad_NoEntryExists; Update to upsert; Remove to Good/Bad_NoEntryExists.
  /// The engine's Good code is an entry's answer only when the store answered plain Good for it; a Good
  /// subcode or an Uncertain code it answered is the answer instead. An entry whose existence read the store
  /// answers Uncertain is answered `Bad_InternalError` (`ReadAnswerUncertain`, the store's code as cause)
  /// and nothing is written or deleted for it.
  /// @param store the history store the Annotations are written to.
  /// @param item the UpdateStructureData operation; carries the Insert / Replace / Update / Remove mode
  ///        and the Annotation entries.
  /// @return the per-entry operation results.
  static UpdateStructureDataItemResult update_structure_data(
    HistoryStore& store, const UpdateStructureDataItem& item);

private:
  /// @ingroup history
  /// Continuation state of a raw or modified read: the node, the rest of the window, the bound still to
  /// return after it, and the page size. Stored opaquely in the SDK's HistoryContinuationPoint.
  /// `answerCode` is the code of the store answers so far, answered on every resumed page.
  struct RawCursor
  {
    ua::NodeId node;
    bool modified{false};
    HistoryWindowWalk walk;
    /// The bound returned after the window (Part 11 6.4.3.2 returnBounds): the value nearest
    /// `trailingBoundAt` in `trailingBoundDirection`, or a Bad_BoundNotFound placeholder at that time.
    std::optional<ua::DateTime> trailingBoundAt;
    Direction trailingBoundDirection{Direction::After};
    /// The window has been returned in full; only the trailing bound is left.
    bool windowDone{false};
    uint32_t pageSize{0};
    ua::StatusCode answerCode{ua::Status::Good};
  };

  /// @ingroup history
  /// Continuation state for a paged event read: the node, the rest of the window, the page size, the
  /// select-clause keys and model statuses the rows are projected with, and the code of the store
  /// answers so far, answered on every resumed page.
  struct EventsCursor
  {
    ua::NodeId node;
    HistoryWindowWalk walk;
    std::vector<std::string> keys;
    std::vector<ua::StatusCode> selectClauseModelStatuses;
    uint32_t pageSize{0};
    ua::StatusCode answerCode{ua::Status::Good};
  };

  static ReadRawItemResult resume_raw(HistoryStore& store, ReadRawItem& item);
  static ReadRawItemResult read_raw_fresh(HistoryStore& store, ReadRawItem& item);
  static ReadRawItemResult read_modified_fresh(HistoryStore& store, ReadRawItem& item);
  static ReadEventsItemResult resume_events(HistoryStore& store, ReadEventsItem& item);
};

}  // namespace ua::history

#endif  // !UA_HISTORY_ENGINE_H
