// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Extension interface through which a namespace serves OPC UA historical data and events.
/// @ingroup address_space

#ifndef UA_NAMESPACE_HISTORY_DELEGATE_H
#define UA_NAMESPACE_HISTORY_DELEGATE_H

#include <any>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "ua_aggregate_configuration.h"
#include "ua_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_duration.h"
#include "ua_event_filter.h"
#include "ua_history_event_field_list.h"
#include "ua_locale_id.h"
#include "ua_modification_info.h"
#include "ua_node_id.h"
#include "ua_numeric_range.h"
#include "ua_perform_update_type.h"
#include "ua_status_code.h"
#include "ua_timestamps_to_return.h"

namespace ua
{

/// Extension interface through which a namespace serves OPC UA historical data and events.
///
/// A namespace implements this interface to expose history for the nodes it owns;
/// the SDK's HistoryRead and HistoryUpdate services dispatch to it. Each operation
/// is a batched, callback-canonical request: the delegate receives the full list of
/// per-node items and reports each outcome through a @ref BatchResult delivered to
/// the supplied callback. The batch-level status reports whether the request as a
/// whole was accepted; the per-item @ref Result values carry each node's outcome and,
/// on failure, an @ref ErrorDetail.
///
/// All operations have default implementations that report
/// `BadHistoryOperationUnsupported` for every item, so a delegate need only override
/// the operations whose support it declares via @ref capabilities. Every `*_async`
/// method is `noexcept` and never throws - failures are reported through the result
/// payload, never by exception.
///
/// @note The callback may be invoked inline on the calling stack or later from a
///       worker thread; callers apply the post discipline (see async rules). Do not
///       block the callback.
/// @ingroup address_space
class NamespaceHistoryDelegate
{
public:
  virtual ~NamespaceHistoryDelegate() = default;

  NamespaceHistoryDelegate(const NamespaceHistoryDelegate&) = delete;
  NamespaceHistoryDelegate& operator=(const NamespaceHistoryDelegate&) = delete;
  NamespaceHistoryDelegate(NamespaceHistoryDelegate&&) = delete;
  NamespaceHistoryDelegate& operator=(NamespaceHistoryDelegate&&) = delete;

protected:
  /// Protected default constructor: the deleted copy/move members above suppress the
  /// implicit default ctor, but derived classes must be able to construct this base.
  NamespaceHistoryDelegate() = default;

public:
  // --- Cursors ---

  /// Opaque pagination state, created and interpreted only by the delegate.
  ///
  /// The SDK stores this inside its HistoryContinuationPoint and hands it back to the
  /// delegate on continuation requests; the SDK never inspects the contained value.
  /// The delegate is responsible for the cursor's lifetime - see @ref release_cursor.
  using Cursor = std::any;

  // --- Capability discovery ---

  /// The set of history operations a delegate supports.
  ///
  /// Returned by @ref capabilities so the SDK can advertise capabilities and reject
  /// unsupported operations early. Each flag defaults to `false`.
  struct Capabilities
  {
    bool readRaw{false};  ///< Supports raw (stored) value history reads.
    bool readModified{false};  ///< Supports reads of modified/replaced value history.
    bool readProcessed{false};  ///< Supports aggregate-processed value history reads.
    bool readAtTime{false};  ///< Supports reads at specific timestamps.
    bool readEvents{false};  ///< Supports historical event reads.
    bool readAnnotations{false};  ///< Supports reads of history annotations.
    bool updateData{false};  ///< Supports inserting/replacing historical values.
    bool updateEvent{false};  ///< Supports inserting/replacing/updating historical events.
    bool insertAnnotation{false};  ///< Supports inserting/replacing/updating history annotations.
    bool deleteRaw{false};  ///< Supports deleting raw value history.
    bool deleteAtTime{false};  ///< Supports deleting values at specific timestamps.
    bool deleteEvents{false};  ///< Supports deleting historical events.
  };

  // --- Contexts ---

  /// Per-request context passed to every history read operation.
  struct ReadContext
  {
    TimestampsToReturn timestampsToReturn{};  ///< Which timestamps the caller wants returned.
    std::vector<LocaleId> sessionLocales;  ///< Session locale preference order, for localized text.

    /// Cooperative cancellation flag; set to `true` when the request is cancelled.
    ///
    /// Non-null for the duration of the call. The delegate should poll it during
    /// long-running work and stop early once it reads `true`. Shared ownership - safe
    /// to observe from any thread.
    shared_ptr<std::atomic_bool> cancelled;

    /// When the SDK answers the request with what it has (its partial-result deadline,
    /// `ServerConfig::partialResultDeadlineFraction` of the timeoutHint). A delegate that can
    /// stop early returns what it has by then, with a cursor for the rest; one that does not is not cut
    /// off - an item still reading is answered with no values and a continuation point that keeps the
    /// read and returns its result on the next HistoryRead (OPC 10000-11 section 6.3). Empty when the
    /// request asked for no timeout.
    std::optional<std::chrono::steady_clock::time_point> deadline;
  };

  /// Per-request context passed to every history update and delete operation.
  struct UpdateContext
  {
    /// Cooperative cancellation flag; set to `true` when the request is cancelled.
    ///
    /// Non-null for the duration of the call. The delegate should poll it during
    /// long-running work and stop early once it reads `true`. Shared ownership - safe
    /// to observe from any thread.
    shared_ptr<std::atomic_bool> cancelled;

    /// The session user that initiated the update, for the ModificationInfo `userName` recorded with
    /// each modification (OPC 10000-11 6.5.3). Empty when no user identity is available.
    String userName;
  };

  // --- Read requests/responses (one per operation type) ---

  /// A single node's raw or modified value-history read request.
  struct ReadRawItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose history is read.
    NumericRange indexRange;  ///< Element range to return from array values; empty for the whole value.
    DateTime startTime;  ///< Inclusive start of the time range.
    DateTime endTime;  ///< Inclusive end of the time range.
    uint32_t maxValuesPerNode{0};  ///< Maximum values to return; 0 means no limit.
    bool returnBounds{false};  ///< Whether to include bounding values just outside the range.
    bool isReadModified{false};  ///< If true, read modified/replaced history instead of raw.
    std::optional<Cursor> cursor;  ///< Continuation cursor from a prior read; empty on the first call.
  };

  /// Successful outcome of a @ref ReadRawItem.
  struct HistoryReadRawSuccess
  {
    std::vector<DataValue> values;  ///< Historical values, in time order.

    /// Modification metadata, present only for modified-history reads.
    ///
    /// Parallel to @ref values when populated.
    std::vector<ModificationInfo> modificationInfos;
    std::optional<Cursor> cursor;  ///< Continuation cursor if more values remain; empty when complete.
  };

  /// Per-item result of a raw/modified value-history read.
  using ReadRawItemResult = Result<HistoryReadRawSuccess>;

  /// A single node's read-at-time request.
  struct ReadAtTimeItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose history is read.
    NumericRange indexRange;  ///< Element range to return from array values; empty for the whole value.
    std::vector<DateTime> timestamps;  ///< Exact timestamps at which to return values.
    bool useSimpleBounds{
      false};  ///< Use simple (vs interpolated) bounding when a timestamp has no exact value.
    std::optional<Cursor> cursor;  ///< Continuation cursor from a prior read; empty on the first call.
  };

  /// Successful outcome of a @ref ReadAtTimeItem.
  struct HistoryReadAtTimeSuccess
  {
    std::vector<DataValue> values;  ///< One value per requested timestamp, in request order.
    std::optional<Cursor> cursor;  ///< Continuation cursor if more values remain; empty when complete.
  };

  /// Per-item result of a read-at-time operation.
  using ReadAtTimeItemResult = Result<HistoryReadAtTimeSuccess>;

  /// A single node's aggregate-processed value-history read request.
  struct ReadProcessedItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose history is read.
    NumericRange indexRange;  ///< Element range to return from array values; empty for the whole value.
    DateTime startTime;  ///< Inclusive start of the time range.
    DateTime endTime;  ///< Inclusive end of the time range.
    Duration processingInterval{0.0};  ///< Aggregation interval, in milliseconds; 0 means a single interval.
    NodeId aggregateType;  ///< Aggregate function to apply (e.g. Average, Minimum).
    AggregateConfiguration aggregateConfiguration;  ///< Detailed aggregate behaviour settings.
    std::optional<Cursor> cursor;  ///< Continuation cursor from a prior read; empty on the first call.
  };

  /// Successful outcome of a @ref ReadProcessedItem.
  struct HistoryReadProcessedSuccess
  {
    std::vector<DataValue> values;  ///< Aggregated values, one per interval, in time order.
    std::optional<Cursor> cursor;  ///< Continuation cursor if more values remain; empty when complete.
  };

  /// Per-item result of an aggregate-processed read.
  using ReadProcessedItemResult = Result<HistoryReadProcessedSuccess>;

  /// A single node's annotation-history read request.
  struct ReadAnnotationItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose annotations are read.
    std::vector<DateTime> reqTimes;  ///< Requested timestamps; results must match this order.
    std::optional<Cursor> cursor;  ///< Continuation cursor from a prior read; empty on the first call.
  };

  /// Successful outcome of a @ref ReadAnnotationItem.
  struct HistoryReadAnnotationSuccess
  {
    std::vector<DataValue>
      values;  ///< Annotation-typed DataValues, in @ref ReadAnnotationItem::reqTimes order.
    std::optional<Cursor> cursor;  ///< Continuation cursor if more values remain; empty when complete.
  };

  /// Per-item result of an annotation read.
  using ReadAnnotationItemResult = Result<HistoryReadAnnotationSuccess>;

  /// A single node's historical-event read request.
  struct ReadEventsItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Event-source node whose history is read.
    DateTime startTime;  ///< Inclusive start of the time range.
    DateTime endTime;  ///< Inclusive end of the time range.
    uint32_t maxValuesPerNode{0};  ///< Maximum events to return; 0 means no limit.
    /// Selects which event fields to return and which events match. The server authorizes the fields of
    /// this filter's select clauses, one per position, and withholds those the session may not read; a
    /// continuation shall therefore project this filter, or refuse with Bad_ContinuationPointInvalid
    /// when it differs from the one its cursor was issued for.
    EventFilter filter;
    std::vector<StatusCode> selectClauseModelStatuses;  ///< Parallel to the filter's select clauses. Good
                                                        ///< means the EventType model declares that field;
                                                        ///< a rich bad status retains why it does not.
    std::optional<Cursor> cursor;  ///< Continuation cursor from a prior read; empty on the first call.
  };

  /// Successful outcome of a @ref ReadEventsItem.
  struct HistoryReadEventsSuccess
  {
    /// Where an archived event came from, so the server can authorize it as it authorizes a live one.
    struct EventOrigin
    {
      NodeId sourceNode;  ///< The event's SourceNode; null when the archive did not record it.
      NodeId eventType;  ///< The event's EventType; null when the archive did not record it.
    };

    std::vector<HistoryEventFieldList> events;  ///< Matching events, each as a list of selected field values.
    std::optional<Cursor> cursor;  ///< Continuation cursor if more events remain; empty when complete.
    /// Parallel to @ref events (may be shorter or empty). When present, the server keeps an event only if
    /// the session holds ReceiveEvents on its SourceNode and its EventType, exactly as live delivery does;
    /// an event without an origin, or a delegate that reports none, is gated by ReadHistory on the
    /// notifier alone. The SDK's own history engine reports the origins it recorded. Declared last so a
    /// delegate that initialises the aggregate positionally with {events, cursor} keeps compiling.
    std::vector<EventOrigin> origins;
  };

  /// Per-item result of a historical-event read.
  using ReadEventsItemResult = Result<HistoryReadEventsSuccess>;

  // --- Update requests/responses ---

  /// A single node's value-history insert/replace request.
  struct UpdateDataItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose history is updated.
    PerformUpdateType performInsertReplace{
      PerformUpdateType::Insert};  ///< Insert, Replace, or Update semantics.
    std::vector<DataValue> values;  ///< Values to insert or replace, in time order.
  };

  /// Successful outcome of a history update or delete operation.
  struct HistoryUpdateSuccess
  {
    std::vector<StatusCode> operationResults;  ///< Per-value status, parallel to the request's value list.
  };

  /// Per-item result of a value-history update.
  using UpdateDataItemResult = Result<HistoryUpdateSuccess>;

  /// A single node's historical-event insert/replace/update request.
  struct UpdateEventsItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Event-source node whose events are updated.
    PerformUpdateType performInsertReplace{
      PerformUpdateType::Insert};  ///< Insert, Replace, or Update semantics.
    EventFilter filter;  ///< Select clauses describing the fields in each @ref events entry, in order.
    std::vector<HistoryEventFieldList> events;  ///< Events to write, each a field-value list per @ref filter.
  };

  /// Per-item result of a historical-event update.
  using UpdateEventsItemResult = Result<HistoryUpdateSuccess>;

  /// A single node's structured-history insert/replace/update request (e.g. Annotations).
  struct UpdateStructureDataItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose structured history is updated.
    PerformUpdateType performInsertReplace{
      PerformUpdateType::Insert};  ///< Insert, Replace, Update, or Remove semantics.
    std::vector<DataValue> values;  ///< Structured entries to write; each Value is e.g. an Annotation.
  };

  /// Per-item result of a structured-history update.
  using UpdateStructureDataItemResult = Result<HistoryUpdateSuccess>;

  /// A single node's raw/modified value-history delete request.
  struct DeleteRawItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose history is deleted.
    bool isDeleteModified{false};  ///< If true, delete modified history instead of raw history.
    DateTime startTime;  ///< Inclusive start of the time range to delete.
    DateTime endTime;  ///< Inclusive end of the time range to delete.
  };

  /// A single node's delete-at-time request.
  struct DeleteAtTimeItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Node whose history is deleted.
    std::vector<DateTime> timestamps;  ///< Exact timestamps whose values are deleted.
  };

  /// A single node's historical-event delete request.
  struct DeleteEventsItem
  {
    size_t index{};  ///< Position of this item in the originating service request.
    NodeId nodeId;  ///< Event-source node whose events are deleted.
    std::vector<ByteString> eventIds;  ///< Identifiers of the events to delete.
  };

  /// Per-item result of any history delete operation.
  using DeleteItemResult = UpdateDataItemResult;

  // --- Detail kind enum (for CP tracking) ---

  /// Identifies which kind of history read a continuation point belongs to.
  ///
  /// Used by the SDK to validate that a continuation request resumes the same read
  /// kind that produced the cursor.
  enum class DetailKind
  {
    Raw,  ///< Raw value-history read.
    Modified,  ///< Modified/replaced value-history read.
    AtTime,  ///< Read-at-time.
    Processed,  ///< Aggregate-processed read.
    Annotation,  ///< Annotation read.
    Events  ///< Historical-event read.
  };

  /// Declares which history operations this delegate supports.
  ///
  /// Overrides should set a flag only for an operation they actually implement; the
  /// SDK uses the result to advertise capabilities and reject unsupported operations.
  ///
  /// @return The supported-operation flags. The default returns all-false (no
  ///         operations supported).
  virtual Capabilities capabilities() const noexcept
  {
    return {};
  }

  // --- Read operations ---
  // Default implementations return BadHistoryOperationUnsupported per item.

  /// Callback receiving the per-item outcomes of a @ref read_raw_async batch.
  using ReadRawCallback = std::function<void(BatchResult<ReadRawItemResult>)>;

  /// Reads raw or modified value history for a batch of nodes.
  ///
  /// @param context  Read context, including cancellation flag and timestamp preference.
  /// @param items    Per-node read requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose batch status reports whether the
  ///                 request was accepted, and each per-item @ref Result holds the node's
  ///                 values or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  /// @see capabilities, release_cursor
  virtual void read_raw_async(
    const ReadContext& context, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref read_at_time_async batch.
  using ReadAtTimeCallback = std::function<void(BatchResult<ReadAtTimeItemResult>)>;

  /// Reads values at specific timestamps for a batch of nodes.
  ///
  /// @param context  Read context, including cancellation flag and timestamp preference.
  /// @param items    Per-node read requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the node's
  ///                 values or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void read_at_time_async(
    const ReadContext& context, std::vector<ReadAtTimeItem> items, ReadAtTimeCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref read_processed_async batch.
  using ReadProcessedCallback = std::function<void(BatchResult<ReadProcessedItemResult>)>;

  /// Reads aggregate-processed value history for a batch of nodes.
  ///
  /// @param context  Read context, including cancellation flag and timestamp preference.
  /// @param items    Per-node read requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 aggregated values or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void read_processed_async(const ReadContext& context, std::vector<ReadProcessedItem> items,
    ReadProcessedCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref read_annotations_async batch.
  using ReadAnnotationCallback = std::function<void(BatchResult<ReadAnnotationItemResult>)>;

  /// Reads history annotations for a batch of nodes.
  ///
  /// @param context  Read context, including cancellation flag and timestamp preference.
  /// @param items    Per-node read requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 annotation values or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void read_annotations_async(const ReadContext& context, std::vector<ReadAnnotationItem> items,
    ReadAnnotationCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref read_events_async batch.
  using ReadEventsCallback = std::function<void(BatchResult<ReadEventsItemResult>)>;

  /// Reads historical events for a batch of event-source nodes.
  ///
  /// @param context  Read context, including cancellation flag and timestamp preference.
  /// @param items    Per-node read requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 matching events or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void read_events_async(
    const ReadContext& context, std::vector<ReadEventsItem> items, ReadEventsCallback callback) noexcept;

  // --- Update operations ---
  // Default implementations return BadHistoryOperationUnsupported per item.

  /// Callback receiving the per-item outcomes of an @ref update_data_async batch.
  using UpdateDataCallback = std::function<void(BatchResult<UpdateDataItemResult>)>;

  /// Inserts or replaces historical values for a batch of nodes.
  ///
  /// @param context  Update context, including the cancellation flag.
  /// @param items    Per-node update requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 per-value status codes or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void update_data_async(
    const UpdateContext& context, std::vector<UpdateDataItem> items, UpdateDataCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of an @ref update_events_async batch.
  using UpdateEventsCallback = std::function<void(BatchResult<UpdateEventsItemResult>)>;

  /// Inserts, replaces, or updates historical events for a batch of event-source nodes.
  ///
  /// @param context  Update context, including the cancellation flag.
  /// @param items    Per-node update requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 per-event status codes or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void update_events_async(const UpdateContext& context, std::vector<UpdateEventsItem> items,
    UpdateEventsCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of an @ref update_structure_data_async batch.
  using UpdateStructureDataCallback = std::function<void(BatchResult<UpdateStructureDataItemResult>)>;

  /// Inserts, replaces, updates, or removes structured history (e.g. Annotations) for a batch of nodes.
  ///
  /// @param context  Update context, including the cancellation flag.
  /// @param items    Per-node update requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 per-entry status codes or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void update_structure_data_async(const UpdateContext& context,
    std::vector<UpdateStructureDataItem> items, UpdateStructureDataCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref delete_raw_async batch.
  using DeleteRawCallback = std::function<void(BatchResult<DeleteItemResult>)>;

  /// Deletes raw or modified value history over a time range for a batch of nodes.
  ///
  /// @param context  Update context, including the cancellation flag.
  /// @param items    Per-node delete requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 outcome or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void delete_raw_async(
    const UpdateContext& context, std::vector<DeleteRawItem> items, DeleteRawCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref delete_at_time_async batch.
  using DeleteAtTimeCallback = std::function<void(BatchResult<DeleteItemResult>)>;

  /// Deletes values at specific timestamps for a batch of nodes.
  ///
  /// @param context  Update context, including the cancellation flag.
  /// @param items    Per-node delete requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 outcome or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void delete_at_time_async(const UpdateContext& context, std::vector<DeleteAtTimeItem> items,
    DeleteAtTimeCallback callback) noexcept;

  /// Callback receiving the per-item outcomes of a @ref delete_events_async batch.
  using DeleteEventsCallback = std::function<void(BatchResult<DeleteItemResult>)>;

  /// Deletes historical events for a batch of event-source nodes.
  ///
  /// @param context  Update context, including the cancellation flag.
  /// @param items    Per-node delete requests, taken by value so the delegate may retain them.
  /// @param callback Receives a @ref BatchResult whose per-item @ref Result holds the
  ///                 outcome or an @ref ErrorDetail. This method never throws.
  /// @note The default implementation reports `BadHistoryOperationUnsupported` per item.
  virtual void delete_events_async(const UpdateContext& context, std::vector<DeleteEventsItem> items,
    DeleteEventsCallback callback) noexcept;

  // --- Cursor lifecycle ---

  /// Releases a continuation cursor the delegate previously issued.
  ///
  /// Called by the SDK when the owning continuation point is released by the client,
  /// evicted, or destroyed. The delegate frees any resources associated with the cursor.
  ///
  /// @param cursor The cursor to release; ownership transfers to this call.
  /// @pre Must be safe to call from any thread, including after the delegate has begun
  ///      shutdown.
  /// @post The cursor must not be used again.
  /// @note Must complete synchronously and never throw.
  /// @see Cursor
  virtual void release_cursor([[maybe_unused]] Cursor cursor) noexcept
  {}
};

}  // namespace ua

#endif  // UA_NAMESPACE_HISTORY_DELEGATE_H
