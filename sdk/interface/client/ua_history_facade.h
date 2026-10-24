// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_FACADE_H
#define UA_HISTORY_FACADE_H

/// @file
/// @brief Tier-2 public `HistoryFacade`: the flattened, one-hop per-`Connection` facade for the Historical
///        Access service set (client design section 8.9, ratified D2). Returned by `Connection::history()`.
/// @ingroup client

#include "ua_aggregate_configuration.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_diagnostic_info.h"
#include "ua_duration.h"
#include "ua_continuation_limits.h"
#include "ua_history_read_cursor.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_perform_update_type.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_timestamps_to_return.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ua
{
class Structure;
}  // namespace ua

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
class WireOps;
struct HistoryReadCursorState;
struct HistoryFacadeTestAccess;
}  // namespace detail

class Connection;

/// A historical time-range selector shared by the Raw / Modified / Processed reads and the range delete
/// (client design section 8.9.1). A default-constructed `ua::DateTime` (the OPC UA null sentinel) means
/// "unspecified" for @ref startTime / @ref endTime; `0` means "unspecified" for @ref numValuesPerNode.
/// @ingroup client
struct TimeRange
{
  /// The inclusive start of the range (null = unspecified).
  ua::DateTime startTime;
  /// The exclusive end of the range (null = unspecified).
  ua::DateTime endTime;
  /// The maximum values to return per node (0 = unspecified; Raw / Modified only).
  std::uint32_t numValuesPerNode = 0;

  /// @return True iff @ref startTime is specified (not the null sentinel).
  [[nodiscard]] bool start_specified() const
  {
    return !startTime.is_null();
  }

  /// @return True iff @ref endTime is specified (not the null sentinel).
  [[nodiscard]] bool end_specified() const
  {
    return !endTime.is_null();
  }

  /// @return True iff @ref numValuesPerNode is specified (non-zero).
  [[nodiscard]] bool count_specified() const
  {
    return numValuesPerNode != 0;
  }
};

/// The optional shaping applied to a history read (client design section 8.9.1).
/// @ingroup client
struct HistoryReadOptions
{
  /// Which timestamps the server should return. Defaults to `Source`; `Neither` is rejected locally
  /// (CL-HIST-010).
  ua::TimestampsToReturn timestampsToReturn = ua::TimestampsToReturn::Source;
  /// Whether a Raw read should return the bounding values (ignored for Modified  -  hard-coded false,
  /// CL-HIST-007).
  bool returnBounds = false;
  /// Per-call AggregateConfiguration override for a processed read (CL-HIST-014, section 8.9.1). When unset
  /// (the default), the processed read sends `useServerCapabilitiesDefaults=true`, so the server applies its
  /// own configured aggregate defaults and the other fields are inert. When set, the exact configuration is
  /// plumbed to the wire; a server that rejects it returns `Bad_AggregateConfigurationRejected`, which the
  /// reader surfaces with a remediation hint. Ignored by non-processed reads (they carry no aggregate).
  std::optional<ua::AggregateConfiguration> aggregateConfiguration;
  /// How many empty pages with a continuation point the cursor re-requests in a row before `next` fails
  /// with `Bad_Timeout`; see @ref ContinuationLimits.
  ContinuationLimits continuationLimits{};
};

/// The tier-2 shape of a per-node HistoryUpdate result (client design section 8.9.1, CL-HIST-021). Mirrors
/// the wire `HistoryUpdateResult` one-for-one: the per-node operation status, the per-update-value operation
/// results (preserved verbatim  -  a per-entry Bad is value-quality, not a service failure, CL-HIST-023), and
/// the optional diagnostics.
/// @ingroup client
struct HistoryUpdateResult
{
  /// The per-node operation-level status (a bad code here is NOT a service failure  -  the outer Result is
  /// still Good; the node's action did not succeed, CL-HIST-021).
  ua::StatusCode statusCode;
  /// The per-update-value operation results (== the input vector length for data writes; per-timestamp for
  /// deletes). Preserved verbatim, including `Good_EntryInserted` / `Bad_EntryExists` etc.
  /// (CL-HIST-019/-023).
  std::vector<ua::StatusCode> operationResults;
  /// The optional per-value diagnostics (server-discretionary per `returnDiagnostics`).
  std::vector<ua::DiagnosticInfo> diagnosticInfos;
};

/// The flattened, one-hop per-`Connection` facade for Historical Access (client design section 8.9, D2).
///
/// A lightweight move-only value handle over the same tier-1 wire interface (`detail::WireOps`) as its parent
/// @ref Connection, reached via `Connection::history()`. Per the ratified D2 flatten, the history reads and
/// writes are DIRECT methods (no `reader()` / `updater()` sub-hop), so a history WRITE is reachable in one
/// hop (`conn.history().update_data_async(...)`). It owns no strand state of its own; every method composes
/// the correct `HistoryReadDetails` / `HistoryUpdateDetails` ExtensibleParameter and forwards through the
/// wire interface's `history_read_async` / `history_update_async` (single ErrorDetail wrap  -  the facade
/// never double-wraps).
///
/// Each operation follows the async / sync / try_sync triple (section 7.0):
///  - `*_async`     -  never throws; the callback receives a `Result<...>` on the executor.
///  - `*_sync`      -  blocks; returns the bare value; throws `UaException` when the `Result` is not Good (an
///                     Uncertain answer included). A Good subcode on the answer is not returned; the
///                     `try_*_sync` form returns it.
///  - `try_*_sync`  -  blocks; returns `Result<...>`; never throws.
///
/// A Good subcode or an Uncertain code the server answers is never replaced with plain Good. A read's cursor
/// Result and its first page carry the read's ServiceResult and per-node statusCode combined
/// (`ua::detail::combined_status`), so Good_NoData reaches the caller; an update's Result carries the
/// ServiceResult beside the per-node @ref HistoryUpdateResult::statusCode; a capability probe's Result
/// carries the ServiceResult and the AccessLevel's status combined, and the HasHistoricalConfiguration list
/// carries every page's code combined. The update preflights act on the server's answers themselves and
/// refuse an Uncertain one with Bad_InternalError (`ReadAnswerUncertain`).
///
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread on the async completion. They MUST
///          NOT be called from the Connection's executor thread.
/// @ingroup client
class HistoryFacade
{
public:
  /// Returns or updates the history facade.
  HistoryFacade(const HistoryFacade&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  HistoryFacade& operator=(const HistoryFacade&) = default;
  /// Returns or updates the history facade.
  HistoryFacade(HistoryFacade&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  HistoryFacade& operator=(HistoryFacade&&) noexcept = default;
  ~HistoryFacade() = default;

  // ============ Reads ( to  HistoryReadCursor) ============

  /// Reads raw historical values over a time range by composing
  /// `ReadRawModifiedDetails { isReadModified=false }` (CL-HIST-007). Pre-flight requires at least two of
  /// `{start, end, count}` (CL-HIST-003).
  /// @param node Target node identifier.
  /// @param range Time range and count constraints.
  /// @param options History-read options.
  /// @param callback Completion callback receiving the cursor or failure detail. The cursor's Result carries
  ///                 the read's code (a Good subcode such as Good_NoData, or an Uncertain code).
  void read_raw_async(ua::NodeId node, TimeRange range, HistoryReadOptions options,
    std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Synchronously read raw. A Good subcode on the answer is not returned; try_read_raw_sync() returns it.
  HistoryReadCursor read_raw_sync(ua::NodeId node, TimeRange range, HistoryReadOptions options = {});
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param options Options controlling the operation.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read raw sync without throwing.
  ua::Result<HistoryReadCursor> try_read_raw_sync(
    ua::NodeId node, TimeRange range, HistoryReadOptions options = {}) noexcept;

  /// Reads modified historical values over a time range by composing
  /// `ReadRawModifiedDetails { isReadModified=true, returnBounds=false }` (CL-HIST-007). Pre-flight requires
  /// at least two of `{start, end, count}` (CL-HIST-003).
  /// @param node Target node identifier.
  /// @param range Time range and count constraints.
  /// @param options History-read options.
  /// @param callback Completion callback receiving the cursor or failure detail. The cursor's Result carries
  ///                 the read's code (a Good subcode such as Good_NoData, or an Uncertain code).
  void read_modified_async(ua::NodeId node, TimeRange range, HistoryReadOptions options,
    std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Synchronously read modified. A Good subcode on the answer is not returned; try_read_modified_sync()
  /// returns it.
  HistoryReadCursor read_modified_sync(ua::NodeId node, TimeRange range, HistoryReadOptions options = {});
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param options Options controlling the operation.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read modified sync without throwing.
  ua::Result<HistoryReadCursor> try_read_modified_sync(
    ua::NodeId node, TimeRange range, HistoryReadOptions options = {}) noexcept;

  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param options Options controlling the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Reads historical values at specific timestamps (composes `ReadAtTimeDetails`, positional order
  /// preserved, CL-HIST-016). The cursor's Result carries the read's code (a Good subcode or an Uncertain
  /// code).
  void read_at_time_async(ua::NodeId node, std::vector<ua::DateTime> requestedTimes,
    HistoryReadOptions options, std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Synchronously read at time. A Good subcode on the answer is not returned; try_read_at_time_sync()
  /// returns it.
  HistoryReadCursor read_at_time_sync(
    ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options = {});
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param options Options controlling the operation.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read at time sync without throwing.
  ua::Result<HistoryReadCursor> try_read_at_time_sync(
    ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options = {}) noexcept;

  /// Reads a single aggregate over a time range (composes `ReadProcessedDetails` with one aggregate,
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param options Options controlling the operation.
  /// @param callback Completion callback that receives the operation result.
  /// CL-HIST-005). Pre-flight: `{start, end}` specified and `start != end` (CL-HIST-004). The cursor's Result
  /// carries the read's code (a Good subcode or an Uncertain code).
  ///
  /// @param aggregateType       The aggregate function NodeId (e.g. `ua::client::aggregate::Average`); passed
  ///                            through verbatim (CL-HIST-006).
  /// @param processingInterval  The aggregation interval in milliseconds.
  void read_processed_async(ua::NodeId node, TimeRange range, ua::NodeId aggregateType,
    ua::Duration processingInterval, HistoryReadOptions options,
    std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param aggregateType The aggregate type.
  /// @param processingInterval The processing interval.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Synchronously read processed. A Good subcode on the answer is not returned; try_read_processed_sync()
  /// returns it.
  HistoryReadCursor read_processed_sync(ua::NodeId node, TimeRange range, ua::NodeId aggregateType,
    ua::Duration processingInterval, HistoryReadOptions options = {});
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param aggregateType The aggregate type.
  /// @param processingInterval The processing interval.
  /// @param options Options controlling the operation.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read processed sync without throwing.
  ua::Result<HistoryReadCursor> try_read_processed_sync(ua::NodeId node, TimeRange range,
    ua::NodeId aggregateType, ua::Duration processingInterval, HistoryReadOptions options = {}) noexcept;

  /// Reads historical annotations at specific timestamps (composes `ReadAnnotationDataDetails`, NS0 i=659,
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param options Options controlling the operation.
  /// @param callback Completion callback that receives the operation result.
  /// CL-HIST-015). The cursor yields the raw annotation `DataValue`s; typed `Annotation` decoding is a later
  /// refinement. The cursor's Result carries the read's code (a Good subcode or an Uncertain code).
  void read_annotations_async(ua::NodeId node, std::vector<ua::DateTime> requestedTimes,
    HistoryReadOptions options, std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Synchronously read annotations. A Good subcode on the answer is not returned;
  /// try_read_annotations_sync() returns it.
  HistoryReadCursor read_annotations_sync(
    ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options = {});
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param options Options controlling the operation.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read annotations sync without throwing.
  ua::Result<HistoryReadCursor> try_read_annotations_sync(
    ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options = {}) noexcept;

  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Reports whether @p node advertises historical-data reads through
  /// `AccessLevel.HistoryRead` (OPC 10000-11 section 5.2.4, CL-HIST-001). The Result carries the Read's
  /// ServiceResult and the AccessLevel's status combined: a Good subcode or an Uncertain code is kept with
  /// the flag, and an Uncertain answer without an AccessLevel is answered with its code and no flag. Only a
  /// plain Good answer is cached.
  void is_history_capable_async(ua::NodeId node, std::function<void(ua::Result<bool>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @return True when the requested condition is satisfied.
  /// Synchronously is history capable. A Good subcode on the answer is not returned;
  /// try_is_history_capable_sync() returns it.
  bool is_history_capable_sync(ua::NodeId node);
  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to is history capable sync without throwing.
  ua::Result<bool> try_is_history_capable_sync(ua::NodeId node) noexcept;

  /// @param historicalDataNode The historical data node.
  /// @param callback Completion callback that receives the operation result.
  /// Discovers the Objects referenced from @p historicalDataNode by
  /// `HasHistoricalConfiguration` (OPC 10000-11 section 5.2.3, CL-HIST-002). The Result carries every
  /// Browse/BrowseNext page's ServiceResult and status combined, so a Good subcode or an Uncertain code is
  /// kept with the list.
  void historical_configurations_async(ua::NodeId historicalDataNode,
    std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback) noexcept;
  /// @param historicalDataNode The historical data node.
  /// @return The requested value.
  /// Synchronously historical configurations. A Good subcode on the answer is not returned;
  /// try_historical_configurations_sync() returns it.
  std::vector<ua::NodeId> historical_configurations_sync(ua::NodeId historicalDataNode);
  /// @param historicalDataNode The historical data node.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to historical configurations sync without throwing.
  ua::Result<std::vector<ua::NodeId>> try_historical_configurations_sync(
    ua::NodeId historicalDataNode) noexcept;

  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Reports whether @p node advertises historical-data updates through
  /// `AccessLevel.HistoryWrite` (OPC 10000-11 section 5.2.4, CL-HIST-020). The Result carries the code as
  /// @ref is_history_capable_async does. The update operations use this flag only from a Good answer.
  void is_history_writable_async(ua::NodeId node, std::function<void(ua::Result<bool>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @return True when the requested condition is satisfied.
  /// Synchronously is history writable. A Good subcode on the answer is not returned;
  /// try_is_history_writable_sync() returns it.
  bool is_history_writable_sync(ua::NodeId node);
  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to is history writable sync without throwing.
  ua::Result<bool> try_is_history_writable_sync(ua::NodeId node) noexcept;

  // ============ Writes / deletes ( to  Result<HistoryUpdateResult>) ============

  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @param performType The perform type.
  /// @param callback Completion callback that receives the operation result.
  /// Inserts / replaces / updates historical values (composes `UpdateDataDetails`, NS0 i=680, with the given
  /// @p performType, CL-HIST-018/-019). The Result carries the HistoryUpdate's ServiceResult (a Good subcode
  /// or an Uncertain code kept); the preflight refuses an Uncertain AccessLevel or HistoryServerCapabilities
  /// answer with Bad_InternalError (`ReadAnswerUncertain`).
  void update_data_async(ua::NodeId node, std::vector<ua::DataValue> values,
    ua::PerformUpdateType performType,
    std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @param performType The perform type.
  /// @return The requested value.
  /// Synchronously update data. A Good subcode on the answer is not returned; try_update_data_sync() returns
  /// it.
  HistoryUpdateResult update_data_sync(
    ua::NodeId node, std::vector<ua::DataValue> values, ua::PerformUpdateType performType);
  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @param performType The perform type.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to update data sync without throwing.
  ua::Result<HistoryUpdateResult> try_update_data_sync(
    ua::NodeId node, std::vector<ua::DataValue> values, ua::PerformUpdateType performType) noexcept;

  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// Inserts historical values (pins `PerformUpdateType::Insert`, CL-HIST-019).
  void insert_data_async(ua::NodeId node, std::vector<ua::DataValue> values,
    std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @return The requested value.
  /// Synchronously insert data. A Good subcode on the answer is not returned; try_insert_data_sync() returns
  /// it.
  HistoryUpdateResult insert_data_sync(ua::NodeId node, std::vector<ua::DataValue> values);
  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to insert data sync without throwing.
  ua::Result<HistoryUpdateResult> try_insert_data_sync(
    ua::NodeId node, std::vector<ua::DataValue> values) noexcept;

  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// Replaces historical values (pins `PerformUpdateType::Replace`, CL-HIST-019).
  void replace_data_async(ua::NodeId node, std::vector<ua::DataValue> values,
    std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @return The requested value.
  /// Synchronously replace data. A Good subcode on the answer is not returned; try_replace_data_sync()
  /// returns it.
  HistoryUpdateResult replace_data_sync(ua::NodeId node, std::vector<ua::DataValue> values);
  /// @param node Target node identifier.
  /// @param values Values to write or evaluate.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to replace data sync without throwing.
  ua::Result<HistoryUpdateResult> try_replace_data_sync(
    ua::NodeId node, std::vector<ua::DataValue> values) noexcept;

  /// Deletes raw / modified historical values over a time range (composes `DeleteRawModifiedDetails`, NS0
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param isDeleteModified The is delete modified.
  /// @param callback Completion callback that receives the operation result.
  /// i=689, CL-HIST-018). Pre-flight: `{start, end}` specified and `start <= end` (CL-HIST-022).
  void delete_raw_modified_async(ua::NodeId node, TimeRange range, bool isDeleteModified,
    std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param isDeleteModified The is delete modified.
  /// @return The requested value.
  /// Synchronously delete raw modified. A Good subcode on the answer is not returned;
  /// try_delete_raw_modified_sync() returns it.
  HistoryUpdateResult delete_raw_modified_sync(ua::NodeId node, TimeRange range, bool isDeleteModified);
  /// @param node Target node identifier.
  /// @param range Index or time range to access.
  /// @param isDeleteModified The is delete modified.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to delete raw modified sync without throwing.
  ua::Result<HistoryUpdateResult> try_delete_raw_modified_sync(
    ua::NodeId node, TimeRange range, bool isDeleteModified) noexcept;

  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @param callback Completion callback that receives the operation result.
  /// Deletes historical values at specific timestamps (composes `DeleteAtTimeDetails`, NS0 i=692,
  /// CL-HIST-018).
  void delete_at_time_async(ua::NodeId node, std::vector<ua::DateTime> requestedTimes,
    std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @return The requested value.
  /// Synchronously delete at time. A Good subcode on the answer is not returned; try_delete_at_time_sync()
  /// returns it.
  HistoryUpdateResult delete_at_time_sync(ua::NodeId node, std::vector<ua::DateTime> requestedTimes);
  /// @param node Target node identifier.
  /// @param requestedTimes The requested times.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to delete at time sync without throwing.
  ua::Result<HistoryUpdateResult> try_delete_at_time_sync(
    ua::NodeId node, std::vector<ua::DateTime> requestedTimes) noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::HistoryFacadeTestAccess;

  HistoryFacade(
    std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor, ua::Logger logger = {});

  /// Wraps a built cursor state in a @ref HistoryReadCursor. A `HistoryFacade` member (hence a friend of the
  /// cursor) so the read completions  -  which run in a `HistoryFacade` member's lambda  -  can allocate the
  /// cursor without exposing a public cursor constructor.
  static HistoryReadCursor make_cursor(std::shared_ptr<detail::HistoryReadCursorState> state);

  /// The one funnel every `read_*_async` post-pre-flight goes through: locks the wire interface, dispatches
  /// the initial HistoryRead carrying @p details for @p node, decodes the first result, and hands back a
  /// cursor (or a bad Result) on @p executor. Static so it captures only value copies (never `this`)  -  the
  /// facade handle may be dropped while the read is in flight. @p logger is stamped onto the cursor state so
  /// the cursor's best-effort continuation-point release logs at the wire boundary (CL-HIST-009).
  static void issue_read(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::Logger logger, ua::NodeId node, std::unique_ptr<ua::Structure> details,
    ua::TimestampsToReturn timestampsToReturn, ContinuationLimits continuationLimits,
    std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept;

  enum class UpdateCapability
  {
    InsertData,
    ReplaceData,
    UpdateData,
    DeleteRaw,
    DeleteAtTime
  };

  void preflight_update_async(
    ua::NodeId node, UpdateCapability capability, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param node The node.
  /// @param capability The capability.
  /// @return The requested value.
  /// Synchronously preflight update. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void preflight_update_sync(ua::NodeId node, UpdateCapability capability);
  /// @param node The node.
  /// @param capability The capability.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to preflight update sync without throwing.
  ua::VoidResult try_preflight_update_sync(ua::NodeId node, UpdateCapability capability) noexcept;

  std::weak_ptr<detail::WireOps> mWireOps;
  boost::asio::any_io_executor mExecutor;
  ua::Logger mLogger;

  struct AttributeProbeCache
  {
    /// Public server capabilities API.
    struct ServerCapabilities
    {
      /// The insert data.
      bool insertData = false;
      /// The replace data.
      bool replaceData = false;
      /// The update data.
      bool updateData = false;
      /// The delete raw.
      bool deleteRaw = false;
      /// The delete at time.
      bool deleteAtTime = false;
    };

    std::mutex mutex;
    std::unordered_map<ua::NodeId, bool> historyReadable;
    std::unordered_map<ua::NodeId, bool> historyWritable;
    std::optional<ServerCapabilities> serverCapabilities;
    bool serverCapabilitiesLoading = false;
    std::vector<std::function<void(ua::VoidResult)>> serverCapabilitiesWaiters;
  };

  std::shared_ptr<AttributeProbeCache> mAttributeProbeCache;
};

}  // namespace ua::client

#endif  // UA_HISTORY_FACADE_H
