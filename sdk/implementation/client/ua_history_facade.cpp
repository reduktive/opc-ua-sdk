// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_facade.h"
#include "ua_browse_drain_guard.h"

#include "ua_aggregate_configuration.h"
#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_client_answer_status.h"
#include "ua_sync_wait.h"
#include "ua_connection_ops.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_history_data.h"
#include "ua_history_read_cursor_state.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_history_read_value_id.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_result.h"
#include "ua_read_annotation_data_details.h"
#include "ua_read_at_time_details.h"
#include "ua_read_processed_details.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_raw_modified_details.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_ref_structure.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_update_data_details.h"
#include "ua_variable_id.h"

#include <boost/asio/post.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-DIAG-002/-015).
constexpr std::string_view readSource = "client.tier2.history_reader.read";
constexpr std::string_view updateSource = "client.tier2.history_updater.update";
constexpr std::string_view resultLengthMismatchSource = "client.tier2.history_updater.result_length_mismatch";
constexpr std::string_view invalidRangeSource = "client.tier2.history_reader.invalid_time_range";
constexpr std::string_view timestampsSource = "client.tier2.history_reader.timestamps_neither_invalid";
constexpr std::string_view aggregateConfigRejectedSource =
  "client.tier2.history_reader.aggregate_config_rejected";
constexpr std::string_view goneSource = "client.tier2.history_facade.connection_gone";

using CursorResult = ua::Result<HistoryReadCursor>;
using UpdateResult = ua::Result<HistoryUpdateResult>;
using NodeListResult = ua::Result<std::vector<ua::NodeId>>;

template<typename Cache>
void complete_capability_waiters(const std::shared_ptr<Cache>& cache, ua::VoidResult result)
{
  std::vector<std::function<void(ua::VoidResult)>> waiters;
  {
    const std::scoped_lock lock{cache->mutex};
    cache->serverCapabilitiesLoading = false;
    waiters.swap(cache->serverCapabilitiesWaiters);
  }
  for (const auto& waiter : waiters)
    waiter(result);
}

NodeListResult history_browse_failure(
  ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail = {})
{
  if (detail)
    return NodeListResult{status, std::move(detail)};
  return NodeListResult{status,
    ua::make_error_detail("HistoricalConfigurationBrowseFailed",
      "browsing HasHistoricalConfiguration failed",
      "client.tier2.history_reader.configuration_browse",
      status)};
}

void append_history_configuration_targets(const ua::BrowseResult& result, std::vector<ua::NodeId>& targets)
{
  for (const auto& reference : result.references())
  {
    if (reference.node_id().is_local())
      targets.push_back(reference.node_id().node_id());
  }
}

/// Follows @p continuationPoint with BrowseNext until the HasHistoricalConfiguration targets are complete.
/// @p answered is the code the pages so far answered (each page's ServiceResult and BrowseResult status
/// combined, @ref ua::detail::combined_status); the list is delivered with it, so a Good subcode or an
/// Uncertain code of any page reaches the caller.
void drain_history_configurations(std::shared_ptr<detail::WireOps> lockedWireOps,
  std::shared_ptr<std::vector<ua::NodeId>> targets, ua::ContinuationPoint continuationPoint,
  ua::StatusCode answered, std::function<void(NodeListResult)> callback,
  std::shared_ptr<detail::BrowseDrainGuard> guard = {})
{
  if (!guard)
  {
    guard = std::make_shared<detail::BrowseDrainGuard>(
      "client.history.configuration_browse", detail::BrowseDrainLimits{}, targets->size());
  }
  ua::BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().push_back(std::move(continuationPoint));
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_next_async(std::move(request),
    [lockedWireOps = std::move(lockedWireOps),
      targets = std::move(targets),
      answered = std::move(answered),
      callback = std::move(callback),
      guard](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      if (!response.has_value())
      {
        callback(history_browse_failure(response.status_code(), response.shared_detail()));
        return;
      }
      const auto serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(history_browse_failure(serviceResult));
        return;
      }
      auto& results = response.value().results();
      if (results.size() != 1 || results[0].status_code().is_bad())
      {
        callback(history_browse_failure(
          results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code()));
        return;
      }
      // CL-VIEW-005: the page is admitted before its references are kept; a self-loop or an exhausted
      // budget ends the drain (a budget refusal releases the server's continuation point best-effort).
      if (auto admitted = guard->admit_page(results[0]); admitted.is_bad())
      {
        ua::client::detail::release_continuation_point_best_effort(
          *lockedWireOps, results[0].continuation_point());
        callback(history_browse_failure(admitted.status_code(), admitted.shared_detail()));
        return;
      }
      append_history_configuration_targets(results[0], *targets);
      answered = ua::detail::combined_status(
        answered, ua::detail::combined_status(serviceResult, results[0].status_code()));
      if (!results[0].continuation_point().empty())
      {
        drain_history_configurations(std::move(lockedWireOps),
          std::move(targets),
          results[0].continuation_point(),
          std::move(answered),
          std::move(callback),
          guard);
        return;
      }
      callback(ua::detail::held(std::move(*targets), std::move(answered)));
    });
}

/// Posts @p result to @p executor for a cursor callback (callbacks always run on the executor); inline when
/// no executor is set (a moved-from facade).
void deliver_cursor(const boost::asio::any_io_executor& executor, std::function<void(CursorResult)> callback,
  CursorResult result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Posts @p result to @p executor for an update callback.
void deliver_update(const boost::asio::any_io_executor& executor, std::function<void(UpdateResult)> callback,
  UpdateResult result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Extracts the `DataValue` page from a `HistoryReadResult` (both `HistoryData` and the derived
/// `HistoryModifiedData` expose `data_values()`).
std::vector<ua::DataValue> extract_page(const ua::HistoryReadResult& result)
{
  if (const auto* data = dynamic_cast<const ua::HistoryData*>(result.history_data().get()))
  {
    return data->data_values().payload();
  }
  return {};
}

/// The count of specified `{start, end, count}` fields  -  the CL-HIST-003 pre-flight input.
int specified_count(const TimeRange& range)
{
  return (range.start_specified() ? 1 : 0) + (range.end_specified() ? 1 : 0) +
         (range.count_specified() ? 1 : 0);
}

/// Applies the range's start/end/count to a Raw/Modified details (unspecified fields carry the null / zero
/// sentinel the server reads as "unspecified").
void apply_range(ua::ReadRawModifiedDetails& details, const TimeRange& range)
{
  details.start_time() = range.startTime;
  details.end_time() = range.endTime;
  details.num_values_per_node() = range.numValuesPerNode;
}

/// The single funnel every `HistoryUpdater` method goes through: locks the interface, dispatches the update
/// carrying @p details, and decodes the first per-node result into a @ref HistoryUpdateResult. Static-shaped
/// (a free function): it captures only value copies, never the facade handle.
void issue_update(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
  std::unique_ptr<ua::Structure> details, std::optional<std::size_t> expectedOperationResults,
  std::function<void(UpdateResult)> callback) noexcept
{
  auto lockedWireOps = wireOps.lock();
  if (!lockedWireOps)
  {
    deliver_update(executor,
      std::move(callback),
      UpdateResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("HistoryUpdateConnectionGone",
          "the Connection was dropped before the history update could be issued",
          std::string{goneSource})});
    return;
  }

  ua::HistoryUpdateRequest request;
  ua::RefStructure<ua::Structure> wrapped;
  wrapped = std::unique_ptr<ua::Structure>(std::move(details));
  request.history_update_details().push_back(std::move(wrapped));

  lockedWireOps->history_update_async(std::move(request),
    [executor, expectedOperationResults, callback = std::move(callback)](
      ua::Result<ua::HistoryUpdateResponse> response) mutable
    {
      if (!response.has_value())
      {
        // Single-wrap: propagate the funnel's service-level ErrorDetail unchanged.
        deliver_update(
          executor, std::move(callback), UpdateResult{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten: the tier-0 funnel returns the HistoryUpdateResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below) and a non-empty results[] silently returns Good.
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver_update(executor,
          std::move(callback),
          UpdateResult{serviceResult,
            ua::make_error_detail("HistoryUpdateServiceFault",
              "the server returned a service-level fault for the history update",
              std::string{updateSource},
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver_update(executor,
          std::move(callback),
          UpdateResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail("HistoryUpdateEmptyResults",
              "the server returned a Good HistoryUpdate response with no result for the single node",
              std::string{updateSource})});
        return;
      }
      // Two-layer: the per-node statusCode and per-entry operationResults ride through VERBATIM inside a GOOD
      // outer Result  -  a per-node / per-entry Bad is value-quality, not a service failure
      // (CL-HIST-021/-023).
      const ua::HistoryUpdateResult& wire = results[0];
      std::vector<ua::StatusCode> operationResults = wire.operation_results().payload();
      // CL-HIST-021 / section 8.9.6: for an UpdateData* call the server must return one operationResult per
      // updateValue. A length mismatch is a protocol defect (not value quality) and surfaces a bad
      // Result<HistoryUpdateResult>. The check is gated on a non-bad per-node statusCode: a per-node Bad
      // means the node's action was rejected wholesale, so a short/empty operationResults is expected and
      // must ride through as value quality (CL-HIST-021), not be promoted to a service failure.
      if (expectedOperationResults && !wire.status_code().is_bad() &&
          operationResults.size() != *expectedOperationResults)
      {
        deliver_update(executor,
          std::move(callback),
          UpdateResult{ua::StatusCode{ua::Status::BadUnexpectedError,
            ua::ErrorDetail::build("HistoryUpdateResultLengthMismatch",
              "The operationResults length does not match the number of updateValues sent",
              std::string{resultLengthMismatchSource})
              .context(ua::ContextKeys::sizeActual, operationResults.size())
              .context(ua::ContextKeys::sizeExpected, *expectedOperationResults)}});
        return;
      }
      HistoryUpdateResult decoded;
      decoded.statusCode = wire.status_code();
      decoded.operationResults = std::move(operationResults);
      decoded.diagnosticInfos = wire.diagnostic_infos().payload();
      // The ServiceResult is the status of the outer Result, so a Good subcode or an Uncertain code of it
      // reaches the caller beside the per-node statusCode.
      deliver_update(executor, std::move(callback), ua::detail::held(std::move(decoded), serviceResult));
    });
}

}  // namespace

HistoryFacade::HistoryFacade(
  std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor, ua::Logger logger)
  : mWireOps(std::move(wireOps)), mExecutor(std::move(executor)), mLogger(std::move(logger)),
    mAttributeProbeCache(std::make_shared<AttributeProbeCache>())
{}

HistoryReadCursor HistoryFacade::make_cursor(std::shared_ptr<detail::HistoryReadCursorState> state)
{
  return HistoryReadCursor{std::move(state)};
}

void HistoryFacade::issue_read(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
  ua::Logger logger, ua::NodeId node, std::unique_ptr<ua::Structure> details,
  ua::TimestampsToReturn timestampsToReturn, ContinuationLimits continuationLimits,
  std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept
{
  auto lockedWireOps = wireOps.lock();
  if (!lockedWireOps)
  {
    deliver_cursor(executor,
      std::move(callback),
      CursorResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("HistoryReadConnectionGone",
          "the Connection was dropped before the history read could be issued",
          std::string{goneSource})});
    return;
  }

  // Snapshot the details so the cursor can re-send them VERBATIM on each continuation (CL-HIST-013); the
  // request gets a deep clone (RefStructure copy) so moving the request does not steal the snapshot.
  ua::RefStructure<ua::Structure> detailsSnapshot;
  detailsSnapshot = std::unique_ptr<ua::Structure>(std::move(details));

  ua::HistoryReadRequest request;
  request.history_read_details() = detailsSnapshot;
  request.timestamps_to_return() = timestampsToReturn;
  request.release_continuation_points() = false;
  ua::HistoryReadValueId valueId;
  valueId.node_id() = node;
  request.nodes_to_read().push_back(std::move(valueId));

  lockedWireOps->history_read_async(std::move(request),
    [wireOps,
      executor,
      logger = std::move(logger),
      node = std::move(node),
      timestampsToReturn,
      continuationLimits,
      detailsSnapshot = std::move(detailsSnapshot),
      callback = std::move(callback)](ua::Result<ua::HistoryReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        // Single-wrap: propagate the funnel's service-level ErrorDetail unchanged.
        deliver_cursor(
          executor, std::move(callback), CursorResult{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten: the tier-0 funnel returns the HistoryReadResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below) and a non-empty results[] silently returns a cursor.
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver_cursor(executor,
          std::move(callback),
          CursorResult{serviceResult,
            ua::make_error_detail("HistoryReadServiceFault",
              "the server returned a service-level fault in the HistoryRead response header",
              std::string{readSource},
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver_cursor(executor,
          std::move(callback),
          CursorResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail("HistoryReadEmptyResults",
              "the server returned a Good HistoryRead response with no result for the single node",
              std::string{readSource})});
        return;
      }
      const ua::HistoryReadResult& result = results[0];
      if (result.status_code().is_bad())
      {
        // CL-HIST-014: a rejected per-call AggregateConfiguration is surfaced with a dedicated source + a
        // remediation hint (retry with useServerCapabilitiesDefaults=true to fall back to the server's
        // configured defaults). Only a processed read can produce this status, so the shared per-node mapping
        // below stays generic for every other bad status.
        if (result.status_code().as_status() == ua::Status::BadAggregateConfigurationRejected)
        {
          deliver_cursor(executor,
            std::move(callback),
            CursorResult{result.status_code(),
              ua::make_error_detail("HistoryReadAggregateConfigRejected",
                "the server rejected the per-call AggregateConfiguration; retry with "
                "useServerCapabilitiesDefaults=true to fall back to the server's configured aggregate "
                "defaults",
                std::string{aggregateConfigRejectedSource})});
          return;
        }
        // A whole-node failure (Bad_NoData / Bad_BoundNotSupported / ...): the read yields NO cursor
        // (CL-HIST-011). A Good_NoData per-node status is NOT bad, so it falls through to an empty cursor.
        deliver_cursor(executor,
          std::move(callback),
          CursorResult{result.status_code(),
            ua::make_error_detail("HistoryReadNodeBad",
              "the server returned a bad per-node history status",
              std::string{readSource})});
        return;
      }

      // The read's code: the ServiceResult and the per-node statusCode combined, so a Good subcode
      // (Good_NoData, Good_MoreData) or an Uncertain code of either reaches the caller on the cursor's
      // Result and on the first page.
      const ua::StatusCode answered = ua::detail::combined_status(serviceResult, result.status_code());
      auto state = std::make_shared<detail::HistoryReadCursorState>();
      state->wireOps = wireOps;
      state->executor = executor;
      state->logger = std::move(logger);
      state->nodeId = std::move(node);
      state->details = std::move(detailsSnapshot);
      state->timestampsToReturn = timestampsToReturn;
      state->firstPage = extract_page(result);
      state->firstPageStatus = answered;
      state->firstPagePending = true;  // delivered by the first next_async (empty for Good_NoData)
      state->continuationPoint = result.continuation_point();
      state->continuationLimits = continuationLimits;
      deliver_cursor(
        executor, std::move(callback), ua::detail::held(make_cursor(std::move(state)), answered));
    });
}

// ============ Reads ============

void HistoryFacade::read_raw_async(ua::NodeId node, TimeRange range, HistoryReadOptions options,
  std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept
{
  if (specified_count(range) < 2)
  {
    // CL-HIST-003: Raw/Modified need at least two of {start, end, count}. Reject before any wire round-trip.
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidArgument,
        ua::make_error_detail("HistoryReadInvalidTimeRange",
          "a raw history read requires at least two of {startTime, endTime, numValuesPerNode}",
          std::string{invalidRangeSource})});
    return;
  }
  if (options.timestampsToReturn == ua::TimestampsToReturn::Neither)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidTimestampArgument,
        ua::make_error_detail("HistoryReadTimestampsNeither",
          "timestampsToReturn=Neither is invalid for a history read",
          std::string{timestampsSource})});
    return;
  }
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->is_read_modified() = false;
  apply_range(*details, range);
  details->return_bounds() = options.returnBounds;
  issue_read(mWireOps,
    mExecutor,
    mLogger,
    std::move(node),
    std::move(details),
    options.timestampsToReturn,
    options.continuationLimits,
    std::move(callback));
}

void HistoryFacade::is_history_capable_async(
  ua::NodeId node, std::function<void(ua::Result<bool>)> callback) noexcept
{
  {
    const std::scoped_lock lock{mAttributeProbeCache->mutex};
    const auto cached = mAttributeProbeCache->historyReadable.find(node);
    if (cached != mAttributeProbeCache->historyReadable.end())
    {
      const bool capable = cached->second;
      boost::asio::post(mExecutor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback), capable]() mutable { callback(ua::Result<bool>{capable}); }));
      return;
    }
  }

  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{},
        [callback = std::move(callback)]() mutable
        {
          callback(ua::Result<bool>{ua::Status::BadConnectionClosed,
            ua::make_error_detail("HistoryCapabilityConnectionGone",
              "the Connection was dropped before AccessLevel could be read",
              "client.tier2.history_reader.capability_probe")});
        }));
    return;
  }

  ua::ReadRequest request;
  ua::ReadValueId target;
  target.node_id() = node;
  target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::AccessLevel);
  request.nodes_to_read().push_back(std::move(target));

  const auto cache = mAttributeProbeCache;
  const auto executor = mExecutor;
  lockedWireOps->read_async(std::move(request),
    [cache, executor, node = std::move(node), callback = std::move(callback)](
      ua::Result<ua::ReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback),
              status = response.status_code(),
              detail = response.shared_detail()]() mutable
            { callback(ua::Result<bool>{status, std::move(detail)}); }));
        return;
      }
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), serviceResult]() mutable
            {
              callback(ua::Result<bool>{serviceResult,
                ua::make_error_detail("HistoryCapabilityReadServiceFault",
                  "the server returned a service-level fault while reading AccessLevel",
                  "client.tier2.history_reader.capability_probe",
                  serviceResult)});
            }));
        return;
      }
      if (response.value().results().size() != 1)
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback)]() mutable
            {
              callback(ua::Result<bool>{ua::Status::BadUnexpectedError,
                ua::make_error_detail("HistoryCapabilityReadResultCount",
                  "the AccessLevel Read did not return exactly one result",
                  "client.tier2.history_reader.capability_probe")});
            }));
        return;
      }
      const ua::DataValue& value = response.value().results()[0];
      // The answer's code: the ServiceResult and the AccessLevel's status combined, so a Good subcode or an
      // Uncertain code of either reaches the caller with the flag.
      const ua::StatusCode answered =
        ua::detail::combined_status(serviceResult, value.status().value_or(ua::StatusCode{ua::Status::Good}));
      if (answered.is_bad())
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), status = answered]() mutable
            {
              callback(ua::Result<bool>{status,
                ua::make_error_detail("HistoryCapabilityAccessLevelBad",
                  "the server returned a bad status for the AccessLevel Attribute",
                  "client.tier2.history_reader.capability_probe",
                  status)});
            }));
        return;
      }
      if (answered.is_uncertain() && value.value().empty())
      {
        // An Uncertain answer without an AccessLevel: the code is the answer, with no flag.
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), status = answered]() mutable
            { callback(ua::Result<bool>{status}); }));
        return;
      }
      const auto* accessLevel = value.value().try_as<std::uint8_t>();
      if (accessLevel == nullptr)
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback)]() mutable
            {
              callback(ua::Result<bool>{ua::Status::BadTypeMismatch,
                ua::make_error_detail("HistoryCapabilityAccessLevelType",
                  "the AccessLevel Attribute was not encoded as Byte",
                  "client.tier2.history_reader.capability_probe")});
            }));
        return;
      }
      const bool capable = (*accessLevel & (std::uint8_t{1} << static_cast<std::uint8_t>(
                                              ua::AccessLevelType::Bit::HistoryRead))) != 0;
      // Only a plain Good answer is cached: a later call answered from the cache reports plain Good, which
      // would replace a Good subcode or an Uncertain code the server gave.
      if (answered.as_status() == ua::Status::Good)
      {
        const std::scoped_lock lock{cache->mutex};
        cache->historyReadable.insert_or_assign(node, capable);
      }
      boost::asio::post(executor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback), capable, answered]() mutable
          { callback(ua::detail::held(capable, answered)); }));
    });
}

void HistoryFacade::is_history_writable_async(
  ua::NodeId node, std::function<void(ua::Result<bool>)> callback) noexcept
{
  {
    const std::scoped_lock lock{mAttributeProbeCache->mutex};
    const auto cached = mAttributeProbeCache->historyWritable.find(node);
    if (cached != mAttributeProbeCache->historyWritable.end())
    {
      const bool writable = cached->second;
      boost::asio::post(mExecutor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback), writable]() mutable { callback(ua::Result<bool>{writable}); }));
      return;
    }
  }
  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{},
        [callback = std::move(callback)]() mutable
        {
          callback(ua::Result<bool>{ua::Status::BadConnectionClosed,
            ua::make_error_detail("HistoryWritableConnectionGone",
              "the Connection was dropped before AccessLevel could be read",
              "client.tier2.history_updater.history_write_probe")});
        }));
    return;
  }
  ua::ReadRequest request;
  ua::ReadValueId target;
  target.node_id() = node;
  target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::AccessLevel);
  request.nodes_to_read().push_back(std::move(target));
  const auto cache = mAttributeProbeCache;
  const auto executor = mExecutor;
  lockedWireOps->read_async(std::move(request),
    [cache, executor, node = std::move(node), callback = std::move(callback)](
      ua::Result<ua::ReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback),
              status = response.status_code(),
              detail = response.shared_detail()]() mutable
            { callback(ua::Result<bool>{status, std::move(detail)}); }));
        return;
      }
      const auto serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad() || response.value().results().size() != 1)
      {
        const auto status =
          serviceResult.is_bad() ? serviceResult : ua::StatusCode{ua::Status::BadUnexpectedError};
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), status]() mutable
            {
              callback(ua::Result<bool>{status,
                ua::make_error_detail("HistoryWritableReadFailed",
                  "the AccessLevel Read returned a service fault or invalid result count",
                  "client.tier2.history_updater.history_write_probe",
                  status)});
            }));
        return;
      }
      const ua::DataValue& value = response.value().results()[0];
      // The answer's code: the ServiceResult and the AccessLevel's status combined, so a Good subcode or an
      // Uncertain code of either reaches the caller with the flag.
      const ua::StatusCode answered =
        ua::detail::combined_status(serviceResult, value.status().value_or(ua::StatusCode{ua::Status::Good}));
      if (answered.is_bad())
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), status = answered]() mutable
            {
              callback(ua::Result<bool>{status,
                ua::make_error_detail("HistoryWritableAccessLevelBad",
                  "the server returned a bad status for the AccessLevel Attribute",
                  "client.tier2.history_updater.history_write_probe",
                  status)});
            }));
        return;
      }
      if (answered.is_uncertain() && value.value().empty())
      {
        // An Uncertain answer without an AccessLevel: the code is the answer, with no flag.
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), status = answered]() mutable
            { callback(ua::Result<bool>{status}); }));
        return;
      }
      const auto* accessLevel = value.value().try_as<std::uint8_t>();
      if (accessLevel == nullptr)
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback)]() mutable
            {
              callback(ua::Result<bool>{ua::Status::BadTypeMismatch,
                ua::make_error_detail("HistoryWritableAccessLevelType",
                  "the AccessLevel Attribute was not encoded as Byte",
                  "client.tier2.history_updater.history_write_probe")});
            }));
        return;
      }
      const bool writable = ua::AccessLevelType{*accessLevel}.test(ua::AccessLevelType::Bit::HistoryWrite);
      // Only a plain Good answer is cached: a later call answered from the cache reports plain Good, which
      // would replace a Good subcode or an Uncertain code the server gave.
      if (answered.as_status() == ua::Status::Good)
      {
        const std::scoped_lock lock{cache->mutex};
        cache->historyWritable.insert_or_assign(node, writable);
      }
      boost::asio::post(executor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback), writable, answered]() mutable
          { callback(ua::detail::held(writable, answered)); }));
    });
}

void HistoryFacade::historical_configurations_async(
  ua::NodeId historicalDataNode, std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{},
        [callback = std::move(callback)]() mutable
        { callback(history_browse_failure(ua::Status::BadConnectionClosed)); }));
    return;
  }

  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = std::move(historicalDataNode);
  browseDescription.browse_direction() = ua::BrowseDirection::Forward;
  browseDescription.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasHistoricalConfiguration};
  browseDescription.include_subtypes() = true;
  browseDescription.node_class_mask() = static_cast<std::uint32_t>(ua::NodeClass::Object);
  browseDescription.result_mask() = static_cast<std::uint32_t>(ua::BrowseResultMask::TargetInfo);
  ua::BrowseRequest request;
  request.nodes_to_browse().push_back(std::move(browseDescription));
  const auto executor = mExecutor;
  lockedWireOps->browse_async(std::move(request),
    [lockedWireOps = std::move(lockedWireOps), executor, callback = std::move(callback)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      if (!response.has_value())
      {
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback),
              result = history_browse_failure(response.status_code(), response.shared_detail())]() mutable
            { callback(std::move(result)); }));
        return;
      }
      const auto serviceResult = response.value().response_header().service_result();
      auto& results = response.value().results();
      if (serviceResult.is_bad() || results.size() != 1 || results[0].status_code().is_bad())
      {
        const auto status =
          serviceResult.is_bad()
            ? serviceResult
            : (results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code());
        boost::asio::post(executor,
          ua::async::guarded(ua::Logger{},
            [callback = std::move(callback), result = history_browse_failure(status)]() mutable
            { callback(std::move(result)); }));
        return;
      }
      auto targets = std::make_shared<std::vector<ua::NodeId>>();
      append_history_configuration_targets(results[0], *targets);
      // The ServiceResult and the BrowseResult status combined: a Good subcode or an Uncertain code of either
      // is the status of the Result holding the list.
      ua::StatusCode answered = ua::detail::combined_status(serviceResult, results[0].status_code());
      if (!results[0].continuation_point().empty())
      {
        drain_history_configurations(std::move(lockedWireOps),
          std::move(targets),
          results[0].continuation_point(),
          std::move(answered),
          [executor, callback = std::move(callback)](NodeListResult result) mutable
          {
            boost::asio::post(executor,
              ua::async::guarded(ua::Logger{},
                [callback = std::move(callback), result = std::move(result)]() mutable
                { callback(std::move(result)); }));
          });
        return;
      }
      boost::asio::post(executor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback),
            targets = std::move(targets),
            answered = std::move(answered)]() mutable
          { callback(ua::detail::held(std::move(*targets), std::move(answered))); }));
    });
}

void HistoryFacade::preflight_update_async(
  ua::NodeId node, UpdateCapability capability, std::function<void(ua::VoidResult)> callback) noexcept
{
  const auto cache = mAttributeProbeCache;
  const auto executor = mExecutor;
  const auto capabilityName = [capability]() -> std::string_view
  {
    switch (capability)
    {
    case UpdateCapability::InsertData:
      return "InsertDataCapability";
    case UpdateCapability::ReplaceData:
      return "ReplaceDataCapability";
    case UpdateCapability::UpdateData:
      return "UpdateDataCapability";
    case UpdateCapability::DeleteRaw:
      return "DeleteRawCapability";
    case UpdateCapability::DeleteAtTime:
      return "DeleteAtTimeCapability";
    }
    return "UnknownCapability";
  };
  auto finishFromCapabilities = [cache, executor, capability, capabilityName = std::string{capabilityName()}](
                                  std::function<void(ua::VoidResult)> completion) mutable
  {
    bool supported = false;
    {
      const std::scoped_lock lock{cache->mutex};
      const auto& capabilities = *cache->serverCapabilities;
      switch (capability)
      {
      case UpdateCapability::InsertData:
        supported = capabilities.insertData;
        break;
      case UpdateCapability::ReplaceData:
        supported = capabilities.replaceData;
        break;
      case UpdateCapability::UpdateData:
        supported = capabilities.updateData;
        break;
      case UpdateCapability::DeleteRaw:
        supported = capabilities.deleteRaw;
        break;
      case UpdateCapability::DeleteAtTime:
        supported = capabilities.deleteAtTime;
        break;
      }
    }
    boost::asio::post(executor,
      ua::async::guarded(ua::Logger{},
        [completion = std::move(completion), supported, capabilityName = std::move(capabilityName)]() mutable
        {
          if (supported)
          {
            completion(ua::VoidResult{});
            return;
          }
          completion(ua::VoidResult{ua::StatusCode{ua::Status::BadHistoryOperationUnsupported,
            ua::ErrorDetail::build("HistoryUpdateCapabilityMissing",
              "The required HistoryServerCapabilities capability is disabled",
              "client.tier2.history_updater.capability_preflight")
              .context(ua::ContextKeys::fieldName, capabilityName)
              .context(ua::ContextKeys::actual, false)}});
        }));
  };

  is_history_writable_async(std::move(node),
    [wireOps = mWireOps,
      cache,
      executor,
      finish = std::move(finishFromCapabilities),
      callback = std::move(callback)](ua::Result<bool> writable) mutable
    {
      // The preflight acts on the flag itself, so only a Good answer is used; an Uncertain one is refused.
      if (!writable.is_good())
      {
        callback(ua::VoidResult{detail::answer_refused(writable.status_code(),
          "ReadAnswerUncertain",
          "client.tier2.history_updater.history_write_preflight")});
        return;
      }
      if (!writable.value())
      {
        callback(ua::VoidResult{ua::Status::BadHistoryOperationUnsupported,
          ua::make_error_detail("HistoryWriteNotAdvertised",
            "AccessLevel.HistoryWrite is not set on the target Variable",
            "client.tier2.history_updater.history_write_preflight")});
        return;
      }
      bool capabilitiesCached = false;
      bool startCapabilitiesLoad = false;
      {
        const std::scoped_lock lock{cache->mutex};
        capabilitiesCached = cache->serverCapabilities.has_value();
        if (!capabilitiesCached)
        {
          cache->serverCapabilitiesWaiters.push_back(
            [finish = std::move(finish), callback = std::move(callback)](ua::VoidResult loaded) mutable
            {
              if (!loaded.is_good())
              {
                callback(ua::VoidResult{loaded.status_code(), loaded.shared_detail()});
                return;
              }
              finish(std::move(callback));
            });
          if (!cache->serverCapabilitiesLoading)
          {
            cache->serverCapabilitiesLoading = true;
            startCapabilitiesLoad = true;
          }
        }
      }
      if (capabilitiesCached)
      {
        finish(std::move(callback));
        return;
      }
      if (!startCapabilitiesLoad)
        return;
      auto lockedWireOps = wireOps.lock();
      if (!lockedWireOps)
      {
        complete_capability_waiters(cache,
          ua::VoidResult{ua::Status::BadConnectionClosed,
            ua::make_error_detail("HistoryCapabilitiesConnectionGone",
              "the Connection was dropped before HistoryServerCapabilities could be read",
              "client.tier2.history_updater.capability_preflight")});
        return;
      }
      const std::array capabilityNodes{ua::VariableId::HistoryServerCapabilities_InsertDataCapability,
        ua::VariableId::HistoryServerCapabilities_ReplaceDataCapability,
        ua::VariableId::HistoryServerCapabilities_UpdateDataCapability,
        ua::VariableId::HistoryServerCapabilities_DeleteRawCapability,
        ua::VariableId::HistoryServerCapabilities_DeleteAtTimeCapability};
      ua::ReadRequest request;
      for (const auto capabilityNode : capabilityNodes)
      {
        ua::ReadValueId target;
        target.node_id() = ua::NodeId{capabilityNode};
        target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
        request.nodes_to_read().push_back(std::move(target));
      }
      lockedWireOps->read_async(std::move(request),
        [cache](ua::Result<ua::ReadResponse> response)
        {
          // The preflight acts on these flags itself, so only a Good answer is used: an Uncertain
          // ServiceResult or flag status is refused (ReadAnswerUncertain), as a Bad one fails the preflight.
          constexpr std::string_view capabilitySource = "client.tier2.history_updater.capability_preflight";
          if (!response.is_good())
          {
            complete_capability_waiters(cache,
              ua::VoidResult{
                detail::answer_refused(response.status_code(), "ReadAnswerUncertain", capabilitySource)});
            return;
          }
          const auto serviceResult = response.value().response_header().service_result();
          if (serviceResult.is_uncertain())
          {
            complete_capability_waiters(cache,
              ua::VoidResult{
                detail::uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", capabilitySource)});
            return;
          }
          if (serviceResult.is_bad() || response.value().results().size() != 5)
          {
            const auto status =
              serviceResult.is_bad() ? serviceResult : ua::StatusCode{ua::Status::BadUnexpectedError};
            complete_capability_waiters(cache,
              ua::VoidResult{status,
                ua::make_error_detail("HistoryCapabilitiesReadFailed",
                  "the HistoryServerCapabilities Read returned a service fault or invalid result count",
                  "client.tier2.history_updater.capability_preflight",
                  status)});
            return;
          }
          AttributeProbeCache::ServerCapabilities decoded;
          bool* outputs[] = {&decoded.insertData,
            &decoded.replaceData,
            &decoded.updateData,
            &decoded.deleteRaw,
            &decoded.deleteAtTime};
          for (std::size_t index = 0; index < response.value().results().size(); ++index)
          {
            const auto& value = response.value().results()[index];
            if (value.status().has_value() && value.status()->is_uncertain())
            {
              complete_capability_waiters(cache,
                ua::VoidResult{detail::uncertain_answer_refused(
                  *value.status(), "ReadAnswerUncertain", capabilitySource)});
              return;
            }
            if ((value.status().has_value() && value.status()->is_bad()) ||
                value.value().try_as<bool>() == nullptr)
            {
              const auto status = value.status().has_value() && value.status()->is_bad()
                                    ? *value.status()
                                    : ua::StatusCode{ua::Status::BadTypeMismatch};
              complete_capability_waiters(cache,
                ua::VoidResult{status,
                  ua::make_error_detail("HistoryCapabilityValueInvalid",
                    "a HistoryServerCapabilities flag was bad or was not encoded as Boolean",
                    "client.tier2.history_updater.capability_preflight",
                    status)});
              return;
            }
            *outputs[index] = *value.value().try_as<bool>();
          }
          {
            const std::scoped_lock lock{cache->mutex};
            cache->serverCapabilities = decoded;
          }
          complete_capability_waiters(cache, ua::VoidResult{});
        });
    });
}

void HistoryFacade::read_modified_async(ua::NodeId node, TimeRange range, HistoryReadOptions options,
  std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept
{
  if (specified_count(range) < 2)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidArgument,
        ua::make_error_detail("HistoryReadInvalidTimeRange",
          "a modified history read requires at least two of {startTime, endTime, numValuesPerNode}",
          std::string{invalidRangeSource})});
    return;
  }
  if (options.timestampsToReturn == ua::TimestampsToReturn::Neither)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidTimestampArgument,
        ua::make_error_detail("HistoryReadTimestampsNeither",
          "timestampsToReturn=Neither is invalid for a history read",
          std::string{timestampsSource})});
    return;
  }
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->is_read_modified() = true;
  apply_range(*details, range);
  details->return_bounds() = false;  // CL-HIST-007: Modified hard-codes returnBounds=false
  issue_read(mWireOps,
    mExecutor,
    mLogger,
    std::move(node),
    std::move(details),
    options.timestampsToReturn,
    options.continuationLimits,
    std::move(callback));
}

void HistoryFacade::read_at_time_async(ua::NodeId node, std::vector<ua::DateTime> requestedTimes,
  HistoryReadOptions options, std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept
{
  if (options.timestampsToReturn == ua::TimestampsToReturn::Neither)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidTimestampArgument,
        ua::make_error_detail("HistoryReadTimestampsNeither",
          "timestampsToReturn=Neither is invalid for a history read",
          std::string{timestampsSource})});
    return;
  }
  auto details = std::make_unique<ua::ReadAtTimeDetails>();
  for (auto& time : requestedTimes)
  {
    details->req_times().push_back(time);  // CL-HIST-016: positional order preserved
  }
  issue_read(mWireOps,
    mExecutor,
    mLogger,
    std::move(node),
    std::move(details),
    options.timestampsToReturn,
    options.continuationLimits,
    std::move(callback));
}

void HistoryFacade::read_processed_async(ua::NodeId node, TimeRange range, ua::NodeId aggregateType,
  ua::Duration processingInterval, HistoryReadOptions options,
  std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept
{
  // CL-HIST-004: Processed needs start AND end, and start != end. Reverse order is accepted (server
  // reverses).
  if (!range.start_specified() || !range.end_specified() || range.startTime == range.endTime)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidArgument,
        ua::make_error_detail("HistoryReadProcessedInvalidRange",
          "a processed history read requires startTime, endTime (start != end) and a processingInterval",
          std::string{invalidRangeSource})});
    return;
  }
  if (options.timestampsToReturn == ua::TimestampsToReturn::Neither)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidTimestampArgument,
        ua::make_error_detail("HistoryReadTimestampsNeither",
          "timestampsToReturn=Neither is invalid for a history read",
          std::string{timestampsSource})});
    return;
  }
  auto details = std::make_unique<ua::ReadProcessedDetails>();
  details->start_time() = range.startTime;
  details->end_time() = range.endTime;
  details->processing_interval() = processingInterval;
  details->aggregate_type().push_back(std::move(aggregateType));  // CL-HIST-005: single aggregate per call
  // CL-HIST-014: plumb a per-call AggregateConfiguration override verbatim when supplied; otherwise defer to
  // the server's configured defaults (useServerCapabilitiesDefaults=true makes the other fields inert).
  if (options.aggregateConfiguration.has_value())
  {
    details->aggregate_configuration() = *options.aggregateConfiguration;
  }
  else
  {
    details->aggregate_configuration().use_server_capabilities_defaults() = true;
  }
  issue_read(mWireOps,
    mExecutor,
    mLogger,
    std::move(node),
    std::move(details),
    options.timestampsToReturn,
    options.continuationLimits,
    std::move(callback));
}

void HistoryFacade::read_annotations_async(ua::NodeId node, std::vector<ua::DateTime> requestedTimes,
  HistoryReadOptions options, std::function<void(ua::Result<HistoryReadCursor>)> callback) noexcept
{
  if (options.timestampsToReturn == ua::TimestampsToReturn::Neither)
  {
    deliver_cursor(mExecutor,
      std::move(callback),
      CursorResult{ua::Status::BadInvalidTimestampArgument,
        ua::make_error_detail("HistoryReadTimestampsNeither",
          "timestampsToReturn=Neither is invalid for a history read",
          std::string{timestampsSource})});
    return;
  }
  // CL-HIST-015: read_annotations constructs ReadAnnotationDataDetails (NS0 i=659), NOT a Raw read against
  // the Annotations Property NodeId.
  auto details = std::make_unique<ua::ReadAnnotationDataDetails>();
  for (auto& time : requestedTimes)
  {
    details->req_times().push_back(time);
  }
  issue_read(mWireOps,
    mExecutor,
    mLogger,
    std::move(node),
    std::move(details),
    options.timestampsToReturn,
    options.continuationLimits,
    std::move(callback));
}

// ============ Writes / deletes ============

void HistoryFacade::update_data_async(ua::NodeId node, std::vector<ua::DataValue> values,
  ua::PerformUpdateType performType, std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept
{
  const auto capability = performType == ua::PerformUpdateType::Insert
                            ? UpdateCapability::InsertData
                            : (performType == ua::PerformUpdateType::Replace ? UpdateCapability::ReplaceData
                                                                             : UpdateCapability::UpdateData);
  const auto wireOps = mWireOps;
  const auto executor = mExecutor;
  const ua::NodeId probeNode = node;
  preflight_update_async(std::move(probeNode),
    capability,
    [wireOps,
      executor,
      node = std::move(node),
      values = std::move(values),
      performType,
      callback = std::move(callback)](ua::VoidResult preflight) mutable
    {
      if (!preflight.is_good())
      {
        callback(UpdateResult{preflight.status_code(), preflight.shared_detail()});
        return;
      }
      const std::size_t updateValueCount = values.size();
      auto details = std::make_unique<ua::UpdateDataDetails>();
      details->node_id() = std::move(node);
      details->perform_insert_replace() = performType;
      for (auto& value : values)
        details->update_values().push_back(std::move(value));
      issue_update(wireOps, executor, std::move(details), updateValueCount, std::move(callback));
    });
}

void HistoryFacade::insert_data_async(ua::NodeId node, std::vector<ua::DataValue> values,
  std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept
{
  update_data_async(std::move(node), std::move(values), ua::PerformUpdateType::Insert, std::move(callback));
}

void HistoryFacade::replace_data_async(ua::NodeId node, std::vector<ua::DataValue> values,
  std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept
{
  update_data_async(std::move(node), std::move(values), ua::PerformUpdateType::Replace, std::move(callback));
}

void HistoryFacade::delete_raw_modified_async(ua::NodeId node, TimeRange range, bool isDeleteModified,
  std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept
{
  // CL-HIST-022: delete requires both start AND end, with start <= end (equality permitted  -
  // single-timestamp delete). Reverse range is rejected locally (unlike read_processed  -  deletes have no
  // order axis).
  if (!range.start_specified() || !range.end_specified() || range.endTime < range.startTime)
  {
    deliver_update(mExecutor,
      std::move(callback),
      UpdateResult{ua::Status::BadInvalidArgument,
        ua::make_error_detail("HistoryDeleteInvalidRange",
          "delete_raw_modified requires startTime and endTime with startTime <= endTime",
          std::string{invalidRangeSource})});
    return;
  }
  const auto wireOps = mWireOps;
  const auto executor = mExecutor;
  const ua::NodeId probeNode = node;
  preflight_update_async(std::move(probeNode),
    UpdateCapability::DeleteRaw,
    [wireOps, executor, node = std::move(node), range, isDeleteModified, callback = std::move(callback)](
      ua::VoidResult preflight) mutable
    {
      if (!preflight.is_good())
      {
        callback(UpdateResult{preflight.status_code(), preflight.shared_detail()});
        return;
      }
      auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
      details->node_id() = std::move(node);
      details->is_delete_modified() = isDeleteModified;
      details->start_time() = range.startTime;
      details->end_time() = range.endTime;
      issue_update(wireOps, executor, std::move(details), std::nullopt, std::move(callback));
    });
}

void HistoryFacade::delete_at_time_async(ua::NodeId node, std::vector<ua::DateTime> requestedTimes,
  std::function<void(ua::Result<HistoryUpdateResult>)> callback) noexcept
{
  const auto wireOps = mWireOps;
  const auto executor = mExecutor;
  const ua::NodeId probeNode = node;
  preflight_update_async(std::move(probeNode),
    UpdateCapability::DeleteAtTime,
    [wireOps,
      executor,
      node = std::move(node),
      requestedTimes = std::move(requestedTimes),
      callback = std::move(callback)](ua::VoidResult preflight) mutable
    {
      if (!preflight.is_good())
      {
        callback(UpdateResult{preflight.status_code(), preflight.shared_detail()});
        return;
      }
      auto details = std::make_unique<ua::DeleteAtTimeDetails>();
      details->node_id() = std::move(node);
      for (auto& time : requestedTimes)
        details->req_times().push_back(time);
      issue_update(wireOps, executor, std::move(details), std::nullopt, std::move(callback));
    });
}

// ============ Sync / try_sync wrappers (section 7.0 triple) ============

HistoryReadCursor HistoryFacade::read_raw_sync(ua::NodeId node, TimeRange range, HistoryReadOptions options)
{
  return ua::detail::good_value(try_read_raw_sync(std::move(node), std::move(range), std::move(options)));
}

ua::Result<HistoryReadCursor> HistoryFacade::try_read_raw_sync(
  ua::NodeId node, TimeRange range, HistoryReadOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryReadCursor>>(mExecutor,
    [this, node = std::move(node), range = std::move(range), options = std::move(options)](
      auto completion) mutable
    { read_raw_async(std::move(node), std::move(range), std::move(options), std::move(completion)); });
}

HistoryReadCursor HistoryFacade::read_modified_sync(
  ua::NodeId node, TimeRange range, HistoryReadOptions options)
{
  return ua::detail::good_value(
    try_read_modified_sync(std::move(node), std::move(range), std::move(options)));
}

ua::Result<HistoryReadCursor> HistoryFacade::try_read_modified_sync(
  ua::NodeId node, TimeRange range, HistoryReadOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryReadCursor>>(mExecutor,
    [this, node = std::move(node), range = std::move(range), options = std::move(options)](
      auto completion) mutable
    { read_modified_async(std::move(node), std::move(range), std::move(options), std::move(completion)); });
}

HistoryReadCursor HistoryFacade::read_at_time_sync(
  ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options)
{
  return ua::detail::good_value(
    try_read_at_time_sync(std::move(node), std::move(requestedTimes), std::move(options)));
}

ua::Result<HistoryReadCursor> HistoryFacade::try_read_at_time_sync(
  ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryReadCursor>>(mExecutor,
    [this, node = std::move(node), requestedTimes = std::move(requestedTimes), options = std::move(options)](
      auto completion) mutable
    {
      read_at_time_async(
        std::move(node), std::move(requestedTimes), std::move(options), std::move(completion));
    });
}

HistoryReadCursor HistoryFacade::read_processed_sync(ua::NodeId node, TimeRange range,
  ua::NodeId aggregateType, ua::Duration processingInterval, HistoryReadOptions options)
{
  return ua::detail::good_value(try_read_processed_sync(
    std::move(node), std::move(range), std::move(aggregateType), processingInterval, std::move(options)));
}

ua::Result<HistoryReadCursor> HistoryFacade::try_read_processed_sync(ua::NodeId node, TimeRange range,
  ua::NodeId aggregateType, ua::Duration processingInterval, HistoryReadOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryReadCursor>>(mExecutor,
    [this,
      node = std::move(node),
      range = std::move(range),
      aggregateType = std::move(aggregateType),
      processingInterval,
      options = std::move(options)](auto completion) mutable
    {
      read_processed_async(std::move(node),
        std::move(range),
        std::move(aggregateType),
        processingInterval,
        std::move(options),
        std::move(completion));
    });
}

HistoryReadCursor HistoryFacade::read_annotations_sync(
  ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options)
{
  return ua::detail::good_value(
    try_read_annotations_sync(std::move(node), std::move(requestedTimes), std::move(options)));
}

ua::Result<HistoryReadCursor> HistoryFacade::try_read_annotations_sync(
  ua::NodeId node, std::vector<ua::DateTime> requestedTimes, HistoryReadOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryReadCursor>>(mExecutor,
    [this, node = std::move(node), requestedTimes = std::move(requestedTimes), options = std::move(options)](
      auto completion) mutable
    {
      read_annotations_async(
        std::move(node), std::move(requestedTimes), std::move(options), std::move(completion));
    });
}

bool HistoryFacade::is_history_capable_sync(ua::NodeId node)
{
  return ua::detail::good_value(try_is_history_capable_sync(std::move(node)));
}

ua::Result<bool> HistoryFacade::try_is_history_capable_sync(ua::NodeId node) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<bool>>(mExecutor,
    [this, node = std::move(node)](auto completion) mutable
    { is_history_capable_async(std::move(node), std::move(completion)); });
}

bool HistoryFacade::is_history_writable_sync(ua::NodeId node)
{
  return ua::detail::good_value(try_is_history_writable_sync(std::move(node)));
}

ua::Result<bool> HistoryFacade::try_is_history_writable_sync(ua::NodeId node) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<bool>>(mExecutor,
    [this, node = std::move(node)](auto completion) mutable
    { is_history_writable_async(std::move(node), std::move(completion)); });
}

std::vector<ua::NodeId> HistoryFacade::historical_configurations_sync(ua::NodeId historicalDataNode)
{
  return ua::detail::good_value(try_historical_configurations_sync(std::move(historicalDataNode)));
}

ua::Result<std::vector<ua::NodeId>> HistoryFacade::try_historical_configurations_sync(
  ua::NodeId historicalDataNode) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::NodeId>>>(mExecutor,
    [this, historicalDataNode = std::move(historicalDataNode)](auto completion) mutable
    { historical_configurations_async(std::move(historicalDataNode), std::move(completion)); });
}

HistoryUpdateResult HistoryFacade::update_data_sync(
  ua::NodeId node, std::vector<ua::DataValue> values, ua::PerformUpdateType performType)
{
  return ua::detail::good_value(try_update_data_sync(std::move(node), std::move(values), performType));
}

ua::Result<HistoryUpdateResult> HistoryFacade::try_update_data_sync(
  ua::NodeId node, std::vector<ua::DataValue> values, ua::PerformUpdateType performType) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryUpdateResult>>(mExecutor,
    [this, node = std::move(node), values = std::move(values), performType](auto completion) mutable
    { update_data_async(std::move(node), std::move(values), performType, std::move(completion)); });
}

HistoryUpdateResult HistoryFacade::insert_data_sync(ua::NodeId node, std::vector<ua::DataValue> values)
{
  return ua::detail::good_value(try_insert_data_sync(std::move(node), std::move(values)));
}

ua::Result<HistoryUpdateResult> HistoryFacade::try_insert_data_sync(
  ua::NodeId node, std::vector<ua::DataValue> values) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryUpdateResult>>(mExecutor,
    [this, node = std::move(node), values = std::move(values)](auto completion) mutable
    { insert_data_async(std::move(node), std::move(values), std::move(completion)); });
}

HistoryUpdateResult HistoryFacade::replace_data_sync(ua::NodeId node, std::vector<ua::DataValue> values)
{
  return ua::detail::good_value(try_replace_data_sync(std::move(node), std::move(values)));
}

ua::Result<HistoryUpdateResult> HistoryFacade::try_replace_data_sync(
  ua::NodeId node, std::vector<ua::DataValue> values) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryUpdateResult>>(mExecutor,
    [this, node = std::move(node), values = std::move(values)](auto completion) mutable
    { replace_data_async(std::move(node), std::move(values), std::move(completion)); });
}

HistoryUpdateResult HistoryFacade::delete_raw_modified_sync(
  ua::NodeId node, TimeRange range, bool isDeleteModified)
{
  return ua::detail::good_value(
    try_delete_raw_modified_sync(std::move(node), std::move(range), isDeleteModified));
}

ua::Result<HistoryUpdateResult> HistoryFacade::try_delete_raw_modified_sync(
  ua::NodeId node, TimeRange range, bool isDeleteModified) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryUpdateResult>>(mExecutor,
    [this, node = std::move(node), range = std::move(range), isDeleteModified](auto completion) mutable {
      delete_raw_modified_async(std::move(node), std::move(range), isDeleteModified, std::move(completion));
    });
}

HistoryUpdateResult HistoryFacade::delete_at_time_sync(
  ua::NodeId node, std::vector<ua::DateTime> requestedTimes)
{
  return ua::detail::good_value(try_delete_at_time_sync(std::move(node), std::move(requestedTimes)));
}

ua::Result<HistoryUpdateResult> HistoryFacade::try_delete_at_time_sync(
  ua::NodeId node, std::vector<ua::DateTime> requestedTimes) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<HistoryUpdateResult>>(mExecutor,
    [this, node = std::move(node), requestedTimes = std::move(requestedTimes)](auto completion) mutable
    { delete_at_time_async(std::move(node), std::move(requestedTimes), std::move(completion)); });
}

// ============================================================================
// Blocking wrappers
//
// One blocking_call per asynchronous operation, the shape every tier-2 facade uses
// (ua_sync_wait.h): the throwing form returns the value of a Good answer of `try_*_sync(...)`
// (ua::detail::good_value) and a void one calls `.value()`, and the non-throwing form arms the
// existing `*_async`. No operation is reimplemented here.
//
// Each blocks the calling thread until the completion runs; called from the executor thread that
// would run it, each refuses with Bad_WouldBlock before starting anything.
// ============================================================================

void HistoryFacade::preflight_update_sync(ua::NodeId node, UpdateCapability capability)
{
  try_preflight_update_sync(std::move(node), std::move(capability)).value();
}

ua::VoidResult HistoryFacade::try_preflight_update_sync(ua::NodeId node, UpdateCapability capability) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(mExecutor,
    [this, node = std::move(node), capability = std::move(capability)](auto completion) mutable
    { preflight_update_async(std::move(node), std::move(capability), std::move(completion)); });
}

}  // namespace ua::client
