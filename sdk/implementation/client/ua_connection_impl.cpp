// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_connection_impl.h"
#include "ua_client_answer_status.h"

#include "ua_access_level_ex_type.h"
#include "ua_address_space_cache.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_connection_event_backbone_ops.h"
#include "ua_connection_ops.h"
#include "ua_connection_subscription_factory.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_change_notification.h"
#include "ua_deadband_type.h"
#include "ua_event_demux.h"
#include "ua_event_notification_list.h"
#include "ua_alarm_condition_tracker_impl.h"
#include "ua_data_change_monitored_item_owner.h"
#include "ua_event_router.h"
#include "ua_event_subscriber_impl.h"
#include "ua_semantic_change_cache.h"
#include "ua_type_reify_consumer.h"
#include "ua_type_resolver.h"
#include "ua_type_resolution_policy.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_diagnostic_info_decoder.h"  // CL-BASEDIAG-001: decode a received serviceDiagnostics
#include "ua_response_diagnostics.h"  // CL-DIAG-005: attach_wire_marker for the general data surface
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_error_detail.h"
#include "ua_get_endpoints_request.h"  // CL-RECONN-005: GetEndpoints on the security-failure recovery path
#include "ua_get_endpoints_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_error_detail_keys.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_notification_message.h"
#include "ua_numeric_range_validation.h"
#include "ua_on_strand.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_value_id.h"
#include "ua_status_change_notification.h"
#include "ua_real_session_ops.h"
#include "ua_reconnect_types.h"
#include "ua_reconnection_fsm.h"
#include "ua_redundancy_manager_impl.h"  // RedundancyManagerImpl::create + RedundancyManagerFactory (W4)
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_sequence_tracker.h"  // SequenceClass + should_deliver (publish-delivery classification gate)
#include "ua_server_state.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_timestamps_to_return.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_transfer_result.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <cmath>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ua::client::detail
{

/// Synchronous leaf shared by the public-handle callback path and connection-strand reconnect commit.
/// Weak cells do not extend handle lifetime; rekeying prunes cells whose handle has gone away.
class SubscriptionIdCellRegistry
{
public:
  void register_cell(std::weak_ptr<std::atomic<std::uint32_t>> cell)
  {
    const std::lock_guard lock{mMutex};
    mCells.push_back(std::move(cell));
  }

  void rekey(std::uint32_t oldId, std::uint32_t newId)
  {
    const std::lock_guard lock{mMutex};
    std::erase_if(mCells,
      [oldId, newId](const std::weak_ptr<std::atomic<std::uint32_t>>& weak)
      {
        auto cell = weak.lock();
        if (!cell)
        {
          return true;
        }
        // Only a cell still naming the old Subscription moves forward. A handle created against the
        // replacement Subscription cannot be overwritten by a late rekey of its predecessor.
        std::uint32_t expected = oldId;
        cell->compare_exchange_strong(expected, newId, std::memory_order_relaxed);
        return false;
      });
  }

private:
  std::mutex mMutex;
  std::vector<std::weak_ptr<std::atomic<std::uint32_t>>> mCells;
};

namespace
{

/// Tier-1 source tag for this component's ErrorDetail wraps (section 8.2A.8).
constexpr std::string_view source = "client.tier1.connection_impl";

/// Operation tag surfaced as ErrorDetail context for the bootstrap Read.
constexpr std::string_view bootstrapOperationTag = "bootstrap.read_namespace_array";

ua::UserTokenType user_token_type_for_identity(const ua::client::UserIdentity& identity)
{
  return std::visit(
    [](const auto& concrete)
    {
      using Identity = std::decay_t<decltype(concrete)>;
      if constexpr (std::is_same_v<Identity, ua::client::AnonymousIdentity>)
      {
        return ua::UserTokenType::Anonymous;
      }
      else if constexpr (std::is_same_v<Identity, ua::client::UsernamePasswordIdentity>)
      {
        return ua::UserTokenType::UserName;
      }
      else if constexpr (std::is_same_v<Identity, ua::client::X509Identity>)
      {
        return ua::UserTokenType::Certificate;
      }
      else
      {
        return ua::UserTokenType::IssuedToken;
      }
    },
    identity);
}

// CL-BASE-003: the Server.ServerCapabilities.OperationLimits.* nodes, read at bootstrap indices 3..14 (in
// this exact order) so the client can chunk batched service calls at the server's per-call limits. Kept in
// sync with parse_operation_limits() and OperationLimits's field order.
constexpr std::array<ua::VariableId, 12> operationLimitNodes{
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData,
  ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents};

constexpr std::array<ua::VariableId, 3> continuationPointLimitNodes{
  ua::VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints,
  ua::VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints,
  ua::VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints};

/// The response index at which the OperationLimits reads begin (after NamespaceArray, ServerArray,
/// and UrisVersion).
constexpr std::size_t operationLimitsStartIndex = 3;

/// Builds the tier-1 ReadRequest for the NamespaceArray bootstrap (CL-SESS-028) plus the UrisVersion
/// ServerArray cache (CL-BASE-002), UrisVersion change counter (CL-BASE-001), and OperationLimits
/// (CL-BASE-003). Indices 0/1/2 are NamespaceArray/ServerArray/UrisVersion; limits follow at index 3.
ua::ReadRequest build_namespace_array_read()
{
  ua::ReadRequest request;
  ua::ReadValueId namespaceArray;
  namespaceArray.node_id() = ua::NodeId{ua::VariableId::Server_NamespaceArray};
  namespaceArray.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  request.nodes_to_read().push_back(std::move(namespaceArray));

  ua::ReadValueId serverArray;
  serverArray.node_id() = ua::NodeId{ua::VariableId::Server_ServerArray};
  serverArray.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  request.nodes_to_read().push_back(std::move(serverArray));

  // CL-BASE-001: read Server.UrisVersion (a VersionTime change counter, OPC 10000-5) in the same batch so
  // the cached snapshot is version-tagged. A server that does not publish it returns a bad/absent value,
  // which is tolerated - the snapshot's urisVersion stays nullopt.
  ua::ReadValueId urisVersion;
  urisVersion.node_id() = ua::NodeId{ua::VariableId::Server_UrisVersion};
  urisVersion.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  request.nodes_to_read().push_back(std::move(urisVersion));

  // CL-BASE-003: read the per-call OperationLimits in the same batch. Each is optional - a server that does
  // not publish a given limit returns a bad/absent value, tolerated as 0 (no client-imposed limit).
  for (const auto limitNode : operationLimitNodes)
  {
    ua::ReadValueId limit;
    limit.node_id() = ua::NodeId{limitNode};
    limit.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(limit));
  }
  for (const auto limitNode : continuationPointLimitNodes)
  {
    ua::ReadValueId limit;
    limit.node_id() = ua::NodeId{limitNode};
    limit.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(limit));
  }

  request.timestamps_to_return() = ua::TimestampsToReturn::Neither;
  return request;
}

/// Extracts a single OperationLimit UInt32 from response index @p index, tolerating a missing / bad /
/// non-UInt32 value as 0 (CL-BASE-003: absent or 0 == no client-imposed limit).
std::uint32_t extract_operation_limit(const ua::ReadResponse& response, std::size_t index)
{
  const auto& results = response.results();
  if (index >= results.size())
  {
    return 0;
  }
  const auto& value = results[index];
  // The SDK sizes its requests by the limit, so only a Good value is used; an Uncertain one counts as absent.
  const auto& limitStatus = value.status();
  if (limitStatus.has_value() && !limitStatus.value().is_good())
  {
    return 0;
  }
  const auto* limit = value.value().try_as<std::uint32_t>();
  return limit != nullptr ? *limit : 0;
}

/// Parses the OperationLimits (CL-BASE-003) from a bootstrap Read response (indices 3..14). A bad overall
/// read yields all-zero (unlimited) limits; each field is independently tolerant of an absent server value.
OperationLimits parse_operation_limits(const ua::Result<ua::ReadResponse>& readResult)
{
  OperationLimits limits;
  if (!readResult.is_good())
  {
    return limits;
  }
  const auto& response = readResult.value();
  limits.maxNodesPerRead = extract_operation_limit(response, operationLimitsStartIndex + 0);
  limits.maxNodesPerWrite = extract_operation_limit(response, operationLimitsStartIndex + 1);
  limits.maxNodesPerMethodCall = extract_operation_limit(response, operationLimitsStartIndex + 2);
  limits.maxNodesPerBrowse = extract_operation_limit(response, operationLimitsStartIndex + 3);
  limits.maxNodesPerRegisterNodes = extract_operation_limit(response, operationLimitsStartIndex + 4);
  limits.maxNodesPerTranslateBrowsePathsToNodeIds =
    extract_operation_limit(response, operationLimitsStartIndex + 5);
  limits.maxNodesPerNodeManagement = extract_operation_limit(response, operationLimitsStartIndex + 6);
  limits.maxMonitoredItemsPerCall = extract_operation_limit(response, operationLimitsStartIndex + 7);
  limits.maxNodesPerHistoryReadData = extract_operation_limit(response, operationLimitsStartIndex + 8);
  limits.maxNodesPerHistoryReadEvents = extract_operation_limit(response, operationLimitsStartIndex + 9);
  limits.maxNodesPerHistoryUpdateData = extract_operation_limit(response, operationLimitsStartIndex + 10);
  limits.maxNodesPerHistoryUpdateEvents = extract_operation_limit(response, operationLimitsStartIndex + 11);
  return limits;
}

ContinuationPointLimits parse_continuation_point_limits(const ua::Result<ua::ReadResponse>& readResult)
{
  ContinuationPointLimits limits;
  if (!readResult.is_good())
  {
    return limits;
  }
  const auto& results = readResult.value().results();
  constexpr std::size_t start = operationLimitsStartIndex + operationLimitNodes.size();
  auto extract = [&results](std::size_t index) -> std::uint16_t
  {
    if (index >= results.size())
    {
      return 0;
    }
    const auto& value = results[index];
    if (value.status().has_value() && !value.status()->is_good())
    {
      return 0;
    }
    const auto* limit = value.value().try_as<std::uint16_t>();
    return limit != nullptr ? *limit : 0;
  };
  limits.maxBrowse = extract(start);
  limits.maxQuery = extract(start + 1);
  limits.maxHistory = extract(start + 2);
  return limits;
}

/// The effective per-call History limit (CL-BASE-003): the smaller of the non-zero Data/Events limits so a
/// mixed HistoryRead/Update batch never exceeds EITHER server limit (0 == unlimited on that dimension).
inline std::uint32_t effective_history_limit(std::uint32_t dataLimit, std::uint32_t eventsLimit)
{
  if (dataLimit != 0 && eventsLimit != 0)
  {
    return std::min(dataLimit, eventsLimit);
  }
  return dataLimit != 0 ? dataLimit : eventsLimit;
}

/// Merges the ResponseHeader of one chunk of a chunked request into the response the caller receives. The
/// first chunk's header is kept; its ServiceResult then becomes every chunk's ServiceResult combined
/// (@ref ua::detail::combined_status), so a Good subcode or an Uncertain code any chunk was answered with
/// reaches the caller rather than only the first chunk's.
///
/// @param merged        The header of the merged response.
/// @param chunk         The header of the chunk's response.
/// @param headerCarried Whether a chunk's header was already merged; set by the first call.
void merge_chunk_response_header(
  ua::ResponseHeader& merged, const ua::ResponseHeader& chunk, bool& headerCarried)
{
  if (!headerCarried)
  {
    merged = chunk;
    headerCarried = true;
    return;
  }
  merged.service_result() = ua::detail::combined_status(merged.service_result(), chunk.service_result());
}

std::size_t count_browse_continuation_points(const ua::BrowseResponse& response)
{
  return static_cast<std::size_t>(std::count_if(response.results().begin(),
    response.results().end(),
    [](const ua::BrowseResult& result) { return !result.continuation_point().empty(); }));
}

std::size_t count_browse_next_continuation_points(const ua::BrowseNextResponse& response)
{
  return static_cast<std::size_t>(std::count_if(response.results().begin(),
    response.results().end(),
    [](const ua::BrowseResult& result) { return !result.continuation_point().empty(); }));
}

std::size_t count_history_continuation_points(const ua::HistoryReadResponse& response)
{
  return static_cast<std::size_t>(std::count_if(response.results().begin(),
    response.results().end(),
    [](const ua::HistoryReadResult& result) { return !result.continuation_point().empty(); }));
}

std::size_t count_query_first_continuation_points(const ua::QueryFirstResponse& response)
{
  return response.continuation_point().empty() ? 0 : 1;
}

std::size_t count_query_next_continuation_points(const ua::QueryNextResponse& response)
{
  return response.revised_continuation_point().empty() ? 0 : 1;
}

/// Converts a std::vector<T> to a ua::Array<T> (move-appending); ua::Array has no iterator-range ctor.
template<typename T>
ua::Array<T> to_ua_array(std::vector<T> values)
{
  ua::Array<T> array;
  array.reserve(values.size());
  for (auto& value : values)
  {
    array.push_back(std::move(value));
  }
  return array;
}

// CL-BASE-003 batched-service chunking (reusable across Read/Write/Browse/Call/...). Splits @p items into
// chunks of at most @p limit (limit 0 => a single chunk) and issues each chunk SEQUENTIALLY via @p
// issueChunk, COLLECTING one @p ChunkResult (the WHOLE per-chunk response) per chunk so @p complete can merge
// results + diagnostics + header with full fidelity. A batched call is ATOMIC to the caller: the first chunk
// whose issueChunk yields a bad Result fails the whole call with that status + ErrorDetail; only after the
// last chunk succeeds is the collected vector delivered. @p complete fires exactly once.
//
// STRAND DISCIPLINE (section 3.1 wf_380842af-63a): issueChunk's completion (chunkDone) is delivered OFF the
// owning strand (invoke_wire_op's completion hops onto the executor), and issueChunk re-enters the loop from
// there. issueChunk MUST therefore re-hop onto the owning strand (post_borrowing_or_else) BEFORE it touches
// any strand-only state (e.g. invoke_wire_op's is_terminal_state()/mState). That re-hop also TRAMPOLINES the
// recursion, so a synchronously-completing issueChunk never grows the stack.
template<typename Item, typename ChunkResult>
struct ChunkLoopState
{
  std::vector<std::vector<Item>> chunks;
  std::size_t nextChunk = 0;
  std::vector<ChunkResult> collected;
  std::function<void(std::vector<Item>, std::function<void(ua::Result<ChunkResult>)>)> issueChunk;
  std::function<void(ua::Result<std::vector<ChunkResult>>)> complete;
};

template<typename Item, typename ChunkResult>
void run_chunk_loop(std::shared_ptr<ChunkLoopState<Item, ChunkResult>> loop)
{
  if (loop->nextChunk >= loop->chunks.size())
  {
    loop->complete(ua::Result<std::vector<ChunkResult>>{std::move(loop->collected)});
    return;
  }
  auto chunk = loop->chunks[loop->nextChunk];
  loop->issueChunk(std::move(chunk),
    [loop](ua::Result<ChunkResult> chunkResult) mutable
    {
      if (!chunkResult.has_value())
      {
        loop->complete(
          ua::Result<std::vector<ChunkResult>>{chunkResult.status_code(), chunkResult.shared_detail()});
        return;
      }
      loop->collected.push_back(std::move(chunkResult.value()));
      ++loop->nextChunk;
      run_chunk_loop(loop);
    });
}

template<typename Item, typename ChunkResult>
void chunk_batch_async(std::vector<Item> items, std::uint32_t limit,
  std::function<void(std::vector<Item>, std::function<void(ua::Result<ChunkResult>)>)> issueChunk,
  std::function<void(ua::Result<std::vector<ChunkResult>>)> complete)
{
  auto loop = std::make_shared<ChunkLoopState<Item, ChunkResult>>();
  const std::size_t chunkSize =
    (limit == 0 || limit >= items.size()) ? std::max<std::size_t>(items.size(), 1) : limit;
  for (std::size_t start = 0; start < items.size(); start += chunkSize)
  {
    const std::size_t end = std::min(start + chunkSize, items.size());
    loop->chunks.emplace_back(
      items.begin() + static_cast<std::ptrdiff_t>(start), items.begin() + static_cast<std::ptrdiff_t>(end));
  }
  loop->issueChunk = std::move(issueChunk);
  loop->complete = std::move(complete);
  run_chunk_loop(loop);
}

/// Builds the tier-1 keep-alive observation Read (section 8.2A.6 / CL-BASE-005).
///
/// State remains the liveness value. ServiceLevel and EstimatedReturnTime travel in the same request so an
/// observed shutdown/maintenance response can govern reconnect pacing without a second wire round-trip
/// that may lose the final answer as the Server goes offline.
ua::ReadRequest build_server_state_read(std::uint32_t timeoutHintMs)
{
  ua::ReadRequest request;
  for (const auto& node : {ua::NodeId{ua::VariableId::Server_ServerStatus_State},
         ua::NodeId{ua::VariableId::Server_ServiceLevel},
         ua::NodeId{ua::VariableId::Server_EstimatedReturnTime}})
  {
    ua::ReadValueId nodeToRead;
    nodeToRead.node_id() = node;
    nodeToRead.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(nodeToRead));
  }
  request.timestamps_to_return() = ua::TimestampsToReturn::Neither;
  // Bound the poll to the keep-alive cadence so a HUNG server (a read that never answers) is timed out and
  // counted as a miss at ~the interval, not held open for the (much larger) default service timeout - which
  // would stall miss detection behind the in-flight guard and defeat the keep-alive's whole purpose.
  request.request_header().timeout_hint() = timeoutHintMs;
  return request;
}

struct KeepAliveServerHint
{
  bool maintenance = false;
  std::optional<ua::DateTime> estimatedReturnTime;
};

/// Whether a keep-alive pacing hint may use @p value: its status is Good. The Connection decides its
/// reconnect pacing on the value itself, so an Uncertain value counts as absent, as a Bad one does.
bool has_usable_value(const ua::DataValue& value)
{
  const auto& valueStatus = value.status();
  return !valueStatus.has_value() || valueStatus.value().is_good();
}

/// Extracts the shutdown/maintenance pacing hint from a successful keep-alive response.
///
/// `ServerState` travels as Int32 and `ServiceLevel` as Byte. `EstimatedReturnTime` is optional: missing,
/// bad, or wrong-typed data is deliberately ignored so a responsive Server remains alive and falls back to
/// slow retry rather than turning an optional-model defect into a transport miss.
KeepAliveServerHint parse_keep_alive_server_hint(const ua::ReadResponse& response)
{
  KeepAliveServerHint hint;
  const auto& results = response.results();
  if (results.size() > 0 && has_usable_value(results[0]))
  {
    if (const auto* state = results[0].value().try_as<std::int32_t>())
    {
      hint.maintenance = *state == static_cast<std::int32_t>(ua::ServerState::Shutdown);
    }
  }
  if (results.size() > 1 && has_usable_value(results[1]))
  {
    if (const auto* serviceLevel = results[1].value().try_as<std::uint8_t>())
    {
      hint.maintenance = hint.maintenance || *serviceLevel == 0;
    }
  }
  if (hint.maintenance && results.size() > 2 && has_usable_value(results[2]))
  {
    if (const auto* estimatedReturnTime = results[2].value().try_as<ua::DateTime>())
    {
      if (estimatedReturnTime->value() > ua::DateTime::now().value())
      {
        hint.estimatedReturnTime = *estimatedReturnTime;
      }
    }
  }
  return hint;
}

/// Parses a NamespaceArray Read response into a validated @ref NamespaceTable snapshot.
///
/// Shared by the bootstrap read and the reconnect re-read: validates the response, extracts the URI
/// string array, and builds the table at @p generation. Returns the table (Good) or the first bad
/// status encountered - it never touches orchestrator state, so both callers own the state transitions.
ua::Result<std::shared_ptr<const NamespaceTable>> build_namespace_table_from_read(
  const ua::Result<ua::ReadResponse>& readResult, std::uint64_t generation)
{
  // The Connection maps every NodeId through this table, so it is built from a Good answer only: an
  // Uncertain answer without a response, an Uncertain ServiceResult or an Uncertain NamespaceArray value is
  // refused.
  if (!readResult.has_value())
  {
    return ua::Result<std::shared_ptr<const NamespaceTable>>{
      answer_refused(readResult.status_code(), "ReadAnswerUncertain", "client.tier1.connection.bootstrap")};
  }

  const ua::StatusCode serviceResult = readResult.value().response_header().service_result();
  if (serviceResult.is_uncertain())
  {
    return ua::Result<std::shared_ptr<const NamespaceTable>>{
      uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", "client.tier1.connection.bootstrap")};
  }

  const auto& results = readResult.value().results();
  if (results.size() == 0)
  {
    return ua::Result<std::shared_ptr<const NamespaceTable>>{ua::Status::BadUnexpectedError};
  }

  const auto& dataValue = results[0];
  const auto& namespaceStatus = dataValue.status();
  if (namespaceStatus.has_value() && namespaceStatus.value().is_uncertain())
  {
    return ua::Result<std::shared_ptr<const NamespaceTable>>{uncertain_answer_refused(
      namespaceStatus.value(), "ReadAnswerUncertain", "client.tier1.connection.bootstrap")};
  }
  if (namespaceStatus.has_value() && namespaceStatus.value().is_bad())
  {
    return ua::Result<std::shared_ptr<const NamespaceTable>>{namespaceStatus.value()};
  }

  if (!dataValue.value().is_array_of_string())
  {
    return ua::Result<std::shared_ptr<const NamespaceTable>>{ua::Status::BadTypeMismatch};
  }
  const auto& uriArray = dataValue.value().as<ua::Array<ua::String>>();

  std::vector<std::string> uris;
  uris.reserve(uriArray.size());
  for (const auto& uri : uriArray)
  {
    uris.emplace_back(static_cast<std::string_view>(uri));
  }

  // CL-BASE-001: extract the UrisVersion counter from index 2 (built by build_namespace_array_read). It is
  // OPTIONAL - a server that does not publish Server.UrisVersion returns a bad or non-UInt32 value, in which
  // case the snapshot is version-untagged (nullopt) rather than failing the whole bootstrap.
  std::optional<std::uint32_t> urisVersion;
  if (results.size() > 2)
  {
    const auto& versionValue = results[2];
    // Only a Good UrisVersion tags the snapshot; an Uncertain one counts as absent.
    const auto& versionStatus = versionValue.status();
    const bool versionIsBad = versionStatus.has_value() && !versionStatus.value().is_good();
    if (!versionIsBad)
    {
      if (const auto* version = versionValue.value().try_as<std::uint32_t>())
      {
        urisVersion = *version;
      }
    }
  }

  return NamespaceTable::create(std::move(uris), urisVersion, generation);
}

ua::Result<std::shared_ptr<const ServerTable>> build_server_table_from_read(
  const ua::Result<ua::ReadResponse>& readResult, std::uint64_t generation)
{
  // An Uncertain answer without a response is refused, as the NamespaceArray's table refuses it.
  if (!readResult.has_value())
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{answer_refused(
      readResult.status_code(), "ReadAnswerUncertain", "client.tier1.connection.bootstrap.server_array")};
  }
  const auto& results = readResult.value().results();
  if (results.size() < 2)
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("ServerArrayResultMissing",
        "bootstrap response omitted the mandatory ServerArray result",
        "client.tier1.connection.bootstrap.server_array")};
  }
  const auto& dataValue = results[1];
  // The ServerTable maps every ServerIndex, so it is built from a Good ServerArray only.
  const auto& serverArrayStatus = dataValue.status();
  if (serverArrayStatus.has_value() && serverArrayStatus.value().is_uncertain())
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{uncertain_answer_refused(
      serverArrayStatus.value(), "ReadAnswerUncertain", "client.tier1.connection.bootstrap.server_array")};
  }
  if (serverArrayStatus.has_value() && serverArrayStatus.value().is_bad())
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{serverArrayStatus.value()};
  }
  if (!dataValue.value().is_array_of_string())
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{ua::Status::BadTypeMismatch,
      ua::make_error_detail("ServerArrayTypeMismatch",
        "ServerArray bootstrap value is not a String array",
        "client.tier1.connection.bootstrap.server_array")};
  }
  std::vector<std::string> uris;
  for (const auto& uri : dataValue.value().as<ua::Array<ua::String>>())
  {
    uris.emplace_back(static_cast<std::string_view>(uri));
  }
  return ServerTable::create(std::move(uris), generation);
}

/// Wraps @p cause in the tier-1 bootstrap-failure ErrorDetail chain (section 8.2A.8).
ua::VoidResult bootstrap_failure(ua::StatusCode cause)
{
  return ua::VoidResult{cause,
    ua::ErrorDetail::build(
      "BootstrapReadFailed", "connection bootstrap failed to read Server.NamespaceArray", std::string{source})
      .context(ua::ContextKeys::method, std::string{bootstrapOperationTag})
      .cause(cause)};
}

// The lifetime count SHALL be at least three times the keep-alive count (OPC 10000-4 section 5.13.3.2,
// Table 90). ConnectionImpl::SubscriptionTuning's own defaults - 30 and 10 - sit exactly at that normative
// boundary, so a caller who raises ONLY the keep-alive would otherwise be left with a lifetime below the
// floor for their new keep-alive, and the server would revise BOTH: they would get a Subscription tuned
// like neither their request nor the default, with nothing to say so.
constexpr std::uint32_t lifetimeToKeepAliveRatio = 3;

/// Decides whether a FAILED CreateSubscription should engage the polled-Read fallback (CL-SUB-019), per the
/// Connection's configured mode: Disabled never engages; OptIn engages only on Bad_ServiceUnsupported (the
/// server explicitly does not support Subscriptions); Auto engages on any create failure.
bool fallback_should_engage(ua::client::SubscriptionFallbackPolicy::Mode mode, ua::StatusCode status)
{
  switch (mode)
  {
  case ua::client::SubscriptionFallbackPolicy::Mode::Disabled:
    return false;
  case ua::client::SubscriptionFallbackPolicy::Mode::OptIn:
    return status.as_status() == ua::Status::BadServiceUnsupported;
  case ua::client::SubscriptionFallbackPolicy::Mode::Auto:
    return true;
  }
  return false;
}

/// Builds the CreateSubscription request from the caller's retained tuning (OPC 10000-4 5.13.2, Table 85).
/// The SINGLE build site, shared by the create funnel, the internal event-backbone create and the
/// session-CHANGED recreate, so none of them can drift from the others. @p tuning defaults to the
/// conventional values an internal caller with nothing to tune wants.
ua::CreateSubscriptionRequest build_create_subscription_request(double publishingInterval,
  std::uint32_t maxNotificationsPerPublish = 0,
  ConnectionImpl::SubscriptionTuning tuning = ConnectionImpl::SubscriptionTuning{})
{
  ua::CreateSubscriptionRequest request;
  request.requested_publishing_interval() = publishingInterval;
  request.requested_lifetime_count() = tuning.lifetimeCount;
  request.requested_max_keep_alive_count() = tuning.maxKeepAliveCount;
  request.max_notifications_per_publish() = maxNotificationsPerPublish;
  request.publishing_enabled() = tuning.publishingEnabled;
  request.priority() = tuning.priority;
  return request;
}

/// Builds a single MonitoredItemCreateRequest (section 8.4) from the six NON-FILTER tuning fields, with
/// defaults matching the historical hardcoded values. SHARED by the create funnel (@ref
/// build_create_monitored_items_request) and the session-CHANGED recreate loop (@ref
/// ConnectionImpl::recovery_recreate_subscription) so the two cannot silently diverge - both carry the
/// caller's retained tuning verbatim. @p discardOldest defaults to true (matching the historical hardcoded
/// value, so the recreate loop keeps its prior behaviour until the batched state-refresh follow-up); the
/// DataChangeFilter is deliberately out of scope (a separate, still-batched piece).
ua::MonitoredItemCreateRequest build_monitored_item_create_request(const ua::NodeId& node,
  std::uint32_t clientHandle, ua::AttributeId attribute = ua::AttributeId::Value,
  const std::optional<std::string>& indexRange = std::nullopt, double samplingIntervalMs = 0.0,
  std::uint32_t queueSize = 1, ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting,
  bool discardOldest = true,
  const std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter>& filter = {})
{
  ua::ReadValueId itemToMonitor;
  itemToMonitor.node_id() = node;
  itemToMonitor.attribute_id() = static_cast<std::uint32_t>(attribute);
  if (indexRange.has_value())
  {
    itemToMonitor.index_range() = *indexRange;  // a NumericRange string; left empty/unset when nullopt
  }

  ua::MonitoringParameters parameters;
  parameters.client_handle() = clientHandle;
  parameters.sampling_interval() =
    samplingIntervalMs;  // 0 = sample at the Subscription's publishing interval
  parameters.queue_size() = queueSize;
  parameters.discard_oldest() = discardOldest;
  // CL-MI-011: encode the caller's DataChangeFilter / AggregateFilter into the wire MonitoringFilter (a copy,
  // not an alias). A monostate (no filter) leaves parameters.filter() null so the wire omits the
  // ExtensionObject (no synthesized deadband=0 filter). Mirrors the event-monitor path's
  // make_unique<EventFilter>.
  std::visit(
    [&parameters](const auto& monitoringFilter)
    {
      using FilterType = std::decay_t<decltype(monitoringFilter)>;
      if constexpr (!std::is_same_v<FilterType, std::monostate>)
      {
        parameters.filter() = std::make_unique<FilterType>(monitoringFilter);
      }
    },
    filter);

  ua::MonitoredItemCreateRequest itemToCreate;
  itemToCreate.item_to_monitor() = std::move(itemToMonitor);
  itemToCreate.monitoring_mode() = monitoringMode;
  itemToCreate.requested_parameters() = std::move(parameters);
  return itemToCreate;
}

/// Builds a single-item CreateMonitoredItems request for @p node (section 8.4). The five NON-FILTER
/// MonitorRequest tuning fields are threaded through with defaults matching the historical hardcoded values,
/// so the id-only
/// @ref create_monitored_item_async caller (which passes none) is byte-for-byte unchanged while
/// @ref monitor_data_change_async can plumb the caller's attribute / indexRange / samplingIntervalMs /
/// queueSize / monitoringMode onto the wire (mirroring the modify path).
ua::CreateMonitoredItemsRequest build_create_monitored_items_request(std::uint32_t subscriptionId,
  const ua::NodeId& node, std::uint32_t clientHandle, ua::AttributeId attribute = ua::AttributeId::Value,
  const std::optional<std::string>& indexRange = std::nullopt, double samplingIntervalMs = 0.0,
  std::uint32_t queueSize = 1, ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting,
  bool discardOldest = true,
  const std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter>& filter = {})
{
  ua::CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  request.items_to_create().push_back(build_monitored_item_create_request(node,
    clientHandle,
    attribute,
    indexRange,
    samplingIntervalMs,
    queueSize,
    monitoringMode,
    discardOldest,
    filter));
  return request;
}

/// CL-MI-024: local structural validation of a monitor DataChangeFilter before it reaches the wire. A
/// PercentDeadband's value is a percentage, so a non-finite or out-of-[0,100] value is invalid INDEPENDENT of
/// the node's DataType  -  reject it locally (Bad_DeadbandFilterInvalid) so no server round-trip is wasted.
/// This is NOT a DataType pre-flight (CL-MI-012 defers that to the server, no extra Read): Absolute/None
/// deadbands carry engineering-unit magnitudes the server validates against the node's EURange, so they pass
/// through here.
ua::VoidResult validate_monitor_data_change_filter(
  const std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter>& filter)
{
  const auto* dataChangeFilter = std::get_if<ua::DataChangeFilter>(&filter);
  if (dataChangeFilter == nullptr)
  {
    return {};  // monostate or AggregateFilter: no PercentDeadband to range-check here
  }
  if (dataChangeFilter->deadband_type() == static_cast<std::uint32_t>(ua::DeadbandType::Percent))
  {
    const double deadband = dataChangeFilter->deadband_value();
    if (!std::isfinite(deadband) || deadband < 0.0 || deadband > 100.0)
    {
      return ua::VoidResult{ua::StatusCode{ua::Status::BadDeadbandFilterInvalid},
        ua::make_error_detail("PercentDeadbandOutOfRange",
          "the PercentDeadband must be a finite value within [0, 100]",
          "client.tier1.monitor.percent_deadband_range")};
    }
  }
  return {};
}

/// Feeds a received Publish response into the pipeline (runs on the executor, from publish_async).
///
/// Demuxes the response's Subscription + sequence into @ref SubscriptionsPipeline::on_publish_response_async,
/// then routes each data-change MonitoredItemNotification to its client handle ONLY when the pipeline
/// classified the sequence as InOrder or Gap - honouring the pipeline's "Duplicate / Invalid -> no dispatch"
/// contract (CL-SUB-002): a Duplicate (a re-sent message the client already processed) must not
/// double-deliver, an Invalid (sequence 0) must not spoof-deliver, and an unknown/spoofed subscriptionId
/// (which classifies Invalid by default) must not deliver by clientHandle. A bad publish result keeps the
/// pump alive (tooMany=false) and delivers nothing - the pump/pipeline own the refill. Holds the pipeline
/// strongly (the callback outlives a racing orchestrator teardown), never touching ConnectionImpl.
// Routes one decoded EventNotificationList to the EventSubscriber: groups its EventFieldLists by the CLIENT
// backbone handle (the inbound demux key the server echoes) and hands each handle's batch to
// on_publish_events_async (which re-marshals onto the subscriber strand + decodes/demuxes). Shared by the
// live Publish demux and the reconnect Republish gap-drain so recovered events are not dropped.
void route_event_notification_list(
  const ua::EventNotificationList& eventList, EventSubscriberImpl& subscriber)
{
  for (auto& [clientHandle, fieldLists] : group_events_by_client_handle(eventList))
  {
    subscriber.on_publish_events_async(clientHandle, std::move(fieldLists), [] {});
  }
}

/// Whether a StatusChangeNotification's status says the Subscription no longer exists on this Session
/// (OPC 10000-4 7.25.4): Bad_Timeout when its lifetime expired, Good_SubscriptionTransferred when it was
/// transferred to another Session.
bool ends_subscription_on_session(const ua::StatusCode& status)
{
  const ua::Status code = status.as_status();
  return code == ua::Status::BadTimeout || code == ua::Status::GoodSubscriptionTransferred;
}

/// The advisory an application receives for a StatusChangeNotification whose status does not end the
/// Subscription: the SDK takes no action on it, and the code reaches the application unchanged as the cause.
std::shared_ptr<const ua::ErrorDetail> status_change_advisory(
  std::uint32_t subscriptionId, ua::StatusCode status)
{
  return ua::ErrorDetail::build("SubscriptionStatusChange",
    "the Server reported a status change of the Subscription",
    "client.subscriptions.status_change")
    .context(ua::ContextKeys::subscriptionId, subscriptionId)
    .cause(std::move(status));
}

void feed_publish_response(const std::shared_ptr<SubscriptionsPipeline>& pipeline,
  std::weak_ptr<EventSubscriberImpl> eventSubscriber, std::weak_ptr<ObserverSink> observerSink,
  ua::Result<ua::PublishResponse> result)
{
  if (!result.has_value())
  {
    // A whole-service Publish failure has no decoded Subscription id. The pipeline owns both pump
    // accounting and CL-SUB-005 BadResponseTooLarge recovery (all live server-backed Subscriptions).
    pipeline->on_publish_failure_async(result.status_code());
    return;
  }

  // Own the response by shared_ptr so the classification completion can carry it across the pipeline-strand
  // hop: a moved PublishResponse would not fit in the std::function completion (which needs a copyable
  // capture), and the delivery loop must run only AFTER the pipeline reports the classification.
  auto response = std::make_shared<const ua::PublishResponse>(std::move(result).value());
  const std::uint32_t subscriptionId = response->subscription_id();
  const std::uint32_t sequenceNumber = response->notification_message().sequence_number();
  // A keep-alive is an empty NotificationMessage (no notifications). Distinguishing it lets the pipeline
  // avoid advancing/acking the peeked sequence number the keep-alive reuses (OPC 10000-4 section 5.13.5).
  const bool hasNotifications = response->notification_message().notification_data().size() != 0;
  const bool hasAvailableSequenceNumbers = response->available_sequence_numbers().size() != 0;
  const bool tooManyPublishRequests =
    response->response_header().service_result() == ua::StatusCode{ua::Status::BadTooManyPublishRequests};
  // A StatusChangeNotification that ends the Subscription on this Session (Bad_Timeout or
  // Good_SubscriptionTransferred) is terminal: the pipeline removes the Subscription and the application
  // receives the code through SubscriptionObserver::on_subscription_terminated. Any other code is passed to
  // the application as an advisory.
  std::optional<ua::StatusCode> terminalStatus;
  std::vector<ua::StatusCode> otherStatusChanges;
  for (const auto& notification : response->notification_message().notification_data())
  {
    const auto* statusChange = dynamic_cast<const ua::StatusChangeNotification*>(notification.get());
    if (statusChange == nullptr)
    {
      continue;
    }
    if (ends_subscription_on_session(statusChange->status()))
    {
      terminalStatus = statusChange->status();
      break;
    }
    otherStatusChanges.push_back(statusChange->status());
  }

  // The classification completion captures the response payload (by value, shared) and the pipeline (strong,
  // as today) - never ConnectionImpl. It delivers ONLY when should_deliver(classification) holds, so
  // Duplicate / Invalid / unknown-subscription messages drop without any user dispatch (CL-SUB-002).
  pipeline->on_publish_response_async(
    subscriptionId,
    sequenceNumber,
    hasNotifications,
    hasAvailableSequenceNumbers,
    tooManyPublishRequests,
    [pipeline,
      eventSubscriber = std::move(eventSubscriber),
      observerSink = std::move(observerSink),
      response,
      terminalStatus,
      otherStatusChanges = std::move(otherStatusChanges),
      subscriptionId](ua::client::detail::SequenceClass classification)
    {
      if (!ua::client::detail::should_deliver(classification))
      {
        return;  // Duplicate / Invalid / unknown subscriptionId -> no user dispatch
      }
      if (terminalStatus.has_value())
      {
        return;  // terminal cleanup owns this message; no sibling payload survives a closed Subscription
      }
      if (!otherStatusChanges.empty())
      {
        if (auto sink = observerSink.lock())
        {
          for (const auto& status : otherStatusChanges)
          {
            sink->fire_advisory_diagnostic(status_change_advisory(subscriptionId, status));
          }
        }
      }
      for (const auto& notification : response->notification_message().notification_data())
      {
        if (const auto* dataChange = dynamic_cast<const ua::DataChangeNotification*>(notification.get()))
        {
          for (const auto& item : dataChange->monitored_items())
          {
            pipeline->deliver_notification_async(item.client_handle(), item.value());
          }
        }
        else if (const auto* eventList = dynamic_cast<const ua::EventNotificationList*>(notification.get()))
        {
          // Route events to the EventSubscriber if one was constructed (a data-only Connection never builds
          // it, so an inbound event for a non-existent backbone simply drops  -  never lazily construct
          // here).
          if (auto subscriber = eventSubscriber.lock())
          {
            route_event_notification_list(*eventList, *subscriber);
          }
        }
      }
    },
    std::move(terminalStatus));
}

}  // namespace

NamespaceRemap compare_namespace_tables(
  const std::shared_ptr<const NamespaceTable>& previous, const std::shared_ptr<const NamespaceTable>& next)
{
  NamespaceRemap remap;
  if (!previous || !next)
  {
    return remap;  // bootstrap: there is nothing to have changed FROM
  }

  remap.sizeChanged = previous->size() != next->size();

  const auto count = std::min(previous->size(), next->size());
  for (std::size_t i = 0; i < count; ++i)
  {
    const auto idx = static_cast<NamespaceIndex>(i);
    if (previous->lookup_uri(idx) != next->lookup_uri(idx))
    {
      remap.contentsChanged = true;
      // A URI that is still present, but at another index, is the case persisted NodeIds cannot
      // survive. A URI that simply disappeared is a content change without a shift.
      if (const auto uri = previous->lookup_uri(idx))
      {
        if (next->lookup_index(*uri).has_value())
        {
          remap.indexShifted = true;
        }
      }
    }
  }
  remap.contentsChanged = remap.contentsChanged || remap.sizeChanged;
  return remap;
}

bool is_channel_fatal(ua::StatusCode status) noexcept
{
  switch (status.as_status())
  {
  case ua::Status::BadSecureChannelClosed:
  case ua::Status::BadSecureChannelIdInvalid:
  case ua::Status::BadServerNotConnected:
  case ua::Status::BadConnectionClosed:
  case ua::Status::BadCommunicationError:
  case ua::Status::BadServerHalted:
  case ua::Status::BadTcpInternalError:
  case ua::Status::BadNotConnected:
  case ua::Status::BadDisconnect:
  case ua::Status::BadSessionIdInvalid:
  case ua::Status::BadSessionClosed:
  case ua::Status::BadSessionNotActivated:
    return true;
  default:
    return false;
  }
}

/// The ConnectionImpl-specific @ref ReconnectionFSMHost (section 8.3 host interface).
///
/// Holds only a `weak_ptr<ConnectionImpl>` (the FSM owns this host strongly and ConnectionImpl owns the
/// FSM, so a strong back-reference would cycle). Every hook locks the weak and forwards to a private
/// ConnectionImpl method, which hops onto the orchestrator's own strand (keeping that strand private).
/// A dead weak completes an owed @p done with `Bad_ConnectionClosed` so the FSM never hangs.
class ConnectionReconnectHost : public ReconnectionFSMHost
{
public:
  explicit ConnectionReconnectHost(std::weak_ptr<ConnectionImpl> connection)
    : mConnection(std::move(connection))
  {}

  void on_fsm_state_changed(ReconnectFsmState /*state*/, ReconnectCause cause, std::size_t attempt) override
  {
    // Thread the attempt counter + cause through (W3): the orchestrator fires `on_reconnecting(attempt,
    // cause)` from these - dropping them here would blind the observer to which attempt / why.
    if (const auto connection = mConnection.lock())
    {
      connection->reconnect_notify_reconnecting(attempt, std::move(cause));
    }
  }

  void on_fsm_reached_active(ReconnectOutcome outcome) override
  {
    // Thread the recovered outcome (incl. its optional cause) through (W3): the orchestrator fires
    // `on_reconnected(outcome)` and the tier-2 RedundancyManager consumes `outcome.cause` (W4).
    if (const auto connection = mConnection.lock())
    {
      connection->reconnect_notify_active(std::move(outcome));
    }
  }

  void on_fsm_failed(ua::StatusCode terminal, std::shared_ptr<const ua::ErrorDetail> chain) override
  {
    // Thread the terminal error chain through (W3): the orchestrator fires `on_disconnected` /
    // `on_error_chain` with the full cause chain - dropping it here would discard the diagnostics the whole
    // slice exists to preserve (the design specification: the chain is never silently dropped).
    if (const auto connection = mConnection.lock())
    {
      connection->reconnect_notify_failed(terminal, std::move(chain));
    }
  }

  void get_endpoints_async(std::function<void(ua::VoidResult)> done) override
  {
    forward(&ConnectionImpl::reconnect_get_endpoints, std::move(done));
  }

  void open_secure_channel_async(std::function<void(ua::VoidResult)> done) override
  {
    forward(&ConnectionImpl::reconnect_open_secure_channel, std::move(done));
  }

  void activate_session_async(std::function<void(ua::VoidResult)> done) override
  {
    forward(&ConnectionImpl::reconnect_activate_session, std::move(done));
  }

  void create_session_async(std::function<void(ua::VoidResult)> done) override
  {
    forward(&ConnectionImpl::reconnect_create_session, std::move(done));
  }

  void re_read_namespace_array_async(std::function<void(ua::VoidResult)> done) override
  {
    forward(&ConnectionImpl::reconnect_re_read_namespace_array, std::move(done));
  }

  void recover_subscriptions_async(
    ua::client::SubscriptionRecovery recovery, std::function<void(ua::VoidResult)> done) override
  {
    // Carries the SubscriptionRecovery policy (session-CHANGED recreate, #24) - so it cannot use the plain
    // `forward` funnel (which drops every arg but `done`); lock + dispatch inline with the same dead-weak
    // contract (a gone orchestrator completes Bad_ConnectionClosed so the FSM step never hangs).
    if (const auto connection = mConnection.lock())
    {
      connection->reconnect_recover_subscriptions(recovery, std::move(done));
    }
    else
    {
      done(ua::VoidResult{ua::Status::BadConnectionClosed});
    }
  }

  void commit_reconnect_async(std::function<void(ua::VoidResult)> done) override
  {
    forward(&ConnectionImpl::reconnect_commit, std::move(done));
  }

private:
  /// Locks the weak orchestrator and forwards @p done to @p primitive; a dead weak completes @p done
  /// with `Bad_ConnectionClosed` so the FSM does not hang waiting on a step that can never return.
  void forward(void (ConnectionImpl::*primitive)(std::function<void(ua::VoidResult)>),
    std::function<void(ua::VoidResult)> done)
  {
    if (const auto connection = mConnection.lock())
    {
      (connection.get()->*primitive)(std::move(done));
    }
    else
    {
      done(ua::VoidResult{ua::Status::BadConnectionClosed});
    }
  }

  std::weak_ptr<ConnectionImpl> mConnection;
};

/// Wires the eagerly-constructed @ref SubscriptionsPipeline onto @p self's upward-interface shim.
///
/// Constructs the one @ref ConnectionOpsShim @p self owns (weak-referencing @p self, capturing its
/// executor for boundary failures) and hands the pipeline the three strong role subobject handles it
/// needs - @ref SubscriptionOps (the Publish/Republish send interface), @ref WireOps (the polled-Read
/// fallback), and @ref SupportOps (namespace/state/executor). All three alias the one shim's control
/// block; the shim weak-refs @p self, so the strong `ConnectionImpl -> pipeline -> shim` chain forms no
/// cycle back into the orchestrator.
void ConnectionImpl::wire_pipeline_and_ops(const std::shared_ptr<ConnectionImpl>& self)
{
  self->mConnectionOps = std::make_shared<ConnectionOpsShim>(self->weak_from_this(), self->mExecutor);
  self->mPipeline = SubscriptionsPipeline::create(
    self->mExecutor,
    std::shared_ptr<SubscriptionOps>(self->mConnectionOps),
    std::shared_ptr<WireOps>(self->mConnectionOps),
    std::shared_ptr<SupportOps>(self->mConnectionOps),
    self->mLogger,
    // Finding 2 / CL-AC-003: the pipeline signals (on ITS strand) a Subscription whose reactive Republish
    // drain left an unrecovered gap. Forward to on_subscription_event_loss, which hops onto the connection
    // strand and drives the A&C-tracker resync. Weak-only: the pipeline (held strong by this orchestrator)
    // must not keep the orchestrator alive  -  mirrors ConnectionOpsShim's weak back-reference, so no cycle.
    [weakConnection = self->weak_from_this()](std::uint32_t subscriptionId)
    {
      if (auto connection = weakConnection.lock())
      {
        connection->on_subscription_event_loss(subscriptionId);
      }
    },
    // CL-DA-010: the in-band SemanticsChanged status-bit trigger. The pipeline signals (on ITS strand) the
    // monitored node whose delivered DataChange carried the bit; forward it into the SemanticChangeCache so a
    // DA typed accessor watching that node re-resolves fresh Properties on its next read. Weak-only (no cycle
    // back into the orchestrator); invalidate_async self-marshals onto the cache's strand, so calling it from
    // the pipeline strand is safe.
    [weakConnection = self->weak_from_this()](ua::NodeId node)
    {
      if (auto connection = weakConnection.lock())
      {
        connection->semantic_change_cache()->invalidate_async({std::move(node)});
      }
    },
    // CL-SUB-008: ObserverSink owns the executor hop and retains the full ErrorDetail chain.
    [weakConnection = self->weak_from_this()](std::uint32_t subscriptionId, ua::StatusCode reason)
    {
      if (auto connection = weakConnection.lock(); connection && connection->mObserverSink)
      {
        connection->mObserverSink->fire_subscription_terminated(
          subscriptionId, reason, reason.shared_detail());
      }
    },
    // CL-SUB-005: automatic maxNotificationsPerPublish recovery reached its floor/cap or its
    // ModifySubscription failed. ObserverSink performs the required executor/observer-strand handoff.
    [weakConnection = self->weak_from_this()](
      std::uint32_t subscriptionId, ua::StatusCode failure, std::uint32_t proposed)
    {
      if (auto connection = weakConnection.lock(); connection && connection->mObserverSink)
      {
        connection->mObserverSink->fire_subscription_recovery_action(
          subscriptionId, failure, failure.shared_detail(), ua::client::ProposedAdjustment{proposed});
      }
    },
    // CL-SUB-002: a live Publish revealed a sequence gap and the Republish drain is starting. Only the
    // pipeline can see this, so an application has no other way to learn it happened.
    [weakConnection = self->weak_from_this()](
      std::uint32_t subscriptionId, std::uint32_t lostFrom, std::uint32_t to)
    {
      if (auto connection = weakConnection.lock(); connection && connection->mObserverSink)
      {
        connection->mObserverSink->fire_publish_gap(subscriptionId, lostFrom, to);
      }
    });
  // The data-change MonitoredItemOwner (section 7.4): connection-lifetime, weak-refs this orchestrator. A
  // self-acting MonitoredItem weak-references it, so its lock failing == the Connection is gone.
  self->mMonitoredItemOwner = DataChangeMonitoredItemOwner::create(self->weak_from_this());
  // The observer fan-out sink (section 7.8 / wiring section 1): weak-refs this orchestrator (no cycle).
  // Constructed here (not in the ctor) because it needs weak_from_this, which is only valid once `self` owns
  // the object. The initial slots snapshot resolves the per-Connection config slots against the Client-level
  // defaults (per-Connection non-null wins).
  self->mObserverSink = ObserverSink::create(self->mExecutor, self->weak_from_this(), self->mLogger);
  self->mObserverSink->set_slots(
    resolve_observer_slots(self->mPerConnectionObservers, self->mClientObserverDefaults));
  // The Session this Connection was handed. It is created by the establisher before this orchestrator
  // exists, so the earliest point it can be reported is here, once the sink and its slots are resolved.
  self->mObserverSink->fire_session_created(self->mSessionId);
  // The EventSubscriber to observer/cache routing router (section 8.13 / Slice W8b): weak-refs this
  // orchestrator (no cycle) and shares its strand (the executor to strand re-marshal target). Constructed
  // here (needs weak_from_this); start()ed on first reach-Active, stop()ped in begin_close.
  self->mEventRouter = EventRouter::create(self->mStrand, self->weak_from_this(), self->mLogger);
}

void ConnectionImpl::wire_redundancy(const std::shared_ptr<ConnectionImpl>& self,
  ua::client::RedundancyPolicy policy, RedundancyDiscoveryProvider discovery)
{
  // Host first (weak-refs self, holds the sink strong), then the manager (holds the host strong). Declared
  // host-before-manager in the header so the manager is destroyed first  -  the host strictly outlives it
  // (section 8.11.3). Write-once here, before `self` is returned to the caller: the members are never
  // reassigned, so
  // @ref redundancy is a lock-free synchronous read.
  self->mRedundancyHost = std::make_shared<RedundancyManagerConnectionHost>(
    self->weak_from_this(), self->mExecutor, self->mObserverSink, std::move(discovery), self->mLogger);
  self->mRedundancyManager = detail::RedundancyManagerImpl::create(
    self->mExecutor, self->mRedundancyHost, self->mLogger, std::move(policy));
}

std::shared_ptr<ConnectionImpl> ConnectionImpl::create_from_ops(boost::asio::any_io_executor executor,
  std::shared_ptr<SessionOps> sessionOps, ConnectionConfig config, ua::Logger logger,
  std::optional<ReconnectWiringOps> reconnect, ObserverSlots clientObserverDefaults)
{
  // The single construction path shared by create() (which wraps a concrete Session in RealSessionOps) and
  // the test-only create_with_ops() (which injects a fake SessionOps). The tier-0 interface and the
  // interface-level ReopenChannelOps are already resolved by the caller, so both production and test drive
  // the SAME orchestrator logic (gating / bootstrap / reconnect primitives)  -  production's RealSessionOps
  // vs a fake.
  auto self = std::shared_ptr<ConnectionImpl>(
    new ConnectionImpl(std::move(executor), std::move(sessionOps), std::move(config), std::move(logger)));
  self->mClientObserverDefaults = std::move(clientObserverDefaults);

  // Construct the SubscriptionsPipeline + upward-interface shim eagerly (reconnect or not): the pump is
  // dormant until the first Subscription is registered. The shim weak-refs this orchestrator, so the strong
  // ConnectionImpl -> pipeline -> shim chain forms no cycle back into ConnectionImpl.
  wire_pipeline_and_ops(self);

  if (reconnect)
  {
    // Wire the reconnect substrate: the FSM owns the host strongly; the host holds this orchestrator
    // weakly (no cycle); this orchestrator owns the FSM. A drop drives the host, which drives the
    // tier-0 primitives below and the dispatch gate.
    self->mReopen = std::move(reconnect->reopenChannel);
    self->mActivateConfig = std::move(reconnect->activateConfig);
    // Server-cert re-validation interface (section 722/section 727, CL-SECADMIN-004). Empty on the current
    // bootstrap-only path (no retained secured channel), so revalidate_server_cert_async is a Good no-op; the
    // connect path fills it in a later slice.
    self->mServerCertValidator = std::move(reconnect->serverCertValidator);
    // Keep-alive is only meaningful with reconnect wiring (a miss drives the FSM); adopt its policy and
    // build the tracker from the miss threshold. The timer is armed later, on reach-active.
    self->mKeepAlivePolicy = reconnect->keepAlive;
    self->mKeepAliveTracker = KeepAliveTracker{self->mKeepAlivePolicy.missedBeforeReconnect};
    auto host = std::make_shared<ConnectionReconnectHost>(self);
    self->mReconnectFsm =
      ReconnectionFSM::create(self->mExecutor, std::move(host), std::move(reconnect->policy), self->mLogger);
    if (reconnect->enableRedundancy)  // J49: redundancy monitoring is opt-in (per-connection wire overhead)
    {
      wire_redundancy(
        self, std::move(reconnect->redundancyPolicy), std::move(reconnect->redundancyDiscovery));
    }
  }
  return self;
}

std::shared_ptr<ConnectionImpl> ConnectionImpl::create(boost::asio::any_io_executor executor,
  ua::client::Session session, ConnectionConfig config, ua::Logger logger,
  std::optional<ReconnectWiring> reconnect, ObserverSlots clientObserverDefaults)
{
  // Adapt the concrete Session -> tier-0 SessionOps interface and the caller-facing ReconnectWiring (yielding
  // a SecureChannel) -> the interface-level ReconnectWiringOps (yielding a ChannelOps) via make_real_reopen,
  // then funnel through the single create_from_ops construction path.
  auto sessionOps = std::make_shared<RealSessionOps>(std::move(session));
  std::optional<ReconnectWiringOps> reconnectOps;
  if (reconnect)
  {
    reconnectOps = ReconnectWiringOps{make_real_reopen(std::move(reconnect->reopenChannel)),
      std::move(reconnect->activateConfig),
      std::move(reconnect->policy),
      reconnect->keepAlive,
      reconnect->enableRedundancy,
      std::move(reconnect->redundancyPolicy),
      std::move(reconnect->redundancyDiscovery),
      std::move(reconnect->serverCertValidator)};
  }
  return create_from_ops(std::move(executor),
    std::move(sessionOps),
    std::move(config),
    std::move(logger),
    std::move(reconnectOps),
    std::move(clientObserverDefaults));
}

std::shared_ptr<ConnectionImpl> ConnectionImpl::create_with_ops(boost::asio::any_io_executor executor,
  std::shared_ptr<SessionOps> sessionOps, ConnectionConfig config, ua::Logger logger, ReopenChannelOps reopen,
  ua::client::Session::ActivateConfig activateConfig, ua::client::ReconnectPolicy policy,
  KeepAlivePolicy keepAlivePolicy, ObserverSlots clientObserverDefaults, bool enableRedundancy,
  ua::client::RedundancyPolicy redundancyPolicy, RedundancyDiscoveryProvider redundancyDiscovery,
  ServerCertValidator serverCertValidator)
{
  // Test-only injecting factory (see ConnectionImplTestAccess): the tier-0 SessionOps interface and the
  // interface-level ReopenChannelOps are the caller's (fakes). Reconnect is ALWAYS wired (mirrors the
  // historical shape the ConnectionImpl unit suite drives); funnels through create_from_ops with a populated
  // ReconnectWiringOps.
  ReconnectWiringOps reconnectOps{std::move(reopen),
    std::move(activateConfig),
    std::move(policy),
    keepAlivePolicy,
    enableRedundancy,
    std::move(redundancyPolicy),
    std::move(redundancyDiscovery),
    std::move(serverCertValidator)};
  return create_from_ops(std::move(executor),
    std::move(sessionOps),
    std::move(config),
    std::move(logger),
    std::move(reconnectOps),
    std::move(clientObserverDefaults));
}

ConnectionImpl::ConnectionImpl(boost::asio::any_io_executor executor, std::shared_ptr<SessionOps> sessionOps,
  ConnectionConfig config, ua::Logger logger)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)), mLogger(std::move(logger)),
    mSessionOps(std::move(sessionOps)),
    mDispatch(ConnectionDispatch::create(
      mExecutor, config.queueOnReconnect, config.pendingQueueLimit, config.maxQueueAge, mLogger)),
    mAddressSpaceCachePolicy(config.addressSpaceCache), mDiagnosticPolicy(config.diagnostics),
    mSubscriptionFallbackMode(config.subscriptionFallback.mode), mTypeResolutionPolicy(config.typeResolution),
    mSubscriptionIdCellRegistry(std::make_unique<SubscriptionIdCellRegistry>()),
    mPerConnectionObservers(config.observers)
{
  mSessionOps->set_return_diagnostics_override(mDiagnosticPolicy.requestedDiagnosticsMask);
  mSessionId = mSessionOps->session_id();  // session is already activated; id is valid
  // Publish the bound-endpoint cross-strand snapshot ONCE (Rule 4; F1/J45): the tier-2 redundancy host's
  // synchronous identity reads (current_endpoint / current_application_uri) serve off this lock-free atomic
  // rather than the connection strand. The connect path fills ConnectionConfig::endpoint; a reconnect-commit
  // republish is a W9 concern.
  mEndpointSnapshot.store(std::make_shared<const ua::EndpointDescription>(std::move(config.endpoint)));
  mEcdhPolicyUri = std::move(config.ecdhPolicyUri);
  mRequestEphemeralKey = config.requestEphemeralKey;
  publish_info();
}

ConnectionImpl::~ConnectionImpl()
{
  // Run the one-shot teardown hook (a registry erase installed by the connect path) BEFORE any member is
  // destroyed, so a concurrent CoreClientImpl registry walk never observes a half-destroyed Connection. The
  // hook is lightweight and non-blocking (see set_teardown_hook); it is invoked at most once per Connection.
  // All owned subordinates (FSM / pipeline / observer sink / redundancy manager) are then destroyed in the
  // usual reverse-declaration order.
  if (mTeardownHook)
  {
    mTeardownHook();
  }
}

void ConnectionImpl::register_subscription_id_cell(std::weak_ptr<std::atomic<std::uint32_t>> cell)
{
  mSubscriptionIdCellRegistry->register_cell(std::move(cell));
}

void ConnectionImpl::rekey_subscription_id_cells(std::uint32_t oldId, std::uint32_t newId)
{
  mSubscriptionIdCellRegistry->rekey(oldId, newId);
}

void ConnectionImpl::set_teardown_hook(std::function<void()> hook)
{
  mTeardownHook = std::move(hook);
}

void ConnectionImpl::start_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  // post_owning: this is the "start()-style keep me alive until my first hop runs" post - the strong
  // self-anchor is threaded through the bootstrap chain so the owed callback fires exactly once even
  // under a teardown race, then released once the executor delivery runs (section 8.2A.3).
  ua::async::post_owning(this,
    mStrand,
    mLogger,
    [callback = std::move(callback)](ConnectionImpl& self) mutable
    { self.begin_bootstrap(std::move(callback)); })();
}

void ConnectionImpl::reactivate_async(
  ua::client::UserIdentity newIdentity, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [newIdentity = std::move(newIdentity)](
      ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // The admission check stays HERE, synchronous, and before the task is assigned. `mReactivateTask`
      // is a single member on a long-lived Connection, so assigning it destroys whatever frame it
      // already holds - a second concurrent call would kill the first reactivation mid-flight and its
      // caller would never be answered. Rejecting before the assignment is what keeps that impossible.
      if (self.mState != ConnectionState::Active || self.mReactivateInFlight || !self.mSessionOps)
      {
        self.deliver_reactivate_result(completion,
          ua::VoidResult{ua::Status::BadInvalidState,
            ua::make_error_detail("ConnectionNotAvailableForReactivation",
              "the Connection must be Active with no other reactivation in progress",
              "client.tier1.connection.reactivate_async")});
        return;
      }

      self.mReactivateTask = self.run_reactivate(std::move(newIdentity), std::move(completion));
    })();
}

void ConnectionImpl::deliver_reactivate_result(
  std::function<void(ua::VoidResult)>& completion, ua::VoidResult result)
{
  if (auto callback = std::move(completion))
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(mLogger,
        [callback = std::move(callback), result = std::move(result)]() mutable
        { callback(std::move(result)); }));
  }
}

ua::async::Task<> ConnectionImpl::run_reactivate(
  ua::client::UserIdentity newIdentity, std::function<void(ua::VoidResult)> completion)
{
  try
  {
    // Admission was decided by the caller, before this task was assigned. @see reactivate_async
    auto config = mActivateConfig;
    config.identity = std::move(newIdentity);
    const auto expectedTokenType = user_token_type_for_identity(config.identity);
    if (const auto endpoint = mEndpointSnapshot.load())
    {
      const auto& policies = endpoint->user_identity_tokens().payload();
      const auto matching = std::ranges::find_if(policies,
        [expectedTokenType](const auto& policy) { return policy.token_type() == expectedTokenType; });
      if (matching != policies.end())
      {
        config.policyId = std::string{matching->policy_id()};
      }
      else if (config.policyId.empty() && expectedTokenType != ua::UserTokenType::Anonymous)
      {
        deliver_reactivate_result(completion,
          ua::VoidResult{ua::Status::BadIdentityTokenRejected,
            ua::make_error_detail("NoMatchingUserTokenPolicy",
              "the active endpoint advertises no UserTokenPolicy matching the requested identity",
              "client.tier1.connection.reactivate_async")});
        co_return;
      }
    }

    mReactivateInFlight = true;
    auto activateResult = co_await await_step<ua::VoidResult>([this, &config](auto stepCompletion)
      { mSessionOps->activate_on_bound_channel_async(config, std::move(stepCompletion)); });

    // Resuming here means the connection is still alive - `await_step` drops the answer otherwise -
    // so the chain's `weak.lock()` check is what the resumption itself now guarantees.
    mReactivateInFlight = false;

    if (mState != ConnectionState::Active)
    {
      deliver_reactivate_result(completion,
        ua::VoidResult{ua::Status::BadConnectionClosed,
          ua::make_error_detail("ConnectionClosedDuringReactivation",
            "the Connection left Active state before ActivateSession completed",
            "client.tier1.connection.reactivate_async")});
      co_return;
    }

    if (activateResult.is_good())
    {
      mActivateConfig = std::move(config);
      if (mObserverSink)
      {
        mObserverSink->fire_session_activated();
      }
      deliver_reactivate_result(completion, {});
      co_return;
    }

    auto detailBuilder = ua::ErrorDetail::build("ConnectionReactivationFailed",
      "ActivateSession rejected the requested user identity",
      "client.tier1.connection.reactivate_async");
    if (activateResult.shared_detail())
    {
      detailBuilder.cause(activateResult.shared_detail());
    }
    else
    {
      detailBuilder.cause(activateResult.status_code());
    }
    deliver_reactivate_result(completion, ua::VoidResult{activateResult.status_code(), detailBuilder});
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    deliver_reactivate_result(
      completion, ua::VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
  co_return;
}

void ConnectionImpl::begin_bootstrap(std::function<void(ua::VoidResult)> callback)
{
  // The Connection has begun its initial connect (section 7.8 on_connecting). Fired off-strand via the sink;
  // the delivery strand keeps it ordered strictly before on_connected (which fires on reach-Active below).
  if (mObserverSink)
  {
    mObserverSink->fire_connecting();
  }
  // Issue the NamespaceArray Read; the tier-0 completion re-enters the strand (post, never inline).
  mSessionOps->read_async(build_namespace_array_read(),
    ua::async::post_owning(this,
      mStrand,
      mLogger,
      [callback = std::move(callback)](ConnectionImpl& self, ua::Result<ua::ReadResponse> readResult) mutable
      { self.finish_bootstrap(std::move(readResult), std::move(callback)); }));
}

void ConnectionImpl::finish_bootstrap(
  ua::Result<ua::ReadResponse> readResult, std::function<void(ua::VoidResult)> callback)
{
  ua::VoidResult outcome = apply_bootstrap_read(readResult);
  if (!outcome.is_good())
  {
    publish_info();  // Failed
    // Deliver the start callback on the executor (never on the connection strand, section 8.2A.1 rule 3).
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [callback = std::move(callback), outcome = std::move(outcome)](ConnectionImpl&) mutable
      { callback(std::move(outcome)); })();
    return;
  }

  // A close_async can race an in-flight bootstrap: if the Connection is already terminal, do NOT
  // resurrect it to Active. Deliver Bad_ConnectionClosed instead (the close callback owns the teardown).
  if (is_terminal_state())
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [callback = std::move(callback)](ConnectionImpl&) mutable
      { callback(ua::VoidResult{ua::Status::BadConnectionClosed}); })();
    return;
  }

  if (!mReconnectFsm)
  {
    // Single-shot Connection: reach Active immediately and deliver Good.
    mState = ConnectionState::Active;
    publish_info();
    on_first_session_active();  // fire on_connected + on_session_activated once (+ W4 attach point)
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [callback = std::move(callback)](ConnectionImpl&) mutable { callback(ua::VoidResult{}); })();
    return;
  }

  // Reconnect-enabled: start the FSM (Idle -> Active) so a later trigger drives a reconnect. mState
  // reaches Active only after BOTH the bootstrap read succeeded AND the FSM is Active, so a trigger
  // issued the moment the start callback fires is never dropped as "FSM not started".
  mReconnectFsm->start_async(ua::async::post_owning(this,
    mStrand,
    mLogger,
    [callback = std::move(callback)](ConnectionImpl& self, ua::VoidResult /*startResult*/) mutable
    {
      // Re-check on the FSM-start completion: a close may have raced the FSM start too.
      if (self.is_terminal_state())
      {
        ua::async::post_owning(&self,
          self.mExecutor,
          self.mLogger,
          [callback = std::move(callback)](ConnectionImpl&) mutable
          { callback(ua::VoidResult{ua::Status::BadConnectionClosed}); })();
        return;
      }
      self.mState = ConnectionState::Active;
      self.publish_info();
      self.on_first_session_active();  // fire on_connected + on_session_activated once (+ W4 attach point)
      self.arm_keep_alive_timer();  // begin polling ServerStatus.State for the whole Active lifetime
                                    // (section 8.2A.6)
      ua::async::post_owning(&self,
        self.mExecutor,
        self.mLogger,
        [callback = std::move(callback)](ConnectionImpl&) mutable { callback(ua::VoidResult{}); })();
    }));
}

bool ConnectionImpl::is_terminal_state() const noexcept
{
  return mState == ConnectionState::Closing || mState == ConnectionState::Closed ||
         mState == ConnectionState::Failed;
}

ua::VoidResult ConnectionImpl::apply_bootstrap_read(const ua::Result<ua::ReadResponse>& readResult)
{
  // generation 0 for the bootstrap snapshot; the reconnect re-read bumps it (see apply_namespace_read).
  auto tableResult = build_namespace_table_from_read(readResult, /*generation=*/0);
  if (!tableResult.is_good())
  {
    mState = ConnectionState::Failed;
    return bootstrap_failure(tableResult.status_code());
  }
  auto serverTableResult = build_server_table_from_read(readResult, /*generation=*/0);
  if (!serverTableResult.is_good())
  {
    mState = ConnectionState::Failed;
    return bootstrap_failure(serverTableResult.status_code());
  }

  mNamespaceTable = tableResult.value();
  mServerTable = serverTableResult.value();
  mOperationLimits = parse_operation_limits(readResult);  // CL-BASE-003
  mContinuationPointLimits = parse_continuation_point_limits(readResult);
  mBrowseContinuationPoints.reset(mContinuationPointLimits.maxBrowse);
  mQueryContinuationPoints.reset(mContinuationPointLimits.maxQuery);
  mHistoryContinuationPoints.reset(mContinuationPointLimits.maxHistory);
  // The Connecting -> Active transition is owned by finish_bootstrap (applied after the reconnect FSM,
  // if any, has started), so a manual trigger works the instant the start callback fires.
  return ua::VoidResult{};
}

ua::VoidResult ConnectionImpl::apply_namespace_read(
  const ua::Result<ua::ReadResponse>& readResult, bool replaceServerTable)
{
  // Reconnect re-read (CL-SESS-028): rebuild the snapshot with a bumped generation, leaving mState to
  // the FSM notify hooks. On a bad read the FSM backs off and retries the step.
  const std::uint64_t generation = mNamespaceTable ? mNamespaceTable->generation() + 1 : 1;
  auto tableResult = build_namespace_table_from_read(readResult, generation);
  if (!tableResult.is_good())
  {
    return ua::VoidResult{tableResult.status_code()};
  }
  std::shared_ptr<const ServerTable> replacementServerTable;
  if (replaceServerTable)
  {
    auto serverTableResult = build_server_table_from_read(readResult, generation);
    if (!serverTableResult.is_good())
    {
      return ua::VoidResult{serverTableResult.status_code(), serverTableResult.shared_detail()};
    }
    replacementServerTable = serverTableResult.value();
  }
  // CL-ADDRSP-004: compare the incoming table against the one being replaced BEFORE the swap, so the
  // observer can be told whether the contents actually changed and, crucially, whether any URI moved
  // INDEX. A NodeId encodes a namespace index, not a URI, so a client that persisted NodeIds across a
  // reconnect to a server whose array shifted will read and write the WRONG NODES - silently. That is
  // what on_namespace_remap exists to prevent, and until now nothing computed
  // these flags or fired it: fire_namespace_remap's only caller in the entire repository was a test.
  const auto previousTable = mNamespaceTable;
  auto remap = compare_namespace_tables(previousTable, tableResult.value());

  mNamespaceTable = tableResult.value();
  if (replacementServerTable)
  {
    mServerTable = std::move(replacementServerTable);
  }
  if (remap.contentsChanged && mObserverSink)
  {
    mObserverSink->fire_namespace_remap(
      static_cast<std::size_t>(mNamespaceTable->generation()), remap.sizeChanged, remap.indexShifted);
  }
  mOperationLimits = parse_operation_limits(readResult);  // CL-BASE-003: refresh limits on reconnect re-read
  mContinuationPointLimits = parse_continuation_point_limits(readResult);
  if (replaceServerTable)
  {
    mBrowseContinuationPoints.reset(mContinuationPointLimits.maxBrowse);
    mQueryContinuationPoints.reset(mContinuationPointLimits.maxQuery);
    mHistoryContinuationPoints.reset(mContinuationPointLimits.maxHistory);
  }
  else
  {
    mBrowseContinuationPoints.set_limit(mContinuationPointLimits.maxBrowse);
    mQueryContinuationPoints.set_limit(mContinuationPointLimits.maxQuery);
    mHistoryContinuationPoints.set_limit(mContinuationPointLimits.maxHistory);
  }
  // Re-seed the TypeResolver with the refreshed table (strand-only). This runs at the precise site of the
  // reconnect table refresh  -  co-located with the mutation it must track  -  so the resolver's snapshot
  // never lags a namespace remap: parked user registrations re-attach against any newly-bound URI, and
  // resolution stays invariant under a remapped NamespaceIndex (CL-VIEW-018). Placed here rather than in
  // reconnect_notify_active so the re-seed is bound to the table change itself (which only
  // apply_namespace_read performs), not to the later reach-Active fan-out.
  if (mNamespaceTable)
  {
    type_resolver()->on_namespace_table_replaced_async(mNamespaceTable, [] {});
  }
  // Republish the cross-strand snapshot at the table-change site (Rule 4 / CL-SESS-028: "the table publishes
  // an immutable snapshot per reconnect"). Without this the atomic `mNamespaceTableSnapshot`  -  read by
  // `namespace_table_snapshot()` for per-Session ExpandedNodeId resolution (CL-ADDRSP-004), decoding, and the
  // cross-strand SupportOps interface  -  would lag the reconnect re-read until the later reach-Active
  // publish, so a URI-tagged NodeId resolved in that window would use the STALE index space. Also refreshes
  // the info snapshot's namespaceCount / urisVersion / operationLimits (all just updated here).
  publish_info();
  return ua::VoidResult{};
}

void ConnectionImpl::surface_response_diagnostics(
  const ua::ResponseHeader& header, std::string_view operationTag) const noexcept
{
  // CL-BASEDIAG-001. STRICT NO-OP default path: the server omits serviceDiagnostics unless the request set
  // returnDiagnostics != 0 (defaultReturnDiagnostics == 0), so this returns before touching the decoder or
  // the observer surface  -  every existing bad-result path is byte-for-byte unchanged (Part 4 section 7.34).
  if (header.service_diagnostics().is_null())
  {
    return;
  }
  // CL-DIAG-012: the emitOnErrorChainObserver policy gate. When disabled, the observer surface is a strict
  // no-op  -  skip the decode AND the fire (the response is delivered unchanged). The always-on CL-DIAG-005
  // Result-marker is INDEPENDENT of this gate (the funnel attaches it regardless), so disabling the observer
  // does not lose the wire-boundary record on the Result.
  if (!mDiagnosticPolicy.emitOnErrorChainObserver)
  {
    return;
  }
  // Best-effort: a malformed server DiagnosticInfo (out-of-range stringTable indexes, deep
  // innerDiagnosticInfo) must NEVER throw out of the wire funnel (process-abort class  -  the reverse-connect
  // no-throw-in-handler lesson). Decode is depth-capped (CL-DIAG-009, policy maxChainDepth) and tolerates
  // -1 / out-of-range indexes; the catch is a defensive backstop so the response is always forwarded
  // unaffected.
  try
  {
    auto sink = observer_sink();
    if (!sink)
    {
      return;
    }
    const ua::StatusCode serviceResult = header.service_result();
    DiagnosticInfoDecoder decoder{};
    decoder.maxChainDepth = mDiagnosticPolicy.maxChainDepth;
    // CL-DIAG-007: map a server NamespaceURI to its source tag (thread-safe atomic snapshot read).
    decoder.namespaceTable = namespace_table_snapshot();
    auto chain = decoder.decode(header.service_diagnostics(), header.string_table(), serviceResult);
    if (serviceResult.is_bad())
    {
      // Part 4 section 7.34: a decoded diagnostic on a BAD service result is the wire-boundary error chain  -
      // the #1 priority (ErrorDetail never silently discarded, logged/surfaced at the boundary).
      sink->fire_error_chain(serviceResult, std::move(chain), std::string{operationTag});
    }
    else
    {
      // Diagnostics on a GOOD result are advisory (a server rarely attaches them).
      sink->fire_advisory_diagnostic(std::move(chain));
    }
  }
  catch (...)
  {
    mLogger.warning({{"source", "client.tier1.connection.surface_response_diagnostics"}},
      "decoding a received serviceDiagnostics threw; dropping the advisory (the response is unaffected)");
  }
}

template<typename Response, typename IssueOnSession>
void ConnectionImpl::invoke_wire_op(std::string operationTag, IssueOnSession issueOnSession,
  std::function<void(ua::Result<Response>)> callback, std::optional<std::uint32_t> requestHandle)
{
  // Lifecycle gating (section 8.2A.3/section 8.2A.5). Terminal states (Closing/Closed/Failed) fast-fail
  // without ever touching the tier-0 session (a service accessor on a closed session blocks - FU-1). Active
  // AND Reconnecting BOTH route through the dispatch gate: Active dispatches immediately, Reconnecting QUEUES
  // and flushes on recovery (CL-SESS-019/021 - reconnect transparency). The session handle is grabbed at
  // DISPATCH time (not now), so a queued op binds to the CURRENT session after a reconnect rebind, and a
  // Reconnecting-state op never touches a mid-rebind session.
  if (is_terminal_state())
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [callback = std::move(callback)](ConnectionImpl&) mutable
      { callback(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
    return;
  }

  // Share the owed callback so the gate's dispatch (Good) and fail (Bad) paths consume it exactly once.
  // CL-BASEDIAG-001: decorate it with a pre-forward inspection  -  on a TRANSPORT-good response, surface any
  // server serviceDiagnostics to the observer fan-out before handing the Result to the caller. `operationTag`
  // is COPIED here (captured `tag`) because it is moved into `pending.operationTag` below; weak_from_this()
  // avoids an owning cycle through the pending map (a gone orchestrator  implies  forward-only). A synthetic
  // transport-Bad completion carries no Response value, so `result.has_value()` gates the header read: a
  // Good result and an Uncertain one holding a response both have their header read.
  auto userCallback = std::make_shared<std::function<void(ua::Result<Response>)>>(std::move(callback));
  auto trackingActive = std::make_shared<std::atomic<bool>>(false);
  auto owed = std::make_shared<std::function<void(ua::Result<Response>)>>(
    [weak = weak_from_this(),
      tag = operationTag,
      userCallback,
      trackingActive,
      requestHandle,
      maxChainDepth = mDiagnosticPolicy.maxChainDepth,
      wrapLevel = mDiagnosticPolicy.wrapLevel](ua::Result<Response> result) mutable
    {
      if (result.has_value())
      {
        const auto& header = result.value().response_header();
        if (auto self = weak.lock())
        {
          self->surface_response_diagnostics(header, tag);
        }
        // The Result's own code and the header's ServiceResult meet here; the code answered is the one
        // ua::detail::combined_status gives. A combined code that is not Bad leaves the Result as it is (the
        // response it holds carries the ServiceResult to the operation that reads it).
        // CL-DIAG-005: a combined code that is Bad (a Bad ServiceResult) is a service-level failure -
        // collapse it to a BAD Result carrying the always-on wire-crossing marker (marker -> decoded server
        // chain) BEFORE forwarding, so EVERY bad Result on the general data surface records the wire
        // boundary, even at returnDiagnostics=0. The observer fan-out above ran first (it reads
        // result.value()); the marker attach is stateless + noexcept, so a gone orchestrator still marks.
        // attach_wire_marker(header) is evaluated before `result` is reassigned, so `header` (a reference
        // into result.value()) is read while still valid.
        const ua::StatusCode ownStatus = result.status_code();
        const ua::StatusCode answered = ua::detail::combined_status(ownStatus, header.service_result());
        if (answered.is_bad())
        {
          // CL-DIAG-007: tag a server NamespaceURI (server.namespace./server.unknown.) using the current
          // snapshot, so the Result chain's marker is consistent with the observer path above. A gone
          // orchestrator (null snapshot) falls back to the raw URI.
          std::shared_ptr<const NamespaceTable> namespaceTable;
          if (auto self = weak.lock())
          {
            namespaceTable = self->namespace_table_snapshot();
            // The Result's own code is not the one answered: a SubCode it carries is logged.
            if (ua::detail::has_subcode(ownStatus))
            {
              self->mLogger.warning({{"operation", std::string_view{tag}},
                                      {"status", ownStatus.as_uint32()},
                                      {"answered", answered.as_uint32()}},
                "A managed Connection service operation's own code gives way to its Bad ServiceResult");
            }
          }
          result = ua::Result<Response>{answered,
            ua::client::detail::attach_wire_marker(header, maxChainDepth, std::move(namespaceTable))};
        }
      }
      if (!result.has_value() && wrapLevel != ua::client::ClientDiagnosticPolicy::WrapLevel::Minimal)
      {
        const ua::StatusCode cause = result.status_code();
        auto detail = ua::ErrorDetail::build("ConnectionServiceFailure",
          "A managed Connection service operation failed",
          std::string{"client.tier1.connection."} + tag);
        detail.cause(cause);
        std::shared_ptr<const ua::ErrorDetail> outer = std::move(detail);
        result = ua::Result<Response>{ua::StatusCode{cause.as_uint32(), std::move(outer)}};
      }
      if (requestHandle && trackingActive->exchange(false, std::memory_order_acq_rel))
      {
        if (auto self = weak.lock())
        {
          auto heldResult = std::make_shared<ua::Result<Response>>(std::move(result));
          ua::async::post_borrowing_or_else(
            self.get(),
            self->mStrand,
            self->mLogger,
            [requestHandle = *requestHandle, userCallback, heldResult](ConnectionImpl& connection) mutable
            {
              auto outstanding = connection.mOutstandingRequestsByHandle.find(requestHandle);
              if (outstanding != connection.mOutstandingRequestsByHandle.end())
              {
                if (--outstanding->second == 0)
                {
                  connection.mOutstandingRequestsByHandle.erase(outstanding);
                }
              }
              ua::async::post_owning(&connection,
                connection.mExecutor,
                connection.mLogger,
                [userCallback, heldResult](ConnectionImpl&) mutable
                { (*userCallback)(std::move(*heldResult)); })();
            },
            [userCallback, heldResult]() mutable { (*userCallback)(std::move(*heldResult)); })();
          return;
        }
      }
      (*userCallback)(std::move(result));
    });

  PendingRequest pending;
  pending.enqueuedAt = std::chrono::steady_clock::now();
  pending.operationTag = std::move(operationTag);
  // dispatch runs on the GATE strand when the gate dispatches (now if Active, or on flush after a
  // reconnect). It hops back onto the connection strand to reach mSessionOps (strand-only), re-checks
  // Active there, and issues the op against the CURRENT session. A gone orchestrator completes the owed Bad.
  pending.dispatch = [weak = weak_from_this(),
                       issueOnSession = std::move(issueOnSession),
                       owed,
                       trackingActive,
                       requestHandle]() mutable
  {
    auto self = weak.lock();
    if (!self)
    {
      (*owed)(ua::Result<Response>{ua::Status::BadConnectionClosed});
      return;
    }
    // post_borrowing_or_else (NOT plain post_borrowing): the alive path issues the op; the gone path (the
    // orchestrator is destroyed between this gate-strand turn and the connection-strand turn) still fires
    // the owed callback Bad, so a user callback is never silently dropped (a sync caller never hangs).
    ua::async::post_borrowing_or_else(
      self.get(),
      self->mStrand,
      self->mLogger,
      [issueOnSession = std::move(issueOnSession), owed, trackingActive, requestHandle](
        ConnectionImpl& conn) mutable
      {
        if (conn.mState != ConnectionState::Active)
        {
          // Raced into non-Active between the gate dispatch and this hop: complete Bad on the executor.
          ua::async::post_owning(&conn,
            conn.mExecutor,
            conn.mLogger,
            [owed](ConnectionImpl&) mutable
            { (*owed)(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
          return;
        }
        if (!conn.mSessionOps)
        {
          // Defensive: an Active Connection always holds a session interface (never nulled while Active), but
          // a missing interface must still complete the owed callback Bad on the executor rather than deref
          // null.
          ua::async::post_owning(&conn,
            conn.mExecutor,
            conn.mLogger,
            [owed](ConnectionImpl&) mutable
            { (*owed)(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
          return;
        }
        if (requestHandle)
        {
          ++conn.mOutstandingRequestsByHandle[*requestHandle];
          trackingActive->store(true, std::memory_order_release);
        }
        try
        {
          issueOnSession(*conn.mSessionOps, owed);  // tier-0 completion normally delivers on executor
        }
        catch (...)
        {
          // The invocation boundary owns a completion. A synchronous collaborator throw is therefore a
          // bad Result, not work for the outer strand guard to log and swallow (which would leave the
          // callback permanently owed). Preserve the rich exception StatusCode and deliver on the public
          // executor, matching the ordinary tier-0 completion path and never invoking user code on the
          // connection strand.
          ua::Result<Response> failure{ua::exception_to_status_code(std::current_exception())};
          ua::async::post_owning(&conn,
            conn.mExecutor,
            conn.mLogger,
            [owed, failure = std::move(failure)](ConnectionImpl&) mutable { (*owed)(std::move(failure)); })();
        }
      },
      [owed]() { (*owed)(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
  };
  pending.fail = [selfWeak = weak_from_this(), executor = mExecutor, logger = mLogger, owed](
                   ua::StatusCode status) mutable
  {
    // The gate is Closed / evicted / aged the op out: complete the owed callback on the executor.
    ua::Result<Response> result{status};
    if (auto self = selfWeak.lock())
    {
      ua::async::post_owning(self.get(),
        executor,
        logger,
        [owed, result = std::move(result)](ConnectionImpl&) mutable { (*owed)(std::move(result)); })();
    }
    else
    {
      (*owed)(std::move(result));
    }
  };

  mDispatch->submit_async(std::move(pending));
}

template<typename Response, typename IssueOnSession, typename CountOpened>
void ConnectionImpl::invoke_initial_continuation_op(OpenContinuationPointTracker& tracker,
  std::string operationTag, IssueOnSession issueOnSession, CountOpened countOpened,
  std::function<void(ua::Result<Response>)> callback, std::optional<std::uint32_t> requestHandle)
{
  auto userCallback = std::make_shared<std::function<void(ua::Result<Response>)>>(std::move(callback));
  auto finish = std::make_shared<std::function<void(ua::Result<Response>)>>(
    [weak = weak_from_this(),
      strand = mStrand,
      logger = mLogger,
      &tracker,
      countOpened = std::move(countOpened),
      userCallback](ua::Result<Response> result) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        (*userCallback)(ua::Result<Response>{ua::Status::BadConnectionClosed});
        return;
      }
      auto state = std::make_shared<ua::Result<Response>>(std::move(result));
      ua::async::post_borrowing_or_else(
        self.get(),
        strand,
        logger,
        [&tracker, countOpened, userCallback, state](ConnectionImpl& connection) mutable
        {
          tracker.complete_initial(state->is_good() ? countOpened(state->value()) : 0);
          ua::async::post_owning(&connection,
            connection.mExecutor,
            connection.mLogger,
            [userCallback, state](ConnectionImpl&) mutable { (*userCallback)(std::move(*state)); })();
        },
        [userCallback]() mutable
        { (*userCallback)(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
    });

  auto admission = [weak = weak_from_this(),
                     operationTag = std::move(operationTag),
                     issueOnSession = std::move(issueOnSession),
                     finish,
                     userCallback,
                     requestHandle](bool granted) mutable
  {
    auto self = weak.lock();
    if (!self)
    {
      (*userCallback)(ua::Result<Response>{ua::Status::BadConnectionClosed});
      return;
    }
    if (!granted)
    {
      ua::async::post_owning(self.get(),
        self->mExecutor,
        self->mLogger,
        [userCallback](ConnectionImpl&) mutable
        { (*userCallback)(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
      return;
    }
    self->invoke_wire_op<Response>(
      std::move(operationTag), std::move(issueOnSession), *finish, requestHandle);
  };

  if (tracker.acquire(std::move(admission)) == OpenContinuationPointTracker::AcquireResult::QueueFull)
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [userCallback](ConnectionImpl&) mutable
      {
        (*userCallback)(ua::Result<Response>{ua::Status::BadTooManyOperations,
          ua::make_error_detail("ContinuationPointAdmissionQueueFull",
            "the continuation-point admission queue reached its configured bound",
            "client.tier1.connection.continuation_points")});
      })();
  }
}

template<typename Response, typename IssueOnSession, typename CountOpened>
void ConnectionImpl::invoke_continuation_op(OpenContinuationPointTracker& tracker, std::size_t consumedPoints,
  std::string operationTag, IssueOnSession issueOnSession, CountOpened countOpened,
  std::function<void(ua::Result<Response>)> callback, std::optional<std::uint32_t> requestHandle)
{
  auto finish = [weak = weak_from_this(),
                  strand = mStrand,
                  logger = mLogger,
                  &tracker,
                  consumedPoints,
                  countOpened = std::move(countOpened),
                  callback = std::move(callback)](ua::Result<Response> result) mutable
  {
    auto self = weak.lock();
    if (!self)
    {
      callback(ua::Result<Response>{ua::Status::BadConnectionClosed});
      return;
    }
    auto state = std::make_shared<ua::Result<Response>>(std::move(result));
    ua::async::post_borrowing_or_else(
      self.get(),
      strand,
      logger,
      [&tracker, consumedPoints, countOpened, callback, state](ConnectionImpl& connection) mutable
      {
        if (state->is_good())
        {
          tracker.replace(consumedPoints, countOpened(state->value()));
        }
        ua::async::post_owning(&connection,
          connection.mExecutor,
          connection.mLogger,
          [callback, state](ConnectionImpl&) mutable { callback(std::move(*state)); })();
      },
      [callback]() mutable { callback(ua::Result<Response>{ua::Status::BadConnectionClosed}); })();
  };
  invoke_wire_op<Response>(
    std::move(operationTag), std::move(issueOnSession), std::move(finish), requestHandle);
}

void ConnectionImpl::read_async(
  ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept
{
  // Completion-owning strand entry: if this is already gone, the owed callback still fires (Bad).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::ReadResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::ReadResponse>)> completion) mutable
    {
      // Request input validation (CL-ATTR-003): a negative MaxAge is an invalid Read request. Reject
      // it in the managed read entry BEFORE it reaches the wire, rather than letting the server fault
      // it. This is request-shape validation, distinct from the tier-0 wire-op's raw response contract.
      if (request.max_age() < 0.0)
      {
        completion(ua::Result<ua::ReadResponse>{ua::Status::BadMaxAgeInvalid,
          ua::make_error_detail("ReadMaxAgeInvalid",
            "the Read request carries a negative MaxAge, which is invalid",
            "client.tier1.connection.read")});
        return;
      }

      // CL-BASE-003: honour the server's MaxNodesPerRead. A batch exceeding the limit is split into <= limit
      // sub-reads, each issued ON THE CONNECTION STRAND, and reassembled (results + diagnostic_infos +
      // header, input order) into one ReadResponse. STRAND: each chunk's wire op is driven from the PREVIOUS
      // chunk's completion, which arrives OFF the strand (invoke_wire_op hops onto the executor), so every
      // chunk re-hops via post_borrowing_or_else before invoke_wire_op reads strand-only mState (section 3.1
      // wf_380842af). ATOMIC to the caller: a chunk's transport/service failure, or a wrong per-chunk result
      // count, fails the whole logical Read.
      const std::uint32_t readLimit = self.mOperationLimits.maxNodesPerRead;
      if (readLimit != 0 && request.nodes_to_read().size() > readLimit)
      {
        std::vector<ua::ReadValueId> items{request.nodes_to_read().begin(), request.nodes_to_read().end()};
        const double maxAge = request.max_age();
        const auto timestamps = request.timestamps_to_return();
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::ReadValueId, ua::ReadResponse>(
          std::move(items),
          readLimit,
          [weak, maxAge, timestamps, header = std::move(header)](std::vector<ua::ReadValueId> chunk,
            std::function<void(ua::Result<ua::ReadResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::ReadResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [weak, chunk = std::move(chunk), chunkDone, header, maxAge, timestamps, expected](
                ConnectionImpl& connection) mutable
              {
                ua::ReadRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.max_age() = maxAge;
                chunkRequest.timestamps_to_return() = timestamps;
                chunkRequest.nodes_to_read() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::ReadResponse>(
                  "read",
                  [chunkRequest = std::move(chunkRequest), weak](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::ReadResponse>)>>
                      owed) mutable
                  {
                    if (auto aliasConn = weak.lock())
                    {
                      aliasConn->apply_alias_substitution(chunkRequest);
                    }
                    session.read_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::ReadResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::ReadResponse> readResult) mutable
                  {
                    if (!readResult.has_value())
                    {
                      chunkDone(
                        ua::Result<ua::ReadResponse>{readResult.status_code(), readResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = readResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::ReadResponse>{serviceResult});
                      return;
                    }
                    if (readResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::ReadResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("ReadChunkResultCountMismatch",
                          "a Read chunk returned a different number of results than the nodes requested",
                          "client.tier1.connection.read.chunk")});
                      return;
                    }
                    chunkDone(std::move(readResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::ReadResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](ua::Result<std::vector<ua::ReadResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::ReadResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::ReadResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::ReadResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::ReadResponse>(
        "read",
        [request = std::move(request), weak = self.weak_from_this()](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::ReadResponse>)>>
            owed) mutable
        {
          // CL-VIEW-009: substitute any cached RegisterNodes alias at DISPATCH time (on the connection
          // strand, after the session is (re)bound)  -  NOT at request build. A request queued across a
          // session-CHANGED reconnect must re-consult the session-scoped, now-cleared alias cache and send
          // the RAW NodeId, not a stale old-session alias the new session never issued (section 3.1). Strict
          // no-op when disabled.
          if (auto conn = weak.lock())
          {
            conn->apply_alias_substitution(request);
          }
          session.read_async(std::move(request),
            [owed](ua::Result<ua::ReadResponse> readResult) mutable { (*owed)(std::move(readResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::history_read_async(
  ua::HistoryReadRequest request, std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::HistoryReadResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::HistoryReadResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a HistoryRead exceeding the (conservative min of the) MaxNodesPerHistoryRead
      // Data/Events limits. Same strand-safe pattern as read_async; the non-array HistoryRead parameters
      // (details / timestamps / releaseContinuationPoints) are preserved on every chunk.
      const std::uint32_t historyReadLimit = effective_history_limit(
        self.mOperationLimits.maxNodesPerHistoryReadData, self.mOperationLimits.maxNodesPerHistoryReadEvents);
      if (historyReadLimit != 0 && request.nodes_to_read().size() > historyReadLimit)
      {
        std::vector<ua::HistoryReadValueId> items{
          request.nodes_to_read().begin(), request.nodes_to_read().end()};
        auto header = request.request_header();
        auto details = request.history_read_details();
        const auto timestamps = request.timestamps_to_return();
        const bool releaseContinuationPoints = request.release_continuation_points();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::HistoryReadValueId, ua::HistoryReadResponse>(
          std::move(items),
          historyReadLimit,
          [weak,
            header = std::move(header),
            details = std::move(details),
            timestamps,
            releaseContinuationPoints](std::vector<ua::HistoryReadValueId> chunk,
            std::function<void(ua::Result<ua::HistoryReadResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::HistoryReadResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [weak,
                chunk = std::move(chunk),
                chunkDone,
                header,
                details,
                timestamps,
                releaseContinuationPoints,
                expected](ConnectionImpl& connection) mutable
              {
                ua::HistoryReadRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.history_read_details() = details;
                chunkRequest.timestamps_to_return() = timestamps;
                chunkRequest.release_continuation_points() = releaseContinuationPoints;
                chunkRequest.nodes_to_read() = to_ua_array(std::move(chunk));
                const std::size_t consumedPoints =
                  static_cast<std::size_t>(std::count_if(chunkRequest.nodes_to_read().begin(),
                    chunkRequest.nodes_to_read().end(),
                    [](const ua::HistoryReadValueId& value) { return !value.continuation_point().empty(); }));
                auto issue = [chunkRequest = std::move(chunkRequest), weak](SessionOps& session,
                               std::shared_ptr<std::function<void(ua::Result<ua::HistoryReadResponse>)>>
                                 owed) mutable
                {
                  if (auto aliasConn = weak.lock())
                  {
                    aliasConn->apply_alias_substitution(chunkRequest);
                  }
                  session.history_read_async(std::move(chunkRequest),
                    [owed](ua::Result<ua::HistoryReadResponse> r) mutable { (*owed)(std::move(r)); });
                };
                auto onResult = [chunkDone, expected](
                                  ua::Result<ua::HistoryReadResponse> historyResult) mutable
                {
                  if (!historyResult.has_value())
                  {
                    chunkDone(ua::Result<ua::HistoryReadResponse>{
                      historyResult.status_code(), historyResult.shared_detail()});
                    return;
                  }
                  const auto serviceResult = historyResult.value().response_header().service_result();
                  if (serviceResult.is_bad())
                  {
                    chunkDone(ua::Result<ua::HistoryReadResponse>{serviceResult});
                    return;
                  }
                  if (historyResult.value().results().size() != expected)
                  {
                    chunkDone(ua::Result<ua::HistoryReadResponse>{ua::Status::BadUnexpectedError,
                      ua::make_error_detail("HistoryReadChunkResultCountMismatch",
                        "a HistoryRead chunk returned a different number of results than the nodes "
                        "requested",
                        "client.tier1.connection.history_read.chunk")});
                    return;
                  }
                  chunkDone(std::move(historyResult));
                };
                if (consumedPoints == 0)
                {
                  connection.invoke_initial_continuation_op<ua::HistoryReadResponse>(
                    connection.mHistoryContinuationPoints,
                    "history_read",
                    std::move(issue),
                    count_history_continuation_points,
                    std::move(onResult),
                    header.request_handle());
                }
                else
                {
                  connection.invoke_continuation_op<ua::HistoryReadResponse>(
                    connection.mHistoryContinuationPoints,
                    consumedPoints,
                    "history_read",
                    std::move(issue),
                    count_history_continuation_points,
                    std::move(onResult),
                    header.request_handle());
                }
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::HistoryReadResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::HistoryReadResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::HistoryReadResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::HistoryReadResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::HistoryReadResponse>{std::move(response)});
          });
        return;
      }

      const std::size_t consumedPoints =
        static_cast<std::size_t>(std::count_if(request.nodes_to_read().begin(),
          request.nodes_to_read().end(),
          [](const ua::HistoryReadValueId& value) { return !value.continuation_point().empty(); }));
      const auto requestHandle = request.request_header().request_handle();
      auto issue = [request = std::move(request), weak = self.weak_from_this()](SessionOps& session,
                     std::shared_ptr<std::function<void(ua::Result<ua::HistoryReadResponse>)>>
                       owed) mutable
      {
        // CL-VIEW-009: substitute at DISPATCH time (see the read path) so a queued request across a
        // session-CHANGED reconnect sends the raw NodeId, not a stale old-session alias (section 3.1).
        if (auto conn = weak.lock())
        {
          conn->apply_alias_substitution(request);
        }
        session.history_read_async(std::move(request),
          [owed](ua::Result<ua::HistoryReadResponse> historyResult) mutable
          { (*owed)(std::move(historyResult)); });
      };
      if (consumedPoints == 0)
      {
        self.invoke_initial_continuation_op<ua::HistoryReadResponse>(self.mHistoryContinuationPoints,
          "history_read",
          std::move(issue),
          count_history_continuation_points,
          std::move(completion),
          requestHandle);
      }
      else
      {
        self.invoke_continuation_op<ua::HistoryReadResponse>(self.mHistoryContinuationPoints,
          consumedPoints,
          "history_read",
          std::move(issue),
          count_history_continuation_points,
          std::move(completion),
          requestHandle);
      }
    })();
}

void ConnectionImpl::write_async(
  ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::WriteResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::WriteResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a Write exceeding MaxNodesPerWrite into <= limit sub-writes, reassembling the
      // per-item StatusCodes + diagnostics + header in input order. Same strand-safe pattern as read_async:
      // each chunk re-hops onto the strand (its completion arrives off-strand) before invoke_wire_op, and a
      // per-chunk result-count mismatch fails the whole atomic Write.
      const std::uint32_t writeLimit = self.mOperationLimits.maxNodesPerWrite;
      if (writeLimit != 0 && request.nodes_to_write().size() > writeLimit)
      {
        std::vector<ua::WriteValue> items{request.nodes_to_write().begin(), request.nodes_to_write().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::WriteValue, ua::WriteResponse>(
          std::move(items),
          writeLimit,
          [weak, header = std::move(header)](std::vector<ua::WriteValue> chunk,
            std::function<void(ua::Result<ua::WriteResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::WriteResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [weak, chunk = std::move(chunk), chunkDone, header, expected](
                ConnectionImpl& connection) mutable
              {
                ua::WriteRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.nodes_to_write() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::WriteResponse>(
                  "write",
                  [chunkRequest = std::move(chunkRequest), weak](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::WriteResponse>)>>
                      owed) mutable
                  {
                    if (auto aliasConn = weak.lock())
                    {
                      aliasConn->apply_alias_substitution(chunkRequest);
                    }
                    session.write_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::WriteResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::WriteResponse> writeResult) mutable
                  {
                    if (!writeResult.has_value())
                    {
                      chunkDone(ua::Result<ua::WriteResponse>{
                        writeResult.status_code(), writeResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = writeResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::WriteResponse>{serviceResult});
                      return;
                    }
                    if (writeResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::WriteResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("WriteChunkResultCountMismatch",
                          "a Write chunk returned a different number of results than the nodes requested",
                          "client.tier1.connection.write.chunk")});
                      return;
                    }
                    chunkDone(std::move(writeResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::WriteResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](ua::Result<std::vector<ua::WriteResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::WriteResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::WriteResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::WriteResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::WriteResponse>(
        "write",
        [request = std::move(request), weak = self.weak_from_this()](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::WriteResponse>)>>
            owed) mutable
        {
          // CL-VIEW-009: substitute at DISPATCH time (see the read path) so a queued request across a
          // session-CHANGED reconnect sends the raw NodeId, not a stale old-session alias (section 3.1).
          if (auto conn = weak.lock())
          {
            conn->apply_alias_substitution(request);
          }
          session.write_async(std::move(request),
            [owed](ua::Result<ua::WriteResponse> writeResult) mutable { (*owed)(std::move(writeResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::browse_async(
  ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::BrowseResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::BrowseResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a Browse exceeding MaxNodesPerBrowse into <= limit sub-browses, preserving the
      // non-array view + requestedMaxReferencesPerNode params per chunk and reassembling the per-node
      // BrowseResults in input order. Same strand-safe pattern as read_async (no alias substitution here).
      const std::uint32_t browseLimit = self.mOperationLimits.maxNodesPerBrowse;
      if (browseLimit != 0 && request.nodes_to_browse().size() > browseLimit)
      {
        std::vector<ua::BrowseDescription> items{
          request.nodes_to_browse().begin(), request.nodes_to_browse().end()};
        auto header = request.request_header();
        auto view = request.view();
        const auto maxReferences = request.requested_max_references_per_node();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::BrowseDescription, ua::BrowseResponse>(
          std::move(items),
          browseLimit,
          [weak, header = std::move(header), view = std::move(view), maxReferences](
            std::vector<ua::BrowseDescription> chunk,
            std::function<void(ua::Result<ua::BrowseResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::BrowseResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, view, maxReferences, expected](
                ConnectionImpl& connection) mutable
              {
                ua::BrowseRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.view() = view;
                chunkRequest.requested_max_references_per_node() = maxReferences;
                chunkRequest.nodes_to_browse() = to_ua_array(std::move(chunk));
                connection.invoke_initial_continuation_op<ua::BrowseResponse>(
                  connection.mBrowseContinuationPoints,
                  "browse",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::BrowseResponse>)>>
                      owed) mutable
                  {
                    session.browse_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::BrowseResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  count_browse_continuation_points,
                  [chunkDone, expected](ua::Result<ua::BrowseResponse> browseResult) mutable
                  {
                    if (!browseResult.has_value())
                    {
                      chunkDone(ua::Result<ua::BrowseResponse>{
                        browseResult.status_code(), browseResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = browseResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::BrowseResponse>{serviceResult});
                      return;
                    }
                    if (browseResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::BrowseResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("BrowseChunkResultCountMismatch",
                          "a Browse chunk returned a different number of results than the nodes requested",
                          "client.tier1.connection.browse.chunk")});
                      return;
                    }
                    chunkDone(std::move(browseResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::BrowseResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](ua::Result<std::vector<ua::BrowseResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::BrowseResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::BrowseResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::BrowseResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_initial_continuation_op<ua::BrowseResponse>(
        self.mBrowseContinuationPoints,
        "browse",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::BrowseResponse>)>>
            owed) mutable
        {
          session.browse_async(std::move(request),
            [owed](ua::Result<ua::BrowseResponse> browseResult) mutable
            { (*owed)(std::move(browseResult)); });
        },
        count_browse_continuation_points,
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::browse_next_async(
  ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::BrowseNextResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::BrowseNextResponse>)> completion) mutable
    {
      // CL-BASE-003: MaxNodesPerBrowse also caps the continuationPoints array on BrowseNext (Part 5
      // section 6.3.11). Chunk them the same strand-safe way, preserving the releaseContinuationPoints flag
      // per chunk.
      const std::uint32_t browseNextLimit = self.mOperationLimits.maxNodesPerBrowse;
      if (browseNextLimit != 0 && request.continuation_points().size() > browseNextLimit)
      {
        std::vector<ua::ContinuationPoint> items{
          request.continuation_points().begin(), request.continuation_points().end()};
        auto header = request.request_header();
        const bool releaseContinuationPoints = request.release_continuation_points();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::ContinuationPoint, ua::BrowseNextResponse>(
          std::move(items),
          browseNextLimit,
          [weak, header = std::move(header), releaseContinuationPoints](
            std::vector<ua::ContinuationPoint> chunk,
            std::function<void(ua::Result<ua::BrowseNextResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::BrowseNextResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, releaseContinuationPoints, expected](
                ConnectionImpl& connection) mutable
              {
                ua::BrowseNextRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.release_continuation_points() = releaseContinuationPoints;
                chunkRequest.continuation_points() = to_ua_array(std::move(chunk));
                connection.invoke_continuation_op<ua::BrowseNextResponse>(
                  connection.mBrowseContinuationPoints,
                  expected,
                  "browse_next",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::BrowseNextResponse>)>>
                      owed) mutable
                  {
                    session.browse_next_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::BrowseNextResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  count_browse_next_continuation_points,
                  [chunkDone, expected](ua::Result<ua::BrowseNextResponse> browseResult) mutable
                  {
                    if (!browseResult.has_value())
                    {
                      chunkDone(ua::Result<ua::BrowseNextResponse>{
                        browseResult.status_code(), browseResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = browseResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::BrowseNextResponse>{serviceResult});
                      return;
                    }
                    if (browseResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::BrowseNextResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("BrowseNextChunkResultCountMismatch",
                          "a BrowseNext chunk returned a different number of results than the continuation "
                          "points requested",
                          "client.tier1.connection.browse_next.chunk")});
                      return;
                    }
                    chunkDone(std::move(browseResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::BrowseNextResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](ua::Result<std::vector<ua::BrowseNextResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::BrowseNextResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::BrowseNextResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::BrowseNextResponse>{std::move(response)});
          });
        return;
      }

      const std::size_t consumedPoints = request.continuation_points().size();
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_continuation_op<ua::BrowseNextResponse>(
        self.mBrowseContinuationPoints,
        consumedPoints,
        "browse_next",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::BrowseNextResponse>)>>
            owed) mutable
        {
          session.browse_next_async(std::move(request),
            [owed](ua::Result<ua::BrowseNextResponse> browseResult) mutable
            { (*owed)(std::move(browseResult)); });
        },
        count_browse_next_continuation_points,
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::browse_next_on_session_async(std::uint64_t expectedSessionGeneration,
  ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::BrowseNextResponse>{ua::Status::BadConnectionClosed},
    [expectedSessionGeneration, request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::BrowseNextResponse>)> completion) mutable
    {
      if (self.mSessionGeneration->load(std::memory_order_relaxed) != expectedSessionGeneration)
      {
        completion(ua::Result<ua::BrowseNextResponse>{ua::Status::BadSessionIdInvalid,
          ua::make_error_detail("BrowseCursorSessionChanged",
            "the Browse continuation point belongs to a Session that has been replaced",
            "client.tier2.browse.session_binding")});
        return;
      }
      const std::size_t consumedPoints = request.continuation_points().size();
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_continuation_op<ua::BrowseNextResponse>(
        self.mBrowseContinuationPoints,
        consumedPoints,
        "browse_next",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::BrowseNextResponse>)>>
            owed) mutable
        {
          session.browse_next_async(std::move(request),
            [owed](ua::Result<ua::BrowseNextResponse> result) mutable { (*owed)(std::move(result)); });
        },
        count_browse_next_continuation_points,
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
  std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](ConnectionImpl& self,
      std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)>
        completion) mutable
    {
      // CL-BASE-003: chunk a TranslateBrowsePathsToNodeIds exceeding MaxNodesPerTranslateBrowsePathsToNodeIds
      // into <= limit sub-requests, reassembling the per-path BrowsePathResults + diagnostics + header in
      // input order. Same strand-safe pattern as read/write: each chunk re-hops onto the strand (its
      // completion arrives off-strand) before invoke_wire_op, and a per-chunk result-count mismatch fails
      // the whole atomic translate.
      const std::uint32_t translateLimit = self.mOperationLimits.maxNodesPerTranslateBrowsePathsToNodeIds;
      if (translateLimit != 0 && request.browse_paths().size() > translateLimit)
      {
        std::vector<ua::BrowsePath> items{request.browse_paths().begin(), request.browse_paths().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::BrowsePath, ua::TranslateBrowsePathsToNodeIdsResponse>(
          std::move(items),
          translateLimit,
          [weak, header = std::move(header)](std::vector<ua::BrowsePath> chunk,
            std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(
                ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                ua::TranslateBrowsePathsToNodeIdsRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.browse_paths() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::TranslateBrowsePathsToNodeIdsResponse>(
                  "translate_browse_paths",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<
                      std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)>>
                      owed) mutable
                  {
                    session.translate_browse_paths_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> r) mutable
                      { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](
                    ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> translateResult) mutable
                  {
                    if (!translateResult.has_value())
                    {
                      chunkDone(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{
                        translateResult.status_code(), translateResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = translateResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{serviceResult});
                      return;
                    }
                    if (translateResult.value().results().size() != expected)
                    {
                      chunkDone(
                        ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{ua::Status::BadUnexpectedError,
                          ua::make_error_detail("TranslateChunkResultCountMismatch",
                            "a TranslateBrowsePaths chunk returned a different number of results than the "
                            "paths requested",
                            "client.tier1.connection.translate.chunk")});
                      return;
                    }
                    chunkDone(std::move(translateResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable {
                chunkDone(
                  ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{ua::Status::BadConnectionClosed});
              })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::TranslateBrowsePathsToNodeIdsResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{
                merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::TranslateBrowsePathsToNodeIdsResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::TranslateBrowsePathsToNodeIdsResponse>(
        "translate_browse_paths",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)>>
            owed) mutable
        {
          session.translate_browse_paths_async(std::move(request),
            [owed](ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> translateResult) mutable
            { (*owed)(std::move(translateResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::call_async(
  ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::CallResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::CallResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a Call exceeding MaxNodesPerMethodCall into <= limit sub-calls, reassembling the
      // per-method results + diagnostics + header in input order. Same strand-safe pattern as read/write.
      const std::uint32_t callLimit = self.mOperationLimits.maxNodesPerMethodCall;
      if (callLimit != 0 && request.methods_to_call().size() > callLimit)
      {
        std::vector<ua::CallMethodRequest> items{
          request.methods_to_call().begin(), request.methods_to_call().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::CallMethodRequest, ua::CallResponse>(
          std::move(items),
          callLimit,
          [weak, header = std::move(header)](std::vector<ua::CallMethodRequest> chunk,
            std::function<void(ua::Result<ua::CallResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::CallResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [weak, chunk = std::move(chunk), chunkDone, header, expected](
                ConnectionImpl& connection) mutable
              {
                ua::CallRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.methods_to_call() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::CallResponse>(
                  "call",
                  [chunkRequest = std::move(chunkRequest), weak](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::CallResponse>)>>
                      owed) mutable
                  {
                    if (auto aliasConn = weak.lock())
                    {
                      aliasConn->apply_alias_substitution(chunkRequest);
                    }
                    session.call_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::CallResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::CallResponse> callResult) mutable
                  {
                    if (!callResult.has_value())
                    {
                      chunkDone(
                        ua::Result<ua::CallResponse>{callResult.status_code(), callResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = callResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::CallResponse>{serviceResult});
                      return;
                    }
                    if (callResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::CallResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("CallChunkResultCountMismatch",
                          "a Call chunk returned a different number of results than the methods requested",
                          "client.tier1.connection.call.chunk")});
                      return;
                    }
                    chunkDone(std::move(callResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::CallResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](ua::Result<std::vector<ua::CallResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::CallResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::CallResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::CallResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::CallResponse>(
        "call",
        [request = std::move(request), weak = self.weak_from_this()](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::CallResponse>)>>
            owed) mutable
        {
          // CL-VIEW-009: substitute at DISPATCH time (see the read path) so a queued request across a
          // session-CHANGED reconnect sends the raw NodeId, not a stale old-session alias (section 3.1).
          if (auto conn = weak.lock())
          {
            conn->apply_alias_substitution(request);
          }
          session.call_async(std::move(request),
            [owed](ua::Result<ua::CallResponse> callResult) mutable { (*owed)(std::move(callResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::cancel_async(
  ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::CancelResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::CancelResponse>)> completion) mutable
    {
      const std::uint32_t cancelledRequestHandle = request.request_handle();
      const auto outstanding = self.mOutstandingRequestsByHandle.find(cancelledRequestHandle);
      const std::size_t expectedCount =
        outstanding == self.mOutstandingRequestsByHandle.end() ? 0 : outstanding->second;
      auto weak = self.weak_from_this();
      self.invoke_wire_op<ua::CancelResponse>(
        "cancel",
        [request = std::move(request), weak, cancelledRequestHandle, expectedCount](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::CancelResponse>)>>
            owed) mutable
        {
          session.cancel_async(std::move(request),
            [owed, weak, cancelledRequestHandle, expectedCount](
              ua::Result<ua::CancelResponse> cancelResult) mutable
            {
              if (cancelResult.is_good())
              {
                const std::size_t actualCount = cancelResult.value().cancel_count();
                if (actualCount != expectedCount)
                {
                  if (auto connection = weak.lock())
                  {
                    std::unique_ptr<ua::ErrorDetail> detail =
                      ua::ErrorDetail::build("CancelCountMismatch",
                        "the server cancelCount differs from the number of matching outstanding requests",
                        "client.tier1.connection.cancel_count")
                        .context(ua::ContextKeys::requestHandle, std::to_string(cancelledRequestHandle))
                        .context(ua::ContextKeys::countExpected, std::to_string(expectedCount))
                        .context(ua::ContextKeys::countActual, std::to_string(actualCount));
                    connection->observer_sink()->fire_advisory_diagnostic(std::move(detail));
                  }
                }
              }
              (*owed)(std::move(cancelResult));
            });
        },
        std::move(completion));
    })();
}

void ConnectionImpl::register_nodes_async(ua::RegisterNodesRequest request,
  std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::RegisterNodesResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::RegisterNodesResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a RegisterNodes exceeding MaxNodesPerRegisterNodes. Each chunk installs its OWN
      // {requested -> registered} aliases (CL-VIEW-010), so the count-check (registered ids == requested
      // nodes) MUST run BEFORE the alias install - a mismatched/malicious response fails the whole atomic
      // call without poisoning the alias cache. The merge concatenates registered_node_ids in input order.
      const std::uint32_t registerLimit = self.mOperationLimits.maxNodesPerRegisterNodes;
      if (registerLimit != 0 && request.nodes_to_register().size() > registerLimit)
      {
        std::vector<ua::NodeId> items{request.nodes_to_register().begin(), request.nodes_to_register().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::NodeId, ua::RegisterNodesResponse>(
          std::move(items),
          registerLimit,
          [weak, header = std::move(header)](std::vector<ua::NodeId> chunk,
            std::function<void(ua::Result<ua::RegisterNodesResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::RegisterNodesResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                std::vector<ua::NodeId> requestedNodes;
                if (connection.mAddressSpaceCachePolicy.enabled &&
                    connection.mAddressSpaceCachePolicy.useRegisterNodes)
                {
                  requestedNodes.assign(chunk.begin(), chunk.end());
                }
                auto installing =
                  connection.install_aliases_on_register(std::move(requestedNodes), chunkDone);
                ua::RegisterNodesRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.nodes_to_register() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::RegisterNodesResponse>(
                  "register_nodes",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::RegisterNodesResponse>)>>
                      owed) mutable
                  {
                    session.register_nodes_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::RegisterNodesResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [installing = std::move(installing), chunkDone, expected](
                    ua::Result<ua::RegisterNodesResponse> registerResult) mutable
                  {
                    if (!registerResult.has_value())
                    {
                      chunkDone(ua::Result<ua::RegisterNodesResponse>{
                        registerResult.status_code(), registerResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = registerResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::RegisterNodesResponse>{serviceResult});
                      return;
                    }
                    if (registerResult.value().registered_node_ids().size() != expected)
                    {
                      chunkDone(ua::Result<ua::RegisterNodesResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("RegisterNodesChunkResultCountMismatch",
                          "a RegisterNodes chunk returned a different number of registered ids than the "
                          "nodes requested",
                          "client.tier1.connection.register_nodes.chunk")});
                      return;
                    }
                    // Count verified: install this chunk's aliases (the wrapper delivers to chunkDone).
                    installing(std::move(registerResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::RegisterNodesResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::RegisterNodesResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::RegisterNodesResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::RegisterNodesResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& id : chunkResponse.registered_node_ids())
              {
                response.registered_node_ids().push_back(std::move(id));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::RegisterNodesResponse>{std::move(response)});
          });
        return;
      }

      // CL-VIEW-010: snapshot the requested nodes BEFORE the request is moved to the wire, so the Good
      // response's registered aliases can be paired with them and installed into the alias cache. A strict
      // no-op when the cache is disabled (empty snapshot; install_aliases_on_register returns the completion
      // unchanged).
      const std::size_t expectedRegisteredNodeCount = request.nodes_to_register().size();
      std::vector<ua::NodeId> requestedNodes;
      if (self.mAddressSpaceCachePolicy.enabled && self.mAddressSpaceCachePolicy.useRegisterNodes)
      {
        requestedNodes.reserve(request.nodes_to_register().size());
        for (const auto& node : request.nodes_to_register())
        {
          requestedNodes.push_back(node);
        }
      }
      const auto requestHandle = request.request_header().request_handle();
      auto installing = self.install_aliases_on_register(std::move(requestedNodes), std::move(completion));
      self.invoke_wire_op<ua::RegisterNodesResponse>(
        "register_nodes",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::RegisterNodesResponse>)>>
            owed) mutable
        {
          session.register_nodes_async(std::move(request),
            [owed](ua::Result<ua::RegisterNodesResponse> registerResult) mutable
            { (*owed)(std::move(registerResult)); });
        },
        [installing = std::move(installing), expectedRegisteredNodeCount](
          ua::Result<ua::RegisterNodesResponse> registerResult) mutable
        {
          if (registerResult.is_good() &&
              registerResult.value().registered_node_ids().size() != expectedRegisteredNodeCount)
          {
            const std::size_t actualRegisteredNodeCount = registerResult.value().registered_node_ids().size();
            auto detail = std::shared_ptr<const ua::ErrorDetail>(
              ua::ErrorDetail::build("RegisterNodesResultCountMismatch",
                "RegisterNodes returned a different number of registered ids than requested",
                "client.tier1.connection.register_nodes")
                .context(ua::ContextKeys::sizeExpected, expectedRegisteredNodeCount)
                .context(ua::ContextKeys::sizeActual, actualRegisteredNodeCount));
            installing(ua::Result<ua::RegisterNodesResponse>{
              ua::StatusCode{ua::Status::BadUnexpectedError, std::move(detail)}});
            return;
          }
          installing(std::move(registerResult));
        },
        requestHandle);
    })();
}

void ConnectionImpl::unregister_nodes_async(ua::UnregisterNodesRequest request,
  std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::UnregisterNodesResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::UnregisterNodesResponse>)> completion) mutable
    {
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::UnregisterNodesResponse>(
        "unregister_nodes",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::UnregisterNodesResponse>)>>
            owed) mutable
        {
          session.unregister_nodes_async(std::move(request),
            [owed](ua::Result<ua::UnregisterNodesResponse> unregisterResult) mutable
            { (*owed)(std::move(unregisterResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::add_nodes_async(
  ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::AddNodesResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::AddNodesResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk an AddNodes exceeding MaxNodesPerNodeManagement into <= limit sub-requests,
      // reassembling the per-node AddNodesResults + diagnostics + header in input order. Same strand-safe
      // pattern as read/write: each chunk re-hops onto the strand (its completion arrives off-strand) before
      // invoke_wire_op, and a per-chunk result-count mismatch fails the whole atomic AddNodes.
      const std::uint32_t nodeManagementLimit = self.mOperationLimits.maxNodesPerNodeManagement;
      if (nodeManagementLimit != 0 && request.nodes_to_add().size() > nodeManagementLimit)
      {
        std::vector<ua::AddNodesItem> items{request.nodes_to_add().begin(), request.nodes_to_add().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::AddNodesItem, ua::AddNodesResponse>(
          std::move(items),
          nodeManagementLimit,
          [weak, header = std::move(header)](std::vector<ua::AddNodesItem> chunk,
            std::function<void(ua::Result<ua::AddNodesResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::AddNodesResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                ua::AddNodesRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.nodes_to_add() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::AddNodesResponse>(
                  "add_nodes",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::AddNodesResponse>)>>
                      owed) mutable
                  {
                    session.add_nodes_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::AddNodesResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::AddNodesResponse> addResult) mutable
                  {
                    if (!addResult.has_value())
                    {
                      chunkDone(
                        ua::Result<ua::AddNodesResponse>{addResult.status_code(), addResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = addResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::AddNodesResponse>{serviceResult});
                      return;
                    }
                    if (addResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::AddNodesResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("AddNodesChunkResultCountMismatch",
                          "an AddNodes chunk returned a different number of results than the nodes requested",
                          "client.tier1.connection.add_nodes.chunk")});
                      return;
                    }
                    chunkDone(std::move(addResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::AddNodesResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](ua::Result<std::vector<ua::AddNodesResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::AddNodesResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::AddNodesResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::AddNodesResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::AddNodesResponse>(
        "add_nodes",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::AddNodesResponse>)>>
            owed) mutable
        {
          session.add_nodes_async(std::move(request),
            [owed](ua::Result<ua::AddNodesResponse> addResult) mutable { (*owed)(std::move(addResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::add_references_async(ua::AddReferencesRequest request,
  std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::AddReferencesResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::AddReferencesResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk an AddReferences exceeding MaxNodesPerNodeManagement into <= limit sub-requests,
      // reassembling the per-reference StatusCodes + diagnostics + header in input order. Same strand-safe
      // pattern as read/write: each chunk re-hops onto the strand (its completion arrives off-strand) before
      // invoke_wire_op, and a per-chunk result-count mismatch fails the whole atomic AddReferences.
      const std::uint32_t nodeManagementLimit = self.mOperationLimits.maxNodesPerNodeManagement;
      if (nodeManagementLimit != 0 && request.references_to_add().size() > nodeManagementLimit)
      {
        std::vector<ua::AddReferencesItem> items{
          request.references_to_add().begin(), request.references_to_add().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::AddReferencesItem, ua::AddReferencesResponse>(
          std::move(items),
          nodeManagementLimit,
          [weak, header = std::move(header)](std::vector<ua::AddReferencesItem> chunk,
            std::function<void(ua::Result<ua::AddReferencesResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::AddReferencesResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                ua::AddReferencesRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.references_to_add() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::AddReferencesResponse>(
                  "add_references",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::AddReferencesResponse>)>>
                      owed) mutable
                  {
                    session.add_references_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::AddReferencesResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::AddReferencesResponse> addResult) mutable
                  {
                    if (!addResult.has_value())
                    {
                      chunkDone(ua::Result<ua::AddReferencesResponse>{
                        addResult.status_code(), addResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = addResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::AddReferencesResponse>{serviceResult});
                      return;
                    }
                    if (addResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::AddReferencesResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("AddReferencesChunkResultCountMismatch",
                          "an AddReferences chunk returned a different number of results than the references "
                          "requested",
                          "client.tier1.connection.add_references.chunk")});
                      return;
                    }
                    chunkDone(std::move(addResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::AddReferencesResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::AddReferencesResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::AddReferencesResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::AddReferencesResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::AddReferencesResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::AddReferencesResponse>(
        "add_references",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::AddReferencesResponse>)>>
            owed) mutable
        {
          session.add_references_async(std::move(request),
            [owed](ua::Result<ua::AddReferencesResponse> addResult) mutable
            { (*owed)(std::move(addResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::delete_nodes_async(
  ua::DeleteNodesRequest request, std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::DeleteNodesResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::DeleteNodesResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a DeleteNodes exceeding MaxNodesPerNodeManagement into <= limit sub-requests,
      // reassembling the per-node StatusCodes + diagnostics + header in input order. Same strand-safe
      // pattern as read/write: each chunk re-hops onto the strand (its completion arrives off-strand) before
      // invoke_wire_op, and a per-chunk result-count mismatch fails the whole atomic DeleteNodes.
      const std::uint32_t nodeManagementLimit = self.mOperationLimits.maxNodesPerNodeManagement;
      if (nodeManagementLimit != 0 && request.nodes_to_delete().size() > nodeManagementLimit)
      {
        std::vector<ua::DeleteNodesItem> items{
          request.nodes_to_delete().begin(), request.nodes_to_delete().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::DeleteNodesItem, ua::DeleteNodesResponse>(
          std::move(items),
          nodeManagementLimit,
          [weak, header = std::move(header)](std::vector<ua::DeleteNodesItem> chunk,
            std::function<void(ua::Result<ua::DeleteNodesResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::DeleteNodesResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                ua::DeleteNodesRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.nodes_to_delete() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::DeleteNodesResponse>(
                  "delete_nodes",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::DeleteNodesResponse>)>>
                      owed) mutable
                  {
                    session.delete_nodes_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::DeleteNodesResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::DeleteNodesResponse> deleteResult) mutable
                  {
                    if (!deleteResult.has_value())
                    {
                      chunkDone(ua::Result<ua::DeleteNodesResponse>{
                        deleteResult.status_code(), deleteResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = deleteResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::DeleteNodesResponse>{serviceResult});
                      return;
                    }
                    if (deleteResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::DeleteNodesResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("DeleteNodesChunkResultCountMismatch",
                          "a DeleteNodes chunk returned a different number of results than the nodes "
                          "requested",
                          "client.tier1.connection.delete_nodes.chunk")});
                      return;
                    }
                    chunkDone(std::move(deleteResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::DeleteNodesResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::DeleteNodesResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::DeleteNodesResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::DeleteNodesResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::DeleteNodesResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::DeleteNodesResponse>(
        "delete_nodes",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::DeleteNodesResponse>)>>
            owed) mutable
        {
          session.delete_nodes_async(std::move(request),
            [owed](ua::Result<ua::DeleteNodesResponse> deleteResult) mutable
            { (*owed)(std::move(deleteResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::delete_references_async(ua::DeleteReferencesRequest request,
  std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::DeleteReferencesResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::DeleteReferencesResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a DeleteReferences exceeding MaxNodesPerNodeManagement into <= limit
      // sub-requests, reassembling the per-reference StatusCodes + diagnostics + header in input order. Same
      // strand-safe pattern as read/write: each chunk re-hops onto the strand (its completion arrives
      // off-strand) before invoke_wire_op, and a per-chunk result-count mismatch fails the whole atomic
      // DeleteReferences.
      const std::uint32_t nodeManagementLimit = self.mOperationLimits.maxNodesPerNodeManagement;
      if (nodeManagementLimit != 0 && request.references_to_delete().size() > nodeManagementLimit)
      {
        std::vector<ua::DeleteReferencesItem> items{
          request.references_to_delete().begin(), request.references_to_delete().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::DeleteReferencesItem, ua::DeleteReferencesResponse>(
          std::move(items),
          nodeManagementLimit,
          [weak, header = std::move(header)](std::vector<ua::DeleteReferencesItem> chunk,
            std::function<void(ua::Result<ua::DeleteReferencesResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::DeleteReferencesResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                ua::DeleteReferencesRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.references_to_delete() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::DeleteReferencesResponse>(
                  "delete_references",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::DeleteReferencesResponse>)>>
                      owed) mutable
                  {
                    session.delete_references_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::DeleteReferencesResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::DeleteReferencesResponse> deleteResult) mutable
                  {
                    if (!deleteResult.has_value())
                    {
                      chunkDone(ua::Result<ua::DeleteReferencesResponse>{
                        deleteResult.status_code(), deleteResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = deleteResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::DeleteReferencesResponse>{serviceResult});
                      return;
                    }
                    if (deleteResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::DeleteReferencesResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("DeleteReferencesChunkResultCountMismatch",
                          "a DeleteReferences chunk returned a different number of results than the "
                          "references requested",
                          "client.tier1.connection.delete_references.chunk")});
                      return;
                    }
                    chunkDone(std::move(deleteResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::DeleteReferencesResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::DeleteReferencesResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(
                ua::Result<ua::DeleteReferencesResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::DeleteReferencesResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::DeleteReferencesResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::DeleteReferencesResponse>(
        "delete_references",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::DeleteReferencesResponse>)>>
            owed) mutable
        {
          session.delete_references_async(std::move(request),
            [owed](ua::Result<ua::DeleteReferencesResponse> deleteResult) mutable
            { (*owed)(std::move(deleteResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::history_update_async(ua::HistoryUpdateRequest request,
  std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::HistoryUpdateResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::HistoryUpdateResponse>)> completion) mutable
    {
      // CL-BASE-003: chunk a HistoryUpdate exceeding the (conservative min of the) MaxNodesPerHistoryUpdate
      // Data/Events limits. Same strand-safe pattern as delete_nodes (no alias substitution).
      const std::uint32_t historyUpdateLimit =
        effective_history_limit(self.mOperationLimits.maxNodesPerHistoryUpdateData,
          self.mOperationLimits.maxNodesPerHistoryUpdateEvents);
      if (historyUpdateLimit != 0 && request.history_update_details().size() > historyUpdateLimit)
      {
        std::vector<ua::RefStructure<ua::Structure>> items{
          request.history_update_details().begin(), request.history_update_details().end()};
        auto header = request.request_header();
        auto weak = self.weak_from_this();
        chunk_batch_async<ua::RefStructure<ua::Structure>, ua::HistoryUpdateResponse>(
          std::move(items),
          historyUpdateLimit,
          [weak, header = std::move(header)](std::vector<ua::RefStructure<ua::Structure>> chunk,
            std::function<void(ua::Result<ua::HistoryUpdateResponse>)>
              chunkDone) mutable
          {
            auto conn = weak.lock();
            if (!conn)
            {
              chunkDone(ua::Result<ua::HistoryUpdateResponse>{ua::Status::BadConnectionClosed});
              return;
            }
            const std::size_t expected = chunk.size();
            ua::async::post_borrowing_or_else(
              conn.get(),
              conn->mStrand,
              conn->mLogger,
              [chunk = std::move(chunk), chunkDone, header, expected](ConnectionImpl& connection) mutable
              {
                ua::HistoryUpdateRequest chunkRequest;
                chunkRequest.request_header() = header;
                chunkRequest.history_update_details() = to_ua_array(std::move(chunk));
                connection.invoke_wire_op<ua::HistoryUpdateResponse>(
                  "history_update",
                  [chunkRequest = std::move(chunkRequest)](SessionOps& session,
                    std::shared_ptr<std::function<void(ua::Result<ua::HistoryUpdateResponse>)>>
                      owed) mutable
                  {
                    session.history_update_async(std::move(chunkRequest),
                      [owed](ua::Result<ua::HistoryUpdateResponse> r) mutable { (*owed)(std::move(r)); });
                  },
                  [chunkDone, expected](ua::Result<ua::HistoryUpdateResponse> historyResult) mutable
                  {
                    if (!historyResult.has_value())
                    {
                      chunkDone(ua::Result<ua::HistoryUpdateResponse>{
                        historyResult.status_code(), historyResult.shared_detail()});
                      return;
                    }
                    const auto serviceResult = historyResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::HistoryUpdateResponse>{serviceResult});
                      return;
                    }
                    if (historyResult.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::HistoryUpdateResponse>{ua::Status::BadUnexpectedError,
                        ua::make_error_detail("HistoryUpdateChunkResultCountMismatch",
                          "a HistoryUpdate chunk returned a different number of results than the details "
                          "requested",
                          "client.tier1.connection.history_update.chunk")});
                      return;
                    }
                    chunkDone(std::move(historyResult));
                  },
                  header.request_handle());
              },
              [chunkDone]() mutable
              { chunkDone(ua::Result<ua::HistoryUpdateResponse>{ua::Status::BadConnectionClosed}); })();
          },
          [completion = std::move(completion)](
            ua::Result<std::vector<ua::HistoryUpdateResponse>> merged) mutable
          {
            if (!merged.has_value())
            {
              completion(ua::Result<ua::HistoryUpdateResponse>{merged.status_code(), merged.shared_detail()});
              return;
            }
            ua::HistoryUpdateResponse response;
            bool headerCarried = false;
            for (auto& chunkResponse : merged.value())
            {
              for (auto& value : chunkResponse.results())
              {
                response.results().push_back(std::move(value));
              }
              for (auto& diagnostic : chunkResponse.diagnostic_infos())
              {
                response.diagnostic_infos().push_back(std::move(diagnostic));
              }
              merge_chunk_response_header(
                response.response_header(), chunkResponse.response_header(), headerCarried);
            }
            completion(ua::Result<ua::HistoryUpdateResponse>{std::move(response)});
          });
        return;
      }

      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::HistoryUpdateResponse>(
        "history_update",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::HistoryUpdateResponse>)>>
            owed) mutable
        {
          session.history_update_async(std::move(request),
            [owed](ua::Result<ua::HistoryUpdateResponse> historyResult) mutable
            { (*owed)(std::move(historyResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::set_monitoring_mode_async(ua::SetMonitoringModeRequest request,
  std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::SetMonitoringModeResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> completion) mutable
    {
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::SetMonitoringModeResponse>(
        "set_monitoring_mode",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::SetMonitoringModeResponse>)>>
            owed) mutable
        {
          session.set_monitoring_mode_async(std::move(request),
            [owed](ua::Result<ua::SetMonitoringModeResponse> monitoringResult) mutable
            { (*owed)(std::move(monitoringResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::modify_monitored_items_async(ua::ModifyMonitoredItemsRequest request,
  std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::ModifyMonitoredItemsResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](ConnectionImpl& self,
      std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)>
        completion) mutable
    {
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::ModifyMonitoredItemsResponse>(
        "modify_monitored_items",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)>>
            owed) mutable
        {
          session.modify_monitored_items_async(std::move(request),
            [owed](ua::Result<ua::ModifyMonitoredItemsResponse> modifyResult) mutable
            { (*owed)(std::move(modifyResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::set_triggering_async(ua::SetTriggeringRequest request,
  std::function<void(ua::Result<ua::SetTriggeringResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::SetTriggeringResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::SetTriggeringResponse>)> completion) mutable
    {
      // CL-SUB-022: SetTriggering is meaningless on a polled-Read fallback (server-less) Subscription  -
      // there is no server-side Subscription to call SetTriggering against. Reject inline with
      // Bad_FilterNotAllowed (the closest-fit status), issuing NO wire request.
      if (self.mFallbackSubscriptions.find(request.subscription_id()) != self.mFallbackSubscriptions.end())
      {
        ua::async::post_owning(&self,
          self.mExecutor,
          self.mLogger,
          [completion = std::move(completion)](ConnectionImpl&) mutable
          {
            completion(ua::Result<ua::SetTriggeringResponse>{ua::Status::BadFilterNotAllowed,
              ua::make_error_detail("FallbackSetTriggeringUnsupported",
                "SetTriggering is not supported on a polled-Read fallback Subscription (no server "
                "Subscription "
                "exists)",
                "client.tier1.subscription_fallback.set_triggering")});
          })();
        return;
      }
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_wire_op<ua::SetTriggeringResponse>(
        "set_triggering",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::SetTriggeringResponse>)>>
            owed) mutable
        {
          session.set_triggering_async(std::move(request),
            [owed](ua::Result<ua::SetTriggeringResponse> triggeringResult) mutable
            { (*owed)(std::move(triggeringResult)); });
        },
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::query_first_async(
  ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::QueryFirstResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::QueryFirstResponse>)> completion) mutable
    {
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_initial_continuation_op<ua::QueryFirstResponse>(
        self.mQueryContinuationPoints,
        "query_first",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::QueryFirstResponse>)>>
            owed) mutable
        {
          session.query_first_async(std::move(request),
            [owed](ua::Result<ua::QueryFirstResponse> queryResult) mutable
            { (*owed)(std::move(queryResult)); });
        },
        count_query_first_continuation_points,
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::query_next_async(
  ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::QueryNextResponse>{ua::Status::BadConnectionClosed},
    [request = std::move(request)](
      ConnectionImpl& self, std::function<void(ua::Result<ua::QueryNextResponse>)> completion) mutable
    {
      const std::size_t consumedPoints = request.continuation_point().empty() ? 0 : 1;
      const auto requestHandle = request.request_header().request_handle();
      self.invoke_continuation_op<ua::QueryNextResponse>(
        self.mQueryContinuationPoints,
        consumedPoints,
        "query_next",
        [request = std::move(request)](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::QueryNextResponse>)>>
            owed) mutable
        {
          session.query_next_async(std::move(request),
            [owed](ua::Result<ua::QueryNextResponse> queryResult) mutable
            { (*owed)(std::move(queryResult)); });
        },
        count_query_next_continuation_points,
        std::move(completion),
        requestHandle);
    })();
}

void ConnectionImpl::delete_subscription_async(std::uint32_t subscriptionId,
  std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::DeleteSubscriptionsResponse>{ua::Status::BadConnectionClosed},
    [subscriptionId](ConnectionImpl& self,
      std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)>
        completion) mutable
    {
      // CL-SUB-019: a fallback (server-less) Subscription has NO wire DeleteSubscriptions  -  tear it down
      // locally (drop it from the fallback registry; the pipeline erase cancels its poll timer + purges its
      // items; unregister owner routing) and complete GOOD with a synthesised single-result response.
      const auto fallback = self.mFallbackSubscriptions.find(subscriptionId);
      if (fallback != self.mFallbackSubscriptions.end())
      {
        self.mFallbackSubscriptions.erase(fallback);
        self.mSubscriptionTuning.erase(subscriptionId);
        self.mPipeline->remove_subscription_async(subscriptionId);
        if (self.mMonitoredItemOwner)
        {
          self.mMonitoredItemOwner->unregister_subscription(subscriptionId);
        }
        ua::async::post_owning(&self,
          self.mExecutor,
          self.mLogger,
          [completion = std::move(completion)](ConnectionImpl&) mutable
          {
            ua::DeleteSubscriptionsResponse response;
            response.results().push_back(ua::StatusCode{ua::Status::Good});
            completion(ua::Result<ua::DeleteSubscriptionsResponse>{std::move(response)});
          })();
        return;
      }
      // On service success the Subscription is gone server-side: deregister it from the pipeline so its
      // sequence tracking + acks stop, AND purge every owner-routing entry it owned so a closed Subscription
      // does not leak self-action routing (WARNING 3). Runs on the executor (the wire completion); the
      // pipeline hop is its own strand-safe post and the owner purge takes its mutex once. A failed delete
      // leaves it tracked (it may still be alive server-side).
      auto pipeline = self.mPipeline;
      auto owner = self.mMonitoredItemOwner;
      auto wrapped = [pipeline,
                       owner,
                       subscriptionId,
                       weakSelf = self.weak_from_this(),
                       completion = std::move(completion)](
                       ua::Result<ua::DeleteSubscriptionsResponse> result) mutable
      {
        if (result.is_good() && result.value().response_header().service_result().is_good())
        {
          pipeline->remove_subscription_async(subscriptionId);
          if (owner)
          {
            owner->unregister_subscription(subscriptionId);
          }
          if (auto strong = weakSelf.lock())
          {
            strong->forget_subscription_tuning(subscriptionId);
          }
        }
        completion(std::move(result));
      };
      self.invoke_wire_op<ua::DeleteSubscriptionsResponse>(
        "delete_subscription",
        [subscriptionId](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)>>
            owed) mutable
        {
          ua::DeleteSubscriptionsRequest request;
          request.subscription_ids().push_back(subscriptionId);
          session.delete_subscriptions_async(std::move(request),
            [owed](ua::Result<ua::DeleteSubscriptionsResponse> deleteResult) mutable
            { (*owed)(std::move(deleteResult)); });
        },
        std::move(wrapped));
    })();
}

void ConnectionImpl::delete_monitored_item_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
  std::uint32_t clientHandle,
  std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::DeleteMonitoredItemsResponse>{ua::Status::BadConnectionClosed},
    [subscriptionId, monitoredItemId, clientHandle](ConnectionImpl& self,
      std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)>
        completion) mutable
    {
      // When the server answers that the item is deleted, it is gone server-side: deregister its client
      // handle so later notifications for it are dropped (advisory) rather than dispatched to a stale
      // callback. The item is deleted for the same answers the MonitoredItem handle's owner unregisters it on
      // (DataChangeMonitoredItemOwner::mi_delete_async): the answer holds the response, neither the Result's
      // code nor the ServiceResult is Bad (ua::detail::combined_status), and the response holds the item's
      // result, which is not Bad. A Good subcode or an Uncertain code on any of them counts as deleted.
      auto pipeline = self.mPipeline;
      auto wrapped = [pipeline, clientHandle, completion = std::move(completion)](
                       ua::Result<ua::DeleteMonitoredItemsResponse> result) mutable
      {
        bool deleted = false;
        if (result.has_value())
        {
          const auto& response = result.value();
          const ua::StatusCode serviceResult =
            ua::detail::combined_status(result.status_code(), response.response_header().service_result());
          deleted = !serviceResult.is_bad() && response.results().size() != 0 &&
                    !ua::detail::combined_status(serviceResult, response.results()[0]).is_bad();
        }
        if (deleted)
        {
          pipeline->remove_monitored_item_async(clientHandle);
        }
        completion(std::move(result));
      };
      self.invoke_wire_op<ua::DeleteMonitoredItemsResponse>(
        "delete_monitored_item",
        [subscriptionId, monitoredItemId](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)>>
            owed) mutable
        {
          ua::DeleteMonitoredItemsRequest request;
          request.subscription_id() = subscriptionId;
          request.monitored_item_ids().push_back(monitoredItemId);
          session.delete_monitored_items_async(std::move(request),
            [owed](ua::Result<ua::DeleteMonitoredItemsResponse> deleteResult) mutable
            { (*owed)(std::move(deleteResult)); });
        },
        std::move(wrapped));
    })();
}

void ConnectionImpl::modify_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
  std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) noexcept
{
  modify_subscription_async(subscriptionId,
    publishingInterval,
    std::nullopt,
    std::nullopt,
    std::nullopt,
    std::nullopt,
    std::move(callback));
}

void ConnectionImpl::modify_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
  std::optional<std::uint32_t> lifetimeCount, std::optional<std::uint32_t> maxKeepAliveCount,
  std::optional<std::uint8_t> priority, std::optional<std::uint32_t> maxNotificationsPerPublish,
  std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::ModifySubscriptionResponse>{ua::Status::BadConnectionClosed},
    [subscriptionId,
      publishingInterval,
      lifetimeCount,
      maxKeepAliveCount,
      priority,
      maxNotificationsPerPublish](ConnectionImpl& self,
      std::function<void(ua::Result<ua::ModifySubscriptionResponse>)>
        completion) mutable
    {
      // CL-SUB-013: a ModifySubscription whose service_result is Bad_SubscriptionIdInvalid means the
      // Subscription is gone server-side (deleted or lifetime-expired)  -  drop the stale local record so its
      // sequence tracking + acks stop and its owner-routing entries are purged (mirrors DeleteSubscription's
      // deregister-on-terminal; the Republish drain already erases on this status, section 8.4.5). NO retry,
      // and a TRANSIENT bad (timeout / connection / Bad_TooManyOperations) keeps the record  -  it may still
      // be alive server-side; only the authoritative Bad_SubscriptionIdInvalid is a definitive "gone".
      // remove_ subscription_async is idempotent, so a stale completion that lands after a session-CHANGED
      // recreate re-keyed the id removes a no-longer-present old id harmlessly (no live-record clobber).
      // Resolve the parameter set to send: the caller's stated fields over the values retained at create
      // (or at the last successful modify). An absent record means the SDK defaults, which is right for a
      // Subscription this Connection never created.
      const auto retained = self.mSubscriptionTuning.find(subscriptionId);
      const SubscriptionTuning resolved = resolve_subscription_tuning(
        retained != self.mSubscriptionTuning.end() ? retained->second : SubscriptionTuning{},
        lifetimeCount,
        maxKeepAliveCount,
        priority,
        maxNotificationsPerPublish);
      auto pipeline = self.mPipeline;
      auto owner = self.mMonitoredItemOwner;
      auto wrapped = [pipeline,
                       owner,
                       subscriptionId,
                       publishingInterval,
                       resolved,
                       weakSelf = self.weak_from_this(),
                       completion = std::move(completion)](
                       ua::Result<ua::ModifySubscriptionResponse> result) mutable
      {
        // CL-DIAG-005 coexistence: the funnel now COLLAPSES a bad serviceResult to a bad Result (with the
        // wire marker attached), so the effective service status is on result.status_code() on the bad path
        // and on the header on the good path. Read it from both, or the BadSubscriptionIdInvalid drop below
        // never fires post-collapse (it would silently regress CL-SUB-012).
        const ua::StatusCode serviceResult =
          !result.has_value() ? result.status_code() : result.value().response_header().service_result();
        if (serviceResult.as_status() == ua::Status::BadSubscriptionIdInvalid)
        {
          pipeline->remove_subscription_async(subscriptionId);
          if (owner)
          {
            owner->unregister_subscription(subscriptionId);
          }
          if (auto strong = weakSelf.lock())
          {
            strong->forget_subscription_tuning(subscriptionId);  // the Subscription is authoritatively gone
          }
        }
        else if (result.has_value() && !serviceResult.is_bad())
        {
          // A Good answer, or an Uncertain one holding the response the caller receives, is followed as the
          // Subscription handle follows it.
          // CL-SUB-013: a successful modify changed the publishing interval  -  refresh the pipeline's
          // RETAINED interval so a session-CHANGED recreate replays the modified value, not the stale
          // create-time one (section 3.1: otherwise the reconnect silently reverts the user's modify).
          // Retains the REQUESTED interval (consistent with create's retain-requested convention; the server
          // re-revises it on recreate).
          pipeline->update_publishing_interval_async(subscriptionId, publishingInterval);
          // The server now holds the resolved set - retain it, or the NEXT modify (and the recreate) would
          // fold the caller's next field over the pre-modify values and quietly undo this one.
          if (auto strong = weakSelf.lock())
          {
            strong->retain_subscription_tuning(subscriptionId, resolved);
          }
        }
        completion(std::move(result));
      };
      self.invoke_wire_op<ua::ModifySubscriptionResponse>(
        "modify_subscription",
        [subscriptionId, publishingInterval, resolved](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::ModifySubscriptionResponse>)>>
            owed) mutable
        {
          // ModifySubscription replaces the WHOLE parameter set (OPC 10000-4 section 5.13.3.1), so every
          // parameter is re-sent from the resolved tuning - the caller's stated fields over the values
          // retained at create. A parameter omitted here is not left alone by the server, it is reset,
          // and the server reports success either way.
          ua::ModifySubscriptionRequest request;
          request.subscription_id() = subscriptionId;
          request.requested_publishing_interval() = publishingInterval;
          request.requested_lifetime_count() = resolved.lifetimeCount;
          request.requested_max_keep_alive_count() = resolved.maxKeepAliveCount;
          request.max_notifications_per_publish() = resolved.maxNotificationsPerPublish;
          request.priority() = resolved.priority;
          session.modify_subscription_async(std::move(request),
            [owed](ua::Result<ua::ModifySubscriptionResponse> modifyResult) mutable
            { (*owed)(std::move(modifyResult)); });
        },
        std::move(wrapped));
    })();
}

void ConnectionImpl::adjust_max_notifications_per_publish_async(std::uint32_t subscriptionId,
  double publishingInterval, std::uint32_t maxNotificationsPerPublish,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [subscriptionId, publishingInterval, maxNotificationsPerPublish](
      ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // This is a ModifySubscription too, so it replaces the whole parameter set as well: re-send the
      // retained tuning, or adjusting the notification cap would reset everything else the caller tuned.
      // The new cap is retained ON SUCCESS below, so a LATER user modify re-sends the adjusted value rather
      // than reinstating the create-time one.
      const auto entry = self.mSubscriptionTuning.find(subscriptionId);
      const SubscriptionTuning retained =
        entry != self.mSubscriptionTuning.end() ? entry->second : SubscriptionTuning{};
      self.invoke_wire_op<ua::ModifySubscriptionResponse>(
        "adjust_max_notifications_per_publish",
        [subscriptionId, publishingInterval, maxNotificationsPerPublish, retained](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::ModifySubscriptionResponse>)>>
            owed) mutable
        {
          ua::ModifySubscriptionRequest request;
          request.subscription_id() = subscriptionId;
          request.requested_publishing_interval() = publishingInterval;
          request.requested_lifetime_count() = retained.lifetimeCount;
          request.requested_max_keep_alive_count() = retained.maxKeepAliveCount;
          request.max_notifications_per_publish() = maxNotificationsPerPublish;
          request.priority() = retained.priority;
          session.modify_subscription_async(std::move(request),
            [owed](ua::Result<ua::ModifySubscriptionResponse> modifyResult) mutable
            { (*owed)(std::move(modifyResult)); });
        },
        [subscriptionId,
          maxNotificationsPerPublish,
          retained,
          weakSelf = self.weak_from_this(),
          completion = std::move(completion)](ua::Result<ua::ModifySubscriptionResponse> result) mutable
        {
          // The pipeline applies the new cap for the answer this completes with when that is not Bad, and the
          // tuning retained here follows the same answers: a Good one, or an Uncertain one holding the
          // response. An Uncertain answer without a response is refused, and a Bad one passed on, so neither
          // changes the cap.
          if (!result.has_value())
          {
            completion(ua::VoidResult{ua::client::detail::answer_refused(
              result.status_code(), "ServiceAnswerUncertain", "client.connection.adjust_max_notifications")});
            return;
          }
          if (auto strong = weakSelf.lock())
          {
            SubscriptionTuning updated = retained;
            updated.maxNotificationsPerPublish = maxNotificationsPerPublish;
            strong->retain_subscription_tuning(subscriptionId, updated);
          }
          // The funnel turned a Bad ServiceResult into a Bad Result; a Good subcode or an Uncertain one is
          // kept.
          completion(ua::VoidResult{result.value().response_header().service_result()});
        });
    })();
}

void ConnectionImpl::set_publishing_mode_async(std::uint32_t subscriptionId, bool publishingEnabled,
  std::function<void(ua::Result<ua::SetPublishingModeResponse>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<ua::SetPublishingModeResponse>{ua::Status::BadConnectionClosed},
    [subscriptionId, publishingEnabled](
      ConnectionImpl& self, std::function<void(ua::Result<ua::SetPublishingModeResponse>)> completion) mutable
    {
      self.invoke_wire_op<ua::SetPublishingModeResponse>(
        "set_publishing_mode",
        [subscriptionId, publishingEnabled](SessionOps& session,
          std::shared_ptr<std::function<void(ua::Result<ua::SetPublishingModeResponse>)>>
            owed) mutable
        {
          ua::SetPublishingModeRequest request;
          request.publishing_enabled() = publishingEnabled;
          request.subscription_ids().push_back(subscriptionId);
          session.set_publishing_mode_async(std::move(request),
            [owed](ua::Result<ua::SetPublishingModeResponse> modeResult) mutable
            { (*owed)(std::move(modeResult)); });
        },
        std::move(completion));
    })();
}

void ConnectionImpl::create_subscription_async(
  double publishingInterval, std::function<void(ua::Result<std::uint32_t>)> callback) noexcept
{
  // Completion-owning strand entry: a gone orchestrator still fires the owed callback (Bad).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<std::uint32_t>{ua::Status::BadConnectionClosed},
    [publishingInterval](
      ConnectionImpl& self, std::function<void(ua::Result<std::uint32_t>)> completion) mutable
    { self.begin_create_subscription(publishingInterval, std::move(completion)); })();
}

void ConnectionImpl::begin_create_subscription(
  double publishingInterval, std::function<void(ua::Result<std::uint32_t>)> completion)
{
  // Gate exactly like a wire op: a non-Active state fast-fails WITHOUT touching mSessionOps (a service-set
  // accessor on a closed session blocks, section 8.2A.3). Deliver the rejection on the executor, never
  // inline.
  if (mState != ConnectionState::Active)
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [completion = std::move(completion)](ConnectionImpl&) mutable
      { completion(ua::Result<std::uint32_t>{ua::Status::BadConnectionClosed}); })();
    return;
  }

  // Active: order the op through the session interface and snapshot the pipeline handle. The completion
  // captures the pipeline STRONGLY so it survives a racing orchestrator teardown; it never reaches back
  // into this orchestrator's state (no cycle, no dangling).
  auto pipeline = mPipeline;
  mSessionOps->create_subscription_async(build_create_subscription_request(publishingInterval),
    [pipeline = std::move(pipeline),
      publishingInterval,
      completion = std::move(completion),
      namespaceTable = namespace_table_snapshot()](ua::Result<ua::CreateSubscriptionResponse> result) mutable
    {
      // Runs on the executor (the tier-0 service delivers there).
      if (!result.has_value())
      {
        completion(ua::Result<std::uint32_t>{result.status_code()});
        return;
      }
      const auto& response = result.value();
      const auto serviceResult = response.response_header().service_result();
      if (serviceResult.is_bad())
      {
        // CL-DIAG-005: this managed path does not flow through invoke_wire_op, so attach the wire marker
        // here. CL-DIAG-007: tag a server NamespaceURI using the snapshot captured at issue time (the array
        // is appends-only within a session, so membership is stable), consistent with the funnel path.
        completion(ua::Result<std::uint32_t>{serviceResult,
          ua::client::detail::attach_wire_marker(response.response_header(), 32, namespaceTable)});
        return;
      }
      const std::uint32_t subscriptionId = response.subscription_id();
      // Retain the publishing interval in the pipeline so a session-CHANGED reconnect can recreate the
      // Subscription (section 6.7, Q5 - the pipeline is the single owner of the recreate params).
      pipeline->add_subscription_async(subscriptionId,
        publishingInterval,
        0,
        [pipeline, subscriptionId, serviceResult, completion = std::move(completion)](
          ua::VoidResult registrationResult) mutable
        {
          if (registrationResult.is_bad())
          {
            completion(ua::Result<std::uint32_t>{registrationResult.status_code()});
            return;
          }
          pipeline->start_async();  // starts the always-on Publish pump
          // The Subscription exists: a Good subcode or an Uncertain ServiceResult stays with its id.
          completion(ua::detail::held(subscriptionId, serviceResult));
        });
    });
}

void ConnectionImpl::create_monitored_item_async(std::uint32_t subscriptionId, ua::NodeId node,
  std::uint32_t clientHandle, std::function<void(ua::DataValue)> onData,
  std::function<void(ua::Result<std::uint32_t>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<std::uint32_t>{ua::Status::BadConnectionClosed},
    [subscriptionId, node = std::move(node), clientHandle, onData = std::move(onData)](
      ConnectionImpl& self, std::function<void(ua::Result<std::uint32_t>)> completion) mutable
    {
      // This id-only accessor ignores the revised sampling interval the create outcome also carries; map
      // the CreatedMonitoredItem outcome down to the server monitored-item id (or forward the failure with
      // its ErrorDetail intact).
      self.begin_create_monitored_item(subscriptionId,
        std::move(node),
        clientHandle,
        std::move(onData),
        [completion = std::move(completion)](ua::Result<CreatedMonitoredItem> outcome) mutable
        {
          if (!outcome.has_value())
          {
            completion(ua::Result<std::uint32_t>{outcome.status_code(), outcome.shared_detail()});
            return;
          }
          completion(ua::detail::held(outcome.value().monitoredItemId, outcome.status_code()));
        });
    })();
}

void ConnectionImpl::begin_create_monitored_item(std::uint32_t subscriptionId, ua::NodeId node,
  std::uint32_t clientHandle, std::function<void(ua::DataValue)> onData,
  std::function<void(ua::Result<CreatedMonitoredItem>)> completion, ua::AttributeId attribute,
  std::optional<std::string> indexRange, double samplingIntervalMs, std::uint32_t queueSize,
  ua::MonitoringMode monitoringMode, bool discardOldest,
  std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter)
{
  if (mState != ConnectionState::Active)
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [completion = std::move(completion)](ConnectionImpl&) mutable
      { completion(ua::Result<CreatedMonitoredItem>{ua::Status::BadConnectionClosed}); })();
    return;
  }

  // CL-SUB-021: a PercentDeadband is not evaluable in fallback (no server-side Subscription -> no EURange
  // pre-read), so refuse it at ATTACH time with Bad_FilterNotAllowed rather than register an unfilterable
  // item (the design specification section 9.3 option ii). Only applies to a fallback (server-less)
  // Subscription.
  if (mFallbackSubscriptions.find(subscriptionId) != mFallbackSubscriptions.end())
  {
    if (const auto* dataChangeFilter = std::get_if<ua::DataChangeFilter>(&filter);
        dataChangeFilter != nullptr &&
        dataChangeFilter->deadband_type() == static_cast<std::uint32_t>(ua::DeadbandType::Percent))
    {
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [completion = std::move(completion)](ConnectionImpl&) mutable
        {
          completion(ua::Result<CreatedMonitoredItem>{ua::Status::BadFilterNotAllowed,
            ua::make_error_detail("FallbackPercentDeadbandUnsupported",
              "PercentDeadband is not supported on a polled-Read fallback Subscription (no server-side "
              "EURange)",
              "client.tier1.subscription_fallback.monitor")});
        })();
      return;
    }
  }

  // Register the data callback FIRST so a fast initial-value notification is not missed (the pipeline
  // hops onData onto the executor on delivery, so we hand it straight over - never invoked inline here).
  // Associate it with the Subscription so deleting the Subscription cascades to remove this item. Retain a
  // COPY of the node AND the caller's tuning (still needed below to build the request) so a session-CHANGED
  // reconnect can recreate the item with the SAME parameters (section 6.7, Q5 - the pipeline is the single
  // owner of the recreate params).
  mPipeline->add_monitored_item_async(subscriptionId,
    clientHandle,
    node,
    std::move(onData),
    attribute,
    indexRange,
    samplingIntervalMs,
    queueSize,
    monitoringMode,
    discardOldest,
    filter);  // CL-MI-011: retain the filter so a session-CHANGED recreate re-sends it (OPEN-MI-011)

  // CL-SUB-019: a fallback (server-less) Subscription has NO wire CreateMonitoredItems  -  the item is polled
  // by the fallback driver. The pipeline registration above is the whole job; complete GOOD immediately with
  // a synthetic CreatedMonitoredItem (the clientHandle stands in for the absent server monitored-item id; the
  // requested tuning is echoed verbatim), transparent to the user's MonitoredItem handle.
  if (mFallbackSubscriptions.find(subscriptionId) != mFallbackSubscriptions.end())
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [completion = std::move(completion), clientHandle, samplingIntervalMs, queueSize](
        ConnectionImpl&) mutable
      {
        CreatedMonitoredItem created;
        created.monitoredItemId = clientHandle;
        created.revisedSamplingIntervalMs = samplingIntervalMs;
        created.revisedQueueSize = queueSize;
        completion(ua::Result<CreatedMonitoredItem>{created});
      })();
    return;
  }

  auto pipeline = mPipeline;
  mSessionOps->create_monitored_items_async(build_create_monitored_items_request(subscriptionId,
                                              node,
                                              clientHandle,
                                              attribute,
                                              indexRange,
                                              samplingIntervalMs,
                                              queueSize,
                                              monitoringMode,
                                              discardOldest,
                                              filter),
    [completion = std::move(completion),
      pipeline = std::move(pipeline),
      clientHandle,
      namespaceTable = namespace_table_snapshot()](
      ua::Result<ua::CreateMonitoredItemsResponse> result) mutable
    {
      // Runs on the executor. On ANY failure, deregister the callback we optimistically registered above
      // so the pipeline does not retain a callback (and over-count) for an item that does not exist
      // server-side - a misbehaving server that rejects items would otherwise leak a callback per attempt.
      auto fail = [&](ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail = nullptr)
      {
        // Removal is part of the public failure postcondition: do not expose the failure until the
        // optimistically registered callback and its published count have both been rolled back. If the
        // pipeline itself is already gone, its callback still runs; preserve the original primary status and
        // ErrorDetail rather than replacing them with the secondary rollback result.
        pipeline->remove_monitored_item_async(clientHandle,
          [completion = std::move(completion), status, detail = std::move(detail)](ua::VoidResult) mutable
          { completion(ua::Result<CreatedMonitoredItem>{status, std::move(detail)}); });
      };
      if (!result.has_value())
      {
        fail(result.status_code(), result.shared_detail());
        return;
      }
      const auto& response = result.value();
      const auto serviceResult = response.response_header().service_result();
      if (serviceResult.is_bad())
      {
        // CL-DIAG-005: managed path (not through invoke_wire_op) - attach the wire marker to the bad Result.
        // CL-DIAG-007: tag a server NamespaceURI via the snapshot captured at issue time.
        fail(serviceResult,
          ua::client::detail::attach_wire_marker(response.response_header(), 32, namespaceTable));
        return;
      }
      if (response.results().size() != 1)
      {
        // Slot alignment (CL-MI-005): a single-item CreateMonitoredItems MUST return exactly one result.
        // A service-Good response with any other count (empty / short / long) cannot be positionally
        // mapped, so reject it with a source-tagged ErrorDetail rather than read results[0] out of an
        // ill-sized array and partially attach (mirrors the Read facade slot-alignment guard,
        // ua_connection.cpp / CL-ATTR-004).
        fail(ua::Status::BadUnexpectedError,
          ua::make_error_detail("CreateMonitoredItemResultCountMismatch",
            "the server returned a CreateMonitoredItems response whose result count is not exactly one for "
            "the single requested item",
            "client.tier1.connection.create_monitored_item.result_count_mismatch"));
        return;
      }
      const auto& itemResult = response.results()[0];
      if (itemResult.status_code().is_bad())
      {
        fail(itemResult.status_code(), itemResult.status_code().shared_detail());
        return;
      }
      // Snapshot the server's REVISED sampling interval + queue size verbatim (CL-MI-002 / CL-MI-019) so the
      // returned handle can expose the ACTUAL cadence + queue depth; the raw values are passed as-is (no
      // normalization) so a spec-violating revision the caller may want to inspect survives to the handle.
      // The item exists: a Good subcode or an Uncertain code of the item or of the ServiceResult (combined)
      // stays with it.
      completion(ua::detail::held(CreatedMonitoredItem{itemResult.monitored_item_id(),
                                    itemResult.revised_sampling_interval(),
                                    itemResult.revised_queue_size()},
        ua::detail::combined_status(serviceResult, itemResult.status_code())));
    });
}

void ConnectionImpl::create_event_monitored_item_async(std::uint32_t subscriptionId, ua::NodeId notifier,
  std::uint32_t clientHandle, ua::EventFilter filter, std::uint32_t queueSize,
  std::function<void(ua::Result<EventBackboneCreated>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<EventBackboneCreated>{ua::Status::BadConnectionClosed},
    [subscriptionId, notifier = std::move(notifier), clientHandle, filter = std::move(filter), queueSize](
      ConnectionImpl& self, std::function<void(ua::Result<EventBackboneCreated>)> completion) mutable
    {
      if (self.mState != ConnectionState::Active)
      {
        ua::async::post_owning(&self,
          self.mExecutor,
          self.mLogger,
          [completion = std::move(completion)](ConnectionImpl&) mutable
          { completion(ua::Result<EventBackboneCreated>{ua::Status::BadConnectionClosed}); })();
        return;
      }

      // Build an event CreateMonitoredItems: attributeId = EventNotifier, samplingInterval = 0, the caller's
      // queue size, filter = the composite EventFilter (CL-MI-013/014 forced at the wire boundary).
      ua::ReadValueId itemToMonitor;
      itemToMonitor.node_id() = notifier;
      itemToMonitor.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::EventNotifier);

      ua::MonitoringParameters parameters;
      parameters.client_handle() = clientHandle;
      parameters.sampling_interval() = 0.0;
      parameters.queue_size() = queueSize;
      parameters.discard_oldest() = true;
      parameters.filter() = std::make_unique<ua::EventFilter>(std::move(filter));

      ua::MonitoredItemCreateRequest itemToCreate;
      itemToCreate.item_to_monitor() = std::move(itemToMonitor);
      itemToCreate.monitoring_mode() = ua::MonitoringMode::Reporting;
      itemToCreate.requested_parameters() = std::move(parameters);

      ua::CreateMonitoredItemsRequest request;
      request.subscription_id() = subscriptionId;
      request.timestamps_to_return() = ua::TimestampsToReturn::Both;
      request.items_to_create().push_back(std::move(itemToCreate));

      self.mSessionOps->create_monitored_items_async(std::move(request),
        [completion = std::move(completion), namespaceTable = self.namespace_table_snapshot()](
          ua::Result<ua::CreateMonitoredItemsResponse> result) mutable
        {
          if (!result.has_value())
          {
            completion(ua::Result<EventBackboneCreated>{result.status_code(), result.shared_detail()});
            return;
          }
          const auto& response = result.value();
          const auto serviceResult = response.response_header().service_result();
          if (serviceResult.is_bad())
          {
            // CL-DIAG-005: managed path (not through invoke_wire_op) - attach the wire marker.
            // CL-DIAG-007: tag a server NamespaceURI via the snapshot captured at issue time.
            completion(ua::Result<EventBackboneCreated>{serviceResult,
              ua::client::detail::attach_wire_marker(response.response_header(), 32, namespaceTable)});
            return;
          }
          if (response.results().size() != 1)
          {
            completion(ua::Result<EventBackboneCreated>{ua::Status::BadUnexpectedError,
              ua::make_error_detail("CreateEventMonitoredItemResultCountMismatch",
                "the server returned a result count other than one for one event monitored item",
                "client.tier1.connection.create_event_monitored_item.result_count_mismatch")});
            return;
          }
          const auto& itemResult = response.results()[0];
          if (itemResult.status_code().is_bad())
          {
            completion(ua::Result<EventBackboneCreated>{
              itemResult.status_code(), itemResult.status_code().shared_detail()});
            return;
          }
          EventBackboneCreated created;
          created.monitoredItemId = itemResult.monitored_item_id();
          const auto* filterResult =
            dynamic_cast<const ua::EventFilterResult*>(itemResult.filter_result().get());
          if (filterResult != nullptr)
          {
            created.filterDiagnostics = bad_event_filter_diagnostics(*filterResult);
          }
          // The item exists: a Good subcode or an Uncertain code of the item or of the ServiceResult
          // (combined) stays with it.
          completion(ua::detail::held(
            std::move(created), ua::detail::combined_status(serviceResult, itemResult.status_code())));
        });
    })();
}

std::shared_ptr<detail::EventSubscriberImpl> ConnectionImpl::events_impl()
{
  std::call_once(mEventSubscriberOnce,
    [this]
    {
      mEventBackboneOps = ConnectionEventBackboneOps::create(weak_from_this());
      // Thread the per-Connection observer sink (weak) into the subscriber so the co-owned A&C tracker can
      // fire AlarmObserver::on_data_integrity_warning (CL-AC-023/025). mObserverSink is created at connect
      // (wire_dependencies), before any events_impl(); an expired sink just skips the observer arm.
      mEventSubscriber.store(EventSubscriberImpl::create(
        mExecutor, mEventBackboneOps, mLogger, EventSubscriberPolicy{}, mObserverSink));
    });
  return mEventSubscriber.load();
}

std::shared_ptr<detail::AlarmConditionTrackerImpl> ConnectionImpl::alarms_impl()
{
  auto subscriber = events_impl();
  if (!subscriber)
  {
    return nullptr;
  }
  // The tracker issues its method Calls / ConditionRefresh through the tier-1 WireOps role (the shim).
  std::weak_ptr<WireOps> wireOps = std::static_pointer_cast<WireOps>(mConnectionOps);
  return subscriber->ensure_alarm_tracker(wireOps, AlarmConditionTrackerPolicy{});
}

std::shared_ptr<detail::TypeResolver> ConnectionImpl::type_resolver()
{
  std::call_once(mTypeResolverOnce,
    [this]
    {
      // The resolver runs on THIS orchestrator's strand and reaches the wire / support interfaces WEAK (the
      // shim aliases, locked per op), so no ownership cycle forms back into ConnectionImpl. The resolution
      // policy is the one this Connection was configured with. No Client-wide overlay.
      // SEEDING (Slice T1 Phase A1): this lazy construction stays, but the resolver is no longer left
      // UNSEEDED  -  on_first_session_active() seeds it with the bootstrap NamespaceTable, and the reconnect
      // NamespaceArray re-read (apply_namespace_read) re-seeds it with the bumped-generation table. So a
      // NodeId namespace remap resolves against the CURRENT table (the former W-1 stale-namespace hazard is
      // closed); registrations parked during the bootstrap window attach at that first seed.
      std::weak_ptr<WireOps> wireOps = std::static_pointer_cast<WireOps>(mConnectionOps);
      std::weak_ptr<SupportOps> supportOps = std::static_pointer_cast<SupportOps>(mConnectionOps);
      // Route installed types to this Connection's TypeObserver (per-connection slot, else the
      // Client-level default). Weak: the sink outlives the resolver only through this orchestrator, and a
      // resolution completing after close must not resurrect it.
      mTypeResolver = TypeResolver::create(mStrand,
        std::move(wireOps),
        std::move(supportOps),
        mTypeResolutionPolicy,
        /*clientWideOverlay=*/nullptr,
        mLogger,
        [weak = weak_from_this()](ua::NodeId encodingId, std::string typeName)
        {
          if (auto self = weak.lock(); self && self->mObserverSink)
          {
            self->mObserverSink->fire_type_registered(std::move(encodingId), std::move(typeName));
          }
        });
    });
  return mTypeResolver;
}

std::shared_ptr<detail::SubscriptionFactoryOps> ConnectionImpl::subscription_factory()
{
  // A stateless weak-ref leaf: a fresh instance per call is cheap and forms no cycle (it only weak-refs this
  // orchestrator, which forwards create_subscription_managed_async / monitor_data_change_async).
  return ConnectionSubscriptionFactory::create(weak_from_this());
}

std::shared_ptr<detail::SemanticChangeCache> ConnectionImpl::semantic_change_cache()
{
  // FREE-THREADED (section 8.18.2): the sole caller reaches this OFF the connection strand  -  the DataAccess
  // handle-build completion runs on mExecutor, not mStrand  -  so this must NOT assert running-on-strand. The
  // cache lives on THIS orchestrator's strand only in the sense that its OWN mutators
  // (register/invalidate/close) self-marshal onto it; the accessor merely hands out the cache handle.
  // `call_once` keeps the construction race-free across threads (mirroring type_resolver() / events_impl()).
  std::call_once(mSemanticChangeCacheOnce,
    [this]
    {
      // Inject THIS orchestrator's strand (no private strand). The cache holds only
      // weak(TypedPropertiesState) entries + a hook sentinel, so no ownership cycle forms back into
      // ConnectionImpl.
      mSemanticChangeCache = SemanticChangeCache::create(mStrand, mLogger);
      // Publish the completed construction (C1): the release store, AFTER the member assignment, pairs with
      // the acquire load in begin_close (which reads mSemanticChangeCache off this accessor's call_once path
      // and so needs its own happens-before edge to the member write).
      mSemanticChangeCacheConstructed.store(true, std::memory_order_release);
      // W8: install the real `on_semantic_change` observer hook HERE  -  a SemanticChangeHook subscribed to
      // this Connection's observer fan-out (section 7.8 AddressSpaceObserver route) that forwards each named
      // NodeId into mSemanticChangeCache->invalidate_async. For W2a the cache self-installs a STUB hook
      // sentinel (dropped on close); the on_semantic_change trigger is wired in W8. Both real triggers route
      // through the one invalidate_async: the in-band `SemanticsChanged` status-bit path
      // (SubscriptionsPipeline publish path) and the `SemanticChangeEventType` event path (section 8.13
      // EventSubscriber, W8).
    });
  return mSemanticChangeCache;
}

std::shared_ptr<detail::AddressSpaceCache> ConnectionImpl::address_space_cache()
{
  // FREE-THREADED (mirrors semantic_change_cache / type_resolver / events_impl): the W8b model-change router
  // reaches this OFF the connection strand (event callbacks fire on the executor, unserialized), so this must
  // NOT assert running-on-strand. The cache lives on THIS orchestrator's strand only in the sense that its
  // OWN async mutators (evict / invalidate / drain) self-marshal onto it; the accessor merely hands out the
  // cache handle. `call_once` keeps the construction race-free across threads.
  std::call_once(mAddressSpaceCacheOnce,
    [this]
    {
      // Inject THIS orchestrator's strand (no private strand) and the upward WireOps interface (the
      // ConnectionOps shim) held WEAK  -  the cache locks it per UnregisterNodes op and bails if the
      // Connection is gone  - so no ownership cycle forms back into ConnectionImpl. mConnectionOps is
      // constructed in wire_pipeline_and_ops before `self` is published, so it is non-null on any reachable
      // call here.
      //
      // POLICY (Slice V1): the immutable per-Connection policy decomposed from the connect ConnectionConfig
      // (default disabled = a clean pass-through no-op, opt-in section 8.7). An ENABLED policy reaches the
      // real cache here, so the RegisterNodes alias substitution / eviction / session-scope wiring goes live;
      // a disabled Connection still gives the W8b CL-EVT-003 model-change router a reachable, non-null
      // (inert) flush target.
      std::weak_ptr<WireOps> wireOps = std::static_pointer_cast<WireOps>(mConnectionOps);
      mAddressSpaceCache =
        AddressSpaceCache::create(mStrand, std::move(wireOps), mAddressSpaceCachePolicy, mLogger);
    });
  return mAddressSpaceCache;
}

// -------- Address-space alias cache wiring (Slice V1 / CL-VIEW-009/010/011) --------

void ConnectionImpl::observe_access_level_ex_async(
  ua::NodeId node, std::uint32_t accessLevelEx, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{},  // optional cache side effect: if the Connection is gone, nothing remains to cache
    [node = std::move(node), accessLevelEx](
      ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (self.mAddressSpaceCachePolicy.enabled)
      {
        auto cache = self.address_space_cache();
        auto attributes = cache->lookup_attributes(node).value_or(AttributeEntry{});
        attributes.accessLevelEx = accessLevelEx;
        cache->install_attributes(node, std::move(attributes));
      }
      completion(ua::VoidResult{});
    })();
}

void ConnectionImpl::observe_value_rank_async(
  ua::NodeId node, std::int32_t valueRank, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{},
    [node = std::move(node), valueRank](
      ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (self.mAddressSpaceCachePolicy.enabled)
      {
        auto cache = self.address_space_cache();
        auto attributes = cache->lookup_attributes(node).value_or(AttributeEntry{});
        attributes.valueRank = valueRank;
        cache->install_attributes(node, std::move(attributes));
      }
      completion(ua::VoidResult{});
    })();
}

void ConnectionImpl::validate_index_range_write_async(
  ua::NodeId node, ua::String indexRange, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadConnectionClosed,
      ua::make_error_detail("IndexRangePreflightConnectionGone",
        "the Connection ended before cached IndexRange write validation could run",
        "client.tier2.typed_access.write_attribute")},
    [node = std::move(node), indexRange = std::move(indexRange)](
      ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (!self.mAddressSpaceCachePolicy.enabled)
      {
        completion(ua::VoidResult{});
        return;
      }
      const auto attributes = self.address_space_cache()->lookup_attributes(node);
      if (!attributes)
      {
        completion(ua::VoidResult{});
        return;
      }
      if (attributes->valueRank)
      {
        auto validation =
          validate_client_numeric_range(node, indexRange, attributes->valueRank, NumericRangeUse::Write);
        if (validation.is_bad())
        {
          completion(ua::VoidResult{validation.status_code(), validation.shared_detail()});
          return;
        }
      }
      if (!attributes->accessLevelEx)
      {
        completion(ua::VoidResult{});
        return;
      }
      const ua::AccessLevelExType accessLevelEx{*attributes->accessLevelEx};
      if (!accessLevelEx.test(ua::AccessLevelExType::Bit::WriteFullArrayOnly))
      {
        completion(ua::VoidResult{});
        return;
      }
      completion(ua::VoidResult{ua::Status::BadWriteNotSupported,
        ua::ErrorDetail::build("WriteFullArrayOnlyIndexRangeRejected",
          "the cached AccessLevelEx forbids an IndexRange write for this Variable",
          "client.tier2.typed_access.write_attribute")
          .context(ua::ContextKeys::nodeId, ua::to_string(node))});
    })();
}

void ConnectionImpl::apply_alias_substitution(ua::ReadRequest& request)
{
  if (!mAddressSpaceCachePolicy.enabled || !mAddressSpaceCachePolicy.useRegisterNodes)
  {
    return;  // disabled: strict no-op (the request is left byte-for-byte unchanged)
  }
  auto cache = address_space_cache();
  for (auto& valueId : request.nodes_to_read())
  {
    valueId.node_id() = cache->lookup_for_request(valueId.node_id());
  }
}

void ConnectionImpl::apply_alias_substitution(ua::WriteRequest& request)
{
  if (!mAddressSpaceCachePolicy.enabled || !mAddressSpaceCachePolicy.useRegisterNodes)
  {
    return;
  }
  auto cache = address_space_cache();
  for (auto& value : request.nodes_to_write())
  {
    value.node_id() = cache->lookup_for_request(value.node_id());
  }
}

void ConnectionImpl::apply_alias_substitution(ua::CallRequest& request)
{
  if (!mAddressSpaceCachePolicy.enabled || !mAddressSpaceCachePolicy.useRegisterNodes)
  {
    return;
  }
  auto cache = address_space_cache();
  for (auto& method : request.methods_to_call())
  {
    // Both the object and the method NodeId can be registered handles.
    method.object_id() = cache->lookup_for_request(method.object_id());
    method.method_id() = cache->lookup_for_request(method.method_id());
  }
}

void ConnectionImpl::apply_alias_substitution(ua::HistoryReadRequest& request)
{
  if (!mAddressSpaceCachePolicy.enabled || !mAddressSpaceCachePolicy.useRegisterNodes)
  {
    return;
  }
  auto cache = address_space_cache();
  for (auto& valueId : request.nodes_to_read())
  {
    valueId.node_id() = cache->lookup_for_request(valueId.node_id());
  }
}

std::function<void(ua::Result<ua::RegisterNodesResponse>)> ConnectionImpl::install_aliases_on_register(
  std::vector<ua::NodeId> requestedNodes,
  std::function<void(ua::Result<ua::RegisterNodesResponse>)> completion)
{
  if (!mAddressSpaceCachePolicy.enabled || !mAddressSpaceCachePolicy.useRegisterNodes)
  {
    return completion;  // disabled: strict no-op (the wire-op delivers the user callback unchanged)
  }
  return
    [weak = weak_from_this(), requestedNodes = std::move(requestedNodes), completion = std::move(completion)](
      ua::Result<ua::RegisterNodesResponse> result) mutable
  {
    // invoke_wire_op already hopped onto the executor before calling this completion.
    auto self = weak.lock();
    // The cache acts on the aliases, so only a Good answer installs them; any other is delivered verbatim.
    if (!self || !result.is_good() || !result.value().response_header().service_result().is_good())
    {
      // The orchestrator is gone, or the RegisterNodes failed: nothing to install  -  deliver verbatim.
      completion(std::move(result));
      return;
    }
    // Pair requested -> registered (a conforming server returns one alias per requested node). Extract the
    // aliases before the result is moved into the strand hop.
    std::vector<ua::NodeId> registered;
    registered.reserve(result.value().registered_node_ids().size());
    for (const auto& node : result.value().registered_node_ids())
    {
      registered.push_back(node);
    }
    // Install ON THE STRAND (the alias cache is caller-on-strand), THEN deliver the user callback on the
    // executor  -  so any op the caller issues from `completion` is ordered strictly AFTER the install. The
    // completion-owning post_borrowing fires the owed completion even if the Connection is destroyed before
    // the strand turn (the gone path delivers the Good result anyway  -  a dead Connection simply has no
    // cache to warm).
    auto goneFallback = result;
    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      std::move(completion),
      std::move(goneFallback),
      [requestedNodes = std::move(requestedNodes),
        registered = std::move(registered),
        result = std::move(result)](
        ConnectionImpl& conn, std::function<void(ua::Result<ua::RegisterNodesResponse>)> settle) mutable
      {
        conn.address_space_cache()->install_aliases(std::move(requestedNodes), std::move(registered));
        ua::async::post_owning(&conn,
          conn.mExecutor,
          conn.mLogger,
          [result = std::move(result), settle = std::move(settle)](ConnectionImpl&) mutable
          { settle(std::move(result)); })();
      })();
  };
}

void ConnectionImpl::pipeline_send_publish(std::vector<SubscriptionAcknowledgement> acknowledgements)
{
  // Called from the PIPELINE strand: hop onto the connection strand before touching mSessionOps. Plain
  // post_borrowing (no owed completion): a gone orchestrator simply drops the Publish (the pump stops).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [acknowledgements = std::move(acknowledgements)](ConnectionImpl& self) mutable
    {
      // Active-gate before the service accessor: a Publish issued after the session starts closing would
      // block on the accessor (FU-1). When not Active we complete nothing - the pump has stopped.
      if (self.mState != ConnectionState::Active)
      {
        return;
      }

      // Map the pipeline's ack type to the wire SubscriptionAcknowledgement.
      ua::PublishRequest request;
      for (const auto& ack : acknowledgements)
      {
        ua::SubscriptionAcknowledgement wireAck;
        wireAck.subscription_id() = ack.subscriptionId;
        wireAck.sequence_number() = ack.sequenceNumber;
        request.subscription_acknowledgements().push_back(std::move(wireAck));
      }

      auto pipeline = self.mPipeline;
      const std::uint64_t issuedEpoch = self.mReconnectAttemptEpoch;
      self.mSessionOps->publish_async(std::move(request),
        ua::async::post_borrowing(&self,
          self.mStrand,
          self.mLogger,
          [pipeline = std::move(pipeline), issuedEpoch](
            ConnectionImpl& conn, ua::Result<ua::PublishResponse> result) mutable
          {
            // The Publish pump is the OPC-UA keep-alive channel, so a channel/session-fatal Publish result
            // is the primary automatic drop signal (CL-RECONN-001). Detection uses the EFFECTIVE status: a
            // transport-bad Result, OR a fatal service_result carried in a well-formed PublishResponse header
            // (a ServiceFault the codec surfaced as a typed response - is_bad() would be false for it). The
            // completion hops back onto this strand (folding the former weakSelf.lock() into that hop) so the
            // drop-notify and the state gate below both read strand-owned state race-free. notify_transport
            // is still epoch-guarded (inside its own strand hop) and debounced against terminal/in-flight
            // states - a stale/superseded completion cannot re-tear-down an already-recovered connection.
            const ua::StatusCode effective =
              !result.has_value() ? result.status_code() : result.value().response_header().service_result();
            if (is_channel_fatal(effective))
            {
              conn.notify_transport_drop_async(effective, issuedEpoch);
            }
            // H2a: only feed the pipeline while Active. During Reconnecting an in-flight stale publish
            // response must NOT drive a reactive gap drain - its data is recovered by the recover-step
            // drain, and a reactive fork on the same Subscription would let a Duplicate-classified response
            // prematurely end the recovery drain and drop a recovered notification (F1-class loss). The pump
            // is stopped during Reconnecting, so skipping the feed also skips a pointless refill.
            if (conn.mState == ConnectionState::Active)
            {
              // CL-SUB-009 / Part 4 section 5.13.8.1: a Bad_NoSubscription Publish response means the last
              // Subscription on the Session was deleted and the server de-queued the outstanding Publishes.
              // It is NOT a fault (not channel-fatal above, no reconnect)  -  drain-and-HOLD the pump (no
              // retry), skipping the normal feed (the response carries no deliverable data; feeding it would
              // refill the doomed pump). A later CreateSubscription resumes publishing.
              if (effective == ua::StatusCode{ua::Status::BadNoSubscription})
              {
                pipeline->on_publish_no_subscription_async();
              }
              else if (effective.as_status() == ua::Status::BadResponseTooLarge)
              {
                // A typed PublishResponse may carry the failure only in ResponseHeader.serviceResult; the
                // outer Result is still Good. Feed the effective rich status explicitly so CL-SUB-005 sees
                // both transport-bad and in-band ServiceFault shapes.
                pipeline->on_publish_failure_async(effective);
              }
              else
              {
                feed_publish_response(pipeline,
                  conn.mEventSubscriber.load(),
                  std::weak_ptr<ObserverSink>{conn.mObserverSink},
                  std::move(result));
              }
            }
          }));
    })();
}

void ConnectionImpl::pipeline_republish(std::uint32_t subscriptionId, std::uint32_t sequenceNumber)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [subscriptionId, sequenceNumber](ConnectionImpl& self)
    {
      // H1: the recover step issues Republishes while mState == Reconnecting (before commit/reach_active),
      // so the plain Active-gate would drop every recovery Republish and stall the barrier. Allow issue
      // when Active OR while a recovery is in progress (strand-confined mRecoveryInProgress). Safe: recovery
      // runs only after the Session is re-activated, and the pump is stopped, so no other caller races.
      if (self.mState != ConnectionState::Active && !self.mRecoveryInProgress)
      {
        return;
      }
      ua::RepublishRequest request;
      request.subscription_id() = subscriptionId;
      request.retransmit_sequence_number() = sequenceNumber;

      auto pipeline = self.mPipeline;
      // H3: capture the reconnect-attempt epoch at ISSUE time (mirror pipeline_send_publish). The
      // republish_async completion runs on the tier-0 executor, so a bare epoch read there would be a
      // cross-strand data race; the completion hops BACK onto this strand and checks the epoch there.
      const std::uint64_t issuedEpoch = self.mReconnectAttemptEpoch;
      // H1 session targeting: on the CL-RECONN-003 recreate path mSessionOps is still the invalidated old
      // session until reconnect_commit swaps it in; the freshly-created session lives in mPendingSession.
      // Target the pending session when one exists (mirror reconnect_re_read_namespace_array).
      SessionOps* activeSession = self.mPendingSession ? self.mPendingSession.get() : self.mSessionOps.get();
      activeSession->republish_async(std::move(request),
        ua::async::post_borrowing(&self,
          self.mStrand,
          self.mLogger,
          [pipeline = std::move(pipeline), subscriptionId, sequenceNumber, issuedEpoch](
            ConnectionImpl& conn, ua::Result<ua::RepublishResponse> result) mutable
          {
            // H3 (F1 keystone): epoch guard INSIDE the strand hop. A Republish issued under a channel a
            // later reconnect attempt has since superseded (epoch moved on) is dropped before it can reach
            // the pipeline's recovery barrier - honouring it would advance the tracker / decrement the
            // barrier against a stale channel. The stalled barrier is then bounded by the FSM step deadline.
            if (conn.mReconnectAttemptEpoch != issuedEpoch)
            {
              return;
            }
            // The effective Republish status: a transport-bad Result, else the in-band service_result.
            // Passed through (not collapsed to a bool) so the pipeline can distinguish
            // Bad_MessageNotAvailable (clean terminator) from Bad_SubscriptionIdInvalid / other faults, and
            // log rather than discard.
            const ua::StatusCode status =
              !result.has_value() ? result.status_code() : result.value().response_header().service_result();
            // Deliver the RECOVERED message's DataChanges to the monitored-item callbacks (mirrors
            // feed_publish_response). Without this the gap-drain recovers sequence continuity but DROPS the
            // data it exists to recover - so a subscription's notifications queued while the client was
            // disconnected are lost on reconnect even though the drain "succeeds" (section 8.4.5 /
            // CL-RECONN-004).
            if (status.is_good())
            {
              auto eventSubscriber = conn.mEventSubscriber.load();
              for (const auto& notification : result.value().notification_message().notification_data())
              {
                if (const auto* dataChange =
                      dynamic_cast<const ua::DataChangeNotification*>(notification.get()))
                {
                  for (const auto& item : dataChange->monitored_items())
                  {
                    pipeline->deliver_notification_async(item.client_handle(), item.value());
                  }
                }
                else if (const auto* eventList =
                           dynamic_cast<const ua::EventNotificationList*>(notification.get()))
                {
                  // Recovered events must also reach the subscriber (else a reconnect drops queued events,
                  // mirroring the CL-RECONN-004 DataChange concern above).
                  if (eventSubscriber)
                  {
                    route_event_notification_list(*eventList, *eventSubscriber);
                  }
                }
              }
            }
            pipeline->on_republish_response_async(subscriptionId, sequenceNumber, status);
          }));
    })();
}

void ConnectionImpl::on_subscription_event_loss(std::uint32_t subscriptionId)
{
  // Finding 2 / CL-AC-003: the pipeline detected a reactive Republish drain that left an unrecovered gap for
  // this Subscription (dropped messages, possibly a lost ConditionRefresh RefreshEnd). Hop onto this strand
  // (weak  -  the pipeline can outlive a torn-down orchestrator) and, if a live event subscriber exists,
  // reset the affected backbone's dead refresh state so the condition state re-syncs. EventLossDetected (not
  // SessionReestablished) so the reset delivers an accurate Bad_SequenceNumberUnknown to any in-flight user
  // ConditionRefresh  -  the session did NOT close here (R4). Mirrors reconnect_commit's reset call. The
  // subscriber self-marshals onto its own strand; this strand never reaches into subscriber/tracker state.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [subscriptionId](ConnectionImpl& self)
    {
      if (auto eventSubscriber = self.mEventSubscriber.load())
      {
        eventSubscriber->on_reconnect_recovered_async(
          {subscriptionId}, BackboneRecoveryReason::EventLossDetected);
      }
    })();
}

void ConnectionImpl::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  // Completion-owning strand entry: a gone orchestrator is effectively already closed -> Good.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    { self.begin_close(std::move(completion)); })();
}

void ConnectionImpl::begin_close(std::function<void(ua::VoidResult)> completion)
{
  if (mState == ConnectionState::Closed)
  {
    ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [completion = std::move(completion)](ConnectionImpl&) mutable { completion(ua::VoidResult{}); })();
    return;
  }
  if (mState == ConnectionState::Closing)
  {
    mPendingCloseCompletions.push_back(std::move(completion));
    return;
  }
  const bool wasActive = mState == ConnectionState::Active;
  mState = ConnectionState::Closing;
  mBrowseContinuationPoints.cancel_all();
  mQueryContinuationPoints.cancel_all();
  mHistoryContinuationPoints.cancel_all();
  // Fire the terminal ConnectionObserver transitions HERE (W3 / WARN-3), BEFORE the sink is severed in
  // @ref close_session (which runs several strand hops later, after the dispatch + tier-0 session close).
  // These fires enqueue onto the sink's own delivery strand; close() FIFO-posts its slots sever onto that
  // SAME strand (HIGH-1), so the terminal fires are delivered before the sever regardless of executor
  // threading - not by hop-count luck. on_disconnected fires only when the close left an Active link (a
  // graceful, intentional close is not an error -> reason Good, no chain); on_closed always fires (every
  // graceful close reaches Closed). A setter that races this close cannot re-arm the sink: mState is already
  // Closing (is_terminal_state() is true), so reresolve_observers_on_strand early-returns, and once close()
  // latches the sink set_slots is a permanent no-op.
  if (mObserverSink)
  {
    if (wasActive)
    {
      mObserverSink->fire_disconnected(ua::StatusCode{ua::Status::Good}, nullptr);
    }
    mObserverSink->fire_closed();
  }
  disarm_keep_alive_timer();  // stop polling before the session starts closing (a poll would block on FU-1)
  // W8b: halt event routing (the backbone MonitoredItems are torn down by the pipeline / session close; the
  // router issues no DeleteMonitoredItems on a closing session). Idempotent.
  if (mEventRouter)
  {
    mEventRouter->stop();
  }
  // A recovery that raced close is abandoned: clear the strand-only flag so the relaxed pipeline_republish
  // gate cannot stay open on the terminal path (the pipeline's own barrier is purged by stop_async below).
  mRecoveryInProgress = false;
  publish_info();
  // Stop the Publish pump BEFORE closing the session so no new Publish is issued once the session starts
  // closing. Combined with the Active-gate in pipeline_send_publish (which runs on this strand), any Publish
  // that raced the pump-stop is dropped rather than blocking on the closed session's service accessor (FU-1).
  if (mPipeline)
  {
    mPipeline->stop_async();
  }
  if (mSemanticChangeCacheConstructed.load(std::memory_order_acquire))
  {
    // section 8.18.3 Connection close: drop the observer hook + clear mEntries. Self-marshals onto this
    // strand (idempotent); after this, live DataAccess handles' interface locks fail and their reads surface
    // Bad. The acquire load pairs with the free-threaded accessor's release store (C1): only read
    // mSemanticChangeCache once its construction has been published, so the strand-side read never races the
    // off-strand call_once write. (A cache still mid-construction on another thread is simply left to its own
    // destructor to clean up  -  the observer hook is a W2a stub, so an unsevered hook is inert.)
    mSemanticChangeCache->close();
  }
  if (mAddressSpaceCachePolicy.enabled)
  {
    // CL-VIEW-010 shutdown drain: best-effort UnregisterNodes for the union of live aliases + the pending
    // batch, then clear. Fire-and-forget (the close does not wait on it); self-marshals onto this strand and
    // is a no-op on an empty cache. Gated on the enabled policy so a disabled Connection never constructs or
    // drains the cache here.
    address_space_cache()->drain_async([]() {});
  }
  // W4 close order (CRITICAL section 8.11.3): drive the redundancy manager TERMINAL *before* the reconnect
  // FSM is cancelled. First fire any in-flight redundancy-reconnect completion Bad (never dropped), then
  // close the manager (do_close: fires any pending force_switch Cancelled, cancels the ServiceLevel MI,
  // releases the host - severing the latent manager->host->orchestrator edge), THEN cancel the FSM. Reversing
  // this (FSM cancelled first) would let a stale failover trigger the manager posts find a cancelled FSM and
  // strand an awaiting completion the dead notify path can never deliver. mCloseStepProbe records the
  // source-level order for the falsifiable ordering oracle (F5). Both close_async / cancel_async are
  // fire-and-forget (not awaited): safe here because `do_close` has no FSM dependency AND mState is already
  // Closing (set above), so any late manager trigger is rejected by is_terminal_state() before it can touch
  // the FSM - a future manager that self-satisfies via the trigger interface DURING close would need this to
  // become an awaited close.
  fire_redundancy_reconnect_pending(ua::VoidResult{ua::StatusCode{ua::Status::BadConnectionClosed},
    ua::ErrorDetail::build(
      "RedundancyReconnectAbandoned", "the Connection is closing", "client.tier1.redundancy.trigger.closing")
      .cause(ua::StatusCode{ua::Status::BadConnectionClosed})});
  if (mRedundancyManager)
  {
    if (mCloseStepProbe)
    {
      mCloseStepProbe("manager_close");
    }
    mRedundancyManager->close_async([](ua::VoidResult) {});
  }
  if (mReconnectFsm)
  {
    if (mCloseStepProbe)
    {
      mCloseStepProbe("fsm_cancel");
    }
    // Stop any in-flight reconnect and its step/backoff timers so a late trigger cannot resurrect the
    // Connection during / after close. Idempotent and fire-and-forget (touches only the FSM's state).
    mReconnectFsm->cancel_async([](ua::VoidResult) {});
  }
  delete_owned_subscriptions_then_close(std::move(completion));
}

void ConnectionImpl::delete_owned_subscriptions_then_close(std::function<void(ua::VoidResult)> completion)
{
  // CL-SUB-010: pipeline server-backed entries are the Subscriptions this Connection currently owns,
  // including ids retained after TransferSubscriptions. Snapshot after the Publish pump is stopped, then
  // await one DeleteSubscriptions before draining the dispatch gate and closing the Session. Fallback
  // subscriptions live outside recovery_descriptors and deliberately never reach the wire.
  mPipeline->recovery_descriptors_async(ua::async::post_owning(this,
    mStrand,
    mLogger,
    [completion = std::move(completion)](
      ConnectionImpl& self, std::vector<RecoveryDescriptor> descriptors) mutable
    {
      if (descriptors.empty())
      {
        self.close_dispatch_then_session(std::move(completion));
        return;
      }

      ua::DeleteSubscriptionsRequest request;
      for (const auto& descriptor : descriptors)
      {
        request.subscription_ids().push_back(descriptor.subscriptionId);
      }
      self.mSessionOps->delete_subscriptions_async(std::move(request),
        ua::async::post_owning(&self,
          self.mStrand,
          self.mLogger,
          [completion = std::move(completion)](
            ConnectionImpl& inner, ua::Result<ua::DeleteSubscriptionsResponse> result) mutable
          {
            const auto logFailure = [&inner](std::string_view scope, ua::StatusCode status)
            {
              const std::string statusText = std::to_string(status.as_uint32());
              const std::string detailText =
                status.shared_detail() ? ua::to_string(*status.shared_detail()) : std::string{};
              inner.mLogger.warning(
                {{"scope", std::string{scope}}, {"status", statusText}, {"detail", detailText}},
                "DeleteSubscriptions during Connection close failed; continuing Session teardown");
            };

            if (!result.has_value())
            {
              logFailure("transport", result.status_code());
            }
            else
            {
              const auto serviceStatus = result.value().response_header().service_result();
              if (!serviceStatus.is_good())
              {
                logFailure("service", serviceStatus);
              }
              for (const auto& itemStatus : result.value().results())
              {
                if (!itemStatus.is_good())
                {
                  logFailure("subscription", itemStatus);
                }
              }
            }
            inner.close_dispatch_then_session(std::move(completion));
          }));
    }));
}

void ConnectionImpl::close_dispatch_then_session(std::function<void(ua::VoidResult)> completion)
{
  // Drain the operation gate only after close-time DeleteSubscriptions completes. Session service response
  // delivery may depend on work already admitted through this gate; closing it first can deadlock the
  // awaited delete on a real transport. post_owning is the sanctioned close self-anchor.
  mDispatch->close_async(ua::async::post_owning(this,
    mStrand,
    mLogger,
    [completion = std::move(completion)](ConnectionImpl& self, ua::VoidResult) mutable
    { self.close_session(std::move(completion)); }));
}

void ConnectionImpl::close_session(std::function<void(ua::VoidResult)> completion)
{
  mSessionOps->close_async(ua::async::post_owning(this,
    mStrand,
    mLogger,
    [completion = std::move(completion)](ConnectionImpl& self, ua::VoidResult) mutable
    {
      // Every FileType fileHandle is Session-scoped (Part 20 section 4.2.2). Publish a new generation before
      // Closed becomes visible so retained FileHandles reject locally as Bad_SessionClosed and never send
      // their stale numeric handle after this Session ends.
      self.mSessionGeneration->fetch_add(1, std::memory_order_release);
      self.mOutstandingRequestsByHandle.clear();
      self.mState = ConnectionState::Closed;
      auto pendingCloseCompletions = std::exchange(self.mPendingCloseCompletions, {});
      // Sever observer delivery only now (WARN-3): the terminal on_disconnected/on_closed emitted in
      // begin_close are already queued on the sink's delivery strand, and close() FIFO-posts the sever onto
      // that same strand behind them (HIGH-1) - so they are delivered before the sever whatever the executor
      // threading. close() latches the sink synchronously so it can never be re-armed.
      if (self.mObserverSink)
      {
        self.mObserverSink->close();
      }
      self.publish_info();
      // Deliver the terminal callback Good on the executor (the tier-0 close status is not surfaced -
      // a graceful close is a success from the orchestrator's view).
      ua::async::post_owning(&self,
        self.mExecutor,
        self.mLogger,
        [completion = std::move(completion), pendingCloseCompletions = std::move(pendingCloseCompletions)](
          ConnectionImpl&) mutable
        {
          completion(ua::VoidResult{});
          for (const auto& pending : pendingCloseCompletions)
          {
            pending(ua::VoidResult{});
          }
        })();
    }));
}

void ConnectionImpl::trigger_reconnect_async() noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [](ConnectionImpl& self)
    {
      if (!self.mReconnectFsm || self.is_terminal_state())
      {
        return;  // single-shot Connection, or already closing/closed/failed: do not start a reconnect
      }
      self.mReconnectFsm->trigger(
        ua::client::TransportDropped{}, ua::StatusCode{ua::Status::BadConnectionClosed}, nullptr);
    })();
}

void ConnectionImpl::revalidate_server_cert_async(bool ownCertificateChanged,
  bool revalidateServerCertificate, std::function<void(ua::VoidResult)> callback) noexcept
{
  // The outer hop OWES the completion (the Client-level walk barrier waits on it), so use the
  // completion-owning post_borrowing: an alive orchestrator runs the handler; a gone one still delivers the
  // completion Good (a gone Connection has nothing to revalidate  -  the ACK is advisory, J53). The
  // completion is delivered on the executor by the handler on every alive path (never the connection strand).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{},
    [ownCertificateChanged, revalidateServerCertificate](
      ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // Terminal/closing -> nothing to do. An OWN-certificate change is not a server-certificate validation
      // result: Part 4 section 6.7 requires a new Session categorically, even if the current server
      // certificate remains trusted. Drive CertRotated before consulting the optional server-validator
      // interface so the production bootstrap/no-validator path cannot silently skip the mandatory reconnect.
      if (self.is_terminal_state())
      {
        self.deliver_revalidate_ack(std::move(completion));
        return;
      }
      if (ownCertificateChanged)
      {
        self.trigger_cert_rotated_reconnect(ua::Status::BadCertificateInvalid,
          ua::make_error_detail("OwnCertificateRotated",
            "the Client application-instance certificate changed; a new Session is required",
            "client.tier1.connection.certificate_update"));
      }
      // No server validator means there is no trust-list consequence to check. The mandatory own-cert
      // reconnect above has already been initiated when applicable.
      if (!revalidateServerCertificate || !self.mServerCertValidator)
      {
        self.deliver_revalidate_ack(std::move(completion));
        return;
      }
      // Invoke the interface (re-validate the current server cert against the store). Its verdict arrives off
      // the connection strand (the store validate is async), so re-hop to the strand to act on it +
      // acknowledge.
      auto weakSelf = self.weak_from_this();
      // Defense-in-depth against an interface that violates its fire-exactly-once contract: honour only the
      // FIRST verdict. Without this, an interface that fires twice on the Connection-gone path (below) would
      // call the owed completion twice and double-decrement the Client-walk barrier (premature aggregate).
      // The alive path is already single-shot (the completion is move-consumed into post_borrowing), so this
      // only hardens the gone path. std::atomic_flag default-inits clear in C++20.
      auto verdictOnce = std::make_shared<std::atomic_flag>();
      self.mServerCertValidator(
        [weakSelf, completion = std::move(completion), verdictOnce](ua::VoidResult verdict) mutable
        {
          if (verdictOnce->test_and_set(std::memory_order_acq_rel))
          {
            return;  // a repeat verdict from a contract-violating interface is ignored (no double barrier
                     // decrement).
          }
          auto strong = weakSelf.lock();
          if (!strong)
          {
            // The Connection was destroyed mid-flight (after dispatch, before the async validate verdict
            // landed): nothing left to act on, BUT the owed completion must still be delivered  -  it is the
            // Client-walk barrier decrement and does NOT touch the gone Connection, so dropping it would hang
            // the aggregate (it would never reach zero). Deliver Good directly (the ack is advisory, J53).
            completion(ua::VoidResult{});
            return;
          }
          ua::async::post_borrowing(strong.get(),
            strong->mStrand,
            strong->mLogger,
            std::move(completion),
            ua::VoidResult{},
            [verdict = std::move(verdict)](
              ConnectionImpl& self2, std::function<void(ua::VoidResult)> completion2) mutable
            {
              // Bad verdict (now-untrusted/revoked/expired): ACT  -  drive the FSM with CertRotated. Never
              // silently discard the rejection reason (the design specification): LOG it at this decision
              // boundary, then THREAD the real status + ErrorDetail chain into the trigger so a subsequent
              // reconnect exhaustion surfaces the actual reason (not a synthetic BadCertificateUntrusted).
              if (verdict.is_bad())
              {
                self2.mLogger.warning(
                  "client.tier1.connection.revalidate: the active server certificate is no "
                  "longer valid (0x{:08x}); routing this Connection to a CertRotated "
                  "reconnect",
                  verdict.status_code().as_uint32());
                self2.trigger_cert_rotated_reconnect(verdict.status_code(), verdict.shared_detail());
              }
              // ACKNOWLEDGED-Good on BOTH the still-trusted and acted-on-untrusted paths (J53).
              self2.deliver_revalidate_ack(std::move(completion2));
            })();
        });
    })();
}

void ConnectionImpl::trigger_cert_rotated_reconnect(
  ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> chain)
{
  // Strand-only (called from the revalidate_server_cert_async verdict re-hop). Mirror
  // trigger_reconnect_async's guard: a single-shot / terminal Connection cannot start a reconnect. Unlike
  // the redundancy trigger this is fire-and-forget  -  no pending completion is stashed (the walk aggregate
  // is advisory, J53). The FSM debounces a re-entrant trigger while a reconnect is already in flight. @p
  // status
  // +
  // @p chain are the SEAM verdict's actual rejection reason
  // (BadCertificate{Untrusted,Revoked,TimeInvalid,...}
  // + its ErrorDetail chain), threaded through so a subsequent reconnect exhaustion surfaces the real reason.
  if (!mReconnectFsm || is_terminal_state())
  {
    return;
  }
  mReconnectFsm->trigger(ua::client::ReconnectCause{ua::client::CertRotated{}}, status, std::move(chain));
}

void ConnectionImpl::deliver_revalidate_ack(std::function<void(ua::VoidResult)> callback)
{
  // Strand  to  executor hop (section 8.2A.1 rule 3): the user callback never fires on the connection strand.
  // The revalidate always acknowledges Good  -  no failure is manufactured here, so there is no ErrorDetail
  // to source-tag on this path.
  ua::async::post_owning(this,
    mExecutor,
    mLogger,
    [callback = std::move(callback)](ConnectionImpl&) mutable { callback(ua::VoidResult{}); })();
}

ua::client::RedundancyManager ConnectionImpl::redundancy()
{
  // Lock-free synchronous read: mRedundancyManager is write-once in wire_redundancy (reconnect-wired only),
  // before `self` is published, and never reassigned. Null on a single-shot Connection -> a null-wrapped
  // handle whose facade is already null-safe (empty info / Bad_ConnectionClosed / Good-close).
  return RedundancyManagerFactory::wrap(mRedundancyManager);
}

void ConnectionImpl::trigger_redundancy_reconnect_async(ua::client::ReconnectCause cause,
  ua::StatusCode degradeStatus, std::shared_ptr<const ua::ErrorDetail> chain,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [cause = std::move(cause), degradeStatus, chain = std::move(chain), callback = std::move(callback)](
      ConnectionImpl& self) mutable
    {
      if (!self.mReconnectFsm || self.is_terminal_state())
      {
        // Single-shot / terminal: no failover reconnect can start. Complete Bad on the executor so the
        // manager returns to Monitoring (section 8.11.5) rather than awaiting a completion that will never
        // come.
        ua::async::post_owning(&self,
          self.mExecutor,
          self.mLogger,
          [callback = std::move(callback)](ConnectionImpl&) mutable
          {
            const ua::StatusCode status{ua::Status::BadConnectionClosed};
            callback(ua::VoidResult{status,
              ua::ErrorDetail::build("RedundancyReconnectUnavailable",
                "the Connection is single-shot or terminal; no failover reconnect can start",
                "client.tier1.redundancy.trigger.unavailable")
                .cause(status)});
          })();
        return;
      }
      // A prior pending completion (should not normally exist  -  the manager serializes triggers) is
      // superseded: fire it Good first so it is never dropped, then stash this one and kick the FSM with the
      // redundancy cause. The stashed completion is fired from the terminal notify handlers / begin_close.
      self.fire_redundancy_reconnect_pending(ua::VoidResult{});
      self.mRedundancyReconnectPending = std::move(callback);
      self.mReconnectFsm->trigger(std::move(cause), degradeStatus, std::move(chain));
    })();
}

void ConnectionImpl::fire_redundancy_reconnect_pending(ua::VoidResult result)
{
  // Strand-only. Hand the single in-flight redundancy-reconnect completion its terminal result on the
  // executor (never the strand  -  the design specification), then clear it so it fires exactly once. No-op
  // if none is pending.
  if (!mRedundancyReconnectPending)
  {
    return;
  }
  ua::async::post_owning(this,
    mExecutor,
    mLogger,
    [pending = std::move(mRedundancyReconnectPending), result = std::move(result)](ConnectionImpl&) mutable
    { pending(std::move(result)); })();
  mRedundancyReconnectPending = nullptr;
}

// ---- Observer registration (section 7.8 / wiring section 1) ----

std::shared_ptr<ObserverSink> ConnectionImpl::observer_sink() const noexcept
{
  return mObserverSink;
}

void ConnectionImpl::reresolve_observers_on_strand()
{
  // Strand-only: rebuild the immutable resolved snapshot from the current per-Connection slots + the
  // Client-level defaults and atomically install it (the sink's set_slots is the single publication point).
  if (mObserverSink)
  {
    mObserverSink->set_slots(resolve_observer_slots(mPerConnectionObservers, mClientObserverDefaults));
  }
}

// Each setter posts to the strand (mPerConnectionObservers is strand-only state), replaces the family slot,
// and re-resolves. A gone orchestrator drops the update (post_borrowing no-ops).

void ConnectionImpl::set_connection_observer_async(std::shared_ptr<ConnectionObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.connection = std::move(observer);
      self.reresolve_observers_on_strand();
    })();
}

void ConnectionImpl::set_subscription_observer_async(std::shared_ptr<SubscriptionObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.subscription = std::move(observer);
      self.reresolve_observers_on_strand();
    })();
}

void ConnectionImpl::set_security_observer_async(std::shared_ptr<SecurityObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.security = std::move(observer);
      self.reresolve_observers_on_strand();
    })();
}

void ConnectionImpl::set_type_observer_async(std::shared_ptr<TypeObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.type = std::move(observer);
      self.reresolve_observers_on_strand();
    })();
}

void ConnectionImpl::set_address_space_observer_async(std::shared_ptr<AddressSpaceObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.addressSpace = std::move(observer);
      self.reresolve_observers_on_strand();
      // M1: a consumer registered AFTER first-active (the common connect-then-observe flow) must still
      // trigger the router's four backbone event Subscriptions. start() is idempotent and re-checks the
      // consumer gate, so once this AddressSpaceObserver is installed the previously-suppressed subscribe now
      // happens.
      self.start_event_routing_if_active();
    })();
}

void ConnectionImpl::set_server_state_observer_async(std::shared_ptr<ServerStateObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.serverState = std::move(observer);
      self.reresolve_observers_on_strand();
      // CL-EVT-005: a ServerStateObserver consumes SystemStatusChange events. Re-evaluate the router gate
      // for the common connect-then-observe flow, matching the address-space and alarm observer setters.
      self.start_event_routing_if_active();
    })();
}

void ConnectionImpl::set_alarm_observer_async(std::shared_ptr<AlarmObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.alarm = std::move(observer);
      self.reresolve_observers_on_strand();
      // M1: an AlarmObserver consumes audit events  -  a late registration must likewise trigger the router's
      // backbone subscriptions (see set_address_space_observer_async).
      self.start_event_routing_if_active();
    })();
}

void ConnectionImpl::set_redundancy_observer_async(std::shared_ptr<RedundancyObserver> observer) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [observer = std::move(observer)](ConnectionImpl& self) mutable
    {
      self.mPerConnectionObservers.redundancy = std::move(observer);
      self.reresolve_observers_on_strand();
    })();
}

void ConnectionImpl::notify_transport_drop_async(ua::StatusCode cause, std::uint64_t issuedEpoch) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [cause, issuedEpoch](ConnectionImpl& self)
    {
      if (!self.mReconnectFsm || self.is_terminal_state())
      {
        return;  // single-shot Connection, or already closing/closed/failed: do not start a reconnect
      }
      if (self.mReconnectAttemptEpoch != issuedEpoch)
      {
        // Stale: this Publish was issued on a channel a later reconnect already superseded (the epoch has
        // moved on). Honouring it would tear down and rebuild a healthy, already-recovered connection.
        return;
      }
      // Carry the observed drop status as the trigger cause (the manual trigger uses a synthetic
      // BadConnectionClosed). The FSM debounces a re-entrant trigger while a reconnect is already in
      // flight, so several fatal Publish responses from one drop collapse to a single reconnect sequence.
      self.mReconnectFsm->trigger(ua::client::TransportDropped{}, cause, nullptr);
    })();
}

void ConnectionImpl::on_channel_lost_async(
  ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [status, detail = std::move(detail)](ConnectionImpl& self) mutable
    {
      if (self.mReconnectFsm || self.is_terminal_state())
        return;  // a reconnecting Connection handles drops itself; a terminal one has nothing left to report
      std::shared_ptr<const ua::ErrorDetail> chain =
        ua::ErrorDetail::build("SecureChannelLost",
          "the SecureChannel of a Connection without automatic reconnect was lost",
          "client.tier1.connection")
          .cause(ua::StatusCode{status.value(), std::move(detail)});
      self.reconnect_notify_failed(status, std::move(chain));
    })();
}

// --- KeepAlive poll (section 8.2A.6) ----------------------------------------------------------------------
// A strand-serialized periodic poll of Server.ServerStatus.State. It is the independent liveness signal
// for a Connection with NO active Subscription: with no Publishes in flight, a silently-dead link (a
// half-open TCP / hung server / black-hole) would otherwise go undetected until the next user wire op
// (which may be never). Armed on reach-active, disarmed on reconnecting / close / terminal.

void ConnectionImpl::arm_keep_alive_timer()
{
  // Strand-only. Keep-alive only exists with reconnect wiring (a miss drives the FSM); an interval <= 0
  // disables it (opt-out); it polls only while Active. Reconstruct the tracker so each Active lifetime
  // begins with a fresh miss count, and reset the in-flight guard before scheduling.
  if (!mReconnectFsm || mKeepAlivePolicy.interval <= std::chrono::milliseconds::zero() ||
      mState != ConnectionState::Active)
  {
    return;
  }
  mKeepAliveTracker = KeepAliveTracker{mKeepAlivePolicy.missedBeforeReconnect};
  mKeepAlivePollInFlight = false;

  // CL-SESS-020 (section 8.2A.6): bound the poll interval by the server's REVISED session timeout so the
  // client polls at least (missedBeforeReconnect + 1) times before the Session auto-closes. An unknown (0)
  // revised timeout honours the configured interval; a pathologically small bound is clamped to a floor (and
  // logged) rather than arming a sub-50 ms busy-poll.
  const double revisedTimeoutMs = mSessionOps ? mSessionOps->revised_session_timeout_ms() : 0.0;
  mEffectiveKeepAliveInterval = mKeepAlivePolicy.interval;
  if (revisedTimeoutMs > 0.0)
  {
    const auto divisor = static_cast<std::int64_t>(mKeepAlivePolicy.missedBeforeReconnect) + 1;
    const std::chrono::milliseconds bound{static_cast<std::int64_t>(revisedTimeoutMs) / divisor};
    mEffectiveKeepAliveInterval = std::min(mKeepAlivePolicy.interval, bound);
    constexpr std::chrono::milliseconds keepAliveFloor{50};
    if (mEffectiveKeepAliveInterval < keepAliveFloor)
    {
      mLogger.warning(
        "keep-alive: revised session timeout {} ms yields an interval below the {} ms floor; clamping",
        static_cast<std::uint64_t>(revisedTimeoutMs),
        keepAliveFloor.count());
      mEffectiveKeepAliveInterval = keepAliveFloor;
    }
  }

  // schedule_every fires on the connection strand (mStrand), so the notifier runs strand-serialized with
  // every other orchestrator turn - no extra hop is needed to reach strand-only state. Weak self-capture:
  // a notifier that fires after this orchestrator is destroyed locks a dead weak and does nothing, and the
  // mKeepAliveTimer member cancels on destruction (cancellation is final, so a pending fire is suppressed).
  auto weakSelf = weak_from_this();
  mKeepAliveTimer = ua::Timer::schedule_every(mStrand,
    mEffectiveKeepAliveInterval,
    [weakSelf](boost::system::error_code error)
    {
      if (error)
      {
        return;  // an Asio-level failure ends the schedule; a cancel never reaches here at all
      }
      if (const auto self = weakSelf.lock())
      {
        self->keep_alive_poll_on_strand();
      }
    });
}

void ConnectionImpl::disarm_keep_alive_timer()
{
  // Strand-only. Cancelling the member stops the schedule, and ua::Timer cancellation is final: an
  // already-queued notifier fire is suppressed rather than delivered. Clear the in-flight guard so a fresh
  // arm starts clean (a poll that completes after disarm is epoch-guarded).
  mKeepAliveTimer = {};
  mKeepAlivePollInFlight = false;
}

void ConnectionImpl::keep_alive_poll_on_strand()
{
  // Runs on the connection strand (the timer fires here). Only poll while Active - a tick that raced a
  // close / reconnect is dropped. Do NOT stack polls: while one read is outstanding, later ticks are
  // skipped, so a slow (hung-server) read occupies at most one interval and its own timeout makes the
  // stall a miss when it completes. The defensive null-session guard mirrors invoke_wire_op.
  if (mState != ConnectionState::Active || mKeepAlivePollInFlight || !mSessionOps)
  {
    return;
  }
  mKeepAlivePollInFlight = true;
  // Read directly on the live session (like pipeline_send_publish) - NOT through the wire-op gate - so the
  // keep-alive probes even while user ops queue during a soft stall. Capture the reconnect-attempt epoch at
  // ISSUE time; the completion hops back onto this strand and epoch-guards, so a poll from a channel a later
  // reconnect superseded cannot feed the tracker of the recovered connection.
  const std::uint64_t issuedEpoch = mReconnectAttemptEpoch;
  const auto timeoutHintMs = static_cast<std::uint32_t>(std::clamp<std::int64_t>(
    mEffectiveKeepAliveInterval.count(), 1, std::numeric_limits<std::uint32_t>::max()));
  mSessionOps->read_async(build_server_state_read(timeoutHintMs),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [issuedEpoch](ConnectionImpl& self, ua::Result<ua::ReadResponse> readResult) mutable
      { self.finish_keep_alive_poll(std::move(readResult), issuedEpoch); }));
}

void ConnectionImpl::finish_keep_alive_poll(
  ua::Result<ua::ReadResponse> readResult, std::uint64_t issuedEpoch)
{
  // Strand-only (re-entered via the strand hop). The epoch guard MUST come BEFORE releasing the in-flight
  // guard: a reconnect resets mKeepAlivePollInFlight (disarm on Reconnecting, arm on Active), so by the time
  // a stale (superseded-attempt) poll completes the guard may already belong to a NEW current-epoch poll -
  // clearing it here for a stale completion would let a second poll STACK on the live one. So a stale
  // completion drops silently WITHOUT touching the guard or the tracker (honouring it would also trigger a
  // reconnect on an already-recovered connection).
  if (mReconnectAttemptEpoch != issuedEpoch)
  {
    return;
  }
  // This completion belongs to the CURRENT in-flight poll: release the guard so the next tick can poll again.
  mKeepAlivePollInFlight = false;
  if (mState != ConnectionState::Active || !mReconnectFsm)
  {
    // A close / reconnect raced the completion (or, defensively, no FSM to drive): drop this poll.
    return;
  }

  // Classify the poll as a MISS (no live answer -> the link/session is gone) vs a SUCCESS (the server
  // answered -> it is alive). A transport-bad Result is a miss: no response came back (a dead link, or no
  // answer within the poll's timeout_hint). A well-formed response is a miss ONLY when its service_result is
  // channel/session-fatal (is_channel_fatal - the server answered but the channel/session is gone, which the
  // reconnect must recover); a response carrying a NON-fatal service error (e.g. Bad_ServerTooBusy under
  // load, Bad_NodeIdUnknown) means the server is ALIVE and answering, so it is a SUCCESSFUL poll - counting
  // it as a miss would spuriously reconnect a live-but-busy server. The effective status (for logging) is the
  // transport status or the in-band service_result, mirroring pipeline_send_publish.
  const ua::StatusCode effective = !readResult.has_value()
                                     ? readResult.status_code()
                                     : readResult.value().response_header().service_result();
  const bool missed = !readResult.has_value() || is_channel_fatal(effective);
  const KeepAliveServerHint serverHint =
    missed ? KeepAliveServerHint{} : parse_keep_alive_server_hint(readResult.value());
  const KeepAliveAction action =
    missed ? mKeepAliveTracker.on_read_failure() : mKeepAliveTracker.on_read_success(serverHint.maintenance);
  if (missed && action == KeepAliveAction::None)
  {
    // A miss below the threshold: log the observed status so an intermittent-but-not-yet-triggering link
    // problem is diagnosable, not silent (the design specification), before the next poll may reset the
    // counter.
    mLogger.debug("keep-alive: missed poll {} of {} (read 0x{:08x})",
      mKeepAliveTracker.consecutive_misses(),
      mKeepAlivePolicy.missedBeforeReconnect,
      effective.as_uint32());
  }

  switch (action)
  {
  case KeepAliveAction::None:
    // Healthy, or still below the miss threshold: nothing to do. The periodic timer re-arms itself on its
    // fixed grid, so the next poll issues on the next tick.
    break;
  case KeepAliveAction::TriggerReconnect:
    // Log the last bad read's status at the wire boundary before the KeepAliveMissed cause subsumes it into
    // a synthetic BadNoCommunication trigger (the design specification: never silently drop the observed
    // status).
    mLogger.warning(
      "keep-alive: {} consecutive missed polls (last read 0x{:08x}); triggering a KeepAliveMissed reconnect",
      mKeepAliveTracker.consecutive_misses(),
      effective.as_uint32());
    notify_keep_alive_missed_async(issuedEpoch);
    break;
  case KeepAliveAction::TriggerShutdown:
    mLogger.info(
      "keep-alive: server reported shutdown/maintenance; triggering a paced ServerShutdown "
      "reconnect (future EstimatedReturnTime={})",
      serverHint.estimatedReturnTime.has_value());
    notify_server_shutdown_async(issuedEpoch, serverHint.estimatedReturnTime);
    break;
  }
}

void ConnectionImpl::notify_keep_alive_missed_async(std::uint64_t issuedEpoch) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [issuedEpoch](ConnectionImpl& self)
    {
      if (!self.mReconnectFsm || self.is_terminal_state())
      {
        return;  // single-shot Connection, or already closing/closed/failed: do not start a reconnect
      }
      if (self.mReconnectAttemptEpoch != issuedEpoch)
      {
        return;  // stale: the poll's channel was superseded by a later reconnect (epoch moved on)
      }
      // Synthetic BadNoCommunication cause (the canonical "no keep-alive for N intervals" status); mirrors
      // the manual trigger's synthetic status. The FSM debounces a re-entrant trigger while a reconnect is
      // already in flight, so a keep-alive miss and a Publish-fatal drop collapse to one reconnect sequence.
      self.mReconnectFsm->trigger(
        ua::client::KeepAliveMissed{}, ua::StatusCode{ua::Status::BadNoCommunication}, nullptr);
    })();
}

void ConnectionImpl::notify_server_shutdown_async(
  std::uint64_t issuedEpoch, std::optional<ua::DateTime> estimatedReturnTime) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [issuedEpoch, estimatedReturnTime = std::move(estimatedReturnTime)](ConnectionImpl& self)
    {
      if (!self.mReconnectFsm || self.is_terminal_state())
      {
        return;
      }
      if (self.mReconnectAttemptEpoch != issuedEpoch)
      {
        return;
      }
      self.mReconnectFsm->trigger(ua::client::ServerShutdown{},
        ua::StatusCode{ua::Status::BadServerHalted},
        nullptr,
        estimatedReturnTime);
    })();
}

// --- Reconnect FSM notify handlers -----------------------------------------------------------------
// Each is called by ConnectionReconnectHost from the FSM strand and hops onto this orchestrator's own
// strand to update mState + drive the dispatch gate. The terminal-state guards keep a late reconnect
// notification from resurrecting a closing/closed Connection.

void ConnectionImpl::reconnect_notify_reconnecting(std::size_t attempt, ReconnectCause cause)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [attempt, cause = std::move(cause)](ConnectionImpl& self) mutable
    {
      if (self.mState == ConnectionState::Closing || self.mState == ConnectionState::Closed ||
          self.mState == ConnectionState::Failed)
      {
        return;
      }
      self.mState = ConnectionState::Reconnecting;
      self.publish_info();
      self.disarm_keep_alive_timer();  // stop polling during the outage (a poll would race the session swap)
      self.mDispatch->notify_reconnecting_async();  // queue wire ops until Active returns
      if (self.mPipeline)
      {
        self.mPipeline->stop_async();  // halt the Publish pump during the outage (its sends would drop)
      }
      // An automatic reconnect attempt has begun (section 7.8 on_reconnecting). Fires once per FSM attempt
      // (the FSM's on_fsm_state_changed is attempt-level) carrying the 1-based attempt + the driving cause.
      if (self.mObserverSink)
      {
        self.mObserverSink->fire_reconnecting(attempt, std::move(cause));
      }
    })();
}

void ConnectionImpl::reconnect_notify_active(ReconnectOutcome outcome)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [outcome = std::move(outcome)](ConnectionImpl& self) mutable
    {
      if (self.mState == ConnectionState::Closing || self.mState == ConnectionState::Closed ||
          self.mState == ConnectionState::Failed)
      {
        return;  // terminal/closing: a late reach-Active must not resurrect a Failed/closed Connection or
                 // re-fire on_reconnected (defense-in-depth; the FSM's terminal + generation discipline also
                 // prevents a second notify).
      }
      self.mState = ConnectionState::Active;
      outcome.subscriptionsTransferred =
        outcome.subscriptionsTransferred || self.mSubscriptionsTransferredThisAttempt;
      outcome.monitoredItemsRecreated =
        std::max(outcome.monitoredItemsRecreated, self.mMonitoredItemsRecreatedThisAttempt);
      self.publish_info();
      self.mDispatch->notify_active_async();  // flush everything that queued during the outage
      // CL-AC-013: subscription recovery has committed and the recovered wire path is Active. Notify the
      // event subsystem BEFORE resuming Publish so a Cold/Warm switch clears former-server alarm state and
      // queues its mandatory ConditionRefresh ahead of any new-server event delivery. The subscriber and
      // tracker each self-marshal onto their shared private strand; this connection strand never reaches in.
      if (outcome.cause)
      {
        if (const auto* switchInfo = std::get_if<ua::client::RedundancySwitchInfo>(&*outcome.cause))
        {
          if (auto eventSubscriber = self.mEventSubscriber.load())
          {
            eventSubscriber->on_redundancy_switch_recovered_async(switchInfo->mode);
          }
        }
      }
      if (self.mPipeline)
      {
        // Resume the Publish pump on the rebound session so subscription notifications flow again
        // (the subscriptions survived the session rebind; the pump's stale outstanding is cleared).
        self.mPipeline->resume_async();
      }
      self.arm_keep_alive_timer();  // resume keep-alive polling on the rebound session (fresh miss count)
      // W4: the FSM reached Active. Fire the pending redundancy-reconnect completion Good so the manager's
      // trigger interface is completed (the manager's trigger completion is a NO-OP on Good  -  it awaits
      // on_reconnect_completed to enter RecoveryWindow, NOT this Good), THEN drive the manager's
      // reconnect-completed hook with the recovered outcome (its optional cause distinguishes the manager's
      // own failover from a plain drop); THAT hook performs the RecoveryWindow transition. The two are posts
      // to the manager's OWN strand, so the 1-hop on_reconnect_completed actually runs before the 2-hop
      // pending-Good  -  harmless precisely because the pending Good is a state-guarded no-op. Copy the
      // outcome for the manager; the observer fire below moves it.
      self.fire_redundancy_reconnect_pending(ua::VoidResult{});
      if (self.mRedundancyManager)
      {
        self.mRedundancyManager->on_reconnect_completed_async(outcome, [](ua::VoidResult) {});
      }
      // A reconnect completed and the Connection is Active again (section 7.8 on_reconnected). Carries the
      // recovered outcome (session-preserved / subscriptions-transferred / the optional driving cause the
      // tier-2 RedundancyManager keys its failover completion on). This is NOT on_connected - that is
      // first-connect only (fired once by on_first_session_active).
      if (self.mObserverSink)
      {
        self.mObserverSink->fire_reconnected(std::move(outcome));
      }
    })();
}

void ConnectionImpl::reconnect_notify_failed(
  ua::StatusCode terminal, std::shared_ptr<const ua::ErrorDetail> chain)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [terminal, chain = std::move(chain)](ConnectionImpl& self) mutable
    {
      if (self.mState == ConnectionState::Closing || self.mState == ConnectionState::Closed ||
          self.mState == ConnectionState::Failed)
      {
        return;  // already terminal/closing: never re-fire on_disconnected/on_error_chain from a second
                 // notify_failed (defense-in-depth; the FSM's terminal discipline also prevents this).
      }
      self.mState = ConnectionState::Failed;
      self.disarm_keep_alive_timer();  // terminal: never poll again (a fired notifier is inert past here)
      // The reconnect gave up: clear the strand-only recovery flag so the relaxed pipeline_republish gate
      // cannot stay open on the terminal Failed path, and purge the pipeline's barrier so it does not linger.
      self.mRecoveryInProgress = false;
      if (self.mPipeline)
      {
        self.mPipeline->stop_async();  // idempotent: halts the pump and clears any recovery barrier
      }
      self.publish_info();
      self.mDispatch->notify_failed_async(terminal);  // complete queued + future ops with the terminal
      // W4: drive the manager's transport-fatal hook FIRST (a no-op while it is already FailingOver), using a
      // COPY of the chain so the observer fires below can still move it. Order vs the pending Bad below is
      // required: firing the pending Bad first would move the manager FailingOver -> Monitoring, and then
      // on_transport_fatal would re-enter scoring (a spurious re-failover) - so on_transport_fatal must run
      // while the manager is still FailingOver (where it is a no-op).
      if (self.mRedundancyManager)
      {
        self.mRedundancyManager->on_transport_fatal_async(terminal, chain, [](ua::VoidResult) {});
      }
      // The Connection terminally left Active for Failed (section 7.8 on_disconnected) carrying the full
      // terminal reason + cause chain, and the same chain crosses the tier/wire boundary advisory
      // (on_error_chain, CL-DIAG-011). Both fire off-strand via the sink; the chain is NEVER dropped (the
      // design specification).
      if (self.mObserverSink)
      {
        self.mObserverSink->fire_disconnected(terminal, chain);
        self.mObserverSink->fire_error_chain(terminal, std::move(chain), "client.tier1.reconnection_fsm");
      }
      // Then fire the pending redundancy-reconnect completion Bad (the failover reconnect exhausted its
      // attempts) - AFTER on_transport_fatal so the manager returns to Monitoring only once, without a
      // spurious re-score.
      self.fire_redundancy_reconnect_pending(ua::VoidResult{terminal,
        ua::ErrorDetail::build("RedundancyReconnectFailed",
          "the failover reconnect exhausted its attempts",
          "client.tier1.redundancy.trigger.failed")
          .cause(terminal)});
    })();
}

void ConnectionImpl::on_first_session_active()
{
  // Strand-only; idempotent-latched. The initial bootstrap reached Active for the FIRST time: fire the
  // one-time on_connected + on_session_activated transitions (section 7.8). A later reconnect reaches Active
  // again, but that is on_reconnected (see reconnect_notify_active), NOT a fresh on_connected - hence the
  // latch.
  if (mFirstActiveReached)
  {
    return;
  }
  mFirstActiveReached = true;
  if (mObserverSink)
  {
    mObserverSink->fire_connected();
    mObserverSink->fire_session_activated();
  }
  // W4 attach point: the (eagerly-constructed, reconnect-wired-only) RedundancyManager needs a live,
  // activated Session before it can read the active server's ServiceLevel / find backups / fail over. Drive
  // its on_session_active hook HERE, on the FIRST reach-Active only (a later reconnect reaches Active again,
  // but that drives on_reconnect_completed, not a fresh on_session_active). The manager self-marshals onto
  // its own strand.
  if (mRedundancyManager)
  {
    mRedundancyManager->on_session_active_async(mSessionId, [](ua::VoidResult) {});
  }
  // W8b attach point: subscribe the four routed NS0 event types (model / semantic / audit) into the observer
  // fan-out + the address-space / semantic-change caches (CL-EVT-003/004). Eager subscribe at first-active
  // (J57); idempotent, so a later reconnect reaching Active again does not re-subscribe.
  if (mEventRouter)
  {
    mEventRouter->start();
  }
  // Seed the TypeResolver with the bootstrap NamespaceTable (strand-only; mNamespaceTable is populated by the
  // bootstrap NamespaceArray read before Active). Building + seeding it here  -  not lazily on the first
  // resolve  -  guarantees any post-Active decode-path consumer sees a SEEDED resolver (closes the W-1
  // stale-namespace hazard) and attaches user registrations parked during the bootstrap window (CL-BASE-008 /
  // CL-ATTR-012).
  if (mNamespaceTable)
  {
    type_resolver()->on_namespace_table_replaced_async(mNamespaceTable, [] {});
  }
}

void ConnectionImpl::start_event_routing_if_active()
{
  // Strand-only (M1). Called from the observer setters after installing a late consumer. start() is
  // idempotent and re-checks its consumer gate, so a first-active connection that had no consumer (and so
  // suppressed the subscribe) now subscribes. Before first-active the eager on_first_session_active start
  // will pick up the consumer, so this is a no-op then.
  if (mEventRouter && mFirstActiveReached)
  {
    mEventRouter->start();
  }
}

// --- Reconnect FSM tier-0 service primitives -------------------------------------------------------
// Each is called by ConnectionReconnectHost from the FSM strand; the completion-owning post hops onto
// this orchestrator's strand and guarantees @p done fires exactly once (Bad_ConnectionClosed if this
// orchestrator is gone by the strand turn - at which point the FSM, which this owns, is gone too).
// @p done itself re-enters the FSM strand, so calling it from this strand is safe (never runs FSM logic
// inline).

void ConnectionImpl::reconnect_get_endpoints(std::function<void(ua::VoidResult)> done)
{
  // CL-RECONN-005: reached only on the security-failure recovery path (SecurityFailure entry, or a
  // security-class OPN failure that refreshes once per attempt). At this point there is NO open channel
  // (the old channel is dead, and mPendingChannel is unset - step_open_channel runs AFTER this step). So
  // open a throwaway discovery channel via the reopen interface, issue a REAL GetEndpoints on it, and refresh
  // the stored endpoint description (server cert / security info) from the response. The discovery channel
  // is dropped after the response (its shared_ptr lives only in the GetEndpoints callback capture);
  // step_open_channel then opens the real channel. See the design specification.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // A close that raced in before this step was posted: bail cleanly (never open a fresh channel to a
      // server we are tearing down from). Mirrors reconnect_open_secure_channel's terminal guard.
      if (self.is_terminal_state())
      {
        completion(ua::VoidResult{ua::Status::BadConnectionClosed});
        return;
      }
      // Bump the dedicated GetEndpoints epoch (section 3.1): a stalled discovery GetEndpoints from a
      // timed-out attempt must NOT regress the published endpoint snapshot after a newer attempt already
      // refreshed it. The attempt epoch cannot be used here - it is bumped at the later open-channel step, so
      // two attempts' GetEndpoints share one attempt epoch. This counter is bumped per get_endpoints and
      // captured through to the completion, which drops its side effect if superseded.
      const std::uint64_t getEndpointsEpoch = ++self.mReconnectGetEndpointsEpoch;
      // Open the discovery channel. The reopen fires on the executor; the re-entry post hops back onto this
      // strand before touching strand-only state. If this orchestrator is gone by then the FSM is gone with
      // it, so a dropped completion is inert (the FSM owns it weakly).
      self.mReopen(ua::async::post_borrowing(&self,
        self.mStrand,
        self.mLogger,
        [settle = std::move(completion), getEndpointsEpoch](
          ConnectionImpl& conn, ua::Result<std::shared_ptr<ChannelOps>> channelResult) mutable
        {
          if (!channelResult.is_good())
          {
            // Could not even open a channel to run discovery on - surface the status; the FSM backs off. The
            // reconnect acts on the channel, so an Uncertain open is refused as a Bad one is.
            settle(ua::VoidResult{answer_refused(
              channelResult.status_code(), "ServiceAnswerUncertain", "client.tier1.reconnect.open_channel")});
            return;
          }
          // A newer GetEndpoints (or a close, which bumps nothing but leaves us terminal) has superseded this
          // stalled reopen: drop it before issuing a pointless discovery request. The completion is inert -
          // the FSM already dropped this attempt's step at its generation guard.
          if (conn.mReconnectGetEndpointsEpoch != getEndpointsEpoch || conn.is_terminal_state())
          {
            settle(ua::VoidResult{ua::Status::BadConnectionClosed});
            return;
          }
          std::shared_ptr<ChannelOps> discoveryChannel = std::move(channelResult).value();
          // Build the GetEndpoints request from the bound endpoint URL (the URL we are reconnecting to).
          ua::GetEndpointsRequest request;
          if (auto endpoint = conn.mEndpointSnapshot.load())
          {
            request.endpoint_url() = endpoint->endpoint_url();
          }
          // Compute the raw channel pointer into a LOCAL before moving the shared_ptr into the callback
          // capture (the design specification section 5): the two arguments to get_endpoints_async are
          // indeterminately sequenced, so reading discoveryChannel.get() as an argument while another
          // argument moves it would be a use-after-move. The moved-from shared_ptr keeps the pointee alive
          // (the callback now owns it), so rawChannel stays valid for the whole async op.
          ChannelOps* rawChannel = discoveryChannel.get();
          rawChannel->get_endpoints_async(std::move(request),
            ua::async::post_borrowing(&conn,
              conn.mStrand,
              conn.mLogger,
              [settle = std::move(settle), getEndpointsEpoch, discoveryChannel = std::move(discoveryChannel)](
                ConnectionImpl& conn2, ua::Result<ua::GetEndpointsResponse> endpointsResult) mutable
              {
                // The bound endpoint is refreshed from this answer, so only a Good one is used: an Uncertain
                // answer, with or without a response, is refused as a Bad one is.
                const ua::StatusCode answer =
                  endpointsResult.has_value() ? ua::detail::combined_status(endpointsResult.status_code(),
                                                  endpointsResult.value().response_header().service_result())
                                              : endpointsResult.status_code();
                if (!answer.is_good())
                {
                  settle(ua::VoidResult{answer_refused(
                    answer, "ServiceAnswerUncertain", "client.tier1.connection.reconnect_get_endpoints")});
                  return;
                }
                // Epoch guard on the SIDE EFFECT (section 3.1): a late-but-good GetEndpoints from a
                // superseded / timed-out attempt must not store its (possibly stale) endpoint description
                // over a newer attempt's fresh one. Also skip after close. The settle is inert either way
                // (FSM-dropped).
                if (conn2.mReconnectGetEndpointsEpoch != getEndpointsEpoch || conn2.is_terminal_state())
                {
                  settle(ua::VoidResult{ua::Status::BadConnectionClosed});
                  return;
                }
                conn2.refresh_endpoint_from_get_endpoints(endpointsResult.value());
                settle(ua::VoidResult{});
                // discoveryChannel drops here - the discovery channel is throwaway; step_open_channel opens
                // the real channel next.
              }));
        }));
    })();
}

void ConnectionImpl::refresh_endpoint_from_get_endpoints(const ua::GetEndpointsResponse& response)
{
  // Strand-only. Replace the published endpoint snapshot with the freshly-fetched description for the
  // endpoint we are bound to - picking up a rotated server certificate / changed security fields
  // (CL-RECONN-005). Match on (endpoint_url, security_policy_uri, security_mode); fall back to any endpoint
  // sharing our URL. Never clobber the current snapshot when nothing matches (a partial / unrelated
  // discovery response must not erase the bound identity).
  auto current = mEndpointSnapshot.load();
  if (!current)
  {
    return;  // nothing bound to refresh against
  }
  const ua::EndpointDescription* exactMatch = nullptr;
  const ua::EndpointDescription* urlMatch = nullptr;
  for (const auto& endpoint : response.endpoints())
  {
    if (endpoint.endpoint_url() != current->endpoint_url())
    {
      continue;
    }
    if (urlMatch == nullptr)
    {
      urlMatch = &endpoint;
    }
    if (endpoint.security_policy_uri() == current->security_policy_uri() &&
        endpoint.security_mode() == current->security_mode())
    {
      exactMatch = &endpoint;
      break;
    }
  }
  const ua::EndpointDescription* chosen = exactMatch != nullptr ? exactMatch : urlMatch;
  if (chosen == nullptr)
  {
    return;  // no endpoint for our URL in the response - keep the current snapshot
  }
  mEndpointSnapshot.store(std::make_shared<const ua::EndpointDescription>(*chosen));
  publish_info();
}

void ConnectionImpl::reconnect_open_secure_channel(std::function<void(ua::VoidResult)> done)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // Do not open a fresh channel to the server after close has begun (a reconnect step may have been
      // posted before close raced in; the FSM cancel cannot un-post it). Bail cleanly instead.
      if (self.is_terminal_state())
      {
        completion(ua::VoidResult{ua::Status::BadConnectionClosed});
        return;
      }
      // open-channel is the FSM's first step of EVERY attempt (begin_attempt): reset the attempt-scoped
      // pending holders here so a prior failed CL-RECONN-003 attempt cannot leave a stale mPendingSession
      // that mis-routes this attempt's activate into the second-pass (activate-new-session) branch. Bump
      // the attempt epoch (section 3.1 finding D): a late reopen/create completion from a step the FSM
      // already timed-out carries a stale epoch and must NOT re-emplace the holders after this reset.
      ++self.mReconnectAttemptEpoch;
      const std::uint64_t epoch = self.mReconnectAttemptEpoch;
      self.mPendingSession.reset();
      self.mPendingChannel.reset();
      // Session-CHANGED recovery (#24) is per-attempt: clear the semantic flag and DISCARD any re-keys a
      // superseded attempt staged. This is the stage-and-commit reset that closes NEW HAZARD 1 - a late
      // transfer/create completion from a timed-out attempt that stages during the backoff window is wiped
      // here before this attempt's recover step re-drives from the pipeline's pristine ids.
      self.mSessionChangedThisAttempt = false;
      self.mSubscriptionsTransferredThisAttempt = false;
      self.mMonitoredItemsRecreatedThisAttempt = 0;
      self.mStagedRekeys.clear();
      self.mStagedOwnerRekeys.clear();  // discard any superseded attempt's staged owner re-keys (CRITICAL 1)
      // mReopen fires its callback on the executor with a Result<SecureChannel>; the re-entry post hops
      // back onto this strand before touching mPendingChannel (strand-only state). If this orchestrator
      // is gone by then the FSM is gone with it, so a dropped completion is inert (FSM owns it weakly).
      self.mReopen(ua::async::post_borrowing(&self,
        self.mStrand,
        self.mLogger,
        [settle = std::move(completion), epoch](
          ConnectionImpl& conn, ua::Result<std::shared_ptr<ChannelOps>> channelResult) mutable
        {
          if (!channelResult.is_good())
          {
            // The reconnect acts on the channel, so an Uncertain open is refused as a Bad one is.
            settle(ua::VoidResult{answer_refused(
              channelResult.status_code(), "ServiceAnswerUncertain", "client.tier1.reconnect.open_channel")});
            return;
          }
          if (conn.mReconnectAttemptEpoch != epoch)
          {
            // A newer attempt superseded this one (this step was timed-out): drop the side-effect.
            settle(ua::VoidResult{ua::Status::BadConnectionClosed});
            return;
          }
          conn.mPendingChannel = std::move(channelResult).value();
          settle(ua::VoidResult{});
        }));
    })();
}

void ConnectionImpl::reconnect_activate_session(std::function<void(ua::VoidResult)> done)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (self.is_terminal_state())
      {
        completion(ua::VoidResult{ua::Status::BadConnectionClosed});
        return;
      }
      if (self.mPendingSession)
      {
        // CL-RECONN-003 second pass: a fresh Session was created (activate-on-existing returned
        // Bad_SessionIdInvalid). Activate THAT session on its own bound channel (create_session bound it),
        // not the stale existing session. commit installs mPendingSession as mSessionOps.
        self.mPendingSession->activate_on_bound_channel_async(self.mActivateConfig, std::move(completion));
        return;
      }
      if (!self.mPendingChannel || !self.mPendingChannel->is_open())
      {
        completion(ua::VoidResult{ua::Status::BadConnectionClosed});
        return;
      }
      // Happy path: rebind the EXISTING session onto the freshly-opened channel (Part 4 5.6.2): the
      // session survives channel loss and re-activates on the new channel. The interface consumes the channel
      // (the session then owns it); its completion IS the FSM completion. A Bad_SessionIdInvalid outcome
      // is routed to create_session by the FSM (which re-opens a channel). The pending channel handle is
      // kept (a shared_ptr copy is passed); its inner channel is consumed, so is_open() flips to false.
      self.mSessionOps->activate_on_channel_async(
        self.mPendingChannel, self.mActivateConfig, std::move(completion));
    })();
}

void ConnectionImpl::reconnect_create_session(std::function<void(ua::VoidResult)> done)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (self.is_terminal_state())
      {
        completion(ua::VoidResult{ua::Status::BadConnectionClosed});
        return;
      }
      // Same attempt as the open/activate that preceded it - capture (do NOT bump) the epoch (section 3.1 D).
      const std::uint64_t epoch = self.mReconnectAttemptEpoch;
      if (self.mPendingChannel && self.mPendingChannel->is_open())
      {
        // CertRotated route (FSM: open -> create, no intervening activate): the freshly-opened channel
        // was NOT consumed, so create the Session on it directly - re-opening would double-open (section 3.1
        // E).
        self.create_session_on(self.mPendingChannel, epoch, std::move(completion));
        return;
      }
      // CL-RECONN-003 route: activate-on-existing returned Bad_SessionIdInvalid and CONSUMED the channel
      // (is_open() is now false), so re-open a fresh channel, then create the Session on it. The FSM
      // re-runs activate_session (which activates the new session); commit installs it.
      self.mReopen(ua::async::post_borrowing(&self,
        self.mStrand,
        self.mLogger,
        [settle = std::move(completion), epoch](
          ConnectionImpl& conn, ua::Result<std::shared_ptr<ChannelOps>> channelResult) mutable
        {
          if (!channelResult.is_good())
          {
            // The reconnect acts on the channel, so an Uncertain open is refused as a Bad one is.
            settle(ua::VoidResult{answer_refused(
              channelResult.status_code(), "ServiceAnswerUncertain", "client.tier1.reconnect.open_channel")});
            return;
          }
          if (conn.mReconnectAttemptEpoch != epoch)
          {
            settle(ua::VoidResult{ua::Status::BadConnectionClosed});
            return;
          }
          conn.mPendingChannel = std::move(channelResult).value();
          conn.create_session_on(conn.mPendingChannel, epoch, std::move(settle));
        }));
    })();
}

void ConnectionImpl::create_session_on(
  const std::shared_ptr<ChannelOps>& channel, std::uint64_t epoch, std::function<void(ua::VoidResult)> settle)
{
  // Runs on the connection strand. Creates a Session on @p channel and stashes it in mPendingSession,
  // epoch-gated (section 3.1 D): a late completion from a superseded attempt drops the side-effect.
  ua::client::SecureChannel::CreateSessionConfig createConfig;
  createConfig.ecdhPolicyUri = mEcdhPolicyUri;
  createConfig.requestEphemeralKey = mRequestEphemeralKey;
  channel->create_session_async(std::move(createConfig),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [settle = std::move(settle), epoch](
        ConnectionImpl& inner, ua::Result<std::shared_ptr<SessionOps>> sessionResult) mutable
      {
        if (!sessionResult.has_value())
        {
          settle(ua::VoidResult{answer_refused(
            sessionResult.status_code(), "ServiceAnswerUncertain", "client.tier1.reconnect.create_session")});
          return;
        }
        if (sessionResult.is_uncertain())
        {
          // The reconnect acts on the Session it creates, so an Uncertain CreateSession answer is refused
          // (the FSM backs off and retries); the Session the server created is closed, best effort.
          const ua::StatusCode refused = uncertain_answer_refused(
            sessionResult.status_code(), "ServiceAnswerUncertain", "client.tier1.reconnect.create_session");
          std::shared_ptr<SessionOps> session = std::move(sessionResult).value();
          SessionOps* rawSession = session.get();
          rawSession->close_async([session = std::move(session)](ua::VoidResult) {});
          settle(ua::VoidResult{refused});
          return;
        }
        if (inner.mReconnectAttemptEpoch != epoch)
        {
          settle(ua::VoidResult{ua::Status::BadConnectionClosed});
          return;
        }
        inner.mPendingSession = std::move(sessionResult).value();
        inner.mPendingSession->set_return_diagnostics_override(
          inner.mDiagnosticPolicy.requestedDiagnosticsMask);
        // Record the semantic fact that THIS attempt created a fresh Session (the old server-side
        // Subscription ids are now gone): the recover step branches on this to transfer-or-recreate rather
        // than Republish-drain (#24). Reset at the next open-channel step (every attempt begins there).
        inner.mSessionChangedThisAttempt = true;
        settle(ua::VoidResult{});
      }));
}

void ConnectionImpl::reconnect_re_read_namespace_array(std::function<void(ua::VoidResult)> done)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // Re-read Server.NamespaceArray and rebuild the snapshot (CL-SESS-028). Read on the session that was
      // just re-activated: the freshly-created mPendingSession on the CL-RECONN-003 path (commit installs
      // it AFTER re-read), or the rebound existing mSession on the happy path. Reading the stale mSession
      // in the create-session case would fail on the invalidated session and loop the reconnect to Failed.
      SessionOps* activeSession = self.mPendingSession ? self.mPendingSession.get() : self.mSessionOps.get();
      activeSession->read_async(build_namespace_array_read(),
        ua::async::post_borrowing(&self,
          self.mStrand,
          self.mLogger,
          [settle = std::move(completion)](
            ConnectionImpl& conn, ua::Result<ua::ReadResponse> readResult) mutable
          { settle(conn.apply_namespace_read(readResult, conn.mSessionChangedThisAttempt)); }));
    })();
}

void ConnectionImpl::reconnect_recover_subscriptions(
  ua::client::SubscriptionRecovery recovery, std::function<void(ua::VoidResult)> done)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [recovery](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (!self.mPipeline)
      {
        completion(ua::VoidResult{});  // no pipeline (never constructed): nothing to recover
        return;
      }

      // Session-CHANGED branch (#24): a fresh Session was created this attempt (activate-on-existing failed
      // -> create_session), so the old server-side Subscription ids are gone and Republish against them
      // would only return Bad_SubscriptionIdInvalid. Snapshot the pipeline's callback-free recreate
      // descriptors (Q5 single owner) - the query fires on the PIPELINE strand, so hop BACK to the
      // connection strand - then drive the transfer-or-recreate barrier. Capture the attempt epoch NOW so
      // every wire completion can drop a response from a superseded attempt (H1).
      if (self.mSessionChangedThisAttempt)
      {
        // CL-VIEW-011: RegisterNodes aliases are Session-scoped. A FRESH Session was created this attempt, so
        // the server lost the registrations  -  clear the alias cache and bump its generation
        // (fire-and-forget; the clear is independent of the subscription recovery below). Gated on the
        // enabled cache so a disabled Connection never touches it. serverIdentityPreserved=true /
        // namespaceArrayChanged=false: this is a same-server reconnect, and the alias-clear + generation-bump
        // (the only effect this slice needs) is UNCONDITIONAL in on_session_changed_async regardless of those
        // flags (they only gate the attribute / browse sub-cache retention, which this slice does not
        // populate).
        if (self.mAddressSpaceCachePolicy.enabled)
        {
          self.address_space_cache()->on_session_changed_async(
            /*serverIdentityPreserved=*/true, /*namespaceArrayChanged=*/false, []() {});
        }
        const std::uint64_t issuedEpoch = self.mReconnectAttemptEpoch;
        self.mPipeline->recovery_descriptors_async(ua::async::post_borrowing(self.weak_from_this(),
          self.mStrand,
          self.mLogger,
          [recovery, issuedEpoch, completion = std::move(completion)](
            ConnectionImpl& conn, std::vector<RecoveryDescriptor> descriptors) mutable {
            conn.recover_session_changed(
              recovery, std::move(descriptors), issuedEpoch, std::move(completion));
          }));
        return;
      }

      // Session-PRESERVED branch (#23, unchanged): the existing Session was re-activated on the new channel,
      // so its Subscriptions still live server-side under the same ids. section 6.7 Republish-on-reconnect:
      // drain each Subscription's retained notifications before Publish resumes. Runs on the connection
      // strand while mState == Reconnecting (the Session was just re-activated; commit/reach_active follow).
      // Mark the recovery so pipeline_republish issues its Republishes during the outage (H1) instead of
      // dropping them on the Active-gate. RecreateOnly is a no-op distinction here (a preserved session keeps
      // its subs); it only diverges on the session-CHANGED branch above.
      self.mRecoveryInProgress = true;
      // The pipeline owns the per-Subscription drain barrier and fires the wrapped done on ITS strand; hop
      // BACK onto the connection strand (mRecoveryInProgress is strand-only) to clear the flag on BOTH
      // success and failure, then complete the FSM step. A Bad outcome makes on_step enter backoff and
      // retry the drain (F6); the sibling-strand post drops the work if this orchestrator (and thus the
      // FSM it owns) is gone by then - an inert loss.
      self.mPipeline->recover_subscriptions_async(ua::async::post_borrowing(self.weak_from_this(),
        self.mStrand,
        self.mLogger,
        [completion = std::move(completion)](ConnectionImpl& conn, ua::VoidResult recovered) mutable
        {
          conn.mRecoveryInProgress = false;
          completion(std::move(recovered));  // re-enters the FSM strand (generation-guarded)
        }));
    })();
}

void ConnectionImpl::recover_session_changed(ua::client::SubscriptionRecovery recovery,
  std::vector<RecoveryDescriptor> descriptors, std::uint64_t issuedEpoch,
  std::function<void(ua::VoidResult)> done)
{
  // Runs on the connection strand (re-posted from the pipeline-strand descriptor snapshot). Drives the
  // heterogeneous transfer-or-recreate barrier for a fresh Session (section 6.7 / #24). All wire ops target
  // mPendingSession (mSessionOps is still the invalidated old session until commit). Re-keys are STAGED and
  // applied atomically at commit (recovery_settle_one) - never mutating the live pipeline mid-drain.
  if (descriptors.empty())
  {
    done(ua::VoidResult{});  // no registered Subscriptions: nothing to transfer or recreate
    return;
  }

  auto barrier = std::make_shared<SessionChangedRecovery>();
  barrier->pending = descriptors.size();
  barrier->issuedEpoch = issuedEpoch;
  barrier->done = std::move(done);

  // RecreateOnly (or a forced RedundancySwitch): skip TransferSubscriptions and recreate every Subscription
  // directly from its retained descriptor.
  if (recovery == ua::client::SubscriptionRecovery::RecreateOnly)
  {
    for (auto& descriptor : descriptors)
    {
      recovery_recreate_subscription(barrier, std::move(descriptor));
    }
    return;
  }

  // TransferThenRecreate: one TransferSubscriptions for every sub (sendInitialValues so a transferred sub
  // re-reports its monitored items' current values on the first post-reconnect Publish). Its completion is
  // epoch-guarded on the connection strand; per result a Good transfer keeps the sub as-is (id + sequence
  // continue; the gap drains reactively once Active) and a bad result routes the sub to recreate (NEW HAZARD
  // 2: Bad_SubscriptionIdInvalid AT TRANSFER means "recreate me", it must NOT reach the A3 erase path).
  ua::TransferSubscriptionsRequest request;
  request.send_initial_values() = true;
  for (const auto& descriptor : descriptors)
  {
    request.subscription_ids().push_back(descriptor.subscriptionId);
  }

  SessionOps* activeSession = mPendingSession ? mPendingSession.get() : mSessionOps.get();
  activeSession->transfer_subscriptions_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [barrier, descriptors = std::move(descriptors)](
        ConnectionImpl& self, ua::Result<ua::TransferSubscriptionsResponse> result) mutable
      {
        // H1 epoch guard: a transfer reply from a superseded attempt must not stage anything. Dropping it
        // leaves the (superseded) barrier stalled; the FSM step deadline bounds that, and this attempt's
        // holders were already reset at its open-channel step.
        if (self.mReconnectAttemptEpoch != barrier->issuedEpoch)
        {
          return;
        }
        const bool transferOk =
          result.is_good() && result.value().response_header().service_result().is_good();
        // A whole-request failure (transport/service fault) or a truncated result array leaves us unable to
        // tell which subs the server accepted, so recreate every one (the safe, no-loss fallback). Guarded so
        // result.value() is only read when the Result is good (transferOk / perResult both imply is_good()).
        const bool perResult = transferOk && result.value().results().size() == descriptors.size();
        self.mSubscriptionsTransferredThisAttempt =
          perResult && std::all_of(result.value().results().begin(),
                         result.value().results().end(),
                         [](const ua::TransferResult& transfer) { return transfer.status_code().is_good(); });
        if (!transferOk)
        {
          // Log the transfer's effective bad status at the wire boundary before it is subsumed into the
          // recreate-all fallback (the design specification: never silently discard the status behind control
          // flow).
          const ua::StatusCode transferStatus =
            !result.has_value() ? result.status_code() : result.value().response_header().service_result();
          self.mLogger.warning(
            "session-CHANGED recovery: TransferSubscriptions failed (0x{:08x}); recreating all {} "
            "subscription(s)",
            transferStatus.as_uint32(),
            descriptors.size());
        }
        for (std::size_t index = 0; index < descriptors.size(); ++index)
        {
          const bool transferred = perResult && result.value().results()[index].status_code().is_good();
          if (transferred)
          {
            // Kept server-side under the SAME id with the sequence counter continuing (Q3): do NOT reset the
            // tracker and do NOT re-key - the transferred Subscription's tracker is preserved, so its queued
            // notifications resume IN ORDER as the pump replays the retransmission queue once Active, and any
            // true gap (server-dropped queue entries) is filled by the reactive Republish drain
            // (section 8.4.5). The section 6.7 SHOULD of seeding an explicit recover-step drain from
            // availableSequenceNumbers is deliberately deferred; its only observable effect is that, if the
            // server dropped queued entries, a last-value-wins consumer may briefly see the current value
            // before the reactive drain back- fills the older gap values (no data loss). This sub is done,
            // clean.
            if (self.mObserverSink)
            {
              self.mObserverSink->fire_subscription_transferred(descriptors[index].subscriptionId);
            }
            self.recovery_settle_one(barrier, ua::StatusCode{ua::Status::Good});
          }
          else
          {
            self.recovery_recreate_subscription(barrier, std::move(descriptors[index]));
          }
        }
      }));
}

void ConnectionImpl::recovery_recreate_subscription(
  std::shared_ptr<SessionChangedRecovery> barrier, RecoveryDescriptor descriptor)
{
  // Runs on the connection strand. Recreate one Subscription on the fresh Session: CreateSubscription then
  // CreateMonitoredItems for every retained item, both epoch-guarded. On full success stage the re-key
  // {oldId -> newId} (applied at commit, which resets the tracker to the fresh server sequence space) and
  // settle good; on any failure settle bad so the whole recovery reports Bad and the FSM re-drives.
  const std::uint32_t oldId = descriptor.subscriptionId;
  // Rebuild with the tuning the caller asked for, not the defaults. A recreate that sent the defaults would
  // hand back a Subscription with a different keep-alive, lifetime, priority and publishing mode from the
  // one that was lost, and report it as a successful recovery.
  const auto retainedEntry = mSubscriptionTuning.find(oldId);
  const SubscriptionTuning retainedTuning =
    retainedEntry != mSubscriptionTuning.end() ? retainedEntry->second : SubscriptionTuning{};
  SessionOps* activeSession = mPendingSession ? mPendingSession.get() : mSessionOps.get();
  activeSession->create_subscription_async(
    build_create_subscription_request(
      descriptor.publishingInterval, descriptor.maxNotificationsPerPublish, retainedTuning),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [barrier, descriptor = std::move(descriptor), oldId](
        ConnectionImpl& self, ua::Result<ua::CreateSubscriptionResponse> result) mutable
      {
        if (self.mReconnectAttemptEpoch != barrier->issuedEpoch)
        {
          return;  // superseded attempt: drop (H1)
        }
        // The recovery restores its state from the answer's data: an Uncertain answer without a response is
        // refused, and one with a response is used as a Good one is, its code carried to the outcome.
        if (!result.has_value())
        {
          self.recovery_settle_one(barrier,
            answer_refused(result.status_code(),
              "ServiceAnswerUncertain",
              "client.tier1.connection.recovery.create_subscription"));
          return;
        }
        const auto serviceResult = ua::detail::combined_status(
          result.status_code(), result.value().response_header().service_result());
        if (serviceResult.is_bad())
        {
          self.recovery_settle_one(barrier, serviceResult);
          return;
        }
        const std::uint32_t newId = result.value().subscription_id();

        // No monitored items to recreate: the sub is ready; stage the re-key and settle.
        if (descriptor.monitoredItems.empty())
        {
          if (self.mObserverSink)
          {
            self.mObserverSink->fire_subscription_recreated(oldId, newId);
          }
          barrier->stagedRekeys.emplace_back(oldId, newId);
          self.recovery_settle_one(barrier, serviceResult);
          return;
        }

        // Recreate every retained monitored item in one CreateMonitoredItems against the new Subscription,
        // preserving each item's client handle (so the pipeline's re-key repoints the existing callbacks).
        // The clientHandles are captured in request order so the response's per-index server monitored-item
        // ids can be paired back to their handles for the owner re-key (CRITICAL 1).
        // Build every retained item from its RETAINED tuning (shared per-item builder) + capture its
        // clientHandle in request order, so a session-CHANGED recreate preserves the caller's
        // attribute / indexRange / sampling / queue / mode and the response ids can be re-keyed by handle.
        std::vector<ua::MonitoredItemCreateRequest> itemsToCreate;
        itemsToCreate.reserve(descriptor.monitoredItems.size());
        std::vector<std::uint32_t> clientHandles;
        clientHandles.reserve(descriptor.monitoredItems.size());
        for (const auto& item : descriptor.monitoredItems)
        {
          itemsToCreate.push_back(build_monitored_item_create_request(item.nodeId,
            item.clientHandle,
            item.attribute,
            item.indexRange,
            item.samplingIntervalMs,
            item.queueSize,
            item.monitoringMode,
            item.discardOldest,
            item.filter));  // CL-MI-011 / OPEN-MI-011: re-send the retained filter on recreate
          clientHandles.push_back(item.clientHandle);
        }
        const std::size_t itemCount = descriptor.monitoredItems.size();

        // CL-BASE-003: chunk the recreate at MaxMonitoredItemsPerCall - the ONLY place the client batches
        // CreateMonitoredItems (the normal path creates one item at a time). Issue <= limit-sized creates
        // against the new Subscription, each epoch-guarded + count-checked, then validate + stage + settle on
        // the merged per-item results. A superseded epoch DROPS (the abandoned barrier is replaced by the new
        // attempt's) - matching the single-create path's H1 guard.
        const std::uint32_t itemLimit = self.mOperationLimits.maxMonitoredItemsPerCall;
        if (itemLimit != 0 && itemCount > itemLimit)
        {
          auto weak = self.weak_from_this();
          chunk_batch_async<ua::MonitoredItemCreateRequest, ua::CreateMonitoredItemsResponse>(
            std::move(itemsToCreate),
            itemLimit,
            [weak, newId, barrier](std::vector<ua::MonitoredItemCreateRequest> chunk,
              std::function<void(ua::Result<ua::CreateMonitoredItemsResponse>)>
                chunkDone) mutable
            {
              auto conn = weak.lock();
              if (!conn)
              {
                chunkDone(ua::Result<ua::CreateMonitoredItemsResponse>{ua::Status::BadConnectionClosed});
                return;
              }
              const std::size_t expected = chunk.size();
              ua::CreateMonitoredItemsRequest chunkRequest;
              chunkRequest.subscription_id() = newId;
              chunkRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
              chunkRequest.items_to_create() = to_ua_array(std::move(chunk));
              SessionOps* chunkSession =
                conn->mPendingSession ? conn->mPendingSession.get() : conn->mSessionOps.get();
              chunkSession->create_monitored_items_async(std::move(chunkRequest),
                ua::async::post_borrowing(conn.get(),
                  conn->mStrand,
                  conn->mLogger,
                  [chunkDone, expected, barrier](
                    ConnectionImpl& c, ua::Result<ua::CreateMonitoredItemsResponse> r) mutable
                  {
                    if (c.mReconnectAttemptEpoch != barrier->issuedEpoch)
                    {
                      return;  // superseded attempt: drop (the barrier is abandoned by the new attempt)
                    }
                    if (!r.has_value())
                    {
                      chunkDone(ua::Result<ua::CreateMonitoredItemsResponse>{answer_refused(r.status_code(),
                        "ServiceAnswerUncertain",
                        "client.tier1.connection.recovery.create_monitored_items")});
                      return;
                    }
                    const auto chunkServiceResult = ua::detail::combined_status(
                      r.status_code(), r.value().response_header().service_result());
                    if (chunkServiceResult.is_bad())
                    {
                      chunkDone(ua::Result<ua::CreateMonitoredItemsResponse>{chunkServiceResult});
                      return;
                    }
                    if (r.value().results().size() != expected)
                    {
                      chunkDone(ua::Result<ua::CreateMonitoredItemsResponse>{ua::Status::BadUnexpectedError});
                      return;
                    }
                    // The merge reads each chunk's code from its header, so the Result's own code joins it.
                    ua::CreateMonitoredItemsResponse response = std::move(r).value();
                    response.response_header().service_result() = chunkServiceResult;
                    chunkDone(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});
                  }));
            },
            [weak, barrier, oldId, newId, itemCount, serviceResult, clientHandles = std::move(clientHandles)](
              ua::Result<std::vector<ua::CreateMonitoredItemsResponse>> merged) mutable
            {
              auto conn = weak.lock();
              if (!conn || conn->mReconnectAttemptEpoch != barrier->issuedEpoch)
              {
                return;  // connection gone or superseded: recovery abandoned
              }
              if (!merged.has_value())
              {
                conn->recovery_settle_one(barrier,
                  answer_refused(merged.status_code(),
                    "ServiceAnswerUncertain",
                    "client.tier1.connection.recovery.create_monitored_items"));
                return;
              }
              ua::StatusCode answered = serviceResult;
              ua::Array<ua::MonitoredItemCreateResult> mergedResults;
              for (auto& chunkResponse : merged.value())
              {
                answered =
                  ua::detail::combined_status(answered, chunkResponse.response_header().service_result());
                for (auto& itemResult : chunkResponse.results())
                {
                  mergedResults.push_back(std::move(itemResult));
                }
              }
              conn->recovery_settle_recreated_items(std::move(barrier),
                oldId,
                newId,
                itemCount,
                std::move(clientHandles),
                mergedResults,
                answered);
            });
          return;
        }

        // Small subscription: recreate every retained item in one CreateMonitoredItems.
        ua::CreateMonitoredItemsRequest itemsRequest;
        itemsRequest.subscription_id() = newId;
        itemsRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
        itemsRequest.items_to_create() = to_ua_array(std::move(itemsToCreate));
        SessionOps* session = self.mPendingSession ? self.mPendingSession.get() : self.mSessionOps.get();
        session->create_monitored_items_async(std::move(itemsRequest),
          ua::async::post_borrowing(&self,
            self.mStrand,
            self.mLogger,
            [barrier, oldId, newId, itemCount, serviceResult, clientHandles = std::move(clientHandles)](
              ConnectionImpl& conn, ua::Result<ua::CreateMonitoredItemsResponse> itemsResult) mutable
            {
              if (conn.mReconnectAttemptEpoch != barrier->issuedEpoch)
              {
                return;  // superseded attempt: drop (H1)
              }
              if (!itemsResult.has_value())
              {
                conn.recovery_settle_one(barrier,
                  answer_refused(itemsResult.status_code(),
                    "ServiceAnswerUncertain",
                    "client.tier1.connection.recovery.create_monitored_items"));
                return;
              }
              const auto itemsServiceResult = ua::detail::combined_status(
                itemsResult.status_code(), itemsResult.value().response_header().service_result());
              if (itemsServiceResult.is_bad())
              {
                conn.recovery_settle_one(barrier, itemsServiceResult);
                return;
              }
              conn.recovery_settle_recreated_items(std::move(barrier),
                oldId,
                newId,
                itemCount,
                std::move(clientHandles),
                itemsResult.value().results(),
                ua::detail::combined_status(serviceResult, itemsServiceResult));
            }));
      }));
}

void ConnectionImpl::recovery_settle_recreated_items(std::shared_ptr<SessionChangedRecovery> barrier,
  std::uint32_t oldId, std::uint32_t newId, std::size_t itemCount, std::vector<std::uint32_t> clientHandles,
  const ua::Array<ua::MonitoredItemCreateResult>& itemResults, ua::StatusCode answered)
{
  // Strand only. Every item must have been created; a per-item bad status means the recreated Subscription
  // is incomplete, so fail the whole recovery (re-drive rather than deliver a partial subscription). An item
  // answered Uncertain holds its new id and is restored, its code carried to the recovery's outcome.
  if (itemResults.size() != itemCount)
  {
    recovery_settle_one(barrier, ua::StatusCode{ua::Status::BadUnexpectedError});
    return;
  }
  for (std::size_t index = 0; index < itemResults.size(); ++index)
  {
    if (itemResults[index].status_code().is_bad())
    {
      recovery_settle_one(barrier, itemResults[index].status_code());
      return;
    }
    answered = ua::detail::combined_status(answered, itemResults[index].status_code());
  }
  mMonitoredItemsRecreatedThisAttempt += itemCount;
  // Fully recreated: stage the pipeline re-key (oldId -> newId; commit moves the pipeline state, repoints the
  // retained callbacks by client handle, and resets the tracker to the fresh sequence space). ALSO stage the
  // OWNER re-key for each recreated item (CRITICAL 1): pair the preserved clientHandle (request order - and,
  // under chunking, contiguous across the merged results) with the NEW server monitored-item id, under the
  // NEW subscription id, so a later self-action targets the recreated server item, not the stale ids. Only
  // reached on FULL per-item success (the loop above returned on any per-item bad status).
  if (mObserverSink)
  {
    mObserverSink->fire_subscription_recreated(oldId, newId);
  }
  barrier->stagedRekeys.emplace_back(oldId, newId);
  for (std::size_t index = 0; index < itemResults.size(); ++index)
  {
    barrier->stagedOwnerRekeys.push_back(DataChangeMonitoredItemOwner::ItemRekey{
      clientHandles[index], newId, itemResults[index].monitored_item_id()});
  }
  recovery_settle_one(barrier, answered);
}

void ConnectionImpl::recovery_settle_one(
  const std::shared_ptr<SessionChangedRecovery>& barrier, ua::StatusCode status)
{
  // Strand only. One Subscription reached a terminal. Fold a bad status into the worst outcome (it carries
  // its own ErrorDetail; the design specification) and, when the last sub settles, either COMMIT the staged
  // re-keys (move them where reconnect_commit applies them) and report the answers' code, or apply NOTHING
  // and report the worst status so the FSM backs off and re-drives from the pipeline's pristine ids
  // (stage-and-commit). A status that is not Bad is a restored Subscription: a Good subcode or an Uncertain
  // code the server answered its recreate with is folded into the code the recovery reports
  // (ua::detail::combined_status). An Uncertain answer without a response arrives here already refused.
  if (!status.is_bad())
  {
    const ua::StatusCode before = barrier->answeredStatus;
    barrier->answeredStatus = ua::detail::combined_status(before, status);
    if (ua::detail::has_subcode(before) && ua::detail::has_subcode(status) &&
        ua::detail::severity_rank(before) == ua::detail::severity_rank(status) && before != status)
    {
      mLogger.warning(
        "session-CHANGED recovery: the code 0x{:08x} of an earlier recreate is replaced by "
        "0x{:08x} in the recovery's outcome",
        before.as_uint32(),
        status.as_uint32());
    }
  }
  else
  {
    // Log the failing recreate status at the wire boundary before the barrier subsumes it into worstStatus
    // (the design specification: log at boundaries before the specific status is lost behind aggregation).
    mLogger.warning(
      "session-CHANGED recovery: a Subscription recreate failed (0x{:08x}); the recovery will "
      "report bad so the reconnect backs off and re-drives",
      status.as_uint32());
    barrier->anyFailed = true;
    if (barrier->worstStatus.is_good())
    {
      barrier->worstStatus = status;
    }
  }
  if (barrier->pending == 0 || --barrier->pending != 0)
  {
    return;  // not the last terminal (or an already-settled barrier): nothing more to do yet
  }

  auto done = std::exchange(barrier->done, {});
  if (!done)
  {
    return;  // defensive: fire at most once
  }
  if (barrier->anyFailed)
  {
    // Apply nothing: leave the pipeline's original ids intact so the retry re-drives from pristine records.
    // (Any Subscription this attempt already recreated server-side is orphaned and times out; the bounded
    // rare cost of the no-loss stage-and-commit contract.)
    mStagedRekeys.clear();
    mStagedOwnerRekeys.clear();  // discard the owner re-keys too (CRITICAL 1): apply nothing on any failure.
    done(ua::VoidResult{barrier->worstStatus});
    return;
  }
  // Full success: hand the staged re-keys to reconnect_commit, which applies them atomically before resume.
  mStagedRekeys = std::move(barrier->stagedRekeys);
  mStagedOwnerRekeys = std::move(barrier->stagedOwnerRekeys);  // owner re-keys applied alongside (CRITICAL 1)
  done(ua::VoidResult{barrier->answeredStatus});
}

void ConnectionImpl::reconnect_commit(std::function<void(ua::VoidResult)> done)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(done),
    ua::VoidResult{ua::Status::BadConnectionClosed},
    [](ConnectionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // activate_async already rebound the existing session onto the new channel. If a fresh session was
      // created instead (activate-on-existing failed), install it now. Refresh the published sessionId
      // and clear the pending holders either way.
      const ua::NodeId supersededSessionId = self.mSessionId;
      const bool sessionReplaced = self.mPendingSession != nullptr;
      if (self.mPendingSession)
      {
        self.mSessionGeneration->fetch_add(1, std::memory_order_relaxed);
        self.mOutstandingRequestsByHandle.clear();
        self.mSessionOps = std::move(self.mPendingSession);  // moved-from shared_ptr is left null
      }
      self.mSessionId = self.mSessionOps->session_id();
      // A reconnect that had to create a fresh Session rather than re-activate the old one. Reported at
      // COMMIT, not at creation, so the id pair an application sees is the one the Connection went on to
      // use - a superseded attempt never reaches here.
      if (sessionReplaced && self.mObserverSink)
      {
        self.mObserverSink->fire_session_recreated(supersededSessionId, self.mSessionId);
      }
      self.mPendingChannel.reset();
      // Apply the session-CHANGED recovery's staged re-keys ATOMICALLY (stage-and-commit, #24). Runs only on
      // full recover success (recovery_settle_one filled mStagedRekeys) and BEFORE the pump resumes (commit
      // precedes reach_active -> resume; both the re-key and resume post to the pipeline strand, so the
      // re-key - posted first - lands before the first post-reconnect Publish, so notifications hit the new
      // id/MI mapping rather than an unknown handle). The pipeline applies the whole batch collision-safely
      // and resets every recreated Subscription's tracker to the fresh server sequence space. Empty on the
      // preserved / recreate-only-failure paths, so a no-op there.
      if (self.mPipeline && !self.mStagedRekeys.empty())
      {
        self.mPipeline->apply_recreate_rekeys_async(self.mStagedRekeys);
      }
      // Re-key the PUBLIC handles in the same lock-step. Everything else here re-keys internal
      // routing; this is what keeps a `Subscription` the application held across the outage
      // addressing the live Subscription rather than the id of the one the server discarded.
      for (const auto& rekey : self.mStagedRekeys)
      {
        self.rekey_subscription_id_cells(rekey.first, rekey.second);
      }
      // Re-key the retained tuning in the same lock-step. The recreate rebuilt each Subscription from this
      // record, so it must follow the id forward - otherwise the NEXT modify or the next recreate reads an
      // absent entry and falls back to the SDK defaults, quietly discarding tuning that survived this one.
      for (const auto& rekey : self.mStagedRekeys)
      {
        const auto entry = self.mSubscriptionTuning.find(rekey.first);
        if (entry != self.mSubscriptionTuning.end())
        {
          self.mSubscriptionTuning[rekey.second] = entry->second;
          self.mSubscriptionTuning.erase(entry);
        }
      }
      // Re-key the OWNER routing map in lock-step (CRITICAL 1): the recreated items kept their clientHandles
      // but got NEW {subscriptionId, monitoredItemId} pairs, and the owner map is the SOLE holder of that
      // routing for self-actions. Only the recreate branch stages owner re-keys (a transferred sub keeps its
      // ids, so its items' routing is unchanged and nothing is staged for it). One rekey_items batch call.
      if (self.mMonitoredItemOwner && !self.mStagedOwnerRekeys.empty())
      {
        self.mMonitoredItemOwner->rekey_items(self.mStagedOwnerRekeys);
      }
      // CL-AC-003 / Finding 1: each staged re-key's old id (`.first`) identifies a SPECIFICALLY-recreated
      // Subscription this attempt (a session-CHANGED reconnect recreated it, so its old-session
      // ConditionRefresh windows can never complete). A TRANSFERRED backbone is NOT re-keyed (the server kept
      // it under the same id and Republish drains its old-session windows), so it is absent from this set and
      // its tracker MUST be left untouched  -  resetting it would deliver a false Bad_SessionClosed and
      // re-arm a redundant refresh. Signal the event subscriber to reset ONLY the recreated backbones'
      // trackers and re-arm their first-event  implies  refresh path (the method posts to the subscriber's
      // OWN strand  -  this connection strand never reaches into subscriber state). Empty on the preserved /
      // recreate-only-failure paths (no call). Build the id list BEFORE the clear below.
      std::vector<std::uint32_t> recreatedSubscriptionIds;
      recreatedSubscriptionIds.reserve(self.mStagedRekeys.size());
      for (const auto& rekey : self.mStagedRekeys)
      {
        recreatedSubscriptionIds.push_back(rekey.first);  // old (create-time) subscription id
      }
      if (!recreatedSubscriptionIds.empty())
      {
        if (auto eventSubscriber = self.mEventSubscriber.load())
        {
          // Reconnect trigger: the session was re-established, so the reset delivers Bad_SessionClosed (R4).
          eventSubscriber->on_reconnect_recovered_async(
            std::move(recreatedSubscriptionIds), BackboneRecoveryReason::SessionReestablished);
        }
      }
      self.mStagedRekeys.clear();
      self.mStagedOwnerRekeys.clear();
      completion(ua::VoidResult{});
    })();
}

void ConnectionImpl::publish_info()
{
  const std::size_t namespaceCount = mNamespaceTable ? mNamespaceTable->size() : std::size_t{0};
  const std::optional<std::uint32_t> urisVersion =
    mNamespaceTable ? mNamespaceTable->uris_version() : std::nullopt;
  // Republish the NamespaceTable snapshot alongside the info snapshot (Rule 4) so the cross-strand
  // SupportOps::namespace_table interface reads the current immutable table without touching this strand.
  mNamespaceTableSnapshot.store(mNamespaceTable);
  mServerTableSnapshot.store(mServerTable);
  mInfoSnapshot.store(std::make_shared<const ConnectionInfo>(ConnectionInfo{
    mState, mSessionId, namespaceCount, urisVersion, mOperationLimits, mContinuationPointLimits}));
}

std::shared_ptr<const ConnectionInfo> ConnectionImpl::info() const noexcept
{
  return mInfoSnapshot.load();
}

std::shared_ptr<const NamespaceTable> ConnectionImpl::namespace_table_snapshot() const noexcept
{
  return mNamespaceTableSnapshot.load();
}

std::shared_ptr<const ServerTable> ConnectionImpl::server_table_snapshot() const noexcept
{
  return mServerTableSnapshot.load();
}

std::shared_ptr<const ua::EndpointDescription> ConnectionImpl::active_endpoint_snapshot() const noexcept
{
  return mEndpointSnapshot.load();
}

std::uint32_t ConnectionImpl::max_nodes_per_read() const noexcept
{
  return mMaxNodesPerRead.load();
}

std::shared_ptr<WireOps> ConnectionImpl::wire_ops() const noexcept
{
  // Alias the one ConnectionOpsShim's control block as its WireOps role subobject (the shim derives from
  // ConnectionOps derives from WireOps). The shim weak-refs this orchestrator, so this strong handle forms
  // no cycle; a tier-2 consumer holds it WEAK anyway.
  return std::shared_ptr<WireOps>(mConnectionOps);
}

std::shared_ptr<SupportOps> ConnectionImpl::support_ops() const noexcept
{
  // Alias the one ConnectionOpsShim's control block as its SupportOps role subobject (the shim derives from
  // ConnectionOps derives from SupportOps). The shim weak-refs this orchestrator, so this strong handle forms
  // no cycle; a tier-2 consumer holds it WEAK anyway.
  return std::shared_ptr<SupportOps>(mConnectionOps);
}

boost::asio::any_io_executor ConnectionImpl::executor() const noexcept
{
  return mExecutor;
}

boost::asio::strand<boost::asio::any_io_executor> ConnectionImpl::strand() const noexcept
{
  return mStrand;
}

void ConnectionImpl::subscription_ids_async(std::function<void(std::vector<std::uint32_t>)> callback) noexcept
{
  // No pipeline (should not happen post-construction) => an empty set, delivered on the executor so the
  // callback contract (never fired inline / on a component strand) holds uniformly.
  if (!mPipeline)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{}, [callback = std::move(callback)]() mutable { callback({}); }));
    return;
  }
  auto recoveryExecutor = mExecutor;
  // recovery_descriptors_async hops to the PIPELINE strand and fires there; map to ids and re-post onto the
  // executor before the user callback runs (the design specification - not on a component strand).
  mPipeline->recovery_descriptors_async(
    [executor = std::move(recoveryExecutor), callback = std::move(callback)](
      std::vector<RecoveryDescriptor> descriptors) mutable
    {
      std::vector<std::uint32_t> ids;
      ids.reserve(descriptors.size());
      for (const auto& descriptor : descriptors)
      {
        ids.push_back(descriptor.subscriptionId);
      }
      boost::asio::post(executor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback), ids = std::move(ids)]() mutable { callback(std::move(ids)); }));
    });
}

std::shared_ptr<detail::MonitoredItemOwner> ConnectionImpl::monitored_item_owner() const noexcept
{
  return mMonitoredItemOwner;
}

void ConnectionImpl::create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
  std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept
{
  create_subscription_managed_async(publishingInterval, publishingEnabled, std::nullopt, std::move(callback));
}

void ConnectionImpl::create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
  std::optional<std::uint32_t> maxNotificationsPerPublish,
  std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept
{
  SubscriptionTuning tuning;
  tuning.publishingEnabled = publishingEnabled;
  create_subscription_managed_async(
    publishingInterval, tuning, maxNotificationsPerPublish, std::move(callback));
}

ConnectionImpl::SubscriptionTuning ConnectionImpl::resolve_subscription_tuning(SubscriptionTuning retained,
  const std::optional<std::uint32_t>& lifetimeCount, const std::optional<std::uint32_t>& maxKeepAliveCount,
  const std::optional<std::uint8_t>& priority, const std::optional<std::uint32_t>& maxNotificationsPerPublish)
{
  SubscriptionTuning resolved = retained;
  if (maxNotificationsPerPublish.has_value())
  {
    resolved.maxNotificationsPerPublish = *maxNotificationsPerPublish;
  }
  if (maxKeepAliveCount.has_value())
  {
    resolved.maxKeepAliveCount = *maxKeepAliveCount;
  }
  if (lifetimeCount.has_value())
  {
    resolved.lifetimeCount = *lifetimeCount;
  }
  else if (maxKeepAliveCount.has_value())
  {
    resolved.lifetimeCount =
      std::max(resolved.lifetimeCount, resolved.maxKeepAliveCount * lifetimeToKeepAliveRatio);
  }
  if (priority.has_value())
  {
    resolved.priority = *priority;
  }
  return resolved;
}

void ConnectionImpl::forget_subscription_tuning(std::uint32_t subscriptionId)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [subscriptionId](ConnectionImpl& self) { self.mSubscriptionTuning.erase(subscriptionId); })();
}

void ConnectionImpl::retain_subscription_tuning(std::uint32_t subscriptionId, SubscriptionTuning tuning)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [subscriptionId, tuning](ConnectionImpl& self) { self.mSubscriptionTuning[subscriptionId] = tuning; })();
}

void ConnectionImpl::create_subscription_managed_async(double publishingInterval, SubscriptionTuning tuning,
  std::optional<std::uint32_t> maxNotificationsPerPublish,
  std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<SubscriptionCreated>{ua::Status::BadConnectionClosed},
    [publishingInterval, tuning, maxNotificationsPerPublish](
      ConnectionImpl& self, std::function<void(ua::Result<SubscriptionCreated>)> completion) mutable
    {
      const bool publishingEnabled = tuning.publishingEnabled;
      // Gate like a wire op (a non-Active state fast-fails WITHOUT touching mSessionOps; section 8.2A.3).
      if (self.mState != ConnectionState::Active)
      {
        ua::async::post_owning(&self,
          self.mExecutor,
          self.mLogger,
          [completion = std::move(completion)](ConnectionImpl&) mutable
          { completion(ua::Result<SubscriptionCreated>{ua::Status::BadConnectionClosed}); })();
        return;
      }

      const std::uint32_t requestedMaxNotifications = maxNotificationsPerPublish.value_or(0);
      // The cap is part of the parameter set a later ModifySubscription replaces, so it belongs in the
      // retained record alongside the other four.
      tuning.maxNotificationsPerPublish = requestedMaxNotifications;
      auto request = build_create_subscription_request(publishingInterval, requestedMaxNotifications, tuning);
      auto pipeline = self.mPipeline;
      self.mSessionOps->create_subscription_async(std::move(request),
        [pipeline = std::move(pipeline),
          publishingInterval,
          publishingEnabled,
          tuning,
          requestedMaxNotifications,
          completion = std::move(completion),
          weakSelf = self.weak_from_this(),
          namespaceTable = self.namespace_table_snapshot()](
          ua::Result<ua::CreateSubscriptionResponse> result) mutable
        {
          // CL-SUB-019: a FAILED CreateSubscription either ENGAGES the polled-Read fallback (per the
          // Connection's fallback mode) or forwards the bad status. Engagement assigns a synthetic
          // client-side Subscription id, registers a fallback driver in the pipeline, and returns a GOOD
          // SubscriptionCreated so the user's handle is valid and unaware. This runs on the executor; the
          // engage path hops to the strand for the synthetic-id counter + fallback registry (both
          // strand-only), then delivers the good result back on the executor.
          auto engageOrForward =
            [&](ua::StatusCode failStatus, std::shared_ptr<const ua::ErrorDetail> failDetail) mutable
          {
            const auto lockedSelf = weakSelf.lock();
            if (!lockedSelf || !fallback_should_engage(lockedSelf->mSubscriptionFallbackMode, failStatus))
            {
              completion(ua::Result<SubscriptionCreated>{failStatus, std::move(failDetail)});
              return;
            }
            ua::async::post_borrowing(lockedSelf.get(),
              lockedSelf->mStrand,
              lockedSelf->mLogger,
              std::move(completion),
              ua::Result<SubscriptionCreated>{ua::Status::BadConnectionClosed},
              [publishingInterval, publishingEnabled](ConnectionImpl& fallbackSelf,
                std::function<void(ua::Result<SubscriptionCreated>)>
                  fallbackCompletion) mutable
              {
                const std::uint32_t syntheticId = fallbackSelf.mNextFallbackSubscriptionId++;
                fallbackSelf.mFallbackSubscriptions.emplace(syntheticId, publishingInterval);
                fallbackSelf.mPipeline->engage_fallback_subscription_async(syntheticId,
                  publishingInterval,
                  publishingEnabled,
                  [syntheticId,
                    publishingInterval,
                    publishingEnabled,
                    fallbackCompletion = std::move(fallbackCompletion)](
                    ua::VoidResult registrationResult) mutable
                  {
                    if (registrationResult.is_bad())
                    {
                      fallbackCompletion(ua::Result<SubscriptionCreated>{registrationResult.status_code()});
                      return;
                    }
                    SubscriptionCreated created;
                    created.subscriptionId = syntheticId;
                    created.revisedPublishingInterval =
                      publishingInterval;  // no server revision  -  echo requested
                    created.publishingEnabled = publishingEnabled;
                    fallbackCompletion(ua::Result<SubscriptionCreated>{created});
                  });
              })();
          };

          if (!result.has_value())
          {
            engageOrForward(result.status_code(), result.shared_detail());
            return;
          }
          const auto& response = result.value();
          const auto serviceResult = response.response_header().service_result();
          if (serviceResult.is_bad())
          {
            // CL-DIAG-005: managed path (not through invoke_wire_op) - attach the wire marker.
            // CL-DIAG-007: tag a server NamespaceURI via the snapshot captured at issue time.
            engageOrForward(serviceResult,
              ua::client::detail::attach_wire_marker(response.response_header(), 32, namespaceTable));
            return;
          }
          const std::uint32_t subscriptionId = response.subscription_id();
          // Retain the REQUESTED interval for session-CHANGED recreate (section 6.7, Q5) - matches the
          // pipeline's recreate contract; the handle snapshot below carries the server-revised interval for
          // display.
          pipeline->add_subscription_async(subscriptionId,
            publishingInterval,
            requestedMaxNotifications,
            [pipeline,
              subscriptionId,
              revisedPublishingInterval = response.revised_publishing_interval(),
              publishingEnabled,
              tuning,
              weakSelf,
              serviceResult,
              completion = std::move(completion)](ua::VoidResult registrationResult) mutable
            {
              if (registrationResult.is_bad())
              {
                completion(ua::Result<SubscriptionCreated>{registrationResult.status_code()});
                return;
              }
              // Retain the tuning the server was just given, keyed by the id it assigned. Modify and the
              // session-CHANGED recreate both rebuild the full parameter set from this record.
              if (auto strong = weakSelf.lock())
              {
                strong->retain_subscription_tuning(subscriptionId, tuning);
              }
              pipeline->start_async();
              SubscriptionCreated created;
              created.subscriptionId = subscriptionId;
              created.revisedPublishingInterval = revisedPublishingInterval;
              created.publishingEnabled = publishingEnabled;
              // The Subscription exists: a Good subcode or an Uncertain ServiceResult stays with it.
              completion(ua::detail::held(std::move(created), serviceResult));
            });
        });
    })();
}

void ConnectionImpl::monitor_data_change_async(std::uint32_t subscriptionId,
  ua::client::MonitorRequest request, ua::client::DataChangeCallback onData,
  std::function<void(ua::client::MonitoredItemResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::client::MonitoredItemResult{ua::Status::BadConnectionClosed},
    [subscriptionId, request = std::move(request), onData = std::move(onData)](
      ConnectionImpl& self, std::function<void(ua::client::MonitoredItemResult)> completion) mutable
    {
      // CL-MI-024: reject a structurally-invalid PercentDeadband LOCALLY before any handle allocation or wire
      // request (no wasted round-trip). NOT a DataType pre-flight  -  that is deferred to the server
      // (CL-MI-012).
      if (const auto filterCheck = validate_monitor_data_change_filter(request.filter); filterCheck.is_bad())
      {
        completion(ua::client::MonitoredItemResult{filterCheck.status_code(), filterCheck.shared_detail()});
        return;
      }
      // Allocate the Connection-unique client handle on the strand (CL-MI-003). begin_create_monitored_item
      // re-gates Active and delivers a rejection on the executor, so no inline Active check is needed here.
      const std::uint32_t clientHandle = self.mHandleAllocator.allocate();
      const ua::NodeId node = request.nodeId;
      const ua::AttributeId attribute = request.attribute;
      const ua::MonitoringMode mode = request.monitoringMode.value_or(ua::MonitoringMode::Reporting);
      // Thread the tuning fields onto the wire (mirroring mi_modify_async). queueSize defaults to 1 when the
      // caller leaves it unset. CL-MI-011: the DataChangeFilter / AggregateFilter is threaded through to the
      // CreateMonitoredItems request (a monostate leaves the wire filter null).
      std::optional<std::string> indexRange = request.indexRange;
      const double samplingIntervalMs = request.samplingIntervalMs;
      const std::uint32_t queueSize = request.queueSize.value_or(1);
      const bool discardOldest = request.discardOldest;
      auto filter = std::move(request.filter);

      // Adapt the pipeline's DataValue delivery into the public DataChangeEvent (pre-decoded node/attribute
      // so the user never sees the wire clientHandle). The pipeline hops this onto the executor. CL-MI-030:
      // hold the value in operation-owned storage while the gated-lazy reify consumer resolves any
      // UnknownStructure encodings; the user callback fires only after the one bounded re-decode pass.
      std::weak_ptr<ConnectionImpl> weakConnection = self.weak_from_this();
      auto sharedOnData =
        std::make_shared<std::function<void(ua::client::DataChangeEvent)>>(std::move(onData));
      std::function<void(ua::DataValue)> dataAdapter =
        [weakConnection, clientHandle, node, attribute, sharedOnData](ua::DataValue value) mutable
      {
        auto storage = std::make_shared<ua::DataValue>(std::move(value));
        std::shared_ptr<TypeResolver> resolver;
        std::shared_ptr<ReifySupport> support;
        if (auto connection = weakConnection.lock())
        {
          resolver = connection->type_resolver();
          if (resolver)
          {
            // Always waits: a MonitoredItem callback's contract is a value that has already had its
            // re-decode pass. `tier2WaitForResolution` governs typed reads, not this delivery path.
            support = std::make_shared<ResolverReifySupport>(
              resolver, connection->namespace_table_snapshot(), /*waitForResolution=*/true);
          }
        }

        auto deliver =
          [weakConnection, resolver, storage, clientHandle, node, attribute, sharedOnData]() mutable
        {
          // Any placeholder still present after resolution/re-decode is delivered losslessly AND reported as
          // an advisory. Dedup is owned by the resolver's bounded strand-side gate.
          if (resolver)
          {
            std::unordered_set<ua::NodeId> unresolved;
            collect_unknown_encodings(storage->value(), unresolved);
            for (const auto& encodingId : unresolved)
            {
              resolver->note_unresolved_async(encodingId,
                [weakConnection, encodingId]
                {
                  if (auto connection = weakConnection.lock())
                  {
                    std::unique_ptr<ua::ErrorDetail> detail =
                      ua::ErrorDetail::build("MonitoredItemStructuredValueUnresolved",
                        "a monitored structured value remained opaque after type resolution",
                        "client.tier1.monitor.structured_value_unresolved")
                        .context(ua::ContextKeys::encoding, ua::to_string(encodingId));
                    connection->observer_sink()->fire_advisory_diagnostic(std::move(detail));
                  }
                });
            }
          }

          ua::client::DataChangeEvent event;
          event.itemId = clientHandle;
          event.nodeId = node;
          event.attribute = attribute;
          event.value = std::move(*storage);
          (*sharedOnData)(std::move(event));
        };
        reify_and_deliver({&storage->value()}, std::move(support), ua::EncodingLimits{}, std::move(deliver));
      };

      auto owner = self.mMonitoredItemOwner;
      self.begin_create_monitored_item(
        subscriptionId,
        node,
        clientHandle,
        std::move(dataAdapter),
        [owner = std::move(owner),
          clientHandle,
          subscriptionId,
          node,
          attribute,
          mode,
          discardOldest,
          completion = std::move(completion)](ua::Result<CreatedMonitoredItem> result) mutable
        {
          if (!result.has_value())
          {
            completion(ua::client::MonitoredItemResult{result.status_code(), result.shared_detail()});
            return;
          }
          const CreatedMonitoredItem created = result.value();
          // Build the SHARED mutable state (D5, CL-MI-019/020/021) seeded from the create result, retain it
          // in the owner's routing entry (so the owner  -  the sole updater  -  can refresh it on a later
          // modify / set-mode), and hand the SAME shared_ptr to the handle so every copy observes the current
          // values.
          auto state = std::make_shared<ua::client::detail::MonitoredItemState>();
          state->mode.store(mode);
          state->revisedSamplingIntervalMs.store(created.revisedSamplingIntervalMs);
          state->revisedQueueSize.store(created.revisedQueueSize);
          state->discardOldest.store(discardOldest);
          owner->register_item(clientHandle, subscriptionId, created.monitoredItemId, state);
          // The item exists: a Good subcode or an Uncertain code the server created it with stays with the
          // handle.
          completion(ua::detail::held(
            ua::client::detail::MonitoredItemFactory::create(
              owner, clientHandle, node, attribute, ua::client::MonitoredItemKind::DataChange, state),
            result.status_code()));
        },
        attribute,
        std::move(indexRange),
        samplingIntervalMs,
        queueSize,
        mode,
        discardOldest,
        std::move(filter));
    })();
}

void ConnectionImpl::set_triggering_by_handles_async(std::uint32_t subscriptionId,
  std::uint32_t triggerHandle, std::vector<std::uint32_t> addHandles,
  std::vector<std::uint32_t> removeHandles,
  std::function<void(ua::Result<ua::client::SetTriggeringResult>)> callback) noexcept
{
  // Resolve every clientHandle to its server monitored-item id via the owner routing map (mutex-guarded, so
  // this is safe off-strand), enforcing TWO preconditions per handle before any wire request is built:
  //   1. EXISTENCE  - a handle with no live routing fails locally Bad_MonitoredItemIdInvalid (not live).
  //   2. MEMBERSHIP - a live handle owned by a DIFFERENT Subscription fails locally Bad_InvalidArgument.
  // OPC UA Part 4 section 5.12.5.1 requires every item in a SetTriggering to belong to the SAME Subscription,
  // so a cross-Subscription reference is a LOCAL argument error - never a wire request carrying a mismatched
  // subscription id (which the server would reject Bad_MonitoredItemIdInvalid, CL-MI-027). Existence is
  // checked BEFORE membership so a non-live handle keeps its Bad_MonitoredItemIdInvalid classification.
  auto owner = mMonitoredItemOwner;
  auto failOnExecutor = [this, &callback](ua::Result<ua::client::SetTriggeringResult> failure)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{},
        [callback = std::move(callback), failure = std::move(failure)]() mutable
        { callback(std::move(failure)); }));
  };

  // Resolves a single handle to its server monitored-item id, enforcing existence then same-Subscription
  // membership. Returns nullopt (and posts the classified failure) when either precondition fails.
  auto resolveMember = [owner, subscriptionId, &failOnExecutor](
                         std::uint32_t handle) -> std::optional<std::uint32_t>
  {
    const auto serverItemId = owner->server_item_id(handle);
    if (!serverItemId)
    {
      failOnExecutor(
        ua::Result<ua::client::SetTriggeringResult>{ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid},
          ua::make_error_detail("BadMonitoredItemIdInvalid",
            "SetTriggering referenced a clientHandle with no live monitored item",
            "client.tier1.connection.set_triggering")});
      return std::nullopt;
    }
    if (owner->subscription_of(handle) != subscriptionId)
    {
      failOnExecutor(
        ua::Result<ua::client::SetTriggeringResult>{ua::StatusCode{ua::Status::BadInvalidArgument},
          ua::make_error_detail("BadInvalidArgument",
            "SetTriggering referenced a clientHandle belonging to a different Subscription",
            "client.tier1.connection.set_triggering")});
      return std::nullopt;
    }
    return serverItemId;
  };

  const auto triggerId = resolveMember(triggerHandle);
  if (!triggerId)
  {
    return;
  }

  ua::SetTriggeringRequest request;
  request.subscription_id() = subscriptionId;
  request.triggering_item_id() = *triggerId;
  // Server processes linksToRemove before linksToAdd (CL-MI-028); the wire order below preserves that.
  for (const auto handle : removeHandles)
  {
    const auto id = resolveMember(handle);
    if (!id)
    {
      return;
    }
    request.links_to_remove().push_back(*id);
  }
  for (const auto handle : addHandles)
  {
    const auto id = resolveMember(handle);
    if (!id)
    {
      return;
    }
    request.links_to_add().push_back(*id);
  }

  set_triggering_async(std::move(request),
    [callback = std::move(callback)](ua::Result<ua::SetTriggeringResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<ua::client::SetTriggeringResult>{result.status_code(), result.shared_detail()});
        return;
      }
      const auto& response = result.value();
      const auto serviceResult = response.response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<ua::client::SetTriggeringResult>{serviceResult});
        return;
      }
      // Per-link bads surface WITHOUT aborting the call (CL-MI-029, Part 4 section 5.12.5.2 Table 78): the
      // request was built in handle order, so the wire result arrays are already paired with the caller's
      // input lists.
      ua::client::SetTriggeringResult triggeringResult;
      triggeringResult.addResults = response.add_results().payload();
      triggeringResult.removeResults = response.remove_results().payload();
      // Two layers: the ServiceResult (a Good subcode or an Uncertain code included) is the status of the
      // outer Result, each link keeps its own.
      callback(ua::detail::held(std::move(triggeringResult), serviceResult));
    });
}

void ConnectionImpl::subscription_descriptors_async(
  std::function<void(std::vector<SubscriptionCreated>)> callback) noexcept
{
  if (!mPipeline)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{}, [callback = std::move(callback)]() mutable { callback({}); }));
    return;
  }
  auto recoveryExecutor = mExecutor;
  mPipeline->recovery_descriptors_async(
    [executor = std::move(recoveryExecutor), callback = std::move(callback)](
      std::vector<RecoveryDescriptor> descriptors) mutable
    {
      std::vector<SubscriptionCreated> result;
      result.reserve(descriptors.size());
      for (const auto& descriptor : descriptors)
      {
        SubscriptionCreated created;
        created.subscriptionId = descriptor.subscriptionId;
        created.revisedPublishingInterval = descriptor.publishingInterval;
        // The per-subscription publishing-enabled flag is not carried through the recovery pipeline:
        // RecoveryDescriptor and add_subscription carry only the interval. A subscription whose
        // publishing was disabled before recovery is therefore reported as enabled by
        // Subscriptions::list_async() afterwards.
        created.publishingEnabled = true;
        result.push_back(created);
      }
      boost::asio::post(executor,
        ua::async::guarded(ua::Logger{},
          [callback = std::move(callback), result = std::move(result)]() mutable
          { callback(std::move(result)); }));
    });
}

}  // namespace ua::client::detail
