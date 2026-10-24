// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::ConnectionImpl (section 8.2A / section 8.3) - the tier-1 Connection
// orchestrator, driven in isolation over a fake tier-0 interface (FakeSessionOps / FakeChannelOps /
// FakeReopen). These exercise the orchestrator's OWN logic - wire-op gating, exactly-once completion,
// bootstrap, the reconnect FSM primitives (including the section 3.1 finding-D epoch guard and finding-E
// channel reuse), monitored-item deregistration, and close ordering - without a real server (see
// testable_interfaces.md).
//
// Falsifiability: each test asserts a specific observable behaviour (which fake op was / was not called,
// the exact status delivered, the pending-holder identity, the pipeline monitored-item count), so an
// orchestrator that skipped the gate, double-fired, or mis-routed a reconnect step fails a concrete
// assertion rather than merely "not crashing".

#include "fake_session_ops.h"
#include "test_log_sink.h"

#include "ua_address_space_cache.h"
#include "ua_client_monitored_item.h"
#include "ua_deadband_type.h"
#include "ua_client_subscription.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_data_change_monitored_item_owner.h"
#include "ua_semantic_change_cache.h"

#include "async_test_runtime.h"

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_attribute_id.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_path_result.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_client_diagnostic_policy.h"
#include "ua_client_observers.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_event_filter.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_diagnostic_info.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_history_read_request.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_read_value_id.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_modify_subscription_response.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_logger.h"
#include "ua_data_change_notification.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_response.h"
#include "ua_query_first_request.h"
#include "ua_query_first_response.h"
#include "ua_query_next_request.h"
#include "ua_query_next_response.h"
#include "ua_read_request.h"
#include "ua_ref_structure.h"
#include "ua_republish_response.h"
#include "ua_variant.h"
#include "ua_data_value.h"
#include "ua_server_state.h"
#include "ua_read_response.h"
#include "ua_reconnect_policy.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_response_header.h"
#include "ua_result.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_transfer_result.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::NodeId;
using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::DataChangeEvent;
using ua::client::MonitoredItem;
using ua::client::MonitoredItemResult;
using ua::client::MonitorRequest;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::SubscriptionRecovery;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::DataChangeMonitoredItemOwner;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::ReconnectFsmState;
using ua::client::detail::SessionOps;
using ua::test_helpers::FakeChannelOps;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

/// A near-zero backoff so any incidental FSM timer fires promptly (the suite drives primitives directly).
ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  return policy;
}

/// A keep-alive policy with the timer DISABLED (interval 0): the default for the fixture, so a test that
/// does not exercise keep-alive never arms the poll timer. The keep-alive suite overrides it explicitly.
KeepAlivePolicy keep_alive_disabled()
{
  return KeepAlivePolicy{/*interval=*/0ms, /*missedBeforeReconnect=*/3};
}

/// A keep-alive policy with the timer ENABLED but on a far-future interval, so the real periodic Timer never
/// auto-fires during a (sub-second) unit test - the keep-alive suite drives each poll deterministically via
/// ConnectionImplTestAccess::run_keep_alive_poll instead of racing the clock.
KeepAlivePolicy keep_alive_enabled(std::size_t missedBeforeReconnect)
{
  return KeepAlivePolicy{/*interval=*/std::chrono::hours{1}, missedBeforeReconnect};
}

/// Builds a ServerStatus.State Read response carrying @p state (single Int32 result), so a keep-alive poll
/// classifies it as a shutdown (or a healthy) answer.
ua::ReadResponse make_server_state_response(ua::ServerState state)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{static_cast<std::int32_t>(state)}});
  return response;
}

/// Builds the three-result keep-alive observation response: State, ServiceLevel, optional
/// EstimatedReturnTime.
ua::ReadResponse make_server_hint_response(
  ua::ServerState state, std::uint8_t serviceLevel, std::optional<ua::DateTime> estimatedReturnTime)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{static_cast<std::int32_t>(state)}});
  response.results().push_back(ua::DataValue{ua::Variant{serviceLevel}});
  if (estimatedReturnTime.has_value())
  {
    response.results().push_back(ua::DataValue{ua::Variant{*estimatedReturnTime}});
  }
  return response;
}

ua::DateTime future_datetime(std::chrono::milliseconds ahead)
{
  return ua::DateTime{
    ua::DateTime::now().value() + std::chrono::duration_cast<ua::datetime::OneHundredNanoSeconds>(ahead)};
}

/// Base fixture: a live runner-thread io_context plus builders + blocking bridges for the async surface.
class ConnectionImplTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;

  std::shared_ptr<ConnectionImpl> make_connection(const std::shared_ptr<FakeSessionOps>& session,
    const std::shared_ptr<FakeReopen>& reopen, ConnectionConfig config = {},
    KeepAlivePolicy keepAlive = keep_alive_disabled())
  {
    return TA::create_with_ops(mRuntime.executor(),
      session,
      std::move(config),
      Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      keepAlive);
  }

  /// As @ref make_connection but seeds the stored ActivateConfig with specific credentials, so a reconnect
  /// re-activation can be checked to reuse them (CL-RECONN-002).
  std::shared_ptr<ConnectionImpl> make_connection_with_activate(
    const std::shared_ptr<FakeSessionOps>& session, const std::shared_ptr<FakeReopen>& reopen,
    Session::ActivateConfig activateConfig, ConnectionConfig config = {})
  {
    return TA::create_with_ops(mRuntime.executor(),
      session,
      std::move(config),
      Logger{},
      reopen->as_ops(),
      std::move(activateConfig),
      fast_policy(),
      keep_alive_disabled());
  }

  static VoidResult start_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult reactivate_and_wait(ConnectionImpl& connection, ua::client::UserIdentity identity)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.reactivate_async(
      std::move(identity), [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::ReadResponse> read_and_wait(ConnectionImpl& connection, ua::ReadRequest request = {})
  {
    std::promise<Result<ua::ReadResponse>> promise;
    auto future = promise.get_future();
    connection.read_async(std::move(request),
      [&promise](Result<ua::ReadResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::WriteResponse> write_and_wait(ConnectionImpl& connection, ua::WriteRequest request = {})
  {
    std::promise<Result<ua::WriteResponse>> promise;
    auto future = promise.get_future();
    connection.write_async(std::move(request),
      [&promise](Result<ua::WriteResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::HistoryReadResponse> history_read_and_wait(
    ConnectionImpl& connection, ua::HistoryReadRequest request = {})
  {
    std::promise<Result<ua::HistoryReadResponse>> promise;
    auto future = promise.get_future();
    connection.history_read_async(std::move(request),
      [&promise](Result<ua::HistoryReadResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::BrowseNextResponse> browse_next_and_wait(
    ConnectionImpl& connection, ua::BrowseNextRequest request = {})
  {
    std::promise<Result<ua::BrowseNextResponse>> promise;
    auto future = promise.get_future();
    connection.browse_next_async(std::move(request),
      [&promise](Result<ua::BrowseNextResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::BrowseNextResponse> browse_next_on_session_and_wait(
    ConnectionImpl& connection, std::uint64_t expectedSessionGeneration, ua::BrowseNextRequest request = {})
  {
    std::promise<Result<ua::BrowseNextResponse>> promise;
    auto future = promise.get_future();
    connection.browse_next_on_session_async(expectedSessionGeneration,
      std::move(request),
      [&promise](Result<ua::BrowseNextResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::TranslateBrowsePathsToNodeIdsResponse> translate_browse_paths_and_wait(
    ConnectionImpl& connection, ua::TranslateBrowsePathsToNodeIdsRequest request = {})
  {
    std::promise<Result<ua::TranslateBrowsePathsToNodeIdsResponse>> promise;
    auto future = promise.get_future();
    connection.translate_browse_paths_async(std::move(request),
      [&promise](Result<ua::TranslateBrowsePathsToNodeIdsResponse> result)
      { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::RegisterNodesResponse> register_nodes_and_wait(
    ConnectionImpl& connection, ua::RegisterNodesRequest request = {})
  {
    std::promise<Result<ua::RegisterNodesResponse>> promise;
    auto future = promise.get_future();
    connection.register_nodes_async(std::move(request),
      [&promise](Result<ua::RegisterNodesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::UnregisterNodesResponse> unregister_nodes_and_wait(
    ConnectionImpl& connection, ua::UnregisterNodesRequest request = {})
  {
    std::promise<Result<ua::UnregisterNodesResponse>> promise;
    auto future = promise.get_future();
    connection.unregister_nodes_async(std::move(request),
      [&promise](Result<ua::UnregisterNodesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::AddNodesResponse> add_nodes_and_wait(
    ConnectionImpl& connection, ua::AddNodesRequest request = {})
  {
    std::promise<Result<ua::AddNodesResponse>> promise;
    auto future = promise.get_future();
    connection.add_nodes_async(std::move(request),
      [&promise](Result<ua::AddNodesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::AddReferencesResponse> add_references_and_wait(
    ConnectionImpl& connection, ua::AddReferencesRequest request = {})
  {
    std::promise<Result<ua::AddReferencesResponse>> promise;
    auto future = promise.get_future();
    connection.add_references_async(std::move(request),
      [&promise](Result<ua::AddReferencesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::DeleteNodesResponse> delete_nodes_and_wait(
    ConnectionImpl& connection, ua::DeleteNodesRequest request = {})
  {
    std::promise<Result<ua::DeleteNodesResponse>> promise;
    auto future = promise.get_future();
    connection.delete_nodes_async(std::move(request),
      [&promise](Result<ua::DeleteNodesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::DeleteReferencesResponse> delete_references_and_wait(
    ConnectionImpl& connection, ua::DeleteReferencesRequest request = {})
  {
    std::promise<Result<ua::DeleteReferencesResponse>> promise;
    auto future = promise.get_future();
    connection.delete_references_async(std::move(request),
      [&promise](Result<ua::DeleteReferencesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::HistoryUpdateResponse> history_update_and_wait(
    ConnectionImpl& connection, ua::HistoryUpdateRequest request = {})
  {
    std::promise<Result<ua::HistoryUpdateResponse>> promise;
    auto future = promise.get_future();
    connection.history_update_async(std::move(request),
      [&promise](Result<ua::HistoryUpdateResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::SetMonitoringModeResponse> set_monitoring_mode_and_wait(
    ConnectionImpl& connection, ua::SetMonitoringModeRequest request = {})
  {
    std::promise<Result<ua::SetMonitoringModeResponse>> promise;
    auto future = promise.get_future();
    connection.set_monitoring_mode_async(std::move(request),
      [&promise](Result<ua::SetMonitoringModeResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::CancelResponse> cancel_and_wait(
    ConnectionImpl& connection, ua::CancelRequest request = {})
  {
    std::promise<Result<ua::CancelResponse>> promise;
    auto future = promise.get_future();
    connection.cancel_async(std::move(request),
      [&promise](Result<ua::CancelResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::CallResponse> call_and_wait(ConnectionImpl& connection, ua::CallRequest request = {})
  {
    std::promise<Result<ua::CallResponse>> promise;
    auto future = promise.get_future();
    connection.call_async(std::move(request),
      [&promise](Result<ua::CallResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::BrowseResponse> browse_and_wait(
    ConnectionImpl& connection, ua::BrowseRequest request = {})
  {
    std::promise<Result<ua::BrowseResponse>> promise;
    auto future = promise.get_future();
    connection.browse_async(std::move(request),
      [&promise](Result<ua::BrowseResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::ModifyMonitoredItemsResponse> modify_monitored_items_and_wait(
    ConnectionImpl& connection, ua::ModifyMonitoredItemsRequest request = {})
  {
    std::promise<Result<ua::ModifyMonitoredItemsResponse>> promise;
    auto future = promise.get_future();
    connection.modify_monitored_items_async(std::move(request),
      [&promise](Result<ua::ModifyMonitoredItemsResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::SetTriggeringResponse> set_triggering_and_wait(
    ConnectionImpl& connection, ua::SetTriggeringRequest request = {})
  {
    std::promise<Result<ua::SetTriggeringResponse>> promise;
    auto future = promise.get_future();
    connection.set_triggering_async(std::move(request),
      [&promise](Result<ua::SetTriggeringResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::client::SetTriggeringResult> set_triggering_by_handles_and_wait(
    ConnectionImpl& connection, std::uint32_t subscriptionId, std::uint32_t triggerHandle,
    std::vector<std::uint32_t> addHandles, std::vector<std::uint32_t> removeHandles)
  {
    std::promise<Result<ua::client::SetTriggeringResult>> promise;
    auto future = promise.get_future();
    connection.set_triggering_by_handles_async(subscriptionId,
      triggerHandle,
      std::move(addHandles),
      std::move(removeHandles),
      [&promise](Result<ua::client::SetTriggeringResult> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::QueryFirstResponse> query_first_and_wait(
    ConnectionImpl& connection, ua::QueryFirstRequest request = {})
  {
    std::promise<Result<ua::QueryFirstResponse>> promise;
    auto future = promise.get_future();
    connection.query_first_async(std::move(request),
      [&promise](Result<ua::QueryFirstResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::QueryNextResponse> query_next_and_wait(
    ConnectionImpl& connection, ua::QueryNextRequest request = {})
  {
    std::promise<Result<ua::QueryNextResponse>> promise;
    auto future = promise.get_future();
    connection.query_next_async(std::move(request),
      [&promise](Result<ua::QueryNextResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult close_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<std::uint32_t> create_subscription_and_wait(
    ConnectionImpl& connection, double publishingInterval = 100.0)
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    connection.create_subscription_async(
      publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::client::detail::SubscriptionCreated> create_managed_and_wait(
    ConnectionImpl& connection, double publishingInterval = 100000.0, bool publishingEnabled = true)
  {
    std::promise<Result<ua::client::detail::SubscriptionCreated>> promise;
    auto future = promise.get_future();
    connection.create_subscription_managed_async(publishingInterval,
      publishingEnabled,
      [&promise](Result<ua::client::detail::SubscriptionCreated> result)
      { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<std::uint32_t> create_monitored_item_and_wait(
    ConnectionImpl& connection, std::uint32_t subscriptionId, std::uint32_t clientHandle,
    std::function<void(ua::DataValue)> onData = [](ua::DataValue) {})
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    connection.create_monitored_item_async(subscriptionId,
      NodeId{2, clientHandle},
      clientHandle,
      std::move(onData),
      [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// Drives monitor_data_change_async - the OWNER path: it allocates a Connection-unique clientHandle AND
  /// registers routing (`clientHandle -> {subscriptionId, serverMonitoredItemId}`) in the connection-lifetime
  /// DataChangeMonitoredItemOwner (unlike create_monitored_item_and_wait, which skips the owner). Blocks for
  /// the MonitoredItem result so a test can capture the item + its allocated clientHandle.
  static MonitoredItemResult monitor_data_change_and_wait(
    ConnectionImpl& connection, std::uint32_t subscriptionId, NodeId node,
    ua::client::DataChangeCallback onData = [](DataChangeEvent) {})
  {
    std::promise<MonitoredItemResult> promise;
    auto future = promise.get_future();
    MonitorRequest request;
    request.nodeId = std::move(node);
    connection.monitor_data_change_async(subscriptionId,
      std::move(request),
      std::move(onData),
      [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// The connection's concrete DataChangeMonitoredItemOwner (created once, never reassigned), for asserting
  /// the self-action routing map directly.
  static DataChangeMonitoredItemOwner* data_change_owner(ConnectionImpl& connection)
  {
    return dynamic_cast<DataChangeMonitoredItemOwner*>(connection.monitored_item_owner().get());
  }

  // --- reconnect FSM primitive drivers (block until the step's `done` fires) -----------------------

  static VoidResult run_get_endpoints(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_get_endpoints(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_open(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_open_secure_channel(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_activate(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_activate_session(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_create_session(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_create_session(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_commit(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_commit(connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// Polls until the fake reopen has parked at least @p n completions (bounded).
  static void wait_for_reopen_pending(FakeReopen& reopen, std::size_t n)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (reopen.pending_count() < n && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    ASSERT_GE(reopen.pending_count(), n);
  }

  static FakeChannelOps* as_fake_channel(const std::shared_ptr<ua::client::detail::ChannelOps>& channel)
  {
    return dynamic_cast<FakeChannelOps*>(channel.get());
  }

  // --- wire-op probe (non-blocking submit + exactly-once accounting) --------------------------------

  /// A submitted Read whose owed callback records its invocation count and captures the delivered Result,
  /// so a test can assert the completion fired exactly once (and with what status) without blocking.
  struct ReadProbe
  {
    std::atomic<int> calls{0};
    std::promise<Result<ua::ReadResponse>> promise;
    std::future<Result<ua::ReadResponse>> future{promise.get_future()};
  };

  /// Submits a Read through @p connection and returns a probe recording the owed callback's invocations.
  /// The probe is kept alive by the callback (shared_ptr capture), so it outlives a late/duplicate fire.
  static std::shared_ptr<ReadProbe> submit_read(ConnectionImpl& connection, ua::ReadRequest request = {})
  {
    auto probe = std::make_shared<ReadProbe>();
    connection.read_async(std::move(request),
      [probe](Result<ua::ReadResponse> result)
      {
        if (probe->calls.fetch_add(1) == 0)
        {
          probe->promise.set_value(std::move(result));
        }
      });
    return probe;
  }

  /// Asserts the probe's callback fired exactly once, after letting any duplicate fire settle.
  static void expect_completed_once(const std::shared_ptr<ReadProbe>& probe)
  {
    std::this_thread::sleep_for(30ms);  // give any erroneous second delivery time to land
    EXPECT_EQ(probe->calls.load(), 1) << "the wire-op callback must be invoked exactly once";
  }

  /// Polls @p predicate until true (bounded), for observing an async side effect that has settled.
  template<typename Predicate>
  static void wait_until(Predicate predicate, const char* what)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    ASSERT_TRUE(predicate()) << "timed out waiting for " << what;
  }

  /// The pipeline's current monitored-item count (0 if no pipeline). Drains the pipeline strand FIRST so any
  /// queued optimistic-register / failure-deregister has executed before the snapshot is sampled. Without the
  /// drain the count is racy: `count == 0` holds in TWO windows - BEFORE the optimistic register runs and
  /// AFTER the deregister runs - and the fake session op completes the caller INLINE (unblocking the test
  /// while register+deregister are still queued), so a poll could observe the pre-register `0`, then catch
  /// the just-registered item an instant later. The drain barrier collapses both windows to the settled
  /// value.
  static std::size_t monitored_item_count(ConnectionImpl& connection)
  {
    (void)TA::pipeline_recovery_descriptors(connection);  // pipeline-strand drain barrier
    auto info = TA::pipeline_info(connection);
    return info ? info->monitoredItemCount : 0;
  }

  /// The pipeline's current subscription count (0 if no pipeline). Drains the pipeline strand first for the
  /// same reason as @ref monitored_item_count - the snapshot must be sampled after any queued register /
  /// deregister has settled, not in the transient window before it runs.
  static std::size_t subscription_count(ConnectionImpl& connection)
  {
    (void)TA::pipeline_recovery_descriptors(connection);  // pipeline-strand drain barrier
    auto info = TA::pipeline_info(connection);
    return info ? info->subscriptionCount : 0;
  }

  /// The RETAINED publishing interval for @p subscriptionId that a session-CHANGED recreate would replay
  /// (the pipeline single-owner record), or nullopt if it is no longer registered. The descriptor query is a
  /// pipeline-strand hop, so it also drains any queued update.
  static std::optional<double> retained_interval_for(ConnectionImpl& connection, std::uint32_t subscriptionId)
  {
    for (const auto& descriptor : TA::pipeline_recovery_descriptors(connection))
    {
      if (descriptor.subscriptionId == subscriptionId)
      {
        return descriptor.publishingInterval;
      }
    }
    return std::nullopt;
  }

  static Result<ua::DeleteSubscriptionsResponse> delete_subscription_and_wait(
    ConnectionImpl& connection, std::uint32_t subscriptionId)
  {
    std::promise<Result<ua::DeleteSubscriptionsResponse>> promise;
    auto future = promise.get_future();
    connection.delete_subscription_async(subscriptionId,
      [&promise](Result<ua::DeleteSubscriptionsResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::DeleteMonitoredItemsResponse> delete_monitored_item_and_wait(ConnectionImpl& connection,
    std::uint32_t subscriptionId, std::uint32_t monitoredItemId, std::uint32_t clientHandle)
  {
    std::promise<Result<ua::DeleteMonitoredItemsResponse>> promise;
    auto future = promise.get_future();
    connection.delete_monitored_item_async(subscriptionId,
      monitoredItemId,
      clientHandle,
      [&promise](Result<ua::DeleteMonitoredItemsResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::ModifySubscriptionResponse> modify_subscription_and_wait(
    ConnectionImpl& connection, std::uint32_t subscriptionId, double publishingInterval)
  {
    std::promise<Result<ua::ModifySubscriptionResponse>> promise;
    auto future = promise.get_future();
    connection.modify_subscription_async(subscriptionId,
      publishingInterval,
      [&promise](Result<ua::ModifySubscriptionResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<ua::SetPublishingModeResponse> set_publishing_mode_and_wait(
    ConnectionImpl& connection, std::uint32_t subscriptionId, bool publishingEnabled)
  {
    std::promise<Result<ua::SetPublishingModeResponse>> promise;
    auto future = promise.get_future();
    connection.set_publishing_mode_async(subscriptionId,
      publishingEnabled,
      [&promise](Result<ua::SetPublishingModeResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// Drives a CL-RECONN-003 rebind through the reconnect primitives: open a fresh channel, activate the
  /// EXISTING session on it (fails Bad_SessionIdInvalid -> consumes the channel), create a FRESH session
  /// on a re-opened channel, activate it on its bound channel, and commit-install it. Returns the freshly
  /// installed session interface so a test can assert a queued wire op flushes onto the rebound (new)
  /// session.
  static FakeSessionOps* rebind_to_fresh_session(ConnectionImpl& connection, FakeSessionOps& existing)
  {
    EXPECT_TRUE(run_open(connection).is_good());
    existing.activateOnChannel.set_result(VoidResult{Status::BadSessionIdInvalid});
    EXPECT_TRUE(run_activate(connection).is_bad());
    EXPECT_TRUE(run_create_session(connection).is_good());
    auto* fresh = dynamic_cast<FakeSessionOps*>(TA::snapshot(connection).pendingSession.get());
    EXPECT_NE(fresh, nullptr);
    EXPECT_TRUE(run_activate(connection).is_good());  // activate_on_bound on the fresh session
    EXPECT_TRUE(run_commit(connection).is_good());  // install the fresh session as the live session
    return fresh;
  }

  // --- session-CHANGED subscription recovery (#24) drivers -----------------------------------------

  /// Drives a CL-RECONN-003 rebind up to (but NOT including) the recover step: open a fresh channel,
  /// activate the EXISTING session (fails Bad_SessionIdInvalid), create a FRESH session, activate it on its
  /// bound channel. Leaves the orchestrator with mPendingSession = the fresh interface and
  /// mSessionChangedThisAttempt = true, so a test can script the fresh interface's transfer/create ops and
  /// then drive recover + commit itself. Returns the fresh session interface.
  static FakeSessionOps* drive_to_fresh_session_pre_recover(
    ConnectionImpl& connection, FakeSessionOps& existing)
  {
    EXPECT_TRUE(run_open(connection).is_good());
    existing.activateOnChannel.set_result(VoidResult{Status::BadSessionIdInvalid});
    EXPECT_TRUE(run_activate(connection).is_bad());
    EXPECT_TRUE(run_create_session(connection).is_good());
    auto* fresh = dynamic_cast<FakeSessionOps*>(TA::snapshot(connection).pendingSession.get());
    EXPECT_NE(fresh, nullptr);
    EXPECT_TRUE(run_activate(connection).is_good());  // activate_on_bound on the fresh session
    return fresh;
  }

  /// Drives the recover step with @p recovery and blocks until its `done` fires (all fakes complete inline).
  static VoidResult run_recover(ConnectionImpl& connection, SubscriptionRecovery recovery)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_recover_subscriptions(
      connection, recovery, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// Builds a CreateSubscriptionResponse carrying @p id (the server-assigned Subscription id).
  static ua::CreateSubscriptionResponse make_create_sub_response(std::uint32_t id)
  {
    ua::CreateSubscriptionResponse response;
    response.subscription_id() = id;
    return response;
  }

  /// Builds a CreateMonitoredItemsResponse with one MonitoredItemCreateResult per @p itemStatuses entry.
  static ua::CreateMonitoredItemsResponse make_create_items_response(std::vector<StatusCode> itemStatuses)
  {
    ua::CreateMonitoredItemsResponse response;
    std::uint32_t nextId = 1;
    for (auto status : itemStatuses)
    {
      ua::MonitoredItemCreateResult item;
      item.status_code() = status;
      item.monitored_item_id() = nextId++;
      response.results().push_back(std::move(item));
    }
    return response;
  }

  /// Builds a CreateMonitoredItemsResponse with a single Good item carrying the given server @p
  /// monitoredItemId (so a session-CHANGED recreate can hand back a specific new server id to assert the
  /// owner re-key).
  static ua::CreateMonitoredItemsResponse make_one_item_response(std::uint32_t monitoredItemId)
  {
    ua::CreateMonitoredItemsResponse response;
    ua::MonitoredItemCreateResult item;
    item.status_code() = StatusCode{Status::Good};
    item.monitored_item_id() = monitoredItemId;
    response.results().push_back(std::move(item));
    return response;
  }

  /// Builds a TransferSubscriptionsResponse with one TransferResult per @p statuses entry (in order).
  static ua::TransferSubscriptionsResponse make_transfer_response(std::vector<StatusCode> statuses)
  {
    ua::TransferSubscriptionsResponse response;
    for (auto status : statuses)
    {
      ua::TransferResult result;
      result.status_code() = status;
      response.results().push_back(std::move(result));
    }
    return response;
  }

  /// Registers one Subscription (@p subId) with one monitored item (@p clientHandle, node {2, clientHandle})
  /// in @p connection's pipeline, scripting @p session's createSubscription to yield @p subId first.
  static void seed_subscription_with_item(ConnectionImpl& connection, FakeSessionOps& session,
    std::uint32_t subId, std::uint32_t clientHandle, double publishingInterval = 100.0)
  {
    session.createSubscription.set_result(
      Result<ua::CreateSubscriptionResponse>{make_create_sub_response(subId)});
    ASSERT_TRUE(create_subscription_and_wait(connection, publishingInterval).is_good());
    ASSERT_TRUE(create_monitored_item_and_wait(connection, subId, clientHandle).is_good());
  }
};

// ============================================================================================
// section 3.1 finding D - a late open-channel completion from a SUPERSEDED reconnect attempt must not
// clobber the next attempt's pending channel (epoch guard).
// ============================================================================================
TEST_F(ConnectionImplTest, ReconnectOpenChannelLateCompletionDoesNotClobberNextAttempt)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park every open-channel completion so we can interleave two attempts
  auto connection = make_connection(session, reopen);

  // Attempt 1's open-channel step: parks yield #1 (issued under epoch 1).
  std::promise<VoidResult> done1;
  auto done1Future = done1.get_future();
  TA::reconnect_open_secure_channel(
    *connection, [&done1](VoidResult result) { done1.set_value(std::move(result)); });
  wait_for_reopen_pending(*reopen, 1);

  // Attempt 2's open-channel step supersedes attempt 1 (epoch bumped to 2, pending reset): parks yield #2.
  std::promise<VoidResult> done2;
  auto done2Future = done2.get_future();
  TA::reconnect_open_secure_channel(
    *connection, [&done2](VoidResult result) { done2.set_value(std::move(result)); });
  wait_for_reopen_pending(*reopen, 2);

  // The SUPERSEDED attempt-1 completion arrives late with channel #111. It must NOT be installed as the
  // pending channel (the epoch guard rejects it) and its step must settle Bad.
  reopen->fire_next_channel(/*id=*/111);
  EXPECT_TRUE(done1Future.get().is_bad())
    << "a superseded open-channel step must settle Bad, not resurrect the attempt";
  {
    auto snapshot = TA::snapshot(*connection);
    auto* pending = as_fake_channel(snapshot.pendingChannel);
    EXPECT_TRUE(pending == nullptr || pending->id() != 111)
      << "a late open completion from a superseded attempt clobbered the next attempt's pending channel";
  }

  // The current attempt-2 completion arrives with channel #222 and IS installed.
  reopen->fire_next_channel(/*id=*/222);
  EXPECT_TRUE(done2Future.get().is_good()) << "the current attempt's open-channel step must succeed";
  {
    auto snapshot = TA::snapshot(*connection);
    auto* pending = as_fake_channel(snapshot.pendingChannel);
    ASSERT_NE(pending, nullptr);
    EXPECT_EQ(pending->id(), 222) << "the current attempt's channel must be the installed pending channel";
  }
}

// ============================================================================================
// section 3.1 finding E - on the CertRotated recovery route the open-channel step leaves an OPEN pending
// channel; create_session must REUSE it, not re-open a second channel.
// ============================================================================================
TEST_F(ConnectionImplTest, ReconnectCreateSessionReusesOpenChannelOnCertRotatedRoute)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();  // inline completion (not held)
  auto connection = make_connection(session, reopen);

  // Open a channel (leaves an OPEN pending channel); one reopen so far.
  ASSERT_TRUE(run_open(*connection).is_good());
  ASSERT_EQ(reopen->call_count(), 1u);
  FakeChannelOps* openChannel = nullptr;
  {
    auto snapshot = TA::snapshot(*connection);
    openChannel = as_fake_channel(snapshot.pendingChannel);
    ASSERT_NE(openChannel, nullptr);
    ASSERT_TRUE(openChannel->is_open());
  }

  // CertRotated route: create_session runs with the channel still open -> reuse it, NO extra reopen.
  const auto reopensBefore = reopen->call_count();
  ASSERT_TRUE(run_create_session(*connection).is_good());
  EXPECT_EQ(reopen->call_count() - reopensBefore, 0u)
    << "create_session must reuse the already-open pending channel on the CertRotated route (no re-open)";
  EXPECT_EQ(openChannel->create_session_call_count(), 1u)
    << "the session must be created ON the reused open channel";
  {
    auto snapshot = TA::snapshot(*connection);
    EXPECT_NE(snapshot.pendingSession, nullptr) << "a fresh session must be staged on the reused channel";
  }
}

// CL-ECC-003 / AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY: a reconnect that creates a new
// Session (the CL-RECONN-003 and CertRotated routes) asks the key agreement the connect planned - the
// ECDHPolicyUri, and no EphemeralKey at all when the connect asked none - rather than a default
// CreateSessionConfig, which asks with the channel's policy and would fault again at a Server that faulted
// the connect's request (interoperability finding 021). Falsifiable: the former reconnect passed a default
// config.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST_F(ConnectionImplTest, ReconnectCreateSessionAsksTheKeyAgreementTheConnectPlanned)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.ecdhPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_AesGcm";
  config.requestEphemeralKey = false;
  auto connection = make_connection(session, reopen, config);

  ASSERT_TRUE(run_open(*connection).is_good());
  FakeChannelOps* channel = as_fake_channel(TA::snapshot(*connection).pendingChannel);
  ASSERT_NE(channel, nullptr);
  ASSERT_TRUE(run_create_session(*connection).is_good());
  const auto created = channel->last_create_config();
  ASSERT_TRUE(created.has_value()) << "the reconnect created no Session";
  EXPECT_FALSE(created->requestEphemeralKey)
    << "the reconnect asked for an EphemeralKey the connect did not ask for";
  EXPECT_EQ(created->ecdhPolicyUri, config.ecdhPolicyUri) << "the reconnect lost the planned ECDHPolicyUri";
}

// @verifies CL-RECONN-006
// The complete production route from an own-certificate update (not a direct FSM test hook) must open a
// channel, create a fresh Session, and attempt TransferSubscriptions for the retained subscription.
// @relation(CL-RECONN-006, scope=function)
// @relation(AC-CL-RECONN-006-01, scope=function)
TEST_F(ConnectionImplTest, OwnCertificateUpdateCreatesSessionAndAttemptsSubscriptionTransfer)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  std::atomic<std::shared_ptr<FakeChannelOps>> reopenedChannel;
  reopen->set_channel_configurator(
    [&reopenedChannel](const std::shared_ptr<FakeChannelOps>& channel) { reopenedChannel.store(channel); });
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  std::promise<VoidResult> acknowledged;
  auto acknowledgedFuture = acknowledged.get_future();
  connection->revalidate_server_cert_async(
    true, true, [&acknowledged](VoidResult result) { acknowledged.set_value(std::move(result)); });
  ASSERT_EQ(acknowledgedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(acknowledgedFuture.get().is_good());

  wait_until(
    [&]
    {
      const auto channel = reopenedChannel.load();
      if (!channel)
        return false;
      const auto freshSession = channel->last_created_session();
      return freshSession && freshSession->transferSubscriptions.call_count() == 1U;
    },
    "own-cert reconnect TransferSubscriptions");

  const auto channel = reopenedChannel.load();
  ASSERT_NE(channel, nullptr);
  EXPECT_EQ(channel->create_session_call_count(), 1U)
    << "own-certificate rotation must create a fresh Session, not activate the old one";
  const auto freshSession = channel->last_created_session();
  ASSERT_NE(freshSession, nullptr);
  ASSERT_EQ(freshSession->transferSubscriptions.call_count(), 1U);
  const auto transferRequests = freshSession->transferSubscriptions.requests();
  ASSERT_EQ(transferRequests.size(), 1U);
  ASSERT_EQ(transferRequests[0].subscription_ids().size(), 1U);
  EXPECT_EQ(transferRequests[0].subscription_ids()[0], 77U);

  close_and_wait(*connection);
}

// ============================================================================================
// CL-RECONN-005 - GetEndpoints on the security-failure recovery path.
//
// Part 4 section 5.4.4 / section 6.7: on a security-class reconnect the Client re-fetches the server's
// endpoints (GetEndpoints) to pick up fresh security information (a rotated server certificate / changed
// policy) before retrying the channel open. reconnect_get_endpoints opens a throwaway discovery channel via
// the reopen interface, issues a REAL GetEndpoints on it, and refreshes the published endpoint snapshot from
// the matching endpoint. These pin that the step issues the service (not the old no-op stub) and consumes the
// response. The FSM SEQUENCING that reaches this step is covered by the reconnection_fsm suite; here we
// exercise the ConnectionImpl host primitive's own logic directly.
// ============================================================================================

namespace
{
/// Builds an EndpointDescription with a distinctive URL / policy / mode / server certificate for the
/// GetEndpoints refresh tests.
ua::EndpointDescription make_endpoint(std::string_view url, ua::MessageSecurityMode mode,
  const ua::ByteString& serverCertificate,
  std::string_view policyUri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
{
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = ua::String{url};
  endpoint.security_policy_uri() = ua::String{policyUri};
  endpoint.security_mode() = mode;
  endpoint.server_certificate() = serverCertificate;
  return endpoint;
}
}  // namespace

// A security-failure reconnect issues a REAL GetEndpoints on a discovery channel (built from the bound
// endpoint URL) and refreshes the published endpoint snapshot with the server certificate the response
// carries. Falsifiable: the old no-op stub issued no GetEndpoints (call_count 0) and never touched the
// snapshot (old certificate would survive), failing both assertions.
// @verifies CL-RECONN-005
// @verifies CL-RECONN-008
// @relation(CL-RECONN-005, CL-RECONN-008, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsIssuesGetEndpointsAndRefreshesServerCertificate)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();  // inline reopen: yields the discovery channel synchronously
  auto connection = make_connection(session, reopen);

  const ua::ByteString oldCertificate{0x01, 0x01, 0x01};
  const ua::ByteString newCertificate{0x09, 0x09, 0x09};
  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, oldCertificate));

  // Script the discovery channel's GetEndpoints to return the SAME endpoint with a NEW server certificate.
  // Retain the channel shared_ptr: the orchestrator releases the throwaway discovery channel the moment its
  // callback completes, so a bare pointer would dangle before the post-hoc inspection below.
  std::shared_ptr<FakeChannelOps> discoveryChannel;
  reopen->set_channel_configurator(
    [&discoveryChannel, &newCertificate](const std::shared_ptr<FakeChannelOps>& channel)
    {
      discoveryChannel = channel;
      ua::GetEndpointsResponse response;
      response.endpoints().push_back(
        make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, newCertificate));
      channel->getEndpoints.set_result(ua::Result<ua::GetEndpointsResponse>{std::move(response)});
    });

  EXPECT_TRUE(run_get_endpoints(*connection).is_good())
    << "a successful GetEndpoints refresh must settle the step Good";

  ASSERT_NE(discoveryChannel, nullptr);
  EXPECT_EQ(discoveryChannel->getEndpoints.call_count(), 1u)
    << "the step must issue a REAL GetEndpoints on the discovery channel (not the old no-op stub)";
  const auto requests = discoveryChannel->getEndpoints.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(std::string_view{requests.front().endpoint_url()}, "opc.tcp://server:4840")
    << "GetEndpoints must target the bound endpoint URL";

  const auto snapshot = connection->active_endpoint_snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->server_certificate(), newCertificate)
    << "the endpoint snapshot must refresh to the server certificate GetEndpoints returned";
}

// When the GetEndpoints response carries no endpoint for the bound URL, the snapshot is NOT clobbered
// (a partial / unrelated discovery response must never erase the bound server identity). Falsifiable: an
// unconditional overwrite would replace the bound endpoint with the mismatched one (or clear it).
// @verifies CL-RECONN-005
// @relation(CL-RECONN-005, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsKeepsSnapshotWhenNoEndpointMatchesBoundUrl)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  const ua::ByteString boundCertificate{0x01, 0x02, 0x03};
  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, boundCertificate));

  // Response advertises a DIFFERENT server's endpoint - nothing matches the bound URL.
  reopen->set_channel_configurator(
    [](const std::shared_ptr<FakeChannelOps>& channel)
    {
      ua::GetEndpointsResponse response;
      response.endpoints().push_back(make_endpoint(
        "opc.tcp://other-server:4840", ua::MessageSecurityMode::SignAndEncrypt, ua::ByteString{0xAA, 0xBB}));
      channel->getEndpoints.set_result(ua::Result<ua::GetEndpointsResponse>{std::move(response)});
    });

  EXPECT_TRUE(run_get_endpoints(*connection).is_good());

  const auto snapshot = connection->active_endpoint_snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(std::string_view{snapshot->endpoint_url()}, "opc.tcp://server:4840")
    << "an unmatched discovery response must not overwrite the bound endpoint";
  EXPECT_EQ(snapshot->server_certificate(), boundCertificate)
    << "an unmatched discovery response must not overwrite the bound server certificate";
}

// A GetEndpoints service FAILURE surfaces its status through the step (the FSM backs off) and does not
// touch the snapshot. Falsifiable: swallowing the error and settling Good would fail the is_bad assertion.
// @verifies CL-RECONN-005
// @relation(CL-RECONN-005, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsPropagatesServiceFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  const ua::ByteString boundCertificate{0x07, 0x07};
  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, boundCertificate));

  reopen->set_channel_configurator(
    [](const std::shared_ptr<FakeChannelOps>& channel) {
      channel->getEndpoints.set_result(ua::Result<ua::GetEndpointsResponse>{Status::BadSecurityChecksFailed});
    });

  const auto result = run_get_endpoints(*connection);
  EXPECT_TRUE(result.is_bad()) << "a failed GetEndpoints must surface a Bad status, not a synthetic Good";
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);

  const auto snapshot = connection->active_endpoint_snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->server_certificate(), boundCertificate)
    << "a failed GetEndpoints must not mutate the endpoint snapshot";
}

// When the discovery channel cannot even be opened, the step surfaces the reopen failure WITHOUT issuing a
// GetEndpoints. Falsifiable: issuing GetEndpoints against a null channel would crash / never park.
// @verifies CL-RECONN-005
// @relation(CL-RECONN-005, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsPropagatesReopenFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the reopen so we can fail it explicitly
  auto connection = make_connection(session, reopen);

  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, ua::ByteString{0x01}));

  std::promise<VoidResult> done;
  auto doneFuture = done.get_future();
  TA::reconnect_get_endpoints(*connection, [&done](VoidResult result) { done.set_value(std::move(result)); });
  wait_for_reopen_pending(*reopen, 1);

  reopen->fire_next_failure(Status::BadCertificateInvalid);
  const auto result = doneFuture.get();
  EXPECT_TRUE(result.is_bad()) << "a reopen failure must surface through the GetEndpoints step";
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateInvalid);
}

// section 3.1 (correctness + lifetime lenses, unanimous): a late-but-good GetEndpoints completion from a
// SUPERSEDED attempt must NOT regress the published endpoint snapshot after a newer attempt already refreshed
// it and reached a healthy state. reconnect_get_endpoints bumps a dedicated mReconnectGetEndpointsEpoch per
// call and drops the snapshot-refresh side effect when a newer GetEndpoints has superseded it. Falsifiable:
// without the epoch guard the stale late completion overwrites the fresh certificate - the assertion that the
// snapshot still holds the fresh cert fails. This mirrors the sibling reconnect primitives' epoch guard.
// @verifies CL-RECONN-005
// @relation(CL-RECONN-005, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsLateCompletionDoesNotRegressSnapshot)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park each reopen so we can interleave two attempts' discovery opens
  auto connection = make_connection(session, reopen);

  const ua::ByteString staleCertificate{0x01, 0x01};
  const ua::ByteString freshCertificate{0x02, 0x02};
  const ua::ByteString regressCertificate{0x03, 0x03};  // what the late (superseded) completion would store
  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, staleCertificate));

  // Each discovery channel parks its GetEndpoints (hold) so the test can drive completions out of order, and
  // is captured (shared_ptr retained) so it survives the orchestrator releasing the throwaway channel.
  std::vector<std::shared_ptr<FakeChannelOps>> channels;
  reopen->set_channel_configurator(
    [&channels](const std::shared_ptr<FakeChannelOps>& channel)
    {
      channel->getEndpoints.set_hold(true);
      channels.push_back(channel);
    });

  auto responseWith = [](const ua::ByteString& certificate)
  {
    ua::GetEndpointsResponse response;
    response.endpoints().push_back(
      make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, certificate));
    return ua::Result<ua::GetEndpointsResponse>{std::move(response)};
  };

  // Attempt A (GetEndpoints epoch 1): open its discovery channel and ISSUE its GetEndpoints (parked) BEFORE
  // attempt B exists, so A's completion later arrives under a superseded epoch.
  std::promise<VoidResult> doneA;
  auto doneAFuture = doneA.get_future();
  TA::reconnect_get_endpoints(*connection, [&doneA](VoidResult r) { doneA.set_value(std::move(r)); });
  wait_for_reopen_pending(*reopen, 1);
  reopen->fire_next_channel(/*id=*/1);
  TA::snapshot(*connection);  // barrier: A's reopen callback issued its (held) GetEndpoints
  ASSERT_EQ(channels.size(), 1u);

  // Attempt B (GetEndpoints epoch 2) supersedes A, opens its own discovery channel and issues GetEndpoints.
  std::promise<VoidResult> doneB;
  auto doneBFuture = doneB.get_future();
  TA::reconnect_get_endpoints(*connection, [&doneB](VoidResult r) { doneB.set_value(std::move(r)); });
  wait_for_reopen_pending(*reopen, 1);
  reopen->fire_next_channel(/*id=*/2);
  TA::snapshot(*connection);
  ASSERT_EQ(channels.size(), 2u);

  // B completes first with the FRESH certificate -> snapshot refreshes to fresh.
  channels[1]->getEndpoints.fire_next(responseWith(freshCertificate));
  EXPECT_TRUE(doneBFuture.get().is_good());
  {
    auto snapshot = connection->active_endpoint_snapshot();
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->server_certificate(), freshCertificate)
      << "the current attempt must refresh the snapshot";
  }

  // A's LATE completion arrives with a would-be-regressing certificate. The epoch guard must drop its side
  // effect: the snapshot stays FRESH and A's step settles Bad (superseded).
  channels[0]->getEndpoints.fire_next(responseWith(regressCertificate));
  EXPECT_TRUE(doneAFuture.get().is_bad()) << "a superseded GetEndpoints step must settle Bad";
  {
    auto snapshot = connection->active_endpoint_snapshot();
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->server_certificate(), freshCertificate)
      << "a late GetEndpoints from a superseded attempt must NOT regress the published endpoint snapshot";
  }
}

// ============================================================================================
// A reconnect step does not act on a server's Uncertain answer: an Uncertain OpenSecureChannel,
// CreateSession or GetEndpoints answer settles the step with Bad_InternalError (ServiceAnswerUncertain,
// whose inner status is the Uncertain code), and nothing the answer carried is installed.
// ============================================================================================

namespace
{
/// A reopen that answers the n-th open with a fresh channel held under the n-th scripted status (Good once
/// the script runs out). `makeChannel` builds each channel; every channel is kept for inspection.
class ScriptedStatusReopen
{
public:
  explicit ScriptedStatusReopen(std::vector<StatusCode> statuses) : mStatuses(std::move(statuses))
  {}

  std::function<std::shared_ptr<FakeChannelOps>(int)> makeChannel = [](int id)
  {
    return std::make_shared<FakeChannelOps>(id);
  };

  ua::client::detail::ReopenChannelOps as_ops()
  {
    return [this](std::function<void(Result<std::shared_ptr<ua::client::detail::ChannelOps>>)> yield)
    {
      StatusCode status{Status::Good};
      std::shared_ptr<FakeChannelOps> channel;
      {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mChannels.size() < mStatuses.size())
        {
          status = mStatuses[mChannels.size()];
        }
        channel = makeChannel(static_cast<int>(mChannels.size()) + 1);
        mChannels.push_back(channel);
      }
      yield(Result<std::shared_ptr<ua::client::detail::ChannelOps>>{
        std::static_pointer_cast<ua::client::detail::ChannelOps>(channel), status});
    };
  }

  std::size_t call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mChannels.size();
  }

  std::shared_ptr<FakeChannelOps> channel(std::size_t index) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return index < mChannels.size() ? mChannels[index] : nullptr;
  }

private:
  mutable std::mutex mMutex;
  std::vector<StatusCode> mStatuses;
  std::vector<std::shared_ptr<FakeChannelOps>> mChannels;
};

/// A channel whose CreateSession answers Uncertain_InitialValue holding @ref session.
class UncertainCreateSessionChannel : public FakeChannelOps
{
public:
  using FakeChannelOps::FakeChannelOps;

  std::shared_ptr<FakeSessionOps> session = std::make_shared<FakeSessionOps>();

  void create_session_async(ua::client::SecureChannel::CreateSessionConfig /*config*/,
    std::function<void(Result<std::shared_ptr<SessionOps>>)> callback) override
  {
    callback(Result<std::shared_ptr<SessionOps>>{
      std::static_pointer_cast<SessionOps>(session), StatusCode{Status::UncertainInitialValue}});
  }
};

/// Checks that @p result is the refusal of the server's Uncertain @p answer: Bad_InternalError whose
/// ErrorDetail chain holds ServiceAnswerUncertain, with its summary and @p answer as its inner status.
void expect_uncertain_answer_refused(const VoidResult& result, Status answer)
{
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  const ua::ErrorDetail* refusal = result.error_detail();
  while (refusal != nullptr && refusal->code != "ServiceAnswerUncertain")
  {
    refusal = refusal->cause.get();
  }
  ASSERT_NE(refusal, nullptr) << "the refusal must name the Uncertain answer";
  EXPECT_EQ(refusal->summary, "The SDK does not act on an answer the server is uncertain of");
  EXPECT_EQ(refusal->innerStatus, StatusCode{answer}.value());
}
}  // namespace

// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, ReconnectOpenRefusesAnUncertainChannelAndInstallsNone)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen =
    std::make_shared<ScriptedStatusReopen>(std::vector<StatusCode>{Status::UncertainInitialValue});
  auto connection = TA::create_with_ops(mRuntime.executor(),
    session,
    ConnectionConfig{},
    Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    keep_alive_disabled());

  expect_uncertain_answer_refused(run_open(*connection), Status::UncertainInitialValue);
  EXPECT_EQ(TA::snapshot(*connection).pendingChannel, nullptr)
    << "a channel opened by an Uncertain answer must not become the pending channel";
}

// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsRefusesAnUncertainDiscoveryChannel)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen =
    std::make_shared<ScriptedStatusReopen>(std::vector<StatusCode>{Status::UncertainInitialValue});
  auto connection = TA::create_with_ops(mRuntime.executor(),
    session,
    ConnectionConfig{},
    Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    keep_alive_disabled());
  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, ua::ByteString{0x01}));

  expect_uncertain_answer_refused(run_get_endpoints(*connection), Status::UncertainInitialValue);
  ASSERT_NE(reopen->channel(0), nullptr);
  EXPECT_EQ(reopen->channel(0)->getEndpoints.call_count(), 0u)
    << "GetEndpoints must not be sent on a channel opened by an Uncertain answer";
}

// The endpoint snapshot (the server certificate the next open validates against) is not refreshed from a
// GetEndpoints response whose ServiceResult is Uncertain.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, ReconnectGetEndpointsRefusesAnUncertainServiceResult)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  const ua::ByteString boundCertificate{0x01, 0x01};
  const ua::ByteString answeredCertificate{0x09, 0x09};
  TA::set_endpoint_snapshot(*connection,
    make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, boundCertificate));
  reopen->set_channel_configurator(
    [&answeredCertificate](const std::shared_ptr<FakeChannelOps>& channel)
    {
      ua::GetEndpointsResponse response;
      response.response_header().service_result() = StatusCode{Status::UncertainNotAllNodesAvailable};
      response.endpoints().push_back(
        make_endpoint("opc.tcp://server:4840", ua::MessageSecurityMode::SignAndEncrypt, answeredCertificate));
      channel->getEndpoints.set_result(Result<ua::GetEndpointsResponse>{std::move(response)});
    });

  expect_uncertain_answer_refused(run_get_endpoints(*connection), Status::UncertainNotAllNodesAvailable);
  const auto snapshot = connection->active_endpoint_snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->server_certificate(), boundCertificate)
    << "an Uncertain GetEndpoints answer must not replace the bound server certificate";
}

// On the CL-RECONN-003 route the channel create_session re-opens is refused when its open is Uncertain.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, ReconnectCreateSessionRefusesAnUncertainReopenedChannel)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<ScriptedStatusReopen>(
    std::vector<StatusCode>{Status::Good, Status::UncertainInitialValue});
  auto connection = TA::create_with_ops(mRuntime.executor(),
    session,
    ConnectionConfig{},
    Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    keep_alive_disabled());
  ASSERT_TRUE(run_open(*connection).is_good());
  session->activateOnChannel.set_result(VoidResult{Status::BadSessionIdInvalid});
  ASSERT_TRUE(run_activate(*connection).is_bad());  // consumes the pending channel

  expect_uncertain_answer_refused(run_create_session(*connection), Status::UncertainInitialValue);
  EXPECT_EQ(reopen->call_count(), 2u) << "create_session must have re-opened the consumed channel";
  ASSERT_NE(reopen->channel(1), nullptr);
  EXPECT_EQ(reopen->channel(1)->create_session_call_count(), 0u)
    << "CreateSession must not be sent on a channel opened by an Uncertain answer";
  EXPECT_EQ(TA::snapshot(*connection).pendingSession, nullptr);
}

// An Uncertain CreateSession answer holding a Session is refused; that Session is closed and not staged.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, ReconnectCreateSessionRefusesAnUncertainSessionAndClosesIt)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<ScriptedStatusReopen>(std::vector<StatusCode>{});
  std::shared_ptr<UncertainCreateSessionChannel> channel;
  reopen->makeChannel = [&channel](int id)
  {
    channel = std::make_shared<UncertainCreateSessionChannel>(id);
    return std::static_pointer_cast<FakeChannelOps>(channel);
  };
  auto connection = TA::create_with_ops(mRuntime.executor(),
    session,
    ConnectionConfig{},
    Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    keep_alive_disabled());
  ASSERT_TRUE(run_open(*connection).is_good());  // the pending channel stays open: create_session reuses it
  ASSERT_NE(channel, nullptr);

  expect_uncertain_answer_refused(run_create_session(*connection), Status::UncertainInitialValue);
  EXPECT_EQ(TA::snapshot(*connection).pendingSession, nullptr)
    << "a Session created by an Uncertain answer must not be staged";
  wait_until([&channel] { return channel->session->close.call_count() == 1u; },
    "the Session created by the Uncertain answer is closed");
  EXPECT_EQ(channel->session->close.call_count(), 1u);
}

// @verifies CL-RECONN-002
// Part 4 6.7 lines 7542-7543: on reconnect "the Client shall use the same security policy, application
// instance certificate and the same user credential." ConnectionImpl stores the original ActivateConfig
// (mActivateConfig) and reconnect_activate_session re-activates the surviving session with THAT config on
// the freshly-opened channel. Seed a distinctive policy id + UsernamePassword credential, drive a
// happy-path reconnect (open channel -> re-activate existing session), and assert the credentials handed to
// the activate interface are the ORIGINAL ones - not a reset/default (anonymous, empty policy) config.
// Falsifiable: a reconnect that dropped or re-defaulted the credentials would surface an empty policy id and
// an AnonymousIdentity, failing every assertion below.
// Scope note: this covers the session-activate half (user-token policy + user credential carried in the
// ActivateConfig). The application-instance-certificate half is reused at the SecureChannel level (the
// reopen ops re-open with the original channel/cert configuration), a separate interface.
// @relation(CL-RECONN-002, scope=function)
TEST_F(ConnectionImplTest, ReconnectActivateReusesOriginalCredentials)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  Session::ActivateConfig activateConfig;
  activateConfig.policyId = "reconnect-user-policy";
  activateConfig.identity = ua::client::UsernamePasswordIdentity{"reconnect-user", "reconnect-secret"};
  auto connection = make_connection_with_activate(session, reopen, activateConfig);

  // Happy-path reconnect: open a fresh channel, then rebind+re-activate the EXISTING session onto it.
  ASSERT_TRUE(run_open(*connection).is_good());
  ASSERT_TRUE(run_activate(*connection).is_good());

  auto captured = session->captured_activate_config();
  EXPECT_EQ(captured.policyId, "reconnect-user-policy")
    << "reconnect must re-activate with the original user-token policy id (CL-RECONN-002)";
  const auto* creds = std::get_if<ua::client::UsernamePasswordIdentity>(&captured.identity);
  ASSERT_NE(creds, nullptr) << "reconnect must reuse the original UsernamePassword credential, not reset it";
  EXPECT_EQ(creds->username, "reconnect-user");
  EXPECT_EQ(creds->password, "reconnect-secret");
}

// @verifies CL-SESS-026
// @verifies CL-SESS-029
// Part 4 section 5.6.3.1 permits a client to change the user assigned to a live Session by issuing another
// ActivateSession. Start a real ConnectionImpl to Active, request a UsernamePassword identity change, and
// assert the existing bound Session receives that exact new identity while the Connection and Session id
// remain unchanged. No subscription recovery operation may run: impersonation preserves the Session and its
// Subscriptions. Falsifiable: a no-op, stale-identity resend, session replacement, or recovery loop fails.
// @relation(CL-SESS-026, CL-SESS-029, scope=function)
TEST_F(ConnectionImplTest, ReactivateCarriesNewIdentityAndPreservesLiveSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  ua::UserTokenPolicy usernamePolicy;
  usernamePolicy.policy_id() = "impersonation-user-policy";
  usernamePolicy.token_type() = ua::UserTokenType::UserName;
  config.endpoint.user_identity_tokens().push_back(usernamePolicy);
  auto connection = make_connection(session, reopen, std::move(config));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto originalSessionId = connection->info()->sessionId;

  auto result = reactivate_and_wait(
    *connection, ua::client::UsernamePasswordIdentity{"impersonated-user", "impersonated-secret"});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(connection->info()->state, ConnectionState::Active);
  EXPECT_EQ(connection->info()->sessionId, originalSessionId);
  EXPECT_EQ(session->activateOnBound.call_count(), 1u);
  const auto captured = session->captured_activate_config();
  EXPECT_EQ(captured.policyId, "impersonation-user-policy");
  const auto* credentials = std::get_if<ua::client::UsernamePasswordIdentity>(&captured.identity);
  ASSERT_NE(credentials, nullptr);
  EXPECT_EQ(credentials->username, "impersonated-user");
  EXPECT_EQ(credentials->password, "impersonated-secret");
  EXPECT_EQ(session->transferSubscriptions.call_count(), 0u);
  EXPECT_EQ(session->republish.call_count(), 0u);
}

// @verifies CL-SESS-026
// Reactivation is a live-Session operation. Before bootstrap reaches Active it must fail locally and must
// not send ActivateSession. This pins the state gate and prevents an identity change from racing connect.
// @relation(CL-SESS-026, scope=function)
TEST_F(ConnectionImplTest, ReactivateBeforeActiveFailsWithoutActivateSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  auto result = reactivate_and_wait(*connection, ua::client::UsernamePasswordIdentity{"user", "secret"});

  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidState});
  EXPECT_EQ(session->activateOnBound.call_count(), 0u);
}

// A second identity change must not race an in-flight ActivateSession and overwrite the success winner's
// reconnect credential. Hold the first request, reject the second locally, then release the first.
TEST_F(ConnectionImplTest, ConcurrentReactivateIsRejectedWithoutSecondActivateSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->activateOnBound.set_hold(true);

  std::promise<VoidResult> firstPromise;
  auto firstFuture = firstPromise.get_future();
  connection->reactivate_async(ua::client::AnonymousIdentity{},
    [&firstPromise](VoidResult result) { firstPromise.set_value(std::move(result)); });
  wait_until([&] { return session->activateOnBound.pending_count() == 1; }, "first reactivation held");

  auto second = reactivate_and_wait(*connection, ua::client::AnonymousIdentity{});
  EXPECT_EQ(second.status_code(), StatusCode{Status::BadInvalidState});
  EXPECT_EQ(session->activateOnBound.call_count(), 1u);

  session->activateOnBound.fire_next({});
  EXPECT_TRUE(firstFuture.get().is_good());
}

// A late successful ActivateSession response must not resurrect or mutate a Connection that closed while
// reactivation was in flight. The owed callback still fires exactly once with BadConnectionClosed.
TEST_F(ConnectionImplTest, ReactivateCompletionAfterCloseCannotResurrectConnection)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->activateOnBound.set_hold(true);

  std::promise<VoidResult> reactivatePromise;
  auto reactivateFuture = reactivatePromise.get_future();
  connection->reactivate_async(ua::client::AnonymousIdentity{},
    [&reactivatePromise](VoidResult result) { reactivatePromise.set_value(std::move(result)); });
  wait_until([&] { return session->activateOnBound.pending_count() == 1; }, "reactivation held");

  std::promise<VoidResult> closePromise;
  auto closeFuture = closePromise.get_future();
  connection->close_async([&closePromise](VoidResult result) { closePromise.set_value(std::move(result)); });
  EXPECT_TRUE(closeFuture.get().is_good());

  session->activateOnBound.fire_next({});
  auto result = reactivateFuture.get();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConnectionClosed});
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);
}

// @verifies CL-SESS-027
// Part 4 section 5.6.3.3: BadIdentityChangeNotSupported is a per-call rejection, not a connection failure.
// The exact status/detail must reach the caller, the Connection remains Active, no reconnect starts, ordinary
// service traffic still works, and reconnect bookkeeping retains the PRIOR credential.
// @relation(CL-SESS-027, scope=function)
TEST_F(ConnectionImplTest, IdentityChangeNotSupportedKeepsPriorIdentityAndActiveConnection)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  Session::ActivateConfig originalConfig;
  originalConfig.policyId = "original-user-policy";
  originalConfig.identity = ua::client::UsernamePasswordIdentity{"original-user", "original-secret"};
  auto connection = make_connection_with_activate(session, reopen, originalConfig);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto serverDetail =
    ua::make_error_detail("ServerRejectedIdentityChange", "identity changes are disabled", "server");
  session->activateOnBound.set_result(
    VoidResult{Status::BadIdentityChangeNotSupported, std::move(serverDetail)});

  auto result =
    reactivate_and_wait(*connection, ua::client::UsernamePasswordIdentity{"new-user", "new-secret"});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityChangeNotSupported});
  ASSERT_NE(result.shared_detail(), nullptr);
  const auto renderedDetail = ua::to_string(*result.shared_detail());
  EXPECT_NE(renderedDetail.find("client.tier1.connection.reactivate_async"), std::string::npos);
  EXPECT_NE(renderedDetail.find("ServerRejectedIdentityChange"), std::string::npos);
  EXPECT_EQ(connection->info()->state, ConnectionState::Active);
  EXPECT_EQ(reopen->call_count(), 0u) << "identity rejection must not trigger reconnect";

  auto readResult = read_and_wait(*connection);
  EXPECT_TRUE(readResult.is_good()) << "the prior active Session must remain usable";

  // Drive the reconnect activation primitive manually only to inspect the stored credential. A rejected
  // identity change must not replace it with the new credential.
  ASSERT_TRUE(run_open(*connection).is_good());
  session->activateOnChannel.set_result({});
  ASSERT_TRUE(run_activate(*connection).is_good());
  const auto retained = session->captured_activate_config();
  EXPECT_EQ(retained.policyId, "original-user-policy");
  const auto* retainedCredentials = std::get_if<ua::client::UsernamePasswordIdentity>(&retained.identity);
  ASSERT_NE(retainedCredentials, nullptr);
  EXPECT_EQ(retainedCredentials->username, "original-user");
  EXPECT_EQ(retainedCredentials->password, "original-secret");
}

// ============================================================================================
// section 3.1 finding E (paired guard) - on the CL-RECONN-003 route the pending channel was CONSUMED by a
// failed activate; create_session must re-open a fresh channel before creating the session.
// ============================================================================================
TEST_F(ConnectionImplTest, ReconnectCreateSessionReopensWhenChannelConsumed)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  // Open a channel, then activate-on-existing FAILS Bad_SessionIdInvalid (consuming the channel).
  ASSERT_TRUE(run_open(*connection).is_good());
  session->activateOnChannel.set_result(VoidResult{Status::BadSessionIdInvalid});
  EXPECT_TRUE(run_activate(*connection).is_bad());
  {
    auto snapshot = TA::snapshot(*connection);
    auto* consumed = as_fake_channel(snapshot.pendingChannel);
    ASSERT_NE(consumed, nullptr);
    ASSERT_FALSE(consumed->is_open()) << "activate must consume (close) the channel it rebinds onto";
  }

  // Channel consumed -> create_session must re-open a fresh channel (one more reopen).
  const auto reopensBefore = reopen->call_count();
  ASSERT_TRUE(run_create_session(*connection).is_good());
  EXPECT_EQ(reopen->call_count() - reopensBefore, 1u)
    << "create_session must re-open a fresh channel when the pending channel was consumed (CL-RECONN-003)";
  {
    auto snapshot = TA::snapshot(*connection);
    EXPECT_NE(snapshot.pendingSession, nullptr) << "a fresh session must be staged on the re-opened channel";
  }
}

// ============================================================================================
// Bootstrap (section 8.2A.3 / CL-SESS-028)
// ============================================================================================

// A successful NamespaceArray bootstrap reaches Active and publishes the session id + namespace count.
// The cached NamespaceTable is built from the bootstrap Server.NamespaceArray read (namespaceCount reflects
// the fetched URIs), which is the observable side of CL-BASE-001.
// @verifies CL-BASE-001
// @relation(CL-BASE-001, scope=function)
TEST_F(ConnectionImplTest, BootstrapSuccessReachesActiveAndPublishesInfo)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->set_session_id(NodeId{3, 77});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_EQ(session->read.call_count(), 1u) << "bootstrap issues exactly one NamespaceArray read";

  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, ConnectionState::Active);
  EXPECT_EQ(info->namespaceCount, 2u) << "the fake NamespaceArray has two URIs";
  EXPECT_EQ(info->sessionId, (NodeId{3, 77}));
  // The default fake bootstrap response carries NO UrisVersion (index-2 result absent) - modelling a
  // server that does not publish it, so the snapshot is version-untagged (CL-BASE-001, tolerated).
  EXPECT_FALSE(info->urisVersion.has_value())
    << "a server that does not publish Server.UrisVersion leaves the snapshot version-untagged";
}

// CL-BASE-001: the bootstrap reads Server.UrisVersion alongside Server.NamespaceArray and version-tags the
// cached snapshot. When the server publishes UrisVersion (index 2 of the batch), the cached
// NamespaceTable's uris_version() carries it, republished on ConnectionInfo.
// @verifies CL-BASE-001
// @relation(CL-BASE-001, scope=function)
TEST_F(ConnectionImplTest, BootstrapCachesServerUrisVersion)
{
  auto session = std::make_shared<FakeSessionOps>();
  // The bootstrap Read batches NamespaceArray + ServerArray + UrisVersion; script a response carrying all.
  session->read.set_result(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response(
    {"http://opcfoundation.org/UA/", "urn:test:connection"}, std::uint32_t{0x0A0B0C0D})});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, ConnectionState::Active);
  ASSERT_TRUE(info->urisVersion.has_value())
    << "the bootstrap must read Server.UrisVersion and version-tag the cached snapshot";
  EXPECT_EQ(*info->urisVersion, 0x0A0B0C0Du);
}

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST_F(ConnectionImplTest, BootstrapCachesServerArrayAndPublishesImmutableSnapshot)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection", "urn:remote:a", "urn:remote:b"})});
  auto connection = make_connection(session, std::make_shared<FakeReopen>());

  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto requests = session->read.requests();
  ASSERT_EQ(requests.size(), 1u);
  ASSERT_GE(requests[0].nodes_to_read().size(), 2u);
  EXPECT_EQ(requests[0].nodes_to_read()[0].node_id(), NodeId{ua::VariableId::Server_NamespaceArray});
  EXPECT_EQ(requests[0].nodes_to_read()[1].node_id(), NodeId{ua::VariableId::Server_ServerArray});

  const auto snapshot = connection->server_table_snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->size(), 3u);
  const auto resolved = snapshot->resolve_server_uri(ua::ExpandedNodeId{NodeId{2, 99}, std::uint32_t{2}});
  ASSERT_TRUE(resolved.is_good());
  EXPECT_EQ(resolved.value(), "urn:remote:b");
  EXPECT_EQ(session->read.call_count(), 1u)
    << "repeated cached ServerIndex lookup must not issue another ServerArray read";
  EXPECT_EQ(snapshot->lookup_uri(2), "urn:remote:b");
  EXPECT_EQ(session->read.call_count(), 1u);
}

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST_F(ConnectionImplTest, ServerTableSurvivesPreservedSessionAndReplacesForFreshSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection", "urn:remote:initial"})});
  auto connection = make_connection(session, std::make_shared<FakeReopen>());
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto initial = connection->server_table_snapshot();
  ASSERT_NE(initial, nullptr);

  ASSERT_TRUE(ConnectionImplTestAccess::apply_namespace_read(*connection,
    {"http://opcfoundation.org/UA/", "urn:test:connection", "urn:new:namespace"},
    {"urn:test:connection", "urn:remote:illegal-mid-session-change"},
    false)
                .is_good());
  EXPECT_EQ(connection->server_table_snapshot(), initial)
    << "re-activating the same Session must retain its original ServerArray snapshot";
  EXPECT_EQ(connection->server_table_snapshot()->lookup_uri(1), "urn:remote:initial");

  ASSERT_TRUE(ConnectionImplTestAccess::apply_namespace_read(*connection,
    {"http://opcfoundation.org/UA/", "urn:test:connection"},
    {"urn:test:connection", "urn:remote:fresh-session"},
    true)
                .is_good());
  const auto fresh = connection->server_table_snapshot();
  ASSERT_NE(fresh, initial);
  EXPECT_EQ(fresh->generation(), 2u);
  EXPECT_EQ(fresh->lookup_uri(1), "urn:remote:fresh-session");
}

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST_F(ConnectionImplTest, BootstrapRejectsMissingMandatoryServerArrayWithCause)
{
  auto session = std::make_shared<FakeSessionOps>();
  ua::Array<ua::String> namespaces;
  namespaces.push_back(ua::String{"http://opcfoundation.org/UA/"});
  namespaces.push_back(ua::String{"urn:test:connection"});
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::move(namespaces)}});
  session->read.set_result(ua::Result<ua::ReadResponse>{std::move(response)});
  auto connection = make_connection(session, std::make_shared<FakeReopen>());

  const auto result = start_and_wait(*connection);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUnexpectedError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BootstrapReadFailed");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->code, "ServerArrayResultMissing");
}

// CL-BASE-003: the bootstrap reads the 12 Server.ServerCapabilities.OperationLimits.* nodes (batch indices
// 3..14, in operationLimitNodes order) and caches them on ConnectionInfo.operationLimits, tolerating any the
// server omits (-> 0 = no client-imposed limit). @verifies CL-BASE-003
TEST_F(ConnectionImplTest, BootstrapCachesOperationLimits)
{
  auto session = std::make_shared<FakeSessionOps>();
  // Values in operationLimitNodes order; two left 0 (HistoryReadData/Events) to prove per-field tolerance.
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 13, 14})});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->operationLimits.maxNodesPerRead, 5u);
  EXPECT_EQ(info->operationLimits.maxNodesPerWrite, 6u);
  EXPECT_EQ(info->operationLimits.maxNodesPerMethodCall, 7u);
  EXPECT_EQ(info->operationLimits.maxNodesPerBrowse, 8u);
  EXPECT_EQ(info->operationLimits.maxNodesPerRegisterNodes, 9u);
  EXPECT_EQ(info->operationLimits.maxNodesPerTranslateBrowsePathsToNodeIds, 10u);
  EXPECT_EQ(info->operationLimits.maxNodesPerNodeManagement, 11u);
  EXPECT_EQ(info->operationLimits.maxMonitoredItemsPerCall, 12u);
  EXPECT_EQ(info->operationLimits.maxNodesPerHistoryReadData, 0u) << "an omitted limit stays 0 (unlimited)";
  EXPECT_EQ(info->operationLimits.maxNodesPerHistoryReadEvents, 0u);
  EXPECT_EQ(info->operationLimits.maxNodesPerHistoryUpdateData, 13u);
  EXPECT_EQ(info->operationLimits.maxNodesPerHistoryUpdateEvents, 14u);
}

// A server that publishes NO OperationLimits leaves them all 0 (unlimited); the bootstrap still succeeds.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
// @relation(AC-COMP-CL-CONNIMPL-07-C, scope=function)
TEST_F(ConnectionImplTest, BootstrapOperationLimitsAbsentAreUnlimited)
{
  auto session = std::make_shared<FakeSessionOps>();  // default response carries no OperationLimits
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, ConnectionState::Active);
  EXPECT_EQ(info->operationLimits.maxNodesPerRead, 0u);
  EXPECT_EQ(info->operationLimits.maxNodesPerBrowse, 0u);
  EXPECT_EQ(info->operationLimits.maxMonitoredItemsPerCall, 0u);

  // The header maps absent, BAD and non-UInt32 alike onto 0 == unlimited, and the omitted-node class above
  // covers only the first. Extended rather than replaced: the observable is right and the input classes
  // were incomplete (qa_remediation_plan.md section 2.4 rule 4).
  auto served = ua::test_helpers::make_namespace_array_response(
    {"http://opcfoundation.org/UA/", "urn:test:connection"}, /*urisVersion=*/std::nullopt, {0, 0});
  served.results()[3] = ua::DataValue{StatusCode{Status::BadNodeIdUnknown}};  // MaxNodesPerRead: bad status
  served.results()[4] = ua::DataValue{ua::Variant{2.5}};  // MaxNodesPerWrite: not a UInt32
  auto malformed = std::make_shared<FakeSessionOps>();
  malformed->read.set_result(Result<ua::ReadResponse>{std::move(served)});
  auto tolerant = make_connection(malformed, std::make_shared<FakeReopen>());
  ASSERT_TRUE(start_and_wait(*tolerant).is_good());

  auto tolerantInfo = tolerant->info();
  ASSERT_NE(tolerantInfo, nullptr);
  EXPECT_EQ(tolerantInfo->operationLimits.maxNodesPerRead, 0u) << "a bad-status limit reads as unlimited";
  EXPECT_EQ(tolerantInfo->operationLimits.maxNodesPerWrite, 0u) << "a non-UInt32 limit reads as unlimited";
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, BootstrapCachesContinuationPointLimits)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection"},
      {2, 3, 4})});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  ASSERT_TRUE(start_and_wait(*connection).is_good());
  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->continuationPointLimits.maxBrowse, 2u);
  EXPECT_EQ(info->continuationPointLimits.maxQuery, 3u);
  EXPECT_EQ(info->continuationPointLimits.maxHistory, 4u);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, BrowseQueuesAtContinuationPointLimitUntilBrowseNextReleases)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection"},
      {1, 0, 0})});
  ua::BrowseResponse initialResponse;
  ua::BrowseResult initialResult;
  initialResult.continuation_point() = ua::ContinuationPoint{0x01};
  initialResponse.results().push_back(std::move(initialResult));
  session->browse.set_result(Result<ua::BrowseResponse>{std::move(initialResponse)});
  ua::BrowseNextResponse terminalResponse;
  terminalResponse.results().push_back(ua::BrowseResult{});
  session->browseNext.set_result(Result<ua::BrowseNextResponse>{std::move(terminalResponse)});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(browse_and_wait(*connection).is_good());
  EXPECT_EQ(TA::snapshot(*connection).browseContinuationPoints, 1u);

  std::promise<Result<ua::BrowseResponse>> secondPromise;
  auto secondFuture = secondPromise.get_future();
  connection->browse_async(
    {}, [&secondPromise](Result<ua::BrowseResponse> result) { secondPromise.set_value(std::move(result)); });
  const auto queued = TA::snapshot(*connection);
  EXPECT_EQ(queued.browseContinuationQueue, 1u);
  EXPECT_EQ(session->browse.call_count(), 1u);

  ua::BrowseNextRequest next;
  next.continuation_points().push_back(ua::ContinuationPoint{0x01});
  ASSERT_TRUE(browse_next_and_wait(*connection, std::move(next)).is_good());
  EXPECT_TRUE(secondFuture.get().is_good());
  EXPECT_EQ(session->browse.call_count(), 2u);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, QueryQueuesAtContinuationPointLimitUntilQueryNextReleases)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection"},
      {0, 1, 0})});
  ua::QueryFirstResponse initialResponse;
  initialResponse.continuation_point() = ua::ContinuationPoint{0x02};
  session->queryFirst.set_result(Result<ua::QueryFirstResponse>{std::move(initialResponse)});
  session->queryNext.set_result(Result<ua::QueryNextResponse>{ua::QueryNextResponse{}});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(query_first_and_wait(*connection).is_good());
  std::promise<Result<ua::QueryFirstResponse>> secondPromise;
  auto secondFuture = secondPromise.get_future();
  connection->query_first_async({},
    [&secondPromise](Result<ua::QueryFirstResponse> result) { secondPromise.set_value(std::move(result)); });
  EXPECT_EQ(TA::snapshot(*connection).queryContinuationQueue, 1u);
  EXPECT_EQ(session->queryFirst.call_count(), 1u);

  ua::QueryNextRequest next;
  next.continuation_point() = ua::ContinuationPoint{0x02};
  ASSERT_TRUE(query_next_and_wait(*connection, std::move(next)).is_good());
  EXPECT_TRUE(secondFuture.get().is_good());
  EXPECT_EQ(session->queryFirst.call_count(), 2u);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, HistoryQueuesAtContinuationPointLimitUntilContinuationReadReleases)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection"},
      {0, 0, 1})});
  session->historyRead.set_result_fn(
    [](const ua::HistoryReadRequest& request)
    {
      ua::HistoryReadResponse response;
      ua::HistoryReadResult result;
      if (request.nodes_to_read().empty() || request.nodes_to_read()[0].continuation_point().empty())
      {
        result.continuation_point() = ua::ContinuationPoint{0x03};
      }
      response.results().push_back(std::move(result));
      return Result<ua::HistoryReadResponse>{std::move(response)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::HistoryReadRequest initial;
  initial.nodes_to_read().push_back(ua::HistoryReadValueId{});
  ASSERT_TRUE(history_read_and_wait(*connection, initial).is_good());
  std::promise<Result<ua::HistoryReadResponse>> secondPromise;
  auto secondFuture = secondPromise.get_future();
  connection->history_read_async(initial,
    [&secondPromise](Result<ua::HistoryReadResponse> result) { secondPromise.set_value(std::move(result)); });
  EXPECT_EQ(TA::snapshot(*connection).historyContinuationQueue, 1u);
  EXPECT_EQ(session->historyRead.call_count(), 1u);

  ua::HistoryReadRequest next;
  ua::HistoryReadValueId value;
  value.continuation_point() = ua::ContinuationPoint{0x03};
  next.nodes_to_read().push_back(std::move(value));
  ASSERT_TRUE(history_read_and_wait(*connection, std::move(next)).is_good());
  EXPECT_TRUE(secondFuture.get().is_good());
  EXPECT_EQ(session->historyRead.call_count(), 3u);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, ZeroContinuationPointLimitDoesNotQueueInitialCalls)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->browse.set_hold(true);
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  std::array<std::promise<Result<ua::BrowseResponse>>, 3> promises;
  std::array<std::future<Result<ua::BrowseResponse>>, 3> futures{
    promises[0].get_future(), promises[1].get_future(), promises[2].get_future()};
  for (auto& promise : promises)
  {
    connection->browse_async(
      {}, [&promise](Result<ua::BrowseResponse> result) { promise.set_value(std::move(result)); });
  }
  wait_until([&] { return session->browse.call_count() == 3; }, "all unlimited Browse calls dispatched");
  EXPECT_EQ(session->browse.call_count(), 3u);
  EXPECT_EQ(TA::snapshot(*connection).browseContinuationQueue, 0u);

  for (std::size_t index = 0; index < promises.size(); ++index)
  {
    session->browse.fire_next(Result<ua::BrowseResponse>{ua::BrowseResponse{}});
    EXPECT_TRUE(futures[index].get().is_good());
  }
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, FailedInitialCallReleasesPermitAndAdmitsQueuedCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection"},
      {1, 0, 0})});
  session->browse.set_hold(true);
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  std::promise<Result<ua::BrowseResponse>> firstPromise;
  std::promise<Result<ua::BrowseResponse>> secondPromise;
  auto firstFuture = firstPromise.get_future();
  auto secondFuture = secondPromise.get_future();
  connection->browse_async(
    {}, [&firstPromise](Result<ua::BrowseResponse> result) { firstPromise.set_value(std::move(result)); });
  connection->browse_async(
    {}, [&secondPromise](Result<ua::BrowseResponse> result) { secondPromise.set_value(std::move(result)); });
  wait_until([&] { return session->browse.call_count() == 1; }, "first held Browse dispatched");
  EXPECT_EQ(session->browse.call_count(), 1u);
  EXPECT_EQ(TA::snapshot(*connection).browseContinuationQueue, 1u);

  session->browse.fire_next(Result<ua::BrowseResponse>{ua::Status::BadInternalError});
  EXPECT_TRUE(firstFuture.get().is_bad());
  wait_until([&] { return session->browse.call_count() == 2; }, "queued Browse admitted after failure");
  session->browse.fire_next(Result<ua::BrowseResponse>{ua::BrowseResponse{}});
  EXPECT_TRUE(secondFuture.get().is_good());
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, CloseCancelsQueuedContinuationPointAdmission)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {},
      {"urn:test:connection"},
      {1, 0, 0})});
  ua::BrowseResponse initialResponse;
  ua::BrowseResult initialResult;
  initialResult.continuation_point() = ua::ContinuationPoint{0x01};
  initialResponse.results().push_back(std::move(initialResult));
  session->browse.set_result(Result<ua::BrowseResponse>{std::move(initialResponse)});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(browse_and_wait(*connection).is_good());

  std::promise<Result<ua::BrowseResponse>> queuedPromise;
  auto queuedFuture = queuedPromise.get_future();
  connection->browse_async(
    {}, [&queuedPromise](Result<ua::BrowseResponse> result) { queuedPromise.set_value(std::move(result)); });
  EXPECT_EQ(TA::snapshot(*connection).browseContinuationQueue, 1u);

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  const auto queuedResult = queuedFuture.get();
  EXPECT_TRUE(queuedResult.is_bad());
  EXPECT_EQ(queuedResult.status_code(), ua::StatusCode{ua::Status::BadConnectionClosed});
  EXPECT_EQ(session->browse.call_count(), 1u);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplTest, ContinuationAdmissionQueueOverflowCarriesStructuredErrorDetail)
{
  auto session = std::make_shared<FakeSessionOps>();
  ua::BrowseResponse initialResponse;
  ua::BrowseResult initialResult;
  initialResult.continuation_point() = ua::ContinuationPoint{0x01};
  initialResponse.results().push_back(std::move(initialResult));
  session->browse.set_result(Result<ua::BrowseResponse>{std::move(initialResponse)});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  TA::configure_browse_continuation_tracker(*connection, 1, 1);
  ASSERT_TRUE(browse_and_wait(*connection).is_good());

  std::promise<Result<ua::BrowseResponse>> queuedPromise;
  std::promise<Result<ua::BrowseResponse>> overflowPromise;
  auto queuedFuture = queuedPromise.get_future();
  auto overflowFuture = overflowPromise.get_future();
  connection->browse_async(
    {}, [&queuedPromise](Result<ua::BrowseResponse> result) { queuedPromise.set_value(std::move(result)); });
  connection->browse_async({},
    [&overflowPromise](Result<ua::BrowseResponse> result) { overflowPromise.set_value(std::move(result)); });

  const auto overflow = overflowFuture.get();
  ASSERT_TRUE(overflow.is_bad());
  EXPECT_EQ(overflow.status_code(), ua::StatusCode{ua::Status::BadTooManyOperations});
  ASSERT_NE(overflow.error_detail(), nullptr);
  EXPECT_EQ(overflow.error_detail()->code, "ContinuationPointAdmissionQueueFull");
  EXPECT_EQ(overflow.error_detail()->source, "client.tier1.connection.continuation_points");

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  EXPECT_TRUE(queuedFuture.get().is_bad());
}

// A FakeSessionOps read handler: the bootstrap NamespaceArray read returns @p namespaceResponse; every other
// (chunk) read returns one Good Int32 DataValue per input node echoing the node's numeric id, so the
// reassembled order is verifiable. Used by the CL-BASE-003 Read-chunking tests.
inline void install_echo_read_handler(FakeSessionOps& session, ua::ReadResponse namespaceResponse)
{
  session.read.set_result_fn(
    [namespaceResponse = std::move(namespaceResponse)](
      const ua::ReadRequest& req) -> ua::Result<ua::ReadResponse>
    {
      if (!req.nodes_to_read().empty() &&
          req.nodes_to_read()[0].node_id() == ua::NodeId{ua::VariableId::Server_NamespaceArray})
      {
        return ua::Result<ua::ReadResponse>{namespaceResponse};
      }
      ua::ReadResponse resp;
      for (const auto& rv : req.nodes_to_read())
      {
        resp.results().push_back(
          ua::DataValue{ua::Variant{static_cast<std::int32_t>(rv.node_id().identifier().get_numeric())}});
      }
      return ua::Result<ua::ReadResponse>{std::move(resp)};
    });
}

// Builds a Read of @p count nodes with numeric ids [base, base+count).
inline ua::ReadRequest make_numeric_read(std::uint32_t base, std::size_t count)
{
  ua::ReadRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::ReadValueId rv;
    rv.node_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    rv.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(rv));
  }
  return request;
}

// CL-BASE-003: a Read exceeding MaxNodesPerRead is split into <= limit-sized sub-reads and reassembled in
// input order; the wire funnel sees ceil(N/limit) reads, the caller sees ONE merged response.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST_F(ConnectionImplTest, ReadChunkedAtMaxNodesPerRead)
{
  auto session = std::make_shared<FakeSessionOps>();
  install_echo_read_handler(*session,
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));  // MaxNodesPerRead = 2
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto bootstrapReads = session->read.call_count();

  auto result = read_and_wait(*connection, make_numeric_read(100, 5));  // 5 nodes, limit 2 -> 3 chunks
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "the merged response carries one DataValue per input";
  for (std::size_t i = 0; i < 5; ++i)
  {
    const auto* asInt = result.value().results()[i].value().try_as<std::int32_t>();
    ASSERT_NE(asInt, nullptr);
    EXPECT_EQ(*asInt, static_cast<std::int32_t>(100 + i)) << "reassembled DataValues must be in input order";
  }
  EXPECT_EQ(session->read.call_count() - bootstrapReads, 3u) << "5 nodes / limit 2 -> ceil = 3 chunk reads";
}

// CL-BASE-003: MaxNodesPerRead 0 (absent) means no client-imposed limit - a large Read is a SINGLE request.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST_F(ConnectionImplTest, ReadUnlimitedWhenMaxNodesPerReadZero)
{
  auto session = std::make_shared<FakeSessionOps>();
  install_echo_read_handler(*session, ua::test_helpers::make_namespace_array_response());  // no limits -> 0
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto bootstrapReads = session->read.call_count();

  auto result = read_and_wait(*connection, make_numeric_read(200, 50));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().results().size(), 50u);
  EXPECT_EQ(session->read.call_count() - bootstrapReads, 1u) << "limit 0 -> a single unchunked read";
}

// CL-BASE-003: a batched Read is ATOMIC - a chunk failing (a per-chunk bad service result) fails the whole
// logical Read. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, ReadChunkFailureFailsWholeCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  const auto namespaceResponse =
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  session->read.set_result_fn(
    [namespaceResponse](const ua::ReadRequest& req) -> ua::Result<ua::ReadResponse>
    {
      if (!req.nodes_to_read().empty() &&
          req.nodes_to_read()[0].node_id() == ua::NodeId{ua::VariableId::Server_NamespaceArray})
      {
        return ua::Result<ua::ReadResponse>{namespaceResponse};
      }
      for (const auto& rv : req.nodes_to_read())
      {
        if (rv.node_id() == ua::NodeId{103u})  // fail the chunk containing node 103
        {
          ua::ReadResponse resp;
          resp.response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyOperations};
          return ua::Result<ua::ReadResponse>{std::move(resp)};
        }
      }
      ua::ReadResponse resp;
      for (const auto& rv : req.nodes_to_read())
      {
        resp.results().push_back(
          ua::DataValue{ua::Variant{static_cast<std::int32_t>(rv.node_id().identifier().get_numeric())}});
      }
      return ua::Result<ua::ReadResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = read_and_wait(*connection, make_numeric_read(100, 5));  // chunk (102,103) fails
  ASSERT_TRUE(result.is_bad()) << "a chunk service-level failure must fail the whole batched Read";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
}

// CL-BASE-003: a chunk returning a WRONG result count (buggy/malicious server) fails the whole call rather
// than silently misaligning the reassembled results. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, ReadChunkResultCountMismatchFailsCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  const auto namespaceResponse =
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  session->read.set_result_fn(
    [namespaceResponse](const ua::ReadRequest& req) -> ua::Result<ua::ReadResponse>
    {
      if (!req.nodes_to_read().empty() &&
          req.nodes_to_read()[0].node_id() == ua::NodeId{ua::VariableId::Server_NamespaceArray})
      {
        return ua::Result<ua::ReadResponse>{namespaceResponse};
      }
      // Return ONE result regardless of the chunk size (a conformance violation the client must reject).
      ua::ReadResponse resp;
      resp.results().push_back(ua::DataValue{ua::Variant{std::int32_t{0}}});
      return ua::Result<ua::ReadResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = read_and_wait(*connection, make_numeric_read(100, 5));  // chunk of 2 -> server returns 1
  ASSERT_TRUE(result.is_bad()) << "a chunk returning the wrong result count must fail the whole Read";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUnexpectedError});
}

// A FakeSessionOps write handler: each write returns one StatusCode per WriteValue whose raw value encodes
// the node's numeric id, so the reassembled order is verifiable. Used by the CL-BASE-003 Write-chunking
// tests.
inline void install_echo_write_handler(FakeSessionOps& session)
{
  session.write.set_result_fn(
    [](const ua::WriteRequest& req) -> ua::Result<ua::WriteResponse>
    {
      ua::WriteResponse resp;
      for (const auto& wv : req.nodes_to_write())
      {
        resp.results().push_back(
          ua::StatusCode{static_cast<ua::Status>(wv.node_id().identifier().get_numeric())});
      }
      return ua::Result<ua::WriteResponse>{std::move(resp)};
    });
}

// Builds a Write of @p count nodes with numeric ids [base, base+count) (Value attribute, empty value).
inline ua::WriteRequest make_numeric_write(std::uint32_t base, std::size_t count)
{
  ua::WriteRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::WriteValue wv;
    wv.node_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    wv.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    request.nodes_to_write().push_back(std::move(wv));
  }
  return request;
}

// CL-BASE-003: a Write exceeding MaxNodesPerWrite is split into <= limit sub-writes and the per-item
// StatusCodes reassembled in input order; the funnel sees ceil(N/limit) writes. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, WriteChunkedAtMaxNodesPerWrite)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})});  // MaxNodesPerWrite = 2 (operationLimitNodes index 1)
  install_echo_write_handler(*session);
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = write_and_wait(*connection, make_numeric_write(100, 5));  // 5 nodes, limit 2 -> 3 chunks
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "one StatusCode per input WriteValue";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().results()[i].as_uint32(), 100u + i) << "reassembled StatusCodes in input order";
  }
  EXPECT_EQ(session->write.call_count(), 3u) << "5 nodes / limit 2 -> 3 chunk writes";
}

// CL-BASE-003: a batched Write is ATOMIC - a chunk service-level failure fails the whole Write.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST_F(ConnectionImplTest, WriteChunkFailureFailsWholeCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})});
  session->write.set_result_fn(
    [](const ua::WriteRequest& req) -> ua::Result<ua::WriteResponse>
    {
      for (const auto& wv : req.nodes_to_write())
      {
        if (wv.node_id() == ua::NodeId{103u})  // fail the chunk containing node 103
        {
          ua::WriteResponse resp;
          resp.response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyOperations};
          return ua::Result<ua::WriteResponse>{std::move(resp)};
        }
      }
      ua::WriteResponse resp;
      for (const auto& wv : req.nodes_to_write())
      {
        resp.results().push_back(ua::StatusCode{ua::Status::Good});
      }
      return ua::Result<ua::WriteResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = write_and_wait(*connection, make_numeric_write(100, 5));  // chunk (102,103) fails
  ASSERT_TRUE(result.is_bad()) << "a chunk service-level failure must fail the whole batched Write";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
}

// A FakeSessionOps call handler: each call returns one CallMethodResult per method whose status_code encodes
// the method's objectId, so the reassembled order is verifiable. Used by the CL-BASE-003 Call-chunking tests.
inline void install_echo_call_handler(FakeSessionOps& session)
{
  session.call.set_result_fn(
    [](const ua::CallRequest& req) -> ua::Result<ua::CallResponse>
    {
      ua::CallResponse resp;
      for (const auto& method : req.methods_to_call())
      {
        ua::CallMethodResult result;
        result.status_code() =
          ua::StatusCode{static_cast<ua::Status>(method.object_id().identifier().get_numeric())};
        resp.results().push_back(std::move(result));
      }
      return ua::Result<ua::CallResponse>{std::move(resp)};
    });
}

// Builds a Call of @p count methods with objectId numeric ids [base, base+count).
inline ua::CallRequest make_numeric_call(std::uint32_t base, std::size_t count)
{
  ua::CallRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::CallMethodRequest method;
    method.object_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    request.methods_to_call().push_back(std::move(method));
  }
  return request;
}

// CL-BASE-003: a Call exceeding MaxNodesPerMethodCall is split into <= limit sub-calls and the per-method
// results reassembled in input order; the funnel sees ceil(N/limit) calls. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, CallChunkedAtMaxNodesPerMethodCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0})});  // MaxNodesPerMethodCall = 2 (operationLimitNodes index 2)
  install_echo_call_handler(*session);
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = call_and_wait(*connection, make_numeric_call(100, 5));  // 5 methods, limit 2 -> 3 chunks
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "one CallMethodResult per input method";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().results()[i].status_code().as_uint32(), 100u + i)
      << "reassembled results must be in input order";
  }
  EXPECT_EQ(session->call.call_count(), 3u) << "5 methods / limit 2 -> 3 chunk calls";
}

// CL-BASE-003: a batched Call is ATOMIC - a chunk service-level failure fails the whole Call.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST_F(ConnectionImplTest, CallChunkFailureFailsWholeCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0})});
  session->call.set_result_fn(
    [](const ua::CallRequest& req) -> ua::Result<ua::CallResponse>
    {
      for (const auto& method : req.methods_to_call())
      {
        if (method.object_id() == ua::NodeId{103u})
        {
          ua::CallResponse resp;
          resp.response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyOperations};
          return ua::Result<ua::CallResponse>{std::move(resp)};
        }
      }
      ua::CallResponse resp;
      for (std::size_t i = 0; i < req.methods_to_call().size(); ++i)
      {
        resp.results().push_back(ua::CallMethodResult{});
      }
      return ua::Result<ua::CallResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = call_and_wait(*connection, make_numeric_call(100, 5));  // chunk (102,103) fails
  ASSERT_TRUE(result.is_bad()) << "a chunk service-level failure must fail the whole batched Call";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
}

// Builds a HistoryRead of @p count nodes with numeric ids [base, base+count).
inline ua::HistoryReadRequest make_numeric_history_read(std::uint32_t base, std::size_t count)
{
  ua::HistoryReadRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::HistoryReadValueId value;
    value.node_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    request.nodes_to_read().push_back(std::move(value));
  }
  return request;
}

// CL-BASE-003: a HistoryRead exceeding the effective MaxNodesPerHistoryRead limit (min of Data/Events) is
// split into <= limit sub-reads and the per-node results reassembled in input order. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, HistoryReadChunkedAtMaxNodesPerHistoryRead)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response(
    {"http://opcfoundation.org/UA/", "urn:test:connection"},
    std::nullopt,
    {0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0})});  // MaxNodesPerHistoryReadData = 2 (operationLimitNodes index 8)
  session->historyRead.set_result_fn(
    [](const ua::HistoryReadRequest& req) -> ua::Result<ua::HistoryReadResponse>
    {
      ua::HistoryReadResponse resp;
      for (const auto& value : req.nodes_to_read())
      {
        ua::HistoryReadResult result;
        result.status_code() =
          ua::StatusCode{static_cast<ua::Status>(value.node_id().identifier().get_numeric())};
        resp.results().push_back(std::move(result));
      }
      return ua::Result<ua::HistoryReadResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = history_read_and_wait(*connection, make_numeric_history_read(100, 5));  // 5, limit 2 -> 3
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "one HistoryReadResult per input node";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().results()[i].status_code().as_uint32(), 100u + i)
      << "reassembled results must be in input order";
  }
  EXPECT_EQ(session->historyRead.call_count(), 3u) << "5 nodes / limit 2 -> 3 chunk history reads";
}

// Builds a Browse of @p count nodes with numeric ids [base, base+count).
inline ua::BrowseRequest make_numeric_browse(std::uint32_t base, std::size_t count)
{
  ua::BrowseRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::BrowseDescription description;
    description.node_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    request.nodes_to_browse().push_back(std::move(description));
  }
  return request;
}

// CL-BASE-003: a Browse exceeding MaxNodesPerBrowse is split into <= limit sub-browses and the per-node
// BrowseResults reassembled in input order. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, BrowseChunkedAtMaxNodesPerBrowse)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0})});  // MaxNodesPerBrowse = 2 (operationLimitNodes index 3)
  session->browse.set_result_fn(
    [](const ua::BrowseRequest& req) -> ua::Result<ua::BrowseResponse>
    {
      ua::BrowseResponse resp;
      for (const auto& description : req.nodes_to_browse())
      {
        ua::BrowseResult result;
        result.status_code() =
          ua::StatusCode{static_cast<ua::Status>(description.node_id().identifier().get_numeric())};
        resp.results().push_back(std::move(result));
      }
      return ua::Result<ua::BrowseResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = browse_and_wait(*connection, make_numeric_browse(100, 5));  // 5 nodes, limit 2 -> 3 chunks
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "one BrowseResult per input node";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().results()[i].status_code().as_uint32(), 100u + i)
      << "reassembled BrowseResults must be in input order";
  }
  EXPECT_EQ(session->browse.call_count(), 3u) << "5 nodes / limit 2 -> 3 chunk browses";
}

// Builds a RegisterNodes of @p count nodes with numeric ids [base, base+count).
inline ua::RegisterNodesRequest make_numeric_register(std::uint32_t base, std::size_t count)
{
  ua::RegisterNodesRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    request.nodes_to_register().push_back(ua::NodeId{static_cast<std::uint32_t>(base + i)});
  }
  return request;
}

// CL-BASE-003: a RegisterNodes exceeding MaxNodesPerRegisterNodes is split into <= limit sub-registers and
// the registered ids reassembled in input order (the per-chunk count-check runs before any alias install).
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST_F(ConnectionImplTest, RegisterNodesChunkedAtMaxNodesPerRegisterNodes)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0})});  // MaxNodesPerRegisterNodes = 2 (operationLimitNodes index 4)
  session->registerNodes.set_result_fn(
    [](const ua::RegisterNodesRequest& req) -> ua::Result<ua::RegisterNodesResponse>
    {
      ua::RegisterNodesResponse resp;
      for (const auto& node : req.nodes_to_register())
      {
        resp.registered_node_ids().push_back(node);  // echo the requested id as the registered id
      }
      return ua::Result<ua::RegisterNodesResponse>{std::move(resp)};
    });
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto result = register_nodes_and_wait(*connection, make_numeric_register(100, 5));  // 5, limit 2 -> 3
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().registered_node_ids().size(), 5u) << "one registered id per input node";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().registered_node_ids()[i], (ua::NodeId{100u + static_cast<std::uint32_t>(i)}))
      << "reassembled registered ids must be in input order";
  }
  EXPECT_EQ(session->registerNodes.call_count(), 3u) << "5 nodes / limit 2 -> 3 chunk register calls";
}

// CL-BASE-003: the ONLY place the client batches CreateMonitoredItems is the session-CHANGED recovery
// recreate (the normal path creates one item at a time). When a recreated subscription has more retained
// items than MaxMonitoredItemsPerCall, the recreate must split them into <= limit-sized CreateMonitoredItems
// and reassemble the per-item results, re-keying every item to ITS OWN recreated server id. To make a
// cross-chunk mis-pairing falsifiable, both the original and the recreate fake bind each returned server
// monitored-item id to the request item's clientHandle (id = clientHandle + offset). After commit the owner
// routing for clientHandle H must read back exactly {88, H + 9000}; had the merge paired a handle with a
// different chunk's result, H would carry a foreign item's id and the per-handle assertion would fail.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST_F(ConnectionImplTest, SessionChangedRecreateChunksMonitoredItemsAtMaxMonitoredItemsPerCall)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0})});  // MaxMonitoredItemsPerCall = 2 (operationLimitNodes index 7)
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Seed a subscription with 5 monitored items through the OWNER path, so each item's clientHandle -> server
  // routing is registered and can be read back after recovery. The original create binds server id to handle
  // (handle + 100); the exact original id is irrelevant (recovery re-keys it) but keeps the fake uniform.
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*subId=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, 100.0).is_good());
  session->createMonitoredItems.set_result_fn(
    [](const ua::CreateMonitoredItemsRequest& req) -> Result<ua::CreateMonitoredItemsResponse>
    {
      ua::CreateMonitoredItemsResponse resp;
      for (const auto& item : req.items_to_create())
      {
        ua::MonitoredItemCreateResult itemResult;
        itemResult.status_code() = ua::StatusCode{ua::Status::Good};
        itemResult.monitored_item_id() = item.requested_parameters().client_handle() + 100;
        resp.results().push_back(std::move(itemResult));
      }
      return Result<ua::CreateMonitoredItemsResponse>{std::move(resp)};
    });
  std::vector<std::uint32_t> handles;
  for (std::uint32_t i = 0; i < 5; ++i)
  {
    const auto monitored = monitor_data_change_and_wait(*connection, /*subId=*/77, NodeId{2, 10 + i});
    ASSERT_TRUE(monitored.is_good());
    handles.push_back(monitored.value().client_handle());
  }

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});  // refuse -> recreate
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  // The chunked recreate issues 3 CreateMonitoredItems. Each returned server id is a function of the request
  // item's clientHandle (handle + 9000), so a merge that pairs clientHandles[i] with a foreign chunk result
  // would re-key that handle to the wrong id and the per-handle read-back below would fail.
  fresh->createMonitoredItems.set_result_fn(
    [](const ua::CreateMonitoredItemsRequest& req) -> Result<ua::CreateMonitoredItemsResponse>
    {
      ua::CreateMonitoredItemsResponse resp;
      for (const auto& item : req.items_to_create())
      {
        ua::MonitoredItemCreateResult itemResult;
        itemResult.status_code() = ua::StatusCode{ua::Status::Good};
        itemResult.monitored_item_id() = item.requested_parameters().client_handle() + 9000;
        resp.results().push_back(std::move(itemResult));
      }
      return Result<ua::CreateMonitoredItemsResponse>{std::move(resp)};
    });

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(fresh->createMonitoredItems.call_count(), 3u)
    << "5 retained items / MaxMonitoredItemsPerCall 2 -> 3 chunked CreateMonitoredItems";
  const auto itemsRequests = fresh->createMonitoredItems.requests();  // by value (snapshot copy)
  ASSERT_EQ(itemsRequests.size(), 3u);
  for (const auto& itemsRequest : itemsRequests)
  {
    EXPECT_LE(itemsRequest.items_to_create().size(), 2u) << "no chunk may exceed MaxMonitoredItemsPerCall";
    EXPECT_EQ(itemsRequest.subscription_id(), 88u) << "each chunk targets the recreated subscription";
  }
  EXPECT_EQ(monitored_item_count(*connection), 5u) << "all 5 items must be recreated + re-keyed";

  // The falsifier: every clientHandle must be re-keyed to the recreated subscription AND to the server id the
  // recreate returned for THAT handle. A cross-chunk merge reorder swaps these ids between handles.
  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  for (const auto handle : handles)
  {
    EXPECT_EQ(owner->subscription_of(handle), std::optional<std::uint32_t>{88})
      << "handle " << handle << " must re-key to the recreated subscription";
    EXPECT_EQ(owner->server_item_id(handle), std::optional<std::uint32_t>{handle + 9000})
      << "handle " << handle << " must re-key to ITS OWN recreated server id (no cross-chunk mis-pairing)";
  }
}

// @verifies CL-MI-011
// A DataChangeFilter supplied on the MonitorRequest must be encoded into the CreateMonitoredItems wire
// request's MonitoringParameters.filter as a DataChangeFilter ExtensionObject carrying trigger + deadbandType
// + deadbandValue. Before the fix the filter was accepted but silently dropped.
// @relation(CL-MI-011, scope=function)
TEST_F(ConnectionImplTest, MonitorDataChangeEncodesDataChangeFilterOnWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/100.0).is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});

  MonitorRequest request;
  request.nodeId = NodeId{2, 7};
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = 1;  // Absolute
  filter.deadband_value() = 2.5;
  request.filter = filter;

  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  connection->monitor_data_change_async(/*subId=*/
    77,
    std::move(request),
    [](DataChangeEvent) {},
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto requests = session->createMonitoredItems.requests();  // by value - outlive the reference below
  ASSERT_FALSE(requests.empty());
  ASSERT_EQ(requests.back().items_to_create().size(), 1u);
  const auto& params = requests.back().items_to_create()[0].requested_parameters();
  const auto* wireFilter = dynamic_cast<const ua::DataChangeFilter*>(params.filter().get());
  ASSERT_NE(wireFilter, nullptr) << "the DataChangeFilter must be encoded into MonitoringParameters.filter";
  EXPECT_EQ(wireFilter->trigger(), ua::DataChangeTrigger::StatusValue);
  EXPECT_EQ(wireFilter->deadband_type(), 1u);
  EXPECT_DOUBLE_EQ(wireFilter->deadband_value(), 2.5);
}

// @verifies CL-MI-012
// The client surfaces a server per-item Bad_FilterNotAllowed (an AbsoluteDeadband the server rejects) as a
// bad MonitoredItemResult, and issues NO local pre-flight Read - Phase-A defers DataType/filter validity to
// the server (no extra wire Read). The callback is owed only after the optimistic attach is rolled back.
// @relation(AC-CL-MI-012-NO-LOCAL-DATATYPE-PRE-FLIGHT, scope=function)
TEST_F(ConnectionImplTest, MonitorDeadbandServerRejectionSurfacedWithNoPreflightRead)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/100.0).is_good());

  const auto rejectionDetail =
    std::shared_ptr<const ua::ErrorDetail>{ua::make_error_detail("InjectedDeadbandRejection",
      "the fake server rejected the AbsoluteDeadband for this node",
      "test.connection.monitor.deadband_rejection")};
  ua::CreateMonitoredItemsResponse response;
  ua::MonitoredItemCreateResult itemResult;
  itemResult.status_code() = ua::StatusCode{ua::Status::BadFilterNotAllowed, rejectionDetail};
  response.results().push_back(std::move(itemResult));
  session->createMonitoredItems.set_hold(true);

  const std::size_t readsBefore = session->read.call_count();

  MonitorRequest request;
  request.nodeId = NodeId{2, 7};
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = 1;  // Absolute
  filter.deadband_value() = 2.5;
  request.filter = filter;

  std::optional<std::size_t> countAtCallback;
  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  connection->monitor_data_change_async(/*subId=*/
    77,
    std::move(request),
    [](DataChangeEvent) {},
    [&connection, &countAtCallback, &promise](MonitoredItemResult result)
    {
      const auto info = TA::pipeline_info(*connection);
      countAtCallback = info ? info->monitoredItemCount : 0;
      promise.set_value(std::move(result));
    });

  wait_until([&] { return session->createMonitoredItems.pending_count() == 1; },
    "the held CreateMonitoredItems response");
  wait_until([&] { return monitored_item_count(*connection) == 1; }, "the optimistic monitored-item attach");
  session->createMonitoredItems.fire_next(Result<ua::CreateMonitoredItemsResponse>{std::move(response)});
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad()) << "a per-item Bad_FilterNotAllowed must surface as a bad Result";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadFilterNotAllowed});
  EXPECT_EQ(result.shared_detail(), rejectionDetail) << "the per-item ErrorDetail must survive unchanged";
  EXPECT_EQ(session->read.call_count(), readsBefore)
    << "the client must NOT pre-flight a Read to validate the filter/DataType (defer to the server)";
  ASSERT_TRUE(countAtCallback.has_value());
  EXPECT_EQ(*countAtCallback, 0u) << "the failure callback must not precede rollback publication";
  EXPECT_EQ(monitored_item_count(*connection), 0u) << "a rejected create must leave no attach state";
}

// @verifies CL-MI-024
// A PercentDeadband DataChangeFilter whose value is outside the inclusive [0,100] range (or non-finite) must
// be rejected LOCALLY with Bad_DeadbandFilterInvalid and NO CreateMonitoredItems on the wire - a percentage
// out of [0,100] is a structural error independent of the node's DataType, so no server round-trip is wasted.
// A valid 5.0 reaches the wire. [neg: boundary [0,100]]
// @relation(CL-MI-024, scope=function)
TEST_F(ConnectionImplTest, MonitorPercentDeadbandRangeValidatedLocally)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/100.0).is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});

  const auto monitorWithPercent = [&](double percent) -> MonitoredItemResult
  {
    MonitorRequest request;
    request.nodeId = NodeId{2, 7};
    ua::DataChangeFilter filter;
    filter.trigger() = ua::DataChangeTrigger::StatusValue;
    filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Percent);
    filter.deadband_value() = percent;
    request.filter = filter;
    std::promise<MonitoredItemResult> promise;
    auto future = promise.get_future();
    connection->monitor_data_change_async(/*subId=*/
      77,
      std::move(request),
      [](DataChangeEvent) {},
      [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
    return future.get();
  };

  // In-range 5.0 -> reaches the wire.
  const std::size_t createsBeforeValid = session->createMonitoredItems.call_count();
  EXPECT_TRUE(monitorWithPercent(5.0).is_good()) << "an in-range PercentDeadband must monitor normally";
  EXPECT_EQ(session->createMonitoredItems.call_count(), createsBeforeValid + 1)
    << "a valid PercentDeadband must emit a CreateMonitoredItems";

  // Out-of-range -1.0 and 100.5 -> local reject, NO wire request.
  for (const double outOfRange : {-1.0, 100.5})
  {
    const std::size_t createsBefore = session->createMonitoredItems.call_count();
    const auto result = monitorWithPercent(outOfRange);
    EXPECT_TRUE(result.is_bad()) << "PercentDeadband " << outOfRange << " must be rejected locally";
    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadDeadbandFilterInvalid});
    EXPECT_EQ(session->createMonitoredItems.call_count(), createsBefore)
      << "an out-of-range PercentDeadband must NOT reach the wire (local short-circuit)";
  }
}

// @verifies CL-MI-011
// A monitor with NO filter must leave MonitoringParameters.filter null on the wire (no synthesized deadband=0
// filter). [neg: absent filter -> null on wire]
// @relation(CL-MI-011, scope=function)
TEST_F(ConnectionImplTest, MonitorDataChangeWithNoFilterOmitsFilterOnWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/100.0).is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});

  MonitorRequest request;
  request.nodeId = NodeId{2, 7};  // request.filter left as monostate (no filter)

  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  connection->monitor_data_change_async(/*subId=*/
    77,
    std::move(request),
    [](DataChangeEvent) {},
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto requests = session->createMonitoredItems.requests();
  ASSERT_FALSE(requests.empty());
  ASSERT_EQ(requests.back().items_to_create().size(), 1u);
  const auto& params = requests.back().items_to_create()[0].requested_parameters();
  EXPECT_EQ(params.filter().get(), nullptr) << "a monitor with no filter must leave the wire filter null";
}

// @verifies CL-MI-011
// OPEN-MI-011: the retained DataChangeFilter must survive a session-CHANGED recreate - the recreated
// CreateMonitoredItems on the fresh session re-sends the caller's filter (deadband/trigger), not the
// builder's default (no filter). Without retention, a reconnect silently strips the deadband.
// @relation(CL-MI-011, scope=function)
TEST_F(ConnectionImplTest, SessionChangedRecreateReSendsRetainedDataChangeFilter)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/100.0).is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});

  // Monitor a filtered item (owner path, so it is retained for recovery).
  {
    MonitorRequest request;
    request.nodeId = NodeId{2, 7};
    ua::DataChangeFilter filter;
    filter.trigger() = ua::DataChangeTrigger::StatusValue;
    filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
    filter.deadband_value() = 2.5;
    request.filter = filter;
    std::promise<MonitoredItemResult> promise;
    auto future = promise.get_future();
    connection->monitor_data_change_async(/*subId=*/
      77,
      std::move(request),
      [](DataChangeEvent) {},
      [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  // Session-CHANGED reconnect: transfer refused -> recreate on the fresh session.
  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  fresh->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*newMiId=*/900)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  const auto requests = fresh->createMonitoredItems.requests();  // by value - outlive the reference below
  ASSERT_FALSE(requests.empty());
  ASSERT_FALSE(requests.back().items_to_create().empty());
  const auto* wireFilter = dynamic_cast<const ua::DataChangeFilter*>(
    requests.back().items_to_create()[0].requested_parameters().filter().get());
  ASSERT_NE(wireFilter, nullptr) << "the recreate must re-send the retained DataChangeFilter (OPEN-MI-011)";
  EXPECT_EQ(wireFilter->deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Absolute));
  EXPECT_DOUBLE_EQ(wireFilter->deadband_value(), 2.5);
}

// A FakeSessionOps translate handler: each translate returns one BrowsePathResult per BrowsePath whose
// status_code encodes the starting node's numeric id, so the reassembled order is verifiable. Used by the
// CL-BASE-003 TranslateBrowsePaths-chunking test.
inline void install_echo_translate_handler(FakeSessionOps& session)
{
  session.translateBrowsePaths.set_result_fn(
    [](const ua::TranslateBrowsePathsToNodeIdsRequest& req)
      -> ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>
    {
      ua::TranslateBrowsePathsToNodeIdsResponse resp;
      for (const auto& path : req.browse_paths())
      {
        ua::BrowsePathResult result;
        result.status_code() =
          ua::StatusCode{static_cast<ua::Status>(path.starting_node().identifier().get_numeric())};
        resp.results().push_back(std::move(result));
      }
      return ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(resp)};
    });
}

// Builds a Translate of @p count BrowsePaths with starting-node numeric ids [base, base+count).
inline ua::TranslateBrowsePathsToNodeIdsRequest make_numeric_translate(std::uint32_t base, std::size_t count)
{
  ua::TranslateBrowsePathsToNodeIdsRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::BrowsePath path;
    path.starting_node() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    request.browse_paths().push_back(std::move(path));
  }
  return request;
}

// CL-BASE-003: a TranslateBrowsePaths exceeding MaxNodesPerTranslateBrowsePathsToNodeIds is split into
// <= limit sub-requests and the per-path BrowsePathResults reassembled in input order; the funnel sees
// ceil(N/limit) translates. @verifies CL-BASE-003
TEST_F(ConnectionImplTest, TranslateChunkedAtMaxNodesPerTranslate)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0})});  // MaxNodesPerTranslate = 2 (operationLimitNodes index 5)
  install_echo_translate_handler(*session);
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // 5 paths, limit 2 -> 3 chunks. If the chunk branch were bypassed (a single dispatch of all 5), the fake
  // would return 5 results in ONE call and call_count would be 1 - so the call_count == 3 assertion below
  // falsifies a missing/broken chunk branch.
  auto result = translate_browse_paths_and_wait(*connection, make_numeric_translate(100, 5));
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "one BrowsePathResult per input BrowsePath";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().results()[i].status_code().as_uint32(), 100u + i)
      << "reassembled BrowsePathResults must be in input order";
  }
  EXPECT_EQ(session->translateBrowsePaths.call_count(), 3u) << "5 paths / limit 2 -> 3 chunk translates";
}

// A FakeSessionOps delete-nodes handler: each delete returns one StatusCode per DeleteNodesItem whose raw
// value encodes the node's numeric id, so the reassembled order is verifiable. Used by the CL-BASE-003
// DeleteNodes-chunking test.
inline void install_echo_delete_nodes_handler(FakeSessionOps& session)
{
  session.deleteNodes.set_result_fn(
    [](const ua::DeleteNodesRequest& req) -> ua::Result<ua::DeleteNodesResponse>
    {
      ua::DeleteNodesResponse resp;
      for (const auto& item : req.nodes_to_delete())
      {
        resp.results().push_back(
          ua::StatusCode{static_cast<ua::Status>(item.node_id().identifier().get_numeric())});
      }
      return ua::Result<ua::DeleteNodesResponse>{std::move(resp)};
    });
}

// Builds a DeleteNodes of @p count items with numeric ids [base, base+count).
inline ua::DeleteNodesRequest make_numeric_delete_nodes(std::uint32_t base, std::size_t count)
{
  ua::DeleteNodesRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::DeleteNodesItem item;
    item.node_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    request.nodes_to_delete().push_back(std::move(item));
  }
  return request;
}

// CL-BASE-003: a DeleteNodes exceeding MaxNodesPerNodeManagement is split into <= limit sub-requests and the
// per-node StatusCodes reassembled in input order; the funnel sees ceil(N/limit) deletes.
// @verifies CL-BASE-003
TEST_F(ConnectionImplTest, DeleteNodesChunkedAtMaxNodesPerNodeManagement)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{
    ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/", "urn:test:connection"},
      std::nullopt,
      {0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0})});  // MaxNodesPerNodeManagement = 2 (operationLimitNodes idx 6)
  install_echo_delete_nodes_handler(*session);
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // 5 items, limit 2 -> 3 chunks. A bypassed chunk branch would dispatch all 5 in ONE call (call_count 1),
  // so the call_count == 3 assertion below falsifies a missing/broken chunk branch.
  auto result = delete_nodes_and_wait(*connection, make_numeric_delete_nodes(100, 5));
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 5u) << "one StatusCode per input DeleteNodesItem";
  for (std::size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.value().results()[i].as_uint32(), 100u + i)
      << "reassembled StatusCodes must be in input order";
  }
  EXPECT_EQ(session->deleteNodes.call_count(), 3u) << "5 nodes / limit 2 -> 3 chunk deletes";
}

// @verifies CL-DIAG-002
// A failed bootstrap Read transitions to Failed and delivers the tier-1 ErrorDetail chain (not resurrected).
// CL-DIAG-002: every tier-1 wrap uses the taxonomic tier-1 source tag; this asserts the observable side -
// the wrap the orchestrator applies at the bootstrap boundary carries source "client.tier1.connection_impl".
// Scope/flag note: the impl tags per-component ("client.tier1.connection_impl"), whereas the requirement's
// example format is per-operation ("client.tier1.connection.<operation>") - the taxonomic PRINCIPLE is met;
// the exact granularity differs (doc-vs-impl, flagged in the batch list).
// @relation(CL-DIAG-002, scope=function)
TEST_F(ConnectionImplTest, BootstrapReadFailureTransitionsFailedAndPropagatesErrorDetail)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{StatusCode{Status::BadServerNotConnected}});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  auto result = start_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());
  auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "a bootstrap failure must carry an ErrorDetail chain (not dropped)";
  EXPECT_EQ(detail->source, "client.tier1.connection_impl");
  EXPECT_EQ(connection->info()->state, ConnectionState::Failed);
}

// @relation(AC-COMP-CL-CONNIMPL-12-A, scope=function)
TEST_F(ConnectionImplTest, EveryDestructionPathRunsTheTeardownHookOnce)
{
  for (const std::string_view path : {std::string_view{"failed bootstrap"},
         std::string_view{"graceful close"},
         std::string_view{"active handle drop"}})
  {
    SCOPED_TRACE(std::string{path});
    auto session = std::make_shared<FakeSessionOps>();
    if (path == "failed bootstrap")
    {
      session->read.set_result(Result<ua::ReadResponse>{StatusCode{Status::BadServerNotConnected}});
    }
    auto connection = make_connection(session, std::make_shared<FakeReopen>());
    auto teardownCalls = std::make_shared<std::atomic<std::size_t>>(0);
    connection->set_teardown_hook([teardownCalls] { teardownCalls->fetch_add(1); });

    const auto started = start_and_wait(*connection);
    if (path == "failed bootstrap")
    {
      ASSERT_TRUE(started.is_bad());
      EXPECT_EQ(connection->info()->state, ConnectionState::Failed);
    }
    else
    {
      ASSERT_TRUE(started.is_good());
      if (path == "graceful close")
      {
        ASSERT_TRUE(close_and_wait(*connection).is_good());
      }
    }
    EXPECT_EQ(teardownCalls->load(), 0u);
    const std::weak_ptr<ConnectionImpl> destroyed = connection;
    connection.reset();
    wait_until([teardownCalls] { return teardownCalls->load() != 0; }, "the destructor hook");
    auto destructionSettled = std::make_shared<std::promise<void>>();
    auto destructionSettledFuture = destructionSettled->get_future();
    // The runtime has one runner; this post runs after any destructor executing on that runner.
    boost::asio::post(mRuntime.executor(), [destructionSettled] { destructionSettled->set_value(); });
    ASSERT_EQ(destructionSettledFuture.wait_for(5s), std::future_status::ready);
    EXPECT_TRUE(destroyed.expired());
    EXPECT_EQ(teardownCalls->load(), 1u);
  }
}

// A bootstrap Read answered Uncertain without a response holds no NamespaceArray, so the Connection is not
// built on it: the start fails with Bad_InternalError, its ErrorDetail chain naming the refusal
// (ReadAnswerUncertain, the code as its inner status), and the Connection is Failed rather than reported as a
// close that raced the bootstrap.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, BootstrapRefusesAnUncertainReadWithoutAResponse)
{
  auto session = std::make_shared<FakeSessionOps>();
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  session->read.set_result(ua::Result<ua::ReadResponse>{uncertain});
  auto connection = make_connection(session, std::make_shared<FakeReopen>());

  const auto result = start_and_wait(*connection);

  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BootstrapReadFailed");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->code, "ReadAnswerUncertain");
  EXPECT_EQ(result.shared_detail()->cause->innerStatus, uncertain.value());
  EXPECT_EQ(connection->info()->state, ConnectionState::Failed);
}

// section 3.1 finding #3: a close that races an in-flight bootstrap must NOT resurrect the Connection to
// Active.
TEST_F(ConnectionImplTest, BootstrapTerminalGuardDeliversClosedWhenCloseRacesBootstrap)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_hold(true);  // park the bootstrap read so close can race it
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  std::promise<VoidResult> startPromise;
  auto startFuture = startPromise.get_future();
  connection->start_async([&startPromise](VoidResult result) { startPromise.set_value(std::move(result)); });
  wait_until([&] { return session->read.pending_count() >= 1; }, "bootstrap read parked");

  // Close races the in-flight bootstrap.
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  // The bootstrap read now completes Good - but the terminal guard must reject it, not reach Active.
  session->read.fire_next(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response()});
  auto startResult = startFuture.get();
  EXPECT_TRUE(startResult.is_bad()) << "a bootstrap completing after close must deliver Bad, not Good";
  EXPECT_EQ(startResult.status_code(), StatusCode{Status::BadConnectionClosed});
  EXPECT_EQ(TA::snapshot(*connection).state, ConnectionState::Closed)
    << "close must not be resurrected to Active";
}

// ============================================================================================
// Wire-op gating (section 8.2A.5)
// ============================================================================================

// When Active a wire op dispatches straight to the tier-0 session and completes Good.
TEST_F(ConnectionImplTest, WireOpDispatchesToOpsWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(write_and_wait(*connection).is_good());
  EXPECT_EQ(session->write.call_count(), 1u) << "an Active write must dispatch to the session";
}

// C1 / W2 - the SemanticChangeCache accessor is FREE-THREADED: its sole real caller
// (Connection::data_access()
// -> the DataAccess handle-build completion) reaches it OFF the connection strand, on the executor. Posting
// the accessor onto the bare executor must NOT abort (it once asserted running-on-strand, which fired on
// every real debug build) and must hand back a non-null cache. @verifies CL-DA-010
TEST_F(ConnectionImplTest, SemanticChangeCacheAccessorIsFreeThreadedOffStrand)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  std::promise<std::shared_ptr<ua::client::detail::SemanticChangeCache>> promise;
  auto future = promise.get_future();
  // Post onto the bare (non-strand) executor: the handler runs OFF the connection strand, exactly like the
  // DataAccess handle-build completion. The accessor must be callable there without an abort.
  boost::asio::post(TA::executor(*connection),
    [&connection, &promise] { promise.set_value(TA::semantic_change_cache(*connection)); });
  auto cache = future.get();
  EXPECT_NE(cache, nullptr) << "the free-threaded accessor must construct + return the cache off-strand";
}

// W8a - the AddressSpaceCache accessor is FREE-THREADED and CO-OWNED, mirroring semantic_change_cache: the
// W8b model-change router reaches it OFF the connection strand (event callbacks fire on the executor).
// Posting the accessor onto the bare executor must NOT abort and must hand back a non-null cache; repeated
// calls (on and off strand) return the SAME instance (call_once), and the default policy leaves it disabled
// (opt-in section 8.7). This is the wiring PREREQUISITE for CL-EVT-003 (the model-change flush target); the
// CL-EVT-003 routing itself is verified by the W8b EventSubscriber-router tests, not here.
TEST_F(ConnectionImplTest, AddressSpaceCacheAccessorIsFreeThreadedAndCoOwned)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  // Post onto the bare (non-strand) executor: the handler runs OFF the connection strand, exactly like the
  // W8b model-change event callback. The accessor must be callable there without an abort.
  std::promise<std::shared_ptr<ua::client::detail::AddressSpaceCache>> promise;
  auto future = promise.get_future();
  boost::asio::post(TA::executor(*connection),
    [&connection, &promise] { promise.set_value(TA::address_space_cache(*connection)); });
  auto cache = future.get();
  ASSERT_NE(cache, nullptr) << "the free-threaded accessor must construct + return the cache off-strand";

  // Idempotent / co-owned: a second call (here from the calling thread) returns the SAME instance
  // (call_once), never a fresh cache per call.
  auto again = TA::address_space_cache(*connection);
  EXPECT_EQ(again, cache) << "call_once must hand back one co-owned instance, not a new cache per call";

  // Default (disabled) policy: opt-in section 8.7 - a disabled cache is a clean pass-through no-op.
  EXPECT_FALSE(cache->enabled()) << "the default AddressSpaceCachePolicy leaves the cache disabled (opt-in)";
}

// HistoryRead routes through the SAME gated invoke_wire_op funnel as read/write: Active dispatches straight
// to the tier-0 session and completes Good.
TEST_F(ConnectionImplTest, HistoryReadDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(history_read_and_wait(*connection).is_good());
  EXPECT_EQ(session->historyRead.call_count(), 1u) << "an Active HistoryRead must dispatch to the session";
}

// A HistoryRead in a terminal state fast-fails Bad_ConnectionClosed WITHOUT touching the session (FU-1 gate).
TEST_F(ConnectionImplTest, HistoryReadFastFailsWhenTerminalWithoutTouchingOps)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  const auto result = history_read_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConnectionClosed});
  EXPECT_EQ(session->historyRead.call_count(), 0u)
    << "a terminal-state HistoryRead must not touch the tier-0 session";
}

// A tier-0 HistoryRead failure propagates through the funnel to the caller.
TEST_F(ConnectionImplTest, HistoryReadPropagatesFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->historyRead.set_result(Result<ua::HistoryReadResponse>{StatusCode{Status::BadServiceUnsupported}});

  const auto result = history_read_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadServiceUnsupported});
}

// BrowseNext (continue a Browse continuation point) routes through the gated funnel: Active dispatches to
// the session; a terminal state fast-fails Bad_ConnectionClosed without touching the session.
TEST_F(ConnectionImplTest, BrowseNextDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(browse_next_and_wait(*connection).is_good());
  EXPECT_EQ(session->browseNext.call_count(), 1u) << "an Active BrowseNext must dispatch to the session";
}

TEST_F(ConnectionImplTest, BrowseNextFastFailsWhenTerminalWithoutTouchingOps)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  const auto result = browse_next_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConnectionClosed});
  EXPECT_EQ(session->browseNext.call_count(), 0u) << "a terminal-state BrowseNext must not touch the session";
}

// TranslateBrowsePathsToNodeIds routes through the same gated funnel: Active dispatches, failures propagate.
TEST_F(ConnectionImplTest, TranslateBrowsePathsDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(translate_browse_paths_and_wait(*connection).is_good());
  EXPECT_EQ(session->translateBrowsePaths.call_count(), 1u)
    << "an Active TranslateBrowsePaths must dispatch to the session";
}

TEST_F(ConnectionImplTest, TranslateBrowsePathsPropagatesFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{StatusCode{Status::BadServiceUnsupported}});

  const auto result = translate_browse_paths_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadServiceUnsupported});
}

// RegisterNodes routes through the SAME gated invoke_wire_op funnel: Active dispatches to the tier-0 session.
TEST_F(ConnectionImplTest, RegisterNodesDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(register_nodes_and_wait(*connection).is_good());
  EXPECT_EQ(session->registerNodes.call_count(), 1u)
    << "an Active RegisterNodes must dispatch to the session";
}

// A conformant RegisterNodes response has exactly one positional registered id per requested node.
// @verifies CL-VIEW-012
// @relation(CL-VIEW-012, scope=function)
TEST_F(ConnectionImplTest, RegisterNodesRejectsShortAndLongResponseBeforeAliasInstall)
{
  for (const std::size_t returnedCount : {1U, 3U})
  {
    auto session = std::make_shared<FakeSessionOps>();
    session->registerNodes.set_result_fn(
      [returnedCount](const ua::RegisterNodesRequest&) -> ua::Result<ua::RegisterNodesResponse>
      {
        ua::RegisterNodesResponse response;
        for (std::size_t index = 0; index < returnedCount; ++index)
        {
          response.registered_node_ids().push_back(ua::NodeId{9000U + static_cast<std::uint32_t>(index)});
        }
        return ua::Result<ua::RegisterNodesResponse>{std::move(response)};
      });
    auto connection = make_connection(session, std::make_shared<FakeReopen>());
    ASSERT_TRUE(start_and_wait(*connection).is_good());

    auto result = register_nodes_and_wait(*connection, make_numeric_register(100, 2));

    ASSERT_TRUE(result.is_bad()) << "returnedCount=" << returnedCount;
    EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUnexpectedError);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->source, "client.tier1.connection.register_nodes");
    EXPECT_EQ(result.shared_detail()->code, "RegisterNodesResultCountMismatch");
  }
}

// UnregisterNodes routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, UnregisterNodesDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(unregister_nodes_and_wait(*connection).is_good());
  EXPECT_EQ(session->unregisterNodes.call_count(), 1u)
    << "an Active UnregisterNodes must dispatch to the session";
}

// AddNodes routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, AddNodesDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(add_nodes_and_wait(*connection).is_good());
  EXPECT_EQ(session->addNodes.call_count(), 1u) << "an Active AddNodes must dispatch to the session";
}

// AddReferences routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, AddReferencesDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(add_references_and_wait(*connection).is_good());
  EXPECT_EQ(session->addReferences.call_count(), 1u)
    << "an Active AddReferences must dispatch to the session";
}

// DeleteNodes routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, DeleteNodesDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(delete_nodes_and_wait(*connection).is_good());
  EXPECT_EQ(session->deleteNodes.call_count(), 1u) << "an Active DeleteNodes must dispatch to the session";
}

// DeleteReferences routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, DeleteReferencesDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(delete_references_and_wait(*connection).is_good());
  EXPECT_EQ(session->deleteReferences.call_count(), 1u)
    << "an Active DeleteReferences must dispatch to the session";
}

// HistoryUpdate routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, HistoryUpdateDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(history_update_and_wait(*connection).is_good());
  EXPECT_EQ(session->historyUpdate.call_count(), 1u)
    << "an Active HistoryUpdate must dispatch to the session";
}

// SetMonitoringMode routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, SetMonitoringModeDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(set_monitoring_mode_and_wait(*connection).is_good());
  EXPECT_EQ(session->setMonitoringMode.call_count(), 1u)
    << "an Active SetMonitoringMode must dispatch to the session";
}

// ModifyMonitoredItems routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, ModifyMonitoredItemsDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(modify_monitored_items_and_wait(*connection).is_good());
  EXPECT_EQ(session->modifyMonitoredItems.call_count(), 1u)
    << "an Active ModifyMonitoredItems must dispatch to the session";
}

// SetTriggering routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, SetTriggeringDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(set_triggering_and_wait(*connection).is_good());
  EXPECT_EQ(session->setTriggering.call_count(), 1u)
    << "an Active SetTriggering must dispatch to the session";
}

// Cancel routes through the SAME gated invoke_wire_op funnel: Active dispatches; terminal fast-fails.
TEST_F(ConnectionImplTest, CancelDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(cancel_and_wait(*connection).is_good());
  EXPECT_EQ(session->cancel.call_count(), 1u) << "an Active Cancel must dispatch to the session";
}

TEST_F(ConnectionImplTest, CancelFastFailsWhenTerminalWithoutTouchingOps)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  const auto result = cancel_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConnectionClosed});
  EXPECT_EQ(session->cancel.call_count(), 0u) << "a terminal-state Cancel must not touch the session";
}

// QueryFirst routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, QueryFirstDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(query_first_and_wait(*connection).is_good());
  EXPECT_EQ(session->queryFirst.call_count(), 1u) << "an Active QueryFirst must dispatch to the session";
}

// QueryNext routes through the SAME gated invoke_wire_op funnel: Active dispatches to the session.
TEST_F(ConnectionImplTest, QueryNextDispatchesToSessionWhenActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(query_next_and_wait(*connection).is_good());
  EXPECT_EQ(session->queryNext.call_count(), 1u) << "an Active QueryNext must dispatch to the session";
}

// A wire op submitted while Reconnecting is QUEUED (not dispatched, not fast-failed) and flushes on Active.
// @relation(AC-COMP-CL-CONNIMPL-19-B, scope=function)
TEST_F(ConnectionImplTest, WireOpQueuesWhileReconnectingThenFlushesOnActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto readsAfterBootstrap = session->read.call_count();  // 1

  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");

  auto probe = submit_read(*connection);
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(probe->calls.load(), 0) << "a wire op must QUEUE during Reconnecting, not complete";
  EXPECT_EQ(session->read.call_count(), readsAfterBootstrap) << "a queued op must not touch the session yet";

  TA::reconnect_notify_active(*connection);  // flush
  EXPECT_TRUE(probe->future.get().is_good()) << "the queued op flushes and completes on return to Active";
  EXPECT_EQ(session->read.call_count(), readsAfterBootstrap + 1) << "flush dispatched the queued read";

  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");
  const auto readsBeforeOrderedQueue = session->read.call_count();
  const std::vector<ua::NodeId> requestedNodes{ua::NodeId{2, 701u}, ua::NodeId{2, 702u}, ua::NodeId{2, 703u}};
  std::vector<std::shared_ptr<ReadProbe>> ordered;
  for (const auto& nodeId : requestedNodes)
  {
    ua::ReadRequest request;
    ua::ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = ua::utils::to_underlying(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(item));
    ordered.push_back(submit_read(*connection, std::move(request)));
  }
  for (const auto& queued : ordered)
  {
    EXPECT_EQ(queued->future.wait_for(30ms), std::future_status::timeout);
    EXPECT_EQ(queued->calls.load(), 0);
  }
  EXPECT_EQ(session->read.call_count(), readsBeforeOrderedQueue);

  TA::reconnect_notify_active(*connection);
  for (const auto& queued : ordered)
  {
    ASSERT_EQ(queued->future.wait_for(5s), std::future_status::ready);
    EXPECT_TRUE(queued->future.get().is_good());
    EXPECT_EQ(queued->calls.load(), 1);
  }
  const auto received = session->read.requests();
  ASSERT_EQ(received.size(), readsBeforeOrderedQueue + requestedNodes.size());
  for (std::size_t index = 0; index < requestedNodes.size(); ++index)
  {
    const auto& request = received[readsBeforeOrderedQueue + index];
    ASSERT_EQ(request.nodes_to_read().size(), 1u);
    EXPECT_EQ(request.nodes_to_read()[0].node_id(), requestedNodes[index]);
  }
}

// FU-2 (reconnect transparency across a SESSION SWAP): a wire op queued while Reconnecting must, on flush,
// dispatch on the CURRENT (rebound) session - grabbed at dispatch time - not the stale session captured when
// it was enqueued. Critical after a CL-RECONN-003 / #24 recreate that installs a brand-new session interface:
// a queued op bound eagerly to the old (now-dead) session would fail or hit the wrong server-side session.
TEST_F(ConnectionImplTest, WireOpQueuedDuringReconnectFlushesOntoReboundSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto oldSessionReads = session->read.call_count();  // 1 (bootstrap)

  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");

  // Queue a read while Reconnecting.
  auto probe = submit_read(*connection);
  std::this_thread::sleep_for(30ms);
  ASSERT_EQ(probe->calls.load(), 0) << "the op must QUEUE during Reconnecting";

  // Drive a CL-RECONN-003 rebind that SWAPS in a brand-new session interface (commit installs
  // mPendingSession).
  auto* fresh = rebind_to_fresh_session(*connection, *session);
  ASSERT_NE(fresh, nullptr);
  const auto freshReadsBeforeFlush = fresh->read.call_count();

  // Flush: the queued read must dispatch on the NEW session, never the stale one.
  TA::reconnect_notify_active(*connection);
  EXPECT_TRUE(probe->future.get().is_good()) << "the queued op flushes and completes after the session swap";
  EXPECT_EQ(fresh->read.call_count(), freshReadsBeforeFlush + 1)
    << "the flushed op must dispatch on the REBOUND session (grabbed at dispatch time)";
  EXPECT_EQ(session->read.call_count(), oldSessionReads)
    << "the stale (pre-swap) session must NOT receive the flushed op";
}

// A wire op in a terminal state fast-fails Bad_ConnectionClosed WITHOUT touching the session (FU-1).
TEST_F(ConnectionImplTest, WireOpFastFailsWhenTerminalWithoutTouchingOps)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());
  const auto readsBeforeClosedOp = session->read.call_count();

  auto result = read_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConnectionClosed});
  EXPECT_EQ(session->read.call_count(), readsBeforeClosedOp)
    << "a terminal-state wire op must NOT touch the (closed) session (FU-1)";
}

// With queueOnReconnect=false, a wire op during Reconnecting fails fast instead of queueing.
TEST_F(ConnectionImplTest, WireOpFailFastNoQueueWhenConfigured)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.queueOnReconnect = false;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");

  auto result = read_and_wait(*connection);  // must not block/queue - fail fast
  EXPECT_TRUE(result.is_bad()) << "with queueOnReconnect=false a Reconnecting wire op fails fast";
}

// The owed callback fires exactly once on the happy dispatch path.
TEST_F(ConnectionImplTest, WireOpCompletesExactlyOnceOnDispatchGoodPath)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto probe = submit_read(*connection);
  EXPECT_TRUE(probe->future.get().is_good());
  expect_completed_once(probe);
}

// The owed callback fires exactly once on the terminal fast-fail path.
TEST_F(ConnectionImplTest, WireOpCompletesExactlyOnceOnFailurePath)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  auto probe = submit_read(*connection);
  EXPECT_TRUE(probe->future.get().is_bad());
  expect_completed_once(probe);
}

// The bootstrap callback fires exactly once on failure (no double-delivery on the Failed transition).
TEST_F(ConnectionImplTest, BootstrapDeliversExactlyOnceOnFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->read.set_result(ua::Result<ua::ReadResponse>{StatusCode{Status::BadServerNotConnected}});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);

  auto calls = std::make_shared<std::atomic<int>>(0);
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection->start_async(
    [calls, &promise](VoidResult result)
    {
      if (calls->fetch_add(1) == 0)
      {
        promise.set_value(std::move(result));
      }
    });
  EXPECT_TRUE(future.get().is_bad());
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(calls->load(), 1) << "the bootstrap callback must fire exactly once";
}

// The close callback fires exactly once.
TEST_F(ConnectionImplTest, CloseDeliversExactlyOnce)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto calls = std::make_shared<std::atomic<int>>(0);
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection->close_async(
    [calls, &promise](VoidResult result)
    {
      if (calls->fetch_add(1) == 0)
      {
        promise.set_value(std::move(result));
      }
    });
  EXPECT_TRUE(future.get().is_good());
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(calls->load(), 1) << "the close callback must fire exactly once";
}

// ============================================================================================
// Reconnect happy rebind + CL-RECONN-003 (section 8.3, #6)
// ============================================================================================

// A happy rebind keeps the EXISTING session (activated on the fresh channel), not a fresh one.
TEST_F(ConnectionImplTest, ReconnectRebindsExistingSessionOntoFreshChannel)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(run_open(*connection).is_good());
  ASSERT_TRUE(run_activate(*connection).is_good());  // activate-on-existing succeeds (no create-session)
  const auto generationBeforeCommit = TA::browse_session_generation(*connection);
  ASSERT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(session->activateOnChannel.call_count(), 1u)
    << "the existing session was rebound onto the channel";
  EXPECT_EQ(TA::session_ops(*connection).get(), session.get())
    << "a happy rebind keeps the existing session live (no fresh session installed)";
  EXPECT_EQ(TA::browse_session_generation(*connection), generationBeforeCommit)
    << "channel reactivation that preserves the Session must preserve continuation-point validity";
}

// section 3.1 #6 / CL-RECONN-003: Bad_SessionIdInvalid on activate creates + installs a FRESH session.
TEST_F(ConnectionImplTest, ReconnectActivateSessionIdInvalidFallsBackToCreateSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto generationBeforeRebind = TA::browse_session_generation(*connection);
  auto* fresh = rebind_to_fresh_session(*connection, *session);
  ASSERT_NE(fresh, nullptr);
  EXPECT_EQ(TA::session_ops(*connection).get(), static_cast<SessionOps*>(fresh))
    << "the freshly-created session must be installed as the live session (not the invalidated one)";
  EXPECT_NE(TA::session_ops(*connection).get(), session.get());
  EXPECT_EQ(TA::browse_session_generation(*connection), generationBeforeRebind + 1)
    << "installing a fresh Session must invalidate continuation points from the replaced Session";
}

// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST_F(ConnectionImplTest, BrowseNextSessionGateRejectsStaleGenerationBeforeSessionDispatch)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  TA::set_browse_session_generation(*connection, 9);

  ua::BrowseNextRequest request;
  request.continuation_points().push_back(ua::ContinuationPoint{0xCA, 0xFE});
  auto result = browse_next_on_session_and_wait(*connection, 8, std::move(request));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSessionIdInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BrowseCursorSessionChanged");
  EXPECT_EQ(session->browseNext.call_count(), 0u)
    << "the connection-strand gate must not dispatch a stale continuation point to the live Session";
}

// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST_F(ConnectionImplTest, BrowseNextSessionGateDispatchesMatchingGeneration)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  TA::set_browse_session_generation(*connection, 9);

  ua::BrowseNextRequest request;
  request.continuation_points().push_back(ua::ContinuationPoint{0xCA, 0xFE});
  auto result = browse_next_on_session_and_wait(*connection, 9, std::move(request));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(session->browseNext.call_count(), 1u);
  const auto requests = session->browseNext.requests();
  ASSERT_EQ(requests.size(), 1u);
  ASSERT_EQ(requests.front().continuation_points().size(), 1u);
  EXPECT_EQ(requests.front().continuation_points()[0], ua::ContinuationPoint({0xCA, 0xFE}));
}

// ============================================================================================
// MonitoredItem callback deregister-on-failure (section 8.4, #2/#4)
// ============================================================================================

// A transport-level CreateMonitoredItems failure deregisters the optimistically-registered callback.
TEST_F(ConnectionImplTest, CreateMonitoredItemDeregistersCallbackOnServiceFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createMonitoredItems.set_result(
    ua::Result<ua::CreateMonitoredItemsResponse>{StatusCode{Status::BadServerNotConnected}});
  EXPECT_TRUE(create_monitored_item_and_wait(*connection, /*subId=*/1, /*handle=*/5).is_bad());
  wait_until([&] { return monitored_item_count(*connection) == 0; }, "monitored item deregistered");
}

// A bad service_result in the CreateMonitoredItems response also deregisters the callback.
TEST_F(ConnectionImplTest, CreateMonitoredItemDeregistersOnServiceResultBad)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateMonitoredItemsResponse response;
  response.response_header().service_result() = StatusCode{Status::BadTooManyOperations};
  session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});
  EXPECT_TRUE(create_monitored_item_and_wait(*connection, /*subId=*/1, /*handle=*/6).is_bad());
  wait_until([&] { return monitored_item_count(*connection) == 0; }, "monitored item deregistered");
}

// A per-item bad status also deregisters the callback.
TEST_F(ConnectionImplTest, CreateMonitoredItemDeregistersOnPerItemBadStatus)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateMonitoredItemsResponse response;
  ua::MonitoredItemCreateResult item;
  item.status_code() = StatusCode{Status::BadNodeIdUnknown};
  response.results().push_back(std::move(item));
  session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});
  EXPECT_TRUE(create_monitored_item_and_wait(*connection, /*subId=*/1, /*handle=*/7).is_bad());
  wait_until([&] { return monitored_item_count(*connection) == 0; }, "monitored item deregistered");
}

// A CreateMonitoredItems response whose result-count is not exactly one (empty / short / long) for the
// single-item create facade is rejected with Bad_UnexpectedError carrying a source-tagged ErrorDetail, and
// NO item is left attached (CL-MI-005 slot-alignment guard, mirroring the Read facade). Without the guard the
// facade would read results[0] out of an ill-sized array and partially attach. Pins the facade fix directly.
TEST_F(ConnectionImplTest, CreateMonitoredItemRejectsResultCountMismatch)
{
  for (const std::size_t badCount : {std::size_t{0}, std::size_t{2}, std::size_t{3}})
  {
    auto session = std::make_shared<FakeSessionOps>();
    auto reopen = std::make_shared<FakeReopen>();
    auto connection = make_connection(session, reopen);
    ASSERT_TRUE(start_and_wait(*connection).is_good());

    // A service-Good response whose results array has badCount entries (each individually Good) for the
    // single requested item.
    session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{
      make_create_items_response(std::vector<StatusCode>(badCount, StatusCode{Status::Good}))});

    const auto result = create_monitored_item_and_wait(*connection, /*subId=*/1, /*handle=*/8);
    EXPECT_TRUE(result.is_bad()) << "a result-count of " << badCount
                                 << " for a single-item create must be rejected, not read positionally";
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadUnexpectedError})
      << "a slot-alignment mismatch must be Bad_UnexpectedError";
    const auto detail = result.status_code().shared_detail();
    ASSERT_TRUE(detail) << "the mismatch rejection must carry a source-tagged ErrorDetail";
    EXPECT_EQ(detail->source, "client.tier1.connection.create_monitored_item.result_count_mismatch");
    wait_until(
      [&] { return monitored_item_count(*connection) == 0; }, "no item attaches on a result-count mismatch");
  }
}

// A CreateMonitoredItems response whose ResponseHeader.serviceResult is bad is surfaced verbatim to the
// caller and leaves NO item attached (CL-MI-007). Complements
// CreateMonitoredItemDeregistersOnServiceResultBad by asserting the EXACT surfaced code across the
// service-level error family.
// @verifies CL-MI-007
// @relation(CL-MI-007, scope=function)
TEST_F(ConnectionImplTest, CreateMonitoredItemSurfacesServiceResultNoAttach)
{
  for (const Status serviceStatus : {Status::BadTooManyOperations,
         Status::BadNothingToDo,
         Status::BadTimestampsToReturnInvalid,
         Status::BadSubscriptionIdInvalid})
  {
    auto session = std::make_shared<FakeSessionOps>();
    auto reopen = std::make_shared<FakeReopen>();
    auto connection = make_connection(session, reopen);
    ASSERT_TRUE(start_and_wait(*connection).is_good());

    ua::CreateMonitoredItemsResponse response;
    response.response_header().service_result() = StatusCode{serviceStatus};
    session->createMonitoredItems.set_result(
      ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});

    const auto result = create_monitored_item_and_wait(*connection, /*subId=*/1, /*handle=*/9);
    EXPECT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), StatusCode{serviceStatus})
      << "the exact service-level status must reach the caller";
    wait_until(
      [&] { return monitored_item_count(*connection) == 0; }, "no item attaches on a bad serviceResult");
  }
}

// The returned MonitoredItem handle snapshots the server's REVISED sampling interval verbatim (CL-MI-002).
// The server revises the requested interval (here to 250.0), and the handle exposes that value as-is - the
// caller learns the ACTUAL cadence. Drives the owner path (monitor_data_change_async) that builds the handle.
// @verifies CL-MI-002
// @relation(CL-MI-002, scope=function)
TEST_F(ConnectionImplTest, MonitorDataChangeHandleStoresRevisedSamplingInterval)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateMonitoredItemsResponse response;
  ua::MonitoredItemCreateResult item;
  item.status_code() = StatusCode{Status::Good};
  item.monitored_item_id() = 42;
  item.revised_sampling_interval() = 250.0;
  response.results().push_back(std::move(item));
  session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});

  const auto result = monitor_data_change_and_wait(*connection, /*subId=*/1, NodeId{2, 100});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().revised_sampling_interval(), 250.0)
    << "the handle must expose the server's revised sampling interval verbatim";
}

// monitor_data_change_async plumbs every NON-FILTER MonitorRequest tuning field onto the wire
// CreateMonitoredItems, verbatim (CL-MI-009), mirroring the modify path (mi_modify_async). The caller's
// attribute, indexRange, samplingIntervalMs, queueSize, and monitoringMode must all reach the itemToMonitor /
// MonitoringParameters - not the builder's historical hardcoded defaults. (The DataChangeFilter is a
// separate, still-batched piece and is deliberately out of scope here.)
// @verifies CL-MI-009
// @relation(CL-MI-009, scope=function)
TEST_F(ConnectionImplTest, MonitorDataChangePlumbsTuningParamsOntoWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  MonitorRequest request;
  request.nodeId = NodeId{2, 100};
  request.attribute = ua::AttributeId::DisplayName;  // deliberately non-default (default is Value)
  request.indexRange = std::string{"0:5"};
  request.samplingIntervalMs = 123.0;
  request.queueSize = 42;
  request.monitoringMode = ua::MonitoringMode::Sampling;

  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  connection->monitor_data_change_async(
    /*subscriptionId=*/
    1,
    std::move(request),
    [](DataChangeEvent) {},
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto requests = session->createMonitoredItems.requests();
  ASSERT_EQ(requests.size(), 1u) << "exactly one CreateMonitoredItems must reach the wire";
  ASSERT_EQ(requests[0].items_to_create().size(), 1u);
  const auto& item = requests[0].items_to_create()[0];
  EXPECT_EQ(item.item_to_monitor().attribute_id(), static_cast<std::uint32_t>(ua::AttributeId::DisplayName))
    << "MonitorRequest.attribute must reach itemToMonitor.attributeId";
  EXPECT_EQ(static_cast<std::string_view>(item.item_to_monitor().index_range()), "0:5")
    << "MonitorRequest.indexRange must reach itemToMonitor.indexRange verbatim";
  EXPECT_EQ(item.requested_parameters().sampling_interval(), 123.0)
    << "MonitorRequest.samplingIntervalMs must reach MonitoringParameters.samplingInterval";
  EXPECT_EQ(item.requested_parameters().queue_size(), 42u)
    << "MonitorRequest.queueSize must reach MonitoringParameters.queueSize";
  EXPECT_EQ(item.monitoring_mode(), ua::MonitoringMode::Sampling)
    << "MonitorRequest.monitoringMode must reach itemToCreate.monitoringMode";
  EXPECT_TRUE(item.requested_parameters().discard_oldest())
    << "discardOldest stays true (MonitorRequest has no discardOldest field)";
}

// Regression guard for the SHARED create funnel: the id-only create_monitored_item_async path (which carries
// NO MonitorRequest) must still emit the historical DEFAULTS onto the wire (attribute=Value, empty
// index-range, samplingInterval=0.0, queueSize=1, monitoringMode=Reporting). This proves plumbing the
// MonitorRequest tuning through begin_create_monitored_item / build_create_monitored_items_request left the
// id-only wire output byte-for-byte unchanged.
TEST_F(ConnectionImplTest, CreateMonitoredItemIdOnlyEmitsDefaultsOnWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ASSERT_TRUE(
    create_monitored_item_and_wait(*connection, /*subscriptionId=*/7, /*clientHandle=*/5).is_good());

  const auto requests = session->createMonitoredItems.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].subscription_id(), 7u);
  ASSERT_EQ(requests[0].items_to_create().size(), 1u);
  const auto& item = requests[0].items_to_create()[0];
  EXPECT_EQ(item.item_to_monitor().attribute_id(), static_cast<std::uint32_t>(ua::AttributeId::Value))
    << "the id-only path must default the attribute to Value";
  EXPECT_TRUE(static_cast<std::string_view>(item.item_to_monitor().index_range()).empty())
    << "the id-only path must leave the index-range empty";
  EXPECT_EQ(item.requested_parameters().sampling_interval(), 0.0)
    << "the id-only path must default the sampling interval to 0.0";
  EXPECT_EQ(item.requested_parameters().queue_size(), 1u)
    << "the id-only path must default the queue size to 1";
  EXPECT_EQ(item.monitoring_mode(), ua::MonitoringMode::Reporting)
    << "the id-only path must default the monitoring mode to Reporting";
  EXPECT_TRUE(item.requested_parameters().discard_oldest());
}

// @verifies CL-MI-014
// @verifies CL-MI-018
// @relation(CL-MI-014, CL-MI-018, scope=function)
TEST_F(ConnectionImplTest, CreateEventMonitoredItemTargetsEventNotifierAttribute)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateMonitoredItemsResponse response;
  ua::MonitoredItemCreateResult itemResult;
  itemResult.status_code() = StatusCode{Status::Good};
  itemResult.monitored_item_id() = 42;
  auto filterResult = std::make_unique<ua::EventFilterResult>();
  filterResult->select_clause_results().push_back(StatusCode{Status::Good});
  filterResult->select_clause_results().push_back(StatusCode{Status::BadTypeDefinitionInvalid});
  itemResult.filter_result().inner_unique_ptr() = std::move(filterResult);
  response.results().push_back(std::move(itemResult));
  session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});

  const NodeId notifier{ua::ObjectId::Server};
  std::promise<ua::Result<ua::client::detail::EventBackboneCreated>> promise;
  auto future = promise.get_future();
  connection->create_event_monitored_item_async(7,
    notifier,
    11,
    ua::EventFilter{},
    16,
    [&promise](auto result) { promise.set_value(std::move(result)); });
  const auto created = future.get();
  ASSERT_TRUE(created.is_good());
  EXPECT_EQ(created.value().monitoredItemId, 42u);
  ASSERT_EQ(created.value().filterDiagnostics.size(), 1u);
  EXPECT_EQ(
    created.value().filterDiagnostics[0].kind, ua::client::detail::EventFilterDiagnosticKind::SelectClause);
  EXPECT_EQ(created.value().filterDiagnostics[0].index, 1u);
  EXPECT_EQ(created.value().filterDiagnostics[0].status, StatusCode{Status::BadTypeDefinitionInvalid});

  const auto requests = session->createMonitoredItems.requests();
  ASSERT_EQ(requests.size(), 1u);
  ASSERT_EQ(requests[0].items_to_create().size(), 1u);
  const auto& target = requests[0].items_to_create()[0].item_to_monitor();
  EXPECT_EQ(target.node_id(), notifier);
  EXPECT_EQ(target.attribute_id(), static_cast<std::uint32_t>(ua::AttributeId::EventNotifier))
    << "Part 4 section 5.12.2.2 requires event monitoring to target EventNotifier";
}

// A single-item request cannot safely consume an empty or oversized response. The event-specific path must
// fail with a rich, source-tagged ErrorDetail rather than indexing or silently taking results[0].
// @verifies CL-MI-018
// @relation(CL-MI-018, scope=function)
TEST_F(ConnectionImplTest, CreateEventMonitoredItemRejectsResultCountMismatchWithDetail)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateMonitoredItemsResponse response;
  session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});

  std::promise<ua::Result<ua::client::detail::EventBackboneCreated>> promise;
  auto future = promise.get_future();
  connection->create_event_monitored_item_async(7,
    NodeId{ua::ObjectId::Server},
    11,
    ua::EventFilter{},
    16,
    [&promise](auto result) { promise.set_value(std::move(result)); });

  const auto result = future.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUnexpectedError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CreateEventMonitoredItemResultCountMismatch");
  EXPECT_EQ(result.shared_detail()->source,
    "client.tier1.connection.create_event_monitored_item.result_count_mismatch");
}

// A CreateSubscription failure propagates the bad status to the caller.
TEST_F(ConnectionImplTest, CreateSubscriptionPropagatesServiceResultFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    ua::Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadServerNotConnected}});
  EXPECT_TRUE(create_subscription_and_wait(*connection).is_bad());
}

// The public create completion is the operation boundary: once it fires, the returned Subscription must
// already be present in the pipeline registry. Otherwise an immediate follow-up create/modify/delete can
// observe stale local state even though the synchronous wrapper has returned success. This assertion runs
// inside the create callback itself, so it proves ordering without polling or a scheduling deadline.
// @verifies CL-SUB-014
// @relation(CL-SUB-014, scope=function)
TEST_F(ConnectionImplTest, CreateSubscriptionCompletesAfterPipelineRegistration)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    ua::Result<ua::CreateSubscriptionResponse>{make_create_sub_response(41)});

  std::promise<std::pair<Result<std::uint32_t>, std::size_t>> promise;
  auto future = promise.get_future();
  connection->create_subscription_async(200.0,
    [connection, &promise](Result<std::uint32_t> result)
    {
      const auto pipelineInfo = TA::pipeline_info(*connection);
      promise.set_value({std::move(result), pipelineInfo ? pipelineInfo->subscriptionCount : 0});
    });

  auto [result, countAtCompletion] = future.get();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 41u);
  EXPECT_EQ(countAtCompletion, 1u)
    << "successful create completion must not outrun local Subscription registration";
}

// CL-DIAG-005: the managed-subscription create path attaches the always-on wire-crossing marker on a bad
// serviceResult (Case-2: good transport, bad ResponseHeader.serviceResult), not just the general wire funnel.
// RED before wiring: begin_create_subscription forwards the bare serviceResult (no ErrorDetail on the
// Result).
// @verifies CL-DIAG-005
// @relation(CL-DIAG-005, scope=function)
TEST_F(ConnectionImplTest, CreateSubscriptionAttachesWireMarkerOnBadServiceResult)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateSubscriptionResponse response;
  response.response_header().service_result() = StatusCode{Status::BadTooManyOperations};
  session->createSubscription.set_result(ua::Result<ua::CreateSubscriptionResponse>{std::move(response)});

  const auto result = create_subscription_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "a bad create-subscription serviceResult must carry the wire marker";
  EXPECT_EQ(detail->source, "client.tier0.session.decode_diagnostic");
}

// ============================================================================================
// Close ordering (section 8.2A.3)
// ============================================================================================

// Close closes the tier-0 session and reaches the Closed terminal state.
TEST_F(ConnectionImplTest, CloseClosesSessionAndReachesClosed)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  EXPECT_EQ(session->close.call_count(), 1u) << "close must close the tier-0 session";
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);
}

// A wire op queued during Reconnecting is drained Bad when the Connection is closed mid-outage.
TEST_F(ConnectionImplTest, CloseWhileReconnectingDrainsQueuedOp)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");
  auto probe = submit_read(*connection);  // queued
  std::this_thread::sleep_for(20ms);
  ASSERT_EQ(probe->calls.load(), 0);

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  EXPECT_TRUE(probe->future.get().is_bad()) << "a queued op must drain Bad when the Connection closes";
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);
}

// ============================================================================================
// Subscription / monitored-item lifecycle - delete (section 8.4, CL-SUB-008 / CL-MI-008)
// ============================================================================================

// Deleting a Subscription deregisters it from the pipeline on service success.
TEST_F(ConnectionImplTest, DeleteSubscriptionDeregistersOnSuccess)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  wait_until([&] { return subscription_count(*connection) == 1; }, "subscription registered");

  EXPECT_TRUE(delete_subscription_and_wait(*connection, subscriptionId).is_good());
  EXPECT_EQ(session->deleteSubscriptions.call_count(), 1u) << "DeleteSubscriptions must reach the session";
  wait_until([&] { return subscription_count(*connection) == 0; }, "subscription deregistered");
}

// A DeleteSubscriptions whose service_result is bad leaves the Subscription tracked (still alive
// server-side).
TEST_F(ConnectionImplTest, DeleteSubscriptionKeepsTrackingOnServiceFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  wait_until([&] { return subscription_count(*connection) == 1; }, "subscription registered");

  ua::DeleteSubscriptionsResponse response;
  response.response_header().service_result() = StatusCode{Status::BadTooManyOperations};
  session->deleteSubscriptions.set_result(ua::Result<ua::DeleteSubscriptionsResponse>{std::move(response)});
  delete_subscription_and_wait(*connection, subscriptionId);
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(subscription_count(*connection), 1u)
    << "a failed DeleteSubscriptions must not deregister the (still-alive) Subscription";
}

// CL-SUB-013: a ModifySubscription whose service_result is Bad_SubscriptionIdInvalid means the Subscription
// is gone server-side (deleted / lifetime-expired) - drop the stale local record (no retry), mirroring
// DeleteSubscription's deregister-on-terminal, so its sequence tracking + acks + owner routing stop.
// @verifies CL-SUB-013
// @relation(CL-SUB-013, scope=function)
TEST_F(ConnectionImplTest, ModifySubscriptionDropsRecordOnBadSubscriptionIdInvalid)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  wait_until([&] { return subscription_count(*connection) == 1; }, "subscription registered");

  ua::ModifySubscriptionResponse response;
  response.response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
  session->modifySubscription.set_result(ua::Result<ua::ModifySubscriptionResponse>{std::move(response)});
  modify_subscription_and_wait(*connection, subscriptionId, /*publishingInterval=*/200.0);
  wait_until([&] { return subscription_count(*connection) == 0; },
    "Bad_SubscriptionIdInvalid must drop the stale local Subscription record");
}

// CL-SUB-013: a TRANSIENT ModifySubscription failure (e.g. Bad_TooManyOperations / connection) leaves the
// Subscription tracked - it may still be alive server-side; only the authoritative Bad_SubscriptionIdInvalid
// is a definitive "gone". No retry either way.
// @verifies CL-SUB-013
// @relation(CL-SUB-013, scope=function)
TEST_F(ConnectionImplTest, ModifySubscriptionKeepsRecordOnTransientFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  wait_until([&] { return subscription_count(*connection) == 1; }, "subscription registered");

  ua::ModifySubscriptionResponse response;
  response.response_header().service_result() = StatusCode{Status::BadTooManyOperations};
  session->modifySubscription.set_result(ua::Result<ua::ModifySubscriptionResponse>{std::move(response)});
  modify_subscription_and_wait(*connection, subscriptionId, /*publishingInterval=*/200.0);
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(subscription_count(*connection), 1u)
    << "a transient ModifySubscription failure must not deregister the (possibly still-alive) Subscription";
}

// CL-SUB-012: a SUCCESSFUL ModifySubscription refreshes the pipeline's RETAINED publishing interval, so a
// session-CHANGED recreate replays the modified interval rather than the stale create-time one (otherwise the
// reconnect silently reverts the user's modify). Surfaced by the CL-SUB-013 section 3.1 review as the
// adjacent gap.
// @verifies CL-SUB-012
// @relation(CL-SUB-012, scope=function)
TEST_F(ConnectionImplTest, ModifySubscriptionRefreshesRetainedIntervalForRecreate)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId =
    create_subscription_and_wait(*connection, /*publishingInterval=*/500.0).value();
  wait_until([&] { return subscription_count(*connection) == 1; }, "subscription registered");
  ASSERT_EQ(retained_interval_for(*connection, subscriptionId), std::optional<double>{500.0})
    << "the create-time interval is retained for recreate";

  // A default (good) ModifySubscription to 200ms.
  EXPECT_TRUE(
    modify_subscription_and_wait(*connection, subscriptionId, /*publishingInterval=*/200.0).is_good());

  EXPECT_EQ(retained_interval_for(*connection, subscriptionId), std::optional<double>{200.0})
    << "a successful modify must refresh the retained interval (else a session-CHANGED recreate reverts to "
       "500)";
}

// Deleting a monitored item deregisters its client handle from the pipeline on service success.
TEST_F(ConnectionImplTest, DeleteMonitoredItemDeregistersOnSuccess)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  ASSERT_TRUE(create_monitored_item_and_wait(*connection, subscriptionId, /*handle=*/9).is_good());
  wait_until([&] { return monitored_item_count(*connection) == 1; }, "monitored item registered");

  ua::DeleteMonitoredItemsResponse deleteResponse;  // one Good result for the one item deleted
  deleteResponse.results().push_back(StatusCode{Status::Good});
  session->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{std::move(deleteResponse)});
  EXPECT_TRUE(
    delete_monitored_item_and_wait(*connection, subscriptionId, /*monitoredItemId=*/500, /*handle=*/9)
      .is_good());
  EXPECT_EQ(session->deleteMonitoredItems.call_count(), 1u) << "DeleteMonitoredItems must reach the session";
  wait_until([&] { return monitored_item_count(*connection) == 0; }, "monitored item deregistered");
}

// A DeleteMonitoredItems answered with a Good ServiceResult and a Bad item status has not deleted the item:
// its client handle stays registered, as the MonitoredItem handle's owner keeps the item, and the response
// reaches the caller with the item's code.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ConnectionImplTest, DeleteMonitoredItemKeepsTheHandleRegisteredOnABadItemStatus)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  ASSERT_TRUE(create_monitored_item_and_wait(*connection, subscriptionId, /*handle=*/9).is_good());
  wait_until([&] { return monitored_item_count(*connection) == 1; }, "monitored item registered");

  ua::DeleteMonitoredItemsResponse deleteResponse;  // ServiceResult Good, the item's status Bad
  deleteResponse.results().push_back(StatusCode{Status::BadMonitoredItemIdInvalid});
  session->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{std::move(deleteResponse)});
  const auto result =
    delete_monitored_item_and_wait(*connection, subscriptionId, /*monitoredItemId=*/500, /*handle=*/9);
  ASSERT_TRUE(result.is_good()) << "the ServiceResult is Good: the item's code is carried in the response";
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0].as_status(), Status::BadMonitoredItemIdInvalid);
  EXPECT_EQ(monitored_item_count(*connection), 1u)
    << "an item the server did not delete keeps its notification routing";
}

// section 3.1 finding: deleting a Subscription must cascade-deregister ITS monitored items from the pipeline
// (a subscription delete implicitly deletes its items server-side) - not leak their callbacks.
TEST_F(ConnectionImplTest, DeleteSubscriptionCascadesToMonitoredItems)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::uint32_t subscriptionId = create_subscription_and_wait(*connection).value();
  ASSERT_TRUE(create_monitored_item_and_wait(*connection, subscriptionId, /*handle=*/5).is_good());
  ASSERT_TRUE(create_monitored_item_and_wait(*connection, subscriptionId, /*handle=*/6).is_good());
  wait_until([&] { return monitored_item_count(*connection) == 2; }, "two monitored items registered");

  EXPECT_TRUE(delete_subscription_and_wait(*connection, subscriptionId).is_good());
  wait_until([&] { return monitored_item_count(*connection) == 0; },
    "deleting the subscription cascades to remove its monitored items");
}

// A delete op in a terminal state fast-fails without touching the session.
TEST_F(ConnectionImplTest, DeleteSubscriptionFastFailsWhenTerminal)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  auto result = delete_subscription_and_wait(*connection, /*subscriptionId=*/1);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(session->deleteSubscriptions.call_count(), 0u)
    << "a terminal-state delete must not touch the (closed) session";
}

// ============================================================================================
// Subscription lifecycle - modify + set publishing mode (section 8.4, CL-SUB-011 / CL-SUB-010)
// ============================================================================================

// ModifySubscription dispatches to the session when Active.
TEST_F(ConnectionImplTest, ModifySubscriptionDispatchesToSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  EXPECT_TRUE(modify_subscription_and_wait(*connection, /*subscriptionId=*/7, /*interval=*/200.0).is_good());
  EXPECT_EQ(session->modifySubscription.call_count(), 1u) << "ModifySubscription must reach the session";
}

// SetPublishingMode dispatches to the session when Active.
TEST_F(ConnectionImplTest, SetPublishingModeDispatchesToSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  EXPECT_TRUE(set_publishing_mode_and_wait(*connection, /*subscriptionId=*/7, /*enabled=*/false).is_good());
  EXPECT_EQ(session->setPublishingMode.call_count(), 1u) << "SetPublishingMode must reach the session";
}

// ModifySubscription fast-fails in a terminal state without touching the session.
TEST_F(ConnectionImplTest, ModifySubscriptionFastFailsWhenTerminal)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());

  EXPECT_TRUE(modify_subscription_and_wait(*connection, /*subscriptionId=*/7, /*interval=*/200.0).is_bad());
  EXPECT_EQ(session->modifySubscription.call_count(), 0u)
    << "a terminal-state modify must not touch the (closed) session";
}

// SetPublishingMode propagates a bad transport result to the caller.
TEST_F(ConnectionImplTest, SetPublishingModePropagatesFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->setPublishingMode.set_result(
    ua::Result<ua::SetPublishingModeResponse>{StatusCode{Status::BadServerNotConnected}});
  EXPECT_TRUE(set_publishing_mode_and_wait(*connection, /*subscriptionId=*/7, /*enabled=*/true).is_bad());
}

// ============================================================================================
// Automatic transport-drop detection (section 8.3, CL-RECONN-001): a channel/session-fatal Publish result
// auto-drives the reconnect FSM. Non-fatal results and terminal states do not.
// ============================================================================================

// The channel-fatal classifier is the gate for automatic drop detection. Pin every fatal code -> true
// and a representative set of Good / transient / lifecycle codes -> false (exhaustive over the policy,
// deterministic - no async timing). This is the falsifiable heart of NonFatalPublishResultDoesNotReconnect.
TEST(ConnectionImplDropClassification, IsChannelFatalCoversEveryFatalCode)
{
  using ua::client::detail::is_channel_fatal;
  for (auto status : {Status::BadSecureChannelClosed,
         Status::BadSecureChannelIdInvalid,
         Status::BadServerNotConnected,
         Status::BadConnectionClosed,
         Status::BadCommunicationError,
         Status::BadServerHalted,
         Status::BadTcpInternalError,
         Status::BadNotConnected,
         Status::BadDisconnect,
         Status::BadSessionIdInvalid,
         Status::BadSessionClosed,
         Status::BadSessionNotActivated})
  {
    EXPECT_TRUE(is_channel_fatal(StatusCode{status}))
      << "status " << StatusCode{status}.as_uint32() << " must be treated as a transport drop";
  }
}

TEST(ConnectionImplDropClassification, IsChannelFatalExcludesTransientAndLifecycle)
{
  using ua::client::detail::is_channel_fatal;
  for (auto status : {Status::Good,
         Status::BadTimeout,
         Status::BadTooManyPublishRequests,
         Status::BadNoSubscription,
         Status::BadNodeIdUnknown,
         Status::BadInternalError,
         Status::BadServiceUnsupported})
  {
    EXPECT_FALSE(is_channel_fatal(StatusCode{status}))
      << "status " << StatusCode{status}.as_uint32() << " must NOT be treated as a transport drop";
  }
}

// A channel-fatal drop notification on an Active connection drives the FSM to reopen a channel.
TEST_F(ConnectionImplTest, TransportDropTriggersReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the reopen so we can observe the FSM reached the open-channel step
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  TA::notify_transport_drop(*connection, StatusCode{Status::BadSecureChannelClosed});
  wait_for_reopen_pending(*reopen, 1);  // ASSERT_GE inside: the drop drove the FSM to reopen a channel
}

// A drop notification after close is a terminal-state no-op (no reconnect).
TEST_F(ConnectionImplTest, TransportDropAfterCloseDoesNotReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(close_and_wait(*connection).is_good());

  const auto reopensBefore = reopen->call_count();
  TA::notify_transport_drop(*connection, StatusCode{Status::BadSecureChannelClosed});
  // The notify posts to the connection strand; a strand-hopped snapshot is a FIFO ordering barrier that
  // guarantees the (guarded) notify handler has run before we read the reopen count.
  auto snapshot = TA::snapshot(*connection);
  EXPECT_EQ(snapshot.state, ConnectionState::Closed);
  EXPECT_EQ(reopen->call_count(), reopensBefore) << "a drop after close must not start a reconnect";
}

// ============================================================================================
// KeepAlive poll (section 8.2A.6, CL-RECONN-009 / CL-SESS-025) - the independent liveness signal a
// subscription-less Connection needs (no Publishes to carry a drop). Driven deterministically via the
// run_keep_alive_poll interface (each call issues ONE poll read; a strand-hopped snapshot barriers its
// completion, which clears the in-flight guard so the next poll can issue).
// ============================================================================================

// N consecutive missed keep-alive polls (the read fails) trigger a KeepAliveMissed reconnect.
// @verifies CL-RECONN-009
// @relation(CL-RECONN-009, scope=function)
TEST_F(ConnectionImplTest, KeepAliveConsecutiveMissedPollsTriggerReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the reopen so we can observe the FSM reached the open-channel step
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());  // bootstrap read succeeds; the keep-alive timer arms
  ASSERT_TRUE(TA::keep_alive_timer_armed(*connection)) << "keep-alive must arm on reaching Active";

  // Every subsequent (keep-alive) read fails: three consecutive misses reach the threshold.
  session->read.set_result(Result<ua::ReadResponse>{StatusCode{Status::BadConnectionClosed}});
  for (int poll = 0; poll < 3; ++poll)
  {
    TA::run_keep_alive_poll(*connection);
    TA::snapshot(*connection);  // barrier: the poll's completion (miss accounting) has settled
  }

  wait_for_reopen_pending(*reopen, 1);  // the third miss drove the FSM to reopen a channel
}

// A successful poll RESETS the consecutive-miss count, so misses below the threshold never trigger.
TEST_F(ConnectionImplTest, KeepAliveGoodPollResetsMissCount)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto pollWith = [&](Result<ua::ReadResponse> scripted)
  {
    session->read.set_result(std::move(scripted));
    TA::run_keep_alive_poll(*connection);
    TA::snapshot(*connection);
  };

  pollWith(Result<ua::ReadResponse>{StatusCode{Status::BadConnectionClosed}});  // miss 1
  pollWith(Result<ua::ReadResponse>{StatusCode{Status::BadConnectionClosed}});  // miss 2
  pollWith(Result<ua::ReadResponse>{make_server_state_response(ua::ServerState::Running)});  // good -> reset
  pollWith(Result<ua::ReadResponse>{StatusCode{Status::BadConnectionClosed}});  // miss 1 (post-reset)
  pollWith(Result<ua::ReadResponse>{StatusCode{Status::BadConnectionClosed}});  // miss 2 (still < 3)

  std::this_thread::sleep_for(30ms);  // give any erroneous trigger time to reach the reopen
  EXPECT_EQ(reopen->call_count(), 0u) << "a good poll must reset the miss count; 2 < 3 must NOT reconnect";
}

// CL-SESS-007 (Part 4 section 5.6.2 lines 2187-2188): the client is prepared to, and does, SUBMIT requests
// in a timely manner to prevent the Session from closing automatically. Its realization is the
// ConnectionImpl keep-alive: a periodic timer (armed on Active) whose every poll issues a lightweight
// Read on the session. This drives run_keep_alive_poll and asserts the session read op is invoked
// exactly once per poll - the proactive submission. Falsifiable: a client that armed the timer but
// submitted no request (or a watchdog that only closes on timeout) would leave read.call_count()
// unchanged across the polls.
// @verifies CL-SESS-007 (scope: verifies the client SUBMITS one keep-alive Read per poll and that the
// periodic timer is armed on Active; the poll-INTERVAL derivation from the revised session timeout is
// CL-SESS-020's obligation, not asserted here).
// @relation(CL-SESS-007, scope=function)
TEST_F(ConnectionImplTest, KeepAlivePollSubmitsAReadRequestPerPoll)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(TA::keep_alive_timer_armed(*connection)) << "keep-alive must arm on reaching Active";

  const auto baseline = session->read.call_count();  // the bootstrap read(s), before any keep-alive poll

  // Each poll returns a healthy ServerState so no reconnect fires; we observe only the submission.
  session->read.set_result(Result<ua::ReadResponse>{make_server_state_response(ua::ServerState::Running)});
  const std::size_t polls = 3;
  for (std::size_t i = 0; i < polls; ++i)
  {
    TA::run_keep_alive_poll(*connection);
    TA::snapshot(*connection);  // barrier: the poll's read has been issued and settled
  }

  EXPECT_EQ(session->read.call_count(), baseline + polls)
    << "each keep-alive poll must submit exactly one keep-alive Read to keep the session alive";
  EXPECT_EQ(reopen->call_count(), 0u) << "healthy keep-alive polls must not trigger a reconnect";

  // The loop above completes each poll before the next tick, so it never reaches the in-flight guard the
  // header states: "only ONE poll is in flight at a time (a slow read counts as its own interval)". Holding
  // the read is what puts a second tick against an outstanding first (section 2.4 rule 4: the observable was
  // right and the assertion under-specified, so the arm is extended).
  const auto beforeHeld = session->read.call_count();
  session->read.set_hold(true);
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);
  ASSERT_EQ(session->read.call_count(), beforeHeld + 1u) << "the held poll must have issued its read";
  ASSERT_TRUE(TA::keep_alive_poll_in_flight(*connection));

  TA::run_keep_alive_poll(*connection);  // the next tick, while the first read is still outstanding
  TA::snapshot(*connection);
  EXPECT_EQ(session->read.call_count(), beforeHeld + 1u)
    << "a tick arriving while a poll is outstanding must not stack a second read";

  session->read.set_hold(false);
  session->read.fire_next(
    Result<ua::ReadResponse>{make_server_state_response(ua::ServerState::Running)});  // release the guard
}

// CL-BASE-005: the liveness observation must fetch all three values atomically enough for the final
// responsive answer to govern reconnect pacing. Falsifiable: omitting either ServiceLevel or
// EstimatedReturnTime leaves no production path for the corresponding maintenance hint.
// @verifies CL-BASE-005
// @relation(CL-BASE-005, scope=function)
TEST_F(ConnectionImplTest, KeepAlivePollReadsStateServiceLevelAndEstimatedReturnTime)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->read.set_result(Result<ua::ReadResponse>{
    make_server_hint_response(ua::ServerState::Running, /*serviceLevel=*/255, std::nullopt)});
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);

  const auto requests = session->read.requests();
  ASSERT_FALSE(requests.empty());
  const auto& request = requests.back();
  ASSERT_EQ(request.nodes_to_read().size(), 3u);
  EXPECT_EQ(request.nodes_to_read()[0].node_id(), ua::NodeId{ua::VariableId::Server_ServerStatus_State});
  EXPECT_EQ(request.nodes_to_read()[1].node_id(), ua::NodeId{ua::VariableId::Server_ServiceLevel});
  EXPECT_EQ(request.nodes_to_read()[2].node_id(), ua::NodeId{ua::VariableId::Server_EstimatedReturnTime});
}

// ServiceLevel zero is Maintenance even while ServerStatus.State still reads Running. A future
// EstimatedReturnTime must hold the first reconnect attempt in the existing FSM deferred state.
// @verifies CL-BASE-005
// @verifies CL-SESS-025
// @relation(CL-BASE-005, CL-SESS-025, scope=function)
TEST_F(ConnectionImplTest, KeepAliveMaintenanceDefersUntilFutureEstimatedReturnTime)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->read.set_result(Result<ua::ReadResponse>{make_server_hint_response(
    ua::ServerState::Running, /*serviceLevel=*/0, future_datetime(std::chrono::hours{1}))});
  TA::run_keep_alive_poll(*connection);
  wait_until(
    [&]
    {
      const auto info = TA::reconnect_fsm_info(*connection);
      return info && info->state == ReconnectFsmState::ShutdownDeferred;
    },
    "future EstimatedReturnTime to enter ShutdownDeferred");

  EXPECT_EQ(reopen->call_count(), 0u) << "no channel reopen may occur before the future return time";
}

// The Connection decides its reconnect pacing on the keep-alive's ServerState and ServiceLevel values itself,
// so a value whose own status is Uncertain counts as absent, as a Bad one does: an Uncertain Shutdown state
// and an Uncertain ServiceLevel of 0 start no maintenance deferral, and the responsive Server stays
// connected. The poll's decision is read from its Info record ("server reported shutdown/maintenance"), which
// the poll's completion writes before the snapshot below runs; the deferral itself is posted after it.
// @verifies CL-BASE-005
// @relation(CL-BASE-005, AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST_F(ConnectionImplTest, KeepAliveUncertainMaintenanceHintIsNotUsed)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  ua::test::TestLogSink log;
  auto connection = TA::create_with_ops(mRuntime.executor(),
    session,
    ConnectionConfig{},
    log.logger(),
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    keep_alive_enabled(/*missedBeforeReconnect=*/1));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  TA::snapshot(*connection);
  const std::size_t infoBefore = log.count(ua::LogLevel::Info);

  auto response = make_server_hint_response(
    ua::ServerState::Shutdown, /*serviceLevel=*/0, future_datetime(std::chrono::hours{1}));
  response.results()[0].status() = ua::StatusCode{ua::Status::UncertainInitialValue};
  response.results()[1].status() = ua::StatusCode{ua::Status::UncertainInitialValue};
  session->read.set_result(Result<ua::ReadResponse>{std::move(response)});
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);

  EXPECT_EQ(log.count(ua::LogLevel::Info), infoBefore)
    << "an Uncertain maintenance hint must not trigger a paced ServerShutdown reconnect";
  const auto info = TA::reconnect_fsm_info(*connection);
  EXPECT_FALSE(info && info->state == ReconnectFsmState::ShutdownDeferred)
    << "an Uncertain maintenance hint must not defer a reconnect";
  EXPECT_EQ(reopen->call_count(), 0u);
}

// An elapsed optional hint cannot defer into the past. It falls back to the shutdown slow-retry path:
// one immediate attempt, with any failed subsequent attempts multiplied by shutdownBackoffMultiplier.
// @verifies CL-BASE-005
// @relation(CL-BASE-005, scope=function)
TEST_F(ConnectionImplTest, KeepAliveMaintenanceWithElapsedHintStartsSlowRetryImmediately)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->read.set_result(Result<ua::ReadResponse>{
    make_server_hint_response(ua::ServerState::Running, /*serviceLevel=*/0, ua::DateTime{})});
  TA::run_keep_alive_poll(*connection);

  wait_for_reopen_pending(*reopen, 1);
}

// Optional model defects are fail-open for liveness and pacing: without shutdown/maintenance, an invalid
// EstimatedReturnTime cannot manufacture a reconnect.
// @verifies CL-BASE-005
// @relation(CL-BASE-005, scope=function)
TEST_F(ConnectionImplTest, KeepAliveInvalidOptionalHintDoesNotManufactureMaintenance)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/1));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::ReadResponse response =
    make_server_hint_response(ua::ServerState::Running, /*serviceLevel=*/255, std::nullopt);
  response.results().push_back(ua::DataValue{ua::Variant{ua::String{"not-a-DateTime"}}});
  session->read.set_result(Result<ua::ReadResponse>{std::move(response)});
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);

  EXPECT_EQ(reopen->call_count(), 0u);
}

// @verifies CL-SESS-020
// The keep-alive poll interval is bounded by the server's REVISED session timeout so the client polls at
// least (missedBeforeReconnect + 1) times before the Session auto-closes: effective =
// min(configured, revisedTimeout / (missed + 1)). Falsifiable: a client that ignored the revised timeout
// would keep the longer configured interval and let a short-timeout session expire.
// @relation(CL-SESS-020, scope=function)
TEST_F(ConnectionImplTest, RevisedTimeoutBoundsKeepAliveInterval)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  session->set_revised_session_timeout_ms(60000.0);  // 60 s revised
  auto connection = make_connection(
    session, reopen, {}, KeepAlivePolicy{std::chrono::milliseconds{30000}, /*missedBeforeReconnect=*/2});
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  // 60000 / (2 + 1) = 20000 ms < the 30000 ms configured interval -> the bound wins.
  EXPECT_EQ(TA::effective_keep_alive_interval(*connection), std::chrono::milliseconds{20000});
}

// @verifies CL-SESS-020
// A long revised timeout must NOT starve the cadence below the configured interval: min() keeps the
// configured value when the revised-timeout bound is larger.
// @relation(CL-SESS-020, scope=function)
TEST_F(ConnectionImplTest, LongRevisedTimeoutKeepsConfiguredKeepAliveInterval)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  session->set_revised_session_timeout_ms(600000.0);  // 10 min -> bound 200 s >> 30 s configured
  auto connection = make_connection(
    session, reopen, {}, KeepAlivePolicy{std::chrono::milliseconds{30000}, /*missedBeforeReconnect=*/2});
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_EQ(TA::effective_keep_alive_interval(*connection), std::chrono::milliseconds{30000});
}

// @verifies CL-SESS-020
// A pathologically short revised timeout (sub-50 ms bound) is clamped to the 50 ms floor rather than
// arming a busy-poll.
// @relation(CL-SESS-020, scope=function)
TEST_F(ConnectionImplTest, PathologicalRevisedTimeoutClampsKeepAliveToFloor)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  session->set_revised_session_timeout_ms(100.0);  // 100 / 3 = 33 ms < 50 ms floor
  auto connection = make_connection(
    session, reopen, {}, KeepAlivePolicy{std::chrono::milliseconds{30000}, /*missedBeforeReconnect=*/2});
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_EQ(TA::effective_keep_alive_interval(*connection), std::chrono::milliseconds{50});
}

// A poll that reads ServerState::Shutdown triggers a ServerShutdown reconnect.
// @verifies CL-SESS-025
// @relation(CL-SESS-025, scope=function)
TEST_F(ConnectionImplTest, KeepAliveShutdownStateTriggersReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->read.set_result(Result<ua::ReadResponse>{make_server_state_response(ua::ServerState::Shutdown)});
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);

  wait_for_reopen_pending(*reopen, 1);  // a single Shutdown poll drives a ServerShutdown reconnect
}

// interval <= 0 disables the keep-alive: the timer never arms.
TEST_F(ConnectionImplTest, KeepAliveDisabledNeverArmsTimer)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, {}, keep_alive_disabled());
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  EXPECT_FALSE(TA::keep_alive_timer_armed(*connection))
    << "a keep-alive interval <= 0 must never arm the poll timer (opt-out)";
}

// The keep-alive timer arms on Active and disarms on close (no poll can fire after close).
TEST_F(ConnectionImplTest, KeepAliveTimerArmsOnActiveAndDisarmsOnClose)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(TA::keep_alive_timer_armed(*connection)) << "the keep-alive timer must be armed while Active";

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  EXPECT_FALSE(TA::keep_alive_timer_armed(*connection)) << "close must disarm the keep-alive timer";
}

// The keep-alive timer follows the reconnect cycle: it DISARMS on entering Reconnecting (no poll during the
// outage - a poll would race the session swap) and RE-ARMS on returning to Active (fresh miss count on the
// rebound session). Pins the disarm-on-reconnecting / re-arm-on-active transitions the reconnect path adds.
TEST_F(ConnectionImplTest, KeepAliveDisarmsOnReconnectingAndRearmsOnActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(TA::keep_alive_timer_armed(*connection)) << "armed on reaching Active";

  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");
  EXPECT_FALSE(TA::keep_alive_timer_armed(*connection)) << "entering Reconnecting must disarm the keep-alive";

  TA::reconnect_notify_active(*connection);
  wait_until([&] { return TA::snapshot(*connection).state == ConnectionState::Active; }, "Active");
  EXPECT_TRUE(TA::keep_alive_timer_armed(*connection)) << "returning to Active must re-arm the keep-alive";
}

// A poll that SUCCEEDS but carries no usable ServerState (empty / non-Int32 value) is a healthy poll, not a
// shutdown and not a miss: the server answered, so the miss count resets and nothing is triggered. Guards
// keep_alive_read_reports_shutdown against a malformed response.
TEST_F(ConnectionImplTest, KeepAliveMalformedStateReadTreatedAsHealthyPoll)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/1));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // A good Read whose single result carries no Int32 State (an empty results array) - must not crash, must
  // not be read as Shutdown, and must be treated as a successful (healthy) poll.
  session->read.set_result(Result<ua::ReadResponse>{ua::ReadResponse{}});
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);

  std::this_thread::sleep_for(20ms);
  EXPECT_EQ(reopen->call_count(), 0u)
    << "a good poll with an unusable ServerState value must be healthy, not a miss or a shutdown";
}

// section 3.1 (keep-alive review, HIGH): a STALE (superseded-attempt) poll completion must be epoch-dropped
// BEFORE the in-flight guard is released - otherwise it clears a LIVE (current-epoch) poll's guard and lets a
// second poll stack. Falsifier: with the clear-before-epoch-guard ordering, poll_in_flight would read false
// after the stale completion.
TEST_F(ConnectionImplTest, KeepAliveStalePollCompletionDoesNotClearLiveGuard)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/3));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Park the keep-alive read so its completion can be fired AFTER the epoch moves on.
  session->read.set_hold(true);
  TA::run_keep_alive_poll(*connection);  // issues the poll read (epoch N), parked; the in-flight guard is set
  wait_until([&] { return session->read.pending_count() >= 1; }, "the keep-alive poll read to be issued");
  ASSERT_TRUE(TA::keep_alive_poll_in_flight(*connection));

  // Supersede the poll's attempt: an open-channel step bumps the attempt epoch (park the reopen so the state
  // stays Active and no reconnect churns the fixture).
  reopen->set_hold(true);
  const auto epochBefore = TA::snapshot(*connection).reconnectAttemptEpoch;
  TA::reconnect_open_secure_channel(*connection, [](VoidResult) {});
  wait_for_reopen_pending(*reopen, 1);
  ASSERT_GT(TA::snapshot(*connection).reconnectAttemptEpoch, epochBefore);

  // The stale poll read now completes (a miss under the OLD epoch). It must be dropped WITHOUT clearing the
  // in-flight guard.
  session->read.fire_next(Result<ua::ReadResponse>{StatusCode{Status::BadConnectionClosed}});
  TA::snapshot(*connection);  // barrier on finish_keep_alive_poll having run
  EXPECT_TRUE(TA::keep_alive_poll_in_flight(*connection))
    << "a stale poll completion must be epoch-dropped BEFORE releasing the guard (no poll stacking)";
}

// section 3.1 (keep-alive review, MEDIUM): a poll that gets a WELL-FORMED response with a NON-fatal service
// error (e.g. Bad_ServerTooBusy under load) means the server ANSWERED - it is alive - so it is a healthy
// poll, not a miss. Only a transport-bad Result (no response) or a channel/session-fatal service_result is a
// miss. Falsifier: with "any bad effective status is a miss", missedBeforeReconnect=1 would reconnect a live
// server.
TEST_F(ConnectionImplTest, KeepAliveBusyServerErrorPollTreatedAsAlive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto connection = make_connection(session, reopen, {}, keep_alive_enabled(/*missedBeforeReconnect=*/1));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // A well-formed response whose service_result is a NON-fatal error: the server is alive and answering.
  ua::ReadResponse busy;
  busy.response_header().service_result() = StatusCode{Status::BadServerTooBusy};
  session->read.set_result(Result<ua::ReadResponse>{std::move(busy)});
  TA::run_keep_alive_poll(*connection);
  TA::snapshot(*connection);

  std::this_thread::sleep_for(20ms);
  EXPECT_EQ(reopen->call_count(), 0u)
    << "a live-but-busy server (good transport, non-fatal service error) must not be counted as a dead-link "
       "miss";
}

// End-to-end: a channel-fatal Publish result from the pump auto-triggers a reconnect (the real wiring:
// publish callback -> is_channel_fatal -> notify_transport_drop_async -> FSM).
TEST_F(ConnectionImplTest, FatalPublishResultTriggersReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  session->publish.set_hold(true);  // park the pump's Publish so we deliver exactly one fatal result
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());

  // The pump issues a Publish once a subscription exists; complete it with a channel-fatal result.
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{StatusCode{Status::BadSecureChannelClosed}});

  wait_for_reopen_pending(*reopen, 1);  // the fatal Publish auto-triggered a reconnect
}

// End-to-end negative: a NON-fatal bad Publish result (e.g. the last subscription was deleted) must not
// trigger a reconnect - it is flow/lifecycle, not a transport drop. The Bad_NoSubscription result the pump
// receives after the last subscription is deleted is accepted as contractually-correct: the pump stays alive
// and no reconnect is attempted, which is the observable side of CL-SUB-009.
// @verifies CL-SUB-009
// @relation(CL-SUB-009, scope=function)
TEST_F(ConnectionImplTest, NonFatalPublishResultDoesNotReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  session->publish.set_hold(true);
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());

  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{StatusCode{Status::BadNoSubscription}});

  // Force a connection-strand round-trip to settle any (wrongly) posted drop notification, then assert
  // the connection stayed Active and no reopen was attempted.
  auto snapshot = TA::snapshot(*connection);
  EXPECT_EQ(snapshot.state, ConnectionState::Active);
  EXPECT_EQ(reopen->call_count(), 0u) << "a non-fatal Publish result must not start a reconnect";
}

// section 3.1 finding 1 - a fatal Publish issued under a PRIOR epoch (its channel already superseded by a
// reconnect) must NOT re-trigger a reconnect on the already-recovered connection.
TEST_F(ConnectionImplTest, TransportDropWithStaleEpochIsIgnored)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the reopen so the open step's epoch bump stands without completing
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto issuedEpoch =
    TA::snapshot(*connection).reconnectAttemptEpoch;  // epoch a Publish is issued under

  // A reconnect open step bumps the attempt epoch (models a real reconnect superseding the old channel).
  std::promise<VoidResult> opened;
  TA::reconnect_open_secure_channel(
    *connection, [&opened](VoidResult result) { opened.set_value(std::move(result)); });
  wait_for_reopen_pending(*reopen, 1);
  ASSERT_GT(TA::snapshot(*connection).reconnectAttemptEpoch, issuedEpoch)
    << "the open step must bump the epoch";

  // A fatal Publish that was issued under the PRIOR epoch (its channel superseded) must be ignored.
  const auto reopensBefore = reopen->call_count();
  TA::notify_transport_drop(*connection, StatusCode{Status::BadSecureChannelClosed}, issuedEpoch);
  auto snapshot = TA::snapshot(*connection);  // ordering barrier after the posted notify
  EXPECT_EQ(reopen->call_count(), reopensBefore) << "a stale-epoch drop must not start a new reconnect";
}

// section 3.1 finding 4 - a channel/session-fatal status carried in the service_result of a WELL-FORMED
// (is_good) PublishResponse (a ServiceFault the codec surfaced as a typed response) must still be
// detected as a drop; a status_code()-only check would miss it because is_bad() is false.
TEST_F(ConnectionImplTest, FatalServiceResultInWellFormedPublishTriggersReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  session->publish.set_hold(true);
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());

  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  ua::PublishResponse response;
  response.response_header().service_result() = StatusCode{Status::BadSessionIdInvalid};
  session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(response)});

  wait_for_reopen_pending(*reopen, 1);  // the in-band fatal service_result auto-triggered a reconnect
}

// ============================================================================================
// Gap recovery - the Republish drain DELIVERS the recovered DataChanges (section 8.4.5 / CL-RECONN-004)
// ============================================================================================

// Builds a RepublishResponse carrying one retained DataChange (clientHandle -> Int32 value).
ua::RepublishResponse make_republish_datachange(std::uint32_t clientHandle, std::int32_t value)
{
  ua::RepublishResponse response;
  auto dataChange = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  item.value() = ua::DataValue{ua::Variant{value}};
  dataChange->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(dataChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

// Builds a PublishResponse for @p subscriptionId at @p sequenceNumber carrying one DataChange
// (clientHandle -> Int32 value), for a live notification delivery.
ua::PublishResponse make_publish_datachange(
  std::uint32_t subscriptionId, std::uint32_t sequenceNumber, std::uint32_t clientHandle, std::int32_t value)
{
  ua::PublishResponse response;
  response.subscription_id() = subscriptionId;
  response.notification_message().sequence_number() = sequenceNumber;
  auto dataChange = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  item.value() = ua::DataValue{ua::Variant{value}};
  dataChange->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(dataChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

// A sequence GAP in a Publish response starts a Republish drain; the retained message's DataChanges must
// be DELIVERED to the monitored-item callback (not merely acknowledged) - the fix that lets a subscription
// recover the notifications queued while the client was disconnected.
TEST_F(ConnectionImplTest, GapDrainDeliversRepublishedData)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::atomic<std::int32_t> delivered{-1};
  auto miResult = create_monitored_item_and_wait(*connection,
    subId.value(),
    /*clientHandle=*/7,
    [&delivered](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        delivered.store(*asInt);
    });
  ASSERT_TRUE(miResult.is_good());

  // Control the Publish + Republish round-trips.
  session->publish.set_hold(true);
  session->republish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");

  // A Publish at seq 3 (the subscription expects seq 1) is a gap -> the pipeline starts a Republish drain.
  ua::PublishResponse gapResponse;
  gapResponse.subscription_id() = subId.value();
  gapResponse.notification_message().sequence_number() = 3;
  session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(gapResponse)});

  // The drain Republishes seq 1: return a retained DataChange for clientHandle 7 -> DELIVERED.
  wait_until([&] { return session->republish.pending_count() >= 1; }, "the gap-drain to Republish");
  session->republish.fire_next(ua::Result<ua::RepublishResponse>{make_republish_datachange(7, 4242)});
  wait_until([&] { return delivered.load() == 4242; }, "the republished DataChange to be delivered");

  // End the drain so the test settles.
  wait_until([&] { return session->republish.pending_count() >= 1; }, "the drain to step to the next seq");
  session->republish.fire_next(ua::Result<ua::RepublishResponse>{StatusCode{Status::BadMessageNotAvailable}});
  EXPECT_EQ(delivered.load(), 4242) << "the recovered value must reach the monitored-item callback";
}

// section 3.1 finding 1 / H3 (F1 keystone): a Republish RESPONSE issued under a PRIOR reconnect-attempt epoch
// (its channel superseded by a later reconnect) must be DROPPED before it can deliver data or advance the
// tracker
// - honouring it would recover notifications against a stale channel. This is the negative twin of
// GapDrainDeliversRepublishedData: the SAME gap-drain wiring, but with the attempt epoch bumped between the
// Republish being issued and its response arriving, so the recovered DataChange must NOT be delivered.
//
// Determinism: AsyncTestRuntime is single-threaded, so posts run in strict FIFO. A SECOND subscription's
// LIVE (current-epoch) Publish notification is fired AFTER the stale Republish response and acts as a
// sentinel - both flow connection-strand -> pipeline-strand -> executor in submission order, so once the
// sentinel value is delivered, the stale value (were the guard absent) would already have been delivered
// too. Asserting the sentinel arrived while the stale value did not is thus a deterministic falsifier for
// the epoch guard (comment out the `mReconnectAttemptEpoch != issuedEpoch` return in pipeline_republish and
// this test fails: staleDelivered becomes 4242).
TEST_F(ConnectionImplTest, StaleEpochRepublishResponseIsDropped)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the reopen so the open step's epoch bump stands without completing
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Two DISTINCT subscriptions (scripted ids): sub 100 is drained under the OLD epoch; sub 200 delivers a
  // live sentinel notification under the NEW epoch.
  ua::CreateSubscriptionResponse createA;
  createA.subscription_id() = 100;
  session->createSubscription.set_result(ua::Result<ua::CreateSubscriptionResponse>{createA});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  ua::CreateSubscriptionResponse createB;
  createB.subscription_id() = 200;
  session->createSubscription.set_result(ua::Result<ua::CreateSubscriptionResponse>{createB});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());

  std::atomic<std::int32_t> staleDelivered{-1};  // handle 7 (sub 100, stale-epoch Republish)
  std::atomic<std::int32_t> sentinelDelivered{-1};  // handle 8 (sub 200, live Publish)
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    /*subscriptionId=*/100,
    /*clientHandle=*/7,
    [&staleDelivered](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        staleDelivered.store(*asInt);
    }).is_good());
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    /*subscriptionId=*/200,
    /*clientHandle=*/8,
    [&sentinelDelivered](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        sentinelDelivered.store(*asInt);
    }).is_good());

  session->publish.set_hold(true);
  session->republish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");

  // Sub 100: a Publish at seq 3 (expects seq 1) is a gap -> a Republish for seq 1 is issued under the
  // CURRENT (pre-bump) epoch.
  const auto issuedEpoch = TA::snapshot(*connection).reconnectAttemptEpoch;
  ua::PublishResponse gap;
  gap.subscription_id() = 100;
  gap.notification_message().sequence_number() = 3;
  session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(gap)});
  wait_until([&] { return session->republish.pending_count() >= 1; }, "the gap-drain to Republish");

  // A reconnect open step bumps the attempt epoch, superseding the channel the Republish was issued under.
  std::promise<VoidResult> opened;
  TA::reconnect_open_secure_channel(
    *connection, [&opened](VoidResult result) { opened.set_value(std::move(result)); });
  wait_for_reopen_pending(*reopen, 1);
  ASSERT_GT(TA::snapshot(*connection).reconnectAttemptEpoch, issuedEpoch)
    << "the open step must bump the epoch";

  // The stale-epoch Republish response arrives now (retained DataChange for handle 7). It must be DROPPED
  // by the epoch guard - not delivered.
  session->republish.fire_next(
    ua::Result<ua::RepublishResponse>{make_republish_datachange(/*clientHandle=*/7, /*value=*/4242)});

  // Sub 200: a live in-order Publish (current epoch) delivers a sentinel for handle 8, fired AFTER the stale
  // Republish so it strictly follows it through the strands.
  session->publish.fire_next(ua::Result<ua::PublishResponse>{
    make_publish_datachange(/*subscriptionId=*/200, /*seq=*/1, /*clientHandle=*/8, /*value=*/8888)});

  wait_until([&] { return sentinelDelivered.load() == 8888; }, "the live sentinel notification to deliver");
  EXPECT_EQ(staleDelivered.load(), -1)
    << "a Republish response from a superseded epoch must be dropped, not delivered";
}

// ============================================================================================
// Session-CHANGED subscription recovery (#24, section 6.7): when a reconnect creates a FRESH Session, the old
// server-side Subscription ids are gone, so the recover step TransferSubscriptions-or-recreates instead of
// Republish-draining. The re-keys are STAGED and applied atomically at commit (stage-and-commit keystone).
// ============================================================================================

// ============================================================================================
// CL-SUB-019 - Polled-Read Subscription fallback engagement (SubscriptionFallbackPolicy Disabled/OptIn/Auto).
// A LARGE polling interval keeps the (engaged) driver's periodic timer from firing within the sub-second
// test; the DELIVERY mechanism is covered by the SubscriptionsPipeline unit suite.
// ============================================================================================

// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST_F(ConnectionImplTest, FallbackEngagesOnBadServiceUnsupportedInOptIn)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::OptIn;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadServiceUnsupported}});

  auto result = create_managed_and_wait(*connection);
  ASSERT_TRUE(result.is_good())
    << "OptIn must engage a fallback on Bad_ServiceUnsupported and return a good Subscription: 0x" << std::hex
    << result.status_code().as_uint32();
  EXPECT_GE(result.value().subscriptionId, 0x80000000u) << "the fallback carries a synthetic client-side id";
  EXPECT_EQ(session->createSubscription.call_count(), 1u)
    << "the wire CreateSubscription was attempted first";
}

// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST_F(ConnectionImplTest, FallbackDoesNotEngageInDisabledMode)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;  // default == Disabled
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadServiceUnsupported}});

  auto result = create_managed_and_wait(*connection);
  ASSERT_TRUE(result.is_bad()) << "Disabled must forward the failed create, never engage a fallback";
  EXPECT_EQ(result.status_code().as_status(), Status::BadServiceUnsupported)
    << "the bad status is forwarded verbatim";
}

// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST_F(ConnectionImplTest, FallbackAutoEngagesOnArbitraryCreateFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::Auto;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadInternalError}});

  auto result = create_managed_and_wait(*connection);
  ASSERT_TRUE(result.is_good()) << "Auto must engage a fallback on ANY create failure: 0x" << std::hex
                                << result.status_code().as_uint32();
  EXPECT_GE(result.value().subscriptionId, 0x80000000u);
}

// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST_F(ConnectionImplTest, FallbackOptInForwardsNonUnsupportedFailure)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::OptIn;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadInternalError}});

  auto result = create_managed_and_wait(*connection);
  ASSERT_TRUE(result.is_bad()) << "OptIn must NOT engage on a non-Unsupported failure - forward it";
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
}

// Transparent handle: monitoring an item on an ENGAGED fallback Subscription succeeds pipeline-locally and
// issues NO wire CreateMonitoredItems (there is no server-side Subscription to create against).
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST_F(ConnectionImplTest, FallbackMonitorIssuesNoWireCreateMonitoredItems)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::Auto;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadInternalError}});
  auto sub = create_managed_and_wait(*connection);
  ASSERT_TRUE(sub.is_good());

  auto item = create_monitored_item_and_wait(*connection, sub.value().subscriptionId, /*clientHandle=*/5);
  ASSERT_TRUE(item.is_good()) << "monitoring a fallback Subscription must succeed (registered for polling)";
  EXPECT_EQ(session->createMonitoredItems.call_count(), 0u)
    << "a fallback monitor must issue ZERO wire CreateMonitoredItems";
}

// CL-SUB-021: a PercentDeadband is not evaluable in fallback (no server-side EURange pre-read), so attaching
// one to a fallback Subscription is refused at attach time with Bad_FilterNotAllowed - no item registered, no
// wire.
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST_F(ConnectionImplTest, FallbackPercentDeadbandRefusedAtAttach)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::Auto;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadInternalError}});
  auto sub = create_managed_and_wait(*connection);
  ASSERT_TRUE(sub.is_good());

  MonitorRequest request;
  request.nodeId = NodeId{2, 5};
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Percent);
  filter.deadband_value() = 10.0;
  request.filter = filter;

  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  connection->monitor_data_change_async(
    sub.value().subscriptionId,
    std::move(request),
    [](DataChangeEvent) {},
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  auto result = future.get();
  ASSERT_TRUE(result.is_bad()) << "a PercentDeadband on a fallback Subscription must be refused at attach";
  EXPECT_EQ(result.status_code().as_status(), Status::BadFilterNotAllowed);
  EXPECT_EQ(session->createMonitoredItems.call_count(), 0u)
    << "a refused PercentDeadband attach must issue ZERO wire CreateMonitoredItems";
}

// CL-SUB-022: SetTriggering on a fallback (server-less) Subscription is rejected inline with
// Bad_FilterNotAllowed and issues NO wire SetTriggering (there is no server Subscription to trigger against).
// @verifies CL-SUB-022
// @relation(CL-SUB-022, scope=function)
TEST_F(ConnectionImplTest, FallbackSetTriggeringRejectedWithBadFilterNotAllowed)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  ConnectionConfig config;
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::Auto;
  auto connection = make_connection(session, reopen, config);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadInternalError}});
  auto sub = create_managed_and_wait(*connection);
  ASSERT_TRUE(sub.is_good());

  ua::SetTriggeringRequest request;
  request.subscription_id() = sub.value().subscriptionId;
  auto result = set_triggering_and_wait(*connection, std::move(request));
  ASSERT_TRUE(result.is_bad()) << "SetTriggering on a fallback Subscription must be refused";
  EXPECT_EQ(result.status_code().as_status(), Status::BadFilterNotAllowed);
  EXPECT_EQ(session->setTriggering.call_count(), 0u)
    << "a fallback SetTriggering must issue ZERO wire SetTriggering";
}

// A transferred subscription (server accepted the transfer) keeps its id + sequence counter, so the pipeline
// is NOT re-keyed and it is NOT recreated - the outage gap is recovered reactively once the pump resumes.
// @relation(AC-CL-RECONN-006-01, scope=function)
TEST_F(ConnectionImplTest, SessionChangedTransferKeepsSubscriptionIdsAndSkipsRecreate)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(
    Result<ua::TransferSubscriptionsResponse>{make_transfer_response({StatusCode{Status::Good}})});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(fresh->transferSubscriptions.call_count(), 1u) << "the transfer must be attempted first";
  EXPECT_EQ(fresh->createSubscription.call_count(), 0u) << "a transferred sub must NOT be recreated";
  const auto transferRequests = fresh->transferSubscriptions.requests();  // by value (snapshot copy)
  ASSERT_EQ(transferRequests.size(), 1u);
  EXPECT_TRUE(transferRequests[0].send_initial_values())
    << "sendInitialValues must be set so the sub re-reports on transfer";
  ASSERT_EQ(transferRequests[0].subscription_ids().size(), 1u);
  EXPECT_EQ(transferRequests[0].subscription_ids()[0], 77u);
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "a transferred sub keeps its server id (no re-key)";
  EXPECT_EQ(TA::reconnect_recovery_outcome(*connection), (std::pair<bool, std::size_t>{true, 0U}))
    << "the public reconnect outcome must report the successful TransferSubscriptions";
  EXPECT_EQ(subscription_count(*connection), 1u);
  EXPECT_EQ(monitored_item_count(*connection), 1u);
}

// @verifies CL-SUB-010
// @relation(CL-SUB-010, scope=function)
// @relation(AC-CL-SUB-010-A-SUBSCRIPTION-ACQUIRED-BY-TRANSFERSUBSCRIPTIONS, scope=function)
TEST_F(ConnectionImplTest, CloseDeletesTransferredSubscriptionBeforeClosingOwningSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(
    Result<ua::TransferSubscriptionsResponse>{make_transfer_response({StatusCode{Status::Good}})});
  ASSERT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  ASSERT_TRUE(run_commit(*connection).is_good());

  fresh->deleteSubscriptions.set_hold(true);
  std::promise<VoidResult> closed;
  auto closedFuture = closed.get_future();
  connection->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
  std::promise<VoidResult> concurrentClose;
  auto concurrentCloseFuture = concurrentClose.get_future();
  connection->close_async(
    [&concurrentClose](VoidResult result) { concurrentClose.set_value(std::move(result)); });

  wait_until([&] { return fresh->deleteSubscriptions.pending_count() == 1; },
    "close-time DeleteSubscriptions request");
  EXPECT_EQ(fresh->deleteSubscriptions.call_count(), 1u)
    << "a concurrent close must join the in-flight teardown, not duplicate DeleteSubscriptions";
  EXPECT_EQ(fresh->close.call_count(), 0u)
    << "the owning Session must remain open until DeleteSubscriptions completes";
  const auto requests = fresh->deleteSubscriptions.requests();
  ASSERT_EQ(requests.size(), 1u);
  ASSERT_EQ(requests.front().subscription_ids().size(), 1u);
  EXPECT_EQ(requests.front().subscription_ids()[0], 77u)
    << "the transferred id remains locally owned and must be deleted";

  ua::DeleteSubscriptionsResponse deleted;
  deleted.results().push_back(StatusCode{Status::Good});
  fresh->deleteSubscriptions.fire_next(Result<ua::DeleteSubscriptionsResponse>{std::move(deleted)});
  ASSERT_EQ(closedFuture.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(closedFuture.get().is_good());
  ASSERT_EQ(concurrentCloseFuture.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(concurrentCloseFuture.get().is_good());
  EXPECT_EQ(fresh->close.call_count(), 1u);
}

// @verifies CL-SUB-010
// @relation(CL-SUB-010, scope=function)
// @relation(AC-CL-SUB-010-A-SUBSCRIPTION-ACQUIRED-BY-TRANSFERSUBSCRIPTIONS, scope=function)
TEST_F(ConnectionImplTest, CloseContinuesSessionTeardownWhenOwnedSubscriptionDeleteFails)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);
  session->deleteSubscriptions.set_result(
    Result<ua::DeleteSubscriptionsResponse>{StatusCode{Status::BadServerNotConnected,
      ua::make_error_detail("DeleteFailed", "server dropped the close-time delete", "test.close_delete")}});

  EXPECT_TRUE(close_and_wait(*connection).is_good())
    << "best-effort delete failure must not strand local Session teardown";
  EXPECT_EQ(session->deleteSubscriptions.call_count(), 1u);
  EXPECT_EQ(session->close.call_count(), 1u);
}

// A refused transfer (Bad_SubscriptionIdInvalid AT TRANSFER = "recreate me", NOT the A3 erase path) routes
// the sub to recreate: CreateSubscription (new id) + CreateMonitoredItems (retained node + client handle).
// The re-key is STAGED (pipeline still holds the OLD id after recover) and applied only at commit.
TEST_F(ConnectionImplTest, SessionChangedRefusedSubscriptionRecreatedWithNewIdAppliedAtCommit)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5, /*interval=*/250.0);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "the re-key must be STAGED, not applied during the recover step (stage-and-commit keystone)";

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{88}))
    << "commit applies the staged re-key old->new atomically";

  EXPECT_EQ(fresh->createSubscription.call_count(), 1u);
  EXPECT_EQ(fresh->createMonitoredItems.call_count(), 1u);
  const auto createSubRequests = fresh->createSubscription.requests();  // by value (snapshot copy)
  ASSERT_EQ(createSubRequests.size(), 1u);
  EXPECT_DOUBLE_EQ(createSubRequests[0].requested_publishing_interval(), 250.0)
    << "recreate must reuse the retained publishing interval";
  const auto itemsRequests = fresh->createMonitoredItems.requests();  // by value (snapshot copy)
  ASSERT_EQ(itemsRequests.size(), 1u);
  EXPECT_EQ(itemsRequests[0].subscription_id(), 88u) << "the item must be created under the NEW sub id";
  ASSERT_EQ(itemsRequests[0].items_to_create().size(), 1u);
  EXPECT_EQ(itemsRequests[0].items_to_create()[0].requested_parameters().client_handle(), 5u)
    << "the retained client handle must be preserved so the pipeline re-keys the existing callback";
  EXPECT_EQ(itemsRequests[0].items_to_create()[0].item_to_monitor().node_id(), NodeId(2, 5))
    << "the retained node must be reused to recreate the item";
  EXPECT_EQ(TA::reconnect_recovery_outcome(*connection), (std::pair<bool, std::size_t>{false, 1U}))
    << "a refused transfer followed by item recreation must report recreation, not transfer";
  EXPECT_EQ(subscription_count(*connection), 1u);
  EXPECT_EQ(monitored_item_count(*connection), 1u);
}

// A session-CHANGED recreate must PRESERVE the caller's monitored-item tuning, not silently revert it to the
// builder's defaults (section 6.7, Q5). The item is created with non-default tuning (attribute=DisplayName,
// indexRange="0:9", samplingIntervalMs=1000, queueSize=100, monitoringMode=Sampling, discardOldest=false)
// through the owner path; after a RecreateOnly rebuild onto a fresh Session, the rebuilt CreateMonitoredItems
// must carry those SAME values. Before the recovery record retained the tuning, recreate emitted defaults -
// dropping the caller's parameters on a reconnect (the create/recreate asymmetry this closes). CL-MI-020: the
// discardOldest leg pins that a non-default overflow policy is NOT reverted to the hardcoded true on
// recreate.
TEST_F(ConnectionImplTest, SessionChangedRecreatePreservesMonitoredItemTuning)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Seed one Subscription (id 77) and a monitored item created with NON-DEFAULT tuning through the owner path
  // (monitor_data_change_async), so the pipeline retains that tuning in its recovery record.
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*publishingInterval=*/250.0).is_good());

  MonitorRequest request;
  request.nodeId = NodeId{2, 5};
  request.attribute = ua::AttributeId::DisplayName;  // deliberately non-default (default is Value)
  request.indexRange = std::string{"0:9"};
  request.samplingIntervalMs = 1000.0;
  request.queueSize = 100;
  request.monitoringMode = ua::MonitoringMode::Sampling;
  request.discardOldest = false;  // non-default overflow policy (CL-MI-020) - must survive the recreate
  {
    std::promise<MonitoredItemResult> promise;
    auto future = promise.get_future();
    connection->monitor_data_change_async(
      /*subscriptionId=*/
      77,
      std::move(request),
      [](DataChangeEvent) {},
      [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }
  // The pipeline registers the item on its own strand, so poll for it to settle before driving recovery.
  wait_until([&] { return monitored_item_count(*connection) == 1; }, "monitored item registered in pipeline");

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::RecreateOnly).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  ASSERT_EQ(fresh->createMonitoredItems.call_count(), 1u);
  const auto itemsRequests = fresh->createMonitoredItems.requests();  // by value (snapshot copy)
  ASSERT_EQ(itemsRequests.size(), 1u);
  EXPECT_EQ(itemsRequests[0].subscription_id(), 88u) << "the item must be recreated under the NEW sub id";
  ASSERT_EQ(itemsRequests[0].items_to_create().size(), 1u);
  const auto& item = itemsRequests[0].items_to_create()[0];
  EXPECT_EQ(item.item_to_monitor().node_id(), NodeId(2, 5)) << "the retained node must be reused";
  EXPECT_EQ(item.item_to_monitor().attribute_id(), static_cast<std::uint32_t>(ua::AttributeId::DisplayName))
    << "recreate must preserve the retained attribute, not default to Value";
  EXPECT_EQ(static_cast<std::string_view>(item.item_to_monitor().index_range()), "0:9")
    << "recreate must preserve the retained index-range, not default to empty";
  EXPECT_EQ(item.requested_parameters().sampling_interval(), 1000.0)
    << "recreate must preserve the retained sampling interval, not default to 0.0";
  EXPECT_EQ(item.requested_parameters().queue_size(), 100u)
    << "recreate must preserve the retained queue size, not default to 1";
  EXPECT_EQ(item.monitoring_mode(), ua::MonitoringMode::Sampling)
    << "recreate must preserve the retained monitoring mode, not default to Reporting";
  EXPECT_FALSE(item.requested_parameters().discard_oldest())
    << "recreate must preserve the retained discardOldest=false, not revert to the hardcoded true "
       "(CL-MI-020)";
}

// A session-CHANGED recreate must rebuild the Subscription with the tuning the CALLER asked for, not the
// SDK defaults: a recreate that sent the defaults would report success while handing back a Subscription
// with a different keep-alive, lifetime, priority and publishing mode from the one that was lost. The
// values here are deliberately non-default (900/300/7/false, never 30/10/0/true), because a test using the
// defaults cannot distinguish a retained parameter set from a rebuilt one. The create-side and modify-side
// legs are in subscription_tuning_wiring_tests.cpp; this one lives here because the reconnect-drive
// machinery does.
TEST_F(ConnectionImplTest, SessionChangedRecreatePreservesSubscriptionTuning)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ConnectionImpl::SubscriptionTuning tuning;
  tuning.lifetimeCount = 900;
  tuning.maxKeepAliveCount = 300;
  tuning.priority = 7;
  tuning.publishingEnabled = false;
  {
    std::promise<Result<ua::client::detail::SubscriptionCreated>> promise;
    auto future = promise.get_future();
    connection->create_subscription_managed_async(/*publishingInterval=*/250.0,
      tuning,
      /*maxNotificationsPerPublish=*/std::nullopt,
      [&promise](Result<ua::client::detail::SubscriptionCreated> result)
      { promise.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }
  ASSERT_EQ(session->createSubscription.requests().size(), 1u);
  EXPECT_EQ(session->createSubscription.requests()[0].requested_lifetime_count(), 900u)
    << "the create itself must carry the caller's lifetime count, not the hardcoded 30";

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});  // refuse -> recreate
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  ASSERT_EQ(fresh->createSubscription.call_count(), 1u);
  const auto createSubRequests = fresh->createSubscription.requests();  // by value (snapshot copy)
  ASSERT_EQ(createSubRequests.size(), 1u);
  EXPECT_DOUBLE_EQ(createSubRequests[0].requested_publishing_interval(), 250.0)
    << "recreate must reuse the retained publishing interval";
  EXPECT_EQ(createSubRequests[0].requested_lifetime_count(), 900u)
    << "recreate must reuse the retained lifetime count, not revert to the default 30";
  EXPECT_EQ(createSubRequests[0].requested_max_keep_alive_count(), 300u)
    << "recreate must reuse the retained keep-alive count, not revert to the default 10 - this is what "
       "decides how fast a dead Subscription is detected";
  EXPECT_EQ(createSubRequests[0].priority(), 7)
    << "recreate must reuse the retained priority, not revert to 0 (lowest)";
  EXPECT_FALSE(createSubRequests[0].publishing_enabled())
    << "recreate must reuse the retained publishing mode, not silently re-enable publishing";
}

// RecreateOnly skips TransferSubscriptions entirely and recreates every subscription from its retained
// descriptor (CL-RECONN-007 forces this for a RedundancySwitch).
TEST_F(ConnectionImplTest, SessionChangedRecreateOnlySkipsTransferAndRecreatesAll)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::RecreateOnly).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(fresh->transferSubscriptions.call_count(), 0u) << "RecreateOnly must skip TransferSubscriptions";
  EXPECT_EQ(fresh->createSubscription.call_count(), 1u);
  EXPECT_EQ(fresh->createMonitoredItems.call_count(), 1u);
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{88}));
}

// section 3.1 (#24 review, HIGH): a recreate whose fresh Session handed back the SAME server id must still
// flow through commit's atomic re-key apply (which resets the tracker) - the id-based assertion stays {77},
// and the pipeline-level ApplyRecreateRekeysSameIdStillResetsTracker proves the tracker reset. This
// connection- level test pins that a same-id recreate drives create + commit cleanly rather than
// short-circuiting.
TEST_F(ConnectionImplTest, SessionChangedRecreateWithReusedSameServerIdCommitsCleanly)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  // The server reassigns the freed id 77 to the recreated Subscription (same id back).
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/77)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(fresh->createSubscription.call_count(), 1u) << "the refused sub must be recreated";
  EXPECT_EQ(fresh->createMonitoredItems.call_count(), 1u);
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "the recreated sub keeps the reused id 77 (the tracker reset is asserted at the pipeline level)";
  EXPECT_EQ(monitored_item_count(*connection), 1u);
}

// The heterogeneous barrier: with MULTIPLE subscriptions, a single reconnect can TRANSFER some and RECREATE
// others, and the barrier must complete only when BOTH the (synchronous) transferred settle AND the
// (asynchronous, two-op) recreate chain have terminated. Sub 77 is transferred (kept), sub 88 is refused and
// recreated as id 99. The transfer is held so the scripted response is matched to the ACTUAL request order
// (recovery_descriptors iterates an unordered_map, so the order is not fixed).
TEST_F(ConnectionImplTest, SessionChangedMixedTransferAndRecreateInOneReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);
  seed_subscription_with_item(*connection, *session, /*subId=*/88, /*clientHandle=*/6);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/99)});

  // Hold the transfer so we can read the actual request order and answer Good for 77, Bad for 88.
  fresh->transferSubscriptions.set_hold(true);
  std::promise<VoidResult> recoverPromise;
  auto recoverFuture = recoverPromise.get_future();
  TA::reconnect_recover_subscriptions(*connection,
    SubscriptionRecovery::TransferThenRecreate,
    [&recoverPromise](VoidResult result) { recoverPromise.set_value(std::move(result)); });
  wait_until([&] { return fresh->transferSubscriptions.pending_count() >= 1; }, "the transfer to be issued");

  const auto transferRequests = fresh->transferSubscriptions.requests();
  ASSERT_EQ(transferRequests.size(), 1u);
  const auto& requestedIds = transferRequests[0].subscription_ids();
  ASSERT_EQ(requestedIds.size(), 2u);
  std::vector<StatusCode> statuses;
  for (std::size_t index = 0; index < requestedIds.size(); ++index)
  {
    statuses.push_back(
      requestedIds[index] == 77u ? StatusCode{Status::Good} : StatusCode{Status::BadSubscriptionIdInvalid});
  }
  fresh->transferSubscriptions.fire_next(
    Result<ua::TransferSubscriptionsResponse>{make_transfer_response(std::move(statuses))});

  ASSERT_EQ(recoverFuture.wait_for(2s), std::future_status::ready)
    << "the heterogeneous barrier must complete once BOTH the transfer and the recreate terminate";
  EXPECT_TRUE(recoverFuture.get().is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  // Sub 77 kept its id (transferred); sub 88 was recreated as id 99. Only the refused sub was recreated.
  auto ids = TA::pipeline_subscription_ids(*connection);
  std::sort(ids.begin(), ids.end());
  EXPECT_EQ(ids, (std::vector<std::uint32_t>{77, 99})) << "77 transferred (kept), 88 recreated -> 99";
  EXPECT_EQ(subscription_count(*connection), 2u);
  EXPECT_EQ(monitored_item_count(*connection), 2u) << "both monitored items survive the mixed recovery";
  EXPECT_EQ(fresh->createSubscription.call_count(), 1u) << "only the ONE refused sub is recreated";
  EXPECT_EQ(fresh->createMonitoredItems.call_count(), 1u);
}

// A whole-request transfer failure (transport / service fault) leaves us unable to tell which subs the
// server accepted, so every sub is recreated (the safe, no-loss fallback).
TEST_F(ConnectionImplTest, SessionChangedTransferWholeRequestFailureRecreatesAll)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(
    Result<ua::TransferSubscriptionsResponse>{StatusCode{Status::BadServiceUnsupported}});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(fresh->createSubscription.call_count(), 1u)
    << "a whole-request transfer failure must recreate all subs";
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{88}));
}

// A failed recreate makes the recovery report Bad (so the FSM backs off and re-drives) and applies NOTHING:
// the pipeline keeps its pristine original id even if commit runs (stage-and-commit
// apply-nothing-on-failure).
TEST_F(ConnectionImplTest, SessionChangedRecreateFailureReportsBadAndAppliesNoRekey)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadServiceUnsupported}});

  const auto recovered = run_recover(*connection, SubscriptionRecovery::TransferThenRecreate);
  EXPECT_TRUE(recovered.is_bad()) << "a failed recreate must make recovery report Bad so the FSM re-drives";
  EXPECT_EQ(recovered.status_code(), StatusCode{Status::BadServiceUnsupported})
    << "the worst terminal status must propagate (its ErrorDetail is preserved)";

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "on recover failure NOTHING is applied - the pipeline keeps its pristine id for the retry";
}

// The recreate is only complete once its monitored items are recreated: a per-item bad CreateMonitoredItems
// result must fail the whole recovery (a partially-recreated Subscription is worse than re-driving), apply
// NOTHING, and leave the pipeline's pristine id for the retry.
TEST_F(ConnectionImplTest, SessionChangedRecreateMonitoredItemsFailureReportsBadAndAppliesNoRekey)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  // CreateSubscription succeeds (new id 99) but CreateMonitoredItems reports the item Bad.
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/99)});
  fresh->createMonitoredItems.set_result(Result<ua::CreateMonitoredItemsResponse>{
    make_create_items_response({StatusCode{Status::BadNodeIdUnknown}})});

  const auto recovered = run_recover(*connection, SubscriptionRecovery::TransferThenRecreate);
  EXPECT_TRUE(recovered.is_bad()) << "a per-item CreateMonitoredItems failure must fail the recovery";
  EXPECT_EQ(recovered.status_code(), StatusCode{Status::BadNodeIdUnknown})
    << "the per-item status must propagate (ErrorDetail preserved)";

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "a failed recreate applies NOTHING - the pipeline keeps its pristine id for the retry";
}

// A recreate's CreateSubscription answered Uncertain with its response holds the new Subscription id, so the
// recovery restores the Subscription from it (the re-key is staged and applied at commit) and reports the
// Uncertain code as its outcome rather than plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ConnectionImplTest, SessionChangedUncertainCreateSubscriptionRestoresAndCarriesTheCode)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  auto created = make_create_sub_response(/*newId=*/88);
  created.response_header().service_result() = uncertain;
  fresh->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(created)});

  const auto recovered = run_recover(*connection, SubscriptionRecovery::RecreateOnly);
  EXPECT_TRUE(recovered.is_uncertain()) << "the recovery carries the answer's code, not plain Good";
  EXPECT_EQ(recovered.status_code(), uncertain);

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{88}))
    << "the Subscription is restored from the Uncertain answer's id";
}

// A recreated item answered Uncertain holds its new monitored-item id, so the recovery restores it and
// reports the item's Uncertain code as its outcome.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ConnectionImplTest, SessionChangedUncertainRecreatedItemRestoresAndCarriesTheCode)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  fresh->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_create_items_response({uncertain})});

  const auto recovered = run_recover(*connection, SubscriptionRecovery::RecreateOnly);
  EXPECT_TRUE(recovered.is_uncertain());
  EXPECT_EQ(recovered.status_code(), uncertain);

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{88}));
}

// A recreate's CreateSubscription answered Uncertain without a response holds no Subscription id: the
// recovery refuses it (Bad_InternalError, ServiceAnswerUncertain, the code as its inner status) so the
// reconnect backs off, and nothing is applied.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, SessionChangedUncertainCreateSubscriptionWithoutAResponseIsRefused)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  fresh->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{uncertain});

  const auto recovered = run_recover(*connection, SubscriptionRecovery::RecreateOnly);
  EXPECT_EQ(recovered.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(recovered.error_detail(), nullptr);
  EXPECT_EQ(recovered.error_detail()->code, "ServiceAnswerUncertain");
  EXPECT_EQ(recovered.error_detail()->innerStatus, uncertain.value());

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "a refused recreate applies nothing";
}

// A recreate's CreateMonitoredItems answered Uncertain without a response holds no item ids: the recovery
// refuses it (Bad_InternalError, ServiceAnswerUncertain) and applies nothing.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(ConnectionImplTest, SessionChangedUncertainCreateMonitoredItemsWithoutAResponseIsRefused)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  fresh->createMonitoredItems.set_result(Result<ua::CreateMonitoredItemsResponse>{uncertain});

  const auto recovered = run_recover(*connection, SubscriptionRecovery::RecreateOnly);
  EXPECT_EQ(recovered.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(recovered.error_detail(), nullptr);
  EXPECT_EQ(recovered.error_detail()->code, "ServiceAnswerUncertain");
  EXPECT_EQ(recovered.error_detail()->innerStatus, uncertain.value());

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}));
}

// After a failed recovery the pipeline is pristine, so a re-drive transfers/creates against the ORIGINAL id
// (no half-applied / double-applied re-key) - the retry-idempotency the stage-and-commit contract guarantees.
TEST_F(ConnectionImplTest, SessionChangedFailedRecoveryRetryReDrivesFromPristineId)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);

  // Attempt 1: transfer refuses, recreate FAILS -> recovery Bad, nothing staged, pipeline pristine.
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{StatusCode{Status::BadInternalError}});
  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_bad());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "a failed recovery must leave the pristine id";

  // Attempt 2 (re-drive): transfer refuses again, recreate SUCCEEDS -> Good, and the re-drive targets id 77.
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());

  ASSERT_GE(fresh->transferSubscriptions.requests().size(), 2u);
  ASSERT_EQ(fresh->transferSubscriptions.requests().back().subscription_ids().size(), 1u);
  EXPECT_EQ(fresh->transferSubscriptions.requests().back().subscription_ids()[0], 77u)
    << "the retry must re-drive from the pipeline's pristine original id, not a half-applied one";

  EXPECT_TRUE(run_commit(*connection).is_good());
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{88}));
}

// ============================================================================================
// CRITICAL 1 (section 3.1 Slice 9) - a session-CHANGED recreate must RE-KEY the
// DataChangeMonitoredItemOwner's self-action routing map, not just the pipeline. The owner map is the SOLE
// holder of clientHandle -> {subscriptionId, serverMonitoredItemId}; if it keeps the STALE ids after
// recreate, every self-action (modify / set-mode / delete / set-triggering) mis-targets the old sub/item ->
// live item un-deletable (leak) or, on server-id reuse, mis-delete a DIFFERENT item (corruption). Seeded
// through the OWNER path (monitor_data_change_async), which registers routing - not the create_monitored_item
// path.
// ============================================================================================

TEST_F(ConnectionImplTest, SessionChangedRecreateRekeysOwnerRouting)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Seed sub 77 + one data-change item (server mi 100) through the OWNER path so routing is registered.
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/250.0).is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});
  const auto monitored = monitor_data_change_and_wait(*connection, /*subId=*/77, NodeId{2, 7});
  ASSERT_TRUE(monitored.is_good());
  const std::uint32_t clientHandle = monitored.value().client_handle();

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  ASSERT_EQ(owner->subscription_of(clientHandle), std::optional<std::uint32_t>{77});
  ASSERT_EQ(owner->server_item_id(clientHandle), std::optional<std::uint32_t>{100});

  // Reconnect onto a fresh Session -> old server ids gone -> transfer refuses -> recreate (new sub 88, mi
  // 900).
  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  fresh->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*newMiId=*/900)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_EQ(owner->subscription_of(clientHandle), std::optional<std::uint32_t>{77})
    << "the owner re-key must be STAGED, not applied during recover (stage-and-commit)";

  EXPECT_TRUE(run_commit(*connection).is_good());

  // The release-blocker assertions: commit re-keyed the owner routing to the RECREATED server ids.
  EXPECT_EQ(owner->subscription_of(clientHandle), std::optional<std::uint32_t>{88})
    << "recreate must re-key the owner's subscription id (else self-actions target the stale sub)";
  EXPECT_EQ(owner->server_item_id(clientHandle), std::optional<std::uint32_t>{900})
    << "recreate must re-key the owner's server monitored-item id (else self-actions target a stale item)";
}

// Behavioral variant: after the recreate + commit, the recreated item's own self-delete must send
// DeleteMonitoredItems targeting the NEW ids {88, 900}, not the stale {77, 100} the owner held pre-fix.
TEST_F(ConnectionImplTest, SessionChangedRecreatedItemSelfDeleteTargetsNewIds)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/250.0).is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});
  const auto monitored = monitor_data_change_and_wait(*connection, /*subId=*/77, NodeId{2, 7});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  fresh->transferSubscriptions.set_result(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  fresh->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*newId=*/88)});
  fresh->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*newMiId=*/900)});
  ua::DeleteMonitoredItemsResponse deleteResponse;
  deleteResponse.results().push_back(StatusCode{Status::Good});
  fresh->deleteMonitoredItems.set_result(Result<ua::DeleteMonitoredItemsResponse>{std::move(deleteResponse)});

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_TRUE(run_commit(*connection).is_good());

  // The connection stays Active across the driver-primitive recovery, so the self-delete dispatches on the
  // freshly-installed session. It must carry the RECREATED ids the owner re-key applied.
  EXPECT_TRUE(item.try_delete_sync().is_good());
  ASSERT_EQ(fresh->deleteMonitoredItems.call_count(), 1u)
    << "the self-delete must route through the owner to the freshly-installed session";
  const auto deleteRequests = fresh->deleteMonitoredItems.requests();
  ASSERT_EQ(deleteRequests.size(), 1u);
  EXPECT_EQ(deleteRequests[0].subscription_id(), 88u)
    << "the self-delete must target the recreated subscription id (owner re-key)";
  ASSERT_EQ(deleteRequests[0].monitored_item_ids().size(), 1u);
  EXPECT_EQ(deleteRequests[0].monitored_item_ids()[0], 900u)
    << "the self-delete must target the recreated server monitored-item id (owner re-key)";
}

// ============================================================================================
// WARNING 3 (section 3.1 Slice 9) - closing a Subscription must PURGE its items' owner-routing entries, else
// the map grows unbounded and re-opens the server-id-reuse mis-route hazard. Two items on sub 77; deleting
// the subscription must drop BOTH their routing entries (delete_subscription_async ->
// unregister_subscription).
// ============================================================================================

TEST_F(ConnectionImplTest, DeleteSubscriptionPurgesOwnerRouting)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/77)});
  ASSERT_TRUE(create_subscription_and_wait(*connection, /*interval=*/100.0).is_good());

  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/100)});
  const auto firstItem = monitor_data_change_and_wait(*connection, /*subId=*/77, NodeId{2, 7});
  ASSERT_TRUE(firstItem.is_good());
  session->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{make_one_item_response(/*miId=*/101)});
  const auto secondItem = monitor_data_change_and_wait(*connection, /*subId=*/77, NodeId{2, 8});
  ASSERT_TRUE(secondItem.is_good());
  const std::uint32_t handle1 = firstItem.value().client_handle();
  const std::uint32_t handle2 = secondItem.value().client_handle();

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  ASSERT_TRUE(owner->subscription_of(handle1).has_value());
  ASSERT_TRUE(owner->subscription_of(handle2).has_value());

  ua::DeleteSubscriptionsResponse deleteResponse;
  deleteResponse.results().push_back(StatusCode{Status::Good});
  session->deleteSubscriptions.set_result(Result<ua::DeleteSubscriptionsResponse>{std::move(deleteResponse)});
  ASSERT_TRUE(delete_subscription_and_wait(*connection, /*subscriptionId=*/77).is_good());

  EXPECT_FALSE(owner->subscription_of(handle1).has_value())
    << "closing the subscription must purge item 1's owner routing (WARNING 3)";
  EXPECT_FALSE(owner->subscription_of(handle2).has_value())
    << "closing the subscription must purge item 2's owner routing (WARNING 3)";
}

// H1 keystone: a transfer response from a SUPERSEDED attempt (the epoch bumped between issue and arrival)
// must be dropped - no re-key, no recreate, and the superseded barrier's `done` must NOT fire. Falsifier:
// remove the epoch guard in recover_session_changed's transfer completion and the stale (refusing) response
// would kick off a recreate and settle the recovery.
TEST_F(ConnectionImplTest, SessionChangedStaleTransferResponseInBackoffWindowIsDropped)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);

  auto* fresh = drive_to_fresh_session_pre_recover(*connection, *session);
  // The epoch-bump open step below resets mPendingSession; the parked transfer completion is owned by the
  // fresh interface, so hold a strong ref for the test's lifetime to keep it (and its parked callback) alive.
  auto pendingKeepAlive = TA::snapshot(*connection).pendingSession;
  ASSERT_EQ(fresh, dynamic_cast<FakeSessionOps*>(pendingKeepAlive.get()));

  fresh->transferSubscriptions.set_hold(true);  // park the transfer so we can bump the epoch under it
  std::atomic<int> recoverDone{0};
  TA::reconnect_recover_subscriptions(*connection,
    SubscriptionRecovery::TransferThenRecreate,
    [&recoverDone](VoidResult) { recoverDone.fetch_add(1); });
  wait_until([&] { return fresh->transferSubscriptions.pending_count() >= 1; },
    "the recover step to issue the transfer");

  const auto issuedEpoch = TA::snapshot(*connection).reconnectAttemptEpoch;
  reopen->set_hold(true);  // park the reopen so the epoch bump stands without completing
  TA::reconnect_open_secure_channel(*connection, [](VoidResult) {});
  wait_for_reopen_pending(*reopen, 1);
  ASSERT_GT(TA::snapshot(*connection).reconnectAttemptEpoch, issuedEpoch)
    << "the open step must bump the attempt epoch";

  // The stale (refusing) transfer response from the superseded attempt arrives now.
  fresh->transferSubscriptions.fire_next(Result<ua::TransferSubscriptionsResponse>{
    make_transfer_response({StatusCode{Status::BadSubscriptionIdInvalid}})});
  std::this_thread::sleep_for(40ms);  // give any erroneous settle / recreate time to land

  EXPECT_EQ(recoverDone.load(), 0)
    << "a superseded-attempt transfer response must not complete the recovery (the barrier stalls)";
  EXPECT_EQ(fresh->createSubscription.call_count(), 0u) << "no recreate may be kicked off a stale response";
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "the pipeline's ids must be untouched by a stale transfer response";
}

// A preserved-session reconnect (activate-on-existing succeeded) does NOT take the transfer/recreate branch:
// the subs still live server-side under the same ids, so recover Republish-drains (#23) and never transfers.
TEST_F(ConnectionImplTest, SessionPreservedRecoveryDoesNotTransferOrRecreate)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);
  // The #23 Republish drain ends on Bad_MessageNotAvailable (queue drained); script that clean terminator so
  // the drain terminates at once rather than looping to the iteration cap.
  session->republish.set_result(Result<ua::RepublishResponse>{StatusCode{Status::BadMessageNotAvailable}});

  // Reconnect that REBINDS the existing session (activate-on-existing succeeds): no fresh session created.
  EXPECT_TRUE(run_open(*connection).is_good());
  EXPECT_TRUE(run_activate(*connection).is_good());  // existing session re-activates on the new channel

  EXPECT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());

  EXPECT_EQ(session->transferSubscriptions.call_count(), 0u)
    << "a preserved session must not transfer - its subs still exist server-side";
  EXPECT_EQ(session->createSubscription.call_count(), 1u)
    << "no recreate on the preserved path (only the initial create from seeding)";
  EXPECT_EQ(TA::pipeline_subscription_ids(*connection), (std::vector<std::uint32_t>{77}))
    << "the preserved sub keeps its id";
}

// ============================================================================================
// Tier-1 wire-op pass-through semantics (section 8.2A.5): every service op forwards the caller's request
// verbatim to the tier-0 session and surfaces the session's Result<Response> unaltered (no clamping,
// no reordering, no coercion, no per-slot collapse). These pin the observable pass-through mandated by
// the View / Attribute / Method / MonitoredItem / Subscription / Session requirements.
// ============================================================================================

/// Builds a PublishResponse for @p subscriptionId at @p sequenceNumber whose single DataChange pairs
/// @p clientHandle with a full @p value (so a test controls the delivered quality StatusCode / InfoBits).
ua::PublishResponse make_publish_with_value(
  std::uint32_t subscriptionId, std::uint32_t sequenceNumber, std::uint32_t clientHandle, ua::DataValue value)
{
  ua::PublishResponse response;
  response.subscription_id() = subscriptionId;
  response.notification_message().sequence_number() = sequenceNumber;
  auto dataChange = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  item.value() = std::move(value);
  dataChange->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(dataChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

/// Builds a PublishResponse whose single DataChange carries one MonitoredItemNotification per (handle, value)
/// pair, IN ORDER, so a test can assert arrival-order delivery across (and within) monitored items.
ua::PublishResponse make_publish_multi(std::uint32_t subscriptionId, std::uint32_t sequenceNumber,
  std::vector<std::pair<std::uint32_t, std::int32_t>> items)
{
  ua::PublishResponse response;
  response.subscription_id() = subscriptionId;
  response.notification_message().sequence_number() = sequenceNumber;
  auto dataChange = std::make_unique<ua::DataChangeNotification>();
  for (auto& [handle, value] : items)
  {
    ua::MonitoredItemNotification item;
    item.client_handle() = handle;
    item.value() = ua::DataValue{ua::Variant{value}};
    dataChange->monitored_items().push_back(std::move(item));
  }
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(dataChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

// ---- Attribute: Read maxAge validation and pass-through (CL-ATTR-001..003) ---------------------------

// A negative maxAge is invalid (Part 4 section 5.10.2.2) and must fail locally with Bad_MaxAgeInvalid
// (Part 4 section 5.10.2.3). Falsifiable: removing the ConnectionImpl validation makes the fake session's
// Read count advance and returns its default Good response; dropping the manufactured ErrorDetail fails the
// source assertion.
// @verifies CL-ATTR-003
// @relation(CL-ATTR-003, scope=function)
TEST_F(ConnectionImplTest, ReadRejectsNegativeMaxAgeBeforeSessionWithErrorDetail)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::vector<double> invalidMaxAges{
    -1.0, -std::numeric_limits<double>::denorm_min(), -std::numeric_limits<double>::infinity()};
  for (const double maxAge : invalidMaxAges)
  {
    SCOPED_TRACE(::testing::Message{} << "maxAge=" << maxAge);
    const auto readsBefore = session->read.call_count();

    ua::ReadRequest request;
    request.max_age() = maxAge;
    const auto result = read_and_wait(*connection, std::move(request));

    ASSERT_TRUE(result.is_bad()) << "a negative maxAge must fail the Read";
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadMaxAgeInvalid});
    EXPECT_EQ(session->read.call_count(), readsBefore)
      << "request validation must reject a negative maxAge before the session/wire interface";
    const auto detail = result.status_code().shared_detail();
    ASSERT_NE(detail, nullptr) << "a locally manufactured failure must carry ErrorDetail";
    EXPECT_EQ(detail->code, "ReadMaxAgeInvalid");
    EXPECT_EQ(detail->source, "client.tier1.connection.read");
  }
}

// maxAge = 0 (request fresh-from-source) reaches the wire unmodified: read_async forwards the caller's
// ReadRequest verbatim, so the maxAge the application chose is exactly what the server sees.
// @verifies CL-ATTR-001
// @relation(CL-ATTR-001, scope=function)
TEST_F(ConnectionImplTest, ReadForwardsMaxAgeZeroUnmodified)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::ReadRequest request;
  request.max_age() = 0.0;
  ua::ReadValueId target;
  target.node_id() = NodeId{2, 1};
  target.attribute_id() = 13;  // Value
  request.nodes_to_read().push_back(std::move(target));
  ASSERT_TRUE(read_and_wait(*connection, std::move(request)).is_good());

  const auto requests = session->read.requests();
  ASSERT_GE(requests.size(), 2u) << "requests[0] is the bootstrap read; the caller's read is last";
  EXPECT_DOUBLE_EQ(requests.back().max_age(), 0.0)
    << "maxAge = 0 must reach the wire unmodified (fresh-from-source)";
}

// maxAge >= Int32.max (accept any cached value) is carried through UNCLAMPED: read_async never rewrites it.
// @verifies CL-ATTR-002
// @relation(CL-ATTR-002, scope=function)
TEST_F(ConnectionImplTest, ReadForwardsLargeMaxAgeUnclamped)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  constexpr double int32Max = 2147483647.0;  // Int32.max as a Duration (ms)
  ua::ReadRequest request;
  request.max_age() = int32Max;
  ASSERT_TRUE(read_and_wait(*connection, std::move(request)).is_good());

  const auto requests = session->read.requests();
  ASSERT_GE(requests.size(), 2u);
  EXPECT_DOUBLE_EQ(requests.back().max_age(), int32Max)
    << "a large maxAge must pass through unclamped (accept cached value)";
}

// ---- Attribute: Write per-slot exposure + no rollback (CL-ATTR-019) ---------------------------------

// A partial WriteResponse (Good on slot 0, Bad on slot 1) is surfaced verbatim per-slot, and the SDK emits
// NO compensating write (rollback is the application's responsibility) - exactly one write reaches the wire.
// @verifies CL-ATTR-019
// @relation(CL-ATTR-019, scope=function)
TEST_F(ConnectionImplTest, WriteSurfacesPerSlotResultsWithoutCompensatingWrite)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::WriteResponse response;
  response.results().push_back(ua::StatusCode{ua::Status::Good});
  response.results().push_back(ua::StatusCode{ua::Status::BadUserAccessDenied});
  session->write.set_result(ua::Result<ua::WriteResponse>{std::move(response)});

  const auto result = write_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0].as_status(), ua::Status::Good);
  EXPECT_EQ(result.value().results()[1].as_status(), ua::Status::BadUserAccessDenied)
    << "each slot's StatusCode must be surfaced independently for the application to roll back";
  EXPECT_EQ(session->write.call_count(), 1u)
    << "the SDK must not emit a compensating write - rollback is the application's job";
}

// ---- Method: Call service (CL-METH-001..009) --------------------------------------------------------

// The only Method surface is the Call service: call_async dispatches a CallRequest carrying the caller's
// (objectId, methodId) pair verbatim - the two NodeIds reach the wire un-collapsed.
// @verifies CL-METH-001, CL-METH-002
// @relation(CL-METH-001, CL-METH-002, scope=function)
TEST_F(ConnectionImplTest, CallDispatchesRequestWithObjectAndMethodNodeIds)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallRequest request;
  ua::CallMethodRequest method;
  method.object_id() = NodeId{2, 10};
  method.method_id() = NodeId{3, 20};
  request.methods_to_call().push_back(std::move(method));
  ASSERT_TRUE(call_and_wait(*connection, std::move(request)).is_good());

  ASSERT_EQ(session->call.call_count(), 1u) << "an Active Call must dispatch a CallRequest to the session";
  const auto requests = session->call.requests();
  ASSERT_EQ(requests.size(), 1u);
  ASSERT_EQ(requests[0].methods_to_call().size(), 1u);
  EXPECT_EQ(requests[0].methods_to_call()[0].object_id(), (NodeId{2, 10}));
  EXPECT_EQ(requests[0].methods_to_call()[0].method_id(), (NodeId{3, 20}))
    << "objectId and methodId must reach the wire as two distinct NodeIds";
}

// A server Bad_MethodInvalid propagates to the caller via the standard Result path (the Call always returns
// a result - success or failure - never fire-and-forget).
// @verifies CL-METH-002, CL-METH-004
// @relation(CL-METH-002, CL-METH-004, scope=function)
TEST_F(ConnectionImplTest, CallPropagatesServiceLevelBadMethodInvalid)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->call.set_result(ua::Result<ua::CallResponse>{ua::StatusCode{ua::Status::BadMethodInvalid}});
  const auto result = call_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadMethodInvalid);
}

// inputArguments are forwarded as a positional vector in the caller's order (no reorder/normalisation).
// @verifies CL-METH-003
// @relation(CL-METH-003, scope=function)
TEST_F(ConnectionImplTest, CallForwardsInputArgumentsPositionally)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallRequest request;
  ua::CallMethodRequest method;
  method.input_arguments().push_back(ua::Variant{std::int32_t{10}});
  method.input_arguments().push_back(ua::Variant{std::int32_t{20}});
  method.input_arguments().push_back(ua::Variant{std::int32_t{30}});
  request.methods_to_call().push_back(std::move(method));
  ASSERT_TRUE(call_and_wait(*connection, std::move(request)).is_good());

  const auto requests = session->call.requests();
  ASSERT_EQ(requests.size(), 1u);
  const auto& args = requests[0].methods_to_call()[0].input_arguments();
  ASSERT_EQ(args.size(), 3u);
  ASSERT_NE(args[0].try_as<std::int32_t>(), nullptr);
  EXPECT_EQ(*args[0].try_as<std::int32_t>(), 10);
  EXPECT_EQ(*args[1].try_as<std::int32_t>(), 20);
  EXPECT_EQ(*args[2].try_as<std::int32_t>(), 30) << "argument order must be preserved on the wire";
}

// An empty inputArguments list stays zero-length on the wire (no null placeholders synthesised).
// @verifies CL-METH-003
// @relation(CL-METH-003, scope=function)
TEST_F(ConnectionImplTest, CallForwardsEmptyInputArgumentsAsZeroLength)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallRequest request;
  request.methods_to_call().push_back(ua::CallMethodRequest{});  // no input arguments
  ASSERT_TRUE(call_and_wait(*connection, std::move(request)).is_good());

  const auto requests = session->call.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].methods_to_call()[0].input_arguments().size(), 0u)
    << "empty inputArguments must stay zero-length (no null padding)";
}

// A CallResponse reaches the caller verbatim - the Call resolves 1:1 on the server's response.
// @verifies CL-METH-004
// @relation(CL-METH-004, scope=function)
TEST_F(ConnectionImplTest, CallResolvesWithServerResponse)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallResponse response;
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{ua::Status::Good};
  response.results().push_back(std::move(methodResult));
  session->call.set_result(ua::Result<ua::CallResponse>{std::move(response)});

  const auto result = call_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1u)
    << "the Call must resolve on the server's CallResponse (1:1 pairing)";
  EXPECT_EQ(result.value().results()[0].status_code().as_status(), ua::Status::Good);
}

// On Bad_InvalidArgument the parallel inputArgumentResults array reaches the caller verbatim, so the caller
// can identify which argument(s) failed.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ConnectionImplTest, CallSurfacesPerArgumentInputArgumentResults)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallResponse response;
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{ua::Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{ua::Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{ua::Status::BadTypeMismatch});
  response.results().push_back(std::move(methodResult));
  session->call.set_result(ua::Result<ua::CallResponse>{std::move(response)});

  const auto result = call_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0].status_code().as_status(), ua::Status::BadInvalidArgument);
  const auto& argResults = result.value().results()[0].input_argument_results();
  ASSERT_EQ(argResults.size(), 2u);
  EXPECT_EQ(argResults[0].as_status(), ua::Status::Good);
  EXPECT_EQ(argResults[1].as_status(), ua::Status::BadTypeMismatch)
    << "the per-argument inputArgumentResults must reach the caller verbatim";
}

// On a Good operation status the outputArguments are surfaced verbatim and consumed positionally.
// @verifies CL-METH-006
// @relation(CL-METH-006, scope=function)
TEST_F(ConnectionImplTest, CallSurfacesOutputArgumentsOnGoodStatus)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallResponse response;
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{ua::Status::Good};
  methodResult.output_arguments().push_back(ua::Variant{std::int32_t{42}});
  response.results().push_back(std::move(methodResult));
  session->call.set_result(ua::Result<ua::CallResponse>{std::move(response)});

  const auto result = call_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1u);
  const auto& outputs = result.value().results()[0].output_arguments();
  ASSERT_EQ(outputs.size(), 1u);
  ASSERT_NE(outputs[0].try_as<std::int32_t>(), nullptr);
  EXPECT_EQ(*outputs[0].try_as<std::int32_t>(), 42)
    << "outputArguments must be surfaced verbatim on a Good operation status";
}

// A ByteString input argument reaches the wire un-widened (no ByteString<->Byte[] coercion), so a genuine
// server-side Argument mismatch is not masked by a client "safety" conversion.
// @verifies CL-METH-008
// @relation(CL-METH-008, scope=function)
TEST_F(ConnectionImplTest, CallForwardsByteStringArgumentWithoutCoercion)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallRequest request;
  ua::CallMethodRequest method;
  method.input_arguments().push_back(
    ua::Variant{ua::ByteString{std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{3}}});
  request.methods_to_call().push_back(std::move(method));
  ASSERT_TRUE(call_and_wait(*connection, std::move(request)).is_good());

  const auto requests = session->call.requests();
  ASSERT_EQ(requests.size(), 1u);
  const auto& args = requests[0].methods_to_call()[0].input_arguments();
  ASSERT_EQ(args.size(), 1u);
  EXPECT_TRUE(args[0].is_byte_string()) << "a ByteString arg must stay a ByteString (not widened to Byte[])";
  EXPECT_FALSE(args[0].is_array_of_uint8());
}

// A short inputArguments vector (fewer than a Method might declare) is forwarded verbatim with no null
// padding - the client truncates trailing optional args rather than sending null placeholders.
// @verifies CL-METH-009
// @relation(CL-METH-009, scope=function)
TEST_F(ConnectionImplTest, CallForwardsShortInputArgumentsWithoutPadding)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CallRequest request;
  ua::CallMethodRequest method;
  method.input_arguments().push_back(ua::Variant{std::int32_t{7}});  // a single (leading) argument only
  request.methods_to_call().push_back(std::move(method));
  ASSERT_TRUE(call_and_wait(*connection, std::move(request)).is_good());

  const auto requests = session->call.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].methods_to_call()[0].input_arguments().size(), 1u)
    << "a short inputArguments vector must be forwarded verbatim (no null padding)";
}

// A server Bad_ArgumentsMissing propagates to the caller via the standard Result path.
// @verifies CL-METH-009
// @relation(CL-METH-009, scope=function)
TEST_F(ConnectionImplTest, CallPropagatesBadArgumentsMissing)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->call.set_result(ua::Result<ua::CallResponse>{ua::StatusCode{ua::Status::BadArgumentsMissing}});
  const auto result = call_and_wait(*connection);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadArgumentsMissing);
}

// ---- MonitoredItem: create alignment + delivery semantics (CL-MI-005/006/008/010/022/025/026/029) ---

// A CreateMonitoredItems response with a service-Good header but an EMPTY results array (no 1:1 alignment
// with the single itemsToCreate entry) is rejected with Bad_UnexpectedError, and the optimistically
// registered callback is deregistered.
// @verifies CL-MI-005
// @relation(CL-MI-005, scope=function)
TEST_F(ConnectionImplTest, CreateMonitoredItemRejectsEmptyResultsArray)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CreateMonitoredItemsResponse response;  // service_result Good, but results() left EMPTY
  session->createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(response)});

  const auto result = create_monitored_item_and_wait(*connection, /*subId=*/1, /*handle=*/5);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUnexpectedError)
    << "an empty results[] (no 1:1 alignment with itemsToCreate) must be rejected Bad_UnexpectedError";
  wait_until([&] { return monitored_item_count(*connection) == 0; }, "monitored item deregistered");
}

// A per-item BAD DataValue status (Bad_UserAccessDenied) arriving in a Publish is NON-fatal: it is delivered
// to the callback unchanged and the item is RETAINED (a later Good notification still arrives).
// @verifies CL-MI-006
// @relation(CL-MI-006, scope=function)
TEST_F(ConnectionImplTest, MonitoredItemBadPerItemStatusIsDeliveredAndItemRetained)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::mutex mutex;
  std::vector<ua::DataValue> delivered;
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    subId.value(),
    /*clientHandle=*/5,
    [&](ua::DataValue value)
    {
      std::lock_guard<std::mutex> lock(mutex);
      delivered.push_back(std::move(value));
    }).is_good());

  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{make_publish_with_value(subId.value(),
    /*seq=*/1,
    /*handle=*/5,
    ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}})});
  wait_until(
    [&]
    {
      std::lock_guard<std::mutex> lock(mutex);
      return delivered.size() == 1;
    },
    "the bad-status notification to deliver");

  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to refill");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{make_publish_with_value(subId.value(),
    /*seq=*/2,
    /*handle=*/5,
    ua::DataValue{ua::Variant{std::int32_t{7}}, ua::StatusCode{ua::Status::Good}})});
  wait_until(
    [&]
    {
      std::lock_guard<std::mutex> lock(mutex);
      return delivered.size() == 2;
    },
    "the good-status notification to deliver (item retained)");

  std::lock_guard<std::mutex> lock(mutex);
  ASSERT_TRUE(delivered[0].status().has_value());
  EXPECT_EQ(delivered[0].status()->as_status(), ua::Status::BadUserAccessDenied)
    << "a per-item bad status must be delivered unchanged, not swallowed";
}

// Bad_IndexRangeNoData on a dynamic array arrives in a Publish (not at Create): the DataValue is passed
// through unchanged and the item is retained (a later in-range value still arrives).
// @verifies CL-MI-010
// @relation(CL-MI-010, scope=function)
TEST_F(ConnectionImplTest, MonitoredItemIndexRangeNoDataDeliveredAndItemRetained)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::mutex mutex;
  std::vector<ua::DataValue> delivered;
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    subId.value(),
    /*clientHandle=*/6,
    [&](ua::DataValue value)
    {
      std::lock_guard<std::mutex> lock(mutex);
      delivered.push_back(std::move(value));
    }).is_good());

  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{make_publish_with_value(subId.value(),
    /*seq=*/1,
    /*handle=*/6,
    ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadIndexRangeNoData}})});
  wait_until(
    [&]
    {
      std::lock_guard<std::mutex> lock(mutex);
      return delivered.size() == 1;
    },
    "the Bad_IndexRangeNoData notification to deliver");

  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to refill");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{make_publish_with_value(subId.value(),
    /*seq=*/2,
    /*handle=*/6,
    ua::DataValue{ua::Variant{std::int32_t{99}}, ua::StatusCode{ua::Status::Good}})});
  wait_until(
    [&]
    {
      std::lock_guard<std::mutex> lock(mutex);
      return delivered.size() == 2;
    },
    "the in-range value to deliver (item retained)");

  std::lock_guard<std::mutex> lock(mutex);
  ASSERT_TRUE(delivered[0].status().has_value());
  EXPECT_EQ(delivered[0].status()->as_status(), ua::Status::BadIndexRangeNoData)
    << "Bad_IndexRangeNoData must be passed through in the Publish, not treated as fatal";
}

// After DeleteMonitoredItems removes an item, a late notification for its client handle is silently dropped
// (the client may receive Notifications after a positive delete, and must not misroute them).
// @verifies CL-MI-008
// @relation(CL-MI-008, scope=function)
TEST_F(ConnectionImplTest, DeletedMonitoredItemDropsLateNotification)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::atomic<int> deliveries{0};
  ASSERT_TRUE(create_monitored_item_and_wait(
    *connection, subId.value(), /*clientHandle=*/5, [&](ua::DataValue) { deliveries.fetch_add(1); })
                .is_good());
  wait_until([&] { return monitored_item_count(*connection) == 1; }, "monitored item registered");

  ua::DeleteMonitoredItemsResponse deleteResponse;  // one Good result for the one item deleted
  deleteResponse.results().push_back(StatusCode{Status::Good});
  session->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{std::move(deleteResponse)});
  ASSERT_TRUE(
    delete_monitored_item_and_wait(*connection, subId.value(), /*monitoredItemId=*/500, /*clientHandle=*/5)
      .is_good());
  wait_until([&] { return monitored_item_count(*connection) == 0; }, "monitored item deregistered");

  // A late notification for the now-deleted handle 5 must be dropped (unknown handle), not delivered.
  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{make_publish_with_value(
    subId.value(), /*seq=*/1, /*handle=*/5, ua::DataValue{ua::Variant{std::int32_t{1}}})});

  std::this_thread::sleep_for(40ms);  // give any erroneous delivery time to land
  EXPECT_EQ(deliveries.load(), 0)
    << "a notification for a deleted item's client handle must be silently dropped";
}

// ModifyMonitoredItems surfaces an op-level per-item bad StatusCode (service header Good) to the caller
// without collapsing the batch.
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST_F(ConnectionImplTest, ModifyMonitoredItemsSurfacesPerItemBadResult)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::ModifyMonitoredItemsResponse response;  // service header Good
  ua::MonitoredItemModifyResult item;
  item.status_code() = ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid};
  response.results().push_back(std::move(item));
  session->modifyMonitoredItems.set_result(ua::Result<ua::ModifyMonitoredItemsResponse>{std::move(response)});

  const auto result = modify_monitored_items_and_wait(*connection);
  ASSERT_TRUE(result.is_good()) << "service header Good: the op-level per-item status carries the failure";
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0].status_code().as_status(), ua::Status::BadMonitoredItemIdInvalid)
    << "the op-level per-item StatusCode must reach the caller";
}

// A service-level SetMonitoringMode failure surfaces to the caller WITH its ErrorDetail chain preserved
// (the funnel never discards the detail attached to the status).
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST_F(ConnectionImplTest, SetMonitoringModePropagatesServiceFailureWithErrorDetail)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto detail = std::make_shared<const ua::ErrorDetail>(
    ua::ErrorDetail{.code = "TooManyOps", .summary = "server rejected the request", .source = "test.fake"});
  session->setMonitoringMode.set_result(
    ua::Result<ua::SetMonitoringModeResponse>{ua::StatusCode{ua::Status::BadTooManyOperations, detail}});

  const auto result = set_monitoring_mode_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(result.status_code().shared_detail(), nullptr) << "the ErrorDetail chain must be preserved";
  EXPECT_EQ(result.status_code().shared_detail()->source, "client.tier1.connection.set_monitoring_mode");
  ASSERT_NE(result.status_code().shared_detail()->cause, nullptr);
  EXPECT_EQ(result.status_code().shared_detail()->cause->source, "test.fake");
}

// The Overflow info-bit on a delivered DataValue StatusCode is surfaced to the callback unaltered.
// @verifies CL-MI-025
// @relation(CL-MI-025, scope=function)
TEST_F(ConnectionImplTest, MonitoredItemOverflowInfoBitPreservedToCallback)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::mutex mutex;
  std::vector<ua::DataValue> delivered;
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    subId.value(),
    /*clientHandle=*/5,
    [&](ua::DataValue value)
    {
      std::lock_guard<std::mutex> lock(mutex);
      delivered.push_back(std::move(value));
    }).is_good());

  ua::StatusCode overflowStatus{ua::Status::Good};
  overflowStatus.overflow(true);
  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{make_publish_with_value(subId.value(),
    /*seq=*/1,
    /*handle=*/5,
    ua::DataValue{ua::Variant{std::int32_t{5}}, overflowStatus})});
  wait_until(
    [&]
    {
      std::lock_guard<std::mutex> lock(mutex);
      return delivered.size() == 1;
    },
    "the notification to deliver");

  std::lock_guard<std::mutex> lock(mutex);
  ASSERT_TRUE(delivered[0].status().has_value());
  EXPECT_TRUE(delivered[0].status()->overflow()) << "the Overflow info-bit must reach the callback unaltered";
}

// Notifications are delivered in arrival (queue) order, including two notifications for the SAME item within
// one response: handles [5, 6, 5] must fire the callbacks in exactly that order.
// @verifies CL-MI-026
// @relation(CL-MI-026, scope=function)
TEST_F(ConnectionImplTest, MonitoredItemNotificationsDeliveredInQueueOrder)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::mutex mutex;
  std::vector<std::uint32_t> order;  // records the client handle of each delivery, in fire order
  auto recorder = [&](std::uint32_t handle)
  {
    return [&, handle](ua::DataValue)
    {
      std::lock_guard<std::mutex> lock(mutex);
      order.push_back(handle);
    };
  };
  ASSERT_TRUE(
    create_monitored_item_and_wait(*connection, subId.value(), /*handle=*/5, recorder(5)).is_good());
  ASSERT_TRUE(
    create_monitored_item_and_wait(*connection, subId.value(), /*handle=*/6, recorder(6)).is_good());

  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{
    make_publish_multi(subId.value(), /*seq=*/1, {{5, 111}, {6, 222}, {5, 333}})});
  wait_until(
    [&]
    {
      std::lock_guard<std::mutex> lock(mutex);
      return order.size() == 3;
    },
    "all three notifications to deliver");

  std::lock_guard<std::mutex> lock(mutex);
  EXPECT_EQ(order, (std::vector<std::uint32_t>{5, 6, 5}))
    << "notifications must be delivered in arrival order, including same-item ordering";
}

// SetTriggering surfaces per-link addResults positionally: a bad link result reaches the caller at its index
// without aborting the whole call.
// @verifies CL-MI-029
// @relation(CL-MI-029, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringSurfacesPerLinkResultsPositionally)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::SetTriggeringResponse response;
  response.add_results().push_back(ua::StatusCode{ua::Status::Good});
  response.add_results().push_back(ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid});
  session->setTriggering.set_result(ua::Result<ua::SetTriggeringResponse>{std::move(response)});

  const auto result = set_triggering_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().add_results().size(), 2u);
  EXPECT_EQ(result.value().add_results()[0].as_status(), ua::Status::Good);
  EXPECT_EQ(result.value().add_results()[1].as_status(), ua::Status::BadMonitoredItemIdInvalid)
    << "per-link addResults must be surfaced positionally without aborting the call";
}

// ---- SetTriggering same-Subscription pre-flight (CL-MI-027) ----------------------------------------
//
// OPC UA Part 4 section 5.12.5.1 requires every item in a SetTriggering (the triggering item AND every
// linksToAdd / linksToRemove item) to belong to the SAME Subscription. The by-handles path must
// enforce this LOCALLY before touching the wire: a handle owned by a different Subscription is a
// Bad_InvalidArgument argument error, not a wire request that the server rejects
// Bad_MonitoredItemIdInvalid. Existence is checked BEFORE membership, so a non-live handle keeps its
// Bad_MonitoredItemIdInvalid classification.
//
// Owner routing common to these cases: two live items under sub 100 (trigger 10 -> item 1000,
// add/remove peer 20 -> item 2000) and one live item under a DIFFERENT sub 200 (foreign 30 -> item
// 3000). `session->setTriggering.call_count()` is the wire-suppression oracle.

// A triggering handle owned by a different Subscription fails locally Bad_InvalidArgument and never
// reaches the wire.
// @verifies CL-MI-027
// @relation(CL-MI-027, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringCrossSubscriptionTriggerHandleFailsLocallyWithoutWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/20, /*subscriptionId=*/100, /*monitoredItemId=*/2000);
  owner->register_item(/*clientHandle=*/30, /*subscriptionId=*/200, /*monitoredItemId=*/3000);

  // Trigger handle 30 belongs to sub 200, but the call targets sub 100.
  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/100, /*triggerHandle=*/30, /*addHandles=*/{20}, /*removeHandles=*/{});

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInvalidArgument)
    << "a triggering handle from a different Subscription must fail Bad_InvalidArgument";
  EXPECT_EQ(session->setTriggering.call_count(), 0u)
    << "a cross-Subscription reference must be caught locally, never sent on the wire";
}

// An add-link handle owned by a different Subscription fails locally Bad_InvalidArgument and never
// reaches the wire.
// @verifies CL-MI-027
// @relation(CL-MI-027, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringCrossSubscriptionAddHandleFailsLocallyWithoutWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/30, /*subscriptionId=*/200, /*monitoredItemId=*/3000);

  // Trigger handle 10 is in sub 100; the add handle 30 is in sub 200.
  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/100, /*triggerHandle=*/10, /*addHandles=*/{30}, /*removeHandles=*/{});

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInvalidArgument)
    << "an add-link handle from a different Subscription must fail Bad_InvalidArgument";
  EXPECT_EQ(session->setTriggering.call_count(), 0u)
    << "a cross-Subscription add link must be caught locally, never sent on the wire";
}

// A remove-link handle owned by a different Subscription fails locally Bad_InvalidArgument and never
// reaches the wire.
// @verifies CL-MI-027
// @relation(CL-MI-027, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringCrossSubscriptionRemoveHandleFailsLocallyWithoutWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/30, /*subscriptionId=*/200, /*monitoredItemId=*/3000);

  // Trigger handle 10 is in sub 100; the remove handle 30 is in sub 200.
  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/100, /*triggerHandle=*/10, /*addHandles=*/{}, /*removeHandles=*/{30});

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInvalidArgument)
    << "a remove-link handle from a different Subscription must fail Bad_InvalidArgument";
  EXPECT_EQ(session->setTriggering.call_count(), 0u)
    << "a cross-Subscription remove link must be caught locally, never sent on the wire";
}

// The green guard: when the trigger AND every add/remove handle belong to the target Subscription, the
// call proceeds to the wire (the SetTriggering request IS issued).
// @verifies CL-MI-027
// @relation(CL-MI-027, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringSameSubscriptionHandlesReachTheWire)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/20, /*subscriptionId=*/100, /*monitoredItemId=*/2000);

  // All handles belong to sub 100.
  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/100, /*triggerHandle=*/10, /*addHandles=*/{20}, /*removeHandles=*/{});

  EXPECT_TRUE(result.is_good()) << "an all-same-Subscription SetTriggering must succeed";
  EXPECT_EQ(session->setTriggering.call_count(), 1u)
    << "an all-same-Subscription SetTriggering must reach the wire exactly once";
}

// OPC UA Part 4 section 5.12.5.2 Table 78: the server processes linksToRemove before linksToAdd. Preserve the
// caller's positional order in both arrays, including when the same item is removed and re-added.
// Falsifiability: swapping the add/remove request population makes both assertions fail.
// @verifies CL-MI-028
// @relation(CL-MI-028, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringEncodesRemoveAndAddListsInSpecifiedOrder)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/20, /*subscriptionId=*/100, /*monitoredItemId=*/2000);
  owner->register_item(/*clientHandle=*/30, /*subscriptionId=*/100, /*monitoredItemId=*/3000);

  const auto result = set_triggering_by_handles_and_wait(*connection,
    /*subscriptionId=*/100,
    /*triggerHandle=*/10,
    /*addHandles=*/{20, 30},
    /*removeHandles=*/{20});
  ASSERT_TRUE(result.is_good());

  const auto requests = session->setTriggering.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests.front().links_to_remove(), (ua::Array<ua::IntegerId>{2000}));
  EXPECT_EQ(requests.front().links_to_add(), (ua::Array<ua::IntegerId>{2000, 3000}));
}

// Existence precedence: a non-live (unregistered) handle still fails Bad_MonitoredItemIdInvalid - the
// membership check must not reclassify a missing handle as Bad_InvalidArgument.
// @verifies CL-MI-027
// @relation(CL-MI-027, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringNonLiveHandleFailsMonitoredItemIdInvalid)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  // Handle 999 is never registered.
  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/100, /*triggerHandle=*/999, /*addHandles=*/{}, /*removeHandles=*/{});

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadMonitoredItemIdInvalid)
    << "a non-live handle must fail Bad_MonitoredItemIdInvalid (existence precedence)";
  EXPECT_EQ(session->setTriggering.call_count(), 0u)
    << "a non-live handle must be caught locally, never sent on the wire";
}

// ---- SetTriggering per-link result surfacing (CL-MI-029) -------------------------------------------
//
// OPC UA Part 4 section 5.12.5.2 Table 78: SetTriggering returns a StatusCode array for linksToAdd and one
// for linksToRemove, each positionally paired with its input list. A per-link Bad must be surfaced at its
// index WITHOUT aborting the call - the by-handles path now delivers the full per-link arrays in a GOOD
// Result<SetTriggeringResult>, not a collapsed VoidResult. Falsifiability: the OLD flatten returned a
// BAD VoidResult on any per-link bad, so `ASSERT_TRUE(result.is_good())` below fails against it.
//
// @verifies CL-MI-029
// @relation(CL-MI-029, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringByHandlesSurfacesPerLinkResultsPositionally)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  // All under the SAME Subscription 100: trigger 10, two add links 20/30, one remove link 40.
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/20, /*subscriptionId=*/100, /*monitoredItemId=*/2000);
  owner->register_item(/*clientHandle=*/30, /*subscriptionId=*/100, /*monitoredItemId=*/3000);
  owner->register_item(/*clientHandle=*/40, /*subscriptionId=*/100, /*monitoredItemId=*/4000);

  // Mixed per-link outcome: add link 20 -> Good, add link 30 -> Bad; the single remove link -> Good.
  ua::SetTriggeringResponse response;
  response.add_results().push_back(ua::StatusCode{ua::Status::Good});
  response.add_results().push_back(ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid});
  response.remove_results().push_back(ua::StatusCode{ua::Status::Good});
  session->setTriggering.set_result(ua::Result<ua::SetTriggeringResponse>{std::move(response)});

  const auto result = set_triggering_by_handles_and_wait(*connection,
    /*subscriptionId=*/100,
    /*triggerHandle=*/10,
    /*addHandles=*/{20, 30},
    /*removeHandles=*/{40});

  ASSERT_TRUE(result.is_good())
    << "a per-link Bad must NOT make the call fail (CL-MI-029): the outer Result stays Good";
  ASSERT_EQ(result.value().addResults.size(), 2u) << "addResults must pair with linksToAdd input order";
  EXPECT_EQ(result.value().addResults[0].as_status(), ua::Status::Good);
  EXPECT_EQ(result.value().addResults[1].as_status(), ua::Status::BadMonitoredItemIdInvalid)
    << "a per-link Bad must be surfaced at its input index, not collapsed away";
  ASSERT_EQ(result.value().removeResults.size(), 1u)
    << "removeResults must pair with linksToRemove input order";
  EXPECT_EQ(result.value().removeResults[0].as_status(), ua::Status::Good);
}

// A service-level fault (ResponseHeader.serviceResult bad) makes the whole call bad (unchanged behaviour):
// per-link surfacing applies only once the service itself succeeded.
// @verifies CL-MI-029
// @relation(CL-MI-029, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringByHandlesServiceLevelBadMakesResultBad)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);
  owner->register_item(/*clientHandle=*/20, /*subscriptionId=*/100, /*monitoredItemId=*/2000);

  ua::SetTriggeringResponse response;
  response.response_header().service_result() = ua::StatusCode{ua::Status::BadSubscriptionIdInvalid};
  session->setTriggering.set_result(ua::Result<ua::SetTriggeringResponse>{std::move(response)});

  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/100, /*triggerHandle=*/10, /*addHandles=*/{20}, /*removeHandles=*/{});

  ASSERT_TRUE(result.is_bad()) << "a service-level fault must fail the whole call";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSubscriptionIdInvalid);
}

// ---- Session: Cancel (CL-SESS-024) -----------------------------------------------------------------

// The cancelCount from the CancelResponse is surfaced to the caller verbatim. This also exercises the
// full Cancel wiring through the ConnectionImpl funnel -> tier-0 session -> CancelResponse routed back
// to the caller, i.e. Cancel is implemented end-to-end (CL-SESS-018).
// NOTE: this routes the CancelResponse itself; CL-SESS-023 (a *cancelled outstanding request's* callback
// receiving Bad_RequestCancelledByClient) is a distinct routing obligation covered by
// ClientSecureChannelInboundDecodeTests.CancelledOutstandingRequestReceivesRequestCancelledByClient.
// The advisory-on-count-divergence half is covered independently below with held requests and an attached
// ConnectionObserver; this test isolates the response-surfacing half.
// @verifies CL-SESS-018, CL-SESS-024
// @relation(CL-SESS-018, CL-SESS-024, scope=function)
TEST_F(ConnectionImplTest, CancelSurfacesCancelCountToCaller)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::CancelResponse response;
  response.cancel_count() = 3;
  session->cancel.set_result(ua::Result<ua::CancelResponse>{std::move(response)});

  const auto result = cancel_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().cancel_count(), 3u) << "cancelCount must be surfaced to the caller";
}

// ---- Subscription: burst handling + modify/publishing-mode/demux (CL-SUB-001/011/013/014/016/017) ---

// The client is prepared for Publish responses arriving faster than the publishing interval: multiple
// distinct back-to-back Publish responses within one interval are all processed and dispatched.
// @verifies CL-SUB-001
// @relation(CL-SUB-001, scope=function)
// @relation(AC-CL-SUB-001-01, scope=function)
TEST_F(ConnectionImplTest, PublishBurstWithinIntervalAllProcessed)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto subId = create_subscription_and_wait(*connection);
  ASSERT_TRUE(subId.is_good());

  std::mutex mutex;
  std::vector<std::int32_t> delivered;
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    subId.value(),
    /*clientHandle=*/5,
    [&](ua::DataValue value)
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (auto asInt = value.value().try_as<std::int32_t>())
        delivered.push_back(*asInt);
    }).is_good());

  session->publish.set_hold(true);
  // Fire three distinct in-order Publish responses back-to-back (no interval wait between them). All three
  // must be processed - the pump has no per-interval rate limit.
  for (std::uint32_t seq = 1; seq <= 3; ++seq)
  {
    wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to have a Publish in flight");
    auto response =
      make_publish_datachange(subId.value(), seq, /*clientHandle=*/5, static_cast<std::int32_t>(seq * 111));
    response.more_notifications() = seq == 1;
    session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(response)});
    wait_until(
      [&]
      {
        std::lock_guard<std::mutex> lock(mutex);
        return delivered.size() == seq;
      },
      "the burst notification to deliver");
  }

  std::lock_guard<std::mutex> lock(mutex);
  EXPECT_EQ(delivered, (std::vector<std::int32_t>{111, 222, 333}))
    << "every back-to-back Publish response in the burst must be processed in order";
}

// A successful ModifySubscription surfaces the response's revised values to the caller and does NOT retry
// (exactly one ModifySubscription reaches the wire).
// @verifies CL-SUB-011
// @relation(CL-SUB-011, scope=function)
TEST_F(ConnectionImplTest, ModifySubscriptionSurfacesRevisedValuesWithoutRetry)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::ModifySubscriptionResponse response;
  response.revised_publishing_interval() = 250.0;
  session->modifySubscription.set_result(ua::Result<ua::ModifySubscriptionResponse>{std::move(response)});

  const auto result =
    modify_subscription_and_wait(*connection, /*subscriptionId=*/7, /*requestedInterval=*/100.0);
  ASSERT_TRUE(result.is_good());
  EXPECT_DOUBLE_EQ(result.value().revised_publishing_interval(), 250.0)
    << "the revised publishing interval must be surfaced to the caller";
  EXPECT_EQ(session->modifySubscription.call_count(), 1u) << "ModifySubscription must not be retried";
}

// ModifySubscription returning Bad_SubscriptionIdInvalid surfaces to the caller WITHOUT retrying.
// @verifies CL-SUB-013
// @relation(CL-SUB-013, scope=function)
TEST_F(ConnectionImplTest, ModifySubscriptionSurfacesBadSubscriptionIdInvalidWithoutRetry)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->modifySubscription.set_result(
    ua::Result<ua::ModifySubscriptionResponse>{ua::StatusCode{ua::Status::BadSubscriptionIdInvalid}});

  const auto result =
    modify_subscription_and_wait(*connection, /*subscriptionId=*/7, /*requestedInterval=*/100.0);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSubscriptionIdInvalid);
  EXPECT_EQ(session->modifySubscription.call_count(), 1u)
    << "Bad_SubscriptionIdInvalid must be surfaced without retrying the modify";
}

// SetPublishingMode honours the per-Subscription results[] even when the service-level result is Good:
// results[0] = Bad_SubscriptionIdInvalid reaches the caller.
// @verifies CL-SUB-014
// @relation(CL-SUB-014, scope=function)
TEST_F(ConnectionImplTest, SetPublishingModeHonoursPerItemResultWhenServiceGood)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::SetPublishingModeResponse response;  // service header Good
  response.results().push_back(ua::StatusCode{ua::Status::BadSubscriptionIdInvalid});
  session->setPublishingMode.set_result(ua::Result<ua::SetPublishingModeResponse>{std::move(response)});

  const auto result =
    set_publishing_mode_and_wait(*connection, /*subscriptionId=*/7, /*publishingEnabled=*/true);
  ASSERT_TRUE(result.is_good()) << "service header Good: the per-item results[] carries the per-sub outcome";
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0].as_status(), ua::Status::BadSubscriptionIdInvalid)
    << "the per-Subscription results[i] must be honoured even when the service result is Good";
}

// Publish notifications are demultiplexed to the correct monitored-item callback across MULTIPLE
// Subscriptions on one Connection: sub 100's handle 5 and sub 200's handle 6 each reach only their own
// callback.
// @verifies CL-SUB-016
// @relation(CL-SUB-016, scope=function)
TEST_F(ConnectionImplTest, NotificationsDemultiplexedByClientHandleAcrossSubscriptions)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  std::atomic<std::int32_t> deliveredA{-1};
  std::atomic<std::int32_t> deliveredB{-1};
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/100)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    /*subscriptionId=*/100,
    /*clientHandle=*/5,
    [&](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        deliveredA.store(*asInt);
    }).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/200)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    /*subscriptionId=*/200,
    /*clientHandle=*/6,
    [&](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        deliveredB.store(*asInt);
    }).is_good());

  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{
    make_publish_datachange(/*subscriptionId=*/100, /*seq=*/1, /*clientHandle=*/5, /*value=*/111)});
  wait_until([&] { return deliveredA.load() == 111; }, "sub 100's handle 5 notification to deliver");

  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to refill");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{
    make_publish_datachange(/*subscriptionId=*/200, /*seq=*/1, /*clientHandle=*/6, /*value=*/222)});
  wait_until([&] { return deliveredB.load() == 222; }, "sub 200's handle 6 notification to deliver");

  EXPECT_EQ(deliveredA.load(), 111) << "sub 100's handle must receive only its own notification";
  EXPECT_EQ(deliveredB.load(), 222) << "sub 200's handle must receive only its own notification";
}

// A registered clientHandle cannot bypass the response-level Subscription demultiplexer. An unknown,
// nonzero subscriptionId classifies Invalid and the delivery gate must drop its payload.
// @verifies CL-SUB-016
// @relation(CL-SUB-016, scope=function)
TEST_F(ConnectionImplTest, UnknownSubscriptionDoesNotDeliverRegisteredClientHandle)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  std::atomic<std::int32_t> delivered{-1};
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/100)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    /*subscriptionId=*/100,
    /*clientHandle=*/5,
    [&](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        delivered.store(*asInt);
    }).is_good());

  session->publish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{
    make_publish_datachange(/*subscriptionId=*/999, /*seq=*/1, /*clientHandle=*/5, /*value=*/333)});
  wait_until([&] { return session->publish.requests().size() >= 3; },
    "the unknown-Subscription response to be classified and the pump refilled");

  EXPECT_EQ(delivered.load(), -1)
    << "a registered clientHandle under an unknown subscriptionId must not reach its callback";
}

// Per-Subscription sequence trackers are isolated: a gap on Subscription A triggers a Republish for A ONLY,
// and Subscription B's in-order delivery is unaffected (its tracker never saw A's gap).
// @verifies CL-SUB-017
// @relation(CL-SUB-017, scope=function)
TEST_F(ConnectionImplTest, SequenceGapOnOneSubscriptionDoesNotAffectAnother)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/100)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  ASSERT_TRUE(
    create_monitored_item_and_wait(*connection, /*subscriptionId=*/100, /*clientHandle=*/5).is_good());
  std::atomic<std::int32_t> deliveredB{-1};
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/200)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  ASSERT_TRUE(create_monitored_item_and_wait(*connection,
    /*subscriptionId=*/200,
    /*clientHandle=*/6,
    [&](ua::DataValue value)
    {
      if (auto asInt = value.value().try_as<std::int32_t>())
        deliveredB.store(*asInt);
    }).is_good());

  session->publish.set_hold(true);
  session->republish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to issue a Publish");

  // Sub 100 (A): a Publish at seq 3 (expects seq 1) is a gap -> a Republish is started for sub 100.
  ua::PublishResponse gap;
  gap.subscription_id() = 100;
  gap.notification_message().sequence_number() = 3;
  session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(gap)});
  wait_until([&] { return session->republish.pending_count() >= 1; }, "the gap-drain to Republish");
  {
    const auto requests = session->republish.requests();
    ASSERT_GE(requests.size(), 1u);
    EXPECT_EQ(requests.back().subscription_id(), 100u) << "the gap on A must Republish A, not B";
  }

  // Sub 200 (B): an in-order Publish at seq 1 must be delivered normally - A's gap must not have advanced
  // B's tracker (which would misclassify B's seq 1 as a duplicate and drop it).
  wait_until([&] { return session->publish.pending_count() >= 1; }, "the pump to refill");
  session->publish.fire_next(ua::Result<ua::PublishResponse>{
    make_publish_datachange(/*subscriptionId=*/200, /*seq=*/1, /*clientHandle=*/6, /*value=*/555)});
  wait_until([&] { return deliveredB.load() == 555; }, "sub 200's in-order notification to deliver");

  // End A's drain and confirm no Republish ever targeted B (its tracker stayed isolated).
  session->republish.fire_next(ua::Result<ua::RepublishResponse>{StatusCode{Status::BadMessageNotAvailable}});
  for (const auto& request : session->republish.requests())
  {
    EXPECT_EQ(request.subscription_id(), 100u) << "a gap on A must never trigger a Republish on B";
  }
}

// Concurrent gaps require independent per-Subscription recovery flags: holding A's Republish in flight must
// not suppress B from starting its own Republish.
// @verifies CL-SUB-017
// @relation(CL-SUB-017, scope=function)
TEST_F(ConnectionImplTest, ConcurrentSequenceGapsStartIndependentRepublishes)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/100)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{make_create_sub_response(/*id=*/200)});
  ASSERT_TRUE(create_subscription_and_wait(*connection).is_good());

  session->publish.set_hold(true);
  session->republish.set_hold(true);
  wait_until([&] { return session->publish.pending_count() >= 2; }, "the two-request Publish window");

  ua::PublishResponse gapA;
  gapA.subscription_id() = 100;
  gapA.notification_message().sequence_number() = 3;
  session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(gapA)});
  wait_until([&] { return session->republish.requests().size() >= 1; }, "Subscription A to Republish");

  ua::PublishResponse gapB;
  gapB.subscription_id() = 200;
  gapB.notification_message().sequence_number() = 3;
  session->publish.fire_next(ua::Result<ua::PublishResponse>{std::move(gapB)});
  wait_until([&] { return session->republish.requests().size() >= 2; },
    "Subscription B to start an independent Republish while A remains in flight");

  const auto requests = session->republish.requests();
  ASSERT_EQ(requests.size(), 2u);
  EXPECT_EQ(requests[0].subscription_id(), 100u);
  EXPECT_EQ(requests[1].subscription_id(), 200u);
}

// ---- View: Browse / TranslateBrowsePaths per-result surfacing (CL-VIEW-004/006/016) ----------------

// A Browse response surfaces each per-node BrowseResult.statusCode independently of the ServiceResult: a
// single bad node does not invalidate the rest of the batch.
// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, scope=function)
TEST_F(ConnectionImplTest, BrowseSurfacesPerNodeStatusIndependentlyOfServiceResult)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::BrowseResponse response;  // service header Good
  ua::BrowseResult good;
  good.status_code() = ua::StatusCode{ua::Status::Good};
  ua::BrowseResult bad;
  bad.status_code() = ua::StatusCode{ua::Status::BadNodeIdUnknown};
  response.results().push_back(std::move(good));
  response.results().push_back(std::move(bad));
  session->browse.set_result(ua::Result<ua::BrowseResponse>{std::move(response)});

  const auto result = browse_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0].status_code().as_status(), ua::Status::Good);
  EXPECT_EQ(result.value().results()[1].status_code().as_status(), ua::Status::BadNodeIdUnknown)
    << "each per-node BrowseResult.statusCode must surface independently of the ServiceResult";
}

// A service-level Browse failure is surfaced for the whole batch (the batch was rejected as a whole).
// @verifies CL-VIEW-006
// @relation(CL-VIEW-006, scope=function)
TEST_F(ConnectionImplTest, BrowseSurfacesServiceLevelFailureForBatch)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::BrowseResponse response;
  response.response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyOperations};
  session->browse.set_result(ua::Result<ua::BrowseResponse>{std::move(response)});

  const auto result = browse_and_wait(*connection);
  // CL-DIAG-005: the funnel now collapses a service-level batch failure onto the Result (with the marker).
  // CL-VIEW-006 still holds: the whole-batch failure surfaces - now as a bad Result carrying the exact
  // status.
  ASSERT_TRUE(result.is_bad()) << "a service-level Browse failure must surface for the whole batch";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(result.status_code().shared_detail(), nullptr) << "with the wire-crossing marker attached";
  EXPECT_EQ(result.status_code().shared_detail()->source, "client.tier1.connection.browse");
  ASSERT_NE(result.status_code().shared_detail()->cause, nullptr);
  EXPECT_EQ(result.status_code().shared_detail()->cause->source, "client.tier0.session.decode_diagnostic");
}

// A TranslateBrowsePaths response surfaces each per-path BrowsePathResult.statusCode independently: one bad
// path does not invalidate the others.
// @verifies CL-VIEW-016
// @relation(CL-VIEW-016, scope=function)
TEST_F(ConnectionImplTest, TranslateBrowsePathsSurfacesPerPathStatusIndependently)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  ua::TranslateBrowsePathsToNodeIdsResponse response;  // service header Good
  ua::BrowsePathResult good;
  good.status_code() = ua::StatusCode{ua::Status::Good};
  ua::BrowsePathResult bad;
  bad.status_code() = ua::StatusCode{ua::Status::BadNoMatch};
  response.results().push_back(std::move(good));
  response.results().push_back(std::move(bad));
  session->translateBrowsePaths.set_result(
    ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  const auto result = translate_browse_paths_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0].status_code().as_status(), ua::Status::Good);
  EXPECT_EQ(result.value().results()[1].status_code().as_status(), ua::Status::BadNoMatch)
    << "each per-path BrowsePathResult.statusCode must surface independently of the ServiceResult";
}

// ---- Reconnect: no Publish during the Republish loop; resume after Bad_MessageNotAvailable (CL-RECONN-007)

// During a reconnect the Publish pump is halted for the whole outage: a Publish that completes while
// Reconnecting does NOT refill the pump (no Publish interleaves the Republish loop), and the pump resumes
// only after the loop terminates (Bad_MessageNotAvailable) and the Connection returns to Active.
// @verifies CL-RECONN-007
// @relation(CL-RECONN-007, scope=function)
TEST_F(ConnectionImplTest, PublishPumpHaltsDuringRepublishLoopAndResumesAfterActive)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Park Publish BEFORE creating the Subscription. Creating it starts an always-refilling pump; enabling
  // hold afterward races that pump and can misclassify an already-queued Active-state Publish as an outage
  // Publish. With the interface parked first, the initial fill is deterministic and every later call is
  // caused by an explicitly fired response.
  session->publish.set_hold(true);
  seed_subscription_with_item(*connection, *session, /*subId=*/77, /*clientHandle=*/5);
  constexpr std::size_t expectedInitialPublishes = 2;  // minimum always-on pipeline target (CL-SUB-003)
  wait_until([&] { return session->publish.pending_count() == expectedInitialPublishes; },
    "the pump to complete its initial fill");
  const auto publishesBeforeOutage = session->publish.call_count();
  ASSERT_EQ(publishesBeforeOutage, expectedInitialPublishes);

  // Enter the outage: the pump is halted.
  TA::reconnect_notify_reconnecting(*connection);
  wait_until(
    [&] { return TA::snapshot(*connection).state == ConnectionState::Reconnecting; }, "Reconnecting");

  // A parked Publish now COMPLETES during the outage. With the pump halted (and the Active-gate closed) this
  // must NOT drive a refill - no new Publish is issued.
  session->publish.fire_next(ua::Result<ua::PublishResponse>{ua::PublishResponse{}});
  TA::snapshot(*connection);  // ordering barrier: the completion has been processed on the strand
  EXPECT_EQ(session->publish.call_count(), publishesBeforeOutage)
    << "no Publish may be issued while Reconnecting (the Republish loop must not be interleaved with "
       "Publish)";

  // Drive the reconnect handshake + the preserved-session Republish drain, which terminates on
  // Bad_MessageNotAvailable. No Publish is issued across the whole recover window.
  ASSERT_TRUE(run_open(*connection).is_good());
  ASSERT_TRUE(run_activate(*connection).is_good());  // existing session re-activates (preserved)
  session->republish.set_result(
    ua::Result<ua::RepublishResponse>{StatusCode{Status::BadMessageNotAvailable}});
  ASSERT_TRUE(run_recover(*connection, SubscriptionRecovery::TransferThenRecreate).is_good());
  EXPECT_GE(session->republish.call_count(), 1u) << "the Republish drain must have run during recovery";
  EXPECT_EQ(session->publish.call_count(), publishesBeforeOutage)
    << "no Publish may be issued during the Republish loop";

  // Return to Active: the pump resumes and issues a fresh Publish (recovery is complete).
  ASSERT_TRUE(run_commit(*connection).is_good());
  TA::reconnect_notify_active(*connection);
  wait_until([&] { return session->publish.call_count() > publishesBeforeOutage; },
    "the Publish pump to resume after returning to Active");
}

// ============================================================================================
// ErrorDetail propagation (section 3.31 / CL-DIAG-001) and multi-Connection isolation (section 3.12.10 /
// CL-MULTI-*) and single-Session-per-Connection (section 3.12.9 / CL-SESS-029).
// ============================================================================================

// A tier-1 Standard wrap preserves the complete upstream ErrorDetail as its cause.
// @verifies CL-DIAG-001
// @relation(CL-DIAG-001, scope=function)
TEST_F(ConnectionImplTest, WireOpForwardPreservesUpstreamErrorDetailSource)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Script the tier-0 write to fail with a bad status carrying a server-side ErrorDetail (distinctive source
  // tag so a replacing wrap is detectable). make_error_detail(code, summary, source) stores arg 3 in mSource.
  session->write.set_result(ua::Result<ua::WriteResponse>{StatusCode{
    Status::BadServiceUnsupported, ua::make_error_detail("BadServiceUnsupported", "Probe", "server.probe")}});

  const auto result = write_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());
  auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "the forwarded bad Result must retain the upstream ErrorDetail chain";
  EXPECT_EQ(detail->source, "client.tier1.connection.write");
  ASSERT_NE(detail->cause, nullptr) << "the Standard tier-1 wrap must retain the upstream detail";
  EXPECT_EQ(detail->cause->source, "server.probe");
}

// Two independent Connection instances (one Client's worth) reach Active with DISTINCT session ids, and
// closing one leaves the other fully live: still Active and still able to service a wire op. Falsifiable:
// cross-Connection state pollution would flip B out of Active (or fail B's write) when A is closed.
// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST_F(ConnectionImplTest, TwoIndependentConnectionsClosingOneLeavesOtherActive)
{
  auto sessionA = std::make_shared<FakeSessionOps>();
  sessionA->set_session_id(NodeId{3, 1});
  auto reopenA = std::make_shared<FakeReopen>();
  auto connectionA = make_connection(sessionA, reopenA);

  auto sessionB = std::make_shared<FakeSessionOps>();
  sessionB->set_session_id(NodeId{3, 2});
  auto reopenB = std::make_shared<FakeReopen>();
  auto connectionB = make_connection(sessionB, reopenB);

  ASSERT_TRUE(start_and_wait(*connectionA).is_good());
  ASSERT_TRUE(start_and_wait(*connectionB).is_good());
  ASSERT_EQ(connectionA->info()->state, ConnectionState::Active);
  ASSERT_EQ(connectionB->info()->state, ConnectionState::Active);
  EXPECT_NE(connectionA->info()->sessionId, connectionB->info()->sessionId)
    << "two independent Connections must carry distinct session ids";

  ASSERT_TRUE(close_and_wait(*connectionA).is_good());
  EXPECT_EQ(connectionB->info()->state, ConnectionState::Active)
    << "closing one Connection must not disturb the other's lifecycle state";
  EXPECT_TRUE(write_and_wait(*connectionB).is_good())
    << "the surviving Connection must still service wire ops after its peer closes";
}

// Per-Connection strand isolation: Connection A hung mid-reconnect (its open-secure-channel completion is
// parked and never fires) does NOT stall Connection B - B services a write promptly. Falsifiable: a shared
// (Client-wide) strand would let A's parked reconnect step block B's write, hanging write_and_wait(B).
// @verifies CL-MULTI-002
// @relation(CL-MULTI-002, scope=function)
TEST_F(ConnectionImplTest, OneConnectionHungInReopenDoesNotStallAnother)
{
  auto sessionA = std::make_shared<FakeSessionOps>();
  auto reopenA = std::make_shared<FakeReopen>();
  reopenA->set_hold(true);  // park A's open-channel yield so A's reconnect step hangs, never completing
  auto connectionA = make_connection(sessionA, reopenA);

  auto sessionB = std::make_shared<FakeSessionOps>();
  auto reopenB = std::make_shared<FakeReopen>();
  auto connectionB = make_connection(sessionB, reopenB);
  ASSERT_TRUE(start_and_wait(*connectionB).is_good());

  // Drive A into a hung open-channel step; wait_for_reopen_pending confirms A is genuinely parked.
  TA::reconnect_open_secure_channel(*connectionA, [](VoidResult) {});
  wait_for_reopen_pending(*reopenA, 1);

  // B must service a wire op despite A being stuck mid-reconnect (independent per-Connection strands).
  EXPECT_TRUE(write_and_wait(*connectionB).is_good())
    << "Connection B must remain responsive while Connection A is hung in reopen";
  EXPECT_EQ(sessionB->write.call_count(), 1u) << "B's write must have dispatched to B's own session";
}

// The architectural half of per-Connection isolation: each ConnectionImpl construction must allocate a
// distinct strand serialization domain, even when both use the same underlying executor.
// @verifies CL-MULTI-002
// @relation(CL-MULTI-002, scope=function)
TEST_F(ConnectionImplTest, ConnectionsOnSameExecutorOwnDistinctStrands)
{
  auto connectionA = make_connection(std::make_shared<FakeSessionOps>(), std::make_shared<FakeReopen>());
  auto connectionB = make_connection(std::make_shared<FakeSessionOps>(), std::make_shared<FakeReopen>());

  EXPECT_TRUE(TA::have_distinct_strands(*connectionA, *connectionB))
    << "each Connection must own its own strand rather than a Client-wide serialization domain";
}

// Per-Connection SecureChannel/Session/state isolation: each Connection's published info reflects ITS OWN
// bootstrap NamespaceArray length and ITS OWN session id, with no cross-bleed. Falsifiable: shared client
// state would make both Connections report the same namespaceCount / sessionId.
// @verifies CL-MULTI-003
// @relation(CL-MULTI-003, scope=function)
TEST_F(ConnectionImplTest, EachConnectionReflectsItsOwnNamespaceCountAndSessionId)
{
  // Connection A: a 3-URI NamespaceArray + session id {3, 1}.
  auto sessionA = std::make_shared<FakeSessionOps>();
  sessionA->set_session_id(NodeId{3, 1});
  sessionA->read.set_result(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response(
    {"http://opcfoundation.org/UA/", "urn:a:one", "urn:a:two"})});
  auto reopenA = std::make_shared<FakeReopen>();
  auto connectionA = make_connection(sessionA, reopenA);

  // Connection B: a 5-URI NamespaceArray + session id {3, 2}.
  auto sessionB = std::make_shared<FakeSessionOps>();
  sessionB->set_session_id(NodeId{3, 2});
  sessionB->read.set_result(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response(
    {"http://opcfoundation.org/UA/", "urn:b:one", "urn:b:two", "urn:b:three", "urn:b:four"})});
  auto reopenB = std::make_shared<FakeReopen>();
  auto connectionB = make_connection(sessionB, reopenB);

  ASSERT_TRUE(start_and_wait(*connectionA).is_good());
  ASSERT_TRUE(start_and_wait(*connectionB).is_good());

  EXPECT_EQ(connectionA->info()->namespaceCount, 3u) << "A must reflect its own 3-URI NamespaceArray";
  EXPECT_EQ(connectionB->info()->namespaceCount, 5u) << "B must reflect its own 5-URI NamespaceArray";
  EXPECT_EQ(connectionA->info()->sessionId, (NodeId{3, 1})) << "A must report its own session id";
  EXPECT_EQ(connectionB->info()->sessionId, (NodeId{3, 2})) << "B must report its own session id";
}

// A Connection maintains exactly ONE Session across its lifetime: a PRESERVING reconnect (open a fresh
// channel, re-activate the EXISTING session on it, commit) keeps the same installed session interface and the
// same published session id - it does not create a second Session. Falsifiable: a reconnect that swapped in
// a new session (or re-keyed the id) would change the installed interface identity or the session id.
// @verifies CL-SESS-029
// @relation(CL-SESS-029, scope=function)
TEST_F(ConnectionImplTest, PreservingReconnectKeepsTheSameSingleSession)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->set_session_id(NodeId{3, 55});
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto sessionIdBefore = connection->info()->sessionId;
  ASSERT_EQ(TA::session_ops(*connection).get(), static_cast<SessionOps*>(session.get()))
    << "the single installed session is the one the connection bootstrapped with";

  // A PRESERVING reconnect: open a fresh channel, re-activate the EXISTING session on it (Good - no rebind),
  // then commit. mPendingSession stays null throughout, so no second Session is created.
  ASSERT_TRUE(run_open(*connection).is_good());
  ASSERT_TRUE(run_activate(*connection).is_good());
  ASSERT_TRUE(run_commit(*connection).is_good());

  EXPECT_EQ(TA::session_ops(*connection).get(), static_cast<SessionOps*>(session.get()))
    << "exactly one Session is installed across the lifetime - the same interface, not a replacement";
  EXPECT_EQ(connection->info()->sessionId, sessionIdBefore)
    << "a preserving reconnect keeps the same session id (no new Session created)";
}

// ============================================================================================================
// CL-BASEDIAG-001 - surface server DiagnosticInfo on the general response funnel (invoke_wire_op wrap).
//
// A received ResponseHeader.serviceDiagnostics on the general wire-response path is decoded (via the BUILT
// DiagnosticInfoDecoder) and surfaced to the ConnectionObserver: on_error_chain for a bad service_result,
// on_advisory_diagnostic for a good one. Strict no-op when serviceDiagnostics is null (returnDiagnostics=0
// default). These drive the REAL read/browse funnel through the fake tier-0 interface with a crafted header.
// ============================================================================================================

/// Thread-safe fake ConnectionObserver: the sink delivers hooks on its own delivery strand (a runner thread),
/// so the counters are atomic and the captured chain / terminal / tag are mutex-guarded.
class RecordingConnectionObserver : public ua::client::ConnectionObserver
{
public:
  std::atomic<int> errorChainCalls{0};
  std::atomic<int> advisoryCalls{0};

  void on_error_chain(const ua::client::Connection&, ua::StatusCode terminalCode,
    std::shared_ptr<const ua::ErrorDetail> chain, std::string_view operationTag) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastTerminal = terminalCode;
      mLastChain = std::move(chain);
      mLastTag = std::string{operationTag};
    }
    ++errorChainCalls;
  }

  void on_advisory_diagnostic(
    const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastAdvisory = std::move(detail);
    }
    ++advisoryCalls;
  }

  ua::StatusCode last_terminal() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastTerminal;
  }

  std::shared_ptr<const ua::ErrorDetail> last_chain() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastChain;
  }

  std::string last_tag() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastTag;
  }

  std::shared_ptr<const ua::ErrorDetail> last_advisory() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastAdvisory;
  }

private:
  mutable std::mutex mMutex;
  ua::StatusCode mLastTerminal{};
  std::shared_ptr<const ua::ErrorDetail> mLastChain;
  std::string mLastTag;
  std::shared_ptr<const ua::ErrorDetail> mLastAdvisory;
};

/// Counts links in an ErrorDetail chain (following mCause) and returns the terminal link.
std::pair<std::size_t, const ua::ErrorDetail*> walk_error_chain(const ua::ErrorDetail* head)
{
  std::size_t depth = 0;
  const ua::ErrorDetail* last = nullptr;
  for (const ua::ErrorDetail* cur = head; cur != nullptr; cur = cur->cause.get())
  {
    ++depth;
    last = cur;
  }
  return {depth, last};
}

/// A single DiagnosticInfo layer carrying @p symbolicIndex (a string-table index) and an optional inner
/// layer.
std::unique_ptr<ua::DiagnosticInfo> make_diag_node(
  std::int32_t symbolicIndex, std::unique_ptr<ua::DiagnosticInfo> inner = nullptr)
{
  auto node = std::make_unique<ua::DiagnosticInfo>();
  node->symbolic_id() = symbolicIndex;
  node->inner_diagnostic_info() = std::move(inner);
  return node;
}

/// A DiagnosticInfo chain @p levels deep, every layer with symbolic_id index 0 (resolves to the empty
/// string).
std::unique_ptr<ua::DiagnosticInfo> build_deep_diag(int levels)
{
  std::unique_ptr<ua::DiagnosticInfo> chain;
  for (int i = 0; i < levels; ++i)
  {
    chain = make_diag_node(0, std::move(chain));
  }
  return chain;
}

/// Crafts a ReadResponse whose header carries @p serviceResult, @p diag (service diagnostics) and
/// @p stringTable, plus one Int32 result value so a round-trip / no-op assertion can observe the payload.
ua::ReadResponse make_diag_read_response(
  ua::StatusCode serviceResult, ua::DiagnosticInfo diag, std::vector<std::string> stringTable = {})
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{7}}});
  auto& header = response.response_header();
  header.service_result() = serviceResult;
  header.service_diagnostics() = std::move(diag);
  ua::Array<ua::String> table;
  for (auto& entry : stringTable)
  {
    table.push_back(ua::String{entry});
  }
  header.string_table() = std::move(table);
  return response;
}

/// Fixture that attaches a RecordingConnectionObserver at connect and drives the connection to Active over
/// the fake interface. The bootstrap NamespaceArray Read (null serviceDiagnostics) never fires the observer,
/// so a subsequent crafted Read/Browse is the sole diagnostics stimulus.
class ConnectionBaseDiagTest : public ConnectionImplTest
{
protected:
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<RecordingConnectionObserver> mObserver = std::make_shared<RecordingConnectionObserver>();

  std::shared_ptr<ConnectionImpl> make_active()
  {
    return make_active_with_policy(ua::client::ClientDiagnosticPolicy{});
  }

  std::shared_ptr<ConnectionImpl> make_active_with_policy(ua::client::ClientDiagnosticPolicy policy)
  {
    ConnectionConfig config;
    config.observers.connection = mObserver;
    config.diagnostics = policy;
    auto connection = make_connection(mSession, mReopen, std::move(config));
    EXPECT_TRUE(start_and_wait(*connection).is_good());
    return connection;
  }
};

// @verifies CL-SESS-024
// A held request with the target requestHandle is outstanding when Cancel is dispatched. A divergent
// cancelCount remains the caller's successful response, fires one structured advisory, and never retries
// Cancel. This is the missing half of CL-SESS-024: merely forwarding cancelCount is insufficient.
// @relation(CL-SESS-024, scope=function)
TEST_F(ConnectionBaseDiagTest, CancelCountMismatchIsAdvisoryAndDoesNotRetry)
{
  auto connection = make_active();
  mSession->read.set_hold(true);

  ua::ReadRequest readRequest;
  readRequest.request_header().request_handle() = 77;
  std::promise<Result<ua::ReadResponse>> readPromise;
  auto readFuture = readPromise.get_future();
  connection->read_async(std::move(readRequest),
    [&readPromise](Result<ua::ReadResponse> result) { readPromise.set_value(std::move(result)); });
  wait_until([&] { return mSession->read.pending_count() == 1; }, "target Read to become outstanding");

  ua::CancelResponse response;
  response.cancel_count() = 0;
  mSession->cancel.set_result(Result<ua::CancelResponse>{std::move(response)});
  ua::CancelRequest cancelRequest;
  cancelRequest.request_handle() = 77;

  const auto result = cancel_and_wait(*connection, std::move(cancelRequest));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().cancel_count(), 0u) << "the advisory must not rewrite the wire response";
  EXPECT_EQ(mSession->cancel.call_count(), 1u) << "count divergence must not trigger a second Cancel";

  wait_until([&] { return mObserver->advisoryCalls.load() == 1; }, "cancelCount advisory to fire");
  const auto detail = mObserver->last_advisory();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "CancelCountMismatch");
  EXPECT_EQ(detail->source, "client.tier1.connection.cancel_count");

  mSession->read.fire_next(Result<ua::ReadResponse>{ua::ReadResponse{}});
  ASSERT_TRUE(readFuture.get().is_good());
}

// @verifies CL-SESS-024
// Matching server and client counts are the quiet control: cancelCount is still surfaced and no advisory
// is manufactured.
// @relation(CL-SESS-024, scope=function)
TEST_F(ConnectionBaseDiagTest, MatchingCancelCountDoesNotFireAdvisory)
{
  auto connection = make_active();
  mSession->read.set_hold(true);

  ua::ReadRequest readRequest;
  readRequest.request_header().request_handle() = 91;
  std::promise<Result<ua::ReadResponse>> readPromise;
  auto readFuture = readPromise.get_future();
  connection->read_async(std::move(readRequest),
    [&readPromise](Result<ua::ReadResponse> result) { readPromise.set_value(std::move(result)); });
  wait_until([&] { return mSession->read.pending_count() == 1; }, "target Read to become outstanding");

  ua::CancelResponse response;
  response.cancel_count() = 1;
  mSession->cancel.set_result(Result<ua::CancelResponse>{std::move(response)});
  ua::CancelRequest cancelRequest;
  cancelRequest.request_handle() = 91;

  const auto result = cancel_and_wait(*connection, std::move(cancelRequest));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().cancel_count(), 1u);
  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0);

  mSession->read.fire_next(Result<ua::ReadResponse>{ua::ReadResponse{}});
  ASSERT_TRUE(readFuture.get().is_good());
}

// @verifies CL-SESS-024
// Accounting is per requestHandle, not a total of all traffic: two matching Reads and one unrelated Read
// make the expected count exactly two.
// @relation(CL-SESS-024, scope=function)
TEST_F(ConnectionBaseDiagTest, CancelExpectedCountGroupsOutstandingRequestsByHandle)
{
  auto connection = make_active();
  mSession->read.set_hold(true);

  std::vector<std::promise<Result<ua::ReadResponse>>> promises(3);
  std::vector<std::future<Result<ua::ReadResponse>>> futures;
  futures.reserve(promises.size());
  for (auto& promise : promises)
  {
    futures.push_back(promise.get_future());
  }
  const std::array<std::uint32_t, 3> handles{12, 12, 13};
  for (std::size_t index = 0; index < handles.size(); ++index)
  {
    ua::ReadRequest request;
    request.request_header().request_handle() = handles[index];
    connection->read_async(std::move(request),
      [&promise = promises[index]](Result<ua::ReadResponse> result)
      { promise.set_value(std::move(result)); });
  }
  wait_until([&] { return mSession->read.pending_count() == 3; }, "three Reads to become outstanding");

  ua::CancelResponse response;
  response.cancel_count() = 2;
  mSession->cancel.set_result(Result<ua::CancelResponse>{std::move(response)});
  ua::CancelRequest cancelRequest;
  cancelRequest.request_handle() = 12;
  ASSERT_TRUE(cancel_and_wait(*connection, std::move(cancelRequest)).is_good());
  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0);

  for (std::size_t index = 0; index < handles.size(); ++index)
  {
    mSession->read.fire_next(Result<ua::ReadResponse>{ua::ReadResponse{}});
    ASSERT_TRUE(futures[index].get().is_good());
  }
}

// @verifies CL-SESS-024
// A completed request is removed before a later Cancel comparison; stale accounting would manufacture an
// advisory for the conforming zero response.
// @relation(CL-SESS-024, scope=function)
TEST_F(ConnectionBaseDiagTest, CompletedRequestIsRemovedFromCancelExpectation)
{
  auto connection = make_active();
  ua::ReadRequest readRequest;
  readRequest.request_header().request_handle() = 33;
  ASSERT_TRUE(read_and_wait(*connection, std::move(readRequest)).is_good());

  ua::CancelResponse response;
  response.cancel_count() = 0;
  mSession->cancel.set_result(Result<ua::CancelResponse>{std::move(response)});
  ua::CancelRequest cancelRequest;
  cancelRequest.request_handle() = 33;
  ASSERT_TRUE(cancel_and_wait(*connection, std::move(cancelRequest)).is_good());
  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0);
}

// @verifies CL-DIAG-011
// @relation(CL-DIAG-011, scope=function)
TEST_F(ConnectionImplTest, ReturnDiagnosticsOverrideIsConfiguredPerConnectionWithoutCrossTalk)
{
  auto firstSession = std::make_shared<FakeSessionOps>();
  auto secondSession = std::make_shared<FakeSessionOps>();
  auto defaultSession = std::make_shared<FakeSessionOps>();

  ConnectionConfig firstConfig;
  firstConfig.diagnostics.requestedDiagnosticsMask = 0xFFFFu;
  ConnectionConfig secondConfig;
  secondConfig.diagnostics.requestedDiagnosticsMask = 0u;

  auto first = make_connection(firstSession, std::make_shared<FakeReopen>(), std::move(firstConfig));
  auto second = make_connection(secondSession, std::make_shared<FakeReopen>(), std::move(secondConfig));
  auto noOverride = make_connection(defaultSession, std::make_shared<FakeReopen>(), ConnectionConfig{});

  EXPECT_EQ(firstSession->returnDiagnosticsOverride, std::optional<uint32_t>{0xFFFFu});
  EXPECT_EQ(secondSession->returnDiagnosticsOverride, std::optional<uint32_t>{0u});
  EXPECT_EQ(defaultSession->returnDiagnosticsOverride, std::nullopt);

  first.reset();
  second.reset();
  noOverride.reset();
}

// @verifies CL-BASEDIAG-001
// A bad service_result carrying a non-empty serviceDiagnostics must fire on_error_chain exactly once with the
// decoded chain (wire-crossing marker outermost, server symbolic below it), the terminal code, and the "read"
// operation tag. advisory must NOT fire. A funnel that decodes nothing surfaces nothing here.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, BadResponseSurfacesViaErrorChain)
{
  auto connection = make_active();

  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, *make_diag_node(0), std::vector<std::string>{"MySymbolic"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad()) << "CL-DIAG-005: the funnel collapses the bad serviceResult onto the Result";

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  EXPECT_EQ(mObserver->errorChainCalls.load(), 1);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0) << "a bad result must not fire the advisory hook";
  EXPECT_EQ(mObserver->last_terminal(), StatusCode{Status::BadInternalError});
  EXPECT_EQ(mObserver->last_tag(), "read");

  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  EXPECT_EQ(chain->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(chain->cause, nullptr) << "the decoded server chain hangs below the marker";
  EXPECT_EQ(chain->cause->code, "server.symbolic.MySymbolic");
}

// @verifies CL-BASEDIAG-001
// A GOOD service_result carrying a non-empty serviceDiagnostics is advisory: on_advisory_diagnostic fires
// with the decoded ErrorDetail, and on_error_chain does NOT.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, GoodResponseSurfacesViaAdvisory)
{
  auto connection = make_active();

  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::Good}, *make_diag_node(0), std::vector<std::string>{"AdvisorySym"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_good());

  wait_until([&] { return mObserver->advisoryCalls.load() >= 1; }, "on_advisory_diagnostic to fire");
  EXPECT_EQ(mObserver->advisoryCalls.load(), 1);
  EXPECT_EQ(mObserver->errorChainCalls.load(), 0) << "a good result must not fire the error-chain hook";

  const auto detail = mObserver->last_advisory();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->code, "server.symbolic.AdvisorySym");
}

// A Result answered Uncertain that holds its response still has the response header read: the server's
// diagnostics reach the error-chain observer, and the Bad ServiceResult, the code ua::detail::combined_status
// gives over the Uncertain code and the ServiceResult, is the Result the application receives.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ConnectionBaseDiagTest, AnUncertainResultHoldingAResponseAnswersItsBadServiceResult)
{
  auto connection = make_active();

  mSession->read.set_result(Result<ua::ReadResponse>{
    make_diag_read_response(
      StatusCode{Status::BadTooManyOperations}, *make_diag_node(0), std::vector<std::string>{"UncertainSym"}),
    StatusCode{Status::UncertainLastUsableValue}});

  const auto result = read_and_wait(*connection);
  EXPECT_EQ(result.status_code().as_status(), Status::BadTooManyOperations)
    << "the Bad ServiceResult collapses the Result, whatever the Result's own code";
  EXPECT_TRUE(result.is_bad());

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  EXPECT_EQ(mObserver->errorChainCalls.load(), 1);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0);
  EXPECT_EQ(mObserver->last_terminal(), StatusCode{Status::BadTooManyOperations});
  EXPECT_EQ(mObserver->last_tag(), "read");
  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->code, "server.symbolic.UncertainSym");
}

// @verifies CL-BASEDIAG-001
// The strict-no-op guard: a null serviceDiagnostics (the returnDiagnostics=0 default) fires NEITHER observer,
// and the forwarded Result is unchanged. This is the invariant that keeps every existing test byte-for-byte
// unchanged; a wrap that fired (or mutated the chain) on the default path would regress thousands of tests.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, EmptyDiagnosticInfoNoObserverFires)
{
  auto connection = make_active();

  // Good service_result, null serviceDiagnostics (default-constructed DiagnosticInfo -> is_null()).
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_diag_read_response(StatusCode{Status::Good}, ua::DiagnosticInfo{})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1U) << "the forwarded response payload is unchanged";
  EXPECT_EQ(result.value().results()[0].value().to<std::int32_t>().value(), 7);

  std::this_thread::sleep_for(50ms);  // let any erroneous fire reach the delivery strand
  EXPECT_EQ(mObserver->errorChainCalls.load(), 0);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0);
}

// @verifies CL-BASEDIAG-001
// String-index fields resolve against the response string table, not their raw integer indexes: symbolicId 2
// and localizedText 3 resolve to the table entries at those indexes.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, DecodesStringTableIndexes)
{
  auto connection = make_active();

  ua::DiagnosticInfo diag;
  diag.symbolic_id() = 2;
  diag.localized_text() = 3;
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_diag_read_response(StatusCode{Status::BadInternalError},
      std::move(diag),
      std::vector<std::string>{"", "", "Foo_Sym", "Foo localized"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());  // CL-DIAG-005: bad serviceResult collapses the Result

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->code, "server.symbolic.Foo_Sym") << "symbolicId index 2 resolves via the table";
  EXPECT_EQ(chain->cause->summary, "Foo localized") << "localizedText index 3 resolves via the table";
}

// @verifies CL-BASEDIAG-001
// A 3-level innerDiagnosticInfo produces a 3-level server cause chain below the marker (marker + 3 = depth
// 4), each level resolving its own symbolicId.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, DecodesInnerDiagnosticInfoRecursively)
{
  auto connection = make_active();

  // L1(sym 1) -> L2(sym 2) -> L3(sym 3).
  auto level3 = make_diag_node(3);
  auto level2 = make_diag_node(2, std::move(level3));
  auto level1 = make_diag_node(1, std::move(level2));
  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, *level1, std::vector<std::string>{"", "L1sym", "L2sym", "L3sym"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());  // CL-DIAG-005: bad serviceResult collapses the Result

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  const auto [depth, terminal] = walk_error_chain(chain.get());
  EXPECT_EQ(depth, 4U) << "marker(1) + three decoded server layers";
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->code, "server.symbolic.L1sym");
  ASSERT_NE(chain->cause->cause, nullptr);
  EXPECT_EQ(chain->cause->cause->code, "server.symbolic.L2sym");
  ASSERT_NE(chain->cause->cause->cause, nullptr);
  EXPECT_EQ(chain->cause->cause->cause->code, "server.symbolic.L3sym");
}

// @verifies CL-BASEDIAG-001
// section 3.1 decode-DoS pin: a deeply nested innerDiagnosticInfo (40 levels) is truncated at the decoder's
// maxChainDepth (32) with a single CHAIN_TRUNCATED sentinel, so a hostile server cannot force unbounded work
// or an unbounded chain onto the observer. This MUST fail if the depth cap is removed (the chain would then
// be 41 links deep with no sentinel).
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, DepthCapPinTruncatesBeyondMaxChainDepth)
{
  auto connection = make_active();

  auto deep = build_deep_diag(40);
  mSession->read.set_result(Result<ua::ReadResponse>{
    make_diag_read_response(StatusCode{Status::BadInternalError}, *deep, std::vector<std::string>{""})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());  // CL-DIAG-005: bad serviceResult collapses the Result

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  const auto [depth, terminal] = walk_error_chain(chain.get());
  EXPECT_EQ(depth, 34U) << "marker(1) + 32 decoded server layers + truncation sentinel(1)";
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "CHAIN_TRUNCATED");
  EXPECT_EQ(terminal->source, "client.diagnostic.truncated");
}

// @verifies CL-BASEDIAG-001
// section 3.1 malformed-index pin: out-of-range / negative string-table indexes must not read out of bounds,
// crash, or throw out of the funnel. The decoder resolves them to a bounded "<unknown:N>" placeholder and the
// funnel still forwards the good transport Result and surfaces the chain (best-effort), rather than aborting.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, MalformedIndexNoThrowNoCrash)
{
  auto connection = make_active();

  ua::DiagnosticInfo diag;
  diag.symbolic_id() = 999;  // out of range for the (empty) table
  diag.namespace_uri() = 12345;  // out of range
  diag.localized_text() = -1;  // negative sentinel
  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, std::move(diag), std::vector<std::string>{})});

  const auto result = read_and_wait(*connection);
  // CL-DIAG-005: the Result is bad because the SERVICE failed (BadInternalError); the malformed diagnostic
  // must not additionally crash/throw - it degrades to a bounded "<unknown>" placeholder below the marker.
  ASSERT_TRUE(result.is_bad()) << "a malformed DiagnosticInfo must never throw out of the funnel";

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire (best-effort)");
  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_NE(chain->cause->code.find("<unknown"), std::string::npos)
    << "an out-of-range index resolves to a bounded placeholder, proving no OOB read";
}

// @verifies CL-BASEDIAG-001
// The operation tag threaded into invoke_wire_op reaches on_error_chain's operationTag - and it is the OP'S
// OWN tag ("browse"), not a hardcoded "read", proving the copy is taken from the per-op tag before it is
// moved into the pending queue.
// @relation(CL-BASEDIAG-001, scope=function)
TEST_F(ConnectionBaseDiagTest, OperationTagPropagation)
{
  auto connection = make_active();

  ua::BrowseResponse browseResponse;
  auto& header = browseResponse.response_header();
  header.service_result() = StatusCode{Status::BadInternalError};
  header.service_diagnostics() = *make_diag_node(0);
  ua::Array<ua::String> table;
  table.push_back(ua::String{"BrowseSym"});
  header.string_table() = std::move(table);
  mSession->browse.set_result(Result<ua::BrowseResponse>{std::move(browseResponse)});

  const auto result = browse_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  EXPECT_EQ(mObserver->last_tag(), "browse") << "the surfaced tag is the browse op's own tag, not read's";
}

// ============================================================================================
// CL-DIAG-005: the always-on wire-crossing marker on the GENERAL DATA SURFACE (the invoke_wire_op funnel),
// not just the tier-0 session/secure-channel paths. A response that crosses the wire with a bad
// ResponseHeader.serviceResult (Case-2: good transport, bad header) COLLAPSES to a BAD Result<T> whose own
// ErrorDetail chain is marker (source "client.tier0.session.decode_diagnostic") -> decoded server chain.
// A Good serviceResult is untouched (strict no-op). The marker is attached even at returnDiagnostics=0.
// These pin the Result-chain shape; the CL-BASEDIAG-001 tests above pin the observer fan-out (both fire off
// the SAME funnel decode). The 6 CL-BASEDIAG-001 tests with a bad serviceResult were migrated is_good ->
// is_bad here, because the collapse now flips the Result they forward.
// ============================================================================================

// @verifies CL-DIAG-005
// The funnel collapses a bad serviceResult to a BAD Result<T> carrying marker -> decoded server chain.
// @relation(CL-DIAG-005, scope=function)
TEST_F(ConnectionBaseDiagTest, FunnelCollapsesBadServiceResultOntoMarkeredResult)
{
  auto connection = make_active();
  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, *make_diag_node(0), std::vector<std::string>{"MySymbolic"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad()) << "a bad serviceResult must collapse the transport-good Result to bad";
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "the collapsed Result must carry the wire-crossing marker";
  EXPECT_EQ(detail->source, "client.tier1.connection.read");
  ASSERT_NE(detail->cause, nullptr) << "the wire marker hangs below the Standard tier-1 wrap";
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr) << "the decoded server chain hangs below the marker";
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.MySymbolic");
}

// @verifies CL-DIAG-005
// The marker is attached even when the server sends NO DiagnosticInfo (the returnDiagnostics=0 default): the
// Result is bad, the marker is present with the terminal status as its inner status, and no server cause
// hangs below it.
// @relation(CL-DIAG-005, scope=function)
TEST_F(ConnectionBaseDiagTest, FunnelMarksBadResultEvenWithoutServerDiagnostics)
{
  auto connection = make_active();
  mSession->read.set_result(Result<ua::ReadResponse>{
    make_diag_read_response(StatusCode{Status::BadNodeIdUnknown}, ua::DiagnosticInfo{})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->source, "client.tier1.connection.read");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  EXPECT_EQ(detail->cause->cause, nullptr) << "no server DiagnosticInfo -> marker with no server cause below";
  EXPECT_EQ(StatusCode{detail->cause->innerStatus}, StatusCode{Status::BadNodeIdUnknown});
}

// @verifies CL-DIAG-005
// Strict no-op: a GOOD serviceResult is never collapsed and never marked - the payload is forwarded verbatim
// and the Result carries no ErrorDetail. Guards against an over-eager collapse regressing the happy path.
// @relation(CL-DIAG-005, scope=function)
TEST_F(ConnectionBaseDiagTest, FunnelLeavesGoodServiceResultUntouched)
{
  auto connection = make_active();
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_diag_read_response(StatusCode{Status::Good}, ua::DiagnosticInfo{})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1U);
  EXPECT_EQ(result.value().results()[0].value().to<std::int32_t>().value(), 7);
  EXPECT_EQ(result.status_code().shared_detail(), nullptr) << "a good Result must carry no marker";
}

// @verifies CL-DIAG-005
// section 3.1 no-throw pin: a malformed server DiagnosticInfo (out-of-range / negative indexes) on a
// bad-serviceResult response still collapses to a bad Result carrying the marker, never throwing out of the
// funnel or crashing (attach_wire_marker is noexcept with a bare-marker fallback - the no-throw-in-handler
// lesson).
// @relation(CL-DIAG-005, scope=function)
TEST_F(ConnectionBaseDiagTest, FunnelMarksBadResultWithMalformedDiagnosticNoThrow)
{
  auto connection = make_active();
  ua::DiagnosticInfo diag;
  diag.symbolic_id() = 999;  // out of range for the empty table
  diag.localized_text() = -1;  // negative sentinel
  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, std::move(diag), std::vector<std::string>{})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad()) << "the service failed; a malformed diagnostic must not change that";
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->source, "client.tier1.connection.read");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
}

// ============================================================================================
// CL-DIAG-012: the ClientDiagnosticPolicy.emitOnErrorChainObserver gate on the diagnostics observer surface.
// Default true (fire); false = strict no-op (no observer fires). CL-DIAG-009: the policy's maxChainDepth caps
// the decoded observer chain. The always-on CL-DIAG-005 Result-marker is INDEPENDENT of this gate.
// ============================================================================================

// @verifies CL-DIAG-012
// With emitOnErrorChainObserver=false, a bad serviceResult carrying diagnostics fires NEITHER observer, yet
// the Result STILL carries the CL-DIAG-005 wire-crossing marker (the observer gate and the Result marker are
// independent). RED before the gate: on_error_chain fires unconditionally today.
// @relation(CL-DIAG-012, scope=function)
TEST_F(ConnectionBaseDiagTest, ObserverSuppressedWhenPolicyDisablesEmit)
{
  ua::client::ClientDiagnosticPolicy policy;
  policy.emitOnErrorChainObserver = false;
  auto connection = make_active_with_policy(policy);

  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, *make_diag_node(0), std::vector<std::string>{"MySymbolic"})});

  const auto result = read_and_wait(*connection);
  // The CL-DIAG-005 Result marker is unaffected by the observer gate.
  ASSERT_TRUE(result.is_bad());
  ASSERT_NE(result.status_code().shared_detail(), nullptr);
  EXPECT_EQ(result.status_code().shared_detail()->source, "client.tier1.connection.read");
  ASSERT_NE(result.status_code().shared_detail()->cause, nullptr);
  EXPECT_EQ(result.status_code().shared_detail()->cause->source, "client.tier0.session.decode_diagnostic");

  std::this_thread::sleep_for(50ms);  // let any erroneous fire reach the delivery strand
  EXPECT_EQ(mObserver->errorChainCalls.load(), 0)
    << "emitOnErrorChainObserver=false must suppress the observer";
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0);
}

// @verifies CL-DIAG-012
// The gate also suppresses the ADVISORY observer (good serviceResult carrying diagnostics) when disabled.
// @relation(CL-DIAG-012, scope=function)
TEST_F(ConnectionBaseDiagTest, AdvisorySuppressedWhenPolicyDisablesEmit)
{
  ua::client::ClientDiagnosticPolicy policy;
  policy.emitOnErrorChainObserver = false;
  auto connection = make_active_with_policy(policy);

  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::Good}, *make_diag_node(0), std::vector<std::string>{"AdvisorySym"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_good());

  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(mObserver->advisoryCalls.load(), 0)
    << "emitOnErrorChainObserver=false must suppress the advisory";
  EXPECT_EQ(mObserver->errorChainCalls.load(), 0);
}

// @verifies CL-DIAG-012
// The default (emitOnErrorChainObserver=true) fires the observer - the pre-policy behaviour is preserved.
// This explicit-true pin guards against an inverted gate. Green under the correct gate.
// @relation(CL-DIAG-012, scope=function)
TEST_F(ConnectionBaseDiagTest, ObserverFiresWhenPolicyEnablesEmit)
{
  ua::client::ClientDiagnosticPolicy policy;
  policy.emitOnErrorChainObserver = true;
  auto connection = make_active_with_policy(policy);

  mSession->read.set_result(Result<ua::ReadResponse>{make_diag_read_response(
    StatusCode{Status::BadInternalError}, *make_diag_node(0), std::vector<std::string>{"MySymbolic"})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  EXPECT_EQ(mObserver->errorChainCalls.load(), 1);
}

// @verifies CL-DIAG-009
// The policy's maxChainDepth caps the decoded OBSERVER chain: maxChainDepth=5 over a 20-level
// innerDiagnosticInfo yields marker(1) + 5 server layers + truncation sentinel(1) = depth 7 (vs the
// default-32 test's 34). RED before the policy is threaded into the decoder (the decoder would use its own
// default 32 -> depth 22).
// @relation(CL-DIAG-009, scope=function)
TEST_F(ConnectionBaseDiagTest, PolicyMaxChainDepthCapsObserverChain)
{
  ua::client::ClientDiagnosticPolicy policy;
  policy.maxChainDepth = 5;
  auto connection = make_active_with_policy(policy);

  auto deep = build_deep_diag(20);
  mSession->read.set_result(Result<ua::ReadResponse>{
    make_diag_read_response(StatusCode{Status::BadInternalError}, *deep, std::vector<std::string>{""})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());

  wait_until([&] { return mObserver->errorChainCalls.load() >= 1; }, "on_error_chain to fire");
  const auto chain = mObserver->last_chain();
  ASSERT_NE(chain, nullptr);
  const auto [depth, terminal] = walk_error_chain(chain.get());
  EXPECT_EQ(depth, 7U) << "marker(1) + 5 server layers (policy cap) + truncation sentinel(1)";
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "CHAIN_TRUNCATED");
}

// @verifies CL-DIAG-009
// The policy's maxChainDepth also caps the CL-DIAG-005 Result marker chain on the funnel path (not just the
// observer): maxChainDepth=5 over a 20-level chain yields a Result whose ErrorDetail is depth 7. RED before
// the policy is threaded into attach_wire_marker (the marker would use the default 32 -> depth 22).
// @relation(CL-DIAG-009, scope=function)
TEST_F(ConnectionBaseDiagTest, PolicyMaxChainDepthCapsResultMarkerChain)
{
  ua::client::ClientDiagnosticPolicy policy;
  policy.maxChainDepth = 5;
  auto connection = make_active_with_policy(policy);

  auto deep = build_deep_diag(20);
  mSession->read.set_result(Result<ua::ReadResponse>{
    make_diag_read_response(StatusCode{Status::BadInternalError}, *deep, std::vector<std::string>{""})});

  const auto result = read_and_wait(*connection);
  ASSERT_TRUE(result.is_bad());
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  const auto [depth, terminal] = walk_error_chain(detail.get());
  EXPECT_EQ(depth, 8U)
    << "the Standard tier-1 wrap precedes the capped marker chain: wrap(1) + marker(1) + 5 + sentinel(1)";
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "CHAIN_TRUNCATED");
}

// ---------------------------------------------------------------------------------------------------
// Criteria authored against COMP-CL-CONNIMPL. Each test below discharges the criterion it cites and was
// written because a recorded search over this suite found no candidate for it - not because the code
// suggested it. The observable in each case comes from section 8.2A.1's hard rules, the header's own declared
// contract, or the SDK design rules, never from the implementation.
// ---------------------------------------------------------------------------------------------------

/// AC-COMP-CL-CONNIMPL-02-C. A tier-0 interface that throws is a collaborator failure mode CO6 enumerates and
/// FakeSessionOps had no way to present. `read_async` is `noexcept`, so an escaping exception terminates
/// the process; the owed completion must still arrive exactly once with a bad Result.
///
/// Regression for D-CONNIMPL-SEAM-THROW-DROPS-COMPLETION: the tier-0 invocation boundary owns the
/// completion and converts a synchronous collaborator exception to a bad Result without retrying it.
// @relation(AC-COMP-CL-CONNIMPL-02-C, scope=function)
TEST_F(ConnectionImplTest, WireOpsThrowStillCompletesCallbackOnce)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // The bootstrap is done, so this only affects the tier-1 Read the test issues.
  session->read.set_result_fn([](const ua::ReadRequest&) -> Result<ua::ReadResponse>
    { throw ua::UaException{StatusCode{Status::BadInternalError}}; });

  auto probe = submit_read(*connection);
  ASSERT_EQ(probe->future.wait_for(2s), std::future_status::ready)
    << "the owed completion was dropped: a throwing interface must still complete the caller";
  EXPECT_TRUE(probe->future.get().is_bad())
    << "a throwing tier-0 interface must surface as a bad Result, not as a throw";
  expect_completed_once(probe);
}

/// AC-COMP-CL-CONNIMPL-04-C. The header states that existence is checked before membership, so a handle
/// that is both unregistered AND named against a Subscription it does not belong to keeps the existence
/// status. The suite's cross-Subscription tests all use live handles, so nothing sat at this boundary.
// @relation(AC-COMP-CL-CONNIMPL-04-C, scope=function)
TEST_F(ConnectionImplTest, SetTriggeringUnregisteredHandleKeepsExistenceStatusOverMembership)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto* owner = data_change_owner(*connection);
  ASSERT_NE(owner, nullptr);
  owner->register_item(/*clientHandle=*/10, /*subscriptionId=*/100, /*monitoredItemId=*/1000);

  // Handle 77 is unregistered, and the call names Subscription 200 - which handle 10 is not in either. Both
  // rejections are reachable; the contract says which one wins.
  const auto result = set_triggering_by_handles_and_wait(
    *connection, /*subscriptionId=*/200, /*triggerHandle=*/77, /*addHandles=*/{10}, /*removeHandles=*/{});

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadMonitoredItemIdInvalid)
    << "existence precedes membership: an unregistered handle keeps Bad_MonitoredItemIdInvalid";
  EXPECT_EQ(session->setTriggering.call_count(), 0u);
}

/// AC-COMP-CL-CONNIMPL-11-A. The ownership model is a compile-time obligation section 8.2A.10 marks as a
/// "compile-fire test" and nothing fired: every subordinate holds this type by `weak_from_this()`, so an
/// instance that could be copied or moved would leave those references on a dead control block.
// @relation(AC-COMP-CL-CONNIMPL-11-A, scope=function)
TEST_F(ConnectionImplTest, ConnectionImplIsNeitherCopyableNorMovable)
{
  static_assert(!std::is_copy_constructible_v<ConnectionImpl>);
  static_assert(!std::is_copy_assignable_v<ConnectionImpl>);
  static_assert(!std::is_move_constructible_v<ConnectionImpl>);
  static_assert(!std::is_move_assignable_v<ConnectionImpl>);
  static_assert(std::is_same_v<decltype(ConnectionImpl::create_from_ops(
                                 boost::asio::any_io_executor{}, nullptr, ConnectionConfig{}, Logger{})),
    std::shared_ptr<ConnectionImpl>>);
  static_assert(std::is_base_of_v<std::enable_shared_from_this<ConnectionImpl>, ConnectionImpl>,
    "the weak-capture discipline the traits above protect is what enable_shared_from_this provides");
  SUCCEED();
}

/// AC-COMP-CL-CONNIMPL-14-A. section 8.2A.1 hard rule 3: a user callback fires on the executor, never on the
/// connection strand. No test in this suite asserted the delivery thread, so a completion that ran inline
/// on the strand - which would let user code block the strand and re-enter under its own serialization -
/// passed every one of them.
// @relation(AC-COMP-CL-CONNIMPL-14-A, scope=function)
TEST_F(ConnectionImplTest, WireOpCompletionDoesNotRunOnTheConnectionStrand)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto strand = connection->strand();
  std::promise<bool> onStrand;
  auto observed = onStrand.get_future();
  connection->read_async({},
    [&strand, &onStrand](Result<ua::ReadResponse>) { onStrand.set_value(strand.running_in_this_thread()); });

  EXPECT_FALSE(observed.get()) << "a dispatched wire-op completion must not run on the connection strand";
}

/// AC-COMP-CL-CONNIMPL-14-B. The terminal fast-fail never reaches the tier-0 interface, so it is the path
/// most likely to complete inline on the strand as an apparent optimisation. Authored separately from 14-A
/// for that reason: a single criterion over the dispatched path would not catch it.
// @relation(AC-COMP-CL-CONNIMPL-14-B, scope=function)
TEST_F(ConnectionImplTest, TerminalFastFailIsDeliveredOffTheConnectionStrand)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(close_and_wait(*connection).is_good());

  auto strand = connection->strand();
  std::promise<std::pair<bool, StatusCode>> outcome;
  auto observed = outcome.get_future();
  connection->read_async({},
    [&strand, &outcome](Result<ua::ReadResponse> result)
    { outcome.set_value({strand.running_in_this_thread(), result.status_code()}); });

  const auto [onStrand, status] = observed.get();
  EXPECT_FALSE(onStrand) << "the fast-fail path must post to the executor like every other completion";
  EXPECT_EQ(status, StatusCode{Status::BadConnectionClosed});
}

/// AC-COMP-CL-CONNIMPL-17-A. CO5.5 re-entrancy, the sub-dimension qa_process.md section 3.2.1 calls
/// detectable only at unit level. Because the completion runs on the executor, a re-entrant call posts to the
/// strand and serializes behind the work already there; a completion delivered under a held lock or on the
/// strand would deadlock here instead.
// @relation(AC-COMP-CL-CONNIMPL-17-A, scope=function)
TEST_F(ConnectionImplTest, WireOpReentrantFromCompletionCompletesNormally)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  const auto readsBefore = session->read.call_count();

  auto inner = std::make_shared<ReadProbe>();
  connection->read_async({},
    [connection, inner](Result<ua::ReadResponse>)
    {
      connection->read_async({},
        [inner](Result<ua::ReadResponse> result)
        {
          if (inner->calls.fetch_add(1) == 0)
          {
            inner->promise.set_value(std::move(result));
          }
        });
    });

  EXPECT_TRUE(inner->future.get().is_good()) << "a re-entrant call from inside a completion must complete";
  expect_completed_once(inner);
  EXPECT_EQ(session->read.call_count(), readsBefore + 2u);
}

/// AC-COMP-CL-CONNIMPL-18-A. section 8.2A.1 hard rule 4 and strand_components.md rule 2: a public entry point
/// posts and returns. The rest of this suite bridges every call through a std::promise on a live runner
/// thread, which is exactly the shape that cannot observe whether the entry point blocked - a blocking
/// implementation passes all 286 of them. Withholding the executor rather than timing the call keeps the
/// arm deterministic.
// @relation(AC-COMP-CL-CONNIMPL-18-A, scope=function)
TEST_F(ConnectionImplTest, PublicEntryPointReturnsBeforeItsStrandWorkRuns)
{
  boost::asio::io_context idle;  // deliberately never run until the assertions are made
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = TA::create_with_ops(idle.get_executor(),
    session,
    ConnectionConfig{},
    Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    keep_alive_disabled());

  std::atomic<int> completions{0};
  connection->read_async({}, [&completions](Result<ua::ReadResponse>) { ++completions; });
  connection->close_async([&completions](VoidResult) { ++completions; });

  EXPECT_EQ(completions.load(), 0)
    << "both entry points must return without waiting on a strand nothing is running";
  EXPECT_EQ(session->read.call_count(), 0u) << "no strand work may run on the caller's thread";

  idle.run();
  EXPECT_EQ(completions.load(), 2) << "the parked work must run once the executor is allowed to proceed";
}

/// AC-COMP-CL-CONNIMPL-24-B. The header claims the lazy accessors are free-threaded and `call_once`-guarded.
/// The suite contains exactly one std::thread and it is a runner for the io_context, so the guard was
/// claimed and never exercised by a second caller. This arm reddens under TSan if the guard is removed.
// @relation(AC-COMP-CL-CONNIMPL-24-B, scope=function)
TEST_F(ConnectionImplTest, ConcurrentFirstCallsToLazyAccessorYieldOneInstance)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  constexpr int racerCount = 8;
  std::atomic<int> ready{0};
  std::atomic<bool> go{false};
  std::vector<std::shared_ptr<ua::client::detail::TypeResolver>> seen(racerCount);
  std::vector<std::thread> racers;
  racers.reserve(racerCount);
  for (int i = 0; i < racerCount; ++i)
  {
    racers.emplace_back(
      [&, i]
      {
        ++ready;
        while (!go.load(std::memory_order_acquire))
        {
          std::this_thread::yield();
        }
        seen[static_cast<std::size_t>(i)] = connection->type_resolver();
      });
  }
  while (ready.load() < racerCount)
  {
    std::this_thread::yield();
  }
  go.store(true, std::memory_order_release);
  for (auto& racer : racers)
  {
    racer.join();
  }

  ASSERT_NE(seen.front(), nullptr);
  for (const auto& resolver : seen)
  {
    EXPECT_EQ(resolver, seen.front()) << "call_once must hand every racing caller the one co-owned instance";
  }
}

}  // namespace
