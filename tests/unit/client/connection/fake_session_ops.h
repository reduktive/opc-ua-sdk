// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_UNIT_CLIENT_CONNECTION_FAKE_SESSION_OPS_H
#define UA_TESTS_UNIT_CLIENT_CONNECTION_FAKE_SESSION_OPS_H

/// @file
/// @brief Fake tier-0 interface (@ref ua::client::detail::SessionOps / @ref ua::client::detail::ChannelOps /
///        @ref ua::client::detail::ReopenChannelOps) for driving @ref ua::client::detail::ConnectionImpl
///        unit tests in isolation (the testable-interfaces rule).
///
/// Each fake op is scriptable (per-op Result, defaulting to Good with a minimally-populated response), can
/// be HELD (its completion captured, not fired, so a test can drive a late completion / exactly-once
/// window), and records its invocation count + captured request. The fakes are thread-safe: a
/// ConnectionImpl drives them from its strand on the runtime's runner thread while the test thread scripts
/// results and fires held completions.

#include <optional>

#include "ua_array.h"
#include "ua_create_monitored_items_response.h"
#include "ua_data_value.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_monitored_item_create_result.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_result.h"
#include "ua_session_ops.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace ua::test_helpers
{

/// Builds a NamespaceArray Read response mirroring the ConnectionImpl bootstrap batch: index 0 is the
/// String[] NamespaceArray; index 1 is String[] ServerArray; index 2 is the optional Server.UrisVersion
/// UInt32 (CL-BASE-001); indices 3.. are the optional OperationLimits UInt32s
/// (CL-BASE-003), in @ref ua::client::detail operationLimitNodes order. When @p operationLimits is provided
/// but @p urisVersion is not, an empty index-2 result is emitted so the limits stay aligned at index 3+
/// (modelling a server that publishes the limits but not UrisVersion). Omitting a value models a server that
/// does not publish that node.
inline ua::ReadResponse make_namespace_array_response(
  std::vector<std::string> uris = {"http://opcfoundation.org/UA/", "urn:test:connection"},
  std::optional<std::uint32_t> urisVersion = std::nullopt, std::vector<std::uint32_t> operationLimits = {},
  std::vector<std::string> serverUris = {"urn:test:connection"},
  std::vector<std::uint16_t> continuationPointLimits = {})
{
  ua::Array<ua::String> array;
  for (auto& uri : uris)
  {
    array.push_back(ua::String{uri});
  }
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::move(array)}});
  ua::Array<ua::String> serverArray;
  for (auto& uri : serverUris)
  {
    serverArray.push_back(ua::String{uri});
  }
  response.results().push_back(ua::DataValue{ua::Variant{std::move(serverArray)}});
  if (urisVersion.has_value())
  {
    response.results().push_back(ua::DataValue{ua::Variant{*urisVersion}});
  }
  else if (!operationLimits.empty() || !continuationPointLimits.empty())
  {
    response.results().push_back(ua::DataValue{});  // index-2 placeholder to keep the limits aligned
  }
  for (const auto limit : operationLimits)
  {
    response.results().push_back(ua::DataValue{ua::Variant{limit}});
  }
  if (!continuationPointLimits.empty())
  {
    while (response.results().size() < 15)
    {
      response.results().push_back(ua::DataValue{});
    }
    for (const auto limit : continuationPointLimits)
    {
      response.results().push_back(ua::DataValue{ua::Variant{limit}});
    }
  }
  return response;
}

/// A scriptable async op returning `Result<Response>`: default Good (holding a value), optionally HELD
/// (completion parked) and always recording its invocation count + captured requests. Thread-safe.
template<typename Request, typename Response>
class ScriptedResultOp
{
public:
  /// Scripts the Result the op completes with when not held (mutex-guarded).
  void set_result(ua::Result<Response> result)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mResult = std::move(result);
  }

  /// Scripts a REQUEST-AWARE result: when set, `invoke` derives the Result from the incoming request via
  /// @p fn instead of the static @ref set_result value (e.g. to return a per-chunk response sized to the
  /// request). Takes precedence over set_result. Cleared by passing an empty function.
  void set_result_fn(std::function<ua::Result<Response>(const Request&)> fn)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mResultFn = std::move(fn);
  }

  /// Enables / disables HOLD mode: while held, an invocation parks its completion instead of firing it.
  void set_hold(bool hold)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mHold = hold;
  }

  /// Number of times the op has been invoked.
  std::size_t call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCalls;
  }

  /// Number of currently-parked (held) completions.
  std::size_t pending_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mHeld.size();
  }

  /// A copy of every request the op has captured, in call order (for asserting what was forwarded).
  std::vector<Request> requests() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mRequests;
  }

  /// Fires the oldest parked completion with @p result (from the test thread).
  void fire_next(ua::Result<Response> result)
  {
    std::function<void(ua::Result<Response>)> callback;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      callback = std::move(mHeld.front());
      mHeld.erase(mHeld.begin());
    }
    callback(std::move(result));
  }

  /// Invoked by the fake interface: records + either parks or completes @p callback.
  void invoke(Request request, std::function<void(ua::Result<Response>)> callback)
  {
    ua::Result<Response> result{Response{}};
    {
      std::lock_guard<std::mutex> lock(mMutex);
      ++mCalls;
      if (mHold)
      {
        mRequests.push_back(std::move(request));
        mHeld.push_back(std::move(callback));
        return;
      }
      result = mResultFn ? mResultFn(request) : mResult;
      mRequests.push_back(std::move(request));
    }
    callback(std::move(result));
  }

private:
  mutable std::mutex mMutex;
  ua::Result<Response> mResult{Response{}};
  std::function<ua::Result<Response>(const Request&)> mResultFn;
  bool mHold = false;
  std::size_t mCalls = 0;
  std::vector<Request> mRequests;
  std::vector<std::function<void(ua::Result<Response>)>> mHeld;
};

/// A scriptable async op returning `VoidResult`: default Good, optionally HELD, recording invocation count.
class ScriptedVoidOp
{
public:
  void set_result(ua::VoidResult result)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mResult = std::move(result);
  }

  void set_hold(bool hold)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mHold = hold;
  }

  std::size_t call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCalls;
  }

  std::size_t pending_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mHeld.size();
  }

  void fire_next(ua::VoidResult result)
  {
    std::function<void(ua::VoidResult)> callback;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      callback = std::move(mHeld.front());
      mHeld.erase(mHeld.begin());
    }
    callback(std::move(result));
  }

  void invoke(std::function<void(ua::VoidResult)> callback)
  {
    ua::VoidResult result{};
    {
      std::lock_guard<std::mutex> lock(mMutex);
      ++mCalls;
      if (mHold)
      {
        mHeld.push_back(std::move(callback));
        return;
      }
      result = mResult;
    }
    callback(std::move(result));
  }

private:
  mutable std::mutex mMutex;
  ua::VoidResult mResult{};
  bool mHold = false;
  std::size_t mCalls = 0;
  std::vector<std::function<void(ua::VoidResult)>> mHeld;
};

class FakeChannelOps;

/// Fake @ref ua::client::detail::SessionOps: each op forwards to a public @ref ScriptedResultOp /
/// @ref ScriptedVoidOp the test can script, hold, and inspect. `read` defaults to a NamespaceArray
/// response so the ConnectionImpl bootstrap reaches Active.
class FakeSessionOps : public ua::client::detail::SessionOps
{
public:
  FakeSessionOps()
  {
    read.set_result(ua::Result<ua::ReadResponse>{make_namespace_array_response()});
    // Default CreateMonitoredItems to a realistic one-good-item response so create_monitored_item
    // succeeds by default (like a real server); failure tests override this explicitly.
    ua::CreateMonitoredItemsResponse createResponse;
    ua::MonitoredItemCreateResult item;
    item.status_code() = ua::StatusCode{ua::Status::Good};
    item.monitored_item_id() = 1;
    createResponse.results().push_back(std::move(item));
    createMonitoredItems.set_result(ua::Result<ua::CreateMonitoredItemsResponse>{std::move(createResponse)});
    // And CreateSubscription to a realistic server-assigned id. A default-constructed response carries
    // SubscriptionId 0, which no server ever returns - IntegerId reserves 0 as the null value
    // (OPC 10000-4 7.19). Leaving it at 0 made every consumer that carries the id onward - the alarm
    // tracker's ConditionRefresh argument among them - look correct in tests while being unable to work
    // against a real server.
    ua::CreateSubscriptionResponse subscriptionResponse;
    subscriptionResponse.subscription_id() = 1;
    subscriptionResponse.revised_publishing_interval() = 500.0;
    subscriptionResponse.revised_lifetime_count() = 60;
    subscriptionResponse.revised_max_keep_alive_count() = 20;
    createSubscription.set_result(
      ua::Result<ua::CreateSubscriptionResponse>{std::move(subscriptionResponse)});
  }

  void set_return_diagnostics_override(std::optional<uint32_t> mask) override
  {
    returnDiagnosticsOverride = mask;
  }

  std::optional<uint32_t> returnDiagnosticsOverride;

  ScriptedResultOp<ua::ReadRequest, ua::ReadResponse> read;
  ScriptedResultOp<ua::HistoryReadRequest, ua::HistoryReadResponse> historyRead;
  ScriptedResultOp<ua::WriteRequest, ua::WriteResponse> write;
  ScriptedResultOp<ua::BrowseRequest, ua::BrowseResponse> browse;
  ScriptedResultOp<ua::BrowseNextRequest, ua::BrowseNextResponse> browseNext;
  ScriptedResultOp<ua::TranslateBrowsePathsToNodeIdsRequest, ua::TranslateBrowsePathsToNodeIdsResponse>
    translateBrowsePaths;
  ScriptedResultOp<ua::CallRequest, ua::CallResponse> call;
  ScriptedResultOp<ua::CancelRequest, ua::CancelResponse> cancel;
  ScriptedResultOp<ua::RegisterNodesRequest, ua::RegisterNodesResponse> registerNodes;
  ScriptedResultOp<ua::UnregisterNodesRequest, ua::UnregisterNodesResponse> unregisterNodes;
  ScriptedResultOp<ua::AddNodesRequest, ua::AddNodesResponse> addNodes;
  ScriptedResultOp<ua::AddReferencesRequest, ua::AddReferencesResponse> addReferences;
  ScriptedResultOp<ua::DeleteNodesRequest, ua::DeleteNodesResponse> deleteNodes;
  ScriptedResultOp<ua::DeleteReferencesRequest, ua::DeleteReferencesResponse> deleteReferences;
  ScriptedResultOp<ua::HistoryUpdateRequest, ua::HistoryUpdateResponse> historyUpdate;
  ScriptedResultOp<ua::SetMonitoringModeRequest, ua::SetMonitoringModeResponse> setMonitoringMode;
  ScriptedResultOp<ua::ModifyMonitoredItemsRequest, ua::ModifyMonitoredItemsResponse> modifyMonitoredItems;
  ScriptedResultOp<ua::SetTriggeringRequest, ua::SetTriggeringResponse> setTriggering;
  ScriptedResultOp<ua::QueryFirstRequest, ua::QueryFirstResponse> queryFirst;
  ScriptedResultOp<ua::QueryNextRequest, ua::QueryNextResponse> queryNext;
  ScriptedResultOp<ua::CreateSubscriptionRequest, ua::CreateSubscriptionResponse> createSubscription;
  ScriptedResultOp<ua::CreateMonitoredItemsRequest, ua::CreateMonitoredItemsResponse> createMonitoredItems;
  ScriptedResultOp<ua::PublishRequest, ua::PublishResponse> publish;
  ScriptedResultOp<ua::RepublishRequest, ua::RepublishResponse> republish;
  ScriptedResultOp<ua::DeleteSubscriptionsRequest, ua::DeleteSubscriptionsResponse> deleteSubscriptions;
  ScriptedResultOp<ua::DeleteMonitoredItemsRequest, ua::DeleteMonitoredItemsResponse> deleteMonitoredItems;
  ScriptedResultOp<ua::ModifySubscriptionRequest, ua::ModifySubscriptionResponse> modifySubscription;
  ScriptedResultOp<ua::SetPublishingModeRequest, ua::SetPublishingModeResponse> setPublishingMode;
  ScriptedResultOp<ua::TransferSubscriptionsRequest, ua::TransferSubscriptionsResponse> transferSubscriptions;
  ScriptedVoidOp activateOnChannel;
  ScriptedVoidOp activateOnBound;
  ScriptedVoidOp close;

  /// Sets the id this session reports from @ref session_id (mutex-guarded).
  void set_session_id(ua::NodeId id)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mSessionId = std::move(id);
  }

  void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) override
  {
    read.invoke(std::move(request), std::move(callback));
  }

  /// The server's revised session timeout (ms) the keep-alive interval is bounded by (CL-SESS-020).
  /// 0 (default) = unknown -> ConnectionImpl uses the configured KeepAlivePolicy.interval unchanged.
  double revised_session_timeout_ms() const override
  {
    return revisedSessionTimeoutMs;
  }

  void set_revised_session_timeout_ms(double value)
  {
    revisedSessionTimeoutMs = value;
  }

  double revisedSessionTimeoutMs{0.0};

  void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) override
  {
    historyRead.invoke(std::move(request), std::move(callback));
  }

  void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) override
  {
    write.invoke(std::move(request), std::move(callback));
  }

  void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) override
  {
    browse.invoke(std::move(request), std::move(callback));
  }

  void browse_next_async(
    ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) override
  {
    browseNext.invoke(std::move(request), std::move(callback));
  }

  void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) override
  {
    translateBrowsePaths.invoke(std::move(request), std::move(callback));
  }

  void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) override
  {
    call.invoke(std::move(request), std::move(callback));
  }

  void cancel_async(
    ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) override
  {
    cancel.invoke(std::move(request), std::move(callback));
  }

  void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) override
  {
    registerNodes.invoke(std::move(request), std::move(callback));
  }

  void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) override
  {
    unregisterNodes.invoke(std::move(request), std::move(callback));
  }

  void add_nodes_async(
    ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) override
  {
    addNodes.invoke(std::move(request), std::move(callback));
  }

  void add_references_async(ua::AddReferencesRequest request,
    std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) override
  {
    addReferences.invoke(std::move(request), std::move(callback));
  }

  void delete_nodes_async(ua::DeleteNodesRequest request,
    std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) override
  {
    deleteNodes.invoke(std::move(request), std::move(callback));
  }

  void delete_references_async(ua::DeleteReferencesRequest request,
    std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) override
  {
    deleteReferences.invoke(std::move(request), std::move(callback));
  }

  void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) override
  {
    historyUpdate.invoke(std::move(request), std::move(callback));
  }

  void set_monitoring_mode_async(ua::SetMonitoringModeRequest request,
    std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> callback) override
  {
    setMonitoringMode.invoke(std::move(request), std::move(callback));
  }

  void modify_monitored_items_async(ua::ModifyMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)> callback) override
  {
    modifyMonitoredItems.invoke(std::move(request), std::move(callback));
  }

  void set_triggering_async(ua::SetTriggeringRequest request,
    std::function<void(ua::Result<ua::SetTriggeringResponse>)> callback) override
  {
    setTriggering.invoke(std::move(request), std::move(callback));
  }

  void query_first_async(
    ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) override
  {
    queryFirst.invoke(std::move(request), std::move(callback));
  }

  void query_next_async(
    ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) override
  {
    queryNext.invoke(std::move(request), std::move(callback));
  }

  void create_subscription_async(ua::CreateSubscriptionRequest request,
    std::function<void(ua::Result<ua::CreateSubscriptionResponse>)> callback) override
  {
    createSubscription.invoke(std::move(request), std::move(callback));
  }

  void create_monitored_items_async(ua::CreateMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::CreateMonitoredItemsResponse>)> callback) override
  {
    createMonitoredItems.invoke(std::move(request), std::move(callback));
  }

  void publish_async(
    ua::PublishRequest request, std::function<void(ua::Result<ua::PublishResponse>)> callback) override
  {
    publish.invoke(std::move(request), std::move(callback));
  }

  void republish_async(
    ua::RepublishRequest request, std::function<void(ua::Result<ua::RepublishResponse>)> callback) override
  {
    republish.invoke(std::move(request), std::move(callback));
  }

  void delete_subscriptions_async(ua::DeleteSubscriptionsRequest request,
    std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)> callback) override
  {
    deleteSubscriptions.invoke(std::move(request), std::move(callback));
  }

  void delete_monitored_items_async(ua::DeleteMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)> callback) override
  {
    deleteMonitoredItems.invoke(std::move(request), std::move(callback));
  }

  void modify_subscription_async(ua::ModifySubscriptionRequest request,
    std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) override
  {
    modifySubscription.invoke(std::move(request), std::move(callback));
  }

  void set_publishing_mode_async(ua::SetPublishingModeRequest request,
    std::function<void(ua::Result<ua::SetPublishingModeResponse>)> callback) override
  {
    setPublishingMode.invoke(std::move(request), std::move(callback));
  }

  void transfer_subscriptions_async(ua::TransferSubscriptionsRequest request,
    std::function<void(ua::Result<ua::TransferSubscriptionsResponse>)> callback) noexcept override
  {
    transferSubscriptions.invoke(std::move(request), std::move(callback));
  }

  void activate_on_channel_async(std::shared_ptr<ua::client::detail::ChannelOps> channel,
    ua::client::Session::ActivateConfig /*config*/, std::function<void(ua::VoidResult)> callback) override;

  void activate_on_bound_channel_async(
    ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback) override
  {
    capture_activate_config(std::move(config));
    activateOnBound.invoke(std::move(callback));
  }

  /// The ActivateConfig most recently handed to either activate interface. Used to assert that a reconnect
  /// re-activates with the ORIGINAL credentials (CL-RECONN-002), not a reset/default config.
  ua::client::Session::ActivateConfig captured_activate_config() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCapturedActivateConfig;
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    close.invoke(std::move(callback));
  }

  [[nodiscard]] ua::NodeId session_id() const override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mSessionId;
  }

private:
  void capture_activate_config(ua::client::Session::ActivateConfig config)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mCapturedActivateConfig = std::move(config);
  }

  mutable std::mutex mMutex;
  ua::NodeId mSessionId{1, 42};
  ua::client::Session::ActivateConfig mCapturedActivateConfig;
};

/// Fake @ref ua::client::detail::ChannelOps: carries a test-visible @ref id, a settable open flag (default
/// open) with a @ref consume that flips it closed (mirroring the production consumed-channel invariant),
/// and a scriptable create-session op that yields a fresh @ref FakeSessionOps.
class FakeChannelOps : public ua::client::detail::ChannelOps
{
public:
  explicit FakeChannelOps(int id) : mId(id)
  {}

  /// The test-visible identity used to assert which channel a pending holder points at.
  int id() const
  {
    return mId;
  }

  /// Flips @ref is_open to false (production activate consumes the inner channel).
  void consume()
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mOpen = false;
  }

  void set_open(bool open)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mOpen = open;
  }

  /// Scripts a bad create-session Result; when unset a fresh @ref FakeSessionOps is yielded.
  void set_create_session_result(ua::StatusCode status)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mCreateSessionStatus = status;
  }

  /// The most recent session yielded by @ref create_session_async (for the test to inspect / configure).
  std::shared_ptr<FakeSessionOps> last_created_session() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastCreatedSession;
  }

  std::size_t create_session_call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCreateSessionCalls;
  }

  /// The config of the most recent @ref create_session_async (empty before the first).
  std::optional<ua::client::SecureChannel::CreateSessionConfig> last_create_config() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastCreateConfig;
  }

  void create_session_async(ua::client::SecureChannel::CreateSessionConfig config,
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::SessionOps>>)> callback) override
  {
    std::shared_ptr<FakeSessionOps> session;
    ua::StatusCode status{ua::Status::Good};
    {
      std::lock_guard<std::mutex> lock(mMutex);
      ++mCreateSessionCalls;
      mLastCreateConfig = std::move(config);
      status = mCreateSessionStatus;
      if (status.is_good())
      {
        session = std::make_shared<FakeSessionOps>();
        mLastCreatedSession = session;
      }
    }
    if (!status.is_good())
    {
      callback(ua::Result<std::shared_ptr<ua::client::detail::SessionOps>>{status});
      return;
    }
    callback(ua::Result<std::shared_ptr<ua::client::detail::SessionOps>>{
      std::static_pointer_cast<ua::client::detail::SessionOps>(session)});
  }

  void get_endpoints_async(ua::GetEndpointsRequest request,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override
  {
    getEndpoints.invoke(std::move(request), std::move(callback));
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    callback(ua::VoidResult{});
  }

  [[nodiscard]] bool is_open() const override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mOpen;
  }

  /// Scriptable GetEndpoints op (CL-RECONN-005): records every GetEndpoints the reconnect FSM issues on the
  /// security-failure path; default Good.
  ScriptedResultOp<ua::GetEndpointsRequest, ua::GetEndpointsResponse> getEndpoints;

private:
  mutable std::mutex mMutex;
  int mId;
  bool mOpen = true;
  ua::StatusCode mCreateSessionStatus{ua::Status::Good};
  std::size_t mCreateSessionCalls = 0;
  std::optional<ua::client::SecureChannel::CreateSessionConfig> mLastCreateConfig;
  std::shared_ptr<FakeSessionOps> mLastCreatedSession;
};

inline void FakeSessionOps::activate_on_channel_async(std::shared_ptr<ua::client::detail::ChannelOps> channel,
  ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback)
{
  capture_activate_config(std::move(config));
  // Production activate MOVES the inner channel into the session, consuming it (is_open -> false) even
  // when activation then fails with Bad_SessionIdInvalid; mirror that so the CL-RECONN-003 route sees a
  // consumed channel and re-opens.
  if (auto* fake = dynamic_cast<FakeChannelOps*>(channel.get()))
  {
    fake->consume();
  }
  activateOnChannel.invoke(std::move(callback));
}

/// Fake @ref ua::client::detail::ReopenChannelOps: yields a fresh @ref FakeChannelOps per reopen, with a
/// HOLD mode (park the yield callback) so a test can drive late / interleaved open-channel completions.
/// Thread-safe; each yielded channel gets a distinct id so pending-holder identity is assertable.
class FakeReopen
{
public:
  /// Returns the interface-level ReopenChannelOps bound to this fake.
  ua::client::detail::ReopenChannelOps as_ops()
  {
    return [this](std::function<void(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>)> yield)
    {
      invoke(std::move(yield));
    };
  }

  void set_hold(bool hold)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mHold = hold;
  }

  /// Optional hook applied to every freshly-created @ref FakeChannelOps BEFORE it is yielded, so a test can
  /// script the channel's ops (e.g. `getEndpoints`) deterministically ahead of the orchestrator using it -
  /// there is otherwise no window to script a channel created inside the reopen (CL-RECONN-005 discovery
  /// channel). The `shared_ptr` is passed (not a bare reference) so a test can RETAIN the channel for
  /// post-hoc inspection: a throwaway discovery channel is otherwise released the moment the orchestrator's
  /// callback completes. Applied in both hold-mode (@ref fire_next_channel) and inline (@ref invoke) paths.
  void set_channel_configurator(std::function<void(const std::shared_ptr<FakeChannelOps>&)> configurator)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mChannelConfigurator = std::move(configurator);
  }

  std::size_t call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCalls;
  }

  std::size_t pending_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mHeld.size();
  }

  /// Fires the oldest parked reopen with a fresh @ref FakeChannelOps of the given @p id (Good). Returns
  /// the channel yielded so the test can assert pending-holder identity by id.
  std::shared_ptr<FakeChannelOps> fire_next_channel(int id)
  {
    auto channel = std::make_shared<FakeChannelOps>(id);
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>)> yield;
    std::function<void(const std::shared_ptr<FakeChannelOps>&)> configurator;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      yield = std::move(mHeld.front());
      mHeld.erase(mHeld.begin());
      configurator = mChannelConfigurator;
    }
    if (configurator)
    {
      configurator(channel);
    }
    yield(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>{
      std::static_pointer_cast<ua::client::detail::ChannelOps>(channel)});
    return channel;
  }

  /// Fires the oldest parked reopen with a bad Result.
  void fire_next_failure(ua::StatusCode status)
  {
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>)> yield;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      yield = std::move(mHeld.front());
      mHeld.erase(mHeld.begin());
    }
    yield(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>{status});
  }

private:
  void invoke(std::function<void(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>)> yield)
  {
    std::function<void(const std::shared_ptr<FakeChannelOps>&)> configurator;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      ++mCalls;
      if (mHold)
      {
        mHeld.push_back(std::move(yield));
        return;
      }
      configurator = mChannelConfigurator;
    }
    // Inline (non-held) completion: yield a fresh open channel numbered by call order.
    auto channel = std::make_shared<FakeChannelOps>(static_cast<int>(call_count()));
    if (configurator)
    {
      configurator(channel);
    }
    yield(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>{
      std::static_pointer_cast<ua::client::detail::ChannelOps>(channel)});
  }

  mutable std::mutex mMutex;
  bool mHold = false;
  std::size_t mCalls = 0;
  std::vector<std::function<void(ua::Result<std::shared_ptr<ua::client::detail::ChannelOps>>)>> mHeld;
  std::function<void(const std::shared_ptr<FakeChannelOps>&)> mChannelConfigurator;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_UNIT_CLIENT_CONNECTION_FAKE_SESSION_OPS_H
