// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Wave C of the configuration coverage matrix - server admission and resource caps
///        (configuration coverage matrix section 6).
///
/// Each row sets ONE cap to a small non-default value and drives a request that exceeds it, asserting the
/// status a peer receives. The default for every cap here is large enough that the same request succeeds,
/// which is what makes the row non-vacuous.
///
/// THE HARD PART IS THE BRANCH, NOT THE STATUS. `Bad_TooManyOperations` and `Bad_TooManySubscriptions` are
/// each raised from several places, so a test that merely provokes the status proves nothing about WHICH
/// limit fired - the "wrong-branch" anti-pattern in section 1. Where two caps share a status, the row pins
/// the branch by leaving the OTHER cap high and shaping the request so only the cap under test can reject it,
/// and says so in its comment.

#include <gmock/gmock.h>
#include "offloading_node_management_delegate.h"
#include <gtest/gtest.h>
#include <functional>

#include "compliance_helpers.h"
#include "ua_url_parser.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include "deferred_namespace.h"
#include "misbehaving_server.h"
#include "ua_create_session_request.h"
#include "requests.h"
#include "ua_open_secure_channel_request.h"
#include "ua_diagnostic_info.h"
#include "role_based_security_fixture.h"
#include "subscription.h"
#include "matchers.h"
#include "ua_session_subscription_services.h"
#include "ua_create_subscription_response.h"
#include "ua_create_subscription_request.h"
#include "test_utilities.h"

#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_value_id.h"
#include "ua_read_event_details.h"
#include "ua_session_attribute_services.h"
#include "ua_date_time.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_update_data_details.h"
#include "ua_update_event_details.h"
#include "ua_perform_update_type.h"
#include "ua_data_value.h"
#include "ua_variant.h"
#include "ua_attribute_id.h"
#include "ua_array.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_string.h"
#include "ua_byte_string.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_session_monitored_item_services.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_method_id.h"
#include "ua_session_method_services.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_localized_text.h"
#include "ua_default_namespace.h"
#include "ua_node_accessor.h"
#include "ua_discovery.h"
#include "ua_listen_options.h"
#include "ua_connection.h"
#include "ua_browse_cursor.h"
#include "ua_event_filter.h"
#include "ua_generic_event.h"
#include "ua_content_filter_element.h"
#include "ua_literal_operand.h"
#include "ua_simple_attribute_operand.h"
#include "ua_objecttype_id.h"
#include "ua_filter_operator.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_close_session_request.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_service_fault.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_client_observers.h"
#include "ua_diagnostic_info.h"
#include "ua_status_change_notification.h"
#include "ua_server_authentication.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_server_configuration.h"
#include "ua_namespace_delegates.h"
#include "ua_session_node_management_services.h"
#include "ua_session_view_services.h"
#include "ua_status.h"
#include "ua_variable_id.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>

#include <atomic>
#include <mutex>
#include <span>
#include <unordered_map>
#include <set>
#include <array>
#include <future>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::test_helpers;

namespace
{

// Records the depth of the deepest decoded ErrorDetail chain the client surfaced.
class ChainDepthObserver : public ua::client::ConnectionObserver
{
public:
  explicit ChainDepthObserver(std::shared_ptr<std::atomic<size_t>> depth) : mDepth(std::move(depth))
  {}

  void on_error_chain(const ua::client::Connection&, ua::StatusCode,
    std::shared_ptr<const ua::ErrorDetail> chain, std::string_view) override
  {
    size_t depth = 0;
    for (const auto* link = chain.get(); link != nullptr; link = link->cause.get())
      ++depth;
    size_t previous = mDepth->load();
    while (depth > previous && !mDepth->compare_exchange_weak(previous, depth))
    {
    }
  }

private:
  std::shared_ptr<std::atomic<size_t>> mDepth;
};

// Holds method-call completions so a request can be kept deliberately in flight. Used by the in-flight
// backpressure rows, which need concurrency the client cannot otherwise be made to produce.
class ParkedCalls
{
public:
  void hold(std::function<void(CallResult)> completion)
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mHeld.push_back(std::move(completion));
    }
    mArrived.notify_all();
  }

  bool wait_for_calls(size_t count, std::chrono::milliseconds timeout = std::chrono::seconds{10})
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mArrived.wait_for(lock, timeout, [&] { return mHeld.size() >= count; });
  }

  void release_all()
  {
    std::vector<std::function<void(CallResult)>> held;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      held.swap(mHeld);
    }
    for (auto& completion : held)
      completion(CallResult{CallMethodResult{}});
  }

private:
  std::mutex mMutex;
  std::condition_variable mArrived;
  std::vector<std::function<void(CallResult)>> mHeld;
};

// Registers `RegisterNodes` with a one-node ceiling. RegisterNodes is the cleanest operation-limit row in
// the wave: `maxNodesPerRegisterNodes` is the ONLY cap that governs it, so `Bad_TooManyOperations` here
// cannot have come from another branch.
class ConfigurationRegisterNodesLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().operationLimits.maxNodesPerRegisterNodes = 1;  // default 1000
  }
};

// Row: OperationLimits::maxNodesPerRegisterNodes.
TEST_F(ConfigurationRegisterNodesLimit, RegisterNodesAboveTheLimitIsRefused)
{
  // Control first: one node is within the ceiling, so a failure below cannot be blamed on the request
  // being malformed or the nodes being unknown.
  auto within = mSession->view().try_register_nodes_sync(register_nodes(mWritableVariableId));
  ASSERT_TRUE(within.is_good()) << to_string(within.status_code());
  EXPECT_EQ(within.value().registered_node_ids().size(), 1u);

  // try_ rather than the throwing wrapper: a refused service result is the expected outcome here, not an
  // error the test wants unwound.
  auto over = mSession->view().try_register_nodes_sync(register_nodes({mWritableVariableId, mTestFolderId}));
  EXPECT_EQ(over.status_code().as_status(), Status::BadTooManyOperations)
    << "two nodes exceed a ceiling of one; under the default of 1000 this same request succeeds, as the "
       "one-node control above shows it is otherwise well formed";
}

// A delegate that accepts everything. Node management answers `Bad_ServiceUnsupported` until a delegate
// is installed, so WITHOUT this the operation limit is never reached and the row would be testing the
// absence of a delegate rather than the cap. It does no address-space work: the limit is enforced before
// any item is dispatched, so the rows below only need the service to be reachable.
class PermissiveNodeManagementDelegate final : public ua::server::NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items, AddNodesCompleteCallback callback) override
  {
    BatchResult<AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      ua::AddNodesResult result;
      result.status_code() = ua::Status::Good;
      const auto& requested = items[i].item.requested_new_node_id().node_id();
      result.added_node_id() = requested.is_null() ? NodeId{items[i].destination.namespaceIndex,
                                                       static_cast<std::uint32_t>(60000u + i)}
                                                   : requested;
      batch.items.emplace_back(std::move(result));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<AddReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    callback(void_batch(items.size()));
  }

  void delete_nodes_async(std::shared_ptr<const Context>, AddressSpace, std::vector<DeleteNodesItem> items,
    NodeMgmtCompleteCallback callback) override
  {
    callback(void_batch(items.size()));
  }

  void delete_references_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    callback(void_batch(items.size()));
  }

private:
  static BatchResult<VoidResult> void_batch(std::size_t count)
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(count);
    return batch;
  }
};

// Registers a one-node ceiling on node management, with a delegate installed so the service is reachable.
class ConfigurationNodeManagementLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;  // default 1000
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();
    mDelegate = std::make_shared<PermissiveNodeManagementDelegate>();
    mServer.server().set_node_management_delegate(ua::test::offloaded(mDelegate));
  }

  std::shared_ptr<PermissiveNodeManagementDelegate> mDelegate;
};

// Row: OperationLimits::maxNodesPerNodeManagement.
//
// DeleteNodes is the probe rather than AddNodes because it carries no node payload to get wrong: the cap
// is checked before any item is dispatched, so nothing but the item COUNT can decide the outcome.
TEST_F(ConfigurationNodeManagementLimit, DeleteNodesAboveTheLimitIsRefused)
{
  const NodeId absentA{mTestNamespaceIndex, 0xDEAD0001u};
  const NodeId absentB{mTestNamespaceIndex, 0xDEAD0002u};

  // Control: one item is within the ceiling, so the SERVICE accepts the request. This is what separates
  // "refused wholesale" below from "reached the delegate".
  auto within = mSession->node_management().try_delete_nodes_sync(delete_nodes({absentA}));
  ASSERT_TRUE(within.is_good()) << "one node is within the ceiling, so the service must accept it: "
                                << to_string(within.status_code());

  auto over = mSession->node_management().try_delete_nodes_sync(delete_nodes({absentA, absentB}));
  EXPECT_EQ(over.status_code().as_status(), Status::BadTooManyOperations)
    << "two nodes exceed a ceiling of one, refused at the service level; under the default of 1000 this "
       "same request is accepted, as the one-node control shows";
}

// Sets the two history-read ceilings to DIFFERENT values so a refusal names which one fired.
class ConfigurationHistoryReadLimits : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    auto& ops = serverCfg.server_capabilities().operationLimits;
    ops.maxNodesPerHistoryReadEvents = 1;  // default 100 - the cap under test
    ops.maxNodesPerHistoryReadData = 100;  // left HIGH on purpose, see the test comment
  }

  // A HistoryRead carrying ReadEventDetails over @p nodeCount nodes. The service checks the operation
  // limit before it validates the details, so a minimal filter is enough to reach the branch.
  static HistoryReadRequest event_read(std::size_t nodeCount)
  {
    HistoryReadRequest request;
    auto details = ua::make_unique<ReadEventDetails>();
    details->num_values_per_node() = 10;
    details->start_time() = DateTime{};
    details->end_time() = DateTime{};
    request.history_read_details() = std::move(details);
    for (std::size_t i = 0; i < nodeCount; ++i)
    {
      HistoryReadValueId item;
      item.node_id() = NodeId{VariableId::Server_ServerStatus};
      request.nodes_to_read().push_back(std::move(item));
    }
    return request;
  }
};

// Row: OperationLimits::maxNodesPerHistoryReadEvents.
//
// THIS ROW PINS A FIX. Before it, the event ceiling was advertised under
// `Server.ServerCapabilities.OperationLimits.MaxNodesPerHistoryReadEvents` and read by nothing: every
// HistoryRead, event or not, was bounded by the DATA ceiling. So the data ceiling is deliberately left at
// 100 here - under the old behaviour a 2-node event read passed, and only a server consulting the EVENT
// ceiling refuses it. The raw-read control below is the other half: it must still be accepted, or the
// refusal above would just mean "some history limit fired".
TEST_F(ConfigurationHistoryReadLimits, EventReadUsesTheEventCeilingNotTheDataCeiling)
{
  // A whole-request rejection is delivered as a ServiceFault, not as a HistoryReadResponse carrying the
  // bad code in its header (Part 4 7.34), so it surfaces on the Result rather than in a response header.
  auto overEvents = mSession->attributes().try_history_read_sync(event_read(2));
  EXPECT_EQ(overEvents.status_code().as_status(), Status::BadTooManyOperations)
    << "two nodes exceed the event ceiling of 1; with the data ceiling of 100 applied instead - the "
       "behaviour before this fix - the request would have been accepted";

  auto withinEvents = mSession->attributes().try_history_read_sync(event_read(1));
  EXPECT_NE(withinEvents.status_code().as_status(), Status::BadTooManyOperations)
    << "one node is within the event ceiling, so the count must not be what refuses it";

  // Branch control: a RAW read of 2 nodes is governed by the data ceiling (100) and must NOT be refused
  // for count. This is what proves the event refusal above came from the event ceiling specifically.
  auto rawTwoNodes = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(DateTime{}, DateTime{}).read(mWritableVariableId).read(mTestFolderId));
  EXPECT_NE(rawTwoNodes.status_code().as_status(), Status::BadTooManyOperations)
    << "the data ceiling is 100, so a 2-node RAW read must not trip an operation limit; if it does, the "
       "service is still applying one ceiling to both request classes";
}

// Server-wide subscription ceiling of 2, with the PER-SESSION ceiling left at its default of 50.
// `Bad_TooManySubscriptions` is raised from two branches (`ua_subscriptions_pipeline.cpp:145` per-session
// and :157 server-wide), so the per-session ceiling is deliberately left high and the third subscription
// is created on a SECOND session holding none of its own: only the server-wide branch can refuse it.
class ConfigurationServerWideSubscriptionLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().maxSubscriptions = 2;  // default 1000
    serverCfg.server_capabilities().maxSubscriptionsPerSession = 50;  // the default, left HIGH on purpose
  }
};

// Row: ServerCapabilities::maxSubscriptions.
TEST_F(ConfigurationServerWideSubscriptionLimit, ThirdSubscriptionAcrossTwoSessionsIsRefused)
{
  auto first = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(first, ServiceResultIsGood());
  auto second = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(second, ServiceResultIsGood()) << "two subscriptions are within the server-wide ceiling";

  // A second session, on its own channel, holding NO subscriptions of its own.
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "SecondSession"});
  session.activate_sync();

  auto third = session.subscriptions().try_create_subscription_sync(build_subscription_request({}));
  EXPECT_EQ(third.status_code().as_status(), Status::BadTooManySubscriptions)
    << "the server-wide count is already 2; this session holds none, so the per-session ceiling of 50 "
       "cannot be what refused it. Under the default server-wide ceiling of 1000 this create succeeds";

  (void)session.try_close_sync();
}

// A one-item ceiling on history data updates. HistoryUpdate is heterogeneous - each item carries its own
// details type - so this row deliberately sends items of ONE class (UpdateDataDetails) and asserts the
// data ceiling governs them. The event ceiling's own row is not written: see defect D6 in the tracker,
// where the update-side event ceiling is recorded as still inert pending a design call on mixed batches.
class ConfigurationHistoryUpdateLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().operationLimits.maxNodesPerHistoryUpdateData = 1;  // default 100
  }

  // @p count UpdateDataDetails items, each a one-value insert against a well-known NS0 variable. The
  // ceiling is checked before any item is validated, so the payload only has to be well formed.
  static HistoryUpdateRequest update_data(std::size_t count)
  {
    HistoryUpdateRequest request;
    for (std::size_t i = 0; i < count; ++i)
    {
      auto details = std::make_unique<UpdateDataDetails>();
      details->node_id() = NodeId{VariableId::Server_ServerStatus_State};
      details->perform_insert_replace() = PerformUpdateType::Insert;
      details->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
      RefStructure<Structure> wrapped;
      wrapped = std::unique_ptr<Structure>(std::move(details));
      request.history_update_details().push_back(std::move(wrapped));
    }
    return request;
  }
};

// Row: OperationLimits::maxNodesPerHistoryUpdateData.
TEST_F(ConfigurationHistoryUpdateLimit, UpdateAboveTheDataCeilingIsRefused)
{
  // Like HistoryRead, a whole-request rejection is a ServiceFault, so it lands on the Result.
  auto over = mSession->attributes().try_history_update_sync(update_data(2));
  EXPECT_EQ(over.status_code().as_status(), Status::BadTooManyOperations)
    << "two items exceed a ceiling of one; under the default of 100 this same request is accepted, as "
       "the one-item control shows";

  auto within = mSession->attributes().try_history_update_sync(update_data(1));
  EXPECT_NE(within.status_code().as_status(), Status::BadTooManyOperations)
    << "one item is within the ceiling, so the count must not be what refuses it";
}

// An 8-element array ceiling. This is the matrix's canonical "advertised is not enforced" case: the value
// is BOTH published under Server.ServerCapabilities.MaxArrayLength AND fed into the server's decode
// limits, so the row needs two oracles and is not covered by either alone.
class ConfigurationArrayLengthLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().maxArrayLength = 8;  // default 65535
  }

  static Array<int32_t> ints(std::size_t count)
  {
    Array<int32_t> values;
    for (std::size_t i = 0; i < count; ++i)
      values.push_back(static_cast<int32_t>(i));
    return values;
  }
};

// Row: ServerCapabilities::maxArrayLength.
//
// Ordered deliberately: the within-limit write and the advertisement read happen BEFORE the oversized
// write, because a decode-limit breach may take the channel down with it and would otherwise mask them.
TEST_F(ConfigurationArrayLengthLimit, ArrayLengthCeilingIsBothAdvertisedAndEnforced)
{
  // Control: 8 elements is exactly the ceiling and must be accepted.
  auto within =
    mSession->attributes().try_write_sync(WriteRequestBuilder().write(mArrayVariableId, Variant{ints(8)}));
  ASSERT_TRUE(within.is_good()) << to_string(within.status_code());
  EXPECT_TRUE(within.value().results()[0].is_good())
    << "a write at exactly the ceiling must succeed, or the enforcement oracle below proves nothing";

  // Oracle 1 - ADVERTISED: the configured value reaches the address space.
  auto advertised = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_MaxArrayLength}));
  ASSERT_TRUE(advertised.is_good()) << to_string(advertised.status_code());
  ASSERT_FALSE(advertised.value().results().empty());
  EXPECT_EQ(advertised.value().results()[0].value().template as<uint32_t>(), 8u)
    << "the configured ceiling must be published under ServerCapabilities.MaxArrayLength";

  // Oracle 2 - ENFORCED: reading the advertised node back is NOT sufficient. A server that published 8
  // and accepted 16 would pass the oracle above; only this half proves the limit is applied.
  auto over =
    mSession->attributes().try_write_sync(WriteRequestBuilder().write(mArrayVariableId, Variant{ints(16)}));
  const bool refused =
    over.is_bad() || (over.value().results().size() == 1 && over.value().results()[0].is_bad());
  EXPECT_TRUE(refused) << "16 elements exceed the ceiling of 8 and must be refused; under the default of "
                          "65535 this same write succeeds. Status was: "
                       << to_string(over.status_code());
}

// String and ByteString ceilings. Both feed the SERVER'S DECODE limits, so the breach happens while the
// request is being decoded - before the target node's data type is ever consulted. That is why these rows
// can write to an Int32 node: a within-limit write is refused for TYPE reasons (`Bad_TypeMismatch` per
// item) while an over-limit write is refused for ENCODING reasons, and the two are distinguishable.
class ConfigurationStringLengthLimits : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    // Chosen ABOVE what the SDK's own bootstrap needs and well below the probes. A 16-byte ceiling looks
    // tidier but kills the handshake itself: session names, URIs and certificates all cross the wire
    // before any test body runs, and the fixture then fails in SetUp with a transport error.
    serverCfg.server_capabilities().maxStringLength = 256;  // default 1048576
    serverCfg.server_capabilities().maxByteStringLength = 4096;  // default 16777216
  }

  // True when the request was rejected as a whole (service level or channel), rather than answered with a
  // per-item result. A decode-limit breach cannot produce a per-item status: decoding never got that far.
  bool refused_wholesale(const auto& result) const
  {
    return result.is_bad() || result.value().results().empty();
  }
};

// Row: ServerCapabilities::maxStringLength.
TEST_F(ConfigurationStringLengthLimits, StringLengthCeilingIsAdvertisedAndEnforced)
{
  auto advertised = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_MaxStringLength}));
  ASSERT_TRUE(advertised.is_good()) << to_string(advertised.status_code());
  ASSERT_FALSE(advertised.value().results().empty());
  EXPECT_EQ(advertised.value().results()[0].value().template as<uint32_t>(), 256u)
    << "the configured ceiling must be published under ServerCapabilities.MaxStringLength";

  // Within the ceiling: the server decodes it and then rejects it on TYPE grounds, per item. The point is
  // that the request survived decoding.
  auto within = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{String{std::string(64, 'a')}}));
  EXPECT_FALSE(refused_wholesale(within))
    << "a 64-character string is within the ceiling and must survive decoding, whatever the node's type "
       "says about it afterwards";

  // Over the ceiling: decoding fails, so there is no per-item result to carry a status.
  auto over = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{String{std::string(1024, 'a')}}));
  EXPECT_TRUE(refused_wholesale(over))
    << "a 1024-character string exceeds the ceiling of 256 and must be refused during decode; under the "
       "default of 1048576 it decodes fine. Status was: "
    << to_string(over.status_code());
}

// Row: ServerCapabilities::maxByteStringLength.
TEST_F(ConfigurationStringLengthLimits, ByteStringLengthCeilingIsAdvertisedAndEnforced)
{
  auto advertised = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_MaxByteStringLength}));
  ASSERT_TRUE(advertised.is_good()) << to_string(advertised.status_code());
  ASSERT_FALSE(advertised.value().results().empty());
  EXPECT_EQ(advertised.value().results()[0].value().template as<uint32_t>(), 4096u)
    << "the configured ceiling must be published under ServerCapabilities.MaxByteStringLength";

  auto within = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{ByteString(512, uint8_t{0x5A})}));
  EXPECT_FALSE(refused_wholesale(within)) << "512 bytes is within the ceiling and must survive decoding";

  auto over = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{ByteString(8192, uint8_t{0x5A})}));
  EXPECT_TRUE(refused_wholesale(over))
    << "8192 bytes exceeds the ceiling of 4096 and must be refused during decode; under the default of "
       "16777216 it decodes fine. Status was: "
    << to_string(over.status_code());
}

// Server-wide monitored-item ceiling of 2, with the PER-SUBSCRIPTION ceiling left at its default. Like
// the subscription row, `Bad_TooManyMonitoredItems` has two sources, so the third item is created on a
// SECOND subscription holding none of its own - only the server-wide gate can reject it.
class ConfigurationServerWideMonitoredItemLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().maxMonitoredItems = 2;  // default 10000
    serverCfg.server_capabilities().maxMonitoredItemsPerSubscription = 50;  // default, left HIGH
  }
};

// Row: ServerCapabilities::maxMonitoredItems.
//
// The server-wide gate rejects PER ITEM (it trims the tail of the batch), not with a service fault, so
// the oracle reads the item's own status rather than the response header.
TEST_F(ConfigurationServerWideMonitoredItemLimit, ItemBeyondTheServerWideCeilingIsRefused)
{
  auto subA = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(subA, ServiceResultIsGood());
  auto subB = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(subB, ServiceResultIsGood());

  for (int i = 0; i < 2; ++i)
  {
    auto created = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subA.subscription_id(), mWritableVariableId));
    ASSERT_EQ(created.results().size(), 1u);
    ASSERT_TRUE(created.results()[0].status_code().is_good())
      << "item " << i << " is within the server-wide ceiling of 2";
  }

  // Third item, on a subscription holding NONE of its own.
  auto third = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subB.subscription_id(), mWritableVariableId));
  ASSERT_EQ(third.results().size(), 1u);
  EXPECT_EQ(third.results()[0].status_code().as_status(), Status::BadTooManyMonitoredItems)
    << "the server-wide count is already 2; this subscription holds none, so the per-subscription "
       "ceiling of 50 cannot be what refused it. Under the default server-wide ceiling of 10000 this "
       "item is created";
}

// ===============================================================================================
// Wave D of the configuration coverage matrix (section 7) - subscription and publish tuning.
// ===============================================================================================

// A keep-alive ceiling of 5. The revision is a pure clamp, so the oracle is the value the client is told
// to use - the most direct kind of observable difference there is.
class ConfigurationKeepAliveLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.maxKeepAliveCount = 5;  // default 300
  }
};

// Row: SubscriptionLimits::maxKeepAliveCount.
TEST_F(ConfigurationKeepAliveLimit, RequestedKeepAliveCountIsClampedToTheCeiling)
{
  auto resp =
    mSession->subscriptions().create_subscription_sync(build_subscription_request({.keepAliveCount = 100}));
  ASSERT_THAT(resp, ServiceResultIsGood());

  EXPECT_EQ(resp.revised_max_keep_alive_count(), 5u)
    << "a requested keep-alive count of 100 must be revised down to the configured ceiling of 5; under "
       "the default of 300 the request is returned unrevised at 100";

  // Control: a request already under the ceiling is returned as asked, so the row is testing the clamp
  // rather than a server that simply overwrites every request with its own number.
  auto under =
    mSession->subscriptions().create_subscription_sync(build_subscription_request({.keepAliveCount = 3}));
  ASSERT_THAT(under, ServiceResultIsGood());
  EXPECT_EQ(under.revised_max_keep_alive_count(), 3u)
    << "a request below the ceiling must be honoured, not clamped to the ceiling";
}

// A lifetime-count ceiling of 50. The revision is a pure clamp; the oracle is the value the client is
// told to use.
class ConfigurationLifetimeCountLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.maxLifetimeCount = 50;  // default 10000
  }
};

// Row: SubscriptionLimits::maxLifetimeCount.
// @relation(AC-SVR-SUB-GEN-034-LIFETIME-COUNT-IS-CAPPED, scope=function)
TEST_F(ConfigurationLifetimeCountLimit, RequestedLifetimeCountIsClampedToTheCeiling)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 100000, .keepAliveCount = 3}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  EXPECT_EQ(resp.revised_lifetime_count(), 50u)
    << "a requested lifetime count of 100000 must be revised down to the configured ceiling of 50; under "
       "the default of 10000 it is revised to 10000";

  auto under = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 20, .keepAliveCount = 3}));
  ASSERT_THAT(under, ServiceResultIsGood());
  EXPECT_EQ(under.revised_lifetime_count(), 20u) << "a request below the ceiling must be honoured";
}

// Durable subscriptions turned OFF. A gate, so both halves are required: the enabled control shows the
// call is otherwise well formed and would succeed, and the disabled case shows the flag actually refuses.
class ConfigurationDurableSubscriptionsDisabled : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.durableSubscriptionsEnabled = false;  // default true
  }
};

class ConfigurationDurableSubscriptionsEnabled : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.durableSubscriptionsEnabled = true;  // the default, stated explicitly
  }
};

namespace
{
// SetSubscriptionDurable through the Call service; returns the operation-level status.
StatusCode set_durable(ua::client::Session& session, uint32_t subscriptionId)
{
  Array<Variant> args;
  args.push_back(Variant{subscriptionId});
  args.push_back(Variant{uint32_t{5}});

  CallMethodRequest methodReq;
  methodReq.object_id() = NodeId{ObjectId::Server};
  methodReq.method_id() = NodeId{MethodId::Server_SetSubscriptionDurable};
  methodReq.input_arguments() = std::move(args);

  CallRequest req;
  req.methods_to_call().push_back(std::move(methodReq));
  auto resp = session.methods().call_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  return resp.results().empty() ? StatusCode{} : resp.results()[0].status_code();
}

// As above, but returns the revised lifetime the server granted (its single output argument).
uint32_t set_durable_revised(ua::client::Session& session, uint32_t subscriptionId, uint32_t requestedHours)
{
  Array<Variant> args;
  args.push_back(Variant{subscriptionId});
  args.push_back(Variant{requestedHours});

  CallMethodRequest methodReq;
  methodReq.object_id() = NodeId{ObjectId::Server};
  methodReq.method_id() = NodeId{MethodId::Server_SetSubscriptionDurable};
  methodReq.input_arguments() = std::move(args);

  CallRequest req;
  req.methods_to_call().push_back(std::move(methodReq));
  auto resp = session.methods().call_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  if (resp.results().empty() || resp.results()[0].output_arguments().empty())
    return 0;
  return resp.results()[0].output_arguments()[0].template as<uint32_t>();
}

}  // namespace

// Row: SubscriptionLimits::durableSubscriptionsEnabled - the OFF half.
TEST_F(ConfigurationDurableSubscriptionsDisabled, SetSubscriptionDurableIsRefusedWhenDisabled)
{
  auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(sub, ServiceResultIsGood());

  EXPECT_EQ(set_durable(*mSession, sub.subscription_id()).as_status(), Status::BadServiceUnsupported)
    << "with durable subscriptions disabled the call must be refused honestly rather than silently "
       "lifting the per-item queue ceiling";
}

// Row: SubscriptionLimits::durableSubscriptionsEnabled - the ON half, which is what stops the OFF half
// above from passing against a server where SetSubscriptionDurable never works at all.
TEST_F(ConfigurationDurableSubscriptionsEnabled, SetSubscriptionDurableSucceedsWhenEnabled)
{
  auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(sub, ServiceResultIsGood());

  EXPECT_TRUE(set_durable(*mSession, sub.subscription_id()).is_good())
    << "with the flag enabled the identical call must succeed";
}

// Durable subscriptions enabled, with a 2-hour lifetime ceiling.
class ConfigurationDurableLifetimeLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.durableSubscriptionsEnabled = true;
    serverCfg.subscriptionLimits.maxDurableSubscriptionLifetimeHours = 2;  // default 24
  }
};

// Row: SubscriptionLimits::maxDurableSubscriptionLifetimeHours.
TEST_F(ConfigurationDurableLifetimeLimit, RequestedDurableLifetimeIsClampedToTheCeiling)
{
  auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(sub, ServiceResultIsGood());

  EXPECT_EQ(set_durable_revised(*mSession, sub.subscription_id(), 48u), 2u)
    << "a requested 48-hour durable lifetime must be revised down to the configured ceiling of 2; under "
       "the default of 24 the same request is revised to 24, not 2";

  // Control on a second subscription: a request already under the ceiling is honoured as asked.
  auto under = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(under, ServiceResultIsGood());
  EXPECT_EQ(set_durable_revised(*mSession, under.subscription_id(), 1u), 1u)
    << "a request below the ceiling must be honoured, not raised to the ceiling";
}

// The durable queue ceiling is `max(nonDurableCeiling, durableCeiling)`, so the non-durable ceiling is set
// LOW (10) and the durable one HIGH (500): that makes the field under test the one that decides, and the
// gap between 500 and 10 is attributable to nothing else.
class ConfigurationDurableQueueSizeLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.durableSubscriptionsEnabled = true;
    serverCfg.server_capabilities().maxMonitoredItemsQueueSize = 10;  // the NON-durable ceiling
    serverCfg.subscriptionLimits.maxDurableMonitoredItemQueueSize = 500;  // default 10000
  }
};

// Row: SubscriptionLimits::maxDurableMonitoredItemQueueSize.
TEST_F(ConfigurationDurableQueueSizeLimit, DurableSubscriptionLiftsTheQueueCeilingToTheDurableValue)
{
  // Control FIRST, on a non-durable subscription: the ordinary ceiling applies.
  auto plain = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(plain, ServiceResultIsGood());
  auto plainItem = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(plain.subscription_id(), mWritableVariableId, {.queueSize = 5000}));
  ASSERT_EQ(plainItem.results().size(), 1u);
  ASSERT_TRUE(plainItem.results()[0].status_code().is_good());
  EXPECT_EQ(plainItem.results()[0].revised_queue_size(), 10u)
    << "a non-durable subscription must clamp to the ordinary ceiling of 10";

  // Subject: the same request on a DURABLE subscription is clamped to the durable ceiling instead.
  auto durable = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(durable, ServiceResultIsGood());
  ASSERT_TRUE(set_durable(*mSession, durable.subscription_id()).is_good())
    << "the subscription must actually become durable, or this row tests nothing";

  auto durableItem = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(durable.subscription_id(), mWritableVariableId, {.queueSize = 5000}));
  ASSERT_EQ(durableItem.results().size(), 1u);
  ASSERT_TRUE(durableItem.results()[0].status_code().is_good());
  EXPECT_EQ(durableItem.results()[0].revised_queue_size(), 500u)
    << "a durable subscription must lift the ceiling to the configured durable value of 500 - not to the "
       "requested 5000, and not left at the non-durable 10 the control above shows";
}

// A 500 ms sampling floor. The revision is a clamp, so the oracle is the interval the client is told to
// expect - and the advertised node carries the same number, making this another two-oracle row.
class ConfigurationSamplingFloor : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().minSupportedSampleRate = 500.0;  // default 0
  }
};

// Row: ServerCapabilities::minSupportedSampleRate.
TEST_F(ConfigurationSamplingFloor, RequestedSamplingIntervalIsRaisedToTheFloor)
{
  auto advertised = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_MinSupportedSampleRate}));
  ASSERT_TRUE(advertised.is_good()) << to_string(advertised.status_code());
  ASSERT_FALSE(advertised.value().results().empty());
  EXPECT_DOUBLE_EQ(advertised.value().results()[0].value().template as<double>(), 500.0)
    << "the configured floor must be published under ServerCapabilities.MinSupportedSampleRate";

  auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(sub, ServiceResultIsGood());

  auto item = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(sub.subscription_id(), mWritableVariableId, {.samplingInterval = 50.0}));
  ASSERT_EQ(item.results().size(), 1u);
  ASSERT_TRUE(item.results()[0].status_code().is_good());
  EXPECT_GE(item.results()[0].revised_sampling_interval(), 500.0)
    << "a requested 50 ms interval must be raised to the configured floor of 500 ms; with the default "
       "floor of 0 the server honours 50 ms";
}

// Two profile URIs, in a deliberate order. `serverProfiles` is advertising-only - there is no service
// entry point to enforce, so unlike the capping rows this one legitimately has a single oracle, and the
// row says so rather than implying an enforcement half is missing.
class ConfigurationServerProfiles : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().serverProfiles = {
      "http://opcfoundation.org/UA-Profile/Server/StandardUA2017",
      "http://opcfoundation.org/UA-Profile/Server/Methods"};  // default {}
  }
};

// Row: ServerCapabilities::serverProfiles.
TEST_F(ConfigurationServerProfiles, ConfiguredProfilesAreAdvertisedVerbatimAndInOrder)
{
  auto read = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_ServerProfileArray}));
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  ASSERT_FALSE(read.value().results().empty());

  const auto profiles = read.value().results()[0].value().template as<Array<String>>();
  ASSERT_EQ(profiles.size(), 2u)
    << "exactly the two configured URIs must be published; the default is an empty array";
  EXPECT_EQ(profiles[0], String{"http://opcfoundation.org/UA-Profile/Server/StandardUA2017"});
  EXPECT_EQ(profiles[1], String{"http://opcfoundation.org/UA-Profile/Server/Methods"})
    << "order is part of the value, not an implementation detail the server may re-sort";
}

// Query continuation points. The Query service set is not implemented, so this ceiling has no enforcement
// site to reach: the row covers the advertisement ONLY and says so, rather than implying a missing
// enforcement half that does not exist to be written.
class ConfigurationQueryContinuationPoints : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().maxQueryContinuationPoints = 1;  // default 100
  }
};

// Row: ServerCapabilities::maxQueryContinuationPoints (advertisement only - see the class comment).
TEST_F(ConfigurationQueryContinuationPoints, ConfiguredCeilingIsAdvertised)
{
  auto read = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints}));
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  ASSERT_FALSE(read.value().results().empty());
  EXPECT_EQ(read.value().results()[0].value().template as<uint16_t>(), uint16_t{1})
    << "the configured ceiling must be published under ServerCapabilities.MaxQueryContinuationPoints; "
       "the default of 100 would read back as 100";
}

// The mirror image of ConfigurationHistoryReadLimits: DATA ceiling low, EVENT ceiling high. Together the
// two fixtures pin both branches of the same check - each proves its own ceiling governs its own request
// class and does not leak into the other.
class ConfigurationHistoryReadDataLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    auto& ops = serverCfg.server_capabilities().operationLimits;
    ops.maxNodesPerHistoryReadData = 1;  // the cap under test
    ops.maxNodesPerHistoryReadEvents = 100;  // left HIGH on purpose
  }

  static HistoryReadRequest event_read(std::size_t nodeCount)
  {
    HistoryReadRequest request;
    auto details = ua::make_unique<ReadEventDetails>();
    details->num_values_per_node() = 10;
    details->start_time() = DateTime{};
    details->end_time() = DateTime{};
    request.history_read_details() = std::move(details);
    for (std::size_t i = 0; i < nodeCount; ++i)
    {
      HistoryReadValueId item;
      item.node_id() = NodeId{VariableId::Server_ServerStatus};
      request.nodes_to_read().push_back(std::move(item));
    }
    return request;
  }
};

// Row: OperationLimits::maxNodesPerHistoryReadData.
TEST_F(ConfigurationHistoryReadDataLimit, RawReadUsesTheDataCeilingNotTheEventCeiling)
{
  auto overData = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(DateTime{}, DateTime{}).read(mWritableVariableId).read(mTestFolderId));
  EXPECT_EQ(overData.status_code().as_status(), Status::BadTooManyOperations)
    << "two nodes exceed the data ceiling of 1; under the default of 100 this raw read is accepted";

  auto withinData = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(DateTime{}, DateTime{}).read(mWritableVariableId));
  EXPECT_NE(withinData.status_code().as_status(), Status::BadTooManyOperations)
    << "one node is within the data ceiling, so the count must not be what refuses it";

  // Branch control, the mirror of the events row: a 2-node EVENT read is governed by the event ceiling
  // (100) and must NOT be refused for count. Together with the events fixture this shows neither ceiling
  // is standing in for the other.
  auto twoEvents = mSession->attributes().try_history_read_sync(event_read(2));
  EXPECT_NE(twoEvents.status_code().as_status(), Status::BadTooManyOperations)
    << "the event ceiling is 100, so a 2-node event read must not trip an operation limit";
}

// Continuation-point expiry. The timeout purges on the NEXT request rather than on a timer, so the row
// browses to get a continuation point, waits past the timeout, and then presents it. Wall-clock cost is
// ~1 s; there is no injectable clock on this path. The HistoryRead row needs a server with history and is
// `ConfigurationHistoryContinuationPointTimeout` in compliance_history_tests.cpp.
class ConfigurationContinuationPointTimeouts : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.browseContinuationPointTimeout = std::chrono::milliseconds{300};  // default 30000
  }
};

// Row: ServerConfig::browseContinuationPointTimeout.
TEST_F(ConfigurationContinuationPointTimeouts, ExpiredBrowseContinuationPointIsRejected)
{
  // One reference per node forces a continuation point on a node that has several.
  auto first = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(NodeId{ObjectId::ObjectsFolder}).max_references_per_node(1));
  ASSERT_FALSE(first.results().empty());
  ASSERT_FALSE(first.results()[0].continuation_point().empty())
    << "the fixture needs a continuation point to expire";
  const auto cp = first.results()[0].continuation_point();

  // Control FIRST: presented immediately, the same point is still valid.
  auto immediate = mSession->view().browse_next_sync(browse_next(cp));
  ASSERT_FALSE(immediate.results().empty());
  EXPECT_NE(immediate.results()[0].status_code().as_status(), Status::BadContinuationPointInvalid)
    << "a continuation point presented at once must still be valid, or the expiry oracle proves nothing";

  // Take a fresh point, wait past the timeout, then present it.
  auto second = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(NodeId{ObjectId::ObjectsFolder}).max_references_per_node(1));
  ASSERT_FALSE(second.results().empty());
  ASSERT_FALSE(second.results()[0].continuation_point().empty());
  std::this_thread::sleep_for(std::chrono::milliseconds{1200});

  auto expired = mSession->view().browse_next_sync(browse_next(second.results()[0].continuation_point()));
  ASSERT_FALSE(expired.results().empty());
  EXPECT_EQ(expired.results()[0].status_code().as_status(), Status::BadContinuationPointInvalid)
    << "after 1.2 s the 300 ms timeout must have expired the point; under the default of 30 s it is "
       "still valid, exactly as the immediate control above shows";
}

// ===============================================================================================
// Wave E of the configuration coverage matrix (section 8) - throttling and DoS controls.
// Housed here rather than in a separate configuration_throttling_tests.cpp: these two rows need the same
// plain server the file already builds, and a second executable-level fixture would buy nothing.
// ===============================================================================================

// Per-IP RATE cap. The counter is incremented per ATTEMPT and pruned on a 60 s window, so closing a
// connection does not give the slot back - which is exactly what separates this from the row above.
class ConfigurationConnectionRateLimit : public ComplianceBase
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.connectionThrottling.maxConnectionAttemptsPerMinute = 3;  // default 30
    serverCfg.connectionThrottling.maxConnectionsPerEndpoint = 50;  // left HIGH on purpose
  }
};

// Row: ConnectionThrottling::maxConnectionAttemptsPerMinute.
TEST_F(ConfigurationConnectionRateLimit, AttemptBeyondThePerMinuteRateIsRefusedEvenWhenNoneAreHeldOpen)
{
  // Each connection is CLOSED before the next attempt, so the concurrency cap of 50 is never approached
  // and cannot be what refuses the third attempt.
  for (int i = 0; i < 2; ++i)
  {
    auto channel = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
    ASSERT_TRUE(channel.is_good()) << "attempt " << i << " is within the rate cap";
    (void)std::move(channel).value().try_close_sync();
  }

  auto third = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
  EXPECT_TRUE(third.is_bad())
    << "the third attempt inside the window must be refused on RATE grounds even though no connection is "
       "held open - the concurrency cap of 50 cannot explain it. Under the default of 30/min it is "
       "admitted";
  if (third.is_good())
    (void)std::move(third).value().try_close_sync();
}

// A handshake that fails (a refused first frame, a peer that closes before HEL, a handshake timeout) must
// release the MaxConnections slot the accept path reserved for it. A server that keeps counting failed
// handshakes refuses every later client once MaxConnections such failures have accumulated.
class ConfigurationFailedHandshakeCleanup : public ComplianceBase
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.maxConnections = 2;
    serverCfg.maxSecureChannels = 2;
  }
};

// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ConfigurationFailedHandshakeCleanup, ConnectionsWhoseHandshakeFailedDoNotOccupyMaxConnections)
{
  const auto parsed = ua::transport::parse_opc_tcp_url(mEndpointUrl, "test");
  ASSERT_TRUE(parsed.is_good()) << mEndpointUrl;

  boost::asio::io_context io;
  boost::asio::ip::tcp::resolver resolver{io};
  const auto endpoints = resolver.resolve(parsed.value().hostname, std::to_string(parsed.value().port));

  // MaxConnections failed handshakes: each sends a frame that is not a HEL and drains the socket until
  // the server has answered and closed it, so the failure is fully processed before the next step.
  for (int attempt = 0; attempt < 2; ++attempt)
  {
    boost::asio::ip::tcp::socket socket{io};
    boost::asio::connect(socket, endpoints);
    const std::array<unsigned char, 8> notAHello{'X', 'X', 'X', 'F', 8, 0, 0, 0};
    boost::asio::write(socket, boost::asio::buffer(notAHello));
    // Bounded drain: the server answers with ERRF and closes. The wait is enforced by the clock
    // (run_for), not only checked between reads, so a server that neither answers nor closes fails
    // the test instead of hanging it.
    boost::system::error_code readError;
    std::array<char, 64> sink{};
    std::function<void()> readMore;
    readMore = [&]
    {
      socket.async_read_some(boost::asio::buffer(sink),
        [&](const boost::system::error_code& ec, std::size_t)
        {
          readError = ec;
          if (!ec)
          {
            readMore();
          }
        });
    };
    readMore();
    io.restart();
    io.run_for(std::chrono::seconds{10});
    ASSERT_TRUE(readError) << "the server must close a connection whose first frame is not a HEL";
  }

  auto channel = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
  EXPECT_TRUE(channel.is_good())
    << "two failed handshakes must not exhaust MaxConnections = 2; a server that never releases a failed "
       "handshake answers this legitimate client with Bad_MaxConnectionsReached: "
    << channel.status_code().as_uint32();
  if (channel.is_good())
  {
    (void)std::move(channel).value().try_close_sync();
  }
}

// Wave I strengthening: session-timeout bounds. `compliance_session_tests.cpp` already asserts a 1 ms
// request is revised "up to its minimum (1000ms)" - but 1000 ms is the COMPILED-IN DEFAULT, so that test
// passes without the field being configured at all (section 1 rule 1). This fixture sets NON-DEFAULT bounds,
// so the default values would fail both oracles below.
class ConfigurationSessionTimeoutBounds : public ComplianceBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    appCfg.stack_limits().sessionMinimumTimeout = std::chrono::milliseconds{5000};  // default 1000
    appCfg.stack_limits().sessionMaximumTimeout = std::chrono::milliseconds{20000};  // default much larger
  }

  double revised_for(std::chrono::milliseconds requested, std::string_view name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session =
      channel.create_session_sync({.requestedSessionTimeout = requested, .sessionName = std::string{name}});
    const double revised = session.revised_session_timeout_ms();
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
    return revised;
  }
};

// Rows: StackLimits::sessionMinimumTimeout and StackLimits::sessionMaximumTimeout.
TEST_F(ConfigurationSessionTimeoutBounds, RequestedSessionTimeoutIsClampedToBothConfiguredBounds)
{
  // Below the floor: revised UP to the configured 5000, not to the default 1000.
  EXPECT_DOUBLE_EQ(revised_for(std::chrono::milliseconds{1}, "BelowFloor"), 5000.0)
    << "a 1 ms request must be raised to the CONFIGURED minimum of 5000 ms; the default minimum of 1000 "
       "would revise to 1000 and is what the pre-existing compliance test asserts";

  // Above the ceiling: revised DOWN to the configured 20000.
  EXPECT_DOUBLE_EQ(revised_for(std::chrono::milliseconds{600000}, "AboveCeiling"), 20000.0)
    << "a 10-minute request must be lowered to the CONFIGURED maximum of 20000 ms";

  // Between the bounds: honoured exactly, so the row tests clamping rather than a server that always
  // answers with one of its own bounds.
  EXPECT_DOUBLE_EQ(revised_for(std::chrono::milliseconds{9000}, "Between"), 9000.0)
    << "a request inside both bounds must be returned unrevised";
}

// Wave I strengthening: the shutdown grace period. Previously set to 60 in the push-certificate suite
// purely to stop a shutdown racing that test - hygiene, with no oracle. The value IS peer-observable:
// it seeds `Server.ServerStatus.SecondsTillShutdown`, which clients read to learn how long they have.
class ConfigurationShutdownGracePeriod : public ComplianceWithSession
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.defaultShutdownGracePeriodSeconds = 12;  // default 5
  }
};

// Row: ServerConfig::defaultShutdownGracePeriodSeconds.
TEST_F(ConfigurationShutdownGracePeriod, DefaultGracePeriodSeedsSecondsTillShutdown)
{
  // Shut down WITHOUT an explicit grace, so the configured default is what supplies it.
  // ASYNC on purpose: the sync form blocks for the whole grace period, by which time the channel is gone
  // and there is nothing left to read. The grace window is precisely when a client can still ask.
  std::promise<void> done;
  mServer.server().shutdown_async({}, [&done](ua::VoidResult) { done.set_value(); });

  auto read = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerStatus_SecondsTillShutdown}));
  ASSERT_TRUE(read.is_good()) << "the session must survive the grace period - that is what it is for: "
                              << to_string(read.status_code());
  ASSERT_FALSE(read.value().results().empty());

  const auto seconds = read.value().results()[0].value().template as<uint32_t>();
  EXPECT_GT(seconds, 5u)
    << "the configured 12 s default must seed SecondsTillShutdown; the compiled-in default of 5 would "
       "leave this at or below 5 even allowing for the countdown having started";
  EXPECT_LE(seconds, 12u) << "and it must not exceed the configured value";

  done.get_future().wait();  // let the shutdown finish before teardown
}

// Wave I / Wave H: the server-wide default locale. `LocalizedText::resolve` tries the SESSION's locales
// first and falls back to `defaultLocale`, so the field only decides anything for a session that
// expressed no preference, reading a node that HAS more than one translation. Both conditions have to be
// engineered - which is why no existing test covers it.
class ConfigurationDefaultLocaleBase : public ComplianceBase
{
protected:
  NodeId mMultiLingualNode;

  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    auto ns = default_ns::Namespace::create("urn:test:default-locale", mServer.thread_pool().executor());
    const auto nsIndex = addressSpace.add_namespace_sync(ns);
    mMultiLingualNode = NodeId{nsIndex, uint32_t{7001}};

    auto node = addressSpace.create_node_sync(mMultiLingualNode, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{nsIndex, "MultiLingual"});
    // Two translations, so resolve() has an actual choice to make.
    variable->set_display_name(LocalizedText::from_translations(
      {{LocaleId{"en"}, String{"Temperature"}}, {LocaleId{"de"}, String{"Temperatur"}}}));
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(Variant{int32_t{1}});
    auto objects = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objects.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMultiLingualNode);
  }

  // A session that expresses NO locale preference, so defaultLocale is what decides.
  std::string display_name_text()
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "LocaleProbe"});
    session.activate_sync();
    auto read = session.attributes().try_read_sync(read_value(mMultiLingualNode, AttributeId::DisplayName));
    EXPECT_TRUE(read.is_good()) << to_string(read.status_code());
    std::string text;
    if (read.is_good() && !read.value().results().empty())
      text = std::string{read.value().results()[0].value().template as<LocalizedText>().text()};
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
    return text;
  }
};

class ConfigurationDefaultLocaleGerman : public ConfigurationDefaultLocaleBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    appCfg.defaultLocale = LocaleId{"de"};  // default "en"
  }
};

class ConfigurationDefaultLocaleEnglish : public ConfigurationDefaultLocaleBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    appCfg.defaultLocale = LocaleId{"en"};  // the default, stated explicitly
  }
};

// Row: ApplicationConfig::defaultLocale - the configured half.
TEST_F(ConfigurationDefaultLocaleGerman, DefaultLocaleSelectsTheGermanTranslation)
{
  EXPECT_EQ(display_name_text(), "Temperatur")
    << "with defaultLocale=de and a session expressing no preference, the German translation must be "
       "chosen; under the default of en this same node reads Temperature";
}

// Control: the same node and the same locale-less session under the default locale.
TEST_F(ConfigurationDefaultLocaleEnglish, DefaultLocaleSelectsTheEnglishTranslation)
{
  EXPECT_EQ(display_name_text(), "Temperature")
    << "the control half - without it, a server that always returned the FIRST translation would satisfy "
       "the German row only by accident of insertion order";
}

// Row: ServerConfig::wellKnownRoles.
//
// THE MATRIX'S PLANNED ORACLE ("browse the Roles folder, see exactly those two") IS WRONG, and finding out
// why is most of what this row is worth. The nine well-known Role OBJECTS are NS0 NodeSet nodes: they
// exist in the address space whether or not the field names them, so that browse returns nine either way.
// What the field actually selects is which Roles get SEEDED INTO THE RoleConfiguration - i.e. which are
// grantable - and the whole seeding block is gated on the host installing a RoleConfiguration hook at all.
//
// The observable difference is therefore the seeded identity mapping rules. Only Anonymous and
// AuthenticatedUser get default rules (the other seven are seeded with empty rule lists), so excluding
// AuthenticatedUser from the selection is the one exclusion a peer can actually see: its Identities
// property stays empty where the default would carry a rule.
class ConfigurationWellKnownRolesBase : public ComplianceRoleBasedSecurity
{
protected:
  // The probe session must be an ADMIN one. Part 18 4.4.1 puts admin-only RolePermissions on the
  // well-known Role instances, so an Anonymous session browses them and sees nothing at all - which is
  // how the first version of this row failed, with an empty browse that looked like an absent property.
  //
  // SecurityAdmin is pre-registered by this grant, which makes `seed_well_known_roles` skip that slot.
  // That is harmless here precisely because the row is about AuthenticatedUser and Anonymous: the Role
  // used to authorise the probe is deliberately NOT one of the Roles being measured.
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }

  // The number of identity mapping rules published on a well-known Role's Identities property.
  size_t identity_rule_count(ObjectId role)
  {
    auto [channel, session] = open_session(ua::MessageSecurityMode::SignAndEncrypt, "WellKnownRoleProbe");
    (void)channel;
    auto browse =
      session.view().browse_sync(BrowseRequestBuilder().browse(NodeId{0, utils::to_underlying(role)}));
    NodeId identities;
    for (const auto& result : browse.results())
    {
      for (const auto& reference : result.references())
      {
        if (static_cast<ua::string_view>(reference.browse_name().name()) == "Identities")
          identities = reference.node_id().node_id();
      }
    }
    EXPECT_FALSE(identities.is_null()) << "the Role object must publish an Identities property";
    if (identities.is_null())
      return 0;
    auto read = session.attributes().read_sync(read_value(identities));
    const auto& value = read.results()[0].value();
    if (value.empty())
      return 0;
    // Identities crosses the wire as ExtensionObjects, so it decodes as RefStructure and the rules are
    // counted by identifying each element, not by asking for a typed array.
    size_t rules = 0;
    for (const auto& entry : value.as<Array<RefStructure<Structure>>>().payload())
    {
      if (dynamic_cast<const IdentityMappingRuleType*>(entry.get()) != nullptr)
        ++rules;
    }
    return rules;
  }
};

// AuthenticatedUser is deliberately absent from the selection.
class ConfigurationWellKnownRolesRestricted : public ConfigurationWellKnownRolesBase
{
protected:
  void customize_server_configuration(ua::server::ServerConfig& cfg) override
  {
    cfg.wellKnownRoles = std::vector<ua::server::WellKnownRole>{
      ua::server::WellKnownRole::Anonymous, ua::server::WellKnownRole::Observer};
  }
};

// The control: the same server with the field left at its nullopt default, which seeds all nine.
class ConfigurationWellKnownRolesDefault : public ConfigurationWellKnownRolesBase
{};

// DEFAULT (nullopt): AuthenticatedUser is seeded with its Part 18 4.3 default rule, so this reads 1.
TEST_F(ConfigurationWellKnownRolesRestricted, UnselectedWellKnownRoleIsNotSeeded)
{
  EXPECT_EQ(identity_rule_count(ObjectId::WellKnownRole_AuthenticatedUser), 0u)
    << "a Role the deployment did not select must not be seeded with grantable identity rules";

  // Pins the other half of the selection: a row asserting only an absence would also pass against a
  // server that seeded NOTHING.
  EXPECT_GT(identity_rule_count(ObjectId::WellKnownRole_Anonymous), 0u)
    << "the Roles that WERE selected must still be seeded";
}

// Control on an otherwise identical server, so the difference is attributable to the field alone.
TEST_F(ConfigurationWellKnownRolesDefault, DefaultSelectionSeedsAuthenticatedUser)
{
  EXPECT_GT(identity_rule_count(ObjectId::WellKnownRole_AuthenticatedUser), 0u)
    << "under the default selection AuthenticatedUser carries its default identity rule - without this "
       "half the restricted row would pass against a server that never seeded any rules at all";
}

// Row: ConnectionConfig::localeIds. The SESSION's locale preference, which `resolve()` consults BEFORE
// falling back to the server default - so this row is the other side of the pair above, and it reuses
// that fixture's multi-translation node for exactly that reason.
//
// The server is left at its default locale ("en") in BOTH halves. That is what makes the row about the
// client field: the only thing that differs between the two reads is what the session asked for, so a
// German answer cannot have come from the server's own preference.
class ConfigurationConnectionLocaleIds : public ConfigurationDefaultLocaleBase
{
protected:
  // The DisplayName a managed Connection sees for the multilingual node when it asks for @p locales.
  //
  // Browse rather than Read: `Connection` exposes no arbitrary-attribute read (only `read_value`), but a
  // BrowseCursor::Entry carries the DisplayName the server resolved for THIS session - which is the same
  // observable, reached through the tier-1 surface the field under test belongs to. Going down to tier-0
  // `activate_sync({.mLocaleIds = ...})` would test ActivateConfig instead and prove nothing about
  // whether ConnectionConfig::localeIds is forwarded at all - the wrong-layer trap that D15 was.
  std::string display_name_for(std::vector<ua::String> locales)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.localeIds = std::move(locales);
    config.reconnect = std::nullopt;
    auto connection = mClient->try_connect_sync(std::move(config));
    EXPECT_TRUE(connection.is_good()) << to_string(connection.status_code());
    if (connection.is_bad())
      return {};
    auto live = std::move(connection).value();

    std::string text;
    auto cursor = live.typed().browse(NodeId{ObjectId::ObjectsFolder}, ua::client::BrowseOptions{});
    for (auto entry = cursor.try_next_sync(); entry.is_good(); entry = cursor.try_next_sync())
    {
      // Compare through node_id(): a bare == on an ExpandedNodeId throws for a remote target.
      if (entry.value().targetNodeId.node_id() == mMultiLingualNode)
        text = std::string{ua::string_view{entry.value().displayName.text()}};
    }
    (void)std::move(live).try_close_sync();
    return text;
  }
};

// DEFAULT (empty): the session expresses no preference and the server falls back to its own locale, so
// the same node reads "Temperature". That control is what stops a server hardcoded to German from passing.
TEST_F(ConfigurationConnectionLocaleIds, SessionLocalePreferenceSelectsTheTranslation)
{
  EXPECT_EQ(display_name_for({"de"}), "Temperatur")
    << "a session asking for de must get the German translation, ahead of the server's own en default";

  EXPECT_EQ(display_name_for({}), "Temperature")
    << "with localeIds empty the server's default decides instead - without this half the row would pass "
       "against a server that ignored the request and always answered in German";
}

// Wave H: ApplicationIdentity::buildInfo. The matrix records this field as "set in
// tests/test_utilities.cpp:15-19 today but never asserted through the wire" - and it could not be, since
// the identity is immutable after construction and no shared fixture exposed it. The
// `configure_application_identity` hook added alongside this row is what makes it reachable.
class ConfigurationBuildInfo : public ComplianceWithSession
{
protected:
  void configure_application_identity(ua::ApplicationIdentity& identity) override
  {
    // Distinctive values per member, so a member wired to the WRONG source is visible rather than
    // coincidentally equal.
    identity.buildInfo.product_uri() = String{"urn:cfgmatrix:product"};
    identity.buildInfo.manufacturer_name() = String{"CfgMatrix Manufacturer"};
    identity.buildInfo.product_name() = String{"CfgMatrix Product"};
    identity.buildInfo.software_version() = String{"9.8.7"};
    identity.buildInfo.build_number() = String{"build-4242"};
  }

  std::string read_build_info_child(VariableId id)
  {
    auto read = mSession->attributes().try_read_sync(read_value(NodeId{id}));
    EXPECT_TRUE(read.is_good()) << to_string(read.status_code());
    if (!read.is_good() || read.value().results().empty())
      return {};
    return std::string{read.value().results()[0].value().template as<String>()};
  }
};

// Row: ApplicationIdentity::buildInfo.
TEST_F(ConfigurationBuildInfo, ConfiguredBuildInfoIsPublishedMemberForMember)
{
  EXPECT_EQ(
    read_build_info_child(VariableId::Server_ServerStatus_BuildInfo_ProductUri), "urn:cfgmatrix:product");
  EXPECT_EQ(read_build_info_child(VariableId::Server_ServerStatus_BuildInfo_ManufacturerName),
    "CfgMatrix Manufacturer");
  EXPECT_EQ(
    read_build_info_child(VariableId::Server_ServerStatus_BuildInfo_ProductName), "CfgMatrix Product");
  EXPECT_EQ(read_build_info_child(VariableId::Server_ServerStatus_BuildInfo_SoftwareVersion), "9.8.7");
  EXPECT_EQ(read_build_info_child(VariableId::Server_ServerStatus_BuildInfo_BuildNumber), "build-4242");
}

// Wave H: the remaining ApplicationIdentity members, reachable via the same hook the BuildInfo row added.
// The advertised ApplicationDescription is where a peer sees them, so GetEndpoints is the oracle.
class ConfigurationApplicationIdentity : public ComplianceWithSession
{
protected:
  void configure_application_identity(ua::ApplicationIdentity& identity) override
  {
    identity.productUri = String{"urn:cfgmatrix:identity:product"};
    identity.applicationName = LocalizedText{String{"CfgMatrix Application"}};
  }
};

// Rows: ApplicationIdentity::productUri and ApplicationIdentity::applicationName.
TEST_F(ConfigurationApplicationIdentity, ConfiguredIdentityIsAdvertisedInTheApplicationDescription)
{
  auto endpoints = mClient->discovery().try_get_endpoints_sync(mEndpointUrl, {});
  ASSERT_TRUE(endpoints.is_good()) << to_string(endpoints.status_code());
  ASSERT_FALSE(endpoints.value().empty()) << "the server must advertise at least one endpoint";

  const auto& description = endpoints.value()[0].server();
  EXPECT_EQ(std::string{ua::String{description.product_uri()}}, "urn:cfgmatrix:identity:product")
    << "the configured ProductUri must reach the advertised ApplicationDescription";
  EXPECT_EQ(std::string{ua::String{description.application_name().text()}}, "CfgMatrix Application")
    << "as must the configured ApplicationName";
}

// Wave H: DiagnosticPolicy::maxLevel - the CLAMP, as distinct from defaultLevel.
//
// `resolve_diagnostic_level` (ua_diagnostic_policy.h:19) grants Full to a user holding the
// `diagnostics:full` claim ONLY IF maxLevel is Full; under Summary the same claim yields Summary. So the
// claim is essential - without it this would merely re-test defaultLevel. `DiagnosticCollector`
// (ua_diagnostic_collector.cpp:36-46) then masks the client's returnDiagnostics down to
// symbolicId/localizedText under Summary, suppressing additionalInfo. That suppression is the oracle.
class ConfigurationDiagnosticClampBase : public ComplianceSecuredWithSession
{
protected:
  // ComplianceSecured exposes configure_components; ComplianceBase does not, which is why this row
  // sits on the secured fixture family rather than the plain one.
  void configure_components(server::ServerComponents& components) override
  {
    components.authenticator = std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"diagnostics:full", "1"}});
  }

  // Drives a failing read with EVERY diagnostic bit requested, and reports whether additionalInfo came
  // back. Reading an absent node produces a per-item Bad with a diagnostic.
  bool additional_info_present()
  {
    auto req = read_value(NodeId{uint16_t{0}, 0xABCDEF01u});  // an id NS0 does not define
    req.request_header().return_diagnostics() = 0xFFFF;
    auto result = mSession->attributes().try_read_sync(std::move(req));
    EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
    if (!result.is_good() || result.value().diagnostic_infos().empty())
      return false;
    return result.value().diagnostic_infos()[0].additional_info().has_value();
  }
};

class ConfigurationDiagnosticClampSummary : public ConfigurationDiagnosticClampBase
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    // defaultLevel deliberately LOW: resolve_diagnostic_level returns defaultLevel unclamped on the
    // fall-through path, so a Full default would mask the ceiling entirely (see D8 in the matrix).
    // Keeping it None makes the diagnostics:full claim the only elevation path, which is what the
    // ceiling is supposed to cap.
    cfg.server.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::None;
    cfg.server.diagnosticPolicy.maxLevel = ServerConfig::DiagnosticPolicy::Level::Summary;  // default Full
  }
};

class ConfigurationDiagnosticClampFull : public ConfigurationDiagnosticClampBase
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::None;
    cfg.server.diagnosticPolicy.maxLevel = ServerConfig::DiagnosticPolicy::Level::Full;  // the default
  }
};

// Row: DiagnosticPolicy::maxLevel - the clamped half.
TEST_F(ConfigurationDiagnosticClampSummary, MaxLevelSummarySuppressesAdditionalInfo)
{
  EXPECT_FALSE(additional_info_present())
    << "maxLevel=Summary must strip additionalInfo even though the client asked for every diagnostic "
       "bit AND the user holds the diagnostics:full claim - that claim is exactly what the ceiling has "
       "to override";
}

// Control: the same claim, the same request, the ceiling raised.
TEST_F(ConfigurationDiagnosticClampFull, MaxLevelFullPermitsAdditionalInfo)
{
  EXPECT_TRUE(additional_info_present())
    << "with the ceiling at Full the identical request returns additionalInfo; without this half the "
       "clamped row would pass against a server that never emits additionalInfo at all";
}

// Wave H: ListenOptions::failIfAlreadyListening. A gate whose two halves are qualitatively different -
// `true` throws `Bad_AlreadyExists`, `false` is IDEMPOTENT and returns the EXISTING listener's handle.
// Asserting only "the second bind succeeded" would miss the handle identity, which is the substance of
// the idempotent branch.
class ConfigurationListenOptions : public ComplianceBase
{
protected:
  // A second bind on the address the fixture's listener already holds.
  transport::BindAddress duplicate_bind() const
  {
    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    // The duplicate check compares the REQUESTED bind, and the fixture requests this literal.
    bind.address = "127.0.0.1:0";
    return bind;
  }
};

// Row: ListenOptions::failIfAlreadyListening.
TEST_F(ConfigurationListenOptions, DuplicateBindFailsOrIsIdempotentPerTheFlag)
{
  ua::server::ListenOptions strict;  // failIfAlreadyListening defaults to true
  ASSERT_TRUE(strict.failIfAlreadyListening) << "the default must be the strict half";
  auto strictResult = mServer.server().try_listen_sync(duplicate_bind(), strict);
  EXPECT_EQ(strictResult.status_code().as_status(), Status::BadAlreadyExists)
    << "with the flag set, a second bind on an address already listened to must be refused";

  ua::server::ListenOptions idempotent;
  idempotent.failIfAlreadyListening = false;
  auto idempotentResult = mServer.server().try_listen_sync(duplicate_bind(), idempotent);
  ASSERT_TRUE(idempotentResult.is_good())
    << "with the flag cleared the same bind must be absorbed: " << to_string(idempotentResult.status_code());
  EXPECT_EQ(idempotentResult.value(), mListener)
    << "and it must return the EXISTING listener's handle - absorbing the bind into the current listener "
       "is the substance of this branch, not merely not-failing";
}

// Wave H: ServerConfig::reverseConnectTargets - the SERVER half of reverse connect.
// `reverse_connect_tests.cpp` covers the client half; this row proves the server DIALS OUT from its own
// configuration on start. A bare TCP acceptor is enough: the oracle is that an inbound connection arrives
// carrying a ReverseHello, which no server ignoring the field would ever send.
class ConfigurationReverseConnectTarget : public ComplianceBase
{
protected:
  ConfigurationReverseConnectTarget()
    : mAcceptor(mAcceptIo, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0))
  {}

  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    // The acceptor is already bound (constructed before SetUp), so its port is known here.
    ua::server::ServerConfig::ReverseConnectTarget target;
    target.name = "ConfiguredTarget";
    target.clientApplicationUri = "urn:open62541cpp:configuration-reverse-connect-client";
    target.clientEndpointUrl = "opc.tcp://127.0.0.1:" + std::to_string(mAcceptor.local_endpoint().port());
    target.serverEndpointUrl = "opc.tcp://127.0.0.1:0";
    serverCfg.reverseConnectTargets.push_back(std::move(target));
  }

  boost::asio::io_context mAcceptIo;
  boost::asio::ip::tcp::acceptor mAcceptor;
};

// Row: ServerConfig::reverseConnectTargets.
// @relation(AC-SVR-RC-019-START-LAUNCHES-TARGETS, scope=function)
TEST_F(ConfigurationReverseConnectTarget, ConfiguredTargetIsDialledOnStart)
{
  boost::asio::ip::tcp::socket socket{mAcceptIo};
  boost::system::error_code acceptError;
  bool accepted = false;
  mAcceptor.async_accept(socket,
    [&](const boost::system::error_code& ec)
    {
      acceptError = ec;
      accepted = true;
    });

  // The server dials out during start(), which SetUp has already run.
  mAcceptIo.run_for(std::chrono::seconds{5});

  ASSERT_TRUE(accepted) << "a server with a configured reverse-connect target must dial the client "
                           "listener on start; with the default empty list nothing ever connects";
  ASSERT_FALSE(acceptError) << acceptError.message();

  // Read the message header and confirm it is a ReverseHello, not any other frame.
  std::array<char, 3> magic{};
  boost::system::error_code readError;
  boost::asio::read(socket, boost::asio::buffer(magic), readError);
  ASSERT_FALSE(readError) << readError.message();
  EXPECT_EQ(std::string(magic.data(), magic.size()), "RHE")
    << "the dialled connection must carry a ReverseHello";
}

// A namespace that counts, per Node, the reference reads the server asks it for. A Browse of a Node in it
// reads that Node's References once per round, so the count is the number of times the server did the
// work a client cache exists to save.
class ReferenceReadCountingNamespace : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static shared_ptr<ReferenceReadCountingNamespace> create(String uri, boost::asio::any_io_executor executor)
  {
    return shared_ptr<ReferenceReadCountingNamespace>(
      new ReferenceReadCountingNamespace(std::move(uri), std::move(executor)));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    {
      std::lock_guard lock{mMutex};
      for (const auto& query : queries)
        ++mReads[query.nodeId];
    }
    default_ns::Namespace::read_references_async(request, queries, std::move(complete));
  }

  std::int64_t reads(const NodeId& node) const
  {
    std::lock_guard lock{mMutex};
    const auto it = mReads.find(node);
    return it == mReads.end() ? 0 : static_cast<std::int64_t>(it->second);
  }

private:
  mutable std::mutex mMutex;
  std::unordered_map<NodeId, std::size_t> mReads;
};

// Wave G: AddressSpaceCachePolicy::enabled. The Browse-result cache is opt-in and exists to spare the
// server round trips, so the oracle is server-side: how often the server read the References of the
// walked folder. It counts nothing but that folder. The Session's BrowseCount is not usable here: a
// Connection with the cache enabled subscribes to the model-change events at activation and resolves their
// event-type hierarchy by Browse, and those Browse requests reach the server while a row walks.
//
// The cached surface is `Connection::typed().browse(...)` -> `BrowseCursor`
// (`ua_browse_cursor.cpp` consults `lookup_browse`); there is no `Connection::address_space()`.
class ConfigurationAddressSpaceCache : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    mWalkNamespace =
      ReferenceReadCountingNamespace::create("urn:test:cache-walks", mServer.thread_pool().executor());
    const auto nsIndex = addressSpace.add_namespace_sync(mWalkNamespace);
    mWalkNamespace->set_namespace_defaults(
      test_namespace_role_permissions(), test_namespace_access_restrictions());
    mFirstFolderId = add_walked_folder(addressSpace, nsIndex, 100, "FirstWalkedFolder");
    mSecondFolderId = add_walked_folder(addressSpace, nsIndex, 200, "SecondWalkedFolder");
  }

  // A Folder organised by ObjectsFolder, organising three Objects: ids @p first .. @p first + 3.
  static NodeId add_walked_folder(
    AddressSpace& addressSpace, uint16_t nsIndex, uint32_t first, const char* name)
  {
    const NodeId folderId{nsIndex, first};
    auto folder = addressSpace.create_node_sync(folderId, NodeClass::Object);
    folder.as<ObjectAccessor>()->set_browse_name(QualifiedName{nsIndex, name});
    folder.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::FolderType});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, folderId);
    folder.add_reference_sync(NodeId{ReferenceTypeId::Organizes},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);
    for (uint32_t i = 1; i <= 3; ++i)
    {
      const NodeId childId{nsIndex, first + i};
      auto child = addressSpace.create_node_sync(childId, NodeClass::Object);
      child.as<ObjectAccessor>()->set_browse_name(
        QualifiedName{nsIndex, std::string{name} + "Child" + std::to_string(i)});
      child.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
      folder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, childId);
      child.add_reference_sync(
        NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{folderId}, /*isForward=*/false);
    }
    return folderId;
  }

  void walk(ua::client::Connection& connection, const NodeId& start)
  {
    auto cursor = connection.typed().browse(start, ua::client::BrowseOptions{});
    while (cursor.try_next_sync().is_good() && cursor.has_more())
    {
    }
  }

  // The server's reference reads of @p start caused by the walk run as @p walkAgain. A walk returns only
  // after the Browse response, which the server sends after the read, so no read can arrive late.
  std::int64_t reads_during(const NodeId& start, const std::function<void()>& walkAgain)
  {
    const std::int64_t before = mWalkNamespace->reads(start);
    walkAgain();
    return mWalkNamespace->reads(start) - before;
  }

  // Reference reads of the first folder for the REPEAT walk only. Connection bootstrap and the first walk
  // are outside the measured window: the first walk is what populates the cache.
  std::int64_t repeat_walk_reads(bool cacheEnabled)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.addressSpaceCache.enabled = cacheEnabled;

    auto connection = mClient->connect_sync(std::move(config));
    walk(connection, mFirstFolderId);
    const auto reads = reads_during(mFirstFolderId, [&] { walk(connection, mFirstFolderId); });
    connection.close_sync();
    return reads;
  }

  shared_ptr<ReferenceReadCountingNamespace> mWalkNamespace;
  NodeId mFirstFolderId;
  NodeId mSecondFolderId;
};

// Row: AddressSpaceCachePolicy::enabled.
TEST_F(ConfigurationAddressSpaceCache, EnabledCacheServesTheRepeatedWalkWithoutTheServer)
{
  const std::int64_t withoutCache = repeat_walk_reads(false);  // the default
  const std::int64_t withCache = repeat_walk_reads(true);

  EXPECT_GT(withoutCache, 0) << "the disabled-cache control must reach the server at all, or the "
                                "comparison below is between two zeroes";
  EXPECT_EQ(withCache, 0)
    << "an enabled cache must serve the second identical walk locally, so the server reads the folder's "
       "References only for the uncached walk ("
    << withCache << " with the cache vs " << withoutCache << " without)";
}

// Wave G: the three cache-size / TTL knobs, all on the fixture above. Each keeps the cache ENABLED and
// varies one bound, so the enabled-vs-disabled difference the gate row proves is held constant and only
// the bound under test can move the count.
class ConfigurationBrowseCacheCapacity : public ConfigurationAddressSpaceCache
{
protected:
  // Reference reads of the first folder's re-walk with the cache enabled and @p maxBrowses cached entries,
  // after walking TWO distinct folders so a one-entry cache must evict between them.
  std::int64_t repeat_browses_with_capacity(std::size_t maxBrowses)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.addressSpaceCache.enabled = true;
    config.addressSpaceCache.maxCachedBrowses = maxBrowses;

    auto connection = mClient->connect_sync(std::move(config));
    walk(connection, mFirstFolderId);
    walk(connection, mSecondFolderId);
    // The FIRST-walked folder, evicted at size 1.
    const auto reads = reads_during(mFirstFolderId, [&] { walk(connection, mFirstFolderId); });
    connection.close_sync();
    return reads;
  }
};

// Row: AddressSpaceCachePolicy::maxCachedBrowses.
TEST_F(ConfigurationBrowseCacheCapacity, BrowseCacheCapacityEvictsTheOldestEntry)
{
  // One entry: walking a second node evicts the first, so re-walking the first reaches the server.
  const std::int64_t evicted = repeat_browses_with_capacity(1);
  // Room for both: the re-walk is served from cache.
  const std::int64_t retained = repeat_browses_with_capacity(8);

  EXPECT_GT(evicted, retained)
    << "with room for ONE browse entry the second node evicts the first, so re-walking the first must "
       "reach the server; with room for eight it is still cached ("
    << evicted << " vs " << retained << ")";
}

// Row: AddressSpaceCachePolicy::browseEntryTtl. Same fixture, same reference-read counter; the variable is
// TIME rather than capacity, so the cache is left roomy in both halves and only the TTL differs.
TEST_F(ConfigurationBrowseCacheCapacity, ExpiredBrowseEntryIsRefetched)
{
  const auto measure = [this](std::chrono::seconds ttl) -> std::int64_t
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.addressSpaceCache.enabled = true;
    config.addressSpaceCache.maxCachedBrowses = 64;  // roomy: eviction cannot be the cause
    config.addressSpaceCache.browseEntryTtl = ttl;

    auto connection = mClient->connect_sync(std::move(config));
    walk(connection, mFirstFolderId);  // populate, unmeasured
    std::this_thread::sleep_for(std::chrono::milliseconds{1200});

    const auto reads = reads_during(mFirstFolderId, [&] { walk(connection, mFirstFolderId); });
    connection.close_sync();
    return reads;
  };

  const std::int64_t expired = measure(std::chrono::seconds{1});  // elapsed during the wait
  const std::int64_t live = measure(std::chrono::seconds{60});  // still well within the TTL

  EXPECT_GT(expired, live)
    << "an entry older than its TTL must be refetched from the server, while the same walk under a 60 s "
       "TTL is still served locally ("
    << expired << " vs " << live
    << "). The cache is roomy in both "
       "halves, so eviction cannot explain the difference";
}

// Wave F: ConnectionConfig::sessionTimeout, via WIRE CAPTURE. The three oracles tried before this one are
// all eliminated (see the matrix row): the diagnostics field is never populated, the revised-value getter
// is tier-0 only, and a managed Connection keep-alive-polls so it is never observed going session-idle.
// What is left - and what the matrix's sibling Wave F rows already assume - is observing what the client
// actually PUT ON THE WIRE. `MisbehavingServer::set_request_observer` sees every decoded request.
class ConfigurationWireCapturedSessionTimeout : public ::testing::Test
{
protected:
  // The requestedSessionTimeout of the first CreateSession the server decodes.
  double captured_requested_timeout(std::optional<std::chrono::milliseconds> configured)
  {
    MisbehavingServer server;
    auto captured = std::make_shared<std::atomic<double>>(0.0);
    server.set_request_observer(
      [captured](const ua::Structure& request)
      {
        if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
        {
          double expected = 0.0;
          captured->compare_exchange_strong(expected, create->requested_session_timeout());
        }
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    // Must match the SAN URI of the client certificate MisbehavingServer issues.
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";
    auto client = Client::create(pool.executor(),
      client::CreateConfig{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)},
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url_none();
    config.sessionTimeout = configured;
    config.reconnect = std::nullopt;
    auto connection = client.try_connect_sync(std::move(config));
    if (connection.is_good())
      (void)std::move(connection).value().try_close_sync();

    const double value = captured->load();
    ::ua::test_utils::stop_pool_in_teardown(pool, "wire-capture");
    return value;
  }
};

// Row: ConnectionConfig::sessionTimeout.
TEST_F(ConfigurationWireCapturedSessionTimeout, PerConnectionTimeoutIsSentOnCreateSession)
{
  const double overridden = captured_requested_timeout(std::chrono::milliseconds{90000});
  EXPECT_DOUBLE_EQ(overridden, 90000.0)
    << "the per-connection sessionTimeout must be what CreateSession carries";

  const double defaulted = captured_requested_timeout(std::nullopt);
  EXPECT_NE(defaulted, 90000.0)
    << "with the slot at its nullopt default the client-wide default is sent instead - without this half "
       "the row would pass against a client that hardcoded 90000";
  EXPECT_GT(defaulted, 0.0) << "and a CreateSession must have been observed at all";
}

// Wave F, continued: the sibling wire-carried fields, on the pattern the sessionTimeout row established.
// `channelLifetime` and `defaultChannelLifetime` are a PRECEDENCE pair - the per-connection slot must win
// over the client-wide default - so one fixture varies both and the assertions distinguish them.
class ConfigurationWireCapturedChannelLifetime : public ::testing::Test
{
protected:
  // The requestedLifetime of the first OpenSecureChannel the server decodes, under a client whose default
  // is @p clientDefault and a connection slot of @p perConnection.
  double captured_requested_lifetime(
    std::chrono::milliseconds clientDefault, std::optional<std::chrono::milliseconds> perConnection)
  {
    MisbehavingServer server;
    auto captured = std::make_shared<std::atomic<double>>(0.0);
    server.set_request_observer(
      [captured](const ua::Structure& request)
      {
        if (const auto* opn = dynamic_cast<const ua::OpenSecureChannelRequest*>(&request))
        {
          double expected = 0.0;
          captured->compare_exchange_strong(expected, static_cast<double>(opn->requested_lifetime()));
        }
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";
    client::CreateConfig createCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    createCfg.client.defaultChannelLifetime = clientDefault;
    auto client = Client::create(pool.executor(),
      std::move(createCfg),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url_none();
    config.channelLifetime = perConnection;
    config.reconnect = std::nullopt;
    auto connection = client.try_connect_sync(std::move(config));
    if (connection.is_good())
      (void)std::move(connection).value().try_close_sync();

    const double value = captured->load();
    ::ua::test_utils::stop_pool_in_teardown(pool, "wire-capture-lifetime");
    return value;
  }
};

// Rows: ClientConfig::defaultChannelLifetime and ConnectionConfig::channelLifetime.
TEST_F(ConfigurationWireCapturedChannelLifetime, PerConnectionLifetimeWinsOverTheClientDefault)
{
  // Client default alone: the OPN carries it, proving defaultChannelLifetime reaches the wire.
  EXPECT_DOUBLE_EQ(captured_requested_lifetime(std::chrono::milliseconds{600000}, std::nullopt), 600000.0)
    << "with no per-connection slot the client-wide default must be what OpenSecureChannel requests";

  // Both set and DIFFERENT: the per-connection slot must win. This is the precedence claim, and it fails
  // for a client that reads either field alone.
  EXPECT_DOUBLE_EQ(
    captured_requested_lifetime(std::chrono::milliseconds{600000}, std::chrono::milliseconds{3000}), 3000.0)
    << "the per-connection channelLifetime must override the client-wide default on the wire";
}

// Wave C: ServerCapabilities::maxWhereClauseParameters. The ceiling is applied when the event filter is
// COMPILED at MonitoredItem creation (`ua_compiled_event_filter.cpp:253`, SVR-EVT-CAP-002), so the oracle is
// the per-item status: a where clause with more elements than the ceiling is refused
// `Bad_MonitoredItemFilterInvalid` while one at the ceiling is accepted.
class ConfigurationWhereClauseLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().maxWhereClauseParameters = 2;  // default 100
    serverCfg.server_capabilities().maxSelectClauseParameters = 2;  // default 100
    serverCfg.subscriptionLimits.maxWhereClauseOperandBytes = 32;  // default 65536
  }

  // An EventFilter with ONE where-clause element carrying a string literal of @p bytes.
  static std::unique_ptr<ua::Structure> event_filter_with_literal_bytes(std::size_t bytes)
  {
    ua::SimpleAttributeOperand select;
    select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    select.browse_path().push_back(QualifiedName{0, "Message"});
    select.attribute_id() = static_cast<ua::IntegerId>(AttributeId::Value);

    // Equals takes TWO operands; a one-operand element is refused on ARITY, which would mask the byte
    // ceiling entirely (the 16-byte control failed exactly that way on the first attempt).
    ua::ContentFilterElement element;
    element.filter_operator() = ua::FilterOperator::Equals;
    for (int i = 0; i < 2; ++i)
    {
      ua::LiteralOperand operand;
      operand.value() = Variant{String{std::string(bytes / 2, 'x')}};
      element.filter_operands().push_back(
        ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
    }

    auto filter = std::make_unique<ua::EventFilter>();
    filter->select_clauses().push_back(std::move(select));
    filter->where_clause().elements().push_back(std::move(element));
    return filter;
  }

  StatusCode create_event_item_with_literal(std::size_t bytes)
  {
    auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
    EXPECT_THAT(sub, ServiceResultIsGood());
    auto resp =
      mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(sub.subscription_id(),
        NodeId{ObjectId::Server},
        event_filter_with_literal_bytes(bytes),
        {.attribute = AttributeId::EventNotifier, .samplingInterval = 0.0, .queueSize = 10}));
    EXPECT_EQ(resp.results().size(), 1u);
    return resp.results().empty() ? StatusCode{} : resp.results()[0].status_code();
  }

  // An EventFilter with @p selects select clauses and @p elements OfType where-clause elements.
  static std::unique_ptr<ua::Structure> event_filter_with(std::size_t elements, std::size_t selects = 1)
  {
    auto filter = std::make_unique<ua::EventFilter>();
    static constexpr std::string_view names[] = {"Message", "Severity", "SourceName", "Time"};
    for (std::size_t i = 0; i < selects; ++i)
    {
      ua::SimpleAttributeOperand select;
      select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
      select.browse_path().push_back(QualifiedName{0, std::string{names[i % 4]}});
      select.attribute_id() = static_cast<ua::IntegerId>(AttributeId::Value);
      filter->select_clauses().push_back(std::move(select));
    }
    for (std::size_t i = 0; i < elements; ++i)
    {
      ua::LiteralOperand operand;
      operand.value() = Variant{NodeId{ObjectTypeId::BaseEventType}};
      ua::ContentFilterElement element;
      element.filter_operator() = ua::FilterOperator::OfType;
      element.filter_operands().push_back(
        ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
      filter->where_clause().elements().push_back(std::move(element));
    }
    return filter;
  }

  StatusCode create_event_item(std::size_t whereElements, std::size_t selects = 1)
  {
    auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
    EXPECT_THAT(sub, ServiceResultIsGood());
    auto resp =
      mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(sub.subscription_id(),
        NodeId{ObjectId::Server},
        event_filter_with(whereElements, selects),
        {.attribute = AttributeId::EventNotifier, .samplingInterval = 0.0, .queueSize = 10}));
    EXPECT_EQ(resp.results().size(), 1u);
    return resp.results().empty() ? StatusCode{} : resp.results()[0].status_code();
  }
};

// Row: ServerCapabilities::maxWhereClauseParameters.
TEST_F(ConfigurationWhereClauseLimit, WhereClauseAboveTheCeilingIsRefused)
{
  EXPECT_TRUE(create_event_item(2).is_good())
    << "a where clause AT the ceiling of 2 must be accepted, or the rejection below proves nothing";
  EXPECT_EQ(create_event_item(3).as_status(), Status::BadMonitoredItemFilterInvalid)
    << "three elements exceed the ceiling of 2; under the default of 100 the same filter is accepted";
}

// Row: ServerCapabilities::maxSelectClauseParameters. Sibling of the where-clause ceiling, enforced at
// `ua_compiled_event_filter.cpp:247`. The where-clause ceiling is held at a value the probes never reach
// (1 element), so only the SELECT ceiling can refuse them.
TEST_F(ConfigurationWhereClauseLimit, SelectClauseAboveTheCeilingIsRefused)
{
  EXPECT_TRUE(create_event_item(/*whereElements=*/1, /*selects=*/2).is_good())
    << "two select clauses are AT the ceiling and must be accepted";
  EXPECT_EQ(
    create_event_item(/*whereElements=*/1, /*selects=*/3).as_status(), Status::BadMonitoredItemFilterInvalid)
    << "three select clauses exceed the ceiling of 2; the where clause stays at 1 element throughout, so "
       "the where-clause ceiling cannot be what refused it";
}

// Wave D: SubscriptionLimits::defaultEventQueueSize - the queue size applied when an event MonitoredItem
// does NOT request one. The request must therefore leave queueSize at 0: passing an explicit size tests
// the clamp instead, which is a different field.
class ConfigurationDefaultEventQueueSize : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.defaultEventQueueSize = 7;  // default 50
  }
};

// Row: SubscriptionLimits::defaultEventQueueSize.
TEST_F(ConfigurationDefaultEventQueueSize, EventItemWithoutAQueueSizeGetsTheConfiguredDefault)
{
  auto sub = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(sub, ServiceResultIsGood());

  ua::SimpleAttributeOperand select;
  select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  select.browse_path().push_back(QualifiedName{0, "Message"});
  select.attribute_id() = static_cast<ua::IntegerId>(AttributeId::Value);
  auto filter = std::make_unique<ua::EventFilter>();
  filter->select_clauses().push_back(std::move(select));

  auto resp =
    mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(sub.subscription_id(),
      NodeId{ObjectId::Server},
      std::move(filter),
      {.attribute = AttributeId::EventNotifier, .samplingInterval = 0.0, .queueSize = 0}));

  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good())
    << to_string(resp.results()[0].status_code().as_status());
  EXPECT_EQ(resp.results()[0].revised_queue_size(), 7u)
    << "an event item that requests NO queue size must be given the configured default of 7; the "
       "compiled-in default of 50 is what an unconfigured server would revise it to";
}

// Row: SubscriptionLimits::maxWhereClauseOperandBytes. Bounds the TOTAL string-literal operand bytes in
// a where clause - a distinct DoS axis from the element/operand COUNTS above, since one element can carry
// an arbitrarily large literal. Element and select counts stay at 1 throughout, so neither count ceiling
// can be what refuses the oversized literal.
TEST_F(ConfigurationWhereClauseLimit, WhereClauseLiteralBytesAboveTheCeilingIsRefused)
{
  EXPECT_TRUE(create_event_item_with_literal(16).is_good())
    << "a 16-byte literal is within the 32-byte ceiling and must be accepted";
  EXPECT_EQ(create_event_item_with_literal(128).as_status(), Status::BadMonitoredItemFilterInvalid)
    << "a 128-byte literal exceeds the ceiling of 32; the filter has ONE element and ONE select clause "
       "throughout, so neither count ceiling can explain the rejection";
}

// Wave D: SubscriptionLimits::maxPendingStatusChanges. When a subscription expires with no Publish
// outstanding, the server PARKS a StatusChangeNotification. A client that creates subscriptions and never
// publishes would grow that backlog without bound, so it is capped evict-oldest. The oracle is how many
// parked notifications a single eventual Publish can retrieve.
class ConfigurationPendingStatusChanges : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.maxPendingStatusChanges = 1;  // default 100
  }
};

// Row: SubscriptionLimits::maxPendingStatusChanges.
TEST_F(ConfigurationPendingStatusChanges, ParkedStatusChangesAreCappedEvictOldest)
{
  // Three short-lived subscriptions, never published to, so all three expire and park a notification.
  for (int i = 0; i < 3; ++i)
  {
    auto sub = mSession->subscriptions().create_subscription_sync(
      build_subscription_request({.publishingInterval = 50.0, .lifetimeCount = 3, .keepAliveCount = 1}));
    ASSERT_THAT(sub, ServiceResultIsGood());
  }

  // Let every subscription outlive its lifetime without a Publish.
  std::this_thread::sleep_for(std::chrono::milliseconds{2000});

  // Drain: each Publish can carry at most one parked StatusChangeNotification.
  int statusChanges = 0;
  for (int i = 0; i < 4; ++i)
  {
    auto resp = mSession->subscriptions().try_publish_sync(ua::PublishRequest{});
    if (!resp.is_good())
      break;
    if (dynamic_cast<const ua::StatusChangeNotification*>(
          resp.value().notification_message().notification_data().empty()
            ? nullptr
            : resp.value().notification_message().notification_data()[0].get()) != nullptr)
    {
      ++statusChanges;
    }
  }

  EXPECT_LE(statusChanges, 1)
    << "with the cap at 1 only the newest parked StatusChangeNotification survives; three expiries under "
       "the default of 100 would all be retrievable ("
    << statusChanges << " seen)";
}

// Wave E: DiscoveryThrottling::delayPerRequest and ::concurrencyThreshold. The server delays a
// discovery request when in-flight count > threshold. Setting the THRESHOLD to 0 makes a single request
// qualify, which removes the need to orchestrate genuine concurrency and the flakiness that comes with
// it. Timing assertions are LOWER bounds only, as the matrix requires.
class ConfigurationDiscoveryThrottling : public ComplianceBase
{
protected:
  std::int64_t timed_get_endpoints()
  {
    const auto start = std::chrono::steady_clock::now();
    auto result = mClient->discovery().try_get_endpoints_sync(mEndpointUrl, {});
    const auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
    return elapsed;
  }
};

class ConfigurationDiscoveryDelayed : public ConfigurationDiscoveryThrottling
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.discoveryThrottling.concurrencyThreshold = 0;  // default 10: every request qualifies
    serverCfg.discoveryThrottling.delayPerRequest = std::chrono::milliseconds{800};  // default 100
  }
};

class ConfigurationDiscoveryAboveThreshold : public ConfigurationDiscoveryThrottling
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    // Same delay, but a threshold no single request can exceed - so the delay must NOT apply.
    serverCfg.discoveryThrottling.concurrencyThreshold = 1000;
    serverCfg.discoveryThrottling.delayPerRequest = std::chrono::milliseconds{800};
  }
};

// Row: DiscoveryThrottling::delayPerRequest.
TEST_F(ConfigurationDiscoveryDelayed, DiscoveryRequestIsDelayedByTheConfiguredAmount)
{
  EXPECT_GE(timed_get_endpoints(), 700)
    << "with the threshold at 0 every discovery request is delayed by the configured 800 ms; the default "
       "of 100 ms would return far sooner";
}

// Row: DiscoveryThrottling::concurrencyThreshold.
TEST_F(ConfigurationDiscoveryAboveThreshold, DiscoveryBelowTheThresholdIsNotDelayed)
{
  EXPECT_LT(timed_get_endpoints(), 700)
    << "a single request cannot exceed a threshold of 1000, so the same 800 ms delay must NOT apply - "
       "this is what separates the threshold from the delay amount";
}

// Row: ConnectionConfig::sessionName.
//
// THE PLANNED ORACLE FOR THIS ROW DOES NOT EXIST. The matrix proposed reading the name back from the
// server's session diagnostics - but `SessionDiagnostics.SessionName` is empty for every session, never
// populated (D14, the same family as the never-populated ActualSessionTimeout that forced the
// sessionTimeout row onto the wire). A diagnostics-based oracle here would assert "" == "" and pass
// against a client that dropped the field entirely.
//
// So this row takes the same route its sibling did: capture what CreateSession actually carries.
class ConfigurationWireCapturedSessionName : public ::testing::Test
{
protected:
  // The sessionName of the first CreateSession the server decodes.
  std::string captured_session_name(std::optional<std::string> configured)
  {
    MisbehavingServer server;
    auto captured = std::make_shared<std::string>();
    auto seen = std::make_shared<std::atomic<bool>>(false);
    server.set_request_observer(
      [captured, seen](const ua::Structure& request)
      {
        if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
        {
          bool expected = false;
          if (seen->compare_exchange_strong(expected, true))
            *captured = std::string{ua::string_view{create->session_name()}};
        }
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    // Must match the SAN URI of the client certificate MisbehavingServer issues.
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";
    auto client = Client::create(pool.executor(),
      client::CreateConfig{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)},
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url_none();
    config.sessionName = configured;
    config.reconnect = std::nullopt;
    auto connection = client.try_connect_sync(std::move(config));
    if (connection.is_good())
      (void)std::move(connection).value().try_close_sync();

    const std::string value = *captured;
    ::ua::test_utils::stop_pool_in_teardown(pool, "wire-capture");
    return value;
  }
};

// DEFAULT (nullopt): the client sends its own product name, so a client that ignored the slot would still
// put a non-empty name on the wire - which is why the control half below is not optional.
TEST_F(ConfigurationWireCapturedSessionName, PerConnectionSessionNameIsSentOnCreateSession)
{
  const std::string overridden = captured_session_name("ConfigurationMatrixNamedSession");
  EXPECT_EQ(overridden, "ConfigurationMatrixNamedSession")
    << "the per-connection sessionName must be what CreateSession carries";

  const std::string defaulted = captured_session_name(std::nullopt);
  EXPECT_NE(defaulted, "ConfigurationMatrixNamedSession")
    << "with the slot at its nullopt default the client's own default name is sent instead - without this "
       "half the row would pass against a client that hardcoded the test's string";
  EXPECT_FALSE(defaulted.empty()) << "and a CreateSession must have been observed at all";
}

// ExecutionLimits::loopLimit is NOT covered here. See the matrix row and D18: the two consumers'
// requirements are disjoint (NS0 import needs more than the method-call walk ever spends), and a synthetic
// deep subtype chain does not lengthen the walk - it ends as BadMethodInvalid after a couple of
// iterations. A test was written and withdrawn rather than left red.

// Row: ServerConfig::maxInFlightRequestsPerConnection.
//
// Per-CONNECTION backpressure on in-flight non-Publish requests, counted at admission on the SecureChannel
// and released when the response is sent. Proving it needs a request that stays outstanding, so the
// fixture installs a method whose handler PARKS its completion callback until the test releases it.
//
// NOT `maxRequestsPerSession`, which was the row originally attempted here: that counter is erased in
// `execute_service`, i.e. at DISPATCH rather than at response, so it does not bound outstanding work at
// all (D19). The channel-level counters are the ones that actually track a request to completion.
class ConfigurationInFlightPerConnection : public ComplianceWithSession
{
protected:
  NodeId mParkingMethodId;
  NodeId mParkingObjectId;
  // Completions of parked calls, released in teardown so no handler outlives the test holding one.
  std::shared_ptr<ParkedCalls> mParked = std::make_shared<ParkedCalls>();

  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.maxInFlightRequestsPerConnection = 1;  // default 0 == unbounded
    // The server-wide cap stays unbounded, so a refusal here can only be the per-connection one. That is
    // what separates this row from its sibling, which shares the same status code.
    cfg.maxInFlightRequests = 0;
  }

  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    auto ns = default_ns::Namespace::create("urn:test:parking", mServer.thread_pool().executor());
    const auto nsIndex = addressSpace.add_namespace_sync(ns);

    mParkingObjectId = NodeId{nsIndex, uint32_t{7100}};
    auto objNode = addressSpace.create_node_sync(mParkingObjectId, NodeClass::Object);
    objNode.as<ObjectAccessor>()->set_browse_name(QualifiedName{nsIndex, "ParkingObject"});
    auto objects = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objects.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mParkingObjectId);

    mParkingMethodId = NodeId{nsIndex, uint32_t{7101}};
    auto methodNode = addressSpace.create_node_sync(mParkingMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    method->set_browse_name(QualifiedName{nsIndex, "Park"});
    method->set_executable(true);
    objNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mParkingMethodId);

    auto* callSource = ns->find_node<Node>(mParkingMethodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler([parked = mParked](const CallMethodRequest&,
                                   std::shared_ptr<const MethodCallContext>,
                                   std::function<void(CallResult)>
                                     cb) { parked->hold(std::move(cb)); });
  }

  void TearDown() override
  {
    mParked->release_all();  // let every parked call finish before the server is torn down
    ComplianceWithSession::TearDown();
  }

  CallRequest park_request()
  {
    CallMethodRequest methodReq;
    methodReq.object_id() = mParkingObjectId;
    methodReq.method_id() = mParkingMethodId;
    CallRequest req;
    req.methods_to_call().push_back(std::move(methodReq));
    return req;
  }
};

// DEFAULT (0 == unbounded): the second request is served normally while the first is still parked - which
// the probe read below demonstrates is otherwise perfectly possible, so the refusal is the cap and not
// head-of-line blocking.
TEST_F(ConfigurationInFlightPerConnection, SecondInFlightRequestOnTheConnectionIsRefused)
{
  std::promise<void> firstDone;
  auto firstFuture = firstDone.get_future();
  mSession->methods().call_async(
    park_request(), [&firstDone](ua::Result<CallResponse>) { firstDone.set_value(); });

  ASSERT_TRUE(mParked->wait_for_calls(1)) << "the first call must reach the parking handler and stay there";

  // A second request on the SAME channel, while the first is outstanding.
  auto second =
    mSession->attributes().try_read_sync(read_value(NodeId{VariableId::Server_ServerStatus_State}));
  const auto secondStatus =
    second.is_good() ? second.value().response_header().service_result() : second.status_code();

  EXPECT_EQ(secondStatus.as_status(), Status::BadServerTooBusy)
    << "with the per-connection cap at 1 a second outstanding request must be refused; with the default "
       "(0 == unbounded) this same read is served while the call is still parked";

  mParked->release_all();
  EXPECT_EQ(firstFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "and the parked request must still complete once released - the cap must not have killed it";
}

// Row: ServerConfig::maxInFlightRequests.
//
// The SERVER-WIDE sibling of the per-connection cap, sharing its status code - so the row is only worth
// anything if it reaches the server-wide branch specifically. It does that by parking the first request on
// ONE channel and issuing the second on a SECOND, independent channel: a per-connection cap cannot explain
// a refusal there, because that second connection has nothing outstanding.
//
// The per-connection cap is pinned at 0 (unbounded) as well, so only the server-wide branch can fire.
class ConfigurationInFlightServerWide : public ConfigurationInFlightPerConnection
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.maxInFlightRequests = 1;  // default nullopt == unbounded
    cfg.maxInFlightRequestsPerConnection = 0;  // the sibling must not be able to explain the refusal
  }
};

// DEFAULT (nullopt == unbounded): the second channel's read is served while the first channel's call is
// still parked.
TEST_F(ConfigurationInFlightServerWide, RequestOnASecondConnectionIsRefusedWhenTheServerWideCapIsReached)
{
  // The second channel and session are established BEFORE anything is parked. With a server-wide cap of 1
  // and a request outstanding, EVERY later request is refused - including session setup - so establishing
  // the probe session afterwards would trip the cap during CreateSession and prove nothing about the read.
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "ServerWideProbe"});
  session.activate_sync();

  std::promise<void> firstDone;
  auto firstFuture = firstDone.get_future();
  mSession->methods().call_async(
    park_request(), [&firstDone](ua::Result<CallResponse>) { firstDone.set_value(); });

  ASSERT_TRUE(mParked->wait_for_calls(1)) << "the first call must reach the parking handler and stay there";

  auto second = session.attributes().try_read_sync(read_value(NodeId{VariableId::Server_ServerStatus_State}));
  const auto secondStatus =
    second.is_good() ? second.value().response_header().service_result() : second.status_code();

  EXPECT_EQ(secondStatus.as_status(), Status::BadServerTooBusy)
    << "the server-wide cap must refuse a request on a DIFFERENT connection - that is what distinguishes "
       "it from mMaxInFlightRequestsPerConnection, which cannot see across connections";

  mParked->release_all();
  EXPECT_EQ(firstFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "and the parked request must still complete once released";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Row: ClientDiagnosticPolicy::maxChainDepth.
//
// Bounds how deep a server-supplied DiagnosticInfo chain the client will DECODE, replacing the remainder
// with a truncation sentinel rather than dropping it (`ua_diagnostic_to_error_detail.cpp:103`). It is a
// client-side defence against a server that returns an arbitrarily deep chain, so the stimulus has to come
// from a server willing to send one - which is what MisbehavingServer's response mutator is for.
//
// TRUNCATED, NOT DROPPED, is the substance of the row: a cap that discarded the chain entirely would also
// bound memory, and would also pass an oracle that only counted depth. The sentinel is what tells an
// operator the chain was cut rather than absent.
class ConfigurationDiagnosticChainDepth : public ::testing::Test
{
protected:
  // Depth of the ErrorDetail chain the client decoded, given a configured cap of @p cap against a server
  // returning a chain of @p serverDepth nested InnerDiagnosticInfos.
  size_t decoded_chain_depth(std::uint32_t cap, size_t serverDepth)
  {
    MisbehavingServer server;
    // Only the READ response is doctored, so connect proceeds normally and the row's own read is what
    // carries the deep chain. Faulting every service instead kills the handshake before any of this runs.
    server.set_response_mutator(
      [serverDepth](ua::Response& response)
      {
        // `ua::Response` is {requestId, Structure}; with set_service_result every service answers with a
        // ServiceFault, whose header carries the diagnostics this row is about.
        auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
        if (read == nullptr)
          return;
        read->response_header().service_result() = StatusCode{Status::BadInternalError};
        // Build serverDepth nested InnerDiagnosticInfos on the response header.
        DiagnosticInfo deepest;
        deepest.symbolic_id() = 0;
        auto current = std::make_unique<DiagnosticInfo>(std::move(deepest));
        for (size_t level = 0; level < serverDepth; ++level)
        {
          DiagnosticInfo outer;
          outer.symbolic_id() = static_cast<std::int32_t>(level);
          outer.inner_diagnostic_info() = std::move(current);
          current = std::make_unique<DiagnosticInfo>(std::move(outer));
        }
        read->response_header().service_diagnostics() = std::move(*current);
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";
    auto client = Client::create(pool.executor(),
      client::CreateConfig{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)},
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    auto captured = std::make_shared<std::atomic<size_t>>(0);
    auto observer = std::make_shared<ChainDepthObserver>(captured);

    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url_none();
    config.diagnostics.maxChainDepth = cap;
    config.connectionObserver = observer;
    config.reconnect = std::nullopt;
    auto connection = client.try_connect_sync(std::move(config));
    if (connection.is_good())
    {
      auto live = std::move(connection).value();
      // The doctored read: its bad service result plus deep diagnostics is what drives on_error_chain.
      (void)live.try_read_value_sync(NodeId{VariableId::Server_ServerStatus_State});
      (void)std::move(live).try_close_sync();
    }

    const size_t depth = captured->load();
    ::ua::test_utils::stop_pool_in_teardown(pool, "chain-depth");
    return depth;
  }
};

// DEFAULT (32): the same 6-deep chain is decoded in full, so the observer sees 7 links rather than 3.
TEST_F(ConfigurationDiagnosticChainDepth, DecodedChainIsTruncatedAtTheConfiguredDepth)
{
  // The comparison is RELATIVE, not an absolute depth. The chain the observer receives also carries the
  // client's own wrapper links (the always-on CL-DIAG-005 wire-crossing marker among them), so "2" is not
  // the number that comes out the far end. What the field controls is how much of the SERVER's chain
  // survives, and the falsifiable statement is that a small cap yields a shorter chain than a large one
  // for the identical server response - a client ignoring the setting returns the same depth for both.
  const size_t capped = decoded_chain_depth(/*cap=*/2, /*serverDepth=*/6);
  const size_t uncapped = decoded_chain_depth(/*cap=*/32, /*serverDepth=*/6);

  EXPECT_GT(capped, 0u) << "the server's diagnostics must have reached the client at all";
  EXPECT_LT(capped, uncapped)
    << "a cap of 2 must decode less of the same 6-deep server chain than the default cap of 32 (capped="
    << capped << " uncapped=" << uncapped << ")";
}

// ===========================================================================
// Rows: ConnectionConfig::securityMode and ConnectionConfig::securityPolicyId
//       (configuration coverage matrix section 12b - both DEMOTED by the mutation spot-check).
//
// WHY THESE ROWS EXIST. Both fields were audited CONFIRMED on the strength of
// `client_security_policy_matrix_tests.cpp`, but a mutation showed that suite gates on DEPRECATION
// (`mAllowDeprecatedSecurityPolicies`, evaluated on the raw config before any endpoint is chosen), not on
// what the channel ends up using. Overriding the requested policy/mode in the endpoint-selection template
// left 532 security tests and 179 session tests green: every existing test asserts that a secured connect
// SUCCEEDS, and none asserts it succeeded with the security the caller asked for. A client that silently
// negotiated something else - including something weaker, where a weaker policy is on offer - would pass
// the whole suite.
//
// THE ORACLE IS WHAT THE SERVER REPORTS, not what the client believes. `SessionSecurityDiagnostics`
// carries the securityMode and securityPolicyUri the server recorded for the channel the session runs on,
// so it is the peer's account of the negotiation. Reading the client's own config back would be the
// assert-the-copy anti-pattern in section 1.
// ===========================================================================
class ConfigurationNegotiatedSecurity : public ComplianceSecured
{
protected:
  void SetUp() override
  {
    ComplianceSecured::SetUp();
    // A SECOND SignAndEncrypt endpoint on a different policy. Without it the fixture offers only
    // Basic256Sha256 for encrypted channels, and "the requested policy was used" cannot be distinguished
    // from "the only encrypted policy on offer was used".
    ServerEndpointConfig aesEp;
    aesEp.name = "Aes128_SignAndEncrypt";
    aesEp.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aesEp.securityPolicyId = SecurityPolicyId::Aes128Sha256RsaOaep;
    aesEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aesEp));
  }

  struct Negotiated
  {
    MessageSecurityMode mode{MessageSecurityMode::Invalid};
    std::string policyUri;
  };

  // What the SERVER reports for a MANAGED connection opened with @p mode and @p policy.
  //
  // THE PROBE MUST GO THROUGH `Client::connect`, not `CoreClient::open_channel_sync`. The tier-0 call takes
  // its own `OpenChannelConfig::securityMode`, a different field entirely; a row built on it passes even
  // when `ConnectionConfig::securityMode` is ignored completely, which is precisely the wrong-layer trap
  // that let the original audit verdict stand.
  //
  // The diagnostics are read over a SEPARATE, always-encrypted tier-0 session: the
  // SessionSecurityDiagnostics nodes carry an EncryptionRequired restriction, so a Sign-only probe cannot
  // read them. The probe's entry is identified by DIFFERENCE against a snapshot taken before it connects,
  // because a managed Connection does not expose its session id.
  Negotiated negotiated_for(MessageSecurityMode mode, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig readerCfg;
    readerCfg.endpointUrl = mEndpointUrl;
    readerCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    readerCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    readerCfg.serverCertificate = mServerCert;
    auto readerChannel = mClient->core().open_channel_sync(std::move(readerCfg));
    auto readerSession = readerChannel.create_session_sync({.sessionName = "NegotiatedReader"});
    readerSession.activate_sync();

    const auto before = security_diagnostics(readerSession);
    std::set<NodeId> knownIds;
    for (const auto& entry : before)
      knownIds.insert(entry.first);

    ua::client::ConnectionConfig probeCfg;
    probeCfg.endpointUrl = mEndpointUrl;
    probeCfg.securityMode = mode;
    probeCfg.securityPolicyId = policy;
    probeCfg.serverCertificate = mServerCert;
    probeCfg.reconnect = std::nullopt;
    auto probe = mClient->try_connect_sync(std::move(probeCfg));
    EXPECT_TRUE(probe.is_good()) << to_string(probe.status_code());

    Negotiated found;
    if (probe.is_good())
    {
      auto live = std::move(probe).value();
      for (const auto& [sessionId, negotiated] : security_diagnostics(readerSession))
      {
        if (knownIds.contains(sessionId))
          continue;  // pre-existing session, not the probe
        found = negotiated;
      }
      (void)std::move(live).try_close_sync();
    }

    (void)readerSession.try_close_sync();
    (void)readerChannel.try_close_sync();
    return found;
  }

  // Every live session's negotiated security, keyed by session id.
  std::vector<std::pair<NodeId, Negotiated>> security_diagnostics(ua::client::Session& session)
  {
    auto read = session.attributes().read_sync(read_value(NodeId{
      VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray}));

    std::vector<std::pair<NodeId, Negotiated>> out;
    if (read.results()[0].value().empty())
      return out;
    for (const auto& entry : read.results()[0].value().as<Array<RefStructure<Structure>>>().payload())
    {
      const auto* diag = dynamic_cast<const ua::SessionSecurityDiagnosticsDataType*>(entry.get());
      if (diag == nullptr)
        continue;
      out.emplace_back(diag->session_id(),
        Negotiated{
          diag->security_mode(), std::string{static_cast<ua::string_view>(diag->security_policy_uri())}});
    }
    return out;
  }
};

// Row: ConnectionConfig::securityMode.
//
// The fixture offers None, Sign and SignAndEncrypt endpoints, so all three are genuinely reachable and a
// client that ignored the field could land on any of them. Both non-default modes are asserted, because a
// single assertion would pass against a client hardcoded to that one mode.
TEST_F(ConfigurationNegotiatedSecurity, ServerReportsTheRequestedSecurityMode)
{
  const auto signOnly = negotiated_for(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(signOnly.mode, MessageSecurityMode::Sign)
    << "the server must record the channel as Sign when Sign was requested";

  const auto signAndEncrypt =
    negotiated_for(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(signAndEncrypt.mode, MessageSecurityMode::SignAndEncrypt)
    << "and SignAndEncrypt when that was requested - asserting one mode alone would pass against a client "
       "that always negotiated it";

  EXPECT_NE(signOnly.mode, signAndEncrypt.mode)
    << "the two requests must produce DIFFERENT negotiated modes; equal values would mean the field is "
       "being ignored, which is exactly what the audit missed";
}

// Row: ConnectionConfig::securityPolicyId.
//
// Held at one mode (SignAndEncrypt) so the sibling cannot explain a difference, and the two policies are
// both non-default and both genuinely offered by the fixture.
TEST_F(ConfigurationNegotiatedSecurity, ServerReportsTheRequestedSecurityPolicy)
{
  const auto sha256 = negotiated_for(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  EXPECT_THAT(sha256.policyUri, ::testing::HasSubstr("Basic256Sha256"))
    << "the server must record the policy the client asked for";

  const auto aes128 =
    negotiated_for(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes128Sha256RsaOaep);
  EXPECT_THAT(aes128.policyUri, ::testing::HasSubstr("Aes128"))
    << "a DIFFERENT requested policy must produce a different negotiated policy; without this half a client "
       "hardcoded to Basic256Sha256 would satisfy the row";
}

// Row: ApplicationConfig::allowInsecureEndpoints (configuration coverage matrix section 12b -
// DEMOTED).
//
// WHY THIS ROW EXISTS. The field was audited CONFIRMED on `transfer_subscriptions_integration_tests.cpp`,
// but disabling the gate entirely left all 16 of that suite's tests green: the `false` path was incidental
// to those tests rather than their subject. This is the gate that decides whether a server will serve
// unencrypted endpoints at all, so an inert one is a silent downgrade of the whole deployment.
//
// The oracle is what a PEER can reach. The gate refuses the endpoint at `add_endpoint`, so with the flag
// off there is no None endpoint to connect to and a client asking for one is refused; with it on, the same
// sequence yields a working unsecured connect. Asserting only that `add_endpoint` throws would be a
// server-side API assertion, not a peer observation.
class ConfigurationAllowInsecureEndpoints : public ::testing::Test
{
protected:
  // Builds a server with the flag at @p allowInsecure, attempts to add a None endpoint, and reports
  // whether a client can then open an unsecured channel to it.
  struct Outcome
  {
    bool endpointAccepted{false};  ///< did add_endpoint survive the gate?
    bool clientConnected{false};  ///< could a peer then actually connect with None?
  };

  Outcome probe(bool allowInsecure)
  {
    Outcome outcome;
    TestServer server;
    server.create([allowInsecure](ua::ApplicationConfig& appCfg)
      { appCfg.allowInsecureEndpoints = allowInsecure; },
      nullptr,
      nullptr);

    auto listener = server.listen_ephemeral();

    ServerEndpointConfig noneEndpoint;
    noneEndpoint.name = "None";
    noneEndpoint.messageSecurityMode = MessageSecurityMode::None;
    noneEndpoint.securityPolicyId = SecurityPolicyId::None;
    noneEndpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    try
    {
      server.add_endpoint(listener, std::move(noneEndpoint));
      outcome.endpointAccepted = true;
    }
    catch (const ua::UaException&)
    {
      outcome.endpointAccepted = false;
    }
    server.start();

    const auto urls = server.server().advertised_urls(listener);
    if (!urls.empty())
    {
      boost::asio::thread_pool pool;
      {
        // The Client is scoped so it is destroyed BEFORE the pool is drained. A refused connect leaves an
        // armed handler behind (the D11 family), and a Client still alive at join time holds it.
        auto client = Client::create(pool.executor(),
          client::CreateConfig{.identity = ApplicationIdentity::load_default(),
            .application = ua::test_utils::create_test_config()},
          ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto(),
            .logSink = test_log_sink(),
            .logLevel = LogLevel::Debug});

        ua::client::ConnectionConfig cfg;
        cfg.endpointUrl = urls.front().str();
        cfg.securityMode = MessageSecurityMode::None;
        cfg.securityPolicyId = SecurityPolicyId::None;
        cfg.reconnect = std::nullopt;
        auto connection = client.try_connect_sync(std::move(cfg));
        outcome.clientConnected = connection.is_good();
        if (connection.is_good())
          (void)std::move(connection).value().try_close_sync();
      }
      ::ua::test_utils::stop_pool_in_teardown(pool, "insecure-endpoint-probe");
    }
    return outcome;
  }
};

// DEFAULT: the SDK ships this permissive, so the `false` path is the one a hardened deployment relies on
// and the one nothing was testing.
TEST_F(ConfigurationAllowInsecureEndpoints, InsecureEndpointIsRefusedWhenTheGateIsOff)
{
  const auto blocked = probe(/*allowInsecure=*/false);
  EXPECT_FALSE(blocked.endpointAccepted)
    << "with allowInsecureEndpoints=false the server must refuse to publish a None endpoint";
  EXPECT_FALSE(blocked.clientConnected)
    << "and no peer may open an unsecured channel - the endpoint must be genuinely absent, not merely "
       "unadvertised";

  // The control is what makes this about the FLAG rather than about None endpoints being broken.
  const auto allowed = probe(/*allowInsecure=*/true);
  EXPECT_TRUE(allowed.endpointAccepted) << "with the gate on, the same endpoint must be accepted";
  EXPECT_TRUE(allowed.clientConnected) << "and a peer must be able to connect to it";
}

// Row: ApplicationConfig::allowDeprecatedSecurityPolicies - the SERVER half
// (configuration coverage matrix section 12b - half-covered).
//
// The field gates BOTH ends. The client half is covered (`ClientSecurityPolicy.RejectsBasic128Rsa15ByDefault`
// reddens when the client gate is disabled), but mutating the SERVER gate at `ua_server_impl.cpp:2460`
// reddened nothing at all: a server that stopped refusing deprecated policies on its own endpoints would
// have gone unnoticed. That is the more dangerous half - a permissive server offers the weak policy to
// every client, not only to this SDK's.
//
// Same shape as the insecure-endpoint row: the gate refuses at `add_endpoint`, so the peer-visible
// consequence is whether the deprecated endpoint exists at all.
class ConfigurationAllowDeprecatedPolicies : public ::testing::Test
{
protected:
  // Whether a Basic128Rsa15 endpoint survives the gate at @p allowDeprecated.
  bool deprecated_endpoint_accepted(bool allowDeprecated)
  {
    TestServer server;
    server.create(
      [allowDeprecated](ua::ApplicationConfig& appCfg)
      {
        appCfg.allowDeprecatedSecurityPolicies = allowDeprecated;
        // Insecure endpoints stay permitted so THIS gate is the only one that can refuse the endpoint.
        appCfg.allowInsecureEndpoints = true;
      },
      nullptr,
      nullptr);

    auto listener = server.listen_ephemeral();

    ServerEndpointConfig deprecatedEndpoint;
    deprecatedEndpoint.name = "Basic128Rsa15_Sign";
    deprecatedEndpoint.messageSecurityMode = MessageSecurityMode::Sign;
    deprecatedEndpoint.securityPolicyId = SecurityPolicyId::Basic128Rsa15;  // deprecated
    deprecatedEndpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    try
    {
      server.add_endpoint(listener, std::move(deprecatedEndpoint));
      return true;
    }
    catch (const ua::UaException&)
    {
      return false;
    }
  }
};

// DEFAULT (false): the server refuses to publish a deprecated-policy endpoint.
TEST_F(ConfigurationAllowDeprecatedPolicies, DeprecatedPolicyEndpointIsRefusedWhenTheGateIsOff)
{
  EXPECT_FALSE(deprecated_endpoint_accepted(/*allowDeprecated=*/false))
    << "with mAllowDeprecatedSecurityPolicies=false the server must refuse to publish a Basic128Rsa15 "
       "endpoint";

  // The control is what makes this about the FLAG rather than about Basic128Rsa15 being unsupported.
  EXPECT_TRUE(deprecated_endpoint_accepted(/*allowDeprecated=*/true))
    << "with the gate on the same endpoint must be accepted - otherwise the row would pass against a build "
       "that simply cannot do Basic128Rsa15 at all";
}

// Row: ServerConfig::authzTimeout (configuration coverage matrix section 6).
//
// A namespace that cannot answer synchronously and never completes its asynchronous permission
// lookup makes the authorization deadline directly observable at the public Session API. The
// configured deadline is far below the one-second default, and the upper bound remains deliberately
// generous because wall-clock timing is the behaviour under test.
class ConfigurationAuthorizationTimeout : public ComplianceSecuredWithSession
{
protected:
  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();

    auto addressSpace = mServer->address_space();
    mPermissionNamespace = ua::test::DeferredNamespace::create(
      "urn:test:configuration:authorization-timeout", mServerThreadPool.executor());
    const auto namespaceIndex = addressSpace.add_namespace_sync(mPermissionNamespace);
    mPermissionNodeId = NodeId{namespaceIndex, uint32_t{9000}};

    auto node = addressSpace.create_node_sync(mPermissionNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{namespaceIndex, "StalledPermissionValue"});
    variable->set_display_name(LocalizedText{"", "StalledPermissionValue"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(int32_t{61});

    mPermissionNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::NeverCompletes);
  }

  void TearDown() override
  {
    mPermissionNamespace.reset();
    ComplianceSecuredWithSession::TearDown();
  }

  void configure_server_create_config(ua::server::CreateConfig& cfg) override
  {
    cfg.server.authzTimeout = std::chrono::milliseconds{25};
  }

  std::shared_ptr<ua::test::DeferredNamespace> mPermissionNamespace;
  NodeId mPermissionNodeId;
};

// @relation(AC-SVR-AUTHZ-023-ASYNC-FAILURE-IS-CONTAINED, scope=function)
TEST_F(ConfigurationAuthorizationTimeout, NonDefaultDeadlineBoundsAStalledPermissionBackend)
{
  const auto started = std::chrono::steady_clock::now();
  auto response = mSession->attributes().read_sync(read_value(mPermissionNodeId));
  const auto elapsed = std::chrono::steady_clock::now() - started;

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_THAT(response.results()[0], HasStatus(Status::BadUserAccessDenied));
  EXPECT_LT(elapsed, std::chrono::milliseconds{900})
    << "the one-second default authorization timeout was used instead of the configured 25 ms value";

  const auto calls = mPermissionNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_TRUE(calls[0].nodes.has_value());
  ASSERT_EQ(calls[0].nodes->size(), 1u);
  EXPECT_EQ((*calls[0].nodes)[0], mPermissionNodeId);

  const auto records = mServerLogSink->records();
  EXPECT_TRUE(std::any_of(records.begin(),
    records.end(),
    [](const CapturingLogSink::Entry& record)
    {
      return record.category == "access_control" &&
             record.message.find("exceeded the authorization deadline") != std::string::npos;
    }))
    << "the rich authorization-timeout cause was not logged before wire projection";
}

// Row: ServerConfig::monitoredItemAccessRecheckInterval (configuration coverage matrix section 6).
//
// Access is checked when a MonitoredItem is created, but permissions change while subscriptions are live.
// The production default is a positive 60 seconds. This fixture uses one second so a non-default public
// configuration value has an observable end-to-end consequence in a bounded test.
class RecheckPermissionNamespace final : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static std::shared_ptr<RecheckPermissionNamespace> create(String uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<RecheckPermissionNamespace>(
      new RecheckPermissionNamespace(std::move(uri), std::move(executor)));
  }

  std::optional<PermissionType> effective_permissions(const AccessIdentity&, const Node*) const override
  {
    return std::nullopt;
  }

  void effective_permissions_async(const RequestInfo&, shared_ptr<const AccessIdentity> identity,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override
  {
    EffectivePermissionsResult result;
    if (!identity)
    {
      result.batchStatus = VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("RecheckPermissionIdentityMissing",
          "The injected permission resolver requires an access identity",
          "RecheckPermissionNamespace")}};
    }
    else if (mFailPermissions.load(std::memory_order_acquire))
    {
      result.batchStatus = VoidResult{StatusCode{Status::BadUnexpectedError,
        ErrorDetail::build("InjectedPeriodicPermissionFailure",
          "The integration-test permission backend is unavailable",
          "RecheckPermissionNamespace")}};
    }
    else
    {
      const size_t resultCount = nodes ? nodes->size() : 1u;
      result.items.assign(resultCount, Result<PermissionType>{all_permissions()});
    }
    callback(std::move(result));
  }

  void set_permission_failure(bool fail) noexcept
  {
    mFailPermissions.store(fail, std::memory_order_release);
  }

private:
  std::atomic_bool mFailPermissions{false};
};

class ConfigurationAccessRecheck : public ComplianceSecuredWithSession
{
protected:
  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();

    auto addressSpace = mServer->address_space();
    mPermissionNamespace = RecheckPermissionNamespace::create(
      "urn:test:configuration:access-recheck", mServerThreadPool.executor());
    const auto namespaceIndex = addressSpace.add_namespace_sync(mPermissionNamespace);
    mPermissionNodeId = NodeId{namespaceIndex, uint32_t{9001}};

    auto node = addressSpace.create_node_sync(mPermissionNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{namespaceIndex, "PermissionBackendValue"});
    variable->set_display_name(LocalizedText{"", "PermissionBackendValue"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(int32_t{73});
  }

  void TearDown() override
  {
    mPermissionNamespace.reset();
    ComplianceSecuredWithSession::TearDown();
  }

  void configure_components(ua::server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void configure_server_create_config(ua::server::CreateConfig& cfg) override
  {
    // A positive non-default interval, short enough for this focused integration fixture.
    cfg.server.monitoredItemAccessRecheckInterval = std::chrono::seconds{1};
  }

  void revoke_monitored_node_read(NodeId monitoredNodeId = NodeId{VariableId::Server_ServerStatus_State})
  {
    auto monitoredNode = mServer->address_space().find_node_sync(monitoredNodeId);
    RolePermissionType permissions;
    permissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    permissions.permissions() = PermissionType{{PermissionType::Bit::Browse}};
    monitoredNode.set_role_permissions(std::vector<RolePermissionType>{permissions});
  }

  std::shared_ptr<RecheckPermissionNamespace> mPermissionNamespace;
  NodeId mPermissionNodeId;
};

// The configured one-second interval, rather than the 60-second default, bounds when the change is seen.
// @relation(AC-SVR-AUTHZ-009-RECHECK-INTERVAL-POSITIVE, scope=function)
TEST_F(ConfigurationAccessRecheck, RevokedAccessIsNoticedWithinTheRecheckInterval)
{
  const auto subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});

  MonitoredItemCreateRequest miReq;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  miReq.item_to_monitor() = std::move(rv);
  miReq.monitoring_mode() = MonitoringMode::Reporting;
  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50;
  params.queue_size() = 100;
  miReq.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest createReq;
  createReq.subscription_id() = subscriptionId;
  createReq.timestamps_to_return() = TimestampsToReturn::Both;
  createReq.items_to_create().push_back(std::move(miReq));
  auto created = mSession->monitored_items().create_monitored_items_sync(std::move(createReq));
  ASSERT_TRUE(created.results()[0].status_code().is_good())
    << "the item must be created while access is still permitted - that is the precondition the recheck "
       "exists to revisit";

  // Revoke AFTER creation. The create-time gate already passed, so only a recheck can notice.
  revoke_monitored_node_read();

  // Poll for a notification carrying a bad status. Bounded well above the one-second interval.
  bool sawDenied = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{8};
  while (!sawDenied && std::chrono::steady_clock::now() < deadline)
  {
    auto published = try_publish_once(*mSession);
    if (!published)
      continue;
    for (const auto& notificationData : published->notification_message().notification_data())
    {
      const auto* dataChange = dynamic_cast<const DataChangeNotification*>(notificationData.get());
      if (dataChange == nullptr)
        continue;
      for (const auto& item : dataChange->monitored_items())
      {
        const auto& status = item.value().status();
        if (status.has_value() && status->is_bad())
          sawDenied = true;
      }
    }
  }

  EXPECT_TRUE(sawDenied)
    << "with a one-second recheck interval the item must report a bad status after access is revoked";

  delete_subscription(*mSession, subscriptionId);
}

// Values sampled before revocation are no longer authorized when Publish finally drains the queue. A
// changing node makes the antecedent non-vacuous: several distinct values accumulate while publishing is
// withheld, and the first post-recheck notification must contain only the denial transition.
// @relation(AC-SVR-AUTHZ-009-REVOCATION-PURGES-QUEUED-CONTENT, scope=function)
TEST_F(ConfigurationAccessRecheck, RevocationDoesNotPublishPreviouslyQueuedProtectedContent)
{
  const auto subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  const NodeId monitoredNode{VariableId::Server_ServerStatus_CurrentTime};

  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = monitoredNode;
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = 41;
  item.requested_parameters().sampling_interval() = 50;
  item.requested_parameters().queue_size() = 100;

  CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_create().push_back(std::move(item));
  auto created = mSession->monitored_items().create_monitored_items_sync(std::move(request));
  ASSERT_EQ(created.results().size(), 1u);
  ASSERT_TRUE(created.results()[0].status_code().is_good());

  std::this_thread::sleep_for(std::chrono::milliseconds{300});
  revoke_monitored_node_read(monitoredNode);
  std::this_thread::sleep_for(std::chrono::milliseconds{1500});

  auto notification = wait_for_data_change(
    *mSession,
    subscriptionId,
    [](const DataChangeNotification& dataChange)
    {
      return std::any_of(dataChange.monitored_items().begin(),
        dataChange.monitored_items().end(),
        [](const MonitoredItemNotification& value) { return value.client_handle() == 41u; });
    },
    std::chrono::seconds{5});
  ASSERT_TRUE(notification.has_value()) << "the revocation transition produced no data notification";
  ASSERT_EQ(notification->monitored_items().size(), 1u)
    << "values queued while access was granted leaked in the same Publish response as the denial";
  const auto& denied = notification->monitored_items()[0];
  EXPECT_EQ(denied.client_handle(), 41u);
  ASSERT_TRUE(denied.value().status().has_value());
  EXPECT_EQ(*denied.value().status(), StatusCode{Status::BadUserAccessDenied});

  delete_subscription(*mSession, subscriptionId);

  const auto eventSubscriptionId =
    create_subscription(*mSession, {.publishingInterval = 50.0, .keepAliveCount = 30});
  SimpleAttributeOperand messageClause;
  messageClause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  messageClause.browse_path().push_back(QualifiedName{0, "Message"});
  messageClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  EventFilter eventFilter;
  eventFilter.select_clauses().push_back(std::move(messageClause));
  const auto eventItemId = create_event_monitored_item(*mSession,
    eventSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(eventFilter),
    {.clientHandle = 42, .samplingInterval = 0.0, .queueSize = 10});
  ASSERT_NE(eventItemId, 0u);

  const auto carriesMessage = [](const EventFieldList& fields, std::string_view expected)
  {
    if (fields.event_fields().empty())
      return false;
    const auto* message = fields.event_fields()[0].try_as<LocalizedText>();
    return message && static_cast<std::string_view>(message->text()) == expected;
  };
  const auto emit = [this](std::string_view message)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "ConfigurationAccessRecheck";
    event.message = LocalizedText{"", std::string{message}};
    mServer->emit_event(event);
  };

  emit("event-control-before-revocation");
  auto controlEvent = wait_for_event(
    *mSession,
    eventSubscriptionId,
    [&carriesMessage](const EventFieldList& fields)
    { return carriesMessage(fields, "event-control-before-revocation"); },
    std::chrono::seconds{5});
  ASSERT_TRUE(controlEvent.has_value())
    << "the Event path must deliver before revocation, or the purge assertion would be vacuous";

  emit("queued-event-must-not-leak");
  std::this_thread::sleep_for(std::chrono::milliseconds{300});
  revoke_monitored_node_read(NodeId{ObjectId::Server});
  std::this_thread::sleep_for(std::chrono::milliseconds{1500});

  auto leakedEvent = wait_for_event(
    *mSession,
    eventSubscriptionId,
    [&carriesMessage](const EventFieldList& fields)
    { return carriesMessage(fields, "queued-event-must-not-leak"); },
    std::chrono::seconds{2});
  EXPECT_FALSE(leakedEvent.has_value())
    << "an Event queued while ReceiveEvents was granted leaked after the periodic revocation decision";

  delete_subscription(*mSession, eventSubscriptionId);
}

// A namespace resolver failure is an infrastructure failure, not a new grant. The affected item fails
// closed, a healthy item in the same Subscription continues, the rich backend cause reaches the server
// log, and a later successful resolution restores delivery.
// @relation(AC-SVR-AUTHZ-009-PERIODIC-FAILURE-FAILS-CLOSED, scope=function)
TEST_F(ConfigurationAccessRecheck, AuthorizationBackendFailureFailsClosedPerItemAndRecovers)
{
  const auto subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});

  const auto makeItem = [](const NodeId& nodeId, uint32_t clientHandle)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = nodeId;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 50;
    item.requested_parameters().queue_size() = 10;
    return item;
  };

  CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_create().push_back(makeItem(mPermissionNodeId, 51));
  request.items_to_create().push_back(makeItem(NodeId{VariableId::Server_ServerStatus_CurrentTime}, 52));
  auto created = mSession->monitored_items().create_monitored_items_sync(std::move(request));
  ASSERT_EQ(created.results().size(), 2u);
  ASSERT_TRUE(created.results()[0].status_code().is_good());
  ASSERT_TRUE(created.results()[1].status_code().is_good());

  auto initial = wait_for_data_change(
    *mSession,
    subscriptionId,
    [](const DataChangeNotification& dataChange)
    {
      return std::any_of(dataChange.monitored_items().begin(),
        dataChange.monitored_items().end(),
        [](const MonitoredItemNotification& value)
        {
          return value.client_handle() == 51u &&
                 (!value.value().status().has_value() || value.value().status()->is_good());
        });
    },
    std::chrono::seconds{5});
  ASSERT_TRUE(initial.has_value())
    << "the permission-backed item must deliver while its backend is healthy before failure is injected";

  mServerLogSink->clear();
  mPermissionNamespace->set_permission_failure(true);

  auto denied = wait_for_data_change(
    *mSession,
    subscriptionId,
    [](const DataChangeNotification& dataChange)
    {
      return std::any_of(dataChange.monitored_items().begin(),
        dataChange.monitored_items().end(),
        [](const MonitoredItemNotification& value)
        {
          return value.client_handle() == 51u && value.value().status().has_value() &&
                 value.value().status()->is_bad();
        });
    },
    std::chrono::seconds{6});
  ASSERT_TRUE(denied.has_value()) << "the backend failure did not revoke the old permitted snapshot";
  const auto failedItem = std::find_if(denied->monitored_items().begin(),
    denied->monitored_items().end(),
    [](const MonitoredItemNotification& value) { return value.client_handle() == 51u; });
  ASSERT_NE(failedItem, denied->monitored_items().end());
  ASSERT_TRUE(failedItem->value().status().has_value());
  EXPECT_EQ(*failedItem->value().status(), StatusCode{Status::BadUserAccessDenied});

  auto healthy = wait_for_data_change(
    *mSession,
    subscriptionId,
    [](const DataChangeNotification& dataChange)
    {
      return std::any_of(dataChange.monitored_items().begin(),
        dataChange.monitored_items().end(),
        [](const MonitoredItemNotification& value)
        {
          return value.client_handle() == 52u &&
                 (!value.value().status().has_value() || value.value().status()->is_good());
        });
    },
    std::chrono::seconds{3});
  EXPECT_TRUE(healthy.has_value())
    << "one failed permission backend must not abort rechecking or publishing the healthy item";

  bool sawBackendFailureLog = false;
  const auto logDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
  do
  {
    for (const auto& record : mServerLogSink->records())
    {
      if (record.category == "access_control" &&
          record.message.find("Namespace effective-permission resolution failed") != std::string::npos)
      {
        sawBackendFailureLog = true;
        break;
      }
    }
    if (!sawBackendFailureLog)
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  while (!sawBackendFailureLog && std::chrono::steady_clock::now() < logDeadline);
  EXPECT_TRUE(sawBackendFailureLog) << "the permission backend failure was not logged before wire projection";

  mPermissionNamespace->set_permission_failure(false);
  auto recovered = wait_for_data_change(
    *mSession,
    subscriptionId,
    [](const DataChangeNotification& dataChange)
    {
      return std::any_of(dataChange.monitored_items().begin(),
        dataChange.monitored_items().end(),
        [](const MonitoredItemNotification& value)
        {
          return value.client_handle() == 51u &&
                 (!value.value().status().has_value() || value.value().status()->is_good());
        });
    },
    std::chrono::seconds{6});
  EXPECT_TRUE(recovered.has_value())
    << "a later successful permission resolution must restore the previously failed item";

  delete_subscription(*mSession, subscriptionId);
}

// Row: OperationLimits::maxNodesPerHistoryUpdateEvents - the ADVERTISEMENT half only.
//
// **The enforcement half is impossible until D6 is fixed**, and that is the substance of this row. The
// field has exactly ONE consumer in the whole SDK - `ua_server_model.cpp:381`, which publishes it on
// `Server.ServerCapabilities.OperationLimits`. `ua_history_update_service.cpp:264` applies
// `maxNodesPerHistoryUpdateData` to EVERY HistoryUpdate regardless of whether the batch carries data or
// event details, so no request can be refused by the event ceiling.
//
// So the server publishes a limit it does not apply. A client that reads OperationLimits to size its
// batches - which is what the node is for - will size event batches against a number the server ignores.
// Covering the advertisement pins the half that works and records the asymmetry; the enforcement row stays
// blocked on D6 rather than being quietly dropped.
class ConfigurationHistoryUpdateEventsAdvertised : public ComplianceWithSession
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().operationLimits.maxNodesPerHistoryUpdateEvents = 7;  // default 100
    // The DATA ceiling is left alone: if both moved, a mutation could not tell which one the node reports.
  }
};

// DEFAULT (100): the node reads 100, so the configured 7 is what distinguishes the two.
TEST_F(ConfigurationHistoryUpdateEventsAdvertised, ConfiguredEventCeilingIsAdvertised)
{
  auto read = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents}));
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  ASSERT_FALSE(read.value().results().empty());

  EXPECT_EQ(read.value().results()[0].value().as<uint32_t>(), 7u)
    << "OperationLimits.MaxNodesPerHistoryUpdateEvents must report the configured ceiling";

  // Pins the asymmetry D6 describes: the sibling the server ACTUALLY enforces still reads its own value,
  // so this row cannot be satisfied by a server that publishes one number for both.
  auto dataRead = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData}));
  ASSERT_TRUE(dataRead.is_good());
  EXPECT_NE(dataRead.value().results()[0].value().as<uint32_t>(), 7u)
    << "the data ceiling must be reported independently of the event ceiling";
}

// Row: ApplicationConfig::mApplicationDescriptionPart.mApplicationUri - the SERVER-CONFIG half.
//
// The Wave I audit found this covered only from the CLIENT side: `client_discovery_get_endpoints_matrix_
// tests.cpp` SUBSTITUTES a mismatching URI into an advertised ApplicationDescription and asserts
// `Bad_CertificateUriInvalid`. That proves the client VALIDATES the URI; it says nothing about the server
// publishing the one its own configuration carries.
//
// This row closes that half: configure a distinctive URI and read it back off the wire through
// GetEndpoints, which is where every client learns a server's identity.
class ConfigurationServerApplicationUri : public ComplianceBase
{
protected:
  static constexpr std::string_view sConfiguredUri = "urn:test:configured:server:uri";
  static constexpr std::string_view sConfiguredName = "ConfiguredServerDisplayName";

  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    appCfg.application_description_part().applicationUri = std::string{sConfiguredUri};
  }

  void configure_application_identity(ua::ApplicationIdentity& identity) override
  {
    identity.applicationName = ua::LocalizedText{"en", std::string{sConfiguredName}};
  }
};

// Row: ApplicationIdentity::applicationName (configuration coverage matrix section 12b - DEMOTED).
//
// The sibling of the URI above, published beside it in `construct_application_description`. The spot-check
// found NEITHER covered from the server side: publishing a fixed name left 37 discovery tests green. A
// covered neighbour is a reason to check a field, not to trust it.
TEST_F(ConfigurationServerApplicationUri, ConfiguredApplicationNameIsAdvertisedOnEveryEndpoint)
{
  auto endpoints = mClient->discovery().try_get_endpoints_sync(mEndpointUrl, {});
  ASSERT_TRUE(endpoints.is_good()) << to_string(endpoints.status_code());
  ASSERT_FALSE(endpoints.value().empty());

  for (const auto& endpoint : endpoints.value())
  {
    EXPECT_EQ(static_cast<ua::string_view>(endpoint.server().application_name().text()), sConfiguredName)
      << "each advertised endpoint must carry the configured ApplicationName";
  }
}

// DEFAULT: the test config's own URI (`urn:test:...` from `create_test_config`), which is a DIFFERENT
// string - so a server ignoring the field advertises that instead and fails the equality below.
TEST_F(ConfigurationServerApplicationUri, ConfiguredApplicationUriIsAdvertisedOnEveryEndpoint)
{
  auto endpoints = mClient->discovery().try_get_endpoints_sync(mEndpointUrl, {});
  ASSERT_TRUE(endpoints.is_good()) << to_string(endpoints.status_code());
  ASSERT_FALSE(endpoints.value().empty()) << "the server must advertise at least one endpoint";

  // EVERY endpoint, not just the first: the description is per-endpoint on the wire, and a server that
  // populated only one would still satisfy a first-only assertion.
  for (const auto& endpoint : endpoints.value())
  {
    EXPECT_EQ(static_cast<ua::string_view>(endpoint.server().application_uri()), sConfiguredUri)
      << "each advertised endpoint must carry the configured ApplicationUri";
  }
}

// Row: ClientConfig::defaultSessionTimeout.
//
// The client-wide fallback used when a Connection leaves `sessionTimeout` unset. Its sibling row
// (`ConnectionConfig::sessionTimeout`) proved the per-connection slot WINS, and its nullopt control showed
// "something else" is sent instead - but never that the something else is THIS field's configured value.
// A client hardcoding 20 minutes would satisfy that control exactly as well.
//
// So this row moves the client-wide default to a distinctive value, leaves the per-connection slot unset,
// and captures what CreateSession actually carries.
class ConfigurationWireCapturedClientDefaultTimeout : public ::testing::Test
{
protected:
  // The requestedSessionTimeout of the first CreateSession, under a client whose default is @p clientDefault
  // and a connection that does NOT set its own.
  double captured_for_client_default(std::chrono::milliseconds clientDefault)
  {
    MisbehavingServer server;
    auto captured = std::make_shared<std::atomic<double>>(0.0);
    server.set_request_observer(
      [captured](const ua::Structure& request)
      {
        if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
        {
          double expected = 0.0;
          captured->compare_exchange_strong(expected, create->requested_session_timeout());
        }
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";

    ua::client::ClientConfig clientCfg;
    clientCfg.defaultSessionTimeout = clientDefault;

    auto client = Client::create(pool.executor(),
      client::CreateConfig{.identity = ApplicationIdentity::load_default(),
        .application = std::move(appCfg),
        .client = clientCfg},
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url_none();
    config.sessionTimeout = std::nullopt;  // the whole point: fall back to the client-wide default
    config.reconnect = std::nullopt;
    auto connection = client.try_connect_sync(std::move(config));
    if (connection.is_good())
      (void)std::move(connection).value().try_close_sync();

    const double value = captured->load();
    ::ua::test_utils::stop_pool_in_teardown(pool, "client-default-timeout");
    return value;
  }
};

// DEFAULT (20 min == 1200000 ms): a client that ignored the field would send that instead of either value
// below, so both halves fail against it.
TEST_F(ConfigurationWireCapturedClientDefaultTimeout, ClientWideDefaultIsSentWhenTheConnectionSlotIsUnset)
{
  EXPECT_DOUBLE_EQ(captured_for_client_default(std::chrono::milliseconds{240000}), 240000.0)
    << "with no per-connection sessionTimeout the client-wide default must be what CreateSession carries";

  // A SECOND distinctive value: one alone could be satisfied by a client hardcoded to that number.
  EXPECT_DOUBLE_EQ(captured_for_client_default(std::chrono::milliseconds{360000}), 360000.0)
    << "and a different configured default must produce a different requested timeout";
}

// Row: SecureChannel::CreateSessionConfig::sessionName - the TIER-0 session name.
//
// Distinct from `ConnectionConfig::sessionName` (the tier-1 slot, covered separately): this is the field a
// caller sets on `create_session_sync`. The audit marked it WEAK because every existing use passes a name
// and then asserts nothing about it - the name is fixture bookkeeping, not an oracle.
//
// It is worth its own row because **D15 fixed the interface both fields flow through**: before that fix the
// client never set `session_name()` on the request at all, so this field was as inert as its tier-1
// sibling. The row pins the tier-0 entry point directly rather than trusting one fix covered both.
class ConfigurationWireCapturedTier0SessionName : public ::testing::Test
{
protected:
  // The sessionName of the first CreateSession, for a TIER-0 create_session_sync call.
  std::string captured_tier0_name(const std::string& requested)
  {
    MisbehavingServer server;
    auto captured = std::make_shared<std::string>();
    auto seen = std::make_shared<std::atomic<bool>>(false);
    server.set_request_observer(
      [captured, seen](const ua::Structure& request)
      {
        if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
        {
          bool expected = false;
          if (seen->compare_exchange_strong(expected, true))
            *captured = std::string{static_cast<ua::string_view>(create->session_name())};
        }
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";
    auto client = Client::create(pool.executor(),
      client::CreateConfig{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)},
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    auto channel = client.core().open_channel_sync({.endpointUrl = server.endpoint_url_none()});
    auto session = channel.create_session_sync({.sessionName = requested});
    (void)session.try_close_sync();
    (void)channel.try_close_sync();

    const std::string value = *captured;
    ::ua::test_utils::stop_pool_in_teardown(pool, "tier0-session-name");
    return value;
  }
};

// DEFAULT: the client's own product name. Two distinctive requests are used because one alone would pass
// against a client hardcoded to that string.
TEST_F(ConfigurationWireCapturedTier0SessionName, Tier0SessionNameIsSentOnCreateSession)
{
  EXPECT_EQ(captured_tier0_name("Tier0NamedSessionA"), "Tier0NamedSessionA")
    << "the tier-0 mSessionName must be what CreateSession carries";
  EXPECT_EQ(captured_tier0_name("Tier0NamedSessionB"), "Tier0NamedSessionB")
    << "and a different requested name must produce a different name on the wire";
}

// AddressSpaceCachePolicy::maxCachedAttributes is NOT covered here, but the matrix's ORIGINAL premise was
// wrong and is corrected there: the attribute cache does have a real consumer
// (`ConnectionImpl::validate_index_range_write_async` reads cached valueRank / accessLevelEx to reject an
// invalid index-range write client-side). The stimulus tried here was rejected earlier with
// BadTypeMismatch in BOTH the cached and evicted cases, so it could not discriminate. See the matrix row.
// Rows: ServerCapabilities::maxHistoryContinuationPoints and maxMonitoredItemsQueueSize - the
// ADVERTISEMENT halves (configuration coverage matrix section 12b, both DEMOTED by the mutation spot-check).
//
// WHY THESE ROWS EXIST. Both were audited CONFIRMED and neither was. `maxHistoryContinuationPoints` had
// one test naming its node, and that test asserts `ASSERT_NE(limit, nullptr)` - the node exists and
// decodes, which ANY value satisfies. `maxMonitoredItemsQueueSize` had no test reading its node at all;
// its enforcement is pinned only incidentally, as the non-durable ceiling another row holds low.
//
// A capability node exists to tell a client how to size its requests. Advertising a number the operator
// did not configure is the failure mode, and asserting the VALUE is the only thing that catches it.
class ConfigurationAdvertisedCapabilities : public ComplianceWithSession
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.server_capabilities().maxHistoryContinuationPoints = 9;  // default 100
    serverCfg.server_capabilities().maxMonitoredItemsQueueSize = 33;  // default much larger
  }

  // Templated on the node's own encoded type: MaxHistoryContinuationPoints is a UInt16 and
  // MaxMonitoredItemsQueueSize a UInt32, and reading either as the other throws a Variant access error.
  template<typename T>
  T advertised(VariableId node)
  {
    auto read = mSession->attributes().try_read_sync(read_value(NodeId{node}));
    EXPECT_TRUE(read.is_good()) << to_string(read.status_code());
    if (read.is_bad() || read.value().results().empty())
      return T{};
    return read.value().results()[0].value().template as<T>();
  }
};

// DEFAULT (100): the node reads 100, so the configured 9 is what distinguishes them.
TEST_F(ConfigurationAdvertisedCapabilities, HistoryContinuationPointCeilingIsAdvertised)
{
  EXPECT_EQ(advertised<uint16_t>(VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints), 9u)
    << "the configured history continuation-point ceiling must be advertised; the pre-existing test "
       "asserted only that this node exists, which any value satisfies";
}

// DEFAULT: a much larger ceiling, so 33 is distinctive.
TEST_F(ConfigurationAdvertisedCapabilities, MonitoredItemQueueSizeCeilingIsAdvertised)
{
  EXPECT_EQ(advertised<uint32_t>(VariableId::Server_ServerCapabilities_MaxMonitoredItemsQueueSize), 33u)
    << "the configured monitored-item queue ceiling must be advertised; no test read this node before";
}

// Row: ExecutionLimits::loopLimit - the CONFIGURATION-VALIDATION half (D18).
//
// The enforcement half stays blocked (the Call service's hierarchy walk never approaches the budget on
// NS0's shallow types), but the field has a second, sharper observable: a value the server's own NS0
// import cannot complete under.
//
// **Before D18 that TERMINATED the process.** `LoopLimit::consume_iteration` throws on exhaustion; the
// import step runner did not catch, so the throw escaped onto an executor thread and called
// std::terminate. A configuration value the API accepted as legal killed the server at startup. This row
// pins both halves of the fix: validation rejects the value with a diagnostic, and nothing aborts.
TEST(ConfigurationLoopLimitValidation, TooSmallLoopLimitIsRejectedRatherThanFatal)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.execution_limits().loopLimit = 1;  // legal by the old rule (> 0), fatal in practice

  // The oracle is a THROWN CONFIGURATION ERROR, not a crash. Without the floor this call never returns -
  // the process dies inside NS0 import - so reaching either branch below is itself part of the assertion.
  try
  {
    appCfg.validate();
    ADD_FAILURE() << "a LoopLimit below the NS0 import floor must be rejected by validation";
  }
  catch (const ua::UaException& error)
  {
    EXPECT_EQ(error.status_code().as_status(), ua::Status::BadConfigurationError)
      << "rejection must name a configuration problem, not a generic failure";
  }

  // The control: the shipped default is comfortably above the floor and must still validate.
  auto defaultCfg = ua::test_utils::create_test_config();
  EXPECT_NO_THROW(defaultCfg.validate())
    << "the default LoopLimit must remain valid - a floor that rejected the default would be a worse bug "
       "than the one it fixes";
}

// Row: OperationLimits::maxNodesPerHistoryUpdateEvents - the ENFORCEMENT half, unblocked by the D6 fix.
//
// Before D6 the server applied the DATA ceiling to every HistoryUpdate regardless of detail class, so the
// event ceiling was advertised and never enforced. The fix counts each class separately and refuses the
// request when EITHER count exceeds its own ceiling.
//
// The mixed-batch rule is the part D6 had to decide, so it is asserted here rather than left implicit: a
// batch is judged per class, not as a whole. Counting the whole batch against one ceiling would refuse a
// request that is inside both - which is what the old behaviour did to mixed batches.
class ConfigurationHistoryUpdateEventCeiling : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    auto& limits = serverCfg.server_capabilities().operationLimits;
    limits.maxNodesPerHistoryUpdateEvents = 1;  // default 100
    limits.maxNodesPerHistoryUpdateData = 4;  // deliberately DIFFERENT, so the two cannot be confused
  }

  // @p events UpdateEventDetails items plus @p data UpdateDataDetails items in one request.
  static HistoryUpdateRequest mixed(std::size_t events, std::size_t data)
  {
    HistoryUpdateRequest request;
    for (std::size_t i = 0; i < events; ++i)
    {
      auto details = std::make_unique<UpdateEventDetails>();
      details->node_id() = NodeId{ObjectId::Server};
      details->perform_insert_replace() = PerformUpdateType::Insert;
      RefStructure<Structure> wrapped;
      wrapped = std::unique_ptr<Structure>(std::move(details));
      request.history_update_details().push_back(std::move(wrapped));
    }
    for (std::size_t i = 0; i < data; ++i)
    {
      auto details = std::make_unique<UpdateDataDetails>();
      details->node_id() = NodeId{VariableId::Server_ServerStatus_State};
      details->perform_insert_replace() = PerformUpdateType::Insert;
      details->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
      RefStructure<Structure> wrapped;
      wrapped = std::unique_ptr<Structure>(std::move(details));
      request.history_update_details().push_back(std::move(wrapped));
    }
    return request;
  }
};

// DEFAULT (100): two event items are far inside the ceiling and the request is not refused on count.
TEST_F(ConfigurationHistoryUpdateEventCeiling, EventItemsAboveTheEventCeilingAreRefused)
{
  auto over = mSession->attributes().try_history_update_sync(mixed(/*events=*/2, /*data=*/0));
  EXPECT_EQ(over.status_code().as_status(), Status::BadTooManyOperations)
    << "two event items exceed an event ceiling of one";

  // Branch control: THREE data items exceed the event ceiling but are inside the data ceiling of four, so
  // a server still applying the data ceiling to everything - or the event ceiling to everything - fails
  // one of these two assertions.
  auto dataOnly = mSession->attributes().try_history_update_sync(mixed(/*events=*/0, /*data=*/3));
  EXPECT_NE(dataOnly.status_code().as_status(), Status::BadTooManyOperations)
    << "three DATA items are inside the data ceiling of four and must not be judged against the event "
       "ceiling of one";
}

// The mixed-batch rule D6 chose: each class against its own ceiling.
TEST_F(ConfigurationHistoryUpdateEventCeiling, MixedBatchIsJudgedPerDetailClass)
{
  // One event + three data: inside BOTH ceilings, though four items total would exceed the event one.
  auto insideBoth = mSession->attributes().try_history_update_sync(mixed(/*events=*/1, /*data=*/3));
  EXPECT_NE(insideBoth.status_code().as_status(), Status::BadTooManyOperations)
    << "a batch inside both ceilings must be accepted; judging the four items as a whole against the "
       "event ceiling of one would refuse it";

  // Two events + one data: inside the data ceiling, over the event one.
  auto overEvents = mSession->attributes().try_history_update_sync(mixed(/*events=*/2, /*data=*/1));
  EXPECT_EQ(overEvents.status_code().as_status(), Status::BadTooManyOperations)
    << "the event class alone exceeds its ceiling, so the request must be refused even though the data "
       "class is inside its own";
}

// Row: ServerConfig::maxRequestsPerSession - unblocked by the D19 fix.
//
// Before D19 this cap bounded nothing: its counter was released in `execute_service`, i.e. at DISPATCH,
// so it measured a window that closes immediately. Demonstrated at the time with exactly this harness -
// cap 1, a method call parked and genuinely outstanding, and an unrelated Read served in 40 ms instead of
// being refused. The counter is now released on the response path, matching the channel-level siblings.
//
// The parking handler is what makes "outstanding" real: the request stays in flight for as long as the
// handler declines to call back, which is the state the cap is supposed to count.
class ConfigurationMaxRequestsPerSession : public ConfigurationInFlightPerConnection
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.maxRequestsPerSession = 1;  // default nullopt == unbounded
    // BOTH channel-level caps stay unbounded, so a refusal here can only be the per-SESSION one. Without
    // this pinning the row could not tell D19's fix from its already-working siblings.
    cfg.maxInFlightRequests = 0;
    cfg.maxInFlightRequestsPerConnection = 0;
  }
};

// DEFAULT (nullopt == unbounded): the second request is served while the first is still parked.
TEST_F(ConfigurationMaxRequestsPerSession, SecondOutstandingRequestOnTheSessionIsRefused)
{
  std::promise<void> firstDone;
  auto firstFuture = firstDone.get_future();
  mSession->methods().call_async(
    park_request(), [&firstDone](ua::Result<CallResponse>) { firstDone.set_value(); });

  ASSERT_TRUE(mParked->wait_for_calls(1)) << "the first call must reach the parking handler and stay there";

  auto second =
    mSession->attributes().try_read_sync(read_value(NodeId{VariableId::Server_ServerStatus_State}));
  const auto secondStatus =
    second.is_good() ? second.value().response_header().service_result() : second.status_code();

  EXPECT_EQ(secondStatus.as_status(), Status::BadServerTooBusy)
    << "with the per-session cap at 1 a second OUTSTANDING request must be refused; before D19 this read "
       "was served in ~40 ms because the counter had already been released at dispatch";

  mParked->release_all();
  EXPECT_EQ(firstFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "and the parked request must still complete once released";
}

// The other half of D19: releasing on the response path must actually release. A cap that never freed its
// slot would pass the row above and then refuse everything forever.
TEST_F(ConfigurationMaxRequestsPerSession, SlotIsReleasedOnceTheResponseIsSent)
{
  for (int attempt = 0; attempt < 3; ++attempt)
  {
    auto read =
      mSession->attributes().try_read_sync(read_value(NodeId{VariableId::Server_ServerStatus_State}));
    ASSERT_TRUE(read.is_good()) << "sequential requests must each be served: the previous response released "
                                   "its slot (attempt "
                                << attempt << ")";
    EXPECT_TRUE(read.value().response_header().service_result().is_good());
  }
}

// Row: ResourceLimits::orphanedSubscriptionStore - unblocked by the D20 close option.
//
// A Session closed with `deleteSubscriptions == false` PARKS its Subscriptions for a later
// TransferSubscriptions (OPC 10000-4 5.6.4). The store is attacker-facing - a client can orphan
// repeatedly - so it is bounded, and at capacity the OLDEST parked Subscription is dropped.
//
// **THE CHANNEL MUST BE SECURED.** Part 4 5.13.7 authorisation, as implemented at
// `ua_subscriptions_pipeline.cpp:1808`, lets an ANONYMOUS owner reclaim only when the owning channel was
// authenticated - otherwise any anonymous caller could claim another's Subscriptions. A first attempt at
// this row parked over a None channel and could reclaim nothing, with a bounded store or a roomy one;
// that refusal was the rule working, not a defect.
class ConfigurationOrphanedStore : public ComplianceSecuredWithSession
{
protected:
  void configure_server_create_config(ua::server::CreateConfig& cfg) override
  {
    cfg.server.resourceLimits.orphanedSubscriptionStore = 1;  // default 16: only ONE parked sub survives
  }

  // Opens a SECURED session, creates a subscription, then closes PARKING it.
  uint32_t park_one_subscription(const std::string& name)
  {
    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;

    auto channel = mClient->core().open_channel_sync(std::move(channelCfg));
    auto session = channel.create_session_sync({.sessionName = name});
    session.activate_sync();
    auto created = session.subscriptions().create_subscription_sync(build_subscription_request({}));
    EXPECT_TRUE(created.response_header().service_result().is_good());
    const uint32_t id = created.subscription_id();

    (void)session.try_close_sync(ua::client::Session::CloseOptions{.deleteSubscriptions = false});
    (void)channel.try_close_sync();
    return id;
  }

  // Whether the fixture's (also secured) session can reclaim @p subscriptionId.
  bool can_transfer(uint32_t subscriptionId)
  {
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(subscriptionId);
    req.send_initial_values() = false;
    auto result = mSession->subscriptions().try_transfer_subscriptions_sync(std::move(req));
    if (result.is_bad() || result.value().results().empty())
      return false;
    return result.value().results()[0].status_code().is_good();
  }
};

/// A server-wide ceiling of 2, on SECURED channels: an anonymous transfer is only authorised between
/// signed channels of the same application, so both sessions here open the way
/// ConfigurationOrphanedStore does.
class ConfigurationServerWideMonitoredItemLimitSecured : public ComplianceSecuredWithSession
{
protected:
  void configure_server_create_config(ua::server::CreateConfig& cfg) override
  {
    cfg.server.server_capabilities().maxMonitoredItems = 2;  // default 10000
    cfg.server.server_capabilities().maxMonitoredItemsPerSubscription = 50;
  }

  static MonitoredItemCreateRequest current_time_item(uint32_t clientHandle)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = NodeId{VariableId::Server_ServerStatus_CurrentTime};
    item.item_to_monitor().attribute_id() = static_cast<IntegerId>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 100.0;
    item.requested_parameters().queue_size() = 1;
    return item;
  }

  static CreateMonitoredItemsRequest one_item(uint32_t subscriptionId, uint32_t clientHandle)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(current_time_item(clientHandle));
    return request;
  }

  // Opens a SECURED session, fills the ceiling with two items on one subscription, then parks it.
  uint32_t park_a_full_subscription(const std::string& name)
  {
    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;
    auto channel = mClient->core().open_channel_sync(std::move(channelCfg));
    auto session = channel.create_session_sync({.sessionName = name});
    session.activate_sync();
    auto created = session.subscriptions().create_subscription_sync(build_subscription_request({}));
    EXPECT_THAT(created, ServiceResultIsGood());
    const uint32_t id = created.subscription_id();
    for (uint32_t handle = 1; handle <= 2; ++handle)
    {
      auto items = session.monitored_items().create_monitored_items_sync(one_item(id, handle));
      EXPECT_EQ(items.results().size(), 1u);
      EXPECT_TRUE(items.results()[0].status_code().is_good()) << "item " << handle << " fills the ceiling";
    }
    (void)session.try_close_sync(ua::client::Session::CloseOptions{.deleteSubscriptions = false});
    (void)channel.try_close_sync();
    return id;
  }
};

// A session that closes with deleteSubscriptions=false parks its subscription; the parked
// subscription's MonitoredItems no longer count against the server-wide ceiling, so another session
// gets the slots. Transferring the orphan back claims them again, bounded by the same ceiling.
// @relation(AC-SVR-SUB-GEN-032-ORPHANS-RELEASE-MONITORED-ITEM-SLOTS, scope=function)
TEST_F(ConfigurationServerWideMonitoredItemLimitSecured, AParkedSubscriptionReleasesItsSlotsToOtherSessions)
{
  const uint32_t parkedId = park_a_full_subscription("ParkingSession");

  // The fixture's (secured, same application) session now gets a slot: the parked subscription holds none.
  auto subB = mSession->subscriptions().create_subscription_sync(build_subscription_request({}));
  ASSERT_THAT(subB, ServiceResultIsGood());
  auto created = mSession->monitored_items().create_monitored_items_sync(one_item(subB.subscription_id(), 7));
  ASSERT_EQ(created.results().size(), 1u);
  EXPECT_TRUE(created.results()[0].status_code().is_good())
    << "a parked subscription's items must not count against the server-wide ceiling; before the fix "
       "this item is refused with BadTooManyMonitoredItems";

  // Claiming the orphan's 2 items back on top of the 1 held would exceed the ceiling: refused, and the
  // orphan stays parked.
  TransferSubscriptionsRequest transfer;
  transfer.subscription_ids().push_back(parkedId);
  transfer.send_initial_values() = false;
  auto refused = mSession->subscriptions().transfer_subscriptions_sync(transfer);
  ASSERT_THAT(refused, ServiceResultIsGood());
  ASSERT_EQ(refused.results().size(), 1u);
  EXPECT_NE(refused.results()[0].status_code().as_status(), Status::BadUserAccessDenied)
    << "both channels are signed and belong to the same application, so the transfer is authorised";
  EXPECT_EQ(refused.results()[0].status_code().as_status(), Status::BadTooManyMonitoredItems)
    << "re-claiming an orphan's items is bounded by the same ceiling as creating them";

  // Release the held slot and the same transfer fits exactly.
  DeleteSubscriptionsRequest release;
  release.subscription_ids().push_back(subB.subscription_id());
  ASSERT_THAT(mSession->subscriptions().delete_subscriptions_sync(release), ServiceResultIsGood());
  auto accepted = mSession->subscriptions().transfer_subscriptions_sync(transfer);
  ASSERT_THAT(accepted, ServiceResultIsGood());
  ASSERT_EQ(accepted.results().size(), 1u);
  EXPECT_TRUE(accepted.results()[0].status_code().is_good()) << "control: a transfer within the ceiling";
}

// DEFAULT (16): both parked subscriptions survive and both transfer.
TEST_F(ConfigurationOrphanedStore, ParkingBeyondTheCapEvictsTheOldest)
{
  const uint32_t first = park_one_subscription("OrphanFirst");
  const uint32_t second = park_one_subscription("OrphanSecond");

  // The survivor FIRST: if reclaim is broken outright, this fails and the eviction assertion below cannot
  // be read as evidence of anything. Ordering the assertions this way is what stops the row passing
  // vacuously against a store that dropped everything.
  EXPECT_TRUE(can_transfer(second))
    << "the newest parked subscription must be reclaimable - without this the eviction assertion below "
       "would pass against a store that kept nothing";

  EXPECT_FALSE(can_transfer(first))
    << "with the store bounded at one, parking a second subscription must evict the first; under the "
       "default of 16 both remain reclaimable";
}

// Row: Session::CloseOptions::deleteSubscriptions (the D20 API addition).
//
// Pins the new option at the wire, independently of whether the server then parks anything: the flag is a
// client-side contract (OPC 10000-4 5.6.4) and this asserts the client actually sends what it was told to.
// Kept separate from the orphaned-store row so a server-side parking problem cannot be mistaken for a
// client-side plumbing problem - which is exactly the ambiguity that appeared when both were one test.
class ConfigurationWireCapturedCloseFlag : public ::testing::Test
{
protected:
  // The deleteSubscriptions flag of the first CloseSession the server decodes.
  std::optional<bool> captured_close_flag(bool deleteSubscriptions)
  {
    MisbehavingServer server;
    auto captured = std::make_shared<std::optional<bool>>();
    server.set_request_observer(
      [captured](const ua::Structure& request)
      {
        if (const auto* close = dynamic_cast<const ua::CloseSessionRequest*>(&request))
        {
          if (!captured->has_value())
            *captured = close->delete_subscriptions();
        }
      });

    boost::asio::thread_pool pool;
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = "urn:test:misbehaving:client";
    auto client = Client::create(pool.executor(),
      client::CreateConfig{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)},
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    auto channel = client.core().open_channel_sync({.endpointUrl = server.endpoint_url_none()});
    auto session = channel.create_session_sync({.sessionName = "CloseFlagProbe"});
    session.activate_sync();
    (void)session.try_close_sync(
      ua::client::Session::CloseOptions{.deleteSubscriptions = deleteSubscriptions});
    (void)channel.try_close_sync();

    const auto value = *captured;
    ::ua::test_utils::stop_pool_in_teardown(pool, "close-flag");
    return value;
  }
};

// DEFAULT (true): the historical behaviour, and what every other close path still sends.
TEST_F(ConfigurationWireCapturedCloseFlag, CloseConfigControlsTheDeleteSubscriptionsFlag)
{
  const auto parked = captured_close_flag(false);
  ASSERT_TRUE(parked.has_value()) << "a CloseSession must have been observed at all";
  EXPECT_FALSE(*parked) << "mDeleteSubscriptions=false must reach the wire as deleteSubscriptions=false";

  const auto deleted = captured_close_flag(true);
  ASSERT_TRUE(deleted.has_value());
  EXPECT_TRUE(*deleted)
    << "and true must still send true - without this half the row would pass against a client that "
       "hardcoded false, which is just the old bug inverted";
}

}  // namespace

// Row: DiagnosticPolicy::defaultLevel vs maxLevel - a self-contradictory pair is refused.
//
// defaultLevel is the ceiling applied to a caller carrying no diagnostics claim, so a default above
// maxLevel means the struct declares a bound its own default exceeds. Before this, that pair was
// accepted and the server emitted at the higher level: resolve_diagnostic_level checked maxLevel on
// the two claim-elevation paths and then returned defaultLevel unchecked.
TEST(ConfigurationDiagnosticPolicyValidation, DefaultLevelAboveMaxLevelIsRejected)
{
  using Level = ua::server::ServerConfig::DiagnosticPolicy::Level;

  ua::server::ServerConfig cfg;
  cfg.diagnosticPolicy.defaultLevel = Level::Full;
  cfg.diagnosticPolicy.maxLevel = Level::Summary;

  try
  {
    cfg.validate();
    ADD_FAILURE() << "a DefaultLevel above MaxLevel must be rejected by validation";
  }
  catch (const ua::UaException& error)
  {
    EXPECT_EQ(error.status_code().as_status(), ua::Status::BadConfigurationError)
      << "rejection must name a configuration problem, not a generic failure";
  }

  // Equal levels are the boundary and must stay legal - the ceiling is inclusive.
  ua::server::ServerConfig equalCfg;
  equalCfg.diagnosticPolicy.defaultLevel = Level::Summary;
  equalCfg.diagnosticPolicy.maxLevel = Level::Summary;
  EXPECT_NO_THROW(equalCfg.validate()) << "DefaultLevel == MaxLevel is a bound met, not exceeded";

  // The control: the shipped defaults (None under Full) must still validate.
  EXPECT_NO_THROW(ua::server::ServerConfig{}.validate())
    << "the shipped DiagnosticPolicy defaults must remain valid";
}
