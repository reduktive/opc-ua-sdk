// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// End-to-end integration tests for the tier-1 managed connect entry point Client::connect_async /
/// connect_sync (section 7.3 / section 8.2A), driven against a real in-tree TestServer over ephemeral TCP.
/// Unlike the ConnectionImpl integration tests (which perform the tier-0 open/create/activate dance by hand
/// and hand the session to ConnectionImpl::create), these drive the PRODUCTION connect path: one
/// Client::connect_sync call opens the SecureChannel, runs CreateSession + ActivateSession with the
/// configured identity, bootstraps the NamespaceArray, and returns an Active managed Connection.
///
/// Oracle: the real client stack talks to a real server. A read of a well-known node returns a real value; a
/// bad endpoint fails the connect with a real transport error. Nothing self-populates its own oracle.

#include "compliance_helpers.h"

#include "ua_browse_cursor.h"
#include "ua_client_subscription.h"
#include "ua_core_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_connection_state.h"
#include "ua_data_value.h"
#include "ua_method_id.h"
#include "ua_node_id.h"
#include "ua_server_state.h"
#include "ua_server_table.h"
#include "ua_string.h"
#include "ua_subscriptions.h"
#include "ua_typed_access.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace
{
using ua::client::ConnectionConfig;
using ua::client::detail::ConnectionState;

using ClientConnectIntegration = ComplianceBase;

// A managed connect reaches Active: connect_sync drives open-channel -> CreateSession -> ActivateSession ->
// NamespaceArray bootstrap end-to-end and hands back an Active Connection whose server-assigned session id is
// populated.
// @verifies CL-SESS-001 [integration] - CreateSession is issued end-to-end on the managed connect path.
// @verifies CL-SESS-009 [integration] - ActivateSession is issued end-to-end on the managed connect path.
// @relation(CL-SESS-001, CL-SESS-009, scope=function)
TEST_F(ClientConnectIntegration, ConnectSyncReachesActiveWithSession)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);

  EXPECT_EQ(connection.state(), ConnectionState::Active);
  auto sessionId = connection.session_id();
  ASSERT_TRUE(sessionId.is_good());
  EXPECT_FALSE(sessionId.value().is_null()) << "the server assigns a session id on CreateSession";

  connection.close_sync();
  EXPECT_EQ(connection.state(), ConnectionState::Closed);
}

// A read through the managed Connection returns a real server value (the tier-1 wire path works off the
// connect_async-produced Connection, not a hand-built one).
TEST_F(ClientConnectIntegration, ReadValueThroughManagedConnection)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  auto value = connection.read_value_sync(ua::NodeId{ua::VariableId::Server_ServerStatus_State});
  EXPECT_FALSE(value.status().has_value() && value.status()->is_bad())
    << "Server.ServerStatus.State reads a non-bad value through the managed Connection";
  EXPECT_FALSE(value.value().empty()) << "the read returned a real server value";

  connection.close_sync();
}

// The managed connect path bootstraps the three Session continuation-point ceilings from the real Server.
// The component unit suite supplies the falsifiable queue/admission oracles; this public-tier integration
// pin proves the production Client -> Connection path reaches a Server that publishes the normative UInt16
// capability properties used by that bootstrap.
// @verifies CL-BASE-004 [integration] - managed Client bootstrap reaches all three advertised ceilings.
// @relation(CL-BASE-004, scope=function)
TEST_F(ClientConnectIntegration, ManagedConnectionServerPublishesContinuationPointLimits)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  const std::array limitNodes{ua::VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints,
    ua::VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints,
    ua::VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints};
  for (const auto limitNode : limitNodes)
  {
    const auto value = connection.read_value_sync(ua::NodeId{limitNode});
    const auto* limit = value.value().try_as<std::uint16_t>();
    ASSERT_NE(limit, nullptr);
    EXPECT_GT(*limit, 0u);
  }

  connection.close_sync();
}

// A connect to a bad endpoint fails with a real transport error (never a hang, never a false Active).
TEST_F(ClientConnectIntegration, ConnectToBadEndpointFailsFast)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://127.0.0.1:1";  // nothing listening on port 1

  auto result = mClient->try_connect_sync(config);

  EXPECT_TRUE(result.is_bad()) << "a connect to a dead endpoint must fail, not hang or falsely succeed";
}

// Part 5 section 6.3.1: a server shall not modify or delete a `ServerArray` entry while a client has an open
// Session, because clients cache the table. That guarantee is what makes the Connection's one-shot
// `ServerTable` snapshot safe to resolve `ExpandedNodeId.serverIndex` against for the whole Session. A
// plausible implementation caches the table and then never checks that its snapshot still describes the
// server it is talking to, so a table that shifted underneath it would resolve an index to the wrong
// server silently.
// @verifies AC-CL-BASE-002-SERVERARRAY-STABLE
TEST_F(ClientConnectIntegration, CachedServerArrayEntriesStayValidForTheSessionLifetime)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  const auto cached = connection.server_table();
  ASSERT_NE(cached, nullptr) << "the managed connect bootstraps a Session-scoped ServerArray snapshot";
  ASSERT_GE(cached->size(), 1u) << "a valid table always carries the local Server at index 0";
  const auto localUri = cached->lookup_uri(0);
  ASSERT_TRUE(localUri.has_value());
  ASSERT_FALSE(localUri->empty()) << "an empty entry 0 would make every comparison below vacuous";
  const std::string localUriAtBootstrap{*localUri};
  const std::uint64_t generationAtBootstrap = cached->generation();

  // The consumption path the guarantee exists for: an ExpandedNodeId's serverIndex resolved against the
  // cache rather than against a fresh read.
  const ua::ExpandedNodeId localTarget{ua::NodeId{ua::VariableId::Server_ServerStatus_State}};
  const auto resolvedAtBootstrap = cached->resolve_server_uri(localTarget);
  ASSERT_TRUE(resolvedAtBootstrap.is_good()) << "serverIndex 0 must resolve off the cached table: 0x"
                                             << std::hex << resolvedAtBootstrap.status_code().as_uint32();
  EXPECT_EQ(resolvedAtBootstrap.value(), localUriAtBootstrap);

  // "Throughout the Session" has to mean the Session has been used in between, otherwise a table
  // recomputed per request is indistinguishable from one held still.
  for (int round = 0; round < 3; ++round)
  {
    const auto tick = connection.read_value_sync(ua::NodeId{ua::VariableId::Server_ServerStatus_CurrentTime});
    EXPECT_FALSE(tick.value().empty()) << "the Session is genuinely in use between the two observations";
  }

  // Conjunct 1 - the cached entries remain valid: the same index still resolves, off the same snapshot,
  // with no re-bootstrap in between.
  const auto stillCached = connection.server_table();
  ASSERT_NE(stillCached, nullptr);
  EXPECT_EQ(stillCached->generation(), generationAtBootstrap)
    << "the Session-scoped snapshot must not be re-bootstrapped mid-Session";
  const auto resolvedLater = stillCached->resolve_server_uri(localTarget);
  ASSERT_TRUE(resolvedLater.is_good()) << "0x" << std::hex << resolvedLater.status_code().as_uint32();
  EXPECT_EQ(resolvedLater.value(), localUriAtBootstrap);
  const auto indexLater = stillCached->lookup_index(localUriAtBootstrap);
  ASSERT_TRUE(indexLater.has_value()) << "the URI the Session cached must still be reachable by index";
  EXPECT_EQ(*indexLater, 0u);

  // Conjunct 2 - the server did not modify or delete an entry this Session may still be using: what it
  // publishes now must still agree, entry for entry, with what the Session cached at bootstrap.
  const auto live = connection.read_value_sync(ua::NodeId{ua::VariableId::Server_ServerArray});
  ASSERT_FALSE(live.status().has_value() && live.status()->is_bad()) << "reading ServerArray returned bad";
  const auto published = live.value().to_vector<ua::String>();
  ASSERT_TRUE(published.is_good()) << "ServerArray did not decode as a String array";
  ASSERT_FALSE(published.value().empty()) << "ServerArray became empty while a Session was open";
  ASSERT_GE(published.value().size(), stillCached->size())
    << "ServerArray lost entries while a Session was open; a server may append but never delete";
  for (std::size_t index = 0; index < stillCached->size(); ++index)
  {
    const auto entry = stillCached->lookup_uri(static_cast<ua::client::ServerIndex>(index));
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(std::string{static_cast<std::string_view>(published.value()[index])}, std::string{*entry})
      << "ServerArray entry " << index << " changed while the Session that cached it was open";
  }

  connection.close_sync();
}

// -------------------------------------------------------------------------------------------------
// Fixtures for the batching / continuation-point rows below.
// -------------------------------------------------------------------------------------------------

// A server carrying a block of read-only Int32 Variables whose value equals their position in the block.
// The value IS the position, so a reassembled batch can be checked slot by slot: a chunk dropped,
// duplicated, or stitched back by completion order rather than request order shows up as a value that does
// not match its index.
class ClientConnectBatchNodes : public ComplianceBase
{
protected:
  static constexpr std::uint32_t sBatchNodeCount = 75;
  static constexpr std::uint32_t sFirstBatchIdentifier = 1000;

  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mTestNamespace =
      ua::default_ns::Namespace::create("urn:test:client-connect-batch", mServer.thread_pool().executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);
    // An unconfigured namespace publishes an empty default and hides every undecorated node it owns, so a
    // fixture whose nodes are read back over a session has to say who may see them.
    ua::RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = ua::NodeId{ua::ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() = ua::test_helpers::all_permissions();
    mTestNamespace->set_namespace_defaults(
      std::vector<ua::RolePermissionType>{anonymousPermissions}, std::nullopt);

    auto objectsFolder = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder});
    for (std::uint32_t position = 0; position < sBatchNodeCount; ++position)
    {
      const ua::NodeId nodeId{mTestNamespaceIndex, sFirstBatchIdentifier + position};
      auto node = addressSpace.create_node_sync(nodeId, ua::NodeClass::Variable);
      node.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition},
        ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
      auto variable = node.as<ua::VariableAccessor>();
      ASSERT_TRUE(variable.has_value());
      const std::string name = "BatchNode" + std::to_string(position);
      variable->set_browse_name(ua::QualifiedName{mTestNamespaceIndex, name});
      variable->set_display_name(ua::LocalizedText{"", name});
      variable->set_data_type(ua::NodeId{ua::DataTypeId::Int32});
      variable->write_value_sync(static_cast<std::int32_t>(position));
      variable->set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
      objectsFolder.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, nodeId);
      mBatchNodeIds.push_back(nodeId);
    }
  }

  std::shared_ptr<ua::default_ns::Namespace> mTestNamespace;
  std::uint16_t mTestNamespaceIndex{0};
  std::vector<ua::NodeId> mBatchNodeIds;
};

// The same block of Nodes, on a server that advertises AND enforces MaxNodesPerRead. The limit sits above
// the client's own 18-Node bootstrap Read (NamespaceArray + ServerArray + UrisVersion + twelve
// OperationLimits + three continuation-point ceilings), which is issued before the client can know of any
// limit at all, so the fixture tests the batching obligation and not the bootstrap.
class ClientConnectAdvertisedReadLimit : public ClientConnectBatchNodes
{
protected:
  static constexpr std::uint32_t sMaxNodesPerRead = 30;

  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ClientConnectBatchNodes::configure_server_config(cfg);
    cfg.server_capabilities().operationLimits.maxNodesPerRead = sMaxNodesPerRead;
  }
};

// The same block of Nodes on a server that publishes NO MaxNodesPerRead at all - the common case, since the
// operational-limits Properties are Optional.
class ClientConnectNoAdvertisedReadLimit : public ClientConnectBatchNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ClientConnectBatchNodes::configure_server_config(cfg);
    cfg.server_capabilities().operationLimits.maxNodesPerRead.reset();
  }
};

// Part 5 section 6.3.11: a batched service call is split into chunks no larger than the corresponding
// `OperationLimits` Property. This server ENFORCES the limit it advertises (an over-limit Read faults with
// Bad_TooManyOperations), so a client that read the Property but batched regardless fails the whole call;
// one that split but reassembled by completion order rather than request order hands the caller values
// belonging to other Nodes.
// @verifies AC-CL-BASE-003-OPERATIONLIMITS
TEST_F(ClientConnectAdvertisedReadLimit, BatchedReadIsSplitToRespectTheAdvertisedMaxNodesPerRead)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  // The antecedent is set by the server, not by the test: the bound the client must honour is the one it
  // can read off the address space.
  const auto advertised = connection.try_read_value_sync(
    ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead});
  ASSERT_TRUE(advertised.is_good()) << "0x" << std::hex << advertised.status_code().as_uint32();
  const auto* advertisedLimit = advertised.value().value().try_as<std::uint32_t>();
  ASSERT_NE(advertisedLimit, nullptr) << "the server must publish MaxNodesPerRead for this row to bite";
  ASSERT_EQ(*advertisedLimit, sMaxNodesPerRead);

  ASSERT_EQ(mBatchNodeIds.size(), static_cast<std::size_t>(sBatchNodeCount));

  // 75 Nodes against a limit of 30 is three Reads - 30 + 30 + 15 - none of them over the limit. The server
  // faults any single Read above 30, so a call that succeeds at all proves no request exceeded the bound.
  const auto values = connection.typed().try_read_values_sync(mBatchNodeIds);
  ASSERT_TRUE(values.is_good()) << "an over-limit batch must be split transparently, not faulted: 0x"
                                << std::hex << values.status_code().as_uint32();
  const auto& results = values.value();
  ASSERT_EQ(results.size(), mBatchNodeIds.size()) << "the reassembled Read must return one result per Node";

  for (std::size_t position = 0; position < results.size(); ++position)
  {
    const auto& dataValue = results[position];
    ASSERT_FALSE(dataValue.status().has_value() && dataValue.status()->is_bad())
      << "result " << position << " is bad - a chunk boundary must not corrupt a per-item result";
    const auto* held = dataValue.value().try_as<std::int32_t>();
    ASSERT_NE(held, nullptr) << "result " << position << " did not decode as the Node's Int32 value";
    EXPECT_EQ(*held, static_cast<std::int32_t>(position))
      << "result " << position
      << " carries another Node's value: the batch was reassembled out of "
         "request order";
  }

  connection.close_sync();
}

// Part 5 section 6.3.11 line 1743 - an operational-limits Property that is provided shall be non-zero, so an
// ABSENT Property means *no limit*, not a limit of nothing. Reading absence as a bound is the failure this
// row exists for: it produces a client that splits every request into batches of zero Nodes, and since the
// Properties are Optional that is the common case rather than the exceptional one.
// @verifies AC-CL-BASE-003-OPERATIONLIMITS
TEST_F(ClientConnectNoAdvertisedReadLimit, BatchedReadIsNotSplitWhenNoMaxNodesPerReadIsAdvertised)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  // The antecedent again comes from the server: this endpoint publishes no usable MaxNodesPerRead.
  const auto advertised = connection.try_read_value_sync(
    ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead});
  if (advertised.is_good())
  {
    const auto* advertisedLimit = advertised.value().value().try_as<std::uint32_t>();
    const std::uint32_t publishedLimit = advertisedLimit != nullptr ? *advertisedLimit : 0u;
    ASSERT_EQ(publishedLimit, 0u)
      << "this fixture's antecedent is an ABSENT MaxNodesPerRead; the server published " << publishedLimit;
  }

  ASSERT_EQ(mBatchNodeIds.size(), static_cast<std::size_t>(sBatchNodeCount));

  const auto values = connection.typed().try_read_values_sync(mBatchNodeIds);
  ASSERT_TRUE(values.is_good()) << "an absent limit must impose no client-side split: 0x" << std::hex
                                << values.status_code().as_uint32();
  const auto& results = values.value();
  ASSERT_EQ(results.size(), mBatchNodeIds.size())
    << "with no advertised limit the whole batch is one Read returning one result per Node";

  for (std::size_t position = 0; position < results.size(); ++position)
  {
    const auto& dataValue = results[position];
    ASSERT_FALSE(dataValue.status().has_value() && dataValue.status()->is_bad())
      << "result " << position << " is bad";
    const auto* held = dataValue.value().try_as<std::int32_t>();
    ASSERT_NE(held, nullptr) << "result " << position << " did not decode as the Node's Int32 value";
    EXPECT_EQ(*held, static_cast<std::int32_t>(position))
      << "result " << position << " carries another Node's value";
  }

  connection.close_sync();
}

// A server that permits exactly one parallel Browse continuation point per Session.
class ClientConnectSingleBrowseContinuationPoint : public ComplianceBase
{
protected:
  static constexpr std::uint16_t sMaxBrowseContinuationPoints = 1;

  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceBase::configure_server_config(cfg);
    cfg.server_capabilities().maxBrowseContinuationPoints = sMaxBrowseContinuationPoints;
  }
};

// Part 5 section 6.3.2: a client should not open more Browse calls with open continuation points than
// `MaxBrowseContinuationPoints` exposes. Leaning on the server instead is destructive rather than merely
// untidy - the server frees the OLDEST point of the SAME Session, so a second parallel browse silently
// invalidates the first one's walk. A plausible implementation reads the Property at bootstrap, caches it,
// and then issues every browse the caller asks for regardless.
// @verifies AC-CL-BASE-004-CONTINUATIONPOINT-LIMITS
TEST_F(
  ClientConnectSingleBrowseContinuationPoint, OutstandingBrowseContinuationPointsStayWithinAdvertisedLimit)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto connection = mClient->connect_sync(config);
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  const auto advertised = connection.try_read_value_sync(
    ua::NodeId{ua::VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints});
  ASSERT_TRUE(advertised.is_good()) << "0x" << std::hex << advertised.status_code().as_uint32();
  const auto* advertisedLimit = advertised.value().value().try_as<std::uint16_t>();
  ASSERT_NE(advertisedLimit, nullptr);
  ASSERT_EQ(*advertisedLimit, sMaxBrowseContinuationPoints)
    << "the cap under test must be the one the server actually advertises";

  ua::client::BrowseOptions options;
  options.requestedMaxReferencesPerNode = 1;  // one reference per page, so every page holds a point back

  auto first = connection.typed().browse(ua::NodeId{ua::ObjectId::Server}, options);
  const auto firstEntry = first.try_next_sync();
  ASSERT_TRUE(firstEntry.is_good()) << "0x" << std::hex << firstEntry.status_code().as_uint32();
  ASSERT_TRUE(first.has_more()) << "the first walk must still hold a continuation point for this row to bite";

  // The single permitted point is now outstanding. A second parallel walk must not be issued.
  auto second = connection.typed().browse(ua::NodeId{ua::ObjectId::ObjectsFolder}, options);
  auto deferred = std::make_shared<std::promise<ua::Result<ua::client::BrowseCursor::Entry>>>();
  auto deferredFuture = deferred->get_future();
  second.next_async([deferred](ua::Result<ua::client::BrowseCursor::Entry> result)
    { deferred->set_value(std::move(result)); });

  EXPECT_EQ(deferredFuture.wait_for(std::chrono::milliseconds{1500}), std::future_status::timeout)
    << "a second parallel Browse was issued while the only permitted continuation point was outstanding";

  // ...and the first walk's point was never left for the server to reclaim: it still continues.
  const auto firstContinued = first.try_next_sync();
  EXPECT_TRUE(firstContinued.is_good())
    << "the first walk's continuation point was invalidated - the client relied on the server to reclaim "
       "it: 0x"
    << std::hex << firstContinued.status_code().as_uint32();

  // Releasing the point must release the deferred walk, not drop it: bounding is queueing, not refusing.
  EXPECT_TRUE(first.try_close_sync().is_good());
  ASSERT_EQ(deferredFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "the deferred Browse was dropped rather than issued once continuation-point capacity returned";
  EXPECT_TRUE(deferredFuture.get().is_good());

  connection.close_sync();
}

// Part 5 section 9.1: `Server.GetMonitoredItems` is Server-Object-scoped but its `subscriptionId` is
// Session-scoped, so the Method must be called on the Session that owns the Subscription; the server answers
// a foreign caller with Bad_UserAccessDenied. The Method reads another Session's subscription state, so this
// is an authorisation boundary, and a client that issued it on whatever Session came to hand would be relying
// on a server to enforce something it may not.
// @verifies AC-CL-BASE-006-GETMONITOREDITEMS-OWNING-SESSION
TEST_F(ClientConnectIntegration, GetMonitoredItemsIsIssuedOnlyOnTheSessionOwningTheSubscription)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto owning = mClient->connect_sync(config);
  ASSERT_EQ(owning.state(), ConnectionState::Active);
  auto foreign = mClient->connect_sync(config);
  ASSERT_EQ(foreign.state(), ConnectionState::Active);

  const auto owningSessionId = owning.session_id();
  const auto foreignSessionId = foreign.session_id();
  ASSERT_TRUE(owningSessionId.is_good());
  ASSERT_TRUE(foreignSessionId.is_good());
  ASSERT_NE(owningSessionId.value(), foreignSessionId.value())
    << "the two Connections must be distinct Sessions, otherwise there is no foreign caller here";

  auto subscription =
    owning.subscriptions().try_create_sync(ua::client::SubscriptionConfig{.publishingIntervalMs = 100.0});
  ASSERT_TRUE(subscription.is_good()) << "0x" << std::hex << subscription.status_code().as_uint32();
  const auto item = subscription.value().try_monitor_sync(
    ua::client::MonitorRequest{.nodeId = ua::NodeId{ua::VariableId::Server_ServerStatus_CurrentTime}},
    [](ua::client::DataChangeEvent) {});
  ASSERT_TRUE(item.is_good()) << "0x" << std::hex << item.status_code().as_uint32();
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();

  // Conjunct 1 - calling the Method for this Subscription on the OTHER Session is refused, and the refusal
  // reaches the caller intact rather than being swallowed or retried into a success.
  const auto foreignCall = foreign.typed().try_call_method_sync(ua::NodeId{ua::ObjectId::Server},
    ua::NodeId{ua::MethodId::Server_GetMonitoredItems},
    std::vector<ua::Variant>{ua::Variant{subscriptionId}});
  ASSERT_TRUE(foreignCall.is_good())
    << "the Call service itself must reach the server so the per-Method refusal is observable: 0x" << std::hex
    << foreignCall.status_code().as_uint32();
  EXPECT_TRUE(foreignCall.value().is_bad())
    << "GetMonitoredItems on a Session that does not own the Subscription must not succeed";
  EXPECT_EQ(foreignCall.value().status_code().as_status(), ua::Status::BadUserAccessDenied)
    << "the ownership refusal must be surfaced verbatim, not masked behind another status";

  // Conjunct 2 - the Subscription handle's own call goes to the owning Session and succeeds. Given
  // conjunct 1 this can only be true if the handle routed through the Connection that created it.
  const auto handles = subscription.value().try_get_monitored_items_sync();
  ASSERT_TRUE(handles.is_good()) << "the owning Session's call must succeed: 0x" << std::hex
                                 << handles.status_code().as_uint32();
  ASSERT_FALSE(handles.value().serverHandles.empty())
    << "the Subscription has one monitored item, so empty arrays would make the parallel check vacuous";
  EXPECT_EQ(handles.value().serverHandles.size(), handles.value().clientHandles.size())
    << "ServerHandles and ClientHandles are parallel arrays";

  owning.close_sync();
  foreign.close_sync();
}

// Part 5 section 9.2 - the sibling of GetMonitoredItems and the more consequential of the two: ResendData
// republishes every monitored item's value, so calling it across Sessions floods a Subscription its owner
// never asked to refresh. The server answers a foreign caller with Bad_UserAccessDenied; a client that
// dispatched the Method through an arbitrary Session, or that flattened the per-Method refusal into a
// success, would hide that.
// @verifies AC-CL-BASE-007-RESENDDATA-OWNING-SESSION
TEST_F(ClientConnectIntegration, ResendDataIsIssuedOnlyOnTheSessionOwningTheSubscription)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;

  auto owning = mClient->connect_sync(config);
  ASSERT_EQ(owning.state(), ConnectionState::Active);
  auto foreign = mClient->connect_sync(config);
  ASSERT_EQ(foreign.state(), ConnectionState::Active);

  const auto owningSessionId = owning.session_id();
  const auto foreignSessionId = foreign.session_id();
  ASSERT_TRUE(owningSessionId.is_good());
  ASSERT_TRUE(foreignSessionId.is_good());
  ASSERT_NE(owningSessionId.value(), foreignSessionId.value())
    << "the two Connections must be distinct Sessions, otherwise there is no foreign caller here";

  auto subscription =
    owning.subscriptions().try_create_sync(ua::client::SubscriptionConfig{.publishingIntervalMs = 100.0});
  ASSERT_TRUE(subscription.is_good()) << "0x" << std::hex << subscription.status_code().as_uint32();
  const auto item = subscription.value().try_monitor_sync(
    ua::client::MonitorRequest{.nodeId = ua::NodeId{ua::VariableId::Server_ServerStatus_CurrentTime}},
    [](ua::client::DataChangeEvent) {});
  ASSERT_TRUE(item.is_good()) << "0x" << std::hex << item.status_code().as_uint32();
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();

  // Conjunct 1 - ResendData for this Subscription on the OTHER Session is refused, and the refusal is
  // surfaced to the caller.
  const auto foreignCall = foreign.typed().try_call_method_sync(ua::NodeId{ua::ObjectId::Server},
    ua::NodeId{ua::MethodId::Server_ResendData},
    std::vector<ua::Variant>{ua::Variant{subscriptionId}});
  ASSERT_TRUE(foreignCall.is_good())
    << "the Call service itself must reach the server so the per-Method refusal is observable: 0x" << std::hex
    << foreignCall.status_code().as_uint32();
  EXPECT_TRUE(foreignCall.value().is_bad())
    << "ResendData on a Session that does not own the Subscription must not succeed";
  EXPECT_EQ(foreignCall.value().status_code().as_status(), ua::Status::BadUserAccessDenied)
    << "the ownership refusal must be surfaced verbatim, not masked behind another status";

  // Conjunct 2 - the Subscription handle's own ResendData goes to the owning Session and is accepted.
  // Given conjunct 1 that is only possible if the handle used the Connection that created it.
  const auto resend = subscription.value().try_resend_data_sync();
  EXPECT_TRUE(resend.is_good()) << "the owning Session's ResendData must succeed: 0x" << std::hex
                                << resend.status_code().as_uint32();

  owning.close_sync();
  foreign.close_sync();
}
}  // namespace
