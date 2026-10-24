// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 8: Client-Server End-to-End Integration Tests
///
/// Full lifecycle tests exercising real Client against TestServer with ephemeral TCP.
/// These tests verify that the client-server stack works end-to-end:
/// connect, session, read, browse, write, close.

#include "compliance_helpers.h"
#include "matchers.h"
#include "test_utilities.h"

#include "ua_client_config_bundle.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_data_value.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server_state.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include "test_components.h"
using namespace ua;
using namespace ua::client;

// ===========================================================================
// Test fixture alias - uses ComplianceWithNodes for write-back tests
// ===========================================================================
using ClientServerIntegration = ComplianceWithNodes;

// ---------------------------------------------------------------------------
// INT-001: Connect and read Server_ServerStatus_State
// Open channel -> create session -> activate -> read -> verify Running(0)
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, INT_001_ConnectAndReadServerState)
{
  // Open channel
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  ASSERT_TRUE(channel.is_open());

  // Create and activate session
  auto session = channel.create_session_sync({.sessionName = "INT_001"});
  ASSERT_TRUE(session.is_created());
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // Read Server_ServerStatus_State (ns=0, i=2259)
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;

  auto resp = session.attributes().read_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_FALSE(resp.results()[0].status().has_value())
    << "Read failed: 0x" << std::hex << resp.results()[0].status().value().as_uint32();

  // ServerState::Running == 0
  auto val = resp.results()[0].value().as<int32_t>();
  EXPECT_EQ(val, static_cast<int32_t>(ServerState::Running));

  session.close_sync();
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// INT-002: Browse Root node - verify well-known children
// Browse the Root folder and verify Objects, Types, Views are present.
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, INT_002_BrowseRootNode)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "INT_002"});
  session.activate_sync();

  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::RootFolder};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  auto resp = session.view().browse_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);

  const auto& result = resp.results()[0];
  EXPECT_TRUE(result.status_code().is_good());

  // Root should have at least Objects, Types, Views
  bool hasObjects = false;
  bool hasTypes = false;
  bool hasViews = false;
  for (const auto& ref : result.references())
  {
    auto targetId = ref.node_id().node_id();
    if (targetId == NodeId{ObjectId::ObjectsFolder})
      hasObjects = true;
    else if (targetId == NodeId{ObjectId::TypesFolder})
      hasTypes = true;
    else if (targetId == NodeId{ObjectId::ViewsFolder})
      hasViews = true;
  }

  EXPECT_TRUE(hasObjects) << "Root missing Objects folder";
  EXPECT_TRUE(hasTypes) << "Root missing Types folder";
  EXPECT_TRUE(hasViews) << "Root missing Views folder";

  session.close_sync();
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// INT-003: Write and read back
// Write a value to a writable variable, read it back, verify match.
// ---------------------------------------------------------------------------
TEST_F(ClientServerIntegration, INT_003_WriteAndReadBack)
{
  // Write a new value
  const int32_t newValue = 12345;
  {
    WriteRequest req;
    WriteValue wv;
    wv.node_id() = mWritableVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    wv.value() = DataValue{Variant{newValue}};
    req.nodes_to_write().push_back(std::move(wv));

    auto resp = mSession->attributes().write_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_good())
      << "Write failed: 0x" << std::hex << resp.results()[0].as_uint32();
  }

  // Read back
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = mWritableVariableId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Both;

    auto resp = mSession->attributes().read_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_FALSE(resp.results()[0].status().has_value())
      << "Read failed: 0x" << std::hex << resp.results()[0].status().value().as_uint32();
    EXPECT_EQ(resp.results()[0].value().as<int32_t>(), newValue);
  }
}

// ---------------------------------------------------------------------------
// INT-004: GetEndpoints on channel without session
// Discovery service should work before any session is created.
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, INT_004_GetEndpointsOnChannel)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  ASSERT_TRUE(channel.is_open());

  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));

  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_GE(resp.endpoints().size(), 1u) << "Server should advertise at least one endpoint";

  // Each endpoint should have a valid URL
  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    std::string url = resp.endpoints()[i].endpoint_url();
    EXPECT_FALSE(url.empty()) << "Endpoint " << i << " has empty URL";
  }

  channel.close_sync();
}

// ---------------------------------------------------------------------------
// INT-005: Clean session and channel close - no errors
// Close session -> close channel -> verify no errors throughout.
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, INT_005_CleanSessionAndChannelClose)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "INT_005"});
  session.activate_sync();

  // Verify session is active before closing
  ASSERT_TRUE(session.is_active());

  // Close session
  auto sessionCloseResult = session.try_close_sync();
  EXPECT_THAT(sessionCloseResult, ::ua::test_helpers::Good())
    << "Session close failed: 0x" << std::hex << sessionCloseResult.status_code().as_uint32();

  // Close channel
  auto channelCloseResult = channel.try_close_sync();
  EXPECT_THAT(channelCloseResult, ::ua::test_helpers::Good())
    << "Channel close failed: 0x" << std::hex << channelCloseResult.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// INT-006: Full lifecycle
// Connect -> session -> read -> browse -> write -> read-back -> close session -> close channel
// ---------------------------------------------------------------------------
TEST_F(ClientServerIntegration, INT_006_FullLifecycle)
{
  // ---- Step 1: Read server state ----
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Both;

    auto resp = mSession->attributes().read_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_FALSE(resp.results()[0].status().has_value())
      << "Read failed: 0x" << std::hex << resp.results()[0].status().value().as_uint32();
  }

  // ---- Step 2: Browse root ----
  {
    BrowseRequest req;
    BrowseDescription desc;
    desc.node_id() = NodeId{ObjectId::RootFolder};
    desc.browse_direction() = BrowseDirection::Forward;
    desc.include_subtypes() = true;
    desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
    req.nodes_to_browse().push_back(std::move(desc));

    auto resp = mSession->view().browse_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].status_code().is_good());
    EXPECT_GE(resp.results()[0].references().size(), 3u) << "Root should have at least Objects, Types, Views";
  }

  // ---- Step 3: Write and read back ----
  const int32_t writeVal = 99999;
  {
    WriteRequest req;
    WriteValue wv;
    wv.node_id() = mWritableVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    wv.value() = DataValue{Variant{writeVal}};
    req.nodes_to_write().push_back(std::move(wv));

    auto resp = mSession->attributes().write_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_good())
      << "Write failed: 0x" << std::hex << resp.results()[0].as_uint32();
  }
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = mWritableVariableId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Both;

    auto resp = mSession->attributes().read_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_EQ(resp.results()[0].value().as<int32_t>(), writeVal);
  }

  // ---- Step 4: Close session and channel ----
  // (handled by ComplianceWithSession::TearDown, but we verify explicit close works)
  auto sessionCloseResult = mSession->try_close_sync();
  EXPECT_THAT(sessionCloseResult, ::ua::test_helpers::Good())
    << "Session close failed: 0x" << std::hex << sessionCloseResult.status_code().as_uint32();
  mSession.reset();  // prevent TearDown from double-closing

  auto channelCloseResult = mChannel->try_close_sync();
  EXPECT_THAT(channelCloseResult, ::ua::test_helpers::Good())
    << "Channel close failed: 0x" << std::hex << channelCloseResult.status_code().as_uint32();
  mChannel.reset();  // prevent TearDown from double-closing
}

// ---------------------------------------------------------------------------
// INT-BACKPRESSURE: incoming-chunk read-pause no-stall (P1.D #1 server + client C2)
//
// Both peers get the tightest possible incoming-chunk cap (1), so EVERY received message drives a
// pause_reads()/resume_reads() call pair across the SecureChannel<->ConnectionProtocol interface (push hits
// the cap -> pause; the immediate drain drops below it -> resume). The OPN, CreateSession,
// ActivateSession, and each Read therefore exercise the backpressure wiring on both the server
// (inbound requests) and the client (inbound responses). If the SecureChannel fails to issue its
// resume - the wiring bug this guards against - the channel stays read-paused and the handshake or a
// subsequent read stalls until timeout. End-to-end no-stall guard; the deferral mechanism it drives
// is unit-tested deterministically in ConnectionProtocolTests.PauseReadsWithholdsNextHeaderReadUntilResume.
// ---------------------------------------------------------------------------
TEST(IncomingChunkBackpressureIntegration, ReadPauseResumeKeepsDataFlowing)
{
  TestServer server;
  server.create([](ua::server::ServerConfig& cfg) { cfg.resourceLimits.incomingChunkQueueDepth = 1; });

  ServerEndpointConfig endpoint;
  endpoint.name = "None";
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  endpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  auto listener = server.listen_ephemeral();
  server.add_endpoint(listener, endpoint);
  server.start();

  auto urls = server.server().advertised_urls(listener);
  ASSERT_FALSE(urls.empty());
  const auto endpointUrl = urls.front().str();

  boost::asio::thread_pool clientPool;
  // create_test_client_config, not a default ApplicationConfig: a Client refuses to create a
  // Session over an unsecured channel unless the application opts in, and this fixture drives a None
  // endpoint.
  auto clientCfg = ua::test_utils::create_test_client_config();
  clientCfg.client.incomingChunkQueueDepth = 1;

  std::optional<Client> client;
  client.emplace(Client::create(clientPool.executor(),
    std::move(clientCfg),
    ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()}));

  {
    auto channel = client->core().open_channel_sync({.endpointUrl = endpointUrl});
    ASSERT_TRUE(channel.is_open());
    auto session = channel.create_session_sync({.sessionName = "Backpressure"});
    session.activate_sync();
    ASSERT_TRUE(session.is_active());

    // A run of reads. With cap=1 on both ends each read drives a full pause->drain->resume cycle on the
    // server (request) and the client (response). All must succeed; a broken resume stalls here.
    for (int i = 0; i < 20; ++i)
    {
      ReadRequest req;
      ReadValueId rv;
      rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
      rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
      req.nodes_to_read().push_back(std::move(rv));
      req.timestamps_to_return() = TimestampsToReturn::Both;

      auto resp = session.attributes().read_sync(std::move(req));
      ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood()) << "read " << i << " failed or stalled";
      ASSERT_EQ(resp.results().size(), 1u);
      EXPECT_FALSE(resp.results()[0].status().has_value());
    }

    session.close_sync();
    channel.close_sync();
  }

  client.reset();
  ::ua::test_utils::stop_pool_in_teardown(clientPool, "client");
}
