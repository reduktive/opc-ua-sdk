// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "compliance_helpers.h"

#include "ua_attribute_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server_state.h"
#include "ua_session_attribute_services.h"
#include "ua_server_status_data_type.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"

#include <thread>

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class ShutdownIntegrationTest : public ComplianceBase
{
protected:
  void open_session()
  {
    mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ShutdownTest"}));
    mSession->activate_sync();
  }

  static ReadValueId make_read(NodeId nodeId, AttributeId attr)
  {
    ReadValueId rv;
    rv.node_id() = std::move(nodeId);
    rv.attribute_id() = static_cast<uint32_t>(attr);
    return rv;
  }

  Result<ReadResponse> try_read_value(const NodeId& nodeId)
  {
    ReadRequest req;
    req.timestamps_to_return() = TimestampsToReturn::Neither;
    req.nodes_to_read().push_back(make_read(nodeId, AttributeId::Value));
    return mSession->attributes().try_read_sync(std::move(req));
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ---------------------------------------------------------------------------
// Test: Client reads shutdown state after shutdown is initiated
// ---------------------------------------------------------------------------

TEST_F(ShutdownIntegrationTest, ClientReadsShutdownStateAfterShutdownInitiated)
{
  open_session();

  // Verify session works before shutdown.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus_State});
    ASSERT_TRUE(result.is_good()) << "Pre-shutdown read failed: 0x" << std::hex
                                  << result.status_code().as_uint32();
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].value().is_int32());
    EXPECT_EQ(resp.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));
  }

  // Initiate shutdown with a long grace period so we can still read.
  ShutdownOptions params;
  params.grace = std::chrono::seconds{10};
  params.reason = LocalizedText{"en", "Test shutdown"};
  mServer.server().shutdown_async(std::move(params), [](VoidResult) {});

  // Give the server a moment to transition to Shutdown state.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // After shutdown initiated: state should be Shutdown.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus_State});
    ASSERT_TRUE(result.is_good()) << "Post-shutdown State read failed: 0x" << std::hex
                                  << result.status_code().as_uint32();
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].value().is_int32());
    EXPECT_EQ(resp.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Shutdown));
  }

  // SecondsTillShutdown should be > 0.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus_SecondsTillShutdown});
    ASSERT_TRUE(result.is_good());
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].value().is_uint32());
    EXPECT_GT(resp.results()[0].value().as<uint32_t>(), 0u);
  }

  // ShutdownReason should contain the provided text.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus_ShutdownReason});
    ASSERT_TRUE(result.is_good());
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].value().is_localized_text());
    EXPECT_EQ(std::string{resp.results()[0].value().as<LocalizedText>().text()}, "Test shutdown");
  }

  // Clean up session and channel before fixture teardown.
  mSession->try_close_sync();
  mSession.reset();
  mChannel->try_close_sync();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Test: ServerStatus aggregate reflects shutdown
// ---------------------------------------------------------------------------

TEST_F(ShutdownIntegrationTest, ServerStatusAggregateReflectsShutdown)
{
  open_session();

  // Read aggregate ServerStatus before shutdown.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus});
    ASSERT_TRUE(result.is_good()) << "Pre-shutdown aggregate read failed: 0x" << std::hex
                                  << result.status_code().as_uint32();
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].value().is_structure());
    auto* status = resp.results()[0].value().try_as<ServerStatusDataType>();
    ASSERT_NE(status, nullptr);
    EXPECT_EQ(status->state(), ServerState::Running);
  }

  // Initiate shutdown.
  ShutdownOptions params;
  params.grace = std::chrono::seconds{10};
  params.reason = LocalizedText{"en", "Aggregate test"};
  mServer.server().shutdown_async(std::move(params), [](VoidResult) {});

  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // Read aggregate ServerStatus after shutdown initiated.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus});
    ASSERT_TRUE(result.is_good());
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].value().is_structure());
    auto* status = resp.results()[0].value().try_as<ServerStatusDataType>();
    ASSERT_NE(status, nullptr);
    EXPECT_EQ(status->state(), ServerState::Shutdown);
    EXPECT_GT(status->seconds_till_shutdown(), 0u);
    EXPECT_EQ(std::string{status->shutdown_reason().text()}, "Aggregate test");
  }

  mSession->try_close_sync();
  mSession.reset();
  mChannel->try_close_sync();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Test: New session rejected during shutdown
// ---------------------------------------------------------------------------

TEST_F(ShutdownIntegrationTest, NewSessionRejectedDuringShutdown)
{
  // Open channel only (no session).
  mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));

  // Initiate shutdown.
  ShutdownOptions params;
  params.grace = std::chrono::seconds{10};
  params.reason = LocalizedText{"en", "Reject session test"};
  mServer.server().shutdown_async(std::move(params), [](VoidResult) {});

  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // Try to create a session - should be rejected.
  auto sessionResult = mChannel->try_create_session_sync({.sessionName = "ShouldFail"});
  EXPECT_TRUE(sessionResult.is_bad())
    << "Expected session creation to fail during shutdown, but it succeeded";

  mChannel->try_close_sync();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Test: Shutdown completes and disconnects clients
// ---------------------------------------------------------------------------

TEST_F(ShutdownIntegrationTest, ShutdownCompletesAndDisconnectsClients)
{
  open_session();

  // Verify session works before shutdown.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServerStatus_State});
    ASSERT_TRUE(result.is_good()) << "Pre-shutdown read failed: 0x" << std::hex
                                  << result.status_code().as_uint32();
  }

  // Synchronous shutdown with 1-second grace period. Blocks until complete.
  mServer.server().shutdown_sync(
    ShutdownOptions{.grace = std::chrono::seconds{1}, .reason = LocalizedText{"en", "Disconnect test"}});

  // After shutdown_sync returns, the server has closed all sessions and channels.
  // A read attempt should fail.
  auto readResult = try_read_value(NodeId{VariableId::Server_ServerStatus_State});
  EXPECT_TRUE(readResult.is_bad()) << "Expected read to fail after shutdown, but it succeeded";

  // Session and channel are dead server-side; just reset our handles.
  mSession.reset();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Test: ServiceLevel reads zero during shutdown
// ---------------------------------------------------------------------------

TEST_F(ShutdownIntegrationTest, ServiceLevelReadsZeroDuringShutdown)
{
  open_session();

  // Before shutdown: ServiceLevel should be 255 (healthy).
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServiceLevel});
    ASSERT_TRUE(result.is_good()) << "Pre-shutdown ServiceLevel read failed: 0x" << std::hex
                                  << result.status_code().as_uint32();
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].value().is_uint8());
    EXPECT_EQ(resp.results()[0].value().as<uint8_t>(), 255u);
  }

  // Initiate shutdown.
  ShutdownOptions params;
  params.grace = std::chrono::seconds{10};
  params.reason = LocalizedText{"en", "ServiceLevel test"};
  mServer.server().shutdown_async(std::move(params), [](VoidResult) {});

  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // During shutdown: ServiceLevel should be 0.
  {
    auto result = try_read_value(NodeId{VariableId::Server_ServiceLevel});
    ASSERT_TRUE(result.is_good());
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].value().is_uint8());
    EXPECT_EQ(resp.results()[0].value().as<uint8_t>(), 0u);
  }

  mSession->try_close_sync();
  mSession.reset();
  mChannel->try_close_sync();
  mChannel.reset();
}
