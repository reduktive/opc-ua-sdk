// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7: Subscription Service Set - Compliance Integration Tests
///
/// Tests covering Part 4 Subscription requirements (SVC-CreateSub-*, SVC-ModSub-*,
/// SVC-SetPubMode-*, SVC-Publish-*, SUB-GEN-*, SVC-Republish-*, SVC-DeleteSub-*,
/// SVC-TransferSub-*).
///
/// These tests exercise the full client->server->client round-trip for subscription
/// lifecycle, monitored item notifications, publish/republish, and deletion.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "sanitizer_budget.h"
#include "subscription.h"

#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"

#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_variable_id.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_notification_message.h"
#include "ua_data_change_notification.h"
#include "ua_monitored_item_notification.h"
#include "ua_status_change_notification.h"
#include "ua_server_configuration.h"
#include "ua_to_string.h"

#include <chrono>
#include <future>
#include <set>
#include <thread>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

// ===========================================================================
// Fixture: ComplianceSubscriptionLimited - constrained subscription limits
// ===========================================================================
class ComplianceSubscriptionLimited : public ::testing::Test
{
protected:
  void SetUp() override
  {

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    server::ServerConfig serverCfg;
    serverCfg.server_capabilities().maxSubscriptionsPerSession = mMaxSubscriptionsPerSession;
    serverCfg.subscriptionLimits.maxPublishRequestsPerSession = mMaxPublishRequestsPerSession;
    // 0 leaves the server default (10000) in place, which no test can reach. A derived fixture
    // lowers it when the server-wide MonitoredItem budget itself is the thing being observed.
    if (mMaxMonitoredItemsServerWide != 0)
      serverCfg.server_capabilities().maxMonitoredItems = mMaxMonitoredItemsServerWide;

    server::CreateConfig createCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    auto logSink = test_log_sink();
    mServer.emplace(server::Server::create(mServerThreadPool.executor(),
      std::move(createCfg),
      server::ServerComponents{.crypto = ua::test_helpers::test_crypto(),
        .authenticator = std::make_shared<AnonymousAuthenticator>(),
        .roleConfiguration = RoleConfiguration::from_well_known_grants(
          {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}}),
        .logSink = logSink,
        .logLevel = LogLevel::Debug}));

    // Listen + start.
    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, endpoint);

    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // Create a writable test variable for tests that need data-change notifications.
    auto addressSpace = mServer->address_space();
    mNamespace = default_ns::Namespace::create("urn:test:sub-limited", mServerThreadPool.executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mNamespace);

    // This fixture stands up its own server instead of deriving from ComplianceBase, so the grant
    // ComplianceBase performs in its SetUp never runs here. A namespace that declares no permissions
    // publishes an ENGAGED, EMPTY default and refuses every undecorated node it owns, which surfaces as
    // BadUserAccessDenied on nodes this fixture itself just created. The helper skips any namespace that
    // already declares permissions, so it cannot grant away a subject under test.
    grant_fixture_namespace_permissions(addressSpace);

    mVariableId = NodeId{mNamespaceIndex, uint32_t{5000}};
    auto varNode = addressSpace.create_node_sync(mVariableId, NodeClass::Variable);
    auto variable = varNode.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mNamespaceIndex, "SubLimitedVar"});
    variable->set_display_name(LocalizedText{"", "SubLimitedVar"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mVariableId);

    // Client.
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));

    mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceSubLimited"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    // The namespace owns a SamplingEngine with periodic bucket timers; drop it before
    // stopping the pool so those timers cancel and the io_context can drain.
    mNamespace.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
  }

  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::optional<server::Server> mServer;
  server::ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;

  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mNamespaceIndex{0};
  NodeId mVariableId;

  uint32_t mMaxSubscriptionsPerSession{2};
  uint32_t mMaxPublishRequestsPerSession{2};
  uint32_t mMaxMonitoredItemsServerWide{0};
};

// ===========================================================================
// CreateSubscription tests (SVC-CreateSub-*)
// ===========================================================================

/// SVC-CreateSub-001: If client sends illegal values (0 lifetime, 0 keepAlive),
/// the server shall revise them, not return an error.
// Covers SVR-SUB-GEN-115 (coverage-audit retag).
// @relation(AC-SVR-SUB-GEN-115-REVISABLE-NO-ERROR, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SVC_CreateSub_001_IllegalValuesRevisedNotError)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 0, .keepAliveCount = 0}));

  EXPECT_NE(resp.subscription_id(), 0u);
  EXPECT_THAT(resp, ServiceResultIsGood());
  // Server must revise 0 values to something non-zero.
  EXPECT_GT(resp.revised_lifetime_count(), 0u);
  EXPECT_GT(resp.revised_max_keep_alive_count(), 0u);
}

/// SVC-CreateSub-002: Requesting interval=0 => revised to fastest supported.
TEST_F(ComplianceWithNodes, SVC_CreateSub_002_ZeroIntervalRevisedToFastest)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 0.0}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_NE(resp.subscription_id(), 0u);
  // Revised interval should be >= 0 (the server's minimum, which is typically > 0).
  EXPECT_GE(resp.revised_publishing_interval(), 0.0);
}

/// SVC-CreateSub-002b: Requesting negative interval => revised to fastest supported.
TEST_F(ComplianceWithNodes, SVC_CreateSub_002_NegativeIntervalRevisedToFastest)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = -1.0}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_NE(resp.subscription_id(), 0u);
  EXPECT_GE(resp.revised_publishing_interval(), 0.0);
}

/// SVC-CreateSub-003: If lifetime < 3*keepAlive, server revises lifetime upward.
// @relation(SVR-SUB-GEN-034, scope=function)
TEST_F(ComplianceWithNodes, SVC_CreateSub_003_LifetimeMinThreeTimesKeepAlive)
{
  // Request lifetime=5, keepAlive=10 => lifetime < 3*10=30, must be revised up.
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 5, .keepAliveCount = 10}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GE(resp.revised_lifetime_count(), 3 * resp.revised_max_keep_alive_count());
}

/// SVC-CreateSub-005: Requesting keepAlive=0 => revised to smallest supported.
// @relation(SVR-SUB-GEN-114, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SVC_CreateSub_005_ZeroKeepAliveRevisedToSmallest)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 30, .keepAliveCount = 0}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GT(resp.revised_max_keep_alive_count(), 0u);
}

/// SVC-CreateSub-006: maxNotificationsPerPublish=0 means no limit; subscription creates OK.
TEST_F(ComplianceWithNodes, SVC_CreateSub_006_ZeroMaxNotificationsNoLimit)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.maxNotificationsPerPublish = 0}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_NE(resp.subscription_id(), 0u);
}

/// SVC-CreateSub-007: Subscription IDs are unique across the server.
TEST_F(ComplianceWithNodes, SVC_CreateSub_007_SubscriptionIdUniqueAcrossServer)
{
  auto resp1 = mSession->subscriptions().create_subscription_sync(build_subscription_request());
  auto resp2 = mSession->subscriptions().create_subscription_sync(build_subscription_request());

  EXPECT_THAT(resp1, ServiceResultIsGood());
  EXPECT_THAT(resp2, ServiceResultIsGood());
  EXPECT_NE(resp1.subscription_id(), 0u);
  EXPECT_NE(resp2.subscription_id(), 0u);
  EXPECT_NE(resp1.subscription_id(), resp2.subscription_id());
}

/// SVC-CreateSub-010: Revised lifetime must be >= 3 * revised keepAlive.
TEST_F(ComplianceWithNodes, SVC_CreateSub_010_RevisedLifetimeMinThreeTimesKeepAlive)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 100, .keepAliveCount = 10}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GE(resp.revised_lifetime_count(), 3 * resp.revised_max_keep_alive_count());
}

/// Basic CreateSubscription succeeds with valid parameters.
TEST_F(ComplianceWithNodes, CreateSubscription_Success)
{
  auto resp = mSession->subscriptions().create_subscription_sync(build_subscription_request());

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_NE(resp.subscription_id(), 0u);
  EXPECT_GT(resp.revised_publishing_interval(), 0.0);
  EXPECT_GT(resp.revised_lifetime_count(), 0u);
  EXPECT_GT(resp.revised_max_keep_alive_count(), 0u);
}

/// Exceeding max subscriptions per session returns BadTooManySubscriptions.
// @relation(SVR-SUB-GEN-116, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceSubscriptionLimited, CreateSubscription_BadTooManySubscriptions)
{
  // Create up to the limit.
  for (uint32_t i = 0; i < mMaxSubscriptionsPerSession; ++i)
  {
    auto resp = mSession->subscriptions().create_subscription_sync(build_subscription_request());
    EXPECT_THAT(resp, ServiceResultIsGood())
      << "Sub " << i << " failed: " << to_string(resp.response_header().service_result());
  }

  // One more should fail.
  auto result = mSession->subscriptions().try_create_subscription_sync(build_subscription_request());
  if (result.is_good())
  {
    // Service succeeded but check the service result in the response header.
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadTooManySubscriptions});
  }
  else
  {
    // The try_ variant returned a bad result - that's also acceptable.
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManySubscriptions});
  }
}

// ===========================================================================
// ModifySubscription tests (SVC-ModSub-*)
// ===========================================================================

/// SVC-ModSub-001: Modifying with bad values (0 lifetime, 0 keepAlive) revises, no error.
TEST_F(ComplianceWithNodes, SVC_ModSub_001_IllegalValuesRevisedNotError)
{
  auto subId = create_subscription(*mSession);

  ModifySubscriptionRequest req;
  req.subscription_id() = subId;
  req.requested_publishing_interval() = 100.0;
  req.requested_lifetime_count() = 0;
  req.requested_max_keep_alive_count() = 0;
  req.max_notifications_per_publish() = 0;
  auto resp = mSession->subscriptions().modify_subscription_sync(std::move(req));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GT(resp.revised_lifetime_count(), 0u);
  EXPECT_GT(resp.revised_max_keep_alive_count(), 0u);
}

/// SVC-ModSub-003: Modifying with interval=0 => revised to fastest supported.
TEST_F(ComplianceWithNodes, SVC_ModSub_003_ZeroIntervalRevised)
{
  auto subId = create_subscription(*mSession);

  ModifySubscriptionRequest req;
  req.subscription_id() = subId;
  req.requested_publishing_interval() = 0.0;
  req.requested_lifetime_count() = 30;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;
  auto resp = mSession->subscriptions().modify_subscription_sync(std::move(req));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GE(resp.revised_publishing_interval(), 0.0);
}

/// SVC-ModSub-004: If lifetime < 3*keepAlive, server revises lifetime upward.
TEST_F(ComplianceWithNodes, SVC_ModSub_004_LifetimeMinThreeTimesKeepAlive)
{
  auto subId = create_subscription(*mSession);

  ModifySubscriptionRequest req;
  req.subscription_id() = subId;
  req.requested_publishing_interval() = 100.0;
  req.requested_lifetime_count() = 5;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;
  auto resp = mSession->subscriptions().modify_subscription_sync(std::move(req));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GE(resp.revised_lifetime_count(), 3 * resp.revised_max_keep_alive_count());
}

/// SVC-ModSub-006: Modifying with keepAlive=0 => revised.
TEST_F(ComplianceWithNodes, SVC_ModSub_006_ZeroKeepAliveRevised)
{
  auto subId = create_subscription(*mSession);

  ModifySubscriptionRequest req;
  req.subscription_id() = subId;
  req.requested_publishing_interval() = 100.0;
  req.requested_lifetime_count() = 30;
  req.requested_max_keep_alive_count() = 0;
  req.max_notifications_per_publish() = 0;
  auto resp = mSession->subscriptions().modify_subscription_sync(std::move(req));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GT(resp.revised_max_keep_alive_count(), 0u);
}

/// ModifySubscription succeeds and changes parameters.
TEST_F(ComplianceWithNodes, ModifySubscription_Success)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 200.0});

  ModifySubscriptionRequest req;
  req.subscription_id() = subId;
  req.requested_publishing_interval() = 500.0;
  req.requested_lifetime_count() = 60;
  req.requested_max_keep_alive_count() = 20;
  req.max_notifications_per_publish() = 100;
  auto resp = mSession->subscriptions().modify_subscription_sync(std::move(req));

  EXPECT_THAT(resp, ServiceResultIsGood());
  // Revised interval should be >= what we asked (server may revise up but not below min).
  EXPECT_GE(resp.revised_publishing_interval(), 100.0);
}

/// ModifySubscription with invalid subscription ID returns error.
// @relation(SVR-SUB-GEN-118, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, ModifySubscription_BadSubscriptionIdInvalid)
{
  ModifySubscriptionRequest req;
  req.subscription_id() = 99999;
  req.requested_publishing_interval() = 100.0;
  req.requested_lifetime_count() = 30;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;

  auto result = mSession->subscriptions().try_modify_subscription_sync(std::move(req));
  if (result.is_good())
  {
    EXPECT_EQ(
      result.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// ===========================================================================
// SetPublishingMode tests (SVC-SetPubMode-*)
// ===========================================================================

/// SVC-SetPubMode-001a: Enable publishing => data notifications flow.
TEST_F(ComplianceWithNodes, SVC_SetPubMode_001_EnablePublishing)
{
  // Create subscription disabled with monitored item, then enable it.
  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {.publishingEnabled = false});

  // Enable publishing.
  set_publishing_mode(*mSession, subId, /*enabled=*/true);

  // Write a value to trigger data change.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{123}});

  // Publish should return a notification for our subscription with a valid seq number.
  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected a Publish response for subscription " << subId;
  EXPECT_EQ(pubResp->subscription_id(), subId);
  // The notification_data should contain something (initial value or data change).
  // At minimum the sequence number should be valid.
  EXPECT_GE(pubResp->notification_message().sequence_number(), 1u);
}

/// SVC-SetPubMode-001b: Disable publishing => no data change notifications.
TEST_F(ComplianceWithNodes, SVC_SetPubMode_001_DisablePublishing)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Consume the initial data change notification.
  drain_initial_publish(*mSession, subId);

  // Disable publishing.
  set_publishing_mode(*mSession, subId, /*enabled=*/false);

  // Write a value - this should NOT generate a data change notification while disabled.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{999}});

  // The next publish should be a keep-alive (empty notification_data). Use the
  // wait_for_publish primitive so we can assert directly on notification_data,
  // which wait_for_data_change would discard.
  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected a Publish response for subscription " << subId;
  // Per SVC-SetPubMode-001 / SVR-SUB-GEN-022: disabling publishing stops NotificationMessages.
  // The response should be a keep-alive with empty notification_data.
  EXPECT_TRUE(pubResp->notification_message().notification_data().empty())
    << "Publishing is disabled - notification_data should be empty (keep-alive)";
}

/// SVC-SetPubMode-003: Disabled publishing still sends keep-alives.
TEST_F(ComplianceWithNodes, SVC_SetPubMode_003_DisableStillSendsKeepAlives)
{
  auto subId = create_subscription(*mSession);

  // Disable publishing.
  set_publishing_mode(*mSession, subId, /*enabled=*/false);

  // Publish should still return a keep-alive (empty notification_data). Use
  // wait_for_publish so we retain the response and can assert on notification_data.
  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected a keep-alive Publish response for subscription " << subId;
  // Keep-alive message: notification_data should be empty.
  EXPECT_TRUE(pubResp->notification_message().notification_data().empty());
}

/// SetPublishingMode with empty subscription_ids list => BadNothingToDo.
TEST_F(ComplianceWithNodes, SetPublishingMode_BadNothingToDo)
{
  SetPublishingModeRequest req;
  req.publishing_enabled() = true;
  // No subscription IDs.

  auto result = mSession->subscriptions().try_set_publishing_mode_sync(std::move(req));
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNothingToDo});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

/// SetPublishingMode with invalid subscription ID => per-result BadSubscriptionIdInvalid.
// @relation(SVR-SUB-GEN-120, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SetPublishingMode_BadSubscriptionIdInvalid)
{
  SetPublishingModeRequest req;
  req.publishing_enabled() = true;
  req.subscription_ids().push_back(99999);
  auto result = mSession->subscriptions().try_set_publishing_mode_sync(std::move(req));

  // Per Table 94: Bad_SubscriptionIdInvalid is an operation-level result.
  // Service result should be Good; per-item result should carry the error.
  if (result.is_good())
  {
    auto& resp = result.value();
    EXPECT_TRUE(resp.response_header().service_result().is_good())
      << "Bad_SubscriptionIdInvalid is operation-level, not service-level: "
      << to_string(resp.response_header().service_result());
    ASSERT_FALSE(resp.results().empty());
    EXPECT_EQ(resp.results()[0], StatusCode{Status::BadSubscriptionIdInvalid});
  }
  else
  {
    // SDK extracted the error - acceptable transport-level behavior.
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// ===========================================================================
// Publish tests (SVC-Publish-*, SUB-GEN-*)
// ===========================================================================

/// SVR-SUB-GEN-002: Publishing happens at the revised interval (publishes arrive).
// @relation(SVR-SUB-GEN-002, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_002_RevisedIntervalHonoured)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Write value to trigger a data change.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{77}});

  auto notif = wait_for_data_change(*mSession, subId);
  EXPECT_TRUE(notif) << "Expected a DataChangeNotification for subscription " << subId;
}

/// DataChange notifications are paced by the publishing interval, not produced on
/// every sample / every Publish request. With continuous changes faster than the
/// publishing interval, the number of data-bearing Publish responses over a window
/// must track window/interval (not the change/poll rate). Mirrors UACTT Subscription
/// Basic 054 ("verify scanrates yield an expected number of dataChanges"), which the
/// pre-fix server failed by answering every Publish out-of-band (136 vs 10).
// Covers SVR-SUB-GEN-002 (publishing-interval pacing).
TEST_F(ComplianceWithNodes, SVC_Publish_DataChangesPacedByPublishingInterval)
{
  constexpr double intervalMs = 200.0;
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession,
    mWritableVariableId,
    {.publishingInterval = intervalMs, .lifetimeCount = 100, .keepAliveCount = 20},
    {.samplingInterval = 0.0});

  // For ~1s, write a fresh value then poll once. With pacing, each poll blocks
  // until the next publishing tick (~200ms) before data is delivered, so ~5
  // data-bearing responses arrive. The pre-fix server returned data on every poll
  // immediately, producing many more.
  int dataResponses = 0;
  int32_t value = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{1000};
  while (std::chrono::steady_clock::now() < deadline)
  {
    write_value_async(*mSession, mWritableVariableId, Variant{value++});
    auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
    if (!resp.notification_message().notification_data().empty())
      ++dataResponses;
  }

  // ~1000/200 = 5 expected. A generous ceiling still separates paced delivery from
  // the pre-fix per-poll delivery (which produced tens).
  EXPECT_LE(dataResponses, 12) << "dataChanges not paced by the publishing interval (got " << dataResponses
                               << ")";
  EXPECT_GE(dataResponses, 2) << "no forward progress under continuous change";
}

/// Any non-Publish Service call referencing the SubscriptionId resets the
/// subscription's lifetime counter (Part 4 section 5.13.1.1 h), keeping it alive without
/// Publish traffic; once the calls stop it expires. Mirrors UACTT Subscription
/// Basic 063 - including the subtle case of a Republish for an UNKNOWN sequence
/// number (the exact call 063 makes), which must still reset the lifetime even
/// though it returns Bad_MessageNotAvailable.
// Covers SUB-GEN (lifetime reset on service call).
TEST_F(ComplianceWithNodes, SVC_CreateSub_ServiceCallsExtendLifetime)
{
  // Short lifetime + fast interval -> unmanaged expiry ~ 5 * 50ms = 250ms.
  uint32_t subId =
    create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 5, .keepAliveCount = 1});

  auto republishStatus = [&]() -> StatusCode
  {
    RepublishRequest req;
    req.subscription_id() = subId;
    req.retransmit_sequence_number() = 0;  // unknown -> Bad_MessageNotAvailable if alive
    auto result = mSession->subscriptions().try_republish_sync(std::move(req));
    return result.is_good() ? result.value().response_header().service_result() : result.status_code();
  };

  // Issue a Republish every ~100ms for ~700ms - far longer than the 250ms
  // unmanaged lifetime. Each call must reset the lifetime, so the subscription is
  // still known (Bad_MessageNotAvailable), never Bad_SubscriptionIdInvalid.
  for (int i = 0; i < 7; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    EXPECT_NE(republishStatus(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "subscription expired despite service calls at iteration " << i;
  }

  // Stop issuing calls: with no Publish traffic and no service calls, the lifetime
  // counter now runs out and the subscription is deleted.
  std::this_thread::sleep_for(std::chrono::milliseconds{1500});
  EXPECT_EQ(republishStatus(), StatusCode{Status::BadSubscriptionIdInvalid})
    << "subscription did not expire after service calls stopped - timer not decrementing";
}

/// SVR-SUB-GEN-014: Exceeding publish queue limit - oldest dequeued.
// @relation(SVR-SUB-GEN-014, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceSubscriptionLimited, SUB_GEN_014_BadTooManyPublishRequests)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 5000.0}));
  ASSERT_THAT(resp, ServiceResultIsGood());

  // Queue more Publish requests than the limit.
  // We use async calls to queue them without blocking.
  // promises must be heap-allocated: the lambdas may fire during session teardown
  // after this stack frame has returned (stack-use-after-return otherwise).
  using PubResult = SessionSubscriptionServices::PublishResponseResult;
  auto promises = std::make_shared<std::vector<std::promise<PubResult>>>(mMaxPublishRequestsPerSession + 1);
  std::vector<std::future<PubResult>> futures;
  for (auto& p : *promises)
    futures.push_back(p.get_future());

  for (uint32_t i = 0; i <= mMaxPublishRequestsPerSession; ++i)
  {
    mSession->subscriptions().publish_async(PublishRequest{},
      [promises, i](PubResult result) mutable { (*promises)[i].set_value(std::move(result)); });
  }

  // The first queued publish (oldest) should get a BadTooManyPublishRequests response
  // or be dequeued. Give it a moment to process.
  auto status = futures[0].wait_for(std::chrono::seconds(5));
  ASSERT_EQ(status, std::future_status::ready)
    << "Oldest Publish request should have been dequeued and returned within 5 seconds";

  {
    auto result = futures[0].get();
    // Per SVR-SUB-GEN-014 / SVC-Publish-004: the oldest Publish request SHALL be
    // dequeued and returned with Bad_TooManyPublishRequests.
    if (result.is_good())
    {
      EXPECT_EQ(
        result.value().response_header().service_result(), StatusCode{Status::BadTooManyPublishRequests});
    }
    else
    {
      EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyPublishRequests});
    }
  }
}

/// SVR-SUB-GEN-020: When no data changes, keep-alive is sent with empty notification_data.
// @relation(SVR-SUB-GEN-020, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_020_KeepAliveAfterMaxCount)
{
  // Create subscription with short keep-alive.
  auto subId = create_subscription(*mSession, {.keepAliveCount = 1});

  // No monitored items = no data changes. First publish should be a keep-alive.
  // Use the wait_for_publish primitive so we keep the response and can assert
  // directly on notification_data().empty().
  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected a keep-alive Publish response for subscription " << subId;
  // Keep-alive: notification_data is empty.
  EXPECT_TRUE(pubResp->notification_message().notification_data().empty());
}

/// SVR-SUB-GEN-021: Keep-alive has the next expected sequence number.
// @relation(SVR-SUB-GEN-021, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_021_KeepAliveHasNextSequenceNumber)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // First publish - initial data change.
  auto pub1 = mSession->subscriptions().publish_sync(PublishRequest{});
  EXPECT_THAT(pub1, ServiceResultIsGood());
  auto seq1 = pub1.notification_message().sequence_number();

  // Acknowledge the first.
  acknowledge(*mSession, subId, seq1);

  // Next publish should be keep-alive or data change with seq1+1.
  // Use wait_for_publish so we can inspect notification_message().sequence_number().
  auto pub2 =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pub2) << "Expected a follow-up Publish response for subscription " << subId;
  auto seq2 = pub2->notification_message().sequence_number();
  EXPECT_EQ(seq2, seq1 + 1);
}

/// SVR-SUB-GEN-030, SVR-SUB-GEN-032: Lifetime counter expiry - subscription closed when lifetime
/// counter reaches the value calculated from MaxKeepAliveCount (SVR-SUB-GEN-032). This test
/// uses very short intervals. If the server does not delete the subscription after lifetime
/// expiry, the test documents that gap.
// @relation(SVR-SUB-GEN-030, SVR-SUB-GEN-032, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_030_LifetimeCounterExpiry)
{
  // Create subscription with very short lifetime.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 3, .keepAliveCount = 1}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  auto subId = createResp.subscription_id();
  auto revisedLifetime = createResp.revised_lifetime_count();
  auto revisedInterval = createResp.revised_publishing_interval();

  // Wait for the subscription to expire. Lifetime = lifetime_count * publishing_interval.
  auto expiryMs = static_cast<int64_t>((revisedLifetime + 2) * revisedInterval);
  std::this_thread::sleep_for(std::chrono::milliseconds(expiryMs + 500));

  // Try to modify the subscription - should fail with BadSubscriptionIdInvalid.
  ModifySubscriptionRequest modReq;
  modReq.subscription_id() = subId;
  modReq.requested_publishing_interval() = 100.0;
  modReq.requested_lifetime_count() = 30;
  modReq.requested_max_keep_alive_count() = 10;
  modReq.max_notifications_per_publish() = 0;
  auto modResult = mSession->subscriptions().try_modify_subscription_sync(std::move(modReq));

  if (modResult.is_good())
  {
    EXPECT_EQ(
      modResult.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
  else
  {
    EXPECT_EQ(modResult.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

/// SVR-SUB-GEN-033, SVR-SUB-GEN-100: Lifetime expiry sends a StatusChangeNotification with BadTimeout.
/// Part 4, Row 27: when the lifetime counter reaches zero, the server shall issue a
/// StatusChangeNotification with Bad_Timeout (SVR-SUB-GEN-100) and transition to CLOSED.
// @relation(SVR-SUB-GEN-033, SVR-SUB-GEN-126, scope=function)
// @verifies AC-SVR-SUB-GEN-100-BADTIMEOUT-CODE
TEST_F(ComplianceWithNodes, SUB_GEN_033_StatusChangeNotificationBadTimeout)
{
  // Create subscription with very short lifetime.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 3, .keepAliveCount = 1}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  auto subId = createResp.subscription_id();

  auto revisedLifetime = createResp.revised_lifetime_count();
  auto revisedInterval = createResp.revised_publishing_interval();
  auto expiryMs = static_cast<int64_t>((revisedLifetime + 2) * revisedInterval);

  // Do NOT send any Publish requests - the lifetime counter only decrements
  // when no Publish requests are queued (Part 4, Row 27).
  std::this_thread::sleep_for(std::chrono::milliseconds(expiryMs));

  // After expiry, the next Publish should carry a StatusChangeNotification with
  // BadTimeout. Use wait_for_status_change with a window long enough to cover
  // the publish cadence - expiry has already happened so the SCN should be
  // immediately available.
  auto scn = wait_for_status_change(*mSession, subId, 2s);
  ASSERT_TRUE(scn) << "Server must send StatusChangeNotification with BadTimeout on lifetime expiry";
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout});
}

/// SVR-SUB-GEN-034: Lifetime < 3*keepAlive => revised up.
// @relation(SVR-SUB-GEN-034, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_034_LifetimeRevisedIfTooSmall)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 2, .keepAliveCount = 5}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_GE(resp.revised_lifetime_count(), 3 * resp.revised_max_keep_alive_count());
}

/// SVR-SUB-GEN-040: Consecutive notifications have sequence numbers incrementing by 1.
// @relation(SVR-SUB-GEN-040, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_040_SequenceNumberIncrementsBy1)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // First publish - initial data change. Use wait_for_publish so we retain the
  // full response (we need its sequence_number()).
  auto pub1 =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pub1) << "Expected initial Publish response for subscription " << subId;
  auto seq1 = pub1->notification_message().sequence_number();

  // Ack and trigger another data change.
  acknowledge(*mSession, subId, seq1);
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});

  auto pub2 =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pub2) << "Expected follow-up Publish response for subscription " << subId;
  auto seq2 = pub2->notification_message().sequence_number();
  EXPECT_EQ(seq2, seq1 + 1);
}

/// SVR-SUB-GEN-041: First notification sequence number is >= 1.
// @relation(SVR-SUB-GEN-041, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_041_SequenceNumberNeverZero)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected a Publish response for subscription " << subId;
  EXPECT_GE(pubResp->notification_message().sequence_number(), 1u);
}

/// SVR-SUB-GEN-042: First notification has sequence number 1.
// @relation(AC-SVR-SUB-GEN-042-FIRST-IS-ONE, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_042_FirstNotificationSeqNum1)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected first Publish response for subscription " << subId;
  EXPECT_EQ(pubResp->notification_message().sequence_number(), 1u);
}

/// SVR-SUB-GEN-050: Sent notifications are retained in retransmission queue until acknowledged.
// @relation(SVR-SUB-GEN-050, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_050_RetransmissionQueueMaintained)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Publish without ack. Use wait_for_publish so we keep the available_sequence_numbers().
  auto pub1 =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pub1) << "Expected initial Publish response for subscription " << subId;
  auto seq1 = pub1->notification_message().sequence_number();

  // The available_sequence_numbers should contain seq1.
  bool found = false;
  for (auto seqNum : pub1->available_sequence_numbers())
  {
    if (seqNum == seq1)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Sequence number " << seq1 << " not found in available_sequence_numbers";

  // Republish should succeed for seq1.
  RepublishRequest repReq;
  repReq.subscription_id() = subId;
  repReq.retransmit_sequence_number() = seq1;
  auto repResp = mSession->subscriptions().republish_sync(std::move(repReq));
  EXPECT_THAT(repResp, ServiceResultIsGood());
}

/// SVR-SUB-GEN-070: Subscription IDs are unique across the server.
// @relation(SVR-SUB-GEN-070, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_070_SubscriptionIdServerUnique)
{
  // Same as SVC_CreateSub_007 - two subs get different IDs.
  auto subId1 = create_subscription(*mSession);
  auto subId2 = create_subscription(*mSession);

  EXPECT_NE(subId1, subId2);
}

/// SVR-SUB-GEN-080: First message is sent at end of first publishing cycle.
// @relation(SVR-SUB-GEN-080, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_080_FirstMessageAfterCreate)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected first Publish response for subscription " << subId;
  EXPECT_EQ(pubResp->subscription_id(), subId);
  // First message should have seq >= 1.
  EXPECT_GE(pubResp->notification_message().sequence_number(), 1u);
}

/// SVR-SUB-GEN-090: Multiple queued notifications are sent in queue order.
// @relation(SVR-SUB-GEN-090, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_090_NotificationsInQueueOrder)
{
  // Create subscription + larger queue MI (samplingInterval=0 for tightest cadence).
  auto [subId, miId] = create_subscription_with_monitored_item(
    *mSession, mWritableVariableId, {}, {.samplingInterval = 0.0, .queueSize = 10});

  // Disable publishing so notifications accumulate in the queue without being sent.
  set_publishing_mode(*mSession, subId, false);

  // Write multiple values with delays between each to ensure each write is sampled
  // as a separate queue entry (the SamplingEngine batches ExceptionQueued items on a
  // 10ms timer tick, then posts to the subscription strand).
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{300}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Re-enable publishing and wait for the queued DataChangeNotification.
  set_publishing_mode(*mSession, subId, true);
  auto dcn = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(dcn) << "Expected DataChangeNotification with queued values";
  // Per SVR-SUB-GEN-090: notifications SHALL appear in queue order.
  if (dcn->monitored_items().size() >= 2)
  {
    // Values should be in chronological order.
    // The last value should be the most recent write.
    auto sz = dcn->monitored_items().size();
    auto& lastItem = dcn->monitored_items()[sz - 1];
    EXPECT_EQ(lastItem.value().value().as<int32_t>(), 300);
  }
}

/// SVR-SUB-GEN-092: PublishTime is the time of first transmission.
// @relation(SVR-SUB-GEN-092, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_092_PublishTimeIsFirstSendTime)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto before = UtcTime::now();
  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  auto after = UtcTime::now();

  ASSERT_TRUE(pubResp) << "Expected a Publish response for subscription " << subId;
  auto publishTime = pubResp->notification_message().publish_time();
  // PublishTime should be between before and after (roughly).
  EXPECT_GE(publishTime, before);
  EXPECT_LE(publishTime, after);
}

/// SVC-Publish-002: Publish requests are not directed to a specific subscription -
/// they serve any subscription that has notifications.
// @relation(SVR-SUB-GEN-010, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SVC_Publish_002_NotDirectedToSubscription)
{
  // Create two subscriptions.
  auto [subId1, miId1] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);
  auto subId2 = create_subscription(*mSession);

  // Publish should return for whichever subscription has data.
  auto pubResp = wait_for_publish(*mSession,
    [subId1, subId2](const PublishResponse& r)
    { return r.subscription_id() == subId1 || r.subscription_id() == subId2; });
  ASSERT_TRUE(pubResp) << "Expected a Publish response for one of the subscriptions";
  EXPECT_TRUE(pubResp->subscription_id() == subId1 || pubResp->subscription_id() == subId2);
}

/// SVC-Publish-011: moreNotifications flag when too many notifications.
TEST_F(ComplianceWithNodes, SVC_Publish_011_MoreNotificationsFlag)
{
  // Create subscription with maxNotificationsPerPublish=1 and MI with queue size > 1.
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession,
    mWritableVariableId,
    {.maxNotificationsPerPublish = 1},
    {.samplingInterval = 0.0, .queueSize = 10});

  // Consume initial notification.
  drain_initial_publish(*mSession, subId);

  // Write multiple values to queue up notifications.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{10}});
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{20}});
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{30}});

  // Short wait for sampling.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Pull the next DataChangeNotification on this subscription. We need the full
  // PublishResponse for more_notifications(), so use wait_for_publish + as_data_change.
  auto pubResp = wait_for_publish(*mSession,
    [subId](const PublishResponse& r)
    { return r.subscription_id() == subId && as_data_change(r) != nullptr; });
  ASSERT_TRUE(pubResp) << "Expected a Publish carrying a DataChangeNotification for sub " << subId;
  // Per SVC-Publish-011: moreNotifications SHALL be TRUE when notifications
  // could not fit in a single response (maxNotificationsPerPublish=1, multiple queued).
  const auto* dcn = as_data_change(*pubResp);
  if (dcn != nullptr && !dcn->monitored_items().empty())
  {
    // If we got notifications but there are more queued, moreNotifications must be true.
    EXPECT_TRUE(pubResp->more_notifications())
      << "moreNotifications should be TRUE when not all notifications fit in one response";
  }
}

/// Publish returns DataChangeNotification when a value changes.
// @relation(SVR-SUB-GEN-011, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, Publish_DataChangeNotification)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Consume initial notification.
  drain_initial_publish(*mSession, subId);

  // Write a new value and wait for the resulting DataChangeNotification.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{555}});

  auto dcn = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(dcn) << "Expected DataChangeNotification after writing a value";
  ASSERT_FALSE(dcn->monitored_items().empty());
  EXPECT_THAT(*dcn, ContainsDataChangeFor(1u, good_value_of<int32_t>(555)));
}

/// Acknowledging a sequence number removes it from available_sequence_numbers.
// @relation(SVR-SUB-GEN-122, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, Publish_AcknowledgeSequenceNumber)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Get first notification (need the raw response for sequence_number).
  auto pub1 =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pub1) << "Expected initial Publish response for subscription " << subId;
  auto seq1 = pub1->notification_message().sequence_number();

  // Acknowledge seq1.
  acknowledge(*mSession, subId, seq1);

  // Next publish for this subscription must no longer list seq1 in
  // available_sequence_numbers.
  auto pub2 =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pub2) << "Expected follow-up Publish response for subscription " << subId;

  for (auto seqNum : pub2->available_sequence_numbers())
  {
    EXPECT_NE(seqNum, seq1) << "Acknowledged sequence number " << seq1
                            << " still in available_sequence_numbers";
  }
}

/// Publish with no subscriptions returns BadNoSubscription.
// @relation(SVR-SUB-GEN-121, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, BadNoSubscription)
{
  // Don't create any subscriptions - just publish.
  auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNoSubscription});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNoSubscription});
  }
}

// ===========================================================================
// Additional SUB-GEN gap closure
// ===========================================================================

/// SVR-SUB-GEN-012: When notifications are ready but no Publish is queued,
/// the server waits and delivers on next Publish.
// @relation(SVR-SUB-GEN-012, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_012_WaitStateWhenNoPublishQueued)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Consume initial notification.
  drain_initial_publish(*mSession, subId);

  // Write a value, but do NOT publish yet - let the notification queue up.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{777}});

  // Wait a bit for the sampling to pick up the change.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  // Now publish - should get the queued data change.
  auto dcn = wait_for_data_change(*mSession, subId);
  EXPECT_TRUE(dcn) << "Expected queued DataChangeNotification to be delivered";
}

/// SVR-SUB-GEN-013: Server accepts more Publish requests than subscriptions.
// @relation(SVR-SUB-GEN-013, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_013_AcceptMorePublishThanSubscriptions)
{
  auto subId = create_subscription(*mSession);

  // Three back-to-back Publish requests for the single subscription must all
  // succeed (keep-alive responses are fine). Use wait_for_publish so we don't
  // block forever on a quirky response.
  for (int i = 0; i < 3; ++i)
  {
    auto pub =
      wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
    EXPECT_TRUE(pub) << "Publish #" << i << " should have returned a response";
  }
}

/// SVR-SUB-GEN-022: Disabled publishing still sends keep-alives.
// @relation(SVR-SUB-GEN-022, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_022_DisabledStillKeepAlive)
{
  auto subId = create_subscription(*mSession, {.keepAliveCount = 1, .publishingEnabled = false});

  // Publish should return keep-alive even though publishing is disabled. Use
  // wait_for_publish so we retain the response for the notification_data assertion.
  auto pubResp =
    wait_for_publish(*mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; });
  ASSERT_TRUE(pubResp) << "Expected a keep-alive Publish response for subscription " << subId;
  // Keep-alive: empty notification_data.
  EXPECT_TRUE(pubResp->notification_message().notification_data().empty());
}

/// SVC-Publish-008: When no subscriptions exist, subscriptionId should be 0 or BadNoSubscription.
TEST_F(ComplianceWithNodes, SVC_Publish_008_SubscriptionIdZeroWhenNone)
{
  auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
  // Per SVC-Publish-008 / Table 96: either BadNoSubscription service error,
  // or a Good response with subscriptionId=0.
  if (result.is_good())
  {
    auto& resp = result.value();
    auto serviceResult = resp.response_header().service_result();
    if (serviceResult.is_good())
    {
      // Per SVC-Publish-008: subscriptionId SHALL be 0 when no subscriptions exist.
      EXPECT_EQ(resp.subscription_id(), 0u);
    }
    else
    {
      EXPECT_EQ(serviceResult, StatusCode{Status::BadNoSubscription});
    }
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNoSubscription});
  }
}

// ===========================================================================
// Republish tests (SVC-Republish-*)
// ===========================================================================

/// SVC-Republish-001: Republish a known sequence number returns the original notification.
TEST_F(ComplianceWithNodes, SVC_Republish_001_RetransmitFromQueue)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pubResp.response_header().service_result().is_good());
  auto seqNum = pubResp.notification_message().sequence_number();

  // Republish the same sequence number.
  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = seqNum;
  auto repResp = mSession->subscriptions().republish_sync(std::move(req));

  EXPECT_TRUE(repResp.response_header().service_result().is_good());
  EXPECT_EQ(repResp.notification_message().sequence_number(), seqNum);
}

/// SVC-Republish-002: Unknown sequence number returns BadMessageNotAvailable.
// @relation(SVR-SUB-GEN-123, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SVC_Republish_002_BadMessageNotAvailable)
{
  auto subId = create_subscription(*mSession);

  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = 99999;  // Non-existent.
  auto result = mSession->subscriptions().try_republish_sync(std::move(req));

  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadMessageNotAvailable});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadMessageNotAvailable});
  }
}

/// SVC-Republish-003: Retransmitted publishTime matches original.
TEST_F(ComplianceWithNodes, SVC_Republish_003_PublishTimeUnchanged)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pubResp.response_header().service_result().is_good());
  auto seqNum = pubResp.notification_message().sequence_number();
  auto originalTime = pubResp.notification_message().publish_time();

  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = seqNum;
  auto repResp = mSession->subscriptions().republish_sync(std::move(req));

  EXPECT_TRUE(repResp.response_header().service_result().is_good());
  EXPECT_EQ(repResp.notification_message().publish_time(), originalTime);
}

/// Republish with invalid subscription ID returns BadSubscriptionIdInvalid.
// @relation(SVR-SUB-GEN-123, scope=function)
TEST_F(ComplianceWithNodes, Republish_BadSubscriptionIdInvalid)
{
  RepublishRequest req;
  req.subscription_id() = 99999;
  req.retransmit_sequence_number() = 1;
  auto result = mSession->subscriptions().try_republish_sync(std::move(req));

  if (result.is_good())
  {
    EXPECT_EQ(
      result.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// ===========================================================================
// DeleteSubscriptions tests (SVC-DeleteSub-*)
// ===========================================================================

/// SVC-DeleteSub-001: Deleting a subscription succeeds.
TEST_F(ComplianceWithNodes, SVC_DeleteSub_001_DeleteSucceeds)
{
  auto subId = create_subscription(*mSession);

  DeleteSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  auto resp = mSession->subscriptions().delete_subscriptions_sync(std::move(req));

  EXPECT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_FALSE(resp.results().empty());
  EXPECT_TRUE(resp.results()[0].is_good());
}

/// SVC-DeleteSub-002: Deleting a subscription deletes its monitored items
/// (no more notifications after deletion).
TEST_F(ComplianceWithNodes, SVC_DeleteSub_002_MonitoredItemsDeleted)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Consume initial notification.
  auto initPub = mSession->subscriptions().publish_sync(PublishRequest{});

  // Delete the subscription.
  DeleteSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  auto delResp = mSession->subscriptions().delete_subscriptions_sync(std::move(req));
  EXPECT_TRUE(delResp.response_header().service_result().is_good());
  ASSERT_FALSE(delResp.results().empty());
  EXPECT_TRUE(delResp.results()[0].is_good());

  // Write a value - no subscription to deliver it.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{888}});

  // Publish should return BadNoSubscription (no subs left).
  auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNoSubscription});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNoSubscription});
  }
}

/// SVC-DeleteSub-003: Deleting the last subscription causes queued Publishes
/// to return BadNoSubscription.
TEST_F(ComplianceWithNodes, SVC_DeleteSub_003_LastSubReturnsNoSubscription)
{
  auto subId = create_subscription(*mSession);

  // Get first publish (keep-alive) to ensure subscription is active.
  auto firstPub = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(firstPub.response_header().service_result().is_good());

  // Delete the last subscription.
  DeleteSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  auto delResp = mSession->subscriptions().delete_subscriptions_sync(std::move(req));
  EXPECT_TRUE(delResp.response_header().service_result().is_good());

  // Next publish should return BadNoSubscription since no subscriptions remain.
  auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
  if (result.is_good())
  {
    auto& resp = result.value();
    auto serviceResult = resp.response_header().service_result();
    if (serviceResult.is_good())
    {
      // If the service result is Good, this must be a StatusChangeNotification
      // for the deleted subscription - verify it.
      auto* scn = as_status_change(resp);
      EXPECT_NE(scn, nullptr) << "After deleting last subscription, a Good Publish response should carry a "
                                 "StatusChangeNotification";
    }
    else
    {
      EXPECT_EQ(serviceResult, StatusCode{Status::BadNoSubscription});
    }
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNoSubscription});
  }
}

/// DeleteSubscriptions with empty list => BadNothingToDo.
// @relation(SVR-SUB-GEN-125, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, DeleteSubscription_BadNothingToDo)
{
  DeleteSubscriptionsRequest req;
  // No subscription IDs.

  auto result = mSession->subscriptions().try_delete_subscriptions_sync(std::move(req));
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNothingToDo});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

/// DeleteSubscriptions with invalid subscription ID => per-result BadSubscriptionIdInvalid.
// @relation(SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, DeleteSubscription_BadSubscriptionIdInvalid)
{
  DeleteSubscriptionsRequest req;
  req.subscription_ids().push_back(99999);

  auto result = mSession->subscriptions().try_delete_subscriptions_sync(std::move(req));
  // Per Table 98: Bad_SubscriptionIdInvalid is an operation-level result.
  if (result.is_good())
  {
    auto& resp = result.value();
    EXPECT_TRUE(resp.response_header().service_result().is_good())
      << "Bad_SubscriptionIdInvalid is operation-level, not service-level: "
      << to_string(resp.response_header().service_result());
    ASSERT_FALSE(resp.results().empty());
    EXPECT_EQ(resp.results()[0], StatusCode{Status::BadSubscriptionIdInvalid});
  }
  else
  {
    // SDK extracted the error - acceptable transport-level behavior.
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// ===========================================================================
// Subscription General Compliance (SUB-GEN-*)
// ===========================================================================

/// SVR-SUB-GEN-001: Publishing interval defines the cyclic rate; each cycle the server
/// attempts to send a NotificationMessage to the client.
/// Bug it catches: Server that never publishes notifications or publishes all at once
/// regardless of interval.
// @relation(SVR-SUB-GEN-001, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_001_PublishingIntervalCyclic)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Consume the initial data change notification.
  auto initPub = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(initPub.response_header().service_result().is_good());
  auto seq0 = initPub.notification_message().sequence_number();

  // Write 3 values with sufficient gaps for the publishing cycle to fire between them.
  std::vector<uint32_t> dataChangeSeqNums;
  for (int32_t val : {100, 200, 300})
  {
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{val}});
    // Sleep long enough for the 100ms publishing cycle to pick up the change.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    PublishRequest ackReq;
    SubscriptionAcknowledgement ack;
    ack.subscription_id() = subId;
    ack.sequence_number() = seq0;
    ackReq.subscription_acknowledgements().push_back(ack);

    auto pub = mSession->subscriptions().publish_sync(std::move(ackReq));
    ASSERT_TRUE(pub.response_header().service_result().is_good());

    auto* dcn = as_data_change(pub);
    if (dcn != nullptr && !dcn->monitored_items().empty())
    {
      dataChangeSeqNums.push_back(pub.notification_message().sequence_number());
    }
    seq0 = pub.notification_message().sequence_number();
  }

  // We should have received at least 2 separate data change notifications,
  // proving the server publishes cyclically (not all batched in one message).
  EXPECT_GE(dataChangeSeqNums.size(), 2u)
    << "Expected multiple separate data change notifications across publishing cycles";

  // Verify sequence numbers are strictly increasing (separate messages).
  for (size_t i = 1; i < dataChangeSeqNums.size(); ++i)
  {
    EXPECT_GT(dataChangeSeqNums[i], dataChangeSeqNums[i - 1])
      << "Sequence numbers should increase across publishing cycles";
  }
}

/// SVR-SUB-GEN-023: If no Publish request is queued when a keep-alive is due, the server
/// defers and responds immediately when the next Publish arrives.
/// Bug it catches: Server that makes a late Publish wait for the next cycle instead of
/// responding immediately with the deferred keep-alive.
// @relation(SVR-SUB-GEN-023, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_023_DeferredKeepAliveOnLatePublish)
{
  // Create subscription with keepAliveCount=1, interval=100ms.
  auto createResp =
    mSession->subscriptions().create_subscription_sync(build_subscription_request({.keepAliveCount = 1}));
  ASSERT_TRUE(createResp.response_header().service_result().is_good());
  auto subId = createResp.subscription_id();
  auto revisedInterval = createResp.revised_publishing_interval();

  // Consume initial keep-alive.
  auto initPub = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(initPub.response_header().service_result().is_good());

  // Do NOT send any Publish for 500ms - multiple keep-alive periods pass.
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // Now send Publish - server has a deferred keep-alive, should respond immediately.
  auto before = std::chrono::steady_clock::now();
  auto pub = mSession->subscriptions().publish_sync(PublishRequest{});
  auto elapsed = std::chrono::steady_clock::now() - before;
  auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

  EXPECT_TRUE(pub.response_header().service_result().is_good());
  EXPECT_EQ(pub.subscription_id(), subId);

  // The response should come back well under one full publishing interval,
  // because the server had a deferred keep-alive ready.
  EXPECT_LT(elapsedMs, static_cast<int64_t>(revisedInterval))
    << "Late Publish should be answered immediately from deferred keep-alive, " << "but took " << elapsedMs
    << "ms (interval=" << revisedInterval << "ms)";
}

/// SVR-SUB-GEN-081: After CreateSubscription, the first Publish should return a keep-alive
/// immediately without waiting for maxKeepAliveCount cycles.
/// Bug it catches: Server that waits the full maxKeepAliveCount x interval before
/// sending the first keep-alive.
// @relation(SVR-SUB-GEN-081, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_081_FirstPublishKeepAliveImmediate)
{
  // Create subscription with a large keepAliveCount so the full wait would be 1000ms.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 10}));
  ASSERT_TRUE(createResp.response_header().service_result().is_good());
  auto subId = createResp.subscription_id();
  auto revisedKeepAlive = createResp.revised_max_keep_alive_count();
  auto revisedInterval = createResp.revised_publishing_interval();

  // The maximum wait if the server incorrectly waits for keepAlive cycles:
  auto maxWaitMs = static_cast<int64_t>(revisedKeepAlive * revisedInterval);

  // Send Publish immediately - should return as keep-alive quickly (within ~1-2 cycles).
  auto before = std::chrono::steady_clock::now();
  auto pub = mSession->subscriptions().publish_sync(PublishRequest{});
  auto elapsed = std::chrono::steady_clock::now() - before;
  auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

  EXPECT_TRUE(pub.response_header().service_result().is_good());
  EXPECT_EQ(pub.subscription_id(), subId);

  // Should be a keep-alive (empty notification_data) OR initial data if MI was created.
  // The key assertion: it should NOT wait maxKeepAliveCount cycles.
  // Allow up to 3x one publishing interval as generous margin.
  auto thresholdMs = static_cast<int64_t>(revisedInterval * 3);
  EXPECT_LT(elapsedMs, std::min(thresholdMs, maxWaitMs / 2))
    << "First Publish should return within a few cycles, not wait for " << revisedKeepAlive
    << " keep-alive cycles (" << maxWaitMs << "ms). " << "Took " << elapsedMs << "ms";
}

/// SVR-SUB-GEN-031: Any service call that uses a SubscriptionId resets the lifetime counter.
/// Bug it catches: Server that doesn't reset lifetime on service calls, causing premature
/// subscription expiry.
// @relation(SVR-SUB-GEN-031, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_031_LifetimeResetByServiceCall)
{
  // Create subscription with very short lifetime. The publishing interval is widened under a sanitizer, and
  // every deadline below is derived from the revised value the server hands back.
  auto req = build_subscription_request(
    {.publishingInterval = ua::test_utils::scaled_ms(100.0), .lifetimeCount = 3, .keepAliveCount = 1});
  auto createResp = mSession->subscriptions().create_subscription_sync(std::move(req));
  ASSERT_TRUE(createResp.response_header().service_result().is_good());
  auto subId = createResp.subscription_id();
  auto revisedLifetime = createResp.revised_lifetime_count();
  auto revisedInterval = createResp.revised_publishing_interval();

  // Total lifetime in ms without refresh.
  auto lifetimeMs = static_cast<int64_t>(revisedLifetime * revisedInterval);

  // Repeatedly call ModifySubscription at intervals shorter than the lifetime,
  // keeping the subscription alive well beyond its original expiry.
  auto totalElapsed = std::chrono::milliseconds(0);
  auto refreshInterval = std::chrono::milliseconds(static_cast<int64_t>(lifetimeMs / 2));

  // Refresh enough times that the total elapsed time exceeds 2x the original lifetime.
  int refreshCount = 0;
  while (totalElapsed.count() < lifetimeMs * 2)
  {
    std::this_thread::sleep_for(refreshInterval);
    totalElapsed += refreshInterval;

    ModifySubscriptionRequest modReq;
    modReq.subscription_id() = subId;
    modReq.requested_publishing_interval() = ua::test_utils::scaled_ms(100.0);
    modReq.requested_lifetime_count() = 3;
    modReq.requested_max_keep_alive_count() = 1;
    modReq.max_notifications_per_publish() = 0;
    auto modResult = mSession->subscriptions().try_modify_subscription_sync(std::move(modReq));

    ASSERT_TRUE(modResult.is_good()) << "ModifySubscription failed at refresh #" << refreshCount << " after "
                                     << totalElapsed.count() << "ms";
    ASSERT_TRUE(modResult.value().response_header().service_result().is_good())
      << "Subscription should still be alive at refresh #" << refreshCount << " after "
      << totalElapsed.count()
      << "ms, but got: " << to_string(modResult.value().response_header().service_result());
    ++refreshCount;
  }

  // Final verification: subscription is still alive after exceeding original lifetime.
  ModifySubscriptionRequest finalReq;
  finalReq.subscription_id() = subId;
  finalReq.requested_publishing_interval() = ua::test_utils::scaled_ms(100.0);
  finalReq.requested_lifetime_count() = 30;
  finalReq.requested_max_keep_alive_count() = 10;
  finalReq.max_notifications_per_publish() = 0;
  auto finalResult = mSession->subscriptions().try_modify_subscription_sync(std::move(finalReq));

  ASSERT_TRUE(finalResult.is_good());
  EXPECT_TRUE(finalResult.value().response_header().service_result().is_good())
    << "Subscription expired despite regular service calls resetting the lifetime counter";
}

/// SVR-SUB-GEN-035: Lifetime of a subscription must be >= 3x the keep-alive interval
/// as negotiated by the server. revisedLifetimeCount >= 3 * revisedMaxKeepAliveCount.
/// Bug it catches: Server that allows lifetime < 3x keep-alive.
// @relation(SVR-SUB-GEN-035, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_035_LifetimeMinThreeTimesKeepAliveInterval)
{
  // Test with several combinations, including one where lifetime is explicitly too low.
  struct TestCase
  {
    double interval;
    uint32_t lifetimeCount;
    uint32_t keepAliveCount;
  };

  std::vector<TestCase> cases = {
    {100.0, 30, 10},  // Normal: lifetime=30, keepAlive=10 -> 30 >= 30 OK
    {100.0, 2, 5},  // Too small: lifetime=2 < 3*5=15, server must revise
    {200.0, 3, 1},  // Tight: lifetime=3 >= 3*1=3
    {50.0, 1, 1},  // Too small: lifetime=1 < 3*1=3, server must revise
    {100.0, 100, 10},  // Large: lifetime=100 >> 30
  };

  for (const auto& tc : cases)
  {
    auto req = build_subscription_request({.publishingInterval = tc.interval,
      .lifetimeCount = tc.lifetimeCount,
      .keepAliveCount = tc.keepAliveCount});
    auto resp = mSession->subscriptions().create_subscription_sync(std::move(req));

    EXPECT_TRUE(resp.response_header().service_result().is_good())
      << "CreateSubscription failed for interval=" << tc.interval << " lifetime=" << tc.lifetimeCount
      << " keepAlive=" << tc.keepAliveCount;

    EXPECT_GE(resp.revised_lifetime_count(), 3 * resp.revised_max_keep_alive_count())
      << "revisedLifetimeCount (" << resp.revised_lifetime_count()
      << ") must be >= 3 * revisedMaxKeepAliveCount (" << resp.revised_max_keep_alive_count()
      << ") for request lifetime=" << tc.lifetimeCount << " keepAlive=" << tc.keepAliveCount;
  }
}

/// SVR-SUB-GEN-044: Sequence number is never reset during the lifetime of a subscription,
/// including across ModifySubscription calls.
/// Bug it catches: Server that resets the sequence counter on ModifySubscription.
// @relation(SVR-SUB-GEN-044, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_044_SequenceNumberNeverResetAcrossModify)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Publish to get seq=1 (initial data change).
  auto pub1 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub1.response_header().service_result().is_good());
  auto seq1 = pub1.notification_message().sequence_number();
  EXPECT_GE(seq1, 1u);

  // Write + publish to get seq=2.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});

  PublishRequest ackReq1;
  SubscriptionAcknowledgement ack1;
  ack1.subscription_id() = subId;
  ack1.sequence_number() = seq1;
  ackReq1.subscription_acknowledgements().push_back(ack1);

  auto pub2 = mSession->subscriptions().publish_sync(std::move(ackReq1));
  ASSERT_TRUE(pub2.response_header().service_result().is_good());
  auto seq2 = pub2.notification_message().sequence_number();
  EXPECT_GT(seq2, seq1) << "Sequence should increase before modify";

  // ModifySubscription - change the interval.
  ModifySubscriptionRequest modReq;
  modReq.subscription_id() = subId;
  modReq.requested_publishing_interval() = 200.0;
  modReq.requested_lifetime_count() = 30;
  modReq.requested_max_keep_alive_count() = 10;
  modReq.max_notifications_per_publish() = 0;
  auto modResp = mSession->subscriptions().modify_subscription_sync(std::move(modReq));
  EXPECT_TRUE(modResp.response_header().service_result().is_good());

  // Write + publish to get seq=3 (after modify).
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{300}});

  PublishRequest ackReq2;
  SubscriptionAcknowledgement ack2;
  ack2.subscription_id() = subId;
  ack2.sequence_number() = seq2;
  ackReq2.subscription_acknowledgements().push_back(ack2);

  auto pub3 = mSession->subscriptions().publish_sync(std::move(ackReq2));
  ASSERT_TRUE(pub3.response_header().service_result().is_good());
  auto seq3 = pub3.notification_message().sequence_number();

  // Sequence numbers must be monotonically increasing across the modify.
  EXPECT_GT(seq3, seq2) << "Sequence number must not reset across ModifySubscription: "
                        << "seq before modify=" << seq2 << ", seq after modify=" << seq3;
}

/// SVR-SUB-GEN-051: The retransmission queue retains unacknowledged notifications.
/// Unacked sequence numbers appear in available_sequence_numbers and can be republished.
/// Bug it catches: Server with no retransmission queue.
// @relation(SVR-SUB-GEN-051, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_051_RetransmissionQueueRetainsUnacked)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Publish 1 - initial data change. Do NOT ack.
  auto pub1 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub1.response_header().service_result().is_good());
  auto seq1 = pub1.notification_message().sequence_number();

  // Write a value and publish again. Do NOT ack seq1.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{555}});
  auto pub2 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub2.response_header().service_result().is_good());
  auto seq2 = pub2.notification_message().sequence_number();

  // Write another value and publish. Still no acks.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{666}});
  auto pub3 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub3.response_header().service_result().is_good());
  auto seq3 = pub3.notification_message().sequence_number();

  // The available_sequence_numbers in pub3 should contain seq1, seq2, and seq3
  // (all unacked).
  auto& availSeqs = pub3.available_sequence_numbers();
  auto containsSeq = [&availSeqs](uint32_t target)
  {
    for (auto s : availSeqs)
    {
      if (s == target)
        return true;
    }
    return false;
  };

  EXPECT_TRUE(containsSeq(seq1)) << "Unacked seq " << seq1 << " should be in available_sequence_numbers";
  EXPECT_TRUE(containsSeq(seq2)) << "Unacked seq " << seq2 << " should be in available_sequence_numbers";
  EXPECT_TRUE(containsSeq(seq3)) << "Unacked seq " << seq3 << " should be in available_sequence_numbers";

  // Republish seq1 - should succeed since it's retained in the retransmission queue.
  RepublishRequest repReq;
  repReq.subscription_id() = subId;
  repReq.retransmit_sequence_number() = seq1;
  auto repResp = mSession->subscriptions().republish_sync(std::move(repReq));
  EXPECT_TRUE(repResp.response_header().service_result().is_good())
    << "Republish of unacked sequence " << seq1 << " should succeed";
  EXPECT_EQ(repResp.notification_message().sequence_number(), seq1);
}

/// SVR-SUB-GEN-052: When the retransmission queue overflows, the oldest entry is evicted.
/// Bug it catches: Server that evicts newest instead of oldest, or has an unbounded queue.
// @relation(SVR-SUB-GEN-052, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceSubscriptionLimited, SUB_GEN_052_RetransmissionQueueOverflowEvictsOldest)
{
  // ComplianceSubscriptionLimited has mMaxPublishRequestsPerSession=2,
  // so retransmission queue size = 2 x 2 = 4.
  // We need to generate >4 unacked notifications.

  // Create subscription + MI on the fixture's writable variable.
  auto subId = create_subscription(*mSession, {.publishingInterval = 100.0});
  auto miReq = build_create_mi_request(subId, mVariableId);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_FALSE(miResp.results().empty());
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Generate >4 notifications without acknowledging.
  // Each write + publish cycle produces one notification with a unique sequence number.
  std::vector<uint32_t> seqNums;

  // First publish: initial data change.
  auto pub = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub.response_header().service_result().is_good());
  seqNums.push_back(pub.notification_message().sequence_number());

  for (int32_t val = 1; val <= 5; ++val)
  {
    write_value_async(*mSession, mVariableId, Variant{int32_t{val}});
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    pub = mSession->subscriptions().publish_sync(PublishRequest{});
    ASSERT_TRUE(pub.response_header().service_result().is_good());
    seqNums.push_back(pub.notification_message().sequence_number());
  }

  // We now have 6 unacked sequence numbers, but queue only holds 4.
  // The oldest (seqNums[0] and seqNums[1]) should have been evicted.
  ASSERT_GE(seqNums.size(), 6u);

  // Check available_sequence_numbers in the last publish.
  auto& availSeqs = pub.available_sequence_numbers();
  auto containsSeq = [&availSeqs](uint32_t target)
  {
    for (auto s : availSeqs)
    {
      if (s == target)
        return true;
    }
    return false;
  };

  // Newest should be available.
  EXPECT_TRUE(containsSeq(seqNums.back()))
    << "Newest sequence " << seqNums.back() << " should still be in retransmission queue";

  // Oldest should have been evicted.
  // Try to Republish the oldest - should fail with BadMessageNotAvailable.
  RepublishRequest repReq;
  repReq.subscription_id() = subId;
  repReq.retransmit_sequence_number() = seqNums[0];
  auto repResult = mSession->subscriptions().try_republish_sync(std::move(repReq));

  if (repResult.is_good())
  {
    EXPECT_EQ(
      repResult.value().response_header().service_result(), StatusCode{Status::BadMessageNotAvailable})
      << "Oldest sequence " << seqNums[0] << " should have been evicted from the retransmission queue";
  }
  else
  {
    EXPECT_EQ(repResult.status_code(), StatusCode{Status::BadMessageNotAvailable})
      << "Oldest sequence " << seqNums[0] << " should have been evicted from the retransmission queue";
  }

  // Newest should still be republishable.
  RepublishRequest repReqNewest;
  repReqNewest.subscription_id() = subId;
  repReqNewest.retransmit_sequence_number() = seqNums.back();
  auto repNewest = mSession->subscriptions().try_republish_sync(std::move(repReqNewest));
  if (repNewest.is_good())
  {
    EXPECT_TRUE(repNewest.value().response_header().service_result().is_good())
      << "Newest sequence " << seqNums.back() << " should still be available for republish";
  }
}

/// SVR-SUB-GEN-060 (SHOULD): Higher priority subscription gets Publish response first.
/// Bug it catches: Server that ignores subscription priority entirely.
// @relation(SVR-SUB-GEN-060, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_060_HigherPrioritySubscriptionFirst)
{
  // Create high-priority subscription (priority=100) with MI on mWritableVariableId.
  auto highResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 10, .priority = 100}));
  ASSERT_TRUE(highResp.response_header().service_result().is_good());
  auto highSubId = highResp.subscription_id();

  auto highMiReq = build_create_mi_request(highSubId, mWritableVariableId, {.clientHandle = 10});
  auto highMiResp = mSession->monitored_items().create_monitored_items_sync(std::move(highMiReq));
  ASSERT_FALSE(highMiResp.results().empty());
  ASSERT_TRUE(highMiResp.results()[0].status_code().is_good());

  // Create low-priority subscription (priority=0) with MI on mFullAccessVariableId.
  auto lowResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 10, .priority = 0}));
  ASSERT_TRUE(lowResp.response_header().service_result().is_good());
  auto lowSubId = lowResp.subscription_id();

  auto lowMiReq = build_create_mi_request(lowSubId, mFullAccessVariableId, {.clientHandle = 20});
  auto lowMiResp = mSession->monitored_items().create_monitored_items_sync(std::move(lowMiReq));
  ASSERT_FALSE(lowMiResp.results().empty());
  ASSERT_TRUE(lowMiResp.results()[0].status_code().is_good());

  // Consume initial data change notifications from both subscriptions.
  auto init1 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(init1.response_header().service_result().is_good());
  auto init2 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(init2.response_header().service_result().is_good());

  // Write to both variables simultaneously.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{777}});
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{888}});

  // Wait for both subscriptions to have pending notifications.
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // Send one Publish - the higher-priority subscription should be served first.
  auto pub1 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub1.response_header().service_result().is_good());

  auto pub2 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pub2.response_header().service_result().is_good());

  // Verify both subscriptions are served (both subIds appear).
  bool highFirst = (pub1.subscription_id() == highSubId);
  bool bothServed = (pub1.subscription_id() != pub2.subscription_id()) &&
                    ((pub1.subscription_id() == highSubId && pub2.subscription_id() == lowSubId) ||
                      (pub1.subscription_id() == lowSubId && pub2.subscription_id() == highSubId));

  // Both subscriptions must be served.
  EXPECT_TRUE(bothServed) << "Expected both subscriptions to be served. Got subId=" << pub1.subscription_id()
                          << " and subId=" << pub2.subscription_id() << " (high=" << highSubId
                          << ", low=" << lowSubId << ")";

  // SHOULD requirement: higher priority should be served first.
  // Document the result even if it fails (this is a SHOULD, not a SHALL).
  EXPECT_TRUE(highFirst) << "SVR-SUB-GEN-060 (SHOULD): Higher priority subscription (id=" << highSubId
                         << ", priority=100) should be served before lower priority (id=" << lowSubId
                         << ", priority=0). First publish was for subId=" << pub1.subscription_id();
}

/// SVR-SUB-GEN-061 (SHOULD): Equal priority subscriptions are served without starvation.
/// Bug it catches: Server that always favors one subscription and starves the other.
// @relation(SVR-SUB-GEN-061, SVR-SUB-GEN-126, scope=function)
TEST_F(ComplianceWithNodes, SUB_GEN_061_EqualPriorityNoStarvation)
{
  // Create two subscriptions with the same priority.
  auto resp1 = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 10, .priority = 0}));
  ASSERT_TRUE(resp1.response_header().service_result().is_good());
  auto subId1 = resp1.subscription_id();

  auto miReq1 = build_create_mi_request(subId1, mWritableVariableId, {.clientHandle = 30});
  auto miResp1 = mSession->monitored_items().create_monitored_items_sync(std::move(miReq1));
  ASSERT_FALSE(miResp1.results().empty());
  ASSERT_TRUE(miResp1.results()[0].status_code().is_good());

  auto resp2 = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 10, .priority = 0}));
  ASSERT_TRUE(resp2.response_header().service_result().is_good());
  auto subId2 = resp2.subscription_id();

  auto miReq2 = build_create_mi_request(subId2, mFullAccessVariableId, {.clientHandle = 40});
  auto miResp2 = mSession->monitored_items().create_monitored_items_sync(std::move(miReq2));
  ASSERT_FALSE(miResp2.results().empty());
  ASSERT_TRUE(miResp2.results()[0].status_code().is_good());

  // Consume initial data change notifications from both subscriptions.
  auto init1 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(init1.response_header().service_result().is_good());
  auto init2 = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(init2.response_header().service_result().is_good());

  // Generate data changes and collect which subscriptions are served across multiple rounds.
  std::set<uint32_t> servedSubIds;

  for (int round = 0; round < 3; ++round)
  {
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100 + round}});
    write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{200 + round}});
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    auto pub = mSession->subscriptions().publish_sync(PublishRequest{});
    if (pub.response_header().service_result().is_good())
    {
      servedSubIds.insert(pub.subscription_id());
    }

    auto pub2 = mSession->subscriptions().publish_sync(PublishRequest{});
    if (pub2.response_header().service_result().is_good())
    {
      servedSubIds.insert(pub2.subscription_id());
    }
  }

  // Both subscription IDs must appear - neither should be starved.
  EXPECT_TRUE(servedSubIds.count(subId1) > 0)
    << "Subscription " << subId1 << " was never served - round-robin violated";
  EXPECT_TRUE(servedSubIds.count(subId2) > 0)
    << "Subscription " << subId2 << " was never served - round-robin violated";
}

// ===========================================================================
// TransferSubscriptions tests (SVC-TransferSub-*)
// ===========================================================================

/// TransferSubscriptions may return BadServiceUnsupported if not implemented.
TEST_F(ComplianceWithNodes, SVC_TransferSub_BadServiceUnsupported)
{
  auto subId = create_subscription(*mSession);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  auto result = mSession->subscriptions().try_transfer_subscriptions_sync(std::move(req));

  if (result.is_good())
  {
    auto& resp = result.value();
    if (resp.response_header().service_result().is_good())
    {
      // Service is implemented. Check per-result status.
      ASSERT_FALSE(resp.results().empty());
      // May succeed or return BadNotSupported per transfer target.
    }
    else
    {
      // Service-level error is acceptable (BadServiceUnsupported or BadNotSupported).
      auto sc = resp.response_header().service_result();
      EXPECT_TRUE(
        sc == StatusCode{Status::BadServiceUnsupported} || sc == StatusCode{Status::BadNotSupported})
        << "Unexpected service result: " << to_string(sc);
    }
  }
  else
  {
    auto sc = result.status_code();
    EXPECT_TRUE(sc == StatusCode{Status::BadServiceUnsupported} || sc == StatusCode{Status::BadNotSupported})
      << "Unexpected error: " << to_string(sc);
  }
}

// ===========================================================================
// Publishing cycle and Publish-request queue obligations (Part 4 section 5.13)
// ===========================================================================

/// Part 4 section 5.13.1.1: the publishing interval is the cyclic rate at which the
/// Subscription executes, so the delivery rate is a property of the timer and not of the
/// work beneath it. A publishing loop driven by sampling completions rather than by the
/// timer still publishes - nothing fails - but it speeds up as monitored items are added
/// or as their sampling intervals shorten, and the client's delivery rate changes
/// underneath it. Measuring one monitored item against ten at the fastest sampling the
/// server grants is what separates the two.
// @verifies AC-SVR-SUB-GEN-001-PUBLISHING-INTERVAL
TEST_F(ComplianceWithNodes, PublishingRateFollowsRevisedIntervalIndependentOfMonitoredItemLoad)
{
  constexpr double requestedIntervalMs = 200.0;
  constexpr auto window = std::chrono::milliseconds{1600};

  auto createResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = requestedIntervalMs, .lifetimeCount = 600, .keepAliveCount = 20}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  const auto revisedInterval = createResp.revised_publishing_interval();
  ASSERT_GT(revisedInterval, 0.0);

  auto addItem = [&](uint32_t clientHandle, double samplingInterval, uint32_t queueSize)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(subId,
      mWritableVariableId,
      {.clientHandle = clientHandle, .samplingInterval = samplingInterval, .queueSize = queueSize}));
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  };

  // Keep a Publish request available throughout and count the data-bearing
  // NotificationMessages that arrive inside a fixed window.
  auto measure = [&](int32_t seed)
  {
    int dataResponses = 0;
    int32_t value = seed;
    const auto deadline = std::chrono::steady_clock::now() + window;
    while (std::chrono::steady_clock::now() < deadline)
    {
      write_value_async(*mSession, mWritableVariableId, Variant{int32_t{value++}});
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      if (!resp.notification_message().notification_data().empty())
        ++dataResponses;
    }
    return dataResponses;
  };

  addItem(1, 100.0, 1);
  const int lightLoad = measure(1000);

  // Nine more items on the same changing Variable, each sampling as fast as the server
  // allows and each queueing several samples per publishing cycle.
  for (uint32_t handle = 2; handle <= 10; ++handle)
  {
    addItem(handle, 0.0, 10);
  }
  // Flush the initial-value notifications the new items produce.
  (void)mSession->subscriptions().publish_sync(PublishRequest{});

  const int heavyLoad = measure(2000);

  const int expected = static_cast<int>(static_cast<double>(window.count()) / revisedInterval);
  ASSERT_GT(expected, 0);

  EXPECT_GE(lightLoad, 2) << "no cyclic delivery with one monitored item";
  EXPECT_GE(heavyLoad, 2) << "no cyclic delivery with ten monitored items";
  EXPECT_LE(lightLoad, 2 * expected + 2)
    << "NotificationMessages arrived faster than the revised interval of " << revisedInterval << "ms ("
    << lightLoad << " in " << window.count() << "ms, expected about " << expected << ")";
  EXPECT_LE(heavyLoad, 2 * expected + 2)
    << "NotificationMessages arrived faster than the revised interval of " << revisedInterval << "ms ("
    << heavyLoad << " in " << window.count() << "ms, expected about " << expected << ")";

  // The rate must not drift with the number of monitored items or with the sampling
  // intervals beneath them.
  EXPECT_LE(heavyLoad, 2 * lightLoad + 2)
    << "publishing rate rose with the monitored-item count: " << lightLoad << " message(s) with one item, "
    << heavyLoad << " with ten";
  EXPECT_LE(lightLoad, 2 * heavyLoad + 2)
    << "publishing rate fell with the monitored-item count: " << lightLoad << " message(s) with one item, "
    << heavyLoad << " with ten";
}

/// Part 4 section 5.13.2: publishingInterval is a revisable parameter, so an illegal
/// value is corrected rather than rejected - and the correction is specifically to the
/// fastest interval the server supports. An implementation that substitutes a house
/// default, or that echoes an out-of-range request back unchanged, still answers Good;
/// only comparing the revision against the server's real floor catches it.
// @verifies AC-SVR-SUB-GEN-002-INTERVAL-ZERO-OR-NEGATIVE
TEST_F(ComplianceWithNodes, ZeroAndNegativePublishingIntervalRevisedToFastestSupported)
{
  auto createWithInterval = [&](double requested)
  {
    return mSession->subscriptions().try_create_subscription_sync(
      build_subscription_request({.publishingInterval = requested}));
  };

  auto zero = createWithInterval(0.0);
  ASSERT_TRUE(zero.is_good()) << "CreateSubscription with publishingInterval 0 failed: "
                              << to_string(zero.status_code());
  EXPECT_THAT(zero.value(), ServiceResultIsGood());
  EXPECT_NE(zero.value().subscription_id(), 0u);

  auto negative = createWithInterval(-100.0);
  ASSERT_TRUE(negative.is_good()) << "CreateSubscription with publishingInterval -100 failed: "
                                  << to_string(negative.status_code());
  EXPECT_THAT(negative.value(), ServiceResultIsGood());
  EXPECT_NE(negative.value().subscription_id(), 0u);

  // Reference point: a positive interval below any plausible server floor is clamped to
  // that floor, so its revision IS the fastest interval the server supports.
  auto fastest = createWithInterval(0.001);
  ASSERT_TRUE(fastest.is_good()) << to_string(fastest.status_code());
  ASSERT_THAT(fastest.value(), ServiceResultIsGood());
  const double fastestInterval = fastest.value().revised_publishing_interval();
  ASSERT_GT(fastestInterval, 0.0);

  EXPECT_DOUBLE_EQ(zero.value().revised_publishing_interval(), fastestInterval)
    << "publishingInterval 0 was not revised to the fastest supported interval";
  EXPECT_DOUBLE_EQ(negative.value().revised_publishing_interval(), fastestInterval)
    << "publishingInterval -100 was not revised to the fastest supported interval";

  // And that floor really is the fastest: a slower request is never revised below it.
  auto slow = createWithInterval(1000.0);
  ASSERT_TRUE(slow.is_good()) << to_string(slow.status_code());
  ASSERT_THAT(slow.value(), ServiceResultIsGood());
  EXPECT_LE(fastestInterval, slow.value().revised_publishing_interval())
    << "the interval granted for an illegal request is slower than one granted for a legal request";
}

/// Part 4 section 5.13.5: a Publish request carries no subscriptionId - it is queued on
/// the Session and whichever Subscription needs one takes it. An implementation that
/// binds the request to a Subscription when it is issued (the one due next, say) behaves
/// correctly on a single-Subscription Session and starves the other one here: the request
/// is queued while NEITHER Subscription has anything to send, and the Subscription that
/// later produces a notification must still be able to consume it.
// @verifies AC-SVR-SUB-GEN-010-PUBLISH-NOT-DIRECTED
TEST_F(ComplianceWithNodes, QueuedPublishIsConsumedByWhicheverSubscriptionNeedsIt)
{
  // A long keep-alive count so that, once the post-create keep-alives are drained,
  // neither Subscription has anything to send for the duration of the test.
  const SubscriptionOptions quiet{.publishingInterval = 100.0, .lifetimeCount = 300, .keepAliveCount = 60};
  const auto subIdA = create_subscription(*mSession, quiet);
  const auto subIdB = create_subscription(*mSession, quiet);
  ASSERT_NE(subIdA, 0u);
  ASSERT_NE(subIdB, 0u);
  ASSERT_NE(subIdA, subIdB);

  using PubResult = SessionSubscriptionServices::PublishResponseResult;

  // Drain the post-create keep-alives and keep the first request nobody answers: at that
  // point it is queued on the Session and cannot have been bound to either Subscription,
  // because neither had anything to send when it was issued.
  // promises are heap-allocated: a callback may fire during session teardown, after this
  // stack frame has returned.
  std::optional<std::future<PubResult>> queued;
  for (int attempt = 0; attempt < 8 && !queued.has_value(); ++attempt)
  {
    auto promise = std::make_shared<std::promise<PubResult>>();
    auto future = promise->get_future();
    mSession->subscriptions().publish_async(
      PublishRequest{}, [promise](PubResult result) mutable { promise->set_value(std::move(result)); });

    if (future.wait_for(std::chrono::milliseconds{600}) == std::future_status::timeout)
    {
      queued = std::move(future);
    }
    else
    {
      (void)future.get();
    }
  }
  ASSERT_TRUE(queued.has_value())
    << "could not reach a state where one Publish request is queued and unanswered";

  // Only now does one of the two Subscriptions acquire something to say.
  auto miResp = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subIdB, mWritableVariableId, {.clientHandle = 91}));
  ASSERT_FALSE(miResp.results().empty());
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  ASSERT_EQ(queued->wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the queued Publish request was not used by the Subscription that produced notifications";
  auto result = queued->get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  const auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood());
  EXPECT_EQ(resp.subscription_id(), subIdB)
    << "the queued Publish was answered for subscription " << resp.subscription_id()
    << ", not for the one with notifications (" << subIdB << ")";
  const auto* dcn = as_data_change(resp);
  ASSERT_NE(dcn, nullptr) << "the queued Publish did not carry the DataChangeNotification it was used for";
  EXPECT_FALSE(dcn->monitored_items().empty());
}

/// Part 4 section 5.13.5: the Publish queue belongs to the Session, and each publishing
/// cycle dequeues at most one request from it. An implementation that answers every
/// queued request as soon as it has something to send, or that keeps a queue per
/// Subscription, passes every single-request test - it takes several requests over
/// several cycles to expose the pacing, and a second Subscription to show that the queue
/// is the Session's and not the Subscription's.
// @verifies AC-SVR-SUB-GEN-011-PUBLISH-QUEUE
TEST_F(ComplianceWithNodes, PublishQueueIsSessionWideAndOneRequestIsConsumedPerCycle)
{
  using PubResult = SessionSubscriptionServices::PublishResponseResult;

  // promises must be heap-allocated: the callbacks may fire during session teardown,
  // after the caller's stack frame has returned.
  auto queuePublishes = [&](std::size_t count)
  {
    auto promises = std::make_shared<std::vector<std::promise<PubResult>>>(count);
    std::vector<std::future<PubResult>> futures;
    for (auto& p : *promises)
      futures.push_back(p.get_future());
    for (std::size_t i = 0; i < count; ++i)
    {
      mSession->subscriptions().publish_async(PublishRequest{},
        [promises, i](PubResult result) mutable { (*promises)[i].set_value(std::move(result)); });
    }
    return futures;
  };

  // keepAliveCount=1 gives every cycle exactly one NotificationMessage to ship, so the
  // number of Publish requests consumed per cycle is directly countable.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 300.0, .lifetimeCount = 60, .keepAliveCount = 1}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId1 = createResp.subscription_id();
  const auto revisedInterval = createResp.revised_publishing_interval();
  ASSERT_GT(revisedInterval, 0.0);

  constexpr std::size_t publishCount = 5;
  const auto queuedAt = std::chrono::steady_clock::now();
  auto futures = queuePublishes(publishCount);

  // Partway through the run the queue must not have been drained wholesale.
  std::this_thread::sleep_for(std::chrono::milliseconds{500});
  std::size_t readyEarly = 0;
  for (auto& f : futures)
  {
    if (f.wait_for(std::chrono::milliseconds{0}) == std::future_status::ready)
      ++readyEarly;
  }
  EXPECT_GE(readyEarly, 1u) << "no queued Publish request was consumed at all";
  EXPECT_LE(readyEarly, 3u) << "more than one Publish request was consumed per publishing cycle: "
                            << readyEarly << " of " << publishCount << " answered within 500ms at a "
                            << revisedInterval << "ms interval";

  std::size_t answered = 0;
  for (auto& f : futures)
  {
    ASSERT_EQ(f.wait_for(std::chrono::seconds{6}), std::future_status::ready)
      << "queued Publish request " << answered << " was never answered";
    auto result = f.get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    EXPECT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subId1);
    ++answered;
  }
  ASSERT_EQ(answered, publishCount);

  const auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - queuedAt);
  EXPECT_GE(elapsed.count(), static_cast<int64_t>(3 * revisedInterval))
    << publishCount << " Publish requests were consumed in " << elapsed.count()
    << "ms - less than one publishing cycle (" << revisedInterval << "ms) each";

  // The queue is the Session's, so a second Subscription on the same Session draws from
  // it too.
  const auto subId2 =
    create_subscription(*mSession, {.publishingInterval = 300.0, .lifetimeCount = 60, .keepAliveCount = 1});
  ASSERT_NE(subId2, subId1);

  auto sharedFutures = queuePublishes(4);
  std::set<uint32_t> servedSubIds;
  for (auto& f : sharedFutures)
  {
    ASSERT_EQ(f.wait_for(std::chrono::seconds{6}), std::future_status::ready)
      << "a Publish request on the shared Session was never answered";
    auto result = f.get();
    ASSERT_THAT(result, Good());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    servedSubIds.insert(result.value().subscription_id());
  }
  ASSERT_FALSE(servedSubIds.empty()) << "no Publish response arrived for either Subscription";
  EXPECT_TRUE(servedSubIds.count(subId1) > 0)
    << "the first Subscription stopped drawing from the Session's Publish queue";
  EXPECT_TRUE(servedSubIds.count(subId2) > 0)
    << "the second Subscription never drew from the Session's Publish queue - the queue is not the "
       "Session's";
}

/// Part 4 section 5.13.1.1: a cycle that begins with notifications ready but no queued
/// Publish request holds them and ships them when a request arrives. Discarding is the
/// natural behaviour for a cyclic process - the cycle ended, so its output is stale - and
/// it silently loses data exactly when the client is slow to post Publish requests. The
/// held notification must also survive the following cycle's data rather than being
/// replaced by it.
// @verifies AC-SVR-SUB-GEN-012-WAIT-FOR-PUBLISH
TEST_F(ComplianceWithNodes, NotificationsAreHeldWhenNoPublishRequestIsQueued)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession,
    mWritableVariableId,
    {.publishingInterval = 100.0, .lifetimeCount = 300, .keepAliveCount = 5},
    {.clientHandle = 1, .samplingInterval = 50.0, .queueSize = 5});

  auto initial = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(initial) << "expected the initial-value DataChangeNotification for subscription " << subId;

  auto carriesValue = [](const DataChangeNotification& dc, int32_t expected)
  {
    for (const auto& mi : dc.monitored_items())
    {
      const auto* actual = mi.value().value().try_as<int32_t>();
      if (mi.client_handle() == 1u && actual != nullptr && *actual == expected)
        return true;
    }
    return false;
  };

  // 111 becomes ready while no Publish request is queued: several publishing cycles pass
  // with nothing to attach it to.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{111}});
  std::this_thread::sleep_for(std::chrono::milliseconds{600});

  // A later cycle produces fresh data. The held notification must survive it.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{222}});
  std::this_thread::sleep_for(std::chrono::milliseconds{300});

  auto held = wait_for_data_change(
    *mSession, subId, [](const DataChangeNotification& dc) { return !dc.monitored_items().empty(); });
  ASSERT_TRUE(held) << "the notification held while no Publish was queued was never delivered";
  ASSERT_FALSE(held->monitored_items().empty());
  EXPECT_TRUE(carriesValue(*held, 111))
    << "the value that was ready when the cycle found no queued Publish was dropped - the Subscription "
       "skipped to the next cycle's data";

  // Nothing was lost the other way either: the later value is delivered too.
  if (!carriesValue(*held, 222))
  {
    auto later = wait_for_data_change(
      *mSession, subId, [&](const DataChangeNotification& dc) { return carriesValue(dc, 222); });
    EXPECT_TRUE(later) << "the value produced after the held one was never delivered";
  }
}

/// Part 4 section 5.13.5: when the per-Session Publish queue is full, the server evicts
/// the OLDEST queued request, answers it Bad_TooManyPublishRequests, and enqueues the new
/// one. Rejecting the newest is the intuitive back-pressure and it is the wrong end - it
/// starves a client that has just recovered, and it satisfies any test that only looks
/// for the status code somewhere in the batch. Both halves have to be asserted.
// @verifies AC-SVR-SUB-GEN-014-PUBLISH-QUEUE-LIMIT
TEST_F(ComplianceSubscriptionLimited, PublishOverTheQueueLimitEvictsOldestAndKeepsNewest)
{
  // A very slow publishing interval holds the queue still while it overflows: nothing
  // can consume a queued request during the overflow.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 5000.0, .lifetimeCount = 600, .keepAliveCount = 200}));
  ASSERT_THAT(createResp, ServiceResultIsGood());

  using PubResult = SessionSubscriptionServices::PublishResponseResult;
  const std::size_t count = mMaxPublishRequestsPerSession + 1;
  // promises must be heap-allocated: the lambdas may fire during session teardown after
  // this stack frame has returned.
  auto promises = std::make_shared<std::vector<std::promise<PubResult>>>(count);
  std::vector<std::future<PubResult>> futures;
  for (auto& p : *promises)
    futures.push_back(p.get_future());

  for (std::size_t i = 0; i < count; ++i)
  {
    mSession->subscriptions().publish_async(PublishRequest{},
      [promises, i](PubResult result) mutable { (*promises)[i].set_value(std::move(result)); });
  }

  // The oldest is de-queued and answered Bad_TooManyPublishRequests.
  ASSERT_EQ(futures.front().wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the oldest queued Publish request was not de-queued when the limit was exceeded";
  {
    auto oldest = futures.front().get();
    if (oldest.is_good())
    {
      EXPECT_EQ(
        oldest.value().response_header().service_result(), StatusCode{Status::BadTooManyPublishRequests});
    }
    else
    {
      EXPECT_EQ(oldest.status_code(), StatusCode{Status::BadTooManyPublishRequests});
    }
  }

  // The newest is kept: it is still queued at the moment the oldest was evicted. Nothing
  // can have consumed it - the only Subscription publishes once every 5 seconds.
  ASSERT_NE(futures.back().wait_for(std::chrono::milliseconds{0}), std::future_status::ready)
    << "the newest Publish request was answered rather than kept in the queue";

  // Being kept means being usable: a second Subscription on the same Session draws the
  // still-queued requests and they are answered normally, never with the overflow error.
  const auto fastSubId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .lifetimeCount = 60, .keepAliveCount = 1});
  ASSERT_NE(fastSubId, 0u);

  for (std::size_t i = 1; i < count; ++i)
  {
    ASSERT_EQ(futures[i].wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "kept Publish request " << i << " was never answered";
    auto result = futures[i].get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    EXPECT_NE(
      result.value().response_header().service_result(), StatusCode{Status::BadTooManyPublishRequests})
      << "Publish request " << i << " was rejected: the limit must evict the OLDEST request, not the newest";
    EXPECT_THAT(result.value(), ServiceResultIsGood());
  }
}

// ===========================================================================
// Publishing-mode and lifetime obligations (Part 4 section 5.13.1.1 / 5.13.2)
// ===========================================================================

/// Part 4 section 5.13.4: disabling publishing suppresses NotificationMessages but the
/// Subscription keeps executing its cycle, so keep-alives continue and the client's Publish
/// requests keep resetting the lifetime counter. An implementation that stops the cycle along
/// with the notifications still passes a single-Publish check - the first message is owed
/// regardless of publishing mode - and then goes quiet, so a client that paused a Subscription
/// comes back to find it closed rather than paused, which is the opposite of what
/// SetPublishingMode is for.
// @verifies AC-SVR-SUB-GEN-022-DISABLED-STILL-KEEPALIVES
TEST_F(ComplianceWithNodes, PublishingDisabledStillSendsKeepAlivesAndDoesNotTimeOut)
{
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 2}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  const auto revisedInterval = createResp.revised_publishing_interval();
  const auto revisedKeepAlive = createResp.revised_max_keep_alive_count();
  ASSERT_GT(revisedInterval, 0.0);
  ASSERT_GT(revisedKeepAlive, 0u);

  // A monitored item on a Variable that is written throughout the window below, so that the
  // Subscription has real Notifications to suppress rather than merely nothing to say.
  auto miResp = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subId, mWritableVariableId, {.clientHandle = 1, .samplingInterval = 50.0}));
  ASSERT_FALSE(miResp.results().empty());
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  drain_initial_publish(*mSession, subId);

  // Pause through the real service - the server decides what publishing-disabled means.
  set_publishing_mode(*mSession, subId, /*enabled=*/false);

  // Run well past several keep-alive periods.
  const auto keepAlivePeriodMs = static_cast<int64_t>(revisedKeepAlive * revisedInterval);
  ASSERT_GT(keepAlivePeriodMs, 0);
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::milliseconds{4 * keepAlivePeriodMs + 400};

  int keepAlives = 0;
  bool sawStatusChange = false;
  int32_t value = 0;
  while (std::chrono::steady_clock::now() < deadline)
  {
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{value++}});
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    if (!result.is_good() || !result.value().response_header().service_result().is_good())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
      continue;
    }
    const auto& resp = result.value();
    if (resp.subscription_id() != subId)
    {
      continue;
    }
    if (as_status_change(resp) != nullptr)
    {
      sawStatusChange = true;
    }
    else if (resp.notification_message().notification_data().empty())
    {
      ++keepAlives;
    }
  }

  EXPECT_GE(keepAlives, 3) << "keep-alive Messages stopped while publishing was disabled: only " << keepAlives
                           << " arrived over " << (4 * keepAlivePeriodMs + 400)
                           << "ms of keep-alive periods of " << keepAlivePeriodMs << "ms";
  EXPECT_FALSE(sawStatusChange)
    << "the Subscription was closed while publishing was disabled - disabling publishing is not "
       "disabling the Subscription";

  // And it really is still there: an unknown sequence number is answered
  // Bad_MessageNotAvailable by a live Subscription and Bad_SubscriptionIdInvalid by one that
  // has been closed.
  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = 0;
  auto rep = mSession->subscriptions().try_republish_sync(std::move(req));
  const auto status = rep.is_good() ? rep.value().response_header().service_result() : rep.status_code();
  EXPECT_NE(status, StatusCode{Status::BadSubscriptionIdInvalid})
    << "the Subscription timed out while publishing was disabled";
}

/// Part 4 section 5.13.1.1: the lifetime counter counts consecutive publishing cycles in which
/// no Publish request was available, and is reset as soon as one is processed. Counting cycles
/// rather than wall-clock time is what makes the lifetime scale with the publishing interval -
/// a timer-based implementation gives a slow Subscription exactly the same grace as a fast one
/// and closes it many cycles early. Two Subscriptions with the same lifetime count and
/// different publishing intervals separate the two readings; a probe is itself a service call
/// and therefore resets the counter it observes, so each Subscription is probed once per
/// question asked of it.
// @verifies AC-SVR-SUB-GEN-030-LIFETIME-COUNTS-CYCLES
TEST_F(ComplianceWithNodes, LifetimeIsCountedInPublishlessCyclesNotElapsedTime)
{
  auto isAlive = [&](uint32_t subscriptionId)
  {
    RepublishRequest req;
    req.subscription_id() = subscriptionId;
    req.retransmit_sequence_number() = 0;  // unknown -> Bad_MessageNotAvailable while alive
    auto result = mSession->subscriptions().try_republish_sync(std::move(req));
    const auto status =
      result.is_good() ? result.value().response_header().service_result() : result.status_code();
    return status != StatusCode{Status::BadSubscriptionIdInvalid};
  };

  // --- The counter resets when a Publish is processed, and runs out when none is. ---
  auto firstResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(firstResp, ServiceResultIsGood());
  const auto pacedSubId = firstResp.subscription_id();
  const auto pacedLifetimeMs =
    static_cast<int64_t>(firstResp.revised_lifetime_count() * firstResp.revised_publishing_interval());
  ASSERT_GT(pacedLifetimeMs, 0);

  // Supply one Publish every half-lifetime: no gap ever reaches the lifetime, but the total
  // elapsed time is several lifetimes. A counter that is never reset closes the Subscription
  // partway through, and a Publish response then carries a StatusChangeNotification.
  for (int i = 0; i < 6; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{pacedLifetimeMs / 2});
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    ASSERT_TRUE(result.is_good()) << "Publish " << i << " failed: " << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood())
      << "Publish " << i << " after " << ((i + 1) * pacedLifetimeMs / 2) << "ms";
    EXPECT_EQ(as_status_change(result.value()), nullptr)
      << "the Subscription was closed at iteration " << i << " despite a Publish being processed every "
      << (pacedLifetimeMs / 2) << "ms - processing a Publish must reset the lifetime counter";
  }

  // Stop supplying them and the counter finally runs out: the counting is real, not absent.
  std::this_thread::sleep_for(std::chrono::milliseconds{pacedLifetimeMs + 600});
  EXPECT_FALSE(isAlive(pacedSubId)) << "the lifetime counter never ran out - a Subscription that outlives "
                                    << (pacedLifetimeMs + 600)
                                    << "ms of publishless cycles is not counting them";

  // --- The counting is per cycle, not per millisecond. ---
  auto fastResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(fastResp, ServiceResultIsGood());
  auto slowResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 500.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(slowResp, ServiceResultIsGood());

  const auto fastSubId = fastResp.subscription_id();
  const auto slowSubId = slowResp.subscription_id();
  ASSERT_NE(fastSubId, slowSubId);
  ASSERT_EQ(fastResp.revised_lifetime_count(), slowResp.revised_lifetime_count())
    << "the two Subscriptions must differ only in publishing interval for this comparison to mean "
       "anything";

  const auto fastLifetimeMs =
    static_cast<int64_t>(fastResp.revised_lifetime_count() * fastResp.revised_publishing_interval());
  const auto slowLifetimeMs =
    static_cast<int64_t>(slowResp.revised_lifetime_count() * slowResp.revised_publishing_interval());
  ASSERT_GT(slowLifetimeMs, 3 * fastLifetimeMs)
    << "the server revised the two publishing intervals too close together to tell cycles from time";

  // One window, no Publish requests and no service calls: long enough for the fast
  // Subscription to exhaust its cycles, far short of the slow one's.
  std::this_thread::sleep_for(std::chrono::milliseconds{fastLifetimeMs + 500});

  EXPECT_FALSE(isAlive(fastSubId)) << "the Subscription publishing every "
                                   << fastResp.revised_publishing_interval() << "ms survived "
                                   << fastResp.revised_lifetime_count() << " publishless cycles";
  EXPECT_TRUE(isAlive(slowSubId))
    << "the Subscription publishing every " << slowResp.revised_publishing_interval()
    << "ms was closed after only " << (fastLifetimeMs + 500) << "ms - its "
    << slowResp.revised_lifetime_count() << " cycles are " << slowLifetimeMs
    << "ms, so the lifetime is being counted in elapsed time rather than in publishing cycles";
}

/// Part 4 section 5.13.1.1(h): "Any Service call that uses the SubscriptionId or the processing
/// of a Publish response resets the lifetime counter." Both halves are obligations, and the
/// Publish half is the one an implementation hooks naturally - a client that is actively
/// modifying a Subscription while holding no Publish outstanding is demonstrably present, and
/// closing it under that client is exactly the failure the clause exists to prevent. Each half
/// is driven on its own Subscription so that neither can be kept alive by the other's traffic,
/// and each is followed by a silence long enough to prove the counter was running at all.
// @verifies AC-SVR-SUB-GEN-031-LIFETIME-RESET
TEST_F(ComplianceWithNodes, LifetimeResetsOnBothAServiceCallAndAProcessedPublish)
{
  auto modifyStatus = [&](uint32_t subscriptionId)
  {
    ModifySubscriptionRequest req;
    req.subscription_id() = subscriptionId;
    req.requested_publishing_interval() = ua::test_utils::scaled_ms(100.0);
    req.requested_lifetime_count() = 6;
    req.requested_max_keep_alive_count() = 2;
    req.max_notifications_per_publish() = 0;
    auto result = mSession->subscriptions().try_modify_subscription_sync(std::move(req));
    return result.is_good() ? result.value().response_header().service_result() : result.status_code();
  };

  // --- Half one: a service call naming the SubscriptionId, with no Publish anywhere. ---
  // The publishing interval is widened under a sanitizer, and every deadline below is derived from
  // the revised value the server hands back - so the counter still has to reset exactly when the
  // test says, with wall-clock room the instrumented build can actually answer in.
  auto serviceResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = ua::test_utils::scaled_ms(100.0), .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(serviceResp, ServiceResultIsGood());
  const auto serviceSubId = serviceResp.subscription_id();
  const auto serviceLifetimeMs =
    static_cast<int64_t>(serviceResp.revised_lifetime_count() * serviceResp.revised_publishing_interval());
  ASSERT_GT(serviceLifetimeMs, 0);

  for (int i = 0; i < 6; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{serviceLifetimeMs / 2});
    EXPECT_EQ(modifyStatus(serviceSubId), StatusCode{Status::Good})
      << "ModifySubscription #" << i << " after " << ((i + 1) * serviceLifetimeMs / 2)
      << "ms - the Subscription timed out although the client was naming its SubscriptionId every "
      << (serviceLifetimeMs / 2) << "ms";
  }

  // The calls stop; the counter must then be free to run out. Without this the first half
  // would also pass on a server that never expires anything.
  const auto silence = serviceLifetimeMs + ua::test_utils::scaled(600ms).count();
  std::this_thread::sleep_for(std::chrono::milliseconds{silence});
  EXPECT_EQ(modifyStatus(serviceSubId), StatusCode{Status::BadSubscriptionIdInvalid})
    << "the Subscription outlived " << silence
    << "ms of silence - its lifetime counter is not running, so the resets above prove nothing";

  // That expiry parks a StatusChangeNotification on the Session. Drain it here so it cannot be
  // delivered onto one of the Publish requests the second half depends on.
  (void)wait_for_status_change(*mSession, serviceSubId, ua::test_utils::scaled(2000ms));

  // --- Half two: the processing of a Publish response, with no service call naming the id. ---
  auto publishResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = ua::test_utils::scaled_ms(100.0), .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(publishResp, ServiceResultIsGood());
  const auto publishSubId = publishResp.subscription_id();
  const auto publishLifetimeMs =
    static_cast<int64_t>(publishResp.revised_lifetime_count() * publishResp.revised_publishing_interval());
  ASSERT_GT(publishLifetimeMs, 0);

  for (int i = 0; i < 5; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{publishLifetimeMs / 2});
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    ASSERT_TRUE(result.is_good()) << "Publish #" << i << " failed: " << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood()) << "Publish #" << i;
    EXPECT_EQ(result.value().subscription_id(), publishSubId);
    EXPECT_EQ(as_status_change(result.value()), nullptr)
      << "the Subscription was closed at Publish #" << i << ", after " << ((i + 1) * publishLifetimeMs / 2)
      << "ms - processing a Publish response must reset the lifetime counter";
  }

  RepublishRequest aliveReq;
  aliveReq.subscription_id() = publishSubId;
  aliveReq.retransmit_sequence_number() = 0;
  auto aliveResult = mSession->subscriptions().try_republish_sync(std::move(aliveReq));
  const auto aliveStatus = aliveResult.is_good() ? aliveResult.value().response_header().service_result()
                                                 : aliveResult.status_code();
  EXPECT_NE(aliveStatus, StatusCode{Status::BadSubscriptionIdInvalid})
    << "the Subscription timed out over " << (5 * publishLifetimeMs / 2)
    << "ms although a Publish response was processed every " << (publishLifetimeMs / 2) << "ms";
}

/// Part 4 section 5.13.1.1(h): a Subscription is closed when its lifetime counter reaches the
/// value calculated from the MaxKeepAliveCount agreed at CreateSubscription - not at some fixed
/// server timeout. A hard-coded expiry passes any single-Subscription test: it closes something
/// eventually, and the test that only waits "long enough" cannot tell the two apart. Two
/// Subscriptions negotiated with different keep-alive counts on the same publishing interval do:
/// at one instant one of them must be closed and the other must not. Probing is itself a service
/// call and resets the counter it reads, so every probe is treated as a fresh start for that
/// Subscription.
// @verifies AC-SVR-SUB-GEN-032-LIFETIME-CLOSES
TEST_F(ComplianceWithNodes, SubscriptionClosesAtALifetimeDerivedFromItsKeepAliveCount)
{
  auto isAlive = [&](uint32_t subscriptionId)
  {
    RepublishRequest req;
    req.subscription_id() = subscriptionId;
    req.retransmit_sequence_number() = 0;
    auto result = mSession->subscriptions().try_republish_sync(std::move(req));
    const auto status =
      result.is_good() ? result.value().response_header().service_result() : result.status_code();
    return status != StatusCode{Status::BadSubscriptionIdInvalid};
  };

  // The publishing interval is widened under a sanitizer; every deadline below is derived from the revised
  // values the server hands back.
  auto shortResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = ua::test_utils::scaled_ms(100.0), .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(shortResp, ServiceResultIsGood());
  auto longResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = ua::test_utils::scaled_ms(100.0), .lifetimeCount = 30, .keepAliveCount = 10}));
  ASSERT_THAT(longResp, ServiceResultIsGood());

  const auto shortSubId = shortResp.subscription_id();
  const auto longSubId = longResp.subscription_id();
  ASSERT_NE(shortSubId, longSubId);
  ASSERT_GT(longResp.revised_max_keep_alive_count(), shortResp.revised_max_keep_alive_count())
    << "the server revised both keep-alive counts to the same value; the derivation cannot be observed";

  const auto shortLifetimeMs =
    static_cast<int64_t>(shortResp.revised_lifetime_count() * shortResp.revised_publishing_interval());
  const auto longLifetimeMs =
    static_cast<int64_t>(longResp.revised_lifetime_count() * longResp.revised_publishing_interval());
  ASSERT_GT(shortLifetimeMs, 0);
  ASSERT_GT(longLifetimeMs, 3 * shortLifetimeMs);

  // Before its limit the short Subscription is still open (this probe restarts its counter).
  std::this_thread::sleep_for(std::chrono::milliseconds{shortLifetimeMs / 2});
  EXPECT_TRUE(isAlive(shortSubId)) << "the Subscription was closed after only " << (shortLifetimeMs / 2)
                                   << "ms, well inside its " << shortLifetimeMs << "ms lifetime";

  // Past its limit it is closed - while the Subscription that negotiated the larger keep-alive
  // count, on the very same publishing interval and after the very same elapsed time, is not.
  std::this_thread::sleep_for(
    std::chrono::milliseconds{shortLifetimeMs} + ua::test_utils::scaled(std::chrono::milliseconds{500}));
  EXPECT_FALSE(isAlive(shortSubId)) << "the Subscription was not closed when its lifetime counter reached "
                                    << shortResp.revised_lifetime_count() << " cycles (" << shortLifetimeMs
                                    << "ms)";
  EXPECT_TRUE(isAlive(longSubId))
    << "the Subscription negotiated with maxKeepAliveCount=" << longResp.revised_max_keep_alive_count()
    << " (lifetime " << longLifetimeMs
    << "ms) was closed at the same moment as one negotiated with maxKeepAliveCount="
    << shortResp.revised_max_keep_alive_count()
    << " - the closing point is a fixed timeout, not the negotiated lifetime";

  // And the longer one does close, at its own longer limit.
  std::this_thread::sleep_for(
    std::chrono::milliseconds{longLifetimeMs} + ua::test_utils::scaled(std::chrono::milliseconds{500}));
  EXPECT_FALSE(isAlive(longSubId)) << "the Subscription was not closed when its lifetime counter reached "
                                   << longResp.revised_lifetime_count() << " cycles (" << longLifetimeMs
                                   << "ms)";
}

// ---------------------------------------------------------------------------
// Fixture: ComplianceSubscriptionMonitoredItemCapped - the server-wide
// MonitoredItem budget lowered to a reachable number, so that whether an item
// still occupies a slot is observable from the client.
// ---------------------------------------------------------------------------
class ComplianceSubscriptionMonitoredItemCapped : public ComplianceSubscriptionLimited
{
protected:
  ComplianceSubscriptionMonitoredItemCapped()
  {
    mMaxMonitoredItemsServerWide = 3;
  }
};

/// Part 4 section 5.13.1.1(h): closing a Subscription deletes its MonitoredItems AND the server
/// issues a StatusChangeNotification with Bad_Timeout. The notification is the half that is easy
/// to remember; the deletion is the half with a resource cost, and forgetting the Subscription
/// record while leaving its items charged against the server-wide MonitoredItem budget is
/// invisible until the budget has been consumed by Subscriptions that no longer exist. Filling
/// the budget, letting the Subscription expire and then refilling it is what makes the deletion
/// observable at all from a client.
// DISABLED: the deletion half of the obligation is UNIMPLEMENTED and this test is correct as
// written - do not weaken it. `SubscriptionsPipeline::delete_subscription` posts the close and then
// drops the owner in the very next statement: `subscription->close_async()` at
// ua_subscriptions_pipeline.cpp:707 followed by `mSubscriptions.erase(it)` at :708. `close_async`
// uses `ua::async::post_borrowing` (ua_subscription.cpp:2376), whose strand turn re-locks a
// `weak_from_this()` and no-ops if the object is gone (ua_on_strand.h:176-180). `mSubscriptions` is
// the only strong owner - the router, the sample sink and the diagnostics manager all hold
// `weak_ptr<Subscription>` - so the erase destroys the Subscription before the posted turn runs and
// `Subscription::close()` never executes. The release of the server-wide budget lives inside that
// dead `close()` (`mSummaryCounters->currentMonitoredItemCount.fetch_sub(mMonitoredItems.size())`,
// ua_subscription.cpp:299-302) and `~Subscription` (:215-244) does not repeat it, so every expired
// Subscription's items stay charged against `MaxMonitoredItems` forever. The same dead `close()`
// also `mMonitoredItems.clear()`s without calling `Namespace::delete_monitoring` for the items'
// `namespaceHandle`s - the only call site is the explicit DeleteMonitoredItems flow
// (ua_subscription.cpp:1731) - so the namespace-side sampling registrations outlive the
// Subscription either way, which is the criterion's "no item survives to sample against a
// Subscription that no longer exists" in its literal form. The StatusChangeNotification conjunct
// passes; only the deletion conjunct fails. Re-enable when close runs on the expiry path.
// Coverage verifies-marker WITHHELD while the test is DISABLED_: it names
// AC-SVR-SUB-GEN-033-CLOSE-DELETES-ITEMS. A live marker on a test that never runs claims
// verification nothing performs. Restore it with the leading marker syntax in the same change that
// re-enables the test.
// The macro must stay on one line: the traceability tooling matches a single-line
// TEST_F and reads a wrapped one as a test that does not exist.
// clang-format off
TEST_F(ComplianceSubscriptionMonitoredItemCapped, LifetimeExpiryDeletesMonitoredItemsAndIssuesBadTimeout)
// clang-format on
{
  const uint32_t cap = mMaxMonitoredItemsServerWide;
  ASSERT_GT(cap, 0u);

  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  const auto lifetimeMs =
    static_cast<int64_t>(createResp.revised_lifetime_count() * createResp.revised_publishing_interval());
  ASSERT_GT(lifetimeMs, 0);

  // Consume the whole server-wide budget on this Subscription.
  for (uint32_t handle = 1; handle <= cap; ++handle)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subId, mVariableId, {.clientHandle = handle}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good())
      << "could not fill the MonitoredItem budget at item " << handle << ": "
      << to_string(miResp.results()[0].status_code());
  }

  // The budget really is exhausted - otherwise the refill after expiry would prove nothing.
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subId, mVariableId, {.clientHandle = cap + 1}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_EQ(miResp.results()[0].status_code(), StatusCode{Status::BadTooManyMonitoredItems})
      << "the server-wide MonitoredItem budget is not being enforced";
  }

  // No Publish request and no service call: the lifetime counter runs out.
  std::this_thread::sleep_for(std::chrono::milliseconds{lifetimeMs + 800});

  // Conjunct one: the StatusChangeNotification carrying Bad_Timeout.
  auto scn = wait_for_status_change(*mSession, subId, 3s);
  ASSERT_TRUE(scn) << "no StatusChangeNotification was issued when the Subscription's lifetime expired";
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout});

  // Conjunct two: its MonitoredItems are gone - a fresh Subscription can claim every slot they
  // held. If they survived their Subscription they would still be sampling, and still counted.
  auto secondResp = mSession->subscriptions().create_subscription_sync(build_subscription_request());
  ASSERT_THAT(secondResp, ServiceResultIsGood());
  const auto secondSubId = secondResp.subscription_id();
  ASSERT_NE(secondSubId, subId);

  for (uint32_t handle = 1; handle <= cap; ++handle)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(secondSubId, mVariableId, {.clientHandle = handle}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    EXPECT_TRUE(miResp.results()[0].status_code().is_good())
      << "item " << handle << " of " << cap << " was refused with "
      << to_string(miResp.results()[0].status_code())
      << " - the expired Subscription's MonitoredItems still hold their slots, so they were not "
         "deleted when it closed";
  }

  // The budget is still being counted, so the successes above are freed slots rather than a
  // limit that quietly stopped applying.
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(secondSubId, mVariableId, {.clientHandle = cap + 1}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    EXPECT_EQ(miResp.results()[0].status_code(), StatusCode{Status::BadTooManyMonitoredItems});
  }
}

/// Part 4 section 5.13.2: the revised lifetime must be at least three keep-alive intervals long
/// - the statement in time of the count relation revisedLifetimeCount >= 3 x
/// revisedMaxKeepAliveCount. The two are only equivalent while both counts are measured against
/// the same publishing interval, so a server that revises the keep-alive count against the
/// requested interval and the lifetime count against the granted one satisfies the count
/// relation and still closes a Subscription before three keep-alives have gone unanswered.
/// Measuring the keep-alive cadence the Subscription actually runs at, rather than trusting the
/// counts, is what distinguishes them.
// @verifies AC-SVR-SUB-GEN-035-LIFETIME-INTERVAL-MINIMUM
TEST_F(ComplianceWithNodes, RevisedLifetimeIsAtLeastThreeKeepAliveIntervalsInTime)
{
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 30, .keepAliveCount = 5}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  const auto revisedInterval = createResp.revised_publishing_interval();
  ASSERT_GT(revisedInterval, 0.0);
  ASSERT_GT(createResp.revised_max_keep_alive_count(), 0u);

  const double declaredKeepAliveMs = createResp.revised_max_keep_alive_count() * revisedInterval;
  const double declaredLifetimeMs = createResp.revised_lifetime_count() * revisedInterval;
  EXPECT_GE(declaredLifetimeMs, 3.0 * declaredKeepAliveMs)
    << "the revised lifetime is " << declaredLifetimeMs << "ms and a keep-alive interval is "
    << declaredKeepAliveMs << "ms";

  // The first message is owed immediately after CreateSubscription, so it says nothing about
  // the cadence; discard it and time the keep-alives that follow.
  auto first = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_THAT(first, ServiceResultIsGood());

  constexpr int samples = 3;
  const auto measureStart = std::chrono::steady_clock::now();
  for (int i = 0; i < samples; ++i)
  {
    auto pub = mSession->subscriptions().publish_sync(PublishRequest{});
    ASSERT_THAT(pub, ServiceResultIsGood()) << "keep-alive " << i;
    ASSERT_EQ(pub.subscription_id(), subId);
    ASSERT_TRUE(pub.notification_message().notification_data().empty())
      << "expected a keep-alive: the Subscription has no monitored items";
  }
  const auto measuredKeepAliveMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - measureStart)
      .count() /
    samples;
  ASSERT_GE(measuredKeepAliveMs, static_cast<int64_t>(revisedInterval))
    << "keep-alives arrived every " << measuredKeepAliveMs << "ms, faster than one publishing cycle ("
    << revisedInterval << "ms) - that is not a keep-alive cadence and nothing can be measured against it";

  // The revised lifetime, in time, against the keep-alive interval actually being run.
  EXPECT_GE(declaredLifetimeMs, 3.0 * static_cast<double>(measuredKeepAliveMs))
    << "the revised lifetime is " << declaredLifetimeMs << "ms but the Subscription keep-alives every "
    << measuredKeepAliveMs << "ms, so it is shorter than three keep-alive intervals";

  // And in practice: after just under three keep-alive intervals of silence - no Publish
  // request, no service call - the Subscription must still be open.
  const auto silenceMs = 3 * measuredKeepAliveMs - 200;
  ASSERT_GT(silenceMs, 0);
  std::this_thread::sleep_for(std::chrono::milliseconds{silenceMs});

  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = 0;
  auto rep = mSession->subscriptions().try_republish_sync(std::move(req));
  const auto status = rep.is_good() ? rep.value().response_header().service_result() : rep.status_code();
  EXPECT_NE(status, StatusCode{Status::BadSubscriptionIdInvalid})
    << "the Subscription was closed after " << silenceMs << "ms, which is less than three of its "
    << measuredKeepAliveMs << "ms keep-alive intervals";
}

// ===========================================================================
// Publish arbitration, retransmission-queue capacity and parameter revision
// (Part 4 section 5.13)
// ===========================================================================

/// Part 4 section 5.13.2: the subscriptionId "shall be unique for the entire Server, not just for
/// the Session, in order to allow the Subscription to be transferred to another Session using the
/// TransferSubscriptions service". A counter kept alongside the Session's own Subscription table is
/// the natural implementation and satisfies every single-Session check - the collision only shows up
/// when two Sessions allocate in step, and it makes the id TransferSubscriptions names ambiguous
/// precisely when a client is reconnecting.
// @verifies AC-SVR-SUB-GEN-070-SUBSCRIPTIONID-SERVER-UNIQUE
TEST_F(ComplianceWithNodes, SubscriptionIdsAreUniqueAcrossSessionsNotOnlyWithinOne)
{
  auto channelB = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto sessionB = channelB.create_session_sync({.sessionName = "SubIdUniquenessB"});
  sessionB.activate_sync();

  auto channelC = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto sessionC = channelC.create_session_sync({.sessionName = "SubIdUniquenessC"});
  sessionC.activate_sync();

  // Allocate in step across the three Sessions. A per-Session counter hands each of them the same
  // sequence, so the collision is between the n-th id issued to one Session and the n-th issued to
  // another - which interleaving is what exposes.
  Session* sessions[] = {&*mSession, &sessionB, &sessionC};
  constexpr int rounds = 3;

  std::vector<uint32_t> ids;
  for (int round = 0; round < rounds; ++round)
  {
    for (auto* session : sessions)
    {
      auto resp = session->subscriptions().create_subscription_sync(build_subscription_request());
      ASSERT_THAT(resp, ServiceResultIsGood()) << "CreateSubscription failed in round " << round;
      EXPECT_NE(resp.subscription_id(), 0u) << "0 is not a valid SubscriptionId";
      ids.push_back(resp.subscription_id());
    }
  }

  ASSERT_EQ(ids.size(), static_cast<std::size_t>(rounds * 3));
  const std::set<uint32_t> distinct(ids.begin(), ids.end());
  ASSERT_FALSE(distinct.empty());
  EXPECT_EQ(distinct.size(), ids.size())
    << "a SubscriptionId recurred across Sessions: " << ids.size()
    << " Subscriptions were created on 3 Sessions but the Server issued only " << distinct.size()
    << " distinct ids, so the id is unique only within a Session";

  (void)sessionB.try_close_sync();
  (void)channelB.try_close_sync();
  (void)sessionC.try_close_sync();
  (void)channelC.try_close_sync();
}

/// Part 4 sections 5.13.2 and 5.13.3: requestedMaxKeepAliveCount 0 is a request for the smallest
/// keep-alive count the Server supports - not an error and not a literal. A server that rejects it
/// fails a conforming request; one that honours it literally emits a keep-alive on every publishing
/// cycle. The rule is restated under ModifySubscription because the two paths revise independently,
/// so an implementation can get Create right and still reject the zero, or silently leave the
/// current count in place, on Modify.
// @verifies AC-SVR-SUB-GEN-114-KEEPALIVE-ZERO
TEST_F(ComplianceWithNodes, ZeroKeepAliveCountIsRevisedToTheSmallestSupportedOnCreateAndOnModify)
{
  // Reference point: 1 is the smallest count a client can legally ask for, so whatever the Server
  // grants for it IS the smallest keep-alive count the Server supports.
  auto smallestResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 30, .keepAliveCount = 1}));
  ASSERT_THAT(smallestResp, ServiceResultIsGood());
  const auto smallest = smallestResp.revised_max_keep_alive_count();
  ASSERT_GT(smallest, 0u);

  // --- Create ---
  auto createResult = mSession->subscriptions().try_create_subscription_sync(
    build_subscription_request({.lifetimeCount = 30, .keepAliveCount = 0}));
  ASSERT_TRUE(createResult.is_good()) << "CreateSubscription with requestedMaxKeepAliveCount 0 failed: "
                                      << to_string(createResult.status_code());
  ASSERT_THAT(createResult.value(), ServiceResultIsGood())
    << "requestedMaxKeepAliveCount 0 is a revisable parameter, not an error";
  ASSERT_NE(createResult.value().subscription_id(), 0u);
  EXPECT_NE(createResult.value().revised_max_keep_alive_count(), 0u)
    << "zero was accepted literally on CreateSubscription - the Subscription would send a keep-alive "
       "on every publishing cycle";
  EXPECT_EQ(createResult.value().revised_max_keep_alive_count(), smallest)
    << "CreateSubscription revised requestedMaxKeepAliveCount 0 to "
    << createResult.value().revised_max_keep_alive_count() << " rather than to the smallest supported "
    << "count (" << smallest << ")";

  // --- Modify ---
  // Modify a Subscription that currently holds a LARGER count, so that a server which simply leaves
  // the negotiated value alone is distinguishable from one that revises the zero.
  auto modifiableResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.lifetimeCount = 60, .keepAliveCount = 10}));
  ASSERT_THAT(modifiableResp, ServiceResultIsGood());
  ASSERT_GT(modifiableResp.revised_max_keep_alive_count(), smallest)
    << "the Server granted the same keep-alive count for a request of 10 as for a request of 1, so a "
       "revision on Modify could not be told from leaving the value untouched";

  ModifySubscriptionRequest modReq;
  modReq.subscription_id() = modifiableResp.subscription_id();
  modReq.requested_publishing_interval() = 100.0;
  modReq.requested_lifetime_count() = 60;
  modReq.requested_max_keep_alive_count() = 0;
  modReq.max_notifications_per_publish() = 0;
  auto modResult = mSession->subscriptions().try_modify_subscription_sync(std::move(modReq));
  ASSERT_TRUE(modResult.is_good()) << "ModifySubscription with requestedMaxKeepAliveCount 0 failed: "
                                   << to_string(modResult.status_code());
  ASSERT_THAT(modResult.value(), ServiceResultIsGood())
    << "requestedMaxKeepAliveCount 0 is revisable on ModifySubscription too, not an error";
  EXPECT_NE(modResult.value().revised_max_keep_alive_count(), 0u)
    << "zero was accepted literally on ModifySubscription";
  EXPECT_EQ(modResult.value().revised_max_keep_alive_count(), smallest)
    << "ModifySubscription revised requestedMaxKeepAliveCount 0 to "
    << modResult.value().revised_max_keep_alive_count() << " rather than to the smallest supported count ("
    << smallest << ")";
}

/// Part 4 section 5.13.1.1: "The Session shall maintain a retransmission queue size of at least two
/// times the number of Publish requests per Session the Server supports." A queue sized to the
/// request limit alone answers every republish-what-I-just-received test and still evicts exactly
/// the messages a reconnecting client is trying to recover, so the client detects a gap it can never
/// fill. Producing 2x the limit of unacknowledged NotificationMessages and then asking for the
/// OLDEST is what separates the two sizes.
// @verifies AC-SVR-SUB-GEN-051-QUEUE-SIZE-MINIMUM
TEST_F(ComplianceSubscriptionLimited, RetransmissionQueueHoldsTwiceThePublishRequestLimit)
{
  const std::size_t required = 2u * static_cast<std::size_t>(mMaxPublishRequestsPerSession);
  ASSERT_GT(required, 0u);

  auto subId = create_subscription(*mSession, {.publishingInterval = 100.0});
  ASSERT_NE(subId, 0u);
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subId, mVariableId, {.clientHandle = 1, .samplingInterval = 0.0}));
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  // Fill the queue with exactly 2x the per-Session Publish-request limit of NotificationMessages,
  // acknowledging none of them. Keep-alives carry no NotificationMessage and are not retained, so
  // only data-bearing responses are counted.
  std::vector<uint32_t> seqNums;
  std::set<uint32_t> availableAtFill;
  for (int32_t value = 1; value <= 40 && seqNums.size() < required; ++value)
  {
    write_value_async(*mSession, mVariableId, Variant{int32_t{value}});
    std::this_thread::sleep_for(std::chrono::milliseconds{150});
    auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
    ASSERT_THAT(resp, ServiceResultIsGood());
    if (resp.notification_message().notification_data().empty())
      continue;
    seqNums.push_back(resp.notification_message().sequence_number());
    availableAtFill.clear();
    for (auto available : resp.available_sequence_numbers())
      availableAtFill.insert(available);
  }
  ASSERT_EQ(seqNums.size(), required)
    << "could not produce " << required << " unacknowledged NotificationMessages, so nothing about the "
    << "retransmission-queue capacity can be concluded";

  // Every one of the 2x messages is still being offered to the client.
  ASSERT_FALSE(availableAtFill.empty()) << "the Server offered no available sequence numbers at all after "
                                        << required << " unacknowledged NotificationMessages";
  for (auto seq : seqNums)
  {
    EXPECT_TRUE(availableAtFill.count(seq) > 0)
      << "unacknowledged sequence number " << seq << " was dropped from available_sequence_numbers "
      << "while only " << required << " messages were outstanding - the retransmission queue is "
      << "smaller than twice the per-Session Publish request limit of " << mMaxPublishRequestsPerSession;
  }

  // And the oldest is genuinely retrievable, not merely advertised.
  RepublishRequest repReq;
  repReq.subscription_id() = subId;
  repReq.retransmit_sequence_number() = seqNums.front();
  auto repResult = mSession->subscriptions().try_republish_sync(std::move(repReq));
  ASSERT_TRUE(repResult.is_good()) << to_string(repResult.status_code());
  EXPECT_THAT(repResult.value(), ServiceResultIsGood())
    << "the oldest of " << required << " unacknowledged NotificationMessages had already been evicted";
  EXPECT_EQ(repResult.value().notification_message().sequence_number(), seqNums.front())
    << "Republish of the oldest retained sequence number returned a different message";
}

/// Part 4 section 5.13.1.1: when more than one Subscription needs to send Notifications, the Server
/// de-queues a Publish request to the Subscription with the highest priority number. A dispatcher
/// that walks its Subscription table in creation or id order looks correct whenever the client
/// happened to create the important Subscription first, so the priority has to run against that
/// order for the arbitration to be visible at all - and the lower-priority Subscription must be
/// shown to have had a Notification waiting, or "the high one went first" says nothing.
// @verifies AC-SVR-SUB-GEN-060-PRIORITY-ORDER
TEST_F(ComplianceWithNodes, HighestPrioritySubscriptionConsumesTheOnlyAvailablePublishRequest)
{
  auto carriesHandle = [](const DataChangeNotification& dc, uint32_t handle)
  {
    for (const auto& mi : dc.monitored_items())
    {
      if (mi.client_handle() == handle)
        return true;
    }
    return false;
  };

  // The LOW-priority Subscription is created FIRST, so it holds the lower SubscriptionId and comes
  // first in any creation-ordered or id-ordered walk of the Session's Subscriptions.
  auto lowResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = 100.0, .lifetimeCount = 120, .keepAliveCount = 30, .priority = 0}));
  ASSERT_THAT(lowResp, ServiceResultIsGood());
  const auto lowSubId = lowResp.subscription_id();
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(lowSubId, mWritableVariableId, {.clientHandle = 60, .samplingInterval = 0.0}));
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  auto highResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = 100.0, .lifetimeCount = 120, .keepAliveCount = 30, .priority = 200}));
  ASSERT_THAT(highResp, ServiceResultIsGood());
  const auto highSubId = highResp.subscription_id();
  ASSERT_NE(highSubId, lowSubId);
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
      highSubId, mFullAccessVariableId, {.clientHandle = 61, .samplingInterval = 0.0}));
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  // Drain the initial-value Notifications both Subscriptions owe, so that the writes below are the
  // only thing either of them has to say when the single Publish request is offered.
  for (int i = 0; i < 8; ++i)
    (void)mSession->subscriptions().try_publish_sync(PublishRequest{});

  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{777}});
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{888}});
  std::this_thread::sleep_for(std::chrono::milliseconds{400});

  // Exactly one Publish request is made available while both Subscriptions have Notifications ready.
  auto first = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_THAT(first, ServiceResultIsGood());
  EXPECT_EQ(first.subscription_id(), highSubId)
    << "the single available Publish request was taken by subscription " << first.subscription_id()
    << "; priority 200 was granted to " << highSubId << " and priority 0 to " << lowSubId;
  const auto* firstDcn = as_data_change(first);
  ASSERT_NE(firstDcn, nullptr)
    << "the Publish request was answered with no DataChangeNotification although both Subscriptions "
       "had one ready";
  ASSERT_FALSE(firstDcn->monitored_items().empty());
  EXPECT_TRUE(carriesHandle(*firstDcn, 61u))
    << "the served Notification did not come from the higher-priority Subscription's monitored item";

  // The lower-priority Subscription really did have a Notification waiting when that request was
  // arbitrated: nothing further is written, yet it delivers a DataChangeNotification on the next
  // request, so the one it delivers can only have been pending already.
  auto second = wait_for_publish(*mSession,
    [lowSubId](const PublishResponse& r)
    { return r.subscription_id() == lowSubId && as_data_change(r) != nullptr; });
  ASSERT_TRUE(second)
    << "the lower-priority Subscription had no Notification pending, so no arbitration took place "
       "and the first response proves nothing";
  const auto* secondDcn = as_data_change(*second);
  ASSERT_NE(secondDcn, nullptr);
  ASSERT_FALSE(secondDcn->monitored_items().empty());
  EXPECT_TRUE(carriesHandle(*secondDcn, 60u))
    << "the deferred Notification did not come from the lower-priority Subscription's monitored item";
}

/// Part 4 section 5.13.2.2: for Subscriptions of equal priority the Server de-queues Publish
/// requests in a round-robin fashion. Priority decides nothing between equals, so an implementation
/// that sorts by priority alone falls back on whatever order its Subscription table iterates in and
/// starves whichever equal Subscription that order visits last. The starvation is invisible while
/// there are at least as many Publish requests in flight as Subscriptions wanting one - every
/// Subscription is served in the same cycle and the ordering never matters.
// @verifies AC-SVR-SUB-GEN-061-EQUAL-PRIORITY-ROUND-ROBIN
TEST_F(ComplianceWithNodes, EqualPrioritySubscriptionsTakeFewerPublishRequestsInRotation)
{
  constexpr int subscriptions = 3;
  constexpr int requestsPerRound = 2;  // deliberately fewer than subscriptions
  constexpr int rounds = 4;

  std::vector<uint32_t> subIds;
  for (int i = 0; i < subscriptions; ++i)
  {
    auto resp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
      {.publishingInterval = 100.0, .lifetimeCount = 120, .keepAliveCount = 30, .priority = 5}));
    ASSERT_THAT(resp, ServiceResultIsGood()) << "CreateSubscription " << i;
    subIds.push_back(resp.subscription_id());

    // All three monitor the SAME Variable, so a single write leaves all three needing to publish in
    // the same cycle.
    auto miResp =
      mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(subIds.back(),
        mWritableVariableId,
        {.clientHandle = static_cast<uint32_t>(70 + i), .samplingInterval = 0.0}));
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }
  ASSERT_EQ(subIds.size(), static_cast<std::size_t>(subscriptions));
  ASSERT_EQ(std::set<uint32_t>(subIds.begin(), subIds.end()).size(), static_cast<std::size_t>(subscriptions))
    << "the Server issued duplicate SubscriptionIds; the rotation cannot be observed";

  // Drain the initial-value Notifications so each round starts from a quiet state.
  for (int i = 0; i < 8; ++i)
    (void)mSession->subscriptions().try_publish_sync(PublishRequest{});

  std::set<uint32_t> everServed;
  for (int round = 0; round < rounds; ++round)
  {
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{1000 + round}});
    std::this_thread::sleep_for(std::chrono::milliseconds{400});

    std::vector<uint32_t> servedThisRound;
    for (int request = 0; request < requestsPerRound; ++request)
    {
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      ASSERT_THAT(resp, ServiceResultIsGood()) << "round " << round << ", request " << request;
      EXPECT_FALSE(resp.notification_message().notification_data().empty())
        << "round " << round << ", request " << request
        << ": a Publish request was answered with a keep-alive although all " << subscriptions
        << " Subscriptions had Notifications ready";
      servedThisRound.push_back(resp.subscription_id());
      everServed.insert(resp.subscription_id());
    }

    ASSERT_EQ(servedThisRound.size(), static_cast<std::size_t>(requestsPerRound));
    EXPECT_NE(servedThisRound[0], servedThisRound[1])
      << "in round " << round << " both Publish requests went to subscription " << servedThisRound[0]
      << " while the other equal-priority Subscriptions also had Notifications ready - the requests "
         "are not being distributed in rotation";
  }

  // No Subscription is starved across cycles.
  ASSERT_FALSE(everServed.empty()) << "no Publish request was served to any Subscription";
  for (auto id : subIds)
  {
    EXPECT_TRUE(everServed.count(id) > 0)
      << "subscription " << id << " was never served across " << rounds << " rounds of " << requestsPerRound
      << " Publish requests, although it had Notifications ready in every one";
  }
}

// ===========================================================================
// Subscription close-out and per-operation service results (Part 4 section 5.13)
// ===========================================================================

/// Part 4 section 5.13.1.1(h): closing an expired Subscription is two obligations at once - a
/// StatusChangeNotification carrying Bad_Timeout is issued AND the Subscription's MonitoredItems are
/// deleted, so that no item survives to sample against a Subscription that no longer exists. The
/// notification is the half that is remembered; the deletion is the half with a resource cost, and an
/// implementation that drops the Subscription record without running its close leaves the items
/// charged against the server-wide MonitoredItem budget forever. Releasing exactly the expired
/// Subscription's items and no more is what separates a real deletion from a budget that was reset
/// wholesale or quietly stopped being enforced, which is why a second Subscription holds one slot
/// throughout and must still hold it at the end.
// @verifies AC-SVR-SUB-GEN-033-CLOSE-DELETES-ITEMS
TEST_F(ComplianceSubscriptionMonitoredItemCapped, ExpiredSubscriptionReleasesExactlyItsOwnMonitoredItems)
{
  const uint32_t cap = mMaxMonitoredItemsServerWide;
  ASSERT_GE(cap, 3u) << "the budget must hold one item for the surviving Subscription and at least two "
                        "for the Subscription whose lifetime expires";
  const uint32_t expiringItems = cap - 1;

  auto createItem = [&](uint32_t subscriptionId, uint32_t clientHandle)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subscriptionId, mVariableId, {.clientHandle = clientHandle}));
    EXPECT_THAT(miResp, ServiceResultIsGood());
    EXPECT_FALSE(miResp.results().empty());
    if (miResp.results().empty())
      return StatusCode{Status::BadInternalError};
    return miResp.results()[0].status_code();
  };

  // A Subscription that outlives the whole test and holds one slot of the budget throughout.
  const auto survivorSubId = create_subscription(
    *mSession, {.publishingInterval = 100.0, .lifetimeCount = 600, .keepAliveCount = 200});
  ASSERT_NE(survivorSubId, 0u);
  ASSERT_EQ(createItem(survivorSubId, 900u), StatusCode{Status::Good});

  // The Subscription under test takes the rest of the budget and is given a short lifetime.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto expiringSubId = createResp.subscription_id();
  ASSERT_NE(expiringSubId, 0u);
  const auto lifetimeMs =
    static_cast<int64_t>(createResp.revised_lifetime_count() * createResp.revised_publishing_interval());
  ASSERT_GT(lifetimeMs, 0);

  for (uint32_t handle = 1; handle <= expiringItems; ++handle)
  {
    ASSERT_EQ(createItem(expiringSubId, handle), StatusCode{Status::Good})
      << "could not fill the MonitoredItem budget at item " << handle << " of " << expiringItems;
  }

  // The budget really is exhausted, so the refill after expiry means something.
  EXPECT_EQ(createItem(survivorSubId, 901u), StatusCode{Status::BadTooManyMonitoredItems})
    << "the server-wide MonitoredItem budget is not being enforced";

  // No Publish request and no Service call naming it: the lifetime counter runs out.
  std::this_thread::sleep_for(std::chrono::milliseconds{lifetimeMs + 800});

  // Conjunct one: the StatusChangeNotification carrying Bad_Timeout.
  auto scn = wait_for_status_change(*mSession, expiringSubId, 3s);
  ASSERT_TRUE(scn) << "no StatusChangeNotification was issued when the Subscription's lifetime expired";
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout});

  // Conjunct two: its MonitoredItems were deleted with it. A fresh Subscription can claim exactly the
  // slots the expired one held - no more, because the surviving Subscription still holds its own.
  const auto freshSubId = create_subscription(*mSession, {.publishingInterval = 100.0});
  ASSERT_NE(freshSubId, 0u);
  ASSERT_NE(freshSubId, expiringSubId);

  for (uint32_t handle = 1; handle <= expiringItems; ++handle)
  {
    EXPECT_EQ(createItem(freshSubId, handle), StatusCode{Status::Good})
      << "slot " << handle << " of " << expiringItems
      << " was refused - the expired Subscription's MonitoredItems still hold their slots, so they "
         "were not deleted when it closed and they are still sampling against a Subscription that no "
         "longer exists";
  }

  // The budget is still being counted, so the successes above are released slots rather than a limit
  // that stopped applying: the surviving Subscription's own item is still charged against it.
  EXPECT_EQ(createItem(freshSubId, expiringItems + 1), StatusCode{Status::BadTooManyMonitoredItems})
    << "the server-wide MonitoredItem budget stopped applying, so the successes above prove no release";
}

/// Part 4 section 5.13.4.4: Bad_SubscriptionIdInvalid is an operation-level result of
/// SetPublishingMode - the service result stays Good and every other entry in the same call takes the
/// new mode. A loop that abandons the batch at its first unknown id answers a single-id request
/// perfectly and silently leaves each later Subscription publishing exactly as before, which
/// results[] alone cannot show: the status codes are right and the mode never changed. Putting the
/// unknown id between the two live ones, and then observing that both stopped publishing, is what
/// separates the two.
// @verifies AC-SVR-SUB-GEN-120-SETPUBLISHING-BADSUBSCRIPTIONID
TEST_F(ComplianceWithNodes, SetPublishingModeAppliesTheModeEitherSideOfAnUnknownSubscriptionId)
{
  constexpr uint32_t unknownSubId = 99999;

  auto [subA, miA] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {}, {.clientHandle = 81});
  auto [subB, miB] =
    create_subscription_with_monitored_item(*mSession, mFullAccessVariableId, {}, {.clientHandle = 82});
  ASSERT_NE(subA, 0u);
  ASSERT_NE(subB, 0u);
  ASSERT_NE(subA, subB);
  ASSERT_NE(subA, unknownSubId);
  ASSERT_NE(subB, unknownSubId);

  // Both Subscriptions draw on the one Publish queue and every response names exactly one of them,
  // so a wait that watches a single Subscription throws away the other's NotificationMessage while
  // it polls. Both are therefore decided from the same drain: the ids that delivered a data-bearing
  // NotificationMessage inside the window, whichever order the Server serves them in.
  auto dataBearingSubscriptions = [&](std::chrono::milliseconds window)
  {
    std::set<uint32_t> served;
    const auto deadline = std::chrono::steady_clock::now() + window;
    do
    {
      auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
      if (result.is_good() && result.value().response_header().service_result().is_good())
      {
        const auto& resp = result.value();
        const auto* dc = as_data_change(resp);
        if (dc != nullptr && !dc->monitored_items().empty())
        {
          served.insert(resp.subscription_id());
          if (served.count(subA) > 0 && served.count(subB) > 0)
            break;
          continue;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    while (std::chrono::steady_clock::now() < deadline);
    return served;
  };

  // Antecedent: both Subscriptions are publishing before the call, so the silence asserted below is
  // the new mode taking effect rather than a Subscription that never published at all.
  {
    const auto publishing = dataBearingSubscriptions(3s);
    ASSERT_GT(publishing.count(subA), 0u)
      << "subscription " << subA << " never published before publishing was disabled";
    ASSERT_GT(publishing.count(subB), 0u)
      << "subscription " << subB << " never published before publishing was disabled";
  }

  // The unknown id sits BETWEEN the two live ones.
  SetPublishingModeRequest disableReq;
  disableReq.publishing_enabled() = false;
  disableReq.subscription_ids().push_back(subA);
  disableReq.subscription_ids().push_back(unknownSubId);
  disableReq.subscription_ids().push_back(subB);
  auto disableResult = mSession->subscriptions().try_set_publishing_mode_sync(std::move(disableReq));
  ASSERT_TRUE(disableResult.is_good()) << to_string(disableResult.status_code());
  const auto& disableResp = disableResult.value();
  EXPECT_THAT(disableResp, ServiceResultIsGood())
    << "Bad_SubscriptionIdInvalid is operation-level in SetPublishingMode, not service-level: "
    << to_string(disableResp.response_header().service_result());
  ASSERT_EQ(disableResp.results().size(), static_cast<std::size_t>(3));
  EXPECT_EQ(disableResp.results()[0], StatusCode{Status::Good});
  EXPECT_EQ(disableResp.results()[1], StatusCode{Status::BadSubscriptionIdInvalid})
    << "the unknown SubscriptionId was not reported in its own slot";
  EXPECT_EQ(disableResp.results()[2], StatusCode{Status::Good});

  // Both live Subscriptions really took the new mode: a fresh write produces no NotificationMessage
  // on either of them.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{4242}});
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{5353}});

  {
    const auto publishing = dataBearingSubscriptions(1500ms);
    EXPECT_EQ(publishing.count(subA), 0u)
      << "subscription " << subA << " kept publishing although SetPublishingMode reported Good for it";
    EXPECT_EQ(publishing.count(subB), 0u)
      << "subscription " << subB
      << " kept publishing: the entry after the unknown SubscriptionId was never applied";
  }

  // And the mode is a pause, not a break - re-enabling over the same three ids restores both, which
  // is also what shows the silence above was the mode rather than two dead Subscriptions.
  SetPublishingModeRequest enableReq;
  enableReq.publishing_enabled() = true;
  enableReq.subscription_ids().push_back(subA);
  enableReq.subscription_ids().push_back(unknownSubId);
  enableReq.subscription_ids().push_back(subB);
  auto enableResult = mSession->subscriptions().try_set_publishing_mode_sync(std::move(enableReq));
  ASSERT_TRUE(enableResult.is_good()) << to_string(enableResult.status_code());
  const auto& enableResp = enableResult.value();
  EXPECT_THAT(enableResp, ServiceResultIsGood());
  ASSERT_EQ(enableResp.results().size(), static_cast<std::size_t>(3));
  EXPECT_EQ(enableResp.results()[0], StatusCode{Status::Good});
  EXPECT_EQ(enableResp.results()[1], StatusCode{Status::BadSubscriptionIdInvalid});
  EXPECT_EQ(enableResp.results()[2], StatusCode{Status::Good});

  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{6464}});
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{7575}});
  {
    const auto publishing = dataBearingSubscriptions(3s);
    EXPECT_GT(publishing.count(subA), 0u)
      << "subscription " << subA << " did not resume publishing when the mode was enabled again";
    EXPECT_GT(publishing.count(subB), 0u)
      << "subscription " << subB << " did not resume publishing when the mode was enabled again";
  }
}

/// Part 4 section 5.13.5: the acknowledgements ride on a Publish request and are answered one status
/// per acknowledgement in results[] - they must never fail the Publish itself. A stale acknowledgement
/// after a reconnect is entirely routine, so an implementation that raises an acknowledgement's error
/// to the service result stops the client publishing at all; and one that reports a single code for
/// the whole batch loses which acknowledgement was refused and why. The two refusals here have
/// different causes and different codes, so both slots are asserted, and the request must still be
/// answered for the Subscription it was queued against.
// @verifies AC-SVR-SUB-GEN-122-PUBLISH-ACK-CODES
TEST_F(ComplianceWithNodes, PublishReportsEachAcknowledgementSeparatelyAndStillServesItsSubscription)
{
  constexpr uint32_t unknownSubId = 99999;
  constexpr uint32_t unknownSequenceNumber = 424242;

  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {}, {.clientHandle = 1});
  ASSERT_NE(subId, 0u);
  ASSERT_NE(subId, unknownSubId);

  // Consume the initial-value NotificationMessage so the Publish below has a fresh one to carry.
  drain_initial_publish(*mSession, subId);
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{321}});
  std::this_thread::sleep_for(std::chrono::milliseconds{400});

  PublishRequest req;
  SubscriptionAcknowledgement unknownSubscription;
  unknownSubscription.subscription_id() = unknownSubId;
  unknownSubscription.sequence_number() = 1;
  req.subscription_acknowledgements().push_back(unknownSubscription);

  SubscriptionAcknowledgement unknownSequence;
  unknownSequence.subscription_id() = subId;
  unknownSequence.sequence_number() = unknownSequenceNumber;  // never sent for this Subscription
  req.subscription_acknowledgements().push_back(unknownSequence);

  auto result = mSession->subscriptions().try_publish_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  const auto& resp = result.value();
  EXPECT_THAT(resp, ServiceResultIsGood())
    << "a refused acknowledgement must not fail the Publish request carrying it: "
    << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), static_cast<std::size_t>(2))
    << "Publish must answer one status per acknowledgement";
  EXPECT_EQ(resp.results()[0], StatusCode{Status::BadSubscriptionIdInvalid})
    << "an acknowledgement naming an unknown SubscriptionId is not reported in its own slot";
  EXPECT_EQ(resp.results()[1], StatusCode{Status::BadSequenceNumberUnknown})
    << "an acknowledgement naming a sequence number the Server never sent is not reported in its own "
       "slot";

  // The Publish itself still served its Subscription.
  EXPECT_EQ(resp.subscription_id(), subId)
    << "the Publish carrying the refused acknowledgements was not used by the Subscription that had "
       "Notifications ready";
  const auto* dcn = as_data_change(resp);
  if (dcn == nullptr || dcn->monitored_items().empty())
  {
    auto later = wait_for_data_change(
      *mSession, subId, [](const DataChangeNotification& dc) { return !dc.monitored_items().empty(); }, 3s);
    EXPECT_TRUE(later) << "the Notification pending when the acknowledgements were refused was never "
                          "delivered - the refusals consumed the Publish without serving it";
  }
}

/// Part 4 section 5.13.8.3: DeleteSubscriptions is a batch Service, so an empty subscriptionIds[]
/// is refused at the service level with Bad_NothingToDo rather than answered Good with an empty
/// results[]. The refusal falls out of the first loop iteration only if the handler validates the
/// batch before iterating it, so the status is read off the service result. The companion
/// Bad_TooManyOperations of the same table is conditional on the Server imposing an operation limit
/// on subscriptionIds[]; Part 5 Table 19 defines no such limit and this Server advertises none, so
/// there is no over-limit batch to construct.
// @verifies AC-SVR-SUB-GEN-125-DELETE-SERVICE-CODES
TEST_F(ComplianceWithNodes, DeleteSubscriptionsRefusesAnEmptyList)
{
  DeleteSubscriptionsRequest req;  // no subscriptionIds

  auto result = mSession->subscriptions().try_delete_subscriptions_sync(std::move(req));

  // A service-level refusal may surface either as a decoded response carrying the status in its
  // header or as a request-level failure, depending on how the stack unwinds it.
  const auto serviceStatus =
    result.is_good() ? result.value().response_header().service_result() : result.status_code();
  EXPECT_EQ(serviceStatus, StatusCode{Status::BadNothingToDo})
    << "an empty subscriptionIds[] must be refused at the service level";
}

/// Part 4 section 5.13.8.4: within DeleteSubscriptions results[] an unknown or already-deleted
/// SubscriptionId carries Bad_SubscriptionIdInvalid while every other entry in the same batch still
/// takes effect. A teardown naming a Subscription that has already expired is routine, so an
/// implementation that abandons the batch at the first refusal - or raises it to the service result -
/// leaves the Subscriptions after it running and charging their resources. results[] alone cannot show
/// that: the status codes read correctly and the Subscription is still there, so the deletion has to
/// be confirmed against the Server afterwards.
// @verifies AC-SVR-SUB-GEN-126-DELETE-BADSUBSCRIPTIONID
TEST_F(ComplianceWithNodes, DeleteSubscriptionsDeletesTheLiveOneAndRefusesTheAlreadyDeletedOne)
{
  const auto goneSubId = create_subscription(*mSession);
  const auto liveSubId = create_subscription(*mSession);
  ASSERT_NE(goneSubId, 0u);
  ASSERT_NE(liveSubId, 0u);
  ASSERT_NE(goneSubId, liveSubId);

  // Make the first one genuinely gone through the real Service rather than inventing an id.
  {
    DeleteSubscriptionsRequest first;
    first.subscription_ids().push_back(goneSubId);
    auto firstResp = mSession->subscriptions().delete_subscriptions_sync(std::move(first));
    ASSERT_THAT(firstResp, ServiceResultIsGood());
    ASSERT_FALSE(firstResp.results().empty());
    ASSERT_TRUE(firstResp.results()[0].is_good());
  }

  // The already-deleted id comes FIRST, so a loop that abandons the batch on its first refusal leaves
  // the live Subscription untouched.
  DeleteSubscriptionsRequest req;
  req.subscription_ids().push_back(goneSubId);
  req.subscription_ids().push_back(liveSubId);
  auto result = mSession->subscriptions().try_delete_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  const auto& resp = result.value();
  EXPECT_THAT(resp, ServiceResultIsGood())
    << "Bad_SubscriptionIdInvalid is operation-level in DeleteSubscriptions, not service-level: "
    << to_string(resp.response_header().service_result());
  ASSERT_EQ(resp.results().size(), static_cast<std::size_t>(2));
  EXPECT_EQ(resp.results()[0], StatusCode{Status::BadSubscriptionIdInvalid})
    << "the already-deleted SubscriptionId was not reported in its own slot";
  EXPECT_EQ(resp.results()[1], StatusCode{Status::Good})
    << "the live Subscription was not deleted because an earlier entry in the batch was refused";

  // It really was deleted, not merely reported deleted: the Server no longer knows the id.
  ModifySubscriptionRequest modReq;
  modReq.subscription_id() = liveSubId;
  modReq.requested_publishing_interval() = 100.0;
  modReq.requested_lifetime_count() = 30;
  modReq.requested_max_keep_alive_count() = 10;
  modReq.max_notifications_per_publish() = 0;
  auto modResult = mSession->subscriptions().try_modify_subscription_sync(std::move(modReq));
  const auto modStatus =
    modResult.is_good() ? modResult.value().response_header().service_result() : modResult.status_code();
  EXPECT_EQ(modStatus, StatusCode{Status::BadSubscriptionIdInvalid})
    << "subscription " << liveSubId
    << " was reported deleted but the Server still accepts Service calls naming it";
}

/// Part 4 section 5.13.1.1(h), Table 85 row 27: when the lifetime counter runs out the Server executes
/// DeleteMonitoredItems() AND IssueStatusChangeNotification(Bad_Timeout). Forgetting the Subscription
/// record is enough to make the notification arrive and to make the client hear nothing further from it,
/// so an implementation that never runs the Subscription's close passes any test that only listens: the
/// items are still registered with their Namespace, still sampling, and still charged against the
/// server-wide MonitoredItem budget. The deletion is therefore observed on both of its consequences -
/// nothing is delivered any more for the dead Subscription or for the client handles of its items, and
/// the slots those items held can be claimed again - with a second Subscription publishing throughout so
/// that neither observation is the silence of a client that stopped asking.
// @verifies AC-SVR-SUB-GEN-033-CLOSE-DELETES-ITEMS
TEST_F(ComplianceSubscriptionMonitoredItemCapped, ExpiredSubscriptionDeletesItemsAndIssuesBadTimeout)
{
  const uint32_t cap = mMaxMonitoredItemsServerWide;
  ASSERT_GE(cap, 3u) << "the budget must hold one item for the surviving Subscription and at least two for "
                        "the Subscription whose lifetime expires";
  const uint32_t expiringItems = cap - 1;
  constexpr uint32_t survivorHandle = 900;

  auto createItem = [&](uint32_t subscriptionId, uint32_t clientHandle)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
      subscriptionId, mVariableId, {.clientHandle = clientHandle, .samplingInterval = 50.0}));
    EXPECT_THAT(miResp, ServiceResultIsGood());
    EXPECT_FALSE(miResp.results().empty());
    if (miResp.results().empty())
      return StatusCode{Status::BadInternalError};
    return miResp.results()[0].status_code();
  };

  // A Subscription that outlives the whole test: it holds one slot of the budget and keeps delivering
  // Notifications, so the window after the expiry is demonstrably carrying traffic.
  const SubscriptionOptions survivorOptions{
    .publishingInterval = 100.0, .lifetimeCount = 600, .keepAliveCount = 200};
  const auto survivorSubId = create_subscription(*mSession, survivorOptions);
  ASSERT_NE(survivorSubId, 0u);
  ASSERT_EQ(createItem(survivorSubId, survivorHandle), StatusCode{Status::Good});

  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto expiringSubId = createResp.subscription_id();
  ASSERT_NE(expiringSubId, 0u);
  ASSERT_NE(expiringSubId, survivorSubId);
  const auto lifetimeMs =
    static_cast<int64_t>(createResp.revised_lifetime_count() * createResp.revised_publishing_interval());
  ASSERT_GT(lifetimeMs, 0);

  // Client handles 1..expiringItems belong to the Subscription that is about to die; nothing else in this
  // test ever uses them, so any later Notification carrying one came from an item that outlived it.
  for (uint32_t handle = 1; handle <= expiringItems; ++handle)
  {
    ASSERT_EQ(createItem(expiringSubId, handle), StatusCode{Status::Good})
      << "could not fill the MonitoredItem budget at item " << handle << " of " << expiringItems;
  }

  // The budget really is exhausted, so the refill at the end means something.
  EXPECT_EQ(createItem(survivorSubId, survivorHandle + 1), StatusCode{Status::BadTooManyMonitoredItems})
    << "the server-wide MonitoredItem budget is not being enforced";

  // Antecedent: the doomed Subscription's items are sampling and delivering before the expiry.
  write_value_async(*mSession, mVariableId, Variant{int32_t{11}});
  auto beforeExpiry = wait_for_publish(
    *mSession,
    [expiringSubId](const PublishResponse& r)
    {
      if (r.subscription_id() != expiringSubId)
        return false;
      const auto* dc = as_data_change(r);
      return dc != nullptr && !dc->monitored_items().empty();
    },
    5s);
  ASSERT_TRUE(beforeExpiry) << "the Subscription whose lifetime is about to expire never delivered a "
                               "DataChangeNotification, so its items falling silent would prove nothing";

  // No Publish request and no Service call naming it: the lifetime counter runs out.
  std::this_thread::sleep_for(std::chrono::milliseconds{lifetimeMs + 800});

  // Conjunct one: the StatusChangeNotification carrying Bad_Timeout.
  auto scn = wait_for_status_change(*mSession, expiringSubId, 3s);
  ASSERT_TRUE(scn) << "no StatusChangeNotification was issued when the Subscription's lifetime expired";
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout});

  // Conjunct two, first half: no item survives to sample against a Subscription that no longer exists.
  // The Variable keeps changing throughout and the surviving Subscription keeps reporting it, so the
  // absence of the dead Subscription's Notifications is measured inside a window that is carrying data.
  bool survivorDelivered = false;
  int32_t value = 100;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{2000};
  while (std::chrono::steady_clock::now() < deadline)
  {
    write_value_async(*mSession, mVariableId, Variant{int32_t{value++}});
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    if (!result.is_good() || !result.value().response_header().service_result().is_good())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
      continue;
    }
    const auto& resp = result.value();
    const auto* dc = as_data_change(resp);
    if (dc == nullptr || dc->monitored_items().empty())
      continue;
    EXPECT_NE(resp.subscription_id(), expiringSubId)
      << "a DataChangeNotification was delivered for subscription " << expiringSubId
      << " after it timed out - its MonitoredItems are still sampling against a Subscription that no "
         "longer exists";
    for (const auto& mi : dc->monitored_items())
    {
      EXPECT_EQ(mi.client_handle(), survivorHandle)
        << "a Notification carried client handle " << mi.client_handle()
        << ", which belonged to a MonitoredItem of the expired Subscription - the item was not deleted "
           "when its Subscription closed";
      if (mi.client_handle() == survivorHandle)
        survivorDelivered = true;
    }
  }
  EXPECT_TRUE(survivorDelivered)
    << "the surviving Subscription delivered nothing at all in the window, so the absence of the expired "
       "Subscription's Notifications is the silence of a quiet Server rather than of a deleted item";

  // Conjunct two, second half: the slots those items held were released. A fresh Subscription can claim
  // exactly as many as the expired one held - no more, because the survivor still holds its own.
  const auto freshSubId = create_subscription(*mSession, {.publishingInterval = 100.0});
  ASSERT_NE(freshSubId, 0u);
  ASSERT_NE(freshSubId, expiringSubId);
  for (uint32_t handle = 1; handle <= expiringItems; ++handle)
  {
    EXPECT_EQ(createItem(freshSubId, survivorHandle + 10 + handle), StatusCode{Status::Good})
      << "slot " << handle << " of " << expiringItems
      << " was refused - the expired Subscription's MonitoredItems still hold their slots, so they were "
         "not deleted when it closed";
  }
  EXPECT_EQ(createItem(freshSubId, survivorHandle + 100), StatusCode{Status::BadTooManyMonitoredItems})
    << "the server-wide MonitoredItem budget stopped applying, so the successes above prove no release";
}

/// Part 4 section 5.13.4.3, Table 93: SetPublishingMode is a batch Service and carries the two service
/// faults every batch Service carries - an empty subscriptionIds[] is Bad_NothingToDo, and a
/// subscriptionIds[] longer than the Server's operation limit is Bad_TooManyOperations. Both are
/// pre-dispatch validation, decided before the batch is walked, so neither may reach an individual
/// Subscription. A handler that only ever loops over subscriptionIds[] answers an over-limit request Good
/// with one Bad_SubscriptionIdInvalid per unknown entry: the client is handed per-operation status codes
/// instead of a refusal, and every Subscription the batch did name has already taken the new publishing
/// mode by the time the Server would have decided it should not have accepted the request at all. The one
/// live Subscription is therefore placed at the head of the over-limit batch and its mode checked after.
// @verifies AC-SVR-SUB-GEN-119-SETPUBLISHINGMODE-SERVICE-ERRORS
TEST_F(ComplianceWithNodes, SetPublishingModeRefusesAnEmptyListAndAnOverLimitBatch)
{
  // Longer than every operation limit this Server advertises: MaxSubscriptions, MaxSubscriptionsPerSession
  // and the largest entry of ServerCapabilities.OperationLimits are all below this count, so no reading of
  // "the Server's operation limit" admits a subscriptionIds[] this long.
  constexpr std::size_t overLimitCount = 2000;

  // --- Bad_NothingToDo: the empty batch. ---
  {
    SetPublishingModeRequest emptyReq;
    emptyReq.publishing_enabled() = true;  // no subscriptionIds
    auto emptyResult = mSession->subscriptions().try_set_publishing_mode_sync(std::move(emptyReq));
    const auto emptyStatus = emptyResult.is_good() ? emptyResult.value().response_header().service_result()
                                                   : emptyResult.status_code();
    EXPECT_EQ(emptyStatus, StatusCode{Status::BadNothingToDo})
      << "an empty subscriptionIds[] must be refused at the service level";
  }

  // --- Bad_TooManyOperations: the over-limit batch. ---
  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {}, {.clientHandle = 55});
  ASSERT_NE(subId, 0u);

  // Antecedent: the Subscription is publishing before the call, so the check afterwards separates "the
  // batch was refused without touching it" from "this Subscription never published anything".
  drain_initial_publish(*mSession, subId);
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{1717}});
  auto beforeCall = wait_for_data_change(
    *mSession, subId, [](const DataChangeNotification& dc) { return !dc.monitored_items().empty(); }, 3s);
  ASSERT_TRUE(beforeCall) << "subscription " << subId
                          << " was not publishing before the over-limit call, so its publishing mode "
                             "afterwards says nothing about whether the batch was walked";

  SetPublishingModeRequest overLimit;
  overLimit.publishing_enabled() = false;
  overLimit.subscription_ids().push_back(subId);
  for (std::size_t i = 1; i < overLimitCount; ++i)
    overLimit.subscription_ids().push_back(static_cast<uint32_t>(100000 + i));
  ASSERT_EQ(static_cast<std::size_t>(overLimit.subscription_ids().size()), overLimitCount);

  auto result = mSession->subscriptions().try_set_publishing_mode_sync(std::move(overLimit));
  const auto serviceStatus =
    result.is_good() ? result.value().response_header().service_result() : result.status_code();
  EXPECT_EQ(serviceStatus, StatusCode{Status::BadTooManyOperations})
    << "a subscriptionIds[] of " << overLimitCount
    << " entries exceeds every operation limit this Server advertises and must be refused at the service "
       "level rather than walked entry by entry";

  // The refusal is pre-dispatch, so the Subscription named first in the batch cannot have taken the new
  // publishing mode.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{1818}});
  auto afterCall = wait_for_data_change(
    *mSession, subId, [](const DataChangeNotification& dc) { return !dc.monitored_items().empty(); }, 3s);
  EXPECT_TRUE(afterCall) << "subscription " << subId
                         << " stopped publishing: the over-limit request was applied entry by entry and "
                            "disabled it, although the Service must be refused before any Subscription is "
                            "touched";
}

// ===========================================================================
// The Subscription state machine as a whole (Part 4 section 5.13.1.2, Table 85)
// ===========================================================================

/// Part 4 section 5.13.1.2, Table 85: the Subscription's run-time behaviour is twenty-seven rows of
/// (state, event, condition) -> (actions, next state), and a Server conforms only if every row can be
/// reached and does what its row says. Implementations are written group by group, and the rows that get
/// dropped are the ones with no message of their own: the LATE state (#8, #10, #11, #12, #17) and the
/// keep-alive counter (#13, #15, #16) emit nothing a client can name, so a Server that simply answers
/// every Publish request the moment it has something to say passes every per-message test and has no LATE
/// state at all, while a Server that never leaves NORMAL still delivers keep-alives, merely on the wrong
/// cadence. Each row is therefore driven from the state it names and read off WHEN its response arrives:
/// answered inside a publishing cycle means LATE, answered only after the keep-alive counter has counted
/// down means KEEPALIVE, answered at the next cycle boundary means NORMAL. The table's own edges are the
/// only ones taken - every Subscription that no row closes is probed afterwards and must still be there,
/// and no Publish response outside rows #25/#27 may carry a StatusChangeNotification.
///
/// Row #23 (TransferSubscriptions with the Client validated) is the single row this endpoint cannot
/// reach: `validate_subscription_transfer` requires an authenticated channel
/// for an Anonymous user and this fixture publishes only MessageSecurityMode::None, so every cross-Session
/// transfer here is row #24. Row #23 is carried separately by SVR-XFER-SM-023 and its own criterion.
// @verifies AC-SVR-SUB-GEN-111-TABLE85
TEST_F(ComplianceSubscriptionLimited, Table85EveryTransitionRowIsDrivenToItsActionsAndNextState)
{
  auto since = [](std::chrono::steady_clock::time_point from)
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - from)
      .count();
  };

  auto republishStatus =
    [](ua::client::Session& session, uint32_t subscriptionId, uint32_t sequenceNumber) -> StatusCode
  {
    RepublishRequest req;
    req.subscription_id() = subscriptionId;
    req.retransmit_sequence_number() = sequenceNumber;
    auto result = session.subscriptions().try_republish_sync(std::move(req));
    return result.is_good() ? result.value().response_header().service_result() : result.status_code();
  };

  // The alive-probe of last resort: a Service call naming the id, whose parameters are the ones every
  // phase of this walk expects to find in place.
  auto modifyStatus = [](ua::client::Session& session, uint32_t subscriptionId) -> StatusCode
  {
    ModifySubscriptionRequest req;
    req.subscription_id() = subscriptionId;
    req.requested_publishing_interval() = 250.0;
    req.requested_lifetime_count() = 80;
    req.requested_max_keep_alive_count() = 6;
    req.max_notifications_per_publish() = 0;
    auto result = session.subscriptions().try_modify_subscription_sync(std::move(req));
    return result.is_good() ? result.value().response_header().service_result() : result.status_code();
  };

  auto deleteStatus = [](ua::client::Session& session, uint32_t subscriptionId) -> StatusCode
  {
    DeleteSubscriptionsRequest req;
    req.subscription_ids().push_back(subscriptionId);
    auto result = session.subscriptions().try_delete_subscriptions_sync(std::move(req));
    if (!result.is_good())
      return result.status_code();
    if (result.value().results().empty())
      return StatusCode{Status::BadInternalError};
    return result.value().results()[0];
  };

  auto setPublishingStatus = [this](uint32_t subscriptionId, bool enabled) -> StatusCode
  {
    SetPublishingModeRequest req;
    req.publishing_enabled() = enabled;
    req.subscription_ids().push_back(subscriptionId);
    auto result = mSession->subscriptions().try_set_publishing_mode_sync(std::move(req));
    if (!result.is_good())
      return result.status_code();
    if (result.value().results().empty())
      return StatusCode{Status::BadInternalError};
    return result.value().results()[0];
  };

  // =========================================================================
  // Rows #1, #3, #7, #9, #13, #15, #16, #17, #12, #11 - the publishing cycle and the keep-alive
  // counter, on a Subscription with no MonitoredItems so that "nothing to send" always holds.
  // =========================================================================
  auto createA = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 250.0, .lifetimeCount = 80, .keepAliveCount = 6}));
  ASSERT_THAT(createA, ServiceResultIsGood()) << "row #1/#3: CreateSubscription was refused outright";
  const auto subA = createA.subscription_id();
  ASSERT_NE(subA, 0u) << "row #3: a Subscription that reached NORMAL must carry an identifier";
  const auto intervalA = createA.revised_publishing_interval();
  const auto keepAliveA = createA.revised_max_keep_alive_count();
  ASSERT_GT(intervalA, 0.0);
  ASSERT_GT(keepAliveA, 2u) << "the keep-alive counter must have room to count down, or rows #15/#16 "
                               "cannot be told from row #11";
  const auto cycleA = static_cast<int64_t>(intervalA);
  const auto keepAliveWindowA = static_cast<int64_t>(keepAliveA * intervalA);

  // Row #7: NORMAL, timer, a Publish request queued and MessageSent==FALSE -> DequeuePublishReq(),
  // ReturnKeepAlive(), MessageSent=TRUE, still NORMAL. Row #3 leaves MessageSent FALSE, so this first
  // keep-alive is owed after ONE cycle; a Subscription that only ever keep-alives out of KEEPALIVE
  // answers after maxKeepAliveCount cycles instead.
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subA);
    EXPECT_TRUE(result.value().notification_message().notification_data().empty())
      << "row #7: the first message of a Subscription with no MonitoredItems is a keep-alive";
    EXPECT_EQ(as_status_change(result.value()), nullptr)
      << "no Table 85 row closes this Subscription at this point";
    EXPECT_LT(waited, 3 * cycleA)
      << "row #7: the first keep-alive took " << waited << "ms rather than about one publishing cycle ("
      << cycleA << "ms) - MessageSent was not FALSE after CreateSubscription, so the client waited the "
      << "whole keep-alive window of " << keepAliveWindowA << "ms for its first message";
  }

  // Row #9: NORMAL, timer, no Publish request queued, MessageSent==TRUE and nothing to send ->
  // StartPublishingTimer(), ResetKeepAliveCounter(), and the Subscription becomes KEEPALIVE. A cycle and
  // a half of silence is enough for the timer to find that state and too short for the counter to run out.
  std::this_thread::sleep_for(std::chrono::milliseconds{cycleA + cycleA / 2});

  // Rows #13, #16 and #15: in KEEPALIVE a Publish request is ENQUEUED (#13) and the keep-alive counter is
  // decremented cycle by cycle (#16) until it reaches one, at which point the queued request is dequeued
  // and answered with a keep-alive and the counter is reset (#15). The whole point is that the answer is
  // NOT immediate: a Subscription that answered straight away never entered KEEPALIVE at all.
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subA);
    EXPECT_TRUE(result.value().notification_message().notification_data().empty());
    EXPECT_EQ(as_status_change(result.value()), nullptr);
    EXPECT_GE(waited, 2 * cycleA) << "rows #9/#13/#16: the Publish request was answered in " << waited
                                  << "ms, inside two publishing " << "cycles of " << cycleA
                                  << "ms - it was not enqueued against a counting keep-alive counter, so "
                                  << "the Subscription never reached KEEPALIVE (its keep-alive window is "
                                  << keepAliveWindowA << "ms)";
  }

  // Row #15's ResetKeepAliveCounter(): the very next request must wait the full count again. Had the
  // counter been left at one, this request would have been answered on the following cycle.
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_TRUE(result.value().notification_message().notification_data().empty());
    EXPECT_GE(waited, 2 * cycleA)
      << "row #15: the keep-alive after a keep-alive arrived in " << waited
      << "ms - ResetKeepAliveCounter() did not run, so the counter stayed at one and the Subscription "
      << "keep-alives on every cycle instead of every " << keepAliveA;
  }

  // Rows #17 and #12, read through row #11: with no Publish request queued the counter runs down to one
  // and the Subscription goes LATE (#17), where each further timer leaves it LATE (#12). A request
  // arriving in LATE is answered from the state, not from the timer (#11), so it comes back at once.
  std::this_thread::sleep_for(std::chrono::milliseconds{keepAliveWindowA + 3 * cycleA});
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subA);
    EXPECT_TRUE(result.value().notification_message().notification_data().empty())
      << "row #11: a Publish request taken in LATE with nothing to send is answered with a keep-alive";
    EXPECT_EQ(as_status_change(result.value()), nullptr);
    EXPECT_LT(waited, 2 * cycleA)
      << "rows #17/#12/#11: the request waited " << waited << "ms after " << (keepAliveWindowA + 3 * cycleA)
      << "ms of silence - the Subscription did not fall into LATE when its keep-alive counter reached "
      << "one, or did not stay there across the cycles that followed";
  }
  ASSERT_EQ(deleteStatus(*mSession, subA), StatusCode{Status::Good});

  // =========================================================================
  // Rows #8, #10 and #12 - LATE entered with Notifications waiting.
  // =========================================================================
  auto createB = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 500.0, .lifetimeCount = 60, .keepAliveCount = 10}));
  ASSERT_THAT(createB, ServiceResultIsGood());
  const auto subB = createB.subscription_id();
  ASSERT_NE(subB, 0u);
  const auto cycleB = static_cast<int64_t>(createB.revised_publishing_interval());
  ASSERT_GT(cycleB, 0);
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subB, mVariableId, {.clientHandle = 200, .samplingInterval = 100.0}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  // Row #8: NORMAL, timer, no Publish request queued and either MessageSent==FALSE or Notifications
  // available -> LATE. Row #10: a request arriving in LATE with Notifications is answered from them at
  // once. No Publish is sent for a cycle and a half, so the timer has to take the row-#8 edge.
  std::this_thread::sleep_for(std::chrono::milliseconds{cycleB + cycleB / 2});
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subB);
    const auto* dcn = as_data_change(result.value());
    ASSERT_NE(dcn, nullptr) << "row #10: the request taken in LATE returned no Notifications although the "
                               "MonitoredItem's initial value was waiting";
    EXPECT_FALSE(dcn->monitored_items().empty());
    EXPECT_EQ(as_status_change(result.value()), nullptr);
    EXPECT_LT(waited, cycleB / 4)
      << "rows #8/#10: the request waited " << waited << "ms of a " << cycleB
      << "ms cycle - the Subscription held its Notifications for the next timer instead of entering LATE "
         "and answering out of it";
  }

  // Row #12: LATE, timer expires -> StartPublishingTimer(), still LATE. Three and a half cycles pass with
  // Notifications waiting and no Publish request; if any of those timers moved the Subscription out of
  // LATE the request below would be paced by the cycle rather than answered on arrival.
  write_value_async(*mSession, mVariableId, Variant{int32_t{12}});
  std::this_thread::sleep_for(std::chrono::milliseconds{3 * cycleB + cycleB / 2});
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subB);
    const auto* dcn = as_data_change(result.value());
    EXPECT_NE(dcn, nullptr) << "row #12: the Notifications waiting through the LATE cycles were lost";
    if (dcn != nullptr)
      EXPECT_FALSE(dcn->monitored_items().empty());
    EXPECT_EQ(as_status_change(result.value()), nullptr);
    EXPECT_LT(waited, cycleB / 4) << "row #12: after " << (3 * cycleB + cycleB / 2)
                                  << "ms of LATE cycles the request waited " << waited
                                  << "ms - a timer expiring in LATE must leave the Subscription in LATE";
  }
  ASSERT_EQ(deleteStatus(*mSession, subB), StatusCode{Status::Good});

  // =========================================================================
  // Row #14 - KEEPALIVE, timer, Notifications available with a request queued -> the Notifications go out
  // on that request and the Subscription returns to NORMAL, instead of the client waiting out the
  // keep-alive counter.
  // =========================================================================
  auto createF = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 250.0, .lifetimeCount = 100, .keepAliveCount = 12}));
  ASSERT_THAT(createF, ServiceResultIsGood());
  const auto subF = createF.subscription_id();
  ASSERT_NE(subF, 0u);
  const auto cycleF = static_cast<int64_t>(createF.revised_publishing_interval());
  const auto keepAliveF = createF.revised_max_keep_alive_count();
  ASSERT_GT(cycleF, 0);
  ASSERT_GT(keepAliveF, 5u) << "the keep-alive window must be several cycles wide for row #14 to be "
                               "separable from rows #15/#16";
  const auto keepAliveWindowF = static_cast<int64_t>(keepAliveF * createF.revised_publishing_interval());
  {
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    ASSERT_TRUE(result.value().notification_message().notification_data().empty());
  }
  std::this_thread::sleep_for(std::chrono::milliseconds{cycleF + cycleF / 2});
  // Creating a MonitoredItem is not a Table 85 event, so the Subscription stays where row #9 left it; the
  // item simply makes Notifications available while it sits in KEEPALIVE.
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subF, mVariableId, {.clientHandle = 300, .samplingInterval = 0.0}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }
  {
    const auto issuedAt = std::chrono::steady_clock::now();
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    EXPECT_EQ(result.value().subscription_id(), subF);
    const auto* dcn = as_data_change(result.value());
    EXPECT_NE(dcn, nullptr) << "row #14: the request queued in KEEPALIVE was answered with a keep-alive "
                               "although Notifications had become available";
    if (dcn != nullptr)
      EXPECT_FALSE(dcn->monitored_items().empty());
    EXPECT_LT(waited, 5 * cycleF) << "row #14: the Notifications took " << waited
                                  << "ms to reach the queued request - the keep-alive "
                                  << "counter was allowed to run down first (its window is "
                                  << keepAliveWindowF
                                  << "ms), so data waits on a counter that has nothing to do with it";
  }
  ASSERT_EQ(deleteStatus(*mSession, subF), StatusCode{Status::Good});

  // =========================================================================
  // Rows #6, #20, #21, #4, #5 and #19 - the Notification-bearing rows and the two Service rows that
  // change the Subscription without changing its state.
  // =========================================================================
  auto createC = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 500.0,
      .lifetimeCount = 60,
      .keepAliveCount = 10,
      .maxNotificationsPerPublish = 1}));
  ASSERT_THAT(createC, ServiceResultIsGood());
  const auto subC = createC.subscription_id();
  ASSERT_NE(subC, 0u);
  const auto cycleC = static_cast<int64_t>(createC.revised_publishing_interval());
  ASSERT_GT(cycleC, 0);
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
      subC, mVariableId, {.clientHandle = 400, .samplingInterval = 0.0, .queueSize = 10}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  // Row #6: NORMAL, timer, a Publish request queued with Notifications available -> ResetLifetimeCounter(),
  // DequeuePublishReq(), ReturnNotifications(), still NORMAL.
  uint32_t seqC = 0;
  {
    write_value_async(*mSession, mVariableId, Variant{int32_t{41}});
    auto pub = wait_for_publish(
      *mSession,
      [subC](const PublishResponse& r)
      {
        const auto* dc = as_data_change(r);
        return r.subscription_id() == subC && dc != nullptr && !dc->monitored_items().empty();
      },
      5s);
    ASSERT_TRUE(pub) << "row #6: a Publish request queued against a Subscription with Notifications "
                        "available was never answered with them";
    seqC = pub->notification_message().sequence_number();
    EXPECT_GE(seqC, 1u);
    EXPECT_EQ(as_status_change(*pub), nullptr);
  }

  // Row #20: Republish naming a message the Server still holds -> ResetLifetimeCounter(), the message is
  // returned. This is also what makes row #4's deletion below falsifiable.
  EXPECT_EQ(republishStatus(*mSession, subC, seqC), StatusCode{Status::Good})
    << "row #20: sequence number " << seqC << " was delivered a moment ago and must be retransmittable";

  // Row #21: Republish naming a message the Server does not hold -> ResetLifetimeCounter() and a negative
  // response. The row changes nothing else, so the message that IS held is still held afterwards.
  EXPECT_EQ(republishStatus(*mSession, subC, 987654u), StatusCode{Status::BadMessageNotAvailable})
    << "row #21: an unknown retransmitSequenceNumber must be refused, not answered";
  EXPECT_EQ(republishStatus(*mSession, subC, seqC), StatusCode{Status::Good})
    << "row #21: the refused Republish disturbed the Subscription - the row returns a negative response "
       "and takes no other action";

  // Row #4: NORMAL, Publish request received while MoreNotifications is FALSE ->
  // DeleteAckedNotificationMsgs() and the request is enqueued. The acknowledged message really is
  // discarded: it was retransmittable on the line above and must not be on the line below.
  {
    PublishRequest ackReq;
    SubscriptionAcknowledgement ack;
    ack.subscription_id() = subC;
    ack.sequence_number() = seqC;
    ackReq.subscription_acknowledgements().push_back(ack);
    auto result = mSession->subscriptions().try_publish_sync(std::move(ackReq));
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    ASSERT_FALSE(result.value().results().empty());
    EXPECT_EQ(result.value().results()[0], StatusCode{Status::Good})
      << "row #4: the acknowledgement of a message the Server had just delivered was refused";
    for (auto available : result.value().available_sequence_numbers())
    {
      EXPECT_NE(available, seqC) << "row #4: acknowledged sequence number " << seqC
                                 << " is still offered in availableSequenceNumbers";
    }
  }
  EXPECT_EQ(republishStatus(*mSession, subC, seqC), StatusCode{Status::BadMessageNotAvailable})
    << "row #4: DeleteAckedNotificationMsgs() did not discard sequence number " << seqC
    << " - the retransmission queue grows for the whole life of the Subscription";

  // Row #5: NORMAL, Publish request received while MoreNotifications is TRUE -> ResetLifetimeCounter() and
  // ReturnNotifications() straight away, rather than the request being enqueued for the next cycle.
  // maxNotificationsPerPublish is one, so a handful of queued values guarantees the flag.
  for (int32_t value = 51; value <= 56; ++value)
  {
    write_value_async(*mSession, mVariableId, Variant{int32_t{value}});
    std::this_thread::sleep_for(std::chrono::milliseconds{60});
  }
  std::this_thread::sleep_for(std::chrono::milliseconds{cycleC});
  {
    auto first = mSession->subscriptions().try_publish_sync(PublishRequest{});
    ASSERT_TRUE(first.is_good()) << to_string(first.status_code());
    ASSERT_THAT(first.value(), ServiceResultIsGood());
    EXPECT_EQ(first.value().subscription_id(), subC);
    EXPECT_TRUE(first.value().more_notifications())
      << "row #5: maxNotificationsPerPublish is 1 and several Notifications were queued, so the response "
         "cannot have carried them all and moreNotifications must be TRUE";

    const auto issuedAt = std::chrono::steady_clock::now();
    auto second = mSession->subscriptions().try_publish_sync(PublishRequest{});
    const auto waited = since(issuedAt);
    ASSERT_TRUE(second.is_good()) << to_string(second.status_code());
    ASSERT_THAT(second.value(), ServiceResultIsGood());
    const auto* dcn = as_data_change(second.value());
    EXPECT_NE(dcn, nullptr) << "row #5: the request that arrived while MoreNotifications was TRUE came "
                               "back without the pending Notifications";
    EXPECT_LT(waited, cycleC / 4)
      << "row #5: the request arriving while MoreNotifications was TRUE waited " << waited << "ms of a "
      << cycleC << "ms cycle - it was enqueued instead of being answered from the batch "
      << "already in hand, so draining a large batch costs one publishing cycle per message";
  }

  // Row #19: SetPublishingMode -> ResetLifetimeCounter(), SetPublishingEnabled() and
  // MoreNotifications=FALSE, with no state change. The flag being cleared is the conjunct with no message
  // of its own: it is read back as the request AFTER the call no longer taking row #5's immediate path.
  // A single probe cannot say so (the next cycle boundary may be milliseconds away), so the call is
  // repeated and the longest wait taken - if the flag survived the call, every probe is answered at once.
  {
    int qualified = 0;
    int64_t longestWait = 0;
    for (int probe = 0; probe < 6; ++probe)
    {
      // Fresh values before every probe, so that a batch is genuinely pending each time rather than the
      // queue running dry and a keep-alive being timed instead.
      for (int32_t step = 0; step < 3; ++step)
      {
        write_value_async(*mSession, mVariableId, Variant{int32_t{600 + probe * 10 + step}});
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{cycleC});

      auto pending = mSession->subscriptions().try_publish_sync(PublishRequest{});
      ASSERT_TRUE(pending.is_good()) << to_string(pending.status_code());
      ASSERT_THAT(pending.value(), ServiceResultIsGood());
      const bool moreWasSet = pending.value().more_notifications();

      EXPECT_EQ(setPublishingStatus(subC, true), StatusCode{Status::Good})
        << "row #19: SetPublishingMode was refused at probe " << probe;

      const auto issuedAt = std::chrono::steady_clock::now();
      auto next = mSession->subscriptions().try_publish_sync(PublishRequest{});
      const auto waited = since(issuedAt);
      ASSERT_TRUE(next.is_good()) << to_string(next.status_code());
      ASSERT_THAT(next.value(), ServiceResultIsGood());
      const auto* nextDcn = as_data_change(next.value());

      // Only a probe that entered the call with MoreNotifications set and still had a batch to draw on
      // afterwards says anything about the flag being cleared.
      if (moreWasSet && nextDcn != nullptr && !nextDcn->monitored_items().empty())
      {
        ++qualified;
        if (waited > longestWait)
          longestWait = waited;
      }
    }
    ASSERT_GE(qualified, 4) << "row #19: only " << qualified
                            << " probes reached the state the row describes (MoreNotifications TRUE with "
                               "a batch still pending), so its clearing cannot be judged";
    EXPECT_GE(longestWait, cycleC / 4)
      << "row #19: every Publish request issued straight after SetPublishingMode was answered from the "
      << "pending batch (longest wait " << longestWait << "ms across " << qualified << " probes of a "
      << cycleC << "ms cycle) - the call did not clear MoreNotifications";
  }

  // Row #19's SetPublishingEnabled(): the mode really changes, and changes back.
  EXPECT_EQ(setPublishingStatus(subC, false), StatusCode{Status::Good});
  write_value_async(*mSession, mVariableId, Variant{int32_t{77}});
  {
    auto leaked = wait_for_publish(
      *mSession,
      [subC](const PublishResponse& r)
      {
        const auto* dc = as_data_change(r);
        return r.subscription_id() == subC && dc != nullptr && !dc->monitored_items().empty();
      },
      2s);
    EXPECT_FALSE(leaked) << "row #19: SetPublishingMode(FALSE) did not stop the NotificationMessages";
  }
  EXPECT_EQ(setPublishingStatus(subC, true), StatusCode{Status::Good});
  write_value_async(*mSession, mVariableId, Variant{int32_t{78}});
  {
    auto resumed = wait_for_data_change(
      *mSession, subC, [](const DataChangeNotification& dc) { return !dc.monitored_items().empty(); }, 5s);
    EXPECT_TRUE(resumed) << "row #19: SetPublishingMode(TRUE) did not restore the NotificationMessages, so "
                            "the silence above was a broken Subscription rather than a paused one";
  }
  ASSERT_EQ(deleteStatus(*mSession, subC), StatusCode{Status::Good});

  // =========================================================================
  // Rows #18, #22, #24, #26 and #25 - the Service rows. Every one of them but #25 must leave the
  // Subscription exactly where it was, which is checked after each in turn.
  // =========================================================================
  const auto subD =
    create_subscription(*mSession, {.publishingInterval = 250.0, .lifetimeCount = 80, .keepAliveCount = 6});
  ASSERT_NE(subD, 0u);

  // Row #18: ModifySubscription -> ResetLifetimeCounter(), UpdateSubscriptionParameters(), a response, and
  // no state change.
  {
    ModifySubscriptionRequest req;
    req.subscription_id() = subD;
    req.requested_publishing_interval() = 750.0;
    req.requested_lifetime_count() = 80;
    req.requested_max_keep_alive_count() = 6;
    req.max_notifications_per_publish() = 7;
    auto resp = mSession->subscriptions().modify_subscription_sync(std::move(req));
    EXPECT_THAT(resp, ServiceResultIsGood()) << "row #18: ModifySubscription was refused";
    EXPECT_GE(resp.revised_publishing_interval(), 500.0)
      << "row #18: UpdateSubscriptionParameters() did not take the new publishing interval - 750ms was "
      << "requested and " << resp.revised_publishing_interval() << "ms was granted";
    EXPECT_GT(resp.revised_lifetime_count(), 0u);
  }
  EXPECT_NE(republishStatus(*mSession, subD, 0u), StatusCode{Status::BadSubscriptionIdInvalid})
    << "row #18: ModifySubscription closed the Subscription; the row changes parameters, not state";

  // Row #22: TransferSubscriptions naming a Subscription this very Session already owns ->
  // ResetLifetimeCounter() and a negative response, with the Subscription untouched.
  {
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(subD);
    req.send_initial_values() = false;
    auto result = mSession->subscriptions().try_transfer_subscriptions_sync(std::move(req));
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    const auto& resp = result.value();
    EXPECT_THAT(resp, ServiceResultIsGood())
      << "row #22: a transfer that changes no Session is refused per operation, not per service";
    ASSERT_FALSE(resp.results().empty());
    EXPECT_TRUE(resp.results()[0].status_code().is_bad())
      << "row #22: transferring a Subscription to the Session that already owns it must return a negative "
      << "response, got " << to_string(resp.results()[0].status_code());
  }
  EXPECT_EQ(modifyStatus(*mSession, subD), StatusCode{Status::Good})
    << "row #22: the refused self-transfer disturbed the Subscription";

  auto channelB = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto sessionB = channelB.create_session_sync({.sessionName = "Table85TransferPeer"});
  sessionB.activate_sync();

  // Row #24: TransferSubscriptions from another Session with the Client not validated ->
  // ReturnNegativeResponse() and nothing else. This endpoint is MessageSecurityMode::None and the user is
  // Anonymous, so the Server cannot validate the requester and must refuse without moving anything.
  {
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(subD);
    req.send_initial_values() = false;
    auto result = sessionB.subscriptions().try_transfer_subscriptions_sync(std::move(req));
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    const auto& resp = result.value();
    EXPECT_THAT(resp, ServiceResultIsGood())
      << "row #24: an unvalidated transfer is refused per operation, not per service";
    ASSERT_FALSE(resp.results().empty());
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadUserAccessDenied})
      << "row #24: an Anonymous transfer over an unauthenticated channel must be refused, got "
      << to_string(resp.results()[0].status_code());
  }
  EXPECT_EQ(modifyStatus(*mSession, subD), StatusCode{Status::Good})
    << "row #24: the Subscription left its Session although the transfer was refused - SetSession() runs "
       "on row #23 only";

  // Row #26: DeleteSubscriptions naming a Subscription that is not assigned to the requesting Client ->
  // ResetLifetimeCounter() and a negative response, with the Subscription still running for its owner.
  EXPECT_EQ(deleteStatus(sessionB, subD), StatusCode{Status::BadSubscriptionIdInvalid})
    << "row #26: a Session that does not own the Subscription must be refused";
  EXPECT_EQ(modifyStatus(*mSession, subD), StatusCode{Status::Good})
    << "row #26: the refused DeleteSubscriptions deleted the Subscription anyway";

  (void)sessionB.try_close_sync();
  (void)channelB.try_close_sync();

  // Row #25: DeleteSubscriptions naming a Subscription assigned to the Client -> DeleteMonitoredItems(),
  // DeletePublishReqQueue(), and CLOSED. The publish-queue half is the one with a client waiting on it:
  // a request is parked in KEEPALIVE (rows #7 then #9 then #13 put it there) and must not be abandoned.
  using PubResult = SessionSubscriptionServices::PublishResponseResult;
  {
    auto warmup = mSession->subscriptions().try_publish_sync(PublishRequest{});
    ASSERT_TRUE(warmup.is_good()) << to_string(warmup.status_code());
    ASSERT_THAT(warmup.value(), ServiceResultIsGood());
  }
  std::this_thread::sleep_for(std::chrono::milliseconds{375});

  // The promise is heap-allocated: the callback may fire during session teardown, after this frame
  // has returned.
  auto promise = std::make_shared<std::promise<PubResult>>();
  auto queued = promise->get_future();
  mSession->subscriptions().publish_async(
    PublishRequest{}, [promise](PubResult result) mutable { promise->set_value(std::move(result)); });
  std::this_thread::sleep_for(std::chrono::milliseconds{250});
  ASSERT_NE(queued.wait_for(std::chrono::milliseconds{0}), std::future_status::ready)
    << "the Publish request that should be sitting in the queue when the Subscription is deleted was "
       "already answered; row #25's DeletePublishReqQueue() cannot be observed";

  EXPECT_EQ(deleteStatus(*mSession, subD), StatusCode{Status::Good}) << "row #25: DeleteSubscriptions "
                                                                        "refused a Subscription the "
                                                                        "requesting Client owns";
  EXPECT_EQ(queued.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "row #25: DeletePublishReqQueue() did not run - the Publish request is still parked against a "
       "Subscription that no longer exists and the client waits for a response that can never come";
  if (queued.wait_for(std::chrono::milliseconds{0}) == std::future_status::ready)
  {
    (void)queued.get();
  }
  EXPECT_EQ(modifyStatus(*mSession, subD), StatusCode{Status::BadSubscriptionIdInvalid})
    << "row #25: the deleted Subscription did not reach CLOSED";
  EXPECT_EQ(republishStatus(*mSession, subD, 0u), StatusCode{Status::BadSubscriptionIdInvalid})
    << "row #25: the deleted Subscription still answers Republish";

  // =========================================================================
  // Rows #2 and #27 - the two rows that end in CLOSED without the Client asking.
  // =========================================================================
  constexpr uint32_t survivorHandle = 500;
  constexpr uint32_t expiringHandle = 501;

  const auto survivorSubId = create_subscription(
    *mSession, {.publishingInterval = 100.0, .lifetimeCount = 600, .keepAliveCount = 200});
  ASSERT_NE(survivorSubId, 0u);
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
      survivorSubId, mVariableId, {.clientHandle = survivorHandle, .samplingInterval = 50.0}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  auto createE = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 6, .keepAliveCount = 2}));
  ASSERT_THAT(createE, ServiceResultIsGood());
  const auto expiringSubId = createE.subscription_id();
  ASSERT_NE(expiringSubId, 0u);
  ASSERT_NE(expiringSubId, survivorSubId);
  const auto expiryMs =
    static_cast<int64_t>(createE.revised_lifetime_count() * createE.revised_publishing_interval());
  ASSERT_GT(expiryMs, 0);
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
      expiringSubId, mVariableId, {.clientHandle = expiringHandle, .samplingInterval = 50.0}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  }

  // Row #2: CREATING, the create fails -> ReturnNegativeResponse() and back to CLOSED. The Session is at
  // its Subscription limit here, so the Server must refuse and must leave no half-built Subscription
  // behind for the Client to be handed an identifier for.
  {
    auto refused = mSession->subscriptions().try_create_subscription_sync(build_subscription_request());
    const auto status =
      refused.is_good() ? refused.value().response_header().service_result() : refused.status_code();
    EXPECT_EQ(status, StatusCode{Status::BadTooManySubscriptions})
      << "row #2: CreateSubscription past the Session's limit must fail, got " << to_string(status);
    if (refused.is_good() && refused.value().response_header().service_result().is_bad())
    {
      EXPECT_EQ(refused.value().subscription_id(), 0u)
        << "row #2: a refused CreateSubscription must leave no Subscription - the machine goes back to "
           "CLOSED and no identifier is issued";
    }
  }

  // Row #27's antecedent: the doomed Subscription is delivering before its lifetime runs out, so its
  // silence afterwards means something.
  write_value_async(*mSession, mVariableId, Variant{int32_t{81}});
  {
    auto beforeExpiry = wait_for_publish(
      *mSession,
      [expiringSubId](const PublishResponse& r)
      {
        const auto* dc = as_data_change(r);
        return r.subscription_id() == expiringSubId && dc != nullptr && !dc->monitored_items().empty();
      },
      5s);
    ASSERT_TRUE(beforeExpiry) << "row #27: the Subscription whose lifetime is about to expire never "
                                 "delivered anything, so nothing about its close can be concluded";
  }

  // Row #27: the lifetime counter runs out -> DeleteMonitoredItems(),
  // IssueStatusChangeNotification(Bad_Timeout), and CLOSED. No Publish request and no Service call naming
  // it for the whole window.
  std::this_thread::sleep_for(std::chrono::milliseconds{expiryMs + 900});

  auto scn = wait_for_status_change(*mSession, expiringSubId, 3s);
  ASSERT_TRUE(scn) << "row #27: no StatusChangeNotification was issued when the lifetime counter expired";
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout})
    << "row #27: the StatusChangeNotification must carry Bad_Timeout";
  EXPECT_EQ(modifyStatus(*mSession, expiringSubId), StatusCode{Status::BadSubscriptionIdInvalid})
    << "row #27: the expired Subscription did not reach CLOSED";

  // Row #27's DeleteMonitoredItems(): nothing may still be sampling for the closed Subscription. The
  // Variable keeps changing and the surviving Subscription keeps reporting it, so this is measured inside
  // a window that is demonstrably carrying traffic rather than in the quiet of a client that stopped
  // asking.
  bool survivorDelivered = false;
  int32_t value = 200;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{2000};
  while (std::chrono::steady_clock::now() < deadline)
  {
    write_value_async(*mSession, mVariableId, Variant{int32_t{value++}});
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    if (!result.is_good() || !result.value().response_header().service_result().is_good())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
      continue;
    }
    const auto& resp = result.value();
    const auto* dc = as_data_change(resp);
    if (dc == nullptr || dc->monitored_items().empty())
    {
      continue;
    }
    EXPECT_NE(resp.subscription_id(), expiringSubId)
      << "row #27: a DataChangeNotification arrived for subscription " << expiringSubId
      << " after it timed out - the closed Subscription is still publishing";
    for (const auto& mi : dc->monitored_items())
    {
      EXPECT_EQ(mi.client_handle(), survivorHandle)
        << "row #27: a Notification carried client handle " << mi.client_handle()
        << ", which belonged to a MonitoredItem of the expired Subscription - DeleteMonitoredItems() did "
           "not run when the lifetime counter closed it";
      if (mi.client_handle() == survivorHandle)
      {
        survivorDelivered = true;
      }
    }
  }
  EXPECT_TRUE(survivorDelivered)
    << "row #27: the surviving Subscription delivered nothing in the window, so the expired "
       "Subscription's silence is the silence of an idle Server rather than of a deleted MonitoredItem";
}

// ===========================================================================
// DeleteSubscriptions, expired Publish requests and ModifySubscription timing
// ===========================================================================

/// Part 4 section 5.13.8.1: "Successful completion of this Service causes all MonitoredItems that use
/// the Subscription to be deleted", and Table 85 row 25 gives the same transition its DeleteMonitoredItems()
/// action. The Subscription reaches CLOSED, so its retransmission queue goes with it: Part 4 section
/// 5.13.6 lets Republish return only messages from "the Subscription's retransmission queue", and a
/// Subscription that no longer exists has none. Both halves cost something to get wrong and neither shows
/// up in the delete response, which is why they are asserted here rather than trusted. A Server that
/// forgets the Subscription record but leaves its MonitoredItems charged against the server-wide
/// MonitoredItem budget looks perfectly healthy until the budget has been eaten by Subscriptions that no
/// longer exist; a Server that keeps the retransmission entries addressable lets a Client republish
/// messages of a Subscription it has already deleted. Filling the budget before the delete and refilling
/// it afterwards is what makes the deletion observable from a Client at all, and the sequence number is
/// proved republishable BEFORE the delete so that its refusal afterwards is the delete's doing.
///
/// This is the explicit-delete counterpart of the lifetime-expiry path
/// (`AC-SVR-SUB-GEN-033-CLOSE-DELETES-ITEMS`): the two share no code path in a Server that closes the
/// Subscription from its own timer, so one can cascade correctly while the other leaks.
// @relation(AC-SVR-SUB-GEN-124-EXPLICIT-DELETE-RELEASES-RESOURCES, scope=function)
TEST_F(ComplianceSubscriptionMonitoredItemCapped, DeleteReleasesItsItemsAndItsRetransmissionQueue)
{
  const uint32_t cap = mMaxMonitoredItemsServerWide;
  ASSERT_GT(cap, 0u) << "this fixture exists to lower the server-wide MonitoredItem budget to a "
                        "reachable number; without one the release of the slots is unobservable";

  // A lifetime long enough that nothing in this test can be attributed to an expiry: 600 cycles of
  // 100ms is a minute, and the whole test runs in seconds.
  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 100.0, .lifetimeCount = 600, .keepAliveCount = 20}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  ASSERT_NE(subId, 0u);

  // Consume the whole server-wide budget on this Subscription.
  for (uint32_t handle = 1; handle <= cap; ++handle)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subId, mVariableId, {.clientHandle = handle, .samplingInterval = 50.0}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_TRUE(miResp.results()[0].status_code().is_good())
      << "could not fill the MonitoredItem budget at item " << handle << " of " << cap << ": "
      << to_string(miResp.results()[0].status_code());
  }
  GTEST_LOG_(INFO) << "subscription " << subId << " holds " << cap
                   << " MonitoredItems, which is the whole server-wide budget";

  // The budget really is exhausted - otherwise the refill after the delete would prove nothing.
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(subId, mVariableId, {.clientHandle = cap + 1}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    ASSERT_EQ(miResp.results()[0].status_code(), StatusCode{Status::BadTooManyMonitoredItems})
      << "the server-wide MonitoredItem budget is not being enforced, so nothing below can be read as a "
         "released slot";
  }

  // An unacknowledged NotificationMessage: taken and deliberately never acknowledged, so it is still in
  // the Subscription's retransmission queue when the delete arrives.
  write_value_async(*mSession, mVariableId, Variant{int32_t{4711}});
  auto delivered = wait_for_publish(
    *mSession,
    [subId](const PublishResponse& resp)
    {
      const auto* dcn = as_data_change(resp);
      return resp.subscription_id() == subId && dcn != nullptr && !dcn->monitored_items().empty();
    },
    5s);
  ASSERT_TRUE(delivered) << "subscription " << subId
                         << " never delivered a DataChangeNotification, so there is no unacknowledged "
                            "message for the delete to drain";
  const auto seqNum = delivered->notification_message().sequence_number();
  ASSERT_NE(seqNum, 0u);

  // Antecedent: while the Subscription lives, that sequence number IS republishable.
  {
    RepublishRequest req;
    req.subscription_id() = subId;
    req.retransmit_sequence_number() = seqNum;
    auto rep = mSession->subscriptions().try_republish_sync(std::move(req));
    ASSERT_TRUE(rep.is_good()) << to_string(rep.status_code());
    ASSERT_THAT(rep.value(), ServiceResultIsGood())
      << "sequence number " << seqNum
      << " was not retransmittable before the delete, so its refusal afterwards would say nothing";
    ASSERT_EQ(rep.value().notification_message().sequence_number(), seqNum);
  }

  DeleteSubscriptionsRequest del;
  del.subscription_ids().push_back(subId);
  auto delResp = mSession->subscriptions().delete_subscriptions_sync(std::move(del));
  ASSERT_THAT(delResp, ServiceResultIsGood());
  ASSERT_FALSE(delResp.results().empty());
  ASSERT_TRUE(delResp.results()[0].is_good())
    << "the delete itself failed with " << to_string(delResp.results()[0]);

  // Conjunct one: nothing survives to be republished. Either refusal is conforming - the Subscription
  // is gone (Bad_SubscriptionIdInvalid) or its queue is (Bad_MessageNotAvailable); returning the
  // message is not.
  {
    RepublishRequest req;
    req.subscription_id() = subId;
    req.retransmit_sequence_number() = seqNum;
    auto rep = mSession->subscriptions().try_republish_sync(std::move(req));
    const auto status = rep.is_good() ? rep.value().response_header().service_result() : rep.status_code();
    EXPECT_TRUE(status.is_bad())
      << "Republish returned sequence number " << seqNum << " of subscription " << subId
      << " after that Subscription was deleted: its retransmission queue outlived it";
  }

  // Conjunct two: its MonitoredItems are deleted, so the slots they held are free again. A survivor
  // would still be sampling the Variable on behalf of a Subscription that no longer exists, and would
  // still be counted against the budget.
  auto secondResp = mSession->subscriptions().create_subscription_sync(build_subscription_request());
  ASSERT_THAT(secondResp, ServiceResultIsGood());
  const auto secondSubId = secondResp.subscription_id();
  ASSERT_NE(secondSubId, 0u);
  ASSERT_NE(secondSubId, subId);

  for (uint32_t handle = 1; handle <= cap; ++handle)
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(secondSubId, mVariableId, {.clientHandle = handle}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    EXPECT_TRUE(miResp.results()[0].status_code().is_good())
      << "item " << handle << " of " << cap << " was refused with "
      << to_string(miResp.results()[0].status_code())
      << " - the deleted Subscription's MonitoredItems still hold their slots, so DeleteSubscriptions "
         "did not delete them";
  }

  // The budget is still being counted, so the successes above are released slots rather than a limit
  // that quietly stopped applying.
  {
    auto miResp = mSession->monitored_items().create_monitored_items_sync(
      build_create_mi_request(secondSubId, mVariableId, {.clientHandle = cap + 1}));
    ASSERT_THAT(miResp, ServiceResultIsGood());
    ASSERT_FALSE(miResp.results().empty());
    EXPECT_EQ(miResp.results()[0].status_code(), StatusCode{Status::BadTooManyMonitoredItems})
      << "the server-wide MonitoredItem budget stopped applying, so the successes above prove nothing";
  }
}

/// Part 4 section 7.33, timeoutHint: "The Server shall check the timeoutHint parameter of a Publish
/// request before processing a Publish response. If the request timed out, a Bad_Timeout Service result
/// is sent and another Publish request is used" - Table 87's DequeuePublishReq() says the same thing in
/// state-machine form. The client has already stopped waiting for that request, so holding it consumes
/// one of the client's Publish slots for a response nobody will read, and - the half asserted here -
/// spends a NotificationMessage on a request whose reply will be dropped by the client's stack.
///
/// **The Bad_Timeout response itself is not observable at this interface, and this test does not claim it.**
/// This SDK's client arms its own deadline at exactly the value it puts in timeoutHint
/// (`ua_session_service_helpers.h`), and a conforming Server checks the hint only when it dequeues -
/// which is after the hint has expired by definition. Any assertion on the expired request's own reply
/// would therefore fail against a conforming Server. What a Client can see is the second half of the
/// sentence: the next request is taken in order. The expired request is put at the head of the queue,
/// nothing is publishable while its hint runs out, and only then does the Variable change: a Server that
/// validates the hint answers the expired request and delivers the notification to the successor, while
/// a Server that dequeues in blind FIFO order sends the notification in reply to a request the client
/// abandoned - the successor then waits for the keep-alive, tens of seconds away.
// @verifies AC-SVR-SUB-GEN-112-EXPIRED-PUBLISH-BAD-TIMEOUT
TEST_F(ComplianceWithNodes, ExpiredPublishRequestIsPassedOverAndTheNextRequestIsUsed)
{
  using PubResult = SessionSubscriptionServices::PublishResponseResult;

  constexpr uint32_t clientHandle = 61;
  constexpr uint32_t shortHintMs = 700;
  constexpr int32_t writtenValue = 5121;

  auto createResp = mSession->subscriptions().create_subscription_sync(
    build_subscription_request({.publishingInterval = 500.0, .lifetimeCount = 600, .keepAliveCount = 60}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  ASSERT_NE(subId, 0u);
  const auto interval = createResp.revised_publishing_interval();
  ASSERT_GT(interval, 0.0);

  // The keep-alive must be far enough away that the only thing which can answer the second request
  // inside the test window is the write below - otherwise a keep-alive would pass this test on a
  // Server that never looked at the hint.
  const auto keepAliveWindowMs = static_cast<int64_t>(createResp.revised_max_keep_alive_count() * interval);
  ASSERT_GT(keepAliveWindowMs, 10000)
    << "the keep-alive window is only " << keepAliveWindowMs
    << "ms, so a keep-alive could answer the successor request and the measurement would not be about "
       "the expired one at all";

  auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
    subId, mWritableVariableId, {.clientHandle = clientHandle, .samplingInterval = 50.0}));
  ASSERT_THAT(miResp, ServiceResultIsGood());
  ASSERT_FALSE(miResp.results().empty());
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Drain what the Subscription already owes - its first message and the MonitoredItem's initial value.
  // Either would answer the expiring request below before its hint ran out, leaving nothing queued past
  // its deadline and nothing for the test to be about.
  ASSERT_TRUE(wait_for_data_change(
    *mSession, subId, [](const DataChangeNotification& dcn) { return !dcn.monitored_items().empty(); }, 5s))
    << "subscription " << subId << " never delivered the MonitoredItem's initial value";

  // The request whose timeoutHint expires while it is queued.
  auto expiring = std::make_shared<std::promise<PubResult>>();
  auto expiringFuture = expiring->get_future();
  PublishRequest expiringReq;
  expiringReq.request_header().timeout_hint() = shortHintMs;
  mSession->subscriptions().publish_async(
    std::move(expiringReq), [expiring](PubResult result) mutable { expiring->set_value(std::move(result)); });

  // Its successor, queued behind it with the client's default (10s) hint.
  std::this_thread::sleep_for(std::chrono::milliseconds{100});
  auto successor = std::make_shared<std::promise<PubResult>>();
  auto successorFuture = successor->get_future();
  mSession->subscriptions().publish_async(
    PublishRequest{}, [successor](PubResult result) mutable { successor->set_value(std::move(result)); });

  // Nothing is publishable while the first request's hint runs out.
  ASSERT_EQ(expiringFuture.wait_for(std::chrono::milliseconds{shortHintMs + 2000}), std::future_status::ready)
    << "the first Publish request was neither answered nor abandoned within its own timeoutHint of "
    << shortHintMs << "ms";
  auto expiringResult = expiringFuture.get();
  // Two outcomes both mean the request outlived its hint: the client's local deadline fired and no
  // response was correlated (`is_good()` false), or the Server dequeued it, judged it expired and
  // answered a bad service result that beat the client's own deadline by a hair. Only a GOOD answer
  // would mean it was served before its deadline, and then this test has no subject. Demanding the
  // transport-level failure alone would fail a Server whose Bad_Timeout arrives fractionally early -
  // an over-reach, since the response race is decided by scheduling, not by conformance.
  const bool answeredBeforeItExpired =
    expiringResult.is_good() && expiringResult.value().response_header().service_result().is_good();
  ASSERT_FALSE(answeredBeforeItExpired)
    << "the first Publish request was answered before its timeoutHint expired, so it never sat in the "
       "queue past its deadline and this test has no subject";

  // Only now does the Subscription acquire something to say.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{writtenValue}});

  ASSERT_EQ(successorFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the successor Publish request was never answered: the NotificationMessage was spent on the "
       "request whose timeoutHint had already expired, and no other request was used in its place";
  auto successorResult = successorFuture.get();
  ASSERT_TRUE(successorResult.is_good()) << to_string(successorResult.status_code());
  const auto& resp = successorResult.value();
  ASSERT_THAT(resp, ServiceResultIsGood());
  EXPECT_EQ(resp.subscription_id(), subId);
  const auto* dcn = as_data_change(resp);
  ASSERT_NE(dcn, nullptr) << "the successor request was answered without the DataChangeNotification the "
                             "expired request was passed over for";
  EXPECT_THAT(*dcn, ContainsDataChangeFor(clientHandle, good_value_of<int32_t>(writtenValue)));
}

/// Part 4 section 5.13.4.1: the revised parameters of a ModifySubscription are "applied immediately ... as
/// soon as possible", and Table 85 row 18 gives UpdateSubscriptionParams() no state of its own to wait
/// in. Bounded here by the publishing cycle in progress, because without a bound "immediately" is
/// unfalsifiable: a Server that stores the revised interval and leaves the running publishing timer on
/// the old one answers ModifySubscription with a perfect response - the revised values, the revised
/// interval, Good - and keeps publishing on the interval the Client just replaced. Reading the response
/// cannot tell the two apart; only the publish timing can. The Subscription is created on an interval
/// four times the one it is modified to, so a delivery inside two revised cycles cannot be the old timer
/// firing, and three consecutive rounds are measured because the first write after the modification can
/// land close enough to an old cycle boundary to be answered in time by luck.
///
/// The bound is what the criterion grants the change to take effect, so the rounds start once that
/// window has passed rather than inside it - measuring from the instant ModifySubscription returns
/// would fail a Server that applies the change at the end of the window the specification allows it.
// @verifies AC-SVR-SUB-GEN-117-MODIFY-TAKES-EFFECT
TEST_F(ComplianceWithNodes, ModifiedPublishingIntervalIsInEffectWithinTwoRevisedCycles)
{
  constexpr uint32_t clientHandle = 71;
  constexpr double slowIntervalMs = 4000.0;
  constexpr double fastInterval = 1000.0;
  constexpr int rounds = 3;

  auto createResp = mSession->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = slowIntervalMs, .lifetimeCount = 60, .keepAliveCount = 20}));
  ASSERT_THAT(createResp, ServiceResultIsGood());
  const auto subId = createResp.subscription_id();
  ASSERT_NE(subId, 0u);
  const auto slowInterval = createResp.revised_publishing_interval();

  auto miResp = mSession->monitored_items().create_monitored_items_sync(build_create_mi_request(
    subId, mWritableVariableId, {.clientHandle = clientHandle, .samplingInterval = 50.0}));
  ASSERT_THAT(miResp, ServiceResultIsGood());
  ASSERT_FALSE(miResp.results().empty());
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Drain the initial value on the slow interval, so the rounds below measure a fresh change rather
  // than a notification that was already queued when the modification arrived.
  ASSERT_TRUE(wait_for_data_change(
    *mSession, subId, [](const DataChangeNotification& dcn) { return !dcn.monitored_items().empty(); }, 10s))
    << "subscription " << subId << " never delivered the MonitoredItem's initial value at its "
    << slowInterval << "ms interval, so there is nothing to modify the timing of";

  ModifySubscriptionRequest mod;
  mod.subscription_id() = subId;
  mod.requested_publishing_interval() = fastInterval;
  mod.requested_lifetime_count() = 600;
  mod.requested_max_keep_alive_count() = 60;
  mod.max_notifications_per_publish() = 0;
  auto modResp = mSession->subscriptions().modify_subscription_sync(std::move(mod));
  ASSERT_THAT(modResp, ServiceResultIsGood());
  const auto revisedInterval = modResp.revised_publishing_interval();
  ASSERT_GT(revisedInterval, 0.0);
  ASSERT_GE(slowInterval, 2.0 * revisedInterval)
    << "the Subscription was created on a " << slowInterval << "ms interval and revised to "
    << revisedInterval
    << "ms; the two must differ by more than the bound asserted below or the measurement cannot tell a "
       "Server that applied the change from one that did not";
  const auto boundMs = static_cast<int64_t>(2.0 * revisedInterval);

  // The obligation grants the modification twice the revised interval to COME INTO EFFECT; the rounds
  // below measure the interval once it IS in effect. Waiting that allowance out here rather than
  // charging it to the first round is what keeps the measurement inside the specification: a Server
  // that legitimately applies the change at the end of the permitted window would otherwise be failed
  // by round 0, whose write is issued the instant ModifySubscription returns. It costs the test one
  // window and costs a Server still running the old timer nothing - rounds 1 and 2 each begin at the
  // delivery of the previous round, so on the old 4000ms cadence every subsequent write lands just
  // after a cycle boundary and waits a full old cycle, well past the bound.
  std::this_thread::sleep_for(std::chrono::milliseconds{boundMs});

  GTEST_LOG_(INFO) << "measuring " << rounds << " deliveries at a revised publishing interval of "
                   << revisedInterval << "ms (created at " << slowInterval << "ms), after allowing the "
                   << boundMs << "ms the modification has to take effect; each must land within " << boundMs
                   << "ms of its write";

  auto carriesValue = [clientHandle](const DataChangeNotification& dcn, int32_t expected)
  {
    for (const auto& mi : dcn.monitored_items())
    {
      const auto* actual = mi.value().value().try_as<int32_t>();
      if (mi.client_handle() == clientHandle && actual != nullptr && *actual == expected)
        return true;
    }
    return false;
  };

  for (int round = 0; round < rounds; ++round)
  {
    const int32_t value = 6100 + round;
    const auto writtenAt = std::chrono::steady_clock::now();
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{value}});

    auto notif = wait_for_data_change(
      *mSession,
      subId,
      [&carriesValue, value](const DataChangeNotification& dcn) { return carriesValue(dcn, value); },
      std::chrono::milliseconds{static_cast<int64_t>(3.0 * slowInterval)});
    const auto waitedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - writtenAt)
        .count();
    ASSERT_TRUE(notif) << "round " << round << ": the value " << value
                       << " was never delivered at all, so the Subscription is not publishing on any "
                          "interval";
    EXPECT_LE(waitedMs, boundMs) << "round " << round << ": the change took " << waitedMs
                                 << "ms to arrive, which is more than two revised publishing cycles ("
                                 << boundMs << "ms) after ModifySubscription revised the interval to "
                                 << revisedInterval
                                 << "ms - the Subscription is still running on its original " << slowInterval
                                 << "ms timer";
  }
}

// Part 4 5.12.2.2: the timestampsToReturn of CreateMonitoredItems decides the timestamps every notification
// of those items carries, as it does for a Read. ServerStatus.CurrentTime is answered by a source that
// stamps only its SourceTimestamp, so a ServerTimestamp in its notifications is the server's own.
TEST_F(ComplianceWithNodes, SVC_CreateMI_NotificationsCarryTheTimestampsTheClientAskedFor)
{
  struct Case
  {
    TimestampsToReturn requested;
    bool source;
    bool server;
  };

  for (const Case c : {Case{TimestampsToReturn::Both, true, true},
         Case{TimestampsToReturn::Source, true, false},
         Case{TimestampsToReturn::Server, false, true},
         Case{TimestampsToReturn::Neither, false, false}})
  {
    const uint32_t subId = ua::test_helpers::create_subscription(*mSession);
    auto request = ua::test_helpers::build_create_mi_request(
      subId, NodeId{VariableId::Server_ServerStatus_CurrentTime}, {.samplingInterval = 100.0});
    request.timestamps_to_return() = c.requested;
    auto created = mSession->monitored_items().create_monitored_items_sync(std::move(request));
    ASSERT_EQ(created.results().size(), 1u);
    ASSERT_TRUE(created.results()[0].status_code().is_good());

    auto notification = ua::test_helpers::wait_for_data_change(*mSession, subId);
    ASSERT_TRUE(notification.has_value())
      << "no notification for TimestampsToReturn " << static_cast<int>(c.requested);
    ASSERT_FALSE(notification->monitored_items().empty());
    const auto& value = notification->monitored_items()[0].value();
    const auto present = [](const std::optional<DateTime>& timestamp)
    {
      return timestamp.has_value() && !timestamp->is_null();
    };
    EXPECT_EQ(present(value.source_timestamp()), c.source)
      << "SourceTimestamp for TimestampsToReturn " << static_cast<int>(c.requested);
    EXPECT_EQ(present(value.server_timestamp()), c.server)
      << "ServerTimestamp for TimestampsToReturn " << static_cast<int>(c.requested);

    DeleteSubscriptionsRequest del;
    del.subscription_ids().push_back(subId);
    (void)mSession->subscriptions().delete_subscriptions_sync(std::move(del));
  }
}

// Part 4 5.13.6: Republish returns the NotificationMessage as it was published - the CTT's Subscription Basic
// 056/057. The values are re-authorized for the requester, but every timestamp is the published one, for
// each timestampsToReturn. CurrentTime's source sets no ServerTimestamp, so the server's own is under test.
TEST_F(ComplianceWithNodes, SVC_Republish_ReturnsTheValuesWithTheTimestampsTheyWerePublishedWith)
{
  for (const auto timestamps : {TimestampsToReturn::Both, TimestampsToReturn::Server})
  {
    const uint32_t subId = ua::test_helpers::create_subscription(*mSession);
    auto request = ua::test_helpers::build_create_mi_request(
      subId, NodeId{VariableId::Server_ServerStatus_CurrentTime}, {.samplingInterval = 100.0});
    request.timestamps_to_return() = timestamps;
    ASSERT_TRUE(mSession->monitored_items()
                  .create_monitored_items_sync(std::move(request))
                  .results()[0]
                  .status_code()
                  .is_good());

    std::optional<PublishResponse> published;
    for (int attempt = 0; attempt < 20 && !published; ++attempt)
    {
      auto response = mSession->subscriptions().publish_sync(PublishRequest{});
      if (response.subscription_id() == subId && as_data_change(response) != nullptr &&
          !as_data_change(response)->monitored_items().empty())
        published = std::move(response);
    }
    ASSERT_TRUE(published.has_value()) << "no data change to republish";

    RepublishRequest republish;
    republish.subscription_id() = subId;
    republish.retransmit_sequence_number() = published->notification_message().sequence_number();
    auto republished = mSession->subscriptions().republish_sync(std::move(republish));
    ASSERT_TRUE(republished.response_header().service_result().is_good());

    const auto* original = as_data_change(*published);
    ASSERT_EQ(republished.notification_message().notification_data().size(), 1u);
    const auto* again = dynamic_cast<const DataChangeNotification*>(
      republished.notification_message().notification_data()[0].get());
    ASSERT_NE(again, nullptr);
    ASSERT_EQ(again->monitored_items().size(), original->monitored_items().size());
    for (size_t i = 0; i < original->monitored_items().size(); ++i)
      EXPECT_EQ(again->monitored_items()[i].value(), original->monitored_items()[i].value())
        << "item " << i << " for TimestampsToReturn " << static_cast<int>(timestamps);

    DeleteSubscriptionsRequest del;
    del.subscription_ids().push_back(subId);
    (void)mSession->subscriptions().delete_subscriptions_sync(std::move(del));
  }
}
