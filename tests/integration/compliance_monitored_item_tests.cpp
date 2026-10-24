// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7: Monitored Item Service Set -- Compliance Integration Tests
///
/// Tests covering Part 4 MonitoredItem requirements:
///   - CreateMonitoredItems (SVC-CreateMI-*)
///   - ModifyMonitoredItems (SVC-ModMI-*)
///   - SetMonitoringMode (SVC-SetMonMode-*)
///   - DeleteMonitoredItems (SVC-DeleteMI-*)
///   - MI General: sampling, monitoring modes, queue management, data change triggers, deadband
///     (MI-GEN-*)

#include "compliance_helpers.h"
#include "offloading_node_management_delegate.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_session_attribute_services.h"

#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_data_change_notification.h"
#include "ua_monitored_item_notification.h"
#include "ua_aggregate_filter.h"
#include "ua_data_change_filter.h"
#include "ua_deadband_type.h"
#include "ua_data_change_trigger.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_attribute_id.h"
#include "ua_server_configuration.h"

#include "ua_session_node_management_services.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_add_nodes_item.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_delete_references_item.h"
#include "ua_namespace_delegates.h"

#include <chrono>
#include <thread>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

// ===========================================================================
// File-local helpers
//
// Most of the boilerplate the original file-static helpers carried has moved
// into `helpers/subscription.h` (PR 9a-c). What remains here is the
// `create_single_mi` shortcut that this file uses heavily: it attaches a
// single MI to a pre-existing subscription and returns the FULL
// `MonitoredItemCreateResult` (status, miId, revised values, filter result)
// so the tests can assert against any of those fields. The helper verbs
// throw away most of that response.
// ===========================================================================

namespace
{

MonitoredItemCreateResult create_single_mi(
  Session& session, uint32_t subId, const NodeId& nodeId, MonitoringOptions opts = {.samplingInterval = 50.0})
{
  auto resp =
    session.monitored_items().create_monitored_items_sync(build_create_mi_request(subId, nodeId, opts));
  EXPECT_EQ(resp.results().size(), 1u);
  return std::move(resp.results()[0]);
}

// Single-publish with ack piggyback - equivalent to the pre-migration file-static
// `do_publish(session, ackSubId, ackSeqNum)`. Kept as a file-local because the
// helper `acknowledge(...)` issues a SEPARATE publish round-trip, which would
// change sequence-number timing for the MI queue-state tests that rely on
// every publish counting exactly once.
PublishResponse publish_with_ack(Session& session, uint32_t ackSubId, uint32_t ackSeqNum)
{
  PublishRequest req;
  SubscriptionAcknowledgement ack;
  ack.subscription_id() = ackSubId;
  ack.sequence_number() = ackSeqNum;
  req.subscription_acknowledgements().push_back(std::move(ack));
  return session.subscriptions().publish_sync(std::move(req));
}

}  // namespace

// ===========================================================================
// Fixture: ComplianceMonitoredItemLimited -- server with small MI limits
// ===========================================================================
class ComplianceMonitoredItemLimited : public ::testing::Test
{
protected:
  void SetUp() override
  {

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    server::ServerConfig serverCfg;
    serverCfg.server_capabilities().operationLimits.maxMonitoredItemsPerCall = 1;
    serverCfg.server_capabilities().maxMonitoredItemsPerSubscription = 2;

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

    // Create test variable.
    auto addressSpace = mServer->address_space();
    mNamespace = default_ns::Namespace::create("urn:test:mi:limited", mServerThreadPool.executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mNamespace);

    mVariableId = NodeId{mNamespaceIndex, uint32_t{9000}};
    auto varNode = addressSpace.create_node_sync(mVariableId, NodeClass::Variable);
    auto variable = varNode.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mNamespaceIndex, "LimitTestVar"});
    variable->set_display_name(LocalizedText{"", "LimitTestVar"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mVariableId);

    // Second variable for per-subscription limit test.
    mVariable2Id = NodeId{mNamespaceIndex, uint32_t{9001}};
    auto var2Node = addressSpace.create_node_sync(mVariable2Id, NodeClass::Variable);
    auto variable2 = var2Node.as<VariableAccessor>();
    ASSERT_TRUE(variable2.has_value());
    variable2->set_browse_name(QualifiedName{mNamespaceIndex, "LimitTestVar2"});
    variable2->set_display_name(LocalizedText{"", "LimitTestVar2"});
    variable2->set_data_type(NodeId{DataTypeId::Int32});
    variable2->write_value_sync(int32_t{0});
    variable2->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mVariable2Id);

    // Third variable.
    mVariable3Id = NodeId{mNamespaceIndex, uint32_t{9002}};
    auto var3Node = addressSpace.create_node_sync(mVariable3Id, NodeClass::Variable);
    auto variable3 = var3Node.as<VariableAccessor>();
    ASSERT_TRUE(variable3.has_value());
    variable3->set_browse_name(QualifiedName{mNamespaceIndex, "LimitTestVar3"});
    variable3->set_display_name(LocalizedText{"", "LimitTestVar3"});
    variable3->set_data_type(NodeId{DataTypeId::Int32});
    variable3->write_value_sync(int32_t{0});
    variable3->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mVariable3Id);

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

    // Client.
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));

    mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceMILimited"}));
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
  NodeId mVariable2Id;
  NodeId mVariable3Id;
};

// ===========================================================================
// CreateMonitoredItems tests
// ===========================================================================

// SVC-CreateMI-009: Illegal sampling interval values are revised, not rejected.
TEST_F(ComplianceWithNodes, SVC_CreateMI_009_IllegalValuesRevisedNotError)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Request a negative sampling interval (other than -1 which means "inherit").
  // The server should revise it to a valid value, not return an error.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = -99.0, .queueSize = 1});
  EXPECT_TRUE(result.status_code().is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  EXPECT_GE(result.revised_sampling_interval(), 0.0);
}

// SVC-CreateMI-011: MonitoredItemIds are unique across monitored items in a subscription.
TEST_F(ComplianceWithNodes, SVC_CreateMI_011_MonitoredItemIdUnique)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result1 = create_single_mi(*mSession, subId, mWritableVariableId, {.clientHandle = 1});
  auto result2 = create_single_mi(*mSession, subId, mWritableVariableId, {.clientHandle = 2});

  ASSERT_TRUE(result1.status_code().is_good());
  ASSERT_TRUE(result2.status_code().is_good());
  EXPECT_NE(result1.monitored_item_id(), result2.monitored_item_id());
}

// Basic: Create MI on a variable succeeds and returns a valid monitoredItemId.
TEST_F(ComplianceWithNodes, CreateMI_Success)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  auto result = create_single_mi(*mSession, subId, mWritableVariableId);

  EXPECT_TRUE(result.status_code().is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  EXPECT_NE(result.monitored_item_id(), 0u);
  EXPECT_GE(result.revised_sampling_interval(), 0.0);
  EXPECT_GE(result.revised_queue_size(), 1u);
}

// BadSubscriptionIdInvalid: Creating MI with invalid subscription ID.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-096, scope=function)
TEST_F(ComplianceWithNodes, CreateMI_BadSubscriptionIdInvalid)
{
  CreateMonitoredItemsRequest req;
  req.subscription_id() = 99999;  // non-existent
  req.timestamps_to_return() = TimestampsToReturn::Both;

  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);
  req.items_to_create().push_back(std::move(item));

  auto result = mSession->monitored_items().try_create_monitored_items_sync(std::move(req));
  // Per Table 78: Bad_SubscriptionIdInvalid is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "Bad_SubscriptionIdInvalid is service-level, not operation-level";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// BadNodeIdUnknown: Creating MI on a non-existent node.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-097, scope=function)
TEST_F(ComplianceWithNodes, CreateMI_BadNodeIdUnknown)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  auto result = create_single_mi(*mSession, subId, NodeId{mTestNamespaceIndex, uint32_t{99999}});

  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNodeIdUnknown});
}

// BadNothingToDo: Empty items_to_create list.
// @relation(SVR-MI-GEN-096, scope=function)
TEST_F(ComplianceWithNodes, CreateMI_BadNothingToDo)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  // items_to_create is empty

  auto result = mSession->monitored_items().try_create_monitored_items_sync(std::move(req));
  // Per Table 78: Bad_NothingToDo is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNothingToDo});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// BadTooManyOperations: Exceed MaxMonitoredItemsPerCall limit (limited fixture).
TEST_F(ComplianceMonitoredItemLimited, CreateMI_BadTooManyOperations)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MaxMonitoredItemsPerCall is 1. Try to create 2 in one call.
  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;

  for (uint32_t i = 0; i < 2; ++i)
  {
    ReadValueId rv;
    rv.node_id() = mVariableId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    MonitoringParameters params;
    params.client_handle() = i + 1;
    params.sampling_interval() = 50.0;
    params.queue_size() = 1;
    params.discard_oldest() = true;

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(params);
    req.items_to_create().push_back(std::move(item));
  }

  auto result = mSession->monitored_items().try_create_monitored_items_sync(std::move(req));
  // Per Table 78: Bad_TooManyOperations is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadTooManyOperations})
      << "Bad_TooManyOperations is service-level, not operation-level";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
  }
}

// BadTimestampsToReturnInvalid: Invalid timestamps enum value.
// @relation(SVR-MI-GEN-096, scope=function)
TEST_F(ComplianceWithNodes, CreateMI_BadTimestampsToReturnInvalid)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Invalid;

  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);
  req.items_to_create().push_back(std::move(item));

  auto result = mSession->monitored_items().try_create_monitored_items_sync(std::move(req));
  // Per Table 78: Bad_TimestampsToReturnInvalid is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(
      result.value().response_header().service_result(), StatusCode{Status::BadTimestampsToReturnInvalid})
      << "Bad_TimestampsToReturnInvalid is service-level, not operation-level";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTimestampsToReturnInvalid});
  }
}

// BadFilterNotAllowed: DataChangeFilter on a non-Value attribute (e.g., EventNotifier).
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-097, SVR-MI-GEN-101, scope=function)
TEST_F(ComplianceWithNodes, CreateMI_BadFilterNotAllowed)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ReadValueId rv;
  rv.node_id() = mTestFolderId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  // Set a DataChangeFilter (should not be allowed on EventNotifier attribute).
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadFilterNotAllowed})
    << "DataChangeFilter on non-Value attribute should return BadFilterNotAllowed: 0x" << std::hex
    << resp.results()[0].status_code().as_uint32();
}

// Bad_DeadbandFilterInvalid: a PercentDeadband on a node with no EURange Property.
//
// OPC 10000-8 Table 29 names this case in the status's own definition - "a PercentDeadband is not
// supported, since an EURange is not configured" - and section 6.2 says the filter "applies only to
// AnalogItems with an EURange Property". mWritableVariableId is a plain variable with no EURange.
//
// The server used to CREATE this item Good and then ignore the deadband, reporting every change at
// the full sampling rate: the caller asked for less traffic and silently got more.
TEST_F(ComplianceWithNodes, CreateMI_PercentDeadbandWithoutEuRangeRejected)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Percent);
  filter->deadband_value() = 10.0;  // a perfectly legal percentage; the NODE is what cannot support it
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadDeadbandFilterInvalid})
    << "a PercentDeadband on a node without an EURange must be refused, not accepted and ignored: 0x"
    << std::hex << resp.results()[0].status_code().as_uint32();
}

// ===========================================================================
// MI General -- Sampling (SVR-MI-GEN-001 through SVR-MI-GEN-006)
// ===========================================================================

// SVR-MI-GEN-001: SamplingInterval=-1 means inherit from subscription's publishing interval.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-001, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_001_NegativeSamplingInheritsFromSub)
{
  double pubInterval = 200.0;
  auto subId = create_subscription(*mSession, {.publishingInterval = pubInterval, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = -1.0, .queueSize = 1});

  EXPECT_TRUE(result.status_code().is_good());
  // Revised sampling interval should be the subscription's publishing interval or higher.
  EXPECT_GE(result.revised_sampling_interval(), pubInterval);
}

// SVR-MI-GEN-004: Revised sampling interval must be equal to or higher than requested.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-004, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_004_RevisedSamplingEqualOrHigher)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});

  EXPECT_TRUE(result.status_code().is_good());
  EXPECT_GE(result.revised_sampling_interval(), 50.0);
}

// ===========================================================================
// MI General -- Monitoring Modes (SVR-MI-GEN-010 through SVR-MI-GEN-014)
// ===========================================================================

// SVR-MI-GEN-010: Disabled mode means no sampling or reporting.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-010, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_010_DisabledModeNoSampling)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI in Disabled mode.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Disabled, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());

  // Write a new value. Disabled MI must not produce a notification for our
  // client handle - predicate-filtered wait returns nullopt if and only if
  // nothing matching ever arrives within the timeout.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100}});

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& item : dc.monitored_items())
      if (item.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Disabled MI should not produce notifications";
}

// SVR-MI-GEN-011: Sampling mode samples but does not report until mode is changed to Reporting.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-011, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_011_SamplingModeSamplesButNoReport)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Write a value -- this should be sampled but not reported.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});

  // Sampling-mode MI must not produce a notification for our client handle.
  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& item : dc.monitored_items())
      if (item.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Sampling-mode MI should not report notifications";

  // Now switch to Reporting -- queued samples should be reported.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Publish again -- should now see the queued notification.
  auto resp2 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn2 = as_data_change(resp2);
  // We expect a notification from the switch to Reporting.
  if (dcn2 != nullptr)
  {
    bool foundAfterSwitch = false;
    for (auto& item : dcn2->monitored_items())
    {
      if (item.client_handle() == 1)
        foundAfterSwitch = true;
    }
    EXPECT_TRUE(foundAfterSwitch) << "After switching to Reporting, queued samples should be delivered";
  }
}

// SVR-MI-GEN-012: Reporting mode samples and reports notifications.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-012, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_012_ReportingModeSamplesAndReports)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());

  // The initial value should be reported on first publish.
  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& item : dc.monitored_items())
      if (item.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  ASSERT_TRUE(notif) << "Reporting mode MI should produce initial notification";
  EXPECT_THAT(*notif, ContainsDataChangeFor(1, good_value_of<int32_t>(42)));
}

// SVR-MI-GEN-013: Enabling a MI should report the first sample immediately.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-013, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_013_EnabledReportsFirstSampleImmediately)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI in Disabled mode.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Disabled, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain any initial publish.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Switch to Reporting.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Publish -- first sample should be reported ASAP.
  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& item : dc.monitored_items())
      if (item.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesOurHandle, 2s);
  ASSERT_TRUE(notif) << "First sample should be reported immediately after enabling";
}

// SVR-MI-GEN-014: Switching to Disabled should delete queued notifications.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-014, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_014_DisabledDeletesQueuedNotifications)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI in Reporting mode with larger queue.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 10});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Disable publishing so notifications queue up.
  set_publishing_mode(*mSession, subId, false);

  // Write several values.
  for (int i = 0; i < 3; ++i)
  {
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200 + i}});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // Switch MI to Disabled -- should clear the queue.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Disabled;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Re-enable publishing. With the MI now Disabled and the queue cleared by
  // the mode transition, no notification for client handle 1 should arrive.
  set_publishing_mode(*mSession, subId, true);
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& item : dc.monitored_items())
      if (item.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Disabled mode should have cleared queued notifications";
}

// ===========================================================================
// MI General -- Queue Management (SVR-MI-GEN-020 through SVR-MI-GEN-025)
// ===========================================================================

// SVR-MI-GEN-020, SVR-MI-GEN-022: discardOldest=true means oldest value is discarded on overflow
// and the next value in the queue gets the overflow flag set (SVR-MI-GEN-022).
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-020, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_020_DiscardOldestTrue)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Disable publishing so notifications queue up.
  set_publishing_mode(*mSession, subId, false);

  // Create MI with queueSize=2, discardOldest=true.
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;  // fastest possible
  params.queue_size() = 2;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good());
  auto revisedQueueSize = resp.results()[0].revised_queue_size();

  // Write 3+ values to overflow the queue.
  // First, write initial + values: the initial value is already queued.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{300}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Re-enable publishing and get notifications.
  set_publishing_mode(*mSession, subId, true);

  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn = as_data_change(pubResp);
  ASSERT_NE(dcn, nullptr) << "Expected DataChangeNotification after overflow";

  // With discardOldest=true, oldest values should be discarded.
  // The most recent values should be present. The number of items depends on revisedQueueSize.
  auto& items = dcn->monitored_items();
  bool hasOurItems = false;
  for (auto& mi : items)
  {
    if (mi.client_handle() == 1)
      hasOurItems = true;
  }
  EXPECT_TRUE(hasOurItems) << "Expected notifications for our MI after overflow";

  // Check for overflow bit on at least one notification.
  bool hasOverflow = false;
  for (auto& mi : items)
  {
    if (mi.client_handle() == 1 && mi.value().status().has_value() && mi.value().status()->overflow())
    {
      hasOverflow = true;
    }
  }
  // Overflow bit should be set when discarding oldest.
  if (revisedQueueSize <= 2)
  {
    EXPECT_TRUE(hasOverflow) << "Overflow bit should be set when oldest is discarded";
  }
}

// SVR-MI-GEN-020, SVR-MI-GEN-023: discardOldest=false means newest value replaces the last value
// in the queue, and the new value gets the overflow flag set (SVR-MI-GEN-023).
TEST_F(ComplianceWithNodes, MI_GEN_020_DiscardOldestFalse)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Disable publishing so notifications queue up.
  set_publishing_mode(*mSession, subId, false);

  // Create MI with queueSize=2, discardOldest=false.
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 2;
  params.discard_oldest() = false;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good());

  // Write values to overflow.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{300}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Re-enable publishing and get notifications.
  set_publishing_mode(*mSession, subId, true);

  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn = as_data_change(pubResp);
  ASSERT_NE(dcn, nullptr) << "Expected DataChangeNotification after overflow";

  // With discardOldest=false, the newest value replaces the last value in the queue.
  // The OLDEST value should still be present. Check overflow bit.
  bool hasOverflow = false;
  for (auto& mi : dcn->monitored_items())
  {
    if (mi.client_handle() == 1 && mi.value().status().has_value() && mi.value().status()->overflow())
    {
      hasOverflow = true;
    }
  }
  EXPECT_TRUE(hasOverflow) << "Overflow bit should be set when newest is replaced (discardOldest=false)";
}

// SVR-MI-GEN-024: Discard policy is irrelevant for queueSize=1.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-024, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_024_DiscardPolicyIgnoredForQueueSize1)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create with discardOldest=true, queueSize=1.
  auto result1 = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  EXPECT_TRUE(result1.status_code().is_good());
  EXPECT_EQ(result1.revised_queue_size(), 1u);

  // Create with discardOldest=false, queueSize=1 -- should also succeed.
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 2;
  params.sampling_interval() = 50.0;
  params.queue_size() = 1;
  params.discard_oldest() = false;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].status_code().is_good());
  EXPECT_EQ(resp.results()[0].revised_queue_size(), 1u);
}

// SVR-MI-GEN-025: Notifications are delivered in queue order.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-025, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_025_NotificationsInQueueOrder)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Ensure the node starts with a value lower than the test writes.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{0}});

  // Disable publishing so notifications queue.
  set_publishing_mode(*mSession, subId, false);

  // Create MI with larger queue.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 0.0, .queueSize = 10});
  ASSERT_TRUE(result.status_code().is_good());

  // Write values in known order.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{10}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{20}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{30}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Re-enable and publish.
  set_publishing_mode(*mSession, subId, true);

  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn = as_data_change(pubResp);
  ASSERT_NE(dcn, nullptr) << "Expected notifications";

  // Extract values for our client handle in order.
  std::vector<int32_t> values;
  for (auto& mi : dcn->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      auto val = mi.value().value().as<int32_t>();
      values.push_back(val);
    }
  }

  // Values should be in increasing order (queue order).
  for (size_t i = 1; i < values.size(); ++i)
  {
    EXPECT_LT(values[i - 1], values[i])
      << "Notifications should be in queue order: " << values[i - 1] << " should be < " << values[i];
  }
}

// SVR-MI-GEN-030: queueSize=0 should be revised to at least 1.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-030, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_030_QueueSizeZeroRevisedTo1)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 0});

  EXPECT_TRUE(result.status_code().is_good());
  EXPECT_GE(result.revised_queue_size(), 1u);
}

// SVR-MI-GEN-030: queueSize=1 should be revised to 1.
TEST_F(ComplianceWithNodes, MI_GEN_030_QueueSize1RevisedTo1)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});

  EXPECT_TRUE(result.status_code().is_good());
  EXPECT_EQ(result.revised_queue_size(), 1u);
}

// ===========================================================================
// MI General -- Data Change Trigger (SVR-MI-GEN-040 through SVR-MI-GEN-053)
// ===========================================================================

// SVR-MI-GEN-040: Default filter (no filter specified) should be STATUS_VALUE.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-040, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_040_DefaultFilterIsStatusValue)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI without specifying a filter.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write a new value -- should trigger notification because default is STATUS_VALUE.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{999}});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto seqNum = resp0.notification_message().sequence_number();
  auto resp = publish_with_ack(*mSession, resp0.subscription_id(), seqNum);
  auto* dcn = as_data_change(resp);
  ASSERT_NE(dcn, nullptr) << "Value change should trigger notification with default STATUS_VALUE filter";

  bool found = false;
  for (auto& item : dcn->monitored_items())
  {
    if (item.client_handle() == 1)
      found = true;
  }
  EXPECT_TRUE(found) << "Value change should be reported with default filter";
}

// SVR-MI-GEN-050: STATUS trigger -- only status changes are reported, not value-only changes.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-050, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_050_StatusOnlyTrigger)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI with STATUS trigger.
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::Status;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write a new value (value change only, status stays Good).
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{777}});

  // With STATUS trigger, a value-only change should NOT be reported.
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "STATUS trigger should NOT report value-only changes";
}

// SVR-MI-GEN-051: STATUS_VALUE trigger -- status or value changes are reported.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-051, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_051_StatusValueTrigger)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write a new value.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{888}});

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesOurHandle, 2s);
  ASSERT_TRUE(notif) << "STATUS_VALUE trigger should report value changes";
  EXPECT_THAT(*notif, ContainsDataChangeFor(1, good_value_of<int32_t>(888)));
}

// SVR-MI-GEN-053: STATUS_VALUE_TIMESTAMP trigger -- status, value, or timestamp changes are reported.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-053, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_053_StatusValueTimestampTrigger)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ReadValueId rv;
  rv.node_id() = mFullAccessVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValueTimestamp;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write same value but with a new source timestamp -- the timestamp change should trigger.
  {
    WriteValue wv;
    wv.node_id() = mFullAccessVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{int32_t{0}};  // same value as initial
    dv.source_timestamp() = UtcTime::now();
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }

  // Per SVR-MI-GEN-053: STATUS_VALUE_TIMESTAMP SHALL report timestamp-only changes.
  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesOurHandle, 2s);
  ASSERT_TRUE(notif) << "STATUS_VALUE_TIMESTAMP should report timestamp-only changes";
}

// ===========================================================================
// MI General -- Initial Value & Deadband (SVR-MI-GEN-060, SVR-MI-GEN-042/043)
// ===========================================================================

// SVR-MI-GEN-060: After create, initial value should be queued (reported on first publish).
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-060, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_060_InitialValueQueuedWithoutFilter)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());

  // First publish should contain the initial value.
  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  ASSERT_TRUE(notif) << "Initial value should be reported on first publish";
  EXPECT_THAT(*notif, ContainsDataChangeFor(1, good_value_of<int32_t>(42))) << "Initial value should be 42";
}

// SVR-MI-GEN-042: Absolute deadband filters small changes.
// @verifies CL-MI-011
// @relation(CL-MI-011, SVR-MI-EVT-015, SVR-MI-GEN-042, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_042_AbsoluteDeadbandFilters)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI with absolute deadband of 10 on the Number variable.
  ReadValueId rv;
  rv.node_id() = mNumberVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = 1;  // Absolute
  filter->deadband_value() = 10.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write value within deadband (change < 10 from initial 0.0).
  {
    WriteValue wv;
    wv.node_id() = mNumberVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{5.0};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good());
  }

  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Change within deadband should NOT produce notification";

  // Now write value outside deadband (change > 10 from last reported value 0.0).
  {
    WriteValue wv;
    wv.node_id() = mNumberVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{15.0};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good());
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto resp2 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn2 = as_data_change(resp2);
  ASSERT_NE(dcn2, nullptr) << "Change exceeding deadband should produce notification";

  bool found = false;
  for (auto& mi : dcn2->monitored_items())
  {
    if (mi.client_handle() == 1)
      found = true;
  }
  EXPECT_TRUE(found) << "Change exceeding deadband should be reported";
}

// SVR-MI-GEN-043: Absolute deadband formula: abs(last - current) > deadband triggers notification.
// @verifies CL-MI-011
// @relation(CL-MI-011, SVR-MI-EVT-015, SVR-MI-GEN-043, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_043_AbsoluteDeadbandFormula)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI with absolute deadband of 5 on the writable variable.
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = 1;  // Absolute
  filter->deadband_value() = 5.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain initial (value = 42).
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write 45 (abs(42-45)=3 < 5 deadband) -- no notification expected.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{45}});

  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "abs(42-45)=3 < deadband 5; should NOT trigger";

  // Write 50 (abs(42-50)=8 > 5 deadband) -- notification expected.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{50}});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto resp2 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn2 = as_data_change(resp2);
  ASSERT_NE(dcn2, nullptr) << "abs(42-50)=8 > deadband 5; should trigger notification";

  bool found2 = false;
  for (auto& mi : dcn2->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      found2 = true;
      EXPECT_EQ(mi.value().value().as<int32_t>(), 50);
    }
  }
  EXPECT_TRUE(found2) << "Change exceeding deadband should be reported";
}

// ===========================================================================
// ModifyMonitoredItems (SVC-ModMI-*)
// ===========================================================================

// SVC-ModMI-001: Changes to sampling interval apply immediately.
TEST_F(ComplianceWithNodes, SVC_ModMI_001_ChangesAppliedImmediately)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Modify to a longer sampling interval.
  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = miId;
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = 5000.0;  // 5 seconds
  modParams.queue_size() = 1;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  EXPECT_TRUE(modResp.results()[0].status_code().is_good());
  EXPECT_GE(modResp.results()[0].revised_sampling_interval(), 5000.0);
}

// SVC-ModMI-003: Illegal values are revised, not rejected.
TEST_F(ComplianceWithNodes, SVC_ModMI_003_IllegalValuesRevised)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Modify with illegal sampling interval.
  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = miId;
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = -99.0;  // illegal
  modParams.queue_size() = 1;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  EXPECT_TRUE(modResp.results()[0].status_code().is_good())
    << "Illegal values should be revised, not rejected: 0x" << std::hex
    << modResp.results()[0].status_code().as_uint32();
  EXPECT_GE(modResp.results()[0].revised_sampling_interval(), 0.0);
}

// SVC-ModMI-005: Revised sampling interval >= requested.
TEST_F(ComplianceWithNodes, SVC_ModMI_005_RevisedSamplingEqualOrHigher)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = miId;
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = 100.0;
  modParams.queue_size() = 1;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  EXPECT_TRUE(modResp.results()[0].status_code().is_good());
  EXPECT_GE(modResp.results()[0].revised_sampling_interval(), 100.0);
}

// Basic: Modify existing MI succeeds.
TEST_F(ComplianceWithNodes, ModifyMI_Success)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = miId;
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = 200.0;
  modParams.queue_size() = 5;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  EXPECT_TRUE(modResp.results()[0].status_code().is_good());
}

// ModifyMI with invalid monitoredItemId.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-EVT-015, SVR-MI-GEN-101, scope=function)
TEST_F(ComplianceWithNodes, ModifyMI_BadMonitoredItemIdInvalid)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = 99999;  // non-existent
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = 200.0;
  modParams.queue_size() = 1;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  EXPECT_TRUE(modResp.results()[0].status_code().is_bad());
  EXPECT_EQ(modResp.results()[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});
}

// ModifyMI with invalid subscription ID.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-EVT-015, SVR-MI-GEN-100, scope=function)
TEST_F(ComplianceWithNodes, ModifyMI_BadSubscriptionIdInvalid)
{
  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = 1;
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = 200.0;
  modParams.queue_size() = 1;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = 99999;  // non-existent
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto result = mSession->monitored_items().try_modify_monitored_items_sync(std::move(modReq));
  // Per spec: Bad_SubscriptionIdInvalid is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "Bad_SubscriptionIdInvalid is service-level, not operation-level";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// ModifyMI with empty items_to_modify list.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-GEN-100, scope=function)
TEST_F(ComplianceWithNodes, ModifyMI_BadNothingToDo)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  // items_to_modify is empty

  auto result = mSession->monitored_items().try_modify_monitored_items_sync(std::move(modReq));
  // Per spec: Bad_NothingToDo is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNothingToDo});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// ===========================================================================
// SetMonitoringMode (SVC-SetMonMode-*)
// ===========================================================================

// SVC-SetMonMode-001: SetMonitoringMode to Reporting causes notifications.
TEST_F(ComplianceWithNodes, SVC_SetMonMode_001_SetToReporting)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI in Disabled mode.
  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Disabled, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain any initial publish.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Switch to Reporting.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Publish should produce a notification.
  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesOurHandle, 2s);
  ASSERT_TRUE(notif) << "Reporting mode should send notifications for our handle";
}

// SVC-SetMonMode-001: SetMonitoringMode to Sampling means no published notifications.
TEST_F(ComplianceWithNodes, SVC_SetMonMode_001_SetToSampling)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Switch to Sampling.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Sampling;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Write a value.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{555}});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Publish -- should not get a notification for our MI.
  auto seqNum = resp0.notification_message().sequence_number();
  auto resp = publish_with_ack(*mSession, resp0.subscription_id(), seqNum);
  auto* dcn = as_data_change(resp);
  if (dcn != nullptr)
  {
    bool found = false;
    for (auto& mi : dcn->monitored_items())
    {
      if (mi.client_handle() == 1)
        found = true;
    }
    EXPECT_FALSE(found) << "Sampling mode should NOT report notifications";
  }
}

// SVC-SetMonMode-001: SetMonitoringMode to Disabled means no sampling.
TEST_F(ComplianceWithNodes, SVC_SetMonMode_001_SetToDisabled)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Switch to Disabled.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Disabled;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Write a value. Disabled MI: no notification for client_handle 1.
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{666}});

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Disabled mode should not produce any notifications";
}

// SVC-SetMonMode-002: Switching to Disabled should clear queued notifications.
TEST_F(ComplianceWithNodes, SVC_SetMonMode_002_DisabledDeletesQueue)
{
  // This is the same as MI_GEN_014. Testing via SetMonitoringMode service.
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 10});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Disable publishing to let queue fill.
  set_publishing_mode(*mSession, subId, false);

  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{200}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Switch MI to Disabled.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Disabled;
  modeReq.monitored_item_ids().push_back(miId);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_good());

  // Re-enable publishing. Disabled mode should have cleared the queue.
  set_publishing_mode(*mSession, subId, true);
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Disabled should have cleared the notification queue";
}

// SetMonitoringMode with invalid subscription ID.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-EVT-015, SVR-MI-GEN-102, scope=function)
TEST_F(ComplianceWithNodes, SetMonitoringMode_BadSubscriptionIdInvalid)
{
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = 99999;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(1);

  auto result = mSession->monitored_items().try_set_monitoring_mode_sync(std::move(modeReq));
  // Per spec: Bad_SubscriptionIdInvalid is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "Bad_SubscriptionIdInvalid is service-level, not operation-level";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// SetMonitoringMode with invalid monitored item ID.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-EVT-015, SVR-MI-GEN-103, scope=function)
TEST_F(ComplianceWithNodes, SetMonitoringMode_BadMonitoredItemIdInvalid)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(99999);  // non-existent

  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  EXPECT_TRUE(modeResp.results()[0].is_bad());
  EXPECT_EQ(modeResp.results()[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

// SetMonitoringMode with invalid mode value.
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST_F(ComplianceWithNodes, SetMonitoringMode_BadMonitoringModeInvalid)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = static_cast<MonitoringMode>(99);  // invalid
  modeReq.monitored_item_ids().push_back(miId);

  auto modeResult = mSession->monitored_items().try_set_monitoring_mode_sync(std::move(modeReq));
  // Per spec: Bad_MonitoringModeInvalid is a service-level result.
  if (modeResult.is_good())
  {
    EXPECT_EQ(
      modeResult.value().response_header().service_result(), StatusCode{Status::BadMonitoringModeInvalid})
      << "Bad_MonitoringModeInvalid is service-level: 0x" << std::hex
      << modeResult.value().response_header().service_result().as_uint32();
  }
  else
  {
    EXPECT_EQ(modeResult.status_code(), StatusCode{Status::BadMonitoringModeInvalid});
  }
}

// SetMonitoringMode with empty monitored_item_ids list.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-GEN-102, scope=function)
TEST_F(ComplianceWithNodes, SetMonitoringMode_BadNothingToDo)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  // monitored_item_ids is empty

  auto result = mSession->monitored_items().try_set_monitoring_mode_sync(std::move(modeReq));
  // Per spec: Bad_NothingToDo is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNothingToDo});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// ===========================================================================
// DeleteMonitoredItems (SVC-DeleteMI-*)
// ===========================================================================

// Delete MI succeeds and no more notifications are produced.
TEST_F(ComplianceWithNodes, DeleteMI_Success)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto result = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain initial.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Delete the MI.
  DeleteMonitoredItemsRequest delReq;
  delReq.subscription_id() = subId;
  delReq.monitored_item_ids().push_back(miId);
  auto delResp = mSession->monitored_items().delete_monitored_items_sync(std::move(delReq));
  ASSERT_EQ(delResp.results().size(), 1u);
  EXPECT_TRUE(delResp.results()[0].is_good());

  // Write a new value.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{999}});

  // Deleted MI should not produce any notifications.
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "Deleted MI should not produce notifications";
}

// DeleteMonitoredItems with non-existent MI ID.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-EVT-015, SVR-MI-GEN-108, scope=function)
TEST_F(ComplianceWithNodes, DeleteMI_BadMonitoredItemIdInvalid)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  DeleteMonitoredItemsRequest delReq;
  delReq.subscription_id() = subId;
  delReq.monitored_item_ids().push_back(99999);

  auto delResp = mSession->monitored_items().delete_monitored_items_sync(std::move(delReq));
  ASSERT_EQ(delResp.results().size(), 1u);
  EXPECT_TRUE(delResp.results()[0].is_bad());
  EXPECT_EQ(delResp.results()[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

// DeleteMonitoredItems with invalid subscription ID.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-EVT-015, SVR-MI-GEN-107, scope=function)
TEST_F(ComplianceWithNodes, DeleteMI_BadSubscriptionIdInvalid)
{
  DeleteMonitoredItemsRequest delReq;
  delReq.subscription_id() = 99999;
  delReq.monitored_item_ids().push_back(1);

  auto result = mSession->monitored_items().try_delete_monitored_items_sync(std::move(delReq));
  // Per spec: Bad_SubscriptionIdInvalid is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "Bad_SubscriptionIdInvalid is service-level, not operation-level";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// DeleteMonitoredItems with empty monitored_item_ids list.
// @verifies CL-MI-022
// @relation(CL-MI-022, SVR-MI-GEN-107, scope=function)
TEST_F(ComplianceWithNodes, DeleteMI_BadNothingToDo)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  DeleteMonitoredItemsRequest delReq;
  delReq.subscription_id() = subId;
  // monitored_item_ids is empty

  auto result = mSession->monitored_items().try_delete_monitored_items_sync(std::move(delReq));
  // Per spec: Bad_NothingToDo is a service-level result.
  if (result.is_good())
  {
    EXPECT_EQ(result.value().response_header().service_result(), StatusCode{Status::BadNothingToDo});
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// ===========================================================================
// Additional gap closure tests
// ===========================================================================

// SVR-MI-GEN-021: Queue overflow sets the Overflow bit on DataValue statusCode.
// @verifies CL-MI-025
// @relation(CL-MI-025, SVR-MI-EVT-015, SVR-MI-GEN-021, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_021_OverflowBitSetOnDiscard)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Disable publishing so notifications queue up.
  set_publishing_mode(*mSession, subId, false);

  // Create MI with small queue.
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 2;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Write enough values to overflow queue (initial + 3 writes > queueSize 2).
  for (int i = 1; i <= 4; ++i)
  {
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{i * 100}});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // Re-enable publishing.
  set_publishing_mode(*mSession, subId, true);

  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn = as_data_change(pubResp);
  ASSERT_NE(dcn, nullptr) << "Expected notifications after queue overflow";

  // Check that overflow bit is set on at least one notification.
  bool hasOverflow = false;
  for (auto& mi : dcn->monitored_items())
  {
    if (mi.client_handle() == 1 && mi.value().status().has_value() && mi.value().status()->overflow())
    {
      hasOverflow = true;
    }
  }
  EXPECT_TRUE(hasOverflow) << "Overflow bit should be set when queue overflows";
}

/// SVR-MI-GEN-041: Deadband is ignored if the status of the data item changes.
/// Even with an absolute deadband filter, a status change must always generate
/// a notification.
/// Bug caught: Server that suppresses status-change notifications because the
/// value didn't exceed the deadband threshold.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-041, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_041_DeadbandIgnoredOnStatusChange)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI with absolute deadband of 1000 on mFullAccessVariableId (has StatusWrite).
  // A deadband of 1000 means no value change will exceed it in this test.
  ReadValueId rv;
  rv.node_id() = mFullAccessVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = 1;  // Absolute
  filter->deadband_value() = 1000.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest createReq;
  createReq.subscription_id() = subId;
  createReq.timestamps_to_return() = TimestampsToReturn::Both;
  createReq.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(createReq));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write value=1 (change of 1 from initial 0 - well within deadband of 1000, no notification).
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{1}});

  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif1 = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif1) << "Value change within deadband should NOT trigger notification";

  // Write a bad status code - this should bypass the deadband filter entirely.
  {
    WriteValue wv;
    wv.node_id() = mFullAccessVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{int32_t{1}};  // Same value, different status
    dv.status() = StatusCode{Status::BadOutOfService};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }

  auto carriesBadStatus = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 && mi.value().status().has_value() &&
          *mi.value().status() == StatusCode{Status::BadOutOfService})
        return true;
    return false;
  };
  auto notif2 = wait_for_data_change(*mSession, subId, carriesBadStatus, 300ms);
  ASSERT_TRUE(notif2) << "SVR-MI-GEN-041: Status change must generate notification even with deadband filter";
}

// CreateMI exceeding per-subscription limit.
// @relation(SVR-MI-GEN-097, scope=function)
TEST_F(ComplianceMonitoredItemLimited, CreateMI_BadTooManyMonitoredItems)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MaxMonitoredItemsPerSubscription is 2.
  // Create 2 MIs (one at a time since MaxMonitoredItemsPerCall is 1).
  auto result1 = create_single_mi(*mSession, subId, mVariableId, {.clientHandle = 1});
  EXPECT_TRUE(result1.status_code().is_good()) << "0x" << std::hex << result1.status_code().as_uint32();

  auto result2 = create_single_mi(*mSession, subId, mVariable2Id, {.clientHandle = 2});
  EXPECT_TRUE(result2.status_code().is_good()) << "0x" << std::hex << result2.status_code().as_uint32();

  // Third MI should fail with too many monitored items.
  auto result3 = create_single_mi(*mSession, subId, mVariable3Id, {.clientHandle = 3});
  EXPECT_TRUE(result3.status_code().is_bad()) << "Third MI should fail when per-subscription limit is 2: 0x"
                                              << std::hex << result3.status_code().as_uint32();
}

// ===========================================================================
// Fixture: ComplianceMIDenySubscribe - RolePermissions deny Read
//
// Part 4 section 5.12.2.1: "When a user adds a monitored item that the user is
// denied read access to, the add operation shall succeed and the
// BadUserAccessDenied shall be returned in the Publish response."
// ===========================================================================
class ComplianceMIDenySubscribe : public ComplianceSecured
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    auto serviceLevel = mServer->address_space().find_node_sync(NodeId{VariableId::Server_ServiceLevel});
    RolePermissionType permissions;
    permissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    permissions.permissions() = PermissionType{{PermissionType::Bit::Browse}};
    serviceLevel.set_role_permissions(std::vector<RolePermissionType>{permissions});

    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::None;
    cfg.securityPolicyId = SecurityPolicyId::None;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceMIDenySubscribe"}));
    mSession->activate_sync();

    // Write a known value to the writable variable in NS0.
    mVariableId = NodeId{VariableId::Server_ServiceLevel};
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
  NodeId mVariableId;
};

/// Part 4 section 5.12.2.1: CreateMonitoredItems succeeds but initial Publish carries
/// BadUserAccessDenied when RolePermissions deny Read.
// Covers SVR-MI-GEN-091 (coverage-audit retag).
TEST_F(ComplianceMIDenySubscribe, MI_AccessDenied_InitialPublishCarriesBadUserAccessDenied)
{
  // Create subscription.
  CreateSubscriptionRequest subReq;
  subReq.requested_publishing_interval() = 50.0;
  subReq.requested_lifetime_count() = 100;
  subReq.requested_max_keep_alive_count() = 10;
  subReq.max_notifications_per_publish() = 0;
  subReq.publishing_enabled() = true;
  auto subResp = mSession->subscriptions().create_subscription_sync(std::move(subReq));
  ASSERT_TRUE(subResp.response_header().service_result().is_good());
  auto subId = subResp.subscription_id();

  // Create monitored item - should succeed with Good despite denied Subscribe.
  CreateMonitoredItemsRequest miReq;
  miReq.subscription_id() = subId;
  miReq.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = mVariableId;
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = 1;
  item.requested_parameters().sampling_interval() = 50.0;
  item.requested_parameters().queue_size() = 1;
  item.requested_parameters().discard_oldest() = true;
  miReq.items_to_create().push_back(std::move(item));

  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  EXPECT_TRUE(miResp.results()[0].status_code().is_good())
    << "CreateMI should succeed even when Subscribe is denied";

  // Publish - initial notification should carry BadUserAccessDenied.
  auto pubResp = mSession->subscriptions().publish_sync(PublishRequest{});
  ASSERT_TRUE(pubResp.response_header().service_result().is_good());

  const DataChangeNotification* dcn = nullptr;
  for (const auto& nd : pubResp.notification_message().notification_data())
  {
    dcn = dynamic_cast<const DataChangeNotification*>(nd.get());
    if (dcn)
      break;
  }

  ASSERT_NE(dcn, nullptr) << "Expected DataChangeNotification in initial Publish";
  ASSERT_FALSE(dcn->monitored_items().empty());

  auto& notification = dcn->monitored_items()[0];
  EXPECT_EQ(notification.client_handle(), 1u);
  ASSERT_TRUE(notification.value().status().has_value());
  EXPECT_EQ(*notification.value().status(), StatusCode{Status::BadUserAccessDenied})
    << "Initial notification should carry BadUserAccessDenied when Subscribe is denied";
}

// ===========================================================================
// Data Change Compliance (SVR-MI-GEN-005, SVR-MI-GEN-044, SVR-MI-GEN-045, SVR-MI-GEN-090)
// ===========================================================================

/// SVR-MI-GEN-005: If MinimumSamplingInterval Attribute is set on a Variable,
/// the server shall revise the requested sampling interval to be at least
/// that value when monitoring the Value attribute.
/// Bug caught: Server ignores MinimumSamplingInterval and returns a lower
/// revisedSamplingInterval.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-005, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_005_RevisedSamplingRespectsMinimum)
{
  // mMinSamplingVariableId has MinimumSamplingInterval=500ms set in the fixture.
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Request a very fast sampling interval (10ms).
  auto result = create_single_mi(*mSession,
    subId,
    mMinSamplingVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 10.0, .queueSize = 1});
  ASSERT_TRUE(result.status_code().is_good());

  // The server must revise the sampling interval to at least 500ms.
  EXPECT_GE(result.revised_sampling_interval(), 500.0)
    << "revisedSamplingInterval should be >= MinimumSamplingInterval (500ms), got "
    << result.revised_sampling_interval();
}

/// SVR-MI-GEN-044: If the monitored item is an array, the entire array is returned
/// when any element exceeds the AbsoluteDeadband or when the array size changes.
/// Bug caught: Server returns only changed elements instead of the entire array.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-044, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_044_DeadbandOnArrayReturnsEntireArray)
{
  // mArrayVariableId is an Int32 array variable {100, 200, 300} set in the fixture.
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI with AbsoluteDeadband=50 on the array variable.
  ReadValueId rv;
  rv.node_id() = mArrayVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = 1;  // Absolute
  filter->deadband_value() = 50.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write array where element [2] changed by 60 (exceeds deadband of 50).
  {
    WriteValue wv;
    wv.node_id() = mArrayVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{100, 200, 360}};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto seqNum = resp0.notification_message().sequence_number();
  auto resp = publish_with_ack(*mSession, resp0.subscription_id(), seqNum);
  auto* dcn = as_data_change(resp);
  ASSERT_NE(dcn, nullptr) << "Expected notification when array element exceeds deadband";

  bool found = false;
  for (auto& mi : dcn->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      found = true;
      // Verify the ENTIRE array is returned, not just the changed element.
      auto& arr = mi.value().value().as<Array<int32_t>>();
      ASSERT_EQ(arr.size(), 3u) << "Entire array should be returned, not just changed elements";
      EXPECT_EQ(arr[0], 100);
      EXPECT_EQ(arr[1], 200);
      EXPECT_EQ(arr[2], 360);
    }
  }
  EXPECT_TRUE(found) << "Expected notification for array change exceeding deadband";
}

/// SVR-MI-GEN-045: DataChangeFilter is always applied to the newest value
/// compared to the last enqueued (current sample) value, not to the
/// intermediate value.
/// Bug caught: Server compares against the previous write instead of the
/// last enqueued value.
// @verifies CL-MI-011
// @relation(CL-MI-011, SVR-MI-EVT-015, SVR-MI-GEN-045, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_045_FilterAppliedToNewestVsLastSample)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI with AbsoluteDeadband=50 on mWritableVariableId (initial 42).
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = 1;  // Absolute
  filter->deadband_value() = 50.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Drain initial notification (last enqueued value = 42).
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write 80: change of 38 from 42 (last enqueued) - within deadband, no notification.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{80}});

  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(notif) << "abs(42-80)=38 < deadband 50; should NOT trigger";

  // Write 100: change of 58 from 42 (last ENQUEUED value, not 80) - exceeds deadband.
  // If server incorrectly compared 100 vs 80 (change of 20), it would miss the notification.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{100}});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto resp2 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto* dcn2 = as_data_change(resp2);
  ASSERT_NE(dcn2, nullptr) << "abs(42-100)=58 > deadband 50; should trigger notification";

  bool found2 = false;
  for (auto& mi : dcn2->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      found2 = true;
      EXPECT_EQ(mi.value().value().as<int32_t>(), 100);
    }
  }
  EXPECT_TRUE(found2) << "Filter should compare against last enqueued value (42), not intermediate (80)";
}

/// SVR-MI-GEN-052: For floating-point values, the server shall check for NaN and only
/// report a single notification when the value enters the NaN state.
/// Bug caught: Server that reports NaN on every sampling cycle, flooding the queue.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-052, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_052_NaNSingleNotification)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI on the Number variable (DataType=Number, accepts double).
  auto result = create_single_mi(*mSession,
    subId,
    mNumberVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 10});
  ASSERT_TRUE(result.status_code().is_good());

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto seqNum = resp0.notification_message().sequence_number();

  // Write NaN.
  {
    WriteValue wv;
    wv.node_id() = mNumberVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{std::numeric_limits<double>::quiet_NaN()};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good());
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // First publish after NaN - should get exactly one NaN notification.
  auto resp1 = publish_with_ack(*mSession, resp0.subscription_id(), seqNum);
  seqNum = resp1.notification_message().sequence_number();
  auto* dcn1 = as_data_change(resp1);
  ASSERT_NE(dcn1, nullptr) << "Expected notification when value enters NaN state";

  int nanCount = 0;
  for (auto& mi : dcn1->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      auto val = mi.value().value().as<double>();
      if (std::isnan(val))
        ++nanCount;
    }
  }
  EXPECT_EQ(nanCount, 1) << "Entering NaN state should produce exactly one notification";

  // Wait for several sampling cycles and publish again - no further NaN notifications.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  acknowledge(*mSession, subId, seqNum);

  auto carriesNaNForOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
    {
      if (mi.client_handle() == 1 && std::isnan(mi.value().value().as<double>()))
        return true;
    }
    return false;
  };
  auto notif2 = wait_for_data_change(*mSession, subId, carriesNaNForOurHandle, 300ms);
  EXPECT_FALSE(notif2) << "NaN should not produce repeated notifications once in NaN state";
}

/// SVR-MI-GEN-071: Attributes other than Value are only monitored for a change in value.
/// The filter is not used. Any change in value causes a notification.
/// Bug caught: Server that applies deadband/data change filters to non-value attributes.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-071, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_071_NonValueAttributeAnyChangeTriggers)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Monitor the DisplayName attribute of mWritableDisplayNameNodeId (has WriteMask.DisplayName).
  ReadValueId rv;
  rv.node_id() = mWritableDisplayNameNodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;
  // No filter - spec says filter is not used for non-value attributes.

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest createReq;
  createReq.subscription_id() = subId;
  createReq.timestamps_to_return() = TimestampsToReturn::Both;
  createReq.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(createReq));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good());

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write a new DisplayName value.
  {
    WriteValue wv;
    wv.node_id() = mWritableDisplayNameNodeId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);
    DataValue dv;
    dv.value() = Variant{LocalizedText{"en", "ChangedDisplay"}};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    EXPECT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesOurHandle, 2s);
  ASSERT_TRUE(notif) << "SVR-MI-GEN-071: Any change to a non-value attribute must trigger notification";

  bool sawNewValue = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      ASSERT_FALSE(mi.value().value().empty())
        << "Non-value attribute notification should carry the new value";
      auto displayName = mi.value().value().as<LocalizedText>();
      EXPECT_EQ(std::string{displayName.text()}, "ChangedDisplay");
      sawNewValue = true;
    }
  }
  EXPECT_TRUE(sawNewValue) << "Non-value attribute change should generate notification";
}

// ===========================================================================
// DeleteOnlyNodeManagementDelegate: minimal delegate for delete-node tests
// ===========================================================================
class DeleteOnlyNodeManagementDelegate final : public server::NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const Context> /*context*/, AddressSpace /*addressSpace*/,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    server::NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<server::NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (size_t i = 0; i < items.size(); ++i)
    {
      batch.items.emplace_back(StatusCode{Status::BadNotSupported});
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const Context> /*context*/, AddressSpace /*addressSpace*/,
    std::vector<AddReferencesItem> items,
    server::NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.assign(items.size(), VoidResult{StatusCode{Status::BadNotSupported}});
    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const Context> /*context*/, AddressSpace addressSpace,
    std::vector<DeleteNodesItem> items,
    server::NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.reserve(items.size());
    for (auto& item : items)
    {
      auto result = addressSpace.try_delete_node_sync(item.node_id(),
        item.delete_target_references(),
        item.delete_target_references() ? ReferenceHalves::Both : ReferenceHalves::ThisHalfOnly);
      batch.items.emplace_back(result.is_good() ? VoidResult{} : VoidResult{result.status_code()});
    }
    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const Context> /*context*/, AddressSpace /*addressSpace*/,
    std::vector<DeleteReferencesItem> items,
    server::NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.assign(items.size(), VoidResult{StatusCode{Status::BadNotSupported}});
    callback(std::move(batch));
  }
};

// ===========================================================================
// ComplianceWithNodeManagement: extends ComplianceWithNodes with delete support
// ===========================================================================
class ComplianceWithNodeManagement : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto delegate = std::make_shared<DeleteOnlyNodeManagementDelegate>();
    mServer.server().set_node_management_delegate(ua::test::offloaded(delegate));
  }
};

/// SVR-MI-GEN-090: If the node being monitored is deleted, the MonitoredItem
/// generates a notification with StatusCode BadNodeIdUnknown, but the
/// MonitoredItem itself is NOT deleted.
/// Bug caught: Server silently deletes the MI when the node is deleted,
/// or doesn't send the error notification.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-090, SVR-MI-GEN-092, scope=function)
TEST_F(ComplianceWithNodeManagement, MI_GEN_090_NodeDeletionGeneratesBadNodeIdUnknown)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Create MI on the fixture's deletable variable.
  auto result = create_single_mi(*mSession,
    subId,
    mDeletableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(result.status_code().is_good());
  auto miId = result.monitored_item_id();

  // Drain initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto seqNum = resp0.notification_message().sequence_number();

  // Delete the node via the client-side DeleteNodes service.
  DeleteNodesRequest delReq;
  DeleteNodesItem delItem;
  delItem.node_id() = mDeletableVariableId;
  delItem.delete_target_references() = true;
  delReq.nodes_to_delete().push_back(std::move(delItem));
  auto delResp = mSession->node_management().delete_nodes_sync(std::move(delReq));
  ASSERT_EQ(delResp.results().size(), 1u);
  EXPECT_TRUE(delResp.results()[0].is_good()) << "DeleteNodes should succeed";

  // Publish with retries - MI needs time to detect node deletion on next sample cycle.
  bool foundBadStatus = false;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto resp = publish_with_ack(*mSession, resp0.subscription_id(), seqNum);
    seqNum = resp.notification_message().sequence_number();
    auto* dcn = as_data_change(resp);
    if (dcn == nullptr)
      continue;
    for (auto& mi : dcn->monitored_items())
    {
      if (mi.client_handle() == 1 && mi.value().status().has_value())
      {
        if (*mi.value().status() == StatusCode{Status::BadNodeIdUnknown})
          foundBadStatus = true;
      }
    }
    if (foundBadStatus)
      break;
  }
  EXPECT_TRUE(foundBadStatus) << "Node deletion should generate BadNodeIdUnknown notification on the MI";

  // Verify the MI still exists: ModifyMonitoredItems should NOT return BadMonitoredItemIdInvalid.
  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = miId;
  MonitoringParameters modParams;
  modParams.client_handle() = 1;
  modParams.sampling_interval() = 100.0;
  modParams.queue_size() = 5;
  modParams.discard_oldest() = true;
  modItem.requested_parameters() = std::move(modParams);

  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));

  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  EXPECT_NE(modResp.results()[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
    << "MI should still exist after the monitored node is deleted";
}

// ===========================================================================
// Triggering Compliance (SVR-MI-GEN-081 through SVR-MI-GEN-088)
// ===========================================================================

/// SVR-MI-GEN-084, SVR-MI-GEN-082: If the linked item is in SAMPLING mode, it is reported when
/// the triggering item fires (SVR-MI-GEN-084). The triggering item in REPORTING mode is also
/// reported when it triggers (SVR-MI-GEN-082).
/// Bug caught: Triggering link never fires (triggeredReportPending not set).
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-084, scope=function)
// @verifies AC-SVR-MI-GEN-082-TRIGGERING-REPORTING
TEST_F(ComplianceWithNodes, MI_GEN_084_TriggeredSamplingItemReportedOnTrigger)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode, on mWritableVariableId.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, SAMPLING mode, on mFullAccessVariableId.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // SetTriggering: A triggers B.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good())
    << "0x" << std::hex << trigResp.add_results()[0].as_uint32();

  // Drain initial notifications (MI-A in Reporting produces initial value).
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write to MI-B's node (so it has a sampled value in its queue).
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{500}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // Write to MI-A's node (triggers MI-A, which should trigger MI-B).
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{999}});

  // Publish - expect notifications for BOTH clientHandle=1 (MI-A) AND clientHandle=2 (MI-B).
  // Filter for the linked-item handle (the harder one to land - only fires when triggered).
  auto carriesLinkedItem = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 2)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesLinkedItem, 2s);
  ASSERT_TRUE(notif) << "Linked item (Sampling) should be reported when triggered";

  bool foundA = false;
  bool foundB = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
      foundA = true;
    if (mi.client_handle() == 2)
      foundB = true;
  }
  EXPECT_TRUE(foundA) << "Triggering item (Reporting) should be in notification";
  EXPECT_TRUE(foundB) << "Linked item (Sampling) should be reported when triggered";
}

// SetTriggering with an invalid triggeringItemId is a SERVICE-level failure (Part 4 Table 79 lists
// Bad_MonitoredItemIdInvalid as a SetTriggering Service Result Code), not a per-link result with a
// Good service result. The UACTT Monitor Triggering setup relies on this.
TEST_F(ComplianceWithNodes, SetTriggering_InvalidTriggeringItem_ServiceLevelBadMonitoredItemIdInvalid)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = IntegerId{99999};  // no such monitored item
  trigReq.links_to_add().push_back(miB);
  auto result = mSession->monitored_items().try_set_triggering_sync(std::move(trigReq));

  if (result.is_good())
  {
    EXPECT_EQ(
      result.value().response_header().service_result(), StatusCode{Status::BadMonitoredItemIdInvalid})
      << "invalid triggeringItemId must fault the whole SetTriggering service";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});
  }
}

/// SVR-MI-GEN-081: If the triggering item is in SAMPLING mode, it is NOT reported
/// when it triggers linked items - only the linked items are reported.
/// Bug caught: Server reports the triggering item in Sampling mode.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-081, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_081_TriggeringItemSamplingNotReported)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, SAMPLING mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, SAMPLING mode.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // SetTriggering: A triggers B.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good());

  // Drain any initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write to MI-B's node so it queues a sample.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{600}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // Write to MI-A's node (MI-A samples; triggers MI-B).
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{888}});

  // Publish - expect only clientHandle=2 (MI-B), NOT clientHandle=1 (MI-A).
  auto carriesLinkedItem = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 2)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesLinkedItem, 2s);
  ASSERT_TRUE(notif) << "Linked item (Sampling) should be reported when triggered";

  bool foundA = false;
  bool foundB = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
      foundA = true;
    if (mi.client_handle() == 2)
      foundB = true;
  }
  EXPECT_FALSE(foundA) << "Triggering item in Sampling mode should NOT be reported";
  EXPECT_TRUE(foundB) << "Linked item (Sampling) should be reported when triggered";
}

/// SVR-MI-GEN-083: If the triggering item is DISABLED, it does not trigger
/// linked items.
/// Bug caught: Server fires triggers from disabled items.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-083, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_083_TriggeringItemDisabledNoTrigger)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, DISABLED mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Disabled, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, SAMPLING mode.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // SetTriggering: A triggers B.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good());

  // Drain any initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write to MI-B's node.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{800}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // Write to MI-A's node - MI-A is disabled, should NOT trigger MI-B.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{444}});

  // Publish - expect NEITHER clientHandle=1 NOR clientHandle=2.
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesEither = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 || mi.client_handle() == 2)
        return true;
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesEither, 300ms);
  EXPECT_FALSE(notif) << "Neither the disabled triggering item nor its linked item should be reported";
}

/// SVR-MI-GEN-085: If the linked item is in REPORTING mode, the trigger is
/// effectively ignored - the item reports on its own cycle.
/// Bug caught: Server suppresses Reporting-mode linked items until triggered.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-085, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_085_LinkedItemReportingIgnoresTrigger)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, REPORTING mode.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // SetTriggering: A triggers B.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good());

  // Drain initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  auto seqNum = resp0.notification_message().sequence_number();

  // Write ONLY to MI-B's node (no write to MI-A - no trigger fires).
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{900}});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Publish - MI-B should report on its own (Reporting mode), independently of trigger.
  auto resp = publish_with_ack(*mSession, resp0.subscription_id(), seqNum);
  auto* dcn = as_data_change(resp);
  ASSERT_NE(dcn, nullptr) << "Reporting-mode linked item should report independently";

  bool foundB = false;
  for (auto& mi : dcn->monitored_items())
  {
    if (mi.client_handle() == 2)
      foundB = true;
  }
  EXPECT_TRUE(foundB) << "Linked item in Reporting mode should report on its own cycle";
}

/// SVR-MI-GEN-086: If the linked item is DISABLED, no notification is sent even
/// when the triggering item fires.
/// Bug caught: Server reports disabled linked items when triggered.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-086, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_086_LinkedItemDisabledNoNotification)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, DISABLED mode.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Disabled, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // SetTriggering: A triggers B.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good());

  // Drain initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Write to MI-A's node (triggers MI-A, which fires trigger for MI-B).
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{333}});

  // Publish - expect clientHandle=1 (MI-A reports) but NOT clientHandle=2 (MI-B is disabled).
  // Predicate matches either handle so the helper does NOT silently skip a publish carrying
  // a spurious MI-B notification (which would be the spec violation under test).
  auto carriesEitherItem = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 || mi.client_handle() == 2)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesEitherItem, 2s);
  ASSERT_TRUE(notif) << "Triggering item (Reporting) should produce notification";

  bool foundA = false;
  bool foundB = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
      foundA = true;
    if (mi.client_handle() == 2)
      foundB = true;
  }
  EXPECT_TRUE(foundA) << "Triggering item (Reporting) should be reported";
  EXPECT_FALSE(foundB) << "Disabled linked item should NOT produce notification even when triggered";
}

/// SVR-MI-GEN-087: First trigger occurs when the first notification is queued
/// for the triggering item AFTER the link is created.
/// Bug caught: Server where first trigger doesn't fire until second notification.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-087, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_087_FirstTriggerOnFirstNotification)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, SAMPLING mode.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // Drain initial notifications BEFORE creating the link.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // NOW create the trigger link.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good());

  // Write to MI-B's node so it queues a sample.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{123}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // Write to MI-A's node - FIRST notification after link creation should trigger MI-B.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{456}});

  // Filter for the linked-item handle (must fire on first trigger).
  auto carriesLinkedItem = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 2)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesLinkedItem, 2s);
  ASSERT_TRUE(notif) << "First trigger should fire on the first notification after link creation";

  bool foundA = false;
  bool foundB = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
      foundA = true;
    if (mi.client_handle() == 2)
      foundB = true;
  }
  EXPECT_TRUE(foundA) << "Triggering item should be reported";
  EXPECT_TRUE(foundB) << "First trigger should fire on the first notification after link creation";
}

/// SVR-MI-GEN-088: Deleting the linked item removes the trigger link, but the
/// triggering item continues to function normally.
/// Bug caught: Deleting linked item breaks the triggering item.
// @relation(SVR-MI-EVT-015, SVR-MI-GEN-088, scope=function)
TEST_F(ComplianceWithNodes, MI_GEN_088_DeleteLinkedItemDeletesLink)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, SAMPLING mode.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  // SetTriggering: A triggers B.
  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  EXPECT_TRUE(trigResp.add_results()[0].is_good());

  // Drain initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Delete MI-B.
  DeleteMonitoredItemsRequest delReq;
  delReq.subscription_id() = subId;
  delReq.monitored_item_ids().push_back(miB);
  auto delResp = mSession->monitored_items().delete_monitored_items_sync(std::move(delReq));
  ASSERT_EQ(delResp.results().size(), 1u);
  EXPECT_TRUE(delResp.results()[0].is_good());

  // Write to MI-A's node - MI-A should still trigger normally, MI-B is gone.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{555}});

  auto carriesTriggeringItem = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesTriggeringItem, 2s);
  ASSERT_TRUE(notif) << "Triggering item should still produce notifications after linked item deleted";

  bool foundA = false;
  bool foundB = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
      foundA = true;
    if (mi.client_handle() == 2)
      foundB = true;
  }
  EXPECT_TRUE(foundA) << "Triggering item (MI-A) should still function after linked item deleted";
  EXPECT_FALSE(foundB) << "Deleted linked item (MI-B) should not appear in notifications";
}

// ===========================================================================
// Queue overflow semantics observed through the delivered queue contents
// ===========================================================================

/// Part 4 section 5.12.1.5: when the queue is full the Server either deletes the oldest
/// Notification and queues the new one (discardOldest=TRUE) or REPLACES the last value added to the
/// queue with the new one (discardOldest=FALSE). FALSE is the trap: read as "reject the newest" it
/// keeps the queue permanently stale - the client asked to keep the oldest history AND have the
/// latest value current, and gets a queue whose newest entry never advances. The overflow bit alone
/// cannot tell the two readings apart, so the queue contents themselves have to be inspected.
// @verifies AC-SVR-MI-GEN-020-DISCARDOLDEST
TEST_F(ComplianceWithNodes, MI_GEN_020_FullQueueEvictsOldestOrReplacesLastPerDiscardOldest)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Known baseline so the initial queued sample is 0, not the fixture's 42.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{0}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Let the queues fill instead of draining, so the whole queue is observable in one notification.
  set_publishing_mode(*mSession, subId, false);

  auto keepOldest = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 3,
      .discardOldest = true});
  ASSERT_TRUE(keepOldest.status_code().is_good()) << "0x" << std::hex << keepOldest.status_code().as_uint32();
  ASSERT_EQ(keepOldest.revised_queue_size(), 3u) << "this test needs a three-deep queue";

  auto keepNewest = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 2,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 3,
      .discardOldest = false});
  ASSERT_TRUE(keepNewest.status_code().is_good()) << "0x" << std::hex << keepNewest.status_code().as_uint32();
  ASSERT_EQ(keepNewest.revised_queue_size(), 3u) << "this test needs a three-deep queue";

  // Four samples into a three-deep queue: 0 (initial), then 10, 20, 30.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{10}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{20}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{30}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  set_publishing_mode(*mSession, subId, true);

  auto carriesBothItems = [](const DataChangeNotification& dc)
  {
    bool sawFirst = false;
    bool sawSecond = false;
    for (auto& mi : dc.monitored_items())
    {
      if (mi.client_handle() == 1)
        sawFirst = true;
      if (mi.client_handle() == 2)
        sawSecond = true;
    }
    return sawFirst && sawSecond;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesBothItems, 2s);
  ASSERT_TRUE(notif) << "both queues should be delivered once publishing is re-enabled";

  std::vector<int32_t> discardOldestValues;
  std::vector<int32_t> replaceLastValues;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
      discardOldestValues.push_back(mi.value().value().as<int32_t>());
    else if (mi.client_handle() == 2)
      replaceLastValues.push_back(mi.value().value().as<int32_t>());
  }

  // discardOldest = TRUE: 0 is evicted, 30 is appended -> {10, 20, 30}.
  ASSERT_EQ(discardOldestValues.size(), 3u) << "a three-deep queue must deliver three entries";
  EXPECT_EQ(discardOldestValues[0], 10) << "discardOldest=TRUE must delete the OLDEST entry (0)";
  EXPECT_EQ(discardOldestValues[1], 20);
  EXPECT_EQ(discardOldestValues[2], 30) << "discardOldest=TRUE must append the arriving value";

  // discardOldest = FALSE: the LAST entry (20) is replaced, the earlier ones survive -> {0, 10, 30}.
  ASSERT_EQ(replaceLastValues.size(), 3u) << "a three-deep queue must deliver three entries";
  EXPECT_EQ(replaceLastValues[0], 0) << "discardOldest=FALSE must keep the earlier entries";
  EXPECT_EQ(replaceLastValues[1], 10) << "discardOldest=FALSE must keep the earlier entries";
  EXPECT_EQ(replaceLastValues[2], 30)
    << "discardOldest=FALSE replaces the LAST entry with the arriving value; it must not discard it";
  for (auto value : replaceLastValues)
  {
    EXPECT_NE(value, 20) << "the last entry added (20) is the one that gets replaced";
  }
}

/// Part 4 section 5.12.1.5 and section 7.39.1 Table 181: a discarded DataValue sets the Overflow
/// InfoBit on the surviving value ONLY where the queue is larger than one. A queue of one discards
/// on every sample by design, so a server that treats every overwrite as a loss raises the flag
/// continuously on the most common configuration and the signal stops meaning anything.
// @verifies AC-SVR-MI-GEN-021-OVERFLOW-BIT
TEST_F(ComplianceWithNodes, MI_GEN_021_OverflowBitOnlyWhenQueueLargerThanOne)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{0}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  set_publishing_mode(*mSession, subId, false);

  auto deepQueue = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 4,
      .discardOldest = true});
  ASSERT_TRUE(deepQueue.status_code().is_good()) << "0x" << std::hex << deepQueue.status_code().as_uint32();
  ASSERT_EQ(deepQueue.revised_queue_size(), 4u) << "this test needs a four-deep queue";

  auto singleSlot = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 2,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 1,
      .discardOldest = true});
  ASSERT_TRUE(singleSlot.status_code().is_good()) << "0x" << std::hex << singleSlot.status_code().as_uint32();
  ASSERT_EQ(singleSlot.revised_queue_size(), 1u);

  // Five samples (0 initial, then 10..40) overflow the four-deep queue exactly once and overwrite
  // the single slot four times.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{10}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{20}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{30}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{40}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  set_publishing_mode(*mSession, subId, true);

  auto carriesBothItems = [](const DataChangeNotification& dc)
  {
    bool sawFirst = false;
    bool sawSecond = false;
    for (auto& mi : dc.monitored_items())
    {
      if (mi.client_handle() == 1)
        sawFirst = true;
      if (mi.client_handle() == 2)
        sawSecond = true;
    }
    return sawFirst && sawSecond;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesBothItems, 2s);
  ASSERT_TRUE(notif) << "both queues should be delivered once publishing is re-enabled";

  std::vector<int32_t> deepValues;
  std::vector<int32_t> singleValues;
  bool deepQueueOverflowFlagged = false;
  bool singleSlotOverflowFlagged = false;
  for (auto& mi : notif->monitored_items())
  {
    const bool overflow = mi.value().status().has_value() && mi.value().status()->overflow();
    if (mi.client_handle() == 1)
    {
      deepValues.push_back(mi.value().value().as<int32_t>());
      deepQueueOverflowFlagged = deepQueueOverflowFlagged || overflow;
    }
    else if (mi.client_handle() == 2)
    {
      singleValues.push_back(mi.value().value().as<int32_t>());
      singleSlotOverflowFlagged = singleSlotOverflowFlagged || overflow;
    }
  }

  ASSERT_EQ(deepValues.size(), 4u) << "a four-deep queue must deliver four entries";
  EXPECT_TRUE(deepQueueOverflowFlagged)
    << "a discard on a queue larger than one must set the Overflow InfoBit on the surviving value";

  // The single-slot item took four overwrites - proven by it carrying the NEWEST value - and must
  // still report no overflow.
  ASSERT_EQ(singleValues.size(), 1u) << "a queue of one must deliver exactly one entry";
  EXPECT_EQ(singleValues[0], 40) << "the single slot must hold the newest sample, proving it overwrote";
  EXPECT_FALSE(singleSlotOverflowFlagged)
    << "a queue of one is a sampling window, not a loss: the Overflow bit must NOT be set";
}

/// Part 4 section 5.12.1.5: the discard policy is ignored when the queue size is one - there is no
/// old and new to choose between. Both policies must keep the newest value, and neither may raise
/// the Overflow bit. A server that routes discardOldest=FALSE through its "replace the last entry"
/// path without the size-one short circuit either flags every overwrite or, worse, rejects the
/// arriving sample and freezes the item on its first value.
// @verifies AC-SVR-MI-GEN-024-POLICY-IGNORED-AT-ONE
TEST_F(ComplianceWithNodes, MI_GEN_024_QueueOfOneKeepsNewestUnderEitherDiscardPolicy)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{0}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  set_publishing_mode(*mSession, subId, false);

  auto discardOldestItem = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 1,
      .discardOldest = true});
  ASSERT_TRUE(discardOldestItem.status_code().is_good())
    << "0x" << std::hex << discardOldestItem.status_code().as_uint32();
  ASSERT_EQ(discardOldestItem.revised_queue_size(), 1u);

  auto discardNewestItem = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 2,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 1,
      .discardOldest = false});
  ASSERT_TRUE(discardNewestItem.status_code().is_good())
    << "0x" << std::hex << discardNewestItem.status_code().as_uint32();
  ASSERT_EQ(discardNewestItem.revised_queue_size(), 1u);

  // Three further samples overwrite the single slot repeatedly on both items.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{10}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{20}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{30}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  set_publishing_mode(*mSession, subId, true);

  auto carriesBothItems = [](const DataChangeNotification& dc)
  {
    bool sawFirst = false;
    bool sawSecond = false;
    for (auto& mi : dc.monitored_items())
    {
      if (mi.client_handle() == 1)
        sawFirst = true;
      if (mi.client_handle() == 2)
        sawSecond = true;
    }
    return sawFirst && sawSecond;
  };
  auto notif = wait_for_data_change(*mSession, subId, carriesBothItems, 2s);
  ASSERT_TRUE(notif) << "both single-slot items should be delivered once publishing is re-enabled";

  std::vector<int32_t> discardOldestValues;
  std::vector<int32_t> discardNewestValues;
  bool discardOldestOverflowFlagged = false;
  bool discardNewestOverflowFlagged = false;
  for (auto& mi : notif->monitored_items())
  {
    const bool overflow = mi.value().status().has_value() && mi.value().status()->overflow();
    if (mi.client_handle() == 1)
    {
      discardOldestValues.push_back(mi.value().value().as<int32_t>());
      discardOldestOverflowFlagged = discardOldestOverflowFlagged || overflow;
    }
    else if (mi.client_handle() == 2)
    {
      discardNewestValues.push_back(mi.value().value().as<int32_t>());
      discardNewestOverflowFlagged = discardNewestOverflowFlagged || overflow;
    }
  }

  ASSERT_EQ(discardOldestValues.size(), 1u) << "a queue of one must deliver exactly one entry";
  EXPECT_EQ(discardOldestValues[0], 30) << "queue size 1 with discardOldest=TRUE must keep the NEWEST";
  EXPECT_FALSE(discardOldestOverflowFlagged) << "queue size 1 must not set the Overflow bit";

  ASSERT_EQ(discardNewestValues.size(), 1u) << "a queue of one must deliver exactly one entry";
  EXPECT_EQ(discardNewestValues[0], 30) << "queue size 1 with discardOldest=FALSE must keep the NEWEST";
  EXPECT_FALSE(discardNewestOverflowFlagged) << "queue size 1 must not set the Overflow bit";
}

/// The CTT's Monitor Queueing 012: a queue of two with discardOldest=FALSE overflows, so its tail entry
/// carries the Overflow bit; ModifyMonitoredItems then shrinks it to one. A queue of one never reports
/// Overflow (SVR-MI-GEN-024), and that holds for the entry a shrink keeps as much as for one enqueued.
// @verifies AC-SVR-MI-GEN-024-POLICY-IGNORED-AT-ONE
TEST_F(ComplianceWithNodes, MI_GEN_024_ShrinkingAnOverflowedQueueToOneClearsTheOverflowBit)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{0}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  set_publishing_mode(*mSession, subId, false);

  auto created = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 7,
      .mode = MonitoringMode::Reporting,
      .samplingInterval = 0.0,
      .queueSize = 2,
      .discardOldest = false});
  ASSERT_TRUE(created.status_code().is_good());
  ASSERT_EQ(created.revised_queue_size(), 2u);

  for (int32_t value : {10, 20, 30, 40})
  {
    write_value_async(*mSession, mWritableVariableId, Variant{value});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  MonitoredItemModifyRequest modItem;
  modItem.monitored_item_id() = created.monitored_item_id();
  MonitoringParameters modParams;
  modParams.client_handle() = 7;
  modParams.sampling_interval() = 0.0;
  modParams.queue_size() = 1;
  modParams.discard_oldest() = false;
  modItem.requested_parameters() = std::move(modParams);
  ModifyMonitoredItemsRequest modReq;
  modReq.subscription_id() = subId;
  modReq.timestamps_to_return() = TimestampsToReturn::Both;
  modReq.items_to_modify().push_back(std::move(modItem));
  auto modResp = mSession->monitored_items().modify_monitored_items_sync(std::move(modReq));
  ASSERT_EQ(modResp.results().size(), 1u);
  ASSERT_TRUE(modResp.results()[0].status_code().is_good());
  ASSERT_EQ(modResp.results()[0].revised_queue_size(), 1u);

  set_publishing_mode(*mSession, subId, true);
  auto notif = wait_for_data_change(
    *mSession,
    subId,
    [](const DataChangeNotification& dc)
    {
      for (auto& mi : dc.monitored_items())
        if (mi.client_handle() == 7)
          return true;
      return false;
    },
    2s);
  ASSERT_TRUE(notif) << "the shrunk item should deliver once publishing is re-enabled";
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() != 7)
      continue;
    EXPECT_FALSE(mi.value().status().has_value() && mi.value().status()->overflow())
      << "a queue of one never reports Overflow, including the entry a shrink kept";
  }
}

/// Part 4 section 5.12.2: for a data MonitoredItem a requested queueSize of 0 is a request for the
/// default and a requested 1 is the literal minimum; the Server returns 1 as revisedQueueSize for
/// BOTH. A server that honours 0 literally creates an item with no room to queue anything, reports
/// Good, and then delivers nothing for the life of the subscription.
// @verifies AC-SVR-MI-GEN-030-QUEUESIZE-DEFAULT
TEST_F(ComplianceWithNodes, MI_GEN_030_DataItemQueueSizeZeroAndOneBothRevisedToOne)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  auto requestedZero = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 0});
  ASSERT_TRUE(requestedZero.status_code().is_good()) << "queueSize 0 is a default request, not an error: 0x"
                                                     << std::hex << requestedZero.status_code().as_uint32();
  EXPECT_EQ(requestedZero.revised_queue_size(), 1u)
    << "queueSize 0 on a data item must be revised to the default of 1";

  auto requestedOne = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 1});
  ASSERT_TRUE(requestedOne.status_code().is_good())
    << "0x" << std::hex << requestedOne.status_code().as_uint32();
  EXPECT_EQ(requestedOne.revised_queue_size(), 1u)
    << "queueSize 1 on a data item must be revised to exactly 1";
}

/// Part 4 section 7.17.2: a deadband is applied only where the trigger includes value changes, and
/// is ignored when the status of the data item changes. A deadband compares magnitudes and a status
/// transition has none, so a server that runs the deadband unconditionally suppresses exactly the
/// notification a Status trigger was configured to deliver.
// @verifies AC-SVR-MI-GEN-041-DEADBAND-ONLY-ON-VALUE
TEST_F(ComplianceWithNodes, MI_GEN_041_DeadbandAppliesOnlyWhereTriggerIncludesValueChanges)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Status-ONLY trigger plus an absolute deadband so wide that no value change in this test could
  // ever cross it. mFullAccessVariableId carries StatusWrite, so the status can be driven.
  ReadValueId rv;
  rv.node_id() = mFullAccessVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::Status;
  filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = 1000.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest createReq;
  createReq.subscription_id() = subId;
  createReq.timestamps_to_return() = TimestampsToReturn::Both;
  createReq.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(createReq));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain the initial value (0).
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };

  // A value-only change (0 -> 1, well inside the deadband) must report nothing under a Status trigger.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{1}});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto valueChangeNotif = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(valueChangeNotif) << "a Status trigger must not report a value-only change";

  // The status change carries no magnitude, so the deadband must not be consulted at all.
  {
    WriteValue wv;
    wv.node_id() = mFullAccessVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{int32_t{1}};  // unchanged value; only the status moves
    dv.status() = StatusCode{Status::BadOutOfService};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    ASSERT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }

  auto carriesBadStatus = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 && mi.value().status().has_value() &&
          *mi.value().status() == StatusCode{Status::BadOutOfService})
        return true;
    return false;
  };
  auto statusChangeNotif = wait_for_data_change(*mSession, subId, carriesBadStatus, 2s);
  ASSERT_TRUE(statusChangeNotif)
    << "the deadband must not suppress a status change: the trigger asked for exactly this";
}

// ===========================================================================
// Fixture: ComplianceMonitoredItemWithStringVariable
//
// ComplianceWithNodes has no non-numeric Variable, and an AbsoluteDeadband
// applies only to Variables of a Number DataType - the rejection cannot be
// exercised without one. Adds a scalar String Variable alongside the shared
// fixture nodes.
// ===========================================================================
class ComplianceMonitoredItemWithStringVariable : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();

    mStringVariableId = NodeId{mTestNamespaceIndex, uint32_t{1020}};
    auto stringNode = addressSpace.create_node_sync(mStringVariableId, NodeClass::Variable);
    stringNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto stringVariable = stringNode.as<VariableAccessor>();
    ASSERT_TRUE(stringVariable.has_value());
    stringVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "DeadbandStringVar"});
    stringVariable->set_display_name(LocalizedText{"", "DeadbandStringVar"});
    stringVariable->set_data_type(NodeId{DataTypeId::String});
    stringVariable->write_value_sync(String{"initial"});
    stringVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mStringVariableId);
  }

  NodeId mStringVariableId;
};

/// Part 4 section 7.22.2 defines the AbsoluteDeadband exception by formula, on the lines directly
/// under the prose about "the absolute change ... that shall cause a Notification": "Generate a
/// Notification if (absolute value of (last cached value - current value) > AbsoluteDeadband)", with
/// the last cached value being "the last value pushed to the queue". The comparison is strictly
/// greater - that formula is the corpus's own SPEC-SVR-MI-GEN-043 / SVR-MI-GEN-043 - so a change of
/// exactly the deadbandValue away from the last queued value is suppressed. Because neither 4.9 nor
/// 5.0 is queued, the later value 9.9 is compared with the still-cached 0.0 and reports.
// @verifies AC-SVR-MI-GEN-042-ABSOLUTEDEADBAND
TEST_F(ComplianceMonitoredItemWithStringVariable, MI_GEN_042_AbsoluteDeadbandSuppressesChangesWithinTheBand)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // --- Numeric Variable: deadband 5.0, baseline 0.0 ---
  {
    ReadValueId rv;
    rv.node_id() = mNumberVariableId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    MonitoringParameters params;
    params.client_handle() = 1;
    params.sampling_interval() = 0.0;
    params.queue_size() = 5;
    params.discard_oldest() = true;

    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
    filter->deadband_value() = 5.0;
    params.filter() = std::move(filter);

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(params);

    CreateMonitoredItemsRequest req;
    req.subscription_id() = subId;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.items_to_create().push_back(std::move(item));

    auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
    ASSERT_EQ(createResp.results().size(), 1u);
    ASSERT_TRUE(createResp.results()[0].status_code().is_good())
      << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();
  }

  // Drain the initial value (0.0) so it becomes the comparison baseline.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };

  // A change of 4.9 is inside the band and must report nothing.
  write_value_async(*mSession, mNumberVariableId, Variant{4.9});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto insideBand = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(insideBand) << "a change of 4.9 against a deadband of 5.0 must not report";

  // 4.9 was suppressed, so the last cached value is still the initial 0.0. A sample of exactly 5.0
  // sits on the boundary: |0.0 - 5.0| is not GREATER than 5.0, so the formula suppresses it too.
  write_value_async(*mSession, mNumberVariableId, Variant{5.0});

  auto atBand = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(atBand) << "a change of exactly the deadbandValue is not GREATER than the band and must "
                          "not report (Part 4 section 7.22.2 formula)";

  // A further change of 5.0 takes the value to 9.9, which is 9.9 from the last cached 0.0 and so
  // exceeds the band: this is the criterion's second stimulus, and it must report.
  write_value_async(*mSession, mNumberVariableId, Variant{9.9});

  auto outsideBand = wait_for_data_change(*mSession, subId, carriesOurHandle, 2s);
  ASSERT_TRUE(outsideBand) << "a change beyond the deadbandValue must report";

  bool sawOutsideValue = false;
  for (auto& mi : outsideBand->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      sawOutsideValue = true;
      EXPECT_DOUBLE_EQ(mi.value().value().as<double>(), 9.9)
        << "the reported notification should carry the value that broke the band";
    }
  }
  EXPECT_TRUE(sawOutsideValue) << "the out-of-band change must be reported for our monitored item";
}

/// Part 4 section 7.22.2 fixes the AbsoluteDeadband comparison as "absolute value of (last cached
/// value - current value)", the last cached value being the last one pushed to the queue - not the
/// most recent sample seen. Comparing consecutive samples instead is the plausible reading and it
/// makes slow drift invisible forever: a signal moving by 3 every cycle against a deadband of 5
/// never reports, because no single step exceeds the band, even though the value has walked
/// arbitrarily far from anything the client was ever told.
// @verifies AC-SVR-MI-GEN-043-ABSOLUTEDEADBAND-FORMULA
TEST_F(ComplianceWithNodes, MI_GEN_043_AbsoluteDeadbandAccumulatesFromTheLastCachedValue)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ReadValueId rv;
  rv.node_id() = mNumberVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = 5.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain the initial value (0.0) - the cached value the deadband measures from.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };

  // First move of 3: |0.0 - 3.0| = 3 is inside the band of 5, so nothing is queued and the cached
  // value stays 0.0.
  write_value_async(*mSession, mNumberVariableId, Variant{3.0});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto firstMove = wait_for_data_change(*mSession, subId, carriesOurHandle, 300ms);
  EXPECT_FALSE(firstMove) << "a single move of 3 against a deadband of 5 must not report";

  // Second move of 3 in the same direction: the step is still only 3, but the distance from the
  // last CACHED value is 6 and so exceeds the band.
  write_value_async(*mSession, mNumberVariableId, Variant{6.0});

  auto secondMove = wait_for_data_change(*mSession, subId, carriesOurHandle, 2s);
  ASSERT_TRUE(secondMove) << "the cumulative movement of 6 from the last cached value 0.0 exceeds the "
                             "deadband of 5 and must report, even though neither step alone does";

  bool sawAccumulatedValue = false;
  for (auto& mi : secondMove->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      sawAccumulatedValue = true;
      EXPECT_DOUBLE_EQ(mi.value().value().as<double>(), 6.0)
        << "the notification must carry the value whose accumulated distance broke the band";
    }
  }
  EXPECT_TRUE(sawAccumulatedValue) << "the accumulated change must be reported for our monitored item";
}

/// Part 4 section 7.22.2: a DataChangeFilter is applied to the newest value in the QUEUE against
/// the current sample. The two candidate reference points - newest queued and last published -
/// only diverge once the queue is backed up, which is precisely when filtering matters. A server
/// that measures from the last published value lets a drifting signal through one deadband step per
/// Publish, so the queue fills with samples the filter was configured to suppress.
// @verifies AC-SVR-MI-GEN-045-FILTER-AGAINST-NEWEST-QUEUED
TEST_F(ComplianceWithNodes, MI_GEN_045_FilterComparesAgainstNewestQueuedValueNotLastPublished)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // Known baseline so the initial queued sample is 0, not the fixture's 42.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{0}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = 10.0;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Publish the initial value 0 and acknowledge it: 0 is now the LAST PUBLISHED value.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  // Stop draining so the next accepted sample stays in the queue, unpublished.
  set_publishing_mode(*mSession, subId, false);

  // 20 is 20 away from the published 0 and so passes the band of 10: it is queued and becomes the
  // newest QUEUED value.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{20}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // 25 is only 5 from the queued 20 - inside the band - but 25 from the last published 0. A server
  // comparing against the published value would queue it.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{25}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  set_publishing_mode(*mSession, subId, true);

  auto carriesOurHandle = [subId](const PublishResponse& resp)
  {
    if (resp.subscription_id() != subId)
      return false;
    const auto* dc = as_data_change(resp);
    if (dc == nullptr)
      return false;
    for (auto& mi : dc->monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto pubResp = wait_for_publish(*mSession, carriesOurHandle, 2s);
  ASSERT_TRUE(pubResp) << "the queued sample must be delivered once publishing is re-enabled";

  const auto* dcn = as_data_change(*pubResp);
  ASSERT_NE(dcn, nullptr);

  std::vector<int32_t> delivered;
  for (auto& mi : dcn->monitored_items())
  {
    if (mi.client_handle() == 1)
      delivered.push_back(mi.value().value().as<int32_t>());
  }
  ASSERT_FALSE(delivered.empty()) << "the accepted sample 20 must have been queued and delivered";
  bool delivered20 = false;
  for (auto value : delivered)
  {
    if (value == 20)
      delivered20 = true;
  }
  EXPECT_TRUE(delivered20) << "20 passed the deadband against the published 0 and must be queued";
  for (auto value : delivered)
  {
    EXPECT_NE(value, 25) << "25 is inside the deadband of the newest QUEUED value 20 and must be "
                            "filtered out, however far it is from the last published value";
  }

  // The suppressed sample must not surface on a later Publish either.
  auto carries25 = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 && mi.value().value().as<int32_t>() == 25)
        return true;
    return false;
  };
  auto later = wait_for_data_change_with_ack(
    *mSession, subId, pubResp->notification_message().sequence_number(), carries25, 500ms);
  EXPECT_FALSE(later) << "the filtered sample must never be delivered";
}

/// Part 4 section 7.22.2: DataChangeTrigger STATUS is the narrowest of the three - only a change of
/// the StatusCode reports. It is the trigger a client picks when it wants to hear about the quality
/// of a signal and nothing else, so a server that folds a value comparison into it (the natural
/// shape if STATUS is implemented as a special case of STATUS_VALUE) delivers the whole data stream
/// the client was trying not to subscribe to.
// @verifies AC-SVR-MI-GEN-050-STATUS-TRIGGER
TEST_F(ComplianceWithNodes, MI_GEN_050_StatusTriggerReportsStatusChangesAndNothingElse)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // mFullAccessVariableId carries StatusWrite, so the StatusCode can actually be driven.
  ReadValueId rv;
  rv.node_id() = mFullAccessVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 0.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::Status;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest createReq;
  createReq.subscription_id() = subId;
  createReq.timestamps_to_return() = TimestampsToReturn::Both;
  createReq.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(createReq));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "0x" << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain the initial value (0).
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Change the value repeatedly; the status stays Good throughout.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{11}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{22}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{33}});

  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto valueChanges = wait_for_data_change(*mSession, subId, carriesOurHandle, 500ms);
  EXPECT_FALSE(valueChanges) << "a Status trigger must report none of the value changes";

  // Now move the StatusCode while leaving the value alone - the one change this trigger selects.
  {
    WriteValue wv;
    wv.node_id() = mFullAccessVariableId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    DataValue dv;
    dv.value() = Variant{int32_t{33}};  // unchanged value; only the status moves
    dv.status() = StatusCode{Status::BadOutOfService};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    ASSERT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }

  auto carriesBadStatus = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 && mi.value().status().has_value() &&
          *mi.value().status() == StatusCode{Status::BadOutOfService})
        return true;
    return false;
  };
  auto statusChange = wait_for_data_change(*mSession, subId, carriesBadStatus, 2s);
  ASSERT_TRUE(statusChange) << "a Status trigger must report the StatusCode change: it is the only "
                               "thing this trigger selects";
}

/// Part 4 section 5.12.1.2: Attributes other than Value are monitored only for a change in value,
/// and "the filter is not used for these Attributes" - any change reports. Applying the filter
/// anyway is the plausible uniformity and it suppresses the item entirely: a DataChangeTrigger of
/// Status on a DisplayName can never match, because the Attribute has no StatusCode to change, so
/// the client would monitor the Attribute and be told about it exactly never.
// @verifies AC-SVR-MI-GEN-071-NONVALUE-ATTRIBUTES
TEST_F(ComplianceWithNodes, MI_GEN_071_NonValueAttributeReportsChangeWithAFilterAttached)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  ReadValueId rv;
  rv.node_id() = mWritableDisplayNameNodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = 5;
  params.discard_oldest() = true;

  // A Status trigger matches nothing on an Attribute that has no status: if the filter were
  // consulted at all, this item could never report.
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::Status;
  params.filter() = std::move(filter);

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest createReq;
  createReq.subscription_id() = subId;
  createReq.timestamps_to_return() = TimestampsToReturn::Both;
  createReq.items_to_create().push_back(std::move(item));

  auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(createReq));
  ASSERT_EQ(createResp.results().size(), 1u);
  ASSERT_TRUE(createResp.results()[0].status_code().is_good())
    << "a DataChangeFilter on a non-Value Attribute is ignored, not a reason to refuse the item: 0x"
    << std::hex << createResp.results()[0].status_code().as_uint32();

  // Drain the initial notification.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  {
    WriteValue wv;
    wv.node_id() = mWritableDisplayNameNodeId;
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);
    DataValue dv;
    dv.value() = Variant{LocalizedText{"en", "FilteredDisplay"}};
    wv.value() = std::move(dv);

    WriteRequest wreq;
    wreq.nodes_to_write().push_back(std::move(wv));
    auto wresp = mSession->attributes().write_sync(std::move(wreq));
    ASSERT_EQ(wresp.results().size(), 1u);
    ASSERT_TRUE(wresp.results()[0].is_good()) << "0x" << std::hex << wresp.results()[0].as_uint32();
  }

  auto carriesOurHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesOurHandle, 2s);
  ASSERT_TRUE(notif) << "any change to a non-Value Attribute reports; the attached filter must not "
                        "suppress it";

  bool sawNewValue = false;
  for (auto& mi : notif->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      ASSERT_FALSE(mi.value().value().empty()) << "the notification must carry the new Attribute value";
      auto displayName = mi.value().value().as<LocalizedText>();
      EXPECT_EQ(std::string{displayName.text()}, "FilteredDisplay");
      sawNewValue = true;
    }
  }
  EXPECT_TRUE(sawNewValue) << "the non-Value Attribute change must be reported for our monitored item";
}

/// Part 4 section 5.12.1.6: a triggering item whose monitoring mode is DISABLED does not trigger
/// the items linked to it - its monitoring is off, so there is no notification to trigger from, and
/// the links stay configured for when it is re-enabled. Disabling by SetMonitoringMode AFTER the
/// links exist is the case a server gets wrong: the link table still names the item, so an
/// implementation that fires from the sampler or from the link table rather than from an actually
/// enqueued notification keeps cascading reports out of an item the client has switched off.
// @verifies AC-SVR-MI-GEN-083-DISABLED-TRIGGER-INERT
TEST_F(ComplianceWithNodes, MI_GEN_083_TriggeringItemDisabledAfterLinkingStopsTriggering)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: linked item, SAMPLING mode - it reports only when triggered.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Sampling, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  ASSERT_TRUE(trigResp.add_results()[0].is_good())
    << "0x" << std::hex << trigResp.add_results()[0].as_uint32();

  // Drain the initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  // Control: while MI-A is enabled the link demonstrably fires, so the negative below is a statement
  // about DISABLED and not about a link that never worked.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{700}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{111}});

  auto carriesLinkedItem = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 2)
        return true;
    return false;
  };
  auto triggered = wait_for_data_change_with_ack(
    *mSession, subId, resp0.notification_message().sequence_number(), carriesLinkedItem, 2s);
  ASSERT_TRUE(triggered) << "the link must fire while the triggering item is enabled, or the "
                            "DISABLED assertion below proves nothing";

  // Now switch the triggering item to DISABLED, leaving the link in place.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Disabled;
  modeReq.monitored_item_ids().push_back(miA);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  ASSERT_TRUE(modeResp.results()[0].is_good()) << "0x" << std::hex << modeResp.results()[0].as_uint32();

  // Give MI-B something to report if it were wrongly triggered, then change the disabled item's
  // source.
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{701}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{222}});

  // Predicate matches EITHER handle so a spurious notification is observed rather than skipped: the
  // disabled triggering item must not report, and no triggered item may report either.
  auto carriesEither = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1 || mi.client_handle() == 2)
        return true;
    return false;
  };
  auto afterDisable = wait_for_data_change(*mSession, subId, carriesEither, 500ms);
  EXPECT_FALSE(afterDisable) << "a DISABLED triggering item neither reports nor triggers its links";
}

/// Part 4 section 7.22.2 gives the AbsoluteDeadband both a formula and a scope: a Notification is
/// generated when the absolute value of (last cached value - current value) exceeds the band, and
/// the parameter "applies only to Variables with any Number data type". The scope half is the one a
/// plausible implementation drops. Validating the filter's own parameters - deadband type in range,
/// value non-negative, attribute is Value - looks like complete validation and accepts an
/// AbsoluteDeadband on a String Variable, which the Server would then evaluate as plain equality. Part 4
/// names no status for that case; the Server refuses it with Bad_FilterNotAllowed, which CTT Monitored
/// Items Deadband Filter Err-002/003/005 require. The numeric half is normative; the String half pins
/// the Server's chosen refusal.
// @verifies AC-SVR-MI-GEN-042-ABSOLUTEDEADBAND
// The macro must stay on one line: the traceability tooling matches a single-line TEST_F and reads
// a wrapped one as a test that does not exist.
// clang-format off
TEST_F(ComplianceMonitoredItemWithStringVariable, MI_GEN_042_AbsoluteDeadbandFiltersNumbersAndRefusesOtherTypes)
// clang-format on
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // --- Numeric half: deadband 5.0 on the Number Variable, whose initial value is 0.0. ---
  {
    ReadValueId rv;
    rv.node_id() = mNumberVariableId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    MonitoringParameters params;
    params.client_handle() = 1;
    params.sampling_interval() = 0.0;
    params.queue_size() = 5;
    params.discard_oldest() = true;

    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
    filter->deadband_value() = 5.0;
    params.filter() = std::move(filter);

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(params);

    CreateMonitoredItemsRequest req;
    req.subscription_id() = subId;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.items_to_create().push_back(std::move(item));

    auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
    ASSERT_EQ(createResp.results().size(), 1u);
    ASSERT_TRUE(createResp.results()[0].status_code().is_good())
      << "an AbsoluteDeadband on a Number Variable must be accepted: 0x" << std::hex
      << createResp.results()[0].status_code().as_uint32();
  }

  // Drain the initial value (0.0): it becomes the cached value the band is measured from.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  auto carriesNumericHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };

  // First stimulus - a change of 4.9 against a band of 5.0 stays inside it and reports nothing.
  write_value_async(*mSession, mNumberVariableId, Variant{4.9});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto insideBand = wait_for_data_change(*mSession, subId, carriesNumericHandle, 300ms);
  EXPECT_FALSE(insideBand) << "a change of 4.9 against a deadband of 5.0 must not report";

  // Second stimulus - a further change of 5.0 takes the value to 9.9. Nothing was queued for the
  // first change, so the cached value is still 0.0 and the distance is 9.9: it must report.
  write_value_async(*mSession, mNumberVariableId, Variant{9.9});

  auto outsideBand = wait_for_data_change(*mSession, subId, carriesNumericHandle, 2s);
  ASSERT_TRUE(outsideBand) << "a change beyond the deadbandValue must report";

  bool sawOutOfBandValue = false;
  for (auto& mi : outsideBand->monitored_items())
  {
    if (mi.client_handle() == 1)
    {
      sawOutOfBandValue = true;
      EXPECT_DOUBLE_EQ(mi.value().value().as<double>(), 9.9)
        << "the notification must carry the value that broke the band";
    }
  }
  EXPECT_TRUE(sawOutOfBandValue) << "the out-of-band change must be reported for our monitored item";

  // --- Out of scope: the same filter on a String Variable is refused with Bad_FilterNotAllowed. ---
  ReadValueId stringRv;
  stringRv.node_id() = mStringVariableId;
  stringRv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters stringParams;
  stringParams.client_handle() = 2;
  stringParams.sampling_interval() = 0.0;
  stringParams.queue_size() = 5;
  stringParams.discard_oldest() = true;

  auto stringFilter = std::make_unique<DataChangeFilter>();
  stringFilter->trigger() = DataChangeTrigger::StatusValue;
  stringFilter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
  stringFilter->deadband_value() = 5.0;
  stringParams.filter() = std::move(stringFilter);

  MonitoredItemCreateRequest stringItem;
  stringItem.item_to_monitor() = std::move(stringRv);
  stringItem.monitoring_mode() = MonitoringMode::Reporting;
  stringItem.requested_parameters() = std::move(stringParams);

  CreateMonitoredItemsRequest stringReq;
  stringReq.subscription_id() = subId;
  stringReq.timestamps_to_return() = TimestampsToReturn::Both;
  stringReq.items_to_create().push_back(std::move(stringItem));

  auto stringResult = mSession->monitored_items().try_create_monitored_items_sync(std::move(stringReq));

  ASSERT_TRUE(stringResult.is_good());
  ASSERT_EQ(stringResult.value().results().size(), 1u);
  EXPECT_EQ(stringResult.value().results()[0].status_code(), StatusCode{Status::BadFilterNotAllowed});
}

/// Part 4 section 5.12.1.6: when the item to report is itself in REPORTING mode the triggering link
/// is redundant - the item already delivers on every publishing cycle, so it reports whether or not
/// its triggering item fires. Duplication is the failure mode. An implementation that releases a
/// queued Notification because the link fired, on top of the release the item's own REPORTING mode
/// already performs, sends the same value twice; and one that treats "linked" as "suppressed until
/// triggered" sends it never. Both halves are driven here: one value with the trigger idle, one with
/// the trigger firing, each of which must appear exactly once.
// @verifies AC-SVR-MI-GEN-085-TOREPORT-REPORTING
TEST_F(ComplianceWithNodes, MI_GEN_085_ReportingItemToReportIsNeitherSuppressedNorDuplicated)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: item to report, also REPORTING - the combination under test.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  ASSERT_TRUE(trigResp.add_results()[0].is_good())
    << "0x" << std::hex << trigResp.add_results()[0].as_uint32();

  // Drain the initial values so only the values written below are counted.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  // --- The trigger does not fire: the item to report must still deliver, exactly once. ---
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{900}});

  int untriggeredCopies = 0;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < deadline)
    {
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      const auto* dcn = as_data_change(resp);
      if (dcn == nullptr)
        continue;
      for (auto& mi : dcn->monitored_items())
        if (mi.client_handle() == 2 && mi.value().value().as<int32_t>() == 900)
          ++untriggeredCopies;
    }
  }
  EXPECT_EQ(untriggeredCopies, 1)
    << "a REPORTING item to report delivers on its own schedule with no trigger, and the link must "
       "neither suppress that delivery nor add a second copy of it";

  // --- The trigger fires: the same item must still deliver its value exactly once. ---
  write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{901}});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{999}});

  int triggeredCopies = 0;
  int triggeringItemSightings = 0;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < deadline)
    {
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      const auto* dcn = as_data_change(resp);
      if (dcn == nullptr)
        continue;
      for (auto& mi : dcn->monitored_items())
      {
        if (mi.client_handle() == 1 && mi.value().value().as<int32_t>() == 999)
          ++triggeringItemSightings;
        if (mi.client_handle() == 2 && mi.value().value().as<int32_t>() == 901)
          ++triggeredCopies;
      }
    }
  }
  EXPECT_GT(triggeringItemSightings, 0)
    << "the triggering item must have queued a notification, or the no-duplication assertion below "
       "says nothing about a trigger that fired";
  EXPECT_EQ(triggeredCopies, 1)
    << "a REPORTING item to report reports on its own schedule whether or not the trigger fires: the "
       "link must not queue a second copy of the same value";
}

/// Part 4 section 5.12.1.6(f): if the monitoring mode of the item to report is DISABLED there is no
/// sampling and therefore no Notification - the trigger cannot override the monitoring mode, because
/// there is nothing for it to release. An implementation that keeps the sampler running for a
/// disabled item and merely withholds delivery passes the "nothing is reported" half and fails the
/// "nothing is sampled" half, and the difference is visible: the samples taken while the item was
/// disabled surface the moment the client enables it. So both halves are asserted - no notification
/// while disabled and triggered, and, on enabling, no value from the window in which it was disabled.
// @verifies AC-SVR-MI-GEN-086-TOREPORT-DISABLED
TEST_F(ComplianceWithNodes, MI_GEN_086_DisabledItemToReportIsNeitherSampledNorReported)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // MI-A: triggering item, Reporting mode.
  auto resultA = create_single_mi(*mSession,
    subId,
    mWritableVariableId,
    {.clientHandle = 1, .mode = MonitoringMode::Reporting, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultA.status_code().is_good());
  auto miA = resultA.monitored_item_id();

  // MI-B: item to report, DISABLED. A queue of five leaves room for the burst a sampling
  // implementation would accumulate while the item is disabled.
  auto resultB = create_single_mi(*mSession,
    subId,
    mFullAccessVariableId,
    {.clientHandle = 2, .mode = MonitoringMode::Disabled, .samplingInterval = 50.0, .queueSize = 5});
  ASSERT_TRUE(resultB.status_code().is_good());
  auto miB = resultB.monitored_item_id();

  SetTriggeringRequest trigReq;
  trigReq.subscription_id() = subId;
  trigReq.triggering_item_id() = miA;
  trigReq.links_to_add().push_back(miB);
  auto trigResp = mSession->monitored_items().set_triggering_sync(std::move(trigReq));
  ASSERT_EQ(trigResp.add_results().size(), 1u);
  ASSERT_TRUE(trigResp.add_results()[0].is_good())
    << "0x" << std::hex << trigResp.add_results()[0].as_uint32();

  // Drain the initial notifications.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  // Move the disabled item's source three times, firing the trigger after each move. 703 is the
  // value the item is left holding.
  for (int i = 0; i < 3; ++i)
  {
    write_value_async(*mSession, mFullAccessVariableId, Variant{int32_t{701 + i}});
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    write_value_async(*mSession, mWritableVariableId, Variant{int32_t{331 + i}});
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
  }

  int triggeringItemSightings = 0;
  int disabledItemSightings = 0;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < deadline)
    {
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      const auto* dcn = as_data_change(resp);
      if (dcn == nullptr)
        continue;
      for (auto& mi : dcn->monitored_items())
      {
        // Only the values written above count as evidence that the trigger fired; the fixture's
        // initial 42 would prove nothing.
        if (mi.client_handle() == 1 && mi.value().value().as<int32_t>() >= 331 &&
            mi.value().value().as<int32_t>() <= 333)
          ++triggeringItemSightings;
        if (mi.client_handle() == 2)
          ++disabledItemSightings;
      }
    }
  }
  EXPECT_GT(triggeringItemSightings, 0)
    << "the triggering item must have fired, or the negative below is about a trigger that never ran";
  EXPECT_EQ(disabledItemSightings, 0)
    << "a DISABLED item to report produces no notification when its triggering item fires";

  // Enable the item and let its queue flush. 701 and 702 are intermediate values of the disabled
  // window - no longer current by the time the item is enabled - so they can only reach the client
  // out of a queue that was being filled while the item was DISABLED.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(miB);
  auto modeResp = mSession->monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_EQ(modeResp.results().size(), 1u);
  ASSERT_TRUE(modeResp.results()[0].is_good()) << "0x" << std::hex << modeResp.results()[0].as_uint32();

  int afterEnableSightings = 0;
  int samplesFromTheDisabledWindow = 0;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < deadline)
    {
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      const auto* dcn = as_data_change(resp);
      if (dcn == nullptr)
        continue;
      for (auto& mi : dcn->monitored_items())
      {
        if (mi.client_handle() != 2)
          continue;
        ++afterEnableSightings;
        const auto reported = mi.value().value().as<int32_t>();
        if (reported == int32_t{701} || reported == int32_t{702})
          ++samplesFromTheDisabledWindow;
      }
    }
  }
  EXPECT_GT(afterEnableSightings, 0)
    << "enabling the item must flush whatever it holds, or the absence of disabled-window samples "
       "below is the absence of any delivery at all and proves nothing";
  EXPECT_EQ(samplesFromTheDisabledWindow, 0)
    << "701 and 702 were superseded before the item was enabled: they can only reach the client from "
       "a queue filled while the item was DISABLED, and section 5.12.1.6(f) says a DISABLED item to "
       "report is not sampling at all";
}

/// Part 4 section 7.22.2 gives the AbsoluteDeadband a magnitude and a scope, and both edges are the
/// ones a plausible implementation drops. The magnitude is fixed by the formula in that clause -
/// "Generate a Notification if (absolute value of (last cached value - current value) >
/// AbsoluteDeadband)", the last cached value being "the last value pushed to the queue", the
/// corpus's own SPEC-SVR-MI-GEN-043 - so the band is measured from the last value the client was
/// told about rather than from the previous sample. That is what separates the criterion's two
/// stimuli against a single baseline of 0.0: a change of 4.9 stays inside the band and queues
/// nothing, so the cached value is still 0.0 when the second change, of exactly the deadbandValue,
/// carries the Variable to 9.9 - 9.9 clear of the cached value, and so reported. The scope is the
/// parameter applying only to Variables of a Number DataType: validating only the filter's own
/// fields (deadband type in range, deadbandValue non-negative, attribute is Value) leaves an
/// AbsoluteDeadband on a String Variable outside the normative antecedent. Part 4 assigns no result
/// to that case; the Server refuses it with Bad_FilterNotAllowed rather than evaluate it as equality.
// @verifies AC-SVR-MI-GEN-042-ABSOLUTEDEADBAND
// The macro must stay on one line: the traceability tooling matches a single-line
// TEST_F and reads a wrapped one as a test that does not exist.
// clang-format off
TEST_F(ComplianceMonitoredItemWithStringVariable, MI_GEN_042_AbsoluteDeadbandReportsBeyondTheBandAndRefusesOtherTypes)
// clang-format on
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  // --- Number Variable (initial value 0.0) with an AbsoluteDeadband of 5.0: must be accepted. ---
  {
    ReadValueId rv;
    rv.node_id() = mNumberVariableId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    MonitoringParameters params;
    params.client_handle() = 1;
    params.sampling_interval() = 0.0;
    params.queue_size() = 5;
    params.discard_oldest() = true;

    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
    filter->deadband_value() = 5.0;
    params.filter() = std::move(filter);

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(params);

    CreateMonitoredItemsRequest req;
    req.subscription_id() = subId;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.items_to_create().push_back(std::move(item));

    auto createResp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
    ASSERT_EQ(createResp.results().size(), 1u);
    ASSERT_TRUE(createResp.results()[0].status_code().is_good())
      << "an AbsoluteDeadband on a Number Variable must be accepted: 0x" << std::hex
      << createResp.results()[0].status_code().as_uint32();
  }

  // Drain the initial value (0.0). Both stimuli below are measured against it: the first is
  // suppressed, so it stays the cached value for the second.
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});

  auto carriesNumericHandle = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.client_handle() == 1)
        return true;
    return false;
  };

  // First stimulus - a change of 4.9 is inside a band of 5.0 and reports nothing.
  write_value_async(*mSession, mNumberVariableId, Variant{4.9});
  acknowledge(*mSession, subId, resp0.notification_message().sequence_number());

  auto insideBand = wait_for_data_change(*mSession, subId, carriesNumericHandle, 500ms);
  EXPECT_FALSE(insideBand) << "a change of 4.9 against a deadband of 5.0 is inside the band and must "
                              "not report";

  // Second stimulus - a further change of exactly the deadbandValue, from 4.9 to 9.9. Nothing was
  // queued for 4.9, so the last cached value is still the initial 0.0 and this sample stands 9.9
  // from it, which is past the band and must be delivered.
  write_value_async(*mSession, mNumberVariableId, Variant{9.9});

  int numericSightings = 0;
  bool sawOutOfBandValue = false;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
    while (std::chrono::steady_clock::now() < deadline && !sawOutOfBandValue)
    {
      auto resp = mSession->subscriptions().publish_sync(PublishRequest{});
      const auto* dcn = as_data_change(resp);
      if (dcn == nullptr)
        continue;
      for (auto& mi : dcn->monitored_items())
      {
        if (mi.client_handle() != 1)
          continue;
        ++numericSightings;
        const double* reported = mi.value().value().try_as<double>();
        if (reported != nullptr && *reported == 9.9)
          sawOutOfBandValue = true;
      }
    }
  }
  EXPECT_TRUE(sawOutOfBandValue)
    << "a change of exactly the deadbandValue, measured from the last cached value the client was "
       "given, must report; notifications seen for this item after the write: "
    << numericSightings;

  // --- The same filter on a String Variable is refused with Bad_FilterNotAllowed. ---
  ReadValueId stringRv;
  stringRv.node_id() = mStringVariableId;
  stringRv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters stringParams;
  stringParams.client_handle() = 2;
  stringParams.sampling_interval() = 0.0;
  stringParams.queue_size() = 5;
  stringParams.discard_oldest() = true;

  auto stringFilter = std::make_unique<DataChangeFilter>();
  stringFilter->trigger() = DataChangeTrigger::StatusValue;
  stringFilter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
  stringFilter->deadband_value() = 5.0;
  stringParams.filter() = std::move(stringFilter);

  MonitoredItemCreateRequest stringItem;
  stringItem.item_to_monitor() = std::move(stringRv);
  stringItem.monitoring_mode() = MonitoringMode::Reporting;
  stringItem.requested_parameters() = std::move(stringParams);

  CreateMonitoredItemsRequest stringReq;
  stringReq.subscription_id() = subId;
  stringReq.timestamps_to_return() = TimestampsToReturn::Both;
  stringReq.items_to_create().push_back(std::move(stringItem));

  auto stringResult = mSession->monitored_items().try_create_monitored_items_sync(std::move(stringReq));

  ASSERT_TRUE(stringResult.is_good());
  ASSERT_EQ(stringResult.value().results().size(), 1u);
  EXPECT_EQ(stringResult.value().results()[0].status_code(), StatusCode{Status::BadFilterNotAllowed});
}

// Part 13 section 5.2: an aggregating MonitoredItem delivers calculated values over a live Subscription, and
// must not deliver historical ones - a Subscription is a live feed with no field distinguishing a past
// value from a current one, so history arriving through it is presented to the Client as now.
//
// This Server delivers none, and the reason is upstream of the timestamp question the criterion asks:
// it accepts no aggregating MonitoredItem at all. `MonitoredItemFactory` refuses an `AggregateFilter`
// on a data-change item with `Bad_MonitoredItemFilterUnsupported`
// (`sdk/implementation/server/subscription/ua_monitored_item_factory.cpp:67-75`). With no such item,
// no requested timestamp can be unsupported and nothing can backfill.
//
// So the obligation holds, and the honest test is of the branch the product took rather than of a
// state it cannot reach. What matters is that the refusal is the *right* refusal and that it reaches
// the Client: `Bad_MonitoredItemFilterUnsupported` says "this Server does not do aggregating
// MonitoredItems", which a Client can act on by reading history explicitly.
// `Bad_FilterNotAllowed` - the code this same factory uses for a filter that is wrong for the
// attribute - would tell it something different and false.
//
// The item-level status is what is asserted, not the Service status: Part 4 requires the Service to
// succeed and the failing operation to carry its own code, and a Server that failed the whole request
// would take down the other items in the batch. A conforming DataChangeFilter item is created in the
// same request as the control, so the test distinguishes "this filter was refused" from "this Server
// refuses monitored items".
// @verifies AC-SVR-HIST-AGG-028-NO-PAST-DATA
TEST_F(ComplianceWithNodes, AnAggregatingMonitoredItemIsRefusedSoNoPastDataCanReachTheSubscription)
{
  const auto subscriptionId = ua::test_helpers::create_subscription(*mSession, {.publishingInterval = 50.0});

  CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  // The subject: an AggregateFilter, which is what a Client asking for aggregated live values sends.
  MonitoredItemCreateRequest aggregated;
  aggregated.item_to_monitor().node_id() = mWritableVariableId;
  aggregated.item_to_monitor().attribute_id() = static_cast<IntegerId>(AttributeId::Value);
  aggregated.monitoring_mode() = MonitoringMode::Reporting;
  aggregated.requested_parameters().client_handle() = 1;
  aggregated.requested_parameters().sampling_interval() = 100.0;
  aggregated.requested_parameters().queue_size() = 10;
  aggregated.requested_parameters().filter().inner_unique_ptr() = std::make_unique<AggregateFilter>();
  request.items_to_create().push_back(std::move(aggregated));

  // The control: an ordinary item in the same request, so a whole-request refusal is distinguishable
  // from a per-item one.
  MonitoredItemCreateRequest plain;
  plain.item_to_monitor().node_id() = mWritableVariableId;
  plain.item_to_monitor().attribute_id() = static_cast<IntegerId>(AttributeId::Value);
  plain.monitoring_mode() = MonitoringMode::Reporting;
  plain.requested_parameters().client_handle() = 2;
  plain.requested_parameters().sampling_interval() = 100.0;
  plain.requested_parameters().queue_size() = 10;
  request.items_to_create().push_back(std::move(plain));

  auto response = mSession->monitored_items().create_monitored_items_sync(std::move(request));
  ASSERT_EQ(response.results().size(), 2u);

  EXPECT_EQ(response.results()[1].status_code().as_status(), Status::Good)
    << "the ordinary MonitoredItem in the same request was refused too, so the assertion below is "
       "about this Server refusing monitored items rather than about the AggregateFilter";

  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::BadMonitoredItemFilterUnsupported)
    << "an AggregateFilter monitored item answered 0x" << std::hex
    << response.results()[0].status_code().as_uint32() << std::dec
    << ". If it was accepted, Part 13 section 5.2's obligation now has a subject this test does not "
       "cover and a backfill arm is owed; if it was refused with a different code, a Client is told "
       "something other than 'this Server does not aggregate over a Subscription' and cannot fall "
       "back to reading history";

  ua::test_helpers::delete_subscription(*mSession, subscriptionId);
}
