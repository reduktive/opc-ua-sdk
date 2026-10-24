// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "deferred_namespace.h"
#include "test_utilities.h"
#include "ua_access_control.h"
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_attribute_write_mask.h"
#include "ua_error_detail.h"
#include "ua_namespace_array.h"
#include "ua_namespace_metadata_publication.h"
#include "ua_role_permission_type.h"
#include "ua_server_authentication.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <future>
#include <mutex>

using namespace std::chrono_literals;
using namespace ua;
using namespace ua::server;

namespace
{

class RecordingLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    const std::lock_guard lock(mMutex);
    mEntries.push_back(entry.message);
    for (const auto& field : entry.fields)
    {
      mFields.emplace_back(std::string{field.key});
    }
  }

  bool contains(std::string_view text) const
  {
    const std::lock_guard lock(mMutex);
    return std::any_of(mEntries.begin(),
      mEntries.end(),
      [&](const std::string& entry) { return entry.find(text) != std::string::npos; });
  }

  bool has_field(std::string_view key) const
  {
    const std::lock_guard lock(mMutex);
    return std::find(mFields.begin(), mFields.end(), key) != mFields.end();
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mEntries;
  std::vector<std::string> mFields;
};

std::shared_ptr<const AccessIdentity> make_identity(uint64_t key = 1, std::vector<NodeId> grantedRoles = {},
  std::optional<std::vector<NodeId>> registeredRoles = std::nullopt)
{
  auto user = std::make_shared<UserIdentity>();
  user->kind = UserTokenKind::UserName;
  user->userId = "alice";
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->messageSecurityMode = MessageSecurityMode::None;
  endpoint->endpointUrl = "opc.tcp://test/None";
  if (registeredRoles)
  {
    return std::make_shared<AccessIdentity>(AccessIdentityKey{key},
      std::move(grantedRoles),
      std::move(*registeredRoles),
      std::move(user),
      std::move(endpoint),
      String{"urn:test:client"});
  }
  return std::make_shared<AccessIdentity>(AccessIdentityKey{key},
    std::move(grantedRoles),
    std::move(user),
    std::move(endpoint),
    String{"urn:test:client"});
}

EndpointSecurityContext channel(MessageSecurityMode mode = MessageSecurityMode::None)
{
  EndpointSecurityContext result;
  result.messageSecurityMode = mode;
  result.endpointUrl = "opc.tcp://test/None";
  return result;
}

AccessControl::Verdict authorize_one(AccessControl& accessControl,
  std::shared_ptr<const AccessIdentity> identity, const NodeAccessor& node, AccessOperation operation,
  EndpointSecurityContext endpoint = channel())
{
  std::promise<std::vector<AccessControl::Verdict>> completion;
  auto future = completion.get_future();
  const std::array items{AccessControl::Item{node, operation}};
  accessControl.authorize_async(ua::RequestInfo{},
    std::move(identity),
    items,
    endpoint,
    [&completion](std::vector<AccessControl::Verdict> verdicts)
    { completion.set_value(std::move(verdicts)); });
  auto verdicts = future.get();
  if (verdicts.size() != 1)
    throw std::logic_error{"single-item authorization returned the wrong cardinality"};
  return std::move(verdicts.front());
}

PermissionType read_permission()
{
  return PermissionType{PermissionType::Bit::Read};
}

AccessOperation read_operation(AttributeId attribute)
{
  if (attribute == AttributeId::Value)
  {
    return AccessOperation::Read;
  }
  if (attribute == AttributeId::RolePermissions)
  {
    return AccessOperation::ReadRolePermissions;
  }
  return AccessOperation::Browse;
}

AccessControl::Verdict permitted_verdict(
  const NodeAccessor& node, AttributeId attribute, PermissionType permissions)
{
  return AccessControl::Verdict{.subject = node.get_node_id(),
    .operation = read_operation(attribute),
    .permitted = true,
    .mask = permissions,
    .cause = StatusCode{Status::Good}};
}

RolePermissionType role_permission(const NodeId& roleId, PermissionType permissions)
{
  RolePermissionType result;
  result.role_id() = roleId;
  result.permissions() = permissions;
  return result;
}

std::vector<RolePermissionType> decode_role_permissions(const DataValue& value)
{
  std::vector<RolePermissionType> result;
  if (!value.value().is_array_of_structure())
  {
    return result;
  }
  for (const auto& encoded : value.value().as<Array<RefStructure<Structure>>>())
  {
    if (const auto* permission = dynamic_cast<const RolePermissionType*>(encoded.get()))
    {
      result.push_back(*permission);
    }
  }
  return result;
}

class AccessControlHelperTest : public ::testing::Test
{
protected:
  boost::asio::thread_pool mPool{2};
  AddressSpace mAddressSpace{AddressSpace::create("urn:test:access-control", mPool.get_executor())};
  std::shared_ptr<ua::test::DeferredNamespace> mNamespace;
  uint16_t mNamespaceIndex{};

  void SetUp() override
  {
    mNamespace = ua::test::DeferredNamespace::create("urn:test:deferred", mPool.get_executor());
    mNamespaceIndex = mAddressSpace.add_namespace_sync(mNamespace);
  }

  void TearDown() override
  {
    mNamespace->shutdown_async([](VoidResult) {});
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeAccessor make_node(uint32_t identifier)
  {
    const NodeId nodeId{mNamespaceIndex, identifier};
    mNamespace->create_node(nodeId, NodeClass::Variable);
    return mAddressSpace.find_node_sync(nodeId);
  }
};

class AccessControlProjectionTest : public AccessControlHelperTest
{};

// @relation(AC-SVR-AUTHZ-023-HELPER-COMPLETES-INLINE-ON-A-HIT, scope=function)
// @relation(AC-SVR-AUTHZ-023-RULE-BASED-NAMESPACE-NEVER-MISSES, scope=function)
TEST_F(AccessControlHelperTest, CompletesInlineWhenNothingMissed)
{
  const auto identity = make_identity();
  auto node = make_node(1001);
  mNamespace->grant(identity->key(), node.get_node_id(), read_permission());
  AccessControl accessControl{mAddressSpace, 100ms};

  bool callReturned = false;
  bool completedBeforeReturn = false;
  std::thread::id completionThread;
  const auto callerThread = std::this_thread::get_id();
  const std::array items{AccessControl::Item{node, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts)
    {
      completedBeforeReturn = !callReturned;
      completionThread = std::this_thread::get_id();
      ASSERT_EQ(verdicts.size(), 1u);
      EXPECT_TRUE(verdicts[0].permitted);
    });
  callReturned = true;

  EXPECT_TRUE(completedBeforeReturn);
  EXPECT_EQ(completionThread, callerThread);
  EXPECT_TRUE(mNamespace->effective_permissions_calls().empty());
  EXPECT_EQ(mNamespace->permission_questions(), 1u);
}

// @relation(AC-SVR-AUTHZ-023-HELPER-SUSPENDS-AND-RESUMES, scope=function)
// @relation(AC-SVR-AUTHZ-023-CANNOT-ANSWER-IS-NOT-A-DENIAL, scope=function)
TEST_F(AccessControlHelperTest, SuspendsOnMissAndUsesTheAsynchronousResultDirectly)
{
  const auto identity = make_identity();
  auto node = make_node(1002);
  mNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  AccessControl accessControl{mAddressSpace, 500ms};

  std::promise<std::pair<std::thread::id, AccessControl::Verdict>> completed;
  auto future = completed.get_future();
  const std::array items{AccessControl::Item{node, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts)
    { completed.set_value({std::this_thread::get_id(), verdicts.at(0)}); });

  EXPECT_EQ(future.wait_for(0ms), std::future_status::timeout);
  ASSERT_TRUE(mNamespace->wait_for_pending_resolutions());
  mNamespace->grant(identity->key(), node.get_node_id(), read_permission());
  mNamespace->complete_pending_resolutions();
  ASSERT_EQ(future.wait_for(2s), std::future_status::ready);
  const auto [completionThread, verdict] = future.get();
  EXPECT_EQ(completionThread, mNamespace->worker_thread_id());
  EXPECT_TRUE(verdict.permitted);
  EXPECT_EQ(verdict.mask, read_permission());
  EXPECT_EQ(mNamespace->permission_questions(), 1u);
  EXPECT_EQ(mNamespace->effective_permissions_calls().size(), 1u);
  mNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-EMPTY-MASK-IS-A-DENIAL, scope=function)
TEST_F(AccessControlHelperTest, EmptyMaskDeniesWithoutAsynchronousResolution)
{
  const auto identity = make_identity();
  auto deniedNode = make_node(1003);
  auto allowedNode = make_node(1004);
  mNamespace->deny(identity->key(), deniedNode.get_node_id());
  mNamespace->grant(identity->key(), allowedNode.get_node_id(), read_permission());
  AccessControl accessControl{mAddressSpace, 100ms};

  std::vector<AccessControl::Verdict> result;
  const std::array items{AccessControl::Item{deniedNode, AccessOperation::Read},
    AccessControl::Item{allowedNode, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { result = std::move(verdicts); });

  ASSERT_EQ(result.size(), 2u);
  EXPECT_FALSE(result[0].permitted);
  EXPECT_EQ(result[0].cause.as_status(), Status::BadUserAccessDenied);
  EXPECT_TRUE(result[1].permitted);
  EXPECT_TRUE(mNamespace->effective_permissions_calls().empty());
  EXPECT_EQ(mNamespace->permission_questions(), 2u);
}

// @relation(AC-SVR-AUTHZ-023-MISSES-BATCH-PER-OPERATION, scope=function)
TEST_F(AccessControlHelperTest, MissesOfOneOperationResolveInOneBatch)
{
  const auto identity = make_identity();
  std::array<NodeAccessor, 3> nodes{make_node(1005), make_node(1006), make_node(1007)};
  mNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  AccessControl accessControl{mAddressSpace, 500ms};
  const std::array items{AccessControl::Item{nodes[0], AccessOperation::Read},
    AccessControl::Item{nodes[1], AccessOperation::Read},
    AccessControl::Item{nodes[2], AccessOperation::Read}};
  std::promise<std::vector<AccessControl::Verdict>> completed;
  auto future = completed.get_future();
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { completed.set_value(std::move(verdicts)); });

  ASSERT_TRUE(mNamespace->wait_for_pending_resolutions());
  const auto calls = mNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_TRUE(calls[0].nodes.has_value());
  EXPECT_EQ(*calls[0].nodes,
    (std::vector<NodeId>{nodes[0].get_node_id(), nodes[1].get_node_id(), nodes[2].get_node_id()}));
  for (const auto& node : nodes)
  {
    mNamespace->grant(identity->key(), node.get_node_id(), read_permission());
  }
  mNamespace->complete_pending_resolutions();
  ASSERT_EQ(future.wait_for(2s), std::future_status::ready);
  for (const auto& verdict : future.get())
  {
    EXPECT_TRUE(verdict.permitted);
  }
  mNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-NONCACHING-NAMESPACE-RETURNS-DIRECTLY, scope=function)
TEST_F(AccessControlHelperTest, NonCachingNamespaceReturnsDirectlyWithoutASecondProbe)
{
  const auto identity = make_identity();
  auto node = make_node(1008);
  mNamespace->set_async_permissions(identity->key(), node.get_node_id(), read_permission());
  auto sink = std::make_shared<RecordingLogSink>();
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  AccessControl accessControl{mAddressSpace, 100ms, Logger{sink, level, "test"}};
  const std::array items{AccessControl::Item{node, AccessOperation::Read}};
  for (size_t authorization = 0; authorization < 2; ++authorization)
  {
    std::vector<AccessControl::Verdict> result;
    accessControl.authorize_async(ua::RequestInfo{},
      identity,
      items,
      channel(),
      [&](std::vector<AccessControl::Verdict> verdicts) { result = std::move(verdicts); });
    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].permitted);
    EXPECT_EQ(result[0].mask, read_permission());
  }

  EXPECT_EQ(mNamespace->permission_questions(), 2u);
  EXPECT_EQ(mNamespace->effective_permissions_calls().size(), 2u);
  EXPECT_FALSE(sink->contains("could not resolve"));
}

// @relation(AC-SVR-AUTHZ-023-ASYNC-FAILURE-IS-CONTAINED, scope=function)
// @relation(AC-SVR-AUTHZ-009-PERIODIC-FAILURE-FAILS-CLOSED, scope=function)
TEST_F(AccessControlHelperTest, FailingResolutionDeniesOnlyItsNamespace)
{
  const auto identity = make_identity();
  auto failedNode = make_node(1009);
  mNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Failing);
  auto healthyNamespace = ua::test::DeferredNamespace::create("urn:test:healthy", mPool.get_executor());
  const uint16_t healthyIndex = mAddressSpace.add_namespace_sync(healthyNamespace);
  healthyNamespace->create_node(NodeId{healthyIndex, 1010}, NodeClass::Variable);
  const NodeAccessor healthyNode = mAddressSpace.find_node_sync(NodeId{healthyIndex, 1010});
  healthyNamespace->grant(identity->key(), healthyNode.get_node_id(), read_permission());
  auto sink = std::make_shared<RecordingLogSink>();
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  AccessControl accessControl{mAddressSpace, 100ms, Logger{sink, level, "test"}};

  std::vector<AccessControl::Verdict> result;
  const std::array items{AccessControl::Item{failedNode, AccessOperation::Read},
    AccessControl::Item{healthyNode, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { result = std::move(verdicts); });

  ASSERT_EQ(result.size(), 2u);
  EXPECT_FALSE(result[0].permitted);
  EXPECT_EQ(result[0].cause.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(result[0].cause.shared_detail(), nullptr);
  EXPECT_EQ(result[0].cause.shared_detail()->code, "AuthorizationResolutionFailed");
  ASSERT_NE(result[0].cause.shared_detail()->cause, nullptr);
  EXPECT_EQ(result[0].cause.shared_detail()->cause->code, "DeferredNamespaceResolutionFailed");
  EXPECT_TRUE(sink->has_field("detail"))
    << "the rich namespace failure must be logged before a wire response strips ErrorDetail";
  EXPECT_TRUE(result[1].permitted);
  healthyNamespace->shutdown_async([](VoidResult) {});
}

// @relation(AC-SVR-AUTHZ-023-ASYNC-FAILURE-IS-CONTAINED, scope=function)
TEST_F(AccessControlHelperTest, StalledResolutionTimesOutWithoutChangingAnsweredNamespace)
{
  const auto identity = make_identity();
  auto stalledNode = make_node(1011);
  mNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::NeverCompletes);
  auto healthyNamespace =
    ua::test::DeferredNamespace::create("urn:test:healthy-timeout", mPool.get_executor());
  const uint16_t healthyIndex = mAddressSpace.add_namespace_sync(healthyNamespace);
  healthyNamespace->create_node(NodeId{healthyIndex, 1012}, NodeClass::Variable);
  const NodeAccessor healthyNode = mAddressSpace.find_node_sync(NodeId{healthyIndex, 1012});
  healthyNamespace->grant(identity->key(), healthyNode.get_node_id(), read_permission());
  AccessControl accessControl{mAddressSpace, 30ms};

  std::promise<std::vector<AccessControl::Verdict>> completed;
  auto future = completed.get_future();
  const std::array items{AccessControl::Item{stalledNode, AccessOperation::Read},
    AccessControl::Item{healthyNode, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { completed.set_value(std::move(verdicts)); });

  ASSERT_EQ(future.wait_for(2s), std::future_status::ready);
  const auto result = future.get();
  ASSERT_EQ(result.size(), 2u);
  EXPECT_FALSE(result[0].permitted);
  EXPECT_EQ(result[0].cause.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(result[0].cause.shared_detail(), nullptr);
  EXPECT_EQ(result[0].cause.shared_detail()->code, "AuthorizationResolutionDeadlineExceeded");
  EXPECT_EQ(result[0].cause.shared_detail()->innerStatus, StatusCode{Status::BadTimeout}.as_uint32());
  EXPECT_TRUE(result[1].permitted);
  healthyNamespace->shutdown_async([](VoidResult) {});
}

// @relation(AC-SVR-AUTHZ-012-STATE-ISOLATION, scope=function)
TEST_F(AccessControlHelperTest, EachNamespaceDecidesOnlyFromItsOwnPermissionTable)
{
  const auto identity = make_identity();
  auto secondNamespace =
    ua::test::DeferredNamespace::create("urn:test:isolated-second", mPool.get_executor());
  const uint16_t secondNamespaceIndex = mAddressSpace.add_namespace_sync(secondNamespace);
  auto firstNode = make_node(2001);
  secondNamespace->create_node(NodeId{secondNamespaceIndex, 2001}, NodeClass::Variable);
  const NodeAccessor secondNode = mAddressSpace.find_node_sync(NodeId{secondNamespaceIndex, 2001});
  mNamespace->grant(identity->key(), firstNode.get_node_id(), read_permission());
  secondNamespace->deny(identity->key(), secondNode.get_node_id());
  AccessControl accessControl{mAddressSpace, 100ms};

  std::vector<AccessControl::Verdict> result;
  const std::array items{AccessControl::Item{firstNode, AccessOperation::Read},
    AccessControl::Item{secondNode, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { result = std::move(verdicts); });

  ASSERT_EQ(result.size(), 2u);
  EXPECT_TRUE(result[0].permitted);
  EXPECT_FALSE(result[1].permitted);
  EXPECT_TRUE(mNamespace->effective_permissions_calls().empty());
  EXPECT_TRUE(secondNamespace->effective_permissions_calls().empty());
  EXPECT_EQ(mNamespace->permission_questions(), 1u);
  EXPECT_EQ(secondNamespace->permission_questions(), 1u);
  secondNamespace->shutdown_async([](VoidResult) {});
}

// @relation(AC-SVR-AUTHZ-015-CHANNEL-REFUSAL-NOT-FLATTENED, scope=function)
// @relation(AC-SVR-AUTHZ-008-NAMESPACE-DEFAULT-APPLIES, scope=function)
TEST_F(AccessControlHelperTest, ChannelGateRunsBeforeTheNamespacePermissionQuestion)
{
  const auto identity = make_identity();
  auto node = make_node(1013);
  mNamespace->grant(identity->key(), node.get_node_id(), read_permission());
  mNamespace->set_default_access_restrictions(
    AccessRestrictionType{AccessRestrictionType::Bit::SigningRequired});
  AccessControl accessControl{mAddressSpace, 100ms};

  std::vector<AccessControl::Verdict> result;
  const std::array items{AccessControl::Item{node, AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(MessageSecurityMode::None),
    [&](std::vector<AccessControl::Verdict> verdicts) { result = std::move(verdicts); });

  ASSERT_EQ(result.size(), 1u);
  EXPECT_TRUE(result[0].channelRefused);
  EXPECT_EQ(result[0].cause.as_status(), Status::BadSecurityModeInsufficient);
  EXPECT_EQ(mNamespace->permission_questions(), 0u);
  EXPECT_TRUE(mNamespace->effective_permissions_calls().empty());
}

// @relation(AC-SVR-AUTHZ-023-CANNOT-ANSWER-IS-NOT-A-DENIAL, scope=function)
TEST_F(AccessControlHelperTest, ImmediateMissUsesTheAsynchronousResultAndFailsClosed)
{
  const auto identity = make_identity();
  auto node = make_node(1014);
  AccessControl accessControl{mAddressSpace, 100ms};

  const auto verdict = authorize_one(accessControl, identity, node, AccessOperation::Read);

  EXPECT_FALSE(verdict.permitted);
  EXPECT_EQ(verdict.cause.as_status(), Status::BadUserAccessDenied);
  EXPECT_EQ(mNamespace->permission_questions(), 1u);
  ASSERT_EQ(mNamespace->effective_permissions_calls().size(), 1u);
  EXPECT_EQ(mNamespace->effective_permissions_calls()[0].identity, identity->key());
}

// @relation(AC-SVR-AUTHZ-022-CONCURRENT-DELETE-SURVIVES, scope=function)
TEST_F(AccessControlHelperTest, DeletedNodeIsReportedWithoutThrowingOrAsynchronousResolution)
{
  const auto identity = make_identity();
  auto node = make_node(1016);
  const NodeId nodeId = node.get_node_id();
  ASSERT_TRUE(mNamespace->delete_node(nodeId, false).is_good());
  AccessControl accessControl{mAddressSpace, 100ms};

  std::vector<AccessControl::Verdict> result;
  const std::array items{AccessControl::Item{node, AccessOperation::Read}};
  EXPECT_NO_THROW(accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { result = std::move(verdicts); }));

  ASSERT_EQ(result.size(), 1u);
  EXPECT_FALSE(result[0].permitted);
  EXPECT_EQ(result[0].cause.as_status(), Status::BadNodeIdUnknown);
  EXPECT_TRUE(mNamespace->effective_permissions_calls().empty());
}

// @relation(AC-SVR-AUTHZ-003-DESTINATION-DECIDES, scope=function)
TEST_F(AccessControlHelperTest, NamespaceDecisionUsesDefaultRolePermissionsAndAddNodeBit)
{
  const NodeId roleId{1, 7001};
  const auto identity = make_identity(1, {roleId});
  RolePermissionType grant;
  grant.role_id() = roleId;
  grant.permissions() = PermissionType{PermissionType::Bit::AddNode};
  mNamespace->set_default_role_permissions(std::vector<RolePermissionType>{grant});
  AccessControl accessControl{mAddressSpace, 100ms};

  std::optional<AccessControl::Verdict> granted;
  accessControl.authorize_namespace_async(ua::RequestInfo{},
    identity,
    mNamespaceIndex,
    channel(),
    [&](AccessControl::Verdict verdict) { granted = verdict; });
  ASSERT_TRUE(granted.has_value());
  EXPECT_TRUE(granted->permitted);

  mNamespace->set_default_role_permissions(std::nullopt);
  std::optional<AccessControl::Verdict> vendorModel;
  accessControl.authorize_namespace_async(ua::RequestInfo{},
    identity,
    mNamespaceIndex,
    channel(),
    [&](AccessControl::Verdict verdict) { vendorModel = verdict; });
  ASSERT_TRUE(vendorModel.has_value());
  EXPECT_FALSE(vendorModel->permitted);
  EXPECT_EQ(vendorModel->cause.as_status(), Status::BadUserAccessDenied);
}

// @relation(AC-SVR-AUTHZ-023-ABSENT-NODE-BATCH-MEANS-NAMESPACE, scope=function)
TEST_F(AccessControlHelperTest, NamespaceSubjectUsesAbsentNodeBatch)
{
  const auto identity = make_identity();
  mNamespace->set_async_namespace_permissions(PermissionType{PermissionType::Bit::AddNode});
  AccessControl accessControl{mAddressSpace, 100ms};

  std::optional<AccessControl::Verdict> result;
  accessControl.authorize_namespace_async(ua::RequestInfo{},
    identity,
    mNamespaceIndex,
    channel(),
    [&](AccessControl::Verdict verdict) { result = verdict; });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->permitted);
  EXPECT_TRUE(result->mask.test(PermissionType::Bit::AddNode));
  EXPECT_EQ(mNamespace->permission_questions(), 1u);
  const auto calls = mNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 1u);
  EXPECT_FALSE(calls.front().nodes.has_value());
}

// @relation(AC-SVR-AUTHZ-025-UNREGISTERED-ROLE-IS-A-DISTINCT-CAUSE, scope=function)
TEST_F(AccessControlHelperTest, UnregisteredRoleReportsADistinctCause)
{
  const NodeId unregisteredRole{1, "unregistered-role"};
  const NodeId registeredRole{1, "registered-role"};
  auto nameSpace = mAddressSpace.create_namespace("urn:test:role-diagnostics", {});
  const uint16_t namespaceIndex = mAddressSpace.add_namespace_sync(nameSpace);
  auto node = mAddressSpace.create_node_sync(NodeId{namespaceIndex, "protected"}, NodeClass::Variable);

  RolePermissionType unknownPermission;
  unknownPermission.role_id() = unregisteredRole;
  unknownPermission.permissions() = read_permission();
  node.set_role_permissions(std::vector<RolePermissionType>{unknownPermission});

  const auto identity = make_identity(90, {unregisteredRole}, std::vector<NodeId>{registeredRole});
  AccessControl accessControl{mAddressSpace, 100ms};
  const auto unknownVerdict = authorize_one(accessControl, identity, node, AccessOperation::Read);
  ASSERT_FALSE(unknownVerdict.permitted);
  ASSERT_NE(unknownVerdict.cause.shared_detail(), nullptr);
  EXPECT_EQ(unknownVerdict.cause.shared_detail()->code, "RoleUnknownToConfiguration");
  const auto unknownRoleContext = std::find_if(unknownVerdict.cause.shared_detail()->context.begin(),
    unknownVerdict.cause.shared_detail()->context.end(),
    [](const NamedValue& value) { return value.key == ContextKeys::actual.value(); });
  ASSERT_NE(unknownRoleContext, unknownVerdict.cause.shared_detail()->context.end());
  EXPECT_EQ(unknownRoleContext->value, unregisteredRole.as_definition());

  RolePermissionType notGrantedPermission;
  notGrantedPermission.role_id() = registeredRole;
  notGrantedPermission.permissions() = read_permission();
  node.set_role_permissions(std::vector<RolePermissionType>{notGrantedPermission});
  const auto notGrantedVerdict = authorize_one(accessControl, identity, node, AccessOperation::Read);
  ASSERT_FALSE(notGrantedVerdict.permitted);
  ASSERT_NE(notGrantedVerdict.cause.shared_detail(), nullptr);
  EXPECT_EQ(notGrantedVerdict.cause.shared_detail()->code, "RoleNotGranted");
}

// @relation(AC-SVR-AUTHZ-025-UNREGISTERED-ROLE-IS-A-DISTINCT-CAUSE, scope=function)
TEST_F(AccessControlHelperTest, AnUnregisteredRoleTheCallerDoesNotHoldLeavesTheGrantIntact)
{
  const NodeId foreignRole{1, "role-from-an-imported-model"};
  const NodeId grantedRole{1, "granted-role"};
  auto nameSpace = mAddressSpace.create_namespace("urn:test:foreign-role-entry", {});
  const uint16_t namespaceIndex = mAddressSpace.add_namespace_sync(nameSpace);
  auto node = mAddressSpace.create_node_sync(NodeId{namespaceIndex, "protected"}, NodeClass::Variable);

  // The shape a NodeSet import produces: the file names a Role of its own that this server never
  // registered, alongside a Role the caller does hold. The foreign entry can only ever add
  // permissions to a Session holding that Role, so it must not subtract from anyone else's.
  RolePermissionType foreignPermission;
  foreignPermission.role_id() = foreignRole;
  foreignPermission.permissions() = read_permission();
  RolePermissionType grantedPermission;
  grantedPermission.role_id() = grantedRole;
  grantedPermission.permissions() = read_permission();
  node.set_role_permissions(std::vector<RolePermissionType>{foreignPermission, grantedPermission});

  const auto identity = make_identity(91, {grantedRole}, std::vector<NodeId>{grantedRole});
  AccessControl accessControl{mAddressSpace, 100ms};
  const auto verdict = authorize_one(accessControl, identity, node, AccessOperation::Read);

  EXPECT_TRUE(verdict.permitted)
    << "a RolePermissions entry for an unheld, unregistered Role must not deny a Role that is granted";
  EXPECT_TRUE(verdict.mask.test(PermissionType::Bit::Read));
}

// @relation(AC-SVR-SECADMIN-053-CACHE-INVALIDATION, scope=function)
TEST_F(AccessControlHelperTest, NodePermissionChangesAreVisibleToTheSameIdentityImmediately)
{
  const NodeId roleId{1, "live-role"};
  auto nameSpace = mAddressSpace.create_namespace("urn:test:live-permissions", {});
  const uint16_t namespaceIndex = mAddressSpace.add_namespace_sync(nameSpace);
  auto node = mAddressSpace.create_node_sync(NodeId{namespaceIndex, "live-node"}, NodeClass::Variable);
  RolePermissionType grant;
  grant.role_id() = roleId;
  grant.permissions() = PermissionType{PermissionType::Bit::Read};
  node.set_role_permissions(std::vector<RolePermissionType>{grant});
  const auto identity = make_identity(91, {roleId}, std::vector<NodeId>{roleId});
  AccessControl accessControl{mAddressSpace, 100ms};

  EXPECT_TRUE(authorize_one(accessControl, identity, node, AccessOperation::Read).permitted);
  node.set_role_permissions(std::vector<RolePermissionType>{});
  const auto revoked = authorize_one(accessControl, identity, node, AccessOperation::Read);
  EXPECT_FALSE(revoked.permitted);
  EXPECT_EQ(revoked.cause.as_status(), Status::BadUserAccessDenied);
}

// @relation(AC-SVR-AUTHZ-006-ATTRIBUTE-WRITE-BITS-SEPARATE, scope=function)
TEST_F(AccessControlHelperTest, AttributeProjectionIntersectsNodeCapabilitiesWithExactPermissionBits)
{
  const auto identity = make_identity();
  auto node = make_node(1015);
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
    AccessLevelType::Bit::CurrentWrite,
    AccessLevelType::Bit::HistoryRead,
    AccessLevelType::Bit::HistoryWrite});
  node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName,
    AttributeWriteMask::Bit::Historizing,
    AttributeWriteMask::Bit::RolePermissions});

  PermissionType permissions{PermissionType::Bit::Browse,
    PermissionType::Bit::Read,
    PermissionType::Bit::ReadHistory,
    PermissionType::Bit::WriteAttribute,
    PermissionType::Bit::WriteRolePermissions};
  mNamespace->grant(identity->key(), node.get_node_id(), permissions);
  AccessControl accessControl{mAddressSpace, 100ms};

  const auto browseVerdict = authorize_one(accessControl, identity, node, AccessOperation::Browse);
  const auto endpoint = channel();
  const DataValue userAccessLevel = accessControl.make_client_attribute_value(*identity,
    node,
    AttributeId::UserAccessLevel,
    DataValue{Variant{variable->get_access_level().as_underlying_type()}},
    browseVerdict,
    endpoint);
  ASSERT_FALSE(userAccessLevel.status() && userAccessLevel.status()->is_bad());
  const AccessLevelType projectedAccess{userAccessLevel.value().as<uint8_t>()};
  EXPECT_TRUE(projectedAccess.test(AccessLevelType::Bit::CurrentRead));
  EXPECT_TRUE(projectedAccess.test(AccessLevelType::Bit::HistoryRead));
  EXPECT_FALSE(projectedAccess.test(AccessLevelType::Bit::CurrentWrite));
  EXPECT_FALSE(projectedAccess.test(AccessLevelType::Bit::HistoryWrite));

  const DataValue userWriteMask = accessControl.make_client_attribute_value(*identity,
    node,
    AttributeId::UserWriteMask,
    DataValue{Variant{node.get_write_mask()->as_underlying_type()}},
    browseVerdict,
    endpoint);
  ASSERT_FALSE(userWriteMask.status() && userWriteMask.status()->is_bad());
  const AttributeWriteMask projectedWrite{userWriteMask.value().as<uint32_t>()};
  EXPECT_TRUE(projectedWrite.test(AttributeWriteMask::Bit::DisplayName));
  EXPECT_TRUE(projectedWrite.test(AttributeWriteMask::Bit::RolePermissions));
  EXPECT_FALSE(projectedWrite.test(AttributeWriteMask::Bit::Historizing));
}

// @relation(AC-SVR-ADDRSP-059-UNCONFIGURED-OVERRIDE-IS-EMPTY, scope=function)
// @verifies AC-SVR-ADDRSP-059-UNCONFIGURED-OVERRIDE-IS-EMPTY
TEST_F(AccessControlHelperTest, UnconfiguredRolePermissionsProjectsAsAnEmptyArray)
{
  const auto identity = make_identity();
  auto node = make_node(1016);
  mNamespace->grant(
    identity->key(), node.get_node_id(), PermissionType{PermissionType::Bit::ReadRolePermissions});
  ASSERT_FALSE(node.get_role_permissions().has_value());

  AccessControl accessControl{mAddressSpace, 100ms};
  const auto verdict = authorize_one(accessControl, identity, node, AccessOperation::ReadRolePermissions);
  const auto endpoint = channel();
  const auto projected = accessControl.make_client_attribute_value(
    *identity, node, AttributeId::RolePermissions, DataValue{}, verdict, endpoint);

  ASSERT_FALSE(projected.status() && projected.status()->is_bad());
  ASSERT_TRUE(projected.value().is_array_of_structure());
  EXPECT_TRUE(projected.value().as<Array<RefStructure<Structure>>>().empty());
}

// @relation(AC-SVR-AUTHZ-011-COMPLETED-VERDICT-PROJECTED-ONCE, scope=function)
// @relation(AC-COMP-SVR-ACCESS-PROJECTION-03-NO-SIDE-EFFECTS, scope=function)
TEST_F(AccessControlProjectionTest, ConsumesCompletedVerdictWithoutAnotherPermissionQuestion)
{
  const auto identity = make_identity();
  auto node = make_node(1101);
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

  const PermissionType permissions{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  mNamespace->set_async_permissions(identity->key(), node.get_node_id(), permissions);
  mNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  AccessControl accessControl{mAddressSpace, 500ms};

  std::promise<AccessControl::Verdict> completed;
  auto future = completed.get_future();
  const std::array items{AccessControl::Item{node, AccessOperation::Browse}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    channel(),
    [&](std::vector<AccessControl::Verdict> verdicts) { completed.set_value(std::move(verdicts.at(0))); });

  ASSERT_TRUE(mNamespace->wait_for_pending_resolutions());
  EXPECT_EQ(future.wait_for(0ms), std::future_status::timeout);
  mNamespace->complete_pending_resolutions();
  ASSERT_EQ(future.wait_for(2s), std::future_status::ready);
  const auto verdict = future.get();
  ASSERT_TRUE(verdict.permitted);
  EXPECT_EQ(verdict.mask, permissions);
  const size_t immediateCalls = mNamespace->permission_questions();
  const size_t asynchronousCalls = mNamespace->effective_permissions_calls().size();

  const auto projected = accessControl.make_client_attribute_value(*identity,
    node,
    AttributeId::UserAccessLevel,
    DataValue{Variant{variable->get_access_level().as_underlying_type()}, StatusCode{Status::Good}},
    verdict,
    channel());

  ASSERT_FALSE(projected.status() && projected.status()->is_bad());
  const AccessLevelType clientValue{projected.value().as<uint8_t>()};
  EXPECT_TRUE(clientValue.test(AccessLevelType::Bit::CurrentRead));
  EXPECT_FALSE(clientValue.test(AccessLevelType::Bit::CurrentWrite));
  EXPECT_EQ(mNamespace->permission_questions(), immediateCalls);
  EXPECT_EQ(mNamespace->effective_permissions_calls().size(), asynchronousCalls);
  mNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-011-PROJECTED-ATTRIBUTE-MATRIX, scope=function)
// @relation(AC-COMP-SVR-ACCESS-PROJECTION-01-COMPLETE-MATRIX, scope=function)
// @relation(AC-COMP-SVR-ACCESS-PROJECTION-02-RICH-FAIL-CLOSED, scope=function)
TEST_F(AccessControlProjectionTest, ProjectedAttributesUseExactVerdictAndPreserveRichFailures)
{
  const NodeId observerRole{1, "observer"};
  const NodeId operatorRole{1, "operator"};
  const auto observer = make_identity(11, {observerRole});
  const auto noRoles = make_identity(12);
  auto node = make_node(1102);
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());

  const auto observerEntry =
    role_permission(observerRole, PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read});
  const auto operatorEntry = role_permission(operatorRole,
    PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write});
  node.set_role_permissions(std::vector<RolePermissionType>{observerEntry, operatorEntry});
  mNamespace->set_default_role_permissions(std::vector<RolePermissionType>{observerEntry, operatorEntry});

  const NodeAccessor unconfiguredNode = make_node(1103);
  const NodeAccessor defaultUserProperty = make_node(1104);
  AccessControl accessControl{mAddressSpace, 100ms};

  const AccessLevelType storedAccess{AccessLevelType::Bit::CurrentRead,
    AccessLevelType::Bit::CurrentWrite,
    AccessLevelType::Bit::HistoryRead,
    AccessLevelType::Bit::HistoryWrite};
  const auto fullAccess = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserAccessLevel,
    DataValue{Variant{storedAccess.as_underlying_type()}, StatusCode{Status::Good}},
    permitted_verdict(node,
      AttributeId::UserAccessLevel,
      PermissionType{PermissionType::Bit::Browse,
        PermissionType::Bit::Read,
        PermissionType::Bit::Write,
        PermissionType::Bit::ReadHistory,
        PermissionType::Bit::InsertHistory}),
    channel());
  EXPECT_EQ(fullAccess.value().as<uint8_t>(), storedAccess.as_underlying_type());
  const auto restrictedAccess = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserAccessLevel,
    DataValue{Variant{storedAccess.as_underlying_type()}, StatusCode{Status::Good}},
    permitted_verdict(node,
      AttributeId::UserAccessLevel,
      PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read}),
    channel());
  EXPECT_EQ(restrictedAccess.value().as<uint8_t>(),
    AccessLevelType{AccessLevelType::Bit::CurrentRead}.as_underlying_type());

  const AttributeWriteMask storedWrite{AttributeWriteMask::Bit::DisplayName,
    AttributeWriteMask::Bit::Historizing,
    AttributeWriteMask::Bit::RolePermissions};
  const auto fullWrite = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserWriteMask,
    DataValue{Variant{storedWrite.as_underlying_type()}, StatusCode{Status::Good}},
    permitted_verdict(node,
      AttributeId::UserWriteMask,
      PermissionType{PermissionType::Bit::Browse,
        PermissionType::Bit::WriteAttribute,
        PermissionType::Bit::WriteHistorizing,
        PermissionType::Bit::WriteRolePermissions}),
    channel());
  EXPECT_EQ(fullWrite.value().as<uint32_t>(), storedWrite.as_underlying_type());
  const auto restrictedWrite = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserWriteMask,
    DataValue{Variant{storedWrite.as_underlying_type()}, StatusCode{Status::Good}},
    permitted_verdict(node,
      AttributeId::UserWriteMask,
      PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::WriteRolePermissions}),
    channel());
  EXPECT_EQ(restrictedWrite.value().as<uint32_t>(),
    AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions}.as_underlying_type());

  const auto executable = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserExecutable,
    DataValue{Variant{true}, StatusCode{Status::Good}},
    permitted_verdict(node,
      AttributeId::UserExecutable,
      PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Call}),
    channel());
  EXPECT_TRUE(executable.value().as<bool>());
  const auto notExecutable = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserExecutable,
    DataValue{Variant{true}, StatusCode{Status::Good}},
    permitted_verdict(node, AttributeId::UserExecutable, PermissionType{PermissionType::Bit::Browse}),
    channel());
  EXPECT_FALSE(notExecutable.value().as<bool>());

  const auto rolePermissions = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::RolePermissions,
    DataValue{},
    permitted_verdict(
      node, AttributeId::RolePermissions, PermissionType{PermissionType::Bit::ReadRolePermissions}),
    channel());
  EXPECT_EQ(decode_role_permissions(rolePermissions),
    (std::vector<RolePermissionType>{observerEntry, operatorEntry}));
  const auto emptyOverride = accessControl.make_client_attribute_value(*observer,
    unconfiguredNode,
    AttributeId::RolePermissions,
    DataValue{},
    permitted_verdict(unconfiguredNode,
      AttributeId::RolePermissions,
      PermissionType{PermissionType::Bit::ReadRolePermissions}),
    channel());
  EXPECT_TRUE(decode_role_permissions(emptyOverride).empty());

  const auto userRoles = accessControl.make_client_attribute_value(*observer,
    node,
    AttributeId::UserRolePermissions,
    DataValue{},
    permitted_verdict(node, AttributeId::UserRolePermissions, PermissionType{PermissionType::Bit::Browse}),
    channel());
  EXPECT_EQ(decode_role_permissions(userRoles), std::vector<RolePermissionType>{observerEntry});
  const auto noUserRoles = accessControl.make_client_attribute_value(*noRoles,
    node,
    AttributeId::UserRolePermissions,
    DataValue{},
    permitted_verdict(node, AttributeId::UserRolePermissions, PermissionType{PermissionType::Bit::Browse}),
    channel());
  EXPECT_TRUE(decode_role_permissions(noUserRoles).empty());

  // A Value now passes through this projection untouched, whoever is reading. Anything that depends
  // on the caller was produced by the node that served it, from the identity given to the read - so
  // there is nothing here to substitute and nothing that needs to know which nodes are special.
  const auto passedThrough = accessControl.make_client_attribute_value(*observer,
    defaultUserProperty,
    AttributeId::Value,
    DataValue{Variant{String{"served-by-the-node"}}, StatusCode{Status::Good}},
    permitted_verdict(defaultUserProperty, AttributeId::Value, PermissionType{PermissionType::Bit::Read}),
    channel());
  ASSERT_TRUE(passedThrough.value().is_string());
  EXPECT_EQ(passedThrough.value().as<String>(), String{"served-by-the-node"});

  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build("ProjectionSentinel", "projection sentinel", "AccessControlProjectionTest")};
  const auto sentinelDetail = sentinel.shared_detail();
  const std::array attributes{AttributeId::UserAccessLevel,
    AttributeId::UserWriteMask,
    AttributeId::UserExecutable,
    AttributeId::RolePermissions,
    AttributeId::UserRolePermissions,
    AttributeId::Value};
  for (const auto attribute : attributes)
  {
    const auto& subject = attribute == AttributeId::Value ? defaultUserProperty : node;
    const AccessControl::Verdict failure{.subject = subject.get_node_id(),
      .operation = read_operation(attribute),
      .permitted = false,
      .cause = sentinel};
    const auto result = accessControl.make_client_attribute_value(
      *observer, subject, attribute, DataValue{Variant{uint32_t{123}}}, failure, channel());
    ASSERT_TRUE(result.status().has_value());
    EXPECT_EQ(result.status()->as_uint32(), sentinel.as_uint32());
    EXPECT_EQ(result.status()->shared_detail(), sentinelDetail);
    EXPECT_TRUE(result.value().empty());
  }
}

// @relation(AC-SVR-AUTHZ-011-USER-WRITE-MASK-GROUPS, scope=function)
// @relation(AC-COMP-SVR-ACCESS-PROJECTION-01-COMPLETE-MATRIX, scope=function)
TEST_F(AccessControlProjectionTest, UserWriteMaskSeparatesAllPermissionGroupsAndIntersectsStoredMask)
{
  const auto identity = make_identity();
  const auto node = make_node(1105);
  AccessControl accessControl{mAddressSpace, 100ms};

  constexpr std::array<PermissionType::Bit, 3> permissionBits{PermissionType::Bit::WriteAttribute,
    PermissionType::Bit::WriteHistorizing,
    PermissionType::Bit::WriteRolePermissions};
  constexpr std::array<AttributeWriteMask::Bit, 3> storedBits{AttributeWriteMask::Bit::DisplayName,
    AttributeWriteMask::Bit::Historizing,
    AttributeWriteMask::Bit::RolePermissions};

  for (uint32_t permissionCombination = 0; permissionCombination < 8; ++permissionCombination)
  {
    PermissionType permissions{PermissionType::Bit::Browse};
    for (size_t bit = 0; bit < permissionBits.size(); ++bit)
    {
      if ((permissionCombination & (uint32_t{1} << bit)) != 0)
      {
        permissions.set(permissionBits[bit]);
      }
    }
    for (uint32_t storedCombination = 0; storedCombination < 8; ++storedCombination)
    {
      AttributeWriteMask stored;
      AttributeWriteMask expected;
      for (size_t bit = 0; bit < storedBits.size(); ++bit)
      {
        if ((storedCombination & (uint32_t{1} << bit)) != 0)
        {
          stored.set(storedBits[bit]);
          if ((permissionCombination & (uint32_t{1} << bit)) != 0)
          {
            expected.set(storedBits[bit]);
          }
        }
      }

      const auto projected = accessControl.make_client_attribute_value(*identity,
        node,
        AttributeId::UserWriteMask,
        DataValue{Variant{stored.as_underlying_type()}, StatusCode{Status::Good}},
        permitted_verdict(node, AttributeId::UserWriteMask, permissions),
        channel());
      ASSERT_FALSE(projected.status() && projected.status()->is_bad());
      EXPECT_EQ(projected.value().as<uint32_t>(), expected.as_underlying_type())
        << "permission combination " << permissionCombination << ", stored combination " << storedCombination;
    }
  }
}

// @relation(AC-SVR-AUTHZ-011-BROWSE-READABLE-CAPABILITY-CHANNEL-CLAMP, scope=function)
TEST_F(AccessControlProjectionTest, BrowseReadableCapabilityIsClampedByItsOperationChannel)
{
  const auto identity = make_identity();
  const auto node = make_node(1106);
  mNamespace->set_default_access_restrictions(
    AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
  AccessControl accessControl{mAddressSpace, 100ms};
  const AccessLevelType stored{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
  const auto verdict = permitted_verdict(node,
    AttributeId::UserAccessLevel,
    PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write});

  const auto none = accessControl.make_client_attribute_value(*identity,
    node,
    AttributeId::UserAccessLevel,
    DataValue{Variant{stored.as_underlying_type()}, StatusCode{Status::Good}},
    verdict,
    channel(MessageSecurityMode::None));
  const auto encrypted = accessControl.make_client_attribute_value(*identity,
    node,
    AttributeId::UserAccessLevel,
    DataValue{Variant{stored.as_underlying_type()}, StatusCode{Status::Good}},
    verdict,
    channel(MessageSecurityMode::SignAndEncrypt));

  ASSERT_FALSE(none.status() && none.status()->is_bad());
  ASSERT_FALSE(encrypted.status() && encrypted.status()->is_bad());
  EXPECT_EQ(none.value().as<uint8_t>(), uint8_t{0});
  EXPECT_EQ(encrypted.value().as<uint8_t>(), stored.as_underlying_type());
}

// @relation(AC-COMP-SVR-ACCESS-PROJECTION-02-RICH-FAIL-CLOSED, scope=function)
TEST_F(AccessControlProjectionTest, RejectsMismatchedVerdictAssociationRichly)
{
  const auto identity = make_identity();
  const auto expectedNode = make_node(1107);
  const auto otherNode = make_node(1108);
  AccessControl accessControl{mAddressSpace, 100ms};
  const AccessControl::Verdict wrongSubject{.subject = otherNode.get_node_id(),
    .operation = AccessOperation::Browse,
    .permitted = true,
    .mask = PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read},
    .cause = StatusCode{Status::Good}};

  const auto result = accessControl.make_client_attribute_value(*identity,
    expectedNode,
    AttributeId::UserAccessLevel,
    DataValue{Variant{uint8_t{1}}, StatusCode{Status::Good}},
    wrongSubject,
    channel());

  ASSERT_TRUE(result.status() && result.status()->is_bad());
  EXPECT_EQ(result.status()->as_status(), Status::BadInternalError);
  ASSERT_NE(result.status()->shared_detail(), nullptr);
  EXPECT_EQ(result.status()->shared_detail()->code, "AttributeProjectionVerdictMismatch");
  EXPECT_TRUE(result.value().empty());
}

}  // namespace
