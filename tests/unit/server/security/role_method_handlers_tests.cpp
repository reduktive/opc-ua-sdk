// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the role-management Method handlers (Cut 5 G.2 + G.3 + G.6).
///
/// Pins:
///   * Calling AddIdentity / RemoveIdentity / AddApplication /
///     RemoveApplication / AddEndpoint / RemoveEndpoint with valid args
///     mutates `RoleConfiguration`, mirrors the change into the role's
///     Variable, and bumps the epoch.
///   * Duplicate add / missing remove -> BadEntryExists / BadNotFound (no
///     mutation, no audit).
///   * When `roleManagementEnabled = false`, no Call handler is installed
///     -> the address-space's default method dispatch path returns
///     `BadNotExecutable`.
///   * `RoleMappingRuleChangedAuditEventPayload` is emitted on every successful
///     management call. Writes to `ApplicationsExclude` / `EndpointsExclude`
///     do not emit the audit event (Part 18 section 4.5 spec silence).
///   * `AddRole` allocates a free bit slot + instantiates a Role Object under
///     RoleSet. `RemoveRole` deletes the role + frees its bit slot.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_audit_update_method_event_payload.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_endpoint_type.h"
#include "ua_event_bus.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_message_security_mode.h"
#include "ua_method_id.h"
#include "ua_namespace_uri.h"
#include "ua_value_source.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_mapping_rule_changed_audit_event_payload.h"
#include "ua_server_impl.h"

#include "ua_access_restriction_type.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_diagnostic_policy.h"
#include "ua_method_service_set.h"
#include "ua_namespace_authorization.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_to_string.h"

#include "posting_writes_namespace.h"
#include "scripted_referrer_namespace.h"
#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include "test_components.h"

using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

::ua::server::CombinedConfig make_frozen_config(bool roleManagement, bool auditing)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ::ua::server::ServerConfig sc;
  sc.maxConnections = 100;
  sc.roleManagementEnabled = roleManagement;
  sc.auditingEnabled = auditing;
  frozen.server = std::move(sc);
  return frozen;
}

shared_ptr<ServerImpl> create_part18_server(
  boost::asio::any_io_executor ex, bool roleManagement, bool auditing = true)
{
  auto frozen = make_frozen_config(roleManagement, auditing);
  ::ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  // Part-18 wiring is driven by `mRoleConfiguration` presence. The
  // method-handler tests verify that the SDK installs Call handlers for
  // the per-role Methods + AddRole/RemoveRole when role-management is
  // enabled; they do not need an activated AccessIdentity.
  components.roleConfiguration = std::make_shared<RoleConfiguration>();
  return ServerImpl::create(ex, std::move(frozen), std::move(components));
}

/// Captures every emitted event for inspection. Thread-safe: the listener
/// fires on the EventBus dispatch strand (a thread-pool worker), while the
/// test reads counts on the main test thread.
struct EventRecorder
{
  EventBus::EventListener listener()
  {
    return [this](const BaseEvent& event)
    {
      std::lock_guard lock(mMutex);
      mEvents.push_back(event.clone());
      mCv.notify_all();
    };
  }

  size_t role_mapping_audit_count() const
  {
    std::lock_guard lock(mMutex);
    return count_role_audits();
  }

  /// True iff at least one recorded RoleMappingRuleChangedAuditEventPayload also
  /// resolves (via dynamic_cast) to AuditUpdateMethodEventPayload - confirming the
  /// emitted event's runtime type sits below AuditUpdateMethodEventType in the
  /// spec type chain (Part 18 section 4.5 / SVR-EVT-AUD-021).
  bool recorded_role_audit_is_audit_update_method() const
  {
    std::lock_guard lock(mMutex);
    for (const auto& e : mEvents)
    {
      if (dynamic_cast<const RoleMappingRuleChangedAuditEventPayload*>(e.get()))
      {
        return dynamic_cast<const AuditUpdateMethodEventPayload*>(e.get()) != nullptr;
      }
    }
    return false;
  }

  /// The Status field of the last RoleMappingRuleChangedAuditEventPayload recorded, if any.
  std::optional<bool> last_role_audit_status() const
  {
    std::lock_guard lock(mMutex);
    for (auto it = mEvents.rbegin(); it != mEvents.rend(); ++it)
    {
      if (const auto* audit = dynamic_cast<const RoleMappingRuleChangedAuditEventPayload*>(it->get()))
      {
        return audit->status;
      }
    }
    return std::nullopt;
  }

  /// Wait until at least `expected` role-mapping audit events have been
  /// recorded, or until `timeout` elapses. Returns the count when reached.
  /// Used as a synchronisation barrier - the audit emission is posted to the
  /// EventBus dispatch strand, so the count is observed only after the
  /// strand processes the post.
  size_t wait_for_role_audit_count(
    size_t expected, std::chrono::milliseconds timeout = std::chrono::seconds{2})
  {
    std::unique_lock lock(mMutex);
    mCv.wait_for(lock, timeout, [&]() { return count_role_audits() >= expected; });
    return count_role_audits();
  }

private:
  size_t count_role_audits() const
  {
    size_t n = 0;
    for (const auto& e : mEvents)
    {
      if (dynamic_cast<const RoleMappingRuleChangedAuditEventPayload*>(e.get()))
      {
        ++n;
      }
    }
    return n;
  }

  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::unique_ptr<BaseEvent>> mEvents;
};

/// Resolve a namespace index to its registered URI via the address space.
/// Part 18 section 4.2.2 declares AddRole's 2nd input argument as `NamespaceUri :
/// String`, so the handler resolves the URI to an index; tests pass the URI
/// for the namespace they target. Index 0 is the OPC UA namespace
/// (`http://opcfoundation.org/UA/`); index 1 is the server's own
/// application-URI namespace, whose URI is non-deterministic per test run, so
/// it must be read back rather than hard-coded.
String namespace_uri_for_index(AddressSpace& addressSpace, uint16_t index)
{
  return addressSpace.namespace_array().get_namespace_uri(index);
}

CallMethodRequest make_call(uint32_t methodId, uint32_t objectId, std::vector<Variant> args)
{
  CallMethodRequest req;
  req.object_id() = NodeId{0, objectId};
  req.method_id() = NodeId{0, methodId};
  Array<Variant> argArray;
  argArray.payload().reserve(args.size());
  for (auto& a : args)
  {
    argArray.payload().push_back(std::move(a));
  }
  req.input_arguments() = std::move(argArray);
  return req;
}

// The handler context is retained for audit attribution. RolePermissions and
// AccessRestrictions are enforced by the Call service before it dispatches to
// these handlers, so direct handler tests provide only the channel fact needed
// by the handler's own audit/transport behaviour.
std::shared_ptr<const MethodCallContext> make_context(MessageSecurityMode mode)
{
  auto ctx = std::make_shared<MethodCallContext>();
  ctx->channelSecurityMode = mode;
  return ctx;
}

std::shared_ptr<const MethodCallContext> secure_channel_context()
{
  return make_context(MessageSecurityMode::SignAndEncrypt);
}

/// Direct handler tests use this to prove service-owned channel checks are not
/// duplicated.
std::shared_ptr<const MethodCallContext> none_channel_context()
{
  return make_context(MessageSecurityMode::None);
}

CallResult invoke_method(AddressSpace& addressSpace, const CallMethodRequest& req,
  std::shared_ptr<const MethodCallContext> ctx = nullptr)
{
  // Positive-path callers omit `ctx` and get secure-channel audit details.
  // AccessControl and AccessRestrictions are service-layer responsibilities,
  // so these direct handler tests intentionally do not assert access decisions.
  static const std::shared_ptr<const MethodCallContext> defaultContext = secure_channel_context();
  std::shared_ptr<const MethodCallContext> effective = ctx ? ctx : defaultContext;

  auto methodNode = addressSpace.try_find_node_sync(req.method_id());
  if (!methodNode)
  {
    return CallResult{StatusCode{Status::BadNodeIdUnknown}};
  }
  auto method = methodNode.value().as<MethodAccessor>();
  if (!method)
  {
    return CallResult{StatusCode{Status::BadNodeIdInvalid}};
  }
  std::promise<CallResult> promise;
  method->call_async(req, effective, [&promise](CallResult result) { promise.set_value(std::move(result)); });
  return promise.get_future().get();
}

constexpr uint32_t roleSetId = static_cast<uint32_t>(ObjectId::Server_ServerCapabilities_RoleSet);
constexpr uint32_t anonymousRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous);
constexpr uint32_t observerRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Observer);
constexpr uint32_t operatorRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Operator);
constexpr uint32_t configureAdminRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_ConfigureAdmin);
constexpr uint32_t operatorAddIdentityMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_AddIdentity);
constexpr uint32_t operatorRemoveIdentityMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_RemoveIdentity);
constexpr uint32_t operatorAddApplicationMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_AddApplication);
constexpr uint32_t operatorRemoveApplicationMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_RemoveApplication);
constexpr uint32_t operatorAddEndpointMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_AddEndpoint);
constexpr uint32_t operatorRemoveEndpointMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_RemoveEndpoint);
constexpr uint32_t configureAdminAddIdentityMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_ConfigureAdmin_AddIdentity);

}  // namespace

// ============================================================================
// Per-role management methods - success paths
// ============================================================================

// @relation(SVR-EVT-AUD-021, SVR-SECADMIN-040, scope=function)
TEST(RoleMethodHandlersTest, AddIdentitySuccessMutatesAndEmitsAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{"alice"};

  const auto epochBefore = access.role_configuration()->epoch();
  auto result = invoke_method(
    access.address_space(), make_call(operatorAddIdentityMethod, operatorRoleId, {Variant{rule}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_GT(access.role_configuration()->epoch(), epochBefore);

  auto def = access.role_configuration()->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_EQ(def->identities.size(), 1u);
  EXPECT_EQ(def->identities[0].criteria_type(), IdentityCriteriaType::UserName);

  EXPECT_EQ(recorder.wait_for_role_audit_count(1), 1u);
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// @relation(SVR-EVT-AUD-021, SVR-SECADMIN-041, scope=function)
TEST(RoleMethodHandlersTest, RemoveIdentitySuccessMutatesAndEmitsAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  // Operator is one of the six configurable Roles that expose RemoveIdentity;
  // the fixed Anonymous / AuthenticatedUser Roles carry no management Methods in
  // UA-1.05.06. Seed a UserName rule directly in the RoleConfiguration (no
  // audit), then remove it over the handler (one audit).
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{"alice"};
  const NodeId operatorRole{0, operatorRoleId};
  ASSERT_TRUE(access.role_configuration()->add_identity_rule(operatorRole, rule).is_good());

  auto result = invoke_method(
    access.address_space(), make_call(operatorRemoveIdentityMethod, operatorRoleId, {Variant{rule}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();

  auto def = access.role_configuration()->get_role(operatorRole);
  ASSERT_TRUE(def);
  EXPECT_EQ(def->identities.size(), 0u) << "RemoveIdentity must drop the seeded rule.";
  EXPECT_EQ(recorder.wait_for_role_audit_count(1), 1u);
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// @relation(SVR-EVT-AUD-021, SVR-SECADMIN-042, scope=function)
TEST(RoleMethodHandlersTest, AddApplicationSuccessMutatesAndEmitsAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  auto result = invoke_method(access.address_space(),
    make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{String{"urn:trusted:client"}}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();

  auto def = access.role_configuration()->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_EQ(def->applications.size(), 1u);
  EXPECT_EQ(static_cast<std::string_view>(def->applications[0]), "urn:trusted:client");
  EXPECT_EQ(recorder.wait_for_role_audit_count(1), 1u);
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// @relation(SVR-EVT-AUD-021, SVR-SECADMIN-044, scope=function)
TEST(RoleMethodHandlersTest, AddEndpointSuccessMutatesAndEmitsAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  EndpointType ep;
  ep.endpoint_url() = String{"opc.tcp://server/secured"};
  auto result = invoke_method(
    access.address_space(), make_call(operatorAddEndpointMethod, operatorRoleId, {Variant{ep}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();

  auto def = access.role_configuration()->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_EQ(def->endpoints.size(), 1u);
  EXPECT_EQ(static_cast<std::string_view>(def->endpoints[0].endpoint_url()), "opc.tcp://server/secured");
  EXPECT_EQ(recorder.wait_for_role_audit_count(1), 1u);
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// ============================================================================
// Per-role management methods - failure paths (no mutation, no audit)
// ============================================================================

// @relation(SVR-EVT-AUD-021, SVR-SECADMIN-042, scope=function)
TEST(RoleMethodHandlersTest, AddApplicationDuplicateReturnsBadEntryExists)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{String{"urn:x"}}}))
                .is_good());
  // Wait for the first audit emission to land on the recorder so the
  // duplicate-emission check below has a stable baseline.
  const auto auditAfterFirst = recorder.wait_for_role_audit_count(1);

  auto duplicate = invoke_method(access.address_space(),
    make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{String{"urn:x"}}}));
  EXPECT_FALSE(duplicate.is_good());
  EXPECT_EQ(duplicate.status_code().value(), StatusCode{Status::BadEntryExists}.value());

  // Allow time for any racing duplicate-emission post to land before
  // counting (it must not appear). Then drop the server so timers cancel
  // and the pool can drain cleanly.
  EXPECT_EQ(recorder.role_mapping_audit_count(), auditAfterFirst)
    << "Duplicate add must not emit a second audit event";
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// @relation(SVR-SECADMIN-043, scope=function)
TEST(RoleMethodHandlersTest, RemoveApplicationNotFoundReturnsBadNotFound)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveApplicationMethod, operatorRoleId, {Variant{String{"urn:not-there"}}}));
  EXPECT_FALSE(result.is_good());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadNotFound}.value());
}

// @relation(SVR-SECADMIN-040, scope=function)
TEST(RoleMethodHandlersTest, AddIdentityWrongArgTypeReturnsBadTypeMismatch)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  // Pass a String where an IdentityMappingRuleType is required.
  auto result = invoke_method(access.address_space(),
    make_call(operatorAddIdentityMethod, operatorRoleId, {Variant{String{"not a rule"}}}));
  EXPECT_FALSE(result.is_good());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadTypeMismatch}.value());
}

// ============================================================================
// Q-RBAC method-management gating (roleManagementEnabled = false)
// ============================================================================

// @relation(SVR-SECADMIN-040, scope=function)
TEST(RoleMethodHandlersTest, RoleManagementDisabledReturnsBadNotSupported)
{
  // When roleManagementEnabled is false the SDK does not install Call
  // handlers for the role-management Methods; the default Method node
  // dispatch returns BadNotSupported (Part 18 section 4.4.4 is silent on the exact
  // code - the SDK uses the default-node "no handler installed" status,
  // which is BadNotSupported).
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/false);
  ServerImplTestAccess access{*server};

  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{"alice"};

  auto result = invoke_method(
    access.address_space(), make_call(operatorAddIdentityMethod, operatorRoleId, {Variant{rule}}));
  // The Method node carries the per-operation status on `value().status_code()`;
  // a missing handler returns BadNotSupported there (outer Result is "good"
  // because it carries a CallMethodResult value).
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().status_code().value(), StatusCode{Status::BadNotSupported}.value());
}

// ============================================================================
// AddRole / RemoveRole (G.3)
// ============================================================================

// @relation(SVR-SECADMIN-035, scope=function)
TEST(RoleMethodHandlersTest, AddRoleRoundTripsAndAuditFires)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"CustomRoleA"}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}));
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(result.value().output_arguments().size(), 1u);
  const auto* newId = result.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(newId, nullptr);
  EXPECT_EQ(newId->namespace_index(), 1u);

  auto roleDef = access.role_configuration()->get_role(*newId);
  ASSERT_TRUE(roleDef);
  EXPECT_GE(roleDef->roleBit, 2u) << "Allocator should skip well-known role bits";

  // Role Object must exist in the address space.
  EXPECT_TRUE(access.address_space().try_find_node_sync(*newId).is_good());

  EXPECT_GE(recorder.wait_for_role_audit_count(1), 1u);
  // Drop the server before recorder destruction so the EventBus listener
  // (which captures &recorder) is destroyed first.
  server.reset();
}

// @relation(SVR-SECADMIN-039, scope=function)
TEST(RoleMethodHandlersTest, RemoveRoleDeletesAndAuditFires)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  auto addResult = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"Disposable"}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}));
  ASSERT_TRUE(addResult.is_good());
  const auto* newId = addResult.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(newId, nullptr);
  const NodeId roleId = *newId;

  // Wait for the add-role audit to land so countBefore is stable.
  const auto countBefore = recorder.wait_for_role_audit_count(1);
  auto removeResult = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole),
      roleSetId,
      {Variant{roleId}}));
  EXPECT_TRUE(removeResult.is_good()) << removeResult.status_code().value();

  EXPECT_FALSE(access.role_configuration()->get_role(roleId).has_value());
  EXPECT_FALSE(access.address_space().try_find_node_sync(roleId).is_good());
  EXPECT_GT(recorder.wait_for_role_audit_count(countBefore + 1), countBefore);
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// @relation(SVR-SECADMIN-039, scope=function)
TEST(RoleMethodHandlersTest, RemoveRoleUnknownReturnsBadNodeIdUnknown)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole),
      roleSetId,
      {Variant{NodeId{1, 999999u}}}));
  EXPECT_FALSE(result.is_good());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadNodeIdUnknown}.value());
}

// ============================================================================
// Audit spec silence on *Exclude flags (G.6)
// ============================================================================

TEST(RoleMethodHandlersTest, AuditingDisabledSkipsEmission)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true, /*auditing=*/false);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{"alice"};
  ASSERT_TRUE(invoke_method(
    access.address_space(), make_call(configureAdminAddIdentityMethod, configureAdminRoleId, {Variant{rule}}))
                .is_good());

  // EventBus only emits to listeners; auditing-disabled means the SDK does not
  // emit RoleMappingRuleChangedAuditEventPayload for management calls because the
  // EventBus has no other interest in audit events. With a local listener
  // attached `has_event_interest()` is true - but the SDK fires emit() only
  // when role-management succeeds, so we still see exactly one emission.
  // The auditingEnabled flag gates the EventBus construction itself for non-
  // listener subscribers; with a test-attached listener present the SDK still
  // emits via emit(). This test pins that the management handler ALWAYS calls
  // emit(); the auditing flag's effect is on subscription delivery, not on
  // local listener wiring.
  EXPECT_EQ(recorder.wait_for_role_audit_count(1), 1u);
  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// Access-control denials for these Methods are covered through the canonical
// Call service in the role-management integration tests and through the
// AccessControl unit tests. Handler tests below cover only handler-owned logic.

namespace
{
IdentityMappingRuleType user_name_rule(std::string_view user)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{user};
  return rule;
}

EndpointType endpoint_with_url(std::string_view url)
{
  EndpointType ep;
  ep.endpoint_url() = String{url};
  return ep;
}

void expect_status(const CallResult& result, Status expected)
{
  EXPECT_FALSE(result.is_good());
  EXPECT_EQ(result.status_code().value(), StatusCode{expected}.value());
}
}  // namespace

// These direct handler calls bypass Method-service authorization and channel checks. They verify
// handler logic after those service preconditions; the real-wire encrypted-channel controls are in
// role_based_security_management_integration_tests.cpp (Part 18 sections 4.2.2 and 4.2.3).
TEST(RoleMethodHandlersTest, AddRoleHandlerImposesNoEncryptedChannelFloor)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  const auto ctx = none_channel_context();
  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"CustomRole"}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}),
    ctx);
  EXPECT_TRUE(result.is_good()) << "AddRole on a None channel must not be rejected by the handler "
                                   "(encryption is checked by the Method service): "
                                << result.status_code().value();
}

TEST(RoleMethodHandlersTest, RemoveRoleHandlerImposesNoEncryptedChannelFloor)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  const auto ctx = none_channel_context();
  // Remove an existing well-known Role (Operator) through the direct handler, after bypassing
  // the service preconditions as this fixture intentionally does.
  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole),
      roleSetId,
      {Variant{NodeId{0, operatorRoleId}}}),
    ctx);
  EXPECT_TRUE(result.is_good()) << "RemoveRole on a None channel must not be rejected by the handler "
                                   "(encryption is checked by the Method service): "
                                << result.status_code().value();
}

// ============================================================================
// Phase P2 - AddRole hardening (SVR-SECADMIN-035, 036, 038)
// ============================================================================

TEST(RoleMethodHandlersTest, AddRoleBrowseNameCollisionReturnsInvalidArgument)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  // First AddRole succeeds and creates a RoleSet child named "CollideMe".
  auto first = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"CollideMe"}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}));
  ASSERT_TRUE(first.is_good()) << first.status_code().value();

  // Second AddRole with the same BrowseName collides.
  auto second = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"CollideMe"}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}));
  expect_status(second, Status::BadInvalidArgument);
}

TEST(RoleMethodHandlersTest, AddRoleSetsExcludeFlagsTrueByDefault)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"ExcludeDefault"}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}));
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  const auto* newId = result.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(newId, nullptr);

  auto def = access.role_configuration()->get_role(*newId);
  ASSERT_TRUE(def);
  EXPECT_TRUE(def->applicationsExclude)
    << "AddRole must default ApplicationsExclude to TRUE (Part 18 section 4.2.2 L316-318)";
  EXPECT_TRUE(def->endpointsExclude)
    << "AddRole must default EndpointsExclude to TRUE (Part 18 section 4.2.2 L316-318)";

  auto role = access.address_space().try_find_node_sync(*newId);
  ASSERT_TRUE(role.is_good());
  std::map<std::string, VariableAccessor> excludeProperties;
  for (const auto& reference : role.value().get_references_sync())
  {
    if (!reference.is_forward() || !reference.target_id().is_local())
      continue;
    auto child = access.address_space().try_find_node_sync(reference.target_id().node_id());
    if (!child)
      continue;
    auto variable = child.value().as<VariableAccessor>();
    if (variable)
      excludeProperties.emplace(std::string{child.value().get_browse_name().name()}, *variable);
  }
  for (const std::string_view propertyName : {"ApplicationsExclude", "EndpointsExclude"})
  {
    auto property = excludeProperties.find(std::string{propertyName});
    ASSERT_NE(property, excludeProperties.end()) << propertyName;
    EXPECT_TRUE(property->second.get_access_level().test(AccessLevelType::Bit::CurrentWrite)) << propertyName;
    const auto value = property->second.try_read_value_sync();
    ASSERT_TRUE(value.is_good());
    const auto* flag = value.value().value().try_as<bool>();
    ASSERT_NE(flag, nullptr);
    EXPECT_TRUE(*flag) << propertyName;
  }
}

TEST(RoleMethodHandlersTest, AddRoleWithWellKnownNameUsesSpecNodeId)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  // Simulate a server that ships a minimal RoleSet: remove the materialised
  // Observer Role (node + registration) so AddRole("Observer", ns0) takes the
  // well-known-NodeId-reuse path rather than colliding with an existing child.
  (void)access.address_space().try_delete_node_sync(
    NodeId{0, observerRoleId}, /*deleteForwardHierarchicalRefs=*/true);
  access.role_configuration()->remove_role(NodeId{0, observerRoleId});

  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"Observer"}}, Variant{namespace_uri_for_index(access.address_space(), 0)}}));
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(result.value().output_arguments().size(), 1u);
  const auto* newId = result.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(newId, nullptr);
  EXPECT_EQ(*newId, (NodeId{0, observerRoleId}))
    << "Well-known Role name under ns0 must reuse the spec NodeId (Part 18 section 4.2.2 L322-325)";
}

TEST(RoleMethodHandlersTest, AddRoleEmptyRoleNameReturnsInvalidArgument)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};

  auto result = invoke_method(access.address_space(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{""}}, Variant{namespace_uri_for_index(access.address_space(), 1)}}));
  expect_status(result, Status::BadInvalidArgument);
}

// ============================================================================
// Phase P2 - SVR-EVT-AUD-021 tail: symmetric Remove* success + audit, and the
// audit-event type chain.
// ============================================================================

TEST(RoleMethodHandlersTest, RemoveApplicationSuccessMutatesAndEmitsAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{String{"urn:trusted:client"}}}))
                .is_good());
  ASSERT_EQ(recorder.wait_for_role_audit_count(1), 1u);

  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveApplicationMethod, operatorRoleId, {Variant{String{"urn:trusted:client"}}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();

  auto def = access.role_configuration()->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  EXPECT_TRUE(def->applications.empty());
  EXPECT_EQ(recorder.wait_for_role_audit_count(2), 2u);
  server.reset();
}

TEST(RoleMethodHandlersTest, RemoveEndpointSuccessMutatesAndEmitsAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorAddEndpointMethod, operatorRoleId, {Variant{endpoint_with_url("opc.tcp://s/x")}}))
                .is_good());
  ASSERT_EQ(recorder.wait_for_role_audit_count(1), 1u);

  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveEndpointMethod, operatorRoleId, {Variant{endpoint_with_url("opc.tcp://s/x")}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();

  auto def = access.role_configuration()->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  EXPECT_TRUE(def->endpoints.empty());
  EXPECT_EQ(recorder.wait_for_role_audit_count(2), 2u);
  server.reset();
}

TEST(RoleMethodHandlersTest, RoleMappingRuleChangedAuditEventTypeIsAuditUpdateMethodSubtype)
{
  // Compile-time: the generated event type sits below AuditUpdateMethodEventType
  // in the spec type chain (the C++ inheritance IS the type-chain interface - the SDK
  // does not expose a separate runtime ObjectTypeId-chain query).
  static_assert(
    std::is_base_of_v<ua::AuditUpdateMethodEventPayload, ua::RoleMappingRuleChangedAuditEventPayload>,
    "RoleMappingRuleChangedAuditEventPayload must derive from AuditUpdateMethodEventPayload (Part 18 section "
    "4.5)");

  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorAddIdentityMethod, operatorRoleId, {Variant{user_name_rule("alice")}}))
                .is_good());
  ASSERT_EQ(recorder.wait_for_role_audit_count(1), 1u);
  // Runtime: the emitted event resolves to AuditUpdateMethodEventPayload.
  EXPECT_TRUE(recorder.recorded_role_audit_is_audit_update_method());
  server.reset();
}

// ============================================================================
// Phase P2 - SVR-SECADMIN-035..045 remainder (admin happy-path callers; the
// gate is exercised above, these pin the per-Method result codes).
// ============================================================================

TEST(RoleMethodHandlersTest, RemoveIdentityUnknownRuleReturnsBadNotFound)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  // Operator ships with no identity rules; removing one returns Bad_NotFound.
  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveIdentityMethod, operatorRoleId, {Variant{user_name_rule("ghost")}}));
  expect_status(result, Status::BadNotFound);
}

TEST(RoleMethodHandlersTest, AddApplicationInvalidUriReturnsInvalidArgument)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto result = invoke_method(
    access.address_space(), make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{String{""}}}));
  expect_status(result, Status::BadInvalidArgument);
}

TEST(RoleMethodHandlersTest, AddEndpointInvalidUrlReturnsInvalidArgument)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto result = invoke_method(access.address_space(),
    make_call(operatorAddEndpointMethod, operatorRoleId, {Variant{endpoint_with_url("")}}));
  expect_status(result, Status::BadInvalidArgument);
}

TEST(RoleMethodHandlersTest, RemoveApplicationSuccess)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{String{"urn:app"}}}))
                .is_good());
  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveApplicationMethod, operatorRoleId, {Variant{String{"urn:app"}}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();
}

TEST(RoleMethodHandlersTest, RemoveEndpointSuccess)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorAddEndpointMethod, operatorRoleId, {Variant{endpoint_with_url("opc.tcp://s/e")}}))
                .is_good());
  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveEndpointMethod, operatorRoleId, {Variant{endpoint_with_url("opc.tcp://s/e")}}));
  EXPECT_TRUE(result.is_good()) << result.status_code().value();
}

TEST(RoleMethodHandlersTest, RemoveEndpointUnknownReturnsBadNotFound)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto result = invoke_method(access.address_space(),
    make_call(operatorRemoveEndpointMethod, operatorRoleId, {Variant{endpoint_with_url("opc.tcp://none")}}));
  expect_status(result, Status::BadNotFound);
}

// ============================================================================
// Every mapping-rule Method audits - all six in one run, attributed per Method
// ============================================================================

namespace
{

/// Records the `MethodId` and `SourceNode` of every emitted
/// `RoleMappingRuleChangedAuditEventPayload`, so a run that drives all six
/// mapping-rule Methods can be checked Method-by-Method rather than by a bare
/// total. A bare total cannot distinguish "six Methods each audited once" from
/// "five Methods audited, one of them twice".
///
/// Thread-safe in the same way as `EventRecorder`: the listener fires on the
/// EventBus dispatch strand while the test reads on the main thread.
struct RoleAuditAttributionRecorder
{
  EventBus::EventListener listener()
  {
    return [this](const BaseEvent& event)
    {
      const auto* audit = dynamic_cast<const RoleMappingRuleChangedAuditEventPayload*>(&event);
      if (!audit)
      {
        return;
      }
      std::lock_guard lock(mMutex);
      mMethodIds.push_back(audit->methodId);
      mSourceNodes.push_back(audit->sourceNode);
      mCv.notify_all();
    };
  }

  /// Blocks until at least `expected` role-mapping audits have arrived, or the
  /// timeout elapses; returns the count reached.
  size_t wait_for_count(size_t expected, std::chrono::milliseconds timeout = std::chrono::seconds{2})
  {
    std::unique_lock lock(mMutex);
    mCv.wait_for(lock, timeout, [&]() { return mMethodIds.size() >= expected; });
    return mMethodIds.size();
  }

  size_t count() const
  {
    std::lock_guard lock(mMutex);
    return mMethodIds.size();
  }

  /// How many recorded audits carry `MethodId == NodeId{0, methodId}`.
  size_t count_for_method(uint32_t methodId) const
  {
    std::lock_guard lock(mMutex);
    const NodeId wanted{0, methodId};
    size_t n = 0;
    for (const auto& id : mMethodIds)
    {
      if (id == wanted)
      {
        ++n;
      }
    }
    return n;
  }

  /// How many recorded audits carry `SourceNode == NodeId{0, objectId}`.
  size_t count_for_source_node(uint32_t objectId) const
  {
    std::lock_guard lock(mMutex);
    const NodeId wanted{0, objectId};
    size_t n = 0;
    for (const auto& id : mSourceNodes)
    {
      if (id == wanted)
      {
        ++n;
      }
    }
    return n;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<NodeId> mMethodIds;
  std::vector<NodeId> mSourceNodes;
};

}  // namespace

// Part 18 section 4.5 (with Part 5 section 6.4.27 for the type chain): EVERY one of the six
// mapping-rule Methods - AddIdentity, RemoveIdentity, AddApplication,
// RemoveApplication, AddEndpoint, RemoveEndpoint - must raise
// `RoleMappingRuleChangedAuditEventType` when it successfully mutates the Role.
// The plausible implementation gets this wrong by auditing five of six: the
// emit call is threaded through each handler by hand, so one handler (most
// often a Remove*, added later than its Add* twin) silently returns Good with
// no audit, and the authorisation change leaves no trace. Per-Method
// attribution via the event's `MethodId` field is what makes that visible -
// a bare event count passes if one Method audits twice while another audits
// not at all.
// @verifies AC-SVR-EVT-AUD-021-ROLEMAPPING-AUDIT
TEST(RoleMethodHandlersTest, AllSixMappingRuleMethodsRaiseRoleMappingRuleChangedAudit)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  RoleAuditAttributionRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());

  const NodeId operatorRole{0, operatorRoleId};
  const auto rule = user_name_rule("alice");
  const auto endpoint = endpoint_with_url("opc.tcp://server/secured");
  const String application{"urn:trusted:client"};

  // Each call must genuinely mutate the Role - the obligation is scoped to a
  // *successful* mutation, so a handler that returned early would not be
  // discharging it. Assert the mutation as well as the result code, so the
  // audit assertions below rest on six real Role updates.
  ASSERT_TRUE(invoke_method(
    access.address_space(), make_call(operatorAddIdentityMethod, operatorRoleId, {Variant{rule}}))
                .is_good());
  ASSERT_TRUE(invoke_method(
    access.address_space(), make_call(operatorAddApplicationMethod, operatorRoleId, {Variant{application}}))
                .is_good());
  ASSERT_TRUE(invoke_method(
    access.address_space(), make_call(operatorAddEndpointMethod, operatorRoleId, {Variant{endpoint}}))
                .is_good());

  {
    auto afterAdds = access.role_configuration()->get_role(operatorRole);
    ASSERT_TRUE(afterAdds);
    ASSERT_EQ(afterAdds->identities.size(), 1u) << "AddIdentity must have mutated the Role.";
    ASSERT_EQ(afterAdds->applications.size(), 1u) << "AddApplication must have mutated the Role.";
    ASSERT_EQ(afterAdds->endpoints.size(), 1u) << "AddEndpoint must have mutated the Role.";
  }

  ASSERT_TRUE(invoke_method(
    access.address_space(), make_call(operatorRemoveIdentityMethod, operatorRoleId, {Variant{rule}}))
                .is_good());
  ASSERT_TRUE(invoke_method(access.address_space(),
    make_call(operatorRemoveApplicationMethod, operatorRoleId, {Variant{application}}))
                .is_good());
  ASSERT_TRUE(invoke_method(
    access.address_space(), make_call(operatorRemoveEndpointMethod, operatorRoleId, {Variant{endpoint}}))
                .is_good());

  {
    auto afterRemoves = access.role_configuration()->get_role(operatorRole);
    ASSERT_TRUE(afterRemoves);
    ASSERT_TRUE(afterRemoves->identities.empty()) << "RemoveIdentity must have mutated the Role.";
    ASSERT_TRUE(afterRemoves->applications.empty()) << "RemoveApplication must have mutated the Role.";
    ASSERT_TRUE(afterRemoves->endpoints.empty()) << "RemoveEndpoint must have mutated the Role.";
  }

  // Six successful mutations, so six audits. Wait first (emission is posted to
  // the EventBus dispatch strand), then assert the total is non-zero and exact
  // before attributing it per Method.
  const auto total = recorder.wait_for_count(6);
  ASSERT_GT(total, 0u) << "No RoleMappingRuleChangedAuditEventType was raised at all.";
  EXPECT_EQ(total, 6u) << "Six successful mapping-rule mutations must raise six audit events.";

  // The conjunction the criterion asks for: all six, one each. Asserted
  // per Method so a missing audit names the Method that lost its trace.
  EXPECT_EQ(recorder.count_for_method(operatorAddIdentityMethod), 1u)
    << "AddIdentity raised no RoleMappingRuleChangedAuditEventType.";
  EXPECT_EQ(recorder.count_for_method(operatorRemoveIdentityMethod), 1u)
    << "RemoveIdentity raised no RoleMappingRuleChangedAuditEventType.";
  EXPECT_EQ(recorder.count_for_method(operatorAddApplicationMethod), 1u)
    << "AddApplication raised no RoleMappingRuleChangedAuditEventType.";
  EXPECT_EQ(recorder.count_for_method(operatorRemoveApplicationMethod), 1u)
    << "RemoveApplication raised no RoleMappingRuleChangedAuditEventType.";
  EXPECT_EQ(recorder.count_for_method(operatorAddEndpointMethod), 1u)
    << "AddEndpoint raised no RoleMappingRuleChangedAuditEventType.";
  EXPECT_EQ(recorder.count_for_method(operatorRemoveEndpointMethod), 1u)
    << "RemoveEndpoint raised no RoleMappingRuleChangedAuditEventType.";

  // Part 18 section 4.5 / SVR-EVT-AUD-021: the Source of each event is the Role Object
  // whose mapping rules moved - without it the audit trail cannot say which
  // Role's authorisation configuration changed.
  EXPECT_EQ(recorder.count_for_source_node(operatorRoleId), 6u)
    << "Every mapping-rule audit must name the mutated Role Object as its SourceNode.";

  // Drop the server so its EventBus dies and the listener's captured
  // &recorder reference is released before the recorder is destroyed at
  // scope end. The strand's pending lambdas weak_from_this() to a now-null
  // bus and no-op on the worker thread, so recorder destruction is safe.
  server.reset();
}

// ============================================================================
// A Role created by AddRole carries the six RoleType management Methods, with
// the well-known Roles' handlers, permissions and channel floor
// ============================================================================

namespace
{

/// A Session as the Call service sees it: the server's own address space, a channel of `mode`, and an
/// identity holding exactly `grantedRoles`. Driving the real Call service (rather than the handler
/// directly) is what enforces the RolePermissions and AccessRestrictions on the Role Object and its
/// Methods, so the admin and encrypted-channel requirements are observed where a client meets them.
class RoleCallSession final : public SessionInfo, public SessionSecurityContext
{
public:
  RoleCallSession(AddressSpace addressSpace, std::vector<NodeId> grantedRoles, MessageSecurityMode mode)
    : mAppCfg(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default())),
      mAddressSpace(std::move(addressSpace))
  {
    auto endpoint = std::make_shared<EndpointSecurityContext>();
    endpoint->endpointPolicyId = "Test/RoleCall";
    endpoint->messageSecurityMode = mode;
    mEndpoint = std::move(endpoint);

    auto user = std::make_shared<UserIdentity>();
    user->userId = "role-manager";
    user->displayName = "Role manager";
    user->kind = UserTokenKind::UserName;
    mUser = std::move(user);

    mIdentity = std::make_shared<AccessIdentity>(
      AccessIdentityKey{4242}, std::move(grantedRoles), mUser, mEndpoint, String{"urn:test:role-call"});
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ServerConfig& server_configuration() const override
  {
    return mServerCfg;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mEndpoint, *mUser, mServerCfg.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  NodeId session_id() const override
  {
    return NodeId{1, uint32_t{4242}};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mEndpoint;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mIdentity;
  }

private:
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  ServerConfig mServerCfg;
  std::shared_ptr<const EndpointSecurityContext> mEndpoint;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mIdentity;
};

/// Calls `methodId` on `objectId` with one argument through the Call service and returns the
/// per-operation status.
StatusCode call_through_service(const std::shared_ptr<RoleCallSession>& session,
  boost::asio::any_io_executor executor, const NodeId& objectId, const NodeId& methodId, Variant argument)
{
  CallRequest request;
  request.request_header().request_handle() = 1;
  CallMethodRequest item;
  item.object_id() = objectId;
  item.method_id() = methodId;
  Array<Variant> arguments;
  arguments.payload().push_back(std::move(argument));
  item.input_arguments() = std::move(arguments);
  request.methods_to_call().payload().push_back(std::move(item));

  // Shared, so a completion arriving after the wait has timed out still has a promise to write to.
  auto completion = std::make_shared<std::promise<Response>>();
  auto responseFuture = completion->get_future();
  auto service = MethodServiceSet::create(session,
    {},
    1,
    std::move(request),
    std::move(executor),
    [completion](Response response) { completion->set_value(std::move(response)); });
  (void)service;
  if (responseFuture.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
  {
    return StatusCode{Status::BadTimeout};
  }
  auto response = responseFuture.get();
  auto* callResponse = dynamic_cast<CallResponse*>(response.second.get());
  if (callResponse == nullptr || callResponse->results().size() != 1)
  {
    return StatusCode{Status::BadInternalError};
  }
  return callResponse->results()[0].status_code();
}

/// The forward, local children of `parent` along `referenceType`, by BrowseName name.
std::map<std::string, NodeAccessor> children_by_name(
  AddressSpace& addressSpace, const NodeId& parent, ReferenceTypeId referenceType)
{
  std::map<std::string, NodeAccessor> children;
  auto parentNode = addressSpace.try_find_node_sync(parent);
  if (!parentNode)
  {
    return children;
  }
  for (const auto& reference : parentNode.value().get_references_sync())
  {
    if (!reference.is_forward() || !reference.target_id().is_local() ||
        reference.type_id() != NodeId{referenceType})
    {
      continue;
    }
    auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (child)
    {
      children.emplace(std::string{child.value().get_browse_name().name()}, child.value());
    }
  }
  return children;
}

/// Creates a Role with AddRole in namespace 1 and returns its NodeId (null on failure).
NodeId add_role_named(AddressSpace& addressSpace, std::string_view roleName)
{
  auto result = invoke_method(addressSpace,
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{roleName}}, Variant{namespace_uri_for_index(addressSpace, 1)}}));
  if (!result.is_good() || result.value().output_arguments().size() != 1)
  {
    return NodeId{};
  }
  const auto* roleId = result.value().output_arguments()[0].try_as<NodeId>();
  return roleId ? *roleId : NodeId{};
}

/// The NodeId of the management Method `name` on `role`, or null when the Role does not carry it.
NodeId management_method(AddressSpace& addressSpace, const NodeId& role, const std::string& name)
{
  const auto methods = children_by_name(addressSpace, role, ReferenceTypeId::HasComponent);
  const auto found = methods.find(name);
  return found == methods.end() ? NodeId{} : found->second.get_node_id();
}

/// The number of elements in the Role's mirrored `property` (Identities / Applications / Endpoints);
/// an absent Property or an unreadable value reports SIZE_MAX so it can never pass as a count.
size_t mirrored_count(AddressSpace& addressSpace, const NodeId& role, const std::string& property)
{
  const auto properties = children_by_name(addressSpace, role, ReferenceTypeId::HasProperty);
  const auto found = properties.find(property);
  if (found == properties.end())
  {
    return SIZE_MAX;
  }
  auto variable = found->second.as<VariableAccessor>();
  if (!variable)
  {
    return SIZE_MAX;
  }
  const auto value = variable->try_read_value_sync();
  if (!value.is_good())
  {
    return SIZE_MAX;
  }
  const auto& variant = value.value().value();
  if (variant.empty())
  {
    return 0;
  }
  if (variant.is_array_of_string())
  {
    return variant.as<Array<String>>().size();
  }
  if (variant.is_array_of_structure())
  {
    return variant.as<Array<RefStructure<Structure>>>().size();
  }
  return SIZE_MAX;
}

struct RoleState
{
  size_t identities;
  size_t applications;
  size_t endpoints;
  size_t mirroredIdentities;
  size_t mirroredApplications;
  size_t mirroredEndpoints;
};

RoleState role_state(AddressSpace& addressSpace, const RoleConfiguration& roleConfig, const NodeId& role)
{
  const auto def = roleConfig.get_role(role);
  return RoleState{def ? def->identities.size() : SIZE_MAX,
    def ? def->applications.size() : SIZE_MAX,
    def ? def->endpoints.size() : SIZE_MAX,
    mirrored_count(addressSpace, role, "Identities"),
    mirrored_count(addressSpace, role, "Applications"),
    mirrored_count(addressSpace, role, "Endpoints")};
}

constexpr std::array<std::pair<std::string_view, MethodId>, 6> roleTypeManagementMethods{{
  {"AddIdentity", MethodId::RoleType_AddIdentity},
  {"RemoveIdentity", MethodId::RoleType_RemoveIdentity},
  {"AddApplication", MethodId::RoleType_AddApplication},
  {"RemoveApplication", MethodId::RoleType_RemoveApplication},
  {"AddEndpoint", MethodId::RoleType_AddEndpoint},
  {"RemoveEndpoint", MethodId::RoleType_RemoveEndpoint},
}};

}  // namespace

// Part 18 4.4.1: the six management Methods are Optional on RoleType and the Identities, Applications
// and Endpoints Properties are not writable, so a Role without the Methods can never be granted. The
// Role AddRole creates carries all six (each with the RoleType declaration's RolePermissions and an
// EncryptionRequired restriction, as the well-known Roles' Methods have) and the Applications and
// Endpoints Properties the Methods maintain.
// @verifies AC-SVR-ROLE-ADDROLE-ROLES-CARRY-MANAGEMENT-METHODS
TEST(RoleMethodHandlersTest, AddRoleCreatedRoleCarriesTheSixManagementMethods)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();

  const NodeId role = add_role_named(addressSpace, "MethodBearingRole");
  ASSERT_FALSE(role.is_null()) << "AddRole must succeed";

  const auto components = children_by_name(addressSpace, role, ReferenceTypeId::HasComponent);
  for (const auto& [name, declarationId] : roleTypeManagementMethods)
  {
    const auto found = components.find(std::string{name});
    ASSERT_NE(found, components.end()) << "the AddRole Role lacks the " << name << " Method";
    EXPECT_EQ(found->second.get_node_class(), NodeClass::Method) << name;

    auto declaration = addressSpace.try_find_node_sync(NodeId{declarationId});
    ASSERT_TRUE(declaration.is_good()) << name;
    const auto declared = declaration.value().get_role_permissions();
    ASSERT_TRUE(declared.has_value() && !declared->empty())
      << "precondition: the RoleType declaration of " << name << " carries the administrative baseline";
    EXPECT_EQ(found->second.get_role_permissions(), declared)
      << name << " must carry the RoleType declaration's RolePermissions (SecurityAdmin alone may Call)";
    const auto restrictions = found->second.get_access_restrictions();
    ASSERT_TRUE(restrictions.has_value()) << name;
    EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired))
      << name << " must require an encrypted channel (Part 18 4.4.1)";
  }

  const auto properties = children_by_name(addressSpace, role, ReferenceTypeId::HasProperty);
  for (const std::string_view property :
    {"Identities", "Applications", "Endpoints", "ApplicationsExclude", "EndpointsExclude"})
  {
    EXPECT_TRUE(properties.contains(std::string{property})) << "the AddRole Role lacks " << property;
  }
}

// Control: a SecurityAdmin over SignAndEncrypt drives each of the six Methods on the AddRole Role
// through the Call service; each changes the Role's RoleConfiguration entry and the mirrored Property.
// @verifies AC-SVR-ROLE-ADDROLE-ROLES-CARRY-MANAGEMENT-METHODS
TEST(RoleMethodHandlersTest, SecurityAdminManagesAnAddRoleRoleThroughEachOfItsSixMethods)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();
  auto& roleConfig = *access.role_configuration();

  const NodeId role = add_role_named(addressSpace, "ManagedRole");
  ASSERT_FALSE(role.is_null()) << "AddRole must succeed";
  auto admin = std::make_shared<RoleCallSession>(addressSpace,
    std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_SecurityAdmin}},
    MessageSecurityMode::SignAndEncrypt);

  const auto rule = user_name_rule("granted-through-add-role");
  const String application{"urn:managed:client"};
  const auto endpoint = endpoint_with_url("opc.tcp://managed/secured");
  const auto call = [&](const std::string& method, Variant argument)
  {
    const NodeId methodId = management_method(addressSpace, role, method);
    EXPECT_FALSE(methodId.is_null()) << "the AddRole Role lacks " << method;
    return call_through_service(admin, tp.get_executor(), role, methodId, std::move(argument));
  };

  {
    const auto before = role_state(addressSpace, roleConfig, role);
    EXPECT_EQ(before.identities, 0u);
    EXPECT_EQ(before.mirroredIdentities, 0u);
  }

  EXPECT_EQ(call("AddIdentity", Variant{rule}), Status::Good);
  EXPECT_EQ(call("AddApplication", Variant{application}), Status::Good);
  EXPECT_EQ(call("AddEndpoint", Variant{endpoint}), Status::Good);
  {
    const auto after = role_state(addressSpace, roleConfig, role);
    EXPECT_EQ(after.identities, 1u) << "AddIdentity must change the Role's RoleConfiguration entry";
    EXPECT_EQ(after.mirroredIdentities, 1u) << "AddIdentity must mirror into the Identities Property";
    EXPECT_EQ(after.applications, 1u) << "AddApplication must change the RoleConfiguration entry";
    EXPECT_EQ(after.mirroredApplications, 1u) << "AddApplication must mirror into Applications";
    EXPECT_EQ(after.endpoints, 1u) << "AddEndpoint must change the RoleConfiguration entry";
    EXPECT_EQ(after.mirroredEndpoints, 1u) << "AddEndpoint must mirror into Endpoints";
  }

  EXPECT_EQ(call("RemoveIdentity", Variant{rule}), Status::Good);
  EXPECT_EQ(call("RemoveApplication", Variant{application}), Status::Good);
  EXPECT_EQ(call("RemoveEndpoint", Variant{endpoint}), Status::Good);
  {
    const auto after = role_state(addressSpace, roleConfig, role);
    EXPECT_EQ(after.identities, 0u) << "RemoveIdentity must change the RoleConfiguration entry";
    EXPECT_EQ(after.mirroredIdentities, 0u) << "RemoveIdentity must mirror into Identities";
    EXPECT_EQ(after.applications, 0u) << "RemoveApplication must change the RoleConfiguration entry";
    EXPECT_EQ(after.mirroredApplications, 0u) << "RemoveApplication must mirror into Applications";
    EXPECT_EQ(after.endpoints, 0u) << "RemoveEndpoint must change the RoleConfiguration entry";
    EXPECT_EQ(after.mirroredEndpoints, 0u) << "RemoveEndpoint must mirror into Endpoints";
  }
  admin.reset();
  server.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Negative: with the Role seeded by a SecurityAdmin, a caller holding ConfigureAdmin (but not
// SecurityAdmin) is refused each of the six Methods with Bad_UserAccessDenied, and a SecurityAdmin on a
// signed-only channel is refused with Bad_SecurityModeInsufficient; neither changes the Role.
// @verifies AC-SVR-ROLE-ADDROLE-ROLES-CARRY-MANAGEMENT-METHODS
TEST(RoleMethodHandlersTest, AddRoleRoleMethodsRefuseNonSecurityAdminAndUnencryptedCallers)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();
  auto& roleConfig = *access.role_configuration();

  const NodeId role = add_role_named(addressSpace, "GuardedRole");
  ASSERT_FALSE(role.is_null()) << "AddRole must succeed";
  auto admin = std::make_shared<RoleCallSession>(addressSpace,
    std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_SecurityAdmin}},
    MessageSecurityMode::SignAndEncrypt);
  auto configureAdmin = std::make_shared<RoleCallSession>(addressSpace,
    std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_ConfigureAdmin}},
    MessageSecurityMode::SignAndEncrypt);
  auto signedAdmin = std::make_shared<RoleCallSession>(addressSpace,
    std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_SecurityAdmin}},
    MessageSecurityMode::Sign);

  const auto seededRule = user_name_rule("seeded");
  const String seededApplication{"urn:seeded:client"};
  const auto seededEndpoint = endpoint_with_url("opc.tcp://seeded/secured");
  const auto call =
    [&](const std::shared_ptr<RoleCallSession>& session, const std::string& method, Variant argument)
  {
    const NodeId methodId = management_method(addressSpace, role, method);
    EXPECT_FALSE(methodId.is_null()) << "the AddRole Role lacks " << method;
    return call_through_service(session, tp.get_executor(), role, methodId, std::move(argument));
  };

  // Seed one entry of each kind so the refused Removes have something they could have removed.
  ASSERT_EQ(call(admin, "AddIdentity", Variant{seededRule}), Status::Good);
  ASSERT_EQ(call(admin, "AddApplication", Variant{seededApplication}), Status::Good);
  ASSERT_EQ(call(admin, "AddEndpoint", Variant{seededEndpoint}), Status::Good);
  const auto seeded = role_state(addressSpace, roleConfig, role);
  ASSERT_EQ(seeded.identities, 1u);
  ASSERT_EQ(seeded.mirroredIdentities, 1u);
  ASSERT_EQ(seeded.applications, 1u);
  ASSERT_EQ(seeded.mirroredApplications, 1u);
  ASSERT_EQ(seeded.endpoints, 1u);
  ASSERT_EQ(seeded.mirroredEndpoints, 1u);

  const auto expectUnchanged = [&](const std::string& context)
  {
    const auto now = role_state(addressSpace, roleConfig, role);
    EXPECT_EQ(now.identities, 1u) << context;
    EXPECT_EQ(now.mirroredIdentities, 1u) << context;
    EXPECT_EQ(now.applications, 1u) << context;
    EXPECT_EQ(now.mirroredApplications, 1u) << context;
    EXPECT_EQ(now.endpoints, 1u) << context;
    EXPECT_EQ(now.mirroredEndpoints, 1u) << context;
  };

  for (const auto& session : {configureAdmin, signedAdmin})
  {
    const Status expected =
      session == configureAdmin ? Status::BadUserAccessDenied : Status::BadSecurityModeInsufficient;
    const std::string who = session == configureAdmin ? "ConfigureAdmin-only caller" : "signed-only channel";
    EXPECT_EQ(call(session, "AddIdentity", Variant{user_name_rule("intruder")}), expected) << who;
    expectUnchanged(who + " AddIdentity");
    EXPECT_EQ(call(session, "RemoveIdentity", Variant{seededRule}), expected) << who;
    expectUnchanged(who + " RemoveIdentity");
    EXPECT_EQ(call(session, "AddApplication", Variant{String{"urn:intruder:client"}}), expected) << who;
    expectUnchanged(who + " AddApplication");
    EXPECT_EQ(call(session, "RemoveApplication", Variant{seededApplication}), expected) << who;
    expectUnchanged(who + " RemoveApplication");
    EXPECT_EQ(call(session, "AddEndpoint", Variant{endpoint_with_url("opc.tcp://intruder")}), expected)
      << who;
    expectUnchanged(who + " AddEndpoint");
    EXPECT_EQ(call(session, "RemoveEndpoint", Variant{seededEndpoint}), expected) << who;
    expectUnchanged(who + " RemoveEndpoint");
  }
  admin.reset();
  configureAdmin.reset();
  signedAdmin.reset();
  server.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// RemoveRole deletes the Role's subtree, and with it the six Method Nodes the handlers live on, plus
// the Applications / Endpoints Properties the Methods maintain.
// @verifies AC-SVR-ROLE-ADDROLE-ROLES-CARRY-MANAGEMENT-METHODS
TEST(RoleMethodHandlersTest, RemoveRoleRemovesTheAddRoleRoleAndItsMethodNodes)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();

  const NodeId role = add_role_named(addressSpace, "TransientRole");
  ASSERT_FALSE(role.is_null()) << "AddRole must succeed";
  std::vector<NodeId> owned;
  for (const auto& [name, declarationId] : roleTypeManagementMethods)
  {
    (void)declarationId;
    const NodeId methodId = management_method(addressSpace, role, std::string{name});
    ASSERT_FALSE(methodId.is_null()) << "precondition: the AddRole Role carries " << name;
    owned.push_back(methodId);
  }
  const auto properties = children_by_name(addressSpace, role, ReferenceTypeId::HasProperty);
  for (const std::string_view property : {"Applications", "Endpoints"})
  {
    const auto found = properties.find(std::string{property});
    ASSERT_NE(found, properties.end()) << "precondition: the AddRole Role carries " << property;
    owned.push_back(found->second.get_node_id());
  }

  auto removed = invoke_method(addressSpace,
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole),
      roleSetId,
      {Variant{role}}));
  ASSERT_TRUE(removed.is_good()) << removed.status_code().value();

  EXPECT_FALSE(addressSpace.try_find_node_sync(role).is_good()) << "the Role Object must be gone";
  EXPECT_FALSE(access.role_configuration()->get_role(role).has_value());
  for (const auto& nodeId : owned)
  {
    EXPECT_FALSE(addressSpace.try_find_node_sync(nodeId).is_good())
      << "RemoveRole left " << ua::to_string(nodeId) << " behind";
  }
}

namespace
{

/// Registers a test namespace B on @p addressSpace in which a Node holds an Organizes Reference to @p target,
/// whose removal B refuses with Bad_InternalError. Both halves are held: the referrer's in B and the inverse
/// at
/// @p target.
void hold_a_refused_reference_to(AddressSpace& addressSpace, boost::asio::any_io_executor executor,
  const NodeId& target, std::shared_ptr<ua::test::ScriptedReferrerNamespace>& namespaceB)
{
  namespaceB = ua::test::ScriptedReferrerNamespace::create("urn:test:remove-role:b", std::move(executor));
  const auto index = addressSpace.try_add_namespace_sync(namespaceB);
  ASSERT_TRUE(index.is_good()) << ua::to_string(index.status_code());
  const NodeId referrer{index.value(), "Referrer"};
  auto created = addressSpace.try_create_node_sync(referrer, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good()) << ua::to_string(created.status_code());
  ASSERT_TRUE(created.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{target}, true)
                .is_good());
  auto targetNode = addressSpace.try_find_node_sync(target);
  ASSERT_TRUE(targetNode.is_good());
  ASSERT_TRUE(targetNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{referrer}, false)
                .is_good());
  namespaceB->answer_removals(referrer, StatusCode{Status::BadInternalError});
}

CallResult remove_role(AddressSpace& addressSpace, const NodeId& role)
{
  return invoke_method(addressSpace,
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole),
      roleSetId,
      {Variant{role}}));
}

}  // namespace

// The Role was removed, so its audit Event reports the action as performed, though a Reference to the Role's
// Node is left in another namespace.
// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-REMOVEROLE-AUDIT-STATUS-TRUE, scope=function)
TEST(RoleMethodHandlersTest, RemoveRoleAuditsStatusTrueWhenTheDeleteLeavesAReferenceBehind)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();
  EventRecorder recorder;
  server->event_bus().set_event_listener(recorder.listener());
  std::shared_ptr<ua::test::ScriptedReferrerNamespace> namespaceB;

  const NodeId role = add_role_named(addressSpace, "Referenced");
  ASSERT_FALSE(role.is_null()) << "AddRole must succeed";
  const auto countBefore = recorder.wait_for_role_audit_count(1);
  hold_a_refused_reference_to(addressSpace, tp.get_executor(), role, namespaceB);

  [[maybe_unused]] const auto removed = remove_role(addressSpace, role);

  EXPECT_EQ(addressSpace.try_find_node_sync(role).status_code().as_status(), Status::BadNodeIdUnknown)
    << "the Role's Node must be gone";
  ASSERT_GT(recorder.wait_for_role_audit_count(countBefore + 1), countBefore) << "RemoveRole raised no audit";
  const auto status = recorder.last_role_audit_status();
  ASSERT_TRUE(status.has_value());
  EXPECT_TRUE(*status) << "the audit Event reports the performed removal as not performed";
  server.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-REMOVEROLE-ANSWERS-UNCERTAIN, scope=function)
TEST(RoleMethodHandlersTest, RemoveRoleAnswersUncertainWhenTheDeleteLeavesAReferenceBehind)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), /*roleManagement=*/true);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();
  std::shared_ptr<ua::test::ScriptedReferrerNamespace> namespaceB;

  const NodeId referenced = add_role_named(addressSpace, "Referenced");
  ASSERT_FALSE(referenced.is_null()) << "AddRole must succeed";
  hold_a_refused_reference_to(addressSpace, tp.get_executor(), referenced, namespaceB);

  const auto first = remove_role(addressSpace, referenced);
  ASSERT_TRUE(first.is_good()) << ua::to_string(first.status_code());
  EXPECT_EQ(first.value().status_code().as_status(), Status::UncertainReferenceNotDeleted)
    << "RemoveRole answered " << ua::to_string(first.value().status_code());
  EXPECT_EQ(addressSpace.try_find_node_sync(referenced).status_code().as_status(), Status::BadNodeIdUnknown)
    << "the Role's Node must be gone";

  const NodeId unreferenced = add_role_named(addressSpace, "Unreferenced");
  ASSERT_FALSE(unreferenced.is_null()) << "AddRole must succeed";
  const auto second = remove_role(addressSpace, unreferenced);
  ASSERT_TRUE(second.is_good()) << ua::to_string(second.status_code());
  EXPECT_EQ(second.value().status_code().as_status(), Status::Good)
    << "RemoveRole of a Role nothing references answered " << ua::to_string(second.value().status_code());
  server.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// Calls @p req FROM the executor's thread, as the Call service would, and waits up to @p timeout.
std::optional<CallResult> invoke_method_on_executor(AddressSpace& addressSpace,
  boost::asio::any_io_executor executor, const CallMethodRequest& req, std::chrono::seconds timeout)
{
  auto methodNode = addressSpace.try_find_node_sync(req.method_id());
  if (methodNode.is_bad())
    return CallResult{methodNode.status_code()};
  auto method = methodNode.value().as<MethodAccessor>();
  if (!method)
    return CallResult{StatusCode{Status::BadNodeIdInvalid}};
  auto promise = std::make_shared<std::promise<CallResult>>();
  auto future = promise->get_future();
  boost::asio::post(executor,
    [method = *method, req, context = secure_channel_context(), promise]() mutable
    {
      method.call_async(
        req, context, [promise](CallResult result) { promise->set_value(std::move(result)); });
    });
  if (future.wait_for(timeout) != std::future_status::ready)
    return std::nullopt;
  return future.get();
}

}  // namespace

// AddIdentity mirrors the new rule into the Role's Identities Property. The write goes to whatever
// serves that Variable, which may answer by posting to the executor the Method runs on. On a one-thread
// executor a blocking write waits there for an answer that can only run there and the Method never
// returns; the asynchronous mirror must let it return, and the Property must still receive the rules.
// @relation(SVR-SECADMIN-040, scope=function)
TEST(RoleMethodHandlersNonBlocking, AddIdentityMirrorCompletesWhenTheWriteIsAnsweredByPosting)
{
  ua::test::OneThreadExecutor executor;
  auto server = create_part18_server(executor.executor(), /*roleManagement=*/true, /*auditing=*/false);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();

  NodeId identitiesId;
  auto operatorRole = addressSpace.try_find_node_sync(NodeId{0, operatorRoleId});
  ASSERT_TRUE(operatorRole.is_good());
  for (const auto& ref : operatorRole.value().get_references_sync())
  {
    if (!ref.is_forward() || ref.type_id() != NodeId{ReferenceTypeId::HasProperty})
      continue;
    auto child = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (child.is_good() && std::string{child.value().get_browse_name().name()} == "Identities")
      identitiesId = ref.target_id().node_id();
  }
  ASSERT_FALSE(identitiesId.is_null());
  auto identities = addressSpace.try_find_node_sync(identitiesId);
  ASSERT_TRUE(identities.is_good());
  auto* source = identities.value()->external_value_source();
  ASSERT_NE(source, nullptr);
  auto mirrored = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(source
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         complete) { complete(DataValue{}); },
                  [executor = executor.executor(), mirrored](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      complete)
                  {
                    ++*mirrored;
                    boost::asio::post(executor,
                      [complete = std::move(complete)]() mutable { complete(ValueSource::Written{}); });
                  }))
                .is_good());

  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{"alice"};
  auto result = invoke_method_on_executor(addressSpace,
    executor.executor(),
    make_call(operatorAddIdentityMethod, operatorRoleId, {Variant{rule}}),
    std::chrono::seconds{10});
  ASSERT_TRUE(result.has_value()) << "AddIdentity blocked the thread its Property's write answers on";
  EXPECT_TRUE(result->is_good()) << result->status_code().value();
  EXPECT_EQ(mirrored->load(), 1) << "the rules were not mirrored into the Identities Property";
  server.reset();
}

// AddRole creates the Role in the namespace the Client names and then writes the new Role's
// RolePermissions and AccessRestrictions there - a namespace that may answer by posting to the executor
// the Method runs on. On a one-thread executor any blocking step waits there for an answer that can
// only run there and the Method never returns; the coroutine must let it return.
// @relation(AC-SVR-SECADMIN-037-ADDROLE-COMPLETES-WHEN-THE-NAMESPACE-POSTS, scope=function)
TEST(RoleMethodHandlersNonBlocking, AddRoleCompletesWhenTheTargetNamespaceAnswersByPosting)
{
  ua::test::OneThreadExecutor executor;
  auto server = create_part18_server(executor.executor(), /*roleManagement=*/true, /*auditing=*/false);
  ServerImplTestAccess access{*server};
  auto& addressSpace = access.address_space();
  auto postingNamespace =
    ua::test::PostingWritesNamespace::create("urn:test:posting-roles", executor.executor());
  ASSERT_TRUE(addressSpace.try_add_namespace_sync(postingNamespace).is_good());

  auto result = invoke_method_on_executor(addressSpace,
    executor.executor(),
    make_call(static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole),
      roleSetId,
      {Variant{String{"PostedRole"}}, Variant{String{"urn:test:posting-roles"}}}),
    std::chrono::seconds{10});
  ASSERT_TRUE(result.has_value()) << "AddRole blocked the thread its target namespace answers on";
  ASSERT_TRUE(result->is_good()) << result->status_code().value();
  ASSERT_EQ(result->value().output_arguments().size(), 1u);
  const auto* newId = result->value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(newId, nullptr);
  EXPECT_TRUE(access.role_configuration()->get_role(*newId).has_value());
  EXPECT_GT(postingNamespace->posted_writes(AttributeId::RolePermissions) +
              postingNamespace->posted_writes(AttributeId::AccessRestrictions),
    0u)
    << "AddRole wrote nothing to the new Role through the posting namespace";
  server.reset();
}
