// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// CTT-mirror integration tests for the Step 6 / Phase P3 RolePermissions Write
/// gate stack + admin-only Read + Property writability (Part 18 Role-Based
/// Security, SVR-SECADMIN-026 / 047 / 048..053, SVR-EVT-AUD-022).
///
/// These stand up a full Part-18-wired server and exercise, over the wire:
///   * SECADMIN-026 - the Identities/Applications/Endpoints Role Properties have
///     AccessLevel.CurrentWrite FALSE (read the bit; a generic Write is rejected).
///   * SECADMIN-047 - the raw RolePermissions Attribute is admin-only readable.
///   * SECADMIN-048..052 - the 5-gate Write stack (master flag / namespace
///     consent / admin / empty self-lock / inoperable guard), each rejection
///     code pinned end-to-end.
///   * SECADMIN-053 - a successful Write is immediately visible to other active
///     Sessions.
///   * SVR-EVT-AUD-022 - a successful Write emits AuditWriteUpdateEventType; a gated
///     rejection emits nothing.
///
/// Falsifiability: the master/namespace/admin gates are pinned with BOTH a
/// rejection AND a success (`AdminWriteSucceeds`), so a deny-everything bug
/// cannot pass. SecurityAdmin is reached only by an authenticated UserName
/// session (`grant_security_admin_to_user`); non-admin tests use a plain
/// Anonymous fixture.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/role_based_security_fixture.h"

#include "matchers.h"
#include "requests.h"

#include "ua_access_level_type.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_audit_write_update_event_payload.h"
#include "ua_base_event.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_role_permission_type.h"
#include "ua_session_attribute_services.h"
#include "ua_variable_id.h"
#include "ua_status.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

// Operator Role Object child Properties. Operator is one of the six configurable
// Roles carrying the full Identities/Applications/Endpoints surface - Anonymous
// carries only Identities in UA-1.05.06.
constexpr uint32_t operatorIdentities = static_cast<uint32_t>(VariableId::WellKnownRole_Operator_Identities);
constexpr uint32_t operatorApplications =
  static_cast<uint32_t>(VariableId::WellKnownRole_Operator_Applications);
constexpr uint32_t operatorEndpoints = static_cast<uint32_t>(VariableId::WellKnownRole_Operator_Endpoints);

NodeId security_admin_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)};
}

NodeId anonymous_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)};
}

/// Write the RolePermissions Attribute of `node` over the wire; return the
/// per-operation StatusCode (or the service-level result on request failure).
StatusCode write_role_permissions(
  Session& session, const NodeId& node, const std::vector<RolePermissionType>& perms)
{
  Variant value{array_utils::copy_to_array_of_references(perms)};
  auto resp = session.attributes().write_sync(
    WriteRequestBuilder{}.write(node, std::move(value), AttributeId::RolePermissions).build());
  if (!resp.response_header().service_result().is_good())
    return resp.response_header().service_result();
  if (resp.results().empty())
    return StatusCode{Status::BadInternalError};
  return resp.results()[0];
}

/// Read a single attribute and return the per-operation result DataValue.
DataValue read_attribute(Session& session, const NodeId& node, AttributeId attr)
{
  auto resp = session.attributes().read_sync(ReadRequestBuilder{}.read(node).attribute(attr).build());
  if (!resp.response_header().service_result().is_good() || resp.results().empty())
  {
    DataValue dv;
    dv.status() = resp.response_header().service_result().is_good() ? StatusCode{Status::BadInternalError}
                                                                    : resp.response_header().service_result();
    return dv;
  }
  return resp.results()[0];
}

/// Thread-safe recorder for `AuditWriteUpdateEventPayload`s emitted on the server's
/// EventBus. Installed via `Server::set_event_listener` - which sets
/// `has_event_interest()` true *synchronously*, so the Write's audit gate
/// (`auditActive`) is reliably armed before the wire Write runs. The listener
/// fires on the EventBus dispatch strand (a worker thread); the test reads
/// counts on the main thread under the mutex. Mirrors the EventRecorder in
/// `role_method_handlers_tests.cpp`.
struct AuditWriteRecorder
{
  std::function<void(const BaseEvent&)> listener()
  {
    return [this](const BaseEvent& event)
    {
      if (dynamic_cast<const AuditWriteUpdateEventPayload*>(&event) == nullptr)
        return;
      std::lock_guard lock(mutex);
      ++countValue;
      cv.notify_all();
    };
  }

  size_t count() const
  {
    std::lock_guard lock(mutex);
    return countValue;
  }

  size_t wait_for_count(size_t expected, std::chrono::milliseconds timeout = std::chrono::seconds{2})
  {
    std::unique_lock lock(mutex);
    cv.wait_for(lock, timeout, [&] { return countValue >= expected; });
    return countValue;
  }

  mutable std::mutex mutex;
  std::condition_variable cv;
  size_t countValue{0};
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Base: a role-gated test Variable (`mTestNodeId`) granting SecurityAdmin the
/// full bit set and Anonymous Browse+Read. RolePermissions writability is
/// expressed by the Node's WriteMask and permission bit 3.
class RbacRpwBase : public ComplianceRoleBasedSecurity
{
protected:
  void customize_server_configuration(ServerConfig& cfg) override
  {
    cfg.auditingEnabled = mAuditingEnabled;
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    mTestNsIndex = install_test_namespace(addressSpace, "urn:test:role-permissions-write");
    mTestNodeId = NodeId{mTestNsIndex, 60001};
    create_role_gated_variable(addressSpace, mTestNodeId, "RpwTarget", initial_permissions());
    auto node = addressSpace.find_node_sync(mTestNodeId);
    node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  }

  virtual std::vector<RolePermissionType> initial_permissions()
  {
    return {make_role_permission(security_admin_role_id(),
              {PermissionType::Bit::Browse,
                PermissionType::Bit::ReadRolePermissions,
                PermissionType::Bit::Read,
                PermissionType::Bit::Write,
                PermissionType::Bit::WriteRolePermissions}),
      make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  }

  /// A proposed set that keeps SecurityAdmin's WriteRolePermissions (clears the
  /// inoperable guard).
  std::vector<RolePermissionType> admin_safe_proposed()
  {
    return {make_role_permission(security_admin_role_id(),
              {PermissionType::Bit::Browse,
                PermissionType::Bit::ReadRolePermissions,
                PermissionType::Bit::Read,
                PermissionType::Bit::Write,
                PermissionType::Bit::WriteRolePermissions}),
      make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  }

  bool mAuditingEnabled{false};
  uint16_t mTestNsIndex{0};
  NodeId mTestNodeId;
};

/// SecurityAdmin session: authenticates as UserName "admin".
class RbacRpwAdminFixture : public RbacRpwBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }
};

/// Non-admin session: default Anonymous authenticator. The Node is writable in
/// principle so the canonical permission-bit denial is the deciding gate.
class RbacRpwNonAdminFixture : public RbacRpwBase
{};

/// The verdict a declining namespace returns. Deliberately not a status any other layer of the write
/// transaction produces, so a test asserting it cannot be satisfied by an earlier gate refusing first.
constexpr Status declineStatus = Status::BadInvalidState;
constexpr string_view declineCode = "TestNamespaceDeclinedPolicy";

/// A namespace that exposes the standard writable Attribute but refuses every prospective policy.
///
/// This is the extension point design section 8.2 step 4 names: the owning namespace decides whether a
/// proposed policy is permitted, and is asked only after caller authorization has already succeeded.
class DecliningNamespace final : public ua::default_ns::Namespace
{
public:
  static std::shared_ptr<DecliningNamespace> create(
    std::string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<DecliningNamespace>{new DecliningNamespace{uri, std::move(executor)}};
  }

  void validate_role_permissions_updates_async(const ua::RequestInfo& request,
    std::span<const ua::RolePermissionsUpdate> updates,
    std::function<void(ua::BatchResult<VoidResult>)> complete) override
  {
    (void)request;
    if (!complete)
    {
      return;
    }
    ua::BatchResult<VoidResult> result;
    for (std::size_t i = 0; i < updates.size(); ++i)
    {
      result.items.emplace_back(StatusCode{declineStatus,
        ErrorDetail::build(std::string{declineCode},
          "This namespace refuses every prospective RolePermissions policy",
          "DecliningNamespace")});
    }
    complete(std::move(result));
  }

private:
  DecliningNamespace(std::string_view uri, boost::asio::any_io_executor executor)
    : ua::default_ns::Namespace(uri, std::move(executor))
  {}
};

/// Administrator whose test Node lives in a namespace that declines every prospective policy.
class RbacRpwDecliningNamespaceFixture : public RbacRpwAdminFixture
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    auto declining =
      DecliningNamespace::create("urn:test:role-permissions-declining", mServerThreadPool.executor());
    declining->set_namespace_defaults(std::vector<RolePermissionType>{}, std::nullopt);
    mTestNsIndex = addressSpace.add_namespace_sync(declining);
    mTestNodeId = NodeId{mTestNsIndex, 60101};
    create_role_gated_variable(addressSpace, mTestNodeId, "RpwDeclineTarget", initial_permissions());
    auto node = addressSpace.find_node_sync(mTestNodeId);
    node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  }
};

/// Administrator with auditing enabled, writing to an ordinary namespace that permits the policy
/// (for the SVR-EVT-AUD-022 success rows).
class RbacRpwAuditFixture : public RbacRpwAdminFixture
{
public:
  RbacRpwAuditFixture()
  {
    mAuditingEnabled = true;
  }
};

/// Administrator with auditing enabled, writing to a namespace that declines - the refusal arm of
/// SVR-EVT-AUD-022, which asserts a refused Write emits nothing.
class RbacRpwDecliningAuditFixture : public RbacRpwDecliningNamespaceFixture
{
public:
  RbacRpwDecliningAuditFixture()
  {
    mAuditingEnabled = true;
  }
};

// ============================================================================
// SECADMIN-026 - Identities/Applications/Endpoints Properties: CurrentWrite FALSE
// (Part 18 section 4.4.1 L635-639) - server_security_role_property_current_write_false_integration
// ============================================================================

// @relation(SVR-SECADMIN-026, scope=function)
TEST_F(RbacRpwAdminFixture, RolePropertyCurrentWriteIsFalseOverWire)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RolePropWrite");

  for (uint32_t propId : {operatorIdentities, operatorApplications, operatorEndpoints})
  {
    auto accessLevel = read_attribute(session, NodeId{0, propId}, AttributeId::AccessLevel);
    EXPECT_THAT(accessLevel, Good()) << "AccessLevel read on role property " << propId;
    const auto* raw = accessLevel.value().try_as<uint8_t>();
    ASSERT_NE(raw, nullptr) << "AccessLevel value not a Byte for property " << propId;
    EXPECT_FALSE(AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentWrite))
      << "Role property " << propId << " must have CurrentWrite FALSE";
  }

  // A generic Value write against Identities is rejected (CurrentWrite FALSE).
  auto writeResp = session.attributes().write_sync(
    WriteRequestBuilder{}
      .write(NodeId{0, operatorIdentities}, Variant{Array<RefStructure<Structure>>{}})
      .build());
  ASSERT_FALSE(writeResp.results().empty());
  EXPECT_EQ(writeResp.results()[0].as_status(), Status::BadNotWritable);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-047 - raw RolePermissions Attribute is admin-only readable
// server_security_role_permissions_admin_read_integration
// ============================================================================

TEST_F(RbacRpwAdminFixture, AdminReadsRolePermissionsAttribute)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AdminRpRead");
  auto value = read_attribute(session, mTestNodeId, AttributeId::RolePermissions);
  EXPECT_THAT(value, Good()) << "SecurityAdmin must be able to read the RolePermissions Attribute";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(SVR-SECADMIN-047, scope=function)
TEST_F(RbacRpwNonAdminFixture, NonAdminRolePermissionsReadDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "NonAdminRpRead");
  auto value = read_attribute(session, mTestNodeId, AttributeId::RolePermissions);
  EXPECT_THAT(value, HasStatus(Status::BadUserAccessDenied))
    << "Non-admin Read of the raw RolePermissions Attribute must be denied (SECADMIN-047)";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-050 - admin gate - server_security_role_permissions_write_admin_only_integration
// ============================================================================

// @relation(AC-SVR-ADDRSP-058-PERMISSIONS-WRITABLE-WHEN-CONFIGURABLE, scope=function)
TEST_F(RbacRpwAdminFixture, AdminWriteSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AdminWrite");
  EXPECT_EQ(write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(), Status::Good);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-SECADMIN-050-ROLEPERMISSIONS-WRITE, scope=function)
TEST_F(RbacRpwNonAdminFixture, NonAdminWriteDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "NonAdminWrite");
  EXPECT_EQ(write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-051 - empty-array self-lock guard
// server_security_role_permissions_empty_array_guard_integration
// ============================================================================

// An empty write is not a rejection: design section 8.2 step 2 maps it to `nullopt`, meaning CLEAR the
// override, and the node then falls back to its namespace default. The write succeeds, and what governs
// the node afterwards is the fallback - here an engaged, empty namespace default, which grants nobody
// anything. The node is consequently unreachable to the very administrator who cleared it, including for
// a further RolePermissions write.
//
// That outcome is the design's, deliberately: the former guard refused this write by consulting a
// server-wide administrator list, which section 8.2 discards as a fictitious global predicate over a
// per-Node decision. Operability of critical surfaces is carried by withholding the RolePermissions
// WriteMask (pinned by ComplianceWithNodes.NoServerOwnedNodeAdvertisesAWritableRolePermissionsAttribute),
// not by second-guessing a permitted write on an ordinary node.
// @relation(AC-SVR-SECADMIN-051-EMPTY-ROLEPERMISSIONS, scope=function)
TEST_F(RbacRpwAdminFixture, EmptyWriteClearsTheOverrideAndFallsBackToTheNamespaceDefault)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "EmptyArray");

  // Before: the override grants this administrator Read on the Value.
  ASSERT_THAT(read_attribute(session, mTestNodeId, AttributeId::Value), Good())
    << "the override must grant the administrator Read before the clear, or the contrast below is empty";

  EXPECT_EQ(write_role_permissions(session, mTestNodeId, {}).as_status(), Status::Good)
    << "an empty array clears the override rather than being refused";

  // After: no override, and the namespace default grants nothing - so the same Read is refused. This is
  // the fallback taking effect, which is the whole observable difference between clearing and rejecting.
  EXPECT_THAT(
    read_attribute(session, mTestNodeId, AttributeId::Value), HasStatus(Status::BadUserAccessDenied))
    << "with the override cleared the engaged-empty namespace default governs, and it grants nothing";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-052 - the owning namespace is what refuses a prospective policy
// ============================================================================

// Design section 8.2 step 4: the decision about whether a prospective policy is permitted belongs to the
// owning namespace, which is asked AFTER caller authorization has already succeeded and is handed no
// caller identity. A namespace that declines must have its exact StatusCode and ErrorDetail surfaced -
// not flattened to a generic refusal - and the former Attribute must be left untouched.
// @relation(AC-SVR-SECADMIN-052-NO-INOPERABLE-PERMISSIONS, scope=function)
TEST_F(RbacRpwDecliningNamespaceFixture, NamespaceValidatorRejectionSurfacesItsExactStatus)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "NsDeclines");

  const auto before = read_attribute(session, mTestNodeId, AttributeId::RolePermissions);
  ASSERT_THAT(before, Good());

  const auto status = write_role_permissions(session, mTestNodeId, admin_safe_proposed());
  EXPECT_EQ(status.as_status(), declineStatus)
    << "the namespace's own verdict must reach the caller, not a generic refusal";
  // The verdict is this namespace's, not the base implementation's: the standard Role model declines a
  // vendor-specific namespace with Bad_NotSupported, and accepts any valid proposal otherwise, so
  // neither of those is what arrived here.
  EXPECT_NE(status.as_status(), Status::BadNotSupported);
  EXPECT_NE(status.as_status(), Status::Good);
  // The accompanying ErrorDetail is deliberately NOT asserted: it is a server-side rich status, and a
  // wire response carries only the StatusCode unless the caller requests DiagnosticInfo. The design's
  // "exact StatusCode and ErrorDetail" describes the service result the stack produces, and the
  // StatusCode is the part of it a remote caller observes here.

  // Step 5 runs only after success, so a declined proposal leaves the stored Attribute as it was.
  const auto after = read_attribute(session, mTestNodeId, AttributeId::RolePermissions);
  EXPECT_THAT(after, Good());
  EXPECT_EQ(after.value().as<Array<RefStructure<Structure>>>().size(),
    before.value().as<Array<RefStructure<Structure>>>().size())
    << "a declined Write must not mutate the Attribute";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-053 - cache invalidation / immediate effect across Sessions
// server_security_role_permissions_write_cache_invalidation_integration
// ============================================================================

// @relation(AC-SVR-SECADMIN-053-CACHE-INVALIDATION, scope=function)
TEST_F(RbacRpwAdminFixture, WriteVisibleToOtherActiveSession)
{
  auto [channelA, sessionA] = open_session(MessageSecurityMode::SignAndEncrypt, "RpwWriterA");
  auto [channelB, sessionB] = open_session(MessageSecurityMode::SignAndEncrypt, "RpwReaderB");

  // Session A writes a distinguishable RolePermissions set (adds Anonymous Write).
  std::vector<RolePermissionType> updated{make_role_permission(security_admin_role_id(),
                                            {PermissionType::Bit::Browse,
                                              PermissionType::Bit::ReadRolePermissions,
                                              PermissionType::Bit::Read,
                                              PermissionType::Bit::Write,
                                              PermissionType::Bit::WriteRolePermissions}),
    make_role_permission(anonymous_role_id(),
      {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write})};
  ASSERT_EQ(write_role_permissions(sessionA, mTestNodeId, updated).as_status(), Status::Good);

  // Session B (separate active Session) immediately reads the new RolePermissions.
  auto value = read_attribute(sessionB, mTestNodeId, AttributeId::RolePermissions);
  ASSERT_THAT(value, Good());
  const auto& arr = value.value().as<Array<RefStructure<Structure>>>();
  bool anonymousHasWrite = false;
  for (size_t i = 0; i < arr.size(); ++i)
  {
    const auto* rp = dynamic_cast<const RolePermissionType*>(arr.payload()[i].get());
    if (rp && rp->role_id() == anonymous_role_id() && rp->permissions().test(PermissionType::Bit::Write))
      anonymousHasWrite = true;
  }
  EXPECT_TRUE(anonymousHasWrite) << "Second Session must observe the updated RolePermissions immediately";

  (void)sessionB.try_close_sync();
  (void)channelB.try_close_sync();
  (void)sessionA.try_close_sync();
  (void)channelA.try_close_sync();
}

// ============================================================================
// SVR-EVT-AUD-022 - successful Write emits AuditWriteUpdateEventType; a gated
// rejection emits nothing. server_audit_role_permissions_write_integration
// ============================================================================

// Covers SVR-EVT-AUD-015, SVR-AUDIT-019 (coverage-audit retag).
// @relation(AC-SVR-EVT-AUD-022-ROLEPERMISSIONS-WRITE-AUDIT, SVR-EVT-AUD-022, scope=function)
TEST_F(RbacRpwAuditFixture, SuccessfulWriteEmitsAuditWriteUpdate)
{
  AuditWriteRecorder recorder;
  mServer->set_event_listener(recorder.listener());  // synchronously arms has_event_interest()

  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AuditSuccess");
  ASSERT_EQ(write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(), Status::Good);

  EXPECT_EQ(recorder.wait_for_count(1), 1u)
    << "A successful RolePermissions Write must emit AuditWriteUpdateEventType (SVR-EVT-AUD-022)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-EVT-AUD-022-ROLEPERMISSIONS-WRITE-AUDIT, SVR-EVT-AUD-022, scope=function)
TEST_F(RbacRpwDecliningAuditFixture, RejectedWriteDoesNotEmitAuditWriteUpdate)
{
  AuditWriteRecorder recorder;
  mServer->set_event_listener(recorder.listener());

  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AuditReject");

  // The rejection is the owning namespace's verdict (design section 8.2 step 4). What matters to this row
  // is only that the Write was refused before step 5 mutated anything, whatever refused it.
  ASSERT_EQ(write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(), declineStatus);

  // Give the dispatch strand time to deliver any (erroneous) emission, then
  // assert none arrived. The rejection path never sets auditActive, so emit()
  // is not even called.
  EXPECT_EQ(recorder.wait_for_count(1, std::chrono::milliseconds{750}), 0u)
    << "A gated RolePermissions Write rejection must not emit AuditWriteUpdateEventType (SVR-EVT-AUD-022)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

}  // namespace

// ============================================================================
// Row: ServerConfig::auditingEnabled - the OFF case
//      (configuration coverage matrix section 12b - DEMOTED by the mutation spot-check).
//
// WHY THIS ROW EXISTS. The field was audited CONFIRMED on the strength of the two tests above, read as the
// ON and OFF halves of the gate. They are not: `SuccessfulWriteEmitsAuditWriteUpdate` and
// `RejectedWriteDoesNotEmitAuditWriteUpdate` BOTH run on `RbacRpwAuditFixture`, which sets the flag TRUE.
// The second tests the no-emit-on-rejection rule (SVR-EVT-AUD-022), not the flag. Forcing auditing on at
// every attribute-service site left all 12 tests in this file green.
//
// section 1 rule 5 wants the OFF case of a gate, and the failure it guards against is an OVER-firing one: a
// server that emits audit events after the operator disabled auditing is leaking a record of every write.
// ============================================================================

/// Auditing left at the base fixture's `false`, with an admin caller whose Writes succeed - so the only
/// reason no audit event appears is the flag.
class RbacRpwAuditDisabledFixture : public RbacRpwAdminFixture
{};

// DEFAULT for this fixture family is `false`, but the SHIPPED default matters less here than the pairing:
// `RbacRpwAuditFixture` runs the identical Write with the flag on and asserts exactly one event, so the two
// together bracket the gate.
TEST_F(RbacRpwAuditDisabledFixture, SuccessfulWriteEmitsNoAuditWhenAuditingDisabled)
{
  AuditWriteRecorder recorder;
  mServer->set_event_listener(recorder.listener());  // synchronously arms has_event_interest()

  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AuditDisabled");

  // The Write must SUCCEED. An audit-free rejection would prove nothing - that is exactly the confusion
  // that let the original CONFIRMED verdict stand.
  ASSERT_EQ(write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(), Status::Good)
    << "the Write must succeed, so that the absence of an audit event is attributable to the flag";

  EXPECT_EQ(recorder.wait_for_count(1, std::chrono::milliseconds{750}), 0u)
    << "with mAuditingEnabled=false a SUCCESSFUL Write must emit no AuditWriteUpdateEventType; the same "
       "Write under RbacRpwAuditFixture (flag on) emits exactly one";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Obligation closure - five ACCEPTANCE_CRITERION observables in this file's
// scope that carried no verification.
// ============================================================================

namespace
{

// The two sibling Properties Part 18 section 4.4 carves OUT of the
// not-directly-writable rule: they are plain Boolean configuration, not
// Method-mutated arrays, and the NS0 NodeSet gives them AccessLevel=3.
constexpr uint32_t operatorApplicationsExclude =
  static_cast<uint32_t>(VariableId::WellKnownRole_Operator_ApplicationsExclude);
constexpr uint32_t operatorEndpointsExclude =
  static_cast<uint32_t>(VariableId::WellKnownRole_Operator_EndpointsExclude);

/// Decode a Variant carrying a `RolePermissionType[]` (the wire form of the
/// RolePermissions Attribute, and of the OldValue / NewValue fields of the
/// Write audit event). Returns empty for a null or non-array Variant, which the
/// callers assert against before decoding.
std::vector<RolePermissionType> decode_role_permissions(const Variant& value)
{
  std::vector<RolePermissionType> out;
  if (value.empty() || !value.is_array())
    return out;
  const auto& arr = value.as<Array<RefStructure<Structure>>>();
  for (size_t i = 0; i < arr.size(); ++i)
  {
    if (const auto* rp = dynamic_cast<const RolePermissionType*>(arr.payload()[i].get()))
      out.push_back(*rp);
  }
  return out;
}

/// Locate the entry for `roleId` in a decoded permission set.
const RolePermissionType* find_role_entry(const std::vector<RolePermissionType>& perms, const NodeId& roleId)
{
  for (const auto& entry : perms)
  {
    if (entry.role_id() == roleId)
      return &entry;
  }
  return nullptr;
}

/// Recorder that keeps the emitted `AuditWriteUpdateEventPayload`s themselves
/// (cloned on the dispatch strand) rather than only counting them, so the
/// OldValue / NewValue / AttributeId fields can be asserted. Same installation
/// contract as `AuditWriteRecorder`: `set_event_listener` arms
/// `has_event_interest()` synchronously.
struct AuditWritePayloadRecorder
{
  /// A snapshot of the three fields the RolePermissions-Write obligation is about.
  struct Captured
  {
    bool present{false};
    uint32_t attributeId{};
    Variant oldValue;
    Variant newValue;
  };

  std::function<void(const BaseEvent&)> listener()
  {
    return [this](const BaseEvent& event)
    {
      const auto* payload = dynamic_cast<const AuditWriteUpdateEventPayload*>(&event);
      if (payload == nullptr)
        return;
      std::lock_guard lock(mutex);
      events.push_back(payload->clone());
      cv.notify_all();
    };
  }

  size_t wait_for_count(size_t expected, std::chrono::milliseconds timeout = std::chrono::seconds{2})
  {
    std::unique_lock lock(mutex);
    cv.wait_for(lock, timeout, [&] { return events.size() >= expected; });
    return events.size();
  }

  Captured first() const
  {
    std::lock_guard lock(mutex);
    Captured out;
    if (events.empty())
      return out;
    const auto* payload = dynamic_cast<const AuditWriteUpdateEventPayload*>(events.front().get());
    if (payload == nullptr)
      return out;
    out.present = true;
    out.attributeId = payload->attributeId;
    out.oldValue = payload->oldValue;
    out.newValue = payload->newValue;
    return out;
  }

  mutable std::mutex mutex;
  std::condition_variable cv;
  std::vector<std::unique_ptr<BaseEvent>> events;
};

/// The test Variable declares `RolePermissions` in its WriteMask, so
/// `UserWriteMask` can advertise the combination of Node writability and the
/// current identity's permission bit 3.
class RbacRpwWriteMaskFixture : public RbacRpwAdminFixture
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    RbacRpwBase::customize_address_space(addressSpace);
    auto node = addressSpace.find_node_sync(mTestNodeId);
    node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  }
};

}  // namespace

// Part 18 section 4.4: the three Method-mutated Role Properties are configured through
// AddIdentity / AddApplication / AddEndpoint so that the change is audited and its
// criteria validated; a direct Attribute Write would bypass both. The carve-out is
// exactly `ApplicationsExclude` / `EndpointsExclude`, which are plain Booleans and
// remain writable. A plausible implementation clears CurrentWrite on the whole Role
// Object surface - the Excludes included - and then the only way to invert an
// Applications/Endpoints list is a Method that has no such argument. "Writable" means the
// written value is read back, not only that the Write answers Good: the Exclude value source
// reads from the Role configuration the Write updates.
// @verifies AC-SVR-SECADMIN-026-ROLE-PROPERTIES-NOT-WRITABLE
TEST_F(RbacRpwAdminFixture, RolePropertyDirectWritesRefusedButExcludeSiblingsRemainWritable)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RolePropExcl");

  // (a) All three Method-mutated Properties advertise CurrentWrite FALSE and refuse a
  // direct Write. The refusal is downstream of authorization: this caller is
  // SecurityAdmin, which the NS0 RolePermissions on these Nodes grant Write. Both halves
  // are asserted here because the obligation is the conjunction: a Property that
  // advertises the bit but accepts the Write, or refuses the Write while advertising it
  // writable, satisfies neither Part 18 section 4.4 nor a client that reads before writing.
  for (uint32_t propId : {operatorIdentities, operatorApplications, operatorEndpoints})
  {
    auto accessLevel = read_attribute(session, NodeId{0, propId}, AttributeId::AccessLevel);
    EXPECT_THAT(accessLevel, Good()) << "AccessLevel read on role property " << propId;
    const auto* raw = accessLevel.value().try_as<uint8_t>();
    ASSERT_NE(raw, nullptr) << "AccessLevel value not a Byte for property " << propId;
    EXPECT_FALSE(AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentWrite))
      << "role property " << propId << " must advertise CurrentWrite FALSE";

    auto resp = session.attributes().write_sync(
      WriteRequestBuilder{}.write(NodeId{0, propId}, Variant{Array<RefStructure<Structure>>{}}).build());
    ASSERT_FALSE(resp.results().empty()) << "Write on role property " << propId << " returned no result";
    EXPECT_EQ(resp.results()[0].as_status(), Status::BadNotWritable)
      << "role property " << propId << " must refuse a direct Attribute Write";
  }

  // (b) The two Exclude siblings are the spec carve-out: CurrentWrite TRUE ...
  for (uint32_t propId : {operatorApplicationsExclude, operatorEndpointsExclude})
  {
    auto accessLevel = read_attribute(session, NodeId{0, propId}, AttributeId::AccessLevel);
    EXPECT_THAT(accessLevel, Good()) << "AccessLevel read on exclude property " << propId;
    const auto* raw = accessLevel.value().try_as<uint8_t>();
    ASSERT_NE(raw, nullptr) << "AccessLevel value not a Byte for exclude property " << propId;
    EXPECT_TRUE(AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentWrite))
      << "exclude property " << propId << " must have CurrentWrite TRUE (Part 18 section 4.4 carve-out)";
  }

  // ... and a real Write of the Boolean is accepted and takes effect. The role-set
  // population wrote `false` at startup, so `true` is a change.
  for (uint32_t propId : {operatorApplicationsExclude, operatorEndpointsExclude})
  {
    auto resp =
      session.attributes().write_sync(WriteRequestBuilder{}.write(NodeId{0, propId}, Variant{true}).build());
    ASSERT_FALSE(resp.results().empty()) << "Write on exclude property " << propId << " returned no result";
    EXPECT_EQ(resp.results()[0].as_status(), Status::Good)
      << "exclude property " << propId << " must remain writable with the Write Service";

    auto readBack = read_attribute(session, NodeId{0, propId}, AttributeId::Value);
    EXPECT_THAT(readBack, Good()) << "read-back of exclude property " << propId;
    const auto* flag = readBack.value().try_as<bool>();
    ASSERT_NE(flag, nullptr) << "exclude property " << propId << " value is not a Boolean";
    EXPECT_TRUE(*flag) << "the accepted Write of exclude property " << propId << " must take effect";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 3 section 5.2.9: where the Server allows Permissions to be changed "these values
// shall be writeable" - the writability must be discoverable, not learned by having a
// Write refused. `UserWriteMask` is the per-Session projection of WriteMask and is the
// only Attribute that can carry that answer. A plausible implementation projects
// UserWriteMask from the Node's Write permission alone and never consults the
// RolePermissions-Write gate, so it advertises a writable RolePermissions Attribute on
// a server that will refuse every such Write.
// @relation(AC-SVR-SECADMIN-048-ROLEPERMISSIONS-WRITABLE-WHEN-ALLOWED, scope=function)
TEST_F(RbacRpwWriteMaskFixture, RolePermissionsAdvertisedWritableWhereChangesArePermitted)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RpwMaskOn");

  auto mask = read_attribute(session, mTestNodeId, AttributeId::UserWriteMask);
  ASSERT_THAT(mask, Good()) << "UserWriteMask must be readable by the administrator";
  const auto* raw = mask.value().try_as<uint32_t>();
  ASSERT_NE(raw, nullptr) << "UserWriteMask value is not a UInt32";
  EXPECT_TRUE(AttributeWriteMask{*raw}.test(AttributeWriteMask::Bit::RolePermissions))
    << "on a server that permits RolePermissions changes the UserWriteMask RolePermissions bit must be set";

  // The advertised bit must predict the outcome.
  EXPECT_EQ(write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(), Status::Good)
    << "the Write must succeed exactly where the bit is set";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-SECADMIN-048-ROLEPERMISSIONS-WRITABLE-WHEN-ALLOWED, scope=function)
// @relation(AC-SVR-SECADMIN-049-ROLEPERMISSIONS-NEEDS-NAMESPACE-SUPPORT, scope=function)
TEST_F(RbacRpwAdminFixture, RolePermissionsIsNotAdvertisedOrWritableWithoutTheNodeCapability)
{
  auto node = mServer->address_space().find_node_sync(mTestNodeId);
  node.set_write_mask(AttributeWriteMask{});
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RpwMaskOff");

  auto mask = read_attribute(session, mTestNodeId, AttributeId::UserWriteMask);
  ASSERT_THAT(mask, Good());
  const auto* raw = mask.value().try_as<uint32_t>();
  ASSERT_NE(raw, nullptr);
  EXPECT_FALSE(AttributeWriteMask{*raw}.test(AttributeWriteMask::Bit::RolePermissions));
  EXPECT_EQ(
    write_role_permissions(session, mTestNodeId, admin_safe_proposed()).as_status(), Status::BadNotWritable);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.2.3: "If a Role is removed all Permissions associated with the Role
// are deleted as well." A per-Session authorization cache is the standard optimisation
// and it is what makes revocation ineffective: the clause admits some lag, not a cache
// that never re-reads. The failure is invisible until someone revokes access from a
// client that is already connected - which is when revocation is being used.
// @verifies AC-SVR-SECADMIN-053-CACHE-INVALIDATION
TEST_F(RbacRpwAdminFixture, RevokedReadPermissionAppliesToTheAlreadyEstablishedSession)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RpwRevoke");

  // Baseline on this session: the Node is readable before the revocation.
  auto before = read_attribute(session, mTestNodeId, AttributeId::Value);
  ASSERT_THAT(before, Good()) << "the established session must be able to read the Node to begin with";

  // Remove Read for the session's Role. WriteRolePermissions is retained so the
  // inoperable guard passes and the change is reversible; Write is retained so the
  // session's continued liveness is observable below.
  std::vector<RolePermissionType> revoked{make_role_permission(security_admin_role_id(),
    {PermissionType::Bit::Browse, PermissionType::Bit::Write, PermissionType::Bit::WriteRolePermissions})};
  ASSERT_EQ(write_role_permissions(session, mTestNodeId, revoked).as_status(), Status::Good)
    << "the revoking Write itself must be accepted";

  // The same, still-active session must now be refused.
  auto after = read_attribute(session, mTestNodeId, AttributeId::Value);
  EXPECT_THAT(after, HasStatus(Status::BadUserAccessDenied))
    << "the permission change must apply to the established session, not only to sessions created after it";

  // Control: the session is still alive and still authorized for what it kept, so the
  // refusal above is the revocation and not a dead or wholly de-authorized session.
  auto writeResp =
    session.attributes().write_sync(WriteRequestBuilder{}.write(mTestNodeId, Variant{int32_t{7}}).build());
  ASSERT_FALSE(writeResp.results().empty());
  EXPECT_EQ(writeResp.results()[0].as_status(), Status::Good)
    << "the session must retain the Write permission it was not stripped of";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 4 section 6.5.9 with Part 18: this is the Write whose audit record matters most,
// because it changes who may do what - and the record is only useful if it says what the
// permissions were and what they became. A plausible implementation captures OldValue
// only on the Value-Attribute path (where a read-back is already being done for
// sampling) and emits the RolePermissions audit event with an empty OldValue, leaving
// the record unable to answer "what was revoked".
// @relation(AC-SVR-EVT-AUD-022-ROLEPERMISSIONS-WRITE-AUDIT, scope=function)
TEST_F(RbacRpwAuditFixture, RolePermissionsWriteAuditCarriesOldAndNewPermissionSets)
{
  AuditWritePayloadRecorder recorder;
  mServer->set_event_listener(recorder.listener());  // synchronously arms has_event_interest()

  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AuditOldNew");

  // A set that differs from the Node's initial permissions in one observable way:
  // Anonymous gains Write. Old and new are therefore distinguishable.
  std::vector<RolePermissionType> updated{make_role_permission(security_admin_role_id(),
                                            {PermissionType::Bit::Browse,
                                              PermissionType::Bit::ReadRolePermissions,
                                              PermissionType::Bit::Read,
                                              PermissionType::Bit::Write,
                                              PermissionType::Bit::WriteRolePermissions}),
    make_role_permission(anonymous_role_id(),
      {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write})};
  ASSERT_EQ(write_role_permissions(session, mTestNodeId, updated).as_status(), Status::Good);

  ASSERT_EQ(recorder.wait_for_count(1), 1u)
    << "a successful RolePermissions Write must raise AuditWriteUpdateEventType";
  auto captured = recorder.first();
  ASSERT_TRUE(captured.present) << "the recorded event is not an AuditWriteUpdateEventPayload";
  EXPECT_EQ(captured.attributeId, static_cast<uint32_t>(AttributeId::RolePermissions))
    << "the audit record must name the RolePermissions Attribute";

  // NewValue carries the permission set that was applied.
  ASSERT_TRUE(captured.newValue.is_array()) << "NewValue must carry the new permission set";
  auto newPerms = decode_role_permissions(captured.newValue);
  ASSERT_FALSE(newPerms.empty()) << "NewValue did not decode to any RolePermissionType entries";
  const auto* newAnonymous = find_role_entry(newPerms, anonymous_role_id());
  ASSERT_NE(newAnonymous, nullptr) << "NewValue must contain the Anonymous Role entry that was written";
  EXPECT_TRUE(newAnonymous->permissions().test(PermissionType::Bit::Write))
    << "NewValue must reflect the granted Write permission";
  const auto* newAdmin = find_role_entry(newPerms, security_admin_role_id());
  ASSERT_NE(newAdmin, nullptr) << "NewValue must contain the SecurityAdmin Role entry that was written";
  EXPECT_TRUE(newAdmin->permissions().test(PermissionType::Bit::WriteRolePermissions))
    << "NewValue must reflect the retained WriteRolePermissions permission";

  // OldValue carries the permission set that was replaced - the half that says what
  // the Write took away.
  ASSERT_TRUE(captured.oldValue.is_array())
    << "OldValue must carry the permission set the Write replaced; without it the audit record cannot "
       "say what was changed";
  auto oldPerms = decode_role_permissions(captured.oldValue);
  ASSERT_FALSE(oldPerms.empty()) << "OldValue did not decode to any RolePermissionType entries";
  const auto* oldAnonymous = find_role_entry(oldPerms, anonymous_role_id());
  ASSERT_NE(oldAnonymous, nullptr) << "OldValue must contain the Anonymous Role entry as it stood before";
  EXPECT_FALSE(oldAnonymous->permissions().test(PermissionType::Bit::Write))
    << "OldValue must be the pre-Write set - Anonymous did not hold Write before this Write";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

namespace
{

/// The Part 18 section 4.4 Property surface of a single Role Object. `0` marks a
/// Property the UA-1.05.06 standard NodeSet does not ship on that Role: Anonymous,
/// AuthenticatedUser and TrustedApplication carry `Identities` alone, the other six
/// carry the full set. Every entry that is present is subject to the same invariant,
/// which is what makes the table - rather than one representative Role - the honest
/// subject of the obligation.
struct RoleObjectPropertySet
{
  const char* roleName;
  uint32_t identities;
  uint32_t applications;
  uint32_t endpoints;
  uint32_t applicationsExclude;
  uint32_t endpointsExclude;
};

constexpr uint32_t role_property(VariableId id)
{
  return static_cast<uint32_t>(id);
}

constexpr RoleObjectPropertySet roleObjectProperties[] = {
  {"Anonymous", role_property(VariableId::WellKnownRole_Anonymous_Identities), 0, 0, 0, 0},
  {"AuthenticatedUser", role_property(VariableId::WellKnownRole_AuthenticatedUser_Identities), 0, 0, 0, 0},
  {"TrustedApplication", role_property(VariableId::WellKnownRole_TrustedApplication_Identities), 0, 0, 0, 0},
  {"Observer",
    role_property(VariableId::WellKnownRole_Observer_Identities),
    role_property(VariableId::WellKnownRole_Observer_Applications),
    role_property(VariableId::WellKnownRole_Observer_Endpoints),
    role_property(VariableId::WellKnownRole_Observer_ApplicationsExclude),
    role_property(VariableId::WellKnownRole_Observer_EndpointsExclude)},
  {"Operator",
    role_property(VariableId::WellKnownRole_Operator_Identities),
    role_property(VariableId::WellKnownRole_Operator_Applications),
    role_property(VariableId::WellKnownRole_Operator_Endpoints),
    role_property(VariableId::WellKnownRole_Operator_ApplicationsExclude),
    role_property(VariableId::WellKnownRole_Operator_EndpointsExclude)},
  {"Engineer",
    role_property(VariableId::WellKnownRole_Engineer_Identities),
    role_property(VariableId::WellKnownRole_Engineer_Applications),
    role_property(VariableId::WellKnownRole_Engineer_Endpoints),
    role_property(VariableId::WellKnownRole_Engineer_ApplicationsExclude),
    role_property(VariableId::WellKnownRole_Engineer_EndpointsExclude)},
  {"Supervisor",
    role_property(VariableId::WellKnownRole_Supervisor_Identities),
    role_property(VariableId::WellKnownRole_Supervisor_Applications),
    role_property(VariableId::WellKnownRole_Supervisor_Endpoints),
    role_property(VariableId::WellKnownRole_Supervisor_ApplicationsExclude),
    role_property(VariableId::WellKnownRole_Supervisor_EndpointsExclude)},
  {"ConfigureAdmin",
    role_property(VariableId::WellKnownRole_ConfigureAdmin_Identities),
    role_property(VariableId::WellKnownRole_ConfigureAdmin_Applications),
    role_property(VariableId::WellKnownRole_ConfigureAdmin_Endpoints),
    role_property(VariableId::WellKnownRole_ConfigureAdmin_ApplicationsExclude),
    role_property(VariableId::WellKnownRole_ConfigureAdmin_EndpointsExclude)},
  {"SecurityAdmin",
    role_property(VariableId::WellKnownRole_SecurityAdmin_Identities),
    role_property(VariableId::WellKnownRole_SecurityAdmin_Applications),
    role_property(VariableId::WellKnownRole_SecurityAdmin_Endpoints),
    role_property(VariableId::WellKnownRole_SecurityAdmin_ApplicationsExclude),
    role_property(VariableId::WellKnownRole_SecurityAdmin_EndpointsExclude)},
};

/// Compare two decoded permission sets. Wire order is not significant, so this is
/// membership by Role plus equality of the permission bits of every entry; a set
/// that gained or lost an entry differs by size. Used to hold an audit record
/// against the address space's own answer rather than against hard-coded bits.
bool permission_sets_match(
  const std::vector<RolePermissionType>& lhs, const std::vector<RolePermissionType>& rhs)
{
  if (lhs.size() != rhs.size())
    return false;
  for (const auto& entry : lhs)
  {
    const auto* other = find_role_entry(rhs, entry.role_id());
    if (other == nullptr)
      return false;
    if (!(other->permissions() == entry.permissions()))
      return false;
  }
  return true;
}

}  // namespace

// Part 18 section 4.4: the invariant is stated over EVERY Role Object, not over a
// representative one - Identities / Applications / Endpoints are mutated through
// AddIdentity / AddApplication / AddEndpoint so the change is audited and validated,
// while ApplicationsExclude / EndpointsExclude are plain configuration Booleans and
// are the carve-out. A plausible implementation clears CurrentWrite on the Roles it
// walks - the ones named in a seeding table, or the ones it installs management
// handlers on - and leaves the rest of the RoleSet exactly as some other code path
// left it, so one unseeded or specially-cased Role Object stays directly writable and
// the whole audited-configuration story has a hole in it. "Remain writable" means the
// written value is read back, so the read-back is asserted and must not be dropped.
// @verifies AC-SVR-SECADMIN-026-ROLE-PROPERTIES-NOT-WRITABLE
TEST_F(RbacRpwAdminFixture, EveryRoleObjectRefusesDirectPropertyWritesAndKeepsExcludesWritable)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RolePropAllRoles");

  // (a) Every Method-mutated Property on every Role Object: the bit is FALSE and the
  // direct Write is refused. Both conjuncts, because a Property that advertises the
  // bit but accepts the Write and one that refuses the Write while advertising itself
  // writable each break a different client. The refusal is downstream of
  // authorization - this caller is SecurityAdmin, which the NS0 RolePermissions on
  // these Nodes grant Write.
  size_t methodMutatedChecked = 0;
  for (const auto& role : roleObjectProperties)
  {
    for (uint32_t propId : {role.identities, role.applications, role.endpoints})
    {
      if (propId == 0)
        continue;
      ++methodMutatedChecked;

      auto accessLevel = read_attribute(session, NodeId{0, propId}, AttributeId::AccessLevel);
      EXPECT_THAT(accessLevel, Good()) << "AccessLevel read on " << role.roleName << " property " << propId;
      const auto* raw = accessLevel.value().try_as<uint8_t>();
      ASSERT_NE(raw, nullptr) << "AccessLevel of " << role.roleName << " property " << propId
                              << " is not a Byte";
      EXPECT_FALSE(AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentWrite))
        << role.roleName << " property " << propId << " must advertise CurrentWrite FALSE";

      auto resp = session.attributes().write_sync(
        WriteRequestBuilder{}.write(NodeId{0, propId}, Variant{Array<RefStructure<Structure>>{}}).build());
      ASSERT_FALSE(resp.results().empty())
        << "Write on " << role.roleName << " property " << propId << " returned no result";
      EXPECT_EQ(resp.results()[0].as_status(), Status::BadNotWritable)
        << role.roleName << " property " << propId << " must refuse a direct Attribute Write";
    }
  }
  ASSERT_GT(methodMutatedChecked, 0u)
    << "no Method-mutated Role Property was exercised - the table is empty and the loop asserted nothing";

  // (b) The Exclude siblings on every Role Object that carries them are the carve-out:
  // the bit is TRUE, the Write is accepted, and the value changes. The role-set
  // population wrote `false` at start-up, so `true` is a real change.
  size_t excludesChecked = 0;
  for (const auto& role : roleObjectProperties)
  {
    for (uint32_t propId : {role.applicationsExclude, role.endpointsExclude})
    {
      if (propId == 0)
        continue;
      ++excludesChecked;

      auto accessLevel = read_attribute(session, NodeId{0, propId}, AttributeId::AccessLevel);
      EXPECT_THAT(accessLevel, Good())
        << "AccessLevel read on " << role.roleName << " exclude property " << propId;
      const auto* raw = accessLevel.value().try_as<uint8_t>();
      ASSERT_NE(raw, nullptr) << "AccessLevel of " << role.roleName << " exclude property " << propId
                              << " is not a Byte";
      EXPECT_TRUE(AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentWrite))
        << role.roleName << " exclude property " << propId
        << " must advertise CurrentWrite TRUE (Part 18 section 4.4 carve-out)";

      auto resp = session.attributes().write_sync(
        WriteRequestBuilder{}.write(NodeId{0, propId}, Variant{true}).build());
      ASSERT_FALSE(resp.results().empty())
        << "Write on " << role.roleName << " exclude property " << propId << " returned no result";
      EXPECT_EQ(resp.results()[0].as_status(), Status::Good)
        << role.roleName << " exclude property " << propId << " must remain writable";

      auto readBack = read_attribute(session, NodeId{0, propId}, AttributeId::Value);
      EXPECT_THAT(readBack, Good()) << "read-back of " << role.roleName << " exclude property " << propId;
      const auto* flag = readBack.value().try_as<bool>();
      ASSERT_NE(flag, nullptr) << role.roleName << " exclude property " << propId
                               << " value is not a Boolean";
      EXPECT_TRUE(*flag) << "the accepted Write of " << role.roleName << " exclude property " << propId
                         << " must take effect - a Write that returns Good and leaves the value alone is "
                            "accepted-and-discarded, not writable";
    }
  }
  ASSERT_GT(excludesChecked, 0u)
    << "no Exclude Property was exercised - the carve-out half of the obligation asserted nothing";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 4 section 6.5.9 with Part 18: the audit record of a RolePermissions Write is
// only useful if OldValue and NewValue are the permission sets that actually stood
// before and after it - an investigator reads the record to answer "who could do what,
// and what changed". This holds the record against the server's own answer: the
// Attribute is read immediately before and immediately after the Write, and the two
// event fields must equal those two reads. A plausible implementation captures the
// permission set once, after the mutation has been applied, and stamps it into both
// fields - or captures OldValue only on the Value-Attribute path, where a read-back is
// already being done for sampling, and leaves it empty here. Either way the record
// says a Write happened but not what it took away, and the revocation this Write
// performs (Anonymous loses Read) becomes unauditable.
// @relation(AC-SVR-EVT-AUD-022-ROLEPERMISSIONS-WRITE-AUDIT, scope=function)
TEST_F(RbacRpwAuditFixture, RolePermissionsWriteAuditRecordMatchesTheAttributeBeforeAndAfterTheWrite)
{
  AuditWritePayloadRecorder recorder;
  mServer->set_event_listener(recorder.listener());  // synchronously arms has_event_interest()

  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AuditGroundTruth");

  // Ground truth before: what the Attribute actually holds.
  auto beforeRead = read_attribute(session, mTestNodeId, AttributeId::RolePermissions);
  ASSERT_THAT(beforeRead, Good()) << "the administrator must be able to read the pre-Write permission set";
  auto beforeSet = decode_role_permissions(beforeRead.value());
  ASSERT_FALSE(beforeSet.empty()) << "the Node must carry a permission set before the Write";

  // A revocation: Anonymous keeps Browse and loses Read. SecurityAdmin retains
  // WriteRolePermissions so the inoperable guard passes and the Write is accepted.
  std::vector<RolePermissionType> updated{make_role_permission(security_admin_role_id(),
                                            {PermissionType::Bit::Browse,
                                              PermissionType::Bit::ReadRolePermissions,
                                              PermissionType::Bit::Read,
                                              PermissionType::Bit::Write,
                                              PermissionType::Bit::WriteRolePermissions}),
    make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse})};
  ASSERT_EQ(write_role_permissions(session, mTestNodeId, updated).as_status(), Status::Good)
    << "the Write must be accepted, otherwise there is no audit record to judge";

  // Ground truth after.
  auto afterRead = read_attribute(session, mTestNodeId, AttributeId::RolePermissions);
  ASSERT_THAT(afterRead, Good()) << "the administrator must be able to read the post-Write permission set";
  auto afterSet = decode_role_permissions(afterRead.value());
  ASSERT_FALSE(afterSet.empty()) << "the Node must carry a permission set after the Write";
  ASSERT_FALSE(permission_sets_match(beforeSet, afterSet))
    << "the Write must actually change the permission set - if before and after were equal the OldValue "
       "and NewValue assertions below could not tell the two apart";

  ASSERT_EQ(recorder.wait_for_count(1), 1u)
    << "a successful RolePermissions Write must raise AuditWriteUpdateEventType (or a subtype)";
  auto captured = recorder.first();
  ASSERT_TRUE(captured.present) << "the recorded event is not an AuditWriteUpdateEventPayload";
  EXPECT_EQ(captured.attributeId, static_cast<uint32_t>(AttributeId::RolePermissions))
    << "the audit record must name the RolePermissions Attribute";

  // NewValue is the set the Attribute now holds.
  ASSERT_TRUE(captured.newValue.is_array()) << "NewValue must carry the permission set the Write applied";
  auto auditedNew = decode_role_permissions(captured.newValue);
  ASSERT_FALSE(auditedNew.empty()) << "NewValue did not decode to any RolePermissionType entries";
  EXPECT_TRUE(permission_sets_match(auditedNew, afterSet))
    << "NewValue must equal the permission set the Node holds after the Write";

  // OldValue is the set the Attribute held before - the half that says what was taken
  // away, and the reason this Write is audited at all.
  ASSERT_TRUE(captured.oldValue.is_array())
    << "OldValue must carry the permission set the Write replaced; without it the audit record cannot say "
       "what was revoked";
  auto auditedOld = decode_role_permissions(captured.oldValue);
  ASSERT_FALSE(auditedOld.empty()) << "OldValue did not decode to any RolePermissionType entries";
  EXPECT_TRUE(permission_sets_match(auditedOld, beforeSet))
    << "OldValue must equal the permission set the Node held before the Write, not the one it holds now";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
