// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// CTT-mirror integration tests for the Step 6 / Phase P4 NamespaceMetadata
/// default-permissions surface (Part 18 Role-Based Security; Part 3 section 5.2.9):
/// SVR-SECADMIN-046 (DefaultRolePermissions Property exposed), 047 (P4 - admin-
/// only Read of that Property), 054 (DefaultUserRolePermissions per-Session
/// view), 055 (per-Node UserRolePermissions projection), 057 (UserRolePermissions
/// not writable), 058 (9 well-known Roles materialised).
///
/// These stand up a full Part-18-wired server and exercise the surfaces over the
/// wire. Falsifiability: the admin-only Read is pinned with BOTH an admin success
/// AND an Anonymous denial; the per-Session filter is pinned by comparing what an
/// Anonymous session sees (only the Anonymous entry) against what a SecurityAdmin
/// session sees (its own roles) - a no-op filter would fail both.
///
/// SECADMIN-056 (vendor-specific omission) is covered at the unit level
/// (`default_role_permissions_property_tests.cpp:NamespaceMetadataPopulationTest`):
/// the SDK pre-wires NS0's delegate during `wire_authorizer`, so a host cannot
/// mark NS0 vendor-specific through the post-create `customize_address_space`
/// interface; the routine's deletion branch is pinned directly instead.

#include <gtest/gtest.h>

#include "helpers/role_based_security_fixture.h"

#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_localized_text.h"
#include "ua_namespace.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_status.h"
#include "ua_timestamps_to_return.h"
#include "ua_utc_time.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

constexpr uint32_t defaultRolePermissions =
  static_cast<uint32_t>(VariableId::OPCUANamespaceMetadata_DefaultRolePermissions);
constexpr uint32_t defaultUserRolePermissions =
  static_cast<uint32_t>(VariableId::OPCUANamespaceMetadata_DefaultUserRolePermissions);

NodeId security_admin_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)};
}

NodeId anonymous_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)};
}

/// Read an attribute and decode its Value as a `RolePermissionType` array.
/// Returns the per-operation status + the decoded entries.
struct RolePermsRead
{
  StatusCode status;
  std::vector<RolePermissionType> entries;
};

RolePermsRead read_role_permissions(Session& session, const NodeId& node, AttributeId attr)
{
  auto resp = session.attributes().read_sync(ReadRequestBuilder{}.read(node).attribute(attr).build());
  RolePermsRead out;
  if (!resp.response_header().service_result().is_good() || resp.results().empty())
  {
    out.status = resp.response_header().service_result().is_good() ? StatusCode{Status::BadInternalError}
                                                                   : resp.response_header().service_result();
    return out;
  }
  const auto& result = resp.results()[0];
  out.status = result.status().value_or(StatusCode{Status::Good});
  if (out.status.is_good() && result.value().is_array_of_structure())
  {
    const auto& arr = result.value().as<Array<RefStructure<Structure>>>();
    for (size_t i = 0; i < arr.size(); ++i)
    {
      if (const auto* rp = dynamic_cast<const RolePermissionType*>(arr.payload()[i].get()))
      {
        out.entries.push_back(*rp);
      }
    }
  }
  return out;
}

bool contains_role(const std::vector<RolePermissionType>& entries, const NodeId& roleId)
{
  for (const auto& e : entries)
  {
    if (e.role_id() == roleId)
      return true;
  }
  return false;
}

/// Locate a forward reference by the BrowseName of its target.
const ReferenceDescription* find_reference_named(const BrowseResult& result, std::string_view browseName)
{
  for (const auto& ref : result.references())
  {
    if (std::string_view{ref.browse_name().name()} == browseName)
      return &ref;
  }
  return nullptr;
}

/// Locate a forward reference by target NodeId.
const ReferenceDescription* find_reference_to(const BrowseResult& result, const NodeId& target)
{
  for (const auto& ref : result.references())
  {
    if (ref.node_id().node_id() == target)
      return &ref;
  }
  return nullptr;
}

/// Create an Int32 Variable that carries **no** `RolePermissions` override, so
/// Namespace permission evaluation must fall back to `DefaultRolePermissions`
/// when it derives the Node's `UserRolePermissions`. Deliberately not
/// `create_role_gated_variable`, which always stamps an override onto the Node
/// (an empty override is still an override, and would not exercise the
/// fallback leg of the chain).
NodeId create_variable_without_role_permissions(
  AddressSpace& addressSpace, const NodeId& nodeId, const std::string& browseName)
{
  auto varNode = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
  auto variable = varNode.as<VariableAccessor>();
  if (!variable.has_value())
  {
    ADD_FAILURE() << "create_node_sync did not return a VariableAccessor for " << browseName;
    return nodeId;
  }
  variable->set_browse_name(QualifiedName{nodeId.namespace_index(), browseName});
  variable->set_display_name(LocalizedText{"", browseName});
  variable->set_data_type(NodeId{DataTypeId::Int32});
  variable->write_value_sync(int32_t{0});
  variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});

  auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
  objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, nodeId);
  return nodeId;
}

/// Base: a per-test namespace with a role-gated Variable carrying an explicit
/// RolePermissions override (Anonymous Browse+Read, SecurityAdmin Browse+Read+Write)
/// for the per-Node UserRolePermissions mirrors.
class RbacDefaultPermsBase : public ComplianceRoleBasedSecurity
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    mTestNsIndex = install_test_namespace(addressSpace, "urn:test:default-permissions");
    mTestNodeId = NodeId{mTestNsIndex, 70001};
    create_role_gated_variable(addressSpace,
      mTestNodeId,
      "UrpTarget",
      {make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read}),
        make_role_permission(security_admin_role_id(),
          {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write})});
  }

  uint16_t mTestNsIndex{0};
  NodeId mTestNodeId;
};

/// SecurityAdmin session (UserName "secadmin").
class RbacDefaultPermsAdminFixture : public RbacDefaultPermsBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "secadmin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "secadmin", std::unordered_map<std::string, std::string>{});
  }
};

/// Non-admin session: default Anonymous authenticator.
class RbacDefaultPermsAnonFixture : public RbacDefaultPermsBase
{};

/// SECADMIN-055: a namespace that *does* publish `DefaultRolePermissions`
/// (Anonymous: Browse only) plus two Variables in it - one carrying an explicit
/// per-Node override that adds Read, one carrying no override at all. The
/// contrast between the two `UserRolePermissions` Reads is what distinguishes
/// "derived from the override" from "derived from the namespace default"; with
/// only one Node an implementation that always returned the namespace default
/// would be indistinguishable from a correct one.
class RbacUrpOverrideFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    auto testNs =
      default_ns::Namespace::create(std::string{"urn:test:urp-override"}, mServerThreadPool.executor());
    testNs->set_namespace_defaults(std::vector<RolePermissionType>{make_role_permission(
                                     anonymous_role_id(), {PermissionType::Bit::Browse})},
      std::nullopt);
    mTestNsIndex = addressSpace.add_namespace_sync(testNs);

    mOverriddenNodeId = NodeId{mTestNsIndex, 70201};
    mInheritingNodeId = NodeId{mTestNsIndex, 70202};

    create_role_gated_variable(addressSpace,
      mOverriddenNodeId,
      "UrpOverridden",
      {make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
    create_variable_without_role_permissions(addressSpace, mInheritingNodeId, "UrpInheriting");
  }

  uint16_t mTestNsIndex{0};
  NodeId mOverriddenNodeId;
  NodeId mInheritingNodeId;
};

/// SECADMIN-057: SecurityAdmin session with the per-Node `RolePermissions`
/// Write gate fully opened (server master flag + namespace consent), so the
/// "`RolePermissions` on the same Node remains writable" half of the
/// obligation is actually reachable rather than blocked by an unrelated gate.
class RbacUrpWritabilityFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "secadmin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "secadmin", std::unordered_map<std::string, std::string>{});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    mTestNsIndex = install_test_namespace(addressSpace, "urn:test:urp-writability");
    mTestNodeId = NodeId{mTestNsIndex, 70301};
    create_role_gated_variable(addressSpace, mTestNodeId, "UrpWriteTarget", admin_writable_permissions());
    auto node = addressSpace.find_node_sync(mTestNodeId);
    node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  }

  /// SecurityAdmin keeps `WriteRolePermissions` in both the installed and the
  /// proposed set, so the self-lock / inoperable guards on the
  /// `RolePermissions` Write path stay clear and the only thing under test is
  /// the Attribute's writability.
  static std::vector<RolePermissionType> admin_writable_permissions()
  {
    return {make_role_permission(security_admin_role_id(),
              {PermissionType::Bit::Browse,
                PermissionType::Bit::Read,
                PermissionType::Bit::Write,
                PermissionType::Bit::WriteRolePermissions}),
      make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  }

  uint16_t mTestNsIndex{0};
  NodeId mTestNodeId;
};

// ============================================================================
// SECADMIN-046 / 047 - DefaultRolePermissions Property exposed, admin-only Read
// ============================================================================

// @relation(AC-SVR-SECADMIN-047-PERMISSIONS-READ-ADMIN, scope=function)
TEST_F(RbacDefaultPermsAdminFixture, AdminReadsDefaultRolePermissionsProperty)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "DrpAdminRead");

  auto read = read_role_permissions(session, NodeId{0, defaultRolePermissions}, AttributeId::Value);
  EXPECT_TRUE(read.status.is_good()) << "admin Read of DefaultRolePermissions: " << read.status.value();
  // All 9 well-known Roles seeded - SecurityAdmin's entry must be present.
  EXPECT_EQ(read.entries.size(), 9u);
  EXPECT_TRUE(contains_role(read.entries, security_admin_role_id()));
  EXPECT_TRUE(contains_role(read.entries, anonymous_role_id()));

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(SVR-SECADMIN-047, scope=function)
TEST_F(RbacDefaultPermsAnonFixture, NonAdminDefaultRolePermissionsReadDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "DrpAnonRead");

  auto read = read_role_permissions(session, NodeId{0, defaultRolePermissions}, AttributeId::Value);
  EXPECT_EQ(read.status, Status::BadUserAccessDenied)
    << "Anonymous Read of DefaultRolePermissions must be denied (admin-only, SECADMIN-047)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-054 - DefaultUserRolePermissions per-Session filtered view
// ============================================================================

// @relation(SVR-SECADMIN-054, scope=function)
TEST_F(RbacDefaultPermsAnonFixture, AnonymousSessionDefaultUserRolePermissionsFilteredToAnonymous)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "DurpAnonRead");

  auto read = read_role_permissions(session, NodeId{0, defaultUserRolePermissions}, AttributeId::Value);
  EXPECT_TRUE(read.status.is_good()) << "Anonymous Read of DefaultUserRolePermissions: "
                                     << read.status.value();
  // Anonymous session holds only the Anonymous Role -> only its entry survives.
  ASSERT_EQ(read.entries.size(), 1u);
  EXPECT_EQ(read.entries[0].role_id(), anonymous_role_id());
  EXPECT_FALSE(contains_role(read.entries, security_admin_role_id()));

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacDefaultPermsAdminFixture, AdminSessionDefaultUserRolePermissionsIncludesSecurityAdmin)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "DurpAdminRead");

  auto read = read_role_permissions(session, NodeId{0, defaultUserRolePermissions}, AttributeId::Value);
  EXPECT_TRUE(read.status.is_good()) << "admin Read of DefaultUserRolePermissions: " << read.status.value();
  // SecurityAdmin session also inherits Anonymous + AuthenticatedUser (dual-rule),
  // so its filtered view carries the SecurityAdmin entry (proving the filter is
  // not a no-op and not deny-all).
  EXPECT_TRUE(contains_role(read.entries, security_admin_role_id()));
  EXPECT_FALSE(
    contains_role(read.entries, NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Operator)}));

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-055 - per-Node UserRolePermissions Attribute (override projection)
// ============================================================================

// @relation(SVR-SECADMIN-055, scope=function)
TEST_F(RbacDefaultPermsAnonFixture, PerNodeUserRolePermissionsFilteredToGrantedRole)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "UrpNodeRead");

  auto read = read_role_permissions(session, mTestNodeId, AttributeId::UserRolePermissions);
  EXPECT_TRUE(read.status.is_good()) << "UserRolePermissions Read: " << read.status.value();
  // The node grants {Anonymous, SecurityAdmin}; the Anonymous session sees only
  // the Anonymous entry.
  ASSERT_EQ(read.entries.size(), 1u);
  EXPECT_EQ(read.entries[0].role_id(), anonymous_role_id());

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-057 - UserRolePermissions Attribute is read-only
// ============================================================================

// @relation(SVR-SECADMIN-057, scope=function)
// @verifies AC-SVR-ADDRSP-065-USERROLEPERMISSIONS-NOT-WRITABLE
TEST_F(RbacDefaultPermsAnonFixture, UserRolePermissionsAttributeWriteRejected)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "UrpNodeWrite");

  std::vector<RolePermissionType> proposed{
    make_role_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  Variant value{array_utils::copy_to_array_of_references(proposed)};
  auto resp = session.attributes().write_sync(
    WriteRequestBuilder{}.write(mTestNodeId, std::move(value), AttributeId::UserRolePermissions).build());

  ASSERT_FALSE(resp.results().empty());
  EXPECT_EQ(resp.results()[0].as_status(), Status::BadNotWritable)
    << "UserRolePermissions Attribute must not be writable (SECADMIN-057)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-058 - all 9 well-known Roles materialised under RoleSet
// ============================================================================

// @relation(SVR-SECADMIN-058, SVR-SECADMIN-069, scope=function)
TEST_F(RbacDefaultPermsAdminFixture, AllWellKnownRolesMaterialisedOverWire)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WellKnownRoles");

  for (const uint32_t roleObjectId : {static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous),
         static_cast<uint32_t>(ObjectId::WellKnownRole_AuthenticatedUser),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Observer),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Operator),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Engineer),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Supervisor),
         static_cast<uint32_t>(ObjectId::WellKnownRole_ConfigureAdmin),
         static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin),
         static_cast<uint32_t>(ObjectId::WellKnownRole_TrustedApplication)})
  {
    auto resp = session.attributes().read_sync(
      ReadRequestBuilder{}.read(NodeId{0, roleObjectId}).attribute(AttributeId::BrowseName).build());
    ASSERT_THAT(resp, ServiceResultIsGood());
    ASSERT_FALSE(resp.results().empty());
    EXPECT_THAT(resp.results()[0], Good())
      << "well-known Role Object " << roleObjectId << " must be readable";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Criterion-level mirrors - the obligations above stated as the observable the
// criterion names, rather than as the surface the SDK happens to expose.
// ============================================================================

// Part 18 section 4.6 / Part 3 section 5.2.9: where the server supports Permissions for a
// namespace, the `DefaultRolePermissions` Property must be *present on the
// NamespaceMetadata Object* - a client discovers it by browsing that Object, not
// by guessing the well-known NodeId. A plausible implementation writes a value
// into the NS0 Variable (so a NodeId-addressed Read succeeds) while the Object
// never actually references it, or deletes it as part of the vendor-specific
// opt-out; browsing is the only stimulus that distinguishes those cases.
// @verifies AC-SVR-SECADMIN-046-DEFAULTROLEPERMISSIONS-PRESENT
// The namespace-owned NS0 policy now makes the metadata Object browsable through ordinary
// RolePermissions, while the publication participant attaches both Properties transactionally. The
// NodeId and NodeClass assertions below ensure this cannot pass on a detached value alone.
TEST_F(RbacDefaultPermsAdminFixture, NamespaceMetadataObjectExposesDefaultRolePermissionsProperty)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "DrpMetadataBrowse");

  auto resp = session.view().browse_sync(browse(NodeId{ObjectId::OPCUANamespaceMetadata}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_FALSE(resp.results().empty());
  const auto& result = resp.results()[0];
  EXPECT_TRUE(result.status_code().is_good())
    << "browse of NamespaceMetadata: " << result.status_code().value();
  ASSERT_FALSE(result.references().empty()) << "NamespaceMetadata Object browsed to zero references";

  const auto* byName = find_reference_named(result, "DefaultRolePermissions");
  ASSERT_NE(byName, nullptr)
    << "the NamespaceMetadata Object must expose a DefaultRolePermissions Property (SECADMIN-046)";
  EXPECT_EQ(byName->node_id().node_id(), (NodeId{0, defaultRolePermissions}));
  EXPECT_EQ(byName->node_class(), NodeClass::Variable);
  EXPECT_NE(find_reference_to(result, NodeId{0, defaultRolePermissions}), nullptr);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 3 section 5.2.9 L1889: the permissions map describes where the authorisation
// boundaries are, so BOTH the namespace-wide Property and the per-Node
// Attribute are admin-only readable, and neither may leak a partial value
// alongside the refusal. A plausible implementation gates one surface (the one
// its own tests cover) and leaves the other open, or returns Bad_UserAccessDenied
// with the decoded array still attached to the DataValue.
// @verifies AC-SVR-SECADMIN-047-PERMISSIONS-READ-ADMIN
TEST_F(RbacDefaultPermsAnonFixture, NonAdminReadOfBothPermissionSurfacesIsRefusedWithNoValue)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "PermsReadDenied");

  auto resp = session.attributes().read_sync(ReadRequestBuilder{}
                                               .read(NodeId{0, defaultRolePermissions})
                                               .attribute(AttributeId::Value)
                                               .read(mTestNodeId)
                                               .attribute(AttributeId::RolePermissions)
                                               .build());
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 2u) << "both permission surfaces must be answered";

  EXPECT_THAT(resp.results()[0], HasStatusPresent(Status::BadUserAccessDenied))
    << "Anonymous Read of the DefaultRolePermissions Property must be refused (SECADMIN-047)";
  EXPECT_TRUE(resp.results()[0].value().empty())
    << "a refused DefaultRolePermissions Read must not carry a partially-redacted value";

  EXPECT_THAT(resp.results()[1], HasStatusPresent(Status::BadUserAccessDenied))
    << "Anonymous Read of the per-Node RolePermissions Attribute must be refused (SECADMIN-047)";
  EXPECT_TRUE(resp.results()[1].value().empty())
    << "a refused RolePermissions Read must not carry a partially-redacted value";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.6: a server that publishes per-Session Role information must add
// `DefaultUserRolePermissions` *alongside* `DefaultRolePermissions` on the same
// metadata Object. Publishing only the first is the plausible failure - the
// admin-facing Property is the one an implementation naturally materialises
// first, and a client is then unable to determine its own effective permissions
// without probing each operation.
// @verifies AC-SVR-SECADMIN-054-DEFAULTUSERROLEPERMISSIONS
// This is deliberately one Browse of one Object: two independent NodeId-addressed Reads would not prove the
// required parent/child publication relationship.
// The macro must stay on one line: the traceability tooling matches a single-line
// TEST_F and reads a wrapped one as a test that does not exist.
// clang-format off
TEST_F(RbacDefaultPermsAdminFixture, MetadataObjectExposesDefaultUserRolePermissionsAlongsideDefaults)
// clang-format on
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "DurpMetadataBrowse");

  auto resp = session.view().browse_sync(browse(NodeId{ObjectId::OPCUANamespaceMetadata}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_FALSE(resp.results().empty());
  const auto& result = resp.results()[0];
  ASSERT_FALSE(result.references().empty()) << "NamespaceMetadata Object browsed to zero references";

  // "alongside" - both, on the same Object, in the same browse.
  const auto* defaults = find_reference_named(result, "DefaultRolePermissions");
  ASSERT_NE(defaults, nullptr) << "DefaultRolePermissions must be present for the pairing to hold";
  EXPECT_EQ(defaults->node_id().node_id(), (NodeId{0, defaultRolePermissions}));

  const auto* userDefaults = find_reference_named(result, "DefaultUserRolePermissions");
  ASSERT_NE(userDefaults, nullptr)
    << "the NamespaceMetadata Object must also expose DefaultUserRolePermissions (SECADMIN-054)";
  EXPECT_EQ(userDefaults->node_id().node_id(), (NodeId{0, defaultUserRolePermissions}));
  EXPECT_EQ(userDefaults->node_class(), NodeClass::Variable);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.6 / Q-RBAC-3: `UserRolePermissions` is derived, so it must be
// re-derived from whatever the Node's effective `RolePermissions` resolve to -
// the per-Node override when there is one, the namespace default otherwise. The
// plausible bug is a projection wired straight to the namespace
// `DefaultRolePermissions`, which looks right on every Node that has no
// override and silently understates (or overstates) the overridden ones. Both
// legs are read from the same Anonymous session so only the Node differs.
// @verifies AC-SVR-SECADMIN-055-USERROLEPERMISSIONS-OVERRIDDEN-TOO
TEST_F(RbacUrpOverrideFixture, NodeOverrideDrivesUserRolePermissionsInsteadOfTheNamespaceDefault)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "UrpOverrideRead");

  auto overridden = read_role_permissions(session, mOverriddenNodeId, AttributeId::UserRolePermissions);
  EXPECT_TRUE(overridden.status.is_good())
    << "UserRolePermissions Read on the overriding Node: " << overridden.status.value();
  ASSERT_EQ(overridden.entries.size(), 1u)
    << "the Anonymous session's projection of the override must carry its Anonymous entry";
  EXPECT_EQ(overridden.entries[0].role_id(), anonymous_role_id());
  // The override grants Anonymous Browse+Read; the namespace default grants Browse only.
  EXPECT_TRUE(overridden.entries[0].permissions().test(PermissionType::Bit::Browse));
  EXPECT_TRUE(overridden.entries[0].permissions().test(PermissionType::Bit::Read))
    << "the derived Attribute must reflect the Node's override, not the namespace default";

  auto inheriting = read_role_permissions(session, mInheritingNodeId, AttributeId::UserRolePermissions);
  EXPECT_TRUE(inheriting.status.is_good())
    << "UserRolePermissions Read on the non-overriding Node: " << inheriting.status.value();
  ASSERT_EQ(inheriting.entries.size(), 1u)
    << "a Node with no override must still project the namespace default";
  EXPECT_EQ(inheriting.entries[0].role_id(), anonymous_role_id());
  EXPECT_TRUE(inheriting.entries[0].permissions().test(PermissionType::Bit::Browse));
  EXPECT_FALSE(inheriting.entries[0].permissions().test(PermissionType::Bit::Read))
    << "the namespace default grants Anonymous Browse only";

  EXPECT_NE(overridden.entries[0].permissions(), inheriting.entries[0].permissions())
    << "override and namespace-default projections must be distinguishable";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-001-DEFAULT-MATCHES-ROLE-MODEL, scope=function)
TEST_F(RbacUrpOverrideFixture, NamespaceDefaultBrowseGrantDoesNotAlsoGrantValueRead)
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "NamespaceDefaultEnforcement");

  auto request = ReadRequestBuilder{}
                   .read(mInheritingNodeId)
                   .attribute(AttributeId::BrowseName)
                   .read(mInheritingNodeId)
                   .attribute(AttributeId::Value)
                   .build();
  auto readResponse = session.attributes().read_sync(std::move(request));
  ASSERT_THAT(readResponse, ServiceResultIsGood());
  ASSERT_EQ(readResponse.results().size(), 2u);
  EXPECT_THAT(readResponse.results()[0], Good());
  EXPECT_THAT(readResponse.results()[1], HasStatus(Status::BadUserAccessDenied));

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 / Part 3 section 5.2.10: "This Attribute shall not be writeable." The two
// Attributes look interchangeable - `RolePermissions` is the admin-configurable
// rule, `UserRolePermissions` the derived per-Session conclusion - so the
// plausible implementation routes both through the same admin-gated write path
// and lets an administrator record a conclusion. Asserting only the refusal
// would also pass on a server that refuses every RolePermissions write, so the
// admin-writable half is pinned on the same Node in the same session.
// @verifies AC-SVR-SECADMIN-057-USERROLEPERMISSIONS-READONLY
TEST_F(RbacUrpWritabilityFixture, AdminUserRolePermissionsWriteRefusedWhileRolePermissionsStaysWritable)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "UrpAdminWrite");

  Variant derived{array_utils::copy_to_array_of_references(admin_writable_permissions())};
  auto derivedResp = session.attributes().write_sync(
    WriteRequestBuilder{}.write(mTestNodeId, std::move(derived), AttributeId::UserRolePermissions).build());
  ASSERT_THAT(derivedResp, ServiceResultIsGood());
  ASSERT_FALSE(derivedResp.results().empty());
  EXPECT_EQ(derivedResp.results()[0].as_status(), Status::BadNotWritable)
    << "UserRolePermissions must be refused even for an administrator (SECADMIN-057)";

  Variant configured{array_utils::copy_to_array_of_references(admin_writable_permissions())};
  auto configuredResp = session.attributes().write_sync(
    WriteRequestBuilder{}.write(mTestNodeId, std::move(configured), AttributeId::RolePermissions).build());
  ASSERT_THAT(configuredResp, ServiceResultIsGood());
  ASSERT_FALSE(configuredResp.results().empty());
  EXPECT_EQ(configuredResp.results()[0].as_status(), Status::Good)
    << "RolePermissions on the same Node must remain writable by an administrator (SECADMIN-057)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.3 Table 2 / Part 3 section 4.8.2: the RoleSet is what a client enumerates
// to discover what it may ask for, and a missing Role is indistinguishable from
// a Role it is not granted. The plausible implementation materialises only the
// Roles its own configuration mentions, or creates the Role Objects without the
// RoleType TypeDefinition - either way a client walking the RoleSet, as CTT
// does, silently sees a narrower server.
// @verifies AC-SVR-SECADMIN-058-EIGHT-WELLKNOWN-ROLES
TEST_F(RbacDefaultPermsAdminFixture, RoleSetContainsEveryWellKnownRoleAsARoleTypeObject)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RoleSetBrowse");

  auto resp = session.view().browse_sync(browse(NodeId{ObjectId::Server_ServerCapabilities_RoleSet}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_FALSE(resp.results().empty());
  const auto& result = resp.results()[0];
  EXPECT_TRUE(result.status_code().is_good()) << "browse of RoleSet: " << result.status_code().value();
  ASSERT_FALSE(result.references().empty()) << "RoleSet browsed to zero references";

  const NodeId roleTypeId{ObjectTypeId::RoleType};
  for (const uint32_t roleObjectId : {static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous),
         static_cast<uint32_t>(ObjectId::WellKnownRole_AuthenticatedUser),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Observer),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Operator),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Engineer),
         static_cast<uint32_t>(ObjectId::WellKnownRole_Supervisor),
         static_cast<uint32_t>(ObjectId::WellKnownRole_ConfigureAdmin),
         static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)})
  {
    const auto* ref = find_reference_to(result, NodeId{0, roleObjectId});
    ASSERT_NE(ref, nullptr) << "well-known Role Object " << roleObjectId
                            << " must be reachable by browsing the RoleSet (SECADMIN-058)";
    EXPECT_EQ(ref->node_class(), NodeClass::Object) << "well-known Role " << roleObjectId;
    EXPECT_EQ(ref->type_definition().node_id(), roleTypeId)
      << "well-known Role " << roleObjectId << " must be an Object of RoleType";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-061..064 - what each well-known Role grants, exercised as operations
//
// The Permissions under test are NOT authored by this fixture. The server
// computes its own well-known-Role defaults at startup and publishes them in
// the NS0 `DefaultRolePermissions` Property; the fixture reads that array back
// and installs it as the test namespace's `DefaultRolePermissions`, so the
// Nodes below are governed by the server's decision about each Role. Setting
// the bits here instead would test the fixture, not the server.
// ============================================================================

/// Minimal raw-history store so a history Read that a Role *permits* can
/// return data. Without it every history Read ends in
/// `Bad_HistoryOperationUnsupported` and the Role gate is unobservable in
/// either direction.
class RoleDefaultsHistoryDelegate : public NamespaceHistoryDelegate
{
public:
  void add_values(const NodeId& nodeId, std::vector<DataValue> values)
  {
    std::lock_guard lock(mMutex);
    auto& existing = mData[nodeId];
    existing.insert(
      existing.end(), std::make_move_iterator(values.begin()), std::make_move_iterator(values.end()));
  }

  Capabilities capabilities() const noexcept override
  {
    Capabilities caps;
    caps.readRaw = true;
    return caps;
  }

  void read_raw_async(const NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<NamespaceHistoryDelegate::ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
    batch.items.reserve(items.size());

    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      auto it = mData.find(item.nodeId);
      if (it != mData.end())
      {
        for (const auto& dv : it->second)
        {
          success.values.push_back(dv);
        }
      }
      batch.items.emplace_back(std::move(success));
    }

    callback(std::move(batch));
  }

private:
  std::mutex mMutex;
  std::unordered_map<NodeId, std::vector<DataValue>> mData;
};

/// Namespace that carries the server's own well-known-Role defaults as its
/// `DefaultRolePermissions` and serves raw history from the delegate above.
class RoleDefaultsNamespace : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static std::shared_ptr<RoleDefaultsNamespace> create(String uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<RoleDefaultsNamespace>(
      new RoleDefaultsNamespace(std::move(uri), std::move(executor)));
  }

  void set_delegate(std::shared_ptr<RoleDefaultsHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  std::shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  std::shared_ptr<RoleDefaultsHistoryDelegate> mDelegate;
};

/// The server's own well-known-Role default Permissions, read from the canonical namespace interface
/// that also answers the wire-visible `DefaultRolePermissions` Property. Sourcing the array from
/// production state stops the Role tests below from asserting against Permissions the test invented
/// without depending on the Property's inert stored placeholder.
std::vector<RolePermissionType> server_namespace_role_defaults(AddressSpace& addressSpace)
{
  const auto nameSpace = addressSpace.namespace_array().get_namespace(0);
  if (!nameSpace)
  {
    ADD_FAILURE() << "NS0 namespace is unavailable";
    return {};
  }
  const auto defaults = nameSpace->default_role_permissions();
  if (!defaults)
  {
    ADD_FAILURE() << "NS0 does not expose the standard Role Permission model";
    return {};
  }
  return *defaults;
}

/// Map an authenticated `UserName` identity onto a well-known Role, mirroring
/// `grant_security_admin_to_user` for the Roles that ship with no identity
/// rules. Pre-registering the slot makes `seed_well_known_roles` leave it
/// alone and keep this rule; the Role's *Permissions* still come from the
/// server.
void grant_well_known_role_to_user(
  RoleConfiguration& config, ObjectId role, uint8_t roleBit, const std::string& userId)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = NodeId{0, static_cast<uint32_t>(role)};
  def.roleBit = roleBit;
  ASSERT_TRUE(config.add_role(std::move(def))) << "well-known Role slot must register";
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{userId};
  auto result = config.add_identity_rule(NodeId{0, static_cast<uint32_t>(role)}, std::move(rule));
  ASSERT_TRUE(result.is_good()) << "UserName rule must register: " << result.status_code().value();
}

/// Window covering every pre-loaded history value with margin.
const DateTime roleHistoryStart{2020, 1, 1, 0, 0, 0.0};
const DateTime roleHistoryEnd{2030, 1, 1, 0, 0, 0.0};

/// Create a Subscription and one data MonitoredItem on `nodeId`, returning the
/// per-item status. `CreateMonitoredItems` is where Part 4 section 5.12.2.1 gates a
/// data subscription (`AccessOperation::Read`), so this is the observable for
/// "subscribe".
///
/// The Subscription is deleted again once that status has been captured. A live
/// data MonitoredItem holds a registration in the namespace's `SamplingEngine`,
/// which keeps a periodic bucket timer armed until the last registration in the
/// bucket is removed (`ua_sampling_engine.cpp:298` cancels the timer only when
/// the bucket empties). An armed timer at `thread_pool::join()` is what the
/// drain diagnostic in `test_utilities.h` reports, so the item is unregistered
/// here rather than left to teardown.
StatusCode subscribe_to_value(Session& session, const NodeId& nodeId)
{
  CreateSubscriptionRequest subReq;
  subReq.requested_publishing_interval() = 100.0;
  subReq.requested_lifetime_count() = 100;
  subReq.requested_max_keep_alive_count() = 10;
  subReq.max_notifications_per_publish() = 0;
  subReq.publishing_enabled() = true;
  subReq.priority() = 0;
  auto subResp = session.subscriptions().create_subscription_sync(std::move(subReq));
  if (!subResp.response_header().service_result().is_good())
  {
    return subResp.response_header().service_result();
  }

  ReadValueId monitored;
  monitored.node_id() = nodeId;
  monitored.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 100.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(monitored);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subResp.subscription_id();
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = session.monitored_items().create_monitored_items_sync(std::move(req));

  DeleteSubscriptionsRequest delReq;
  delReq.subscription_ids().push_back(subResp.subscription_id());
  (void)session.subscriptions().try_delete_subscriptions_sync(std::move(delReq));

  if (!resp.response_header().service_result().is_good())
  {
    return resp.response_header().service_result();
  }
  if (resp.results().empty())
  {
    ADD_FAILURE() << "CreateMonitoredItems returned no per-item result";
    return StatusCode{Status::BadInternalError};
  }
  return resp.results()[0].status_code();
}

/// Base for the well-known-Role default-Permission mirrors: one Object (the
/// Browse target), one Variable carrying live data + raw history, and one
/// Method - none of them carrying a per-Node `RolePermissions` override, so
/// every decision below falls through to the namespace defaults, which are the
/// server's own published Role defaults.
class WellKnownRoleDefaultsBase : public ComplianceRoleBasedSecurity
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    mHistory = std::make_shared<RoleDefaultsHistoryDelegate>();
    mTestNamespace =
      RoleDefaultsNamespace::create(String{"urn:test:wellknown-role-defaults"}, mServerThreadPool.executor());
    mTestNamespace->set_delegate(mHistory);
    mTestNamespace->set_namespace_defaults(server_namespace_role_defaults(addressSpace), std::nullopt);
    mTestNsIndex = addressSpace.add_namespace_sync(mTestNamespace);

    mFolderId = NodeId{mTestNsIndex, uint32_t{72000}};
    mVariableId = NodeId{mTestNsIndex, uint32_t{72001}};
    mMethodId = NodeId{mTestNsIndex, uint32_t{72002}};

    auto folderNode = addressSpace.create_node_sync(mFolderId, NodeClass::Object);
    folderNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto folder = folderNode.as<ObjectAccessor>();
    ASSERT_TRUE(folder.has_value());
    folder->set_browse_name(QualifiedName{mTestNsIndex, "RoleDefaultsFolder"});
    folder->set_display_name(LocalizedText{"", "RoleDefaultsFolder"});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mFolderId);

    auto varNode = addressSpace.create_node_sync(mVariableId, NodeClass::Variable);
    auto variable = varNode.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNsIndex, "LiveData"});
    variable->set_display_name(LocalizedText{"", "LiveData"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{7});
    // HistoryRead is the capability advertisement the HistoryRead service tests
    // before it reaches the Role gate; without it a refusal would be
    // "unsupported", not "denied", and the criterion would be unfalsifiable.
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::HistoryRead});
    // Same reasoning for the configuration-data write: open the DisplayName
    // WriteMask bit statically so a refusal is the Role's, not a zero WriteMask.
    varNode.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mVariableId);

    auto methodNode = addressSpace.create_node_sync(mMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mTestNsIndex, "RoleDefaultsMethod"});
    method->set_display_name(LocalizedText{"", "RoleDefaultsMethod"});
    method->set_executable(true);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMethodId);
    {
      // A handler is installed so that a refused Call is attributable to the
      // Role and not to a missing implementation.
      auto* callSource = mTestNamespace->find_node<Node>(mMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
    }

    std::vector<DataValue> history;
    for (int32_t i = 0; i < 3; ++i)
    {
      DataValue dv;
      dv.value() = Variant{int32_t{i}};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.server_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      history.push_back(std::move(dv));
    }
    mHistory->add_values(mVariableId, std::move(history));
  }

  /// The namespace owns a `SamplingEngine` with periodic bucket timers, and a
  /// fixture member keeps it alive past the base teardown that joins the server
  /// thread pool. Drop the fixture's reference first so the address space holds
  /// the last one and the engine is destroyed (cancelling its timers) when the
  /// server is, before the join. Same discipline as
  /// `compliance_subscription_tests.cpp:153`.
  void TearDown() override
  {
    mTestNamespace.reset();
    mHistory.reset();
    ComplianceRoleBasedSecurity::TearDown();
  }

  std::shared_ptr<RoleDefaultsNamespace> mTestNamespace;
  std::shared_ptr<RoleDefaultsHistoryDelegate> mHistory;
  uint16_t mTestNsIndex{0};
  NodeId mFolderId;
  NodeId mVariableId;
  NodeId mMethodId;
};

/// Anonymous Session: the default `AnonymousAuthenticator`, so the Session
/// resolves to the Anonymous Role and nothing else.
class AnonymousRoleDefaultsFixture : public WellKnownRoleDefaultsBase
{};

/// A Session with valid non-anonymous credentials and no Role grant of its
/// own. Part 18 section 4.3's dual rule also puts it in the Anonymous Role, which is
/// the point of the criterion: authenticating must not add write access.
class AuthenticatedUserRoleDefaultsFixture : public WellKnownRoleDefaultsBase
{
protected:
  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "plainuser", std::unordered_map<std::string, std::string>{});
  }
};

/// Observer Session (UserName "observer" mapped onto the well-known Observer
/// Role, canonical bit 2).
class ObserverRoleDefaultsFixture : public WellKnownRoleDefaultsBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_well_known_role_to_user(config, ObjectId::WellKnownRole_Observer, 2, "observer");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "observer", std::unordered_map<std::string, std::string>{});
  }
};

/// Operator Session (UserName "operator" mapped onto the well-known Operator
/// Role, canonical bit 3).
class OperatorRoleDefaultsFixture : public WellKnownRoleDefaultsBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_well_known_role_to_user(config, ObjectId::WellKnownRole_Operator, 3, "operator");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "operator", std::unordered_map<std::string, std::string>{});
  }
};

// Part 18 section 4.3: the Anonymous Role "has very limited access for use when a
// Session has anonymous credentials". It is the surface an unconfigured server
// hands an unauthenticated caller, so the criterion names what must be refused,
// not only what must work. The plausible implementation reaches for a single
// "read-only" notion and lets it carry history and Method calls too - both are
// read-shaped, and both leak far more than browsing a value does.
// @verifies AC-SVR-SECADMIN-061-ANONYMOUS-PERMISSIONS
// The macro must stay on one line: the traceability tooling matches a single-line
// TEST_F and reads a wrapped one as a test that does not exist.
// clang-format off
TEST_F(AnonymousRoleDefaultsFixture, AnonymousRoleGrantsBrowseAndReadAndRefusesWriteCallAndHistoryRead)
// clang-format on
{
  auto [channel, session] = open_session(MessageSecurityMode::None, "AnonRoleDefaults");

  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "the Anonymous Role must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "the Anonymous Role must permit reading a live value";

  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(mVariableId, Variant{int32_t{99}})),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "the Anonymous Role must not permit a Write";

  auto callResp = session.methods().call_sync(CallRequestBuilder{}.call(mFolderId, mMethodId));
  ASSERT_THAT(callResp, ServiceResultIsGood());
  ASSERT_FALSE(callResp.results().empty());
  EXPECT_THAT(callResp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "the Anonymous Role must not permit a Method Call";

  auto historyResp =
    session.attributes().history_read_sync(history_read_raw(mVariableId, roleHistoryStart, roleHistoryEnd));
  ASSERT_THAT(historyResp, ServiceResultIsGood());
  ASSERT_FALSE(historyResp.results().empty());
  EXPECT_THAT(historyResp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "the Anonymous Role must not permit a history Read (the Node advertises HistoryRead and the "
       "namespace serves history, so this refusal can only come from the Role)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.3: AuthenticatedUser "has limited access for use when a Session
// has valid non-anonymous credentials but has not been explicitly granted
// access to a Role". Authentication is not authorisation, and this Role is
// where that is stated as a default - a server that granted Write on the
// strength of valid credentials would make every configured Role redundant.
// @verifies AC-SVR-SECADMIN-062-AUTHENTICATEDUSER-PERMISSIONS
TEST_F(AuthenticatedUserRoleDefaultsFixture, AuthenticatedUserRoleReadsButGainsNoWriteOverAnonymous)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AuthUserRoleDefaults");

  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "the AuthenticatedUser Role must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "the AuthenticatedUser Role must permit reading a live value";

  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(mVariableId, Variant{int32_t{99}})),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "holding valid credentials must not by itself confer Write";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.3 / Part 3 section 4.8.2 Table 2: Observer "is allowed to browse, read
// live data, read historical data/events or subscribe to data/events" - and
// nothing else. The boundary that matters is the one it does not cross: no
// Method call, no Write. A plausible implementation folds Observer in with
// Operator (the two differ only by write-and-call) and hands an observer the
// ability to actuate.
// @verifies AC-SVR-SECADMIN-063-OBSERVER-PERMISSIONS
TEST_F(ObserverRoleDefaultsFixture, ObserverRoleGrantsTheFourReadsAndRefusesWriteAndCall)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ObserverRoleDefaults");

  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "Observer must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "Observer must permit reading live data";

  auto historyResp =
    session.attributes().history_read_sync(history_read_raw(mVariableId, roleHistoryStart, roleHistoryEnd));
  ASSERT_THAT(historyResp, ServiceResultIsGood());
  ASSERT_FALSE(historyResp.results().empty());
  EXPECT_THAT(historyResp.results()[0], Good()) << "Observer must permit reading historical data";

  EXPECT_THAT(subscribe_to_value(session, mVariableId), Good()) << "Observer must permit subscribing to data";

  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(mVariableId, Variant{int32_t{99}})),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "Observer must not permit a Write";

  auto callResp = session.methods().call_sync(CallRequestBuilder{}.call(mFolderId, mMethodId));
  ASSERT_THAT(callResp, ServiceResultIsGood());
  ASSERT_FALSE(callResp.results().empty());
  EXPECT_THAT(callResp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "Observer must not permit a Method Call - that is precisely what separates it from Supervisor";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 3 section 4.8.2 Table 2: Operator is Observer plus "write some live data and
// call some Methods". Live data and configuration data are the distinction,
// and it is the one an implementation collapses: both are Writes through the
// same service, so a Role granted an undifferentiated "write" hands an
// operator the ability to reconfigure the server. The Node's WriteMask opens
// the DisplayName bit, so the configuration Write can only be refused by the
// Role.
// @verifies AC-SVR-SECADMIN-064-OPERATOR-PERMISSIONS
// The implementation now preserves this distinction end-to-end: Value writes
// require Write, while non-Value configuration attributes require WriteAttribute.
// @relation(AC-SVR-AUTHZ-006-ATTRIBUTE-WRITE-BITS-SEPARATE, scope=function)
TEST_F(OperatorRoleDefaultsFixture, OperatorRoleAddsLiveDataWriteButNotConfigurationWrite)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "OperatorRoleDefaults");

  // Observer's operations first - Operator is defined as a superset.
  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "Operator must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "Operator must permit reading live data";

  auto historyResp =
    session.attributes().history_read_sync(history_read_raw(mVariableId, roleHistoryStart, roleHistoryEnd));
  ASSERT_THAT(historyResp, ServiceResultIsGood());
  ASSERT_FALSE(historyResp.results().empty());
  EXPECT_THAT(historyResp.results()[0], Good()) << "Operator must permit reading historical data";

  EXPECT_THAT(subscribe_to_value(session, mVariableId), Good()) << "Operator must permit subscribing to data";

  // Live data: the Value Attribute.
  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(mVariableId, Variant{int32_t{99}})),
    WriteSucceeds())
    << "Operator must permit writing live data";

  // Configuration data: a non-Value Attribute of the very same Node.
  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(
                mVariableId, Variant{LocalizedText{"", "Reconfigured"}}, AttributeId::DisplayName)),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "Operator must not permit writing configuration data";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

/// Engineer Session (UserName "engineer" mapped onto the well-known Engineer
/// Role, canonical bit 4 - `ua_server_impl.cpp:3555`).
class EngineerRoleDefaultsFixture : public WellKnownRoleDefaultsBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_well_known_role_to_user(config, ObjectId::WellKnownRole_Engineer, 4, "engineer");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "engineer", std::unordered_map<std::string, std::string>{});
  }
};

// Part 3 section 4.8.2 Table 2 / Part 18 section 4.3: Engineer is the
// configuration-mutator Role - browse, read AND write configuration data, read
// history, call Methods and subscribe - and it is defined by the authority it
// stops short of. "Security-related settings remain refused" is the whole
// boundary between Engineer and SecurityAdmin, and the plausible implementation
// erases it: Engineer is the Role that already carries the widest write surface,
// so a mask assembled as "configuration authority" naturally swallows the
// permissions map along with everything else configurable, and an engineer who
// can retune a setpoint can also rewrite who is allowed to. The refusal is
// therefore read from the same Session that just succeeded at the six granted
// operations - a Role that was simply denied everything, or granted everything,
// would fail this test in one direction or the other.
// @verifies AC-SVR-SECADMIN-065-ENGINEER-PERMISSIONS
TEST_F(EngineerRoleDefaultsFixture, EngineerRoleConfiguresAndCallsButIsRefusedSecuritySettings)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "EngineerRoleDefaults");

  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "Engineer must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "Engineer must permit reading live data";

  // Configuration data is a non-Value Attribute of the same Node - read it and
  // then write it, which is the pair Operator is allowed only half of.
  auto configReadResp = session.attributes().read_sync(
    ReadRequestBuilder{}.read(mVariableId).attribute(AttributeId::DisplayName).build());
  ASSERT_THAT(configReadResp, ServiceResultIsGood());
  ASSERT_FALSE(configReadResp.results().empty());
  EXPECT_THAT(configReadResp.results()[0], Good()) << "Engineer must permit reading configuration data";

  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(
                mVariableId, Variant{LocalizedText{"", "EngineerConfigured"}}, AttributeId::DisplayName)),
    WriteSucceeds())
    << "Engineer must permit writing configuration data";

  auto historyResp =
    session.attributes().history_read_sync(history_read_raw(mVariableId, roleHistoryStart, roleHistoryEnd));
  ASSERT_THAT(historyResp, ServiceResultIsGood());
  ASSERT_FALSE(historyResp.results().empty());
  EXPECT_THAT(historyResp.results()[0], Good()) << "Engineer must permit reading historical data";

  auto callResp = session.methods().call_sync(CallRequestBuilder{}.call(mFolderId, mMethodId));
  ASSERT_THAT(callResp, ServiceResultIsGood());
  ASSERT_FALSE(callResp.results().empty());
  EXPECT_THAT(callResp.results()[0], HasStatus(Status::Good))
    << "Engineer must permit a Method Call (a handler is installed, so a refusal is the Role's)";

  EXPECT_THAT(subscribe_to_value(session, mVariableId), Good()) << "Engineer must permit subscribing to data";

  // The security-related setting: the permissions map itself, admin-only by
  // Part 3 section 5.2.9 L1889. Engineer's published default carries no
  // ReadRolePermissions bit, and the Property's own RolePermissions name
  // SecurityAdmin alone, so this refusal comes from the server's Role model and
  // not from the fixture.
  auto securityResp = session.attributes().read_sync(
    ReadRequestBuilder{}.read(NodeId{0, defaultRolePermissions}).attribute(AttributeId::Value).build());
  ASSERT_THAT(securityResp, ServiceResultIsGood());
  ASSERT_FALSE(securityResp.results().empty());
  EXPECT_THAT(securityResp.results()[0], HasStatusPresent(Status::BadUserAccessDenied))
    << "configuration authority must not carry security authority - the permissions map stays "
       "SecurityAdmin-only (SECADMIN-065 / SECADMIN-068)";
  EXPECT_TRUE(securityResp.results()[0].value().empty())
    << "a refused Read of the permissions map must not leak it alongside the refusal";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

/// Supervisor Session (UserName "supervisor" mapped onto the well-known
/// Supervisor Role, canonical bit 5 - `ua_server_impl.cpp:3557`).
class SupervisorRoleDefaultsFixture : public WellKnownRoleDefaultsBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_well_known_role_to_user(config, ObjectId::WellKnownRole_Supervisor, 5, "supervisor");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "supervisor", std::unordered_map<std::string, std::string>{});
  }
};

// Part 3 section 4.8.2 Table 2 / Part 18 section 4.3: Supervisor "is allowed to
// browse, read live data, read historical data/events, call Methods or
// subscribe to data/events" - Observer's set plus the Call, and no Write (Part 3
// section 4.8.3 Table 4). A Role that may actuate through a Method but may not
// write a Variable is the counter-intuitive one, and it is where a plausible
// implementation "corrects" the spec: ranked by authority a Call is the more
// powerful of the two, so a mask assembled by seniority hands Supervisor Write
// as well and the boundary against Operator disappears - while a mask assembled
// by copying Observer leaves the Call out and the boundary against Observer
// disappears instead. Both refusal and grant are therefore read from the same
// Session, so a Role denied everything, or granted everything, fails this test
// in one direction or the other.
// @verifies AC-SVR-SECADMIN-066-SUPERVISOR-PERMISSIONS
TEST_F(SupervisorRoleDefaultsFixture, SupervisorRoleAddsTheMethodCallToObserverButIsStillRefusedWrites)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "SupervisorRoleDefaults");

  // Observer's four operations first - Supervisor is defined as that set plus Call.
  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "Supervisor must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "Supervisor must permit reading live data";

  auto historyResp =
    session.attributes().history_read_sync(history_read_raw(mVariableId, roleHistoryStart, roleHistoryEnd));
  ASSERT_THAT(historyResp, ServiceResultIsGood());
  ASSERT_FALSE(historyResp.results().empty());
  EXPECT_THAT(historyResp.results()[0], Good()) << "Supervisor must permit reading historical data";

  EXPECT_THAT(subscribe_to_value(session, mVariableId), Good())
    << "Supervisor must permit subscribing to data";

  auto callResp = session.methods().call_sync(CallRequestBuilder{}.call(mFolderId, mMethodId));
  ASSERT_THAT(callResp, ServiceResultIsGood());
  ASSERT_FALSE(callResp.results().empty());
  EXPECT_THAT(callResp.results()[0], HasStatus(Status::Good))
    << "Supervisor must permit a Method Call - the one operation that separates it from Observer (a "
       "handler is installed, so a refusal would be the Role's)";

  // The write, from the same Session that just succeeded at all five above.
  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(mVariableId, Variant{int32_t{99}})),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "Supervisor must not permit a Write - the one operation that separates it from Operator";

  // Supervisor carries no write authority of any kind, so the configuration
  // half is refused too. The Node's WriteMask opens the DisplayName bit, so this
  // refusal can only come from the Role.
  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(
                mVariableId, Variant{LocalizedText{"", "SupervisorConfigured"}}, AttributeId::DisplayName)),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "Supervisor must not permit writing configuration data either";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

}  // namespace
