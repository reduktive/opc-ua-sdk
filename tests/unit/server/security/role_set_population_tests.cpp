// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for `populate_role_set` (Cut 5 G.1).
///
/// Pins:
///   * RoleType ObjectType definition carries admin-only RolePermissions +
///     EncryptionRequired AccessRestrictions after Part-18 server creation.
///   * All 9 well-known role Objects + their HasProperty children carry the
///     same attrs.
///   * Per-role Variable values mirror the active RoleConfiguration content
///     (Anonymous gets the Anonymous identity rule; Operator's Identities
///     list is empty by default).
///   * When `wellKnownRoles` selects a subset, only the listed roles are
///     populated.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_endpoint_type.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_permission_type.h"
#include "ua_server_impl.h"
#include "ua_variable_id.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

::ua::server::CombinedConfig make_frozen_config(
  bool roleManagement = false, bool enableClaimToRoleMapping = false)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ::ua::server::ServerConfig sc;
  sc.maxConnections = 100;
  sc.roleManagementEnabled = roleManagement;
  sc.enableClaimToRoleMapping = enableClaimToRoleMapping;
  frozen.server = std::move(sc);
  return frozen;
}

shared_ptr<ServerImpl> create_part18_server(boost::asio::any_io_executor ex,
  std::optional<std::vector<WellKnownRole>> selection = std::nullopt, bool roleManagement = false,
  bool enableClaimToRoleMapping = false, std::shared_ptr<RoleConfiguration> roleConfiguration = nullptr)
{
  auto frozen = make_frozen_config(roleManagement, enableClaimToRoleMapping);
  frozen.server.wellKnownRoles = std::move(selection);
  ::ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  // Part-18 wiring is driven by `mRoleConfiguration` presence; population
  // tests don't need an activated AccessIdentity.
  components.roleConfiguration =
    roleConfiguration ? std::move(roleConfiguration) : std::make_shared<RoleConfiguration>();
  return ServerImpl::create(ex, std::move(frozen), std::move(components));
}

bool admin_only_role_permissions(const std::vector<RolePermissionType>& perms)
{
  if (perms.size() != 2)
    return false;
  bool hasSecurityAdmin = false;
  bool hasConfigureAdmin = false;
  for (const auto& p : perms)
  {
    if (p.role_id() == NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)})
    {
      if (!p.permissions().test(PermissionType::Bit::Browse))
        return false;
      if (!p.permissions().test(PermissionType::Bit::Read))
        return false;
      if (!p.permissions().test(PermissionType::Bit::Write))
        return false;
      hasSecurityAdmin = true;
    }
    if (p.role_id() == NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_ConfigureAdmin)})
    {
      hasConfigureAdmin = true;
    }
  }
  return hasSecurityAdmin && hasConfigureAdmin;
}

/// True iff `perms` grants the given well-known role (by NS0 numeric id).
bool grants_role(const std::vector<RolePermissionType>& perms, uint32_t roleNumeric)
{
  return std::any_of(perms.begin(),
    perms.end(),
    [&](const RolePermissionType& entry) noexcept { return entry.role_id() == NodeId{0, roleNumeric}; });
}

const RolePermissionType* role_grant(const std::vector<RolePermissionType>& permissions, const NodeId& roleId)
{
  const auto found = std::find_if(permissions.begin(),
    permissions.end(),
    [&roleId](const RolePermissionType& entry) { return entry.role_id() == roleId; });
  return found == permissions.end() ? nullptr : &*found;
}

/// Number of identity rules in a role Object's `Identities` Property. Returns 0
/// when the Property is missing, has no value, or is not an array - i.e. "not
/// mirrored from RoleConfiguration".
size_t identities_count(AddressSpace& addressSpace, uint32_t roleObjectId)
{
  auto roleObject = addressSpace.try_find_node_sync(NodeId{0, roleObjectId});
  if (!roleObject)
    return 0;
  auto refs = roleObject.value().try_get_references_sync();
  if (!refs)
    return 0;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    if (ref.type_id().identifier().get_numeric() != static_cast<uint32_t>(ReferenceTypeId::HasProperty))
      continue;
    auto child = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (!child || static_cast<std::string_view>(child.value().get_browse_name().name()) != "Identities")
      continue;
    auto variable = child.value().as<VariableAccessor>();
    if (!variable)
      return 0;
    auto value = variable->try_read_value_sync();
    if (!value || !value.value().value().is_array())
      return 0;
    return value.value().value().as<Array<RefStructure<Structure>>>().size();
  }
  return 0;
}

constexpr uint32_t roleTypeId = static_cast<uint32_t>(ObjectTypeId::RoleType);
constexpr uint32_t anonymousRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous);
constexpr uint32_t operatorRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Operator);
constexpr uint32_t observerRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Observer);

}  // namespace

// ============================================================================
// Type-level attrs (G.5 inheritance plumbing)
// ============================================================================

// @relation(AC-SVR-ROLESET-MANAGEMENT-ENCRYPTION-POLICY, scope=function)
TEST(RoleSetPopulationTest, RoleSetManagementCallsRequireEncryption)
{
  for (const auto& selection : {std::optional<std::vector<WellKnownRole>>{},
         std::optional<std::vector<WellKnownRole>>{{WellKnownRole::Anonymous}}})
  {
    boost::asio::thread_pool pool{1};
    auto server = create_part18_server(pool.get_executor(), selection, true);
    {
      ServerImplTestAccess access{*server};
      for (const auto method : {MethodId::Server_ServerCapabilities_RoleSet_AddRole,
             MethodId::Server_ServerCapabilities_RoleSet_RemoveRole})
      {
        const auto node = access.address_space().try_find_node_sync(NodeId{method});
        ASSERT_TRUE(node);
        const auto restrictions = node.value().get_access_restrictions();
        ASSERT_TRUE(restrictions.has_value());
        EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::SigningRequired));
        EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
        EXPECT_FALSE(restrictions->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
      }
    }
    server.reset();
    pool.join();
  }
}

TEST(RoleSetPopulationTest, RoleTypeCarriesAdminOnlyRolePermissions)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  auto roleType = access.address_space().try_find_node_sync(NodeId{0, roleTypeId});
  ASSERT_TRUE(roleType);
  auto perms = roleType.value().get_role_permissions();
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(admin_only_role_permissions(*perms));

  auto restrictions = roleType.value().get_access_restrictions();
  ASSERT_TRUE(restrictions.has_value());
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
}

// Part 3 Table 2 / Part 18: Role membership and RolePermissions are security settings. The policy
// authored on RoleType (and copied by AddRole onto every custom Role) grants their management to
// SecurityAdmin alone; ConfigureAdmin may browse and read the Role objects but not change who holds them.
// @relation(AC-SVR-SECADMIN-037-ROLE-MANAGEMENT-IS-SECURITY-ADMIN-ONLY, scope=function)
TEST(RoleSetPopulationTest, RoleTypePolicyGrantsRoleManagementToSecurityAdminAlone)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  auto roleType = access.address_space().try_find_node_sync(NodeId{0, roleTypeId});
  ASSERT_TRUE(roleType);
  auto perms = roleType.value().get_role_permissions();
  ASSERT_TRUE(perms.has_value());

  const NodeId securityAdmin{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)};
  const NodeId configureAdmin{0, static_cast<uint32_t>(ObjectId::WellKnownRole_ConfigureAdmin)};
  bool sawSecurityAdmin = false;
  bool sawConfigureAdmin = false;
  for (const auto& entry : *perms)
  {
    if (entry.role_id() == securityAdmin)
    {
      sawSecurityAdmin = true;
      EXPECT_TRUE(entry.permissions().test(PermissionType::Bit::Call));
      EXPECT_TRUE(entry.permissions().test(PermissionType::Bit::WriteRolePermissions));
    }
    if (entry.role_id() == configureAdmin)
    {
      sawConfigureAdmin = true;
      EXPECT_TRUE(entry.permissions().test(PermissionType::Bit::Browse));
      EXPECT_TRUE(entry.permissions().test(PermissionType::Bit::Read));
      EXPECT_FALSE(entry.permissions().test(PermissionType::Bit::Call))
        << "ConfigureAdmin must not be able to call AddIdentity/RemoveIdentity on a Role";
      EXPECT_FALSE(entry.permissions().test(PermissionType::Bit::WriteRolePermissions))
        << "ConfigureAdmin must not be able to rewrite a Role's RolePermissions";
      EXPECT_FALSE(entry.permissions().test(PermissionType::Bit::Write));
    }
  }
  EXPECT_TRUE(sawSecurityAdmin);
  EXPECT_TRUE(sawConfigureAdmin);
}

// ============================================================================
// Instance-level attrs
// ============================================================================

// From UA-1.05.06 the NodeSet ships RolePermissions on the role Objects, so
// populate_role_set no longer overwrites them. The Anonymous role Object must
// carry the NodeSet-shipped grants - including the spec's `Anonymous: Browse`
// grant that the removed SDK admin-only overwrite would have stripped - proving
// the SDK honours the imported spec values rather than clobbering them.
// @relation(SVR-SECADMIN-058, scope=function)
TEST(RoleSetPopulationTest, AnonymousRoleObjectCarriesNodeSetRolePermissions)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  auto roleObject = access.address_space().try_find_node_sync(NodeId{0, anonymousRoleId});
  ASSERT_TRUE(roleObject);
  auto perms = roleObject.value().get_role_permissions();
  ASSERT_TRUE(perms.has_value()) << "Anonymous role Object must carry NodeSet-shipped RolePermissions";
  EXPECT_TRUE(grants_role(*perms, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)))
    << "SecurityAdmin must retain administrative access to the role Object";
  EXPECT_TRUE(grants_role(*perms, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)))
    << "the spec's Anonymous:Browse grant must survive - the SDK must not overwrite it with admin-only perms";
  EXPECT_FALSE(admin_only_role_permissions(*perms))
    << "the SDK admin-only overwrite must no longer be applied to role instances";
}

// The role Object's children (Identities/Applications/Endpoints Properties + the
// management Methods) carry the NodeSet-shipped RolePermissions (SecurityAdmin) +
// AccessRestrictions=3 (Signing+Encryption). Part 18 section 4.4.1 additionally
// requires the encrypted-channel condition to govern Browse, so population merges
// ApplyRestrictionsToBrowse while preserving every NodeSet-supplied bit and grant.
// @relation(AC-SVR-SECADMIN-025-ROLETYPE-ADMIN-ENCRYPTED, scope=function)
TEST(RoleSetPopulationTest, RoleChildPropertiesCarryNodeSetAttrs)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  auto roleObject = access.address_space().try_find_node_sync(NodeId{0, anonymousRoleId});
  ASSERT_TRUE(roleObject);
  auto roleRestrictions = roleObject.value().get_access_restrictions();
  ASSERT_TRUE(roleRestrictions.has_value());
  EXPECT_TRUE(roleRestrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
  EXPECT_TRUE(roleRestrictions->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
  auto refs = roleObject.value().try_get_references_sync();
  ASSERT_TRUE(refs);

  bool sawChild = false;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    const auto type = ref.type_id().identifier().get_numeric();
    if (type != static_cast<uint32_t>(ReferenceTypeId::HasProperty) &&
        type != static_cast<uint32_t>(ReferenceTypeId::HasComponent))
      continue;
    auto child = access.address_space().try_find_node_sync(ref.target_id().node_id());
    if (!child)
      continue;
    // `get_browse_name` returns by value; `childName` outlives the statement, so the QualifiedName it
    // views must be a named local rather than a temporary.
    const QualifiedName childBrowseName = child.value().get_browse_name();
    const auto childName = static_cast<std::string_view>(childBrowseName.name());
    auto perms = child.value().get_role_permissions();
    auto restr = child.value().get_access_restrictions();
    EXPECT_TRUE(perms.has_value()) << "Child " << childName << " missing RolePermissions";
    EXPECT_TRUE(restr.has_value()) << "Child " << childName << " missing AccessRestrictions";
    if (perms && restr)
    {
      EXPECT_TRUE(grants_role(*perms, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)))
        << "Child " << childName << " must grant SecurityAdmin per the NodeSet";
      // Part 18 section 4.4.1: the per-role surface requires an encrypted channel
      // (NodeSet ships AccessRestrictions=3 = Signing + Encryption).
      EXPECT_TRUE(restr->test(AccessRestrictionType::Bit::SigningRequired));
      EXPECT_TRUE(restr->test(AccessRestrictionType::Bit::EncryptionRequired));
      EXPECT_TRUE(restr->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
    }
    sawChild = true;
  }
  EXPECT_TRUE(sawChild) << "Anonymous role Object must have at least one HasProperty/HasComponent child";
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-NORMAL-POLICY, scope=function)
TEST(RoleSetPopulationTest, RoleManagementAccessMaterializesExactOrdinaryPolicyOnlyOnRoleSurface)
{
  boost::asio::thread_pool pool;
  auto roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::Engineer, IdentityCriteriaType::UserName, String{"engineer"}}});
  const NodeId engineerRole{ObjectId::WellKnownRole_Engineer};
  ASSERT_TRUE(roleConfiguration->grant_role_management_access({engineerRole}).is_good());
  auto server = create_part18_server(pool.get_executor(), std::nullopt, true, false, roleConfiguration);
  ServerImplTestAccess access{*server};

  const std::array<NodeId, 4> managementNodes{NodeId{ObjectId::Server_ServerCapabilities_RoleSet},
    NodeId{MethodId::Server_ServerCapabilities_RoleSet_AddRole},
    NodeId{ObjectId::WellKnownRole_Operator},
    NodeId{MethodId::WellKnownRole_Operator_AddIdentity}};
  const NodeId securityAdminRole{ObjectId::WellKnownRole_SecurityAdmin};
  for (const auto& nodeId : managementNodes)
  {
    auto node = access.address_space().try_find_node_sync(nodeId);
    ASSERT_TRUE(node.is_good()) << nodeId.as_definition();
    const auto permissions = node.value().get_role_permissions();
    ASSERT_TRUE(permissions.has_value()) << nodeId.as_definition();
    const auto* securityAdmin = role_grant(*permissions, securityAdminRole);
    const auto* engineer = role_grant(*permissions, engineerRole);
    ASSERT_NE(securityAdmin, nullptr) << nodeId.as_definition();
    ASSERT_NE(engineer, nullptr) << nodeId.as_definition();
    EXPECT_EQ(engineer->permissions(), securityAdmin->permissions())
      << "the helper must derive the node-specific grant rather than apply one magic mask";
  }

  auto updateCertificate =
    access.address_space().try_find_node_sync(NodeId{MethodId::ServerConfiguration_UpdateCertificate});
  ASSERT_TRUE(updateCertificate.is_good());
  const auto unrelatedPermissions = updateCertificate.value().get_role_permissions();
  ASSERT_TRUE(unrelatedPermissions.has_value());
  EXPECT_EQ(role_grant(*unrelatedPermissions, engineerRole), nullptr)
    << "Role-management authoring must not widen the Part 12 SecurityAdmin-only surface";
}

// The RoleType baseline is authored once, at NS0 import, and a Role the deployment designates through
// grant_role_management_access keeps SecurityAdmin-equivalent access on it (and so on every Role
// AddRole creates from it): populate_role_set must not replace that policy with a second copy. The
// designated Role is Engineer, which no re-stamp ever carried, so a returning second copy of either
// shape reddens the arm; the ConfigureAdmin entry pins the baseline's Browse|Read shape alongside.
// @relation(AC-SVR-SECADMIN-037-ROLE-MANAGEMENT-IS-SECURITY-ADMIN-ONLY, scope=function)
TEST(RoleSetPopulationTest, ADesignatedRoleKeepsItsManagementAccessOnTheRoleTypeBaseline)
{
  boost::asio::thread_pool pool;
  auto roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::Engineer, IdentityCriteriaType::UserName, String{"engineer"}}});
  const NodeId engineerRole{ObjectId::WellKnownRole_Engineer};
  const NodeId configureAdminRole{ObjectId::WellKnownRole_ConfigureAdmin};
  const NodeId securityAdminRole{ObjectId::WellKnownRole_SecurityAdmin};
  ASSERT_TRUE(roleConfiguration->grant_role_management_access({engineerRole}).is_good());
  auto server = create_part18_server(pool.get_executor(), std::nullopt, true, false, roleConfiguration);
  ServerImplTestAccess access{*server};

  for (const auto& nodeId : {NodeId{0, roleTypeId}, NodeId{MethodId::RoleType_AddIdentity}})
  {
    auto node = access.address_space().try_find_node_sync(nodeId);
    ASSERT_TRUE(node.is_good()) << nodeId.as_definition();
    const auto permissions = node.value().get_role_permissions();
    ASSERT_TRUE(permissions.has_value()) << nodeId.as_definition();
    const auto* securityAdmin = role_grant(*permissions, securityAdminRole);
    const auto* engineer = role_grant(*permissions, engineerRole);
    const auto* configureAdmin = role_grant(*permissions, configureAdminRole);
    ASSERT_NE(securityAdmin, nullptr) << nodeId.as_definition();
    ASSERT_NE(engineer, nullptr)
      << "a designated Role's management access on the RoleType baseline must survive server start: "
      << nodeId.as_definition();
    EXPECT_EQ(engineer->permissions(), securityAdmin->permissions()) << nodeId.as_definition();
    EXPECT_TRUE(engineer->permissions().test(PermissionType::Bit::Call)) << nodeId.as_definition();
    ASSERT_NE(configureAdmin, nullptr) << nodeId.as_definition();
    EXPECT_FALSE(configureAdmin->permissions().test(PermissionType::Bit::Call))
      << "the baseline itself still gives ConfigureAdmin Browse|Read only: " << nodeId.as_definition();
  }
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-ATOMIC-VALIDATION, scope=function)
TEST(RoleSetPopulationTest, RoleManagementAccessValidationIsAtomicAndRich)
{
  boost::asio::thread_pool pool;
  auto roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::Engineer, IdentityCriteriaType::UserName, String{"engineer"}}});
  const NodeId engineerRole{ObjectId::WellKnownRole_Engineer};
  const auto empty = roleConfiguration->grant_role_management_access({});
  EXPECT_EQ(empty.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(empty.shared_detail(), nullptr);
  EXPECT_EQ(empty.shared_detail()->code, "RoleManagementAccessEmpty");
  const auto nullRole = roleConfiguration->grant_role_management_access({engineerRole, NodeId{}});
  EXPECT_EQ(nullRole.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(nullRole.shared_detail(), nullptr);
  EXPECT_EQ(nullRole.shared_detail()->code, "RoleManagementAccessRoleNull");
  const auto invalid = roleConfiguration->grant_role_management_access({engineerRole, NodeId{1, 999999U}});
  EXPECT_EQ(invalid.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(invalid.shared_detail(), nullptr);
  EXPECT_EQ(invalid.shared_detail()->code, "RoleManagementAccessRoleUnknown");

  auto server = create_part18_server(pool.get_executor(), std::nullopt, true, false, roleConfiguration);
  ServerImplTestAccess access{*server};
  for (const auto nodeId : {NodeId{ObjectId::Server_ServerCapabilities_RoleSet},
         NodeId{MethodId::Server_ServerCapabilities_RoleSet_AddRole}})
  {
    auto node = access.address_space().try_find_node_sync(nodeId);
    ASSERT_TRUE(node.is_good());
    const auto permissions = node.value().get_role_permissions();
    ASSERT_TRUE(permissions.has_value());
    EXPECT_EQ(role_grant(*permissions, engineerRole), nullptr)
      << "a valid prefix of an invalid batch must not be retained";
  }
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-ATOMIC-VALIDATION, scope=function)
TEST(RoleSetPopulationTest, RoleManagementAccessCannotBeAuthoredAfterServerConsumption)
{
  boost::asio::thread_pool pool;
  auto roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::Engineer, IdentityCriteriaType::UserName, String{"engineer"}}});
  auto server = create_part18_server(pool.get_executor(), std::nullopt, true, false, roleConfiguration);
  ServerImplTestAccess access{*server};
  const NodeId engineerRole{ObjectId::WellKnownRole_Engineer};
  auto roleSet =
    access.address_space().try_find_node_sync(NodeId{ObjectId::Server_ServerCapabilities_RoleSet});
  ASSERT_TRUE(roleSet.is_good());
  const auto before = roleSet.value().get_role_permissions();

  const auto late = roleConfiguration->grant_role_management_access({engineerRole});
  EXPECT_EQ(late.status_code().as_status(), Status::BadInvalidState);
  ASSERT_NE(late.shared_detail(), nullptr);
  EXPECT_EQ(late.shared_detail()->code, "RoleManagementAccessAlreadyConsumed");
  EXPECT_EQ(roleSet.value().get_role_permissions(), before);
}

// ============================================================================
// Variable values mirror RoleConfiguration
// ============================================================================

// @relation(SVR-SECADMIN-059, scope=function)
TEST(RoleSetPopulationTest, AnonymousIdentitiesVariableContainsAnonymousRule)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  // Locate the Anonymous role's Identities Property by walking HasProperty refs.
  auto roleObject = access.address_space().try_find_node_sync(NodeId{0, anonymousRoleId});
  ASSERT_TRUE(roleObject);
  auto refs = roleObject.value().try_get_references_sync();
  ASSERT_TRUE(refs);

  optional<NodeAccessor> identitiesNode;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    if (ref.type_id().identifier().get_numeric() != static_cast<uint32_t>(ReferenceTypeId::HasProperty))
      continue;
    auto child = access.address_space().try_find_node_sync(ref.target_id().node_id());
    if (child && static_cast<std::string_view>(
                   static_cast<std::string_view>(child.value().get_browse_name().name())) == "Identities")
    {
      identitiesNode = child.value();
      break;
    }
  }
  ASSERT_TRUE(identitiesNode);

  auto variable = identitiesNode->as<VariableAccessor>();
  ASSERT_TRUE(variable);
  auto value = variable->try_read_value_sync();
  ASSERT_TRUE(value);

  // Anonymous identity rule is the first element in the array of structures.
  ASSERT_TRUE(value.value().value().is_array())
    << "Identities Variable must contain an array of identity mapping rules";
  const auto& arr = value.value().value().as<Array<RefStructure<Structure>>>();
  ASSERT_GE(arr.size(), 1u);
  const auto* rule = dynamic_cast<const IdentityMappingRuleType*>(arr.payload()[0].get());
  ASSERT_NE(rule, nullptr);
  EXPECT_EQ(rule->criteria_type(), IdentityCriteriaType::Anonymous);
}

// Part 18 section 4.3 L408-414 + CTT v1.05.06 `Security Role Well Known Group 2/002.js`:
// Anonymous Role default Identities must contain BOTH an `Anonymous` rule AND
// an `AuthenticatedUser` rule, so a caller authenticated under any token kind
// still inherits the Anonymous role. Without the second rule, anything granted
// only to Anonymous would silently disappear after authentication - a common
// cert-failure mode flagged in Step 4 section 3.1 CP-2.
// @relation(AC-SVR-SECADMIN-059-ANONYMOUS-IDENTITIES, scope=function)
TEST(RoleSetPopulationTest, AnonymousIdentitiesAlsoContainsAuthenticatedUserRule)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  auto roleObject = access.address_space().try_find_node_sync(NodeId{0, anonymousRoleId});
  ASSERT_TRUE(roleObject);
  auto refs = roleObject.value().try_get_references_sync();
  ASSERT_TRUE(refs);

  optional<NodeAccessor> identitiesNode;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    if (ref.type_id().identifier().get_numeric() != static_cast<uint32_t>(ReferenceTypeId::HasProperty))
      continue;
    auto child = access.address_space().try_find_node_sync(ref.target_id().node_id());
    if (child && static_cast<std::string_view>(
                   static_cast<std::string_view>(child.value().get_browse_name().name())) == "Identities")
    {
      identitiesNode = child.value();
      break;
    }
  }
  ASSERT_TRUE(identitiesNode);

  auto variable = identitiesNode->as<VariableAccessor>();
  ASSERT_TRUE(variable);
  auto value = variable->try_read_value_sync();
  ASSERT_TRUE(value);
  ASSERT_TRUE(value.value().value().is_array());

  const auto& arr = value.value().value().as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(arr.size(), 2u) << "Anonymous Identities must contain exactly two default rules";

  bool foundAnonymous = false;
  bool foundAuthenticatedUser = false;
  for (size_t i = 0; i < arr.size(); ++i)
  {
    const auto* rule = dynamic_cast<const IdentityMappingRuleType*>(arr.payload()[i].get());
    ASSERT_NE(rule, nullptr);
    if (rule->criteria_type() == IdentityCriteriaType::Anonymous)
      foundAnonymous = true;
    if (rule->criteria_type() == IdentityCriteriaType::AuthenticatedUser)
      foundAuthenticatedUser = true;
  }
  EXPECT_TRUE(foundAnonymous) << "Anonymous Identities must include an Anonymous-criteria rule";
  EXPECT_TRUE(foundAuthenticatedUser)
    << "Anonymous Identities must include an AuthenticatedUser-criteria rule "
       "(Part 18 section 4.3 L408-414 + CTT v1.05.06 Security Role Well Known Group 2/002.js)";
}

TEST(RoleSetPopulationTest, OperatorIdentitiesVariableIsEmptyByDefault)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());
  ServerImplTestAccess access{*server};

  auto roleObject = access.address_space().try_find_node_sync(NodeId{0, operatorRoleId});
  ASSERT_TRUE(roleObject);
  auto refs = roleObject.value().try_get_references_sync();
  ASSERT_TRUE(refs);

  optional<NodeAccessor> identitiesNode;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    if (ref.type_id().identifier().get_numeric() != static_cast<uint32_t>(ReferenceTypeId::HasProperty))
      continue;
    auto child = access.address_space().try_find_node_sync(ref.target_id().node_id());
    if (child && static_cast<std::string_view>(
                   static_cast<std::string_view>(child.value().get_browse_name().name())) == "Identities")
    {
      identitiesNode = child.value();
      break;
    }
  }
  ASSERT_TRUE(identitiesNode);
  auto variable = identitiesNode->as<VariableAccessor>();
  ASSERT_TRUE(variable);
  auto value = variable->try_read_value_sync();
  ASSERT_TRUE(value);
  ASSERT_TRUE(value.value().value().is_array());
  EXPECT_EQ(value.value().value().as<Array<RefStructure<Structure>>>().size(), 0u);
}

// @relation(AC-SVR-AUTHZ-025-CLAIM-PATH-ADMINISTERS-NS0, scope=function)
TEST(RoleSetPopulationTest, ClaimPathPublishesItsRuleAndCustomConfiguration)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), std::nullopt, false, true);
  ServerImplTestAccess access{*server};
  const NodeId securityAdminRole{ObjectId::WellKnownRole_SecurityAdmin};

  auto definition = access.role_configuration()->get_role(securityAdminRole);
  ASSERT_TRUE(definition.has_value());
  ASSERT_TRUE(definition->customConfiguration);
  ASSERT_EQ(definition->identities.size(), 1u);
  EXPECT_EQ(definition->identities.front().criteria_type(), IdentityCriteriaType::Role);
  EXPECT_EQ(static_cast<std::string_view>(definition->identities.front().criteria()), "SecurityAdmin");

  auto property = access.address_space().try_find_node_sync(
    NodeId{VariableId::WellKnownRole_SecurityAdmin_CustomConfiguration});
  ASSERT_TRUE(property.is_good());
  auto variable = property.value().as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  auto value = variable->try_read_value_sync();
  ASSERT_TRUE(value.is_good());
  ASSERT_NE(value.value().value().try_as<bool>(), nullptr);
  EXPECT_TRUE(*value.value().value().try_as<bool>());

  auto disabledServer = create_part18_server(tp.get_executor());
  ServerImplTestAccess disabledAccess{*disabledServer};
  auto disabledDefinition = disabledAccess.role_configuration()->get_role(securityAdminRole);
  ASSERT_TRUE(disabledDefinition.has_value());
  EXPECT_FALSE(disabledDefinition->customConfiguration);
  EXPECT_TRUE(disabledDefinition->identities.empty());
}

// ============================================================================
// Selection
// ============================================================================

// @relation(SVR-BASE-014, SVR-SECADMIN-058, SVR-SECADMIN-069, scope=function)
// @relation(AC-SVR-SECADMIN-025-ROLETYPE-ADMIN-ENCRYPTED, scope=function)
TEST(RoleSetPopulationTest, SelectionRestrictsRolePopulation)
{
  // RolePermissions/AccessRestrictions now come from the NodeSet for every role
  // regardless of selection, so the remaining selection-gated SDK behaviour is
  // the runtime Variable mirroring. With selection = {Anonymous}: Anonymous's
  // Identities Variable is mirrored from RoleConfiguration (its seeded rules),
  // while Observer - not selected - keeps its empty NodeSet-default Identities.
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor(), std::vector<WellKnownRole>{WellKnownRole::Anonymous});
  ServerImplTestAccess access{*server};

  EXPECT_GT(identities_count(access.address_space(), anonymousRoleId), 0u)
    << "selected Anonymous must have its Identities mirrored from RoleConfiguration";
  EXPECT_EQ(identities_count(access.address_space(), observerRoleId), 0u)
    << "unselected Observer must keep its empty NodeSet-default Identities (not mirrored)";
  auto observer = access.address_space().try_find_node_sync(NodeId{0, observerRoleId});
  ASSERT_TRUE(observer);
  const auto restrictions = observer.value().get_access_restrictions();
  ASSERT_TRUE(restrictions.has_value());
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse))
    << "selection must not weaken the security profile of an unmirrored Role";
}

// SVR-SECADMIN-058: with no selector (default), all 9 well-known Role Objects
// are materialised under Server.ServerCapabilities.RoleSet (Part 18 section 4.3 Table 2
// rows). TrustedApplication (069, NodeId 18625) is included since the NodeSet
// pin moved to UA-1.05.06.
// @relation(SVR-SECADMIN-058, scope=function)
TEST(RoleSetPopulationTest, AllWellKnownRolesMaterialisedByDefault)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());  // default selection = all
  ServerImplTestAccess access{*server};

  for (const ObjectId wellKnownRole : {ObjectId::WellKnownRole_Anonymous,
         ObjectId::WellKnownRole_AuthenticatedUser,
         ObjectId::WellKnownRole_Observer,
         ObjectId::WellKnownRole_Operator,
         ObjectId::WellKnownRole_Engineer,
         ObjectId::WellKnownRole_Supervisor,
         ObjectId::WellKnownRole_ConfigureAdmin,
         ObjectId::WellKnownRole_SecurityAdmin,
         ObjectId::WellKnownRole_TrustedApplication})
  {
    const uint32_t roleObjectId = static_cast<uint32_t>(wellKnownRole);
    auto roleObject = access.address_space().try_find_node_sync(NodeId{0, roleObjectId});
    ASSERT_TRUE(roleObject) << "well-known role Object " << roleObjectId << " must be materialised";
    EXPECT_TRUE(roleObject.value().get_role_permissions().has_value())
      << "well-known role Object " << roleObjectId << " must carry NodeSet-shipped RolePermissions";
  }
}

// SVR-SECADMIN-069: the TrustedApplication well-known Role (NodeId 18625, added
// in UA-1.05.04) is materialised and self-seeds the TrustedApplication identity
// criteria so a trusted-application Session is granted the Role automatically.
// @relation(SVR-SECADMIN-069, scope=function)
TEST(RoleSetPopulationTest, TrustedApplicationRoleMaterialisedWhenSelected)
{
  boost::asio::thread_pool tp;
  auto server =
    create_part18_server(tp.get_executor(), std::vector<WellKnownRole>{WellKnownRole::TrustedApplication});
  ServerImplTestAccess access{*server};

  const NodeId trustedAppRole{0, static_cast<uint32_t>(ObjectId::WellKnownRole_TrustedApplication)};

  // The Object is materialised and carries the NodeSet-shipped RolePermissions.
  auto roleObject = access.address_space().try_find_node_sync(trustedAppRole);
  ASSERT_TRUE(roleObject);
  EXPECT_TRUE(roleObject.value().get_role_permissions().has_value());

  // RoleConfiguration carries the role + its self-seeded TrustedApplication rule.
  ASSERT_NE(access.role_configuration(), nullptr);
  auto def = access.role_configuration()->get_role(trustedAppRole);
  ASSERT_TRUE(def.has_value());
  ASSERT_EQ(def->identities.size(), 1u);
  EXPECT_EQ(def->identities[0].criteria_type(), IdentityCriteriaType::TrustedApplication);
}

// ============================================================================
// RoleSet membership (what a client sees when it browses the RoleSet Object)
// ============================================================================

namespace
{

constexpr uint32_t roleSetId = static_cast<uint32_t>(ObjectId::Server_ServerCapabilities_RoleSet);

/// Targets of the forward `HasComponent` references of
/// `Server.ServerCapabilities.RoleSet` - the membership a client enumerates when
/// it browses the RoleSet Object (the NodeSet models each Role as a HasComponent
/// child of `i=15606`, and `AddRole` links new Roles the same way).
std::vector<NodeId> role_set_child_ids(AddressSpace& addressSpace)
{
  std::vector<NodeId> children;
  auto roleSet = addressSpace.try_find_node_sync(NodeId{0, roleSetId});
  if (!roleSet)
    return children;
  auto refs = roleSet.value().try_get_references_sync();
  if (!refs)
    return children;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    if (ref.type_id().identifier().get_numeric() != static_cast<uint32_t>(ReferenceTypeId::HasComponent))
      continue;
    children.push_back(ref.target_id().node_id());
  }
  return children;
}

/// True iff `nodeId` resolves to a Node whose `HasTypeDefinition` target is
/// `RoleType` - i.e. the Node is browsable *as a Role*, not merely present.
bool has_role_type_definition(AddressSpace& addressSpace, const NodeId& nodeId)
{
  auto node = addressSpace.try_find_node_sync(nodeId);
  if (!node)
    return false;
  auto refs = node.value().try_get_references_sync();
  if (!refs)
    return false;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    if (ref.type_id().identifier().get_numeric() != static_cast<uint32_t>(ReferenceTypeId::HasTypeDefinition))
      continue;
    if (ref.target_id().node_id() == NodeId{0, roleTypeId})
      return true;
  }
  return false;
}

bool contains_node(const std::vector<NodeId>& ids, const NodeId& id)
{
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

/// Part-18 server whose `RoleConfiguration` the host pre-populates before
/// startup wiring runs - the shape `ServerComponents::roleConfiguration`
/// documents ("skipping any role already pre-populated by the host").
shared_ptr<ServerImpl> create_part18_server_with_config(
  boost::asio::any_io_executor ex, std::shared_ptr<RoleConfiguration> roleConfig)
{
  auto frozen = make_frozen_config();
  ::ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.roleConfiguration = std::move(roleConfig);
  return ServerImpl::create(ex, std::move(frozen), std::move(components));
}

}  // namespace

// Part 5 section 6.3 / Part 18 section 4.3: the RoleSet Object is the container a
// client browses to discover the Roles a Server knows about, and every Role in it
// must be an Object of RoleType. A plausible implementation materialises the Role
// Nodes at their well-known NodeIds - so a direct read of `i=15644` succeeds -
// while leaving them unreferenced from `Server.ServerCapabilities.RoleSet`, or
// links them without a RoleType TypeDefinition; a client that only ever browses
// then sees an empty or untyped RoleSet and cannot preview its authorization.
// @verifies AC-SVR-BASE-014-ROLESET-EXPOSED
TEST(RoleSetPopulationTest, ConfiguredRolesAreBrowsableUnderRoleSetAsRoleTypeObjects)
{
  boost::asio::thread_pool tp;
  auto server = create_part18_server(tp.get_executor());  // default selection = all
  ServerImplTestAccess access{*server};
  ASSERT_NE(access.role_configuration(), nullptr);

  auto roleSet = access.address_space().try_find_node_sync(NodeId{0, roleSetId});
  ASSERT_TRUE(roleSet) << "Server.ServerCapabilities.RoleSet must exist";

  const auto children = role_set_child_ids(access.address_space());
  ASSERT_FALSE(children.empty()) << "RoleSet browsed to zero Role children";

  size_t configuredRoles = 0;
  for (const ObjectId wellKnownRole : {ObjectId::WellKnownRole_Anonymous,
         ObjectId::WellKnownRole_AuthenticatedUser,
         ObjectId::WellKnownRole_Observer,
         ObjectId::WellKnownRole_Operator,
         ObjectId::WellKnownRole_Engineer,
         ObjectId::WellKnownRole_Supervisor,
         ObjectId::WellKnownRole_ConfigureAdmin,
         ObjectId::WellKnownRole_SecurityAdmin,
         ObjectId::WellKnownRole_TrustedApplication})
  {
    const uint32_t roleObjectId = static_cast<uint32_t>(wellKnownRole);
    const NodeId roleId{0, roleObjectId};

    // "Configured" is read back from the live RoleConfiguration the server
    // seeded, so the expectation is derived from the server's own configuration
    // rather than asserted by the test.
    if (!access.role_configuration()->get_role(roleId).has_value())
      continue;
    ++configuredRoles;

    EXPECT_TRUE(contains_node(children, roleId))
      << "configured Role " << roleObjectId << " must be reachable by browsing the RoleSet";
    EXPECT_TRUE(has_role_type_definition(access.address_space(), roleId))
      << "configured Role " << roleObjectId << " must be an Object of RoleType";
  }
  ASSERT_GT(configuredRoles, 0u) << "no Role was configured - the assertions above would be vacuous";
}

// @relation(AC-SVR-AUTHZ-028-NO-ROLE-MATERIALISED-PUBLISHES-EMPTY, scope=function)
TEST(RoleSetPopulationTest, EmptySelectionLeavesNoRoleObjectBrowsableUnderRoleSet)
{
  boost::asio::thread_pool threadPool;
  auto server = create_part18_server(threadPool.get_executor(), std::vector<WellKnownRole>{});
  ServerImplTestAccess access{*server};

  ASSERT_TRUE(access.role_configuration()->roles().empty());
  const auto children = role_set_child_ids(access.address_space());
  for (const auto& child : children)
  {
    EXPECT_FALSE(has_role_type_definition(access.address_space(), child));
  }
}

// Part 5 section 6.3 / SVR-BASE-014: *every* Role declared by the application -
// not only the well-known ones - appears as a child Object of
// `Server.ServerCapabilities.RoleSet`, because clients use the RoleSet for
// authorization preview and a Role that is enforced but invisible cannot be
// previewed. The plausible implementation mirrors only the well-known Role table
// into the address space, so a Role the host pre-populates into the
// `RoleConfiguration` it supplies via `ServerComponents` is honoured by the
// Role evaluator yet never surfaces under the RoleSet.
// @verifies AC-SVR-BASE-014-ROLESET-EXPOSED
// @relation(AC-SVR-SECADMIN-025-ROLETYPE-ADMIN-ENCRYPTED, scope=function)
TEST(RoleSetPopulationTest, HostDeclaredRoleIsBrowsableUnderRoleSetAsARoleTypeObject)
{
  // The host's own namespace (index 1 is the server's application URI) is where
  // a vendor Role belongs; NS0 is reserved for the spec-defined Roles.
  const NodeId customRoleId{1, 42000u};

  auto roleConfig = std::make_shared<RoleConfiguration>();
  RoleConfiguration::RoleDefinition custom;
  custom.roleId = customRoleId;
  custom.roleBit = 40;  // outside the well-known band (bits 0-8)
  custom.browseName = QualifiedName{1, "HostDeclaredRole"};
  ASSERT_TRUE(roleConfig->add_role(std::move(custom)));

  boost::asio::thread_pool tp;
  auto server = create_part18_server_with_config(tp.get_executor(), roleConfig);
  ServerImplTestAccess access{*server};

  // The Role survived startup wiring as a configured Role: the antecedent is
  // established by the server's own seeding pass, not by the test.
  ASSERT_NE(access.role_configuration(), nullptr);
  ASSERT_TRUE(access.role_configuration()->get_role(customRoleId).has_value())
    << "the host-declared Role must remain configured after well-known seeding";

  const auto children = role_set_child_ids(access.address_space());
  ASSERT_FALSE(children.empty()) << "RoleSet browsed to zero Role children";

  EXPECT_TRUE(contains_node(children, customRoleId))
    << "the host-declared Role must be reachable by browsing the RoleSet";
  EXPECT_TRUE(has_role_type_definition(access.address_space(), customRoleId))
    << "the host-declared Role must be an Object of RoleType";
  auto customRole = access.address_space().try_find_node_sync(customRoleId);
  ASSERT_TRUE(customRole);
  const auto restrictions = customRole.value().get_access_restrictions();
  ASSERT_TRUE(restrictions.has_value());
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
}
