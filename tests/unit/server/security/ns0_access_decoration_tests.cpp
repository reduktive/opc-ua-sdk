// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "nodeset_ns0.h"
#include "test_utilities.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_datatype_id.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_method_id.h"
#include "ua_ns0_access_decoration.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"
#include "ua_well_known_role_permissions.h"

#include <algorithm>
#include <array>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace ua;
using namespace ua::server;
using namespace ua::xml::nodeset;

namespace
{

/// Parses NS0 once for the whole suite: the function under test is pure, so there is no per-test state
/// to isolate and parsing is by far the dominant cost.
class Ns0AccessDecorationTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    sThreadPool = new boost::asio::thread_pool{1};
    sAddressSpace = new AddressSpace{AddressSpace::create("", sThreadPool->get_executor())};
    sStructureFactory = new StructureFactory{};

    memory_stream_device::ExternalReadOnly streamDevice{utils::span_of_char_to_span_of_byte(nodesetNs0)};
    const MemoryStream inputStream{streamDevice};
    const auto configuration = ApplicationConfig::load_default();
    sNodeSets = new std::vector<shared_ptr<NodeSet>>{Parser::parse(make_encoding_limits(configuration),
      inputStream,
      *sStructureFactory,
      sAddressSpace->namespace_array(),
      sAddressSpace->server_array(),
      Parser::GetDependentModelCallback{})};
    ASSERT_EQ(sNodeSets->size(), 1U);

    sDecoration = new ImportEngine::AccessDecorationMap{compute_ns0_access_decoration(*sNodeSets->front())};
  }

  static void TearDownTestSuite()
  {
    delete sDecoration;
    sDecoration = nullptr;
    delete sNodeSets;
    sNodeSets = nullptr;
    delete sStructureFactory;
    sStructureFactory = nullptr;
    delete sAddressSpace;
    sAddressSpace = nullptr;
    ::ua::test_utils::drain_with_timeout(*sThreadPool);
    delete sThreadPool;
    sThreadPool = nullptr;
  }

  /// The array that governs `nodeId` once imported: the stamp when there is one, the NodeSet's own
  /// declaration otherwise, and namespace 0's DefaultRolePermissions when neither speaks (Part 3 5.2.9) -
  /// each well-known Role with its general mask, as the server installs it when every Role is configured.
  /// Arms assert against this rather than against the map, so they measure the resulting posture rather
  /// than the presence of an entry.
  static std::vector<RolePermissionType> effective_array(
    const ImportEngine::AccessDecorationMap& decoration, const NodeId& nodeId)
  {
    const auto stamped = decoration.find(nodeId);
    if (stamped != decoration.end() && stamped->second.rolePermissions)
    {
      return *stamped->second.rolePermissions;
    }
    auto* node = sNodeSets->front()->find_node(nodeId);
    if (!node)
      return {};
    auto declared = node->role_permissions();
    if (!declared.empty() || node->has_no_permissions())
      return declared;
    return well_known_role_default_permissions(well_known_roles());
  }

  /// True when neither the decoration nor the NodeSet gives `nodeId` an array, so the namespace default
  /// governs it.
  static bool takes_the_namespace_default(const NodeId& nodeId)
  {
    const auto stamped = sDecoration->find(nodeId);
    if (stamped != sDecoration->end() && stamped->second.rolePermissions)
      return false;
    auto* node = sNodeSets->front()->find_node(nodeId);
    return node != nullptr && node->role_permissions().empty() && !node->has_no_permissions();
  }

  static std::vector<RolePermissionType> effective_array(const NodeId& nodeId)
  {
    return effective_array(*sDecoration, nodeId);
  }

  static std::optional<PermissionType> permissions_of(const NodeId& nodeId, WellKnownRole role)
  {
    const NodeId roleId = well_known_role_node_id(role);
    for (const auto& entry : effective_array(nodeId))
    {
      if (entry.role_id() == roleId)
      {
        return entry.permissions();
      }
    }
    return std::nullopt;
  }

  /// The AccessRestrictions the import will write for `nodeId`: the stamp when there is one, the
  /// NodeSet's own declaration otherwise.
  static std::optional<AccessRestrictionType> effective_restrictions(const NodeId& nodeId)
  {
    const auto stamped = sDecoration->find(nodeId);
    if (stamped != sDecoration->end() && stamped->second.accessRestrictions)
    {
      return *stamped->second.accessRestrictions;
    }
    auto* node = sNodeSets->front()->find_node(nodeId);
    if (!node)
      return std::nullopt;
    return node->access_restrictions();
  }

  static bool is_stamped(const NodeId& nodeId)
  {
    const auto found = sDecoration->find(nodeId);
    return found != sDecoration->end() && found->second.rolePermissions.has_value();
  }

  static shared_ptr<NodeSet> parse_independent_ns0()
  {
    memory_stream_device::ExternalReadOnly streamDevice{utils::span_of_char_to_span_of_byte(nodesetNs0)};
    const MemoryStream inputStream{streamDevice};
    const auto configuration = ApplicationConfig::load_default();
    auto nodeSets = Parser::parse(make_encoding_limits(configuration),
      inputStream,
      *sStructureFactory,
      sAddressSpace->namespace_array(),
      sAddressSpace->server_array(),
      Parser::GetDependentModelCallback{});
    if (nodeSets.size() != 1U)
    {
      throw std::runtime_error{"The shipped NS0 fixture did not parse as one NodeSet"};
    }
    return std::move(nodeSets.front());
  }

  static shared_ptr<NodeSet> parse_independent_nodeset(std::span<const char> source)
  {
    memory_stream_device::ExternalReadOnly streamDevice{utils::span_of_char_to_span_of_byte(source)};
    const MemoryStream inputStream{streamDevice};
    const auto configuration = ApplicationConfig::load_default();
    auto nodeSets = Parser::parse(make_encoding_limits(configuration),
      inputStream,
      *sStructureFactory,
      sAddressSpace->namespace_array(),
      sAddressSpace->server_array(),
      Parser::GetDependentModelCallback{});
    if (nodeSets.size() != 1U)
    {
      throw std::runtime_error{"The malformed-policy fixture did not parse as one NodeSet"};
    }
    return std::move(nodeSets.front());
  }

  static void expect_bad_configuration(const NodeSet& nodeSet, std::span<const NodeId> roleIds,
    std::string_view detailCode, const NodeId& offendingNode)
  {
    try
    {
      (void)compute_ns0_access_decoration(nodeSet, roleIds);
      FAIL() << "malformed Role-management policy unexpectedly produced a decoration";
    }
    catch (const UaException& exception)
    {
      EXPECT_EQ(exception.status(), Status::BadConfigurationError);
      const auto* detail = exception.detail();
      ASSERT_NE(detail, nullptr);
      EXPECT_EQ(detail->code, detailCode);
      ASSERT_EQ(detail->context.size(), 1U);
      EXPECT_EQ(detail->context.front().key, ContextKeys::nodeId.value());
      EXPECT_EQ(detail->context.front().value, offendingNode.as_definition());
    }
    catch (...)
    {
      FAIL() << "malformed Role-management policy lost its UaException/ErrorDetail";
    }
    EXPECT_FALSE(sDecoration->empty()) << "an independent malformed input mutated the shipped plan";
  }

  static boost::asio::thread_pool* sThreadPool;
  static AddressSpace* sAddressSpace;
  static StructureFactory* sStructureFactory;
  static std::vector<shared_ptr<NodeSet>>* sNodeSets;
  static ImportEngine::AccessDecorationMap* sDecoration;
};

boost::asio::thread_pool* Ns0AccessDecorationTest::sThreadPool{nullptr};
AddressSpace* Ns0AccessDecorationTest::sAddressSpace{nullptr};
StructureFactory* Ns0AccessDecorationTest::sStructureFactory{nullptr};
std::vector<shared_ptr<NodeSet>>* Ns0AccessDecorationTest::sNodeSets{nullptr};
ImportEngine::AccessDecorationMap* Ns0AccessDecorationTest::sDecoration{nullptr};

constexpr std::array historyCapabilityVariables{
  VariableId::HistoryServerCapabilities_AccessHistoryDataCapability,
  VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability,
  VariableId::HistoryServerCapabilities_MaxReturnDataValues,
  VariableId::HistoryServerCapabilities_MaxReturnEventValues,
  VariableId::HistoryServerCapabilities_InsertDataCapability,
  VariableId::HistoryServerCapabilities_ReplaceDataCapability,
  VariableId::HistoryServerCapabilities_UpdateDataCapability,
  VariableId::HistoryServerCapabilities_DeleteRawCapability,
  VariableId::HistoryServerCapabilities_DeleteAtTimeCapability,
  VariableId::HistoryServerCapabilities_InsertEventCapability,
  VariableId::HistoryServerCapabilities_ReplaceEventCapability,
  VariableId::HistoryServerCapabilities_UpdateEventCapability,
  VariableId::HistoryServerCapabilities_DeleteEventCapability,
  VariableId::HistoryServerCapabilities_InsertAnnotationCapability,
  VariableId::HistoryServerCapabilities_ServerTimestampSupported};

constexpr std::string_view roleSetWithoutSecurityAdmin = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <UAObjectType NodeId="i=15620" BrowseName="RoleType"/>
  <UAObject NodeId="i=15606" BrowseName="RoleSet">
    <RolePermissions>
      <RolePermission Permissions="1">i=15716</RolePermission>
    </RolePermissions>
  </UAObject>
</UANodeSet>
)";

}  // namespace

// Part 18 sections 4.2.2 and 4.2.3 require encrypted invocation independently of Call permission.
// Part 3 section 8.56 applies the encryption bit to Browse only when its separate bit is set.
// @relation(AC-SVR-ROLESET-MANAGEMENT-ENCRYPTION-POLICY, scope=function)
TEST_F(Ns0AccessDecorationTest, RoleSetManagementMethodsRequireEncryption)
{
  for (const auto method : {MethodId::RoleSetType_AddRole,
         MethodId::RoleSetType_RemoveRole,
         MethodId::Server_ServerCapabilities_RoleSet_AddRole,
         MethodId::Server_ServerCapabilities_RoleSet_RemoveRole})
  {
    const NodeId methodId{method};
    SCOPED_TRACE(to_string(methodId));
    const auto* published = sNodeSets->front()->find_node(methodId);
    ASSERT_NE(published, nullptr);
    const auto restrictions = effective_restrictions(methodId);
    ASSERT_TRUE(restrictions.has_value());
    EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
    const auto original = published->access_restrictions().value_or(AccessRestrictionType{});
    for (const auto bit : {AccessRestrictionType::Bit::SigningRequired,
           AccessRestrictionType::Bit::SessionRequired,
           AccessRestrictionType::Bit::ApplyRestrictionsToBrowse})
    {
      EXPECT_EQ(restrictions->test(bit), original.test(bit));
    }
    if (!published->role_permissions().empty())
    {
      EXPECT_EQ(effective_array(methodId), published->role_permissions());
    }
  }

  const NodeId unrelated{MethodId::Server_GetMonitoredItems};
  const auto* published = sNodeSets->front()->find_node(unrelated);
  ASSERT_NE(published, nullptr);
  EXPECT_EQ(effective_restrictions(unrelated), published->access_restrictions());
}

// @relation(AC-SVR-ROLESET-MANAGEMENT-ENCRYPTION-POLICY, scope=function)
TEST_F(Ns0AccessDecorationTest, RoleSetEncryptionPreservesEveryPublishedRestriction)
{
  // -1 omits the Attribute; 0..15 covers every combination of Part 3 section 8.56's four defined bits.
  for (int publishedBits = -1; publishedBits < 16; ++publishedBits)
  {
    SCOPED_TRACE(publishedBits);
    std::string source = R"(<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
      <UAObjectType NodeId="i=15620" BrowseName="RoleType"/>)";
    for (const auto method : {MethodId::RoleSetType_AddRole,
           MethodId::RoleSetType_RemoveRole,
           MethodId::Server_ServerCapabilities_RoleSet_AddRole,
           MethodId::Server_ServerCapabilities_RoleSet_RemoveRole})
    {
      source += "<UAMethod NodeId=\"" + NodeId{method}.as_definition() + "\" BrowseName=\"Management\"";
      if (publishedBits >= 0)
      {
        source += " AccessRestrictions=\"" + std::to_string(publishedBits) + "\"";
      }
      source += "/>";
    }
    source += "</UANodeSet>";
    const auto input = parse_independent_nodeset(std::span<const char>{source.data(), source.size()});
    const auto authored = compute_ns0_access_decoration(*input);
    for (const auto method : {MethodId::RoleSetType_AddRole,
           MethodId::RoleSetType_RemoveRole,
           MethodId::Server_ServerCapabilities_RoleSet_AddRole,
           MethodId::Server_ServerCapabilities_RoleSet_RemoveRole})
    {
      const NodeId methodId{method};
      const auto found = authored.find(methodId);
      ASSERT_NE(found, authored.end()) << to_string(methodId);
      ASSERT_TRUE(found->second.accessRestrictions.has_value());
      auto expected = input->find_node(methodId)->access_restrictions().value_or(AccessRestrictionType{});
      expected.set(AccessRestrictionType::Bit::EncryptionRequired);
      EXPECT_EQ(*found->second.accessRestrictions, expected);
    }
  }
}

// @relation(AC-SVR-ROLESET-MANAGEMENT-ENCRYPTION-POLICY, scope=function)
TEST_F(Ns0AccessDecorationTest, MissingRoleSetMethodsAreNotInvented)
{
  auto input = parse_independent_ns0();
  const NodeId missing{MethodId::Server_ServerCapabilities_RoleSet_AddRole};
  const NodeId empty{MethodId::RoleSetType_RemoveRole};
  ASSERT_EQ(input->nodes().erase(missing), 1U);
  input->nodes().at(empty).reset();
  const auto authored = compute_ns0_access_decoration(*input);
  EXPECT_FALSE(authored.contains(missing));
  EXPECT_FALSE(authored.contains(empty));
  for (const auto method :
    {MethodId::RoleSetType_AddRole, MethodId::Server_ServerCapabilities_RoleSet_RemoveRole})
  {
    const auto found = authored.find(NodeId{method});
    ASSERT_NE(found, authored.end());
    ASSERT_TRUE(found->second.accessRestrictions.has_value());
    EXPECT_TRUE(found->second.accessRestrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
  }
}

// Every well-known Role can read the bootstrap Nodes. Six of the nine are named by none of them in the
// NodeSet, so without the floor a session holding only one of those six never reaches Active.
// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(Ns0AccessDecorationTest, BootstrapNodesAreReadableByEveryWellKnownRole)
{
  for (const NodeId& nodeId : {NodeId{ObjectId::Server},
         NodeId{VariableId::Server_ServerArray},
         NodeId{VariableId::Server_NamespaceArray},
         NodeId{VariableId::Server_ServerStatus}})
  {
    for (const auto role : well_known_roles())
    {
      const auto permissions = permissions_of(nodeId, role);
      ASSERT_TRUE(permissions.has_value()) << "no entry for role on " << to_string(nodeId);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse)) << to_string(nodeId);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Read)) << to_string(nodeId);
    }
  }
}

// Part 3 Table 2 / Part 18: Role membership and RolePermissions are security settings. The baseline
// the import authors on the RoleType declaration surface (copied by AddRole onto every custom Role)
// grants their management to SecurityAdmin alone; ConfigureAdmin may browse and read the surface.
// @relation(AC-SVR-SECADMIN-037-ROLE-MANAGEMENT-IS-SECURITY-ADMIN-ONLY, scope=function)
TEST_F(Ns0AccessDecorationTest, RoleTypeBaselineGrantsRoleManagementToSecurityAdminAlone)
{
  for (const NodeId& nodeId : {NodeId{ObjectTypeId::RoleType}, NodeId{MethodId::RoleType_AddIdentity}})
  {
    const auto configureAdmin = permissions_of(nodeId, WellKnownRole::ConfigureAdmin);
    ASSERT_TRUE(configureAdmin.has_value()) << to_string(nodeId);
    EXPECT_EQ(*configureAdmin, (PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read}))
      << "ConfigureAdmin may browse and read, and nothing more, on " << to_string(nodeId);
    const auto securityAdmin = permissions_of(nodeId, WellKnownRole::SecurityAdmin);
    ASSERT_TRUE(securityAdmin.has_value()) << to_string(nodeId);
    EXPECT_TRUE(securityAdmin->test(PermissionType::Bit::Call)) << to_string(nodeId);
    EXPECT_TRUE(securityAdmin->test(PermissionType::Bit::WriteRolePermissions)) << to_string(nodeId);
  }
}

// The floor widens and never narrows: a Role the NodeSet names keeps the mask it published.
// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(Ns0AccessDecorationTest, BootstrapFloorPreservesThePublishedAdministrativeMask)
{
  const NodeId namespaceArray{VariableId::Server_NamespaceArray};
  const auto published = permissions_of(namespaceArray, WellKnownRole::SecurityAdmin);
  ASSERT_TRUE(published.has_value());
  EXPECT_TRUE(published->test(PermissionType::Bit::Write));
  EXPECT_TRUE(published->test(PermissionType::Bit::WriteRolePermissions));

  // ... while a Role the NodeSet does not name gets the floor and nothing beyond it.
  const auto observer = permissions_of(namespaceArray, WellKnownRole::Observer);
  ASSERT_TRUE(observer.has_value());
  EXPECT_FALSE(observer->test(PermissionType::Bit::Write));
  EXPECT_EQ(observer->value().count(), 2U);
}

// HistoryServerCapabilities is a concrete, non-sensitive discovery surface whose Property Values
// drive client pre-flight decisions. The NodeSet leaves it undecorated, so it takes the namespace
// default, which every well-known Role may Browse and Read.
// @relation(AC-SVR-AUTHZ-013-HISTORY-CAPABILITIES-READABLE, scope=function)
TEST_F(Ns0AccessDecorationTest, HistoryCapabilitySurfaceIsReadableByEveryWellKnownRole)
{
  const std::array objects{NodeId{ObjectId::HistoryServerCapabilities},
    NodeId{ObjectId::HistoryServerCapabilities_AggregateFunctions}};
  for (const auto& nodeId : objects)
  {
    ASSERT_TRUE(takes_the_namespace_default(nodeId)) << to_string(nodeId) << " has an array of its own";
    for (const auto role : well_known_roles())
    {
      const auto permissions = permissions_of(nodeId, role);
      ASSERT_TRUE(permissions.has_value()) << to_string(nodeId) << " omits " << well_known_role_name(role);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse))
        << to_string(nodeId) << " is not browsable by " << well_known_role_name(role);
    }
  }

  for (const auto variable : historyCapabilityVariables)
  {
    const NodeId nodeId{variable};
    ASSERT_TRUE(takes_the_namespace_default(nodeId)) << to_string(nodeId) << " has an array of its own";
    for (const auto role : well_known_roles())
    {
      const auto permissions = permissions_of(nodeId, role);
      ASSERT_TRUE(permissions.has_value()) << to_string(nodeId) << " omits " << well_known_role_name(role);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse))
        << to_string(nodeId) << " is not browsable by " << well_known_role_name(role);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Read))
        << to_string(nodeId) << " is not readable by " << well_known_role_name(role);

      const auto general = well_known_role_permissions(role).as_underlying_type();
      EXPECT_EQ(permissions->as_underlying_type() & general, general)
        << to_string(nodeId) << " narrows the general mask for " << well_known_role_name(role);
    }
  }
}

// The namespace default reaches only Nodes without an array; the neighbouring Role-management surface
// keeps the NodeSet's SecurityAdmin-only array.
// @relation(AC-SVR-AUTHZ-013-HISTORY-CAPABILITIES-READABLE, scope=function)
TEST_F(Ns0AccessDecorationTest, HistoryCapabilityFloorDoesNotWidenRoleManagement)
{
  const NodeId identities{VariableId::WellKnownRole_Anonymous_Identities};
  EXPECT_FALSE(permissions_of(identities, WellKnownRole::Observer).has_value());
  EXPECT_FALSE(permissions_of(identities, WellKnownRole::Anonymous).has_value());
  const auto administrator = permissions_of(identities, WellKnownRole::SecurityAdmin);
  ASSERT_TRUE(administrator.has_value());
  EXPECT_TRUE(administrator->test(PermissionType::Bit::Read));
}

// Part 3 Table 37 bit 0 reaches every Attribute except the Value and RolePermissions, so a Browse grant does
// not read an EnumStrings. No EnumStrings Node in NS0 carries a RolePermissions array of its own, so the
// namespace default governs it and every well-known Role may Read it.
// @relation(AC-SVR-AUTHZ-001-DEFAULT-MATCHES-ROLE-MODEL, scope=function)
TEST_F(Ns0AccessDecorationTest, TypeMetadataValuesAreReadableByEveryWellKnownRole)
{
  // ServerState's EnumStrings: a Value a client must read to decode ServerStatus.
  const NodeId enumStrings{VariableId::ServerState_EnumStrings};
  ASSERT_TRUE(takes_the_namespace_default(enumStrings));
  for (const auto role : well_known_roles())
  {
    const auto permissions = permissions_of(enumStrings, role);
    ASSERT_TRUE(permissions.has_value());
    EXPECT_TRUE(permissions->test(PermissionType::Bit::Read));
    EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse));
  }
}

// Part 3 5.2.9 restricts DefaultRolePermissions to administrators, and the NodeSet decorates it with
// nothing - so without the stamp the namespace default reaches it.
// @relation(AC-SVR-AUTHZ-014-BIT1-IS-PER-NODE, scope=function)
TEST_F(Ns0AccessDecorationTest, DefaultRolePermissionsIsStampedForAdministratorsOnly)
{
  const NodeId defaultRolePermissions{VariableId::OPCUANamespaceMetadata_DefaultRolePermissions};
  ASSERT_TRUE(is_stamped(defaultRolePermissions));
  EXPECT_FALSE(permissions_of(defaultRolePermissions, WellKnownRole::Anonymous).has_value());
  EXPECT_FALSE(permissions_of(defaultRolePermissions, WellKnownRole::Observer).has_value());
  const auto admin = permissions_of(defaultRolePermissions, WellKnownRole::SecurityAdmin);
  ASSERT_TRUE(admin.has_value());
  EXPECT_TRUE(admin->test(PermissionType::Bit::Read));
  EXPECT_TRUE(admin->test(PermissionType::Bit::ReadRolePermissions));
}

// DefaultUserRolePermissions is already filtered to the current Session and is not part of Part 3
// 5.2.9's administrator-only sentence, so unlike its sibling it takes the namespace default and every
// Role can read the projection that describes it.
// @relation(AC-SVR-AUTHZ-024-USER-PROPERTY-IS-PER-SESSION-AND-OMITTED, scope=function)
TEST_F(Ns0AccessDecorationTest, DefaultUserRolePermissionsIsReadableByEveryWellKnownRole)
{
  const NodeId defaultUserRolePermissions{VariableId::OPCUANamespaceMetadata_DefaultUserRolePermissions};
  ASSERT_TRUE(takes_the_namespace_default(defaultUserRolePermissions));
  for (const auto role : well_known_roles())
  {
    const auto permissions = permissions_of(defaultUserRolePermissions, role);
    ASSERT_TRUE(permissions.has_value());
    EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse));
    EXPECT_TRUE(permissions->test(PermissionType::Bit::Read));
  }
}

// Part 5 7.16 and 12.12: security diagnostics shall be restricted to authorised users. The NodeSet
// decorates one Node of that surface; the others are members of the same types, so only an explicit
// rule reaches them. Refusing the type side as well broke CTT Base
// Info Base Types 003, which resolves each type's Mandatory members as a generic Client.
// @relation(AC-SVR-AUTHZ-018-DIAGNOSTICS-GATED-ON-EVERY-PATH, scope=function)
TEST_F(Ns0AccessDecorationTest, SecurityDiagnosticsSurfaceIsClosedToNonAdministrators)
{
  // Part 5 12.12 restricts the information, so the posture follows where a Node sits.
  //
  // The live instance: nothing for Anonymous or Observer.
  const NodeId instance{
    VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray};
  EXPECT_FALSE(permissions_of(instance, WellKnownRole::Anonymous).has_value());
  EXPECT_FALSE(permissions_of(instance, WellKnownRole::Observer).has_value());
  ASSERT_TRUE(permissions_of(instance, WellKnownRole::SecurityAdmin).has_value());
  EXPECT_TRUE(permissions_of(instance, WellKnownRole::SecurityAdmin)->test(PermissionType::Bit::Read));

  // The InstanceDeclarations: runtime instances copy their RolePermissions, so every other Role may
  // Browse them - generic Clients resolve a type's Mandatory members (Part 3 6.4.2) - and none may Read.
  for (const NodeId& nodeId :
    {NodeId{VariableId::SessionsDiagnosticsSummaryType_SessionSecurityDiagnosticsArray},
      NodeId{
        VariableId::ServerType_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
      NodeId{VariableId::ServerDiagnosticsType_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
      NodeId{0U, 2031U},
      NodeId{0U, 3179U},
      NodeId{0U, 12143U},
      NodeId{0U, 12861U},
      NodeId{0U, 2245U}})
  {
    for (const auto role : {WellKnownRole::Anonymous, WellKnownRole::Observer})
    {
      const auto permissions = permissions_of(nodeId, role);
      ASSERT_TRUE(permissions.has_value()) << "no Browse entry on " << to_string(nodeId);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse)) << to_string(nodeId);
      EXPECT_FALSE(permissions->test(PermissionType::Bit::Read)) << "Read granted on " << to_string(nodeId);
    }
    const auto admin = permissions_of(nodeId, WellKnownRole::SecurityAdmin);
    ASSERT_TRUE(admin.has_value()) << "SecurityAdmin cannot reach " << to_string(nodeId);
    EXPECT_TRUE(admin->test(PermissionType::Bit::Read)) << to_string(nodeId);
  }

  // The type definitions hold no session data and are never copied from: the namespace default.
  for (const NodeId& nodeId : {NodeId{VariableTypeId::SessionSecurityDiagnosticsType},
         NodeId{VariableTypeId::SessionSecurityDiagnosticsArrayType},
         NodeId{DataTypeId::SessionSecurityDiagnosticsDataType}})
  {
    const auto permissions = permissions_of(nodeId, WellKnownRole::Anonymous);
    ASSERT_TRUE(permissions.has_value()) << "Anonymous cannot reach " << to_string(nodeId);
    EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse)) << to_string(nodeId);
    EXPECT_TRUE(permissions->test(PermissionType::Bit::Read)) << to_string(nodeId);
  }
}

// The RoleSetType `<RoleName>` placeholder is an InstanceDeclaration that no Role Object is instantiated
// from - AddRole instantiates RoleType, whose declarations keep the administrative baseline. Generic
// Clients resolve a type's members by browse path (Part 3 6.4.2; CTT Base Info Base Types 003), so every
// Role may Browse the placeholder and its members, and none gains Read or any other bit from that.
// @relation(AC-SVR-AUTHZ-018-DIAGNOSTICS-GATED-ON-EVERY-PATH, scope=function)
TEST_F(Ns0AccessDecorationTest, RoleSetPlaceholderIsBrowsableButOtherwiseAdministrative)
{
  // The placeholder's only member in the standard NodeSet is its Identities Property.
  for (const NodeId& nodeId : {NodeId{ObjectId::RoleSetType_RoleName_Placeholder},
         NodeId{VariableId::RoleSetType_RoleName_Placeholder_Identities}})
  {
    for (const auto role : {WellKnownRole::Anonymous, WellKnownRole::Observer})
    {
      const auto permissions = permissions_of(nodeId, role);
      ASSERT_TRUE(permissions.has_value()) << "no Browse entry on " << to_string(nodeId);
      EXPECT_TRUE(permissions->test(PermissionType::Bit::Browse)) << to_string(nodeId);
      EXPECT_FALSE(permissions->test(PermissionType::Bit::Read)) << "Read granted on " << to_string(nodeId);
    }
    const auto admin = permissions_of(nodeId, WellKnownRole::SecurityAdmin);
    ASSERT_TRUE(admin.has_value()) << "SecurityAdmin cannot reach " << to_string(nodeId);
    EXPECT_TRUE(admin->test(PermissionType::Bit::Read)) << to_string(nodeId);
  }
}

// The one decorated member of the security-diagnostics surface also declares AccessRestrictions
// (SigningRequired | EncryptionRequired): its peers and their instance declarations carry client
// identities and take the same restriction, so no per-session SessionSecurityDiagnostics is readable
// on an unencrypted channel whatever the Role.
// @verifies AC-SVR-AUTHZ-018-THE-SECURITY-DIAGNOSTICS-SURFACE-REQUIRES-AN-ENCRYPTED-CHANNEL
TEST_F(Ns0AccessDecorationTest, SecurityDiagnosticsSurfaceRequiresAnEncryptedChannel)
{
  const auto declared = effective_restrictions(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray});
  ASSERT_TRUE(declared.has_value());
  ASSERT_TRUE(declared->test(AccessRestrictionType::Bit::EncryptionRequired)) << "the template declares it";
  // The three undecorated peer instances, the SessionSecurityDiagnostics instance declaration under
  // SessionDiagnosticsObjectType (every per-session instance is created from it), and one mandatory
  // child of each declaration.
  for (const NodeId& nodeId :
    {NodeId{VariableId::SessionsDiagnosticsSummaryType_SessionSecurityDiagnosticsArray},
      NodeId{
        VariableId::ServerType_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
      NodeId{VariableId::ServerDiagnosticsType_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
      NodeId{VariableId::SessionDiagnosticsObjectType_SessionSecurityDiagnostics},
      NodeId{0U, 3179U},
      NodeId{0U, 12143U},
      NodeId{0U, 12861U},
      NodeId{0U, 2245U}})
  {
    const auto restrictions = effective_restrictions(nodeId);
    ASSERT_TRUE(restrictions.has_value()) << to_string(nodeId) << " carries no restriction";
    EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired))
      << to_string(nodeId) << " is readable on an unencrypted channel";
  }
}

// The types of the surface disclose no session data: type discovery and DataTypeDefinition reads keep
// working on any channel.
// @verifies AC-SVR-AUTHZ-018-THE-SECURITY-DIAGNOSTICS-SURFACE-REQUIRES-AN-ENCRYPTED-CHANNEL
TEST_F(Ns0AccessDecorationTest, TypeNodesOfTheSecurityDiagnosticsSurfaceCarryNoChannelRestriction)
{
  for (const NodeId& nodeId : {NodeId{VariableTypeId::SessionSecurityDiagnosticsType},
         NodeId{VariableTypeId::SessionSecurityDiagnosticsArrayType},
         NodeId{DataTypeId::SessionSecurityDiagnosticsDataType}})
  {
    const auto restrictions = effective_restrictions(nodeId);
    EXPECT_TRUE(
      !restrictions.has_value() || !restrictions->test(AccessRestrictionType::Bit::EncryptionRequired))
      << to_string(nodeId) << " must stay reachable on any channel";
  }
}

// Part 5 7.13, 7.14 and 12.11 place no access restriction on the session diagnostics, unlike 7.16 and 12.12
// for the security diagnostics, so the members each Session's diagnostics are copied from take the namespace
// default.
// @relation(AC-SVR-AUTHZ-014-BIT1-IS-PER-NODE, scope=function)
TEST_F(Ns0AccessDecorationTest, SessionDiagnosticsSurfaceTakesTheNamespaceDefault)
{
  for (const NodeId& nodeId : {NodeId{VariableId::SessionsDiagnosticsSummaryType_SessionDiagnosticsArray},
         NodeId{VariableId::SessionDiagnosticsObjectType_SessionDiagnostics}})
  {
    EXPECT_TRUE(takes_the_namespace_default(nodeId)) << to_string(nodeId);
    const auto observer = permissions_of(nodeId, WellKnownRole::Observer);
    ASSERT_TRUE(observer.has_value()) << to_string(nodeId);
    EXPECT_TRUE(observer->test(PermissionType::Bit::Read)) << to_string(nodeId);
  }
}

// AuditEventType grants Anonymous Browse and Read but not ReceiveEvents, and SecurityAdmin everything. A
// Client receives an Event only if ReceiveEvents is set on its EventType and its SourceNode (Table 37 bit
// 11), so a subtype that took the namespace default would deliver audit Events to every Role that default
// gives ReceiveEvents. The NodeSet decorates 48 of the 58 subtypes and leaves ten; the rule gives the ten
// their supertype's array, as Part 3 6.3.2's inheritance of Attribute values does, and every subtype ends
// with one.
// @relation(AC-SVR-AUTHZ-007-EVENT-SOURCE-HALF, scope=function)
TEST_F(Ns0AccessDecorationTest, EveryAuditEventTypeSubtypeReachesSecurityAdminAlone)
{
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  std::vector<NodeId> subtypes;
  std::vector<NodeId> frontier{NodeId{ObjectTypeId::AuditEventType}};
  while (!frontier.empty())
  {
    const NodeId current = frontier.back();
    frontier.pop_back();
    for (const auto& [nodeId, node] : sNodeSets->front()->nodes())
    {
      if (!node)
        continue;
      for (const auto& reference : node->references())
      {
        const bool currentIsSupertype =
          reference.typeId == hasSubtype && ((nodeId == current && reference.isForward) ||
                                              (reference.targetId == current && !reference.isForward));
        const NodeId candidate = nodeId == current ? reference.targetId : nodeId;
        if (currentIsSupertype && candidate != current &&
            std::find(subtypes.begin(), subtypes.end(), candidate) == subtypes.end())
        {
          subtypes.push_back(candidate);
          frontier.push_back(candidate);
        }
      }
    }
  }
  ASSERT_EQ(subtypes.size(), 58U) << "AuditEventType's subtypes in the NodeSet";

  for (const auto& nodeId : subtypes)
  {
    EXPECT_FALSE(takes_the_namespace_default(nodeId)) << to_string(nodeId) << " has no array";
    for (const auto role : well_known_roles())
    {
      const auto permissions = permissions_of(nodeId, role);
      const bool receives = permissions.has_value() && permissions->test(PermissionType::Bit::ReceiveEvents);
      EXPECT_EQ(receives, role == WellKnownRole::SecurityAdmin)
        << to_string(nodeId) << " for " << well_known_role_name(role);
    }
  }
}

// An undecorated Variable under an Object takes the namespace default, not the Object's array, which never
// grants Read because Read applies only to Variables (Part 3 Table 37). ServerLog's and the OPC UA namespace
// metadata's Properties have no array in the NodeSet, so Anonymous may read them. A Node the NodeSet
// decorates keeps its array: TransactionDiagnostics is closed to Anonymous and open to SecurityAdmin.
// @relation(AC-SVR-AUTHZ-014-BIT1-IS-PER-NODE, scope=function)
TEST_F(Ns0AccessDecorationTest, VariablesUnderAnObjectTakeTheNamespaceDefault)
{
  for (const auto variable : {VariableId::ServerLog_MaxRecords,
         VariableId::ServerLog_MaxStorageDuration,
         VariableId::ServerLog_MinimumSeverity,
         VariableId::OPCUANamespaceMetadata_NamespaceUri,
         VariableId::OPCUANamespaceMetadata_NamespaceVersion,
         VariableId::OPCUANamespaceMetadata_StaticStringNodeIdPattern})
  {
    EXPECT_TRUE(takes_the_namespace_default(NodeId{variable})) << ua::to_string(NodeId{variable});
    const auto anonymous = permissions_of(NodeId{variable}, WellKnownRole::Anonymous);
    ASSERT_TRUE(anonymous.has_value()) << ua::to_string(NodeId{variable});
    EXPECT_TRUE(anonymous->test(PermissionType::Bit::Read)) << ua::to_string(NodeId{variable});
    EXPECT_TRUE(anonymous->test(PermissionType::Bit::Browse)) << ua::to_string(NodeId{variable});
    EXPECT_FALSE(anonymous->test(PermissionType::Bit::Write)) << ua::to_string(NodeId{variable});
  }

  EXPECT_FALSE(permissions_of(
    NodeId{VariableId::ServerConfiguration_TransactionDiagnostics_StartTime}, WellKnownRole::Anonymous)
                 .has_value());
  const auto admin = permissions_of(
    NodeId{VariableId::ServerConfiguration_TransactionDiagnostics_StartTime}, WellKnownRole::SecurityAdmin);
  ASSERT_TRUE(admin.has_value());
  EXPECT_TRUE(admin->test(PermissionType::Bit::Read));
}

// The push-management surface under ServerConfiguration carries the NodeSet's own arrays except on two
// folders; they take the array the NodeSet gives ServerConfiguration, so a Role it does not name gets
// nothing there.
// @relation(AC-SVR-AUTHZ-014-BIT1-IS-PER-NODE, scope=function)
TEST_F(Ns0AccessDecorationTest, UndecoratedServerConfigurationFoldersTakeServerConfigurationsArray)
{
  const auto serverConfiguration = effective_array(NodeId{ObjectId::ServerConfiguration});
  ASSERT_FALSE(serverConfiguration.empty());
  for (const NodeId& nodeId :
    {NodeId{ObjectId::AuthorizationServices}, NodeId{ObjectId::KeyCredentialConfiguration}})
  {
    ASSERT_TRUE(is_stamped(nodeId)) << to_string(nodeId);
    auto stamped = effective_array(nodeId);
    auto published = serverConfiguration;
    const auto byRole = [](const RolePermissionType& a, const RolePermissionType& b)
    {
      return to_string(a.role_id()) < to_string(b.role_id());
    };
    std::sort(stamped.begin(), stamped.end(), byRole);
    std::sort(published.begin(), published.end(), byRole);
    EXPECT_EQ(stamped, published) << to_string(nodeId);
    EXPECT_FALSE(permissions_of(nodeId, WellKnownRole::Operator).has_value()) << to_string(nodeId);
  }
}

// A Node the NodeSet decorates keeps its own array: the policy fills silence, it does not overrule.
// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(Ns0AccessDecorationTest, DecoratedNodesAreLeftAlone)
{
  // i=16192, the Anonymous Role's Identities Property, is decorated for SecurityAdmin alone.
  EXPECT_FALSE(is_stamped(NodeId{0U, 16192U}));
  // i=3708 is the security-diagnostics template and is decorated.
  EXPECT_FALSE(is_stamped(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray}));
}

// Configuration-time Role authoring copies the exact, node-specific SecurityAdmin grant into
// ordinary RolePermissions. It is deliberately part of the pure import plan: runtime authorization
// sees no administrator side list and startup needs no blocking address-space traversal.
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-NORMAL-POLICY, scope=function)
TEST_F(Ns0AccessDecorationTest, RoleManagementAuthoringCopiesExactPolicyAndIsConfined)
{
  const NodeId engineerRole{ObjectId::WellKnownRole_Engineer};
  const std::array roleIds{engineerRole};
  ImportEngine::AccessDecorationMap authored;
  try
  {
    authored = compute_ns0_access_decoration(*sNodeSets->front(), roleIds);
  }
  catch (const UaException& exception)
  {
    std::string context;
    if (const auto* detail = exception.detail())
    {
      for (const auto& fact : detail->context)
      {
        context += " " + fact.key + "=" + fact.value;
      }
    }
    FAIL() << exception.what() << context;
  }
  const NodeId securityAdminRole{ObjectId::WellKnownRole_SecurityAdmin};

  const std::array managementNodes{NodeId{ObjectTypeId::RoleType},
    NodeId{ObjectId::Server_ServerCapabilities_RoleSet},
    NodeId{MethodId::Server_ServerCapabilities_RoleSet_AddRole},
    NodeId{ObjectId::WellKnownRole_Operator},
    NodeId{MethodId::WellKnownRole_Operator_AddIdentity}};
  for (const auto& nodeId : managementNodes)
  {
    const auto baseline = effective_array(*sDecoration, nodeId);
    const auto configured = effective_array(authored, nodeId);
    const auto securityAdmin = std::find_if(configured.begin(),
      configured.end(),
      [&securityAdminRole](const RolePermissionType& entry) { return entry.role_id() == securityAdminRole; });
    const auto engineer = std::find_if(configured.begin(),
      configured.end(),
      [&engineerRole](const RolePermissionType& entry) { return entry.role_id() == engineerRole; });
    ASSERT_NE(securityAdmin, configured.end()) << to_string(nodeId);
    ASSERT_NE(engineer, configured.end()) << to_string(nodeId);
    EXPECT_EQ(engineer->permissions(), securityAdmin->permissions()) << to_string(nodeId);

    for (const auto& original : baseline)
    {
      const auto preserved = std::find_if(configured.begin(),
        configured.end(),
        [&original](const RolePermissionType& entry) { return entry.role_id() == original.role_id(); });
      ASSERT_NE(preserved, configured.end()) << to_string(nodeId);
      EXPECT_EQ(*preserved, original) << to_string(nodeId);
    }
  }

  const NodeId unrelated{MethodId::ServerConfiguration_UpdateCertificate};
  EXPECT_EQ(effective_array(authored, unrelated), effective_array(*sDecoration, unrelated));
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-IMPORT-VALIDATION, scope=function)
TEST_F(Ns0AccessDecorationTest, MissingRoleTypeFailsRichly)
{
  auto malformed = parse_independent_ns0();
  const NodeId roleType{ObjectTypeId::RoleType};
  ASSERT_EQ(malformed->nodes().erase(roleType), 1U);
  expect_bad_configuration(*malformed, {}, "RoleTypeMissing", roleType);
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-IMPORT-VALIDATION, scope=function)
TEST_F(Ns0AccessDecorationTest, MissingRoleSetFailsConfiguredAuthoringRichly)
{
  auto malformed = parse_independent_ns0();
  const NodeId roleSet{ObjectId::Server_ServerCapabilities_RoleSet};
  ASSERT_EQ(malformed->nodes().erase(roleSet), 1U);
  const std::array roleIds{NodeId{ObjectId::WellKnownRole_Engineer}};
  expect_bad_configuration(*malformed, roleIds, "RoleManagementSurfaceRootMissing", roleSet);
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-IMPORT-VALIDATION, scope=function)
TEST_F(Ns0AccessDecorationTest, NullRoleSetPolicyFailsConfiguredAuthoringRichly)
{
  auto malformed = parse_independent_ns0();
  const NodeId roleSet{ObjectId::Server_ServerCapabilities_RoleSet};
  const auto found = malformed->nodes().find(roleSet);
  ASSERT_NE(found, malformed->nodes().end());
  found->second.reset();
  const std::array roleIds{NodeId{ObjectId::WellKnownRole_Engineer}};
  expect_bad_configuration(*malformed, roleIds, "RoleManagementSurfacePolicyMissing", roleSet);
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-IMPORT-VALIDATION, scope=function)
TEST_F(Ns0AccessDecorationTest, MissingSecurityAdminBaselineFailsConfiguredAuthoringRichly)
{
  auto malformed = parse_independent_nodeset(
    std::span<const char>{roleSetWithoutSecurityAdmin.data(), roleSetWithoutSecurityAdmin.size()});
  const NodeId roleSet{ObjectId::Server_ServerCapabilities_RoleSet};
  const std::array roleIds{NodeId{ObjectId::WellKnownRole_Engineer}};
  expect_bad_configuration(*malformed, roleIds, "RoleManagementSurfaceBaselineMissing", roleSet);
}

// Every override names a Node of NS0 and specifies at least one access Attribute. A permissions
// override cannot be an empty array, which the import would write as an explicit deny-all.
// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(Ns0AccessDecorationTest, EveryStampNamesAKnownNodeAndDefinesAccessPolicy)
{
  ASSERT_FALSE(sDecoration->empty());
  for (const auto& [nodeId, decoration] : *sDecoration)
  {
    EXPECT_NE(sNodeSets->front()->find_node(nodeId), nullptr) << to_string(nodeId) << " is not in NS0";
    ASSERT_TRUE(decoration.rolePermissions.has_value() || decoration.accessRestrictions.has_value());
    if (decoration.rolePermissions)
    {
      EXPECT_FALSE(decoration.rolePermissions->empty()) << to_string(nodeId) << " stamped deny-all";
    }
  }
}
