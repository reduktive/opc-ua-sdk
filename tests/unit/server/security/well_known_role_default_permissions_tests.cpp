// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the per-well-known-role default permission bitmasks installed
/// on NS0's canonical namespace access-control interface.
///
/// Closes SVR-SECADMIN-061..069 (Anonymous / AuthenticatedUser / Observer /
/// Operator / Engineer / Supervisor / ConfigureAdmin / SecurityAdmin /
/// TrustedApplication default permission bitmasks). Each test drives the real
/// wiring pass via `create_part18_server` and reads the enforced namespace
/// default back, asserting the role's entry carries exactly the Part 3 section
/// 4.8.2 Table 2-derived permission bits. Publication of that same value is
/// covered independently by `NamespaceMetadataPublicationTest`.
///
/// TrustedApplication (SVR-SECADMIN-069) was added in OPC 10000 Release 1.05.04
/// (NodeId 18625); it is materialised here since the NodeSet pin moved to
/// UA-1.05.06.

#include <gtest/gtest.h>

#include "ua_default_namespace.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_role_permission_type.h"
#include "ua_server_impl.h"
#include "ua_variable_id.h"
#include "ua_well_known_role_permissions.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

::ua::server::CombinedConfig make_frozen_config()
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ::ua::server::ServerConfig sc;
  sc.maxConnections = 100;
  frozen.server = std::move(sc);
  return frozen;
}

shared_ptr<ServerImpl> create_part18_server(
  boost::asio::any_io_executor ex, std::optional<std::vector<WellKnownRole>> selection = std::nullopt)
{
  auto frozen = make_frozen_config();
  frozen.server.wellKnownRoles = std::move(selection);
  ::ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.roleConfiguration = std::make_shared<RoleConfiguration>();
  return ServerImpl::create(ex, std::move(frozen), std::move(components));
}

/// Read NS0's enforced default and return a map of role-id numeric to granted
/// `PermissionType` for each entry.
std::map<uint32_t, PermissionType> read_default_role_permissions(AddressSpace& addressSpace)
{
  std::map<uint32_t, PermissionType> out;
  auto nameSpace = addressSpace.namespace_array().get_namespace(0);
  if (!nameSpace)
  {
    return out;
  }
  const auto defaults = nameSpace->default_role_permissions();
  if (!defaults)
  {
    return out;
  }
  for (const auto& rolePermission : *defaults)
  {
    if (rolePermission.role_id().is_numeric())
    {
      out.emplace(rolePermission.role_id().identifier().get_numeric(), rolePermission.permissions());
    }
  }
  return out;
}

std::optional<PermissionType> permissions_for_role(AddressSpace& addressSpace, ObjectId roleObjectId)
{
  auto perms = read_default_role_permissions(addressSpace);
  auto it = perms.find(static_cast<uint32_t>(roleObjectId));
  if (it == perms.end())
  {
    return std::nullopt;
  }
  return it->second;
}

using Bit = PermissionType::Bit;

}  // namespace

// @relation(AC-SVR-AUTHZ-025-WELL-KNOWN-ROLE-HELPERS, scope=function)
TEST(WellKnownRolePermissionsTest, ConstructionHelpersDeriveRoleIdsAndDefaults)
{
  const auto defaults =
    well_known_role_default_permissions({WellKnownRole::Observer, WellKnownRole::Observer});
  ASSERT_EQ(defaults.size(), 1u);
  EXPECT_EQ(defaults.front().role_id(), NodeId{ObjectId::WellKnownRole_Observer});
  EXPECT_EQ(defaults.front().permissions().as_underlying_type(),
    well_known_role_permissions(WellKnownRole::Observer).as_underlying_type());
  EXPECT_EQ(well_known_role_name(WellKnownRole::Observer), "Observer");

  const auto nodeOverride =
    make_well_known_role_permission(WellKnownRole::Operator, PermissionType{Bit::Browse, Bit::Read});
  EXPECT_EQ(nodeOverride.role_id(), NodeId{ObjectId::WellKnownRole_Operator});
  EXPECT_EQ(nodeOverride.permissions().as_underlying_type(),
    PermissionType({Bit::Browse, Bit::Read}).as_underlying_type());
}

// @relation(AC-SVR-AUTHZ-030-ONE-ROLE-SET-AUTHORS-IDENTITY-AND-NAMESPACE, scope=function)
TEST(WellKnownRolePermissionsTest, OneRoleSpanAuthorsMatchingNamespaceDefaults)
{
  const auto roles = well_known_roles();
  const auto defaults = well_known_role_default_permissions(roles);

  ASSERT_EQ(defaults.size(), roles.size());
  for (size_t index = 0; index < roles.size(); ++index)
  {
    EXPECT_EQ(defaults[index].role_id(), well_known_role_node_id(roles[index]));
    EXPECT_EQ(defaults[index].permissions().as_underlying_type(),
      well_known_role_permissions(roles[index]).as_underlying_type());
  }
}

// @relation(AC-SVR-AUTHZ-025-WELL-KNOWN-ROLE-HELPERS, scope=function)
TEST(WellKnownRolePermissionsTest, PublicNamespaceCreationAcceptsConstructedDefaults)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("urn:test:role-helper", threadPool.get_executor());

  auto nameSpace = addressSpace.create_namespace(
    "urn:test:role-helper:configured", well_known_role_default_permissions({WellKnownRole::Observer}));

  const auto defaults = nameSpace->default_role_permissions();
  ASSERT_TRUE(defaults.has_value());
  ASSERT_EQ(defaults->size(), 1u);
  EXPECT_EQ(defaults->front().role_id(), NodeId{ObjectId::WellKnownRole_Observer});
  EXPECT_EQ(defaults->front().permissions().as_underlying_type(),
    well_known_role_permissions(WellKnownRole::Observer).as_underlying_type());

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-AUTHZ-025-WELL-KNOWN-ROLE-HELPERS, scope=function)
TEST(WellKnownRolePermissionsTest, InvalidRoleIsRefusedRatherThanAliased)
{
  const auto invalid = static_cast<WellKnownRole>(255);
  EXPECT_TRUE(well_known_role_node_id(invalid).is_null());
  EXPECT_TRUE(well_known_role_name(invalid).empty());
  EXPECT_FALSE(well_known_role_bit(invalid).has_value());
  EXPECT_EQ(well_known_role_permissions(invalid).as_underlying_type(), 0u);

  try
  {
    (void)make_well_known_role_permission(invalid, PermissionType{Bit::Browse});
    FAIL() << "Invalid well-known Role was accepted";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadInvalidArgument);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "InvalidWellKnownRole");
  }
}

/// Shared-server fixture (POC): the default-selection Part-18 server is built ONCE
/// for the whole suite in `SetUpTestSuite()` and reused read-only by every test.
/// These tests only READ the installed NS0 namespace default; none
/// mutate the address space or server state, so a single shared instance is safe.
class WellKnownRoleDefaultPermissionsTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>();
    sServer = create_part18_server(sThreadPool->get_executor());
  }

  static void TearDownTestSuite()
  {
    sServer.reset();
    if (sThreadPool)
    {
      sThreadPool->join();
      sThreadPool.reset();
    }
  }

  // Read-only access to the shared suite server's address space.
  AddressSpace& shared_address_space()
  {
    return shared_access().address_space();
  }

private:
  static ServerImplTestAccess& shared_access()
  {
    static ServerImplTestAccess access{*sServer};
    return access;
  }

  static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  static shared_ptr<ServerImpl> sServer;
};

std::unique_ptr<boost::asio::thread_pool> WellKnownRoleDefaultPermissionsTest::sThreadPool;
shared_ptr<ServerImpl> WellKnownRoleDefaultPermissionsTest::sServer;

// @relation(AC-SVR-SECADMIN-061-ANONYMOUS-PERMISSIONS, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, AnonymousRoleDefaultPermissionsAllowBrowseRead)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_Anonymous);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_FALSE(perms->test(Bit::Write));
  EXPECT_FALSE(perms->test(Bit::Call));
}

// @relation(AC-SVR-SECADMIN-062-AUTHENTICATEDUSER-PERMISSIONS, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, AuthenticatedUserRoleDefaultPermissionsAllowBrowseRead)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_AuthenticatedUser);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_FALSE(perms->test(Bit::Write));
}

// @relation(SVR-SECADMIN-063, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, ObserverRoleDefaultPermissionsAllowReadAndSubscribe)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_Observer);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::ReadHistory));
  EXPECT_TRUE(perms->test(Bit::ReceiveEvents));
  // Observer is read-only - no Write, no Call.
  EXPECT_FALSE(perms->test(Bit::Write));
  EXPECT_FALSE(perms->test(Bit::Call));
}

// @relation(SVR-SECADMIN-064, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, OperatorRoleDefaultPermissionsAllowWriteAndCall)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_Operator);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::Write));
  EXPECT_TRUE(perms->test(Bit::ReadHistory));
  EXPECT_TRUE(perms->test(Bit::ReceiveEvents));
  EXPECT_TRUE(perms->test(Bit::Call));
  // Operator is not a security admin.
  EXPECT_FALSE(perms->test(Bit::WriteRolePermissions));
}

// @relation(SVR-SECADMIN-065, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, EngineerRoleDefaultPermissionsAllowConfigWrite)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_Engineer);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::Write));
  EXPECT_TRUE(perms->test(Bit::WriteAttribute));
  EXPECT_TRUE(perms->test(Bit::ReadHistory));
  EXPECT_TRUE(perms->test(Bit::Call));
  EXPECT_FALSE(perms->test(Bit::WriteRolePermissions));
}

// @relation(SVR-SECADMIN-066, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, SupervisorRoleDefaultPermissionsAllowCallAndSubscribe)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_Supervisor);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::ReadHistory));
  EXPECT_TRUE(perms->test(Bit::ReceiveEvents));
  EXPECT_TRUE(perms->test(Bit::Call));
  // Part 3 section 4.8.2 L1272-1273 grants Supervisor NO Write.
  EXPECT_FALSE(perms->test(Bit::Write));
}

// @relation(SVR-SECADMIN-067, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, ConfigureAdminRoleDefaultPermissionsAllowNonSecurityConfig)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_ConfigureAdmin);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::Write));
  EXPECT_TRUE(perms->test(Bit::WriteAttribute));
  EXPECT_TRUE(perms->test(Bit::Call));
  // Policy grant beyond Table 2: the Role that reshapes the Address Space must be able to receive the
  // ModelChangeEvents announcing its own edits. Every Event names an EventType Node in ns=0 and Part 3
  // 8.55 gates on it, so a Role without this bit receives no Event at all, from any Node.
  EXPECT_TRUE(perms->test(Bit::ReceiveEvents));
  // ConfigureAdmin changes non-security settings only - no RolePermissions write.
  EXPECT_FALSE(perms->test(Bit::WriteRolePermissions));
  EXPECT_FALSE(perms->test(Bit::ReadRolePermissions));
}

// @relation(SVR-SECADMIN-068, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, SecurityAdminRoleDefaultPermissionsAllowSecurityConfig)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_SecurityAdmin);
  ASSERT_TRUE(perms.has_value());
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::Write));
  EXPECT_TRUE(perms->test(Bit::WriteAttribute));
  EXPECT_TRUE(perms->test(Bit::Call));
  // Policy grant beyond Table 2: without it the security administrator cannot subscribe to the
  // AuditEvents reporting the security-relevant activity it exists to oversee.
  EXPECT_TRUE(perms->test(Bit::ReceiveEvents));
  // SecurityAdmin is the only well-known role granted the RolePermissions bits.
  EXPECT_TRUE(perms->test(Bit::ReadRolePermissions));
  EXPECT_TRUE(perms->test(Bit::WriteRolePermissions));
}

// @relation(SVR-SECADMIN-069, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, TrustedApplicationRoleDefaultPermissionsAllowReadAndSubscribe)
{
  auto perms = permissions_for_role(shared_address_space(), ObjectId::WellKnownRole_TrustedApplication);
  ASSERT_TRUE(perms.has_value());
  // Trusted-application read/subscribe baseline:
  // browse, read live data, receive events.
  EXPECT_TRUE(perms->test(Bit::Browse));
  EXPECT_TRUE(perms->test(Bit::Read));
  EXPECT_TRUE(perms->test(Bit::ReceiveEvents));
  // Read-only peer - no write, no history, no call, no admin.
  EXPECT_FALSE(perms->test(Bit::Write));
  EXPECT_FALSE(perms->test(Bit::ReadHistory));
  EXPECT_FALSE(perms->test(Bit::Call));
  EXPECT_FALSE(perms->test(Bit::WriteRolePermissions));
}

// @relation(AC-SVR-AUTHZ-024-USER-PROPERTY-IS-PER-SESSION-AND-OMITTED, scope=function)
TEST_F(WellKnownRoleDefaultPermissionsTest, DefaultUserPropertyIsReadableThroughTheInstalledDefault)
{
  const auto nameSpace = shared_address_space().namespace_array().get_namespace(0);
  ASSERT_NE(nameSpace, nullptr);
  // Namespace 0 is an in-memory namespace, which hands out the Node the immediate form is asked about.
  const auto inMemory = std::dynamic_pointer_cast<default_ns::Namespace>(nameSpace);
  ASSERT_NE(inMemory, nullptr);
  const auto property =
    inMemory->find_node<Node>(NodeId{VariableId::OPCUANamespaceMetadata_DefaultUserRolePermissions});
  ASSERT_NE(property, nullptr);
  AccessIdentity identity{
    AccessIdentityKey{1}, {NodeId{ObjectId::WellKnownRole_SecurityAdmin}}, nullptr, nullptr, String{}};

  const auto permissions = nameSpace->effective_permissions(identity, property.get());

  ASSERT_TRUE(permissions.has_value());
  EXPECT_TRUE(permissions->test(Bit::Read));
}

// Distinct per-test config (Observer-only selection): cannot share the default
// suite server, so this test keeps its own local pool + server.
TEST(WellKnownRoleDefaultPermissionsSelectionTest, SelectionRestrictsSeededDefaultPermissions)
{
  boost::asio::thread_pool tp;
  // Only Observer is selected for materialisation, so only Observer's entry is installed.
  auto server = create_part18_server(tp.get_executor(), std::vector<WellKnownRole>{WellKnownRole::Observer});
  ServerImplTestAccess access{*server};
  auto perms = read_default_role_permissions(access.address_space());
  EXPECT_EQ(perms.size(), 1u);
  EXPECT_TRUE(perms.count(static_cast<uint32_t>(ObjectId::WellKnownRole_Observer)) == 1);
  EXPECT_TRUE(perms.count(static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)) == 0);
}
