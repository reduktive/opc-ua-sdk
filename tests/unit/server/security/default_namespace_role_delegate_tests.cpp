// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for default_ns::Namespace access-control defaults.
///
/// Pins the direct namespace contract that replaced the legacy authorization delegate:
/// engaged-empty standard defaults, explicit vendor-model nullopt, verbatim configured values,
/// and configuration-only single assignment.

#include <gtest/gtest.h>

#include "ua_default_namespace.h"
#include "ua_exceptions.h"
#include "ua_object_id.h"
#include "ua_role_permission_type.h"

#include <boost/asio/thread_pool.hpp>

#include <optional>
#include <vector>

using namespace ua;

namespace
{

NodeId observer_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Observer)};
}

RolePermissionType make_permission(const NodeId& roleId, std::initializer_list<PermissionType::Bit> bits)
{
  RolePermissionType entry;
  entry.role_id() = roleId;
  entry.permissions() = PermissionType{bits};
  return entry;
}

class DefaultNamespaceRoleDelegateTest : public ::testing::Test
{
protected:
  void TearDown() override
  {
    mPool.join();
  }

  std::shared_ptr<default_ns::Namespace> make_ns()
  {
    return default_ns::Namespace::create("urn:default-namespace-access-tests", mPool.get_executor());
  }

  boost::asio::thread_pool mPool{1};
};

}  // namespace

TEST_F(DefaultNamespaceRoleDelegateTest, DefaultsToEngagedEmptyStandardRoleModel)
{
  auto nameSpace = make_ns();
  const auto permissions = nameSpace->default_role_permissions();
  ASSERT_TRUE(permissions.has_value());
  EXPECT_TRUE(permissions->empty());
  EXPECT_FALSE(nameSpace->default_access_restrictions().has_value());
}

TEST_F(DefaultNamespaceRoleDelegateTest, SetNamespaceDefaultsStoresBothValuesVerbatim)
{
  auto nameSpace = make_ns();
  std::vector<RolePermissionType> defaults{
    make_permission(observer_role_id(), {PermissionType::Bit::Read, PermissionType::Bit::Browse})};
  AccessRestrictionType restrictions{AccessRestrictionType::Bit::EncryptionRequired};

  nameSpace->set_namespace_defaults(defaults, restrictions);

  const auto permissions = nameSpace->default_role_permissions();
  ASSERT_TRUE(permissions.has_value());
  ASSERT_EQ(permissions->size(), 1u);
  EXPECT_EQ(permissions->front().role_id(), observer_role_id());
  const auto resolvedRestrictions = nameSpace->default_access_restrictions();
  ASSERT_TRUE(resolvedRestrictions.has_value());
  EXPECT_TRUE(resolvedRestrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
}

TEST_F(DefaultNamespaceRoleDelegateTest, ExplicitVendorModelPropagatesNullopt)
{
  auto nameSpace = make_ns();
  nameSpace->set_namespace_defaults(std::nullopt, std::nullopt);
  EXPECT_FALSE(nameSpace->default_role_permissions().has_value());
  EXPECT_FALSE(nameSpace->default_access_restrictions().has_value());
}

// @relation(AC-SVR-AUTHZ-017-DEFAULTS-CONFIGURE-ONCE, scope=function)
TEST_F(DefaultNamespaceRoleDelegateTest, ReplacingDefaultsRejectsAfterFirstConfiguration)
{
  auto nameSpace = make_ns();
  const auto originalPermissions = std::vector<RolePermissionType>{
    make_permission(observer_role_id(), {PermissionType::Bit::Read, PermissionType::Bit::Browse})};
  const auto originalRestrictions = AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired};
  nameSpace->set_namespace_defaults(originalPermissions, originalRestrictions);

  try
  {
    nameSpace->set_namespace_defaults(std::vector<RolePermissionType>{}, std::nullopt);
    FAIL() << "replacing configured namespace defaults must be refused";
  }
  catch (const UaException& error)
  {
    EXPECT_EQ(error.status(), Status::BadInvalidState);
  }

  EXPECT_EQ(nameSpace->default_role_permissions(), originalPermissions);
  EXPECT_EQ(nameSpace->default_access_restrictions(), originalRestrictions);
}

// @relation(SVR-SECADMIN-056, scope=function)
TEST_F(DefaultNamespaceRoleDelegateTest, VendorSpecificModelDefaultsFalse)
{
  auto nameSpace = make_ns();
  const auto permissions = nameSpace->default_role_permissions();
  ASSERT_TRUE(permissions.has_value()) << "an unconfigured default namespace uses the standard Role model";
  EXPECT_TRUE(permissions->empty());
}

TEST_F(DefaultNamespaceRoleDelegateTest, VendorSpecificModelIsTheExplicitNulloptState)
{
  auto nameSpace = make_ns();
  nameSpace->set_namespace_defaults(std::nullopt, std::nullopt);
  EXPECT_FALSE(nameSpace->default_role_permissions().has_value());
}
