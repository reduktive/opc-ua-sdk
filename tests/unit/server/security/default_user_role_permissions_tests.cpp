// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the per-Session `UserRolePermissions` / `DefaultUserRolePermissions`
/// projection.
///
/// Closes the projection-logic slice of SVR-SECADMIN-054 (DefaultUserRolePermissions
/// per-Session filtered view) and SVR-SECADMIN-055 (per-Node UserRolePermissions
/// override -> namespace-default fallback). The service wiring (Read returns the
/// projection; Write of UserRolePermissions -> `Bad_NotWritable`, SECADMIN-057) is
/// exercised by the integration mirrors
/// (`role_based_security_*_integration_tests.cpp`).

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_role_permissions.h"
#include "ua_role_permission_type.h"
#include "ua_security_policy.h"

#include <boost/asio/thread_pool.hpp>

#include <array>
#include <memory>
#include <span>
#include <utility>
#include <vector>

using namespace ua;

namespace
{

NodeId role_id(ObjectId roleObjectId)
{
  return NodeId{0, static_cast<uint32_t>(roleObjectId)};
}

RolePermissionType make_permission(const NodeId& roleId, std::initializer_list<PermissionType::Bit> bits)
{
  RolePermissionType entry;
  entry.role_id() = roleId;
  entry.permissions() = PermissionType{bits};
  return entry;
}

class DefaultUserRolePermissionsTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mAddressSpace = std::make_unique<AddressSpace>(AddressSpace::create("urn:durp-tests", mExecutor));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeAccessor make_node(uint32_t numericId, std::optional<std::vector<RolePermissionType>> perms)
  {
    auto node = mAddressSpace->try_create_node_sync(NodeId{1, numericId}, NodeClass::Object, {}).value();
    if (perms)
    {
      node.set_role_permissions(std::move(perms));
    }
    return node;
  }

  void install_delegate(std::optional<std::vector<RolePermissionType>> defaults)
  {
    auto ns = mAddressSpace->namespace_array().get_namespace(static_cast<uint16_t>(1));
    auto* defaultNs = dynamic_cast<default_ns::Namespace*>(ns.get());
    ASSERT_NE(defaultNs, nullptr);
    defaultNs->set_namespace_defaults(std::move(defaults), std::nullopt);
  }

  std::optional<std::vector<RolePermissionType>> namespace_defaults() const
  {
    return mAddressSpace->namespace_array()
      .get_namespace(static_cast<uint16_t>(1))
      ->default_role_permissions();
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

// ============================================================================
// filter_user_role_permissions - DefaultUserRolePermissions Property projection
// ============================================================================

// @relation(SVR-SECADMIN-054, scope=function)
TEST_F(DefaultUserRolePermissionsTest, PropertyContainsOnlyAssignedRolePermissions)
{
  std::vector<RolePermissionType> source{
    make_permission(role_id(ObjectId::WellKnownRole_Anonymous), {PermissionType::Bit::Browse}),
    make_permission(role_id(ObjectId::WellKnownRole_Observer), {PermissionType::Bit::Read}),
    make_permission(role_id(ObjectId::WellKnownRole_Operator), {PermissionType::Bit::Write})};

  const std::array grantedRoles{role_id(ObjectId::WellKnownRole_Observer)};
  auto filtered = role_permissions::filter_role_permissions(source, grantedRoles);

  ASSERT_EQ(filtered.size(), 1u);
  EXPECT_EQ(filtered[0].role_id(), role_id(ObjectId::WellKnownRole_Observer));
}

// @relation(SVR-SECADMIN-054, scope=function)
TEST_F(DefaultUserRolePermissionsTest, AnonymousSessionGetsOnlyAnonymousRolePermissions)
{
  std::vector<RolePermissionType> source{
    make_permission(role_id(ObjectId::WellKnownRole_Anonymous), {PermissionType::Bit::Browse}),
    make_permission(role_id(ObjectId::WellKnownRole_Observer), {PermissionType::Bit::Read})};

  const std::array grantedRoles{role_id(ObjectId::WellKnownRole_Anonymous)};
  auto filtered = role_permissions::filter_role_permissions(source, grantedRoles);

  ASSERT_EQ(filtered.size(), 1u);
  EXPECT_EQ(filtered[0].role_id(), role_id(ObjectId::WellKnownRole_Anonymous));
}

TEST_F(DefaultUserRolePermissionsTest, FilterEmptyMaskReturnsEmpty)
{
  std::vector<RolePermissionType> source{
    make_permission(role_id(ObjectId::WellKnownRole_Observer), {PermissionType::Bit::Read})};

  EXPECT_TRUE(role_permissions::filter_role_permissions(source, std::span<const NodeId>{}).empty());
}

// ============================================================================
// user_role_permissions - per-Node UserRolePermissions Attribute projection
// ============================================================================

// @relation(SVR-SECADMIN-055, scope=function)
TEST_F(DefaultUserRolePermissionsTest, NodeWithRolePermissionsOverrideExposesUserRolePermissions)
{
  auto node = make_node(7001,
    std::vector<RolePermissionType>{
      make_permission(role_id(ObjectId::WellKnownRole_Observer), {PermissionType::Bit::Read}),
      make_permission(role_id(ObjectId::WellKnownRole_Operator), {PermissionType::Bit::Write})});

  auto effective = role_permissions::resolve_role_permissions(node, namespace_defaults());
  ASSERT_TRUE(effective.has_value());
  const std::array grantedRoles{role_id(ObjectId::WellKnownRole_Observer)};
  auto projected = role_permissions::filter_role_permissions(*effective, grantedRoles);

  ASSERT_EQ(projected.size(), 1u);
  EXPECT_EQ(projected[0].role_id(), role_id(ObjectId::WellKnownRole_Observer));
  EXPECT_TRUE(projected[0].permissions().test(PermissionType::Bit::Read));
}

// @relation(SVR-SECADMIN-055, scope=function)
TEST_F(DefaultUserRolePermissionsTest, NodeWithoutOverrideReturnsDefaultUserRolePermissions)
{
  // Namespace exposes a DefaultRolePermissions fallback; the Node carries no
  // override -> UserRolePermissions resolves to the (filtered) namespace default.
  install_delegate(std::vector<RolePermissionType>{
    make_permission(role_id(ObjectId::WellKnownRole_Observer), {PermissionType::Bit::Read}),
    make_permission(role_id(ObjectId::WellKnownRole_Operator), {PermissionType::Bit::Write})});

  auto node = make_node(7002, std::nullopt);  // no per-Node RolePermissions override

  auto effective = role_permissions::resolve_role_permissions(node, namespace_defaults());
  ASSERT_TRUE(effective.has_value());
  const std::array grantedRoles{role_id(ObjectId::WellKnownRole_Operator)};
  auto projected = role_permissions::filter_role_permissions(*effective, grantedRoles);

  ASSERT_EQ(projected.size(), 1u);
  EXPECT_EQ(projected[0].role_id(), role_id(ObjectId::WellKnownRole_Operator));
  EXPECT_TRUE(projected[0].permissions().test(PermissionType::Bit::Write));
}

TEST_F(DefaultUserRolePermissionsTest, NodeWithoutOverrideOrDefaultReturnsEmpty)
{
  auto node = make_node(7003, std::nullopt);  // no override, namespace has no delegate default
  auto effective = role_permissions::resolve_role_permissions(node, namespace_defaults());
  ASSERT_TRUE(effective.has_value());
  const std::array grantedRoles{role_id(ObjectId::WellKnownRole_Observer)};
  EXPECT_TRUE(role_permissions::filter_role_permissions(*effective, grantedRoles).empty());
}

}  // namespace
