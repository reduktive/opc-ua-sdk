// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the pure RBAC permission helpers in `role_permission_utils`.
///
/// These tests cover the building blocks consumed by Namespace Role-model evaluation:
///   * Node -> namespace fallback for `RolePermissions` and `AccessRestrictions`.
///   * `merge_permission_bits` granted-mask filtering, including the
///     no-matching-role and unknown-role-bit branches.
///   * `access_restrictions_satisfied` per-bit channel-mode checks.
///   * `permission_bit_for_operation` mapping table.
///   * `project_access_level` / `project_write_mask` projections onto the
///     `UserAccessLevel` / `UserWriteMask` attribute layouts.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_node_accessor.h"
#include "ua_role_permission_utils.h"
#include "ua_role_permissions.h"

#include <boost/asio/thread_pool.hpp>

#include <optional>
#include <vector>

using namespace ua;
using namespace ua::server;
namespace rbac_utils = ua::server::role_permission_utils;
// The Role model itself moved down to the address-space layer; only the two operation-aware
// helpers are left in `rbac_utils`.
namespace role_model = ua::role_permissions;

namespace
{

constexpr uint8_t currentReadBit{0x01};
constexpr uint8_t currentWriteBit{0x02};
constexpr uint8_t historyReadBit{0x04};
constexpr uint8_t historyWriteBit{0x08};
constexpr uint8_t semanticChangeBit{0x10};
constexpr uint8_t statusWriteBit{0x20};
constexpr uint8_t timestampWriteBit{0x40};
// RBAC projection keeps current-write and history-write semantically separate:
// PermissionType::Write covers current-side write bits only; HistoryWrite is
// driven by the explicit history-permission bits.
constexpr uint8_t currentWriteAllBits =
  currentWriteBit | semanticChangeBit | statusWriteBit | timestampWriteBit;

class RolePermissionUtilsTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mAddressSpace = std::make_unique<AddressSpace>(AddressSpace::create("urn:rpu-tests", mExecutor));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeAccessor make_node(uint32_t numericId)
  {
    return mAddressSpace->try_create_node_sync(NodeId{1, numericId}, NodeClass::Object, {}).value();
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

RolePermissionType make_entry(uint32_t roleNumericId, std::initializer_list<PermissionType::Bit> bits)
{
  RolePermissionType entry;
  entry.role_id() = NodeId{1, roleNumericId};
  PermissionType perms{bits};
  entry.permissions() = perms;
  return entry;
}

// ============================================================================
// resolve_role_permissions / resolve_access_restrictions
// ============================================================================

TEST_F(RolePermissionUtilsTest, ResolveRolePermissionsPrefersNodeValue)
{
  auto node = make_node(1);
  std::vector<RolePermissionType> nodePerms{make_entry(100, {PermissionType::Bit::Read})};
  node.set_role_permissions(nodePerms);

  std::vector<RolePermissionType> nsDefault{make_entry(200, {PermissionType::Bit::Write})};
  const auto resolved = role_model::resolve_role_permissions(node, nsDefault);
  ASSERT_TRUE(resolved.has_value());
  ASSERT_EQ(resolved->size(), 1u);
  EXPECT_EQ(resolved->front().role_id(), (NodeId{1, 100}));
}

TEST_F(RolePermissionUtilsTest, ResolveRolePermissionsFallsBackToNamespaceDefault)
{
  auto node = make_node(2);
  std::vector<RolePermissionType> nsDefault{make_entry(200, {PermissionType::Bit::Write})};
  const auto resolved = role_model::resolve_role_permissions(node, nsDefault);
  ASSERT_TRUE(resolved.has_value());
  ASSERT_EQ(resolved->size(), 1u);
  EXPECT_EQ(resolved->front().role_id(), (NodeId{1, 200}));
}

// Part 3 5.2.9 makes an empty array the documented way to REMOVE an override: "If the
// administrator wishes to remove overridden Permissions, an empty array shall be written to this
// Attribute", and a Server that supports overrides but has none configured "shall" expose the
// Attribute as an empty array. An empty array therefore means *not configured*, so the namespace
// default applies. Reading it as "configured, granting nothing" turns the specification's own
// removal procedure into a deny-all.
// @relation(AC-SVR-AUTHZ-004-EMPTY-ARRAY-RESTORES-DEFAULT, scope=function)
TEST_F(RolePermissionUtilsTest, ResolveRolePermissionsTreatsEmptyNodeArrayAsUnconfigured)
{
  auto node = make_node(4);
  node.set_role_permissions(std::vector<RolePermissionType>{});

  std::vector<RolePermissionType> nsDefault{make_entry(200, {PermissionType::Bit::Read})};
  const auto resolved = role_model::resolve_role_permissions(node, nsDefault);

  ASSERT_TRUE(resolved.has_value());
  ASSERT_EQ(resolved->size(), 1u) << "an empty node array must fall through to the namespace default";
  EXPECT_EQ(resolved->front().role_id(), (NodeId{1, 200}));
}

TEST_F(RolePermissionUtilsTest, ResolveRolePermissionsAbsentWhenBothMissing)
{
  auto node = make_node(3);
  const auto resolved = role_model::resolve_role_permissions(node, std::nullopt);
  EXPECT_FALSE(resolved.has_value());
}

// A retained accessor can race deletion after resolution. The resolver deliberately is not noexcept:
// the node reports the race as Bad_NodeIdUnknown and the decision boundary can convert it instead of
// terminating the process.
// @relation(AC-SVR-AUTHZ-022-CONCURRENT-DELETE-SURVIVES, scope=function)
TEST_F(RolePermissionUtilsTest, DecisionOnDeletedNodeDoesNotTerminate)
{
  const NodeId nodeId{1, 31U};
  auto node = make_node(31);
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(nodeId, false).is_good());

  try
  {
    (void)role_model::resolve_role_permissions(node, std::nullopt);
    FAIL() << "a deleted node must not retain readable access-control attributes";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status_code(), Status::BadNodeIdUnknown);
  }
}

TEST_F(RolePermissionUtilsTest, ResolveAccessRestrictionsPrefersNodeValue)
{
  auto node = make_node(4);
  AccessRestrictionType nodeRestrictions;
  nodeRestrictions.set(AccessRestrictionType::Bit::SigningRequired);
  node.set_access_restrictions(nodeRestrictions);

  AccessRestrictionType nsDefault;
  nsDefault.set(AccessRestrictionType::Bit::EncryptionRequired);
  const auto resolved = role_model::resolve_access_restrictions(node, nsDefault);
  ASSERT_TRUE(resolved.has_value());
  EXPECT_TRUE(resolved->test(AccessRestrictionType::Bit::SigningRequired));
  EXPECT_FALSE(resolved->test(AccessRestrictionType::Bit::EncryptionRequired));
}

TEST_F(RolePermissionUtilsTest, ResolveAccessRestrictionsFallsBackToNamespace)
{
  auto node = make_node(5);
  AccessRestrictionType nsDefault;
  nsDefault.set(AccessRestrictionType::Bit::EncryptionRequired);
  const auto resolved = role_model::resolve_access_restrictions(node, nsDefault);
  ASSERT_TRUE(resolved.has_value());
  EXPECT_TRUE(resolved->test(AccessRestrictionType::Bit::EncryptionRequired));
}

TEST_F(RolePermissionUtilsTest, ResolveAccessRestrictionsAbsentWhenBothMissing)
{
  auto node = make_node(6);
  EXPECT_FALSE(role_model::resolve_access_restrictions(node, std::nullopt).has_value());
}

// ============================================================================
// merge_permission_bits
// ============================================================================

TEST(RolePermissionMergeTest, NoEntriesYieldsHadAnyFalse)
{
  const std::vector<RolePermissionType> empty;
  const std::vector<NodeId> granted{NodeId{1, 100}};
  const auto merged = role_model::merge_permission_bits(empty, granted);
  EXPECT_FALSE(merged.hadAny);
  EXPECT_EQ(merged.permissions.as_underlying_type(), 0u);
}

TEST(RolePermissionMergeTest, MergeOnlyEntriesWithGrantedRole)
{
  const std::vector<RolePermissionType> perms{
    make_entry(100, {PermissionType::Bit::Read}),
    make_entry(101, {PermissionType::Bit::Write}),
    make_entry(102, {PermissionType::Bit::Browse}),
  };

  // Hold the Roles of entries 0 and 2, so Read and Browse merge in and Write does not.
  const std::vector<NodeId> granted{NodeId{1, 100}, NodeId{1, 102}};
  const auto merged = role_model::merge_permission_bits(perms, granted);
  EXPECT_TRUE(merged.hadAny);
  EXPECT_TRUE(merged.permissions.test(PermissionType::Bit::Read));
  EXPECT_TRUE(merged.permissions.test(PermissionType::Bit::Browse));
  EXPECT_FALSE(merged.permissions.test(PermissionType::Bit::Write));
}

TEST(RolePermissionMergeTest, RolesTheIdentityDoesNotHoldAreIgnoredButStillCount)
{
  const std::vector<RolePermissionType> perms{make_entry(100, {PermissionType::Bit::Read})};
  const std::vector<NodeId> granted;

  const auto merged = role_model::merge_permission_bits(perms, granted);
  // hadAny stays true because the entry is present: "this node grants these Roles nothing" is a
  // different answer from "this node carries no RolePermissions at all", and only the first denies
  // without consulting the namespace default.
  EXPECT_TRUE(merged.hadAny);
  EXPECT_FALSE(merged.permissions.test(PermissionType::Bit::Read));
}

TEST(RolePermissionMergeTest, MultipleEntriesOrTogether)
{
  const std::vector<RolePermissionType> perms{
    make_entry(100, {PermissionType::Bit::Read, PermissionType::Bit::Browse}),
    make_entry(101, {PermissionType::Bit::Write, PermissionType::Bit::Browse}),
  };
  const std::vector<NodeId> granted{NodeId{1, 100}, NodeId{1, 101}};
  const auto merged = role_model::merge_permission_bits(perms, granted);
  EXPECT_TRUE(merged.permissions.test(PermissionType::Bit::Read));
  EXPECT_TRUE(merged.permissions.test(PermissionType::Bit::Write));
  EXPECT_TRUE(merged.permissions.test(PermissionType::Bit::Browse));
}

// The predicate overload is the same evaluation with the grant test supplied by the caller; it exists
// for a caller whose grant is not a list of NodeIds, and must agree with the span form.
TEST(RolePermissionMergeTest, PredicateOverloadAgreesWithTheSpanForm)
{
  const std::vector<RolePermissionType> perms{
    make_entry(100, {PermissionType::Bit::Read}),
    make_entry(101, {PermissionType::Bit::Write}),
  };
  const std::vector<NodeId> granted{NodeId{1, 101}};

  const auto viaSpan = role_model::merge_permission_bits(perms, granted);
  const auto viaPredicate = role_model::merge_permission_bits(perms,
    role_model::RoleGrantPredicate{[](const NodeId& roleId)
      {
        return roleId == NodeId{1, 101};
      }});

  EXPECT_EQ(viaSpan.hadAny, viaPredicate.hadAny);
  EXPECT_EQ(viaSpan.permissions.as_underlying_type(), viaPredicate.permissions.as_underlying_type());
  EXPECT_TRUE(viaPredicate.permissions.test(PermissionType::Bit::Write));
}

// filter_role_permissions keeps the per-Role structure instead of collapsing it, because the
// UserRolePermissions Attribute is re-encoded from what it returns.
TEST(RolePermissionFilterTest, KeepsOnlyTheEntriesNamingAGrantedRole)
{
  const std::vector<RolePermissionType> perms{
    make_entry(100, {PermissionType::Bit::Read}),
    make_entry(101, {PermissionType::Bit::Write}),
    make_entry(102, {PermissionType::Bit::Browse}),
  };
  const std::vector<NodeId> granted{NodeId{1, 102}, NodeId{1, 100}};

  const auto filtered = role_model::filter_role_permissions(perms, granted);
  ASSERT_EQ(filtered.size(), 2U);
  // Original order, not the order the Roles were granted in.
  EXPECT_EQ(filtered[0].role_id(), (NodeId{1, 100}));
  EXPECT_EQ(filtered[1].role_id(), (NodeId{1, 102}));
}

// ============================================================================
// access_restrictions_satisfied
// ============================================================================

TEST(AccessRestrictionsTest, NoRestrictionsAlwaysSatisfied)
{
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(std::nullopt, MessageSecurityMode::None));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(std::nullopt, MessageSecurityMode::Sign));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(std::nullopt, MessageSecurityMode::SignAndEncrypt));
}

TEST(AccessRestrictionsTest, SigningRequiredRejectsNoneMode)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::SigningRequired);
  EXPECT_FALSE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Sign));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::SignAndEncrypt));
}

TEST(AccessRestrictionsTest, EncryptionRequiredRejectsSignOnly)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::EncryptionRequired);
  EXPECT_FALSE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None));
  EXPECT_FALSE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Sign));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::SignAndEncrypt));
}

TEST(AccessRestrictionsTest, SessionRequiredRejectsInvalidMode)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::SessionRequired);
  EXPECT_FALSE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Invalid));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None));
}

// ============================================================================
// ApplyRestrictionsToBrowse - Part 3 section 5.2.11 carve-out
// ============================================================================
//
// Per the spec: SigningRequired and EncryptionRequired do NOT apply to
// Browse-class operations (Browse, TranslateBrowsePaths) unless the
// ApplyRestrictionsToBrowse bit is set on the same node. SessionRequired
// applies regardless of operation (no carve-out).

TEST(AccessRestrictionsTest, BrowseSkipsSigningRequiredWhenBitClear)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::SigningRequired);
  // Bit::ApplyRestrictionsToBrowse intentionally NOT set.
  EXPECT_TRUE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Browse));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(
    r, MessageSecurityMode::None, AccessOperation::TranslateBrowsePaths));
  // Non-Browse operations still enforce SigningRequired.
  EXPECT_FALSE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Read));
  EXPECT_FALSE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Write));
}

// @relation(AC-SVR-AUTHZ-019-BROWSE-CARVE-OUT, scope=function)
TEST(AccessRestrictionsTest, BrowseSkipsEncryptionRequiredWhenBitClear)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::EncryptionRequired);
  EXPECT_TRUE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Sign, AccessOperation::Browse));
  // Non-Browse operations: Sign is still insufficient for EncryptionRequired.
  EXPECT_FALSE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Sign, AccessOperation::Read));
}

TEST(AccessRestrictionsTest, BrowseEnforcesSigningRequiredWhenApplyBitSet)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::SigningRequired);
  r.set(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  EXPECT_FALSE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Browse));
  EXPECT_FALSE(rbac_utils::access_restrictions_satisfied(
    r, MessageSecurityMode::None, AccessOperation::TranslateBrowsePaths));
  EXPECT_TRUE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Sign, AccessOperation::Browse));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(
    r, MessageSecurityMode::SignAndEncrypt, AccessOperation::Browse));
}

// @relation(AC-SVR-AUTHZ-019-BROWSE-CARVE-OUT, scope=function)
TEST(AccessRestrictionsTest, BrowseEnforcesEncryptionRequiredWhenApplyBitSet)
{
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::EncryptionRequired);
  r.set(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  EXPECT_FALSE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Sign, AccessOperation::Browse));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(
    r, MessageSecurityMode::SignAndEncrypt, AccessOperation::Browse));
}

TEST(AccessRestrictionsTest, SessionRequiredAppliesToBrowseRegardlessOfApplyBit)
{
  // Per section 5.2.11 SessionRequired has no Browse carve-out - it applies even when
  // ApplyRestrictionsToBrowse is clear.
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::SessionRequired);
  EXPECT_FALSE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::Invalid, AccessOperation::Browse));
  EXPECT_TRUE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Browse));
}

TEST(AccessRestrictionsTest, ApplyRestrictionsToBrowseAloneIsHarmless)
{
  // The ApplyRestrictionsToBrowse bit on its own (no other restriction bits)
  // means "if there were any restrictions they'd also apply to Browse" - but
  // there are none, so the check is permissive.
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  EXPECT_TRUE(
    rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Browse));
  EXPECT_TRUE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None, AccessOperation::Read));
}

TEST(AccessRestrictionsTest, UnparameterisedOverloadEnforcesAllBitsUnconditionally)
{
  // The non-operation overload is for callers outside Browse-class flows
  // (e.g. mask projections). It must enforce every bit regardless.
  AccessRestrictionType r;
  r.set(AccessRestrictionType::Bit::SigningRequired);
  EXPECT_FALSE(rbac_utils::access_restrictions_satisfied(r, MessageSecurityMode::None));
}

// ============================================================================
// permission_bit_for_operation
// ============================================================================

TEST(PermissionBitMappingTest, OperationToBitTable)
{
  using rbac_utils::permission_bit_for_operation;
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::Browse), PermissionType::Bit::Browse);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::ReadRolePermissions),
    PermissionType::Bit::ReadRolePermissions);
  EXPECT_EQ(
    permission_bit_for_operation(AccessOperation::WriteAttribute), PermissionType::Bit::WriteAttribute);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::WriteRolePermissions),
    PermissionType::Bit::WriteRolePermissions);
  EXPECT_EQ(
    permission_bit_for_operation(AccessOperation::WriteHistorizing), PermissionType::Bit::WriteHistorizing);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::Read), PermissionType::Bit::Read);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::Write), PermissionType::Bit::Write);
  EXPECT_EQ(
    permission_bit_for_operation(AccessOperation::WriteAttribute), PermissionType::Bit::WriteAttribute);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::HistoryRead), PermissionType::Bit::ReadHistory);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::Call), PermissionType::Bit::Call);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::TranslateBrowsePaths), PermissionType::Bit::Browse);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::AddNodes), PermissionType::Bit::AddNode);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::DeleteNodes), PermissionType::Bit::DeleteNode);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::AddReferences), PermissionType::Bit::AddReference);
  EXPECT_EQ(
    permission_bit_for_operation(AccessOperation::DeleteReferences), PermissionType::Bit::RemoveReference);

  // Granular Part 3 section 8.55 history/event operations. Each maps to its own
  // permission bit so a node can grant insert but not delete.
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::InsertHistory), PermissionType::Bit::InsertHistory);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::ModifyHistory), PermissionType::Bit::ModifyHistory);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::DeleteHistory), PermissionType::Bit::DeleteHistory);
  EXPECT_EQ(permission_bit_for_operation(AccessOperation::ReceiveEvents), PermissionType::Bit::ReceiveEvents);
}

// ============================================================================
// project_access_level / project_write_mask
// ============================================================================

TEST(ProjectAccessLevelTest, ReadBitProjectsCurrentRead)
{
  PermissionType p;
  p.set(PermissionType::Bit::Read);
  EXPECT_EQ(role_model::project_access_level(p), currentReadBit);
}

TEST(ProjectAccessLevelTest, WriteBitProjectsCurrentWriteBitsOnly)
{
  PermissionType p;
  p.set(PermissionType::Bit::Write);
  EXPECT_EQ(role_model::project_access_level(p), currentWriteAllBits);
  EXPECT_EQ(role_model::project_access_level(p) & historyWriteBit, 0u)
    << "Write permission must NOT imply HistoryWrite";
}

TEST(ProjectAccessLevelTest, HistoryReadProjectsHistoryReadBit)
{
  PermissionType p;
  p.set(PermissionType::Bit::ReadHistory);
  EXPECT_EQ(role_model::project_access_level(p), historyReadBit);
}

TEST(ProjectAccessLevelTest, AnyHistoryWriteBitProjectsHistoryWriteBit)
{
  for (auto bit : {PermissionType::Bit::InsertHistory,
         PermissionType::Bit::ModifyHistory,
         PermissionType::Bit::DeleteHistory})
  {
    PermissionType p;
    p.set(bit);
    EXPECT_EQ(role_model::project_access_level(p), historyWriteBit)
      << "permission bit " << static_cast<int>(bit) << " should project HistoryWrite";
  }
}

TEST(ProjectAccessLevelTest, CombinedReadWriteAndHistory)
{
  PermissionType p;
  p.set(PermissionType::Bit::Read);
  p.set(PermissionType::Bit::Write);
  p.set(PermissionType::Bit::ReadHistory);
  p.set(PermissionType::Bit::InsertHistory);
  EXPECT_EQ(role_model::project_access_level(p),
    currentReadBit | currentWriteAllBits | historyReadBit | historyWriteBit);
}

TEST(ProjectWriteMaskTest, NoBitsYieldsZero)
{
  PermissionType p;
  EXPECT_EQ(role_model::project_write_mask(p), 0u);
}

// @relation(AC-SVR-AUTHZ-006-ATTRIBUTE-WRITE-BITS-SEPARATE, scope=function)
TEST(ProjectWriteMaskTest, AttributeBitsProjectAtTable37Granularity)
{
  PermissionType writeOnly;
  writeOnly.set(PermissionType::Bit::Write);
  EXPECT_EQ(role_model::project_write_mask(writeOnly), 0u)
    << "Value Write does not make any AttributeWriteMask bit writable";

  PermissionType attrOnly;
  attrOnly.set(PermissionType::Bit::WriteAttribute);
  AttributeWriteMask projectedAttributes{role_model::project_write_mask(attrOnly)};
  EXPECT_TRUE(projectedAttributes.test(AttributeWriteMask::Bit::DisplayName));
  EXPECT_FALSE(projectedAttributes.test(AttributeWriteMask::Bit::Historizing));
  EXPECT_FALSE(projectedAttributes.test(AttributeWriteMask::Bit::RolePermissions));

  PermissionType historizingOnly;
  historizingOnly.set(PermissionType::Bit::WriteHistorizing);
  AttributeWriteMask projectedHistorizing{role_model::project_write_mask(historizingOnly)};
  EXPECT_TRUE(projectedHistorizing.test(AttributeWriteMask::Bit::Historizing));
  EXPECT_FALSE(projectedHistorizing.test(AttributeWriteMask::Bit::DisplayName));

  PermissionType rolePermissionsOnly;
  rolePermissionsOnly.set(PermissionType::Bit::WriteRolePermissions);
  AttributeWriteMask projectedRolePermissions{role_model::project_write_mask(rolePermissionsOnly)};
  EXPECT_TRUE(projectedRolePermissions.test(AttributeWriteMask::Bit::RolePermissions));
  EXPECT_FALSE(projectedRolePermissions.test(AttributeWriteMask::Bit::DisplayName));
}

}  // namespace
