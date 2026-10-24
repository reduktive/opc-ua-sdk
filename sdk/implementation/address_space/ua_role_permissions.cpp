// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role_permissions.h"

#include "ua_node_accessor.h"
#include "ua_node_description.h"

#include <algorithm>
#include <cstdint>

namespace ua::role_permissions
{

namespace
{

constexpr uint8_t currentReadBit{0x01};
constexpr uint8_t currentWriteBit{0x02};
constexpr uint8_t historyReadBit{0x04};
constexpr uint8_t historyWriteBit{0x08};
constexpr uint8_t semanticChangeBit{0x10};
constexpr uint8_t statusWriteBit{0x20};
constexpr uint8_t timestampWriteBit{0x40};

// PermissionType::Write projects every CurrentWrite-related bit, but not HistoryWrite: history-side
// writes are gated by the separate InsertHistory / ModifyHistory / DeleteHistory bits.
constexpr uint8_t currentWriteAllBits =
  currentWriteBit | semanticChangeBit | statusWriteBit | timestampWriteBit;

// The two grant shapes differ only in how one Role is tested, so the loop is written once and the
// overloads bind the test. Templated rather than taking a `std::function` so the span form neither
// allocates nor pays an indirect call - the permitted path is on every request.
template<typename GrantTest>
MergedPermissions merge_with(const std::vector<RolePermissionType>& permissions, const GrantTest& granted)
{
  MergedPermissions out;
  for (const auto& entry : permissions)
  {
    out.hadAny = true;
    if (!granted(entry.role_id()))
    {
      continue;
    }
    out.permissions.from_underlying_type(
      out.permissions.as_underlying_type() | entry.permissions().as_underlying_type());
  }
  return out;
}

template<typename GrantTest>
std::vector<RolePermissionType> filter_with(
  const std::vector<RolePermissionType>& source, const GrantTest& granted)
{
  std::vector<RolePermissionType> out;
  out.reserve(source.size());
  for (const auto& entry : source)
  {
    if (granted(entry.role_id()))
    {
      out.push_back(entry);
    }
  }
  return out;
}

/// Membership of a Role in a granted set. Linear because the set is a session's Role list - single
/// digits in every deployment - so an index would cost more to build than it saves.
struct GrantedRoleSpan
{
  std::span<const NodeId> roles;

  bool operator()(const NodeId& roleId) const noexcept
  {
    return std::find(roles.begin(), roles.end(), roleId) != roles.end();
  }
};

}  // namespace

std::optional<std::vector<RolePermissionType>> resolve_role_permissions(
  const NodeAccessor& node, const std::optional<std::vector<RolePermissionType>>& namespaceDefault)
{
  if (auto nodePermissions = node.get_role_permissions(); nodePermissions && !nodePermissions->empty())
  {
    return nodePermissions;
  }
  return namespaceDefault;
}

std::optional<AccessRestrictionType> resolve_access_restrictions(
  const NodeAccessor& node, const std::optional<AccessRestrictionType>& namespaceDefault)
{
  if (auto nodeRestrictions = node.get_access_restrictions())
  {
    return nodeRestrictions;
  }
  return namespaceDefault;
}

std::optional<std::vector<RolePermissionType>> resolve_role_permissions(
  const NodeDescription& node, const std::optional<std::vector<RolePermissionType>>& namespaceDefault)
{
  if (const auto* nodePermissions = node.role_permissions(); nodePermissions && !nodePermissions->empty())
  {
    return *nodePermissions;
  }
  return namespaceDefault;
}

std::optional<AccessRestrictionType> resolve_access_restrictions(
  const NodeDescription& node, const std::optional<AccessRestrictionType>& namespaceDefault) noexcept
{
  if (auto nodeRestrictions = node.access_restrictions())
  {
    return nodeRestrictions;
  }
  return namespaceDefault;
}

MergedPermissions merge_permission_bits(
  const std::vector<RolePermissionType>& permissions, std::span<const NodeId> grantedRoles) noexcept
{
  return merge_with(permissions, GrantedRoleSpan{grantedRoles});
}

MergedPermissions merge_permission_bits(
  const std::vector<RolePermissionType>& permissions, const RoleGrantPredicate& isGranted) noexcept
{
  return merge_with(permissions, isGranted);
}

std::vector<RolePermissionType> filter_role_permissions(
  const std::vector<RolePermissionType>& source, std::span<const NodeId> grantedRoles) noexcept
{
  return filter_with(source, GrantedRoleSpan{grantedRoles});
}

std::vector<RolePermissionType> filter_role_permissions(
  const std::vector<RolePermissionType>& source, const RoleGrantPredicate& isGranted) noexcept
{
  return filter_with(source, isGranted);
}

uint8_t project_access_level(const PermissionType& merged) noexcept
{
  uint8_t mask{0};
  if (merged.test(PermissionType::Bit::Read))
  {
    mask |= currentReadBit;
  }
  if (merged.test(PermissionType::Bit::Write))
  {
    mask |= currentWriteAllBits;
  }
  if (merged.test(PermissionType::Bit::ReadHistory))
  {
    mask |= historyReadBit;
  }
  if (merged.test(PermissionType::Bit::InsertHistory) || merged.test(PermissionType::Bit::ModifyHistory) ||
      merged.test(PermissionType::Bit::DeleteHistory))
  {
    mask |= historyWriteBit;
  }
  return mask;
}

uint32_t project_write_mask(const PermissionType& merged) noexcept
{
  AttributeWriteMask projected;
  if (merged.test(PermissionType::Bit::WriteAttribute))
  {
    projected.from_underlying_type(0xffffffffu);
    projected.reset(AttributeWriteMask::Bit::Historizing);
    projected.reset(AttributeWriteMask::Bit::RolePermissions);
  }
  if (merged.test(PermissionType::Bit::WriteHistorizing))
  {
    projected.set(AttributeWriteMask::Bit::Historizing);
  }
  if (merged.test(PermissionType::Bit::WriteRolePermissions))
  {
    projected.set(AttributeWriteMask::Bit::RolePermissions);
  }
  return projected.as_underlying_type();
}

}  // namespace ua::role_permissions
