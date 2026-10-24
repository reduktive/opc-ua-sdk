// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_WELL_KNOWN_ROLE_PERMISSIONS_H
#define UA_WELL_KNOWN_ROLE_PERMISSIONS_H

/// @file
/// @brief Well-known Role identifiers, SDK default policy, and declarative construction helpers.
/// @ingroup security

#include "ua_node_id.h"
#include "ua_permission_type.h"
#include "ua_role_permission_type.h"
#include "ua_server_configuration.h"

#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace ua::server
{

/// The nine well-known Roles this SDK materialises, in Part 3 4.8.2 Table 2 order. Part 18
/// defines three SecurityKeyServer Roles that `populate_role_set` does not materialise, so no
/// Session can hold them through this configuration surface.
///
/// @return The nine materialised Roles, in Part 3 4.8.2 Table 2 order.
std::span<const WellKnownRole> well_known_roles() noexcept;

/// Returns the stable Part 3 well-known Role name used in access-token Role claims.
///
/// An invalid enum value returns an empty view rather than aliasing another Role.
///
/// @param role The well-known Role to name.
/// @return The stable Part 3 Role name, or an empty view when @p role is out of range.
std::string_view well_known_role_name(WellKnownRole role) noexcept;

/// Returns the standard NS0 Role Object NodeId for @p role.
///
/// An invalid enum value returns a null NodeId rather than aliasing another Role. Application policy
/// construction should normally use `make_well_known_role_permission`, which reports invalid input
/// as `BadInvalidArgument`.
///
/// @param role The well-known Role whose standard Object NodeId is wanted.
/// @return The NS0 Role Object NodeId, or a null NodeId when @p role is out of range.
NodeId well_known_role_node_id(WellKnownRole role) noexcept;

/// Returns the dense internal bit slot assigned to a valid well-known Role.
///
/// An out-of-range enum value returns `nullopt` rather than silently aliasing another Role.
///
/// @param role The well-known Role whose internal bit slot is wanted.
/// @return The dense bit slot assigned to @p role, or `nullopt` when it is out of range.
std::optional<uint8_t> well_known_role_bit(WellKnownRole role) noexcept;

/// Returns this SDK's default `PermissionType` bitmask for @p role.
///
/// This is SDK policy rather than a normative derivation: Part 3 4.8.2 Table 2 labels the permissions
/// suggested. An invalid enum value returns an empty mask.
///
/// @param role The well-known Role whose default mask is wanted.
/// @return This SDK's default `PermissionType` mask for @p role, or an empty mask when it is
///         out of range.
PermissionType well_known_role_permissions(WellKnownRole role) noexcept;

/// Constructs one node or namespace Role-permission entry without a numeric Role NodeId.
///
/// @param role        The well-known Role whose standard Object NodeId is used.
/// @param permissions The exact mask to attach to the node or namespace.
/// @return A `RolePermissionType` containing the derived Role NodeId and @p permissions.
/// @throws UaException with `BadInvalidArgument` when @p role is out of range.
RolePermissionType make_well_known_role_permission(WellKnownRole role, PermissionType permissions);

/// Constructs namespace defaults from the SDK's documented policy for selected well-known Roles.
///
/// The input order is preserved and a repeated Role is emitted once. This is the concise path for
/// `Namespace::set_namespace_defaults`; use `make_well_known_role_permission` where a node needs a
/// mask different from the SDK default.
///
/// @param roles Roles whose SDK default masks are requested.
/// @return One exact `RolePermissionType` per distinct Role.
/// @throws UaException with `BadInvalidArgument` when any Role is out of range.
std::vector<RolePermissionType> well_known_role_default_permissions(
  std::initializer_list<WellKnownRole> roles);

/// Constructs namespace defaults from one borrowed set of well-known Roles.
///
/// This is the span form of the initializer-list helper. It preserves input order, emits a repeated
/// Role once, and allows the public `well_known_roles` set to be reused for identity mapping and
/// namespace authoring without expanding parallel per-Role declarations.
///
/// @param roles Roles whose SDK default masks are requested.
/// @return One exact `RolePermissionType` per distinct Role.
/// @throws UaException with `BadInvalidArgument` when any Role is out of range.
std::vector<RolePermissionType> well_known_role_default_permissions(std::span<const WellKnownRole> roles);

}  // namespace ua::server

#endif  // UA_WELL_KNOWN_ROLE_PERMISSIONS_H
