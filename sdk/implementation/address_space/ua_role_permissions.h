// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The Part 3 Role-permission evaluation, in the layer that owns the nodes it evaluates.
/// @ingroup address_space

#ifndef UA_ROLE_PERMISSIONS_H
#define UA_ROLE_PERMISSIONS_H

#include "ua_access_restriction_type.h"
#include "ua_node_id.h"
#include "ua_permission_type.h"
#include "ua_role_permission_type.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace ua
{
class NodeAccessor;
class NodeDescription;
}  // namespace ua

/// The standard Role model of Part 3 4.8.3 and 5.2.9, as pure functions over a node and a set of
/// granted Roles.
///
/// These live in the address-space layer rather than the server because the default
/// @ref ua::Namespace::effective_permissions is what a namespace overriding nothing inherits, and a
/// namespace cannot be made to depend on the session and service machinery to answer a question about
/// its own nodes. Nothing here knows which operation is in flight - the mapping from an operation to
/// the bit that gates it is a service-layer concern and stays there.
namespace ua::role_permissions
{

/// Outcome of merging a node's `RolePermissions` against the Roles an identity holds.
///
/// The flag is what separates "the node grants these Roles nothing" from "the node carries no
/// `RolePermissions` at all", which take different fallback paths.
///
/// @ingroup address_space
struct MergedPermissions
{
  PermissionType permissions{};  ///< Every `PermissionType` bit OR-merged across the entries whose
                                 ///< Role the identity holds.
  bool hadAny{false};  ///< `true` iff at least one `RolePermissions` entry was present; `false`
                       ///< distinguishes "nothing granted" from "no `RolePermissions` present".
};

/// Tests whether a Role is one of those granted.
///
/// Supplied by callers whose grant is not already a list of NodeIds; the span overloads below are the
/// ordinary form and allocate nothing.
///
/// @ingroup address_space
using RoleGrantPredicate = std::function<bool(const NodeId&)>;

/// Resolves the effective `RolePermissions` for a node via the node -> namespace-default fallback chain.
///
/// Prefers the node's own `RolePermissions`; when the node carries none, falls back to the namespace
/// default of Part 3 5.2.9.
///
/// Not `noexcept`: it reads an Attribute of a node that another thread may be deleting concurrently,
/// and the accessor reports that by throwing. A `noexcept` spelling would turn a routine race into
/// `std::terminate`.
///
/// @param node             Node whose `RolePermissions` Attribute is consulted; borrowed for the call.
/// @param namespaceDefault The owning namespace's `DefaultRolePermissions`, used as the fallback.
/// @return The effective `RolePermissions`, or `nullopt` iff the node carries none and the namespace
///         publishes none - which is the namespace declaring it does not use the Role model, and
///         callers deny.
std::optional<std::vector<RolePermissionType>> resolve_role_permissions(
  const NodeAccessor& node, const std::optional<std::vector<RolePermissionType>>& namespaceDefault);

/// Resolves the effective `AccessRestrictions` for a node via the node -> namespace-default chain.
///
/// Not `noexcept`, for the reason @ref resolve_role_permissions gives.
///
/// @param node             Node whose `AccessRestrictions` Attribute is consulted; borrowed for the call.
/// @param namespaceDefault The owning namespace's `DefaultAccessRestrictions`, used as the fallback.
/// @return The effective `AccessRestrictions`, or `nullopt` iff neither is present, meaning no channel
///         condition applies.
std::optional<AccessRestrictionType> resolve_access_restrictions(
  const NodeAccessor& node, const std::optional<AccessRestrictionType>& namespaceDefault);

/// @overload Takes the node's description, whose RolePermissions are never an empty array.
///
/// @param node             Description whose RolePermissions are consulted; borrowed for the call.
/// @param namespaceDefault The owning namespace's `DefaultRolePermissions`, used as the fallback.
/// @return As the overload taking an accessor. Never throws but for allocation.
std::optional<std::vector<RolePermissionType>> resolve_role_permissions(
  const NodeDescription& node, const std::optional<std::vector<RolePermissionType>>& namespaceDefault);

/// @overload Takes the node's description.
///
/// @param node             Description whose AccessRestrictions are consulted; borrowed for the call.
/// @param namespaceDefault The owning namespace's `DefaultAccessRestrictions`, used as the fallback.
/// @return As the overload taking an accessor. Never throws.
std::optional<AccessRestrictionType> resolve_access_restrictions(
  const NodeDescription& node, const std::optional<AccessRestrictionType>& namespaceDefault) noexcept;

/// Merges a node's `RolePermissions` down to the single mask an identity holding @p grantedRoles gets.
///
/// Entries naming a Role the identity does not hold contribute nothing; entries naming one it does are
/// OR-merged. Contrast @ref filter_role_permissions, which keeps the per-Role structure.
///
/// @param permissions   The node's `RolePermissions` entries.
/// @param grantedRoles  The Role NodeIds the identity holds; may be empty.
/// @return The merged bits, plus whether any entry was present at all. Never throws.
/// @see filter_role_permissions
MergedPermissions merge_permission_bits(
  const std::vector<RolePermissionType>& permissions, std::span<const NodeId> grantedRoles) noexcept;

/// Merges a node's `RolePermissions` against a caller-supplied grant test.
///
/// The general form, for a caller whose grant is not a list of NodeIds. Identical in every other
/// respect to the span overload.
///
/// @param permissions The node's `RolePermissions` entries.
/// @param isGranted   Tests one Role NodeId; invoked synchronously per entry and not retained.
/// @return The merged bits, plus whether any entry was present at all. Never throws.
MergedPermissions merge_permission_bits(
  const std::vector<RolePermissionType>& permissions, const RoleGrantPredicate& isGranted) noexcept;

/// Filters `RolePermissions` down to the entries naming a Role the identity holds.
///
/// Backs the `UserRolePermissions` Attribute and the `DefaultUserRolePermissions` Property projection
/// of Part 3 5.2.9 and 5.2.10, so it keeps the per-Role structure the Attribute is encoded from;
/// contrast @ref merge_permission_bits, which collapses to one mask.
///
/// @param source       The full `RolePermissions` entries to project.
/// @param grantedRoles The Role NodeIds the identity holds; may be empty.
/// @return The subset naming a granted Role, in the original order. Never throws.
/// @see merge_permission_bits
std::vector<RolePermissionType> filter_role_permissions(
  const std::vector<RolePermissionType>& source, std::span<const NodeId> grantedRoles) noexcept;

/// Filters `RolePermissions` against a caller-supplied grant test.
///
/// @param source    The full `RolePermissions` entries to project.
/// @param isGranted Tests one Role NodeId; invoked synchronously per entry and not retained.
/// @return The subset naming a granted Role, in the original order. Never throws.
std::vector<RolePermissionType> filter_role_permissions(
  const std::vector<RolePermissionType>& source, const RoleGrantPredicate& isGranted) noexcept;

/// Projects a merged `PermissionType` onto the 8-bit `UserAccessLevel` layout (Part 3 5.6.2).
///
/// @param merged The merged permission bits; pass an empty set where the channel condition failed,
///               which clears every bit.
/// @return The `UserAccessLevel` byte. Never throws.
/// @see project_write_mask
uint8_t project_access_level(const PermissionType& merged) noexcept;

/// Projects a merged `PermissionType` onto the 32-bit `UserWriteMask` layout (Part 3 5.2.7).
///
/// @param merged The merged permission bits; pass an empty set where the channel condition failed.
/// @return The `UserWriteMask` value. Never throws.
/// @see project_access_level
uint32_t project_write_mask(const PermissionType& merged) noexcept;

}  // namespace ua::role_permissions

#endif  // UA_ROLE_PERMISSIONS_H
