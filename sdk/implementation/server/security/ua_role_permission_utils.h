// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The two access-control helpers that depend on which operation is in flight.
/// @ingroup security

#ifndef UA_ROLE_PERMISSION_UTILS_H
#define UA_ROLE_PERMISSION_UTILS_H

#include "ua_access_restriction_type.h"
#include "ua_message_security_mode.h"
#include "ua_permission_type.h"

#include "ua_access_operation.h"

#include <optional>

/// What is left of the access-control helpers once the Role model itself has moved down to the
/// address-space layer as `ua::role_permissions`.
///
/// Only these two remain, and they remain for one reason: both take an @ref AccessOperation, and a
/// namespace is never told which operation is in flight. Everything that evaluates a node's
/// `RolePermissions` against a set of granted Roles is in
/// `sdk/interface/address_space/ua_role_permissions.h`.
namespace ua::server::role_permission_utils
{

/// Tests whether the channel security satisfies a node's `AccessRestrictions` for a given operation.
///
/// Per Part 3 5.2.11, `SigningRequired` and `EncryptionRequired` do NOT apply to Browse-class
/// operations (`Browse`, `TranslateBrowsePaths`) unless the `ApplyRestrictionsToBrowse` bit is set on
/// the same node; `SessionRequired` applies regardless of operation. This overload encodes that
/// operation-aware rule. Use the
/// access_restrictions_satisfied(std::optional<AccessRestrictionType>, MessageSecurityMode) overload
/// for flows outside Browse-class operations, which applies every restriction unconditionally.
///
/// @param restrictions The node's effective `AccessRestrictions`; `nullopt` means none apply.
/// @param channelMode  Security mode of the channel carrying the request.
/// @param operation    Operation being authorized, selecting the Browse-class exemption above.
/// @return `true` iff @p restrictions is absent or every applicable signing / encryption / session bit
///         is compatible with @p channelMode. Never throws.
/// @see access_restrictions_satisfied(std::optional<AccessRestrictionType>, MessageSecurityMode)
bool access_restrictions_satisfied(std::optional<AccessRestrictionType> restrictions,
  MessageSecurityMode channelMode, AccessOperation operation) noexcept;

/// Tests whether the channel security satisfies a node's `AccessRestrictions`, applying all of them.
///
/// Operation-agnostic variant: every signing / encryption / session bit is enforced unconditionally,
/// with no Browse-class exemption. Used by callers outside Browse-class flows.
///
/// @param restrictions The node's effective `AccessRestrictions`; `nullopt` means none apply.
/// @param channelMode  Security mode of the channel carrying the request.
/// @return `true` iff @p restrictions is absent or all of its bits are compatible with @p channelMode.
///         Never throws.
/// @see access_restrictions_satisfied(std::optional<AccessRestrictionType>, MessageSecurityMode,
///      AccessOperation)
bool access_restrictions_satisfied(
  std::optional<AccessRestrictionType> restrictions, MessageSecurityMode channelMode) noexcept;

/// Maps an @ref AccessOperation to the `PermissionType::Bit` that gates it (Part 3 Table 37).
///
/// @param operation Operation being authorized.
/// @return The permission bit whose grant authorizes @p operation. Never throws.
PermissionType::Bit permission_bit_for_operation(AccessOperation operation) noexcept;

}  // namespace ua::server::role_permission_utils

#endif  // UA_ROLE_PERMISSION_UTILS_H
