// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role_permission_utils.h"

namespace ua::server::role_permission_utils
{

bool access_restrictions_satisfied(std::optional<AccessRestrictionType> restrictions,
  MessageSecurityMode channelMode, AccessOperation operation) noexcept
{
  if (!restrictions)
  {
    return true;
  }

  const bool signedChannel =
    channelMode == MessageSecurityMode::Sign || channelMode == MessageSecurityMode::SignAndEncrypt;
  const bool encryptedChannel = channelMode == MessageSecurityMode::SignAndEncrypt;
  const bool isBrowseClass =
    operation == AccessOperation::Browse || operation == AccessOperation::TranslateBrowsePaths;
  const bool applyToBrowse = restrictions->test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  const bool enforceChannelBits = !isBrowseClass || applyToBrowse;

  if (enforceChannelBits && restrictions->test(AccessRestrictionType::Bit::SigningRequired) && !signedChannel)
  {
    return false;
  }
  if (enforceChannelBits && restrictions->test(AccessRestrictionType::Bit::EncryptionRequired) &&
      !encryptedChannel)
  {
    return false;
  }
  // SessionRequired is enforced at the dispatcher (every request that reaches
  // namespace access control is already in a session); honour the bit by checking it is set
  // and treating non-session contexts (channelMode == Invalid) as failures.
  // Per Part 3 5.2.11 the SessionRequired carve-out does NOT depend on
  // ApplyRestrictionsToBrowse - the bit applies to every operation including
  // Browse.
  if (restrictions->test(AccessRestrictionType::Bit::SessionRequired) &&
      channelMode == MessageSecurityMode::Invalid)
  {
    return false;
  }
  return true;
}

bool access_restrictions_satisfied(
  std::optional<AccessRestrictionType> restrictions, MessageSecurityMode channelMode) noexcept
{
  // Mask-projection / non-Browse-flow callers: enforce every bit
  // unconditionally. Use AccessOperation::Read as a sentinel; the only
  // Browse-class operations are Browse / TranslateBrowsePaths.
  return access_restrictions_satisfied(restrictions, channelMode, AccessOperation::Read);
}

PermissionType::Bit permission_bit_for_operation(AccessOperation operation) noexcept
{
  switch (operation)
  {
  case AccessOperation::Browse:
    return PermissionType::Bit::Browse;
  case AccessOperation::ReadRolePermissions:
    return PermissionType::Bit::ReadRolePermissions;
  case AccessOperation::WriteAttribute:
    return PermissionType::Bit::WriteAttribute;
  case AccessOperation::WriteRolePermissions:
    return PermissionType::Bit::WriteRolePermissions;
  case AccessOperation::WriteHistorizing:
    return PermissionType::Bit::WriteHistorizing;
  case AccessOperation::Read:
    return PermissionType::Bit::Read;
  case AccessOperation::Write:
    return PermissionType::Bit::Write;
  case AccessOperation::HistoryRead:
    return PermissionType::Bit::ReadHistory;
  case AccessOperation::InsertHistory:
    return PermissionType::Bit::InsertHistory;
  case AccessOperation::ModifyHistory:
    return PermissionType::Bit::ModifyHistory;
  case AccessOperation::DeleteHistory:
    return PermissionType::Bit::DeleteHistory;
  case AccessOperation::Call:
    return PermissionType::Bit::Call;
  case AccessOperation::TranslateBrowsePaths:
    return PermissionType::Bit::Browse;
  case AccessOperation::ReceiveEvents:
    return PermissionType::Bit::ReceiveEvents;
  case AccessOperation::AddNodes:
    return PermissionType::Bit::AddNode;
  case AccessOperation::DeleteNodes:
    return PermissionType::Bit::DeleteNode;
  case AccessOperation::AddReferences:
    return PermissionType::Bit::AddReference;
  case AccessOperation::DeleteReferences:
    return PermissionType::Bit::RemoveReference;
  }
  return PermissionType::Bit::Browse;
}

}  // namespace ua::server::role_permission_utils
