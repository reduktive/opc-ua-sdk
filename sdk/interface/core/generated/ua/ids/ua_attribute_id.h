// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ATTRIBUTE_ID_H
#define UA_ATTRIBUTE_ID_H

#include "ua_includes.h"

namespace ua
{

enum class AttributeId : uint32_t
{
  NodeId = 1,
  NodeClass = 2,
  BrowseName = 3,
  DisplayName = 4,
  Description = 5,
  WriteMask = 6,
  UserWriteMask = 7,
  IsAbstract = 8,
  Symmetric = 9,
  InverseName = 10,
  ContainsNoLoops = 11,
  EventNotifier = 12,
  Value = 13,
  DataType = 14,
  ValueRank = 15,
  ArrayDimensions = 16,
  AccessLevel = 17,
  UserAccessLevel = 18,
  MinimumSamplingInterval = 19,
  Historizing = 20,
  Executable = 21,
  UserExecutable = 22,
  DataTypeDefinition = 23,
  RolePermissions = 24,
  UserRolePermissions = 25,
  AccessRestrictions = 26,
  AccessLevelEx = 27
};

}  // namespace ua

#endif  // UA_ATTRIBUTE_ID_H
