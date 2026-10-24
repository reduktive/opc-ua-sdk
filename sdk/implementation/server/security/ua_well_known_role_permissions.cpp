// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_well_known_role_permissions.h"

#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_object_id.h"
#include "ua_utilities.h"

#include <algorithm>
#include <array>
#include <string>

namespace ua::server
{

namespace
{

constexpr std::array<WellKnownRole, 9> wellKnownRoles{{
  WellKnownRole::Anonymous,
  WellKnownRole::AuthenticatedUser,
  WellKnownRole::Observer,
  WellKnownRole::Operator,
  WellKnownRole::Engineer,
  WellKnownRole::Supervisor,
  WellKnownRole::ConfigureAdmin,
  WellKnownRole::SecurityAdmin,
  WellKnownRole::TrustedApplication,
}};

}  // namespace

std::span<const WellKnownRole> well_known_roles() noexcept
{
  return {wellKnownRoles.data(), wellKnownRoles.size()};
}

std::string_view well_known_role_name(WellKnownRole role) noexcept
{
  switch (role)
  {
  case WellKnownRole::Anonymous:
    return "Anonymous";
  case WellKnownRole::AuthenticatedUser:
    return "AuthenticatedUser";
  case WellKnownRole::Observer:
    return "Observer";
  case WellKnownRole::Operator:
    return "Operator";
  case WellKnownRole::Engineer:
    return "Engineer";
  case WellKnownRole::Supervisor:
    return "Supervisor";
  case WellKnownRole::ConfigureAdmin:
    return "ConfigureAdmin";
  case WellKnownRole::SecurityAdmin:
    return "SecurityAdmin";
  case WellKnownRole::TrustedApplication:
    return "TrustedApplication";
  }
  return {};
}

NodeId well_known_role_node_id(WellKnownRole role) noexcept
{
  switch (role)
  {
  case WellKnownRole::Anonymous:
    return NodeId{ObjectId::WellKnownRole_Anonymous};
  case WellKnownRole::AuthenticatedUser:
    return NodeId{ObjectId::WellKnownRole_AuthenticatedUser};
  case WellKnownRole::Observer:
    return NodeId{ObjectId::WellKnownRole_Observer};
  case WellKnownRole::Operator:
    return NodeId{ObjectId::WellKnownRole_Operator};
  case WellKnownRole::Engineer:
    return NodeId{ObjectId::WellKnownRole_Engineer};
  case WellKnownRole::Supervisor:
    return NodeId{ObjectId::WellKnownRole_Supervisor};
  case WellKnownRole::ConfigureAdmin:
    return NodeId{ObjectId::WellKnownRole_ConfigureAdmin};
  case WellKnownRole::SecurityAdmin:
    return NodeId{ObjectId::WellKnownRole_SecurityAdmin};
  case WellKnownRole::TrustedApplication:
    return NodeId{ObjectId::WellKnownRole_TrustedApplication};
  }
  return {};
}

std::optional<uint8_t> well_known_role_bit(WellKnownRole role) noexcept
{
  switch (role)
  {
  case WellKnownRole::Anonymous:
    return 0;
  case WellKnownRole::AuthenticatedUser:
    return 1;
  case WellKnownRole::Observer:
    return 2;
  case WellKnownRole::Operator:
    return 3;
  case WellKnownRole::Engineer:
    return 4;
  case WellKnownRole::Supervisor:
    return 5;
  case WellKnownRole::ConfigureAdmin:
    return 6;
  case WellKnownRole::SecurityAdmin:
    return 7;
  case WellKnownRole::TrustedApplication:
    return 8;
  }
  return std::nullopt;
}

PermissionType well_known_role_permissions(WellKnownRole role) noexcept
{
  using Bit = PermissionType::Bit;
  switch (role)
  {
  // The Security Role Well Known Group 2 profile requires both baseline roles to browse and read
  // non-security Server/type nodes; per-node RolePermissions still narrow where that floor applies.
  case WellKnownRole::Anonymous:
  case WellKnownRole::AuthenticatedUser:
    return PermissionType{Bit::Browse, Bit::Read};
  case WellKnownRole::Observer:
    // Table 2: browse, read live data, read history, subscribe to data/events.
    return PermissionType{Bit::Browse, Bit::Read, Bit::ReadHistory, Bit::ReceiveEvents};
  case WellKnownRole::Operator:
    // Table 2: Observer plus writing some live data and calling some Methods. Which
    // data and which Methods is narrowed per-Node by an explicit RolePermissions array.
    return PermissionType{
      Bit::Browse, Bit::Read, Bit::Write, Bit::ReadHistory, Bit::ReceiveEvents, Bit::Call};
  case WellKnownRole::Engineer:
    // Table 2: browse, read/write configuration data, read history, call, subscribe.
    // Historizing is a configuration Attribute rather than a value, so "write
    // configuration data" reaches WriteHistorizing. The three history-write bits are a
    // policy grant beyond Table 2; 9.5 states the reasoning.
    return PermissionType{Bit::Browse,
      Bit::WriteAttribute,
      Bit::WriteHistorizing,
      Bit::Read,
      Bit::Write,
      Bit::ReadHistory,
      Bit::InsertHistory,
      Bit::ModifyHistory,
      Bit::DeleteHistory,
      Bit::ReceiveEvents,
      Bit::Call};
  case WellKnownRole::Supervisor:
    // Table 2: browse, read live data, read history, call, subscribe. No Write.
    return PermissionType{Bit::Browse, Bit::Read, Bit::ReadHistory, Bit::ReceiveEvents, Bit::Call};
  case WellKnownRole::ConfigureAdmin:
    // Table 2: change the non-security related configuration settings. The shape of the
    // Address Space is non-security configuration and no other Table 2 sentence reaches
    // it, so the four node-management bits derive from that row. WriteRolePermissions is
    // security-related and belongs to SecurityAdmin alone.
    //
    // ReceiveEvents is a policy grant beyond Table 2, whose administrative rows say what a
    // Role may CHANGE and are silent on what it may OBSERVE. Reading that silence as denial
    // leaves the Role that reshapes the Address Space unable to receive the ModelChangeEvents
    // announcing its own edits: every Event names an EventType Node in ns=0 (Part 3 8.55
    // requires ReceiveEvents on the EventTypeId as well as the SourceNode), so a Role without
    // the bit receives nothing at all, from any Node, however the host configures its own
    // namespaces. 9.5 states the reasoning for the sibling extrapolations.
    return PermissionType{Bit::Browse,
      Bit::WriteAttribute,
      Bit::WriteHistorizing,
      Bit::Read,
      Bit::Write,
      Bit::ReceiveEvents,
      Bit::Call,
      Bit::AddReference,
      Bit::RemoveReference,
      Bit::DeleteNode,
      Bit::AddNode};
  case WellKnownRole::SecurityAdmin:
    // Table 2: change security related settings - the two RolePermissions bits plus the
    // configuration-write surface. The node-management grant is a policy grant beyond
    // that row; 9.5 states the reasoning.
    //
    // ReceiveEvents is the same kind of policy grant, and the sharpest instance of it: without
    // the bit the security administrator cannot subscribe to the AuditEvents that report the
    // security-relevant activity it exists to oversee. Part 5 makes auditing a security
    // concern, and Table 2's security row is silent on observation rather than denying it.
    return PermissionType{Bit::Browse,
      Bit::ReadRolePermissions,
      Bit::WriteAttribute,
      Bit::WriteRolePermissions,
      Bit::WriteHistorizing,
      Bit::Read,
      Bit::Write,
      Bit::ReceiveEvents,
      Bit::Call,
      Bit::AddReference,
      Bit::RemoveReference,
      Bit::DeleteNode,
      Bit::AddNode};
  case WellKnownRole::TrustedApplication:
    // Named by no Table 2 row. A trusted peer application browses, reads live data and
    // receives events; it never writes, modifies history, or touches security settings.
    return PermissionType{Bit::Browse, Bit::Read, Bit::ReceiveEvents};
  }
  return {};
}

RolePermissionType make_well_known_role_permission(WellKnownRole role, PermissionType permissions)
{
  if (!well_known_role_bit(role))
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidWellKnownRole",
        "A well-known Role policy entry used an out-of-range Role value",
        "WellKnownRolePermissions")
        .context(ContextKeys::actual, std::to_string(utils::to_underlying(role)))};
  }
  RolePermissionType entry;
  entry.role_id() = well_known_role_node_id(role);
  entry.permissions() = permissions;
  return entry;
}

std::vector<RolePermissionType> well_known_role_default_permissions(
  std::initializer_list<WellKnownRole> roles)
{
  return well_known_role_default_permissions(std::span<const WellKnownRole>{roles.begin(), roles.size()});
}

std::vector<RolePermissionType> well_known_role_default_permissions(std::span<const WellKnownRole> roles)
{
  std::vector<RolePermissionType> permissions;
  permissions.reserve(roles.size());
  for (const auto role : roles)
  {
    const auto roleId = well_known_role_node_id(role);
    if (std::find_if(permissions.begin(),
          permissions.end(),
          [&roleId](const RolePermissionType& entry)
          { return entry.role_id() == roleId; }) != permissions.end())
    {
      continue;
    }
    permissions.push_back(make_well_known_role_permission(role, well_known_role_permissions(role)));
  }
  return permissions;
}

}  // namespace ua::server
