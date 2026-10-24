// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ROLE_METHOD_HANDLERS_H
#define UA_ROLE_METHOD_HANDLERS_H

#include "ua_address_space.h"
#include "ua_server_configuration.h"

#include <memory>
#include <optional>
#include <vector>

namespace ua::server
{

class EventBus;
class RoleConfiguration;

/// Attach call handlers to the runtime role-management Methods exposed by the
/// `RoleSet` Object (`AddRole` / `RemoveRole`) and by each well-known Role
/// Object (`AddIdentity` / `RemoveIdentity` / `AddApplication` /
/// `RemoveApplication` / `AddEndpoint` / `RemoveEndpoint`). A Role created by
/// `AddRole` carries the same six Methods with the same handlers, installed when
/// it is created; `RemoveRole` deletes them with the Role's Nodes. Also install
/// write-notifier callbacks on the two writable `*Exclude` Variables so
/// direct Writes mirror back into `RoleConfiguration`.
///
/// Each successful management call emits `RoleMappingRuleChangedAuditEvent`
/// (Part 18 4.5) via the supplied `EventBus`. Writes to the `*Exclude`
/// Variables do NOT emit the audit event (4.5 lists only the 6 management
/// methods + AddRole/RemoveRole - Exclude-flag writes are spec-silent and
/// covered by the generic AuditWriteUpdateEventType if wired by Part 5).
///
/// `eventBus` may be empty when auditing is disabled - handlers gracefully
/// skip emission. `serverApplicationUri` is included on every audit event.
///
/// Authorization is enforced by the Call service from each Method node's RolePermissions and
/// AccessRestrictions before a handler can be invoked.
void attach_role_management_handlers(AddressSpace addressSpace, std::shared_ptr<RoleConfiguration> roleConfig,
  std::weak_ptr<EventBus> eventBus, ua::String serverApplicationUri,
  const std::optional<std::vector<WellKnownRole>>& selection);

}  // namespace ua::server

#endif  // UA_ROLE_METHOD_HANDLERS_H
