// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ROLE_SET_POPULATION_H
#define UA_ROLE_SET_POPULATION_H

#include "ua_address_space.h"
#include "ua_server_configuration.h"

#include <memory>
#include <optional>
#include <vector>

namespace ua::server
{

class RoleConfiguration;

/// Mirror `RoleConfiguration` state into the well-known and host-declared Role instances in NS0.
///
/// `compute_ns0_access_decoration` applies the Part-18 access-control Attributes atomically while
/// importing NS0. This later materialisation step writes configured Variable values, includes only
/// the selected well-known Roles, and creates any host-declared custom Role Objects with RoleType as
/// their TypeDefinition. It does not synthesize or overwrite access policy.
///
/// Variable values on each role instance are populated from the matching
/// `RoleConfiguration::RoleDefinition`. Roles not in the supplied selection (when set) are skipped.
///
/// Implements the role-set population step (Cut 5: G.1).
void populate_role_set(AddressSpace addressSpace, const RoleConfiguration& roleConfig,
  const std::optional<std::vector<WellKnownRole>>& selection);

}  // namespace ua::server

#endif  // UA_ROLE_SET_POPULATION_H
