// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A relative path that follows hierarchical references by BrowseName.
/// @ingroup core_types

#ifndef UA_HIERARCHICAL_PATH_H
#define UA_HIERARCHICAL_PATH_H

#include "ua_qualified_name.h"
#include "ua_relative_path.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ua
{

/// Builds a relative path that follows forward `HierarchicalReferences`, subtypes included, through the
/// named children in order: one shape for any modelled containment (Organizes, HasComponent,
/// HasProperty, ...). Use it with `TypedAccess::resolve_path_sync` or a TranslateBrowsePathsToNodeIds
/// request.
///
/// @code
/// const ua::RelativePath path = ua::hierarchical_path(ns, {"Plant", "Boiler", "Setpoint"});
/// @endcode
///
/// @param namespaceIndex The namespace index of every BrowseName.
/// @param names          The children's BrowseName names, from the start node down.
/// @return The relative path.
/// @ingroup core_types
RelativePath hierarchical_path(uint16_t namespaceIndex, std::vector<std::string> names);

/// Builds a relative path that follows forward `HierarchicalReferences`, subtypes included, through the
/// children with these BrowseNames in order, for a path that crosses namespaces.
///
/// @param names The children's BrowseNames, from the start node down.
/// @return The relative path.
/// @ingroup core_types
RelativePath hierarchical_path(std::vector<QualifiedName> names);

}  // namespace ua

#endif  // UA_HIERARCHICAL_PATH_H
