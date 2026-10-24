// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief What the SDK knows of namespace-0 ReferenceTypes without looking anything up.
/// @ingroup core_types

#ifndef UA_REFERENCE_TYPE_MODEL_H
#define UA_REFERENCE_TYPE_MODEL_H

#include "ua_node_id.h"

#include <span>

namespace ua
{

/// The ReferenceType a Reference of @p referenceType is identified by (OPC 10000-3 section 4.3.4): "Any
/// subtypes of concrete ReferenceTypes are considered to be equal to the base concrete ReferenceTypes when
/// identifying References". For a concrete namespace-0 type this is the highest concrete type above it -
/// HasComponent for HasOrderedComponent, HasEventSource for HasNotifier. Any other type, an application
/// type included, is returned as it is: its supertypes are not known without a lookup.
///
/// @param referenceType A ReferenceType's NodeId.
/// @return The NodeId References of @p referenceType are identified by.
[[nodiscard]] NodeId reference_identity_type(const NodeId& referenceType);

/// Whether a Reference of @p referenceType may be one a Browse hinted with @p hint wants, decided from the
/// namespace-0 type model alone (NR-61). A namespace that applies a ReferenceType hint may leave out a
/// Reference only when this returns `false`.
///
/// `false` only for a namespace-0 type that is neither one of @p hint nor a namespace-0 subtype of one; any
/// other type may match - an application type may be a subtype of a hinted type, which only a lookup could
/// show. A namespace-0 ReferenceType has only namespace-0 supertypes, so an application type in @p hint is
/// never a supertype of a namespace-0 one. An empty @p hint asks for every Reference.
///
/// @param referenceType The type of the Reference to keep or leave out.
/// @param hint          The hinted ReferenceTypes; their subtypes are wanted too.
/// @return Whether the Reference may be wanted.
[[nodiscard]] bool reference_type_may_match_hint(
  const NodeId& referenceType, std::span<const NodeId> hint) noexcept;

}  // namespace ua

#endif  // UA_REFERENCE_TYPE_MODEL_H
