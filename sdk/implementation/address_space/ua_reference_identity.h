// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Which References of an add a Node already holds, as OPC 10000-3 section 4.3.4 identifies them.

#ifndef UA_REFERENCE_IDENTITY_H
#define UA_REFERENCE_IDENTITY_H

#include "ua_reference.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <span>
#include <vector>

namespace ua::reference_identity
{

/// For each of @p added, whether it is the same Reference (@ref Reference::identifies_same_reference_as) as
/// one of @p held or as an earlier one of @p added. Takes time proportional to the size of @p held plus
/// that of @p added: References are first matched by target, and only those with the same target are
/// compared further.
///
/// @param held  The References the source Node holds.
/// @param added The References to add, in order.
/// @return One entry per element of @p added; `true` where that Reference is held or repeated.
std::vector<bool> held_or_repeated(std::span<const Reference> held, std::span<const Reference> added);

/// The References a source Node holding @p held must be given so that it holds each of @p added as the type
/// asked for or a namespace-0 subtype of it (@ref held_as_requested). The References OPC 10000-3
/// section 4.3.4 identifies as one are decided together, so the answer does not depend on their order: a
/// group the Node holds adds nothing when the held type is each one's type or a subtype of it; a group it
/// does not hold adds the one member whose type is each other member's type or a subtype of it. A
/// ReferenceType has one supertype, so the types of a group that can be held as asked form one line of
/// subtypes. The cost and the matching are those of
/// @ref held_or_repeated.
///
/// @param held  The References the source Node holds.
/// @param added The References to add.
/// @return The References to add, one per group not held, in the order of each group's first member; or the
///         refusal (@ref conflicting_type_refusal) of the first member found that cannot be held as asked.
Result<std::vector<Reference>> references_to_add(
  std::span<const Reference> held, std::span<const Reference> added);

/// Whether @p identified, the same Reference as @p requested, is the Reference asked for: of @p requested's
/// type, or of a namespace-0 subtype of it, so that a Browse for @p requested's type finds it. Two
/// References of different types are the same Reference only when both types are namespace-0 types (an
/// application type is identified by its own NodeId), so the namespace-0 type model decides it.
///
/// @param requested The Reference to add.
/// @param identified The held or repeated Reference @p requested is identified with.
/// @return `false` when @p identified's type is a supertype of, or unrelated to, @p requested's.
[[nodiscard]] bool held_as_requested(const Reference& requested, const Reference& identified) noexcept;

/// The refusal of an add of @p requested when the same Reference is held, or repeated, as @p identified with
/// a type that is not the one asked for (@ref held_as_requested is `false`):
/// Bad_DuplicateReferenceNotAllowed, naming both types and the target.
[[nodiscard]] StatusCode conflicting_type_refusal(const Reference& requested, const Reference& identified);

}  // namespace ua::reference_identity

#endif  // UA_REFERENCE_IDENTITY_H
