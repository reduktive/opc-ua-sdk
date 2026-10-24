// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_HALVES_H
#define UA_REFERENCE_HALVES_H

/// @file
/// @brief Which halves of a Reference an add, a removal or a Node deletion changes.
/// @ingroup address_space

namespace ua
{

/// Which halves of a Reference an add, a removal or a Node deletion changes.
///
/// A Reference is held as two halves: the forward half on its source Node and the inverse half on its target
/// (OPC 10000-3 5.3.2: "A bidirectional Reference is modelled as two separate References"). The address space
/// keeps the two together by default; an application asks for one half only where a request names one, such
/// as DeleteReferences with `deleteBidirectional` FALSE (OPC 10000-4 5.7.5.1) or DeleteNodes with
/// `deleteTargetReferences` FALSE (5.7.4.2).
/// @ingroup address_space
enum class ReferenceHalves
{
  /// The named half and the other half, on a target in this Server. An add adds the other half for the types
  /// the address space pairs: HierarchicalReferences, GeneratesEvent and their subtypes, HasSubtype and
  /// HasEncoding. A removal removes the other half for every type; an other half that is not held is not a
  /// failure. A Node deletion also removes the halves other Nodes hold of the deleted Nodes' References. A
  /// target in another Server keeps its half.
  Both,
  /// Only the named half. A change that would leave a Node without a half OPC 10000-3 requires is refused
  /// with `Bad_NotSupported` and changes nothing: an add or a removal of either half of HasEncoding alone
  /// (5.8.4), an add of a supertype's forward HasSubtype alone, or a removal of a subtype's inverse
  /// HasSubtype alone (5.3.3.3: the subtype holds the inverse half; the supertype's forward half is
  /// optional). A Node deletion removes the deleted Nodes and the halves they hold, and leaves the halves
  /// other Nodes hold of their References (OPC 10000-4 5.7.4.1: "left unresolved").
  ThisHalfOnly,
};

}  // namespace ua

#endif  // UA_REFERENCE_HALVES_H
