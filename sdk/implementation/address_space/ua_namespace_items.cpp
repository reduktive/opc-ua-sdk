// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_items.h"

#include <utility>

namespace ua
{

std::array<ReferenceChange, 2> ReferenceChange::both_halves(
  NodeId source, NodeId referenceType, NodeId target)
{
  // The inverse half is held by the target and points back at the source. Neither half is marked
  // sourceCreated: only the creator knows which source it created in the same operation, and sets it.
  ReferenceChange forward{
    .source = source, .referenceType = referenceType, .target = ExpandedNodeId{target}, .isForward = true};
  ReferenceChange inverse{.source = std::move(target),
    .referenceType = std::move(referenceType),
    .target = ExpandedNodeId{std::move(source)},
    .isForward = false};
  return {std::move(forward), std::move(inverse)};
}

}  // namespace ua
