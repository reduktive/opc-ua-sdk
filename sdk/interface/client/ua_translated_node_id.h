// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TRANSLATED_NODE_ID_H
#define UA_TRANSLATED_NODE_ID_H

/// @file
/// @brief One target of a relative-path translation (client design section 7.2A).
/// @ingroup client

#include "ua_expanded_node_id.h"
#include "ua_node_id.h"

#include <cstdint>
#include <string_view>

namespace ua::client
{

/// One target of a relative-path translation: tier-2 sugar over a wire @ref ua::BrowsePathTarget
/// (`TypedAccess::translate_browse_path`, section 7.2A / CL-VIEW-014/015/019).
///
/// `translate_browse_path` returns one per target the server found. A PARTIAL or cross-server target is
/// data, not an error: @ref is_fully_resolved or @ref is_local is false, and @ref remainingPathIndex
/// names the first element left to resolve. The SDK never connects to another server to resolve the
/// rest (CL-VIEW-019); the target is kept as its full @ref ExpandedNodeId.
/// @ingroup client
struct TranslatedNodeId
{
  /// The sentinel @ref remainingPathIndex value meaning "the whole relative path resolved to @ref targetId"
  /// (the wire `UInt32.max`).
  static constexpr std::uint32_t fullyResolved = 0xFFFFFFFFu;

  /// The resolved target. For a fully-resolved LOCAL path this is a plain @ref ua::NodeId wrapped in an
  /// @ref ExpandedNodeId with `serverIndex == 0` and an empty `namespaceUri`; for a target on ANOTHER server
  /// (a cross-server / partial resolution) it retains the full @ref ExpandedNodeId  -  the SDK does NOT
  /// auto-connect to resolve further (CL-VIEW-019). Read @ref is_local before calling @ref local_node_id.
  ua::ExpandedNodeId targetId;

  /// The index of the FIRST relative-path element that was NOT resolved, or @ref fullyResolved when the
  /// whole path resolved (CL-VIEW-015). A value other than @ref fullyResolved means PARTIAL resolution: the
  /// residual path begins at this element (normally because @ref targetId is on another server). The raw wire
  /// value is surfaced verbatim (no normalisation beyond naming the sentinel).
  std::uint32_t remainingPathIndex = fullyResolved;

  /// @return True when the requested condition is satisfied.
  /// True when the whole relative path resolved to @ref targetId (`remainingPathIndex == fullyResolved`).
  [[nodiscard]] bool is_fully_resolved() const noexcept
  {
    return remainingPathIndex == fullyResolved;
  }

  /// @return True when the requested condition is satisfied.
  /// True when @ref targetId is a LOCAL node (`serverIndex == 0` and an empty `namespaceUri`), so
  /// @ref local_node_id is meaningful.
  [[nodiscard]] bool is_local() const noexcept
  {
    return targetId.server_index() == 0 && static_cast<std::string_view>(targetId.namespace_uri()).empty();
  }

  /// @return A reference to this object.
  /// The resolved target as a plain @ref ua::NodeId. Meaningful only when @ref is_local is true; for a
  /// cross-server target the returned NodeId is the server-relative node without its @ref ExpandedNodeId
  /// server/namespace context (read @ref targetId directly for a cross-server target).
  [[nodiscard]] const ua::NodeId& local_node_id() const noexcept
  {
    return targetId.node_id();
  }
};

}  // namespace ua::client

#endif  // UA_TRANSLATED_NODE_ID_H
