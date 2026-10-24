// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_TABLE_H
#define UA_SERVER_TABLE_H

/// @file
/// @brief Per-Connection immutable snapshot of a server's ServerArray (client tier-1).
/// @ingroup client

#include "ua_expanded_node_id.h"
#include "ua_result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ua::client
{

/// A server index into `Server.ServerArray` (an OPC UA `UInt32`).
using ServerIndex = std::uint32_t;

/// Immutable, Session-scoped snapshot of `Server.ServerArray` (OPC 10000-5 section 6.3.1).
/// @ingroup client
class ServerTable
{
public:
  /// @param index The index.
  /// @return The requested value.
  /// Returns the URI at @p index, or null when the index is outside this snapshot.
  [[nodiscard]] std::optional<std::string_view> lookup_uri(ServerIndex index) const noexcept;

  /// @param uri The uri.
  /// @return The requested value.
  /// Returns the first index carrying @p uri, or null when absent.
  [[nodiscard]] std::optional<ServerIndex> lookup_index(std::string_view uri) const noexcept;

  /// @param expanded The expanded.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Resolves an ExpandedNodeId's ServerIndex to its Server URI without altering the NodeId.
  [[nodiscard]] ua::Result<std::string> resolve_server_uri(const ua::ExpandedNodeId& expanded) const noexcept;

  /// @return The requested value.
  /// Number of entries in the snapshot. A valid table always has at least the local Server at index 0.
  [[nodiscard]] std::size_t size() const noexcept;

  /// @return The requested value.
  /// Session generation assigned by ConnectionImpl (0 initially, incremented on Session re-bootstrap).
  [[nodiscard]] std::uint64_t generation() const noexcept;

  /// @param uris The uris.
  /// @param generation The generation.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Creates a validated snapshot. Empty tables and arrays beyond the UInt32 index domain are rejected.
  [[nodiscard]] static ua::Result<std::shared_ptr<const ServerTable>> create(
    std::vector<std::string> uris, std::uint64_t generation);

  ServerTable(const ServerTable&) = delete;
  ServerTable& operator=(const ServerTable&) = delete;
  ServerTable(ServerTable&&) = delete;
  ServerTable& operator=(ServerTable&&) = delete;
  ~ServerTable() = default;

private:
  struct UriHash
  {
    using is_transparent = void;
    [[nodiscard]] std::size_t operator()(std::string_view value) const noexcept;
    [[nodiscard]] std::size_t operator()(const std::string& value) const noexcept;
  };

  explicit ServerTable(std::vector<std::string> uris, std::uint64_t generation);

  std::vector<std::string> mUriByIndex;
  std::unordered_map<std::string, ServerIndex, UriHash, std::equal_to<>> mIndexByUri;
  std::uint64_t mGeneration = 0;
};

}  // namespace ua::client

#endif  // UA_SERVER_TABLE_H
