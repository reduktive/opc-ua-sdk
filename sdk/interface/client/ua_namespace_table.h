// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_TABLE_H
#define UA_NAMESPACE_TABLE_H

/// @file
/// @brief Per-Connection immutable snapshot of a server's NamespaceArray (client tier-1).
/// @ingroup client

#include "ua_byte_string.h"
#include "ua_expanded_node_id.h"
#include "ua_node_id.h"
#include "ua_result.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ua::client
{

/// A namespace index into a server's `Server.NamespaceArray` (an OPC UA `UInt16`).
using NamespaceIndex = std::uint16_t;

/// A per-`Connection` immutable snapshot of the server's `Server.NamespaceArray`.
///
/// Holds the `NamespaceUri`  and  `NamespaceIndex` mapping the client needs to (a) translate a `NodeId`
/// built against one snapshot into another snapshot's index space across a reconnect
/// (@ref translate), (b) resolve an `ExpandedNodeId.namespaceUri` over the encoded index per the
/// codec invariant (@ref resolve_local, CL-VIEW-018), and (c) produce `server.namespace.<uri>` source
/// tags for the `DiagnosticInfo` decoder (@ref source_tag_for_namespace_uri, CL-DIAG-007).
///
/// **Immutable and value-typed.** Every field is fixed at construction; there are no mutators. A
/// server renumbering its namespaces across Sessions is modelled by *replacement*  -  `ConnectionImpl`
/// atomic-stores a fresh snapshot  -  never by mutating an existing one. Consequently every accessor is
/// a pure, non-blocking read that is safe from any thread once a `std::shared_ptr<const NamespaceTable>`
/// snapshot has been taken; the snapshot stays valid for the duration of an operation even if
/// `ConnectionImpl` installs a newer instance mid-flight.
///
/// **One per Connection** (CL-MULTI-001..003): there is no static or cross-Connection state, so two
/// Connections to servers that number the same URI differently never interfere.
///
/// Construct via @ref create, which validates the array (index 0 must be the NS0 URI) and returns a
/// shared, `const` snapshot.
/// @ingroup client
class NamespaceTable
{
public:
  /// Returns the index mapped to @p uri, or `std::nullopt` if @p uri is not in this snapshot.
  ///
  /// @param uri Namespace URI to look up (heterogeneous lookup - no allocation).
  /// @return The mapped @ref NamespaceIndex, or `std::nullopt`.
  [[nodiscard]] std::optional<NamespaceIndex> lookup_index(std::string_view uri) const noexcept;

  /// Returns the URI at @p idx, or `std::nullopt` if @p idx is out of range.
  ///
  /// @param idx Namespace index to look up.
  /// @return A `string_view` into this snapshot's storage (valid for the snapshot's lifetime), or
  ///         `std::nullopt` if @p idx `>=` @ref size.
  [[nodiscard]] std::optional<std::string_view> lookup_uri(NamespaceIndex idx) const noexcept;

  /// Returns the number of namespaces in this snapshot (always `>= 1` - NS0 is present).
  ///
  /// @return The namespace count.
  [[nodiscard]] std::size_t size() const noexcept;

  /// Returns this snapshot's generation counter (monotonic across re-reads on one Connection).
  ///
  /// @return The generation assigned by `ConnectionImpl` at construction.
  [[nodiscard]] std::uint64_t generation() const noexcept;

  /// Returns the server's `Server.UrisVersion`, or `std::nullopt` if the server does not publish it.
  ///
  /// `UrisVersion` is a `VersionTime` (OPC 10000-5  -  a `UInt32` change counter for the namespace/server
  /// arrays). A client that cached NamespaceIndexes uses it to detect that the cached indexes may have
  /// changed (CL-BASE-001); it is also the `urisVersion` a session-less invocation echoes back.
  ///
  /// @return The `UrisVersion` counter (CL-BASE-001), or `std::nullopt` if the server did not publish it.
  [[nodiscard]] std::optional<std::uint32_t> uris_version() const noexcept;

  /// Translates a @ref NodeId built against @p sourceTable into this snapshot's index space.
  ///
  /// Resolves @p node's index to a URI via @p sourceTable, then re-resolves that URI to this
  /// snapshot's index (CL-SESS-028 / CL-ADDRSP-004 remap). The identifier is preserved verbatim; only
  /// the namespace index changes.
  ///
  /// @param node        The NodeId to translate; its index is interpreted against @p sourceTable.
  /// @param sourceTable The snapshot @p node's index was built against.
  /// @return A good `Result<NodeId>` in this snapshot's index space; or `Bad_NodeIdUnknown` chained
  ///         with `client.namespace_table.uri_unresolved` when the source URI is absent here; or
  ///         `Bad_NodeIdInvalid` chained with `client.namespace_table.index_out_of_range` when
  ///         @p node's index is out of @p sourceTable's range.
  [[nodiscard]] Result<NodeId> translate(
    const NodeId& node, const NamespaceTable& sourceTable) const noexcept;

  /// Resolves an @ref ExpandedNodeId to a local @ref NodeId per the CL-VIEW-018 codec invariant.
  ///
  /// If `expanded.namespace_uri()` is non-empty it overrides the encoded index; otherwise the encoded
  /// index is authoritative.
  ///
  /// @param expanded The ExpandedNodeId to resolve.
  /// @return A good `Result<NodeId>` at this snapshot's local index; or `Bad_NodeIdUnknown` chained
  ///         with `client.namespace_table.uri_unresolved` (the unresolved URI preserved verbatim in
  ///         the ErrorDetail) when a non-empty URI is absent here; or `Bad_NodeIdInvalid` chained with
  ///         `client.namespace_table.index_out_of_range` when the URI is empty and the encoded index
  ///         is out of range.
  [[nodiscard]] Result<NodeId> resolve_local(const ExpandedNodeId& expanded) const noexcept;

  /// Builds the `DiagnosticInfo` source tag for @p uri (CL-DIAG-007).
  ///
  /// @param uri The namespace URI carried by a decoded `DiagnosticInfo` layer.
  /// @return `"server.namespace." + uri` when @p uri is in this snapshot, else
  ///         `"server.unknown." + uri`. The literal URI is always preserved.
  [[nodiscard]] std::string source_tag_for_namespace_uri(std::string_view uri) const;

  /// Creates a validated, shared, immutable snapshot from a decoded `NamespaceArray`.
  ///
  /// @param uris        The `Server.NamespaceArray` URIs, in index order; `uris[0]` must be the NS0
  ///                    URI (`http://opcfoundation.org/UA/`). A URI that repeats keeps its first
  ///                    (lowest) index; the caller may surface a non-conformance advisory.
  /// @param urisVersion The optional `Server.UrisVersion` counter (CL-BASE-001), or `std::nullopt`.
  /// @param generation  The generation counter assigned by `ConnectionImpl`.
  /// @return A good `Result` holding the snapshot; or `Bad_UnexpectedError` chained with
  ///         `client.namespace_table.ns0_missing` when @p uris is empty or `uris[0]` is not the NS0
  ///         URI; or `Bad_UnexpectedError` chained with `client.namespace_table.too_large` when
  ///         @p uris cannot be indexed by a `UInt16`.
  ///
  /// @note Returns a `Result` (rather than a bare `shared_ptr`) so a malformed array fails with a
  ///       propagatable @ref ua::ErrorDetail instead of being silently accepted or dropped.
  [[nodiscard]] static Result<std::shared_ptr<const NamespaceTable>> create(
    std::vector<std::string> uris, std::optional<std::uint32_t> urisVersion, std::uint64_t generation);

  NamespaceTable(const NamespaceTable&) = delete;
  NamespaceTable& operator=(const NamespaceTable&) = delete;
  NamespaceTable(NamespaceTable&&) = delete;
  NamespaceTable& operator=(NamespaceTable&&) = delete;
  ~NamespaceTable() = default;

private:
  /// Transparent hash so `mIndexByUri` accepts `string_view` lookups without allocating a `std::string`.
  struct UriHash
  {
    using is_transparent = void;

    [[nodiscard]] std::size_t operator()(std::string_view uri) const noexcept
    {
      return std::hash<std::string_view>{}(uri);
    }
  };

  /// Private: instances are only produced by @ref create, after validation.
  NamespaceTable(
    std::vector<std::string> uris, std::optional<std::uint32_t> urisVersion, std::uint64_t generation);

  std::vector<std::string> mUriByIndex;
  std::unordered_map<std::string, NamespaceIndex, UriHash, std::equal_to<>> mIndexByUri;
  std::optional<std::uint32_t> mUrisVersion;
  std::uint64_t mGeneration;
};

}  // namespace ua::client

#endif  // UA_NAMESPACE_TABLE_H
