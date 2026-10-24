// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA ExpandedNodeId built-in type - a NodeId plus optional namespace URI and server
/// index.
/// @ingroup core_types

#ifndef UA_EXPANDED_NODE_ID_H
#define UA_EXPANDED_NODE_ID_H

#include "ua_built_in_types_fwd_decl.h"
#include "ua_result.h"
#include "ua_codec_namespace_context.h"
#include "ua_node_id.h"

namespace ua
{

/// A @ref NodeId extended with an optional namespace URI and server index.
///
/// Identifies a node that may live in another server's address space. Beyond the wrapped
/// @ref NodeId it carries two optional qualifiers:
/// - a *namespace URI* that, when present, supersedes the wrapped NodeId's numeric namespace index
///   (the URI is the authoritative namespace identity; the index is meaningful only relative to a
///   particular server's namespace table);
/// - a *server index* into the local server's ServerArray, where `0` denotes the local server.
///
/// A default-constructed instance is null (index-based, local, and wrapping a null NodeId); see
/// is_null(). Equality is member-wise over the wrapped NodeId, namespace URI, and server index, so
/// two values that designate the same node by different means (URI versus index) do not compare
/// equal.
/// @see NodeId
/// @ingroup core_types
class ExpandedNodeId
{
public:
  /// Constructs a null ExpandedNodeId (null NodeId, empty namespace URI, server index 0).
  ExpandedNodeId() = default;

  /// Constructs an index-based, local ExpandedNodeId wrapping @p nodeId.
  ///
  /// @param nodeId Node identity to wrap; its namespace index is retained as-is.
  explicit ExpandedNodeId(NodeId nodeId);

  /// Constructs a local ExpandedNodeId identified by namespace URI.
  ///
  /// When @p namespaceUri is non-empty it supersedes the namespace index carried by @p nodeId.
  ///
  /// @param nodeId       Node identity to wrap.
  /// @param namespaceUri Namespace URI; copied into this value.
  ExpandedNodeId(NodeId nodeId, string_view namespaceUri);

  /// Constructs an index-based ExpandedNodeId on the server addressed by @p serverIndex.
  ///
  /// @param nodeId      Node identity to wrap.
  /// @param serverIndex Index into the local server's ServerArray; `0` denotes the local server.
  ExpandedNodeId(NodeId nodeId, uint32_t serverIndex);

  /// Constructs an ExpandedNodeId with both a namespace URI and a server index.
  ///
  /// When @p namespaceUri is non-empty it supersedes the namespace index carried by @p nodeId.
  ///
  /// @param nodeId       Node identity to wrap.
  /// @param namespaceUri Namespace URI; copied into this value.
  /// @param serverIndex  Index into the local server's ServerArray; `0` denotes the local server.
  ExpandedNodeId(NodeId nodeId, string_view namespaceUri, uint32_t serverIndex);

  /// Copies the wrapped NodeId, namespace URI, and server index.
  /// @param other ExpandedNodeId to copy.
  ExpandedNodeId(const ExpandedNodeId& other) = default;
  /// Moves @p other's NodeId and namespace URI, leaving it null.
  /// @param other ExpandedNodeId to move from; left null.
  ExpandedNodeId(ExpandedNodeId&& other) noexcept = default;
  /// Copy-assigns the wrapped NodeId, namespace URI, and server index.
  /// @param other ExpandedNodeId to copy.
  /// @return Reference to this ExpandedNodeId.
  ExpandedNodeId& operator=(const ExpandedNodeId& other) = default;
  /// Move-assigns @p other's NodeId and namespace URI, leaving it null.
  /// @param other ExpandedNodeId to move from; left null.
  /// @return Reference to this ExpandedNodeId.
  ExpandedNodeId& operator=(ExpandedNodeId&& other) noexcept = default;
  /// Destroys the ExpandedNodeId, releasing its wrapped NodeId and namespace URI.
  ~ExpandedNodeId() = default;

  /// Compares member-wise over the wrapped NodeId, namespace URI, and server index.
  ///
  /// Values that designate the same node by different means (URI versus namespace index) do not
  /// compare equal.
  ///
  /// @param obj ExpandedNodeId to compare against.
  /// @return `true` when the wrapped NodeId, namespace URI, and server index all match.
  bool operator==(const ExpandedNodeId& obj) const = default;

  /// Returns the wrapped node identity.
  ///
  /// @return Read-only reference to the wrapped @ref NodeId, owned by this ExpandedNodeId.
  const NodeId& node_id() const;

  /// Returns a mutable reference to the wrapped node identity.
  ///
  /// @return Mutable reference to the wrapped @ref NodeId, owned by this ExpandedNodeId.
  NodeId& node_id();

  /// Returns the namespace URI, or an empty String when this value is index-based.
  ///
  /// When non-empty, the URI supersedes the wrapped NodeId's namespace index.
  ///
  /// @return Read-only reference to the namespace URI, owned by this ExpandedNodeId.
  const String& namespace_uri() const;

  /// Returns a mutable reference to the namespace URI.
  ///
  /// Setting a non-empty URI makes this value not-index-based; clearing it makes it index-based.
  ///
  /// @return Mutable reference to the namespace URI, owned by this ExpandedNodeId.
  String& namespace_uri();

  /// Returns the server index.
  ///
  /// @return Index into the local server's ServerArray; `0` denotes the local server.
  uint32_t server_index() const;

  /// Returns a mutable reference to the server index.
  ///
  /// @return Mutable reference to the server index; `0` denotes the local server.
  uint32_t& server_index();

  /// Reports whether this is the null ExpandedNodeId.
  ///
  /// @return `true` when the value is index-based, local, and wraps a null NodeId.
  bool is_null() const;

  /// Reports whether the value addresses the local server.
  ///
  /// @return `true` when the server index is `0`.
  bool is_local() const;

  /// Reports whether the namespace is conveyed by index rather than URI.
  ///
  /// @return `true` when no namespace URI is set (the wrapped NodeId's namespace index applies).
  bool is_index_based() const;

  /// Reports whether the value addresses a remote server.
  ///
  /// @return `true` when the server index is non-zero.
  bool is_remote() const;

  /// Reports whether the namespace is conveyed by URI rather than index.
  ///
  /// @return `true` when a namespace URI is set; the inverse of is_index_based().
  bool is_not_index_based() const;

  /// Parses the text @ref ua::to_string writes for an ExpandedNodeId: optional `svr=<index>;` and
  /// `nsu=<uri>;` prefixes followed by the NodeId text (for example `svr=1;nsu=http://example.org;i=42`).
  /// `parse(to_string(id)) == id` for every ExpandedNodeId.
  ///
  /// @param text The textual ExpandedNodeId.
  /// @return The ExpandedNodeId @p text names.
  /// @throws UaException with @ref Status::BadDecodingError if @p text is not that form (for example an
  ///         unparseable server index, an `svr=0` prefix, or a missing separator).
  /// @see try_parse, as_definition
  static ExpandedNodeId parse(string_view text);

  /// Parses like @ref parse and reports a malformed text as a bad result instead of throwing.
  ///
  /// @param text The textual ExpandedNodeId.
  /// @return The ExpandedNodeId, or Bad_DecodingError with an @ref ErrorDetail naming the fault.
  [[nodiscard]] static ExpandedNodeIdResult try_parse(string_view text) noexcept;

  /// Renders this value as its textual definition.
  ///
  /// Emits the optional `svr=<index>;` prefix only when the server index is non-zero and the
  /// optional `nsu=<uri>;` prefix only when a namespace URI is set, followed by the NodeId portion.
  ///
  /// @return The textual ExpandedNodeId definition; @ref parse reads it back.
  /// @see parse
  std::string as_definition() const;

  /// Resets the value to null (clears the namespace URI, sets the server index to `0`, and clears
  /// the wrapped NodeId).
  void clear();

  // Resolve a URI-based ExpandedNodeId to a runtime-index NodeId via the namespace-resolution interface.
  // Takes the resolver behaviour directly (never a concrete NamespaceArray) so this core value type
  // stays free of any address-space dependency.

  /// Resolves this value to a runtime-index @ref NodeId.
  ///
  /// When the value is index-based the wrapped NodeId is returned unchanged. Otherwise
  /// @p resolveNamespaceIndex is invoked synchronously with the namespace URI and its result
  /// replaces the namespace index of the returned NodeId. The resolver is taken as a behaviour interface
  /// (never a concrete @ref NamespaceArray) so this core value type stays free of any
  /// address-space dependency. The server index is not represented in the result.
  ///
  /// @param resolveNamespaceIndex Synchronous URI-to-index resolver, invoked only when this value
  ///                              is not index-based.
  /// @return The resolved @ref NodeId.
  /// @see NamespaceIndexResolver
  NodeId to_node_id(const NamespaceIndexResolver& resolveNamespaceIndex) const;

  /// Returns the built-in type identifier for ExpandedNodeId.
  ///
  /// @return Always @ref BuiltInTypeId::ExpandedNodeId.
  static BuiltInTypeId built_in_type_id();

private:
  void assign_definition(string_view definition);

  NodeId mNodeId;
  String mNamespaceUri;
  uint32_t mServerIndex{0};
};

/// Returns the OPC UA type name for ExpandedNodeId.
///
/// @return The literal `"ExpandedNodeId"`.
template<>
inline string_view get_typename<ExpandedNodeId>()
{
  return "ExpandedNodeId";
}

}  // namespace ua

namespace std
{

template<>
struct hash<ua::ExpandedNodeId>
{
  size_t operator()(const ua::ExpandedNodeId& obj) const
  {
    size_t h = hash<ua::NodeId>{}(obj.node_id());
    const string_view uri = obj.namespace_uri();
    if (!uri.empty())
    {
      h ^= hash<string_view>{}(uri) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    h ^= hash<uint32_t>{}(obj.server_index()) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
  }
};

}  // namespace std

#endif  // !UA_EXPANDED_NODE_ID_H
