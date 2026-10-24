// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Codec-facing namespace-resolution and index-translation interface.
/// @ingroup core_types

#ifndef UA_CODEC_NAMESPACE_CONTEXT_H
#define UA_CODEC_NAMESPACE_CONTEXT_H

#include "ua_includes.h"

namespace ua
{

class NodeId;
class ExpandedNodeId;
class QualifiedName;

/// Synchronous behaviour interface that resolves a namespace URI to its runtime index.
///
/// Injected into any core operation that needs URI-to-index resolution, so that resolution is a
/// behaviour rather than a dependency on a concrete `NamespaceArray`. The callable is invoked
/// synchronously and returns the index value; it is not an async completion handler. Despite the
/// historical "callback" naming, this is not a callback in the SDK sense (the SDK reserves
/// "callback" for `std::function<void(Result<T>)>`).
///
/// @see CodecNamespaceContext
using NamespaceIndexResolver = std::function<uint16_t(string_view)>;

/// In-place transform that rewrites the namespace index carried by a `NodeId`.
///
/// Used by codecs at persistence/import boundaries where a decoded or encoded value may carry a
/// namespace index that is not yet in the server's global namespace table (for example a
/// NodeSet-local index). Mutates its argument in place to avoid copying nested `Variant`
/// payloads.
///
/// @see QualifiedNameTranslator, ExpandedNodeIdTranslator, CodecNamespaceContext
using NodeIdTranslator = std::function<void(NodeId&)>;

/// In-place transform that rewrites the namespace index carried by a `QualifiedName`.
///
/// @see NodeIdTranslator, ExpandedNodeIdTranslator, CodecNamespaceContext
using QualifiedNameTranslator = std::function<void(QualifiedName&)>;

/// In-place transform that rewrites the namespace index carried by an `ExpandedNodeId`.
///
/// @see NodeIdTranslator, QualifiedNameTranslator, CodecNamespaceContext
using ExpandedNodeIdTranslator = std::function<void(ExpandedNodeId&)>;

/// Bundle of namespace-resolution and index-translation hooks supplied to codecs.
///
/// Groups the URI-to-index resolver used during encoding with the optional in-place translators
/// applied to decoded/encoded values. All hooks are invoked synchronously by the codec on the
/// calling thread; an unset hook is simply not invoked. Each hook owns its captured state for the
/// lifetime of the context.
///
/// @ingroup core_types
struct CodecNamespaceContext
{
  /// Resolves a namespace URI to a runtime index for encoders and generated code.
  ///
  /// The underlying @ref NamespaceArray lookup uses a transparent hash and equality, so resolution
  /// is allocation-free even when called with a `string_view` argument; no per-call cache layer is
  /// needed. May be unset when no resolution is required.
  NamespaceIndexResolver getNamespaceIndex;

  /// Optional in-place translator applied to @ref NodeId values; unset to skip translation.
  NodeIdTranslator translateNodeId;

  /// Optional in-place translator applied to @ref QualifiedName values; unset to skip translation.
  QualifiedNameTranslator translateQualifiedName;

  /// Optional in-place translator applied to @ref ExpandedNodeId values; unset to skip translation.
  ExpandedNodeIdTranslator translateExpandedNodeId;

  /// Constructs a context with no resolver and no translators.
  CodecNamespaceContext() = default;

  /// Constructs a context from a resolver and optional translators.
  ///
  /// Each argument maps one-to-one onto the corresponding stored member.
  ///
  /// @param namespaceIndexResolver      Resolver for URI-to-index lookups.
  /// @param nodeIdTranslator        Optional @ref NodeId translator; omit to leave unset.
  /// @param qualifiedNameTranslator Optional @ref QualifiedName translator; omit to leave unset.
  /// @param expandedNodeIdTranslator Optional @ref ExpandedNodeId translator; omit to leave unset.
  explicit CodecNamespaceContext(NamespaceIndexResolver namespaceIndexResolver,
    NodeIdTranslator nodeIdTranslator = {}, QualifiedNameTranslator qualifiedNameTranslator = {},
    ExpandedNodeIdTranslator expandedNodeIdTranslator = {});

  /// Creates a context carrying only in-place index translators and no resolver.
  ///
  /// @param translateNodeId         Translator applied to @ref NodeId values.
  /// @param translateQualifiedName  Translator applied to @ref QualifiedName values.
  /// @param translateExpandedNodeId Translator applied to @ref ExpandedNodeId values.
  /// @return A context with the given translators and an unset resolver.
  static CodecNamespaceContext with_translators(NodeIdTranslator translateNodeId,
    QualifiedNameTranslator translateQualifiedName, ExpandedNodeIdTranslator translateExpandedNodeId);
};

}  // namespace ua

#endif  // !UA_CODEC_NAMESPACE_CONTEXT_H
