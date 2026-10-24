// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief XML-free facade for exporting an AddressSpace to an OPC UA NodeSet2 document.
/// @ingroup address_space

#ifndef UA_NODESET_EXPORT_H
#define UA_NODESET_EXPORT_H

#include "ua_address_space_file.h"
#include "ua_date_time.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_nodeset_document.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_string.h"
#include "ua_structure_factory.h"

namespace ua
{

class Stream;
class AddressSpace;

// =============================================================================
// Public NodeSet export API - XML-free facade (the read-side mirror of
// `ua_nodeset_import.h`).
//
// Customers serialise a live server `AddressSpace` (one or more namespaces) into
// an OPC-UA NodeSet2 XML document through these functions. The XML backend, the
// envelope writer, and the export engine are all confined to `implementation/`;
// none of them appear here. Failures are reported through `Result<T>` /
// `ErrorDetail` rather than thrown out of the `try_*` form.
//
// Asymmetry with import is deliberate. Import options that have no export meaning
// are dropped: there is no `namespace_factory` (export reads the namespaces the
// server already has) and no `resolve_required_model` (export *declares* its
// `<Models>` / `<RequiredModel>` header, it does not resolve dependency streams).
// =============================================================================

/// Outcome counts of a completed NodeSet export.
///
/// @ingroup address_space
struct NodeSetExportSummary
{
  /// The non-NS0 namespaces written to the document, in file order. Each entry's `server_index`
  /// holds the FILE-local index assigned to the URI (1..k); NS0 is implicit and not listed.
  std::vector<NamespaceMapping> namespacesWritten;
  std::size_t nodesExported{};  ///< Count of nodes the @ref NodeSetExportOptions::nodeFilter accepted.
  std::size_t referencesExported{};  ///< Count of references written across all exported nodes.
};

/// A `<RequiredModel>` dependency declared by an exported `<Model>`.
///
/// @ingroup address_space
struct NodeSetModelRef
{
  String uri;  ///< Required model namespace URI.
  String version;  ///< Required model version string.
  DateTime publicationDate;  ///< Required model publication date.
};

/// One `<Model>` entry written to the document's `<Models>` header.
///
/// @ingroup address_space
struct NodeSetExportModel
{
  String uri;  ///< Model namespace URI.
  String version;  ///< Model version string.
  DateTime publicationDate;  ///< Model publication date.
  std::vector<NodeSetModelRef> requiredModels;  ///< Declared `<RequiredModel>` dependencies.
};

/// Immutable, lightweight view of a node passed to @ref NodeSetExportOptions::nodeFilter.
///
/// Unlike the import-side `NodeView` (backed by a parse tree), this carries the live node's identity
/// and browse name directly - the attributes a filter needs to decide whether to export the node.
///
/// @ingroup address_space
struct ExportNodeView
{
  NodeId nodeId;  ///< The node's NodeId (server namespace index).
  NodeClass nodeClass;  ///< The node's NodeClass.
  QualifiedName browseName;  ///< The node's browse name (server namespace index).
};

/// Controls which namespaces, nodes, and references are exported, and how the document is framed.
///
/// All members default to a permissive configuration: empty filters include everything, the scope is
/// @ref Scope::Full, aliases are emitted, and an unencodable value fails the export.
///
/// @ingroup address_space
struct NodeSetExportOptions
{
  /// Server namespace indices to export. An empty list exports nothing (a valid, header-only
  /// document). NS0 is never exported as content; referenced NS0 ids are emitted with no namespace
  /// prefix.
  std::vector<uint16_t> namespaces;

  /// Predicate selecting which nodes are exported; an empty function includes all.
  std::function<bool(const ExportNodeView&)> nodeFilter;

  /// Predicate selecting which references are exported; an empty function includes all.
  std::function<bool(const ReferenceView&)> referenceFilter;

  /// Subset of the address space to export.
  enum class Scope
  {
    Full,  ///< Export all nodes and references the filters accept.
    TypeDefinitionsOnly  ///< Export only type-definition nodes (Object/Variable/Data/Reference types).
  } scope = Scope::Full;  ///< Defaults to @ref Scope::Full.

  /// `<Models>` header entries, each with its `<RequiredModel>` dependencies.
  std::vector<NodeSetExportModel> models;

  /// Optional `LastModified` timestamp, written as an attribute on `<UANodeSet>` when set.
  optional<DateTime> lastModified;

  /// Whether to emit an `<Aliases>` table giving symbolic names to the reference/data types used.
  ///
  /// Aliases are a readability/size optimisation only; the document round-trips either way.
  bool emitAliases = true;

  /// Reifies an opaque binary-bodied ExtensionObject value to a typed `Structure` so it can be
  /// transcoded to XML. Empty leaves such a value unresolved (then governed by
  /// @ref onUnencodableStructure). The body's embedded ids are re-translated server->file on
  /// re-emit, so reification is sound when the stored body uses server namespace indices (the normal
  /// case for a live value); a body preserved verbatim from an `ImportOpaque` is the documented
  /// exception, mirroring the importer's opaque caveat.
  StructureResolver structureResolver;

  /// Disposition for a value that cannot be transcoded to XML (an unresolved opaque binary-bodied
  /// ExtensionObject).
  enum class OnUnencodableStructure
  {
    /// Abort the export with a clean @ref Result error (default).
    Fail,
    /// Omit the offending `<Value>` but keep the rest of the node and the document.
    OmitValue
  } onUnencodableStructure =
    OnUnencodableStructure::Fail;  ///< Defaults to @ref OnUnencodableStructure::Fail.
};

/// The serialised document bytes paired with the export summary.
using NodeSetExportResult = std::pair<std::vector<byte>, NodeSetExportSummary>;

// =============================================================================
// Export is async-canonical: the engine never blocks a thread, so it runs on the
// AddressSpace's own executor. The canonical async form OWNS its inputs (an async
// op outlives the call): `AddressSpace` by value, the output sink as a
// `shared_ptr<Stream>` (co-owned, so it cannot dangle across the async boundary -
// this is why the async form takes a smart pointer rather than a `Stream&`), and
// options moved in. The document is serialised straight into that sink, so nothing
// is buffered in memory. An owned-buffer overload and the `*_sync` forms are thin
// conveniences layered on top.
// =============================================================================

/// Exports an address space to a NodeSet2 document asynchronously, writing into @p out.
///
/// The canonical, genuinely non-blocking entry point. The document is serialised **directly into**
/// @p out - no intermediate document buffer is materialised, so exporting a large namespace to a
/// `FileStream` never holds the document in memory. All inputs are owned for the operation's
/// lifetime: @p addressSpace by value (shared handle), @p out co-owned by `shared_ptr` (so it cannot
/// dangle across the async boundary - the reason a bare `Stream&` is not accepted here), and
/// @p options moved in.
///
/// @param addressSpace Address space the nodes and references are read from; owned by value.
/// @param out          Output sink the NodeSet2 document is written to; co-owned for the operation.
/// @param options      Target namespaces, filtering, scope, and header configuration; moved in.
/// @param completion   Invoked exactly once, on the address space executor: on success the Result
///                     holds a `NodeSetExportSummary`, on failure it carries an `ErrorDetail`.
///                     This overload never throws.
/// @see try_export_nodeset_sync, export_nodeset_sync
void export_nodeset_async(AddressSpace addressSpace, shared_ptr<Stream> out, NodeSetExportOptions options,
  std::function<void(Result<NodeSetExportSummary>)> completion);

/// Exports an address space into an owned byte buffer asynchronously (convenience).
///
/// Wraps the canonical `export_nodeset_async` with an internal `MemoryStream` and hands the
/// materialised bytes to the completion - for callers who want the document in memory rather than
/// streamed to a sink.
///
/// @param addressSpace Address space the nodes and references are read from; owned by value.
/// @param options      Target namespaces, filtering, scope, and header configuration; moved in.
/// @param completion   Invoked exactly once, on the address space executor: on success the Result
///                     holds the document bytes and a `NodeSetExportSummary`, on failure it
///                     carries an `ErrorDetail`. This overload never throws.
/// @see try_export_nodeset_sync, export_nodeset_sync
void export_nodeset_async(AddressSpace addressSpace, NodeSetExportOptions options,
  std::function<void(Result<NodeSetExportResult>)> completion);

/// Exports an address space to an owned NodeSet2 buffer, blocking until complete.
///
/// Blocks on the caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are read from; owned by value.
/// @param options      Target namespaces, filtering, scope, and header configuration.
/// @return The document bytes and summary, or an `ErrorDetail` on failure. Never throws.
/// @see export_nodeset_async
Result<NodeSetExportResult> try_export_nodeset_sync(AddressSpace addressSpace, NodeSetExportOptions options);

/// Exports an address space, writing the NodeSet2 document to @p out, blocking until complete.
///
/// Blocks on the caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are read from; owned by value.
/// @param out          Output stream the NodeSet2 document is written to.
/// @param options      Target namespaces, filtering, scope, and header configuration.
/// @return The export summary, or an `ErrorDetail` on failure. Never throws.
/// @see export_nodeset_async, export_nodeset_sync
Result<NodeSetExportSummary> try_export_nodeset_sync(
  AddressSpace addressSpace, Stream& out, NodeSetExportOptions options);

/// Exports an address space, writing the NodeSet2 document to @p out, blocking until complete.
///
/// Blocks on the caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are read from; owned by value.
/// @param out          Output stream the NodeSet2 document is written to.
/// @param options      Target namespaces, filtering, scope, and header configuration.
/// A Good subcode on the answer is not returned; try_export_nodeset_sync() returns it.
/// @return The export summary.
/// @throws UaException if the export fails.
/// @see export_nodeset_async, try_export_nodeset_sync
NodeSetExportSummary export_nodeset_sync(
  AddressSpace addressSpace, Stream& out, NodeSetExportOptions options);

// =============================================================================
// AddressSpaceFileType.ExportNamespace() method wiring
//
// The standard `AddressSpaceFileType` carries an `ExportNamespace()` method whose contract is to
// serialise the namespace(s) the file represents and make the result readable through the FileType
// Open/Read methods. The factory below builds a handler that, on each call, asks @p openOutput for a
// fresh writable stream and serialises the export DIRECTLY into it - buffer-free end to end (e.g. a
// `FileStream` truncating the FileHelper-backed file). The binding of *which* namespaces a file
// exports is a deployment decision fixed at install time, since the method itself takes no arguments.
// Install the handler with `AddressSpaceFile::set_export_namespace_handler_*`.
// =============================================================================

/// Yields a fresh, writable destination stream for one `ExportNamespace()` invocation (e.g. the file
/// opened for write/truncate). A bad `Result` fails the call cleanly (the open error propagates); an
/// Uncertain one, with or without a stream, fails it with `Bad_InternalError` (`AnswerUncertain`, the
/// provider's code as its cause), since the export does not write into a stream its provider is uncertain
/// of. The returned stream is co-owned for the export and flushed on success.
using NodeSetStreamProvider = std::function<Result<shared_ptr<Stream>>(shared_ptr<const MethodCallContext>)>;

/// Builds an `ExportNamespace()` method handler that serialises @p options from @p addressSpace
/// straight into the stream @p openOutput supplies for each call (no intermediate buffer). The
/// stream is flushed before the call reports success, so a subsequent client Open/Read sees the
/// document. The handler is reusable: each `ExportNamespace()` call re-opens and re-exports.
///
/// @param addressSpace Address space exported on each call; owned by value (shared handle).
/// @param options      Export configuration applied on every call; copied per call.
/// @param openOutput   Supplies the writable destination stream for each invocation.
/// @return An asynchronous handler for `AddressSpaceFile::set_export_namespace_handler_*`; the export
///         completes after its stream is flushed.
AddressSpaceFile::ExportNamespaceAsyncHandler make_export_namespace_handler(
  AddressSpace addressSpace, NodeSetExportOptions options, NodeSetStreamProvider openOutput);

}  // namespace ua

#endif  // !UA_NODESET_EXPORT_H
