// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief XML-free facade for importing an OPC UA NodeSet2 into an AddressSpace.
///
/// @details Customers import their own OPC UA NodeSet2 XML into a server's AddressSpace through
/// these functions, layering on the parse + inspection model in `ua_nodeset_document.h`: parse a
/// `NodeSetDocument` (or pass a `Stream` to the convenience overloads), then import it. The XML
/// backend, the internal parse-tree, and the importer machinery are confined to `implementation/`;
/// none appear here, and failures are reported through `Result` / `ErrorDetail` rather than
/// thrown out of the `try_*` form.
///
/// Import is **async-canonical** and genuinely non-blocking: the engine never blocks a thread, so it
/// runs on the AddressSpace's own executor (there is no `workExecutor` footgun). The async entry
/// point owns its inputs for the lifetime of the operation  -  `AddressSpace` by value (a shared
/// handle), the parsed model as `shared_ptr<const NodeSetDocument>`, and the options/completion
/// moved in. There is deliberately no `Stream` overload on the async form (a `Stream` cannot be
/// owned by value and parsing is synchronous anyway); compose `parse_nodeset` with
/// `import_nodeset_async`. The `*_sync` / `try_*_sync` forms are thin promise/future wrappers for
/// external convenience only.
/// @ingroup address_space

#ifndef UA_NODESET_IMPORT_H
#define UA_NODESET_IMPORT_H

#include "ua_namespace.h"
#include "ua_nodeset_document.h"
#include "ua_result.h"
#include "ua_structure_factory.h"

#include <functional>

namespace ua
{

class Stream;
class AddressSpace;

/// Allocates a `Namespace` for a file-declared URI the server does not yet know.
///
/// Invoked during NodeSet import when a file introduces a namespace URI the server has not yet
/// registered. The abstraction is a function rather than a base class, mirroring
/// `StructureResolver` - it is held by value and copied freely.
///
/// An empty callable means an unknown URI is treated as a clean error by the caller; a non-empty
/// callable that returns null likewise causes the caller to report a clean error rather than
/// proceed with a missing namespace.
///
/// @param uri Namespace URI for which a `Namespace` must be allocated.
/// @return The newly allocated `Namespace`, whose @c uri() must equal @p uri; null to signal
///         that the URI cannot be satisfied.
/// @see StructureResolver
using NamespaceFactory = std::function<shared_ptr<Namespace>(string_view uri)>;

/// Outcome counts of a completed NodeSet import.
///
/// @ingroup address_space
struct NodeSetImportSummary
{
  /// URIs the file declared that were resolved to, or newly allocated in, the server namespace
  /// table during this import.
  std::vector<NamespaceMapping> namespacesAllocated;
  std::size_t nodesImported{};  ///< Count of nodes the @ref NodeSetImportOptions::nodeFilter accepted.
  std::size_t
    referencesImported{};  ///< Count of references the @ref NodeSetImportOptions::referenceFilter accepted.
};

/// Controls how a NodeSet is filtered, scoped, and resolved during import.
///
/// All members default to a permissive, side-effect-free configuration: empty filters include
/// everything, the scope is @ref Scope::Full, and unset resolvers disable their respective
/// behaviour (surfacing the corresponding gap as a clean `Result` error rather than a crash).
///
/// @ingroup address_space
struct NodeSetImportOptions
{
  /// Predicate selecting which nodes are imported; an empty function includes all.
  ///
  /// Category filtering (types vs. instances) is expressed through @ref NodeView::category within
  /// this predicate - there is no separate category parameter.
  std::function<bool(const NodeView&)> nodeFilter;
  /// Predicate selecting which references are imported; an empty function includes all.
  std::function<bool(const ReferenceView&)> referenceFilter;

  /// Subset of the NodeSet to import.
  enum class Scope
  {
    Full,  ///< Import all nodes and references the filters accept.
    TypeDefinitionsOnly  ///< Import only type-definition nodes (types, not instances).
  } scope = Scope::Full;  ///< Defaults to @ref Scope::Full.

  /// Allocates server namespace slots for URIs the file declares but the server lacks.
  ///
  /// Required when importing a file that introduces new namespaces. When empty, an unknown URI
  /// yields a clean `Result` error rather than a crash.
  NamespaceFactory namespaceFactory;

  /// Resolves a `<RequiredModel>` dependency to the NodeSet stream that satisfies it.
  ///
  /// The returned stream is owned by the import for the duration of dependency resolution. When
  /// empty, no dependency resolution is performed and a missing dependency surfaces as a
  /// `Result` error.
  std::function<std::unique_ptr<Stream>(const ModelRef&)> resolveRequiredModel;

  /// Resolves the custom ExtensionObject value types (named by `<TypeId>`) encountered during
  /// decode; empty disables custom types.
  ///
  /// NodeId / QualifiedName values nested inside such a structure are namespace-translated only
  /// when the structure is decodable, so supplying this resolver is what enables struct-embedded
  /// ids to be translated from the file-local to the server namespace.
  StructureResolver structureResolver;

  /// Disposition for a value containing an ExtensionObject whose type cannot be resolved.
  enum class OnUnknownStructure
  {
    /// Abort the import with a clean `Result` error (default).
    ///
    /// Preferred for import: the embedded namespace-qualified ids inside an unresolved body
    /// cannot be translated from the file-local to the server namespace, so storing it could
    /// yield a semantically wrong value.
    Fail,
    /// Store the value as a preserved opaque ExtensionObject.
    ///
    /// It round-trips on the wire and can be reified later, but its embedded ids remain file-local
    /// (untranslated).
    ImportOpaque
  } onUnknownStructure = OnUnknownStructure::Fail;  ///< Defaults to @ref OnUnknownStructure::Fail.
};

/// Imports a parsed NodeSet into an address space asynchronously.
///
/// The canonical, genuinely non-blocking entry point: the import runs on the address space's own
/// executor and never blocks a thread. All inputs are owned for the lifetime of the operation -
/// pass @p addressSpace by value (shared handle), the immutable @p document by shared pointer, and
/// move @p options in. There is deliberately no `Stream` overload on the async form; compose
/// `parse_nodeset` with this function instead.
///
/// @param addressSpace Address space the nodes and references are written into; owned by value.
/// @param document     Shared, immutable parsed model; read but not modified by the import.
/// @param options      Filtering, scope, and resolver configuration; moved in.
/// @param completion   Invoked exactly once, on the address space executor: on success the Result
///                     holds the `NodeSetImportSummary`, on failure it carries an
///                     `ErrorDetail`. This overload never throws.
/// @see try_import_nodeset_sync, import_nodeset_sync
void import_nodeset_async(AddressSpace addressSpace, shared_ptr<const NodeSetDocument> document,
  NodeSetImportOptions options, std::function<void(Result<NodeSetImportSummary>)> completion);

/// Imports a parsed NodeSet into an address space, blocking until complete.
///
/// Blocks on the caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are written into; owned by value.
/// @param document     Shared, immutable parsed model; read but not modified by the import.
/// @param options      Filtering, scope, and resolver configuration.
/// @return The import summary, or an `ErrorDetail` on failure. Never throws.
/// @see import_nodeset_async, import_nodeset_sync
Result<NodeSetImportSummary> try_import_nodeset_sync(
  AddressSpace addressSpace, shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options);

/// Parses @p nodeset inline and imports it into an address space, blocking until complete.
///
/// Convenience overload that parses the stream, then imports the parsed document. Blocks on the
/// caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are written into; owned by value.
/// @param nodeset      NodeSet stream parsed inline, then imported. Borrowed for the call only.
/// @param options      Filtering, scope, and resolver configuration.
/// @return The import summary, or an `ErrorDetail` on parse or import failure. Never throws.
/// @see import_nodeset_async, import_nodeset_sync
Result<NodeSetImportSummary> try_import_nodeset_sync(
  AddressSpace addressSpace, const Stream& nodeset, NodeSetImportOptions options);

/// Imports a parsed NodeSet into an address space, blocking until complete.
///
/// Blocks on the caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are written into; owned by value.
/// @param document     Shared, immutable parsed model; read but not modified by the import.
/// @param options      Filtering, scope, and resolver configuration.
/// A Good subcode on the answer is not returned; try_import_nodeset_sync() returns it.
/// @return The import summary.
/// @throws UaException if the import fails.
/// @see import_nodeset_async, try_import_nodeset_sync
NodeSetImportSummary import_nodeset_sync(
  AddressSpace addressSpace, shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options);

/// Parses @p nodeset inline and imports it into an address space, blocking until complete.
///
/// Convenience overload that parses the stream, then imports the parsed document. Blocks on the
/// caller's thread (never an address space executor thread).
///
/// @param addressSpace Address space the nodes and references are written into; owned by value.
/// @param nodeset      NodeSet stream parsed inline, then imported. Borrowed for the call only.
/// @param options      Filtering, scope, and resolver configuration.
/// A Good subcode on the answer is not returned; try_import_nodeset_sync() returns it.
/// @return The import summary.
/// @throws UaException if the parse or import fails.
/// @see import_nodeset_async, try_import_nodeset_sync
NodeSetImportSummary import_nodeset_sync(
  AddressSpace addressSpace, const Stream& nodeset, NodeSetImportOptions options);

}  // namespace ua

#endif  // !UA_NODESET_IMPORT_H
