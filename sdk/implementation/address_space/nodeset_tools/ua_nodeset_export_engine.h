// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODESET_EXPORT_ENGINE_H
#define UA_NODESET_EXPORT_ENGINE_H

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ua_address_space.h"
#include "ua_encoding_limits.h"
#include "ua_node_id.h"
#include "ua_nodeset_document.h"
#include "ua_nodeset_writer.h"
#include "ua_result.h"
#include "ua_resource_budgets.h"
#include "ua_structure_factory.h"

namespace ua::xml::nodeset
{

// Async, non-blocking NodeSet export engine. The read-side mirror of `ImportEngine`: it reads a
// live `AddressSpace` to assemble the inputs a NodeSet2 writer needs. This Phase covers DISCOVERY
// only - producing the work-list of NodeIds to export. The per-node read/emit pass is a later phase.
//
// Lifetime: the engine keeps itself alive across the async chain by capturing a strong
// `shared_from_this()` in each continuation - the documented exception to weak-capture for a
// *bounded operation that must outlive each step*. It is not a cycle: each operation's completion
// fires exactly once, releasing the chain.
//
// Shutdown safety (D-V): the address space is held WEAKLY (`WeakAddressSpace`) and `lock()`-ed per
// step, mirroring `ImportEngine`. An in-flight discovery therefore never pins the address space
// alive (no shutdown latency). If a `lock()` fails (teardown in progress) the operation completes
// once with `BadShutdown`.
//
// Threading: every AddressSpace call posts its continuation back onto the AS executor, and the
// enumerate/traversal steps are driven strictly sequentially (the next is posted only when the
// previous completes). The engine's mutable working state (work-list, visited set, needs-traversal
// set, cursor) is therefore touched only from those serialized continuations -
// single-threaded-by-construction; no extra strand is needed.
class ExportEngine : public std::enable_shared_from_this<ExportEngine>
{
public:
  ExportEngine() = delete;
  ExportEngine(const ExportEngine&) = delete;
  ExportEngine(ExportEngine&&) = delete;
  ExportEngine& operator=(const ExportEngine&) = delete;
  ExportEngine& operator=(ExportEngine&&) = delete;
  ~ExportEngine() = default;

  // Completion for discovery: the combined, de-duplicated work-list of NodeIds to export, or a bad
  // Result carrying the failing status + ErrorDetail. Invoked exactly once on the AS executor.
  using DiscoverCompletion = std::function<void(Result<std::vector<NodeId>>)>;

  // Holds `addressSpace` weakly for the duration of the async operation; `limits` bounds the
  // browse traversal fallback so a pathological graph cannot run unbounded.
  static shared_ptr<ExportEngine> create(EncodingLimits limits, AddressSpace addressSpace);

  // --- Async discovery. Invokes `completion` exactly once, on the AS executor. ---
  //
  // Hybrid node discovery for the requested target namespace indices:
  //   1. Per target ns, `enumerate_nodes_async`. A good result appends those ids to the work-list;
  //      `BadNotSupported` marks that ns for browse-traversal; any other bad status fails the whole
  //      discovery (propagating its ErrorDetail).
  //   2. If any ns needs traversal, ONE BFS browse-traversal from the standard roots collects every
  //      reachable node whose `namespace_index()` is in the needs-traversal set (following both
  //      forward and inverse references so encoding objects are reachable). An id that does not
  //      resolve is skipped; a lookup answered Uncertain fails the discovery with `Bad_InternalError`
  //      (`LookupAnswerUncertain`, the answer as cause), as does one in the export's read pass.
  //   3. The combined results are de-duplicated and returned in the completion.
  void discover_async(std::vector<uint16_t> targetNamespaceIndices, DiscoverCompletion completion);

  // --- Export configuration & outcome --------------------------------------------------------------

  // Engine-level node / reference predicates. The XML-free facade adapts its public view-based
  // predicates into these. An empty function includes everything.
  using ExportNodePredicate = std::function<bool(const ExportedNode&)>;
  using ExportReferencePredicate = std::function<bool(const ExportedReference&)>;

  // Subset of the address space to export (mirrors NodeSetImportOptions::Scope).
  enum class ExportScope
  {
    Full,  // Export every discovered node the filters accept.
    TypeDefinitionsOnly  // Export only type-definition nodes (Object/Variable/Data/Reference types).
  };

  struct ExportSettings
  {
    std::vector<uint16_t> targetNamespaceIndices;
    std::vector<NodeSetModel> models;  // `<Models>` header (each may carry `<RequiredModel>` deps).
    optional<DateTime> lastModified;  // `LastModified` attribute on `<UANodeSet>` when set.
    ExportNodePredicate nodeFilter;  // empty => include all.
    ExportReferencePredicate referenceFilter;  // empty => include all.
    ExportScope scope{ExportScope::Full};
    bool emitAliases{true};
    bool failOnUnencodableStructure{true};
    // Reifies an opaque binary-bodied ExtensionObject value to a typed Structure (so it can be
    // transcoded to XML) before serialisation. Empty leaves opaque values unresolved (then handled by
    // failOnUnencodableStructure).
    StructureResolver structureResolver;
  };

  // Summary of a completed export. The document itself is serialised into the caller's `Stream`, so
  // it is NOT held here - only the counts and the namespaces written.
  struct ExportSummary
  {
    std::vector<NamespaceMapping> namespacesWritten;  // non-NS0 namespaces, in file order (uri + index).
    std::size_t nodesExported{};
    std::size_t referencesExported{};
  };

  // The serialised document plus its summary. Produced by the `try_export_sync` buffer convenience,
  // which materialises the bytes from an internal stream; the async path never builds this.
  struct ExportOutcome
  {
    std::string document;
    std::vector<NamespaceMapping> namespacesWritten;
    std::size_t nodesExported{};
    std::size_t referencesExported{};
  };

  // --- Async export. Invokes `completion` exactly once, on the AS executor. ---
  //
  // Discovers the target namespaces' nodes (via `discover_async`), reads each node (attributes
  // synchronously off the resident accessor; references and a Variable's live value via the async
  // accessor methods, since a sync read would deadlock the single-thread AS executor), applies the
  // node/reference filters and scope, optionally resolves `<Aliases>`, and serialises the NodeSet2
  // document DIRECTLY into `out` - no intermediate document buffer is materialised. `out` is co-owned
  // (shared_ptr) for the operation's lifetime, so it cannot dangle across the async boundary. The
  // completion carries only the summary.
  using ExportCompletion = std::function<void(Result<ExportSummary>)>;
  void export_async(ExportSettings settings, shared_ptr<Stream> out, ExportCompletion completion);

  // --- Synchronous convenience (two-variant pattern, mirrors `ImportEngine::try_*_sync`) ---------
  //
  // Wraps `discover_async` and BLOCKS on the CALLER's thread until it completes. The caller's thread
  // must NOT be an AddressSpace-executor thread: the wrapper blocks, so driving it from a
  // single-threaded AS executor would deadlock - the very footgun the async engine exists to avoid.
  // Intended for startup and test contexts that own a separate thread to run the executor. Any
  // thrown exception is funnelled into a bad Result - never propagated.
  Result<std::vector<NodeId>> try_discover_sync(std::vector<uint16_t> targetNamespaceIndices);

  // Blocking convenience that materialises the document into an owned buffer (wraps `export_async`
  // with an internal MemoryStream). Same caller-thread requirement as `try_discover_sync`.
  Result<ExportOutcome> try_export_sync(ExportSettings settings);

private:
  ExportEngine(EncodingLimits limits, AddressSpace addressSpace);

  // Discovery and export each run as one self-owning coroutine, defined in the .cpp. The step
  // functions they replace - fifteen of them, plus two heap-frame structs and two post_step
  // templates - were only ever the shape a callback chain forces on a loop.
  class DiscoverOperation;
  class ExportOperation;

  // Immutable after construction.
  const EncodingLimits mLimits;
  const WeakAddressSpace mAddressSpace;
};

}  // namespace ua::xml::nodeset

#endif  // !UA_NODESET_EXPORT_ENGINE_H
