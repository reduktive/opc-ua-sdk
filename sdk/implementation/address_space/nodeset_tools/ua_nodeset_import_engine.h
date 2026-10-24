// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODESET_IMPORT_ENGINE_H
#define UA_NODESET_IMPORT_ENGINE_H

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ua_address_space.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_namespace_registration_coordinator.h"
#include "ua_result.h"
#include "ua_nodeset_parser.h"

namespace ua
{

class Namespace;

namespace xml::nodeset
{

// Callable that allocates a server Namespace for a file-declared URI the server does not yet
// know. Mirrors design decision D-R (the public import option is a callable, not an abstract
// class); the public surface adapts into this type. Empty => an unknown URI is a clean error.
using NamespaceAllocator = std::function<shared_ptr<Namespace>(string_view uri)>;

// Async, non-blocking NodeSet import engine. Reimplements the (retired) synchronous `Importer`
// as a continuation flow.
//
// Lifetime: the engine keeps itself alive across the async chain by capturing a
// strong `shared_from_this()` in each continuation - the documented exception to weak-capture
// for a *bounded operation that must outlive each step*. It is not a cycle: each operation's
// completion fires exactly once, releasing the chain.
//
// Shutdown safety (D-V): the address space is held WEAKLY (`WeakAddressSpace`) and `lock()`-ed
// per step, mirroring `AddressSpace::codec_namespace_context`. An in-flight import therefore
// never pins the address space alive (no shutdown latency). If a `lock()` fails (teardown in
// progress) the operation completes once with `BadShutdown`.
//
// Threading: every AddressSpace call posts its continuation back onto the AS executor, and an
// operation's phases and their chunks are driven strictly sequentially (the next is sent only when the
// previous has answered). The engine's mutable state is therefore touched only from those serialized
// continuations - single-threaded-by-construction; no extra strand is needed.
class ImportEngine : public std::enable_shared_from_this<ImportEngine>
{
public:
  ImportEngine() = delete;
  ImportEngine(const ImportEngine&) = delete;
  ImportEngine(ImportEngine&&) = delete;
  ImportEngine& operator=(const ImportEngine&) = delete;
  ImportEngine& operator=(ImportEngine&&) = delete;
  ~ImportEngine() = default;

  using ImportNodePredicate = std::function<bool(const Node& node)>;
  using ImportReferencePredicate = std::function<bool(const Node& node, const Node::Reference& reference)>;
  using Completion = std::function<void(VoidResult)>;

  // `nodeSets` are held by value (owning shared_ptr copies) so the engine owns its inputs for the
  // duration of the async operation. `namespaceAllocator` may be empty (unknown URI => error).
  static shared_ptr<ImportEngine> create(EncodingLimits limits, AddressSpace addressSpace,
    std::vector<shared_ptr<NodeSet>> nodeSets, NamespaceAllocator namespaceAllocator);

  // When true (default), a value containing an ExtensionObject of an unresolved type aborts the
  // import. When false, such values are imported as preserved opaque ExtensionObjects.
  void set_fail_on_unknown_structure(bool value)
  {
    mFailOnUnknownStructure = value;
  }

  // When false (default), Draft/Deprecated nodes are skipped (D-Q).
  void set_include_non_released(bool value)
  {
    mIncludeNonReleased = value;
  }

  // Override the StructureResolver used to decode values (D-H 6). Empty (default) => each NodeSet's
  // own parse-time resolver is used (what NS0 and standard-struct values rely on); a non-empty
  // override realizes values with the *target's* types, so one parsed document resolves per-target.
  void set_structure_resolver(StructureResolver resolver)
  {
    mStructureResolverOverride = std::move(resolver);
  }

  // What the import writes for one source node's access-control Attributes in place of what the NodeSet
  // declares. An engaged member replaces (an engaged-but-empty RolePermissions means deny-all, exactly
  // as <HasNoPermissions> does); a disengaged one leaves the NodeSet's own declaration alone.
  struct AccessDecoration
  {
    optional<std::vector<RolePermissionType>> rolePermissions;
    optional<AccessRestrictionType> accessRestrictions;
  };

  // Keyed by the node's id in the source NodeSet's frame - the frame the caller computed against. The
  // engine translates the stamped Role ids on the way out exactly as it translates the NodeSet's own.
  using AccessDecorationMap = std::unordered_map<NodeId, AccessDecoration>;

  // Install a per-node override of RolePermissions / AccessRestrictions. Empty (default) => the NodeSet
  // is imported as written. Its one caller is the server's NS0 decoration; it is not a general
  // attribute-rewriting interface.
  void set_access_decoration(AccessDecorationMap decoration)
  {
    mAccessDecoration = std::move(decoration);
  }

  // --- Async operations. Each invokes `completion` exactly once, on the AS executor. ---

  // Import every node (each individually, no forward-reference recursion) that passes `nodePred`.
  void import_all_async(optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred,
    Completion completion);

  // Import type definitions (and their type-child instance declarations) only. See the retired
  // `Importer::import_type_definitions_only` for the exact category/parent-walk semantics.
  void import_type_definitions_only_async(std::string excludedCategorySubstring,
    optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred,
    Completion completion);

  // Import a single node (no forward-reference recursion).
  void import_node_async(NodeId nodeId, optional<ImportReferencePredicate> refPred, Completion completion);

  // Import a node and the transitive closure of its forward references.
  void import_node_and_forward_refs_async(NodeId nodeId, optional<ImportNodePredicate> nodePred,
    optional<ImportReferencePredicate> refPred, Completion completion);

  // --- Synchronous convenience (two-variant pattern, mirrors `import_nodeset_sync`) --------------
  //
  // Each wraps the corresponding `*_async` op and BLOCKS on the CALLER's thread until it completes.
  // The caller's thread must NOT be an AddressSpace-executor thread: the wrapper blocks, so driving
  // it from a single-threaded AS executor would deadlock - the very footgun the async engine exists
  // to avoid (see the file header). Intended for startup and test contexts that own a separate
  // thread to run the executor. `try_*_sync` return the `VoidResult` and never throw; the unprefixed
  // `*_sync` throw `UaException` on a bad Result.

  VoidResult try_import_all_sync(
    optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred);
  void import_all_sync(optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred);

  VoidResult try_import_type_definitions_only_sync(std::string excludedCategorySubstring,
    optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred);
  void import_type_definitions_only_sync(std::string excludedCategorySubstring,
    optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred);

  VoidResult try_import_node_sync(NodeId nodeId, optional<ImportReferencePredicate> refPred);
  void import_node_sync(NodeId nodeId, optional<ImportReferencePredicate> refPred);

  VoidResult try_import_node_and_forward_refs_sync(
    NodeId nodeId, optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred);
  void import_node_and_forward_refs_sync(
    NodeId nodeId, optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred);

  // Counts of what was actually committed, accumulated across operations on this engine.
  [[nodiscard]] std::size_t nodes_imported() const
  {
    return mNodesImported;
  }

  [[nodiscard]] std::size_t references_imported() const
  {
    return mReferencesImported;
  }

  /// Translates one document-local NodeId through the namespace maps built for this import.
  /// Available after import begins; used by the public facade for post-import metadata corrections.
  NodeIdResult translated_node_id(const NodeId& documentNodeId) const noexcept;

private:
  ImportEngine(EncodingLimits limits, AddressSpace addressSpace, std::vector<shared_ptr<NodeSet>> nodeSets,
    NamespaceAllocator namespaceAllocator);

  // One import operation carried through its phases (NR-31): the Nodes it reaches are looked up, the missing
  // ones created, then every Reference of them added, then the created Variables' Values written.
  struct Operation;
  struct NamespaceMapFrame;
  struct RegistrationMetadataSource;
  struct RegistrationMetadataFrame;

  // ---- Operation phases. Each phase is sent in chunks of its operation limit, one after another, and each
  // answer is handled on a fresh stack; a handler called after its phase has ended does nothing. ----
  void start_operation(shared_ptr<Operation> operation);
  void charge_node(Operation& operation) const;
  // Adds the Node the files hold as @p fileLocalId, or the resolved @p xmlNode, unless it was reached
  // already, the files do not hold it, or it is not released; the failure of its budget or translation,
  // located.
  optional<StatusCode> add_item(Operation& operation, const NodeId& fileLocalId) noexcept;
  optional<StatusCode> add_item(Operation& operation, const NodeSet* nodeSet, Node* xmlNode) noexcept;
  optional<StatusCode> add_resolved_item(
    Operation& operation, const NodeSet* nodeSet, Node* xmlNode) noexcept;
  void look_up_level(shared_ptr<Operation> operation);
  void look_up_next(shared_ptr<Operation> operation);
  void on_looked_up(
    shared_ptr<Operation> operation, std::size_t begin, BatchResult<NodeAccessorResult> found);
  void create_level(shared_ptr<Operation> operation);
  void create_next(shared_ptr<Operation> operation);
  void on_created(shared_ptr<Operation> operation, std::size_t begin, std::size_t end,
    std::vector<NodeAccessorResult> created);
  /// Deletes @p refusedHeld, the Nodes the namespace holds from creates the import refused, then answers the
  /// operation @p failure. A Node that cannot be deleted is logged; the answer stays @p failure.
  void remove_refused_then_finish(
    shared_ptr<Operation> operation, std::vector<NodeId> refusedHeld, StatusCode failure);
  void next_level(shared_ptr<Operation> operation);
  void add_references(shared_ptr<Operation> operation);
  // Keeps, of the halves one source is sent that are one Reference, the one whose type is each other's or a
  // subtype of it (DL-11); the refusal, located, when their types are not one line of subtypes.
  optional<StatusCode> keep_one_half_per_reference(Operation& operation) const;
  void add_next_references(shared_ptr<Operation> operation);
  void on_references_added(shared_ptr<Operation> operation, std::size_t begin, std::vector<VoidResult> added);
  void write_next_values(shared_ptr<Operation> operation);
  void on_values_written(
    shared_ptr<Operation> operation, std::vector<std::size_t> written, std::vector<VoidResult> results);
  void finish(shared_ptr<Operation> operation, VoidResult result);
  // The address space the operation imports into: the staged one, else the engine's.
  WeakAddressSpace handle_of(const Operation& operation) const;

  // Posts `fn` onto the AS executor with a fresh stack (post discipline). If the AS can no longer
  // be locked, finishes the operation once with Bad_Shutdown (AddressSpaceGone) instead.
  // Templated over the handler (not a std::function) to avoid the type-erasure heap allocation that
  // clangsa mis-reads as a leak (cplusplus.NewDeleteLeaks); defined out-of-line, instantiated only
  // within this TU.
  template<class Fn>
  void post_next(shared_ptr<Operation> operation, Fn&& fn);

  // Shared backing for the `try_*_sync` variants: kicks `start` (which launches one async op and
  // moves its predicates into the chain synchronously), then blocks the caller's thread on the
  // completion. Any thrown exception is funnelled into a bad `VoidResult` - never propagated.
  VoidResult drive_sync(const std::function<void(Completion)>& start);

  // ---- Namespace registration + synchronous translation against the resulting maps ----
  void build_namespace_maps_async(optional<ImportNodePredicate> nodePred,
    optional<ImportReferencePredicate> refPred, Completion completion);
  void drive_namespace_maps(shared_ptr<NamespaceMapFrame> frame);
  void on_namespace_registered(shared_ptr<NamespaceMapFrame> frame, String requestedUri, UInt16Result result);
  void prepare_existing_imported_metadata(
    shared_ptr<NamespaceMapFrame> frame, String requestedUri, uint16_t namespaceIndex);
  void on_existing_imported_metadata_prepared(
    shared_ptr<NamespaceMapFrame> frame, String requestedUri, uint16_t namespaceIndex, VoidResult result);
  void finish_namespace_maps(shared_ptr<NamespaceMapFrame> frame, VoidResult result);
  shared_ptr<RegistrationMetadataSource> find_registration_metadata_source(string_view namespaceUri,
    const optional<ImportNodePredicate>& nodePred, const optional<ImportReferencePredicate>& refPred) const;
  ::ua::detail::NamespaceRegistrationInitializer make_metadata_initializer(String namespaceUri,
    shared_ptr<RegistrationMetadataSource> source, optional<ImportReferencePredicate> refPred);
  void stage_registration_metadata_async(AddressSpace stagedAddressSpace, uint16_t namespaceIndex,
    String namespaceUri, shared_ptr<RegistrationMetadataSource> source,
    optional<ImportReferencePredicate> refPred,
    ::ua::detail::NamespaceRegistrationInitializationCallback completion);
  void drive_registration_metadata(shared_ptr<RegistrationMetadataFrame> frame);
  void finish_registration_metadata(shared_ptr<RegistrationMetadataFrame> frame, VoidResult result);
  std::vector<uint16_t> registration_namespace_map(
    const NodeSet& nodeSet, string_view candidateUri, uint16_t candidateIndex) const;
  const std::vector<uint16_t>& ns_index_map(const NodeSet& nodeSet) const;
  NodeId translate_node_id(const NodeSet& nodeSet, const NodeId& nodeId) const;
  QualifiedName translate_qualified_name(const NodeSet& nodeSet, const QualifiedName& browseName) const;
  CodecNamespaceContext make_translation_config(const NodeSet& nodeSet) const;

  // The resolver to decode `nodeSet`'s values with: the override if set, else the NodeSet's own (D-H 6).
  const StructureResolver& resolver_for(const NodeSet& nodeSet) const;

  // Build the full set of creation attributes for a source node (base + class-specific). May throw
  // (the DataType/VariableType paths throw UaException on an unresolved structure or a bad parent);
  // callers wrap the call so the exception becomes a bad VoidResult on the frame. A Variable's live
  // Value is NOT a creation attribute - it is written through the async value path post-create.
  ua::InitialAttributes build_initial_attributes(const Node& source, const NodeSet& nodeSet);

  void copy_base_attributes(const Node& source, const NodeSet& nodeSet, ua::InitialAttributes& attributes);
  void copy_attributes(const ReferenceType& source, ua::InitialAttributes& attributes);
  void copy_attributes(const DataType& source, const NodeSet& nodeSet, ua::InitialAttributes& attributes);
  void copy_attributes(const Object& source, ua::InitialAttributes& attributes);
  void copy_attributes(const VariableType& source, const NodeSet& nodeSet, ua::InitialAttributes& attributes);
  void copy_attributes(const Method& source, ua::InitialAttributes& attributes);
  void copy_attributes(const ObjectType& source, ua::InitialAttributes& attributes);
  void copy_attributes(const View& source, ua::InitialAttributes& attributes);

  bool has_optional_fields(span<const DataTypeField> fields);
  bool allows_sub_types(span<const DataTypeField> fields);
  NodeId default_binary_encoding_id(const Node& dataType, const NodeSet& nodeSet);

  // A DataType encoding object (Default Binary / Default XML) - an Object whose HasTypeDefinition
  // target is DataTypeEncodingType (i=76). These nodes carry no ParentNodeId and are reachable only
  // via the inverse HasEncoding from their DataType, so the type-child parent-walk cannot reach them.
  static bool is_data_type_encoding(const Node& node);

  // Part 16 section 4.4.5 model normalization. Build once from the parsed graph so every import
  // operation sees the same bidirectional, deduplicated GeneratesEvent closure without mutating
  // the caller-owned NodeSet document.
  void build_state_machine_reference_closure();

  std::pair<const NodeSet*, Node*> find_node_with_nodeset(const NodeId& nodeId) const;

  // Immutable after construction.
  const EncodingLimits mLimits;
  const WeakAddressSpace mAddressSpace;
  const std::vector<shared_ptr<NodeSet>> mNodeSets;
  const NamespaceAllocator mNamespaceAllocator;

  // Non-owning view over mNodeSets for the (mutable-span) `utilities::*` helpers.
  NodeSets node_sets() const
  {
    return NodeSets{const_cast<shared_ptr<NodeSet>*>(mNodeSets.data()), mNodeSets.size()};
  }

  // Working state - touched only from serialized continuations.
  std::unordered_map<const NodeSet*, std::vector<uint16_t>> mNodeSetNsIndexMaps;
  std::unordered_map<const Node*, std::vector<Node::Reference>> mDerivedReferences;
  // Source nodes this engine has found or created in the address space, by any earlier or current
  // operation. A filtered import keeps a reference to one of these even when its own filter would not
  // import the target: the target is already there, so the reference does not dangle.
  std::unordered_set<const Node*> mNodesInAddressSpace;
  bool mNamespaceMapsBuilt{false};
  std::size_t mNodesImported{0};
  std::size_t mReferencesImported{0};

  // Policy.
  bool mFailOnUnknownStructure{true};
  bool mIncludeNonReleased{false};
  // Empty => decode each NodeSet's values with its own parse-time resolver (D-H 6).
  StructureResolver mStructureResolverOverride;
  // Empty => import each node's access-control Attributes exactly as the NodeSet declares them.
  AccessDecorationMap mAccessDecoration;
};

}  // namespace xml::nodeset

}  // namespace ua

#endif  // !UA_NODESET_IMPORT_ENGINE_H
