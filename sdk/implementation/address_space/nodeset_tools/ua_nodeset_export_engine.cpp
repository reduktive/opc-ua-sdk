// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_nodeset_export_engine.h"
#include "ua_callback_safety.h"

#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_binary_codec.h"
#include "ua_built_in_type_id.h"
#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_event_notifier_type.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_memory_stream.h"
#include "ua_node_accessor.h"
#include "ua_namespace_route.h"
#include "ua_node_class.h"
#include "ua_on_strand.h"
#include "ua_object_id.h"
#include "ua_integer_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_self_owning_operation.h"
#include "ua_sync_wait.h"
#include "ua_reference.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_unknown_structure.h"
#include "ua_utilities.h"
#include "ua_variant.h"
#include "ua_xml_codec.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <deque>
#include <future>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ua::xml::nodeset
{

namespace
{

// The standard roots seeded into the browse-traversal frontier. Reaching every exportable node
// from these roots requires following BOTH forward and inverse references: encoding objects
// (Default Binary / Default XML) are reachable only via the inverse HasEncoding from their DataType,
// and the four type-folder subtrees hang under the Types folder.
std::vector<NodeId> standard_roots()
{
  return {NodeId{ObjectId::RootFolder},
    NodeId{ObjectId::ObjectsFolder},
    NodeId{ObjectId::TypesFolder},
    NodeId{ObjectId::ViewsFolder},
    NodeId{ObjectId::ObjectTypesFolder},
    NodeId{ObjectId::VariableTypesFolder},
    NodeId{ObjectId::DataTypesFolder},
    NodeId{ObjectId::ReferenceTypesFolder}};
}

}  // namespace

// Per-operation discovery state, heap-allocated and carried (by shared_ptr) through the async chain.
// Touched only from the AS-executor-serialized continuations - single-threaded-by-construction.
Result<std::vector<NodeId>> ExportEngine::try_discover_sync(std::vector<uint16_t> targetNamespaceIndices)
{
  // External/startup-thread convenience: block on the CALLER's thread (never an AS-executor thread).
  // The promise is a local; the documented sync-wrapper exception permits a local
  // completion that references it. discover_async launches the async op synchronously before
  // returning, so the caller's locals stay valid for the launch.
  try
  {
    auto locked = mAddressSpace.lock();
    if (!locked)
    {
      return Result<std::vector<NodeId>>{StatusCode{Status::BadShutdown}};
    }
    // The comment above says "never an AS-executor thread". This is that sentence enforced: a thread
    // of the executor cannot wait for work queued to it, so the wait is refused rather than entered.
    const auto executor = locked->executor();

    return ua::async::detail::blocking_call<Result<std::vector<NodeId>>>(executor,
      [&](std::function<void(Result<std::vector<NodeId>>)> complete)
      { discover_async(std::move(targetNamespaceIndices), std::move(complete)); });
  }
  catch (...)
  {
    return Result<std::vector<NodeId>>{StatusCode{ua::exception_to_status_code(std::current_exception())}};
  }
}

// =================================================================================================
// Export read pass - per-node read (synchronous off the resident accessor) + document serialisation.
// =================================================================================================

namespace
{

// Extracts a scalar LocalizedText attribute WITHOUT throwing: an absent/empty, array, or
// non-LocalizedText Variant yields an empty vector, so the element is simply not emitted. A throwing
// Variant access inside an asio handler would terminate the process, so this stays total.
std::vector<LocalizedText> read_localized_text_attribute(
  const NodeAccessor& accessor, AttributeId attributeId)
{
  const Variant value = accessor.read_attribute(attributeId);
  if (value.empty() || value.is_array() || value.get_built_in_type() != BuiltInTypeId::LocalizedText)
  {
    return {};
  }
  return {value.as<LocalizedText>()};
}

// Reads a resident node's ATTRIBUTES into a (partial) ExportedNode. Synchronous and safe: the
// find_node caching contract (I2) makes the attribute set a guaranteed local hit. References and a
// Variable's live value are NOT covered by that cache and are read asynchronously by the caller; a
// VariableType's default Value IS a stored attribute, so it is read here. Server-index ids.
ExportedNode read_node_attributes(const NodeAccessor& accessor)
{
  ExportedNode node;
  // Identity attributes are essential and reliably I2-cached. If one of these throws the node cannot
  // be represented and the caller skips it; everything below is best-effort so a node missing an
  // optional/uninitialised attribute still exports with whatever is readable (it must not vanish).
  // NodeId, NodeClass and BrowseName are essential and mandatory in the NodeSet2 schema. If any
  // throws (a bare/partial node), this function throws and the caller skips the node - a node we
  // cannot name cannot be emitted as valid `<UA*>` markup, so skipping it keeps the document valid
  // rather than writing an invalid empty BrowseName.
  node.nodeId = accessor.get_node_id();
  node.nodeClass = accessor.get_node_class();
  node.browseName = accessor.get_browse_name();
  // `get_browse_name` answers for a node carrying no BrowseName rather than throwing, so the skip
  // above has to be asked for explicitly here: an unnameable node must still not reach the document.
  if (node.browseName.name().empty())
  {
    throw UaException{Status::BadNodeIdUnknown,
      ErrorDetail::build("ExportNodeHasNoBrowseName",
        "Node carries no BrowseName and cannot be emitted as valid NodeSet2 markup",
        "NodeSetExportEngine")
        .context(ua::ContextKeys::nodeId, ua::to_string(node.nodeId))};
  }

  // The remaining base attributes are optional; their absence must not drop the node.
  try
  {
    if (const auto writeMask = accessor.get_write_mask())
    {
      node.writeMask = writeMask->as_underlying_type();
    }

    // DisplayName / Description / InverseName have no typed getter; read them as attributes.
    node.displayName = read_localized_text_attribute(accessor, AttributeId::DisplayName);
    node.description = read_localized_text_attribute(accessor, AttributeId::Description);
  }
  catch (const std::exception&)
  {
    // An optional base attribute was unreadable; the node still exports with its identity + browse name.
    ua::detail::ignore_expected_exception();
  }

  // Class-specific attributes. A bare or partial node may lack a mandatory attribute whose typed
  // getter then throws; the catch below keeps the base node (and its references) by omitting the
  // class-specific attributes rather than dropping the whole node.
  try
  {
    if (const auto variable = accessor.as<VariableAccessor>())
    {
      node.dataType = variable->get_data_type();
      node.valueRank = variable->get_value_rank().as_int32();
      if (const auto dimensions = variable->get_array_dimensions())
      {
        node.arrayDimensions.assign(dimensions->begin(), dimensions->end());
      }
      node.accessLevel = variable->get_access_level().as_underlying_type();
      node.historizing = variable->get_historizing();
      if (const auto samplingInterval = variable->get_minimum_sampling_interval())
      {
        node.minimumSamplingInterval =
          samplingInterval;  // assign the optional directly (no deref round-trip)
      }
      // The Variable's live value is dynamic (not in the resident attribute cache); on_node_read reads
      // it asynchronously.
    }
    else if (const auto variableType = accessor.as<VariableTypeAccessor>())
    {
      node.dataType = variableType->get_data_type();
      node.valueRank = variableType->get_value_rank().as_int32();
      if (const auto dimensions = variableType->get_array_dimensions())
      {
        node.arrayDimensions.assign(dimensions->begin(), dimensions->end());
      }
      node.isAbstract = variableType->get_is_abstract();
      if (const auto value = variableType->get_value(); value && !value->value().empty())
      {
        node.value = value->value();
      }
    }
    else if (const auto objectType = accessor.as<ObjectTypeAccessor>())
    {
      node.isAbstract = objectType->get_is_abstract();
    }
    else if (const auto dataType = accessor.as<DataTypeAccessor>())
    {
      node.isAbstract = dataType->get_is_abstract();
      // The DataTypeDefinition attribute is read synchronously off the resident accessor (same
      // contract as get_is_abstract); a null result simply omits the `<Definition>` element.
      node.dataTypeDefinition = dataType->get_data_type_definition();
    }
    else if (const auto referenceType = accessor.as<ReferenceTypeAccessor>())
    {
      node.isAbstract = referenceType->get_is_abstract();
      node.symmetric = referenceType->get_symmetric();
      node.inverseName = read_localized_text_attribute(accessor, AttributeId::InverseName);
    }
    else if (const auto object = accessor.as<ObjectAccessor>())
    {
      node.eventNotifier = object->get_event_notifier().as_underlying_type();
    }
    else if (const auto view = accessor.as<ViewAccessor>())
    {
      node.eventNotifier = view->get_event_notifier().as_underlying_type();
      node.containsNoLoops = view->get_contains_no_loops();
    }
    else if (const auto method = accessor.as<MethodAccessor>())
    {
      node.executable = method->get_executable();
    }
  }
  catch (const std::exception&)
  {
    // A class-specific getter threw (e.g. an unset mandatory attribute on a partial node); the base
    // node and its references are still exported.
    ua::detail::ignore_expected_exception();
  }

  return node;
}

// Collects every server namespace index reachable from ids EMBEDDED in a Variant value (a scalar or
// array NodeId/QualifiedName/ExpandedNodeId, or such fields nested inside an ExtensionObject). Rather
// than hand-walk every Variant shape, this drives the XmlEncoder once with recording translators: the
// encoder already visits every embedded id and invokes the translators, so their side effect captures
// the complete namespace set. The encoded output is discarded; a value the encoder cannot serialise
// (an unresolved opaque body) is ignored here and handled by the writer's unencodable policy.
//
// This means every value is XML-encoded twice (once here to harvest namespaces, once in build_and_write
// to actually emit it). That is a deliberate trade for a complete `<NamespaceUris>` table without
// hand-walking every Variant shape; export is a tooling/non-hot path, so the extra pass is acceptable.
void collect_value_namespaces(const Variant& value, const EncodingLimits& limits, std::set<uint16_t>& out)
{
  const CodecNamespaceContext recorder =
    CodecNamespaceContext::with_translators([&out](NodeId& id) { out.insert(id.namespace_index()); },
      [&out](QualifiedName& name) { out.insert(name.namespace_index()); },
      [&out](ExpandedNodeId& id)
      {
        if (!id.is_remote())
        {
          out.insert(id.node_id().namespace_index());
        }
      });
  try
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream(device);
    XmlEncoder encoder(recorder, stream);
    const StackDepth limit = limits.stack_depth();
    encoder.encode(limit, "", value);
  }
  catch (const std::exception&)
  {
    // Unencodable value (e.g. an unresolved opaque body): no embedded ids to collect.
    ua::detail::ignore_expected_exception();
  }
}

// Accumulates every server namespace index a node's ids reference (own id, browse name, data type,
// reference types and targets, structure-definition field/base types, AND ids embedded in its value)
// so the header's NamespaceUris table is complete before it is written.
void collect_namespaces(const ExportedNode& node, const EncodingLimits& limits, std::set<uint16_t>& out)
{
  out.insert(node.nodeId.namespace_index());
  out.insert(node.browseName.namespace_index());
  if (node.dataType)
  {
    out.insert(node.dataType->namespace_index());
  }
  for (const auto& reference : node.references)
  {
    out.insert(reference.referenceTypeId.namespace_index());
    out.insert(reference.targetId.node_id().namespace_index());
  }
  // A structure `<Definition>`'s base type and field types may reference further namespaces.
  if (node.dataTypeDefinition)
  {
    if (const auto* structure = dynamic_cast<const StructureDefinition*>(node.dataTypeDefinition.get()))
    {
      out.insert(structure->base_data_type().namespace_index());
      for (const auto& field : structure->fields())
      {
        out.insert(field.data_type().namespace_index());
      }
    }
  }
  // Ids embedded inside a `<Value>` must be in the table too, or their server->file translation would
  // collapse an unlisted namespace to NS0 and silently corrupt the value on re-import.
  if (node.value)
  {
    collect_value_namespaces(*node.value, limits, out);
  }
}

// Reifies an opaque binary-bodied ExtensionObject value to a typed Structure (via `resolver`) so it
// can be transcoded to XML. Typed values and XML-bodied opaque values are returned unchanged (the
// encoder handles them); if there is no resolver, the value is not a scalar opaque-binary structure,
// the resolver declines, or the binary decode fails, the original value is returned (the writer's
// unencodable policy then applies). Arrays of opaque structures are not reified (a known limitation).
//
// Soundness note: reification then re-emits the body's embedded ids through the value translators, so
// it is correct only when the stored body uses SERVER namespace indices (the normal case for a live
// value). A body preserved verbatim from an `ImportOpaque` (file-local indices) is the documented
// exception, mirroring the importer's own opaque caveat.
Variant reify_value(const Variant& value, const StructureResolver& resolver, const EncodingLimits& limits)
{
  if (!resolver || !value.is_structure())
  {
    return value;
  }
  const auto* unknown = dynamic_cast<const UnknownStructure*>(&value.as<Structure>());
  if (unknown == nullptr || unknown->body_encoding() != UnknownStructure::BodyEncoding::Binary)
  {
    return value;
  }
  auto typed = resolver(unknown->encoding_id());
  if (!typed)
  {
    return value;
  }
  try
  {
    const ByteString& body = unknown->encoded_data();
    memory_stream_device::ExternalReadOnly device{static_cast<span<const byte>>(body)};
    MemoryStream stream(device);
    UaBinaryDecoder decoder{resolver, stream, limits};
    decoder.decode(limits.stack_depth(), *typed);
    // The body and the resolved type must match exactly: trailing bytes mean the body was encoded
    // against a different definition (or is corrupt), so the decode would be silently truncated.
    // Decline the reification in that case and keep the opaque value (policy then governs it).
    if (stream.get_position() != body.size())
    {
      return value;
    }
    return Variant{std::move(typed)};
  }
  catch (const std::exception&)
  {
    return value;
  }
}

}  // namespace

namespace
{

// True if `node` is a type-definition node (the classes kept under ExportScope::TypeDefinitionsOnly).
bool is_type_definition(const ExportedNode& node)
{
  switch (node.nodeClass)
  {
  case NodeClass::ObjectType:
  case NodeClass::VariableType:
  case NodeClass::DataType:
  case NodeClass::ReferenceType:
    return true;
  default:
    return false;
  }
}

// Gathers the distinct reference/data type ids worth aliasing across the exported nodes: every
// reference type, every node DataType, and a structure definition's base/field data types.
std::vector<NodeId> gather_alias_candidates(const std::vector<ExportedNode>& nodes)
{
  std::vector<NodeId> candidates;
  std::unordered_set<NodeId> seen;
  auto add = [&](const NodeId& id)
  {
    if (!id.is_null() && seen.insert(id).second)
    {
      candidates.push_back(id);
    }
  };
  for (const auto& node : nodes)
  {
    for (const auto& reference : node.references)
    {
      add(reference.referenceTypeId);
    }
    if (node.dataType)
    {
      add(*node.dataType);
    }
    if (node.dataTypeDefinition)
    {
      if (const auto* structure = dynamic_cast<const StructureDefinition*>(node.dataTypeDefinition.get()))
      {
        add(structure->base_data_type());
        for (const auto& field : structure->fields())
        {
          add(field.data_type());
        }
      }
    }
  }
  return candidates;
}

// Resolves the (id, name) pairs into the writer's alias list, dropping any name shared by more than
// one id (an ambiguous alias would not round-trip) and ordering the result by name for stable output.
std::vector<std::pair<NodeId, String>> finalize_aliases(
  const std::vector<std::pair<NodeId, String>>& resolved)
{
  std::unordered_map<std::string, int> nameCounts;
  for (const auto& [id, name] : resolved)
  {
    ++nameCounts[std::string{static_cast<string_view>(name)}];
  }
  std::vector<std::pair<NodeId, String>> aliases;
  for (const auto& entry : resolved)
  {
    if (nameCounts[std::string{static_cast<string_view>(entry.second)}] == 1)
    {
      aliases.push_back(entry);
    }
  }
  std::sort(aliases.begin(),
    aliases.end(),
    [](const auto& lhs, const auto& rhs)
    { return static_cast<string_view>(lhs.second) < static_cast<string_view>(rhs.second); });
  return aliases;
}

}  // namespace

/// Discovers the work-list for an export: every node in the target namespaces.
///
/// Two phases. Each target namespace is asked to enumerate itself; any that declines with
/// BadNotSupported is collected instead by a single breadth-first browse from the standard roots,
/// which runs once for all of them. The frontier's `visited` set covers every id ever enqueued, so a
/// cyclic graph still visits each node once.
///
/// The address space is held WEAKLY and re-locked before every step, exactly as the flow this
/// replaces did: the engine must not keep an address space alive, and a discovery outliving one
/// answers BadShutdown rather than touching it.
ExportEngine::ExportEngine(EncodingLimits limits, AddressSpace addressSpace)
  : mLimits(limits), mAddressSpace(addressSpace.weak())
{}

shared_ptr<ExportEngine> ExportEngine::create(EncodingLimits limits, AddressSpace addressSpace)
{
  class Wrapper : public ExportEngine
  {
  public:
    Wrapper(EncodingLimits limits, AddressSpace addressSpace) : ExportEngine{limits, std::move(addressSpace)}
    {}
  };

  return make_shared<Wrapper>(limits, std::move(addressSpace));
}

class ExportEngine::DiscoverOperation final : public ua::async::SelfOwningOperation<DiscoverOperation>
{
public:
  static void start(WeakAddressSpace weakAddressSpace, WorkBudget budget,
    std::vector<uint16_t> targetNamespaceIndices, DiscoverCompletion completion)
  {
    auto locked = weakAddressSpace.lock();
    if (!locked)
    {
      completion(Result<std::vector<NodeId>>{StatusCode{Status::BadShutdown}});
      return;
    }
    launch(std::make_shared<DiscoverOperation>(boost::asio::make_strand(locked->executor()),
      locked->logger(),
      std::move(weakAddressSpace),
      budget,
      std::move(targetNamespaceIndices),
      std::move(completion)));
  }

  DiscoverOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    WeakAddressSpace weakAddressSpace, WorkBudget budget, std::vector<uint16_t> targetNamespaceIndices,
    DiscoverCompletion completion)
    : ua::async::SelfOwningOperation<DiscoverOperation>(std::move(strand), std::move(logger)),
      mAddressSpace(std::move(weakAddressSpace)), mBudget(budget),
      mTargetNamespaceIndices(std::move(targetNamespaceIndices)), mCompletion(std::move(completion))
  {}

private:
  friend class ua::async::SelfOwningOperation<DiscoverOperation>;

  // Declared ahead of the body that co_awaits them: an `auto` return type has to be deduced before a
  // caller can name it.
  auto enumerate_nodes(AddressSpace& addressSpace, uint16_t namespaceIndex)
  {
    return await_step<Result<std::vector<NodeId>>>([&addressSpace, namespaceIndex](auto completion) mutable
      { addressSpace.enumerate_nodes_async(namespaceIndex, std::move(completion)); });
  }

  auto find_node(AddressSpace& addressSpace, NodeId nodeId)
  {
    return await_step<NodeAccessorResult>([&addressSpace, nodeId = std::move(nodeId)](auto completion) mutable
      { addressSpace.find_node_async(nodeId, std::move(completion)); });
  }

  auto get_references(NodeAccessor& node)
  {
    return await_step<Result<References>>(
      [&node](auto completion) mutable { node.get_references_async(std::move(completion)); });
  }

  ua::async::Task<> run()
  {
    try
    {
      // Namespaces whose `enumerate_nodes` declines: collected by the browse traversal instead.
      std::set<uint16_t> needsTraversal;
      std::vector<NodeId> workList;

      for (const uint16_t namespaceIndex : mTargetNamespaceIndices)
      {
        auto addressSpace = lock_address_space();
        if (!addressSpace)
        {
          co_return;  // already answered BadShutdown
        }
        auto enumerated = co_await enumerate_nodes(*addressSpace, namespaceIndex);
        if (enumerated.is_good())
        {
          auto& ids = enumerated.value();
          workList.insert(
            workList.end(), std::make_move_iterator(ids.begin()), std::make_move_iterator(ids.end()));
        }
        else if (enumerated.status_code().as_status() == Status::BadNotSupported)
        {
          needsTraversal.insert(namespaceIndex);
        }
        else
        {
          // Any other bad status fails the whole discovery, propagating its ErrorDetail.
          finish(Result<std::vector<NodeId>>{enumerated.status_code()});
          co_return;
        }
      }

      if (!needsTraversal.empty() && !co_await traverse(needsTraversal, workList))
      {
        co_return;
      }

      finish(deduplicate(std::move(workList)));
    }
    catch (const ua::async::Abandoned&)
    {
      finish(Result<std::vector<NodeId>>{StatusCode{Status::BadOperationAbandoned}});
    }
    catch (...)
    {
      finish(Result<std::vector<NodeId>>{StatusCode{ua::exception_to_status_code(std::current_exception())}});
    }
  }

  /// One breadth-first browse from the standard roots, collecting nodes belonging to any namespace
  /// that declined to enumerate itself.
  /// @return false when the operation has already answered with a failure.
  ua::async::Task<bool> traverse(const std::set<uint16_t>& needsTraversal, std::vector<NodeId>& workList)
  {
    std::deque<NodeId> frontier;
    std::set<NodeId> visited;
    for (auto& root : standard_roots())
    {
      if (visited.insert(root).second)
      {
        frontier.push_back(std::move(root));
      }
    }

    while (!frontier.empty())
    {
      // One node unit of the work budget per node visited. Exhaustion is a hard failure - never a
      // silent truncation: a pathological graph must surface a bounded error, not a partial export
      // that would re-import as a corrupt graph. NOTE: this fallback browses the WHOLE reachable
      // graph from the standard roots, so its cost scales with the total address-space size, not the
      // size of the target namespace. Enumerable namespaces avoid the traversal entirely.
      try
      {
        mBudget.consume_node();
      }
      catch (const UaException& exception)
      {
        finish(Result<std::vector<NodeId>>{StatusCode{Status::BadEncodingLimitsExceeded},
          ErrorDetail::build("ExportTraversalBudgetExceeded",
            "NodeSet export browse-traversal exceeded its work budget",
            "ExportEngine")
            .context(ua::ContextKeys::sizeActual, std::to_string(mBudget.nodes_used()))
            .cause(exception.status_code())});
        co_return false;
      }

      NodeId nodeId = std::move(frontier.front());
      frontier.pop_front();

      auto addressSpace = lock_address_space();
      if (!addressSpace)
      {
        co_return false;
      }
      auto found = co_await find_node(*addressSpace, nodeId);
      if (found.is_uncertain())
      {
        // An Uncertain lookup is not acted on, and skipping it would silently drop the Node and every
        // Node reached only through it, so it is refused.
        finish(Result<std::vector<NodeId>>{
          ::ua::detail::lookup_failure(nodeId, found.status_code(), "ExportEngine")});
        co_return false;
      }
      if (!found.is_good())
      {
        // A reachable id that cannot be resolved is not fatal: the standard roots (and dangling
        // targets) may not exist in a partial graph. Skip it and continue the walk.
        continue;
      }

      if (needsTraversal.count(nodeId.namespace_index()) != 0)
      {
        workList.push_back(std::move(nodeId));
      }

      auto accessor = found.value();
      auto references = co_await get_references(accessor);
      if (!references.is_good())
      {
        // Failure to read a node's references aborts discovery: the traversal cannot be trusted to
        // be complete, and a partial work-list would silently drop nodes. An Uncertain answer is not
        // acted on, so it is refused.
        finish(Result<std::vector<NodeId>>{
          ::ua::detail::references_failure(references.status_code(), "ExportEngine")});
        co_return false;
      }

      for (const auto& reference : references.value())
      {
        // Both forward AND inverse references are followed: encoding objects are reachable only via
        // the inverse HasEncoding from their DataType. Remote targets cannot be browsed locally.
        const ExpandedNodeId& target = reference.target_id();
        if (target.is_remote())
        {
          continue;
        }
        NodeId targetId = target.node_id();
        if (visited.insert(targetId).second)
        {
          frontier.push_back(std::move(targetId));
        }
      }
    }
    co_return true;
  }

  /// Locks the address space, or answers BadShutdown and returns nullopt.
  std::optional<AddressSpace> lock_address_space()
  {
    auto locked = mAddressSpace.lock();
    if (!locked)
    {
      finish(Result<std::vector<NodeId>>{StatusCode{Status::BadShutdown}});
      return std::nullopt;
    }
    return locked;
  }

  /// A node can appear from both enumerate and traversal, or be shared across enumerable
  /// namespaces. Order is unspecified, so a set-backed dedup is fine.
  static Result<std::vector<NodeId>> deduplicate(std::vector<NodeId> workList)
  {
    std::vector<NodeId> deduped;
    deduped.reserve(workList.size());
    std::unordered_set<NodeId> seen;
    seen.reserve(workList.size());
    for (auto& id : workList)
    {
      if (seen.insert(id).second)
      {
        deduped.push_back(std::move(id));
      }
    }
    return Result<std::vector<NodeId>>{std::move(deduped)};
  }

  void fail_to_start(StatusCode status)
  {
    finish(Result<std::vector<NodeId>>{status, status.shared_detail()});
  }

  /// Fires once: a body that failed a step and then unwound must not answer twice.
  void finish(Result<std::vector<NodeId>> result)
  {
    if (auto completion = std::exchange(mCompletion, nullptr))
    {
      completion(std::move(result));
    }
  }

  WeakAddressSpace mAddressSpace;
  WorkBudget mBudget;
  std::vector<uint16_t> mTargetNamespaceIndices;
  DiscoverCompletion mCompletion;
};

/// Exports a NodeSet2 document: discovery, then a read pass over every discovered node, then an
/// optional alias-resolution pass, then serialisation.
///
/// Which failures are fatal differs per step and is carried over unchanged. A node that no longer
/// resolves, or whose attributes cannot be read, is skipped; a lookup answered Uncertain is FATAL, refused
/// with `Bad_InternalError` (`LookupAnswerUncertain`), since the SDK does not act on it and a skip would
/// drop a Node the namespace holds. A node's references failing to read is
/// FATAL, because references define the graph and a silently truncated set would re-import as a
/// corrupt one. A node's Value failing to read is not - the node still exports its attributes and
/// references. An id that will not resolve during alias resolution is simply not aliased.
class ExportEngine::ExportOperation final : public ua::async::SelfOwningOperation<ExportOperation>
{
public:
  static void start(WeakAddressSpace weakAddressSpace, EncodingLimits limits, ExportSettings settings,
    shared_ptr<Stream> out, ExportCompletion completion)
  {
    auto locked = weakAddressSpace.lock();
    if (!locked)
    {
      completion(Result<ExportSummary>{StatusCode{Status::BadShutdown}});
      return;
    }
    launch(std::make_shared<ExportOperation>(boost::asio::make_strand(locked->executor()),
      locked->logger(),
      std::move(weakAddressSpace),
      limits,
      std::move(settings),
      std::move(out),
      std::move(completion)));
  }

  ExportOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    WeakAddressSpace weakAddressSpace, EncodingLimits limits, ExportSettings settings, shared_ptr<Stream> out,
    ExportCompletion completion)
    : ua::async::SelfOwningOperation<ExportOperation>(std::move(strand), std::move(logger)),
      mAddressSpace(std::move(weakAddressSpace)), mLimits(limits), mSettings(std::move(settings)),
      mOut(std::move(out)), mCompletion(std::move(completion))
  {}

private:
  friend class ua::async::SelfOwningOperation<ExportOperation>;

  auto discover()
  {
    return await_step<Result<std::vector<NodeId>>>(
      [this](auto completion) mutable
      {
        DiscoverOperation::start(
          mAddressSpace, mLimits.work_budget(), mSettings.targetNamespaceIndices, std::move(completion));
      });
  }

  auto find_node(AddressSpace& addressSpace, NodeId nodeId)
  {
    return await_step<NodeAccessorResult>([&addressSpace, nodeId = std::move(nodeId)](auto completion) mutable
      { addressSpace.find_node_async(nodeId, std::move(completion)); });
  }

  auto get_references(NodeAccessor& node)
  {
    return await_step<Result<References>>(
      [&node](auto completion) mutable { node.get_references_async(std::move(completion)); });
  }

  auto read_value(VariableAccessor& variable, ReadValueId readValueId)
  {
    return await_step<DataValueResult>(
      [&variable, readValueId = std::move(readValueId)](auto completion) mutable
      {
        // NodeSet export writes a document, not a Session's view: no identity applies.
        variable.read_value_async(
          Duration{}, /*setSourceTimestamp=*/false, readValueId, nullptr, std::move(completion));
      });
  }

  ua::async::Task<> run()
  {
    try
    {
      if (!mOut)
      {
        finish(Result<ExportSummary>{StatusCode{Status::BadInvalidArgument},
          ErrorDetail::build(
            "ExportNoStream", "export_async called with a null output stream", "ExportEngine")});
        co_return;
      }

      auto discovered = co_await discover();
      if (!discovered.is_good())
      {
        finish(Result<ExportSummary>{discovered.status_code()});
        co_return;
      }
      auto workList = std::move(discovered).value();

      for (const auto& nodeId : workList)
      {
        if (!co_await read_one_node(nodeId))
        {
          co_return;  // already answered
        }
      }

      if (mSettings.emitAliases && !co_await resolve_aliases())
      {
        co_return;
      }

      build_and_write();
    }
    catch (const ua::async::Abandoned&)
    {
      finish(Result<ExportSummary>{StatusCode{Status::BadOperationAbandoned}});
    }
    catch (...)
    {
      finish(Result<ExportSummary>{StatusCode{ua::exception_to_status_code(std::current_exception())}});
    }
  }

  /// @return false when the operation has already answered with a failure.
  ua::async::Task<bool> read_one_node(const NodeId& nodeId)
  {
    auto addressSpace = lock_address_space();
    if (!addressSpace)
    {
      co_return false;
    }

    auto found = co_await find_node(*addressSpace, nodeId);
    if (found.is_uncertain())
    {
      // An Uncertain lookup is not acted on, and skipping it would silently drop a Node the namespace
      // holds, so it is refused.
      finish(
        Result<ExportSummary>{::ua::detail::lookup_failure(nodeId, found.status_code(), "ExportEngine")});
      co_return false;
    }
    if (!found.is_good())
    {
      co_return true;  // a discovered id that no longer resolves is skipped, not fatal
    }
    auto accessor = found.value();

    ExportedNode node;
    try
    {
      node = read_node_attributes(accessor);
      // A VariableType's default Value is read synchronously above; reify an opaque body now so it
      // can be serialised. (reify_value is pure - no operation state, no address-space access.)
      if (optional<Variant>& nodeValue = node.value)
      {
        nodeValue = reify_value(*nodeValue, mSettings.structureResolver, mLimits);
      }
    }
    catch (const std::exception&)
    {
      co_return true;  // a node whose attributes cannot be read is skipped, not fatal
    }

    // Apply scope + the node filter as early as possible (the identity/browse attributes the
    // predicate inspects are now read), so a rejected node skips the more expensive reference and
    // value reads. A rejected node is omitted entirely - it neither emits references nor contributes
    // to the namespace table.
    const bool inScope = mSettings.scope == ExportScope::Full || is_type_definition(node);
    if (!inScope || (mSettings.nodeFilter && !mSettings.nodeFilter(node)))
    {
      co_return true;
    }

    auto references = co_await get_references(accessor);
    if (!references.is_good())
    {
      // FATAL, unlike a node's value: a node's references define the graph, so exporting it with a
      // silently truncated reference set would re-import as a corrupt graph. An Uncertain answer is
      // not acted on, so it is refused.
      finish(
        Result<ExportSummary>{::ua::detail::references_failure(references.status_code(), "ExportEngine")});
      co_return false;
    }
    for (const auto& reference : references.value())
    {
      ExportedReference exported;
      exported.referenceTypeId = reference.type_id();
      exported.targetId = reference.target_id();
      exported.isForward = reference.is_forward();
      if (mSettings.referenceFilter && !mSettings.referenceFilter(exported))
      {
        continue;
      }
      node.references.push_back(std::move(exported));
    }

    // A Variable INSTANCE's live value flows through the async read path; a VariableType's default
    // Value was already read (and reified) above, so only NodeClass::Variable reads here. A bare
    // variable completes with a null DataValue + Good status, leaving the value unset (no `<Value>`).
    if (node.nodeClass == NodeClass::Variable)
    {
      if (auto variable = accessor.as<VariableAccessor>())
      {
        ReadValueId readValueId;
        readValueId.node_id() = node.nodeId;
        readValueId.attribute_id() = utils::to_underlying(AttributeId::Value);
        auto value = co_await read_value(*variable, std::move(readValueId));
        // Non-fatal: the node still exports its attributes and references.
        if (value.is_good() && !value.value().value().empty())
        {
          node.value = reify_value(value.value().value(), mSettings.structureResolver, mLimits);
        }
      }
    }

    collect_namespaces(node, mLimits, mReferencedNamespaces);
    mNodes.push_back(std::move(node));
    co_return true;
  }

  /// Resolves the browse name of each reference/data type id the exported nodes use, so the writer
  /// can emit an `<Aliases>` table and substitute symbolic names.
  /// @return false when the operation has already answered with a failure.
  ua::async::Task<bool> resolve_aliases()
  {
    for (const auto& candidateId : gather_alias_candidates(mNodes))
    {
      auto addressSpace = lock_address_space();
      if (!addressSpace)
      {
        co_return false;
      }
      auto found = co_await find_node(*addressSpace, candidateId);
      // Non-fatal: the id may be absent from a bare address space (an NS0 type, typically), so it
      // is simply not aliased and its raw id is emitted instead. Aliases are an output convenience,
      // never a correctness requirement of the document.
      if (!found.is_good())
      {
        continue;
      }
      try
      {
        const QualifiedName browseName = found.value().get_browse_name();
        const string_view name = static_cast<string_view>(browseName.name());
        if (!name.empty())
        {
          mResolvedAliases.emplace_back(candidateId, String{name});
        }
      }
      catch (const std::exception&)
      {
        // Browse name unreadable - leave this id un-aliased.
        ua::detail::ignore_expected_exception();
      }
    }
    co_return true;
  }

  std::optional<AddressSpace> lock_address_space()
  {
    auto locked = mAddressSpace.lock();
    if (!locked)
    {
      finish(Result<ExportSummary>{StatusCode{Status::BadShutdown}});
      return std::nullopt;
    }
    return locked;
  }

  void fail_to_start(StatusCode status)
  {
    finish(Result<ExportSummary>{status, status.shared_detail()});
  }

  /// Fires once: a body that failed a step and then unwound must not answer twice.
  void finish(Result<ExportSummary> result)
  {
    if (auto completion = std::exchange(mCompletion, nullptr))
    {
      completion(std::move(result));
    }
  }

  void build_and_write();

  WeakAddressSpace mAddressSpace;
  EncodingLimits mLimits;
  ExportSettings mSettings;
  shared_ptr<Stream> mOut;
  ExportCompletion mCompletion;

  std::vector<ExportedNode> mNodes;
  std::set<uint16_t> mReferencedNamespaces;
  std::vector<std::pair<NodeId, String>> mResolvedAliases;
};

void ExportEngine::ExportOperation::build_and_write()
{
  auto locked = mAddressSpace.lock();
  if (!locked)
  {
    finish(Result<ExportSummary>{StatusCode{Status::BadShutdown}});
    return;
  }
  AddressSpace addressSpace = std::move(*locked);

  ExportSummary summary;
  try
  {
    // Build the server->file namespace map: file index 0 == NS0 (implicit); referenced non-zero
    // server indices take file indices 1..k in ascending order. Shared (shared_ptr) so the same map
    // backs both the envelope index function and the `<Value>` embedded-id translators.
    auto serverToFile = make_shared<std::unordered_map<uint16_t, uint16_t>>();
    serverToFile->emplace(uint16_t{0}, uint16_t{0});
    std::vector<String> namespaceUris;
    uint16_t nextFileIndex = 1;
    for (const uint16_t serverIndex : mReferencedNamespaces)
    {
      if (serverIndex == 0)
      {
        continue;
      }
      serverToFile->emplace(serverIndex, nextFileIndex);
      String uri = addressSpace.namespace_array().get_namespace_uri(serverIndex);
      summary.namespacesWritten.push_back(NamespaceMapping{uri, nextFileIndex});
      namespaceUris.push_back(std::move(uri));
      ++nextFileIndex;
    }

    auto toFileIndex = [serverToFile](uint16_t serverIndex) -> uint16_t
    {
      const auto entry = serverToFile->find(serverIndex);
      return entry != serverToFile->end() ? entry->second : uint16_t{0};
    };

    NodeSetWriterOptions options;
    options.namespaceUris = std::move(namespaceUris);
    options.models = std::move(mSettings.models);
    options.lastModified = mSettings.lastModified;
    options.aliases = finalize_aliases(mResolvedAliases);
    options.serverToFileIndex = toFileIndex;
    options.failOnUnencodableStructure = mSettings.failOnUnencodableStructure;
    // Translate ids embedded inside a `<Value>` from server to file indices (server->file), so a
    // NodeId / QualifiedName / ExpandedNodeId carried in a value re-imports to the correct namespace.
    options.valueContext = CodecNamespaceContext::with_translators([toFileIndex](NodeId& id)
      { id.namespace_index() = toFileIndex(id.namespace_index()); },
      [toFileIndex](QualifiedName& name) { name.namespace_index() = toFileIndex(name.namespace_index()); },
      [toFileIndex](ExpandedNodeId& id)
      {
        if (!id.is_remote())
        {
          id.node_id().namespace_index() = toFileIndex(id.node_id().namespace_index());
        }
      });

    // Serialise directly into the caller-provided stream - no intermediate document buffer.
    NodeSetWriter writer(*mOut, mLimits, std::move(options));
    writer.begin_document();
    for (const auto& node : mNodes)
    {
      writer.write_node(node);
      summary.referencesExported += node.references.size();
    }
    writer.end_document();
    summary.nodesExported = mNodes.size();
  }
  catch (const std::exception& exception)
  {
    // Preserve the underlying cause (a thrown UaException's status + detail, e.g. a dangling target
    // namespace from get_namespace_uri, or an XmlEncoder failure) rather than flattening it.
    const StatusCode cause = ua::exception_to_status_code(std::current_exception());
    finish(Result<ExportSummary>{StatusCode{Status::BadEncodingError},
      ErrorDetail::build("ExportSerializationFailed", "NodeSet export serialization failed", "ExportEngine")
        .context(ua::ContextKeys::errorMessage, exception.what())
        .cause(cause)});
    return;
  }

  finish(Result<ExportSummary>{std::move(summary)});
}

// =================================================================================================
// Async discovery entry point.
// =================================================================================================

void ExportEngine::discover_async(std::vector<uint16_t> targetNamespaceIndices, DiscoverCompletion completion)
{
  DiscoverOperation::start(
    mAddressSpace, mLimits.work_budget(), std::move(targetNamespaceIndices), std::move(completion));
}

void ExportEngine::export_async(ExportSettings settings, shared_ptr<Stream> out, ExportCompletion completion)
{
  ExportOperation::start(mAddressSpace, mLimits, std::move(settings), std::move(out), std::move(completion));
}

Result<ExportEngine::ExportOutcome> ExportEngine::try_export_sync(ExportSettings settings)
{
  // Buffer convenience: serialise into an internal MemoryStream, then materialise its bytes. The
  // device + stream are held alive for the whole blocking call. (Sync wraps async.)
  try
  {
    auto device = make_shared<memory_stream_device::Dynamic>();
    auto stream = make_shared<MemoryStream<memory_stream_device::Dynamic>>(*device);

    auto locked = mAddressSpace.lock();
    if (!locked)
    {
      return Result<ExportOutcome>{StatusCode{Status::BadShutdown}};
    }
    auto summaryResult = ua::async::detail::blocking_call<Result<ExportSummary>>(locked->executor(),
      [&](std::function<void(Result<ExportSummary>)> complete)
      { export_async(std::move(settings), stream, std::move(complete)); });
    if (!summaryResult.is_good())
    {
      return Result<ExportOutcome>{summaryResult.status_code()};
    }

    ExportOutcome outcome;
    const auto data = device->get_data();
    outcome.document.assign(reinterpret_cast<const char*>(data.data()), data.size());
    outcome.namespacesWritten = std::move(summaryResult.value().namespacesWritten);
    outcome.nodesExported = summaryResult.value().nodesExported;
    outcome.referencesExported = summaryResult.value().referencesExported;
    return Result<ExportOutcome>{std::move(outcome)};
  }
  catch (...)
  {
    return Result<ExportOutcome>{StatusCode{ua::exception_to_status_code(std::current_exception())}};
  }
}

}  // namespace ua::xml::nodeset
