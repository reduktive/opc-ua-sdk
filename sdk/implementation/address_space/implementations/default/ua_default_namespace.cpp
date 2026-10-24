// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_namespace.h"
#include "ua_namespace_batch_support.h"
#include "ua_node_accessor.h"
#include "ua_node_utilities.h"
#include "ua_numeric_range_parser.h"
#include "ua_reference_type_model.h"
#include "ua_write_value.h"
#include "ua_reference_identity.h"
#include "ua_access_level_ex_type.h"
#include "ua_callback_safety.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_access_level_type.h"
#include "ua_error_detail.h"
#include "ua_to_string.h"

#include <algorithm>
#include <chrono>
#include <boost/asio/post.hpp>
#include <boost/container/small_vector.hpp>
#include <fmt/format.h>
#include <deque>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <ranges>
#include <utility>
#include "ua_default_base_node.h"
#include "ua_namespace_context_state.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_namespace_monitoring_support_access.h"
#include "ua_namespace_route.h"
#include "ua_node.h"
#include "ua_on_strand.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_add_references_item.h"
#include "ua_add_nodes_result.h"
#include "ua_default_data_type_node.h"
#include "ua_default_object_node.h"
#include "ua_default_object_type_node.h"
#include "ua_default_reference_type_node.h"
#include "ua_default_variable_node.h"
#include "ua_default_variable_type_node.h"
#include "ua_default_view_node.h"
#include "ua_default_method_node.h"
#include "ua_error_detail.h"
#include "ua_event_notifier_type.h"
#include "ua_sampling_engine.h"
#include "ua_to_result.h"
#include "ua_write_value.h"

namespace ua::default_ns
{

NodeDescription Namespace::creation_description(
  const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& given)
{
  // The description's factory defaults cover every other mandatory Attribute; a Variable is also writable
  // here unless its creation says otherwise.
  InitialAttributes attributes;
  attributes.reserve(given.size() + 1);
  if (nodeClass == NodeClass::Variable)
  {
    attributes.emplace_back(AttributeId::AccessLevel,
      Variant{AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite}
                .as_underlying_type()});
  }
  attributes.insert(attributes.end(), given.begin(), given.end());
  auto built = NodeDescription::try_from_attributes(nodeId, nodeClass, attributes);
  if (!built.is_good())
  {
    throw UaException{built.status_code()};
  }
  return built.value();
}

String Namespace::uri() const
{
  return mUri;
}

void Namespace::shutdown_async(std::function<void(VoidResult)> callback) noexcept
{
  // Nothing of this namespace runs in the background: its monitored items are sampled by the
  // registration's helper, which the address space shuts down before it calls this (NR-47 rule 7).
  if (callback)
  {
    detail::invoke_user_callback(std::move(callback), VoidResult{});
  }
}

void Namespace::find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
  std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete)
{
  // The store is local, so there is no round trip to collapse: the batch is the local lookup run once per id,
  // in order. Through the AddressSpace this is entered only for a subclass that declines the immediate form
  // to model a remote store, which is why this calls `resolve_here` and not the virtual `find_node`: that
  // subclass's own decline would otherwise be dereferenced here, by its own base class.
  (void)request;
  (void)maxAge;
  BatchResult<NodeResult> result;
  result.items.reserve(nodeIds.size());
  for (const auto& nodeId : nodeIds)
  {
    result.items.push_back(resolve_here(nodeId));
  }
  complete(std::move(result));
}

std::optional<NodeResult> Namespace::find_node(const NodeId& nodeId, std::optional<Duration> maxAge)
{
  // Always engaged: the whole store is in memory, so there is nothing to go away for.
  (void)maxAge;
  return resolve_here(nodeId);
}

NodeResult Namespace::resolve_here(const NodeId& nodeId)
{
  shared_ptr<BaseNode> node;
  {
    const ReadLock lock(mMutex);
    node = find_node_internal(nodeId);
  }

  // Built outside the lock, and returned rather than delivered: this answers on the caller's thread,
  // which may be driving a loop over many ids, and a user continuation running under mMutex would
  // deadlock the moment it re-entered the namespace.
  if (node)
  {
    return NodeResult{shared_ptr<Node>{std::move(node)}};
  }

  // Engaged, and bad. "This namespace has no such node" is a real answer, not a decline - see the
  // contract on ua::Namespace::find_node.
  return NodeResult{StatusCode{Status::BadNodeIdUnknown},
    std::shared_ptr<const ErrorDetail>(
      ErrorDetail::build("NodeNotFound", "Node does not exist in namespace", "DefaultNamespace")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))
        .context(ua::ContextKeys::namespaceUri, std::string{std::string_view{mUri}}))};
}

void Namespace::enumerate_nodes_async(
  const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> callback)
{
  (void)request;
  // Snapshot the owned nodes under the read lock, then resolve each id and fire the callback
  // OUTSIDE the lock (never invoke a user-provided callback while holding a
  // mutex). The callback may re-enter the namespace and would otherwise deadlock on mMutex.
  std::vector<shared_ptr<BaseNode>> nodes;
  {
    const ReadLock lock(mMutex);
    nodes.reserve(mNodes.size());
    for (const auto& entry : mNodes)
    {
      nodes.push_back(entry.second);
    }
  }

  std::vector<NodeId> ids;
  ids.reserve(nodes.size());
  for (const auto& node : nodes)
  {
    ids.push_back(node->node_id());
  }

  callback(Result<std::vector<NodeId>>{std::move(ids)});
}

Namespace::Namespace(string_view uri, boost::asio::any_io_executor executor) : mUri(uri)
{
  // The address space's executor runs this namespace's work once it is attached; nothing is kept from here.
  UA_UNUSED(executor);
  // A namespace that is never configured still has defaults - engaged and empty Role permissions,
  // which is 5.2.9's "the Role model applies and grants nothing", as distinct from the `nullopt` that
  // declares a vendor model. Published here so that every read of mDefaults, from construction
  // onwards, names a live snapshot and no reader has to test for null.
  auto initial = std::make_unique<const Defaults>();
  const Defaults* published = initial.get();
  mPublishedDefaults.push_back(std::move(initial));
  mDefaults.store(published, std::memory_order_release);
  mLink->owner = this;
}

Namespace::~Namespace()
{
  // A Node that outlives this namespace reaches nothing through its link from here on; a Node inside a call
  // through it holds the shared lock, which this waits for.
  const std::unique_lock lock{mLink->mutex};
  mLink->owner = nullptr;
}

shared_ptr<Namespace> Namespace::create(string_view uri, boost::asio::any_io_executor executor)
{
  struct Wrapper : public Namespace
  {
  public:
    Wrapper(string_view uri, boost::asio::any_io_executor executor) : Namespace(uri, std::move(executor))
    {}
  };

  return make_shared<Wrapper>(uri, std::move(executor));
}

shared_ptr<BaseNode> Namespace::find_node_internal(const ua::NodeId& nodeId)
{
  shared_ptr<BaseNode> node;

  if (nodeId.namespace_index() == context().index())
  {
    auto result = mNodes.find(nodeId.identifier());
    if (result != mNodes.end())
    {
      node = result->second;
    }
  }

  return node;
}

void Namespace::configure_node(const shared_ptr<BaseNode>& node)
{
  node->mOwner = this;
  node->mMayHoldVersions = mMayHoldVersions;
  node->mNamespaceLink = mLink;
  if (BaseNode::is_version_name(node->mDescription.browse_name()))
  {
    mMayHoldVersions->store(true, std::memory_order_release);
  }
}

void Namespace::advance_model_generation() const noexcept
{
  context().model_changed({});
}

ua::Logger Namespace::version_logger() const
{
  return detail::NamespaceContextAccess::logger(context()).with_category("reference-mutations");
}

ua::Logger Namespace::logger_of(NamespaceLink& link) noexcept
{
  try
  {
    const std::shared_lock lock{link.mutex};
    if (link.owner != nullptr)
    {
      return detail::NamespaceContextAccess::logger(link.owner->context());
    }
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
  return ua::Logger{};
}

VoidResult Namespace::change_own_references(NamespaceLink& link, const shared_ptr<BaseNode>& holder,
  std::vector<Reference> references, bool add, bool reportMissing)
{
  const std::shared_lock linkLock{link.mutex};
  if (link.owner == nullptr)
  {
    return VoidResult{Status::BadInvalidState,
      ErrorDetail::build(
        "NamespaceUnavailable", "The namespace that created this Node is gone", "DefaultNamespace")
        .context(ContextKeys::nodeId, holder->mNodeId)};
  }
  Namespace& owner = *link.owner;
  BaseNode::ReferencesOutcome outcome;
  {
    // Held while the References change, so that a delete of the Node cannot run between the check and the
    // change.
    const ReadLock lock{owner.mMutex};
    const auto held = owner.mNodes.find(holder->mNodeId.identifier());
    if (held == owner.mNodes.end() || held->second != holder)
    {
      return VoidResult{Status::BadNodeIdUnknown,
        ErrorDetail::build("NodeNotFound", "This namespace no longer holds the Node", "DefaultNamespace")
          .context(ContextKeys::nodeId, holder->mNodeId)};
    }
    // No event-graph check here, and none on any Reference change: Part 3 7.17 is checked by
    // `AddressSpace::validate_event_graph_async`, which the server's implementer calls once the model is
    // built.
    outcome = holder->change_references(references, add, reportMissing);
  }
  if (outcome.changed)
  {
    owner.advance_model_generation();
  }
  return std::move(outcome.result);
}

NodeResult Namespace::create_with_attributes(
  const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& initialAttributes) noexcept
{
  try
  {
    // The Node is built with all its Attributes before it is added, under the namespace's lock, so no lookup
    // finds it without them; a refused Attribute creates nothing (as a failed AddNodesItem).
    const WriteLock lock(mMutex);
    return NodeResult{create_node_internal(nodeId, nodeClass, initialAttributes)};
  }
  catch (...)
  {
    return NodeResult{ua::exception_to_status_code(std::current_exception())};
  }
}

shared_ptr<Node> Namespace::create_node(const NodeId& nodeId, NodeClass nodeClass)
{
  const WriteLock lock(mMutex);
  return create_node_internal(nodeId, nodeClass);
}

shared_ptr<Node> Namespace::create_node_internal(
  const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& initialAttributes)
{
  shared_ptr<Node> node;

  switch (nodeClass)
  {
  case NodeClass::DataType:
    node = create_node_internal<DataTypeNode>(nodeId, initialAttributes);
    break;

  case NodeClass::Method:
    node = create_node_internal<MethodNode>(nodeId, initialAttributes);
    break;

  case NodeClass::Object:
    node = create_node_internal<ObjectNode>(nodeId, initialAttributes);
    break;

  case NodeClass::ObjectType:
    node = create_node_internal<ObjectTypeNode>(nodeId, initialAttributes);
    break;

  case NodeClass::ReferenceType:
    node = create_node_internal<ReferenceTypeNode>(nodeId, initialAttributes);
    break;

  case NodeClass::Variable:
    node = create_node_internal<VariableNode>(nodeId, initialAttributes);
    break;

  case NodeClass::VariableType:
    node = create_node_internal<VariableTypeNode>(nodeId, initialAttributes);
    break;

  case NodeClass::View:
    node = create_node_internal<ViewNode>(nodeId, initialAttributes);
    break;

  case NodeClass::Unspecified:
  default:
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidNodeClass", "Cannot create node with Unspecified node class", "DefaultNamespace")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    break;
  }

  return node;
}

DeleteNodeResult Namespace::delete_node(const NodeId& nodeId, bool deleteForwardHierarchicalRefs)
{
  std::optional<DeleteNodeResult> result;
  std::vector<shared_ptr<ViewNode>> views;

  // SVR-MI-GEN-090: the Node is marked deleted here, and each item monitoring it receives
  // Bad_NodeIdUnknown at its next tick, from the registration's helper (DL-68 (6)).
  {
    const WriteLock lock(mMutex);
    std::unordered_set<NodeId> deleted;
    result = delete_node_internal(nodeId, deleteForwardHierarchicalRefs, deleted);
    remove_references_to_locked(deleted);
    if (result->is_good())
    {
      views = remove_from_views_locked(nodeId);
    }
  }

  // A synchronous delete cannot await the ViewVersion advance; it is posted, and a failure is logged.
  advance_view_versions(view_versions_of(views), nullptr);
  return std::move(*result);
}

std::vector<shared_ptr<ViewNode>> Namespace::remove_from_views_locked(const NodeId& deleted)
{
  std::vector<shared_ptr<ViewNode>> changed;
  std::erase_if(mViews,
    [&deleted, &changed](const std::weak_ptr<ViewNode>& entry)
    {
      auto view = entry.lock();
      // The stored id, not node_id(): the View being deleted is already marked deleted, and node_id() refuses a
      // deleted node.
      if (!view || view->deleted() || static_cast<const BaseNode&>(*view).mNodeId == deleted)
      {
        return true;
      }
      if (view->remove_member(deleted))
      {
        changed.push_back(std::move(view));
      }
      return false;
    });
  return changed;
}

Namespace::ViewVersions Namespace::view_versions_of(const std::vector<shared_ptr<ViewNode>>& views)
{
  ViewVersions found;
  if (views.empty())
  {
    return found;
  }
  found.logger = version_logger();
  for (const auto& view : views)
  {
    try
    {
      if (auto property = version_property(*view, /*view=*/true))
      {
        found.properties.emplace_back(view->mutation_snapshot().nodeId, std::move(property));
      }
    }
    catch (...)
    {
      detail::ignore_expected_exception();
    }
  }
  return found;
}

void Namespace::advance_view_versions(ViewVersions views, std::function<void()> done)
{
  // One more than the Views: the loop holds one, so that inline answers do not finish early.
  auto outstanding = std::make_shared<std::atomic<size_t>>(views.properties.size() + 1);
  auto oneAdvanced = [outstanding, done = std::move(done)]()
  {
    if (outstanding->fetch_sub(1, std::memory_order_acq_rel) == 1 && done)
    {
      done();
    }
  };
  for (auto& [viewId, property] : views.properties)
  {
    // Part 3 Table 10: the ViewVersion is updated when Nodes are removed from a View. A failure does not fail
    // the delete, whose Node is gone; it is logged.
    advance_version(nullptr,
      std::move(property),
      /*view=*/true,
      [logger = views.logger, viewId, oneAdvanced](VoidResult advanced)
      {
        if (advanced.is_bad())
        {
          try
          {
            logger.with_category("address_space")
              .warning({{"view", to_string(viewId)}, {"status", to_string(advanced.status_code())}},
                "A View lost a member and its ViewVersion could not advance");
          }
          catch (...)
          {
            detail::ignore_expected_exception();
          }
        }
        oneAdvanced();
      });
  }
  oneAdvanced();
}

DeleteNodeResult Namespace::delete_node_internal(
  const NodeId& nodeId, bool removeReferencesToIt, std::unordered_set<NodeId>& deleted)
{
  auto node = find_node_internal(nodeId);
  if (!node)
  {
    return DeleteNodeResult{StatusCode{Status::BadNodeIdUnknown},
      std::shared_ptr<const ErrorDetail>(
        ErrorDetail::build("NodeNotFound", "Node does not exist in namespace", "DefaultNamespace")
          .context(ua::ContextKeys::nodeId, nodeId)
          .context(ua::ContextKeys::namespaceUri, std::string{std::string_view{mUri}}))};
  }
  std::vector<ExternalReference> externalReferences;
  if (removeReferencesToIt)
  {
    base_node_details::SharedReferences held;
    {
      const ReadLock lock{node->mMutex};
      held = node->mReferences;
    }
    for (const auto& reference : *held)
    {
      // The other half of a Reference to a Node of another namespace is that namespace's: the address space
      // removes it there.
      const auto& targetId = reference.target_id();
      if (targetId.is_local() && targetId.is_index_based() &&
          targetId.node_id().namespace_index() != nodeId.namespace_index())
      {
        externalReferences.push_back(
          ExternalReference{reference.type_id(), targetId, reference.is_forward()});
      }
    }
    deleted.insert(nodeId);
  }
  node->mark_as_deleted();
  mNodes.erase(nodeId.identifier());
  return DeleteNodeResult{std::move(externalReferences)};
}

std::vector<shared_ptr<BaseNode>> Namespace::remove_references_to_locked(
  const std::unordered_set<NodeId>& deleted)
{
  std::vector<shared_ptr<BaseNode>> changed;
  if (deleted.empty())
  {
    return changed;
  }
  for (const auto& [identifier, node] : mNodes)
  {
    (void)identifier;
    if (node->remove_references_to(deleted))
    {
      changed.push_back(node);
    }
  }
  return changed;
}

namespace
{

// The NodeId of @p node's TypeDefinition when it is an Object or Variable, otherwise null (OPC 10000-5 12.16,
// `affectedType`).
NodeId affected_type_of(const base_node_details::MutationSnapshot& node)
{
  if ((node.nodeClass != NodeClass::Object && node.nodeClass != NodeClass::Variable) || !node.references)
  {
    return NodeId{};
  }
  const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
  for (const auto& reference : *node.references)
  {
    if (reference.is_forward() && reference.type_id() == hasTypeDefinition &&
        reference.target_id().is_local())
    {
      return reference.target_id().node_id();
    }
  }
  return NodeId{};
}

// The answer of an item whose change was stored but whose Node's NodeVersion could not advance (DL-22 as
// reversed): the generic Uncertain, with why.
StatusCode version_not_advanced(const StatusCode& why)
{
  return StatusCode{Status::Uncertain, why.shared_detail()};
}

}  // namespace

shared_ptr<VariableNode> Namespace::version_property(const BaseNode& node, bool view, bool locked)
{
  if (!mMayHoldVersions->load(std::memory_order_acquire))
  {
    return nullptr;
  }
  const string_view name = view ? "ViewVersion" : "NodeVersion";
  const NodeId hasProperty{ReferenceTypeId::HasProperty};
  const NodeId hasModellingRule{ReferenceTypeId::HasModellingRule};
  const auto references = node.mutation_snapshot().references;
  if (!references)
  {
    return nullptr;
  }
  std::optional<ReadLock> lock;
  if (!locked)
  {
    lock.emplace(mMutex);
  }
  for (const auto& reference : *references)
  {
    if (!reference.is_forward() || reference.type_id() != hasProperty || !reference.target_id().is_local())
    {
      continue;
    }
    auto property =
      std::dynamic_pointer_cast<VariableNode>(find_node_internal(reference.target_id().node_id()));
    if (!property)
    {
      continue;
    }
    const QualifiedName browseName = property->browse_name();
    if (browseName.namespace_index() != 0 || static_cast<string_view>(browseName.name()) != name)
    {
      continue;
    }
    const auto propertyReferences = property->mutation_snapshot().references;
    if (propertyReferences && std::ranges::any_of(*propertyReferences,
                                [&hasModellingRule](const Reference& held)
                                { return held.is_forward() && held.type_id() == hasModellingRule; }))
    {
      continue;
    }
    return property;
  }
  return nullptr;
}

void Namespace::advance_version(shared_ptr<std::atomic<uint64_t>> counter, shared_ptr<VariableNode> property,
  bool view, std::function<void(VoidResult)> done)
{
  try
  {
    auto next = [counter = std::move(counter), view](const Variant& current) -> Result<Variant>
    {
      if (view)
      {
        const auto* held = current.try_as<uint32_t>();
        if (!current.empty() && held == nullptr)
        {
          return Result<Variant>{Status::BadTypeMismatch,
            ErrorDetail::build("ViewVersionTypeMismatch",
              "The ViewVersion Property does not contain a UInt32 value",
              "DefaultNamespace")};
        }
        // Part 3 Table 10: greater than 0, and changed.
        const uint32_t advanced = held == nullptr ? 1U : *held + 1U;
        return Variant{advanced == 0U ? uint32_t{1} : advanced};
      }
      const auto* held = current.try_as<String>();
      if (!current.empty() && held == nullptr)
      {
        return Result<Variant>{Status::BadTypeMismatch,
          ErrorDetail::build("NodeVersionTypeMismatch",
            "The changed Node's NodeVersion Property does not contain a String",
            "DefaultNamespace")};
      }
      std::string advanced = fmt::format("{}", counter->fetch_add(1, std::memory_order_relaxed) + 1);
      if (held != nullptr && static_cast<string_view>(*held) == advanced)
      {
        advanced = fmt::format("{}", counter->fetch_add(1, std::memory_order_relaxed) + 1);
      }
      return Variant{String{advanced}};
    };
    std::function<void(VoidResult)> answered = [property, done](VoidResult result)
    {
      done(std::move(result));
    };
    if (property->update_default_source_async(next, answered))
    {
      return;
    }
    // A Property whose Value an application source holds: read, then written through it.
    ReadValueId read;
    read.node_id() = property->node_id();
    read.attribute_id() = utils::to_underlying(AttributeId::Value);
    property->read_value(0.0,
      false,
      read,
      /*identity=*/nullptr,
      [property, read, next, answered = std::move(answered)](DataValueResult current) mutable
      {
        // The next version is computed from the Value read, so an Uncertain read is not acted on.
        if (!current.is_good())
        {
          answered(VoidResult{::ua::detail::read_failure(current.status_code(), "DefaultNamespace")});
          return;
        }
        auto advanced = next(current.value().value());
        if (!advanced.is_good())
        {
          answered(VoidResult{advanced.status_code(), advanced.shared_detail()});
          return;
        }
        WriteValue write;
        write.node_id() = read.node_id();
        write.attribute_id() = read.attribute_id();
        write.value().value() = std::move(advanced).value();
        property->write_value_async(write, nullptr, std::move(answered));
      });
  }
  catch (...)
  {
    detail::invoke_user_callback(
      std::move(done), VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void Namespace::advance_versions(
  std::vector<VersionedChange> changes, std::function<void(VersionsAdvanced)> done)
{
  struct Join
  {
    std::mutex mutex;
    VersionsAdvanced outcome;
    // One more than the advances started: the loop holds one, so that inline answers do not finish early.
    std::size_t remaining{1};
    std::function<void(VersionsAdvanced)> done;
  };

  auto join = std::make_shared<Join>();
  join->done = std::move(done);
  const auto finishOne = [join]()
  {
    {
      const std::lock_guard lock{join->mutex};
      if (--join->remaining != 0)
      {
        return;
      }
    }
    detail::invoke_user_callback(join->done, std::move(join->outcome));
  };
  for (auto& change : changes)
  {
    try
    {
      auto property = version_property(*change.node, /*view=*/false);
      if (!property)
      {
        continue;
      }
      const auto snapshot = change.node->mutation_snapshot();
      VersionedNode reported{snapshot.nodeId, affected_type_of(snapshot)};
      if (change.created)
      {
        const std::lock_guard lock{join->mutex};
        join->outcome.reported.push_back(std::move(reported));
        continue;
      }
      {
        const std::lock_guard lock{join->mutex};
        ++join->remaining;
      }
      advance_version(mNodeVersionCounter,
        std::move(property),
        /*view=*/false,
        [join, finishOne, reported = std::move(reported)](VoidResult advanced) mutable
        {
          {
            const std::lock_guard lock{join->mutex};
            if (advanced.is_bad())
            {
              join->outcome.refused.insert_or_assign(reported.node, advanced.status_code());
            }
            else
            {
              join->outcome.reported.push_back(std::move(reported));
            }
          }
          finishOne();
        });
    }
    catch (...)
    {
      detail::ignore_expected_exception();
    }
  }
  finishOne();
}

namespace
{

using Delivery = NamespaceMonitoringSupport::Delivery;
using MonitoringAccess = ua::detail::MonitoringSupportAccess;

/// How this namespace feeds an item, decided when the item is created or modified: an item on an attribute
/// other than the Value is told of each change. An item on the Value at interval 0 is told of each change
/// when the Node's MinimumSamplingInterval is 0, or is absent while no application source owns the Value:
/// the default source's Value changes only by a write, which is reported. An application source claims to
/// report every change through `notify_value_changed` only with an explicit 0 (OPC 10000-4 5.12.1.2,
/// exception-based; an absent value is read as unknown, a spec-silent choice). Every other Value item is
/// sampled, so a Value that differs per caller is read for each subscription's current caller (NR-49).
Delivery delivery_for(const Node* node, AttributeId attributeId, Duration samplingInterval)
{
  if (attributeId != AttributeId::Value)
  {
    return Delivery::Reported;
  }
  if (samplingInterval != 0 || node == nullptr)
  {
    return Delivery::Sampled;
  }
  std::optional<Duration> minimumSamplingInterval;
  bool applicationSource = false;
  try
  {
    minimumSamplingInterval = node->attributes().minimum_sampling_interval();
    if (!minimumSamplingInterval)
    {
      const auto* variable = dynamic_cast<const VariableNode*>(node);
      applicationSource = variable != nullptr && variable->application_source() != nullptr;
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
  if (minimumSamplingInterval)
  {
    return *minimumSamplingInterval == 0 ? Delivery::Reported : Delivery::Sampled;
  }
  return applicationSource ? Delivery::Sampled : Delivery::Reported;
}

/// The in-memory Node a registration's count is kept on, or null for a Node of another kind.
BaseNode* counted_node(const shared_ptr<Node>& node)
{
  return dynamic_cast<BaseNode*>(node.get());
}

}  // namespace

void Namespace::create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const MonitoringCreateItem> items,
  std::function<void(BatchResult<MonitoringCreateItemResult>)> callback)
{
  (void)request;
  (void)caller;
  // Resolve nodes under read lock. The Node found here replaces any the caller passed, which nothing here
  // checks is one of this namespace's own.
  std::vector<NamespaceMonitoringSupport::ResolvedMonitoringItem> resolved;
  resolved.reserve(items.size());

  {
    const ReadLock lock(mMutex);

    for (const auto& item : items)
    {
      NamespaceMonitoringSupport::ResolvedMonitoringItem resolvedItem;
      resolvedItem.item = item;
      resolvedItem.item.node = find_node_internal(item.nodeId);
      resolved.push_back(std::move(resolvedItem));
    }
  }

  // The rule is applied, and the Node's count raised for each Reported item, with no lock of this
  // namespace held. The count rises BEFORE the registration exists, so that every write committed once
  // the registration exists is reported to it; a write in between reaches the helper with nothing to
  // deliver.
  auto& helper = context().monitoring();
  const auto weakHelper = helper.weak_from_this();
  for (auto& item : resolved)
  {
    item.delivery = delivery_for(item.item.node.get(), item.item.attributeId, item.item.samplingInterval);
    auto* node = counted_node(item.item.node);
    if (node == nullptr)
    {
      continue;
    }
    if (item.delivery == Delivery::Reported)
    {
      node->raise_reported_registrations(weakHelper);
    }
    else if (item.item.attributeId == AttributeId::Value)
    {
      // Linked without counting, so that a change of the Variable's DataType reaches the helper and marks the
      // Value's registrations StructureChanged whatever their delivery (NR-68 item 10).
      node->link_monitoring_helper(weakHelper);
    }
  }

  auto createResults = helper.create_monitoring(resolved);

  BatchResult<MonitoringCreateItemResult> results;
  results.items.reserve(createResults.size());
  for (size_t i = 0; i < createResults.size(); ++i)
  {
    if (createResults[i].result.is_bad() && resolved[i].delivery == Delivery::Reported)
    {
      if (auto* node = counted_node(resolved[i].item.node))
      {
        node->lower_reported_registrations();
      }
    }
    results.items.push_back(std::move(createResults[i].result));
  }

  callback(std::move(results));
}

void Namespace::delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
  std::function<void(BatchResult<VoidResult>)> callback)
{
  (void)request;
  // The Node each registration was created on, asked before the registration goes, so that its count
  // is lowered on that Node object and never on a Node added again under the same NodeId.
  auto& helper = context().monitoring();
  std::vector<std::optional<MonitoringAccess::Registration>> registrations;
  registrations.reserve(handles.size());
  for (auto handle : handles)
  {
    registrations.push_back(MonitoringAccess::registration(helper, handle));
  }

  auto deleted = helper.delete_monitoring(handles);
  for (size_t i = 0; i < deleted.size() && i < registrations.size(); ++i)
  {
    const auto& registration = registrations[i];
    if (deleted[i].is_good() && registration && registration->delivery == Delivery::Reported)
    {
      if (auto* node = counted_node(registration->node))
      {
        node->lower_reported_registrations();
      }
    }
  }

  BatchResult<VoidResult> batch;
  batch.items.assign(std::make_move_iterator(deleted.begin()), std::make_move_iterator(deleted.end()));
  callback(std::move(batch));
}

void Namespace::set_namespace_defaults(std::optional<std::vector<RolePermissionType>> rolePermissions,
  std::optional<AccessRestrictionType> accessRestrictions)
{
  const WriteLock lock(mMutex);
  if (mNamespaceDefaultsConfigured)
  {
    throw UaException{Status::BadInvalidState,
      ErrorDetail::build("NamespaceDefaultsAlreadyConfigured",
        "The namespace access-control defaults have already been configured",
        "DefaultNamespace")
        .context(ua::ContextKeys::namespaceUri, std::string{std::string_view{mUri}})};
  }
  // Published as one immutable snapshot and retained, so readers need no lock. The write lock above
  // still serialises writers against each other and against the retention vector; it is the READ
  // side that no longer takes it.
  auto snapshot = std::make_unique<const Defaults>(Defaults{std::move(rolePermissions), accessRestrictions});
  const Defaults* published = snapshot.get();
  mPublishedDefaults.push_back(std::move(snapshot));
  // Release: everything written into the snapshot above happens-before any acquire load that sees
  // this pointer. Without it a reader could see the pointer while the vector it names is still being
  // filled.
  mDefaults.store(published, std::memory_order_release);
  mNamespaceDefaultsConfigured = true;
}

std::optional<std::vector<RolePermissionType>> Namespace::default_role_permissions() const
{
  // No lock: see mDefaults. Asked once per authorised operation, so this was a shared-lock
  // acquisition per operation on the namespace-wide mutex, writing its reader counter from every
  // core. The snapshot it names is immutable and is never freed while this namespace lives.
  return mDefaults.load(std::memory_order_acquire)->rolePermissions;
}

std::optional<AccessRestrictionType> Namespace::default_access_restrictions() const
{
  return mDefaults.load(std::memory_order_acquire)->accessRestrictions;
}

void Namespace::modify_monitoring_async(const RequestInfo& request,
  std::span<const MonitoringModifyItem> items,
  std::function<void(BatchResult<MonitoringModifyItemResult>)> callback)
{
  (void)request;
  // A modify is marked by the rule a create is (DL-68 (8)), on the Node the registration was created
  // on. The count is raised before a modify to Reported and lowered after a modify to Sampled, so a
  // write in between at worst reaches the helper with nothing to deliver. A write made while the
  // registration was Sampled, since its last sample, is not reported to it: the helper reads the Node
  // once at the registration's next tick after a modify from Sampled to Reported.
  auto& helper = context().monitoring();
  const auto weakHelper = helper.weak_from_this();
  std::vector<NamespaceMonitoringSupport::ResolvedMonitoringModifyItem> resolved;
  std::vector<std::optional<MonitoringAccess::Registration>> registrations;
  resolved.reserve(items.size());
  registrations.reserve(items.size());
  for (const auto& item : items)
  {
    auto registration = MonitoringAccess::registration(helper, item.handle);
    NamespaceMonitoringSupport::ResolvedMonitoringModifyItem modify;
    modify.item = item;
    if (registration)
    {
      modify.delivery =
        delivery_for(registration->node.get(), registration->attributeId, item.samplingInterval);
      if (registration->delivery == Delivery::Sampled && modify.delivery == Delivery::Reported)
      {
        if (auto* node = counted_node(registration->node))
        {
          node->raise_reported_registrations(weakHelper);
        }
      }
    }
    resolved.push_back(std::move(modify));
    registrations.push_back(std::move(registration));
  }

  auto modifyResults = helper.modify_monitoring(resolved);

  BatchResult<MonitoringModifyItemResult> results;
  results.items.reserve(modifyResults.size());
  for (size_t i = 0; i < modifyResults.size(); ++i)
  {
    const auto& registration = registrations[i];
    if (registration)
    {
      auto* node = counted_node(registration->node);
      const bool toReported =
        registration->delivery == Delivery::Sampled && resolved[i].delivery == Delivery::Reported;
      const bool toSampled =
        registration->delivery == Delivery::Reported && resolved[i].delivery == Delivery::Sampled;
      const bool good = modifyResults[i].result.is_good();
      if (node != nullptr && ((toReported && !good) || (toSampled && good)))
      {
        node->lower_reported_registrations();
      }
    }
    results.items.push_back(std::move(modifyResults[i].result));
  }

  callback(std::move(results));
}

// --- Batched members over this namespace's own Nodes (NR-70 C1) --------------------------------------------

namespace
{

using detail::batch::client_attribute_value;
using detail::batch::current_exception_status;
using detail::batch::failed_answer;
using detail::batch::join_items;
using detail::batch::merged_value_write;
using detail::batch::merges;
using detail::batch::narrowed;
using detail::batch::run_once;
using detail::batch::take_once;
using detail::batch::written_as_given;

// The page of @p held a query asks for: from the offset its token holds, at most @p maxReferences of them (0
// for all), with the token of the next page while References remain.
NodeReferences page_of(const References& held, uint32_t maxReferences, const ByteString& token)
{
  const uint64_t total = held.size();
  const uint64_t offset = std::min<uint64_t>(detail::decode_offset(token), total);
  const uint64_t end = maxReferences == 0 ? total : std::min<uint64_t>(offset + maxReferences, total);
  NodeReferences page;
  page.references = held.slice(static_cast<uint32_t>(offset), static_cast<uint32_t>(end - offset));
  page.resumeToken = end < total ? detail::encode_offset(static_cast<uint32_t>(end)) : ByteString{};
  return page;
}

// The References of @p held a query hinted with @p hint may want (NR-61): all of them for no hint, and none
// whose type reference_type_may_match_hint rules out.
References hinted(References held, std::span<const NodeId> hint)
{
  if (hint.empty())
  {
    return held;
  }
  std::vector<Reference> kept;
  kept.reserve(held.size());
  for (const Reference& reference : held)
  {
    if (reference_type_may_match_hint(reference.type_id(), hint))
    {
      kept.push_back(reference);
    }
  }
  if (kept.size() == held.size())
  {
    return held;
  }
  return References{std::move(kept)};
}

// Whether the namespace-0 DataType @p dataType can hold a String or a ByteString: BaseDataType, String,
// ByteString and their subtypes in namespace 0 (OPC 10000-5, the 1.05 NodeSet). Every other namespace-0
// DataType, an Enumeration, a Structure, Counter or any other subtype of a number included, cannot.
bool may_hold_string_or_byte_string(uint32_t dataType)
{
  switch (static_cast<DataTypeId>(dataType))
  {
  case DataTypeId::BaseDataType:
  case DataTypeId::String:
  case DataTypeId::NumericRange:
  case DataTypeId::LocaleId:
  case DataTypeId::NormalizedString:
  case DataTypeId::DecimalString:
  case DataTypeId::DurationString:
  case DataTypeId::TimeString:
  case DataTypeId::DateString:
  case DataTypeId::UriString:
  case DataTypeId::SemanticVersionString:
  case DataTypeId::EncodedTicket:
  case DataTypeId::TrimmedString:
  case DataTypeId::ByteString:
  case DataTypeId::Image:
  case DataTypeId::ImageBMP:
  case DataTypeId::ImageGIF:
  case DataTypeId::ImageJPG:
  case DataTypeId::ImagePNG:
  case DataTypeId::ApplicationInstanceCertificate:
  case DataTypeId::ContinuationPoint:
  case DataTypeId::AudioDataType:
    return true;
  default:
    return false;
  }
}

// NR-11 rule 3.2: a ranged access to a Scalar Variable whose DataType can hold neither a String nor a
// ByteString is refused before any source is called, with what apply_read gives that shape
// (Bad_IndexRangeNoData). Every namespace-0 DataType is decided here without a lookup; a ranged access to a
// Variable whose DataType is of another namespace goes to its source, which applies the range.
bool screened_out(const VariableNode& variable, const String& indexRange)
{
  if (indexRange.empty())
  {
    return false;
  }
  const Variant rank = variable.read_attribute(AttributeId::ValueRank);
  const auto* valueRank = rank.try_as<int32_t>();
  if (!rank.empty() && (valueRank == nullptr || *valueRank != -1))
  {
    return false;
  }
  const Variant type = variable.read_attribute(AttributeId::DataType);
  const auto* dataType = type.try_as<NodeId>();
  if (dataType == nullptr || dataType->namespace_index() != 0 || !dataType->is_numeric())
  {
    return false;
  }
  return !may_hold_string_or_byte_string(dataType->identifier().get_numeric());
}

StatusCode index_range_no_data(const NodeId& nodeId)
{
  return StatusCode{Status::BadIndexRangeNoData,
    ErrorDetail::build("ScalarHasNoIndexRange",
      "The Variable is a scalar whose DataType holds no String or ByteString, so no IndexRange selects data",
      "DefaultNamespace")
      .context(ContextKeys::nodeId, to_string(nodeId))};
}

// A Variable's Value write. A Variable with an application source gets the write as given, a partial Value
// with its range included: the source merges (NR-11 rule 3). Otherwise the write goes to the Variable's
// default source, installed if it has none, which merges a range or ValidBits under its lock (NR-11 rule 4).
// The Variable lives until its source answers.
void write_variable_value(shared_ptr<VariableNode> variable, const WriteValue& write,
  const RequestInfo& request, const CallerInfo* caller, VariableNode::ValueWritten answer)
{
  VariableNode& writing = *variable;
  VariableNode::ValueWritten answered = [variable, answer = std::move(answer)](
                                          VoidResult written, bool initial)
  {
    answer(std::move(written), initial);
  };
  if (auto source = writing.application_source())
  {
    if (screened_out(writing, write.index_range()))
    {
      answered(VoidResult{index_range_no_data(write.node_id())}, false);
      return;
    }
    writing.write_to_source_async(source, request, write, caller, std::move(answered));
    return;
  }
  if (!write.index_range().empty())
  {
    // A range that does not parse is the item's answer; nothing is read.
    if (auto range = parse_numeric_range(write.index_range()); range.is_bad())
    {
      answered(VoidResult{range.status_code()}, false);
      return;
    }
  }
  if (writing.write_to_default_source_async(write, caller == nullptr, answered))
  {
    return;
  }
  // An application source was attached since it was looked for: it is written, and merges.
  if (auto source = writing.application_source())
  {
    writing.write_to_source_async(source, request, write, caller, std::move(answered));
    return;
  }
  answered(
    VoidResult{StatusCode{Status::BadInternalError,
      ErrorDetail::build("ValueOwnerUnknown", "The Variable has no value source", "DefaultNamespace")}},
    false);
}

// Any other Attribute, a VariableType's Value included: a client's write as the Write service decodes it, the
// server's own as given where written_as_given says so and encoded otherwise. The Node lives until it
// answers.
void write_node_attribute(shared_ptr<BaseNode> node, AttributeId attributeId, const WriteValue& write,
  bool client, std::function<void(VoidResult)> answer)
{
  auto answered = [node, answer = std::move(answer)](VoidResult written)
  {
    answer(std::move(written));
  };
  if (!client)
  {
    if (auto given = written_as_given(attributeId, write.value()))
    {
      node->write_attribute_async(attributeId, std::move(*given), std::move(answered));
      return;
    }
  }
  const NodeDescription nodeDescription = node->attributes();
  auto encoded =
    client ? client_attribute_value(
               nodeDescription.node_class(), nodeDescription.node_id(), attributeId, write.value().value())
           : node_utils::encode_writable_attribute_of_class(
               nodeDescription.node_class(), nodeDescription.node_id(), attributeId, write.value().value());
  if (!encoded.is_good())
  {
    answered(VoidResult{encoded.status_code()});
    return;
  }
  node->write_attribute_async(attributeId, std::move(encoded).value(), std::move(answered));
}

}  // namespace

Result<shared_ptr<BaseNode>> Namespace::own_node(const Node& node, const NodeId& nodeId)
{
  const auto* own = dynamic_cast<const BaseNode*>(&node);
  const auto returnedForNodeId = [this, own, &nodeId]
  {
    if (own->mNodeId == nodeId)
    {
      return true;
    }
    const std::optional<NodeResult> found = find_node(nodeId, std::nullopt);
    return found.has_value() && found->is_good() && found->value().get() == own;
  };
  if (own == nullptr || own->mOwner != this || !returnedForNodeId())
  {
    return StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("ForeignNode",
        "The item carries a Node this namespace did not return for its NodeId",
        "DefaultNamespace")
        .context(ContextKeys::nodeId, to_string(nodeId))};
  }
  if (own->deleted())
  {
    return StatusCode{Status::BadNodeIdUnknown,
      ErrorDetail::build("NodeDeleted", "The item's Node has been deleted", "DefaultNamespace")
        .context(ContextKeys::nodeId, to_string(nodeId))};
  }
  return std::static_pointer_cast<BaseNode>(std::const_pointer_cast<Node>(own->shared_from_this()));
}

void Namespace::read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
  std::function<void(BatchResult<NodeReferencesResult>)> complete)
{
  (void)request;
  BatchResult<NodeReferencesResult> result;
  try
  {
    result.items.reserve(queries.size());
    for (const ReferenceQuery& query : queries)
    {
      try
      {
        auto own = own_node(query.node, query.nodeId);
        if (!own.is_good())
        {
          result.items.emplace_back(own.status_code());
          continue;
        }
        const BaseNode& node = *own.value();
        References held;
        bool deleted = false;
        {
          const ReadLock lock{node.mMutex};
          deleted = node.deleted();
          if (!deleted)
          {
            held = References{node.mReferences};
          }
        }
        if (deleted)
        {
          result.items.emplace_back(StatusCode{Status::BadNodeIdUnknown,
            ErrorDetail::build("NodeDeleted", "The item's Node has been deleted", "DefaultNamespace")
              .context(ContextKeys::nodeId, to_string(query.nodeId))});
          continue;
        }
        result.items.emplace_back(
          page_of(hinted(std::move(held), query.referenceTypeHint), query.maxReferences, query.resumeToken));
      }
      catch (...)
      {
        result.items.emplace_back(current_exception_status());
      }
    }
  }
  catch (...)
  {
    result = failed_answer<BatchResult<NodeReferencesResult>>(current_exception_status());
  }
  detail::invoke_user_callback(std::move(complete), std::move(result));
}

std::shared_ptr<ValueSource> Namespace::common_source(std::span<const ValueReadItem> items)
{
  std::shared_ptr<ValueSource> common;
  for (const ValueReadItem& item : items)
  {
    auto own = own_node(item.node, item.value.node_id());
    if (!own.is_good())
    {
      return nullptr;
    }
    const auto* variable = dynamic_cast<const VariableNode*>(own.value().get());
    if (variable == nullptr || screened_out(*variable, item.value.index_range()))
    {
      return nullptr;
    }
    auto source = variable->application_source();
    if (!source || (common && common.get() != source.get()))
    {
      return nullptr;
    }
    common = std::move(source);
  }
  return common;
}

bool Namespace::read_from_default_source(const ValueReadItem& item, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)>& complete) noexcept
{
  BatchResult<DataValueResult> answer;
  try
  {
    auto own = own_node(item.node, item.value.node_id());
    if (!own.is_good())
    {
      return false;
    }
    const auto* variable = dynamic_cast<const VariableNode*>(own.value().get());
    if (variable == nullptr)
    {
      return false;
    }
    auto source = variable->default_source();
    if (!source && variable->application_source())
    {
      return false;
    }
    if (screened_out(*variable, item.value.index_range()))
    {
      answer.items.push_back(DataValueResult{index_range_no_data(item.value.node_id())});
    }
    else
    {
      // A Variable never written has no source yet, and a null Value (OPC 10000-3 5.6.2).
      answer.items.push_back(
        narrowed(DataValueResult{source ? source->read(maxAge, setSourceTimestamp) : DataValue{}},
          NumericRange{item.value.index_range()}));
    }
  }
  catch (...)
  {
    // The general path reads the item again and answers what fails.
    return false;
  }
  detail::invoke_user_callback(std::move(complete), std::move(answer));
  return true;
}

void Namespace::read_values_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  // NR-13a rule 1 and DL-115 (2): one item of a Variable on its default source is read through the source's
  // synchronous member.
  if (items.size() == 1 && read_from_default_source(items.front(), maxAge, setSourceTimestamp, complete))
  {
    return;
  }
  const ValueSource::ReadContext context{request, caller, maxAge, setSourceTimestamp};
  // NR-13a rules 1 and 2: items that all have one source - one item, most often - go to it in one call with
  // the completion passed through: no grouping state, no join, and up to four items no allocation by the
  // namespace. A source that throws is answered by the route (NR-23 rule 4).
  std::shared_ptr<ValueSource> common;
  try
  {
    common = items.empty() ? nullptr : common_source(items);
  }
  catch (...)
  {
    detail::invoke_user_callback(
      std::move(complete), failed_answer<BatchResult<DataValueResult>>(current_exception_status()));
    return;
  }
  if (common)
  {
    if (items.size() == 1)
    {
      const ValueSource::ReadItem item{items.front().node, items.front().value};
      common->read_async(context, std::span<const ValueSource::ReadItem>{&item, 1}, std::move(complete));
      return;
    }
    boost::container::small_vector<ValueSource::ReadItem, 4> sourceItems;
    for (const ValueReadItem& item : items)
    {
      sourceItems.push_back(ValueSource::ReadItem{item.node, item.value});
    }
    common->read_async(context, sourceItems, std::move(complete));
    return;
  }

  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    // NR-13 rules 3 and 4: the items of each application source, by the source's address, go to it in one
    // call; the default sources answer the others directly. The groups are made by sorting, and each keeps
    // its source until it answers.
    struct Group
    {
      std::shared_ptr<ValueSource> source;
      std::vector<std::size_t> indices;
      std::vector<std::function<void(DataValueResult)>> answers;
    };

    std::vector<Group> groups;
    std::vector<std::size_t> groupOf(items.size(), items.size());
    {
      std::vector<std::pair<std::shared_ptr<ValueSource>, std::size_t>> sourced;
      for (std::size_t index = 0; index < items.size(); ++index)
      {
        auto own = own_node(items[index].node, items[index].value.node_id());
        const auto* variable = own.is_good() ? dynamic_cast<const VariableNode*>(own.value().get()) : nullptr;
        if (variable == nullptr || screened_out(*variable, items[index].value.index_range()))
        {
          continue;
        }
        if (auto source = variable->application_source())
        {
          sourced.emplace_back(std::move(source), index);
        }
      }
      std::sort(sourced.begin(),
        sourced.end(),
        [](const auto& left, const auto& right)
        {
          return std::less<>{}(left.first.get(), right.first.get()) ||
                 (left.first.get() == right.first.get() && left.second < right.second);
        });
      for (auto& [source, index] : sourced)
      {
        if (groups.empty() || groups.back().source.get() != source.get())
        {
          groups.push_back(Group{std::move(source), {}, {}});
        }
        groupOf[index] = groups.size() - 1;
        groups.back().indices.push_back(index);
      }
    }

    // Held by each item's completion: the CallerInfo is valid only until this returns.
    shared_ptr<const AccessIdentity> identity = caller != nullptr ? caller->identity : nullptr;
    join_items<DataValueResult>(
      items.size(),
      [this, items, identity, maxAge, setSourceTimestamp, &groups, &groupOf](
        std::size_t index, std::function<void(DataValueResult)> answer)
      {
        if (groupOf[index] < groups.size())
        {
          // Answered when its source answers, below.
          groups[groupOf[index]].answers.push_back(std::move(answer));
          return;
        }
        const ValueReadItem& item = items[index];
        auto own = own_node(item.node, item.value.node_id());
        if (!own.is_good())
        {
          answer(DataValueResult{own.status_code()});
          return;
        }
        // The Node lives until it answers.
        shared_ptr<BaseNode> node = std::move(own).value();
        if (auto variable = std::dynamic_pointer_cast<VariableNode>(node))
        {
          if (screened_out(*variable, item.value.index_range()))
          {
            answer(DataValueResult{index_range_no_data(item.value.node_id())});
            return;
          }
          answer(narrowed(DataValueResult{variable->read_default_source(maxAge, setSourceTimestamp)},
            NumericRange{item.value.index_range()}));
          return;
        }
        const BaseNode& reading = *node;
        reading.read_value(maxAge,
          setSourceTimestamp,
          item.value,
          identity.get(),
          [node, identity, range = NumericRange{item.value.index_range()}, answer = std::move(answer)](
            DataValueResult read)
          {
            try
            {
              answer(narrowed(std::move(read), range));
            }
            catch (...)
            {
              answer(DataValueResult{current_exception_status()});
            }
          });
      },
      [once](BatchResult<DataValueResult> read) { run_once(once, std::move(read)); });

    for (auto& group : groups)
    {
      // A join that could not be made answered the whole call and started no item.
      if (group.answers.size() == group.indices.size())
      {
        read_group(context, items, std::move(group.source), group.indices, std::move(group.answers));
      }
    }
  }
  catch (...)
  {
    run_once(once, failed_answer<BatchResult<DataValueResult>>(current_exception_status()));
  }
}

std::vector<Namespace::SourceWrites> Namespace::source_write_groups(std::span<const ValueWriteItem> items)
{
  std::vector<std::pair<std::shared_ptr<ValueSource>, std::size_t>> sourced;
  for (std::size_t index = 0; index < items.size(); ++index)
  {
    const ValueWriteItem& item = items[index];
    if (static_cast<AttributeId>(item.value.attribute_id()) != AttributeId::Value)
    {
      continue;
    }
    auto own = own_node(item.node, item.value.node_id());
    auto variable = own.is_good() ? std::dynamic_pointer_cast<VariableNode>(own.value()) : nullptr;
    if (!variable || screened_out(*variable, item.value.index_range()))
    {
      continue;
    }
    if (auto source = variable->application_source())
    {
      sourced.emplace_back(std::move(source), index);
    }
  }
  std::sort(sourced.begin(),
    sourced.end(),
    [](const auto& left, const auto& right)
    {
      return std::less<>{}(left.first.get(), right.first.get()) ||
             (left.first.get() == right.first.get() && left.second < right.second);
    });
  std::vector<SourceWrites> groups;
  for (std::size_t begin = 0; begin < sourced.size();)
  {
    std::size_t end = begin + 1;
    while (end < sourced.size() && sourced[end].first.get() == sourced[begin].first.get())
    {
      ++end;
    }
    // A source with one item is written through the item's own path.
    if (end - begin > 1)
    {
      SourceWrites group{sourced[begin].first, {}, {}};
      for (std::size_t k = begin; k < end; ++k)
      {
        group.indices.push_back(sourced[k].second);
      }
      groups.push_back(std::move(group));
    }
    begin = end;
  }
  return groups;
}

void Namespace::write_group(const ValueSource::WriteContext& context, std::span<const ValueWriteItem> items,
  SourceWrites group) noexcept
{
  struct Completions
  {
    std::atomic<bool> answered{false};
    std::vector<VariableNode::ValueWritten> each;
  };

  auto completions = std::make_shared<Completions>();
  const auto answerEvery = [completions](const VoidResult& failed)
  {
    if (completions->answered.exchange(true, std::memory_order_acq_rel))
    {
      return;
    }
    for (auto& completion : completions->each)
    {
      detail::invoke_user_callback(completion, VoidResult{failed}, false);
    }
  };
  try
  {
    std::vector<ValueSource::WriteItem> sourceItems;
    sourceItems.reserve(group.indices.size());
    completions->each.reserve(group.indices.size());
    for (std::size_t k = 0; k < group.indices.size(); ++k)
    {
      const ValueWriteItem& item = items[group.indices[k]];
      // Checked by source_write_groups: the item's Node is a Variable of this namespace.
      auto variable =
        std::static_pointer_cast<VariableNode>(std::const_pointer_cast<Node>(item.node.shared_from_this()));
      completions->each.push_back(variable->source_write_completion(group.source, group.answers[k]));
      sourceItems.push_back(ValueSource::WriteItem{item.node, item.value});
    }
    group.source->write_async(context,
      sourceItems,
      [source = group.source, completions, answerEvery](BatchResult<ValueSource::WriteResult> written)
      {
        if (written.batchStatus.is_bad())
        {
          answerEvery(written.batchStatus);
          return;
        }
        if (written.items.size() != completions->each.size())
        {
          answerEvery(VoidResult{StatusCode{Status::BadInternalError,
            ErrorDetail::build("ValueSourceAnswerSize",
              "The value source answered another number of items than it was given",
              "DefaultNamespace")}});
          return;
        }
        if (completions->answered.exchange(true, std::memory_order_acq_rel))
        {
          return;
        }
        for (std::size_t i = 0; i < written.items.size(); ++i)
        {
          auto& answer = written.items[i];
          if (!answer.has_value())
          {
            detail::invoke_user_callback(
              completions->each[i], VoidResult{answer.status_code(), answer.shared_detail()}, false);
            continue;
          }
          detail::invoke_user_callback(
            completions->each[i], VoidResult{answer.status_code()}, answer.value().initial);
        }
      });
  }
  catch (...)
  {
    const VoidResult failed{current_exception_status()};
    if (completions->each.size() < group.answers.size())
    {
      // Items whose completion was not made yet still hold their answer.
      for (std::size_t k = completions->each.size(); k < group.answers.size(); ++k)
      {
        if (group.answers[k])
        {
          detail::invoke_user_callback(group.answers[k], VoidResult{failed}, false);
        }
      }
    }
    answerEvery(failed);
  }
}

void Namespace::read_group(const ValueSource::ReadContext& context, std::span<const ValueReadItem> items,
  std::shared_ptr<ValueSource> source, const std::vector<std::size_t>& indices,
  std::vector<std::function<void(DataValueResult)>> answers) noexcept
{
  // Each answer is accepted once by the join, so a source that answers and then throws is answered once.
  auto shared = std::make_shared<std::vector<std::function<void(DataValueResult)>>>(std::move(answers));
  const auto answerEvery = [shared](const DataValueResult& failed)
  {
    for (auto& answer : *shared)
    {
      detail::invoke_user_callback(answer, DataValueResult{failed});
    }
  };
  try
  {
    std::vector<ValueSource::ReadItem> sourceItems;
    sourceItems.reserve(indices.size());
    for (const std::size_t index : indices)
    {
      sourceItems.push_back(ValueSource::ReadItem{items[index].node, items[index].value});
    }
    source->read_async(context,
      sourceItems,
      [source, shared, answerEvery](BatchResult<DataValueResult> read)
      {
        if (read.batchStatus.is_bad())
        {
          answerEvery(DataValueResult{read.batchStatus.status_code(), read.batchStatus.shared_detail()});
          return;
        }
        if (read.items.size() != shared->size())
        {
          answerEvery(DataValueResult{StatusCode{Status::BadInternalError,
            ErrorDetail::build("ValueSourceAnswerSize",
              "The value source answered another number of items than it was given",
              "DefaultNamespace")}});
          return;
        }
        for (std::size_t i = 0; i < read.items.size(); ++i)
        {
          detail::invoke_user_callback((*shared)[i], std::move(read.items[i]));
        }
      });
  }
  catch (...)
  {
    answerEvery(DataValueResult{current_exception_status()});
  }
}

bool Namespace::values_committed(std::span<CommittedValue> committed) noexcept
{
  bool anyConstant = false;
  std::vector<SemanticChangeReport> reports;
  const NodeId hasProperty{ReferenceTypeId::HasProperty};
  for (CommittedValue& value : committed)
  {
    try
    {
      const VariableNode& variable = *value.variable;
      const auto accessLevelValue = variable.read_attribute(AttributeId::AccessLevelEx);
      if (const auto* raw = accessLevelValue.try_as<uint32_t>())
      {
        AccessLevelExType accessLevelEx;
        accessLevelEx.from_underlying_type(*raw);
        // A first Value is not a change (NR-38 rule 1, NR-40 rule 4).
        value.constant = !value.initial && accessLevelEx.test(AccessLevelExType::Bit::Constant);
        anyConstant = anyConstant || value.constant;
      }
      // The owner, from the inverse HasProperty the Property holds (NR-37 rule 3).
      base_node_details::SharedReferences references;
      {
        const ReadLock lock(variable.mMutex);
        references = variable.mReferences;
      }
      const Reference* owner = nullptr;
      for (const auto& reference : *references)
      {
        if (!reference.is_forward() && reference.type_id() == hasProperty && reference.target_id().is_local())
        {
          owner = &reference;
          break;
        }
      }
      if (owner == nullptr)
      {
        continue;
      }
      const NodeId& ownerId = owner->target_id().node_id();
      if (!context().monitoring().property_value_changed(ownerId, variable, value.initial))
      {
        continue;
      }
      // The event names the owner and its TypeDefinition, which this namespace holds (NR-38 rule 2); an owner
      // in another namespace is not supported (NR-37 rule 5). The Node table changes under the namespace's
      // lock, so the lookup takes it.
      shared_ptr<BaseNode> ownerNode;
      {
        const ReadLock lock(mMutex);
        ownerNode = find_node_internal(ownerId);
      }
      if (ownerNode)
      {
        reports.push_back(SemanticChangeReport{ownerId, affected_type_of(ownerNode->mutation_snapshot())});
      }
    }
    catch (...)
    {
      // A Variable deleted since it was written changes nothing more.
      detail::ignore_expected_exception();
    }
  }
  if (!reports.empty())
  {
    context().semantics_changed(reports);
  }
  return anyConstant;
}

void Namespace::own_value_committed(NamespaceLink& link, shared_ptr<VariableNode> variable, bool initial,
  VoidResult result, std::function<void(VoidResult)> answer) noexcept
{
  bool queued = false;
  try
  {
    const std::shared_lock lock{link.mutex};
    if (link.owner != nullptr)
    {
      CommittedValue committed{std::move(variable), initial, false, 0};
      if (link.owner->values_committed(std::span<CommittedValue>{&committed, 1}))
      {
        // The write is answered once ConfigurationVersion is advanced (NR-40 rule 4); a failed advance is the
        // write's answer.
        auto advanced = [result, answer](VoidResult advance) mutable
        {
          if (answer)
          {
            detail::invoke_user_callback(
              std::move(answer), advance.is_good() ? std::move(result) : std::move(advance));
          }
        };
        queued = link.owner->context().constant_values_changed(std::move(advanced)).is_good();
      }
    }
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
  // A context that refuses the advance has no ConfigurationVersion to advance: the write keeps its answer.
  if (!queued && answer)
  {
    detail::invoke_user_callback(std::move(answer), std::move(result));
  }
}

template<typename Answer>
void Namespace::finish_value_writes(NamespaceLink& link, std::span<CommittedValue> committed, Answer answer,
  BatchResult<VoidResult> answers, std::vector<VersionedNode> versioned) noexcept
{
  // The answer of a call whose items changed a Constant Value, kept until ConfigurationVersion is advanced.
  struct Pending
  {
    BatchResult<VoidResult> answers;
    std::vector<VersionedNode> versioned;
    std::vector<std::size_t> constantItems;
  };

  shared_ptr<Pending> pending;
  try
  {
    const std::shared_lock lock{link.mutex};
    if (link.owner != nullptr && !committed.empty() && link.owner->values_committed(committed))
    {
      pending = std::make_shared<Pending>();
      pending->answers = std::move(answers);
      pending->versioned = std::move(versioned);
      for (const CommittedValue& value : committed)
      {
        if (value.constant)
        {
          pending->constantItems.push_back(value.index);
        }
      }
      // A failed advance is the answer of each Constant item that was Good (NR-40 rule 4).
      auto advanced = [pending, answer](VoidResult advance) mutable
      {
        if (advance.is_bad())
        {
          for (const std::size_t index : pending->constantItems)
          {
            if (index < pending->answers.items.size() && !pending->answers.items[index].is_bad())
            {
              pending->answers.items[index] = advance;
            }
          }
        }
        answer(std::move(pending->answers), std::move(pending->versioned));
      };
      if (link.owner->context().constant_values_changed(std::move(advanced)).is_good())
      {
        return;
      }
    }
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
  // Answered without the link's lock. A context that refuses the advance has no ConfigurationVersion to
  // advance: the items keep their answers.
  if (pending)
  {
    answer(std::move(pending->answers), std::move(pending->versioned));
    return;
  }
  answer(std::move(answers), std::move(versioned));
}

std::shared_ptr<ValueSource> Namespace::common_write_source(std::span<const ValueWriteItem> items)
{
  std::shared_ptr<ValueSource> common;
  for (const ValueWriteItem& item : items)
  {
    if (static_cast<AttributeId>(item.value.attribute_id()) != AttributeId::Value || merges(item.value))
    {
      return nullptr;
    }
    auto own = own_node(item.node, item.value.node_id());
    if (!own.is_good())
    {
      return nullptr;
    }
    const auto* variable = dynamic_cast<const VariableNode*>(own.value().get());
    if (variable == nullptr)
    {
      return nullptr;
    }
    auto source = variable->application_source();
    if (!source || (common && common.get() != source.get()))
    {
      return nullptr;
    }
    common = std::move(source);
  }
  return common;
}

bool Namespace::write_to_default_source(const CallerInfo* caller, const ValueWriteItem& item,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)>& complete) noexcept
{
  shared_ptr<const VariableNode> variable;
  std::shared_ptr<DefaultValueSource> source;
  try
  {
    if (static_cast<AttributeId>(item.value.attribute_id()) != AttributeId::Value)
    {
      return false;
    }
    auto own = own_node(item.node, item.value.node_id());
    if (!own.is_good())
    {
      return false;
    }
    auto writing = std::dynamic_pointer_cast<VariableNode>(std::move(own).value());
    if (!writing)
    {
      return false;
    }
    source = writing->default_source_for_write();
    if (!source)
    {
      return false;
    }
    variable = std::move(writing);
  }
  catch (...)
  {
    // Nothing is written yet: the general path writes the item and answers what fails.
    return false;
  }

  BatchResult<VoidResult> answers;
  CommittedValue committed;
  bool written = false;
  try
  {
    // Committed and reported under the Variable's commit lock, so that two writes are reported in the order
    // they were committed (NR-48 rule 4).
    auto stored = variable->commit_to_default_source(*source, item.value, caller == nullptr);
    if (!stored.has_value())
    {
      answers.items.push_back(VoidResult{stored.status_code(), stored.shared_detail()});
    }
    else
    {
      // The write's answer keeps the code of the commit, a Good subcode included.
      answers.items.push_back(VoidResult{stored.status_code()});
      committed = CommittedValue{std::move(variable), stored.value().initial, false, 0};
      written = true;
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(std::move(complete),
      failed_answer<BatchResult<VoidResult>>(current_exception_status()),
      std::vector<VersionedNode>{});
    return true;
  }
  finish_value_writes(
    *mLink,
    written ? std::span<CommittedValue>{&committed, 1} : std::span<CommittedValue>{},
    [complete = std::move(complete)](
      BatchResult<VoidResult> result, std::vector<VersionedNode> versioned) mutable
    { detail::invoke_user_callback(std::move(complete), std::move(result), std::move(versioned)); },
    std::move(answers),
    std::vector<VersionedNode>{});
  return true;
}

void Namespace::write_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueWriteItem> items,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  // NR-13a rule 1 and DL-115 (2): one Value write to a Variable on its default source is applied through the
  // source's synchronous member, with no completion wrapper.
  if (items.size() == 1 && write_to_default_source(caller, items.front(), complete))
  {
    return;
  }
  // NR-13a rules 1 and 2: Value writes that all have one source - one item, most often - go to it in one
  // call. The completion is wrapped once, to tell the Reported registrations and run the steps for the
  // committed Values (NR-37, NR-38, NR-40): no grouping state and no join.
  std::shared_ptr<ValueSource> common;
  try
  {
    common = items.empty() ? nullptr : common_write_source(items);
  }
  catch (...)
  {
    detail::invoke_user_callback(std::move(complete),
      failed_answer<BatchResult<VoidResult>>(current_exception_status()),
      std::vector<VersionedNode>{});
    return;
  }
  if (common)
  {
    write_to_common_source(request, caller, items, std::move(common), std::move(complete));
    return;
  }

  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    const bool client = caller != nullptr;

    // The Nodes whose NodeVersion a write advanced, and the Values committed, collected as the items answer.
    struct Collected
    {
      std::mutex mutex;
      std::vector<VersionedNode> nodes;
      std::vector<CommittedValue> values;
    };

    auto collected = std::make_shared<Collected>();
    const bool mayHoldVersions = mMayHoldVersions->load(std::memory_order_acquire);
    const auto committedAnswer =
      [collected](
        shared_ptr<const VariableNode> variable, std::size_t index, std::function<void(VoidResult)> answer)
      -> VariableNode::ValueWritten
    {
      return [collected, variable = std::move(variable), index, answer = std::move(answer)](
               VoidResult result, bool initial) mutable
      {
        if (result.is_good())
        {
          try
          {
            const std::lock_guard lock{collected->mutex};
            collected->values.push_back(CommittedValue{std::move(variable), initial, false, index});
          }
          catch (...)
          {
            detail::ignore_expected_exception();
          }
        }
        answer(std::move(result));
      };
    };
    // NR-13 rule 3: the Value writes of each source that has more than one go to it in one call.
    std::vector<SourceWrites> groups = source_write_groups(items);
    std::vector<std::size_t> groupOf(items.size(), groups.size());
    for (std::size_t g = 0; g < groups.size(); ++g)
    {
      for (const std::size_t index : groups[g].indices)
      {
        groupOf[index] = g;
      }
    }
    join_items<VoidResult>(
      items.size(),
      [this,
        &request,
        caller,
        items,
        client,
        collected,
        mayHoldVersions,
        &groups,
        &groupOf,
        &committedAnswer](std::size_t index, std::function<void(VoidResult)> answer)
      {
        if (groupOf[index] < groups.size())
        {
          // Answered when its source answers, below. Checked by source_write_groups: a Variable of this
          // namespace.
          auto variable = std::static_pointer_cast<const VariableNode>(items[index].node.shared_from_this());
          groups[groupOf[index]].answers.push_back(
            committedAnswer(std::move(variable), index, std::move(answer)));
          return;
        }
        const ValueWriteItem& item = items[index];
        auto own = own_node(item.node, item.value.node_id());
        if (!own.is_good())
        {
          answer(VoidResult{own.status_code()});
          return;
        }
        shared_ptr<BaseNode> node = std::move(own).value();
        const auto attributeId = static_cast<AttributeId>(item.value.attribute_id());
        if (attributeId == AttributeId::Value)
        {
          if (auto variable = std::dynamic_pointer_cast<VariableNode>(node))
          {
            auto written = committedAnswer(variable, index, std::move(answer));
            write_variable_value(std::move(variable), item.value, request, caller, std::move(written));
            return;
          }
        }
        const NodeClass nodeClass = node->get_node_class();
        if (!mayHoldVersions ||
            (attributeId != AttributeId::DataType && attributeId != AttributeId::ValueRank &&
              attributeId != AttributeId::ArrayDimensions) ||
            (nodeClass != NodeClass::Variable && nodeClass != NodeClass::VariableType))
        {
          write_node_attribute(std::move(node), attributeId, item.value, client, std::move(answer));
          return;
        }
        // OPC 10000-3 Tables 13 and 14: a change of these three advances the NodeVersion. A write that leaves
        // the value as it was changes nothing. The Property is found before the write, which does not change
        // it, so that the completion uses nothing of the namespace.
        auto property = version_property(*node, /*view=*/false);
        if (!property)
        {
          write_node_attribute(std::move(node), attributeId, item.value, client, std::move(answer));
          return;
        }
        Variant before = node->read_attribute(attributeId);
        auto written = [counter = mNodeVersionCounter,
                         property = std::move(property),
                         node,
                         attributeId,
                         before = std::move(before),
                         collected,
                         answer = std::move(answer)](VoidResult result) mutable
        {
          try
          {
            if (result.is_bad() || node->read_attribute(attributeId) == before)
            {
              answer(std::move(result));
              return;
            }
            advance_version(std::move(counter),
              std::move(property),
              /*view=*/false,
              [node, collected, result = std::move(result), answer = std::move(answer)](
                VoidResult advanced) mutable
              {
                if (advanced.is_bad())
                {
                  answer(VoidResult{version_not_advanced(advanced.status_code())});
                  return;
                }
                try
                {
                  const auto snapshot = node->mutation_snapshot();
                  const std::lock_guard lock{collected->mutex};
                  collected->nodes.push_back(VersionedNode{snapshot.nodeId, affected_type_of(snapshot)});
                }
                catch (...)
                {
                  detail::ignore_expected_exception();
                }
                answer(std::move(result));
              });
          }
          catch (...)
          {
            answer(VoidResult{current_exception_status()});
          }
        };
        write_node_attribute(std::move(node), attributeId, item.value, client, std::move(written));
      },
      [once, collected, link = mLink](BatchResult<VoidResult> written)
      {
        std::vector<VersionedNode> nodes;
        std::vector<CommittedValue> values;
        {
          const std::lock_guard lock{collected->mutex};
          nodes.swap(collected->nodes);
          values.swap(collected->values);
        }
        finish_value_writes(
          *link,
          std::span<CommittedValue>{values},
          [once](BatchResult<VoidResult> answers, std::vector<VersionedNode> versioned)
          { run_once(once, std::move(answers), std::move(versioned)); },
          std::move(written),
          std::move(nodes));
      });
    const ValueSource::WriteContext context{request, caller};
    for (auto& group : groups)
    {
      // A join that could not be made answered the whole call and started no item.
      if (group.answers.size() == group.indices.size())
      {
        write_group(context, items, std::move(group));
      }
    }
  }
  catch (...)
  {
    run_once(
      once, failed_answer<BatchResult<VoidResult>>(current_exception_status()), std::vector<VersionedNode>{});
  }
}

void Namespace::write_to_common_source(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueWriteItem> items, std::shared_ptr<ValueSource> source,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) noexcept
{
  try
  {
    // Checked by common_write_source: each item's Node is a Variable of this namespace, written whole.
    boost::container::small_vector<ValueSource::WriteItem, 4> sourceItems;
    boost::container::small_vector<shared_ptr<const VariableNode>, 4> variables;
    for (const ValueWriteItem& item : items)
    {
      sourceItems.push_back(ValueSource::WriteItem{item.node, item.value});
      variables.push_back(std::static_pointer_cast<const VariableNode>(item.node.shared_from_this()));
    }
    const ValueSource::WriteContext context{request, caller};
    // The wrapper holds the source until it answers (NR-13 rule 4): a source replaced on its Variable while
    // this write is outstanding is not destroyed with the write in it.
    ValueSource& writing = *source;
    writing.write_async(context,
      sourceItems,
      [source = std::move(source),
        link = mLink,
        variables = std::move(variables),
        complete = std::move(complete)](BatchResult<ValueSource::WriteResult> answered) mutable
      {
        BatchResult<VoidResult> answers;
        boost::container::small_vector<CommittedValue, 4> committed;
        // The committed Variables with a Reported registration: a source may keep another Value than the
        // one written, so theirs are read back from it and reported as it then holds them (DL-115 (3)).
        boost::container::small_vector<shared_ptr<const VariableNode>, 4> reported;
        try
        {
          const bool sized = answered.batchStatus.is_good() && answered.items.size() == variables.size();
          for (std::size_t i = 0; i < variables.size(); ++i)
          {
            if (!sized)
            {
              // A failure of the call is every item's.
              answers.items.push_back(
                answered.batchStatus.is_bad()
                  ? answered.batchStatus
                  : VoidResult{StatusCode{Status::BadInternalError,
                      ErrorDetail::build("ValueSourceAnswerSize",
                        "The value source answered another number of items than it was given",
                        "DefaultNamespace")}});
              continue;
            }
            auto& answer = answered.items[i];
            if (!answer.has_value())
            {
              answers.items.push_back(VoidResult{answer.status_code(), answer.shared_detail()});
              continue;
            }
            answers.items.push_back(VoidResult{answer.status_code()});
            committed.push_back(CommittedValue{variables[i], answer.value().initial, false, i});
            if (variables[i]->has_reported_registrations())
            {
              reported.push_back(variables[i]);
            }
          }
        }
        catch (...)
        {
          detail::invoke_user_callback(std::move(complete),
            failed_answer<BatchResult<VoidResult>>(current_exception_status()),
            std::vector<VersionedNode>{});
          return;
        }
        auto finish = [link,
                        committed = std::move(committed),
                        answers = std::move(answers),
                        complete = std::move(complete)]() mutable
        {
          finish_value_writes(
            *link,
            std::span<CommittedValue>{committed.data(), committed.size()},
            [complete = std::move(complete)](
              BatchResult<VoidResult> result, std::vector<VersionedNode> versioned) mutable
            { detail::invoke_user_callback(std::move(complete), std::move(result), std::move(versioned)); },
            std::move(answers),
            std::vector<VersionedNode>{});
        };
        if (reported.empty())
        {
          finish();
          return;
        }
        // Answered once the Values read back are reported. Copied, so that a failure to wrap it still
        // answers the writes, unreported.
        std::function<void()> answer;
        try
        {
          answer = finish;
        }
        catch (...)
        {
          finish();
          return;
        }
        VariableNode::report_values_held(source, reported, answer);
      });
  }
  catch (...)
  {
    detail::invoke_user_callback(std::move(complete),
      failed_answer<BatchResult<VoidResult>>(current_exception_status()),
      std::vector<VersionedNode>{});
  }
}

void Namespace::call_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete)
{
  (void)request;
  (void)caller;
  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    join_items<std::optional<CallResult>>(
      items.size(),
      [this, items](std::size_t index, std::function<void(std::optional<CallResult>)> answer)
      {
        const CallItem& item = items[index];
        auto own = own_node(item.method, item.request.method_id());
        if (!own.is_good())
        {
          // A Method of this namespace that has been deleted is answered; any other belongs to the namespace
          // that returned it, which runs the call.
          if (own.status_code().as_status() == Status::BadNodeIdUnknown)
          {
            answer(std::optional<CallResult>{CallResult{own.status_code()}});
            return;
          }
          answer(std::nullopt);
          return;
        }
        // The Method lives until its handler answers, which may be after this returns, when the caller's item
        // has ended: the handler is given a request of its own.
        shared_ptr<BaseNode> method = std::move(own).value();
        const BaseNode& calling = *method;
        auto ownRequest = std::make_shared<const CallMethodRequest>(item.request);
        calling.call(*ownRequest,
          item.context,
          [method, ownRequest, answer = std::move(answer)](CallResult called)
          { answer(std::optional<CallResult>{std::move(called)}); });
      },
      [once](BatchResult<std::optional<CallResult>> called) { run_once(once, std::move(called)); });
  }
  catch (...)
  {
    run_once(once, failed_answer<BatchResult<std::optional<CallResult>>>(current_exception_status()));
  }
}

void Namespace::view_contains_async(const RequestInfo& request, const NodeId& view,
  std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete)
{
  (void)request;
  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    // The View Node lives until its members answer.
    shared_ptr<BaseNode> viewNode = find_node<BaseNode>(view);
    const NodeResult missing = viewNode ? NodeResult{shared_ptr<Node>{viewNode}} : resolve_here(view);
    join_items<BoolResult>(
      nodes.size(),
      [&nodes, &viewNode, &missing](std::size_t index, std::function<void(BoolResult)> answer)
      {
        if (!viewNode)
        {
          answer(
            BoolResult{missing.is_good() ? StatusCode{Status::BadNodeIdUnknown} : missing.status_code()});
          return;
        }
        const ExpandedNodeId& candidate = nodes[index];
        if (!candidate.is_local() || !candidate.namespace_uri().empty())
        {
          answer(BoolResult{false});
          return;
        }
        viewNode->is_node_in_view_async(candidate.node_id(),
          [viewNode, answer = std::move(answer)](BoolResult contained) { answer(std::move(contained)); });
      },
      [once](BatchResult<BoolResult> contained) { run_once(once, std::move(contained)); });
  }
  catch (...)
  {
    run_once(once, failed_answer<BatchResult<BoolResult>>(current_exception_status()));
  }
}

void Namespace::add_to_view_async(const RequestInfo& request, const NodeId& view,
  std::span<const NodeId> nodes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    // The View Node lives until its members answer.
    shared_ptr<BaseNode> viewNode = find_node<BaseNode>(view);
    auto asView = std::dynamic_pointer_cast<ViewNode>(viewNode);
    if (asView)
    {
      // The members first, then the ViewVersion once (OPC 10000-3 5.4, Table 10). The View Node gains no
      // Reference, so nothing is reported. A ViewVersion that cannot advance takes the members back out and
      // is the answer of each.
      BatchResult<VoidResult> added;
      added.items.resize(nodes.size());
      std::vector<NodeId> inserted;
      for (const NodeId& member : nodes)
      {
        if (asView->add_member(member))
        {
          inserted.push_back(member);
        }
      }
      auto property = inserted.empty() ? nullptr : version_property(*asView, /*view=*/true);
      if (!property)
      {
        run_once(once, std::move(added), std::vector<VersionedNode>{});
        return;
      }
      advance_version(nullptr,
        std::move(property),
        /*view=*/true,
        [once,
          asView,
          inserted = std::move(inserted),
          added = std::move(added),
          nodes = std::vector<NodeId>(nodes.begin(), nodes.end())](VoidResult advanced) mutable
        {
          if (advanced.is_bad())
          {
            for (const NodeId& member : inserted)
            {
              (void)asView->remove_member(member);
            }
            for (std::size_t i = 0; i < nodes.size(); ++i)
            {
              if (std::ranges::find(inserted, nodes[i]) != inserted.end())
              {
                added.items[i] = advanced;
              }
            }
          }
          run_once(once, std::move(added), std::vector<VersionedNode>{});
        });
      return;
    }
    const NodeResult missing = viewNode ? NodeResult{shared_ptr<Node>{viewNode}} : resolve_here(view);
    join_items<VoidResult>(
      nodes.size(),
      [&nodes, &viewNode, &missing](std::size_t index, std::function<void(VoidResult)> answer)
      {
        if (!viewNode)
        {
          answer(
            VoidResult{missing.is_good() ? StatusCode{Status::BadNodeIdUnknown} : missing.status_code()});
          return;
        }
        viewNode->add_node_to_view_async(nodes[index],
          [viewNode, answer = std::move(answer)](VoidResult added) { answer(std::move(added)); });
      },
      [once](BatchResult<VoidResult> added)
      { run_once(once, std::move(added), std::vector<VersionedNode>{}); });
  }
  catch (...)
  {
    run_once(
      once, failed_answer<BatchResult<VoidResult>>(current_exception_status()), std::vector<VersionedNode>{});
  }
}

void Namespace::create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
  std::function<void(BatchResult<NodeResult>)> complete)
{
  (void)request;
  BatchResult<NodeResult> result;
  try
  {
    result.items.reserve(nodes.size());
    for (const NodeCreation& creation : nodes)
    {
      result.items.push_back(
        create_with_attributes(creation.nodeId, creation.nodeClass, creation.attributes));
    }
  }
  catch (...)
  {
    result = failed_answer<BatchResult<NodeResult>>(current_exception_status());
  }
  detail::invoke_user_callback(std::move(complete), std::move(result));
}

void Namespace::delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes,
  ReferenceHalves halves,
  std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    BatchResult<DeleteNodeResult> result;
    result.items.reserve(nodes.size());
    std::vector<shared_ptr<ViewNode>> views;
    // A deleted Node that was versioned is reported with the TypeDefinition it had; its NodeVersion is not
    // written. A Node left that lost a Reference to one advances its own (NR-36 rule 2).
    std::vector<VersionedNode> deletedVersioned;
    std::vector<VersionedChange> survivors;
    const bool mayHoldVersions = mMayHoldVersions->load(std::memory_order_acquire);
    {
      // SVR-MI-GEN-090: each Node is marked deleted here, and each item monitoring it receives
      // Bad_NodeIdUnknown at its next tick, from the registration's helper (DL-68 (6)).
      const WriteLock lock(mMutex);
      std::unordered_set<NodeId> deleted;
      for (const NodeId& nodeId : nodes)
      {
        DeleteNodeResult item = [&]() -> DeleteNodeResult
        {
          try
          {
            if (mayHoldVersions)
            {
              if (const auto node = find_node_internal(nodeId); node && version_property(*node, false, true))
              {
                const auto snapshot = node->mutation_snapshot();
                deletedVersioned.push_back(VersionedNode{snapshot.nodeId, affected_type_of(snapshot)});
              }
            }
            // ThisHalfOnly: the Nodes left keep their halves of References to it (OPC 10000-4 5.7.4.2).
            auto removed = delete_node_internal(nodeId, halves == ReferenceHalves::Both, deleted);
            if (removed.is_good())
            {
              for (auto& view : remove_from_views_locked(nodeId))
              {
                if (std::ranges::find(views, view) == views.end())
                {
                  views.push_back(std::move(view));
                }
              }
            }
            return removed;
          }
          catch (...)
          {
            return DeleteNodeResult{current_exception_status()};
          }
        }();
        result.items.push_back(std::move(item));
      }
      for (auto& survivor : remove_references_to_locked(deleted))
      {
        if (mayHoldVersions)
        {
          survivors.push_back(VersionedChange{std::move(survivor), false});
        }
      }
    }
    // The delete answers once the Nodes left have advanced their NodeVersions and the Views that listed a
    // deleted Node their ViewVersions (F11). A NodeVersion that cannot advance does not fail the delete; it
    // is not reported.
    Logger logger;
    if (!survivors.empty())
    {
      logger = version_logger();
    }
    advance_versions(std::move(survivors),
      [once,
        views = view_versions_of(views),
        result = std::move(result),
        deletedVersioned = std::move(deletedVersioned),
        logger = std::move(logger)](VersionsAdvanced advanced) mutable
      {
        for (const auto& [node, why] : advanced.refused)
        {
          try
          {
            logger.with_category("address_space")
              .warning({{"node", to_string(node)}, {"status", to_string(why)}},
                "A Node lost a Reference to a deleted Node and its NodeVersion could not advance");
          }
          catch (...)
          {
            detail::ignore_expected_exception();
          }
        }
        deletedVersioned.insert(deletedVersioned.end(),
          std::make_move_iterator(advanced.reported.begin()),
          std::make_move_iterator(advanced.reported.end()));
        advance_view_versions(std::move(views),
          [once, result = std::move(result), versioned = std::move(deletedVersioned)]() mutable
          { run_once(once, std::move(result), std::move(versioned)); });
      });
  }
  catch (...)
  {
    run_once(once,
      failed_answer<BatchResult<DeleteNodeResult>>(current_exception_status()),
      std::vector<VersionedNode>{});
  }
}

void Namespace::add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  change_own_references(changes, true, complete);
}

void Namespace::remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  change_own_references(changes, false, complete);
}

void Namespace::change_own_references(std::span<const ReferenceChange> changes, bool add,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)>& complete) noexcept
{
  BatchResult<VoidResult> result;
  // Each source whose References changed, once.
  std::vector<VersionedChange> touched;
  std::unordered_map<const BaseNode*, std::size_t> touchedAt;
  const bool mayHoldVersions = mMayHoldVersions->load(std::memory_order_acquire);
  try
  {
    result.items.reserve(changes.size());
    for (const ReferenceChange& change : changes)
    {
      VoidResult item = [&]() -> VoidResult
      {
        try
        {
          const auto source = find_node<BaseNode>(change.source);
          if (!source)
          {
            return VoidResult{Status::BadNodeIdUnknown,
              ErrorDetail::build(
                "NodeNotFound", "This namespace holds no Node for the change's source", "DefaultNamespace")
                .context(ContextKeys::nodeId, to_string(change.source))};
          }
          // Only an add keeps a remote target's DisplayName with the Reference.
          std::vector<Reference> references{
            add ? Reference{change.referenceType, change.target, change.isForward, change.targetDisplayName}
                : Reference{change.referenceType, change.target, change.isForward}};
          auto outcome = source->change_references(references, add, /*reportMissing=*/!add);
          if (outcome.changed && mayHoldVersions)
          {
            const auto [entry, added] = touchedAt.try_emplace(source.get(), touched.size());
            if (added)
            {
              touched.push_back(VersionedChange{source, add && change.sourceCreated});
            }
            // A source created in this operation keeps its NodeVersion only when every change made to it here
            // marks it created.
            touched[entry->second].created = touched[entry->second].created && add && change.sourceCreated;
          }
          return std::move(outcome.result);
        }
        catch (...)
        {
          return VoidResult{current_exception_status()};
        }
      }();
      result.items.push_back(std::move(item));
    }
  }
  catch (...)
  {
    result = failed_answer<BatchResult<VoidResult>>(current_exception_status());
    touched.clear();
  }
  if (touched.empty())
  {
    detail::invoke_user_callback(std::move(complete), std::move(result), std::vector<VersionedNode>{});
    return;
  }
  // A change stored whose source's NodeVersion cannot advance keeps its answer: the Reference changed as
  // asked. The NodeVersion that holds another type than String is logged, and the Node is not reported.
  Logger logger = version_logger();
  advance_versions(std::move(touched),
    [complete = std::move(complete), result = std::move(result), logger = std::move(logger)](
      VersionsAdvanced advanced) mutable
    {
      for (const auto& [node, why] : advanced.refused)
      {
        try
        {
          logger.with_category("address_space")
            .warning({{"node", to_string(node)}, {"status", to_string(why)}},
              "A Node's References changed and its NodeVersion could not advance");
        }
        catch (...)
        {
          detail::ignore_expected_exception();
        }
      }
      detail::invoke_user_callback(std::move(complete), std::move(result), std::move(advanced.reported));
    });
}

}  // namespace ua::default_ns
