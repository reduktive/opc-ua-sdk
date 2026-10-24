// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_event_graph_check.h"

#include "ua_browse_direction.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_notifier_type.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_node_description.h"
#include "ua_object_id.h"
#include "ua_reference.h"
#include "ua_reference_type_model.h"
#include "ua_referencetype_id.h"
#include "ua_self_owning_operation.h"
#include "ua_subtype_facts.h"
#include "ua_weak_address_space.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <cstddef>
#include <deque>
#include <exception>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ua::detail
{

namespace
{

namespace namespace_calls = ::ua::namespace_calls;

/// What the rules of Part 3 7.17 and 7.18 read of a Node.
struct NodeFacts
{
  NodeClass nodeClass{NodeClass::Unspecified};
  std::optional<EventNotifierType> eventNotifier;
};

/// Whether a ReferenceType is HasEventSource or a subtype of it, and whether of HasNotifier.
enum class Family : int
{
  None = 0,
  EventSource = 1,
  Notifier = 2
};

/// A Reference as a Node holds it.
struct HeldReference
{
  NodeId holder;
  Reference reference;
};

/// The family of @p type where it is known without a lookup: HasEventSource and HasNotifier themselves, a
/// type already classified, and a namespace-0 type the SDK's model places outside HasEventSource.
std::optional<Family> known_family(
  const NodeId& type, const std::unordered_map<NodeId, Family>& classified) noexcept
{
  try
  {
    static const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
    static const NodeId hasNotifier{ReferenceTypeId::HasNotifier};
    if (type == hasNotifier)
    {
      return Family::Notifier;
    }
    if (type == hasEventSource)
    {
      return Family::EventSource;
    }
    if (const auto found = classified.find(type); found != classified.end())
    {
      return found->second;
    }
    // The model answers false only for a namespace-0 type it knows to be outside the hint; a type it does not
    // know is walked.
    if (type.namespace_index() == 0 && !reference_type_may_match_hint(type, std::span{&hasEventSource, 1}))
    {
      return Family::None;
    }
  }
  catch (...)
  {
    ignore_expected_exception();
  }
  return std::nullopt;
}

/// The facts of a Node the lookup found.
std::optional<NodeFacts> facts_of(const NodeAccessor& node) noexcept
{
  const auto described = NodeAccessorRoute::attributes(node);
  if (!described.is_good())
  {
    return std::nullopt;
  }
  return NodeFacts{described.value().node_class(), described.value().event_notifier()};
}

bool subscribable(const NodeFacts& facts) noexcept
{
  return facts.eventNotifier.has_value() &&
         facts.eventNotifier->test(EventNotifierType::Bit::SubscribeToEvents);
}

/// One event-family Reference between two Nodes, from its source to its target.
struct EventEdge
{
  NodeId source;
  NodeId target;
  NodeId referenceType;
};

/// The rules of Part 3 7.17 and 7.18 on @p references, each of an event-family type, given the facts of every
/// Node found: each end resolves, the source is a source of Events and the target of a HasNotifier is a
/// subscribable Object, and following them never returns to a Node. A Reference with an end in @p unread,
/// whose lookup failed for a reason other than the Node not existing, is not checked. Good, or the first
/// violation.
VoidResult validate(const std::vector<HeldReference>& references,
  const std::unordered_map<NodeId, Family>& classified, const std::unordered_map<NodeId, NodeFacts>& facts,
  const std::unordered_set<NodeId>& unread)
{
  std::vector<EventEdge> edges;
  edges.reserve(references.size());
  for (const auto& [holder, reference] : references)
  {
    if (!reference.target_id().is_local() || !reference.target_id().is_index_based())
    {
      return VoidResult{Status::BadReferenceNotAllowed,
        ErrorDetail::build("EventReferenceEndpointUnavailable",
          "An event-family reference endpoint cannot be resolved in this address space",
          "AddressSpace")
          .context(ContextKeys::nodeId, reference.target_id())
          .context(ContextKeys::actual, reference.type_id())};
    }
    const NodeId& otherId = reference.target_id().node_id();
    const NodeId& sourceId = reference.is_forward() ? holder : otherId;
    const NodeId& targetId = reference.is_forward() ? otherId : holder;
    if (unread.contains(sourceId) || unread.contains(targetId))
    {
      continue;
    }
    const auto source = facts.find(sourceId);
    const auto target = facts.find(targetId);
    if (source == facts.end())
    {
      return VoidResult{Status::BadReferenceNotAllowed,
        ErrorDetail::build("EventReferenceSourceUnavailable",
          "The event reference source cannot be resolved in this address space",
          "AddressSpace")
          .context(ContextKeys::nodeId, sourceId)
          .context(ContextKeys::actual, reference.type_id())};
    }
    if (target == facts.end())
    {
      return VoidResult{Status::BadReferenceNotAllowed,
        ErrorDetail::build("EventReferenceTargetUnavailable",
          "The event reference target cannot be resolved in this address space",
          "AddressSpace")
          .context(ContextKeys::nodeId, targetId)
          .context(ContextKeys::actual, reference.type_id())};
    }

    const bool notifierFamily = classified.at(reference.type_id()) == Family::Notifier;
    const bool validEventSource =
      source->second.nodeClass == NodeClass::ObjectType ||
      ((source->second.nodeClass == NodeClass::Object || source->second.nodeClass == NodeClass::View) &&
        subscribable(source->second));
    const bool validNotifierSource =
      source->second.nodeClass == NodeClass::Object && subscribable(source->second);
    if ((notifierFamily && !validNotifierSource) || (!notifierFamily && !validEventSource))
    {
      return VoidResult{Status::BadReferenceNotAllowed,
        ErrorDetail::build("EventReferenceSourceNotSubscribable",
          "The event reference source does not satisfy its inherited constraints",
          "AddressSpace")
          .context(ContextKeys::nodeId, sourceId)
          .context(ContextKeys::actual, reference.type_id())};
    }
    if (notifierFamily && (target->second.nodeClass != NodeClass::Object || !subscribable(target->second)))
    {
      return VoidResult{Status::BadReferenceNotAllowed,
        ErrorDetail::build("EventReferenceTargetNotSubscribable",
          "The HasNotifier target is not a subscribable Object",
          "AddressSpace")
          .context(ContextKeys::nodeId, targetId)
          .context(ContextKeys::actual, reference.type_id())};
    }
    edges.push_back(EventEdge{sourceId, targetId, reference.type_id()});
  }

  // A loop is what is left when every Node no edge reaches is taken away, repeatedly (Kahn). Both halves of a
  // Reference may be among the edges; a repeated edge changes no count that matters.
  std::unordered_map<NodeId, std::vector<std::size_t>> outgoing;
  std::unordered_map<NodeId, std::size_t> indegree;
  for (std::size_t index = 0; index < edges.size(); ++index)
  {
    outgoing[edges[index].source].push_back(index);
    ++indegree[edges[index].target];
    indegree.try_emplace(edges[index].source, 0);
  }
  std::deque<NodeId> ready;
  for (const auto& [nodeId, degree] : indegree)
  {
    if (degree == 0)
    {
      ready.push_back(nodeId);
    }
  }
  std::size_t removedNodes = 0;
  while (!ready.empty())
  {
    const NodeId nodeId = std::move(ready.front());
    ready.pop_front();
    ++removedNodes;
    const auto leaving = outgoing.find(nodeId);
    if (leaving == outgoing.end())
    {
      continue;
    }
    for (const std::size_t edgeIndex : leaving->second)
    {
      auto& targetDegree = indegree[edges[edgeIndex].target];
      if (--targetDegree == 0)
      {
        ready.push_back(edges[edgeIndex].target);
      }
    }
  }
  if (removedNodes != indegree.size())
  {
    const auto closing = std::ranges::find_if(edges,
      [&indegree](const EventEdge& edge)
      { return indegree[edge.source] != 0 && indegree[edge.target] != 0; });
    const EventEdge& edge = closing != edges.end() ? *closing : edges.front();
    const StatusCode targetCause{Status::BadReferenceNotAllowed,
      ErrorDetail::build("EventReferenceCycleTarget",
        "The event-family reference reaches a node already retained in the cyclic remainder",
        "AddressSpace")
        .context(ContextKeys::nodeId, edge.target)};
    return VoidResult{Status::BadReferenceNotAllowed,
      ErrorDetail::build(
        "EventReferenceCycle", "The event-family reference graph contains a cycle", "AddressSpace")
        .context(ContextKeys::nodeId, edge.source)
        .context(ContextKeys::actual, edge.referenceType)
        .cause(targetCause)};
  }
  return {};
}

/// The check of @ref check_event_graph, on a strand of its own.
///
/// @see ua::async::SelfOwningOperation
class EventGraphCheck final : public ua::async::SelfOwningOperation<EventGraphCheck>
{
public:
  EventGraphCheck(const AddressSpace& addressSpace, std::optional<uint32_t> maxNodesPerBrowse,
    std::function<void(VoidResult)> complete)
    : ua::async::SelfOwningOperation<EventGraphCheck>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mMaxNodesPerBrowse(maxNodesPerBrowse),
      mComplete(std::move(complete))
  {}

  static void start(const AddressSpace& addressSpace, std::optional<uint32_t> maxNodesPerBrowse,
    std::function<void(VoidResult)> complete)
  {
    launch(std::make_shared<EventGraphCheck>(addressSpace, maxNodesPerBrowse, std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<EventGraphCheck>;

  ua::async::Task<> run()
  {
    try
    {
      co_await run_checked();
    }
    catch (const ua::async::Abandoned& abandoned)
    {
      // Answered, not rethrown: this is the root task, and its caller is owed exactly one answer (R16).
      finish(VoidResult{abandoned.status_code()});
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  ua::async::Task<> run_checked()
  {
    // 1. Every namespace's NodeIds. Each step locks the address space for its own call only.
    std::size_t namespaceCount = 0;
    {
      const auto owner = mAddressSpace.lock();
      if (!owner)
      {
        finish(VoidResult{address_space_gone("AddressSpace")});
        co_return;
      }
      namespaceCount = owner->namespace_array().get_namespace_array().size();
    }
    std::vector<NodeId> frontier;
    std::unordered_set<NodeId> visited;
    for (std::size_t index = 0; index < namespaceCount && index <= UINT16_MAX; ++index)
    {
      const auto namespaceIndex = static_cast<uint16_t>(index);
      bool registered = false;
      auto listed = co_await await_step<Result<std::vector<NodeId>>>(
        [this, namespaceIndex, &registered](auto completion)
        {
          auto owner = mAddressSpace.lock();
          if (!owner)
          {
            completion(Result<std::vector<NodeId>>{address_space_gone("AddressSpace")});
            return;
          }
          // An index whose URI is known but holds no namespace has no Nodes to enumerate.
          registered = owner->namespace_array().get_namespace(namespaceIndex) != nullptr;
          if (!registered)
          {
            completion(Result<std::vector<NodeId>>{std::vector<NodeId>{}});
            return;
          }
          owner->enumerate_nodes_async(namespaceIndex, std::move(completion));
        });
      if (gone())
      {
        co_return;
      }
      if (!listed.is_good())
      {
        if (registered)
        {
          mDeclined.push_back(namespaceIndex);
          // A namespace that does not list its Nodes is reported by its index; one whose listing failed also
          // by why.
          if (listed.status_code() != Status::BadNotSupported)
          {
            note_gap(listed.status_code());
          }
        }
        continue;
      }
      for (auto& nodeId : listed.value())
      {
        if (visited.insert(nodeId).second)
        {
          frontier.push_back(std::move(nodeId));
        }
      }
    }
    // The Server Object is the root notifier (OPC 10000-5 8.3.2), read whether or not namespace 0 enumerates.
    const NodeId server{ObjectId::Server};
    if (visited.insert(server).second)
    {
      frontier.push_back(server);
    }

    // 2. A round per step of reachability into the namespaces that declined.
    while (!frontier.empty())
    {
      auto found = co_await await_step<std::vector<NodeAccessorResult>>(
        [this, &frontier](auto completion)
        {
          const auto owner = mAddressSpace.lock();
          if (!owner)
          {
            completion(std::vector<NodeAccessorResult>{});
            return;
          }
          namespace_calls::find_nodes(*owner, RequestInfo{}, frontier, std::move(completion));
        });
      if (gone())
      {
        co_return;
      }
      std::vector<namespace_calls::ReferenceRead> reads;
      std::vector<NodeId> readFor;
      for (std::size_t i = 0; i < frontier.size(); ++i)
      {
        if (i >= found.size())
        {
          note_gap(StatusCode{Status::BadInternalError});
          break;
        }
        // A Node deleted since its namespace listed it, or a Server Object the address space does not hold,
        // has no References to read; an endpoint that names it is found unresolved in step 4.
        if (!found[i].is_good())
        {
          if (found[i].status_code() != Status::BadNodeIdUnknown)
          {
            note_gap(found[i].status_code());
          }
          continue;
        }
        if (auto nodeFacts = facts_of(found[i].value()))
        {
          mFacts.insert_or_assign(frontier[i], *nodeFacts);
        }
        reads.push_back(namespace_calls::ReferenceRead{found[i].value(),
          frontier[i],
          BrowseDirection::Both,
          NodeId{ReferenceTypeId::HasEventSource},
          {NodeId{ReferenceTypeId::HasNotifier}},
          /*subtypes=*/true});
        readFor.push_back(frontier[i]);
      }
      frontier.clear();
      if (reads.empty())
      {
        break;
      }
      auto references = co_await await_step<std::vector<Result<std::vector<Reference>>>>(
        [this, &reads](auto completion)
        {
          const auto owner = mAddressSpace.lock();
          if (!owner)
          {
            completion(std::vector<Result<std::vector<Reference>>>{});
            return;
          }
          namespace_calls::read_references(
            *owner, RequestInfo{}, std::move(reads), mMaxNodesPerBrowse, std::move(completion));
        });
      if (gone())
      {
        co_return;
      }
      std::vector<HeldReference> retainedReferences;
      std::vector<NodeId> unknownTypes;
      std::unordered_set<NodeId> asked;
      for (std::size_t r = 0; r < readFor.size(); ++r)
      {
        if (r >= references.size())
        {
          note_gap(StatusCode{Status::BadInternalError});
          break;
        }
        if (!references[r].is_good())
        {
          note_gap(references[r].status_code());
          continue;
        }
        for (auto& reference : references[r].value())
        {
          if (!known_family(reference.type_id(), mClassified) && asked.insert(reference.type_id()).second)
          {
            unknownTypes.push_back(reference.type_id());
          }
          retainedReferences.push_back(HeldReference{readFor[r], std::move(reference)});
        }
      }

      // 3. The ReferenceTypes not known without a lookup, walked up their supertypes together.
      if (!unknownTypes.empty())
      {
        co_await classify(std::move(unknownTypes));
        if (gone())
        {
          co_return;
        }
      }

      // The event-family References found, and the Nodes of namespaces that declined that they reach.
      for (auto& entry : retainedReferences)
      {
        const auto family = known_family(entry.reference.type_id(), mClassified);
        if (!family || *family == Family::None)
        {
          continue;
        }
        mClassified.try_emplace(entry.reference.type_id(), *family);
        const ExpandedNodeId& other = entry.reference.target_id();
        if (other.is_local() && other.is_index_based() &&
            std::ranges::find(mDeclined, other.node_id().namespace_index()) != mDeclined.end() &&
            visited.insert(other.node_id()).second)
        {
          frontier.push_back(other.node_id());
        }
        mEventReferences.push_back(std::move(entry));
      }
    }

    // 4. The endpoints not looked up yet, for their facts; one that is not found stays unresolved.
    std::vector<NodeId> endpoints;
    std::unordered_set<NodeId> listedEndpoints;
    for (const auto& entry : mEventReferences)
    {
      const ExpandedNodeId& other = entry.reference.target_id();
      if (other.is_local() && other.is_index_based() && !mFacts.contains(other.node_id()) &&
          listedEndpoints.insert(other.node_id()).second)
      {
        endpoints.push_back(other.node_id());
      }
    }
    if (!endpoints.empty())
    {
      auto found = co_await await_step<std::vector<NodeAccessorResult>>(
        [this, &endpoints](auto completion)
        {
          const auto owner = mAddressSpace.lock();
          if (!owner)
          {
            completion(std::vector<NodeAccessorResult>{});
            return;
          }
          namespace_calls::find_nodes(*owner, RequestInfo{}, endpoints, std::move(completion));
        });
      if (gone())
      {
        co_return;
      }
      for (std::size_t i = 0; i < endpoints.size(); ++i)
      {
        // Not fatal: an endpoint that does not exist is reported by the endpoint rules below; one whose
        // lookup failed otherwise is not checked, and the check answers that not all of the graph was read.
        if (i >= found.size() || !found[i].is_good())
        {
          const auto failure =
            i < found.size() ? found[i].status_code() : StatusCode{Status::BadInternalError};
          if (failure != Status::BadNodeIdUnknown)
          {
            mUnread.insert(endpoints[i]);
            note_gap(failure);
          }
          continue;
        }
        if (auto nodeFacts = facts_of(found[i].value()))
        {
          mFacts.insert_or_assign(endpoints[i], *nodeFacts);
        }
      }
    }

    // 5 and 6. The rules in memory; then Good, or what was not read.
    auto verdict = validate(mEventReferences, mClassified, mFacts, mUnread);
    if (verdict.is_bad() || (mDeclined.empty() && !mFirstGap))
    {
      finish(std::move(verdict));
      co_return;
    }
    auto detail = ErrorDetail::build("EventGraphNotFullyChecked",
      "Part of the event-source graph could not be read, and the part read holds no violation",
      "AddressSpace");
    if (!mDeclined.empty())
    {
      std::string declined;
      for (const uint16_t index : mDeclined)
      {
        declined += (declined.empty() ? "" : ", ") + std::to_string(index);
      }
      detail.context(ContextKeys::namespaceIndex, std::move(declined));
    }
    if (mFirstGap)
    {
      detail.cause(*mFirstGap);
    }
    finish(VoidResult{StatusCode{Status::UncertainNotAllNodesAvailable,
      static_cast<std::shared_ptr<const ErrorDetail>>(std::move(detail))}});
  }

  /// Classifies @p types by walking their supertypes: one lookup of the types, then their chains together. A
  /// type that does not exist, or whose chain ends without reaching HasEventSource, is not event-family; one
  /// whose lookup or walk failed otherwise is not either, and is a gap.
  ua::async::Task<> classify(std::vector<NodeId> types)
  {
    auto found = co_await await_step<std::vector<NodeAccessorResult>>(
      [this, &types](auto completion)
      {
        const auto owner = mAddressSpace.lock();
        if (!owner)
        {
          completion(std::vector<NodeAccessorResult>{});
          return;
        }
        namespace_calls::find_nodes(*owner, RequestInfo{}, types, std::move(completion));
      });
    if (!mAddressSpace.lock())
    {
      co_return;
    }
    std::vector<std::pair<NodeAccessor, NodeId>> starts;
    std::vector<NodeId> walked;
    for (std::size_t i = 0; i < types.size(); ++i)
    {
      if (i >= found.size() || !found[i].is_good())
      {
        if (i >= found.size() || found[i].status_code() != Status::BadNodeIdUnknown)
        {
          note_gap(i < found.size() ? found[i].status_code() : StatusCode{Status::BadInternalError});
        }
        mClassified.insert_or_assign(types[i], Family::None);
        continue;
      }
      starts.emplace_back(found[i].value(), types[i]);
      walked.push_back(types[i]);
    }
    if (starts.empty())
    {
      co_return;
    }
    // The walk's check runs on the namespaces' threads, so it reads a copy of what is classified.
    auto classified = std::make_shared<const std::unordered_map<NodeId, Family>>(mClassified);
    auto ends = co_await await_step<std::vector<::ua::SupertypeWalkEnd>>(
      [this, &starts, classified](auto completion)
      {
        const auto owner = mAddressSpace.lock();
        if (!owner)
        {
          completion(std::vector<::ua::SupertypeWalkEnd>{});
          return;
        }
        ::ua::walk_supertypes(
          *owner,
          RequestInfo{},
          std::move(starts),
          ::ua::maxTypeWalkDepth,
          [classified](std::size_t, const NodeId& type) -> std::optional<int>
          {
            const auto family = known_family(type, *classified);
            return family ? std::optional<int>{static_cast<int>(*family)} : std::nullopt;
          },
          std::move(completion));
      });
    using How = ::ua::SupertypeWalkEnd::How;
    for (std::size_t s = 0; s < walked.size(); ++s)
    {
      const NodeId& type = walked[s];
      if (s >= ends.size())
      {
        note_gap(StatusCode{Status::BadInternalError});
        mClassified.insert_or_assign(type, Family::None);
        continue;
      }
      if (ends[s].how == How::Decided)
      {
        mClassified.insert_or_assign(type, static_cast<Family>(ends[s].value));
        continue;
      }
      // A supertype that does not exist ends the chain as one without a supertype does.
      if (ends[s].how == How::Failed && ends[s].failure != Status::BadNodeIdUnknown)
      {
        note_gap(ends[s].failure);
      }
      mClassified.insert_or_assign(type, Family::None);
    }
  }

  /// Whether the address space has gone; if so, the check is answered.
  bool gone()
  {
    if (mAddressSpace.lock())
    {
      return false;
    }
    finish(VoidResult{address_space_gone("AddressSpace")});
    return true;
  }

  void note_gap(StatusCode status)
  {
    if (!mFirstGap)
    {
      mFirstGap = std::move(status);
    }
  }

  void fail_to_start(StatusCode status)
  {
    finish(VoidResult{std::move(status)});
  }

  void finish(VoidResult verdict)
  {
    auto complete = std::move(mComplete);
    mComplete = nullptr;
    if (complete)
    {
      invoke_user_callback(mLogger, complete, std::move(verdict));
    }
  }

  WeakAddressSpace mAddressSpace;
  std::optional<uint32_t> mMaxNodesPerBrowse;
  std::function<void(VoidResult)> mComplete;
  std::vector<uint16_t> mDeclined;
  std::optional<StatusCode> mFirstGap;
  std::unordered_map<NodeId, NodeFacts> mFacts;
  std::unordered_set<NodeId> mUnread;
  std::unordered_map<NodeId, Family> mClassified;
  std::vector<HeldReference> mEventReferences;
};

}  // namespace

void check_event_graph(const AddressSpace& addressSpace, std::optional<uint32_t> maxNodesPerBrowse,
  std::function<void(VoidResult)> complete) noexcept
{
  try
  {
    EventGraphCheck::start(addressSpace, maxNodesPerBrowse, complete);
  }
  catch (...)
  {
    invoke_user_callback(complete, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua::detail
