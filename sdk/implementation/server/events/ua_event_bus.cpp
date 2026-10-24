// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_event_bus.h"

#include "ua_self_owning_operation.h"

#include "ua_callback_safety.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail_keys.h"
#include "ua_event_notifier_type.h"
#include "ua_exceptions.h"
#include "ua_log_exception.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_object_id.h"
#include "ua_on_strand.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_subtype_facts.h"
#include "ua_to_string.h"
#include <boost/asio/post.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ua::server
{

namespace
{

const NodeId serverObjectId{ObjectId::Server};
const NodeId hasNotifierTypeId{ReferenceTypeId::HasNotifier};
const NodeId hasEventSourceTypeId{ReferenceTypeId::HasEventSource};

/// Data needed to deliver an event to a registered monitored item.
struct RegistrationSnapshot
{
  NodeId monitoredNode;
  IntegerId monitoredItemId;
  EventDeliveryCallback callback;
  bool requiresDeclarationModel{false};
};

/// Works out who should receive one Event, and delivers it to them.
///
/// Two steps. The climb finds the notifier set from the Event's SourceNode a level at a time: the Nodes of a
/// level are looked up with one call per namespace, and their inverse References read with one call per
/// namespace, hinted {HasEventSource, HasNotifier} (NR-28, NR-61). Then each View an item monitors is asked,
/// in one membership call naming every notifier, whether it contains one.
///
/// Runs on the bus dispatch strand, and `await_step` posts every answer onto it, so a namespace that answers
/// inline does not recurse through a deep notifier hierarchy. The bus guarantees only one of these is in
/// flight at a time, so per-emit completion order still matches submission order (Part 4 5.12.1.5).
///
/// The climb is best-effort throughout: a Node that will not resolve, whose References cannot be read, or
/// that throws because it was soft-deleted underneath us, is not climbed further rather than failing the
/// delivery. A climb lookup, References read or validation that fails with `Bad_NodeIdUnknown` is logged at
/// Debug, since a namespace may refuse NodeIds that are not its own; any other climb failure at Warning. The
/// calls carry the server's own `RequestInfo` and no caller: lookups, References and membership do not depend
/// on one (NR-8, NR-16 rule 2).
/// @see ua::async::SelfOwningOperation
class DispatchEventOperation final : public ua::async::SelfOwningOperation<DispatchEventOperation>
{
public:
  DispatchEventOperation(AddressSpace addressSpace, std::shared_ptr<BaseEvent> event,
    std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel,
    std::vector<RegistrationSnapshot> snapshot, boost::asio::strand<boost::asio::any_io_executor> strand,
    std::shared_ptr<EventSourceTypeCache> eventSourceTypes, std::function<void()> onComplete)
    : ua::async::SelfOwningOperation<DispatchEventOperation>(
        std::move(strand), addressSpace.logger().with_category("events")),
      mAddressSpace(addressSpace.weak()), mEvent(std::move(event)),
      mDeclarationModel(std::move(declarationModel)), mRegistrySnapshot(std::move(snapshot)),
      mEventSourceTypes(std::move(eventSourceTypes)), mOnComplete(std::move(onComplete)),
      mNotifierSet{serverObjectId},  // SVR-EVT-SRV-002: always include Server Object
      mTraversalLimit(EncodingLimits{}.execution.loopLimit)
  {}

  static void run(AddressSpace addressSpace, std::shared_ptr<BaseEvent> event,
    std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel,
    std::vector<RegistrationSnapshot> registrySnapshot,
    boost::asio::strand<boost::asio::any_io_executor> strand,
    std::shared_ptr<EventSourceTypeCache> eventSourceTypes, std::function<void()> onComplete)
  {
    launch(std::make_shared<DispatchEventOperation>(std::move(addressSpace),
      std::move(event),
      std::move(declarationModel),
      std::move(registrySnapshot),
      std::move(strand),
      std::move(eventSourceTypes),
      std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<DispatchEventOperation>;

  /// One page after another of each Node's References, until its namespace answers no resume token.
  using ReferencePages = std::vector<ua::References>;

  /// Whether a Reference of namespace-0 type @p referenceType carries Events from its target to its
  /// source (Part 3 7.18, 5.3.3.3): HasEventSource and its namespace-0 subtypes, which are HasNotifier alone.
  static bool is_namespace_zero_event_source_type(const NodeId& referenceType) noexcept
  {
    return referenceType == hasNotifierTypeId || referenceType == hasEventSourceTypeId;
  }

  /// Whether the climb may follow @p reference to its target: an inverse Reference to a local Node.
  static bool climbs(const Reference& reference)
  {
    return !reference.is_forward() && !reference.is_remote() && reference.target_id().is_local();
  }

  const Logger& events_logger() const noexcept
  {
    return mLogger;
  }

  /// Logs a climb lookup, References read or validation that failed with @p status: at Debug when it is
  /// `Bad_NodeIdUnknown`, since a namespace may refuse NodeIds that are not its own, otherwise at Warning
  /// (COMP-SVR-NAMESPACE-CALLS-12 rule 2).
  void log_climb_failure(const char* site, const StatusCode& status) const
  {
    const LogLevel level =
      status.as_status() == Status::BadNodeIdUnknown ? LogLevel::Debug : LogLevel::Warning;
    log_exception(events_logger(), level, site, status);
  }

  /// Whether application ReferenceType @p referenceType is a subtype of HasEventSource, as decided for this
  /// model generation; `nullopt` when it is not decided.
  std::optional<bool> decided_event_source_type(const NodeId& referenceType) const
  {
    return mEventSourceTypes->subtypes->lookup(std::make_pair(referenceType, hasEventSourceTypeId));
  }

  /// A ReferenceType that could not be decided is not followed, and its failure is logged once per type per
  /// model generation, so an Event storm through a broken type cannot log once per Event (DL-9). A type that
  /// does not exist, or whose supertype does not exist (`Bad_NodeIdUnknown`), is not followed for the rest of
  /// the model generation, as the climb before level batching kept it; any other failure, an Uncertain answer
  /// included, may pass, so only this Event's climb leaves the type undecided.
  void fail_event_source_type(const NodeId& referenceType, const StatusCode& status)
  {
    if (status.as_status() == Status::BadNodeIdUnknown)
    {
      mEventSourceTypes->subtypes->store(std::make_pair(referenceType, hasEventSourceTypeId), false);
    }
    else
    {
      mUndecidableTypes.insert(referenceType);
    }
    if (mEventSourceTypes->failuresLogged.insert(referenceType).second)
    {
      log_exception(events_logger(), LogLevel::Warning, "EventBus.EventSourceReferenceType", status);
    }
  }

  ua::async::Task<> run()
  {
    try
    {
      co_await climb();
      co_await add_views();
      deliver();
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      log_exception(events_logger(), LogLevel::Warning, "EventBus.Dispatch", std::current_exception());
      deliver();
    }
    co_return;
  }

  /// Climbs the HasEventSource family from the Event's SourceNode, a level at a time, adding each Object or
  /// View with SubscribeToEvents it reaches to the notifier set.
  ua::async::Task<> climb()
  {
    // An Event that is not specific to a Node has a null SourceNode (OPC 10000-5 6.4.2). It is not looked up:
    // the climb starts with no level, and the Server Object remains its notifier.
    std::vector<NodeId> level;
    if (!mEvent->sourceNode.is_null())
    {
      level.push_back(mEvent->sourceNode);
    }
    std::unordered_set<NodeId> visited;
    bool budgetSpent = false;
    while (!level.empty() && !budgetSpent)
    {
      // The level's Nodes not visited yet, in level order, one budget unit each. The Server Object is the
      // root of the event hierarchy (Part 9 6.2) and is in every notifier set; continuing above it would give
      // every Event of the Server to whatever references it, so it is neither looked up nor read. Exhausting
      // the budget stops the CLIMB, not the delivery: the notifiers found so far are still the right
      // recipients, and dropping the Event as well would turn a bounded traversal into lost data.
      std::vector<NodeId> nodeIds;
      for (auto& nodeId : level)
      {
        if (nodeId == serverObjectId || !visited.insert(nodeId).second)
        {
          continue;
        }
        try
        {
          mTraversalLimit.consume_iteration();
        }
        catch (...)
        {
          log_exception(events_logger(),
            LogLevel::Warning,
            "EventBus.NotifierClimbTraversalBudget",
            std::current_exception());
          budgetSpent = true;
          break;
        }
        nodeIds.push_back(std::move(nodeId));
      }
      if (nodeIds.empty())
      {
        co_return;
      }

      // One lookup per namespace. A Node that does not resolve is skipped: a namespace may refuse NodeIds
      // that are not its own.
      auto found = co_await await_step<std::vector<NodeAccessorResult>>(
        [this, &nodeIds](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            namespace_calls::find_nodes(*addressSpace, RequestInfo{}, nodeIds, std::move(completion));
          else
            completion(std::vector<NodeAccessorResult>(
              nodeIds.size(), NodeAccessorResult{ua::detail::address_space_gone("EventBus")}));
        });

      std::vector<NodeAccessor> toRead;
      std::vector<NodeId> toReadIds;
      for (std::size_t k = 0; k < nodeIds.size() && k < found.size(); ++k)
      {
        if (!found[k].is_good())
        {
          log_climb_failure("EventBus.NotifierClimbLookup", found[k].status_code());
          continue;
        }
        NodeAccessor node = std::move(found[k]).value();
        // Node accessors may throw BadNodeIdUnknown if the underlying Node has been soft-deleted concurrently
        // (a race against NodeManagement or role teardown); any throw skips the Node.
        try
        {
          // An ObjectType's References describe its instances (Part 3 7.17), so the climb does not pass it.
          if (node.get_node_class() == NodeClass::ObjectType)
          {
            continue;
          }
          bool subscribable = false;
          if (auto objectAccessor = node.as<ObjectAccessor>())
          {
            subscribable =
              objectAccessor->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents);
          }
          else if (auto viewAccessor = node.as<ViewAccessor>())
          {
            subscribable = viewAccessor->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents);
          }
          if (subscribable &&
              std::find(mNotifierSet.begin(), mNotifierSet.end(), nodeIds[k]) == mNotifierSet.end())
          {
            mNotifierSet.push_back(nodeIds[k]);
          }
        }
        catch (...)
        {
          log_climb_failure(
            "EventBus.NotifierClimbValidation", exception_to_status_code(std::current_exception()));
          continue;
        }
        toRead.push_back(std::move(node));
        toReadIds.push_back(nodeIds[k]);
      }
      // A level cut by the budget is the last: what lies above it is not climbed.
      if (budgetSpent || toRead.empty())
      {
        co_return;
      }

      const auto references = co_await read_inverse_references(std::move(toRead), std::move(toReadIds));

      // A Reference is followed when its type carries Events from its target to its source: a namespace-0
      // type by its NodeId, an application type by its supertypes (DL-9). The application types this level
      // names that are not decided for this model generation are decided together.
      std::vector<NodeId> undecided;
      std::unordered_set<NodeId> named;
      for (const auto& pages : references)
      {
        if (!pages)
        {
          continue;
        }
        for (const auto& page : *pages)
        {
          for (const auto& reference : page)
          {
            const NodeId& type = reference.type_id();
            if (climbs(reference) && type.namespace_index() != 0 && !mUndecidableTypes.contains(type) &&
                !decided_event_source_type(type) && named.insert(type).second)
            {
              undecided.push_back(type);
            }
          }
        }
      }
      if (!undecided.empty())
      {
        co_await decide_event_source_types(std::move(undecided));
      }

      // The next level: the targets followed, in answer order; a target already visited is dropped there.
      std::vector<NodeId> next;
      for (const auto& pages : references)
      {
        if (!pages)
        {
          continue;
        }
        for (const auto& page : *pages)
        {
          for (const auto& reference : page)
          {
            if (!climbs(reference))
            {
              continue;
            }
            const NodeId& type = reference.type_id();
            const bool followed = type.namespace_index() == 0
                                    ? is_namespace_zero_event_source_type(type)
                                    : decided_event_source_type(type).value_or(false);
            if (followed)
            {
              next.push_back(reference.target_id().node_id());
            }
          }
        }
      }
      level = std::move(next);
    }
  }

  /// The inverse References of @p nodes (whose NodeIds are @p nodeIds), hinted {HasEventSource, HasNotifier}:
  /// one read per namespace, then again for the Nodes a namespace answered with a resume token, until none is
  /// left. A Node whose read is not Good has no answer (`nullopt`). So has one whose namespace answers
  /// `maxEmptyReferencePages` pages in a row with a token and no References: its last token is released and
  /// the failure logged (DL-67 (8)). An answer that holds a Reference starts the count again.
  ua::async::Task<std::vector<std::optional<ReferencePages>>> read_inverse_references(
    std::vector<NodeAccessor> nodes, std::vector<NodeId> nodeIds)
  {
    struct Paging
    {
      ua::detail::ResumeToken token;
      std::size_t emptyPages{0};
    };

    std::vector<std::optional<ReferencePages>> answers(
      nodes.size(), std::optional<ReferencePages>{std::in_place});
    std::vector<Paging> paging(nodes.size());
    std::vector<std::size_t> pending(nodes.size());
    std::iota(pending.begin(), pending.end(), std::size_t{0});
    while (!pending.empty())
    {
      // A token sent is consumed by the call whatever it answers, so it is no longer this climb's to release.
      std::vector<ua::detail::ReferenceRead> reads;
      reads.reserve(pending.size());
      for (const std::size_t k : pending)
      {
        reads.push_back(ua::detail::ReferenceRead{nodes[k],
          BrowseDirection::Inverse,
          {hasEventSourceTypeId, hasNotifierTypeId},
          0,
          std::move(paging[k].token)});
      }
      auto pages = co_await await_step<std::vector<ua::detail::ReferencePage>>(
        [this, &reads](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            ua::detail::NodeAccessorRoute::read_references(
              RequestInfo{}, std::move(reads), std::move(completion), mAddressSpace);
            return;
          }
          const StatusCode ownerGone = ua::detail::address_space_gone("EventBus");
          std::vector<ua::detail::ReferencePage> stopped;
          stopped.reserve(reads.size());
          for (auto& read : reads)
          {
            if (auto token = std::get_if<ua::detail::ResumeToken>(&read.resumeToken))
              token->release();
            stopped.push_back({NodeReferencesResult{ownerGone}, {}});
          }
          completion(std::move(stopped));
        });
      if (pages.size() != pending.size())
      {
        // The pages could not be allocated; the route released the tokens answered.
        log_exception(events_logger(),
          LogLevel::Warning,
          "EventBus.NotifierClimbReferences",
          StatusCode{Status::BadOutOfMemory});
        for (const std::size_t k : pending)
        {
          answers[k].reset();
        }
        break;
      }

      std::vector<std::size_t> next;
      for (std::size_t i = 0; i < pending.size(); ++i)
      {
        const std::size_t k = pending[i];
        NodeReferencesResult& answer = pages[i].answer;
        if (!answer.is_good())
        {
          pages[i].resumeToken.release();
          answers[k].reset();
          log_climb_failure("EventBus.NotifierClimbReferences", answer.status_code());
          continue;
        }
        Paging& node = paging[k];
        node.token = std::move(pages[i].resumeToken);
        ua::References& page = answer.value().references;
        node.emptyPages = page.empty() ? node.emptyPages + 1 : 0;
        if (!node.token.empty() && (node.emptyPages >= ua::detail::maxEmptyReferencePages))
        {
          node.token.release();
          answers[k].reset();
          log_exception(events_logger(),
            LogLevel::Warning,
            "EventBus.NotifierClimbReferences",
            StatusCode{Status::BadInternalError,
              ErrorDetail::build("NamespacePagingDidNotEnd",
                "The namespace kept answering resume tokens for the References of a Node",
                "EventBus")
                .context(ua::ContextKeys::nodeId, ua::to_string(nodeIds[k]))
                .context(ua::ContextKeys::limit, std::to_string(ua::detail::maxEmptyReferencePages))});
          continue;
        }
        if (!page.empty())
        {
          answers[k]->push_back(std::move(page));
        }
        if (!node.token.empty())
        {
          next.push_back(k);
        }
      }
      pending = std::move(next);
    }
    co_return std::move(answers);
  }

  /// Decides, for this model generation, whether each of the application ReferenceTypes @p types is a
  /// subtype of HasEventSource: one lookup per namespace, then their supertype chains walked together until
  /// each reaches HasEventSource or HasNotifier (yes) or another namespace-0 type (no). A type whose lookup
  /// or walk fails is handled by @ref fail_event_source_type, with the status of the failure.
  ua::async::Task<> decide_event_source_types(std::vector<NodeId> types)
  {
    auto found = co_await await_step<std::vector<NodeAccessorResult>>(
      [this, &types](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          namespace_calls::find_nodes(*addressSpace, RequestInfo{}, types, std::move(completion));
        else
          completion(std::vector<NodeAccessorResult>(
            types.size(), NodeAccessorResult{ua::detail::address_space_gone("EventBus")}));
      });

    std::vector<std::pair<NodeAccessor, NodeId>> starts;
    std::vector<std::size_t> startOf;
    for (std::size_t k = 0; k < types.size(); ++k)
    {
      if (k >= found.size() || !found[k].is_good())
      {
        fail_event_source_type(
          types[k], k < found.size() ? found[k].status_code() : StatusCode{Status::BadInternalError});
        continue;
      }
      starts.emplace_back(std::move(found[k]).value(), types[k]);
      startOf.push_back(k);
    }
    if (starts.empty())
    {
      co_return;
    }

    std::vector<SupertypeWalkEnd> ends;
    std::optional<StatusCode> walkFailure;
    try
    {
      ends = co_await await_step<std::vector<SupertypeWalkEnd>>(
        [this, &starts](auto completion)
        {
          auto addressSpace = mAddressSpace.lock();
          if (!addressSpace)
          {
            completion(std::vector<SupertypeWalkEnd>(starts.size(),
              SupertypeWalkEnd{
                SupertypeWalkEnd::How::Failed, 0, ua::detail::address_space_gone("EventBus")}));
            return;
          }
          walk_supertypes(
            *addressSpace,
            RequestInfo{},
            std::move(starts),
            EncodingLimits{}.execution.loopLimit,
            [](std::size_t, const NodeId& type) -> std::optional<int>
            {
              if (is_namespace_zero_event_source_type(type))
              {
                return 1;
              }
              if (type.namespace_index() == 0)
              {
                return 0;
              }
              return std::nullopt;
            },
            std::move(completion));
        });
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      walkFailure = exception_to_status_code(std::current_exception());
    }

    for (std::size_t chain = 0; chain < startOf.size(); ++chain)
    {
      const NodeId& type = types[startOf[chain]];
      if (walkFailure)
      {
        fail_event_source_type(type, *walkFailure);
        continue;
      }
      const SupertypeWalkEnd end = chain < ends.size()
                                     ? ends[chain]
                                     : SupertypeWalkEnd{SupertypeWalkEnd::How::Failed,
                                         0,
                                         StatusCode{Status::BadInternalError,
                                           ErrorDetail::build("SupertypeWalkEndMissing",
                                             "The supertype walk answered fewer chains than it was given",
                                             "EventBus")}};
      switch (end.how)
      {
      case SupertypeWalkEnd::How::Decided:
        mEventSourceTypes->subtypes->store(std::make_pair(type, hasEventSourceTypeId), end.value == 1);
        break;
      case SupertypeWalkEnd::How::NoSuper:
        mEventSourceTypes->subtypes->store(std::make_pair(type, hasEventSourceTypeId), false);
        break;
      case SupertypeWalkEnd::How::Failed:
        fail_event_source_type(type, end.failure);
        break;
      }
    }
  }

  /// Adds to the notifier set each View an item monitors that contains a notifier. Part 3 5.4: "A View that
  /// supports Events shall provide all Events that occur in any Object used as EventNotifier that is part of
  /// the content of the View"; a View contains what its membership answers, the membership Browse uses.
  ///
  /// The monitored Nodes that are not notifiers are looked up with one call per namespace, and each View with
  /// SubscribeToEvents is asked, in one membership call, about every notifier but the Server Object, which is
  /// a member of no View; the Views are asked together. Routing is best-effort because EventSink::emit has no
  /// failure result: a lookup or a membership answer that is not Good is logged here, while its StatusCode
  /// still owns its ErrorDetail, and read as "not a member".
  ua::async::Task<> add_views()
  {
    std::vector<ExpandedNodeId> subjects;
    for (const auto& notifier : mNotifierSet)
    {
      if (notifier != serverObjectId)
      {
        subjects.emplace_back(notifier);
      }
    }
    if (subjects.empty())
    {
      co_return;
    }

    std::vector<NodeId> candidates;
    for (const auto& item : mRegistrySnapshot)
    {
      if (std::find(mNotifierSet.begin(), mNotifierSet.end(), item.monitoredNode) != mNotifierSet.end() ||
          std::find(candidates.begin(), candidates.end(), item.monitoredNode) != candidates.end())
      {
        continue;
      }
      candidates.push_back(item.monitoredNode);
    }
    if (candidates.empty())
    {
      co_return;
    }

    auto found = co_await await_step<std::vector<NodeAccessorResult>>(
      [this, &candidates](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          namespace_calls::find_nodes(*addressSpace, RequestInfo{}, candidates, std::move(completion));
        else
          completion(std::vector<NodeAccessorResult>(
            candidates.size(), NodeAccessorResult{ua::detail::address_space_gone("EventBus")}));
      });

    std::vector<NodeAccessor> views;
    std::vector<NodeId> viewIds;
    for (std::size_t k = 0; k < candidates.size() && k < found.size(); ++k)
    {
      if (!found[k].is_good())
      {
        log_exception(events_logger(), LogLevel::Warning, "EventBus.ViewLookup", found[k].status_code());
        continue;
      }
      try
      {
        NodeAccessor node = std::move(found[k]).value();
        const auto view = node.as<ViewAccessor>();
        if (!view || !view->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
        {
          continue;
        }
        views.push_back(std::move(node));
        viewIds.push_back(candidates[k]);
      }
      catch (...)
      {
        log_exception(
          events_logger(), LogLevel::Warning, "EventBus.ViewValidation", std::current_exception());
      }
    }
    if (views.empty())
    {
      co_return;
    }

    auto answers = co_await await_step<std::vector<std::vector<BoolResult>>>(
      [this, &views, &subjects](auto completion)
      {
        // Membership is a new operation; a successful View lookup alone did not establish it.
        auto addressSpace = mAddressSpace.lock();
        if (!addressSpace)
        {
          completion(std::vector<std::vector<BoolResult>>(views.size(),
            std::vector<BoolResult>(
              subjects.size(), BoolResult{ua::detail::address_space_gone("EventBus")})));
          return;
        }
        // Each View answers on its namespace's thread; the last answer hands them all back.
        struct Join
        {
          std::function<void(std::vector<std::vector<BoolResult>>)> completion;
          std::vector<std::vector<BoolResult>> answers;
          std::atomic<std::size_t> remaining{0};
        };
        auto join = std::make_shared<Join>();
        join->answers.resize(views.size());
        join->remaining.store(views.size(), std::memory_order_relaxed);
        std::vector<std::vector<ExpandedNodeId>> asked(views.size(), subjects);
        std::vector<std::function<void(std::vector<BoolResult>)>> answered;
        answered.reserve(views.size());
        for (std::size_t v = 0; v < views.size(); ++v)
        {
          answered.emplace_back(
            [join, v](std::vector<BoolResult> answer)
            {
              join->answers[v] = std::move(answer);
              if (join->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1)
              {
                join->completion(std::move(join->answers));
              }
            });
        }
        join->completion = std::move(completion);
        // Everything is built, so every View is asked.
        const RequestInfo request{};
        for (std::size_t v = 0; v < views.size(); ++v)
        {
          ua::detail::NodeAccessorRoute::view_contains(
            request, views[v], std::move(asked[v]), std::move(answered[v]));
        }
      });

    for (std::size_t v = 0; v < views.size(); ++v)
    {
      if (v >= answers.size() || answers[v].size() != subjects.size())
      {
        // The answers could not be allocated.
        log_exception(
          events_logger(), LogLevel::Warning, "EventBus.ViewMembership", StatusCode{Status::BadOutOfMemory});
        continue;
      }
      bool member = false;
      for (const auto& answer : answers[v])
      {
        if (!answer.is_good())
        {
          log_exception(events_logger(), LogLevel::Warning, "EventBus.ViewMembership", answer.status_code());
          continue;
        }
        member = member || answer.value();
      }
      if (member)
      {
        mNotifierSet.push_back(viewIds[v]);
      }
    }
  }

  void fail_to_start(StatusCode)
  {
    deliver();
  }

  void deliver()
  {
    if (!mEvent)
    {
      return;
    }
    auto sharedConst = std::shared_ptr<const BaseEvent>(std::move(mEvent));
    const auto& logger = events_logger();
    for (auto& item : mRegistrySnapshot)
    {
      for (const auto& notifier : mNotifierSet)
      {
        if (item.monitoredNode == notifier)
        {
          ::ua::detail::invoke_user_callback(
            logger, item.callback, item.monitoredItemId, sharedConst, mDeclarationModel);
          break;  // Do not deliver the same event twice to the same registration.
        }
      }
    }
    // Hand control back to the bus so the next pending dispatch task can start. On the dispatch
    // strand.
    if (auto onComplete = std::exchange(mOnComplete, nullptr))
    {
      ::ua::detail::invoke_user_callback(logger, onComplete);
    }
  }

  WeakAddressSpace mAddressSpace;
  std::shared_ptr<BaseEvent> mEvent;
  std::shared_ptr<const event_type_model::DeclarationsResult> mDeclarationModel;
  std::vector<RegistrationSnapshot> mRegistrySnapshot;
  std::shared_ptr<EventSourceTypeCache> mEventSourceTypes;
  std::function<void()> mOnComplete;
  std::vector<NodeId> mNotifierSet;
  /// Application ReferenceTypes this Event's climb could not decide, so not asked about again for it.
  std::unordered_set<NodeId> mUndecidableTypes;
  /// Bounds how much of the address space one Event's climb may traverse: one unit per Node visited.
  ///
  /// The climb already terminates on any graph - it keeps a visited set, so a cycle in the HasNotifier
  /// graph cannot loop it and cannot deliver the same Event twice. What the visited set does not bound is
  /// SIZE: its ceiling is the number of reachable Nodes, so one Event on a pathologically connected address
  /// space could climb a large part of it.
  LoopLimit mTraversalLimit;
};

/// Resolves an EventType's supertype chain (`[eventType, parent, ...,
/// BaseEventType]`) by walking `HasSubtype` upward via the address space, then
/// invokes `mDone` with the immutable chain. Runs on the EventBus dispatch
/// strand; each async hop reposts onto the strand (get_super_type_async may fire
/// inline for in-memory address spaces, so this also breaks any stack recursion).
/// Best-effort: any resolution failure stops the walk and returns the chain
/// gathered so far (at minimum `[eventType]`, so an exact-type match still works).
/// Collects an event type and every supertype above it, nearest first.
///
/// A supertype walk, which the chain expressed as two functions calling each other through a strand
/// repost. It is a `while` loop now; the repost survives as `await_step`'s post, which is what keeps
/// an address space that answers inline from recursing.
///
/// Every failure ends the walk with whatever has been collected so far rather than propagating: an
/// EventType that will not resolve simply has an exact-match-only chain. `mDone` is also told whether the
/// chain is complete: it is not when a lookup failed for a reason other than the Node not existing, and such
/// a chain is not kept for the next Event.
/// @see ua::async::SelfOwningOperation
class ResolveTypeHierarchyOperation final
  : public ua::async::SelfOwningOperation<ResolveTypeHierarchyOperation>
{
public:
  using Done = std::function<void(std::shared_ptr<const std::vector<NodeId>>, bool complete)>;

  ResolveTypeHierarchyOperation(AddressSpace addressSpace, NodeId eventType,
    boost::asio::strand<boost::asio::any_io_executor> strand, Done done)
    : ua::async::SelfOwningOperation<ResolveTypeHierarchyOperation>(
        std::move(strand), addressSpace.logger().with_category("events")),
      mAddressSpace(addressSpace.weak()), mEventType(std::move(eventType)), mDone(std::move(done)),
      mChain(std::make_shared<std::vector<NodeId>>())
  {}

  static void run(AddressSpace addressSpace, NodeId eventType,
    boost::asio::strand<boost::asio::any_io_executor> strand, Done done)
  {
    launch(std::make_shared<ResolveTypeHierarchyOperation>(
      std::move(addressSpace), std::move(eventType), std::move(strand), std::move(done)));
  }

private:
  friend class ua::async::SelfOwningOperation<ResolveTypeHierarchyOperation>;

  ua::async::Task<> run()
  {
    try
    {
      mChain->push_back(mEventType);

      auto node = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_node_async(mEventType, std::move(completion));
          else
            completion(NodeAccessorResult{ua::detail::address_space_gone("EventBus")});
        });
      if (!node.is_good())
      {
        finish(node.status_code());  // Keep the exact-match-only chain and its diagnostic.
        co_return;
      }

      NodeAccessor current = node.value();
      while (true)
      {
        node_utils::OptionalNodeAccessorResult superResult{StatusCode{Status::BadInternalError}};
        try
        {
          superResult = co_await await_step<node_utils::OptionalNodeAccessorResult>(
            [this, current](auto completion) mutable
            {
              if (!current.is_type())
              {
                completion(node_utils::OptionalNodeAccessorResult{optional<NodeAccessor>{std::nullopt}});
                return;
              }
              if (auto addressSpace = mAddressSpace.lock())
                node_utils::get_super_type_async(*addressSpace, std::move(current), std::move(completion));
              else
                completion(
                  node_utils::OptionalNodeAccessorResult{ua::detail::address_space_gone("EventBus")});
            });
        }
        catch (const ua::async::Abandoned&)
        {
          throw;
        }
        catch (const UaException&)
        {
          finish(exception_to_status_code(std::current_exception()));
          co_return;
        }

        if (!superResult.is_good())
        {
          finish(superResult.status_code());
          co_return;
        }
        // Bind the payload optional once (a single value() call) so the engaged check and the deref
        // operate on the same object - the checker cannot tie two separate value() calls together.
        auto& superNodeOpt = superResult.value();
        if (!superNodeOpt.has_value())
        {
          finish();  // reached the root (no supertype).
          co_return;
        }

        auto superNode = std::move(superNodeOpt.value());
        NodeId superId;
        try
        {
          superId = superNode.get_node_id();
        }
        catch (const UaException&)
        {
          finish(exception_to_status_code(std::current_exception()));
          co_return;
        }
        // Cycle guard (malformed hierarchy) - stop if we have already seen this type.
        if (std::find(mChain->begin(), mChain->end(), superId) != mChain->end())
        {
          finish();
          co_return;
        }
        mChain->push_back(std::move(superId));
        current = std::move(superNode);
      }
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      finish(exception_to_status_code(std::current_exception()));
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    finish(std::move(status));
  }

  void finish(std::optional<StatusCode> failure = std::nullopt)
  {
    if (auto done = std::exchange(mDone, nullptr))
    {
      if (failure && mLogger.is_enabled(LogLevel::Warning))
      {
        try
        {
          const auto eventType = to_string(mEventType);
          const auto status = to_string(*failure);
          if (const auto detail = failure->shared_detail())
          {
            const auto error = to_string(*detail);
            mLogger.warning({{"event_type", std::string_view{eventType}},
                              {"status", std::string_view{status}},
                              {"error", std::string_view{error}}},
              "EventBus.EventTypeHierarchy");
          }
          else
          {
            mLogger.warning(
              {{"event_type", std::string_view{eventType}}, {"status", std::string_view{status}}},
              "EventBus.EventTypeHierarchy");
          }
        }
        catch (...)
        {
          // Diagnostic formatting must not prevent delivery of the established best-effort chain.
          ua::async::detail::report_guarded_exception(mLogger, "EventBus.EventTypeHierarchy logging");
        }
      }
      const bool complete = !failure || *failure == Status::BadNodeIdUnknown;
      ::ua::detail::invoke_user_callback(
        mLogger, done, std::shared_ptr<const std::vector<NodeId>>(std::move(mChain)), complete);
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeId mEventType;
  Done mDone;
  std::shared_ptr<std::vector<NodeId>> mChain;
};

}  // namespace

EventBus::EventBus(AddressSpace addressSpace, size_t maxPendingDispatches)
  : mAddressSpace(std::move(addressSpace)),
    mDispatchStrand(boost::asio::make_strand(mAddressSpace.executor())),
    mMaxPendingDispatches(maxPendingDispatches < 1 ? 1 : maxPendingDispatches)
{}

uint64_t EventBus::dropped_dispatch_count() const
{
  return mDroppedDispatchCount.load(std::memory_order_relaxed);
}

void EventBus::enqueue_dispatch_on_strand(DispatchTask task, DroppedEventInfo info)
{
  // Memory backstop: bound the queue of not-yet-started dispatch tasks. A burst of emits faster than
  // dispatch drains would otherwise grow mPendingDispatches without limit. Drop the oldest pending
  // task (it never runs), record the overflow, and report the lost event's identity to the observer
  // so the host can surface the loss (and persist it out-of-band when it is an audit event).
  while (mPendingDispatches.size() >= mMaxPendingDispatches)
  {
    if (mOnDispatchDropped)
    {
      mOnDispatchDropped(mPendingDispatches.front().info);
    }
    mPendingDispatches.pop();  // drop-oldest
    mDroppedDispatchCount.fetch_add(1, std::memory_order_relaxed);
  }

  mPendingDispatches.push({std::move(task), std::move(info)});
  if (!mDispatching)
  {
    start_next_dispatch_on_strand();
  }
}

void EventBus::set_dispatch_dropped_observer(DispatchDroppedObserver observer)
{
  // mOnDispatchDropped is strand-owned; post the assignment so the strand stays its sole writer.
  // Capture weak_from_this(), NOT shared_from_this(): this setter runs once during server
  // construction, and if the executor never services the dispatch strand before teardown a strong
  // capture would keep the bus parked in its own strand queue forever - a pure self-cycle that, via
  // the bus's strong mAddressSpace, pins the entire NS0 node graph (LeakSanitizer: ~12 MB, all
  // indirect). A weak capture lets the bus be destroyed with the server; a stale post simply no-ops.
  // This is the bus's only self-capture; every other one is already weak.
  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [observer = std::move(observer)](EventBus& self) mutable
    { self.mOnDispatchDropped = std::move(observer); })();
}

void EventBus::start_next_dispatch_on_strand()
{
  if (mDispatching || mPendingDispatches.empty())
  {
    return;
  }
  mDispatching = true;
  auto task = std::move(mPendingDispatches.front().task);
  mPendingDispatches.pop();

  auto weak = weak_from_this();
  task(
    [weak]()
    {
      auto self = weak.lock();
      if (!self)
        return;
      self->on_dispatch_complete();
    });
}

void EventBus::on_dispatch_complete()
{
  // Always post to the strand (even though we're already on it) so that
  // chains of synchronous dispatch tasks (e.g. many emit_to_subscription
  // calls back-to-back) don't recurse on the C++ stack.
  mDispatching = false;
  if (mPendingDispatches.empty())
  {
    return;
  }
  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [](EventBus& self) { self.start_next_dispatch_on_strand(); })();
}

// Lightweight identity of an event, captured alongside its (type-erased) dispatch task so a drop can
// be reported to the host. Built from the cloned event before it is moved into the task.
namespace
{
DroppedEventInfo make_dropped_info(const BaseEvent& event)
{
  return DroppedEventInfo{event.eventType, event.sourceNode, std::string{event.sourceName}, event.severity};
}
}  // namespace

void EventBus::emit(BaseEvent& event)
{
  // Auto-fill on the caller's thread so callers (e.g. ConditionInstance::emit_condition_event)
  // can read back the assigned EventId immediately after this returns.
  auto_fill(event);

  // Clone for delivery - preserves the concrete event type.
  std::shared_ptr<BaseEvent> shared = event.clone();

  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [ev = std::move(shared)](EventBus& self) mutable
    {
      // Snapshot the registry NOW - synchronously, in emit order on the dispatch
      // strand - so this event is delivered only to MonitoredItems that were
      // already registered when the emit was processed. Per OPC 10000-9 4.5,
      // "the currently existing state will not be reported": Event Notifications
      // begin at subscription time, and an Event emitted before a MonitoredItem
      // was created must NOT reach it (it can only obtain prior state via
      // ConditionRefresh). Because emit() and register_event_item() both post to
      // this strand, and a synchronous emit() (e.g. ConditionInstance enable/
      // disable) is posted before the subsequent CreateMonitoredItems register,
      // the registry at this point correctly excludes a not-yet-registered MI.
      //
      // The snapshot MUST be taken here, not after the async EventType-hierarchy
      // resolution below: that resolution reposts onto this strand on a cache
      // miss, which would let a concurrently-posted register_event_item insert
      // run first and wrongly pull a just-created MI into the snapshot - the
      // race behind the intermittent COND-1802 (DisableEventHasRetainFalse)
      // failure, where a pre-creation Retain=true enable event leaked to a new MI.
      std::vector<RegistrationSnapshot> snapshot;
      snapshot.reserve(self.mRegistry.size());
      for (const auto& [handle, item] : self.mRegistry)
      {
        snapshot.push_back(
          {item.monitoredNode, item.monitoredItemId, item.callback, item.requiresDeclarationModel});
      }

      // Build the dispatch task. The task captures the cloned event, the
      // emit-time registry snapshot, and a weak self; it is invoked later when
      // this task reaches the head of the pending queue.
      auto weakSelf = self.weak_from_this();
      auto droppedInfo = make_dropped_info(*ev);
      self.enqueue_dispatch_on_strand(
        [weakSelf, ev = std::move(ev), snapshot = std::move(snapshot)](
          std::function<void()> onComplete) mutable
        {
          auto lockedSelf = weakSelf.lock();
          if (!lockedSelf)
          {
            onComplete();
            return;
          }

          // Resolve the event's EventType supertype chain (for OfType subtype
          // matching) before listener + fan-out, so every observer sees the
          // populated event_type_hierarchy. Stays within this dispatch task's
          // serialisation window (onComplete is only invoked once the flow ends).
          NodeId eventType = ev->eventType;
          auto weakBus = lockedSelf->weak_from_this();
          lockedSelf->resolve_event_type_hierarchy_async(std::move(eventType),
            [weakBus, ev = std::move(ev), snapshot = std::move(snapshot), onComplete = std::move(onComplete)](
              std::shared_ptr<const std::vector<NodeId>> chain) mutable
            {
              auto lockedBus = weakBus.lock();
              if (!lockedBus)
              {
                onComplete();
                return;
              }
              ev->eventTypeHierarchy = std::move(chain);
              const bool requiresDeclarationModel = std::any_of(snapshot.begin(),
                snapshot.end(),
                [](const RegistrationSnapshot& item) { return item.requiresDeclarationModel; });
              if (!requiresDeclarationModel)
              {
                if (lockedBus->mEventListener)
                  ::ua::detail::invoke_user_callback(
                    lockedBus->mAddressSpace.logger().with_category("events"),
                    lockedBus->mEventListener,
                    *ev);
                DispatchEventOperation::run(lockedBus->mAddressSpace,
                  std::move(ev),
                  nullptr,
                  std::move(snapshot),
                  lockedBus->mDispatchStrand,
                  lockedBus->event_source_types(),
                  std::move(onComplete));
                return;
              }
              auto declarationType = ev->eventType;
              auto weakDeclarationBus = lockedBus->weak_from_this();
              lockedBus->resolve_event_type_declarations_async(std::move(declarationType),
                [weakDeclarationBus,
                  ev = std::move(ev),
                  snapshot = std::move(snapshot),
                  onComplete = std::move(onComplete)](
                  std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel) mutable
                {
                  auto declarationBus = weakDeclarationBus.lock();
                  if (!declarationBus)
                  {
                    onComplete();
                    return;
                  }

                  // Listener fires on the strand, before subscriber fan-out, on the same task.
                  if (declarationBus->mEventListener)
                    ::ua::detail::invoke_user_callback(
                      declarationBus->mAddressSpace.logger().with_category("events"),
                      declarationBus->mEventListener,
                      *ev);

                  DispatchEventOperation::run(declarationBus->mAddressSpace,
                    std::move(ev),
                    std::move(declarationModel),
                    std::move(snapshot),
                    declarationBus->mDispatchStrand,
                    declarationBus->event_source_types(),
                    std::move(onComplete));
                });
            });
        },
        std::move(droppedInfo));
    })();
}

std::shared_ptr<EventSourceTypeCache> EventBus::event_source_types()
{
  const auto modelGeneration = mAddressSpace.model_generation();
  if (!mEventSourceTypes || mEventSourceTypesGeneration != modelGeneration)
  {
    mEventSourceTypes = std::make_shared<EventSourceTypeCache>();
    mEventSourceTypesGeneration = modelGeneration;
  }
  return mEventSourceTypes;
}

void EventBus::resolve_event_type_hierarchy_async(
  NodeId eventType, std::function<void(std::shared_ptr<const std::vector<NodeId>>)> done)
{
  const auto modelGeneration = mAddressSpace.model_generation();
  if (auto it = mEventTypeHierarchyCache.find(eventType); it != mEventTypeHierarchyCache.end())
  {
    if (it->second.modelGeneration == modelGeneration)
    {
      done(it->second.hierarchy);
      return;
    }
    mEventTypeHierarchyCache.erase(it);
  }

  auto weak = weak_from_this();
  ResolveTypeHierarchyOperation::run(mAddressSpace,
    eventType,
    mDispatchStrand,
    [weak, eventType, modelGeneration, done = std::move(done)](
      std::shared_ptr<const std::vector<NodeId>> chain, bool complete) mutable
    {
      if (auto self = weak.lock())
      {
        if (complete && self->mAddressSpace.model_generation() == modelGeneration)
        {
          self->mEventTypeHierarchyCache.insert_or_assign(
            std::move(eventType), HierarchyCacheEntry{modelGeneration, chain});
        }
      }
      done(std::move(chain));
    });
}

void EventBus::resolve_event_type_declarations_async(
  NodeId eventType, std::function<void(std::shared_ptr<const event_type_model::DeclarationsResult>)> done)
{
  const auto modelGeneration = mAddressSpace.model_generation();
  if (auto cached = mEventTypeDeclarationsCache.find(eventType); cached != mEventTypeDeclarationsCache.end())
  {
    if (cached->second.modelGeneration == modelGeneration)
    {
      done(cached->second.declarations);
      return;
    }
    mEventTypeDeclarationsCache.erase(cached);
  }

  event_type_model::CollectCallback completion = ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [eventType, modelGeneration, done = std::move(done)](
      EventBus& self, event_type_model::DeclarationsResult result) mutable
    {
      if (result.is_bad())
      {
        log_exception(self.mAddressSpace.logger().with_category("events"),
          LogLevel::Error,
          "EventBus EventType declaration resolution",
          result.status_code());
      }
      auto declarationModel = std::make_shared<const event_type_model::DeclarationsResult>(std::move(result));
      // Declarations read while the model changed answer this Event, as the type hierarchy's do, and are not
      // kept: the next Event of the type reads them again. A read that waited for no change to overlap it
      // would not end while Nodes are being created.
      if (declarationModel->is_good() && self.mAddressSpace.model_generation() == modelGeneration)
      {
        self.mEventTypeDeclarationsCache.insert_or_assign(
          eventType, DeclarationCacheEntry{modelGeneration, declarationModel});
      }
      done(std::move(declarationModel));
    });

  if (!mDeclarationResolver)
  {
    event_type_model::collect_declarations_async(mAddressSpace, std::move(eventType), std::move(completion));
    return;
  }

  auto guardedCompletion = ua::detail::make_fire_once<event_type_model::DeclarationsResult>(completion);
  try
  {
    mDeclarationResolver(mAddressSpace, std::move(eventType), guardedCompletion);
  }
  catch (...)
  {
    guardedCompletion(
      event_type_model::DeclarationsResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void EventBus::auto_fill(BaseEvent& event)
{
  // EventId - unique per event (SVR-EVT-BET-003)
  if (event.eventId.empty())
  {
    auto id = mNextEventId.fetch_add(1, std::memory_order_relaxed);
    event.eventId.resize(sizeof(id));
    std::memcpy(event.eventId.data(), &id, sizeof(id));
  }

  // ReceiveTime - always set by server (SVR-EVT-BET-005)
  event.receiveTime = DateTime::now();

  // Time - set if not already provided (SVR-EVT-BET-004: preserve if set)
  if (event.time.is_null())
  {
    event.time = event.receiveTime;
  }

  // Severity - clamp to [1, 1000] (SVR-EVT-BET-007)
  if (event.severity < 1)
    event.severity = 1;
  else if (event.severity > 1000)
    event.severity = 1000;
}

void EventBus::emit_to_subscription(uint32_t subscriptionId, BaseEvent& event)
{
  // Auto-fill on the caller's thread (matches emit() - EventId visible on return). A ConditionRefresh replay
  // re-sends an Event the server already received (OPC 10000-9 5.5.2) and keeps the ReceiveTime it was given,
  // so a client can order it against live transitions; one that carries none is stamped (SVR-EVT-BET-005).
  const DateTime replayedReceiveTime = event.receiveTime;
  auto_fill(event);
  if (!replayedReceiveTime.is_null())
  {
    event.receiveTime = replayedReceiveTime;
  }

  // Clone the event for delivery (mutable until the type hierarchy is attached).
  std::shared_ptr<BaseEvent> sharedEvent = event.clone();

  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [subscriptionId, ev = std::move(sharedEvent)](EventBus& self) mutable
    {
      auto weakSelf = self.weak_from_this();
      auto droppedInfo = make_dropped_info(*ev);
      self.enqueue_dispatch_on_strand(
        [weakSelf, subscriptionId, ev = std::move(ev)](std::function<void()> onComplete) mutable
        {
          auto lockedSelf = weakSelf.lock();
          if (!lockedSelf)
          {
            onComplete();
            return;
          }

          // Resolve the EventType supertype chain (for OfType matching) before
          // delivery: a refreshed Condition still passes through the item's where clause.
          // RefreshStart and RefreshEnd ignore it (CompiledEventFilter, Part 9 4.5).
          NodeId eventType = ev->eventType;
          auto weakBus = lockedSelf->weak_from_this();
          lockedSelf->resolve_event_type_hierarchy_async(std::move(eventType),
            [weakBus, subscriptionId, ev = std::move(ev), onComplete = std::move(onComplete)](
              std::shared_ptr<const std::vector<NodeId>> chain) mutable
            {
              auto lockedBus = weakBus.lock();
              if (!lockedBus)
              {
                onComplete();
                return;
              }
              ev->eventTypeHierarchy = std::move(chain);
              const bool requiresDeclarationModel = std::any_of(lockedBus->mRegistry.begin(),
                lockedBus->mRegistry.end(),
                [subscriptionId](const auto& registered) {
                  return registered.second.subscriptionId == subscriptionId &&
                         registered.second.requiresDeclarationModel;
                });
              if (!requiresDeclarationModel)
              {
                const std::shared_ptr<const BaseEvent> constEv = std::move(ev);
                const auto logger = lockedBus->mAddressSpace.logger().with_category("events");
                for (const auto& [handle, item] : lockedBus->mRegistry)
                {
                  if (item.subscriptionId == subscriptionId)
                    ::ua::detail::invoke_user_callback(
                      logger, item.callback, item.monitoredItemId, constEv, nullptr);
                }
                ::ua::detail::invoke_user_callback(logger, onComplete);
                return;
              }
              auto declarationType = ev->eventType;
              auto weakDeclarationBus = lockedBus->weak_from_this();
              lockedBus->resolve_event_type_declarations_async(std::move(declarationType),
                [weakDeclarationBus, subscriptionId, ev = std::move(ev), onComplete = std::move(onComplete)](
                  std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel) mutable
                {
                  auto declarationBus = weakDeclarationBus.lock();
                  if (!declarationBus)
                  {
                    onComplete();
                    return;
                  }
                  const std::shared_ptr<const BaseEvent> constEv = std::move(ev);
                  const auto logger = declarationBus->mAddressSpace.logger().with_category("events");
                  for (const auto& [handle, item] : declarationBus->mRegistry)
                  {
                    if (item.subscriptionId == subscriptionId)
                      ::ua::detail::invoke_user_callback(
                        logger, item.callback, item.monitoredItemId, constEv, declarationModel);
                  }
                  ::ua::detail::invoke_user_callback(logger, onComplete);
                });
            });
        },
        std::move(droppedInfo));
    })();
}

void EventBus::emit_to_monitored_item(uint32_t subscriptionId, IntegerId monitoredItemId, BaseEvent& event)
{
  // Auto-fill on the caller's thread (matches emit() - EventId visible on return).
  auto_fill(event);

  // Clone the event for delivery (mutable until the type hierarchy is attached).
  std::shared_ptr<BaseEvent> sharedEvent = event.clone();

  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [subscriptionId, monitoredItemId, ev = std::move(sharedEvent)](EventBus& self) mutable
    {
      auto weakSelf = self.weak_from_this();
      auto droppedInfo = make_dropped_info(*ev);
      self.enqueue_dispatch_on_strand(
        [weakSelf, subscriptionId, monitoredItemId, ev = std::move(ev)](
          std::function<void()> onComplete) mutable
        {
          auto lockedSelf = weakSelf.lock();
          if (!lockedSelf)
          {
            onComplete();
            return;
          }

          // Resolve the EventType supertype chain (for OfType matching) before
          // delivery: a refreshed Condition still passes through the item's where clause.
          // RefreshStart and RefreshEnd ignore it (CompiledEventFilter, Part 9 4.5).
          NodeId eventType = ev->eventType;
          auto weakBus = lockedSelf->weak_from_this();
          lockedSelf->resolve_event_type_hierarchy_async(std::move(eventType),
            [weakBus,
              subscriptionId,
              monitoredItemId,
              ev = std::move(ev),
              onComplete = std::move(onComplete)](std::shared_ptr<const std::vector<NodeId>> chain) mutable
            {
              auto lockedBus = weakBus.lock();
              if (!lockedBus)
              {
                onComplete();
                return;
              }
              ev->eventTypeHierarchy = std::move(chain);
              const auto target = std::find_if(lockedBus->mRegistry.begin(),
                lockedBus->mRegistry.end(),
                [subscriptionId, monitoredItemId](const auto& registered)
                {
                  return registered.second.subscriptionId == subscriptionId &&
                         registered.second.monitoredItemId == monitoredItemId;
                });
              if (target == lockedBus->mRegistry.end())
              {
                onComplete();
                return;
              }
              if (!target->second.requiresDeclarationModel)
              {
                const std::shared_ptr<const BaseEvent> constEv = std::move(ev);
                const auto logger = lockedBus->mAddressSpace.logger().with_category("events");
                ::ua::detail::invoke_user_callback(
                  logger, target->second.callback, target->second.monitoredItemId, constEv, nullptr);
                ::ua::detail::invoke_user_callback(logger, onComplete);
                return;
              }
              auto declarationType = ev->eventType;
              auto weakDeclarationBus = lockedBus->weak_from_this();
              lockedBus->resolve_event_type_declarations_async(std::move(declarationType),
                [weakDeclarationBus,
                  subscriptionId,
                  monitoredItemId,
                  ev = std::move(ev),
                  onComplete = std::move(onComplete)](
                  std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel) mutable
                {
                  auto declarationBus = weakDeclarationBus.lock();
                  if (!declarationBus)
                  {
                    onComplete();
                    return;
                  }
                  const std::shared_ptr<const BaseEvent> constEv = std::move(ev);
                  const auto logger = declarationBus->mAddressSpace.logger().with_category("events");
                  for (const auto& [handle, item] : declarationBus->mRegistry)
                  {
                    if (item.subscriptionId == subscriptionId && item.monitoredItemId == monitoredItemId)
                      ::ua::detail::invoke_user_callback(
                        logger, item.callback, item.monitoredItemId, constEv, declarationModel);
                  }
                  ::ua::detail::invoke_user_callback(logger, onComplete);
                });
            });
        },
        std::move(droppedInfo));
    })();
}

void EventBus::resolve_event_item_node_async(
  uint32_t subscriptionId, IntegerId monitoredItemId, std::function<void(std::optional<NodeId>)> callback)
{
  // Completion-owning: the post owns `callback` and must fire it exactly once,
  // including when the bus is gone by the time the strand turn runs - in which
  // case the gone-result (std::nullopt, "not found") is delivered.
  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    std::move(callback),
    std::optional<NodeId>{std::nullopt},
    [subscriptionId, monitoredItemId](EventBus& self, std::function<void(std::optional<NodeId>)> done)
    {
      for (const auto& [handle, item] : self.mRegistry)
      {
        if (item.subscriptionId == subscriptionId && item.monitoredItemId == monitoredItemId)
        {
          done(item.monitoredNode);
          return;
        }
      }
      done(std::nullopt);
    })();
}

void EventBus::has_event_items_async(uint32_t subscriptionId, std::function<void(Result<bool>)> callback)
{
  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    std::move(callback),
    Result<bool>{StatusCode{Status::BadShutdown}},
    [subscriptionId](EventBus& self, std::function<void(Result<bool>)> done)
    {
      const bool hasEventItem = std::any_of(self.mRegistry.begin(),
        self.mRegistry.end(),
        [subscriptionId](const auto& entry) { return entry.second.subscriptionId == subscriptionId; });
      done(Result<bool>{hasEventItem});
    })();
}

EventMonitoringHandle EventBus::register_event_item(
  NodeId monitoredNode, IntegerId monitoredItemId, uint32_t subscriptionId, EventDeliveryCallback callback)
{
  return register_event_item_impl(
    std::move(monitoredNode), monitoredItemId, subscriptionId, true, std::move(callback));
}

EventMonitoringHandle EventBus::register_event_item(NodeId monitoredNode, IntegerId monitoredItemId,
  uint32_t subscriptionId, EventDeliveryCallback callback, bool requiresDeclarationModel)
{
  return register_event_item_impl(
    std::move(monitoredNode), monitoredItemId, subscriptionId, requiresDeclarationModel, std::move(callback));
}

EventMonitoringHandle EventBus::register_event_item_impl(NodeId monitoredNode, IntegerId monitoredItemId,
  uint32_t subscriptionId, bool requiresDeclarationModel, EventDeliveryCallback callback)
{
  auto handle = mNextHandle.fetch_add(1, std::memory_order_relaxed);

  // Eager: registering interest may not have reached the strand yet, but the
  // two-gate audit emission path must see the gate flip before the next emit.
  // The strand-side update_interest_flag reconciles authoritatively once the
  // insert lands.
  mHasEventInterest.store(true, std::memory_order_relaxed);

  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [handle,
      node = std::move(monitoredNode),
      monitoredItemId,
      subscriptionId,
      requiresDeclarationModel,
      callback = std::move(callback)](EventBus& self) mutable
    {
      self.mRegistry.emplace(handle,
        RegisteredItem{std::move(node),
          monitoredItemId,
          subscriptionId,
          std::move(callback),
          requiresDeclarationModel,
          handle});
      self.update_interest_flag();
    })();

  return handle;
}

EventMonitoringHandle EventBus::register_event_item(NodeId monitoredNode, IntegerId monitoredItemId,
  uint32_t subscriptionId, LegacyEventDeliveryCallback callback)
{
  return register_event_item_impl(std::move(monitoredNode),
    monitoredItemId,
    subscriptionId,
    false,
    EventDeliveryCallback{[callback = std::move(callback)](IntegerId deliveredId,
                            std::shared_ptr<const BaseEvent>
                              event,
                            std::shared_ptr<const event_type_model::DeclarationsResult>)
      {
        callback(deliveredId, std::move(event));
      }});
}

void EventBus::deregister_event_item(EventMonitoringHandle handle)
{
  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [handle](EventBus& self)
    {
      self.mRegistry.erase(handle);
      self.update_interest_flag();
    })();
}

void EventBus::set_event_listener(EventListener listener)
{
  // Eager: installing a non-null listener must make has_event_interest()
  // return true immediately so the audit-emission gate observes the flip on
  // the caller's thread (same rationale as register_event_item). Clearing
  // (nullptr) does NOT eagerly flip false - the registry may still be
  // non-empty; the strand-side update_interest_flag reconciles.
  if (listener)
  {
    mHasEventInterest.store(true, std::memory_order_relaxed);
  }

  ua::async::post_borrowing(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [listener = std::move(listener)](EventBus& self) mutable
    {
      if (self.mListenerClosed)
      {
        return;  // The server has shut down: no listener is installed again.
      }
      self.mEventListener = std::move(listener);
      self.update_interest_flag();
    })();
}

void EventBus::close_listener_async(std::function<void()> done)
{
  // Owning: the bus stays alive until the close has run, so @p done always runs and shutdown completes.
  ua::async::post_owning(this,
    mDispatchStrand,
    mAddressSpace.logger().with_category("events"),
    [done = std::move(done)](EventBus& self) mutable
    {
      self.mListenerClosed = true;
      self.mEventListener = nullptr;
      self.update_interest_flag();
      if (done)
      {
        done();
      }
    })();
}

bool EventBus::has_event_interest() const noexcept
{
  return mHasEventInterest.load(std::memory_order_relaxed);
}

void EventBus::update_interest_flag()
{
  // Must be called on the dispatch strand.
  mHasEventInterest.store(!mRegistry.empty() || static_cast<bool>(mEventListener), std::memory_order_relaxed);
}

}  // namespace ua::server
