// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_event_type_model.h"

#include "ua_self_owning_operation.h"

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_on_strand.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_routing.h"
#include "ua_subtype_facts.h"
#include "ua_to_string.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <cstddef>
#include <deque>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ua::server::event_type_model
{

namespace
{

constexpr size_t maxTypeDepth = 64;
constexpr size_t maxDeclarationDepth = 64;
constexpr size_t maxDeclarations = 100000;

/// How many types and declarations the walks take, together, in one strand turn before they yield it. The
/// facts of a whole depth arrive at once, so a depth of thousands of declarations would otherwise be composed
/// in one turn.
constexpr size_t entriesPerTurn = 1024;

/// How many select clauses are resolved in one strand turn before the resolution yields it.
constexpr size_t clausesPerTurn = 64;

bool is_core_aggregate(const NodeId& type)
{
  return type == NodeId{ReferenceTypeId::Aggregates} || type == NodeId{ReferenceTypeId::HasComponent} ||
         type == NodeId{ReferenceTypeId::HasProperty} || type == NodeId{ReferenceTypeId::HasOrderedComponent};
}

bool is_intrinsic_non_aggregate(const NodeId& type)
{
  return type.namespace_index() == 0 && !is_core_aggregate(type);
}

bool same_path(const std::vector<QualifiedName>& lhs, const std::vector<QualifiedName>& rhs)
{
  return lhs == rhs;
}

/// The answer for an item a call left unanswered, which the calls this operation makes never do.
StatusCode answer_missing()
{
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build("EventTypeModelAnswerMissing",
      "A call of the EventType model answered fewer items than it was asked about",
      "EventTypeModel")};
}

struct PendingDeclaration
{
  NodeId nodeId;
  std::vector<QualifiedName> parentPath;
};

/// One requested EventType's walk, in the order the single form has always walked it: the supertype chain
/// from the type to BaseEventType, collecting the aggregate children of each type on the way, then those
/// children breadth first, collecting *their* aggregate children, so a nested Object contributes its own
/// fields under its BrowsePath. It advances as far as the facts the request holds allow.
struct TypeWalk
{
  explicit TypeWalk(NodeId type) : eventType(std::move(type))
  {
    pendingTypes.push_back(eventType);
  }

  NodeId eventType;
  std::deque<NodeId> pendingTypes;
  std::set<NodeId> seenTypes;
  bool reachedBaseEventType{false};
  bool typesWalked{false};
  /// How many entries of the queue of the stage the walk is in have named what they wait for this round.
  size_t prefetched{0};
  std::deque<PendingDeclaration> pendingDeclarations;
  Declarations declarations;
  /// Set once the walk has ended, Good or not.
  std::optional<DeclarationsResult> result;
};

/// NodeIds a walk waits for, each named once.
struct NeedList
{
  std::vector<NodeId> ids;
  std::unordered_set<NodeId> named;

  void add(const NodeId& nodeId)
  {
    if (named.insert(nodeId).second)
    {
      ids.push_back(nodeId);
    }
  }
};

/// What the walks wait for before they can go on.
struct Needs
{
  NeedList lookups;
  NeedList typeReferences;
  NeedList declarationReferences;
  NeedList classifications;
};

/// How far a walk got: to its end, to a fact it waits for, or to the end of this strand turn's budget.
enum class Advance
{
  Done,
  Blocked,
  Yield
};

/// Collects the declarations of a request's EventTypes, and resolves its EventFilters' select clauses against
/// them (NR-28 rule 3).
///
/// The types are walked together, a round at a time. A walk advances as far as the facts the request holds
/// allow, then names the fact it waits for: a Node's lookup, its References, or whether an application
/// ReferenceType is a subtype of Aggregates. Each round fetches what every walk waits for with one call per
/// namespace, so a Node shared by several types is looked up and read once, and a type level or a declaration
/// depth of every walk is one lookup and one References read. Each type's declarations are composed from
/// those facts exactly as one type alone has always composed them: the same order, deduplication by
/// BrowsePath (the first wins), Mandatory from HasModellingRule, the skip of a declaration without a
/// BrowseName, the bounds and the ErrorDetail of each failure.
///
/// The strand is made rather than borrowed, as `AddressSpace` hands out a bare executor; `await_step` posts
/// every answer onto it, so a namespace that answers inline does not nest one round inside another, and the
/// callers are answered after their call returns. @see ua::async::SelfOwningOperation
class EventTypeModelOperation final : public ua::async::SelfOwningOperation<EventTypeModelOperation>
{
public:
  using DeclarationsCompletion = std::function<void(std::vector<DeclarationsResult>)>;
  using ModelsCompletion = std::function<void(std::vector<SelectClauseModelsResult>)>;

  EventTypeModelOperation(AddressSpace addressSpace, RequestInfo request, std::vector<NodeId> eventTypes,
    std::vector<EventFilter> filters, DeclarationsCompletion onDeclarations, ModelsCompletion onModels)
    : ua::async::SelfOwningOperation<EventTypeModelOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mLoopLimit(addressSpace.limits().loopLimit),
      mRequest(std::move(request)), mEventTypes(std::move(eventTypes)), mFilters(std::move(filters)),
      mOnDeclarations(std::move(onDeclarations)), mOnModels(std::move(onModels))
  {}

  static void collect(AddressSpace addressSpace, RequestInfo request, std::vector<NodeId> eventTypes,
    DeclarationsCompletion onComplete)
  {
    launch(std::make_shared<EventTypeModelOperation>(std::move(addressSpace),
      std::move(request),
      std::move(eventTypes),
      std::vector<EventFilter>{},
      std::move(onComplete),
      nullptr));
  }

  static void resolve(AddressSpace addressSpace, RequestInfo request, std::vector<EventFilter> filters,
    ModelsCompletion onComplete)
  {
    // Every distinct type the clauses name, in the order first named.
    std::vector<NodeId> eventTypes;
    std::unordered_set<NodeId> named;
    for (const auto& filter : filters)
    {
      for (size_t clauseIndex = 0; clauseIndex < filter.select_clauses().size(); ++clauseIndex)
      {
        const NodeId& typeId = filter.select_clauses()[clauseIndex].type_definition_id();
        if (!typeId.is_null() && named.insert(typeId).second)
        {
          eventTypes.push_back(typeId);
        }
      }
    }
    launch(std::make_shared<EventTypeModelOperation>(std::move(addressSpace),
      std::move(request),
      std::move(eventTypes),
      std::move(filters),
      nullptr,
      std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<EventTypeModelOperation>;

  /// Hands the strand back between rounds of composition. `await_step` posts its answer, so awaiting a
  /// completion that fires immediately IS that post: the body resumes in a new turn, on a fresh stack (R18).
  auto yield_strand()
  {
    return await_step<bool>([](auto completion) { completion(true); });
  }

  ua::async::Task<> run()
  {
    std::optional<StatusCode> collectionFailure;
    try
    {
      co_await collect();
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
      co_return;
    }
    catch (...)
    {
      collectionFailure = ua::exception_to_status_code(std::current_exception());
    }
    try
    {
      if (collectionFailure)
      {
        for (const auto& eventType : mEventTypes)
        {
          const auto walk = mWalkOf.find(eventType);
          if (walk == mWalkOf.end() || walk->second >= mWalks.size())
          {
            fail_every_answer(*collectionFailure);
            co_return;
          }
        }
        for (auto& walk : mWalks)
        {
          if (!walk.result)
          {
            walk.result = DeclarationsResult{*collectionFailure};
          }
        }
      }
      if (mOnModels)
      {
        co_await resolve_models();
      }
      else
      {
        finish_declarations();
      }
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      fail_every_answer(ua::exception_to_status_code(std::current_exception()));
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail_every_answer(status);
  }

  /// Answers every type or filter with @p status; nothing when the answer has been given.
  void fail_every_answer(const StatusCode& status)
  {
    if (mOnDeclarations)
    {
      std::vector<DeclarationsResult> answers(mEventTypes.size(), DeclarationsResult{status});
      if (auto callback = std::move(mOnDeclarations))
      {
        callback(std::move(answers));
      }
    }
    if (mOnModels)
    {
      std::vector<SelectClauseModelsResult> answers(mFilters.size(), SelectClauseModelsResult{status});
      if (auto callback = std::move(mOnModels))
      {
        callback(std::move(answers));
      }
    }
  }

  // --- the rounds ----------------------------------------------------------------------------------------

  /// Walks every requested type to its end: each round advances every walk as far as the facts allow, then
  /// fetches what they wait for with one call per namespace. ReferenceTypes are classified first, since a
  /// walk waiting for one could then join the same round's lookup as the others.
  ua::async::Task<> collect()
  {
    for (const auto& eventType : mEventTypes)
    {
      if (mWalkOf.try_emplace(eventType, mWalks.size()).second)
      {
        mWalks.emplace_back(eventType);
      }
    }

    // What the walks wait for, gathered over the strand turns of one round: the budget may stop a walk, or
    // the naming of its queue, in one turn, and the next turn goes on from there.
    Needs needs;
    while (true)
    {
      size_t budget = entriesPerTurn;
      bool walking = false;
      bool yielded = false;
      for (auto& walk : mWalks)
      {
        if (walk.result)
        {
          continue;
        }
        Advance advanced = advance(walk, needs, budget);
        if (advanced == Advance::Blocked && !prefetch(walk, needs, budget))
        {
          advanced = Advance::Yield;
        }
        walking = walking || advanced != Advance::Done;
        yielded = yielded || advanced == Advance::Yield;
      }
      if (!walking)
      {
        co_return;
      }
      // The walks the budget stopped first take their turn; what everyone waits for is fetched once all have
      // said what it is.
      if (yielded)
      {
        co_await yield_strand();
        continue;
      }

      // The facts fetched now change what each walk waits for, so the next round names its queue afresh.
      Needs round = std::exchange(needs, Needs{});
      for (auto& walk : mWalks)
      {
        walk.prefetched = 0;
      }
      if (!round.classifications.ids.empty())
      {
        co_await classify(std::move(round.classifications.ids));
      }
      else if (!round.lookups.ids.empty())
      {
        co_await look_up(std::move(round.lookups.ids));
      }
      else if (!round.typeReferences.ids.empty() || !round.declarationReferences.ids.empty())
      {
        co_await read_references(
          std::move(round.typeReferences.ids), std::move(round.declarationReferences.ids));
      }
      else
      {
        // A walk only waits after naming what it waits for; one that named nothing would wait for ever.
        for (auto& walk : mWalks)
        {
          if (!walk.result)
          {
            walk.result = DeclarationsResult{answer_missing()};
          }
        }
        co_return;
      }
    }
  }

  /// One lookup per namespace of @p nodeIds, for the request.
  ua::async::Task<> look_up(std::vector<NodeId> nodeIds)
  {
    auto found = co_await await_step<std::vector<NodeAccessorResult>>(
      [this, &nodeIds](auto completion)
      {
        auto owner = mAddressSpace.lock();
        if (!owner)
        {
          throw UaException{ua::detail::address_space_gone("EventTypeModel")};
        }
        namespace_calls::find_nodes(*owner, mRequest, nodeIds, std::move(completion));
      });
    for (size_t k = 0; k < nodeIds.size(); ++k)
    {
      NodeAccessorResult answer =
        k < found.size() ? std::move(found[k]) : NodeAccessorResult{answer_missing()};
      if (answer.is_uncertain())
      {
        // The walk decides the model on the Nodes it finds, so it does not act on a Node the namespace is
        // uncertain of, whether or not the answer holds it.
        answer = NodeAccessorResult{
          ::ua::detail::lookup_failure(nodeIds[k], answer.status_code(), "EventTypeModel")};
      }
      mLookups.try_emplace(nodeIds[k], std::move(answer));
    }
  }

  /// The References of the types @p typeIds (both directions, hinted {HasSubtype, Aggregates}) and of the
  /// declarations @p declarationIds (Forward, hinted {Aggregates, HasModellingRule}): one read per namespace,
  /// then again for the Nodes a namespace answered with a resume token, until none is left. A Node whose
  /// namespace answers `maxEmptyReferencePages` pages in a row with a token and no References fails
  /// `Bad_InternalError` (`NamespacePagingDidNotEnd`), its last token released (DL-67 (8)); an answer that
  /// holds a Reference starts the count again.
  ua::async::Task<> read_references(std::vector<NodeId> typeIds, std::vector<NodeId> declarationIds)
  {
    struct Reading
    {
      NodeId nodeId;
      bool forType{false};
      std::optional<NodeAccessor> node;
      ua::detail::ResumeToken token;
      size_t emptyPages{0};
      std::vector<Reference> found;
      std::optional<StatusCode> failed;
    };

    std::vector<Reading> readings;
    readings.reserve(typeIds.size() + declarationIds.size());
    const auto add = [this, &readings](NodeId nodeId, bool forType)
    {
      Reading reading;
      reading.nodeId = std::move(nodeId);
      reading.forType = forType;
      // A walk asks for a Node's References only after its lookup answered Good.
      const auto looked = mLookups.find(reading.nodeId);
      if (looked != mLookups.end() && looked->second.is_good())
      {
        reading.node = looked->second.value();
      }
      else
      {
        reading.failed = answer_missing();
      }
      readings.push_back(std::move(reading));
    };
    for (auto& nodeId : typeIds)
    {
      add(std::move(nodeId), true);
    }
    for (auto& nodeId : declarationIds)
    {
      add(std::move(nodeId), false);
    }

    std::vector<size_t> pending;
    pending.reserve(readings.size());
    for (size_t k = 0; k < readings.size(); ++k)
    {
      if (!readings[k].failed)
      {
        pending.push_back(k);
      }
    }
    while (!pending.empty())
    {
      // A token sent is consumed by the call whatever it answers, so it is no longer this read's to release.
      std::vector<ua::detail::ReferenceRead> reads;
      reads.reserve(pending.size());
      for (const size_t k : pending)
      {
        Reading& reading = readings[k];
        reads.push_back(ua::detail::ReferenceRead{*reading.node,
          reading.forType ? BrowseDirection::Both : BrowseDirection::Forward,
          reading.forType
            ? std::vector<NodeId>{NodeId{ReferenceTypeId::HasSubtype}, NodeId{ReferenceTypeId::Aggregates}}
            : std::vector<NodeId>{NodeId{ReferenceTypeId::Aggregates},
                NodeId{ReferenceTypeId::HasModellingRule}},
          0,
          std::move(reading.token)});
      }
      auto pages = co_await await_step<std::vector<ua::detail::ReferencePage>>(
        [this, &reads](auto completion)
        {
          auto owner = mAddressSpace.lock();
          if (!owner)
          {
            throw UaException{ua::detail::address_space_gone("EventTypeModel")};
          }
          ua::detail::NodeAccessorRoute::read_references(
            mRequest, std::move(reads), std::move(completion), mAddressSpace);
        });
      if (pages.size() != pending.size())
      {
        // The pages could not be allocated; the route released the tokens answered.
        for (const size_t k : pending)
        {
          readings[k].failed = StatusCode{Status::BadOutOfMemory};
        }
        break;
      }

      std::vector<size_t> next;
      for (size_t i = 0; i < pending.size(); ++i)
      {
        const size_t k = pending[i];
        Reading& reading = readings[k];
        NodeReferencesResult& answer = pages[i].answer;
        if (!answer.is_good())
        {
          // An Uncertain page, with or without References, is refused: the walk decides the model on them.
          reading.failed = server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
            answer.status_code(),
            "EventTypeModel",
            reading.nodeId);
          continue;
        }
        reading.token = std::move(pages[i].resumeToken);
        const References& page = answer.value().references;
        reading.emptyPages = page.empty() ? reading.emptyPages + 1 : 0;
        if (!reading.token.empty() && reading.emptyPages >= ua::detail::maxEmptyReferencePages)
        {
          reading.token.release();
          reading.failed = StatusCode{Status::BadInternalError,
            ErrorDetail::build("NamespacePagingDidNotEnd",
              "The namespace kept answering resume tokens for the References of a Node",
              "EventTypeModel")
              .context(ua::ContextKeys::nodeId, to_string(reading.nodeId))
              .context(ua::ContextKeys::limit, std::to_string(ua::detail::maxEmptyReferencePages))};
          continue;
        }
        reading.found.insert(reading.found.end(), page.begin(), page.end());
        if (!reading.token.empty())
        {
          next.push_back(k);
        }
      }
      pending = std::move(next);
    }

    for (auto& reading : readings)
    {
      auto& held = reading.forType ? mTypeReferences : mDeclarationReferences;
      if (reading.failed)
      {
        held.try_emplace(reading.nodeId, *reading.failed);
      }
      else
      {
        held.try_emplace(reading.nodeId, std::move(reading.found));
      }
    }
  }

  /// Whether each of the application ReferenceTypes @p types is a subtype of Aggregates, for the rest of the
  /// request: one lookup per namespace, then their supertype chains walked together until each reaches
  /// Aggregates (yes) or References (no). A type the address space does not hold is not an aggregate, as the
  /// single form has always answered; a walk that fails is the classification's failure.
  ua::async::Task<> classify(std::vector<NodeId> types)
  {
    auto found = co_await await_step<std::vector<NodeAccessorResult>>(
      [this, &types](auto completion)
      {
        auto owner = mAddressSpace.lock();
        if (!owner)
        {
          throw UaException{ua::detail::address_space_gone("EventTypeModel")};
        }
        namespace_calls::find_nodes(*owner, mRequest, types, std::move(completion));
      });

    std::vector<std::pair<NodeAccessor, NodeId>> starts;
    std::vector<size_t> startOf;
    for (size_t k = 0; k < types.size(); ++k)
    {
      if (k >= found.size())
      {
        mAggregates.try_emplace(types[k], BoolResult{false});
        continue;
      }
      if (!found[k].is_good())
      {
        if (found[k].is_bad() && found[k].status_code().as_status() == Status::BadNodeIdUnknown)
        {
          mAggregates.try_emplace(types[k], BoolResult{false});
        }
        else
        {
          mAggregates.try_emplace(types[k],
            BoolResult{::ua::detail::lookup_failure(types[k], found[k].status_code(), "EventTypeModel")});
        }
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
          auto owner = mAddressSpace.lock();
          if (!owner)
          {
            throw UaException{ua::detail::address_space_gone("EventTypeModel")};
          }
          walk_supertypes(
            *owner,
            mRequest,
            std::move(starts),
            mLoopLimit,
            [](std::size_t, const NodeId& type) -> std::optional<int>
            {
              if (type == NodeId{ReferenceTypeId::Aggregates})
              {
                return 1;
              }
              if (type == NodeId{ReferenceTypeId::References})
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
      walkFailure = ua::exception_to_status_code(std::current_exception());
    }

    for (size_t chain = 0; chain < startOf.size(); ++chain)
    {
      const NodeId& type = types[startOf[chain]];
      if (walkFailure)
      {
        mAggregates.try_emplace(type, BoolResult{*walkFailure});
        continue;
      }
      if (chain >= ends.size())
      {
        mAggregates.try_emplace(type, BoolResult{answer_missing()});
        continue;
      }
      const SupertypeWalkEnd& end = ends[chain];
      switch (end.how)
      {
      case SupertypeWalkEnd::How::Decided:
        mAggregates.try_emplace(type, BoolResult{end.value == 1});
        break;
      case SupertypeWalkEnd::How::NoSuper:
        mAggregates.try_emplace(type, BoolResult{false});
        break;
      case SupertypeWalkEnd::How::Failed:
        mAggregates.try_emplace(type, BoolResult{end.failure.is_good() ? answer_missing() : end.failure});
        break;
      }
    }
  }

  // --- one walk ------------------------------------------------------------------------------------------

  /// Whether a Reference of @p references names an application ReferenceType not yet classified that the
  /// walk would classify; each is added to @p needs. @p declarationClass is the declaration's NodeClass, or
  /// `nullopt` for a type's References.
  bool awaits_classification(
    const std::vector<Reference>& references, std::optional<NodeClass> declarationClass, Needs& needs) const
  {
    bool waiting = false;
    for (const auto& reference : references)
    {
      if (!reference.is_forward() || reference.is_remote() || !reference.target_id().is_local())
      {
        continue;
      }
      const NodeId& type = reference.type_id();
      if (declarationClass &&
          (type == NodeId{ReferenceTypeId::HasModellingRule} ||
            (*declarationClass != NodeClass::Object && *declarationClass != NodeClass::Variable)))
      {
        continue;
      }
      if (is_core_aggregate(type) || is_intrinsic_non_aggregate(type) || mAggregates.contains(type))
      {
        continue;
      }
      needs.classifications.add(type);
      waiting = true;
    }
    return waiting;
  }

  /// Names, for a walk that waits, the first fact each entry of its queue waits for, not only its next
  /// entry's: the rest of the type level or the declaration depth is then fetched in the same round. Only
  /// the queue of the stage the walk is in; an entry the walk would refuse before fetching (a type already
  /// walked, a declaration nested beyond the bound) names nothing, and nor does one whose getter throws,
  /// which the walk reports when it reaches it. Each entry takes one unit of @p budget; the naming goes on
  /// from `walk.prefetched` and stops when the budget is spent.
  /// @return Whether every entry of the queue has named what it waits for.
  bool prefetch(TypeWalk& walk, Needs& needs, size_t& budget) const
  {
    const size_t queued = walk.typesWalked ? walk.pendingDeclarations.size() : walk.pendingTypes.size();
    for (; walk.prefetched < queued; ++walk.prefetched)
    {
      if (budget == 0)
      {
        return false;
      }
      --budget;
      try
      {
        if (walk.typesWalked)
        {
          name_declaration_needs(walk.pendingDeclarations[walk.prefetched], needs);
        }
        else if (!walk.seenTypes.contains(walk.pendingTypes[walk.prefetched]))
        {
          name_type_needs(walk.pendingTypes[walk.prefetched], needs);
        }
      }
      catch (...)
      {
        ua::detail::ignore_expected_exception();
      }
    }
    return true;
  }

  /// The first fact the queued type @p typeId waits for, as the walk would ask for it.
  void name_type_needs(const NodeId& typeId, Needs& needs) const
  {
    const auto looked = mLookups.find(typeId);
    if (looked == mLookups.end())
    {
      needs.lookups.add(typeId);
      return;
    }
    if (!looked->second.is_good() || !looked->second.value().as<ObjectTypeAccessor>())
    {
      return;
    }
    const auto read = mTypeReferences.find(typeId);
    if (read == mTypeReferences.end())
    {
      needs.typeReferences.add(typeId);
    }
    else if (read->second.is_good())
    {
      awaits_classification(read->second.value(), std::nullopt, needs);
    }
  }

  /// The first fact the queued declaration @p pending waits for, as the walk would ask for it.
  void name_declaration_needs(const PendingDeclaration& pending, Needs& needs) const
  {
    if (pending.parentPath.size() >= maxDeclarationDepth)
    {
      return;
    }
    const auto looked = mLookups.find(pending.nodeId);
    if (looked == mLookups.end())
    {
      needs.lookups.add(pending.nodeId);
      return;
    }
    if (!looked->second.is_good() || looked->second.value().get_browse_name().name().empty())
    {
      return;
    }
    const auto read = mDeclarationReferences.find(pending.nodeId);
    if (read == mDeclarationReferences.end())
    {
      needs.declarationReferences.add(pending.nodeId);
    }
    else if (read->second.is_good())
    {
      awaits_classification(read->second.value(), looked->second.value().get_node_class(), needs);
    }
  }

  /// Advances @p walk as far as the facts held allow, taking at most @p budget types and declarations.
  Advance advance(TypeWalk& walk, Needs& needs, size_t& budget)
  {
    try
    {
      // --- the supertype chain, and each type's own aggregate children ---------------------
      while (!walk.typesWalked)
      {
        if (budget == 0)
        {
          return Advance::Yield;
        }
        if (walk.pendingTypes.empty())
        {
          if (!walk.reachedBaseEventType)
          {
            fail_type(walk, "The supplied type is not an ObjectType below BaseEventType");
            return Advance::Done;
          }
          walk.typesWalked = true;
          break;
        }
        if (walk.seenTypes.size() >= maxTypeDepth)
        {
          fail_type(walk, "The EventType supertype hierarchy exceeded its bounded depth");
          return Advance::Done;
        }

        const NodeId& currentTypeId = walk.pendingTypes.front();
        if (walk.seenTypes.contains(currentTypeId))
        {
          fail_type(walk, "The EventType supertype hierarchy contains a cycle");
          return Advance::Done;
        }

        const auto looked = mLookups.find(currentTypeId);
        if (looked == mLookups.end())
        {
          needs.lookups.add(currentTypeId);
          return Advance::Blocked;
        }
        if (!looked->second.is_good())
        {
          if (looked->second.status_code().as_status() == Status::BadNodeIdUnknown)
          {
            fail_type(walk,
              "An EventType or one of its supertypes could not be resolved",
              looked->second.status_code());
          }
          else
          {
            fail(walk,
              looked->second.status_code(),
              "EventTypeLookupFailed",
              "An EventType or one of its supertypes could not be resolved");
          }
          return Advance::Done;
        }
        if (!looked->second.value().as<ObjectTypeAccessor>())
        {
          fail_type(walk, "The supplied Event type hierarchy contains a node that is not an ObjectType");
          return Advance::Done;
        }

        const auto read = mTypeReferences.find(currentTypeId);
        if (read == mTypeReferences.end())
        {
          needs.typeReferences.add(currentTypeId);
          return Advance::Blocked;
        }
        if (!read->second.is_good())
        {
          fail(walk,
            read->second.status_code(),
            "EventTypeReferencesUnavailable",
            "EventType references could not be read");
          return Advance::Done;
        }
        const std::vector<Reference>& references = read->second.value();
        if (awaits_classification(references, std::nullopt, needs))
        {
          return Advance::Blocked;
        }

        --budget;
        const NodeId typeId = currentTypeId;
        walk.pendingTypes.pop_front();
        walk.seenTypes.insert(typeId);
        const bool currentTypeIsBase = typeId == NodeId{ObjectTypeId::BaseEventType};
        walk.reachedBaseEventType = walk.reachedBaseEventType || currentTypeIsBase;

        for (const auto& reference : references)
        {
          if (reference.is_remote() || !reference.target_id().is_local())
          {
            continue;
          }
          if (!reference.is_forward() && !currentTypeIsBase &&
              reference.type_id() == NodeId{ReferenceTypeId::HasSubtype})
          {
            walk.pendingTypes.push_back(reference.target_id().node_id());
            continue;
          }
          if (!reference.is_forward())
          {
            continue;
          }
          if (is_core_aggregate(reference.type_id()))
          {
            walk.pendingDeclarations.push_back({reference.target_id().node_id(), {}});
            continue;
          }
          if (is_intrinsic_non_aggregate(reference.type_id()))
          {
            continue;
          }

          const BoolResult& classified = mAggregates.at(reference.type_id());
          if (!classified.is_good())
          {
            fail(walk,
              classified.status_code(),
              "AggregateReferenceClassificationFailed",
              "An EventType reference could not be classified against Aggregates");
            return Advance::Done;
          }
          if (classified.value())
          {
            walk.pendingDeclarations.push_back({reference.target_id().node_id(), {}});
          }
        }
      }

      // --- the declarations those types contributed, and everything under them --------------
      while (true)
      {
        if (budget == 0)
        {
          return Advance::Yield;
        }
        if (walk.pendingDeclarations.empty())
        {
          walk.result = DeclarationsResult{std::move(walk.declarations)};
          return Advance::Done;
        }
        if (walk.declarations.size() + walk.pendingDeclarations.size() > maxDeclarations)
        {
          fail(walk,
            StatusCode{Status::BadEncodingLimitsExceeded},
            "EventTypeDeclarationLimitExceeded",
            "The EventType declaration graph exceeded its bounded size");
          return Advance::Done;
        }

        const PendingDeclaration& current = walk.pendingDeclarations.front();
        if (current.parentPath.size() >= maxDeclarationDepth)
        {
          fail(walk,
            StatusCode{Status::BadEncodingLimitsExceeded},
            "EventTypeDeclarationDepthExceeded",
            "The EventType declaration graph exceeded its bounded nesting depth");
          return Advance::Done;
        }

        const auto looked = mLookups.find(current.nodeId);
        if (looked == mLookups.end())
        {
          needs.lookups.add(current.nodeId);
          return Advance::Blocked;
        }
        if (!looked->second.is_good())
        {
          fail(walk,
            looked->second.status_code(),
            "EventTypeDeclarationUnavailable",
            "An InstanceDeclaration referenced by the EventType could not be resolved");
          return Advance::Done;
        }
        const NodeAccessor& node = looked->second.value();

        // An InstanceDeclaration is addressed by its BrowsePath, so one carrying no BrowseName names
        // no event field - and two such declarations under one parent would dedup against each other
        // on an equal, empty path. Skip it and its subtree rather than declaring a field nothing can
        // select.
        const QualifiedName declarationName = node.get_browse_name();
        if (declarationName.name().empty())
        {
          --budget;
          walk.pendingDeclarations.pop_front();
          continue;
        }
        const NodeClass currentNodeClass = node.get_node_class();

        const auto read = mDeclarationReferences.find(current.nodeId);
        if (read == mDeclarationReferences.end())
        {
          needs.declarationReferences.add(current.nodeId);
          return Advance::Blocked;
        }
        if (!read->second.is_good())
        {
          fail(walk,
            read->second.status_code(),
            "EventTypeDeclarationReferencesUnavailable",
            "InstanceDeclaration references could not be read");
          return Advance::Done;
        }
        const std::vector<Reference>& references = read->second.value();
        if (awaits_classification(references, currentNodeClass, needs))
        {
          return Advance::Blocked;
        }

        --budget;
        const PendingDeclaration taken = std::move(walk.pendingDeclarations.front());
        walk.pendingDeclarations.pop_front();

        Declaration declaration;
        declaration.browsePath = taken.parentPath;
        declaration.browsePath.push_back(declarationName);
        declaration.nodeId = taken.nodeId;
        declaration.accessor = node;
        declaration.nodeClass = currentNodeClass;
        if (auto variable = node.as<VariableAccessor>())
        {
          try
          {
            declaration.dataType = variable->get_data_type();
          }
          catch (...)
          {
            // DataType constrains history-update values but is irrelevant to BrowsePath NodeClass
            // validation. A namespace that omits the optional cached attribute leaves it unknown.
            declaration.dataType = NodeId{};
          }
        }
        const std::vector<QualifiedName> currentPath = declaration.browsePath;

        const auto alreadyDeclared = std::find_if(walk.declarations.begin(),
          walk.declarations.end(),
          [&declaration](const Declaration& existing)
          { return same_path(existing.browsePath, declaration.browsePath); });
        if (alreadyDeclared == walk.declarations.end())
          walk.declarations.push_back(std::move(declaration));

        for (const auto& reference : references)
        {
          if (!reference.is_forward() || reference.is_remote() || !reference.target_id().is_local())
          {
            continue;
          }
          if (reference.type_id() == NodeId{ReferenceTypeId::HasModellingRule})
          {
            if (reference.target_id().node_id() == NodeId{ObjectId::ModellingRule_Mandatory})
            {
              const auto found = std::find_if(walk.declarations.rbegin(),
                walk.declarations.rend(),
                [&currentPath](const Declaration& candidate)
                { return same_path(candidate.browsePath, currentPath); });
              if (found != walk.declarations.rend())
                found->mandatory = true;
            }
            continue;
          }
          if (currentNodeClass != NodeClass::Object && currentNodeClass != NodeClass::Variable)
          {
            continue;
          }
          if (is_core_aggregate(reference.type_id()))
          {
            walk.pendingDeclarations.push_back({reference.target_id().node_id(), currentPath});
            continue;
          }
          if (is_intrinsic_non_aggregate(reference.type_id()))
          {
            continue;
          }

          const BoolResult& classified = mAggregates.at(reference.type_id());
          if (!classified.is_good())
          {
            fail(walk,
              classified.status_code(),
              "AggregateReferenceClassificationFailed",
              "An InstanceDeclaration reference could not be classified against Aggregates");
            return Advance::Done;
          }
          if (classified.value())
          {
            walk.pendingDeclarations.push_back({reference.target_id().node_id(), currentPath});
          }
        }
      }
    }
    catch (...)
    {
      walk.result = DeclarationsResult{ua::exception_to_status_code(std::current_exception())};
      return Advance::Done;
    }
  }

  /// Ends @p walk with @p status under the ErrorDetail @p key. A status that is not Bad (an Uncertain answer,
  /// which holds no value) is answered `Bad_InternalError` with it as the cause, so the result is never read
  /// as holding declarations.
  static void fail(TypeWalk& walk, const StatusCode& status, std::string_view key, std::string_view message)
  {
    std::unique_ptr<ua::ErrorDetail> detail =
      ErrorDetail::build(std::string{key}, "Event type model operation failed", "EventTypeModel")
        .context(ua::ContextKeys::nodeId, to_string(walk.eventType))
        .context(ua::ContextKeys::errorMessage, std::string{message})
        .cause(status);
    const Status outer = status.is_bad() ? status.as_status() : Status::BadInternalError;
    walk.result = DeclarationsResult{StatusCode{outer, std::move(detail)}};
  }

  static void fail_type(TypeWalk& walk, std::string_view message, const StatusCode& cause = StatusCode{})
  {
    auto builder =
      ErrorDetail::build("EventTypeDefinitionInvalid", "Event type definition is invalid", "EventTypeModel");
    builder.context(ua::ContextKeys::nodeId, to_string(walk.eventType));
    builder.context(ua::ContextKeys::errorMessage, std::string{message});
    if (!cause.is_good() || cause.shared_detail())
      builder.cause(cause);
    std::unique_ptr<ua::ErrorDetail> detail = builder;
    walk.result = DeclarationsResult{StatusCode{Status::BadTypeDefinitionInvalid, std::move(detail)}};
  }

  // --- the answers ---------------------------------------------------------------------------------------

  /// The walk's result for @p eventType; null when it has none, which `collect` does not leave.
  const DeclarationsResult* result_of(const NodeId& eventType) const
  {
    const auto walk = mWalkOf.find(eventType);
    if (walk == mWalkOf.end())
    {
      return nullptr;
    }
    const auto& walkResult = mWalks[walk->second].result;
    if (!walkResult)
    {
      return nullptr;
    }
    return &walkResult.value();
  }

  void finish_declarations()
  {
    std::vector<DeclarationsResult> answers;
    answers.reserve(mEventTypes.size());
    for (const auto& eventType : mEventTypes)
    {
      const DeclarationsResult* result = result_of(eventType);
      answers.push_back(result ? *result : DeclarationsResult{answer_missing()});
    }
    if (auto callback = std::move(mOnDeclarations))
    {
      callback(std::move(answers));
    }
  }

  /// Resolves each SelectClause of each filter against the declarations of the type it names.
  ///
  /// A clause that names no type definition, or whose BrowsePath is not among the declarations, is Good with
  /// no accessor rather than an error: Part 4 7.22.3 makes declaration availability depend on the concrete
  /// Event type, so projection decides per Event whether the field is present. Only a traversal through
  /// something that is neither Object nor Variable is a filter error.
  ua::async::Task<> resolve_models()
  {
    std::vector<SelectClauseModelsResult> answers;
    answers.reserve(mFilters.size());
    size_t clausesThisTurn = 0;
    for (const auto& filter : mFilters)
    {
      std::optional<SelectClauseModelsResult> answer;
      try
      {
        SelectClauseModels models;
        models.reserve(filter.select_clauses().size());
        for (size_t clauseIndex = 0; clauseIndex < filter.select_clauses().size(); ++clauseIndex)
        {
          if (++clausesThisTurn > clausesPerTurn)
          {
            clausesThisTurn = 0;
            co_await yield_strand();
          }
          models.push_back(model_of(filter.select_clauses()[clauseIndex]));
        }
        answer.emplace(std::move(models));
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        answer.emplace(ua::exception_to_status_code(std::current_exception()));
      }
      answers.push_back(std::move(*answer));
    }
    if (auto callback = std::move(mOnModels))
    {
      callback(std::move(answers));
    }
    co_return;
  }

  SelectClauseModel model_of(const SimpleAttributeOperand& clause) const
  {
    if (clause.type_definition_id().is_null())
    {
      return SelectClauseModel{.status = StatusCode{Status::Good}, .declarationAccessor = std::nullopt};
    }

    const DeclarationsResult* declarationsResult = result_of(clause.type_definition_id());
    if (!declarationsResult)
    {
      return SelectClauseModel{.status = answer_missing(), .declarationAccessor = std::nullopt};
    }
    if (!declarationsResult->is_good())
    {
      return SelectClauseModel{
        .status = declarationsResult->status_code(), .declarationAccessor = std::nullopt};
    }

    const auto& path = clause.browse_path();
    if (path.empty())
    {
      // The type itself, as its walk looked it up.
      const auto looked = mLookups.find(clause.type_definition_id());
      if (looked == mLookups.end())
      {
        return SelectClauseModel{.status = answer_missing(), .declarationAccessor = std::nullopt};
      }
      if (!looked->second.is_good())
      {
        return SelectClauseModel{.status = looked->second.status_code(), .declarationAccessor = std::nullopt};
      }
      return SelectClauseModel{
        .status = StatusCode{Status::Good}, .declarationAccessor = looked->second.value()};
    }

    const auto& declarations = declarationsResult->value();
    std::optional<NodeAccessor> declarationAccessor;
    for (size_t pathIndex = 0; pathIndex < path.size(); ++pathIndex)
    {
      const auto pathSpan = path.as_span();
      const std::span<const QualifiedName> prefix{pathSpan.data(), pathIndex + 1};
      const auto found = std::find_if(declarations.begin(),
        declarations.end(),
        [prefix](const Declaration& declaration)
        {
          return declaration.browsePath.size() == prefix.size() &&
                 std::equal(prefix.begin(), prefix.end(), declaration.browsePath.begin());
        });
      if (found == declarations.end())
      {
        // Part 4 section 7.22.3: declaration availability can depend on the concrete Event type,
        // so projection decides whether this field is present for each Event.
        return SelectClauseModel{.status = StatusCode{Status::Good}, .declarationAccessor = std::nullopt};
      }
      if (pathIndex + 1 == path.size())
        declarationAccessor = found->accessor;
      if (found->nodeClass != NodeClass::Object && found->nodeClass != NodeClass::Variable)
      {
        return SelectClauseModel{
          .status = StatusCode{Status::BadFilterOperandInvalid,
            ErrorDetail::build("EventFieldNodeClassInvalid",
              "A SimpleAttributeOperand BrowsePath may traverse only Object or Variable declarations",
              "EventTypeModel")
              .context(ua::ContextKeys::index, pathIndex)
              .context(ua::ContextKeys::nodeBrowseName, to_string(path[pathIndex]))
              .context(ua::ContextKeys::nodeId, to_string(found->nodeId))
              .context(ua::ContextKeys::value, to_string(found->nodeClass))},
          .declarationAccessor = std::nullopt};
      }
    }
    return SelectClauseModel{
      .status = StatusCode{Status::Good}, .declarationAccessor = std::move(declarationAccessor)};
  }

  WeakAddressSpace mAddressSpace;
  size_t mLoopLimit;
  RequestInfo mRequest;
  /// The types asked for, in order, repeats included; the select-clause form's distinct types.
  std::vector<NodeId> mEventTypes;
  std::vector<EventFilter> mFilters;
  DeclarationsCompletion mOnDeclarations;
  ModelsCompletion mOnModels;

  /// One walk per distinct type, and where each type's walk is.
  std::vector<TypeWalk> mWalks;
  std::unordered_map<NodeId, size_t> mWalkOf;

  /// What the request has learned, each fact fetched once: every Node's lookup answer, the References of the
  /// Nodes walked as types and as declarations, and whether each application ReferenceType met is a subtype
  /// of Aggregates.
  std::unordered_map<NodeId, NodeAccessorResult> mLookups;
  std::unordered_map<NodeId, Result<std::vector<Reference>>> mTypeReferences;
  std::unordered_map<NodeId, Result<std::vector<Reference>>> mDeclarationReferences;
  std::unordered_map<NodeId, BoolResult> mAggregates;
};

}  // namespace

void collect_declarations_async(
  AddressSpace addressSpace, NodeId eventType, CollectCallback onComplete) noexcept
{
  Logger logger;
  try
  {
    logger = addressSpace.logger().with_category("events");
    std::vector<NodeId> eventTypes;
    eventTypes.push_back(std::move(eventType));
    EventTypeModelOperation::collect(std::move(addressSpace),
      RequestInfo{},
      std::move(eventTypes),
      [onComplete](std::vector<DeclarationsResult> results)
      { onComplete(results.empty() ? DeclarationsResult{answer_missing()} : std::move(results.front())); });
  }
  catch (...)
  {
    const auto failure = ua::exception_to_status_code(std::current_exception());
    ::ua::detail::invoke_user_callback(logger, onComplete, DeclarationsResult{std::move(failure)});
  }
}

void resolve_select_clause_models_async(
  AddressSpace addressSpace, EventFilter filter, ResolveSelectClauseModelsCallback onComplete) noexcept
{
  Logger logger;
  try
  {
    logger = addressSpace.logger().with_category("events");
    std::vector<EventFilter> filters;
    filters.push_back(std::move(filter));
    EventTypeModelOperation::resolve(std::move(addressSpace),
      RequestInfo{},
      std::move(filters),
      [onComplete](std::vector<SelectClauseModelsResult> results) {
        onComplete(results.empty() ? SelectClauseModelsResult{answer_missing()} : std::move(results.front()));
      });
  }
  catch (...)
  {
    const auto failure = ua::exception_to_status_code(std::current_exception());
    ::ua::detail::invoke_user_callback(logger, onComplete, SelectClauseModelsResult{std::move(failure)});
  }
}

void resolve_select_clause_models_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<EventFilter> filters,
  std::function<void(std::vector<SelectClauseModelsResult>)> onComplete) noexcept
{
  Logger logger;
  const size_t count = filters.size();
  try
  {
    logger = addressSpace.logger().with_category("events");
    EventTypeModelOperation::resolve(
      std::move(addressSpace), std::move(request), std::move(filters), onComplete);
  }
  catch (...)
  {
    const auto failure = ua::exception_to_status_code(std::current_exception());
    // An empty answer only when not even the failures could be allocated.
    std::vector<SelectClauseModelsResult> failed;
    try
    {
      failed.assign(count, SelectClauseModelsResult{failure});
    }
    catch (...)
    {
      failed.clear();
    }
    ::ua::detail::invoke_user_callback(logger, onComplete, std::move(failed));
  }
}

void validate_select_clauses_async(
  AddressSpace addressSpace, EventFilter filter, ValidateSelectClausesCallback onComplete) noexcept
{
  resolve_select_clause_models_async(std::move(addressSpace),
    std::move(filter),
    [onComplete = std::move(onComplete)](SelectClauseModelsResult result) mutable
    {
      if (!onComplete)
        return;
      if (!result.has_value())
      {
        onComplete(SelectClauseStatusesResult{result.status_code()});
        return;
      }
      std::optional<SelectClauseStatusesResult> statusesResult;
      try
      {
        SelectClauseStatuses statuses;
        statuses.reserve(result.value().size());
        for (const auto& model : result.value())
          statuses.push_back(model.status);
        // The statuses keep the code of the models they come from: a Good subcode or an Uncertain code.
        statusesResult.emplace(std::move(statuses), result.status_code());
      }
      catch (...)
      {
        statusesResult.emplace(ua::exception_to_status_code(std::current_exception()));
      }
      onComplete(std::move(*statusesResult));
    });
}

}  // namespace ua::server::event_type_model
