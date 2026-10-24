// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subtype_facts.h"

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node_accessor_route.h"
#include "ua_on_strand.h"
#include "ua_reference_type_model.h"
#include "ua_referencetype_id.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>

namespace ua
{

namespace namespace_calls
{

void find_nodes(const AddressSpace& addressSpace, const RequestInfo& request, std::vector<NodeId> nodeIds,
  std::function<void(std::vector<NodeAccessorResult>)> done) noexcept
{
  try
  {
    std::vector<ua::detail::LookupItem> lookups;
    lookups.reserve(nodeIds.size());
    for (auto& nodeId : nodeIds)
    {
      lookups.push_back(ua::detail::LookupItem{std::move(nodeId), std::nullopt});
    }
    const std::size_t count = lookups.size();
    ua::detail::NodeAccessorRoute::find_nodes(
      addressSpace.weak(),
      request,
      lookups,
      [count, done](BatchResult<NodeAccessorResult> found)
      {
        if (found.batchStatus.is_good() && found.items.size() == count)
        {
          done(std::vector<NodeAccessorResult>(
            std::make_move_iterator(found.items.begin()), std::make_move_iterator(found.items.end())));
          return;
        }
        const StatusCode failure =
          found.batchStatus.is_bad()
            ? found.batchStatus.status_code()
            : StatusCode{Status::BadInternalError,
                ErrorDetail::build("LookupItemCountMismatch",
                  "The lookup answered another number of items than it was asked for",
                  "WriteTypeFacts")
                  .context(ContextKeys::sizeExpected, std::to_string(count))
                  .context(ContextKeys::sizeActual, std::to_string(found.items.size()))};
        done(std::vector<NodeAccessorResult>(count, NodeAccessorResult{failure}));
      },
      addressSpace.weak());
  }
  catch (...)
  {
    done(std::vector<NodeAccessorResult>(
      nodeIds.size(), NodeAccessorResult{exception_to_status_code(std::current_exception())}));
  }
}

namespace
{

// A reading runs this many rounds on the stack the previous round answered on, then the next round starts
// from a post to the address space's executor: namespaces may answer inline, and a namespace that pages for
// long would otherwise nest every round inside the previous one.
constexpr std::size_t inlineRounds = 32;

// The types a read hints: its type, then its other types.
std::vector<NodeId> hinted_types(const ReferenceRead& read)
{
  std::vector<NodeId> types;
  types.reserve(1 + read.otherTypes.size());
  types.push_back(read.referenceType);
  types.insert(types.end(), read.otherTypes.begin(), read.otherTypes.end());
  return types;
}

// Whether a read keeps a Reference of @p type: one of its types, or, when it keeps subtypes, a type that may
// be a subtype of one.
bool type_read(const ReferenceRead& read, const NodeId& type)
{
  if (type == read.referenceType || std::ranges::find(read.otherTypes, type) != read.otherTypes.end())
  {
    return true;
  }
  return read.subtypes && reference_type_may_match_hint(type, hinted_types(read));
}

struct ReferenceReading : std::enable_shared_from_this<ReferenceReading>
{
  ReferenceReading(const AddressSpace& space, RequestInfo info, std::optional<uint32_t> callLimit)
    : addressSpace(space.weak()), executor(space.executor()), logger(space.logger()),
      request(std::move(info)), limit(callLimit)
  {}

  WeakAddressSpace addressSpace;
  boost::asio::any_io_executor executor;
  Logger logger;
  RequestInfo request;
  std::vector<ReferenceRead> reads;
  std::optional<uint32_t> limit;
  std::vector<std::vector<Reference>> found;
  std::vector<std::optional<StatusCode>> failed;
  std::vector<bool> ended;
  std::vector<Result<std::vector<Reference>>> answers;
  /// Each read's resume token, held with the namespace that issued it, so that a reading that stops or is
  /// dropped before passing it back releases it.
  std::vector<ua::detail::ResumeToken> tokens;
  /// The namespace each read was last sent to.
  std::vector<weak_ptr<Namespace>> issuers;
  /// Each read's answers in a row that held a token and no References.
  std::vector<std::size_t> emptyPages;
  /// Logger copies are prepared before dispatch, then moved during non-throwing token adoption.
  std::vector<Logger> tokenLoggers;
  std::function<void(std::vector<Result<std::vector<Reference>>>)> done;
  std::size_t rounds{0};
};

void finish_reading(
  const shared_ptr<ReferenceReading>& reading, std::optional<StatusCode> failure = std::nullopt) noexcept
{
  if (!reading->done)
  {
    return;
  }
  for (std::size_t k = 0; k < reading->reads.size(); ++k)
  {
    reading->tokens[k].release();
    if (failure && !reading->ended[k])
    {
      reading->failed[k] = *failure;
    }
    const auto& lookupFailure = reading->failed[k];
    if (lookupFailure)
    {
      reading->answers[k] = Result<std::vector<Reference>>{lookupFailure.value()};
    }
    else
    {
      reading->answers[k] = Result<std::vector<Reference>>{std::move(reading->found[k])};
    }
  }
  auto done = std::exchange(reading->done, nullptr);
  ua::detail::invoke_user_callback(reading->logger, done, std::move(reading->answers));
}

void read_round(shared_ptr<ReferenceReading> reading, std::vector<std::size_t> pending);

// The next round, on this stack or, every `inlineRounds` rounds, from a post.
void next_round(shared_ptr<ReferenceReading> reading, std::vector<std::size_t> pending)
{
  if (reading->rounds % inlineRounds != 0)
  {
    read_round(std::move(reading), std::move(pending));
    return;
  }
  try
  {
    async::post_owning(reading.get(),
      reading->executor,
      reading->logger,
      [pending](ReferenceReading& state) mutable
      { read_round(state.shared_from_this(), std::move(pending)); })();
  }
  catch (...)
  {
    finish_reading(reading, exception_to_status_code(std::current_exception()));
  }
}

void read_round(shared_ptr<ReferenceReading> reading, std::vector<std::size_t> pending)
{
  ++reading->rounds;
  try
  {
    auto shared = std::make_shared<std::vector<std::size_t>>(std::move(pending));
    auto addressSpace = reading->addressSpace.lock();
    if (!addressSpace)
    {
      finish_reading(reading, ua::detail::address_space_gone("NamespaceCalls"));
      return;
    }
    std::vector<uint16_t> indexAt;
    indexAt.reserve(shared->size());
    for (const std::size_t k : *shared)
    {
      indexAt.push_back(reading->reads[k].nodeId.namespace_index());
      reading->tokenLoggers[k] = reading->logger;
    }
    const auto& namespaces = addressSpace->namespace_array();
    auto split = ua::detail::split_by_namespace<NodeReferencesResult>(
      indexAt, [&namespaces](uint16_t index) { return namespaces.get_namespace(index); });
    for (const auto& part : split.parts)
    {
      for (const std::size_t position : part.positions)
      {
        reading->issuers[(*shared)[position]] = part.nameSpace;
      }
    }
    ua::detail::NamespaceRoute<NodeReferencesResult>::run(
      std::move(split.answers),
      std::move(split.parts),
      reading->limit,
      [reading, shared](Namespace& nameSpace,
        std::span<const std::size_t>
          positions,
        std::function<void(BatchResult<NodeReferencesResult>)>
          answer)
      {
        // Construct every fallible field before transferring tokens to the actual invocation.
        std::vector<ReferenceQuery> queries;
        queries.reserve(positions.size());
        for (const std::size_t position : positions)
        {
          const std::size_t k = (*shared)[position];
          const ReferenceRead& read = reading->reads[k];
          queries.push_back(
            ReferenceQuery{*read.node, read.nodeId, read.direction, hinted_types(read), 0U, {}});
        }
        for (std::size_t position = 0; position < positions.size(); ++position)
        {
          queries[position].resumeToken = reading->tokens[(*shared)[positions[position]]].take();
        }
        nameSpace.read_references_async(reading->request, queries, std::move(answer));
      },
      [reading, shared](std::vector<NodeReferencesResult> answers)
      {
        try
        {
          // Adopt every token and preserve every received rich failure before filtering can allocate.
          for (std::size_t position = 0; position < shared->size() && position < answers.size(); ++position)
          {
            const std::size_t k = (*shared)[position];
            auto& answer = answers[position];
            if (!answer.is_good())
            {
              reading->failed[k] = answer.status_code();
              reading->ended[k] = true;
              continue;
            }
            reading->tokens[k] = ua::detail::ResumeToken{std::move(answer.value().resumeToken),
              reading->issuers[k],
              std::move(reading->tokenLoggers[k])};
          }
          std::vector<std::size_t> next;
          for (std::size_t position = 0; position < shared->size() && position < answers.size(); ++position)
          {
            const std::size_t k = (*shared)[position];
            auto& answer = answers[position];
            if (!answer.is_good())
            {
              continue;
            }
            const ReferenceRead& read = reading->reads[k];
            const NodeReferences& page = answer.value();
            for (const auto& reference : page.references)
            {
              const bool forward = read.direction != BrowseDirection::Inverse;
              const bool directionFits =
                read.direction == BrowseDirection::Both || reference.is_forward() == forward;
              if (directionFits && type_read(read, reference.type_id()))
              {
                reading->found[k].push_back(reference);
              }
            }
            reading->emptyPages[k] = page.references.empty() ? reading->emptyPages[k] + 1 : 0;
            if (reading->tokens[k].empty())
            {
              reading->ended[k] = true;
              continue;
            }
            if (reading->emptyPages[k] >= ua::detail::maxEmptyReferencePages)
            {
              // The namespace kept answering a token with no References: the read fails, and its last
              // token is released.
              reading->tokens[k].release();
              reading->failed[k] = StatusCode{Status::BadInternalError,
                ErrorDetail::build("NamespacePagingDidNotEnd",
                  "The namespace kept answering resume tokens for the References of a Node",
                  "NamespaceCalls")
                  .context(ContextKeys::nodeId, to_string(read.nodeId))
                  .context(ContextKeys::limit, std::to_string(ua::detail::maxEmptyReferencePages))};
              reading->ended[k] = true;
              continue;
            }
            next.push_back(k);
          }
          if (next.empty())
          {
            finish_reading(reading);
            return;
          }
          next_round(reading, std::move(next));
        }
        catch (...)
        {
          finish_reading(reading, exception_to_status_code(std::current_exception()));
        }
      },
      reading->addressSpace);
  }
  catch (...)
  {
    finish_reading(reading, exception_to_status_code(std::current_exception()));
  }
}

}  // namespace

void read_references(const AddressSpace& addressSpace, const RequestInfo& request,
  std::vector<ReferenceRead> reads, std::optional<uint32_t> limit,
  std::function<void(std::vector<Result<std::vector<Reference>>>)> done) noexcept
{
  const std::size_t count = reads.size();
  try
  {
    auto reading = std::make_shared<ReferenceReading>(addressSpace, request, limit);
    reading->reads = std::move(reads);
    reading->found.resize(count);
    reading->failed.resize(count);
    reading->ended.resize(count);
    reading->answers.assign(count, Result<std::vector<Reference>>{StatusCode{Status::BadInternalError}});
    reading->tokens.resize(count);
    reading->issuers.resize(count);
    reading->emptyPages.resize(count);
    reading->tokenLoggers.resize(count);
    std::vector<std::size_t> pending(count);
    reading->done = std::move(done);
    if (count == 0)
    {
      finish_reading(reading);
      return;
    }
    for (std::size_t k = 0; k < count; ++k)
    {
      pending[k] = k;
    }
    read_round(std::move(reading), std::move(pending));
  }
  catch (...)
  {
    if (done)
    {
      done(std::vector<Result<std::vector<Reference>>>(
        count, Result<std::vector<Reference>>{exception_to_status_code(std::current_exception())}));
    }
  }
}

}  // namespace namespace_calls

namespace
{

// A chain climbs this many levels on the stack the previous level answered on, then the next level starts
// from a post to the address space's executor: namespaces may answer inline, and a deep bound would otherwise
// nest a level's calls inside the previous one's without limit.
constexpr std::size_t inlineLevels = 32;

struct Walking : std::enable_shared_from_this<Walking>
{
  explicit Walking(const AddressSpace& space)
    : addressSpace(space.weak()), executor(space.executor()), logger(space.logger()),
      unended(Status::BadInternalError, ErrorDetail::build("SupertypeWalkUnended",
                                          "The walk ended without an end for this chain", "SubtypeFacts"))
  {}

  WeakAddressSpace addressSpace;
  boost::asio::any_io_executor executor;
  Logger logger;
  RequestInfo request;
  SupertypeWalkCheck check;
  std::vector<std::optional<NodeAccessor>> current;
  std::vector<NodeId> currentId;
  std::vector<std::optional<SupertypeWalkEnd>> ends;
  std::vector<SupertypeWalkEnd> answers;
  std::size_t depth{0};
  std::size_t maxDepth{0};
  std::function<void(std::vector<SupertypeWalkEnd>)> done;
  StatusCode unended;
};

void finish_walk(
  const shared_ptr<Walking>& walking, std::optional<StatusCode> failure = std::nullopt) noexcept
{
  if (!walking->done)
  {
    return;
  }
  for (std::size_t chain = 0; chain < walking->ends.size(); ++chain)
  {
    walking->answers[chain] = walking->ends[chain].value_or(
      SupertypeWalkEnd{SupertypeWalkEnd::How::Failed, 0, failure.value_or(walking->unended)});
  }
  auto done = std::exchange(walking->done, nullptr);
  ua::detail::invoke_user_callback(walking->logger, done, std::move(walking->answers));
}

void walk_level(shared_ptr<Walking> walking);

// The next level, on this stack or, every `inlineLevels` levels, from a post.
void next_level(shared_ptr<Walking> walking)
{
  try
  {
    if (walking->depth % inlineLevels != 0)
    {
      walk_level(std::move(walking));
      return;
    }
    async::post_owning(walking.get(),
      walking->executor,
      walking->logger,
      [](Walking& state) { walk_level(state.shared_from_this()); })();
  }
  catch (...)
  {
    finish_walk(walking, exception_to_status_code(std::current_exception()));
  }
}

// One level: the chains still walking are checked at their current type; those not decided read its inverse
// HasSubtype References, and their supertypes are looked up.
void walk_level(shared_ptr<Walking> walking)
{
  try
  {
    using How = SupertypeWalkEnd::How;
    std::vector<std::size_t> active;
    for (std::size_t chain = 0; chain < walking->ends.size(); ++chain)
    {
      if (walking->ends[chain])
      {
        continue;
      }
      try
      {
        if (auto decided = walking->check(chain, walking->currentId[chain]))
        {
          walking->ends[chain] = SupertypeWalkEnd{How::Decided, *decided, StatusCode{}};
          continue;
        }
        if (walking->depth >= walking->maxDepth)
        {
          walking->ends[chain] = SupertypeWalkEnd{How::Failed,
            0,
            StatusCode{Status::BadEncodingLimitsExceeded,
              ErrorDetail::build("SupertypeWalkTooDeep",
                "The supertype chain climbed its bound without being decided",
                "SubtypeFacts")
                .context(ContextKeys::nodeId, to_string(walking->currentId[chain]))
                .context(ContextKeys::limit, std::to_string(walking->maxDepth))}};
          continue;
        }
        // A Node that is not a type has no supertype, as node_utils::get_super_type_async answers.
        if (!walking->current[chain]->is_type())
        {
          walking->ends[chain] = SupertypeWalkEnd{How::NoSuper, 0, StatusCode{}};
          continue;
        }
      }
      catch (...)
      {
        walking->ends[chain] =
          SupertypeWalkEnd{How::Failed, 0, exception_to_status_code(std::current_exception())};
        continue;
      }
      active.push_back(chain);
    }
    if (active.empty())
    {
      finish_walk(walking);
      return;
    }

    auto owner = walking->addressSpace.lock();
    if (!owner)
    {
      finish_walk(walking, ua::detail::address_space_gone("SubtypeFacts"));
      return;
    }
    std::vector<namespace_calls::ReferenceRead> reads;
    reads.reserve(active.size());
    for (const std::size_t chain : active)
    {
      reads.push_back(namespace_calls::ReferenceRead{*walking->current[chain],
        walking->currentId[chain],
        BrowseDirection::Inverse,
        NodeId{ReferenceTypeId::HasSubtype}});
    }
    namespace_calls::read_references(*owner,
      walking->request,
      std::move(reads),
      std::nullopt,
      [walking, active](std::vector<Result<std::vector<Reference>>> references)
      {
        try
        {
          // Adopt every received failure and empty chain before allocating continuing-chain storage.
          for (std::size_t k = 0; k < active.size(); ++k)
          {
            const std::size_t chain = active[k];
            if (k >= references.size())
            {
              walking->ends[chain] = SupertypeWalkEnd{How::Failed, 0, StatusCode{Status::BadInternalError}};
            }
            else if (!references[k].is_good())
            {
              walking->ends[chain] = SupertypeWalkEnd{How::Failed, 0, references[k].status_code()};
            }
            else if (references[k].value().empty())
            {
              walking->ends[chain] = SupertypeWalkEnd{How::NoSuper, 0, StatusCode{}};
            }
          }
          std::vector<std::size_t> climbing;
          std::vector<NodeId> supertypes;
          for (std::size_t k = 0; k < active.size(); ++k)
          {
            const std::size_t chain = active[k];
            if (walking->ends[chain])
            {
              continue;
            }
            const auto& held = references[k].value();
            const auto target = held.front().target_id();
            if (!target.is_local())
            {
              walking->ends[chain] = SupertypeWalkEnd{How::Failed,
                0,
                StatusCode{Status::BadNotSupported,
                  ErrorDetail::build(
                    "SupertypeRemote", "The supertype is a Node of another server", "SubtypeFacts")
                    .context(ContextKeys::nodeId, to_string(walking->currentId[chain]))}};
              continue;
            }
            // A supertype the check decides needs no lookup.
            try
            {
              if (auto decided = walking->check(chain, target.node_id()))
              {
                walking->ends[chain] = SupertypeWalkEnd{How::Decided, *decided, StatusCode{}};
                continue;
              }
            }
            catch (...)
            {
              walking->ends[chain] =
                SupertypeWalkEnd{How::Failed, 0, exception_to_status_code(std::current_exception())};
              continue;
            }
            climbing.push_back(chain);
            supertypes.push_back(target.node_id());
          }
          if (climbing.empty())
          {
            finish_walk(walking);
            return;
          }
          ++walking->depth;
          auto addressSpace = walking->addressSpace.lock();
          if (!addressSpace)
          {
            finish_walk(walking, ua::detail::address_space_gone("SubtypeFacts"));
            return;
          }
          namespace_calls::find_nodes(*addressSpace,
            walking->request,
            supertypes,
            [walking, climbing, supertypes](std::vector<NodeAccessorResult> found)
            {
              try
              {
                // An earlier successful NodeId copy cannot replace a later received rich refusal.
                for (std::size_t k = 0; k < climbing.size(); ++k)
                {
                  const std::size_t chain = climbing[k];
                  if (k >= found.size())
                  {
                    walking->ends[chain] =
                      SupertypeWalkEnd{How::Failed, 0, StatusCode{Status::BadInternalError}};
                  }
                  else if (!found[k].is_good())
                  {
                    walking->ends[chain] = SupertypeWalkEnd{How::Failed, 0, found[k].status_code()};
                  }
                }
                for (std::size_t k = 0; k < climbing.size(); ++k)
                {
                  const std::size_t chain = climbing[k];
                  if (walking->ends[chain])
                  {
                    continue;
                  }
                  walking->current[chain] = std::move(found[k]).value();
                  walking->currentId[chain] = supertypes[k];
                }
                next_level(walking);
              }
              catch (...)
              {
                finish_walk(walking, exception_to_status_code(std::current_exception()));
              }
            });
        }
        catch (...)
        {
          finish_walk(walking, exception_to_status_code(std::current_exception()));
        }
      });
  }
  catch (...)
  {
    finish_walk(walking, exception_to_status_code(std::current_exception()));
  }
}

}  // namespace

void walk_supertypes(AddressSpace addressSpace, RequestInfo request,
  std::vector<std::pair<NodeAccessor, NodeId>> starts, std::size_t maxDepth, SupertypeWalkCheck check,
  std::function<void(std::vector<SupertypeWalkEnd>)> done)
{
  auto walking = std::make_shared<Walking>(addressSpace);
  walking->request = std::move(request);
  walking->check = std::move(check);
  walking->maxDepth = maxDepth;
  walking->ends.resize(starts.size());
  walking->answers.resize(starts.size());
  for (auto& [node, nodeId] : starts)
  {
    walking->current.emplace_back(std::move(node));
    walking->currentId.push_back(std::move(nodeId));
  }
  walking->done = std::move(done);
  walk_level(std::move(walking));
}

namespace
{

/// The answer of a chain whose walk ended @p end, started at @p written: true when decided, false when it
/// ended without reaching the type asked about or failed for a reason that answers false (the start or a
/// supertype not existing, a remote supertype, the depth bound), and the failure otherwise.
BoolResult answer_of(const SupertypeWalkEnd& end, const NodeId& written)
{
  if (end.how == SupertypeWalkEnd::How::Decided)
  {
    return BoolResult{end.value == 1};
  }
  if (end.how == SupertypeWalkEnd::How::NoSuper || end.failure == Status::BadNodeIdUnknown)
  {
    return BoolResult{false};
  }
  const auto& detail = end.failure.shared_detail();
  if (detail && (detail->code == "SupertypeRemote" || detail->code == "SupertypeWalkTooDeep"))
  {
    return BoolResult{false};
  }
  return BoolResult{ua::detail::lookup_failure(written, end.failure, "SubtypeFacts")};
}

}  // namespace

void SubtypeFacts::resolve_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<std::pair<NodeId, NodeId>> questions, Bounds bounds,
  std::function<void(std::vector<bool>)> done) noexcept
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
  }
  catch (...)
  {
    // Logging is optional for this projection; continue with the null logger if its copy fails.
    ua::detail::ignore_expected_exception();
  }
  decide_async(std::move(addressSpace),
    std::move(request),
    std::move(questions),
    std::move(bounds),
    [logger, done = std::move(done)](std::vector<BoolResult> decided) mutable
    {
      std::vector<bool> answers;
      try
      {
        answers.reserve(decided.size());
        for (const auto& answer : decided)
        {
          answers.push_back(answer.is_good() && answer.value());
        }
      }
      catch (...)
      {
        answers.assign(decided.size(), false);
      }
      ua::detail::invoke_user_callback(logger, done, std::move(answers));
    });
}

void SubtypeFacts::decide_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<std::pair<NodeId, NodeId>> questions, Bounds bounds,
  std::function<void(std::vector<BoolResult>)> done) noexcept
{
  Logger logger;
  shared_ptr<std::vector<BoolResult>> answers;
  try
  {
    logger = addressSpace.logger();
    if (questions.empty())
    {
      ua::detail::invoke_user_callback(logger, done, std::vector<BoolResult>{});
      return;
    }
    answers = std::make_shared<std::vector<BoolResult>>(questions.size(), BoolResult{false});
    auto asked = std::make_shared<std::vector<std::pair<NodeId, NodeId>>>(std::move(questions));
    auto passed = std::make_shared<std::function<bool(const NodeId&)>>(std::move(bounds.passed));
    const std::size_t maxDepth = bounds.maxDepth;
    std::vector<NodeId> written;
    written.reserve(asked->size());
    for (const auto& question : *asked)
    {
      written.push_back(question.first);
    }
    namespace_calls::find_nodes(addressSpace,
      request,
      written,
      [addressSpace = addressSpace.weak(), logger, request, asked, passed, maxDepth, answers, done](
        std::vector<NodeAccessorResult> found) mutable
      {
        try
        {
          // Establish every equality fact, and every lookup that failed, before allocating storage for the
          // walks.
          for (std::size_t k = 0; k < asked->size(); ++k)
          {
            if (k >= found.size())
            {
              (*answers)[k] = BoolResult{StatusCode{Status::BadInternalError}};
            }
            else if (found[k].is_good())
            {
              (*answers)[k] = BoolResult{(*asked)[k].first == (*asked)[k].second};
            }
            else if (found[k].status_code() != Status::BadNodeIdUnknown)
            {
              (*answers)[k] = BoolResult{
                ua::detail::lookup_failure((*asked)[k].first, found[k].status_code(), "SubtypeFacts")};
            }
          }
          std::vector<std::pair<NodeAccessor, NodeId>> walks;
          auto walkOf = std::make_shared<std::vector<std::size_t>>();
          walks.reserve(asked->size());
          walkOf->reserve(asked->size());
          for (std::size_t k = 0; k < asked->size() && k < found.size(); ++k)
          {
            if (!found[k].is_good() || (*answers)[k].value())
            {
              continue;
            }
            walks.emplace_back(found[k].value(), (*asked)[k].first);
            walkOf->push_back(k);
          }
          if (walks.empty())
          {
            ua::detail::invoke_user_callback(logger, done, std::move(*answers));
            return;
          }
          auto owner = addressSpace.lock();
          if (!owner)
          {
            for (const std::size_t k : *walkOf)
            {
              (*answers)[k] = BoolResult{ua::detail::address_space_gone("SubtypeFacts")};
            }
            ua::detail::invoke_user_callback(logger, done, std::move(*answers));
            return;
          }
          walk_supertypes(
            *owner,
            std::move(request),
            std::move(walks),
            maxDepth,
            [asked, walkOf, passed](std::size_t chain, const NodeId& type) -> std::optional<int>
            {
              if (type == (*asked)[(*walkOf)[chain]].second)
              {
                return 1;
              }
              if (*passed && (*passed)(type))
              {
                return 0;
              }
              return std::nullopt;
            },
            [asked, answers, walkOf, logger, done](std::vector<SupertypeWalkEnd> ends)
            {
              try
              {
                for (std::size_t chain = 0; chain < walkOf->size(); ++chain)
                {
                  const std::size_t k = (*walkOf)[chain];
                  (*answers)[k] = chain < ends.size() ? answer_of(ends[chain], (*asked)[k].first)
                                                      : BoolResult{StatusCode{Status::BadInternalError}};
                }
              }
              catch (...)
              {
                const auto failure = exception_to_status_code(std::current_exception());
                for (const std::size_t k : *walkOf)
                {
                  (*answers)[k] = BoolResult{failure};
                }
              }
              ua::detail::invoke_user_callback(logger, done, std::move(*answers));
            });
        }
        catch (...)
        {
          const auto failure = exception_to_status_code(std::current_exception());
          for (auto& answer : *answers)
          {
            if (answer.is_good() && !answer.value())
            {
              answer = BoolResult{failure};
            }
          }
          ua::detail::invoke_user_callback(logger, done, std::move(*answers));
        }
      });
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(logger, done, std::vector<BoolResult>{});
  }
}

}  // namespace ua
