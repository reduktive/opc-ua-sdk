// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_node_deletion.h"

#include "ua_address_space_impl.h"
#include "ua_callback_safety.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_model_change_step.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_reference_halves.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
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

using AnswerRoute = NamespaceRoute<VoidResult>;

constexpr std::size_t unresolved = std::numeric_limits<std::size_t>::max();

// What every step of one delete holds. The address space is held weakly, so that the completions given to the
// namespaces hold neither it nor a namespace (CALLS-21 rule 1), and a step that finds it gone ends the delete
// (rule 2).
struct Context
{
  weak_ptr<AddressSpaceImpl> addressSpace;
  WeakAddressSpace handle;
  shared_ptr<const NamespaceRegistrationRoute> registrationRoute;
  Logger logger;
  std::optional<uint32_t> nodeManagementLimit;
  EncodingLimits limits;
  /// Whether the other Nodes' halves of the deleted Nodes' References are removed (Both) or left
  /// (ThisHalfOnly).
  ReferenceHalves halves{ReferenceHalves::Both};
  /// The delete's model changes, raised once its last call has answered (NR-36 rule 4).
  shared_ptr<ModelChangeStep> step;
};

uint8_t verb(ModelChangeStructureVerbMask mask) noexcept
{
  return static_cast<uint8_t>(static_cast<int32_t>(mask));
}

StatusCode namespace_not_found(uint16_t namespaceIndex) noexcept
{
  try
  {
    return StatusCode{Status::BadNodeIdUnknown,
      ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "AddressSpace")
        .context(ContextKeys::namespaceIndex, std::to_string(namespaceIndex))};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

// Logs a referrer in another namespace that may keep its half of a Reference to a deleted Node.
void log_left_behind(const Logger& logger, const NodeId& deleted, const NodeId& referrer,
  const StatusCode& status, bool referrerFound) noexcept
{
  try
  {
    const std::string nodeText = to_string(deleted);
    const std::string referrerText = to_string(referrer);
    const std::string statusText = to_string(status);
    const std::string errorText = status.shared_detail() ? to_string(*status.shared_detail()) : std::string{};
    // Two calls: the message is a fmt format string, which must be a literal checked when compiled.
    if (referrerFound)
    {
      logger.with_category("address_space")
        .warning({{"deleted_node", nodeText},
                   {"referrer", referrerText},
                   {"status", statusText},
                   {"error", errorText}},
          "Could not remove a cross-namespace reference to a deleted node; the referrer keeps a reference to "
          "a "
          "node that no longer exists");
    }
    else
    {
      logger.with_category("address_space")
        .warning({{"deleted_node", nodeText},
                   {"referrer", referrerText},
                   {"status", statusText},
                   {"error", errorText}},
          "Could not find a node in another namespace that referenced a deleted node; if it still exists, it "
          "keeps a reference to a node that no longer exists");
    }
  }
  catch (...)
  {
    ignore_expected_exception();
  }
}

// Part 4 5.7.4.4 Table 30: the Node is deleted, but not every Reference to it could be. The cause names the
// first referrer left holding its half, and why.
VoidResult reference_not_deleted(
  const NodeId& deleted, const NodeId& referrer, const StatusCode& cause) noexcept
{
  try
  {
    return VoidResult{StatusCode{Status::UncertainReferenceNotDeleted,
      ErrorDetail::build("CrossNamespaceReferenceNotRemoved",
        "The node was deleted, but a node in another namespace may still hold a Reference to it",
        "AddressSpace")
        .context(ContextKeys::nodeId, to_string(deleted))
        .cause(StatusCode{cause.as_status(),
          ErrorDetail::build("ReferrerKeepsReference",
            "A node in another namespace keeps its half of a Reference to the deleted node",
            "AddressSpace")
            .context(ContextKeys::nodeId, to_string(referrer))
            .cause(cause)})}};
  }
  catch (...)
  {
    return VoidResult{StatusCode{Status::UncertainReferenceNotDeleted}};
  }
}

// Removes, in the other namespaces, their halves of the References that the Nodes deleted by one call report
// (NR-30 rule 5): one `remove_references_async` per referrer namespace, and none when the delete leaves those
// halves (ThisHalfOnly). `done` receives one answer per Node: its delete's failure, Good, or
// Uncertain_ReferenceNotDeleted when a removal left a Reference to it behind.
void remove_other_halves(const shared_ptr<const Context>& context, std::vector<NodeId> deleted,
  std::vector<DeleteNodeResult> results, std::function<void(std::vector<VoidResult>)> done) noexcept
{
  struct Removal
  {
    std::vector<NodeId> deleted;
    std::vector<VoidResult> outcomes;
    std::vector<ReferenceChange> changes;
    // Per change: the position of the deleted Node it belongs to, and whether its namespace was found.
    std::vector<std::size_t> owners;
    std::vector<bool> resolved;
    std::function<void(std::vector<VoidResult>)> done;
  };

  shared_ptr<Removal> removal;
  std::vector<std::optional<VoidResult>> answers;
  std::vector<AnswerRoute::Part> parts;
  try
  {
    removal = std::make_shared<Removal>();
    removal->deleted = std::move(deleted);
    removal->done = std::move(done);
    removal->outcomes.reserve(results.size());
    for (std::size_t i = 0; i < results.size(); ++i)
    {
      const DeleteNodeResult& result = results[i];
      // A delete answered other than Good is the Node's outcome, and its References are not acted on.
      if (!result.is_good())
      {
        removal->outcomes.emplace_back(result.status_code(), result.shared_detail());
        continue;
      }
      // The namespace's Good code is the outcome, a Good subcode included.
      removal->outcomes.emplace_back(result.status_code());
      if (context->halves == ReferenceHalves::ThisHalfOnly)
      {
        continue;
      }
      for (const auto& external : result.value())
      {
        // A target in another Server, or one named by its namespace URI, is not this address space's to
        // change.
        if (!external.target.is_local() || !external.target.is_index_based())
        {
          continue;
        }
        removal->changes.push_back(ReferenceChange{.source = external.target.node_id(),
          .referenceType = external.referenceType,
          .target = ExpandedNodeId{removal->deleted[i]},
          .isForward = !external.isForward});
        removal->owners.push_back(i);
      }
    }
    if (removal->changes.empty())
    {
      std::exchange(removal->done, nullptr)(std::move(removal->outcomes));
      return;
    }
    auto space = context->addressSpace.lock();
    if (!space)
    {
      for (const std::size_t owner : removal->owners)
      {
        removal->outcomes[owner] = VoidResult{address_space_gone("delete_node_async")};
      }
      std::exchange(removal->done, nullptr)(std::move(removal->outcomes));
      return;
    }
    answers.resize(removal->changes.size());
    removal->resolved.assign(removal->changes.size(), true);
    std::unordered_map<uint16_t, std::size_t> partOf;
    for (std::size_t k = 0; k < removal->changes.size(); ++k)
    {
      const uint16_t namespaceIndex = removal->changes[k].source.namespace_index();
      auto [found, added] = partOf.try_emplace(namespaceIndex, unresolved);
      if (added)
      {
        if (auto nameSpace =
              NodeDeletion::resolve_namespace(*space, namespaceIndex, context->registrationRoute))
        {
          found->second = parts.size();
          parts.push_back(AnswerRoute::Part{std::move(nameSpace), {}});
        }
      }
      if (found->second == unresolved)
      {
        answers[k] = VoidResult{namespace_not_found(namespaceIndex)};
        removal->resolved[k] = false;
        continue;
      }
      parts[found->second].positions.push_back(k);
    }
  }
  catch (...)
  {
    // Before the state was built, the completion is still the caller's.
    auto pending = removal ? std::exchange(removal->done, nullptr) : std::move(done);
    if (pending)
    {
      const auto failure = exception_to_status_code(std::current_exception());
      std::vector<VoidResult> failed;
      try
      {
        failed.assign(results.size(), VoidResult{failure});
      }
      catch (...)
      {
        ignore_expected_exception();
      }
      pending(std::move(failed));
    }
    return;
  }

  AnswerRoute::run(
    std::move(answers),
    std::move(parts),
    context->nodeManagementLimit,
    [removal, context](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<VoidResult>)>
        answer)
    {
      std::vector<ReferenceChange> asked;
      asked.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        asked.push_back(removal->changes[position]);
      }
      nameSpace.remove_references_async(RequestInfo{},
        asked,
        recording_versions<VoidResult>(std::move(answer),
          *context->step,
          [](const NodeId&) { return verb(ModelChangeStructureVerbMask::ReferenceDeleted); }));
    },
    [removal, context](std::vector<VoidResult> removed)
    {
      if (const auto owner = context->addressSpace.lock())
      {
        owner->model_changed_if_any(removed);
      }
      try
      {
        // The first failure of each Node, in change order.
        std::vector<std::optional<std::size_t>> firstFailure(removal->deleted.size());
        for (std::size_t k = 0; k < removed.size() && k < removal->changes.size(); ++k)
        {
          const std::size_t owner = removal->owners[k];
          const NodeId& referrer = removal->changes[k].source;
          const StatusCode status = removed[k].status_code();
          if (!removal->resolved[k])
          {
            log_left_behind(
              context->logger, removal->deleted[owner], referrer, status, /*referrerFound=*/false);
            continue;
          }
          if (is_address_space_gone(status))
          {
            removal->outcomes[owner] = VoidResult{status};
            continue;
          }
          // Uncertain_ReferenceNotDeleted: the referrer holds no such Reference. Bad_NodeIdUnknown: its
          // namespace does not hold the referrer, which therefore holds nothing.
          if (removed[k].is_good() || status.as_status() == Status::UncertainReferenceNotDeleted ||
              status.as_status() == Status::BadNodeIdUnknown)
          {
            continue;
          }
          log_left_behind(context->logger, removal->deleted[owner], referrer, status, /*referrerFound=*/true);
          if (!firstFailure[owner])
          {
            firstFailure[owner] = k;
          }
        }
        for (std::size_t owner = 0; owner < firstFailure.size(); ++owner)
        {
          if (firstFailure[owner] && removal->outcomes[owner].is_good())
          {
            const std::size_t k = *firstFailure[owner];
            removal->outcomes[owner] = reference_not_deleted(
              removal->deleted[owner], removal->changes[k].source, removed[k].status_code());
          }
        }
        std::exchange(removal->done, nullptr)(std::move(removal->outcomes));
      }
      catch (...)
      {
        const auto failure = exception_to_status_code(std::current_exception());
        std::vector<VoidResult> failed;
        try
        {
          failed.assign(removal->deleted.size(), VoidResult{failure});
        }
        catch (...)
        {
          ignore_expected_exception();
        }
        if (removal->done)
        {
          std::exchange(removal->done, nullptr)(std::move(failed));
        }
      }
    },
    context->handle);
}

// Deletes @p nodes with one `delete_nodes_async` per namespace, split by maxNodesPerNodeManagement; each
// call's Nodes are answered once the removals of their other halves have answered. `done` receives one answer
// per Node, in order, once; it must not throw.
void delete_nodes(const shared_ptr<const Context>& context, std::vector<NodeId> nodes,
  std::function<void(std::vector<VoidResult>)> done) noexcept
{
  const std::size_t count = nodes.size();
  shared_ptr<const std::vector<NodeId>> requested;
  std::vector<std::optional<VoidResult>> answers;
  std::vector<AnswerRoute::Part> parts;
  try
  {
    auto space = context->addressSpace.lock();
    if (!space)
    {
      done(std::vector<VoidResult>(count, VoidResult{address_space_gone("delete_node_async")}));
      return;
    }
    answers.resize(count);
    std::unordered_map<uint16_t, std::size_t> partOf;
    for (std::size_t i = 0; i < count; ++i)
    {
      const uint16_t namespaceIndex = nodes[i].namespace_index();
      auto [found, added] = partOf.try_emplace(namespaceIndex, unresolved);
      if (added)
      {
        if (auto nameSpace =
              NodeDeletion::resolve_namespace(*space, namespaceIndex, context->registrationRoute))
        {
          found->second = parts.size();
          parts.push_back(AnswerRoute::Part{std::move(nameSpace), {}});
        }
      }
      if (found->second == unresolved)
      {
        answers[i] = VoidResult{namespace_not_found(namespaceIndex)};
        continue;
      }
      parts[found->second].positions.push_back(i);
    }
    requested = std::make_shared<const std::vector<NodeId>>(std::move(nodes));
  }
  catch (...)
  {
    const auto failure = exception_to_status_code(std::current_exception());
    std::vector<VoidResult> failed;
    try
    {
      failed.assign(count, VoidResult{failure});
    }
    catch (...)
    {
      ignore_expected_exception();
    }
    done(std::move(failed));
    return;
  }

  AnswerRoute::run(
    std::move(answers),
    std::move(parts),
    context->nodeManagementLimit,
    [context, requested](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<VoidResult>)>
        answer)
    {
      std::vector<NodeId> asked;
      asked.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        asked.push_back((*requested)[position]);
      }
      auto deleting = std::make_shared<const std::vector<NodeId>>(std::move(asked));
      // The call ends when its answer, and the removals of the other halves it starts, have been passed on.
      auto call = context->step->call();
      auto pending = std::make_shared<std::function<void(BatchResult<VoidResult>)>>(
        [answer = std::move(answer), call](BatchResult<VoidResult> result)
        {
          call->end();
          answer(std::move(result));
        });
      auto answered = std::make_shared<std::atomic<bool>>(false);
      nameSpace.delete_nodes_async(RequestInfo{},
        *deleting,
        context->halves,
        [context, deleting, pending, answered, call](
          BatchResult<DeleteNodeResult> deleted, std::vector<VersionedNode> versioned)
        {
          // A second completion is ignored here as the route ignores it, so the removals run once.
          if (answered->exchange(true, std::memory_order_acq_rel))
          {
            return;
          }
          try
          {
            // A deleted Node is NodeDeleted; a Node left that lost a Reference to one is ReferenceDeleted.
            const std::unordered_set<NodeId> sent{deleting->begin(), deleting->end()};
            call->step().record(versioned,
              [&sent](const NodeId& node)
              {
                return sent.contains(node) ? verb(ModelChangeStructureVerbMask::NodeDeleted)
                                           : verb(ModelChangeStructureVerbMask::ReferenceDeleted);
              });
            if (!deleted.batchStatus.is_good() || deleted.items.size() != deleting->size())
            {
              // Passed on as answered: the route fails every item of the call.
              BatchResult<VoidResult> passed;
              passed.batchStatus = std::move(deleted.batchStatus);
              passed.items.resize(deleted.items.size());
              (*pending)(std::move(passed));
              return;
            }
            std::vector<DeleteNodeResult> results{
              std::make_move_iterator(deleted.items.begin()), std::make_move_iterator(deleted.items.end())};
            if (const auto owner = context->addressSpace.lock())
            {
              owner->model_changed_if_any(results);
            }
            remove_other_halves(context,
              *deleting,
              std::move(results),
              [pending](std::vector<VoidResult> outcomes)
              {
                BatchResult<VoidResult> result;
                try
                {
                  result.items.assign(
                    std::make_move_iterator(outcomes.begin()), std::make_move_iterator(outcomes.end()));
                }
                catch (...)
                {
                  result.items.clear();
                  result.batchStatus = VoidResult{exception_to_status_code(std::current_exception())};
                }
                (*pending)(std::move(result));
              });
          }
          catch (...)
          {
            BatchResult<VoidResult> failed;
            failed.batchStatus = VoidResult{exception_to_status_code(std::current_exception())};
            (*pending)(std::move(failed));
          }
        });
    },
    std::move(done),
    context->handle);
}

// A delete of a Node's forward hierarchical subtree (NR-17 rule 3): the subtree is found one level at a time,
// then the levels are deleted deepest first, each as one call per namespace. Every step runs after the
// previous one has answered, so the members need no lock.
class SubtreeDeletion : public std::enable_shared_from_this<SubtreeDeletion>
{
public:
  SubtreeDeletion(shared_ptr<const Context> context, std::function<void(VoidResult)> callback)
    : mContext(std::move(context)), mCallback(std::move(callback))
  {}

  void start(const NodeId& root) noexcept
  {
    try
    {
      mReached.insert(root);
      find_level({root});
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

private:
  // One level being read: its Nodes, and per Node the forward References read so far or why they could not
  // be.
  struct Level
  {
    std::vector<NodeId> ids;
    std::vector<NodeAccessor> nodes;
    std::vector<std::vector<Reference>> forward;
    std::vector<std::optional<StatusCode>> failed;
    std::vector<std::size_t> emptyPages;
  };

  // Looks the level's Nodes up with one batched lookup per namespace. The root must exist; a deeper Node that
  // does not exist is skipped, and one whose lookup fails otherwise is skipped with the failure as the
  // delete's answer, as a Node whose References cannot be read is.
  void find_level(std::vector<NodeId> ids) noexcept
  {
    try
    {
      auto space = mContext->addressSpace.lock();
      if (!space)
      {
        finish(VoidResult{address_space_gone("delete_node_async")});
        return;
      }
      std::vector<LookupItem> items;
      items.reserve(ids.size());
      for (const auto& id : ids)
      {
        items.push_back(LookupItem{id, std::nullopt});
      }
      space->find_nodes_async(
        RequestInfo{},
        items,
        [self = shared_from_this(), ids](BatchResult<NodeAccessorResult> found) mutable
        { self->on_level_found(std::move(ids), std::move(found)); },
        mContext->registrationRoute,
        mContext->handle);
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  void on_level_found(std::vector<NodeId> ids, BatchResult<NodeAccessorResult> found) noexcept
  {
    try
    {
      const bool rootLevel = std::exchange(mRootPending, false);
      if (!found.batchStatus.is_good() || found.items.size() != ids.size())
      {
        const StatusCode failure = found.batchStatus.is_good() ? StatusCode{Status::BadInternalError}
                                                               : found.batchStatus.status_code();
        if (rootLevel || is_address_space_gone(failure))
        {
          finish(VoidResult{failure});
          return;
        }
        rank(VoidResult{failure});
        delete_next_level();
        return;
      }
      auto level = std::make_shared<Level>();
      for (std::size_t i = 0; i < ids.size(); ++i)
      {
        auto& answer = found.items[i];
        // The deletion acts on the Node it looks up, so an Uncertain lookup is refused.
        if (!answer.is_good())
        {
          if (rootLevel || is_address_space_gone(answer.status_code()))
          {
            finish(
              VoidResult{::ua::detail::lookup_failure(ids[i], answer.status_code(), "delete_node_async")});
            return;
          }
          // Not fatal: the rest of the subtree is deleted; a child that exists but could not be looked up is
          // left, and the delete answers why.
          if (answer.status_code() != Status::BadNodeIdUnknown)
          {
            rank(VoidResult{::ua::detail::lookup_failure(ids[i], answer.status_code(), "delete_node_async")});
          }
          continue;
        }
        level->ids.push_back(std::move(ids[i]));
        level->nodes.push_back(answer.value());
      }
      if (level->ids.empty())
      {
        delete_next_level();
        return;
      }
      level->forward.resize(level->ids.size());
      level->failed.resize(level->ids.size());
      level->emptyPages.assign(level->ids.size(), 0);
      std::vector<std::size_t> all(level->ids.size());
      for (std::size_t k = 0; k < all.size(); ++k)
      {
        all[k] = k;
      }
      read_round(std::move(level), std::move(all), {});
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  // Reads the forward References of the level's Nodes @p which, one `read_references_async` per namespace;
  // @p tokens are their resume tokens, empty on the first round.
  void read_round(
    shared_ptr<Level> level, std::vector<std::size_t> which, std::vector<ResumeToken> tokens) noexcept
  {
    try
    {
      std::vector<ReferenceRead> reads;
      reads.reserve(which.size());
      for (std::size_t j = 0; j < which.size(); ++j)
      {
        ReferenceRead read{level->nodes[which[j]], BrowseDirection::Forward, {}, 0, ByteString{}};
        if (j < tokens.size())
        {
          read.resumeToken = std::move(tokens[j]);
        }
        reads.push_back(std::move(read));
      }
      NodeAccessorRoute::read_references(
        RequestInfo{},
        std::move(reads),
        [self = shared_from_this(), level, which](std::vector<ReferencePage> pages)
        { self->on_round_read(level, which, std::move(pages)); },
        mContext->handle);
    }
    catch (...)
    {
      for (auto& token : tokens)
      {
        token.release();
      }
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  void on_round_read(const shared_ptr<Level>& level, const std::vector<std::size_t>& which,
    std::vector<ReferencePage> pages) noexcept
  {
    try
    {
      if (pages.size() != which.size())
      {
        for (auto& page : pages)
        {
          page.resumeToken.release();
        }
        for (const std::size_t k : which)
        {
          level->failed[k] = StatusCode{Status::BadOutOfMemory};
        }
        classify_level(level);
        return;
      }
      std::vector<std::size_t> next;
      std::vector<ResumeToken> nextTokens;
      for (std::size_t j = 0; j < which.size(); ++j)
      {
        const std::size_t k = which[j];
        auto& page = pages[j];
        // The deletion acts on the References it reads, so an Uncertain answer is refused.
        if (!page.answer.is_good())
        {
          page.resumeToken.release();
          level->failed[k] = references_failure(page.answer.status_code(), "delete_node_async");
          continue;
        }
        const NodeReferences& read = page.answer.value();
        for (const auto& reference : read.references)
        {
          if (reference.is_forward())
          {
            level->forward[k].push_back(reference);
          }
        }
        level->emptyPages[k] = read.references.empty() ? level->emptyPages[k] + 1 : 0;
        if (page.resumeToken.empty())
        {
          continue;
        }
        if (level->emptyPages[k] >= maxEmptyReferencePages)
        {
          // The namespace kept answering a token with no References: the read fails, and its last token is
          // released.
          page.resumeToken.release();
          level->failed[k] = StatusCode{Status::BadInternalError,
            ErrorDetail::build("NamespacePagingDidNotEnd",
              "The namespace kept answering resume tokens for the References of a Node",
              "AddressSpace")
              .context(ContextKeys::nodeId, to_string(level->ids[k]))
              .context(ContextKeys::limit, std::to_string(maxEmptyReferencePages))};
          continue;
        }
        next.push_back(k);
        nextTokens.push_back(std::move(page.resumeToken));
      }
      if (!next.empty())
      {
        read_round(level, std::move(next), std::move(nextTokens));
        return;
      }
      classify_level(level);
    }
    catch (...)
    {
      for (auto& page : pages)
      {
        page.resumeToken.release();
      }
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  // Asks, once per ReferenceType the level's forward References use, whether it is hierarchical.
  void classify_level(const shared_ptr<Level>& level) noexcept
  {
    try
    {
      for (std::size_t k = 0; k < level->ids.size(); ++k)
      {
        const auto& lookupFailure = level->failed[k];
        if (lookupFailure && is_address_space_gone(lookupFailure.value()))
        {
          finish(VoidResult{lookupFailure.value()});
          return;
        }
      }
      auto types = std::make_shared<std::vector<NodeId>>();
      std::unordered_set<NodeId> seen;
      for (std::size_t k = 0; k < level->ids.size(); ++k)
      {
        if (level->failed[k])
        {
          continue;
        }
        for (const auto& reference : level->forward[k])
        {
          if (seen.insert(reference.type_id()).second)
          {
            types->push_back(reference.type_id());
          }
        }
      }
      auto verdicts = std::make_shared<std::unordered_map<NodeId, BoolResult>>();
      classify_next(level, types, 0, verdicts);
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  void classify_next(const shared_ptr<Level>& level, const shared_ptr<std::vector<NodeId>>& types,
    std::size_t index, const shared_ptr<std::unordered_map<NodeId, BoolResult>>& verdicts) noexcept
  {
    try
    {
      if (index >= types->size())
      {
        next_level(level, *verdicts);
        return;
      }
      auto handle = mContext->handle.lock();
      if (!handle)
      {
        finish(VoidResult{address_space_gone("delete_node_async")});
        return;
      }
      node_utils::is_ref_of_type_cached_async(mContext->limits,
        *handle,
        /*allowSubTypes=*/true,
        (*types)[index],
        NodeId{ReferenceTypeId::HierarchicalReferences},
        mRefTypeCache,
        [self = shared_from_this(), level, types, index, verdicts](BoolResult hierarchical)
        {
          try
          {
            verdicts->insert_or_assign((*types)[index], std::move(hierarchical));
          }
          catch (...)
          {
            self->finish(VoidResult{exception_to_status_code(std::current_exception())});
            return;
          }
          self->classify_next(level, types, index + 1, verdicts);
        });
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  // Keeps the level's Nodes whose children are known, and finds the next level from their hierarchical
  // targets. A Node whose References could not be read or classified is not deleted, and answers that
  // failure.
  void next_level(
    const shared_ptr<Level>& level, const std::unordered_map<NodeId, BoolResult>& verdicts) noexcept
  {
    try
    {
      std::vector<NodeId> deletable;
      std::vector<NodeId> next;
      for (std::size_t k = 0; k < level->ids.size(); ++k)
      {
        if (level->failed[k])
        {
          rank(VoidResult{*level->failed[k]});
          continue;
        }
        std::vector<NodeId> children;
        std::optional<StatusCode> failure;
        for (const auto& reference : level->forward[k])
        {
          const auto verdict = verdicts.find(reference.type_id());
          if (verdict == verdicts.end())
          {
            continue;
          }
          if (!verdict->second.is_good())
          {
            if (is_address_space_gone(verdict->second.status_code()))
            {
              finish(VoidResult{verdict->second.status_code()});
              return;
            }
            failure = verdict->second.status_code();
            break;
          }
          // Only a local target can be deleted through this address space; a remote one is another Server's.
          const auto& target = reference.target_id();
          if (verdict->second.value() && target.is_local() && target.is_index_based())
          {
            children.push_back(target.node_id());
          }
        }
        if (failure)
        {
          rank(VoidResult{*failure});
          continue;
        }
        deletable.push_back(level->ids[k]);
        for (auto& child : children)
        {
          if (mReached.insert(child).second)
          {
            next.push_back(std::move(child));
          }
        }
      }
      mLevels.push_back(std::move(deletable));
      if (next.empty())
      {
        delete_next_level();
        return;
      }
      find_level(std::move(next));
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  // Deletes the deepest level not yet deleted; once none is left, answers.
  void delete_next_level() noexcept
  {
    try
    {
      while (!mLevels.empty() && mLevels.back().empty())
      {
        mLevels.pop_back();
      }
      if (mLevels.empty())
      {
        finish(std::nullopt);
        return;
      }
      std::vector<NodeId> level = std::move(mLevels.back());
      mLevels.pop_back();
      delete_nodes(mContext,
        std::move(level),
        [self = shared_from_this()](std::vector<VoidResult> answers)
        {
          for (auto& answer : answers)
          {
            if (is_address_space_gone(answer.status_code()))
            {
              self->finish(std::move(answer));
              return;
            }
            self->rank(std::move(answer));
          }
          self->delete_next_level();
        });
    }
    catch (...)
    {
      finish(VoidResult{exception_to_status_code(std::current_exception())});
    }
  }

  // Keeps the worst answer: the first Bad, else the first Uncertain, else the Good code the Good answers
  // combine to by combined_status, so a namespace's Good subcode is answered rather than plain Good.
  void rank(VoidResult answer) noexcept
  {
    if ((answer.is_bad() && !mWorst.is_bad()) || (answer.is_uncertain() && mWorst.is_good()))
    {
      mWorst = std::move(answer);
      return;
    }
    if (answer.is_good() && mWorst.is_good())
    {
      mWorst = VoidResult{combined_status(mWorst.status_code(), answer.status_code())};
    }
  }

  // Answers once: @p forced when given, otherwise the worst answer.
  void finish(std::optional<VoidResult> forced) noexcept
  {
    auto callback = std::exchange(mCallback, nullptr);
    if (callback)
    {
      invoke_user_callback(callback, forced ? std::move(*forced) : std::move(mWorst));
    }
  }

  shared_ptr<const Context> mContext;
  std::function<void(VoidResult)> mCallback;
  std::shared_ptr<node_utils::RefTypeCache> mRefTypeCache{std::make_shared<node_utils::RefTypeCache>()};
  std::unordered_set<NodeId> mReached;
  // The levels found so far that remain to be deleted, the root's first.
  std::vector<std::vector<NodeId>> mLevels;
  bool mRootPending{true};
  VoidResult mWorst;
};

}  // namespace

shared_ptr<Namespace> NodeDeletion::resolve_namespace(const AddressSpaceImpl& addressSpace,
  uint16_t namespaceIndex, const shared_ptr<const NamespaceRegistrationRoute>& registrationRoute) noexcept
{
  return addressSpace.resolve_namespace(namespaceIndex, registrationRoute);
}

void NodeDeletion::run(const shared_ptr<AddressSpaceImpl>& addressSpace, WeakAddressSpace selfHandle,
  const NodeId& nodeId, bool subtree, ReferenceHalves halves,
  shared_ptr<const NamespaceRegistrationRoute> registrationRoute,
  std::function<void(VoidResult)> callback) noexcept
{
  // Kept by copy so that a throw before the delete has started can still be answered.
  std::function<void(VoidResult)> fallback = callback;
  try
  {
    auto context = std::make_shared<Context>();
    context->addressSpace = addressSpace;
    context->handle = std::move(selfHandle);
    context->registrationRoute = std::move(registrationRoute);
    context->halves = halves;
    context->logger = addressSpace->logger();
    const auto& operationLimits = addressSpace->mOperationLimits;
    context->nodeManagementLimit =
      operationLimits ? operationLimits.value().maxNodesPerNodeManagement : std::nullopt;
    context->limits = EncodingLimits{.execution = addressSpace->limits()};
    // The delete's event is raised before its caller is answered (NR-46).
    context->step = ModelChangeStep::create(addressSpace);
    callback = [step = context->step, inner = std::move(callback)](VoidResult result) mutable
    {
      step->close([inner = std::move(inner), result = std::move(result)]() mutable
        { invoke_user_callback(inner, std::move(result)); });
    };
    if (!subtree)
    {
      delete_nodes(context,
        {nodeId},
        [callback = std::move(callback)](std::vector<VoidResult> answers)
        {
          invoke_user_callback(callback,
            answers.empty() ? VoidResult{StatusCode{Status::BadInternalError}} : std::move(answers.front()));
        });
      return;
    }
    auto deletion = std::make_shared<SubtreeDeletion>(std::move(context), std::move(callback));
    deletion->start(nodeId);
  }
  catch (...)
  {
    invoke_user_callback(fallback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua::detail
