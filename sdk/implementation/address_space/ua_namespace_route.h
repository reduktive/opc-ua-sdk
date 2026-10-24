// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_address_space.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_to_result.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::detail
{

/// What an item of a namespace released before the route's call to it is answered: `Bad_Shutdown`
/// (`NamespaceReleased`).
inline StatusCode namespace_released()
{
  return StatusCode{Status::BadShutdown,
    ErrorDetail::build("NamespaceReleased",
      "The namespace was released before the call that would have answered this item",
      "NamespaceRoute")};
}

/// The summary of the ErrorDetail with which the SDK refuses an Uncertain answer it would act on.
inline constexpr std::string_view uncertainAnswerSummary{
  "The SDK does not act on an answer the namespace is uncertain of"};

/// What a step answers when an answer the SDK would act on, @p answer, is not Good (a Node lookup, a type or
/// References walk that decides a rule, a Property read, instantiation, deletion): a Bad answer is the step's
/// own; an Uncertain one is refused whether or not it holds a value, with `Bad_InternalError` and the
/// ErrorDetail @p code (@ref uncertainAnswerSummary), whose cause is @p answer with its own detail
/// (COMP-SVR-STATUS-ROUTING-02). A detail that cannot be built answers the allocation failure instead.
///
/// @param answer The answer, which is not Good.
/// @param code   The ErrorDetail code naming what was answered: `LookupAnswerUncertain`,
///               `ReadAnswerUncertain` or `ReferencesAnswerUncertain`, or `AnswerUncertain` for an
///               application answer that is none of those.
/// @param source The detail's source.
/// @return The status the step answers.
inline StatusCode answer_failure(
  const StatusCode& answer, std::string_view code, std::string_view source) noexcept
{
  if (answer.is_bad())
  {
    return answer;
  }
  try
  {
    return StatusCode{Status::BadInternalError,
      ErrorDetail::build(std::string{code}, std::string{uncertainAnswerSummary}, std::string{source})
        .cause(answer)};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

/// What an operation answers when the lookup of its Node @p nodeId was answered @p answer, which is not Good:
/// a Bad answer is the operation's own; an Uncertain one, with or without the Node, is refused with
/// `Bad_InternalError` (`LookupAnswerUncertain`, @ref uncertainAnswerSummary) with @p answer as its cause
/// (COMP-SVR-NAMESPACE-CALLS-24), @p source the detail's source. A detail that cannot be built answers the
/// allocation failure instead.
inline StatusCode lookup_failure(
  const NodeId& nodeId, const StatusCode& answer, std::string_view source) noexcept
{
  if (answer.is_bad())
  {
    return answer;
  }
  try
  {
    return StatusCode{Status::BadInternalError,
      ErrorDetail::build("LookupAnswerUncertain", std::string{uncertainAnswerSummary}, std::string{source})
        .context(ContextKeys::nodeId, nodeId)
        .cause(answer)};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

/// @ref answer_failure for a References read the SDK would act on (`ReferencesAnswerUncertain`).
inline StatusCode references_failure(const StatusCode& answer, std::string_view source) noexcept
{
  return answer_failure(answer, "ReferencesAnswerUncertain", source);
}

/// @ref answer_failure for a Value read the SDK would act on (`ReadAnswerUncertain`).
inline StatusCode read_failure(const StatusCode& answer, std::string_view source) noexcept
{
  return answer_failure(answer, "ReadAnswerUncertain", source);
}

/// True when @p status says a step that needed the address space found it gone: what @ref address_space_gone
/// answers, or what an accessor without its address space answers (`AccessorWithoutAddressSpace`). A composed
/// operation propagates it rather than reading it as an absent Node or Property (CALLS-21 rule 2).
inline bool is_address_space_gone(const StatusCode& status) noexcept
{
  const auto& detail = status.shared_detail();
  return status == StatusCode{Status::BadShutdown} && detail != nullptr &&
         (detail->code == "AddressSpaceGone" || detail->code == "AccessorWithoutAddressSpace");
}

/// The address space's route into the namespaces for one batched member (NR-23 rules 1 and 4, NR-31 rule 5).
///
/// The caller splits the request by namespace into parts; the route starts every part before it awaits any,
/// sends each part as consecutive calls of at most `limit` items (the next call starts when the previous one
/// completes), and puts every answer at its request position. Each call passes the guards of NR-23 rule 4: a
/// throw fails that call's items with `Bad_InternalError` (`NamespaceCallThrew`); a second completion is
/// ignored; an answer with another number of items than the call had fails every item of the call with
/// `Bad_InternalError` (`NamespaceItemCountMismatch`), since no answer can be matched to its item; a Bad
/// batch status fails every item of the call with that status. The route holds no lock while a namespace
/// runs, and a call answered inline is followed by the next in a loop rather than by recursion.
///
/// @tparam Answer The per-item answer of the member, constructible from a failed `StatusCode`.
template<typename Answer>
class NamespaceRoute
{
public:
  /// One namespace's part of the request: the namespace and the request positions of its items, in request
  /// order.
  ///
  /// The route holds the namespace strongly only until the part's first call has returned and while it calls
  /// one of the namespace's members; the completion it gives the namespace holds it weakly, so a namespace
  /// holding a completion it has not answered does not keep itself alive. A part whose namespace has been
  /// released before its next call answers the items of that call and of every later one with
  /// @ref namespace_released, and the route still completes once.
  struct Part
  {
    shared_ptr<Namespace> nameSpace;
    std::vector<std::size_t> positions;
  };

  /// Calls the member for one call's items. `positions` are request positions, valid until the call returns;
  /// `answer` takes the namespace's batch for exactly those items, in that order.
  using Invoke = std::function<void(Namespace& nameSpace, std::span<const std::size_t> positions,
    std::function<void(BatchResult<Answer>)> answer)>;

  /// Receives one answer per request position, once. The route calls it from `noexcept` code, so a throw from
  /// it ends the process, as a throw from a lookup's completion did before the route.
  using Done = std::function<void(std::vector<Answer>)>;

  /// Runs the parts and completes `done` once.
  ///
  /// @param answers  One slot per request position; a filled slot is already answered (by the caller, before
  ///                 routing) and no part may name it.
  /// @param parts    The namespaces' parts; together they name every empty slot once.
  /// @param limit    The matching operation limit; `nullopt` sends each part as one call. It is never 0
  ///                 (`AddressSpace::set_operation_limits` refuses one); a 0 is taken as unset
  ///                 rather than looping.
  /// @param invoke   Calls the member for one call's items.
  /// @param done     Receives the answers in request order.
  /// @param requiredAddressSpace Optional weak owner required before each actual namespace invocation.
  ///                 Losing it refuses only unissued positions with `Bad_Shutdown/AddressSpaceGone`,
  ///                 before testing namespace lifetime; callers omitting it retain their diagnostics.
  static void run(std::vector<std::optional<Answer>> answers, std::vector<Part> parts,
    std::optional<uint32_t> limit, Invoke invoke, Done done,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept
  {
    auto state = std::make_shared<State>();
    state->answers = std::move(answers);
    state->limit = limit;
    state->invoke = std::move(invoke);
    state->done = std::move(done);
    state->requiredAddressSpace = std::move(requiredAddressSpace);
    // One count per part plus one released after every part has started, so that a part answered inline
    // cannot complete the route while a later part is still unstarted.
    state->remaining.store(parts.size() + 1U, std::memory_order_relaxed);
    for (auto& part : parts)
    {
      // The caller's reference, held across the part's first call and released when it returns.
      const shared_ptr<Namespace> namespaceOwner = std::move(part.nameSpace);
      auto partRun = std::make_shared<PartRun>();
      partRun->state = state;
      partRun->nameSpace = namespaceOwner;
      partRun->positions = std::move(part.positions);
      run_part(std::move(partRun));
    }
    finish_one(*state);
  }

private:
  struct State
  {
    std::vector<std::optional<Answer>> answers;
    std::optional<uint32_t> limit;
    Invoke invoke;
    Done done;
    std::optional<WeakAddressSpace> requiredAddressSpace;
    std::atomic<std::size_t> remaining{0};
  };

  // Held by every completion of the part, so it holds the namespace weakly.
  struct PartRun
  {
    shared_ptr<State> state;
    weak_ptr<Namespace> nameSpace;
    std::vector<std::size_t> positions;
    std::size_t next{0};
  };

  // Where one call stands, for the loop that started it and for its completion.
  enum class CallPhase : int
  {
    Invoking,
    AnsweredWhileInvoking,
    Returned,
  };

  struct Call
  {
    std::atomic<bool> answered{false};
    std::atomic<CallPhase> phase{CallPhase::Invoking};
  };

  static void finish_one(State& state) noexcept
  {
    if (state.remaining.fetch_sub(1, std::memory_order_acq_rel) != 1)
    {
      return;
    }
    std::vector<Answer> result;
    result.reserve(state.answers.size());
    for (auto& slot : state.answers)
    {
      if (slot)
      {
        result.push_back(std::move(*slot));
      }
      else
      {
        result.push_back(Answer{StatusCode{Status::BadInternalError,
          ErrorDetail::build(
            "RouteItemNotAnswered", "No namespace call answered this item", "NamespaceRoute")}});
      }
    }
    state.done(std::move(result));
  }

  static void fail_call(State& state, std::span<const std::size_t> positions, const StatusCode& status)
  {
    for (const std::size_t position : positions)
    {
      state.answers[position] = Answer{status};
    }
  }

  static void accept(State& state, std::span<const std::size_t> positions, BatchResult<Answer> batch)
  {
    if (batch.batchStatus.is_bad())
    {
      fail_call(state, positions, batch.batchStatus.status_code());
      return;
    }
    if (batch.items.size() != positions.size())
    {
      fail_call(state,
        positions,
        StatusCode{Status::BadInternalError,
          ErrorDetail::build("NamespaceItemCountMismatch",
            "The namespace answered another number of items than the call had",
            "NamespaceRoute")
            .context(ContextKeys::sizeExpected, std::to_string(positions.size()))
            .context(ContextKeys::sizeActual, std::to_string(batch.items.size()))});
      return;
    }
    for (std::size_t k = 0; k < positions.size(); ++k)
    {
      state.answers[positions[k]] = std::move(batch.items[k]);
    }
  }

  // Sends the part's calls one after another. A call answered while the namespace member was still running is
  // followed here, in the loop; one answered later continues the part from its completion. The namespace is
  // held only while its member runs.
  static void run_part(shared_ptr<PartRun> run) noexcept
  {
    State& state = *run->state;
    const std::size_t total = run->positions.size();
    while (run->next < total)
    {
      const std::size_t begin = run->next;
      // The composed caller's required owner is tested before the namespace and held only for this
      // synchronous invocation. Already accepted answers are never replaced by this refusal.
      std::optional<AddressSpace> addressSpace;
      if (state.requiredAddressSpace)
      {
        addressSpace = state.requiredAddressSpace->lock();
        if (!addressSpace)
        {
          run->next = total;
          fail_call(state,
            std::span<const std::size_t>{run->positions.data() + begin, total - begin},
            address_space_gone("NamespaceRoute"));
          break;
        }
      }
      shared_ptr<Namespace> nameSpace = run->nameSpace.lock();
      if (!nameSpace)
      {
        run->next = total;
        fail_call(state,
          std::span<const std::size_t>{run->positions.data() + begin, total - begin},
          namespace_released());
        break;
      }
      const std::size_t remaining = total - begin;
      const std::size_t size = state.limit && *state.limit > 0U
                                 ? std::min<std::size_t>(remaining, static_cast<std::size_t>(*state.limit))
                                 : remaining;
      run->next = begin + size;
      const std::span<const std::size_t> positions{run->positions.data() + begin, size};
      auto call = std::make_shared<Call>();
      auto answer = [run, positions, call](BatchResult<Answer> batch)
      {
        if (call->answered.exchange(true, std::memory_order_acq_rel))
        {
          return;  // a second completion of the same call
        }
        accept(*run->state, positions, std::move(batch));
        if (call->phase.exchange(CallPhase::AnsweredWhileInvoking, std::memory_order_acq_rel) ==
            CallPhase::Returned)
        {
          continue_part(run);
        }
      };
      try
      {
        state.invoke(*nameSpace, positions, answer);
      }
      catch (...)
      {
        BatchResult<Answer> threw;
        threw.batchStatus = VoidResult{StatusCode{Status::BadInternalError,
          ErrorDetail::build("NamespaceCallThrew", "The namespace's member threw", "NamespaceRoute")
            .cause(exception_to_status_code(std::current_exception()))}};
        answer(std::move(threw));
      }
      nameSpace.reset();
      addressSpace.reset();
      if (call->phase.exchange(CallPhase::Returned, std::memory_order_acq_rel) == CallPhase::Invoking)
      {
        return;  // the completion continues the part
      }
    }
    finish_one(state);
  }

  static void continue_part(shared_ptr<PartRun> run) noexcept
  {
    run_part(std::move(run));
  }
};

/// The items of a batched call split by the namespace each belongs to, as @ref NamespaceRoute::run takes
/// them.
template<typename Answer>
struct NamespaceSplit
{
  /// One slot per item: engaged for an item already answered (its namespace is not registered).
  std::vector<std::optional<Answer>> answers;
  /// One part per namespace, its positions in item order.
  std::vector<typename NamespaceRoute<Answer>::Part> parts;
};

/// Splits items by namespace: item `k` belongs to namespace `indexAt[k]`, which @p resolve gives (a
/// `shared_ptr<Namespace>`, null for an index that is not registered). An item of an unregistered namespace
/// is answered `Bad_NodeIdUnknown` (`NamespaceNotFound`). Each index is resolved once; the parts are in the
/// order their namespaces first appear.
template<typename Answer, typename Resolve>
NamespaceSplit<Answer> split_by_namespace(std::span<const uint16_t> indexAt, Resolve&& resolve)
{
  NamespaceSplit<Answer> split;
  split.answers.resize(indexAt.size());
  std::vector<std::pair<uint16_t, std::optional<std::size_t>>> seen;
  for (std::size_t position = 0; position < indexAt.size(); ++position)
  {
    const uint16_t index = indexAt[position];
    auto known =
      std::find_if(seen.begin(), seen.end(), [index](const auto& entry) { return entry.first == index; });
    if (known == seen.end())
    {
      std::optional<std::size_t> part;
      if (shared_ptr<Namespace> nameSpace = resolve(index))
      {
        part = split.parts.size();
        split.parts.push_back(typename NamespaceRoute<Answer>::Part{std::move(nameSpace), {}});
      }
      seen.emplace_back(index, part);
      known = std::prev(seen.end());
    }
    const auto& partIndex = known->second;
    if (!partIndex)
    {
      split.answers[position] = Answer{StatusCode{Status::BadNodeIdUnknown,
        ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "NamespaceRoute")
          .context(ContextKeys::namespaceIndex, std::to_string(index))}};
      continue;
    }
    split.parts[partIndex.value()].positions.push_back(position);
  }
  return split;
}

}  // namespace ua::detail
