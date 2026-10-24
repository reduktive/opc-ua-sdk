// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_BATCH_SUPPORT_H
#define UA_NAMESPACE_BATCH_SUPPORT_H

// What the batched members of `Namespace` (its temporary defaults) and of the in-memory namespace share: a
// completion run at most once, the join of one call per item, the narrowing of a Value read to its
// IndexRange, and the forms a Value or Attribute write takes before it is applied, without copying items.

#include "ua_namespace.h"

#include "ua_callback_safety.h"
#include "ua_numeric_range.h"

#include <atomic>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace ua::detail
{

/// The resume token of a paged References read whose tokens hold nothing: the offset of the next Reference.
/// A token of another size decodes as 0. Defined with `Node`'s paged read.
uint32_t decode_offset(const ByteString& token);
ByteString encode_offset(uint32_t offset);

}  // namespace ua::detail

namespace ua::detail::batch
{

/// The status of the exception being handled.
inline StatusCode current_exception_status() noexcept
{
  return ua::exception_to_status_code(std::current_exception());
}

/// The answer a member gives for a failure: a batch fails in its batch status, a versioned-Node output is
/// empty, a call is answered (never declined), and any other result carries the status.
template<typename Answer>
Answer failed_answer(const StatusCode& status)
{
  if constexpr (requires(Answer answer) { answer.batchStatus; })
  {
    Answer answer;
    answer.batchStatus = VoidResult{status};
    return answer;
  }
  else if constexpr (std::is_same_v<Answer, std::vector<VersionedNode>>)
  {
    return {};
  }
  else if constexpr (std::is_same_v<Answer, std::optional<CallResult>>)
  {
    return std::optional<CallResult>{CallResult{status}};
  }
  else
  {
    return Answer{status};
  }
}

/// A member's completion, run at most once: a second call is dropped. Copies share it.
template<typename... Args>
struct OnceState
{
  std::atomic<bool> done{false};
  std::function<void(Args...)> complete;
};

template<typename... Args>
using Once = shared_ptr<OnceState<Args...>>;

/// Takes @p complete into a completion run at most once. When even that cannot be allocated, @p complete
/// is answered Bad_OutOfMemory at once and null is returned.
template<typename... Args>
Once<Args...> take_once(std::function<void(Args...)>& complete) noexcept
{
  try
  {
    auto once = std::make_shared<OnceState<Args...>>();
    once->complete = std::move(complete);
    return once;
  }
  catch (...)
  {
    detail::invoke_user_callback(
      std::move(complete), failed_answer<std::decay_t<Args>>(StatusCode{Status::BadOutOfMemory})...);
    return nullptr;
  }
}

template<typename... Args, typename... Values>
void run_once(const Once<Args...>& once, Values&&... values) noexcept
{
  if (!once->done.exchange(true, std::memory_order_acq_rel))
  {
    detail::invoke_user_callback(std::move(once->complete), std::forward<Values>(values)...);
  }
}

/// Answers a batched member from one call per item. @p start begins item @p index's call, which answers
/// it through the function it is given, inline or later and on any thread. @p finish runs once, with one
/// answer per item in item order, after the last item has answered. An item whose start throws is
/// answered with the exception's status, and a second answer for an item is dropped. @p start is called
/// only before this returns, so it may refer to the member's arguments; the answers may not.
template<typename Item>
void join_items(std::size_t count, const std::function<void(std::size_t, std::function<void(Item)>)>& start,
  std::function<void(BatchResult<Item>)> finish) noexcept
{
  struct Join
  {
    std::vector<std::optional<Item>> answers;
    std::unique_ptr<std::atomic<bool>[]> answered;
    // One more than the items: the loop holds one, so that answers given inline cannot finish the
    // batch before every item has started.
    std::atomic<std::size_t> remaining{0};
    std::function<void(BatchResult<Item>)> finish;
  };

  shared_ptr<Join> join;
  try
  {
    join = std::make_shared<Join>();
    join->answers.resize(count);
    join->answered = std::make_unique<std::atomic<bool>[]>(count);
    join->remaining.store(count + 1, std::memory_order_relaxed);
  }
  catch (...)
  {
    detail::invoke_user_callback(
      std::move(finish), failed_answer<BatchResult<Item>>(current_exception_status()));
    return;
  }
  join->finish = std::move(finish);

  const auto finishOne = [join]
  {
    if (join->remaining.fetch_sub(1, std::memory_order_acq_rel) != 1)
    {
      return;
    }
    BatchResult<Item> result;
    try
    {
      result.items.reserve(join->answers.size());
      for (auto& answer : join->answers)
      {
        result.items.push_back(std::move(*answer));
      }
    }
    catch (...)
    {
      result.items.clear();
      result.batchStatus = VoidResult{current_exception_status()};
    }
    detail::invoke_user_callback(std::move(join->finish), std::move(result));
  };

  for (std::size_t index = 0; index < count; ++index)
  {
    const auto answer = [join, index, finishOne](Item item)
    {
      if (join->answered[index].exchange(true, std::memory_order_acq_rel))
      {
        return;
      }
      join->answers[index] = std::move(item);
      finishOne();
    };
    try
    {
      start(index, answer);
    }
    catch (...)
    {
      answer(failed_answer<Item>(current_exception_status()));
    }
  }
  finishOne();
}

/// A Value read for an item, narrowed to the item's IndexRange. A range the Value cannot satisfy fails the
/// item with the status apply_to_value sets; a Value whose own status is Bad is passed on unchanged.
DataValueResult narrowed(DataValueResult read, const NumericRange& range);

/// What is written to a Node as it is given, rather than encoded as a client's write
/// (COMP-ADDRSP-ACCESSOR-ROUTE-05 item 2): the forms the accessor's setters write and a client's write cannot
/// express. A VariableType's Value is stored as the whole DataValue, a null one clearing it; a null clears an
/// optional Attribute (the setters taking std::nullopt); the Attributes the Write service's encoding does not
/// handle are written as the setters build them. Nothing for any other value, which is encoded.
std::optional<Variant> written_as_given(AttributeId attributeId, const DataValue& written);

/// Whether a Variable's Value write merges into the current Value before it is written: a write with an
/// IndexRange (OPC 10000-4 7.27), or an OptionSet carrying ValidBits (OPC 10000-3 8.40).
bool merges(const WriteValue& write);

/// The whole-Value write a merging write (@ref merges) becomes, from the @p current Value read for it: a
/// ranged write's partial value applied to the current Value (index_range_utils::apply_write), or an
/// OptionSet's written bits merged into the current OptionSet (merge_option_set_value) with its ValidBits
/// cleared. The result has no IndexRange. A failed read, a range that does not apply, and a current Value
/// that is not an OptionSet fail the item with their status; the server's own OptionSet write (@p serversOwn)
/// to a Variable holding none is written as given.
Result<WriteValue> merged_value_write(
  const WriteValue& written, const DataValueResult& current, bool serversOwn);

/// The wire form to store for a client's write of an Attribute other than a Variable's Value, as the Write
/// service decodes it: RolePermissions decoded strictly, in the form the accessor's setter stores; any other
/// value as node_utils::encode_writable_attribute encodes it, which refuses a value of another type, an
/// Attribute a client cannot write and one the NodeClass does not define.
Result<Variant> client_attribute_value(
  NodeClass nodeClass, const NodeId& nodeId, AttributeId attributeId, const Variant& value);

}  // namespace ua::detail::batch

namespace ua::node_utils
{

/// node_utils::encode_writable_attribute for a Node of @p nodeClass, without an accessor: what a namespace
/// writing its own Node uses.
Result<Variant> encode_writable_attribute_of_class(
  NodeClass nodeClass, const NodeId& nodeId, AttributeId id, const Variant& value) noexcept;

}  // namespace ua::node_utils

#endif  // UA_NAMESPACE_BATCH_SUPPORT_H
