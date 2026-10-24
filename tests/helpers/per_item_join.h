// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_PER_ITEM_JOIN_H
#define UA_TEST_PER_ITEM_JOIN_H

#include "ua_result.h"

#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace ua::test
{

/// Joins one answer per item of a batched member into the batch's answer, in item order, for a test namespace
/// that answers its items one at a time (some from Nodes of its own, the rest through the in-memory member).
///
/// The batch completes once every item has answered and @ref started has been called, so that answers given
/// inline while the items are still being started cannot complete it early. A second answer for an item is
/// dropped. Shared by the item answers; hold it in a `shared_ptr`.
template<typename Answer>
class PerItemJoin
{
public:
  PerItemJoin(std::size_t count, std::function<void(BatchResult<Answer>)> complete)
    : mAnswers(count), mRemaining(count + 1), mComplete(std::move(complete))
  {}

  /// Records item @p index's answer.
  void answer(std::size_t index, Answer answer)
  {
    {
      const std::lock_guard lock{mMutex};
      if (mAnswers[index].has_value())
      {
        return;
      }
      mAnswers[index] = std::move(answer);
    }
    finish_one();
  }

  /// Called once, after every item has been started.
  void started()
  {
    finish_one();
  }

private:
  void finish_one()
  {
    BatchResult<Answer> result;
    std::function<void(BatchResult<Answer>)> complete;
    {
      const std::lock_guard lock{mMutex};
      if (--mRemaining != 0)
      {
        return;
      }
      result.items.reserve(mAnswers.size());
      for (auto& answer : mAnswers)
      {
        result.items.push_back(std::move(*answer));
      }
      complete = std::move(mComplete);
    }
    complete(std::move(result));
  }

  std::mutex mMutex;
  std::vector<std::optional<Answer>> mAnswers;
  std::size_t mRemaining;
  std::function<void(BatchResult<Answer>)> mComplete;
};

/// The answer of a one-item call of a batched member: its item, or the batch's failure.
template<typename Answer>
Answer only_item(BatchResult<Answer> batch)
{
  if (batch.batchStatus.is_bad())
  {
    return Answer{batch.batchStatus.status_code()};
  }
  if (batch.items.size() != 1)
  {
    return Answer{StatusCode{Status::BadInternalError}};
  }
  return std::move(batch.items[0]);
}

}  // namespace ua::test

#endif  // UA_TEST_PER_ITEM_JOIN_H
