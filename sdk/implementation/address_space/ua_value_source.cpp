// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_value_source.h"

#include "ua_numeric_range_parser.h"
#include "ua_whole_value_source.h"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ua
{

namespace
{

/// Calls @p each for every one of @p count items with a completion for that item, and @p complete once every
/// item has answered, with the answers in item order. A single item's completion passes its answer straight
/// on (NR-13a rule 4); several items share one join. A second answer for an item is dropped, as the
/// namespace's own joins drop it. An exception from @p each propagates to the caller.
template<typename T, typename Each>
void answer_each(std::size_t count, std::function<void(BatchResult<T>)> complete, Each&& each)
{
  if (count == 0)
  {
    complete(BatchResult<T>{});
    return;
  }
  if (count == 1)
  {
    each(std::size_t{0},
      std::function<void(T)>{[complete = std::move(complete), answered = false](T answer) mutable
        {
          if (std::exchange(answered, true))
          {
            return;
          }
          BatchResult<T> batch;
          batch.items.push_back(std::move(answer));
          complete(std::move(batch));
        }});
    return;
  }

  struct Join
  {
    std::mutex mutex;
    BatchResult<T> batch;
    std::vector<bool> answered;
    std::size_t remaining;
    std::function<void(BatchResult<T>)> complete;
  };

  auto join = std::make_shared<Join>();
  join->batch.items.resize(count, T{StatusCode{Status::BadInternalError}});
  join->answered.assign(count, false);
  join->remaining = count;
  join->complete = std::move(complete);
  for (std::size_t index = 0; index < count; ++index)
  {
    each(index,
      std::function<void(T)>{[join, index](T answer)
        {
          {
            const std::lock_guard lock{join->mutex};
            if (join->answered[index])
            {
              return;
            }
            join->answered[index] = true;
            join->batch.items[index] = std::move(answer);
            if (--join->remaining != 0)
            {
              return;
            }
          }
          join->complete(std::move(join->batch));
        }});
  }
}

/// The source @ref make_value_source builds.
class FunctionValueSource final : public ValueSource
{
public:
  FunctionValueSource(ReadValueHandler read, WriteValueHandler write)
    : mRead(std::move(read)), mWrite(std::move(write))
  {}

  void read_async(const ReadContext& context, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    answer_each<DataValueResult>(items.size(),
      std::move(complete),
      [this, &context, items](std::size_t index, std::function<void(DataValueResult)> answer)
      { mRead(context, items[index].node, items[index].value, std::move(answer)); });
  }

  void write_async(const WriteContext& context, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override
  {
    if (!mWrite)
    {
      ValueSource::write_async(context, items, std::move(complete));
      return;
    }
    answer_each<WriteResult>(items.size(),
      std::move(complete),
      [this, &context, items](std::size_t index, std::function<void(WriteResult)> answer)
      { mWrite(context, items[index].node, items[index].value, std::move(answer)); });
  }

private:
  ReadValueHandler mRead;
  WriteValueHandler mWrite;
};

}  // namespace

void ValueSource::write_async(const WriteContext&, std::span<const WriteItem> items,
  std::function<void(BatchResult<WriteResult>)> complete)
{
  BatchResult<WriteResult> refused;
  refused.items.assign(items.size(), WriteResult{StatusCode{Status::BadNotWritable}});
  complete(std::move(refused));
}

std::shared_ptr<ValueSource> make_value_source(
  ValueSource::ReadValueHandler read, ValueSource::WriteValueHandler write)
{
  if (!read)
  {
    throw std::invalid_argument("make_value_source: the read handler is empty");
  }
  return std::make_shared<FunctionValueSource>(std::move(read), std::move(write));
}

}  // namespace ua

namespace ua::detail
{

std::shared_ptr<ValueSource> whole_value_source(WholeValueRead read, ValueSource::WriteValueHandler write)
{
  return make_value_source(
    [read = std::move(read)](const ValueSource::ReadContext& context,
      const Node&,
      const ReadValueId& item,
      std::function<void(DataValueResult)>
        done)
    {
      read(context,
        [done = std::move(done), range = item.index_range()](DataValueResult value)
        {
          if (value.is_good())
          {
            index_range_utils::apply_to_value(value.value(), range);
          }
          done(std::move(value));
        });
    },
    std::move(write));
}

}  // namespace ua::detail
