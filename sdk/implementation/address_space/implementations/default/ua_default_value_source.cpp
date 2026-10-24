// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_value_source.h"
#include "ua_callback_safety.h"
#include "ua_namespace_batch_support.h"
#include "ua_to_result.h"

#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>

namespace ua::default_ns
{

void DefaultValueSource::read_async(const ReadContext& context, std::span<const ReadItem> items,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  BatchResult<DataValueResult> answer;
  try
  {
    answer.items.reserve(items.size());
    for (const ReadItem& item : items)
    {
      answer.items.push_back(
        detail::batch::narrowed(DataValueResult{read(context.maxAge, context.setSourceTimestamp)},
          NumericRange{item.value.index_range()}));
    }
  }
  catch (...)
  {
    answer = BatchResult<DataValueResult>{};
    answer.batchStatus = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(complete), std::move(answer));
}

void DefaultValueSource::write_async(const WriteContext& context, std::span<const WriteItem> items,
  std::function<void(BatchResult<WriteResult>)> complete)
{
  BatchResult<WriteResult> answer;
  try
  {
    answer.items.reserve(items.size());
    for (const WriteItem& item : items)
    {
      auto stored = write(item.value, context.caller == nullptr);
      answer.items.push_back(stored.has_value()
                               ? WriteResult{Written{stored.value().initial}, stored.status_code()}
                               : WriteResult{stored.status_code(), stored.shared_detail()});
    }
  }
  catch (...)
  {
    answer = BatchResult<WriteResult>{};
    answer.batchStatus = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(complete), std::move(answer));
}

DataValue DefaultValueSource::read(Duration maxAge, bool setSourceTimestamp) const
{
  DataValue result;
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mValue.has_value())
    {
      result = mValue.value();
    }
  }
  // This source is the Value's data source, so the Server knows the Value it holds to be accurate at the
  // moment it is read (Part 4 7.11.4). Part 4 5.10.2.2 measures a Value's age from its ServerTimestamp and
  // obliges a new read when the Value held is older than maxAge; here that read yields the same Value, known
  // accurate now. A ServerTimestamp held - the one a client wrote (5.10.4.2) or the one set when the Value
  // was stored - is therefore returned only while it is within maxAge, and always at maxAge of Int32 max or
  // more, the cached-value read. The Value held is not changed.
  if (auto& serverTimestamp = result.server_timestamp(); serverTimestamp && !serverTimestamp->is_null())
  {
    constexpr Duration cachedValueMaxAge = static_cast<Duration>(std::numeric_limits<int32_t>::max());
    if (maxAge < cachedValueMaxAge)
    {
      const DateTime now = DateTime::now();
      const double ageMs =
        std::chrono::duration<double, std::milli>(now.value() - serverTimestamp->value()).count();
      if (maxAge <= 0.0 || ageMs > maxAge)
      {
        serverTimestamp = now;
      }
    }
  }
  if (!setSourceTimestamp)
  {
    result.source_timestamp().reset();
  }
  return result;
}

Result<DefaultValueSource::Stored> DefaultValueSource::write(const WriteValue& write, bool serversOwn)
{
  const std::lock_guard<std::mutex> lock(mMutex);
  const bool initial = !mValue || mValue->value().empty();
  if (!detail::batch::merges(write))
  {
    mValue = write.value();
    return Stored{std::nullopt, initial};
  }
  auto merged =
    detail::batch::merged_value_write(write, DataValueResult{mValue.value_or(DataValue{})}, serversOwn);
  if (!merged.is_good())
  {
    return Result<Stored>{merged.status_code(), merged.shared_detail()};
  }
  mValue = std::move(merged).value().value();
  return Stored{*mValue, initial};
}

Result<DataValue> DefaultValueSource::update(
  const std::function<Result<Variant>(const Variant& current)>& next)
{
  const std::lock_guard<std::mutex> lock(mMutex);
  auto value = next(mValue ? mValue->value() : Variant{});
  if (!value.is_good())
  {
    return Result<DataValue>{value.status_code(), value.shared_detail()};
  }
  DataValue updated;
  updated.value() = std::move(value).value();
  updated.source_timestamp() = DateTime::now();
  updated.server_timestamp() = updated.source_timestamp();
  mValue = updated;
  return updated;
}

}  // namespace ua::default_ns
