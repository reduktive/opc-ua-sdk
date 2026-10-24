// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_value.h"
#include "ua_variant.h"

#include <new>
#include <utility>

namespace ua
{

Variant* DataValue::value_ptr() noexcept
{
  // The inline buffer must be large/aligned enough for a complete Variant. Variant is incomplete in
  // the header (it embeds a boxed DataValue scalar alternative), so the buffer is verified here where
  // Variant is complete. A failure means bumping the literals in ua_data_value.h.
  static_assert(sizeof(Variant) <= sVariantBufferSize, "DataValue::kVariantBufferSize too small for Variant");
  static_assert(
    alignof(Variant) <= sVariantBufferAlign, "DataValue::kVariantBufferAlign too small for Variant");
  return std::launder(reinterpret_cast<Variant*>(mValueBuffer));
}

const Variant* DataValue::value_ptr() const noexcept
{
  return std::launder(reinterpret_cast<const Variant*>(mValueBuffer));
}

DataValue::DataValue()
{
  new (mValueBuffer) Variant();
}

DataValue::~DataValue()
{
  value_ptr()->~Variant();
}

DataValue::DataValue(const DataValue& other)
  : mStatus(other.mStatus), mSourceTimestamp(other.mSourceTimestamp),
    mServerTimestamp(other.mServerTimestamp), mSourcePicoSeconds(other.mSourcePicoSeconds),
    mServerPicoSeconds(other.mServerPicoSeconds)
{
  new (mValueBuffer) Variant(*other.value_ptr());
}

DataValue::DataValue(DataValue&& other) noexcept
  : mStatus(std::move(other.mStatus)), mSourceTimestamp(other.mSourceTimestamp),
    mServerTimestamp(other.mServerTimestamp), mSourcePicoSeconds(other.mSourcePicoSeconds),
    mServerPicoSeconds(other.mServerPicoSeconds)
{
  // Inline storage: the Variant is move-constructed into THIS buffer; `other`'s Variant is left in a
  // moved-from (empty) state at its own address. A reference previously obtained from other.value()
  // does not follow the value here (unlike the old boxed unique_ptr).
  new (mValueBuffer) Variant(std::move(*other.value_ptr()));
}

DataValue& DataValue::operator=(const DataValue& other)
{
  if (this != &other)
  {
    *value_ptr() = *other.value_ptr();
    mStatus = other.mStatus;
    mSourceTimestamp = other.mSourceTimestamp;
    mServerTimestamp = other.mServerTimestamp;
    mSourcePicoSeconds = other.mSourcePicoSeconds;
    mServerPicoSeconds = other.mServerPicoSeconds;
  }
  return *this;
}

DataValue& DataValue::operator=(DataValue&& other) noexcept
{
  if (this != &other)
  {
    *value_ptr() = std::move(*other.value_ptr());
    mStatus = std::move(other.mStatus);
    mSourceTimestamp = other.mSourceTimestamp;
    mServerTimestamp = other.mServerTimestamp;
    mSourcePicoSeconds = other.mSourcePicoSeconds;
    mServerPicoSeconds = other.mServerPicoSeconds;
  }
  return *this;
}

bool DataValue::operator==(const DataValue& other) const
{
  return *value_ptr() == *other.value_ptr() && mStatus == other.mStatus &&
         mSourceTimestamp == other.mSourceTimestamp && mServerTimestamp == other.mServerTimestamp &&
         mSourcePicoSeconds == other.mSourcePicoSeconds && mServerPicoSeconds == other.mServerPicoSeconds;
}

DataValue::DataValue(Variant value)
{
  new (mValueBuffer) Variant(std::move(value));
}

DataValue::DataValue(Variant value, StatusCode status) : mStatus(status)
{
  new (mValueBuffer) Variant(std::move(value));
}

DataValue::DataValue(Variant value, DateTime sourceTimestamp) : mSourceTimestamp(sourceTimestamp)
{
  new (mValueBuffer) Variant(std::move(value));
}

DataValue::DataValue(Variant value, StatusCode status, DateTime sourceTimestamp)
  : mStatus(status), mSourceTimestamp(sourceTimestamp)
{
  new (mValueBuffer) Variant(std::move(value));
}

DataValue::DataValue(StatusCode status) : mStatus(status)
{
  new (mValueBuffer) Variant();
}

const Variant& DataValue::value() const
{
  return *value_ptr();
}

Variant& DataValue::value()
{
  return *value_ptr();
}

const optional<StatusCode>& DataValue::status() const
{
  return mStatus;
}

optional<StatusCode>& DataValue::status()
{
  return mStatus;
}

const optional<DateTime>& DataValue::source_timestamp() const
{
  return mSourceTimestamp;
}

optional<DateTime>& DataValue::source_timestamp()
{
  return mSourceTimestamp;
}

const optional<uint16_t>& DataValue::source_pico_seconds() const
{
  return mSourcePicoSeconds;
}

optional<uint16_t>& DataValue::source_pico_seconds()
{
  return mSourcePicoSeconds;
}

const optional<DateTime>& DataValue::server_timestamp() const
{
  return mServerTimestamp;
}

optional<DateTime>& DataValue::server_timestamp()
{
  return mServerTimestamp;
}

const optional<uint16_t>& DataValue::server_pico_seconds() const
{
  return mServerPicoSeconds;
}

optional<uint16_t>& DataValue::server_pico_seconds()
{
  return mServerPicoSeconds;
}

bool DataValue::is_null() const
{
  return (value_ptr()->empty() && !mStatus.has_value() && !mSourceTimestamp.has_value() &&
          !mSourcePicoSeconds.has_value() && !mServerTimestamp.has_value() &&
          !mServerPicoSeconds.has_value());
}

void DataValue::clear()
{
  value_ptr()->clear();
  mStatus.reset();
  mSourceTimestamp.reset();
  mSourcePicoSeconds.reset();
  mServerTimestamp.reset();
  mServerPicoSeconds.reset();
}

BuiltInTypeId DataValue::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::DataValue};
}

}  // namespace ua
