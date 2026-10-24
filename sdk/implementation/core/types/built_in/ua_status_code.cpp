// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_status_code.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "fmt/format.h"

namespace ua
{

StatusCode::StatusCode(Status value, std::shared_ptr<const ErrorDetail> detail) noexcept
  : mValue(utils::to_underlying(value)), mDetail(std::move(detail))
{}

StatusCode::StatusCode(StatusCodeValue value, std::shared_ptr<const ErrorDetail> detail) noexcept
  : mValue(value), mDetail(std::move(detail))
{}

StatusCode::~StatusCode() = default;

StatusCode::StatusCode(const StatusCode& other) noexcept = default;

StatusCode::StatusCode(StatusCode&& other) noexcept = default;

StatusCode& StatusCode::operator=(const StatusCode& other) noexcept = default;

StatusCode& StatusCode::operator=(StatusCode&& other) noexcept = default;

const ErrorDetail* StatusCode::detail() const noexcept
{
  return mDetail.get();
}

bool StatusCode::test_bit(uint32_t bit) const
{
  if (bit > 31U)
  {
    throw UaException(Status::BadOutOfRange,
      ErrorDetail::build("InvalidStatusCode", "test_bit(): bit index out of range (max 31)", "StatusCode")
        .context(ua::ContextKeys::bitIndex, std::to_string(bit)));
  }
  return (mValue >> bit) & 1U;
}

void StatusCode::set_bit(uint32_t bit, bool value)
{
  if (bit > 31U)
  {
    throw UaException(Status::BadOutOfRange,
      ErrorDetail::build("InvalidStatusCode", "set_bit(): bit index out of range (max 31)", "StatusCode")
        .context(ua::ContextKeys::bitIndex, std::to_string(bit)));
  }
  if (value)
  {
    mValue |= (1U << bit);
  }
  else
  {
    mValue &= ~(1U << bit);
  }
}

BuiltInTypeId StatusCode::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::StatusCode};
}

StatusCode& StatusCode::operator=(Status other) noexcept
{
  mValue = utils::to_underlying(other);
  mDetail.reset();
  return *this;
}

}  // namespace ua
