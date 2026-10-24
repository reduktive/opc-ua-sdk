// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_value_rank.h"

namespace ua
{

ValueRank::ValueRank() : mValue(any)
{}

ValueRank::ValueRank(int32_t value) : mValue(value)
{
  check_true(value >= scalarOrOneDimension);
}

bool ValueRank::is_any() const
{
  return mValue == any;
}

bool ValueRank::is_scalar() const
{
  return mValue == scalar;
}

bool ValueRank::is_scalar_or_one_dimension() const
{
  return mValue == scalarOrOneDimension;
}

bool ValueRank::is_array() const
{
  return mValue > 0;
}

bool ValueRank::is_one_dimensional() const
{
  return mValue == 1;
}

bool ValueRank::is_one_or_more_dimensional() const
{
  return mValue == 0;
}

optional<int32_t> ValueRank::no_of_dimensions() const
{
  optional<int32_t> result;
  if (is_array())
  {
    result = mValue;
  }
  return result;
}

int32_t ValueRank::as_int32() const
{
  return mValue;
}

void ValueRank::set_to_any()
{
  mValue = any;
}

void ValueRank::set_to_scalar()
{
  mValue = scalar;
}

void ValueRank::set_to_one_dimensional()
{
  mValue = 1;
}

void ValueRank::set_to_one_or_more_dimensional()
{
  mValue = oneOrMore;
}

void ValueRank::set_no_of_dimensions(size_t noOfDims)
{
  mValue = numeric_cast<int32_t>(noOfDims);
}

}  // namespace ua