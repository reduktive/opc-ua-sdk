// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_array_base.h"
#include "ua_resource_budgets.h"
#include "ua_codec.h"
#include "ua_error_detail.h"

#include <limits>

namespace ua
{

int32_t ArrayBase::value_rank() const
{
  if (!mDimensions.has_value())
  {
    return 1;
  }
  else
  {
    return numeric_cast<int32_t>(mDimensions->size());
  }
}

size_t ArrayBase::calculate_no_of_elements(const ua::Dimensions& dimensions)
{
  if (dimensions.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("ArrayDimensionMismatch", "Dimensions vector is empty", "ArrayBase"));
  }

  const size_t count = dimensions.size();
  size_t noOfElements = 1;

  for (size_t i = 0; i < count; ++i)
  {
    if (dimensions[i] <= 0)
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build(
          "ArrayDimensionMismatch", "Array dimension value must be greater than zero", "ArrayBase")
          .context(ua::ContextKeys::index, std::to_string(i))
          .context(ua::ContextKeys::actual, std::to_string(dimensions[i])));
    }

    const auto dimension = numeric_cast<size_t>(dimensions[i]);
    if (noOfElements > std::numeric_limits<size_t>::max() / dimension)
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build("ArrayDimensionMismatch", "Array dimension product overflows", "ArrayBase")
          .context(ua::ContextKeys::index, std::to_string(i)));
    }
    noOfElements *= dimension;
  }

  return noOfElements;
}

const optional<ua::Dimensions>& ArrayBase::dimensions() const
{
  return mDimensions;
}

optional<ua::Dimensions>& ArrayBase::dimensions()
{
  return mDimensions;
}

ArrayBase::ArrayBase(const Dimensions& dimensions) : mDimensions(dimensions)
{}

ArrayBase::ArrayBase(Dimensions&& dimensions) : mDimensions(std::move(dimensions))
{}

void ArrayBase::add_and_validate_dimensions(Dimensions&& dims)
{
  if (!dims.empty())
  {
    const size_t expectedNoOfElements = calculate_no_of_elements(dims);
    if (expectedNoOfElements != size())
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build("ArrayResizeFailed", "Dimensions product does not match array size", "ArrayBase")
          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedNoOfElements))
          .context(ua::ContextKeys::sizeActual, std::to_string(size())));
    }
    mDimensions = std::move(dims);
  }
  else
  {
    mDimensions.reset();
  }
}

}  // namespace ua
