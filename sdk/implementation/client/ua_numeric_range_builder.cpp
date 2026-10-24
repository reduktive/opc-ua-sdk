// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_range_builder.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_status.h"

#include <charconv>
#include <new>
#include <string>
#include <system_error>

namespace ua::client
{
namespace
{

ua::Result<ua::NumericRange> dimension_count_failure(
  std::size_t expectedDimensions, std::size_t actualDimensions)
{
  return ua::Result<ua::NumericRange>{ua::Status::BadIndexRangeInvalid,
    ua::ErrorDetail::build("NumericRangeDimensionCountMismatch",
      "the NumericRange must specify every dimension of the Variable",
      "client.tier2.numeric_range_builder")
      .context(ua::ContextKeys::sizeExpected, expectedDimensions)
      .context(ua::ContextKeys::sizeActual, actualDimensions)};
}

void append_index(std::string& output, std::uint32_t index)
{
  char buffer[16]{};
  const auto conversion = std::to_chars(buffer, buffer + sizeof(buffer), index);
  if (conversion.ec == std::errc{})
  {
    output.append(buffer, conversion.ptr);
  }
}

}  // namespace

ua::Result<ua::NumericRange> NumericRangeBuilder::from_string(
  ua::NumericRange range, std::optional<std::size_t> expectedDimensions) noexcept
{
  try
  {
    auto parsed = ua::parse_numeric_range(range);
    if (!parsed.is_good())
    {
      return ua::Result<ua::NumericRange>{parsed.status_code(),
        ua::ErrorDetail::build("NumericRangeSyntaxInvalid",
          "the NumericRange does not conform to the Part 4 syntax",
          "client.tier2.numeric_range_builder")
          .cause(parsed.status_code())
          .cause(parsed.shared_detail())};
    }
    if (expectedDimensions && !parsed.value().empty() &&
        parsed.value().dimension_count() != *expectedDimensions)
    {
      return dimension_count_failure(*expectedDimensions, parsed.value().dimension_count());
    }
    return ua::Result<ua::NumericRange>{std::move(range)};
  }
  catch (const std::bad_alloc&)
  {
    return ua::Result<ua::NumericRange>{ua::Status::BadOutOfMemory};
  }
  catch (...)
  {
    return ua::Result<ua::NumericRange>{ua::Status::BadUnexpectedError};
  }
}

ua::Result<ua::NumericRange> NumericRangeBuilder::from_dimensions(
  std::vector<ua::DimensionRange> dimensions, std::optional<std::size_t> expectedDimensions) noexcept
{
  try
  {
    if (expectedDimensions && !dimensions.empty() && dimensions.size() != *expectedDimensions)
    {
      return dimension_count_failure(*expectedDimensions, dimensions.size());
    }

    std::string wire;
    wire.reserve(dimensions.size() * 12);
    for (std::size_t index = 0; index < dimensions.size(); ++index)
    {
      const auto& dimension = dimensions[index];
      if (dimension.low > dimension.high)
      {
        return ua::Result<ua::NumericRange>{ua::Status::BadIndexRangeInvalid,
          ua::ErrorDetail::build("NumericRangeBoundsInvalid",
            "a NumericRange lower bound must not exceed its upper bound",
            "client.tier2.numeric_range_builder")
            .context(ua::ContextKeys::index, index)};
      }
      if (index != 0)
      {
        wire.push_back(',');
      }
      append_index(wire, dimension.low);
      if (dimension.low != dimension.high)
      {
        wire.push_back(':');
        append_index(wire, dimension.high);
      }
    }
    return ua::Result<ua::NumericRange>{ua::NumericRange{wire}};
  }
  catch (const std::bad_alloc&)
  {
    return ua::Result<ua::NumericRange>{ua::Status::BadOutOfMemory};
  }
  catch (...)
  {
    return ua::Result<ua::NumericRange>{ua::Status::BadUnexpectedError};
  }
}

}  // namespace ua::client
