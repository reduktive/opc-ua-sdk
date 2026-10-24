// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_range_parser.h"
#include "ua_error_detail.h"
#include "ua_result.h"

#include <charconv>
#include <string_view>

namespace ua
{

namespace
{

ParsedNumericRangeResult make_invalid(std::string summary, std::string_view offendingInput)
{
  return {StatusCode{Status::BadIndexRangeInvalid},
    ErrorDetail::build("IndexRangeInvalid", "Invalid numeric index range", "NumericRangeParser")
      .context(ua::ContextKeys::errorMessage, std::move(summary))
      .context(ua::ContextKeys::value, std::string{offendingInput})};
}

/// Parse a single dimension segment (e.g. "3" or "2:5").
/// On error, returns empty optional and sets errorMsg.
std::optional<DimensionRange> parse_dimension(std::string_view segment, std::string& errorMsg)
{
  if (segment.empty())
  {
    errorMsg = "Empty dimension segment";
    return std::nullopt;
  }

  auto colonPos = segment.find(':');

  if (colonPos == 0)
  {
    errorMsg = "Leading colon in dimension segment";
    return std::nullopt;
  }

  if (colonPos == segment.size() - 1)
  {
    errorMsg = "Trailing colon in dimension segment";
    return std::nullopt;
  }

  if (colonPos == std::string_view::npos)
  {
    uint32_t index = 0;
    auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), index);
    if (ec != std::errc{} || ptr != segment.data() + segment.size())
    {
      errorMsg = "Non-numeric character in index";
      return std::nullopt;
    }
    return DimensionRange{index, index};
  }

  // Check for additional colons (e.g. "1:2:3")
  if (segment.find(':', colonPos + 1) != std::string_view::npos)
  {
    errorMsg = "Too many colons in dimension segment";
    return std::nullopt;
  }

  auto lowStr = segment.substr(0, colonPos);
  auto highStr = segment.substr(colonPos + 1);

  uint32_t low = 0;
  {
    auto [ptr, ec] = std::from_chars(lowStr.data(), lowStr.data() + lowStr.size(), low);
    if (ec != std::errc{} || ptr != lowStr.data() + lowStr.size())
    {
      errorMsg = "Non-numeric character in low bound";
      return std::nullopt;
    }
  }

  uint32_t high = 0;
  {
    auto [ptr, ec] = std::from_chars(highStr.data(), highStr.data() + highStr.size(), high);
    if (ec != std::errc{} || ptr != highStr.data() + highStr.size())
    {
      errorMsg = "Non-numeric character in high bound";
      return std::nullopt;
    }
  }

  if (low >= high)
  {
    errorMsg = "Low bound must be less than high bound";
    return std::nullopt;
  }

  return DimensionRange{low, high};
}

}  // namespace

ParsedNumericRangeResult parse_numeric_range(const NumericRange& range)
{
  if (range.empty())
  {
    return ParsedNumericRange{};
  }

  std::string_view input = range;

  // Check for leading or trailing comma
  if (input.front() == ',' || input.back() == ',')
  {
    return make_invalid("Leading or trailing comma", input);
  }

  ParsedNumericRange result;

  while (!input.empty())
  {
    auto commaPos = input.find(',');
    std::string_view segment;

    if (commaPos == std::string_view::npos)
    {
      segment = input;
      input = {};
    }
    else
    {
      segment = input.substr(0, commaPos);
      input = input.substr(commaPos + 1);
    }

    std::string errorMsg;
    auto dimResult = parse_dimension(segment, errorMsg);
    if (!dimResult)
    {
      return make_invalid(std::move(errorMsg), segment);
    }

    result.dimensions.push_back(*dimResult);
  }

  return result;
}

}  // namespace ua
