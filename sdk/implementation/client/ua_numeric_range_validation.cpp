// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_range_validation.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_numeric_range_builder.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <limits>

namespace ua::client::detail
{

ua::ParsedNumericRangeResult validate_client_numeric_range(const ua::NodeId& node,
  const ua::NumericRange& range, std::optional<std::int32_t> valueRank, NumericRangeUse use)
{
  auto validated = ua::client::NumericRangeBuilder::from_string(range);
  if (!validated.is_good())
  {
    return ua::ParsedNumericRangeResult{validated.status_code(), validated.shared_detail()};
  }
  auto parsed = ua::parse_numeric_range(validated.value());
  if (!parsed.is_good() || parsed.value().empty() || !valueRank || *valueRank <= 0)
  {
    return parsed;
  }

  const auto actualDimensions = parsed.value().dimension_count();
  const auto requiredDimensions = static_cast<std::size_t>(*valueRank);
  // A String or ByteString element contributes a trailing substring/byte-range dimension even
  // though ValueRank counts only the containing array dimensions (Part 4 section 7.27). ValueRank
  // alone cannot distinguish that valid form from an excessive dimension, so reject only an
  // incomplete range here and leave any trailing-dimension type check to the Server.
  if (actualDimensions < requiredDimensions)
  {
    return ua::ParsedNumericRangeResult{
      use == NumericRangeUse::Read ? ua::Status::BadIndexRangeNoData : ua::Status::BadIndexRangeInvalid,
      ua::ErrorDetail::build("NumericRangeDimensionCountMismatch",
        "the NumericRange must specify every dimension of the Variable",
        "client.tier2.numeric_range")
        .context(ua::ContextKeys::nodeId, ua::to_string(node))
        .context(ua::ContextKeys::sizeExpected, requiredDimensions)
        .context(ua::ContextKeys::sizeActual, actualDimensions)};
  }

  return parsed;
}

ua::VoidResult validate_client_numeric_range_write_cardinality(
  const ua::NodeId& node, const ua::ParsedNumericRange& range, const ua::Variant& value)
{
  std::size_t expectedCardinality = 1;
  for (const auto& dimension : range.dimensions)
  {
    const auto low = static_cast<std::size_t>(dimension.low);
    const auto high = static_cast<std::size_t>(dimension.high);
    if (high == std::numeric_limits<std::size_t>::max() || high + 1 < low)
    {
      return ua::VoidResult{ua::Status::BadTypeMismatch,
        ua::ErrorDetail::build("NumericRangeWriteCardinalityOverflow",
          "the NumericRange selected cardinality cannot be represented by this client",
          "client.tier2.numeric_range")
          .context(ua::ContextKeys::nodeId, ua::to_string(node))};
    }
    const auto extent = high - low + 1;
    if (extent != 0 && expectedCardinality > std::numeric_limits<std::size_t>::max() / extent)
    {
      return ua::VoidResult{ua::Status::BadTypeMismatch,
        ua::ErrorDetail::build("NumericRangeWriteCardinalityOverflow",
          "the NumericRange selected cardinality cannot be represented by this client",
          "client.tier2.numeric_range")
          .context(ua::ContextKeys::nodeId, ua::to_string(node))};
    }
    expectedCardinality *= extent;
  }

  const std::size_t actualCardinality = value.is_array() ? value.get_array_base().size() : 0;
  if (!value.is_array() || actualCardinality != expectedCardinality)
  {
    return ua::VoidResult{ua::Status::BadTypeMismatch,
      ua::ErrorDetail::build("NumericRangeWriteCardinalityMismatch",
        "the ranged Write value cardinality must equal the NumericRange selected cardinality",
        "client.tier2.numeric_range")
        .context(ua::ContextKeys::nodeId, ua::to_string(node))
        .context(ua::ContextKeys::sizeExpected, expectedCardinality)
        .context(ua::ContextKeys::sizeActual, actualCardinality)};
  }
  return ua::VoidResult{};
}

}  // namespace ua::client::detail
