// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 builder for syntactically valid OPC UA NumericRange values.
/// @ingroup client

#ifndef UA_NUMERIC_RANGE_BUILDER_H
#define UA_NUMERIC_RANGE_BUILDER_H

#include "ua_numeric_range.h"
#include "ua_numeric_range_parser.h"
#include "ua_result.h"

#include <cstddef>
#include <optional>
#include <vector>

namespace ua::client
{

/// Builds validated NumericRange wire values for tier-2 client operations.
///
/// Both entry points enforce the Part 4 section 7.27 grammar. When @p expectedDimensions is supplied, the
/// builder also requires exactly that many comma-separated dimensions. The returned NumericRange is ready to
/// pass to a tier-1 request; tier-1 itself intentionally continues to accept raw wire-shaped strings.
/// @ingroup client
class NumericRangeBuilder
{
public:
  /// @param range Index or time range to access.
  /// @param expectedDimensions The expected dimensions.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Validates an existing wire-form NumericRange without normalising it.
  [[nodiscard]] static ua::Result<ua::NumericRange> from_string(
    ua::NumericRange range, std::optional<std::size_t> expectedDimensions = std::nullopt) noexcept;

  /// Encodes structured inclusive dimension ranges into a valid NumericRange.
  ///
  /// @param dimensions The dimensions.
  /// @param expectedDimensions The expected dimensions.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// A dimension whose bounds are equal is encoded as a single index; otherwise @c low:high is emitted and
  /// @c low must be strictly less than @c high.
  [[nodiscard]] static ua::Result<ua::NumericRange> from_dimensions(
    std::vector<ua::DimensionRange> dimensions,
    std::optional<std::size_t> expectedDimensions = std::nullopt) noexcept;
};

}  // namespace ua::client

#endif  // UA_NUMERIC_RANGE_BUILDER_H
