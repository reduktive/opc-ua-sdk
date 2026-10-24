// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Part 4 NumericRange validation at public tier-2 client boundaries.

#ifndef UA_NUMERIC_RANGE_VALIDATION_H
#define UA_NUMERIC_RANGE_VALIDATION_H

#include "ua_node_id.h"
#include "ua_numeric_range_parser.h"
#include "ua_result.h"
#include "ua_variant.h"

#include <cstdint>
#include <optional>

namespace ua::client::detail
{

/// Whether a range is checked for a Read or for a Write: the two answer a range with too few dimensions with
/// different status codes, as the server's Read and Write do.
enum class NumericRangeUse
{
  Read,
  Write
};

/// Parses @p range and, when a fixed Variable rank is known, requires every dimension to be specified.
///
/// A range with fewer dimensions than @p valueRank answers what the server would: Bad_IndexRangeNoData for a
/// Read (Part 4 7.27, a request with a valid syntax that selects nothing), which the caller delivers as the
/// Read's value status, and Bad_IndexRangeInvalid for a Write, which fails the Write.
[[nodiscard]] ua::ParsedNumericRangeResult validate_client_numeric_range(const ua::NodeId& node,
  const ua::NumericRange& range, std::optional<std::int32_t> valueRank, NumericRangeUse use);

/// Requires the array payload cardinality to equal the product of all inclusive range extents.
[[nodiscard]] ua::VoidResult validate_client_numeric_range_write_cardinality(
  const ua::NodeId& node, const ua::ParsedNumericRange& range, const ua::Variant& value);

}  // namespace ua::client::detail

#endif  // UA_NUMERIC_RANGE_VALIDATION_H
