// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Parser for OPC UA NumericRange strings into structured index ranges.
/// @ingroup core_types

#ifndef UA_NUMERIC_RANGE_PARSER_H
#define UA_NUMERIC_RANGE_PARSER_H

#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_numeric_range.h"

#include <vector>

namespace ua
{

template<typename T>
class Result;

/// An inclusive index range for a single dimension of a NumericRange.
///
/// Both bounds are zero-based array indices. The range covers every index from
/// @ref low to @ref high inclusive; a single-index selection is encoded as
/// @ref high equal to @ref low.
/// @ingroup core_types
struct DimensionRange
{
  uint32_t low;  ///< Lowest selected index in this dimension (inclusive).
  uint32_t high;  ///< Highest selected index in this dimension (inclusive); equals @ref low for a
                  ///< single index.
};

/// A NumericRange parsed into one inclusive @ref DimensionRange per dimension.
///
/// The dimensions are ordered outermost-first, matching the comma-separated
/// order of the source NumericRange string. An empty @ref dimensions vector
/// denotes the whole value (the result of parsing an empty range string).
/// @ingroup core_types
struct ParsedNumericRange
{
  std::vector<DimensionRange> dimensions;  ///< One inclusive range per dimension, outermost first.

  /// Whether the parsed range selects the whole value (no dimensions).
  ///
  /// @return `true` if there are no dimensions, meaning the whole value is selected.
  bool empty() const
  {
    return dimensions.empty();
  }

  /// The number of dimensions in the parsed range.
  ///
  /// @return The number of dimensions in the parsed range.
  size_t dimension_count() const
  {
    return dimensions.size();
  }

  /// The number of selected elements in dimension @p dim.
  ///
  /// @param dim Zero-based dimension index.
  /// @return The inclusive element count `high - low + 1`, or `0` if @p dim is out of range.
  size_t element_count(size_t dim) const
  {
    return dim < dimensions.size() ? (dimensions[dim].high - dimensions[dim].low + 1) : 0;
  }
};

/// Result of parsing a NumericRange: a @ref ParsedNumericRange or an @ref ErrorDetail.
using ParsedNumericRangeResult = Result<ParsedNumericRange>;

/// Parses an OPC UA NumericRange string into structured dimension ranges.
///
/// Implements the NumericRange grammar from OPC UA Part 4 7.27. An empty input
/// string parses successfully to an empty `ParsedNumericRange` (selecting the
/// whole value). This call never throws.
///
/// @param range The NumericRange string to parse.
/// @return The parsed range on success, or an `ErrorDetail` carrying
///         `BadIndexRangeInvalid` on a syntax error. Never throws.
ParsedNumericRangeResult parse_numeric_range(const NumericRange& range);

/// IndexRange slicing and partial-write helpers for @ref Variant values.
///
/// Implements the IndexRange semantics of OPC UA Part 4 for Read and Write: a
/// range selects a sub-region of an array, String, or ByteString value. The
/// functions are pure and synchronous; they never throw and report failures as
/// an @ref ErrorDetail on the returned @ref VariantResult.
namespace index_range_utils
{

/// Applies an IndexRange to a Variant and returns the selected sub-value.
///
/// Slices @p source according to @p range following OPC UA Part 4 Read
/// semantics. Supports 1-D array slices, 2-D slices of String and ByteString
/// arrays, and character/byte slices of scalar String and ByteString values.
///
/// @param source The full value to slice.
/// @param range  The parsed range selecting the sub-region. An empty range is a
///               pass-through that yields a copy of @p source unchanged.
/// @return The sliced sub-value, or an @ref ErrorDetail on failure: @c
///         BadIndexRangeNoData when the range selects nothing, has a number of
///         dimensions other than the value's, or the value shape is unsupported.
///         Never throws.
/// @see apply_write
VariantResult apply_read(const Variant& source, const ParsedNumericRange& range);

/// Merges a partial value into an existing Variant at the given IndexRange.
///
/// Writes @p partial into the sub-region of @p existing selected by @p range
/// following OPC UA Part 4 Write semantics, returning the merged value;
/// @p existing is not modified in place. Supports 1-D array, 2-D String and
/// ByteString array, and scalar String and ByteString targets.
///
/// @param existing The current value into which the partial value is merged.
/// @param partial  The replacement data for the selected sub-region. Its shape
///                 must match the target (array vs. scalar, built-in type).
/// @param range    The parsed range selecting the target sub-region. An empty
///                 range is a full replacement that yields a copy of @p partial.
/// @return The merged value, or an @ref ErrorDetail on failure: @c
///         BadTypeMismatch when @p partial does not match @p existing, @c
///         BadIndexRangeNoData when the range selects nothing or the value
///         shape is unsupported, @c BadIndexRangeInvalid for a malformed range.
///         Never throws.
/// @see apply_read
VariantResult apply_write(const Variant& existing, const Variant& partial, const ParsedNumericRange& range);

/// Narrows the Value of @p value to @p range, as OPC UA Part 4 7.27 defines it for a read.
///
/// The read-side IndexRange step of the Read service, of monitored items and of any namespace that
/// narrows a whole Value itself; a history read applies each item's IndexRange in its history delegate
/// (the SDK's own uses @ref apply_read). A value whose status is Bad, and an empty range,
/// leave @p value unchanged. A malformed range sets the status to Bad_IndexRangeInvalid. A
/// syntactically valid range that selects nothing sets Bad_IndexRangeNoData, including a range whose
/// number of dimensions differs from the value's ("All other invalid requests with a valid syntax
/// shall result in Bad_IndexRangeNoData"). Upper bounds beyond the value give a partial result. On
/// failure the status carries an @ref ErrorDetail and the Value is null (Part 4 7.11.1 Table 135, "the
/// Server shall set it to null"). Never throws.
///
/// @param value The DataValue whose Value is narrowed in place.
/// @param range The IndexRange of the read, as the client sent it.
void apply_to_value(DataValue& value, const NumericRange& range);

}  // namespace index_range_utils

}  // namespace ua

#endif  // UA_NUMERIC_RANGE_PARSER_H
