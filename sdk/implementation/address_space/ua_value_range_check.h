// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_VALUE_RANGE_CHECK_H
#define UA_VALUE_RANGE_CHECK_H

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node_id.h"
#include "ua_numeric_range_parser.h"
#include "ua_status_code.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

namespace ua::detail
{

/// Where a Value is larger than the IndexRange it was produced for (NR-10 rule 8): the check that the
/// route applies to a namespace's `read_values_async` answer and the monitored item to every value it
/// queues that it does not narrow itself.
struct RangeExcess
{
  /// The dimension; when `rank`, the number of dimensions the range names.
  std::size_t dimension{0};
  /// The elements the range selects in that dimension; when `rank`, the dimensions the range names.
  std::size_t expected{0};
  /// The elements the Value holds in that dimension; when `rank`, the Value's dimensions.
  std::size_t actual{0};
  /// Whether the Value has more dimensions than the range names.
  bool rank{false};
};

/// Whether @p actual elements in @p dimension are more than @p range selects there.
inline std::optional<RangeExcess> dimension_beyond(
  const ParsedNumericRange& range, std::size_t dimension, std::size_t actual)
{
  if (actual == 0)
  {
    return std::nullopt;
  }
  if (dimension >= range.dimension_count())
  {
    return RangeExcess{dimension, 0, actual, false};
  }
  // The range selects high - low + 1 elements, a count that does not fit a UInt32 for 0:4294967295, so the
  // Value's count less one is compared with high - low.
  const DimensionRange& selected = range.dimensions[dimension];
  const std::uint64_t span = std::uint64_t{selected.high} - selected.low;
  if (static_cast<std::uint64_t>(actual) - 1 > span)
  {
    return RangeExcess{dimension, static_cast<std::size_t>(span + 1), actual, false};
  }
  return std::nullopt;
}

/// The characters of a String's UTF-8: one per byte that does not continue a sequence. Part 4 7.27 lets a
/// range select a substring without naming its unit, so a namespace may count characters or bytes; the
/// smaller count, characters, refuses neither.
inline std::size_t character_count(std::string_view text)
{
  return static_cast<std::size_t>(std::count_if(
    text.begin(), text.end(), [](char c) { return (static_cast<unsigned char>(c) & 0xC0U) != 0x80U; }));
}

/// The first dimension of a 1-D array's String or ByteString elements, the range's second, that an element
/// exceeds.
template<typename Element>
std::optional<RangeExcess> element_beyond(const Variant& value, const ParsedNumericRange& range)
{
  const auto& elements = value.as<Array<Element>>();
  for (std::size_t k = 0; k < elements.size(); ++k)
  {
    std::size_t length = 0;
    if constexpr (std::is_same_v<Element, String>)
    {
      length = character_count(std::string_view{elements[k]});
    }
    else
    {
      length = elements[k].size();
    }
    if (auto excess = dimension_beyond(range, 1, length))
    {
      return excess;
    }
  }
  return std::nullopt;
}

/// The first dimension in which @p value holds more than @p range selects; none for an empty range or Value.
/// A scalar String or ByteString has one dimension, its characters or bytes; any other scalar has none. A
/// 1-D array has its elements, and for a range of two or more dimensions its String or ByteString elements'
/// own length as the second; an array with ArrayDimensions of rank two or more has those, and exceeds a
/// range naming fewer.
inline std::optional<RangeExcess> first_dimension_beyond(
  const Variant& value, const ParsedNumericRange& range)
{
  if (range.empty() || value.empty())
  {
    return std::nullopt;
  }
  if (value.is_string())
  {
    return dimension_beyond(range, 0, character_count(std::string_view{value.as<String>()}));
  }
  if (value.is_byte_string())
  {
    return dimension_beyond(range, 0, value.as<ByteString>().size());
  }
  if (!value.is_array())
  {
    return std::nullopt;
  }
  const ArrayBase& array = value.get_array_base();
  const auto& dimensions = array.dimensions();
  if (dimensions && dimensions->size() >= 2)
  {
    if (dimensions->size() > range.dimension_count())
    {
      return RangeExcess{range.dimension_count(), range.dimension_count(), dimensions->size(), true};
    }
    for (std::size_t i = 0; i < dimensions->size(); ++i)
    {
      const int32_t length = (*dimensions)[i];
      if (auto excess = dimension_beyond(range, i, length > 0 ? static_cast<std::size_t>(length) : 0U))
      {
        return excess;
      }
    }
    return std::nullopt;
  }
  if (auto excess = dimension_beyond(range, 0, array.size()))
  {
    return excess;
  }
  if (range.dimension_count() < 2)
  {
    return std::nullopt;
  }
  if (value.is_array_of_string())
  {
    return element_beyond<String>(value, range);
  }
  if (value.is_array_of_byte_string())
  {
    return element_beyond<ByteString>(value, range);
  }
  return std::nullopt;
}

/// The answer for a Value produced for @p nodeId larger than its IndexRange: `Bad_InternalError` with the
/// ErrorDetail `NamespaceValueExceedsRange`. The namespace broke its contract, so the item fails rather than
/// passing on data the client did not ask for. The detail names the namespace by @p namespaceUri when the
/// reporter holds it, and always by the NodeId's namespace index.
///
/// @param nodeId       The Node whose Value was produced.
/// @param excess       Where the Value is larger than its range.
/// @param reporter     The component that found it, the detail's source.
/// @param namespaceUri The URI of the namespace that produced the Value, when known.
inline StatusCode value_exceeds_range(const NodeId& nodeId, const RangeExcess& excess, std::string reporter,
  std::optional<std::string> namespaceUri = std::nullopt)
{
  auto detail = ErrorDetail::build("NamespaceValueExceedsRange",
    "The namespace answered a Value larger than the IndexRange it was asked to apply",
    std::move(reporter));
  if (namespaceUri)
  {
    detail.context(ContextKeys::namespaceUri, std::move(*namespaceUri));
  }
  detail.context(ContextKeys::namespaceIndex, std::to_string(nodeId.namespace_index()))
    .context(ContextKeys::nodeId, to_string(nodeId));
  if (excess.rank)
  {
    detail.context(ContextKeys::countExpected, std::to_string(excess.expected))
      .context(ContextKeys::countActual, std::to_string(excess.actual));
  }
  else
  {
    detail.context(ContextKeys::index, std::to_string(excess.dimension))
      .context(ContextKeys::sizeExpected, std::to_string(excess.expected))
      .context(ContextKeys::sizeActual, std::to_string(excess.actual));
  }
  return StatusCode{Status::BadInternalError, std::move(detail)};
}

}  // namespace ua::detail

#endif  // !UA_VALUE_RANGE_CHECK_H
