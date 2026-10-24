// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_access_utils.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include "ua_array.h"
#include "ua_built_in_type_id.h"
#include "ua_error_detail.h"
#include "ua_status_code.h"
#include "ua_to_result.h"

namespace ua::data_access_utils
{

namespace
{

constexpr std::string_view errorSource = "DataAccess";

/// The smallest value of the integer type T that is not below @p low, or nothing when every value of T is.
///
/// An integer is below a limit exactly when it is below the limit's ceiling, so the comparison is made in T
/// and no value of T is rounded through a double. Every value of T lies below 2^digits, an exact double.
template<typename T>
std::optional<T> lowest_integer_at_or_above(double low)
{
  const double end = std::ldexp(1.0, std::numeric_limits<T>::digits);
  const double ceiling = std::ceil(low);
  if (ceiling >= end)
  {
    return std::nullopt;
  }
  if (ceiling <= static_cast<double>(std::numeric_limits<T>::min()))
  {
    return std::numeric_limits<T>::min();
  }
  return static_cast<T>(ceiling);
}

/// The largest value of the integer type T that is not above @p high, or nothing when every value of T is.
template<typename T>
std::optional<T> highest_integer_at_or_below(double high)
{
  const double end = std::ldexp(1.0, std::numeric_limits<T>::digits);
  const double floor = std::floor(high);
  if (floor >= end)
  {
    return std::numeric_limits<T>::max();
  }
  if (floor < static_cast<double>(std::numeric_limits<T>::min()))
  {
    return std::nullopt;
  }
  return static_cast<T>(floor);
}

/// The smallest value of the floating-point type F that is not below @p low.
///
/// A limit that F cannot hold exactly rounds to a neighbour, which may lie on the wrong side of it; the next
/// value of F inward is then taken, so a clamped Float is never outside the range.
template<typename F>
F lowest_float_at_or_above(double low)
{
  constexpr F max = std::numeric_limits<F>::max();
  constexpr F infinity = std::numeric_limits<F>::infinity();
  if (low > static_cast<double>(max))
  {
    return infinity;
  }
  if (low < -static_cast<double>(max))
  {
    return std::isinf(low) ? -infinity : -max;
  }
  F converted = static_cast<F>(low);
  if (static_cast<double>(converted) < low)
  {
    converted = std::nextafter(converted, infinity);
  }
  return converted;
}

/// The largest value of the floating-point type F that is not above @p high.
template<typename F>
F highest_float_at_or_below(double high)
{
  constexpr F max = std::numeric_limits<F>::max();
  constexpr F infinity = std::numeric_limits<F>::infinity();
  if (high < -static_cast<double>(max))
  {
    return -infinity;
  }
  if (high > static_cast<double>(max))
  {
    return std::isinf(high) ? infinity : max;
  }
  F converted = static_cast<F>(high);
  if (static_cast<double>(converted) > high)
  {
    converted = std::nextafter(converted, -infinity);
  }
  return converted;
}

/// The values of T that @p range admits, as the lowest and the highest, or nothing when it admits none. A NaN
/// limit leaves its side unbounded (OPC 10000-8 5.6.2).
template<typename T>
std::optional<std::pair<T, T>> values_admitted(const Range& range)
{
  T lowest;
  T highest;
  if constexpr (std::is_floating_point_v<T>)
  {
    lowest = std::isnan(range.low()) ? -std::numeric_limits<T>::infinity()
                                     : lowest_float_at_or_above<T>(range.low());
    highest = std::isnan(range.high()) ? std::numeric_limits<T>::infinity()
                                       : highest_float_at_or_below<T>(range.high());
  }
  else
  {
    lowest = std::numeric_limits<T>::min();
    highest = std::numeric_limits<T>::max();
    if (!std::isnan(range.low()))
    {
      const auto limit = lowest_integer_at_or_above<T>(range.low());
      if (!limit)
      {
        return std::nullopt;
      }
      lowest = *limit;
    }
    if (!std::isnan(range.high()))
    {
      const auto limit = highest_integer_at_or_below<T>(range.high());
      if (!limit)
      {
        return std::nullopt;
      }
      highest = *limit;
    }
  }
  if (highest < lowest)
  {
    return std::nullopt;
  }
  return std::pair{lowest, highest};
}

/// The decimal text of @p element for an ErrorDetail, exact for every type: an integer in full, and a Float
/// or Double as the shortest text that reads back as the same value, so a value just outside a limit is never
/// shown as the limit and a small value is never shown as 0.
template<typename T>
std::string text_of(T element)
{
  if constexpr (std::is_floating_point_v<T>)
  {
    std::array<char, 32> buffer{};
    const auto conversion = std::to_chars(buffer.data(), buffer.data() + buffer.size(), element);
    return std::string(buffer.data(), conversion.ptr);
  }
  else if constexpr (std::is_signed_v<T>)
  {
    return std::to_string(static_cast<int64_t>(element));
  }
  else
  {
    return std::to_string(static_cast<uint64_t>(element));
  }
}

/// The elements of @p value as a list: the payload of an array, or the scalar as one element.
template<typename T>
std::vector<T> elements_of(const Variant& value)
{
  if (value.is_array())
  {
    return value.as<Array<T>>().payload();
  }
  return {value.as<T>()};
}

template<typename T>
VoidResult apply_range_to(Variant& value, const Range& range, DataAccessOutOfRangePolicy policy)
{
  const auto admitted = values_admitted<T>(range);
  const auto outside = [&admitted](T element)
  {
    if constexpr (std::is_floating_point_v<T>)
    {
      if (std::isnan(element))
      {
        return true;  // a NaN is not inside a range that has a known limit
      }
    }
    return !admitted || element < admitted->first || element > admitted->second;
  };
  const auto refuse = [&range](T element, size_t index)
  {
    return VoidResult{Status::BadOutOfRange,
      ErrorDetail::build(
        "AnalogOutOfRange", "value is outside the configured range", std::string{errorSource})
        .context(ContextKeys::actual, text_of(element))
        .context(ContextKeys::min, text_of(range.low()))
        .context(ContextKeys::max, text_of(range.high()))
        .context(ContextKeys::index, std::to_string(index))};
  };

  auto elements = elements_of<T>(value);
  bool clamped = false;
  for (size_t index = 0; index < elements.size(); ++index)
  {
    T& element = elements[index];
    if (!outside(element))
    {
      continue;  // an element inside the range is kept exactly as written
    }
    // Clamp has no value to give an element of a type the range admits no value of.
    if (policy == DataAccessOutOfRangePolicy::Reject || !admitted)
    {
      return refuse(element, index);
    }
    const T nearest = element < admitted->first ? admitted->first : admitted->second;
    if constexpr (std::is_floating_point_v<T>)
    {
      // Nor a NaN, and it never stores an infinity it was not given: a range whose only values of T are
      // infinite admits no value to clamp to.
      if (std::isnan(element) || std::isinf(nearest))
      {
        return refuse(element, index);
      }
    }
    element = nearest;
    clamped = true;
  }
  if (!clamped)
  {
    return {};
  }
  if (value.is_array())
  {
    Array<T> replacement = value.as<Array<T>>();
    replacement.payload() = std::move(elements);
    value = Variant{std::move(replacement)};
  }
  else
  {
    value = Variant{elements.front()};
  }
  return VoidResult{StatusCode{Status::GoodClamped}};
}

/// An element of an enumeration write: its value as Int64, or nothing when it has none (a UInt64 above the
/// Int64 range, or a Float or Double that is NaN, not integral or outside the Int64 range), which no index
/// and no EnumValue (whose Value is an Int64) can match; and its decimal text.
struct IntegerElement
{
  std::optional<int64_t> value;
  std::string text;
};

/// The elements of @p value as integers, or nothing when the elements are neither of an integer type nor
/// Float or Double.
std::optional<std::vector<IntegerElement>> integer_elements(const Variant& value)
{
  const auto convert = [&value]<typename T>() -> std::vector<IntegerElement>
  {
    std::vector<IntegerElement> result;
    for (const auto element : elements_of<T>(value))
    {
      if constexpr (std::is_same_v<T, uint64_t>)
      {
        if (element > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        {
          result.push_back({std::nullopt, text_of(element)});
          continue;
        }
      }
      if constexpr (std::is_floating_point_v<T>)
      {
        // Every Int64 lies in [-2^63, 2^63), whose bounds are exact doubles.
        const double asDouble = element;
        const double end = std::ldexp(1.0, std::numeric_limits<int64_t>::digits);
        if (!std::isfinite(asDouble) || std::trunc(asDouble) != asDouble || asDouble < -end ||
            asDouble >= end)
        {
          result.push_back({std::nullopt, text_of(element)});
          continue;
        }
      }
      result.push_back({static_cast<int64_t>(element), text_of(element)});
    }
    return result;
  };
  if (value.empty())
  {
    return std::nullopt;
  }
  switch (value.get_built_in_type())
  {
  case BuiltInTypeId::SByte:
    return convert.template operator()<int8_t>();
  case BuiltInTypeId::Byte:
    return convert.template operator()<uint8_t>();
  case BuiltInTypeId::Int16:
    return convert.template operator()<int16_t>();
  case BuiltInTypeId::UInt16:
    return convert.template operator()<uint16_t>();
  case BuiltInTypeId::Int32:
    return convert.template operator()<int32_t>();
  case BuiltInTypeId::UInt32:
    return convert.template operator()<uint32_t>();
  case BuiltInTypeId::Int64:
    return convert.template operator()<int64_t>();
  case BuiltInTypeId::UInt64:
    return convert.template operator()<uint64_t>();
  case BuiltInTypeId::Float:
    return convert.template operator()<float>();
  case BuiltInTypeId::Double:
    return convert.template operator()<double>();
  default:
    return std::nullopt;
  }
}

}  // namespace

VoidResult apply_analog_range(Variant& value, const Range& range, DataAccessOutOfRangePolicy policy)
{
  try
  {
    if (value.empty())
    {
      return {};
    }
    if (std::isnan(range.low()) && std::isnan(range.high()))
    {
      return {};  // neither limit is known
    }
    if (!std::isnan(range.low()) && !std::isnan(range.high()) && range.high() < range.low())
    {
      return {};  // not a usable range
    }
    switch (value.get_built_in_type())
    {
    case BuiltInTypeId::SByte:
      return apply_range_to<int8_t>(value, range, policy);
    case BuiltInTypeId::Byte:
      return apply_range_to<uint8_t>(value, range, policy);
    case BuiltInTypeId::Int16:
      return apply_range_to<int16_t>(value, range, policy);
    case BuiltInTypeId::UInt16:
      return apply_range_to<uint16_t>(value, range, policy);
    case BuiltInTypeId::Int32:
      return apply_range_to<int32_t>(value, range, policy);
    case BuiltInTypeId::UInt32:
      return apply_range_to<uint32_t>(value, range, policy);
    case BuiltInTypeId::Int64:
      return apply_range_to<int64_t>(value, range, policy);
    case BuiltInTypeId::UInt64:
      return apply_range_to<uint64_t>(value, range, policy);
    case BuiltInTypeId::Float:
      return apply_range_to<float>(value, range, policy);
    case BuiltInTypeId::Double:
      return apply_range_to<double>(value, range, policy);
    default:
      return {};  // not numeric: the DataType checks decide it
    }
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

VoidResult check_enum_strings_index(const Variant& value, std::span<const LocalizedText> enumStrings)
{
  try
  {
    const auto indexes = integer_elements(value);
    if (!indexes)
    {
      return {};
    }
    for (size_t element = 0; element < indexes->size(); ++element)
    {
      const auto& index = (*indexes)[element];
      if (!index.value || *index.value < 0 || static_cast<uint64_t>(*index.value) >= enumStrings.size())
      {
        return VoidResult{Status::BadOutOfRange,
          ErrorDetail::build("MultiStateIndexOutOfRange",
            "index is not within the valid EnumStrings range",
            std::string{errorSource})
            .context(ContextKeys::actual, index.text)
            .context(ContextKeys::sizeMax, std::to_string(enumStrings.size()))
            .context(ContextKeys::index, std::to_string(element))};
      }
    }
    return {};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

VoidResult check_enum_values_member(const Variant& value, std::span<const EnumValueType> enumValues)
{
  try
  {
    const auto wanted = integer_elements(value);
    if (!wanted)
    {
      return {};
    }
    for (size_t element = 0; element < wanted->size(); ++element)
    {
      const auto& candidate = (*wanted)[element];
      bool defined = false;
      if (candidate.value)
      {
        for (const auto& entry : enumValues)
        {
          if (entry.value() == *candidate.value)
          {
            defined = true;
            break;
          }
        }
      }
      if (!defined)
      {
        return VoidResult{Status::BadOutOfRange,
          ErrorDetail::build(
            "MultiStateValueInvalid", "value is not a defined EnumValue", std::string{errorSource})
            .context(ContextKeys::actual, candidate.text)
            .context(ContextKeys::index, std::to_string(element))};
      }
    }
    return {};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

bool is_semantic_property(const QualifiedName& browseName, const AccessLevelExType& accessLevelEx) noexcept
{
  if (accessLevelEx.test(AccessLevelExType::Bit::SemanticChange))
  {
    return true;
  }
  if (browseName.namespace_index() != 0)
  {
    return false;
  }
  // OPC 10000-8 5.3.2.2, 5.3.3.2 to 5.3.3.4 and 5.3.4.1 to 5.3.4.6.
  static constexpr std::array<std::string_view, 12> part8Names{"EURange",
    "EngineeringUnits",
    "InstrumentRange",
    "Title",
    "AxisDefinition",
    "XAxisDefinition",
    "YAxisDefinition",
    "ZAxisDefinition",
    "FalseState",
    "TrueState",
    "EnumStrings",
    "EnumValues"};
  const auto name = static_cast<std::string_view>(browseName.name());
  return std::find(part8Names.begin(), part8Names.end(), name) != part8Names.end();
}

}  // namespace ua::data_access_utils
