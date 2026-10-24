// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_range_parser.h"
#include <cstddef>
#include <type_traits>
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_result.h"
#include "ua_string.h"
#include "ua_variant.h"

namespace ua
{
namespace index_range_utils
{

namespace
{

constexpr string_view errorSource = "IndexRangeUtils";

VariantResult make_no_data(const std::string& reason)
{
  return {StatusCode{Status::BadIndexRangeNoData},
    ErrorDetail::build("IndexRangeNoData", "Index range selects no data", std::string{errorSource})
      .context(ContextKeys::errorMessage, reason)};
}

// Context-bearing overload: the caller builds the ErrorDetail with structured facts via
// ErrorDetail::build(...).context(...); this helper just wraps it in the Status code.
VariantResult make_no_data(std::unique_ptr<ErrorDetail> detail)
{
  return {StatusCode{Status::BadIndexRangeNoData}, std::move(detail)};
}

VariantResult make_invalid(std::unique_ptr<ErrorDetail> detail)
{
  return {StatusCode{Status::BadIndexRangeInvalid}, std::move(detail)};
}

VariantResult make_type_mismatch(const std::string& reason)
{
  return {StatusCode{Status::BadTypeMismatch},
    ErrorDetail::build("TypeMismatch", "Variant type mismatch", std::string{errorSource})
      .context(ua::ContextKeys::errorMessage, reason)};
}

// Map a Variant's built-in element type to the concrete C++ type and invoke `op.operator()<T>()`.
// Every type-parameterised array operation (1-D / N-D, read / write) routes through this one switch,
// so the element-type table lives in a single place. ExtensionObject maps to RefStructure<Structure>
// (the per-T helpers provide clone() specializations for it).
template<typename Op>
VariantResult dispatch_by_type(BuiltInTypeId type, Op op)
{
  switch (type)
  {
  case BuiltInTypeId::Boolean:
    return op.template operator()<bool>();
  case BuiltInTypeId::SByte:
    return op.template operator()<int8_t>();
  case BuiltInTypeId::Byte:
    return op.template operator()<uint8_t>();
  case BuiltInTypeId::Int16:
    return op.template operator()<int16_t>();
  case BuiltInTypeId::UInt16:
    return op.template operator()<uint16_t>();
  case BuiltInTypeId::Int32:
    return op.template operator()<int32_t>();
  case BuiltInTypeId::UInt32:
    return op.template operator()<uint32_t>();
  case BuiltInTypeId::Int64:
    return op.template operator()<int64_t>();
  case BuiltInTypeId::UInt64:
    return op.template operator()<uint64_t>();
  case BuiltInTypeId::Float:
    return op.template operator()<float>();
  case BuiltInTypeId::Double:
    return op.template operator()<double>();
  case BuiltInTypeId::DateTime:
    return op.template operator()<DateTime>();
  case BuiltInTypeId::Guid:
    return op.template operator()<Guid>();
  case BuiltInTypeId::String:
    return op.template operator()<String>();
  case BuiltInTypeId::ByteString:
    return op.template operator()<ByteString>();
  case BuiltInTypeId::XmlElement:
    return op.template operator()<XmlElement>();
  case BuiltInTypeId::NodeId:
    return op.template operator()<NodeId>();
  case BuiltInTypeId::ExpandedNodeId:
    return op.template operator()<ExpandedNodeId>();
  case BuiltInTypeId::StatusCode:
    return op.template operator()<StatusCode>();
  case BuiltInTypeId::QualifiedName:
    return op.template operator()<QualifiedName>();
  case BuiltInTypeId::LocalizedText:
    return op.template operator()<LocalizedText>();
  case BuiltInTypeId::ExtensionObject:
    return op.template operator()<RefStructure<Structure>>();
  case BuiltInTypeId::DataValue:
    return op.template operator()<DataValue>();
  case BuiltInTypeId::Variant:
    return op.template operator()<Variant>();
  default:
    return make_no_data("Unsupported array element type for IndexRange");
  }
}

// --- Read helpers ---

template<typename T>
VariantResult slice_array_1d(const Variant& source, const DimensionRange& dim)
{
  const auto& arr = source.as<Array<T>>();
  if (arr.empty() || dim.low >= arr.size())
  {
    return make_no_data(
      ErrorDetail::build("IndexRangeNoData", "Index range start exceeds array size", std::string{errorSource})
        .context(ua::ContextKeys::index, std::to_string(dim.low))
        .context(ua::ContextKeys::sizeActual, std::to_string(arr.size())));
  }
  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(arr.size() - 1));
  Array<T> result;
  const auto& payload = arr.payload();
  for (uint32_t i = dim.low; i <= high; ++i)
  {
    result.push_back(payload[i]);
  }
  return Variant{std::move(result)};
}

// Specialization for RefStructure<Structure> which needs clone()
template<>
VariantResult slice_array_1d<RefStructure<Structure>>(const Variant& source, const DimensionRange& dim)
{
  const auto& arr = source.as<Array<RefStructure<Structure>>>();
  if (arr.empty() || dim.low >= arr.size())
  {
    return make_no_data(
      ErrorDetail::build("IndexRangeNoData", "Index range start exceeds array size", std::string{errorSource})
        .context(ua::ContextKeys::index, std::to_string(dim.low))
        .context(ua::ContextKeys::sizeActual, std::to_string(arr.size())));
  }
  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(arr.size() - 1));
  Array<RefStructure<Structure>> result;
  for (uint32_t i = dim.low; i <= high; ++i)
  {
    const auto& element = arr[i];
    if (element.get())
    {
      result.push_back(RefStructure<Structure>{element.get()->clone()});
    }
    else
    {
      result.push_back(RefStructure<Structure>{});
    }
  }
  return Variant{std::move(result)};
}

VariantResult read_scalar_string(const Variant& source, const DimensionRange& dim)
{
  const auto& str = source.as<String>();
  if (str.empty() || dim.low >= str.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Index range start exceeds string length", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(dim.low))
                          .context(ua::ContextKeys::length, std::to_string(str.size())));
  }
  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(str.size() - 1));
  const string_view sv = str;
  String result{sv.substr(dim.low, high - dim.low + 1)};
  return Variant{std::move(result)};
}

VariantResult read_scalar_byte_string(const Variant& source, const DimensionRange& dim)
{
  const auto& bs = source.as<ByteString>();
  if (bs.empty() || dim.low >= bs.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Index range start exceeds ByteString length", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(dim.low))
                          .context(ua::ContextKeys::length, std::to_string(bs.size())));
  }
  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(bs.size() - 1));
  ByteString result(
    bs.begin() + static_cast<std::ptrdiff_t>(dim.low), bs.begin() + static_cast<std::ptrdiff_t>(high) + 1);
  return Variant{std::move(result)};
}

VariantResult read_string_array_2d(
  const Variant& source, const DimensionRange& arrayDim, const DimensionRange& charDim)
{
  const auto& arr = source.as<Array<String>>();
  if (arr.empty() || arrayDim.low >= arr.size())
  {
    return make_no_data(
      ErrorDetail::build("IndexRangeNoData", "Index range start exceeds array size", std::string{errorSource})
        .context(ua::ContextKeys::index, std::to_string(arrayDim.low))
        .context(ua::ContextKeys::sizeActual, std::to_string(arr.size())));
  }
  const uint32_t arrayHigh = std::min(arrayDim.high, numeric_cast<uint32_t>(arr.size() - 1));
  Array<String> result;
  for (uint32_t i = arrayDim.low; i <= arrayHigh; ++i)
  {
    const auto& str = arr[i];
    const string_view sv = str;
    if (charDim.low >= sv.size())
    {
      result.push_back(String{""});
    }
    else
    {
      const uint32_t charHigh = std::min(charDim.high, numeric_cast<uint32_t>(sv.size() - 1));
      result.push_back(String{sv.substr(charDim.low, charHigh - charDim.low + 1)});
    }
  }
  return Variant{std::move(result)};
}

VariantResult read_byte_string_array_2d(
  const Variant& source, const DimensionRange& arrayDim, const DimensionRange& byteDim)
{
  const auto& arr = source.as<Array<ByteString>>();
  if (arr.empty() || arrayDim.low >= arr.size())
  {
    return make_no_data(
      ErrorDetail::build("IndexRangeNoData", "Index range start exceeds array size", std::string{errorSource})
        .context(ua::ContextKeys::index, std::to_string(arrayDim.low))
        .context(ua::ContextKeys::sizeActual, std::to_string(arr.size())));
  }
  const uint32_t arrayHigh = std::min(arrayDim.high, numeric_cast<uint32_t>(arr.size() - 1));
  Array<ByteString> result;
  for (uint32_t i = arrayDim.low; i <= arrayHigh; ++i)
  {
    const auto& bs = arr[i];
    if (byteDim.low >= bs.size())
    {
      result.push_back(ByteString{});
    }
    else
    {
      const uint32_t byteHigh = std::min(byteDim.high, numeric_cast<uint32_t>(bs.size() - 1));
      result.push_back(ByteString(bs.begin() + static_cast<std::ptrdiff_t>(byteDim.low),
        bs.begin() + static_cast<std::ptrdiff_t>(byteHigh) + 1));
    }
  }
  return Variant{std::move(result)};
}

VariantResult dispatch_array_read_1d(const Variant& source, const DimensionRange& dim)
{
  return dispatch_by_type(
    source.get_built_in_type(), [&]<typename T>() { return slice_array_1d<T>(source, dim); });
}

// --- Write helpers ---

template<typename T>
VariantResult write_array_1d(const Variant& existing, const Variant& partial, const DimensionRange& dim)
{
  const auto& existingArr = existing.as<Array<T>>();
  const auto& partialArr = partial.as<Array<T>>();

  if (dim.low >= existingArr.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Write index range start exceeds existing array size", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(dim.low))
                          .context(ua::ContextKeys::sizeActual, std::to_string(existingArr.size())));
  }

  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(existingArr.size() - 1));
  const uint32_t expectedCount = high - dim.low + 1;

  if (partialArr.size() != expectedCount)
  {
    return make_invalid(ErrorDetail::build(
      "IndexRangeInvalid", "Partial array size does not match index range extent", std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedCount))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialArr.size())));
  }

  Array<T> result;
  const auto& existingPayload = existingArr.payload();
  const auto& partialPayload = partialArr.payload();
  for (size_t i = 0; i < existingPayload.size(); ++i)
  {
    if (i >= dim.low && i <= high)
    {
      result.push_back(partialPayload[i - dim.low]);
    }
    else
    {
      result.push_back(existingPayload[i]);
    }
  }
  return Variant{std::move(result)};
}

// Specialization for RefStructure<Structure> which needs clone()
template<>
VariantResult write_array_1d<RefStructure<Structure>>(
  const Variant& existing, const Variant& partial, const DimensionRange& dim)
{
  const auto& existingArr = existing.as<Array<RefStructure<Structure>>>();
  const auto& partialArr = partial.as<Array<RefStructure<Structure>>>();

  if (dim.low >= existingArr.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Write index range start exceeds existing array size", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(dim.low))
                          .context(ua::ContextKeys::sizeActual, std::to_string(existingArr.size())));
  }

  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(existingArr.size() - 1));
  const uint32_t expectedCount = high - dim.low + 1;

  if (partialArr.size() != expectedCount)
  {
    return make_invalid(ErrorDetail::build(
      "IndexRangeInvalid", "Partial array size does not match index range extent", std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedCount))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialArr.size())));
  }

  Array<RefStructure<Structure>> result;
  const auto& payload = existingArr.payload();
  for (size_t i = 0; i < payload.size(); ++i)
  {
    if (i >= dim.low && i <= high)
    {
      const auto& element = partialArr[i - dim.low];
      if (element.get())
      {
        result.push_back(RefStructure<Structure>{element.get()->clone()});
      }
      else
      {
        result.push_back(RefStructure<Structure>{});
      }
    }
    else
    {
      const auto& element = payload[i];
      if (element.get())
      {
        result.push_back(RefStructure<Structure>{element.get()->clone()});
      }
      else
      {
        result.push_back(RefStructure<Structure>{});
      }
    }
  }
  return Variant{std::move(result)};
}

VariantResult write_scalar_string(const Variant& existing, const Variant& partial, const DimensionRange& dim)
{
  const auto& existingStr = existing.as<String>();
  const auto& partialStr = partial.as<String>();

  const string_view existingSv = existingStr;
  const string_view partialSv = partialStr;

  if (dim.low >= existingSv.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Write index range start exceeds string length", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(dim.low))
                          .context(ua::ContextKeys::length, std::to_string(existingSv.size())));
  }

  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(existingSv.size() - 1));
  const uint32_t expectedCount = high - dim.low + 1;

  if (partialSv.size() != expectedCount)
  {
    return make_invalid(ErrorDetail::build(
      "IndexRangeInvalid", "Partial string size does not match index range extent", std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedCount))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialSv.size())));
  }

  std::string result;
  result.reserve(existingSv.size());
  result.append(existingSv.data(), dim.low);
  result.append(partialSv.data(), partialSv.size());
  result.append(existingSv.data() + high + 1, existingSv.size() - high - 1);
  return Variant{String{result}};
}

VariantResult write_scalar_byte_string(
  const Variant& existing, const Variant& partial, const DimensionRange& dim)
{
  const auto& existingBs = existing.as<ByteString>();
  const auto& partialBs = partial.as<ByteString>();

  if (dim.low >= existingBs.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Write index range start exceeds ByteString length", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(dim.low))
                          .context(ua::ContextKeys::length, std::to_string(existingBs.size())));
  }

  const uint32_t high = std::min(dim.high, numeric_cast<uint32_t>(existingBs.size() - 1));
  const uint32_t expectedCount = high - dim.low + 1;

  if (partialBs.size() != expectedCount)
  {
    return make_invalid(ErrorDetail::build("IndexRangeInvalid",
      "Partial ByteString size does not match index range extent",
      std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedCount))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialBs.size())));
  }

  ByteString result = existingBs;
  for (uint32_t i = dim.low; i <= high; ++i)
  {
    result[i] = partialBs[i - dim.low];
  }
  return Variant{std::move(result)};
}

VariantResult write_string_array_2d(const Variant& existing, const Variant& partial,
  const DimensionRange& arrayDim, const DimensionRange& charDim)
{
  const auto& existingArr = existing.as<Array<String>>();
  const auto& partialArr = partial.as<Array<String>>();

  if (arrayDim.low >= existingArr.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Write index range start exceeds array size", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(arrayDim.low))
                          .context(ua::ContextKeys::sizeActual, std::to_string(existingArr.size())));
  }

  const uint32_t arrayHigh = std::min(arrayDim.high, numeric_cast<uint32_t>(existingArr.size() - 1));
  const uint32_t expectedArrayCount = arrayHigh - arrayDim.low + 1;

  if (partialArr.size() != expectedArrayCount)
  {
    return make_invalid(ErrorDetail::build(
      "IndexRangeInvalid", "Partial array size does not match index range extent", std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedArrayCount))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialArr.size())));
  }

  Array<String> result;
  const auto& payload = existingArr.payload();
  for (size_t i = 0; i < payload.size(); ++i)
  {
    if (i >= arrayDim.low && i <= arrayHigh)
    {
      const string_view existingSv = payload[i];
      const string_view partialSv = partialArr[i - arrayDim.low];

      if (charDim.low >= existingSv.size())
      {
        result.push_back(payload[i]);
        continue;
      }

      const uint32_t charHigh = std::min(charDim.high, numeric_cast<uint32_t>(existingSv.size() - 1));

      std::string merged;
      merged.reserve(existingSv.size());
      merged.append(existingSv.data(), charDim.low);
      merged.append(partialSv.data(), partialSv.size());
      merged.append(existingSv.data() + charHigh + 1, existingSv.size() - charHigh - 1);
      result.push_back(String{merged});
    }
    else
    {
      result.push_back(payload[i]);
    }
  }
  return Variant{std::move(result)};
}

VariantResult write_byte_string_array_2d(const Variant& existing, const Variant& partial,
  const DimensionRange& arrayDim, const DimensionRange& byteDim)
{
  const auto& existingArr = existing.as<Array<ByteString>>();
  const auto& partialArr = partial.as<Array<ByteString>>();

  if (arrayDim.low >= existingArr.size())
  {
    return make_no_data(ErrorDetail::build(
      "IndexRangeNoData", "Write index range start exceeds array size", std::string{errorSource})
                          .context(ua::ContextKeys::index, std::to_string(arrayDim.low))
                          .context(ua::ContextKeys::sizeActual, std::to_string(existingArr.size())));
  }

  const uint32_t arrayHigh = std::min(arrayDim.high, numeric_cast<uint32_t>(existingArr.size() - 1));
  const uint32_t expectedArrayCount = arrayHigh - arrayDim.low + 1;

  if (partialArr.size() != expectedArrayCount)
  {
    return make_invalid(ErrorDetail::build(
      "IndexRangeInvalid", "Partial array size does not match index range extent", std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedArrayCount))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialArr.size())));
  }

  Array<ByteString> result;
  const auto& payload = existingArr.payload();
  for (size_t i = 0; i < payload.size(); ++i)
  {
    if (i >= arrayDim.low && i <= arrayHigh)
    {
      const auto& existingBs = payload[i];
      const auto& partialBs = partialArr[i - arrayDim.low];

      if (byteDim.low >= existingBs.size())
      {
        result.push_back(payload[i]);
        continue;
      }

      const uint32_t byteHigh = std::min(byteDim.high, numeric_cast<uint32_t>(existingBs.size() - 1));

      ByteString merged;
      merged.reserve(existingBs.size());
      auto& mp = merged.payload();
      mp.insert(mp.end(), existingBs.begin(), existingBs.begin() + static_cast<std::ptrdiff_t>(byteDim.low));
      mp.insert(mp.end(), partialBs.begin(), partialBs.end());
      mp.insert(mp.end(), existingBs.begin() + static_cast<std::ptrdiff_t>(byteHigh) + 1, existingBs.end());
      result.push_back(std::move(merged));
    }
    else
    {
      result.push_back(payload[i]);
    }
  }
  return Variant{std::move(result)};
}

bool types_match(const Variant& a, const Variant& b)
{
  if (a.is_array() != b.is_array())
    return false;
  if (a.empty() || b.empty())
    return false;
  return a.get_built_in_type() == b.get_built_in_type();
}

VariantResult dispatch_array_write_1d(
  const Variant& existing, const Variant& partial, const DimensionRange& dim)
{
  if (!types_match(existing, partial))
  {
    return make_type_mismatch("Existing and partial variant types do not match for write");
  }

  return dispatch_by_type(
    existing.get_built_in_type(), [&]<typename T>() { return write_array_1d<T>(existing, partial, dim); });
}

// --- Multi-dimensional (true N-D) array read/write ---
//
// A genuine multi-dimensional array Variant carries a flattened payload plus an ArrayDimensions
// vector (row-major, Part 6 5.2.2.16). The IndexRange specifies one [low:high] per dimension; the
// selected sub-block is itself a multi-dimensional array. (Contrast the String/ByteString 2D path,
// which slices the *characters* of a 1-D array of strings.)

// Per-dimension slice geometry: clamped low/high, output extent, and row-major source strides.
struct NdSlice
{
  std::vector<uint32_t> low;
  std::vector<uint32_t> extent;
  std::vector<size_t> stride;
  size_t total{1};
};

// Which operation a slice serves; the two answer a dimension-count mismatch differently.
enum class Operation
{
  Read,
  Write
};

// Validate the range against the source dimensions and compute the slice geometry. On failure,
// writes the error into `error` and returns false.
bool compute_nd_slice(const Dimensions& dims, const ParsedNumericRange& range, NdSlice& out,
  VariantResult& error, Operation operation)
{
  const size_t ndims = dims.size();
  if (range.dimension_count() != ndims)
  {
    // Part 4 7.27: on a read, a valid range that does not fit the value selects no data; a write keeps
    // Bad_IndexRangeInvalid, which Part 4 Table 61 also allows for a range the Server cannot write.
    if (operation == Operation::Read)
    {
      error = make_no_data(ErrorDetail::build("IndexRangeNoData",
        "IndexRange dimension count does not match the array's dimensions",
        std::string{errorSource})
                             .context(ua::ContextKeys::expected, std::to_string(ndims))
                             .context(ua::ContextKeys::actual, std::to_string(range.dimension_count())));
      return false;
    }
    error = make_invalid(ErrorDetail::build("IndexRangeInvalid",
      "IndexRange dimension count does not match the array's dimensions",
      std::string{errorSource})
                           .context(ua::ContextKeys::expected, std::to_string(ndims))
                           .context(ua::ContextKeys::actual, std::to_string(range.dimension_count())));
    return false;
  }
  out.low.resize(ndims);
  out.extent.resize(ndims);
  out.stride.resize(ndims);
  for (size_t k = 0; k < ndims; ++k)
  {
    const auto dimSize = numeric_cast<uint32_t>(dims[k]);
    const auto low = range.dimensions[k].low;
    if (low >= dimSize)
    {
      error = make_no_data(ErrorDetail::build(
        "IndexRangeNoData", "Index range start exceeds dimension size", std::string{errorSource})
                             .context(ua::ContextKeys::index, std::to_string(low))
                             .context(ua::ContextKeys::sizeActual, std::to_string(dimSize))
                             .context(ua::ContextKeys::operationIndex, std::to_string(k)));
      return false;
    }
    const auto high = std::min(range.dimensions[k].high, dimSize - 1);
    if (high < low)
    {
      error = make_no_data(
        ErrorDetail::build("IndexRangeNoData", "Index range start exceeds end", std::string{errorSource})
          .context(ua::ContextKeys::min, std::to_string(low))
          .context(ua::ContextKeys::max, std::to_string(high))
          .context(ua::ContextKeys::operationIndex, std::to_string(k)));
      return false;
    }
    out.low[k] = low;
    out.extent[k] = high - low + 1;
    out.total *= out.extent[k];
  }
  out.stride[ndims - 1] = 1;
  for (size_t k = ndims - 1; k > 0; --k)
  {
    out.stride[k - 1] = out.stride[k] * numeric_cast<size_t>(dims[k]);
  }
  return true;
}

// Advance a row-major coordinate (last dimension fastest). Returns false when it wraps past the end.
bool advance_coord(std::vector<uint32_t>& coord, const std::vector<uint32_t>& extent)
{
  for (size_t k = extent.size(); k-- > 0;)
  {
    if (++coord[k] < extent[k])
      return true;
    coord[k] = 0;
  }
  return false;
}

// Copy one array element by value, deep-cloning when it owns a polymorphic Structure
// (ExtensionObject) so a slice never aliases the source payload. Returning by value also keeps the
// std::vector<bool> proxy-reference happy on assignment.
template<typename T>
T copy_element(const T& element)
{
  return element;
}

template<>
RefStructure<Structure> copy_element<RefStructure<Structure>>(const RefStructure<Structure>& element)
{
  return element.get() ? RefStructure<Structure>{element.get()->clone()} : RefStructure<Structure>{};
}

template<typename T>
VariantResult slice_array_nd(const Variant& source, const Dimensions& dims, const NdSlice& slice)
{
  const auto& payload = source.as<Array<T>>().payload();
  const size_t ndims = dims.size();

  Array<T> result;
  std::vector<uint32_t> coord(ndims, 0);
  for (size_t n = 0; n < slice.total; ++n)
  {
    size_t sourceIndex = 0;
    for (size_t k = 0; k < ndims; ++k)
      sourceIndex += static_cast<size_t>(slice.low[k] + coord[k]) * slice.stride[k];
    if (sourceIndex >= payload.size())
      return make_no_data(ErrorDetail::build(
        "IndexRangeNoData", "Index range exceeds the flattened array payload", std::string{errorSource})
                            .context(ua::ContextKeys::index, std::to_string(sourceIndex))
                            .context(ua::ContextKeys::sizeActual, std::to_string(payload.size())));
    result.push_back(copy_element<T>(payload[sourceIndex]));
    advance_coord(coord, slice.extent);
  }

  Dimensions resultDims;
  for (auto extent : slice.extent)
    resultDims.push_back(numeric_cast<int32_t>(extent));
  result.dimensions() = std::move(resultDims);
  return Variant{std::move(result)};
}

template<typename T>
VariantResult write_array_nd(
  const Variant& existing, const Variant& partial, const Dimensions& dims, const NdSlice& slice)
{
  const auto& existingArr = existing.as<Array<T>>();
  const auto& partialArr = partial.as<Array<T>>();
  if (partialArr.size() != slice.total)
  {
    return make_invalid(ErrorDetail::build("IndexRangeInvalid",
      "Partial array size does not match the index range extent",
      std::string{errorSource})
                          .context(ua::ContextKeys::sizeExpected, std::to_string(slice.total))
                          .context(ua::ContextKeys::sizeActual, std::to_string(partialArr.size())));
  }

  Array<T> result{existingArr};
  const auto& partialPayload = partialArr.payload();
  const size_t ndims = dims.size();
  std::vector<uint32_t> coord(ndims, 0);
  for (size_t n = 0; n < slice.total; ++n)
  {
    size_t destIndex = 0;
    for (size_t k = 0; k < ndims; ++k)
      destIndex += static_cast<size_t>(slice.low[k] + coord[k]) * slice.stride[k];
    if (destIndex >= result.size())
      return make_no_data(ErrorDetail::build(
        "IndexRangeNoData", "Index range exceeds the flattened array payload", std::string{errorSource})
                            .context(ua::ContextKeys::index, std::to_string(destIndex))
                            .context(ua::ContextKeys::sizeActual, std::to_string(result.size())));
    result[destIndex] = copy_element<T>(partialPayload[n]);
    advance_coord(coord, slice.extent);
  }
  result.dimensions() = existingArr.dimensions();
  return Variant{std::move(result)};
}

VariantResult dispatch_array_read_nd(const Variant& source, const Dimensions& dims, const NdSlice& slice)
{
  return dispatch_by_type(
    source.get_built_in_type(), [&]<typename T>() { return slice_array_nd<T>(source, dims, slice); });
}

VariantResult dispatch_array_write_nd(
  const Variant& existing, const Variant& partial, const Dimensions& dims, const NdSlice& slice)
{
  return dispatch_by_type(existing.get_built_in_type(),
    [&]<typename T>() { return write_array_nd<T>(existing, partial, dims, slice); });
}

}  // namespace

VariantResult apply_read(const Variant& source, const ParsedNumericRange& range)
{
  if (range.empty())
  {
    return source;
  }

  if (source.empty())
  {
    return make_no_data("Cannot apply IndexRange to empty Variant");
  }

  const size_t dimCount = range.dimension_count();

  if (source.is_array())
  {
    // A genuine multi-dimensional array (ArrayDimensions present, rank >= 2) is sliced as an N-D
    // block. This is distinct from the dimCount==2 char-range path below, which slices the characters
    // of a 1-D array of String/ByteString.
    const auto& arrayDims = source.get_array_base().dimensions();
    if (arrayDims.has_value() && arrayDims->size() >= 2)
    {
      NdSlice slice;
      VariantResult error = make_no_data("uninitialised");
      if (!compute_nd_slice(*arrayDims, range, slice, error, Operation::Read))
        return error;
      return dispatch_array_read_nd(source, *arrayDims, slice);
    }

    if (dimCount == 1)
    {
      return dispatch_array_read_1d(source, range.dimensions[0]);
    }

    if (dimCount == 2)
    {
      auto builtIn = source.get_built_in_type();
      if (builtIn == BuiltInTypeId::String)
      {
        return read_string_array_2d(source, range.dimensions[0], range.dimensions[1]);
      }
      if (builtIn == BuiltInTypeId::ByteString)
      {
        return read_byte_string_array_2d(source, range.dimensions[0], range.dimensions[1]);
      }
      return make_no_data("2D IndexRange only supported for String and ByteString arrays");
    }

    return make_no_data("IndexRange with more than 2 dimensions is not supported");
  }

  // Scalar
  if (dimCount == 1)
  {
    auto builtIn = source.get_built_in_type();
    if (builtIn == BuiltInTypeId::String)
    {
      return read_scalar_string(source, range.dimensions[0]);
    }
    if (builtIn == BuiltInTypeId::ByteString)
    {
      return read_scalar_byte_string(source, range.dimensions[0]);
    }
    return make_no_data("IndexRange not applicable to this scalar type");
  }

  if (dimCount >= 2)
  {
    return make_no_data("Multi-dimensional IndexRange not supported for scalar values");
  }

  return make_no_data("Invalid IndexRange dimension count");
}

VariantResult apply_write(const Variant& existing, const Variant& partial, const ParsedNumericRange& range)
{
  if (range.empty())
  {
    return partial;
  }

  if (existing.empty())
  {
    return make_no_data("Cannot apply IndexRange write to empty existing Variant");
  }

  const size_t dimCount = range.dimension_count();

  if (existing.is_array())
  {
    if (!partial.is_array())
    {
      return make_type_mismatch("Partial value must be an array when existing value is an array");
    }

    // True multi-dimensional array: overwrite an N-D sub-block (see the read path for the contrast
    // with the String/ByteString char-range case).
    const auto& arrayDims = existing.get_array_base().dimensions();
    if (arrayDims.has_value() && arrayDims->size() >= 2)
    {
      if (!types_match(existing, partial))
      {
        return make_type_mismatch("Existing and partial variant types do not match for write");
      }
      NdSlice slice;
      VariantResult error = make_no_data("uninitialised");
      if (!compute_nd_slice(*arrayDims, range, slice, error, Operation::Write))
        return error;
      return dispatch_array_write_nd(existing, partial, *arrayDims, slice);
    }

    if (dimCount == 1)
    {
      return dispatch_array_write_1d(existing, partial, range.dimensions[0]);
    }

    if (dimCount == 2)
    {
      if (!types_match(existing, partial))
      {
        return make_type_mismatch("Existing and partial variant types do not match for write");
      }

      auto builtIn = existing.get_built_in_type();
      if (builtIn == BuiltInTypeId::String)
      {
        return write_string_array_2d(existing, partial, range.dimensions[0], range.dimensions[1]);
      }
      if (builtIn == BuiltInTypeId::ByteString)
      {
        return write_byte_string_array_2d(existing, partial, range.dimensions[0], range.dimensions[1]);
      }
      return make_no_data("2D IndexRange write only supported for String and ByteString arrays");
    }

    return make_no_data("IndexRange with more than 2 dimensions is not supported for write");
  }

  // Scalar write
  if (dimCount == 1)
  {
    auto builtIn = existing.get_built_in_type();
    if (builtIn == BuiltInTypeId::String)
    {
      if (!partial.is_scalar() || partial.get_built_in_type() != BuiltInTypeId::String)
      {
        return make_type_mismatch("Partial value must be a scalar String for String write");
      }
      return write_scalar_string(existing, partial, range.dimensions[0]);
    }
    if (builtIn == BuiltInTypeId::ByteString)
    {
      if (!partial.is_scalar() || partial.get_built_in_type() != BuiltInTypeId::ByteString)
      {
        return make_type_mismatch("Partial value must be a scalar ByteString for ByteString write");
      }
      return write_scalar_byte_string(existing, partial, range.dimensions[0]);
    }
    return make_no_data("IndexRange write not applicable to this scalar type");
  }

  if (dimCount >= 2)
  {
    return make_no_data("Multi-dimensional IndexRange not supported for scalar write");
  }

  return make_no_data("Invalid IndexRange dimension count for write");
}

void apply_to_value(DataValue& value, const NumericRange& range)
{
  if (range.empty())
  {
    return;
  }
  const auto& status = value.status();
  if (status && status->is_bad())
  {
    return;
  }
  auto parsed = parse_numeric_range(range);
  if (!parsed.is_good())
  {
    value.status() = parsed.status_code();
    value.value() = Variant{};
    return;
  }
  if (parsed.value().empty())
  {
    return;
  }
  auto sliced = apply_read(value.value(), parsed.value());
  if (!sliced.is_good())
  {
    value.status() = sliced.status_code();
    value.value() = Variant{};
    return;
  }
  value.value() = std::move(sliced).value();
}

}  // namespace index_range_utils
}  // namespace ua
