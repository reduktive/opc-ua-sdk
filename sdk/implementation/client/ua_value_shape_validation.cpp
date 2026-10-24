// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_value_shape_validation.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <cstddef>
#include <string>

namespace ua::client::detail
{

namespace
{

ua::VoidResult rank_mismatch(const ua::NodeId& node, std::int32_t expectedRank, std::int32_t actualRank)
{
  return ua::VoidResult{ua::Status::BadTypeMismatch,
    ua::ErrorDetail::build("VariableValueRankMismatch",
      "the outgoing value rank is incompatible with the Variable ValueRank",
      "client.tier2.typed_access.write_shape")
      .context(ua::ContextKeys::nodeId, ua::to_string(node))
      .context(ua::ContextKeys::expected, expectedRank)
      .context(ua::ContextKeys::actual, actualRank)};
}

ua::VoidResult malformed_metadata(const ua::NodeId& node, std::int32_t valueRank, std::size_t dimensionCount)
{
  return ua::VoidResult{ua::Status::BadUnexpectedError,
    ua::ErrorDetail::build("VariableShapeMetadataInvalid",
      "the Variable ValueRank and ArrayDimensions attributes are inconsistent",
      "client.tier2.typed_access.write_shape")
      .context(ua::ContextKeys::nodeId, ua::to_string(node))
      .context(ua::ContextKeys::actual, valueRank)
      .context(ua::ContextKeys::countTotal, dimensionCount)};
}

}  // namespace

ua::VoidResult validate_variable_write_shape(
  const ua::NodeId& node, const ua::Variant& value, const VariableShape& shape)
{
  // A null Variant carries no rank. Whether null is writable is controlled by the Variable's AllowNulls
  // Property/server semantics, so shape validation must not invent a rejection.
  if (value.empty())
  {
    return ua::VoidResult{};
  }

  const bool isArray = value.is_array();
  const auto* byteString = value.try_as<ua::ByteString>();
  const bool isByteArray = isArray && value.get_built_in_type() == ua::BuiltInTypeId::Byte;
  // Part 6 encodes ByteString and Byte[] as interchangeable byte sequences. Shape validation must not
  // reject either representation before the existing DataType-aware server check sees it.
  const bool byteStringAsArray = byteString && shape.valueRank == 1;
  const bool byteArrayAsScalar = isByteArray && shape.valueRank == -1;
  const std::int32_t actualRank =
    byteStringAsArray ? 1 : (byteArrayAsScalar ? -1 : (isArray ? value.get_array_base().value_rank() : -1));

  bool rankAccepted = false;
  switch (shape.valueRank)
  {
  case -3:  // ScalarOrOneDimension
    rankAccepted = actualRank == -1 || actualRank == 1;
    break;
  case -2:  // Any
    rankAccepted = true;
    break;
  case -1:  // Scalar
    rankAccepted = actualRank == -1;
    break;
  case 0:  // OneOrMoreDimensions
    rankAccepted = actualRank >= 1;
    break;
  default:
    if (shape.valueRank < -3)
    {
      const std::size_t dimensionCount =
        shape.arrayDimensions ? shape.arrayDimensions->size() : std::size_t{0};
      return malformed_metadata(node, shape.valueRank, dimensionCount);
    }
    rankAccepted = actualRank == shape.valueRank;
    break;
  }

  if (!rankAccepted)
  {
    return rank_mismatch(node, shape.valueRank, actualRank);
  }

  if (!shape.arrayDimensions || shape.arrayDimensions->empty())
  {
    return ua::VoidResult{};
  }
  if ((!isArray && !byteStringAsArray) ||
      shape.arrayDimensions->size() != static_cast<std::size_t>(actualRank))
  {
    return malformed_metadata(node, shape.valueRank, shape.arrayDimensions->size());
  }

  std::vector<std::uint32_t> actualDimensions;
  if (byteStringAsArray)
  {
    actualDimensions.push_back(static_cast<std::uint32_t>(byteString->size()));
  }
  else
  {
    const auto& array = value.get_array_base();
    const auto& arrayDimensions = array.dimensions();
    if (arrayDimensions && !arrayDimensions.value().empty())
    {
      actualDimensions.reserve(arrayDimensions.value().size());
      for (const auto dimension : arrayDimensions.value())
      {
        actualDimensions.push_back(static_cast<std::uint32_t>(dimension));
      }
    }
    else
    {
      actualDimensions.push_back(static_cast<std::uint32_t>(array.size()));
    }
  }

  for (std::size_t index = 0; index < shape.arrayDimensions->size(); ++index)
  {
    const std::uint32_t maximum = (*shape.arrayDimensions)[index];
    if (maximum != 0 && actualDimensions[index] > maximum)
    {
      return ua::VoidResult{ua::Status::BadOutOfRange,
        ua::ErrorDetail::build("VariableArrayDimensionExceeded",
          "an outgoing array dimension exceeds the Variable ArrayDimensions maximum",
          "client.tier2.typed_access.write_shape")
          .context(ua::ContextKeys::nodeId, ua::to_string(node))
          .context(ua::ContextKeys::index, index)
          .context(ua::ContextKeys::sizeActual, actualDimensions[index])
          .context(ua::ContextKeys::sizeMax, maximum)};
    }
  }

  return ua::VoidResult{};
}

}  // namespace ua::client::detail
