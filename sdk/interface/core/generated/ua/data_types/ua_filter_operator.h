// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_FILTER_OPERATOR_H
#define UA_DATA_TYPE_FILTER_OPERATOR_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA FilterOperator enumeration data type.
/// @ingroup ua_data_types
enum class FilterOperator : int32_t
{
  Equals = 0,
  IsNull = 1,
  GreaterThan = 2,
  LessThan = 3,
  GreaterThanOrEqual = 4,
  LessThanOrEqual = 5,
  Like = 6,
  Not = 7,
  Between = 8,
  InList = 9,
  And = 10,
  Or = 11,
  Cast = 12,
  InView = 13,
  OfType = 14,
  RelatedTo = 15,
  BitwiseAnd = 16,
  BitwiseOr = 17
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(FilterOperator value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of FilterOperator.
bool is_valid(FilterOperator value);

}  // namespace ua

/// The OPC UA DataType of the FilterOperator enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::FilterOperator>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::FilterOperator};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_FILTER_OPERATOR_H
