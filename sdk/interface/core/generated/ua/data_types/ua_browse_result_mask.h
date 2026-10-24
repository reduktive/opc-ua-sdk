// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_BROWSE_RESULT_MASK_H
#define UA_DATA_TYPE_BROWSE_RESULT_MASK_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA BrowseResultMask enumeration data type.
/// @ingroup ua_data_types
enum class BrowseResultMask : int32_t
{
  None = 0,
  ReferenceTypeId = 1,
  IsForward = 2,
  NodeClass = 4,
  BrowseName = 8,
  DisplayName = 16,
  TypeDefinition = 32,
  All = 63,
  ReferenceTypeInfo = 3,
  TargetInfo = 60
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(BrowseResultMask value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of BrowseResultMask.
bool is_valid(BrowseResultMask value);

}  // namespace ua

/// The OPC UA DataType of the BrowseResultMask enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::BrowseResultMask>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::BrowseResultMask};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_BROWSE_RESULT_MASK_H
