// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_STRUCTURE_TYPE_H
#define UA_DATA_TYPE_STRUCTURE_TYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA StructureType enumeration data type.
/// @ingroup ua_data_types
enum class StructureType : int32_t
{
  Structure = 0,
  StructureWithOptionalFields = 1,
  Union = 2,
  StructureWithSubtypedValues = 3,
  UnionWithSubtypedValues = 4
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(StructureType value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of StructureType.
bool is_valid(StructureType value);

}  // namespace ua

/// The OPC UA DataType of the StructureType enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::StructureType>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::StructureType};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_STRUCTURE_TYPE_H
