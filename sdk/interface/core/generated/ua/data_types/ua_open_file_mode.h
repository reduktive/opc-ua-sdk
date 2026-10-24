// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_OPEN_FILE_MODE_H
#define UA_DATA_TYPE_OPEN_FILE_MODE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA OpenFileMode enumeration data type.
/// @ingroup ua_data_types
enum class OpenFileMode : int32_t
{
  Read = 1,
  Write = 2,
  EraseExisting = 4,
  Append = 8
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(OpenFileMode value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of OpenFileMode.
bool is_valid(OpenFileMode value);

}  // namespace ua

/// The OPC UA DataType of the OpenFileMode enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::OpenFileMode>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::OpenFileMode};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_OPEN_FILE_MODE_H
