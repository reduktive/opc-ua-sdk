// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_CONFIGURATION_UPDATE_TYPE_H
#define UA_DATA_TYPE_CONFIGURATION_UPDATE_TYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA ConfigurationUpdateType enumeration data type.
/// @ingroup ua_data_types
enum class ConfigurationUpdateType : int32_t
{
  Insert = 1,  ///< The target is added. An error occurs if a name conflict occurs.
  Replace =
    2,  ///< Existing records are updated. An error occurs if a name cannot be matched to an existing record.
  InsertOrReplace =
    3,  ///< Existing records are updated. New records are created if no match to an exising record.
  Delete =
    4,  ///< Existing records are deleted. An error occurs if a name cannot be matched to an existing record.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(ConfigurationUpdateType value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of ConfigurationUpdateType.
bool is_valid(ConfigurationUpdateType value);

}  // namespace ua

/// The OPC UA DataType of the ConfigurationUpdateType enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::ConfigurationUpdateType>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::ConfigurationUpdateType};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_CONFIGURATION_UPDATE_TYPE_H
