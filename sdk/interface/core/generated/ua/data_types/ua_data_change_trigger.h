// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_DATA_CHANGE_TRIGGER_H
#define UA_DATA_TYPE_DATA_CHANGE_TRIGGER_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA DataChangeTrigger enumeration data type.
/// @ingroup ua_data_types
enum class DataChangeTrigger : int32_t
{
  Status = 0,
  StatusValue = 1,
  StatusValueTimestamp = 2
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(DataChangeTrigger value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of DataChangeTrigger.
bool is_valid(DataChangeTrigger value);

}  // namespace ua

/// The OPC UA DataType of the DataChangeTrigger enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::DataChangeTrigger>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::DataChangeTrigger};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_DATA_CHANGE_TRIGGER_H
