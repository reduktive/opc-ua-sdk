// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_INTERFACE_ADMIN_STATUS_H
#define UA_DATA_TYPE_INTERFACE_ADMIN_STATUS_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA InterfaceAdminStatus enumeration data type.
/// @ingroup ua_data_types
enum class InterfaceAdminStatus : int32_t
{
  Up = 0,  ///< Ready to pass packets.
  Down = 1,  ///< Not ready to pass packets and not in some test mode.
  Testing = 2,  ///< In some test mode.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(InterfaceAdminStatus value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of InterfaceAdminStatus.
bool is_valid(InterfaceAdminStatus value);

}  // namespace ua

/// The OPC UA DataType of the InterfaceAdminStatus enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::InterfaceAdminStatus>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::InterfaceAdminStatus};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_INTERFACE_ADMIN_STATUS_H
