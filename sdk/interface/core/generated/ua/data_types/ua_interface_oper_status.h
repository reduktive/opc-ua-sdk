// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_INTERFACE_OPER_STATUS_H
#define UA_DATA_TYPE_INTERFACE_OPER_STATUS_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA InterfaceOperStatus enumeration data type.
/// @ingroup ua_data_types
enum class InterfaceOperStatus : int32_t
{
  Up = 0,  ///< Ready to pass packets.
  Down = 1,  ///< The interface does not pass any packets.
  Testing = 2,  ///< In some test mode. No operational packets can be passed.
  Unknown = 3,  ///< Status cannot be determined for some reason.
  Dormant = 4,  ///< Waiting for some external event.
  NotPresent = 5,  ///< Some component (typically hardware) is missing.
  LowerLayerDown = 6,  ///< Down due to state of lower-layer interface(s).
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(InterfaceOperStatus value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of InterfaceOperStatus.
bool is_valid(InterfaceOperStatus value);

}  // namespace ua

/// The OPC UA DataType of the InterfaceOperStatus enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::InterfaceOperStatus>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::InterfaceOperStatus};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_INTERFACE_OPER_STATUS_H
