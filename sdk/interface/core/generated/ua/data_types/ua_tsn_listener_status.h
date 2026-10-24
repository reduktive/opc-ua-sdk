// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_TSN_LISTENER_STATUS_H
#define UA_DATA_TYPE_TSN_LISTENER_STATUS_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA TsnListenerStatus enumeration data type.
/// @ingroup ua_data_types
enum class TsnListenerStatus : int32_t
{
  None = 0,  ///< No Listener detected.
  Ready = 1,  ///< Listener ready (configured).
  PartialFailed = 2,  ///< One or more Listeners ready, and one or more Listeners failed.
  Failed = 3,  ///< Listener failed.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(TsnListenerStatus value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of TsnListenerStatus.
bool is_valid(TsnListenerStatus value);

}  // namespace ua

/// The OPC UA DataType of the TsnListenerStatus enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::TsnListenerStatus>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::TsnListenerStatus};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_TSN_LISTENER_STATUS_H
