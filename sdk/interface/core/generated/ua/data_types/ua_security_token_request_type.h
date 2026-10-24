// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SECURITY_TOKEN_REQUEST_TYPE_H
#define UA_DATA_TYPE_SECURITY_TOKEN_REQUEST_TYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA SecurityTokenRequestType enumeration data type.
/// @ingroup ua_data_types
enum class SecurityTokenRequestType : int32_t
{
  Issue = 0,
  Renew = 1
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(SecurityTokenRequestType value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of SecurityTokenRequestType.
bool is_valid(SecurityTokenRequestType value);

}  // namespace ua

/// The OPC UA DataType of the SecurityTokenRequestType enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::SecurityTokenRequestType>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::SecurityTokenRequestType};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_SECURITY_TOKEN_REQUEST_TYPE_H
