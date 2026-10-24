// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_MAN_ADDR_IF_SUBTYPE_H
#define UA_DATA_TYPE_MAN_ADDR_IF_SUBTYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA ManAddrIfSubtype enumeration data type.
/// @ingroup ua_data_types
enum class ManAddrIfSubtype : int32_t
{
  None = 0,  ///< Optional variable is not set.
  Unknown = 1,  ///< Interface is not known.
  PortRef = 2,  ///< Interface based on the port-ref MIB object.
  SystemPortNumber = 3,  ///< Interface based on the system port number.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(ManAddrIfSubtype value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of ManAddrIfSubtype.
bool is_valid(ManAddrIfSubtype value);

}  // namespace ua

/// The OPC UA DataType of the ManAddrIfSubtype enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::ManAddrIfSubtype>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::ManAddrIfSubtype};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_MAN_ADDR_IF_SUBTYPE_H
