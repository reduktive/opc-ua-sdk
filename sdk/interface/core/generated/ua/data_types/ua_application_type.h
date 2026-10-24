// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_APPLICATION_TYPE_H
#define UA_DATA_TYPE_APPLICATION_TYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA ApplicationType enumeration data type.
/// @ingroup ua_data_types
enum class ApplicationType : int32_t
{
  Server = 0,
  Client = 1,
  ClientAndServer = 2,
  DiscoveryServer = 3
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(ApplicationType value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of ApplicationType.
bool is_valid(ApplicationType value);

}  // namespace ua

/// The OPC UA DataType of the ApplicationType enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::ApplicationType>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::ApplicationType};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_APPLICATION_TYPE_H
