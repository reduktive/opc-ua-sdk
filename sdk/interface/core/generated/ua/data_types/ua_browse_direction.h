// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_BROWSE_DIRECTION_H
#define UA_DATA_TYPE_BROWSE_DIRECTION_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA BrowseDirection enumeration data type.
/// @ingroup ua_data_types
enum class BrowseDirection : int32_t
{
  Forward = 0,
  Inverse = 1,
  Both = 2,
  Invalid = 3
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(BrowseDirection value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of BrowseDirection.
bool is_valid(BrowseDirection value);

}  // namespace ua

/// The OPC UA DataType of the BrowseDirection enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::BrowseDirection>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::BrowseDirection};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_BROWSE_DIRECTION_H
