// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SERVER_STATE_H
#define UA_DATA_TYPE_SERVER_STATE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA ServerState enumeration data type.
/// @ingroup ua_data_types
enum class ServerState : int32_t
{
  Running = 0,
  Failed = 1,
  NoConfiguration = 2,
  Suspended = 3,
  Shutdown = 4,
  Test = 5,
  CommunicationFault = 6,
  Unknown = 7
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(ServerState value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of ServerState.
bool is_valid(ServerState value);

}  // namespace ua

/// The OPC UA DataType of the ServerState enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::ServerState>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::ServerState};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_SERVER_STATE_H
