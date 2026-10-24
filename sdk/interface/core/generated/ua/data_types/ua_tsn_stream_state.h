// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_TSN_STREAM_STATE_H
#define UA_DATA_TYPE_TSN_STREAM_STATE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA TsnStreamState enumeration data type.
/// @ingroup ua_data_types
enum class TsnStreamState : int32_t
{
  Disabled = 0,  ///< The related TSN Stream is currently disabled.
  Configuring = 1,  ///< The related TSN Stream is in the process of receiving configuration parameters from
                    ///< the TSN Control Layer.
  Ready = 2,  ///< The related TSN Stream has successfully received and applied the configuration from the TSN
              ///< Control Layer. The related TSN Stream is not fully operational as long as local
              ///< preconditions (e.g. synchronization state) are not valid.
  Operational = 3,  ///< The related TSN Stream object is configured and all other required preconditions
                    ///< (e.g. synchronization state) for sending / receiving data are valid.
  Error = 4,  ///< The related TSN Stream object is in an error state.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(TsnStreamState value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of TsnStreamState.
bool is_valid(TsnStreamState value);

}  // namespace ua

/// The OPC UA DataType of the TsnStreamState enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::TsnStreamState>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::TsnStreamState};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_TSN_STREAM_STATE_H
