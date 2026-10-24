// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_NEGOTIATION_STATUS_H
#define UA_DATA_TYPE_NEGOTIATION_STATUS_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA NegotiationStatus enumeration data type.
/// @ingroup ua_data_types
enum class NegotiationStatus : int32_t
{
  InProgress = 0,  ///< The auto-negotiation protocol is running and negotiation is currently in-progress.
  Complete = 1,  ///< The auto-negotiation protocol has completed successfully.
  Failed = 2,  ///< The auto-negotiation protocol has failed.
  Unknown = 3,  ///< The auto-negotiation status is not currently known, this could be because it is still
                ///< negotiating or the protocol cannot run (e.g., if no medium is present).
  NoNegotiation = 4,  ///< No auto-negotiation is executed. The auto-negotiation function is either not
                      ///< supported on this interface or has not been enabled.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(NegotiationStatus value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of NegotiationStatus.
bool is_valid(NegotiationStatus value);

}  // namespace ua

/// The OPC UA DataType of the NegotiationStatus enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::NegotiationStatus>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::NegotiationStatus};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_NEGOTIATION_STATUS_H
