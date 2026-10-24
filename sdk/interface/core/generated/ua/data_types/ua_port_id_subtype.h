// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_PORT_ID_SUBTYPE_H
#define UA_DATA_TYPE_PORT_ID_SUBTYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA PortIdSubtype enumeration data type.
/// @ingroup ua_data_types
enum class PortIdSubtype : int32_t
{
  InterfaceAlias =
    1,  ///< Represents a port identifier based on the ifAlias MIB object defined in IETF RFC 2863.
  PortComponent = 2,  ///< Represents a port identifier based on the value of entPhysicalAlias (defined in
                      ///< IETF RFC 2737) for a port component (i.e., entPhysicalClass value of port(10) or
                      ///< backplane(4)), within the containing chassis.
  MacAddress = 3,  ///< Represents a port identifier based on a unicast source address (encoded in network
                   ///< byte order and IEEE 802.3 canonical bit order) which has been detected by the agent
                   ///< and associated with a particular port (IEEE Std 802-2014).
  NetworkAddress = 4,  ///< Represents a port identifier based on a network address, detected by the agent and
                       ///< associated with a particular port.
  InterfaceName =
    5,  ///< Represents a port identifier based on the ifName MIB object, defined in IETF RFC 2863.
  AgentCircuitId =
    6,  ///< Represents a port identifier based on the agent-local identifier of the circuit (defined in IETF
        ///< RFC 3046), detected by the agent and associated with a particular port.
  Local = 7,  ///< Represents a port identifier based on a value locally assigned.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(PortIdSubtype value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of PortIdSubtype.
bool is_valid(PortIdSubtype value);

}  // namespace ua

/// The OPC UA DataType of the PortIdSubtype enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::PortIdSubtype>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::PortIdSubtype};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_PORT_ID_SUBTYPE_H
