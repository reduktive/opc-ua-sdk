// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_CHASSIS_ID_SUBTYPE_H
#define UA_DATA_TYPE_CHASSIS_ID_SUBTYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA ChassisIdSubtype enumeration data type.
/// @ingroup ua_data_types
enum class ChassisIdSubtype : int32_t
{
  ChassisComponent =
    1,  ///< Represents a chassis identifier based on the value of entPhysicalAlias object (defined in IETF
        ///< RFC 2737) for a chassis component (i.e., an entPhysicalClass value of chassis(3)).
  InterfaceAlias = 2,  ///< Represents a chassis identifier based on the value of ifAlias object (defined in
                       ///< IETF RFC 2863) for an interface on the containing chassis.
  PortComponent =
    3,  ///< Represents a chassis identifier based on the value of entPhysicalAlias object (defined in IETF
        ///< RFC 2737) for a port or backplane component (i.e., entPhysicalClass has a value of port(10), or
        ///< backplane(4)), within the containing chassis.
  MacAddress = 4,  ///< Represents a chassis identifier based on the value of a unicast source address
                   ///< (encoded in network byte order and IEEE 802.3 canonical bit order) of a port on the
                   ///< containing chassis as defined in IEEE Std 802-2014.
  NetworkAddress = 5,  ///< Represents a chassis identifier based on a network address associated with a
                       ///< particular chassis. The encoded address is actually composed of two fields. The
                       ///< first field is a single octet, representing the IANA AddressFamilyNumbers value
                       ///< for the specific address type, and the second field is the network address value.
  InterfaceName = 6,  ///< Represents a chassis identifier based on the value of ifName object (defined in
                      ///< IETF RFC 2863) for an interface on the containing chassis.
  Local = 7,  ///< Represents a chassis identifier based on a locally defined value.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(ChassisIdSubtype value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of ChassisIdSubtype.
bool is_valid(ChassisIdSubtype value);

}  // namespace ua

/// The OPC UA DataType of the ChassisIdSubtype enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::ChassisIdSubtype>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::ChassisIdSubtype};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_CHASSIS_ID_SUBTYPE_H
