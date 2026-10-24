// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_NAMING_RULE_TYPE_H
#define UA_DATA_TYPE_NAMING_RULE_TYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA NamingRuleType enumeration data type.
/// @ingroup ua_data_types
enum class NamingRuleType : int32_t
{
  Mandatory = 1,  ///< The BrowseName must appear in all instances of the type.
  Optional = 2,  ///< The BrowseName may appear in an instance of the type.
  Constraint = 3,  ///< The modelling rule defines a constraint and the BrowseName is not used in an instance
                   ///< of the type.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(NamingRuleType value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of NamingRuleType.
bool is_valid(NamingRuleType value);

}  // namespace ua

/// The OPC UA DataType of the NamingRuleType enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::NamingRuleType>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::NamingRuleType};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_NAMING_RULE_TYPE_H
