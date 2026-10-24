// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_NODE_CLASS_H
#define UA_DATA_TYPE_NODE_CLASS_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA NodeClass enumeration data type.
/// @ingroup ua_data_types
enum class NodeClass : int32_t
{
  Unspecified = 0,  ///< No value is specified.
  Object = 1,  ///< The Node is an Object.
  Variable = 2,  ///< The Node is a Variable.
  Method = 4,  ///< The Node is a Method.
  ObjectType = 8,  ///< The Node is an ObjectType.
  VariableType = 16,  ///< The Node is a VariableType.
  ReferenceType = 32,  ///< The Node is a ReferenceType.
  DataType = 64,  ///< The Node is a DataType.
  View = 128,  ///< The Node is a View.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(NodeClass value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of NodeClass.
bool is_valid(NodeClass value);

}  // namespace ua

/// The OPC UA DataType of the NodeClass enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::NodeClass>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::NodeClass};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_NODE_CLASS_H
