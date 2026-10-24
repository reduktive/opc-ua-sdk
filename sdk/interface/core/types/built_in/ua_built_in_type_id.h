// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Identifiers for the 25 OPC UA built-in types and the mapping from C++ types to them.
/// @ingroup core_types

#ifndef UA_BUILT_IN_TYPE_ID_H
#define UA_BUILT_IN_TYPE_ID_H

#include "ua_includes.h"

namespace ua
{

/// Numeric identifier of an OPC UA built-in type.
///
/// The enumerator values are the wire encoding IDs defined by OPC 10000-6
/// (the byte stored in a @ref Variant's encoding mask), so the underlying
/// type is `uint8_t` and the values must not be changed. `Null` (0) denotes
/// the absence of a value rather than a built-in type.
/// @ingroup core_types
enum class BuiltInTypeId : uint8_t
{
  Null = 0,  ///< No value present (an empty @ref Variant).
  Boolean = 1,  ///< Two-state logical value.
  SByte = 2,  ///< Signed 8-bit integer.
  Byte = 3,  ///< Unsigned 8-bit integer.
  Int16 = 4,  ///< Signed 16-bit integer.
  UInt16 = 5,  ///< Unsigned 16-bit integer.
  Int32 = 6,  ///< Signed 32-bit integer.
  UInt32 = 7,  ///< Unsigned 32-bit integer.
  Int64 = 8,  ///< Signed 64-bit integer.
  UInt64 = 9,  ///< Unsigned 64-bit integer.
  Float = 10,  ///< IEEE 754 single-precision floating point.
  Double = 11,  ///< IEEE 754 double-precision floating point.
  String = 12,  ///< Unicode string (UTF-8 on the wire).
  DateTime = 13,  ///< UTC instant as 100 ns ticks since 1601-01-01.
  Guid = 14,  ///< 16-byte globally unique identifier.
  ByteString = 15,  ///< Opaque sequence of bytes.
  XmlElement = 16,  ///< Serialised XML element.
  NodeId = 17,  ///< Identifier of a node in the address space.
  ExpandedNodeId = 18,  ///< @ref NodeId extended with namespace URI and server index.
  StatusCode = 19,  ///< 32-bit operation result/status code.
  QualifiedName = 20,  ///< Namespace-qualified name.
  LocalizedText = 21,  ///< Text paired with a locale identifier.
  ExtensionObject = 22,  ///< Encoded structured value (a @ref Structure).
  DataValue = 23,  ///< Value plus status code and timestamps.
  Variant = 24,  ///< A union of any built-in type (possibly an array).
  DiagnosticInfo = 25  ///< Nested diagnostic information for a service result.
};

/// Maps a C++ type to its OPC UA `BuiltInTypeId`.
///
/// The primary template forwards to the type's own `built_in_type_id()`
/// static member; SDK value types (such as `NodeId` or `DataValue`)
/// provide one. Fundamental types, enumerations, `std::string`, and
/// extension objects are covered by the overloads and specialisations below.
///
/// @tparam T C++ type to classify; must expose `static BuiltInTypeId
///           built_in_type_id()` unless matched by a more specific overload.
/// @return The built-in type identifier corresponding to @p T.
template<typename T>
BuiltInTypeId built_in_type()
{
  return T::built_in_type_id();
}

/// Maps any C++ enumeration to `BuiltInTypeId::Int32`.
///
/// OPC UA encodes enumerations as `Int32` on the wire, so every enum type
/// classifies as `BuiltInTypeId::Int32` regardless of its underlying type.
///
/// @tparam T An enumeration type (selected via the `IsEnum` concept constraint).
/// @return Always `BuiltInTypeId::Int32`.
template<typename T>
  requires IsEnum<T>
BuiltInTypeId built_in_type()
{
  return BuiltInTypeId::Int32;
}

/// Maps `bool` to `BuiltInTypeId::Boolean`.
/// @return `BuiltInTypeId::Boolean`.
template<>
inline BuiltInTypeId built_in_type<bool>()
{
  return BuiltInTypeId::Boolean;
}

/// Maps `int8_t` to `BuiltInTypeId::SByte`.
/// @return `BuiltInTypeId::SByte`.
template<>
inline BuiltInTypeId built_in_type<int8_t>()
{
  return BuiltInTypeId::SByte;
}

/// Maps `uint8_t` to `BuiltInTypeId::Byte`.
/// @return `BuiltInTypeId::Byte`.
template<>
inline BuiltInTypeId built_in_type<uint8_t>()
{
  return BuiltInTypeId::Byte;
}

/// Maps `int16_t` to `BuiltInTypeId::Int16`.
/// @return `BuiltInTypeId::Int16`.
template<>
inline BuiltInTypeId built_in_type<int16_t>()
{
  return BuiltInTypeId::Int16;
}

/// Maps `uint16_t` to `BuiltInTypeId::UInt16`.
/// @return `BuiltInTypeId::UInt16`.
template<>
inline BuiltInTypeId built_in_type<uint16_t>()
{
  return BuiltInTypeId::UInt16;
}

/// Maps `int32_t` to `BuiltInTypeId::Int32`.
/// @return `BuiltInTypeId::Int32`.
template<>
inline BuiltInTypeId built_in_type<int32_t>()
{
  return BuiltInTypeId::Int32;
}

/// Maps `uint32_t` to `BuiltInTypeId::UInt32`.
/// @return `BuiltInTypeId::UInt32`.
template<>
inline BuiltInTypeId built_in_type<uint32_t>()
{
  return BuiltInTypeId::UInt32;
}

/// Maps `int64_t` to `BuiltInTypeId::Int64`.
/// @return `BuiltInTypeId::Int64`.
template<>
inline BuiltInTypeId built_in_type<int64_t>()
{
  return BuiltInTypeId::Int64;
}

/// Maps `uint64_t` to `BuiltInTypeId::UInt64`.
/// @return `BuiltInTypeId::UInt64`.
template<>
inline BuiltInTypeId built_in_type<uint64_t>()
{
  return BuiltInTypeId::UInt64;
}

/// Maps `float` to `BuiltInTypeId::Float`.
/// @return `BuiltInTypeId::Float`.
template<>
inline BuiltInTypeId built_in_type<float>()
{
  return BuiltInTypeId::Float;
}

/// Maps `double` to `BuiltInTypeId::Double`.
/// @return `BuiltInTypeId::Double`.
template<>
inline BuiltInTypeId built_in_type<double>()
{
  return BuiltInTypeId::Double;
}

// ByteString is a class declared in ua_byte_string.h; built_in_type<ByteString>()
// is defined there via ByteString::built_in_type_id().

/// Maps `std::string` to `BuiltInTypeId::String`.
/// @return `BuiltInTypeId::String`.
template<>
inline BuiltInTypeId built_in_type<std::string>()
{
  return BuiltInTypeId::String;
}

/// Maps an owned `Structure` to `BuiltInTypeId::ExtensionObject`.
/// @return `BuiltInTypeId::ExtensionObject`.
template<>
inline BuiltInTypeId built_in_type<unique_ptr<Structure>>()
{
  return BuiltInTypeId::ExtensionObject;
}

}  // namespace ua

#endif  //! UA_BUILT_IN_TYPE_ID_H
