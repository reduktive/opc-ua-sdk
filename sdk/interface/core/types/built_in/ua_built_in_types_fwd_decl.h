// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Forward declarations and result-type aliases for the built-in OPC UA types.
/// @ingroup core_types

#ifndef UA_BUILT_IN_TYPES_FWD_DECL_H
#define UA_BUILT_IN_TYPES_FWD_DECL_H

#include "ua_includes.h"
#include "ua_datatype_id.h"
#include "ua_built_in_type_id.h"

#include <vector>

namespace ua
{

template<typename T>
class Result;

/// Result alias carrying a `bool` payload or an @ref ErrorDetail on failure.
using BoolResult = Result<bool>;
/// Result alias carrying a `uint8_t` payload or an @ref ErrorDetail on failure.
using UInt8Result = Result<uint8_t>;
/// Result alias carrying a `uint16_t` payload or an @ref ErrorDetail on failure.
using UInt16Result = Result<uint16_t>;
/// Result alias carrying a `uint32_t` payload or an @ref ErrorDetail on failure.
using UInt32Result = Result<uint32_t>;
/// Result alias carrying a `uint64_t` payload or an @ref ErrorDetail on failure.
using UInt64Result = Result<uint64_t>;
/// Result alias carrying an `int8_t` payload or an @ref ErrorDetail on failure.
using Int8Result = Result<int8_t>;
/// Result alias carrying an `int16_t` payload or an @ref ErrorDetail on failure.
using Int16Result = Result<int16_t>;
/// Result alias carrying an `int32_t` payload or an @ref ErrorDetail on failure.
using Int32Result = Result<int32_t>;
/// Result alias carrying an `int64_t` payload or an @ref ErrorDetail on failure.
using Int64Result = Result<int64_t>;
/// Result alias carrying a plain `int` payload or an @ref ErrorDetail on failure.
using IntResult = Result<int>;
/// Result alias carrying a `float` payload or an @ref ErrorDetail on failure.
using FloatResult = Result<float>;
/// Result alias carrying a `double` payload or an @ref ErrorDetail on failure.
using DoubleResult = Result<double>;

class ByteString;
/// Result alias carrying a @ref ByteString payload or an @ref ErrorDetail on failure.
using ByteStringResult = Result<ByteString>;

class XmlElement;
class String;
/// Result alias carrying a @ref String payload or an @ref ErrorDetail on failure.
using StringResult = Result<String>;

class DateTime;
/// Result alias carrying a @ref DateTime payload or an @ref ErrorDetail on failure.
using DateTimeResult = Result<DateTime>;

class Guid;
/// Result alias carrying a @ref Guid payload or an @ref ErrorDetail on failure.
using GuidResult = Result<Guid>;
class NodeId;
/// Result alias carrying a @ref NodeId payload or an @ref ErrorDetail on failure.
using NodeIdResult = Result<NodeId>;

class ExpandedNodeId;
/// Result alias carrying an @ref ExpandedNodeId payload or an @ref ErrorDetail on failure.
using ExpandedNodeIdResult = Result<ExpandedNodeId>;
class StatusCode;
class QualifiedName;
/// Result alias carrying a @ref QualifiedName payload or an @ref ErrorDetail on failure.
using QualifiedNameResult = Result<QualifiedName>;

class LocalizedText;
/// Result alias carrying a @ref LocalizedText payload or an @ref ErrorDetail on failure.
using LocalizedTextResult = Result<LocalizedText>;

class Structure;
class DataValue;
/// Result alias carrying a `DataValue` payload or an `ErrorDetail` on failure.
using DataValueResult = Result<DataValue>;

class CallMethodResult;
/// Result alias carrying a @ref CallMethodResult payload or an @ref ErrorDetail on failure.
using CallResult = Result<CallMethodResult>;

class DiagnosticInfo;
class Decimal;
class Variant;
/// Result alias carrying a @ref Variant payload or an @ref ErrorDetail on failure.
using VariantResult = Result<Variant>;

class ArrayBase;

template<typename T>
class Array;

/// Returns the OPC UA wire type name for @p T (e.g. "Int32", "Double").
///
/// Resolves through the `Tag` dispatch helper: built-in arithmetic types are
/// answered by the explicit specialisations below, while user and generated
/// types are answered by an ADL-found `type_name(Tag<T>)` overload.
///
/// @tparam T Type whose OPC UA type name is requested.
/// @return The type name as a non-owning view into a string with static storage
///         duration.
/// @throws UaException with `Status::BadNotSupported` if @p T has no
///         registered type name.
/// @see type_name, Tag
template<typename T>
std::string_view get_typename();

/// Empty tag type used to dispatch @ref type_name overloads on @p T.
///
/// Carries no state; it exists only to select the right `type_name` overload by
/// ADL without requiring the caller to name @p T explicitly.
///
/// @tparam T Type the tag stands in for.
template<typename T>
struct Tag
{};

/// Default `Tag` dispatch overload that rejects unregistered types.
///
/// Selected when no more specific `type_name(Tag<T>)` overload is visible for
/// @p T, signalling that @p T has no OPC UA wire type name.
///
/// @tparam T Type carried by the tag.
/// @return Never returns normally.
/// @throws UaException with `Status::BadNotSupported` always.
/// @see get_typename
template<typename T>
std::string_view type_name(Tag<T>)
{
  throw UaException{Status::BadNotSupported, std::unique_ptr<ErrorDetail>{}};
}

template<typename T>
class RefStructure;

/// `Tag` dispatch overload that unwraps a `RefStructure` to its element type.
///
/// Forwards to the type name of @p T so a `RefStructure<T>` reports the same OPC
/// UA type name as the structure it references.
///
/// @tparam T Element type referenced by the `RefStructure`.
/// @return The OPC UA type name of @p T.
/// @see get_typename
template<typename T>
std::string_view type_name(Tag<RefStructure<T>>)
{
  return get_typename<T>();
}

template<typename T>
std::string_view get_typename()
{
  return type_name(Tag<T>{});
}

/// Maps `bool` to the OPC UA type name "Boolean".
/// @return The literal `"Boolean"`.
template<>
inline string_view get_typename<bool>()
{
  return "Boolean";
}

/// Maps `int8_t` to the OPC UA type name "SByte".
/// @return The literal `"SByte"`.
template<>
inline string_view get_typename<int8_t>()
{
  return "SByte";
}

/// Maps `uint8_t` to the OPC UA type name "Byte".
/// @return The literal `"Byte"`.
template<>
inline string_view get_typename<uint8_t>()
{
  return "Byte";
}

/// Maps `int16_t` to the OPC UA type name "Int16".
/// @return The literal `"Int16"`.
template<>
inline string_view get_typename<int16_t>()
{
  return "Int16";
}

/// Maps `uint16_t` to the OPC UA type name "UInt16".
/// @return The literal `"UInt16"`.
template<>
inline string_view get_typename<uint16_t>()
{
  return "UInt16";
}

/// Maps `int32_t` to the OPC UA type name "Int32".
/// @return The literal `"Int32"`.
template<>
inline string_view get_typename<int32_t>()
{
  return "Int32";
}

/// Maps `uint32_t` to the OPC UA type name "UInt32".
/// @return The literal `"UInt32"`.
template<>
inline string_view get_typename<uint32_t>()
{
  return "UInt32";
}

/// Maps `int64_t` to the OPC UA type name "Int64".
/// @return The literal `"Int64"`.
template<>
inline string_view get_typename<int64_t>()
{
  return "Int64";
}

/// Maps `uint64_t` to the OPC UA type name "UInt64".
/// @return The literal `"UInt64"`.
template<>
inline string_view get_typename<uint64_t>()
{
  return "UInt64";
}

/// Maps `double` to the OPC UA type name "Double".
/// @return The literal `"Double"`.
template<>
inline string_view get_typename<double>()
{
  return "Double";
}

/// Maps `float` to the OPC UA type name "Float".
/// @return The literal `"Float"`.
template<>
inline string_view get_typename<float>()
{
  return "Float";
}

// template<typename T> using OneToMany = std::variant<T, UniquePtr<Array<T>>>;
//
//  template<typename T>
//  DataTypeId get_data_type_id()
// {
//    throw std::invalid_argument("Type is not a UA DataType");
//  };
//
//  template<>
//  DataTypeId get_data_type_id<int16_t>()
// {
//    return DataTypeId::Int16;
//  };
//
//  template<typename T>
//  DataTypeId get_data_type_id(const T&)
// {
//    return get_data_type_id<T>();
//  };

}  // namespace ua

#endif  // !UA_BUILT_IN_TYPES_FWD_DECL_H
