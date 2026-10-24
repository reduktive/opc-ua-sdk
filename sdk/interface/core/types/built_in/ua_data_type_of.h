// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The OPC UA DataType, ValueRank and ArrayDimensions a C++ type describes.
/// @ingroup core_types

#ifndef UA_DATA_TYPE_OF_H
#define UA_DATA_TYPE_OF_H

#include "ua_array.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_data_type_trait.h"
#include "ua_datatype_id.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_uri.h"
#include "ua_node_id.h"
#include "ua_utilities.h"
#include "ua_value_rank.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ua
{

/// @cond DATA_TYPE_OF_DETAIL
namespace detail
{

/// A DataType of namespace 0, the base of the built-in specialisations below.
template<DataTypeId Id>
struct Ns0DataType
{
  /// The DataType's identifier in namespace 0.
  static constexpr DataTypeId id{Id};
  /// Namespace 0.
  static constexpr std::string_view namespaceUri = specNamespaceUri;
};

}  // namespace detail

/// @endcond

/// @cond BUILT_IN_DATA_TYPES
template<>
struct DataTypeOf<bool> : detail::Ns0DataType<DataTypeId::Boolean>
{};

template<>
struct DataTypeOf<int8_t> : detail::Ns0DataType<DataTypeId::SByte>
{};

template<>
struct DataTypeOf<uint8_t> : detail::Ns0DataType<DataTypeId::Byte>
{};

template<>
struct DataTypeOf<int16_t> : detail::Ns0DataType<DataTypeId::Int16>
{};

template<>
struct DataTypeOf<uint16_t> : detail::Ns0DataType<DataTypeId::UInt16>
{};

template<>
struct DataTypeOf<int32_t> : detail::Ns0DataType<DataTypeId::Int32>
{};

template<>
struct DataTypeOf<uint32_t> : detail::Ns0DataType<DataTypeId::UInt32>
{};

template<>
struct DataTypeOf<int64_t> : detail::Ns0DataType<DataTypeId::Int64>
{};

template<>
struct DataTypeOf<uint64_t> : detail::Ns0DataType<DataTypeId::UInt64>
{};

template<>
struct DataTypeOf<float> : detail::Ns0DataType<DataTypeId::Float>
{};

template<>
struct DataTypeOf<double> : detail::Ns0DataType<DataTypeId::Double>
{};

template<>
struct DataTypeOf<String> : detail::Ns0DataType<DataTypeId::String>
{};

template<>
struct DataTypeOf<std::string> : detail::Ns0DataType<DataTypeId::String>
{};

template<>
struct DataTypeOf<DateTime> : detail::Ns0DataType<DataTypeId::DateTime>
{};

template<>
struct DataTypeOf<Guid> : detail::Ns0DataType<DataTypeId::Guid>
{};

template<>
struct DataTypeOf<ByteString> : detail::Ns0DataType<DataTypeId::ByteString>
{};

template<>
struct DataTypeOf<XmlElement> : detail::Ns0DataType<DataTypeId::XmlElement>
{};

template<>
struct DataTypeOf<NodeId> : detail::Ns0DataType<DataTypeId::NodeId>
{};

template<>
struct DataTypeOf<ExpandedNodeId> : detail::Ns0DataType<DataTypeId::ExpandedNodeId>
{};

template<>
struct DataTypeOf<StatusCode> : detail::Ns0DataType<DataTypeId::StatusCode>
{};

template<>
struct DataTypeOf<QualifiedName> : detail::Ns0DataType<DataTypeId::QualifiedName>
{};

template<>
struct DataTypeOf<LocalizedText> : detail::Ns0DataType<DataTypeId::LocalizedText>
{};

template<>
struct DataTypeOf<DataValue> : detail::Ns0DataType<DataTypeId::DataValue>
{};

template<>
struct DataTypeOf<DiagnosticInfo> : detail::Ns0DataType<DataTypeId::DiagnosticInfo>
{};

template<>
struct DataTypeOf<Variant> : detail::Ns0DataType<DataTypeId::BaseDataType>
{};

template<>
struct DataTypeOf<Decimal> : detail::Ns0DataType<DataTypeId::Decimal>
{};

/// @endcond

/// @cond DATA_TYPE_OF_DETAIL
namespace detail
{

/// `ua::Array<U>` and `std::vector<U>` are one-dimensional arrays of `U`.
template<typename T>
struct DataTypeArray
{
  static constexpr bool isArray = false;
};

template<typename U>
struct DataTypeArray<Array<U>>
{
  static constexpr bool isArray = true;
  using Element = U;
};

template<typename U, typename Allocator>
struct DataTypeArray<std::vector<U, Allocator>>
{
  static constexpr bool isArray = true;
  using Element = U;
};

/// `std::optional<U>` describes the same DataType as `U` (an optional trailing argument).
template<typename T>
struct DataTypeOptional
{
  static constexpr bool isOptional = false;
};

template<typename U>
struct DataTypeOptional<std::optional<U>>
{
  static constexpr bool isOptional = true;
  using Inner = U;
};

/// A type mapped through @ref ua::DataTypeOf.
template<typename T>
concept DeclaresDataType = requires {
  DataTypeOf<T>::id;
  DataTypeOf<T>::namespaceUri;
};

/// A type emitted by the type generator, which names its DataType and the namespace that owns it.
template<typename T>
concept GeneratedDataType = requires {
  T::typeId;
  T::typeNamespaceUri;
};

template<typename T>
consteval bool scalar_has_data_type()
{
  return DeclaresDataType<T> || GeneratedDataType<T>;
}

template<typename T>
consteval bool has_data_type()
{
  using Value = std::remove_cvref_t<T>;
  if constexpr (DataTypeOptional<Value>::isOptional)
  {
    using Inner = typename DataTypeOptional<Value>::Inner;
    return !DataTypeOptional<Inner>::isOptional && has_data_type<Inner>();
  }
  else if constexpr (DataTypeArray<Value>::isArray)
  {
    using Element = typename DataTypeArray<Value>::Element;
    return !DataTypeArray<Element>::isArray && !DataTypeOptional<Element>::isOptional &&
           scalar_has_data_type<Element>();
  }
  else
  {
    return scalar_has_data_type<Value>();
  }
}

/// The numeric identifier of a DataType named by an enumerator or an integer.
template<typename Id>
constexpr uint32_t numeric_data_type_id(Id id) noexcept
{
  if constexpr (std::is_enum_v<Id>)
  {
    return static_cast<uint32_t>(utils::to_underlying(id));
  }
  else
  {
    return static_cast<uint32_t>(id);
  }
}

/// The DataType @p id of the namespace @p namespaceUri: a plain NodeId for namespace 0, otherwise the
/// numeric identifier with the URI, for the caller to resolve against a server's namespace array.
template<typename Id>
ExpandedNodeId data_type_node(Id id, std::string_view namespaceUri)
{
  const NodeId nodeId{0, numeric_data_type_id(id)};
  if (namespaceUri == specNamespaceUri)
  {
    return ExpandedNodeId{nodeId};
  }
  return ExpandedNodeId{nodeId, namespaceUri};
}

}  // namespace detail

/// @endcond

/// True when @p T describes an OPC UA DataType that @ref ua::data_type_of can name.
///
/// Mapped are: the built-in types (the C++ integer and floating-point types of each width, `bool`,
/// `ua::String` and `std::string`, and the SDK's value types; `ua::Variant` is BaseDataType and
/// `ua::Decimal` is Decimal); every generated structure, union and enumeration; any type with a
/// @ref ua::DataTypeOf specialisation; `ua::Array<U>` and `std::vector<U>` of a mapped scalar `U`; and
/// `std::optional<U>` of a mapped `U`. Nothing else is: an option set, a raw extension object, a nested
/// array or a structure known only at run time has no DataType here, and is described with an explicit
/// DataType NodeId instead.
/// @tparam T The C++ type.
template<typename T>
inline constexpr bool hasDataType = detail::has_data_type<T>();

/// Returns the OPC UA DataType that @p T describes.
///
/// A namespace-0 DataType is returned as a plain NodeId (no namespace URI). A DataType of another
/// namespace, such as a companion specification's structure, carries its numeric identifier and its
/// namespace URI: only a running server knows that namespace's index, so the caller resolves it
/// against the server's namespace array. An array or optional type returns its element's DataType.
/// A type without a DataType does not compile here (see @ref ua::hasDataType); nothing falls back to
/// BaseDataType.
/// @tparam T The C++ type.
/// @return The DataType, as an ExpandedNodeId whose namespace URI is set unless it is namespace 0.
template<typename T>
ExpandedNodeId data_type_of()
{
  static_assert(hasDataType<T>,
    "No OPC UA DataType is known for this C++ type: specialise ua::DataTypeOf for it, or describe the "
    "argument with an explicit DataType NodeId");
  using Value = std::remove_cvref_t<T>;
  if constexpr (detail::DataTypeOptional<Value>::isOptional)
  {
    return data_type_of<typename detail::DataTypeOptional<Value>::Inner>();
  }
  else if constexpr (detail::DataTypeArray<Value>::isArray)
  {
    return data_type_of<typename detail::DataTypeArray<Value>::Element>();
  }
  else if constexpr (detail::DeclaresDataType<Value>)
  {
    return detail::data_type_node(DataTypeOf<Value>::id, DataTypeOf<Value>::namespaceUri);
  }
  else
  {
    return detail::data_type_node(Value::typeId, Value::typeNamespaceUri);
  }
}

/// Returns the ValueRank that @p T describes: @ref ua::ValueRank::scalar, or 1 for `ua::Array<U>` and
/// `std::vector<U>`. `std::optional<U>` has the rank of `U`.
/// @tparam T A type for which @ref ua::hasDataType is true.
/// @return The ValueRank.
template<typename T>
ValueRank value_rank_of()
{
  static_assert(hasDataType<T>,
    "No OPC UA DataType is known for this C++ type: specialise ua::DataTypeOf for it, or describe the "
    "argument with an explicit DataType NodeId");
  using Value = std::remove_cvref_t<T>;
  if constexpr (detail::DataTypeOptional<Value>::isOptional)
  {
    return value_rank_of<typename detail::DataTypeOptional<Value>::Inner>();
  }
  else if constexpr (detail::DataTypeArray<Value>::isArray)
  {
    return ValueRank{1};
  }
  else
  {
    return ValueRank{ValueRank::scalar};
  }
}

/// Returns the ArrayDimensions that @p T describes: empty for a scalar, `{0}` (one dimension of any
/// length) for `ua::Array<U>` and `std::vector<U>`. `std::optional<U>` has the dimensions of `U`.
/// @tparam T A type for which @ref ua::hasDataType is true.
/// @return The ArrayDimensions.
template<typename T>
std::vector<uint32_t> array_dimensions_of()
{
  static_assert(hasDataType<T>,
    "No OPC UA DataType is known for this C++ type: specialise ua::DataTypeOf for it, or describe the "
    "argument with an explicit DataType NodeId");
  using Value = std::remove_cvref_t<T>;
  if constexpr (detail::DataTypeOptional<Value>::isOptional)
  {
    return array_dimensions_of<typename detail::DataTypeOptional<Value>::Inner>();
  }
  else if constexpr (detail::DataTypeArray<Value>::isArray)
  {
    return {0};
  }
  else
  {
    return {};
  }
}

}  // namespace ua

#endif  // UA_DATA_TYPE_OF_H
