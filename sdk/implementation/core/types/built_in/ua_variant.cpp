// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_variant.h"
#include "ua_data_value.h"
#include "ua_structure.h"
#include "ua_binary_codec.h"
#include "ua_error_detail.h"
#include "ua_to_string.h"

namespace ua
{

namespace
{
// Single out-of-line definition of the Variant "wrong type / empty access" error.
// The access templates (as<T>/get<T>) instantiate their throw sites once per
// visited alternative per T (~50 T x ~25 alternatives); inlining make_error_detail
// at each site bloated both the object code and the branch count enormously.
// Routing every site through this one [[noreturn]] helper emits the
// error-construction machinery exactly once.
[[noreturn]] void throw_variant_error(const char* category, const char* message)
{
  throw UaException(Status::BadInvalidState,
    ErrorDetail::build(category, "Variant access error", "Variant")
      .context(ua::ContextKeys::errorMessage, message));
}
}  // namespace

std::unique_ptr<ErrorDetail> Variant::make_coercion_error(
  BuiltInTypeId expected, BuiltInTypeId actual, bool actualIsArray, bool expectedIsArray)
{
  std::string actualName = to_string(actual);
  if (actualIsArray)
  {
    actualName += "[]";
  }
  std::string expectedName = to_string(expected);
  if (expectedIsArray)
  {
    expectedName += "[]";
  }
  return ErrorDetail::build(
    "VariantCoercionTypeMismatch", "Variant does not hold the requested built-in type", "Variant")
    .context(ua::ContextKeys::typeExpected, std::move(expectedName))
    .context(ua::ContextKeys::typeActual, std::move(actualName));
}

// --- Variant implementation ---

Variant::Variant()
{}

Variant::Variant(const Variant& other)
{
  copy_from(other);
}

Variant::Variant(Variant&& other) noexcept : mValue(std::move(other.mValue))
{}

Variant& Variant::operator=(const Variant& other)
{
  copy_from(other);
  return *this;
}

Variant& Variant::operator=(Variant&& other) noexcept
{
  mValue = std::move(other.mValue);
  return *this;
}

bool Variant::operator==(const Variant& other) const
{
  if (mValue.index() != other.mValue.index())
  {
    return false;
  }

  if (empty() && other.empty())
  {
    return true;
  }

  auto lhsScalar = std::get_if<ScalarGroup>(&mValue);
  auto rhsScalar = std::get_if<ScalarGroup>(&other.mValue);
  if (lhsScalar && rhsScalar)
  {
    return *lhsScalar == *rhsScalar;
  }

  auto lhsArray = std::get_if<ArrayGroup>(&mValue);
  auto rhsArray = std::get_if<ArrayGroup>(&other.mValue);
  if (lhsArray && rhsArray)
  {
    if (!*lhsArray && !*rhsArray)
    {
      return true;
    }
    if (!*lhsArray || !*rhsArray)
    {
      return false;
    }
    return **lhsArray == **rhsArray;
  }

  return false;
}

void Variant::copy_from(const Variant& other)
{
  auto scalarGroup = std::get_if<ScalarGroup>(&other.mValue);
  if (scalarGroup)
  {
    std::visit(
      [&]<typename T>(const T& arg)
      {
        ScalarGroup group = arg;
        mValue = std::move(group);
      },
      *scalarGroup);
    return;
  }

  auto arrayGroup = std::get_if<ArrayGroup>(&other.mValue);
  if (arrayGroup && *arrayGroup)
  {
    std::visit(
      [&]<typename T>(const T& arg)
      {
        ArrayGroupInstance temp = arg;
        auto group = make_unique<ArrayGroupInstance>(std::move(temp));
        mValue = ArrayGroup{std::move(group)};
      },
      **arrayGroup);
    return;
  }

  clear();
}

bool Variant::is_array() const
{
  return std::holds_alternative<ArrayGroup>(mValue);
}

bool Variant::empty() const
{
  return std::holds_alternative<std::monostate>(mValue);
}

bool Variant::is_scalar() const
{
  return std::holds_alternative<ScalarGroup>(mValue);
}

bool Variant::is_boolean() const
{
  return is_scalar_present<bool>();
}

bool Variant::is_int8() const
{
  return is_scalar_present<int8_t>();
}

bool Variant::is_uint8() const
{
  return is_scalar_present<uint8_t>();
}

bool Variant::is_int16() const
{
  return is_scalar_present<int16_t>();
}

bool Variant::is_uint16() const
{
  return is_scalar_present<uint16_t>();
}

bool Variant::is_int32() const
{
  return is_scalar_present<int32_t>();
}

bool Variant::is_uint32() const
{
  return is_scalar_present<uint32_t>();
}

bool Variant::is_int64() const
{
  return is_scalar_present<int64_t>();
}

bool Variant::is_uint64() const
{
  return is_scalar_present<uint64_t>();
}

bool Variant::is_float() const
{
  return is_scalar_present<float>();
}

bool Variant::is_double() const
{
  return is_scalar_present<double>();
}

bool Variant::is_date_time() const
{
  return is_scalar_present<DateTime>();
}

bool Variant::is_guid() const
{
  return is_scalar_present<Guid>();
}

bool Variant::is_xml_element() const
{
  return is_scalar_present<XmlElement>();
}

bool Variant::is_string() const
{
  return is_scalar_present<String>();
}

bool Variant::is_byte_string() const
{
  return is_scalar_present<ByteString>();
}

bool Variant::is_node_id() const
{
  return is_scalar_present<NodeId>();
}

bool Variant::is_expanded_node_id() const
{
  return is_scalar_present<ExpandedNodeId>();
}

bool Variant::is_status_code() const
{
  return is_scalar_present<StatusCode>();
}

bool Variant::is_qualified_name() const
{
  return is_scalar_present<QualifiedName>();
}

bool Variant::is_localized_text() const
{
  return is_scalar_present<LocalizedText>();
}

bool Variant::is_structure() const
{
  return is_scalar_present<RefStructure<Structure>>();
}

bool Variant::is_data_value() const
{
  return is_scalar_present<DataValue>();
}

bool Variant::is_decimal() const
{
  return is_scalar_present<Decimal>();
}

bool Variant::is_array_of_boolean() const
{
  return is_array_present<bool>();
}

bool Variant::is_array_of_int8() const
{
  return is_array_present<int8_t>();
}

bool Variant::is_array_of_uint8() const
{
  return is_array_present<uint8_t>();
}

bool Variant::is_array_of_int16() const
{
  return is_array_present<int16_t>();
}

bool Variant::is_array_of_uint16() const
{
  return is_array_present<uint16_t>();
}

bool Variant::is_array_of_int32() const
{
  return is_array_present<int32_t>();
}

bool Variant::is_array_of_uint32() const
{
  return is_array_present<uint32_t>();
}

bool Variant::is_array_of_int64() const
{
  return is_array_present<int64_t>();
}

bool Variant::is_array_of_uint64() const
{
  return is_array_present<uint64_t>();
}

bool Variant::is_array_of_float() const
{
  return is_array_present<float>();
}

bool Variant::is_array_of_double() const
{
  return is_array_present<double>();
}

bool Variant::is_array_of_date_time() const
{
  return is_array_present<DateTime>();
}

bool Variant::is_array_of_guid() const
{
  return is_array_present<Guid>();
}

bool Variant::is_array_of_xml_element() const
{
  return is_array_present<XmlElement>();
}

bool Variant::is_array_of_string() const
{
  return is_array_present<String>();
}

bool Variant::is_array_of_byte_string() const
{
  return is_array_present<ByteString>();
}

bool Variant::is_array_of_node_id() const
{
  return is_array_present<NodeId>();
}

bool Variant::is_array_of_expanded_node_id() const
{
  return is_array_present<ExpandedNodeId>();
}

bool Variant::is_array_of_status_code() const
{
  return is_array_present<StatusCode>();
}

bool Variant::is_array_of_qualified_name() const
{
  return is_array_present<QualifiedName>();
}

bool Variant::is_array_of_localized_text() const
{
  return is_array_present<LocalizedText>();
}

bool Variant::is_array_of_structure() const
{
  return is_array_present<RefStructure<Structure>>();
}

bool Variant::is_array_of_data_value() const
{
  return is_array_present<DataValue>();
}

bool Variant::is_array_of_decimal() const
{
  return is_array_present<Decimal>();
}

bool Variant::is_array_of_variant() const
{
  return is_array_present<Variant>();
}

const ArrayBase& Variant::get_array_base() const
{
  auto group = std::get_if<ArrayGroup>(&mValue);
  if (!group || !*group)
  {
    throw_variant_error("InvalidVariantAccess", "Variant does not contain an array");
  }

  return std::visit([]<typename T>(const T& arg) -> const ArrayBase& { return arg; }, **group);
}

ArrayBase& Variant::get_array_base()
{
  auto group = std::get_if<ArrayGroup>(&mValue);
  if (!group || !*group)
  {
    throw_variant_error("InvalidVariantAccess", "Variant does not contain an array");
  }

  return std::visit([]<typename T>(T& arg) -> ArrayBase& { return arg; }, **group);
}

BuiltInTypeId Variant::get_built_in_type() const
{
  auto scalarGroup = std::get_if<ScalarGroup>(&mValue);
  if (scalarGroup)
  {
    return std::visit(
      []<typename T>(const T& arg) -> BuiltInTypeId
      {
        UA_UNUSED(arg);
        if constexpr (std::is_same_v<T, detail::BoxedDataValue>)
        {
          return DataValue::built_in_type_id();  // boxed alternative -> logical DataValue
        }
        else
        {
          return built_in_type<T>();
        }
      },
      *scalarGroup);
  }

  auto arrayGroup = std::get_if<ArrayGroup>(&mValue);
  if (arrayGroup && *arrayGroup)
  {
    return std::visit(
      []<typename T>(const T& arg) -> BuiltInTypeId { return arg.built_in_type_id(); }, **arrayGroup);
  }

  throw_variant_error("InvalidVariantAccess", "Cannot get built-in type of empty Variant");
}

BuiltInTypeId Variant::actual_type_or_null() const noexcept
{
  auto scalarGroup = std::get_if<ScalarGroup>(&mValue);
  if (scalarGroup)
  {
    return std::visit(
      []<typename T>(const T& arg) -> BuiltInTypeId
      {
        UA_UNUSED(arg);
        if constexpr (std::is_same_v<T, detail::BoxedDataValue>)
        {
          return DataValue::built_in_type_id();  // boxed alternative -> logical DataValue
        }
        else
        {
          return built_in_type<T>();
        }
      },
      *scalarGroup);
  }

  auto arrayGroup = std::get_if<ArrayGroup>(&mValue);
  if (arrayGroup && *arrayGroup)
  {
    return std::visit(
      []<typename T>(const T& arg) -> BuiltInTypeId { return arg.built_in_type_id(); }, **arrayGroup);
  }

  // Empty (monostate) OR the moved-from-array state (ArrayGroup alternative present, backing wrapper
  // moved out) OR any other non-live state -> report Null rather than throw. This is the
  // noexcept-safe counterpart to get_built_in_type(), which throws for these states and so must never
  // be called from the noexcept to<T>() / to_vector<T>() coercers.
  return BuiltInTypeId::Null;
}

void Variant::clear()
{
  mValue = std::monostate{};
}

BuiltInTypeId Variant::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::Variant};
}

template<typename Type>
bool Variant::is_array_present() const
{
  auto group = std::get_if<ArrayGroup>(&mValue);
  if (!group || !*group)
  {
    return false;
  }
  return std::holds_alternative<Array<Type>>(**group);
}

template<typename Type>
bool Variant::is_scalar_present() const
{
  auto group = std::get_if<ScalarGroup>(&mValue);
  if (!group)
  {
    return false;
  }
  if constexpr (std::is_same_v<Type, DataValue>)
  {
    // DataValue is stored boxed (detail::BoxedDataValue).
    return std::holds_alternative<detail::BoxedDataValue>(*group);
  }
  else
  {
    return std::holds_alternative<Type>(*group);
  }
}

// Template implementations follow with explicit instantiations as a compilation speed optimisation

template<typename Encoder>
void Variant::encode(StackDepth limit, Encoder& encoder) const
{
  auto scalarGroup = std::get_if<ScalarGroup>(&mValue);
  if (scalarGroup)
  {
    auto visitor = [&limit, &encoder](auto& arg)
    {
      using T = std::decay_t<decltype(arg)>;
      if constexpr (std::is_same_v<T, RefStructure<Structure>>)
      {
        encoder.encode(limit, arg.get());
      }
      else if constexpr (std::is_same_v<T, detail::BoxedDataValue>)
      {
        encoder.encode(limit, *arg);  // debox to the logical DataValue
      }
      else
      {
        encoder.encode(limit, arg);
      }
    };

    std::visit(visitor, *scalarGroup);
    return;
  }

  auto arrayGroup = std::get_if<ArrayGroup>(&mValue);
  if (arrayGroup && *arrayGroup)
  {
    std::visit([&limit, &encoder](auto& arg) { encoder.encode(limit, arg); }, **arrayGroup);
    return;
  }

  throw_variant_error("InvalidVariantAccess", "Cannot encode empty Variant");
}

template void Variant::encode<UaBinaryEncoder>(StackDepth limit, UaBinaryEncoder& encoder) const;

template<typename T>
  requires IsBuiltInScalarType<T>
Variant& Variant::operator=(const T& value)
{
  if constexpr (std::is_same_v<T, DataValue>)
  {
    // DataValue is stored boxed; construct the BoxedDataValue alternative directly.
    mValue = ScalarGroup{std::in_place_type<detail::BoxedDataValue>, value};
  }
  else
  {
    ScalarGroup group = value;
    mValue = std::move(group);
  }
  return *this;
}

template Variant& Variant::operator= <bool>(const bool& value);
template Variant& Variant::operator= <int8_t>(const int8_t& value);
template Variant& Variant::operator= <uint8_t>(const uint8_t& value);
template Variant& Variant::operator= <int16_t>(const int16_t& value);
template Variant& Variant::operator= <uint16_t>(const uint16_t& value);
template Variant& Variant::operator= <int32_t>(const int32_t& value);
template Variant& Variant::operator= <uint32_t>(const uint32_t& value);
template Variant& Variant::operator= <int64_t>(const int64_t& value);
template Variant& Variant::operator= <uint64_t>(const uint64_t& value);
template Variant& Variant::operator= <float>(const float& value);
template Variant& Variant::operator= <double>(const double& value);
template Variant& Variant::operator= <DateTime>(const DateTime& value);
template Variant& Variant::operator= <Guid>(const Guid& value);
template Variant& Variant::operator= <XmlElement>(const XmlElement& value);
template Variant& Variant::operator= <String>(const String& value);
template Variant& Variant::operator= <ByteString>(const ByteString& value);
template Variant& Variant::operator= <NodeId>(const NodeId& value);
template Variant& Variant::operator= <ExpandedNodeId>(const ExpandedNodeId& value);
template Variant& Variant::operator= <StatusCode>(const StatusCode& value);
template Variant& Variant::operator= <QualifiedName>(const QualifiedName& value);
template Variant& Variant::operator= <LocalizedText>(const LocalizedText& value);
template Variant& Variant::operator= <DataValue>(const DataValue& value);
template Variant& Variant::operator= <Decimal>(const Decimal& value);

template<typename T>
  requires IsBuiltInArrayType<T>
Variant& Variant::operator=(const T& value)
{
  auto group = make_unique<ArrayGroupInstance>();
  *group = value;
  mValue = ArrayGroup{std::move(group)};
  return *this;
}

template Variant& Variant::operator= <Array<bool>>(const Array<bool>& value);
template Variant& Variant::operator= <Array<int8_t>>(const Array<int8_t>& value);
template Variant& Variant::operator= <Array<uint8_t>>(const Array<uint8_t>& value);
template Variant& Variant::operator= <Array<int16_t>>(const Array<int16_t>& value);
template Variant& Variant::operator= <Array<uint16_t>>(const Array<uint16_t>& value);
template Variant& Variant::operator= <Array<int32_t>>(const Array<int32_t>& value);
template Variant& Variant::operator= <Array<uint32_t>>(const Array<uint32_t>& value);
template Variant& Variant::operator= <Array<int64_t>>(const Array<int64_t>& value);
template Variant& Variant::operator= <Array<uint64_t>>(const Array<uint64_t>& value);
template Variant& Variant::operator= <Array<float>>(const Array<float>& value);
template Variant& Variant::operator= <Array<double>>(const Array<double>& value);
template Variant& Variant::operator= <Array<DateTime>>(const Array<DateTime>& value);
template Variant& Variant::operator= <Array<Guid>>(const Array<Guid>& value);
template Variant& Variant::operator= <Array<XmlElement>>(const Array<XmlElement>& value);
template Variant& Variant::operator= <Array<String>>(const Array<String>& value);
template Variant& Variant::operator= <Array<ByteString>>(const Array<ByteString>& value);
template Variant& Variant::operator= <Array<NodeId>>(const Array<NodeId>& value);
template Variant& Variant::operator= <Array<ExpandedNodeId>>(const Array<ExpandedNodeId>& value);
template Variant& Variant::operator= <Array<StatusCode>>(const Array<StatusCode>& value);
template Variant& Variant::operator= <Array<QualifiedName>>(const Array<QualifiedName>& value);
template Variant& Variant::operator= <Array<LocalizedText>>(const Array<LocalizedText>& value);
template Variant& Variant::operator= <Array<RefStructure<Structure>>>(
  const Array<RefStructure<Structure>>& value);

template Variant& Variant::operator= <Array<DataValue>>(const Array<DataValue>& value);
template Variant& Variant::operator= <Array<Decimal>>(const Array<Decimal>& value);
template Variant& Variant::operator= <Array<Variant>>(const Array<Variant>& value);

template<typename T>
  requires IsBuiltInScalarType<T>
Variant& Variant::operator=(T&& value) noexcept
{
  if constexpr (std::is_same_v<std::remove_reference_t<T>, DataValue>)
  {
    // DataValue is stored boxed; construct the BoxedDataValue alternative directly.
    mValue = ScalarGroup{std::in_place_type<detail::BoxedDataValue>, std::forward<T>(value)};
  }
  else
  {
    ScalarGroup group = std::forward<T>(value);
    mValue = std::move(group);
  }
  return *this;
}

template Variant& Variant::operator= <bool>(bool&& value) noexcept;
template Variant& Variant::operator= <int8_t>(int8_t&& value) noexcept;
template Variant& Variant::operator= <uint8_t>(uint8_t&& value) noexcept;
template Variant& Variant::operator= <int16_t>(int16_t&& value) noexcept;
template Variant& Variant::operator= <uint16_t>(uint16_t&& value) noexcept;
template Variant& Variant::operator= <int32_t>(int32_t&& value) noexcept;
template Variant& Variant::operator= <uint32_t>(uint32_t&& value) noexcept;
template Variant& Variant::operator= <int64_t>(int64_t&& value) noexcept;
template Variant& Variant::operator= <uint64_t>(uint64_t&& value) noexcept;
template Variant& Variant::operator= <float>(float&& value) noexcept;
template Variant& Variant::operator= <double>(double&& value) noexcept;
template Variant& Variant::operator= <DateTime>(DateTime&& value) noexcept;
template Variant& Variant::operator= <Guid>(Guid&& value) noexcept;
template Variant& Variant::operator= <XmlElement>(XmlElement&& value) noexcept;
template Variant& Variant::operator= <String>(String&& value) noexcept;
template Variant& Variant::operator= <ByteString>(ByteString&& value) noexcept;
template Variant& Variant::operator= <NodeId>(NodeId&& value) noexcept;
template Variant& Variant::operator= <ExpandedNodeId>(ExpandedNodeId&& value) noexcept;
template Variant& Variant::operator= <StatusCode>(StatusCode&& value) noexcept;
template Variant& Variant::operator= <QualifiedName>(QualifiedName&& value) noexcept;
template Variant& Variant::operator= <LocalizedText>(LocalizedText&& value) noexcept;
template Variant& Variant::operator= <DataValue>(DataValue&& value) noexcept;
template Variant& Variant::operator= <Decimal>(Decimal&& value) noexcept;

template<typename T>
  requires IsBuiltInArrayType<T>
Variant& Variant::operator=(T&& value) noexcept
{
  auto group = make_unique<ArrayGroupInstance>();
  *group = std::forward<T>(value);
  mValue = ArrayGroup{std::move(group)};
  return *this;
}

template Variant& Variant::operator= <Array<bool>>(Array<bool>&& value) noexcept;
template Variant& Variant::operator= <Array<int8_t>>(Array<int8_t>&& value) noexcept;
template Variant& Variant::operator= <Array<uint8_t>>(Array<uint8_t>&& value) noexcept;
template Variant& Variant::operator= <Array<int16_t>>(Array<int16_t>&& value) noexcept;
template Variant& Variant::operator= <Array<uint16_t>>(Array<uint16_t>&& value) noexcept;
template Variant& Variant::operator= <Array<int32_t>>(Array<int32_t>&& value) noexcept;
template Variant& Variant::operator= <Array<uint32_t>>(Array<uint32_t>&& value) noexcept;
template Variant& Variant::operator= <Array<int64_t>>(Array<int64_t>&& value) noexcept;
template Variant& Variant::operator= <Array<uint64_t>>(Array<uint64_t>&& value) noexcept;
template Variant& Variant::operator= <Array<float>>(Array<float>&& value) noexcept;
template Variant& Variant::operator= <Array<double>>(Array<double>&& value) noexcept;
template Variant& Variant::operator= <Array<DateTime>>(Array<DateTime>&& value) noexcept;
template Variant& Variant::operator= <Array<Guid>>(Array<Guid>&& value) noexcept;
template Variant& Variant::operator= <Array<XmlElement>>(Array<XmlElement>&& value) noexcept;
template Variant& Variant::operator= <Array<String>>(Array<String>&& value) noexcept;
template Variant& Variant::operator= <Array<ByteString>>(Array<ByteString>&& value) noexcept;
template Variant& Variant::operator= <Array<NodeId>>(Array<NodeId>&& value) noexcept;
template Variant& Variant::operator= <Array<ExpandedNodeId>>(Array<ExpandedNodeId>&& value) noexcept;
template Variant& Variant::operator= <Array<StatusCode>>(Array<StatusCode>&& value) noexcept;
template Variant& Variant::operator= <Array<QualifiedName>>(Array<QualifiedName>&& value) noexcept;
template Variant& Variant::operator= <Array<LocalizedText>>(Array<LocalizedText>&& value) noexcept;
template Variant& Variant::operator= <Array<RefStructure<Structure>>>(
  Array<RefStructure<Structure>>&& value) noexcept;

template Variant& Variant::operator= <Array<DataValue>>(Array<DataValue>&& value) noexcept;
template Variant& Variant::operator= <Array<Decimal>>(Array<Decimal>&& value) noexcept;
template Variant& Variant::operator= <Array<Variant>>(Array<Variant>&& value) noexcept;

// T is known at each call, so resolve the value directly with std::get_if rather
// than std::visit over every alternative: one active-index check instead of a full
// dispatch table emitted per instantiation. A built-in scalar lives in ScalarGroup,
// an Array<...> in ArrayGroupInstance - selected with if constexpr so only the
// relevant get_if (and its single alternative) is instantiated.
template<typename T>
auto Variant::as() const -> const T&
{
  if constexpr (IsBuiltInScalarType<T>)
  {
    if (auto* scalarGroup = std::get_if<ScalarGroup>(&mValue))
    {
      if constexpr (std::is_same_v<T, DataValue>)
      {
        // DataValue is stored boxed; debox to the logical DataValue.
        if (auto* boxed = std::get_if<detail::BoxedDataValue>(scalarGroup))
        {
          return **boxed;
        }
      }
      else
      {
        if (auto* value = std::get_if<T>(scalarGroup))
        {
          return *value;
        }
      }
      throw_variant_error("VariantTypeMismatch", "Variant does not contain the requested scalar type");
    }
  }
  else
  {
    if (auto* arrayGroup = std::get_if<ArrayGroup>(&mValue); arrayGroup && *arrayGroup)
    {
      if (auto* value = std::get_if<T>(&**arrayGroup))
      {
        return *value;
      }
      throw_variant_error("VariantTypeMismatch", "Variant does not contain the requested array type");
    }
  }

  throw_variant_error("InvalidVariantAccess", "Variant is empty");
}

template<typename T>
auto Variant::as() -> T&
{
  if constexpr (IsBuiltInScalarType<T>)
  {
    if (auto* scalarGroup = std::get_if<ScalarGroup>(&mValue))
    {
      if constexpr (std::is_same_v<T, DataValue>)
      {
        // DataValue is stored boxed; debox to the logical DataValue.
        if (auto* boxed = std::get_if<detail::BoxedDataValue>(scalarGroup))
        {
          return **boxed;
        }
      }
      else
      {
        if (auto* value = std::get_if<T>(scalarGroup))
        {
          return *value;
        }
      }
      throw_variant_error("VariantTypeMismatch", "Variant does not contain the requested scalar type");
    }
  }
  else
  {
    if (auto* arrayGroup = std::get_if<ArrayGroup>(&mValue); arrayGroup && *arrayGroup)
    {
      if (auto* value = std::get_if<T>(&**arrayGroup))
      {
        return *value;
      }
      throw_variant_error("VariantTypeMismatch", "Variant does not contain the requested array type");
    }
  }

  throw_variant_error("InvalidVariantAccess", "Variant is empty");
}

template<>
auto Variant::as() const -> const Variant&
{
  return *this;
}

template<>
auto Variant::as() const -> const Structure&
{
  if (auto scalarGroup = std::get_if<ScalarGroup>(&mValue))
  {
    if (auto structure = std::get_if<RefStructure<Structure>>(scalarGroup))
    {
      return **structure;
    }
  }
  throw_variant_error("VariantTypeMismatch", "Variant does not contain a Structure scalar");
}

template<>
auto Variant::as() const -> const unique_ptr<Structure>&
{
  if (auto scalarGroup = std::get_if<ScalarGroup>(&mValue))
  {
    if (auto structure = std::get_if<RefStructure<Structure>>(scalarGroup))
    {
      return structure->inner_unique_ptr();
    }
  }
  throw_variant_error(
    "VariantTypeMismatch", "Variant does not contain a Structure scalar (unique_ptr access)");
}

template<>
auto Variant::as() -> Structure&
{
  if (auto scalarGroup = std::get_if<ScalarGroup>(&mValue))
  {
    if (auto structure = std::get_if<RefStructure<Structure>>(scalarGroup))
    {
      return **structure;
    }
  }
  throw_variant_error("VariantTypeMismatch", "Variant does not contain a mutable Structure scalar");
}

template<>
auto Variant::as() -> unique_ptr<Structure>&
{
  if (auto scalarGroup = std::get_if<ScalarGroup>(&mValue))
  {
    if (auto structure = std::get_if<RefStructure<Structure>>(scalarGroup))
    {
      return structure->inner_unique_ptr();
    }
  }
  throw_variant_error("VariantTypeMismatch", "Variant does not contain a mutable Structure unique_ptr");
}

template auto Variant::as<bool>() const -> const bool&;
template auto Variant::as<int8_t>() const -> const int8_t&;
template auto Variant::as<uint8_t>() const -> const uint8_t&;
template auto Variant::as<int16_t>() const -> const int16_t&;
template auto Variant::as<uint16_t>() const -> const uint16_t&;
template auto Variant::as<int32_t>() const -> const int32_t&;
template auto Variant::as<uint32_t>() const -> const uint32_t&;
template auto Variant::as<int64_t>() const -> const int64_t&;
template auto Variant::as<uint64_t>() const -> const uint64_t&;
template auto Variant::as<float>() const -> const float&;
template auto Variant::as<double>() const -> const double&;
template auto Variant::as<DateTime>() const -> const DateTime&;
template auto Variant::as<Guid>() const -> const Guid&;
template auto Variant::as<XmlElement>() const -> const XmlElement&;
template auto Variant::as<String>() const -> const String&;
template auto Variant::as<ByteString>() const -> const ByteString&;
template auto Variant::as<NodeId>() const -> const NodeId&;
template auto Variant::as<ExpandedNodeId>() const -> const ExpandedNodeId&;
template auto Variant::as<StatusCode>() const -> const StatusCode&;
template auto Variant::as<QualifiedName>() const -> const QualifiedName&;
template auto Variant::as<LocalizedText>() const -> const LocalizedText&;
template auto Variant::as<RefStructure<Structure>>() const -> const RefStructure<Structure>&;

template auto Variant::as<DataValue>() const -> const DataValue&;
template auto Variant::as<Decimal>() const -> const Decimal&;

template auto Variant::as<Array<bool>>() const -> const Array<bool>&;
template auto Variant::as<Array<int8_t>>() const -> const Array<int8_t>&;
template auto Variant::as<Array<uint8_t>>() const -> const Array<uint8_t>&;
template auto Variant::as<Array<int16_t>>() const -> const Array<int16_t>&;
template auto Variant::as<Array<uint16_t>>() const -> const Array<uint16_t>&;
template auto Variant::as<Array<int32_t>>() const -> const Array<int32_t>&;
template auto Variant::as<Array<uint32_t>>() const -> const Array<uint32_t>&;
template auto Variant::as<Array<int64_t>>() const -> const Array<int64_t>&;
template auto Variant::as<Array<uint64_t>>() const -> const Array<uint64_t>&;
template auto Variant::as<Array<float>>() const -> const Array<float>&;
template auto Variant::as<Array<double>>() const -> const Array<double>&;
template auto Variant::as<Array<DateTime>>() const -> const Array<DateTime>&;
template auto Variant::as<Array<Guid>>() const -> const Array<Guid>&;
template auto Variant::as<Array<XmlElement>>() const -> const Array<XmlElement>&;
template auto Variant::as<Array<String>>() const -> const Array<String>&;
template auto Variant::as<Array<ByteString>>() const -> const Array<ByteString>&;
template auto Variant::as<Array<NodeId>>() const -> const Array<NodeId>&;
template auto Variant::as<Array<ExpandedNodeId>>() const -> const Array<ExpandedNodeId>&;
template auto Variant::as<Array<StatusCode>>() const -> const Array<StatusCode>&;
template auto Variant::as<Array<QualifiedName>>() const -> const Array<QualifiedName>&;
template auto Variant::as<Array<LocalizedText>>() const -> const Array<LocalizedText>&;
template auto Variant::as<Array<RefStructure<Structure>>>() const -> const Array<RefStructure<Structure>>&;

template auto Variant::as<Array<Decimal>>() const -> const Array<Decimal>&;
template auto Variant::as<Array<Variant>>() const -> const Array<Variant>&;

template auto Variant::as<Array<DataValue>>() const -> const Array<DataValue>&;

template<>
auto Variant::as() -> Variant&
{
  return *this;
}

template auto Variant::as<bool>() -> bool&;
template auto Variant::as<int8_t>() -> int8_t&;
template auto Variant::as<uint8_t>() -> uint8_t&;
template auto Variant::as<int16_t>() -> int16_t&;
template auto Variant::as<uint16_t>() -> uint16_t&;
template auto Variant::as<int32_t>() -> int32_t&;
template auto Variant::as<uint32_t>() -> uint32_t&;
template auto Variant::as<int64_t>() -> int64_t&;
template auto Variant::as<uint64_t>() -> uint64_t&;
template auto Variant::as<float>() -> float&;
template auto Variant::as<double>() -> double&;
template auto Variant::as<DateTime>() -> DateTime&;
template auto Variant::as<Guid>() -> Guid&;
template auto Variant::as<XmlElement>() -> XmlElement&;
template auto Variant::as<String>() -> String&;
template auto Variant::as<ByteString>() -> ByteString&;
template auto Variant::as<NodeId>() -> NodeId&;
template auto Variant::as<ExpandedNodeId>() -> ExpandedNodeId&;
template auto Variant::as<StatusCode>() -> StatusCode&;
template auto Variant::as<QualifiedName>() -> QualifiedName&;
template auto Variant::as<LocalizedText>() -> LocalizedText&;
template auto Variant::as<RefStructure<Structure>>() -> RefStructure<Structure>&;

template auto Variant::as<DataValue>() -> DataValue&;
template auto Variant::as<Decimal>() -> Decimal&;

template auto Variant::as<Array<bool>>() -> Array<bool>&;
template auto Variant::as<Array<int8_t>>() -> Array<int8_t>&;
template auto Variant::as<Array<uint8_t>>() -> Array<uint8_t>&;
template auto Variant::as<Array<int16_t>>() -> Array<int16_t>&;
template auto Variant::as<Array<uint16_t>>() -> Array<uint16_t>&;
template auto Variant::as<Array<int32_t>>() -> Array<int32_t>&;
template auto Variant::as<Array<uint32_t>>() -> Array<uint32_t>&;
template auto Variant::as<Array<int64_t>>() -> Array<int64_t>&;
template auto Variant::as<Array<uint64_t>>() -> Array<uint64_t>&;
template auto Variant::as<Array<float>>() -> Array<float>&;
template auto Variant::as<Array<double>>() -> Array<double>&;
template auto Variant::as<Array<DateTime>>() -> Array<DateTime>&;
template auto Variant::as<Array<Guid>>() -> Array<Guid>&;
template auto Variant::as<Array<XmlElement>>() -> Array<XmlElement>&;
template auto Variant::as<Array<String>>() -> Array<String>&;
template auto Variant::as<Array<ByteString>>() -> Array<ByteString>&;
template auto Variant::as<Array<NodeId>>() -> Array<NodeId>&;
template auto Variant::as<Array<ExpandedNodeId>>() -> Array<ExpandedNodeId>&;
template auto Variant::as<Array<StatusCode>>() -> Array<StatusCode>&;
template auto Variant::as<Array<QualifiedName>>() -> Array<QualifiedName>&;
template auto Variant::as<Array<LocalizedText>>() -> Array<LocalizedText>&;
template auto Variant::as<Array<RefStructure<Structure>>>() -> Array<RefStructure<Structure>>&;

template auto Variant::as<Array<Decimal>>() -> Array<Decimal>&;
template auto Variant::as<Array<Variant>>() -> Array<Variant>&;

template auto Variant::as<Array<DataValue>>() -> Array<DataValue>&;

}  // namespace ua
