// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_field_codec.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_union.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "ua_to_string.h"
#include "ua_date_time.h"
#include "ua_diagnostic_info.h"
#include "ua_data_value.h"
#include "ua_xml_element.h"

namespace ua::detail
{

Variant make_default_field_value(BuiltInTypeId builtInType, int32_t valueRank)
{
  if (valueRank >= 0)
  {
    // Array field - default to empty Variant (null array)
    return Variant{};
  }

  switch (builtInType)
  {
  case BuiltInTypeId::Boolean:
    return Variant{false};
  case BuiltInTypeId::SByte:
    return Variant{int8_t{0}};
  case BuiltInTypeId::Byte:
    return Variant{uint8_t{0}};
  case BuiltInTypeId::Int16:
    return Variant{int16_t{0}};
  case BuiltInTypeId::UInt16:
    return Variant{uint16_t{0}};
  case BuiltInTypeId::Int32:
    return Variant{int32_t{0}};
  case BuiltInTypeId::UInt32:
    return Variant{uint32_t{0}};
  case BuiltInTypeId::Int64:
    return Variant{int64_t{0}};
  case BuiltInTypeId::UInt64:
    return Variant{uint64_t{0}};
  case BuiltInTypeId::Float:
    return Variant{float{0.0f}};
  case BuiltInTypeId::Double:
    return Variant{double{0.0}};
  case BuiltInTypeId::String:
    return Variant{String{}};
  case BuiltInTypeId::DateTime:
    return Variant{DateTime{}};
  case BuiltInTypeId::Guid:
    return Variant{Guid{}};
  case BuiltInTypeId::ByteString:
    return Variant{ByteString{}};
  case BuiltInTypeId::XmlElement:
    return Variant{XmlElement{}};
  case BuiltInTypeId::NodeId:
    return Variant{NodeId{}};
  case BuiltInTypeId::ExpandedNodeId:
    return Variant{ExpandedNodeId{}};
  case BuiltInTypeId::StatusCode:
    return Variant{StatusCode{}};
  case BuiltInTypeId::QualifiedName:
    return Variant{QualifiedName{}};
  case BuiltInTypeId::LocalizedText:
    return Variant{LocalizedText{}};
  case BuiltInTypeId::DataValue:
    return Variant{DataValue{}};
  // These have no distinct default scalar payload, so all decode to an empty Variant:
  // DiagnosticInfo cannot be stored directly in a Variant, and structure fields
  // (ExtensionObject) default to an empty/null value.
  case BuiltInTypeId::Variant:
  case BuiltInTypeId::DiagnosticInfo:
  case BuiltInTypeId::ExtensionObject:
  case BuiltInTypeId::Null:
    return Variant{};
  }
  return Variant{};
}

namespace
{

/// Encode a single scalar element.
void encode_scalar_element(StackDepth limit, const Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, UaBinaryEncoder& encoder);

/// Decode a single scalar element.
void decode_scalar_element(StackDepth limit, Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, UaBinaryDecoder& decoder);

}  // namespace

void encode_dynamic_field(StackDepth limit, const Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, int32_t valueRank,
  UaBinaryEncoder& encoder)
{
  if (valueRank >= 0)
  {
    // Array field: encode via the encoder's typed Array<T> support.
    // The Variant holds a typed Array<T> which the encoder handles natively.
    switch (builtInType)
    {
    case BuiltInTypeId::Boolean:
      encoder.encode(limit, fieldValue.empty() ? Array<bool>{} : fieldValue.as<Array<bool>>());
      break;
    case BuiltInTypeId::SByte:
      encoder.encode(limit, fieldValue.empty() ? Array<int8_t>{} : fieldValue.as<Array<int8_t>>());
      break;
    case BuiltInTypeId::Byte:
      encoder.encode(limit, fieldValue.empty() ? Array<uint8_t>{} : fieldValue.as<Array<uint8_t>>());
      break;
    case BuiltInTypeId::Int16:
      encoder.encode(limit, fieldValue.empty() ? Array<int16_t>{} : fieldValue.as<Array<int16_t>>());
      break;
    case BuiltInTypeId::UInt16:
      encoder.encode(limit, fieldValue.empty() ? Array<uint16_t>{} : fieldValue.as<Array<uint16_t>>());
      break;
    case BuiltInTypeId::Int32:
      encoder.encode(limit, fieldValue.empty() ? Array<int32_t>{} : fieldValue.as<Array<int32_t>>());
      break;
    case BuiltInTypeId::UInt32:
      encoder.encode(limit, fieldValue.empty() ? Array<uint32_t>{} : fieldValue.as<Array<uint32_t>>());
      break;
    case BuiltInTypeId::Int64:
      encoder.encode(limit, fieldValue.empty() ? Array<int64_t>{} : fieldValue.as<Array<int64_t>>());
      break;
    case BuiltInTypeId::UInt64:
      encoder.encode(limit, fieldValue.empty() ? Array<uint64_t>{} : fieldValue.as<Array<uint64_t>>());
      break;
    case BuiltInTypeId::Float:
      encoder.encode(limit, fieldValue.empty() ? Array<float>{} : fieldValue.as<Array<float>>());
      break;
    case BuiltInTypeId::Double:
      encoder.encode(limit, fieldValue.empty() ? Array<double>{} : fieldValue.as<Array<double>>());
      break;
    case BuiltInTypeId::String:
      encoder.encode(limit, fieldValue.empty() ? Array<String>{} : fieldValue.as<Array<String>>());
      break;
    case BuiltInTypeId::DateTime:
      encoder.encode(limit, fieldValue.empty() ? Array<DateTime>{} : fieldValue.as<Array<DateTime>>());
      break;
    case BuiltInTypeId::Guid:
      encoder.encode(limit, fieldValue.empty() ? Array<Guid>{} : fieldValue.as<Array<Guid>>());
      break;
    case BuiltInTypeId::ByteString:
      encoder.encode(limit, fieldValue.empty() ? Array<ByteString>{} : fieldValue.as<Array<ByteString>>());
      break;
    case BuiltInTypeId::NodeId:
      encoder.encode(limit, fieldValue.empty() ? Array<NodeId>{} : fieldValue.as<Array<NodeId>>());
      break;
    case BuiltInTypeId::ExpandedNodeId:
      encoder.encode(
        limit, fieldValue.empty() ? Array<ExpandedNodeId>{} : fieldValue.as<Array<ExpandedNodeId>>());
      break;
    case BuiltInTypeId::StatusCode:
      encoder.encode(limit, fieldValue.empty() ? Array<StatusCode>{} : fieldValue.as<Array<StatusCode>>());
      break;
    case BuiltInTypeId::QualifiedName:
      encoder.encode(
        limit, fieldValue.empty() ? Array<QualifiedName>{} : fieldValue.as<Array<QualifiedName>>());
      break;
    case BuiltInTypeId::LocalizedText:
      encoder.encode(
        limit, fieldValue.empty() ? Array<LocalizedText>{} : fieldValue.as<Array<LocalizedText>>());
      break;
    case BuiltInTypeId::DataValue:
      encoder.encode(limit, fieldValue.empty() ? Array<DataValue>{} : fieldValue.as<Array<DataValue>>());
      break;
    case BuiltInTypeId::XmlElement:
      encoder.encode(limit, fieldValue.empty() ? Array<XmlElement>{} : fieldValue.as<Array<XmlElement>>());
      break;
    case BuiltInTypeId::Variant:
      encoder.encode(limit, fieldValue.empty() ? Array<Variant>{} : fieldValue.as<Array<Variant>>());
      break;
    case BuiltInTypeId::ExtensionObject:
    {
      // Array of structures - encode length + each element.
      if (fieldValue.empty())
      {
        encoder.encode(limit, int32_t{0});
      }
      else
      {
        auto& elements = fieldValue.as<Array<Variant>>();
        encoder.encode(limit, numeric_cast<int32_t>(elements.size()));
        for (const auto& element : elements)
        {
          if (element.is_structure())
          {
            encoder.encode(limit, element.as<Structure>());
          }
          else if (nestedDescriptor)
          {
            // Concrete element type with empty value - encode default inline
            auto nestedStructType = nestedDescriptor->structure_type();
            if (nestedStructType == StructureType::Union ||
                nestedStructType == StructureType::UnionWithSubtypedValues)
            {
              const DynamicUnion defaultInstance(nestedDescriptor);
              encoder.encode(limit, defaultInstance);
            }
            else
            {
              const DynamicStructure defaultInstance(nestedDescriptor);
              encoder.encode(limit, defaultInstance);
            }
          }
          else
          {
            encoder.encode(limit, static_cast<const Structure*>(nullptr));
          }
        }
      }
      break;
    }
    default:
      throw UaException(Status::BadEncodingError,
        ErrorDetail::build(
          "UnsupportedArrayType", "Unsupported array element type for dynamic field", "encode_dynamic_field")
          .context(ua::ContextKeys::typeName, to_string(builtInType)));
    }
    return;
  }

  encode_scalar_element(limit, fieldValue, builtInType, nestedDescriptor, encoder);
}

namespace
{

void encode_scalar_element(StackDepth limit, const Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, UaBinaryEncoder& encoder)
{
  switch (builtInType)
  {
  case BuiltInTypeId::Boolean:
    encoder.encode(limit, fieldValue.as<bool>());
    break;
  case BuiltInTypeId::SByte:
    encoder.encode(limit, fieldValue.as<int8_t>());
    break;
  case BuiltInTypeId::Byte:
    encoder.encode(limit, fieldValue.as<uint8_t>());
    break;
  case BuiltInTypeId::Int16:
    encoder.encode(limit, fieldValue.as<int16_t>());
    break;
  case BuiltInTypeId::UInt16:
    encoder.encode(limit, fieldValue.as<uint16_t>());
    break;
  case BuiltInTypeId::Int32:
    encoder.encode(limit, fieldValue.as<int32_t>());
    break;
  case BuiltInTypeId::UInt32:
    encoder.encode(limit, fieldValue.as<uint32_t>());
    break;
  case BuiltInTypeId::Int64:
    encoder.encode(limit, fieldValue.as<int64_t>());
    break;
  case BuiltInTypeId::UInt64:
    encoder.encode(limit, fieldValue.as<uint64_t>());
    break;
  case BuiltInTypeId::Float:
    encoder.encode(limit, fieldValue.as<float>());
    break;
  case BuiltInTypeId::Double:
    encoder.encode(limit, fieldValue.as<double>());
    break;
  case BuiltInTypeId::String:
    encoder.encode(limit, string_view(fieldValue.as<String>()));
    break;
  case BuiltInTypeId::DateTime:
    encoder.encode(limit, fieldValue.as<DateTime>());
    break;
  case BuiltInTypeId::Guid:
    encoder.encode(limit, fieldValue.as<Guid>());
    break;
  case BuiltInTypeId::ByteString:
    encoder.encode(limit, fieldValue.as<ByteString>());
    break;
  case BuiltInTypeId::XmlElement:
    encoder.encode(limit, fieldValue.as<XmlElement>());
    break;
  case BuiltInTypeId::NodeId:
    encoder.encode(limit, fieldValue.as<NodeId>());
    break;
  case BuiltInTypeId::ExpandedNodeId:
    encoder.encode(limit, fieldValue.as<ExpandedNodeId>());
    break;
  case BuiltInTypeId::StatusCode:
    encoder.encode(limit, fieldValue.as<StatusCode>());
    break;
  case BuiltInTypeId::QualifiedName:
    encoder.encode(limit, fieldValue.as<QualifiedName>());
    break;
  case BuiltInTypeId::LocalizedText:
    encoder.encode(limit, fieldValue.as<LocalizedText>());
    break;
  case BuiltInTypeId::DataValue:
    encoder.encode(limit, fieldValue.as<DataValue>());
    break;
  case BuiltInTypeId::Variant:
    encoder.encode(limit, fieldValue);
    break;
  case BuiltInTypeId::DiagnosticInfo:
    throw UaException(Status::BadEncodingError,
      make_error_detail(
        "UnsupportedFieldType", "DiagnosticInfo fields are not supported", "encode_dynamic_field"));
  case BuiltInTypeId::ExtensionObject:
    if (nestedDescriptor)
    {
      if (fieldValue.is_structure())
      {
        // Concrete nested type -- encode inline (no ExtensionObject wrapper)
        encoder.encode(limit, fieldValue.as<Structure>());
      }
      else
      {
        // Concrete nested type with empty/default value -- encode default-constructed instance inline.
        // Inline encoding has no null indicator; the decoder always reads inline for concrete types.
        auto nestedStructType = nestedDescriptor->structure_type();
        if (nestedStructType == StructureType::Union ||
            nestedStructType == StructureType::UnionWithSubtypedValues)
        {
          const DynamicUnion defaultInstance(nestedDescriptor);
          encoder.encode(limit, defaultInstance);
        }
        else
        {
          const DynamicStructure defaultInstance(nestedDescriptor);
          encoder.encode(limit, defaultInstance);
        }
      }
    }
    else if (fieldValue.is_structure())
    {
      // Abstract Structure field -- wrap in ExtensionObject
      encoder.encode(limit, fieldValue.as<Structure>().clone().get());
    }
    else
    {
      // Encode null extension object
      encoder.encode(limit, static_cast<const Structure*>(nullptr));
    }
    break;
  case BuiltInTypeId::Null:
    break;
  }
}

}  // namespace

void decode_dynamic_field(StackDepth limit, Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, int32_t valueRank,
  UaBinaryDecoder& decoder)
{
  if (valueRank >= 0)
  {
    // Array field: decode using the decoder's typed array support.
    switch (builtInType)
    {
      // clang-format off
#define DECODE_ARRAY(TYPE) { Array<TYPE> temp; decoder.decode(limit, temp); fieldValue = Variant{std::move(temp)}; break; }
    case BuiltInTypeId::Boolean: DECODE_ARRAY(bool)
    case BuiltInTypeId::SByte: DECODE_ARRAY(int8_t)
    case BuiltInTypeId::Byte: DECODE_ARRAY(uint8_t)
    case BuiltInTypeId::Int16: DECODE_ARRAY(int16_t)
    case BuiltInTypeId::UInt16: DECODE_ARRAY(uint16_t)
    case BuiltInTypeId::Int32: DECODE_ARRAY(int32_t)
    case BuiltInTypeId::UInt32: DECODE_ARRAY(uint32_t)
    case BuiltInTypeId::Int64: DECODE_ARRAY(int64_t)
    case BuiltInTypeId::UInt64: DECODE_ARRAY(uint64_t)
    case BuiltInTypeId::Float: DECODE_ARRAY(float)
    case BuiltInTypeId::Double: DECODE_ARRAY(double)
    case BuiltInTypeId::String: DECODE_ARRAY(String)
    case BuiltInTypeId::DateTime: DECODE_ARRAY(DateTime)
    case BuiltInTypeId::Guid: DECODE_ARRAY(Guid)
    case BuiltInTypeId::ByteString: DECODE_ARRAY(ByteString)
    case BuiltInTypeId::NodeId: DECODE_ARRAY(NodeId)
    case BuiltInTypeId::ExpandedNodeId: DECODE_ARRAY(ExpandedNodeId)
    case BuiltInTypeId::StatusCode: DECODE_ARRAY(StatusCode)
    case BuiltInTypeId::QualifiedName: DECODE_ARRAY(QualifiedName)
    case BuiltInTypeId::LocalizedText: DECODE_ARRAY(LocalizedText)
    case BuiltInTypeId::XmlElement: DECODE_ARRAY(XmlElement)
    case BuiltInTypeId::DataValue: DECODE_ARRAY(DataValue)
    case BuiltInTypeId::Variant: DECODE_ARRAY(Variant)
#undef DECODE_ARRAY
      // clang-format on
    case BuiltInTypeId::ExtensionObject:
    {
      // Array of structures - decode length + each element.
      int32_t length{};
      decoder.decode(limit, length);
      if (length <= 0)
      {
        fieldValue = Variant{};
      }
      else
      {
        // Enforce the same allocation cap the typed Array<T> decode applies (decode(Array<T>&) in
        // ua_binary_codec.h). This branch hand-rolls the element loop, so without the check it would
        // resize() to an attacker-supplied count (up to INT32_MAX) from a few wire bytes before
        // reading any element - an unbounded-allocation DoS.
        if (numeric_cast<size_t>(length) > decoder.max_array_length())
        {
          throw UaException(Status::BadEncodingLimitsExceeded,
            ErrorDetail::build(
              "EncodingLimitExceeded", "Array length exceeds maximum", "decode_dynamic_field")
              .context(ua::ContextKeys::sizeActual, std::to_string(length))
              .context(ua::ContextKeys::sizeMax, std::to_string(decoder.max_array_length())));
        }
        decoder.require_remaining_bytes(numeric_cast<size_t>(length));
        // A nested structure can hold further arrays: construct each element only as it is decoded.
        Array<Variant> elements;
        elements.payload().reserve(
          std::min(numeric_cast<size_t>(length), UaBinaryDecoder::aggregateArrayReserve));
        for (int32_t i = 0; i < length; ++i)
        {
          auto& slot = elements.payload().emplace_back();
          if (nestedDescriptor)
          {
            auto nestedStructType = nestedDescriptor->structure_type();
            unique_ptr<Structure> nested;
            if (nestedStructType == StructureType::Union ||
                nestedStructType == StructureType::UnionWithSubtypedValues)
            {
              nested = std::make_unique<DynamicUnion>(nestedDescriptor);
            }
            else
            {
              nested = std::make_unique<DynamicStructure>(nestedDescriptor);
            }
            decoder.decode(limit, *nested);
            slot = Variant{std::move(nested)};
          }
          else
          {
            unique_ptr<Structure> temp;
            decoder.decode(limit, temp);
            if (temp)
            {
              slot = Variant{std::move(temp)};
            }
          }
        }
        fieldValue = Variant{std::move(elements)};
      }
      break;
    }
    default:
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build(
          "UnsupportedArrayType", "Unsupported array element type for dynamic field", "decode_dynamic_field")
          .context(ua::ContextKeys::typeName, to_string(builtInType)));
    }
    return;
  }

  decode_scalar_element(limit, fieldValue, builtInType, nestedDescriptor, decoder);
}

namespace
{

void decode_scalar_element(StackDepth limit, Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, UaBinaryDecoder& decoder)
{
  switch (builtInType)
  {
  case BuiltInTypeId::Boolean:
  {
    bool temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::SByte:
  {
    int8_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Byte:
  {
    uint8_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Int16:
  {
    int16_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::UInt16:
  {
    uint16_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Int32:
  {
    int32_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::UInt32:
  {
    uint32_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Int64:
  {
    int64_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::UInt64:
  {
    uint64_t temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Float:
  {
    float temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Double:
  {
    double temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::String:
  {
    String temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::DateTime:
  {
    DateTime temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::Guid:
  {
    Guid temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{temp};
    break;
  }
  case BuiltInTypeId::ByteString:
  {
    ByteString temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::XmlElement:
  {
    XmlElement temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::NodeId:
  {
    NodeId temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::ExpandedNodeId:
  {
    ExpandedNodeId temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::StatusCode:
  {
    StatusCode temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::QualifiedName:
  {
    QualifiedName temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::LocalizedText:
  {
    LocalizedText temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::DataValue:
  {
    DataValue temp{};
    decoder.decode(limit, temp);
    fieldValue = Variant{std::move(temp)};
    break;
  }
  case BuiltInTypeId::Variant:
  {
    Variant temp{};
    decoder.decode(limit, temp);
    fieldValue = std::move(temp);
    break;
  }
  case BuiltInTypeId::DiagnosticInfo:
    throw UaException(Status::BadDecodingError,
      make_error_detail(
        "UnsupportedFieldType", "DiagnosticInfo fields are not supported", "decode_dynamic_field"));
  case BuiltInTypeId::ExtensionObject:
  {
    if (nestedDescriptor)
    {
      // Concrete nested type -- decode inline (no ExtensionObject wrapper)
      auto nestedStructType = nestedDescriptor->structure_type();
      unique_ptr<Structure> nested;
      if (nestedStructType == StructureType::Union ||
          nestedStructType == StructureType::UnionWithSubtypedValues)
      {
        nested = std::make_unique<DynamicUnion>(nestedDescriptor);
      }
      else
      {
        nested = std::make_unique<DynamicStructure>(nestedDescriptor);
      }
      decoder.decode(limit, *nested);
      fieldValue = Variant{std::move(nested)};
    }
    else
    {
      // Abstract Structure field -- decode as ExtensionObject
      unique_ptr<Structure> temp;
      decoder.decode(limit, temp);
      if (temp)
      {
        fieldValue = Variant{std::move(temp)};
      }
      else
      {
        fieldValue = Variant{};
      }
    }
    break;
  }
  case BuiltInTypeId::Null:
    break;
  }
}

}  // namespace

}  // namespace ua::detail
