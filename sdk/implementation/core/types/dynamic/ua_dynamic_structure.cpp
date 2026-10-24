// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_structure.h"
#include "ua_data_value.h"
#include "ua_dynamic_field_codec.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "fmt/format.h"

namespace
{

/// The EncodingMask is a UInt32 (Part 6 section 5.2.7): a descriptor with more than 32 optional fields
/// cannot be encoded, and shifting by 32 or more is undefined.
uint32_t optional_field_bit(uint32_t optionalBitIndex)
{
  if (optionalBitIndex >= 32)
  {
    throw ua::UaException(ua::Status::BadEncodingLimitsExceeded,
      ua::ErrorDetail::build("TooManyOptionalFields",
        "A structure may not declare more than 32 optional fields",
        "DynamicStructure")
        .context(ua::ContextKeys::index, std::to_string(optionalBitIndex)));
  }
  return 1u << optionalBitIndex;
}

}  // namespace

namespace ua
{

namespace
{

bool is_optional_field(const DynamicStructureTypeDescriptor& descriptor, const StructureField& field) noexcept
{
  return descriptor.structure_type() == StructureType::StructureWithOptionalFields && field.is_optional();
}

}  // namespace

DynamicStructure::DynamicStructure(shared_ptr<const DynamicStructureTypeDescriptor> descriptor)
  : mDescriptor(std::move(descriptor))
{
  const size_t count = mDescriptor->field_count();
  mFields.reserve(count);
  for (size_t i = 0; i < count; ++i)
  {
    mFields.push_back(detail::make_default_field_value(
      mDescriptor->field_built_in_type(i), mDescriptor->field(i).value_rank()));
  }
}

DynamicStructure::DynamicStructure(const DynamicStructure& other)
  : Structure(other), mDescriptor(other.mDescriptor), mFields(other.mFields),
    mEncodingMask(other.mEncodingMask)
{}

DynamicStructure& DynamicStructure::operator=(const DynamicStructure& other)
{
  if (this != &other)
  {
    mDescriptor = other.mDescriptor;
    mFields = other.mFields;
    mEncodingMask = other.mEncodingMask;
  }
  return *this;
}

bool DynamicStructure::operator==(const DynamicStructure& other) const
{
  return mDescriptor.get() == other.mDescriptor.get() && mEncodingMask == other.mEncodingMask &&
         mFields == other.mFields;
}

bool DynamicStructure::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  const NodeId myTypeId{ns.getNamespaceIndex(mDescriptor->type_id().namespace_uri()),
    mDescriptor->type_id().node_id().identifier().get_numeric()};
  if (dataTypeId == myTypeId)
  {
    return true;
  }
  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DynamicStructure::type_id(const CodecNamespaceContext& ns) const
{
  const auto& expandedId = mDescriptor->type_id();
  if (ns.getNamespaceIndex)
  {
    return NodeId{
      ns.getNamespaceIndex(expandedId.namespace_uri()), expandedId.node_id().identifier().get_numeric()};
  }
  return expandedId.node_id();
}

ExpandedNodeId DynamicStructure::type_id() const
{
  return mDescriptor->type_id();
}

String DynamicStructure::type_name() const
{
  return mDescriptor->type_name();
}

void DynamicStructure::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{
  auto* binary = encoder.get_ua_binary();
  if (binary)
  {
    const auto& encodingId = mDescriptor->encoding_id();
    if (ns.getNamespaceIndex)
    {
      const NodeId localId{
        ns.getNamespaceIndex(encodingId.namespace_uri()), encodingId.node_id().identifier().get_numeric()};
      binary->encode(limit, localId);
    }
    else
    {
      binary->encode(limit, encodingId.node_id());
    }
  }
}

void DynamicStructure::encode(StackDepth limit, Encoder& encoder) const
{
  Structure::encode(limit, encoder);

  auto* binary = encoder.get_ua_binary();
  if (!binary)
  {
    throw UaException(Status::BadEncodingError,
      ErrorDetail::build(
        "UnsupportedEncoding", "DynamicStructure only supports UA Binary encoding", "DynamicStructure")
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name())));
  }

  // For StructureWithOptionalFields: write the encoding mask
  if (mDescriptor->structure_type() == StructureType::StructureWithOptionalFields)
  {
    binary->encode(limit, mEncodingMask);
  }

  // Track the optional field bit position
  uint32_t optionalBitIndex = 0;

  for (size_t i = 0; i < mDescriptor->field_count(); ++i)
  {
    const auto& fieldDef = mDescriptor->field(i);
    const bool isOptional = is_optional_field(*mDescriptor, fieldDef);

    if (isOptional)
    {
      const uint32_t bitMask = optional_field_bit(optionalBitIndex);
      ++optionalBitIndex;

      if ((mEncodingMask & bitMask) == 0)
      {
        // Optional field not present - skip encoding
        continue;
      }
    }

    detail::encode_dynamic_field(limit,
      mFields[i],
      mDescriptor->field_built_in_type(i),
      mDescriptor->nested_descriptor(i),
      mDescriptor->field(i).value_rank(),
      *binary);
  }
}

void DynamicStructure::decode(StackDepth limit, Decoder& decoder)
{
  Structure::decode(limit, decoder);

  auto* binary = decoder.get_ua_binary();
  if (!binary)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "UnsupportedDecoding", "DynamicStructure only supports UA Binary decoding", "DynamicStructure")
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name())));
  }

  // For StructureWithOptionalFields: read the encoding mask
  if (mDescriptor->structure_type() == StructureType::StructureWithOptionalFields)
  {
    binary->decode(limit, mEncodingMask);
  }

  // Track the optional field bit position
  uint32_t optionalBitIndex = 0;

  for (size_t i = 0; i < mDescriptor->field_count(); ++i)
  {
    const auto& fieldDef = mDescriptor->field(i);
    const bool isOptional = is_optional_field(*mDescriptor, fieldDef);

    if (isOptional)
    {
      const uint32_t bitMask = optional_field_bit(optionalBitIndex);
      ++optionalBitIndex;

      if ((mEncodingMask & bitMask) == 0)
      {
        // Optional field not present - reset to default
        mFields[i] =
          detail::make_default_field_value(mDescriptor->field_built_in_type(i), fieldDef.value_rank());
        continue;
      }
    }

    detail::decode_dynamic_field(limit,
      mFields[i],
      mDescriptor->field_built_in_type(i),
      mDescriptor->nested_descriptor(i),
      fieldDef.value_rank(),
      *binary);
  }
}

unique_ptr<Structure> DynamicStructure::clone() const
{
  return make_unique<DynamicStructure>(*this);
}

std::string DynamicStructure::to_string(int indent) const
{
  std::string result;
  const std::string indentStr(numeric_cast<size_t>(indent), ' ');
  result += indentStr + std::string(mDescriptor->type_name()) + " {\n";

  uint32_t optionalBitIndex = 0;
  for (size_t i = 0; i < mDescriptor->field_count(); ++i)
  {
    const auto& fieldDef = mDescriptor->field(i);
    const bool isOptional = is_optional_field(*mDescriptor, fieldDef);
    bool isPresent = true;

    if (isOptional)
    {
      const uint32_t bitMask = optional_field_bit(optionalBitIndex);
      ++optionalBitIndex;
      isPresent = (mEncodingMask & bitMask) != 0;
    }

    result += indentStr + "  " + std::string(fieldDef.name()) + ": ";

    if (isOptional && !isPresent)
    {
      result += "<absent>";
    }
    else if (mFields[i].is_structure())
    {
      result += mFields[i].as<Structure>().to_string(indent + 2);
    }
    else
    {
      // simple (non-structure) fields: emit a fixed placeholder; we do not stringify the scalar payload here
      result += "<value>";
    }
    result += "\n";
  }

  result += indentStr + "}";
  return result;
}

Variant& DynamicStructure::operator[](string_view name)
{
  return mFields[require_field_index(name)];
}

const Variant& DynamicStructure::operator[](string_view name) const
{
  return mFields[require_field_index(name)];
}

Variant& DynamicStructure::field(size_t index)
{
  if (index >= mFields.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("FieldIndexOutOfRange", "Field index is out of range", "DynamicStructure")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeMax, std::to_string(mFields.size())));
  }
  return mFields[index];
}

const Variant& DynamicStructure::field(size_t index) const
{
  if (index >= mFields.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("FieldIndexOutOfRange", "Field index is out of range", "DynamicStructure")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeMax, std::to_string(mFields.size())));
  }
  return mFields[index];
}

bool DynamicStructure::has_field(string_view name) const
{
  auto idx = mDescriptor->field_index(name);
  if (!idx.has_value())
  {
    return false;
  }

  // For non-optional fields, they are always present
  const auto& fieldDef = mDescriptor->field(idx.value());
  if (!is_optional_field(*mDescriptor, fieldDef))
  {
    return true;
  }

  // Count optional fields up to and including this one to find the bit position
  uint32_t optionalBitIndex = 0;
  for (size_t i = 0; i <= idx.value(); ++i)
  {
    if (is_optional_field(*mDescriptor, mDescriptor->field(i)))
    {
      if (i == idx.value())
      {
        const uint32_t bitMask = optional_field_bit(optionalBitIndex);
        return (mEncodingMask & bitMask) != 0;
      }
      ++optionalBitIndex;
    }
  }

  return false;
}

void DynamicStructure::set_field_present(string_view name, bool present)
{
  const size_t fieldIdx = require_field_index(name);
  const auto& fieldDef = mDescriptor->field(fieldIdx);

  if (!is_optional_field(*mDescriptor, fieldDef))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "FieldNotOptional", "Field is not optional and cannot have its presence changed", "DynamicStructure")
        .context(ua::ContextKeys::fieldName, std::string(name)));
  }

  // Count optional fields up to this one
  uint32_t optionalBitIndex = 0;
  for (size_t i = 0; i < fieldIdx; ++i)
  {
    if (is_optional_field(*mDescriptor, mDescriptor->field(i)))
    {
      ++optionalBitIndex;
    }
  }

  const uint32_t bitMask = optional_field_bit(optionalBitIndex);
  if (present)
  {
    mEncodingMask |= bitMask;
  }
  else
  {
    mEncodingMask &= ~bitMask;
  }
}

const DynamicStructureTypeDescriptor& DynamicStructure::descriptor() const
{
  return *mDescriptor;
}

size_t DynamicStructure::field_count() const
{
  return mFields.size();
}

size_t DynamicStructure::require_field_index(string_view name) const
{
  auto idx = mDescriptor->field_index(name);
  if (!idx.has_value())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("FieldNotFound", "Field not found in type", "DynamicStructure")
        .context(ua::ContextKeys::fieldName, std::string(name))
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name())));
  }
  return idx.value();
}

}  // namespace ua
