// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_union.h"
#include "ua_data_value.h"
#include "ua_dynamic_field_codec.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "fmt/format.h"

namespace ua
{

DynamicUnion::DynamicUnion(shared_ptr<const DynamicStructureTypeDescriptor> descriptor)
  : mDescriptor(std::move(descriptor))
{
  auto structType = mDescriptor->structure_type();
  if (structType != StructureType::Union && structType != StructureType::UnionWithSubtypedValues)
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidStructureType",
        "DynamicUnion requires StructureType::Union or UnionWithSubtypedValues",
        "DynamicUnion")
        .context(ua::ContextKeys::actual, std::to_string(utils::to_underlying(structType))));
  }

  const size_t count = mDescriptor->field_count();
  mFields.reserve(count);
  for (size_t i = 0; i < count; ++i)
  {
    mFields.push_back(detail::make_default_field_value(
      mDescriptor->field_built_in_type(i), mDescriptor->field(i).value_rank()));
  }
}

DynamicUnion::DynamicUnion(const DynamicUnion& other)
  : Union(other), mDescriptor(other.mDescriptor), mFields(other.mFields), mSwitchField(other.mSwitchField)
{}

DynamicUnion& DynamicUnion::operator=(const DynamicUnion& other)
{
  if (this != &other)
  {
    mDescriptor = other.mDescriptor;
    mFields = other.mFields;
    mSwitchField = other.mSwitchField;
  }
  return *this;
}

bool DynamicUnion::operator==(const DynamicUnion& other) const
{
  return mDescriptor.get() == other.mDescriptor.get() && mSwitchField == other.mSwitchField &&
         mFields == other.mFields;
}

uint32_t DynamicUnion::switch_field() const
{
  return mSwitchField;
}

uint32_t DynamicUnion::field_count() const
{
  return numeric_cast<uint32_t>(mFields.size());
}

void DynamicUnion::clear()
{
  mSwitchField = 0;
}

bool DynamicUnion::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  const NodeId myTypeId{ns.getNamespaceIndex(mDescriptor->type_id().namespace_uri()),
    mDescriptor->type_id().node_id().identifier().get_numeric()};
  if (dataTypeId == myTypeId)
  {
    return true;
  }
  return Union::is_of_type(ns, dataTypeId);
}

NodeId DynamicUnion::type_id(const CodecNamespaceContext& ns) const
{
  const auto& expandedId = mDescriptor->type_id();
  if (ns.getNamespaceIndex)
  {
    return NodeId{
      ns.getNamespaceIndex(expandedId.namespace_uri()), expandedId.node_id().identifier().get_numeric()};
  }
  return expandedId.node_id();
}

ExpandedNodeId DynamicUnion::type_id() const
{
  return mDescriptor->type_id();
}

String DynamicUnion::type_name() const
{
  return mDescriptor->type_name();
}

void DynamicUnion::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
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

void DynamicUnion::encode(StackDepth limit, Encoder& encoder) const
{
  Structure::encode(limit, encoder);

  auto* binary = encoder.get_ua_binary();
  if (!binary)
  {
    throw UaException(Status::BadEncodingError,
      ErrorDetail::build(
        "UnsupportedEncoding", "DynamicUnion only supports UA Binary encoding", "DynamicUnion")
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name()))
        .context(ua::ContextKeys::encoding, "UA Binary"));
  }

  // Write the switch field (uint32_t)
  binary->encode(limit, mSwitchField);

  // If a field is selected, encode it
  if (mSwitchField > 0 && mSwitchField <= numeric_cast<uint32_t>(mFields.size()))
  {
    const size_t index = mSwitchField - 1;
    detail::encode_dynamic_field(limit,
      mFields[index],
      mDescriptor->field_built_in_type(index),
      mDescriptor->nested_descriptor(index),
      mDescriptor->field(index).value_rank(),
      *binary);
  }
}

void DynamicUnion::decode(StackDepth limit, Decoder& decoder)
{
  Structure::decode(limit, decoder);

  auto* binary = decoder.get_ua_binary();
  if (!binary)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "UnsupportedDecoding", "DynamicUnion only supports UA Binary decoding", "DynamicUnion")
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name()))
        .context(ua::ContextKeys::encoding, "UA Binary"));
  }

  // Read the switch field
  binary->decode(limit, mSwitchField);

  // If a field is selected, decode it
  if (mSwitchField > 0 && mSwitchField <= numeric_cast<uint32_t>(mFields.size()))
  {
    const size_t index = mSwitchField - 1;
    detail::decode_dynamic_field(limit,
      mFields[index],
      mDescriptor->field_built_in_type(index),
      mDescriptor->nested_descriptor(index),
      mDescriptor->field(index).value_rank(),
      *binary);
  }
}

unique_ptr<Structure> DynamicUnion::clone() const
{
  return make_unique<DynamicUnion>(*this);
}

std::string DynamicUnion::to_string(int indent) const
{
  std::string result;
  const std::string indentStr(numeric_cast<size_t>(indent), ' ');
  result += indentStr + std::string(mDescriptor->type_name()) + " (Union) {\n";

  if (mSwitchField == 0)
  {
    result += indentStr + "  <null>\n";
  }
  else if (mSwitchField <= numeric_cast<uint32_t>(mFields.size()))
  {
    const size_t index = mSwitchField - 1;
    const auto& fieldDef = mDescriptor->field(index);
    result += indentStr + "  " + std::string(fieldDef.name()) + ": ";

    if (mFields[index].is_structure())
    {
      result += mFields[index].as<Structure>().to_string(indent + 2);
    }
    else
    {
      result += "<value>";
    }
    result += "\n";
  }

  result += indentStr + "}";
  return result;
}

const Variant& DynamicUnion::value() const
{
  if (mSwitchField == 0)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("NullUnion", "Cannot get value of null union (no field selected)", "DynamicUnion")
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name())));
  }
  return mFields[mSwitchField - 1];
}

void DynamicUnion::select(string_view name, Variant fieldValue)
{
  const size_t index = require_field_index(name);
  mFields[index] = std::move(fieldValue);
  mSwitchField = numeric_cast<uint32_t>(index + 1);
}

void DynamicUnion::select(size_t index, Variant fieldValue)
{
  if (index >= mFields.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("FieldIndexOutOfRange", "Field index is out of range", "DynamicUnion")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeActual, std::to_string(mFields.size())));
  }
  mFields[index] = std::move(fieldValue);
  mSwitchField = numeric_cast<uint32_t>(index + 1);
}

string_view DynamicUnion::active_field_name() const
{
  if (mSwitchField == 0 || mSwitchField > numeric_cast<uint32_t>(mFields.size()))
  {
    return {};
  }
  return mDescriptor->field(mSwitchField - 1).name();
}

const DynamicStructureTypeDescriptor& DynamicUnion::descriptor() const
{
  return *mDescriptor;
}

size_t DynamicUnion::require_field_index(string_view name) const
{
  auto idx = mDescriptor->field_index(name);
  if (!idx.has_value())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("FieldNotFound", "Field not found in type", "DynamicUnion")
        .context(ua::ContextKeys::fieldName, std::string(name))
        .context(ua::ContextKeys::typeName, std::string(mDescriptor->type_name())));
  }
  return idx.value();
}

}  // namespace ua
