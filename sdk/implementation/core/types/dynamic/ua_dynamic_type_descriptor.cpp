// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_type_descriptor.h"
#include "ua_datatype_id.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "fmt/format.h"

namespace ua
{

DynamicStructureTypeDescriptor::DynamicStructureTypeDescriptor(String typeName, ExpandedNodeId typeId,
  ExpandedNodeId encodingId, StructureDefinition definition, NamespaceUriLookup nsLookup)
  : mTypeName(std::move(typeName)), mTypeId(std::move(typeId)), mEncodingId(std::move(encodingId)),
    mDefinition(std::move(definition))
{
  const auto& fields = mDefinition.fields();
  const size_t count = fields.size();

  mFieldBuiltInTypes.reserve(count);
  mFieldDataTypeExpanded.reserve(count);
  mNestedDescriptors.resize(count);

  for (size_t i = 0; i < count; ++i)
  {
    const auto& currentField = fields[i];
    mFieldNameIndex.emplace(string_view(currentField.name()), i);
    mFieldBuiltInTypes.push_back(data_type_to_built_in_type(currentField.data_type()));

    // Resolve field DataType to a URI-based ExpandedNodeId for non-zero namespaces when a
    // lookup is available; otherwise (namespace 0, or no lookup) keep the NodeId as-is.
    const auto& fieldDataType = currentField.data_type();
    if (fieldDataType.namespace_index() != 0 && nsLookup)
    {
      auto uri = nsLookup(fieldDataType.namespace_index());
      NodeId idPart = fieldDataType;
      idPart.namespace_index() = 0;
      mFieldDataTypeExpanded.emplace_back(std::move(idPart), static_cast<string_view>(uri));
    }
    else
    {
      mFieldDataTypeExpanded.emplace_back(fieldDataType);
    }
  }
}

DynamicStructureTypeDescriptor::DynamicStructureTypeDescriptor(
  String typeName, ExpandedNodeId typeId, ExpandedNodeId encodingId, StructureDefinition definition)
  : DynamicStructureTypeDescriptor(
      std::move(typeName), std::move(typeId), std::move(encodingId), std::move(definition), {})
{}

const String& DynamicStructureTypeDescriptor::type_name() const
{
  return mTypeName;
}

const ExpandedNodeId& DynamicStructureTypeDescriptor::type_id() const
{
  return mTypeId;
}

const ExpandedNodeId& DynamicStructureTypeDescriptor::encoding_id() const
{
  return mEncodingId;
}

StructureType DynamicStructureTypeDescriptor::structure_type() const
{
  return mDefinition.structure_type();
}

size_t DynamicStructureTypeDescriptor::field_count() const
{
  return mDefinition.fields().size();
}

const StructureField& DynamicStructureTypeDescriptor::field(size_t index) const
{
  if (index >= mDefinition.fields().size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "FieldIndexOutOfRange", "Field index is out of range", "DynamicStructureTypeDescriptor")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeMax, std::to_string(mDefinition.fields().size())));
  }
  return mDefinition.fields()[index];
}

std::optional<size_t> DynamicStructureTypeDescriptor::field_index(string_view name) const
{
  auto it = mFieldNameIndex.find(name);
  if (it == mFieldNameIndex.end())
  {
    return std::nullopt;
  }
  return it->second;
}

const ExpandedNodeId& DynamicStructureTypeDescriptor::field_data_type_expanded(size_t index) const
{
  if (index >= mFieldDataTypeExpanded.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "FieldIndexOutOfRange", "Field index is out of range", "DynamicStructureTypeDescriptor")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeMax, std::to_string(mFieldDataTypeExpanded.size())));
  }
  return mFieldDataTypeExpanded[index];
}

BuiltInTypeId DynamicStructureTypeDescriptor::field_built_in_type(size_t index) const
{
  if (index >= mFieldBuiltInTypes.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "FieldIndexOutOfRange", "Field index is out of range", "DynamicStructureTypeDescriptor")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeMax, std::to_string(mFieldBuiltInTypes.size())));
  }
  return mFieldBuiltInTypes[index];
}

void DynamicStructureTypeDescriptor::set_field_built_in_type(size_t index, BuiltInTypeId builtInType)
{
  if (index >= mFieldBuiltInTypes.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "FieldIndexOutOfRange", "Field index is out of range", "DynamicStructureTypeDescriptor")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeMax, std::to_string(mFieldBuiltInTypes.size())));
  }
  mFieldBuiltInTypes[index] = builtInType;
}

shared_ptr<const DynamicStructureTypeDescriptor> DynamicStructureTypeDescriptor::nested_descriptor(
  size_t fieldIndex) const
{
  if (fieldIndex >= mNestedDescriptors.size())
  {
    return nullptr;
  }
  return mNestedDescriptors[fieldIndex];
}

void DynamicStructureTypeDescriptor::resolve_nested(
  size_t fieldIndex, shared_ptr<const DynamicStructureTypeDescriptor> descriptor)
{
  if (fieldIndex < mNestedDescriptors.size())
  {
    mNestedDescriptors[fieldIndex] = std::move(descriptor);
  }
}

bool DynamicStructureTypeDescriptor::fully_resolved() const
{
  for (size_t i = 0; i < mFieldBuiltInTypes.size(); ++i)
  {
    if (mFieldBuiltInTypes[i] == BuiltInTypeId::ExtensionObject && !mNestedDescriptors[i])
    {
      return false;
    }
  }
  return true;
}

const StructureDefinition& DynamicStructureTypeDescriptor::definition() const
{
  return mDefinition;
}

BuiltInTypeId DynamicStructureTypeDescriptor::data_type_to_built_in_type(const NodeId& dataType)
{
  // Only NS0 numeric NodeIds have a standard mapping to built-in types.
  if (dataType.namespace_index() != 0 || !dataType.is_numeric())
  {
    return BuiltInTypeId::ExtensionObject;
  }

  const uint32_t id = dataType.identifier().get_numeric();

  switch (id)
  {
  case utils::to_underlying(DataTypeId::Boolean):
    return BuiltInTypeId::Boolean;
  case utils::to_underlying(DataTypeId::SByte):
    return BuiltInTypeId::SByte;
  case utils::to_underlying(DataTypeId::Byte):
    return BuiltInTypeId::Byte;
  case utils::to_underlying(DataTypeId::Int16):
    return BuiltInTypeId::Int16;
  case utils::to_underlying(DataTypeId::UInt16):
    return BuiltInTypeId::UInt16;
  case utils::to_underlying(DataTypeId::Int32):
    return BuiltInTypeId::Int32;
  case utils::to_underlying(DataTypeId::UInt32):
    return BuiltInTypeId::UInt32;
  case utils::to_underlying(DataTypeId::Int64):
    return BuiltInTypeId::Int64;
  case utils::to_underlying(DataTypeId::UInt64):
    return BuiltInTypeId::UInt64;
  case utils::to_underlying(DataTypeId::Float):
    return BuiltInTypeId::Float;
  case utils::to_underlying(DataTypeId::Double):
    return BuiltInTypeId::Double;
  case utils::to_underlying(DataTypeId::String):
    return BuiltInTypeId::String;
  case utils::to_underlying(DataTypeId::DateTime):
    return BuiltInTypeId::DateTime;
  case utils::to_underlying(DataTypeId::Guid):
    return BuiltInTypeId::Guid;
  case utils::to_underlying(DataTypeId::ByteString):
    return BuiltInTypeId::ByteString;
  case utils::to_underlying(DataTypeId::XmlElement):
    return BuiltInTypeId::XmlElement;
  case utils::to_underlying(DataTypeId::NodeId):
    return BuiltInTypeId::NodeId;
  case utils::to_underlying(DataTypeId::ExpandedNodeId):
    return BuiltInTypeId::ExpandedNodeId;
  case utils::to_underlying(DataTypeId::StatusCode):
    return BuiltInTypeId::StatusCode;
  case utils::to_underlying(DataTypeId::QualifiedName):
    return BuiltInTypeId::QualifiedName;
  case utils::to_underlying(DataTypeId::LocalizedText):
    return BuiltInTypeId::LocalizedText;
  case utils::to_underlying(DataTypeId::Structure):
    return BuiltInTypeId::ExtensionObject;
  case utils::to_underlying(DataTypeId::DataValue):
    return BuiltInTypeId::DataValue;
  case utils::to_underlying(DataTypeId::BaseDataType):
    return BuiltInTypeId::Variant;
  case utils::to_underlying(DataTypeId::DiagnosticInfo):
    return BuiltInTypeId::DiagnosticInfo;

  // Abstract numeric types map to their widest concrete type
  case utils::to_underlying(DataTypeId::Number):
    return BuiltInTypeId::Double;
  case utils::to_underlying(DataTypeId::Integer):
    return BuiltInTypeId::Int64;
  case utils::to_underlying(DataTypeId::UInteger):
    return BuiltInTypeId::UInt64;
  case utils::to_underlying(DataTypeId::Enumeration):
    return BuiltInTypeId::Int32;

  default:
    // Unknown NS0 type - treat as structure (ExtensionObject)
    return BuiltInTypeId::ExtensionObject;
  }
}

}  // namespace ua
