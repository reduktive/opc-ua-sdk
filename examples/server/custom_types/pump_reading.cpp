// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "pump_reading.h"

#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_expanded_node_id.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_structure_field.h"
#include "ua_structure_type.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <string>
#include <tuple>
#include <utility>

namespace examples::pump
{
namespace
{
// Change these for your type.
// A custom DataType needs two nodes: the type itself, and one encoding node per encoding it offers.
// The identifiers are the server's to choose and only have to be unique within its namespace.
constexpr std::uint32_t typeIdentifier = 5001;
constexpr std::uint32_t encodingIdentifier = 5002;
constexpr std::string_view serialNumber = "PMP-1043";
constexpr double flowRate = 12.5;
constexpr double pressure = 4.25;
// An optional field: part of the type, but absent from a value unless that value says otherwise.
// This is how a type carries a field that only some instances have, without a sentinel value.
constexpr std::string_view optionalFieldName = "MaintenanceNote";
constexpr std::string_view maintenanceNote = "Impeller replaced 2026-08-14";

/// The field list that *is* the type: a name, a DataType, and a rank, in wire order.
///
/// Field order is part of the type. Adding a field in the middle changes what every existing encoded
/// value means, so a type that is already deployed is extended at the end or not at all.
std::shared_ptr<ua::StructureDefinition> pump_reading_definition(std::uint16_t namespaceIndex)
{
  auto definition = std::make_shared<ua::StructureDefinition>();
  // WithOptionalFields, not Structure: the encoding then carries a mask saying which optional
  // fields this particular value actually has.
  definition->structure_type() = ua::StructureType::StructureWithOptionalFields;
  definition->base_data_type() = ua::NodeId{ua::DataTypeId::Structure};
  definition->default_encoding_id() = ua::NodeId{namespaceIndex, encodingIdentifier};

  ua::Array<ua::StructureField> fields;
  for (const auto& [name, dataType, optional] :
    {std::tuple<std::string_view, ua::DataTypeId, bool>{"SerialNumber", ua::DataTypeId::String, false},
      std::tuple<std::string_view, ua::DataTypeId, bool>{"FlowRate", ua::DataTypeId::Double, false},
      std::tuple<std::string_view, ua::DataTypeId, bool>{"Pressure", ua::DataTypeId::Double, false},
      std::tuple<std::string_view, ua::DataTypeId, bool>{optionalFieldName, ua::DataTypeId::String, true}})
  {
    ua::StructureField field;
    field.name() = ua::String{std::string{name}};
    field.data_type() = ua::NodeId{dataType};
    field.value_rank() = -1;
    field.is_optional() = optional;
    fields.push_back(std::move(field));
  }
  definition->fields() = std::move(fields);
  return definition;
}

/// Builds one value of the custom type.
///
/// A `DynamicStructure` carries its fields in Variants against a shared, immutable descriptor, which
/// is how a value of a runtime-defined type exists at all in a program that was never compiled
/// against it. The server is in exactly the same position as the client here.
std::unique_ptr<ua::DynamicStructure> make_reading(
  std::uint16_t namespaceIndex, const std::shared_ptr<ua::StructureDefinition>& definition)
{
  auto descriptor =
    std::make_shared<const ua::DynamicStructureTypeDescriptor>(ua::String{std::string{typeName}},
      ua::ExpandedNodeId{ua::NodeId{namespaceIndex, typeIdentifier}, std::string{namespaceUri}},
      ua::ExpandedNodeId{ua::NodeId{namespaceIndex, encodingIdentifier}, std::string{namespaceUri}},
      *definition);

  auto reading = std::make_unique<ua::DynamicStructure>(std::move(descriptor));
  (*reading)["SerialNumber"] = ua::Variant{ua::String{std::string{serialNumber}}};
  (*reading)["FlowRate"] = ua::Variant{flowRate};
  (*reading)["Pressure"] = ua::Variant{pressure};
  // An optional field is absent until it is marked present. Assigning a value is not enough: the
  // presence mask is what a decoder reads, and a field nobody marked stays off the wire.
  reading->set_field_present(optionalFieldName, true);
  (*reading)[optionalFieldName] = ua::Variant{ua::String{std::string{maintenanceNote}}};
  return reading;
}

}  // namespace

/// Publishes the DataType node and the encoding node a client needs to make sense of a value.
///
/// Three references do the work. `HasSubtype` from `Structure` puts the type in the DataType
/// hierarchy, where a client browsing for types will find it. `HasEncoding` links the type to its
/// `Default Binary` encoding node. And the encoding node's `HasTypeDefinition` marks it as an
/// encoding rather than an ordinary Object. A type missing any of them is not discoverable.
std::shared_ptr<ua::StructureDefinition> publish_data_type(
  ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const auto definition = pump_reading_definition(namespaceIndex);
  const ua::NodeId typeId{namespaceIndex, typeIdentifier};
  ua::NodeAccessor typeNode = addressSpace.create_node_sync(typeId, ua::NodeClass::DataType);
  typeNode.set_browse_name(ua::QualifiedName{namespaceIndex, std::string{typeName}});
  typeNode.set_display_name(ua::LocalizedText{"", std::string{typeName}});
  ua::DataTypeAccessor dataType = typeNode.as<ua::DataTypeAccessor>().value();
  dataType.set_is_abstract(false);
  dataType.set_data_type_definition(definition);
  addressSpace.find_node_sync(ua::NodeId{ua::DataTypeId::Structure})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasSubtype}, typeId);

  const ua::NodeId encodingId{namespaceIndex, encodingIdentifier};
  ua::NodeAccessor encodingNode = addressSpace.create_node_sync(encodingId, ua::NodeClass::Object);
  encodingNode.set_browse_name(ua::QualifiedName{0, "Default Binary"});
  encodingNode.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::DataTypeEncodingType});
  typeNode.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasEncoding}, encodingId);
  // Both directions, explicitly. The address space does not materialise the inverse of a reference
  // you add, and a client resolving a value starts from the encoding id it found on the wire and
  // browses HasEncoding *backwards* to reach the DataType. Without this edge the type is published
  // and still undiscoverable, and the client decodes an opaque structure instead.
  encodingNode.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasEncoding}, ua::ExpandedNodeId{typeId}, false);
  return definition;
}

/// Adds a Variable whose value is one of these structures.
void add_reading_variable(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex,
  const std::shared_ptr<ua::StructureDefinition>& definition)
{
  const ua::NodeId pumpId{namespaceIndex, "Pump"};
  ua::NodeAccessor pump = addressSpace.create_node_sync(pumpId, ua::NodeClass::Object);
  pump.set_browse_name(ua::QualifiedName{namespaceIndex, "Pump"});
  pump.set_display_name(ua::LocalizedText{"", "Pump"});
  pump.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::FolderType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, pumpId);

  const ua::NodeId readingId{namespaceIndex, "Pump.Reading"};
  ua::VariableAccessor variable =
    addressSpace.create_node_sync(readingId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  variable.set_browse_name(ua::QualifiedName{namespaceIndex, "Reading"});
  variable.set_display_name(ua::LocalizedText{"", "Reading"});
  // The Variable's DataType names the custom type, so a client knows what to expect before reading.
  variable.set_data_type(ua::NodeId{namespaceIndex, typeIdentifier});
  variable.set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
  variable.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  pump.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, readingId);
  variable.write_value_sync(ua::Variant{make_reading(namespaceIndex, definition)});
}

}  // namespace examples::pump
