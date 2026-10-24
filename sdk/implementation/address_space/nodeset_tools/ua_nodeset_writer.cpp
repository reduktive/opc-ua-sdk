// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_nodeset_writer.h"

#include <fmt/core.h>

#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_memory_stream.h"
#include "ua_resource_budgets.h"
#include "ua_stream.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_structure_type.h"
#include "ua_utilities.h"
#include "ua_xml_codec.h"

namespace ua::xml::nodeset
{

namespace
{

// The OPC UA XML "Types.xsd" namespace, declared as the default xmlns on a `<Value>` so the value
// content emitted by `XmlEncoder` (unprefixed element names) is correctly namespaced for external
// tooling, without changing the codec.
constexpr string_view typesNamespaceUri = "http://opcfoundation.org/UA/2008/02/Types.xsd";

}  // namespace

NodeSetWriter::NodeSetWriter(Stream& stream, EncodingLimits limits, NodeSetWriterOptions options)
  : mStream(stream), mLimits(limits), mOptions(std::move(options)), mWriter(stream)
{
  for (const auto& [nodeId, alias] : mOptions.aliases)
  {
    mAliasByServerId.emplace(nodeId, alias);
  }
}

string_view NodeSetWriter::element_for_class(NodeClass nodeClass)
{
  switch (nodeClass)
  {
  case NodeClass::Object:
    return "UAObject";
  case NodeClass::Variable:
    return "UAVariable";
  case NodeClass::Method:
    return "UAMethod";
  case NodeClass::ObjectType:
    return "UAObjectType";
  case NodeClass::VariableType:
    return "UAVariableType";
  case NodeClass::ReferenceType:
    return "UAReferenceType";
  case NodeClass::DataType:
    return "UADataType";
  case NodeClass::View:
    return "UAView";
  default:
    // Unspecified should not occur for a real node; emit a generic object element rather than throw.
    return "UAObject";
  }
}

std::string NodeSetWriter::file_node_id(const NodeId& nodeId) const
{
  const uint16_t fileIndex = mOptions.serverToFileIndex(nodeId.namespace_index());
  std::string out = fileIndex != 0 ? fmt::format("ns={};", fileIndex) : std::string{};

  if (nodeId.is_numeric())
  {
    out += fmt::format("i={}", nodeId.identifier().get_numeric());
  }
  else if (nodeId.is_string())
  {
    out += "s=";
    out += static_cast<string_view>(nodeId.identifier().get_string());
  }
  else if (nodeId.is_guid())
  {
    out += "g=";
    out += static_cast<string_view>(nodeId.identifier().get_guid().as_string());
  }
  else if (nodeId.is_opaque())
  {
    out += "b=";
    out += utils::base64_encode(nodeId.identifier().get_opaque());
  }
  return out;
}

std::string NodeSetWriter::file_node_id(const ExpandedNodeId& nodeId) const
{
  // Local cross-namespace targets carry the right server index in their inner NodeId; remap it.
  // (Remote, server-qualified targets are out of scope for this phase.)
  return file_node_id(nodeId.node_id());
}

std::string NodeSetWriter::file_id_or_alias(const NodeId& nodeId) const
{
  const auto entry = mAliasByServerId.find(nodeId);
  if (entry != mAliasByServerId.end())
  {
    return std::string{static_cast<string_view>(entry->second)};
  }
  return file_node_id(nodeId);
}

std::string NodeSetWriter::file_qualified_name(const QualifiedName& browseName) const
{
  const uint16_t fileIndex = mOptions.serverToFileIndex(browseName.namespace_index());
  const string_view name = static_cast<string_view>(browseName.name());
  if (fileIndex != 0)
  {
    return fmt::format("{}:{}", fileIndex, name);
  }
  return std::string{name};
}

void NodeSetWriter::write_localized_texts(string_view element, const std::vector<LocalizedText>& texts)
{
  for (const auto& localizedText : texts)
  {
    mWriter.start_element(element);
    const string_view locale = static_cast<string_view>(localizedText.locale());
    if (!locale.empty())
    {
      mWriter.attribute("Locale", locale);
    }
    mWriter.text(static_cast<string_view>(localizedText.text()));
    mWriter.end_element(element);
  }
}

void NodeSetWriter::write_references(const std::vector<ExportedReference>& references)
{
  if (references.empty())
  {
    return;
  }
  mWriter.start_element("References");
  for (const auto& reference : references)
  {
    mWriter.start_element("Reference");
    mWriter.attribute("ReferenceType", file_id_or_alias(reference.referenceTypeId));
    mWriter.attribute("IsForward", reference.isForward ? "true" : "false");
    mWriter.text(file_node_id(reference.targetId));
    mWriter.end_element("Reference");
  }
  mWriter.end_element("References");
}

void NodeSetWriter::write_value(const Variant& value)
{
  // Encode the value content (unprefixed typed elements) into a SCRATCH buffer first, so a failure to
  // transcode (an unresolved opaque binary-bodied ExtensionObject) is handled before any `<Value>`
  // markup is emitted. Per the failOnUnencodableStructure policy the failure either propagates (the
  // document is abandoned) or the `<Value>` is silently omitted while the rest of the node stands.
  memory_stream_device::Dynamic device;
  MemoryStream temp(device);
  XmlEncoder encoder(mOptions.valueContext, temp);
  const StackDepth limit = mLimits.stack_depth();
  try
  {
    encoder.encode(limit, "", value);
  }
  catch (const std::exception&)
  {
    if (mOptions.failOnUnencodableStructure)
    {
      throw;
    }
    return;
  }

  const auto data = device.get_data();
  const string_view content{reinterpret_cast<const char*>(data.data()), data.size()};

  mWriter.start_element("Value");
  mWriter.attribute("xmlns", typesNamespaceUri);
  mWriter.raw(content);
  mWriter.end_element("Value");
}

void NodeSetWriter::write_definition(const ExportedNode& node)
{
  if (!node.dataTypeDefinition)
  {
    return;
  }
  const auto* structure = dynamic_cast<const StructureDefinition*>(node.dataTypeDefinition.get());
  const auto* enumeration = dynamic_cast<const EnumDefinition*>(node.dataTypeDefinition.get());
  if (structure == nullptr && enumeration == nullptr)
  {
    return;
  }

  mWriter.start_element("Definition");
  // The `<Definition>` Name mirrors the DataType's (unprefixed) browse name, as standard NodeSet2
  // files emit it.
  mWriter.attribute("Name", static_cast<string_view>(node.browseName.name()));

  if (structure != nullptr)
  {
    const StructureType structureType = structure->structure_type();
    if (structureType == StructureType::Union || structureType == StructureType::UnionWithSubtypedValues)
    {
      mWriter.attribute("IsUnion", "true");
    }
    for (const auto& field : structure->fields())
    {
      mWriter.start_element("Field");
      mWriter.attribute("Name", static_cast<string_view>(field.name()));
      mWriter.attribute("DataType", file_id_or_alias(field.data_type()));
      if (field.value_rank() != -1)
      {
        mWriter.attribute("ValueRank", fmt::format("{}", field.value_rank()));
      }
      if (field.array_dimensions().size() != 0)
      {
        std::string dimensions;
        for (std::size_t i = 0; i < field.array_dimensions().size(); ++i)
        {
          if (i != 0)
          {
            dimensions += ',';
          }
          dimensions += fmt::format("{}", field.array_dimensions()[i]);
        }
        mWriter.attribute("ArrayDimensions", dimensions);
      }
      if (field.is_optional())
      {
        mWriter.attribute("IsOptional", "true");
      }
      if (!static_cast<string_view>(field.description().text()).empty())
      {
        write_localized_texts("Description", {field.description()});
      }
      mWriter.end_element("Field");
    }
  }
  else
  {
    for (const auto& field : enumeration->fields())
    {
      mWriter.start_element("Field");
      mWriter.attribute("Name", static_cast<string_view>(field.name()));
      mWriter.attribute("Value", fmt::format("{}", field.value()));
      if (!static_cast<string_view>(field.display_name().text()).empty())
      {
        write_localized_texts("DisplayName", {field.display_name()});
      }
      if (!static_cast<string_view>(field.description().text()).empty())
      {
        write_localized_texts("Description", {field.description()});
      }
      mWriter.end_element("Field");
    }
  }

  mWriter.end_element("Definition");
}

void NodeSetWriter::begin_document()
{
  mWriter.write_declaration();
  mWriter.start_element("UANodeSet");
  mWriter.attribute("xmlns", "http://opcfoundation.org/UA/2011/03/UANodeSet.xsd");
  mWriter.attribute("xmlns:uax", typesNamespaceUri);
  mWriter.attribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
  if (mOptions.lastModified)
  {
    mWriter.attribute("LastModified", static_cast<string_view>(mOptions.lastModified->as_iso_string()));
  }

  if (!mOptions.namespaceUris.empty())
  {
    mWriter.start_element("NamespaceUris");
    for (const auto& uri : mOptions.namespaceUris)
    {
      mWriter.start_element("Uri");
      mWriter.text(static_cast<string_view>(uri));
      mWriter.end_element("Uri");
    }
    mWriter.end_element("NamespaceUris");
  }

  if (!mOptions.models.empty())
  {
    mWriter.start_element("Models");
    for (const auto& model : mOptions.models)
    {
      mWriter.start_element("Model");
      mWriter.attribute("ModelUri", static_cast<string_view>(model.modelUri));
      mWriter.attribute("Version", static_cast<string_view>(model.version));
      mWriter.attribute("PublicationDate", static_cast<string_view>(model.publicationDate.as_iso_string()));
      for (const auto& required : model.requiredModels)
      {
        mWriter.start_element("RequiredModel");
        mWriter.attribute("ModelUri", static_cast<string_view>(required.modelUri));
        mWriter.attribute("Version", static_cast<string_view>(required.version));
        mWriter.attribute(
          "PublicationDate", static_cast<string_view>(required.publicationDate.as_iso_string()));
        mWriter.end_element("RequiredModel");
      }
      mWriter.end_element("Model");
    }
    mWriter.end_element("Models");
  }

  if (!mOptions.aliases.empty())
  {
    mWriter.start_element("Aliases");
    for (const auto& [nodeId, alias] : mOptions.aliases)
    {
      mWriter.start_element("Alias");
      mWriter.attribute("Alias", static_cast<string_view>(alias));
      mWriter.text(file_node_id(nodeId));
      mWriter.end_element("Alias");
    }
    mWriter.end_element("Aliases");
  }
}

void NodeSetWriter::write_node(const ExportedNode& node)
{
  const string_view element = element_for_class(node.nodeClass);
  mWriter.start_element(element);

  // Attributes (NodeSet2 schema order: identity first, then class-specific).
  mWriter.attribute("NodeId", file_node_id(node.nodeId));
  mWriter.attribute("BrowseName", file_qualified_name(node.browseName));
  if (node.writeMask && *node.writeMask != 0)
  {
    mWriter.attribute("WriteMask", fmt::format("{}", *node.writeMask));
  }
  if (node.isAbstract && *node.isAbstract)
  {
    mWriter.attribute("IsAbstract", "true");
  }
  if (node.symmetric && *node.symmetric)
  {
    mWriter.attribute("Symmetric", "true");
  }
  if (node.dataType)
  {
    mWriter.attribute("DataType", file_id_or_alias(*node.dataType));
  }
  if (node.valueRank)
  {
    mWriter.attribute("ValueRank", fmt::format("{}", *node.valueRank));
  }
  if (!node.arrayDimensions.empty())
  {
    std::string dimensions;
    for (std::size_t i = 0; i < node.arrayDimensions.size(); ++i)
    {
      if (i != 0)
      {
        dimensions += ',';
      }
      dimensions += fmt::format("{}", node.arrayDimensions[i]);
    }
    mWriter.attribute("ArrayDimensions", dimensions);
  }
  if (node.accessLevel)
  {
    mWriter.attribute("AccessLevel", fmt::format("{}", static_cast<uint32_t>(*node.accessLevel)));
  }
  if (node.minimumSamplingInterval)
  {
    mWriter.attribute("MinimumSamplingInterval", fmt::format("{}", *node.minimumSamplingInterval));
  }
  if (node.historizing && *node.historizing)
  {
    mWriter.attribute("Historizing", "true");
  }
  if (node.eventNotifier && *node.eventNotifier != 0)
  {
    mWriter.attribute("EventNotifier", fmt::format("{}", static_cast<uint32_t>(*node.eventNotifier)));
  }
  if (node.containsNoLoops && *node.containsNoLoops)
  {
    mWriter.attribute("ContainsNoLoops", "true");
  }
  if (node.executable)
  {
    mWriter.attribute("Executable", *node.executable ? "true" : "false");
  }

  // Children (NodeSet2 schema order: base sequence, then derived-class elements).
  write_localized_texts("DisplayName", node.displayName);
  write_localized_texts("Description", node.description);
  write_references(node.references);
  if (node.nodeClass == NodeClass::ReferenceType)
  {
    write_localized_texts("InverseName", node.inverseName);
  }
  if (node.nodeClass == NodeClass::DataType)
  {
    write_definition(node);
  }
  if (node.value)
  {
    write_value(*node.value);
  }

  mWriter.end_element(element);
}

void NodeSetWriter::end_document()
{
  mWriter.end_element("UANodeSet");
}

}  // namespace ua::xml::nodeset
