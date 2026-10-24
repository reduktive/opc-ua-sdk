// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_encoding_limits.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_localized_text.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_structure_type.h"
#include "ua_memory_stream.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_string.h"
#include "ua_variant.h"
#include "ua_xml_parser.h"

#include "ua_nodeset_writer.h"

using namespace ua;
using ua::xml::nodeset::ExportedNode;
using ua::xml::nodeset::ExportedReference;
using ua::xml::nodeset::NodeSetModel;
using ua::xml::nodeset::NodeSetWriter;
using ua::xml::nodeset::NodeSetWriterOptions;

namespace
{

constexpr auto npos = std::string::npos;

// Serializes a document via NodeSetWriter and returns the bytes as a string. Defaults an unset
// remap to identity so tests that don't exercise remapping stay terse.
std::string write_doc(NodeSetWriterOptions options, const std::vector<ExportedNode>& nodes)
{
  if (!options.serverToFileIndex)
  {
    options.serverToFileIndex = [](uint16_t serverIndex)
    {
      return serverIndex;
    };
  }

  memory_stream_device::Dynamic device;
  MemoryStream stream(device);
  NodeSetWriter writer(stream, EncodingLimits{}, std::move(options));
  writer.begin_document();
  for (const auto& node : nodes)
  {
    writer.write_node(node);
  }
  writer.end_document();

  const auto data = device.get_data();
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

ExportedNode make_object(NodeId nodeId, uint16_t browseNs, std::string browseName)
{
  ExportedNode node;
  node.nodeId = std::move(nodeId);
  node.nodeClass = NodeClass::Object;
  node.browseName = QualifiedName{browseNs, browseName};
  node.displayName = {LocalizedText{"", browseName}};
  return node;
}

}  // namespace

TEST(NodeSetWriterTests, EnvelopeHeader)
{
  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:test"}};
  options.serverToFileIndex = [](uint16_t serverIndex)
  {
    return static_cast<uint16_t>(serverIndex == 0 ? 0 : 1);
  };
  options.models = {NodeSetModel{String{"urn:test"}, String{"1.0.0"}, DateTime{2024, 1, 1, 0, 0, 0, 0}}};

  const std::string xml = write_doc(std::move(options), {});

  EXPECT_NE(xml.find("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"), npos) << xml;
  EXPECT_NE(xml.find("<UANodeSet xmlns=\"http://opcfoundation.org/UA/2011/03/UANodeSet.xsd\" "
                     "xmlns:uax=\"http://opcfoundation.org/UA/2008/02/Types.xsd\" "
                     "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"),
    npos)
    << xml;
  EXPECT_NE(xml.find("<NamespaceUris><Uri>urn:test</Uri></NamespaceUris>"), npos) << xml;
  EXPECT_NE(
    xml.find("<Model ModelUri=\"urn:test\" Version=\"1.0.0\" PublicationDate=\"2024-01-01T00:00:00Z\"/>"),
    npos)
    << xml;
  EXPECT_NE(xml.find("</UANodeSet>"), npos) << xml;
}

TEST(NodeSetWriterTests, ObjectNode)
{
  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:test"}};

  const std::string xml = write_doc(std::move(options), {make_object(NodeId{1, 5u}, 1, "Obj")});

  EXPECT_NE(
    xml.find("<UAObject NodeId=\"ns=1;i=5\" BrowseName=\"1:Obj\"><DisplayName>Obj</DisplayName></UAObject>"),
    npos)
    << xml;
}

TEST(NodeSetWriterTests, VariableWithValueAndReferences)
{
  ExportedNode node;
  node.nodeId = NodeId{1, 6u};
  node.nodeClass = NodeClass::Variable;
  node.browseName = QualifiedName{1, "Temp"};
  node.displayName = {LocalizedText{"", "Temp"}};
  node.dataType = NodeId{0, 6u};  // Int32 (i=6) in NS0
  node.valueRank = -1;
  node.accessLevel = uint8_t{1};
  node.value = Variant{static_cast<int32_t>(42)};

  ExportedReference reference;
  reference.referenceTypeId = NodeId{ReferenceTypeId::HasTypeDefinition};  // i=40, NS0
  reference.targetId = ExpandedNodeId{NodeId{0, 63u}};  // BaseDataVariableType (i=63), NS0
  reference.isForward = true;
  node.references = {reference};

  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:test"}};
  const std::string xml = write_doc(std::move(options), {node});

  EXPECT_NE(xml.find("<UAVariable NodeId=\"ns=1;i=6\" BrowseName=\"1:Temp\" DataType=\"i=6\" "
                     "ValueRank=\"-1\" AccessLevel=\"1\">"),
    npos)
    << xml;
  EXPECT_NE(xml.find("<DisplayName>Temp</DisplayName>"), npos) << xml;
  EXPECT_NE(
    xml.find(
      "<References><Reference ReferenceType=\"i=40\" IsForward=\"true\">i=63</Reference></References>"),
    npos)
    << xml;
  EXPECT_NE(
    xml.find("<Value xmlns=\"http://opcfoundation.org/UA/2008/02/Types.xsd\"><Int32>42</Int32></Value>"),
    npos)
    << xml;
}

TEST(NodeSetWriterTests, ReferenceTypeWithInverseName)
{
  ExportedNode node;
  node.nodeId = NodeId{1, 100u};
  node.nodeClass = NodeClass::ReferenceType;
  node.browseName = QualifiedName{1, "Controls"};
  node.displayName = {LocalizedText{"", "Controls"}};
  node.isAbstract = false;  // omitted when false
  node.symmetric = false;  // omitted when false
  node.inverseName = {LocalizedText{"", "ControlledBy"}};

  const std::string xml = write_doc({}, {node});

  EXPECT_NE(xml.find("<UAReferenceType NodeId=\"ns=1;i=100\" BrowseName=\"1:Controls\">"), npos) << xml;
  EXPECT_EQ(xml.find("IsAbstract"), npos) << xml;  // false attributes are omitted
  EXPECT_EQ(xml.find("Symmetric"), npos) << xml;
  EXPECT_NE(xml.find("<InverseName>ControlledBy</InverseName>"), npos) << xml;
}

TEST(NodeSetWriterTests, AbstractTypeEmitsIsAbstract)
{
  ExportedNode node = make_object(NodeId{1, 200u}, 1, "AbstractType");
  node.nodeClass = NodeClass::ObjectType;
  node.isAbstract = true;

  const std::string xml = write_doc({}, {node});
  EXPECT_NE(
    xml.find("<UAObjectType NodeId=\"ns=1;i=200\" BrowseName=\"1:AbstractType\" IsAbstract=\"true\">"), npos)
    << xml;
}

TEST(NodeSetWriterTests, AllNodeIdIdentifierForms)
{
  std::vector<ExportedNode> nodes;
  nodes.push_back(make_object(NodeId{0, 84u}, 0, "Numeric"));  // NS0 numeric -> i=84
  nodes.push_back(make_object(NodeId{1, "Foo"}, 1, "StringId"));
  nodes.push_back(make_object(NodeId{1, Guid::parse("12345678-1234-1234-1234-1234567890ab")}, 1, "GuidId"));
  nodes.push_back(
    make_object(NodeId{1, ByteString{uint8_t{1}, uint8_t{2}, uint8_t{3}, uint8_t{4}}}, 1, "OpaqueId"));

  const std::string xml = write_doc({}, nodes);

  EXPECT_NE(xml.find("NodeId=\"i=84\""), npos) << xml;
  EXPECT_NE(xml.find("NodeId=\"ns=1;s=Foo\""), npos) << xml;
  EXPECT_NE(xml.find("NodeId=\"ns=1;g=12345678-1234-1234-1234-1234567890ab\""), npos) << xml;
  EXPECT_NE(xml.find("NodeId=\"ns=1;b=AQIDBA==\""), npos) << xml;  // base64 of {1,2,3,4}
}

TEST(NodeSetWriterTests, NamespaceIndexRemap)
{
  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:two"}};  // file index 1 == server index 2
  options.serverToFileIndex = [](uint16_t serverIndex)
  {
    return static_cast<uint16_t>(serverIndex == 2 ? 1 : 0);
  };

  // A node owned by server namespace 2 must serialize with file index 1.
  const std::string xml = write_doc(std::move(options), {make_object(NodeId{2, 7u}, 2, "Remapped")});

  EXPECT_NE(xml.find("NodeId=\"ns=1;i=7\""), npos) << xml;
  EXPECT_NE(xml.find("BrowseName=\"1:Remapped\""), npos) << xml;
}

TEST(NodeSetWriterTests, OutputIsWellFormedXmlRootedAtUANodeSet)
{
  ExportedNode variable;
  variable.nodeId = NodeId{1, 6u};
  variable.nodeClass = NodeClass::Variable;
  variable.browseName = QualifiedName{1, "Temp"};
  variable.displayName = {LocalizedText{"", "Temp"}};
  variable.value = Variant{static_cast<int32_t>(7)};

  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:test"}};
  std::string xml = write_doc(std::move(options), {make_object(NodeId{1, 5u}, 1, "Obj"), variable});

  // Parse the emitted document with the low-level XML parser to confirm it is well-formed and rooted
  // at <UANodeSet>.
  std::vector<char> writable(xml.begin(), xml.end());
  writable.push_back('\0');
  auto context = xml::parse(writable.data());
  auto root = context.xml_element().get_first_child();
  ASSERT_TRUE(root.has_value()) << xml;
  EXPECT_EQ(std::string(root->get_name()), "UANodeSet") << xml;

  auto firstNode = root->get_first_child();
  ASSERT_TRUE(firstNode.has_value()) << xml;
}

// A UADataType carrying a StructureDefinition emits a `<Definition>` with one `<Field>` per member;
// scalar fields omit ValueRank, array/optional fields carry ValueRank/IsOptional, and field DataTypes
// are namespace-remapped like any other id.
TEST(NodeSetWriterTests, DataTypeStructureDefinition)
{
  ExportedNode node;
  node.nodeId = NodeId{1, 4000u};
  node.nodeClass = NodeClass::DataType;
  node.browseName = QualifiedName{1, "MyStruct"};
  node.displayName = {LocalizedText{"", "MyStruct"}};

  auto definition = make_shared<StructureDefinition>();
  definition->structure_type() = StructureType::Structure;
  StructureField width;
  width.name() = String{"Width"};
  width.data_type() = NodeId{6u};  // Int32, scalar
  width.value_rank() = -1;
  definition->fields().push_back(std::move(width));
  StructureField tags;
  tags.name() = String{"Tags"};
  tags.data_type() = NodeId{12u};  // String, array, optional
  tags.value_rank() = 1;
  tags.is_optional() = true;
  definition->fields().push_back(std::move(tags));
  node.dataTypeDefinition = definition;

  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:test"}};
  std::string xml = write_doc(std::move(options), {node});

  EXPECT_NE(xml.find("<UADataType NodeId=\"ns=1;i=4000\""), npos) << xml;
  EXPECT_NE(xml.find("<Definition Name=\"MyStruct\">"), npos) << xml;
  EXPECT_NE(xml.find("<Field Name=\"Width\" DataType=\"i=6\"/>"), npos) << xml;
  EXPECT_NE(xml.find("<Field Name=\"Tags\" DataType=\"i=12\" ValueRank=\"1\" IsOptional=\"true\"/>"), npos)
    << xml;

  std::vector<char> writable(xml.begin(), xml.end());
  writable.push_back('\0');
  auto context = xml::parse(writable.data());
  auto root = context.xml_element().get_first_child();
  ASSERT_TRUE(root.has_value()) << xml;
  EXPECT_EQ(std::string(root->get_name()), "UANodeSet") << xml;
}

// When set, LastModified is emitted as an attribute on the `<UANodeSet>` root element.
TEST(NodeSetWriterTests, LastModifiedAttribute)
{
  NodeSetWriterOptions options;
  options.lastModified = DateTime{2024, 6, 1, 12, 30, 0, 0};
  const std::string xml = write_doc(std::move(options), {});
  EXPECT_NE(xml.find("LastModified=\"2024-06-01T12:30:00Z\""), npos) << xml;
}

// A `<Model>` emits its declared `<RequiredModel>` dependencies as nested elements.
TEST(NodeSetWriterTests, ModelWithRequiredModels)
{
  using ua::xml::nodeset::NodeSetRequiredModel;

  NodeSetWriterOptions options;
  options.namespaceUris = {String{"urn:app"}};
  NodeSetModel model;
  model.modelUri = String{"urn:app"};
  model.version = String{"1.0.0"};
  model.publicationDate = DateTime{2024, 1, 1, 0, 0, 0, 0};
  model.requiredModels = {NodeSetRequiredModel{
    String{"http://opcfoundation.org/UA/"}, String{"1.05.03"}, DateTime{2023, 12, 15, 0, 0, 0, 0}}};
  options.models = {model};

  const std::string xml = write_doc(std::move(options), {});

  EXPECT_NE(xml.find("<Model ModelUri=\"urn:app\" Version=\"1.0.0\" "
                     "PublicationDate=\"2024-01-01T00:00:00Z\"><RequiredModel "
                     "ModelUri=\"http://opcfoundation.org/UA/\" Version=\"1.05.03\" "
                     "PublicationDate=\"2023-12-15T00:00:00Z\"/></Model>"),
    npos)
    << xml;
}

// A Union structure carries IsUnion="true" on its `<Definition>`.
TEST(NodeSetWriterTests, DataTypeUnionDefinitionEmitsIsUnion)
{
  ExportedNode node;
  node.nodeId = NodeId{1, 4001u};
  node.nodeClass = NodeClass::DataType;
  node.browseName = QualifiedName{1, "MyUnion"};

  auto definition = make_shared<StructureDefinition>();
  definition->structure_type() = StructureType::Union;
  StructureField option;
  option.name() = String{"Number"};
  option.data_type() = NodeId{6u};
  option.value_rank() = -1;
  definition->fields().push_back(std::move(option));
  node.dataTypeDefinition = definition;

  std::string xml = write_doc(NodeSetWriterOptions{}, {node});
  EXPECT_NE(xml.find("<Definition Name=\"MyUnion\" IsUnion=\"true\">"), npos) << xml;
}

// A UADataType carrying an EnumDefinition emits `<Field Name Value>` per enumerator, with an optional
// `<DisplayName>` child.
TEST(NodeSetWriterTests, DataTypeEnumDefinition)
{
  ExportedNode node;
  node.nodeId = NodeId{1, 4002u};
  node.nodeClass = NodeClass::DataType;
  node.browseName = QualifiedName{1, "MyEnum"};

  auto definition = make_shared<EnumDefinition>();
  EnumField red;
  red.name() = String{"Red"};
  red.value() = 0;
  definition->fields().push_back(std::move(red));
  EnumField green;
  green.name() = String{"Green"};
  green.value() = 1;
  green.display_name() = LocalizedText{"", "Green colour"};
  definition->fields().push_back(std::move(green));
  node.dataTypeDefinition = definition;

  std::string xml = write_doc(NodeSetWriterOptions{}, {node});

  EXPECT_NE(xml.find("<Definition Name=\"MyEnum\">"), npos) << xml;
  EXPECT_NE(xml.find("<Field Name=\"Red\" Value=\"0\"/>"), npos) << xml;
  EXPECT_NE(xml.find("<Field Name=\"Green\" Value=\"1\">"), npos) << xml;
  EXPECT_NE(xml.find("<DisplayName>Green colour</DisplayName>"), npos) << xml;
}
