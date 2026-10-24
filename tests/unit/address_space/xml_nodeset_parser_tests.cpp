// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>
#include <stdexcept>
#include <utility>

#include "test_utilities.h"
#include "ua_exceptions.h"
#include "ua_nodeset_parser.h"
#include "ua_file_stream.h"
#include "ua_structure_factory.h"
#include "ua_memory_stream.h"
#include "nodeset_ns0.h"
#include "ua_address_space.h"

using namespace ua;
using namespace ua::xml::nodeset;

class XmlNodeSetParserTest : public ::testing::Test
{
protected:
  std::vector<shared_ptr<NodeSet>> mNodeSets;
  boost::asio::thread_pool mThreadPool{1};
  optional<AddressSpace> mAddressSpace;
  StructureFactory mStructureFactory;

  void SetUp() override;

  void TearDown() override;
};

void XmlNodeSetParserTest::SetUp()
{
  mAddressSpace = AddressSpace::create("", mThreadPool.get_executor());
  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();

  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  mNodeSets = Parser::parse(limits,
    inputStream,
    mStructureFactory,
    mAddressSpace->namespace_array(),
    mAddressSpace->server_array(),
    Parser::GetDependentModelCallback{});
}

void XmlNodeSetParserTest::TearDown()
{
  ::ua::test_utils::drain_with_timeout(mThreadPool);
}

TEST_F(XmlNodeSetParserTest, BuiltInNodeSetTest)
{
  memory_stream_device::ExternalReadOnly streamDevice{utils::span_of_char_to_span_of_byte(nodesetNs0)};
  MemoryStream inputStream{streamDevice};

  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  mNodeSets = Parser::parse(limits,
    inputStream,
    mStructureFactory,
    mAddressSpace->namespace_array(),
    mAddressSpace->server_array(),
    Parser::GetDependentModelCallback{});

  ASSERT_EQ(mNodeSets.size(), 1);
}

// Part 3 section 8.48: inherited Structure fields precede the derived type's fields in base order.
// @relation(AC-SVR-ADDRSP-227-STRUCTUREDEFINITION-BASE-FIRST, scope=function)
TEST_F(XmlNodeSetParserTest, DerivedStructureFieldsAreAggregatedBaseFirst)
{
  constexpr string_view nodeSetXml = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:structure-base-first</Uri></NamespaceUris>
  <UADataType NodeId="ns=1;i=5001" BrowseName="1:BaseStructure">
    <References>
      <Reference ReferenceType="i=45" IsForward="false">i=22</Reference>
    </References>
    <Definition Name="BaseStructure">
      <Field Name="BaseFirst" DataType="i=6"/>
      <Field Name="BaseSecond" DataType="i=12"/>
    </Definition>
  </UADataType>
  <UADataType NodeId="ns=1;i=5002" BrowseName="1:DerivedStructure">
    <References>
      <Reference ReferenceType="i=45" IsForward="false">ns=1;i=5001</Reference>
    </References>
    <Definition Name="DerivedStructure">
      <Field Name="DerivedFirst" DataType="i=1"/>
      <Field Name="DerivedSecond" DataType="i=11"/>
    </Definition>
  </UADataType>
</UANodeSet>)";

  memory_stream_device::ExternalReadOnly streamDevice{
    utils::span_of_char_to_span_of_byte(span<const char>{nodeSetXml.data(), nodeSetXml.size()})};
  MemoryStream inputStream{streamDevice};
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  mNodeSets = Parser::parse(limits,
    inputStream,
    mStructureFactory,
    mAddressSpace->namespace_array(),
    mAddressSpace->server_array(),
    Parser::GetDependentModelCallback{});

  ASSERT_EQ(mNodeSets.size(), 1u);
  const auto* derived =
    dynamic_cast<const DataType*>(mNodeSets.front()->find_node(NodeId{uint16_t{1}, 5002u}));
  ASSERT_NE(derived, nullptr);

  std::vector<std::string> names;
  for (const auto& field : utilities::aggregate_fields(mNodeSets, *derived))
    names.emplace_back(static_cast<std::string_view>(field.name()));

  const std::vector<std::string> expected{"BaseFirst", "BaseSecond", "DerivedFirst", "DerivedSecond"};
  EXPECT_EQ(names, expected);
}

TEST_F(XmlNodeSetParserTest, FieldAssignmentPreservesEachDocumentsTypeAliases)
{
  constexpr string_view firstXml = R"(<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:field-assignment:first</Uri></NamespaceUris>
  <Aliases><Alias Alias="FieldType">i=6</Alias></Aliases>
  <UADataType NodeId="ns=1;i=5001" BrowseName="1:FirstStructure">
    <Definition Name="FirstStructure"><Field Name="First" DataType="FieldType"/></Definition>
  </UADataType>
</UANodeSet>)";
  constexpr string_view secondXml = R"(<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:field-assignment:second</Uri></NamespaceUris>
  <Aliases><Alias Alias="FieldType">i=12</Alias></Aliases>
  <UADataType NodeId="ns=1;i=5001" BrowseName="1:SecondStructure">
    <Definition Name="SecondStructure"><Field Name="Second" DataType="FieldType"/></Definition>
  </UADataType>
</UANodeSet>)";
  const auto fieldsFrom = [&](string_view source)
  {
    memory_stream_device::ExternalReadOnly streamDevice{
      utils::span_of_char_to_span_of_byte(span<const char>{source.data(), source.size()})};
    MemoryStream inputStream{streamDevice};
    auto documents = Parser::parse(make_encoding_limits(ApplicationConfig::load_default()),
      inputStream,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      Parser::GetDependentModelCallback{});
    if (documents.size() != 1)
      throw std::runtime_error{"Field assignment fixture needs one parsed document"};
    const auto* dataType =
      dynamic_cast<const DataType*>(documents.front()->find_node(NodeId{uint16_t{1}, 5001U}));
    if (!dataType)
      throw std::runtime_error{"Field assignment fixture needs its DataType"};
    const auto definition = dataType->definition();
    if (!definition)
      throw std::runtime_error{"Field assignment fixture needs its definition"};
    // Returned fields borrow their document; retain both for every assignment below.
    return std::pair{std::move(documents), definition->fields()};
  };
  auto [firstDocuments, firstFields] = fieldsFrom(firstXml);
  auto [secondDocuments, secondFields] = fieldsFrom(secondXml);
  ASSERT_EQ(firstFields.size(), 1U);
  ASSERT_EQ(secondFields.size(), 1U);
  const NodeId firstType{uint16_t{0}, 6U};
  const NodeId secondType{uint16_t{0}, 12U};

  auto assigned = firstFields.front();
  assigned = secondFields.front();
  EXPECT_EQ(assigned.name(), String{"Second"});
  EXPECT_EQ(assigned.data_type(), secondType);
  assigned = std::move(firstFields.front());
  EXPECT_EQ(assigned.name(), String{"First"});
  EXPECT_EQ(assigned.data_type(), firstType);
  EXPECT_EQ(firstFields.front().data_type(), firstType);

  auto& self = assigned;
  assigned = self;
  EXPECT_EQ(assigned.data_type(), firstType);
  assigned = std::move(self);
  EXPECT_EQ(assigned.name(), String{"First"});
  EXPECT_EQ(assigned.data_type(), firstType);

  std::vector<DataTypeField> fields{firstFields.front(), secondFields.front(), firstFields.front()};
  fields.erase(fields.begin());
  fields.reserve(16);
  ASSERT_EQ(fields.size(), 2U);
  EXPECT_EQ(fields.front().name(), String{"Second"});
  EXPECT_EQ(fields.front().data_type(), secondType);
  EXPECT_EQ(fields.back().name(), String{"First"});
  EXPECT_EQ(fields.back().data_type(), firstType);
}

// Malformed / empty / non-NodeSet input must surface as a clean UaException
// (BadDecodingError), never an unguarded std::optional access that terminates the
// process - a DoS when importing an untrusted NodeSet. Regression for the crash
// found by the Phase 2 decode fuzzer (tooling/fuzzer/libfuzzer/fuzz_nodeset_parse).
TEST_F(XmlNodeSetParserTest, MalformedInputThrowsInsteadOfTerminating)
{
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto parseBytes = [&](std::string xml)
  {
    memory_stream_device::ExternalReadOnly streamDevice{
      utils::span_of_char_to_span_of_byte(span<const char>{xml.data(), xml.size()})};
    MemoryStream inputStream{streamDevice};
    return Parser::parse(limits,
      inputStream,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      Parser::GetDependentModelCallback{});
  };

  EXPECT_THROW(parseBytes(""), UaException);  // empty (the fuzzer's repro)
  EXPECT_THROW(parseBytes("not xml at all"), UaException);  // non-XML (rapidxml::parse_error)
  EXPECT_THROW(parseBytes(R"(<?xml version="1.0"?><Root/>)"), UaException);  // XML, no <UANodeSet>
  // A UANode with no NodeId attribute - node_id() must not bad_optional_access.
  EXPECT_THROW(parseBytes(R"(<?xml version="1.0"?><UANodeSet )"
                          R"(xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">)"
                          R"(<UAObject BrowseName="1:X"/></UANodeSet>)"),
    UaException);
}

namespace
{
// A one-object NodeSet whose object carries one RolePermission naming `roleText`, with the alias
// `AdminRole` declared for i=15644.
std::vector<shared_ptr<NodeSet>> parse_role_permission_nodeset(
  AddressSpace& addressSpace, StructureFactory& factory, std::string_view roleText)
{
  const std::string xml = std::string{R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:role-permission-alias</Uri></NamespaceUris>
  <Aliases><Alias Alias="AdminRole">i=15644</Alias></Aliases>
  <UAObject NodeId="ns=1;i=5001" BrowseName="1:Guarded">
    <RolePermissions><RolePermission Permissions="1">)"} +
                          std::string{roleText} + R"(</RolePermission></RolePermissions>
  </UAObject>
</UANodeSet>)";
  memory_stream_device::ExternalReadOnly streamDevice{
    utils::span_of_char_to_span_of_byte(span<const char>{xml.data(), xml.size()})};
  MemoryStream inputStream{streamDevice};
  return Parser::parse(make_encoding_limits(ApplicationConfig::load_default()),
    inputStream,
    factory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});
}
}  // namespace

// A RolePermission may name its Role by a declared alias; the alias is looked up by the
// RolePermission's own text. It was looked up by the node element's text (whitespace), so an aliased
// RolePermission escaped the parser as std::bad_optional_access.
// @verifies AC-COMP-CORE-XML-CODEC-05-AN-ALIASED-ROLE-PERMISSION-RESOLVES-OR-IS-A-DECODING-ERROR
TEST(XmlNodeSetRolePermissionTest, AnAliasedRolePermissionResolvesToTheAliasTarget)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("", threadPool.get_executor());
  StructureFactory factory;
  const auto nodeSets = parse_role_permission_nodeset(addressSpace, factory, "AdminRole");
  ASSERT_EQ(nodeSets.size(), 1u);
  auto* node = nodeSets.front()->find_node(NodeId{uint16_t{1}, 5001u});
  ASSERT_NE(node, nullptr);

  std::vector<RolePermissionType> permissions;
  try
  {
    permissions = node->role_permissions();
  }
  catch (const std::exception& error)
  {
    FAIL() << "an aliased RolePermission must resolve: " << error.what();
  }
  ASSERT_EQ(permissions.size(), 1u);
  EXPECT_EQ(permissions.front().role_id(), (NodeId{0, 15644u}));
  EXPECT_EQ(permissions.front().permissions().as_underlying_type(), 1u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A RolePermission naming neither a NodeId nor a declared alias is Bad_DecodingError with a detail,
// not a std::bad_optional_access escaping the import.
// @verifies AC-COMP-CORE-XML-CODEC-05-AN-ALIASED-ROLE-PERMISSION-RESOLVES-OR-IS-A-DECODING-ERROR
TEST(XmlNodeSetRolePermissionTest, ARolePermissionNamingAnUndeclaredAliasIsADecodingError)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("", threadPool.get_executor());
  StructureFactory factory;
  const auto nodeSets = parse_role_permission_nodeset(addressSpace, factory, "NoSuchRole");
  ASSERT_EQ(nodeSets.size(), 1u);
  auto* node = nodeSets.front()->find_node(NodeId{uint16_t{1}, 5001u});
  ASSERT_NE(node, nullptr);

  try
  {
    (void)node->role_permissions();
    ADD_FAILURE() << "an undeclared alias was accepted";
  }
  catch (const UaException& error)
  {
    EXPECT_EQ(error.status(), Status::BadDecodingError);
    ASSERT_NE(error.detail(), nullptr);
    EXPECT_EQ(error.detail()->code, "RolePermissionRoleIdInvalid");
  }
  catch (const std::exception& error)
  {
    ADD_FAILURE() << "a non-UaException escaped: " << error.what();
  }
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// control: a RolePermission naming its Role by NodeId is read as before.
// @verifies AC-COMP-CORE-XML-CODEC-05-AN-ALIASED-ROLE-PERMISSION-RESOLVES-OR-IS-A-DECODING-ERROR
TEST(XmlNodeSetRolePermissionTest, ARolePermissionNamingANodeIdIsRead)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("", threadPool.get_executor());
  StructureFactory factory;
  const auto nodeSets = parse_role_permission_nodeset(addressSpace, factory, "i=15656");
  ASSERT_EQ(nodeSets.size(), 1u);
  auto* node = nodeSets.front()->find_node(NodeId{uint16_t{1}, 5001u});
  ASSERT_NE(node, nullptr);
  const auto permissions = node->role_permissions();
  ASSERT_EQ(permissions.size(), 1u);
  EXPECT_EQ(permissions.front().role_id(), (NodeId{0, 15656u}));
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A NodeSet Variable's Value is decoded under the import's EncodingLimits: an array longer than the
// maximum array length is Bad_EncodingLimitsExceeded, as it is in UA Binary; one at the limit decodes.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST(XmlNodeSetValueLimitTest, AVariableValueArrayLongerThanTheMaximumArrayLengthIsRefused)
{
  constexpr std::string_view xml = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:value-array-limit</Uri></NamespaceUris>
  <UAVariable NodeId="ns=1;i=6001" BrowseName="1:Values" DataType="i=6" ValueRank="1">
    <Value><ListOfInt32 xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd"><Int32>1</Int32><Int32>2</Int32><Int32>3</Int32></ListOfInt32></Value>
  </UAVariable>
</UANodeSet>)";
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("", threadPool.get_executor());
  StructureFactory factory;
  const auto valueUnderCap = [&](size_t cap)
  {
    auto limits = make_encoding_limits(ApplicationConfig::load_default());
    limits.maxArrayLength = cap;
    memory_stream_device::ExternalReadOnly streamDevice{
      utils::span_of_char_to_span_of_byte(span<const char>{xml.data(), xml.size()})};
    MemoryStream inputStream{streamDevice};
    const auto nodeSets = Parser::parse(limits,
      inputStream,
      factory,
      addressSpace.namespace_array(),
      addressSpace.server_array(),
      Parser::GetDependentModelCallback{});
    auto* variable = dynamic_cast<Variable*>(nodeSets.front()->find_node(NodeId{uint16_t{1}, 6001u}));
    if (variable == nullptr)
    {
      throw std::runtime_error("the Variable is missing");
    }
    return variable->value();
  };

  try
  {
    (void)valueUnderCap(2);
    ADD_FAILURE() << "an array of three was accepted under a cap of two";
  }
  catch (const UaException& error)
  {
    EXPECT_EQ(error.status(), Status::BadEncodingLimitsExceeded);
  }

  const auto atTheCap = valueUnderCap(3);
  ASSERT_TRUE(atTheCap.is_array());
  EXPECT_EQ(atTheCap.as<Array<int32_t>>().payload().size(), 3u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST_F(XmlNodeSetParserTest, NodeSetTests)
{
  ASSERT_EQ(mNodeSets.size(), 1);

  auto& nodeSet = *mNodeSets.front();

  //  ASSERT_TRUE(nodeSet.server_uris());
  //  ASSERT_EQ(nodeSet.server_uris()->uris().size(), 1);

  NodeId booleanId{DataTypeId::Boolean};
  ASSERT_EQ(nodeSet.aliases()->find_raw_node_id("Boolean").value(), booleanId);

  ASSERT_EQ(nodeSet.models().size(), 1);
  auto& model = nodeSet.models().front();

  ASSERT_EQ(model.model_uri(), mAddressSpace->namespace_array().get_namespace_uri(0));

  ASSERT_EQ(model.version(), String{"1.05.06"});

  // ASSERT_TRUE(model.publication_date());

  ua::xml::nodeset::Node* booleanDataType = nodeSet.find_node(booleanId);
  ASSERT_TRUE(booleanDataType);

  auto dataType = dynamic_cast<DataType*>(booleanDataType);
  ASSERT_TRUE(dataType);
}

// TEST_CASE("ModelTests")
//{}
//
// TEST_CASE("NodeTests")
//{
//   NodeId objectId(3062);
//   Xml::Node* object = 0;
//   status = nodeSet.FindNode(objectId, object);
//   REQUIRE(status.IsGood());
//   REQUIRE(object);
//
//   NodeId nodeId;
//   status = object->GetNodeId(allocator, nodeId);
//   REQUIRE(status.IsGood());
//   REQUIRE(nodeId == objectId);
//
//   QualifiedName browseName;
//   status = object->GetBrowseName(allocator, browseName);
//   REQUIRE(status.IsGood());
//   REQUIRE(browseName.NamespaceIndex() == 0);
//   SpanOfConstChar comparisonString = SpanOfConstChar(UA_STR_ARG("Default Binary"));
//   REQUIRE(memcmp(browseName.Name().Bytes().Data(), comparisonString.Data(), comparisonString.Length()) ==
//   0);
//
//   AttributeWriteMask writeMask;
//   status = object->GetWriteMask(allocator, writeMask);
//   REQUIRE(status.IsGood());
//   REQUIRE(writeMask == 1);
//
//   status = object->GetUserWriteMask(allocator, writeMask);
//   REQUIRE(status.IsGood());
//   REQUIRE(writeMask == 2);
//
//   String symbolicName;
//   status = object->GetSymbolicName(allocator, symbolicName);
//   REQUIRE(status.IsGood());
//   comparisonString = SpanOfConstChar(UA_STR_ARG("DefaultBinary"));
//   REQUIRE(memcmp(symbolicName.Bytes().Data(), comparisonString.Data(), comparisonString.Length()) == 0);
//
//   Xml::Node::ReleaseStatus releaseStatus;
//   status = object->GetReleaseStatus(allocator, releaseStatus);
//   REQUIRE(status.IsGood());
//   REQUIRE(releaseStatus == Xml::Node::ReleaseStatus::Deprecated);
//
//   AccessRestrictionType accessRestrictions;
//   status = object->GetAccessRestrictions(allocator, accessRestrictions);
//   REQUIRE(status.IsGood());
//   REQUIRE(accessRestrictions == 0);
//
//   ArrayOfRolePermissionType rolePermissions;
//   status = object->GetRolePermissions(allocator, rolePermissions);
//   REQUIRE(status.IsGood());
//   REQUIRE(rolePermissions.Size() == 2);
//   REQUIRE(rolePermissions[0].RoleId() == NodeId(5));
//   REQUIRE(rolePermissions[0].Permissions() == 1);
//   REQUIRE(rolePermissions[1].RoleId() == NodeId(6));
//   REQUIRE(rolePermissions[1].Permissions() == 2);
//
//   ArrayOfXmlElement extensions;
//   status = object->GetExtensions(allocator, extensions);
//   REQUIRE(status.IsGood());
//   REQUIRE(extensions.Size() == 2);
//
//   static const char extensionsText[] = "<Extension><ext>iiota:extension:ext1</ext></Extension>";
//
//   REQUIRE(SpanCompare(extensions[0].Chars(), SpanOfConstChar(UA_STR_ARG(extensionsText))));
//
//   ArrayOfLocalizedText displayNames;
//   status = object->GetDisplayName(allocator, displayNames);
//   REQUIRE(status.IsGood());
//   REQUIRE(displayNames.Size() == 1);
//   REQUIRE(displayNames[0].Locale().IsNotNull());
//   REQUIRE(displayNames[0].Text().IsNotNull());
//   comparisonString = SpanOfConstChar(UA_STR_ARG("Default Binary"));
//   REQUIRE(
//     memcmp(displayNames[0].Text().Bytes().Data(), comparisonString.Data(), comparisonString.Length()) ==
//     0);
//   comparisonString = SpanOfConstChar(UA_STR_ARG("en-IE"));
//   REQUIRE(
//     memcmp(displayNames[0].Locale().Bytes().Data(), comparisonString.Data(), comparisonString.Length()) ==
//     0);
//
//   ArrayOfLocalizedText descriptions;
//   status = object->GetDescription(allocator, descriptions);
//   REQUIRE(status.IsGood());
//   REQUIRE(descriptions.Size() == 1);
//   REQUIRE(descriptions[0].Locale().IsNotNull());
//   REQUIRE(descriptions[0].Text().IsNotNull());
//   comparisonString = SpanOfConstChar(UA_STR_ARG("My Description"));
//   REQUIRE(
//     memcmp(descriptions[0].Text().Bytes().Data(), comparisonString.Data(), comparisonString.Length()) ==
//     0);
//   comparisonString = SpanOfConstChar(UA_STR_ARG("en-GB"));
//   REQUIRE(
//     memcmp(descriptions[0].Locale().Bytes().Data(), comparisonString.Data(), comparisonString.Length()) ==
//     0);
//
//   String documentation;
//   status = object->GetDocumentation(allocator, documentation);
//   REQUIRE(status.IsGood());
//   comparisonString = SpanOfConstChar(UA_STR_ARG("My Documentation"));
//   REQUIRE(memcmp(documentation.Bytes().Data(), comparisonString.Data(), comparisonString.Length()) == 0);
//
//   Array<Xml::Reference> references;
//   status = object->GetReferences(allocator, references);
//   REQUIRE(status.IsGood());
//   REQUIRE(references.Size() == 2);
//   ExpandedNodeId retrievedObjectType;
//   status = references[0].GetTargetId(allocator, retrievedObjectType);
//   REQUIRE(status.IsGood());
//   REQUIRE(ExpandedNodeId(58) == retrievedObjectType);
//   status = references[1].GetTargetId(allocator, retrievedObjectType);
//   REQUIRE(status.IsGood());
// }
//
// TEST_CASE("TypeTests")
//{
//   NodeId serverObjectTypeId(ObjectTypeIdentifiers::ServerType);
//   Xml::ObjectType* serverObjectType = 0;
//   status = nodeSet.FindNode(serverObjectTypeId, serverObjectType);
//   REQUIRE(status.IsGood());
//   REQUIRE(serverObjectType);
//
//   Boolean isAbstract;
//   status = serverObjectType->GetIsAbstract(allocator, isAbstract);
//   REQUIRE(status.IsGood());
//   REQUIRE(!isAbstract);
// }
//
// TEST_CASE("InstanceTests")
//{
//   NodeId instanceId(2254);
//   Xml::Instance* instance = 0;
//   status = nodeSet.FindNode(instanceId, instance);
//   REQUIRE(status.IsGood());
//   REQUIRE(instance);
//
//   ExpandedNodeId nodeId;
//   status = instance->GetParentNodeId(allocator, nodeId);
//   REQUIRE(status.IsGood());
//   REQUIRE(nodeId == ExpandedNodeId(2253));
// }
//
// TEST_CASE("VariableTypeTests")
//{
//   NodeId variableTypeId(19084);
//   Xml::VariableType* variableType = 0;
//   status = nodeSet.FindNode(variableTypeId, variableType);
//   REQUIRE(status.IsGood());
//   REQUIRE(variableType);
//
//   NodeId dataType;
//   status = variableType->GetDataType(allocator, dataType);
//   REQUIRE(status.IsGood());
//   REQUIRE(dataType == NodeId(DataTypeIdentifiers::Number));
//
//   Int32 valueRank;
//   status = variableType->GetValueRank(allocator, valueRank);
//   REQUIRE(status.IsGood());
//   REQUIRE(valueRank == -1);
//
//   ArrayOfUInt32 arrayDimensions;
//   status = variableType->GetArrayDimensions(allocator, arrayDimensions);
//   REQUIRE(status.IsGood());
//   REQUIRE(arrayDimensions.Size() == 0);
//
//   UniquePtr<Variant> value;
//   status = variableType->GetValue(allocator, value);
//   REQUIRE(status.IsBad());
// }
//
// TEST_CASE("ReferenceTypeTests")
//{
//   NodeId referenceTypeId(35);
//   Xml::ReferenceType* referenceType = 0;
//   status = nodeSet.FindNode(referenceTypeId, referenceType);
//   REQUIRE(status.IsGood());
//   REQUIRE(referenceType);
//
//   ArrayOfLocalizedText inverseName;
//   status = referenceType->GetInverseName(allocator, inverseName);
//   REQUIRE(status.IsGood());
//   REQUIRE(inverseName.Size() == 1);
//   REQUIRE(inverseName[0].Text().IsNotNull());
//   SpanOfConstChar comparisonString = SpanOfConstChar(UA_STR_ARG("OrganizedBy"));
//   REQUIRE(
//     memcmp(inverseName[0].Text().Bytes().Data(), comparisonString.Data(), comparisonString.Length()) == 0);
//
//   Boolean isSymmetric;
//   status = referenceType->GetIsAbstract(allocator, isSymmetric);
//   REQUIRE(status.IsGood());
//   REQUIRE(!isSymmetric);
// }
//
// TEST_CASE("DataTypeTests")
//{
//   NodeId dataTypeId(120);
//   Xml::DataType* dataType = 0;
//   status = nodeSet.FindNode(dataTypeId, dataType);
//   REQUIRE(status.IsGood());
//   REQUIRE(dataType);
//
//   Xml::DataTypeDefinition definition;
//   status = dataType->GetDefinition(allocator, definition);
//   REQUIRE(status.IsGood());
//
//   Xml::DataType::DataTypePurpose purpose;
//   status = dataType->GetPurpose(allocator, purpose);
//   REQUIRE(status.IsGood());
//   REQUIRE(purpose == Xml::DataType::DataTypePurpose::Normal);
// }
//
// TEST_CASE("ObjectTests")
//{
//   NodeId objectId(78);
//   Xml::Object* object = 0;
//   status = nodeSet.FindNode(objectId, object);
//   REQUIRE(status.IsGood());
//   REQUIRE(object);
//
//   EventNotifierType eventNotifier;
//   status = object->GetEventNotifier(allocator, eventNotifier);
//   REQUIRE(status.IsGood());
// }
//
// TEST_CASE("VariableTests")
//{
//   NodeId variableId(11878);
//   Xml::Variable* variable = 0;
//   status = nodeSet.FindNode(variableId, variable);
//   REQUIRE(status.IsGood());
//   REQUIRE(variable);
//
//   NodeId dataType;
//   status = variable->GetDataType(allocator, dataType);
//   REQUIRE(status.IsGood());
//   REQUIRE(dataType == NodeId(7594));
//
//   Int32 valueRank;
//   status = variable->GetValueRank(allocator, valueRank);
//   REQUIRE(status.IsGood());
//   REQUIRE(valueRank == 1);
//
//   ArrayOfUInt32 arrayDimensions;
//   status = variable->GetArrayDimensions(allocator, arrayDimensions);
//   REQUIRE(status.IsGood());
//   REQUIRE(arrayDimensions.Size() == 1);
//   REQUIRE(arrayDimensions[0] == 0);
//
//   status = EnumValueType::RegisterTypeWithFactory(dataTypeFactory);
//   REQUIRE(status.IsGood());
//
//   UniquePtr<Variant> value;
//   status = variable->GetValue(allocator, value);
//   REQUIRE(status.IsGood());
//   REQUIRE(value.IsSet());
//
//   ArrayOfStructure* arrayOfStructure = value->DowncastTo<ArrayOfStructure>();
//   REQUIRE(arrayOfStructure);
//   REQUIRE(arrayOfStructure->Size() == 9);
//
//   EnumValueType* enumValueType = (*arrayOfStructure)[0]->DowncastTo<EnumValueType>();
//   REQUIRE(enumValueType);
// }
//
// TEST_CASE("MethodTests")
//{
//   NodeId methodId(16296);
//   Xml::Method* method = 0;
//   status = nodeSet.FindNode(methodId, method);
//   REQUIRE(status.IsGood());
//   REQUIRE(method);
//
//   Array<Xml::MethodArgument> argDescriptions;
//   status = method->GetArgumentDescriptions(allocator, argDescriptions);
//   REQUIRE(status.IsGood());
//
//   Boolean isExecutable;
//   status = method->GetExecutable(allocator, isExecutable);
//   REQUIRE(status.IsGood());
//   REQUIRE(isExecutable);
//
//   status = method->GetUserExecutable(allocator, isExecutable);
//   REQUIRE(status.IsGood());
//   REQUIRE(isExecutable);
//
//   NodeId declId;
//   status = method->GetMethodDeclarationId(allocator, declId);
//   REQUIRE(status.IsGood());
//   REQUIRE(declId == NodeId(15997));
// }
//
// TEST_CASE("ViewTests")
//{}
//
// TEST_CASE("LoadMultipleNodeSets")
//{}
// }
//
// REQUIRE(0 == allocator.SpaceAllocated());
//
// UA_ALL_TESTS_COMPLETE
// }
//
// TEST_CASE("XmlMultipleNodeSetTests")
//{
//   HeapAllocator allocator;
//
//   {
//     UriArray namespaceArray;
//     Status status = namespaceArray.Initialise(allocator);
//     REQUIRE(status.IsGood());
//     uint16_t index = 0;
//     status = namespaceArray.AddUri(SpanOfConstChar(UA_STR_ARG("http://opcfoundation.org/UA/")), index);
//     REQUIRE(status.IsGood());
//
//     UriArray serverArray;
//     status = serverArray.Initialise(allocator);
//     REQUIRE(status.IsGood());
//
//     DataTypeFactory dataTypeFactory;
//     status = dataTypeFactory.Initialise(allocator, allocator, 100, namespaceArray);
//     REQUIRE(status.IsGood());
//
//     TEST_CASE("MDIS_Tests")
//     {
//       FileStream inputStream;
//       SpanOfConstChar fileName(
//         UA_STR_ARG("../../../../../Resources/OPCF/UA-Nodeset-1.04/MDIS/Opc.MDIS.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//     }
//
//     TEST_CASE("ADI_Tests")
//     {
//       FileStream inputStream;
//       SpanOfConstChar fileName(
//         UA_STR_ARG("../../../../../Resources/OPCF/UA-Nodeset-1.04/ADI/Opc.Ua.Adi.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//     }
//
//     TEST_CASE("PLCopen_Tests")
//     {
//       FileStream inputStream;
//       SpanOfConstChar fileName(
//         UA_STR_ARG("../../../../../Resources/OPCF/UA-Nodeset-1.04/PLCopen/Opc.Ua.Plc.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//     }
//
//     TEST_CASE("AML_Tests")
//     {
//       FileStream inputStream;
//       SpanOfConstChar fileName(
//         UA_STR_ARG("../../../../../Resources/OPCF/UA-Nodeset-1.04/AML/Opc.Ua.AMLLibraries.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//     }
//   }
//
//   REQUIRE(0 == allocator.SpaceAllocated());
//
//   UA_ALL_TESTS_COMPLETE
// }
//
// TEST_CASE("XmlIndexMappingTests")
//{
//   HeapAllocator allocator;
//
//   {
//     UriArray namespaceArray;
//     Status status = namespaceArray.Initialise(allocator);
//     REQUIRE(status.IsGood());
//     uint16_t index = 0;
//
//     status = namespaceArray.AddUri(SpanOfConstChar(UA_STR_ARG("http://opcfoundation.org/UA/")), index);
//     REQUIRE(status.IsGood());
//
//     UriArray serverArray;
//     status = serverArray.Initialise(allocator);
//     REQUIRE(status.IsGood());
//
//     DataTypeFactory dataTypeFactory;
//     status = dataTypeFactory.Initialise(allocator, allocator, 100, namespaceArray);
//     REQUIRE(status.IsGood());
//
//     TEST_CASE("NoMapping_Tests")
//     {
//       FileStream inputStream;
//       SpanOfConstChar fileName(
//         UA_STR_ARG("../../../../../Resources/OPCF/UA-Nodeset-1.04/Schema/Opc.Ua.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//       REQUIRE(nodeSets.First());
//       REQUIRE(nodeSets.First()->IsSet());
//
//       NodeId objectId(3062);
//       Xml::Node* object = 0;
//       status = (*nodeSets.First())->FindNode(objectId, object);
//       REQUIRE(status.IsGood());
//       REQUIRE(object);
//     }
//
//     TEST_CASE("NameSpace_Mapping_Tests")
//     {
//       status = namespaceArray.AddUri(SpanOfConstChar(UA_STR_ARG("MyDummyUri")), index);
//       REQUIRE(status.IsGood());
//
//       FileStream inputStream;
//       SpanOfConstChar fileName(
//         UA_STR_ARG("../../../../../Resources/OPCF/UA-Nodeset-1.04/MDIS/Opc.MDIS.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//       REQUIRE(nodeSets.First());
//       REQUIRE(nodeSets.First()->IsSet());
//
//       NodeId id(2, 497);
//       Xml::Node* node = 0;
//       status = (*nodeSets.First())->FindNode(id, node);
//       REQUIRE(status.IsGood());
//       REQUIRE(node);
//     }
//
//     TEST_CASE("Server_Mapping_Tests")
//     {
//       status = namespaceArray.AddUri(SpanOfConstChar(UA_STR_ARG("MyDummyUri")), index);
//       REQUIRE(status.IsGood());
//
//       status = serverArray.AddUri(SpanOfConstChar(UA_STR_ARG("CurrentServer")), index);
//       REQUIRE(status.IsGood());
//
//       status = serverArray.AddUri(SpanOfConstChar(UA_STR_ARG("MyDummyUri1")), index);
//       REQUIRE(status.IsGood());
//
//       status = serverArray.AddUri(SpanOfConstChar(UA_STR_ARG("MyDummyUri2")), index);
//       REQUIRE(status.IsGood());
//
//       FileStream inputStream;
//       SpanOfConstChar fileName(UA_STR_ARG("../../../../test_files/Test.NodeSet2.xml"));
//
//       status = inputStream.Initialise(allocator, fileName);
//       REQUIRE(status.IsGood());
//
//       status = inputStream.OpenForRead(false);
//       REQUIRE(status.IsGood());
//
//       List<UniquePtr<Xml::NodeSet>> nodeSets;
//       status = nodeSets.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       XmlAssistant assistant;
//       status = assistant.Initialise(allocator);
//       REQUIRE(status.IsGood());
//
//       Xml xmlTooling;
//       status = xmlTooling.LoadNodeSet(
//         allocator, assistant, inputStream, dataTypeFactory, namespaceArray, serverArray, nodeSets);
//       REQUIRE(status.IsGood());
//       REQUIRE(nodeSets.Size() > 0);
//       REQUIRE(nodeSets.First());
//       REQUIRE(nodeSets.First()->IsSet());
//
//       NodeId id(0, 3062);
//       Xml::Node* node = 0;
//       status = (*nodeSets.First())->FindNode(id, node);
//       REQUIRE(status.IsGood());
//       REQUIRE(node);
//
//       Array<Xml::Reference> references;
//       status = node->GetReferences(allocator, references);
//       REQUIRE(status.IsGood());
//       REQUIRE(references.Size() == 2);
//       ExpandedNodeId targetId;
//       status = references[1].GetTargetId(allocator, targetId);
//       REQUIRE(status.IsGood());
//       REQUIRE(targetId.ServerIndex() == 2);
//     }
//   }
//
//   REQUIRE(0 == allocator.SpaceAllocated());
//
//   UA_ALL_TESTS_COMPLETE
// }
