// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_range.h"
#include "ua_data_value.h"
#include <gtest/gtest.h>
#include <string>
#include "ua_dynamic_type_descriptor.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_union.h"
#include "ua_dynamic_type_registry.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"
#include "ua_data_type_registration.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_datatype_id.h"
#include "ua_signature_data.h"

using namespace ua;

namespace
{

const EncodingLimits& make_limits()
{
  static EncodingLimits limits = []
  {
    const auto cfg = ApplicationConfig::load_default();
    return make_encoding_limits(cfg);
  }();
  return limits;
}

StackDepth make_limit()
{
  auto cfg = ApplicationConfig::load_default();
  return StackDepth{cfg.execution_limits().decodeWorkLimit};
}

/// Helper: build a StructureDefinition with the given fields
StructureDefinition make_definition(StructureType structType, std::vector<StructureField> fields)
{
  StructureDefinition def;
  def.structure_type() = structType;
  Array<StructureField> fieldArray;
  fieldArray.resize(fields.size());
  for (size_t i = 0; i < fields.size(); ++i)
  {
    fieldArray[i] = std::move(fields[i]);
  }
  def.fields() = std::move(fieldArray);
  return def;
}

/// Helper: build a StructureField from a DataTypeId
StructureField make_field(string_view name, DataTypeId dataType, bool isOptional = false)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = NodeId{dataType};
  field.value_rank() = -1;  // Scalar
  field.is_optional() = isOptional;
  return field;
}

/// Helper: build a StructureField from an arbitrary NodeId (for nested structure types)
StructureField make_field(string_view name, NodeId dataType, bool isOptional = false)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = std::move(dataType);
  field.value_rank() = -1;  // Scalar
  field.is_optional() = isOptional;
  return field;
}

/// Helper: create a descriptor for a simple test type
shared_ptr<const DynamicStructureTypeDescriptor> make_test_descriptor(string_view typeName = "TestType",
  StructureType structType = StructureType::Structure, std::vector<StructureField> fields = {})
{
  if (fields.empty())
  {
    fields.push_back(make_field("Name", DataTypeId::String));
    fields.push_back(make_field("Value", DataTypeId::Int32));
    fields.push_back(make_field("Active", DataTypeId::Boolean));
  }

  auto def = make_definition(structType, std::move(fields));

  ExpandedNodeId typeId{NodeId{1, uint32_t{1000}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{1001}}, "urn:test:ns"};

  return std::make_shared<DynamicStructureTypeDescriptor>(
    String{typeName}, std::move(typeId), std::move(encodingId), std::move(def));
}

/// Test namespace URI lookup: maps index 1 to "urn:test:ns"
NamespaceUriLookup test_ns_lookup()
{
  return [](uint16_t nsIndex) -> String
  {
    if (nsIndex == 1)
    {
      return String{"urn:test:ns"};
    }
    return {};
  };
}

/// Test namespace index lookup: maps "urn:test:ns" to index 1
NamespaceIndexLookup test_ns_index_lookup()
{
  return [](string_view uri) -> std::optional<uint16_t>
  {
    if (uri == "urn:test:ns")
    {
      return uint16_t{1};
    }
    return std::nullopt;
  };
}

}  // namespace

// ============================================================================
// DynamicStructureTypeDescriptor tests
// ============================================================================

// Covers SVR-ADDRSP-208 (coverage-audit retag).
TEST(DynamicStructureTypeDescriptor, ConstructFromDefinition)
{
  auto desc = make_test_descriptor();

  EXPECT_EQ(string_view(desc->type_name()), "TestType");
  EXPECT_EQ(desc->field_count(), 3u);
  EXPECT_EQ(desc->structure_type(), StructureType::Structure);
}

TEST(DynamicStructureTypeDescriptor, FieldLookupByName)
{
  auto desc = make_test_descriptor();

  auto nameIdx = desc->field_index("Name");
  ASSERT_TRUE(nameIdx.has_value());
  EXPECT_EQ(nameIdx.value(), 0u);

  auto valueIdx = desc->field_index("Value");
  ASSERT_TRUE(valueIdx.has_value());
  EXPECT_EQ(valueIdx.value(), 1u);

  auto missing = desc->field_index("Missing");
  EXPECT_FALSE(missing.has_value());
}

TEST(DynamicStructureTypeDescriptor, FieldBuiltInType)
{
  auto desc = make_test_descriptor();

  EXPECT_EQ(desc->field_built_in_type(0), BuiltInTypeId::String);
  EXPECT_EQ(desc->field_built_in_type(1), BuiltInTypeId::Int32);
  EXPECT_EQ(desc->field_built_in_type(2), BuiltInTypeId::Boolean);
}

TEST(DynamicStructureTypeDescriptor, DataTypeToBuiltInType)
{
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Boolean}),
    BuiltInTypeId::Boolean);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Int32}),
    BuiltInTypeId::Int32);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::String}),
    BuiltInTypeId::String);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Double}),
    BuiltInTypeId::Double);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::DateTime}),
    BuiltInTypeId::DateTime);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Guid}),
    BuiltInTypeId::Guid);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::ByteString}),
    BuiltInTypeId::ByteString);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::NodeId}),
    BuiltInTypeId::NodeId);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::StatusCode}),
    BuiltInTypeId::StatusCode);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Structure}),
    BuiltInTypeId::ExtensionObject);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::BaseDataType}),
    BuiltInTypeId::Variant);

  // Abstract numeric types
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Number}),
    BuiltInTypeId::Double);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Integer}),
    BuiltInTypeId::Int64);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::UInteger}),
    BuiltInTypeId::UInt64);
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{DataTypeId::Enumeration}),
    BuiltInTypeId::Int32);

  // Custom type (non-NS0)
  EXPECT_EQ(DynamicStructureTypeDescriptor::data_type_to_built_in_type(NodeId{1, uint32_t{5000}}),
    BuiltInTypeId::ExtensionObject);
}

TEST(DynamicStructureTypeDescriptor, NestedDescriptorResolution)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Inner", DataTypeId::Structure));
  auto desc = std::make_shared<DynamicStructureTypeDescriptor>(String{"Outer"},
    ExpandedNodeId{NodeId{1, uint32_t{2000}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{2001}}, "urn:test:ns"},
    make_definition(StructureType::Structure, fields));

  EXPECT_FALSE(desc->fully_resolved());
  EXPECT_EQ(desc->nested_descriptor(0), nullptr);

  auto innerDesc = make_test_descriptor("Inner");
  desc->resolve_nested(0, innerDesc);

  EXPECT_TRUE(desc->fully_resolved());
  EXPECT_EQ(desc->nested_descriptor(0).get(), innerDesc.get());
}

// ============================================================================
// DynamicStructure tests
// ============================================================================

TEST(DynamicStructure, DefaultConstruction)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  EXPECT_EQ(ds.field_count(), 3u);

  // Name (String) defaults to empty
  EXPECT_TRUE(ds.field(0).is_string());
  EXPECT_TRUE(ds.field(0).as<String>().empty());

  // Value (Int32) defaults to 0
  EXPECT_TRUE(ds.field(1).is_int32());
  EXPECT_EQ(ds.field(1).as<int32_t>(), 0);

  // Active (Boolean) defaults to false
  EXPECT_TRUE(ds.field(2).is_boolean());
  EXPECT_EQ(ds.field(2).as<bool>(), false);
}

TEST(DynamicStructure, FieldAccessByName)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  ds["Name"] = Variant{String{"Hello"}};
  ds["Value"] = Variant{int32_t{42}};
  ds["Active"] = Variant{true};

  EXPECT_EQ(ds["Name"].as<String>(), String{"Hello"});
  EXPECT_EQ(ds["Value"].as<int32_t>(), 42);
  EXPECT_EQ(ds["Active"].as<bool>(), true);
}

TEST(DynamicStructure, FieldAccessByIndex)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  ds.field(0) = Variant{String{"World"}};
  ds.field(1) = Variant{int32_t{99}};

  EXPECT_EQ(ds.field(0).as<String>(), String{"World"});
  EXPECT_EQ(ds.field(1).as<int32_t>(), 99);
}

TEST(DynamicStructure, FieldAccessByNameThrowsForUnknown)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  EXPECT_THROW(ds["NonExistent"], UaException);
}

TEST(DynamicStructure, FieldAccessByIndexThrowsForOutOfRange)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  EXPECT_THROW(ds.field(99), UaException);
}

TEST(DynamicStructure, CloneIndependence)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);
  ds["Name"] = Variant{String{"Original"}};
  ds["Value"] = Variant{int32_t{10}};

  auto cloned = ds.clone();
  auto* clonedDs = dynamic_cast<DynamicStructure*>(cloned.get());
  ASSERT_NE(clonedDs, nullptr);

  // Verify clone has same values
  EXPECT_EQ((*clonedDs)["Name"].as<String>(), String{"Original"});
  EXPECT_EQ((*clonedDs)["Value"].as<int32_t>(), 10);

  // Modify original, clone should be unaffected
  ds["Value"] = Variant{int32_t{20}};
  EXPECT_EQ((*clonedDs)["Value"].as<int32_t>(), 10);
  EXPECT_EQ(ds["Value"].as<int32_t>(), 20);
}

TEST(DynamicStructure, Equality)
{
  auto desc = make_test_descriptor();

  DynamicStructure ds1(desc);
  ds1["Name"] = Variant{String{"Test"}};
  ds1["Value"] = Variant{int32_t{42}};

  DynamicStructure ds2(desc);
  ds2["Name"] = Variant{String{"Test"}};
  ds2["Value"] = Variant{int32_t{42}};

  EXPECT_TRUE(ds1 == ds2);

  ds2["Value"] = Variant{int32_t{43}};
  EXPECT_FALSE(ds1 == ds2);
}

TEST(DynamicStructure, EqualityDifferentDescriptor)
{
  auto desc1 = make_test_descriptor("Type1");
  auto desc2 = make_test_descriptor("Type2");

  DynamicStructure ds1(desc1);
  DynamicStructure ds2(desc2);

  // Different descriptors => not equal even if fields are the same
  EXPECT_FALSE(ds1 == ds2);
}

TEST(DynamicStructure, TypeId)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  auto expandedId = ds.type_id();
  EXPECT_EQ(expandedId.namespace_uri(), String{"urn:test:ns"});
  EXPECT_EQ(expandedId.node_id().identifier().get_numeric(), 1000u);
}

TEST(DynamicStructure, TypeName)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  EXPECT_EQ(string_view(ds.type_name()), "TestType");
}

TEST(DynamicStructure, IsOfType)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  CodecNamespaceContext ns{[](string_view uri) -> uint16_t
    {
      if (uri == "urn:test:ns")
        return 1;
      return 0;
    }};

  // Should match its own type
  EXPECT_TRUE(ds.is_of_type(ns, NodeId{1, uint32_t{1000}}));

  // D13: every structured DataType is a subtype of Structure (i=22); StructureType (i=98) is the Enumeration
  // of structure kinds, not a supertype.
  EXPECT_TRUE(ds.is_of_type(ns, NodeId{DataTypeId::Structure}));
  EXPECT_FALSE(ds.is_of_type(ns, NodeId{DataTypeId::StructureType}));

  // Should match BaseDataType
  EXPECT_TRUE(ds.is_of_type(ns, NodeId{DataTypeId::BaseDataType}));

  // Should not match a different type
  EXPECT_FALSE(ds.is_of_type(ns, NodeId{1, uint32_t{9999}}));
}

// D13 (public_api_1_0_design.md section 13.10): a generated structure's supertype chain ends at Structure,
// not at the StructureType Enumeration.
TEST(StructureIsOfType, AGeneratedStructureIsAStructureAndNotAStructureType)
{
  const Range range;
  const CodecNamespaceContext ns{[](string_view) -> uint16_t
    {
      return 0;
    }};
  EXPECT_TRUE(range.is_of_type(ns, NodeId{DataTypeId::Range})) << "control: its own type";
  EXPECT_TRUE(range.is_of_type(ns, NodeId{DataTypeId::Structure}));
  EXPECT_TRUE(range.is_of_type(ns, NodeId{DataTypeId::BaseDataType}));
  EXPECT_FALSE(range.is_of_type(ns, NodeId{DataTypeId::StructureType}));
  EXPECT_FALSE(range.is_of_type(ns, NodeId{DataTypeId::Union}));
}

TEST(DynamicStructure, ToStringSmoke)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);
  ds["Name"] = Variant{String{"Hello"}};

  auto str = ds.to_string();
  EXPECT_FALSE(str.empty());
  EXPECT_NE(str.find("TestType"), std::string::npos);
  EXPECT_NE(str.find("Name"), std::string::npos);
}

// ============================================================================
// Optional fields
// ============================================================================

TEST(DynamicStructure, OptionalFieldPresence)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Required", DataTypeId::Int32, false));
  fields.push_back(make_field("Optional1", DataTypeId::String, true));
  fields.push_back(make_field("Optional2", DataTypeId::Boolean, true));

  auto desc =
    make_test_descriptor("OptionalTest", StructureType::StructureWithOptionalFields, std::move(fields));
  DynamicStructure ds(desc);

  // Optional fields start as not present
  EXPECT_TRUE(ds.has_field("Required"));
  EXPECT_FALSE(ds.has_field("Optional1"));
  EXPECT_FALSE(ds.has_field("Optional2"));

  // Set optional field present
  ds.set_field_present("Optional1", true);
  EXPECT_TRUE(ds.has_field("Optional1"));
  EXPECT_FALSE(ds.has_field("Optional2"));

  // Clear optional field
  ds.set_field_present("Optional1", false);
  EXPECT_FALSE(ds.has_field("Optional1"));
}

TEST(DynamicStructure, SetFieldPresentThrowsForNonOptional)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  EXPECT_THROW(ds.set_field_present("Name", true), UaException);
}

// ============================================================================
// Encode/Decode round-trip
// ============================================================================

// Covers SVR-RC-003, SVR-RC-004 (coverage-audit retag).
TEST(DynamicStructure, EncodeDecodeRoundTrip)
{
  auto desc = make_test_descriptor();
  DynamicStructure input(desc);
  input["Name"] = Variant{String{"RoundTrip"}};
  input["Value"] = Variant{int32_t{12345}};
  input["Active"] = Variant{true};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  input.encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure output(desc);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  EXPECT_EQ(output["Name"].as<String>(), String{"RoundTrip"});
  EXPECT_EQ(output["Value"].as<int32_t>(), 12345);
  EXPECT_EQ(output["Active"].as<bool>(), true);

  EXPECT_TRUE(input == output);
}

TEST(DynamicStructure, EncodeDecodeAllBuiltInTypes)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Bool", DataTypeId::Boolean));
  fields.push_back(make_field("SByte", DataTypeId::SByte));
  fields.push_back(make_field("Byte", DataTypeId::Byte));
  fields.push_back(make_field("Int16", DataTypeId::Int16));
  fields.push_back(make_field("UInt16", DataTypeId::UInt16));
  fields.push_back(make_field("Int32", DataTypeId::Int32));
  fields.push_back(make_field("UInt32", DataTypeId::UInt32));
  fields.push_back(make_field("Int64", DataTypeId::Int64));
  fields.push_back(make_field("UInt64", DataTypeId::UInt64));
  fields.push_back(make_field("Float", DataTypeId::Float));
  fields.push_back(make_field("Double", DataTypeId::Double));
  fields.push_back(make_field("Str", DataTypeId::String));
  fields.push_back(make_field("NodeIdField", DataTypeId::NodeId));
  fields.push_back(make_field("StatusCodeField", DataTypeId::StatusCode));
  fields.push_back(make_field("QName", DataTypeId::QualifiedName));
  fields.push_back(make_field("LText", DataTypeId::LocalizedText));

  auto desc = make_test_descriptor("AllTypes", StructureType::Structure, std::move(fields));
  DynamicStructure input(desc);

  input["Bool"] = Variant{true};
  input["SByte"] = Variant{int8_t{-42}};
  input["Byte"] = Variant{uint8_t{200}};
  input["Int16"] = Variant{int16_t{-1000}};
  input["UInt16"] = Variant{uint16_t{50000}};
  input["Int32"] = Variant{int32_t{-100000}};
  input["UInt32"] = Variant{uint32_t{3000000}};
  input["Int64"] = Variant{int64_t{-9999999999LL}};
  input["UInt64"] = Variant{uint64_t{18446744073709551615ULL}};
  input["Float"] = Variant{float{3.14f}};
  input["Double"] = Variant{double{2.718281828}};
  input["Str"] = Variant{String{"hello world"}};
  input["NodeIdField"] = Variant{NodeId{2, uint32_t{42}}};
  input["StatusCodeField"] = Variant{StatusCode{Status::BadInternalError}};
  input["QName"] = Variant{QualifiedName{1, "TestName"}};
  input["LText"] = Variant{LocalizedText{"en", "Hello"}};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  input.encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure output(desc);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  EXPECT_EQ(output["Bool"].as<bool>(), true);
  EXPECT_EQ(output["SByte"].as<int8_t>(), int8_t{-42});
  EXPECT_EQ(output["Byte"].as<uint8_t>(), uint8_t{200});
  EXPECT_EQ(output["Int16"].as<int16_t>(), int16_t{-1000});
  EXPECT_EQ(output["UInt16"].as<uint16_t>(), uint16_t{50000});
  EXPECT_EQ(output["Int32"].as<int32_t>(), int32_t{-100000});
  EXPECT_EQ(output["UInt32"].as<uint32_t>(), uint32_t{3000000});
  EXPECT_EQ(output["Int64"].as<int64_t>(), int64_t{-9999999999LL});
  EXPECT_EQ(output["UInt64"].as<uint64_t>(), uint64_t{18446744073709551615ULL});
  EXPECT_FLOAT_EQ(output["Float"].as<float>(), 3.14f);
  EXPECT_DOUBLE_EQ(output["Double"].as<double>(), 2.718281828);
  EXPECT_EQ(output["Str"].as<String>(), String{"hello world"});
  auto expectedNodeId = NodeId{2, uint32_t{42}};
  EXPECT_EQ(output["NodeIdField"].as<NodeId>(), expectedNodeId);
  EXPECT_EQ(output["StatusCodeField"].as<StatusCode>(), StatusCode{Status::BadInternalError});
  auto expectedQName = QualifiedName{1, "TestName"};
  EXPECT_EQ(output["QName"].as<QualifiedName>(), expectedQName);
  auto expectedLText = LocalizedText{"en", "Hello"};
  EXPECT_EQ(output["LText"].as<LocalizedText>(), expectedLText);

  EXPECT_TRUE(input == output);
}

TEST(DynamicStructure, EncodeDecodeOptionalFields)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Required", DataTypeId::Int32, false));
  fields.push_back(make_field("Optional1", DataTypeId::String, true));
  fields.push_back(make_field("Optional2", DataTypeId::Boolean, true));

  auto desc =
    make_test_descriptor("OptionalRoundTrip", StructureType::StructureWithOptionalFields, std::move(fields));

  DynamicStructure input(desc);
  input["Required"] = Variant{int32_t{42}};
  input["Optional1"] = Variant{String{"present"}};
  input.set_field_present("Optional1", true);
  // Optional2 is absent

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  input.encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure output(desc);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  EXPECT_EQ(output["Required"].as<int32_t>(), 42);
  EXPECT_TRUE(output.has_field("Optional1"));
  EXPECT_EQ(output["Optional1"].as<String>(), String{"present"});
  EXPECT_FALSE(output.has_field("Optional2"));

  EXPECT_TRUE(input == output);
}

TEST(DynamicStructure, Descriptor)
{
  auto desc = make_test_descriptor();
  DynamicStructure ds(desc);

  EXPECT_EQ(&ds.descriptor(), desc.get());
}

// ============================================================================
// Nested dynamic structure encode/decode (Phase 5)
// ============================================================================

TEST(DynamicStructure, NestedStructureInlineEncodeDecodeRoundTrip)
{
  // Inner type: { Label: String, Score: Double }
  NodeId innerTypeNodeId{1, uint32_t{5000}};
  ExpandedNodeId innerTypeId{innerTypeNodeId, "urn:test:ns"};
  ExpandedNodeId innerEncodingId{NodeId{1, uint32_t{5001}}, "urn:test:ns"};

  std::vector<StructureField> innerFields;
  innerFields.push_back(make_field("Label", DataTypeId::String));
  innerFields.push_back(make_field("Score", DataTypeId::Double));

  auto innerDesc = std::make_shared<DynamicStructureTypeDescriptor>(String{"InnerType"},
    innerTypeId,
    innerEncodingId,
    make_definition(StructureType::Structure, innerFields));

  // Outer type: { Name: String, Inner: InnerType (concrete, inline encoded) }
  std::vector<StructureField> outerFields;
  outerFields.push_back(make_field("Name", DataTypeId::String));
  outerFields.push_back(make_field("Inner", innerTypeNodeId));

  auto outerDesc = std::make_shared<DynamicStructureTypeDescriptor>(String{"OuterType"},
    ExpandedNodeId{NodeId{1, uint32_t{6000}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{6001}}, "urn:test:ns"},
    make_definition(StructureType::Structure, outerFields));

  // Resolve the nested descriptor slot
  outerDesc->resolve_nested(1, innerDesc);

  // Build and populate
  DynamicStructure outer(outerDesc);
  outer["Name"] = Variant{String{"Parent"}};

  auto inner = std::make_unique<DynamicStructure>(innerDesc);
  (*inner)["Label"] = Variant{String{"Child"}};
  (*inner)["Score"] = Variant{double{99.5}};
  outer["Inner"] = Variant{std::move(inner)};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  outer.encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure decoded(outerDesc);
  Decoder dec(decoder);
  decoded.decode(make_limit(), dec);

  EXPECT_EQ(decoded["Name"].as<String>(), String{"Parent"});
  ASSERT_TRUE(decoded["Inner"].is_structure());
  const auto& decodedInner = decoded["Inner"].as<Structure>();
  auto* innerDs = dynamic_cast<const DynamicStructure*>(&decodedInner);
  ASSERT_NE(innerDs, nullptr);
  EXPECT_EQ((*innerDs)["Label"].as<String>(), String{"Child"});
  EXPECT_DOUBLE_EQ((*innerDs)["Score"].as<double>(), 99.5);
}

TEST(DynamicStructure, ThreeLevelNestedEncodeDecodeRoundTrip)
{
  // Type C: { Value: Int32 }
  NodeId typeCNodeId{1, uint32_t{7000}};
  auto descC = std::make_shared<DynamicStructureTypeDescriptor>(String{"TypeC"},
    ExpandedNodeId{typeCNodeId, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{7001}}, "urn:test:ns"},
    make_definition(StructureType::Structure, {make_field("Value", DataTypeId::Int32)}));

  // Type B: { Tag: String, Nested: TypeC }
  NodeId typeBNodeId{1, uint32_t{8000}};
  auto descB = std::make_shared<DynamicStructureTypeDescriptor>(String{"TypeB"},
    ExpandedNodeId{typeBNodeId, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{8001}}, "urn:test:ns"},
    make_definition(
      StructureType::Structure, {make_field("Tag", DataTypeId::String), make_field("Nested", typeCNodeId)}));

  // Type A: { Count: UInt32, Child: TypeB }
  auto descA = std::make_shared<DynamicStructureTypeDescriptor>(String{"TypeA"},
    ExpandedNodeId{NodeId{1, uint32_t{9000}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{9001}}, "urn:test:ns"},
    make_definition(
      StructureType::Structure, {make_field("Count", DataTypeId::UInt32), make_field("Child", typeBNodeId)}));

  // Resolve nested descriptors
  descB->resolve_nested(1, descC);
  descA->resolve_nested(1, descB);

  // Build: A { Count=42, Child=B { Tag="hello", Nested=C { Value=7 } } }
  auto innerC = std::make_unique<DynamicStructure>(descC);
  (*innerC)["Value"] = Variant{int32_t{7}};

  auto innerB = std::make_unique<DynamicStructure>(descB);
  (*innerB)["Tag"] = Variant{String{"hello"}};
  (*innerB)["Nested"] = Variant{std::move(innerC)};

  DynamicStructure outerA(descA);
  outerA["Count"] = Variant{uint32_t{42}};
  outerA["Child"] = Variant{std::move(innerB)};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  outerA.encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure decoded(descA);
  Decoder dec(decoder);
  decoded.decode(make_limit(), dec);

  EXPECT_EQ(decoded["Count"].as<uint32_t>(), 42u);

  ASSERT_TRUE(decoded["Child"].is_structure());
  const auto& decodedB = dynamic_cast<const DynamicStructure&>(decoded["Child"].as<Structure>());
  EXPECT_EQ(decodedB["Tag"].as<String>(), String{"hello"});

  ASSERT_TRUE(decodedB["Nested"].is_structure());
  const auto& decodedC = dynamic_cast<const DynamicStructure&>(decodedB["Nested"].as<Structure>());
  EXPECT_EQ(decodedC["Value"].as<int32_t>(), 7);
}

TEST(DynamicStructure, AbstractStructureFieldUsesExtensionObject)
{
  // A field typed as abstract Structure (DataTypeId::Structure = i=22) should encode as ExtensionObject
  std::vector<StructureField> fields;
  fields.push_back(make_field("Name", DataTypeId::String));
  fields.push_back(make_field("Payload", DataTypeId::Structure));  // abstract

  auto desc = std::make_shared<DynamicStructureTypeDescriptor>(String{"ContainerType"},
    ExpandedNodeId{NodeId{1, uint32_t{11000}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{11001}}, "urn:test:ns"},
    make_definition(StructureType::Structure, std::move(fields)));

  // The nested descriptor for abstract Structure should be null (not resolved)
  EXPECT_FALSE(desc->nested_descriptor(1));

  // Build with a known static type in the Payload field
  DynamicStructure ds(desc);
  ds["Name"] = Variant{String{"test"}};

  // We need the static type's factory registered for decoding to work
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);

  // Use SignatureData as the payload
  auto sig = std::make_unique<SignatureData>();
  sig->algorithm() = String{"RSA-SHA256"};
  sig->signature() = ByteString{0x01, 0x02};
  ds["Payload"] = Variant{std::move(sig)};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  ds.encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure decoded(desc);
  Decoder dec(decoder);
  decoded.decode(make_limit(), dec);

  EXPECT_EQ(decoded["Name"].as<String>(), String{"test"});
  ASSERT_TRUE(decoded["Payload"].is_structure());
  auto* decodedSig = dynamic_cast<const SignatureData*>(&decoded["Payload"].as<Structure>());
  ASSERT_NE(decodedSig, nullptr);
  EXPECT_EQ(decodedSig->algorithm(), String{"RSA-SHA256"});
  EXPECT_EQ(decodedSig->signature(), ByteString({0x01, 0x02}));
}

TEST(DynamicStructure, NestedViaRegistryEagerResolution)
{
  // Register types in dependency order (inner first, then outer)
  // to verify eager resolution produces working encode/decode
  StructureFactory factory;
  DynamicTypeRegistry registry;

  // Type IDs use ns=0 with URI (registry convention)
  NodeId innerFieldDataType{1, uint32_t{12000}};  // as it appears in the StructureField
  ExpandedNodeId innerTypeId{NodeId{0, uint32_t{12000}}, "urn:test:ns"};
  ExpandedNodeId innerEncodingId{NodeId{0, uint32_t{12001}}, "urn:test:ns"};

  NodeId outerFieldDataType{1, uint32_t{13000}};
  ExpandedNodeId outerTypeId{NodeId{0, uint32_t{13000}}, "urn:test:ns"};
  ExpandedNodeId outerEncodingId{NodeId{0, uint32_t{13001}}, "urn:test:ns"};

  // Register inner first (the dependency)
  std::vector<StructureField> innerFields;
  innerFields.push_back(make_field("Label", DataTypeId::String));

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(innerFields)),
                  innerTypeId,
                  innerEncodingId,
                  String{"InnerType"})
                .is_good());

  // Register outer (has field of inner type - should resolve eagerly via nsLookup)
  std::vector<StructureField> outerFields;
  outerFields.push_back(make_field("Id", DataTypeId::UInt32));
  outerFields.push_back(make_field("Detail", innerFieldDataType));

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(outerFields)),
                  outerTypeId,
                  outerEncodingId,
                  String{"OuterType"},
                  test_ns_lookup())
                .is_good());

  registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
    { factory.register_type(id, std::move(create)); },
    test_ns_index_lookup());

  // Create via factory and populate - use ns=1 since test_ns_index_lookup maps "urn:test:ns" to 1
  auto outerInstance = factory.create_instance(NodeId{1, uint32_t{13001}});
  ASSERT_NE(outerInstance, nullptr);
  auto* outerDs = dynamic_cast<DynamicStructure*>(outerInstance.get());
  ASSERT_NE(outerDs, nullptr);

  (*outerDs)["Id"] = Variant{uint32_t{42}};

  auto innerInstance = factory.create_instance(NodeId{1, uint32_t{12001}});
  auto* innerDs = dynamic_cast<DynamicStructure*>(innerInstance.get());
  ASSERT_NE(innerDs, nullptr);
  (*innerDs)["Label"] = Variant{String{"nested"}};
  (*outerDs)["Detail"] = Variant{std::move(innerInstance)};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  outerDs->encode(make_limit(), enc);

  // Decode
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  auto decodedOuter = factory.create_instance(NodeId{1, uint32_t{13001}});
  auto* decodedDs = dynamic_cast<DynamicStructure*>(decodedOuter.get());
  ASSERT_NE(decodedDs, nullptr);

  Decoder dec(decoder);
  decodedDs->decode(make_limit(), dec);

  EXPECT_EQ((*decodedDs)["Id"].as<uint32_t>(), 42u);
  ASSERT_TRUE((*decodedDs)["Detail"].is_structure());
  const auto& decodedInner = dynamic_cast<const DynamicStructure&>((*decodedDs)["Detail"].as<Structure>());
  EXPECT_EQ(decodedInner["Label"].as<String>(), String{"nested"});
}

// ============================================================================
// Allocation-cap on the manual array-of-structure decode (security regression)
// ============================================================================

// The array-of-structure branch in decode_dynamic_field hand-rolls its element loop instead of going
// through the typed decode(Array<T>&). It must still enforce EncodingLimits::maxArrayLength before
// resize(), or a few wire bytes (just the int32 length) drive a multi-GB pre-allocation - an
// unbounded-allocation DoS reachable pre-auth via any dynamically-typed field in a request body.
TEST(DynamicStructure, ArrayOfStructureFieldRejectsOversizedLength)
{
  // Inner type: { Value: Int32 }
  const NodeId innerTypeNodeId{1, uint32_t{7000}};
  std::vector<StructureField> innerFields;
  innerFields.push_back(make_field("Value", DataTypeId::Int32));
  auto innerDesc = std::make_shared<DynamicStructureTypeDescriptor>(String{"InnerType"},
    ExpandedNodeId{innerTypeNodeId, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{7001}}, "urn:test:ns"},
    make_definition(StructureType::Structure, innerFields));

  // Outer type: { Items: InnerType[] } - a single 1-D array-of-structure field, no optionals (so the
  // wire begins directly with the array length, no encoding mask).
  StructureField arrayField = make_field("Items", innerTypeNodeId);
  arrayField.value_rank() = 1;  // 1-D array
  std::vector<StructureField> outerFields;
  outerFields.push_back(std::move(arrayField));
  auto outerDesc = std::make_shared<DynamicStructureTypeDescriptor>(String{"OuterType"},
    ExpandedNodeId{NodeId{1, uint32_t{8000}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{8001}}, "urn:test:ns"},
    make_definition(StructureType::Structure, outerFields));
  outerDesc->resolve_nested(0, innerDesc);

  // Hostile wire: ONLY the array length field = INT32_MAX (little-endian). A correct decoder rejects
  // on the MaxArrayLength cap (default 65535) before allocating ~2.1e9 Variants; it never reads an
  // element, so no element bytes follow.
  const std::vector<ua::byte> wire{static_cast<ua::byte>(0xFF),
    static_cast<ua::byte>(0xFF),
    static_cast<ua::byte>(0xFF),
    static_cast<ua::byte>(0x7F)};

  memory_stream_device::ExternalReadOnly device{wire};
  MemoryStream stream{device};
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DynamicStructure decoded(outerDesc);
  Decoder dec(decoder);
  try
  {
    decoded.decode(make_limit(), dec);
    FAIL() << "expected the oversized array-of-structure length to be rejected";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadEncodingLimitsExceeded);
  }
}

// Part 3 section 8.49 Table 33's `StructureType` enum and Table 34's `IsOptional` row, read together, and
// the reading matters because the flag is overloaded:
//
//   StructureWithSubtypedValues  3  "A Structure **without optional fields** where one or more of the
//                                    fields allow subtyping"
//   IsOptional  "... If the structureType is StructureWithSubtypedValues, or UnionWithSubTypedValues
//                this field is used to indicate **if the data type field allows subtyping**.
//                Subtyping is allowed when set to TRUE."
//
// So a `StructureWithSubtypedValues` has no optional fields at all, and `isOptional == TRUE` on one of
// its fields does not mean the field may be absent - it means the field may carry a subtype. The
// criterion this discharges once read the flag by its name and asked for "a StructureWithSubtypedValues
// carrying an optional field", which is a combination the enum does not admit: optionality lives in
// StructureWithOptionalFields (value 1) and subtyping in value 3, and a StructureDefinition has exactly
// one structureType.
//
// What the clause does require is in the DataType row: "If the structureType is
// StructureWithSubtypedValues, or UnionWithSubtypedValues and the isOptional field is TRUE then the
// encoding of the field **shall be able to transport any subtype of the DataType**." That is the
// obligation, and it is what this drives: a field declared as the abstract `Structure` DataType with
// subtyping allowed, carrying a concrete subtype, must survive encode and decode as that subtype
// rather than being flattened to what the declaration says.
//
// The control is the neighbouring non-subtyped field. Without it a decoder that lost every field would
// pass the subtype check vacuously by returning nothing at all.
// @verifies AC-SVR-ADDRSP-229-SUBTYPED-OPTIONAL-FIELDS
TEST(DynamicStructure, SubtypedValuesFieldTransportsTheConcreteSubtypeItWasGiven)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Label", DataTypeId::String, /*isOptional=*/false));
  // isOptional TRUE under StructureWithSubtypedValues means "this field allows subtyping".
  fields.push_back(make_field("Payload", DataTypeId::Structure, /*isOptional=*/true));

  auto desc = std::make_shared<DynamicStructureTypeDescriptor>(String{"SubtypedContainerType"},
    ExpandedNodeId{NodeId{1, uint32_t{11200}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{11201}}, "urn:test:ns"},
    make_definition(StructureType::StructureWithSubtypedValues, std::move(fields)));

  ASSERT_EQ(desc->definition().structure_type(), StructureType::StructureWithSubtypedValues)
    << "the descriptor did not keep the structureType, so what follows is not about subtyped values";

  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);

  DynamicStructure input(desc);
  input["Label"] = Variant{String{"subtyped"}};

  auto sig = std::make_unique<SignatureData>();
  sig->algorithm() = String{"RSA-SHA256"};
  sig->signature() = ByteString{0x0A, 0x0B, 0x0C};
  input["Payload"] = Variant{std::move(sig)};

  EXPECT_TRUE(input.has_field("Payload"))
    << "isOptional means allows-subtyping for this structureType, never field absence";
  EXPECT_THROW(input.set_field_present("Payload", false), UaException)
    << "a subtyping permission must not expose the optional-field presence API";
  EXPECT_EQ(input.to_string().find("<absent>"), std::string::npos)
    << "diagnostic rendering must not describe a mandatory subtyped field as absent";

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  input.encode(make_limit(), enc);

  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  DynamicStructure output(desc);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  EXPECT_EQ(output["Label"].as<String>(), String{"subtyped"})
    << "the non-subtyped field did not survive the round trip, so a failure below would be about the "
       "decoder generally rather than about subtyped values";

  ASSERT_TRUE(output["Payload"].is_structure())
    << "the subtyping-allowed field did not decode as a Structure at all, so the encoding did not "
       "transport the value it was given";
  const auto* decodedSig = dynamic_cast<const SignatureData*>(&output["Payload"].as<Structure>());
  ASSERT_NE(decodedSig, nullptr)
    << "the subtyping-allowed field decoded as something other than the SignatureData it was given. "
       "Part 3 Table 34 requires the encoding of such a field to transport any subtype of the "
       "declared DataType; a field that arrives as its declared abstract type has lost which subtype "
       "it was, and no reader can recover it";
  EXPECT_EQ(decodedSig->algorithm(), String{"RSA-SHA256"});
  EXPECT_EQ(decodedSig->signature(), ByteString({0x0A, 0x0B, 0x0C}));

  EXPECT_TRUE(input == output) << "the round trip changed the value";
}

// The EncodingMask is a UInt32 (Part 6 section 5.2.7): 32 optional fields are the most a structure
// can carry, and the 33rd is refused rather than shifted out of range.
// @relation(AC-SVR-UASC-064-OPTIONAL-FIELD-COUNT-IS-BOUNDED, scope=function)
TEST(DynamicStructure, ThirtyThirdOptionalFieldIsRefused)
{
  std::vector<StructureField> fields;
  for (int i = 1; i <= 33; ++i)
  {
    fields.push_back(make_field("Optional" + std::to_string(i), DataTypeId::Int32, true));
  }
  auto desc =
    make_test_descriptor("TooManyOptional", StructureType::StructureWithOptionalFields, std::move(fields));
  DynamicStructure ds(desc);

  try
  {
    ds.set_field_present("Optional33", true);
    FAIL() << "the 33rd optional field has no encoding-mask bit";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadEncodingLimitsExceeded);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "TooManyOptionalFields");
  }
}

// @relation(AC-SVR-UASC-064-OPTIONAL-FIELD-COUNT-IS-BOUNDED, scope=function)  // control arm
TEST(DynamicStructure, ThirtyTwoOptionalFieldsAreAddressable)
{
  std::vector<StructureField> fields;
  for (int i = 1; i <= 32; ++i)
  {
    fields.push_back(make_field("Optional" + std::to_string(i), DataTypeId::Int32, true));
  }
  auto desc =
    make_test_descriptor("MaxOptional", StructureType::StructureWithOptionalFields, std::move(fields));
  DynamicStructure ds(desc);

  EXPECT_NO_THROW(ds.set_field_present("Optional32", true));
  EXPECT_TRUE(ds.has_field("Optional32"));
  EXPECT_FALSE(ds.has_field("Optional31"));
}
