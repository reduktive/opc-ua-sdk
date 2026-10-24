// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_value.h"
#include <gtest/gtest.h>
#include "ua_dynamic_type_descriptor.h"
#include "ua_dynamic_union.h"
#include "ua_binary_codec.h"
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

/// Helper: build a StructureField
StructureField make_field(string_view name, DataTypeId dataType, bool allowsSubtyping = false)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = NodeId{dataType};
  field.value_rank() = -1;  // Scalar
  field.is_optional() = allowsSubtyping;
  return field;
}

/// Helper: create a union descriptor with 3 fields: Int32, String, Double
shared_ptr<const DynamicStructureTypeDescriptor> make_union_descriptor(
  string_view typeName = "TestUnion", StructureType structType = StructureType::Union)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("IntValue", DataTypeId::Int32));
  fields.push_back(make_field("StringValue", DataTypeId::String));
  fields.push_back(make_field("DoubleValue", DataTypeId::Double));

  auto def = make_definition(structType, std::move(fields));

  ExpandedNodeId typeId{NodeId{1, uint32_t{2000}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{2001}}, "urn:test:ns"};

  return std::make_shared<DynamicStructureTypeDescriptor>(
    String{typeName}, std::move(typeId), std::move(encodingId), std::move(def));
}

}  // namespace

// ============================================================================
// Construction
// ============================================================================

TEST(DynamicUnion, DefaultConstruction)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  EXPECT_EQ(du.switch_field(), 0u);
  EXPECT_EQ(du.field_count(), 3u);
}

TEST(DynamicUnion, ConstructionRejectsNonUnionDescriptor)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Field1", DataTypeId::Int32));

  auto def = make_definition(StructureType::Structure, std::move(fields));
  auto desc = std::make_shared<DynamicStructureTypeDescriptor>(String{"NotUnion"},
    ExpandedNodeId{NodeId{1, uint32_t{3000}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{3001}}, "urn:test:ns"},
    std::move(def));

  EXPECT_THROW(DynamicUnion du(desc), UaException);
}

// ============================================================================
// Select and access
// ============================================================================

TEST(DynamicUnion, SelectByName)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  du.select("IntValue", Variant{int32_t{42}});

  EXPECT_EQ(du.switch_field(), 1u);
  EXPECT_EQ(du.value().as<int32_t>(), 42);
  EXPECT_EQ(du.active_field_name(), "IntValue");
}

TEST(DynamicUnion, SelectByIndex)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  du.select(size_t{1}, Variant{String{"hello"}});

  EXPECT_EQ(du.switch_field(), 2u);
  EXPECT_EQ(du.value().as<String>(), String{"hello"});
  EXPECT_EQ(du.active_field_name(), "StringValue");
}

TEST(DynamicUnion, Clear)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  du.select("IntValue", Variant{int32_t{42}});
  EXPECT_EQ(du.switch_field(), 1u);

  du.clear();
  EXPECT_EQ(du.switch_field(), 0u);
  EXPECT_EQ(du.active_field_name(), string_view{});
}

TEST(DynamicUnion, ValueThrowsWhenNull)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  EXPECT_THROW(du.value(), UaException);
}

TEST(DynamicUnion, SelectOutOfRange)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  EXPECT_THROW(du.select(size_t{99}, Variant{int32_t{1}}), UaException);
}

TEST(DynamicUnion, SelectByNameUnknownField)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  EXPECT_THROW(du.select("NonExistent", Variant{int32_t{1}}), UaException);
}

// ============================================================================
// Encode/Decode round-trip
// ============================================================================

TEST(DynamicUnion, EncodeDecodeNullUnion)
{
  auto desc = make_union_descriptor();
  DynamicUnion input(desc);

  // Encode (switch=0, null union)
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

  DynamicUnion output(desc);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  EXPECT_EQ(output.switch_field(), 0u);
  EXPECT_TRUE(input == output);
}

TEST(DynamicUnion, EncodeDecodeWithValue)
{
  auto desc = make_union_descriptor();
  DynamicUnion input(desc);
  input.select("StringValue", Variant{String{"encoded"}});

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

  DynamicUnion output(desc);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  EXPECT_EQ(output.switch_field(), 2u);
  EXPECT_EQ(output.value().as<String>(), String{"encoded"});
  EXPECT_EQ(output.active_field_name(), "StringValue");
  EXPECT_TRUE(input == output);
}

TEST(DynamicUnion, EncodeDecodeAllFields)
{
  auto desc = make_union_descriptor();

  // Test each field alternative
  struct TestCase
  {
    string_view fieldName;
    Variant fieldValue;
    uint32_t expectedSwitch;
  };

  std::vector<TestCase> cases;
  cases.push_back({"IntValue", Variant{int32_t{-12345}}, 1});
  cases.push_back({"StringValue", Variant{String{"test string"}}, 2});
  cases.push_back({"DoubleValue", Variant{double{3.14159}}, 3});

  for (auto& tc : cases)
  {
    DynamicUnion input(desc);
    input.select(tc.fieldName, std::move(tc.fieldValue));

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

    DynamicUnion output(desc);
    Decoder dec(decoder);
    output.decode(make_limit(), dec);

    EXPECT_EQ(output.switch_field(), tc.expectedSwitch) << "Failed for field: " << tc.fieldName;
    EXPECT_TRUE(input == output) << "Failed for field: " << tc.fieldName;
  }
}

// Part 3 section 8.51: for UnionWithSubtypedValues, isOptional=TRUE means the selected field may carry any
// subtype of its declared DataType. It does not make the union arm optional. This is the union control
// for AC-SVR-ADDRSP-229-SUBTYPED-OPTIONAL-FIELDS; the Structure sibling exercises the overloaded flag's
// presence-mask hazard, while this arm proves the same concrete subtype survives the union switch path.
// @verifies AC-SVR-ADDRSP-229-SUBTYPED-OPTIONAL-FIELDS
TEST(DynamicUnion, SubtypingAllowedFieldTransportsTheConcreteSubtypeItWasGiven)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("Payload", DataTypeId::Structure, /*allowsSubtyping=*/true));

  auto descriptor = std::make_shared<DynamicStructureTypeDescriptor>(String{"SubtypedUnionType"},
    ExpandedNodeId{NodeId{1, uint32_t{11300}}, "urn:test:ns"},
    ExpandedNodeId{NodeId{1, uint32_t{11301}}, "urn:test:ns"},
    make_definition(StructureType::UnionWithSubtypedValues, std::move(fields)));

  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);

  auto signature = std::make_unique<SignatureData>();
  signature->algorithm() = String{"RSA-SHA256"};
  signature->signature() = ByteString{0x0A, 0x0B, 0x0C};

  DynamicUnion input(descriptor);
  input.select("Payload", Variant{std::move(signature)});

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  input.encode(make_limit(), enc);

  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  DynamicUnion output(descriptor);
  Decoder dec(decoder);
  output.decode(make_limit(), dec);

  ASSERT_EQ(output.active_field_name(), "Payload");
  ASSERT_TRUE(output.value().is_structure());
  const auto* decodedSignature = dynamic_cast<const SignatureData*>(&output.value().as<Structure>());
  ASSERT_NE(decodedSignature, nullptr);
  EXPECT_EQ(decodedSignature->algorithm(), String{"RSA-SHA256"});
  EXPECT_EQ(decodedSignature->signature(), ByteString({0x0A, 0x0B, 0x0C}));
  EXPECT_TRUE(input == output);
}

// ============================================================================
// Clone
// ============================================================================

TEST(DynamicUnion, Clone)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);
  du.select("IntValue", Variant{int32_t{100}});

  auto cloned = du.clone();
  auto* clonedUnion = dynamic_cast<DynamicUnion*>(cloned.get());
  ASSERT_NE(clonedUnion, nullptr);

  // Verify clone has same values
  EXPECT_EQ(clonedUnion->switch_field(), 1u);
  EXPECT_EQ(clonedUnion->value().as<int32_t>(), 100);

  // Modify original, clone should be unaffected
  du.select("DoubleValue", Variant{double{9.9}});
  EXPECT_EQ(clonedUnion->switch_field(), 1u);
  EXPECT_EQ(clonedUnion->value().as<int32_t>(), 100);
  EXPECT_EQ(du.switch_field(), 3u);
}

// ============================================================================
// Equality
// ============================================================================

TEST(DynamicUnion, EqualitySameFieldAndValue)
{
  auto desc = make_union_descriptor();

  DynamicUnion du1(desc);
  du1.select("IntValue", Variant{int32_t{42}});

  DynamicUnion du2(desc);
  du2.select("IntValue", Variant{int32_t{42}});

  EXPECT_TRUE(du1 == du2);
}

TEST(DynamicUnion, EqualityDifferentField)
{
  auto desc = make_union_descriptor();

  DynamicUnion du1(desc);
  du1.select("IntValue", Variant{int32_t{42}});

  DynamicUnion du2(desc);
  du2.select("DoubleValue", Variant{double{42.0}});

  EXPECT_FALSE(du1 == du2);
}

TEST(DynamicUnion, EqualityNullVsNonNull)
{
  auto desc = make_union_descriptor();

  DynamicUnion du1(desc);

  DynamicUnion du2(desc);
  du2.select("IntValue", Variant{int32_t{0}});

  EXPECT_FALSE(du1 == du2);
}

TEST(DynamicUnion, EqualityBothNull)
{
  auto desc = make_union_descriptor();

  DynamicUnion du1(desc);
  DynamicUnion du2(desc);

  EXPECT_TRUE(du1 == du2);
}

TEST(DynamicUnion, EqualityDifferentDescriptor)
{
  auto desc1 = make_union_descriptor("Union1");
  auto desc2 = make_union_descriptor("Union2");

  DynamicUnion du1(desc1);
  DynamicUnion du2(desc2);

  EXPECT_FALSE(du1 == du2);
}

// ============================================================================
// Type identity
// ============================================================================

TEST(DynamicUnion, TypeId)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  auto expandedId = du.type_id();
  EXPECT_EQ(expandedId.namespace_uri(), String{"urn:test:ns"});
  EXPECT_EQ(expandedId.node_id().identifier().get_numeric(), 2000u);
}

TEST(DynamicUnion, TypeName)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  EXPECT_EQ(string_view(du.type_name()), "TestUnion");
}

TEST(DynamicUnion, IsOfType)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  CodecNamespaceContext ns{[](string_view uri) -> uint16_t
    {
      if (uri == "urn:test:ns")
        return 1;
      return 0;
    }};

  // Should match its own type
  EXPECT_TRUE(du.is_of_type(ns, NodeId{1, uint32_t{2000}}));

  // D13: a union is a subtype of Union (i=12756) and of Structure (i=22); StructureType (i=98) is the
  // Enumeration of structure kinds, not a supertype.
  EXPECT_TRUE(du.is_of_type(ns, NodeId{DataTypeId::Union}));
  EXPECT_TRUE(du.is_of_type(ns, NodeId{DataTypeId::Structure}));
  EXPECT_TRUE(du.is_of_type(ns, NodeId{DataTypeId::BaseDataType}));
  EXPECT_FALSE(du.is_of_type(ns, NodeId{DataTypeId::StructureType}));

  // Should not match a different type
  EXPECT_FALSE(du.is_of_type(ns, NodeId{1, uint32_t{9999}}));
}

// ============================================================================
// to_string
// ============================================================================

TEST(DynamicUnion, ToStringSmoke)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  // Null union
  auto str = du.to_string();
  EXPECT_FALSE(str.empty());
  EXPECT_NE(str.find("TestUnion"), std::string::npos);
  EXPECT_NE(str.find("<null>"), std::string::npos);

  // With a selected field
  du.select("IntValue", Variant{int32_t{42}});
  str = du.to_string();
  EXPECT_NE(str.find("TestUnion"), std::string::npos);
  EXPECT_NE(str.find("IntValue"), std::string::npos);
}

TEST(DynamicUnion, Descriptor)
{
  auto desc = make_union_descriptor();
  DynamicUnion du(desc);

  EXPECT_EQ(&du.descriptor(), desc.get());
}
