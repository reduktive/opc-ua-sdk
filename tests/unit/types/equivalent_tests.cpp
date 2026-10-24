// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_value.h"
#include <gtest/gtest.h>
#include "ua_structure.h"
#include "ua_signature_data.h"
#include "ua_eu_information.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_datatype_id.h"

using namespace ua;

namespace
{

/// Helper: build a StructureField
StructureField make_field(string_view name, DataTypeId dataType)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = NodeId{dataType};
  field.value_rank() = -1;  // Scalar
  field.is_optional() = false;
  return field;
}

/// Helper: build a StructureDefinition with the given fields
StructureDefinition make_definition(std::vector<StructureField> fields)
{
  StructureDefinition def;
  def.structure_type() = StructureType::Structure;
  Array<StructureField> fieldArray;
  fieldArray.resize(fields.size());
  for (size_t i = 0; i < fields.size(); ++i)
  {
    fieldArray[i] = std::move(fields[i]);
  }
  def.fields() = std::move(fieldArray);
  return def;
}

/// Helper: create a descriptor for a simple two-field test type
shared_ptr<const DynamicStructureTypeDescriptor> make_two_field_descriptor(
  string_view typeName = "TestType", uint32_t typeNumericId = 1000, uint32_t encodingNumericId = 1001)
{
  std::vector<StructureField> fields;
  fields.push_back(make_field("FieldA", DataTypeId::String));
  fields.push_back(make_field("FieldB", DataTypeId::Int32));

  auto def = make_definition(std::move(fields));

  ExpandedNodeId typeId{NodeId{1, typeNumericId}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, encodingNumericId}, "urn:test:ns"};

  return std::make_shared<DynamicStructureTypeDescriptor>(
    String{typeName}, std::move(typeId), std::move(encodingId), std::move(def));
}

}  // namespace

// ============================================================================
// Static-to-static tests
// ============================================================================

TEST(Equivalent, StaticToStatic_Equal)
{
  SignatureData a;
  a.algorithm() = String{"RSA-SHA256"};
  a.signature() = ByteString{0x01, 0x02, 0x03};

  SignatureData b;
  b.algorithm() = String{"RSA-SHA256"};
  b.signature() = ByteString{0x01, 0x02, 0x03};

  EXPECT_TRUE(equivalent(a, b));
}

TEST(Equivalent, StaticToStatic_NotEqual)
{
  SignatureData a;
  a.algorithm() = String{"RSA-SHA256"};
  a.signature() = ByteString{0x01, 0x02, 0x03};

  SignatureData b;
  b.algorithm() = String{"RSA-SHA1"};
  b.signature() = ByteString{0x04, 0x05};

  EXPECT_FALSE(equivalent(a, b));
}

TEST(Equivalent, DifferentTypes_NotEquivalent)
{
  SignatureData sig;
  sig.algorithm() = String{"RSA-SHA256"};

  EUInformation eu;
  eu.namespace_uri() = String{"http://example.org"};
  eu.unit_id() = 42;

  EXPECT_FALSE(equivalent(sig, eu));
}

TEST(Equivalent, SameObject_Equivalent)
{
  SignatureData a;
  a.algorithm() = String{"test"};

  EXPECT_TRUE(equivalent(a, a));
}

TEST(Equivalent, DefaultConstructed_Equivalent)
{
  SignatureData a;
  SignatureData b;

  EXPECT_TRUE(equivalent(a, b));
}

// ============================================================================
// Dynamic-to-dynamic tests
// ============================================================================

TEST(Equivalent, DynamicToDynamic_Equal)
{
  auto descriptor = make_two_field_descriptor();

  DynamicStructure a(descriptor);
  a[string_view{"FieldA"}] = Variant{String{"hello"}};
  a[string_view{"FieldB"}] = Variant{int32_t{42}};

  DynamicStructure b(descriptor);
  b[string_view{"FieldA"}] = Variant{String{"hello"}};
  b[string_view{"FieldB"}] = Variant{int32_t{42}};

  EXPECT_TRUE(equivalent(a, b));
}

TEST(Equivalent, DynamicToDynamic_NotEqual)
{
  auto descriptor = make_two_field_descriptor();

  DynamicStructure a(descriptor);
  a[string_view{"FieldA"}] = Variant{String{"hello"}};
  a[string_view{"FieldB"}] = Variant{int32_t{42}};

  DynamicStructure b(descriptor);
  b[string_view{"FieldA"}] = Variant{String{"world"}};
  b[string_view{"FieldB"}] = Variant{int32_t{99}};

  EXPECT_FALSE(equivalent(a, b));
}

TEST(Equivalent, DynamicDifferentTypes_NotEquivalent)
{
  auto descriptorA = make_two_field_descriptor("TypeA", 1000, 1001);
  auto descriptorB = make_two_field_descriptor("TypeB", 2000, 2001);

  DynamicStructure a(descriptorA);
  a[string_view{"FieldA"}] = Variant{String{"hello"}};
  a[string_view{"FieldB"}] = Variant{int32_t{42}};

  DynamicStructure b(descriptorB);
  b[string_view{"FieldA"}] = Variant{String{"hello"}};
  b[string_view{"FieldB"}] = Variant{int32_t{42}};

  EXPECT_FALSE(equivalent(a, b));
}

TEST(Equivalent, DynamicDefaultConstructed_Equivalent)
{
  auto descriptor = make_two_field_descriptor();

  DynamicStructure a(descriptor);
  DynamicStructure b(descriptor);

  EXPECT_TRUE(equivalent(a, b));
}

// ============================================================================
// Mixed static/dynamic (basic - different types)
// ============================================================================

TEST(Equivalent, StaticVsDynamic_DifferentType_NotEquivalent)
{
  SignatureData sig;
  sig.algorithm() = String{"test"};

  auto descriptor = make_two_field_descriptor();
  DynamicStructure dyn(descriptor);
  dyn[string_view{"FieldA"}] = Variant{String{"test"}};

  EXPECT_FALSE(equivalent(sig, dyn));
}

// ============================================================================
// Cross-type equivalence: static vs dynamic with same type definition
// ============================================================================

TEST(Equivalent, StaticVsDynamic_SameType_Equivalent)
{
  // Build a DynamicStructure matching SignatureData's definition
  // SignatureData: type=456, encoding=458, ns="http://opcfoundation.org/UA/"
  // Fields: Algorithm (String), Signature (ByteString)
  std::vector<StructureField> fields;
  {
    StructureField f;
    f.name() = String{"Algorithm"};
    f.data_type() = NodeId{DataTypeId::String};
    f.value_rank() = -1;
    f.is_optional() = false;
    fields.push_back(std::move(f));
  }
  {
    StructureField f;
    f.name() = String{"Signature"};
    f.data_type() = NodeId{DataTypeId::ByteString};
    f.value_rank() = -1;
    f.is_optional() = false;
    fields.push_back(std::move(f));
  }

  StructureDefinition def;
  def.structure_type() = StructureType::Structure;
  Array<StructureField> fieldArray;
  fieldArray.resize(fields.size());
  for (size_t i = 0; i < fields.size(); ++i)
  {
    fieldArray[i] = std::move(fields[i]);
  }
  def.fields() = std::move(fieldArray);

  ExpandedNodeId typeId{NodeId{0, uint32_t{456}}, "http://opcfoundation.org/UA/"};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{458}}, "http://opcfoundation.org/UA/"};

  auto descriptor = std::make_shared<DynamicStructureTypeDescriptor>(
    String{"SignatureData"}, typeId, encodingId, std::move(def));

  // Create static
  SignatureData sig;
  sig.algorithm() = String{"RSA-SHA256"};
  sig.signature() = ByteString{0xAA, 0xBB, 0xCC};

  // Create dynamic with same values
  DynamicStructure dyn(descriptor);
  dyn[string_view{"Algorithm"}] = Variant{String{"RSA-SHA256"}};
  dyn[string_view{"Signature"}] = Variant{ByteString{0xAA, 0xBB, 0xCC}};

  EXPECT_TRUE(equivalent(sig, dyn));
  EXPECT_TRUE(equivalent(dyn, sig));
}

TEST(Equivalent, StaticVsDynamic_SameType_DifferentValues_NotEquivalent)
{
  std::vector<StructureField> fields;
  {
    StructureField f;
    f.name() = String{"Algorithm"};
    f.data_type() = NodeId{DataTypeId::String};
    f.value_rank() = -1;
    f.is_optional() = false;
    fields.push_back(std::move(f));
  }
  {
    StructureField f;
    f.name() = String{"Signature"};
    f.data_type() = NodeId{DataTypeId::ByteString};
    f.value_rank() = -1;
    f.is_optional() = false;
    fields.push_back(std::move(f));
  }

  StructureDefinition def;
  def.structure_type() = StructureType::Structure;
  Array<StructureField> fieldArray;
  fieldArray.resize(fields.size());
  for (size_t i = 0; i < fields.size(); ++i)
  {
    fieldArray[i] = std::move(fields[i]);
  }
  def.fields() = std::move(fieldArray);

  ExpandedNodeId typeId{NodeId{0, uint32_t{456}}, "http://opcfoundation.org/UA/"};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{458}}, "http://opcfoundation.org/UA/"};

  auto descriptor = std::make_shared<DynamicStructureTypeDescriptor>(
    String{"SignatureData"}, typeId, encodingId, std::move(def));

  SignatureData sig;
  sig.algorithm() = String{"RSA-SHA256"};
  sig.signature() = ByteString{0x01};

  DynamicStructure dyn(descriptor);
  dyn[string_view{"Algorithm"}] = Variant{String{"RSA-SHA256"}};
  dyn[string_view{"Signature"}] = Variant{ByteString{0xFF}};  // different value

  EXPECT_FALSE(equivalent(sig, dyn));
}
