// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_value.h"
#include <gtest/gtest.h>
#include "ua_dynamic_type_registry.h"
#include "ua_dynamic_structure.h"
#include <optional>
#include "ua_dynamic_union.h"
#include "ua_exceptions.h"
#include "ua_structure_factory.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_memory_stream.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_datatype_id.h"

using namespace ua;

namespace
{

StackDepth make_limit()
{
  auto cfg = ApplicationConfig::load_default();
  return StackDepth{cfg.execution_limits().decodeWorkLimit};
}

const EncodingLimits& make_limits()
{
  static EncodingLimits limits = []
  {
    const auto cfg = ApplicationConfig::load_default();
    return make_encoding_limits(cfg);
  }();
  return limits;
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
StructureField make_field(string_view name, DataTypeId dataType, bool isOptional = false)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = NodeId{dataType};
  field.value_rank() = -1;  // Scalar
  field.is_optional() = isOptional;
  return field;
}

/// Helper: build a StructureField with a custom (non-NS0) data type
StructureField make_custom_field(string_view name, NodeId dataType)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = std::move(dataType);
  field.value_rank() = -1;
  field.is_optional() = false;
  return field;
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

}  // namespace

// ============================================================================
// Registration and lookup
// ============================================================================

TEST(DynamicTypeRegistry, RegisterStructure)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Name", DataTypeId::String));
  fields.push_back(make_field("Value", DataTypeId::Int32));

  ExpandedNodeId typeId{NodeId{1, uint32_t{1000}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{1001}}, "urn:test:ns"};

  auto result = registry.register_type(
    make_definition(StructureType::Structure, std::move(fields)), typeId, encodingId, String{"SimpleType"});
  ASSERT_TRUE(result.is_good());

  const auto found = registry.find_structure(typeId);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(string_view(found->type_name()), "SimpleType");
  EXPECT_EQ(found->field_count(), 2u);
}

TEST(DynamicTypeRegistry, RegisterEnum)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  EnumDefinition enumDef;
  Array<EnumField> enumFields;
  enumFields.resize(3);
  enumFields[0].value() = 0;
  enumFields[0].display_name() = LocalizedText{"", "Red"};
  enumFields[1].value() = 1;
  enumFields[1].display_name() = LocalizedText{"", "Green"};
  enumFields[2].value() = 2;
  enumFields[2].display_name() = LocalizedText{"", "Blue"};
  enumDef.fields() = std::move(enumFields);

  ExpandedNodeId typeId{NodeId{1, uint32_t{2000}}, "urn:test:ns"};

  auto result = registry.register_type(std::move(enumDef), typeId, String{"ColorEnum"});
  ASSERT_TRUE(result.is_good());

  const auto found = registry.find_enum(typeId);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(string_view(found->type_name()), "ColorEnum");
  EXPECT_FALSE(found->is_option_set());
}

TEST(DynamicTypeRegistry, RegisterEnumAsOptionSet)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  EnumDefinition enumDef;
  Array<EnumField> enumFields;
  enumFields.resize(2);
  enumFields[0].value() = 0;
  enumFields[0].display_name() = LocalizedText{"", "BitA"};
  enumFields[1].value() = 1;
  enumFields[1].display_name() = LocalizedText{"", "BitB"};
  enumDef.fields() = std::move(enumFields);

  ExpandedNodeId typeId{NodeId{1, uint32_t{2100}}, "urn:test:ns"};

  auto result = registry.register_type(std::move(enumDef), typeId, String{"FlagsOptionSet"}, true);
  ASSERT_TRUE(result.is_good());

  const auto found = registry.find_enum(typeId);
  ASSERT_NE(found, nullptr);
  EXPECT_TRUE(found->is_option_set());
}

// ============================================================================
// Factory integration
// ============================================================================

TEST(DynamicTypeRegistry, FactoryIntegration_StructureCreatedViaFactory)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Temperature", DataTypeId::Double));

  // NS0-only type IDs (no namespace URI) - required for no-arg register_all_with
  ExpandedNodeId typeId{NodeId{0, uint32_t{3000}}};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{3001}}};

  auto result = registry.register_type(make_definition(StructureType::Structure, std::move(fields)),
    typeId,
    encodingId,
    String{"SensorReading"});
  ASSERT_TRUE(result.is_good());

  // Wire types to the factory
  registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
    { factory.register_type(id, std::move(create)); });

  // The factory should now be able to create instances using the local encoding NodeId
  auto instance = factory.create_instance(encodingId.node_id());
  ASSERT_NE(instance, nullptr);

  // Verify it's a DynamicStructure
  auto* dynamicStruct = dynamic_cast<DynamicStructure*>(instance.get());
  ASSERT_NE(dynamicStruct, nullptr);
  EXPECT_EQ(dynamicStruct->field_count(), 1u);
  EXPECT_EQ(string_view(dynamicStruct->descriptor().type_name()), "SensorReading");
}

TEST(DynamicTypeRegistry, FactoryIntegration_UnionCreatedViaFactory)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("IntChoice", DataTypeId::Int32));
  fields.push_back(make_field("StringChoice", DataTypeId::String));

  // NS0-only type IDs (no namespace URI) - required for no-arg register_all_with
  ExpandedNodeId typeId{NodeId{0, uint32_t{4000}}};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{4001}}};

  auto result = registry.register_type(
    make_definition(StructureType::Union, std::move(fields)), typeId, encodingId, String{"MyUnion"});
  ASSERT_TRUE(result.is_good());

  registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
    { factory.register_type(id, std::move(create)); });

  auto instance = factory.create_instance(encodingId.node_id());
  ASSERT_NE(instance, nullptr);

  auto* dynamicUnion = dynamic_cast<DynamicUnion*>(instance.get());
  ASSERT_NE(dynamicUnion, nullptr);
  EXPECT_EQ(dynamicUnion->field_count(), 2u);
  EXPECT_EQ(string_view(dynamicUnion->descriptor().type_name()), "MyUnion");
}

TEST(DynamicTypeRegistry, FactoryIntegration_UnionWithSubtypedValues)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Choice", DataTypeId::Double));

  // NS0-only type IDs (no namespace URI) - required for no-arg register_all_with
  ExpandedNodeId typeId{NodeId{0, uint32_t{4100}}};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{4101}}};

  auto result =
    registry.register_type(make_definition(StructureType::UnionWithSubtypedValues, std::move(fields)),
      typeId,
      encodingId,
      String{"SubtypedUnion"});
  ASSERT_TRUE(result.is_good());

  registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
    { factory.register_type(id, std::move(create)); });

  auto instance = factory.create_instance(encodingId.node_id());
  ASSERT_NE(instance, nullptr);

  auto* dynamicUnion = dynamic_cast<DynamicUnion*>(instance.get());
  ASSERT_NE(dynamicUnion, nullptr);
}

// ============================================================================
// Eager resolution - dependencies must be registered before dependents
// ============================================================================

TEST(DynamicTypeRegistry, EagerResolution_DependencyRegisteredFirst)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  // Register type B first (simple type)
  std::vector<StructureField> fieldsB;
  fieldsB.push_back(make_field("X", DataTypeId::Int32));

  ExpandedNodeId typeIdB{NodeId{0, uint32_t{5000}}, "urn:test:ns"};
  ExpandedNodeId encodingIdB{NodeId{0, uint32_t{5001}}, "urn:test:ns"};

  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fieldsB)), typeIdB, encodingIdB, String{"TypeB"})
      .is_good());

  // Register type A which has a field of type B
  std::vector<StructureField> fieldsA;
  fieldsA.push_back(make_field("Label", DataTypeId::String));
  fieldsA.push_back(make_custom_field("Inner", NodeId{1, uint32_t{5000}}));

  ExpandedNodeId typeIdA{NodeId{1, uint32_t{6000}}, "urn:test:ns"};
  ExpandedNodeId encodingIdA{NodeId{1, uint32_t{6001}}, "urn:test:ns"};

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(fieldsA)),
                  typeIdA,
                  encodingIdA,
                  String{"TypeA"},
                  test_ns_lookup())
                .is_good());

  // Type A's nested slot for field "Inner" should be resolved to type B
  const auto descA = registry.find_structure(typeIdA);
  ASSERT_NE(descA, nullptr);
  ASSERT_NE(descA->nested_descriptor(1), nullptr);
  EXPECT_EQ(string_view(descA->nested_descriptor(1)->type_name()), "TypeB");
}

TEST(DynamicTypeRegistry, EagerResolution_DependencyOrderRequired)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  // Register type B first (the dependency)
  std::vector<StructureField> fieldsB;
  fieldsB.push_back(make_field("X", DataTypeId::Int32));

  ExpandedNodeId typeIdB{NodeId{0, uint32_t{5000}}, "urn:test:ns"};
  ExpandedNodeId encodingIdB{NodeId{0, uint32_t{5001}}, "urn:test:ns"};

  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fieldsB)), typeIdB, encodingIdB, String{"TypeB"})
      .is_good());

  // Now register type A which has a field of type B - should resolve eagerly
  std::vector<StructureField> fieldsA;
  fieldsA.push_back(make_field("Label", DataTypeId::String));
  fieldsA.push_back(make_custom_field("Inner", NodeId{1, uint32_t{5000}}));

  ExpandedNodeId typeIdA{NodeId{1, uint32_t{6000}}, "urn:test:ns"};
  ExpandedNodeId encodingIdA{NodeId{1, uint32_t{6001}}, "urn:test:ns"};

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(fieldsA)),
                  typeIdA,
                  encodingIdA,
                  String{"TypeA"},
                  test_ns_lookup())
                .is_good());

  // A's nested slot should be resolved immediately after registration
  const auto descA = registry.find_structure(typeIdA);
  ASSERT_NE(descA, nullptr);
  ASSERT_NE(descA->nested_descriptor(1), nullptr);
  EXPECT_EQ(string_view(descA->nested_descriptor(1)->type_name()), "TypeB");
  EXPECT_TRUE(descA->fully_resolved());
}

// ============================================================================
// Registration errors for unresolved dependencies
// ============================================================================

TEST(DynamicTypeRegistry, RegisterType_RejectsUnresolvedFieldDependency)
{
  DynamicTypeRegistry registry;

  // Register type A with a field of unknown custom type B - should fail
  std::vector<StructureField> fieldsA;
  fieldsA.push_back(make_field("Label", DataTypeId::String));
  fieldsA.push_back(make_custom_field("Inner", NodeId{1, uint32_t{9999}}));

  ExpandedNodeId typeIdA{NodeId{1, uint32_t{8000}}, "urn:test:ns"};
  ExpandedNodeId encodingIdA{NodeId{1, uint32_t{8001}}, "urn:test:ns"};

  auto result = registry.register_type(make_definition(StructureType::Structure, std::move(fieldsA)),
    typeIdA,
    encodingIdA,
    String{"TypeWithMissing"});

  EXPECT_FALSE(result.is_good()) << "register_type should fail when a field references an unregistered type";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadDataTypeIdUnknown});
}

TEST(DynamicTypeRegistry, RegisterType_AllowsAbstractStructureField)
{
  DynamicTypeRegistry registry;

  // Register type with a field of abstract "Structure" base type (NS0 id 22)
  // This should succeed - it means "any structure"
  std::vector<StructureField> fields;
  fields.push_back(make_field("AnyStruct", DataTypeId::Structure));

  ExpandedNodeId typeId{NodeId{1, uint32_t{8100}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{8101}}, "urn:test:ns"};

  auto result = registry.register_type(
    make_definition(StructureType::Structure, std::move(fields)), typeId, encodingId, String{"HasAbstract"});

  EXPECT_TRUE(result.is_good()) << "Abstract Structure (i=22) field should be allowed";
}

// ============================================================================
// Duplicate registration
// ============================================================================

TEST(DynamicTypeRegistry, DuplicateRegistration_Updates)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  ExpandedNodeId typeId{NodeId{1, uint32_t{9000}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{9001}}, "urn:test:ns"};

  // Register first version
  std::vector<StructureField> fields1;
  fields1.push_back(make_field("A", DataTypeId::Int32));

  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fields1)), typeId, encodingId, String{"V1"})
      .is_good());

  const auto found1 = registry.find_structure(typeId);
  ASSERT_NE(found1, nullptr);
  EXPECT_EQ(found1->field_count(), 1u);

  // Register second version with same typeId
  std::vector<StructureField> fields2;
  fields2.push_back(make_field("A", DataTypeId::Int32));
  fields2.push_back(make_field("B", DataTypeId::String));

  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fields2)), typeId, encodingId, String{"V2"})
      .is_good());

  const auto found2 = registry.find_structure(typeId);
  ASSERT_NE(found2, nullptr);
  EXPECT_EQ(found2->field_count(), 2u);
  EXPECT_EQ(string_view(found2->type_name()), "V2");
}

// Public API review item 9 (API-9.5, D10): a lookup shares the descriptor, so one held across a
// re-registration of its type stays valid (it was a raw pointer the re-registration freed), and an instance
// is built straight from it.
TEST(DynamicTypeRegistry, ADescriptorHeldAcrossAReRegistrationStaysValid)
{
  DynamicTypeRegistry registry;
  const ExpandedNodeId typeId{NodeId{1, uint32_t{9100}}, "urn:test:ns"};
  const ExpandedNodeId encodingId{NodeId{1, uint32_t{9101}}, "urn:test:ns"};

  std::vector<StructureField> first;
  first.push_back(make_field("A", DataTypeId::Int32));
  ASSERT_TRUE(registry
                .register_type(
                  make_definition(StructureType::Structure, std::move(first)), typeId, encodingId, String{"V1"})
                .is_good());
  const shared_ptr<const DynamicStructureTypeDescriptor> held = registry.find_structure(typeId);
  ASSERT_NE(held, nullptr);

  std::vector<StructureField> second;
  second.push_back(make_field("B", DataTypeId::String));
  second.push_back(make_field("C", DataTypeId::Double));
  ASSERT_TRUE(registry
                .register_type(
                  make_definition(StructureType::Structure, std::move(second)), typeId, encodingId, String{"V2"})
                .is_good());

  EXPECT_EQ(string_view(held->type_name()), "V1") << "the held descriptor is the one looked up, still alive";
  EXPECT_EQ(held->field_count(), 1u);
  const DynamicStructure instance{held};
  EXPECT_EQ(instance.descriptor().field_count(), 1u) << "an instance is built from the shared descriptor";
  EXPECT_EQ(string_view(registry.find_structure(typeId)->type_name()), "V2");
}

// ============================================================================
// Lookup returns nullptr for unknown types
// ============================================================================

TEST(DynamicTypeRegistry, FindStructure_ReturnsNullForUnknown)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  ExpandedNodeId unknownId{NodeId{1, uint32_t{99999}}, "urn:test:ns"};
  EXPECT_EQ(registry.find_structure(unknownId), nullptr);
}

TEST(DynamicTypeRegistry, FindEnum_ReturnsNullForUnknown)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  ExpandedNodeId unknownId{NodeId{1, uint32_t{99999}}, "urn:test:ns"};
  EXPECT_EQ(registry.find_enum(unknownId), nullptr);
}

// ============================================================================
// Encode/Decode round-trip via factory
// ============================================================================

TEST(DynamicTypeRegistry, EncodeDecodeViaFactory)
{
  StructureFactory factory;
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Name", DataTypeId::String));
  fields.push_back(make_field("Count", DataTypeId::Int32));

  // NS0-only type IDs (no namespace URI) - required for no-arg register_all_with
  ExpandedNodeId typeId{NodeId{0, uint32_t{10000}}};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{10001}}};

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(fields)),
                  typeId,
                  encodingId,
                  String{"RoundTripType"})
                .is_good());

  registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
    { factory.register_type(id, std::move(create)); });

  // Create and populate a DynamicStructure
  auto original = factory.create_instance(encodingId.node_id());
  ASSERT_NE(original, nullptr);
  auto* origDs = dynamic_cast<DynamicStructure*>(original.get());
  ASSERT_NE(origDs, nullptr);

  (*origDs)["Name"] = Variant{String{"Hello"}};
  (*origDs)["Count"] = Variant{int32_t{42}};

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  origDs->encode(make_limit(), enc);
  stream.flush();

  // Decode via factory-created instance
  auto decoded = factory.create_instance(encodingId.node_id());
  ASSERT_NE(decoded, nullptr);
  auto* decodedDs = dynamic_cast<DynamicStructure*>(decoded.get());
  ASSERT_NE(decodedDs, nullptr);

  stream.seek_from_start(0);
  UaBinaryDecoder decoder(factory.resolver(), stream, make_limits());
  Decoder dec(decoder);
  decodedDs->decode(make_limit(), dec);

  EXPECT_EQ(decodedDs->field(0).as<String>(), String{"Hello"});
  EXPECT_EQ(decodedDs->field(1).as<int32_t>(), 42);
  EXPECT_TRUE(*origDs == *decodedDs);
}

// ============================================================================
// No-arg overload guards for non-NS0 types
// ============================================================================

TEST(DynamicTypeRegistry, NoArgMakeResolverThrowsForNonNs0Types)
{
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Value", DataTypeId::Int32));

  // Register a type with a namespace URI in its encoding ID (non-NS0)
  ExpandedNodeId typeId{NodeId{1, uint32_t{20000}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{20001}}, "urn:test:ns"};

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(fields)),
                  typeId,
                  encodingId,
                  String{"NonNs0Type"})
                .is_good());

  EXPECT_THROW(registry.make_resolver(), UaException);
}

TEST(DynamicTypeRegistry, NoArgRegisterAllWithThrowsForNonNs0Types)
{
  DynamicTypeRegistry registry;
  StructureFactory factory;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Value", DataTypeId::Int32));

  // Register a type with a namespace URI in its encoding ID (non-NS0)
  ExpandedNodeId typeId{NodeId{1, uint32_t{21000}}, "urn:test:ns"};
  ExpandedNodeId encodingId{NodeId{1, uint32_t{21001}}, "urn:test:ns"};

  ASSERT_TRUE(registry
                .register_type(make_definition(StructureType::Structure, std::move(fields)),
                  typeId,
                  encodingId,
                  String{"NonNs0Type"})
                .is_good());

  EXPECT_THROW(
    registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
      { factory.register_type(id, std::move(create)); }),
    UaException);
}

TEST(DynamicTypeRegistry, NoArgMakeResolverWorksForNs0OnlyTypes)
{
  DynamicTypeRegistry registry;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Value", DataTypeId::Int32));

  // Register a type without a namespace URI (NS0-only)
  ExpandedNodeId typeId{NodeId{0, uint32_t{22000}}};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{22001}}};

  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fields)), typeId, encodingId, String{"Ns0Type"})
      .is_good());

  // Should not throw
  StructureResolver resolver;
  EXPECT_NO_THROW(resolver = registry.make_resolver());

  // Resolver should work
  auto instance = resolver(NodeId{0, uint32_t{22001}});
  ASSERT_NE(instance, nullptr);
  auto* dynamicStruct = dynamic_cast<DynamicStructure*>(instance.get());
  ASSERT_NE(dynamicStruct, nullptr);
  EXPECT_EQ(string_view(dynamicStruct->descriptor().type_name()), "Ns0Type");
}

TEST(DynamicTypeRegistry, NoArgRegisterAllWithWorksForNs0OnlyTypes)
{
  DynamicTypeRegistry registry;
  StructureFactory factory;

  std::vector<StructureField> fields;
  fields.push_back(make_field("Value", DataTypeId::Int32));

  // Register a type without a namespace URI (NS0-only)
  ExpandedNodeId typeId{NodeId{0, uint32_t{23000}}};
  ExpandedNodeId encodingId{NodeId{0, uint32_t{23001}}};

  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fields)), typeId, encodingId, String{"Ns0Type"})
      .is_good());

  // Should not throw
  EXPECT_NO_THROW(
    registry.register_all_with([&factory](const NodeId& id, std::function<unique_ptr<Structure>()> create)
      { factory.register_type(id, std::move(create)); }));

  auto instance = factory.create_instance(NodeId{0, uint32_t{23001}});
  ASSERT_NE(instance, nullptr);
}

// ============================================================================
// Namespace-URI identity: two types that share numeric identifiers but differ
// only by namespace URI resolve independently (URI is the true key).
// ============================================================================

TEST(DynamicTypeRegistry, NamespaceUriDisambiguation)
{
  DynamicTypeRegistry registry;

  // Type A and Type B share the SAME numeric type/encoding identifiers and differ only in their
  // namespace URI. Give them different field layouts so a resolved instance is identifiable.
  std::vector<StructureField> fieldsA;
  fieldsA.push_back(make_field("OnlyField", DataTypeId::Int32));
  ExpandedNodeId typeIdA{NodeId{0, uint32_t{3000}}, "urn:test:A"};
  ExpandedNodeId encodingIdA{NodeId{0, uint32_t{3001}}, "urn:test:A"};
  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fieldsA)), typeIdA, encodingIdA, String{"TypeA"})
      .is_good());

  std::vector<StructureField> fieldsB;
  fieldsB.push_back(make_field("First", DataTypeId::Double));
  fieldsB.push_back(make_field("Second", DataTypeId::Double));
  ExpandedNodeId typeIdB{NodeId{0, uint32_t{3000}}, "urn:test:B"};
  ExpandedNodeId encodingIdB{NodeId{0, uint32_t{3001}}, "urn:test:B"};
  ASSERT_TRUE(
    registry
      .register_type(
        make_definition(StructureType::Structure, std::move(fieldsB)), typeIdB, encodingIdB, String{"TypeB"})
      .is_good());

  // Both are registered independently despite the identical numeric identifiers.
  const auto descA = registry.find_structure(typeIdA);
  const auto descB = registry.find_structure(typeIdB);
  ASSERT_NE(descA, nullptr);
  ASSERT_NE(descB, nullptr);
  EXPECT_EQ(descA->field_count(), 1u);
  EXPECT_EQ(descB->field_count(), 2u);

  // A resolver mapping each URI to a DIFFERENT local index resolves each encoding NodeId to its
  // own descriptor - the numeric collision does not conflate them.
  NamespaceIndexLookup nsLookup = [](string_view uri) -> std::optional<uint16_t>
  {
    if (uri == "urn:test:A")
    {
      return uint16_t{1};
    }
    if (uri == "urn:test:B")
    {
      return uint16_t{2};
    }
    return std::nullopt;
  };
  auto resolver = registry.make_resolver(nsLookup);

  auto instanceA = resolver(NodeId{1, uint32_t{3001}});
  auto instanceB = resolver(NodeId{2, uint32_t{3001}});
  ASSERT_NE(instanceA, nullptr);
  ASSERT_NE(instanceB, nullptr);

  auto* structA = dynamic_cast<DynamicStructure*>(instanceA.get());
  auto* structB = dynamic_cast<DynamicStructure*>(instanceB.get());
  ASSERT_NE(structA, nullptr);
  ASSERT_NE(structB, nullptr);
  EXPECT_EQ(structA->field_count(), 1u);
  EXPECT_EQ(structB->field_count(), 2u);
  EXPECT_NE(structA->type_id(), structB->type_id());  // distinct URIs -> distinct type identities
}
