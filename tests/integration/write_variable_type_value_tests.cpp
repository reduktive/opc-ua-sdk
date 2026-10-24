// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 3 section 8.60, Table 43: WriteMask bit 21 (ValueForVariableType) "Indicates if the Value Attribute is
// writable for a VariableType"; set, the Value is writable, and clear, it is not. A Client writes a
// VariableType's Value through the Write service and reads it back; the value is checked against the
// VariableType's DataType and ValueRank (Part 4 section 5.10.4.2, Table 59, Bad_TypeMismatch), and it is
// written whole (Bad_WriteNotSupported for an IndexRange).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_data_value.h"
#include "ua_node_accessor.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

using namespace ua;
using namespace ua::test_helpers;

namespace
{

class WriteVariableTypeValue : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    mWritableScalarType =
      create_type(7600u, "WritableScalarType", true, ValueRank::scalar, Variant{int32_t{7}});
    mReadOnlyScalarType =
      create_type(7601u, "ReadOnlyScalarType", false, ValueRank::scalar, Variant{int32_t{7}});
    mWritableArrayType = create_type(7602u, "WritableArrayType", true, 1, Variant{Array<int32_t>{1, 2, 3}});
    mWritableDurationType = create_type(7603u,
      "WritableDurationType",
      true,
      ValueRank::scalar,
      Variant{double{1.5}},
      NodeId{DataTypeId::Duration});
  }

  // A VariableType of DataType Int32 below BaseDataVariableType, whose WriteMask sets or clears bit 21.
  NodeId create_type(uint32_t id, const char* name, bool valueForVariableType, int32_t valueRank,
    Variant value, NodeId dataType = NodeId{DataTypeId::Int32})
  {
    auto addressSpace = mServer.server().address_space();
    const NodeId typeId{mTestNamespaceIndex, id};
    auto created = addressSpace.try_create_node_sync(typeId, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good()) << "the VariableType " << name << " could not be created";
    if (created.is_bad())
      return typeId;
    auto type = created.value();
    type.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    type.set_display_name(LocalizedText{"", name});
    auto variableType = type.as<VariableTypeAccessor>();
    EXPECT_TRUE(variableType.has_value());
    if (!variableType.has_value())
      return typeId;
    variableType->set_data_type(std::move(dataType));
    variableType->set_value_rank(ValueRank{valueRank});
    variableType->set_value(DataValue{std::move(value)});
    // The only difference between the types the tests contrast is bit 21; DisplayName keeps the clear
    // WriteMask from being empty.
    type.set_write_mask(valueForVariableType
                          ? AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType,
                              AttributeWriteMask::Bit::DisplayName}
                          : AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    addressSpace.find_node_sync(NodeId{VariableTypeId::BaseDataVariableType})
      .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, typeId);  // and its inverse half (NR-70 B8)
    return typeId;
  }

  StatusCode write(const NodeId& typeId, Variant value, const char* indexRange = nullptr)
  {
    WriteRequestBuilder builder;
    builder.write(typeId, std::move(value));
    if (indexRange != nullptr)
      builder.index_range(String{indexRange});
    auto response = mSession->attributes().write_sync(builder.build());
    EXPECT_THAT(response, ServiceResultIsGood());
    if (response.results().size() != 1u)
    {
      ADD_FAILURE() << "the Write answered " << response.results().size() << " results for one item";
      return StatusCode{Status::BadUnexpectedError};
    }
    return response.results()[0];
  }

  Variant read_value_of(const NodeId& typeId)
  {
    auto response = mSession->attributes().read_sync(read_value(typeId));
    EXPECT_THAT(response, ServiceResultIsGood());
    if (response.results().size() != 1u)
    {
      ADD_FAILURE() << "the Read answered " << response.results().size() << " results for one item";
      return {};
    }
    EXPECT_THAT(response.results()[0], Good()) << "reading the VariableType's Value";
    return response.results()[0].value();
  }

  NodeId mWritableScalarType;
  NodeId mReadOnlyScalarType;
  NodeId mWritableArrayType;
  NodeId mWritableDurationType;
};

}  // namespace

// @relation(AC-SVR-ATTR-WRITE-032-BIT21-SET-ACCEPTED, scope=function)
TEST_F(WriteVariableTypeValue, AcceptedWhenWriteMaskBit21IsSet)
{
  EXPECT_EQ(write(mWritableScalarType, Variant{int32_t{42}}).as_status(), Status::Good)
    << "a VariableType whose WriteMask sets ValueForVariableType refused a write of its Value";
  EXPECT_EQ(to_string(read_value_of(mWritableScalarType)), to_string(Variant{int32_t{42}}));
}

// @relation(AC-SVR-ATTR-WRITE-032-BIT21-CLEAR-NOTWRITABLE, scope=function)
TEST_F(WriteVariableTypeValue, RefusedWhenBit21IsClear)
{
  EXPECT_EQ(write(mReadOnlyScalarType, Variant{int32_t{42}}).as_status(), Status::BadNotWritable);
  EXPECT_EQ(to_string(read_value_of(mReadOnlyScalarType)), to_string(Variant{int32_t{7}}));
}

// @relation(AC-SVR-ATTR-WRITE-032-VALUE-TYPE-MISMATCH, scope=function)
TEST_F(WriteVariableTypeValue, AValueOfTheWrongTypeOrShapeIsTypeMismatch)
{
  EXPECT_EQ(write(mWritableScalarType, Variant{String{"seven"}}).as_status(), Status::BadTypeMismatch)
    << "a String was written to the Value of an Int32 VariableType";
  EXPECT_EQ(to_string(read_value_of(mWritableScalarType)), to_string(Variant{int32_t{7}}));

  EXPECT_EQ(write(mWritableScalarType, Variant{Array<int32_t>{1, 2}}).as_status(), Status::BadTypeMismatch)
    << "an array was written to the Value of a scalar VariableType";
  EXPECT_EQ(to_string(read_value_of(mWritableScalarType)), to_string(Variant{int32_t{7}}));

  EXPECT_EQ(write(mWritableScalarType, Variant{int32_t{42}}).as_status(), Status::Good)
    << "the control write of a scalar Int32 was refused";
  EXPECT_EQ(to_string(read_value_of(mWritableScalarType)), to_string(Variant{int32_t{42}}));

  // A DataType that is a subtype of a built-in type: Duration (i=290) is a Double.
  EXPECT_EQ(write(mWritableDurationType, Variant{String{"PT1S"}}).as_status(), Status::BadTypeMismatch)
    << "a String was written to the Value of a Duration VariableType";
  EXPECT_EQ(to_string(read_value_of(mWritableDurationType)), to_string(Variant{double{1.5}}));
  EXPECT_EQ(write(mWritableDurationType, Variant{double{2.5}}).as_status(), Status::Good)
    << "the control write of a Double to a Duration VariableType was refused";
  EXPECT_EQ(to_string(read_value_of(mWritableDurationType)), to_string(Variant{double{2.5}}));
}

// @relation(AC-SVR-ATTR-WRITE-032-INDEXRANGE-WRITENOTSUPPORTED, scope=function)
TEST_F(WriteVariableTypeValue, AnIndexRangeWriteIsWriteNotSupported)
{
  EXPECT_EQ(
    write(mWritableArrayType, Variant{Array<int32_t>{9}}, "1").as_status(), Status::BadWriteNotSupported);
  EXPECT_EQ(to_string(read_value_of(mWritableArrayType)), to_string(Variant{Array<int32_t>{1, 2, 3}}));
}

// Part 3 section 8.60: an Attribute the Node does not support has its WriteMask bit clear; section 8.7: null
// "indicat[es] that a value is not present". DL-29: a null write of a VariableType's Value is held as a null
// value, so a Read answers Good with null rather than Bad_AttributeIdInvalid. A VariableType created without
// a Value is the control that one holding no Value still lacks the Attribute.
// @relation(AC-SVR-ATTR-WRITE-032-NULL-WRITE-HELD, scope=function)
TEST_F(WriteVariableTypeValue, ANullWriteIsHeldAndReadsGoodWithANullValue)
{
  const auto heldType = create_type(7604u, "NullWrittenType", true, ValueRank::scalar, Variant{int32_t{7}});
  const NodeId withoutValue{mTestNamespaceIndex, uint32_t{7605}};
  {
    auto addressSpace = mServer.server().address_space();
    auto created = addressSpace.try_create_node_sync(withoutValue, NodeClass::VariableType, {});
    ASSERT_TRUE(created.is_good()) << "the VariableType without a Value could not be created";
    auto type = created.value();
    type.set_browse_name(QualifiedName{mTestNamespaceIndex, "ValuelessType"});
    type.set_display_name(LocalizedText{"", "ValuelessType"});
    auto variableType = type.as<VariableTypeAccessor>();
    ASSERT_TRUE(variableType.has_value());
    variableType->set_data_type(NodeId{DataTypeId::Int32});
    variableType->set_value_rank(ValueRank{ValueRank::scalar});
    type.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType});
  }

  EXPECT_EQ(write(heldType, Variant{}).as_status(), Status::Good)
    << "the null write of the VariableType's Value was refused";
  auto response =
    mSession->attributes().read_sync(ReadRequestBuilder().read(heldType).read(withoutValue).build());
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_THAT(response.results()[0], HasStatus(Status::Good))
    << "the Read of the Value written as null does not answer Good";
  EXPECT_TRUE(response.results()[0].value().empty())
    << "the Value written as null reads " << to_string(response.results()[0].value());
  EXPECT_THAT(response.results()[1], HasStatus(Status::BadAttributeIdInvalid))
    << "a VariableType created without a Value answers a Read of it";
}

// DL-20: a VariableType's Value given at creation reads back through the Read service, whether it is given
// as the value's Variant, as AddNodes carries it (Part 4 section 7.24.6, Table 159), or as a DataValue
// holding the value; the DataValue form is the control.
// @relation(AC-COMP-ADDRSP-CREATE-NODE-INITIAL-ATTRIBUTES-01-VARIABLETYPE-VALUE-AS-VARIANT, scope=function)
TEST_F(WriteVariableTypeValue, AValueGivenAtCreationReadsBack)
{
  auto addressSpace = mServer.server().address_space();
  const auto create = [&](uint32_t id, const char* name, Variant value)
  {
    const NodeId typeId{mTestNamespaceIndex, id};
    InitialAttributes attributes;
    attributes.emplace_back(AttributeId::BrowseName, Variant{QualifiedName{mTestNamespaceIndex, name}});
    attributes.emplace_back(AttributeId::DisplayName, Variant{LocalizedText{"", name}});
    attributes.emplace_back(AttributeId::DataType, Variant{NodeId{DataTypeId::Int32}});
    attributes.emplace_back(AttributeId::Value, std::move(value));
    auto created = addressSpace.try_create_node_sync(typeId, NodeClass::VariableType, std::move(attributes));
    EXPECT_EQ(created.status_code().as_status(), Status::Good) << "the VariableType " << name;
    return typeId;
  };
  const auto asVariant = create(7610u, "ValueAsVariantType", Variant{int32_t{7}});
  const auto asDataValue = create(7611u, "ValueAsDataValueType", Variant{DataValue{Variant{int32_t{7}}}});

  auto response = mSession->attributes().read_sync(ReadRequestBuilder().read(asVariant).read(asDataValue));
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_THAT(response.results()[0], HasStatus(Status::Good))
    << "the Value given as a Variant at creation does not read back";
  EXPECT_EQ(to_string(response.results()[0].value()), to_string(Variant{int32_t{7}}));
  EXPECT_THAT(response.results()[1], HasStatus(Status::Good)) << "the DataValue form no longer reads back";
  EXPECT_EQ(to_string(response.results()[1].value()), to_string(Variant{int32_t{7}}));
}
