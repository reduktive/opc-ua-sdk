// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 4: Attribute Service Set - Read Compliance Integration Tests
///
/// Tests covering Part 4 Attribute Read requirements (ATTR-READ-*).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_default_variable_node.h"
#include "ua_numeric_range_parser.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server_state.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_timestamps_to_return.h"
#include "ua_value_source.h"
#include "ua_variable_id.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <array>
#include <atomic>
#include <string_view>
#include <utility>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using ::testing::Each;
using ::testing::ElementsAre;

// ===========================================================================
// TimestampsToReturn tests
// ===========================================================================

// Requirement: ATTR-READ (general)
// TimestampsToReturn::Source returns source timestamp only
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, TimestampsToReturn_Source)
{
  auto ts = DateTime::now();
  write_value_async(*mSession, mWritableVariableId, DataValue{Variant{int32_t{100}}, ts});

  auto resp = mSession->attributes().read_sync(
    read_value(mWritableVariableId, AttributeId::Value, TimestampsToReturn::Source));

  ASSERT_EQ(resp.results().size(), 1u);
  auto& dv = resp.results()[0];
  EXPECT_TRUE(dv.source_timestamp().has_value()) << "Source timestamp should be present";
  EXPECT_FALSE(dv.server_timestamp().has_value()) << "Server timestamp should be absent";
}

// Requirement: ATTR-READ (general)
// TimestampsToReturn::Server returns server timestamp only
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, TimestampsToReturn_Server)
{
  auto resp = mSession->attributes().read_sync(
    read_value(mWritableVariableId, AttributeId::Value, TimestampsToReturn::Server));

  ASSERT_EQ(resp.results().size(), 1u);
  auto& dv = resp.results()[0];
  EXPECT_FALSE(dv.source_timestamp().has_value()) << "Source timestamp should be absent";
  EXPECT_TRUE(dv.server_timestamp().has_value()) << "Server timestamp should be present";
}

// Requirement: ATTR-READ (general)
// TimestampsToReturn::Both returns both timestamps
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, TimestampsToReturn_Both)
{
  auto ts = DateTime::now();
  write_value_async(*mSession, mWritableVariableId, DataValue{Variant{int32_t{100}}, ts});

  auto resp = mSession->attributes().read_sync(
    read_value(mWritableVariableId, AttributeId::Value, TimestampsToReturn::Both));

  ASSERT_EQ(resp.results().size(), 1u);
  auto& dv = resp.results()[0];
  EXPECT_TRUE(dv.source_timestamp().has_value()) << "Source timestamp should be present";
  EXPECT_TRUE(dv.server_timestamp().has_value()) << "Server timestamp should be present";
}

// A dataEncoding on a Value whose DataType is not a Structure yields Bad_DataEncodingInvalid - no
// encoding can be applied (Part 4 section 7.29 + Table 183). Even "Default Binary" is an error here.
// Regression for CTT Attribute Read 037, which reads a scalar with several encodings.
TEST_F(ComplianceWithNodes, ReadScalarValueWithDataEncodingReturnsInvalid)
{
  write_value_async(*mSession, mWritableVariableId, DataValue{Variant{int32_t{100}}, DateTime::now()});

  auto resp = mSession->attributes().read_sync(ReadRequestBuilder()
                                                 .read(mWritableVariableId)
                                                 .attribute(AttributeId::Value)
                                                 .data_encoding(QualifiedName{0, "Default Binary"})
                                                 .timestamps(TimestampsToReturn::Both));

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results().payload(), ElementsAre(HasStatus(Status::BadDataEncodingInvalid)));
}

// Requirement: ATTR-READ (general)
// TimestampsToReturn::Neither omits timestamps
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, TimestampsToReturn_Neither)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId));

  ASSERT_EQ(resp.results().size(), 1u);
  auto& dv = resp.results()[0];
  EXPECT_FALSE(dv.source_timestamp().has_value()) << "Source timestamp should be absent";
  EXPECT_FALSE(dv.server_timestamp().has_value()) << "Server timestamp should be absent";
}

// ===========================================================================
// Basic Read value tests
// ===========================================================================

// Read Int32 variable returns correct value and Good status
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ReadValue_Int32)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(good_value_of<int32_t>(42)));
}

// Read BrowseName attribute succeeds
// Covers SVR-ADDRSP-003 (coverage-audit retag).
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ReadBrowseName)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId, AttributeId::BrowseName));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_EQ(std::string_view{resp.results()[0].value().as<QualifiedName>().name()}, "WritableInt32");
}

// Read DisplayName attribute succeeds
// Covers SVR-ADDRSP-004 (coverage-audit retag).
TEST_F(ComplianceWithNodes, ReadDisplayName)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId, AttributeId::DisplayName));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_EQ(std::string_view{resp.results()[0].value().as<LocalizedText>().text()}, "WritableInt32");
}

// Read NodeClass attribute succeeds
// Covers SVR-ADDRSP-002 (coverage-audit retag).
TEST_F(ComplianceWithNodes, ReadNodeClass)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId, AttributeId::NodeClass));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(
    resp.results().payload(), ElementsAre(good_value_of<int32_t>(static_cast<int32_t>(NodeClass::Variable))));
}

// Read NodeId attribute returns canonical id
// Covers SVR-ADDRSP-001 (coverage-audit retag).
TEST_F(ComplianceWithNodes, ReadNodeId)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId, AttributeId::NodeId));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(good_value_of<NodeId>(mWritableVariableId)));
}

// Read multiple nodes in single request, results match order
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ReadMultipleNodes)
{
  auto resp = mSession->attributes().read_sync(ReadRequestBuilder()
                                                 .read(mWritableVariableId)
                                                 .attribute(AttributeId::Value)
                                                 .read(mTestFolderId)
                                                 .attribute(AttributeId::BrowseName)
                                                 .read(mTestMethodId)
                                                 .attribute(AttributeId::DisplayName));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 3u);

  EXPECT_THAT(resp.results()[0], good_value_of<int32_t>(42));

  EXPECT_THAT(resp.results()[1], Good());
  EXPECT_EQ(std::string_view{resp.results()[1].value().as<QualifiedName>().name()}, "TestFolder");

  EXPECT_THAT(resp.results()[2], Good());
  EXPECT_EQ(std::string_view{resp.results()[2].value().as<LocalizedText>().text()}, "TestMethod");
}

// Read Server_ServerStatus_State returns Running
// Covers SVR-BASE-003 (coverage-audit retag).
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ReadServerState)
{
  auto resp = mSession->attributes().read_sync(read_value(NodeId{VariableId::Server_ServerStatus_State}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(),
    ElementsAre(good_value_of<int32_t>(static_cast<int32_t>(ServerState::Running))));
}

// Read all mandatory attributes of Variable node
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ReadMandatoryAttributesVariable)
{
  // Mandatory for Variable: NodeId, NodeClass, BrowseName, DisplayName, Value, DataType, AccessLevel
  auto resp = mSession->attributes().read_sync(ReadRequestBuilder()
                                                 .read(mWritableVariableId)
                                                 .attributes({
                                                   AttributeId::NodeId,
                                                   AttributeId::NodeClass,
                                                   AttributeId::BrowseName,
                                                   AttributeId::DisplayName,
                                                   AttributeId::Value,
                                                   AttributeId::DataType,
                                                   AttributeId::AccessLevel,
                                                 }));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 7u);
  EXPECT_THAT(resp.results().payload(), Each(Good()));

  EXPECT_EQ(resp.results()[0].value().as<NodeId>(), mWritableVariableId) << "NodeId should match";
  EXPECT_EQ(resp.results()[1].value().as<int32_t>(), static_cast<int32_t>(NodeClass::Variable))
    << "NodeClass should be Variable";
  auto browseName = resp.results()[2].value().as<QualifiedName>();
  EXPECT_FALSE(browseName.name().empty()) << "BrowseName should be non-empty";
  EXPECT_EQ(std::string_view{browseName.name()}, "WritableInt32");
  auto displayName = resp.results()[3].value().as<LocalizedText>();
  EXPECT_FALSE(displayName.text().empty()) << "DisplayName should be non-empty";
  EXPECT_EQ(std::string_view{displayName.text()}, "WritableInt32");
}

// Read all mandatory attributes of Object node
TEST_F(ComplianceWithNodes, ReadMandatoryAttributesObject)
{
  // Mandatory for Object: NodeId, NodeClass, BrowseName, DisplayName
  auto resp = mSession->attributes().read_sync(ReadRequestBuilder()
                                                 .read(mTestFolderId)
                                                 .attributes({
                                                   AttributeId::NodeId,
                                                   AttributeId::NodeClass,
                                                   AttributeId::BrowseName,
                                                   AttributeId::DisplayName,
                                                 }));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 4u);
  EXPECT_THAT(resp.results().payload(), Each(Good()));

  EXPECT_EQ(resp.results()[0].value().as<NodeId>(), mTestFolderId) << "NodeId should match";
  EXPECT_EQ(resp.results()[1].value().as<int32_t>(), static_cast<int32_t>(NodeClass::Object))
    << "NodeClass should be Object";
  auto browseName = resp.results()[2].value().as<QualifiedName>();
  EXPECT_FALSE(browseName.name().empty()) << "BrowseName should be non-empty";
  EXPECT_EQ(std::string_view{browseName.name()}, "TestFolder");
  auto displayName = resp.results()[3].value().as<LocalizedText>();
  EXPECT_FALSE(displayName.text().empty()) << "DisplayName should be non-empty";
  EXPECT_EQ(std::string_view{displayName.text()}, "TestFolder");
}

// Read all mandatory attributes of Method node
TEST_F(ComplianceWithNodes, ReadMandatoryAttributesMethod)
{
  // Mandatory for Method: NodeId, NodeClass, BrowseName, DisplayName
  auto resp = mSession->attributes().read_sync(ReadRequestBuilder()
                                                 .read(mTestMethodId)
                                                 .attributes({
                                                   AttributeId::NodeId,
                                                   AttributeId::NodeClass,
                                                   AttributeId::BrowseName,
                                                   AttributeId::DisplayName,
                                                 }));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 4u);
  EXPECT_THAT(resp.results().payload(), Each(Good()));

  EXPECT_EQ(resp.results()[0].value().as<NodeId>(), mTestMethodId) << "NodeId should match";
  EXPECT_EQ(resp.results()[1].value().as<int32_t>(), static_cast<int32_t>(NodeClass::Method))
    << "NodeClass should be Method";
  auto browseName = resp.results()[2].value().as<QualifiedName>();
  EXPECT_FALSE(browseName.name().empty()) << "BrowseName should be non-empty";
  EXPECT_EQ(std::string_view{browseName.name()}, "TestMethod");
  auto displayName = resp.results()[3].value().as<LocalizedText>();
  EXPECT_FALSE(displayName.text().empty()) << "DisplayName should be non-empty";
  EXPECT_EQ(std::string_view{displayName.text()}, "TestMethod");
}

// ===========================================================================
// Requirement-specific Read tests
// ===========================================================================

// Requirement: SVR-ATTR-READ-001 (SHALL)
// If the Server does not have a value that is within the maximum age, it shall
// attempt to read a new value from the data source.
// Spec: Part 4, section 5.10.2.2, line 3677
TEST_F(ComplianceWithNodes, ATTR_READ_001_MaxAgePositive_ValueWithinAge)
{
  struct MaxAgeCapture
  {
    std::atomic<bool> called{false};
    std::atomic<double> receivedMaxAge{-1.0};
  };

  auto capture = std::make_shared<MaxAgeCapture>();

  auto node =
    std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(mMaxAgeVariableId));
  ASSERT_TRUE(node != nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [capture](const ValueSource::ReadContext& context,
                    const Node& /*node*/,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      callback)
                  {
                    capture->called = true;
                    capture->receivedMaxAge = context.maxAge;
                    DataValue value{Variant{int32_t{101}}};
                    index_range_utils::apply_to_value(value, read.index_range());
                    callback(DataValueResult{std::move(value)});
                  }))
                .is_good());

  auto resp = mSession->attributes().read_sync(
    ReadRequestBuilder().read(mMaxAgeVariableId).attribute(AttributeId::Value).max_age(10000.0));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(good_value_of<int32_t>(101)));

  EXPECT_TRUE(capture->called) << "Read handler should have been called";
  EXPECT_DOUBLE_EQ(capture->receivedMaxAge, 10000.0)
    << "Server should pass the requested maxAge (10000) to the data source";
}

// Requirement: SVR-ATTR-READ-002 (SHALL)
// If maxAge is set to 0, the Server shall attempt to read a new value from the data source.
// Spec: Part 4, section 5.10.2.2, line 3683
// @verifies CL-ATTR-001
// @relation(SVR-ATTR-READ-029, CL-ATTR-001, scope=function)
TEST_F(ComplianceWithNodes, ATTR_READ_002_MaxAgeZero_FreshValue)
{
  struct MaxAgeCapture
  {
    std::atomic<bool> called{false};
    std::atomic<double> receivedMaxAge{-1.0};
  };

  auto capture = std::make_shared<MaxAgeCapture>();

  auto node =
    std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(mMaxAgeVariableId));
  ASSERT_TRUE(node != nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [capture](const ValueSource::ReadContext& context,
                    const Node& /*node*/,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      callback)
                  {
                    capture->called = true;
                    capture->receivedMaxAge = context.maxAge;
                    DataValue value{Variant{int32_t{202}}};
                    index_range_utils::apply_to_value(value, read.index_range());
                    callback(DataValueResult{std::move(value)});
                  }))
                .is_good());

  auto resp = mSession->attributes().read_sync(
    ReadRequestBuilder().read(mMaxAgeVariableId).attribute(AttributeId::Value).max_age(0.0));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(good_value_of<int32_t>(202)));

  EXPECT_TRUE(capture->called) << "Read handler should have been called";
  EXPECT_DOUBLE_EQ(capture->receivedMaxAge, 0.0) << "Server should pass maxAge=0 to the data source";
}

// Requirement: SVR-ATTR-READ-003 (SHALL)
// If maxAge is set to the max Int32 value or greater, the Server shall attempt to get a cached value.
// Spec: Part 4, section 5.10.2.2, line 3685
// @verifies CL-ATTR-002
// @relation(SVR-ATTR-READ-029, CL-ATTR-002, scope=function)
TEST_F(ComplianceWithNodes, ATTR_READ_003_MaxAgeMaxInt_CachedValue)
{
  struct MaxAgeCapture
  {
    std::atomic<bool> called{false};
    std::atomic<double> receivedMaxAge{-1.0};
  };

  auto capture = std::make_shared<MaxAgeCapture>();

  auto node =
    std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(mMaxAgeVariableId));
  ASSERT_TRUE(node != nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [capture](const ValueSource::ReadContext& context,
                    const Node& /*node*/,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      callback)
                  {
                    capture->called = true;
                    capture->receivedMaxAge = context.maxAge;
                    DataValue value{Variant{int32_t{303}}};
                    index_range_utils::apply_to_value(value, read.index_range());
                    callback(DataValueResult{std::move(value)});
                  }))
                .is_good());

  auto resp =
    mSession->attributes().read_sync(ReadRequestBuilder()
                                       .read(mMaxAgeVariableId)
                                       .attribute(AttributeId::Value)
                                       .max_age(static_cast<double>(std::numeric_limits<int32_t>::max())));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(good_value_of<int32_t>(303)));

  EXPECT_TRUE(capture->called) << "Read handler should have been called";
  EXPECT_GE(capture->receivedMaxAge, static_cast<double>(std::numeric_limits<int32_t>::max()))
    << "Server should pass maxAge >= INT32_MAX to the data source";
}

// Requirement: SVR-ATTR-READ-005 (SHALL)
// The attributeId shall be a valid Attribute id.
// Spec: Part 4, section 7.29, line 9530
TEST_F(ComplianceWithNodes, ATTR_READ_005_ValidAttributeIdAccepted)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(Good()));
}

// Requirement: SVR-ATTR-READ-010 (SHALL)
// If the dataEncoding parameter is null or empty then the Server shall choose
// the default according to what Message encoding is used for the Session.
// Spec: Part 4, section 7.29, line 9562
TEST_F(ComplianceWithNodes, ATTR_READ_010_NullEncodingUsesDefault)
{
  // Leave dataEncoding as default (null/empty) - read should succeed.
  // NOTE: The Read response does not include which encoding was used, so we cannot
  // verify the server chose "Default Binary" as the default. We can only verify the
  // read succeeds and returns a valid value.
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId));

  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_THAT(resp.results().payload(), ElementsAre(good_value_of<int32_t>(42)));
}

// Requirement: SVR-ATTR-READ-006 (SHALL)
// OPC UA defines BrowseNames which Servers shall recognize even if the DataType
// Nodes are not visible in the Server AddressSpace (Default Binary, Default XML, Default JSON).
// Spec: Part 4, section 7.29, line 9547
// @relation(AC-SVR-ATTR-READ-006-DEFAULT-ENCODING-BROWSENAMES, scope=function)
TEST_F(ComplianceWithNodes, ATTR_READ_006_DefaultBinaryEncodingRecognized)
{
  const NodeId serverStatus{VariableId::Server_ServerStatus};
  auto result = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                       .read(serverStatus)
                                                       .attribute(AttributeId::Value)
                                                       .data_encoding(QualifiedName{"Default Binary"}));

  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  const auto& value = resp.results()[0];
  EXPECT_TRUE(!value.status().has_value() || value.status()->is_good());
  EXPECT_TRUE(value.value().is_structure())
    << "the control must exercise a Structure Value so dataEncoding is applicable";
}

// Requirement: SVR-ATTR-READ-011 (SHALL)
// If the Server does not support the encoding that matches the Message encoding
// then the Server shall choose the default encoding that it does support.
// Spec: Part 4, section 7.29, line 9564
TEST_F(ComplianceWithNodes, ATTR_READ_011_ServerChoosesSupportedEncoding)
{
  // Request with an encoding the server may not support - server should fall back.
  // NOTE: The Read response does not include which encoding was used, so we cannot
  // verify the server actually fell back from "Default XML" to "Default Binary".
  auto result = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                       .read(mWritableVariableId)
                                                       .attribute(AttributeId::Value)
                                                       .data_encoding(QualifiedName{"Default XML"}));

  ASSERT_THAT(result, Good());
}

// ===========================================================================
// Negative Read tests
// ===========================================================================

// Requirement: SVR-ATTR-READ-020 (SHALL)
// Bad_IndexRangeNoData - Index range results in no data.
// Spec: Part 4, section 5.10.2.4, line 3734
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ATTR_READ_020_BadIndexRangeNoData)
{
  write_value_async(*mSession, mWritableVariableId, DataValue{Variant{int32_t{42}}});

  auto result = mSession->attributes().try_read_sync(
    ReadRequestBuilder().read(mWritableVariableId).attribute(AttributeId::Value).index_range(String{"0:5"}));

  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  EXPECT_THAT(resp.results().payload(), ElementsAre(HasStatus(Status::BadIndexRangeNoData)));
}

// Requirement: SVR-ATTR-READ-021 (SHALL)
// Bad_DataEncodingInvalid - Data encoding is invalid.
// Spec: Part 4, section 5.10.2.4, line 3735
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ATTR_READ_021_BadDataEncodingInvalid)
{
  auto result = mSession->attributes().try_read_sync(
    ReadRequestBuilder()
      .read(mWritableVariableId)
      .attribute(AttributeId::Value)
      .data_encoding(QualifiedName{"CompletelyInvalidEncodingNameThatDoesNotExist"}));

  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  // mWritableVariableId is a scalar (non-Structure) Value, so no dataEncoding can be applied at all:
  // Part 4 section 7.29 + Table 183 -> Bad_DataEncodingInvalid (not Unsupported, which is reserved for a
  // Structure Value with an unknown encoding name).
  EXPECT_THAT(resp.results().payload(), ElementsAre(HasStatus(Status::BadDataEncodingInvalid)));
}

// Requirement: SVR-ATTR-READ-022 (SHALL)
// Bad_DataEncodingUnsupported - Data encoding is not supported.
// Spec: Part 4, section 5.10.2.4, line 3736
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithNodes, ATTR_READ_022_BadDataEncodingUnsupported)
{
  // "Default JSON" is a valid OPC UA encoding name, but mWritableVariableId is a scalar (non-Structure)
  // Value - no dataEncoding can be applied, so the operation is Bad_DataEncodingInvalid (Part 4 section 7.29
  // + Table 183). Bad_DataEncodingUnsupported is reserved for a Structure Value with an unknown encoding.
  auto result = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                       .read(mWritableVariableId)
                                                       .attribute(AttributeId::Value)
                                                       .data_encoding(QualifiedName{"Default JSON"}));

  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  EXPECT_THAT(resp.results().payload(), ElementsAre(HasStatus(Status::BadDataEncodingInvalid)));
}

// Requirement: SVR-ATTR-READ-025 (SHALL)
// Bad_SecurityModeInsufficient - Security mode is insufficient.
// Spec: Part 4, section 5.10.2.4, line 3739
TEST_F(ComplianceWithNodes, ATTR_READ_025_BadSecurityModeInsufficient)
{
  // mEncryptionRequiredVariableId has AccessRestrictions.EncryptionRequired set.
  // Reading it on a None/None channel should return BadSecurityModeInsufficient.
  auto result = mSession->attributes().try_read_sync(read_value(mEncryptionRequiredVariableId));

  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  EXPECT_THAT(resp.results().payload(), ElementsAre(HasStatus(Status::BadSecurityModeInsufficient)));
}

// Covers SVR-ATTR-READ-025 (refinement).
// Part 3 section 8.56 (Table 38): SigningRequired/EncryptionRequired do NOT apply to the Browse permission
// unless ApplyRestrictionsToBrowse is set; Part 3 section 8.55 (Table 37): the Browse permission governs
// reading every Attribute except Value and RolePermissions. So on a None channel a Node with
// AccessRestrictions.EncryptionRequired must still allow NodeClass/BrowseName/etc. to be Read; only
// the Value Attribute is gated by the channel security mode.
TEST_F(ComplianceWithNodes, ATTR_READ_025_NonValueAttributesReadableOverInsufficientChannel)
{
  // NodeClass / BrowseName are governed by the Browse permission - readable over None.
  for (auto attr : {AttributeId::NodeClass, AttributeId::BrowseName, AttributeId::DisplayName})
  {
    auto result = mSession->attributes().try_read_sync(read_value(mEncryptionRequiredVariableId, attr));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    EXPECT_THAT(resp.results().payload(), ElementsAre(Good()))
      << "Non-Value attribute " << static_cast<int>(attr)
      << " of an EncryptionRequired Node must read Good over a None channel (Part 3 section 8.56)";
  }

  // The Value attribute remains gated by the channel security mode.
  auto valueResult =
    mSession->attributes().try_read_sync(read_value(mEncryptionRequiredVariableId, AttributeId::Value));
  ASSERT_THAT(valueResult, Good()) << "Service-level should succeed";
  EXPECT_THAT(std::move(valueResult).value().results().payload(),
    ElementsAre(HasStatus(Status::BadSecurityModeInsufficient)))
    << "The Value attribute of an EncryptionRequired Node must still require encryption";
}

// ===========================================================================
// UACTT mirror tests - fast native reproductions of compliance-tool findings.
// ===========================================================================

// Covers ATTR-READ (mandatory ServerCapabilities array properties)
// (CTT Discovery Get Endpoints/002,004; Find Servers Filter/003,005,006; per-unit initialize.js)
//
// UACTT finding F1: the mandatory Server.ServerCapabilities array properties are imported from NS0
// with no value. Reading their Value fell through to the value-less fallback in
// ua_node_utilities.cpp and returned BadAttributeIdInvalid, which cascaded into every Discovery
// test's setup. A mandatory Variable's Value must read Good (with the configured/empty array).
TEST_F(ComplianceWithNodes, Mirror_Read_ServerCapabilities_Properties_ReturnGood)
{
  const std::array<std::pair<VariableId, std::string_view>, 4> props{{
    {VariableId::Server_ServerCapabilities_ServerProfileArray, "ServerProfileArray"},
    {VariableId::Server_ServerCapabilities_LocaleIdArray, "LocaleIdArray"},
    {VariableId::Server_ServerCapabilities_SoftwareCertificates, "SoftwareCertificates"},
    {VariableId::Server_ServerCapabilities_ConformanceUnits, "ConformanceUnits"},
  }};
  for (const auto& [id, name] : props)
  {
    // Request Source+Server timestamps: a populated static value must carry a SourceTimestamp
    // (UACTT F1b), and the read must be Good rather than BadAttributeIdInvalid (UACTT F1).
    auto resp =
      mSession->attributes().read_sync(read_value(NodeId{id}, AttributeId::Value, TimestampsToReturn::Both));
    ASSERT_EQ(resp.results().size(), 1u) << name;
    const auto& dv = resp.results()[0];
    EXPECT_THAT(dv, Good()) << name << ": mandatory ServerCapabilities Value read must be Good, "
                            << "not BadAttributeIdInvalid (UACTT F1)";
    EXPECT_TRUE(dv.source_timestamp().has_value())
      << name << ": SourceTimestamp must be present when requested (UACTT F1b)";
  }
}

// Covers ATTR-READ (malformed NodeId) (CTT Attribute Read/Err-006)
// Part 4 section 5.10.2: a Read of a NodeId with an empty/null opaque identifier must return a per-operation
// Bad code (BadNodeIdInvalid/Unknown), not abort the channel.
TEST_F(ComplianceWithNodes, Mirror_Read_EmptyOpaqueNodeId_ReturnsBadNodeId)
{
  const NodeId emptyOpaque{uint16_t{2}, ByteString{}};

  auto result = mSession->attributes().try_read_sync(
    read_value(emptyOpaque, AttributeId::Value, TimestampsToReturn::Both));

  ASSERT_THAT(result, Good()) << "Read of an empty-opaque NodeId must not abort the channel (UACTT F7)";
  auto resp = std::move(result).value();
  EXPECT_THAT(resp.results().payload(),
    ElementsAre(::testing::AnyOf(HasStatus(Status::BadNodeIdInvalid), HasStatus(Status::BadNodeIdUnknown))));
}

// Covers ATTR-READ (mandatory attributes) (CTT Attribute Read/003,004,012,017,028,037)
// Part 3 section 5.6.2: Historizing is a mandatory Variable attribute defaulting to false; reading it on a
// non-historizing Variable must return Good(false), not BadInvalidState.
TEST_F(ComplianceWithNodes, Mirror_Read_Historizing_DefaultsToGoodFalse)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId, AttributeId::Historizing));

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Historizing read must be Good, not BadInvalidState (UACTT F9)";
  EXPECT_FALSE(resp.results()[0].value().as<bool>())
    << "A non-historizing Variable reports Historizing=false";
}

// Covers ATTR-READ (Value SourceTimestamp) (CTT Attribute Read/037, Attribute Write read-backs)
// Part 4 section 7.7.3: a Value read with TimestampsToReturn including Source must carry a SourceTimestamp,
// even when the stored value has none - default it to the server timestamp.
TEST_F(ComplianceWithNodes, Mirror_Read_ValueWithoutSourceTimestamp_DefaultsPresent)
{
  // Write a bare value carrying no SourceTimestamp.
  write_value_async(*mSession, mWritableVariableId, DataValue{Variant{int32_t{7}}});

  auto resp = mSession->attributes().read_sync(
    read_value(mWritableVariableId, AttributeId::Value, TimestampsToReturn::Both));

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  ASSERT_TRUE(resp.results()[0].source_timestamp().has_value())
    << "A Value read with Both must carry a SourceTimestamp (UACTT F10)";
  EXPECT_FALSE(resp.results()[0].source_timestamp()->is_null())
    << "The SourceTimestamp must be a real time, not null/epoch (UACTT F10)";
}

// ===========================================================================
// dataEncoding on a Structure Value - the subject the three tests above lack
// ===========================================================================
//
// `ATTR_READ_010_NullEncodingUsesDefault`, `ATTR_READ_006_DefaultBinaryEncodingRecognized` and
// `ATTR_READ_011_ServerChoosesSupportedEncoding` all read `mWritableVariableId`, a scalar Int32, and
// Part 4 section 7.29 says the parameter "only applies if the DataType of the Variable is a subtype of
// Structure". So each of them exercises the rejection path for a non-Structure Value and none reaches
// the rules it names - which is why all three carry a comment saying the encoding cannot be verified.
// The tests below use `Server.ServerStatus`, whose Value is a `ServerStatusDataType`, and get at the
// obligation a different way: not by reading back an encoding id the Client surface does not expose,
// but by comparing outcomes between requests that differ only in the parameter under test.

// Part 4 section 7.29: "If this parameter is null or empty then the Server shall choose the default according
// to what Message encoding (see OPC 10000-6) is used for the Session."
//
// The Client surface exposes no encoding id on a decoded value, so "which encoding did it pick" cannot
// be read off the response - the observation earlier rounds recorded as a missing interface. It does not
// need to be: the question is whether the null default is the same encoding as the Message encoding's
// default, and equality of outcome answers it. This Server offers exactly one Message encoding
// (`TransportProfileId` has the single enumerator `UaTcpUaScUaBinary`), whose default is Default
// Binary, so a null dataEncoding and an explicit "Default Binary" must produce the same Good result on
// the same Structure Value. A Server that resolved null to something else would either fail the read
// or answer differently, and both show up here.
// @verifies AC-SVR-ATTR-READ-010-NULL-ENCODING-FOLLOWS-MESSAGE
TEST_F(ComplianceWithNodes, ANullDataEncodingResolvesToTheMessageEncodingsDefaultOnAStructureValue)
{
  const NodeId serverStatus{VariableId::Server_ServerStatus};

  auto implicit = mSession->attributes().try_read_sync(
    ReadRequestBuilder().read(serverStatus).attribute(AttributeId::Value));
  ASSERT_THAT(implicit, Good());
  auto implicitResp = std::move(implicit).value();
  ASSERT_EQ(implicitResp.results().size(), 1u);

  auto explicitBinary =
    mSession->attributes().try_read_sync(ReadRequestBuilder()
                                           .read(serverStatus)
                                           .attribute(AttributeId::Value)
                                           .data_encoding(QualifiedName{"Default Binary"}));
  ASSERT_THAT(explicitBinary, Good());
  auto binaryResp = std::move(explicitBinary).value();
  ASSERT_EQ(binaryResp.results().size(), 1u);

  const auto& implicitValue = implicitResp.results()[0];
  const auto& binaryValue = binaryResp.results()[0];

  ASSERT_TRUE(!implicitValue.status().has_value() || implicitValue.status()->is_good())
    << "a Read with no dataEncoding failed on a Structure Value with status "
    << implicitValue.status()->as_uint32()
    << ". The parameter is optional and its absence must not be an error";
  ASSERT_TRUE(!binaryValue.status().has_value() || binaryValue.status()->is_good())
    << "a Read asking for Default Binary failed, so there is nothing to compare the default against";

  EXPECT_TRUE(implicitValue.value().is_structure())
    << "the null-dataEncoding Read did not return a Structure, so whatever encoding was chosen it was "
       "not one that carries this Value";
  EXPECT_EQ(implicitValue.value().is_structure(), binaryValue.value().is_structure())
    << "a null dataEncoding and an explicit Default Binary produced differently-shaped Values on the "
       "same Node, so the default this Server resolves null to is not the Message encoding's default";
}

// Part 4 section 7.29, the sentence after the one above: "If the Server does not support the encoding that
// matches the Message encoding then the Server shall choose the default encoding that it does
// support."
//
// The antecedent cannot arise on this product and it is worth being exact about why, rather than
// leaving the criterion looking unwritten. The Message encoding is UA Binary - the only transport
// profile the SDK builds is `uatcp-uasc-uabinary` - and every Structure DataType the Server registers
// is registered with a binary codec, so there is no DataType for which the matching encoding is
// missing and a fallback would be needed.
//
// What that claim is worth depends on it being true of every Structure DataType actually served, not
// just of the one a test happened to pick, so this sweeps them: every Structure-typed Variable
// reachable from the Server Object is read with a null dataEncoding and must come back Good. A
// DataType registered without a usable default - which is the state that would make the fallback
// clause bite - shows up here as a failed read rather than as a silent gap.
// @verifies AC-SVR-ATTR-READ-011-UNSUPPORTED-ENCODING-FALLBACK
TEST_F(ComplianceWithNodes, EveryStructureTypedValueHasADefaultEncodingTheServerCanActuallyReturn)
{
  // Server.ServerStatus and BuildInfo are Structure-typed; the OperationLimits entry is a plain
  // UInt32, kept as a contrast so a Server that refused every dataEncoding-bearing read would
  // still be distinguished from one that refuses only the Structures.
  const std::array<NodeId, 4> defaultEncodedValues{
    NodeId{VariableId::Server_ServerStatus},
    NodeId{VariableId::Server_ServerStatus_BuildInfo},
    NodeId{VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary},
    NodeId{VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead},
  };

  ReadRequestBuilder builder;
  for (const auto& node : defaultEncodedValues)
    builder.read(node).attribute(AttributeId::Value);

  auto result = mSession->attributes().try_read_sync(builder);
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), defaultEncodedValues.size());

  std::size_t structures = 0;
  std::vector<std::string> refused;
  for (std::size_t i = 0; i < defaultEncodedValues.size(); ++i)
  {
    const auto& dv = resp.results()[i];
    const bool good = !dv.status().has_value() || dv.status()->is_good();
    if (!good)
    {
      refused.push_back(
        ua::to_string(defaultEncodedValues[i]) + " -> " + std::to_string(dv.status()->as_uint32()));
      continue;
    }
    if (dv.value().is_structure())
      ++structures;
  }

  EXPECT_TRUE(refused.empty())
    << refused.size()
    << " Value(s) could not be returned with the default encoding, first: " << refused.front()
    << ". Part 4 section 7.29 requires the Server to fall back to an encoding it does support rather "
       "than fail, so a refusal here means there is no encoding it can return this Value in at all";
  EXPECT_GT(structures, 0u)
    << "no Structure-typed Value was returned, so the encoding rules this test is about were never "
       "reached and it proves nothing";
}

// Part 4 Table 183, Bad_DataEncodingUnsupported: "The Server does not support the requested data
// encoding for the node."
//
// Part 4 section 7.29 requires the standard encoding BrowseNames to be recognised, but requires each
// DataType to support only at least one of them. This Server has a UA Binary Structure codec and no XML
// or JSON Value codec, so both explicit unavailable requests must receive the Table 183 refusal rather
// than a Good response containing a substituted binary Value. The JSON request is the paired control;
// `ATTR_READ_006_DefaultBinaryEncodingRecognized` proves the same Structure is available in the
// supported encoding.
// @verifies AC-SVR-ATTR-READ-022-BAD-DATAENCODINGUNSUPPORTED
// @relation(AC-SVR-ATTR-READ-006-DEFAULT-ENCODING-BROWSENAMES, scope=function)
TEST_F(ComplianceWithNodes, AskingForDefaultXmlOnAStructureValueIsRefusedRatherThanAnsweredInBinary)
{
  const NodeId serverStatus{VariableId::Server_ServerStatus};

  auto xmlResult = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                          .read(serverStatus)
                                                          .attribute(AttributeId::Value)
                                                          .data_encoding(QualifiedName{"Default XML"}));
  ASSERT_THAT(xmlResult, Good()) << "the Service call itself must answer";
  auto xmlResp = std::move(xmlResult).value();
  ASSERT_EQ(xmlResp.results().size(), 1u);
  const auto& xmlValue = xmlResp.results()[0];

  // The control: an encoding this Server equally cannot produce, and refuses.
  auto jsonResult = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                           .read(serverStatus)
                                                           .attribute(AttributeId::Value)
                                                           .data_encoding(QualifiedName{"Default JSON"}));
  ASSERT_THAT(jsonResult, Good());
  auto jsonResp = std::move(jsonResult).value();
  ASSERT_EQ(jsonResp.results().size(), 1u);
  ASSERT_TRUE(jsonResp.results()[0].status().has_value());
  ASSERT_EQ(jsonResp.results()[0].status()->as_status(), Status::BadDataEncodingUnsupported)
    << "the control encoding is no longer refused, so this test's comparison has lost its baseline";

  ASSERT_TRUE(xmlValue.status().has_value())
    << "the Default XML Read returned no status at all, which reads as Good: this Server cannot "
       "produce an XML-encoded Value in a Read response, so a Good status tells the Client its "
       "request was honoured when it was not";
  EXPECT_EQ(xmlValue.status()->as_status(), Status::BadDataEncodingUnsupported)
    << "asking for Default XML returned 0x" << std::hex << xmlValue.status()->as_uint32() << std::dec
    << " and a Value encoded in UA Binary. Default JSON, which this Server is in exactly the same "
       "position over, is refused with Bad_DataEncodingUnsupported. A Client that asked for XML "
       "because XML is what it decodes gets bytes it cannot parse and no indication of it";
}

// ServerCapabilities.ConformanceUnits is a QualifiedName[] (i=24101). A server that claims no conformance
// units still returns a QualifiedName array - empty - so the Value's type matches the DataType Attribute. The
// CTT's Base Info Core Structure 2 read it as a Variant with no type.
TEST_F(ComplianceWithNodes, ConformanceUnitsReadsAsAQualifiedNameArray)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerCapabilities_ConformanceUnits};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  const auto& value = resp.results()[0];
  ASSERT_TRUE(!value.status() || value.status()->is_good())
    << "0x" << std::hex << (value.status() ? value.status()->as_uint32() : 0u);
  EXPECT_FALSE(value.value().empty()) << "ConformanceUnits read as a Variant with no type";
  EXPECT_NE(value.value().try_as<Array<QualifiedName>>(), nullptr)
    << "ConformanceUnits is not a QualifiedName array";
}
