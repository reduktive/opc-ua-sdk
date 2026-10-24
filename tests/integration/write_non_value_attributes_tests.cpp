// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 4 section 5.10.4.2, Table 59: a Server returns Bad_WriteNotSupported "if an indexRange is provided and
// writing of indexRange is not possible for the Node"; section 5.10.4.4, Table 61: for a value, status code
// and timestamp combination it does not support, it "shall not perform any write on this Node". The SDK
// writes no IndexRange, timestamp or status of an Attribute other than a Variable's Value (delivery decision
// DL-6). A SecurityAdmin Client writes over a signed and encrypted channel, so it may write RolePermissions
// and is returned DiagnosticInfo.

#include "helpers/role_based_security_fixture.h"

#include "access_control_test_support.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_diagnostic_bits.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;

namespace
{

constexpr const char* rangeOne = "1";

NodeId security_admin()
{
  return NodeId{ObjectId::WellKnownRole_SecurityAdmin};
}

class WriteNonValueAttributes : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(server::RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  std::shared_ptr<server::UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      server::UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }

  void customize_server_configuration(server::ServerConfig& serverConfig) override
  {
    serverConfig.diagnosticPolicy.defaultLevel = server::ServerConfig::DiagnosticPolicy::Level::Full;
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    mIndex = install_test_namespace(addressSpace, "urn:test:write-non-value-attributes");
    grant_namespace_to_test_client(addressSpace, mIndex, {security_admin()});

    mPermissionsNode = create_object(addressSpace, 7800u, AttributeWriteMask::Bit::RolePermissions);
    addressSpace.find_node_sync(mPermissionsNode).set_role_permissions(two_role_permissions());
    mShapeNode = NodeId{mIndex, uint32_t{7801}};
    {
      auto node = addressSpace.create_node_sync(mShapeNode, NodeClass::Variable);
      node.set_browse_name(QualifiedName{mIndex, "Shape"});
      node.set_display_name(LocalizedText{"", "Shape"});
      node.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
      auto variable = node.as<VariableAccessor>();
      ASSERT_TRUE(variable.has_value());
      variable->set_data_type(NodeId{DataTypeId::Int32});
      variable->set_value_rank(ValueRank{2});
      variable->set_array_dimensions(std::vector<uint32_t>{2, 3});
      node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ArrayDimensions});
    }
    mNameNode = create_object(addressSpace, 7802u, AttributeWriteMask::Bit::DisplayName);
    mArrayTypeNode = create_variable_type(addressSpace, 7803u, 1, Variant{Array<int32_t>{1, 2, 3}});

    mStampedNameNode = create_object(addressSpace, 7804u, AttributeWriteMask::Bit::DisplayName);
    mStampedPermissionsNode = create_object(addressSpace, 7805u, AttributeWriteMask::Bit::RolePermissions);
    addressSpace.find_node_sync(mStampedPermissionsNode).set_role_permissions(two_role_permissions());
    mScalarTypeNode = create_variable_type(addressSpace, 7806u, ValueRank::scalar, Variant{int32_t{7}});
  }

  // Two entries: SecurityAdmin with every permission, and Anonymous with Browse and Read.
  static std::vector<RolePermissionType> two_role_permissions()
  {
    return {make_role_permission(security_admin(),
              {PermissionType::Bit::Browse,
                PermissionType::Bit::ReadRolePermissions,
                PermissionType::Bit::Read,
                PermissionType::Bit::Write,
                PermissionType::Bit::WriteAttribute,
                PermissionType::Bit::WriteRolePermissions}),
      make_role_permission(
        NodeId{ObjectId::WellKnownRole_Anonymous}, {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  }

  // One entry: SecurityAdmin with every permission, so the Session can still write after it.
  static Variant one_role_permission()
  {
    const std::vector<RolePermissionType> one{make_role_permission(security_admin(),
      {PermissionType::Bit::Browse,
        PermissionType::Bit::ReadRolePermissions,
        PermissionType::Bit::Read,
        PermissionType::Bit::Write,
        PermissionType::Bit::WriteAttribute,
        PermissionType::Bit::WriteRolePermissions})};
    return Variant{array_utils::copy_to_array_of_references(one)};
  }

  NodeId create_object(AddressSpace& addressSpace, uint32_t id, AttributeWriteMask::Bit writable)
  {
    const NodeId nodeId{mIndex, id};
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Object);
    const std::string name = "Object" + std::to_string(id);
    node.set_browse_name(QualifiedName{mIndex, name});
    node.set_display_name(LocalizedText{"", "Original"});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    node.set_write_mask(AttributeWriteMask{writable});
    return nodeId;
  }

  // A VariableType of DataType Int32 below BaseDataVariableType whose WriteMask sets bit 21
  // (ValueForVariableType).
  NodeId create_variable_type(AddressSpace& addressSpace, uint32_t id, int32_t valueRank, Variant value)
  {
    const NodeId typeId{mIndex, id};
    auto created = addressSpace.try_create_node_sync(typeId, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good()) << "the VariableType " << id << " could not be created";
    if (created.is_bad())
      return typeId;
    auto type = created.value();
    const std::string name = "Type" + std::to_string(id);
    type.set_browse_name(QualifiedName{mIndex, name});
    type.set_display_name(LocalizedText{"", name});
    auto variableType = type.as<VariableTypeAccessor>();
    EXPECT_TRUE(variableType.has_value());
    if (!variableType.has_value())
      return typeId;
    variableType->set_data_type(NodeId{DataTypeId::Int32});
    variableType->set_value_rank(ValueRank{valueRank});
    variableType->set_value(DataValue{std::move(value)});
    type.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType});
    addressSpace.find_node_sync(NodeId{VariableTypeId::BaseDataVariableType})
      .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, typeId);  // and its inverse half (NR-70 B8)
    return typeId;
  }

  static WriteValue attribute_write(
    const NodeId& nodeId, AttributeId attributeId, Variant value, const char* indexRange = nullptr)
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = static_cast<uint32_t>(attributeId);
    if (indexRange != nullptr)
      wv.index_range() = indexRange;
    wv.value().value() = std::move(value);
    return wv;
  }

  static WriteResponse write(client::Session& session, std::vector<WriteValue> items)
  {
    WriteRequest request;
    request.request_header().return_diagnostics() = diag::operationLevelMask;
    for (auto& item : items)
      request.nodes_to_write().payload().push_back(std::move(item));
    auto response = session.attributes().write_sync(std::move(request));
    EXPECT_THAT(response, ServiceResultIsGood());
    return response;
  }

  // The symbolic id the DiagnosticInfo of @p item names, or "" when it names none.
  static std::string symbolic_id(const WriteResponse& response, size_t item)
  {
    if (item >= response.diagnostic_infos().size())
      return {};
    const auto& diagnostic = response.diagnostic_infos()[item];
    if (!diagnostic.symbolic_id().has_value())
      return {};
    const auto index = static_cast<size_t>(*diagnostic.symbolic_id());
    const auto& strings = response.response_header().string_table();
    return index < strings.size() ? std::string{strings[index]} : std::string{};
  }

  static void expect_refused(
    const WriteResponse& response, size_t item, const char* detailCode, const char* what)
  {
    ASSERT_GT(response.results().size(), item) << what;
    EXPECT_EQ(response.results()[item].as_status(), Status::BadWriteNotSupported)
      << what << " answered " << to_string(response.results()[item]);
    EXPECT_EQ(symbolic_id(response, item), detailCode) << what;
  }

  static DataValue read(client::Session& session, const NodeId& nodeId, AttributeId attributeId)
  {
    auto response =
      session.attributes().read_sync(ReadRequestBuilder{}.read(nodeId).attribute(attributeId).build());
    if (response.results().size() != 1u)
    {
      ADD_FAILURE() << "the Read answered " << response.results().size() << " results for one item";
      return {};
    }
    EXPECT_THAT(response.results()[0], Good())
      << "reading " << to_string(attributeId) << " of " << to_string(nodeId);
    return response.results()[0];
  }

  static size_t role_permission_count(client::Session& session, const NodeId& nodeId)
  {
    const auto value = read(session, nodeId, AttributeId::RolePermissions).value();
    if (!value.is_array_of_structure())
      return 0u;
    return value.as<Array<RefStructure<Structure>>>().size();
  }

  static std::string display_name(client::Session& session, const NodeId& nodeId)
  {
    const auto value = read(session, nodeId, AttributeId::DisplayName).value();
    const auto* text = value.try_as<LocalizedText>();
    return text == nullptr ? std::string{"<not a LocalizedText>"}
                           : std::string{static_cast<std::string_view>(text->text())};
  }

  uint16_t mIndex = 0;
  NodeId mPermissionsNode;
  NodeId mShapeNode;
  NodeId mNameNode;
  NodeId mArrayTypeNode;
  NodeId mStampedNameNode;
  NodeId mStampedPermissionsNode;
  NodeId mScalarTypeNode;
};

}  // namespace

// The classes are an array Attribute (ArrayDimensions), a scalar one (DisplayName), the RolePermissions route
// and a VariableType's Value. The same four writes with no IndexRange, the ArrayDimensions with two entries,
// are the control that each is writable.
// @relation(AC-SVR-ATTR-WRITE-005-NON-VALUE-INDEXRANGE-REFUSED, scope=function)
TEST_F(WriteNonValueAttributes, AnIndexRangeIsWriteNotSupportedAndNothingIsWritten)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteNonValueRange");
  const auto writes = [this](const char* indexRange)
  {
    // The ranged write keeps [5], refused for its range before its value is looked at; the unranged one sends
    // two entries, which the ValueRank of 2 takes (DL-32).
    Array<uint32_t> dimensions;
    dimensions.payload() = indexRange != nullptr ? std::vector<uint32_t>{5} : std::vector<uint32_t>{4, 6};
    return std::vector<WriteValue>{
      attribute_write(mPermissionsNode, AttributeId::RolePermissions, one_role_permission(), indexRange),
      attribute_write(mShapeNode, AttributeId::ArrayDimensions, Variant{std::move(dimensions)}, indexRange),
      attribute_write(mNameNode, AttributeId::DisplayName, Variant{LocalizedText{"", "Renamed"}}, indexRange),
      attribute_write(mArrayTypeNode, AttributeId::Value, Variant{Array<int32_t>{9}}, indexRange)};
  };

  const auto ranged = write(session, writes(rangeOne));
  ASSERT_EQ(ranged.results().size(), 4u);
  expect_refused(ranged, 0, "IndexRangeWriteNotSupported", "the ranged RolePermissions write");
  expect_refused(ranged, 1, "IndexRangeWriteNotSupported", "the ranged ArrayDimensions write");
  expect_refused(ranged, 2, "IndexRangeWriteNotSupported", "the ranged DisplayName write");
  expect_refused(ranged, 3, "IndexRangeWriteNotSupported", "the ranged VariableType Value write");

  EXPECT_EQ(role_permission_count(session, mPermissionsNode), 2u)
    << "the ranged write replaced the RolePermissions";
  EXPECT_EQ(to_string(read(session, mShapeNode, AttributeId::ArrayDimensions).value()),
    to_string(Variant{Array<uint32_t>{2, 3}}))
    << "the ranged write changed the ArrayDimensions";
  EXPECT_EQ(display_name(session, mNameNode), "Original") << "the ranged write changed the DisplayName";
  EXPECT_EQ(to_string(read(session, mArrayTypeNode, AttributeId::Value).value()),
    to_string(Variant{Array<int32_t>{1, 2, 3}}))
    << "the ranged write changed the VariableType's Value";

  const auto whole = write(session, writes(nullptr));
  ASSERT_EQ(whole.results().size(), 4u);
  const char* names[] = {"RolePermissions", "ArrayDimensions", "DisplayName", "VariableType Value"};
  for (size_t item = 0; item < 4u; ++item)
  {
    EXPECT_EQ(whole.results()[item].as_status(), Status::Good)
      << "the " << names[item] << " write with no IndexRange answered " << to_string(whole.results()[item])
      << " (" << symbolic_id(whole, item) << ")";
  }
  EXPECT_EQ(to_string(read(session, mShapeNode, AttributeId::ArrayDimensions).value()),
    to_string(Variant{Array<uint32_t>{4, 6}}))
    << "the unranged ArrayDimensions write was not stored";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// The classes are a SourceTimestamp, a ServerTimestamp, an Uncertain status, a Good status with info bits,
// the RolePermissions route and a VariableType's Value. A DataValue whose timestamps are null and whose
// status is 0 is what unset fields encode as: the control.
// @relation(AC-SVR-ATTR-WRITE-022-NON-VALUE-TIMESTAMP-OR-STATUS-REFUSED, scope=function)
TEST_F(WriteNonValueAttributes, ATimestampOrStatusIsWriteNotSupportedAndNothingIsWritten)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteNonValueStamps");
  const auto renamed = [this]
  {
    return attribute_write(mStampedNameNode, AttributeId::DisplayName, Variant{LocalizedText{"", "Renamed"}});
  };
  auto withSourceTimestamp = renamed();
  withSourceTimestamp.value().source_timestamp() = DateTime::now();
  auto withServerTimestamp = renamed();
  withServerTimestamp.value().server_timestamp() = DateTime::now();
  auto withUncertain = renamed();
  withUncertain.value().status() = StatusCode{Status::Uncertain};
  auto withGoodInfoBits = renamed();
  // Severity Good, InfoType DataValue (bit 10) and the Overflow info bit (bit 7).
  withGoodInfoBits.value().status() = StatusCode{StatusCodeValue{0x00000480U}};
  auto permissionsWithTimestamp =
    attribute_write(mStampedPermissionsNode, AttributeId::RolePermissions, one_role_permission());
  permissionsWithTimestamp.value().source_timestamp() = DateTime::now();
  auto typeValueWithTimestamp = attribute_write(mScalarTypeNode, AttributeId::Value, Variant{int32_t{42}});
  typeValueWithTimestamp.value().source_timestamp() = DateTime::now();

  const auto refused = write(session,
    {withSourceTimestamp,
      withServerTimestamp,
      withUncertain,
      withGoodInfoBits,
      permissionsWithTimestamp,
      typeValueWithTimestamp});
  ASSERT_EQ(refused.results().size(), 6u);
  expect_refused(refused, 0, "TimestampWriteNotSupported", "the DisplayName write with a SourceTimestamp");
  expect_refused(refused, 1, "TimestampWriteNotSupported", "the DisplayName write with a ServerTimestamp");
  expect_refused(refused, 2, "StatusWriteNotSupported", "the DisplayName write with the status Uncertain");
  expect_refused(
    refused, 3, "StatusWriteNotSupported", "the DisplayName write with a Good status and info bits");
  expect_refused(
    refused, 4, "TimestampWriteNotSupported", "the RolePermissions write with a SourceTimestamp");
  expect_refused(
    refused, 5, "TimestampWriteNotSupported", "the VariableType Value write with a SourceTimestamp");

  EXPECT_EQ(display_name(session, mStampedNameNode), "Original") << "a refused write changed the DisplayName";
  EXPECT_EQ(role_permission_count(session, mStampedPermissionsNode), 2u)
    << "a refused write replaced the RolePermissions";
  EXPECT_EQ(
    to_string(read(session, mScalarTypeNode, AttributeId::Value).value()), to_string(Variant{int32_t{7}}))
    << "a refused write changed the VariableType's Value";

  auto unset = renamed();
  unset.value().status() = StatusCode{Status::Good};
  unset.value().source_timestamp() = DateTime{};
  unset.value().server_timestamp() = DateTime{};
  const auto control = write(session, {unset});
  ASSERT_EQ(control.results().size(), 1u);
  EXPECT_EQ(control.results()[0].as_status(), Status::Good)
    << "the write with null timestamps and the status 0 answered " << to_string(control.results()[0]) << " ("
    << symbolic_id(control, 0) << ")";
  EXPECT_EQ(display_name(session, mStampedNameNode), "Renamed");
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// --- ArrayDimensions written by a Client (DL-32) -----------------------------------------------------------

namespace
{

class WriteArrayDimensions : public WriteNonValueAttributes
{
protected:
  // A Variable or VariableType of DataType Int32 with ValueRank @p rank and, unless null, the ArrayDimensions
  // @p dimensions, whose WriteMask sets bit 1 (ArrayDimensions) only.
  NodeId create_dimensioned(
    uint32_t id, NodeClass nodeClass, int32_t rank, std::optional<std::vector<uint32_t>> dimensions)
  {
    auto addressSpace = mServer->address_space();
    const NodeId nodeId{mIndex, id};
    auto created = addressSpace.try_create_node_sync(nodeId, nodeClass, {});
    EXPECT_TRUE(created.is_good()) << "the node " << id << " could not be created";
    if (created.is_bad())
      return nodeId;
    auto node = std::move(created).value();
    const std::string name = "Dimensioned" + std::to_string(id);
    node.set_browse_name(QualifiedName{mIndex, name});
    node.set_display_name(LocalizedText{"", name});
    if (auto variable = node.as<VariableAccessor>())
    {
      variable->set_data_type(NodeId{DataTypeId::Int32});
      variable->set_value_rank(ValueRank{rank});
      if (dimensions)
        variable->set_array_dimensions(*dimensions);
    }
    else if (auto type = node.as<VariableTypeAccessor>())
    {
      type->set_data_type(NodeId{DataTypeId::Int32});
      type->set_value_rank(ValueRank{rank});
      if (dimensions)
        type->set_array_dimensions(*dimensions);
    }
    node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ArrayDimensions});
    return nodeId;
  }

  static Variant dimensions_of(std::vector<uint32_t> entries)
  {
    Array<uint32_t> dimensions;
    dimensions.payload() = std::move(entries);
    return Variant{std::move(dimensions)};
  }

  // The status of one ArrayDimensions write of @p value to @p nodeId.
  static StatusCode write_dimensions(client::Session& session, const NodeId& nodeId, Variant value)
  {
    const auto response =
      write(session, {attribute_write(nodeId, AttributeId::ArrayDimensions, std::move(value))});
    if (response.results().size() != 1u)
    {
      ADD_FAILURE() << "the Write answered " << response.results().size() << " results for one item";
      return StatusCode{Status::BadUnexpectedError};
    }
    return response.results()[0];
  }

  static constexpr const char* sAbsent = "absent (Bad_AttributeIdInvalid with no value)";

  // The ArrayDimensions a Read of @p nodeId returns, or `sAbsent` when it answers Bad_AttributeIdInvalid with
  // no value, as for a node created without them.
  static std::string read_dimensions(client::Session& session, const NodeId& nodeId)
  {
    auto response = session.attributes().read_sync(
      ReadRequestBuilder{}.read(nodeId).attribute(AttributeId::ArrayDimensions).build());
    if (response.results().size() != 1u)
      return "the Read answered " + std::to_string(response.results().size()) + " results";
    const auto& result = response.results()[0];
    const auto status = result.status().value_or(StatusCode{Status::Good});
    if (status.as_status() == Status::BadAttributeIdInvalid && result.value().empty())
      return sAbsent;
    if (status.is_bad())
      return "the Read answered " + to_string(status) + " with " + to_string(result.value());
    return to_string(result.value());
  }
};

}  // namespace

// Part 3 section 8.60, Table 43: bit 1 "Indicates if the ArrayDimensions Attribute is writable";
// section 5.6.2, Table 13 (Variable) and section 5.6.5, Table 14 (VariableType): the number of entries equals
// the ValueRank. DL-32: a ValueRank n greater than 0 takes n entries.
// @relation(AC-SVR-ATTR-WRITE-033-MATCHING-COUNT-STORED, scope=function)
TEST_F(WriteArrayDimensions, AsManyEntriesAsTheValueRankAreStored)
{
  const auto v2 = create_dimensioned(7900u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto t2 = create_dimensioned(7901u, NodeClass::VariableType, 2, std::vector<uint32_t>{2, 3});
  const auto v1 = create_dimensioned(7902u, NodeClass::Variable, 1, std::vector<uint32_t>{5});
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteArrayDimensionsCount");

  EXPECT_THAT(write_dimensions(session, v2, dimensions_of({4, 6})), HasStatus(Status::Good))
    << "[4, 6] to V2";
  EXPECT_THAT(write_dimensions(session, t2, dimensions_of({4, 6})), HasStatus(Status::Good))
    << "[4, 6] to T2";
  EXPECT_THAT(write_dimensions(session, v1, dimensions_of({7})), HasStatus(Status::Good)) << "[7] to V1";
  EXPECT_EQ(read_dimensions(session, v2), to_string(dimensions_of({4, 6}))) << "V2";
  EXPECT_EQ(read_dimensions(session, t2), to_string(dimensions_of({4, 6}))) << "T2";
  EXPECT_EQ(read_dimensions(session, v1), to_string(dimensions_of({7}))) << "V1";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 4 section 5.10.4.2, Table 59: a Server may impose validations and "shall return a Bad_TypeMismatch
// error if the validation fails". DL-32: a count other than a positive ValueRank is refused and nothing is
// stored; fewer and more entries on V2, fewer on T2.
// @relation(AC-SVR-ATTR-WRITE-033-WRONG-COUNT-TYPE-MISMATCH, scope=function)
TEST_F(WriteArrayDimensions, AWrongNumberOfEntriesIsTypeMismatch)
{
  const auto v2 = create_dimensioned(7910u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto t2 = create_dimensioned(7911u, NodeClass::VariableType, 2, std::vector<uint32_t>{2, 3});
  const auto held = to_string(dimensions_of({2, 3}));
  auto [channel, session] =
    open_session(MessageSecurityMode::SignAndEncrypt, "WriteArrayDimensionsWrongCount");

  EXPECT_THAT(write_dimensions(session, v2, dimensions_of({5})), HasStatus(Status::BadTypeMismatch))
    << "[5] to V2";
  EXPECT_EQ(read_dimensions(session, v2), held) << "V2 after [5]";
  EXPECT_THAT(write_dimensions(session, v2, dimensions_of({1, 2, 3})), HasStatus(Status::BadTypeMismatch))
    << "[1, 2, 3] to V2";
  EXPECT_EQ(read_dimensions(session, v2), held) << "V2 after [1, 2, 3]";
  EXPECT_THAT(write_dimensions(session, t2, dimensions_of({2})), HasStatus(Status::BadTypeMismatch))
    << "[2] to T2";
  EXPECT_EQ(read_dimensions(session, t2), held) << "T2 after [2]";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 6 section 5.1.9: "null, empty and zero length arrays are semantically the same". DL-32: null or an
// empty array is accepted at every ValueRank and held as null, which a Read answers as it answers a node
// created without ArrayDimensions (Ve, the control).
// @relation(AC-SVR-ATTR-WRITE-033-NULL-OR-EMPTY-STORED-AS-NULL, scope=function)
TEST_F(WriteArrayDimensions, NullOrEmptyIsAcceptedAndReadsAsAbsent)
{
  const auto va = create_dimensioned(7920u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto vd = create_dimensioned(7921u, NodeClass::Variable, -3, std::vector<uint32_t>{4});
  const auto vb = create_dimensioned(7922u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto vc = create_dimensioned(7923u, NodeClass::Variable, -1, std::nullopt);
  const auto tb = create_dimensioned(7924u, NodeClass::VariableType, 2, std::vector<uint32_t>{2, 3});
  const auto ve = create_dimensioned(7925u, NodeClass::Variable, 2, std::nullopt);
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteArrayDimensionsNull");

  EXPECT_THAT(write_dimensions(session, va, Variant{}), HasStatus(Status::Good)) << "null to Va";
  EXPECT_THAT(write_dimensions(session, vd, Variant{}), HasStatus(Status::Good)) << "null to Vd";
  EXPECT_THAT(write_dimensions(session, vb, dimensions_of({})), HasStatus(Status::Good)) << "[] to Vb";
  EXPECT_THAT(write_dimensions(session, vc, dimensions_of({})), HasStatus(Status::Good)) << "[] to Vc";
  EXPECT_THAT(write_dimensions(session, tb, dimensions_of({})), HasStatus(Status::Good)) << "[] to Tb";
  const std::pair<NodeId, const char*> nodes[] = {
    {va, "Va"}, {vd, "Vd"}, {vb, "Vb"}, {vc, "Vc"}, {tb, "Tb"}, {ve, "Ve"}};
  for (const auto& [nodeId, name] : nodes)
    EXPECT_EQ(read_dimensions(session, nodeId), sAbsent) << name;
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 3 section 5.6.2, Table 13: a Variable's ArrayDimensions "shall be null if the Value is not an array";
// section 5.6.5, Table 14: a VariableType's "shall be null if ValueRank <= 0". DL-32 checks what the
// ValueRank makes knowable: Scalar takes no entry, ScalarOrOneDimension one, a VariableType of ValueRank 0 or
// less none, and a Variable of ValueRank 0 or -2 any number. Vom and T0 differ only in NodeClass.
// @relation(AC-SVR-ATTR-WRITE-033-NON-POSITIVE-VALUERANK, scope=function)
TEST_F(WriteArrayDimensions, AtAValueRankOfZeroOrLessTheValueRankAndNodeClassDecide)
{
  const auto vs = create_dimensioned(7930u, NodeClass::Variable, -1, std::nullopt);
  const auto vso = create_dimensioned(7931u, NodeClass::Variable, -3, std::nullopt);
  const auto vom = create_dimensioned(7932u, NodeClass::Variable, 0, std::nullopt);
  const auto vany = create_dimensioned(7933u, NodeClass::Variable, -2, std::nullopt);
  const auto t0 = create_dimensioned(7934u, NodeClass::VariableType, 0, std::nullopt);
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteArrayDimensionsRank");

  EXPECT_THAT(write_dimensions(session, vs, dimensions_of({3})), HasStatus(Status::BadTypeMismatch))
    << "[3] to Vs";
  EXPECT_EQ(read_dimensions(session, vs), sAbsent) << "Vs after [3]";
  EXPECT_THAT(write_dimensions(session, vso, dimensions_of({2, 2})), HasStatus(Status::BadTypeMismatch))
    << "[2, 2] to Vso";
  EXPECT_EQ(read_dimensions(session, vso), sAbsent) << "Vso after [2, 2]";
  EXPECT_THAT(write_dimensions(session, vso, dimensions_of({4})), HasStatus(Status::Good)) << "[4] to Vso";
  EXPECT_EQ(read_dimensions(session, vso), to_string(dimensions_of({4}))) << "Vso after [4]";
  EXPECT_THAT(write_dimensions(session, vom, dimensions_of({3})), HasStatus(Status::Good)) << "[3] to Vom";
  EXPECT_EQ(read_dimensions(session, vom), to_string(dimensions_of({3}))) << "Vom after [3]";
  EXPECT_THAT(write_dimensions(session, vom, dimensions_of({2, 2, 2})), HasStatus(Status::Good))
    << "[2, 2, 2] to Vom";
  EXPECT_EQ(read_dimensions(session, vom), to_string(dimensions_of({2, 2, 2}))) << "Vom after [2, 2, 2]";
  EXPECT_THAT(write_dimensions(session, vany, dimensions_of({3})), HasStatus(Status::Good)) << "[3] to Vany";
  EXPECT_EQ(read_dimensions(session, vany), to_string(dimensions_of({3}))) << "Vany after [3]";
  EXPECT_THAT(write_dimensions(session, vany, dimensions_of({2, 2})), HasStatus(Status::Good))
    << "[2, 2] to Vany";
  EXPECT_EQ(read_dimensions(session, vany), to_string(dimensions_of({2, 2}))) << "Vany after [2, 2]";
  EXPECT_THAT(write_dimensions(session, t0, dimensions_of({3})), HasStatus(Status::BadTypeMismatch))
    << "[3] to T0";
  EXPECT_EQ(read_dimensions(session, t0), sAbsent) << "T0 after [3]";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 3 section 5.6.2, Table 13 gives ArrayDimensions the DataType UInt32[]; Part 4 section 5.10.4.2, Table
// 59 answers a value of another type Bad_TypeMismatch. DL-32 takes a one-dimensional UInt32 array or null
// only, so the scalar and the matrix are refused too. Each refused value has one entry, which ValueRank 1
// takes; {7} is the control.
// @relation(AC-SVR-ATTR-WRITE-033-NOT-A-UINT32-ARRAY, scope=function)
TEST_F(WriteArrayDimensions, AValueThatIsNotAOneDimensionalUInt32ArrayIsTypeMismatch)
{
  const auto v1 = create_dimensioned(7940u, NodeClass::Variable, 1, std::vector<uint32_t>{5});
  const auto held = to_string(dimensions_of({5}));
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteArrayDimensionsType");

  EXPECT_THAT(write_dimensions(session, v1, Variant{Array<int32_t>{3}}), HasStatus(Status::BadTypeMismatch))
    << "the Int32 array {3}";
  EXPECT_EQ(read_dimensions(session, v1), held) << "after the Int32 array";
  EXPECT_THAT(
    write_dimensions(session, v1, Variant{Array<uint32_t>{Dimensions{1, 1}, std::vector<uint32_t>{3}}}),
    HasStatus(Status::BadTypeMismatch))
    << "the UInt32 matrix {3} with array dimensions {1, 1}";
  EXPECT_EQ(read_dimensions(session, v1), held) << "after the UInt32 matrix";
  EXPECT_THAT(write_dimensions(session, v1, Variant{uint32_t{3}}), HasStatus(Status::BadTypeMismatch))
    << "the scalar UInt32 3";
  EXPECT_EQ(read_dimensions(session, v1), held) << "after the scalar UInt32";
  EXPECT_THAT(write_dimensions(session, v1, dimensions_of({7})), HasStatus(Status::Good))
    << "the UInt32 array {7}";
  EXPECT_EQ(read_dimensions(session, v1), to_string(dimensions_of({7}))) << "after the UInt32 array {7}";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
