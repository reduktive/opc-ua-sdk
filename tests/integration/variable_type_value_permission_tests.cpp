// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 3 section 8.55, Table 37: WriteAttribute "affects the value of a UserWriteMask Attribute" and "is
// valid for all NodeClasses"; Write "is only valid for Variables". Neither covers a VariableType's Value; the
// SDK authorizes its write for WriteAttribute (delivery decision DL-28), so the write and bit 21
// (ValueForVariableType) of the UserWriteMask a Session reads agree. The Session is Anonymous and holds the
// Anonymous Role and no other; the RolePermissions of the VariableType T and the Variable V give that Role
// the Permissions each test names.

#include "helpers/role_based_security_fixture.h"

#include "matchers.h"
#include "requests.h"

#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
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
#include <initializer_list>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;

namespace
{

class VariableTypeValuePermission : public ComplianceRoleBasedSecurity
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    mIndex = install_test_namespace(addressSpace, "urn:test:variable-type-value-permission");
  }

  // Gives the Anonymous Role exactly @p permissions on a VariableType T of DataType Int32 whose WriteMask
  // sets bit 21 and whose Value is 7, and on an Int32 Variable V whose AccessLevel sets CurrentWrite.
  void create_nodes(std::initializer_list<PermissionType::Bit> permissions)
  {
    auto addressSpace = mServer->address_space();
    const std::vector<RolePermissionType> granted{
      make_role_permission(NodeId{ObjectId::WellKnownRole_Anonymous}, permissions)};

    mType = NodeId{mIndex, uint32_t{7700}};
    auto created = addressSpace.try_create_node_sync(mType, NodeClass::VariableType, {});
    ASSERT_TRUE(created.is_good()) << "the VariableType T could not be created";
    auto type = created.value();
    type.set_browse_name(QualifiedName{mIndex, "PermissionType"});
    type.set_display_name(LocalizedText{"", "PermissionType"});
    auto variableType = type.as<VariableTypeAccessor>();
    ASSERT_TRUE(variableType.has_value());
    variableType->set_data_type(NodeId{DataTypeId::Int32});
    variableType->set_value_rank(ValueRank{ValueRank::scalar});
    variableType->set_value(DataValue{Variant{int32_t{7}}});
    type.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType});
    addressSpace.find_node_sync(NodeId{VariableTypeId::BaseDataVariableType})
      .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, mType);  // and its inverse half (NR-70 B8)
    type.set_role_permissions(granted);

    mVariable =
      create_role_gated_variable(addressSpace, NodeId{mIndex, uint32_t{7701}}, "PermissionVariable", granted);
  }

  static WriteResponse write_both(
    client::Session& session, const NodeId& type, const NodeId& variable, int32_t value)
  {
    WriteRequest request;
    for (const auto& nodeId : {type, variable})
    {
      WriteValue item;
      item.node_id() = nodeId;
      item.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
      item.value().value() = Variant{value};
      request.nodes_to_write().payload().push_back(std::move(item));
    }
    auto response = session.attributes().write_sync(std::move(request));
    EXPECT_THAT(response, ServiceResultIsGood());
    return response;
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

  static bool user_write_mask_sets_bit_21(client::Session& session, const NodeId& nodeId)
  {
    const auto value = read(session, nodeId, AttributeId::UserWriteMask).value();
    const auto* mask = value.try_as<uint32_t>();
    if (mask == nullptr)
    {
      ADD_FAILURE() << "the UserWriteMask reads " << to_string(value);
      return false;
    }
    return AttributeWriteMask{*mask}.test(AttributeWriteMask::Bit::ValueForVariableType);
  }

  uint16_t mIndex = 0;
  NodeId mType;
  NodeId mVariable;
};

}  // namespace

// DL-28: a Session holding WriteAttribute and not Write reads bit 21 set in T's UserWriteMask and writes T's
// Value. V is the control that a Variable's Value is still authorized for Write.
// @relation(AC-SVR-ATTR-WRITE-032-WRITEATTRIBUTE-AUTHORIZES, scope=function)
TEST_F(VariableTypeValuePermission, WriteAttributeWithoutWriteWritesTheValue)
{
  create_nodes({PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::WriteAttribute});
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteAttributeWithoutWrite");

  EXPECT_TRUE(user_write_mask_sets_bit_21(session, mType))
    << "the UserWriteMask of T does not set bit 21 for a Session holding WriteAttribute";
  const auto written = write_both(session, mType, mVariable, 9);
  ASSERT_EQ(written.results().size(), 2u);
  EXPECT_THAT(written.results()[0], HasStatus(Status::Good)) << "the write of T's Value";
  EXPECT_EQ(to_string(read(session, mType, AttributeId::Value).value()), to_string(Variant{int32_t{9}}));
  EXPECT_THAT(written.results()[1], HasStatus(Status::BadUserAccessDenied)) << "the write of V's Value";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// DL-28, the other half of the pair: a Session holding Write and not WriteAttribute, as the well-known
// Operator does, reads bit 21 clear in T's UserWriteMask and is refused T's Value with Bad_UserAccessDenied;
// it still writes V's Value.
// @relation(AC-SVR-ATTR-WRITE-032-WRITE-WITHOUT-WRITEATTRIBUTE-DENIED, scope=function)
TEST_F(VariableTypeValuePermission, WriteWithoutWriteAttributeIsUserAccessDenied)
{
  create_nodes({PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write});
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "WriteWithoutWriteAttribute");

  EXPECT_FALSE(user_write_mask_sets_bit_21(session, mType))
    << "the UserWriteMask of T sets bit 21 for a Session without WriteAttribute";
  const auto written = write_both(session, mType, mVariable, 11);
  ASSERT_EQ(written.results().size(), 2u);
  EXPECT_THAT(written.results()[0], HasStatus(Status::BadUserAccessDenied)) << "the write of T's Value";
  EXPECT_EQ(to_string(read(session, mType, AttributeId::Value).value()), to_string(Variant{int32_t{7}}));
  EXPECT_THAT(written.results()[1], HasStatus(Status::Good)) << "the write of V's Value";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
