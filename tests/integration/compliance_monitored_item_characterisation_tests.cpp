// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Non-normative monitored-item behavior retained by the QA remediation sweep.

#include "compliance_helpers.h"
#include "subscription.h"

#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_timestamps_to_return.h"
#include "ua_value_rank.h"

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

class AbsoluteDeadbandNonNumericCharacterisation : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();
    mStringVariableId = NodeId{mTestNamespaceIndex, uint32_t{1020}};
    auto stringNode = addressSpace.create_node_sync(mStringVariableId, NodeClass::Variable);
    stringNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto stringVariable = stringNode.as<VariableAccessor>();
    ASSERT_TRUE(stringVariable.has_value());
    stringVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "DeadbandStringVar"});
    stringVariable->set_display_name(LocalizedText{"", "DeadbandStringVar"});
    stringVariable->set_data_type(NodeId{DataTypeId::String});
    stringVariable->write_value_sync(String{"initial"});
    stringVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mStringVariableId);

    mStringArrayVariableId = NodeId{mTestNamespaceIndex, uint32_t{1021}};
    add_variable(mStringArrayVariableId,
      "DeadbandStringArrayVar",
      NodeId{DataTypeId::String},
      Variant{Array<String>{String{"a"}, String{"b"}}},
      ValueRank{1});
    mBaseDataTypeVariableId = NodeId{mTestNamespaceIndex, uint32_t{1022}};
    add_variable(
      mBaseDataTypeVariableId, "DeadbandBaseDataTypeVar", NodeId{DataTypeId::BaseDataType}, Variant{0.0});
  }

  void add_variable(const NodeId& id, const char* name, const NodeId& dataType, Variant value,
    ValueRank valueRank = ValueRank{-1})
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.create_node_sync(id, NodeClass::Variable);
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    variable->set_display_name(LocalizedText{"", name});
    variable->set_data_type(dataType);
    variable->set_value_rank(valueRank);
    variable->write_value_sync(std::move(value));
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, id);
  }

  static std::unique_ptr<DataChangeFilter> absolute_deadband(double value)
  {
    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<std::uint32_t>(DeadbandType::Absolute);
    filter->deadband_value() = value;
    return filter;
  }

  /// Creates one Reporting item on @p nodeId's Value and returns its result status.
  MonitoredItemCreateResult create_item(IntegerId subscriptionId, const NodeId& nodeId, bool withDeadband)
  {
    ReadValueId valueToRead;
    valueToRead.node_id() = nodeId;
    valueToRead.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    MonitoringParameters parameters;
    parameters.client_handle() = 2;
    parameters.sampling_interval() = 0.0;
    parameters.queue_size() = 5;
    parameters.discard_oldest() = true;
    if (withDeadband)
    {
      parameters.filter() = absolute_deadband(5.0);
    }

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(valueToRead);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(parameters);

    CreateMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(std::move(item));

    auto response = mSession->monitored_items().create_monitored_items_sync(std::move(request));
    EXPECT_EQ(response.results().size(), 1u);
    return response.results().empty() ? MonitoredItemCreateResult{} : response.results()[0];
  }

  NodeId mStringVariableId;
  NodeId mStringArrayVariableId;
  NodeId mBaseDataTypeVariableId;
};

/// Part 4 section 7.22.2 (Table 146) says an AbsoluteDeadband "applies only to Variables with any Number
/// data type" and assigns no status to a request outside that scope. The Server's choice is to refuse
/// it with Bad_FilterNotAllowed (the code CTT Monitored Items Deadband Filter Err-002/003/005 require)
/// rather than accept a filter it would evaluate as plain equality. The choice is keyed on the
/// Variable's DataType, not its current value, and holds for Create and Modify alike. Numeric
/// suppression is verified in compliance_monitored_item_tests.cpp.
///
/// Four arms: a String scalar and a String array are refused on Create; a Variable declared
/// BaseDataType, which may hold numbers, is accepted (the control that keeps the refusal from reaching
/// every Variable not literally typed as a Number); and a Modify that adds the filter to an item
/// created without one is refused.
// @characterises(server.subscription.absolute_deadband_non_numeric)
TEST_F(AbsoluteDeadbandNonNumericCharacterisation, RefusedOnNonNumericDataTypesForCreateAndModify)
{
  auto subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});

  const auto scalar = create_item(subscriptionId, mStringVariableId, /*withDeadband=*/true);
  EXPECT_EQ(scalar.status_code(), StatusCode{Status::BadFilterNotAllowed})
    << "an AbsoluteDeadband on a String Variable must be refused: 0x" << std::hex
    << scalar.status_code().as_uint32();

  const auto array = create_item(subscriptionId, mStringArrayVariableId, /*withDeadband=*/true);
  EXPECT_EQ(array.status_code(), StatusCode{Status::BadFilterNotAllowed})
    << "an AbsoluteDeadband on a String array Variable must be refused: 0x" << std::hex
    << array.status_code().as_uint32();

  const auto untyped = create_item(subscriptionId, mBaseDataTypeVariableId, /*withDeadband=*/true);
  EXPECT_TRUE(untyped.status_code().is_good())
    << "an AbsoluteDeadband on a BaseDataType Variable must be accepted: 0x" << std::hex
    << untyped.status_code().as_uint32();

  const auto created = create_item(subscriptionId, mStringVariableId, /*withDeadband=*/false);
  ASSERT_TRUE(created.status_code().is_good());

  MonitoringParameters parameters;
  parameters.client_handle() = 2;
  parameters.sampling_interval() = 0.0;
  parameters.queue_size() = 5;
  parameters.discard_oldest() = true;
  parameters.filter() = absolute_deadband(10.0);

  MonitoredItemModifyRequest modifyItem;
  modifyItem.monitored_item_id() = created.monitored_item_id();
  modifyItem.requested_parameters() = std::move(parameters);

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_modify().push_back(std::move(modifyItem));

  auto response = mSession->monitored_items().modify_monitored_items_sync(std::move(request));
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadFilterNotAllowed})
    << "a Modify adding an AbsoluteDeadband on a String Variable must be refused: 0x" << std::hex
    << response.results()[0].status_code().as_uint32();
}
