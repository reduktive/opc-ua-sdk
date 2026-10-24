// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The Data Access write check of OPC 10000-8 through the Write service, end to end. Part 8 section 5.3.2.2:
// the EURange and InstrumentRange Properties of BaseAnalogType bound the Value, "If the analog item's Value
// contains an array, the Properties shall apply to all elements in the array", and what a write outside the
// range does is the Server's choice. The SDK's choice is the policy
// set in ServerConfig::dataAccessWritePolicy: Reject answers Bad_OutOfRange and stores nothing; Clamp stores
// the nearest value of the element's type inside the range, and the Write answers Good_Clamped (Part 4
// section 7.39.2, Table 183). A NaN limit is not known (Part 8 section 5.6.2) and bounds nothing on its side.
// Every instance of BaseAnalogType or a subtype is to be checked (NR-58), which the fix of
// D-NR-F5-BASEANALOGTYPE-INSTANCES-NOT-RANGE-CHECKED makes true (C4, DL-35); until then only instances of
// AnalogItemType and its subtypes are.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_data_access_utils.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_server_configuration.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <cstdint>
#include <limits>
#include <memory>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

class DataAccessWrite : public ComplianceWithNodes
{
protected:
  // Each test chooses its own policy, which the server takes at creation, so the server starts in use_policy.
  void SetUp() override
  {}

  void TearDown() override
  {
    ComplianceWithNodes::TearDown();
  }

  void configure_server_config(ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.dataAccessWritePolicy = mPolicy;
  }

  // Starts the server with the Data Access write check set to @p policy.
  void use_policy(DataAccessOutOfRangePolicy policy)
  {
    mPolicy = policy;
    ComplianceWithNodes::SetUp();
  }

  DataAccessOutOfRangePolicy mPolicy{DataAccessOutOfRangePolicy::Reject};

  // Creates a readable and writable Variable of @p typeDefinition and @p dataType, with an EURange Property
  // {low, high} and no InstrumentRange, holding @p initial.
  NodeId make_analog(uint32_t identifier, const NodeId& typeDefinition, const Variant& initial, double low,
    double high, bool oneDimension = false, const NodeId& dataType = NodeId{DataTypeId::Double})
  {
    auto addressSpace = mServer.server().address_space();
    const NodeId variableId{mTestNamespaceIndex, identifier};
    auto variableNode = addressSpace.create_node_sync(variableId, NodeClass::Variable);
    auto variable = variableNode.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    const std::string name = "Analog" + std::to_string(identifier);
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    variable->set_display_name(LocalizedText{"", String{name}});
    variable->set_data_type(dataType);
    if (oneDimension)
      variable->set_value_rank(ValueRank{1});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(DataValue{initial});
    variableNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeDefinition);

    const NodeId euRangeId{mTestNamespaceIndex, identifier + 1};
    auto euRangeNode = addressSpace.create_node_sync(euRangeId, NodeClass::Variable);
    auto euRange = euRangeNode.as<VariableAccessor>();
    EXPECT_TRUE(euRange.has_value());
    euRange->set_browse_name(QualifiedName{0, "EURange"});
    euRange->set_data_type(NodeId{DataTypeId::Range});
    auto range = std::make_unique<Range>();
    range->low() = low;
    range->high() = high;
    euRange->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    euRangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    variableNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euRangeId);
    return variableId;
  }

  StatusCode write(const NodeId& node, const Variant& value)
  {
    auto response = mSession->attributes().write_sync(WriteRequestBuilder().write(node, value));
    EXPECT_EQ(response.results().size(), 1u);
    return response.results().empty() ? StatusCode{Status::BadUnexpectedError} : response.results()[0];
  }

  Variant read(const NodeId& node)
  {
    return mSession->attributes().read_sync(read_value(node)).results()[0].value();
  }
};

}  // namespace

// @relation(AC-SVR-DA-003-ARRAY-WRITE-RANGE-CHECKED, scope=function)
TEST_F(DataAccessWrite, AnArrayWriteOutsideTheEuRangeIsRejected)
{
  use_policy(DataAccessOutOfRangePolicy::Reject);
  const auto analog = make_analog(
    6100, NodeId{VariableTypeId::AnalogItemType}, Variant{Array<double>{10.0, 20.0, 30.0}}, 0.0, 100.0, true);

  EXPECT_THAT(write(analog, Variant{Array<double>{15.0, 150.0, 25.0}}), HasStatus(Status::BadOutOfRange))
    << "an array with one element outside the EURange was accepted";
  EXPECT_EQ(read(analog), (Variant{Array<double>{10.0, 20.0, 30.0}}))
    << to_string(read(analog)) << ": the refused array was stored";

  EXPECT_THAT(write(analog, Variant{Array<double>{15.0, 50.0, 25.0}}), HasStatus(Status::Good))
    << "an array inside the EURange was refused";
  EXPECT_EQ(read(analog), (Variant{Array<double>{15.0, 50.0, 25.0}})) << to_string(read(analog));
}

// @relation(AC-SVR-DA-025-UNKNOWN-LIMIT-UNBOUNDED-ON-WRITE, scope=function)
TEST_F(DataAccessWrite, ANaNEuRangeLimitLeavesThatSideUnbounded)
{
  use_policy(DataAccessOutOfRangePolicy::Reject);
  const auto analog = make_analog(6110,
    NodeId{VariableTypeId::AnalogItemType},
    Variant{double{50.0}},
    0.0,
    std::numeric_limits<double>::quiet_NaN());

  EXPECT_THAT(write(analog, Variant{double{1000.0}}), HasStatus(Status::Good))
    << "an unknown (NaN) high limit bounded the write";
  EXPECT_EQ(read(analog), Variant{double{1000.0}}) << to_string(read(analog));

  EXPECT_THAT(write(analog, Variant{double{-5.0}}), HasStatus(Status::BadOutOfRange))
    << "the known low limit no longer bounds the write";
  EXPECT_EQ(read(analog), Variant{double{1000.0}})
    << to_string(read(analog)) << ": the refused value was stored";
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-ELEMENT-COMPARED-IN-ITS-OWN-TYPE, scope=function)
TEST_F(DataAccessWrite, AClampedArrayKeepsItsInRangeElementsExactly)
{
  use_policy(DataAccessOutOfRangePolicy::Clamp);
  const auto analog = make_analog(6150,
    NodeId{VariableTypeId::AnalogItemType},
    Variant{Array<int64_t>{1, 2}},
    0.0,
    1e19,
    true,
    NodeId{DataTypeId::Int64});

  // 9007199254740993 is 2^53 + 1, which a Double cannot hold.
  const auto status = write(analog, Variant{Array<int64_t>{9007199254740993, -1}});
  EXPECT_TRUE(status.is_good()) << to_string(status) << ": the clamped array was refused";
  EXPECT_EQ(read(analog), (Variant{Array<int64_t>{9007199254740993, 0}}))
    << to_string(read(analog)) << ": the stored array is not the written one with only -1 clamped";
}

// @relation(AC-SVR-DA-007-CLAMPED-WRITE-ANSWERS-GOOD-CLAMPED, scope=function)
TEST_F(DataAccessWrite, AClampedWriteAnswersGoodClamped)
{
  use_policy(DataAccessOutOfRangePolicy::Clamp);
  const auto analog =
    make_analog(6120, NodeId{VariableTypeId::AnalogItemType}, Variant{double{50.0}}, 0.0, 100.0);

  EXPECT_THAT(write(analog, Variant{double{150.0}}), HasStatus(Status::GoodClamped))
    << "a clamped write did not tell the Client its value was changed";
  EXPECT_EQ(read(analog), Variant{double{100.0}}) << to_string(read(analog));

  EXPECT_THAT(write(analog, Variant{double{40.0}}), HasStatus(Status::Good))
    << "a write inside the range was reported as clamped";
  EXPECT_EQ(read(analog), Variant{double{40.0}}) << to_string(read(analog));
}

// @relation(AC-SVR-DA-007-EVERY-BASEANALOGTYPE-INSTANCE-CHECKED, scope=function)
TEST_F(DataAccessWrite, ABaseAnalogTypeInstanceIsRangeChecked)
{
  use_policy(DataAccessOutOfRangePolicy::Reject);
  const auto baseAnalog =
    make_analog(6130, NodeId{VariableTypeId::BaseAnalogType}, Variant{double{50.0}}, 0.0, 100.0);
  const auto analogItem =
    make_analog(6132, NodeId{VariableTypeId::AnalogItemType}, Variant{double{50.0}}, 0.0, 100.0);

  EXPECT_THAT(write(baseAnalog, Variant{double{150.0}}), HasStatus(Status::BadOutOfRange))
    << "a BaseAnalogType instance was not range-checked";
  EXPECT_EQ(read(baseAnalog), Variant{double{50.0}}) << to_string(read(baseAnalog));

  EXPECT_THAT(write(analogItem, Variant{double{150.0}}), HasStatus(Status::BadOutOfRange))
    << "the AnalogItemType control is no longer range-checked";
  EXPECT_EQ(read(analogItem), Variant{double{50.0}}) << to_string(read(analogItem));
}

// @relation(AC-SVR-DA-007-EVERY-BASEANALOGTYPE-INSTANCE-CHECKED, scope=function)
TEST_F(DataAccessWrite, AnAnalogUnitTypeInstanceIsRangeChecked)
{
  use_policy(DataAccessOutOfRangePolicy::Reject);
  const auto analogUnit =
    make_analog(6140, NodeId{VariableTypeId::AnalogUnitType}, Variant{double{50.0}}, 0.0, 100.0);
  const auto analogItem =
    make_analog(6142, NodeId{VariableTypeId::AnalogItemType}, Variant{double{50.0}}, 0.0, 100.0);

  EXPECT_THAT(write(analogUnit, Variant{double{150.0}}), HasStatus(Status::BadOutOfRange))
    << "an AnalogUnitType instance was not range-checked";
  EXPECT_EQ(read(analogUnit), Variant{double{50.0}}) << to_string(read(analogUnit));

  EXPECT_THAT(write(analogItem, Variant{double{150.0}}), HasStatus(Status::BadOutOfRange))
    << "the AnalogItemType control is no longer range-checked";
  EXPECT_EQ(read(analogItem), Variant{double{50.0}}) << to_string(read(analogItem));
}
