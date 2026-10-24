// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The Data Access range rule's type decision, through the Write service. Part 8 section 5.3.2.2 defines
// EURange and InstrumentRange on BaseAnalogType, and section 5.3.2.4 derives AnalogUnitType from
// BaseAnalogType, not from AnalogItemType; NR-58 makes every instance of BaseAnalogType or a subtype
// range-checked. The Write service is driven with a write to an instance on a server whose
// `dataAccessWritePolicy` is Reject.

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <utility>

#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_data_access_utils.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace std::chrono_literals;
using namespace ua;
using namespace ua::server;

namespace
{

class DataAccessWriteInterceptorUnit : public ::testing::Test
{
protected:
  void SetUp() override
  {
    ServerConfig serverConfig;
    serverConfig.dataAccessWritePolicy = write_policy();
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    auto server = Server::create(mThreadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    mSessionInfo = std::make_shared<SessionInfoStub>(std::move(server), mThreadPool.get_executor());
  }

  void TearDown() override
  {
    mSessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// The server's `dataAccessWritePolicy`.
  virtual DataAccessOutOfRangePolicy write_policy() const
  {
    return DataAccessOutOfRangePolicy::Reject;
  }

  AddressSpace address_space() const
  {
    return mSessionInfo->address_space();
  }

  // Gives the Variable @p variableId the InstrumentRange Property {@p low, @p high}.
  void add_instrument_range(const NodeId& variableId, const NodeId& propertyId, double low, double high)
  {
    auto address = address_space();
    auto property = address.create_node_sync(propertyId, NodeClass::Variable);
    property.set_browse_name(QualifiedName{0, "InstrumentRange"});
    auto range = std::make_unique<Range>();
    range->low() = low;
    range->high() = high;
    property.as<VariableAccessor>()->write_value_sync(
      DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    auto variable = address.find_node_sync(variableId);
    variable.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{variableId}, /*isForward=*/false);
  }

  // The Value the Variable @p nodeId holds.
  Variant value_of(const NodeId& nodeId)
  {
    auto found = address_space().try_find_node_sync(nodeId);
    if (!found.is_good())
    {
      ADD_FAILURE() << "the Variable was not found";
      return Variant{};
    }
    auto read = found.value().as<VariableAccessor>()->try_read_value_sync();
    if (!read.is_good())
    {
      ADD_FAILURE() << "the Value was not read";
      return Variant{};
    }
    return read.value().value();
  }

  // A readable and writable Double Variable of @p typeDefinition holding 50.0, with the EURange Property
  // {0, 100}.
  void make_analog(const NodeId& variableId, const NodeId& euRangeId, const NodeId& typeDefinition)
  {
    auto address = address_space();
    auto variable = address.create_node_sync(variableId, NodeClass::Variable);
    variable.set_browse_name(QualifiedName{1, "Analog"});
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    variable.as<VariableAccessor>()->set_access_level(accessLevel);
    variable.as<VariableAccessor>()->set_data_type(NodeId{DataTypeId::Double});
    variable.as<VariableAccessor>()->write_value_sync(double{50.0});
    variable.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeDefinition);

    auto property = address.create_node_sync(euRangeId, NodeClass::Variable);
    property.set_browse_name(QualifiedName{0, "EURange"});
    auto range = std::make_unique<Range>();
    range->low() = 0.0;
    range->high() = 100.0;
    property.as<VariableAccessor>()->write_value_sync(
      DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    variable.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euRangeId);
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{variableId}, /*isForward=*/false);
  }

  // The status the Write service answers for a Value write of @p value to @p nodeId.
  StatusCode write(const NodeId& nodeId, Variant value)
  {
    WriteValue item;
    item.node_id() = nodeId;
    item.attribute_id() = utils::to_underlying(AttributeId::Value);
    item.value().value() = std::move(value);
    WriteRequest request;
    request.request_header().request_handle() = 1;
    request.nodes_to_write().payload().push_back(std::move(item));

    auto promise = std::make_shared<std::promise<StatusCode>>();
    auto future = promise->get_future();
    auto service = AttributeServiceSet::create(mSessionInfo,
      1,
      std::move(request),
      mThreadPool.get_executor(),
      [promise](Response response)
      {
        if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
            writeResponse != nullptr && writeResponse->results().size() == 1)
        {
          promise->set_value(writeResponse->results()[0]);
        }
        else
        {
          promise->set_value(StatusCode{Status::BadInternalError});
        }
      });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the Write did not complete";
      return StatusCode{Status::BadTimeout};
    }
    return future.get();
  }

  boost::asio::thread_pool mThreadPool{2};
  std::shared_ptr<SessionInfoStub> mSessionInfo;
};

}  // namespace

// @relation(AC-SVR-DA-007-EVERY-BASEANALOGTYPE-INSTANCE-CHECKED, scope=function)
TEST_F(DataAccessWriteInterceptorUnit, AnAnalogUnitTypeInstanceIsRangeChecked)
{
  const NodeId analogUnit{1, uint32_t{7200}};
  const NodeId analogItem{1, uint32_t{7210}};
  make_analog(analogUnit, NodeId{1, uint32_t{7201}}, NodeId{VariableTypeId::AnalogUnitType});
  make_analog(analogItem, NodeId{1, uint32_t{7211}}, NodeId{VariableTypeId::AnalogItemType});

  EXPECT_EQ(write(analogUnit, Variant{double{150.0}}).as_status(), Status::BadOutOfRange)
    << "a write outside the EURange of an AnalogUnitType instance was not refused";
  EXPECT_EQ(write(analogUnit, Variant{double{75.0}}).as_status(), Status::Good)
    << "a write inside the EURange of an AnalogUnitType instance was refused";
  EXPECT_EQ(write(analogItem, Variant{double{150.0}}).as_status(), Status::BadOutOfRange)
    << "the AnalogItemType control is no longer range-checked";
}

// NR-59: an analog item's write is bounded by its InstrumentRange when it has one, otherwise by its EURange.
// The value 120 is outside EURange {0, 100} and inside InstrumentRange {-50, 150}: with Reject it is accepted
// on the item that has both. The control is an item with the same EURange and no InstrumentRange, which
// refuses the same value with Bad_OutOfRange; 200, outside the InstrumentRange as well, is refused on both.
// @relation(AC-SVR-DA-007-INSTRUMENT-RANGE-BOUNDS-THE-WRITE-WHEN-PRESENT, scope=function)
TEST_F(DataAccessWriteInterceptorUnit, AWiderInstrumentRangeBoundsTheWriteInsteadOfTheEuRange)
{
  const NodeId withBoth{1, uint32_t{7220}};
  const NodeId euRangeOnly{1, uint32_t{7230}};
  make_analog(withBoth, NodeId{1, uint32_t{7221}}, NodeId{VariableTypeId::AnalogItemType});
  add_instrument_range(withBoth, NodeId{1, uint32_t{7222}}, -50.0, 150.0);
  make_analog(euRangeOnly, NodeId{1, uint32_t{7231}}, NodeId{VariableTypeId::AnalogItemType});

  EXPECT_EQ(write(withBoth, Variant{double{120.0}}).as_status(), Status::Good)
    << "a write inside the InstrumentRange and outside the EURange was refused";
  EXPECT_EQ(write(euRangeOnly, Variant{double{120.0}}).as_status(), Status::BadOutOfRange)
    << "the control: a write outside the EURange of an item without InstrumentRange was not refused";
  EXPECT_EQ(write(withBoth, Variant{double{200.0}}).as_status(), Status::BadOutOfRange)
    << "a write outside the InstrumentRange was not refused";
}

// NR-59: the InstrumentRange bounds the write also when it is narrower than the EURange. The value 90 is
// inside EURange {0, 100} and outside InstrumentRange {20, 80}: it is refused with Bad_OutOfRange, and 50,
// inside both, is accepted.
// @relation(AC-SVR-DA-007-INSTRUMENT-RANGE-BOUNDS-THE-WRITE-WHEN-PRESENT, scope=function)
TEST_F(DataAccessWriteInterceptorUnit, ANarrowerInstrumentRangeBoundsTheWriteInsteadOfTheEuRange)
{
  const NodeId analogItem{1, uint32_t{7240}};
  make_analog(analogItem, NodeId{1, uint32_t{7241}}, NodeId{VariableTypeId::AnalogItemType});
  add_instrument_range(analogItem, NodeId{1, uint32_t{7242}}, 20.0, 80.0);

  EXPECT_EQ(write(analogItem, Variant{double{90.0}}).as_status(), Status::BadOutOfRange)
    << "a write inside the EURange and outside the InstrumentRange was not refused";
  EXPECT_EQ(write(analogItem, Variant{double{50.0}}).as_status(), Status::Good)
    << "a write inside both ranges was refused";
}

namespace
{

class DataAccessWriteClampUnit : public DataAccessWriteInterceptorUnit
{
protected:
  DataAccessOutOfRangePolicy write_policy() const override
  {
    return DataAccessOutOfRangePolicy::Clamp;
  }
};

}  // namespace

// NR-59: dataAccessWritePolicy applies to the bounding range. With Clamp, 200 written to an item with EURange
// {0, 100} and InstrumentRange {-50, 150} is stored as 150, the InstrumentRange's high limit; the control is
// the item without InstrumentRange, which stores 100.
// @relation(AC-SVR-DA-007-THE-POLICY-APPLIES-TO-THE-BOUNDING-RANGE, scope=function)
TEST_F(DataAccessWriteClampUnit, ClampUsesTheInstrumentRangeWhenPresent)
{
  const NodeId withBoth{1, uint32_t{7250}};
  const NodeId euRangeOnly{1, uint32_t{7260}};
  make_analog(withBoth, NodeId{1, uint32_t{7251}}, NodeId{VariableTypeId::AnalogItemType});
  add_instrument_range(withBoth, NodeId{1, uint32_t{7252}}, -50.0, 150.0);
  make_analog(euRangeOnly, NodeId{1, uint32_t{7261}}, NodeId{VariableTypeId::AnalogItemType});

  ASSERT_TRUE(write(withBoth, Variant{double{200.0}}).is_good());
  ASSERT_TRUE(write(euRangeOnly, Variant{double{200.0}}).is_good());

  const auto stored = value_of(withBoth);
  ASSERT_TRUE(stored.is_double());
  EXPECT_EQ(stored.as<double>(), 150.0) << "the write was not clamped to the InstrumentRange";
  const auto control = value_of(euRangeOnly);
  ASSERT_TRUE(control.is_double());
  EXPECT_EQ(control.as<double>(), 100.0) << "the control was not clamped to the EURange";
}

// A write is bounded by a Good range only: an InstrumentRange whose own status is Uncertain does not bound
// it, as a missing one does not, so the EURange bounds it. 120 is outside EURange {0, 100} and inside the
// InstrumentRange {-50, 150}: it is refused with Bad_OutOfRange where the InstrumentRange is Uncertain, and
// accepted on the control, whose InstrumentRange is Good.
// @relation(AC-SVR-DA-007-INSTRUMENT-RANGE-BOUNDS-THE-WRITE-WHEN-PRESENT, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(DataAccessWriteInterceptorUnit, AnInstrumentRangeWhoseOwnStatusIsUncertainDoesNotBoundTheWrite)
{
  const NodeId uncertain{1, uint32_t{7280}};
  const NodeId control{1, uint32_t{7290}};
  make_analog(uncertain, NodeId{1, uint32_t{7281}}, NodeId{VariableTypeId::AnalogItemType});
  add_instrument_range(uncertain, NodeId{1, uint32_t{7282}}, -50.0, 150.0);
  make_analog(control, NodeId{1, uint32_t{7291}}, NodeId{VariableTypeId::AnalogItemType});
  add_instrument_range(control, NodeId{1, uint32_t{7292}}, -50.0, 150.0);
  auto range = std::make_unique<Range>();
  range->low() = -50.0;
  range->high() = 150.0;
  address_space()
    .find_node_sync(NodeId{1, uint32_t{7282}})
    .as<VariableAccessor>()
    ->write_value_sync(DataValue{
      Variant{RefStructure<Structure>{std::move(range)}}, StatusCode{Status::UncertainLastUsableValue}});

  EXPECT_EQ(write(uncertain, Variant{double{120.0}}).as_status(), Status::BadOutOfRange)
    << "an Uncertain InstrumentRange bounded the write in place of the EURange";
  EXPECT_EQ(write(control, Variant{double{120.0}}).as_status(), Status::Good)
    << "the control: a write inside a Good InstrumentRange was refused";
}
