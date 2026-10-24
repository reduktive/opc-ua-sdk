// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for the Write service's Data Access write check (ServerConfig::dataAccessWritePolicy),
/// which enforces the Data Access facet's write semantics generically:
/// AnalogItem values are bounded by EURange/InstrumentRange (reject or clamp), and MultiStateDiscrete
/// indices are bounded by EnumStrings. The DA nodes are created directly in the address space (typed
/// via HasTypeDefinition + their range/enum property), proving the check works off the node's
/// type + properties, not any node-class capability.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_data_access_utils.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_range.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <memory>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

DataValue read_value_of(Session& session, const NodeId& node)
{
  return session.attributes().read_sync(read_value(node)).results()[0];
}

}  // namespace

// Base fixture: creates an AnalogItem (EURange [0,100]) and a MultiStateDiscrete (3 states), then
// sets the Data Access write policy chosen by the derived fixture.
class DataAccessBase : public ComplianceWithNodes
{
protected:
  virtual DataAccessOutOfRangePolicy policy() const
  {
    return DataAccessOutOfRangePolicy::Reject;
  }

  void configure_server_config(ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.dataAccessWritePolicy = policy();
  }

  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};

    // --- AnalogItem (Double) with EURange [0, 100] ---
    mAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6000}};
    auto analogNode = addressSpace.create_node_sync(mAnalogId, NodeClass::Variable);
    auto analog = analogNode.as<VariableAccessor>();
    ASSERT_TRUE(analog.has_value());
    analog->set_browse_name(QualifiedName{mTestNamespaceIndex, "AnalogValue"});
    analog->set_display_name(LocalizedText{"", "AnalogValue"});
    analog->set_data_type(NodeId{DataTypeId::Double});
    analog->set_access_level(readWrite);
    analog->write_value_sync(double{50.0});
    analogNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType});

    auto euRangeId = NodeId{mTestNamespaceIndex, uint32_t{6001}};
    auto euRangeNode = addressSpace.create_node_sync(euRangeId, NodeClass::Variable);
    auto euRange = euRangeNode.as<VariableAccessor>();
    ASSERT_TRUE(euRange.has_value());
    euRange->set_browse_name(QualifiedName{0, "EURange"});
    euRange->set_data_type(NodeId{DataTypeId::Range});
    auto range = std::make_unique<Range>();
    range->low() = 0.0;
    range->high() = 100.0;
    euRange->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    euRangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    analogNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euRangeId);

    // --- MultiStateDiscrete (UInt32) with EnumStrings {Off, Low, High} ---
    mMultiStateId = NodeId{mTestNamespaceIndex, uint32_t{6010}};
    auto msNode = addressSpace.create_node_sync(mMultiStateId, NodeClass::Variable);
    auto multiState = msNode.as<VariableAccessor>();
    ASSERT_TRUE(multiState.has_value());
    multiState->set_browse_name(QualifiedName{mTestNamespaceIndex, "MultiState"});
    multiState->set_display_name(LocalizedText{"", "MultiState"});
    multiState->set_data_type(NodeId{DataTypeId::UInt32});
    multiState->set_access_level(readWrite);
    multiState->write_value_sync(uint32_t{0});
    msNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::MultiStateDiscreteType});

    auto enumStringsId = NodeId{mTestNamespaceIndex, uint32_t{6011}};
    auto enumStringsNode = addressSpace.create_node_sync(enumStringsId, NodeClass::Variable);
    auto enumStrings = enumStringsNode.as<VariableAccessor>();
    ASSERT_TRUE(enumStrings.has_value());
    enumStrings->set_browse_name(QualifiedName{0, "EnumStrings"});
    enumStrings->set_data_type(NodeId{DataTypeId::LocalizedText});
    Array<LocalizedText> states;
    states.push_back(LocalizedText{"", "Off"});
    states.push_back(LocalizedText{"", "Low"});
    states.push_back(LocalizedText{"", "High"});
    enumStrings->write_value_sync(DataValue{Variant{std::move(states)}});
    enumStringsNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    msNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, enumStringsId);
  }

  NodeId mAnalogId;
  NodeId mMultiStateId;
};

// Default policy = Reject (OPC 10000-8 section 5.2).
class DataAccessReject : public DataAccessBase
{};

// Covers SVR-DA-007 (coverage-audit retag).
TEST_F(DataAccessReject, AnalogWriteOutOfRangeRejected)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mAnalogId, Variant{double{150.0}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Bad(Status::BadOutOfRange));
  EXPECT_THAT(read_value_of(*mSession, mAnalogId), good_value_of<double>(50.0));  // unchanged
}

TEST_F(DataAccessReject, AnalogWriteInRangeAccepted)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mAnalogId, Variant{double{75.0}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_THAT(read_value_of(*mSession, mAnalogId), good_value_of<double>(75.0));
}

TEST_F(DataAccessReject, AnalogBoundaryAccepted)
{
  EXPECT_THAT(mSession->attributes()
                .write_sync(WriteRequestBuilder().write(mAnalogId, Variant{double{100.0}}))
                .results()[0],
    Good());
  EXPECT_THAT(read_value_of(*mSession, mAnalogId), good_value_of<double>(100.0));
}

// Covers SVR-DA-011 (coverage-audit retag).
TEST_F(DataAccessReject, MultiStateIndexOutOfRangeRejected)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mMultiStateId, Variant{uint32_t{5}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Bad(Status::BadOutOfRange));
}

TEST_F(DataAccessReject, MultiStateValidIndexAccepted)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mMultiStateId, Variant{uint32_t{2}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_THAT(read_value_of(*mSession, mMultiStateId), good_value_of<uint32_t>(2u));
}

// Clamp policy: out-of-range analog writes are accepted but clamped to the range.
class DataAccessClamp : public DataAccessBase
{
protected:
  DataAccessOutOfRangePolicy policy() const override
  {
    return DataAccessOutOfRangePolicy::Clamp;
  }
};

// @relation(AC-SVR-DA-007-CLAMPED-WRITE-ANSWERS-GOOD-CLAMPED, scope=function)
TEST_F(DataAccessClamp, AnalogWriteAboveRangeClampedToHigh)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mAnalogId, Variant{double{150.0}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::GoodClamped));
  EXPECT_THAT(read_value_of(*mSession, mAnalogId), good_value_of<double>(100.0));
}

// @relation(AC-SVR-DA-007-CLAMPED-WRITE-ANSWERS-GOOD-CLAMPED, scope=function)
TEST_F(DataAccessClamp, AnalogWriteBelowRangeClampedToLow)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mAnalogId, Variant{double{-10.0}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::GoodClamped));
  EXPECT_THAT(read_value_of(*mSession, mAnalogId), good_value_of<double>(0.0));
}
