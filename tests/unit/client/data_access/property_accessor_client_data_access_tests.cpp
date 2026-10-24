// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 DataAccess facade + generic PropertyAccessor (client design section 8.18.1.a /
// .d). Covers the DA Property pre-flight (Browse HasProperty + batched Read of Property Values), the
// typed-value decoding (AnalogItem / TwoStateDiscrete / MultiStateDiscrete / MultiStateValueDiscrete), the
// PercentDeadband filter construction (CL-DA-003..006, J24 reading), the write passthrough (CL-DA-007), the
// dictionary-entry write (CL-DA-012), the verbatim StatusCode / NaN / opaque-Definition pass-throughs
// (CL-DA-013/015/017), and the PropertyAccessor explicit override (CL-AC-022).
//
// The tests drive the real code through the fake upward interface roles (FakeWireOps / FakeSupportOps) with
// no real ConnectionImpl: Property resolution is scripted via browsePages + scriptedReadResponses, and writes
// via writeOutcomes. Handles that need a known Property snapshot are built directly through
// DataAccessClientTestAccess over a hand-populated state (bypassing the async factory).
//
// Falsifiability: an accessor that skips the mandatory-Property preflight fails
// HandleConstructionBadOnMissingMandatoryProperty; one that mis-composes the deadband filter fails the
// PercentDeadband* tests; one that remaps a DA StatusCode fails StatusCodesPassedThroughVerbatim; one that
// parses/rounds a pass-through fails Definition/Range/ValuePrecision; one that mis-resolves the dictionary
// entry fails the MSDE tests; a PropertyAccessor that fails to match a BrowseName fails ReadProperty*.

#include "ua_data_access.h"
#include "ua_property_accessor.h"

#include "fake_connection_ops.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_continuation_point.h"
#include "ua_data_access_state.h"
#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
#include "ua_data_access_test_access.h"
#include "ua_data_value.h"
#include "ua_enum_value_type.h"
#include "ua_eu_information.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_read_response.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_ref_structure.h"
#include "ua_semantic_change_cache.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::AnalogItemHandle;
using ua::client::AnalogItemHandleResult;
using ua::client::AnalogItemValue;
using ua::client::BrowseName;
using ua::client::DataAccessAccessor;
using ua::client::DataValueResult;
using ua::client::MultiStateDiscreteHandleResult;
using ua::client::MultiStateDiscreteValue;
using ua::client::MultiStateValueDiscreteHandleResult;
using ua::client::MultiStateValueDiscreteValue;
using ua::client::PropertyAccessor;
using ua::client::TwoStateDiscreteHandleResult;
using ua::client::TwoStateDiscreteValue;
using ua::client::detail::AnalogItemState;
using ua::client::detail::DataAccessClientTestAccess;
using ua::client::detail::MultiStateDiscreteState;
using ua::client::detail::MultiStateValueDiscreteState;
using ua::test_helpers::FakeSupportOps;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{std::uint16_t{0}, identifier};
}

constexpr std::uint32_t valueAttribute = static_cast<std::uint32_t>(ua::AttributeId::Value);

// ---- value / reference builders ----

ua::DataValue dv_range(double low, double high)
{
  ua::Range range;
  range.low() = low;
  range.high() = high;
  return ua::DataValue{ua::Variant{range}};
}

ua::DataValue dv_eu(std::string namespaceUri)
{
  ua::EUInformation eu;
  eu.namespace_uri() = ua::String{std::move(namespaceUri)};
  return ua::DataValue{ua::Variant{eu}};
}

ua::DataValue dv_double(double value)
{
  return ua::DataValue{ua::Variant{value}};
}

ua::DataValue dv_string(std::string value)
{
  return ua::DataValue{ua::Variant{ua::String{std::move(value)}}};
}

ua::DataValue dv_localized(std::string text)
{
  return ua::DataValue{ua::Variant{ua::LocalizedText{ua::String{std::move(text)}}}};
}

ua::DataValue dv_enum_strings(const std::vector<std::string>& strings)
{
  ua::Array<ua::LocalizedText> array;
  for (const auto& text : strings)
  {
    array.push_back(ua::LocalizedText{ua::String{text}});
  }
  return ua::DataValue{ua::Variant{std::move(array)}};
}

ua::EnumValueType enum_value(std::int64_t value, std::string name)
{
  ua::EnumValueType entry;
  entry.value() = value;
  entry.display_name() = ua::LocalizedText{ua::String{std::move(name)}};
  return entry;
}

ua::DataValue dv_enum_values(const std::vector<std::pair<std::int64_t, std::string>>& entries)
{
  ua::Array<ua::RefStructure<ua::Structure>> array;
  for (const auto& [value, name] : entries)
  {
    array.push_back(
      ua::RefStructure<ua::Structure>{std::make_unique<ua::EnumValueType>(enum_value(value, name))});
  }
  return ua::DataValue{ua::Variant{std::move(array)}};
}

ua::ReferenceDescription prop_ref(std::string_view browseName, std::uint32_t identifier)
{
  ua::ReferenceDescription reference;
  reference.browse_name() = ua::QualifiedName{std::uint16_t{0}, browseName};
  reference.node_id() = ua::ExpandedNodeId{node(identifier)};
  return reference;
}

ua::ReadResponse read_response(std::vector<ua::DataValue> values)
{
  ua::ReadResponse response;
  for (auto& value : values)
  {
    response.results().push_back(std::move(value));
  }
  return response;
}

struct PropSpec
{
  std::string name;
  ua::DataValue value;
};

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> supportOps = std::make_shared<FakeSupportOps>();

  DataAccessAccessor accessor()
  {
    return DataAccessClientTestAccess::make_accessor(wireOps, supportOps, ctx.get_executor());
  }

  PropertyAccessor property(ua::NodeId nodeId)
  {
    return DataAccessClientTestAccess::make_property_accessor(
      std::move(nodeId), wireOps, supportOps, ctx.get_executor());
  }

  void run()
  {
    ctx.run();
    ctx.restart();
  }

  // Scripts one Property resolution: a Browse page whose HasProperty children are @p props (in order), plus
  // the batched Property-Value Read response carrying the same values in the same order. Subsequent
  // scriptedReadResponses (e.g. a Variable Value read) are pushed AFTER this by the caller.
  void script_resolution(std::vector<PropSpec> props)
  {
    FakeWireOps::BrowsePage page;
    std::vector<ua::DataValue> values;
    std::uint32_t identifier = 6000;
    for (auto& spec : props)
    {
      page.references.push_back(prop_ref(spec.name, identifier++));
      values.push_back(std::move(spec.value));
    }
    wireOps->browsePages.push_back(std::move(page));
    wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{read_response(std::move(values))});
  }

  // Pushes the next scripted Read response (e.g. the Variable Value read a handle read issues).
  void script_read(std::vector<ua::DataValue> values)
  {
    wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{read_response(std::move(values))});
  }

  // Publishes @p props as a handle state's immutable resolved-Property snapshot (mirrors the production
  // publish_properties atomic swap): the DA typed handles now hold their resolved Properties in
  // DataAccessHandleBase::resolvedProperties, not as loose per-type fields (H2 / section 8.18.2).
  static void set_resolved(
    ua::client::detail::DataAccessHandleBase& state, ua::client::detail::ResolvedProperties props)
  {
    state.resolvedProperties.store(
      std::make_shared<const ua::client::detail::ResolvedProperties>(std::move(props)));
  }

  // Hand-builds an AnalogItemState over the fake interfaces so filter/write/read paths run against a known
  // Property snapshot without going through the async factory.
  std::shared_ptr<AnalogItemState> analog_state(ua::NodeId nodeId, std::optional<ua::Range> euRange)
  {
    auto state = std::make_shared<AnalogItemState>();
    state->wireOps = wireOps;
    state->supportOps = supportOps;
    state->executor = ctx.get_executor();
    state->nodeId = std::move(nodeId);
    ua::client::detail::ResolvedProperties props;
    if (euRange)
    {
      props.emplace("EURange", ua::DataValue{ua::Variant{*euRange}});
    }
    set_resolved(*state, std::move(props));
    return state;
  }

  std::shared_ptr<MultiStateDiscreteState> msd_state(ua::NodeId nodeId, std::vector<std::string> strings)
  {
    auto state = std::make_shared<MultiStateDiscreteState>();
    state->wireOps = wireOps;
    state->supportOps = supportOps;
    state->executor = ctx.get_executor();
    state->nodeId = std::move(nodeId);
    ua::client::detail::ResolvedProperties props;
    props.emplace("EnumStrings", dv_enum_strings(strings));
    set_resolved(*state, std::move(props));
    return state;
  }

  std::shared_ptr<MultiStateValueDiscreteState> msvd_state(
    ua::NodeId nodeId, std::vector<std::pair<std::int64_t, std::string>> entries)
  {
    auto state = std::make_shared<MultiStateValueDiscreteState>();
    state->wireOps = wireOps;
    state->supportOps = supportOps;
    state->executor = ctx.get_executor();
    state->nodeId = std::move(nodeId);
    ua::client::detail::ResolvedProperties props;
    props.emplace("EnumValues", dv_enum_values(entries));
    set_resolved(*state, std::move(props));
    return state;
  }

  // Hand-builds a MultiStateValueDiscreteState for a MultiStateDictionaryEntryDiscreteBaseType (CL-DA-012):
  // EnumValues plus a 2-D (@p states x @p dictionaries) EnumDictionaryEntries NodeId table, flattened
  // row-major (element [s][d] == @p flatEntries[s * dictionaries + d]). This is the cached snapshot the
  // spec-correct write_via_dictionary_async selects from - dim0 is the state (enum-value) index, dim1 is the
  // dictionary index (OPC 10000-19 section 7.1).
  std::shared_ptr<MultiStateValueDiscreteState> msde_state(ua::NodeId nodeId,
    std::vector<std::pair<std::int64_t, std::string>> entries, std::size_t states, std::size_t dictionaries,
    const std::vector<ua::NodeId>& flatEntries)
  {
    auto state = std::make_shared<MultiStateValueDiscreteState>();
    state->wireOps = wireOps;
    state->supportOps = supportOps;
    state->executor = ctx.get_executor();
    state->nodeId = std::move(nodeId);
    ua::client::detail::ResolvedProperties props;
    props.emplace("EnumValues", dv_enum_values(entries));
    ua::Array<ua::NodeId> table(
      ua::Dimensions{static_cast<std::int32_t>(states), static_cast<std::int32_t>(dictionaries)},
      flatEntries);
    props.emplace("EnumDictionaryEntries", ua::DataValue{ua::Variant{std::move(table)}});
    set_resolved(*state, std::move(props));
    return state;
  }

  // Runs analog_item_async against the currently-scripted resolution and returns the handle Result.
  AnalogItemHandleResult build_analog(ua::NodeId nodeId)
  {
    std::optional<AnalogItemHandleResult> captured;
    accessor().analog_item_async(
      std::move(nodeId), [&captured](AnalogItemHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }

  // Runs base_analog_async against the currently-scripted resolution and returns the handle Result.
  AnalogItemHandleResult build_base_analog(ua::NodeId nodeId)
  {
    std::optional<AnalogItemHandleResult> captured;
    accessor().base_analog_async(
      std::move(nodeId), [&captured](AnalogItemHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }

  // Runs analog_unit_async against the currently-scripted resolution and returns the handle Result.
  AnalogItemHandleResult build_analog_unit(ua::NodeId nodeId)
  {
    std::optional<AnalogItemHandleResult> captured;
    accessor().analog_unit_async(
      std::move(nodeId), [&captured](AnalogItemHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }

  // Runs analog_unit_range_async against the currently-scripted resolution and returns the handle Result.
  AnalogItemHandleResult build_analog_unit_range(ua::NodeId nodeId)
  {
    std::optional<AnalogItemHandleResult> captured;
    accessor().analog_unit_range_async(
      std::move(nodeId), [&captured](AnalogItemHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }
};

// ===========================================================================
// DataAccessAccessor - Property pre-flight resolution (CL-DA-001)
// ===========================================================================

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, AnalogItemResolvesMandatoryPropertiesAndComposesBrowse)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}, {"EngineeringUnits", dv_eu("http://units")}});

  AnalogItemHandleResult result = f.build_analog(node(10));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().node_id(), node(10));

  // The pre-flight Browse targets the Variable NodeId with a forward HasProperty reference.
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  const auto& description = f.wireOps->browseRequests[0].nodes_to_browse()[0];
  EXPECT_EQ(description.node_id(), node(10));
  EXPECT_EQ(
    description.reference_type_id(), (ua::NodeId{std::uint16_t{0}, ua::ReferenceTypeId::HasProperty}));
  EXPECT_EQ(description.browse_direction(), ua::BrowseDirection::Forward);

  // The matched Property Values are Read in one batched Read of the two matched child NodeIds' Value attr.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 2U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].attribute_id(), valueAttribute);
}

// Matrix row ClientDataAccess.BaseAnalogHandleSucceedsWithNoOptionalProperties (unit half): BaseAnalogType
// has NO Mandatory Property, so base_analog_async resolves a usable AnalogItemHandle even when the node
// exposes NONE of the Optional analog Properties. This is exactly the case analog_item_async REJECTS
// (Mandatory EURange absent), so the distinguishing assertion is: the SAME empty resolution that fails
// analog_item_async succeeds here. Falsifiable: were base_analog to require EURange (apply_analog), the
// empty-resolution handle would be Bad. @verifies CL-DA-001
TEST(ClientDataAccessResolution, BaseAnalogHandleSucceedsWithNoOptionalProperties)
{
  Fixture f;
  f.script_resolution({});  // a BaseAnalogType node exposing none of the Optional Properties

  AnalogItemHandleResult result = f.build_base_analog(node(20));
  ASSERT_TRUE(result.is_good())
    << "BaseAnalogType has no Mandatory Property, so the handle must resolve with no Properties present";
  EXPECT_EQ(result.value().node_id(), node(20));

  // Cross-check the discriminator: the identical empty resolution FAILS analog_item_async (EURange
  // Mandatory).
  Fixture g;
  g.script_resolution({});
  EXPECT_TRUE(g.build_analog(node(20)).is_bad())
    << "analog_item_async must still reject the same empty resolution (Mandatory EURange), proving "
       "base_analog_async's relaxation is real";
}

// BaseAnalogType still surfaces whatever Optional Properties the node DOES expose (EURange here), so a
// caller reading e.g. euRange() off the handle sees the resolved value. @verifies CL-DA-001
TEST(ClientDataAccessResolution, BaseAnalogHandlePublishesOptionalPropertiesWhenPresent)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(-5.0, 5.0)}});

  AnalogItemHandleResult result = f.build_base_analog(node(21));
  ASSERT_TRUE(result.is_good());
  // One matched Property child (EURange) is Read; the base-shape browse targets HasProperty like analog_item.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 1U);
}

// AnalogUnitType (OPC 10000-8 section 5.3.2.4) mandates ONLY EngineeringUnits; EURange is Optional (it
// derives from BaseAnalogType, not AnalogItemType). So analog_unit_async succeeds with EngineeringUnits
// present and NO EURange, and fails when EngineeringUnits is absent even though EURange resolves. The
// discriminators guard both edges: analog_item_async (EURange Mandatory) would REJECT the
// EURange-less-but-EU-bearing node, and ACCEPT the EU-less-but-EURange-bearing node - exactly opposite to
// analog_unit_async. @verifies CL-DA-001
TEST(ClientDataAccessResolution, AnalogUnitHandleRequiresEngineeringUnitsNotEuRange)
{
  Fixture f;
  // EngineeringUnits present, EURange ABSENT - the AnalogUnitType Mandatory shape.
  f.script_resolution({{"EngineeringUnits", dv_eu("http://units")}});
  EXPECT_TRUE(f.build_analog_unit(node(30)).is_good())
    << "AnalogUnitType mandates EngineeringUnits, NOT EURange; this must resolve";

  Fixture disc;
  disc.script_resolution({{"EngineeringUnits", dv_eu("http://units")}});
  EXPECT_TRUE(disc.build_analog(node(30)).is_bad())
    << "analog_item_async requires EURange, so the same EURange-less node must fail it (discriminator)";
}

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, AnalogUnitHandleBadWhenEngineeringUnitsMissing)
{
  Fixture f;
  // EURange present but the (type-)Mandatory EngineeringUnits absent.
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  EXPECT_TRUE(f.build_analog_unit(node(31)).is_bad())
    << "AnalogUnitType must reject a node lacking its Mandatory EngineeringUnits";

  Fixture disc;
  disc.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  EXPECT_TRUE(disc.build_analog(node(31)).is_good())
    << "analog_item_async accepts the EURange-only node (EngineeringUnits Optional) - discriminator";
}

// AnalogUnitRangeType (OPC 10000-8 section 5.3.2.5) mandates BOTH EURange and EngineeringUnits, so it fails
// on EITHER missing and succeeds only when both resolve. @verifies CL-DA-001
TEST(ClientDataAccessResolution, AnalogUnitRangeHandleRequiresBothEuRangeAndEngineeringUnits)
{
  {
    Fixture f;
    f.script_resolution({{"EURange", dv_range(0.0, 100.0)}, {"EngineeringUnits", dv_eu("http://units")}});
    EXPECT_TRUE(f.build_analog_unit_range(node(40)).is_good()) << "both Mandatory Properties present -> good";
  }
  {
    Fixture f;  // EURange absent
    f.script_resolution({{"EngineeringUnits", dv_eu("http://units")}});
    EXPECT_TRUE(f.build_analog_unit_range(node(41)).is_bad()) << "EURange absent -> bad";
  }
  {
    Fixture f;  // EngineeringUnits absent
    f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
    EXPECT_TRUE(f.build_analog_unit_range(node(42)).is_bad()) << "EngineeringUnits absent -> bad";
  }
}

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, HandleConstructionBadOnMissingMandatoryProperty)
{
  Fixture f;
  // A page with only Definition - the Mandatory EURange for AnalogItemType is absent.
  f.script_resolution({{"Definition", dv_string("opaque")}});

  AnalogItemHandleResult result = f.build_analog(node(11));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNotFound);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// Matrix row ClientDataAccess.AnalogItemHandleBadWhenEuRangeMissing (unit half): the factory pre-flight
// rejects an AnalogItemType node whose Mandatory EURange is absent EVEN WHEN other (Optional) analog
// Properties resolve - proving the gate keys on EURange specifically, not merely "some Property present".
// (Distinct from HandleConstructionBadOnMissingMandatoryProperty, whose page carries only a non-analog
// Definition child.) @verifies CL-DA-001
TEST(ClientDataAccessResolution, AnalogItemHandleBadWhenEuRangeMissing)
{
  Fixture f;
  // EngineeringUnits + InstrumentRange resolve (both Optional for AnalogItemType), but the Mandatory EURange
  // is absent.
  f.script_resolution(
    {{"EngineeringUnits", dv_eu("http://units")}, {"InstrumentRange", dv_range(-5.0, 5.0)}});

  AnalogItemHandleResult result = f.build_analog(node(50));
  ASSERT_TRUE(result.is_bad())
    << "the Mandatory-EURange gate must fire even when Optional analog Properties are present";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNotFound);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, AnalogItemResolvesAcrossBrowseNextPagination)
{
  Fixture f;
  // Page 1 returns a non-mandatory Property child and a non-empty continuation point (the mandatory EURange
  // is withheld to page 2); page 2 (delivered via BrowseNext) returns EURange with an empty continuation
  // point. The handle must page via BrowseNext and still resolve the mandatory EURange.
  FakeWireOps::BrowsePage page1;
  page1.references.push_back(prop_ref("EngineeringUnits", 6000));
  page1.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x01}}};
  f.wireOps->browsePages.push_back(std::move(page1));
  FakeWireOps::BrowsePage page2;
  page2.references.push_back(prop_ref("EURange", 6001));  // mandatory, only reachable on page 2
  f.wireOps->browsePages.push_back(std::move(page2));
  // The batched Property-Value Read is answered in accumulated match order: [EngineeringUnits, EURange].
  f.script_read({dv_eu("http://units"), dv_range(0.0, 100.0)});

  AnalogItemHandleResult handle = f.build_analog(node(15));
  ASSERT_TRUE(handle.is_good());  // EURange resolved despite living on page 2 -> pagination worked
  EXPECT_FALSE(f.wireOps->browseNextRequests.empty());  // a BrowseNext was issued to fetch page 2

  f.script_read({dv_double(7.0)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->euRange.has_value());
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 100.0);
  ASSERT_TRUE(captured->engineeringUnits.has_value());
}

// @verifies AC-CL-DA-001-MANDATORY-BEFORE-TYPED
// @relation(AC-CL-DA-001-MANDATORY-BEFORE-TYPED, scope=function)
TEST(ClientDataAccessResolution, HandleConstructionBadOnReadResultCountMismatch)
{
  Fixture f;
  // The Browse matches one Property child (EURange) so the batched Read sends one ReadValueId; the server
  // over-returns (two DataValues). Positionally stitching would silently mis-map; the SDK must reject the
  // count mismatch rather than trust alignment.
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  f.wireOps->resultsPerReadDelta = 1;  // over-return one DataValue vs ReadValueIds sent

  AnalogItemHandleResult result = f.build_analog(node(16));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, FactoryFailsWhenConnectionGone)
{
  Fixture f;
  f.wireOps.reset();  // the wire interface weak-ref expires -> the lock fails

  std::optional<AnalogItemHandleResult> captured;
  f.accessor().analog_item_async(
    node(12), [&captured](AnalogItemHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.connection_closed");
}

// ===========================================================================
// AnalogItemHandle - CL-DA-010 SemanticChange auto re-resolve
// ===========================================================================
//
// The DataAccess handle registers its Property snapshot with the per-Connection SemanticChangeCache at
// construction. When that NodeId is invalidated (the in-band SemanticsChanged bit / a SemanticChangeEventType
// - both deferred to W8; here driven directly via SemanticChangeCache::invalidate_async), the next read must
// RE-RESOLVE the Properties (a second Browse + Property Read) BEFORE the Value read, and surface the fresh
// Property values. These tests count the browse/read calls so the re-resolve is falsifiable - not just
// is_good.

// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST(ClientDataAccessSemanticChange, ReadReResolvesPropertiesWhenInvalidated)
{
  Fixture f;
  auto cache = ua::client::detail::SemanticChangeCache::create(
    boost::asio::make_strand(f.ctx.get_executor()), ua::Logger{});
  f.supportOps->semanticChangeCache = cache;

  // Build the handle (registers with the cache) - EURange resolves to 0..100.
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(30));
  ASSERT_TRUE(handle.is_good());
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);  // one resolution Browse at construction
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);  // one Property Read at construction

  // Invalidate this NodeId (the real trigger - SemanticsChanged bit / SemanticChangeEventType - is deferred
  // to W8; W2a drives invalidate_async directly).
  cache->invalidate_async({node(30)});
  f.run();

  // Script the re-resolve (Browse + Property Read: EURange now 0..200) followed by the Value Read.
  f.script_resolution({{"EURange", dv_range(0.0, 200.0)}});
  f.script_read({dv_double(50.0)});

  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  // Falsifiable: the invalidated read RE-RESOLVED - a second Browse (HasProperty) + a batched Property Read
  // happened BEFORE the Value Read, so the browse count grew by 1 and the read count grew by 2.
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2U) << "the invalidated read must re-browse the Properties";
  EXPECT_EQ(f.wireOps->readRequests.size(), 3U) << "re-resolve Property Read + the Value Read";
  // The freshly-resolved Property value is visible in the delivered handle value.
  ASSERT_TRUE(captured->euRange.has_value());
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 200.0);
  EXPECT_DOUBLE_EQ(captured->value.value().to<double>().value(), 50.0);

  // A SECOND read (flag now cleared) must NOT re-resolve again.
  f.script_read({dv_double(51.0)});
  std::optional<AnalogItemValue> second;
  handle.value().read_async([&second](ua::Result<AnalogItemValue> r) { second = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2U) << "the flag was cleared - no further re-browse";
  EXPECT_EQ(f.wireOps->readRequests.size(), 4U) << "only the Value Read for the second read";
}

// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST(ClientDataAccessSemanticChange, ReadDoesNotReResolveWhenNotInvalidated)
{
  Fixture f;
  auto cache = ua::client::detail::SemanticChangeCache::create(
    boost::asio::make_strand(f.ctx.get_executor()), ua::Logger{});
  f.supportOps->semanticChangeCache = cache;

  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(31));
  ASSERT_TRUE(handle.is_good());
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);

  f.script_read({dv_double(7.0)});  // only the Value Read (no invalidation -> no re-resolve)
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 1U) << "a non-invalidated read must NOT re-browse";
  EXPECT_EQ(f.wireOps->readRequests.size(), 2U) << "only the Value Read";
  ASSERT_TRUE(captured->euRange.has_value());
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 100.0) << "the original Property snapshot is unchanged";
}

// The handle build still works when the Connection has NO SemanticChangeCache (a gone/absent cache): the
// Ticket stays empty and reads never re-resolve - the manual refresh path is unaffected. @verifies CL-DA-010
TEST(ClientDataAccessSemanticChange, HandleBuildsWithoutCacheAndReadsNormally)
{
  Fixture f;  // supportOps->semanticChangeCache left null; supportOps->executor unset -> getter returns null
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(32));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(3.0)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 1U) << "no cache -> no auto re-resolve path engaged";
  EXPECT_DOUBLE_EQ(captured->value.value().to<double>().value(), 3.0);
}

// H1 - an invalidation that RACES the re-resolve window must NOT be lost. The read clears the invalidation
// flag at the START of the re-resolve (not after it completes); a change landing during the re-resolve
// re-sets it, so the next read re-resolves again. Under the old "clear after re-resolve" the raced change was
// swallowed and a stale snapshot served. @verifies CL-DA-010
TEST(ClientDataAccessSemanticChange, InvalidateDuringReResolveIsNotLost)
{
  Fixture f;
  auto state = f.analog_state(node(36), ua::Range{});  // resolved EURange snapshot present
  auto handle = ua::client::detail::DataAccessClientTestAccess::make_analog_handle(state);
  state->invalidated.store(true);  // a prior semantic change flagged the handle

  // Interpose: when the re-resolve Property Read is served (the FIRST read after arming), a NEW semantic
  // change lands and re-sets the flag - the deterministic stand-in for an invalidate that races the
  // re-resolve window (SemanticChangeCache::invalidate_on_strand does exactly this `store(true)`).
  bool armed = true;
  f.wireOps->onReadServed = [&]
  {
    if (armed)
    {
      armed = false;
      state->invalidated.store(true);
    }
  };
  f.script_resolution({{"EURange", dv_range(0.0, 200.0)}});  // first re-resolve
  f.script_read({dv_double(1.0)});  // the Value read
  std::optional<AnalogItemValue> first;
  handle.read_async([&first](ua::Result<AnalogItemValue> r) { first = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(first.has_value());
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);  // one re-resolve browse so far
  EXPECT_TRUE(state->invalidated.load()) << "the change that raced the re-resolve must survive";

  // A SUBSEQUENT read must re-resolve AGAIN (a second browse) because the raced change is still pending.
  // Under the buggy end-of-re-resolve clear the flag would have been cleared and this read would skip
  // re-resolution.
  f.script_resolution({{"EURange", dv_range(0.0, 300.0)}});
  f.script_read({dv_double(2.0)});
  std::optional<AnalogItemValue> second;
  handle.read_async([&second](ua::Result<AnalogItemValue> r) { second = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2U)
    << "the raced invalidation must not be lost - the next read must re-resolve again";
  ASSERT_TRUE(second->euRange.has_value());
  EXPECT_DOUBLE_EQ(second->euRange->high(), 300.0);
}

// M1 - a semantic change that lands DURING handle construction (between the resolve snapshot and the
// registration) must not be lost: the handle registers with the cache BEFORE the construction resolve, so the
// change flips the flag and the FIRST read re-resolves. Under the old register-after-resolve the change was
// dropped (the entry did not yet exist). @verifies CL-DA-010
TEST(ClientDataAccessSemanticChange, ChangeDuringConstructionReResolvesOnFirstRead)
{
  Fixture f;
  auto cache = ua::client::detail::SemanticChangeCache::create(
    boost::asio::make_strand(f.ctx.get_executor()), ua::Logger{});
  f.supportOps->semanticChangeCache = cache;

  // Interpose: when the CONSTRUCTION Property Read is served, invalidate this NodeId. Because the handle is
  // registered with the cache BEFORE the construction resolve is issued (M1), the registration insert is
  // posted to the cache strand ahead of this invalidate, so the entry exists when the invalidate runs and its
  // flag is flipped. (Register-after-resolve would post the insert AFTER this invalidate, which would find no
  // entry and drop the change.)
  bool armed = true;
  f.wireOps->onReadServed = [&]
  {
    if (armed)
    {
      armed = false;
      cache->invalidate_async({node(35)});
    }
  };
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(35));
  ASSERT_TRUE(handle.is_good());
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);  // one construction browse

  // The construction-time change flipped the flag: the FIRST read must re-resolve (a second browse).
  f.script_resolution({{"EURange", dv_range(0.0, 250.0)}});
  f.script_read({dv_double(9.0)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2U)
    << "a change during construction must re-resolve on the first read (register-before-resolve)";
  ASSERT_TRUE(captured->euRange.has_value());
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 250.0);
}

// W1(a) - an invalidated read whose re-resolve Browse fails surfaces Bad (with the resolve source), leaves
// the handle invalidated for retry, and a LATER (healthy) read re-resolves and succeeds. @verifies CL-DA-010
TEST(ClientDataAccessSemanticChange, ReResolveBrowseFailureKeepsInvalidatedForRetry)
{
  Fixture f;
  auto state = f.analog_state(node(37), ua::Range{});
  auto handle = ua::client::detail::DataAccessClientTestAccess::make_analog_handle(state);
  state->invalidated.store(true);

  f.wireOps->browseServiceStatus =
    ua::StatusCode{ua::Status::BadServerNotConnected};  // re-resolve Browse fails
  std::optional<ua::Result<AnalogItemValue>> firstResult;
  handle.read_async([&firstResult](ua::Result<AnalogItemValue> r) { firstResult = std::move(r); });
  f.run();
  ASSERT_TRUE(firstResult.has_value());
  ASSERT_TRUE(firstResult->is_bad());
  EXPECT_EQ(firstResult->status_code().as_status(), ua::Status::BadServerNotConnected);
  ASSERT_NE(firstResult->shared_detail(), nullptr);
  EXPECT_EQ(firstResult->shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
  EXPECT_TRUE(state->invalidated.load()) << "a failed re-resolve must leave the handle invalidated for retry";

  // A later read re-resolves again (flag still set) and, with the Browse now healthy, succeeds.
  f.wireOps->browseServiceStatus = ua::StatusCode{ua::Status::Good};
  f.script_resolution({{"EURange", dv_range(0.0, 250.0)}});
  f.script_read({dv_double(9.0)});
  std::optional<AnalogItemValue> retry;
  handle.read_async([&retry](ua::Result<AnalogItemValue> r) { retry = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(retry.has_value());
  ASSERT_TRUE(retry->euRange.has_value());
  EXPECT_DOUBLE_EQ(retry->euRange->high(), 250.0);
  EXPECT_FALSE(state->invalidated.load()) << "the successful re-resolve cleared the flag";
}

// W1(b) - an invalidated read whose re-resolve no longer surfaces the Mandatory Property yields Bad_NotFound,
// delivers NO stale value (no Value read is issued), and leaves the handle invalidated. @verifies CL-DA-010
TEST(ClientDataAccessSemanticChange, ReResolveMandatoryVanishedYieldsBadNotFoundNoStaleValue)
{
  Fixture f;
  auto state = f.analog_state(node(38), ua::Range{});
  auto handle = ua::client::detail::DataAccessClientTestAccess::make_analog_handle(state);
  state->invalidated.store(true);

  // The re-resolve Browse/Read no longer surfaces the Mandatory EURange (only Definition).
  f.script_resolution({{"Definition", dv_string("opaque")}});
  std::optional<ua::Result<AnalogItemValue>> result;
  handle.read_async([&result](ua::Result<AnalogItemValue> r) { result = std::move(r); });
  f.run();
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_status(), ua::Status::BadNotFound);
  ASSERT_NE(result->shared_detail(), nullptr);
  EXPECT_EQ(result->shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
  EXPECT_TRUE(state->invalidated.load()) << "a vanished Mandatory Property leaves the handle invalidated";
  // Only the re-resolve Property Read ran (Definition child) - NO Variable Value read, so no stale value
  // could be delivered.
  EXPECT_EQ(f.wireOps->readRequests.size(), 1U) << "no Value read after a failed re-resolve (no stale value)";
}

// ===========================================================================
// AnalogItemHandle - typed read combines Value + resolved Properties
// ===========================================================================

// @verifies CL-DA-016
// @relation(CL-DA-016, scope=function)
TEST(ClientDataAccessAnalog, EuRangeAndInstrumentRangeAreDistinctAndBothRead)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}, {"InstrumentRange", dv_range(-50.0, 250.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(20));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(42.0)});  // the Variable Value read
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->euRange.has_value());
  ASSERT_TRUE(captured->instrumentRange.has_value());
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 100.0);
  EXPECT_DOUBLE_EQ(captured->instrumentRange->high(), 250.0);
  EXPECT_NE(captured->euRange->low(), captured->instrumentRange->low());
}

// @verifies CL-DA-014
// @relation(CL-DA-014, scope=function)
TEST(ClientDataAccessAnalog, EngineeringUnitsNamespaceUriPassthrough)
{
  Fixture f;
  f.script_resolution(
    {{"EURange", dv_range(0.0, 10.0)}, {"EngineeringUnits", dv_eu("http://unece.example/units")}});
  AnalogItemHandleResult handle = f.build_analog(node(21));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(1.0)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->engineeringUnits.has_value());
  EXPECT_EQ(
    static_cast<std::string>(captured->engineeringUnits->namespace_uri()), "http://unece.example/units");
}

// The control arm of AC-CL-DA-014. Its sibling asserts one namespaceUri survives, which an accessor
// returning that one constant would also satisfy. This run differs in exactly one variable - the
// namespaceUri the EngineeringUnits Property carries - and the surfaced value must move with it.
// @verifies CL-DA-014
// @relation(CL-DA-014, scope=function)
TEST(ClientDataAccessAnalog, EngineeringUnitsNamespaceUriIsPerNodeNotAConstant)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 10.0)}, {"EngineeringUnits", dv_eu("urn:vendor:private")}});
  AnalogItemHandleResult handle = f.build_analog(node(23));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(1.0)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->engineeringUnits.has_value());
  EXPECT_EQ(static_cast<std::string>(captured->engineeringUnits->namespace_uri()), "urn:vendor:private")
    << "the accessor must surface this node's namespaceUri, not the one its sibling test scripts";
}

// @verifies CL-DA-017
// @relation(CL-DA-017, scope=function)
TEST(ClientDataAccessAnalog, DefinitionPropertyIsOpaqueStringPassthrough)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"Definition", dv_string("VENDOR::opaque::blob")}});
  AnalogItemHandleResult handle = f.build_analog(node(22));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(0.5)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->definition.has_value());
  EXPECT_EQ(*captured->definition, "VENDOR::opaque::blob");
}

// The control arm of AC-CL-DA-017. Truncation is one of the three behaviours that criterion prohibits, and
// a 20-character Definition cannot probe it: any cap above that length passes the sibling. This run differs
// from it in exactly one variable - the length of the Definition the Property carries - and asserts the
// surfaced string is the same length as the scripted one, so any cap at all reddens it.
// @verifies CL-DA-017
// @relation(CL-DA-017, scope=function)
TEST(ClientDataAccessAnalog, LongDefinitionPropertyIsSurfacedWholeNotTruncated)
{
  Fixture f;
  // Long enough to sit above every plausible internal buffer bound, and self-describing at both ends so a
  // truncation that kept a prefix is distinguishable from one that kept a suffix.
  std::string longDefinition = "HEAD::";
  longDefinition.append(8192, 'x');
  longDefinition += "::TAIL";

  f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"Definition", dv_string(longDefinition)}});
  AnalogItemHandleResult handle = f.build_analog(node(24));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(0.5)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->definition.has_value());
  EXPECT_EQ(captured->definition->size(), longDefinition.size())
    << "Definition must be surfaced whole; a shorter string here is a truncation";
  EXPECT_EQ(*captured->definition, longDefinition);
}

// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST(ClientDataAccessAnalog, ValuePrecisionSurfacedInHandleNotApplied)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"ValuePrecision", dv_double(3.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(23));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(0.123456)});  // not rounded to the precision bound
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->valuePrecision.has_value());
  EXPECT_EQ(*captured->valuePrecision, std::int16_t{3});
  // The Value is surfaced verbatim - the precision bound is informational, not applied.
  EXPECT_DOUBLE_EQ(captured->value.value().to<double>().value(), 0.123456);
}

// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST(ClientDataAccessAnalog, ValuePrecisionNanLeavesNulloptNoUndefinedCast)
{
  Fixture f;
  const double nan = std::numeric_limits<double>::quiet_NaN();
  // A server-controlled NaN ValuePrecision must NOT be narrowed to int16 ([conv.fpint] is UB for NaN):
  // the SDK guards the cast and leaves the optional empty.
  f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"ValuePrecision", dv_double(nan)}});
  AnalogItemHandleResult handle = f.build_analog(node(27));
  ASSERT_TRUE(handle.is_good());  // NaN ValuePrecision does not fail construction; EURange still resolves

  f.script_read({dv_double(0.5)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_FALSE(captured->valuePrecision.has_value());  // guarded: NaN -> nullopt, no UB narrowing
}

// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST(ClientDataAccessAnalog, ValuePrecisionOutOfInt16RangeLeavesNulloptNoUndefinedCast)
{
  Fixture f;
  // A ValuePrecision outside [INT16_MIN, INT16_MAX] is likewise UB to narrow ([conv.fpint]): leave nullopt.
  f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"ValuePrecision", dv_double(1e30)}});
  AnalogItemHandleResult handle = f.build_analog(node(28));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(0.5)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_FALSE(captured->valuePrecision.has_value());  // out of int16 range -> nullopt, no UB narrowing
}

// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST(ClientDataAccessAnalog, ValuePrecisionInInt16RangeStillSurfaced)
{
  Fixture f;
  // The guard must not reject a valid, in-range value (negative endpoint checked too).
  f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"ValuePrecision", dv_double(-4.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(29));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(0.5)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->valuePrecision.has_value());
  EXPECT_EQ(*captured->valuePrecision, std::int16_t{-4});
}

// Matrix row ClientDataAccess.ValuePrecisionNegativeRoundedToWhole (unit half). CL-DA-002 (Part 8
// section 5.3.1): ValuePrecision "shall always be interpreted as a whole number by rounding it to the nearest
// whole number." extract_value_precision rounds the finite, in-int16 server Double to the nearest whole
// number (std::rint = round-half-to-even, Banker's - the matrix's strengthened tie oracle), NOT truncation
// toward zero. This pins the FRACTIONAL rounding across positive / negative / half-value inputs, which the
// whole-value tests (ValuePrecisionInInt16RangeStillSurfaced -4.0 -> {-4},
// ValuePrecisionSurfacedInHandleNotApplied 3.0 -> {3}) do not exercise.
//
// Falsifiable against truncation-toward-zero (would give 1.5 -> 1, -1.6 -> -1, -2.7 -> -2), round-half-UP
// (2.5 -> 3), and floor (-1.4 -> -2, 1.5 -> 1). The ties (0.5 -> 0, 1.5 -> 2, 2.5 -> 2) pin
// round-half-to-EVEN specifically. @verifies CL-DA-002
TEST(ClientDataAccessAnalog, ValuePrecisionRoundsToNearestWholeNumber)
{
  struct RoundingCase
  {
    double precision;
    std::int16_t expected;
  };

  for (const RoundingCase testCase : {RoundingCase{0.5, 0},  // tie -> nearest even (0)
         RoundingCase{1.5, 2},  // tie -> nearest even (2)
         RoundingCase{2.5, 2},  // tie -> nearest even (2)
         RoundingCase{-1.0, -1},  // whole
         RoundingCase{-1.4, -1},  // nearer -1
         RoundingCase{-1.6, -2},  // nearer -2
         RoundingCase{-2.7, -3}})  // nearer -3
  {
    Fixture f;  // fresh fixture per input so the scripted resolution/read do not bleed across iterations
    f.script_resolution({{"EURange", dv_range(0.0, 1.0)}, {"ValuePrecision", dv_double(testCase.precision)}});
    AnalogItemHandleResult handle = f.build_analog(node(60));
    ASSERT_TRUE(handle.is_good()) << "precision=" << testCase.precision;

    f.script_read({dv_double(0.5)});
    std::optional<AnalogItemValue> captured;
    handle.value().read_async(
      [&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
    f.run();

    ASSERT_TRUE(captured.has_value()) << "precision=" << testCase.precision;
    ASSERT_TRUE(captured->valuePrecision.has_value()) << "precision=" << testCase.precision;
    EXPECT_EQ(*captured->valuePrecision, testCase.expected)
      << "ValuePrecision " << testCase.precision << " must round to the nearest whole number "
      << testCase.expected << " (round-half-to-even), per Part 8 section 5.3.1";
  }
}

// @verifies CL-DA-013
// @relation(CL-DA-013, scope=function)
TEST(ClientDataAccessAnalog, RangeNanPassesThroughAsNan)
{
  Fixture f;
  const double nan = std::numeric_limits<double>::quiet_NaN();
  f.script_resolution({{"EURange", dv_range(nan, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(24));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(1.0)});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->euRange.has_value());
  EXPECT_TRUE(std::isnan(captured->euRange->low()));
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 100.0);
}

// Part 8 section 5.6.2: "If a limit is not known a NaN shall be used." NaN is the conforming encoding of an
// unknown Range limit, not a malformed Range - yet every defensive reflex destroys it: validating `low <=
// high` (false for NaN) and rejecting, clamping the bound to 0 or a double extreme, or dropping the Property
// altogether all turn a legal server response into an error the caller cannot distinguish from a real
// failure. The percent-deadband consumer is the arm that breaks first (a band derived from a NaN bound is
// NaN); it must decline the filter rather than make the read behind it fail. Both bounds of both Range-typed
// Properties (EURange.Low, InstrumentRange.High) carry a NaN here, so a one-sided guard cannot pass.
// @verifies AC-CL-DA-013-RANGE-NAN
TEST(ClientDataAccessAnalog, NanRangeLimitIsSurfacedAsUnknownNotAsAReadFailure)
{
  Fixture f;
  const double nan = std::numeric_limits<double>::quiet_NaN();
  f.script_resolution({{"EURange", dv_range(nan, 100.0)}, {"InstrumentRange", dv_range(-50.0, nan)}});

  AnalogItemHandleResult handle = f.build_analog(node(27));
  ASSERT_TRUE(handle.is_good())
    << "a NaN limit means 'limit unknown'; the Mandatory-EURange pre-flight must accept it";

  f.script_read({dv_double(42.0)});
  std::optional<ua::Result<AnalogItemValue>> captured;
  EXPECT_NO_THROW(
    handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); }));
  EXPECT_NO_THROW(f.run());  // the typed decode runs here: no exception may escape the NaN bounds

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << "an unknown limit is not a read failure";
  const AnalogItemValue& value = captured->value();
  ASSERT_TRUE(value.euRange.has_value()) << "the Range Property must still be surfaced, not dropped";
  EXPECT_TRUE(std::isnan(value.euRange->low())) << "EURange.Low must arrive as NaN - no substitute value";
  EXPECT_DOUBLE_EQ(value.euRange->high(), 100.0) << "the known bound is untouched";
  ASSERT_TRUE(value.instrumentRange.has_value());
  EXPECT_TRUE(std::isnan(value.instrumentRange->high()))
    << "InstrumentRange.High must arrive as NaN - the unknown bound may be either end of either Range";
  EXPECT_DOUBLE_EQ(value.instrumentRange->low(), -50.0);

  // The consumer that would break: whatever the deadband arm decides, it must never emit a Good filter
  // carrying a NaN band derived from the unknown bound, and it must not latch a failure onto the handle.
  const ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(10.0);
  EXPECT_FALSE(filter.is_good() && std::isnan(filter.value().deadband_value()))
    << "a deadband derived from a NaN bound must be declined, not emitted as a Good NaN filter";

  // The read is still not reported as a failure after the NaN has passed through the deadband consumer.
  f.script_read({dv_double(43.0)});
  std::optional<ua::Result<AnalogItemValue>> second;
  handle.value().read_async([&second](ua::Result<AnalogItemValue> r) { second = std::move(r); });
  f.run();
  ASSERT_TRUE(second.has_value());
  ASSERT_TRUE(second->is_good()) << "the unknown limit must not latch a failure on the handle";
  ASSERT_TRUE(second->value().euRange.has_value());
  EXPECT_TRUE(std::isnan(second->value().euRange->low()));
}

// @verifies CL-DA-015
// @relation(CL-DA-015, scope=function)
TEST(ClientDataAccessAnalog, StatusCodesPassedThroughVerbatim)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(25), ua::Range{}));
  // A DA-specific quality StatusCode: the read SUCCEEDS but the *value* is out of service.
  f.script_read({ua::DataValue{ua::Variant{7.0}, ua::StatusCode{ua::Status::BadOutOfService}}});

  std::optional<ua::Result<AnalogItemValue>> captured;
  handle.read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());  // the read itself succeeded; the *state* is what is bad
  ASSERT_TRUE(captured->value().value.status().has_value());
  EXPECT_EQ(captured->value().value.status()->as_status(), ua::Status::BadOutOfService);  // not remapped
}

// @verifies CL-DA-009
// @relation(CL-DA-009, scope=function)
TEST(ClientDataAccessAnalog, ArrayPropertiesAreScalarNotPerElement)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(26));
  ASSERT_TRUE(handle.is_good());

  // The Variable Value is an array; the DA Property (euRange) stays a single scalar optional.
  ua::Array<double> array;
  array.push_back(1.0);
  array.push_back(2.0);
  f.script_read({ua::DataValue{ua::Variant{std::move(array)}}});
  std::optional<AnalogItemValue> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->value.value().is_array());  // the Value is per-element
  ASSERT_TRUE(captured->euRange.has_value());  // the Property is a single scalar, not split per element
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 100.0);
}

// ===========================================================================
// AnalogItemHandle::make_percent_deadband_filter (CL-DA-003..006, J24)
// ===========================================================================

// @verifies AC-CL-DA-003-PERCENT-OF-EURANGE
// @relation(AC-CL-DA-003-PERCENT-OF-EURANGE, scope=function)
TEST(ClientDataAccessDeadband, BuildsPercentDeadbandFilterWhenEuRangePresent)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(30), ua::Range{}));

  ua::Result<ua::DataChangeFilter> filter = handle.make_percent_deadband_filter(10.0);
  ASSERT_TRUE(filter.is_good());
  // The wire carries PercentDeadband; the SDK does not translate to an absolute band locally.
  EXPECT_EQ(filter.value().deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Percent));
  EXPECT_DOUBLE_EQ(filter.value().deadband_value(), 10.0);
  EXPECT_EQ(filter.value().trigger(), ua::DataChangeTrigger::StatusValue);
}

// @verifies CL-DA-004
// @relation(CL-DA-004, scope=function)
TEST(ClientDataAccessDeadband, PercentOutOfRangeRejectedLocally)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(31), ua::Range{}));

  for (double percent : {-0.1, 100.1, 250.0})
  {
    ua::Result<ua::DataChangeFilter> filter = handle.make_percent_deadband_filter(percent);
    ASSERT_TRUE(filter.is_bad()) << "percent=" << percent;
    EXPECT_EQ(filter.status_code().as_status(), ua::Status::BadDeadbandFilterInvalid);
    ASSERT_NE(filter.shared_detail(), nullptr);
    EXPECT_EQ(filter.shared_detail()->source, "client.tier2.data_access.percent_deadband");
  }
}

// @verifies CL-DA-004
// @relation(CL-DA-004, scope=function)
TEST(ClientDataAccessDeadband, PercentNanRejectedLocally)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(34), ua::Range{}));

  // NaN slips past a naive `percent < 0 || percent > 100` check (both comparisons are false for NaN); the
  // SDK must reject it explicitly rather than emit a Good filter carrying a NaN deadband.
  ua::Result<ua::DataChangeFilter> filter =
    handle.make_percent_deadband_filter(std::numeric_limits<double>::quiet_NaN());
  ASSERT_TRUE(filter.is_bad());
  EXPECT_EQ(filter.status_code().as_status(), ua::Status::BadDeadbandFilterInvalid);
  ASSERT_NE(filter.shared_detail(), nullptr);
  EXPECT_EQ(filter.shared_detail()->source, "client.tier2.data_access.percent_deadband");
}

// @verifies CL-DA-004
// @relation(CL-DA-004, scope=function)
TEST(ClientDataAccessDeadband, BoundaryPercentsAreAccepted)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(35), ua::Range{}));

  // The endpoints 0 and 100 are inclusive (CL-DA-004: outside [0, 100] is rejected).
  for (double percent : {0.0, 100.0})
  {
    ua::Result<ua::DataChangeFilter> filter = handle.make_percent_deadband_filter(percent);
    ASSERT_TRUE(filter.is_good()) << "percent=" << percent;
    EXPECT_EQ(filter.value().deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Percent));
    EXPECT_DOUBLE_EQ(filter.value().deadband_value(), percent);
  }
}

// @verifies CL-DA-005
// @relation(CL-DA-005, scope=function)
TEST(ClientDataAccessDeadband, RequiresEuRangeElseFilterNotAllowed)
{
  Fixture f;
  // euRange ABSENT (built directly, bypassing the factory's mandatory check).
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(32), std::nullopt));

  ua::Result<ua::DataChangeFilter> filter = handle.make_percent_deadband_filter(5.0);
  ASSERT_TRUE(filter.is_bad());
  EXPECT_EQ(filter.status_code().as_status(), ua::Status::BadFilterNotAllowed);
  ASSERT_NE(filter.shared_detail(), nullptr);
  EXPECT_EQ(
    filter.shared_detail()->summary, "EURange Property is required for PercentDeadband but is absent");
}

// @verifies CL-DA-006
// @relation(CL-DA-006, scope=function)
TEST(ClientDataAccessDeadband, ArrayVariableUsesOneUnsplitFilter)
{
  Fixture f;
  // Build a real resolved handle then drive it through an actual array-Value read, so the test genuinely
  // exercises the array path (a scalar-only handle could not catch a per-element split regression).
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(33));
  ASSERT_TRUE(handle.is_good());

  ua::Array<double> array;
  array.push_back(1.0);
  array.push_back(2.0);
  array.push_back(3.0);
  f.script_read({ua::DataValue{ua::Variant{std::move(array)}}});
  std::optional<AnalogItemValue> readback;
  handle.value().read_async([&readback](ua::Result<AnalogItemValue> r) { readback = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(readback.has_value());
  EXPECT_TRUE(readback->value.value().is_array());  // the Value really is a multi-element array

  // For an array Variable the same single filter is used - the SDK does not split per element: one filter
  // carries the scalar percent, and the server applies it per element.
  ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(2.5);
  ASSERT_TRUE(filter.is_good());
  EXPECT_EQ(filter.value().deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Percent));
  EXPECT_DOUBLE_EQ(filter.value().deadband_value(), 2.5);
}

// ===========================================================================
// Write passthrough (CL-DA-007)
// ===========================================================================

// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST(ClientDataAccessWrite, WritePassesThroughAndComposesValueWrite)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(40), ua::Range{}));

  std::optional<ua::VoidResult> captured;
  handle.write_value_async(ua::Variant{3.14}, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->writeRequests.size(), 1U);
  const auto& writeValue = f.wireOps->writeRequests[0].nodes_to_write()[0];
  EXPECT_EQ(writeValue.node_id(), node(40));
  EXPECT_EQ(writeValue.attribute_id(), valueAttribute);
  EXPECT_DOUBLE_EQ(writeValue.value().value().to<double>().value(), 3.14);
}

// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST(ClientDataAccessWrite, ServerRejectOrClampSurfacesVerbatimWithSource)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(41), ua::Range{}));
  f.wireOps->writeOutcomes.push_back(ua::StatusCode{ua::Status::BadOutOfRange});  // server rejects verbatim

  std::optional<ua::VoidResult> captured;
  handle.write_value_async(ua::Variant{999.0}, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadOutOfRange);  // server status verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.write");
}

// ===========================================================================
// refresh_properties (CL-DA-010 manual path)
// ===========================================================================

// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST(ClientDataAccessRefresh, RefreshReResolvesPropertiesVisibleAcrossHandleCopies)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(70));
  ASSERT_TRUE(handle.is_good());
  AnalogItemHandle copy = handle.value();  // a copy shares the resolved-Property snapshot

  // A refresh re-resolves the Properties with a NEW EURange; the shared snapshot is replaced in place.
  f.script_resolution({{"EURange", dv_range(-10.0, 250.0)}});
  std::optional<ua::VoidResult> refreshed;
  handle.value().refresh_properties_async([&refreshed](ua::VoidResult r) { refreshed = std::move(r); });
  f.run();
  ASSERT_TRUE(refreshed.has_value());
  ASSERT_TRUE(refreshed->is_good());

  // The COPY sees the refreshed Property values (shared state).
  f.script_read({dv_double(1.0)});
  std::optional<AnalogItemValue> captured;
  copy.read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r).value(); });
  f.run();
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->euRange.has_value());
  EXPECT_DOUBLE_EQ(captured->euRange->low(), -10.0);
  EXPECT_DOUBLE_EQ(captured->euRange->high(), 250.0);
}

// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST(ClientDataAccessRefresh, RefreshBadWhenMandatoryPropertyVanishes)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)}});
  AnalogItemHandleResult handle = f.build_analog(node(71));
  ASSERT_TRUE(handle.is_good());

  // A refresh whose Browse/Read no longer surfaces the Mandatory EURange must be reported Bad_NotFound
  // (mirroring construction), not silently delivered Good.
  f.script_resolution({{"Definition", dv_string("opaque")}});  // EURange gone
  std::optional<ua::VoidResult> refreshed;
  handle.value().refresh_properties_async([&refreshed](ua::VoidResult r) { refreshed = std::move(r); });
  f.run();

  ASSERT_TRUE(refreshed.has_value());
  ASSERT_TRUE(refreshed->is_bad());
  EXPECT_EQ(refreshed->status_code().as_status(), ua::Status::BadNotFound);
  ASSERT_NE(refreshed->shared_detail(), nullptr);
  EXPECT_EQ(refreshed->shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// ===========================================================================
// Handle op negative paths (gone interface / service failure)
// ===========================================================================

// @verifies CL-DA-015
// @relation(CL-DA-015, scope=function)
TEST(ClientDataAccessNegative, ReadOnGoneWireOpsReturnsConnectionClosed)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(72), ua::Range{}));
  f.wireOps.reset();  // the wire interface weak-ref expires before the read is issued

  std::optional<ua::Result<AnalogItemValue>> captured;
  handle.read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.connection_closed");
}

// @verifies CL-DA-015
// @verifies CL-DIAG-003
// @relation(CL-DA-015, CL-DIAG-003, scope=function)
TEST(ClientDataAccessNegative, ReadServiceBadSurfacedWithReadSource)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(73), ua::Range{}));
  f.wireOps->readStatus = ua::StatusCode{ua::Status::BadOutOfService};  // the Read service call itself fails

  std::optional<ua::Result<AnalogItemValue>> captured;
  handle.read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadOutOfService);  // status verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.read");
}

// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST(ClientDataAccessNegative, WriteValueOnGoneWireOpsReturnsConnectionClosed)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(74), ua::Range{}));
  f.wireOps.reset();

  std::optional<ua::VoidResult> captured;
  handle.write_value_async(ua::Variant{1.0}, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.connection_closed");
}

// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST(ClientDataAccessNegative, WriteViaDictionaryOnGoneWireOpsReturnsConnectionClosed)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msvd_state(node(75), {{1, "Low"}, {2, "High"}}));
  f.wireOps.reset();

  std::optional<ua::VoidResult> captured;
  handle.write_via_dictionary_async(0, 0, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.connection_closed");
}

// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST(ClientDataAccessNegative, WriteViaDictionaryServiceFailSurfacesResolveSource)
{
  Fixture f;
  // A 2x1 EnumDictionaryEntries table so the (0,0) index passes the LOCAL bounds check and reaches the wire.
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msde_state(node(76), {{1, "Low"}, {2, "High"}}, 2, 1, {node(900), node(901)}));
  // The ValueAsDictionaryEntries Property-resolution Browse fails at the service level; no write is issued.
  f.wireOps->browseServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected};

  std::optional<ua::VoidResult> captured;
  handle.write_via_dictionary_async(0, 0, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadServerNotConnected);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.write_via_dictionary");
  EXPECT_TRUE(f.wireOps->writeRequests.empty());  // resolution failed -> no write issued
}

// ===========================================================================
// serviceResult FLATTEN facades (error_handling.md): the wire funnel returns each response VERBATIM, so a
// bad ResponseHeader.serviceResult (a service-level fault, e.g. Bad_TooManyOperations / Bad_SessionIdInvalid)
// with an empty results[] must surface as the true service status + a source-tagged ErrorDetail - never be
// masked by the empty-results / count-mismatch branch as Bad_UnexpectedError.
// ===========================================================================

// read_value_and_decode (every *Handle::read_async): an empty-results service fault must NOT mask as
// DataAccessReadEmpty (Bad_UnexpectedError).
// @verifies CL-DA-015
// @relation(CL-DA-015, scope=function)
TEST(ClientDataAccessNegative, ReadValueFlattensBadServiceResult)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(80), ua::Range{}));
  ua::ReadResponse response;  // empty results[]
  response.response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

  std::optional<ua::Result<AnalogItemValue>> captured;
  handle.read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad()) << "a bad serviceResult must surface, not be masked as Bad_UnexpectedError";
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "DataAccessReadServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.read");
}

// do_write_value (every *Handle::write_value_async): an empty-results service fault must NOT mask as
// DataAccessWriteEmpty (Bad_UnexpectedError).
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST(ClientDataAccessNegative, WriteValueFlattensBadServiceResult)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(81), ua::Range{}));
  f.wireOps->writeHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->writeResultsDelta = -1;  // single-node write -> zero results (the empty service-fault shape)

  std::optional<ua::VoidResult> captured;
  handle.write_value_async(ua::Variant{1.0}, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad()) << "a bad serviceResult must surface, not be masked as Bad_UnexpectedError";
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "DataAccessWriteServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.write");
}

// do_write_node_value (write_via_dictionary_async ValueAsDictionaryEntries Write): an empty-results service
// fault on the dictionary Write must NOT mask as DataAccessWriteEmpty (Bad_UnexpectedError); it surfaces the
// true service status under the write_via_dictionary source (do_write_node_value threads the source through).
// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST(ClientDataAccessNegative, WriteViaDictionaryWriteFlattensBadServiceResult)
{
  Fixture f;
  // A 1x1 EnumDictionaryEntries table so the (0,0) index resolves + reaches the ValueAsDictionaryEntries
  // Write.
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msde_state(node(85), {{1, "Low"}, {2, "High"}}, 1, 1, {node(910)}));
  // The one-level HasProperty Browse of the Variable matches "ValueAsDictionaryEntries" -> node(755) ...
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("ValueAsDictionaryEntries", 755));
  f.wireOps->browsePages.push_back(std::move(page));
  // ... but the Write returns a Good-transport response whose SERVICE result is bad, with empty results[].
  f.wireOps->writeHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->writeResultsDelta = -1;  // single-node write -> zero results (the empty service-fault shape)

  std::optional<ua::VoidResult> captured;
  handle.write_via_dictionary_async(0, 0, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad()) << "a bad serviceResult must surface, not be masked as Bad_UnexpectedError";
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "DataAccessWriteServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.write_via_dictionary");
}

// resolve_properties (batched Property-Value Read during construction): an empty-values service fault must
// NOT mask as DataAccessPropertyReadCountMismatch (Bad_UnexpectedError).
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, PropertyReadFlattensBadServiceResult)
{
  Fixture f;
  // The Browse matches one Property child (EURange) so the batched Read sends one ReadValueId ...
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("EURange", 6000));
  f.wireOps->browsePages.push_back(std::move(page));
  // ... but the Read returns a Good-transport response whose SERVICE result is bad, with empty values[].
  ua::ReadResponse response;
  response.response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

  AnalogItemHandleResult result = f.build_analog(node(82));
  ASSERT_TRUE(result.is_bad())
    << "a bad serviceResult must surface, not be masked as a count-mismatch Bad_UnexpectedError";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DataAccessPropertyReadServiceFault");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// browse_property_children (HasProperty Browse during construction): an empty-results service fault must NOT
// mask as DataAccessPropertyBrowseEmpty (Bad_UnexpectedError).
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, PropertyBrowseFlattensBadServiceResult)
{
  Fixture f;
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->browseOmitResults = true;  // Good-transport response with empty results[] (service-fault shape)

  AnalogItemHandleResult result = f.build_analog(node(83));
  ASSERT_TRUE(result.is_bad()) << "a bad serviceResult must surface, not be masked as Bad_UnexpectedError";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DataAccessPropertyBrowseServiceFault");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// drain_property_children (continuation BrowseNext during construction): an empty-results service fault on a
// continuation page must NOT mask as DataAccessPropertyBrowseNextEmpty (Bad_UnexpectedError).
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, PropertyBrowseNextFlattensBadServiceResult)
{
  Fixture f;
  // Page 1 returns a child AND a non-empty continuation point, forcing a BrowseNext to drain page 2 ...
  FakeWireOps::BrowsePage page1;
  page1.references.push_back(prop_ref("EngineeringUnits", 6000));
  page1.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x01}}};
  f.wireOps->browsePages.push_back(std::move(page1));
  // ... but the BrowseNext returns a Good-transport response whose SERVICE result is bad, empty results[].
  f.wireOps->browseNextHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->browseNextOmitResults = true;

  AnalogItemHandleResult result = f.build_analog(node(84));
  ASSERT_FALSE(f.wireOps->browseNextRequests.empty()) << "a BrowseNext must have been issued to drain page 2";
  ASSERT_TRUE(result.is_bad())
    << "a bad BrowseNext serviceResult must surface, not be masked as Bad_UnexpectedError";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTooManyOperations);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DataAccessPropertyBrowseNextServiceFault");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// A server that answers every BrowseNext with the same continuation point and no references would keep the
// resolution draining forever. Ten empty pages in a row are asked again (a server may stop early with nothing
// to show); the eleventh ends the drain with Bad_Timeout (public API review D1, API-D1.4) and the point is
// released.
TEST(ClientDataAccessResolution, PropertyBrowseNextEmptyPagesBeyondTheLimitEndTheDrain)
{
  Fixture f;
  FakeWireOps::BrowsePage page1;
  page1.references.push_back(prop_ref("EngineeringUnits", 6000));
  page1.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x01}}};
  f.wireOps->browsePages.push_back(std::move(page1));
  FakeWireOps::BrowsePage looping;  // the same point, no references
  looping.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x01}}};
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->browsePages.push_back(looping);
  }

  AnalogItemHandleResult result = f.build_analog(node(84));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BrowseDrainEmptyPageLimitExceeded");
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 12U)
    << "eleven reads, then one release of the point the server still holds";
}

// ===========================================================================
// MultiStateDiscrete - currentName in/out of enum range (CL-DA-008)
// ===========================================================================

// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST(ClientDataAccessMultiStateDiscrete, ValueInsideEnumYieldsCurrentName)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_multi_state_discrete_handle(
    f.msd_state(node(50), {"Off", "Low", "High"}));
  f.script_read({ua::DataValue{ua::Variant{std::uint32_t{1}}}});

  std::optional<MultiStateDiscreteValue> captured;
  handle.read_async([&captured](ua::Result<MultiStateDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->rawIndex, 1U);
  ASSERT_TRUE(captured->currentName.has_value());
  EXPECT_EQ(static_cast<std::string>(captured->currentName->text()), "Low");
}

// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST(ClientDataAccessMultiStateDiscrete, ValueOutsideEnumYieldsNulloptNameButSurfacesRawIndex)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_multi_state_discrete_handle(
    f.msd_state(node(51), {"Off", "Low", "High"}));
  f.script_read({ua::DataValue{ua::Variant{std::uint32_t{5}}}});  // out of [0,3)

  std::optional<MultiStateDiscreteValue> captured;
  handle.read_async([&captured](ua::Result<MultiStateDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->rawIndex, 5U);  // always surfaced
  EXPECT_FALSE(captured->currentName.has_value());  // out of range -> nullopt
}

// Matrix row ClientDataAccess.MultiStateEmptyEnumStringYieldsEmptyNotMissing (unit half): an IN-range
// rawIndex pointing at an enumStrings entry whose Text is EMPTY must surface currentName.has_value()==true
// carrying an EMPTY LocalizedText - the present-empty case, DISTINCT from the out-of-range nullopt case above
// (ValueOutsideEnumYieldsNulloptNameButSurfacesRawIndex). Conflating empty text with absent (=> nullopt)
// would lose the in-range/out-of-range distinction (CTT DA/Basic/Err-004-02). @verifies CL-DA-008
TEST(ClientDataAccessMultiStateDiscrete, EmptyEnumStringInRangeYieldsPresentEmptyName)
{
  Fixture f;
  // enumStrings[1] is a present-but-empty LocalizedText; the read selects index 1 (in range).
  auto handle =
    DataAccessClientTestAccess::make_multi_state_discrete_handle(f.msd_state(node(52), {"Off", "", "High"}));
  f.script_read({ua::DataValue{ua::Variant{std::uint32_t{1}}}});

  std::optional<MultiStateDiscreteValue> captured;
  handle.read_async([&captured](ua::Result<MultiStateDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->rawIndex, 1U);
  ASSERT_TRUE(captured->currentName.has_value())
    << "an in-range index with empty text is present-empty, NOT the out-of-range nullopt case";
  EXPECT_TRUE(captured->currentName->text().empty())
    << "the in-range empty enum string surfaces as an EMPTY LocalizedText, distinct from absent (nullopt)";
}

// ===========================================================================
// MultiStateValueDiscrete - currentName match + write_via_dictionary (CL-DA-008/012)
// ===========================================================================

// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST(ClientDataAccessMultiStateValue, ValueMatchingEnumYieldsName)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msvd_state(node(60), {{1, "Low"}, {2, "High"}}));
  f.script_read({ua::DataValue{ua::Variant{std::int64_t{2}}}});

  std::optional<MultiStateValueDiscreteValue> captured;
  handle.read_async(
    [&captured](ua::Result<MultiStateValueDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->rawValue, 2);
  ASSERT_TRUE(captured->currentName.has_value());
  EXPECT_EQ(static_cast<std::string>(captured->currentName->text()), "High");
}

// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST(ClientDataAccessMultiStateValue, ValueMatchingNoEnumYieldsNulloptName)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msvd_state(node(61), {{1, "Low"}, {2, "High"}}));
  f.script_read({ua::DataValue{ua::Variant{std::int64_t{99}}}});

  std::optional<MultiStateValueDiscreteValue> captured;
  handle.read_async(
    [&captured](ua::Result<MultiStateValueDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->rawValue, 99);  // always surfaced
  EXPECT_FALSE(captured->currentName.has_value());
}

// CL-DA-012 spec-correct write (OPC 10000-19 section 7.1): write_via_dictionary_async selects the declared
// EnumDictionaryEntries[state][dictionary] NodeId from the cached 2-D table and Writes it (as a
// single-element NodeId[]) to the resolved ValueAsDictionaryEntries Property node's Value attribute - NOT an
// integer to the Variable's own Value. Falsifiable: the pre-fix behaviour (integer-to-Value) targets the
// Variable node and carries an Int64, both asserted against here.
// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST(ClientDataAccessMultiStateValue, client_da_msde_dbt_write_uses_declared_entry)
{
  Fixture f;
  // A 3-state x 2-dictionary EnumDictionaryEntries table, flattened row-major: element [s][d] is
  // node(800 + s * 2 + d), so [1][0] == node(802).
  const std::vector<ua::NodeId> flat{node(800), node(801), node(802), node(803), node(804), node(805)};
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msde_state(node(62), {{1, "Low"}, {2, "High"}, {3, "Running"}}, 3, 2, flat));
  // The one-level HasProperty Browse of the Variable resolves the ValueAsDictionaryEntries child ->
  // node(760).
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("ValueAsDictionaryEntries", 760));
  f.wireOps->browsePages.push_back(std::move(page));

  std::optional<ua::VoidResult> captured;
  handle.write_via_dictionary_async(1, 0, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  // The Variable was Browsed one level for its HasProperty children (to resolve ValueAsDictionaryEntries) ...
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->browseRequests[0].nodes_to_browse()[0].node_id(), node(62));
  EXPECT_EQ(f.wireOps->browseRequests[0].nodes_to_browse()[0].reference_type_id(),
    (ua::NodeId{std::uint16_t{0}, ua::ReferenceTypeId::HasProperty}));
  // ... and NO child Value Read is issued (the entry NodeId comes from the cached table, not a Read).
  EXPECT_TRUE(f.wireOps->readRequests.empty());
  // The Write targets the resolved ValueAsDictionaryEntries PROPERTY node (node 760), NOT the Variable (62).
  ASSERT_EQ(f.wireOps->writeRequests.size(), 1U);
  const auto& writeValue = f.wireOps->writeRequests[0].nodes_to_write()[0];
  EXPECT_EQ(writeValue.node_id(), node(760));
  EXPECT_EQ(writeValue.attribute_id(), valueAttribute);
  // The payload is a single-element NodeId[] carrying EnumDictionaryEntries[1][0] == node(802).
  auto written = writeValue.value().value().to_vector<ua::NodeId>();
  ASSERT_TRUE(written.is_good()) << "the dictionary write must carry a NodeId[] payload, not an integer";
  ASSERT_EQ(written.value().size(), 1U);
  EXPECT_EQ(written.value()[0], node(802));
}

// CL-DA-012 negative: an out-of-range state_index (5, table has only 3 states) is rejected LOCALLY against
// the cached EnumDictionaryEntries bounds - a Bad VoidResult under the write_via_dictionary source, and ZERO
// wire requests (no Browse, no Write). Falsifiable: the pre-fix behaviour issued a Value Write regardless of
// index.
// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST(ClientDataAccessMultiStateValue, client_da_msde_dbt_write_rejects_unknown_entry)
{
  Fixture f;
  const std::vector<ua::NodeId> flat{node(800), node(801), node(802), node(803), node(804), node(805)};
  auto handle = DataAccessClientTestAccess::make_multi_state_value_handle(
    f.msde_state(node(63), {{1, "Low"}, {2, "High"}, {3, "Running"}}, 3, 2, flat));

  std::optional<ua::VoidResult> captured;
  handle.write_via_dictionary_async(5, 0, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.data_access.write_via_dictionary");
  // The strong "no wire request" clause: an out-of-bounds index touches the wire for NOTHING.
  EXPECT_TRUE(f.wireOps->writeRequests.empty()) << "an out-of-range index must issue ZERO Write requests";
  EXPECT_TRUE(f.wireOps->browseRequests.empty()) << "an out-of-range index must issue ZERO Browse requests";
}

// ===========================================================================
// Factory-driven resolution for the remaining typed handles (decoders under the async pre-flight)
// ===========================================================================

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, TwoStateDiscreteResolvesTrueFalseStateAndDecodesBoolean)
{
  Fixture f;
  f.script_resolution({{"TrueState", dv_localized("On")}, {"FalseState", dv_localized("Off")}});

  std::optional<TwoStateDiscreteHandleResult> built;
  f.accessor().two_state_discrete_async(
    node(90), [&built](TwoStateDiscreteHandleResult r) { built = std::move(r); });
  f.run();
  ASSERT_TRUE(built.has_value());
  ASSERT_TRUE(built->is_good());

  f.script_read({ua::DataValue{ua::Variant{true}}});
  std::optional<TwoStateDiscreteValue> captured;
  built->value().read_async(
    [&captured](ua::Result<TwoStateDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->state);
  EXPECT_EQ(static_cast<std::string>(captured->trueState.text()), "On");
  EXPECT_EQ(static_cast<std::string>(captured->falseState.text()), "Off");
}

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, MultiStateDiscreteResolvesEnumStringsUnderPreflight)
{
  Fixture f;
  f.script_resolution({{"EnumStrings", dv_enum_strings({"Off", "Low", "High"})}});

  std::optional<MultiStateDiscreteHandleResult> built;
  f.accessor().multi_state_discrete_async(
    node(91), [&built](MultiStateDiscreteHandleResult r) { built = std::move(r); });
  f.run();
  ASSERT_TRUE(built.has_value());
  ASSERT_TRUE(built->is_good());

  f.script_read({ua::DataValue{ua::Variant{std::uint32_t{2}}}});
  std::optional<MultiStateDiscreteValue> captured;
  built->value().read_async(
    [&captured](ua::Result<MultiStateDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_EQ(captured->enumStrings.size(), 3U);
  EXPECT_EQ(captured->rawIndex, 2U);
  ASSERT_TRUE(captured->currentName.has_value());
  EXPECT_EQ(static_cast<std::string>(captured->currentName->text()), "High");
}

// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST(ClientDataAccessResolution, MultiStateValueResolvesEnumValuesUnderPreflight)
{
  Fixture f;
  f.script_resolution({{"EnumValues", dv_enum_values({{10, "Ten"}, {20, "Twenty"}})},
    {"ValueAsText", dv_localized("Twenty")}});  // ValueAsText is also Mandatory (CL-DA-001)

  std::optional<MultiStateValueDiscreteHandleResult> built;
  f.accessor().multi_state_value_discrete_async(
    node(92), [&built](MultiStateValueDiscreteHandleResult r) { built = std::move(r); });
  f.run();
  ASSERT_TRUE(built.has_value());
  ASSERT_TRUE(built->is_good());

  f.script_read({ua::DataValue{ua::Variant{std::int64_t{20}}}});
  std::optional<MultiStateValueDiscreteValue> captured;
  built->value().read_async(
    [&captured](ua::Result<MultiStateValueDiscreteValue> r) { captured = std::move(r).value(); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_EQ(captured->enumValues.size(), 2U);  // decode_enum_values decoded both ExtensionObjects
  EXPECT_EQ(captured->rawValue, 20);
  ASSERT_TRUE(captured->currentName.has_value());
  EXPECT_EQ(static_cast<std::string>(captured->currentName->text()), "Twenty");
}

// MultiStateDictionaryEntryDiscreteBaseType (OPC 10000-19 section 7.1) mandates EnumDictionaryEntries on top
// of the inherited MSVD EnumValues, so multi_state_dictionary_entry_async rejects a node lacking
// EnumDictionaryEntries EVEN WHEN EnumValues resolves - exactly the case multi_state_value_discrete_async
// ACCEPTS (it enforces only EnumValues). The discriminator (the same EnumValues-only resolution succeeds
// through the MSVD accessor) proves the EnumDictionaryEntries gate is real. @verifies CL-DA-001
TEST(ClientDataAccessResolution, MsdeDbtRequiresEnumDictionaryEntriesOnTopOfEnumValues)
{
  const ua::DataValue dictEntries{ua::Variant{ua::NodeId{std::uint16_t{0}, std::uint32_t{99}}}};
  const auto enumValues = dv_enum_values({{1, "Low"}, {2, "High"}});
  const auto valueAsText = dv_localized("Low");  // inherited Mandatory ValueAsText (CL-DA-001)

  // EnumValues + ValueAsText + EnumDictionaryEntries present -> good.
  {
    Fixture f;
    f.script_resolution(
      {{"EnumValues", enumValues}, {"ValueAsText", valueAsText}, {"EnumDictionaryEntries", dictEntries}});
    std::optional<MultiStateValueDiscreteHandleResult> built;
    f.accessor().multi_state_dictionary_entry_async(
      node(50), [&built](MultiStateValueDiscreteHandleResult r) { built = std::move(r); });
    f.run();
    ASSERT_TRUE(built.has_value());
    EXPECT_TRUE(built->is_good()) << "all Mandatory Properties present must resolve an MSDE-DBT handle";
  }

  // EnumValues + ValueAsText present, EnumDictionaryEntries ABSENT -> bad through MSDE, GOOD through MSVD.
  {
    Fixture f;
    f.script_resolution({{"EnumValues", enumValues}, {"ValueAsText", valueAsText}});
    std::optional<MultiStateValueDiscreteHandleResult> built;
    f.accessor().multi_state_dictionary_entry_async(
      node(51), [&built](MultiStateValueDiscreteHandleResult r) { built = std::move(r); });
    f.run();
    ASSERT_TRUE(built.has_value());
    EXPECT_TRUE(built->is_bad()) << "MSDE-DBT must reject a node lacking Mandatory EnumDictionaryEntries";

    // Discriminator: the MSVD accessor (EnumValues + ValueAsText Mandatory, EnumDictionaryEntries NOT)
    // accepts the same node - proving the EnumDictionaryEntries gate is distinct to the MSDE accessor.
    Fixture disc;
    disc.script_resolution({{"EnumValues", enumValues}, {"ValueAsText", valueAsText}});
    std::optional<MultiStateValueDiscreteHandleResult> mvsd;
    disc.accessor().multi_state_value_discrete_async(
      node(51), [&mvsd](MultiStateValueDiscreteHandleResult r) { mvsd = std::move(r); });
    disc.run();
    ASSERT_TRUE(mvsd.has_value());
    EXPECT_TRUE(mvsd->is_good())
      << "the MSVD accessor accepts the EnumValues+ValueAsText node - the MSDE gate is distinct";
  }

  // EnumDictionaryEntries + ValueAsText present, EnumValues ABSENT -> bad (inherited Mandatory EnumValues).
  {
    Fixture f;
    f.script_resolution({{"ValueAsText", valueAsText}, {"EnumDictionaryEntries", dictEntries}});
    std::optional<MultiStateValueDiscreteHandleResult> built;
    f.accessor().multi_state_dictionary_entry_async(
      node(52), [&built](MultiStateValueDiscreteHandleResult r) { built = std::move(r); });
    f.run();
    ASSERT_TRUE(built.has_value());
    EXPECT_TRUE(built->is_bad()) << "MSDE-DBT must still enforce the inherited Mandatory EnumValues";
  }
}

// ===========================================================================
// PropertyAccessor explicit override (CL-AC-022)
// ===========================================================================

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, BrowsesHasPropertyMatchesBrowseNameAndReadsValue)
{
  Fixture f;
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("EURange", 6100));
  f.wireOps->browsePages.push_back(std::move(page));
  f.script_read({dv_range(0.0, 100.0)});

  std::optional<DataValueResult> captured;
  f.property(node(80)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  // Browse one level HasProperty on the target node...
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  const auto& description = f.wireOps->browseRequests[0].nodes_to_browse()[0];
  EXPECT_EQ(description.node_id(), node(80));
  EXPECT_EQ(
    description.reference_type_id(), (ua::NodeId{std::uint16_t{0}, ua::ReferenceTypeId::HasProperty}));
  // ...then Read the matched child's Value attribute.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(6100));
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].attribute_id(), valueAttribute);
  EXPECT_DOUBLE_EQ(captured->value().value().try_as<ua::Range>()->high(), 100.0);
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, NoMatchingChildReturnsBadNotFound)
{
  Fixture f;
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("SomeOtherProperty", 6200));  // not the wanted BrowseName
  f.wireOps->browsePages.push_back(std::move(page));

  std::optional<DataValueResult> captured;
  f.property(node(81)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotFound);
  EXPECT_TRUE(f.wireOps->readRequests.empty());  // no match -> no Read issued
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, PaginatesBrowseNextToMatchChildOnSecondPage)
{
  Fixture f;
  // Page 1 returns a non-matching child plus a non-empty continuation point; the wanted BrowseName is only
  // on page 2 (fetched via BrowseNext). The match must succeed across the page boundary.
  FakeWireOps::BrowsePage page1;
  page1.references.push_back(prop_ref("SomeOtherProperty", 6300));
  page1.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x09}}};
  f.wireOps->browsePages.push_back(std::move(page1));
  FakeWireOps::BrowsePage page2;
  page2.references.push_back(prop_ref("EURange", 6301));  // wanted child, only on page 2
  f.wireOps->browsePages.push_back(std::move(page2));
  f.script_read({dv_range(0.0, 100.0)});

  std::optional<DataValueResult> captured;
  f.property(node(83)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_FALSE(f.wireOps->browseNextRequests.empty());  // a BrowseNext was issued to reach page 2
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(6301));
  EXPECT_DOUBLE_EQ(captured->value().value().try_as<ua::Range>()->high(), 100.0);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(PropertyAccessorRead, BrowseNextEmptyPagesBeyondTheLimitEndTheDrain)
{
  Fixture f;
  FakeWireOps::BrowsePage page1;
  page1.references.push_back(prop_ref("SomeOtherProperty", 6300));
  page1.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x09}}};
  f.wireOps->browsePages.push_back(std::move(page1));
  FakeWireOps::BrowsePage looping;
  looping.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x09}}};
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->browsePages.push_back(looping);
  }

  std::optional<DataValueResult> captured;
  f.property(node(83)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 12U)
    << "eleven reads, then one release of the point the server still holds";
}

// @verifies AC-CL-VIEW-002-A-BUDGET-REFUSAL-RELEASES-THE-CONTINUATION-POINT
// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// Two pages of 60,000 references cross the 100,000-reference budget on the second: the drain ends
// Bad_ResponseTooLarge and the point the refused page carried is released with a release-only BrowseNext
// (the production wiring of the release, not the helper alone).
TEST(PropertyAccessorRead, BrowseNextReferenceBudgetEndsTheDrainAndReleasesThePoint)
{
  Fixture f;
  const auto bigPage = [](std::uint8_t tag)
  {
    FakeWireOps::BrowsePage page;
    page.references.reserve(60'000);
    for (std::uint32_t i = 0; i < 60'000; ++i)
    {
      page.references.push_back(prop_ref("Filler", 100'000 + i));
    }
    page.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{tag}}};
    return page;
  };
  f.wireOps->browsePages.push_back(bigPage(0x01));
  f.wireOps->browsePages.push_back(bigPage(0x02));

  std::optional<DataValueResult> captured;
  f.property(node(83)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadResponseTooLarge);
  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 2U) << "the drain BrowseNext, then the release";
  EXPECT_TRUE(f.wireOps->browseNextRequests[1].release_continuation_points());
  ASSERT_EQ(f.wireOps->browseNextRequests[1].continuation_points().size(), 1U);
  EXPECT_EQ(f.wireOps->browseNextRequests[1].continuation_points()[0],
    ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x02}}});
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, UncachedReachesSameWireOpsAsCached)
{
  Fixture f;
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("EURange", 6400));
  f.wireOps->browsePages.push_back(std::move(page));
  f.script_read({dv_range(0.0, 42.0)});

  std::optional<DataValueResult> captured;
  f.property(node(84)).read_property_uncached_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  // Same wire ops as the cached variant: one Browse (HasProperty) then a Value Read of the matched child.
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->browseRequests[0].nodes_to_browse()[0].node_id(), node(84));
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(6400));
  EXPECT_DOUBLE_EQ(captured->value().value().try_as<ua::Range>()->high(), 42.0);
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorPath, ResolvesEachHopThenReadsFinalValue)
{
  Fixture f;
  // A 2-segment path ["CurrentState", "Id"]: each hop is a one-level hierarchical Browse; the final node's
  // Value is Read.
  FakeWireOps::BrowsePage hop1;
  hop1.references.push_back(prop_ref("CurrentState", 810));
  f.wireOps->browsePages.push_back(std::move(hop1));
  FakeWireOps::BrowsePage hop2;
  hop2.references.push_back(prop_ref("Id", 811));
  f.wireOps->browsePages.push_back(std::move(hop2));
  f.script_read({dv_string("running")});

  std::optional<DataValueResult> captured;
  f.property(node(85)).read_property_path_async(
    {BrowseName{std::uint16_t{0}, "CurrentState"}, BrowseName{std::uint16_t{0}, "Id"}},
    [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  // Hop 1 browses the start node; hop 2 browses the node matched by hop 1.
  ASSERT_EQ(f.wireOps->browseRequests.size(), 2U);
  EXPECT_EQ(f.wireOps->browseRequests[0].nodes_to_browse()[0].node_id(), node(85));
  EXPECT_EQ(f.wireOps->browseRequests[1].nodes_to_browse()[0].node_id(), node(810));
  // The final matched node's Value is Read.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(811));
  EXPECT_EQ(static_cast<std::string>(captured->value().value().to<ua::String>().value()), "running");
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorPath, MidPathNoMatchReturnsBadNotFoundAndIssuesNoRead)
{
  Fixture f;
  // Hop 1 matches "CurrentState"; hop 2 has no child named "Missing" -> Bad_NotFound, no Value Read.
  FakeWireOps::BrowsePage hop1;
  hop1.references.push_back(prop_ref("CurrentState", 820));
  f.wireOps->browsePages.push_back(std::move(hop1));
  FakeWireOps::BrowsePage hop2;
  hop2.references.push_back(prop_ref("SomethingElse", 821));  // not "Missing"
  f.wireOps->browsePages.push_back(std::move(hop2));

  std::optional<DataValueResult> captured;
  f.property(node(86)).read_property_path_async(
    {BrowseName{std::uint16_t{0}, "CurrentState"}, BrowseName{std::uint16_t{0}, "Missing"}},
    [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotFound);
  EXPECT_TRUE(f.wireOps->readRequests.empty());  // path broke before the final Value Read
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, ConnectionGoneReturnsBadConnectionClosed)
{
  Fixture f;
  auto accessor = f.property(node(82));
  f.wireOps.reset();  // the interface weak-ref expires

  std::optional<DataValueResult> captured;
  accessor.read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.property.connection_closed");
}

// A transport-Good Read whose ResponseHeader.serviceResult is Bad with an empty results[] (a legal
// service-fault shape) MUST surface the true serviceResult, not the masked Bad_UnexpectedError the
// empty-results branch would otherwise fabricate (read_value serviceResult FLATTEN).
// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, ReadServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  ua::ReadResponse response;
  response.response_header().service_result() = ua::StatusCode{ua::Status::BadSessionIdInvalid};
  // results[] intentionally empty: the shape that masked the fault before the flatten.
  f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

  std::optional<DataValueResult> captured;
  // An empty path reads this node's own Value directly (read_value, no Browse).
  f.property(node(90)).read_property_path_async(
    {}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);
  EXPECT_NE(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.property.read_property_path");
}

// A transport-Good Browse whose ResponseHeader.serviceResult is Bad with an empty results[] MUST surface
// the true serviceResult, not the masked Bad_UnexpectedError (browse_children serviceResult FLATTEN).
// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, BrowseServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->browseOmitResults = true;  // empty results[]: the service-fault shape

  std::optional<DataValueResult> captured;
  f.property(node(91)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTooManyOperations);
  EXPECT_NE(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  EXPECT_TRUE(f.wireOps->readRequests.empty());  // the Browse faulted -> no Value Read
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.property.read_property");
}

// A transport-Good BrowseNext (continuing a paged Property Browse) whose ResponseHeader.serviceResult is
// Bad with an empty results[] MUST surface the true serviceResult, not the masked Bad_UnexpectedError
// (drain_children serviceResult FLATTEN).
// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(PropertyAccessorRead, BrowseNextServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  // Page 1 hands back a non-empty continuation point, so drain_children issues a BrowseNext...
  FakeWireOps::BrowsePage page1;
  page1.references.push_back(prop_ref("SomeOtherProperty", 6500));
  page1.continuationPoint = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x09}}};
  f.wireOps->browsePages.push_back(std::move(page1));
  // ...which returns a service-level fault with an empty results[] array.
  f.wireOps->browseNextHeaderServiceResult = ua::StatusCode{ua::Status::BadSessionClosed};
  f.wireOps->browseNextOmitResults = true;

  std::optional<DataValueResult> captured;
  f.property(node(92)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);
  EXPECT_NE(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  EXPECT_FALSE(f.wireOps->browseNextRequests.empty());  // a BrowseNext was in fact issued
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.property.read_property");
}

// ===========================================================================
// A Good subcode or an Uncertain code the server answers reaches the application (DataAccess handles)
// ===========================================================================

/// @p value with @p status set on it.
ua::DataValue with_status(ua::DataValue value, ua::Status status)
{
  value.status() = ua::StatusCode{status};
  return value;
}

// A write the server answers Good_Clamped completes with Good_Clamped, not plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-WRITES-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDataAccessStatusRouting, AWritesGoodClampedReachesTheApplication)
{
  Fixture f;
  auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(70), ua::Range{}));
  f.wireOps->writeOutcomes.push_back(ua::StatusCode{ua::Status::GoodClamped});

  std::optional<ua::VoidResult> captured;
  handle.write_value_async(ua::Variant{150.0}, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::GoodClamped});
}

// A Good subcode on the Write's ServiceResult is kept when the write's own status is plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDataAccessStatusRouting, AWritesServiceResultGoodSubcodeReachesTheApplication)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    auto handle = DataAccessClientTestAccess::make_analog_handle(f.analog_state(node(71), ua::Range{}));
    f.wireOps->writeHeaderServiceResult = ua::StatusCode{serviceStatus};

    std::optional<ua::VoidResult> captured;
    handle.write_value_async(ua::Variant{1.0}, [&captured](ua::VoidResult r) { captured = std::move(r); });
    f.run();

    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{serviceStatus});
  }
}

// An Optional Property the server answered Uncertain with a value is decoded, and its code is the status of
// the typed value's Result.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientDataAccessStatusRouting, AnUncertainOptionalPropertysCodeReachesTheTypedValue)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)},
    {"InstrumentRange", with_status(dv_range(-10.0, 110.0), ua::Status::UncertainSensorCalibration)}});
  AnalogItemHandleResult handle = f.build_analog(node(72));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(42.0)});
  std::optional<ua::Result<AnalogItemValue>> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainSensorCalibration});
  const auto value = captured->value_or(AnalogItemValue{});
  ASSERT_TRUE(value.instrumentRange.has_value());
  EXPECT_DOUBLE_EQ(value.instrumentRange->high(), 110.0);
}

// An Optional Property the server answered Bad is left unset even when the DataValue carries a value.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientDataAccessStatusRouting, ABadOptionalPropertyIsNotDecoded)
{
  Fixture f;
  f.script_resolution({{"EURange", dv_range(0.0, 100.0)},
    {"InstrumentRange", with_status(dv_range(-10.0, 110.0), ua::Status::BadSensorFailure)}});
  AnalogItemHandleResult handle = f.build_analog(node(73));
  ASSERT_TRUE(handle.is_good());

  f.script_read({dv_double(42.0)});
  std::optional<ua::Result<AnalogItemValue>> captured;
  handle.value().read_async([&captured](ua::Result<AnalogItemValue> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::Good});
  ASSERT_TRUE(captured->is_good());
  EXPECT_FALSE(captured->value().instrumentRange.has_value());
  EXPECT_TRUE(captured->value().euRange.has_value());
}

// The handle decides from its Mandatory Properties, so an Uncertain EURange refuses the handle with
// Bad_InternalError (ReadAnswerUncertain), the Uncertain code as the cause.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientDataAccessStatusRouting, AnUncertainMandatoryPropertyRefusesTheHandle)
{
  Fixture f;
  f.script_resolution({{"EURange", with_status(dv_range(0.0, 100.0), ua::Status::UncertainLastUsableValue)}});
  AnalogItemHandleResult handle = f.build_analog(node(74));

  EXPECT_EQ(handle.status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->code, "ReadAnswerUncertain");
}

// The PercentDeadband precondition is a decision from EURange, so an Uncertain EURange is refused.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientDataAccessStatusRouting, ThePercentDeadbandRefusesAnUncertainEuRange)
{
  Fixture f;
  auto state = f.analog_state(node(75), std::nullopt);
  ua::client::detail::ResolvedProperties props;
  props.emplace(
    "EURange", with_status(ua::DataValue{ua::Variant{ua::Range{}}}, ua::Status::UncertainLastUsableValue));
  Fixture::set_resolved(*state, std::move(props));
  auto handle = DataAccessClientTestAccess::make_analog_handle(state);

  const auto filter = handle.make_percent_deadband_filter(10.0);
  EXPECT_EQ(filter.status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(filter.shared_detail(), nullptr);
  EXPECT_EQ(filter.shared_detail()->code, "ReadAnswerUncertain");
}

// A Good subcode on the Property Read's ServiceResult is the status of the Result holding the DataValue.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(PropertyAccessorStatusRouting, TheReadsServiceResultGoodSubcodeReachesTheApplication)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    FakeWireOps::BrowsePage page;
    page.references.push_back(prop_ref("EURange", 6200));
    f.wireOps->browsePages.push_back(std::move(page));
    ua::ReadResponse response = read_response({dv_range(0.0, 100.0)});
    response.response_header().service_result() = ua::StatusCode{serviceStatus};
    f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

    std::optional<DataValueResult> captured;
    f.property(node(90)).read_property_async(
      BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
    f.run();

    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{serviceStatus});
    ASSERT_TRUE(captured->is_good());
    const auto* range = captured->value().value().try_as<ua::Range>();
    ASSERT_NE(range, nullptr);
    EXPECT_DOUBLE_EQ(range->low(), 0.0);
    EXPECT_DOUBLE_EQ(range->high(), 100.0);
  }
}

// The Browse that finds the Property is a lookup the next Read depends on, so an Uncertain page is refused
// with Bad_InternalError (ReferencesAnswerUncertain) and nothing is read.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PropertyAccessorStatusRouting, AnUncertainBrowseIsRefusedAndNothingIsRead)
{
  Fixture f;
  FakeWireOps::BrowsePage page;
  page.references.push_back(prop_ref("EURange", 6201));
  page.status = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
  f.wireOps->browsePages.push_back(std::move(page));

  std::optional<DataValueResult> captured;
  f.property(node(91)).read_property_async(
    BrowseName{std::uint16_t{0}, "EURange"}, [&captured](DataValueResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReferencesAnswerUncertain");
  EXPECT_TRUE(f.wireOps->readRequests.empty());
}

}  // namespace
