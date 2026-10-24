// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 StateMachine typed-access facade (client design section 8.18.1.b,
// CL-SM-001..009). Covers the address-space pre-flight (Browse CurrentState / LastTransition components +
// their Id / TransitionTime Properties + the AvailableStates / AvailableTransitions topology), the
// CurrentState / LastTransition typed reads (CL-SM-001/002/004), NodeId-identity comparison (CL-SM-003/006),
// the finite topology cache + refresh (CL-SM-005), and the ProgramStateMachine Executable pre-flight + local
// state-method matrix + wire Call (CL-SM-007/008/009).
//
// The tests drive the real code through the fake upward interface roles (FakeWireOps / FakeSupportOps) with
// no real ConnectionImpl: resolution is scripted via browsePages + scriptedReadResponses, method Calls via
// callOutcomes. Handles are built through StateMachineClientTestAccess over the async factories.
//
// Falsifiability: a factory that skips the CurrentState pre-flight fails
// HandleConstructionBadWhenCurrentState Missing; a current_state that mis-batches the Read fails
// CurrentStateReadsNameAndId; one that maps a Bad DataValue status onto the outer Result fails
// BadStateNotActiveSurfacesViaStatusCodeNotResult; a current_state_is that matches by text fails
// CurrentStateIsComparesByNodeId; an invoke that Calls a non-executable method fails
// InvokeSkipsCallWhenNotExecutable; one that ignores the matrix fails
// LocalStateMethodMatrixBlocksInvalidTransitions; one that pads/reorders args fails
// InvokePassesArgumentsVerbatim.

#include "ua_state_machine_access.h"

#include "fake_connection_ops.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_call_method_result.h"
#include "ua_client_monitored_item.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_subscriber_impl.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_expanded_node_id.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_read_response.h"
#include "ua_reference_description.h"
#include "ua_response_header.h"
#include "ua_simple_attribute_operand.h"
#include "ua_state_machine_access_state.h"
#include "ua_state_machine_access_test_access.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::AvailableState;
using ua::client::EventNotification;
using ua::client::FiniteStateMachineHandleResult;
using ua::client::MonitoredItemKind;
using ua::client::MonitoredItemResult;
using ua::client::ProgramMethod;
using ua::client::ProgramStateMachineHandle;
using ua::client::ProgramStateMachineHandleResult;
using ua::client::StateMachineHandle;
using ua::client::StateMachineHandleResult;
using ua::client::StateVariable;
using ua::client::TransitionEventNotification;
using ua::client::TransitionVariable;
using ua::client::detail::EventBackboneCreated;
using ua::client::detail::EventBackboneOps;
using ua::client::detail::EventSubscriberImpl;
using ua::client::detail::StateMachineClientTestAccess;
using ua::test_helpers::FakeSupportOps;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{std::uint16_t{0}, identifier};
}

ua::NodeId well_known(ua::ObjectId id)
{
  return ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(id)};
}

constexpr std::uint32_t valueAttribute = static_cast<std::uint32_t>(ua::AttributeId::Value);
constexpr std::uint32_t executableAttribute = static_cast<std::uint32_t>(ua::AttributeId::Executable);

// Well-known child node ids the fixture resolves the machine's components/properties to.
constexpr std::uint32_t currentStateNode = 100;
constexpr std::uint32_t currentStateIdNode = 101;
constexpr std::uint32_t lastTransitionNode = 110;
constexpr std::uint32_t lastTransitionIdNode = 111;
constexpr std::uint32_t lastTransitionTimeNode = 112;
constexpr std::uint32_t availableStatesNode = 120;
constexpr std::uint32_t availableTransitionsNode = 121;
constexpr std::uint32_t startMethodNode = 130;
constexpr std::uint32_t suspendMethodNode = 131;
constexpr std::uint32_t resumeMethodNode = 132;
constexpr std::uint32_t haltMethodNode = 133;
constexpr std::uint32_t resetMethodNode = 134;

// ---- reference / value builders ----

ua::ReferenceDescription child_ref(std::string_view browseName, std::uint32_t identifier)
{
  ua::ReferenceDescription reference;
  reference.browse_name() = ua::QualifiedName{std::uint16_t{0}, browseName};
  reference.node_id() = ua::ExpandedNodeId{node(identifier)};
  return reference;
}

ua::DataValue dv_localized(std::string text)
{
  return ua::DataValue{ua::Variant{ua::LocalizedText{ua::String{std::move(text)}}}};
}

ua::DataValue dv_localized_status(std::string text, ua::Status status)
{
  return ua::DataValue{ua::Variant{ua::LocalizedText{ua::String{std::move(text)}}}, ua::StatusCode{status}};
}

ua::DataValue dv_nodeid(ua::NodeId value)
{
  return ua::DataValue{ua::Variant{std::move(value)}};
}

ua::DataValue dv_qualified_name(ua::QualifiedName value)
{
  return ua::DataValue{ua::Variant{std::move(value)}};
}

ua::DataValue dv_bool(bool value)
{
  return ua::DataValue{ua::Variant{value}};
}

ua::DataValue dv_datetime(ua::DateTime value)
{
  return ua::DataValue{ua::Variant{value}};
}

ua::DataValue dv_nodeid_array(const std::vector<ua::NodeId>& ids)
{
  ua::Array<ua::NodeId> array;
  for (const auto& id : ids)
  {
    array.push_back(id);
  }
  return ua::DataValue{ua::Variant{std::move(array)}};
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

// A Good-transport ReadResponse whose SERVICE-level serviceResult is bad, carrying an EMPTY results[] (the
// spec-legal service-fault shape). Exercises the read continuations' serviceResult FLATTEN facade
// (error_handling.md): without the flatten an empty results[] masks the fault as Bad_UnexpectedError.
ua::ReadResponse read_service_fault(ua::Status status)
{
  ua::ReadResponse response;
  response.response_header().service_result() = ua::StatusCode{status};
  return response;
}

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> supportOps = std::make_shared<FakeSupportOps>();

  ua::client::StateMachineAccessor accessor()
  {
    return StateMachineClientTestAccess::make_accessor(wireOps, supportOps, ctx.get_executor());
  }

  void run()
  {
    ctx.run();
    ctx.restart();
  }

  void push_browse(std::vector<ua::ReferenceDescription> references)
  {
    FakeWireOps::BrowsePage page;
    page.references = std::move(references);
    wireOps->browsePages.push_back(std::move(page));
  }

  void push_read(std::vector<ua::DataValue> values)
  {
    wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{read_response(std::move(values))});
  }

  void script_unowned_identity(std::string_view browseName)
  {
    push_read({dv_qualified_name(ua::QualifiedName{0, browseName})});
    push_browse({});
  }

  // Scripts the base pre-flight browses: the machine's HasComponent children (CurrentState + optional
  // LastTransition + optional standard methods), then CurrentState's HasProperty Id, then (when present)
  // LastTransition's HasProperty Id + TransitionTime.
  void script_base(bool withLastTransition, bool withMethods)
  {
    std::vector<ua::ReferenceDescription> components;
    components.push_back(child_ref("CurrentState", currentStateNode));
    if (withLastTransition)
    {
      components.push_back(child_ref("LastTransition", lastTransitionNode));
    }
    if (withMethods)
    {
      components.push_back(child_ref("Start", startMethodNode));
      components.push_back(child_ref("Suspend", suspendMethodNode));
      components.push_back(child_ref("Resume", resumeMethodNode));
      components.push_back(child_ref("Halt", haltMethodNode));
      components.push_back(child_ref("Reset", resetMethodNode));
    }
    push_browse(std::move(components));
    push_browse({child_ref("Id", currentStateIdNode)});
    if (withLastTransition)
    {
      push_browse(
        {child_ref("Id", lastTransitionIdNode), child_ref("TransitionTime", lastTransitionTimeNode)});
    }
  }

  // Scripts the finite topology pre-flight: the machine's HasProperty AvailableStates / AvailableTransitions,
  // then the batched Read of the two NodeId-array Values.
  void script_topology(std::vector<ua::NodeId> states, std::vector<ua::NodeId> transitions)
  {
    push_browse({child_ref("AvailableStates", availableStatesNode),
      child_ref("AvailableTransitions", availableTransitionsNode)});
    push_read({dv_nodeid_array(states), dv_nodeid_array(transitions)});
  }

  StateMachineHandleResult build_base(ua::NodeId machine, bool withLastTransition = false)
  {
    script_base(withLastTransition, /*withMethods=*/false);
    std::optional<StateMachineHandleResult> captured;
    accessor().state_machine_async(
      std::move(machine), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }

  FiniteStateMachineHandleResult build_finite(
    ua::NodeId machine, std::vector<ua::NodeId> states, std::vector<ua::NodeId> transitions)
  {
    script_base(/*withLastTransition=*/false, /*withMethods=*/false);
    script_topology(std::move(states), std::move(transitions));
    std::optional<FiniteStateMachineHandleResult> captured;
    accessor().finite_state_machine_async(
      std::move(machine), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }

  ProgramStateMachineHandleResult build_program(ua::NodeId machine)
  {
    script_base(/*withLastTransition=*/false, /*withMethods=*/true);
    // The program matrix uses the well-known state NodeIds (not the cached topology), so build with an empty
    // topology (a HasProperty browse that resolves no AvailableStates / AvailableTransitions -> no Read).
    // This keeps `readRequests` clean so the op-level Read assertions below are unambiguous.
    push_browse({});
    std::optional<ProgramStateMachineHandleResult> captured;
    accessor().program_state_machine_async(
      std::move(machine), [&captured](ProgramStateMachineHandleResult r) { captured = std::move(r); });
    run();
    return std::move(*captured);
  }
};

// ===========================================================================
// StateMachineHandle::current_state_async (CL-SM-001 / CL-SM-002)
// ===========================================================================

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineCurrentState, CurrentStateReadsNameAndId)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(10));
  ASSERT_TRUE(handle.is_good());
  EXPECT_EQ(handle.value().machine_id(), node(10));

  const ua::NodeId runningId = well_known(ua::ObjectId::ProgramStateMachineType_Running);
  f.push_read({dv_localized("Running"), dv_nodeid(runningId)});

  std::optional<ua::client::StateVariableResult> captured;
  handle.value().current_state_async(
    [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(static_cast<std::string>(captured->value().name.text()), "Running");
  ASSERT_TRUE(captured->value().id.has_value());
  EXPECT_EQ(*captured->value().id, runningId);

  // The batched Read targets CurrentState.Value then CurrentState.Id.Value (base resolution issued no reads).
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  const auto& nodesToRead = f.wireOps->readRequests[0].nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 2U);
  EXPECT_EQ(nodesToRead[0].node_id(), node(currentStateNode));
  EXPECT_EQ(nodesToRead[0].attribute_id(), valueAttribute);
  EXPECT_EQ(nodesToRead[1].node_id(), node(currentStateIdNode));
  EXPECT_EQ(nodesToRead[1].attribute_id(), valueAttribute);
}

// @verifies CL-SM-002
// @verifies AC-CL-ATTR-005-STATUS-BEFORE-VALUE
// @relation(CL-SM-002, scope=function)
TEST(ClientStateMachineCurrentState, BadStateNotActiveSurfacesWithoutExposingStaleValue)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(11));
  ASSERT_TRUE(handle.is_good());

  // A misbehaving server supplies a stale payload beside Bad quality. Part 4 section 7.11.1 requires the
  // server to send null, but tier 2 must remain status-first even when its peer violates that rule.
  f.push_read({dv_localized_status("Inactive", ua::Status::BadStateNotActive),
    ua::DataValue{ua::Variant{well_known(ua::ObjectId::ProgramStateMachineType_Halted)},
      ua::StatusCode{ua::Status::BadStateNotActive}}});

  std::optional<ua::client::StateVariableResult> captured;
  handle.value().current_state_async(
    [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());  // the read succeeded; the *state* is what is bad (two-layer model)
  EXPECT_EQ(captured->value().statusCode.as_status(), ua::Status::BadStateNotActive);
  EXPECT_TRUE(captured->value().name.text().empty())
    << "a Bad DataValue's unusable stale payload must not reach the typed application surface";
  EXPECT_FALSE(captured->value().id.has_value())
    << "the same status-before-value rule applies independently to the Id Property DataValue";
}

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineCurrentState, ConstructionBadWhenCurrentStateComponentMissing)
{
  Fixture f;
  // The machine's HasComponent browse omits CurrentState (Mandatory) -> construction fails.
  f.push_browse({child_ref("LastTransition", lastTransitionNode)});

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(12), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotFound);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.construction");
}

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineCurrentState, PagedComponentBrowseFollowsContinuationPointToResolveChild)
{
  Fixture f;
  // The machine's HasComponent browse is paginated: page 1 carries a NON-EMPTY continuation point and only a
  // non-target child; page 2 (delivered via BrowseNext) carries the Mandatory CurrentState. If the paged
  // drain dropped page-2 children, CurrentState would be unresolved and construction would fail Bad_NotFound.
  FakeWireOps::BrowsePage firstPage;
  firstPage.references.push_back(child_ref("SomeOtherComponent", 900));
  firstPage.continuationPoint = ua::ContinuationPoint{0x01};
  f.wireOps->browsePages.push_back(std::move(firstPage));
  f.push_browse({child_ref("CurrentState", currentStateNode)});  // page 2 (no CP): the child needed
  f.push_browse({child_ref("Id", currentStateIdNode)});  // CurrentState's HasProperty Id

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(15), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());  // CurrentState resolved from page 2 -> handle built
  EXPECT_EQ(captured->value().machine_id(), node(15));
  EXPECT_FALSE(f.wireOps->browseNextRequests.empty());  // the continuation point WAS followed
}

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineCurrentState, FactoryFailsWhenConnectionGone)
{
  Fixture f;
  f.wireOps.reset();  // the wire interface weak-ref expires -> the lock fails

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(13), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.connection_closed");
}

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineCurrentState, CurrentStateOnMovedFromHandleFastFails)
{
  StateMachineHandle sentinel;  // default-constructed: no state
  std::optional<ua::client::StateVariableResult> captured;
  sentinel.current_state_async([&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInvalidState);
}

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineCurrentState, CurrentStateOnGoneInterfaceReturnsConnectionClosed)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(14));
  ASSERT_TRUE(handle.is_good());
  f.wireOps.reset();  // the wire interface weak-ref expires before the op is issued

  std::optional<ua::client::StateVariableResult> captured;
  handle.value().current_state_async(
    [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.connection_closed");
}

// ===========================================================================
// StateMachineHandle::current_state_is_async (CL-SM-003 / CL-SM-006)
// ===========================================================================

// @verifies CL-SM-003
// @relation(CL-SM-003, scope=function)
TEST(ClientStateMachineCurrentStateIs, ComparesByNodeIdEquality)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(20));
  ASSERT_TRUE(handle.is_good());

  const ua::NodeId runningId = well_known(ua::ObjectId::ProgramStateMachineType_Running);
  f.push_read({dv_nodeid(runningId)});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    runningId, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value());
  // Only CurrentState.Id (not the CurrentState value) is Read for the comparison.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  ASSERT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(currentStateIdNode));
}

// @verifies CL-SM-003
// @relation(CL-SM-003, scope=function)
TEST(ClientStateMachineCurrentStateIs, MismatchReturnsFalse)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(21));
  ASSERT_TRUE(handle.is_good());

  // Server reports the machine is in Running; the caller asks about Ready -> false.
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  f.script_unowned_identity("Running");
  f.script_unowned_identity("Ready");

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(well_known(ua::ObjectId::ProgramStateMachineType_Ready),
    [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_FALSE(captured->value());
}

// @verifies CL-SM-003
// @relation(CL-SM-003, scope=function)
TEST(ClientStateMachineCurrentStateIs, OpaqueApplicationDefinedIdsCompareWithoutMetadata)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(211));
  ASSERT_TRUE(handle.is_good());

  const ua::NodeId currentId = node(2110);
  const ua::NodeId expectedId = node(2111);
  f.push_read({dv_nodeid(currentId)});
  f.push_read({ua::DataValue{ua::StatusCode{ua::Status::BadNodeIdUnknown}}});
  f.push_read({ua::DataValue{ua::StatusCode{ua::Status::BadNodeIdUnknown}}});
  const std::size_t browsesBeforeComparison = f.wireOps->browseRequests.size();

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    expectedId, [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_FALSE(captured->value());
  EXPECT_EQ(f.wireOps->browseRequests.size(), browsesBeforeComparison);
}

// @verifies CL-SM-006
// @relation(CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, SubtypeStateIdEqualsSupertypeIdNodeId)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(22));
  ASSERT_TRUE(handle.is_good());

  // CL-SM-006: a compliant server reuses the supertype-declared state NodeId for the subtype's
  // CurrentState.Id, so the caller can compare against the well-known supertype id directly.
  const ua::NodeId supertypeReadyId = well_known(ua::ObjectId::ProgramStateMachineType_Ready);
  f.push_read({dv_nodeid(supertypeReadyId)});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    supertypeReadyId, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value());
}

// @verifies CL-SM-006
// The caller may hold the replicated State Object NodeId declared by a subtype even though the server must
// report CurrentState.Id as the Object where that state was first defined. The helper resolves the subtype
// Object through its owning ObjectType and HasSubtype ancestry before comparing.
// @relation(CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, SubtypeStateObjectResolvesToFirstSupertypeDefinition)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(220));
  ASSERT_TRUE(handle.is_good());

  const ua::NodeId originStateId = node(2200);
  const ua::NodeId subtypeStateId = node(2201);
  f.push_read({dv_nodeid(originStateId)});  // CurrentState.Id

  // Normalize the reported origin Id: BrowseName, inverse HasComponent owner, then no owner supertype.
  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  f.push_browse({child_ref("OriginMachineType", 2210)});
  f.push_browse({});

  // Normalize the caller's subtype Id: find its owner, walk to the owner supertype, and find the replicated
  // state with the same BrowseName. That parent has no further supertype, so the origin is 2200.
  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  f.push_browse({child_ref("SubtypeMachineType", 2211)});
  f.push_browse({child_ref("OriginMachineType", 2210)});
  f.push_browse({child_ref("Running", 2200)});
  f.push_browse({});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    subtypeStateId, [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value());

  ASSERT_EQ(f.wireOps->browseRequests.size(), 8U);
  EXPECT_EQ(
    f.wireOps->browseRequests[2].nodes_to_browse()[0].browse_direction(), ua::BrowseDirection::Inverse);
  EXPECT_EQ(
    f.wireOps->browseRequests[4].nodes_to_browse()[0].browse_direction(), ua::BrowseDirection::Inverse);
}

// @verifies CL-SM-006
// A malformed HasSubtype cycle is rejected deterministically instead of hanging or silently matching.
// @relation(CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, CyclicOwnerTypeHierarchyReturnsSourceTaggedBad)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(222));
  ASSERT_TRUE(handle.is_good());

  const ua::NodeId currentStateId = node(2220);
  const ua::NodeId expectedStateId = node(2221);
  f.push_read({dv_nodeid(currentStateId)});
  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  f.push_browse({child_ref("CyclicMachineType", 2230)});  // inverse HasComponent owner
  f.push_browse({child_ref("CyclicMachineType", 2230)});  // inverse HasSubtype points to itself
  f.push_browse({child_ref("Running", 2220)});  // same-name parent replica

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    expectedStateId, [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentIdentityResolveFailed");
  ASSERT_NE(captured->shared_detail()->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->code, "StateMachineIdentityTypeCycle");
}

// @verifies CL-SM-006
// A primary failure while reading identity metadata retains its StatusCode and shared ErrorDetail chain at
// the public helper boundary.
// @relation(CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, IdentityMetadataReadFailurePreservesErrorDetail)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(223));
  ASSERT_TRUE(handle.is_good());

  f.push_read({dv_nodeid(node(2230))});
  auto injected = ua::make_error_detail(
    "InjectedIdentityMetadataFailure", "injected identity metadata failure", "test.state_machine");
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{ua::Status::BadTimeout, std::move(injected)});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    node(2231), [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentIdentityResolveFailed");
  ASSERT_NE(captured->shared_detail()->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->code, "StateMachineIdentityBrowseNameReadFailed");
  ASSERT_NE(captured->shared_detail()->cause->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->cause->code, "InjectedIdentityMetadataFailure");
}

// @verifies CL-SM-006
// String state ids are the case a moved-from NodeId loses: each owner lookup must browse the State the
// identity names, whichever order the compiler builds the Browse call's arguments in.
// @relation(CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, StringStateIdsLookUpTheOwnerOfTheStateTheyName)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(224));
  ASSERT_TRUE(handle.is_good());

  const ua::NodeId originStateId{2, ua::String{"OriginMachineType.Running"}};
  const ua::NodeId subtypeStateId{2, ua::String{"SubtypeMachineType.Running"}};
  ua::ReferenceDescription originReplica = child_ref("Running", 0);
  originReplica.node_id() = ua::ExpandedNodeId{originStateId};
  f.push_read({dv_nodeid(originStateId)});  // CurrentState.Id

  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  f.push_browse({child_ref("OriginMachineType", 2240)});
  f.push_browse({});

  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  f.push_browse({child_ref("SubtypeMachineType", 2241)});
  f.push_browse({child_ref("OriginMachineType", 2240)});
  f.push_browse({originReplica});
  f.push_browse({});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    subtypeStateId, [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value());
  ASSERT_EQ(f.wireOps->browseRequests.size(), 8U);
  EXPECT_EQ(f.wireOps->browseRequests[2].nodes_to_browse()[0].node_id(), originStateId);
  EXPECT_EQ(f.wireOps->browseRequests[4].nodes_to_browse()[0].node_id(), subtypeStateId);
}

// @verifies CL-SM-006
// @verifies CL-DIAG-003
// A failed owner lookup keeps the current_state_is source on its ErrorDetail, whichever order the compiler
// builds the Browse call's arguments in.
// @relation(CL-DIAG-003, CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, OwnerLookupFailureKeepsTheCurrentStateIsSource)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(225));
  ASSERT_TRUE(handle.is_good());

  f.push_read({dv_nodeid(node(2250))});
  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  FakeWireOps::BrowsePage refused;
  refused.status = ua::StatusCode{ua::Status::BadNodeIdUnknown};
  f.wireOps->browsePages.push_back(std::move(refused));

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    node(2251), [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNodeIdUnknown);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentIdentityResolveFailed");
  ASSERT_NE(captured->shared_detail()->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->code, "StateMachineBrowseBad");
  EXPECT_EQ(captured->shared_detail()->cause->source, "client.tier2.state_machine.current_state_is");
}

// @verifies CL-SM-006
// @verifies CL-DIAG-003
// A failed supertype lookup while walking the owner's ObjectType hierarchy keeps the current_state_is source
// on its ErrorDetail, whichever order the compiler builds the Browse call's arguments in.
// @relation(CL-DIAG-003, CL-SM-006, scope=function)
TEST(ClientStateMachineCurrentStateIs, SupertypeLookupFailureKeepsTheCurrentStateIsSource)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(226));
  ASSERT_TRUE(handle.is_good());

  f.push_read({dv_nodeid(node(2260))});
  f.push_read({dv_qualified_name(ua::QualifiedName{0, "Running"})});
  f.push_browse({child_ref("OwnerMachineType", 2270)});  // inverse HasComponent owner
  FakeWireOps::BrowsePage refused;
  refused.status = ua::StatusCode{ua::Status::BadNodeIdUnknown};
  f.wireOps->browsePages.push_back(std::move(refused));  // inverse HasSubtype of the owner type

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    node(2261), [&captured](ua::Result<bool> result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNodeIdUnknown);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentIdentityResolveFailed");
  ASSERT_NE(captured->shared_detail()->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->code, "StateMachineBrowseBad");
  EXPECT_EQ(captured->shared_detail()->cause->source, "client.tier2.state_machine.current_state_is");
}

// @verifies CL-SM-003
// @relation(CL-SM-003, scope=function)
TEST(ClientStateMachineCurrentStateIs, EmptyCurrentStateIdValueMeansNotActiveGoodFalse)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(23));
  ASSERT_TRUE(handle.is_good());

  // The server reports no active state: CurrentState.Id carries an empty (null) Value. That is a valid
  // "the machine is not in any state" answer, so the comparison is Good/false - NOT a decode Bad. Only a
  // Value that holds a genuinely non-NodeId type is an undecodable Bad.
  f.push_read({ua::DataValue{ua::Variant{}}});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(well_known(ua::ObjectId::ProgramStateMachineType_Running),
    [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());  // empty CurrentState.Id -> Good, not a decode Bad
  EXPECT_FALSE(captured->value());  // no active state is not the expected state
}

// @verifies CL-SM-003
// @verifies CL-DIAG-003
// @relation(CL-DIAG-003, CL-SM-003, scope=function)
TEST(ClientStateMachineCurrentStateIs, NonNodeIdCurrentStateIdValueStaysBad)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(24));
  ASSERT_TRUE(handle.is_good());

  // A CurrentState.Id whose Value holds a genuinely non-NodeId type (here an Int32) is undecodable and stays
  // Bad, tagged with the current_state_is source.
  f.push_read({ua::DataValue{ua::Variant{std::int32_t{7}}}});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(well_known(ua::ObjectId::ProgramStateMachineType_Running),
    [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.current_state_is");
}

// ===========================================================================
// StateMachineHandle::last_transition_async (CL-SM-004)
// ===========================================================================

// @verifies CL-SM-004
// @relation(CL-SM-004, scope=function)
TEST(ClientStateMachineLastTransition, ResolvesIdAndTransitionTime)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(30), /*withLastTransition=*/true);
  ASSERT_TRUE(handle.is_good());

  const ua::NodeId transitionId = well_known(ua::ObjectId::ProgramStateMachineType_RunningToHalted);
  const ua::DateTime transitionTime{2026, 7, 18, 10, 30, 0.0};
  f.push_read({dv_localized("RunningToHalted"), dv_nodeid(transitionId), dv_datetime(transitionTime)});

  std::optional<ua::client::TransitionVariableResult> captured;
  handle.value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(static_cast<std::string>(captured->value().name.text()), "RunningToHalted");
  ASSERT_TRUE(captured->value().id.has_value());
  EXPECT_EQ(*captured->value().id, transitionId);
  ASSERT_TRUE(captured->value().transitionTime.has_value());
  EXPECT_EQ(*captured->value().transitionTime, transitionTime);
  // The Read batches LastTransition.Value, its Id, and its TransitionTime.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  const auto& nodesToRead = f.wireOps->readRequests[0].nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 3U);
  EXPECT_EQ(nodesToRead[0].node_id(), node(lastTransitionNode));
  EXPECT_EQ(nodesToRead[1].node_id(), node(lastTransitionIdNode));
  EXPECT_EQ(nodesToRead[2].node_id(), node(lastTransitionTimeNode));
}

// @verifies CL-SM-004
// When the LastTransition exposes NO TransitionTime Property, the transition time falls back to the
// LastTransition.Value DataValue's SourceTimestamp (ua_state_machine_access.cpp ~:1161-1162). Distinct from
// ResolvesIdAndTransitionTime (TransitionTime Property PRESENT): here the Property is absent, the Read
// batches only [Value, Id], and the ONLY source of a time is the Value's SourceTimestamp. A version asserting
// a Property value would have no third Read result to read.
// @relation(CL-SM-004, scope=function)
TEST(ClientStateMachineLastTransition, AbsentTransitionTimePropertyFallsBackToSourceTimestamp)
{
  Fixture f;
  // Base pre-flight scripted by hand (script_base always adds a TransitionTime child): the LastTransition
  // exposes its Mandatory Id Property but NOT the Optional TransitionTime Property.
  f.push_browse(
    {child_ref("CurrentState", currentStateNode), child_ref("LastTransition", lastTransitionNode)});
  f.push_browse({child_ref("Id", currentStateIdNode)});
  f.push_browse({child_ref("Id", lastTransitionIdNode)});  // Id only - no TransitionTime child
  std::optional<StateMachineHandleResult> built;
  f.accessor().state_machine_async(node(32), [&built](StateMachineHandleResult r) { built = std::move(r); });
  f.run();
  ASSERT_TRUE(built.has_value());
  ASSERT_TRUE(built->is_good());

  // The LastTransition read batches only [Value, Id]; the Value DataValue carries a SourceTimestamp that the
  // fallback must surface as the transition time.
  const ua::DateTime sourceTime{2026, 7, 20, 8, 15, 0.0};
  const ua::NodeId transitionId = well_known(ua::ObjectId::ProgramStateMachineType_RunningToSuspended);
  ua::DataValue lastTransitionValue = dv_localized("Run->Suspend");
  lastTransitionValue.source_timestamp() = sourceTime;
  f.push_read({lastTransitionValue, dv_nodeid(transitionId)});

  std::optional<ua::client::TransitionVariableResult> captured;
  built->value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(static_cast<std::string>(captured->value().name.text()), "Run->Suspend");
  ASSERT_TRUE(captured->value().id.has_value());
  EXPECT_EQ(*captured->value().id, transitionId);
  ASSERT_TRUE(captured->value().transitionTime.has_value());
  EXPECT_EQ(*captured->value().transitionTime, sourceTime)
    << "with no TransitionTime Property the time falls back to the Value's SourceTimestamp";
  // Only two ReadValueIds were sent (Value + Id) - no TransitionTime read.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 2U);
}

// @verifies CL-SM-004
// @relation(CL-SM-004, scope=function)
TEST(ClientStateMachineLastTransition, AbsentReturnsBadNotFoundWithoutRead)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(31), /*withLastTransition=*/false);
  ASSERT_TRUE(handle.is_good());

  std::optional<ua::client::TransitionVariableResult> captured;
  handle.value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotFound);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.last_transition_not_present");
  EXPECT_TRUE(f.wireOps->readRequests.empty());  // absent LastTransition -> no wire Read issued
}

// ===========================================================================
// FiniteStateMachineHandle topology (CL-SM-005)
// ===========================================================================

// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineFinite, ResolvesAvailableStatesAndTransitions)
{
  Fixture f;
  const std::vector<ua::NodeId> states{well_known(ua::ObjectId::ProgramStateMachineType_Ready),
    well_known(ua::ObjectId::ProgramStateMachineType_Running)};
  const std::vector<ua::NodeId> transitions{well_known(ua::ObjectId::ProgramStateMachineType_ReadyToRunning)};
  FiniteStateMachineHandleResult handle = f.build_finite(node(40), states, transitions);
  ASSERT_TRUE(handle.is_good());

  const std::vector<AvailableState> resolvedStates = handle.value().available_states();
  ASSERT_EQ(resolvedStates.size(), 2U);
  EXPECT_EQ(resolvedStates[0].stateId, states[0]);
  EXPECT_EQ(resolvedStates[1].stateId, states[1]);
  const auto resolvedTransitions = handle.value().available_transitions();
  ASSERT_EQ(resolvedTransitions.size(), 1U);
  EXPECT_EQ(resolvedTransitions[0].transitionId, transitions[0]);

  // The topology Read batches AvailableStates.Value + AvailableTransitions.Value. A second Read follows it
  // for the entries' DisplayName / Number metadata (one batch for the whole topology).
  ASSERT_EQ(f.wireOps->readRequests.size(), 2U);
  const auto& nodesToRead = f.wireOps->readRequests[0].nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 2U);
  EXPECT_EQ(nodesToRead[0].node_id(), node(availableStatesNode));
  EXPECT_EQ(nodesToRead[1].node_id(), node(availableTransitionsNode));

  const auto provenance = handle.value().topology_provenance();
  EXPECT_TRUE(provenance.statesPublished);
  EXPECT_TRUE(provenance.transitionsPublished);
  EXPECT_TRUE(provenance.enrichmentComplete);
}

// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineFinite, RefreshTopologyReReadsAndReplacesCacheAcrossCopies)
{
  Fixture f;
  FiniteStateMachineHandleResult handle =
    f.build_finite(node(41), {well_known(ua::ObjectId::ProgramStateMachineType_Ready)}, {});
  ASSERT_TRUE(handle.is_good());
  ua::client::FiniteStateMachineHandle copy = handle.value();  // shares the cached topology snapshot
  ASSERT_EQ(copy.available_states().size(), 1U);

  // A refresh re-resolves with a NEW topology (two states); the shared snapshot is replaced in place.
  const std::vector<ua::NodeId> newStates{well_known(ua::ObjectId::ProgramStateMachineType_Ready),
    well_known(ua::ObjectId::ProgramStateMachineType_Running)};
  f.script_topology(newStates, {});
  std::optional<ua::VoidResult> refreshed;
  handle.value().refresh_topology_async([&refreshed](ua::VoidResult r) { refreshed = std::move(r); });
  f.run();
  ASSERT_TRUE(refreshed.has_value());
  ASSERT_TRUE(refreshed->is_good());

  // The COPY observes the refreshed topology (shared state).
  const auto refreshedStates = copy.available_states();
  ASSERT_EQ(refreshedStates.size(), 2U);
  EXPECT_EQ(refreshedStates[1].stateId, newStates[1]);
}

// @verifies CL-SM-005
// A resolved topology carries more than opaque ids: OPC 10000-16 4.4.2/4.4.4 give StateType a Mandatory
// StateNumber, TransitionType a Mandatory TransitionNumber, and a transition names its endpoints through the
// FromState / ToState ReferenceTypes. Without the endpoints a transition list cannot be read as a graph.
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineFinite, TransitionEndpointsNamesAndNumbersAreResolved)
{
  Fixture f;
  const ua::NodeId ready = well_known(ua::ObjectId::ProgramStateMachineType_Ready);
  const ua::NodeId running = well_known(ua::ObjectId::ProgramStateMachineType_Running);
  const ua::NodeId readyToRunning = well_known(ua::ObjectId::ProgramStateMachineType_ReadyToRunning);

  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode),
    child_ref("AvailableTransitions", availableTransitionsNode)});
  f.push_read({dv_nodeid_array({ready, running}), dv_nodeid_array({readyToRunning})});
  // The enrichment Browse asks FromState then ToState for the one transition, in that order.
  constexpr std::uint32_t fromStateTarget = 950;
  constexpr std::uint32_t toStateTarget = 951;
  f.push_browse({child_ref("Ready", fromStateTarget)});  // FromState -> the Ready state object
  f.push_browse({child_ref("Running", toStateTarget)});  // ToState   -> the Running state object
  // Each entry's Number Property resolves to its own node, then one Read carries the three DisplayNames
  // followed by the three Numbers.
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    for (std::size_t i = 0; i < request.browse_paths().size(); ++i)
    {
      ua::BrowsePathResult result;
      ua::BrowsePathTarget target;
      target.target_id() = ua::ExpandedNodeId{node(static_cast<std::uint32_t>(900 + i))};
      result.targets().push_back(std::move(target));
      response.results().push_back(std::move(result));
    }
    return response;
  };
  f.push_read({ua::DataValue{ua::Variant{ua::LocalizedText{"", "Ready"}}},
    ua::DataValue{ua::Variant{ua::LocalizedText{"", "Running"}}},
    ua::DataValue{ua::Variant{ua::LocalizedText{"", "Ready To Running"}}},
    ua::DataValue{ua::Variant{std::uint32_t{1}}},
    ua::DataValue{ua::Variant{std::uint32_t{2}}},
    ua::DataValue{ua::Variant{std::uint32_t{11}}}});

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(43), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  const auto states = captured->value().available_states();
  ASSERT_EQ(states.size(), 2U);
  EXPECT_EQ(static_cast<std::string_view>(states[0].name.text()), "Ready");
  EXPECT_EQ(static_cast<std::string_view>(states[1].name.text()), "Running");
  ASSERT_TRUE(states[0].number.has_value());
  EXPECT_EQ(*states[0].number, 1U);
  ASSERT_TRUE(states[1].number.has_value());
  EXPECT_EQ(*states[1].number, 2U);

  const auto transitions = captured->value().available_transitions();
  ASSERT_EQ(transitions.size(), 1U);
  EXPECT_EQ(static_cast<std::string_view>(transitions[0].name.text()), "Ready To Running");
  ASSERT_TRUE(transitions[0].number.has_value());
  EXPECT_EQ(*transitions[0].number, 11U);
  ASSERT_TRUE(transitions[0].fromStateId.has_value())
    << "a transition with no endpoints is an opaque id, not a graph edge";
  EXPECT_EQ(*transitions[0].fromStateId, node(fromStateTarget));
  ASSERT_TRUE(transitions[0].toStateId.has_value());
  EXPECT_EQ(*transitions[0].toStateId, node(toStateTarget))
    << "FromState and ToState must not be conflated - the direction is the whole point";
}

// Enrichment is best-effort: the entry ids are the contract, so a server that cannot answer the metadata
// reads still yields a Good topology with the ids intact.
TEST(ClientStateMachineFinite, FailedMetadataResolutionStillYieldsTheTopologyIds)
{
  Fixture f;
  const ua::NodeId ready = well_known(ua::ObjectId::ProgramStateMachineType_Ready);
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode),
    child_ref("AvailableTransitions", availableTransitionsNode)});
  f.push_read({dv_nodeid_array({ready}), dv_nodeid_array({})});
  // No translate handler and no scripted metadata Read: the enrichment cannot resolve anything.
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{ua::StatusCode{ua::Status::BadServiceUnsupported}});

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(44), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << "a metadata failure must not fail the whole topology";
  const auto states = captured->value().available_states();
  ASSERT_EQ(states.size(), 1U);
  EXPECT_EQ(states[0].stateId, ready);
  EXPECT_FALSE(states[0].number.has_value()) << "unresolved metadata stays empty rather than being invented";

  // The array was published and read; only the metadata lookup failed, and the caller can tell.
  const auto provenance = captured->value().topology_provenance();
  EXPECT_TRUE(provenance.statesPublished);
  EXPECT_FALSE(provenance.enrichmentComplete)
    << "an empty number must not read the same as one the server does not publish";
}

// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineFinite, EmptyTopologyWhenAvailablePropertiesAbsent)
{
  Fixture f;
  // Base resolution succeeds, but the machine exposes neither AvailableStates nor AvailableTransitions.
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({});  // machine HasProperty browse returns no AvailableStates/AvailableTransitions

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(42), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());  // absent topology is tolerated (empty), not an error
  EXPECT_TRUE(captured->value().available_states().empty());
  EXPECT_TRUE(captured->value().available_transitions().empty());
  EXPECT_TRUE(f.wireOps->readRequests.empty());  // nothing to Read when neither Property is present

  const auto provenance = captured->value().topology_provenance();
  EXPECT_FALSE(provenance.statesPublished);
  EXPECT_FALSE(provenance.transitionsPublished);
  EXPECT_TRUE(provenance.enrichmentComplete) << "nothing to enrich is not a failure to enrich";
}

/// OPC 10000-16 4.4.2 makes both arrays Optional, so a server may publish `AvailableStates` and leave it
/// empty. The topology then looks exactly like the absent case above - same empty vectors, same Good - and
/// only the provenance separates them.
// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineFinite, PublishedButEmptyTopologyIsDistinguishableFromAnAbsentOne)
{
  Fixture f;
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode)});  // published, no AvailableTransitions
  f.push_read({dv_nodeid_array({})});  // ...and the array it publishes is empty

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(45), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value().available_states().empty());
  EXPECT_TRUE(captured->value().available_transitions().empty());

  const auto provenance = captured->value().topology_provenance();
  EXPECT_TRUE(provenance.statesPublished) << "the server DID publish AvailableStates; it is simply empty";
  EXPECT_FALSE(provenance.transitionsPublished);
  EXPECT_TRUE(provenance.enrichmentComplete);
}

/// A published `AvailableStates` whose Value is Bad leaves the list empty as an empty array does, but the SDK
/// read no states: the provenance says the array was not read, so the empty list is not taken for an array
/// the server publishes empty. The topology is still Good, the Property being Optional.
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineFinite, APublishedTopologyWhoseValueIsBadIsNotReportedAsRead)
{
  Fixture f;
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode)});
  f.push_read({ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadNotReadable}}});

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(46), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value().available_states().empty());

  const auto provenance = captured->value().topology_provenance();
  EXPECT_FALSE(provenance.statesPublished) << "the AvailableStates Value was Bad, so the SDK read no states";
  EXPECT_FALSE(provenance.transitionsPublished);
}

// ===========================================================================
// ProgramStateMachineHandle::can_invoke_async (CL-SM-007)
// ===========================================================================

// @verifies CL-SM-007
// @relation(CL-SM-007, scope=function)
TEST(ClientStateMachineProgram, CanInvokeReadsExecutableAttribute)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(50));
  ASSERT_TRUE(handle.is_good());

  f.push_read({dv_bool(true)});
  std::optional<ua::Result<bool>> captured;
  handle.value().can_invoke_async(
    ProgramMethod::Start, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value());
  // The Read targets the Start method node's Executable Attribute.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  ASSERT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(startMethodNode));
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].attribute_id(), executableAttribute);
}

// @verifies CL-SM-007
// @relation(CL-SM-007, scope=function)
TEST(ClientStateMachineProgram, InvokeSkipsCallWhenNotExecutable)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(51));
  ASSERT_TRUE(handle.is_good());

  f.push_read({dv_bool(false)});  // Executable == false
  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Start, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotExecutable);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.method_not_executable");
  EXPECT_TRUE(f.wireOps->callRequests.empty());  // not executable -> no wire Call
}

// ===========================================================================
// ProgramStateMachineHandle::invoke_async (CL-SM-008 / CL-SM-009)
// ===========================================================================

// @verifies CL-SM-008
// @relation(CL-SM-008, scope=function)
TEST(ClientStateMachineProgram, InvokePassesArgumentsVerbatimAndComposesCall)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(52));
  ASSERT_TRUE(handle.is_good());

  // Suspend is valid from Running. Executable=true; CurrentState.Id=Running; Call succeeds.
  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  FakeWireOps::CallOutcome outcome;
  outcome.status = ua::StatusCode{ua::Status::Good};
  outcome.outputs.push_back(ua::Variant{std::int32_t{7}});
  f.wireOps->callOutcomes.push_back(std::move(outcome));

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(ProgramMethod::Suspend,
    {ua::Variant{std::int32_t{42}}},
    [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);
  const auto& methodCall = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(methodCall.object_id(), node(52));  // Call targets the machine Object
  EXPECT_EQ(methodCall.method_id(), node(suspendMethodNode));
  ASSERT_EQ(methodCall.input_arguments().size(), 1U);  // args are not padded
  EXPECT_EQ(methodCall.input_arguments()[0].to<std::int32_t>().value(), 42);  // verbatim
}

// @verifies CL-SM-008
// @relation(CL-SM-008, scope=function)
TEST(ClientStateMachineProgram, InvokeServerRejectSurfacesVerbatimWithMethodCallSource)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(53));
  ASSERT_TRUE(handle.is_good());

  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  FakeWireOps::CallOutcome outcome;
  outcome.status = ua::StatusCode{ua::Status::BadArgumentsMissing};  // server rejects verbatim
  f.wireOps->callOutcomes.push_back(std::move(outcome));

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadArgumentsMissing);  // status verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.method_call");
}

// @verifies CL-SM-009
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineProgram, LocalStateMethodMatrixBlocksInvalidTransition)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(54));
  ASSERT_TRUE(handle.is_good());

  // Suspend requires Running; the machine is Ready -> matrix mismatch, no wire Call.
  f.push_read({dv_bool(true)});  // Executable passes
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Ready))});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInvalidState);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.state_method_mismatch");
  EXPECT_TRUE(f.wireOps->callRequests.empty());  // matrix mismatch -> no wire Call
}

// @verifies CL-SM-009
// Table-driven gate for the whole ProgramMethod x ProgramState matrix (Part 10 Table 4), complementing the
// single-transition LocalStateMethodMatrixBlocksInvalidTransition above: invoke_async's CL-SM-009 pre-check
// must PERMIT a cause exactly from the states Table 4 names as its source states (Call issued) and BLOCK it
// from every other state (Bad_InvalidState, source state_method_mismatch, zero wire Calls). This is the
// reqs-doc client_program_state_machine_state_matrix_documents_method_validity gate. The Executable
// pre-flight is forced true throughout so the matrix is the sole gate; each combo's CurrentState.Id is the
// well-known Part-10 state Object NodeId.
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineProgram, ProgramMethodStateMatrixMatchesPart10Table4)
{
  struct State
  {
    ua::ObjectId id;
    const char* name;
  };

  const std::array<State, 4> states{{
    {ua::ObjectId::ProgramStateMachineType_Ready, "Ready"},
    {ua::ObjectId::ProgramStateMachineType_Running, "Running"},
    {ua::ObjectId::ProgramStateMachineType_Suspended, "Suspended"},
    {ua::ObjectId::ProgramStateMachineType_Halted, "Halted"},
  }};

  struct MethodRow
  {
    ProgramMethod method;
    const char* name;
    std::array<bool, 4> allowed;  ///< aligned to states[] = {Ready, Running, Suspended, Halted}
  };

  // Part 10 Table 4 (== the built matrix): Start from Ready; Suspend from Running; Resume from Suspended;
  // Halt from Ready/Running/Suspended; Reset from Running/Suspended/Halted (the *ToReady transitions); Stop
  // (the non-Part-10 convenience) from Running/Suspended.
  const std::array<MethodRow, 6> rows{{
    {ProgramMethod::Start, "Start", {{true, false, false, false}}},
    {ProgramMethod::Suspend, "Suspend", {{false, true, false, false}}},
    {ProgramMethod::Resume, "Resume", {{false, false, true, false}}},
    {ProgramMethod::Halt, "Halt", {{true, true, true, false}}},
    {ProgramMethod::Reset, "Reset", {{false, true, true, true}}},
    {ProgramMethod::Stop, "Stop", {{false, true, true, false}}},
  }};

  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(60));
  ASSERT_TRUE(handle.is_good());

  for (const auto& row : rows)
  {
    for (std::size_t s = 0; s < states.size(); ++s)
    {
      SCOPED_TRACE(std::string{row.name} + " from " + states[s].name);
      const bool allowed = row.allowed[s];
      const std::size_t callsBefore = f.wireOps->callRequests.size();

      f.push_read({dv_bool(true)});  // Executable=true so the matrix is the sole gate
      f.push_read({dv_nodeid(well_known(states[s].id))});  // CurrentState.Id for this state
      if (allowed)
      {
        FakeWireOps::CallOutcome outcome;
        outcome.status = ua::StatusCode{ua::Status::Good};
        f.wireOps->callOutcomes.push_back(std::move(outcome));
      }

      std::optional<ua::Result<ua::CallMethodResult>> captured;
      handle.value().invoke_async(
        row.method, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
      f.run();

      ASSERT_TRUE(captured.has_value());
      if (allowed)
      {
        EXPECT_TRUE(captured->is_good())
          << "Table 4 permits this cause from this state; the matrix must not block it";
        EXPECT_EQ(f.wireOps->callRequests.size(), callsBefore + 1)
          << "a permitted transition must issue exactly one wire Call";
      }
      else
      {
        ASSERT_TRUE(captured->is_bad())
          << "Table 4 forbids this cause from this state; the matrix must block it";
        EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInvalidState);
        ASSERT_NE(captured->shared_detail(), nullptr);
        EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.state_method_mismatch");
        EXPECT_EQ(f.wireOps->callRequests.size(), callsBefore)
          << "a blocked transition must issue no wire Call";
      }
    }
  }
}

// @verifies CL-SM-009
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineProgram, SkipLocalStateCheckBypassesMatrixAndCalls)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(55));
  ASSERT_TRUE(handle.is_good());
  ProgramStateMachineHandle unchecked = handle.value().skip_local_state_check();

  // Suspend from Ready would normally be blocked; the override skips the matrix (and its CurrentState.Id
  // Read).
  f.push_read({dv_bool(true)});  // Executable only
  f.wireOps->callOutcomes.push_back(FakeWireOps::CallOutcome{});  // Good, empty outputs

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  unchecked.invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);  // matrix bypassed -> the Call is issued
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].method_id(), node(suspendMethodNode));
  // Only the Executable Read was issued (no CurrentState.Id Read for the skipped matrix check).
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].attribute_id(), executableAttribute);
}

// @verifies CL-SM-009
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineProgram, StopAliasesHaltMethodFromActiveState)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(56));
  ASSERT_TRUE(handle.is_good());

  // Stop is a non-Part-10 convenience: valid from {Running, Suspended}, routed to the Halt method node.
  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  f.wireOps->callOutcomes.push_back(FakeWireOps::CallOutcome{});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Stop, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].method_id(), node(haltMethodNode));
}

// @verifies CL-SM-009
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineProgram, ResetIsValidFromRunning)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(58));
  ASSERT_TRUE(handle.is_good());

  // Part-10 ProgramStateMachineType: Reset is a valid cause from {Halted, Running, Suspended} (the
  // HaltedToReady / RunningToReady / SuspendedToReady transitions), not from Halted alone. Here the machine
  // is Running -> the local matrix must permit Reset and the wire Call is issued.
  f.push_read({dv_bool(true)});  // Executable passes
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  f.wireOps->callOutcomes.push_back(FakeWireOps::CallOutcome{});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Reset, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);  // exactly one Call issued
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].method_id(), node(resetMethodNode));
}

// @verifies CL-SM-009
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineProgram, ResetIsValidFromSuspended)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(59));
  ASSERT_TRUE(handle.is_good());

  // Reset is likewise valid from Suspended (SuspendedToReady).
  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Suspended))});
  f.wireOps->callOutcomes.push_back(FakeWireOps::CallOutcome{});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Reset, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].method_id(), node(resetMethodNode));
}

// @verifies CL-SM-007
// @relation(CL-SM-007, scope=function)
TEST(ClientStateMachineProgram, InvokeOnGoneInterfaceReturnsConnectionClosed)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(57));
  ASSERT_TRUE(handle.is_good());
  f.wireOps.reset();

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Start, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.connection_closed");
}

// ===========================================================================
// Wire-boundary error guards (result-count mismatches + empty responses)
// ===========================================================================

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineErrorBranch, CurrentStateReadCountMismatchIsBad)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(60));
  ASSERT_TRUE(handle.is_good());

  // The server under-returns: one DataValue for a two-ReadValueId CurrentState batch -> BadUnexpectedError.
  f.wireOps->resultsPerReadDelta = -1;
  f.push_read(
    {dv_localized("Running"), dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});

  std::optional<ua::client::StateVariableResult> captured;
  handle.value().current_state_async(
    [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.current_state");
}

// @verifies CL-SM-004
// @relation(CL-SM-004, scope=function)
TEST(ClientStateMachineErrorBranch, LastTransitionReadCountMismatchIsBad)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(61), /*withLastTransition=*/true);
  ASSERT_TRUE(handle.is_good());

  // The server under-returns one of the three expected DataValues (Value + Id + TransitionTime).
  f.wireOps->resultsPerReadDelta = -1;
  const ua::NodeId transitionId = well_known(ua::ObjectId::ProgramStateMachineType_RunningToHalted);
  f.push_read({dv_localized("RunningToHalted"), dv_nodeid(transitionId), dv_datetime(ua::DateTime{})});

  std::optional<ua::client::TransitionVariableResult> captured;
  handle.value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.last_transition");
}

// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineErrorBranch, TopologyReadCountMismatchIsBad)
{
  Fixture f;
  // The topology Read under-returns (one DataValue for the two present AvailableStates / AvailableTransitions
  // Values) -> construction fails BadUnexpectedError with the topology source (the W1 guard, ~:439).
  f.wireOps->resultsPerReadDelta = -1;
  FiniteStateMachineHandleResult handle = f.build_finite(node(62),
    {well_known(ua::ObjectId::ProgramStateMachineType_Ready)},
    {well_known(ua::ObjectId::ProgramStateMachineType_ReadyToRunning)});

  ASSERT_TRUE(handle.is_bad());
  EXPECT_EQ(handle.status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->source, "client.tier2.state_machine.topology");
}

// @verifies CL-SM-007
// @relation(CL-SM-007, scope=function)
TEST(ClientStateMachineErrorBranch, ExecutableReadEmptyIsBad)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(63));
  ASSERT_TRUE(handle.is_good());

  // The Executable Read returns zero DataValues -> BadUnexpectedError with the executable source (~:1123).
  f.wireOps->resultsPerReadDelta = -1;
  f.push_read({dv_bool(true)});

  std::optional<ua::Result<bool>> captured;
  handle.value().can_invoke_async(
    ProgramMethod::Start, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.executable");
}

// @verifies CL-SM-007
// @relation(CL-SM-007, scope=function)
TEST(ClientStateMachineErrorBranch, ExecutableDecodeNonBooleanIsBad)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(65));
  ASSERT_TRUE(handle.is_good());

  // The Executable Attribute Value holds a non-Boolean (a NodeId) -> decode Bad, executable source (~:1132).
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});

  std::optional<ua::Result<bool>> captured;
  handle.value().can_invoke_async(
    ProgramMethod::Start, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.executable");
}

// @verifies CL-SM-008
// @relation(CL-SM-008, scope=function)
TEST(ClientStateMachineErrorBranch, CallEmptyResultsIsBad)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(64));
  ASSERT_TRUE(handle.is_good());

  // Executable passes and the matrix allows (Suspend from Running), but the server returns a Good Call
  // response with NO result -> BadUnexpectedError tagged with the method-call source (~:1182).
  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  // No callOutcomes pushed -> the fake returns an empty CallResponse.

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.method_call");
}

// ===========================================================================
// StateMachineAccessor::subscribe_transitions_async (CL-SM-010 / CL-SM-011)
// ===========================================================================
//
// The wrapper is driven against a REAL EventSubscriberImpl (the section 8.13 backbone) wired to a mockable
// FakeEventBackboneOps: `event_subscriber()` returns the concrete, non-virtual, private-ctor
// EventSubscriberImpl, so a lightweight substitutable FakeEventSubscriber is not possible without making its
// subscribe methods virtual + its ctor protected (invasive to a section 3.1-reviewed strand component).
// Driving the real Impl over the existing narrow backbone interface is a STRONGER, real-path test: it asserts
// the composed EventFilter that actually reaches the wire and the real client-side demux/decode of a Publish
// notification.

// Minimal mockable backbone interface: records the composed EventFilter each create/modify sends, and hands
// back fixed server ids so a Publish can be routed back through on_publish_events_async.
class FakeEventBackboneOps : public EventBackboneOps
{
public:
  std::vector<ua::EventFilter> createFilters;
  std::uint32_t subscriptionId = 100;
  std::uint32_t monitoredItemId = 500;
  std::uint32_t clientHandle =
    0;  ///< the CLIENT-assigned backbone handle (the inbound demux key) the sub set

  void create_backbone_async(ua::NodeId /*notifier*/, ua::EventFilter filter, std::uint32_t clientHandleArg,
    std::uint32_t /*queueSize*/,
    std::function<void(ua::Result<EventBackboneCreated>)> callback) noexcept override
  {
    clientHandle = clientHandleArg;
    createFilters.push_back(std::move(filter));
    EventBackboneCreated created;
    created.subscriptionId = subscriptionId;
    created.monitoredItemId = monitoredItemId;
    callback(ua::Result<EventBackboneCreated>{created});
  }

  void modify_backbone_filter_async(std::uint32_t, std::uint32_t, std::uint32_t, ua::EventFilter,
    std::function<void(ua::Result<ua::client::detail::EventFilterDiagnostics>)> callback) noexcept override
  {
    callback(
      ua::Result<ua::client::detail::EventFilterDiagnostics>{ua::client::detail::EventFilterDiagnostics{}});
  }

  void delete_backbone_async(
    std::uint32_t, std::uint32_t, std::function<void(ua::VoidResult)> callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  // No type hierarchy in this fake: report the requested types as having no declared subtypes.
  void resolve_event_subtypes_async(std::vector<ua::NodeId> roots,
    std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback) noexcept override
  {
    callback(ua::Result<std::vector<ua::NodeId>>{std::move(roots)});
  }
};

const ua::NodeId transitionEventType{ua::ObjectTypeId::TransitionEventType};

// True iff @p filter carries a SelectClause whose BrowsePath equals @p path (ns0 segments).
bool has_select_clause(const ua::EventFilter& filter, const std::vector<std::string_view>& path)
{
  for (const auto& clause : filter.select_clauses())
  {
    if (clause.browse_path().size() != path.size())
    {
      continue;
    }
    bool matches = true;
    for (std::size_t i = 0; i < path.size(); ++i)
    {
      if (static_cast<std::string_view>(clause.browse_path()[i].name()) != path[i])
      {
        matches = false;
        break;
      }
    }
    if (matches)
    {
      return true;
    }
  }
  return false;
}

// The single OfType NodeId in a WhereClause (nullopt when absent / not an OfType-over-literal element).
std::optional<ua::NodeId> where_of_type(const ua::EventFilter& filter)
{
  for (const auto& element : filter.where_clause().elements())
  {
    if (element.filter_operator() != ua::FilterOperator::OfType || element.filter_operands().empty())
    {
      continue;
    }
    const auto* literal = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
    if (literal == nullptr)
    {
      continue;
    }
    if (const auto asNode = literal->value().to<ua::NodeId>(); asNode.is_good())
    {
      return asNode.value();
    }
  }
  return std::nullopt;
}

// Builds the 14-field EventFieldList in the backbone's composite SelectClause order: 8 BaseEventType
// mandatories, then Transition / Transition.Id / FromState / FromState.Id / ToState / ToState.Id.
ua::EventFieldList transition_event_fields(const ua::NodeId& sourceNode, const ua::NodeId& transitionId,
  std::string transitionName, const ua::NodeId& fromStateId, const ua::NodeId& toStateId, ua::DateTime time)
{
  ua::EventFieldList list;
  list.client_handle() = 0;
  list.event_fields().push_back(ua::Variant{ua::ByteString{}});  // EventId
  list.event_fields().push_back(ua::Variant{transitionEventType});  // EventType
  list.event_fields().push_back(ua::Variant{sourceNode});  // SourceNode
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "src"}});  // SourceName
  list.event_fields().push_back(ua::Variant{time});  // Time
  list.event_fields().push_back(ua::Variant{ua::DateTime{}});  // ReceiveTime
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "msg"}});  // Message
  list.event_fields().push_back(ua::Variant{std::uint16_t{700}});  // Severity
  list.event_fields().push_back(
    ua::Variant{ua::LocalizedText{ua::String{std::move(transitionName)}}});  // Transition
  list.event_fields().push_back(ua::Variant{transitionId});  // Transition.Id
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "from"}});  // FromState
  list.event_fields().push_back(ua::Variant{fromStateId});  // FromState.Id
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "to"}});  // ToState
  list.event_fields().push_back(ua::Variant{toStateId});  // ToState.Id
  return list;
}

struct SubscribeFixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> supportOps = std::make_shared<FakeSupportOps>();
  std::shared_ptr<FakeEventBackboneOps> backbone = std::make_shared<FakeEventBackboneOps>();
  std::shared_ptr<EventSubscriberImpl> subscriber =
    EventSubscriberImpl::create(ctx.get_executor(), backbone, ua::Logger{});

  SubscribeFixture()
  {
    supportOps->eventSubscriber = subscriber;
  }

  ua::client::StateMachineAccessor accessor()
  {
    return StateMachineClientTestAccess::make_accessor(wireOps, supportOps, ctx.get_executor());
  }

  void run()
  {
    ctx.run();
    ctx.restart();
  }
};

// @verifies CL-SM-010
// @relation(CL-SM-010, scope=function)
TEST(ClientStateMachineSubscribeTransitions, BuildsOfTypeAndTransitionSelectClauses)
{
  SubscribeFixture f;
  std::optional<MonitoredItemResult> item;
  f.accessor().subscribe_transitions_async(
    node(10), [](TransitionEventNotification) {}, [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();

  ASSERT_TRUE(item.has_value());
  ASSERT_TRUE(item->is_good());
  EXPECT_EQ(item->value().kind(), MonitoredItemKind::Event);

  // The composed filter that actually reached the backbone.
  ASSERT_EQ(f.backbone->createFilters.size(), 1u);
  const ua::EventFilter& filter = f.backbone->createFilters[0];

  // CL-SM-010: OfType(TransitionEventType) WhereClause.
  const auto ofType = where_of_type(filter);
  ASSERT_TRUE(ofType.has_value());
  EXPECT_EQ(*ofType, transitionEventType);

  // CL-SM-010: SelectClauses for Transition / FromState / ToState and their Id Properties.
  EXPECT_TRUE(has_select_clause(filter, {"Transition"}));
  EXPECT_TRUE(has_select_clause(filter, {"Transition", "Id"}));
  EXPECT_TRUE(has_select_clause(filter, {"FromState"}));
  EXPECT_TRUE(has_select_clause(filter, {"FromState", "Id"}));
  EXPECT_TRUE(has_select_clause(filter, {"ToState"}));
  EXPECT_TRUE(has_select_clause(filter, {"ToState", "Id"}));
}

// @verifies CL-SM-011
// @relation(CL-SM-011, scope=function)
TEST(ClientStateMachineSubscribeTransitions, DecodesMatchingSourceNodeIntoTransitionEventNotification)
{
  SubscribeFixture f;
  std::vector<TransitionEventNotification> delivered;
  f.accessor().subscribe_transitions_async(
    node(10),
    [&delivered](TransitionEventNotification n) { delivered.push_back(std::move(n)); },
    [](MonitoredItemResult) {});
  f.run();

  const ua::NodeId transitionId = node(51);
  const ua::NodeId fromStateId = node(52);
  const ua::NodeId toStateId = node(53);
  const ua::DateTime time{2026, 7, 18, 9, 30, 0.0};
  f.subscriber->on_publish_events_async(f.backbone->clientHandle,
    {transition_event_fields(node(10), transitionId, "Ready->Running", fromStateId, toStateId, time)},
    [] {});
  f.run();

  ASSERT_EQ(delivered.size(), 1u);
  EXPECT_EQ(delivered[0].sourceNode, node(10));
  EXPECT_EQ(delivered[0].transitionId, transitionId);
  EXPECT_EQ(static_cast<std::string>(delivered[0].transitionName.text()), "Ready->Running");
  EXPECT_EQ(delivered[0].fromStateId, fromStateId);
  EXPECT_EQ(delivered[0].toStateId, toStateId);
  EXPECT_EQ(delivered[0].time, time);
}

// @verifies CL-SM-011
// The CL-SM-011 sourceNode demux: a TransitionEvent for a DIFFERENT machine must NOT reach this consumer.
// @verifies CL-SM-011
// section 3.1 W-3: the TransitionEvent field array is server-controlled - a wrong-type or null field must
// decode safely (no throw across the noexcept decode, no UB - the 10d-C1/11a-C1 class) with the undecodable
// field defaulted (NodeId{}), and the callback must still fire (demuxed on the present SourceNode).
// @relation(CL-SM-011, scope=function)
TEST(ClientStateMachineSubscribeTransitions, MalformedEventFieldArrayDecodesSafelyWithDefaults)
{
  SubscribeFixture f;
  std::vector<TransitionEventNotification> delivered;
  f.accessor().subscribe_transitions_async(
    node(10),
    [&delivered](TransitionEventNotification n) { delivered.push_back(std::move(n)); },
    [](MonitoredItemResult) {});
  f.run();

  // (a) A wrong-type Transition.Id (a String where a NodeId is expected): still demuxes on SourceNode; the
  // undecodable Transition.Id defaults to NodeId{}; no throw/UB.
  ua::EventFieldList wrongType =
    transition_event_fields(node(10), node(51), "X", node(52), node(53), ua::DateTime{});
  wrongType.event_fields()[9] = ua::Variant{ua::String{"not-a-nodeid"}};  // Transition.Id slot
  f.subscriber->on_publish_events_async(f.backbone->clientHandle, {wrongType}, [] {});
  f.run();
  ASSERT_EQ(delivered.size(), 1u);
  EXPECT_EQ(delivered[0].sourceNode, node(10));
  EXPECT_EQ(delivered[0].transitionId, ua::NodeId{});  // wrong-type => default, not a crash

  // (b) Null Id fields (empty Variants): each undecodable Id defaults; the callback still fires.
  ua::EventFieldList nullIds =
    transition_event_fields(node(10), node(51), "Y", node(52), node(53), ua::DateTime{});
  nullIds.event_fields()[9] = ua::Variant{};  // Transition.Id
  nullIds.event_fields()[11] = ua::Variant{};  // FromState.Id
  nullIds.event_fields()[13] = ua::Variant{};  // ToState.Id
  f.subscriber->on_publish_events_async(f.backbone->clientHandle, {nullIds}, [] {});
  f.run();
  ASSERT_EQ(delivered.size(), 2u);
  EXPECT_EQ(delivered[1].sourceNode, node(10));
  EXPECT_EQ(delivered[1].transitionId, ua::NodeId{});
  EXPECT_EQ(delivered[1].fromStateId, ua::NodeId{});
  EXPECT_EQ(delivered[1].toStateId, ua::NodeId{});
}

TEST(ClientStateMachineSubscribeTransitions, FiltersOutNotificationsForADifferentSourceNode)
{
  SubscribeFixture f;
  std::vector<TransitionEventNotification> delivered;
  f.accessor().subscribe_transitions_async(
    node(10),
    [&delivered](TransitionEventNotification n) { delivered.push_back(std::move(n)); },
    [](MonitoredItemResult) {});
  f.run();

  // Event for machine node(99) - the wrapper (subscribed to node(10)) must drop it.
  f.subscriber->on_publish_events_async(f.backbone->clientHandle,
    {transition_event_fields(node(99), node(51), "X", node(52), node(53), ua::DateTime{})},
    [] {});
  f.run();
  EXPECT_TRUE(delivered.empty());

  // A matching event for node(10) still gets through (the filter is a demux, not a mute).
  f.subscriber->on_publish_events_async(f.backbone->clientHandle,
    {transition_event_fields(node(10), node(51), "Y", node(52), node(53), ua::DateTime{})},
    [] {});
  f.run();
  ASSERT_EQ(delivered.size(), 1u);
  EXPECT_EQ(delivered[0].sourceNode, node(10));
}

// @verifies CL-SM-010
// @relation(CL-SM-010, scope=function)
TEST(ClientStateMachineSubscribeTransitions, GoneEventSubscriberReturnsConnectionClosed)
{
  SubscribeFixture f;
  f.supportOps->eventSubscriber = nullptr;  // no backbone available == a gone interface

  std::optional<MonitoredItemResult> item;
  f.accessor().subscribe_transitions_async(
    node(10), [](TransitionEventNotification) {}, [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();

  ASSERT_TRUE(item.has_value());
  ASSERT_TRUE(item->is_bad());
  EXPECT_EQ(item->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(item->shared_detail(), nullptr);
  EXPECT_EQ(item->shared_detail()->source, "client.tier2.state_machine.subscribe_transitions");
}

// ===========================================================================
// ServiceFault flatten (error_handling.md): each Browse / Read / Call continuation returns the response
// VERBATIM from the tier-0 funnel, so a bad ResponseHeader.serviceResult must surface that EXACT service
// status - never masked as Bad_UnexpectedError by the empty/count-mismatch branch, nor silently returned
// Good. One test per DISTINCT flatten site.
// ===========================================================================

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineServiceFault, BrowseChildrenSurfacesBadServiceResultDuringConstruction)
{
  Fixture f;
  // The HasComponent children Browse returns a Good-transport response whose SERVICE-level serviceResult is
  // bad, with an empty results[]. Without the flatten, construction masks it as Bad_UnexpectedError.
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->browseOmitResults = true;

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(200), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTooManyOperations);  // verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineBrowseServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.construction");
}

// @verifies CL-SM-001
// @relation(CL-SM-001, scope=function)
TEST(ClientStateMachineServiceFault, DrainChildrenSurfacesBadBrowseNextServiceResultDuringConstruction)
{
  Fixture f;
  // Page 1 of the HasComponent Browse carries a non-empty continuation point (Good), so drain_children issues
  // a BrowseNext; that BrowseNext returns a bad SERVICE-level serviceResult with an empty results[].
  FakeWireOps::BrowsePage firstPage;
  firstPage.references.push_back(child_ref("SomeChild", 900));
  firstPage.continuationPoint = ua::ContinuationPoint{0x01};
  f.wireOps->browsePages.push_back(std::move(firstPage));
  f.wireOps->browseNextHeaderServiceResult = ua::StatusCode{ua::Status::BadSessionIdInvalid};
  f.wireOps->browseNextOmitResults = true;

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(201), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);  // verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineBrowseNextServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.construction");
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(ClientStateMachineServiceFault, DrainChildrenEmptyPagesBeyondTheLimitEndTheDrainDuringConstruction)
{
  Fixture f;
  FakeWireOps::BrowsePage firstPage;
  firstPage.references.push_back(child_ref("SomeChild", 900));
  firstPage.continuationPoint = ua::ContinuationPoint{0x01};
  f.wireOps->browsePages.push_back(std::move(firstPage));
  FakeWireOps::BrowsePage looping;
  looping.continuationPoint = ua::ContinuationPoint{0x01};
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->browsePages.push_back(looping);
  }

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(201), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "BrowseDrainEmptyPageLimitExceeded");
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 12U)
    << "eleven reads, then one release of the point the server still holds";
}

// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST(ClientStateMachineServiceFault, TopologyReadSurfacesBadServiceResultDuringFiniteConstruction)
{
  Fixture f;
  // Base resolution (browse-only) succeeds; the topology HasProperty Browse succeeds; the batched
  // AvailableStates / AvailableTransitions Read returns a bad SERVICE-level serviceResult with empty
  // results[].
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode),
    child_ref("AvailableTransitions", availableTransitionsNode)});
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{read_service_fault(ua::Status::BadSessionClosed)});

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(202), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineTopologyServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.topology");
}

// @verifies CL-SM-002
// @relation(CL-SM-002, scope=function)
TEST(ClientStateMachineServiceFault, CurrentStateSurfacesBadServiceResult)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(203));
  ASSERT_TRUE(handle.is_good());

  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{read_service_fault(ua::Status::BadSessionIdInvalid)});

  std::optional<ua::client::StateVariableResult> captured;
  handle.value().current_state_async(
    [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentStateServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.current_state");
}

// @verifies CL-SM-004
// @relation(CL-SM-004, scope=function)
TEST(ClientStateMachineServiceFault, LastTransitionSurfacesBadServiceResult)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(204), /*withLastTransition=*/true);
  ASSERT_TRUE(handle.is_good());

  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{read_service_fault(ua::Status::BadTooManyOperations)});

  std::optional<ua::client::TransitionVariableResult> captured;
  handle.value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(
    captured->status_code().as_status(), ua::Status::BadTooManyOperations);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineLastTransitionServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.last_transition");
}

// @verifies CL-SM-003
// @relation(CL-SM-003, scope=function)
TEST(ClientStateMachineServiceFault, CurrentStateIsSurfacesBadServiceResult)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(205));
  ASSERT_TRUE(handle.is_good());

  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{read_service_fault(ua::Status::BadSessionClosed)});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(well_known(ua::ObjectId::ProgramStateMachineType_Running),
    [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentStateIdServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.current_state_is");
}

// @verifies CL-SM-007
// @relation(CL-SM-007, scope=function)
TEST(ClientStateMachineServiceFault, ReadExecutableSurfacesBadServiceResult)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(206));
  ASSERT_TRUE(handle.is_good());

  // The Executable Read returns a bad SERVICE-level serviceResult with empty results[].
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{read_service_fault(ua::Status::BadUserAccessDenied)});

  std::optional<ua::Result<bool>> captured;
  handle.value().can_invoke_async(
    ProgramMethod::Start, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUserAccessDenied);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineExecutableServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.executable");
}

// @verifies CL-SM-008
// @relation(CL-SM-008, scope=function)
TEST(ClientStateMachineServiceFault, MethodCallSurfacesBadServiceResult)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(207));
  ASSERT_TRUE(handle.is_good());

  // Executable passes and the matrix allows (Suspend from Running); the Call itself returns a bad
  // SERVICE-level serviceResult with empty results[].
  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  f.wireOps->callHeaderServiceResult = ua::StatusCode{ua::Status::BadSessionIdInvalid};

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCallServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.method_call");
}

// @verifies CL-SM-009
// @relation(CL-SM-009, scope=function)
TEST(ClientStateMachineServiceFault, InvokeStep2CurrentStateIdReadSurfacesBadServiceResult)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(208));
  ASSERT_TRUE(handle.is_good());

  // Executable passes (first scripted read); the step-2 CurrentState.Id matrix Read returns a bad
  // SERVICE-level serviceResult with empty results[] (second scripted read).
  f.push_read({dv_bool(true)});
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{read_service_fault(ua::Status::BadSessionClosed)});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "StateMachineCurrentStateIdReadServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.state_machine.state_method_mismatch");
  EXPECT_TRUE(f.wireOps->callRequests.empty());  // the matrix read faulted -> no wire Call issued
}

// ===========================================================================
// Status routing: the server's code reaches the application; the SDK acts only on Good answers
// ===========================================================================

ua::DataValue with_status(ua::DataValue value, ua::Status status)
{
  value.status() = ua::StatusCode{status};
  return value;
}

// A Good subcode on the program Method's statusCode reaches the caller on the Result, with the
// CallMethodResult.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientStateMachineStatusRouting, AnInvokesGoodSubcodeReachesTheApplication)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    Fixture f;
    ProgramStateMachineHandleResult handle = f.build_program(node(300));
    ASSERT_TRUE(handle.is_good());
    f.push_read({dv_bool(true)});
    f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
    FakeWireOps::CallOutcome outcome;
    outcome.status = ua::StatusCode{methodStatus};
    if (methodStatus == ua::Status::GoodClamped)
    {
      outcome.outputs.push_back(ua::Variant{std::int32_t{5}});
    }
    f.wireOps->callOutcomes.push_back(std::move(outcome));

    std::optional<ua::Result<ua::CallMethodResult>> captured;
    handle.value().invoke_async(ProgramMethod::Suspend,
      {},
      [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
    f.run();

    ASSERT_TRUE(captured.has_value());
    ASSERT_TRUE(captured->is_good());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{methodStatus});
    EXPECT_EQ(captured->value().status_code(), ua::StatusCode{methodStatus});
    if (methodStatus == ua::Status::GoodClamped)
    {
      ASSERT_EQ(captured->value().output_arguments().size(), 1U);
      EXPECT_EQ(captured->value().output_arguments()[0], ua::Variant{std::int32_t{5}});
    }
    else
    {
      EXPECT_TRUE(captured->value().output_arguments().empty());
    }
  }
}

// An Uncertain statusCode of the program Method is the Result's code, with the CallMethodResult held.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientStateMachineStatusRouting, AnInvokesUncertainCodeReachesTheApplication)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(301));
  ASSERT_TRUE(handle.is_good());
  f.push_read({dv_bool(true)});
  f.push_read({dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
  FakeWireOps::CallOutcome outcome;
  outcome.status = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
  outcome.outputs.push_back(ua::Variant{std::int32_t{5}});
  f.wireOps->callOutcomes.push_back(std::move(outcome));

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable});
  EXPECT_EQ(captured->value_or(ua::CallMethodResult{}).output_arguments().size(), 1U);
  ASSERT_TRUE(captured->has_value());
  ASSERT_FALSE(captured->value().output_arguments().empty());
  EXPECT_EQ(captured->value().output_arguments()[0], ua::Variant{std::int32_t{5}});
}

// The Executable flag the SDK decides on is used only when Good: an Uncertain one refuses the invoke with
// Bad_InternalError (ReadAnswerUncertain) and nothing is called.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainExecutableRefusesTheInvoke)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(302));
  ASSERT_TRUE(handle.is_good());
  f.push_read({with_status(dv_bool(true), ua::Status::UncertainLastUsableValue)});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Start, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// The CurrentState.Id the matrix decides on is used only when Good: an Uncertain one refuses the invoke with
// Bad_InternalError (ReadAnswerUncertain) and nothing is called.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainCurrentStateIdRefusesTheInvoke)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(303));
  ASSERT_TRUE(handle.is_good());
  f.push_read({dv_bool(true)});
  f.push_read({with_status(dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running)),
    ua::Status::UncertainLastUsableValue)});

  std::optional<ua::Result<ua::CallMethodResult>> captured;
  handle.value().invoke_async(
    ProgramMethod::Suspend, {}, [&captured](ua::Result<ua::CallMethodResult> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// can_invoke answers the application, so an Uncertain Executable gives the flag with the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainExecutableGivesCanInvokeItsCode)
{
  Fixture f;
  ProgramStateMachineHandleResult handle = f.build_program(node(304));
  ASSERT_TRUE(handle.is_good());
  f.push_read({with_status(dv_bool(true), ua::Status::UncertainLastUsableValue)});

  std::optional<ua::Result<bool>> captured;
  handle.value().can_invoke_async(
    ProgramMethod::Start, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_TRUE(captured->value_or(false));
}

// current_state_is answers with the CurrentState.Id Read's code: an Uncertain Id gives the comparison with
// the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainCurrentStateIdGivesTheComparisonWithItsCode)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(305));
  ASSERT_TRUE(handle.is_good());
  const ua::NodeId running = well_known(ua::ObjectId::ProgramStateMachineType_Running);
  f.push_read({with_status(dv_nodeid(running), ua::Status::UncertainLastUsableValue)});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(
    running, [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_TRUE(captured->value_or(false));
}

// A Bad CurrentState.Id fails current_state_is with that code (it is not a Good "not in this state").
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, ABadCurrentStateIdFailsTheComparison)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(306));
  ASSERT_TRUE(handle.is_good());
  f.push_read({ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}}});

  std::optional<ua::Result<bool>> captured;
  handle.value().current_state_is_async(well_known(ua::ObjectId::ProgramStateMachineType_Running),
    [&captured](ua::Result<bool> r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUserAccessDenied);
}

// An Uncertain Id Property is not hidden behind a Good CurrentState: StateVariable.statusCode carries it.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainIdReachesTheStateVariablesStatus)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(307));
  ASSERT_TRUE(handle.is_good());
  f.push_read({dv_localized("Running"),
    with_status(dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running)),
      ua::Status::UncertainLastUsableValue)});

  std::optional<ua::client::StateVariableResult> captured;
  handle.value().current_state_async(
    [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().statusCode, ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_EQ(captured->value().id, well_known(ua::ObjectId::ProgramStateMachineType_Running));
}

// A Good subcode on the CurrentState Read's ServiceResult reaches the caller on the outer Result.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientStateMachineStatusRouting, ACurrentStateReadsServiceResultGoodSubcodeReachesTheApplication)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    StateMachineHandleResult handle = f.build_base(node(308));
    ASSERT_TRUE(handle.is_good());
    ua::ReadResponse response = read_response(
      {dv_localized("Running"), dv_nodeid(well_known(ua::ObjectId::ProgramStateMachineType_Running))});
    response.response_header().service_result() = ua::StatusCode{serviceStatus};
    f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

    std::optional<ua::client::StateVariableResult> captured;
    handle.value().current_state_async(
      [&captured](ua::client::StateVariableResult r) { captured = std::move(r); });
    f.run();

    ASSERT_TRUE(captured.has_value());
    ASSERT_TRUE(captured->is_good());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{serviceStatus});
    EXPECT_EQ(captured->value().name.text(), ua::String{"Running"});
    ASSERT_TRUE(captured->value().id.has_value());
    EXPECT_EQ(*captured->value().id, well_known(ua::ObjectId::ProgramStateMachineType_Running));
  }
}

// last_transition answers with the Read's code: an Uncertain LastTransition with a value gives the
// transition with the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainLastTransitionKeepsItsValueAndCode)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(309), /*withLastTransition=*/true);
  ASSERT_TRUE(handle.is_good());
  f.push_read({with_status(dv_localized("HaltedToReady"), ua::Status::UncertainLastUsableValue),
    dv_nodeid(node(4000)),
    dv_datetime(ua::DateTime{2026, 7, 24, 12, 0, 0.0})});

  std::optional<ua::client::TransitionVariableResult> captured;
  handle.value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_EQ(captured->value_or(TransitionVariable{}).id, node(4000));
}

// The pre-flight the handle keeps uses only Good answers: an Uncertain Browse page refuses the build with
// Bad_InternalError (ReferencesAnswerUncertain).
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainComponentBrowseRefusesTheHandle)
{
  Fixture f;
  FakeWireOps::BrowsePage page;
  page.references.push_back(child_ref("CurrentState", currentStateNode));
  page.status = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
  f.wireOps->browsePages.push_back(std::move(page));

  std::optional<StateMachineHandleResult> captured;
  f.accessor().state_machine_async(
    node(310), [&captured](StateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReferencesAnswerUncertain");
}

// The topology the handle keeps uses only Good answers: an Uncertain AvailableStates value refuses the build
// with Bad_InternalError (ReadAnswerUncertain).
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, AnUncertainAvailableStatesRefusesTheFiniteHandle)
{
  Fixture f;
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode)});
  f.push_read({with_status(dv_nodeid_array({node(500)}), ua::Status::UncertainLastUsableValue)});

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(311), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReadAnswerUncertain");
}

// AvailableStates is Optional: a Bad value is not decoded, its list is left empty and the handle is built.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, ABadAvailableStatesLeavesTheListEmptyAndBuildsTheFiniteHandle)
{
  Fixture f;
  f.script_base(/*withLastTransition=*/false, /*withMethods=*/false);
  f.push_browse({child_ref("AvailableStates", availableStatesNode)});
  f.push_read({ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}}});

  std::optional<FiniteStateMachineHandleResult> captured;
  f.accessor().finite_state_machine_async(
    node(312), [&captured](FiniteStateMachineHandleResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value().available_states().empty());
}

// The optional Id and TransitionTime Properties do not decide the transition: a Bad one leaves its field
// unset (the time falls back to LastTransition's SourceTimestamp) and the transition is answered Good.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientStateMachineStatusRouting, ABadIdOrTransitionTimeLeavesTheFieldUnsetAndKeepsTheTransition)
{
  Fixture f;
  StateMachineHandleResult handle = f.build_base(node(313), /*withLastTransition=*/true);
  ASSERT_TRUE(handle.is_good());
  const ua::DateTime sourceTime{2026, 7, 20, 8, 15, 0.0};
  ua::DataValue lastTransitionValue = dv_localized("HaltedToReady");
  lastTransitionValue.source_timestamp() = sourceTime;
  f.push_read({lastTransitionValue,
    ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}},
    ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}}});

  std::optional<ua::client::TransitionVariableResult> captured;
  handle.value().last_transition_async(
    [&captured](ua::client::TransitionVariableResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::Good});
  EXPECT_EQ(static_cast<std::string>(captured->value().name.text()), "HaltedToReady");
  EXPECT_FALSE(captured->value().id.has_value());
  ASSERT_TRUE(captured->value().transitionTime.has_value());
  EXPECT_EQ(*captured->value().transitionTime, sourceTime);
}

}  // namespace
