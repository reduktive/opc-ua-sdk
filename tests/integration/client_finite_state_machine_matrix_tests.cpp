// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientFiniteStateMachine` integration cluster of the client integration-test matrix (the
///        `ClientFiniteStateMachine.*` rows, spec ref section 8.18.4.2, CL-SM-005 / CL-SM-006; client design
///        section 8.18.1.b). These drive the TIER-2 `FiniteStateMachineType` typed-access facade end-to-end
///        through the PUBLIC `ua::client::Connection` (`Connection::state_machine_accessor()` ->
///        `StateMachineAccessor::finite_state_machine_async` -> `FiniteStateMachineHandle`) over a REAL
///        reference server, exercising the resolved AvailableStates/AvailableTransitions topology, the
///        CurrentState.Id identity comparison, and the handle-owned topology cache / explicit
///        `refresh_topology_async` re-read.
///
/// HARNESS: the `client_state_machine_matrix_tests.cpp` fixture pattern - a `ComplianceWithNodes` server
/// extended with `FiniteStateMachineType` Object instances, an activated Session handed to a started
/// `ConnectionImpl`, then wrapped into the public `ua::client::Connection` via `ConnectionHandleFactory`, so
/// the resolution runs the genuine managed Browse+Read path. The matrix names a MisbehavingServer for the
/// subtype / sequenced-read rows, but that fixture owns a nodeless server with no interface to add a
/// namespace, so a machine's pre-flight Browse would fail there. This cluster therefore co-locates the real
/// state-machine nodes and the deterministic request-observer interface
/// (`ServerImplTestAccess::set_on_secure_channel_available`
/// + `SecureChannelTestAccess::set_request_observer`, the same interface MisbehavingServer uses) on one
/// server, and drives the topology change via a server-side address-space write (the change a
/// GeneralModelChangeEvent would announce). Timing: every completion is bridged off the executor via
/// `std::promise`; only the test thread blocks on a future. No fixed sleeps.
///
/// KEY INVESTIGATION FINDINGS (the required forensic results this file pins):
///
///   1. AVAILABLESTATES / AVAILABLETRANSITIONS RESOLUTION IS BUILT END-TO-END. `finite_state_machine_async`
///      runs `resolve_topology` (ua_state_machine_access.cpp:427): a one-level HasProperty Browse of the
///      machine matches the ns0 `AvailableStates` / `AvailableTransitions` Properties, then a single batched
///      Read of their Values decodes each `NodeId[]` into the topology (decode_states :391 /
///      decode_transitions :408 keep the state/transition Object NodeId only - name/number are not resolved
///      in v1). Row ResolvesAvailableStatesAndTransitions pins the exact resolved sets against a known server
///      machine.
///
///   2. CURRENTSTATE.ID IDENTITY NORMALIZES REPLICATED SUBTYPE OBJECTS (CL-SM-006).
///      `current_state_is_async` reads `CurrentState.Id`; raw equality remains the fast path. On a mismatch,
///      both NodeIds are resolved through their inverse HasComponent owner and the owner's inverse HasSubtype
///      chain, matching the same-BrowseName State replica required by Part 16 section 4.4.18. The resulting
///      first-definition NodeIds are compared. A null/empty CurrentState.Id still compares false. Rows
///      StateIdDoesNotMatchUnrelatedState and SubtypeStateIdEqualsSupertypeIdNodeId pin the two CL-SM-006
///      directions: unrelated states remain distinct, while a caller-supplied subtype State Object matches
///      the supertype-origin Id reported by the server.
///
///   3. AN ABSENT TOPOLOGY SURFACES AS AN EMPTY LIST + A GOOD HANDLE - NOT A HARD FAILURE, NOT `nullopt`.
///      `resolve_topology` returns an empty (Good) `Topology` when neither Available* Property is present
///      (:446), and `finite_state_machine_async` still constructs the handle. CALIBRATION (row
///      AvailableStatesAbsentSurfacesNullopt): the BUILT accessor `available_states()` returns
///      `std::vector<AvailableState>` - never `std::optional` - so "surfaces nullopt" is not representable in
///      the built API; the real absent-behaviour is an EMPTY vector. This row keeps the strong part (handle
///      still constructs / not a hard Bad Result) and locks the empty-list outcome, resolving the matrix
///      drift (section 5.x #4) to the single built behaviour.
///
///   4. THE TOPOLOGY CACHE IS HANDLE-OWNED, RESOLVED ONCE AT CONSTRUCTION, AND IS NEVER AUTO-INVALIDATED BY A
///      MODEL CHANGE. `available_states()` / `available_transitions()` load the atomically-published snapshot
///      captured at construction (ua_state_machine_access.cpp:1305/1317); the ONLY re-read is the explicit
///      `refresh_topology_async` (:1327). Two forensic facts establish that a model change does not touch it:
///      `refresh_topology_async` has ZERO internal callers anywhere in the SDK (it is application-driven),
///      and the model-change route `AddressSpaceCache::on_model_change_async` is called ONLY from
///      ua_event_router.cpp:426 and invalidates the alias / attribute / Browse sub-caches - it has no
///      connection to any FiniteStateMachineHandle's topology snapshot. So a server-side topology change is
///      invisible to a live handle until the application calls `refresh_topology_async`.
///      - This is why the matrix DROPPED `ModelChangeInvalidatesTopologyCache` as "contradicts adopted
///      design"
///        (matrix line 1079): the adopted design is explicit-refresh, not auto-invalidation. This file
///        authors that row in its CALIBRATED form - it asserts the REAL behaviour (stale-until-refresh, i.e.
///        NO auto-invalidation) and documents that this is BY DESIGN, not a defect. The assertion is
///        falsifiable: it would flip the moment auto-invalidation is wired, forcing a design revisit.
///      - Row TopologyReReadOnRefreshNotCachedStale (calibrated per the matrix note: the design never serves
///      a
///        stale value across an explicit refresh) then pins that `refresh_topology_async` issues a GENUINE
///        second wire Read - evidenced by a request-observer read count of exactly two against the sequenced
///        server value - and surfaces the new value in array order.
///
/// Falsifiability: every row encodes its matrix `[neg: ...]` falsifier and asserts the EXACT observable, with
/// a positive control where an always-false / always-true comparison would otherwise pass vacuously.

#include "compliance_helpers.h"
#include "requests.h"

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_state_machine_access.h"

#include "ua_access_level_type.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_base_event.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_filter_operator.h"
#include "ua_instantiation_options.h"
#include "ua_instantiation_service.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_node_subtree.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_server_configuration.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_simple_attribute_operand.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;

namespace
{

// Runs the ConnectionImpl bootstrap and blocks (on the test thread) until it completes.
VoidResult start_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// Closes the ConnectionImpl and blocks (on the test thread) until it completes.
VoidResult close_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// Well-known ns0 Part-10 state / transition Object NodeIds, reused as state identities (CL-SM-006 Id reuse).
// These are only NodeID *values* stored in the AvailableStates / AvailableTransitions arrays and in the
// CurrentState.Id Property - the client stores/compares them verbatim and never dereferences them, so they do
// not need to exist as real nodes.
const NodeId runningStateNode{ObjectId::ProgramStateMachineType_Running};
const NodeId readyStateNode{ObjectId::ProgramStateMachineType_Ready};
const NodeId suspendedStateId{ObjectId::ProgramStateMachineType_Suspended};
const NodeId haltedStateId{ObjectId::ProgramStateMachineType_Halted};
const NodeId runningToSuspendedId{ObjectId::ProgramStateMachineType_RunningToSuspended};

// A read-only counter of the Reads that referenced a single target node (the AvailableStates Property of the
// re-read machine). Populated on a server strand by the per-channel request observer (which fires at the top
// of request handling, BEFORE the response), read by the test thread; the two run concurrently, hence the
// mutex. Each `resolve_topology` issues exactly one Read of that node, so the count == the number of topology
// resolutions the client performed (1 at construction, +1 per refresh).
struct TargetReadCounter
{
  mutable std::mutex mutex;
  NodeId target;
  int count{0};

  void observe(const ua::Structure& request)
  {
    const auto* read = dynamic_cast<const ua::ReadRequest*>(&request);
    if (read == nullptr)
    {
      return;
    }
    std::lock_guard lock(mutex);
    for (const auto& readValue : read->nodes_to_read())
    {
      if (readValue.node_id() == target)
      {
        ++count;
        break;  // one increment per Read that touches the target, regardless of batch size
      }
    }
  }

  int reads() const
  {
    std::lock_guard lock(mutex);
    return count;
  }

  void set_target(NodeId node)
  {
    std::lock_guard lock(mutex);
    target = std::move(node);
  }
};

// Every Event the running server emitted, captured through the PUBLIC `Server::set_event_listener` interface
// (ua_server.h), which the EventBus invokes for each Event before subscriber fan-out. Recorded on the bus
// dispatch strand and read from the test thread, hence the mutex; each Event is CLONED because the listener
// only borrows its argument for the duration of the call. `wait_until` is a bounded wait rather than a sleep:
// it returns the instant the Events arrive, and the deadline only bounds the failure case. The predicate runs
// under the mutex, so it must stay a pure inspection of the captured Events - a blocking address-space lookup
// inside it would hold the recorder against the strand that is trying to fill it.
struct EmittedEventRecorder
{
  using Captured = std::vector<std::shared_ptr<const ua::BaseEvent>>;

  mutable std::mutex mutex;
  std::condition_variable arrived;
  Captured events;

  void record(const ua::BaseEvent& event)
  {
    {
      std::lock_guard lock(mutex);
      events.push_back(std::shared_ptr<const ua::BaseEvent>{event.clone()});
    }
    arrived.notify_all();
  }

  Captured wait_until(
    const std::function<bool(const Captured&)>& satisfied, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock(mutex);
    arrived.wait_for(lock, timeout, [&] { return satisfied(events); });
    return events;
  }
};

}  // namespace

// ============================================================================================================
// Fixture - ComplianceWithNodes extended with FiniteStateMachineType instances, driven through the PUBLIC
// Connection. Suite name `ClientFiniteStateMachine` (tests named exactly `ClientFiniteStateMachine.<Row>`).
// ============================================================================================================
class ClientFiniteStateMachine : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    // FM1 (9000): a finite machine declaring AvailableStates = [Ready, Halted] and AvailableTransitions =
    // [RunningToSuspended], plus the Mandatory CurrentState "Running" + Id. Serves
    // ResolvesAvailableStatesAndTransitions.
    {
      auto machine = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9000}}, "FmTopology");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9001}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{9002}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateNode}});
      add_node_id_array_component(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9003}},
        "AvailableStates",
        Array<NodeId>{readyStateNode, haltedStateId});
      add_node_id_array_component(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9004}},
        "AvailableTransitions",
        Array<NodeId>{runningToSuspendedId});
    }

    // FM2 (9010): CurrentState "Running" + Id, and NO AvailableStates / AvailableTransitions Properties.
    // Serves StateIdDoesNotMatchUnrelatedState (identity comparison) and AvailableStatesAbsentSurfacesNullopt
    // (empty topology + Good handle).
    {
      auto machine =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9010}}, "FmNoTopology");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9011}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{9012}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateNode}});
    }

    // FM3 (9020): an instance of a runtime SUBTYPE of ProgramStateMachineType whose CurrentState.Id VALUE is
    // the SUPERTYPE's Running state Object NodeId (the Part-5 Id-reuse rule: a subtype that reuses an
    // inherited state does not allocate a new NodeId for it). Serves SubtypeStateIdEqualsSupertypeIdNodeId.
    // The subtype re-declares the WHOLE of ProgramStateMachineType's State / Transition set, because that is
    // what Part 16 section 4.4.18 requires of a subtype and a subtype carrying only the one State the
    // CL-SM-006 row hands to the client is a model no conforming server publishes; the hand-built Running
    // replica is adopted as the counterpart for that name so it keeps the NodeId the row supplies.
    {
      const NodeId subtypeId{mTestNamespaceIndex, uint32_t{9019}};
      auto subtype = create_subtype(
        addressSpace, subtypeId, "MyProgramSubtype", NodeId{ObjectTypeId::ProgramStateMachineType});
      add_state_object(addressSpace, subtype, mSubtypeRunningStateId, "Running");
      replicate_state_machine_declaration(
        addressSpace, subtype, NodeId{ObjectTypeId::ProgramStateMachineType}, 99100U);
      auto machine =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9020}}, "FmSubtype", subtypeId);
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9021}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{9022}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateNode}});  // the SUPERTYPE-defined Running NodeId, reused by the subtype
    }

    // FM4 (9030): CurrentState "Running" + Id and AvailableStates = [Ready, Suspended] initially. The two
    // cache rows re-write this Property's Value at runtime to [Ready, Halted] (the change a
    // GeneralModelChangeEvent would announce) and assert the handle's cache behaviour. Serves
    // ModelChangeInvalidatesTopologyCache and TopologyReReadOnRefreshNotCachedStale.
    {
      auto machine = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9030}}, "FmReRead");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9031}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{9032}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateNode}});
      add_node_id_array_component(addressSpace,
        machine,
        mReReadStatesId,
        "AvailableStates",
        Array<NodeId>{readyStateNode, suspendedStateId});
    }

    // FM5 (9050 type / 9060 instance): a CONCRETE FiniteStateMachineType subtype carrying the full Part-16
    // declaration a server needs in order to decide Method executability - two States (Ready being the
    // InitialState), two Transitions each with FromState / ToState, and a HasCause from each Transition to
    // the Method that fires it. The instance carries the CurrentState.Id that says which State it is in, plus
    // the Start / Stop Methods an instantiation of the type produces. Nothing here decides Executable: both
    // Methods are published Executable, which is exactly the declaration a server that tracks the machine's
    // state has to narrow. Serves the Executable / at-least-one-State / at-most-one-InitialState rows.
    {
      mExecMachineTypeId = NodeId{mTestNamespaceIndex, uint32_t{9050}};
      mExecReadyStateId = NodeId{mTestNamespaceIndex, uint32_t{9051}};
      mExecRunningStateId = NodeId{mTestNamespaceIndex, uint32_t{9052}};
      mExecCurrentStateIdPropertyId = NodeId{mTestNamespaceIndex, uint32_t{9062}};
      mExecStartMethodId = NodeId{mTestNamespaceIndex, uint32_t{9063}};
      mExecStopMethodId = NodeId{mTestNamespaceIndex, uint32_t{9064}};

      auto machineType = create_subtype(
        addressSpace, mExecMachineTypeId, "FmExecType", NodeId{ObjectTypeId::FiniteStateMachineType});

      // The Methods the Transitions name as their Cause, declared on the type as the standard NodeSet does.
      const NodeId typeStartMethodId{mTestNamespaceIndex, uint32_t{9055}};
      const NodeId typeStopMethodId{mTestNamespaceIndex, uint32_t{9056}};
      add_method(addressSpace, machineType, typeStartMethodId, "Start");
      add_method(addressSpace, machineType, typeStopMethodId, "Stop");

      add_state(
        addressSpace, machineType, mExecReadyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
      add_state(addressSpace, machineType, mExecRunningStateId, "Running", NodeId{ObjectTypeId::StateType});
      auto readyState = addressSpace.find_node_sync(mExecReadyStateId);
      add_property(addressSpace,
        readyState,
        NodeId{mTestNamespaceIndex, uint32_t{9057}},
        "StateNumber",
        NodeId{DataTypeId::UInt32},
        DataValue{Variant{uint32_t{11}}});
      auto runningState = addressSpace.find_node_sync(mExecRunningStateId);
      add_property(addressSpace,
        runningState,
        NodeId{mTestNamespaceIndex, uint32_t{9058}},
        "StateNumber",
        NodeId{DataTypeId::UInt32},
        DataValue{Variant{uint32_t{12}}});

      add_transition(addressSpace,
        machineType,
        NodeId{mTestNamespaceIndex, uint32_t{9053}},
        "ReadyToRunning",
        mExecReadyStateId,
        mExecRunningStateId,
        typeStartMethodId);
      add_transition(addressSpace,
        machineType,
        NodeId{mTestNamespaceIndex, uint32_t{9054}},
        "RunningToReady",
        mExecRunningStateId,
        mExecReadyStateId,
        typeStopMethodId);

      auto machine = create_machine(
        addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9060}}, "FmExec", mExecMachineTypeId);
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{9061}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Ready"}}});
      add_property(addressSpace,
        currentState,
        mExecCurrentStateIdPropertyId,
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{mExecReadyStateId}});
      add_method(addressSpace, machine, mExecStartMethodId, "Start");
      add_method(addressSpace, machine, mExecStopMethodId, "Stop");
    }

    // FM6 (9070 parent / 9075 sub): the Part-16 4.4.5 COMPOSITION - a machine whose "Machining" State owns a
    // sub-state machine through HasSubStateMachine. The parent is published IN Machining, so the sub-machine
    // starts out active; the sub-machine row then moves the parent to Idle - both halves of the parent's
    // CurrentState, so the parent model consistently reports itself out of Machining - and re-reads the
    // sub-machine. The sub-machine's CurrentState is written with a Good quality, which is the quality a
    // server tracking the composition has to replace with Bad_StateNotActive once the owning State stops
    // being current.
    {
      mSubParentMachineId = NodeId{mTestNamespaceIndex, uint32_t{9070}};
      mSubParentCurrentStateId = NodeId{mTestNamespaceIndex, uint32_t{9071}};
      mSubParentCurrentStateIdPropertyId = NodeId{mTestNamespaceIndex, uint32_t{9072}};
      mSubParentIdleStateId = NodeId{mTestNamespaceIndex, uint32_t{9073}};
      mSubParentMachiningStateId = NodeId{mTestNamespaceIndex, uint32_t{9074}};
      mSubMachineId = NodeId{mTestNamespaceIndex, uint32_t{9075}};
      mSubMachineCurrentStateId = NodeId{mTestNamespaceIndex, uint32_t{9076}};
      mSubMachineCurrentStateIdPropertyId = NodeId{mTestNamespaceIndex, uint32_t{9077}};

      auto parent = create_machine(addressSpace, mSubParentMachineId, "FmSubParent");
      auto parentCurrentState = add_state_variable(addressSpace,
        parent,
        mSubParentCurrentStateId,
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Machining"}}});
      add_property(addressSpace,
        parentCurrentState,
        mSubParentCurrentStateIdPropertyId,
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{mSubParentMachiningStateId}});
      add_state(addressSpace, parent, mSubParentIdleStateId, "Idle", NodeId{ObjectTypeId::StateType});
      add_state(
        addressSpace, parent, mSubParentMachiningStateId, "Machining", NodeId{ObjectTypeId::StateType});

      auto subMachine = create_machine(addressSpace, mSubMachineId, "FmSubMachine");
      parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mSubMachineId);
      auto machiningState = addressSpace.find_node_sync(mSubParentMachiningStateId);
      machiningState.add_reference_sync(NodeId{ReferenceTypeId::HasSubStateMachine}, mSubMachineId);
      subMachine.add_reference_sync(
        NodeId{ReferenceTypeId::HasSubStateMachine}, mSubParentMachiningStateId, false);
      auto subCurrentState = add_state_variable(addressSpace,
        subMachine,
        mSubMachineCurrentStateId,
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "SubRunning"}}});
      subCurrentState.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mSubMachineId, false);
      add_property(addressSpace,
        subCurrentState,
        mSubMachineCurrentStateIdPropertyId,
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateNode}});
    }

    // Count Reads that touch FM4's AvailableStates Property so the re-read row can prove a genuine second
    // read.
    mReadCounter->set_target(mReReadStatesId);
    install_request_observer();
    install_event_listener();
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();

    // A dedicated channel + activated session handed to a started ConnectionImpl, then wrapped into the
    // PUBLIC Connection handle via the test wrap interface (the same shape the connect path produces).
    mConnChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    auto session = mConnChannel->create_session_sync({.sessionName = "CLIENT_FSM_MATRIX"});
    session.activate_sync();
    mConnImpl = ConnectionImpl::create(
      mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    ASSERT_TRUE(start_and_wait(*mConnImpl).is_good());
    mConnection.emplace(ConnectionHandleFactory::make_connection(mConnImpl));
  }

  void TearDown() override
  {
    if (mConnImpl)
    {
      (void)close_and_wait(*mConnImpl);
    }
    mConnection.reset();
    mConnImpl.reset();
    mConnChannel.reset();
    ComplianceWithNodes::TearDown();
  }

  // ---- state-machine node builders ----

  // Creates a StateMachine Object @p machineId (HasTypeDefinition @p typeDefinition, default
  // FiniteStateMachineType), organised under the Objects folder so it is browsable. Returns the created node
  // so component / Property children can be attached.
  NodeAccessor create_machine(AddressSpace& addressSpace, const NodeId& machineId, std::string browseName,
    const NodeId& typeDefinition = NodeId{ObjectTypeId::FiniteStateMachineType})
  {
    auto node = addressSpace.create_node_sync(machineId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    EXPECT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    object->set_display_name(LocalizedText{"", browseName});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeDefinition);
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, machineId);
    return node;
  }

  // Creates a non-abstract runtime ObjectType @p subtypeId whose supertype is @p supertype (inverse
  // HasSubtype), so a machine can be an instance of a genuine subtype of ProgramStateMachineType.
  NodeAccessor create_subtype(
    AddressSpace& addressSpace, const NodeId& subtypeId, std::string browseName, const NodeId& supertype)
  {
    auto node = addressSpace.create_node_sync(subtypeId, NodeClass::ObjectType);
    auto objectType = node.as<ObjectTypeAccessor>();
    EXPECT_TRUE(objectType.has_value());
    objectType->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    objectType->set_display_name(LocalizedText{"", browseName});
    objectType->set_is_abstract(false);
    // Inverse HasSubtype = "this type's super type is <supertype>".
    node.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, supertype, /*isForward=*/false);
    return node;
  }

  // Adds the replicated State Object required on a finite-state-machine subtype by Part 16 section 4.4.18.
  // Its BrowseName matches the first definition on the supertype, but its NodeId is distinct; CL-SM-006
  // normalization maps it back to that first definition.
  void add_state_object(
    AddressSpace& addressSpace, NodeAccessor& machineType, const NodeId& stateId, std::string_view browseName)
  {
    auto node = addressSpace.create_node_sync(stateId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    EXPECT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{0, std::string{browseName}});
    object->set_display_name(LocalizedText{"", std::string{browseName}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::StateType});
    machineType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, stateId);
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, machineType.get_node_id(), /*isForward=*/false);
  }

  // Adds an ns0-BrowseName state Variable child (@p ns0Name is "CurrentState") via HasComponent, DataType
  // LocalizedText, carrying @p value verbatim. Returns the child so its Id Property can be attached.
  NodeAccessor add_state_variable(AddressSpace& addressSpace, NodeAccessor& machine, const NodeId& childId,
    std::string_view ns0Name, DataValue value)
  {
    auto node = addressSpace.create_node_sync(childId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{0, std::string{ns0Name}});
    variable->set_display_name(LocalizedText{"", std::string{ns0Name}});
    variable->set_data_type(NodeId{DataTypeId::LocalizedText});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(std::move(value));
    machine.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, childId);
    return node;
  }

  // Adds an ns0-BrowseName scalar Property child (@p ns0Name is "Id") via HasProperty on @p owner, DataType
  // @p dataType, carrying @p value verbatim.
  static void add_property(AddressSpace& addressSpace, NodeAccessor& owner, const NodeId& propertyId,
    std::string_view ns0Name, const NodeId& dataType, DataValue value)
  {
    auto node = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{0, std::string{ns0Name}});
    variable->set_display_name(LocalizedText{"", std::string{ns0Name}});
    variable->set_data_type(dataType);
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(std::move(value));
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
  }

  // Adds an ns0-BrowseName one-dimensional NodeId[] Property child (@p ns0Name is "AvailableStates" /
  // "AvailableTransitions") via HasProperty on @p machine - exactly the topology Properties resolve_topology
  // browses + reads. The Value is a NodeId array (DataType NodeId, ValueRank 1).
  // AvailableStates / AvailableTransitions are COMPONENTS of a FiniteStateMachineType, not Properties:
  //
  //     HasComponent  Variable  AvailableStates       NodeId[]  BaseDataVariableType  Optional
  //     HasComponent  Variable  AvailableTransitions  NodeId[]  BaseDataVariableType  Optional
  //                                                    - OPC 10000-16, FiniteStateMachineType definition
  //
  // This fixture previously published them as HasProperty/PropertyType, matching what the SDK
  // browsed for rather than what the standard defines. The client browsed HasProperty and found
  // them here, so the rows passed - against a server no conforming implementation resembles. Both
  // are now built the way a real server builds them, which is what makes these rows evidence.
  void add_node_id_array_component(AddressSpace& addressSpace, NodeAccessor& machine,
    const NodeId& componentId, std::string_view ns0Name, Array<NodeId> value)
  {
    auto node = addressSpace.create_node_sync(componentId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{0, std::string{ns0Name}});
    variable->set_display_name(LocalizedText{"", std::string{ns0Name}});
    variable->set_data_type(NodeId{DataTypeId::NodeId});
    variable->set_value_rank(ValueRank{1});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(DataValue{Variant{std::move(value)}});
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    machine.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, componentId);
  }

  // Adds a State Object (@p typeDefinition is StateType or its InitialStateType subtype) as a HasComponent
  // child of @p machineType, wired in BOTH directions the way the standard NodeSet stores a State: the type
  // sources the forward HasComponent and the State carries the inverse back to its machine.
  void add_state(AddressSpace& addressSpace, NodeAccessor& machineType, const NodeId& stateId,
    std::string_view browseName, const NodeId& typeDefinition)
  {
    auto node = addressSpace.create_node_sync(stateId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    EXPECT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{0, std::string{browseName}});
    object->set_display_name(LocalizedText{"", std::string{browseName}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeDefinition);
    machineType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, stateId);
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, machineType.get_node_id(), /*isForward=*/false);
  }

  // Adds a Transition Object to @p machineType carrying the three references Part 16 section 4.4.5 / 4.4.7
  // require to make a Transition meaningful: FromState, ToState, and the HasCause naming the Method that
  // fires it. This is the declaration that says WHEN @p cause is a legitimate call.
  void add_transition(AddressSpace& addressSpace, NodeAccessor& machineType, const NodeId& transitionId,
    std::string_view browseName, const NodeId& fromState, const NodeId& toState, const NodeId& cause)
  {
    auto node = addressSpace.create_node_sync(transitionId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    EXPECT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{0, std::string{browseName}});
    object->set_display_name(LocalizedText{"", std::string{browseName}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::TransitionType});
    machineType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, transitionId);
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, machineType.get_node_id(), /*isForward=*/false);
    node.add_reference_sync(NodeId{ReferenceTypeId::FromState}, fromState);
    node.add_reference_sync(NodeId{ReferenceTypeId::ToState}, toState);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasCause}, cause);
  }

  // Gives @p replica the @p propertyName Property ("StateNumber" / "TransitionNumber") that @p declaration
  // carries, as @p propertyId. The number is taken through `number_property` - the same reader the
  // replication assertion uses - so the two agree by construction: a declaration whose number that reader
  // reports as absent leaves the replica without the Property, which the reader also reports as absent.
  void replicate_number_property(AddressSpace& addressSpace, const NodeId& declaration, const NodeId& replica,
    std::string_view propertyName, const NodeId& propertyId)
  {
    const auto number = number_property(declaration, propertyName);
    if (!number.has_value())
    {
      return;
    }
    auto owner = addressSpace.find_node_sync(replica);
    add_property(
      addressSpace, owner, propertyId, propertyName, NodeId{DataTypeId::UInt32}, DataValue{Variant{*number}});
  }

  // Re-declares on @p subtype every State and Transition @p supertype defines. States and Transitions carry
  // no ModellingRule (Part 16 sections 4.4.26 / 4.4.27), so a subtype inherits neither and has to carry its
  // own copy of each - a subtype built with only the one State a row happens to need is not a model any
  // conforming server publishes. Each counterpart keeps the declaration's BrowseName, ObjectType and
  // StateNumber / TransitionNumber; a replicated Transition's FromState / ToState name the subtype's own
  // State counterparts, and its HasCause / HasEffect / HasGuard / HasSubStateMachine name the same targets
  // the declaration's do. A State @p subtype already declares is ADOPTED as the counterpart for that
  // BrowseName rather than duplicated, so a hand-built replica keeps the NodeId a row hands to the client.
  // The subtype also sources a GeneratesEvent to every EventType its Transitions name as an Effect (section
  // 4.4.2). NodeIds for the generated nodes are allocated from @p firstReplicaIdentifier upward.
  void replicate_state_machine_declaration(AddressSpace& addressSpace, NodeAccessor& subtype,
    const NodeId& supertype, std::uint32_t firstReplicaIdentifier)
  {
    std::uint32_t nextIdentifier = firstReplicaIdentifier;
    const auto allocate = [&]
    {
      return NodeId{mTestNamespaceIndex, nextIdentifier++};
    };

    std::map<std::string, NodeId> stateCounterparts;
    for (const auto& declared : components_of_type(subtype.get_node_id(), NodeId{ObjectTypeId::StateType}))
    {
      stateCounterparts.emplace(browse_name_of(declared), declared);
    }
    for (const auto& state : components_of_type(supertype, NodeId{ObjectTypeId::StateType}))
    {
      const std::string name = browse_name_of(state);
      auto counterpart = stateCounterparts.find(name);
      if (counterpart == stateCounterparts.end())
      {
        counterpart = stateCounterparts.emplace(name, allocate()).first;
        add_state(addressSpace, subtype, counterpart->second, name, type_definition_of(state));
      }
      replicate_number_property(addressSpace, state, counterpart->second, "StateNumber", allocate());
    }

    const std::vector<NodeId> stateEndpoints{
      NodeId{ReferenceTypeId::FromState}, NodeId{ReferenceTypeId::ToState}};
    const std::vector<NodeId> carriedReferences{NodeId{ReferenceTypeId::HasCause},
      NodeId{ReferenceTypeId::HasEffect},
      NodeId{ReferenceTypeId::HasGuard},
      NodeId{ReferenceTypeId::HasSubStateMachine}};
    std::vector<NodeId> effects;
    for (const auto& transition : components_of_type(supertype, NodeId{ObjectTypeId::TransitionType}))
    {
      const NodeId replicaId = allocate();
      const std::string name = browse_name_of(transition);
      auto node = addressSpace.create_node_sync(replicaId, NodeClass::Object);
      auto object = node.as<ObjectAccessor>();
      EXPECT_TRUE(object.has_value());
      object->set_browse_name(QualifiedName{0, name});
      object->set_display_name(LocalizedText{"", name});
      node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, type_definition_of(transition));
      subtype.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, replicaId);
      node.add_reference_sync(
        NodeId{ReferenceTypeId::HasComponent}, subtype.get_node_id(), /*isForward=*/false);
      replicate_number_property(addressSpace, transition, replicaId, "TransitionNumber", allocate());

      for (const auto& referenceType : stateEndpoints)
      {
        for (const auto& target : forward_targets(transition, referenceType))
        {
          const auto counterpart = stateCounterparts.find(browse_name_of(target));
          node.add_reference_sync(
            referenceType, (counterpart == stateCounterparts.end()) ? target : counterpart->second);
        }
      }
      for (const auto& referenceType : carriedReferences)
      {
        for (const auto& target : forward_targets(transition, referenceType))
        {
          node.add_reference_sync(referenceType, target);
          if ((referenceType == NodeId{ReferenceTypeId::HasEffect}) &&
              (std::find(effects.begin(), effects.end(), target) == effects.end()))
          {
            effects.push_back(target);
          }
        }
      }
    }
    for (const auto& effect : effects)
    {
      subtype.add_reference_sync(NodeId{ReferenceTypeId::GeneratesEvent}, effect);
    }
  }

  // Adds an ns0-BrowseName Method child of @p owner, published EXECUTABLE. The value is deliberately the
  // permissive one: a server that derives executability from the machine's state has to narrow it, and one
  // that does not will simply keep serving what was declared.
  void add_method(
    AddressSpace& addressSpace, NodeAccessor& owner, const NodeId& methodId, std::string_view browseName)
  {
    auto node = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = node.as<MethodAccessor>();
    EXPECT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{0, std::string{browseName}});
    method->set_display_name(LocalizedText{"", std::string{browseName}});
    method->set_executable(true);
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, owner.get_node_id(), /*isForward=*/false);
  }

  // Adds a Transition Object carrying FromState / ToState and deliberately NO HasCause. That is the shape
  // Part 16 section 4.6.2 requires of a Transition leaving a ChoiceState: the pseudo-state is exited the
  // instant it is entered, by evaluating Guards, so there is no moment at which the machine waits for a
  // trigger. Returns the node so a HasGuard can be attached to it.
  NodeAccessor add_causeless_transition(AddressSpace& addressSpace, NodeAccessor& machineType,
    const NodeId& transitionId, std::string_view browseName, const NodeId& fromState, const NodeId& toState)
  {
    auto node = addressSpace.create_node_sync(transitionId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    EXPECT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{0, std::string{browseName}});
    object->set_display_name(LocalizedText{"", std::string{browseName}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::TransitionType});
    machineType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, transitionId);
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, machineType.get_node_id(), /*isForward=*/false);
    node.add_reference_sync(NodeId{ReferenceTypeId::FromState}, fromState);
    node.add_reference_sync(NodeId{ReferenceTypeId::ToState}, toState);
    return node;
  }

  // Adds a Guard Variable of VariableType @p guardType (an ExpressionGuardVariableType or an
  // ElseGuardVariableType) as a HasComponent child of @p machineType, and links @p transition to it with the
  // HasGuard Reference. A GuardVariableType's Value is a Boolean (Part 16 section 4.6.4).
  void add_guard(AddressSpace& addressSpace, NodeAccessor& machineType, NodeAccessor& transition,
    const NodeId& guardId, std::string_view browseName, const NodeId& guardType)
  {
    auto node = addressSpace.create_node_sync(guardId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{0, std::string{browseName}});
    variable->set_display_name(LocalizedText{"", std::string{browseName}});
    variable->set_data_type(NodeId{DataTypeId::Boolean});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(DataValue{Variant{true}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, guardType);
    machineType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, guardId);
    transition.add_reference_sync(NodeId{ReferenceTypeId::HasGuard}, guardId);
  }

  struct ChoiceStateExemplar
  {
    NodeId machineTypeId;
    NodeId idleStateId;
    NodeId choiceStateId;
    NodeId leftStateId;
    NodeId rightStateId;
    NodeId goMethodId;
    NodeId expressionGuardedTransitionId;
    NodeId elseGuardedTransitionId;
    NodeId expressionGuardId;
    NodeId elseGuardId;
    NodeId instanceId;
    NodeId currentStateIdPropertyId;
  };

  // Builds the Part 16 section 4.6 ChoiceState model that no type in the loaded NS0 exhibits: a machine whose
  // "Decide" State is a ChoiceStateType, entered from Idle by a Method-caused Transition and left by TWO
  // Transitions that carry no HasCause - one guarded by an ExpressionGuardVariableType, the other by the
  // single ElseGuardVariableType that provides the covering default - plus ONE INSTANCE of it, reporting
  // Idle and reachable through the Cause Method. Built out of the same address-space builders
  // configure_server uses, so the running server publishes it exactly as it publishes any other type.
  // Every section 4.6 sweep below needs a subject: without one each of them would hold over the empty set.
  // The instance is what lets the section 4.6.2 row observe the RUNTIME obligation (the machine leaves the
  // pseudo-state) rather than restate the model this builder just wrote.
  // NodeIds are allocated from @p firstIdentifier upward (eighteen of them).
  ChoiceStateExemplar add_choice_state_exemplar(std::uint32_t firstIdentifier)
  {
    auto addressSpace = mServer.server().address_space();
    ChoiceStateExemplar exemplar;
    exemplar.machineTypeId = NodeId{mTestNamespaceIndex, firstIdentifier};
    exemplar.idleStateId = NodeId{mTestNamespaceIndex, firstIdentifier + 1U};
    exemplar.choiceStateId = NodeId{mTestNamespaceIndex, firstIdentifier + 2U};
    exemplar.leftStateId = NodeId{mTestNamespaceIndex, firstIdentifier + 3U};
    exemplar.rightStateId = NodeId{mTestNamespaceIndex, firstIdentifier + 4U};
    exemplar.goMethodId = NodeId{mTestNamespaceIndex, firstIdentifier + 5U};
    const NodeId idleToDecideId{mTestNamespaceIndex, firstIdentifier + 6U};
    exemplar.expressionGuardedTransitionId = NodeId{mTestNamespaceIndex, firstIdentifier + 7U};
    exemplar.elseGuardedTransitionId = NodeId{mTestNamespaceIndex, firstIdentifier + 8U};
    exemplar.expressionGuardId = NodeId{mTestNamespaceIndex, firstIdentifier + 9U};
    exemplar.elseGuardId = NodeId{mTestNamespaceIndex, firstIdentifier + 10U};
    exemplar.instanceId = NodeId{mTestNamespaceIndex, firstIdentifier + 11U};
    const NodeId currentStateId{mTestNamespaceIndex, firstIdentifier + 12U};
    exemplar.currentStateIdPropertyId = NodeId{mTestNamespaceIndex, firstIdentifier + 13U};

    auto machineType = create_subtype(
      addressSpace, exemplar.machineTypeId, "FmChoice", NodeId{ObjectTypeId::FiniteStateMachineType});
    add_state(
      addressSpace, machineType, exemplar.idleStateId, "Idle", NodeId{ObjectTypeId::InitialStateType});
    add_state(
      addressSpace, machineType, exemplar.choiceStateId, "Decide", NodeId{ObjectTypeId::ChoiceStateType});
    add_state(addressSpace, machineType, exemplar.leftStateId, "Left", NodeId{ObjectTypeId::StateType});
    add_state(addressSpace, machineType, exemplar.rightStateId, "Right", NodeId{ObjectTypeId::StateType});
    std::uint32_t stateNumberPropertyIdentifier = firstIdentifier + 14U;
    std::uint32_t stateNumber = 1U;
    for (const auto& stateId :
      {exemplar.idleStateId, exemplar.choiceStateId, exemplar.leftStateId, exemplar.rightStateId})
    {
      auto state = addressSpace.find_node_sync(stateId);
      add_property(addressSpace,
        state,
        NodeId{mTestNamespaceIndex, stateNumberPropertyIdentifier++},
        "StateNumber",
        NodeId{DataTypeId::UInt32},
        DataValue{Variant{stateNumber++}});
    }
    add_method(addressSpace, machineType, exemplar.goMethodId, "Go");
    add_transition(addressSpace,
      machineType,
      idleToDecideId,
      "IdleToDecide",
      exemplar.idleStateId,
      exemplar.choiceStateId,
      exemplar.goMethodId);
    auto toLeft = add_causeless_transition(addressSpace,
      machineType,
      exemplar.expressionGuardedTransitionId,
      "DecideToLeft",
      exemplar.choiceStateId,
      exemplar.leftStateId);
    auto toRight = add_causeless_transition(addressSpace,
      machineType,
      exemplar.elseGuardedTransitionId,
      "DecideToRight",
      exemplar.choiceStateId,
      exemplar.rightStateId);
    add_guard(addressSpace,
      machineType,
      toLeft,
      exemplar.expressionGuardId,
      "LeftGuard",
      NodeId{VariableTypeId::ExpressionGuardVariableType});
    add_guard(addressSpace,
      machineType,
      toRight,
      exemplar.elseGuardId,
      "ElseGuard",
      NodeId{VariableTypeId::ElseGuardVariableType});

    auto machine =
      create_machine(addressSpace, exemplar.instanceId, "FmChoiceInstance", exemplar.machineTypeId);
    auto currentState = add_state_variable(
      addressSpace, machine, currentStateId, "CurrentState", DataValue{Variant{LocalizedText{"en", "Idle"}}});
    currentState.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
    add_property(addressSpace,
      currentState,
      exemplar.currentStateIdPropertyId,
      "Id",
      NodeId{DataTypeId::NodeId},
      DataValue{Variant{exemplar.idleStateId}});

    // The Cause Method carries a handler that does nothing but succeed: the application's Method body is not
    // what the section 4.6 obligations are about, so it gets out of the way and lets the Call return Good,
    // which is what makes the Transition INTO the ChoiceState genuinely triggered by a Client.
    auto methodNode = mTestNamespace->find_node<Node>(exemplar.goMethodId);
    EXPECT_NE(methodNode, nullptr) << "the Transition's Cause Method was not created in the test namespace";
    auto* callSource = (methodNode != nullptr) ? methodNode->method_call_source() : nullptr;
    EXPECT_NE(callSource, nullptr)
      << "the Transition's Cause Method exposes no call source, so a Client cannot enter the ChoiceState";
    if (callSource != nullptr)
    {
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            complete)
        {
          CallMethodResult result;
          complete(CallResult{std::move(result)});
        });
    }
    return exemplar;
  }

  struct EffectMachineExemplar
  {
    NodeId machineTypeId;
    NodeId readyStateId;
    NodeId runningStateId;
    NodeId transitionId;
    NodeId startMethodId;
    NodeId firstInstanceId;
    NodeId secondInstanceId;
    std::uint32_t readyStateNumber{1U};
    std::uint32_t runningStateNumber{2U};
  };

  // Builds the Part 16 section 4.4.14 model the Effect and SourceNode obligations need and that no type in
  // the loaded NS0 provides: a concrete FiniteStateMachineType subtype whose single Transition names a Method
  // as its HasCause and TransitionEventType as its HasEffect, plus TWO instances of it - a SourceNode naming
  // "the machine" can only be told apart from one naming the type when there is more than one machine. The
  // Cause Method carries a handler that does nothing but succeed: the application's Method body is not what
  // these obligations are about, so it gets out of the way and lets the Call return Good, which is what makes
  // the Transition genuinely triggered by a Client. NodeIds are allocated from @p firstIdentifier upward.
  EffectMachineExemplar add_effect_machine_exemplar(std::uint32_t firstIdentifier)
  {
    auto addressSpace = mServer.server().address_space();
    EffectMachineExemplar exemplar;
    exemplar.machineTypeId = NodeId{mTestNamespaceIndex, firstIdentifier};
    exemplar.readyStateId = NodeId{mTestNamespaceIndex, firstIdentifier + 1U};
    exemplar.runningStateId = NodeId{mTestNamespaceIndex, firstIdentifier + 2U};
    exemplar.startMethodId = NodeId{mTestNamespaceIndex, firstIdentifier + 3U};
    exemplar.transitionId = NodeId{mTestNamespaceIndex, firstIdentifier + 4U};
    exemplar.firstInstanceId = NodeId{mTestNamespaceIndex, firstIdentifier + 5U};
    exemplar.secondInstanceId = NodeId{mTestNamespaceIndex, firstIdentifier + 6U};

    auto machineType = create_subtype(
      addressSpace, exemplar.machineTypeId, "FmEffect", NodeId{ObjectTypeId::FiniteStateMachineType});
    add_method(addressSpace, machineType, exemplar.startMethodId, "Start");
    add_state(
      addressSpace, machineType, exemplar.readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
    add_state(addressSpace, machineType, exemplar.runningStateId, "Running", NodeId{ObjectTypeId::StateType});
    auto readyState = addressSpace.find_node_sync(exemplar.readyStateId);
    add_property(addressSpace,
      readyState,
      NodeId{mTestNamespaceIndex, firstIdentifier + 7U},
      "StateNumber",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{exemplar.readyStateNumber}});
    auto runningState = addressSpace.find_node_sync(exemplar.runningStateId);
    add_property(addressSpace,
      runningState,
      NodeId{mTestNamespaceIndex, firstIdentifier + 8U},
      "StateNumber",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{exemplar.runningStateNumber}});
    add_transition(addressSpace,
      machineType,
      exemplar.transitionId,
      "ReadyToRunning",
      exemplar.readyStateId,
      exemplar.runningStateId,
      exemplar.startMethodId);
    auto transition = addressSpace.find_node_sync(exemplar.transitionId);
    transition.add_reference_sync(
      NodeId{ReferenceTypeId::HasEffect}, NodeId{ObjectTypeId::TransitionEventType});
    machineType.add_reference_sync(
      NodeId{ReferenceTypeId::GeneratesEvent}, NodeId{ObjectTypeId::TransitionEventType});

    std::uint32_t nextIdentifier = firstIdentifier + 9U;
    int ordinal{0};
    for (const auto& instanceId : {exemplar.firstInstanceId, exemplar.secondInstanceId})
    {
      auto machine = create_machine(
        addressSpace, instanceId, "FmEffectInstance" + std::to_string(++ordinal), exemplar.machineTypeId);
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, nextIdentifier++},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Ready"}}});
      currentState.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, nextIdentifier++},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{exemplar.readyStateId}});
    }

    auto methodNode = mTestNamespace->find_node<Node>(exemplar.startMethodId);
    EXPECT_NE(methodNode, nullptr) << "the Transition's Cause Method was not created in the test namespace";
    auto* callSource = (methodNode != nullptr) ? methodNode->method_call_source() : nullptr;
    EXPECT_NE(callSource, nullptr)
      << "the Transition's Cause Method exposes no call source, so a Client cannot trigger the Transition";
    if (callSource != nullptr)
    {
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            complete)
        {
          CallMethodResult result;
          complete(CallResult{std::move(result)});
        });
    }
    return exemplar;
  }

  // ---- address-space walkers (over the model the RUNNING server publishes, not over a fixture copy) ----

  // Every NodeId the server's address space owns, across every namespace this fixture reaches. Enumeration
  // rather than a Browse from Root is what makes the walk COMPLETE: an invariant asserted over "every type in
  // the address space" is not established by a sample, and a bounded Browse silently truncates.
  std::vector<NodeId> enumerate_all_nodes()
  {
    auto addressSpace = mServer.server().address_space();
    std::vector<NodeId> ids;
    for (uint16_t index = 0; index <= mTestNamespaceIndex; ++index)
    {
      std::promise<Result<std::vector<NodeId>>> promise;
      auto future = promise.get_future();
      addressSpace.enumerate_nodes_async(
        index, [&promise](Result<std::vector<NodeId>> outcome) { promise.set_value(std::move(outcome)); });
      auto outcome = future.get();
      if (outcome.is_bad())
      {
        continue;
      }
      for (const auto& id : outcome.value())
      {
        ids.push_back(id);
      }
    }
    return ids;
  }

  // The local FORWARD targets of @p referenceType on @p nodeId.
  std::vector<NodeId> forward_targets(const NodeId& nodeId, const NodeId& referenceType)
  {
    std::vector<NodeId> targets;
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad())
    {
      return targets;
    }
    auto references = node.value().try_get_references_sync();
    if (references.is_bad())
    {
      return targets;
    }
    for (const auto& reference : references.value())
    {
      if (reference.is_forward() && !reference.is_remote() && (reference.type_id() == referenceType))
      {
        targets.push_back(reference.target_id().node_id());
      }
    }
    return targets;
  }

  // The HasTypeDefinition target of @p nodeId, or a null NodeId when it declares none. HasTypeDefinition is
  // one of the two reference types the NodeSet importer does NOT mirror, so it is read forward from the node.
  NodeId type_definition_of(const NodeId& nodeId)
  {
    auto targets = forward_targets(nodeId, NodeId{ReferenceTypeId::HasTypeDefinition});
    return targets.empty() ? NodeId{} : targets.front();
  }

  // True when @p typeId is @p ancestor or, transitively, a subtype of it. Walks the INVERSE HasSubtype chain
  // upward - the direction both the standard NodeSet and this fixture's runtime subtypes actually store.
  // Bounded, so a malformed cyclic hierarchy reports false instead of hanging the walk.
  bool is_type_or_subtype_of(const NodeId& typeId, const NodeId& ancestor)
  {
    auto addressSpace = mServer.server().address_space();
    NodeId current = typeId;
    for (int hop = 0; hop < 64; ++hop)
    {
      if (current == ancestor)
      {
        return true;
      }
      auto node = addressSpace.try_find_node_sync(current);
      if (node.is_bad())
      {
        return false;
      }
      auto references = node.value().try_get_references_sync();
      if (references.is_bad())
      {
        return false;
      }
      NodeId supertype;
      for (const auto& reference : references.value())
      {
        if (!reference.is_forward() && !reference.is_remote() &&
            (reference.type_id() == NodeId{ReferenceTypeId::HasSubtype}))
        {
          supertype = reference.target_id().node_id();
          break;
        }
      }
      if (supertype.is_null())
      {
        return false;
      }
      current = supertype;
    }
    return false;
  }

  // True when @p node declares itself abstract, read in wire form. `ObjectTypeAccessor::get_is_abstract`
  // resolves an unset IsAbstract by throwing, and a type node created through the address-space API
  // without one holds an empty Variant, so a single such type anywhere in the walked namespaces aborts
  // the enumeration instead of being classified. An unset attribute reads as NOT abstract - the meaning
  // an omitted IsAbstract carries in a NodeSet - which keeps the type inside an invariant asserted over
  // every type rather than silently dropping it.
  static bool is_abstract_type(const NodeAccessor& node)
  {
    const Variant stored = node.read_attribute(AttributeId::IsAbstract);
    const bool* isAbstract = stored.try_as<bool>();
    return (isAbstract != nullptr) && *isAbstract;
  }

  // Every non-abstract ObjectType in the address space that is @p rootType or a subtype of it.
  std::vector<NodeId> concrete_subtypes_of(const NodeId& rootType)
  {
    auto addressSpace = mServer.server().address_space();
    std::vector<NodeId> types;
    for (const auto& nodeId : enumerate_all_nodes())
    {
      auto node = addressSpace.try_find_node_sync(nodeId);
      if (node.is_bad())
      {
        continue;
      }
      auto objectType = node.value().as<ObjectTypeAccessor>();
      if (!objectType.has_value() || is_abstract_type(node.value()))
      {
        continue;
      }
      if (is_type_or_subtype_of(nodeId, rootType))
      {
        types.push_back(nodeId);
      }
    }
    return types;
  }

  // The HasComponent children of @p ownerId whose HasTypeDefinition is @p childType or a subtype of it.
  std::vector<NodeId> components_of_type(const NodeId& ownerId, const NodeId& childType)
  {
    std::vector<NodeId> matches;
    for (const auto& child : forward_targets(ownerId, NodeId{ReferenceTypeId::HasComponent}))
    {
      const auto definition = type_definition_of(child);
      if (!definition.is_null() && is_type_or_subtype_of(definition, childType))
      {
        matches.push_back(child);
      }
    }
    return matches;
  }

  // The BrowseName of @p nodeId as a plain string, read in WIRE form for the same reason `is_abstract_type`
  // is: the accessor getter resolves an unset attribute by throwing, which would abort a walk that spans
  // every node in the model instead of classifying the one offender. An unnamed or unreachable node yields
  // an empty string, which a name comparison reports as a mismatch rather than silently skipping.
  std::string browse_name_of(const NodeId& nodeId)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad())
    {
      return std::string{};
    }
    const Variant stored = node.value().read_attribute(AttributeId::BrowseName);
    const QualifiedName* name = stored.try_as<QualifiedName>();
    return (name == nullptr) ? std::string{} : std::string{static_cast<std::string_view>(name->name())};
  }

  // The BrowseNames of @p nodeIds, sorted so two declarations compare as SETS (the address space fixes no
  // order on HasComponent children, so an ordered comparison would report drift that is not there).
  std::vector<std::string> browse_names_of(const std::vector<NodeId>& nodeIds)
  {
    std::vector<std::string> names;
    names.reserve(nodeIds.size());
    for (const auto& nodeId : nodeIds)
    {
      names.push_back(browse_name_of(nodeId));
    }
    std::sort(names.begin(), names.end());
    return names;
  }

  // The sorted BrowseNames of the FORWARD @p referenceType targets on @p nodeId. Comparing targets by name
  // rather than by NodeId is what lets a subtype satisfy the replication rule either by pointing at the
  // supertype's node or by pointing at its own override of it.
  std::vector<std::string> target_browse_names(const NodeId& nodeId, const NodeId& referenceType)
  {
    return browse_names_of(forward_targets(nodeId, referenceType));
  }

  static std::string join_names(const std::vector<std::string>& names)
  {
    std::string joined;
    for (const auto& name : names)
    {
      if (!joined.empty())
      {
        joined += ", ";
      }
      joined += name;
    }
    return joined.empty() ? std::string{"<none>"} : joined;
  }

  static std::string number_text(std::optional<std::uint32_t> number)
  {
    return number.has_value() ? std::to_string(*number) : std::string{"<absent>"};
  }

  // The direct supertype of @p typeId (its INVERSE HasSubtype target), or a null NodeId when it declares
  // none. Read inverse rather than forward because that is the direction both the standard NodeSet and this
  // fixture's runtime `create_subtype` store, so a forward walk from the supertype would miss the latter.
  NodeId direct_supertype_of(const NodeId& typeId)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(typeId);
    if (node.is_bad())
    {
      return NodeId{};
    }
    auto references = node.value().try_get_references_sync();
    if (references.is_bad())
    {
      return NodeId{};
    }
    for (const auto& reference : references.value())
    {
      if (!reference.is_forward() && !reference.is_remote() &&
          (reference.type_id() == NodeId{ReferenceTypeId::HasSubtype}))
      {
        return reference.target_id().node_id();
      }
    }
    return NodeId{};
  }

  struct TypePair
  {
    NodeId supertype;
    NodeId subtype;
  };

  // Every (supertype, subtype) ObjectType pair in the address space whose SUPERTYPE is StateMachineType or a
  // subtype of it, derived from each type's own inverse HasSubtype so that runtime-registered subtypes are
  // enumerated alongside the NodeSet's.
  std::vector<TypePair> state_machine_type_subtype_pairs()
  {
    auto addressSpace = mServer.server().address_space();
    std::vector<TypePair> pairs;
    for (const auto& nodeId : enumerate_all_nodes())
    {
      auto node = addressSpace.try_find_node_sync(nodeId);
      if (node.is_bad() || !node.value().as<ObjectTypeAccessor>().has_value())
      {
        continue;
      }
      const NodeId supertype = direct_supertype_of(nodeId);
      if (supertype.is_null() || !is_type_or_subtype_of(supertype, NodeId{ObjectTypeId::StateMachineType}))
      {
        continue;
      }
      pairs.push_back(TypePair{supertype, nodeId});
    }
    return pairs;
  }

  // Every Object in the address space whose HasTypeDefinition is TransitionType or a subtype of it -
  // enumerated rather than browsed from a known machine, because "every Transition" is not established by a
  // sample.
  std::vector<NodeId> all_transition_objects()
  {
    auto addressSpace = mServer.server().address_space();
    std::vector<NodeId> transitions;
    for (const auto& nodeId : enumerate_all_nodes())
    {
      auto node = addressSpace.try_find_node_sync(nodeId);
      if (node.is_bad() || !node.value().as<ObjectAccessor>().has_value())
      {
        continue;
      }
      const NodeId definition = type_definition_of(nodeId);
      if (!definition.is_null() && is_type_or_subtype_of(definition, NodeId{ObjectTypeId::TransitionType}))
      {
        transitions.push_back(nodeId);
      }
    }
    return transitions;
  }

  // True when @p nodeId is an Object whose HasTypeDefinition is StateType or a subtype of it.
  bool is_state_object(const NodeId& nodeId)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad() || !node.value().as<ObjectAccessor>().has_value())
    {
      return false;
    }
    const NodeId definition = type_definition_of(nodeId);
    return !definition.is_null() && is_type_or_subtype_of(definition, NodeId{ObjectTypeId::StateType});
  }

  // The UInt32 Value of @p ownerId's HasProperty child named @p propertyName ("StateNumber" /
  // "TransitionNumber"), or std::nullopt when no such Property carries one. Absent is DISTINGUISHED from
  // zero: a counterpart that dropped the Property altogether is a different (and equally breaking) drift
  // from one that carries a different number.
  //
  // Read through the Variable's VALUE path rather than `read_attribute(AttributeId::Value)`, which the
  // other walkers here use for their attributes. A Variable's live Value is not one of its stored
  // attributes - it is served by the node's value source (default_ns::VariableNode::read_value, and
  // write_attribute_async refuses AttributeId::Value outright), so the attribute read returns an empty
  // Variant for every Property in the model and would report each of them as absent. `try_read_value_sync`
  // is the non-throwing form, which is what a walk spanning every node in the model needs.
  std::optional<std::uint32_t> number_property(const NodeId& ownerId, std::string_view propertyName)
  {
    auto addressSpace = mServer.server().address_space();
    for (const auto& property : forward_targets(ownerId, NodeId{ReferenceTypeId::HasProperty}))
    {
      const std::string name = browse_name_of(property);
      if (std::string_view{name} != propertyName)
      {
        continue;
      }
      auto node = addressSpace.try_find_node_sync(property);
      if (node.is_bad())
      {
        continue;
      }
      auto variable = node.value().as<VariableAccessor>();
      if (!variable.has_value())
      {
        continue;
      }
      const auto stored = variable->try_read_value_sync();
      if (stored.is_bad())
      {
        continue;
      }
      const std::uint32_t* number = stored.value().value().try_as<std::uint32_t>();
      if (number != nullptr)
      {
        return std::optional<std::uint32_t>{*number};
      }
    }
    return std::nullopt;
  }

  // True when @p nodeId is an OBJECT whose HasTypeDefinition is @p rootType or a subtype of it. The
  // NodeClass half is required in the section 4.4.11-section 4.4.15 clauses, each of which names "an
  // Object of the ObjectType X": a Variable whose type definition happens to sit in the same hierarchy does
  // not satisfy them, and a check written on the type definition alone would accept one.
  bool is_object_of_type(const NodeId& nodeId, const NodeId& rootType)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad() || !node.value().as<ObjectAccessor>().has_value())
    {
      return false;
    }
    const NodeId definition = type_definition_of(nodeId);
    return !definition.is_null() && is_type_or_subtype_of(definition, rootType);
  }

  // True when @p nodeId is a VARIABLE whose HasTypeDefinition is @p rootType or a subtype of it - the
  // counterpart of is_object_of_type for the one clause in the family (section 4.6.3 HasGuard) whose target
  // is a Variable rather than an Object.
  bool is_variable_of_type(const NodeId& nodeId, const NodeId& rootType)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad() || !node.value().as<VariableAccessor>().has_value())
    {
      return false;
    }
    const NodeId definition = type_definition_of(nodeId);
    return !definition.is_null() && is_type_or_subtype_of(definition, rootType);
  }

  // True when @p nodeId sources a HasModellingRule Reference. Read FORWARD off the node, which is the
  // direction a ModellingRule is stored in and the direction a NodeSet declares it.
  bool has_modelling_rule(const NodeId& nodeId)
  {
    return !forward_targets(nodeId, NodeId{ReferenceTypeId::HasModellingRule}).empty();
  }

  // Every ObjectType in the address space that is @p rootType or a subtype of it, ABSTRACT ONES INCLUDED -
  // unlike concrete_subtypes_of, which exists for the clauses scoped to instantiable machines. The
  // section 4.4.8 / section 4.4.10 clauses constrain how a State or Transition is attached to the type that
  // DECLARES it, and an abstract machine type declares its States exactly as a concrete one does.
  std::vector<NodeId> all_subtypes_of(const NodeId& rootType)
  {
    auto addressSpace = mServer.server().address_space();
    std::vector<NodeId> types;
    for (const auto& nodeId : enumerate_all_nodes())
    {
      auto node = addressSpace.try_find_node_sync(nodeId);
      if (node.is_bad() || !node.value().as<ObjectTypeAccessor>().has_value())
      {
        continue;
      }
      if (is_type_or_subtype_of(nodeId, rootType))
      {
        types.push_back(nodeId);
      }
    }
    return types;
  }

  struct DirectedReference
  {
    NodeId source;
    NodeId target;
    NodeId referenceType;
  };

  // Every FORWARD, local reference @p nodeId sources, carrying its ReferenceType. `forward_targets` answers
  // "which targets does THIS reference type reach"; this answers the question section 4.4.8 asks, which is
  // the other way round - given a target, WHICH ReferenceType reached it.
  std::vector<DirectedReference> forward_references(const NodeId& nodeId)
  {
    std::vector<DirectedReference> found;
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad())
    {
      return found;
    }
    auto references = node.value().try_get_references_sync();
    if (references.is_bad())
    {
      return found;
    }
    for (const auto& reference : references.value())
    {
      if (reference.is_forward() && !reference.is_remote())
      {
        found.push_back(DirectedReference{nodeId, reference.target_id().node_id(), reference.type_id()});
      }
    }
    return found;
  }

  // Every FORWARD reference in the published model whose ReferenceType is @p referenceType or a subtype of
  // it, as (source, target, ReferenceType) triples. Enumerated over every node rather than browsed from a
  // known machine, because "every FromState reference in the address space" is not established by a sample.
  // Subtypes are included because a subtype of a ReferenceType inherits its endpoint constraints - Part 9
  // section 7.2 restates the TransitionType source rule verbatim for HasEffectDisable - so a sweep of the
  // exact type alone would let the four Part 9 HasEffect subtypes through unexamined. The classification is
  // memoised: a subtype walk per reference would repeat the same handful of answers across the whole model.
  std::vector<DirectedReference> references_of_type(const NodeId& referenceType)
  {
    auto addressSpace = mServer.server().address_space();
    std::map<NodeId, bool> classified;
    std::vector<DirectedReference> found;
    for (const auto& nodeId : enumerate_all_nodes())
    {
      auto node = addressSpace.try_find_node_sync(nodeId);
      if (node.is_bad())
      {
        continue;
      }
      auto references = node.value().try_get_references_sync();
      if (references.is_bad())
      {
        continue;
      }
      for (const auto& reference : references.value())
      {
        if (!reference.is_forward() || reference.is_remote())
        {
          continue;
        }
        auto known = classified.find(reference.type_id());
        if (known == classified.end())
        {
          const bool matches = is_type_or_subtype_of(reference.type_id(), referenceType);
          known = classified.emplace(reference.type_id(), matches).first;
        }
        if (known->second)
        {
          found.push_back(DirectedReference{nodeId, reference.target_id().node_id(), reference.type_id()});
        }
      }
    }
    return found;
  }

  // Maps every node some other node reaches through a HasComponent (or HasComponent-subtype) Reference to
  // the sources that reach it - "which StateMachine does this node belong to". Derived by a FORWARD scan of
  // the whole model rather than from each node's inverse References, because a node wired by a one-sided
  // add_reference_sync stores no inverse and would otherwise read as belonging to nothing at all.
  std::map<NodeId, std::vector<NodeId>> has_component_owners()
  {
    std::map<NodeId, std::vector<NodeId>> owners;
    for (const auto& reference : references_of_type(NodeId{ReferenceTypeId::HasComponent}))
    {
      owners[reference.target].push_back(reference.source);
    }
    return owners;
  }

  // Reads @p nodeId's Value Attribute over the WIRE on the raw Session, or std::nullopt when the Read did
  // not deliver exactly one result. Deliberately not routed through a typed handle: the obligation under
  // test is what the SERVER reports, and a handle-level or Connection-level cache could otherwise stand in
  // for the server's second answer.
  std::optional<DataValue> read_data_value(const NodeId& nodeId)
  {
    auto response = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::Value));
    if (response.is_bad())
    {
      return std::nullopt;
    }
    auto value = std::move(response).value();
    if (value.results().size() != 1U)
    {
      return std::nullopt;
    }
    return std::optional<DataValue>{value.results()[0]};
  }

  // Reads the Executable Attribute of @p methodId over the wire, or std::nullopt when the Read did not
  // deliver a Boolean.
  std::optional<bool> read_executable(const NodeId& methodId)
  {
    auto response = mSession->attributes().try_read_sync(read_value(methodId, AttributeId::Executable));
    if (response.is_bad())
    {
      return std::nullopt;
    }
    auto value = std::move(response).value();
    if (value.results().size() != 1U)
    {
      return std::nullopt;
    }
    const bool* flag = value.results()[0].value().try_as<bool>();
    return (flag != nullptr) ? std::optional<bool>{*flag} : std::nullopt;
  }

  // Re-writes a scalar NodeId Property Value on the running server - here the machine's CurrentState.Id, i.e.
  // the State the machine reports itself to be in. Written on the address space directly because the Property
  // is CurrentRead-only to clients; the next client Read observes the new state.
  void write_node_id_value(const NodeId& propertyId, const NodeId& value)
  {
    auto addressSpace = mServer.server().address_space();
    addressSpace.find_node_sync(propertyId)
      .as<VariableAccessor>()
      ->write_value_sync(DataValue{Variant{value}});
  }

  // Re-writes a scalar LocalizedText Variable Value on the running server - here a machine's CurrentState
  // Variable, the human-readable half of the state the machine reports itself to be in. Written on the
  // address space directly for the same reason write_node_id_value is: the Variable is CurrentRead-only to
  // clients.
  void write_localized_text_value(const NodeId& variableId, LocalizedText value)
  {
    auto addressSpace = mServer.server().address_space();
    addressSpace.find_node_sync(variableId)
      .as<VariableAccessor>()
      ->write_value_sync(DataValue{Variant{std::move(value)}});
  }

  // Re-writes the AvailableStates Property Value on the running server - the server-side model change the two
  // cache rows react to. Done directly on the address space (bypasses the CurrentRead-only access level a
  // client Write would hit); the next client Read of the Property returns the new value.
  void write_node_id_array(const NodeId& propertyId, Array<NodeId> value)
  {
    auto addressSpace = mServer.server().address_space();
    addressSpace.find_node_sync(propertyId)
      .as<VariableAccessor>()
      ->write_value_sync(DataValue{Variant{std::move(value)}});
  }

  // Installs the MisbehavingServer-style per-channel request observer (the same interface MisbehavingServer
  // uses), feeding every request into the shared read counter. Installed before the server starts so it is
  // active for the channel the Connection opens.
  void install_request_observer()
  {
    auto& serverImpl = ServerTestAccess::impl(mServer.server());
    ServerImplTestAccess(serverImpl)
      .set_on_secure_channel_available(
        [counter = mReadCounter](std::shared_ptr<ua::server::SecureChannel> secureChannel)
        {
          ua::server::SecureChannelTestAccess::post_on_strand(std::move(secureChannel),
            [counter](auto& guard)
            {
              guard.set_request_observer([counter](std::uint32_t /*requestId*/, const ua::Structure& request)
                { counter->observe(request); });
            });
        });
  }

  // Installs the public `Server::set_event_listener` interface so every Event the server emits is captured
  // for the rows that assert over one. Installed here, before the server starts, for the same reason the
  // request observer is - and for one more: the listener is also what tells the EventBus that an observer
  // exists, and the emission gate reads that flag before deciding whether to build an Event at all, so a
  // listener installed after the fact would miss Events that were never made.
  void install_event_listener()
  {
    mServer.server().set_event_listener(
      [recorder = mEvents](const ua::BaseEvent& event) { recorder->record(event); });
  }

  // ---- typed-handle drivers (block on the test thread for the async completion) ----

  FiniteStateMachineHandleResult build_finite_machine(const NodeId& machineId)
  {
    std::promise<FiniteStateMachineHandleResult> promise;
    auto future = promise.get_future();
    mConnection->state_machine_accessor().finite_state_machine_async(
      machineId, [&promise](FiniteStateMachineHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static StateVariableResult read_current_state(StateMachineHandle handle)
  {
    std::promise<StateVariableResult> promise;
    auto future = promise.get_future();
    handle.current_state_async(
      [&promise](StateVariableResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<bool> current_state_is(StateMachineHandle handle, NodeId expectedStateId)
  {
    std::promise<Result<bool>> promise;
    auto future = promise.get_future();
    handle.current_state_is_async(
      std::move(expectedStateId), [&promise](Result<bool> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult refresh_topology(FiniteStateMachineHandle handle)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    handle.refresh_topology_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // FM4's AvailableStates Property NodeId (the re-read target).
  NodeId mReReadStatesId{mTestNamespaceIndex, uint32_t{9033}};
  NodeId mSubtypeRunningStateId{mTestNamespaceIndex, uint32_t{99023}};

  // FM5's nodes. Assigned in configure_server(), NOT in the member initialiser: mTestNamespaceIndex is only
  // populated once ComplianceWithNodes::configure_server() has registered the namespace, which happens long
  // after this fixture's members are constructed.
  NodeId mExecMachineTypeId;
  NodeId mExecReadyStateId;
  NodeId mExecRunningStateId;
  NodeId mExecCurrentStateIdPropertyId;
  NodeId mExecStartMethodId;
  NodeId mExecStopMethodId;

  // FM6's nodes (the HasSubStateMachine composition). Assigned in configure_server() for the same reason
  // FM5's are.
  NodeId mSubParentMachineId;
  NodeId mSubParentCurrentStateId;
  NodeId mSubParentCurrentStateIdPropertyId;
  NodeId mSubParentIdleStateId;
  NodeId mSubParentMachiningStateId;
  NodeId mSubMachineId;
  NodeId mSubMachineCurrentStateId;
  NodeId mSubMachineCurrentStateIdPropertyId;

  std::shared_ptr<TargetReadCounter> mReadCounter{std::make_shared<TargetReadCounter>()};
  std::shared_ptr<EmittedEventRecorder> mEvents{std::make_shared<EmittedEventRecorder>()};

  // Fully qualify the client channel/connection types: `SecureChannel` is ambiguous here (both ua::client::
  // and ua::server:: are in scope via the test-access interfaces).
  std::optional<ua::client::SecureChannel> mConnChannel;
  std::shared_ptr<ConnectionImpl> mConnImpl;
  std::optional<ua::client::Connection> mConnection;
};

// @relation(AC-SVR-SM-013-AVAILABLESTATES, scope=function)

// ============================================================================================================
// ResolvesAvailableStatesAndTransitions (CL-SM-005)
// The FiniteStateMachineType topology is browsed + read end-to-end: available_states() yields exactly the
// declared state Object NodeIds in order and available_transitions() the declared transition Object NodeIds.
// [neg] falsifier: if the Available* NodeId[] Values are not browsed/read the lists are empty and the
// topology is unknown - so asserting the exact non-empty, ordered sets refutes it.
// ============================================================================================================
// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST_F(ClientFiniteStateMachine, ResolvesAvailableStatesAndTransitions)
{
  auto handle = build_finite_machine(NodeId{mTestNamespaceIndex, uint32_t{9000}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  const auto states = handle.value().available_states();
  ASSERT_EQ(states.size(), 2U) << "the AvailableStates NodeId[] must be browsed + read into the topology";
  EXPECT_EQ(states[0].stateId, readyStateNode) << "AvailableStates[0] must resolve to the declared Ready Id";
  EXPECT_EQ(states[1].stateId, haltedStateId)
    << "AvailableStates[1] must resolve to the declared Halted Id, in array order";

  const auto transitions = handle.value().available_transitions();
  ASSERT_EQ(transitions.size(), 1U) << "the AvailableTransitions NodeId[] must be resolved";
  EXPECT_EQ(transitions[0].transitionId, runningToSuspendedId)
    << "AvailableTransitions[0] must resolve to the declared transition Id";
}

// ============================================================================================================
// StateIdDoesNotMatchUnrelatedState (CL-SM-006)
// current_state_is against an UNRELATED state NodeId (while the machine reports a different CurrentState.Id)
// returns false. [neg] falsifier: if identity resolution over-normalises (maps everything to a common
// ancestor) an unrelated state would wrongly match. A positive control (the machine's own state Id matches)
// guards against a vacuously-always-false comparison.
// ============================================================================================================
// @verifies CL-SM-006
// @relation(CL-SM-006, scope=function)
TEST_F(ClientFiniteStateMachine, StateIdDoesNotMatchUnrelatedState)
{
  auto handle = build_finite_machine(NodeId{mTestNamespaceIndex, uint32_t{9010}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  // The machine is in Running; an unrelated (Suspended) state Id must NOT match.
  auto unrelated = current_state_is(handle.value(), suspendedStateId);
  ASSERT_TRUE(unrelated.is_good()) << "0x" << std::hex << unrelated.status_code().as_uint32();
  EXPECT_FALSE(unrelated.value())
    << "an unrelated State NodeId must remain distinct after independent origin normalization";

  // Positive control: the machine's actual state Id matches (proves the comparison is not always false).
  auto own = current_state_is(handle.value(), runningStateNode);
  ASSERT_TRUE(own.is_good()) << "0x" << std::hex << own.status_code().as_uint32();
  EXPECT_TRUE(own.value()) << "the machine's own CurrentState.Id (Running) must match";
}

// ============================================================================================================
// SubtypeStateIdEqualsSupertypeIdNodeId (CL-SM-006)
// A subtype instance whose CurrentState.Id VALUE is the SUPERTYPE's Running state Object NodeId matches
// current_state_is when the caller supplies the subtype's distinct replicated Running Object NodeId. [neg]
// falsifier: raw NodeId equality returns false; resolving the subtype owner/type hierarchy must reach the
// first definition. A negative control guards against a vacuously-always-true comparison.
// ============================================================================================================
// @verifies CL-SM-006
// @relation(CL-SM-006, scope=function)
TEST_F(ClientFiniteStateMachine, SubtypeStateIdEqualsSupertypeIdNodeId)
{
  auto handle = build_finite_machine(NodeId{mTestNamespaceIndex, uint32_t{9020}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  // The subtype instance reports the SUPERTYPE-defined Running Id as its CurrentState.Id (the reuse rule).
  auto state = read_current_state(handle.value());
  ASSERT_TRUE(state.is_good()) << "0x" << std::hex << state.status_code().as_uint32();
  ASSERT_TRUE(state.value().id.has_value());
  EXPECT_EQ(*state.value().id, runningStateNode)
    << "a subtype that reuses the inherited Running state reports the SUPERTYPE's Running NodeId";

  // Passing the distinct subtype replica matches after resolution to the supertype's first definition.
  auto match = current_state_is(handle.value(), mSubtypeRunningStateId);
  ASSERT_TRUE(match.is_good()) << "0x" << std::hex << match.status_code().as_uint32();
  EXPECT_TRUE(match.value())
    << "the subtype Running Object must resolve to the supertype-defined Running identity";

  // Negative control: an unrelated supertype state Id must not match.
  auto other = current_state_is(handle.value(), suspendedStateId);
  ASSERT_TRUE(other.is_good()) << "0x" << std::hex << other.status_code().as_uint32();
  EXPECT_FALSE(other.value()) << "a different state Id must not match (comparison is not vacuously true)";
}

// @relation(AC-SVR-SM-013-AVAILABLESTATES, scope=function)

// ============================================================================================================
// AvailableStatesAbsentSurfacesNullopt (CL-SM-005)
// A finite machine WITHOUT the Optional AvailableStates / AvailableTransitions Properties still builds a Good
// handle (not a hard Bad Result), and its topology accessors surface an EMPTY list.
// CALIBRATION: the built accessors return std::vector (never std::optional), so "surfaces nullopt" is not
// representable - the real absent-behaviour is an EMPTY vector. This resolves the matrix drift (section 5.x
// #4) to the single built outcome while keeping the strong part (handle constructs / not a hard Bad Result).
// [neg] falsifier: an absent topology must not hard-fail the handle nor fabricate a bogus non-empty set.
// ============================================================================================================
// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST_F(ClientFiniteStateMachine, AvailableStatesAbsentSurfacesNullopt)
{
  auto handle = build_finite_machine(NodeId{mTestNamespaceIndex, uint32_t{9010}});
  ASSERT_TRUE(handle.is_good()) << "an absent topology must NOT hard-fail the finite handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  EXPECT_TRUE(handle.value().available_states().empty())
    << "CALIBRATION: absent AvailableStates surfaces an EMPTY vector (the built API returns std::vector, "
       "never "
       "std::optional), not a fabricated non-empty set";
  EXPECT_TRUE(handle.value().available_transitions().empty())
    << "absent AvailableTransitions must surface an empty vector too";
}

// ============================================================================================================
// ModelChangeInvalidatesTopologyCache (CL-SM-005) - CALIBRATED to the adopted design (matrix line 1079
// dropped the auto-invalidation premise as "contradicts adopted design"). A live handle's topology snapshot
// is captured once at construction and is NOT auto-invalidated by a server-side model change: after the
// AvailableStates Property Value changes on the server, available_states() STILL returns the
// construction-time snapshot (stale-by-design). The design's explicit mechanism - refresh_topology_async - is
// what updates it. This is BY DESIGN, not a defect: refresh_topology_async has no internal callers and the
// model-change route (AddressSpaceCache::on_model_change_async) never reaches a FiniteStateMachineHandle's
// topology cache. The assertion would flip if auto-invalidation were ever wired, forcing a design revisit.
// [neg]: a topology change must not silently mutate the cached snapshot without an explicit refresh.
// ============================================================================================================
// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST_F(ClientFiniteStateMachine, ModelChangeInvalidatesTopologyCache)
{
  auto handle = build_finite_machine(NodeId{mTestNamespaceIndex, uint32_t{9030}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  // Construction-time snapshot: [Ready, Suspended].
  const auto before = handle.value().available_states();
  ASSERT_EQ(before.size(), 2U);
  EXPECT_EQ(before[1].stateId, suspendedStateId);

  // A server-side topology change (the change a GeneralModelChangeEvent would announce): [Ready, Halted].
  write_node_id_array(mReReadStatesId, Array<NodeId>{readyStateNode, haltedStateId});

  // REAL behaviour: the handle's cache is NOT auto-invalidated - available_states() still serves the
  // construction snapshot.
  const auto afterChange = handle.value().available_states();
  ASSERT_EQ(afterChange.size(), 2U);
  EXPECT_EQ(afterChange[1].stateId, suspendedStateId)
    << "BY DESIGN: a model change does not auto-invalidate the handle topology cache; the snapshot is stale "
       "until an explicit refresh_topology_async";

  // The adopted mechanism: an explicit refresh re-reads and adopts the changed topology.
  auto refreshed = refresh_topology(handle.value());
  ASSERT_TRUE(refreshed.is_good()) << "0x" << std::hex << refreshed.status_code().as_uint32();
  const auto afterRefresh = handle.value().available_states();
  ASSERT_EQ(afterRefresh.size(), 2U);
  EXPECT_EQ(afterRefresh[1].stateId, haltedStateId) << "the explicit refresh must adopt the changed topology";
}

// ============================================================================================================
// TopologyReReadOnRefreshNotCachedStale (CL-SM-005)
// refresh_topology_async issues a GENUINE second wire Read rather than serving the cached value: with the
// server sequenced [Ready, Suspended] then [Ready, Halted], the handle surfaces the first value at
// construction and the second after refresh, and the server observes exactly two distinct Reads of the
// AvailableStates Property. [neg]: an explicit refresh must re-read, not serve cache.
// ============================================================================================================
// @verifies CL-SM-005
// @relation(CL-SM-005, scope=function)
TEST_F(ClientFiniteStateMachine, TopologyReReadOnRefreshNotCachedStale)
{
  auto handle = build_finite_machine(NodeId{mTestNamespaceIndex, uint32_t{9030}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  // Construction performed the first topology Read.
  EXPECT_EQ(mReadCounter->reads(), 1) << "the construction pre-flight must have read AvailableStates once";
  const auto first = handle.value().available_states();
  ASSERT_EQ(first.size(), 2U);
  EXPECT_EQ(first[1].stateId, suspendedStateId)
    << "the first read must surface the initial [Ready, Suspended]";

  // Sequence the server to the new topology, then refresh.
  write_node_id_array(mReReadStatesId, Array<NodeId>{readyStateNode, haltedStateId});
  auto refreshed = refresh_topology(handle.value());
  ASSERT_TRUE(refreshed.is_good()) << "0x" << std::hex << refreshed.status_code().as_uint32();

  // The refresh must have issued a distinct SECOND Read (not served the cached value).
  EXPECT_EQ(mReadCounter->reads(), 2)
    << "refresh_topology_async must issue a genuine second wire Read, not serve the cache";
  const auto second = handle.value().available_states();
  ASSERT_EQ(second.size(), 2U);
  EXPECT_EQ(second[1].stateId, haltedStateId)
    << "the re-read must surface the sequenced [Ready, Halted] in order, never a stale cached value";
}

// ============================================================================================================
// Part 16 section 4.4.2 / 4.4.5: a StateMachineType "shall have GeneratesEvent References to the targets of a
// HasEffect Reference for each of its Transitions". The obligation is a CONTAINMENT between two derived sets,
// not a presence check, so an implementation that wires GeneratesEvent by hand (or that publishes a type
// exactly as the vendor NodeSet declares it, without deriving the closure) passes every per-reference check
// while still under-advertising: each Transition's effect is reachable, the type's advertisement is not.
// A client builds its EventFilter from GeneratesEvent, so a missing entry does not stop the Event being
// raised - it stops the client subscribing to it, and the failure surfaces as a subscription that never
// fires.
// ============================================================================================================
// @verifies AC-SVR-SM-003-GENERATESEVENT
TEST_F(ClientFiniteStateMachine, StateMachineTypeAdvertisesEveryEventItsTransitionsCanRaise)
{
  const auto machineTypes = concrete_subtypes_of(NodeId{ObjectTypeId::StateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no concrete StateMachineType at all - the containment below would be vacuous";

  int effectsExamined{0};
  std::string unadvertised;
  for (const auto& machineType : machineTypes)
  {
    const auto generated = forward_targets(machineType, NodeId{ReferenceTypeId::GeneratesEvent});
    for (const auto& transition : components_of_type(machineType, NodeId{ObjectTypeId::TransitionType}))
    {
      for (const auto& effect : forward_targets(transition, NodeId{ReferenceTypeId::HasEffect}))
      {
        if (!is_type_or_subtype_of(effect, NodeId{ObjectTypeId::BaseEventType}))
        {
          continue;  // HasEffect may also name a non-Event effect; only EventTypes carry the obligation
        }
        ++effectsExamined;
        if (std::find(generated.begin(), generated.end(), effect) == generated.end())
        {
          unadvertised += "\n  " + ua::to_string(machineType) + " Transition " + ua::to_string(transition) +
                          " -HasEffect-> " + ua::to_string(effect) + " (not among " +
                          std::to_string(generated.size()) + " GeneratesEvent targets)";
        }
      }
    }
  }

  ASSERT_GT(effectsExamined, 0)
    << "no Transition in the published model names an EventType via HasEffect, so the containment asserted "
       "below would hold vacuously";
  EXPECT_TRUE(unadvertised.empty())
    << "every EventType a Transition can raise must appear among its StateMachineType's GeneratesEvent "
       "targets; these do not:"
    << unadvertised;
}

// ============================================================================================================
// Part 16 section 4.4.2: "The Executable Attribute is used to indicate whether the Method is valid given the
// current state of the machine." The model here declares everything needed to decide that - Start is the
// HasCause of the Transition out of Ready, Stop the HasCause of the Transition out of Running - and both
// Methods are published Executable. A server that treats Executable as a static Attribute set at modelling
// time (rather than deriving it from CurrentState.Id against the Transitions' FromState) offers the caller a
// button that cannot work, and the Call then fails with Bad_InvalidState at the worst possible moment.
// Both directions are asserted in both states, so neither an always-true nor an always-false answer passes.
// ============================================================================================================
// @verifies AC-SVR-SM-004-EXECUTABLE-TRACKS-STATE
TEST_F(ClientFiniteStateMachine, StateMachineMethodExecutableFollowsCurrentState)
{
  // The machine reports Ready: only the Transition out of Ready (caused by Start) can be taken.
  const auto startInReady = read_executable(mExecStartMethodId);
  ASSERT_TRUE(startInReady.has_value()) << "Executable is mandatory on a Method and must read as a Boolean";
  EXPECT_TRUE(*startInReady)
    << "Start causes ReadyToRunning and the machine is in Ready, so Start must read Executable";

  const auto stopInReady = read_executable(mExecStopMethodId);
  ASSERT_TRUE(stopInReady.has_value()) << "Executable is mandatory on a Method and must read as a Boolean";
  EXPECT_FALSE(*stopInReady)
    << "Stop causes RunningToReady, whose FromState is Running; while the machine is in Ready its Executable "
       "must be false rather than the value declared at modelling time";

  // Move the machine into Running. Nothing else changes - only CurrentState.Id.
  write_node_id_value(mExecCurrentStateIdPropertyId, mExecRunningStateId);

  const auto startInRunning = read_executable(mExecStartMethodId);
  ASSERT_TRUE(startInRunning.has_value()) << "Executable must still read as a Boolean after the state change";
  EXPECT_FALSE(*startInRunning)
    << "ReadyToRunning cannot be taken from Running, so Start must stop being Executable when the machine "
       "leaves Ready";

  const auto stopInRunning = read_executable(mExecStopMethodId);
  ASSERT_TRUE(stopInRunning.has_value()) << "Executable must still read as a Boolean after the state change";
  EXPECT_TRUE(*stopInRunning)
    << "RunningToReady is now takeable, so Stop must become Executable - the Attribute tracks the state in "
       "both directions, it is not merely narrowed once";
}

// ============================================================================================================
// The machine's state is one of two conditions on Executable; the Executable Attribute the application sets
// is the other. The Call service refuses a Method whose Attribute is false with Bad_NotExecutable, so a Read
// that answered the state alone would offer a client a Method every Call of which is refused. Start is set
// not executable while the machine is in Ready, Start's FromState, so only the Attribute decides.
// ============================================================================================================
// @verifies AC-SVR-SM-004-EXECUTABLE-TRACKS-STATE
// @relation(AC-SVR-SM-004-EXECUTABLE-TRACKS-STATE, scope=function)
TEST_F(ClientFiniteStateMachine, AMethodTheApplicationMadeNotExecutableReadsNotExecutableInItsFromState)
{
  auto addressSpace = mServer.server().address_space();
  auto start = addressSpace.find_node_sync(mExecStartMethodId).as<MethodAccessor>();
  ASSERT_TRUE(start.has_value());
  start->set_executable(false);

  const auto startInReady = read_executable(mExecStartMethodId);
  ASSERT_TRUE(startInReady.has_value()) << "Executable is mandatory on a Method and must read as a Boolean";
  EXPECT_FALSE(*startInReady)
    << "the application set Start not executable, so Start must read not Executable even in its FromState";

  auto call = mSession->methods().try_call_sync(
    call_method(NodeId{mTestNamespaceIndex, uint32_t{9060}}, mExecStartMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service failed: 0x" << std::hex << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::BadNotExecutable)
    << "the Call service refuses a Method whose Executable Attribute is false, as the Read answered";
}

// ============================================================================================================
// Part 16 section 4.4.5: "A concrete subtype of FiniteStateMachineType shall define at least one State." The
// clause constrains the published model, so it is observed over the model rather than over a rejection path.
// An empty concrete machine looks well-formed to every per-node check - it has a valid BrowseName, a valid
// supertype and a CurrentState Variable - and only fails when a client browses for the states it is supposed
// to be able to be in and finds none, which is the point at which nothing can be said about the machine.
// ============================================================================================================
// @verifies AC-SVR-SM-008-ATLEAST-ONE-STATE
TEST_F(ClientFiniteStateMachine, ConcreteFiniteStateMachineTypeDefinesAtLeastOneState)
{
  const auto machineTypes = concrete_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no concrete FiniteStateMachineType subtype, so the invariant below would be vacuous";

  std::string stateless;
  for (const auto& machineType : machineTypes)
  {
    if (components_of_type(machineType, NodeId{ObjectTypeId::StateType}).empty())
    {
      stateless += "\n  " + ua::to_string(machineType);
    }
  }
  EXPECT_TRUE(stateless.empty())
    << "every non-abstract FiniteStateMachineType subtype must define at least one StateType child; these "
       "define none:"
    << stateless;
}

// ============================================================================================================
// Part 16 section 4.4.9: a FiniteStateMachine "can have at most one State of type InitialStateType". Two
// InitialStates would leave the entry state undefined - the machine would start wherever the implementation
// happened to look first, and a client reading the model could not predict it. Entry into that State is a
// separate, activation-conditioned obligation (section 4.4.5, "the State that the machine goes into when it
// is activated"); this walk activates no machine, so it asserts the declaration count only.
// ============================================================================================================
// @verifies AC-SVR-SM-009-ONE-INITIAL-STATE
TEST_F(ClientFiniteStateMachine, FiniteStateMachineDeclaresAtMostOneInitialState)
{
  const auto machineTypes = concrete_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no concrete FiniteStateMachineType subtype, so the count below would be vacuous";

  std::string overDeclared;
  int declaringTypes{0};
  for (const auto& machineType : machineTypes)
  {
    const auto initialStates = components_of_type(machineType, NodeId{ObjectTypeId::InitialStateType});
    if (initialStates.size() > 1U)
    {
      overDeclared +=
        "\n  " + ua::to_string(machineType) + " declares " + std::to_string(initialStates.size());
    }
    if (initialStates.size() == 1U)
    {
      ++declaringTypes;
    }
  }
  EXPECT_TRUE(overDeclared.empty())
    << "a FiniteStateMachine may declare at most one InitialStateType State; these declare more:"
    << overDeclared;
  EXPECT_GT(declaringTypes, 0)
    << "no machine type declares an InitialState at all, so the at-most-one count above is vacuous";
}

// ============================================================================================================
// Part 16 section 4.4.5 / 4.4.10: a Transition has EXACTLY one FromState and EXACTLY one ToState, and both
// targets are Objects of StateType or a subtype. Exactly-one is stronger than at-least-one in both
// directions, and the extra direction is the one that fails silently: a second FromState leaves the
// transition's origin ambiguous, so an evaluator that takes the first reference behaves differently from one
// that takes the last against the same conforming-looking model, and every per-reference presence check
// passes on both. The count is asserted over the model the RUNNING server publishes rather than over the
// source NodeSet, because reference mirroring at import is exactly the step that can duplicate a reference.
// ============================================================================================================
// @verifies AC-SVR-SM-010-FROM-TO-EXACTLY-ONE
TEST_F(ClientFiniteStateMachine, TransitionDeclaresExactlyOneFromStateAndOneToState)
{
  const auto transitions = all_transition_objects();
  ASSERT_FALSE(transitions.empty())
    << "the walk found no Transition Object at all, so the counts below would be vacuous";

  std::string malformed;
  for (const auto& transition : transitions)
  {
    const auto fromStates = forward_targets(transition, NodeId{ReferenceTypeId::FromState});
    const auto toStates = forward_targets(transition, NodeId{ReferenceTypeId::ToState});
    if (fromStates.size() != 1U)
    {
      malformed += "\n  " + ua::to_string(transition) + " declares " + std::to_string(fromStates.size()) +
                   " FromState references (exactly one is required)";
    }
    if (toStates.size() != 1U)
    {
      malformed += "\n  " + ua::to_string(transition) + " declares " + std::to_string(toStates.size()) +
                   " ToState references (exactly one is required)";
    }
    for (const auto& target : fromStates)
    {
      if (!is_state_object(target))
      {
        malformed += "\n  " + ua::to_string(transition) + " FromState target " + ua::to_string(target) +
                     " is not an Object of StateType or a subtype";
      }
    }
    for (const auto& target : toStates)
    {
      if (!is_state_object(target))
      {
        malformed += "\n  " + ua::to_string(transition) + " ToState target " + ua::to_string(target) +
                     " is not an Object of StateType or a subtype";
      }
    }
  }
  EXPECT_TRUE(malformed.empty())
    << "every Transition must declare exactly one FromState and exactly one ToState, each an Object of "
       "StateType or a subtype; these do not:"
    << malformed;
}

// ============================================================================================================
// Part 16 section 4.4.18: a subtype of a concrete StateMachineType adds no top-level State or Transition and
// removes none - the two are forbidden in separate sentences, so the observation is set EQUALITY and not
// containment (a subtype that dropped a State satisfies a containment check written in the natural
// direction). This is the property that makes a state-machine taxonomy something a client can hard-code
// against, and this very file's SubtypeStateIdEqualsSupertypeIdNodeId row consumes it: a caller-supplied
// subtype State resolving to the supertype's identity only means anything if the subtype really carries the
// supertype's states. Compared by BrowseName because the replicas are distinct nodes by construction.
// ============================================================================================================
// @verifies AC-SVR-SM-014-SUBTYPE-NO-CHANGE
TEST_F(ClientFiniteStateMachine, SubtypeAddsAndRemovesNoTopLevelStateOrTransition)
{
  const auto pairs = state_machine_type_subtype_pairs();
  ASSERT_FALSE(pairs.empty())
    << "the walk found no StateMachineType subtype at all, so the comparison below would be vacuous";

  auto addressSpace = mServer.server().address_space();
  int substantivePairs{0};
  std::string drift;
  for (const auto& pair : pairs)
  {
    auto supertypeNode = addressSpace.try_find_node_sync(pair.supertype);
    if (supertypeNode.is_bad() || is_abstract_type(supertypeNode.value()))
    {
      continue;  // the clause is scoped to subtypes of a CONCRETE machine type
    }
    const auto supertypeStates =
      browse_names_of(components_of_type(pair.supertype, NodeId{ObjectTypeId::StateType}));
    const auto subtypeStates =
      browse_names_of(components_of_type(pair.subtype, NodeId{ObjectTypeId::StateType}));
    const auto supertypeTransitions =
      browse_names_of(components_of_type(pair.supertype, NodeId{ObjectTypeId::TransitionType}));
    const auto subtypeTransitions =
      browse_names_of(components_of_type(pair.subtype, NodeId{ObjectTypeId::TransitionType}));
    if (!supertypeStates.empty() || !supertypeTransitions.empty())
    {
      ++substantivePairs;
    }
    if (supertypeStates != subtypeStates)
    {
      drift += "\n  " + ua::to_string(pair.subtype) + " declares States [" + join_names(subtypeStates) +
               "] where its supertype " + ua::to_string(pair.supertype) + " declares [" +
               join_names(supertypeStates) + "]";
    }
    if (supertypeTransitions != subtypeTransitions)
    {
      drift += "\n  " + ua::to_string(pair.subtype) + " declares Transitions [" +
               join_names(subtypeTransitions) + "] where its supertype " + ua::to_string(pair.supertype) +
               " declares [" + join_names(supertypeTransitions) + "]";
    }
  }
  ASSERT_GT(substantivePairs, 0)
    << "no concrete supertype in the walk declares a State or a Transition, so every comparison above was "
       "the empty set against the empty set";
  EXPECT_TRUE(drift.empty())
    << "a subtype of a concrete StateMachineType may add SubStateMachines, Transitions into them and Causes "
       "or Effects on existing Transitions, but its top-level State and Transition sets must equal its "
       "supertype's; these differ:"
    << drift;
}

// ============================================================================================================
// Part 16 section 4.4.18: States and Transitions carry no ModellingRule (sections 4.4.26 / 4.4.27), so
// nothing inherits them - a subtype must RE-DECLARE every one of them, and manual replication is what drifts.
// The BrowseName-and-Number pairing is asserted together because the two identifiers are consumed by
// different clients: a counterpart with the right name and a different StateNumber breaks everything that
// switches on the number, one with the right number and a different name breaks everything that browses by
// name. The structural references are asserted by TARGET NAME, which is what admits the subtle half of the
// clause: a subtype that overrides a Method used as a Cause but leaves HasCause pointing at the supertype's
// Method has wired the transition to the implementation it replaced.
// ============================================================================================================
// @verifies AC-SVR-SM-015-SUBTYPE-REPLICATION
TEST_F(ClientFiniteStateMachine, SubtypeReplicatesSupertypeStatesTransitionsAndReferences)
{
  const auto pairs = state_machine_type_subtype_pairs();
  ASSERT_FALSE(pairs.empty())
    << "the walk found no StateMachineType subtype at all, so the replication check below would be vacuous";

  const std::vector<NodeId> structuralReferences{NodeId{ReferenceTypeId::FromState},
    NodeId{ReferenceTypeId::ToState},
    NodeId{ReferenceTypeId::HasCause},
    NodeId{ReferenceTypeId::HasEffect},
    NodeId{ReferenceTypeId::HasSubStateMachine},
    NodeId{ReferenceTypeId::HasGuard}};

  int statesExamined{0};
  int transitionsExamined{0};
  std::string unreplicated;
  for (const auto& pair : pairs)
  {
    const auto supertypeStates = components_of_type(pair.supertype, NodeId{ObjectTypeId::StateType});
    const auto subtypeStates = components_of_type(pair.subtype, NodeId{ObjectTypeId::StateType});
    for (const auto& state : supertypeStates)
    {
      ++statesExamined;
      const std::string name = browse_name_of(state);
      NodeId counterpart;
      for (const auto& candidate : subtypeStates)
      {
        if (browse_name_of(candidate) == name)
        {
          counterpart = candidate;
          break;
        }
      }
      if (counterpart.is_null())
      {
        unreplicated += "\n  " + ua::to_string(pair.subtype) + " has no counterpart for State '" + name +
                        "' declared on " + ua::to_string(pair.supertype);
        continue;
      }
      if (type_definition_of(counterpart) != type_definition_of(state))
      {
        unreplicated += "\n  " + ua::to_string(pair.subtype) + " State '" + name + "' is a " +
                        ua::to_string(type_definition_of(counterpart)) + " where the supertype declares a " +
                        ua::to_string(type_definition_of(state));
      }
      if (number_property(counterpart, "StateNumber") != number_property(state, "StateNumber"))
      {
        unreplicated += "\n  " + ua::to_string(pair.subtype) + " State '" + name + "' has StateNumber " +
                        number_text(number_property(counterpart, "StateNumber")) +
                        " where the supertype declares " + number_text(number_property(state, "StateNumber"));
      }
    }

    const auto supertypeTransitions =
      components_of_type(pair.supertype, NodeId{ObjectTypeId::TransitionType});
    const auto subtypeTransitions = components_of_type(pair.subtype, NodeId{ObjectTypeId::TransitionType});
    for (const auto& transition : supertypeTransitions)
    {
      ++transitionsExamined;
      const std::string name = browse_name_of(transition);
      NodeId counterpart;
      for (const auto& candidate : subtypeTransitions)
      {
        if (browse_name_of(candidate) == name)
        {
          counterpart = candidate;
          break;
        }
      }
      if (counterpart.is_null())
      {
        unreplicated += "\n  " + ua::to_string(pair.subtype) + " has no counterpart for Transition '" + name +
                        "' declared on " + ua::to_string(pair.supertype);
        continue;
      }
      if (number_property(counterpart, "TransitionNumber") != number_property(transition, "TransitionNumber"))
      {
        unreplicated +=
          "\n  " + ua::to_string(pair.subtype) + " Transition '" + name + "' has TransitionNumber " +
          number_text(number_property(counterpart, "TransitionNumber")) + " where the supertype declares " +
          number_text(number_property(transition, "TransitionNumber"));
      }
      for (const auto& referenceType : structuralReferences)
      {
        const auto declared = target_browse_names(transition, referenceType);
        const auto replicated = target_browse_names(counterpart, referenceType);
        if (declared != replicated)
        {
          unreplicated += "\n  " + ua::to_string(pair.subtype) + " Transition '" + name + "' " +
                          ua::to_string(referenceType) + " targets [" + join_names(replicated) +
                          "] do not replicate the supertype's [" + join_names(declared) + "]";
        }
      }
    }
  }
  ASSERT_GT(statesExamined, 0)
    << "no supertype in the walk declares a State, so the state replication check above examined nothing";
  ASSERT_GT(transitionsExamined, 0)
    << "no supertype in the walk declares a Transition, so the transition replication check above examined "
       "nothing";
  EXPECT_TRUE(unreplicated.empty())
    << "a subtype must re-declare every State and Transition of its supertype with the same ObjectType, "
       "BrowseName and Number, and every structural reference on them; these are not replicated:"
    << unreplicated;
}

// ============================================================================================================
// Part 16 section 4.4.5: a sub-state machine is not active while the State that owns it (through
// HasSubStateMachine) is not the parent machine's current state, and in that case its CurrentState Variable
// shall carry the status Bad_StateNotActive. The observable the spec names is the QUALITY of the read, not
// the value: a server that keeps serving the last state at Good quality reports a branch the machine is no
// longer in as if it were still running, with nothing in the read to tell an operator it stopped. Whether the
// stale value or the CurrentState.Id Property is also cleared is unconstrained - the corpus's own reference
// model of an inactive machine publishes Bad_StateNotActive beside a populated value - so only the status is
// asserted. Both halves are checked: while the owning State is current the sub-machine must NOT report
// Bad_StateNotActive, otherwise a server that returned it unconditionally would pass.
// ============================================================================================================
// @verifies AC-SVR-SM-006-SUBSTATEMACHINE-ACTIVE-WITH-PARENT
TEST_F(ClientFiniteStateMachine, SubStateMachineCurrentStateNullOnceParentStateLeft)
{
  // The parent machine is published IN "Machining", the State that owns the sub-machine.
  const auto activeState = read_data_value(mSubMachineCurrentStateId);
  ASSERT_TRUE(activeState.has_value()) << "the sub-machine's CurrentState must be readable";
  EXPECT_FALSE(
    activeState->status().has_value() && (activeState->status()->as_status() == Status::BadStateNotActive))
    << "the sub-machine is active while its parent occupies the State that owns it, so its CurrentState must "
       "not report Bad_StateNotActive";
  const LocalizedText* activeText = activeState->value().try_as<LocalizedText>();
  ASSERT_NE(activeText, nullptr) << "CurrentState must decode as a LocalizedText while the machine is active";
  EXPECT_FALSE(static_cast<std::string>(activeText->text()).empty())
    << "while its parent state is current the sub-machine must report the state it is in";

  // The parent LEAVES "Machining" for "Idle" - both halves of its CurrentState, so the parent model reports
  // itself out of the owning State consistently and the antecedent of the rule genuinely holds.
  write_localized_text_value(mSubParentCurrentStateId, LocalizedText{"en", "Idle"});
  write_node_id_value(mSubParentCurrentStateIdPropertyId, mSubParentIdleStateId);

  const auto inactiveState = read_data_value(mSubMachineCurrentStateId);
  ASSERT_TRUE(inactiveState.has_value()) << "the sub-machine's CurrentState must still be readable";
  ASSERT_TRUE(inactiveState->status().has_value())
    << "once the parent left the owning State the sub-machine is inactive, so its CurrentState must carry a "
       "status rather than the default Good quality";
  EXPECT_EQ(inactiveState->status()->as_status(), Status::BadStateNotActive)
    << "the CurrentState of a sub-state machine whose parent State is not active shall read "
       "Bad_StateNotActive";
}

// ============================================================================================================
// Part 10 section 4.2.3 Table 1, section 4.2.4 Table 2 and section 4.2.7 Table 4: the Program state machine
// is a FIXED taxonomy - exactly four States (Halted 11, Ready 12, Running 13, Suspended 14) and exactly nine
// Transitions (HaltedToReady 1 through ReadyToHalted 9). "Exactly" runs in both directions and that is the
// whole obligation: a missing Transition makes a legal Program operation unreachable, and an extra State lets
// a Program report a state a generic client's state handling has no case for. An implementation that
// publishes the taxonomy from a hand-maintained list, or that lets a subtype extend it, passes every per-node
// check - each State is a well-formed StateType child with a plausible name - and only the SET comparison
// against Part 10 catches it. The Numbers are asserted beside the names because the two identifiers are
// consumed by different clients: one switches on the number, the other browses by name, and either alone
// leaves half the taxonomy unpinned.
// ============================================================================================================
// @verifies AC-SVR-SM-016-PROGRAM-FSM-SHAPE
TEST_F(ClientFiniteStateMachine, ProgramStateMachineDeclaresExactlyThePartTenStatesAndTransitions)
{
  // Sorted, because browse_names_of compares declarations as SETS.
  const std::vector<std::string> partTenStates{"Halted", "Ready", "Running", "Suspended"};
  const std::vector<std::string> partTenTransitions{"HaltedToReady",
    "ReadyToHalted",
    "ReadyToRunning",
    "RunningToHalted",
    "RunningToReady",
    "RunningToSuspended",
    "SuspendedToHalted",
    "SuspendedToReady",
    "SuspendedToRunning"};
  const std::map<std::string, std::uint32_t> partTenStateNumbers{
    {"Halted", 11U}, {"Ready", 12U}, {"Running", 13U}, {"Suspended", 14U}};
  const std::map<std::string, std::uint32_t> partTenTransitionNumbers{{"HaltedToReady", 1U},
    {"ReadyToRunning", 2U},
    {"RunningToHalted", 3U},
    {"RunningToReady", 4U},
    {"RunningToSuspended", 5U},
    {"SuspendedToRunning", 6U},
    {"SuspendedToHalted", 7U},
    {"SuspendedToReady", 8U},
    {"ReadyToHalted", 9U}};

  const auto programTypes = concrete_subtypes_of(NodeId{ObjectTypeId::ProgramStateMachineType});
  ASSERT_FALSE(programTypes.empty())
    << "the walk found no concrete ProgramStateMachineType at all, so the taxonomy comparison below would be "
       "vacuous";

  std::string drift;
  for (const auto& programType : programTypes)
  {
    const auto states = components_of_type(programType, NodeId{ObjectTypeId::StateType});
    const auto transitions = components_of_type(programType, NodeId{ObjectTypeId::TransitionType});
    const auto stateNames = browse_names_of(states);
    const auto transitionNames = browse_names_of(transitions);
    if (stateNames != partTenStates)
    {
      drift += "\n  " + ua::to_string(programType) + " declares States [" + join_names(stateNames) +
               "] where Part 10 defines exactly [" + join_names(partTenStates) + "]";
    }
    if (transitionNames != partTenTransitions)
    {
      drift += "\n  " + ua::to_string(programType) + " declares Transitions [" + join_names(transitionNames) +
               "] where Part 10 defines exactly [" + join_names(partTenTransitions) + "]";
    }
    for (const auto& state : states)
    {
      const std::string name = browse_name_of(state);
      const auto expected = partTenStateNumbers.find(name);
      if (expected == partTenStateNumbers.end())
      {
        continue;  // an unexpected State is already reported by the set comparison above
      }
      const auto declared = number_property(state, "StateNumber");
      if (declared != std::optional<std::uint32_t>{expected->second})
      {
        drift += "\n  " + ua::to_string(programType) + " State '" + name + "' has StateNumber " +
                 number_text(declared) + " where Part 10 defines " + std::to_string(expected->second);
      }
    }
    for (const auto& transition : transitions)
    {
      const std::string name = browse_name_of(transition);
      const auto expected = partTenTransitionNumbers.find(name);
      if (expected == partTenTransitionNumbers.end())
      {
        continue;  // an unexpected Transition is already reported by the set comparison above
      }
      const auto declared = number_property(transition, "TransitionNumber");
      if (declared != std::optional<std::uint32_t>{expected->second})
      {
        drift += "\n  " + ua::to_string(programType) + " Transition '" + name + "' has TransitionNumber " +
                 number_text(declared) + " where Part 10 defines " + std::to_string(expected->second);
      }
    }
  }
  EXPECT_TRUE(drift.empty())
    << "a ProgramStateMachineType must declare exactly the four Part 10 States and the nine Part 10 "
       "Transitions, each carrying the Number Part 10 gives it; these differ:"
    << drift;
}

// ============================================================================================================
// Part 16 section 4.4.5: each State shall have a BrowseName and a StateNumber that are independently unique
// within its StateMachine. The scope is deliberately tested in both directions: every machine with multiple
// States must be collision-free, while at least one name and one number must be reused by DIFFERENT machines.
// A validator accidentally indexed across the whole server would therefore fail the latter controls.
// ============================================================================================================
// @relation(AC-SVR-SM-012-STATE-IDENTITIES-UNIQUE, scope=function)
TEST_F(ClientFiniteStateMachine, StateBrowseNamesAndNumbersAreUniqueWithinEachStateMachine)
{
  const auto machineTypes = concrete_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no concrete FiniteStateMachineType subtype, so uniqueness would be vacuous";

  int machinesDeclaringTwoStates{0};
  std::map<std::string, int> machinesDeclaringName;
  std::map<std::uint32_t, int> machinesDeclaringNumber;
  std::string collisions;
  std::string missingNumbers;
  for (const auto& machineType : machineTypes)
  {
    const auto states = components_of_type(machineType, NodeId{ObjectTypeId::StateType});
    if (states.size() >= 2U)
    {
      ++machinesDeclaringTwoStates;
    }

    std::map<std::string, std::vector<NodeId>> statesByName;
    std::map<std::uint32_t, std::vector<NodeId>> statesByNumber;
    for (const auto& state : states)
    {
      statesByName[browse_name_of(state)].push_back(state);
      const auto number = number_property(state, "StateNumber");
      if (!number.has_value())
      {
        missingNumbers += "\n  " + ua::to_string(machineType) + " State " + ua::to_string(state);
        continue;
      }
      statesByNumber[*number].push_back(state);
    }

    for (const auto& [name, declared] : statesByName)
    {
      ++machinesDeclaringName[name];
      if (declared.size() > 1U)
      {
        collisions += "\n  " + ua::to_string(machineType) + " declares " + std::to_string(declared.size()) +
                      " States named '" + name + "'";
      }
    }
    for (const auto& [number, declared] : statesByNumber)
    {
      ++machinesDeclaringNumber[number];
      if (declared.size() > 1U)
      {
        collisions += "\n  " + ua::to_string(machineType) + " declares StateNumber " +
                      std::to_string(number) + " on " + std::to_string(declared.size()) + " States";
      }
    }
  }

  ASSERT_GT(machinesDeclaringTwoStates, 0)
    << "no machine declares two States, so no within-machine identity comparison occurred";
  EXPECT_TRUE(missingNumbers.empty())
    << "StateNumber is mandatory on every State; these published States omit it:" << missingNumbers;
  EXPECT_TRUE(collisions.empty())
    << "State BrowseName and StateNumber are each unique within one StateMachine; collisions:" << collisions;

  const auto reusedNames = std::count_if(machinesDeclaringName.begin(),
    machinesDeclaringName.end(),
    [](const auto& entry) { return entry.second > 1; });
  const auto reusedNumbers = std::count_if(machinesDeclaringNumber.begin(),
    machinesDeclaringNumber.end(),
    [](const auto& entry) { return entry.second > 1; });
  EXPECT_GT(reusedNames, 0)
    << "the published model must reuse a State BrowseName across different machines to pin per-machine scope";
  EXPECT_GT(reusedNumbers, 0)
    << "the published model must reuse a StateNumber across different machines to pin per-machine scope";
}

// ============================================================================================================
// Part 16 section 4.4.5: "Each Transition shall have a BrowseName which is unique within the StateMachine."
// The scope is the whole difficulty. A generator that allocates Transition nodes from a template and dedupes
// by NodeId happily produces two children named ToRunning on one machine - both are well-formed, both browse,
// and a client resolving the Transition by BrowseName then silently gets whichever the server enumerates
// first. The opposite mistake is as easy: a check written over the whole address space rejects two DIFFERENT
// machines that each define a ToRunning, which is conforming and common. The final expectation pins that
// second direction, so a wrongly-global rule cannot pass this walk unchanged.
// ============================================================================================================
// @verifies AC-SVR-SM-017-TRANSITION-BROWSENAME
TEST_F(ClientFiniteStateMachine, TransitionBrowseNamesAreUniqueWithinEachStateMachine)
{
  const auto machineTypes = concrete_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no concrete FiniteStateMachineType subtype, so the uniqueness check below would be "
       "vacuous";

  int typesDeclaringTwoTransitions{0};
  std::map<std::string, int> machinesDeclaringName;
  std::string collisions;
  for (const auto& machineType : machineTypes)
  {
    const auto transitions = components_of_type(machineType, NodeId{ObjectTypeId::TransitionType});
    if (transitions.size() >= 2U)
    {
      ++typesDeclaringTwoTransitions;
    }
    std::map<std::string, int> declared;
    for (const auto& transition : transitions)
    {
      ++declared[browse_name_of(transition)];
    }
    for (const auto& entry : declared)
    {
      ++machinesDeclaringName[entry.first];
      if (entry.second > 1)
      {
        collisions += "\n  " + ua::to_string(machineType) + " declares " + std::to_string(entry.second) +
                      " Transitions named '" + entry.first + "'";
      }
    }
  }

  ASSERT_GT(typesDeclaringTwoTransitions, 0)
    << "no machine type in the walk declares two Transitions, so every uniqueness comparison above was of a "
       "set against itself";
  EXPECT_TRUE(collisions.empty())
    << "every Transition of a StateMachine must carry a BrowseName unique within that machine; these repeat:"
    << collisions;

  int sharedAcrossMachines{0};
  for (const auto& entry : machinesDeclaringName)
  {
    if (entry.second > 1)
    {
      ++sharedAcrossMachines;
    }
  }
  EXPECT_GT(sharedAcrossMachines, 0)
    << "uniqueness is per-StateMachine, not global: the published model must contain a Transition BrowseName "
       "declared by two DIFFERENT machines, otherwise a wrongly-global uniqueness rule would pass this walk "
       "unchanged";
}

// ============================================================================================================
// Part 16 section 4.4.5: a Transition "may have a TransitionNumber which shall also be unique across all
// Transitions defined in the StateMachine" - a `may` governing a `shall`, and the mixed-presence case is
// where both natural readings break. A check that requires the Number rejects a conforming machine; a check
// that treats an ABSENT Number as a value reports a collision on every second Transition that omits one. The
// server side of that same trap is an importer or node builder that materialises the optional Property as a
// present zero: two Transitions that declare nothing then both read back as 0, which is a genuine uniqueness
// violation in the model the server publishes and is exactly what this walk detects. The mixed-presence
// machine the criterion's stimulus names is built here because no type in the loaded model exhibits it.
// ============================================================================================================
// @verifies AC-SVR-SM-018-TRANSITIONNUMBER
TEST_F(ClientFiniteStateMachine, DeclaredTransitionNumbersAreUniqueWithinEachStateMachine)
{
  // A conforming machine with SOME Transitions numbered and some not, built out of the same builders
  // configure_server uses so it is published by the running server exactly as any other type is.
  auto addressSpace = mServer.server().address_space();
  auto mixedType = create_subtype(addressSpace,
    NodeId{mTestNamespaceIndex, uint32_t{9200}},
    "FmMixedNumbers",
    NodeId{ObjectTypeId::FiniteStateMachineType});
  const NodeId idleStateId{mTestNamespaceIndex, uint32_t{9201}};
  const NodeId busyStateId{mTestNamespaceIndex, uint32_t{9202}};
  add_state(addressSpace, mixedType, idleStateId, "Idle", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, mixedType, busyStateId, "Busy", NodeId{ObjectTypeId::StateType});
  const NodeId goMethodId{mTestNamespaceIndex, uint32_t{9203}};
  add_method(addressSpace, mixedType, goMethodId, "Go");
  const NodeId numberedOneId{mTestNamespaceIndex, uint32_t{9204}};
  const NodeId numberedTwoId{mTestNamespaceIndex, uint32_t{9205}};
  const NodeId unnumberedId{mTestNamespaceIndex, uint32_t{9206}};
  add_transition(addressSpace, mixedType, numberedOneId, "IdleToBusy", idleStateId, busyStateId, goMethodId);
  add_transition(addressSpace, mixedType, numberedTwoId, "BusyToIdle", busyStateId, idleStateId, goMethodId);
  add_transition(addressSpace, mixedType, unnumberedId, "BusyToBusy", busyStateId, busyStateId, goMethodId);
  auto numberedOne = addressSpace.find_node_sync(numberedOneId);
  add_property(addressSpace,
    numberedOne,
    NodeId{mTestNamespaceIndex, uint32_t{9207}},
    "TransitionNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{12}}});
  auto numberedTwo = addressSpace.find_node_sync(numberedTwoId);
  add_property(addressSpace,
    numberedTwo,
    NodeId{mTestNamespaceIndex, uint32_t{9208}},
    "TransitionNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{21}}});

  const auto machineTypes = concrete_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no concrete FiniteStateMachineType subtype, so the uniqueness check below would be "
       "vacuous";

  int machinesDeclaringTwoNumbers{0};
  int machinesWithMixedPresence{0};
  int transitionsWithoutANumber{0};
  std::string collisions;
  for (const auto& machineType : machineTypes)
  {
    std::map<std::uint32_t, std::vector<std::string>> declared;
    int declaredCount{0};
    int absentCount{0};
    for (const auto& transition : components_of_type(machineType, NodeId{ObjectTypeId::TransitionType}))
    {
      const auto number = number_property(transition, "TransitionNumber");
      if (!number.has_value())
      {
        ++absentCount;
        ++transitionsWithoutANumber;
        continue;  // the `may`: an absent Number is not a value and cannot collide with one
      }
      ++declaredCount;
      declared[*number].push_back(browse_name_of(transition));
    }
    if (declaredCount >= 2)
    {
      ++machinesDeclaringTwoNumbers;
    }
    if ((declaredCount > 0) && (absentCount > 0))
    {
      ++machinesWithMixedPresence;
    }
    for (const auto& entry : declared)
    {
      if (entry.second.size() > 1U)
      {
        collisions += "\n  " + ua::to_string(machineType) + " declares TransitionNumber " +
                      std::to_string(entry.first) + " on [" + join_names(entry.second) + "]";
      }
    }
  }

  ASSERT_GT(machinesDeclaringTwoNumbers, 0)
    << "no machine in the walk declares two TransitionNumbers, so the uniqueness comparison above compared "
       "nothing";
  EXPECT_GT(transitionsWithoutANumber, 0)
    << "no Transition in the published model omits its TransitionNumber, so the tolerance the clause's `may` "
       "requires was never exercised - the optional Property is being materialised where it was not declared";
  EXPECT_GT(machinesWithMixedPresence, 0)
    << "the mixed-presence machine built above must read back as mixed: a server that materialises an absent "
       "optional TransitionNumber as a present value destroys the distinction the `may` rests on";
  EXPECT_TRUE(collisions.empty())
    << "a TransitionNumber, where declared, must be unique across the Transitions of its StateMachine, and a "
       "Transition that declares none must not be treated as carrying one; these values repeat:"
    << collisions;
}

// ============================================================================================================
// Part 16 section 4.4.5: a State that hosts a child state machine is wired to it with a `HasSubStateMachine`
// Reference - not `HasComponent`, not a vendor ReferenceType. The wrong ReferenceType is the failure that
// looks right in every browse: the child machine appears under the State, its own States and Transitions
// resolve, and a client inspecting the model sees a composition that is complete. It is the runtime that
// breaks - `HasSubStateMachine` is the reference activation is propagated along, so a `HasComponent` link
// yields a child that browses correctly and never activates, and the only symptom is a sub-machine that
// stays in its initial state forever. The walk enumerates the model the running server publishes so an
// importer that rewrites the reference on the way in is caught alongside a hand-built one.
// @verifies AC-SVR-SM-019-HASSUBSTATEMACHINE
TEST_F(ClientFiniteStateMachine, StateHostingASubStateMachineLinksItWithHasSubStateMachine)
{
  auto addressSpace = mServer.server().address_space();

  int hostingLinks{0};
  std::string wrongReference;
  for (const auto& nodeId : enumerate_all_nodes())
  {
    if (!is_state_object(nodeId))
    {
      continue;
    }
    auto node = addressSpace.try_find_node_sync(nodeId);
    if (node.is_bad())
    {
      continue;
    }
    auto references = node.value().try_get_references_sync();
    if (references.is_bad())
    {
      continue;
    }
    for (const auto& reference : references.value())
    {
      if (!reference.is_forward() || reference.is_remote() ||
          (reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition}))
      {
        continue;
      }
      const NodeId target = reference.target_id().node_id();
      const NodeId definition = type_definition_of(target);
      if (definition.is_null() || !is_type_or_subtype_of(definition, NodeId{ObjectTypeId::StateMachineType}))
      {
        continue;  // the reference does not reach a state-machine Object, so the clause does not apply
      }
      ++hostingLinks;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasSubStateMachine})
      {
        wrongReference += "\n  State " + ua::to_string(nodeId) + " reaches the state machine " +
                          ua::to_string(target) + " through " + ua::to_string(reference.type_id()) +
                          " rather than HasSubStateMachine";
      }
    }
  }

  ASSERT_GT(hostingLinks, 0)
    << "no State in the published model reaches a state-machine Object at all, so the ReferenceType check "
       "above examined nothing";
  EXPECT_TRUE(wrongReference.empty())
    << "a State that hosts a SubStateMachine must be linked to it by HasSubStateMachine, the reference the "
       "runtime walks to propagate activation; these use another:"
    << wrongReference;
}

// ============================================================================================================
// Part 16 section 4.4.6: "The Name Property is inherited from StateVariableType. Its Value shall be the
// BrowseName of one of the State Objects of the FiniteStateMachineType." The obligation is membership, and
// SVR-SM-021 adds the consequence of SVR-SM-012's BrowseName uniqueness - the Name therefore identifies
// exactly one State. So what has to survive the round trip is a QualifiedName that still resolves against the
// machine's declared topology when both are fetched over the wire: a server that dropped the namespace index
// from the QualifiedName, or that did not expose the type's State Objects under HasComponent to Browse, would
// publish a Name matching nothing, and the machine would be uninterpretable to a client that had only the
// protocol.
// @verifies AC-SVR-SM-021-FINITESTATE-NAME-IS-BROWSENAME
TEST_F(ClientFiniteStateMachine, FiniteStateVariableNameIsTheBrowseNameOfExactlyOneDeclaredState)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9210}};
  const NodeId readyStateId{mTestNamespaceIndex, uint32_t{9211}};
  const NodeId runningStateId{mTestNamespaceIndex, uint32_t{9213}};
  const NodeId currentStateId{mTestNamespaceIndex, uint32_t{9216}};
  const NodeId currentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9217}};
  const NodeId currentStateNamePropertyId{mTestNamespaceIndex, uint32_t{9218}};

  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmStateRenderings", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, runningStateId, "Running", NodeId{ObjectTypeId::StateType});

  auto machine = create_machine(
    addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9215}}, "FmStateRenderingsInstance", machineTypeId);
  auto currentState = add_state_variable(
    addressSpace, machine, currentStateId, "CurrentState", DataValue{Variant{LocalizedText{"en", "Ready"}}});
  currentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
  add_property(addressSpace,
    currentState,
    currentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{readyStateId}});
  add_property(addressSpace,
    currentState,
    currentStateNamePropertyId,
    "Name",
    NodeId{DataTypeId::QualifiedName},
    DataValue{Variant{QualifiedName{0, std::string{"Ready"}}}});

  const auto reportedName = read_data_value(currentStateNamePropertyId);
  ASSERT_TRUE(reportedName.has_value()) << "CurrentState.Name must be readable once the instance exposes it";
  const QualifiedName* name = reportedName->value().try_as<QualifiedName>();
  ASSERT_NE(name, nullptr)
    << "the Name Property of a StateVariableType is a QualifiedName (Part 16 section 4.4.3)";
  const std::string reported{static_cast<std::string_view>(name->name())};

  // The machine's declared topology, fetched the same way a client with only the protocol would fetch it.
  const auto declaredStates =
    browse_names_of(components_of_type(machineTypeId, NodeId{ObjectTypeId::StateType}));
  ASSERT_GT(declaredStates.size(), 1u)
    << "the machine type must declare more than one State, or a Name naming 'one of' them says nothing";

  const auto matches =
    static_cast<std::size_t>(std::count(declaredStates.begin(), declaredStates.end(), reported));
  EXPECT_EQ(matches, 1u) << "CurrentState.Name must be the BrowseName of exactly one of the machine's own "
                            "States (Part 16 section 4.4.6 with SVR-SM-012's BrowseName uniqueness); '"
                         << reported << "' matches " << matches << " of [" << join_names(declaredStates)
                         << "]";
}

// ============================================================================================================
// Part 16 section 4.4.6: "The Number Property is inherited from StateVariableType. Its Value shall be the
// StateNumber for one of the State Objects of the FiniteStateMachineType." Number is the rendering a
// generated client stub switches on, being the only locale-independent scalar of the three, so a Number that
// resolves to no declared State sends the client down a branch belonging to no state at all. The two States
// carry different StateNumbers deliberately and the expected values are read back from the State Objects' own
// StateNumber Properties rather than restated, so the check follows a machine renumbered in the model.
// @verifies AC-SVR-SM-022-FINITESTATE-NUMBER-IS-STATENUMBER
TEST_F(ClientFiniteStateMachine, FiniteStateVariableNumberIsTheStateNumberOfExactlyOneDeclaredState)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9220}};
  const NodeId readyStateId{mTestNamespaceIndex, uint32_t{9221}};
  const NodeId runningStateId{mTestNamespaceIndex, uint32_t{9223}};
  const NodeId currentStateId{mTestNamespaceIndex, uint32_t{9226}};
  const NodeId currentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9227}};
  const NodeId currentStateNumberPropertyId{mTestNamespaceIndex, uint32_t{9229}};

  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmNumberRenderings", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, runningStateId, "Running", NodeId{ObjectTypeId::StateType});
  auto readyState = addressSpace.find_node_sync(readyStateId);
  add_property(addressSpace,
    readyState,
    NodeId{mTestNamespaceIndex, uint32_t{9222}},
    "StateNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{1}}});
  auto runningState = addressSpace.find_node_sync(runningStateId);
  add_property(addressSpace,
    runningState,
    NodeId{mTestNamespaceIndex, uint32_t{9224}},
    "StateNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{2}}});

  auto machine = create_machine(
    addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9225}}, "FmNumberRenderingsInstance", machineTypeId);
  auto currentState = add_state_variable(
    addressSpace, machine, currentStateId, "CurrentState", DataValue{Variant{LocalizedText{"en", "Ready"}}});
  currentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
  add_property(addressSpace,
    currentState,
    currentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{readyStateId}});
  add_property(addressSpace,
    currentState,
    currentStateNumberPropertyId,
    "Number",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{1}}});

  const auto readyNumber = number_property(readyStateId, "StateNumber");
  const auto runningNumber = number_property(runningStateId, "StateNumber");
  ASSERT_TRUE(readyNumber.has_value()) << "the Ready State must publish the StateNumber it was built with";
  ASSERT_TRUE(runningNumber.has_value())
    << "the Running State must publish the StateNumber it was built with";
  ASSERT_NE(*readyNumber, *runningNumber)
    << "the two States must carry different StateNumbers, or a Number matching 'one of' them says nothing";

  const auto reportedNumber = read_data_value(currentStateNumberPropertyId);
  ASSERT_TRUE(reportedNumber.has_value())
    << "CurrentState.Number must be readable once the instance exposes it";
  const std::uint32_t* number = reportedNumber->value().try_as<std::uint32_t>();
  ASSERT_NE(number, nullptr)
    << "the Number Property of a StateVariableType is a UInt32 (Part 16 section 4.4.3)";

  // The StateNumbers the machine's own States declare, read back over the wire rather than restated.
  std::vector<std::uint32_t> declaredNumbers;
  for (const auto& stateId : components_of_type(machineTypeId, NodeId{ObjectTypeId::StateType}))
  {
    if (const auto stateNumber = number_property(stateId, "StateNumber"); stateNumber.has_value())
    {
      declaredNumbers.push_back(*stateNumber);
    }
  }
  ASSERT_GT(declaredNumbers.size(), 1u)
    << "fewer than two of the machine's States publish a StateNumber, so the membership check below would "
       "be vacuous";

  const auto matches =
    static_cast<std::size_t>(std::count(declaredNumbers.begin(), declaredNumbers.end(), *number));
  EXPECT_EQ(matches, 1u) << "CurrentState.Number must be the StateNumber of exactly one of the machine's own "
                            "States (Part 16 section 4.4.6); "
                         << *number << " matches " << matches << " of the " << declaredNumbers.size()
                         << " StateNumbers declared";
}

// ============================================================================================================
// Part 16 section 4.4.7: "This value shall be the NodeId of one of the Transition Objects of the
// FiniteStateMachineType." LastTransition is the cheap way to follow a machine without subscribing to events,
// and a client can only follow it if the NodeId it reads resolves against the Transitions the type declares.
// Both sides are fetched over the wire - the Property value, and the Transition Objects reached by browsing
// the type - so an identifier that arrived with a mangled namespace index, or a type whose Transitions are
// not reachable by Browse, fails here rather than in the client that later cannot resolve it.
// @verifies AC-SVR-SM-023-FINITETRANSITION-ID-IS-NODEID
TEST_F(ClientFiniteStateMachine, FiniteTransitionVariableIdIsTheNodeIdOfATransitionOfTheMachine)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9240}};
  const NodeId readyStateId{mTestNamespaceIndex, uint32_t{9241}};
  const NodeId runningStateId{mTestNamespaceIndex, uint32_t{9242}};
  const NodeId readyToRunningId{mTestNamespaceIndex, uint32_t{9245}};
  const NodeId currentStateId{mTestNamespaceIndex, uint32_t{9251}};
  const NodeId currentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9252}};
  const NodeId lastTransitionId{mTestNamespaceIndex, uint32_t{9253}};
  const NodeId lastTransitionIdPropertyId{mTestNamespaceIndex, uint32_t{9254}};

  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmTransitionRenderings", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, runningStateId, "Running", NodeId{ObjectTypeId::StateType});
  const NodeId startMethodId{mTestNamespaceIndex, uint32_t{9243}};
  const NodeId stopMethodId{mTestNamespaceIndex, uint32_t{9244}};
  add_method(addressSpace, machineType, startMethodId, "Start");
  add_method(addressSpace, machineType, stopMethodId, "Stop");
  add_transition(addressSpace,
    machineType,
    readyToRunningId,
    "ReadyToRunning",
    readyStateId,
    runningStateId,
    startMethodId);
  add_transition(addressSpace,
    machineType,
    NodeId{mTestNamespaceIndex, uint32_t{9246}},
    "RunningToReady",
    runningStateId,
    readyStateId,
    stopMethodId);

  auto machine = create_machine(addressSpace,
    NodeId{mTestNamespaceIndex, uint32_t{9250}},
    "FmTransitionRenderingsInstance",
    machineTypeId);
  auto currentState = add_state_variable(
    addressSpace, machine, currentStateId, "CurrentState", DataValue{Variant{LocalizedText{"en", "Ready"}}});
  currentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
  add_property(addressSpace,
    currentState,
    currentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{readyStateId}});
  auto lastTransition = add_state_variable(
    addressSpace, machine, lastTransitionId, "LastTransition", DataValue{Variant{LocalizedText{}}});
  lastTransition.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteTransitionVariableType});
  // A machine that has taken the Ready -> Running Transition publishes it here. The Property is Mandatory on
  // FiniteTransitionVariableType, so a conforming machine never leaves it identifying nothing.
  add_property(addressSpace,
    lastTransition,
    lastTransitionIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{readyToRunningId}});

  const auto transitions = components_of_type(machineTypeId, NodeId{ObjectTypeId::TransitionType});
  ASSERT_GT(transitions.size(), 1u)
    << "the machine type must declare more than one Transition, or an Id naming 'one of' them says nothing";

  const auto reported = read_data_value(lastTransitionIdPropertyId);
  ASSERT_TRUE(reported.has_value()) << "LastTransition.Id must be readable";
  const NodeId* reportedId = reported->value().try_as<NodeId>();
  ASSERT_NE(reportedId, nullptr) << "LastTransition.Id must decode as a NodeId";
  EXPECT_FALSE(reportedId->is_null()) << "LastTransition.Id came back identifying no Transition at all";

  const auto matches =
    static_cast<std::size_t>(std::count(transitions.begin(), transitions.end(), *reportedId));
  EXPECT_EQ(matches, 1u) << "LastTransition.Id must be the NodeId of exactly one of the machine's own "
                            "Transition Objects (Part 16 section 4.4.7); "
                         << ua::to_string(*reportedId) << " matches " << matches << " of the "
                         << transitions.size() << " it declares";
}

// ============================================================================================================
// Part 16 section 4.4.7: "The Name Property is inherited from the TransitionVariableType. Its Value shall be
// the BrowseName of one of the Transition Objects of the FiniteStateMachineType." It is the human-facing half
// of the pair Id anchors, read by a different consumer - an HMI renders Name where a rule engine keys on Id -
// so a Name that resolves to no declared Transition puts a label on the operator's screen that corresponds to
// nothing in the machine. Both the Name and the declared Transitions are fetched over the wire, so the
// resolution a client would have to perform is the one performed here.
// @verifies AC-SVR-SM-024-FINITETRANSITION-NAME-IS-BROWSENAME
TEST_F(ClientFiniteStateMachine, FiniteTransitionVariableNameIsTheBrowseNameOfATransitionOfTheMachine)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9260}};
  const NodeId readyStateId{mTestNamespaceIndex, uint32_t{9261}};
  const NodeId runningStateId{mTestNamespaceIndex, uint32_t{9262}};
  const NodeId readyToRunningId{mTestNamespaceIndex, uint32_t{9265}};
  const NodeId currentStateId{mTestNamespaceIndex, uint32_t{9271}};
  const NodeId currentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9272}};
  const NodeId lastTransitionId{mTestNamespaceIndex, uint32_t{9273}};
  const NodeId lastTransitionNamePropertyId{mTestNamespaceIndex, uint32_t{9275}};

  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmTransitionNames", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, runningStateId, "Running", NodeId{ObjectTypeId::StateType});
  const NodeId startMethodId{mTestNamespaceIndex, uint32_t{9263}};
  const NodeId stopMethodId{mTestNamespaceIndex, uint32_t{9264}};
  add_method(addressSpace, machineType, startMethodId, "Start");
  add_method(addressSpace, machineType, stopMethodId, "Stop");
  add_transition(addressSpace,
    machineType,
    readyToRunningId,
    "ReadyToRunning",
    readyStateId,
    runningStateId,
    startMethodId);
  add_transition(addressSpace,
    machineType,
    NodeId{mTestNamespaceIndex, uint32_t{9266}},
    "RunningToReady",
    runningStateId,
    readyStateId,
    stopMethodId);

  auto machine = create_machine(
    addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9270}}, "FmTransitionNamesInstance", machineTypeId);
  auto currentState = add_state_variable(
    addressSpace, machine, currentStateId, "CurrentState", DataValue{Variant{LocalizedText{"en", "Ready"}}});
  currentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
  add_property(addressSpace,
    currentState,
    currentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{readyStateId}});
  auto lastTransition = add_state_variable(
    addressSpace, machine, lastTransitionId, "LastTransition", DataValue{Variant{LocalizedText{}}});
  lastTransition.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteTransitionVariableType});
  // A machine that has taken the Ready -> Running Transition names it here, as a conforming machine does.
  add_property(addressSpace,
    lastTransition,
    lastTransitionNamePropertyId,
    "Name",
    NodeId{DataTypeId::QualifiedName},
    DataValue{Variant{QualifiedName{mTestNamespaceIndex, browse_name_of(readyToRunningId)}}});

  const auto declaredTransitions =
    browse_names_of(components_of_type(machineTypeId, NodeId{ObjectTypeId::TransitionType}));
  ASSERT_GT(declaredTransitions.size(), 1u)
    << "the machine type must declare more than one Transition, or a Name naming 'one of' them says nothing";

  const auto read = read_data_value(lastTransitionNamePropertyId);
  ASSERT_TRUE(read.has_value()) << "LastTransition.Name must be readable";
  const QualifiedName* readName = read->value().try_as<QualifiedName>();
  ASSERT_NE(readName, nullptr)
    << "the Name Property of a TransitionVariableType is a QualifiedName (Part 16 section 4.4.4)";
  const std::string reported{static_cast<std::string_view>(readName->name())};

  const auto matches =
    static_cast<std::size_t>(std::count(declaredTransitions.begin(), declaredTransitions.end(), reported));
  EXPECT_EQ(matches, 1u) << "LastTransition.Name must be the BrowseName of exactly one of the machine's own "
                            "Transitions (Part 16 section 4.4.7); '"
                         << reported << "' matches " << matches << " of [" << join_names(declaredTransitions)
                         << "]";
}

// ============================================================================================================
// The absent ModellingRule is the mechanism, not an omission. A State that acquired one would be instantiated
// onto every instance of the machine, giving each instance a private copy of what is meant to be one shared
// taxonomy - which is exactly why section 4.4.18 makes a SUBTYPE re-declare its States by hand rather than
// inherit them, and why this file's SubtypeReplicatesSupertypeStatesTransitionsAndReferences row exists at
// all. The ReferenceType half fails just as quietly: HasComponent is what a state lookup walks, so a State
// attached by any other reference browses correctly and is invisible to every one of them. Both halves are
// read off the model the RUNNING server publishes, because an importer that materialises a default
// ModellingRule is precisely the step that would introduce one where the NodeSet declared none. Part 16
// section 4.4.8 - a State hangs off its FiniteStateMachineType by HasComponent and has no ModellingRule.
// @verifies AC-SVR-SM-026-STATE-NO-MODELLINGRULE
TEST_F(ClientFiniteStateMachine, StateObjectsHangOffTheirMachineTypeByHasComponentAndCarryNoModellingRule)
{
  const auto machineTypes = all_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no FiniteStateMachineType at all, so the invariant below would be vacuous";

  int statesDeclared{0};
  std::string offenders;
  for (const auto& machineType : machineTypes)
  {
    for (const auto& reference : forward_references(machineType))
    {
      if (!is_object_of_type(reference.target, NodeId{ObjectTypeId::StateType}))
      {
        continue;  // the reference does not reach a State Object, so the clause does not apply to it
      }
      ++statesDeclared;
      if (!is_type_or_subtype_of(reference.referenceType, NodeId{ReferenceTypeId::HasComponent}))
      {
        offenders += "\n  " + ua::to_string(machineType) + " reaches State " +
                     ua::to_string(reference.target) + " through " + ua::to_string(reference.referenceType) +
                     " rather than HasComponent or a subtype of it";
      }
      if (has_modelling_rule(reference.target))
      {
        offenders += "\n  State " + ua::to_string(reference.target) + " declared on " +
                     ua::to_string(machineType) +
                     " carries a ModellingRule, so it would be instantiated "
                     "onto every instance of the machine";
      }
    }
  }

  ASSERT_GT(statesDeclared, 0)
    << "no FiniteStateMachineType in the published model reaches a State Object at all, so the two checks "
       "above examined nothing";
  EXPECT_TRUE(offenders.empty())
    << "every State Object must be reached from its FiniteStateMachineType by HasComponent or a subtype of "
       "it, and must carry no ModellingRule; these do not:"
    << offenders;
}

// ============================================================================================================
// The Transition-side twin of the State clause, and a separate clause about a separate NodeClass: a
// Transition that acquired a ModellingRule would be copied onto every instance, so the same Transition would
// exist once per machine instance and the TransitionNumber that is supposed to identify it across the type
// would identify one copy among many. A single sweep would discharge both obligations, but they are kept
// apart because a validator that special-cases StateType and forgets TransitionType is the realistic failure
// and a merged assertion would report it as one.
// Part 16 section 4.4.10 - a Transition hangs off its FiniteStateMachineType by HasComponent and has no
// ModellingRule.
// @verifies AC-SVR-SM-027-TRANSITION-NO-MODELLINGRULE
TEST_F(
  ClientFiniteStateMachine, TransitionObjectsHangOffTheirMachineTypeByHasComponentAndCarryNoModellingRule)
{
  const auto machineTypes = all_subtypes_of(NodeId{ObjectTypeId::FiniteStateMachineType});
  ASSERT_FALSE(machineTypes.empty())
    << "the walk found no FiniteStateMachineType at all, so the invariant below would be vacuous";

  int transitionsDeclared{0};
  std::string offenders;
  for (const auto& machineType : machineTypes)
  {
    for (const auto& reference : forward_references(machineType))
    {
      if (!is_object_of_type(reference.target, NodeId{ObjectTypeId::TransitionType}))
      {
        continue;  // the reference does not reach a Transition Object, so the clause does not apply to it
      }
      ++transitionsDeclared;
      if (!is_type_or_subtype_of(reference.referenceType, NodeId{ReferenceTypeId::HasComponent}))
      {
        offenders += "\n  " + ua::to_string(machineType) + " reaches Transition " +
                     ua::to_string(reference.target) + " through " + ua::to_string(reference.referenceType) +
                     " rather than HasComponent or a subtype of it";
      }
      if (has_modelling_rule(reference.target))
      {
        offenders += "\n  Transition " + ua::to_string(reference.target) + " declared on " +
                     ua::to_string(machineType) +
                     " carries a ModellingRule, so it would be instantiated "
                     "onto every instance of the machine";
      }
    }
  }

  ASSERT_GT(transitionsDeclared, 0)
    << "no FiniteStateMachineType in the published model reaches a Transition Object at all, so the two "
       "checks above examined nothing";
  EXPECT_TRUE(offenders.empty())
    << "every Transition Object must be reached from its FiniteStateMachineType by HasComponent or a subtype "
       "of it, and must carry no ModellingRule; these do not:"
    << offenders;
}

// ============================================================================================================
// Where TransitionDeclaresExactlyOneFromStateAndOneToState constrains HOW MANY FromState references a
// Transition has, this constrains WHAT the reference may connect - and the two miss each other exactly: a
// Transition carrying one FromState that points at a Variable passes the cardinality check and is caught only
// here, while a State reached by a FromState sourced from something that is not a Transition is invisible to
// a walk that starts from Transitions at all. This sweep starts from the REFERENCE, so a FromState sourced
// from a Variable, an ObjectType or a State is examined rather than never visited. Part 16 section 4.4.11 - a
// FromState Reference runs from a TransitionType Object to a StateType Object.
// @verifies AC-SVR-SM-028-FROMSTATE-TYPING
TEST_F(ClientFiniteStateMachine, FromStateRunsFromATransitionObjectToAStateObject)
{
  const auto links = references_of_type(NodeId{ReferenceTypeId::FromState});
  ASSERT_FALSE(links.empty())
    << "the walk found no FromState reference in the whole address space, so the typing check below would be "
       "vacuous";

  std::string offenders;
  for (const auto& link : links)
  {
    if (!is_object_of_type(link.source, NodeId{ObjectTypeId::TransitionType}))
    {
      offenders += "\n  FromState source " + ua::to_string(link.source) +
                   " is not an Object of TransitionType or a subtype (it reaches " +
                   ua::to_string(link.target) + ")";
    }
    if (!is_object_of_type(link.target, NodeId{ObjectTypeId::StateType}))
    {
      offenders += "\n  FromState target " + ua::to_string(link.target) +
                   " is not an Object of StateType or a subtype (reached from " + ua::to_string(link.source) +
                   ")";
    }
  }
  EXPECT_TRUE(offenders.empty())
    << "every FromState Reference must run from an Object of TransitionType or a subtype to an Object of "
       "StateType or a subtype; these do not:"
    << offenders;
}

// ============================================================================================================
// The destination-side twin of the FromState clause. It is kept as its own sweep for the reason the two
// clauses are separate sentences in the specification: a model builder that wires FromState from a template
// and ToState by hand gets one right and the other wrong, and an assertion that folded them together would
// report a single failure for what are two independent wiring paths.
// Part 16 section 4.4.12 - a ToState Reference runs from a TransitionType Object to a StateType Object.
// @verifies AC-SVR-SM-029-TOSTATE-TYPING
TEST_F(ClientFiniteStateMachine, ToStateRunsFromATransitionObjectToAStateObject)
{
  const auto links = references_of_type(NodeId{ReferenceTypeId::ToState});
  ASSERT_FALSE(links.empty())
    << "the walk found no ToState reference in the whole address space, so the typing check below would be "
       "vacuous";

  std::string offenders;
  for (const auto& link : links)
  {
    if (!is_object_of_type(link.source, NodeId{ObjectTypeId::TransitionType}))
    {
      offenders += "\n  ToState source " + ua::to_string(link.source) +
                   " is not an Object of TransitionType or a subtype (it reaches " +
                   ua::to_string(link.target) + ")";
    }
    if (!is_object_of_type(link.target, NodeId{ObjectTypeId::StateType}))
    {
      offenders += "\n  ToState target " + ua::to_string(link.target) +
                   " is not an Object of StateType or a subtype (reached from " + ua::to_string(link.source) +
                   ")";
    }
  }
  EXPECT_TRUE(offenders.empty())
    << "every ToState Reference must run from an Object of TransitionType or a subtype to an Object of "
       "StateType or a subtype; these do not:"
    << offenders;
}

// ============================================================================================================
// This clause constrains ONE end. The second half of the sentence - "The TargetNode can be of any NodeClass"
// - is doing as much work as the first: a validator written by analogy with FromState would constrain the
// target too and reject the Method-triggered transitions that are the common case, so the freedom is asserted
// here as a positive fact about the model rather than left as an absence. The final expectation is what makes
// that concrete: a walk over a model containing no Method-caused Transition would never have exercised the
// freedom, and a wrongly-narrowed validator would pass it unchanged.
// Part 16 section 4.4.13 - a HasCause Reference runs from a TransitionType Object; its TargetNode may be any
// NodeClass.
// @verifies AC-SVR-SM-030-HASCAUSE-TYPING
TEST_F(ClientFiniteStateMachine, HasCauseRunsFromATransitionObjectAndLeavesItsTargetUnconstrained)
{
  auto addressSpace = mServer.server().address_space();
  const auto isMethod = [&addressSpace](const NodeId& nodeId)
  {
    auto node = addressSpace.try_find_node_sync(nodeId);
    return !node.is_bad() && node.value().as<MethodAccessor>().has_value();
  };

  const auto links = references_of_type(NodeId{ReferenceTypeId::HasCause});
  ASSERT_FALSE(links.empty())
    << "the walk found no HasCause reference in the whole address space, so the source check below would be "
       "vacuous";

  int methodTargets{0};
  std::string offenders;
  for (const auto& link : links)
  {
    if (!is_object_of_type(link.source, NodeId{ObjectTypeId::TransitionType}))
    {
      offenders += "\n  " + ua::to_string(link.referenceType) + " source " + ua::to_string(link.source) +
                   " is not an Object of TransitionType or a subtype (it reaches " +
                   ua::to_string(link.target) + ")";
    }
    if (isMethod(link.target))
    {
      ++methodTargets;
    }
  }

  EXPECT_TRUE(offenders.empty())
    << "every HasCause Reference must be sourced from an Object of TransitionType or a subtype; these are "
       "not:"
    << offenders;
  EXPECT_GT(methodTargets, 0)
    << "the clause constrains the SourceNode only - the TargetNode can be of any NodeClass - so a model in "
       "which no HasCause reaches a Method never exercises that freedom, and a validator that wrongly "
       "constrained the target by analogy with FromState would pass this walk unnoticed";
}

// ============================================================================================================
// The twin of the HasCause clause, with the same one-ended shape and the same trap in the second sentence.
// Where the target IS an EventType, the generation contract of SVR-SM-011 then applies - but that is a
// consequence of what the target happens to be, not a constraint on what it may be, so the sweep asserts
// nothing about the target beyond the fact that the model does reach a NodeClass other than Object through
// it. The Part 9 HasEffectDisable / Enable / Suppressed / Unsuppressed subtypes are swept alongside the base
// type: section 7.2 restates the TransitionType source rule for them verbatim, so a model that wires one of
// them from a State rather than a Transition is an offender the base-type-only sweep would never look at.
// Part 16 section 4.4.14 - a HasEffect Reference runs from a TransitionType Object; its TargetNode may be any
// NodeClass.
// @verifies AC-SVR-SM-031-HASEFFECT-TYPING
TEST_F(ClientFiniteStateMachine, HasEffectRunsFromATransitionObjectAndLeavesItsTargetUnconstrained)
{
  auto addressSpace = mServer.server().address_space();
  const auto isObjectType = [&addressSpace](const NodeId& nodeId)
  {
    auto node = addressSpace.try_find_node_sync(nodeId);
    return !node.is_bad() && node.value().as<ObjectTypeAccessor>().has_value();
  };

  const auto links = references_of_type(NodeId{ReferenceTypeId::HasEffect});
  ASSERT_FALSE(links.empty())
    << "the walk found no HasEffect reference in the whole address space, so the source check below would be "
       "vacuous";

  int nonObjectTargets{0};
  std::string offenders;
  for (const auto& link : links)
  {
    if (!is_object_of_type(link.source, NodeId{ObjectTypeId::TransitionType}))
    {
      offenders += "\n  " + ua::to_string(link.referenceType) + " source " + ua::to_string(link.source) +
                   " is not an Object of TransitionType or a subtype (it reaches " +
                   ua::to_string(link.target) + ")";
    }
    if (isObjectType(link.target))
    {
      ++nonObjectTargets;
    }
  }

  EXPECT_TRUE(offenders.empty())
    << "every HasEffect Reference (and every subtype of it) must be sourced from an Object of TransitionType "
       "or a subtype; these are not:"
    << offenders;
  EXPECT_GT(nonObjectTargets, 0)
    << "the clause leaves the TargetNode unconstrained, and the EventType case is the one that makes that "
       "matter: a model in which no HasEffect reaches an ObjectType never exercises the freedom, so a "
       "validator that required an Object target would pass this walk unnoticed";
}

// ============================================================================================================
// Two obligations in one clause, and the second is the one the specification words as `can be` rather than
// `shall be`. The corpus records that the SDK reads it as an invariant regardless, and the reason is
// operational rather than editorial: a SubStateMachine reached from two parent States has two States able to
// activate it and neither owning its deactivation, so the machine's lifecycle is decided by whichever parent
// the runtime happens to walk first. The typing half is asserted from the reference outward, so a
// HasSubStateMachine sourced from a Variable - the shape Part 9 uses to hang a limit machine off a
// TwoStateVariable - is examined rather than skipped by a walk that only ever starts at States.
// Part 16 section 4.4.15 - HasSubStateMachine runs State to StateMachineType, and each target has at most
// one.
// @verifies AC-SVR-SM-032-HASSUBSTATEMACHINE-TYPING
TEST_F(ClientFiniteStateMachine, HasSubStateMachineRunsFromAStateToAStateMachineNoMachineHavingTwoParents)
{
  const auto links = references_of_type(NodeId{ReferenceTypeId::HasSubStateMachine});
  ASSERT_FALSE(links.empty())
    << "the walk found no HasSubStateMachine reference in the whole address space, so the checks below would "
       "be vacuous";

  std::map<NodeId, int> parentsOf;
  std::string offenders;
  for (const auto& link : links)
  {
    ++parentsOf[link.target];
    if (!is_object_of_type(link.source, NodeId{ObjectTypeId::StateType}))
    {
      offenders += "\n  HasSubStateMachine source " + ua::to_string(link.source) +
                   " is not an Object of StateType (it hosts " + ua::to_string(link.target) + ")";
    }
    if (!is_object_of_type(link.target, NodeId{ObjectTypeId::StateMachineType}))
    {
      offenders += "\n  HasSubStateMachine target " + ua::to_string(link.target) +
                   " is not an Object of StateMachineType or a subtype (hosted by " +
                   ua::to_string(link.source) + ")";
    }
  }
  for (const auto& entry : parentsOf)
  {
    if (entry.second > 1)
    {
      offenders += "\n  SubStateMachine " + ua::to_string(entry.first) + " is hosted by " +
                   std::to_string(entry.second) +
                   " States, so no one State owns its activation and deactivation";
    }
  }

  EXPECT_TRUE(offenders.empty())
    << "HasSubStateMachine must run from a StateType Object to a StateMachineType Object, and no machine may "
       "be the target of more than one; these break that:"
    << offenders;
}

// ============================================================================================================
// This is what makes "the enclosing machine" a well-defined phrase, and the sub-machine lifecycle rule of
// SVR-SM-006 depends on it: the runtime walks upward from a SubStateMachine to find the State whose
// occupancy decides whether it is active, and a State hosting a machine owned by a DIFFERENT machine makes
// that walk ambiguous rather than merely unusual - there are then two answers to "which machine is this a
// sub-machine of" and nothing in the model chooses. Ownership is derived from a forward HasComponent scan of
// the whole model rather than from each node's inverse references, because a machine wired by a one-sided
// add_reference_sync stores no inverse and would otherwise read as belonging to nothing at all.
// Part 16 section 4.4.15 - the source State and the target SubStateMachine shall belong to the same
// StateMachine.
// @verifies AC-SVR-SM-033-SUBSTATEMACHINE-SAME-PARENT
TEST_F(ClientFiniteStateMachine, AStateAndTheSubStateMachineItHostsBelongToTheSameStateMachine)
{
  const auto links = references_of_type(NodeId{ReferenceTypeId::HasSubStateMachine});
  ASSERT_FALSE(links.empty())
    << "the walk found no HasSubStateMachine reference in the whole address space, so the ownership check "
       "below would be vacuous";

  const auto owners = has_component_owners();
  const auto idList = [](const std::vector<NodeId>& ids)
  {
    std::vector<std::string> names;
    names.reserve(ids.size());
    for (const auto& id : ids)
    {
      names.push_back(ua::to_string(id));
    }
    return names;
  };

  int examined{0};
  std::string offenders;
  for (const auto& link : links)
  {
    const auto stateOwners = owners.find(link.source);
    const auto machineOwners = owners.find(link.target);
    if ((stateOwners == owners.end()) || (machineOwners == owners.end()))
    {
      offenders += "\n  " + ua::to_string(link.source) + " hosts " + ua::to_string(link.target) + " but " +
                   ((stateOwners == owners.end()) ? "the State" : "the SubStateMachine") +
                   " is not a HasComponent child of any StateMachine at all";
      continue;
    }
    ++examined;
    bool shared{false};
    for (const auto& owner : stateOwners->second)
    {
      if (std::find(machineOwners->second.begin(), machineOwners->second.end(), owner) !=
          machineOwners->second.end())
      {
        shared = true;
        break;
      }
    }
    if (!shared)
    {
      offenders += "\n  State " + ua::to_string(link.source) + " belongs to [" +
                   join_names(idList(stateOwners->second)) + "] but the SubStateMachine it hosts, " +
                   ua::to_string(link.target) + ", belongs to [" + join_names(idList(machineOwners->second)) +
                   "]";
    }
  }

  ASSERT_GT(examined, 0)
    << "no HasSubStateMachine in the published model connects two nodes that both have a HasComponent owner, "
       "so the same-owner comparison above compared nothing";
  EXPECT_TRUE(offenders.empty())
    << "a State and the SubStateMachine it hosts must be HasComponent children of the same StateMachine; "
       "these are not:"
    << offenders;
}

// ============================================================================================================
// The last of the six renderings that keep a machine's state and transition reports interpretable. Number is
// the locale-independent one, so it is what a generated client stub switches on, and a Number that resolves
// to no declared Transition sends that stub down a branch belonging to no transition at all. The expected
// values are read back from the Transition Objects' own TransitionNumber Properties rather than restated in
// the test, so the check follows a machine that was renumbered in the model instead of pinning the numbers
// this test happened to write.
// Part 16 section 4.4.7 - a FiniteTransitionVariable's Number is the TransitionNumber of one of the machine's
// Transitions.
// @verifies AC-SVR-SM-025-FINITETRANSITION-NUMBER
TEST_F(ClientFiniteStateMachine, FiniteTransitionVariableNumberIsTheTransitionNumberOfATransitionOfTheMachine)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9280}};
  const NodeId readyStateId{mTestNamespaceIndex, uint32_t{9281}};
  const NodeId runningStateId{mTestNamespaceIndex, uint32_t{9282}};
  const NodeId startMethodId{mTestNamespaceIndex, uint32_t{9283}};
  const NodeId stopMethodId{mTestNamespaceIndex, uint32_t{9284}};
  const NodeId readyToRunningId{mTestNamespaceIndex, uint32_t{9285}};
  const NodeId runningToReadyId{mTestNamespaceIndex, uint32_t{9286}};
  const NodeId currentStateId{mTestNamespaceIndex, uint32_t{9291}};
  const NodeId currentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9292}};
  const NodeId lastTransitionId{mTestNamespaceIndex, uint32_t{9293}};
  const NodeId lastTransitionNumberPropertyId{mTestNamespaceIndex, uint32_t{9294}};

  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmTransitionNumbers", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, runningStateId, "Running", NodeId{ObjectTypeId::StateType});
  add_method(addressSpace, machineType, startMethodId, "Start");
  add_method(addressSpace, machineType, stopMethodId, "Stop");
  add_transition(addressSpace,
    machineType,
    readyToRunningId,
    "ReadyToRunning",
    readyStateId,
    runningStateId,
    startMethodId);
  add_transition(addressSpace,
    machineType,
    runningToReadyId,
    "RunningToReady",
    runningStateId,
    readyStateId,
    stopMethodId);
  auto readyToRunning = addressSpace.find_node_sync(readyToRunningId);
  add_property(addressSpace,
    readyToRunning,
    NodeId{mTestNamespaceIndex, uint32_t{9287}},
    "TransitionNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{2}}});
  auto runningToReady = addressSpace.find_node_sync(runningToReadyId);
  add_property(addressSpace,
    runningToReady,
    NodeId{mTestNamespaceIndex, uint32_t{9288}},
    "TransitionNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{4}}});

  auto machine = create_machine(
    addressSpace, NodeId{mTestNamespaceIndex, uint32_t{9290}}, "FmTransitionNumbersInstance", machineTypeId);
  auto currentState = add_state_variable(addressSpace,
    machine,
    currentStateId,
    "CurrentState",
    DataValue{Variant{LocalizedText{"en", "Running"}}});
  currentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
  add_property(addressSpace,
    currentState,
    currentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{runningStateId}});
  auto lastTransition = add_state_variable(
    addressSpace, machine, lastTransitionId, "LastTransition", DataValue{Variant{LocalizedText{}}});
  lastTransition.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteTransitionVariableType});
  // The machine has just taken Ready -> Running, so LastTransition renders that Transition and publishes the
  // TransitionNumber the Transition Object itself declares.
  add_property(addressSpace,
    lastTransition,
    lastTransitionNumberPropertyId,
    "Number",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{std::uint32_t{2}}});

  // The TransitionNumbers the machine's own Transitions declare, read back rather than restated.
  std::vector<std::uint32_t> declaredNumbers;
  for (const auto& transitionId : components_of_type(machineTypeId, NodeId{ObjectTypeId::TransitionType}))
  {
    if (const auto declared = number_property(transitionId, "TransitionNumber"); declared.has_value())
    {
      declaredNumbers.push_back(*declared);
    }
  }
  ASSERT_GT(declaredNumbers.size(), 1u)
    << "fewer than two of the machine's Transitions publish a TransitionNumber, so the membership check "
       "below would be vacuous";
  ASSERT_NE(declaredNumbers[0], declaredNumbers[1])
    << "the two Transitions must carry different TransitionNumbers, or a Number matching 'one of' them says "
       "nothing";

  const auto reported = read_data_value(lastTransitionNumberPropertyId);
  ASSERT_TRUE(reported.has_value()) << "LastTransition.Number must be readable";
  const std::uint32_t* number = reported->value().try_as<std::uint32_t>();
  ASSERT_NE(number, nullptr)
    << "the Number Property of a TransitionVariableType is a UInt32 (Part 16 section 4.4.4)";

  const auto matches =
    static_cast<std::size_t>(std::count(declaredNumbers.begin(), declaredNumbers.end(), *number));
  EXPECT_EQ(matches, 1u) << "LastTransition.Number must be the TransitionNumber of exactly one of the "
                            "machine's own Transition Objects (Part 16 section 4.4.7); "
                         << *number << " matches " << matches << " of the " << declaredNumbers.size()
                         << " TransitionNumbers declared";
}

// ============================================================================================================
// A ChoiceState is a pseudo-state: it is exited the instant it is entered, by evaluating Guards, so there is
// no moment at which the machine sits in it waiting for something to happen. A HasCause on a leaving
// Transition is therefore unreachable BY CONSTRUCTION rather than merely redundant - the machine has already
// left the state before any cause could fire - and a model carrying one describes a behaviour that cannot
// occur, which no amount of runtime testing will ever surface as a failure. The section 4.6 model the sweep
// needs is built here because no type in the loaded NS0 exhibits one. Part 16 section 4.6.2 - no Transition
// leaving a ChoiceState carries a trigger, i.e. a HasCause or a subtype of one.
// @verifies AC-SVR-SM-038-CHOICESTATE-NO-CAUSE
TEST_F(ClientFiniteStateMachine, NoTransitionLeavingAChoiceStateCarriesAHasCause)
{
  const auto exemplar = add_choice_state_exemplar(9300U);
  ASSERT_TRUE(is_object_of_type(exemplar.choiceStateId, NodeId{ObjectTypeId::ChoiceStateType}))
    << "the ChoiceState the sweep below needs did not come back as a ChoiceStateType Object, so the sweep "
       "would examine no leaving Transition at all";

  int leavingTransitions{0};
  std::string offenders;
  for (const auto& transition : all_transition_objects())
  {
    bool leavesAChoiceState{false};
    for (const auto& fromState : forward_targets(transition, NodeId{ReferenceTypeId::FromState}))
    {
      if (is_object_of_type(fromState, NodeId{ObjectTypeId::ChoiceStateType}))
      {
        leavesAChoiceState = true;
      }
    }
    if (!leavesAChoiceState)
    {
      continue;
    }
    ++leavingTransitions;
    for (const auto& reference : forward_references(transition))
    {
      if (is_type_or_subtype_of(reference.referenceType, NodeId{ReferenceTypeId::HasCause}))
      {
        offenders += "\n  Transition " + ua::to_string(transition) + " leaves a ChoiceState yet declares " +
                     ua::to_string(reference.referenceType) + " to " + ua::to_string(reference.target);
      }
    }
  }

  ASSERT_GT(leavingTransitions, 0)
    << "no Transition in the published model leaves a ChoiceState, so the check above examined nothing";
  EXPECT_TRUE(offenders.empty())
    << "a ChoiceState is exited on Guard evaluation the moment it is entered, so no Transition leaving one "
       "may declare a trigger; these do:"
    << offenders;
}

// ============================================================================================================
// Unlike HasCause and HasEffect, this ReferenceType constrains BOTH ends, and the target constraint is a
// VariableType where every neighbour in the family names an ObjectType. That is the one thing a validator
// written from the neighbours gets wrong: it looks for an Object of some GuardType, finds a Variable, and
// either rejects a conforming model or waves through a Guard pointing at an Object that can never carry a
// Boolean. Both guard kinds are present in the model the sweep runs over - an ExpressionGuardVariableType and
// an ElseGuardVariableType - so the "or one of its subtypes" half is exercised rather than assumed.
// Part 16 section 4.6.3 - a HasGuard Reference runs from a TransitionType Object to a GuardVariableType
// Variable.
// @verifies AC-SVR-SM-039-HASGUARD-TYPING
TEST_F(ClientFiniteStateMachine, HasGuardRunsFromATransitionObjectToAGuardVariable)
{
  const auto exemplar = add_choice_state_exemplar(9300U);

  const auto links = references_of_type(NodeId{ReferenceTypeId::HasGuard});
  ASSERT_FALSE(links.empty())
    << "the walk found no HasGuard reference in the whole address space, so the typing check below would be "
       "vacuous";

  int expressionGuards{0};
  int elseGuards{0};
  std::string offenders;
  for (const auto& link : links)
  {
    if (!is_object_of_type(link.source, NodeId{ObjectTypeId::TransitionType}))
    {
      offenders += "\n  HasGuard source " + ua::to_string(link.source) +
                   " is not an Object of TransitionType or a subtype (it reaches " +
                   ua::to_string(link.target) + ")";
    }
    if (!is_variable_of_type(link.target, NodeId{VariableTypeId::GuardVariableType}))
    {
      offenders += "\n  HasGuard target " + ua::to_string(link.target) +
                   " is not a Variable of GuardVariableType or a subtype (reached from " +
                   ua::to_string(link.source) + ")";
    }
    if (is_variable_of_type(link.target, NodeId{VariableTypeId::ExpressionGuardVariableType}))
    {
      ++expressionGuards;
    }
    if (is_variable_of_type(link.target, NodeId{VariableTypeId::ElseGuardVariableType}))
    {
      ++elseGuards;
    }
  }

  EXPECT_TRUE(offenders.empty())
    << "every HasGuard Reference must run from an Object of TransitionType or a subtype to a Variable of "
       "GuardVariableType or a subtype; these do not:"
    << offenders;
  EXPECT_GT(expressionGuards, 0) << "no HasGuard in the model reaches an ExpressionGuardVariableType, so the "
                                    "'or one of its subtypes' half of the target rule was never exercised";
  EXPECT_GT(elseGuards, 0) << "no HasGuard in the model reaches an ElseGuardVariableType (" +
                                ua::to_string(exemplar.elseGuardId) +
                                " was built to be one), so the second guard subtype was never exercised";
}

// ============================================================================================================
// An Else guard means "when no other Guard on this state's leaving Transitions matched", and that needs a
// moment at which all of them are evaluated together - which only a pseudo-state has. On an ordinary State
// the leaving Transitions are evaluated as their causes fire, one at a time and at unrelated moments, so
// there is no point at which "no other matched" is a determinate fact and the Else path becomes a transition
// that may or may not be taken depending on when the evaluator happened to look. ChoiceStateType is the only
// pseudo-state Part 16 defines, so it is what the sweep tests the FromState against.
// Part 16 section 4.6.6 - an ElseGuardVariableType is referenced only from Transitions leaving a
// pseudo-state.
// @verifies AC-SVR-SM-042-ELSEGUARD-PSEUDOSTATE
TEST_F(ClientFiniteStateMachine, ElseGuardsAppearOnlyOnTransitionsLeavingAPseudoState)
{
  const auto exemplar = add_choice_state_exemplar(9300U);
  ASSERT_TRUE(is_variable_of_type(exemplar.elseGuardId, NodeId{VariableTypeId::ElseGuardVariableType}))
    << "the ElseGuard the sweep below needs did not come back as an ElseGuardVariableType Variable, so the "
       "sweep would examine no Transition at all";

  int elseGuardedTransitions{0};
  std::string offenders;
  for (const auto& transition : all_transition_objects())
  {
    bool carriesAnElseGuard{false};
    for (const auto& guard : forward_targets(transition, NodeId{ReferenceTypeId::HasGuard}))
    {
      if (is_variable_of_type(guard, NodeId{VariableTypeId::ElseGuardVariableType}))
      {
        carriesAnElseGuard = true;
      }
    }
    if (!carriesAnElseGuard)
    {
      continue;
    }
    ++elseGuardedTransitions;
    const auto fromStates = forward_targets(transition, NodeId{ReferenceTypeId::FromState});
    if (fromStates.empty())
    {
      offenders += "\n  Transition " + ua::to_string(transition) +
                   " references an ElseGuardVariableType but leaves no State at all";
    }
    for (const auto& fromState : fromStates)
    {
      if (!is_object_of_type(fromState, NodeId{ObjectTypeId::ChoiceStateType}))
      {
        offenders += "\n  Transition " + ua::to_string(transition) +
                     " references an ElseGuardVariableType but leaves " + ua::to_string(fromState) +
                     ", which is not a pseudo-state";
      }
    }
  }

  ASSERT_GT(elseGuardedTransitions, 0)
    << "no Transition in the published model references an ElseGuardVariableType, so the check above "
       "examined nothing";
  EXPECT_TRUE(offenders.empty())
    << "an ElseGuardVariableType may only be referenced from a Transition leaving a pseudo-state such as a "
       "ChoiceState; these leave an ordinary State:"
    << offenders;
}

// ============================================================================================================
// Two Else paths out of one State are two definitions of "when nothing else matched", and nothing in the
// model orders them - so the default path taken depends on the order the server enumerates references in,
// which is a property of the implementation rather than of the machine. The final expectation is what keeps
// the at-most-one count honest: a State with a single leaving Transition satisfies it without the rule ever
// binding, so the model must contain an Else-guarded State that has more than one way out.
// Part 16 section 4.6.6 - each State has at most one leaving Transition referencing an ElseGuardVariableType.
// @verifies AC-SVR-SM-043-ONE-ELSE-PER-STATE
TEST_F(ClientFiniteStateMachine, AStateHasAtMostOneElseGuardedLeavingTransition)
{
  const auto exemplar = add_choice_state_exemplar(9300U);
  ASSERT_TRUE(is_variable_of_type(exemplar.elseGuardId, NodeId{VariableTypeId::ElseGuardVariableType}))
    << "the ElseGuard the count below needs did not come back as an ElseGuardVariableType Variable";

  std::map<NodeId, int> leavingTransitions;
  std::map<NodeId, int> elseGuardedLeavers;
  for (const auto& transition : all_transition_objects())
  {
    bool carriesAnElseGuard{false};
    for (const auto& guard : forward_targets(transition, NodeId{ReferenceTypeId::HasGuard}))
    {
      if (is_variable_of_type(guard, NodeId{VariableTypeId::ElseGuardVariableType}))
      {
        carriesAnElseGuard = true;
      }
    }
    for (const auto& fromState : forward_targets(transition, NodeId{ReferenceTypeId::FromState}))
    {
      ++leavingTransitions[fromState];
      if (carriesAnElseGuard)
      {
        ++elseGuardedLeavers[fromState];
      }
    }
  }

  int statesWithADefaultPath{0};
  int statesWhereTheRuleBinds{0};
  std::string offenders;
  for (const auto& entry : elseGuardedLeavers)
  {
    if (entry.second >= 1)
    {
      ++statesWithADefaultPath;
    }
    if (leavingTransitions[entry.first] > 1)
    {
      ++statesWhereTheRuleBinds;
    }
    if (entry.second > 1)
    {
      offenders += "\n  State " + ua::to_string(entry.first) + " has " + std::to_string(entry.second) +
                   " leaving Transitions referencing an ElseGuardVariableType, so which one is the default "
                   "path depends on traversal order";
    }
  }

  ASSERT_GT(statesWithADefaultPath, 0)
    << "no State in the published model has an Else-guarded leaving Transition, so the count above counted "
       "nothing";
  EXPECT_GT(statesWhereTheRuleBinds, 0)
    << "every Else-guarded State in the model has only one leaving Transition, so the at-most-one rule is "
       "satisfied without ever binding - the model must contain a State with more than one way out";
  EXPECT_TRUE(offenders.empty())
    << "a State may have at most one leaving Transition referencing an ElseGuardVariableType; these have "
       "more:"
    << offenders;
}

// ============================================================================================================
// An Else guard combined with an Expression guard is self-contradictory rather than merely redundant: Else
// means "this Transition is taken when no other Guard matched", and an Expression alongside it makes the same
// Transition conditional on a test - so the Transition would have to be both the fallback and one of the
// candidates the fallback is evaluated against. The count is taken over the model the RUNNING server
// publishes rather than over the source declaration, because reference mirroring at import is exactly the
// step that can turn one declared HasGuard into two. The Expression-guarded sibling is required to exist so
// that a walk which classified every Guard as an Else guard could not pass this unchanged.
// Part 16 section 4.6.6 - a Transition referencing an ElseGuardVariableType references no other Guard.
// @verifies AC-SVR-SM-044-ELSE-IS-SOLE-GUARD
TEST_F(ClientFiniteStateMachine, ATransitionCarryingAnElseGuardCarriesNoOtherGuard)
{
  const auto exemplar = add_choice_state_exemplar(9300U);
  ASSERT_TRUE(is_variable_of_type(exemplar.elseGuardId, NodeId{VariableTypeId::ElseGuardVariableType}))
    << "the ElseGuard the count below needs did not come back as an ElseGuardVariableType Variable";

  int elseGuardedTransitions{0};
  int otherwiseGuardedTransitions{0};
  std::string offenders;
  for (const auto& transition : all_transition_objects())
  {
    const auto guards = forward_targets(transition, NodeId{ReferenceTypeId::HasGuard});
    if (guards.empty())
    {
      continue;
    }
    bool carriesAnElseGuard{false};
    for (const auto& guard : guards)
    {
      if (is_variable_of_type(guard, NodeId{VariableTypeId::ElseGuardVariableType}))
      {
        carriesAnElseGuard = true;
      }
    }
    if (!carriesAnElseGuard)
    {
      ++otherwiseGuardedTransitions;
      continue;
    }
    ++elseGuardedTransitions;
    if (guards.size() != 1U)
    {
      offenders += "\n  Transition " + ua::to_string(transition) +
                   " references an ElseGuardVariableType alongside " + std::to_string(guards.size() - 1U) +
                   " other Guard reference(s), so it is both the fallback and a candidate the fallback is "
                   "evaluated against";
    }
  }

  ASSERT_GT(elseGuardedTransitions, 0)
    << "no Transition in the published model references an ElseGuardVariableType, so the count above counted "
       "nothing";
  EXPECT_GT(otherwiseGuardedTransitions, 0)
    << "every guarded Transition in the model carries an Else guard, so a walk that classified every Guard "
       "as an Else guard would pass this unchanged - the model must contain a Transition guarded by "
       "something else";
  EXPECT_TRUE(offenders.empty())
    << "an ElseGuardVariableType must be the only Guard of its Transition; these carry another beside it:"
    << offenders;
}

// ============================================================================================================
// The Effect link is a GENERATION CONTRACT, not an annotation on the model. A subscriber learns that a
// machine moved only because the Event arrives, so a server that publishes the HasEffect and never raises the
// Event leaves the subscriber waiting on a Subscription that is working perfectly and will never fire - a
// failure with no symptom anywhere except the silence. The Transition is triggered the way a Client triggers
// one: by calling the Method the Transition names as its HasCause. That the Call returned Good is asserted
// first, because an Event obligation whose antecedent never happened would otherwise report as a missing
// Event rather than as a Transition that was never triggered.
// Part 16 section 4.4.14 - each time a Transition whose HasEffect names an EventType is triggered, an Event
// of that type or a subtype shall be generated.
// @relation(AC-SVR-SM-011-HASEFFECT-FIRES-EVENT, scope=function)
TEST_F(ClientFiniteStateMachine, TransitionCarryingAnEventTypeEffectRaisesThatEventWhenItIsTriggered)
{
  const auto exemplar = add_effect_machine_exemplar(9400U);
  const auto effectTypes = all_subtypes_of(NodeId{ObjectTypeId::TransitionEventType});
  ASSERT_FALSE(effectTypes.empty())
    << "TransitionEventType is not in the published model, so nothing below could recognise the Event the "
       "Transition declares as its Effect";

  auto call =
    mSession->methods().try_call_sync(call_method(exemplar.firstInstanceId, exemplar.startMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service itself failed: 0x" << std::hex
                              << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Method the Transition names as its HasCause could not be called, so the Transition was never "
       "triggered and the Event obligation below was never reached: 0x"
    << std::hex << response.results()[0].status_code().as_uint32();

  const auto matches = [&effectTypes](const std::shared_ptr<const BaseEvent>& event)
  {
    return std::find(effectTypes.begin(), effectTypes.end(), event->eventType) != effectTypes.end();
  };
  const auto captured = mEvents->wait_until([&matches](const EmittedEventRecorder::Captured& events)
    { return std::any_of(events.begin(), events.end(), matches); },
    5000ms);

  const auto raised = static_cast<std::size_t>(std::count_if(captured.begin(), captured.end(), matches));
  EXPECT_GT(raised, 0U)
    << "the Transition declares TransitionEventType as its HasEffect and a Client triggered it through its "
       "Cause Method, so an Event of that type or a subtype must have been generated; the server emitted "
    << captured.size() << " Event(s), none of them one";
}

// ============================================================================================================
// A subscriber receives the Events of every instance of a type on ONE Subscription, and SourceNode is the
// only field that separates them - so a server that filled it with the StateMachineType, or with the
// Transition Object, would leave two machines' transitions indistinguishable while every single-machine test
// still passed. Two instances of one type are therefore driven, and each Event is required to name the
// instance whose Transition it reports. The Calls are asserted Good first for the same reason as above: a
// SourceNode obligation is about the Events that were raised, not about Events that never happened.
// Part 16 section 4.4.16 - SourceNode shall be the NodeId of the StateMachine instance where the Transition
// occurs.
// @relation(AC-SVR-SM-034-TRANSITIONEVENT-SOURCENODE, scope=function)
TEST_F(ClientFiniteStateMachine, TransitionEventSourceNodeNamesTheMachineInstanceTheTransitionOccurredIn)
{
  const auto exemplar = add_effect_machine_exemplar(9400U);
  const auto effectTypes = all_subtypes_of(NodeId{ObjectTypeId::TransitionEventType});
  ASSERT_FALSE(effectTypes.empty()) << "TransitionEventType is not in the published model, so nothing below "
                                       "could recognise a TransitionEvent";

  for (const auto& instanceId : {exemplar.firstInstanceId, exemplar.secondInstanceId})
  {
    auto call = mSession->methods().try_call_sync(call_method(instanceId, exemplar.startMethodId));
    ASSERT_TRUE(call.is_good()) << "the Call service failed for " << ua::to_string(instanceId) << ": 0x"
                                << std::hex << call.status_code().as_uint32();
    auto response = std::move(call).value();
    ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
    ASSERT_TRUE(response.results()[0].status_code().is_good())
      << "the Cause Method could not be called on " << ua::to_string(instanceId)
      << ", so no Transition was triggered there: 0x" << std::hex
      << response.results()[0].status_code().as_uint32();
  }

  const auto matches = [&effectTypes](const std::shared_ptr<const BaseEvent>& event)
  {
    return std::find(effectTypes.begin(), effectTypes.end(), event->eventType) != effectTypes.end();
  };
  const auto captured = mEvents->wait_until([&matches](const EmittedEventRecorder::Captured& events)
    { return std::count_if(events.begin(), events.end(), matches) >= 2; },
    5000ms);

  std::vector<std::string> sources;
  bool namesFirst{false};
  bool namesSecond{false};
  for (const auto& event : captured)
  {
    if (!matches(event))
    {
      continue;
    }
    sources.push_back(ua::to_string(event->sourceNode));
    namesFirst = namesFirst || (event->sourceNode == exemplar.firstInstanceId);
    namesSecond = namesSecond || (event->sourceNode == exemplar.secondInstanceId);
  }

  ASSERT_GE(sources.size(), 2U)
    << "a Transition was triggered on each of two different instances, but the server raised "
    << sources.size() << " TransitionEvent(s), so the SourceNodes below have nothing to distinguish";
  EXPECT_TRUE(namesFirst) << "no TransitionEvent names the first machine instance "
                          << ua::to_string(exemplar.firstInstanceId) << " as its SourceNode; the SourceNodes "
                          << "seen were [" << join_names(sources) << "]";
  EXPECT_TRUE(namesSecond) << "no TransitionEvent names the second machine instance "
                           << ua::to_string(exemplar.secondInstanceId)
                           << " as its SourceNode; the SourceNodes " << "seen were [" << join_names(sources)
                           << "]";
}

// ============================================================================================================
// A ChoiceState is transient by definition - it exists to be left the instant it is entered - so a case in
// which no Guard holds leaves the machine sitting in a state its own model says it cannot occupy, with no
// Transition out and nothing to report but a machine that stopped. The observable is therefore a RUNTIME one:
// the machine is driven INTO the pseudo-state through the Method that causes the Transition to it, and its
// CurrentState.Id is then required to name one of the States the ChoiceState's leaving Transitions reach.
// Deliberately NOT asserted as "every ChoiceState carries an ElseGuardVariableType": section 4.6.2 requires
// only that the Guards be defined so at least one is true, and the Additional-context Else-guard idiom is the
// RECOMMENDED way to get there, not the required one - a ChoiceState whose Expression Guards are between them
// exhaustive conforms, and a sweep demanding an Else guard would report it as a defect and get a conforming
// model "fixed" by bolting on a Guard that can never fire. Both failure modes the clause names are separated
// in the expectations below: a machine still in Decide has stalled; a machine still in Idle never entered.
// The section 4.6 model and the instance the row drives are built here because no type in the loaded NS0
// exhibits one and no instance of one exists to drive. Part 16 section 4.6.2 - the Guards on a ChoiceState's
// Transitions shall be defined so at least one is true and a Transition can be determined.
// @verifies AC-SVR-SM-037-CHOICESTATE-GUARDS-TOTAL
TEST_F(ClientFiniteStateMachine, AMachineEnteringAChoiceStateResolvesOutOfItRatherThanStalling)
{
  const auto exemplar = add_choice_state_exemplar(9300U);
  ASSERT_TRUE(is_object_of_type(exemplar.choiceStateId, NodeId{ObjectTypeId::ChoiceStateType}))
    << "the Decide State did not come back as a ChoiceStateType Object, so entering it below would exercise "
       "no pseudo-state at all";

  // The States the ChoiceState's leaving Transitions reach, read back off the published model rather than
  // restated, so the row follows a machine whose branches were re-modelled.
  std::vector<NodeId> resolvableStates;
  for (const auto& transition : all_transition_objects())
  {
    const auto fromStates = forward_targets(transition, NodeId{ReferenceTypeId::FromState});
    if (std::find(fromStates.begin(), fromStates.end(), exemplar.choiceStateId) == fromStates.end())
    {
      continue;
    }
    for (const auto& toState : forward_targets(transition, NodeId{ReferenceTypeId::ToState}))
    {
      resolvableStates.push_back(toState);
    }
  }
  ASSERT_GT(resolvableStates.size(), 1U)
    << "the ChoiceState reaches fewer than two States, so there is no choice for the Guards to determine and "
       "the expectations below would say nothing about Guard evaluation";

  // Enter the ChoiceState the way a Client enters it: by calling the Method the Transition into it names as
  // its Cause. Asserted Good first - an obligation about what happens on entry says nothing if entry failed.
  auto call = mSession->methods().try_call_sync(call_method(exemplar.instanceId, exemplar.goMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service itself failed: 0x" << std::hex
                              << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Method that causes the Transition into the ChoiceState could not be called, so the machine never "
       "entered it and the obligation below was never reached: 0x"
    << std::hex << response.results()[0].status_code().as_uint32();

  const auto reported = read_data_value(exemplar.currentStateIdPropertyId);
  ASSERT_TRUE(reported.has_value()) << "the machine's CurrentState.Id must be readable";
  const NodeId* stateId = reported->value().try_as<NodeId>();
  ASSERT_NE(stateId, nullptr) << "CurrentState.Id must decode as a NodeId (Part 16 section 4.4.6)";

  EXPECT_NE(*stateId, exemplar.choiceStateId)
    << "the machine is resting IN the ChoiceState, which is the stall section 4.6.2 forbids: a ChoiceState "
       "is "
       "exited "
       "the instant it is entered, so no Guard evaluated true and no Transition could be determined";
  EXPECT_NE(*stateId, exemplar.idleStateId)
    << "the machine never left Idle, so the Transition into the ChoiceState was not taken and nothing about "
       "Guard evaluation was exercised";
  const bool resolved =
    std::find(resolvableStates.begin(), resolvableStates.end(), *stateId) != resolvableStates.end();
  EXPECT_TRUE(resolved)
    << "on entering the ChoiceState the Guards must determine one of its leaving Transitions, so the machine "
       "must report one of the States they reach; it reports "
    << ua::to_string(*stateId);
}

// ============================================================================================================
// The clause covers the case where a Guard's ContentFilter reaches OUTSIDE the machine, and the failure mode
// is specific rather than general: with no reference from the instance to the Variable's instance, the
// evaluator holds a name it cannot resolve, so the Guard is neither true nor false and what the Transition
// does depends on how the evaluator treats an unresolved term. The Variable is declared on the OWNING
// Object's type, which is the case the clause names, and the instance is produced by the SERVER's own
// instantiation of that type rather than hand-built here - a hand-built instance would carry exactly the
// references this test wrote onto it, which would prove nothing about what a server materialises.
// Part 16 section 4.6.5 - where a Guard's ContentFilter names a Variable the StateMachine does not own, the
// StateMachine instance shall reference that Variable.
// @verifies AC-SVR-SM-041-EXTERNAL-GUARD-VARIABLE
TEST_F(ClientFiniteStateMachine, InstantiatedMachineReferencesTheExternallyOwnedVariableItsGuardNames)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId ownerTypeId{mTestNamespaceIndex, uint32_t{9500}};
  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9501}};
  const NodeId idleStateId{mTestNamespaceIndex, uint32_t{9502}};
  const NodeId busyStateId{mTestNamespaceIndex, uint32_t{9503}};
  const NodeId goMethodId{mTestNamespaceIndex, uint32_t{9504}};
  const NodeId transitionId{mTestNamespaceIndex, uint32_t{9505}};
  const NodeId guardId{mTestNamespaceIndex, uint32_t{9506}};
  const NodeId expressionPropertyId{mTestNamespaceIndex, uint32_t{9507}};
  const NodeId thresholdDeclarationId{mTestNamespaceIndex, uint32_t{9508}};
  const NodeId machineDeclarationId{mTestNamespaceIndex, uint32_t{9509}};

  auto ownerType =
    create_subtype(addressSpace, ownerTypeId, "FmGuardOwnerType", NodeId{ObjectTypeId::BaseObjectType});

  // The machine type, whose one Transition is guarded by an Expression naming a Variable the machine does not
  // own - the ContentFilter operand resolves against the OWNING Object's type, not against the machine.
  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmExternalGuard", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, idleStateId, "Idle", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, busyStateId, "Busy", NodeId{ObjectTypeId::StateType});
  add_method(addressSpace, machineType, goMethodId, "Go");
  add_transition(addressSpace, machineType, transitionId, "IdleToBusy", idleStateId, busyStateId, goMethodId);
  auto transition = addressSpace.find_node_sync(transitionId);
  add_guard(addressSpace,
    machineType,
    transition,
    guardId,
    "ThresholdGuard",
    NodeId{VariableTypeId::ExpressionGuardVariableType});

  SimpleAttributeOperand external;
  external.type_definition_id() = ownerTypeId;
  external.browse_path().push_back(QualifiedName{mTestNamespaceIndex, std::string{"Threshold"}});
  external.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  LiteralOperand bound;
  bound.value() = Variant{std::int32_t{5}};
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::GreaterThan;
  RefStructure<Structure> externalRef;
  externalRef = std::unique_ptr<Structure>(std::make_unique<SimpleAttributeOperand>(std::move(external)));
  element.filter_operands().push_back(std::move(externalRef));
  RefStructure<Structure> boundRef;
  boundRef = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(bound)));
  element.filter_operands().push_back(std::move(boundRef));
  ContentFilter expression;
  expression.elements().push_back(std::move(element));
  auto guard = addressSpace.find_node_sync(guardId);
  add_property(addressSpace,
    guard,
    expressionPropertyId,
    "Expression",
    NodeId{DataTypeId::ContentFilter},
    DataValue{Variant{expression}});

  // The owning type: the Variable the Guard names, and the machine itself, both Mandatory so the server
  // materialises both when the type is instantiated.
  auto thresholdNode = addressSpace.create_node_sync(thresholdDeclarationId, NodeClass::Variable);
  auto threshold = thresholdNode.as<VariableAccessor>();
  ASSERT_TRUE(threshold.has_value());
  threshold->set_browse_name(QualifiedName{mTestNamespaceIndex, "Threshold"});
  threshold->set_display_name(LocalizedText{"", "Threshold"});
  threshold->set_data_type(NodeId{DataTypeId::Int32});
  threshold->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
  threshold->write_value_sync(DataValue{Variant{std::int32_t{9}}});
  thresholdNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
  ownerType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, thresholdDeclarationId);
  thresholdNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ownerTypeId, /*isForward=*/false);
  thresholdNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasModellingRule}, NodeId{ObjectId::ModellingRule_Mandatory});

  auto machineNode = addressSpace.create_node_sync(machineDeclarationId, NodeClass::Object);
  auto machineObject = machineNode.as<ObjectAccessor>();
  ASSERT_TRUE(machineObject.has_value());
  machineObject->set_browse_name(QualifiedName{mTestNamespaceIndex, "Machine"});
  machineObject->set_display_name(LocalizedText{"", "Machine"});
  machineNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, machineTypeId);
  ownerType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, machineDeclarationId);
  machineNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ownerTypeId, /*isForward=*/false);
  machineNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasModellingRule}, NodeId{ObjectId::ModellingRule_Mandatory});

  InstantiationService instantiation{addressSpace};
  InstantiationOptions options;
  std::promise<NodeSubtreeResult> promise;
  auto future = promise.get_future();
  instantiation.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "FmGuardOwner"},
    ownerTypeId,
    options,
    [&promise](NodeSubtreeResult outcome) { promise.set_value(std::move(outcome)); });
  auto instantiated = future.get();
  ASSERT_TRUE(instantiated.is_good())
    << "instantiating the Object that owns the machine failed, so the obligation below was never reached: 0x"
    << std::hex << instantiated.status_code().as_uint32();
  // The handle deletes what it created when it dies; released so the instance outlives this statement.
  auto subtree = std::move(instantiated).value();
  const NodeId ownerInstanceId = subtree.root();
  subtree.release();

  NodeId thresholdInstanceId;
  NodeId machineInstanceId;
  for (const auto& child : forward_targets(ownerInstanceId, NodeId{ReferenceTypeId::HasComponent}))
  {
    const std::string name = browse_name_of(child);
    if (name == "Threshold")
    {
      thresholdInstanceId = child;
    }
    if (name == "Machine")
    {
      machineInstanceId = child;
    }
  }
  ASSERT_FALSE(thresholdInstanceId.is_null())
    << "the server materialised no Threshold Variable on the instance, so there is no Variable instance for "
       "the machine to reference and the check below would compare against nothing";
  ASSERT_FALSE(machineInstanceId.is_null())
    << "the server materialised no state machine on the instance, so there is no StateMachine instance to "
       "carry the reference the clause requires";

  bool wired{false};
  std::vector<std::string> reached;
  for (const auto& reference : forward_references(machineInstanceId))
  {
    reached.push_back(ua::to_string(reference.target));
    wired = wired || (reference.target == thresholdInstanceId);
  }
  EXPECT_TRUE(wired) << "the Guard's ContentFilter names a Variable owned by the enclosing Object's type, so "
                        "the StateMachine instance must reference that Variable's instance "
                     << ua::to_string(thresholdInstanceId) << "; the instance reaches only ["
                     << join_names(reached) << "]";
}

// ============================================================================================================
// Part 16 section 4.4.6: "The Id Property is inherited from the StateVariableType. Its Value shall be the
// NodeId of one of the State Objects of the FiniteStateMachineType." Id is the identifier application control
// logic keys on - section 4.4.2 says so in as many words ("Applications should use the Id Property of
// CurrentState if they need a unique identifier for the state") - and what makes it usable is that it
// ADDRESSES the State: a client browses on from it to the State's own members, StateNumber and any
// SubStateMachine among them. A synthetic identifier allocated per state name would compare equal to itself,
// satisfy every single-machine equality check a client performs, and resolve to nothing at all. Both halves
// are therefore asserted: the reported Id is resolved in the published model and required to be an Object of
// StateType, and it is required to be exactly one of the States the machine's own type declares. The value
// travels over the wire while the declared topology is read from the model, so an Id that arrived with a
// mangled namespace index fails here rather than in the client that later cannot resolve it.
// @verifies AC-SVR-SM-020-FINITESTATE-ID-IS-NODEID
TEST_F(ClientFiniteStateMachine, FiniteStateVariableIdIsTheNodeIdOfAStateOfTheMachine)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId machineTypeId{mTestNamespaceIndex, uint32_t{9710}};
  const NodeId readyStateId{mTestNamespaceIndex, uint32_t{9711}};
  const NodeId runningStateId{mTestNamespaceIndex, uint32_t{9712}};
  const NodeId machineId{mTestNamespaceIndex, uint32_t{9715}};
  const NodeId currentStateId{mTestNamespaceIndex, uint32_t{9716}};
  const NodeId currentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9717}};

  auto machineType = create_subtype(
    addressSpace, machineTypeId, "FmIdRendering", NodeId{ObjectTypeId::FiniteStateMachineType});
  add_state(addressSpace, machineType, readyStateId, "Ready", NodeId{ObjectTypeId::InitialStateType});
  add_state(addressSpace, machineType, runningStateId, "Running", NodeId{ObjectTypeId::StateType});

  auto machine = create_machine(addressSpace, machineId, "FmIdRenderingInstance", machineTypeId);
  auto currentState = add_state_variable(
    addressSpace, machine, currentStateId, "CurrentState", DataValue{Variant{LocalizedText{"en", "Ready"}}});
  currentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::FiniteStateVariableType});
  add_property(addressSpace,
    currentState,
    currentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{readyStateId}});

  const auto declaredStates = components_of_type(machineTypeId, NodeId{ObjectTypeId::StateType});
  ASSERT_GT(declaredStates.size(), 1u)
    << "the machine type must declare more than one State, or an Id naming 'one of' them says nothing";
  GTEST_LOG_(INFO) << "machine type declares " << declaredStates.size() << " State Objects";

  const auto reported = read_data_value(currentStateIdPropertyId);
  ASSERT_TRUE(reported.has_value())
    << "CurrentState.Id is Mandatory on StateVariableType and must be readable";
  const NodeId* reportedId = reported->value().try_as<NodeId>();
  ASSERT_NE(reportedId, nullptr) << "the Id of a FiniteStateVariableType is the NodeId of a State Object "
                                    "(Part 16 section 4.4.6), so it must "
                                    "decode as a NodeId";
  EXPECT_FALSE(reportedId->is_null()) << "CurrentState.Id came back identifying no State at all";

  // Resolve it, which is what the criterion's stimulus asks for and what a client does with it.
  EXPECT_TRUE(is_object_of_type(*reportedId, NodeId{ObjectTypeId::StateType}))
    << "CurrentState.Id must resolve to an Object of StateType in the published model; "
    << ua::to_string(*reportedId) << " does not";

  const auto matches =
    static_cast<std::size_t>(std::count(declaredStates.begin(), declaredStates.end(), *reportedId));
  EXPECT_EQ(matches, 1u) << "CurrentState.Id must be the NodeId of exactly one of the machine's own State "
                            "Objects (Part 16 section 4.4.6); "
                         << ua::to_string(*reportedId) << " matches " << matches << " of the "
                         << declaredStates.size() << " the type declares";
}

// ============================================================================================================
// Part 16 section 4.4.2: "A StateMachine may not be active. In this case, the CurrentState and LastTransition
// Variables shall have a status equal to Bad_StateNotActive (see Table 17)."
//
// WRITTEN TO THE CLAUSE, NOT TO THE CRITERION'S TITLE. The criterion reads "both are null"; section 4.4.2
// obliges a STATUS and says nothing about the value, and a server that keeps serving the last state while
// re-qualifying it Bad_StateNotActive conforms - that is the shape of the corpus's own reference model of an
// inactive machine (client_state_machine_matrix_tests.cpp M4/M5). Asserting nullity would fail that
// conforming server, so the status is what is asserted here, exactly as
// `AC-SVR-SM-006-SUBSTATEMACHINE-ACTIVE-WITH-PARENT` was narrowed for the same sentence in section 4.4.5.
//
// The inactive machine is a SubStateMachine whose owning State is no longer current: section 4.4.5 gives that
// as the one condition under which the model itself says a machine is not active, and nothing else in the
// address space expresses "inactive". BOTH Variables are driven, which is what separates this from the
// CurrentState- only section 4.4.5 row: an implementation that re-qualified CurrentState and left
// LastTransition at Good would report a machine that has stopped as one that just took a transition. The
// active reads are asserted first as the control - a server answering Bad_StateNotActive unconditionally
// would otherwise pass.
// @verifies AC-SVR-SM-005-INACTIVE-RETURNS-NULL
TEST_F(ClientFiniteStateMachine, InactiveMachineQualifiesCurrentStateAndLastTransitionBadStateNotActive)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId parentMachineId{mTestNamespaceIndex, uint32_t{9720}};
  const NodeId parentCurrentStateId{mTestNamespaceIndex, uint32_t{9721}};
  const NodeId parentCurrentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9722}};
  const NodeId parentIdleStateId{mTestNamespaceIndex, uint32_t{9723}};
  const NodeId parentMachiningStateId{mTestNamespaceIndex, uint32_t{9724}};
  const NodeId subMachineId{mTestNamespaceIndex, uint32_t{9725}};
  const NodeId subCurrentStateId{mTestNamespaceIndex, uint32_t{9726}};
  const NodeId subCurrentStateIdPropertyId{mTestNamespaceIndex, uint32_t{9727}};
  const NodeId subLastTransitionId{mTestNamespaceIndex, uint32_t{9728}};
  const NodeId subLastTransitionIdPropertyId{mTestNamespaceIndex, uint32_t{9729}};

  auto parent = create_machine(addressSpace, parentMachineId, "FmInactiveParent");
  auto parentCurrentState = add_state_variable(addressSpace,
    parent,
    parentCurrentStateId,
    "CurrentState",
    DataValue{Variant{LocalizedText{"en", "Machining"}}});
  add_property(addressSpace,
    parentCurrentState,
    parentCurrentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{parentMachiningStateId}});
  add_state(addressSpace, parent, parentIdleStateId, "Idle", NodeId{ObjectTypeId::StateType});
  add_state(addressSpace, parent, parentMachiningStateId, "Machining", NodeId{ObjectTypeId::StateType});

  auto subMachine = create_machine(addressSpace, subMachineId, "FmInactiveSub");
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, subMachineId);
  addressSpace.find_node_sync(parentMachiningStateId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasSubStateMachine}, subMachineId);
  subMachine.add_reference_sync(NodeId{ReferenceTypeId::HasSubStateMachine}, parentMachiningStateId, false);

  auto subCurrentState = add_state_variable(addressSpace,
    subMachine,
    subCurrentStateId,
    "CurrentState",
    DataValue{Variant{LocalizedText{"en", "SubRunning"}}});
  subCurrentState.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, subMachineId, false);
  subCurrentState.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::StateVariableType});
  add_property(addressSpace,
    subCurrentState,
    subCurrentStateIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{runningStateNode}});
  auto subLastTransition = add_state_variable(addressSpace,
    subMachine,
    subLastTransitionId,
    "LastTransition",
    DataValue{Variant{LocalizedText{"en", "SubReadyToRunning"}}});
  subLastTransition.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, subMachineId, false);
  subLastTransition.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::TransitionVariableType});
  add_property(addressSpace,
    subLastTransition,
    subLastTransitionIdPropertyId,
    "Id",
    NodeId{DataTypeId::NodeId},
    DataValue{Variant{runningToSuspendedId}});

  // Control: while the owning State is the parent's current state the machine IS active, so neither Variable
  // may carry Bad_StateNotActive.
  for (const auto& variableId : {subCurrentStateId, subLastTransitionId})
  {
    const auto active = read_data_value(variableId);
    ASSERT_TRUE(active.has_value()) << "the active machine's " << ua::to_string(variableId)
                                    << " must be readable";
    EXPECT_FALSE(active->status().has_value() && (active->status()->as_status() == Status::BadStateNotActive))
      << "the machine is active while its owning State is current, so " << ua::to_string(variableId)
      << " must not already report Bad_StateNotActive";
  }

  // Stimulus: the parent leaves the State that owns the machine - both halves of its CurrentState, so the
  // model reports the parent out of that State consistently and the antecedent genuinely holds.
  write_localized_text_value(parentCurrentStateId, LocalizedText{"en", "Idle"});
  write_node_id_value(parentCurrentStateIdPropertyId, parentIdleStateId);

  for (const auto& variableId : {subCurrentStateId, subLastTransitionId})
  {
    const auto inactive = read_data_value(variableId);
    ASSERT_TRUE(inactive.has_value())
      << "the inactive machine's " << ua::to_string(variableId) << " must still be readable";
    ASSERT_TRUE(inactive->status().has_value())
      << "the machine is no longer active, so " << ua::to_string(variableId)
      << " must carry a status rather than the default Good quality";
    EXPECT_EQ(inactive->status()->as_status(), Status::BadStateNotActive)
      << "the CurrentState and LastTransition Variables of a StateMachine that is not active shall have a "
         "status equal to Bad_StateNotActive (Part 16 section 4.4.2); "
      << ua::to_string(variableId) << " reports otherwise";
  }
}

// ============================================================================================================
// Part 16 section 4.4.2: "An instance of this ObjectType shall generate an Event whenever a significant state
// change occurs." The Server decides which changes are significant, so the machine driven here is one whose
// own model settles the question: its Transition names TransitionEventType as its HasEffect and its type
// sources the matching GeneratesEvent, which is the server declaring this change to be one it reports. Table
// 15 then makes ToState Mandatory on that Event, so an Event that names no state at all fails: announcing
// that something moved without saying where it moved to leaves a subscriber holding a notification it must
// follow with a Read, and the read races the next transition. Polling CurrentState instead is what this
// clause exists to make unnecessary: a machine passing through a transient state between polls looks as
// though it never entered it. The Transition is triggered the way a Client triggers one, through the Method
// the model names as its HasCause, and the Call is asserted Good first so a missing Event cannot really be a
// Transition that never happened. The Events are observed through the public `Server::set_event_listener`
// interface, which sees every Event the bus dispatches - the criterion's Subscription is a delivery path over
// the same emission, and its own obligations are not this criterion's.
//
// THE RENDERING OF THE STATE IS NOT PRESCRIBED, AND IS DELIBERATELY NOT PRESCRIBED HERE. Table 15 types
// ToState as a `StateVariableType`, not as the `FiniteStateVariableType` whose Id section 4.4.6 pins to a
// NodeId, and section 4.4.3 defines the base Id as a BaseDataType "name which uniquely identifies the current
// state within the StateMachineType". A server rendering that identity as the State's NodeId, as its
// BrowseName, or as the LocalizedText Value is conforming in each case, so demanding the NodeId specifically
// would manufacture a defect against two of the three. What is NOT optional is WHICH state is named: an Event
// naming Ready, or naming nothing, fails in every rendering. Where the Id is present in a rendering this
// model can compare against it is authoritative and there is no fallback - a wrong Id is not rescued by a
// right Name.
// @relation(AC-SVR-SM-001-STATE-CHANGE-EVENT, scope=function)
TEST_F(ClientFiniteStateMachine, SignificantStateChangeRaisesAnEventCarryingTheStateTheMachineEntered)
{
  const auto exemplar = add_effect_machine_exemplar(9400U);

  auto call =
    mSession->methods().try_call_sync(call_method(exemplar.firstInstanceId, exemplar.startMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service itself failed: 0x" << std::hex
                              << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Method that moves the machine from Ready to Running could not be called, so no state change "
       "occurred and the Event obligation below was never reached: 0x"
    << std::hex << response.results()[0].status_code().as_uint32();

  const std::vector<QualifiedName> toStatePath{QualifiedName{0, std::string{"ToState"}}};
  const std::vector<QualifiedName> toStateIdPath{
    QualifiedName{0, std::string{"ToState"}}, QualifiedName{0, std::string{"Id"}}};
  const std::vector<QualifiedName> toStateNamePath{
    QualifiedName{0, std::string{"ToState"}}, QualifiedName{0, std::string{"Name"}}};

  // "Carries a state" is any of the renderings, not the LocalizedText Value alone: an Event that populated
  // only ToState.Id would otherwise count as carrying nothing and be reported as a missing Event.
  const auto carriesState = [&toStatePath, &toStateIdPath, &toStateNamePath](
                              const std::shared_ptr<const BaseEvent>& event)
  {
    return !event->resolve_field(toStatePath).empty() || !event->resolve_field(toStateIdPath).empty() ||
           !event->resolve_field(toStateNamePath).empty();
  };
  const auto captured = mEvents->wait_until([&carriesState](const EmittedEventRecorder::Captured& events)
    { return std::any_of(events.begin(), events.end(), carriesState); },
    5000ms);

  const auto carrying =
    static_cast<std::size_t>(std::count_if(captured.begin(), captured.end(), carriesState));
  GTEST_LOG_(INFO) << "the server emitted " << captured.size() << " Event(s), " << carrying
                   << " of them naming a state";
  ASSERT_GT(carrying, 0U)
    << "the machine took a Transition its own type advertises through GeneratesEvent, so a significant state "
       "change must have raised an Event reporting the state it entered; the server emitted "
    << captured.size() << " Event(s), none of them carrying a state";

  // The BrowseName the textual renderings must produce, read back from the model rather than restated, so a
  // renamed State moves the expectation with it.
  const std::string enteredStateName = browse_name_of(exemplar.runningStateId);
  ASSERT_FALSE(enteredStateName.empty())
    << "the State the machine moves into carries no BrowseName in the published model, so the textual "
       "renderings below could not be recognised";

  bool namesEnteredState{false};
  std::vector<std::string> reportedStates;
  for (const auto& event : captured)
  {
    if (!carriesState(event))
    {
      continue;
    }
    const Variant id = event->resolve_field(toStateIdPath);
    const Variant name = event->resolve_field(toStateNamePath);
    const Variant text = event->resolve_field(toStatePath);
    const NodeId* idAsNodeId = id.try_as<NodeId>();
    const String* idAsName = id.try_as<String>();
    const QualifiedName* stateName = name.try_as<QualifiedName>();
    const LocalizedText* stateText = text.try_as<LocalizedText>();

    bool identifies{false};
    std::string rendered;
    if (idAsNodeId != nullptr)
    {
      // The FiniteStateVariableType rendering (section 4.4.6): authoritative on its own.
      rendered = "Id=" + ua::to_string(*idAsNodeId);
      identifies = (*idAsNodeId == exemplar.runningStateId);
    }
    else if (idAsName != nullptr)
    {
      rendered = "Id='" + std::string{static_cast<std::string_view>(*idAsName)} + "'";
      identifies = (std::string{static_cast<std::string_view>(*idAsName)} == enteredStateName);
    }
    else if (stateName != nullptr)
    {
      // No Id in a rendering this model can compare against: fall back on Name, which section 4.4.3 requires
      // the Event to carry whether or not the instance exposes it.
      rendered = "Name='" + std::string{static_cast<std::string_view>(stateName->name())} + "'";
      identifies = (std::string{static_cast<std::string_view>(stateName->name())} == enteredStateName);
    }
    else if (stateText != nullptr)
    {
      rendered = "Value='" + std::string{static_cast<std::string_view>(stateText->text())} + "'";
      identifies = (std::string{static_cast<std::string_view>(stateText->text())} == enteredStateName);
    }
    else
    {
      rendered = "<no state identification>";
    }
    reportedStates.push_back(rendered);
    namesEnteredState = namesEnteredState || identifies;
  }
  EXPECT_TRUE(namesEnteredState) << "the Event must carry the NEW state: the machine moved into "
                                 << enteredStateName << " (" << ua::to_string(exemplar.runningStateId)
                                 << "), and the state-carrying Events reported ["
                                 << join_names(reportedStates) << "]";
}

// ============================================================================================================
// Part 16 section 4.4.3 requires a state-carrying Event to supply every optional StateVariableType
// Property even when the AddressSpace instance omits them. The fixture asserts that omission before
// stimulating the runtime, so an implementation that merely copies instance Properties cannot pass.
// The retained arm drives the public Call and Event listener path; exact GREEN evidence promotes both
// the state-change emission and optional-payload criteria.
// @relation(AC-SVR-SM-001-STATE-CHANGE-EVENT, scope=function)
// @relation(AC-SVR-SM-007-EVENT-OPTIONALS, scope=function)
TEST_F(ClientFiniteStateMachine, EventCarryingStateSuppliesEveryOptionalStateVariablePropertyAnyway)
{
  const auto exemplar = add_effect_machine_exemplar(9400U);

  // The stimulus's precondition: the machine instance's StateVariable exposes none of the three optional
  // Properties of StateVariableType.
  NodeId currentStateVariableId;
  for (const auto& child : forward_targets(exemplar.firstInstanceId, NodeId{ReferenceTypeId::HasComponent}))
  {
    if (browse_name_of(child) == "CurrentState")
    {
      currentStateVariableId = child;
    }
  }
  ASSERT_FALSE(currentStateVariableId.is_null())
    << "the machine instance publishes no CurrentState Variable, so there is no state-carrying instance for "
       "the payload below to be compared against";
  const auto exposed =
    browse_names_of(forward_targets(currentStateVariableId, NodeId{ReferenceTypeId::HasProperty}));
  for (const auto& optional : {"Name", "Number", "EffectiveDisplayName"})
  {
    ASSERT_EQ(static_cast<std::size_t>(std::count(exposed.begin(), exposed.end(), std::string{optional})), 0u)
      << "the stimulus requires an instance that OMITS the optional Properties; this one exposes " << optional
      << " ([" << join_names(exposed) << "]), which would make the payload check below prove nothing";
  }

  auto call =
    mSession->methods().try_call_sync(call_method(exemplar.firstInstanceId, exemplar.startMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service itself failed: 0x" << std::hex
                              << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Cause Method could not be called, so no state change occurred and no Event carrying state could "
       "have been produced: 0x"
    << std::hex << response.results()[0].status_code().as_uint32();

  const std::vector<QualifiedName> toStatePath{QualifiedName{0, std::string{"ToState"}}};
  const std::vector<QualifiedName> toStateIdPath{
    QualifiedName{0, std::string{"ToState"}}, QualifiedName{0, std::string{"Id"}}};
  // An Event "includes the current state" if it names it in ANY of StateVariableType's renderings. Keying the
  // population on the LocalizedText Value alone would let an Event carrying only ToState.Id - a member of the
  // population, and precisely the payload this clause is about - leave through the skip below unexamined.
  const auto carriesState = [&toStatePath, &toStateIdPath](const std::shared_ptr<const BaseEvent>& event)
  {
    return !event->resolve_field(toStatePath).empty() || !event->resolve_field(toStateIdPath).empty();
  };
  const auto captured = mEvents->wait_until([&carriesState](const EmittedEventRecorder::Captured& events)
    { return std::any_of(events.begin(), events.end(), carriesState); },
    5000ms);

  std::shared_ptr<const BaseEvent> stateCarrying;
  std::size_t stateCarryingCount{0};
  for (const auto& event : captured)
  {
    if (!carriesState(event))
    {
      continue;
    }
    ++stateCarryingCount;
    if (stateCarrying == nullptr)
    {
      stateCarrying = event;
    }
  }
  GTEST_LOG_(INFO) << "the server emitted " << captured.size() << " Event(s), " << stateCarryingCount
                   << " of them including the state of the machine";
  ASSERT_NE(stateCarrying, nullptr)
    << "the server produced no Event including the state of the machine (" << captured.size()
    << " Event(s) emitted). Part 16 section 4.4.2 owes that emission unconditionally - 'An instance of this "
       "ObjectType shall generate an Event whenever a significant state change occurs' - and the State "
       "Machine 2022 Server Facet this product declares carries it as a Mandatory conformance unit. The "
       "population this clause quantifies over is empty because the emission is missing, not because the "
       "clause does not apply, so this fails against "
       "D-NO-STATE-MACHINE-RUNTIME-A-HASCAUSE-METHOD-CALL-TAKES-NO rather than abstaining";

  const Variant name = stateCarrying->resolve_field(std::vector<QualifiedName>{
    QualifiedName{0, std::string{"ToState"}}, QualifiedName{0, std::string{"Name"}}});
  const Variant number = stateCarrying->resolve_field(std::vector<QualifiedName>{
    QualifiedName{0, std::string{"ToState"}}, QualifiedName{0, std::string{"Number"}}});
  const Variant effectiveDisplayName = stateCarrying->resolve_field(std::vector<QualifiedName>{
    QualifiedName{0, std::string{"ToState"}}, QualifiedName{0, std::string{"EffectiveDisplayName"}}});

  EXPECT_FALSE(name.empty())
    << "Name is an optional Property of StateVariableType and the instance exposes none of them, which is "
       "exactly the case section 4.4.3 requires the Event to carry it in";
  const auto* stateName = name.try_as<QualifiedName>();
  ASSERT_NE(stateName, nullptr)
    << "the Name Property of a StateVariableType is a QualifiedName (Part 16 section 4.4.3 Table 2)";
  EXPECT_EQ(*stateName, QualifiedName(0, "Running"))
    << "the Event must derive Name from the entered State Object BrowseName";
  EXPECT_FALSE(number.empty())
    << "Number must be supplied in the Event even though the instance in the AddressSpace omits it";
  const auto* stateNumber = number.try_as<std::uint32_t>();
  ASSERT_NE(stateNumber, nullptr)
    << "the Number Property of a StateVariableType is a UInt32 (Part 16 section 4.4.3 Table 2)";
  EXPECT_EQ(*stateNumber, exemplar.runningStateNumber)
    << "the Event must derive Number from the entered State Object StateNumber";
  EXPECT_FALSE(effectiveDisplayName.empty())
    << "EffectiveDisplayName must be supplied in the Event even though the instance in the AddressSpace "
       "omits it";
  const auto* stateDisplay = effectiveDisplayName.try_as<LocalizedText>();
  ASSERT_NE(stateDisplay, nullptr) << "the EffectiveDisplayName Property of a StateVariableType is a "
                                      "LocalizedText (Part 16 section 4.4.3 Table 2)";
  EXPECT_EQ(*stateDisplay, LocalizedText("", "Running"))
    << "the Event must derive EffectiveDisplayName from the entered State Object DisplayName";
}

// ============================================================================================================
// The same model and the same connection, with auditing switched ON. The three rows below are conditional on
// it - `SVR-SM-035`, `SVR-SM-036` and `SVR-SM-045` are each scoped "only when Auditing is enabled" - and a
// server built with `ServerConfig::auditingEnabled` false raises no audit Event at all, which would
// leave every one of them holding over the empty set. Kept as a subclass rather than switched on for the
// whole file so that the rows above keep running against the configuration they were written for.
// ============================================================================================================
class ClientFiniteStateMachineAuditing : public ClientFiniteStateMachine
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ClientFiniteStateMachine::configure_server_config(cfg);
    cfg.auditingEnabled = true;
  }
};

// ============================================================================================================
// For an audit Event the identification IS the record: which machine was changed is the fact being audited,
// and an audit trail that names the type rather than the instance says only that some machine of that kind
// moved. Two instances of one type are driven through the Method that causes the Transition, so a SourceNode
// filled with the type, or with the Method - both shared across every instance - is distinguishable from one
// filled with the machine the change happened in.
// Part 16 section 4.4.17 - SourceNode shall be the NodeId of the StateMachine instance where the State
// changed.
// @verifies AC-SVR-SM-035-AUDITUPDATESTATE-SOURCENODE
TEST_F(ClientFiniteStateMachineAuditing, AuditUpdateStateEventSourceNodeNamesTheMachineWhoseStateChanged)
{
  const auto exemplar = add_effect_machine_exemplar(9400U);
  const auto auditTypes = all_subtypes_of(NodeId{ObjectTypeId::AuditUpdateStateEventType});
  ASSERT_FALSE(auditTypes.empty())
    << "AuditUpdateStateEventType is not in the published model, so nothing below could recognise the audit "
       "Event a state change raises";

  for (const auto& instanceId : {exemplar.firstInstanceId, exemplar.secondInstanceId})
  {
    auto call = mSession->methods().try_call_sync(call_method(instanceId, exemplar.startMethodId));
    ASSERT_TRUE(call.is_good()) << "the Call service failed for " << ua::to_string(instanceId) << ": 0x"
                                << std::hex << call.status_code().as_uint32();
    auto response = std::move(call).value();
    ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
    ASSERT_TRUE(response.results()[0].status_code().is_good())
      << "the Method that changes the machine's State could not be called on " << ua::to_string(instanceId)
      << ", so no State changed there: 0x" << std::hex << response.results()[0].status_code().as_uint32();
  }

  const auto matches = [&auditTypes](const std::shared_ptr<const BaseEvent>& event)
  {
    return std::find(auditTypes.begin(), auditTypes.end(), event->eventType) != auditTypes.end();
  };
  const auto captured = mEvents->wait_until([&matches](const EmittedEventRecorder::Captured& events)
    { return std::count_if(events.begin(), events.end(), matches) >= 2; },
    5000ms);

  std::vector<std::string> sources;
  bool namesFirst{false};
  bool namesSecond{false};
  for (const auto& event : captured)
  {
    if (!matches(event))
    {
      continue;
    }
    sources.push_back(ua::to_string(event->sourceNode));
    namesFirst = namesFirst || (event->sourceNode == exemplar.firstInstanceId);
    namesSecond = namesSecond || (event->sourceNode == exemplar.secondInstanceId);
  }

  ASSERT_GE(sources.size(), 2U)
    << "the State was changed on each of two different machines with auditing enabled, but the server raised "
    << sources.size() << " AuditUpdateStateEvent(s), so the SourceNodes below have nothing to distinguish";
  EXPECT_TRUE(namesFirst) << "no AuditUpdateStateEvent names the first machine "
                          << ua::to_string(exemplar.firstInstanceId) << " as its SourceNode; the SourceNodes "
                          << "seen were [" << join_names(sources) << "]";
  EXPECT_TRUE(namesSecond) << "no AuditUpdateStateEvent names the second machine "
                           << ua::to_string(exemplar.secondInstanceId)
                           << " as its SourceNode; the SourceNodes " << "seen were [" << join_names(sources)
                           << "]";
}

// ============================================================================================================
// The obligation comes from the Mandatory column of Table 16 rather than from the body text, which describes
// where it does not require - Part 16 section 1.10 is what gives the column its `shall` weight, and a reader
// checking the prose for a `shall` would conclude both Properties are optional and author nothing. What the
// pair is for is the reconstruction: an audit record saying only that a State changed cannot be replayed,
// while OldStateId and NewStateId together say which move was made. Both are therefore required to be
// present AND to name the States either side of the Transition that was triggered, not merely to be set.
// Part 16 section 4.4.17 Table 16 - OldStateId and NewStateId are Mandatory on AuditUpdateStateEventType.
// @verifies AC-SVR-SM-036-AUDIT-STATE-IDS
TEST_F(ClientFiniteStateMachineAuditing, AuditUpdateStateEventCarriesTheStateIdsEitherSideOfTheTransition)
{
  const auto exemplar = add_effect_machine_exemplar(9400U);
  const auto auditTypes = all_subtypes_of(NodeId{ObjectTypeId::AuditUpdateStateEventType});
  ASSERT_FALSE(auditTypes.empty())
    << "AuditUpdateStateEventType is not in the published model, so nothing below could recognise the audit "
       "Event a state change raises";

  auto call =
    mSession->methods().try_call_sync(call_method(exemplar.firstInstanceId, exemplar.startMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service itself failed: 0x" << std::hex
                              << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Method that moves the machine from Ready to Running could not be called, so no State changed and "
       "the obligation below was never reached: 0x"
    << std::hex << response.results()[0].status_code().as_uint32();

  const auto matches = [&auditTypes](const std::shared_ptr<const BaseEvent>& event)
  {
    return std::find(auditTypes.begin(), auditTypes.end(), event->eventType) != auditTypes.end();
  };
  const auto captured = mEvents->wait_until([&matches](const EmittedEventRecorder::Captured& events)
    { return std::any_of(events.begin(), events.end(), matches); },
    5000ms);

  std::shared_ptr<const BaseEvent> audit;
  for (const auto& event : captured)
  {
    if (matches(event) && (audit == nullptr))
    {
      audit = event;
    }
  }
  ASSERT_NE(audit, nullptr)
    << "the machine's State was changed through a Method with auditing enabled, so an AuditUpdateStateEvent "
       "must have been raised; the server emitted "
    << captured.size() << " Event(s), none of them one";

  const std::vector<QualifiedName> oldStatePath{QualifiedName{0, std::string{"OldStateId"}}};
  const std::vector<QualifiedName> newStatePath{QualifiedName{0, std::string{"NewStateId"}}};
  const Variant oldState = audit->resolve_field(oldStatePath);
  const Variant newState = audit->resolve_field(newStatePath);
  ASSERT_FALSE(oldState.empty()) << "OldStateId is Mandatory on AuditUpdateStateEventType, so the Event must "
                                    "carry it populated rather than empty";
  ASSERT_FALSE(newState.empty()) << "NewStateId is Mandatory on AuditUpdateStateEventType, so the Event must "
                                    "carry it populated rather than empty";

  const NodeId* oldStateId = oldState.try_as<NodeId>();
  const NodeId* newStateId = newState.try_as<NodeId>();
  ASSERT_NE(oldStateId, nullptr) << "OldStateId carries the StateId of the State the machine left, which is "
                                    "the NodeId of a State Object";
  ASSERT_NE(newStateId, nullptr) << "NewStateId carries the StateId of the State the machine entered, which "
                                    "is the NodeId of a State Object";
  EXPECT_EQ(*oldStateId, exemplar.readyStateId)
    << "the Transition was taken from Ready, so OldStateId must name that State: it names "
    << ua::to_string(*oldStateId);
  EXPECT_EQ(*newStateId, exemplar.runningStateId)
    << "the Transition was taken to Running, so NewStateId must name that State: it names "
    << ua::to_string(*newStateId);
}

// ============================================================================================================
// The supertype rule behind every Method-audit obligation: a Method NodeId is shared across every instance of
// its ObjectType, so it identifies WHAT was invoked and never on WHICH node - SourceNode is the only field
// that says which Object was acted on, exactly as the `objectId` of the Call is what selects it. An audit
// trail whose SourceNode named the Method, or the ObjectType, would record every call to a shared Method
// identically and be useless as a record of what happened to which machine. Two Objects of one ObjectType are
// therefore called through the SAME Method node, which is the only arrangement in which a SourceNode filled
// from the Method rather than from the target is distinguishable at all.
// Part 5 section 6.4.27 - SourceNode shall be the NodeId of the Object that the Method resides on.
// @verifies AC-SVR-SM-045-AUDITUPDATEMETHOD-SOURCENODE
// @relation(AC-SVR-SM-046-AUDITUPDATEMETHOD-SOURCENAME, scope=function)
TEST_F(ClientFiniteStateMachineAuditing, AuditUpdateMethodEventSourceNodeNamesTheObjectTheMethodWasCalledOn)
{
  auto addressSpace = mServer.server().address_space();
  // A second instance of the fixture's TestObjectType, beside the one it already publishes; create_machine is
  // the fixture's generic "Object with a HasTypeDefinition, organised under the Objects folder" builder.
  const NodeId secondObjectId{mTestNamespaceIndex, uint32_t{9600}};
  create_machine(addressSpace, secondObjectId, "FmSecondTypedObject", mTestObjectTypeId);

  const auto auditTypes = all_subtypes_of(NodeId{ObjectTypeId::AuditUpdateMethodEventType});
  ASSERT_FALSE(auditTypes.empty())
    << "AuditUpdateMethodEventType is not in the published model, so nothing below could recognise the audit "
       "Event a Method call raises";

  for (const auto& objectId : {mTypedObjectId, secondObjectId})
  {
    auto call = mSession->methods().try_call_sync(call_method(objectId, mObjectTypeMethodId));
    ASSERT_TRUE(call.is_good()) << "the Call service failed for " << ua::to_string(objectId) << ": 0x"
                                << std::hex << call.status_code().as_uint32();
    auto response = std::move(call).value();
    ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
    ASSERT_TRUE(response.results()[0].status_code().is_good())
      << "the Method could not be called on " << ua::to_string(objectId)
      << ", so no audited action took place there: 0x" << std::hex
      << response.results()[0].status_code().as_uint32();
  }

  const auto matches = [&auditTypes](const std::shared_ptr<const BaseEvent>& event)
  {
    return std::find(auditTypes.begin(), auditTypes.end(), event->eventType) != auditTypes.end();
  };
  const auto captured = mEvents->wait_until([&matches](const EmittedEventRecorder::Captured& events)
    { return std::count_if(events.begin(), events.end(), matches) >= 2; },
    5000ms);

  std::vector<std::string> sources;
  bool namesFirst{false};
  bool namesSecond{false};
  for (const auto& event : captured)
  {
    if (!matches(event))
    {
      continue;
    }
    sources.push_back(ua::to_string(event->sourceNode));
    EXPECT_EQ(static_cast<std::string_view>(event->sourceName), "Attribute/Call")
      << "AuditUpdateMethodEventType SourceName is fixed by Part 5 section 6.4.27 and is not the Method name";
    namesFirst = namesFirst || (event->sourceNode == mTypedObjectId);
    namesSecond = namesSecond || (event->sourceNode == secondObjectId);
  }

  ASSERT_GE(sources.size(), 2U)
    << "the same Method was called on each of two different Objects with auditing enabled, but the server "
       "raised "
    << sources.size() << " AuditUpdateMethodEvent(s), so the SourceNodes below have nothing to distinguish";
  EXPECT_TRUE(namesFirst) << "no AuditUpdateMethodEvent names the first Object "
                          << ua::to_string(mTypedObjectId)
                          << " as its SourceNode; the SourceNodes seen were [" << join_names(sources) << "]";
  EXPECT_TRUE(namesSecond) << "no AuditUpdateMethodEvent names the second Object "
                           << ua::to_string(secondObjectId)
                           << " as its SourceNode; the SourceNodes seen were [" << join_names(sources) << "]";
}

// ============================================================================================================
// A Transition carries a TransitionNumber (Part 16 section 4.4.10, Table 9), and the TransitionEvent it
// raises names the Transition taken in its Transition field, whose Number identifies the transition
// (section 4.4.4). A subscriber that keys on numbers - as a Program's client does, Part 10 Table 6 numbering
// every Program Transition - can only do so when the Event carries it.
// ============================================================================================================
// @verifies AC-SVR-SM-025-FINITETRANSITION-NUMBER
// @relation(AC-SVR-SM-025-FINITETRANSITION-NUMBER, scope=function)
TEST_F(ClientFiniteStateMachine, ATransitionEventCarriesTheTransitionNumberOfTheTransitionTaken)
{
  const auto exemplar = add_effect_machine_exemplar(9800U);
  auto addressSpace = mServer.server().address_space();
  auto transition = addressSpace.find_node_sync(exemplar.transitionId);
  add_property(addressSpace,
    transition,
    NodeId{mTestNamespaceIndex, uint32_t{9830}},
    "TransitionNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{uint32_t{2}}});

  auto call =
    mSession->methods().try_call_sync(call_method(exemplar.firstInstanceId, exemplar.startMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service failed: 0x" << std::hex << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Cause Method could not be called, so no Transition was taken: 0x" << std::hex
    << response.results()[0].status_code().as_uint32();

  const auto matches = [&exemplar](const std::shared_ptr<const BaseEvent>& event)
  {
    return event->eventType == NodeId{ObjectTypeId::TransitionEventType} &&
           event->sourceNode == exemplar.firstInstanceId;
  };
  const auto captured = mEvents->wait_until([&matches](const EmittedEventRecorder::Captured& events)
    { return std::any_of(events.begin(), events.end(), matches); },
    5000ms);
  const auto event = std::find_if(captured.begin(), captured.end(), matches);
  ASSERT_NE(event, captured.end()) << "the Transition names TransitionEventType as its effect, so a "
                                      "TransitionEvent must have been raised";

  const Variant number = (*event)->resolve_field(std::vector<QualifiedName>{
    QualifiedName{0, std::string{"Transition"}}, QualifiedName{0, std::string{"Number"}}});
  const auto* transitionNumber = number.try_as<uint32_t>();
  ASSERT_NE(transitionNumber, nullptr)
    << "the Transition declares a TransitionNumber, so the Event's Transition/Number must carry it";
  EXPECT_EQ(*transitionNumber, 2U);
}

// ============================================================================================================
// Part 16 section 4.4.14: a Transition whose HasEffect names an EventType raises "an Event of that EventType
// or a subtype". Each Program Transition names AuditProgramTransitionEventType, which Part 10 section 5.2.6
// has a server raise when it audits; its supertype AuditUpdateStateEventType is not that EventType, and it
// lacks the Mandatory TransitionNumber. The Event names the Program Control Method in its SourceName,
// "Method/Start", and has Status TRUE because a Method caused the Transition.
// ============================================================================================================
// @verifies AC-SVR-SM-011-HASEFFECT-FIRES-EVENT
// @relation(AC-SVR-SM-011-HASEFFECT-FIRES-EVENT, scope=function)
TEST_F(
  ClientFiniteStateMachineAuditing, AnAuditEffectIsRaisedAsTheAuditEventTypeItNamesWithTheTransitionNumber)
{
  const auto exemplar = add_effect_machine_exemplar(9850U);
  auto addressSpace = mServer.server().address_space();
  auto transition = addressSpace.find_node_sync(exemplar.transitionId);
  transition.add_reference_sync(
    NodeId{ReferenceTypeId::HasEffect}, NodeId{ObjectTypeId::AuditProgramTransitionEventType});
  addressSpace.find_node_sync(exemplar.machineTypeId)
    .add_reference_sync(
      NodeId{ReferenceTypeId::GeneratesEvent}, NodeId{ObjectTypeId::AuditProgramTransitionEventType});
  add_property(addressSpace,
    transition,
    NodeId{mTestNamespaceIndex, uint32_t{9880}},
    "TransitionNumber",
    NodeId{DataTypeId::UInt32},
    DataValue{Variant{uint32_t{2}}});

  auto call =
    mSession->methods().try_call_sync(call_method(exemplar.firstInstanceId, exemplar.startMethodId));
  ASSERT_TRUE(call.is_good()) << "the Call service failed: 0x" << std::hex << call.status_code().as_uint32();
  auto response = std::move(call).value();
  ASSERT_EQ(response.results().size(), 1U) << "one Call must come back with exactly one result";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "the Cause Method could not be called, so no Transition was taken: 0x" << std::hex
    << response.results()[0].status_code().as_uint32();

  const auto isProgramAudit = [](const std::shared_ptr<const BaseEvent>& event)
  {
    return event->eventType == NodeId{ObjectTypeId::AuditProgramTransitionEventType};
  };
  const auto captured = mEvents->wait_until([&isProgramAudit](const EmittedEventRecorder::Captured& events)
    { return std::any_of(events.begin(), events.end(), isProgramAudit); },
    5000ms);
  const auto audit = std::find_if(captured.begin(), captured.end(), isProgramAudit);
  ASSERT_NE(audit, captured.end())
    << "the Transition names AuditProgramTransitionEventType as an effect and the "
       "server audits, so an Event of that type must have been raised";
  EXPECT_EQ(std::count_if(captured.begin(),
              captured.end(),
              [](const std::shared_ptr<const BaseEvent>& event)
              { return event->eventType == NodeId{ObjectTypeId::AuditUpdateStateEventType}; }),
    0)
    << "the audit Event is raised as the EventType the effect names, not as its supertype as well";

  EXPECT_EQ((*audit)->sourceNode, exemplar.firstInstanceId);
  EXPECT_EQ((*audit)->sourceName, "Method/Start");
  const Variant number =
    (*audit)->resolve_field(std::vector<QualifiedName>{QualifiedName{0, std::string{"TransitionNumber"}}});
  const auto* transitionNumber = number.try_as<uint32_t>();
  ASSERT_NE(transitionNumber, nullptr) << "TransitionNumber is Mandatory on AuditProgramTransitionEventType";
  EXPECT_EQ(*transitionNumber, 2U);
  const Variant status =
    (*audit)->resolve_field(std::vector<QualifiedName>{QualifiedName{0, std::string{"Status"}}});
  const auto* methodCaused = status.try_as<bool>();
  ASSERT_NE(methodCaused, nullptr) << "Status is Mandatory on AuditEventType";
  EXPECT_TRUE(*methodCaused) << "a Program Control Method caused the Transition";
  const Variant newState =
    (*audit)->resolve_field(std::vector<QualifiedName>{QualifiedName{0, std::string{"NewStateId"}}});
  ASSERT_NE(newState.try_as<NodeId>(), nullptr);
  EXPECT_EQ(*newState.try_as<NodeId>(), exemplar.runningStateId);
}
