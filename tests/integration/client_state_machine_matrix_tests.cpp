// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientStateMachine` integration cluster of the client integration-test matrix (the eight
///        `ClientStateMachine.*` rows, spec ref section 8.18.4.2, CL-SM-001..004/006; client design
///        section 8.18.1.b). These drive the TIER-2 StateMachine typed-access facade end-to-end through the
///        PUBLIC `ua::client::Connection` (`Connection::state_machine_accessor()` ->
///        `StateMachineAccessor::state_machine_async` -> `StateMachineHandle`) over a REAL reference server.
///
/// The Connection is a genuine public handle wrapped by `ConnectionHandleFactory` over a started
/// `ConnectionImpl` (the same orchestrator the DataAccess / subscription integration tests use), bound to an
/// activated Session on an ephemeral-TCP `ComplianceWithNodes` server extended with several StateMachine
/// Object instances. Each machine carries the ns0-BrowseName components the client's address-space pre-flight
/// resolves: a Mandatory `CurrentState` (`StateVariableType`) with its `Id` Property, and - where the row
/// needs it - an Optional `LastTransition` (`TransitionVariableType`) with its `Id` / `TransitionTime`
/// Properties.
///
/// HARNESS CHOICE (reported): the matrix names `MisbehavingServer (Read-response injection)` for the
/// inactive-status / locale / source-timestamp rows. The `MisbehavingServer` fixture owns its OWN server with
/// no address-space nodes and no interface to add a namespace, so a machine's pre-flight Browse would fail there.
/// This cluster therefore builds the state-machine nodes IN-TREE on a `ComplianceWithNodes` server and
/// installs the SAME underlying response-interceptor interface the `MisbehavingServer` uses
/// (`ServerImplTestAccess::set_on_secure_channel_available` + `SecureChannelTestAccess::set_response_
/// interceptor`) directly on that server - co-locating the real nodes and the deterministic Read-response
/// injection on one server. Only the source-timestamp fallback row needs the injection; the inactive-status
/// and locale rows are served entirely from stored node values (a stored Bad quality StatusCode and stored
/// per-locale `LocalizedText` Values are returned verbatim on a Read).
///
/// Timing: every completion is bridged off the executor via `std::promise`; the test thread is the only one
/// that blocks on a future (never a pool thread). No fixed sleeps.

#include "compliance_helpers.h"

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_state_machine_access.h"

#include "ua_access_level_type.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_read_response.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <future>
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

// Well-known ns0 Part-10 state / transition Object NodeIds reused as state identities (CL-SM-006 Id reuse).
const NodeId runningStateId{ObjectId::ProgramStateMachineType_Running};
const NodeId readyStateId{ObjectId::ProgramStateMachineType_Ready};
const NodeId haltedStateId{ObjectId::ProgramStateMachineType_Halted};
const NodeId suspendedStateId{ObjectId::ProgramStateMachineType_Suspended};
const NodeId runningToSuspendedId{ObjectId::ProgramStateMachineType_RunningToSuspended};

// A DateTime carried by M1's LastTransition.TransitionTime Property (the authoritative time the impl reads).
const DateTime transitionTimeProperty{2026, 7, 20, 10, 30, 0.0};
// A DateTime injected as the SourceTimestamp of M3's LastTransition.Value Read (the fallback time).
const DateTime fallbackSourceTime{2026, 7, 20, 8, 15, 0.0};

// The LastTransition display name M1/M3 serve; the response interceptor keys the source-timestamp injection
// on exactly this text so it colours only a LastTransition.Value Read.
constexpr std::string_view transitionName = "Run->Suspend";

// Mutex-guarded injection state co-owned by the fixture and every installed response interceptor. Because it
// is a shared_ptr held by the strand-bound interceptor closures, a strand turn that runs during teardown
// still touches live state. Only the source-timestamp fallback row arms it; every other row leaves it inert.
struct StateMachineInjection
{
  mutable std::mutex mutex;
  bool injectFallbackSourceTimestamp{false};
  // When armed, stamps Bad_ArgumentsMissing onto the first CallMethodResult of every CallResponse - models a
  // server that rejects a method Call with a per-op Bad status (CL-SM-008 verbatim-surface). Only the
  // ServerArgumentsMissing row arms it.
  bool injectCallArgumentsMissing{false};

  // Runs on the channel strand for every response, BEFORE signing. When armed, stamps the fallback source
  // timestamp onto a LastTransition.Value DataValue (the first result of a Read whose leading value is the
  // transitionName LocalizedText), modelling a server whose LastTransition carries a SourceTimestamp but no
  // TransitionTime Property; and/or stamps Bad_ArgumentsMissing onto a CallResponse's first result.
  void intercept(ua::Response& response)
  {
    std::lock_guard lock(mutex);
    if (injectCallArgumentsMissing)
    {
      if (auto* call = dynamic_cast<ua::CallResponse*>(response.second.get());
          call != nullptr && !call->results().empty())
      {
        call->response_header().service_result() = ua::StatusCode{ua::Status::Good};
        call->results()[0].status_code() = ua::StatusCode{ua::Status::BadArgumentsMissing};
      }
    }
    if (!injectFallbackSourceTimestamp)
    {
      return;
    }
    auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
    if (read == nullptr || read->results().empty())
    {
      return;
    }
    ua::DataValue& first = read->results()[0];
    if (const auto text = first.value().to<ua::LocalizedText>();
        text.is_good() && static_cast<std::string>(text.value().text()) == transitionName)
    {
      first.source_timestamp() = fallbackSourceTime;
    }
  }
};

// A read-only capture of the CallRequests the client put on the wire, populated on a server strand by the
// per-channel request observer and read by the test thread (the two run concurrently, hence the mutex). The
// observer fires at the top of the server's request handling, BEFORE dispatch/response, so by the time an
// invoke completion is delivered on the client executor every Call it issued has already been recorded.
struct CallRequestCapture
{
  mutable std::mutex mutex;
  std::vector<ua::CallMethodRequest> methodsToCall;

  void observe(const ua::Structure& request)
  {
    if (const auto* call = dynamic_cast<const ua::CallRequest*>(&request))
    {
      std::lock_guard lock(mutex);
      for (const auto& method : call->methods_to_call())
      {
        methodsToCall.push_back(method);
      }
    }
  }

  std::size_t call_count() const
  {
    std::lock_guard lock(mutex);
    return methodsToCall.size();
  }

  std::vector<ua::CallMethodRequest> snapshot() const
  {
    std::lock_guard lock(mutex);
    return methodsToCall;
  }
};

}  // namespace

// ============================================================================================================
// Fixture - ComplianceWithNodes extended with StateMachine instances, driven through the PUBLIC Connection.
// Suite name `ClientStateMachine` (tests named exactly `ClientStateMachine.<Row>`).
// ============================================================================================================
class ClientStateMachine : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    // M1 (8000): full machine - CurrentState "Running"@en + Id, LastTransition "Run->Suspend" + Id +
    // TransitionTime. Serves ReadCurrentStateNameAndId and ReadLastTransitionResolvesIdAndTime.
    {
      auto machine = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8000}}, "SmFull");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8001}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8002}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateId}});
      auto lastTransition = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8003}},
        "LastTransition",
        DataValue{Variant{LocalizedText{"en", std::string{transitionName}}}});
      add_property(addressSpace,
        lastTransition,
        NodeId{mTestNamespaceIndex, uint32_t{8004}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningToSuspendedId}});
      add_property(addressSpace,
        lastTransition,
        NodeId{mTestNamespaceIndex, uint32_t{8005}},
        "TransitionTime",
        NodeId{DataTypeId::DateTime},
        DataValue{Variant{transitionTimeProperty}});
    }

    // M2 (8010): CurrentState + Id, NO LastTransition. Serves LastTransitionAbsentReturnsBadNotFound.
    {
      auto machine =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8010}}, "SmNoLastTransition");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8011}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Ready"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8012}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{readyStateId}});
    }

    // M3 (8020): CurrentState + Id, LastTransition "Run->Suspend" + Id but NO TransitionTime Property. Serves
    // LastTransitionFallsBackToSourceTimestamp (the interceptor injects the LastTransition.Value
    // SourceTimestamp).
    {
      auto machine = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8020}}, "SmFallback");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8021}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8022}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateId}});
      auto lastTransition = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8023}},
        "LastTransition",
        DataValue{Variant{LocalizedText{"en", std::string{transitionName}}}});
      add_property(addressSpace,
        lastTransition,
        NodeId{mTestNamespaceIndex, uint32_t{8024}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningToSuspendedId}});
    }

    // M4 (8030): CurrentState Value carries a Bad_StateNotActive quality StatusCode + Id. Serves
    // InactiveSurfacesBadStateNotActiveViaStatusCodeNotResult.
    {
      auto machine = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8030}}, "SmInactive");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8031}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"", "Inactive"}}, StatusCode{Status::BadStateNotActive}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8032}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{haltedStateId}});
    }

    // M5 (8040): a "sub-state-machine" whose CurrentState carries Bad_StateNotActive. Structurally identical
    // to M4 (the client has no sub-machine special-casing). Serves
    // InactiveSubStateMachinePropagatesStatusUnchanged.
    {
      auto machine =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8040}}, "SmSubInactive");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8041}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"", "SubInactive"}}, StatusCode{Status::BadStateNotActive}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8042}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{haltedStateId}});
    }

    // M6 (8050) EN / M7 (8060) FR: two machines reporting the SAME CurrentState.Id (Running) rendered in
    // different locales. Serves CurrentStateIsComparesByNodeIdAcrossLocales.
    {
      auto machineEn =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8050}}, "SmLocaleEn");
      auto currentStateEn = add_state_variable(addressSpace,
        machineEn,
        NodeId{mTestNamespaceIndex, uint32_t{8051}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentStateEn,
        NodeId{mTestNamespaceIndex, uint32_t{8052}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateId}});

      auto machineFr =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8060}}, "SmLocaleFr");
      auto currentStateFr = add_state_variable(addressSpace,
        machineFr,
        NodeId{mTestNamespaceIndex, uint32_t{8061}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"fr", "En cours"}}});
      add_property(addressSpace,
        currentStateFr,
        NodeId{mTestNamespaceIndex, uint32_t{8062}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateId}});
    }

    // M8 (8070) / M9 (8080): two machines each in an "Idle" state whose DISPLAY NAMES are identical but whose
    // state Id NodeIds differ. Serves CurrentStateIsRejectsDisplayNameMatch.
    {
      auto machineA = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8070}}, "SmIdleA");
      auto currentStateA = add_state_variable(addressSpace,
        machineA,
        NodeId{mTestNamespaceIndex, uint32_t{8071}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"", "Idle"}}});
      add_property(addressSpace,
        currentStateA,
        NodeId{mTestNamespaceIndex, uint32_t{8072}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{mIdleStateAId}});

      auto machineB = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8080}}, "SmIdleB");
      auto currentStateB = add_state_variable(addressSpace,
        machineB,
        NodeId{mTestNamespaceIndex, uint32_t{8081}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"", "Idle"}}});
      add_property(addressSpace,
        currentStateB,
        NodeId{mTestNamespaceIndex, uint32_t{8082}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{mIdleStateBId}});
    }

    // --- Part-10 ProgramStateMachineType instances (8200+, disjoint from the 8000-8082 finite machines and
    // the 8100/8101 identity values above). These are structurally program machines: CurrentState + Id plus
    // the Part-10 Control Methods (Start / Suspend, ...) as ns0-BrowseName HasComponent children. The
    // client's program_state_machine_async resolves the methods by ns0 BrowseName (not by type definition),
    // so the create_machine HasTypeDefinition (FiniteStateMachineType) is immaterial to the program facade.
    // The CurrentState.Id VALUE is a well-known Part-10 ProgramState Object NodeId so the local state-method
    // matrix (program_state_of) recognises the state.

    // P1 (8200): program in Ready; Start Method Executable=true, no InputArguments Property (a no-arg
    // method). Serves CanInvokeReadsExecutableAttribute (can_invoke(Start) -> true) and
    // InvokeEmptyArgsWhenTypeDefinesNone (invoke(Start, {}) is valid from Ready -> Call with an empty
    // InputArguments list).
    {
      auto machine = create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8200}}, "SmProgReady");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8201}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Ready"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8202}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{readyStateId}});
      add_method(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8203}},
        "Start",
        /*executable=*/true,
        /*installGoodHandler=*/true);
    }

    // P2 (8210): program in Running; Start Method Executable=false. Serves CanInvokeFalseWhenNotExecutable
    // (can_invoke(Start) reads the false Executable Attribute verbatim -> false).
    {
      auto machine =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8210}}, "SmProgRunning");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8211}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8212}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateId}});
      add_method(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8213}},
        "Start",
        /*executable=*/false,
        /*installGoodHandler=*/false);
    }

    // P3 (8220): program in Running; Start Executable=true (matrix-invalid from Running) and Suspend
    // Executable=true (matrix-valid from Running), both with Good handlers. Serves
    // InvokePassesArgumentsVerbatim (invoke(Suspend, {42})),
    // LocalStateMatrixBlocksInvalidTransitionWithoutWireCall (invoke(Start) blocked locally),
    // IsInStateReflectsCurrentState (Running), and ServerArgumentsMissingSurfacesBadStatus (the Call response
    // is injected Bad_ArgumentsMissing).
    {
      auto machine =
        create_machine(addressSpace, NodeId{mTestNamespaceIndex, uint32_t{8220}}, "SmProgRunningMethods");
      auto currentState = add_state_variable(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8221}},
        "CurrentState",
        DataValue{Variant{LocalizedText{"en", "Running"}}});
      add_property(addressSpace,
        currentState,
        NodeId{mTestNamespaceIndex, uint32_t{8222}},
        "Id",
        NodeId{DataTypeId::NodeId},
        DataValue{Variant{runningStateId}});
      add_method(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8223}},
        "Start",
        /*executable=*/true,
        /*installGoodHandler=*/true);
      add_method(addressSpace,
        machine,
        NodeId{mTestNamespaceIndex, uint32_t{8224}},
        "Suspend",
        /*executable=*/true,
        /*installGoodHandler=*/true);
    }

    install_response_interceptor();
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();

    // A dedicated channel + activated session handed to a started ConnectionImpl, then wrapped into the
    // PUBLIC Connection handle via the test wrap interface (the same shape the connect path produces).
    mConnChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    auto session = mConnChannel->create_session_sync({.sessionName = "CLIENT_SM_MATRIX"});
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

  // Creates a StateMachine Object @p machineId (HasTypeDefinition FiniteStateMachineType), organised under
  // the Objects folder so it is browsable. Returns the created node so component children can be attached.
  NodeAccessor create_machine(AddressSpace& addressSpace, const NodeId& machineId, std::string browseName)
  {
    auto node = addressSpace.create_node_sync(machineId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    EXPECT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    object->set_display_name(LocalizedText{"", browseName});
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::FiniteStateMachineType});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, machineId);
    return node;
  }

  // Adds an ns0-BrowseName state Variable child (@p ns0Name is "CurrentState" or "LastTransition") via
  // HasComponent, DataType LocalizedText, carrying @p value verbatim (quality StatusCode included). Returns
  // the child node so its Id / TransitionTime Properties can be attached to it.
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

  // Adds an ns0-BrowseName Property child (@p ns0Name is "Id" or "TransitionTime") via HasProperty on
  // @p owner (the CurrentState / LastTransition variable), DataType @p dataType, carrying @p value verbatim.
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

  // Adds an ns0-BrowseName Part-10 Control Method (@p ns0Name is "Start" / "Suspend" / ...) via HasComponent
  // on
  // @p machine with the given `Executable` Attribute - exactly the ns0-BrowseName children the client's
  // program facade resolves the method nodes from. When @p installGoodHandler is set a call handler returning
  // a Good, empty `CallMethodResult` is registered so an executable, matrix-valid invoke round-trips to a
  // Good per-op status; a non-executable method needs none (the server rejects on the Executable Attribute
  // before dispatch).
  void add_method(AddressSpace& addressSpace, NodeAccessor& machine, const NodeId& methodId,
    std::string_view ns0Name, bool executable, bool installGoodHandler)
  {
    auto node = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = node.as<MethodAccessor>();
    EXPECT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{0, std::string{ns0Name}});
    method->set_display_name(LocalizedText{"", std::string{ns0Name}});
    method->set_executable(executable);
    machine.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);
    if (installGoodHandler)
    {
      auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
      EXPECT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            callback)
        {
          CallMethodResult result;
          callback(CallResult{std::move(result)});
        });
    }
  }

  // Installs the MisbehavingServer-style per-channel response interceptor (the same interface MisbehavingServer
  // uses), consulting the shared StateMachineInjection. Installed before the server starts so it is active
  // for every channel the Connection opens.
  void install_response_interceptor()
  {
    auto& serverImpl = ServerTestAccess::impl(mServer.server());
    ServerImplTestAccess(serverImpl)
      .set_on_secure_channel_available(
        [injection = mInjection, capture = mCallCapture](
          std::shared_ptr<ua::server::SecureChannel> secureChannel)
        {
          ua::server::SecureChannelTestAccess::post_on_strand(std::move(secureChannel),
            [injection, capture](auto& guard)
            {
              guard.set_response_interceptor(
                [injection](ua::Response& response) { injection->intercept(response); });
              // The request observer fires at the top of the server's request handling (before dispatch), so
              // every Call the client issues is recorded before its completion reaches the client executor.
              guard.set_request_observer([capture](std::uint32_t /*requestId*/, const ua::Structure& request)
                { capture->observe(request); });
            });
        });
  }

  // ---- typed-handle drivers (block on the test thread for the async completion) ----

  StateMachineHandleResult build_state_machine(const NodeId& machineId)
  {
    std::promise<StateMachineHandleResult> promise;
    auto future = promise.get_future();
    mConnection->state_machine_accessor().state_machine_async(
      machineId, [&promise](StateMachineHandleResult result) { promise.set_value(std::move(result)); });
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

  static TransitionVariableResult read_last_transition(StateMachineHandle handle)
  {
    std::promise<TransitionVariableResult> promise;
    auto future = promise.get_future();
    handle.last_transition_async(
      [&promise](TransitionVariableResult result) { promise.set_value(std::move(result)); });
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

  ProgramStateMachineHandleResult build_program_machine(const NodeId& machineId)
  {
    std::promise<ProgramStateMachineHandleResult> promise;
    auto future = promise.get_future();
    mConnection->state_machine_accessor().program_state_machine_async(machineId,
      [&promise](ProgramStateMachineHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<bool> can_invoke(ProgramStateMachineHandle handle, ProgramMethod method)
  {
    std::promise<Result<bool>> promise;
    auto future = promise.get_future();
    handle.can_invoke_async(
      method, [&promise](Result<bool> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<CallMethodResult> invoke(
    ProgramStateMachineHandle handle, ProgramMethod method, std::vector<Variant> args)
  {
    std::promise<Result<CallMethodResult>> promise;
    auto future = promise.get_future();
    handle.invoke_async(method,
      std::move(args),
      [&promise](Result<CallMethodResult> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  std::shared_ptr<StateMachineInjection> mInjection{std::make_shared<StateMachineInjection>()};
  std::shared_ptr<CallRequestCapture> mCallCapture{std::make_shared<CallRequestCapture>()};
  // State identities for the display-name-match rejection row: two "Idle" states with different NodeIds.
  NodeId mIdleStateAId{mTestNamespaceIndex, uint32_t{8100}};
  NodeId mIdleStateBId{mTestNamespaceIndex, uint32_t{8101}};

  // Fully qualify the client channel/connection types: `SecureChannel` is ambiguous here (both
  // ua::client:: and ua::server:: are in scope via the test-access interfaces).
  std::optional<ua::client::SecureChannel> mConnChannel;
  std::shared_ptr<ConnectionImpl> mConnImpl;
  std::optional<ua::client::Connection> mConnection;
};

// ============================================================================================================
// Happy-path reads (CL-SM-001 / CL-SM-004)
// ============================================================================================================

// @verifies CL-SM-001
// CurrentState resolves both the LocalizedText Value (name) and the Id Property (state NodeId) in one read.
// @relation(CL-SM-001, scope=function)
TEST_F(ClientStateMachine, ReadCurrentStateNameAndId)
{
  auto handle = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8000}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto state = read_current_state(handle.value());
  ASSERT_TRUE(state.is_good()) << "0x" << std::hex << state.status_code().as_uint32();
  EXPECT_EQ(static_cast<std::string>(state.value().name.text()), "Running");
  ASSERT_TRUE(state.value().id.has_value());
  EXPECT_EQ(*state.value().id, runningStateId);
}

// @verifies CL-SM-004
// LastTransition resolves the LocalizedText name, the Id Property, and the TransitionTime Property value.
// @relation(CL-SM-004, scope=function)
TEST_F(ClientStateMachine, ReadLastTransitionResolvesIdAndTime)
{
  auto handle = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8000}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto transition = read_last_transition(handle.value());
  ASSERT_TRUE(transition.is_good()) << "0x" << std::hex << transition.status_code().as_uint32();
  EXPECT_EQ(static_cast<std::string>(transition.value().name.text()), std::string{transitionName});
  ASSERT_TRUE(transition.value().id.has_value());
  EXPECT_EQ(*transition.value().id, runningToSuspendedId);
  ASSERT_TRUE(transition.value().transitionTime.has_value());
  EXPECT_EQ(*transition.value().transitionTime, transitionTimeProperty);
}

// @verifies CL-SM-004
// A machine without the Optional LastTransition component fails last_transition with Bad_NotFound (the BUILT
// behaviour; the matrix's suggested "empty-Good/nullopt" oracle was NOT adopted - reported).
// @relation(CL-SM-004, scope=function)
TEST_F(ClientStateMachine, LastTransitionAbsentReturnsBadNotFound)
{
  auto handle = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8010}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto transition = read_last_transition(handle.value());
  ASSERT_TRUE(transition.is_bad());
  EXPECT_EQ(transition.status_code().as_status(), Status::BadNotFound);
  ASSERT_NE(transition.shared_detail(), nullptr);
  EXPECT_EQ(transition.shared_detail()->source, "client.tier2.state_machine.last_transition_not_present");
}

// @verifies CL-SM-004
// When the LastTransition carries no TransitionTime Property, the transition time falls back to the
// LastTransition.Value DataValue's SourceTimestamp. The interceptor stamps a known SourceTimestamp onto the
// (property-less) LastTransition.Value Read so the fallback is asserted deterministically end-to-end.
// @relation(CL-SM-004, scope=function)
TEST_F(ClientStateMachine, LastTransitionFallsBackToSourceTimestamp)
{
  {
    std::lock_guard lock(mInjection->mutex);
    mInjection->injectFallbackSourceTimestamp = true;  // stamp the LastTransition.Value SourceTimestamp
  }

  auto handle = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8020}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto transition = read_last_transition(handle.value());
  ASSERT_TRUE(transition.is_good()) << "0x" << std::hex << transition.status_code().as_uint32();
  EXPECT_EQ(static_cast<std::string>(transition.value().name.text()), std::string{transitionName});
  ASSERT_TRUE(transition.value().id.has_value());
  EXPECT_EQ(*transition.value().id, runningToSuspendedId);
  ASSERT_TRUE(transition.value().transitionTime.has_value());
  EXPECT_EQ(*transition.value().transitionTime, fallbackSourceTime)
    << "with no TransitionTime Property the time must fall back to the Value's SourceTimestamp";
}

// ============================================================================================================
// Inactive state - Bad_StateNotActive is an IN-BAND value status, not a service failure (CL-SM-002)
// ============================================================================================================

// @verifies CL-SM-002
// A CurrentState whose DataValue.StatusCode is Bad_StateNotActive surfaces as an in-band value status: the
// callback receives a Good outer Result whose StateVariable.statusCode == Bad_StateNotActive. Part 4
// section 7.11.1 requires the server to null the unusable Value; the SDK must neither expose a stale name nor
// collapse the per-value Bad into a transport-level failure.
// @relation(CL-SM-002, scope=function)
TEST_F(ClientStateMachine, InactiveSurfacesBadStateNotActiveViaStatusCodeNotResult)
{
  auto handle = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8030}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto state = read_current_state(handle.value());
  ASSERT_TRUE(state.is_good())
    << "the outer Result must stay Good: Bad_StateNotActive is an in-band value status";
  EXPECT_EQ(state.value().statusCode.as_status(), Status::BadStateNotActive);
  EXPECT_TRUE(state.value().name.text().empty())
    << "the server must null an error-status DataValue and tier 2 must not expose a stale name";
}

// @verifies CL-SM-002
// An inactive SUB-state-machine propagates its Bad_StateNotActive CurrentState quality through the typed
// accessor unchanged. The client has no sub-machine special-casing, so this proves it neither masks nor
// remaps the in-band status for a (semantically) sub-machine handle.
// @relation(CL-SM-002, scope=function)
TEST_F(ClientStateMachine, InactiveSubStateMachinePropagatesStatusUnchanged)
{
  auto handle = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8040}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto state = read_current_state(handle.value());
  ASSERT_TRUE(state.is_good());
  EXPECT_EQ(state.value().statusCode.as_status(), Status::BadStateNotActive)
    << "the sub-machine's inactive status must survive the typed accessor unchanged";
}

// ============================================================================================================
// current_state_is - identity by NodeId, never by display name (CL-SM-003 / CL-SM-006)
// ============================================================================================================

// @verifies CL-SM-003
// current_state_is compares the CurrentState by its Id NodeId, which is locale-independent. Two machines
// report the SAME state Id rendered in different locales ("Running"@en / "En cours"@fr); current_state_is
// returns true for both. The display names genuinely differ (proving the locale varied), yet the Id-based
// comparison is stable - the exact locale-fragility the spec warns against would flip the second machine.
// @relation(CL-SM-003, scope=function)
TEST_F(ClientStateMachine, CurrentStateIsComparesByNodeIdAcrossLocales)
{
  auto handleEn = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8050}});
  ASSERT_TRUE(handleEn.is_good()) << "0x" << std::hex << handleEn.status_code().as_uint32();
  auto handleFr = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8060}});
  ASSERT_TRUE(handleFr.is_good()) << "0x" << std::hex << handleFr.status_code().as_uint32();

  // Precondition: the two machines really do render the same state in different locales.
  const std::string nameEn =
    static_cast<std::string>(read_current_state(handleEn.value()).value().name.text());
  const std::string nameFr =
    static_cast<std::string>(read_current_state(handleFr.value()).value().name.text());
  EXPECT_EQ(nameEn, "Running");
  EXPECT_EQ(nameFr, "En cours");
  ASSERT_NE(nameEn, nameFr) << "the two locales must render the state differently for this test to matter";

  auto matchEn = current_state_is(handleEn.value(), runningStateId);
  ASSERT_TRUE(matchEn.is_good()) << "0x" << std::hex << matchEn.status_code().as_uint32();
  EXPECT_TRUE(matchEn.value());
  auto matchFr = current_state_is(handleFr.value(), runningStateId);
  ASSERT_TRUE(matchFr.is_good()) << "0x" << std::hex << matchFr.status_code().as_uint32();
  EXPECT_TRUE(matchFr.value())
    << "the Id-based comparison must hold regardless of the CurrentState LocalizedText locale";
}

// @verifies CL-SM-003
// current_state_is must NOT match by display name. Two machines are each in an "Idle" state whose display
// names are identical but whose state Id NodeIds differ; machine A's current_state_is against machine B's
// Idle-state Id returns false (only its own Id matches). A display-name comparison would wrongly return true.
// @relation(CL-SM-003, scope=function)
TEST_F(ClientStateMachine, CurrentStateIsRejectsDisplayNameMatch)
{
  auto handleA = build_state_machine(NodeId{mTestNamespaceIndex, uint32_t{8070}});
  ASSERT_TRUE(handleA.is_good()) << "0x" << std::hex << handleA.status_code().as_uint32();

  // machine B's Idle-state Id shares machine A's "Idle" DISPLAY NAME but is a different NodeId -> no match.
  auto crossMatch = current_state_is(handleA.value(), mIdleStateBId);
  ASSERT_TRUE(crossMatch.is_good()) << "0x" << std::hex << crossMatch.status_code().as_uint32();
  EXPECT_FALSE(crossMatch.value())
    << "same display name, different Id NodeId must NOT match (no display-name equality)";

  // Positive control: machine A's OWN Idle-state Id matches (guards against an always-false comparison).
  auto selfMatch = current_state_is(handleA.value(), mIdleStateAId);
  ASSERT_TRUE(selfMatch.is_good()) << "0x" << std::hex << selfMatch.status_code().as_uint32();
  EXPECT_TRUE(selfMatch.value());
}

// ============================================================================================================
// ClientProgramStateMachine - Part-10 ProgramStateMachineType facade (CL-SM-007/008/009, section 8.18.4.2).
// Reuses the ClientStateMachine fixture (StateMachine nodes + response-interceptor + request-observer interfaces)
// under the ProgramStateMachine suite name via a trivial subclass. Program machines P1 (8200) / P2 (8210) /
// P3 (8220) carry the Part-10 Control Methods as ns0-BrowseName HasComponent children (see configure_server).
// ============================================================================================================
class ClientProgramStateMachine : public ClientStateMachine
{};

// @verifies CL-SM-007
// Start.Executable is false (P2, machine in Running); can_invoke must surface false - never synthesise true -
// so the application is not misled into an invalid Call. (Unit half pre-existing: no separate unit authored.)
// @relation(CL-SM-007, scope=function)
TEST_F(ClientProgramStateMachine, CanInvokeFalseWhenNotExecutable)
{
  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8210}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto result = can_invoke(handle.value(), ProgramMethod::Start);
  ASSERT_TRUE(result.is_good()) << "reading a false Executable Attribute is not a service failure";
  EXPECT_FALSE(result.value())
    << "Start.Executable is false; can_invoke must reflect it, not synthesise executability";
}

// @verifies CL-SM-007
// Start.Executable is true (P1, machine in Ready); can_invoke reflects the method node's Executable
// Attribute. The op-level pin (a Read of AttributeId::Executable on the Start node) is the pre-existing unit
// half (ClientStateMachineProgram.CanInvokeReadsExecutableAttribute) - reported; no renamed duplicate
// authored.
// @relation(CL-SM-007, scope=function)
TEST_F(ClientProgramStateMachine, CanInvokeReadsExecutableAttribute)
{
  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8200}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto result = can_invoke(handle.value(), ProgramMethod::Start);
  ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  EXPECT_TRUE(result.value())
    << "Start.Executable is true; can_invoke must read and reflect the method node's Executable Attribute";
}

// @verifies CL-SM-008
// A method whose type defines no InputArguments (P1 Start): invoke(Start, {}) is matrix-valid from Ready and
// executable, so it reaches the wire Call - and that Call carries an EMPTY InputArguments list. The SDK must
// not inject placeholder arguments (the server would reject a padded call).
// @relation(CL-SM-008, scope=function)
TEST_F(ClientProgramStateMachine, InvokeEmptyArgsWhenTypeDefinesNone)
{
  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8200}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto result = invoke(handle.value(), ProgramMethod::Start, {});
  ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();

  auto calls = mCallCapture->snapshot();
  ASSERT_EQ(calls.size(), 1U) << "invoke must issue exactly one Call";
  EXPECT_TRUE(calls[0].input_arguments().empty())
    << "a no-argument method must send an empty InputArguments list, not synthesised placeholders";
}

// @verifies CL-SM-008
// The caller's argument vector is forwarded verbatim into the CallMethodRequest (P3 Suspend, valid from
// Running): invoke(Suspend, {Int32 42}) puts exactly [Variant{42}] on the wire - no padding, no reorder, no
// synthesis. The pure-logic pin (args forwarded to call_method_async unchanged) is the pre-existing unit half
// (ClientStateMachineProgram.InvokePassesArgumentsVerbatimAndComposesCall) - reported; no duplicate authored.
// @relation(CL-SM-008, scope=function)
TEST_F(ClientProgramStateMachine, InvokePassesArgumentsVerbatim)
{
  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8220}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto result = invoke(handle.value(), ProgramMethod::Suspend, {Variant{std::int32_t{42}}});
  ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();

  auto calls = mCallCapture->snapshot();
  ASSERT_EQ(calls.size(), 1U);
  const auto& inputs = calls[0].input_arguments();
  ASSERT_EQ(inputs.size(), 1U) << "the caller's single argument must reach the wire unpadded";
  const std::int32_t* value = inputs[0].try_as<std::int32_t>();
  ASSERT_NE(value, nullptr) << "the argument must travel as the Int32 the caller supplied";
  EXPECT_EQ(*value, 42) << "the argument must be forwarded verbatim (no reorder/synthesis)";
}

// @verifies AC-CL-SM-009-STATE-GATED-CALLS
// The state-identity query reflects the machine's CurrentState.Id (P3, in Running): exactly one program-state
// predicate is true (Running), the others false.
//
// UNBUILT (reported): the reqs-doc design coverage names a typed `is_in_state(ProgramState)` helper, but the
// BUILT ProgramStateMachineHandle has no such method (ProgramState is an internal enum). The built,
// equivalent query is the inherited current_state_is_async(NodeId) over the well-known Part-10 ProgramState
// Object NodeIds - this test drives that.
// @relation(AC-CL-SM-009-STATE-GATED-CALLS, scope=function)
TEST_F(ClientProgramStateMachine, IsInStateReflectsCurrentState)
{
  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8220}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto running = current_state_is(handle.value(), runningStateId);
  ASSERT_TRUE(running.is_good()) << "0x" << std::hex << running.status_code().as_uint32();
  EXPECT_TRUE(running.value()) << "the machine's CurrentState.Id is Running";

  auto ready = current_state_is(handle.value(), readyStateId);
  ASSERT_TRUE(ready.is_good());
  EXPECT_FALSE(ready.value());
  auto suspended = current_state_is(handle.value(), suspendedStateId);
  ASSERT_TRUE(suspended.is_good());
  EXPECT_FALSE(suspended.value());
  auto halted = current_state_is(handle.value(), haltedStateId);
  ASSERT_TRUE(halted.is_good());
  EXPECT_FALSE(halted.value()) << "exactly one program-state predicate is true (Running)";
}

// @verifies AC-CL-SM-009-STATE-GATED-CALLS
// The BUILT invoke_async runs a client-side pre-check (the local Part-10 state-method matrix): Start is a
// valid cause only from Ready (Part 10 Table 4). Invoked from Running (P3, Start executable so the Executable
// pre-flight passes), it is blocked LOCALLY - Bad_InvalidState, source state_method_mismatch - with NO wire
// Call. The request observer confirms zero Calls reached the server.
//
// Reported (design tension): the matrix reviewer flags this auto-gate as diverging from CL-SM-009's intent
// (an application-side gate via is_in_state / can_invoke, not on invoke_async). The gate IS built, so this
// test pins the BUILT behaviour; the ratification of the auto-gate design is deferred to the maintainer.
// @relation(AC-CL-SM-009-STATE-GATED-CALLS, scope=function)
TEST_F(ClientProgramStateMachine, LocalStateMatrixBlocksInvalidTransitionWithoutWireCall)
{
  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8220}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto result = invoke(handle.value(), ProgramMethod::Start, {});
  ASSERT_TRUE(result.is_bad()) << "Start from Running is not a permitted transition";
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidState);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.state_machine.state_method_mismatch");
  EXPECT_EQ(mCallCapture->call_count(), 0U)
    << "an invalid transition must be blocked locally by the state matrix, with zero wire Calls";
}

// @verifies CL-SM-008
// A server that answers the method Call with a per-op Bad_ArgumentsMissing (client under-supplied per the
// type definition): the tier-2 facade must surface that status verbatim, chained beneath source
// client.tier2.state_machine.method_call - never masked to Good. (P3 Suspend is executable and matrix-valid
// from Running, so the invoke reaches the wire Call; the response interceptor injects the per-op Bad status.)
// @relation(CL-SM-008, scope=function)
TEST_F(ClientProgramStateMachine, ServerArgumentsMissingSurfacesBadStatus)
{
  {
    std::lock_guard lock(mInjection->mutex);
    mInjection->injectCallArgumentsMissing = true;  // stamp Bad_ArgumentsMissing onto the CallResponse
  }

  auto handle = build_program_machine(NodeId{mTestNamespaceIndex, uint32_t{8220}});
  ASSERT_TRUE(handle.is_good()) << "0x" << std::hex << handle.status_code().as_uint32();

  auto result = invoke(handle.value(), ProgramMethod::Suspend, {});
  ASSERT_TRUE(result.is_bad()) << "the server's per-op Bad status must not be swallowed or mapped to Good";
  EXPECT_EQ(result.status_code().as_status(), Status::BadArgumentsMissing);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.state_machine.method_call");
}
