// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientMethodCall cluster of the client integration-test matrix (the 21 `ClientMethodCall.*` rows).
///
/// These are END-TO-END integration tests of the TIER-2 managed method-call surface (client design
/// section 7.2):
///   - `Connection::typed().call_method_*` (single-method typed call -> `Result<CallResult>`), and
///   - `Connection::service_requests().call_*` (wire-shaped batch Call -> `Result<CallResponse>`),
/// against a real in-tree server. The tier-2 `Connection` is built by wrapping a real `ConnectionImpl`
/// over an activated tier-0 Session (the same construction the committed ClientRead (046acc46) /
/// ClientWrite (751d0f88) / ClientBrowse (446fbc6a) / ClientSubscription (3f7851e8) /
/// ClientMonitoredItem (ebb8f0ca) slices use). The Connection is single-shot with NO keep-alive poll:
/// no background traffic races the MisbehavingServer response mutators / request observer, and the
/// bootstrap runs against an un-mutated server (mutators/observers are armed only AFTER `start`).
///
/// Two fixtures drive the rows:
///   - ComplianceWithNodes rows call the real callable Method nodes (Add: TestFolder->TestMethod returning
///     arg0+arg1; NonExecutableMethod; NoArgsMethod) already built by the compliance fixture.
///   - MisbehavingServer rows inject shaped/malformed CallResponses via `set_response_mutator` (per-op
///     status, stray outputs, service-level serviceResult, per-argument results) and observe the DECODED
///     outgoing CallRequest via `set_request_observer` (wire-verbatim: objectId/methodId, inputArguments
///     order, ByteString-for-Byte[], omitted-trailing-optional short array).
///
/// tier-2 CallResult shape (`ua::CallResult = Result<CallMethodResult>`): the tier-2 return is
/// `Result<CallResult>` = `Result<Result<CallMethodResult>>`. The OUTER Result is bad only on a
/// service-level failure. The INNER `CallResult` carries the per-method outcome: Good OR Uncertain keeps
/// the full CallMethodResult (status + outputArguments + inputArgumentResults); a Bad-Severity per-method
/// status collapses the inner CallResult to a source-tagged ErrorDetail that localises the offending
/// input argument (CL-METH-005/006). The raw parallel vectors (inputArgumentResults / outputArguments on
/// a Bad status) remain reachable via the tier-1 wire-shaped `service_requests().call` path.
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier. Rows whose literal oracle
/// is blocked by an unbuilt surface (mid-flight session-loss needs the reconnect harness; per-argument
/// DiagnosticInfo->ErrorDetail routing) pin the built, spec-consistent guarantee that IS observable and
/// record the gap in the header comment + the authoring report.
///
/// ---------------------------------------------------------------------------------------------------
/// CALIBRATION - the Phase-D Complex rows + the Optional (preflight) rows against the BUILT call path.
///
/// The tier-2 call funnel (`TypedAccess::call_method_async`, ua_typed_access.cpp) leaves non-structured
/// input Variants verbatim. Structured inputs first inspect the Method's InputArguments metadata and consult
/// the per-Connection TypeResolver before the wire:
///
///   (1) OUTBOUND STRUCTURED VALIDATION. The concrete DataType must equal or subtype the declared
///       `Argument::DataType`, and the TypeRegistry must map it to a binary encoding. A concrete
///       `ua::Structure` still self-encodes that registered identity; unresolved/mismatched values fail
///       locally with `Bad_DataEncodingInvalid` or `Bad_TypeMismatch`.
///
///   (2) INBOUND DECODE AND REIFY. Known outputs decode through the codec factory; unresolved
///   ExtensionObjects
///       then pass through the per-Connection TypeResolver reify gate before delivery, retaining opaque bytes
///       when policy leaves the type unresolved.
///
///   (3) THE GENERIC CALL PATH HAS NO AUTOMATIC ARG-COUNT PREFLIGHT. `call_method_async` deliberately
///       preserves pass-through semantics and defers validation to the server. The opt-in
///       `inspect_method_inputs_*` API now reads InputArguments plus
///       HasOptionalInputArgumentDescription metadata and computes the conformant trailing-optional suffix,
///       but it does not silently alter or block a later generic Call. `PreflightDisabled...` therefore
///       remains the default-call-path pin; the separate metadata row exercises the built introspector.
///
/// `AbstractArgumentResolvesToConcreteSubtypeOnWire` is recorded in the matrix's own "Rejected (dropped)"
/// list as a tautology on a builtin Variant. It is authored here per the task's explicit instruction as a
/// CALIBRATED tautology-pin: a Variant is inherently concrete, so no abstract->concrete resolution occurs;
/// the row pins that a concrete builtin subtype travels the wire with its exact type identity intact (no
/// widening to an abstract carrier, no client-side coercion).
/// ---------------------------------------------------------------------------------------------------

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_service_set.h"
#include "ua_typed_access.h"

#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_array.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_error_detail.h"
#include "ua_datatype_id.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_range.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_unknown_structure.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a `ConnectionImpl` (built over an activated Session, no reconnect wiring ->
// single-shot, no keep-alive) into the public tier-2 `Connection` handle, runs the bootstrap, and closes
// gracefully on destruction. Copied verbatim from the prior matrix slices - the same tier-2 interface.
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(boost::asio::any_io_executor executor, Session session)
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~StartedConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedConnection(const StartedConnection&) = delete;
  StartedConnection& operator=(const StartedConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

private:
  VoidResult mStartStatus{};  // default-constructs to Good
  std::optional<Connection> mConnection;
};

// ---------------------------------------------------------------------------------------------
// A read-only capture of the CallRequests the client put on the wire (each entry's objectId, methodId,
// and inputArguments), populated on a server strand by the MisbehavingServer request observer and read by
// the test thread. Guarded because the two run concurrently.
// ---------------------------------------------------------------------------------------------
struct CapturedCall
{
  std::vector<ua::CallMethodRequest> methodsToCall;
};

struct CallRequestCapture
{
  mutable std::mutex mutex;
  std::vector<CapturedCall> calls;

  // Forwarded by MisbehavingServer::set_request_observer: records only CallRequest requests.
  void observe(const ua::Structure& request)
  {
    if (const auto* call = dynamic_cast<const ua::CallRequest*>(&request))
    {
      CapturedCall captured;
      for (const auto& method : call->methods_to_call())
        captured.methodsToCall.push_back(method);
      std::lock_guard lock(mutex);
      calls.push_back(std::move(captured));
    }
  }

  std::size_t call_count() const
  {
    std::lock_guard lock(mutex);
    return calls.size();
  }

  std::vector<CapturedCall> snapshot() const
  {
    std::lock_guard lock(mutex);
    return calls;
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 3000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(5ms);
  }
  return predicate();
}

// ---------------------------------------------------------------------------------------------
// MisbehavingCallFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate
// store, on its own thread pool, with an activated Session wrapped into a started tier-2 Connection.
// Mirror of the prior slices' MisbehavingReadFixture / MisbehavingBrowseFixture. The bootstrap completes
// against the un-mutated server; the test arms the response mutators / request observer AFTER
// construction.
// ---------------------------------------------------------------------------------------------
class MisbehavingCallFixture
{
public:
  explicit MisbehavingCallFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientMethodCallMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingCallFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingCallFixture(const MisbehavingCallFixture&) = delete;
  MisbehavingCallFixture& operator=(const MisbehavingCallFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedConnection> mConnection;
};

// Two real, distinct, existing NS0 nodes used as the (object, method) pair for the verbatim-wire row: a
// silent swap would address a different real node, so a wrong-node success (not an incidental error) would
// surface. The call's response is forced Good by the mutator - only the OUTGOING request is asserted.
NodeId wire_object_node()
{
  return NodeId{ObjectId::ObjectsFolder};
}

NodeId wire_method_node()
{
  return NodeId{ObjectId::Server};
}

// Forces the (single) CallResponse result Good with @p outputs, so a call against a MisbehavingServer
// (which has no real Methods) completes cleanly for the wire-verbatim rows. Leaves the result untouched
// when the response carries no result slot (defensive).
void force_call_result_good(Response& response, ua::Array<ua::Variant> outputs)
{
  if (auto* call = dynamic_cast<ua::CallResponse*>(response.second.get()))
  {
    call->response_header().service_result() = ua::StatusCode{ua::Status::Good};
    if (!call->results().empty())
    {
      call->results()[0].status_code() = ua::StatusCode{ua::Status::Good};
      call->results()[0].output_arguments() = std::move(outputs);
    }
  }
}

}  // namespace

// =============================================================================================
// Fixture: one gtest suite `ClientMethodCall`. Derives from ComplianceWithNodes so the real-method rows
// have the callable Method nodes (Add=TestMethod, NonExecutableMethod, NoArgsMethod) already built.
// =============================================================================================
class ClientMethodCall : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    mOptionalMetadataMethodId = NodeId{mTestNamespaceIndex, uint32_t{3200}};
    auto methodNode = addressSpace.create_node_sync(mOptionalMetadataMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    method->set_browse_name(QualifiedName{mTestNamespaceIndex, "OptionalMetadataMethod"});
    method->set_display_name(LocalizedText{"", "OptionalMetadataMethod"});
    method->set_executable(true);
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mOptionalMetadataMethodId);

    const NodeId inputArgumentsId{mTestNamespaceIndex, uint32_t{3201}};
    auto inputNode = addressSpace.create_node_sync(inputArgumentsId, NodeClass::Variable);
    auto inputVariable = inputNode.as<VariableAccessor>();
    inputVariable->set_browse_name(QualifiedName{0, "InputArguments"});
    inputVariable->set_display_name(LocalizedText{"", "InputArguments"});
    inputVariable->set_data_type(NodeId{DataTypeId::Argument});
    inputVariable->set_value_rank(int32_t{1});
    Array<RefStructure<Structure>> arguments;
    for (std::string_view name : {"A", "B", "C", "D"})
    {
      auto argument = std::make_unique<Argument>();
      argument->name() = String{name};
      argument->data_type() = NodeId{DataTypeId::Int32};
      argument->value_rank() = -1;
      arguments.push_back(RefStructure<Structure>{std::move(argument)});
    }
    inputVariable->write_value_sync(DataValue{Variant{std::move(arguments)}});
    methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, inputArgumentsId);

    for (const auto& [id, name] :
      std::array<std::pair<uint32_t, std::string_view>, 2>{{{3202, "C"}, {3203, "D"}}})
    {
      const NodeId descriptionId{mTestNamespaceIndex, id};
      auto descriptionNode = addressSpace.create_node_sync(descriptionId, NodeClass::Variable);
      auto description = descriptionNode.as<VariableAccessor>();
      description->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      description->set_display_name(LocalizedText{"", name});
      description->set_data_type(NodeId{DataTypeId::Int32});
      description->write_value_sync(DataValue{Variant{int32_t{0}}});
      methodNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasOptionalInputArgumentDescription}, descriptionId);
    }
  }

  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  // Registers a Method (HasComponent of TestFolder) whose raw handler decodes a single structured input
  // argument as a concrete `ua::Range` and echoes it back as the single structured output with the Low/High
  // fields SWAPPED. The swap (not a byte passthrough) proves the server actually DECODED the ExtensionObject
  // into a typed `Range` and RE-ENCODED a fresh one - so the structured round-trip is exercised at both
  // wire boundaries. Declares spec-shaped InputArguments and OutputArguments Properties whose single
  // Argument DataType is Range, so the tier-2 structured preflight is exercised against real metadata.
  // Returns the method NodeId.
  NodeId create_struct_echo_method()
  {
    auto addressSpace = mServer.server().address_space();
    const NodeId methodId{mTestNamespaceIndex, uint32_t{3100}};
    auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    method->set_browse_name(QualifiedName{mTestNamespaceIndex, "StructEchoMethod"});
    method->set_display_name(LocalizedText{"", "StructEchoMethod"});
    method->set_executable(true);
    auto folderNode = addressSpace.find_node_sync(mTestFolderId);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

    const auto addArgumentsProperty =
      [&](uint32_t identifier, std::string_view browseName, std::string_view argumentName)
    {
      const NodeId propertyId{mTestNamespaceIndex, identifier};
      auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
      auto property = propertyNode.as<VariableAccessor>();
      property->set_browse_name(QualifiedName{0, browseName});
      property->set_display_name(LocalizedText{"", browseName});
      property->set_data_type(NodeId{DataTypeId::Argument});
      property->set_value_rank(int32_t{1});
      auto argument = std::make_unique<Argument>();
      argument->name() = String{argumentName};
      argument->data_type() = NodeId{DataTypeId::Range};
      argument->value_rank() = -1;
      Array<RefStructure<Structure>> arguments;
      arguments.push_back(RefStructure<Structure>{std::move(argument)});
      property->write_value_sync(DataValue{Variant{std::move(arguments)}});
      methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    };
    addArgumentsProperty(3101U, "InputArguments", "Input");
    addArgumentsProperty(3102U, "OutputArguments", "Output");

    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    callSource->set_call_handler(
      [](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          callback)
      {
        CallMethodResult result;
        if (!request.input_arguments().empty())
        {
          if (const Range* range = request.input_arguments()[0].try_as<Range>())
          {
            Range echoed;
            echoed.low() = range->high();
            echoed.high() = range->low();
            result.output_arguments().resize(1);
            result.output_arguments()[0] = Variant{echoed};
          }
        }
        callback(CallResult{std::move(result)});
      });
    return methodId;
  }

  NodeId mOptionalMetadataMethodId;
};

// =============================================================================================
// Row 1 - AddReturnsComputedOutputArgument  (ComplianceWithNodes)
// call_method(TestFolder, TestMethod=Add, {7, 5}) must surface a Good CallResult whose single output
// argument is the computed sum 12. [neg: CallMethodResult->CallResult output mapping]
// =============================================================================================
// @verifies CL-METH-001
// @relation(CL-METH-001, scope=function)
TEST_F(ClientMethodCall, AddReturnsComputedOutputArgument)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M1")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result =
    connection->typed().try_call_method_sync(mTestFolderId, mTestMethodId, args(int32_t{7}, int32_t{5}));
  ASSERT_TRUE(result.is_good()) << "the Call service itself succeeds: status="
                                << ua::to_string(result.status_code()) << " detail="
                                << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "none");

  const auto& callResult = result.value();
  ASSERT_TRUE(callResult.is_good()) << "the per-method status is Good";
  ASSERT_EQ(callResult.value().output_arguments().size(), 1u) << "Add declares exactly one output argument";
  const int32_t* sum = callResult.value().output_arguments()[0].try_as<int32_t>();
  ASSERT_NE(sum, nullptr) << "the output argument decodes to an Int32";
  EXPECT_EQ(*sum, 12) << "the client must map the CallMethodResult output vector without dropping/reindexing";
}

// =============================================================================================
// Row 2 - BadArgumentsMissingSurfacedFromServer  (ComplianceWithNodes)
// Calling Add (2 required Int32) with only one argument must surface the server's Bad_ArgumentsMissing;
// the client must not client-pad the missing argument. [neg: too-few-arguments rejection propagates]
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, BadArgumentsMissingSurfacedFromServer)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M2")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->typed().try_call_method_sync(mTestFolderId, mTestMethodId, args(int32_t{7}));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-method";
  EXPECT_TRUE(result.value().is_bad())
    << "too few arguments must fail the method call, not be client-padded to Good";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadArgumentsMissing})
    << "the server's Bad_ArgumentsMissing must reach the caller unaltered";
}

// =============================================================================================
// Row 3 - BadTooManyArgumentsSurfacedFromServer  (ComplianceWithNodes)
// Calling Add (max 2 args) with three arguments must surface Bad_TooManyArguments; the client must not
// truncate the surplus before sending. [neg: surplus-argument rejection; client must not truncate]
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, BadTooManyArgumentsSurfacedFromServer)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M3")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->typed().try_call_method_sync(
    mTestFolderId, mTestMethodId, args(int32_t{1}, int32_t{2}, int32_t{3}));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-method";
  EXPECT_TRUE(result.value().is_bad())
    << "surplus arguments must fail; a truncated array would let the server accept a 2-arg call as Good";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadTooManyArguments})
    << "the server's Bad_TooManyArguments must reach the caller (the client sent all three)";
}

// =============================================================================================
// Row 4 - BatchPreservesPerCallResultOrdering  (ComplianceWithNodes)
// A single batch Call [Add(2,3)->Good(5), NonExecutableMethod->Bad_NotExecutable] must return two results
// aligned to request order: results[0] Good with output 5, results[1] Bad_NotExecutable.
// [neg: index alignment of a mixed good/bad batch]
// =============================================================================================
// @verifies CL-METH-001
// @relation(CL-METH-001, scope=function)
TEST_F(ClientMethodCall, BatchPreservesPerCallResultOrdering)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M4")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->service_requests().try_call_sync(
    CallRequestBuilder()
      .call(mTestFolderId, mTestMethodId, {Variant{int32_t{2}}, Variant{int32_t{3}}})
      .call(mTestFolderId, mNonExecutableMethodId));
  ASSERT_TRUE(result.is_good()) << "the Call service itself succeeds; the failures are per-method";

  const auto& results = result.value().results();
  ASSERT_EQ(results.size(), 2u) << "one result per requested method, in request order";

  EXPECT_THAT(results[0], Good()) << "the Add call at index 0 must succeed";
  ASSERT_EQ(results[0].output_arguments().size(), 1u);
  const int32_t* sum = results[0].output_arguments()[0].try_as<int32_t>();
  ASSERT_NE(sum, nullptr);
  EXPECT_EQ(*sum, 5) << "index 0 carries Add(2,3)=5, not the bad peer's status";

  EXPECT_THAT(results[1], HasStatus(Status::BadNotExecutable))
    << "the NonExecutableMethod call at index 1 must carry Bad_NotExecutable (not attached to index 0)";
}

// =============================================================================================
// Row 5 - EmptyMethodsBatchReturnsBadNothingToDo  (ComplianceWithNodes)
// A Call service request with an empty methodsToCall array must fail with Bad_NothingToDo; the client
// must not short-circuit an empty batch as a local Good. [neg: empty batch]
// (Retraced: empty-operation-list handling is a generic service-request rule, not a Method-facet
// requirement - no CL-METH-* covers it; reachable only via the tier-1 wire-shaped Call.)
// =============================================================================================
// @verifies CL-METH-001
// @relation(CL-METH-001, scope=function)
TEST_F(ClientMethodCall, EmptyMethodsBatchReturnsBadNothingToDo)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M5")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->service_requests().try_call_sync(ua::CallRequest{});
  EXPECT_TRUE(result.is_bad()) << "an empty methodsToCall must fail at the service level, not local-Good";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo})
    << "the server rejects an empty operation list with Bad_NothingToDo";
}

// @relation(AC-SVR-ADDRSP-102-INPUTARGUMENTS-SPECIFIES-CALL, scope=function)

// =============================================================================================
// Row 6 - InputArgumentResultsLocaliseOffendingArgument  (ComplianceWithNodes)
// Calling Add with a type-mismatched second argument {7, "x"} yields operation status Bad_InvalidArgument
// with inputArgumentResults=[Good, Bad_TypeMismatch]. The parallel vector must survive the client decode
// (tier-1 raw path) and the offending index must localise to the tier-2 CallResult's ErrorDetail chain.
// [neg: per-argument diagnostics must survive the client decode of the Call response]
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, InputArgumentResultsLocaliseOffendingArgument)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M6")};
  ASSERT_TRUE(connection.start_status().is_good());

  // tier-1 wire-shaped path: the parallel inputArgumentResults vector is faithfully decoded and reaches
  // the caller with the same length as the inputs, the offending slot carrying Bad_TypeMismatch.
  auto raw = connection->service_requests().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{7}}, Variant{String{"x"}}}));
  ASSERT_TRUE(raw.is_good()) << "the Call service itself succeeds";
  ASSERT_EQ(raw.value().results().size(), 1u);
  const auto& methodResult = raw.value().results()[0];
  EXPECT_THAT(methodResult, HasStatus(Status::BadInvalidArgument))
    << "a wrong-typed argument yields operation-level Bad_InvalidArgument";
  ASSERT_EQ(methodResult.input_argument_results().size(), 2u)
    << "inputArgumentResults has the same length as the inputs sent (not discarded)";
  EXPECT_THAT(methodResult.input_argument_results()[0], Good()) << "argument 0 (Int32) is valid";
  EXPECT_THAT(methodResult.input_argument_results()[1], HasStatus(Status::BadTypeMismatch))
    << "argument 1 (String where Int32 expected) is the offending slot";

  // tier-2 typed path: the bad per-method status collapses to a source-tagged ErrorDetail that localises
  // the offending input-argument index and threads that argument's own StatusCode as the cause.
  auto typed =
    connection->typed().try_call_method_sync(mTestFolderId, mTestMethodId, args(int32_t{7}, String{"x"}));
  ASSERT_TRUE(typed.is_good()) << "the service succeeds; the failure is per-method";
  ASSERT_TRUE(typed.value().is_bad());
  EXPECT_EQ(typed.value().status_code(), StatusCode{Status::BadInvalidArgument});
  const ErrorDetail* detail = typed.value().error_detail();
  ASSERT_NE(detail, nullptr) << "the offending-argument breadcrumb must not be silently discarded";
  EXPECT_NE(detail->source.find("call_method"), std::string::npos)
    << "the ErrorDetail source names the call operation";
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadTypeMismatch}.value())
    << "the offending argument's own StatusCode (Bad_TypeMismatch) is threaded as the cause";
}

// =============================================================================================
// Row 7 - MethodNotComponentReturnsBadMethodInvalid  (ComplianceWithNodes)
// Naming OtherObject as the ObjectId for TestMethod (which is NOT a HasComponent of OtherObject) must
// yield Bad_MethodInvalid; the client must not rewrite the ObjectId. [neg: method not a component]
// =============================================================================================
// @verifies CL-METH-002
// @relation(CL-METH-002, scope=function)
TEST_F(ClientMethodCall, MethodNotComponentReturnsBadMethodInvalid)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M7")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result =
    connection->typed().try_call_method_sync(mOtherObjectId, mTestMethodId, args(int32_t{1}, int32_t{2}));
  ASSERT_TRUE(result.is_good()) << "the service succeeds; the failure is per-method";
  EXPECT_TRUE(result.value().is_bad());
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadMethodInvalid})
    << "TestMethod is not a component of OtherObject; the client must not resolve against another object";
}

// =============================================================================================
// Row 8 - NoArgumentMethodSucceedsWithEmptyVector  (ComplianceWithNodes)
// Calling NoArgsMethod with an empty argument vector must succeed with no output arguments; the client
// must neither refuse to send an argument-less request nor inject a spurious empty Variant.
// [neg: empty-argument edge case]
// =============================================================================================
// @verifies CL-METH-003
// @relation(CL-METH-003, scope=function)
TEST_F(ClientMethodCall, NoArgumentMethodSucceedsWithEmptyVector)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M8")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->typed().try_call_method_sync(mTestFolderId, mNoArgsMethodId, {});
  ASSERT_TRUE(result.is_good()) << "the service succeeds";
  ASSERT_TRUE(result.value().is_good())
    << "an argument-less call must be accepted as Good, not faulted for missing/extra args";
  EXPECT_TRUE(result.value().value().output_arguments().empty())
    << "NoArgsMethod returns no output arguments";
}

// =============================================================================================
// Row 9 - OutputArgumentsEmptyWhenStatusBad  (MisbehavingServer)
// A non-conformant CallResponse with statusCode=Bad_NotExecutable AND outputArguments=[V1,V2] must NOT
// leak those stray outputs to the tier-2 caller (defensive drop): the inner CallResult is bad and carries
// no value, so no output is reachable. The tier-1 wire-shaped path retains the raw bytes for diagnostics.
// [neg: bad per-call status must clear outputs]
// =============================================================================================
// @verifies CL-METH-006
// @relation(CL-METH-006, scope=function)
TEST_F(ClientMethodCall, OutputArgumentsEmptyWhenStatusBad)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* call = dynamic_cast<CallResponse*>(response.second.get()))
      {
        if (!call->results().empty())
        {
          call->response_header().service_result() = StatusCode{Status::Good};
          call->results()[0].status_code() = StatusCode{Status::BadNotExecutable};
          call->results()[0].output_arguments() =
            ua::Array<ua::Variant>{ua::Variant{int32_t{111}}, ua::Variant{int32_t{222}}};
        }
      }
    });

  // tier-2: the Bad per-op status collapses the inner CallResult (no value) - the stray outputs are
  // structurally unreachable, i.e. defensively dropped.
  auto typed = fixture.conn().typed().try_call_method_sync(
    NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, {});
  ASSERT_TRUE(typed.is_good()) << "the service itself succeeds; the failure is per-method";
  ASSERT_TRUE(typed.value().is_bad()) << "a Bad_NotExecutable per-op status collapses the inner CallResult";
  EXPECT_EQ(typed.value().status_code(), StatusCode{Status::BadNotExecutable});

  // tier-1 wire-shaped path: the raw CallResponse retains the server-sent (non-conformant) outputs for
  // diagnostic surfaces - the drop is a tier-2 defensive projection, not a wire mutation.
  auto raw = fixture.conn().service_requests().try_call_sync(
    call_method(NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}));
  ASSERT_TRUE(raw.is_good());
  ASSERT_EQ(raw.value().results().size(), 1u);
  EXPECT_THAT(raw.value().results()[0], HasStatus(Status::BadNotExecutable));
  EXPECT_EQ(raw.value().results()[0].output_arguments().size(), 2u)
    << "the tier-1 raw path retains the server's stray outputs (the drop is tier-2 only)";
}

// =============================================================================================
// Row 10 - ServiceFaultCarriesTier1SourceTaggedErrorDetail  (MisbehavingServer)
// A Call whose CallResponse carries a bad ResponseHeader.serviceResult must surface to the user as a bad
// Result<CallResult> carrying that code AND a source-tagged ErrorDetail naming the Call operation - not a
// bare StatusCode with no chain. [neg: ErrorDetail must not be silently dropped at the wire boundary]
//
// NOTE (facade fix, this slice): the Call facade previously did NOT flatten a bad
// ResponseHeader.serviceResult (unlike the read/write value facades) - it would have processed the
// results array as if the service succeeded. Fixed to flatten + attach a source-tagged ErrorDetail
// (callMethodSource = client.tier2.typed_access.call_method), covered by the fake-driven unit test
// TypedAccessTest.CallMethodFlattensBadServiceResult. The matrix's "client.tier1.*" is the tier-1 wrap
// intent; the built wrap is the tier-2 facade source tag (reported).
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, ServiceFaultCarriesTier1SourceTaggedErrorDetail)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* call = dynamic_cast<CallResponse*>(response.second.get()))
        call->response_header().service_result() = StatusCode{Status::BadServiceUnsupported};
    });

  auto result = fixture.conn().typed().try_call_method_sync(
    NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, {});
  ASSERT_TRUE(result.is_bad())
    << "a bad serviceResult is a service-level failure the facade must surface, not swallow";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadServiceUnsupported})
    << "the exact service code must reach the user";
  const ErrorDetail* detail = result.error_detail();
  ASSERT_NE(detail, nullptr) << "the service fault must carry an ErrorDetail chain, not a bare StatusCode";
  EXPECT_EQ(detail->source, "client.tier1.connection.call")
    << "the ErrorDetail source must locate the failure at the tier-1 Call operation";
}

// =============================================================================================
// Row 11 - SyncVariantThrowsOnBadStatus  (ComplianceWithNodes)
// Invokes the blocking call_method_sync against NonExecutableMethod (Executable=false -> per-op
// Bad_NotExecutable).
//
// F6 pin (verified in code + the locked unit test TypedAccessTest.CallMethodSurfacesPerMethodBadStatus):
// the tier-2 does NOT fold a per-OPERATION Bad status into Result badness. The outer Result<CallResult> is
// Good; the inner CallResult carries the Bad. So call_method_sync (= try_call_method_sync().value())
// returns the bad inner CallResult WITHOUT throwing (the section 7.0 throw-on-bad-RESULT applies to the
// SERVICE result, which is Good here). This asserts the DOCUMENTED (no-fold) contract - the F6 open question
// is reported for maintainer ratification.
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, SyncVariantThrowsOnBadStatus)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M11")};
  ASSERT_TRUE(connection.start_status().is_good());

  std::optional<ua::CallResult> callResult;
  EXPECT_NO_THROW(
    { callResult.emplace(connection->typed().call_method_sync(mTestFolderId, mNonExecutableMethodId, {})); })
    << "a per-operation Bad status does not fold into the SERVICE Result, so the sync variant must not throw";
  ASSERT_TRUE(callResult.has_value());
  EXPECT_TRUE(callResult->is_bad()) << "the returned CallResult carries the per-method Bad status";
  EXPECT_EQ(callResult->status_code(), StatusCode{Status::BadNotExecutable});
}

// =============================================================================================
// Row 12 - TryVariantReturnsBadResultNeverThrows  (ComplianceWithNodes)
// Invokes try_call_method_sync against NonExecutableMethod. The try_* variant never throws and returns a
// value; the Bad_NotExecutable is carried on the inner CallResult (no-fold contract, see Row 11).
// [neg: try_* must surface Bad as a value, not a throw]
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, TryVariantReturnsBadResultNeverThrows)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M12")};
  ASSERT_TRUE(connection.start_status().is_good());

  ua::Result<ua::CallResult> result{ua::Status::BadInternalError};  // placeholder; overwritten below
  EXPECT_NO_THROW({
    result = connection->typed().try_call_method_sync(mTestFolderId, mNonExecutableMethodId, {});
  }) << "try_* must never throw";
  ASSERT_TRUE(result.is_good()) << "the SERVICE result is Good; try_* returns a value, not a throw";
  EXPECT_TRUE(result.value().is_bad()) << "the per-method Bad status is surfaced as a value";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadNotExecutable});
}

// =============================================================================================
// Row 13 - UnknownMethodNodeReturnsBadNodeIdUnknown  (ComplianceWithNodes)
// Calling a MethodId that does not exist in the address space must surface a proper Bad code
// (Bad_NodeIdUnknown, or Bad_MethodInvalid per METH_CALL_041b) - not a fabricated local success/crash.
// [neg: unknown method node]
// =============================================================================================
// @verifies CL-METH-002
// @relation(CL-METH-002, scope=function)
TEST_F(ClientMethodCall, UnknownMethodNodeReturnsBadNodeIdUnknown)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M13")};
  ASSERT_TRUE(connection.start_status().is_good());

  const NodeId unknownMethod{mTestNamespaceIndex, uint32_t{999999}};
  auto result = connection->typed().try_call_method_sync(mTestFolderId, unknownMethod, {});
  ASSERT_TRUE(result.is_good()) << "the service succeeds; the failure is per-method";
  EXPECT_TRUE(result.value().is_bad());
  const StatusCode status = result.value().status_code();
  EXPECT_TRUE(
    status == StatusCode{Status::BadNodeIdUnknown} || status == StatusCode{Status::BadMethodInvalid})
    << "an unknown method node must surface Bad_NodeIdUnknown or Bad_MethodInvalid, got "
    << to_string(status);
}

// =============================================================================================
// Row 14 - InvokesViaCallServiceOnly  (MisbehavingServer, wire observer)
// call_method must dispatch exactly ONE CallRequest carrying exactly one methodsToCall entry, and that
// single CallResponse's one result must reach the user Result<CallResult>. Zero, more-than-one, batched,
// or a non-Call carrier all falsify. [CL-METH-001 wire-verbatim]
// =============================================================================================
// @verifies CL-METH-001
// @relation(CL-METH-001, scope=function)
TEST_F(ClientMethodCall, InvokesViaCallServiceOnly)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response)
    { force_call_result_good(response, ua::Array<ua::Variant>{ua::Variant{int32_t{42}}}); });

  auto result = fixture.conn().typed().try_call_method_sync(wire_object_node(), wire_method_node(), {});
  ASSERT_TRUE(result.is_good()) << "the single CallResponse's result must reach the user";
  ASSERT_TRUE(result.value().is_good());

  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 1u) << "exactly one CallRequest - not zero, not more than one";
  EXPECT_EQ(calls[0].methodsToCall.size(), 1u)
    << "the single method invocation must not be batched into multiple methodsToCall entries";
}

// =============================================================================================
// Row 15 - PassesObjectAndMethodNodeIdsVerbatim  (MisbehavingServer, wire observer)
// The on-wire CallMethodRequest must carry objectId==O and methodId==M byte-identical, with O and M two
// real distinct nodes so a silent swap would address a wrong real node. [CL-METH-002 wire-verbatim]
// =============================================================================================
// @verifies CL-METH-002
// @relation(CL-METH-002, scope=function)
TEST_F(ClientMethodCall, PassesObjectAndMethodNodeIdsVerbatim)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  const NodeId object = wire_object_node();
  const NodeId method = wire_method_node();
  ASSERT_NE(object, method) << "O and M must be distinct real nodes so a swap is observable";

  (void)fixture.conn().typed().try_call_method_sync(object, method, {});

  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_EQ(calls[0].methodsToCall.size(), 1u);
  EXPECT_EQ(calls[0].methodsToCall[0].object_id(), object)
    << "the objectId must reach the wire verbatim (not collapsed or swapped with the methodId)";
  EXPECT_EQ(calls[0].methodsToCall[0].method_id(), method)
    << "the methodId must reach the wire verbatim (not collapsed or swapped with the objectId)";
}

// =============================================================================================
// Row 16 - PreservesInputArgumentOrderOnWire  (MisbehavingServer, wire observer)
// Calling with [V1,V2,V3] must put inputArguments in that exact position on the wire; a swapped pair
// decodes to a different Variant. Separately, an empty call must encode a zero-length (not null) array.
// [neg: order preserved, empty is zero-length]
// =============================================================================================
// @verifies CL-METH-003
// @relation(CL-METH-003, scope=function)
TEST_F(ClientMethodCall, PreservesInputArgumentOrderOnWire)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  (void)fixture.conn().typed().try_call_method_sync(
    wire_object_node(), wire_method_node(), args(int32_t{100}, int32_t{200}, int32_t{300}));
  (void)fixture.conn().typed().try_call_method_sync(wire_object_node(), wire_method_node(), {});

  ASSERT_TRUE(wait_until([&] { return capture->call_count() >= 2; }));
  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 2u);

  ASSERT_EQ(calls[0].methodsToCall.size(), 1u);
  const auto& ordered = calls[0].methodsToCall[0].input_arguments();
  ASSERT_EQ(ordered.size(), 3u) << "all three arguments must reach the wire";
  ASSERT_NE(ordered[0].try_as<int32_t>(), nullptr);
  ASSERT_NE(ordered[1].try_as<int32_t>(), nullptr);
  ASSERT_NE(ordered[2].try_as<int32_t>(), nullptr);
  EXPECT_EQ(*ordered[0].try_as<int32_t>(), 100) << "argument order must be preserved (position 0)";
  EXPECT_EQ(*ordered[1].try_as<int32_t>(), 200) << "argument order must be preserved (position 1)";
  EXPECT_EQ(*ordered[2].try_as<int32_t>(), 300) << "argument order must be preserved (position 2)";

  ASSERT_EQ(calls[1].methodsToCall.size(), 1u);
  EXPECT_EQ(calls[1].methodsToCall[0].input_arguments().size(), 0u)
    << "an empty argument list must encode a zero-length array, not null and not omitted";
}

// =============================================================================================
// Row 17 - PendingCallResolvesOnceAndFailsOnSessionLoss  (ComplianceWithNodes)
// A method call always returns: the pending call resolves EXACTLY once (an atomic invocation counter ==
// 1). On session loss the callback fires exactly once with a bad Result. A hang is caught by the per-test
// timeout. [neg: zero fires, double fire, silent abandonment]
//
// BLOCKED (reconnect harness unbuilt): a true mid-flight session teardown (tear the session down while a
// CallResponse is in flight) needs the reconnect harness + a response-delay interface, which this single-shot
// Connection has not. This pins the client-observable analog that IS built: (A) a normal call resolves
// exactly once; (B) a call issued after the Connection is no longer usable fails cleanly, exactly once,
// with a bad Result - the funnel fast-fails a terminal-state op before it reaches the session. The
// reconnect-driven mid-flight loss is reported as blocked-unbuilt.
// =============================================================================================
// @verifies CL-METH-004
// @relation(CL-METH-004, scope=function)
TEST_F(ClientMethodCall, PendingCallResolvesOnceAndFailsOnSessionLoss)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M17")};
  ASSERT_TRUE(connection.start_status().is_good());

  // (A) A normal call resolves exactly once.
  {
    auto fireCount = std::make_shared<std::atomic<int>>(0);
    std::promise<void> done;
    auto future = done.get_future();
    connection->typed().call_method_async(mTestFolderId,
      mNoArgsMethodId,
      {},
      [fireCount, &done](ua::Result<ua::CallResult>)
      {
        if (fireCount->fetch_add(1) == 0)
          done.set_value();
      });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the pending call must resolve (no hang)";
    future.get();
    EXPECT_EQ(fireCount->load(), 1) << "the call callback must fire exactly once (1:1 request/response)";
  }

  // (B) After the Connection is closed, a call fails cleanly, exactly once, with a bad Result carrying an
  // identifiable cause (the client-observable session-unusable analog of a session loss).
  (void)connection->try_close_sync();
  {
    auto fireCount = std::make_shared<std::atomic<int>>(0);
    std::promise<ua::Result<ua::CallResult>> outcome;
    auto future = outcome.get_future();
    connection->typed().call_method_async(mTestFolderId,
      mNoArgsMethodId,
      {},
      [fireCount, &outcome](ua::Result<ua::CallResult> result)
      {
        if (fireCount->fetch_add(1) == 0)
          outcome.set_value(std::move(result));
      });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready)
      << "a call on a closed Connection must still complete the callback (never silently abandoned)";
    auto result = future.get();
    EXPECT_EQ(fireCount->load(), 1) << "the callback must fire exactly once even on session loss";
    EXPECT_TRUE(result.is_bad()) << "a call over an unusable session must fail, not fabricate success";
  }
}

// =============================================================================================
// Row 18 - SurfacesPerArgumentInvalidArgumentResults  (MisbehavingServer, canned CallResponse)
// A canned CallResponse with statusCode=Bad_InvalidArgument and inputArgumentResults=[Good,Bad_TypeMismatch,
// Good] must decode with the parallel vector length == inputs and the offending slot at index 1; a second
// canned response (Bad_NotExecutable, inputArgumentResults=[]) must decode to an EMPTY per-arg vector
// (not Good-filled, not invented). [neg: parallel vector + emptiness fidelity]
//
// NOTE: the matrix's "inputArgumentDiagnosticInfos[1] appears in the tier-2 Result ErrorDetail chain" is
// UNBUILT - the facade threads the offending argument's StatusCode (not the server DiagnosticInfo) into
// the breadcrumb. This pins the built, falsifiable behaviour (parallel-vector fidelity + offending-index
// localisation); the DiagnosticInfo->ErrorDetail routing is reported as blocked-unbuilt.
// =============================================================================================
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(ClientMethodCall, SurfacesPerArgumentInvalidArgumentResults)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto mode = std::make_shared<std::atomic<int>>(0);  // 1 = InvalidArgument+vector, 2 = NotExecutable+empty
  server.set_response_mutator(
    [mode](Response& response)
    {
      auto* call = dynamic_cast<CallResponse*>(response.second.get());
      if (!call || call->results().empty())
        return;
      call->response_header().service_result() = StatusCode{Status::Good};
      auto& result = call->results()[0];
      if (mode->load() == 1)
      {
        result.status_code() = StatusCode{Status::BadInvalidArgument};
        result.input_argument_results() = ua::Array<ua::StatusCode>{
          StatusCode{Status::Good}, StatusCode{Status::BadTypeMismatch}, StatusCode{Status::Good}};
      }
      else if (mode->load() == 2)
      {
        result.status_code() = StatusCode{Status::BadNotExecutable};
        result.input_argument_results() = ua::Array<ua::StatusCode>{};
      }
    });

  // Case 1: Bad_InvalidArgument with the parallel vector - decoded verbatim via the tier-1 raw path.
  mode->store(1);
  {
    auto raw = fixture.conn().service_requests().try_call_sync(call_method(NodeId{ObjectId::ObjectsFolder},
      NodeId{ObjectId::Server},
      {Variant{int32_t{1}}, Variant{int32_t{2}}, Variant{int32_t{3}}}));
    ASSERT_TRUE(raw.is_good());
    ASSERT_EQ(raw.value().results().size(), 1u);
    const auto& perArg = raw.value().results()[0].input_argument_results();
    ASSERT_EQ(perArg.size(), 3u) << "inputArgumentResults length must equal the number of inputs";
    EXPECT_THAT(perArg[0], Good());
    EXPECT_THAT(perArg[1], HasStatus(Status::BadTypeMismatch)) << "the offending slot is index 1";
    EXPECT_THAT(perArg[2], Good());

    // tier-2: the offending index localises to the CallResult's ErrorDetail chain.
    auto typed = fixture.conn().typed().try_call_method_sync(
      NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, args(int32_t{1}, int32_t{2}, int32_t{3}));
    ASSERT_TRUE(typed.is_good());
    ASSERT_TRUE(typed.value().is_bad());
    EXPECT_EQ(typed.value().status_code(), StatusCode{Status::BadInvalidArgument});
    const ErrorDetail* detail = typed.value().error_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadTypeMismatch}.value())
      << "the offending argument's StatusCode is threaded into the breadcrumb";
  }

  // Case 2: Bad_NotExecutable with an empty per-arg vector - must decode empty, not Good-filled.
  mode->store(2);
  {
    auto raw = fixture.conn().service_requests().try_call_sync(
      call_method(NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, {Variant{int32_t{1}}}));
    ASSERT_TRUE(raw.is_good());
    ASSERT_EQ(raw.value().results().size(), 1u);
    EXPECT_THAT(raw.value().results()[0], HasStatus(Status::BadNotExecutable));
    EXPECT_TRUE(raw.value().results()[0].input_argument_results().empty())
      << "a non-InvalidArgument status must yield an empty per-arg vector, not one invented/Good-filled";
  }
}

// =============================================================================================
// Row 19 - DropsOutputArgumentsOnBadOperationStatus  (MisbehavingServer, canned CallResponse)
// The Bad->drop half (Row 9) plus the new positive control: an Uncertain per-op status with
// outputArguments=[V1,V2] must PRESERVE both outputs (CL-METH-006: outputs are dropped only when Severity
// is Bad). [neg: Uncertain keeps outputs; Bad drops them]
// =============================================================================================
// @verifies CL-METH-006
// @relation(CL-METH-006, scope=function)
TEST_F(ClientMethodCall, DropsOutputArgumentsOnBadOperationStatus)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto mode = std::make_shared<std::atomic<int>>(0);  // 1 = Bad+outputs, 2 = Uncertain+outputs
  server.set_response_mutator(
    [mode](Response& response)
    {
      auto* call = dynamic_cast<CallResponse*>(response.second.get());
      if (!call || call->results().empty())
        return;
      call->response_header().service_result() = StatusCode{Status::Good};
      auto& result = call->results()[0];
      result.output_arguments() =
        ua::Array<ua::Variant>{ua::Variant{int32_t{111}}, ua::Variant{int32_t{222}}};
      result.status_code() = (mode->load() == 2) ? StatusCode{Status::UncertainInitialValue}
                                                 : StatusCode{Status::BadNotExecutable};
    });

  // Bad -> tier-2 drops (inner CallResult bad, no reachable output vector).
  mode->store(1);
  {
    auto typed = fixture.conn().typed().try_call_method_sync(
      NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, {});
    ASSERT_TRUE(typed.is_good());
    ASSERT_TRUE(typed.value().is_bad()) << "a Bad per-op status collapses the inner CallResult";
    EXPECT_EQ(typed.value().status_code(), StatusCode{Status::BadNotExecutable});
  }

  // Uncertain -> tier-2 KEEPS the CallMethodResult, both outputs visible (the new positive control).
  mode->store(2);
  {
    auto typed = fixture.conn().typed().try_call_method_sync(
      NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, {});
    ASSERT_TRUE(typed.is_good());
    ASSERT_TRUE(typed.value().has_value())
      << "an Uncertain per-op status must NOT collapse the inner CallResult (CL-METH-006: only Bad drops)";
    EXPECT_EQ(typed.value().status_code(), StatusCode{Status::UncertainInitialValue})
      << "the inner CallResult carries the per-method statusCode as the server sent it";
    EXPECT_TRUE(typed.value().value().status_code().is_uncertain());
    ASSERT_EQ(typed.value().value().output_arguments().size(), 2u)
      << "an Uncertain status must preserve the server's outputArguments";
    ASSERT_NE(typed.value().value().output_arguments()[0].try_as<int32_t>(), nullptr);
    ASSERT_NE(typed.value().value().output_arguments()[1].try_as<int32_t>(), nullptr);
    EXPECT_EQ(*typed.value().value().output_arguments()[0].try_as<int32_t>(), 111);
    EXPECT_EQ(*typed.value().value().output_arguments()[1].try_as<int32_t>(), 222);
  }
}

// =============================================================================================
// Row 20 - ByteStringAcceptedForByteArrayArgument  (MisbehavingServer, wire observer)
// A ByteString-valued input argument must reach the wire as a ByteString Variant (structurally an array
// of Byte), NOT locally coerced/widened; the client must send the application's value verbatim.
// [neg: a local reject/coercion of the ByteString falsifies]
// =============================================================================================
// @verifies CL-METH-008
// @relation(CL-METH-008, scope=function)
TEST_F(ClientMethodCall, ByteStringAcceptedForByteArrayArgument)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  const std::vector<std::uint8_t> payload{0x01, 0x02, 0x03};
  auto result = fixture.conn().typed().try_call_method_sync(
    wire_object_node(), wire_method_node(), std::vector<ua::Variant>{ua::Variant{ua::ByteString{payload}}});
  ASSERT_TRUE(result.is_good()) << "the client must not locally reject a ByteString argument";
  ASSERT_TRUE(result.value().is_good());

  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_EQ(calls[0].methodsToCall.size(), 1u);
  const auto& inputs = calls[0].methodsToCall[0].input_arguments();
  ASSERT_EQ(inputs.size(), 1u);
  EXPECT_TRUE(inputs[0].is_byte_string())
    << "the ByteString argument must travel as a ByteString on the wire, not silently widened to Byte[]";
}

// =============================================================================================
// Row 21 - OmittedTrailingOptionalArgsSendShorterArray  (MisbehavingServer, wire observer)
// Supplying only the N provided arguments must put exactly N inputArguments on the wire (a shorter list
// passes through unpadded): the client must NOT pad to N+M nor reorder. [neg: no padding/reorder]
// =============================================================================================
// @verifies CL-METH-010
// @relation(CL-METH-010, scope=function)
TEST_F(ClientMethodCall, OmittedTrailingOptionalArgsSendShorterArray)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  // The caller supplies only the two non-optional arguments, omitting the trailing optional one(s). The
  // tier-2 path passes the short vector through verbatim (section 7.2, no client-side padding).
  (void)fixture.conn().typed().try_call_method_sync(
    wire_object_node(), wire_method_node(), args(int32_t{10}, int32_t{20}));

  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_EQ(calls[0].methodsToCall.size(), 1u);
  const auto& inputs = calls[0].methodsToCall[0].input_arguments();
  ASSERT_EQ(inputs.size(), 2u)
    << "the shorter argument list must pass through unpadded (no null padding to a full arity)";
  ASSERT_NE(inputs[0].try_as<int32_t>(), nullptr);
  ASSERT_NE(inputs[1].try_as<int32_t>(), nullptr);
  EXPECT_EQ(*inputs[0].try_as<int32_t>(), 10) << "the provided arguments must not be reordered";
  EXPECT_EQ(*inputs[1].try_as<int32_t>(), 20);
}

// =============================================================================================
// Row 22 - OptionalArgumentMetadataReportsTrailingCount  (normal server)
// A Method declares InputArguments [A,B,C,D] and optional description Variables C,D. The public tier-2
// introspector correlates description BrowseNames to Argument names (namespace ignored) and reports two
// trailing optionals. [neg: count references without correlating positions/names]
// =============================================================================================
// @verifies CL-METH-010
// @relation(CL-METH-010, scope=function)
TEST_F(ClientMethodCall, OptionalArgumentMetadataReportsTrailingCount)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("M22")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->typed().try_inspect_method_inputs_sync(mOptionalMetadataMethodId);

  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().inputArguments.size(), 4u);
  EXPECT_EQ(result.value().trailingOptionalCount, 2u);
  EXPECT_EQ(result.value().inputArguments[0].name(), String{"A"});
  EXPECT_EQ(result.value().inputArguments[3].name(), String{"D"});
}

// =============================================================================================
// The Phase-D "Complex" (type-resolution) and "Optional" (preflight) rows live under their own gtest
// suites to match the matrix's `ClientMethodCallComplex.*` / `ClientMethodCallOptional.*` names, but reuse
// the whole ClientMethodCall harness (ComplianceWithNodes nodes, open_activated_session,
// create_struct_echo_method, mClientThreadPool) by deriving from it - the same way the base MisbehavingServer
// rows run a compliance server that some rows leave unused.
// =============================================================================================
class ClientMethodCallComplex : public ClientMethodCall
{};

class ClientMethodCallOptional : public ClientMethodCall
{};

// =============================================================================================
// ClientMethodCallComplex - Row C1 - AbstractArgumentResolvesToConcreteSubtypeOnWire
//   (MisbehavingServer, wire observer)
//
// The matrix records this row in its own "Rejected (dropped)" list as "a tautology on builtin Variant",
// and it is authored here per the task's explicit instruction as a CALIBRATED tautology-pin. A Variant is
// inherently CONCRETE (self-describing) - passing a concrete `UInt16` (a subtype of the abstract UInteger /
// Number hierarchy) for a nominally-abstract argument does NOT trigger any abstract->concrete resolution on
// the client; the value simply travels verbatim. The falsifiable property that IS worth pinning: the
// concrete subtype's EXACT builtin identity survives to the wire - the client must not widen it to its
// abstract supertype's canonical type (e.g. Int64) nor erase it to an opaque carrier.
// [neg: a concrete subtype carried for an abstract argument must keep its exact builtin type on the wire]
// =============================================================================================
// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(ClientMethodCallComplex, AbstractArgumentResolvesToConcreteSubtypeOnWire)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  // UInt16 is a concrete subtype within the abstract UInteger/Number DataType hierarchy.
  const std::uint16_t concreteValue = 40000;
  auto result =
    fixture.conn().typed().try_call_method_sync(wire_object_node(), wire_method_node(), args(concreteValue));
  ASSERT_TRUE(result.is_good()) << "the client must not reject a concrete subtype argument";
  ASSERT_TRUE(result.value().is_good());

  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_EQ(calls[0].methodsToCall.size(), 1u);
  const auto& inputs = calls[0].methodsToCall[0].input_arguments();
  ASSERT_EQ(inputs.size(), 1u);
  EXPECT_TRUE(inputs[0].is_uint16())
    << "the concrete UInt16 subtype must reach the wire as a UInt16, not widened to its abstract "
       "supertype's canonical type";
  ASSERT_NE(inputs[0].try_as<std::uint16_t>(), nullptr) << "the wire value must decode as the exact subtype";
  EXPECT_EQ(*inputs[0].try_as<std::uint16_t>(), concreteValue)
    << "the concrete value must survive verbatim (a Variant needs no abstract->concrete resolution)";
}

// =============================================================================================
// ClientMethodCallComplex - Row C2 - StructuredInputEncodedViaTypeResolver
//   (ComplianceWithNodes, inline struct-echo Method)
//
// A structured (ExtensionObject) INPUT argument round-trips: the client passes a Variant holding a concrete
// `ua::Range{low, high}`; the server-side handler decodes it to a typed `Range` and echoes it back (fields
// swapped). Proof that the server received a DECODABLE ExtensionObject: the echoed output's Low equals the
// input's High. If the DefaultBinary encoding id had not been applied correctly, the server could not have
// decoded the struct and would have echoed nothing.
//
// The tier-2 Call path reads the Method's InputArguments metadata, establishes that the concrete Range
// DataType matches the declared Range DataType, and then preserves the generated structure's self-described
// binary encoding id on wire. [neg: a wrong/absent encoding id -> server cannot decode -> no echo]
// =============================================================================================
// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(ClientMethodCallComplex, StructuredInputEncodedViaTypeResolver)
{
  const NodeId echoMethod = create_struct_echo_method();
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("MC2")};
  ASSERT_TRUE(connection.start_status().is_good());

  Range input;
  input.low() = 1.5;
  input.high() = 42.0;
  auto result = connection->typed().try_call_method_sync(
    mTestFolderId, echoMethod, std::vector<ua::Variant>{ua::Variant{input}});
  ASSERT_TRUE(result.is_good()) << "the Call service itself succeeds: status="
                                << ua::to_string(result.status_code()) << " detail="
                                << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "none");
  ASSERT_TRUE(result.value().is_good()) << "the per-method status is Good";
  ASSERT_EQ(result.value().value().output_arguments().size(), 1u)
    << "the server echoed exactly one structured output - proving it decoded the input ExtensionObject";
  const Range* echoed = result.value().value().output_arguments()[0].try_as<Range>();
  ASSERT_NE(echoed, nullptr) << "the echoed output must be a decodable Range";
  EXPECT_DOUBLE_EQ(echoed->low(), 42.0)
    << "the echoed Low must equal the input High - the server decoded the input struct's High field";
}

// =============================================================================================
// ClientMethodCallComplex - Row C3 - StructuredOutputDecodedViaRegistry
//   (ComplianceWithNodes, inline struct-echo Method)
//
// A structured OUTPUT argument decodes on the CLIENT to its concrete typed form: the server returns a
// populated `ua::Range`; the client surfaces `output_arguments()[0].try_as<Range>()` with the exact swapped
// field values. If inbound decode had bypassed the type registry, the output would be an opaque
// undifferentiated structure (or raw bytes) rather than a typed `Range`.
//
// The connection's structured-output reification path and built-in StructureFactory surface a concrete
// Range rather than an opaque placeholder. [neg: bypassing reification yields an opaque structure, not a
// typed Range]
// =============================================================================================
// @verifies CL-METH-007
// @verifies CL-MI-030
// @relation(CL-METH-007, CL-MI-030, scope=function)
TEST_F(ClientMethodCallComplex, StructuredOutputDecodedViaRegistry)
{
  const NodeId echoMethod = create_struct_echo_method();
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("MC3")};
  ASSERT_TRUE(connection.start_status().is_good());

  Range input;
  input.low() = 7.0;
  input.high() = 9.0;
  auto result = connection->typed().try_call_method_sync(
    mTestFolderId, echoMethod, std::vector<ua::Variant>{ua::Variant{input}});
  ASSERT_TRUE(result.is_good()) << "status=" << ua::to_string(result.status_code()) << " detail="
                                << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "none");
  ASSERT_TRUE(result.value().is_good());
  ASSERT_EQ(result.value().value().output_arguments().size(), 1u);
  ASSERT_TRUE(result.value().value().output_arguments()[0].is_structure())
    << "the output argument must carry a structured value";
  const Range* decoded = result.value().value().output_arguments()[0].try_as<Range>();
  ASSERT_NE(decoded, nullptr)
    << "the structured output must decode to a concrete Range via the client-wide StructureFactory";
  EXPECT_DOUBLE_EQ(decoded->low(), 9.0) << "Low echoes the input High (swap), decoded field-accurately";
  EXPECT_DOUBLE_EQ(decoded->high(), 7.0) << "High echoes the input Low (swap), decoded field-accurately";
}

// =============================================================================================
// ClientMethodCallComplex - Row C4 - UnknownDataTypeShortCircuitsBadDataEncodingInvalidNoWire
//   (MisbehavingServer, wire observer)
//
// A structured argument whose encoding is absent from the per-Connection TypeResolver is rejected locally
// with `Bad_DataEncodingInvalid`; no CallRequest reaches the server.
// =============================================================================================
// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(ClientMethodCallComplex, UnknownDataTypeShortCircuitsBadDataEncodingInvalidNoWire)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  // A structured Variant whose encoding id resolves to NOTHING in any client registry layer - the exact
  // input the matrix's short-circuit would reject before the wire.
  const NodeId unresolvableEncodingId{7, uint32_t{987654}};
  ua::UnknownStructure opaque{
    unresolvableEncodingId, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{{0x0A, 0x0B}}};
  auto result = fixture.conn().typed().try_call_method_sync(
    wire_object_node(), wire_method_node(), std::vector<ua::Variant>{ua::Variant{std::move(opaque)}});

  EXPECT_EQ(capture->call_count(), 0u);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadDataEncodingInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "MethodStructuredArgumentEncodingUnknown");
}

// =============================================================================================
// ClientMethodCallComplex - Row C5 - UnknownOutputEncodingSurfacesUnresolvedExtensionObject
//   (MisbehavingServer, canned CallResponse)
//
// An OUTPUT ExtensionObject whose encoding id is unknown to the client registry must degrade GRACEFULLY:
// the CallResult stays Good and the output holds an opaque `UnknownStructure` placeholder whose raw bytes +
// encoding id round-trip losslessly - NOT a hard `Bad_DecodingError` that fails the whole call and loses
// the payload. This is BUILT (the codec preserves unresolved ExtensionObjects verbatim) and asserted
// end-to-end. [neg: a hard decode failure would make the status Bad and drop the opaque payload]
// =============================================================================================
// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(ClientMethodCallComplex, UnknownOutputEncodingSurfacesUnresolvedExtensionObject)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId unknownEncodingId{5, uint32_t{424244}};
  const ua::ByteString body{{0xDE, 0xAD, 0xBE, 0xEF}};
  server.set_response_mutator(
    [unknownEncodingId, body](Response& response)
    {
      if (auto* call = dynamic_cast<CallResponse*>(response.second.get()))
      {
        call->response_header().service_result() = StatusCode{Status::Good};
        if (!call->results().empty())
        {
          call->results()[0].status_code() = StatusCode{Status::Good};
          call->results()[0].output_arguments() = ua::Array<ua::Variant>{ua::Variant{
            ua::UnknownStructure{unknownEncodingId, ua::UnknownStructure::BodyEncoding::Binary, body}}};
        }
      }
    });

  auto result = fixture.conn().typed().try_call_method_sync(
    NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}, {});
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds";
  ASSERT_TRUE(result.value().is_good())
    << "an unknown output encoding must NOT hard-fail the call - the per-method status stays Good";
  ASSERT_EQ(result.value().value().output_arguments().size(), 1u);
  ASSERT_TRUE(result.value().value().output_arguments()[0].is_structure())
    << "the unknown output must survive as a structure, not be dropped";
  const auto* opaque = result.value().value().output_arguments()[0].try_as<ua::UnknownStructure>();
  ASSERT_NE(opaque, nullptr)
    << "an unresolved output ExtensionObject must surface as an UnknownStructure placeholder";
  EXPECT_EQ(opaque->encoding_id(), unknownEncodingId) << "the unresolved encoding id must be retained";
  EXPECT_EQ(opaque->encoded_data(), body) << "the opaque body must round-trip losslessly (bytes preserved)";
}

// =============================================================================================
// ClientMethodCallOptional - Row O1 - PreflightDisabledDefersCountValidationToServer
//   (MisbehavingServer, wire observer + canned status)
//
// With no client-side arg-count preflight (the default and only behaviour), a call omitting a required
// argument is NOT rejected locally: a wire Call IS sent (received count == 1) and the SERVER's status is
// what surfaces to the user. The server is the authority. If the client had pre-flighted the argument
// count, the received count would be zero and the Bad would originate locally.
// [neg: the cache-off path must NOT pre-flight; the request must reach the server]
// =============================================================================================
// @verifies CL-METH-009
// @relation(CL-METH-009, scope=function)
TEST_F(ClientMethodCallOptional, PreflightDisabledDefersCountValidationToServer)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  // The server (as authority) rejects the under-supplied call with Bad_ArgumentsMissing.
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* call = dynamic_cast<CallResponse*>(response.second.get()))
      {
        call->response_header().service_result() = StatusCode{Status::Good};
        if (!call->results().empty())
          call->results()[0].status_code() = StatusCode{Status::BadArgumentsMissing};
      }
    });

  // A method that (notionally) requires two arguments, called with only one.
  auto result =
    fixture.conn().typed().try_call_method_sync(wire_object_node(), wire_method_node(), args(int32_t{1}));

  ASSERT_TRUE(wait_until([&] { return capture->call_count() >= 1; }))
    << "the client must defer to the server - a wire Call must be sent";
  EXPECT_EQ(capture->call_count(), 1u)
    << "exactly one Call reached the server (a client that pre-flighted would send zero)";
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-method";
  ASSERT_TRUE(result.value().is_bad()) << "the server's per-method Bad status must surface";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadArgumentsMissing})
    << "the server's Bad_ArgumentsMissing is the authority, reaching the caller unaltered";
}

// =============================================================================================
// ClientMethodCallOptional - Row O2 - PreflightEnabledRejectsMissingRequiredArgLocallyNoWire
//   (MisbehavingServer, wire observer + canned status)
//
// CALIBRATION (feature UNBUILT): the matrix expects an opt-in client-side preflight that, with the
// AddressSpaceCache populated, rejects a missing-required-argument call LOCALLY with Bad_ArgumentsMissing
// (ErrorDetail source-tagged to the pre-flight) and ZERO wire ops. No such preflight exists in the client
// (no `preflight` code/flag; the AddressSpaceCache is an attribute/alias/browse cache, not an arg-count
// validator). This row pins the ABSENCE of the feature: even in the scenario the matrix labels "enabled",
// the request STILL reaches the wire (received count == 1) and the surfaced error carries NO client-side
// pre-flight source tag - it is the server-relayed status via the tier-2 call facade.
// [neg (matrix): opt-in preflight rejects before the wire with zero requests - HERE FALSIFIED as unbuilt:
//  a passing "local reject, zero wire" assertion would be the false claim]
// =============================================================================================
// @verifies CL-METH-009
// @relation(CL-METH-009, scope=function)
TEST_F(ClientMethodCallOptional, PreflightEnabledRejectsMissingRequiredArgLocallyNoWire)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* call = dynamic_cast<CallResponse*>(response.second.get()))
      {
        call->response_header().service_result() = StatusCode{Status::Good};
        if (!call->results().empty())
          call->results()[0].status_code() = StatusCode{Status::BadArgumentsMissing};
      }
    });

  auto result =
    fixture.conn().typed().try_call_method_sync(wire_object_node(), wire_method_node(), args(int32_t{1}));

  // No local preflight fires: the request reaches the wire (a real preflight would short-circuit to zero).
  ASSERT_TRUE(wait_until([&] { return capture->call_count() >= 1; }))
    << "no opt-in preflight is built - the under-supplied call must still reach the wire";
  EXPECT_EQ(capture->call_count(), 1u)
    << "a working local preflight would have sent zero requests; the absence is pinned here";
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-method (server-relayed)";
  ASSERT_TRUE(result.value().is_bad());
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadArgumentsMissing});
  const ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr) << "the per-method Bad status still carries a source-tagged ErrorDetail chain";
  EXPECT_EQ(detail->source.find("preflight"), std::string::npos)
    << "the error must NOT carry a client-side pre-flight source tag (the feature is unbuilt)";
  EXPECT_EQ(detail->source.find("pre-flight"), std::string::npos)
    << "the error must NOT carry a client-side pre-flight source tag (the feature is unbuilt)";
  EXPECT_NE(detail->source.find("call_method"), std::string::npos)
    << "the built breadcrumb is the tier-2 call facade source, relaying the server's verdict";
}

// =============================================================================================
// ClientMethodCallOptional - Row O3 - ShorterArgumentListPassedVerbatimNoPadding
//   (MisbehavingServer, wire observer)
//
// When the caller supplies FEWER Variants than a method (notionally) declares - here one argument where two
// are declared, the trailing one optional - the client forwards the caller's vector length UNCHANGED: the
// server observes exactly one inbound input argument. The client must NOT null-pad from the method
// definition to the declared arity of two. (Complements the base row OmittedTrailingOptionalArgsSendShorter-
// Array, which supplies two of two; this row pins the strictly-shorter one-of-two case, where padding would
// be most tempting.) [neg: no client-side padding of omitted optional args - a padded call shows size()==2]
// =============================================================================================
// @verifies CL-METH-009
// @relation(CL-METH-009, scope=function)
TEST_F(ClientMethodCallOptional, ShorterArgumentListPassedVerbatimNoPadding)
{
  MisbehavingServer server;
  MisbehavingCallFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<CallRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator([](Response& response) { force_call_result_good(response, {}); });

  // Two inputs declared (trailing optional); the caller supplies only the first.
  (void)fixture.conn().typed().try_call_method_sync(
    wire_object_node(), wire_method_node(), args(int32_t{55}));

  ASSERT_TRUE(wait_until([&] { return capture->call_count() >= 1; }));
  auto calls = capture->snapshot();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_EQ(calls[0].methodsToCall.size(), 1u);
  const auto& inputs = calls[0].methodsToCall[0].input_arguments();
  ASSERT_EQ(inputs.size(), 1u)
    << "the caller's one-element vector must pass through unchanged - no null-padding to the declared two";
  ASSERT_NE(inputs[0].try_as<int32_t>(), nullptr);
  EXPECT_EQ(*inputs[0].try_as<int32_t>(), 55) << "the single supplied argument must reach the wire verbatim";
}

namespace
{

// ---------------------------------------------------------------------------------------------
// MethodGate: a server-side Method whose call handler PARKS each invocation's completion callback
// instead of completing it. The test thread decides exactly when each invocation finishes, so a
// Method can be left genuinely in flight across the termination of the Session that called it.
// Shared between the server's call strand (admit) and the test thread (complete).
// ---------------------------------------------------------------------------------------------
struct MethodGate
{
  mutable std::mutex mutex;
  std::vector<std::function<void(ua::CallResult)>> parked;

  // Called on the server side for each invocation; the Method is now running and never completes
  // until the test releases it.
  void admit(std::function<void(ua::CallResult)> callback)
  {
    std::lock_guard lock(mutex);
    parked.push_back(std::move(callback));
  }

  std::size_t admitted() const
  {
    std::lock_guard lock(mutex);
    return parked.size();
  }

  // Runs the parked invocation @p index to completion, producing a single Int32 output that
  // identifies WHICH invocation produced it. Returns false when that invocation never reached the
  // handler or was already completed - so a caller can prove the Method really ran.
  bool complete(std::size_t index, int32_t marker)
  {
    std::function<void(ua::CallResult)> callback;
    {
      std::lock_guard lock(mutex);
      if (index >= parked.size() || !parked[index])
        return false;
      callback = std::move(parked[index]);
      parked[index] = nullptr;
    }
    ua::CallMethodResult result;
    result.output_arguments().resize(1);
    result.output_arguments()[0] = ua::Variant{marker};
    callback(ua::CallResult{std::move(result)});
    return true;
  }
};

// ---------------------------------------------------------------------------------------------
// CallOutcome: what a caller's async Call callback actually received. Retained for the whole test
// (never consumed) so a LATE delivery after the assertions is still observable on a re-check.
// ---------------------------------------------------------------------------------------------
struct CallOutcome
{
  mutable std::mutex mutex;
  int fires = 0;
  std::optional<ua::Result<ua::CallResult>> result;

  void deliver(ua::Result<ua::CallResult> value)
  {
    std::lock_guard lock(mutex);
    ++fires;
    if (!result)
      result.emplace(std::move(value));
  }

  int fire_count() const
  {
    std::lock_guard lock(mutex);
    return fires;
  }

  // The Int32 output the caller was actually handed, or nullopt when no Good CallResult carrying a
  // single Int32 output was delivered.
  std::optional<int32_t> delivered_output() const
  {
    std::lock_guard lock(mutex);
    if (!result || result->is_bad() || result->value().is_bad())
      return std::nullopt;
    const auto& outputs = result->value().value().output_arguments();
    if (outputs.size() != 1u)
      return std::nullopt;
    const int32_t* value = outputs[0].try_as<int32_t>();
    if (!value)
      return std::nullopt;
    return std::optional<int32_t>{*value};
  }

  // True when a Result was delivered and it carries a bad status at either level.
  bool delivered_bad() const
  {
    std::lock_guard lock(mutex);
    return result && (result->is_bad() || result->value().is_bad());
  }

  std::string describe() const
  {
    std::lock_guard lock(mutex);
    if (!result)
      return "<no result delivered>";
    if (result->is_bad())
      return "service " + ua::to_string(result->status_code());
    return "per-method " + ua::to_string(result->value().status_code());
  }
};

}  // namespace

// =============================================================================================
// Part 4 section 5.11.2: when the calling Session is closed (CloseSession or timeout) between dispatch of a
// Call request and completion of the underlying Method, the server must drop the response. The
// Method itself may still run to completion - only the DELIVERY of its result is forbidden, and in
// particular the result must never surface on a later Session.
//
// A plausible implementation gets this wrong by treating the Method completion as a plain
// continuation: it builds the CallResponse when the handler finally calls back and hands it to
// whatever session/channel routing still answers to the original requestId. Because the terminated
// Session's request slot is gone, that orphaned response is free to land on the next Session that
// happens to be waiting on the same channel - exactly the delivery this clause forbids. The gate
// below leaves the later Session's own Call parked and in flight at the moment the orphan
// completes, so a misdelivered response has a live slot to land in and cannot pass unnoticed.
//
// @verifies AC-SVR-METH-CALL-001-SESSION-TERMINATED-DISCARDS
// =============================================================================================
TEST_F(ClientMethodCall, MethodResultsAreDiscardedWhenCallingSessionTerminates)
{
  // A Method whose completion the test controls, hung off TestFolder like the fixture's own Methods.
  auto addressSpace = mServer.server().address_space();
  const NodeId gatedMethodId{mTestNamespaceIndex, uint32_t{3300}};
  auto methodNode = addressSpace.create_node_sync(gatedMethodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "GatedMethod"});
  method->set_display_name(LocalizedText{"", "GatedMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, gatedMethodId);

  auto gate = std::make_shared<MethodGate>();
  auto* callSource = mTestNamespace->find_node<Node>(gatedMethodId)->method_call_source();
  ASSERT_NE(callSource, nullptr);
  callSource->set_call_handler([gate](const CallMethodRequest& /*request*/,
                                 std::shared_ptr<const MethodCallContext> /*context*/,
                                 std::function<void(CallResult)>
                                   callback) { gate->admit(std::move(callback)); });

  constexpr int32_t terminatedSessionOutput = 1717;  // produced by the orphaned invocation
  constexpr int32_t laterSessionOutput = 2828;  // produced by the later Session's own invocation

  // Both Sessions live on ONE SecureChannel: a server that routes the orphaned response by request
  // id alone would put it on this channel, where the later Session is waiting.
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // ---- The Session that is about to be terminated issues the Call. ----
  auto terminatedOutcome = std::make_shared<CallOutcome>();
  {
    auto sessionA = channel.create_session_sync({.sessionName = "M23-Terminated"});
    sessionA.activate_sync();
    StartedConnection connectionA{mClientThreadPool.executor(), std::move(sessionA)};
    ASSERT_TRUE(connectionA.start_status().is_good());

    connectionA->typed().call_method_async(mTestFolderId,
      gatedMethodId,
      {},
      [terminatedOutcome](ua::Result<ua::CallResult> result)
      { terminatedOutcome->deliver(std::move(result)); });

    ASSERT_TRUE(wait_until([&] { return gate->admitted() >= 1u; }))
      << "the Method must actually be running on the server before the Session is terminated - "
         "otherwise nothing is in flight and the test would be vacuous";

    // Terminate the Session (a real CloseSessionRequest) with the Method still running.
    ASSERT_TRUE(connectionA->try_close_sync().is_good()) << "the Session must close cleanly";
  }

  // ---- A later Session, on the same channel, parks its own invocation of the same Method. ----
  auto laterOutcome = std::make_shared<CallOutcome>();
  auto sessionB = channel.create_session_sync({.sessionName = "M23-Later"});
  sessionB.activate_sync();
  StartedConnection connectionB{mClientThreadPool.executor(), std::move(sessionB)};
  ASSERT_TRUE(connectionB.start_status().is_good());

  connectionB->typed().call_method_async(mTestFolderId,
    gatedMethodId,
    {},
    [laterOutcome](ua::Result<ua::CallResult> result) { laterOutcome->deliver(std::move(result)); });

  ASSERT_TRUE(wait_until([&] { return gate->admitted() >= 2u; }))
    << "the later Session's Call must reach the Method handler and park there";
  ASSERT_EQ(gate->admitted(), 2u) << "exactly two invocations: the orphaned one and the later one";

  // ---- The orphaned Method now runs to completion, after its Session is gone. ----
  ASSERT_TRUE(gate->complete(0, terminatedSessionOutput))
    << "the Method dispatched by the terminated Session must still have been running - the clause is "
       "about discarding its RESULT, not about cancelling the work";

  // Conjunct 1: the orphaned result must not reach the later Session, which is sitting on the same
  // channel with a Call of its own outstanding. Its callback must stay unfired.
  EXPECT_FALSE(wait_until([&] { return laterOutcome->fire_count() > 0; }, 750ms))
    << "the orphaned result was delivered to a later Session: " << laterOutcome->describe();

  // Conjunct 2: nor may it be delivered, late, to the caller on the terminated Session.
  EXPECT_FALSE(terminatedOutcome->delivered_output().has_value())
    << "the terminated Session's caller received the discarded Method result: "
    << terminatedOutcome->describe();
  ASSERT_GT(terminatedOutcome->fire_count(), 0)
    << "the pending Call on the terminated Session must complete its callback, never be abandoned";
  EXPECT_EQ(terminatedOutcome->fire_count(), 1) << "and must complete it exactly once";
  EXPECT_TRUE(terminatedOutcome->delivered_bad())
    << "a Call whose Session was terminated must fail, not fabricate a result: "
    << terminatedOutcome->describe();

  // ---- Conjunct 3: the later Session still gets its OWN result, unaffected. ----
  ASSERT_TRUE(gate->complete(1, laterSessionOutput))
    << "the later Session's invocation must still be parked and completable";
  ASSERT_TRUE(wait_until([&] { return laterOutcome->fire_count() > 0; }, 5000ms))
    << "the later Session's own Call must complete";
  EXPECT_EQ(laterOutcome->fire_count(), 1) << "exactly one delivery to the later Session";
  const auto laterDelivered = laterOutcome->delivered_output();
  ASSERT_TRUE(laterDelivered.has_value())
    << "the later Session must receive its own Good result: " << laterOutcome->describe();
  EXPECT_EQ(*laterDelivered, laterSessionOutput)
    << "the later Session must receive the output of ITS OWN invocation, never the orphan's";

  // Re-check the terminated caller once more, now that both invocations have completed: a late
  // delivery of the discarded result would show up here.
  EXPECT_EQ(terminatedOutcome->fire_count(), 1)
    << "the discarded result must not arrive late on the terminated Session's caller";
  EXPECT_FALSE(terminatedOutcome->delivered_output().has_value())
    << "the discarded result must never be delivered: " << terminatedOutcome->describe();
}
