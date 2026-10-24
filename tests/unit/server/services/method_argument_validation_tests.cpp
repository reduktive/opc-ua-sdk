// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// clang-format off
#include <gtest/gtest.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "ua_address_space.h"
#include "ua_argument.h"
#include "ua_array.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_method_node.h"
#include "ua_default_namespace.h"
#include "ua_diagnostic_bits.h"
#include "ua_error_detail.h"
#include "ua_method_argument_validation.h"
#include "ua_method_response_correlation.h"
#include "ua_method_service_set.h"
#include "ua_node.h"
#include "ua_object_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_value_rank.h"
#include "ua_variant.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_namespace.h"
#include "fake_node.h"
#include "node_holding_namespace.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// --- Test helper: invoke MethodServiceSet and wait for result ------
struct CallTestResult
{
  CallResponse response;
  bool completed{false};
};

CallTestResult invoke_call_service(
  shared_ptr<SessionInfo> sessionInfo, CallRequest request, boost::asio::any_io_executor executor,
  optional<MethodResponseCorrelation> responseCorrelation = std::nullopt)
{
  std::condition_variable cv;
  std::mutex mtx;
  CallTestResult testResult;

  auto service = MethodServiceSet::create(sessionInfo,
    std::vector<LocaleId>{LocaleId{"en"}},
    0,
    std::move(request),
    executor,
    [&cv, &mtx, &testResult](Response response)
    {
      auto* callResponse = dynamic_cast<CallResponse*>(std::get<shared_ptr<Structure>>(response).get());
      std::lock_guard lock(mtx);
      if (callResponse)
      {
        testResult.response = std::move(*callResponse);
        testResult.completed = true;
      }
      cv.notify_all();
    },
    responseCorrelation);

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 2s, [&testResult] { return testResult.completed; });
  return testResult;
}

// Build an Argument structure (name / data type / value rank) for an InputArguments Property.
Argument make_argument(string_view name, DataTypeId dataType, int32_t valueRank = ValueRank::scalar)
{
  Argument argument;
  argument.name() = String{name};
  argument.data_type() = NodeId{dataType};
  argument.value_rank() = valueRank;
  return argument;
}

// Fixture: a server + plain namespace holding an Object, a Method with a RAW call handler that
// records invocation, and (optionally) an InputArguments Property of declared arguments. This is
// the default per-item Call path with NO MethodAdapter, so the service is the only thing that can
// validate input arguments against the model.
class MethodArgumentValidationFixture
{
public:
  explicit MethodArgumentValidationFixture(boost::asio::thread_pool& threadPool)
    : mExecutor(threadPool.get_executor())
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = ServerConfig{}};
    auto server = Server::create(mExecutor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

    mNamespace = default_ns::Namespace::create("uri://method-validation-ns", mExecutor);
    mNamespaceIndex = server.address_space().add_namespace_sync(mNamespace);

    // The AddressSpace is a shared handle over the server's internal state; it stays valid after
    // the Server is moved into the SessionInfoStub, so the fixture keeps it for node setup.
    mAddressSpace = server.address_space();
    auto& addressSpace = *mAddressSpace;

    // Object: ns=mNamespaceIndex;i=2000 under the Objects folder.
    mObjectId = NodeId{mNamespaceIndex, uint32_t{2000}};
    auto objectNode = addressSpace.create_node_sync(mObjectId, NodeClass::Object);
    auto object = objectNode.as<ObjectAccessor>();
    object->set_browse_name(QualifiedName{mNamespaceIndex, "ValidationObject"});
    object->set_display_name(LocalizedText{"", "ValidationObject"});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mObjectId);

    // Method: ns=mNamespaceIndex;i=3000 on the Object (HasComponent).
    mMethodId = NodeId{mNamespaceIndex, uint32_t{3000}};
    auto methodNode = addressSpace.create_node_sync(mMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    method->set_browse_name(QualifiedName{mNamespaceIndex, "ValidationMethod"});
    method->set_display_name(LocalizedText{"", "ValidationMethod"});
    method->set_executable(true);
    objectNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMethodId);

    // RAW call handler (no MethodAdapter): records invocation and returns Good. Validation here
    // can only come from the service reading the model, never from the handler.
    auto* callSource = mNamespace->find_node<Node>(mMethodId)->method_call_source();
    auto handlerInvoked = mHandlerInvoked;
    auto callContext = mCallContext;
    callSource->set_call_handler(
      [handlerInvoked, callContext](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> context,
        std::function<void(CallResult)> callback)
      {
        *handlerInvoked = true;
        *callContext = std::move(context);
        CallMethodResult result;
        result.status_code() = Status::Good;
        callback(CallResult{std::move(result)});
      });

    mServer.emplace(std::move(server));
  }

  // Attach an InputArguments Property (Variable, BrowseName "InputArguments") to the Method,
  // declaring `arguments` as its value. Mirrors how the address-space surfaces an Argument array.
  void attach_input_arguments(const std::vector<Argument>& arguments)
  {
    auto& addressSpace = *mAddressSpace;
    NodeId inputArgsId{mNamespaceIndex, uint32_t{3001}};
    auto inputArgsNode = addressSpace.create_node_sync(inputArgsId, NodeClass::Variable);
    auto inputArgs = inputArgsNode.as<VariableAccessor>();
    inputArgs->set_browse_name(QualifiedName{0, "InputArguments"});
    inputArgs->set_display_name(LocalizedText{"", "InputArguments"});
    inputArgs->set_data_type(NodeId{DataTypeId::Argument});
    // The InputArguments Property is a one-dimensional array of Argument (ValueRank = 1).
    inputArgs->set_value_rank(int32_t{1});

    Array<RefStructure<Structure>> elements;
    elements.resize(arguments.size());
    for (size_t i = 0; i < arguments.size(); ++i)
    {
      elements[i] = RefStructure<Structure>{std::make_unique<Argument>(arguments[i])};
    }
    // Wrap in an explicit DataValue so the DataValue overload of write_value_sync is selected
    // unambiguously (the templated T overload would otherwise be a candidate for Variant).
    inputArgs->write_value_sync(DataValue{Variant{std::move(elements)}});

    auto methodNode = addressSpace.find_node_sync(mMethodId);
    methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, inputArgsId);
  }

  void attach_optional_input_argument_description(string_view argumentName)
  {
    auto& addressSpace = *mAddressSpace;
    const NodeId descriptionId{mNamespaceIndex, uint32_t{3002}};
    auto descriptionNode = addressSpace.create_node_sync(descriptionId, NodeClass::Variable);
    auto description = descriptionNode.as<VariableAccessor>();
    description->set_browse_name(QualifiedName{mNamespaceIndex, argumentName});
    description->set_display_name(LocalizedText{"", argumentName});
    description->set_data_type(NodeId{DataTypeId::Int32});
    description->set_value_rank(ValueRank::scalar);
    description->write_value_sync(DataValue{Variant{int32_t{0}}});
    descriptionNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});

    auto methodNode = addressSpace.find_node_sync(mMethodId);
    methodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasOptionalInputArgumentDescription}, descriptionId);
  }

  shared_ptr<SessionInfo> make_session()
  {
    // Server is move-only; hand ownership to the session stub. The fixture keeps mAddressSpace
    // (a shared handle) so node accessors stay valid for the duration of the test.
    return make_shared<SessionInfoStub>(std::move(*mServer), mExecutor);
  }

  CallRequest make_call_request(std::vector<Variant> inputArguments)
  {
    return make_call_request_for_object(mObjectId, std::move(inputArguments));
  }

  CallRequest make_call_request_for_object(NodeId objectId, std::vector<Variant> inputArguments)
  {
    CallRequest callRequest;
    callRequest.methods_to_call().resize(1);
    callRequest.methods_to_call()[0].object_id() = std::move(objectId);
    callRequest.methods_to_call()[0].method_id() = mMethodId;
    callRequest.methods_to_call()[0].input_arguments().payload() = std::move(inputArguments);
    return callRequest;
  }

  CallRequest make_unknown_object_call_request()
  {
    return make_call_request_for_object(NodeId{mNamespaceIndex, uint32_t{999999}}, {});
  }

  // Create an ObjectType node and build a CallRequest that invokes mMethodId with the ObjectType as the
  // ObjectId. A Method that is a component of an ObjectType is a Method *declaration* (a template), not an
  // executable instance, so an ObjectType ObjectId is not a valid target. Call before make_session().
  CallRequest make_object_type_object_id_request()
  {
    NodeId typeId{mNamespaceIndex, uint32_t{4000}};
    auto typeNode = mAddressSpace->create_node_sync(typeId, NodeClass::ObjectType);
    typeNode.set_browse_name(QualifiedName{mNamespaceIndex, "ValidationObjectType"});
    typeNode.set_display_name(LocalizedText{"", "ValidationObjectType"});

    CallRequest callRequest;
    callRequest.methods_to_call().resize(1);
    callRequest.methods_to_call()[0].object_id() = typeId;
    callRequest.methods_to_call()[0].method_id() = mMethodId;
    return callRequest;
  }

  // Create an ObjectType that SOURCES a Method via HasComponent (like ConditionType sources
  // ConditionRefresh) plus a recording handler, and build a CallRequest invoking that Method with the
  // ObjectType as the ObjectId. Per Part 4 section 5.11.2 this is VALID and must reach the handler - it must NOT
  // be rejected as Bad_NodeIdInvalid. Call before make_session().
  CallRequest make_type_sourced_method_request()
  {
    auto& addressSpace = *mAddressSpace;
    NodeId typeId{mNamespaceIndex, uint32_t{4100}};
    auto typeNode = addressSpace.create_node_sync(typeId, NodeClass::ObjectType);
    typeNode.set_browse_name(QualifiedName{mNamespaceIndex, "SourcingObjectType"});
    typeNode.set_display_name(LocalizedText{"", "SourcingObjectType"});

    NodeId methodId{mNamespaceIndex, uint32_t{4101}};
    auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    method->set_browse_name(QualifiedName{mNamespaceIndex, "TypeSourcedMethod"});
    method->set_display_name(LocalizedText{"", "TypeSourcedMethod"});
    method->set_executable(true);
    typeNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

    auto* callSource = mNamespace->find_node<Node>(methodId)->method_call_source();
    auto handlerInvoked = mHandlerInvoked;
    callSource->set_call_handler(
      [handlerInvoked](const CallMethodRequest&, std::shared_ptr<const MethodCallContext>,
        std::function<void(CallResult)> callback)
      {
        *handlerInvoked = true;
        CallMethodResult result;
        result.status_code() = Status::Good;
        callback(CallResult{std::move(result)});
      });

    CallRequest callRequest;
    callRequest.methods_to_call().resize(1);
    callRequest.methods_to_call()[0].object_id() = typeId;
    callRequest.methods_to_call()[0].method_id() = methodId;
    return callRequest;
  }

  CallRequest make_object_instance_declared_method_request(bool declaredOnType,
    const shared_ptr<std::atomic_uint32_t>& invocationCount, uint32_t outputValue)
  {
    auto& addressSpace = *mAddressSpace;
    const NodeId typeId{mNamespaceIndex, uint32_t{4200}};
    const NodeId objectId{mNamespaceIndex, uint32_t{4201}};
    const NodeId methodId{mNamespaceIndex, uint32_t{4202}};

    auto typeNode = addressSpace.create_node_sync(typeId, NodeClass::ObjectType);
    typeNode.set_browse_name(QualifiedName{mNamespaceIndex, "DeclaredMethodType"});
    typeNode.set_display_name(LocalizedText{"", "DeclaredMethodType"});

    auto objectNode = addressSpace.create_node_sync(objectId, NodeClass::Object);
    objectNode.set_browse_name(QualifiedName{mNamespaceIndex, "DeclaredMethodObject"});
    objectNode.set_display_name(LocalizedText{"", "DeclaredMethodObject"});
    objectNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeId);

    auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    method->set_browse_name(QualifiedName{mNamespaceIndex, "DeclaredMethod"});
    method->set_display_name(LocalizedText{"", "DeclaredMethod"});
    method->set_executable(true);
    (declaredOnType ? typeNode : objectNode)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

    auto* callSource = mNamespace->find_node<Node>(methodId)->method_call_source();
    callSource->set_call_handler(
      [invocationCount, outputValue](const CallMethodRequest&, shared_ptr<const MethodCallContext>,
        std::function<void(CallResult)> callback)
      {
        ++*invocationCount;
        CallMethodResult result;
        result.status_code() = Status::Good;
        result.output_arguments().push_back(Variant{outputValue});
        callback(CallResult{std::move(result)});
      });

    CallRequest request;
    request.methods_to_call().resize(1);
    request.methods_to_call()[0].object_id() = objectId;
    request.methods_to_call()[0].method_id() = methodId;
    return request;
  }

  void set_handler_result(StatusCode status, std::vector<StatusCode> inputArgumentResults,
    std::vector<Variant> outputArguments = {})
  {
    auto* callSource = mNamespace->find_node<Node>(mMethodId)->method_call_source();
    auto handlerInvoked = mHandlerInvoked;
    callSource->set_call_handler(
      [handlerInvoked,
        status = std::move(status),
        inputArgumentResults = std::move(inputArgumentResults),
        outputArguments = std::move(outputArguments)](const CallMethodRequest&,
        shared_ptr<const MethodCallContext>,
        std::function<void(CallResult)> callback)
      {
        *handlerInvoked = true;
        CallMethodResult result;
        result.status_code() = status;
        result.input_argument_results().resize(inputArgumentResults.size());
        for (size_t index = 0; index < inputArgumentResults.size(); ++index)
          result.input_argument_results()[index] = inputArgumentResults[index];
        for (auto& output : outputArguments)
          result.output_arguments().push_back(std::move(output));
        callback(CallResult{std::move(result)});
      });
  }

  bool handler_invoked() const { return *mHandlerInvoked; }
  void reset_handler_invoked() { *mHandlerInvoked = false; }
  shared_ptr<const MethodCallContext> call_context() const { return *mCallContext; }

private:
  boost::asio::any_io_executor mExecutor;
  shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mNamespaceIndex{0};
  NodeId mObjectId;
  NodeId mMethodId;
  std::shared_ptr<std::atomic_bool> mHandlerInvoked{std::make_shared<std::atomic_bool>(false)};
  shared_ptr<shared_ptr<const MethodCallContext>> mCallContext{
    std::make_shared<shared_ptr<const MethodCallContext>>()};
  std::optional<AddressSpace> mAddressSpace;
  std::optional<Server> mServer;
};

}  // namespace

// --- Sync-core validation tests (validate_input_arguments) ------------------

// Spec: OPC 10000-4 section 5.11.2 - supplying fewer than the declared (required) inputs -> Bad_ArgumentsMissing.
TEST(MethodArgumentValidationCore, TooFewArgumentsIsArgumentsMissing)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("a", DataTypeId::Int32));
  expected.payload().push_back(make_argument("b", DataTypeId::Int32));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{int32_t{1}});

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::BadArgumentsMissing});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadArgumentsMissing});
  // No per-argument diagnostics for a count mismatch.
  EXPECT_TRUE(result.input_argument_results().payload().empty());
}

// Spec: OPC 10000-4 section 5.11.2 - supplying more than the declared inputs -> Bad_TooManyArguments.
TEST(MethodArgumentValidationCore, TooManyArgumentsIsTooManyArguments)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("a", DataTypeId::Int32));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{int32_t{1}});
  request.input_arguments().payload().push_back(Variant{int32_t{2}});

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::BadTooManyArguments});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyArguments});
  EXPECT_TRUE(result.input_argument_results().payload().empty());
}

// Spec: OPC 10000-4 section 5.11.2 - a wrong-typed argument -> Bad_InvalidArgument with the per-argument
// inputArgumentResults sized to the declared count and Bad_TypeMismatch at the offending index.
TEST(MethodArgumentValidationCore, WrongTypeIsInvalidArgumentWithPerArgResult)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("a", DataTypeId::Int32));
  expected.payload().push_back(make_argument("b", DataTypeId::Int32));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{String{"not-an-int"}});  // wrong: String
  request.input_arguments().payload().push_back(Variant{int32_t{2}});            // ok: Int32

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::BadInvalidArgument});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_EQ(result.input_argument_results().size(), 2u);
  EXPECT_EQ(result.input_argument_results()[0], StatusCode{Status::BadTypeMismatch});
  EXPECT_EQ(result.input_argument_results()[1], StatusCode{Status::Good});
}

// Spec: OPC 10000-4 section 5.11.2 - correctly-typed, correctly-counted arguments -> Good, no per-arg
// diagnostics carried.
TEST(MethodArgumentValidationCore, MatchingArgumentsAreGood)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("a", DataTypeId::Int32));
  expected.payload().push_back(make_argument("b", DataTypeId::Int32));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{int32_t{1}});
  request.input_arguments().payload().push_back(Variant{int32_t{2}});

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::Good});
  EXPECT_TRUE(result.input_argument_results().payload().empty());
}

// Abstract supertype acceptance: an Integer-typed declaration accepts any concrete integer.
TEST(MethodArgumentValidationCore, AbstractIntegerAcceptsConcreteInteger)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("n", DataTypeId::Integer));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{int32_t{7}});

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::Good});
}

// A concrete named subtype of a built-in (Duration is a subtype of Double; IntegerId of UInt32)
// arrives on the wire as its built-in encoding, so a Double/UInt32-carrying value satisfies a
// Duration/IntegerId-declared argument. The model layer cannot resolve the subtype's built-in root
// here, so it accepts and defers precise checking to the handler. Regression guard for condition
// methods like TimedShelve(ShelvingTime : Duration) and ConditionRefresh(SubscriptionId :
// IntegerId), which must not be rejected by model validation.
TEST(MethodArgumentValidationCore, NamedSubtypeOfBuiltInAcceptsBuiltInEncodedValue)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("shelvingTime", DataTypeId::Duration));
  expected.payload().push_back(make_argument("subscriptionId", DataTypeId::IntegerId));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{double{5000.0}});  // Duration -> Double
  request.input_arguments().payload().push_back(Variant{uint32_t{42}});    // IntegerId -> UInt32

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::Good});
  EXPECT_TRUE(result.input_argument_results().payload().empty());
}

// A Null/empty supplied value is a valid Variant state (an omitted optional input or a
// BaseDataType input passed as Null, e.g. GenerateFileForRead's GenerateOptions, called as
// `{Variant{}}`). Model validation must accept it - whether Null is acceptable is the handler's
// decision. A Null Variant is neither scalar nor array, so this also guards the rank-check order.
TEST(MethodArgumentValidationCore, NullSuppliedValueIsAccepted)
{
  Array<Argument> expected;
  expected.payload().push_back(make_argument("generateOptions", DataTypeId::BaseDataType));

  CallMethodRequest request;
  request.input_arguments().payload().push_back(Variant{});  // Null

  CallMethodResult result;
  EXPECT_EQ(validate_input_arguments(expected, request, result), StatusCode{Status::Good});
  EXPECT_TRUE(result.input_argument_results().payload().empty());
}

// --- End-to-end service tests (default per-item Call path) ------------------

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(MethodArgumentValidationService, CarriesPrivateResponseCorrelationToMethodHandler)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto sessionInfo = fixture.make_session();
  const MethodResponseCorrelation correlation{17, 41};

  auto result = invoke_call_service(sessionInfo,
    fixture.make_call_request({}),
    threadPool.get_executor(),
    correlation);

  ASSERT_TRUE(result.completed);
  ASSERT_TRUE(fixture.handler_invoked());
  ASSERT_NE(fixture.call_context(), nullptr);
  auto observed = ua::detail::MethodCallContextInternalAccess::response_correlation(*fixture.call_context());
  ASSERT_TRUE(observed.has_value());
  EXPECT_EQ(*observed, correlation);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// RED-first: a Method with an InputArguments Property of two Int32 args, called with only one
// argument, must be rejected with Bad_ArgumentsMissing and the raw handler must NOT run.
TEST(MethodArgumentValidationService, FewerArgsRejectedHandlerNotInvoked)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments(
    {make_argument("a", DataTypeId::Int32), make_argument("b", DataTypeId::Int32)});

  auto sessionInfo = fixture.make_session();
  auto request = fixture.make_call_request({Variant{int32_t{1}}});
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::BadArgumentsMissing});
  EXPECT_FALSE(fixture.handler_invoked());
  // Count mismatch carries no per-argument diagnostics.
  EXPECT_TRUE(result.response.results()[0].input_argument_results().payload().empty());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// OPC 10000-4 section 5.11.2.2 and section 5.11.2.4 permit omission only of trailing inputs explicitly
// described by HasOptionalInputArgumentDescription. The paired required-input call prevents an
// implementation from accepting every short list.
// @relation(AC-SVR-METH-CALL-014-OPTIONAL-ARGUMENTS-OMITTED, scope=function)
TEST(MethodArgumentValidationService, OptionalTrailingArgumentCanBeOmittedButRequiredArgumentCannot)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments(
    {make_argument("Required", DataTypeId::Int32), make_argument("Optional", DataTypeId::Int32)});
  fixture.attach_optional_input_argument_description("Optional");

  auto sessionInfo = fixture.make_session();
  auto optionalTailOmitted = invoke_call_service(sessionInfo,
    fixture.make_call_request({Variant{int32_t{1}}}),
    threadPool.get_executor());

  ASSERT_TRUE(optionalTailOmitted.completed);
  ASSERT_EQ(optionalTailOmitted.response.results().size(), 1u);
  EXPECT_EQ(optionalTailOmitted.response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(fixture.handler_invoked());

  fixture.reset_handler_invoked();
  auto requiredArgumentOmitted = invoke_call_service(
    sessionInfo, fixture.make_call_request({}), threadPool.get_executor());

  ASSERT_TRUE(requiredArgumentOmitted.completed);
  ASSERT_EQ(requiredArgumentOmitted.response.results().size(), 1u);
  EXPECT_EQ(
    requiredArgumentOmitted.response.results()[0].status_code(), StatusCode{Status::BadArgumentsMissing});
  EXPECT_FALSE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.11.2.4 plus the common StatusCode definitions distinguish malformed ObjectIds from
// well-formed identifiers that name no Node. The Method body must not run for either refusal.
// @relation(AC-SVR-METH-CALL-040-BAD-NODEIDINVALID, scope=function)
TEST(MethodArgumentValidationService, NullAndStructurallyInvalidObjectIdsReturnRichBadNodeIdInvalid)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto sessionInfo = fixture.make_session();

  const std::vector<NodeId> invalidObjectIds{
    NodeId{}, NodeId{uint16_t{0}, String{""}}, NodeId{uint16_t{1}, String{std::string(4097, 'x')}}};
  for (const auto& objectId : invalidObjectIds)
  {
    fixture.reset_handler_invoked();
    auto invalid = invoke_call_service(sessionInfo,
      fixture.make_call_request_for_object(objectId, {}),
      threadPool.get_executor());

    ASSERT_TRUE(invalid.completed);
    ASSERT_EQ(invalid.response.results().size(), 1u);
    const auto& status = invalid.response.results()[0].status_code();
    EXPECT_EQ(status.as_status(), Status::BadNodeIdInvalid);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "MethodObjectIdInvalid");
    EXPECT_FALSE(fixture.handler_invoked());
  }

  fixture.reset_handler_invoked();
  auto unknown = invoke_call_service(
    sessionInfo, fixture.make_unknown_object_call_request(), threadPool.get_executor());
  ASSERT_TRUE(unknown.completed);
  ASSERT_EQ(unknown.response.results().size(), 1u);
  EXPECT_EQ(unknown.response.results()[0].status_code().as_status(), Status::BadNodeIdUnknown);
  EXPECT_FALSE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// RED-first: too many arguments -> Bad_TooManyArguments, handler not invoked.
TEST(MethodArgumentValidationService, MoreArgsRejectedHandlerNotInvoked)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments(
    {make_argument("a", DataTypeId::Int32), make_argument("b", DataTypeId::Int32)});

  auto sessionInfo = fixture.make_session();
  auto request = fixture.make_call_request(
    {Variant{int32_t{1}}, Variant{int32_t{2}}, Variant{int32_t{3}}});
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::BadTooManyArguments});
  EXPECT_FALSE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A Method cannot be invoked on an ObjectType node (a Method that is a component of a type is a
// declaration, not an executable instance). validate_object_id must report Bad_NodeIdInvalid for the
// operation (outer CallResult stays Good) and the handler must NOT run. This is the OPC 10000-9
// section 5.5.6/section 5.7.3/section 5.7.4 requirement that a Condition Method called with the ConditionType Node as the
// ObjectId returns Bad_NodeIdInvalid (overriding the generic Part-4 Bad_MethodInvalid).
TEST(MethodArgumentValidationService, ObjectTypeObjectIdRejectedWithBadNodeIdInvalid)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto request = fixture.make_object_type_object_id_request();

  auto sessionInfo = fixture.make_session();
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::BadNodeIdInvalid});
  EXPECT_FALSE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Regression guard: a Method that the ObjectType SOURCES (HasComponent) IS invocable with the ObjectType
// as the ObjectId (Part 4 section 5.11.2) - this is exactly how the UACTT invokes ConditionRefresh/ConditionRefresh2
// on the ConditionType Node. The type-node rejection must NOT break this: the call must reach the handler.
TEST(MethodArgumentValidationService, TypeSourcedMethodOnObjectTypeReachesHandler)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto request = fixture.make_type_sourced_method_request();

  auto sessionInfo = fixture.make_session();
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::Good})
    << "A Method the ObjectType sources (HasComponent) must be invocable on the type (e.g. ConditionRefresh "
       "on ConditionType) and reach the handler, not be rejected as Bad_NodeIdInvalid";
  EXPECT_TRUE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-METH-CALL-013-TYPE-DECLARED-METHOD, scope=function)
TEST(MethodArgumentValidationService, TypeDeclaredMethodOnObjectInstanceReachesHandler)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto invocationCount = std::make_shared<std::atomic_uint32_t>(0U);
  auto request = fixture.make_object_instance_declared_method_request(true, invocationCount, 0xA13U);

  auto sessionInfo = fixture.make_session();
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1U);
  ASSERT_EQ(result.response.results()[0].status_code(), StatusCode{Status::Good});
  ASSERT_EQ(result.response.results()[0].output_arguments().size(), 1U);
  ASSERT_NE(result.response.results()[0].output_arguments()[0].try_as<uint32_t>(), nullptr);
  EXPECT_EQ(*result.response.results()[0].output_arguments()[0].try_as<uint32_t>(), 0xA13U);
  EXPECT_EQ(invocationCount->load(), 1U);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-METH-CALL-013-TYPE-DECLARED-METHOD, scope=function)
TEST(MethodArgumentValidationService, InstanceDeclaredMethodOnObjectInstanceReachesHandler)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto invocationCount = std::make_shared<std::atomic_uint32_t>(0U);
  auto request = fixture.make_object_instance_declared_method_request(false, invocationCount, 0xB13U);

  auto sessionInfo = fixture.make_session();
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1U);
  ASSERT_EQ(result.response.results()[0].status_code(), StatusCode{Status::Good});
  ASSERT_EQ(result.response.results()[0].output_arguments().size(), 1U);
  ASSERT_NE(result.response.results()[0].output_arguments()[0].try_as<uint32_t>(), nullptr);
  EXPECT_EQ(*result.response.results()[0].output_arguments()[0].try_as<uint32_t>(), 0xB13U);
  EXPECT_EQ(invocationCount->load(), 1U);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// RED-first: wrong type -> Bad_InvalidArgument, per-arg inputArgumentResults [Bad_TypeMismatch, Good],
// handler not invoked.
TEST(MethodArgumentValidationService, WrongTypeRejectedWithPerArgResults)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments(
    {make_argument("a", DataTypeId::Int32), make_argument("b", DataTypeId::Int32)});

  auto sessionInfo = fixture.make_session();
  auto request = fixture.make_call_request({Variant{String{"oops"}}, Variant{int32_t{2}}});
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  const auto& callResult = result.response.results()[0];
  EXPECT_EQ(callResult.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_EQ(callResult.input_argument_results().size(), 2u);
  EXPECT_EQ(callResult.input_argument_results()[0], StatusCode{Status::BadTypeMismatch});
  EXPECT_EQ(callResult.input_argument_results()[1], StatusCode{Status::Good});
  EXPECT_FALSE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Matching args -> Good and the handler runs.
TEST(MethodArgumentValidationService, MatchingArgsAcceptedHandlerInvoked)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments(
    {make_argument("a", DataTypeId::Int32), make_argument("b", DataTypeId::Int32)});

  auto sessionInfo = fixture.make_session();
  auto request = fixture.make_call_request({Variant{int32_t{1}}, Variant{int32_t{2}}});
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-METH-CALL-022-INPUTARGUMENTRESULTS-SHAPE, scope=function)
// @defect(D-INPUTARGUMENTRESULTS-IS-RETURNED-FULLY-POPULATED-ON)
TEST(MethodArgumentValidationService, InputArgumentResultsAreClearedUnlessStatusIsBadInvalidArgument)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments(
    {make_argument("a", DataTypeId::Int32), make_argument("b", DataTypeId::Int32)});
  auto sessionInfo = fixture.make_session();

  const auto invokeScripted =
    [&](StatusCode status, std::vector<StatusCode> inputArgumentResults)
  {
    fixture.set_handler_result(std::move(status), std::move(inputArgumentResults));
    auto result = invoke_call_service(sessionInfo,
      fixture.make_call_request({Variant{int32_t{1}}, Variant{int32_t{2}}}),
      threadPool.get_executor());
    EXPECT_TRUE(result.completed);
    EXPECT_EQ(result.response.results().size(), 1u);
    if (!result.completed || result.response.results().size() != 1u)
      return CallMethodResult{};
    return std::move(result.response.results()[0]);
  };

  auto good = invokeScripted(StatusCode{}, {StatusCode{}, StatusCode{}});
  EXPECT_TRUE(good.status_code().is_good());
  EXPECT_TRUE(good.input_argument_results().payload().empty())
    << "a successful Method operation cannot carry per-argument failures";

  const std::shared_ptr<const ErrorDetail> badDetail = make_error_detail(
    "ScriptedMethodFailure", "The scripted Method failed after argument validation", "Test");
  auto otherBad = invokeScripted(StatusCode{Status::BadOutOfRange, badDetail},
    {StatusCode{Status::BadTypeMismatch}, StatusCode{}});
  EXPECT_EQ(otherBad.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(otherBad.status_code().shared_detail(), badDetail);
  EXPECT_TRUE(otherBad.input_argument_results().payload().empty())
    << "inputArgumentResults is reserved for operation-level BadInvalidArgument";

  auto invalidArguments = invokeScripted(StatusCode{Status::BadInvalidArgument},
    {StatusCode{}, StatusCode{Status::BadTypeMismatch}});
  EXPECT_EQ(invalidArguments.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_EQ(invalidArguments.input_argument_results().size(), 2u);
  EXPECT_TRUE(invalidArguments.input_argument_results()[0].is_good());
  EXPECT_EQ(
    invalidArguments.input_argument_results()[1].as_status(), Status::BadTypeMismatch);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-METH-CALL-021-BAD-MEANS-NO-OUTPUTS, scope=function)
// @defect(D-CALL-RESPONSE-FRAMER-DOES-NOT-STRIP)
TEST(MethodArgumentValidationService, BadMethodResultDropsOutputsAndPreservesItsRichStatus)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto sessionInfo = fixture.make_session();

  const std::shared_ptr<const ErrorDetail> badDetail = make_error_detail(
    "ScriptedMethodFailure", "The scripted Method failed after producing a partial output", "Test");
  fixture.set_handler_result(
    StatusCode{Status::BadOutOfRange, badDetail}, {}, {Variant{int32_t{41}}});
  auto badResult = invoke_call_service(
    sessionInfo, fixture.make_call_request({}), threadPool.get_executor());

  ASSERT_TRUE(badResult.completed);
  ASSERT_EQ(badResult.response.results().size(), 1u);
  const auto& badOperation = badResult.response.results()[0];
  EXPECT_EQ(badOperation.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(badOperation.status_code().shared_detail(), badDetail);
  EXPECT_TRUE(badOperation.output_arguments().payload().empty())
    << "partial Method outputs are not meaningful beside a Bad operation result";

  fixture.set_handler_result(StatusCode{}, {}, {Variant{int32_t{42}}});
  auto goodResult = invoke_call_service(
    sessionInfo, fixture.make_call_request({}), threadPool.get_executor());

  ASSERT_TRUE(goodResult.completed);
  ASSERT_EQ(goodResult.response.results().size(), 1u);
  const auto& goodOperation = goodResult.response.results()[0];
  ASSERT_EQ(goodOperation.output_arguments().size(), 1u);
  ASSERT_TRUE(goodOperation.output_arguments()[0].is_int32());
  EXPECT_EQ(goodOperation.output_arguments()[0].as<int32_t>(), 42);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-METH-CALL-030-APPLICATION-DETAIL-REACHES-DIAGNOSTIC, scope=function)
TEST(MethodArgumentValidationService, BadMethodResultEmitsApplicationDiagnosticWhenRequested)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  auto sessionInfo = fixture.make_session();
  auto* sessionStub = dynamic_cast<SessionInfoStub*>(sessionInfo.get());
  ASSERT_NE(sessionStub, nullptr);
  sessionStub->enable_operation_diagnostics();

  const std::shared_ptr<const ErrorDetail> badDetail = make_error_detail(
    "ScriptedMethodFailure", "The scripted Method rejected the application request", "Test");
  fixture.set_handler_result(StatusCode{Status::BadOutOfRange, badDetail}, {});
  auto request = fixture.make_call_request({});
  request.request_header().return_diagnostics() = diag::operationLevelMask;

  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code().as_status(), Status::BadOutOfRange);
  ASSERT_EQ(result.response.diagnostic_infos().size(), 1u);
  const auto& diagnostic = result.response.diagnostic_infos()[0];
  ASSERT_TRUE(diagnostic.symbolic_id().has_value());
  const auto symbolicIndex = static_cast<size_t>(*diagnostic.symbolic_id());
  ASSERT_LT(symbolicIndex, result.response.response_header().string_table().size());
  EXPECT_EQ(std::string{result.response.response_header().string_table()[symbolicIndex]},
    "ScriptedMethodFailure");

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Regression: a Method with NO InputArguments Property is NOT model-validated. The raw handler
// runs even when called with arguments (validation is delegated to the handler/adapter). This
// guards the existing no-Property methods (e.g. ComplianceMethodOpLimited) from being regressed.
TEST(MethodArgumentValidationService, NoInputArgumentsPropertySkipsValidation)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  // No attach_input_arguments() - the method has no InputArguments Property.

  auto sessionInfo = fixture.make_session();
  auto request = fixture.make_call_request({Variant{int32_t{1}}, Variant{int32_t{2}}});
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A Method declaring an empty InputArguments Property accepts a no-argument call.
TEST(MethodArgumentValidationService, EmptyInputArgumentsAcceptsNoArgs)
{
  boost::asio::thread_pool threadPool;
  MethodArgumentValidationFixture fixture(threadPool);
  fixture.attach_input_arguments({});  // present but empty -> zero declared arguments

  auto sessionInfo = fixture.make_session();
  auto request = fixture.make_call_request({});
  auto result = invoke_call_service(sessionInfo, std::move(request), threadPool.get_executor());

  ASSERT_TRUE(result.completed);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_EQ(result.response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(fixture.handler_invoked());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
