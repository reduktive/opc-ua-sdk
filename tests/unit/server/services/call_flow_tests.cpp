// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the Call service calls the namespaces that own its Methods and Objects: one lookup and one permissions
// call per namespace before any Method runs, carrying the request's deadline and the Session's identity; each
// distinct Method, type level and InputArguments Property resolved once per request; an Uncertain lookup
// answer refusing only its item; the InputArguments Property taken as 0:InputArguments; and the state-machine
// hook making no namespace call for an Object that is not a state machine. Then the calls themselves: one
// `call_async` per namespace per request with the request's deadline and the Session's caller, the declined
// items offered to their Methods' namespaces in one call, a namespace still running at the timeoutHint told
// to stop, and an answer that arrives after the response audited. Last, a Method of a state machine the SDK
// manages: its transition applied and its call audited once whenever its answer arrives, at the timeoutHint,
// after a cancel, or with its namespace call discarded.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <variant>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>
#include <array>

#include "ua_address_space.h"
#include "ua_argument.h"
#include "ua_audit_update_method_event_payload.h"
#include "ua_base_event.h"
#include "ua_array.h"
#include "ua_byte_string.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_exceptions.h"
#include "ua_method_adapter.h"
#include "ua_method_result.h"
#include "ua_method_service_set.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;
using RecordedCall = BatchRecordingNamespace::Call;

namespace
{

constexpr auto uncertainAnswer = Status::UncertainNoCommunicationLastUsableValue;

struct CallOutcome
{
  bool answered{false};
  StatusCode serviceResult;
  std::optional<CallResponse> response;

  /// When the response arrived, taken as it arrived.
  DateTime arrived;
};

// What the Methods' handlers saw: which ran, with which input arguments, and what the watched namespaces had
// recorded at the moment the first of them ran.
struct HandlerLog
{
  std::mutex mutex;
  bool anyRan{false};
  std::vector<std::weak_ptr<BatchRecordingNamespace>> watched;
  std::vector<std::vector<RecordedCall>> atFirstHandler;
  std::set<std::string> ran;
  std::map<std::string, std::vector<Variant>> inputs;

  void record(const std::string& name, const CallMethodRequest& request)
  {
    std::lock_guard lock(mutex);
    if (!anyRan)
    {
      anyRan = true;
      for (const auto& weak : watched)
      {
        auto nameSpace = weak.lock();
        atFirstHandler.push_back(nameSpace ? nameSpace->calls() : std::vector<RecordedCall>{});
      }
    }
    ran.insert(name);
    inputs[name] = request.input_arguments().payload();
  }

  bool has_run(const std::string& name)
  {
    std::lock_guard lock(mutex);
    return ran.count(name) != 0;
  }

  // The calls watched namespace @p index had recorded when the first handler ran.
  std::vector<RecordedCall> first_handler_calls(std::size_t index)
  {
    std::lock_guard lock(mutex);
    return index < atFirstHandler.size() ? atFirstHandler[index] : std::vector<RecordedCall>{};
  }
};

// A server with the given namespaces registered, and a Session on it with access control installed.
struct CallHarness
{
  ~CallHarness()
  {
    shutdown();
  }

  void shutdown()
  {
    services.clear();
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool{4};
  shared_ptr<SessionInfoStub> sessionInfo;
  std::vector<shared_ptr<MethodServiceSet>> services;
  shared_ptr<HandlerLog> log{std::make_shared<HandlerLog>()};
  shared_ptr<std::atomic<std::size_t>> responseCount{std::make_shared<std::atomic<std::size_t>>(0)};

  std::vector<uint16_t> setup(
    const std::vector<shared_ptr<ua::Namespace>>& namespaces, ServerConfig serverConfig = ServerConfig{})
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    auto server = Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    std::vector<uint16_t> indexes;
    for (const auto& nameSpace : namespaces)
    {
      indexes.push_back(server.address_space().add_namespace_sync(nameSpace));
    }
    sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
    return indexes;
  }

  // A Node of @p nodeClass whose BrowseName is @p name in @p browseNameIndex (the Node's own namespace when
  // not given).
  NodeId create(const NodeId& nodeId, const std::string& name, NodeClass nodeClass,
    std::optional<uint16_t> browseNameIndex = std::nullopt)
  {
    auto created = sessionInfo->address_space().try_create_node_sync(nodeId, nodeClass);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      created.value().set_browse_name(
        QualifiedName{browseNameIndex.value_or(nodeId.namespace_index()), name});
      created.value().set_display_name(LocalizedText{"", name});
      if (nodeClass == NodeClass::Method)
      {
        auto method = created.value().as<MethodAccessor>();
        EXPECT_TRUE(method.has_value()) << nodeId.as_definition();
        if (method)
        {
          method->set_executable(true);
        }
      }
    }
    return nodeId;
  }

  // A Reference of @p type from @p source to @p target: the forward half held by the source and the inverse
  // half held by the target. The address space adds the inverse half of a HasSubtype itself (NR-70 B8).
  void link(const NodeId& source, ReferenceTypeId type, const NodeId& target)
  {
    auto addressSpace = sessionInfo->address_space();
    auto from = addressSpace.try_find_node_sync(source);
    auto to = addressSpace.try_find_node_sync(target);
    ASSERT_TRUE(from.is_good()) << source.as_definition();
    ASSERT_TRUE(to.is_good()) << target.as_definition();
    EXPECT_TRUE(from.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{target}, true).is_good())
      << source.as_definition() << " to " << target.as_definition();
    if (type == ReferenceTypeId::HasSubtype || type == ReferenceTypeId::HasEncoding)
    {
      return;
    }
    EXPECT_TRUE(to.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{source}, false).is_good())
      << target.as_definition() << " from " << source.as_definition();
  }

  // The forward HasTypeDefinition Reference of @p instance to @p typeDefinition, held by the instance only.
  void type(const NodeId& instance, const NodeId& typeDefinition)
  {
    auto node = sessionInfo->address_space().try_find_node_sync(instance);
    ASSERT_TRUE(node.is_good()) << instance.as_definition();
    EXPECT_TRUE(node.value()
                  .try_add_reference_sync(
                    NodeId{ReferenceTypeId::HasTypeDefinition}, ExpandedNodeId{typeDefinition}, true)
                  .is_good())
      << instance.as_definition();
  }

  // A Variable @p nodeId with the BrowseName 0:@p name, the DataType @p dataType and the Value @p value.
  NodeId variable(const NodeId& nodeId, const std::string& name, const NodeId& dataType, Variant value)
  {
    create(nodeId, name, NodeClass::Variable, 0);
    auto node = sessionInfo->address_space().try_find_node_sync(nodeId);
    EXPECT_TRUE(node.is_good()) << nodeId.as_definition();
    if (node.is_good())
    {
      auto accessor = node.value().as<VariableAccessor>();
      EXPECT_TRUE(accessor.has_value()) << nodeId.as_definition();
      if (accessor)
      {
        accessor->set_data_type(dataType);
        EXPECT_TRUE(accessor->try_write_value_sync(DataValue{std::move(value)}).is_good())
          << nodeId.as_definition();
      }
    }
    return nodeId;
  }

  // A Variable @p nodeId with the BrowseName @p browseNameIndex:InputArguments whose Value declares one
  // argument per name in @p arguments, the target of a HasProperty Reference from @p method. Existing
  // calls declare scalar Int32; @p dataType and @p valueRank allow other declared input types.
  NodeId input_arguments(const NodeId& method, const NodeId& nodeId, uint16_t browseNameIndex,
    const std::vector<std::string>& arguments, const NodeId& dataType = NodeId{DataTypeId::Int32},
    int32_t valueRank = ValueRank::scalar)
  {
    create(nodeId, "InputArguments", NodeClass::Variable, browseNameIndex);
    auto node = sessionInfo->address_space().try_find_node_sync(nodeId);
    EXPECT_TRUE(node.is_good()) << nodeId.as_definition();
    if (node.is_good())
    {
      auto variable = node.value().as<VariableAccessor>();
      EXPECT_TRUE(variable.has_value()) << nodeId.as_definition();
      if (variable)
      {
        variable->set_data_type(NodeId{DataTypeId::Argument});
        variable->set_value_rank(int32_t{1});
        Array<RefStructure<Structure>> elements;
        elements.resize(arguments.size());
        for (std::size_t i = 0; i < arguments.size(); ++i)
        {
          Argument argument;
          argument.name() = String{arguments[i]};
          argument.data_type() = dataType;
          argument.value_rank() = valueRank;
          if (valueRank > 0)
          {
            argument.array_dimensions().resize(numeric_cast<std::size_t>(valueRank));
          }
          elements[i] = RefStructure<Structure>{std::make_unique<Argument>(std::move(argument))};
        }
        EXPECT_TRUE(variable->try_write_value_sync(DataValue{Variant{std::move(elements)}}).is_good())
          << nodeId.as_definition();
      }
    }
    link(method, ReferenceTypeId::HasProperty, nodeId);
    return nodeId;
  }

  // Installs on @p method, held by @p nameSpace, a handler that records its run in @ref log under @p name and
  // answers Good with the one output argument @p output.
  void handle(
    ua::default_ns::Namespace& nameSpace, const NodeId& method, const std::string& name, int32_t output)
  {
    auto node = nameSpace.find_node<Node>(method);
    ASSERT_NE(node, nullptr) << method.as_definition();
    auto* source = node->method_call_source();
    ASSERT_NE(source, nullptr) << method.as_definition();
    EXPECT_TRUE(source
                  ->set_call_handler(
                    [log = log, name, output](const CallMethodRequest& request,
                      shared_ptr<const MethodCallContext>,
                      std::function<void(CallResult)>
                        callback)
                    {
                      log->record(name, request);
                      CallMethodResult result;
                      result.status_code() = Status::Good;
                      result.output_arguments().push_back(Variant{output});
                      callback(CallResult{std::move(result)});
                    })
                  .is_good())
      << method.as_definition();
  }

  // Installs on @p method, held by @p nameSpace, the typed handler @p handler of a Method with no input
  // arguments and one Int32 output argument, through the adapter add_method installs a typed handler with.
  template<typename Handler>
  void handle_typed(ua::default_ns::Namespace& nameSpace, const NodeId& method, Handler handler)
  {
    auto node = nameSpace.find_node<Node>(method);
    ASSERT_NE(node, nullptr) << method.as_definition();
    auto* source = node->method_call_source();
    ASSERT_NE(source, nullptr) << method.as_definition();
    EXPECT_TRUE(source->set_call_handler(MethodAdapter<std::tuple<>, std::tuple<int32_t>>{std::move(handler)})
                  .is_good())
      << method.as_definition();
  }

  // Sends @p request on @p session (this harness's Session when not given) and returns its response once it
  // has arrived, or no answer after 10 s.
  CallOutcome call(CallRequest request, const shared_ptr<SessionInfo>& session = nullptr)
  {
    auto pending = start(std::move(request), session);
    return await(pending);
  }

  // Sends @p request on @p session (this harness's Session when not given) without waiting for its response.
  // The service holds the Session weakly, as a server Session's services do.
  std::future<CallOutcome> start(CallRequest request, const shared_ptr<SessionInfo>& session = nullptr)
  {
    auto promise = std::make_shared<std::promise<CallOutcome>>();
    auto future = promise->get_future();
    services.push_back(MethodServiceSet::create(
      session ? std::weak_ptr<SessionInfo>{session} : std::weak_ptr<SessionInfo>{sessionInfo},
      std::vector<LocaleId>{LocaleId{"en"}},
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise, responseCount = responseCount](Response response)
      {
        ++*responseCount;
        CallOutcome outcome;
        outcome.arrived = DateTime::now();
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* called = dynamic_cast<CallResponse*>(response.second.get()))
        {
          outcome.serviceResult = called->response_header().service_result();
          outcome.response = std::move(*called);
        }
        promise->set_value(std::move(outcome));
      }));
    return future;
  }

  // The response of a request @ref start sent, or no answer when it has not arrived within 10 s.
  static CallOutcome await(std::future<CallOutcome>& pending)
  {
    if (pending.wait_for(10s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the Call was not answered";
      return {};
    }
    return pending.get();
  }
};

CallMethodRequest item_of(const NodeId& object, const NodeId& method, std::vector<Variant> inputs = {})
{
  CallMethodRequest item;
  item.object_id() = object;
  item.method_id() = method;
  for (auto& input : inputs)
  {
    item.input_arguments().push_back(std::move(input));
  }
  return item;
}

CallRequest request_of(std::vector<CallMethodRequest> items, uint32_t timeoutHint = 0)
{
  CallRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = timeoutHint;
  for (auto& item : items)
  {
    request.methods_to_call().push_back(std::move(item));
  }
  return request;
}

// A recording namespace holding one Object and one Method, as one_method_namespace registers it.
struct OneMethodNamespace
{
  shared_ptr<BatchRecordingNamespace> nameSpace;
  uint16_t index{0};
  NodeId object;
  NodeId method;
};

// Registers a recording namespace under @p uri on @p harness's server, holding the Object i=100 and the
// Method i=200 named @p methodName, the target of a HasComponent Reference from the Object, whose handler
// records its run under @p handlerName and answers Good with the one output argument @p output. @p prepare,
// when given, then adds to the Nodes what a test needs. Last the namespace declines its single lookups and
// its immediate permissions, and its record is cleared, so that what it records afterwards is the Call's.
OneMethodNamespace one_method_namespace(CallHarness& harness, const std::string& uri,
  const std::string& handlerName, int32_t output, const std::string& methodName = "Method",
  const std::function<void(const OneMethodNamespace&)>& prepare = {})
{
  OneMethodNamespace built;
  built.nameSpace = make_shared<BatchRecordingNamespace>(uri, harness.threadPool.get_executor());
  built.index = harness.setup({built.nameSpace}).at(0);
  built.object = harness.create(NodeId{built.index, 100}, "Object", NodeClass::Object);
  built.method = harness.create(NodeId{built.index, 200}, methodName, NodeClass::Method);
  harness.link(built.object, ReferenceTypeId::HasComponent, built.method);
  harness.handle(*built.nameSpace, built.method, handlerName, output);
  if (prepare)
  {
    prepare(built);
  }
  built.nameSpace->decline_single_lookups();
  built.nameSpace->decline_immediate_permissions();
  built.nameSpace->reset();
  return built;
}

// How many of @p calls are of @p member.
std::size_t count_of(const std::vector<RecordedCall>& calls, Member member)
{
  return static_cast<std::size_t>(std::count_if(
    calls.begin(), calls.end(), [member](const RecordedCall& call) { return call.member == member; }));
}

// How many times @p nodeId is named among @p calls of @p member: once per NodeId, or per query of a
// read_references_async call.
std::size_t times_named(const std::vector<RecordedCall>& calls, Member member, const NodeId& nodeId)
{
  std::size_t named = 0;
  for (const auto& call : calls)
  {
    if (call.member == member)
    {
      named += static_cast<std::size_t>(std::count(call.nodeIds.begin(), call.nodeIds.end(), nodeId));
    }
  }
  return named;
}

// The effective_permissions_async calls among @p calls.
std::size_t permission_calls(const std::vector<RecordedCall>& calls)
{
  return count_of(calls, Member::PermissionsAsyncForRequest);
}

std::string detail_code(const StatusCode& status)
{
  const auto detail = status.shared_detail();
  return detail ? detail->code : std::string{"(none)"};
}

StatusCodeValue detail_cause(const StatusCode& status)
{
  const auto detail = status.shared_detail();
  return detail ? detail->innerStatus : StatusCode{Status::Good}.value();
}

// Whether result @p index of @p outcome is Good with the one Int32 output argument @p output.
void expect_good_with_output(const CallOutcome& outcome, std::size_t index, int32_t output)
{
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_LT(index, outcome.response->results().size());
  const auto& result = outcome.response->results()[index];
  EXPECT_EQ(result.status_code().as_status(), Status::Good)
    << "item " << index + 1 << ": " << to_string(result.status_code());
  ASSERT_EQ(result.output_arguments().size(), 1U) << "item " << index + 1 << "'s output arguments";
  ASSERT_TRUE(result.output_arguments()[0].is_int32()) << "item " << index + 1;
  EXPECT_EQ(result.output_arguments()[0].as<int32_t>(), output) << "item " << index + 1 << "'s output";
}

// Expects result @p index of @p outcome to be the refusal of an item whose lookup was answered Uncertain.
void expect_uncertain_lookup_refusal(const CallOutcome& outcome, std::size_t index)
{
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_LT(index, outcome.response->results().size());
  const auto& status = outcome.response->results()[index].status_code();
  EXPECT_EQ(status.as_status(), Status::BadInternalError)
    << "item " << index + 1 << ": " << to_string(status);
  EXPECT_EQ(detail_code(status), "LookupAnswerUncertain")
    << "item " << index + 1 << ": " << to_string(status);
  EXPECT_EQ(detail_cause(status), StatusCode{uncertainAnswer}.value())
    << "item " << index + 1 << ": the ErrorDetail's cause is not the Uncertain answer";
}

// Whether @p condition holds within @p limit, polled.
bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds limit)
{
  const auto deadline = std::chrono::steady_clock::now() + limit;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(5ms);
  }
  return true;
}

// The objectIds of each of @p calls, one call per brace.
std::string describe_calls(const std::vector<RecordedCall>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    text += " {";
    for (std::size_t i = 0; i < call.nodeIds.size(); ++i)
    {
      text += (i == 0 ? "" : ", ") + to_string(call.nodeIds[i]);
    }
    text += "}";
  }
  return text.empty() ? std::string{" none"} : text;
}

// Expects @p calls to be one call_async whose items are on @p objects, in that order.
void expect_one_call_of(
  const std::vector<RecordedCall>& calls, const std::vector<NodeId>& objects, const std::string& nameSpace)
{
  EXPECT_EQ(calls.size(), 1U) << nameSpace
                              << "'s call_async calls, by their items' Objects:" << describe_calls(calls);
  if (!calls.empty())
  {
    EXPECT_EQ(calls.front().nodeIds, objects)
      << "the items of " << nameSpace << "'s first call_async, by their Objects:" << describe_calls(calls);
  }
}

// An EventBus that records each AuditUpdateMethodEventType Event (or subtype) it is given, then dispatches
// it. The Call service raises an audit Event only through an EventBus with event interest, which the test
// gives it with a local listener.
class MethodAuditBus : public EventBus
{
public:
  struct Record
  {
    NodeId eventType;
    NodeId sourceNode;
    NodeId methodId;
    bool status{false};
    /// The Event's ActionTimeStamp, when it holds a DateTime.
    std::optional<DateTime> actionTimeStamp;
  };

  explicit MethodAuditBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    if (const auto* audit = dynamic_cast<const AuditUpdateMethodEventPayload*>(&event))
    {
      {
        std::lock_guard lock(mMutex);
        const auto* stamp = audit->actionTimeStamp.try_as<DateTime>();
        mRecords.push_back(Record{audit->eventType,
          audit->sourceNode,
          audit->methodId,
          audit->status,
          stamp ? std::optional<DateTime>{*stamp} : std::nullopt});
      }
      mRecorded.notify_all();
    }
    EventBus::emit(event);
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

  // Waits until an Event for @p method on @p object has been recorded, or @p limit passes.
  bool wait_for(const NodeId& object, const NodeId& method, std::chrono::milliseconds limit) const
  {
    std::unique_lock lock(mMutex);
    return mRecorded.wait_for(lock,
      limit,
      [this, &object, &method]
      {
        return std::any_of(mRecords.begin(),
          mRecords.end(),
          [&object, &method](const Record& record)
          { return record.sourceNode == object && record.methodId == method; });
      });
  }

private:
  mutable std::mutex mMutex;
  mutable std::condition_variable mRecorded;
  std::vector<Record> mRecords;
};

// What Start answers with: Good and this one output argument.
constexpr int32_t startOutput = 42;

// A Session on the harness's server that the test can close. Every member answers as the harness's own
// Session does; closing it is releasing it, as a closing Session releases its SessionInfo, and the server
// keeps running.
class ClosableSession final : public SessionInfo, public SessionSecurityContext
{
public:
  explicit ClosableSession(shared_ptr<SessionInfoStub> serverSession)
    : mServerSession(std::move(serverSession))
  {}

  shared_ptr<std::atomic<bool>> serverConfigurationUnavailable{std::make_shared<std::atomic<bool>>(false)};

  AddressSpace address_space() const override
  {
    return mServerSession->address_space();
  }

  const ::ua::ApplicationConfig& configuration() const override
  {
    return mServerSession->configuration();
  }

  const ::ua::server::ServerConfig& server_configuration() const override
  {
    if (serverConfigurationUnavailable->load())
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail(
          "ServerConfigurationUnavailable", "Server configuration is unavailable", "test.call-flow")};
    }
    return mServerSession->server_configuration();
  }

  ua::server::DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return mServerSession->diagnostic_security_context();
  }

  Logger logger() const override
  {
    return mServerSession->logger();
  }

  std::shared_ptr<ua::EventSink> event_sink() const override
  {
    return mServerSession->event_sink();
  }

  uint32_t max_response_message_size() const override
  {
    return mServerSession->max_response_message_size();
  }

  ua::NodeId session_id() const override
  {
    return mServerSession->session_id();
  }

  std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint_security() const override
  {
    return mServerSession->endpoint_security();
  }

  std::shared_ptr<const ua::server::UserIdentity> user_identity() const override
  {
    return mServerSession->user_identity();
  }

  std::shared_ptr<const ua::AccessIdentity> access_identity() const override
  {
    return mServerSession->access_identity();
  }

private:
  // The harness's Session, through which the server is reached; it owns the server.
  shared_ptr<SessionInfoStub> mServerSession;
};

// A server with auditing enabled whose one namespace R holds a FiniteStateMachineType subtype - States Ready
// (initial) and Running, each with its StateNumber, and a Transition from Ready to Running whose cause is the
// type's Method Start - and instances of it, each in Ready. Start answers Good with the output argument
// @ref startOutput; once @ref armed is set, it first makes R hold the next lookup naming Start, which, the
// request's own lookups having been made before the Method ran, is the transition's.
struct StateMachineCallHarness
{
  ~StateMachineCallHarness()
  {
    harness.shutdown();
    bus.reset();
  }

  struct Machine
  {
    NodeId object;
    NodeId stateId;
  };

  // Keep the bus alive while services finish, then release its strand before the executor is destroyed.
  shared_ptr<MethodAuditBus> bus;
  CallHarness harness;
  shared_ptr<BatchRecordingNamespace> r;
  uint16_t index{0};
  NodeId ready;
  NodeId running;
  NodeId start;
  std::vector<Machine> machines;
  shared_ptr<std::atomic<bool>> armed{std::make_shared<std::atomic<bool>>(false)};

  // Builds the server, the type, one instance per name in @p instances (in @ref machines, in order) and
  // Start's handler. Called under ASSERT_NO_FATAL_FAILURE.
  void build(const std::string& uri, const std::vector<std::string>& instances)
  {
    r = make_shared<BatchRecordingNamespace>(uri, harness.threadPool.get_executor());
    ServerConfig serverConfig;
    serverConfig.auditingEnabled = true;
    index = harness.setup({r}, std::move(serverConfig)).at(0);
    ASSERT_TRUE(harness.sessionInfo->server_configuration().auditingEnabled);
    bus = std::make_shared<MethodAuditBus>(harness.sessionInfo->address_space());
    bus->set_event_listener([](const BaseEvent&) {});
    harness.sessionInfo->eventSink = bus.get();

    const NodeId machineType = harness.create(NodeId{index, 300}, "MachineType", NodeClass::ObjectType);
    {
      auto typeNode = harness.sessionInfo->address_space().try_find_node_sync(machineType);
      ASSERT_TRUE(typeNode.is_good());
      EXPECT_TRUE(typeNode.value()
                    .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
                      ExpandedNodeId{NodeId{ObjectTypeId::FiniteStateMachineType}},
                      false)
                    .is_good());
    }
    ready = harness.create(NodeId{index, 301}, "Ready", NodeClass::Object, 0);
    harness.type(ready, NodeId{ObjectTypeId::InitialStateType});
    harness.link(machineType, ReferenceTypeId::HasComponent, ready);
    harness.link(ready,
      ReferenceTypeId::HasProperty,
      harness.variable(NodeId{index, 311}, "StateNumber", NodeId{DataTypeId::UInt32}, Variant{uint32_t{1}}));
    running = harness.create(NodeId{index, 302}, "Running", NodeClass::Object, 0);
    harness.type(running, NodeId{ObjectTypeId::StateType});
    harness.link(machineType, ReferenceTypeId::HasComponent, running);
    harness.link(running,
      ReferenceTypeId::HasProperty,
      harness.variable(NodeId{index, 312}, "StateNumber", NodeId{DataTypeId::UInt32}, Variant{uint32_t{2}}));
    start = harness.create(NodeId{index, 303}, "Start", NodeClass::Method, 0);
    harness.link(machineType, ReferenceTypeId::HasComponent, start);
    const NodeId transition = harness.create(NodeId{index, 304}, "ReadyToRunning", NodeClass::Object, 0);
    harness.type(transition, NodeId{ObjectTypeId::TransitionType});
    harness.link(machineType, ReferenceTypeId::HasComponent, transition);
    harness.link(transition, ReferenceTypeId::FromState, ready);
    harness.link(transition, ReferenceTypeId::ToState, running);
    harness.link(transition, ReferenceTypeId::HasCause, start);

    for (std::size_t k = 0; k < instances.size(); ++k)
    {
      const auto first = static_cast<uint32_t>(100 + 10 * k);
      const NodeId object = harness.create(NodeId{index, first}, instances[k], NodeClass::Object);
      harness.type(object, machineType);
      const NodeId currentState = harness.variable(NodeId{index, first + 1},
        "CurrentState",
        NodeId{DataTypeId::LocalizedText},
        Variant{LocalizedText{"en", "Ready"}});
      harness.type(currentState, NodeId{VariableTypeId::FiniteStateVariableType});
      harness.link(object, ReferenceTypeId::HasComponent, currentState);
      const NodeId stateId =
        harness.variable(NodeId{index, first + 2}, "Id", NodeId{DataTypeId::NodeId}, Variant{ready});
      harness.link(currentState, ReferenceTypeId::HasProperty, stateId);
      machines.push_back(Machine{object, stateId});
    }

    auto node = static_cast<ua::default_ns::Namespace&>(*r).find_node<Node>(start);
    ASSERT_NE(node, nullptr);
    auto* source = node->method_call_source();
    ASSERT_NE(source, nullptr);
    ASSERT_TRUE(source
                  ->set_call_handler(
                    [weak = std::weak_ptr<BatchRecordingNamespace>{r}, armed = armed, start = start](
                      const CallMethodRequest&,
                      shared_ptr<const MethodCallContext>,
                      std::function<void(CallResult)>
                        callback)
                    {
                      if (auto self = weak.lock(); self && armed->load())
                      {
                        self->hold_lookups_of({start});
                      }
                      CallMethodResult result;
                      result.status_code() = Status::Good;
                      result.output_arguments().push_back(Variant{startOutput});
                      callback(CallResult{std::move(result)});
                    })
                  .is_good());
    r->decline_single_lookups();
    r->decline_immediate_permissions();
    r->reset();
  }

  // The state a machine's CurrentState Id names, or none when it cannot be read.
  std::optional<NodeId> state_of(const Machine& machine) const
  {
    auto variable = harness.sessionInfo->address_space().try_find_sync<VariableAccessor>(machine.stateId);
    if (!variable.is_good())
    {
      return std::nullopt;
    }
    auto value = variable.value().try_read_value_sync();
    if (!value.is_good())
    {
      return std::nullopt;
    }
    const auto* id = value.value().value().try_as<NodeId>();
    return id ? std::optional<NodeId>{*id} : std::nullopt;
  }

  static std::string text(const std::optional<NodeId>& state)
  {
    return state ? to_string(*state) : std::string{"(unreadable)"};
  }

  // Whether @p machine's CurrentState Id names @p state within @p limit.
  bool wait_for_state(const Machine& machine, const NodeId& state, std::chrono::milliseconds limit) const
  {
    return wait_until(
      [this, &machine, &state] { return state_of(machine) == std::optional<NodeId>{state}; }, limit);
  }

  // The audit Events raised for Start on @p object, as recorded, in the order they were raised.
  std::vector<MethodAuditBus::Record> records_of(const NodeId& object) const
  {
    std::vector<MethodAuditBus::Record> records;
    for (const auto& record : bus->records())
    {
      if (record.sourceNode == object && record.methodId == start)
      {
        records.push_back(record);
      }
    }
    return records;
  }

  // The audit Events raised for Start on @p object, by type and Status, in a fixed order.
  std::vector<std::string> audits_of(const NodeId& object) const
  {
    std::vector<std::string> audits;
    for (const auto& record : bus->records())
    {
      if (record.sourceNode == object && record.methodId == start)
      {
        audits.push_back(to_string(record.eventType) + (record.status ? " true" : " false"));
      }
    }
    std::sort(audits.begin(), audits.end());
    return audits;
  }

  // The audit Events raised for Start on @p object, counted again 200 ms after @p count have been raised, so
  // that a duplicate raised in a later turn has arrived; those raised within 3 s when fewer are.
  std::vector<std::string> audits_settled(const NodeId& object, std::size_t count) const
  {
    if (wait_until([this, &object, count] { return audits_of(object).size() >= count; }, 3000ms))
    {
      std::this_thread::sleep_for(200ms);
    }
    return audits_of(object);
  }
};

// The audit Events, as StateMachineCallHarness::audits_of gives them, of a call audited with @p status: one
// AuditUpdateMethodEventType Event, and, when @p transitioned, one AuditUpdateStateEventType Event with
// Status true.
std::vector<std::string> expected_audits(bool status, bool transitioned)
{
  std::vector<std::string> expected{
    to_string(NodeId{ObjectTypeId::AuditUpdateMethodEventType}) + (status ? " true" : " false")};
  if (transitioned)
  {
    expected.push_back(to_string(NodeId{ObjectTypeId::AuditUpdateStateEventType}) + " true");
  }
  std::sort(expected.begin(), expected.end());
  return expected;
}

// The failure the namespace answers a refused write of a machine's new state with.
StatusCode refused_state_write()
{
  return StatusCode{Status::BadOutOfService,
    std::shared_ptr<const ErrorDetail>{
      ErrorDetail::build("StateWriteRefused", "the namespace refused the write of the new state", "test")}};
}

// The status of result @p index of @p outcome, or Bad_NoData when the outcome has no such result.
StatusCode result_status(const CallOutcome& outcome, std::size_t index)
{
  if (!outcome.response.has_value() || index >= outcome.response->results().size())
  {
    return StatusCode{Status::BadNoData};
  }
  return outcome.response->results()[index].status_code();
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-THE-LOOKUPS-AND-PERMISSIONS-ARE-ONE-CALL-PER-NAMESPACE, scope=function)
TEST(CallFlow, TheLookupsAndPermissionsAreOneCallPerNamespace)
{
  CallHarness harness;
  auto r1 = make_shared<BatchRecordingNamespace>("urn:test:call-flow:r1", harness.threadPool.get_executor());
  auto r2 = make_shared<BatchRecordingNamespace>("urn:test:call-flow:r2", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2});
  std::vector<CallMethodRequest> items;
  for (uint32_t k = 0; k < 6; ++k)
  {
    const bool first = k % 2 == 0;
    const uint16_t index = indexes.at(first ? 0 : 1);
    auto& nameSpace = first ? *r1 : *r2;
    const NodeId object =
      harness.create(NodeId{index, 100 + k}, "Object" + std::to_string(k), NodeClass::Object);
    const NodeId method =
      harness.create(NodeId{index, 200 + k}, "Method" + std::to_string(k), NodeClass::Method);
    harness.link(object, ReferenceTypeId::HasComponent, method);
    harness.handle(nameSpace, method, "M" + std::to_string(k), static_cast<int32_t>(1000 + k));
    items.push_back(item_of(object, method));
  }
  for (const auto& r : {r1, r2})
  {
    r->decline_single_lookups();
    r->decline_immediate_permissions();
    r->reset();
  }
  harness.log->watched = {r1, r2};

  const auto outcome = harness.call(request_of(std::move(items)));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  const auto atFirst1 = harness.log->first_handler_calls(0);
  const auto atFirst2 = harness.log->first_handler_calls(1);
  EXPECT_EQ(count_of(atFirst1, Member::BatchedLookup), 1U)
    << "R1's find_nodes_async calls before the first handler";
  EXPECT_EQ(permission_calls(atFirst1), 1U)
    << "R1's effective_permissions_async calls before the first handler";
  EXPECT_EQ(count_of(atFirst2, Member::BatchedLookup), 1U)
    << "R2's find_nodes_async calls before the first handler";
  EXPECT_EQ(permission_calls(atFirst2), 1U)
    << "R2's effective_permissions_async calls before the first handler";
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 6U);
  for (std::size_t k = 0; k < 6; ++k)
  {
    expect_good_with_output(outcome, k, static_cast<int32_t>(1000 + k));
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-THE-NAMESPACE-CALLS-CARRY-THE-REQUEST, scope=function)
TEST(CallFlow, TheNamespaceCallsCarryTheRequest)
{
  CallHarness harness;
  const auto [r, index, object, method] = one_method_namespace(harness, "urn:test:call-flow:request", "M", 7);
  const auto identity = harness.sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr) << "the Session must hold an identity for this test to mean anything";

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.call(request_of({item_of(object, method)}, 5000));

  const auto lookups = r->calls(Member::BatchedLookup);
  EXPECT_FALSE(lookups.empty()) << "no find_nodes_async call";
  for (const auto& lookup : lookups)
  {
    EXPECT_TRUE(lookup.hasRequest) << "lookup #" << lookup.sequence << " takes no RequestInfo";
    EXPECT_GE(lookup.deadline, sent + 4s) << "lookup #" << lookup.sequence << "'s deadline";
    EXPECT_LE(lookup.deadline, sent + 6s) << "lookup #" << lookup.sequence << "'s deadline";
  }
  const auto permissions = r->calls(Member::PermissionsAsyncForRequest);
  EXPECT_FALSE(permissions.empty()) << "no effective_permissions_async call taking a RequestInfo";
  for (const auto& permission : permissions)
  {
    EXPECT_GE(permission.deadline, sent + 4s) << "permissions call #" << permission.sequence << "'s deadline";
    EXPECT_LE(permission.deadline, sent + 6s) << "permissions call #" << permission.sequence << "'s deadline";
    EXPECT_EQ(permission.identity.get(), identity.get())
      << "permissions call #" << permission.sequence << " is not for the Session's identity";
  }

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 7);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-EACH-DISTINCT-METHOD-IS-RESOLVED-ONCE, scope=function)
TEST(CallFlow, EachDistinctMethodIsResolvedOnce)
{
  CallHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:one-method", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  const NodeId inputArguments = harness.input_arguments(method, NodeId{index, 201}, 0, {"value"});
  harness.handle(*r, method, "M", 5);
  std::vector<CallMethodRequest> items;
  for (uint32_t k = 0; k < 5; ++k)
  {
    const NodeId object =
      harness.create(NodeId{index, 100 + k}, "Object" + std::to_string(k), NodeClass::Object);
    harness.link(object, ReferenceTypeId::HasComponent, method);
    items.push_back(item_of(object, method, {Variant{static_cast<int32_t>(k)}}));
  }
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->reset();
  harness.log->watched = {r};

  const auto outcome = harness.call(request_of(std::move(items)));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(times_named(harness.log->first_handler_calls(0), Member::BatchedLookup, method), 1U)
    << "the times M is named in find_nodes_async calls before the first handler";
  std::size_t inputArgumentReads = 0;
  for (const auto& read : r->calls(Member::ReadValues))
  {
    if (std::find(read.nodeIds.begin(), read.nodeIds.end(), inputArguments) != read.nodeIds.end())
    {
      ++inputArgumentReads;
    }
  }
  EXPECT_EQ(inputArgumentReads, 1U) << "read_values_async calls naming M's InputArguments Property";
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 5U);
  for (std::size_t k = 0; k < 5; ++k)
  {
    expect_good_with_output(outcome, k, 5);
  }
}

// @relation(AC-SVR-METH-CALL-032-BYTESTRING-FOR-BYTE-ARRAY, scope=function)
// @relation(AC-SVR-METH-CALL-051-ARG-BAD-TYPEMISMATCH, scope=function)
TEST(CallFlow, AByteStringIsAcceptedForAnArrayOfByteInput)
{
  CallHarness harness;
  NodeId inputArguments;
  const auto [nameSpace, index, object, method] = one_method_namespace(harness,
    "urn:test:call-flow:byte-array-acceptance",
    "ByteArray",
    73,
    "Method",
    [&harness, &inputArguments](const OneMethodNamespace& built)
    {
      inputArguments = harness.input_arguments(
        built.method, NodeId{built.index, 201}, 0, {"payload"}, NodeId{DataTypeId::Byte}, int32_t{1});
    });
  const ByteString payload{0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64};

  const auto outcome = harness.call(request_of({item_of(object, method, {Variant{payload}})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 73);
  EXPECT_EQ(outcome.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  EXPECT_TRUE(outcome.response->results()[0].input_argument_results().empty());
  ASSERT_TRUE(harness.log->has_run("ByteArray"));
  {
    const std::lock_guard lock{harness.log->mutex};
    const auto received = harness.log->inputs.find("ByteArray");
    ASSERT_NE(received, harness.log->inputs.end());
    ASSERT_EQ(received->second.size(), 1U);
    ASSERT_TRUE(received->second[0].is_byte_string());
    EXPECT_EQ(received->second[0].as<ByteString>(), payload);
  }
  const auto dispatched = nameSpace->calls(Member::Call);
  ASSERT_EQ(dispatched.size(), 1U);
  EXPECT_EQ(dispatched[0].nodeIds, (std::vector<NodeId>{object}));
  EXPECT_EQ(times_named(nameSpace->calls(), Member::ReadValues, inputArguments), 1U);
  harness.services.clear();
  harness.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.ByteArrayAcceptance");
  EXPECT_EQ(harness.responseCount->load(), 1U);
}

// @relation(AC-SVR-METH-CALL-051-ARG-BAD-TYPEMISMATCH, scope=function)
TEST(CallFlow, AStringIsRefusedForAnArrayOfByteInput)
{
  CallHarness harness;
  NodeId inputArguments;
  const auto [nameSpace, index, object, method] = one_method_namespace(harness,
    "urn:test:call-flow:byte-array-rejection",
    "ByteArray",
    73,
    "Method",
    [&harness, &inputArguments](const OneMethodNamespace& built)
    {
      inputArguments = harness.input_arguments(
        built.method, NodeId{built.index, 201}, 0, {"payload"}, NodeId{DataTypeId::Byte}, int32_t{1});
    });

  const auto outcome = harness.call(request_of({item_of(object, method, {Variant{String{"payload"}}})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& refusal = outcome.response->results()[0];
  EXPECT_EQ(refusal.status_code().value(), StatusCode{Status::BadInvalidArgument}.value());
  ASSERT_EQ(refusal.input_argument_results().size(), 1U);
  EXPECT_EQ(refusal.input_argument_results()[0].value(), StatusCode{Status::BadTypeMismatch}.value());
  EXPECT_TRUE(refusal.output_arguments().empty());
  EXPECT_TRUE(nameSpace->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("ByteArray"));
  EXPECT_EQ(times_named(nameSpace->calls(), Member::ReadValues, inputArguments), 1U);
  harness.services.clear();
  harness.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.ByteArrayRejection");
  EXPECT_EQ(harness.responseCount->load(), 1U);
  EXPECT_TRUE(nameSpace->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("ByteArray"));
}

// @relation(AC-COMP-SVR-METHOD-INPUT-ARGUMENT-READ-01-RICH-UPSTREAM-FAILURES, scope=function)
TEST(CallFlow, AFailedInputArgumentsReadIsTheItemsAnswer)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:input-argument-failures", harness.threadPool.get_executor());
  const auto index = harness.setup({nameSpace}).at(0);
  std::vector<NodeId> objects;
  std::vector<NodeId> methods;
  std::vector<NodeId> inputArguments;
  for (uint32_t ordinal = 1; ordinal <= 3; ++ordinal)
  {
    objects.push_back(
      harness.create(NodeId{index, 100 + ordinal}, "Object" + std::to_string(ordinal), NodeClass::Object));
    methods.push_back(
      harness.create(NodeId{index, 200 + ordinal}, "Method" + std::to_string(ordinal), NodeClass::Method));
    harness.link(objects.back(), ReferenceTypeId::HasComponent, methods.back());
    harness.handle(
      *nameSpace, methods.back(), "Method" + std::to_string(ordinal), numeric_cast<int32_t>(ordinal));
    if (ordinal < 3)
    {
      inputArguments.push_back(harness.input_arguments(methods.back(), NodeId{index, 300 + ordinal}, 0, {}));
    }
  }
  StatusCode referencesRefusal{Status::BadCommunicationError,
    ErrorDetail::build(
      "InputArgumentsReferencesRefusal", "Method Properties could not be read", "CallFlow.InputArguments")};
  referencesRefusal.structure_changed(true);
  StatusCode lookupRefusal{Status::BadResourceUnavailable,
    ErrorDetail::build("InputArgumentsLookupRefusal",
      "The InputArguments Property could not be resolved",
      "CallFlow.InputArguments")};
  lookupRefusal.semantics_changed(true);
  ASSERT_NE(referencesRefusal.value(), StatusCode{Status::BadCommunicationError}.value());
  ASSERT_NE(lookupRefusal.value(), StatusCode{Status::BadResourceUnavailable}.value());
  ASSERT_NE(referencesRefusal.shared_detail(), nullptr);
  ASSERT_NE(lookupRefusal.shared_detail(), nullptr);
  ASSERT_NE(referencesRefusal.shared_detail(), lookupRefusal.shared_detail());
  const auto refusalQuery = times_named(nameSpace->calls(), Member::ReadReferences, methods[0]) + 1;
  nameSpace->answer_reference_query_of(methods[0], refusalQuery, referencesRefusal);
  nameSpace->answer_lookup_of(inputArguments[1], lookupRefusal);
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();

  const auto outcome = harness.call(request_of(
    {item_of(objects[0], methods[0]), item_of(objects[1], methods[1]), item_of(objects[2], methods[2])}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 3U);
  const auto& referencesAnswer = outcome.response->results()[0];
  EXPECT_EQ(referencesAnswer.status_code().value(), referencesRefusal.value());
  EXPECT_EQ(referencesAnswer.status_code().shared_detail(), referencesRefusal.shared_detail());
  EXPECT_TRUE(referencesAnswer.output_arguments().empty());
  const auto& lookupAnswer = outcome.response->results()[1];
  EXPECT_EQ(lookupAnswer.status_code().value(), lookupRefusal.value());
  EXPECT_EQ(lookupAnswer.status_code().shared_detail(), lookupRefusal.shared_detail());
  EXPECT_TRUE(lookupAnswer.output_arguments().empty());
  expect_good_with_output(outcome, 2, 3);
  EXPECT_EQ(outcome.response->results()[2].status_code().value(), StatusCode{Status::Good}.value());
  EXPECT_FALSE(harness.log->has_run("Method1"));
  EXPECT_FALSE(harness.log->has_run("Method2"));
  EXPECT_TRUE(harness.log->has_run("Method3"));
  const auto dispatched = nameSpace->calls(Member::Call);
  ASSERT_EQ(dispatched.size(), 1U);
  EXPECT_EQ(dispatched[0].nodeIds, (std::vector<NodeId>{objects[2]}));
  harness.services.clear();
  harness.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.InputArgumentsFailures");
  EXPECT_EQ(harness.responseCount->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("Method1"));
  EXPECT_FALSE(harness.log->has_run("Method2"));
  EXPECT_EQ(nameSpace->calls(Member::Call).size(), 1U);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-TYPE-FACTS-ARE-RESOLVED-ONCE-PER-REQUEST, scope=function)
TEST(CallFlow, TypeFactsAreResolvedOncePerRequest)
{
  CallHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:type-facts", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId t1 = harness.create(NodeId{index, 300}, "T1", NodeClass::ObjectType);
  const NodeId t2 = harness.create(NodeId{index, 301}, "T2", NodeClass::ObjectType);
  harness.link(t1, ReferenceTypeId::HasSubtype, t2);
  const NodeId method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  harness.link(t1, ReferenceTypeId::HasComponent, method);
  harness.handle(*r, method, "M", 9);
  std::vector<CallMethodRequest> items;
  for (uint32_t k = 0; k < 4; ++k)
  {
    const NodeId object =
      harness.create(NodeId{index, 100 + k}, "Object" + std::to_string(k), NodeClass::Object);
    harness.type(object, t2);
    items.push_back(item_of(object, method));
  }
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->reset();
  harness.log->watched = {r};

  const auto outcome = harness.call(request_of(std::move(items)));

  ASSERT_TRUE(outcome.answered);
  const auto atFirst = harness.log->first_handler_calls(0);
  EXPECT_EQ(times_named(atFirst, Member::BatchedLookup, t2), 1U)
    << "the times T2 is named in find_nodes_async calls before the first handler";
  EXPECT_EQ(times_named(atFirst, Member::ReadReferences, t2), 1U)
    << "the times T2 is named in read_references_async calls before the first handler";
  EXPECT_EQ(times_named(atFirst, Member::ReadReferences, t1), 1U)
    << "the times T1 is named in read_references_async calls before the first handler";
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 4U);
  for (std::size_t k = 0; k < 4; ++k)
  {
    expect_good_with_output(outcome, k, 9);
  }
}

// Case 1: the lookups of a Method and of an Object.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-ITEM, scope=function)
TEST(CallFlow, AnUncertainLookupAnswerRefusesOnlyItsItem)
{
  CallHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:uncertain", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  std::vector<NodeId> objects;
  std::vector<NodeId> methods;
  for (uint32_t i = 1; i <= 4; ++i)
  {
    objects.push_back(harness.create(NodeId{index, 100 + i}, "O" + std::to_string(i), NodeClass::Object));
    methods.push_back(harness.create(NodeId{index, 200 + i}, "M" + std::to_string(i), NodeClass::Method));
    harness.link(objects.back(), ReferenceTypeId::HasComponent, methods.back());
    harness.handle(*r, methods.back(), "M" + std::to_string(i), static_cast<int32_t>(i));
  }
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->answer_lookup_of(methods[0], StatusCode{uncertainAnswer});
  r->answer_lookup_of(objects[1], StatusCode{uncertainAnswer});
  r->reset();

  std::vector<CallMethodRequest> items;
  for (std::size_t i = 0; i < 4; ++i)
  {
    items.push_back(item_of(objects[i], methods[i]));
  }
  const auto outcome = harness.call(request_of(std::move(items)));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 4U);
  expect_uncertain_lookup_refusal(outcome, 0);
  expect_uncertain_lookup_refusal(outcome, 1);
  expect_good_with_output(outcome, 2, 3);
  expect_good_with_output(outcome, 3, 4);
  EXPECT_FALSE(harness.log->has_run("M1")) << "M1's handler ran";
  EXPECT_FALSE(harness.log->has_run("M2")) << "M2's handler ran";
}

// Case 2: the lookup of a Method's InputArguments Property. Reaching the assertions is the observation that
// the process keeps running.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-ITEM, scope=function)
TEST(CallFlow, AnUncertainInputArgumentsLookupAnswerRefusesOnlyItsItem)
{
  CallHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:uncertain-input-arguments", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  std::vector<NodeId> objects;
  std::vector<NodeId> methods;
  std::vector<NodeId> inputArguments;
  for (uint32_t i = 1; i <= 2; ++i)
  {
    objects.push_back(harness.create(NodeId{index, 100 + i}, "P" + std::to_string(i), NodeClass::Object));
    methods.push_back(harness.create(NodeId{index, 200 + i}, "N" + std::to_string(i), NodeClass::Method));
    harness.link(objects.back(), ReferenceTypeId::HasComponent, methods.back());
    inputArguments.push_back(harness.input_arguments(methods.back(), NodeId{index, 300 + i}, 0, {}));
    harness.handle(*r, methods.back(), "N" + std::to_string(i), static_cast<int32_t>(i));
  }
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->answer_lookup_of(inputArguments[0], StatusCode{uncertainAnswer});
  r->reset();

  const auto outcome =
    harness.call(request_of({item_of(objects[0], methods[0]), item_of(objects[1], methods[1])}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  expect_uncertain_lookup_refusal(outcome, 0);
  expect_good_with_output(outcome, 1, 2);
  EXPECT_FALSE(harness.log->has_run("N1")) << "N1's handler ran";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-THE-INPUT-ARGUMENTS-PROPERTY-IS-THE-ONE-OF-NAMESPACE-ZERO, scope=function)
TEST(CallFlow, TheInputArgumentsPropertyIsTheOneOfNamespaceZero)
{
  CallHarness harness;
  auto n = ua::default_ns::Namespace::create(
    "urn:test:call-flow:input-arguments", harness.threadPool.get_executor());
  const auto index = harness.setup({n}).at(0);
  ASSERT_GT(index, 0U);
  const NodeId object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const NodeId method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, method);
  harness.input_arguments(method, NodeId{index, 201}, index, {"own"});
  harness.input_arguments(method, NodeId{index, 202}, 0, {"first", "second"});
  harness.handle(*n, method, "M", 3);

  const auto outcome =
    harness.call(request_of({item_of(object, method, {Variant{int32_t{11}}, Variant{int32_t{12}}})}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 3);
  std::lock_guard lock(harness.log->mutex);
  const auto& received = harness.log->inputs["M"];
  ASSERT_EQ(received.size(), 2U) << "the arguments M's handler received";
  ASSERT_TRUE(received[0].is_int32());
  ASSERT_TRUE(received[1].is_int32());
  EXPECT_EQ(received[0].as<int32_t>(), 11);
  EXPECT_EQ(received[1].as<int32_t>(), 12);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-THE-HOOK-RUNS-ONLY-FOR-A-STATE-MACHINE, scope=function)
TEST(CallFlow, TheHookRunsOnlyForAStateMachine)
{
  CallHarness harness;
  const auto [r, index, object, method] = one_method_namespace(harness, "urn:test:call-flow:hook", "M", 1);
  harness.log->watched = {r};

  const auto outcome = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 1);
  ASSERT_TRUE(harness.log->has_run("M"));
  const auto atHandler = harness.log->first_handler_calls(0);
  const std::size_t lastBefore = atHandler.empty() ? 0 : atHandler.back().sequence;
  std::string after;
  for (const auto& call : r->calls())
  {
    if (call.sequence > lastBefore)
    {
      after += " #" + std::to_string(call.sequence) + " (Member " +
               std::to_string(static_cast<int>(call.member)) + ")";
    }
  }
  EXPECT_TRUE(after.empty()) << "R received calls after M's handler had run:" << after;
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-A-FAILED-PROPERTY-LOOKUP-AFTER-INPUT-ARGUMENTS-DOES-NOT-FAIL-THE-CALL, scope=function)
TEST(CallFlow, AFailedPropertyLookupAfterInputArgumentsDoesNotFailTheCall)
{
  CallHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:properties", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId objectA = harness.create(NodeId{index, 100}, "ObjectA", NodeClass::Object);
  const NodeId objectB = harness.create(NodeId{index, 101}, "ObjectB", NodeClass::Object);
  const NodeId methodA = harness.create(NodeId{index, 200}, "MethodA", NodeClass::Method);
  const NodeId methodB = harness.create(NodeId{index, 201}, "MethodB", NodeClass::Method);
  harness.link(objectA, ReferenceTypeId::HasComponent, methodA);
  harness.link(objectB, ReferenceTypeId::HasComponent, methodB);
  const NodeId p1 = harness.create(NodeId{index, 400}, "P1", NodeClass::Variable);
  const NodeId p2 = harness.create(NodeId{index, 401}, "P2", NodeClass::Variable);
  harness.link(methodA, ReferenceTypeId::HasProperty, p1);
  harness.input_arguments(methodA, NodeId{index, 300}, 0, {});
  harness.input_arguments(methodB, NodeId{index, 301}, 0, {});
  harness.link(methodB, ReferenceTypeId::HasProperty, p2);
  harness.handle(*r, methodA, "A", 1);
  harness.handle(*r, methodB, "B", 2);
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->answer_lookup_of(p1, StatusCode{Status::BadNodeIdUnknown});
  r->answer_lookup_of(p2, StatusCode{Status::BadNodeIdUnknown});
  r->reset();

  const auto outcome = harness.call(request_of({item_of(objectA, methodA), item_of(objectB, methodB)}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  const auto& first = outcome.response->results()[0].status_code();
  EXPECT_EQ(first.as_status(), Status::BadNodeIdUnknown) << "the first item: " << to_string(first);
  expect_good_with_output(outcome, 1, 2);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-A-METHOD-OF-AN-UNKNOWN-NAMESPACE-IS-BAD-METHOD-INVALID, scope=function)
TEST(CallFlow, AMethodOfAnUnknownNamespaceIsBadMethodInvalid)
{
  CallHarness harness;
  auto n = ua::default_ns::Namespace::create(
    "urn:test:call-flow:unknown-namespace", harness.threadPool.get_executor());
  const auto index = harness.setup({n}).at(0);
  const NodeId object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const NodeId method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, method);
  harness.handle(*n, method, "M", 1);
  constexpr uint16_t unknownIndex = 250;
  ASSERT_LT(harness.sessionInfo->address_space().namespace_array().get_namespace_array().size(),
    std::size_t{unknownIndex})
    << "the server must not have the namespace index the test calls unknown";

  const auto outcome = harness.call(request_of({item_of(object, NodeId{unknownIndex, uint32_t{200}}),
    item_of(NodeId{unknownIndex, uint32_t{100}}, method)}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  const auto& first = outcome.response->results()[0].status_code();
  const auto& second = outcome.response->results()[1].status_code();
  EXPECT_EQ(first.as_status(), Status::BadMethodInvalid) << "the unknown Method: " << to_string(first);
  EXPECT_EQ(second.as_status(), Status::BadNodeIdUnknown) << "the unknown Object: " << to_string(second);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-AN-UNCERTAIN-READ-ANSWER-REFUSES-ONLY-ITS-ITEM, scope=function)
TEST(CallFlow, AnUncertainReadAnswerRefusesOnlyItsItem)
{
  CallHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:uncertain-reads", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  std::vector<NodeId> objects;
  std::vector<NodeId> methods;
  std::vector<NodeId> inputArguments;
  for (uint32_t i = 1; i <= 4; ++i)
  {
    objects.push_back(harness.create(NodeId{index, 100 + i}, "O" + std::to_string(i), NodeClass::Object));
    methods.push_back(harness.create(NodeId{index, 200 + i}, "M" + std::to_string(i), NodeClass::Method));
    harness.link(objects.back(), ReferenceTypeId::HasComponent, methods.back());
    inputArguments.push_back(harness.input_arguments(methods.back(), NodeId{index, 300 + i}, 0, {}));
    harness.handle(*r, methods.back(), "M" + std::to_string(i), static_cast<int32_t>(i));
  }
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->fail_value_reads_of(inputArguments[0], StatusCode{uncertainAnswer});
  // The References query to answer is counted over every query the namespace has received, the setup's
  // included.
  const auto before = r->calls(Member::ReadReferences);
  r->answer_reference_query_of(
    objects[1], times_named(before, Member::ReadReferences, objects[1]) + 1, StatusCode{uncertainAnswer});
  r->answer_reference_query_of(
    methods[2], times_named(before, Member::ReadReferences, methods[2]) + 1, StatusCode{uncertainAnswer});
  r->reset();

  std::vector<CallMethodRequest> items;
  for (std::size_t i = 0; i < 4; ++i)
  {
    items.push_back(item_of(objects[i], methods[i]));
  }
  const auto outcome = harness.call(request_of(std::move(items)));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 4U);
  const std::vector<std::string> details{
    "ReadAnswerUncertain", "ReferencesAnswerUncertain", "ReferencesAnswerUncertain"};
  for (std::size_t i = 0; i < details.size(); ++i)
  {
    const auto& status = outcome.response->results()[i].status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError) << "item " << i + 1 << ": " << to_string(status);
    EXPECT_EQ(detail_code(status), details[i]) << "item " << i + 1 << ": " << to_string(status);
    EXPECT_EQ(detail_cause(status), StatusCode{uncertainAnswer}.value())
      << "item " << i + 1 << ": the ErrorDetail's cause is not the Uncertain answer";
  }
  expect_good_with_output(outcome, 3, 4);
  EXPECT_FALSE(harness.log->has_run("M1")) << "M1's handler ran";
  EXPECT_FALSE(harness.log->has_run("M2")) << "M2's handler ran";
  EXPECT_FALSE(harness.log->has_run("M3")) << "M3's handler ran";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-18-A-CALL-ON-AN-OBJECT-DELETED-BEFORE-ITS-CALL-IS-BAD-NODE-ID-UNKNOWN, scope=function)
TEST(CallFlow, ACallOnAnObjectDeletedBeforeItsCallIsBadNodeIdUnknown)
{
  CallHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:deleted-object", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  // M is declared by O's type and O holds no Reference to M, so that deleting O leaves M.
  const NodeId type = harness.create(NodeId{index, 300}, "T", NodeClass::ObjectType);
  const NodeId method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  harness.link(type, ReferenceTypeId::HasComponent, method);
  const NodeId object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  harness.type(object, type);
  const NodeId inputArguments = harness.input_arguments(method, NodeId{index, 201}, 0, {});
  harness.handle(*r, method, "M", 1);
  r->decline_single_lookups();
  r->decline_immediate_permissions();

  // O is deleted when R receives the read of M's InputArguments Value, after the request's lookups.
  struct Deletion
  {
    std::mutex mutex;
    std::optional<StatusCode> status;
  };

  auto deletion = std::make_shared<Deletion>();
  r->on_value_read(
    [weak = std::weak_ptr<BatchRecordingNamespace>{r}, deletion, object, inputArguments](
      const RecordedCall& read)
    {
      auto self = weak.lock();
      if (!self || std::find(read.nodeIds.begin(), read.nodeIds.end(), inputArguments) == read.nodeIds.end())
      {
        return;
      }
      const std::lock_guard lock(deletion->mutex);
      if (!deletion->status)
      {
        deletion->status = self->delete_node(object, false).status_code();
      }
    });
  r->reset();

  const auto outcome = harness.call(request_of({item_of(object, method)}));

  {
    const std::lock_guard lock(deletion->mutex);
    ASSERT_TRUE(deletion->status.has_value())
      << "R received no read of M's InputArguments Value, so O was not deleted";
    ASSERT_TRUE(deletion->status->is_good()) << "deleting O: " << to_string(*deletion->status);
  }
  const auto methodNode = static_cast<ua::default_ns::Namespace&>(*r).find_node<Node>(method);
  ASSERT_TRUE(methodNode != nullptr && !methodNode->deleted()) << "deleting O deleted M too";
  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& status = outcome.response->results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadNodeIdUnknown) << to_string(status);
  EXPECT_FALSE(harness.log->has_run("M")) << "M's handler ran for a deleted Object";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-ONE-CALL-PER-NAMESPACE-PER-REQUEST, scope=function)
TEST(CallFlow, OneCallPerNamespacePerRequest)
{
  CallHarness harness;
  auto r1 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:calls-r1", harness.threadPool.get_executor());
  auto r2 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:calls-r2", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2});
  std::vector<CallMethodRequest> items;
  std::vector<NodeId> objectsOfR1;
  std::vector<NodeId> objectsOfR2;
  for (uint32_t k = 0; k < 6; ++k)
  {
    const bool first = k % 2 == 0;
    const uint16_t index = indexes.at(first ? 0 : 1);
    auto& nameSpace = first ? *r1 : *r2;
    const NodeId object =
      harness.create(NodeId{index, 100 + k}, "Object" + std::to_string(k), NodeClass::Object);
    const NodeId method =
      harness.create(NodeId{index, 200 + k}, "Method" + std::to_string(k), NodeClass::Method);
    harness.link(object, ReferenceTypeId::HasComponent, method);
    harness.handle(nameSpace, method, "M" + std::to_string(k), static_cast<int32_t>(1000 + k));
    items.push_back(item_of(object, method));
    (first ? objectsOfR1 : objectsOfR2).push_back(object);
  }
  for (const auto& r : {r1, r2})
  {
    r->decline_single_lookups();
    r->decline_immediate_permissions();
    r->reset();
  }

  const auto outcome = harness.call(request_of(std::move(items)));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  expect_one_call_of(r1->calls(Member::Call), objectsOfR1, "R1");
  expect_one_call_of(r2->calls(Member::Call), objectsOfR2, "R2");
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 6U);
  for (std::size_t k = 0; k < 6; ++k)
  {
    expect_good_with_output(outcome, k, static_cast<int32_t>(1000 + k));
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-THE-CALL-CARRIES-THE-REQUEST-AND-THE-CALLER, scope=function)
TEST(CallFlow, TheCallCarriesTheRequestAndTheCaller)
{
  CallHarness harness;
  const auto [r, index, object, method] =
    one_method_namespace(harness, "urn:test:call-flow:call-request", "M", 7);
  const auto identity = harness.sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr) << "the Session must hold an identity for this test to mean anything";

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.call(request_of({item_of(object, method)}, 5000));

  const auto calls = r->calls(Member::Call);
  EXPECT_FALSE(calls.empty()) << "R received no call_async";
  for (const auto& call : calls)
  {
    EXPECT_TRUE(call.hasRequest) << "call_async #" << call.sequence << " takes no RequestInfo";
    EXPECT_GE(call.deadline, sent + 4s) << "call_async #" << call.sequence << "'s deadline";
    EXPECT_LE(call.deadline, sent + 6s) << "call_async #" << call.sequence << "'s deadline";
    EXPECT_TRUE(call.hasCaller) << "call_async #" << call.sequence << " was given no CallerInfo";
    EXPECT_EQ(call.identity.get(), identity.get())
      << "call_async #" << call.sequence << "'s CallerInfo does not hold the Session's identity";
  }
  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 7);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-NAMESPACE-STILL-RUNNING-AT-THE-HINT-IS-TOLD-TO-STOP, scope=function)
TEST(CallFlow, ANamespaceStillRunningAtTheHintIsToldToStop)
{
  CallHarness harness;
  auto r1 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:hint-r1", harness.threadPool.get_executor());
  auto r2 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:hint-r2", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2});
  const NodeId object1 = harness.create(NodeId{indexes.at(0), 100}, "Object1", NodeClass::Object);
  const NodeId method1 = harness.create(NodeId{indexes.at(0), 200}, "Method1", NodeClass::Method);
  harness.link(object1, ReferenceTypeId::HasComponent, method1);
  harness.handle(*r1, method1, "M1", 1);
  const NodeId object2 = harness.create(NodeId{indexes.at(1), 100}, "Object2", NodeClass::Object);
  const NodeId method2 = harness.create(NodeId{indexes.at(1), 200}, "Method2", NodeClass::Method);
  harness.link(object2, ReferenceTypeId::HasComponent, method2);
  harness.handle(*r2, method2, "M2", 2);
  for (const auto& r : {r1, r2})
  {
    r->decline_single_lookups();
    r->decline_immediate_permissions();
    r->reset();
  }
  r2->hold_calls();

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.call(request_of({item_of(object1, method1), item_of(object2, method2)}, 300));
  const auto arrived = std::chrono::steady_clock::now();

  // What R2 was given, taken before it is released.
  const bool held = r2->wait_for_held_calls(1, 1000ms);
  const auto heldCalls = r2->calls(Member::Call);
  const RequestInfo heldRequest = r2->held_call_request(0);
  const bool cancelledAtResponse = heldRequest.cancelled && heldRequest.cancelled->load();
  r2->release_held_calls();

  ASSERT_TRUE(outcome.answered);
  EXPECT_GE(arrived, sent + 300ms) << "the response arrived before the timeoutHint";
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  expect_good_with_output(outcome, 0, 1);
  const auto& second = outcome.response->results()[1].status_code();
  EXPECT_EQ(second.as_status(), Status::BadTimeout) << "the second item: " << to_string(second);
  ASSERT_TRUE(held) << "R2 held no call_async";
  ASSERT_FALSE(heldCalls.empty());
  EXPECT_LE(heldCalls.front().deadline, sent + 350ms) << "the deadline of R2's call_async";
  EXPECT_TRUE(cancelledAtResponse)
    << "the cancellation flag of R2's RequestInfo is not set after the response";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-DENIED-ITEM-DOES-NOT-REACH-THE-NAMESPACE, scope=function)
TEST(CallFlow, ADeniedItemDoesNotReachTheNamespace)
{
  CallHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:call-denied", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  std::vector<NodeId> objects;
  std::vector<NodeId> methods;
  for (uint32_t i = 1; i <= 3; ++i)
  {
    objects.push_back(harness.create(NodeId{index, 100 + i}, "O" + std::to_string(i), NodeClass::Object));
    methods.push_back(harness.create(NodeId{index, 200 + i}, "M" + std::to_string(i), NodeClass::Method));
    harness.link(objects.back(), ReferenceTypeId::HasComponent, methods.back());
    harness.handle(*r, methods.back(), "M" + std::to_string(i), static_cast<int32_t>(i));
  }
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  // Every permission but Call on the second Method; every permission on the other Nodes.
  auto withoutCall = ua::test_helpers::all_permissions();
  withoutCall.reset(PermissionType::Bit::Call);
  r->grant(methods[1], withoutCall);
  r->reset();

  const auto outcome = harness.call(request_of(
    {item_of(objects[0], methods[0]), item_of(objects[1], methods[1]), item_of(objects[2], methods[2])}));

  ASSERT_TRUE(outcome.answered);
  expect_one_call_of(r->calls(Member::Call), {objects[0], objects[2]}, "R");
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 3U);
  expect_good_with_output(outcome, 0, 1);
  const auto& second = outcome.response->results()[1].status_code();
  EXPECT_EQ(second.as_status(), Status::BadUserAccessDenied) << "the second item: " << to_string(second);
  expect_good_with_output(outcome, 2, 3);
  EXPECT_TRUE(outcome.response->results()[1].output_arguments().empty());
  EXPECT_FALSE(harness.log->has_run("M2"));
  EXPECT_EQ(harness.responseCount->load(), 1U);
  const auto firstCalls = r->calls(Member::Call);
  ASSERT_EQ(firstCalls.size(), 1U);
  EXPECT_EQ(firstCalls[0].methodRequests,
    (std::vector<CallMethodRequest>{item_of(objects[0], methods[0]), item_of(objects[2], methods[2])}));

  CallMethodResult firstAnswer;
  firstAnswer.status_code() = Status::Good;
  firstAnswer.output_arguments().push_back(Variant{int32_t{41}});
  CallMethodResult thirdAnswer;
  thirdAnswer.status_code() = Status::Good;
  thirdAnswer.output_arguments().push_back(Variant{int32_t{42}});
  thirdAnswer.output_arguments().push_back(Variant{int32_t{43}});
  thirdAnswer.output_arguments().push_back(Variant{int32_t{44}});
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  r->answer_calls(
    [firstMethod = methods[0], firstAnswer, thirdAnswer, scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      BatchResult<std::optional<CallResult>> answer;
      for (const auto& request : call.methodRequests)
      {
        auto result = thirdAnswer;
        if (request.method_id() == firstMethod)
        {
          result = firstAnswer;
        }
        answer.items.emplace_back(CallResult{std::move(result)});
      }
      return answer;
    });
  r->reset();
  const std::vector<CallMethodRequest> repeatedItems{
    item_of(objects[0], methods[0]), item_of(objects[1], methods[1]), item_of(objects[2], methods[2])};
  CallOutcome repeated;
  ASSERT_NO_THROW(repeated = harness.call(request_of(repeatedItems)));

  ASSERT_TRUE(repeated.answered);
  EXPECT_EQ(repeated.serviceResult.value(), StatusCode{Status::Good}.value());
  const auto repeatedCalls = r->calls(Member::Call);
  expect_one_call_of(repeatedCalls, {objects[0], objects[2]}, "R's repeated filtered Call");
  ASSERT_EQ(repeatedCalls.size(), 1U);
  EXPECT_EQ(
    repeatedCalls[0].methodRequests, (std::vector<CallMethodRequest>{repeatedItems[0], repeatedItems[2]}));
  EXPECT_EQ(scriptCalls->load(), 1U);
  ASSERT_TRUE(repeated.response.has_value());
  ASSERT_EQ(repeated.response->results().size(), 3U);
  EXPECT_EQ(repeated.response->results()[0], firstAnswer);
  ASSERT_EQ(repeated.response->results()[0].output_arguments().size(), 1U);
  EXPECT_EQ(
    repeated.response->results()[1].status_code().value(), StatusCode{Status::BadUserAccessDenied}.value());
  EXPECT_TRUE(repeated.response->results()[1].output_arguments().empty());
  EXPECT_EQ(repeated.response->results()[2], thirdAnswer);
  ASSERT_EQ(repeated.response->results()[2].output_arguments().size(), 3U);
  EXPECT_FALSE(harness.log->has_run("M2"));
  EXPECT_EQ(harness.responseCount->load(), 2U);
  EXPECT_EQ(harness.responseCount->load(), 2U);
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_EQ(r->calls(Member::Call).size(), 1U);
  EXPECT_FALSE(harness.log->has_run("M2"));
  r->reset();
  CallOutcome deniedOnly;
  ASSERT_NO_THROW(deniedOnly = harness.call(request_of({item_of(objects[1], methods[1])})));

  ASSERT_TRUE(deniedOnly.answered);
  EXPECT_EQ(deniedOnly.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(deniedOnly.response.has_value());
  ASSERT_EQ(deniedOnly.response->results().size(), 1U);
  EXPECT_EQ(
    deniedOnly.response->results()[0].status_code().value(), StatusCode{Status::BadUserAccessDenied}.value());
  EXPECT_TRUE(deniedOnly.response->results()[0].output_arguments().empty());
  EXPECT_EQ(harness.responseCount->load(), 3U);
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_TRUE(r->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("M2"));
  harness.services.clear();
  harness.sessionInfo.reset();
  ASSERT_NO_THROW(
    ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.DeniedSubsetOutputs"));
  EXPECT_EQ(harness.responseCount->load(), 3U);
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_TRUE(r->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("M2"));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-FAILED-DEFAULT-ITEM-DOES-NOT-ERASE-ANOTHER-NAMESPACES-ANSWER, scope=function)
TEST(CallFlow, AFailedDefaultItemDoesNotEraseAnotherNamespacesAnswer)
{
  CallHarness harness;
  auto overriding = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:mixed-preservation-override", harness.threadPool.get_executor());
  auto ordinary = ua::default_ns::Namespace::create(
    "urn:test:call-flow:mixed-preservation-default", harness.threadPool.get_executor());
  const auto indexes = harness.setup({overriding, ordinary});
  const auto object = harness.create(NodeId{indexes.at(0), 100}, "Object", NodeClass::Object);
  const auto method = harness.create(NodeId{indexes.at(0), 200}, "Method", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, method);
  harness.handle(*overriding, method, "OverrideControl", 1);
  const auto ordinaryObject = harness.create(NodeId{indexes.at(1), 100}, "OrdinaryObject", NodeClass::Object);
  const NodeId missingMethod{indexes.at(1), 200};
  ASSERT_NE(ordinary->find_node<Node>(ordinaryObject), nullptr);
  ASSERT_EQ(ordinary->find_node<Node>(missingMethod), nullptr);
  CallMethodResult supplied;
  supplied.status_code() = Status::Good;
  supplied.output_arguments().push_back(Variant{int32_t{19}});
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  overriding->answer_calls(
    [supplied, scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t item = 0; item < call.methodRequests.size(); ++item)
      {
        answer.items.emplace_back(CallResult{supplied});
      }
      return answer;
    });
  overriding->decline_single_lookups();
  overriding->decline_immediate_permissions();
  overriding->reset();
  const std::vector<CallMethodRequest> items{item_of(object, method), item_of(ordinaryObject, missingMethod)};

  CallOutcome outcome;
  ASSERT_NO_THROW(outcome = harness.call(request_of(items)));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(outcome.response->results()[0], supplied);
  EXPECT_EQ(outcome.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  expect_good_with_output(outcome, 0, 19);
  EXPECT_EQ(
    outcome.response->results()[1].status_code().value(), StatusCode{Status::BadMethodInvalid}.value());
  EXPECT_TRUE(outcome.response->results()[1].output_arguments().empty());
  const auto calls = overriding->calls(Member::Call);
  ASSERT_EQ(calls.size(), 1U);
  EXPECT_EQ(calls[0].nodeIds, (std::vector<NodeId>{object}));
  EXPECT_EQ(calls[0].methodRequests, (std::vector<CallMethodRequest>{items[0]}));
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("OverrideControl"));
  EXPECT_EQ(harness.responseCount->load(), 1U);
  harness.services.clear();
  harness.sessionInfo.reset();
  ASSERT_NO_THROW(
    ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.MixedAnswerPreservation"));
  EXPECT_EQ(harness.responseCount->load(), 1U);
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_EQ(overriding->calls(Member::Call).size(), 1U);
  EXPECT_FALSE(harness.log->has_run("OverrideControl"));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-BAD-INTERNAL-ERROR-KEEPS-ITS-STATUS-AND-DETAIL, scope=function)
TEST(CallFlow, ABadInternalErrorKeepsItsStatusAndDetail)
{
  CallHarness harness;
  const auto [nameSpace, index, object, method] =
    one_method_namespace(harness, "urn:test:call-flow:embedded-internal-error", "EmbeddedErrorControl", 1);
  const shared_ptr<const ErrorDetail> suppliedDetail =
    ErrorDetail::build("NamespaceMethodInternalError", "The namespace cannot complete the Method", "CallFlow")
      .detail("The retained namespace detail of the embedded Method failure");
  StatusCode suppliedStatus{Status::BadInternalError, suppliedDetail};
  suppliedStatus.semantics_changed(true);
  CallMethodResult refusedAnswer;
  refusedAnswer.status_code() = suppliedStatus;
  CallMethodResult permittedAnswer;
  permittedAnswer.status_code() = Status::Good;
  permittedAnswer.output_arguments().push_back(Variant{int32_t{29}});
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  nameSpace->answer_calls(
    [refusedAnswer, permittedAnswer, scriptCalls](const RecordedCall& call)
    {
      const auto invocation = scriptCalls->fetch_add(1);
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t item = 0; item < call.methodRequests.size(); ++item)
      {
        auto result = permittedAnswer;
        if (invocation == 0)
        {
          result = refusedAnswer;
        }
        answer.items.emplace_back(CallResult{std::move(result)});
      }
      return answer;
    });
  const std::vector<CallMethodRequest> items{item_of(object, method)};

  CallOutcome refused;
  ASSERT_NO_THROW(refused = harness.call(request_of(items)));

  ASSERT_TRUE(refused.answered);
  EXPECT_EQ(refused.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(refused.response.has_value());
  ASSERT_EQ(refused.response->results().size(), 1U);
  const auto& result = refused.response->results()[0];
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  EXPECT_EQ(result.status_code().value(), suppliedStatus.value());
  EXPECT_EQ(result.status_code().shared_detail(), suppliedDetail);
  EXPECT_TRUE(result.output_arguments().empty());
  const auto refusedCalls = nameSpace->calls(Member::Call);
  ASSERT_EQ(refusedCalls.size(), 1U);
  EXPECT_EQ(refusedCalls[0].nodeIds, (std::vector<NodeId>{object}));
  EXPECT_EQ(refusedCalls[0].methodRequests, items);
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("EmbeddedErrorControl"));
  EXPECT_EQ(harness.responseCount->load(), 1U);
  nameSpace->reset();

  CallOutcome permitted;
  ASSERT_NO_THROW(permitted = harness.call(request_of(items)));

  ASSERT_TRUE(permitted.answered);
  EXPECT_EQ(permitted.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(permitted.response.has_value());
  ASSERT_EQ(permitted.response->results().size(), 1U);
  EXPECT_EQ(permitted.response->results()[0], permittedAnswer);
  EXPECT_EQ(permitted.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  expect_good_with_output(permitted, 0, 29);
  const auto permittedCalls = nameSpace->calls(Member::Call);
  ASSERT_EQ(permittedCalls.size(), 1U);
  EXPECT_EQ(permittedCalls[0].nodeIds, (std::vector<NodeId>{object}));
  EXPECT_EQ(permittedCalls[0].methodRequests, items);
  EXPECT_EQ(scriptCalls->load(), 2U);
  EXPECT_FALSE(harness.log->has_run("EmbeddedErrorControl"));
  EXPECT_EQ(harness.responseCount->load(), 2U);
  harness.services.clear();
  harness.sessionInfo.reset();
  ASSERT_NO_THROW(
    ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.EmbeddedInternalError"));
  EXPECT_EQ(harness.responseCount->load(), 2U);
  EXPECT_EQ(scriptCalls->load(), 2U);
  EXPECT_EQ(nameSpace->calls(Member::Call).size(), 1U);
  EXPECT_FALSE(harness.log->has_run("EmbeddedErrorControl"));
}

// @relation(AC-SVR-METH-CALL-042-THE-DELEGATE-PATH-CHECKS-EXECUTABLE, scope=function)
TEST(CallFlow, ANonExecutableMethodIsNotGivenToItsNamespace)
{
  CallHarness harness;
  const auto [nameSpace, index, object, method] = one_method_namespace(harness,
    "urn:test:call-flow:executable",
    "Executable",
    83,
    "Method",
    [&harness](const OneMethodNamespace& built)
    {
      auto found = harness.sessionInfo->address_space().try_find_node_sync(built.method);
      ASSERT_TRUE(found.is_good());
      auto accessor = found.value().as<MethodAccessor>();
      ASSERT_TRUE(accessor.has_value());
      accessor->set_executable(false);
    });
  nameSpace->grant(object, ua::test_helpers::all_permissions());
  nameSpace->grant(method, ua::test_helpers::all_permissions());

  const auto outcome = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& refusal = outcome.response->results()[0];
  EXPECT_EQ(refusal.status_code().value(), StatusCode{Status::BadNotExecutable}.value());
  EXPECT_TRUE(refusal.output_arguments().empty());
  EXPECT_TRUE(nameSpace->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("Executable"));
  harness.services.clear();
  harness.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.NonExecutableMethod");
  EXPECT_EQ(harness.responseCount->load(), 1U);
  EXPECT_TRUE(nameSpace->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("Executable"));
}

// @relation(AC-SVR-METH-CALL-042-THE-DELEGATE-PATH-CHECKS-EXECUTABLE, scope=function)
TEST(CallFlow, AnExecutableMethodIsGivenToItsNamespace)
{
  CallHarness harness;
  const auto [nameSpace, index, object, method] = one_method_namespace(harness,
    "urn:test:call-flow:executable",
    "Executable",
    83,
    "Method",
    [&harness](const OneMethodNamespace& built)
    {
      auto found = harness.sessionInfo->address_space().try_find_node_sync(built.method);
      ASSERT_TRUE(found.is_good());
      auto accessor = found.value().as<MethodAccessor>();
      ASSERT_TRUE(accessor.has_value());
      accessor->set_executable(true);
    });
  nameSpace->grant(object, ua::test_helpers::all_permissions());
  nameSpace->grant(method, ua::test_helpers::all_permissions());
  const auto identity = harness.sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr);

  const auto outcome = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 83);
  EXPECT_EQ(outcome.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  EXPECT_TRUE(harness.log->has_run("Executable"));
  const auto dispatched = nameSpace->calls(Member::Call);
  ASSERT_EQ(dispatched.size(), 1U);
  EXPECT_EQ(dispatched[0].nodeIds, (std::vector<NodeId>{object}));
  EXPECT_TRUE(dispatched[0].hasCaller);
  EXPECT_EQ(dispatched[0].identity.get(), identity.get());
  harness.services.clear();
  harness.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.ExecutableMethod");
  EXPECT_EQ(harness.responseCount->load(), 1U);
  EXPECT_EQ(nameSpace->calls(Member::Call).size(), 1U);
}

// @relation(AC-SVR-AUTHZ-007-CALL-OBJECT-HALF, scope=function)
TEST(CallFlow, AnObjectTheSessionMayNotCallIsNotGivenToItsNamespace)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:object-call-permission", harness.threadPool.get_executor());
  const auto index = harness.setup({nameSpace}).at(0);
  const auto objectType = harness.create(NodeId{index, 300}, "ObjectType", NodeClass::ObjectType);
  const auto method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  harness.link(objectType, ReferenceTypeId::HasComponent, method);
  harness.type(object, objectType);
  harness.handle(*nameSpace, method, "TypeLevelMethod", 97);
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  const auto allPermissions = ua::test_helpers::all_permissions();
  auto withoutCall = allPermissions;
  withoutCall.reset(PermissionType::Bit::Call);
  nameSpace->grant(method, allPermissions);
  nameSpace->grant(object, withoutCall);
  nameSpace->reset();
  const auto identity = harness.sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr);

  const auto refused = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(refused.answered);
  EXPECT_EQ(refused.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(refused.response.has_value());
  ASSERT_EQ(refused.response->results().size(), 1U);
  EXPECT_EQ(
    refused.response->results()[0].status_code().value(), StatusCode{Status::BadUserAccessDenied}.value());
  EXPECT_TRUE(refused.response->results()[0].output_arguments().empty());
  EXPECT_TRUE(nameSpace->calls(Member::Call).empty());
  EXPECT_FALSE(harness.log->has_run("TypeLevelMethod"));
  for (const auto& permission : nameSpace->calls(Member::PermissionsAsyncForRequest))
  {
    EXPECT_EQ(permission.identity.get(), identity.get());
  }

  // The same Object and type-level Method become callable when both retain Call permission.
  nameSpace->grant(object, allPermissions);
  nameSpace->reset();
  const auto permitted = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(permitted.answered);
  EXPECT_EQ(permitted.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(permitted.response.has_value());
  ASSERT_EQ(permitted.response->results().size(), 1U);
  expect_good_with_output(permitted, 0, 97);
  EXPECT_EQ(permitted.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  EXPECT_TRUE(harness.log->has_run("TypeLevelMethod"));
  const auto dispatched = nameSpace->calls(Member::Call);
  ASSERT_EQ(dispatched.size(), 1U);
  EXPECT_EQ(dispatched[0].nodeIds, (std::vector<NodeId>{object}));
  EXPECT_TRUE(dispatched[0].hasCaller);
  EXPECT_EQ(dispatched[0].identity.get(), identity.get());
  for (const auto& permission : nameSpace->calls(Member::PermissionsAsyncForRequest))
  {
    EXPECT_EQ(permission.identity.get(), identity.get());
  }
  harness.services.clear();
  harness.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.ObjectCallPermission");
  EXPECT_EQ(harness.responseCount->load(), 2U);
  EXPECT_EQ(nameSpace->calls(Member::Call).size(), 1U);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-DECLINED-ITEMS-ARE-OFFERED-TO-THE-METHODS-NAMESPACE-IN-ONE-CALL, scope=function)
TEST(CallFlow, DeclinedItemsAreOfferedToTheMethodsNamespaceInOneCall)
{
  CallHarness harness;
  auto r1 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:declined-r1", harness.threadPool.get_executor());
  auto r2 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:declined-r2", harness.threadPool.get_executor());
  auto r3 =
    make_shared<BatchRecordingNamespace>("urn:test:call-flow:declined-r3", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2, r3});
  std::vector<NodeId> objects;
  std::vector<NodeId> methods;
  for (uint32_t k = 0; k < 3; ++k)
  {
    objects.push_back(
      harness.create(NodeId{indexes.at(0), 100 + k}, "Object" + std::to_string(k), NodeClass::Object));
    methods.push_back(
      harness.create(NodeId{indexes.at(1), 200 + k}, "Method" + std::to_string(k), NodeClass::Method));
    harness.link(objects.back(), ReferenceTypeId::HasComponent, methods.back());
    harness.handle(*r2, methods.back(), "M" + std::to_string(k), static_cast<int32_t>(10 + k));
  }
  const NodeId object3 = harness.create(NodeId{indexes.at(2), 100}, "Object3", NodeClass::Object);
  const NodeId method3 = harness.create(NodeId{indexes.at(2), 200}, "Method3", NodeClass::Method);
  harness.link(object3, ReferenceTypeId::HasComponent, method3);
  harness.handle(*r3, method3, "M3", 13);
  for (const auto& r : {r1, r2, r3})
  {
    r->decline_single_lookups();
    r->decline_immediate_permissions();
    r->reset();
  }
  r1->decline_calls();
  r3->hold_calls();

  auto pending = harness.start(request_of({item_of(objects[0], methods[0]),
                                            item_of(objects[1], methods[1]),
                                            item_of(objects[2], methods[2]),
                                            item_of(object3, method3)},
    5000));
  // R3 is released once R2 has answered, which is after its three Methods' handlers have run.
  const bool r2Answered = wait_until([&harness]
    { return harness.log->has_run("M0") && harness.log->has_run("M1") && harness.log->has_run("M2"); },
    3000ms);
  const auto r1Calls = r1->calls(Member::Call);
  const auto r2Calls = r2->calls(Member::Call);
  r3->release_held_calls();
  const auto outcome = CallHarness::await(pending);

  EXPECT_TRUE(r2Answered) << "R2's three Methods had not run 3 s after the request, while R3 held its call";
  expect_one_call_of(r1Calls, objects, "R1");
  expect_one_call_of(r2Calls, objects, "R2 (before R3 was released)");
  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 4U);
  for (std::size_t k = 0; k < 4; ++k)
  {
    expect_good_with_output(outcome, k, static_cast<int32_t>(10 + k));
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-LATE-ANSWER-IS-AUDITED, scope=function)
TEST(CallFlow, ALateAnswerIsAudited)
{
  shared_ptr<MethodAuditBus> bus;
  CallHarness harness;

  // Keep the bus alive while services finish, then release its strand before the executor is destroyed,
  // on every exit from the test, including a failed ASSERT.
  struct ReleaseBusBeforeExecutor
  {
    CallHarness& harness;
    shared_ptr<MethodAuditBus>& bus;

    ~ReleaseBusBeforeExecutor()
    {
      harness.shutdown();
      bus.reset();
    }
  } releaseBus{harness, bus};

  auto r = make_shared<BatchRecordingNamespace>("urn:test:call-flow:late", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  const auto index = harness.setup({r}, std::move(serverConfig)).at(0);
  ASSERT_TRUE(harness.sessionInfo->server_configuration().auditingEnabled);
  bus = std::make_shared<MethodAuditBus>(harness.sessionInfo->address_space());
  bus->set_event_listener([](const BaseEvent&) {});
  harness.sessionInfo->eventSink = bus.get();
  const NodeId object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const NodeId method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, method);
  harness.input_arguments(method, NodeId{index, 201}, 0, {"value"});
  harness.handle(*r, method, "M", 1);
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->reset();
  r->hold_calls();

  const auto outcome = harness.call(request_of({item_of(object, method, {Variant{int32_t{17}}})}, 300));

  const bool held = r->wait_for_held_calls(1, 1000ms);
  r->release_held_calls();
  const bool ran = wait_until([&harness] { return harness.log->has_run("M"); }, 3000ms);
  const bool audited = bus->wait_for(object, method, 3000ms);

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& status = outcome.response->results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadTimeout) << "the response's result: " << to_string(status);
  ASSERT_TRUE(held) << "R held no call_async";
  ASSERT_TRUE(ran) << "R did not answer within 3 s of its release";
  {
    std::lock_guard lock(harness.log->mutex);
    const auto& received = harness.log->inputs["M"];
    ASSERT_EQ(received.size(), 1U) << "the input arguments R read from its item";
    ASSERT_TRUE(received[0].is_int32());
    EXPECT_EQ(received[0].as<int32_t>(), 17) << "the input argument R read from its item";
  }
  EXPECT_TRUE(audited)
    << "no AuditUpdateMethodEventType Event for the Method and the Object within 3 s of R's answer";
  std::vector<MethodAuditBus::Record> matching;
  for (const auto& record : bus->records())
  {
    if (record.sourceNode == object && record.methodId == method)
    {
      matching.push_back(record);
    }
  }
  ASSERT_EQ(matching.size(), 1U) << "AuditUpdateMethodEventType Events for the Method and the Object";
  EXPECT_TRUE(matching.front().status) << "the audit Event's Status";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-TRANSITION-RUNNING-AT-THE-HINT-COMPLETES-AND-IS-AUDITED, scope=function)
TEST(CallFlow, ATransitionRunningAtTheHintCompletesAndIsAudited)
{
  StateMachineCallHarness fixture;
  // Two instances, each in Ready: the first is the control that shows the SDK moves this model.
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:transition", {"Control", "Machine"}));
  const auto& control = fixture.machines.at(0);
  const auto& machine = fixture.machines.at(1);

  const auto controlOutcome =
    fixture.harness.call(request_of({item_of(control.object, fixture.start)}, 5000));
  ASSERT_TRUE(controlOutcome.answered);
  ASSERT_TRUE(controlOutcome.response.has_value());
  ASSERT_EQ(controlOutcome.response->results().size(), 1U);
  const auto& controlStatus = controlOutcome.response->results()[0].status_code();
  ASSERT_EQ(controlStatus.as_status(), Status::Good) << "the control's call: " << to_string(controlStatus);
  ASSERT_EQ(fixture.state_of(control), std::optional<NodeId>{fixture.running})
    << "the control did not move to Running, so the model is not one the SDK transitions; its state is "
    << StateMachineCallHarness::text(fixture.state_of(control));

  fixture.armed->store(true);
  const auto outcome = fixture.harness.call(request_of({item_of(machine.object, fixture.start)}, 300));

  const bool held = fixture.r->wait_for_held_lookups(1, 1000ms);
  const auto stateAtResponse = fixture.state_of(machine);
  fixture.r->hold_lookups_of({});
  fixture.r->release_held_lookups();
  const bool moved = fixture.wait_for_state(machine, fixture.running, 3000ms);
  const auto controlAudits = fixture.audits_of(control.object);
  // Once as many have been raised as the control raised, a further 200 ms lets a duplicate raised in a later
  // turn arrive before they are compared.
  const auto audits = fixture.audits_settled(machine.object, controlAudits.size());

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& status = outcome.response->results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadTimeout) << "the response's result: " << to_string(status);
  ASSERT_TRUE(held) << "R held no lookup after Start had answered";
  ASSERT_EQ(stateAtResponse, std::optional<NodeId>{fixture.ready})
    << "the transition had completed before the response, so it was not running at the hint; the state was "
    << StateMachineCallHarness::text(stateAtResponse);
  EXPECT_TRUE(moved) << "the machine's CurrentState is not Running 3 s after the release: "
                     << StateMachineCallHarness::text(fixture.state_of(machine));
  // What a call with no hint raises: one AuditUpdateMethodEventType and one AuditUpdateStateEventType Event,
  // each with Status true.
  ASSERT_EQ(controlAudits, expected_audits(true, true)) << "the audit Events the control's call raised";
  EXPECT_EQ(audits, controlAudits)
    << "the audit Events raised for Start and the machine within 3 s of the release";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-LATE-GOOD-ANSWER-IS-TRANSITIONED-AND-AUDITED, scope=function)
TEST(CallFlow, ALateGoodAnswerIsTransitionedAndAudited)
{
  StateMachineCallHarness fixture;
  // The first instance is the other one, called with no hint.
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:late-transition", {"Control", "Machine"}));
  const auto& control = fixture.machines.at(0);
  const auto& machine = fixture.machines.at(1);

  const auto controlOutcome = fixture.harness.call(request_of({item_of(control.object, fixture.start)}));
  ASSERT_EQ(result_status(controlOutcome, 0).as_status(), Status::Good)
    << "the control's call: " << to_string(result_status(controlOutcome, 0));
  ASSERT_EQ(fixture.state_of(control), std::optional<NodeId>{fixture.running})
    << "the control did not move to Running, so the model is not one the SDK transitions; its state is "
    << StateMachineCallHarness::text(fixture.state_of(control));
  // The number of audit Events a call with no hint raises.
  const auto controlAudits = fixture.audits_settled(control.object, 1);

  fixture.r->hold_calls();
  const auto outcome = fixture.harness.call(request_of({item_of(machine.object, fixture.start)}, 300));
  const bool held = fixture.r->wait_for_held_calls(1, 1000ms);
  fixture.r->release_held_calls();
  const bool moved = fixture.wait_for_state(machine, fixture.running, 3000ms);
  const auto audits = fixture.audits_settled(machine.object, controlAudits.size());
  const auto records = fixture.records_of(machine.object);

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(held) << "R held no call_async";
  EXPECT_EQ(result_status(outcome, 0).as_status(), Status::BadTimeout)
    << "the response's result: " << to_string(result_status(outcome, 0));
  EXPECT_TRUE(moved) << "the machine's CurrentState is not Running 3 s after the release: "
                     << StateMachineCallHarness::text(fixture.state_of(machine));
  EXPECT_EQ(audits, expected_audits(true, true))
    << "the audit Events raised for Start and the machine, counted 200 ms after they reached "
    << controlAudits.size();
  // The two Events carry one ActionTimeStamp, earlier than the response.
  ASSERT_EQ(records.size(), 2U) << "the audit Events raised for Start and the machine";
  ASSERT_TRUE(records[0].actionTimeStamp.has_value())
    << "the first audit Event carries no DateTime ActionTimeStamp";
  ASSERT_TRUE(records[1].actionTimeStamp.has_value())
    << "the second audit Event carries no DateTime ActionTimeStamp";
  EXPECT_EQ(*records[0].actionTimeStamp, *records[1].actionTimeStamp)
    << "the two audit Events' ActionTimeStamps: " << records[0].actionTimeStamp->as_iso_string() << " and "
    << records[1].actionTimeStamp->as_iso_string();
  EXPECT_LT(*records[0].actionTimeStamp, outcome.arrived)
    << "the ActionTimeStamp " << records[0].actionTimeStamp->as_iso_string()
    << " is not earlier than the response, which arrived at " << outcome.arrived.as_iso_string();
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-CANCELLED-CALL-WHOSE-METHOD-RUNS-IS-TRANSITIONED, scope=function)
TEST(CallFlow, ACancelledCallWhoseMethodRunsIsTransitioned)
{
  StateMachineCallHarness fixture;
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:cancelled-transition", {"Machine"}));
  const auto& machine = fixture.machines.at(0);

  fixture.r->hold_calls();
  auto pending = fixture.harness.start(request_of({item_of(machine.object, fixture.start)}));
  const bool held = fixture.r->wait_for_held_calls(1, 3000ms);
  fixture.harness.services.back()->cancel();
  const auto outcome = CallHarness::await(pending);
  fixture.r->release_held_calls();
  const bool moved = fixture.wait_for_state(machine, fixture.running, 3000ms);
  const auto audits = fixture.audits_settled(machine.object, 2);

  ASSERT_TRUE(held) << "R held no call_async";
  ASSERT_TRUE(outcome.answered);
  ASSERT_EQ(outcome.serviceResult.as_status(), Status::BadRequestCancelledByClient)
    << "the response is not the cancelled response: " << to_string(outcome.serviceResult);
  EXPECT_TRUE(moved) << "the machine's CurrentState is not Running 3 s after the release: "
                     << StateMachineCallHarness::text(fixture.state_of(machine));
  EXPECT_EQ(audits, expected_audits(true, true))
    << "the audit Events raised for Start and the machine, counted 200 ms after they reached two";
}

// OPC 10000-4 5.11.2.4 forbids a Good status with a sub-status as a Method's statusCode: the Call service
// answers plain Good, keeps the outputs, and the given code with its detail is the cause of the ErrorDetail.
// @relation(AC-SVR-METH-CALL-031-NO-GOOD-SUBSTATUS, scope=function)
TEST(CallFlow, AGoodStatusWithASubStatusIsAnsweredPlainGoodWithTheCodeAsTheCause)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:qualified-statuses", harness.threadPool.get_executor());
  const auto index = harness.setup({nameSpace}).at(0);
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const auto clampedMethod = harness.create(NodeId{index, 200}, "Clamped", NodeClass::Method);
  const auto overriddenMethod = harness.create(NodeId{index, 201}, "Overridden", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, clampedMethod);
  harness.link(object, ReferenceTypeId::HasComponent, overriddenMethod);
  harness.handle(*nameSpace, clampedMethod, "Clamped", 1);
  harness.handle(*nameSpace, overriddenMethod, "Overridden", 1);
  const shared_ptr<const ErrorDetail> clampedDetail =
    ErrorDetail::build("MethodAnswerClamped", "The namespace qualified the clamped answer", "CallFlow")
      .detail("The independently retained qualification detail for the first Method");
  const shared_ptr<const ErrorDetail> overriddenDetail =
    ErrorDetail::build("MethodAnswerOverridden", "The namespace qualified the overridden answer", "CallFlow")
      .detail("The independently retained qualification detail for the second Method");
  const std::array<StatusCode, 2> supplied{
    StatusCode{Status::GoodClamped, clampedDetail}, StatusCode{Status::GoodLocalOverride, overriddenDetail}};
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  nameSpace->answer_calls(
    [clampedMethod, supplied, scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      BatchResult<std::optional<CallResult>> answer;
      for (const auto& request : call.methodRequests)
      {
        CallMethodResult result;
        result.status_code() = supplied[1];
        result.output_arguments().push_back(Variant{int32_t{22}});
        if (request.method_id() == clampedMethod)
        {
          result.status_code() = supplied[0];
          result.output_arguments().payload().front() = Variant{int32_t{21}};
        }
        answer.items.emplace_back(CallResult{std::move(result)});
      }
      return answer;
    });
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();
  const std::vector<CallMethodRequest> items{
    item_of(object, clampedMethod), item_of(object, overriddenMethod)};

  const auto outcome = harness.call(request_of(items));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  const auto calls = nameSpace->calls(Member::Call);
  expect_one_call_of(calls, {object, object}, "qualified-status namespace");
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("Clamped"));
  EXPECT_FALSE(harness.log->has_run("Overridden"));
  if (calls.size() == 1)
  {
    EXPECT_EQ(calls.front().methodRequests, items);
  }
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  for (std::size_t item = 0; item < supplied.size(); ++item)
  {
    const auto& status = outcome.response->results()[item].status_code();
    EXPECT_EQ(status.value(), StatusCode{Status::Good}.value())
      << "item " << item + 1 << " is not answered plain Good: " << to_string(status);
    EXPECT_EQ(detail_code(status), "MethodStatusQualified") << "item " << item + 1;
    EXPECT_EQ(detail_cause(status), supplied[item].value())
      << "item " << item + 1 << ": the given code is not the ErrorDetail's cause";
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->cause, supplied[item].shared_detail())
      << "item " << item + 1 << ": the given code's own detail is lost";
    expect_good_with_output(outcome, item, item == 0 ? 21 : 22);
  }
}

// The namespace's code on its CallResult and the CallMethodResult's statusCode share the one statusCode a
// Method answers: a Good subcode on the result is answered plain Good with the code as the cause, an Item's
// own Bad status stands, and the outputs of a Good answer are kept.
// @relation(AC-SVR-METH-CALL-031-NO-GOOD-SUBSTATUS, scope=function)
TEST(CallFlow, AGoodSubStatusOnTheNamespacesAnswerIsAnsweredPlainGood)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:qualified-answers", harness.threadPool.get_executor());
  const auto index = harness.setup({nameSpace}).at(0);
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const auto qualifiedMethod = harness.create(NodeId{index, 200}, "Qualified", NodeClass::Method);
  const auto failedMethod = harness.create(NodeId{index, 201}, "Failed", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, qualifiedMethod);
  harness.link(object, ReferenceTypeId::HasComponent, failedMethod);
  harness.handle(*nameSpace, qualifiedMethod, "Qualified", 1);
  harness.handle(*nameSpace, failedMethod, "Failed", 1);
  const shared_ptr<const ErrorDetail> answerDetail =
    ErrorDetail::build("CallAnswerOverridden", "The namespace qualified its answer", "CallFlow");
  const StatusCode qualified{Status::GoodLocalOverride, answerDetail};
  nameSpace->answer_calls(
    [qualifiedMethod, qualified](const RecordedCall& call)
    {
      BatchResult<std::optional<CallResult>> answer;
      for (const auto& request : call.methodRequests)
      {
        CallMethodResult result;
        result.output_arguments().push_back(Variant{int32_t{31}});
        if (request.method_id() != qualifiedMethod)
        {
          result.status_code() = StatusCode{Status::BadDeviceFailure};
        }
        answer.items.emplace_back(CallResult{std::move(result), qualified});
      }
      return answer;
    });
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();

  const auto outcome =
    harness.call(request_of({item_of(object, qualifiedMethod), item_of(object, failedMethod)}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  const auto& status = outcome.response->results()[0].status_code();
  EXPECT_EQ(status.value(), StatusCode{Status::Good}.value()) << to_string(status);
  EXPECT_EQ(detail_code(status), "MethodStatusQualified");
  EXPECT_EQ(detail_cause(status), qualified.value()) << "the namespace's code is not the ErrorDetail's cause";
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->cause, answerDetail);
  expect_good_with_output(outcome, 0, 31);
  const auto& failed = outcome.response->results()[1];
  EXPECT_EQ(failed.status_code().as_status(), Status::BadDeviceFailure)
    << "the Method's own Bad status did not stand: " << to_string(failed.status_code());
  EXPECT_TRUE(failed.output_arguments().empty()) << "a Bad Method status kept its outputs";
}

// A typed Method handler's Good subcode, given through with_status or through a Result holding the output,
// reaches the Call service as the handler gave it, and the Call service answers it plain Good with the
// outputs and the ErrorDetail MethodStatusQualified, whose cause is the given code with its own detail (OPC
// 10000-4 5.11.2.4). Control: a typed handler's Uncertain status is answered unchanged with its output.
// Records each warning's message and field values as one line.
class WarningRecorder final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    if (entry.level != LogLevel::Warning)
    {
      return;
    }
    std::ostringstream line;
    line << entry.message;
    for (const auto& field : entry.fields)
    {
      std::visit([&line](const auto& value) { line << ' ' << value; }, field.value);
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(line.str());
  }

  std::vector<std::string> entries() const
  {
    const std::lock_guard lock{mMutex};
    return mEntries;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mEntries;
};

// @relation(AC-SVR-METH-CALL-031-A-TYPED-HANDLERS-GOOD-SUBCODE-IS-ANSWERED-GOOD, scope=function)
TEST(CallFlow, ATypedHandlersGoodSubcodeIsAnsweredPlainGoodWithTheCodeAsTheCause)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:typed-good-subcode", harness.threadPool.get_executor());
  const auto index = harness.setup({nameSpace}).at(0);
  auto warnings = std::make_shared<WarningRecorder>();
  harness.sessionInfo->log =
    Logger{warnings, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const auto withStatusMethod = harness.create(NodeId{index, 200}, "WithStatus", NodeClass::Method);
  const auto fromResultMethod = harness.create(NodeId{index, 201}, "FromResult", NodeClass::Method);
  const auto uncertainMethod = harness.create(NodeId{index, 202}, "Uncertain", NodeClass::Method);
  for (const auto& method : {withStatusMethod, fromResultMethod, uncertainMethod})
  {
    harness.link(object, ReferenceTypeId::HasComponent, method);
  }
  const shared_ptr<const ErrorDetail> clampedDetail =
    ErrorDetail::build("PumpRateClamped", "The pump clamped the requested rate", "CallFlow");
  const StatusCode clamped{Status::GoodClamped, clampedDetail};
  harness.handle_typed(*nameSpace,
    withStatusMethod,
    [clamped](const MethodCall&) { return MethodResult<int32_t>::with_status(clamped, int32_t{51}); });
  harness.handle_typed(*nameSpace,
    fromResultMethod,
    [clamped](const MethodCall&) -> MethodResult<int32_t> { return Result<int32_t>{int32_t{52}, clamped}; });
  harness.handle_typed(*nameSpace,
    uncertainMethod,
    [](const MethodCall&)
    { return MethodResult<int32_t>::with_status(Status::UncertainLastUsableValue, int32_t{53}); });
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();

  const auto outcome = harness.call(request_of({item_of(object, withStatusMethod),
    item_of(object, fromResultMethod),
    item_of(object, uncertainMethod)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 3U);
  for (std::size_t item = 0; item < 2; ++item)
  {
    const auto& status = outcome.response->results()[item].status_code();
    EXPECT_EQ(status.value(), StatusCode{Status::Good}.value())
      << "item " << item + 1 << " is not answered plain Good: " << to_string(status);
    EXPECT_EQ(detail_code(status), "MethodStatusQualified") << "item " << item + 1;
    EXPECT_EQ(detail_cause(status), clamped.value())
      << "item " << item + 1 << ": the handler's code is not the ErrorDetail's cause";
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->cause, clampedDetail)
      << "item " << item + 1 << ": the handler's ErrorDetail is lost";
    expect_good_with_output(outcome, item, item == 0 ? 51 : 52);
  }
  const auto& uncertain = outcome.response->results()[2];
  EXPECT_EQ(uncertain.status_code().value(), StatusCode{Status::UncertainLastUsableValue}.value())
    << to_string(uncertain.status_code());
  EXPECT_EQ(uncertain.status_code().shared_detail(), nullptr) << "an Uncertain status was qualified";
  ASSERT_EQ(uncertain.output_arguments().size(), 1U) << "the outputs of an Uncertain status were dropped";
  EXPECT_EQ(uncertain.output_arguments()[0].as<int32_t>(), 53);

  // One warning for each Method whose Good subcode was answered Good, naming the Method and the code.
  const auto logged = warnings->entries();
  EXPECT_EQ(logged.size(), 2U);
  for (const auto& method : {withStatusMethod, fromResultMethod})
  {
    const auto named = std::count_if(logged.begin(),
      logged.end(),
      [&](const std::string& text)
      {
        return text.find(to_string(method)) != std::string::npos &&
               text.find(to_string(clamped)) != std::string::npos;
      });
    EXPECT_EQ(named, 1) << "no single warning names " << to_string(method) << " and " << to_string(clamped);
  }
}

// An Uncertain answer holding a CallMethodResult is answered: its code is the Method's statusCode and its
// outputs are kept, since an Uncertain code may be answered as a Method's statusCode.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-CALL-PASSES-AN-UNCERTAIN-ANSWER-WITH-ITS-OUTPUTS, scope=function)
TEST(CallFlow, AnUncertainAnswerWithAResultIsAnsweredWithItsOutputs)
{
  CallHarness harness;
  const auto [nameSpace, index, object, method] =
    one_method_namespace(harness, "urn:test:call-flow:uncertain-answer", "Uncertain", 1, "Uncertain");
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  nameSpace->answer_calls(
    [uncertain](const RecordedCall& call)
    {
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t item = 0; item < call.methodRequests.size(); ++item)
      {
        CallMethodResult result;
        result.output_arguments().push_back(Variant{int32_t{41}});
        answer.items.emplace_back(CallResult{std::move(result), uncertain});
      }
      return answer;
    });

  const auto outcome = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& result = outcome.response->results()[0];
  EXPECT_EQ(result.status_code().value(), uncertain.value()) << to_string(result.status_code());
  ASSERT_EQ(result.output_arguments().size(), 1U) << "the outputs of an Uncertain answer were dropped";
  EXPECT_EQ(result.output_arguments()[0].as<int32_t>(), 41);

  const StatusCode sensorUncertain{Status::UncertainSensorNotAccurate};
  nameSpace->answer_calls(
    [sensorUncertain](const RecordedCall& call)
    {
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t item = 0; item < call.methodRequests.size(); ++item)
      {
        CallMethodResult supplied;
        supplied.output_arguments().push_back(Variant{int32_t{41}});
        answer.items.emplace_back(CallResult{std::move(supplied), sensorUncertain});
      }
      return answer;
    });

  const auto declared = harness.call(request_of({item_of(object, method)}));

  ASSERT_TRUE(declared.answered);
  ASSERT_TRUE(declared.response.has_value());
  ASSERT_EQ(declared.response->results().size(), 1U);
  const auto& declaredResult = declared.response->results()[0];
  EXPECT_EQ(declaredResult.status_code().value(), sensorUncertain.value());
  ASSERT_EQ(declaredResult.output_arguments().size(), 1U);
  EXPECT_EQ(declaredResult.output_arguments()[0], Variant{int32_t{41}});
}

// @relation(AC-SVR-METH-CALL-031-NO-GOOD-SUBSTATUS, scope=function)
TEST(CallFlow, AnUnqualifiedGoodStatusIsAnsweredUnchanged)
{
  CallHarness harness;
  const auto [nameSpace, index, object, method] =
    one_method_namespace(harness, "urn:test:call-flow:plain-status", "Unqualified", 1, "Unqualified");
  CallMethodResult supplied;
  supplied.status_code() = Status::Good;
  supplied.output_arguments().push_back(Variant{int32_t{19}});
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  nameSpace->answer_calls(
    [supplied, scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t item = 0; item < call.methodRequests.size(); ++item)
      {
        answer.items.emplace_back(CallResult{supplied});
      }
      return answer;
    });
  const std::vector<CallMethodRequest> items{item_of(object, method)};

  const auto outcome = harness.call(request_of(items));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  const auto calls = nameSpace->calls(Member::Call);
  expect_one_call_of(calls, {object}, "unqualified-status namespace");
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("Unqualified"));
  if (calls.size() == 1)
  {
    EXPECT_EQ(calls.front().methodRequests, items);
  }
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0], supplied);
  EXPECT_EQ(outcome.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  EXPECT_EQ(outcome.response->results()[0].status_code().shared_detail(), nullptr);
  expect_good_with_output(outcome, 0, 19);
}

// @relation(AC-SVR-METH-CALL-049-BAD-NOCOMMUNICATION, scope=function)
TEST(CallFlow, ANamespaceThatCannotReachItsTargetIsAnsweredBadNoCommunication)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:no-communication", harness.threadPool.get_executor());
  const auto index = harness.setup({nameSpace}).at(0);
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const auto resultMethod = harness.create(NodeId{index, 200}, "ResultRefusal", NodeClass::Method);
  const auto outerMethod = harness.create(NodeId{index, 201}, "OuterRefusal", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, resultMethod);
  harness.link(object, ReferenceTypeId::HasComponent, outerMethod);
  harness.handle(*nameSpace, resultMethod, "ResultRefusal", 1);
  harness.handle(*nameSpace, outerMethod, "OuterRefusal", 1);
  const shared_ptr<const ErrorDetail> resultDetail =
    ErrorDetail::build(
      "MethodTargetUnreachable", "The namespace cannot reach the first Method's target", "CallFlow")
      .detail("The failure is carried inside a successful outer CallResult");
  const shared_ptr<const ErrorDetail> outerDetail =
    ErrorDetail::build(
      "MethodCallUnavailable", "The namespace cannot reach the second Method's target", "CallFlow")
      .detail("The failure is carried by a refused outer CallResult");
  StatusCode resultStatus{Status::BadNoCommunication, resultDetail};
  resultStatus.semantics_changed(true);
  StatusCode outerStatus{Status::BadNoCommunication, outerDetail};
  outerStatus.structure_changed(true);
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  nameSpace->answer_calls(
    [resultMethod, resultStatus, outerStatus, scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      BatchResult<std::optional<CallResult>> answer;
      for (const auto& request : call.methodRequests)
      {
        if (request.method_id() == resultMethod)
        {
          CallMethodResult result;
          result.status_code() = resultStatus;
          answer.items.emplace_back(CallResult{std::move(result)});
        }
        else
        {
          answer.items.emplace_back(CallResult{outerStatus});
        }
      }
      return answer;
    });
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();
  const std::vector<CallMethodRequest> items{item_of(object, resultMethod), item_of(object, outerMethod)};

  const auto outcome = harness.call(request_of(items));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  const auto calls = nameSpace->calls(Member::Call);
  expect_one_call_of(calls, {object, object}, "unreachable-target namespace");
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("ResultRefusal"));
  EXPECT_FALSE(harness.log->has_run("OuterRefusal"));
  if (calls.size() == 1)
  {
    EXPECT_EQ(calls.front().methodRequests, items);
  }
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  const std::array<StatusCode, 2> supplied{resultStatus, outerStatus};
  for (std::size_t item = 0; item < supplied.size(); ++item)
  {
    const auto& result = outcome.response->results()[item];
    const auto& status = result.status_code();
    EXPECT_EQ(status.as_status(), Status::BadNoCommunication);
    EXPECT_EQ(status.value(), supplied[item].value());
    EXPECT_EQ(status.shared_detail(), supplied[item].shared_detail());
    EXPECT_NE(status.as_status(), Status::BadInvalidArgument);
    EXPECT_NE(status.as_status(), Status::BadUserAccessDenied);
    EXPECT_TRUE(result.output_arguments().empty());
  }
}

// @relation(AC-SVR-METH-CALL-050-ARG-BAD-OUTOFRANGE, scope=function)
TEST(CallFlow, AnArgumentOutsideItsRangeIsReportedInItsSlot)
{
  CallHarness harness;
  const auto [nameSpace, index, object, method] = one_method_namespace(harness,
    "urn:test:call-flow:argument-range",
    "Ranged",
    1,
    "Ranged",
    [&harness](const OneMethodNamespace& built)
    { harness.input_arguments(built.method, NodeId{built.index, 201}, 0, {"inRange", "aboveMaximum"}); });
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  nameSpace->answer_calls(
    [scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      constexpr int32_t declaredMaximum{100};
      BatchResult<std::optional<CallResult>> answer;
      for (const auto& request : call.methodRequests)
      {
        const auto& supplied = request.input_arguments();
        CallMethodResult result;
        result.input_argument_results().resize(supplied.size());
        bool outOfRange{false};
        for (std::size_t argument = 0; argument < supplied.size(); ++argument)
        {
          const auto* value = supplied[argument].try_as<int32_t>();
          EXPECT_NE(value, nullptr);
          if (value && *value > declaredMaximum)
          {
            result.input_argument_results()[argument] = Status::BadOutOfRange;
            outOfRange = true;
          }
          else
          {
            result.input_argument_results()[argument] = Status::Good;
          }
        }
        result.status_code() = Status::Good;
        if (outOfRange)
        {
          result.status_code() = Status::BadInvalidArgument;
        }
        answer.items.emplace_back(CallResult{std::move(result)});
      }
      return answer;
    });
  const std::vector<CallMethodRequest> items{
    item_of(object, method, {Variant{int32_t{50}}, Variant{int32_t{4096}}})};

  const auto outcome = harness.call(request_of(items));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  const auto calls = nameSpace->calls(Member::Call);
  expect_one_call_of(calls, {object}, "ranged-argument namespace");
  EXPECT_EQ(scriptCalls->load(), 1U);
  EXPECT_FALSE(harness.log->has_run("Ranged"));
  ASSERT_EQ(calls.size(), 1U);
  ASSERT_EQ(calls.front().methodRequests.size(), 1U);
  EXPECT_EQ(calls.front().methodRequests, items);
  const auto& received = calls.front().methodRequests.front().input_arguments();
  ASSERT_EQ(received.size(), 2U);
  ASSERT_TRUE(received[0].is_int32());
  ASSERT_TRUE(received[1].is_int32());
  EXPECT_EQ(received[0].as<int32_t>(), 50);
  EXPECT_EQ(received[1].as<int32_t>(), 4096);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& result = outcome.response->results()[0];
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadInvalidArgument}.value());
  ASSERT_EQ(result.input_argument_results().size(), 2U);
  EXPECT_EQ(result.input_argument_results()[0].value(), StatusCode{Status::Good}.value());
  EXPECT_EQ(result.input_argument_results()[1].value(), StatusCode{Status::BadOutOfRange}.value());
}

// @relation(AC-SVR-METH-CALL-061-BAD-TOOMANYOPERATIONS, scope=function)
TEST(CallFlow, ACallAboveTheOperationLimitRunsNoMethod)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:operation-limit", harness.threadPool.get_executor());
  ServerConfig configuration;
  configuration.server_capabilities().operationLimits.maxNodesPerMethodCall = 1;
  const auto index = harness.setup({nameSpace}, std::move(configuration)).at(0);
  EXPECT_EQ(
    harness.sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerMethodCall,
    std::optional<uint32_t>{1});
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const auto first = harness.create(NodeId{index, 200}, "First", NodeClass::Method);
  const auto second = harness.create(NodeId{index, 201}, "Second", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, first);
  harness.link(object, ReferenceTypeId::HasComponent, second);
  harness.handle(*nameSpace, first, "First", 1);
  harness.handle(*nameSpace, second, "Second", 1);
  const auto scriptCalls = std::make_shared<std::atomic_size_t>(0);
  nameSpace->answer_calls(
    [scriptCalls](const RecordedCall& call)
    {
      ++*scriptCalls;
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t item = 0; item < call.methodRequests.size(); ++item)
      {
        CallMethodResult result;
        result.output_arguments().push_back(Variant{int32_t{7}});
        answer.items.emplace_back(CallResult{std::move(result)});
      }
      return answer;
    });
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();

  const auto outcome = harness.call(request_of({item_of(object, first), item_of(object, second)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::BadTooManyOperations);
  EXPECT_EQ(nameSpace->count(Member::Call), 0U);
  EXPECT_TRUE(nameSpace->calls(Member::Call).empty());
  EXPECT_EQ(scriptCalls->load(), 0U);
  EXPECT_FALSE(harness.log->has_run("First"));
  EXPECT_FALSE(harness.log->has_run("Second"));
}

// This injects unavailable configuration through the Session dependency; the live Server is not destroyed.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-A-CALL-WHOSE-SERVER-IS-DESTROYED-WHILE-ITS-METHOD-RUNS-IS-ANSWERED, scope=function)
TEST(CallFlow, ACallWhoseServerIsDestroyedWhileItsMethodRunsIsAnswered)
{
  CallHarness harness;
  auto nameSpace = make_shared<BatchRecordingNamespace>(
    "urn:test:call-flow:configuration-unavailable", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  const auto index = harness.setup({nameSpace}, std::move(serverConfig)).at(0);
  const auto object = harness.create(NodeId{index, 100}, "Object", NodeClass::Object);
  const auto method = harness.create(NodeId{index, 200}, "Method", NodeClass::Method);
  harness.link(object, ReferenceTypeId::HasComponent, method);
  nameSpace->decline_single_lookups();
  nameSpace->decline_immediate_permissions();
  nameSpace->reset();

  auto session = std::make_shared<ClosableSession>(harness.sessionInfo);
  const auto unavailable = session->serverConfigurationUnavailable;
  ASSERT_FALSE(unavailable->load());
  ASSERT_TRUE(session->server_configuration().auditingEnabled);
  nameSpace->answer_calls(
    [weakSession = std::weak_ptr<ClosableSession>{session}](const RecordedCall& received)
    {
      if (const auto runningSession = weakSession.lock())
      {
        runningSession->serverConfigurationUnavailable->store(true);
      }
      BatchResult<std::optional<CallResult>> answers;
      for (const auto& request : received.methodRequests)
      {
        (void)request;
        CallMethodResult answer;
        answer.status_code() = Status::Good;
        answer.output_arguments().push_back(Variant{int32_t{1}});
        answers.items.emplace_back(CallResult{std::move(answer)});
      }
      return answers;
    });

  CallOutcome outcome;
  ASSERT_NO_THROW(outcome = harness.call(request_of({item_of(object, method)}), session));
  ASSERT_TRUE(outcome.answered) << "the configuration refusal must not prevent bounded Call completion";
  EXPECT_TRUE(unavailable->load()) << "the namespace invocation sets the unavailable-configuration state";
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::Good}.value());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  expect_good_with_output(outcome, 0, 1);
  EXPECT_EQ(outcome.response->results()[0].status_code().value(), StatusCode{Status::Good}.value());
  EXPECT_EQ(harness.responseCount->load(), 1U);
  const auto calls = nameSpace->calls(Member::Call);
  ASSERT_EQ(calls.size(), 1U);
  ASSERT_EQ(calls[0].methodRequests.size(), 1U);
  EXPECT_EQ(calls[0].methodRequests[0].object_id(), object);
  EXPECT_EQ(calls[0].methodRequests[0].method_id(), method);

  harness.services.clear();
  session.reset();
  harness.sessionInfo.reset();
  ASSERT_NO_THROW(
    ::ua::test_utils::drain_with_timeout(harness.threadPool, 10s, "CallFlow.ConfigurationUnavailable"));
  EXPECT_TRUE(unavailable->load());
  EXPECT_EQ(harness.responseCount->load(), 1U);
  EXPECT_EQ(nameSpace->calls(Member::Call).size(), 1U);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-CANCEL-DURING-THE-TRANSITION-DOES-NOT-STOP-IT, scope=function)
TEST(CallFlow, ACancelDuringTheTransitionDoesNotStopIt)
{
  StateMachineCallHarness fixture;
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:cancel-in-transition", {"Machine"}));
  const auto& machine = fixture.machines.at(0);

  fixture.armed->store(true);
  auto pending = fixture.harness.start(request_of({item_of(machine.object, fixture.start)}));
  const bool held = fixture.r->wait_for_held_lookups(1, 3000ms);
  fixture.harness.services.back()->cancel();
  const auto outcome = CallHarness::await(pending);
  const auto stateAtResponse = fixture.state_of(machine);
  fixture.r->hold_lookups_of({});
  fixture.r->release_held_lookups();
  const bool moved = fixture.wait_for_state(machine, fixture.running, 3000ms);
  const auto audits = fixture.audits_settled(machine.object, 2);

  ASSERT_TRUE(held) << "R held no lookup after Start had answered";
  ASSERT_TRUE(outcome.answered);
  ASSERT_EQ(outcome.serviceResult.as_status(), Status::BadRequestCancelledByClient)
    << "the response is not the cancelled response: " << to_string(outcome.serviceResult);
  ASSERT_EQ(stateAtResponse, std::optional<NodeId>{fixture.ready})
    << "the transition had completed before the cancelled response, so it was not running at the cancel; the "
       "state was "
    << StateMachineCallHarness::text(stateAtResponse);
  EXPECT_TRUE(moved) << "the machine's CurrentState is not Running 3 s after the release: "
                     << StateMachineCallHarness::text(fixture.state_of(machine));
  EXPECT_EQ(audits, expected_audits(true, true))
    << "the audit Events raised for Start and the machine, counted 200 ms after they reached two";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-LATE-TRANSITION-THAT-FAILS-IS-AUDITED-AS-NOT-PERFORMED, scope=function)
TEST(CallFlow, ALateTransitionThatFailsIsAuditedAsNotPerformed)
{
  StateMachineCallHarness fixture;
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:late-refused-transition", {"Machine"}));
  const auto& machine = fixture.machines.at(0);
  fixture.r->fail_writes_of(machine.stateId, refused_state_write());

  fixture.r->hold_calls();
  const auto outcome = fixture.harness.call(request_of({item_of(machine.object, fixture.start)}, 300));
  const bool held = fixture.r->wait_for_held_calls(1, 1000ms);
  fixture.r->release_held_calls();
  const auto audits = fixture.audits_settled(machine.object, 1);
  const auto state = fixture.state_of(machine);

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(held) << "R held no call_async";
  EXPECT_EQ(result_status(outcome, 0).as_status(), Status::BadTimeout)
    << "the response's result: " << to_string(result_status(outcome, 0));
  EXPECT_EQ(state, std::optional<NodeId>{fixture.ready})
    << "the machine's CurrentState after the release: " << StateMachineCallHarness::text(state);
  EXPECT_EQ(audits, expected_audits(false, false))
    << "the audit Events raised for Start and the machine, counted 200 ms after the first";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-DISCARDED-TRANSITION-IS-AUDITED-ONCE-AS-NOT-PERFORMED, scope=function)
TEST(CallFlow, ADiscardedTransitionIsAuditedOnceAsNotPerformed)
{
  StateMachineCallHarness fixture;
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:discarded-transition", {"Machine"}));
  const auto& machine = fixture.machines.at(0);

  fixture.armed->store(true);
  auto pending = fixture.harness.start(request_of({item_of(machine.object, fixture.start)}));
  const bool held = fixture.r->wait_for_held_lookups(1, 3000ms);
  fixture.r->hold_lookups_of({});
  const auto discarded = fixture.r->discard_held_lookups();
  const auto outcome = CallHarness::await(pending);
  const auto audits = fixture.audits_settled(machine.object, 1);
  const auto state = fixture.state_of(machine);

  ASSERT_TRUE(held) << "R held no lookup after Start had answered";
  ASSERT_EQ(discarded, 1U) << "the lookups R discarded";
  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(result_status(outcome, 0).as_status(), Status::BadShutdown)
    << "the item's result: " << to_string(result_status(outcome, 0));
  EXPECT_EQ(state, std::optional<NodeId>{fixture.ready})
    << "the machine's CurrentState: " << StateMachineCallHarness::text(state);
  EXPECT_EQ(audits, expected_audits(false, false))
    << "the audit Events raised for Start and the machine, counted 200 ms after the first";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-TRANSITION-ANSWERED-IN-TIME-IS-THE-ITEMS-RESULT, scope=function)
TEST(CallFlow, ATransitionAnsweredInTimeIsTheItemsResult)
{
  StateMachineCallHarness fixture;
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:transition-in-time", {"Applied", "Refused"}));
  const auto& applied = fixture.machines.at(0);
  const auto& refused = fixture.machines.at(1);
  const auto refusal = refused_state_write();
  fixture.r->fail_writes_of(refused.stateId, refusal);

  // (a) The transition applies.
  const auto appliedOutcome = fixture.harness.call(request_of({item_of(applied.object, fixture.start)}));
  const auto appliedState = fixture.state_of(applied);
  const auto appliedAudits = fixture.audits_settled(applied.object, 2);

  ASSERT_TRUE(appliedOutcome.answered);
  expect_good_with_output(appliedOutcome, 0, startOutput);
  EXPECT_EQ(appliedState, std::optional<NodeId>{fixture.running})
    << "the applied machine's CurrentState after the response: "
    << StateMachineCallHarness::text(appliedState);
  EXPECT_EQ(appliedAudits, expected_audits(true, true))
    << "the audit Events raised for Start and the applied machine, counted 200 ms after they reached two";

  // (b) The write of the new state fails.
  const auto refusedOutcome = fixture.harness.call(request_of({item_of(refused.object, fixture.start)}));
  const auto refusedState = fixture.state_of(refused);
  const auto refusedAudits = fixture.audits_settled(refused.object, 1);

  ASSERT_TRUE(refusedOutcome.answered);
  ASSERT_TRUE(refusedOutcome.response.has_value());
  ASSERT_EQ(refusedOutcome.response->results().size(), 1U);
  const auto& refusedResult = refusedOutcome.response->results()[0];
  EXPECT_EQ(refusedResult.status_code().as_status(), refusal.as_status())
    << "the refused machine's result: " << to_string(refusedResult.status_code());
  EXPECT_NE(refusedResult.status_code().shared_detail(), nullptr)
    << "the refused machine's result carries no ErrorDetail";
  ASSERT_EQ(refusedResult.output_arguments().size(), 1U) << "the refused machine's output arguments";
  ASSERT_TRUE(refusedResult.output_arguments()[0].is_int32());
  EXPECT_EQ(refusedResult.output_arguments()[0].as<int32_t>(), startOutput) << "the refused machine's output";
  EXPECT_EQ(refusedState, std::optional<NodeId>{fixture.ready})
    << "the refused machine's CurrentState after the response: "
    << StateMachineCallHarness::text(refusedState);
  EXPECT_EQ(refusedAudits, expected_audits(false, false))
    << "the audit Events raised for Start and the refused machine, counted 200 ms after the first";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-20-A-LATE-ANSWER-AFTER-THE-SESSION-CLOSES-IS-AUDITED, scope=function)
TEST(CallFlow, ALateAnswerAfterTheSessionClosesIsAudited)
{
  StateMachineCallHarness fixture;
  ASSERT_NO_FATAL_FAILURE(fixture.build("urn:test:call-flow:late-after-close", {"Machine"}));
  const auto& machine = fixture.machines.at(0);
  // The Session that makes the call.
  shared_ptr<SessionInfo> session = std::make_shared<ClosableSession>(fixture.harness.sessionInfo);
  const std::weak_ptr<SessionInfo> closing = session;

  fixture.r->hold_calls();
  const auto outcome =
    fixture.harness.call(request_of({item_of(machine.object, fixture.start)}, 300), session);
  const bool held = fixture.r->wait_for_held_calls(1, 1000ms);
  session.reset();
  const bool closed = wait_until([&closing] { return closing.expired(); }, 1000ms);
  fixture.r->release_held_calls();
  const bool moved = fixture.wait_for_state(machine, fixture.running, 3000ms);
  const auto audits = fixture.audits_settled(machine.object, 2);

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(held) << "R held no call_async";
  ASSERT_TRUE(closed) << "the Session is still held 1 s after the test released it, so it did not close";
  EXPECT_TRUE(moved) << "the machine's CurrentState is not Running 3 s after the release: "
                     << StateMachineCallHarness::text(fixture.state_of(machine));
  EXPECT_EQ(audits, expected_audits(true, true))
    << "the audit Events raised for Start and the machine, counted 200 ms after they reached two";
}
