// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <fmt/core.h>
#include <atomic>
#include <chrono>
#include <future>
#include <boost/asio/io_context.hpp>
#include "ua_read_service.h"
#include "ua_default_object_node.h"
#include "ua_default_namespace.h"
#include "ua_namespace_service_delegates.h"
#include "ua_server.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_timer.h"
#include "ua_register_nodes_service.h"
#include "ua_attribute_id.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include <optional>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

// @relation(SVR-VIEW-REG-007, SVR-VIEW-URG-002, scope=function)
TEST(RegisterNodesServiceTests, RegisterASingleNode)
{
  NodeId nodeId{123};
  boost::asio::thread_pool threadPool;
  auto ns = default_ns::Namespace::create("uri://my-namespace", threadPool.get_executor());
  ns->create_node(nodeId, NodeClass::Object);

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  server.address_space().add_namespace_sync(ns);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  RegisterNodesRequest registerNodesRequest;
  registerNodesRequest.nodes_to_register().resize(1);
  registerNodesRequest.nodes_to_register()[0] = NodeId{123};

  std::promise<void> done;
  std::atomic<bool> gotExpectedResult{false};

  auto registerNodesService = RegisterNodesServiceSet::create(sessionInfo,
    std::move(registerNodesRequest),
    threadPool.get_executor(),
    [&done, &gotExpectedResult](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      auto registerNodesResponse = std::get_if<RegisterNodesResponse>(&response);
      if (registerNodesResponse && (registerNodesResponse->registered_node_ids().size() == 1))
      {
        auto result = registerNodesResponse->registered_node_ids().payload().front();
        if (result == NodeId{123})
        {
          gotExpectedResult = true;
        }
      }
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(1s), std::future_status::ready);

  GTEST_ASSERT_TRUE(gotExpectedResult);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(SVR-VIEW-REG-008, SVR-VIEW-URG-002, scope=function)
TEST(RegisterNodesServiceTests, TooManyOperationsIsRejected)
{
  NodeId nodeId{123};
  boost::asio::thread_pool threadPool;
  auto ns = default_ns::Namespace::create("uri://my-namespace", threadPool.get_executor());
  ns->create_node(nodeId, NodeClass::Object);

  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().operationLimits.maxNodesPerRegisterNodes = 1;

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverCfg)};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  server.address_space().add_namespace_sync(ns);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  RegisterNodesRequest registerNodesRequest;
  registerNodesRequest.nodes_to_register().resize(2);
  registerNodesRequest.nodes_to_register()[0] = NodeId{123};
  registerNodesRequest.nodes_to_register()[1] = NodeId{123};

  std::promise<void> done;
  std::optional<StatusCode> gotStatus;

  auto service = RegisterNodesServiceSet::create(sessionInfo,
    std::move(registerNodesRequest),
    threadPool.get_executor(),
    [&](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      if (auto* sf = std::get_if<ServiceFault>(&response))
      {
        gotStatus = sf->response_header().service_result();
      }
      else if (auto* ok = std::get_if<RegisterNodesResponse>(&response))
      {
        gotStatus = ok->response_header().service_result();
      }
      done.set_value();
    });
  UA_UNUSED(service);

  ASSERT_EQ(done.get_future().wait_for(1s), std::future_status::ready);

  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::BadTooManyOperations);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// --- Phase 5 end-to-end guarantee: register_nodes delegate drops callback --

namespace
{

class DroppingRegisterNodesNamespace final
  : public default_ns::Namespace,
    public NamespaceRegisterNodesDelegate,
    public std::enable_shared_from_this<DroppingRegisterNodesNamespace>
{
public:
  DroppingRegisterNodesNamespace(string_view uri, boost::asio::any_io_executor ex)
    : default_ns::Namespace(uri, std::move(ex))
  {}

  std::atomic<bool> registerEntered{false};

  shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override
  {
    return std::dynamic_pointer_cast<NamespaceRegisterNodesDelegate>(shared_from_this());
  }

  void register_nodes_async(
    const Context&, std::vector<Item>, RegisterCompleteCallback callback) noexcept override
  {
    registerEntered.store(true);
    // Drop - destructor fires default CallbackNotInvoked BatchResult.
    (void)callback;
  }

  void unregister_nodes_async(
    const Context&, std::vector<Item>, UnregisterCompleteCallback callback) noexcept override
  {
    (void)callback;
  }
};

}  // namespace

namespace
{

class CountingRegisterNodesNamespace final
  : public default_ns::Namespace,
    public NamespaceRegisterNodesDelegate,
    public std::enable_shared_from_this<CountingRegisterNodesNamespace>
{
public:
  CountingRegisterNodesNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override
  {
    return std::dynamic_pointer_cast<NamespaceRegisterNodesDelegate>(shared_from_this());
  }

  void register_nodes_async(
    const Context&, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override
  {
    registerCalls.fetch_add(1);
    itemsSeen.fetch_add(items.size());

    BatchResult<NodeId> batch;
    batch.items.reserve(items.size());
    for (auto& item : items)
    {
      batch.items.emplace_back(std::move(item.nodeId));
    }
    callback(std::move(batch));
  }

  void unregister_nodes_async(
    const Context&, std::vector<Item>, UnregisterCompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  std::atomic<size_t> registerCalls{0};
  std::atomic<size_t> itemsSeen{0};
};

void expect_structurally_invalid_node_rejects_whole_request(NodeId structurallyInvalid,
  string_view expectedIdentifierType, string_view expectedDetailCode = "StructurallyInvalidNodeId",
  std::optional<size_t> expectedIdentifierLength = size_t{4097},
  std::optional<size_t> expectedMaximumLength = size_t{4096},
  std::optional<string_view> expectedEncoding = std::nullopt)
{
  boost::asio::thread_pool threadPool;
  auto countingNamespace = make_shared<CountingRegisterNodesNamespace>(
    "uri://structural-node-id-validation", threadPool.get_executor());

  ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  const uint16_t namespaceIndex = server.address_space().add_namespace_sync(countingNamespace);
  structurallyInvalid.namespace_index() = namespaceIndex;

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  RegisterNodesRequest request;
  request.nodes_to_register().push_back(NodeId{namespaceIndex, "Valid.Before"});
  request.nodes_to_register().push_back(std::move(structurallyInvalid));
  request.nodes_to_register().push_back(NodeId{namespaceIndex, "Valid.After"});

  std::promise<void> done;
  std::atomic<size_t> callbackCount{0};
  std::optional<RegisterNodesServiceSet::ResponseOrServiceFault> observedResponse;

  auto service = RegisterNodesServiceSet::create(sessionInfo,
    std::move(request),
    threadPool.get_executor(),
    [&callbackCount, &done, &observedResponse](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      if (callbackCount.fetch_add(1) == 0)
      {
        observedResponse.emplace(std::move(response));
        done.set_value();
      }
    });
  UA_UNUSED(service);

  const bool completed = done.get_future().wait_for(1s) == std::future_status::ready;
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);

  ASSERT_TRUE(completed) << "RegisterNodes structural rejection must complete";
  ASSERT_TRUE(observedResponse.has_value());
  EXPECT_EQ(callbackCount.load(), 1u) << "the service completion must fire exactly once";

  const auto* fault = std::get_if<ServiceFault>(&*observedResponse);
  ASSERT_NE(fault, nullptr) << "whole-request rejection must return a ServiceFault";
  const StatusCode status = fault->response_header().service_result();
  EXPECT_EQ(status.as_status(), Status::BadNodeIdInvalid);

  const auto detail = status.shared_detail();
  ASSERT_NE(detail, nullptr) << "BadNodeIdInvalid must retain its ErrorDetail";
  EXPECT_EQ(detail->code, expectedDetailCode);
  EXPECT_EQ(detail->source, "RegisterNodesService");
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::operationIndex.value()), "1");
  EXPECT_EQ(
    ::ua::test_utils::error_context(detail.get(), ContextKeys::typeName.value()), expectedIdentifierType);
  if (expectedIdentifierLength)
  {
    EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeActual.value()),
      std::to_string(*expectedIdentifierLength));
  }
  else
  {
    EXPECT_TRUE(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeActual.value()).empty());
  }
  if (expectedMaximumLength)
  {
    EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeMax.value()),
      std::to_string(*expectedMaximumLength));
  }
  else
  {
    EXPECT_TRUE(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeMax.value()).empty());
  }
  if (expectedEncoding)
  {
    EXPECT_EQ(
      ::ua::test_utils::error_context(detail.get(), ContextKeys::encoding.value()), *expectedEncoding);
  }

  EXPECT_EQ(countingNamespace->registerCalls.load(), 0u)
    << "structural validation must reject before any namespace dispatch";
  EXPECT_EQ(countingNamespace->itemsSeen.load(), 0u) << "neither valid neighbour may be partially registered";
}

}  // namespace

// Part 4 section 5.8.5.3 Table 44 requires a service-level BadNodeIdInvalid and complete rejection when
// any requested NodeId is structurally invalid. Part 3 section 8.2.4 limits String identifiers to 4096
// characters.
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(RegisterNodesServiceTests, OversizedStringNodeIdRejectsWholeRequestBeforeNamespaceDispatch)
{
  std::string oversizedIdentifier;
  oversizedIdentifier.reserve(4097 * 2);
  for (size_t characterIndex = 0; characterIndex < 4097; ++characterIndex)
  {
    oversizedIdentifier += "\xC2\xA2";
  }
  ASSERT_EQ(oversizedIdentifier.size(), 8194u) << "the stimulus must contain 4097 two-byte UTF-8 characters";
  expect_structurally_invalid_node_rejects_whole_request(
    NodeId{0, std::string_view{oversizedIdentifier}}, "String");
}

// Part 4 section 5.8.5.3 Table 44 requires a service-level BadNodeIdInvalid and complete rejection when
// any requested NodeId is structurally invalid. Part 3 section 8.2.4 limits Opaque identifiers to 4096
// bytes; this separate arm prevents a String-only validation fix.
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(RegisterNodesServiceTests, OversizedOpaqueNodeIdRejectsWholeRequestBeforeNamespaceDispatch)
{
  expect_structurally_invalid_node_rejects_whole_request(
    NodeId{ByteString(std::size_t{4097}, uint8_t{0xA5})}, "Opaque");
}

// OPC UA String identifiers are UTF-8 character sequences. A malformed sequence is structurally
// invalid and therefore has the same Part 4 section 5.8.5.3 whole-service BadNodeIdInvalid disposition.
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(RegisterNodesServiceTests, MalformedUtf8StringNodeIdRejectsWholeRequestBeforeNamespaceDispatch)
{
  const std::string malformedIdentifier{"\xC0\xAF"};
  ASSERT_EQ(malformedIdentifier.size(), 2u) << "the stimulus is the overlong UTF-8 encoding of '/'";
  expect_structurally_invalid_node_rejects_whole_request(NodeId{0, std::string_view{malformedIdentifier}},
    "String",
    "MalformedNodeIdStringIdentifier",
    std::nullopt,
    std::nullopt,
    string_view{"UTF-8"});
}

// Part 4 section 5.8.5.1 distinguishes structural failures from ordinary unknown NodeIds: identifiers
// at the Part 3 section 8.2.4 bounds remain structurally valid, and unknown/null NodeIds are echoed.
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(RegisterNodesServiceTests, StructuralBoundariesNullAndUnknownNodeIdsRemainGoodAndEchoed)
{
  boost::asio::thread_pool threadPool;
  auto countingNamespace = make_shared<CountingRegisterNodesNamespace>(
    "uri://structural-node-id-boundary", threadPool.get_executor());

  ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  const uint16_t namespaceIndex = server.address_space().add_namespace_sync(countingNamespace);
  constexpr uint16_t absentNamespaceIndex{65000};

  std::string maximumStringIdentifier;
  maximumStringIdentifier.reserve(4096 * 2);
  for (size_t characterIndex = 0; characterIndex < 4096; ++characterIndex)
  {
    maximumStringIdentifier += "\xC2\xA2";
  }
  ASSERT_EQ(maximumStringIdentifier.size(), 8192u)
    << "the boundary control must contain 4096 two-byte UTF-8 characters";
  const NodeId maximumString{namespaceIndex, std::string_view{maximumStringIdentifier}};
  const NodeId maximumOpaque{namespaceIndex, ByteString(std::size_t{4096}, uint8_t{0xA5})};
  const NodeId guidNode{namespaceIndex, Guid::parse("01234567-89ab-cdef-0123-456789abcdef")};
  const NodeId nullNode;
  const NodeId unknownNode{absentNamespaceIndex, "Unknown.But.Structurally.Valid"};
  const std::vector<NodeId> expected{maximumString, maximumOpaque, guidNode, nullNode, unknownNode};

  RegisterNodesRequest request;
  for (const auto& nodeId : expected)
  {
    request.nodes_to_register().push_back(nodeId);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::promise<void> done;
  std::atomic<size_t> callbackCount{0};
  std::optional<RegisterNodesServiceSet::ResponseOrServiceFault> observedResponse;

  auto service = RegisterNodesServiceSet::create(sessionInfo,
    std::move(request),
    threadPool.get_executor(),
    [&callbackCount, &done, &observedResponse](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      if (callbackCount.fetch_add(1) == 0)
      {
        observedResponse.emplace(std::move(response));
        done.set_value();
      }
    });
  UA_UNUSED(service);

  const bool completed = done.get_future().wait_for(1s) == std::future_status::ready;
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);

  ASSERT_TRUE(completed);
  ASSERT_TRUE(observedResponse.has_value());
  EXPECT_EQ(callbackCount.load(), 1u);
  const auto* response = std::get_if<RegisterNodesResponse>(&*observedResponse);
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  EXPECT_EQ(response->registered_node_ids().payload(), expected);
  EXPECT_EQ(countingNamespace->registerCalls.load(), 1u);
  EXPECT_EQ(countingNamespace->itemsSeen.load(), 3u)
    << "only the valid bounded String, Opaque, and GUID identifiers belong to the delegate namespace";
}

// Phase 5 end-to-end guarantee: a RegisterNodes delegate that drops its
// RegisterCompleteCallback without invoking it must not hang the service - the
// std::function<void(T)> RAII default fires a bad BatchResult, which the service treats
// as a batch failure and echoes the original NodeIds back (existing fallback
// behavior). The atomic flag proves the delegate was entered; the arrival of
// the response within a timeout proves the guarantee (no hang).

// --- Mixed batch: optimisable and unoptimisable Nodes in one request ------

namespace
{

// A namespace that can pre-cache a handle for exactly one identifier and has nothing to
// offer for any other Node it is given. The nodes it optimises come back under an alias
// (identifier + aliasOffset); everything else it hands straight back, which is what a
// real namespace does for a Node whose handle it cannot cache.
class PartiallyOptimisingRegisterNodesNamespace final
  : public default_ns::Namespace,
    public NamespaceRegisterNodesDelegate,
    public std::enable_shared_from_this<PartiallyOptimisingRegisterNodesNamespace>
{
public:
  static constexpr uint32_t aliasOffset{9000};

  PartiallyOptimisingRegisterNodesNamespace(
    string_view uri, boost::asio::any_io_executor executor, uint32_t optimisableIdentifier)
    : default_ns::Namespace(uri, std::move(executor)), mOptimisableIdentifier(optimisableIdentifier)
  {}

  std::atomic<size_t> itemsSeen{0};

  shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override
  {
    return std::dynamic_pointer_cast<NamespaceRegisterNodesDelegate>(shared_from_this());
  }

  void register_nodes_async(
    const Context&, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override
  {
    BatchResult<NodeId> batch;
    batch.items.reserve(items.size());
    for (auto& item : items)
    {
      itemsSeen.fetch_add(1);
      if (item.nodeId.is_numeric() && (item.nodeId.identifier().get_numeric() == mOptimisableIdentifier))
      {
        batch.items.emplace_back(
          NodeId{item.nodeId.namespace_index(), item.nodeId.identifier().get_numeric() + aliasOffset});
      }
      else
      {
        // No optimisation available for this Node - hand back the id the client supplied.
        batch.items.emplace_back(std::move(item.nodeId));
      }
    }
    callback(std::move(batch));
  }

  void unregister_nodes_async(
    const Context&, std::vector<Item>, UnregisterCompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

private:
  uint32_t mOptimisableIdentifier;
};

}  // namespace

// Part 4 section 5.8.5: RegisterNodes is an optimisation hint, so a Node the server cannot
// optimise must come back as `registeredNodeIds[i] == nodesToRegister[i]` with no error -
// erroring, or omitting the slot, would make the service unusable on the mixed batches
// that are the only kind real clients send. A plausible implementation gets this wrong in
// three ways: it rejects the whole request because part of it was not optimisable, it
// fabricates a useless alias for every id so the client loses the id it already had, or
// it packs only the optimised results and so shifts the surviving ids out of request
// order. The batch below is mixed twice over - a namespace with no register-nodes
// delegate at all (nothing the server can do), and a delegate namespace that optimises
// one of its two Nodes - and the unoptimisable slots are interleaved with the optimised
// one so a positional shift cannot pass.
// @verifies AC-SVR-VIEW-REG-007-RETURN-ORIGINAL-WHEN-NO-OPTIMISATION
TEST(RegisterNodesServiceTests, NodesTheServerCannotOptimiseAreReturnedUnchangedAndWithoutError)
{
  boost::asio::thread_pool threadPool;

  // No register-nodes delegate: the server has no optimisation to offer for anything here.
  auto plainNs = default_ns::Namespace::create("uri://no-optimisation-namespace", threadPool.get_executor());

  // Optimises identifier 601 only; 602 is a Node it cannot help with.
  auto optimisingNs = make_shared<PartiallyOptimisingRegisterNodesNamespace>(
    "uri://partial-optimisation-namespace", threadPool.get_executor(), 601u);

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  const uint16_t plainIndex = server.address_space().add_namespace_sync(plainNs);
  const uint16_t optimisingIndex = server.address_space().add_namespace_sync(optimisingNs);

  const NodeId unoptimisableA{plainIndex, 501u};
  const NodeId optimisable{optimisingIndex, 601u};
  const NodeId unoptimisableB{plainIndex, 502u};
  const NodeId unoptimisableC{optimisingIndex, 602u};
  const NodeId expectedAlias{optimisingIndex, 601u + PartiallyOptimisingRegisterNodesNamespace::aliasOffset};

  plainNs->create_node(unoptimisableA, NodeClass::Object);
  plainNs->create_node(unoptimisableB, NodeClass::Object);
  optimisingNs->create_node(optimisable, NodeClass::Object);
  optimisingNs->create_node(unoptimisableC, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  RegisterNodesRequest registerNodesRequest;
  registerNodesRequest.nodes_to_register().resize(4);
  registerNodesRequest.nodes_to_register()[0] = unoptimisableA;
  registerNodesRequest.nodes_to_register()[1] = optimisable;
  registerNodesRequest.nodes_to_register()[2] = unoptimisableB;
  registerNodesRequest.nodes_to_register()[3] = unoptimisableC;

  std::promise<void> done;
  std::vector<NodeId> registered;
  std::optional<StatusCode> gotStatus;
  std::atomic<bool> gotFault{false};

  auto service = RegisterNodesServiceSet::create(sessionInfo,
    std::move(registerNodesRequest),
    threadPool.get_executor(),
    [&](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      if (auto* ok = std::get_if<RegisterNodesResponse>(&response))
      {
        gotStatus = ok->response_header().service_result();
        registered = ok->registered_node_ids().payload();
      }
      else if (auto* sf = std::get_if<ServiceFault>(&response))
      {
        gotFault = true;
        gotStatus = sf->response_header().service_result();
      }
      done.set_value();
    });
  UA_UNUSED(service);

  ASSERT_EQ(done.get_future().wait_for(1s), std::future_status::ready);

  // No error is returned for the unoptimisable Nodes: the request is answered by a
  // RegisterNodesResponse with a Good service result, not by a fault.
  EXPECT_FALSE(gotFault.load());
  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::Good);

  // One result per requested Node, in request order.
  ASSERT_EQ(registered.size(), 4u);

  // The three Nodes the server could not optimise carry the ids the client supplied.
  EXPECT_EQ(registered[0], unoptimisableA);
  EXPECT_EQ(registered[2], unoptimisableB);
  EXPECT_EQ(registered[3], unoptimisableC);

  // The batch really was mixed: the one Node the server could optimise came back aliased,
  // so the passthrough above is a decision about those Nodes and not a blanket echo.
  EXPECT_EQ(registered[1], expectedAlias);

  // Both Nodes of the delegate namespace were offered to it - the unoptimisable one was
  // not silently withheld from the namespace that owns it.
  EXPECT_EQ(optimisingNs->itemsSeen.load(), 2u);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.5.2 (Table 43): "In case no optimization is supported for a Node, the Server
// shall return the NodeId from the request." The hard cases are the Nodes the server knows
// least about - one whose namespace index is not in the NamespaceArray at all, and one whose
// namespace exists but has never seen that identifier. A plausible implementation treats "I
// cannot resolve this" as an error and faults the whole request with Bad_NodeIdUnknown, or
// answers Good but reports the unresolvable slots through the response header's
// serviceDiagnostics/stringTable - "no error is returned for them" forbids both, because
// RegisterNodes is only a hint and a client that gets a fault loses the ids it already had for
// the Nodes the server *could* address. A second failure mode is identifier fidelity: an
// implementation that rebuilds the echo from a numeric handle rather than copying the request
// value mangles a string identifier, so slot 0 carries one. The one optimisable Node keeps the
// batch genuinely mixed, so the passthrough is a per-Node decision and not a blanket echo, and
// it sits between the unoptimisable slots so a positional shift cannot pass.
// @verifies AC-SVR-VIEW-REG-007-RETURN-ORIGINAL-WHEN-NO-OPTIMISATION
TEST(RegisterNodesServiceTests, UnresolvableNodesAreEchoedBackWithoutErrorOrDiagnostic)
{
  boost::asio::thread_pool threadPool;

  // No register-nodes delegate: the SDK's own no-optimisation path answers for this namespace.
  auto plainNs = default_ns::Namespace::create("uri://echo-only-namespace", threadPool.get_executor());

  // Optimises identifier 701 only.
  auto optimisingNs = make_shared<PartiallyOptimisingRegisterNodesNamespace>(
    "uri://partial-optimisation-namespace-2", threadPool.get_executor(), 701u);

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  const uint16_t plainIndex = server.address_space().add_namespace_sync(plainNs);
  const uint16_t optimisingIndex = server.address_space().add_namespace_sync(optimisingNs);

  // An index past everything the server was given - there is no Namespace object behind it.
  const uint16_t absentNamespaceIndex = static_cast<uint16_t>(optimisingIndex + 7u);

  const NodeId stringIdentifierNode{plainIndex, "node-addressed-by-name"};
  const NodeId optimisable{optimisingIndex, 701u};
  const NodeId nodeInAbsentNamespace{absentNamespaceIndex, 4242u};
  const NodeId neverCreatedNode{plainIndex, 9999u};
  const NodeId expectedAlias{optimisingIndex, 701u + PartiallyOptimisingRegisterNodesNamespace::aliasOffset};

  plainNs->create_node(stringIdentifierNode, NodeClass::Object);
  optimisingNs->create_node(optimisable, NodeClass::Object);
  // neverCreatedNode and nodeInAbsentNamespace are deliberately not created.

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  RegisterNodesRequest registerNodesRequest;
  // Ask for the fullest diagnostics the client can ask for, so "no error is returned" is
  // asserted at the setting under which a server would be most tempted to report one.
  registerNodesRequest.request_header().return_diagnostics() = 0xFFFF;
  registerNodesRequest.nodes_to_register().resize(4);
  registerNodesRequest.nodes_to_register()[0] = stringIdentifierNode;
  registerNodesRequest.nodes_to_register()[1] = optimisable;
  registerNodesRequest.nodes_to_register()[2] = nodeInAbsentNamespace;
  registerNodesRequest.nodes_to_register()[3] = neverCreatedNode;

  std::promise<void> done;
  std::vector<NodeId> registered;
  std::optional<StatusCode> gotStatus;
  std::atomic<bool> gotFault{false};
  std::optional<bool> diagnosticsAreNull;
  std::optional<bool> stringTableIsEmpty;

  auto service = RegisterNodesServiceSet::create(sessionInfo,
    std::move(registerNodesRequest),
    threadPool.get_executor(),
    [&](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      if (auto* ok = std::get_if<RegisterNodesResponse>(&response))
      {
        gotStatus = ok->response_header().service_result();
        registered = ok->registered_node_ids().payload();
        diagnosticsAreNull = ok->response_header().service_diagnostics().is_null();
        stringTableIsEmpty = ok->response_header().string_table().empty();
      }
      else if (auto* sf = std::get_if<ServiceFault>(&response))
      {
        gotFault = true;
        gotStatus = sf->response_header().service_result();
      }
      done.set_value();
    });
  UA_UNUSED(service);

  ASSERT_EQ(done.get_future().wait_for(1s), std::future_status::ready);

  // Not resolving a Node is not an error: the answer is a RegisterNodesResponse with a Good
  // service result, not a fault, even though three of the four Nodes could not be optimised.
  EXPECT_FALSE(gotFault.load());
  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::Good);

  // One result per requested Node, in request order - nothing is dropped for being unoptimisable.
  ASSERT_EQ(registered.size(), 4u);

  // Each Node the server has no optimisation for carries back exactly the id supplied.
  EXPECT_EQ(registered[0], stringIdentifierNode);
  EXPECT_EQ(registered[2], nodeInAbsentNamespace);
  EXPECT_EQ(registered[3], neverCreatedNode);

  // The echoed id is the request value, identifier type and all - not a rebuilt numeric handle.
  EXPECT_TRUE(registered[0].is_string());
  EXPECT_EQ(registered[2].namespace_index(), absentNamespaceIndex);

  // The batch really was mixed: the one Node the server could optimise came back aliased.
  EXPECT_EQ(registered[1], expectedAlias);

  // ...and no error was reported for the unoptimisable Nodes by the back door either: with full
  // diagnostics requested the response header carries neither a serviceDiagnostics entry nor a
  // string-table entry describing them.
  ASSERT_TRUE(diagnosticsAreNull.has_value());
  EXPECT_TRUE(*diagnosticsAreNull);
  ASSERT_TRUE(stringTableIsEmpty.has_value());
  EXPECT_TRUE(*stringTableIsEmpty);

  // The optimisable Node was the only one handed to the delegate namespace; the Nodes belonging
  // to namespaces with nothing to offer were answered without inventing a delegate for them.
  EXPECT_EQ(optimisingNs->itemsSeen.load(), 1u);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
