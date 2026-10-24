// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <fmt/core.h>
#include <chrono>
#include <future>
#include <boost/asio/io_context.hpp>
#include "ua_read_service.h"
#include "ua_default_object_node.h"
#include "ua_default_namespace.h"
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

// @relation(SVR-VIEW-URG-001, SVR-VIEW-URG-002, scope=function)
TEST(UnregisterNodesServiceTests, UnregisterASingleNode)
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

  UnregisterNodesRequest unregisterNodesRequest;
  unregisterNodesRequest.nodes_to_unregister().resize(1);
  unregisterNodesRequest.nodes_to_unregister()[0] = NodeId{123};

  std::promise<void> done;
  std::atomic<bool> gotExpectedResult{false};

  auto unregisterNodesService = RegisterNodesServiceSet::create(sessionInfo,
    std::move(unregisterNodesRequest),
    threadPool.get_executor(),
    [&done, &gotExpectedResult](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      auto unregisterNodesResponse = std::get_if<UnregisterNodesResponse>(&response);
      if (unregisterNodesResponse && unregisterNodesResponse->response_header().service_result().is_good())
      {
        gotExpectedResult = true;
      }
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(1s), std::future_status::ready);

  GTEST_ASSERT_TRUE(gotExpectedResult);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Covers SVR-BASE-007 (coverage-audit retag).
// @relation(SVR-VIEW-URG-002, scope=function)
TEST(UnregisterNodesServiceTests, TooManyOperationsIsRejected)
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

  UnregisterNodesRequest unregisterNodesRequest;
  unregisterNodesRequest.nodes_to_unregister().resize(2);
  unregisterNodesRequest.nodes_to_unregister()[0] = NodeId{123};
  unregisterNodesRequest.nodes_to_unregister()[1] = NodeId{123};

  std::promise<void> done;
  std::optional<StatusCode> gotStatus;

  auto service = RegisterNodesServiceSet::create(sessionInfo,
    std::move(unregisterNodesRequest),
    threadPool.get_executor(),
    [&](RegisterNodesServiceSet::ResponseOrServiceFault response)
    {
      if (auto* sf = std::get_if<ServiceFault>(&response))
      {
        gotStatus = sf->response_header().service_result();
      }
      else if (auto* ok = std::get_if<UnregisterNodesResponse>(&response))
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
