// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>

#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "ua_call_request.h"
#include "ua_browse_request.h"
#include "ua_read_request.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_read_service.h"
#include "ua_browse_service.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_method_service_set.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

// @relation(SVR-VIEW-TBP-008, scope=function)
TEST(OperationLimitsServiceTests, TranslateBrowsePathsTooManyOperationsIsRejected)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().operationLimits.maxNodesPerTranslateBrowsePathsToNodeIds = 1;

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverCfg)};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  TranslateBrowsePathsToNodeIdsRequest req;
  req.browse_paths().resize(2);

  std::condition_variable cv;
  std::mutex mtx;
  std::optional<StatusCode> gotStatus;

  auto svc = TranslateBrowsePathsService::create(sessionInfo,
    {},
    1,
    std::move(req),
    threadPool.get_executor(),
    [&](auto r)
    {
      auto* sf = dynamic_cast<ServiceFault*>(r.second.get());
      ASSERT_NE(sf, nullptr);
      {
        std::lock_guard<std::mutex> lk(mtx);
        gotStatus = sf->response_header().service_result();
      }
      cv.notify_all();
    });
  UA_UNUSED(svc);

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 1000ms, [&]() { return gotStatus.has_value(); });

  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::BadTooManyOperations);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(OperationLimitsServiceTests, ReadTooManyOperationsIsRejected)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().operationLimits.maxNodesPerRead = 1;

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverCfg)};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  ReadRequest req;
  req.nodes_to_read().resize(2);

  std::condition_variable cv;
  std::mutex mtx;
  std::optional<StatusCode> gotStatus;

  auto svc = ReadService::create(sessionInfo,
    {},
    1,
    std::move(req),
    threadPool.get_executor(),
    [&](auto response)
    {
      auto* sf = dynamic_cast<ServiceFault*>(response.second.get());
      ASSERT_NE(sf, nullptr);
      {
        std::lock_guard<std::mutex> lk(mtx);
        gotStatus = sf->response_header().service_result();
      }
      cv.notify_all();
    });
  UA_UNUSED(svc);

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 1000ms, [&]() { return gotStatus.has_value(); });

  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::BadTooManyOperations);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(SVR-VIEW-BRW-008, scope=function)
TEST(OperationLimitsServiceTests, BrowseTooManyOperationsIsRejected)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().operationLimits.maxNodesPerBrowse = 1;

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverCfg)};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  BrowseRequest req;
  req.nodes_to_browse().resize(2);

  std::condition_variable cv;
  std::mutex mtx;
  std::optional<StatusCode> gotStatus;

  auto svc = BrowseService::create(sessionInfo,
    {},
    1,
    std::move(req),
    threadPool.get_executor(),
    [&](BrowseService::BrowseServiceResponse response)
    {
      auto* sf = dynamic_cast<ServiceFault*>(response.response.second.get());
      ASSERT_NE(sf, nullptr);
      {
        std::lock_guard<std::mutex> lk(mtx);
        gotStatus = sf->response_header().service_result();
      }
      cv.notify_all();
    });
  UA_UNUSED(svc);

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 1000ms, [&]() { return gotStatus.has_value(); });

  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::BadTooManyOperations);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(OperationLimitsServiceTests, MethodCallTooManyOperationsIsRejected)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().operationLimits.maxNodesPerMethodCall = 1;

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverCfg)};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  CallRequest req;
  req.methods_to_call().resize(2);

  std::condition_variable cv;
  std::mutex mtx;
  std::optional<StatusCode> gotStatus;

  auto svc = MethodServiceSet::create(sessionInfo,
    {},
    1,
    std::move(req),
    threadPool.get_executor(),
    [&](auto r)
    {
      auto* sf = dynamic_cast<ServiceFault*>(r.second.get());
      ASSERT_NE(sf, nullptr);
      {
        std::lock_guard<std::mutex> lk(mtx);
        gotStatus = sf->response_header().service_result();
      }
      cv.notify_all();
    });
  UA_UNUSED(svc);

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 1000ms, [&]() { return gotStatus.has_value(); });

  ASSERT_TRUE(gotStatus.has_value());
  EXPECT_EQ(*gotStatus, Status::BadTooManyOperations);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// CreateMonitoredItemsTooManyOperationsIsRejected - removed with MonitoredItemsServiceSet stub.
// Will be re-implemented against SubscriptionsPipeline in the subscription test suite.
