// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <future>
#include <thread>

#include "ua_server.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// Calls ::ua::test_utils::drain_with_timeout(pool) on a worker thread and waits up to `timeout` for it to
// return. On timeout, forcibly stops the pool so the worker can be joined (test still fails). This is the
// property Phase A is meant to enforce: after the foolproof shutdown pattern,
// ::ua::test_utils::drain_with_timeout(pool) must return without needing pool.stop() to force termination.
::testing::AssertionResult join_with_timeout(
  boost::asio::thread_pool& pool, std::chrono::milliseconds timeout)
{
  std::promise<void> done;
  auto fut = done.get_future();
  std::thread joiner(
    [&]()
    {
      ::ua::test_utils::drain_with_timeout(pool);
      done.set_value();
    });
  if (fut.wait_for(timeout) == std::future_status::ready)
  {
    joiner.join();
    return ::testing::AssertionSuccess();
  }
  pool.stop();
  joiner.join();
  return ::testing::AssertionFailure()
         << "::ua::test_utils::drain_with_timeout(pool) did not return within " << timeout.count() << "ms";
}

Server make_test_server(boost::asio::any_io_executor ex)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = Server::create(
    ex, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  return server;
}

constexpr auto joinTimeout = 5s;

}  // namespace

// Bare shutdown: create Server, call shutdown_sync, ::ua::test_utils::drain_with_timeout(pool) must return
// promptly.
TEST(ServerShutdownSafetyTests, JoinReturnsAfterBareShutdown)
{
  boost::asio::thread_pool pool;
  {
    auto server = make_test_server(pool.get_executor());
    server.shutdown_sync();
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Shutdown with an active listener: opens a TCP listener, shuts down,
// ::ua::test_utils::drain_with_timeout(pool) must return promptly. Exercises the cascade through acceptor
// close + listener teardown.
TEST(ServerShutdownSafetyTests, JoinReturnsAfterShutdownWithActiveListener)
{
  boost::asio::thread_pool pool;
  {
    auto server = make_test_server(pool.get_executor());

    ua::transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    (void)server.listen_sync(std::move(bind), {});

    server.shutdown_sync();
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Double shutdown: the first call drains the impl; the second sees a null impl and
// must return BadInvalidState (not crash, not hang).
TEST(ServerShutdownSafetyTests, DoubleShutdownReturnsBadInvalidState)
{
  boost::asio::thread_pool pool;
  auto server = make_test_server(pool.get_executor());

  const auto first = server.try_shutdown_sync();
  EXPECT_TRUE(first.is_good());

  const auto second = server.try_shutdown_sync();
  ASSERT_TRUE(second.is_bad());
  EXPECT_EQ(second.status_code(), StatusCode{Status::BadInvalidState});

  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// RAII destruction without explicit shutdown: drop Server out of scope,
// ::ua::test_utils::drain_with_timeout(pool) must still return promptly. The Server destructor releases the
// impl strong-ref; ~ServerImpl runs the same cascade that explicit shutdown would. Validates the "user forgot
// to call shutdown" path the design doc calls out as the RAII fallback.
TEST(ServerShutdownSafetyTests, JoinReturnsAfterRaiiDestructionNoShutdown)
{
  boost::asio::thread_pool pool;
  {
    auto server = make_test_server(pool.get_executor());
    (void)server;
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// RAII destruction with an active listener and no explicit shutdown: a more
// realistic "user forgot" path - listener bound, then Server scope exits.
TEST(ServerShutdownSafetyTests, JoinReturnsAfterRaiiDestructionWithActiveListener)
{
  boost::asio::thread_pool pool;
  {
    auto server = make_test_server(pool.get_executor());

    ua::transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    (void)server.listen_sync(std::move(bind), {});
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}
