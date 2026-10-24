// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::ConnectionDispatch (section 8.2A.5) - the wire-op submit gate +
// reconnect pause/queue coordination at the core of ConnectionImpl. Active -> dispatch now; Reconnecting ->
// queue (or fail-fast); Failed/Closed -> fail; notify_active flushes FIFO; notify_failed/close drain.
//
// Falsifiability: a no-op stub never dispatches (SubmitDispatchesWhenActive fails), never flushes
// (NotifyActiveFlushes fails), never fires close's callback (Close fails).

#include "ua_connection_dispatch.h"

#include "ua_logger.h"
#include "ua_pending_request_queue.h"
#include "ua_result.h"
#include "ua_status.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using ua::client::detail::ConnectionDispatch;
using ua::client::detail::DispatchState;
using ua::client::detail::PendingRequest;

struct Recorder
{
  std::vector<std::string> log;

  PendingRequest make(std::string tag)
  {
    PendingRequest request;
    request.dispatch = [this, tag]
    {
      log.push_back("dispatch:" + tag);
    };
    request.fail = [this, tag](ua::StatusCode status)
    {
      log.push_back("fail:" + tag + ":" + std::to_string(status.value()));
    };
    request.enqueuedAt = std::chrono::steady_clock::now();
    request.operationTag = tag;
    return request;
  }
};

struct Fixture
{
  boost::asio::io_context ctx;
  Recorder rec;

  std::shared_ptr<ConnectionDispatch> make(bool queueOnReconnect = true)
  {
    return ConnectionDispatch::create(
      ctx.get_executor(), queueOnReconnect, /*limit=*/1024, /*maxAge=*/30s, ua::Logger{});
  }
};

TEST(ConnectionDispatch, SubmitDispatchesWhenActive)
{
  Fixture f;
  auto gate = f.make();
  gate->submit_async(f.rec.make("a"));
  f.ctx.run();
  EXPECT_EQ(f.rec.log, (std::vector<std::string>{"dispatch:a"}));
}

TEST(ConnectionDispatch, SubmitQueuesWhenReconnecting)
{
  Fixture f;
  auto gate = f.make();
  gate->notify_reconnecting_async();
  gate->submit_async(f.rec.make("a"));
  f.ctx.run();
  EXPECT_TRUE(f.rec.log.empty()) << "a submit during reconnect must not dispatch";
  EXPECT_EQ(gate->info()->state, DispatchState::Reconnecting);
  EXPECT_EQ(gate->info()->pendingCount, 1u);
}

TEST(ConnectionDispatch, NotifyActiveFlushesQueueFifo)
{
  Fixture f;
  auto gate = f.make();
  gate->notify_reconnecting_async();
  gate->submit_async(f.rec.make("a"));
  gate->submit_async(f.rec.make("b"));
  gate->notify_active_async();
  f.ctx.run();
  EXPECT_EQ(f.rec.log, (std::vector<std::string>{"dispatch:a", "dispatch:b"}));
  EXPECT_EQ(gate->info()->state, DispatchState::Active);
  EXPECT_EQ(gate->info()->pendingCount, 0u);
}

TEST(ConnectionDispatch, SubmitFailsFastWhenReconnectingWithoutQueue)
{
  Fixture f;
  auto gate = f.make(/*queueOnReconnect=*/false);
  gate->notify_reconnecting_async();
  gate->submit_async(f.rec.make("a"));
  f.ctx.run();
  ASSERT_EQ(f.rec.log.size(), 1u);
  EXPECT_EQ(
    f.rec.log[0], "fail:a:" + std::to_string(static_cast<uint32_t>(ua::Status::BadSessionNotActivated)));
}

TEST(ConnectionDispatch, NotifyFailedDrainsQueue)
{
  Fixture f;
  auto gate = f.make();
  gate->notify_reconnecting_async();
  gate->submit_async(f.rec.make("a"));
  gate->submit_async(f.rec.make("b"));
  gate->notify_failed_async(ua::Status::BadConnectionClosed);
  f.ctx.run();
  const auto code = std::to_string(static_cast<uint32_t>(ua::Status::BadConnectionClosed));
  EXPECT_EQ(f.rec.log, (std::vector<std::string>{"fail:a:" + code, "fail:b:" + code}));
  EXPECT_EQ(gate->info()->state, DispatchState::Failed);
}

TEST(ConnectionDispatch, SubmitFailsWhenClosed)
{
  Fixture f;
  auto gate = f.make();
  gate->close_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();
  gate->submit_async(f.rec.make("a"));
  f.ctx.run();
  ASSERT_EQ(f.rec.log.size(), 1u);
  EXPECT_EQ(f.rec.log[0], "fail:a:" + std::to_string(static_cast<uint32_t>(ua::Status::BadConnectionClosed)));
}

TEST(ConnectionDispatch, CloseDrainsQueueAndReportsGood)
{
  Fixture f;
  auto gate = f.make();
  gate->notify_reconnecting_async();
  gate->submit_async(f.rec.make("a"));

  ua::VoidResult closed{ua::Status::BadInternalError};
  gate->close_async([&](ua::VoidResult r) { closed = r; });
  f.ctx.run();

  EXPECT_TRUE(closed.is_good());
  EXPECT_EQ(gate->info()->state, DispatchState::Closed);
  ASSERT_EQ(f.rec.log.size(), 1u) << "the queued op must be drained on close";
  EXPECT_EQ(f.rec.log[0], "fail:a:" + std::to_string(static_cast<uint32_t>(ua::Status::BadConnectionClosed)));
}

}  // namespace
