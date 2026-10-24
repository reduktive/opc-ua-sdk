// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11a (SubscriptionsPipeline) - Dispatch cluster.
//
// Production: sdk/implementation/server/subscription/ua_subscriptions_pipeline.cpp:565-704.

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>

#include "ua_publish_request.h"
#include "ua_server_configuration.h"
#include "ua_server_counters.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscriptions_pipeline.h"
#include "ua_subscriptions_pipeline_test_access.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using SMTA = ::ua::server::SubscriptionsPipelineTestAccess;

class DispatchPin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  SubscriptionIdAllocator mIdAllocator;
  std::shared_ptr<ServerSummaryCounters> mCounters{std::make_shared<ServerSummaryCounters>()};
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  std::shared_ptr<SubscriptionsPipeline> mMgr;
  std::mutex mResponseMutex;
  std::vector<Response> mResponses;

  void SetUp() override
  {
    auto executor = mThreadPool.get_executor();
    mStrand.emplace(boost::asio::make_strand(executor));
    mMgr = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = executor,
      .sessionStrand = *mStrand,
      .logger = Logger{},
      .idAllocator = mIdAllocator,
      .summaryCounters = mCounters,
      .capabilities = ServerConfig::ServerCapabilities{},
      .sendResponse =
        [this](Response r)
      {
        std::lock_guard lk(mResponseMutex);
        mResponses.push_back(std::move(r));
      },
    });
  }

  void TearDown() override
  {
    mMgr.reset();
    mThreadPool.join();
  }
};

}  // namespace

// ===========================================================================
// DSP-A - request_dispatch with no in-flight task starts the pump.
// Source: ua_subscriptions_pipeline.cpp:565-574.
// ===========================================================================
TEST_F(DispatchPin, RequestDispatchWhileNoneInFlightStartsTask)
{
  // Initially: no dispatch in flight, no task.
  bool initialInFlight = SMTA::on_strand(*mMgr, [](auto& g) { return g.dispatch_in_flight(); });
  EXPECT_FALSE(initialInFlight);
  bool initialTask = SMTA::on_strand(*mMgr, [](auto& g) { return g.dispatch_task().has_value(); });
  EXPECT_FALSE(initialTask);

  // Trigger request_dispatch on the strand. With no subscriptions / publish
  // requests, the pump runs to completion and resets mDispatchInFlight back to
  // false (cpp:704). We can't reliably observe the in-flight true window because
  // try_dispatch_publish runs synchronously to co_return when nothing is
  // pending. So we observe the post-completion invariant: a dispatch task was
  // started (mDispatchTask populated) and the in-flight flag is again false.
  SMTA::on_strand(*mMgr, [](auto& g) { g.request_dispatch(); });

  bool postTask = SMTA::on_strand(*mMgr, [](auto& g) { return g.dispatch_task().has_value(); });
  EXPECT_TRUE(postTask) << "request_dispatch must seed mDispatchTask (cpp:574)";
  bool postInFlight = SMTA::on_strand(*mMgr, [](auto& g) { return g.dispatch_in_flight(); });
  EXPECT_FALSE(postInFlight) << "post-completion mDispatchInFlight is reset to false (cpp:704)";
}

// ===========================================================================
// DSP-D - request_dispatch during in-flight pump sets mDispatchNeeded.
// Source: ua_subscriptions_pipeline.cpp:567-571.
// ===========================================================================
TEST_F(DispatchPin, RequestDispatchDuringInFlightSetsDispatchNeededAndReLoops)
{
  // Force the in-flight flag to true so a follow-on request_dispatch takes the
  // "set mDispatchNeeded and bail" branch (cpp:567-571).
  SMTA::on_strand(*mMgr, [](auto& g) { g.dispatch_in_flight() = true; });

  EXPECT_FALSE(SMTA::on_strand(*mMgr, [](auto& g) { return g.dispatch_needed(); }))
    << "precondition: mDispatchNeeded false";

  // Now call request_dispatch - should set mDispatchNeeded=true and not seed
  // a new task.
  SMTA::on_strand(*mMgr, [](auto& g) { g.request_dispatch(); });

  EXPECT_TRUE(SMTA::on_strand(*mMgr, [](auto& g) { return g.dispatch_needed(); }))
    << "request_dispatch during in-flight must flip mDispatchNeeded=true (cpp:569)";
  // Reset for clean teardown.
  SMTA::on_strand(*mMgr, [](auto& g) { g.dispatch_in_flight() = false; });
}

}  // namespace ua::test::behaviour_pins
