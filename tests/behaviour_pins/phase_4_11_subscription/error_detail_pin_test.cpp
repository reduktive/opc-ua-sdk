// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11a (Subscription / SubscriptionsPipeline) -
// ErrorDetail propagation cluster. Only ED-G survives the section 9.5 dissolve audit;
// ED-A..ED-F were retired (skip-only stubs depending on fakes that never landed
// and/or documented production-side ErrorDetail-loss gaps).

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_diagnostic_bits.h"
#include "ua_service_fault.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_subscription_id_allocator.h"
#include "ua_subscriptions_pipeline.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{

// ED-G - Close-drain publish queue fault carries non-null detail.
// Production at ua_subscriptions_pipeline.cpp drain_publish_queue allocates
// make_error_detail("SessionClosed") and applies it via DiagnosticCollector.
// When the client requests service-level diagnostics in
// request_header().return_diagnostics() and the Session's diagnostic context
// allows them, the resulting ServiceFault's response_header().service_diagnostics()
// carries the symbolicId derived from the ErrorDetail.
TEST(SubscriptionErrorDetailPin, CloseDrainPublishQueueFaultDetailNonNull)
{
  using namespace ua;
  using namespace ua::server;
  using namespace std::chrono_literals;

  boost::asio::thread_pool pool;
  SubscriptionIdAllocator idAllocator;
  auto counters = std::make_shared<ServerSummaryCounters>();
  auto executor = pool.get_executor();
  boost::asio::strand<boost::asio::any_io_executor> strand = boost::asio::make_strand(executor);

  std::mutex mutex;
  std::condition_variable cv;
  std::vector<Response> responses;

  auto manager = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = executor,
    .sessionStrand = strand,
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = counters,
    .capabilities = {},
    .sendResponse =
      [&](Response r)
    {
      std::lock_guard lk(mutex);
      responses.push_back(std::move(r));
      cv.notify_all();
    },
    .diagnosticSecurityContext =
      []
    {
      return DiagnosticSecurityContext{.authenticated = true,
        .securedChannel = true,
        .effectiveLevel = ServerConfig::DiagnosticPolicy::Level::Summary};
    },
  });

  auto runOnStrand = [&](auto&& fn)
  {
    std::promise<void> done;
    boost::asio::post(strand,
      [&]()
      {
        fn();
        done.set_value();
      });
    done.get_future().get();
  };

  // Create a subscription so PublishRequests are queued (no-subscription path
  // would short-circuit with BadNoSubscription).
  {
    CreateSubscriptionRequest createReq;
    createReq.requested_publishing_interval() = 50.0;
    createReq.requested_lifetime_count() = 300;
    createReq.requested_max_keep_alive_count() = 10;
    createReq.max_notifications_per_publish() = 0;
    createReq.publishing_enabled() = true;
    createReq.priority() = 0;
    runOnStrand([&]() { manager->handle_create_subscription(/*reqId=*/100u, createReq); });
    std::unique_lock waitLk(mutex);
    cv.wait_for(waitLk, 1000ms, [&] { return responses.size() >= 1; });
  }

  // Queue two publish requests that request service-level diagnostics
  // (symbolicId + localizedText bits - sufficient to surface ErrorDetail).
  for (int i = 0; i < 2; ++i)
  {
    PublishRequest req;
    req.request_header().return_diagnostics() = diag::serviceSymbolicId | diag::serviceLocalizedText;
    uint32_t reqId = static_cast<uint32_t>(i + 1);
    runOnStrand([&]() { manager->handle_publish(reqId, req); });
  }

  // Snapshot response count before close_all so we can isolate drain output.
  size_t before;
  {
    std::lock_guard lk(mutex);
    before = responses.size();
  }

  // Drive close_all - drains queued PublishRequests with BadSessionClosed.
  runOnStrand([&]() { manager->close_all(); });

  std::unique_lock lk(mutex);
  ASSERT_TRUE(cv.wait_for(lk, 2000ms, [&] { return responses.size() >= before + 2; }));

  size_t faultsChecked = 0;
  for (size_t i = before; i < responses.size(); ++i)
  {
    auto* fault = dynamic_cast<ServiceFault*>(responses[i].second.get());
    if (!fault)
      continue;
    if (fault->response_header().service_result() != StatusCode{Status::BadSessionClosed})
      continue;
    // service_diagnostics() should carry the symbolicId that derives from
    // make_error_detail("SessionClosed", ...). The DiagnosticCollector
    // emits a non-empty DiagnosticInfo when the bitmask requests it.
    const auto& info = fault->response_header().service_diagnostics();
    EXPECT_TRUE(info.symbolic_id().has_value())
      << "drain_publish_queue must allocate ErrorDetail at the rejection site so symbolicId surfaces";
    ++faultsChecked;
  }
  EXPECT_GE(faultsChecked, 2u) << "expected ServiceFault{BadSessionClosed} for each queued PublishRequest";

  lk.unlock();
  pool.join();
}

}  // namespace ua::test::behaviour_pins
