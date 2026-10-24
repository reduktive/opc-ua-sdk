// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Absent-session guard unit tests for SessionViewServices (View Service Set forwarder).
//
// Each async method locks its weak_ptr<SessionImpl>; when the owning session has been destroyed the
// guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling pointer. The
// harness grabs a live service handle, then destroys the impl so the handle's weak_ptr is expired.
// A missing guard would crash on the null lock or never invoke the callback, not return
// Bad_SessionIdInvalid; a still-live (Closed) impl would return Bad_SessionClosed. Only a genuinely
// dead session plus a working guard yields Bad_SessionIdInvalid.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "session_service_guard_fixture.h"
#include "test_utilities.h"

#include "ua_browse_path_result.h"
#include "ua_browse_result.h"
#include "ua_error_detail.h"
#include "ua_session_view_services.h"

#include <boost/asio/thread_pool.hpp>

#include <condition_variable>
#include <mutex>
#include <optional>

using namespace ua;
using namespace ua::client;
using ua::client::guard_test::DeadSessionHarness;
using ua::client::test_capture::CaptureHarness;

using namespace std::chrono_literals;

TEST(SessionViewServicesGuard, BrowseOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto view = harness.live().view();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  view.browse_async(BrowseRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionViewServicesGuard, BrowseNextOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto view = harness.live().view();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  view.browse_next_async(BrowseNextRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionViewServicesGuard, TranslateBrowsePathsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto view = harness.live().view();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  view.translate_browse_paths_async(TranslateBrowsePathsToNodeIdsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionViewServicesGuard, RegisterNodesOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto view = harness.live().view();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  view.register_nodes_async(RegisterNodesRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionViewServicesGuard, UnregisterNodesOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto view = harness.live().view();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  view.unregister_nodes_async(UnregisterNodesRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

// --- Response-forwarding / per-item decomposition tests (real send -> response -> callback path) ---
//
// These drive the real SessionViewServices accessor over a live SessionImpl / null-connection
// SecureChannel (the capture harness), then resolve the parked channel request with a synthetic
// response. They assert the tier-0 forwarder surfaces per-node/per-path statuses at their own index
// (batch not collapsed) and surfaces a service-level Bad on the batch Result without discarding its
// ErrorDetail.

// @verifies CL-VIEW-004
// Part 4 section 5.8.2.4 + section 7.6: each BrowseResult.statusCode is surfaced independently of the
// ServiceResult and of its peers - a single bad per-node status must not invalidate the rest of the batch.
// Drives a real Browse and injects a Good service result whose per-node results are {Bad, Good, Uncertain}.
// Falsifies any implementation that collapses the batch (returns a bad Result when any per-node status
// is bad), drops/filters entries, reorders them, or overwrites per-node codes with the service result:
// the is_good(), size(), and per-index status assertions would each fail.
// @relation(CL-VIEW-004, scope=function)
TEST(SessionViewServicesForwarding, BrowsePerNodeStatusesSurfaceIndependentlyOfServiceResult)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto view = harness.session_handle().view();

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    std::optional<SessionViewServices::BrowseResponseResult> captured;

    view.browse_async(BrowseRequest{},
      [&](SessionViewServices::BrowseResponseResult result)
      {
        std::lock_guard<std::mutex> lk(mx);
        captured.emplace(std::move(result));
        fired = true;
        cv.notify_one();
      });

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "browse_async must forward a Browse through the real Session -> SecureChannel send path";
    ASSERT_TRUE(harness.first_captured<BrowseRequest>().has_value())
      << "the driven Browse must reach the channel as a BrowseRequest";

    auto response = std::make_shared<BrowseResponse>();
    response->response_header().service_result() = Status::Good;
    BrowseResult badNode;
    badNode.status_code() = Status::BadNodeIdInvalid;
    BrowseResult goodNode;
    goodNode.status_code() = Status::Good;
    BrowseResult uncertainNode;
    uncertainNode.status_code() = Status::UncertainNotAllNodesAvailable;
    response->results().push_back(badNode);
    response->results().push_back(goodNode);
    response->results().push_back(uncertainNode);
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }

    ASSERT_TRUE(captured.has_value());
    ASSERT_TRUE(captured->is_good())
      << "a per-node bad status must not turn the whole Browse batch Result bad";
    const auto& resp = captured->value();
    ASSERT_EQ(resp.results().size(), 3u) << "every per-node result must be surfaced, none filtered";
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadNodeIdInvalid});
    EXPECT_EQ(resp.results()[1].status_code(), StatusCode{Status::Good});
    EXPECT_EQ(resp.results()[2].status_code(), StatusCode{Status::UncertainNotAllNodesAvailable});
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-VIEW-006
// Part 4 section 5.8.2.3 Table 35: a service-level Bad rejects the request as a whole - the client must
// surface that status on the awaited batch Result (aborting the batch), not swallow it or return a
// good Result. A service-level Bad reaches the session as a bad channel result (the SecureChannel
// converts a ServiceFault into a bad ServiceResponseResult); this test resolves the parked channel
// request with a bad SRR carrying Bad_ViewIdUnknown + an ErrorDetail, exactly as the channel would.
// Falsifies any forwarder that maps the service status to a generic code, reports the batch as good,
// or discards the ErrorDetail (highest-priority no-discard rule).
// @relation(CL-VIEW-006, scope=function)
TEST(SessionViewServicesForwarding, BrowseServiceLevelBadSurfacesStatusAndDetailForBatch)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto view = harness.session_handle().view();

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    std::optional<SessionViewServices::BrowseResponseResult> captured;

    view.browse_async(BrowseRequest{},
      [&](SessionViewServices::BrowseResponseResult result)
      {
        std::lock_guard<std::mutex> lk(mx);
        captured.emplace(std::move(result));
        fired = true;
        cv.notify_one();
      });

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "browse_async must forward a Browse through the real send path before a fault can arrive";

    auto serviceDetail = std::shared_ptr<const ErrorDetail>(
      make_error_detail("ServiceFault", "Server rejected the Browse batch", "server"));

    // Resolve the oldest parked channel request with a service-level bad result, mirroring the
    // SecureChannel's ServiceFault -> bad ServiceResponseResult conversion.
    bool injected = SecureChannelTestAccess::on_strand(*harness.channel,
      [&](auto& guard) -> bool
      {
        auto& pending = guard.pending_requests();
        if (pending.empty())
        {
          return false;
        }
        auto it = pending.begin();
        auto channelCallback = std::move(it->second);
        pending.erase(it);
        channelCallback(SecureChannelImpl::ServiceResponseResult{Status::BadViewIdUnknown, serviceDetail});
        return true;
      });
    ASSERT_TRUE(injected) << "a Browse request must be parked in the channel to fail";

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }

    ASSERT_TRUE(captured.has_value());
    EXPECT_FALSE(captured->is_good())
      << "a service-level Bad must abort the batch (bad Result), not surface as good";
    EXPECT_EQ(captured->status_code(), StatusCode{Status::BadViewIdUnknown})
      << "the exact service-level status must surface on the batch Result";
    ASSERT_NE(captured->shared_detail(), nullptr) << "the ErrorDetail must not be discarded at the interface";
    EXPECT_EQ(captured->shared_detail().get(), serviceDetail.get())
      << "the inbound ErrorDetail must be propagated through verbatim, not rebuilt or dropped";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-VIEW-016
// Part 4 section 5.8.4.4 Table 42: each BrowsePathResult.statusCode is surfaced independently at its index,
// distinct from the service-level result - one bad path does not invalidate the others. Drives a real
// TranslateBrowsePathsToNodeIds and injects a Good service result whose per-path results are
// {Bad_NoMatch, Good, Uncertain_ReferenceOutOfServer}. Falsifies any implementation that collapses
// the batch on a per-path bad, drops/reorders entries, or overwrites per-path codes with the service
// result.
// @relation(CL-VIEW-016, scope=function)
TEST(SessionViewServicesForwarding, TranslatePerPathStatusesSurfaceIndependentlyOfServiceResult)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto view = harness.session_handle().view();

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    std::optional<SessionViewServices::TranslateResponseResult> captured;

    view.translate_browse_paths_async(TranslateBrowsePathsToNodeIdsRequest{},
      [&](SessionViewServices::TranslateResponseResult result)
      {
        std::lock_guard<std::mutex> lk(mx);
        captured.emplace(std::move(result));
        fired = true;
        cv.notify_one();
      });

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "translate_browse_paths_async must forward the request through the real send path";
    ASSERT_TRUE(harness.first_captured<TranslateBrowsePathsToNodeIdsRequest>().has_value())
      << "the driven Translate must reach the channel as a TranslateBrowsePathsToNodeIdsRequest";

    auto response = std::make_shared<TranslateBrowsePathsToNodeIdsResponse>();
    response->response_header().service_result() = Status::Good;
    BrowsePathResult noMatchPath;
    noMatchPath.status_code() = Status::BadNoMatch;
    BrowsePathResult goodPath;
    goodPath.status_code() = Status::Good;
    BrowsePathResult uncertainPath;
    uncertainPath.status_code() = Status::UncertainReferenceOutOfServer;
    response->results().push_back(noMatchPath);
    response->results().push_back(goodPath);
    response->results().push_back(uncertainPath);
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }

    ASSERT_TRUE(captured.has_value());
    ASSERT_TRUE(captured->is_good())
      << "a per-path bad status must not turn the whole Translate batch Result bad";
    const auto& resp = captured->value();
    ASSERT_EQ(resp.results().size(), 3u) << "every per-path result must be surfaced, none filtered";
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadNoMatch});
    EXPECT_EQ(resp.results()[1].status_code(), StatusCode{Status::Good});
    EXPECT_EQ(resp.results()[2].status_code(), StatusCode{Status::UncertainReferenceOutOfServer});
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
