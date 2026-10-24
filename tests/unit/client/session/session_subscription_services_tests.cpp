// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for SessionSubscriptionServices (Subscription Service Set forwarder).
//
// Part 1 - Absent-session guards. Each async method locks its weak_ptr<SessionImpl>; when the owning
// session has been destroyed the guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a
// dangling pointer. A missing guard would crash on the null lock or drop the callback; a still-live
// (Closed) impl would return Bad_SessionClosed. Only a genuinely dead session plus a working guard yields
// Bad_SessionIdInvalid.
//
// Part 2 - Live per-item result decomposition (CL-SUB-014). Driven over the null-connection capture
// harness: the real set_publishing_mode_async call travels Session -> SecureChannel, a synthetic response
// is injected, and the tests assert the forwarder honours the per-Subscription results[] verbatim even when
// the service-level result is Good.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "session_service_guard_fixture.h"
#include "test_utilities.h"

#include "ua_session_subscription_services.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"

#include <boost/asio/thread_pool.hpp>

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;
using ua::client::guard_test::DeadSessionHarness;
using ua::client::test_capture::CaptureHarness;

TEST(SessionSubscriptionServicesGuard, CreateSubscriptionOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  subscriptions.create_subscription_async(CreateSubscriptionRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionSubscriptionServicesGuard, ModifySubscriptionOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  subscriptions.modify_subscription_async(ModifySubscriptionRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionSubscriptionServicesGuard, SetPublishingModeOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  subscriptions.set_publishing_mode_async(SetPublishingModeRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionSubscriptionServicesGuard, PublishOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  subscriptions.publish_async(PublishRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionSubscriptionServicesGuard, RepublishOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  subscriptions.republish_async(RepublishRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionSubscriptionServicesGuard, TransferSubscriptionsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  subscriptions.transfer_subscriptions_async(TransferSubscriptionsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionSubscriptionServicesGuard, DeleteSubscriptionsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto subscriptions = harness.live().subscriptions();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  subscriptions.delete_subscriptions_async(DeleteSubscriptionsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

// @verifies CL-SUB-014
// SetPublishingMode results are per-Subscription: "The size and order of the [results] list matches the
// size and order of the subscriptionIds request parameter", and when the service result is Good the client
// must still walk results[] and surface each Subscription's per-item StatusCode rather than collapsing the
// response to its service-level status. We drive a real 2-Subscription set_publishing_mode_async, capture
// the outgoing request to confirm it travels the Session -> SecureChannel path with its subscriptionIds and
// publishingEnabled intact, then inject a response whose service result is Good but whose results are
// [Good, Bad_SubscriptionIdInvalid], and assert (a) the caller Result is good (the service completed) and
// (b) both per-item StatusCodes surface unmodified and in order. Falsifies if the forwarder collapses the
// mixed per-item results into a single status, reorders/drops results[], or elevates a per-item Bad to the
// service-level Result.
// @relation(CL-SUB-014, scope=function)
TEST(SessionSubscriptionServicesSetPublishingMode, PerItemBadSurfacesWhenServiceResultGood)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    SetPublishingModeRequest request;
    request.publishing_enabled() = true;
    request.subscription_ids().push_back(IntegerId{4201});
    request.subscription_ids().push_back(IntegerId{4202});

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    bool good{false};
    std::vector<StatusCode> perItem;

    harness.session_handle().subscriptions().set_publishing_mode_async(request,
      [&](auto result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          good = result.is_good();
          if (good)
          {
            const auto& results = result.value().results();
            for (std::size_t i = 0; i < results.size(); ++i)
            {
              perItem.push_back(results[i]);
            }
          }
        }
        cv.notify_one();
      });

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "set_publishing_mode_async must forward a SetPublishingMode to the channel";
    auto captured = harness.first_captured<SetPublishingModeRequest>();
    ASSERT_TRUE(captured.has_value())
      << "the SetPublishingModeRequest must reach the SecureChannel send path";
    ASSERT_EQ(captured->subscription_ids().size(), 2u) << "both target subscriptions must be forwarded";
    EXPECT_EQ(captured->subscription_ids()[0], IntegerId{4201});
    EXPECT_EQ(captured->subscription_ids()[1], IntegerId{4202});
    EXPECT_TRUE(captured->publishing_enabled()) << "the publishingEnabled flag must be forwarded verbatim";

    auto response = std::make_shared<SetPublishingModeResponse>();
    response->response_header().service_result() = Status::Good;
    response->results().push_back(StatusCode{Status::Good});
    response->results().push_back(StatusCode{Status::BadSubscriptionIdInvalid});
    ASSERT_TRUE(harness.inject_channel_response(response));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }

    ASSERT_TRUE(good) << "a SetPublishingMode with a Good service result must surface as a good Result";
    ASSERT_EQ(perItem.size(), 2u) << "every per-Subscription StatusCode must be exposed to the caller";
    EXPECT_EQ(perItem[0], StatusCode{Status::Good}) << "the valid Subscription's result must pass through";
    EXPECT_EQ(perItem[1], StatusCode{Status::BadSubscriptionIdInvalid})
      << "the invalid Subscription's per-item failure must surface, not collapse the whole response";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SUB-014
// When every per-Subscription result is Bad the client must surface all of them (CTT Sub/Modify/Err-009):
// a Good service result carrying results[*] = Bad_SubscriptionIdInvalid must reach the caller with each
// per-item failure intact, not shortcut into a single service-level failure. We drive a real 3-Subscription
// set_publishing_mode_async, inject an all-Bad results vector under a Good service result, and assert the
// caller Result is good and all three per-item StatusCodes are Bad_SubscriptionIdInvalid. Falsifies if any
// per-item Bad is dropped or rewritten, or if the all-Bad results elevate the service-level Result to bad.
// @relation(CL-SUB-014, scope=function)
TEST(SessionSubscriptionServicesSetPublishingMode, AllPerItemBadSurfacesEvery)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    SetPublishingModeRequest request;
    request.publishing_enabled() = false;
    request.subscription_ids().push_back(IntegerId{7001});
    request.subscription_ids().push_back(IntegerId{7002});
    request.subscription_ids().push_back(IntegerId{7003});

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    bool good{false};
    std::vector<StatusCode> perItem;

    harness.session_handle().subscriptions().set_publishing_mode_async(request,
      [&](auto result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          good = result.is_good();
          if (good)
          {
            const auto& results = result.value().results();
            for (std::size_t i = 0; i < results.size(); ++i)
            {
              perItem.push_back(results[i]);
            }
          }
        }
        cv.notify_one();
      });

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "set_publishing_mode_async must forward a SetPublishingMode to the channel";
    ASSERT_TRUE(harness.first_captured<SetPublishingModeRequest>().has_value())
      << "the SetPublishingModeRequest must reach the SecureChannel send path";

    auto response = std::make_shared<SetPublishingModeResponse>();
    response->response_header().service_result() = Status::Good;
    response->results().push_back(StatusCode{Status::BadSubscriptionIdInvalid});
    response->results().push_back(StatusCode{Status::BadSubscriptionIdInvalid});
    response->results().push_back(StatusCode{Status::BadSubscriptionIdInvalid});
    ASSERT_TRUE(harness.inject_channel_response(response));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }

    ASSERT_TRUE(good)
      << "an all-Bad results vector under a Good service result must still surface as a good Result";
    ASSERT_EQ(perItem.size(), 3u) << "every per-Subscription StatusCode must be exposed to the caller";
    for (std::size_t i = 0; i < perItem.size(); ++i)
    {
      EXPECT_EQ(perItem[i], StatusCode{Status::BadSubscriptionIdInvalid})
        << "per-item failure at index " << i << " must surface unmodified";
    }
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
