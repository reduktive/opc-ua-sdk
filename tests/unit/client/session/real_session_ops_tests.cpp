// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::RealSessionOps / RealChannelOps (the production adapters that wire the
// tier-0 SessionOps / ChannelOps interface onto concrete client Session / SecureChannel handles).
//
// RealSessionOps forwards each ordered op to the matching service-set accessor of the Session it owns.
// These tests assert the observable forwarding: session_id() surfaces the underlying session id, read_async
// pushes a ReadRequest down the real send path, the activate-on-channel adapter rejects a mispaired
// (non-RealChannelOps) channel with Bad_InvalidState, and RealChannelOps::is_open() reflects the wrapped
// channel's state.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "test_utilities.h"

#include "ua_real_session_ops.h"

#include "ua_read_request.h"
#include "ua_read_response.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>

using namespace std::chrono_literals;
using ua::client::test_capture::CaptureHarness;

namespace
{

/// A ChannelOps that is deliberately NOT a RealChannelOps, to exercise the defensive dynamic_cast branch in
/// RealSessionOps::activate_on_channel_async.
class NotARealChannelOps : public ua::client::detail::ChannelOps
{
public:
  void create_session_async(ua::client::SecureChannel::CreateSessionConfig /*config*/,
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::SessionOps>>)> callback) override
  {
    callback(ua::Result<std::shared_ptr<ua::client::detail::SessionOps>>{ua::Status::BadInternalError});
  }

  void get_endpoints_async(ua::GetEndpointsRequest /*request*/,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override
  {
    callback(ua::Result<ua::GetEndpointsResponse>{ua::Status::BadInternalError});
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    callback(ua::VoidResult{});
  }

  [[nodiscard]] bool is_open() const override
  {
    return true;
  }
};

}  // namespace

// session_id() forwards to the wrapped Session: the id the server assigned is surfaced verbatim.
TEST(RealSessionOps, SessionIdForwardsToWrappedSession)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    ua::client::detail::RealSessionOps ops{harness.session_handle()};
    EXPECT_EQ(ops.session_id(), ua::NodeId(1, 42))
      << "the adapter must surface the wrapped session's server-assigned id";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// read_async forwards to Session::attributes().read_async: the request travels the real client send path
// (captured through the SecureChannel outgoing-request observer) and the response is surfaced to the caller.
TEST(RealSessionOps, ReadForwardsRequestThroughSessionSendPath)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    ua::client::detail::RealSessionOps ops{harness.session_handle()};

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    bool good{false};
    ops.read_async(ua::ReadRequest{},
      [&](ua::Result<ua::ReadResponse> result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          good = result.is_good();
          cv.notify_one();
        }
      });

    // The forwarded Read must reach the channel send path.
    ASSERT_TRUE(harness.wait_for_pending_request()) << "read_async must forward a Read to the session";
    auto forwarded = harness.first_captured<ua::ReadRequest>();
    EXPECT_TRUE(forwarded.has_value())
      << "the ReadRequest must be sent through the real Session -> SecureChannel path";

    // Complete it so the caller callback surfaces the response.
    auto response = std::make_shared<ua::ReadResponse>();
    response->response_header().service_result() = ua::Status::Good;
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }
    EXPECT_TRUE(good) << "a good ReadResponse must be surfaced to the caller";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// activate_on_channel_async rejects a channel that is not a RealChannelOps: production only ever pairs the
// two, so a mispaired channel is a defensive programming error reported as Bad_InvalidState, synchronously.
TEST(RealSessionOps, ActivateOnMispairedChannelReturnsBadInvalidState)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    ua::client::detail::RealSessionOps ops{harness.session_handle()};

    bool fired{false};
    ua::StatusCode status{ua::Status::Good};
    ops.activate_on_channel_async(std::make_shared<NotARealChannelOps>(),
      ua::client::Session::ActivateConfig{},
      [&](ua::VoidResult result)
      {
        fired = true;
        status = result.status_code();
      });

    EXPECT_TRUE(fired) << "the guard must invoke the callback synchronously, not drop it";
    EXPECT_EQ(status, ua::StatusCode{ua::Status::BadInvalidState});
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// RealChannelOps::is_open() forwards to the wrapped SecureChannel's open state.
TEST(RealChannelOps, IsOpenForwardsToWrappedChannel)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    ua::client::detail::RealChannelOps channel{
      ua::client::SecureChannelTestAccess::make_channel(harness.channel)};

    // Drive the underlying channel's open flag, then confirm the adapter reflects each value.
    ua::client::SecureChannelTestAccess::on_strand(
      *harness.channel, [](auto& g) { g.atomic_is_open().store(true, std::memory_order_release); });
    EXPECT_TRUE(channel.is_open()) << "is_open() must report true when the wrapped channel is open";

    ua::client::SecureChannelTestAccess::on_strand(
      *harness.channel, [](auto& g) { g.atomic_is_open().store(false, std::memory_order_release); });
    EXPECT_FALSE(channel.is_open()) << "is_open() must report false when the wrapped channel is closed";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
