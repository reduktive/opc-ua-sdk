// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// maxInFlightRequests - per-connection + server-wide in-flight admission caps.
//
// The SecureChannel enforces two admission caps over the high-volume session-service request path
// (ServerConfig::maxInFlightRequestsPerConnection / maxInFlightRequests). A request is
// "counted" from when it is forwarded to a session (handle_forward_to_session, non-Publish) until
// its response is sent (send_response_message_internal). Over either cap -> Bad_ServerTooBusy.
// Publish requests are parked flow-control bounded separately, so they are excluded.
//
// These tests drive a SecureChannel directly via FakeSecureChannelDependencies +
// SecureChannelTestAccess: a registered session whose request callback records (and does NOT answer)
// the requests it receives keeps them "in flight", so injecting past the cap exercises the rejection
// path; a response sink captures any Bad_ServerTooBusy ServiceFault. Each test is falsifiable -
// disabling the admission block in handle_forward_to_session makes the over-cap request forward and
// the expected fault disappear.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "fake_secure_channel_dependencies.h"

#include "ua_defines.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node_id.h"
#include "ua_publish_request.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_service_fault.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins::phase_4_7
{
namespace
{

using namespace std::chrono_literals;
using SCTA = ::ua::server::SecureChannelTestAccess;

template<typename Pred>
bool wait_until(Pred pred, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
      return true;
    std::this_thread::sleep_for(1ms);
  }
  return pred();
}

}  // namespace

class SecureChannelInflightCaps : public ::testing::Test
{
protected:
  void TearDown() override
  {
    mChannel.reset();
    mDeps.reset();
    if (mPool)
    {
      mPool->stop();
      mPool.reset();
    }
  }

  // Build a channel whose ServerConfig carries the given caps (snapshotted in the ctor), give
  // it a minimal None context, mark it Open, register a single session whose request callback records
  // the forwarded requestIds (and never replies, so they stay in flight), and install a response sink
  // that captures any ServiceFault. Caps are std::optional -> nullopt leaves the cap unbounded.
  void build(std::optional<uint32_t> perConnectionCap, std::optional<uint32_t> serverWideCap)
  {
    mPool = std::make_unique<::boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeSecureChannelDependencies>(mPool->executor());
    mDeps->mutable_server_configuration().maxInFlightRequestsPerConnection = perConnectionCap;
    mDeps->mutable_server_configuration().maxInFlightRequests = serverWideCap;

    mChannel = ::ua::server::SecureChannel::create(
      mDeps, nullptr, ::ua::connection_protocol::NegotiatedLimits{}, ::ua::server::ListenerHandle{1}, "L");

    SCTA::on_strand(*mChannel, [&](auto& g) { g.set_minimal_context_none(mPool->executor(), "L/None"); });
    SCTA::on_strand(*mChannel, [](auto& g) { g.channel_state() = SCTA::ChannelState::Open; });

    mChannel->register_session(
      mToken,
      [this](::ua::Request request)
      {
        std::lock_guard<std::mutex> lock{mMutex};
        mForwardedIds.push_back(std::get<uint32_t>(request));
      },
      [](::ua::StatusCode, ::ua::shared_ptr<const ::ua::ErrorDetail>) {});

    SCTA::on_strand(*mChannel,
      [&](auto& g)
      {
        g.set_response_sink(
          [this](const ::ua::Response& response)
          {
            if (auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get()))
            {
              std::lock_guard<std::mutex> lock{mMutex};
              mFaults.emplace_back(response.first, fault->response_header().service_result());
            }
          });
      });

    SCTA::strand_barrier(*mChannel);
  }

  void inject_read(uint32_t requestId)
  {
    auto request = std::make_shared<::ua::ReadRequest>();
    SCTA::on_strand(*mChannel, [&](auto& g) { g.inject_decoded_request(requestId, request, mToken); });
  }

  void inject_publish(uint32_t requestId)
  {
    auto request = std::make_shared<::ua::PublishRequest>();
    SCTA::on_strand(*mChannel, [&](auto& g) { g.inject_decoded_request(requestId, request, mToken); });
  }

  size_t forwarded_count()
  {
    std::lock_guard<std::mutex> lock{mMutex};
    return mForwardedIds.size();
  }

  bool forwarded_contains(uint32_t requestId)
  {
    std::lock_guard<std::mutex> lock{mMutex};
    return std::find(mForwardedIds.begin(), mForwardedIds.end(), requestId) != mForwardedIds.end();
  }

  std::optional<::ua::StatusCode> fault_for(uint32_t requestId)
  {
    std::lock_guard<std::mutex> lock{mMutex};
    for (const auto& [id, status] : mFaults)
      if (id == requestId)
        return status;
    return std::nullopt;
  }

  uint32_t server_wide_in_flight()
  {
    return mDeps->in_flight_requests_counter()->load(std::memory_order_relaxed);
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeSecureChannelDependencies> mDeps;
  std::shared_ptr<::ua::server::SecureChannel> mChannel;
  ::ua::NodeId mToken{1, uint32_t(42)};

  std::mutex mMutex;
  std::vector<uint32_t> mForwardedIds;
  std::vector<std::pair<uint32_t, ::ua::StatusCode>> mFaults;
};

// Per-connection cap of 2: the first two requests forward, the third is rejected Bad_ServerTooBusy
// and never reaches the session.
TEST_F(SecureChannelInflightCaps, PerConnectionCapRejectsOverLimit)
{
  build(/*perConnectionCap=*/2, /*serverWideCap=*/std::nullopt);

  inject_read(1);
  inject_read(2);
  ASSERT_TRUE(wait_until([&] { return forwarded_count() == 2; }, 2s));

  inject_read(3);
  ASSERT_TRUE(wait_until([&] { return fault_for(3).has_value(); }, 2s))
    << "third request over the per-connection cap should be rejected";

  EXPECT_EQ(*fault_for(3), ::ua::StatusCode{::ua::Status::BadServerTooBusy});
  // Enriched: the fault carries the admission limit + channel/request context.
  const auto detail = fault_for(3)->shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_TRUE(std::any_of(detail->context.begin(),
    detail->context.end(),
    [](const ::ua::NamedValue& entry) { return entry.key == ::ua::ContextKeys::limit.value(); }));
  EXPECT_FALSE(forwarded_contains(3)) << "rejected request must not be forwarded to the session";
  EXPECT_EQ(forwarded_count(), 2u);
}

// Publish requests are flow-controlled separately and excluded from the caps: with a per-connection
// cap of 1, many Publish requests all forward and none is rejected.
TEST_F(SecureChannelInflightCaps, PublishRequestsAreNotCounted)
{
  build(/*perConnectionCap=*/1, /*serverWideCap=*/std::nullopt);

  inject_publish(1);
  inject_publish(2);
  inject_publish(3);
  ASSERT_TRUE(wait_until([&] { return forwarded_count() == 3; }, 2s));

  EXPECT_FALSE(fault_for(2).has_value()) << "Publish must not be counted against the in-flight cap";
  EXPECT_FALSE(fault_for(3).has_value());
  EXPECT_EQ(server_wide_in_flight(), 0u) << "Publish must not increment the server-wide counter";
}

// Server-wide cap reached (preloaded counter) rejects a fresh request even though the per-connection
// cap is unbounded.
TEST_F(SecureChannelInflightCaps, ServerWideCapRejects)
{
  build(/*perConnectionCap=*/std::nullopt, /*serverWideCap=*/2);
  mDeps->in_flight_requests_counter()->store(2, std::memory_order_relaxed);

  inject_read(1);
  ASSERT_TRUE(wait_until([&] { return fault_for(1).has_value(); }, 2s))
    << "request should be rejected when the server-wide cap is already reached";

  EXPECT_EQ(*fault_for(1), ::ua::StatusCode{::ua::Status::BadServerTooBusy});
  // Enriched: the fault carries the admission limit + channel/request context.
  const auto detail = fault_for(1)->shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_TRUE(std::any_of(detail->context.begin(),
    detail->context.end(),
    [](const ::ua::NamedValue& entry) { return entry.key == ::ua::ContextKeys::limit.value(); }));
  EXPECT_FALSE(forwarded_contains(1));
}

// Sending a response releases the in-flight slot (per-connection + server-wide), so a subsequent
// request that would otherwise be over-cap is admitted.
TEST_F(SecureChannelInflightCaps, ResponseReleasesInFlightSlot)
{
  build(/*perConnectionCap=*/1, /*serverWideCap=*/std::nullopt);

  inject_read(1);
  ASSERT_TRUE(wait_until([&] { return forwarded_contains(1); }, 2s));
  ASSERT_TRUE(wait_until([&] { return server_wide_in_flight() == 1; }, 2s));

  // Answer request 1 - this decrements both the per-connection set and the server-wide counter.
  mChannel->send_response_message(::ua::Response{1, std::make_shared<::ua::ReadResponse>()});
  ASSERT_TRUE(wait_until([&] { return server_wide_in_flight() == 0; }, 2s))
    << "response must release the in-flight reservation";

  // The slot is free, so request 2 is admitted (would be rejected if the slot were still held).
  inject_read(2);
  ASSERT_TRUE(wait_until([&] { return forwarded_contains(2); }, 2s))
    << "freed slot should admit the next request";
  EXPECT_FALSE(fault_for(2).has_value());
  EXPECT_EQ(server_wide_in_flight(), 1u);
}

}  // namespace ua::test::behaviour_pins::phase_4_7
