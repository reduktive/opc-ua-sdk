// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Integration tests for the client-side close/teardown contract.
//
// After close, the impl must release all asio-bound resources so the client thread pool
// can drain. ComplianceBase's TearDown calls stop_pool_in_teardown(), which records a
// non-fatal gtest failure if the pool fails to drain - that is the implicit assertion
// every test in this file relies on.

#include <gtest/gtest.h>

#include "compliance_helpers.h"

#include "ua_close_secure_channel_request.h"
#include "ua_open_secure_channel_request.h"

#include <chrono>

using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------
// Graceful close - channel + session both closed, pool drains in TearDown.
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithSession, CloseTeardown_GracefulSessionAndChannelDrainPool)
{
  ASSERT_TRUE(mSession->is_active());
  ASSERT_TRUE(mChannel->is_open());

  EXPECT_TRUE(mSession->try_close_sync().is_good());
  EXPECT_FALSE(mSession->is_active());

  EXPECT_TRUE(mChannel->try_close_sync().is_good());
  EXPECT_FALSE(mChannel->is_open());

  // Drop the user-visible handles before TearDown exercises the pool drain assertion.
  // After a full teardown the impls must not be keeping the io_context alive even if
  // the user kept the handles around - but releasing them here mirrors typical usage
  // and keeps the test focused on the SDK's drain behavior.
  mSession.reset();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Idempotent close on the channel - second close completes Good without hanging.
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, CloseTeardown_ChannelDoubleCloseIsIdempotent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  ASSERT_TRUE(channel.is_open());

  ASSERT_TRUE(channel.try_close_sync().is_good());
  EXPECT_FALSE(channel.is_open());

  // Second close - channel is already in Closed state. Must complete promptly with Good.
  auto second = channel.try_close_sync();
  EXPECT_TRUE(second.is_good()) << "second close returned status 0x" << std::hex
                                << second.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// Idempotent close on the session - second close completes Good without hanging.
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithSession, CloseTeardown_SessionDoubleCloseIsIdempotent)
{
  ASSERT_TRUE(mSession->try_close_sync().is_good());
  EXPECT_FALSE(mSession->is_active());

  auto second = mSession->try_close_sync();
  EXPECT_TRUE(second.is_good()) << "second close returned status 0x" << std::hex
                                << second.status_code().as_uint32();

  // Channel still needs explicit close so its pool work also drains.
  EXPECT_TRUE(mChannel->try_close_sync().is_good());

  mSession.reset();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Closing a channel while a session is still attached must still drain. The session's
// own close path is bypassed here - the channel teardown must release pending requests
// and any session-side state held against the channel.
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithSession, CloseTeardown_ChannelCloseWithoutSessionCloseDrainsPool)
{
  ASSERT_TRUE(mSession->is_active());
  ASSERT_TRUE(mChannel->is_open());

  // Skip session close - go straight to channel close.
  EXPECT_TRUE(mChannel->try_close_sync().is_good());
  EXPECT_FALSE(mChannel->is_open());

  // The session is now stranded on a dead channel. Releasing the handles should not
  // leak any pool work - strand-bound timers and queued callbacks must have been
  // resolved by the channel's close_transport sink.
  mSession.reset();
  mChannel.reset();
}

// ---------------------------------------------------------------------------
// Close after the server has shut down (channel already errored): close completes
// promptly without waiting for the transport-close timeout, and the pool drains.
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithSession, CloseTeardown_CloseAfterServerVanishedDrainsPool)
{
  ASSERT_TRUE(mChannel->is_open());

  // Shut down the server so all client-side connections drop. The client should
  // observe the transport error and transition the channel to Closed.
  ASSERT_TRUE(mServer.server().try_shutdown_sync({.grace = std::chrono::seconds{0}}).is_good());

  // Give the client's transport a chance to observe EOF and route it through the
  // channel's strand. Poll briefly rather than sleeping a fixed duration.
  auto deadline = std::chrono::steady_clock::now() + 5s;
  while (mChannel->is_open() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(20ms);
  }
  EXPECT_FALSE(mChannel->is_open());

  // Close on an already-closed channel - must complete promptly.
  auto sessionClose = mSession->try_close_sync();
  // Session is stranded on a dead channel; outcome may be Good or a not-active
  // status. Either is acceptable as long as it returns and does not hang.
  static_cast<void>(sessionClose);

  auto channelClose = mChannel->try_close_sync();
  static_cast<void>(channelClose);

  mSession.reset();
  mChannel.reset();
}

}  // namespace
