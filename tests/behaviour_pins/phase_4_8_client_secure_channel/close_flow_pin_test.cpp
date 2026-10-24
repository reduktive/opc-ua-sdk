// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - close flow.
//
//
// Infra-gap status: pins requiring CLO-on-wire observation (CL-C wire byte
// capture), drain-timeout via real timers (CL-E), and transport-close timeout
// (CL-F) require either a fake ConnectionProtocol or wall-clock waits coupled
// with a fake transport - see agent return.
//
// What IS pinned here:
//   CL-A : close() from Idle state fires callback with VoidResult{} good.
//          (impl.cpp :1058-1062 path)
//   CL-B : close() from Closed state fires callback with VoidResult{} good
//          (idempotent close; impl.cpp :1058-1062 same branch).
//   CL-C : close() from Opening state fires callback with
//          BadSecureChannelClosed (impl.cpp :1064-1068).
//   CL-D : close() from Open state with no outgoing queue and nullptr
//          connection drains-immediately and fires callback with good.
//          (Drain-immediate fast-path at impl.cpp :1092-1118 skipped; transport
//          wait at :1122 also skipped because mConnection is nullptr.)
//   CL-E : close() callback fires on the channel strand thread (affinity).
//   CL-F : Destroying the channel mid-flight (with a pending close callback
//          that has not yet fired) routes the close-callback through the
//          destructor's safety net at impl.cpp :141-149 with
//          BadSecureChannelClosed + non-null detail "ChannelDestroyed".

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_byte_string.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_status_code.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>

#include "../../../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"

namespace ua::test::behaviour_pins
{
namespace
{

using namespace std::chrono_literals;

class FakeClientSecureChannelDeps : public ua::client::SecureChannelDependencies
{
public:
  explicit FakeClientSecureChannelDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(ua::ApplicationConfig::load_default())
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  std::shared_ptr<const ua::Crypto> crypto() override
  {
    return nullptr;
  }

  std::shared_ptr<ua::CertificateStore> certificate_store() override
  {
    return nullptr;
  }

  const ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  ua::StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  ua::Logger logger() override
  {
    return {};
  }

  uint32_t service_timeout_ms() override
  {
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return 0;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ua::ApplicationConfig mAppCfg;
  ua::StructureFactory mFactory;
};

struct CloseSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  ua::StatusCode status{ua::Status::BadInternalError};
  std::shared_ptr<const ua::ErrorDetail> detail;
  std::thread::id threadId;

  bool wait(std::chrono::milliseconds timeout = 1500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

using STA = ua::client::SecureChannelTestAccess;

class ClientSecureChannelCloseFlowPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeClientSecureChannelDeps>(mPool->executor());
    mClose = std::make_shared<CloseSync>();
  }

  void TearDown() override
  {
    if (mImpl)
      mImpl.reset();
    if (mPool)
      mPool->stop();
  }

  void create_impl()
  {
    mImpl = ua::client::SecureChannelImpl::create(
      mDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      ua::client::SecureChannelImpl::Config{},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});
  }

  void invoke_close()
  {
    auto closeSync = mClose;
    mImpl->close(
      [closeSync](ua::VoidResult r)
      {
        {
          std::lock_guard<std::mutex> lk(closeSync->mx);
          closeSync->fired = true;
          closeSync->status = r.status_code();
          closeSync->detail = r.shared_detail();
          closeSync->threadId = std::this_thread::get_id();
        }
        closeSync->cv.notify_one();
      });
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeClientSecureChannelDeps> mDeps;
  std::shared_ptr<CloseSync> mClose;
  std::shared_ptr<ua::client::SecureChannelImpl> mImpl;
};

}  // namespace

// ---------------------------------------------------------------------------
// CL-A - close() from Idle fires callback with VoidResult{} good.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelCloseFlowPin, CloseFromIdleStateFiresCallbackWithGood)
{
  create_impl();
  // Channel was constructed Idle and nullptr connection means setup_and_open
  // is skipped (impl.cpp :207-211).
  invoke_close();
  ASSERT_TRUE(mClose->wait());
  EXPECT_TRUE(mClose->status.is_good())
    << "close() from Idle must succeed without sending CLO (impl.cpp :1058-1062)";
}

// ---------------------------------------------------------------------------
// CL-B - close() from Closed fires callback with VoidResult{} good.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelCloseFlowPin, CloseFromClosedStateFiresCallbackWithGood)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_closed(); });

  invoke_close();
  ASSERT_TRUE(mClose->wait());
  EXPECT_TRUE(mClose->status.is_good())
    << "close() from Closed must be idempotent and good (impl.cpp :1058-1062)";
}

// ---------------------------------------------------------------------------
// CL-C - close() from Opening fires callback with BadSecureChannelClosed.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelCloseFlowPin, CloseFromOpeningStateFiresCallbackWithBadSecureChannelClosed)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });

  invoke_close();
  ASSERT_TRUE(mClose->wait());
  EXPECT_EQ(mClose->status, ua::StatusCode{ua::Status::BadSecureChannelClosed})
    << "close() from intermediate state must fail with BadSecureChannelClosed (impl.cpp :1064-1068)";
}

// ---------------------------------------------------------------------------
// CL-D - close() from Open with empty queue and nullptr connection drains
// immediately and fires callback with good.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelCloseFlowPin, CloseFromOpenWithEmptyQueueDrainsImmediatelyAndFiresGood)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(/*channelId=*/42); });

  invoke_close();
  ASSERT_TRUE(mClose->wait());
  EXPECT_TRUE(mClose->status.is_good())
    << "close() from Open with empty queue / nullptr connection must succeed";

  // Channel must transition through Closing -> Closed and reflect in atomic
  // is_open snapshot.
  EXPECT_FALSE(mImpl->is_open());
  auto state = STA::on_strand(*mImpl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, ua::client::SecureChannelImpl::ChannelState::Closed);
}

// ---------------------------------------------------------------------------
// CL-E - close callback fires on the channel strand thread.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelCloseFlowPin, CloseCallbackFiresOnChannelStrandThread)
{
  create_impl();
  // Capture strand thread id (1-thread pool: stable id).
  const std::thread::id strandThreadId =
    STA::on_strand(*mImpl, [](auto&) { return std::this_thread::get_id(); });

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(); });
  invoke_close();
  ASSERT_TRUE(mClose->wait());

  EXPECT_EQ(mClose->threadId, strandThreadId)
    << "close callback fired on a thread other than the channel strand - strand discipline broken";
}

// ---------------------------------------------------------------------------
// CL-F - Destructor-during-flight fires close callback with BadSecureChannelClosed
// and ChannelDestroyed detail.
// ---------------------------------------------------------------------------
//
// Locks the destructor safety net at impl.cpp :141-149. Pin section 3.2 "Destructor
// obligations" - every still-set callback must fire with non-null detail.

TEST_F(ClientSecureChannelCloseFlowPin, DestructorWithPendingCloseCallbackFiresChannelDestroyedDetail)
{
  // We need to construct an impl with mCloseCallback set but no strand activity
  // to drive it. Easiest: install the callback on the strand directly via test
  // access, then drop the impl synchronously from the main test thread.
  //
  // Note: the destructor invokes mCloseCallback INLINE on the dropping thread
  // (impl.cpp :141-149) using ua::detail::invoke_user_callback. So the callback
  // fires on the main test thread when we reset the shared_ptr.

  create_impl();
  // Move the channel to a state that won't immediately complete close - Idle
  // would trigger immediate close_transport from a normal close() call. We
  // install mCloseCallback directly via the test access.
  auto closeSync = mClose;
  STA::on_strand(*mImpl,
    [closeSync](auto& g)
    {
      g.close_callback() = [closeSync](ua::VoidResult r)
      {
        {
          std::lock_guard<std::mutex> lk(closeSync->mx);
          closeSync->fired = true;
          closeSync->status = r.status_code();
          closeSync->detail = r.shared_detail();
          closeSync->threadId = std::this_thread::get_id();
        }
        closeSync->cv.notify_one();
      };
    });

  // Drop the last shared_ptr from the main test thread - the destructor's
  // safety net at impl.cpp :141-149 must fire mCloseCallback inline.
  mImpl.reset();

  ASSERT_TRUE(mClose->wait()) << "Destructor must fire mCloseCallback safety net";
  EXPECT_EQ(mClose->status, ua::StatusCode{ua::Status::BadSecureChannelClosed});
  ASSERT_NE(mClose->detail, nullptr) << "ChannelDestroyed safety net must carry an ErrorDetail";
  EXPECT_EQ(mClose->detail->code, "ChannelDestroyed")
    << "Destructor-fired close callback must carry the ChannelDestroyed code (impl.cpp :145)";
}

}  // namespace ua::test::behaviour_pins
