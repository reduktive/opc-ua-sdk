// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - Open / OPN-Issue.
//
// Infra-gap status: many runbook section 4.1 pins (OC-A wire token-id assertion,
// OC-B wire client-nonce assertion, OC-C wire ephemeral pub-key, OC-D opn-timer
// cancellation, OC-E renewal-timer scheduling) require either (a) a
// `FakeAsyncCrypto` collaborator that the section 4.0.1 sharing strategy expected to
// re-use from 4.3a/4.7a, or (b) a `FakeConnectionProtocol` that intercepts
// `send_message_chunk` to capture wire bytes. Neither exists in the tree
// today (`tests/behaviour_pins/phase_4_3_security_policy/` and
// `phase_4_7_server_secure_channel/` are referenced in the parent CMakeLists
// but the directories are absent). `ConnectionProtocol` is also a concrete
// non-abstract class - there is no abstract base to subclass. The flagged-
// missing infra is documented in the agent return.
//
// What IS pinned here:
//   OC-OPN-A : Good OPN-Issue response transitions Opening -> Open and fires
//              mOnOpened with VoidResult{} good. (final-status pin)
//   OC-OPN-B : Good OPN-Issue response publishes mAtomicChannelId and
//              mAtomicIsOpen - visible cross-strand via is_open() /
//              secure_channel_id() with no posting. (cross-strand-read pin)
//   OC-OPN-C : Good OPN-Issue clears mOnOpened so a stray OPN response while
//              Open is silently ignored without re-firing the user callback.
//              (state-machine invariant pin)
//   OC-OPN-D : Renewal timer is armed for non-zero revisedLifetime.
//              (deterministic-content pin against scheduled timer)
//   OC-OPN-E : Renewal timer is NOT armed for zero revisedLifetime.
//              (negative pairing for OC-OPN-D)
//   OC-OPN-F : mOnOpened callback fires on the channel strand - threading
//              affinity captured via std::this_thread::get_id() compared with
//              the channel-strand thread captured at fixture construction.

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

// Test access to SecureChannelImpl internals (friend-only access).
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

// Captured per-test state - heap-allocated so capturing a shared_ptr by value
// in lambdas is safe across thread boundaries.
struct OpenedSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  ua::StatusCode status{ua::Status::BadInternalError};
  std::shared_ptr<const ua::ErrorDetail> detail;
  std::thread::id threadId;

  bool wait(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

using STA = ua::client::SecureChannelTestAccess;

// Fixture: 1-thread pool so the channel strand always runs on one
// observable thread id.
class ClientSecureChannelOpenChannelPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*threads=*/1);
    mDeps = std::make_shared<FakeClientSecureChannelDeps>(mPool->executor());
    mOpened = std::make_shared<OpenedSync>();
  }

  void TearDown() override
  {
    // Explicit pool stop before locals destruct so worker threads
    // join before the fixture's mutex/cv are destroyed.
    if (mImpl)
    {
      mImpl.reset();
    }
    if (mPool)
    {
      mPool->stop();
    }
  }

  // Build a SecureChannelImpl with default Config (None policy, None mode).
  void create_impl()
  {
    auto opened = mOpened;
    mImpl = ua::client::SecureChannelImpl::create(
      mDeps,
      /*connection=*/nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      ua::client::SecureChannelImpl::Config{},
      [opened](ua::VoidResult r)
      {
        {
          std::lock_guard<std::mutex> lk(opened->mx);
          opened->fired = true;
          opened->status = r.status_code();
          opened->detail = r.shared_detail();
          opened->threadId = std::this_thread::get_id();
        }
        opened->cv.notify_one();
      },
      [](ua::VoidResult) {});
  }

  // Capture the strand-running thread id by posting a sentinel onto it.
  std::thread::id capture_strand_thread_id()
  {
    return STA::on_strand(*mImpl, [](auto&) { return std::this_thread::get_id(); });
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeClientSecureChannelDeps> mDeps;
  std::shared_ptr<OpenedSync> mOpened;
  std::shared_ptr<ua::client::SecureChannelImpl> mImpl;
};

}  // namespace

// ---------------------------------------------------------------------------
// OC-OPN-A - Good OPN-Issue response opens the channel and fires mOnOpened.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOpenChannelPin, GoodOpnIssueResponseOpensChannelAndFiresOnOpened)
{
  create_impl();

  // The channel was constructed Idle (no connection). Move it to Opening
  // synthetically - this models the post-`setup_and_open` state where the
  // OPN-Issue request has been sent and the channel is awaiting a response.
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });

  // Inject a synthetic good OPN-Issue response on the channel strand.
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        /*secureChannelId=*/uint32_t{42},
        /*tokenId=*/uint32_t{100},
        /*revisedLifetime=*/std::chrono::milliseconds{60000},
        /*serverNonce=*/ua::ByteString{},
        /*detail=*/nullptr);
    });

  ASSERT_TRUE(mOpened->wait()) << "mOnOpened did not fire after good OPN-Issue response";
  EXPECT_TRUE(mOpened->status.is_good());
  EXPECT_EQ(mOpened->status, ua::StatusCode{ua::Status::Good});
}

// ---------------------------------------------------------------------------
// OC-OPN-B - Good OPN-Issue publishes atomic snapshot for cross-strand reads.
// ---------------------------------------------------------------------------
//
// Verifies Rule 4 of the strand-serialised component design rules: cross-strand
// reads of channel id and is_open observe the values published during the
// OPN-Issue completion without strand posting.

TEST_F(ClientSecureChannelOpenChannelPin, GoodOpnIssueResponsePublishesAtomicChannelIdAndIsOpen)
{
  create_impl();

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{4242},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });
  ASSERT_TRUE(mOpened->wait());

  // Cross-strand reads from the main test thread (no strand posting).
  EXPECT_TRUE(mImpl->is_open());
  EXPECT_EQ(mImpl->secure_channel_id(), 4242u);
}

// ---------------------------------------------------------------------------
// OC-OPN-C - mOnOpened is cleared after first successful open.
// ---------------------------------------------------------------------------
//
// Locks the section 3.2 "Token rotation atomicity" invariant: once OPN-Issue resolves,
// mOnOpened is cleared so a stray OPN response (e.g. arriving while Open) does
// NOT re-fire the user callback. Any 4.8b restructure must preserve the
// fire-once-and-clear semantic at impl.cpp :820-821.

TEST_F(ClientSecureChannelOpenChannelPin, GoodOpnIssueResponseClearsOnOpenedSlot)
{
  create_impl();

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });
  ASSERT_TRUE(mOpened->wait());

  // After OPN-Issue completes, mOnOpened must be cleared.
  bool slotIsEmpty = STA::on_strand(*mImpl, [](auto& g) { return !static_cast<bool>(g.on_opened()); });
  EXPECT_TRUE(slotIsEmpty)
    << "mOnOpened slot must be cleared post-open to honour fire-once-and-clear (impl.cpp :820-821)";
}

// ---------------------------------------------------------------------------
// OC-OPN-D - Non-zero revisedLifetime arms the renewal timer.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOpenChannelPin, GoodOpnIssueResponseWithLifetimeArmsRenewalTimer)
{
  create_impl();

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });
  ASSERT_TRUE(mOpened->wait());

  bool timerArmed = STA::on_strand(*mImpl, [](auto& g) { return static_cast<bool>(g.renewal_timer()); });
  EXPECT_TRUE(timerArmed) << "renewal timer must be armed when revisedLifetime > 0";
}

// ---------------------------------------------------------------------------
// OC-OPN-E - Zero revisedLifetime does NOT arm the renewal timer.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOpenChannelPin, GoodOpnIssueResponseWithZeroLifetimeDoesNotArmRenewalTimer)
{
  create_impl();

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{0},
        ua::ByteString{},
        nullptr);
    });
  ASSERT_TRUE(mOpened->wait());

  bool timerArmed = STA::on_strand(*mImpl, [](auto& g) { return static_cast<bool>(g.renewal_timer()); });
  EXPECT_FALSE(timerArmed) << "renewal timer must NOT be armed when revisedLifetime == 0";
}

// ---------------------------------------------------------------------------
// OC-OPN-F - mOnOpened callback fires on the channel strand thread.
// ---------------------------------------------------------------------------
//
// Threading affinity per runbook section 3.2 "Final-callback strand affinity".

TEST_F(ClientSecureChannelOpenChannelPin, OnOpenedCallbackFiresOnChannelStrandThread)
{
  create_impl();

  // Capture the channel-strand thread id by running a sentinel on it. With a
  // 1-thread pool, every strand-posted lambda runs on the same OS thread, so
  // this id is the canonical strand-thread id for this fixture.
  const std::thread::id strandThreadId = capture_strand_thread_id();

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });
  ASSERT_TRUE(mOpened->wait());

  EXPECT_EQ(mOpened->threadId, strandThreadId)
    << "mOnOpened did not fire on the channel strand thread - strand discipline broken";
}

}  // namespace ua::test::behaviour_pins
