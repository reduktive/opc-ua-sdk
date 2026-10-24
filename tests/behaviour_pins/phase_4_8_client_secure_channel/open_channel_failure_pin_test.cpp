// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - OPN failure modes.
//
//
// Infra-gap status: pins requiring a fake CertificateStore / FakeAsyncCrypto
// (OF-A through OF-D, OF-E OPN timeout via wall-clock with margin) are NOT
// covered here - see agent return for the list of skipped pins.
//
// What IS pinned here:
//   OF-OPN-A : Server OPN response with bad service status fires mOnOpened with
//              that status and a non-null ErrorDetail (default
//              "ServerOPNFault" if the response carried no detail).
//              (failure-mode pin)
//   OF-OPN-B : Server OPN response with bad service status forwards the
//              caller-supplied detail pointer-identically (lossless propagation).
//   OF-OPN-C : Server nonce too short (< 32 bytes) on authenticated policy
//              rejects with BadNonceInvalid + non-null detail
//              "ServerNonceInvalid".
//   OF-OPN-D : Server nonce wrong size (mismatched mNonceLength) rejects with
//              BadNonceInvalid + non-null detail "ServerNonceInvalid".
//   OF-OPN-E : OPN response in non-Opening / non-Renewing state is silently
//              ignored - mOnOpened is NOT fired (no spurious callback).
//   OF-OPN-F : Channel state transitions to Closed on a bad service status.

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>

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

struct OpenedSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  ua::StatusCode status{ua::Status::Good};
  std::shared_ptr<const ua::ErrorDetail> detail;

  bool wait(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

using STA = ua::client::SecureChannelTestAccess;

class ClientSecureChannelOpenChannelFailurePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeClientSecureChannelDeps>(mPool->executor());
    mOpened = std::make_shared<OpenedSync>();
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
    auto opened = mOpened;
    mImpl = ua::client::SecureChannelImpl::create(
      mDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      ua::client::SecureChannelImpl::Config{},
      [opened](ua::VoidResult r)
      {
        {
          std::lock_guard<std::mutex> lk(opened->mx);
          opened->fired = true;
          opened->status = r.status_code();
          opened->detail = r.shared_detail();
        }
        opened->cv.notify_one();
      },
      [](ua::VoidResult) {});
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeClientSecureChannelDeps> mDeps;
  std::shared_ptr<OpenedSync> mOpened;
  std::shared_ptr<ua::client::SecureChannelImpl> mImpl;
};

}  // namespace

// ---------------------------------------------------------------------------
// OF-OPN-A - Server OPN service-result is bad: fires mOnOpened bad with
// non-null synthesized detail when the wire detail was nullptr.
// ---------------------------------------------------------------------------

// clang-format off  -- this declaration must stay on ONE line: the requirements gate matches
// the JUnit test name against the tree-sitter function name, and a wrapped TEST_F cannot be
// matched (it fails the whole export, not just this test). Exceeds ColumnLimit by a few chars.
TEST_F(
  ClientSecureChannelOpenChannelFailurePin, ServerBadStatusWithNoDetailFiresMOnOpenedWithSynthesizedDetail)
// clang-format on
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
        uint32_t{0},
        uint32_t{0},
        std::chrono::milliseconds{0},
        ua::ByteString{},
        /*detail=*/nullptr);
    });

  ASSERT_TRUE(mOpened->wait()) << "mOnOpened did not fire on bad OPN service status";
  EXPECT_EQ(mOpened->status, ua::StatusCode{ua::Status::BadSecurityChecksFailed});
  EXPECT_NE(mOpened->detail, nullptr)
    << "Bad OPN response must carry an ErrorDetail (the ErrorDetail propagation rule)";
}

// ---------------------------------------------------------------------------
// OF-OPN-B - Server OPN service-result is bad with a wire-supplied detail:
// the caller-supplied detail is forwarded pointer-identically (lossless).
// ---------------------------------------------------------------------------
//
// Mirrors section 3.2 "ErrorDetail propagation per failure pin" - locks lossless
// propagation through the bad-status branch at impl.cpp :686-696.

TEST_F(ClientSecureChannelOpenChannelFailurePin, ServerBadStatusWithDetailForwardsDetailPointerIdentically)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });

  // Construct an inner detail from the test side. The runbook contract is
  // that this exact shared_ptr must reach the mOnOpened callback.
  auto innerDetail = std::shared_ptr<const ua::ErrorDetail>(
    ua::make_error_detail("UpstreamServerCause", "synthetic test detail", "test"));

  auto innerCopy = innerDetail;  // capture by value - pointer comparison post.
  STA::on_strand(*mImpl,
    [innerCopy](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::BadSecurityModeRejected},
        uint32_t{0},
        uint32_t{0},
        std::chrono::milliseconds{0},
        ua::ByteString{},
        innerCopy);
    });

  ASSERT_TRUE(mOpened->wait());
  ASSERT_NE(mOpened->detail, nullptr);
  EXPECT_EQ(mOpened->detail.get(), innerDetail.get())
    << "ErrorDetail was copied/replaced at the OPN-bad-status boundary - must be lossless";
}

// ---------------------------------------------------------------------------
// OF-OPN-C - Server nonce too short on authenticated policy.
// ---------------------------------------------------------------------------
//
// Verifies impl.cpp :701-709. We mark the channel as authenticated via test
// access (set_is_authenticated) so the nonce-validation branch runs.

TEST_F(ClientSecureChannelOpenChannelFailurePin, AuthenticatedShortServerNonceRejectedWithBadNonceInvalid)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*mImpl, [](auto& g) { g.set_is_authenticated(/*authenticated=*/true, /*nonceLength=*/32); });

  // Build a too-short nonce (16 bytes < 32 minimum).
  std::vector<uint8_t> shortNonceBytes(16, 0xab);
  ua::ByteString shortNonce{std::move(shortNonceBytes)};

  STA::on_strand(*mImpl,
    [shortNonce](auto& g) mutable
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        std::move(shortNonce),
        nullptr);
    });

  ASSERT_TRUE(mOpened->wait());
  EXPECT_EQ(mOpened->status, ua::StatusCode{ua::Status::BadNonceInvalid});
  ASSERT_NE(mOpened->detail, nullptr) << "ServerNonceInvalid must carry an ErrorDetail";
  EXPECT_EQ(mOpened->detail->code, "ServerNonceInvalid")
    << "Detail code must identify the server-nonce validation failure";
}

// ---------------------------------------------------------------------------
// OF-OPN-D - Server nonce length mismatch on authenticated policy.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOpenChannelFailurePin, AuthenticatedMismatchedServerNonceLengthRejected)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });
  // Expected nonce length 32, server returns 48.
  STA::on_strand(*mImpl, [](auto& g) { g.set_is_authenticated(/*authenticated=*/true, /*nonceLength=*/32); });

  std::vector<uint8_t> wrongNonceBytes(48, 0xcd);
  ua::ByteString wrongNonce{std::move(wrongNonceBytes)};

  STA::on_strand(*mImpl,
    [wrongNonce](auto& g) mutable
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        std::move(wrongNonce),
        nullptr);
    });

  ASSERT_TRUE(mOpened->wait());
  EXPECT_EQ(mOpened->status, ua::StatusCode{ua::Status::BadNonceInvalid});
  ASSERT_NE(mOpened->detail, nullptr);
  EXPECT_EQ(mOpened->detail->code, "ServerNonceInvalid");
}

// ---------------------------------------------------------------------------
// OF-OPN-E - OPN response in unexpected state is silently ignored.
// ---------------------------------------------------------------------------
//
// Verifies impl.cpp :680-684. The state-machine guard must drop the OPN
// response without firing mOnOpened a second time.

// clang-format off  -- this declaration must stay on ONE line: the requirements gate matches
// the JUnit test name against the tree-sitter function name, and a wrapped TEST_F cannot be
// matched (it fails the whole export, not just this test). Exceeds ColumnLimit by a few chars.
TEST_F(
  ClientSecureChannelOpenChannelFailurePin, OpnResponseInOpenStateIsSilentlyIgnoredAndDoesNotFireOnOpened)
// clang-format on
{
  create_impl();
  // Move directly to Open, then inject another OPN response. mOnOpened was
  // bound at construction; after open it should be cleared, and a stray OPN
  // response in Open state must be ignored.
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(/*channelId=*/7); });

  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{99},
        uint32_t{99},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });

  // Drain the strand to ensure any racing post-handle work has run.
  STA::strand_barrier(*mImpl);

  std::lock_guard<std::mutex> lk(mOpened->mx);
  EXPECT_FALSE(mOpened->fired) << "Stray OPN response in Open state must NOT re-fire mOnOpened";
}

// ---------------------------------------------------------------------------
// OF-OPN-F - Channel state transitions to Closed on bad service status.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOpenChannelFailurePin, BadOpnServiceStatusTransitionsChannelStateToClosed)
{
  create_impl();
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::BadInternalError},
        uint32_t{0},
        uint32_t{0},
        std::chrono::milliseconds{0},
        ua::ByteString{},
        nullptr);
    });
  ASSERT_TRUE(mOpened->wait());

  auto state = STA::on_strand(*mImpl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, ua::client::SecureChannelImpl::ChannelState::Closed);
  EXPECT_FALSE(mImpl->is_open()) << "is_open() must reflect Closed state cross-strand";
}

}  // namespace ua::test::behaviour_pins
