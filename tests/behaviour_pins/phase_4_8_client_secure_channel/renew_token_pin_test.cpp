// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - Token renewal.
//
//
// Infra-gap status: pins requiring wire-observable OPN-Renew bytes (RN-A wire
// new-nonce assertion) cannot be authored without a fake ConnectionProtocol
// - see agent return.
//
// What IS pinned here:
//   RN-A : handle_token_renewal in Open state transitions to Renewing.
//   RN-B : handle_token_renewal in non-Open state is a no-op (state unchanged).
//   RN-C : Server nonce reused on renewal rejected with BadNonceInvalid +
//          non-null detail "ServerNonceInvalid".
//   RN-D : Channel state returns to Open after a good Renew response
//          (Renewing -> Open).
//   RN-E : mOnOpened is NOT fired on Renew completion (already cleared on
//          first open per impl.cpp :820-821, the renew branch at :738-761
//          does not re-fire it).

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

struct ErrorSync
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

class ClientSecureChannelRenewTokenPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeClientSecureChannelDeps>(mPool->executor());
    mError = std::make_shared<ErrorSync>();
  }

  void TearDown() override
  {
    if (mImpl)
      mImpl.reset();
    if (mPool)
      mPool->stop();
  }

  void create_impl_and_force_open(uint32_t channelId = 1)
  {
    auto error = mError;
    mImpl = ua::client::SecureChannelImpl::create(
      mDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      ua::client::SecureChannelImpl::Config{},
      [](ua::VoidResult) {},
      [error](ua::VoidResult r)
      {
        {
          std::lock_guard<std::mutex> lk(error->mx);
          error->fired = true;
          error->status = r.status_code();
          error->detail = r.shared_detail();
        }
        error->cv.notify_one();
      });
    STA::on_strand(*mImpl, [channelId](auto& g) { g.set_channel_open(channelId); });
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeClientSecureChannelDeps> mDeps;
  std::shared_ptr<ErrorSync> mError;
  std::shared_ptr<ua::client::SecureChannelImpl> mImpl;
};

}  // namespace

// ---------------------------------------------------------------------------
// RN-A - handle_token_renewal transitions Open -> Renewing.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelRenewTokenPin, RenewalFromOpenTransitionsChannelStateToRenewing)
{
  create_impl_and_force_open();

  STA::on_strand(*mImpl, [](auto& g) { g.handle_token_renewal(); });
  STA::strand_barrier(*mImpl);

  auto state = STA::on_strand(*mImpl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, ua::client::SecureChannelImpl::ChannelState::Renewing);
}

// ---------------------------------------------------------------------------
// RN-B - handle_token_renewal in non-Open state is a no-op.
// ---------------------------------------------------------------------------
//
// Verifies impl.cpp :1008-1009 (renewal early-return when state is not Open).

TEST_F(ClientSecureChannelRenewTokenPin, RenewalIgnoredWhenChannelNotOpen)
{
  create_impl_and_force_open();
  // Move to Closed; renewal must NOT touch state.
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_closed(); });

  STA::on_strand(*mImpl, [](auto& g) { g.handle_token_renewal(); });
  STA::strand_barrier(*mImpl);

  auto state = STA::on_strand(*mImpl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, ua::client::SecureChannelImpl::ChannelState::Closed)
    << "Renewal in Closed state must be a no-op";
}

// ---------------------------------------------------------------------------
// RN-C - Server nonce reuse on renewal rejected.
// ---------------------------------------------------------------------------
//
// Verifies impl.cpp :723-730. After authenticated open we set mServerNonce to
// a known value, transition to Renewing, then drive an OPN-Renew response
// carrying the same server nonce - must be rejected.

TEST_F(ClientSecureChannelRenewTokenPin, RenewalServerNonceReuseRejectedWithBadNonceInvalid)
{
  create_impl_and_force_open();

  // Configure authenticated state and a baseline server nonce.
  std::vector<uint8_t> baselineBytes(32, 0x77);
  ua::ByteString baselineNonce{baselineBytes};
  STA::on_strand(*mImpl, [](auto& g) { g.set_is_authenticated(true, 32); });
  STA::on_strand(*mImpl, [baselineNonce](auto& g) mutable { g.set_server_nonce(std::move(baselineNonce)); });

  // Move to Renewing and inject an OPN-Renew response with the SAME nonce.
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_renewing(); });

  ua::ByteString sameNonce{baselineBytes};
  STA::on_strand(*mImpl,
    [sameNonce](auto& g) mutable
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{2},
        std::chrono::milliseconds{60000},
        std::move(sameNonce),
        nullptr);
    });

  ASSERT_TRUE(mError->wait()) << "Channel error callback must fire on nonce reuse";
  EXPECT_EQ(mError->status, ua::StatusCode{ua::Status::BadNonceInvalid});
  ASSERT_NE(mError->detail, nullptr);
  EXPECT_EQ(mError->detail->code, "ServerNonceInvalid")
    << "Nonce-reuse failure must carry the ServerNonceInvalid detail";
}

// ---------------------------------------------------------------------------
// RN-D - Good OPN-Renew response transitions Renewing -> Open.
// ---------------------------------------------------------------------------
//
// Verifies impl.cpp :738-761. Use unauthenticated channel so server-nonce
// validation does not run; the renew branch creates a new SecurityToken and
// transitions back to Open.

TEST_F(ClientSecureChannelRenewTokenPin, RenewalGoodResponseTransitionsRenewingBackToOpen)
{
  create_impl_and_force_open();
  // Default config is unauthenticated (None / None), so set_is_authenticated
  // is left false and server-nonce validation is skipped.
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_renewing(); });

  // The renewal names THIS channel's id (1, the id force-open gave it): a renewal response for another
  // channel id is refused since CL-SC-008's correlation check (security review 2026-09-28), and the
  // placeholder 0 this pin used to send reads as exactly that.
  STA::on_strand(*mImpl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        /*secureChannelId=*/uint32_t{1},
        /*tokenId=*/uint32_t{200},
        /*revisedLifetime=*/std::chrono::milliseconds{60000},
        /*serverNonce=*/ua::ByteString{},
        nullptr);
    });

  STA::strand_barrier(*mImpl);
  auto state = STA::on_strand(*mImpl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, ua::client::SecureChannelImpl::ChannelState::Open);
  auto tokenId = STA::on_strand(*mImpl, [](auto& g) { return g.channel_token_id(); });
  EXPECT_EQ(tokenId, 200u) << "New token id must be stored on renewal";
}

// ---------------------------------------------------------------------------
// RN-E - mOnOpened is NOT re-fired on a Renew completion.
// ---------------------------------------------------------------------------
//
// Locks the section 3.2 invariant that the renew branch (impl.cpp :738-761) does
// NOT call mOnOpened - that callback was cleared on first open.

TEST_F(ClientSecureChannelRenewTokenPin, RenewalCompletionDoesNotReFireOnOpenedCallback)
{
  // Construct directly so we observe mOnOpened firing precisely once.
  std::mutex mx;
  std::condition_variable cv;
  int onOpenedCalls{0};
  auto* mxp = &mx;
  auto* cvp = &cv;
  auto* counterp = &onOpenedCalls;

  auto impl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [mxp, cvp, counterp](ua::VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(*mxp);
        ++(*counterp);
      }
      cvp->notify_one();
    },
    [](ua::VoidResult) {});

  // Drive a normal OPN-Issue completion -> mOnOpened fires once.
  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{100},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return onOpenedCalls == 1; }));
  }

  // Now drive a Renew transition + Renew response. mOnOpened must NOT fire.
  STA::on_strand(*impl, [](auto& g) { g.set_channel_renewing(); });
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{200},
        std::chrono::milliseconds{60000},
        ua::ByteString{},
        nullptr);
    });
  STA::strand_barrier(*impl);

  std::lock_guard<std::mutex> lk(mx);
  EXPECT_EQ(onOpenedCalls, 1) << "Renew completion must NOT re-fire mOnOpened (cleared on first open)";

  impl.reset();
}

}  // namespace ua::test::behaviour_pins
