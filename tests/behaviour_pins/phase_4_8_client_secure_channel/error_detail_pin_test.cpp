// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - ErrorDetail
// propagation across failure boundaries.
//
//
// Infra-gap status: pins requiring fake CertificateStore / FakeAsyncCrypto
// failure stimuli (ED-A through ED-D) are NOT covered here - the section 4.0.1 fakes
// do not exist. Pins for service-fault diagnostics propagation (ED-F) and
// per-request timeout detail (ED-E) require a fake transport / wire-bytes
// capture and are out of scope.
//
// What IS pinned here:
//   ED-A : Bad OPN service status forwards the wire-supplied ErrorDetail
//          pointer-identically (lossless propagation through the outer
//          failure boundary at impl.cpp :686-696).
//   ED-B : Destructor with pending request callback fires that callback with
//          BadSecureChannelClosed + non-null detail "ChannelDestroyed"
//          (impl.cpp :151-158).
//   ED-C : Destructor with mOnOpened set (channel destroyed mid-open) fires
//          mOnOpened with BadSecureChannelClosed + non-null detail
//          "ChannelDestroyed" (impl.cpp :132-140).
//   ED-D : Server nonce-too-short rejection carries detail with code
//          "ServerNonceInvalid" - locks the failure-mode-specific code so a
//          regression that emits a generic detail is caught.
//   ED-E : Transport error while channel is Open fires the channel error
//          callback with non-null detail "ChannelError"
//          (impl.cpp ChunkReceiveError -> handle_channel_error).

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <vector>

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_byte_string.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_read_request.h"
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

template<typename Result>
struct CallbackSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  std::optional<Result> result;

  bool wait(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

using STA = ua::client::SecureChannelTestAccess;

class ClientSecureChannelErrorDetailPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeClientSecureChannelDeps>(mPool->executor());
  }

  void TearDown() override
  {
    if (mPool)
      mPool->stop();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeClientSecureChannelDeps> mDeps;
};

}  // namespace

// ---------------------------------------------------------------------------
// ED-A - Bad OPN service status forwards detail pointer-identically.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelErrorDetailPin, BadOpnStatusForwardsCallerDetailPointerIdentically)
{
  auto sync = std::make_shared<CallbackSync<ua::VoidResult>>();
  auto impl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [sync](ua::VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->result = r;
      }
      sync->cv.notify_one();
    },
    [](ua::VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  auto innerDetail = std::shared_ptr<const ua::ErrorDetail>(
    ua::make_error_detail("UpstreamCause", "synthetic ED-A test detail", "test"));

  STA::on_strand(*impl,
    [innerDetail](auto& g)
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
        uint32_t{0},
        uint32_t{0},
        std::chrono::milliseconds{0},
        ua::ByteString{},
        innerDetail);
    });

  ASSERT_TRUE(sync->wait());
  ASSERT_NE(sync->result->shared_detail(), nullptr);
  EXPECT_EQ(sync->result->shared_detail().get(), innerDetail.get())
    << "ErrorDetail copied/replaced at OPN-bad-status boundary - must be lossless";

  impl.reset();
}

// ---------------------------------------------------------------------------
// ED-B - Destructor fires pending request callbacks with ChannelDestroyed.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelErrorDetailPin, DestructorFiresPendingRequestCallbackWithChannelDestroyedDetail)
{
  auto requestSync = std::make_shared<CallbackSync<ua::client::SecureChannelImpl::ServiceResponseResult>>();

  auto impl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});

  // Force channel open and register a pending request that nothing will
  // ever respond to. send_request posts to the strand, validates the
  // Open state, allocates a requestId, queues the message, and parks the
  // callback in mPendingRequests. With nullptr connection, the pump drains
  // the queue silently (impl.cpp :626-634), so the callback stays parked.
  STA::on_strand(*impl, [](auto& g) { g.set_channel_open(/*channelId=*/42); });

  impl->send_request(std::make_shared<ua::ReadRequest>(),
    [requestSync](ua::client::SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(requestSync->mx);
        requestSync->fired = true;
        requestSync->result = r;
      }
      requestSync->cv.notify_one();
    });

  // Drain the strand to ensure send_request has fully posted and the callback
  // is parked.
  STA::strand_barrier(*impl);
  auto pendingCount = STA::on_strand(*impl, [](auto& g) { return g.pending_requests().size(); });
  ASSERT_EQ(pendingCount, 1u) << "Pending request must be parked before destructor runs";

  // Drop the last shared_ptr - destructor's safety net at impl.cpp :154-158
  // must fire the parked callback inline.
  impl.reset();

  ASSERT_TRUE(requestSync->wait()) << "Destructor must fire parked pending-request callback";
  EXPECT_EQ(requestSync->result->status_code(), ua::StatusCode{ua::Status::BadSecureChannelClosed});
  ASSERT_NE(requestSync->result->shared_detail(), nullptr);
  EXPECT_EQ(requestSync->result->shared_detail()->code, "ChannelDestroyed")
    << "Destructor-fired pending callback must carry the ChannelDestroyed code (impl.cpp :152-153)";
}

// ---------------------------------------------------------------------------
// ED-C - Destructor fires mOnOpened with ChannelDestroyed when channel was
// destroyed mid-open.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelErrorDetailPin, DestructorFiresOnOpenedWithChannelDestroyedDetailWhenMidOpen)
{
  auto sync = std::make_shared<CallbackSync<ua::VoidResult>>();
  auto impl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [sync](ua::VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->result = r;
      }
      sync->cv.notify_one();
    },
    [](ua::VoidResult) {});

  // Don't drive open - leave mOnOpened set.
  STA::strand_barrier(*impl);
  // Drop the last shared_ptr; destructor at impl.cpp :132-140 fires
  // mOnOpened with ChannelDestroyed.
  impl.reset();

  ASSERT_TRUE(sync->wait()) << "Destructor must fire mOnOpened safety net for mid-open destroy";
  EXPECT_EQ(sync->result->status_code(), ua::StatusCode{ua::Status::BadSecureChannelClosed});
  ASSERT_NE(sync->result->shared_detail(), nullptr);
  EXPECT_EQ(sync->result->shared_detail()->code, "ChannelDestroyed");
}

// ---------------------------------------------------------------------------
// ED-D - Server nonce-too-short rejection carries the
// ServerNonceInvalid detail code (locks the failure-specific attribution).
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelErrorDetailPin, ServerShortNonceRejectionCarriesServerNonceInvalidDetailCode)
{
  auto sync = std::make_shared<CallbackSync<ua::VoidResult>>();
  auto impl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [sync](ua::VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->result = r;
      }
      sync->cv.notify_one();
    },
    [](ua::VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });
  STA::on_strand(*impl, [](auto& g) { g.set_is_authenticated(true, 32); });

  std::vector<uint8_t> shortBytes(8, 0x11);
  ua::ByteString shortNonce{std::move(shortBytes)};
  STA::on_strand(*impl,
    [shortNonce](auto& g) mutable
    {
      g.handle_opn_response(ua::StatusCode{ua::Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        std::move(shortNonce),
        nullptr);
    });

  ASSERT_TRUE(sync->wait());
  EXPECT_EQ(sync->result->status_code(), ua::StatusCode{ua::Status::BadNonceInvalid});
  ASSERT_NE(sync->result->shared_detail(), nullptr);
  EXPECT_EQ(sync->result->shared_detail()->code, "ServerNonceInvalid")
    << "Short-nonce failure must carry the failure-specific code, not a generic one";

  impl.reset();
}

// ---------------------------------------------------------------------------
// ED-E - Transport error while open fires error callback with non-null detail.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelErrorDetailPin, TransportErrorWhileOpenFiresChannelErrorWithChannelErrorDetail)
{
  auto sync = std::make_shared<CallbackSync<ua::VoidResult>>();
  auto impl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [sync](ua::VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->result = r;
      }
      sync->cv.notify_one();
    });

  // Force open so transport error routes through mOnError (post-open path
  // would normally use mOnChannelError, but mOnChannelError is not set in
  // the default Config - mOnError is preserved if mOnOpened is cleared).
  STA::on_strand(*impl, [](auto& g) { g.set_channel_open(); });

  // receive_transport_error fires synchronously into the channel error path.
  STA::on_strand(*impl,
    [](auto& g)
    { g.receive_transport_error(ua::StatusCode{ua::Status::BadConnectionClosed}, std::string_view{}); });

  ASSERT_TRUE(sync->wait()) << "Transport error must reach channel error callback";
  EXPECT_TRUE(sync->result->status_code().is_bad());
  ASSERT_NE(sync->result->shared_detail(), nullptr) << "Channel error must carry an ErrorDetail";
  EXPECT_EQ(sync->result->shared_detail()->code, "ChannelError")
    << "Transport-error path must produce the ChannelError detail code";

  impl.reset();
}

}  // namespace ua::test::behaviour_pins
