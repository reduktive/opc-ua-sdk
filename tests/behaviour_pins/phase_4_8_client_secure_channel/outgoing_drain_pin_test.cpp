// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - outgoing drain.
//
//
// Infra-gap status: pins requiring wire-bytes capture (OD-H recorded chunks),
// per-request timeout via real timer + wall-clock waits (OD-D, OD-E),
// FakeAsyncSecurityPolicy boundary observability (OD-F drain-complete on
// fake encode, OD-I encode-throw routing) cannot be authored without missing
// fakes - see agent return.
//
// What IS pinned here:
//   OD-A : send_request when channel is Open registers callback in
//          mPendingRequests and assigns a fresh requestId.
//   OD-B : send_request when channel is Closed fires callback with
//          BadSecureChannelClosed + non-null detail "ChannelNotOpen".
//   OD-C : send_request when channel is Opening fires callback with
//          BadSecureChannelClosed (impl.cpp :1235-1242).
//   OD-D : send_request when channel is Renewing is accepted (allowed per
//          impl.cpp :1235-1242 which permits Open OR Renewing) - the request
//          parks in mPendingRequests with a fresh id.
//   OD-E : send_request callback fires on the channel strand thread when
//          rejected synchronously.

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
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

struct ResponseSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  ua::StatusCode status{ua::Status::Good};
  std::shared_ptr<const ua::ErrorDetail> detail;
  std::thread::id threadId;

  bool wait(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

using STA = ua::client::SecureChannelTestAccess;

class ClientSecureChannelOutgoingDrainPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeClientSecureChannelDeps>(mPool->executor());
  }

  void TearDown() override
  {
    if (mImpl)
      mImpl.reset();
    if (mPool)
      mPool->stop();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeClientSecureChannelDeps> mDeps;
  std::shared_ptr<ua::client::SecureChannelImpl> mImpl;
};

}  // namespace

// ---------------------------------------------------------------------------
// OD-A - send_request when Open registers callback in mPendingRequests.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOutgoingDrainPin, SendRequestWhenOpenRegistersCallbackInPendingRequests)
{
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(/*channelId=*/42); });

  // Capture next-request-id pre-call.
  auto preNextId = STA::on_strand(*mImpl, [](auto& g) { return g.next_request_id(); });

  mImpl->send_request(
    std::make_shared<ua::ReadRequest>(), [](ua::client::SecureChannelImpl::ServiceResponseResult) {});

  // Drain the strand and observe state.
  STA::strand_barrier(*mImpl);
  auto pendingCount = STA::on_strand(*mImpl, [](auto& g) { return g.pending_requests().size(); });
  EXPECT_EQ(pendingCount, 1u) << "send_request must park callback in mPendingRequests";

  auto postNextId = STA::on_strand(*mImpl, [](auto& g) { return g.next_request_id(); });
  EXPECT_EQ(postNextId, preNextId + 1) << "send_request must consume one request id";
}

// ---------------------------------------------------------------------------
// OD-B - send_request when Closed fires callback with BadSecureChannelClosed.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOutgoingDrainPin, SendRequestWhenClosedFiresCallbackWithBadSecureChannelClosed)
{
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_closed(); });

  auto sync = std::make_shared<ResponseSync>();
  mImpl->send_request(std::make_shared<ua::ReadRequest>(),
    [sync](ua::client::SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->status = r.status_code();
        sync->detail = r.shared_detail();
        sync->threadId = std::this_thread::get_id();
      }
      sync->cv.notify_one();
    });

  ASSERT_TRUE(sync->wait());
  EXPECT_EQ(sync->status, ua::StatusCode{ua::Status::BadSecureChannelClosed});
  ASSERT_NE(sync->detail, nullptr) << "send_request rejection must carry an ErrorDetail";
}

// ---------------------------------------------------------------------------
// OD-C - send_request when Opening fires callback with BadSecureChannelClosed.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOutgoingDrainPin, SendRequestWhenOpeningFiresCallbackWithBadSecureChannelClosed)
{
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_opening(); });

  auto sync = std::make_shared<ResponseSync>();
  mImpl->send_request(std::make_shared<ua::ReadRequest>(),
    [sync](ua::client::SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->status = r.status_code();
      }
      sync->cv.notify_one();
    });

  ASSERT_TRUE(sync->wait());
  EXPECT_EQ(sync->status, ua::StatusCode{ua::Status::BadSecureChannelClosed});
}

// ---------------------------------------------------------------------------
// OD-D - send_request when Renewing is ACCEPTED.
// ---------------------------------------------------------------------------
//
// Locks impl.cpp :1235-1242: the gate accepts both Open AND Renewing. A
// regression that gated only on Open would silently break in-flight requests
// during token rotation.

TEST_F(ClientSecureChannelOutgoingDrainPin, SendRequestWhenRenewingIsAcceptedAndParksCallback)
{
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(/*channelId=*/42); });
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_renewing(); });

  mImpl->send_request(
    std::make_shared<ua::ReadRequest>(), [](ua::client::SecureChannelImpl::ServiceResponseResult) {});
  STA::strand_barrier(*mImpl);

  auto pendingCount = STA::on_strand(*mImpl, [](auto& g) { return g.pending_requests().size(); });
  EXPECT_EQ(pendingCount, 1u)
    << "send_request must be accepted in Renewing state (token rotation must not break in-flight requests)";
}

// ---------------------------------------------------------------------------
// OD-E - Synchronously-rejected send_request callback fires on channel strand.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelOutgoingDrainPin, RejectedSendRequestCallbackFiresOnChannelStrandThread)
{
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_closed(); });

  const std::thread::id strandThreadId =
    STA::on_strand(*mImpl, [](auto&) { return std::this_thread::get_id(); });

  auto sync = std::make_shared<ResponseSync>();
  mImpl->send_request(std::make_shared<ua::ReadRequest>(),
    [sync](ua::client::SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->fired = true;
        sync->status = r.status_code();
        sync->threadId = std::this_thread::get_id();
      }
      sync->cv.notify_one();
    });

  ASSERT_TRUE(sync->wait());
  EXPECT_EQ(sync->threadId, strandThreadId)
    << "Rejected send_request callback fired on a non-strand thread - strand discipline broken";
}

}  // namespace ua::test::behaviour_pins
