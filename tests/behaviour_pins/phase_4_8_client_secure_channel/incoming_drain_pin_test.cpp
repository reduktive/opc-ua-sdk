// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - incoming drain.
//
//
// Infra-gap status: pins requiring fake SecurityPolicy decode_message_chunk
// boundary observability (ID-A pump-state assertions, ID-B re-seed guard,
// ID-C re-seed-after-done, ID-E response correlation through real decode,
// ID-F unknown-typeId, ID-G ServiceFault correlation, ID-H decode-throw
// routing) cannot be authored without a FakeAsyncSecurityPolicy that the
// section 4.0.1 sharing strategy relies on - see agent return.
//
// What IS pinned here:
//   ID-A : receive_message_chunk with bad status invokes channel error
//          (impl.cpp :386-399) and produces detail "ChunkReceiveError".
//   ID-B : receive_message_chunk with bad status when state is already
//          Closed is a no-op (idempotent error path; impl.cpp :390 guard).
//   ID-C : receive_transport_error in Closed state is silently ignored
//          (impl.cpp :411-412).
//   ID-D : Bad-status chunk failure carries the correct
//          status code as supplied (StatusCode passed through unmodified).
//   ID-E : Bad-status chunk failure carries pending request callbacks back
//          with non-null detail (lossless propagation through
//          handle_channel_error -> failure of all pending requests).

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>

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

struct VoidSync
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

class ClientSecureChannelIncomingDrainPin : public ::testing::Test
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
// ID-A - Bad-status chunk invokes channel error with ChunkReceiveError detail.
// ---------------------------------------------------------------------------

// Re-authored 2026-05-03 (MR2.5 R4): production deliberately preserves the inner
// `ChunkReceiveError` detail at `handle_channel_error` (ua_client_secure_channel_impl.cpp:858)
// when a caller provides one. This is the SDK's "lossless ErrorDetail propagation" rule -
// the inner detail carries strictly more information than a wrapping outer "ChannelError"
// would. The pin therefore asserts the inner-detail code as the user-observable signal.
TEST_F(ClientSecureChannelIncomingDrainPin, BadStatusChunkInvokesChannelErrorWithChunkReceiveErrorDetail)
{
  auto errorSync = std::make_shared<VoidSync>();
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [errorSync](ua::VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(errorSync->mx);
        errorSync->fired = true;
        errorSync->status = r.status_code();
        errorSync->detail = r.shared_detail();
      }
      errorSync->cv.notify_one();
    });

  // Force open so the error path routes through mOnError (mOnOpened cleared).
  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(); });

  STA::on_strand(*mImpl,
    [](auto& g)
    { g.receive_message_chunk(ua::StatusCode{ua::Status::BadConnectionClosed}, std::vector<ua::byte>{}); });

  ASSERT_TRUE(errorSync->wait());
  EXPECT_TRUE(errorSync->status.is_bad());
  ASSERT_NE(errorSync->detail, nullptr) << "Bad-status chunk path must carry an ErrorDetail";
  EXPECT_EQ(errorSync->detail->code, "ChunkReceiveError")
    << "Inner detail must be propagated losslessly (no wrapping outer ChannelError)";

  auto state = STA::on_strand(*mImpl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, ua::client::SecureChannelImpl::ChannelState::Closed);
}

// ---------------------------------------------------------------------------
// ID-B - Bad-status chunk in Closed state is a no-op.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelIncomingDrainPin, BadStatusChunkWhenAlreadyClosedIsANoOp)
{
  int errorCallbackCount{0};
  std::mutex mx;
  std::condition_variable cv;

  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [&](ua::VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        ++errorCallbackCount;
      }
      cv.notify_one();
    });

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_closed(); });

  STA::on_strand(*mImpl,
    [](auto& g)
    { g.receive_message_chunk(ua::StatusCode{ua::Status::BadConnectionClosed}, std::vector<ua::byte>{}); });
  STA::strand_barrier(*mImpl);

  std::lock_guard<std::mutex> lk(mx);
  EXPECT_EQ(errorCallbackCount, 0)
    << "Bad-status chunk in Closed state must not re-invoke the error callback (impl.cpp :390 guard)";
}

// ---------------------------------------------------------------------------
// ID-C - receive_transport_error in Closed state is silently ignored.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelIncomingDrainPin, TransportErrorInClosedStateIsSilentlyIgnored)
{
  int errorCallbackCount{0};
  std::mutex mx;
  std::condition_variable cv;

  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [&](ua::VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        ++errorCallbackCount;
      }
      cv.notify_one();
    });

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_closed(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    { g.receive_transport_error(ua::StatusCode{ua::Status::BadConnectionClosed}, std::string_view{}); });
  STA::strand_barrier(*mImpl);

  std::lock_guard<std::mutex> lk(mx);
  EXPECT_EQ(errorCallbackCount, 0) << "Transport error in Closed state must be ignored (impl.cpp :411-412)";
}

// ---------------------------------------------------------------------------
// ID-D - Bad-status chunk supplies the original status code unmodified.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelIncomingDrainPin, BadStatusChunkPropagatesOriginalStatusCodeToErrorCallback)
{
  auto errorSync = std::make_shared<VoidSync>();
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [errorSync](ua::VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(errorSync->mx);
        errorSync->fired = true;
        errorSync->status = r.status_code();
      }
      errorSync->cv.notify_one();
    });

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(); });
  STA::on_strand(*mImpl,
    [](auto& g)
    { g.receive_message_chunk(ua::StatusCode{ua::Status::BadCommunicationError}, std::vector<ua::byte>{}); });

  ASSERT_TRUE(errorSync->wait());
  EXPECT_EQ(errorSync->status, ua::StatusCode{ua::Status::BadCommunicationError})
    << "Original transport status code must propagate unmodified to the channel error callback";
}

// ---------------------------------------------------------------------------
// ID-E - Bad-status chunk fails pending requests with non-null detail.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelIncomingDrainPin, BadStatusChunkFailsPendingRequestsWithNonNullDetail)
{
  mImpl = ua::client::SecureChannelImpl::create(
    mDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    ua::client::SecureChannelImpl::Config{},
    [](ua::VoidResult) {},
    [](ua::VoidResult) {});

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(); });

  auto requestSync = std::make_shared<VoidSync>();
  mImpl->send_request(std::make_shared<ua::ReadRequest>(),
    [requestSync](ua::client::SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(requestSync->mx);
        requestSync->fired = true;
        requestSync->status = r.status_code();
        requestSync->detail = r.shared_detail();
      }
      requestSync->cv.notify_one();
    });
  STA::strand_barrier(*mImpl);

  // Drive a transport error which fails all pending.
  STA::on_strand(*mImpl,
    [](auto& g)
    { g.receive_message_chunk(ua::StatusCode{ua::Status::BadConnectionClosed}, std::vector<ua::byte>{}); });

  ASSERT_TRUE(requestSync->wait());
  EXPECT_TRUE(requestSync->status.is_bad());
  ASSERT_NE(requestSync->detail, nullptr)
    << "Failing a pending request via channel error must carry an ErrorDetail";
}

}  // namespace ua::test::behaviour_pins
