// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.8 (Client SecureChannel) - strand dispatch.
//
//
// Infra-gap status: the runbook section 4.7 strand-dispatch contract pins (SD-A
// through SD-E) require BOTH a real OpenSslCrypto + CertificateStoreFiles
// (for the inline-fast-path branch) AND a FakeAsyncCrypto / FakeAsyncSecurityPolicy
// firing from a dedicated worker thread (for the async-dispatch branch).
// Neither set of fakes exists in the tree today (see agent return). The full
// SD-A / SD-B / SD-C / SD-D / SD-E are NOT covered.
//
// What IS pinned here (an attenuated subset that still locks externally-
// observable strand affinity):
//   SD-PUB-A : send_request callback fires on the channel strand thread
//              (rejection path; minimal observability proxy for SD-D's
//              "pump iteration runs on strand").
//   SD-PUB-B : Channel-error callback (mOnError) fires on the channel strand
//              thread (proxy for SD-A's "open chain stays on strand").
//
// These are the same threading-affinity pins as in close_flow_pin_test.cpp /
// outgoing_drain_pin_test.cpp but isolated here to keep the section 4.7 directory
// non-empty when reviewers grep by file.

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

using STA = ua::client::SecureChannelTestAccess;

class ClientSecureChannelStrandDispatchPin : public ::testing::Test
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
// SD-PUB-A - send_request rejection callback fires on the channel strand.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelStrandDispatchPin, SendRequestRejectionCallbackFiresOnChannelStrand)
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

  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  std::thread::id observed;
  mImpl->send_request(std::make_shared<ua::ReadRequest>(),
    [&](ua::client::SecureChannelImpl::ServiceResponseResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        observed = std::this_thread::get_id();
        // Notify under the lock: the waiting thread re-acquires mx before returning from wait_for,
        // so it cannot destroy cv (at test-body exit) while this worker is still in notify_one.
        cv.notify_one();
      }
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return fired; }));
  }
  EXPECT_EQ(observed, strandThreadId)
    << "send_request rejection callback fired off the channel strand thread";
}

// ---------------------------------------------------------------------------
// SD-PUB-B - Channel-error callback (mOnError) fires on the channel strand.
// ---------------------------------------------------------------------------

TEST_F(ClientSecureChannelStrandDispatchPin, ChannelErrorCallbackFiresOnChannelStrandThread)
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  std::thread::id observed;
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
        fired = true;
        observed = std::this_thread::get_id();
        // Notify under the lock: the waiting thread re-acquires mx before returning from wait_for,
        // so it cannot destroy cv (at test-body exit) while this worker is still in notify_one.
        cv.notify_one();
      }
    });

  STA::on_strand(*mImpl, [](auto& g) { g.set_channel_open(); });
  const std::thread::id strandThreadId =
    STA::on_strand(*mImpl, [](auto&) { return std::this_thread::get_id(); });

  STA::on_strand(*mImpl,
    [](auto& g)
    { g.receive_transport_error(ua::StatusCode{ua::Status::BadConnectionClosed}, std::string_view{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return fired; }));
  }
  EXPECT_EQ(observed, strandThreadId)
    << "Channel-error callback fired on a non-strand thread - strand discipline broken";
}

}  // namespace ua::test::behaviour_pins
