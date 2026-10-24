// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <limits>

#include "test_utilities.h"
#include "integration/helpers/sanitizer_budget.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_error_detail.h"
#include "ua_read_request.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_structure_factory.h"
#include "ua_exceptions.h"
#include <boost/asio/thread_pool.hpp>

// Test-only access to client secure channel internals.
#include "../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"

// CL-UASC-020: the encode-failure path only runs when the channel has a real (non-null) connection, so
// these helpers wire a real client ConnectionProtocol over a fake transport and override the security
// policy with a parked-encode fake.
#include "fake_async_security_policy.h"
#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"
#include "ua_binary_codec.h"
#include "ua_connection_protocol.h"
#include "ua_crypto.h"
#include "ua_memory_stream.h"
#include "ua_open_secure_channel_request.h"
#include "ua_reverse_hello.h"
#include "ua_stack_utilities.h"

// LDS registration lifecycle: the app-layer register client (cadence / retry) and the LDS-side
// registry it registers into (expiry).
#include "ua_discovery_registration.h"
#include "ua_lds_registrar.h"
#include "ua_registered_server.h"
#include "ua_registered_server_store.h"
#include "ua_server_configuration.h"

// LDS-side inbound registration: the real RegisterServer2 service handler that validates an
// inbound registration before it reaches the registry, and the discovery dependencies it reads.
#include "fake_discovery_dependencies.h"
#include "ua_discovery_service_set.h"
#include "ua_mdns_discovery_configuration.h"
#include "ua_service_fault.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <optional>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;

using STA = SecureChannelTestAccess;

namespace
{

class FakeClientSecureChannelDeps : public SecureChannelDependencies
{
public:
  explicit FakeClientSecureChannelDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(ApplicationConfig::load_default())
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  shared_ptr<CertificateStore> certificate_store() override
  {
    return nullptr;
  }

  const ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  Logger logger() override
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

  /// Opts this application in to unsecured channels, so a Session may be created over one.
  void allow_insecure_endpoints(bool allow)
  {
    mAppCfg.allowInsecureEndpoints = allow;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ApplicationConfig mAppCfg;
  StructureFactory mFactory;
};

/// Synchronization state for callbacks, heap-allocated to avoid move issues.
struct CallbackSync
{
  std::mutex mx;
  std::condition_variable cv;

  bool opened{false};
  StatusCode openedStatus{Status::Good};
  bool errorOccurred{false};
  StatusCode errorStatus{Status::Good};

  bool wait_opened(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return opened; });
  }

  bool wait_error(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return errorOccurred; });
  }
};

/// Helper: create a SecureChannelImpl with no connection (test mode).
struct TestSecureChannelSetup
{
  std::shared_ptr<FakeClientSecureChannelDeps> deps;
  std::shared_ptr<SecureChannelImpl> impl;
  std::shared_ptr<CallbackSync> sync;

  /// Drop every executor-pinned shared_ptr so a subsequent pool.join() drains.
  void release()
  {
    impl.reset();
    deps.reset();
    sync.reset();
  }

  static TestSecureChannelSetup create(
    boost::asio::any_io_executor ex, SecureChannelImpl::Config channelConfig = {})
  {
    TestSecureChannelSetup s;
    s.deps = std::make_shared<FakeClientSecureChannelDeps>(ex);
    s.sync = std::make_shared<CallbackSync>();

    auto syncPtr = s.sync;
    s.impl = SecureChannelImpl::create(
      s.deps,
      nullptr,  // No connection (test mode)
      ua::connection_protocol::NegotiatedLimits{},
      std::move(channelConfig),
      [syncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->opened = true;
          syncPtr->openedStatus = result.status_code();
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = result.status_code();
        }
        syncPtr->cv.notify_one();
      });

    return s;
  }

  void set_channel_open_on_strand(uint32_t channelId = 42)
  {
    STA::on_strand(*impl, [channelId](auto& g) { g.set_channel_open(channelId); });
  }

  void set_channel_opening_on_strand()
  {
    STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });
  }

  void set_channel_renewing_on_strand()
  {
    STA::on_strand(*impl, [](auto& g) { g.set_channel_renewing(); });
  }

  void set_channel_closed_on_strand()
  {
    STA::on_strand(*impl, [](auto& g) { g.set_channel_closed(); });
  }

  void set_is_authenticated_on_strand(bool authenticated, uint32_t nonceLength = 0)
  {
    STA::on_strand(
      *impl, [authenticated, nonceLength](auto& g) { g.set_is_authenticated(authenticated, nonceLength); });
  }

  void set_server_nonce_on_strand(ByteString nonce)
  {
    STA::on_strand(
      *impl, [nonce = std::move(nonce)](auto& g) mutable { g.set_server_nonce(std::move(nonce)); });
  }
};

}  // namespace

// --- Construction and lifecycle tests ---

TEST(ClientSecureChannelShellTests, CreateWithNullConnectionDoesNotCrash)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // The impl should be in Opening state (logic sent SendOpenSecureChannelRequest,
  // but no connection means it was drained silently).
  EXPECT_FALSE(setup.impl->is_open());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-AUDIT-002
// @relation(CL-AUDIT-002, scope=function)
TEST(ClientSecureChannelShellTests, AuditProviderRunsBeforeRenewAndCloseDispatch)
{
  boost::asio::thread_pool pool;
  std::atomic<std::size_t> providerCalls{0};
  SecureChannelImpl::Config config;
  config.auditEntryIdProvider = [&providerCalls]
  {
    providerCalls.fetch_add(1);
    return String{"channel-audit"};
  };
  auto setup = TestSecureChannelSetup::create(pool.get_executor(), std::move(config));

  setup.set_channel_open_on_strand();
  STA::on_strand(*setup.impl, [](auto& guard) { guard.handle_token_renewal(); });
  STA::strand_barrier(*setup.impl);
  ASSERT_GE(providerCalls.load(), 1U) << "OpenSecureChannel renewal must obtain its audit id before dispatch";
  setup.set_channel_open_on_strand();
  setup.impl->close([](VoidResult) {});
  STA::strand_barrier(*setup.impl);
  ASSERT_GE(providerCalls.load(), 2U) << "CloseSecureChannel must obtain its audit id before dispatch";
  EXPECT_EQ(providerCalls.load(), 2U);

  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSecureChannelShellTests, SecureChannelIdReturnsZeroBeforeOpen)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  EXPECT_EQ(setup.impl->secure_channel_id(), 0u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Send request when closed ---

TEST(ClientSecureChannelShellTests, SendRequestWhenClosedReturnsBadSecureChannelClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.impl->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_EQ(resultStatus, Status::BadSecureChannelClosed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Send request when open registers in pending map ---

TEST(ClientSecureChannelShellTests, SendRequestWhenOpenRegistersInPendingMap)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Force channel open.
  setup.set_channel_open_on_strand(42);

  // Send a request. The message will be queued and drained (no connection),
  // but the callback should be registered in the pending map.
  setup.impl->send_request(
    std::make_shared<ua::ReadRequest>(), [](SecureChannelImpl::ServiceResponseResult) {});

  // Wait deterministically for the strand to process the send_request post.
  auto pendingCount = STA::on_strand(*setup.impl, [](auto& g) { return g.pending_requests().size(); });
  EXPECT_EQ(pendingCount, 1u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Local response wait ---

// The Client waits for a response past the timeoutHint it sent: the hint plus a tenth, at least 500 ms
// more, saturating; 0 (no timeout) stays 0.
// @relation(AC-CL-SESS-030-WAIT-PAST-THE-HINT, scope=function)
TEST(ClientSecureChannelShellTests, ResponseWaitIsTheHintPlusATenthAndAtLeast500Ms)
{
  EXPECT_EQ(SecureChannelImpl::response_wait_for(0), 0u);
  EXPECT_EQ(SecureChannelImpl::response_wait_for(200), 700u);
  EXPECT_EQ(SecureChannelImpl::response_wait_for(5000), 5500u);
  EXPECT_EQ(SecureChannelImpl::response_wait_for(10000), 11000u);
  EXPECT_EQ(SecureChannelImpl::response_wait_for(std::numeric_limits<uint32_t>::max()),
    std::numeric_limits<uint32_t>::max());
}

// A request whose response never comes is failed locally with Bad_Timeout - not at the hint it carried,
// when a Server answering at the hint would still be heard, but once the margin past it has gone.
// @relation(AC-CL-SESS-030-WAIT-PAST-THE-HINT, scope=function)
TEST(ClientSecureChannelShellTests, UnansweredRequestFailsLocallyAfterTheHintAndItsMargin)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_open_on_strand(42);

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};
  const auto sent = std::chrono::steady_clock::now();
  std::chrono::steady_clock::time_point firedAt;
  setup.impl->send_request(
    std::make_shared<ua::ReadRequest>(),
    [&](SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
        firedAt = std::chrono::steady_clock::now();
      }
      cv.notify_one();
    },
    /*timeoutMs=*/200);

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 3000ms, [&]() { return callbackFired; }));
  }
  EXPECT_EQ(resultStatus, Status::BadTimeout);
  EXPECT_GE(firedAt - sent, 690ms) << "the Client must wait past the 200 ms hint: 200 ms + 500 ms";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Close tests ---

TEST(ClientSecureChannelShellTests, CloseWhenOpenCallsCallback)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Force channel open.
  setup.set_channel_open_on_strand(42);

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.impl->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return closeFired; }));
  }

  EXPECT_TRUE(closeStatus.is_good());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A closed channel cannot renew, so its key-agreement secrets - the chained key material of Part 6 6.8.1 Step
// 2 and the ephemeral private key - are scrubbed when the channel releases its security state, even though an
// operation may still hold the context.
// @relation(AC-COMP-ECC-KEY-AGREEMENT-SECRETS-RELEASED, scope=function)
TEST(ClientSecureChannelShellTests, ACloseScrubsTheKeyAgreementSecrets)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_open_on_strand();
  std::shared_ptr<ua::SecureChannelContext> context;
  STA::on_strand(*setup.impl,
    [&](auto& g)
    {
      context = g.context();
      context->keyAgreementIkm = ByteString(48, uint8_t{0x5a});
      context->localEphemeralPrivateKey = ByteString(32, uint8_t{0xa5});
    });
  ASSERT_NE(context, nullptr);

  STA::on_strand(*setup.impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });
  // The release is posted behind the close; the barrier lets it run.
  STA::strand_barrier(*setup.impl);

  bool released = false;
  STA::on_strand(*setup.impl, [&](auto& g) { released = g.context() == nullptr; });
  EXPECT_TRUE(released);
  EXPECT_TRUE(context->keyAgreementIkm.empty());
  EXPECT_TRUE(context->localEphemeralPrivateKey.empty());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The orderly close releases the security state too, once its CloseSecureChannel is encoded, and scrubs the
// key-agreement secrets with it.
// @relation(AC-COMP-ECC-KEY-AGREEMENT-SECRETS-RELEASED, scope=function)
TEST(ClientSecureChannelShellTests, AnOrderlyCloseScrubsTheKeyAgreementSecrets)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_open_on_strand(42);
  std::shared_ptr<ua::SecureChannelContext> context;
  STA::on_strand(*setup.impl,
    [&](auto& g)
    {
      context = g.context();
      context->keyAgreementIkm = ByteString(48, uint8_t{0x5a});
      context->localEphemeralPrivateKey = ByteString(32, uint8_t{0xa5});
    });
  ASSERT_NE(context, nullptr);

  std::promise<StatusCode> closed;
  auto closedFuture = closed.get_future();
  setup.impl->close([&closed](VoidResult result) { closed.set_value(result.status_code()); });
  ASSERT_EQ(closedFuture.wait_for(test_utils::scaled(2000ms)), std::future_status::ready);
  EXPECT_TRUE(closedFuture.get().is_good());
  STA::strand_barrier(*setup.impl);

  bool released = false;
  STA::on_strand(*setup.impl, [&](auto& g) { released = g.context() == nullptr; });
  EXPECT_TRUE(released);
  EXPECT_TRUE(context->keyAgreementIkm.empty());
  EXPECT_TRUE(context->localEphemeralPrivateKey.empty());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A create_session posted onto the strand AFTER the close-drain (which resets mContext + mSecurityPolicy to
// null) must fast-fail with a source-tagged Bad_SecureChannelClosed - not dereference the nulled mContext.
// This is the disconnect-then-create-session ordering the reconnect / session machinery can hit (e.g. a
// renewal-validation failure disconnects the channel, then a queued create-session fires); before the guard
// it was a SIGSEGV at `self.mContext->localCertificate`. [neg: unguarded deref of a nulled context]
TEST(ClientSecureChannelShellTests, CreateSessionOnClosedChannelFailsFastNoCrash)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Reproduce the post-close-drain state on the strand: Closed + mContext nulled exactly as
  // close_channel_async does. (mSecurityPolicy is nulled by the same drain; nulling mContext alone already
  // reproduces the crash - the deref at line ~1897 - and exercises the guard, which fires on either being
  // null.)
  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.set_channel_closed();
      g.context().reset();
    });

  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  StatusCode status{Status::BadInternalError};
  std::shared_ptr<const ua::ErrorDetail> detail;

  setup.impl->create_session(SecureChannel::CreateSessionConfig{},
    [&](auto result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        status = result.status_code();
        detail = result.shared_detail();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return fired; }))
      << "create_session on a closed channel must complete (fast-fail), not crash or hang";
  }

  EXPECT_EQ(status, StatusCode{Status::BadSecureChannelClosed});
  ASSERT_NE(detail, nullptr) << "the closed-channel rejection must carry a source-tagged ErrorDetail";
  EXPECT_EQ(detail->source, "client.tier0.secure_channel.create_session.channel_closed");
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Session carries user identity and authorization, so create_session is refused on a channel with no
// security unless the application opted in - the client-side mirror of the Server's
// `allowInsecureEndpoints` gate on exposing a None endpoint. Enforced at CreateSession rather than at
// channel open, so session-less discovery over a None channel is unaffected.
// [neg: an unsecured Session created with no opt-in]
TEST(ClientSecureChannelShellTests, CreateSessionOnUnsecuredChannelIsRejectedByDefault)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());  // default Config: policy/mode None
  STA::on_strand(*setup.impl, [](auto& g) { g.set_channel_open(); });

  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  StatusCode status{Status::BadInternalError};
  std::shared_ptr<const ua::ErrorDetail> detail;

  setup.impl->create_session(SecureChannel::CreateSessionConfig{},
    [&](auto result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        status = result.status_code();
        detail = result.shared_detail();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return fired; })) << "create_session must complete";
  }

  EXPECT_EQ(status, StatusCode{Status::BadSecurityModeRejected});
  ASSERT_NE(detail, nullptr) << "the rejection must carry a source-tagged ErrorDetail";
  EXPECT_EQ(detail->source, "client.tier0.secure_channel.create_session.insecure_channel");
  // The diagnostic must name the setting to change, or the caller cannot act on it.
  EXPECT_NE(detail->summary.find("allowInsecureEndpoints"), std::string::npos) << "was: " << detail->summary;

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// With the opt-in set the gate must NOT fire. This is an absence test, and it is sound because its
// negative control above completes within milliseconds: the gate rejects on the strand, before any I/O.
// So if no rejection has arrived after the same window, the gate did not fire. The request itself cannot
// complete here - past the gate it awaits a CreateSession response, and the fake deps carry no transport -
// which is why this asserts the absence of the rejection rather than a successful Session.
TEST(ClientSecureChannelShellTests, CreateSessionOnUnsecuredChannelIsAllowedWhenOptedIn)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.deps->allow_insecure_endpoints(true);
  STA::on_strand(*setup.impl, [](auto& g) { g.set_channel_open(); });

  std::mutex mx;
  bool fired{false};
  StatusCode status{Status::BadInternalError};
  std::shared_ptr<const ua::ErrorDetail> detail;

  setup.impl->create_session(SecureChannel::CreateSessionConfig{},
    [&](auto result)
    {
      std::lock_guard<std::mutex> lk(mx);
      fired = true;
      status = result.status_code();
      detail = result.shared_detail();
    });

  std::this_thread::sleep_for(300ms);

  {
    std::lock_guard<std::mutex> lk(mx);
    if (fired)
    {
      EXPECT_NE(status, StatusCode{Status::BadSecurityModeRejected})
        << "the insecure-channel gate must not fire once the application has opted in";
      if (detail)
      {
        EXPECT_NE(detail->source, "client.tier0.secure_channel.create_session.insecure_channel");
      }
    }
  }

  // Getting past the gate leaves a CreateSession awaiting a response that the transport-less fake deps can
  // never deliver. The absence assertion above is the evidence that the gate let it through; now drive the
  // normal channel-close path so that request is cancelled and its ownership is released before teardown.
  std::promise<VoidResult> closed;
  auto closeFuture = closed.get_future();
  setup.impl->close([&closed](VoidResult result) { closed.set_value(std::move(result)); });
  ASSERT_EQ(closeFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(closeFuture.get().is_good());

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, CloseWhenAlreadyClosedDoesNotCrash)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Force channel to Closed state first.
  setup.set_channel_closed_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.impl->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  // Close callback must fire promptly for already-closed channel.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return closeFired; }));
  }

  EXPECT_TRUE(closeStatus.is_good());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Transport error propagation ---

TEST(ClientSecureChannelShellTests, TransportErrorFailsPendingRequests)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Force channel open and register a pending request.
  setup.set_channel_open_on_strand(42);

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.impl->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
      }
      cv.notify_one();
    });

  // Use strand_barrier to ensure the send has been processed,
  // then inject the error on the strand.
  STA::strand_barrier(*setup.impl);

  STA::on_strand(*setup.impl,
    [](auto& g)
    { g.receive_message_chunk(StatusCode{Status::BadConnectionClosed}, std::vector<ua::byte>{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_TRUE(resultStatus.is_bad());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- ErrorDetail propagation tests ---

TEST(ClientSecureChannelShellTests, TransportErrorPropagatesErrorDetailToPendingRequests)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Force channel open and register a pending request.
  setup.set_channel_open_on_strand(42);

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  shared_ptr<const ErrorDetail> receivedDetail;

  setup.impl->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        receivedDetail = r.shared_detail();
      }
      cv.notify_one();
    });

  // Use strand_barrier to ensure the send has been processed.
  STA::strand_barrier(*setup.impl);

  // Simulate transport error on the strand.
  STA::on_strand(*setup.impl,
    [](auto& g)
    { g.receive_message_chunk(StatusCode{Status::BadConnectionClosed}, std::vector<ua::byte>{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  // The receive_message_chunk error path creates a "ChunkReceiveError" ErrorDetail.
  ASSERT_NE(receivedDetail, nullptr);
  EXPECT_EQ(receivedDetail->code, "ChunkReceiveError");
  EXPECT_FALSE(receivedDetail->summary.empty());
  EXPECT_EQ(receivedDetail->source, "client::SecureChannel");
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, TransportErrorPropagatesErrorDetailToErrorCallback)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool errorFired{false};
  shared_ptr<const ErrorDetail> receivedDetail;

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,  // No connection (test mode)
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        errorFired = true;
        receivedDetail = result.shared_detail();
      }
      cv.notify_one();
    });

  // Force channel open on the strand so the transport error triggers ChannelError action.
  // set_channel_open() also clears mOnOpened so handle_channel_error routes to mOnError.
  STA::on_strand(*impl, [](auto& g) { g.set_channel_open(); });

  // Simulate transport error on the strand.
  STA::on_strand(*impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return errorFired; }));
  }

  ASSERT_NE(receivedDetail, nullptr);
  EXPECT_EQ(receivedDetail->code, "ChannelError");
  EXPECT_EQ(receivedDetail->source, "client::SecureChannel");
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The hold-and-release mechanics behind ClientSecureChannelInboundDecodeTests.
// AResponseReceivedBeforeTheTransportFailsIsDelivered: a transport failure that arrives while the incoming
// drain is busy is held, the channel stays open, and the failure is reported once when the drain empties;
// with nothing pending it is reported at once.
TEST(ClientSecureChannelShellTests, ATransportFailureWaitsForAChunkStillBeingDecoded)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());
  std::atomic<int> errors{0};
  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [&](VoidResult) { errors.fetch_add(1); });
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.set_channel_open();
      g.incoming_drain_scheduled() = true;  // a received chunk is being decoded
      g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{});
    });
  STA::on_strand(*impl,
    [](auto& g)
    {
      EXPECT_EQ(g.channel_state(), SecureChannelImpl::ChannelState::Open)
        << "the channel stays open while the received chunk is processed";
    });
  EXPECT_EQ(errors.load(), 0) << "the failure is held behind the chunk";

  // The decode finishes and the drain finds nothing more: the failure is reported now, once.
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.incoming_drain_scheduled() = false;
      g.drain_incoming();
    });
  STA::on_strand(
    *impl, [](auto& g) { EXPECT_EQ(g.channel_state(), SecureChannelImpl::ChannelState::Closed); });
  for (int i = 0; i < 50 && errors.load() == 0; ++i)
    std::this_thread::sleep_for(10ms);
  EXPECT_EQ(errors.load(), 1);

  // Control: with nothing received pending, a failure is reported at once.
  std::atomic<int> immediate{0};
  auto other = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [&](VoidResult) { immediate.fetch_add(1); });
  STA::on_strand(*other,
    [](auto& g)
    {
      g.set_channel_open();
      g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{});
    });
  for (int i = 0; i < 50 && immediate.load() == 0; ++i)
    std::this_thread::sleep_for(10ms);
  EXPECT_EQ(immediate.load(), 1);

  impl.reset();
  other.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, TransportErrorPropagatesErrorDetailToOpenedCallback)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::Good};
  shared_ptr<const ErrorDetail> receivedDetail;

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,  // No connection (test mode)
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
        receivedDetail = result.shared_detail();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  // Channel is in Idle state (never opened). A transport error should still fire
  // the onOpened callback since setup_and_open() hasn't completed.
  // Simulate transport error on the strand.
  STA::on_strand(
    *impl, [](auto& g) { g.receive_transport_error(StatusCode{Status::BadTimeout}, std::string_view{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_TRUE(openedStatus.is_bad());
  ASSERT_NE(receivedDetail, nullptr);
  EXPECT_EQ(receivedDetail->code, "ChannelError");
  EXPECT_EQ(receivedDetail->source, "client::SecureChannel");
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Open Flow tests
// ============================================================================

TEST(ClientSecureChannelShellTests, CreateWithNullConnectionStaysIdle)
{
  // When created with no connection, initialise() returns early and the channel stays Idle.
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  SecureChannelImpl::ChannelState state{};
  state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Idle);
  EXPECT_FALSE(setup.impl->is_open());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, GoodOPNResponseOpensChannel)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::BadInternalError};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  // Set channel to Opening state (simulating OPN request sent).
  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  // Inject a good OPN response on the strand.
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{42},
        uint32_t{100},
        std::chrono::milliseconds{60000},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_TRUE(openedStatus.is_good());
  EXPECT_TRUE(impl->is_open());
  EXPECT_EQ(impl->secure_channel_id(), 42u);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_token_id(); }), 100u);
  EXPECT_EQ(
    STA::on_strand(*impl, [](auto& g) { return g.revised_lifetime(); }), std::chrono::milliseconds{60000});
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The OpenSecureChannel response's Good subcode reaches the opener: the channel opens and the open callback
// receives the server's code rather than a plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientSecureChannelShellTests, OPNResponseGoodSubcodeReachesTheOpener)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    boost::asio::thread_pool tp;
    auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

    std::mutex mx;
    std::condition_variable cv;
    bool openedFired{false};
    StatusCode openedStatus{Status::BadInternalError};

    auto impl = SecureChannelImpl::create(
      deps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      SecureChannelImpl::Config{},
      [&](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          openedFired = true;
          openedStatus = result.status_code();
        }
        cv.notify_one();
      },
      [](VoidResult) {});

    STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });
    STA::on_strand(*impl,
      [serviceStatus](auto& g)
      {
        g.handle_opn_response(StatusCode{serviceStatus},
          uint32_t{42},
          uint32_t{100},
          std::chrono::milliseconds{60000},
          ByteString{},
          nullptr);
      });

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
    }

    EXPECT_TRUE(impl->is_open());
    EXPECT_EQ(openedStatus.value(), StatusCode{serviceStatus}.value());
    EXPECT_EQ(impl->secure_channel_id(), 42u);
    EXPECT_EQ(STA::on_strand(*impl, [](auto& guard) { return guard.channel_token_id(); }), 100u);
    EXPECT_EQ(STA::on_strand(*impl, [](auto& guard) { return guard.revised_lifetime(); }),
      std::chrono::milliseconds{60000});
    impl.reset();
    deps.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

TEST(ClientSecureChannelShellTests, GoodOPNResponseZeroLifetimeNoRenewalTimer)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{0},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_TRUE(impl->is_open());
  // With lifetime=0, no renewal timer should be scheduled.
  // The renewal timer should be unset (default-constructed / empty).
  auto timerSet = STA::on_strand(*impl, [](auto& g) { return static_cast<bool>(g.renewal_timer()); });
  EXPECT_FALSE(timerSet);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, BadOPNResponseWhileOpeningEmitsErrorAndCloseTransport)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::BadSecurityChecksFailed},
        uint32_t{0},
        uint32_t{0},
        std::chrono::milliseconds{0},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_EQ(openedStatus, Status::BadSecurityChecksFailed);
  EXPECT_FALSE(impl->is_open());
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, SendRequestWhileOpeningReturnsBadSecureChannelClosed)
{
  // Sending a request while the channel is in Opening state (not yet Open) should fail.
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Channel is in Idle state (no connection). Set to Opening.
  setup.set_channel_opening_on_strand();

  // Attempt to send a request while Opening (not Open) should fail.
  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.impl->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_EQ(resultStatus, Status::BadSecureChannelClosed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Token Renewal tests
// ============================================================================

TEST(ClientSecureChannelShellTests, TokenRenewalDueTransitionsToRenewing)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(1);

  // Trigger renewal on the strand.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });

  // After renewal, state should be Renewing.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Renewing);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-SC-007-THE-RENEWAL-DELAY-HAS-A-FLOOR
// Three quarters of the revised lifetime, never below the floor: a server revising the lifetime down to a
// few milliseconds would otherwise have the client renew continuously.
TEST(ClientSecureChannelShellTests, RenewalDelayHasAFloor)
{
  using namespace std::chrono_literals;
  EXPECT_EQ(STA::renewal_delay(1ms), 500ms) << "a 1 ms lifetime renews at the floor, not every 0 ms";
  EXPECT_EQ(STA::renewal_delay(400ms), 500ms);
  EXPECT_EQ(STA::renewal_delay(1000ms), 750ms) << "a 1 s lifetime keeps its three-quarters schedule";
  EXPECT_EQ(STA::renewal_delay(600000ms), 450000ms);
}

// @verifies AC-CL-SC-008-AN-OPN-RESPONSE-ANSWERS-THE-OUTSTANDING-REQUEST-FOR-THIS-CHANNEL
// A renewal response under a request id other than the outstanding OpenSecureChannel request's installs
// nothing: the channel is closed.
TEST(ClientSecureChannelShellTests, RenewResponseUnderAnotherRequestIdClosesTheChannel)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_open_on_strand(42);
  setup.set_channel_renewing_on_strand();
  STA::set_opn_request_id(*setup.impl, 7u);

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response_for_request(8u,
        ua::StatusCode{ua::Status::Good},
        42u,
        2u,
        std::chrono::milliseconds{60000},
        ua::ByteString(std::vector<std::uint8_t>(32, 0x5A)),
        nullptr);
    });

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  ASSERT_TRUE(setup.sync->wait_error()) << "the refusal is reported through the channel-error callback";
  EXPECT_EQ(setup.sync->errorStatus.as_status(), ua::Status::BadSecurityChecksFailed);
  EXPECT_FALSE(setup.impl->is_open());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-SC-008-AN-OPN-RESPONSE-ANSWERS-THE-OUTSTANDING-REQUEST-FOR-THIS-CHANNEL
// A renewal response naming another SecureChannelId would have the client sign under a token issued to a
// different channel: the channel is closed.
TEST(ClientSecureChannelShellTests, RenewResponseNamingAnotherChannelIdClosesTheChannel)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_open_on_strand(42);
  setup.set_channel_renewing_on_strand();
  STA::set_opn_request_id(*setup.impl, 7u);

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response_for_request(7u,
        ua::StatusCode{ua::Status::Good},
        43u,
        2u,
        std::chrono::milliseconds{60000},
        ua::ByteString(std::vector<std::uint8_t>(32, 0x5A)),
        nullptr);
    });

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  ASSERT_TRUE(setup.sync->wait_error()) << "the refusal is reported through the channel-error callback";
  EXPECT_EQ(setup.sync->errorStatus.as_status(), ua::Status::BadSecureChannelIdInvalid);
  EXPECT_FALSE(setup.impl->is_open());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-SC-008-AN-OPN-RESPONSE-ANSWERS-THE-OUTSTANDING-REQUEST-FOR-THIS-CHANNEL
// The control: the renewal response under the outstanding request id, for this channel, is not refused
// by the correlation checks (the channel is not closed by them).
TEST(ClientSecureChannelShellTests, RenewResponseForThisChannelUnderItsRequestIdIsNotRefused)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_open_on_strand(42);
  setup.set_channel_renewing_on_strand();
  STA::set_opn_request_id(*setup.impl, 7u);

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response_for_request(7u,
        ua::StatusCode{ua::Status::Good},
        42u,
        2u,
        std::chrono::milliseconds{60000},
        ua::ByteString(std::vector<std::uint8_t>(32, 0x5A)),
        nullptr);
    });

  EXPECT_NE(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-SC-008-AN-OPN-RESPONSE-ANSWERS-THE-OUTSTANDING-REQUEST-FOR-THIS-CHANNEL
// The Issue path: while Opening, a response under a request id that is not the OPN request's is refused.
TEST(ClientSecureChannelShellTests, OpnResponseUnderAnotherRequestIdWhileOpeningClosesTheChannel)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_opening_on_strand();
  STA::set_opn_request_id(*setup.impl, 1u);

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response_for_request(2u,
        ua::StatusCode{ua::Status::Good},
        42u,
        1u,
        std::chrono::milliseconds{60000},
        ua::ByteString(std::vector<std::uint8_t>(32, 0x5A)),
        nullptr);
    });

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  ASSERT_TRUE(setup.sync->wait_opened()) << "while Opening, the refusal is reported to the open callback";
  EXPECT_EQ(setup.sync->openedStatus.as_status(), ua::Status::BadSecurityChecksFailed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-SC-008-AN-OPN-RESPONSE-ANSWERS-THE-OUTSTANDING-REQUEST-FOR-THIS-CHANNEL
// The Issue-path control: the response under the outstanding request id is not refused by the correlation
// checks (no channel-error callback fires, the channel is not Closed).
TEST(ClientSecureChannelShellTests, OpnResponseUnderTheOutstandingRequestIdWhileOpeningIsNotRefused)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());
  setup.set_channel_opening_on_strand();
  STA::set_opn_request_id(*setup.impl, 1u);

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response_for_request(1u,
        ua::StatusCode{ua::Status::Good},
        42u,
        1u,
        std::chrono::milliseconds{60000},
        ua::ByteString(std::vector<std::uint8_t>(32, 0x5A)),
        nullptr);
    });

  EXPECT_NE(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  EXPECT_FALSE(setup.sync->wait_error(std::chrono::milliseconds{100}));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, TokenRenewalDueIgnoredWhenNotOpen)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Set to Opening (not Open).
  setup.set_channel_opening_on_strand();

  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });

  // State should still be Opening.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Opening);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, GoodOPNResponseWhileRenewingEmitsChannelRenewed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Set up open channel then move to Renewing.
  setup.set_channel_open_on_strand(1);
  setup.set_channel_renewing_on_strand();

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{200},
        std::chrono::milliseconds{120000},
        ByteString{},
        nullptr);
    });

  // Use strand barrier to ensure the coroutine completes.
  STA::strand_barrier(*setup.impl);

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Open);
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), 200u);
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.revised_lifetime(); }),
    std::chrono::milliseconds{120000});
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, BadOPNResponseWhileRenewingClosesChannel)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool errorFired{false};
  StatusCode errorStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        errorFired = true;
        errorStatus = result.status_code();
      }
      cv.notify_one();
    });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.set_channel_open();
      g.set_channel_renewing();
    });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::BadInternalError},
        uint32_t{0},
        uint32_t{0},
        std::chrono::milliseconds{0},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return errorFired; }));
  }

  EXPECT_EQ(errorStatus, Status::BadInternalError);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Transport Error per State tests
// ============================================================================

TEST(ClientSecureChannelShellTests, TransportErrorWhileOpeningClosesChannel)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_EQ(openedStatus, Status::BadConnectionClosed);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, TransportErrorWhileRenewingClosesChannel)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool errorFired{false};
  StatusCode errorStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        errorFired = true;
        errorStatus = result.status_code();
      }
      cv.notify_one();
    });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.set_channel_open();
      g.set_channel_renewing();
    });

  STA::on_strand(*impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return errorFired; }));
  }

  EXPECT_EQ(errorStatus, Status::BadConnectionClosed);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, TransportErrorWhileClosedIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Move to Closed state.
  setup.set_channel_opening_on_strand();
  setup.set_channel_closed_on_strand();

  STA::on_strand(*setup.impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });

  // Should still be Closed, no crash.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Close per State tests
// ============================================================================

TEST(ClientSecureChannelShellTests, CloseWhileOpenTearsDownToClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(42);

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.impl->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return closeFired; }));
  }

  EXPECT_TRUE(closeStatus.is_good());
  // Close fully tears down the channel - by the time the close callback fires,
  // the drain + transport-close waits have completed (or were skipped in test
  // mode with no connection) and the channel is in Closed state.
  EXPECT_FALSE(setup.impl->is_open());
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, CloseWhileRenewingTearsDownToClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(42);
  setup.set_channel_renewing_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.impl->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return closeFired; }));
  }

  EXPECT_TRUE(closeStatus.is_good());
  EXPECT_FALSE(setup.impl->is_open());
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, CloseWhileOpeningJustClosesTransport)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_opening_on_strand();

  setup.impl->close([](VoidResult) {});

  // Use strand barrier to ensure close has been processed.
  STA::strand_barrier(*setup.impl);

  // After close while Opening, state should transition to Closed.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, CloseWhileIdleCallsCallbackWithGood)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Channel is Idle (no connection, initialise returned early).
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Idle);

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.impl->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return closeFired; }));
  }

  EXPECT_TRUE(closeStatus.is_good());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, CloseWhileWaitingForEntropyClosesTransport)
{
  // In the new architecture, "WaitingForEntropy" is an implicit state within
  // setup_and_open(). Without a real crypto provider, we approximate by
  // setting the channel to Opening state and closing it.
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_opening_on_strand();

  setup.impl->close([](VoidResult) {});

  // Use strand barrier to ensure close has been processed.
  STA::strand_barrier(*setup.impl);

  // Close while in an intermediate (Opening) state should transition to Closed.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Spurious Response Handling tests
// ============================================================================

TEST(ClientSecureChannelShellTests, OPNResponseWhileClosedIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_closed_on_strand();

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{100},
        std::chrono::milliseconds{60000},
        ByteString{},
        nullptr);
    });

  // Channel should remain Closed.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  EXPECT_FALSE(setup.impl->is_open());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, OPNResponseWhileOpenIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(1);

  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{999},
        std::chrono::milliseconds{60000},
        ByteString{},
        nullptr);
    });

  // Token ID should be unchanged (set_channel_open does not set mChannelTokenId).
  // The original token ID from set_channel_open is 0 (only context is set).
  // Important: OPN response was ignored, so token should not change.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Open);
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), 0u);  // Unchanged.
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Nonce / Entropy tests
// ============================================================================

TEST(ClientSecureChannelShellTests, ServerNoncePropagatedOnOpen)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  ByteString serverNonce{std::vector<std::byte>{std::byte{0xAA}, std::byte{0xBB}}};

  auto nonceCopy = serverNonce;
  STA::on_strand(*impl,
    [nonce = std::move(nonceCopy)](auto& g) mutable
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        std::move(nonce),
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) -> ByteString { return g.server_nonce(); }), serverNonce);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, OpenUnauthenticatedEmptyNonce)
{
  // Unauthenticated channels send an empty nonce.
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Default is unauthenticated (mIsAuthenticated = false). Read on strand.
  bool authenticated{true};
  bool nonceEmpty{false};
  STA::on_strand(*setup.impl,
    [&authenticated, &nonceEmpty](auto& g)
    {
      authenticated = g.is_authenticated();
      nonceEmpty = g.last_client_nonce().empty();
    });
  EXPECT_FALSE(authenticated);
  EXPECT_TRUE(nonceEmpty);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, ServerNonceEmptyRejectedWhenAuthenticated)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.set_channel_opening();
      g.set_is_authenticated(true, 0);
    });

  // Empty server nonce - should be rejected for authenticated channels.
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_EQ(openedStatus, Status::BadNonceInvalid);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, ServerNonceTooShortRejectedWhenAuthenticated)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.set_channel_opening();
      g.set_is_authenticated(true, 0);
    });

  // Create a short nonce (16 bytes, less than required 32).
  ByteString shortNonce{std::vector<std::byte>(16, std::byte{0x42})};

  STA::on_strand(*impl,
    [nonce = std::move(shortNonce)](auto& g) mutable
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        std::move(nonce),
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_EQ(openedStatus, Status::BadNonceInvalid);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SC-015
// @relation(CL-SC-015, scope=function)
TEST(ClientSecureChannelShellTests, ServerNonceWrongLengthRejectedWhenAuthenticated)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.set_channel_opening();
      g.set_is_authenticated(true, 48);  // Expects 48-byte nonce.
    });

  // Provide 32-byte nonce (wrong length).
  ByteString wrongLenNonce{std::vector<std::byte>(32, std::byte{0x42})};

  STA::on_strand(*impl,
    [nonce = std::move(wrongLenNonce)](auto& g) mutable
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        std::move(nonce),
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_EQ(openedStatus, Status::BadNonceInvalid);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SC-016
// @relation(CL-SC-016, scope=function)
TEST(ClientSecureChannelShellTests, ServerNonceReusedOnRenewalRejected)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool errorFired{false};
  StatusCode errorStatus{Status::Good};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        errorFired = true;
        errorStatus = result.status_code();
      }
      cv.notify_one();
    });

  // Set up the channel as open with an authenticated policy and a known server nonce.
  ByteString serverNonce{std::vector<std::byte>(32, std::byte{0x42})};
  STA::on_strand(*impl,
    [&serverNonce](auto& g)
    {
      g.set_channel_open();
      g.set_is_authenticated(true, 0);
      g.set_server_nonce(serverNonce);
      g.set_channel_renewing();
    });

  auto nonceCopy = serverNonce;  // Same nonce as before - should be rejected.
  STA::on_strand(*impl,
    [nonce = std::move(nonceCopy)](auto& g) mutable
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{200},
        std::chrono::milliseconds{60000},
        std::move(nonce),
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return errorFired; }));
  }

  EXPECT_EQ(errorStatus, Status::BadNonceInvalid);
  EXPECT_EQ(STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, ServerNonceValidationSkippedWhenUnauthenticated)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};
  StatusCode openedStatus{Status::BadInternalError};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
        openedStatus = result.status_code();
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });
  // Unauthenticated (default).

  // Empty server nonce - should be OK for unauthenticated.
  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{1},
        std::chrono::milliseconds{60000},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_TRUE(openedStatus.is_good());
  EXPECT_EQ(
    STA::on_strand(*impl, [](auto& g) { return g.channel_state(); }), SecureChannelImpl::ChannelState::Open);
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, RenewalUnauthenticatedTransitionsToRenewing)
{
  // Unauthenticated renewal skips nonce generation and goes directly to Renewing.
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(1);
  // Default: unauthenticated (mIsAuthenticated = false).

  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });

  // Should be in Renewing state with an empty client nonce.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Renewing);
  EXPECT_TRUE(STA::on_strand(*setup.impl, [](auto& g) { return g.last_client_nonce().empty(); }));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelShellTests, RenewalThenGoodOPNResponseCompletesForUnauthenticated)
{
  // For unauthenticated channels, renewal produces an OPN Renew with empty nonce
  // and transitions to Renewing. We can then verify the good response path.
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(1);

  // First trigger renewal.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Renewing);

  // Now inject a good OPN response to complete renewal.
  STA::on_strand(*setup.impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{300},
        std::chrono::milliseconds{90000},
        ByteString{},
        nullptr);
    });

  // Use strand barrier to ensure the coroutine completes.
  STA::strand_barrier(*setup.impl);

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Open);
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), 300u);
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.revised_lifetime(); }),
    std::chrono::milliseconds{90000});
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Test #42: Renewal timer scheduled for non-zero lifetime
// =============================================================================

TEST(ClientSecureChannelShellTests, RenewalScheduledBeforeRevisedLifetimeExpires)
{
  // Spec: Part 4, 5.5.2 - Client shall renew before revisedLifetime expires.
  // Open channel with non-zero lifetime, verify renewal timer is set.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{100},
        std::chrono::milliseconds{10000},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_TRUE(impl->is_open());
  auto timerSet = STA::on_strand(*impl, [](auto& g) { return static_cast<bool>(g.renewal_timer()); });
  EXPECT_TRUE(timerSet) << "Renewal timer must be set for non-zero lifetime";
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Test #43: Renewal timer scheduled even with SecurityMode None (unauthenticated)
// =============================================================================

// @verifies CL-SC-007, CL-UASC-016
// @relation(CL-SC-007, CL-UASC-016, scope=function)
TEST(ClientSecureChannelShellTests, RenewalScheduledEvenWhenSecurityModeNone)
{
  // Spec: Part 4, 5.5.2 - Renewal is required regardless of security mode.
  // Open unauthenticated channel with non-zero lifetime, verify renewal timer is set.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool openedFired{false};

  auto impl = SecureChannelImpl::create(
    deps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        openedFired = true;
      }
      cv.notify_one();
    },
    [](VoidResult) {});

  // Default: unauthenticated (is_authenticated = false).
  EXPECT_FALSE(STA::on_strand(*impl, [](auto& g) { return g.is_authenticated(); }));

  STA::on_strand(*impl, [](auto& g) { g.set_channel_opening(); });

  STA::on_strand(*impl,
    [](auto& g)
    {
      g.handle_opn_response(StatusCode{Status::Good},
        uint32_t{1},
        uint32_t{100},
        std::chrono::milliseconds{30000},
        ByteString{},
        nullptr);
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return openedFired; }));
  }

  EXPECT_TRUE(impl->is_open());
  auto timerSet = STA::on_strand(*impl, [](auto& g) { return static_cast<bool>(g.renewal_timer()); });
  EXPECT_TRUE(timerSet) << "Renewal timer must be set even for unauthenticated channels";
  impl.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// LDS registration (RegisterServer / RegisterServer2) - session-less keystone
//
// register_server*_async route through the bare-channel send_request path
// (the file-local typed_request_async template) and must NOT require an Active
// session. These tests build a public SecureChannel directly over a
// SecureChannelImpl that has NO connection and NO session whatsoever - the only
// way the request can be dispatched is via the channel's own pending-request
// map. A test that secretly went through a session would have nothing to route
// through here and could never observe the pending request, so the
// pending-map assertion is the discriminating check.
// =============================================================================

namespace
{

/// On-strand: deliver a single response Structure to the one pending request,
/// mimicking what receive_message_chunk does after decode. The bare channel
/// has exactly one pending request (the register call under test). Returns the
/// number of pending requests observed BEFORE delivery (must be 1 for the
/// session-less path to be proven).
size_t deliver_single_pending_response(SecureChannelImpl& impl, std::shared_ptr<ua::Structure> response)
{
  return STA::on_strand(impl,
    [response = std::move(response)](auto& g) mutable -> size_t
    {
      auto& pending = g.pending_requests();
      const size_t count = pending.size();
      if (count == 1)
      {
        auto callback = std::move(pending.begin()->second);
        pending.erase(pending.begin());
        callback(SecureChannelImpl::ServiceResponseResult{std::move(response)});
      }
      return count;
    });
}

}  // namespace

// @relation(AC-SVR-DISC-LDS-004-REGISTERSERVER2-SUPPORTED, scope=function)

TEST(ClientSecureChannelLdsTests, RegisterServer2SucceedsOverSessionLessChannel)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  // Bare channel: no connection, no session. Force it Open.
  setup.set_channel_open_on_strand(42);
  std::optional<SecureChannel> channel{STA::make_channel(setup.impl)};

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::BadInternalError};
  bool valueHeld{false};

  channel->register_server2_async(ua::RegisterServer2Request{},
    [&](SecureChannel::RegisterServer2ResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
        valueHeld = static_cast<bool>(r);
      }
      cv.notify_one();
    });

  // The request must land in the bare channel's pending map - proof it bypassed
  // any session (there is none). Deliver a Good RegisterServer2Response.
  STA::strand_barrier(*setup.impl);
  auto response = std::make_shared<ua::RegisterServer2Response>();
  response->response_header().service_result() = StatusCode{Status::Good};
  const size_t pendingBeforeDelivery = deliver_single_pending_response(*setup.impl, std::move(response));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_EQ(pendingBeforeDelivery, 1u)
    << "RegisterServer2 must dispatch through the bare channel, not a session";
  EXPECT_TRUE(resultStatus.is_good());
  EXPECT_TRUE(valueHeld);
  // Drop the public-channel handle (holds an extra impl ref) before drain so the
  // impl destructor cancels its renewal timer and the pool can join.
  channel.reset();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-DISC-LDS-004-REGISTERSERVER2-SUPPORTED, scope=function)

TEST(ClientSecureChannelLdsTests, RegisterServerV1SucceedsOverSessionLessChannel)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(42);
  std::optional<SecureChannel> channel{STA::make_channel(setup.impl)};

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::BadInternalError};
  bool valueHeld{false};

  channel->register_server_async(ua::RegisterServerRequest{},
    [&](SecureChannel::RegisterServerResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
        valueHeld = static_cast<bool>(r);
      }
      cv.notify_one();
    });

  STA::strand_barrier(*setup.impl);
  auto response = std::make_shared<ua::RegisterServerResponse>();
  response->response_header().service_result() = StatusCode{Status::Good};
  const size_t pendingBeforeDelivery = deliver_single_pending_response(*setup.impl, std::move(response));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_EQ(pendingBeforeDelivery, 1u)
    << "RegisterServer (v1) must dispatch through the bare channel, not a session";
  EXPECT_TRUE(resultStatus.is_good());
  EXPECT_TRUE(valueHeld);
  channel.reset();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelLdsTests, RegisterServer2TransportErrorSurfacesErrorDetailThroughCallback)
{
  boost::asio::thread_pool tp;
  auto setup = TestSecureChannelSetup::create(tp.get_executor());

  setup.set_channel_open_on_strand(42);
  auto channel = STA::make_channel(setup.impl);

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};
  shared_ptr<const ErrorDetail> receivedDetail;

  channel.register_server2_async(ua::RegisterServer2Request{},
    [&](SecureChannel::RegisterServer2ResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
        receivedDetail = r.shared_detail();
      }
      cv.notify_one();
    });

  // Fail the in-flight request via a transport error on the strand. The error
  // (with ErrorDetail) must surface through the register callback as a bad Result.
  STA::strand_barrier(*setup.impl);
  STA::on_strand(*setup.impl,
    [](auto& g)
    { g.receive_message_chunk(StatusCode{Status::BadConnectionClosed}, std::vector<ua::byte>{}); });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_TRUE(resultStatus.is_bad());
  ASSERT_NE(receivedDetail, nullptr) << "ErrorDetail must propagate to the register callback";
  EXPECT_FALSE(receivedDetail->summary.empty());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSecureChannelLdsTests, TryRegisterServer2SyncReturnsErrorWithoutThrowOnNullImpl)
{
  // A SecureChannel built over a null impl exercises the try_*_sync error path
  // without needing a live transport: typed_request_async short-circuits to
  // BadInvalidState. try_*_sync must return that as a Result and never throw.
  auto channel = STA::make_channel(nullptr);

  SecureChannel::RegisterServer2ResponseResult result =
    channel.try_register_server2_sync(ua::RegisterServer2Request{});

  EXPECT_TRUE(result.is_bad());
  EXPECT_FALSE(static_cast<bool>(result));
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadInvalidState}.value());
}

TEST(ClientSecureChannelLdsTests, TryRegisterServerSyncReturnsErrorWithoutThrowOnNullImpl)
{
  auto channel = STA::make_channel(nullptr);

  SecureChannel::RegisterServerResponseResult result =
    channel.try_register_server_sync(ua::RegisterServerRequest{});

  EXPECT_TRUE(result.is_bad());
  EXPECT_FALSE(static_cast<bool>(result));
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadInvalidState}.value());
}

TEST(ClientSecureChannelLdsTests, RegisterServer2SyncThrowsUaExceptionOnError)
{
  auto channel = STA::make_channel(nullptr);

  EXPECT_THROW(channel.register_server2_sync(ua::RegisterServer2Request{}), ua::UaException);
}

TEST(ClientSecureChannelLdsTests, RegisterServerSyncThrowsUaExceptionOnError)
{
  auto channel = STA::make_channel(nullptr);

  EXPECT_THROW(channel.register_server_sync(ua::RegisterServerRequest{}), ua::UaException);
}

// =============================================================================
// Test #80: Client abort reports error immediately (not yet implemented)
// =============================================================================

TEST(ClientSecureChannelShellTests, DISABLED_ClientAbortReportsErrorImmediately)
{
  // Spec: Part 6, 6.7.3 - Client shall report error without waiting for response.
  // When a client-side encoding error occurs mid-message, the client should send an
  // abort chunk and report the error to the application immediately.
  // Requires encoding-error injection infrastructure to force an error mid-chunk.
  // TODO: Add encoding-error injection, then assert error callback fires immediately.
  FAIL() << "Encoding-error injection infrastructure not yet available";
}

// Test #83 (CloseWhileNotOpenDoesNotSendCLO) deleted - duplicate of CloseWhileIdleCallsCallbackWithGood.

// ============================================================================
// CL-UASC-020 - a client-side message ENCODE failure is reported to the
// application immediately, without waiting for (or consuming) any server
// response.
//
// The real path is on_message_encoded(bad) -> handle_unexpected_exception ->
// close_transport, which synchronously fails the opener sink / pending requests
// with the encode-error StatusCode. drain_outgoing only hands a message to
// SecurityPolicy::encode_message_async when the channel has a NON-NULL
// connection (a null connection short-circuits both initialise() and
// drain_outgoing), so - unlike the null-connection cases above - these tests
// wire a real client ConnectionProtocol over a FakeTransportConnection (HEL/ACK
// handshake) and override the SecurityPolicy with FakeAsyncSecurityPolicy via
// Config::securityPolicyFactory, so the parked OPN/request encode can be fired
// with a BAD VoidResult on demand. No server OPN response is ever delivered.
// ============================================================================

namespace
{

using ua::test_helpers::FakeAsyncSecurityPolicy;
using ua::test_helpers::FakeConnectionProtocolDeps;
using ua::test_helpers::FakeTransportConnection;

/// Build a minimal ACK frame so the fake transport can complete the HEL/ACK handshake.
std::vector<byte> build_ack_frame(uint32_t recvBuf, uint32_t sendBuf, uint32_t maxMsg, uint32_t maxChunks)
{
  memory_stream_device::Dynamic streamDevice{connection_protocol::acknowledgeSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'A'});
  enc.encode(limit, uint8_t{'C'});
  enc.encode(limit, uint8_t{'K'});
  enc.encode(limit, uint8_t{'F'});
  enc.encode(limit, uint32_t{connection_protocol::acknowledgeSize});
  enc.encode(limit, uint32_t{0});  // protocolVersion
  enc.encode(limit, recvBuf);
  enc.encode(limit, sendBuf);
  enc.encode(limit, maxMsg);
  enc.encode(limit, maxChunks);

  auto out = streamDevice.move_storage_out();
  out.resize(connection_protocol::acknowledgeSize);
  return out;
}

/// A completed (HEL/ACK-handshaked) client ConnectionProtocol over a fake transport. A
/// SecureChannelImpl created with this connection actually runs start_open -> send_message_internal ->
/// drain_outgoing -> encode_message_async (which a null connection would short-circuit).
struct WiredClientConnection
{
  std::shared_ptr<FakeTransportConnection> transport;
  std::shared_ptr<FakeConnectionProtocolDeps> cpDeps;
  std::shared_ptr<ConnectionProtocol> connection;
  connection_protocol::NegotiatedLimits negotiatedLimits;
};

WiredClientConnection make_wired_client_connection(boost::asio::any_io_executor ex)
{
  struct HandshakeSync
  {
    std::mutex mx;
    std::condition_variable cv;
    bool complete{false};
    StatusCode status{Status::Good};
    connection_protocol::NegotiatedLimits negotiated;
  };

  WiredClientConnection wired;
  wired.transport = std::make_shared<FakeTransportConnection>();
  wired.cpDeps = std::make_shared<FakeConnectionProtocolDeps>(ex);
  wired.transport->enqueue_hello_message(build_ack_frame(65536, 65536, 0, 0));

  auto sync = std::make_shared<HandshakeSync>();
  wired.connection = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    wired.cpDeps,
    wired.transport,
    false,
    60s,
    [sync](StatusCode st,
      std::shared_ptr<ConnectionProtocol>,
      connection_protocol::NegotiatedLimits neg,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(sync->mx);
        sync->complete = true;
        sync->status = st;
        sync->negotiated = neg;
      }
      sync->cv.notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) {},
    "opc.tcp://localhost:4840");

  {
    std::unique_lock<std::mutex> lk(sync->mx);
    EXPECT_TRUE(sync->cv.wait_for(lk, 2s, [&]() { return sync->complete; }))
      << "ConnectionProtocol HEL/ACK handshake did not complete";
  }
  EXPECT_TRUE(sync->status.is_good());
  wired.negotiatedLimits = sync->negotiated;
  return wired;
}

}  // namespace

// @verifies CL-UASC-020
// @relation(CL-UASC-020, scope=function)
TEST(ClientSecureChannelShellTests, EncodeErrorDuringOpenFiresOpenerImmediatelyWithoutServerResponse)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());
  auto fake = FakeAsyncSecurityPolicy::create();
  auto wired = make_wired_client_connection(tp.get_executor());

  auto sync = std::make_shared<CallbackSync>();
  auto syncPtr = sync;

  SecureChannelImpl::Config config;
  config.securityMode = ua::MessageSecurityMode::None;
  config.securityPolicyId = ua::SecurityPolicyId::None;
  config.securityPolicyFactory = [fake](ua::SecurityPolicyId)
  {
    return fake;
  };

  auto impl = SecureChannelImpl::create(
    deps,
    wired.connection,
    wired.negotiatedLimits,
    config,
    [syncPtr](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->opened = true;
        syncPtr->openedStatus = result.status_code();
      }
      syncPtr->cv.notify_one();
    },
    [syncPtr](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->errorOccurred = true;
        syncPtr->errorStatus = result.status_code();
      }
      syncPtr->cv.notify_one();
    });

  // The REAL start_open (unauthenticated None path) hands exactly one encode - the client-sent OPN
  // Issue request - to the fake policy, which parks it. Drain the strand to reach that point.
  STA::strand_barrier(*impl);
  ASSERT_EQ(fake->pending_encode_message_count(), 1u)
    << "the client OPN request must be handed to SecurityPolicy::encode_message_async";

  // Fire the parked encode BAD. No server OPN response is (or ever will be) delivered.
  auto detail = std::shared_ptr<const ErrorDetail>(
    ua::make_error_detail("EncodeFailed", "forced client encode failure", "test"));
  fake->fail_pending_encode_message(0, StatusCode{Status::BadEncodingError}, detail);

  // The opener sink must fire well within the 10s OPN/service timeout (latency bound) with EXACTLY the
  // injected encode error (status bound). Together these falsify: swallowing the error (never fires),
  // waiting for a server reply or the OPN deadline (BadTimeout and/or only after 10s), and reporting Good.
  ASSERT_TRUE(sync->wait_opened(2s))
    << "encode failure must surface to the opener without waiting for a server response";
  EXPECT_EQ(sync->openedStatus, StatusCode{Status::BadEncodingError});
  EXPECT_FALSE(impl->is_open());

  impl.reset();
  wired.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-UASC-020
// @relation(CL-UASC-020, scope=function)
TEST(ClientSecureChannelShellTests, EncodeErrorOnRequestFailsPendingRequestImmediatelyWithoutServerResponse)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());
  auto fake = FakeAsyncSecurityPolicy::create();
  auto wired = make_wired_client_connection(tp.get_executor());

  SecureChannelImpl::Config config;
  config.securityMode = ua::MessageSecurityMode::None;
  config.securityPolicyId = ua::SecurityPolicyId::None;
  config.securityPolicyFactory = [fake](ua::SecurityPolicyId)
  {
    return fake;
  };

  auto impl = SecureChannelImpl::create(
    deps, wired.connection, wired.negotiatedLimits, config, [](VoidResult) {}, [](VoidResult) {});

  // Let the OPN encode park, complete it GOOD so the outgoing queue drains cleanly, then force the
  // channel Open so a service request can be dispatched through the pending-request map.
  STA::strand_barrier(*impl);
  ASSERT_EQ(fake->pending_encode_message_count(), 1u);
  fake->complete_pending_encode_message(0);
  STA::on_strand(*impl, [](auto& g) { g.set_channel_open(42); });

  // Send a service request; its encode parks in the fake.
  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};
  std::shared_ptr<const ErrorDetail> resultDetail;

  impl->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SecureChannelImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
        resultDetail = r.shared_detail();
      }
      cv.notify_one();
    });

  STA::strand_barrier(*impl);
  ASSERT_EQ(fake->pending_encode_message_count(), 1u)
    << "the service request must be handed to SecurityPolicy::encode_message_async";

  // Fire the request encode BAD. No server response is (or ever will be) delivered.
  auto detail = std::shared_ptr<const ErrorDetail>(
    ua::make_error_detail("EncodeFailed", "forced client encode failure", "test"));
  fake->fail_pending_encode_message(0, StatusCode{Status::BadEncodingError}, detail);

  // The pending-request callback must fire well within the per-request/service timeout (latency bound)
  // with EXACTLY the injected encode error (status bound) and carry its propagated ErrorDetail. An impl
  // that waited for the request deadline would only fire after 10s -> this 2s wait FAILS.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 2s, [&]() { return callbackFired; }))
      << "encode failure must fail the pending request without waiting for a server response";
  }
  EXPECT_EQ(resultStatus, StatusCode{Status::BadEncodingError});
  EXPECT_NE(resultDetail, nullptr) << "the encode ErrorDetail must propagate to the request callback";

  impl.reset();
  wired.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// LDS registration lifecycle - the obligations that surround the RegisterServer /
// RegisterServer2 calls exercised above: the register client's re-registration schedule and
// retry behaviour (ua::app::DiscoveryRegistration) and the LDS-side registry that expires a
// registration which is not renewed (ua::server::RegisteredServerStore).
//
// Both components are driven through their real code paths. The only interface that is faked is
// LdsRegistrar - the open/register/close cycle against a socket - which is exactly the interface the
// production design exposes for this purpose; the schedule, the backoff, the expiry sweep and the
// registry state all come from the components under test.
// =============================================================================

namespace
{

using ua::app::DiscoveryRegistration;
using ua::app::DiscoveryRegistrationConfig;
using ua::app::DiscoveryRegistrationInfo;
using ua::app::DiscoveryRegistrationObserver;
using ua::app::DiscoveryTarget;
using ua::app::LdsRegistrar;

using LdsRegistryConfig = ua::server::ServerConfig::LocalDiscoveryServer;

/// LdsRegistrar whose availability the test flips at runtime: while "unavailable" every cycle
/// fails the way an absent Discovery Server does, and once made available every cycle succeeds.
/// Counts the cycles so the test can tell a single attempt from a retry loop.
class ScriptedLdsRegistrar : public LdsRegistrar
{
public:
  void set_available(bool available)
  {
    mAvailable.store(available);
  }

  void register_async(DiscoveryTarget, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>>, bool, RegisterResultCallback callback) noexcept override
  {
    if (server.is_online())
    {
      mOnlineCalls.fetch_add(1U);
    }
    else
    {
      mOfflineCalls.fetch_add(1U);
    }

    if (!callback)
      return;

    if (!mAvailable.load())
    {
      callback(ua::Result<RegisterOutcome>{ua::StatusCode{Status::BadConnectionClosed}});
      return;
    }
    callback(ua::Result<RegisterOutcome>{RegisterOutcome{false}});
  }

  std::size_t online_calls() const
  {
    return mOnlineCalls.load();
  }

  std::size_t offline_calls() const
  {
    return mOfflineCalls.load();
  }

private:
  std::atomic<bool> mAvailable{true};
  std::atomic<std::size_t> mOnlineCalls{0};
  std::atomic<std::size_t> mOfflineCalls{0};
};

/// LdsRegistrar that forwards each cycle into a real RegisteredServerStore, so the driver's
/// schedule is observed through the registry it is supposed to keep alive rather than through a
/// counter the test owns.
class StoreBackedLdsRegistrar : public LdsRegistrar
{
public:
  explicit StoreBackedLdsRegistrar(std::shared_ptr<ua::server::RegisteredServerStore> store)
    : mStore(std::move(store))
  {}

  void register_async(DiscoveryTarget, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>>, bool, RegisterResultCallback callback) noexcept override
  {
    if (server.is_online())
      mOnlineCalls.fetch_add(1U);

    mStore->register_async(std::move(server),
      [callback = std::move(callback)](ua::VoidResult result)
      {
        if (!callback)
          return;
        if (result.is_bad())
        {
          callback(ua::Result<RegisterOutcome>{result.status_code()});
          return;
        }
        callback(ua::Result<RegisterOutcome>{RegisterOutcome{false}});
      });
  }

  std::size_t online_calls() const
  {
    return mOnlineCalls.load();
  }

private:
  std::shared_ptr<ua::server::RegisteredServerStore> mStore;
  std::atomic<std::size_t> mOnlineCalls{0};
};

/// Counts the driver's edge-triggered lifecycle notifications.
class CountingRegistrationObserver : public DiscoveryRegistrationObserver
{
public:
  void on_registration_established(const DiscoveryRegistrationInfo&) override
  {
    mEstablished.fetch_add(1U);
  }

  void on_registration_failed(const DiscoveryRegistrationInfo&, ua::StatusCode,
    std::shared_ptr<const ua::ErrorDetail>, std::chrono::steady_clock::time_point) override
  {
    mFailed.fetch_add(1U);
  }

  std::size_t established() const
  {
    return mEstablished.load();
  }

  std::size_t failed() const
  {
    return mFailed.load();
  }

private:
  std::atomic<std::size_t> mEstablished{0};
  std::atomic<std::size_t> mFailed{0};
};

DiscoveryTarget make_lds_target(const std::string& url)
{
  DiscoveryTarget target;
  target.discoveryUrl = url;
  return target;
}

ua::RegisteredServer make_online_registration(const std::string& serverUri)
{
  ua::RegisteredServer server;
  server.server_uri() = ua::String{serverUri};
  server.product_uri() = ua::String{"urn:test:product"};
  server.server_type() = ua::ApplicationType::Server;
  server.server_names().payload().push_back(ua::LocalizedText{ua::String{"en"}, ua::String{"Test Server"}});
  server.discovery_urls().payload().push_back(ua::String{"opc.tcp://localhost:4840"});
  server.is_online() = true;
  return server;
}

bool snapshot_contains(const std::vector<ua::RegisteredServer>& snapshot, const std::string& serverUri)
{
  for (const auto& entry : snapshot)
  {
    if (std::string{entry.server_uri()} == serverUri)
      return true;
  }
  return false;
}

/// Poll a predicate on the MAIN test thread until satisfied or the budget elapses.
template<typename Pred>
bool poll_until(Pred pred, std::chrono::milliseconds budget)
{
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
      return true;
    std::this_thread::sleep_for(25ms);
  }
  return pred();
}

void start_driver_sync(const std::shared_ptr<DiscoveryRegistration>& driver)
{
  auto started = std::make_shared<std::promise<void>>();
  auto future = started->get_future();
  driver->start_async([started](ua::VoidResult) { started->set_value(); });
  EXPECT_EQ(future.wait_for(2s), std::future_status::ready) << "start_async did not complete";
}

void stop_driver_sync(const std::shared_ptr<DiscoveryRegistration>& driver)
{
  auto stopped = std::make_shared<std::promise<void>>();
  auto future = stopped->get_future();
  driver->stop_async([stopped](ua::VoidResult) { stopped->set_value(); });
  EXPECT_EQ(future.wait_for(8s), std::future_status::ready) << "stop_async did not complete";
}

std::vector<DiscoveryRegistration::Status> driver_status_sync(
  const std::shared_ptr<DiscoveryRegistration>& driver)
{
  auto promised = std::make_shared<std::promise<std::vector<DiscoveryRegistration::Status>>>();
  auto future = promised->get_future();
  driver->status_async([promised](std::vector<DiscoveryRegistration::Status> status)
    { promised->set_value(std::move(status)); });
  if (future.wait_for(2s) != std::future_status::ready)
    return {};
  return future.get();
}

ua::VoidResult store_register_sync(
  ua::server::RegisteredServerStore& store, const ua::RegisteredServer& server)
{
  auto promised = std::make_shared<std::promise<ua::VoidResult>>();
  auto future = promised->get_future();
  store.register_async(ua::RegisteredServer{server},
    [promised](ua::VoidResult result) { promised->set_value(std::move(result)); });
  if (future.wait_for(2s) != std::future_status::ready)
    return ua::VoidResult{Status::BadTimeout};
  return future.get();
}

void shutdown_store_sync(ua::server::RegisteredServerStore& store)
{
  auto done = std::make_shared<std::promise<void>>();
  auto future = done->get_future();
  store.shutdown_async([done](ua::VoidResult) { done->set_value(); });
  EXPECT_EQ(future.wait_for(2s), std::future_status::ready) << "store shutdown_async did not complete";
}

/// Run one driver at @p cadence until its first cycle succeeds and report the delay it actually
/// scheduled the NEXT re-registration at - the period the driver applies, as distinct from the one
/// it was handed. Returns a negative duration when no re-registration was ever scheduled. Stops the
/// driver before returning so the long cadence timer cannot outlive the pool.
std::chrono::seconds observed_reregistration_period(
  boost::asio::thread_pool& pool, std::chrono::seconds cadence)
{
  auto registrar = std::make_shared<ScriptedLdsRegistrar>();

  DiscoveryRegistrationConfig config;
  config.targets.push_back(make_lds_target("opc.tcp://lds:4840"));
  config.cadence = cadence;
  config.backoffInitial = 1s;
  config.backoffCap = 1s;
  config.shutdownDeregisterTimeout = 2s;

  auto driver = DiscoveryRegistration::create(
    pool.get_executor(), registrar, make_online_registration("urn:test:cadence-server"), config);
  start_driver_sync(driver);

  std::vector<DiscoveryRegistration::Status> status;
  const bool scheduled = poll_until(
    [&]
    {
      status = driver_status_sync(driver);
      return !status.empty() && status.front().lastSuccess.has_value() &&
             status.front().nextAttempt.has_value();
    },
    5000ms);

  std::chrono::seconds period{-1};
  if (scheduled)
  {
    period = std::chrono::duration_cast<std::chrono::seconds>(
      *status.front().nextAttempt - std::chrono::steady_clock::now());
  }

  stop_driver_sync(driver);
  return period;
}

}  // namespace

// Part 4 section 5.4.5.1: "If an error occurs during registration (e.g. the Discovery Server is not
// running) then the Server shall periodically re-attempt registration." Start-up order between a
// server and its LDS is not guaranteed, so an implementation that treats the first failed
// RegisterServer as terminal - the natural reading of a one-shot "register at start-up" step -
// leaves the server permanently undiscoverable whenever it wins that race.
// @verifies AC-SVR-DISC-RS-011-RETRY-ON-ERROR
TEST(LdsRegistrationLifecycleTests, RegistrationIsRetriedUntilTheDiscoveryServerBecomesAvailable)
{
  boost::asio::thread_pool pool(2);
  auto registrar = std::make_shared<ScriptedLdsRegistrar>();
  auto observer = std::make_shared<CountingRegistrationObserver>();

  // The Discovery Server is not running when the server starts.
  registrar->set_available(false);

  DiscoveryRegistrationConfig config;
  config.targets.push_back(make_lds_target("opc.tcp://lds:4840"));
  config.cadence = 1s;
  config.backoffInitial = 1s;
  config.backoffCap = 1s;
  config.shutdownDeregisterTimeout = 2s;

  auto driver = DiscoveryRegistration::create(
    pool.get_executor(), registrar, make_online_registration("urn:test:retrying-server"), config);
  driver->set_observer(observer);
  start_driver_sync(driver);

  // While the LDS is down the driver must keep re-attempting rather than give up after the error.
  ASSERT_TRUE(poll_until([&] { return registrar->online_calls() >= 3U; }, 8000ms))
    << "registration was not re-attempted while the Discovery Server was unavailable; attempts: "
    << registrar->online_calls();
  EXPECT_GE(observer->failed(), 1U) << "each failed attempt must be reported";
  ASSERT_EQ(observer->established(), 0U) << "no registration can have succeeded while the LDS is down";

  // Bring the Discovery Server up. Nothing else changes - no restart, no operator action.
  registrar->set_available(true);

  ASSERT_TRUE(poll_until([&] { return observer->established() >= 1U; }, 8000ms))
    << "registration did not succeed once the Discovery Server became available";

  const auto status = driver_status_sync(driver);
  ASSERT_FALSE(status.empty()) << "the driver must report a status for its configured target";
  EXPECT_TRUE(status.front().lastSuccess.has_value()) << "a successful registration must be recorded";
  EXPECT_TRUE(status.front().lastError.is_good())
    << "the last cycle must be clean once the Discovery Server is available";

  stop_driver_sync(driver);
  driver.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 5.4.5.1: "The period of the recurring registration should be configurable; however, the
// maximum is 10 minutes." The maximum is not cosmetic - Part 12 section 5 expires an online registration
// that is not renewed within ten minutes, so any period above the cap guarantees the record is gone
// between registrations. An implementation that simply schedules the configured value honours the
// "configurable" half and silently breaks discovery for anyone who configures a larger period.
// @verifies AC-SVR-DISC-RS-010-PERIOD-CONFIGURABLE
TEST(LdsRegistrationLifecycleTests, ReRegistrationPeriodIsConfigurableAndNeverExceedsTenMinutes)
{
  boost::asio::thread_pool pool(2);

  // Below the maximum: the configured period is what the driver applies.
  const auto configuredPeriod = observed_reregistration_period(pool, 300s);
  ASSERT_GT(configuredPeriod, 0s) << "the driver never scheduled a re-registration";
  EXPECT_GT(configuredPeriod, 290s) << "a configured 5-minute period must be honoured, not overridden; "
                                       "observed "
                                    << configuredPeriod.count() << "s";
  EXPECT_LE(configuredPeriod, 300s) << "the driver must not stretch a configured period; observed "
                                    << configuredPeriod.count() << "s";

  // Above the maximum: clamped to ten minutes, or the record expires between registrations.
  const auto clampedPeriod = observed_reregistration_period(pool, 1200s);
  ASSERT_GT(clampedPeriod, 0s) << "the driver never scheduled a re-registration";
  EXPECT_LE(clampedPeriod, 600s) << "a configured period above 10 minutes must be clamped to 10 minutes; "
                                    "observed "
                                 << clampedPeriod.count() << "s";

  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 5.4.5.1: "manually launched Servers shall periodically register with the Discovery Server
// as long as they are able to receive connections from Clients." The contrast with the
// automatically-launched case is that a manual server is running, so it must renew its own record
// rather than lean on a semaphore file. A driver that registers once at start-up passes every
// smoke test and then disappears from the LDS one expiry window later, with nothing in the server
// to notice. The registry here is the real LDS-side store, and the un-renewed control registration
// is what makes "still present" evidence of re-registration rather than of a store that never
// expires anything.
// @verifies AC-SVR-DISC-RS-008-MANUAL-SERVER-REREGISTERS
TEST(LdsRegistrationLifecycleTests, ManuallyLaunchedServerStaysRegisteredPastTheExpiryWindow)
{
  boost::asio::thread_pool pool(2);

  auto store = ua::server::RegisteredServerStore::create(
    pool.get_executor(), LdsRegistryConfig{.enabled = true, .registrationExpiry = 2s});

  // Control: a peer that registers once and never again.
  ASSERT_TRUE(store_register_sync(*store, make_online_registration("urn:test:one-shot-server")).is_good())
    << "the control registration must be accepted";

  auto registrar = std::make_shared<StoreBackedLdsRegistrar>(store);

  DiscoveryRegistrationConfig config;
  config.targets.push_back(make_lds_target("opc.tcp://lds:4840"));
  config.cadence = 1s;
  config.backoffInitial = 1s;
  config.backoffCap = 1s;
  config.shutdownDeregisterTimeout = 2s;

  auto driver = DiscoveryRegistration::create(
    pool.get_executor(), registrar, make_online_registration("urn:test:manual-server"), config);
  start_driver_sync(driver);

  ASSERT_TRUE(
    poll_until([&] { return snapshot_contains(store->snapshot(), "urn:test:manual-server"); }, 4000ms))
    << "the manually-launched server's first registration never reached the registry";
  ASSERT_TRUE(snapshot_contains(store->snapshot(), "urn:test:one-shot-server"))
    << "the control registration must start out present, or its later absence proves nothing";

  // Run past a full expiry window with no operator action of any kind.
  ASSERT_TRUE(
    poll_until([&] { return !snapshot_contains(store->snapshot(), "urn:test:one-shot-server"); }, 12000ms))
    << "the registry never expired the un-renewed control registration, so this test cannot "
       "distinguish a re-registering server from a registry that forgets nothing";

  const auto snapshot = store->snapshot();
  ASSERT_FALSE(snapshot.empty()) << "the registry must still hold the re-registering server";
  EXPECT_TRUE(snapshot_contains(snapshot, "urn:test:manual-server"))
    << "a manually-launched server must re-register on its own schedule and survive the expiry window";
  EXPECT_FALSE(snapshot_contains(snapshot, "urn:test:one-shot-server"));
  // WAIT for the third registration rather than asserting one happened to have arrived. Nothing
  // above waits on the registration count - the polls before it wait for registry CONTENT - so the
  // old EXPECT_GE simply sampled whatever the 2s expiry had produced by then. On this machine that
  // was three; in a container it was two, and the test failed for being slower rather than wrong.
  //
  // The property is that re-registration RECURS unattended, so the test now waits for recurrence
  // and fails only if it never comes. The budget is generous against a 2s expiry: a real failure
  // to re-register never satisfies it, however long the wait.
  EXPECT_TRUE(poll_until([&] { return registrar->online_calls() >= 3U; }, 12000ms))
    << "re-registration must recur without operator action; online registrations sent: "
    << registrar->online_calls();

  stop_driver_sync(driver);
  driver.reset();
  shutdown_store_sync(*store);
  store.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 12 section 5 (Figure 11): online registrations expire, and the Discovery Server removes a record
// whose server has not re-registered within the window. The exemption is the semaphore file - an
// automatically-launched server is not running to re-register, so expiring its record un-discovers
// exactly the servers the semaphore mechanism exists for. A sweep that only compares each entry's
// deadline against the clock gets the first two cases right and silently drops the third.
// @verifies AC-SVR-DISC-LDS-006-REGISTRATION-EXPIRY
TEST(LdsRegistrationLifecycleTests, OnlineRegistrationExpiresUnlessRenewedOrHeldBySemaphoreFile)
{
  boost::asio::thread_pool pool(2);

  // A real, readable file, so a registry that honours the exemption by checking the file cannot
  // fail this test for the wrong reason.
  const auto semaphorePath = std::filesystem::temp_directory_path() /
                             ("ua_lds_semaphore_" +
                               std::to_string(static_cast<unsigned long long>(
                                 std::chrono::steady_clock::now().time_since_epoch().count())) +
                               ".tmp");
  {
    std::ofstream semaphoreFile{semaphorePath};
    semaphoreFile << "present";
  }
  ASSERT_TRUE(std::filesystem::exists(semaphorePath)) << "the semaphore file must exist for this test";

  auto store = ua::server::RegisteredServerStore::create(
    pool.get_executor(), LdsRegistryConfig{.enabled = true, .registrationExpiry = 2s});

  auto semaphoreRegistration = make_online_registration("urn:test:auto-launched-server");
  semaphoreRegistration.semaphore_file_path() = ua::String{semaphorePath.string()};

  ASSERT_TRUE(store_register_sync(*store, make_online_registration("urn:test:stale-server")).is_good());
  ASSERT_TRUE(store_register_sync(*store, make_online_registration("urn:test:renewing-server")).is_good());
  ASSERT_TRUE(store_register_sync(*store, semaphoreRegistration).is_good());

  {
    const auto initial = store->snapshot();
    ASSERT_TRUE(snapshot_contains(initial, "urn:test:stale-server"));
    ASSERT_TRUE(snapshot_contains(initial, "urn:test:renewing-server"));
    ASSERT_TRUE(snapshot_contains(initial, "urn:test:auto-launched-server"));
  }

  // Run past the expiry window. Only the renewing server re-registers within the interval; the
  // other two are left alone.
  const auto renewalDeadline = std::chrono::steady_clock::now() + 5s;
  while (std::chrono::steady_clock::now() < renewalDeadline)
  {
    std::this_thread::sleep_for(500ms);
    ASSERT_TRUE(store_register_sync(*store, make_online_registration("urn:test:renewing-server")).is_good())
      << "the renewal must be accepted, or the survival assertion below proves nothing";
  }

  const auto snapshot = store->snapshot();
  ASSERT_FALSE(snapshot.empty()) << "the renewed registration must still be served";
  EXPECT_FALSE(snapshot_contains(snapshot, "urn:test:stale-server"))
    << "an online registration that stopped being renewed must be removed once it expires";
  EXPECT_TRUE(snapshot_contains(snapshot, "urn:test:renewing-server"))
    << "a registration renewed within the expiry interval must survive";
  EXPECT_TRUE(snapshot_contains(snapshot, "urn:test:auto-launched-server"))
    << "a registration carrying a semaphore file path must not be expired on the re-registration "
       "deadline: the server it names is not running to renew it";

  shutdown_store_sync(*store);
  store.reset();
  ::ua::test_utils::drain_with_timeout(pool);

  std::error_code removeError;
  std::filesystem::remove(semaphorePath, removeError);
}

// =============================================================================================
// Registration content that reaches the LDS record - the fields a registering server only ever
// gets one chance to supply. Driven end to end through the real DiscoveryRegistration driver and
// the real RegisteredServerStore, read back through the registry's published snapshot.
// =============================================================================================

namespace
{

/// Locate one registration in a registry snapshot by serverUri. Returns a copy so the caller can
/// use the non-const accessors the generated types expose.
std::optional<ua::RegisteredServer> find_registration(
  const std::vector<ua::RegisteredServer>& snapshot, const std::string& serverUri)
{
  for (const auto& entry : snapshot)
  {
    if (std::string{entry.server_uri()} == serverUri)
      return entry;
  }
  return std::nullopt;
}

/// A unique-per-run path under the system temp directory, so parallel runs cannot collide.
std::filesystem::path make_unique_temp_path(const std::string& prefix)
{
  return std::filesystem::temp_directory_path() /
         (prefix + std::to_string(static_cast<unsigned long long>(
                     std::chrono::steady_clock::now().time_since_epoch().count())));
}

}  // namespace

// Part 4 section 5.4.5: the registration is the ONLY chance to supply per-locale names - FindServers picks
// among them per the client's requested locale and cannot invent one that was never registered.
// The natural implementation of a re-registering driver rebuilds a minimal RegisteredServer for
// each cycle (uri + one name + urls), which passes every single-locale smoke test and silently
// strips every locale but the first, so a client asking for "de" is served the English name for
// the rest of the server's uptime.
// @verifies AC-SVR-DISC-RS-005-LOCALIZED-NAMES
TEST(LdsRegistrationLifecycleTests, RegistrationCarriesOneLocalisedNamePerSupportedLocale)
{
  boost::asio::thread_pool pool(2);

  auto store = ua::server::RegisteredServerStore::create(
    pool.get_executor(), LdsRegistryConfig{.enabled = true, .registrationExpiry = 600s});

  // The server supports three locales and advertises a name in each.
  auto identity = make_online_registration("urn:test:multi-locale-server");
  identity.server_names().payload().clear();
  identity.server_names().payload().push_back(ua::LocalizedText{ua::String{"en"}, ua::String{"Test Server"}});
  identity.server_names().payload().push_back(ua::LocalizedText{ua::String{"de"}, ua::String{"Testserver"}});
  identity.server_names().payload().push_back(
    ua::LocalizedText{ua::String{"fr"}, ua::String{"Serveur de test"}});

  auto registrar = std::make_shared<StoreBackedLdsRegistrar>(store);

  DiscoveryRegistrationConfig config;
  config.targets.push_back(make_lds_target("opc.tcp://lds:4840"));
  config.cadence = 1s;
  config.backoffInitial = 1s;
  config.backoffCap = 1s;
  config.shutdownDeregisterTimeout = 2s;

  auto driver = DiscoveryRegistration::create(pool.get_executor(), registrar, identity, config);
  start_driver_sync(driver);

  ASSERT_TRUE(
    poll_until([&] { return snapshot_contains(store->snapshot(), "urn:test:multi-locale-server"); }, 8000ms))
    << "the registration never reached the registry, so its contents cannot be read";
  // Read the record only after a re-registration cycle has overwritten it: a driver that carries
  // the full identity on the first cycle and a reduced one on every cycle afterwards must fail.
  ASSERT_TRUE(poll_until([&] { return registrar->online_calls() >= 2U; }, 8000ms))
    << "the driver never re-registered, so this test cannot see what a renewal publishes; cycles: "
    << registrar->online_calls();

  const auto snapshot = store->snapshot();
  ASSERT_FALSE(snapshot.empty()) << "the registry must still hold the registration";
  auto record = find_registration(snapshot, "urn:test:multi-locale-server");
  ASSERT_TRUE(record.has_value()) << "the re-registered record is missing from the registry";

  const auto& names = record->server_names().payload();
  ASSERT_EQ(names.size(), 3u) << "one localised name per supported locale must survive registration; "
                                 "names in the record: "
                              << names.size();

  auto hasLocalisedName = [&names](const std::string& locale, const std::string& text)
  {
    for (const auto& name : names)
    {
      if (std::string{name.locale()} == locale && std::string{name.text()} == text)
        return true;
    }
    return false;
  };
  EXPECT_TRUE(hasLocalisedName("en", "Test Server")) << "the en name is absent from the record";
  EXPECT_TRUE(hasLocalisedName("de", "Testserver")) << "the de name is absent from the record";
  EXPECT_TRUE(hasLocalisedName("fr", "Serveur de test")) << "the fr name is absent from the record";

  stop_driver_sync(driver);
  driver.reset();
  shutdown_store_sync(*store);
  store.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 5.4.5.1: an automatically-launched server registers a semaphoreFilePath, because it is
// not running to re-register every ten minutes - the file is the only thing keeping its record
// alive, and the Discovery Server must be able to read it (SPEC-SVR-DISC-RS-014). An
// implementation that treats the path as a start-up-only field, or rebuilds the registration for
// each renewal cycle from the mandatory fields alone, drops it and the record is expired at the
// next sweep exactly for the servers the semaphore mechanism exists to keep discoverable.
// @verifies AC-SVR-DISC-RS-013-SEMAPHORE-PATH
TEST(LdsRegistrationLifecycleTests, AutomaticallyLaunchedServerRegistersAReadableSemaphoreFilePath)
{
  boost::asio::thread_pool pool(2);

  // A real, readable file: the observation is not "some string is present" but "the Discovery
  // Server can read the file the registration names".
  const auto semaphorePath = make_unique_temp_path("ua_lds_auto_launch_semaphore_");
  {
    std::ofstream semaphoreFile{semaphorePath};
    semaphoreFile << "semaphore";
  }
  ASSERT_TRUE(std::filesystem::exists(semaphorePath)) << "the semaphore file must exist for this test";

  auto store = ua::server::RegisteredServerStore::create(
    pool.get_executor(), LdsRegistryConfig{.enabled = true, .registrationExpiry = 600s});

  auto identity = make_online_registration("urn:test:auto-launched-register");
  identity.semaphore_file_path() = ua::String{semaphorePath.string()};

  auto registrar = std::make_shared<StoreBackedLdsRegistrar>(store);

  DiscoveryRegistrationConfig config;
  config.targets.push_back(make_lds_target("opc.tcp://lds:4840"));
  config.cadence = 1s;
  config.backoffInitial = 1s;
  config.backoffCap = 1s;
  config.shutdownDeregisterTimeout = 2s;

  auto driver = DiscoveryRegistration::create(pool.get_executor(), registrar, identity, config);
  start_driver_sync(driver);

  ASSERT_TRUE(poll_until(
    [&] { return snapshot_contains(store->snapshot(), "urn:test:auto-launched-register"); }, 8000ms))
    << "the registration never reached the registry, so its semaphore path cannot be read";
  // As above: read the record a renewal cycle has rewritten, not only the first one.
  ASSERT_TRUE(poll_until([&] { return registrar->online_calls() >= 2U; }, 8000ms))
    << "the driver never re-registered, so this test cannot see what a renewal publishes; cycles: "
    << registrar->online_calls();

  const auto snapshot = store->snapshot();
  ASSERT_FALSE(snapshot.empty()) << "the registry must still hold the registration";
  auto record = find_registration(snapshot, "urn:test:auto-launched-register");
  ASSERT_TRUE(record.has_value()) << "the re-registered record is missing from the registry";

  // Conjunct 1 - the path is present in the record the LDS holds.
  const std::string recordedPath{record->semaphore_file_path()};
  ASSERT_FALSE(recordedPath.empty())
    << "an automatically-launched server must register a semaphoreFilePath; the record carries none";
  EXPECT_EQ(recordedPath, semaphorePath.string())
    << "the registered semaphore path must be the one configured, unaltered";

  // Conjunct 2 - it names a file the Discovery Server can read. Opened through the path taken FROM
  // THE RECORD, which is the only path the LDS ever sees.
  std::ifstream recordedFile{recordedPath};
  ASSERT_TRUE(recordedFile.is_open())
    << "the registered semaphoreFilePath does not name a file the Discovery Server can open: "
    << recordedPath;
  std::string contents;
  recordedFile >> contents;
  EXPECT_EQ(contents, "semaphore") << "the registered path does not resolve to the semaphore file";

  stop_driver_sync(driver);
  driver.reset();
  shutdown_store_sync(*store);
  store.reset();
  ::ua::test_utils::drain_with_timeout(pool);

  std::error_code removeError;
  std::filesystem::remove(semaphorePath, removeError);
}

// =============================================================================================
// LDS-side inbound registration validation - the service results a Discovery Server owes a
// registering server. Driven through the real session-less DiscoveryServiceSet<RegisterServer2Request>
// handler into a real RegisteredServerStore, so both the wire result and the registry side effect
// are observed. Only the dependency bundle is faked.
// =============================================================================================

namespace
{

/// Real inbound RegisterServer2 path plus the registry it writes into.
struct InboundLdsHarness
{
  std::shared_ptr<ua::test_helpers::FakeDiscoveryDependencies> deps;
  std::shared_ptr<ua::server::RegisteredServerStore> store;

  static InboundLdsHarness create(boost::asio::any_io_executor executor)
  {
    InboundLdsHarness harness;
    harness.deps = std::make_shared<ua::test_helpers::FakeDiscoveryDependencies>(executor);
    // A live store is what turns the server-as-LDS feature ON; without it every registration is
    // refused with Bad_ServiceUnsupported and no validation code would run at all.
    harness.store = ua::server::RegisteredServerStore::create(
      executor, LdsRegistryConfig{.enabled = true, .registrationExpiry = 600s});
    harness.deps->set_registered_server_store(harness.store);
    return harness;
  }
};

/// An authenticated channel whose peer certificate applicationUri equals @p serverUri, so the
/// security-mode gate and the cert-continuity gate both pass and the check under test is the only
/// one that can reject the registration.
ua::server::InboundRegistrationContext make_matching_registration_context(const std::string& serverUri)
{
  ua::server::InboundRegistrationContext context;
  context.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  context.peerApplicationUri = serverUri;
  return context;
}

/// Drive one RegisterServer2 through the real handler and return the wire response.
ua::Response run_inbound_register2(const std::shared_ptr<ua::test_helpers::FakeDiscoveryDependencies>& deps,
  boost::asio::any_io_executor executor, ua::RegisterServer2Request request,
  ua::server::InboundRegistrationContext context)
{
  auto promised = std::make_shared<std::promise<ua::Response>>();
  auto future = promised->get_future();
  auto service = ua::server::DiscoveryServiceSet<ua::RegisterServer2Request>::create(
    deps,
    ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(request),
    executor,
    [promised](ua::Response response) { promised->set_value(std::move(response)); },
    std::move(context));
  if (future.wait_for(2s) != std::future_status::ready)
  {
    ADD_FAILURE() << "the RegisterServer2 handler never completed";
    return ua::Response{};
  }
  return future.get();
}

/// Service-level result of an inbound RegisterServer2, whether it faulted or was accepted. Never
/// dereferences a null response, so a caller can assert the code without an early return that
/// would skip its own teardown.
ua::StatusCode inbound_service_result(const ua::Response& response)
{
  if (auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get()))
    return fault->response_header().service_result();
  if (auto* accepted = dynamic_cast<ua::RegisterServer2Response*>(response.second.get()))
    return accepted->response_header().service_result();
  return ua::StatusCode{ua::Status::BadUnexpectedError};
}

}  // namespace

// Part 4 section 5.4.5.3: an empty OR syntactically invalid serverUri is Bad_ServerUriInvalid, one of four
// distinct registration codes that each name their own bad field so an installer can diagnose a
// failed registration without the LDS's log. The empty case is the obvious half; the syntax half is
// the one a plausible implementation drops, because the certificate-continuity check
// (SVR-DISC-RS-003) appears to cover it - it does not, since a server whose certificate carries the
// same malformed applicationUri satisfies that check and registers a record no client can key on.
// Both registrations here present a matching peer applicationUri precisely so nothing but the
// serverUri validation itself can reject them.
// EXPECTED TO FAIL against the current server: the behaviour is UNIMPLEMENTED, and the test is the
// report of that. Its assertions must not be weakened to make it pass. SVR-DISC-RS-016 obliges the
// LDS to return Bad_ServerUriInvalid when serverUri "is empty (or fails validation for syntax /
// scheme)", but the gate at sdk/implementation/server/services/ua_discovery_service_set.cpp:641
// tests only `serverUri.empty()`; there is no URI-syntax validation anywhere on the inbound path.
// The certificate-continuity gate below it does not cover the gap, because a peer whose certificate
// carries the same malformed applicationUri passes it, so "not a uri" is accepted and recorded.
// Case (a) passes today, case (b) and the registry conjunct fail - see defect
// D-INBOUND-REGISTERSERVERREGISTERSERVER2-VALIDATES-SERVERURI-EMPTINESS-ONLY-NEVER. The fix is a
// syntax/scheme check at gate (2).
// @verifies AC-SVR-DISC-RS-016-SERVERURIINVALID
TEST(LdsInboundRegistrationValidationTests, EmptyOrMalformedServerUriIsRejectedWithBadServerUriInvalid)
{
  boost::asio::thread_pool pool(2);
  auto harness = InboundLdsHarness::create(pool.get_executor());

  // (a) empty serverUri.
  {
    ua::RegisterServer2Request request;
    request.server() = make_online_registration("");

    const auto response = run_inbound_register2(harness.deps,
      pool.get_executor(),
      std::move(request),
      make_matching_registration_context("urn:test:register-client"));

    EXPECT_EQ(inbound_service_result(response), ua::StatusCode{ua::Status::BadServerUriInvalid})
      << "an empty serverUri must be refused with Bad_ServerUriInvalid";
  }

  // A syntax arm was removed here on 2026-08-10, with the same one on the RegisterServer twin: Table 7
  // obliges nothing about serverUri syntax, and a syntax gate would refuse the bare GUID form.

  EXPECT_TRUE(harness.store->snapshot().empty())
    << "a registration refused for an invalid serverUri must not appear in the registry";

  shutdown_store_sync(*harness.store);
  harness.store.reset();
  harness.deps.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 5.4.5.2 Table 7: a serverType that is Client_1 or outside the ApplicationType enumeration
// is Bad_InvalidArgument, and nothing is recorded. Registration is the one discovery operation that
// writes, so an accepted malformed record is served to every client that queries afterwards - and a
// serverType nobody can decode is exactly the record a client cannot filter out. Rejecting Client_1
// while letting an out-of-range value through is the easy half-implementation: a switch over the
// named enumerators with no default, or an `!= Client` test, gets the first case right and admits
// the second.
// @verifies AC-SVR-DISC-RS-020-INVALID-SERVERTYPE
TEST(LdsInboundRegistrationValidationTests, InvalidServerTypeIsRejectedWithBadInvalidArgumentAndNotRecorded)
{
  boost::asio::thread_pool pool(2);
  auto harness = InboundLdsHarness::create(pool.get_executor());

  // (a) Client_1 - a Client is not a Server and may not register as one.
  {
    const std::string serverUri{"urn:test:client-type-server"};
    auto server = make_online_registration(serverUri);
    server.server_type() = ua::ApplicationType::Client;

    ua::RegisterServer2Request request;
    request.server() = std::move(server);

    const auto response = run_inbound_register2(
      harness.deps, pool.get_executor(), std::move(request), make_matching_registration_context(serverUri));

    EXPECT_EQ(inbound_service_result(response), ua::StatusCode{ua::Status::BadInvalidArgument})
      << "serverType Client must be refused with Bad_InvalidArgument";
  }

  // (b) a value outside the enumeration altogether.
  {
    const std::string serverUri{"urn:test:out-of-range-type-server"};
    auto server = make_online_registration(serverUri);
    server.server_type() = static_cast<ua::ApplicationType>(42);

    ua::RegisterServer2Request request;
    request.server() = std::move(server);

    const auto response = run_inbound_register2(
      harness.deps, pool.get_executor(), std::move(request), make_matching_registration_context(serverUri));

    EXPECT_EQ(inbound_service_result(response), ua::StatusCode{ua::Status::BadInvalidArgument})
      << "a serverType outside the ApplicationType enumeration must be refused with "
         "Bad_InvalidArgument";
  }

  // The second conjunct: no record is created by either rejected registration.
  EXPECT_TRUE(harness.store->snapshot().empty())
    << "a registration refused for an invalid serverType must not appear in the registry";

  shutdown_store_sync(*harness.store);
  harness.store.reset();
  harness.deps.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 5.4.6: discoveryConfiguration is extensible by design, so a configuration the Discovery
// Server does not recognise is reported as Bad_NotSupported IN ITS OWN configurationResults entry
// - per configuration, not per call. Failing the whole
// registration on an unknown entry would make every future extension break registration against
// existing Discovery Servers; conversely, returning Good for every entry (the shape a handler that
// only counts the entries produces) tells a registering server its mDNS configuration was applied
// when it was silently ignored. This implementation is not an LDS-ME and interprets no discovery
// configuration types, including MdnsDiscoveryConfiguration, so every entry in this stimulus is
// unsupported. The mixed concrete types prove the response is positional rather than one status for
// the call.
// @verifies AC-SVR-DISC-RS2-003-UNKNOWN-CONFIG-NOTSUPPORTED
TEST(LdsInboundRegistrationValidationTests, UnknownDiscoveryConfigurationIsReportedNotSupportedPerEntry)
{
  boost::asio::thread_pool pool(2);
  auto harness = InboundLdsHarness::create(pool.get_executor());

  const std::string serverUri{"urn:test:mixed-configuration-server"};
  ua::RegisterServer2Request request;
  request.server() = make_online_registration(serverUri);

  // Entry 0 is a real configuration type that this non-LDS-ME does not interpret. Entry 1 is an
  // unrelated structure standing in for a future extension it also does not understand.
  {
    ua::RefStructure<ua::Structure> known;
    known = std::unique_ptr<ua::Structure>{std::make_unique<ua::MdnsDiscoveryConfiguration>()};
    ua::RefStructure<ua::Structure> unknown;
    unknown = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    request.discovery_configuration().payload().push_back(std::move(known));
    request.discovery_configuration().payload().push_back(std::move(unknown));
  }

  const auto response = run_inbound_register2(
    harness.deps, pool.get_executor(), std::move(request), make_matching_registration_context(serverUri));

  // The call as a whole must succeed: an unknown entry is not a service-level failure.
  auto* accepted = dynamic_cast<ua::RegisterServer2Response*>(response.second.get());
  ASSERT_NE(accepted, nullptr)
    << "an unrecognised discoveryConfiguration must not fail the whole RegisterServer2 call";
  EXPECT_TRUE(accepted->response_header().service_result().is_good())
    << "the registration itself must be accepted; only the unknown configuration is refused";

  const auto& results = accepted->configuration_results().payload();
  ASSERT_EQ(results.size(), 2u) << "one configurationResults entry per supplied discoveryConfiguration; "
                                   "entries returned: "
                                << results.size();
  for (size_t index = 0; index < results.size(); ++index)
  {
    EXPECT_EQ(results[index], ua::StatusCode{ua::Status::BadNotSupported})
      << "each unrecognised configuration must be reported in its own entry";
    ASSERT_NE(results[index].shared_detail(), nullptr);
    EXPECT_EQ(results[index].shared_detail()->code, "DiscoveryConfigurationUnsupported");
    ASSERT_EQ(results[index].shared_detail()->context.size(), 1u);
    EXPECT_EQ(results[index].shared_detail()->context[0].key, ua::ContextKeys::operationIndex.value());
    EXPECT_EQ(results[index].shared_detail()->context[0].value, std::to_string(index));
  }

  // Per-configuration refusal does not roll back the registration.
  EXPECT_TRUE(snapshot_contains(harness.store->snapshot(), serverUri))
    << "the registration carrying one known configuration must be recorded";

  shutdown_store_sync(*harness.store);
  harness.store.reset();
  harness.deps.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// =============================================================================================
// The same LDS-side obligations driven through the RegisterServer (v1) service. Part 4 section 5.4.5.3 -
// the Table 7 service-result codes these criteria cite - belongs to RegisterServer, not to
// RegisterServer2, and the two are separate template instantiations of the inbound handler
// (DiscoveryServiceSet<RegisterServerRequest> / <RegisterServer2Request>), so a v2-only test
// leaves the service the obligation actually names unexercised.
// =============================================================================================

namespace
{

/// Drive one RegisterServer (v1) through the real handler and return the wire response.
ua::Response run_inbound_register1(const std::shared_ptr<ua::test_helpers::FakeDiscoveryDependencies>& deps,
  boost::asio::any_io_executor executor, ua::RegisterServerRequest request,
  ua::server::InboundRegistrationContext context)
{
  auto promised = std::make_shared<std::promise<ua::Response>>();
  auto future = promised->get_future();
  auto service = ua::server::DiscoveryServiceSet<ua::RegisterServerRequest>::create(
    deps,
    ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(request),
    executor,
    [promised](ua::Response response) { promised->set_value(std::move(response)); },
    std::move(context));
  if (future.wait_for(2s) != std::future_status::ready)
  {
    ADD_FAILURE() << "the RegisterServer handler never completed";
    return ua::Response{};
  }
  return future.get();
}

/// Service-level result of an inbound RegisterServer (v1), whether it faulted or was accepted.
/// Never dereferences a null response, so a caller can assert the code without an early return
/// that would skip its own teardown.
ua::StatusCode inbound_v1_service_result(const ua::Response& response)
{
  if (auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get()))
    return fault->response_header().service_result();
  if (auto* accepted = dynamic_cast<ua::RegisterServerResponse*>(response.second.get()))
    return accepted->response_header().service_result();
  return ua::StatusCode{ua::Status::BadUnexpectedError};
}

}  // namespace

// Part 4 section 5.4.5.3, Table 7: on the RegisterServer service an empty OR syntactically invalid
// serverUri is Bad_ServerUriInvalid. serverUri is the key every later FindServers response is
// filtered on, so a record keyed by a string that is not a URI can never be matched by the client
// that needs it, and the installer gets no diagnostic naming the offending field. The plausible
// implementation checks emptiness and stops there, on the reasoning that the certificate-continuity
// check (SVR-DISC-RS-003) already ties serverUri to a validated identity - it does not: a server
// whose certificate carries the same malformed applicationUri satisfies continuity exactly. Both
// registrations here present a matching peer applicationUri, so nothing but the serverUri
// validation itself can reject them, and the registry conjunct is checked with the store still
// live so a silently-accepted record is visible.
// EXPECTED TO FAIL against HEAD: gate (2) in
// sdk/implementation/server/services/ua_discovery_service_set.cpp tests only `serverUri.empty()`;
// there is no URI syntax/scheme validation anywhere on the inbound path, for either service.
// Case (a) passes today; case (b) and the registry conjunct do not.
// @verifies AC-SVR-DISC-RS-016-SERVERURIINVALID
TEST(LdsInboundRegistrationValidationTests, RegisterServerRefusesAnEmptyOrMalformedServerUri)
{
  boost::asio::thread_pool pool(2);
  auto harness = InboundLdsHarness::create(pool.get_executor());

  // (a) empty serverUri.
  {
    ua::RegisterServerRequest request;
    request.server() = make_online_registration("");

    const auto response = run_inbound_register1(harness.deps,
      pool.get_executor(),
      std::move(request),
      make_matching_registration_context("urn:test:v1-register-client"));

    EXPECT_EQ(inbound_v1_service_result(response), ua::StatusCode{ua::Status::BadServerUriInvalid})
      << "RegisterServer must refuse an empty serverUri with Bad_ServerUriInvalid";
  }

  // A syntax arm was removed here on 2026-08-10. `AC-SVR-DISC-RS-016-SERVERURIINVALID` asks for the
  // empty case; nothing in Part 4 section 5.4.5.3 Table 7 obliges URI-syntax validation of a serverUri, and
  // a syntax gate would refuse the bare GUID form the specification permits.

  EXPECT_TRUE(harness.store->snapshot().empty())
    << "a registration refused for an invalid serverUri must not appear in the registry";

  shutdown_store_sync(*harness.store);
  harness.store.reset();
  harness.deps.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Two semaphore-path rows were retired here on 2026-08-10 with the narrowing of
// AC-SVR-DISC-RS-019-SEMAPHOREFILEMISSING: Part 4 section 5.4.5.3 enumerates the code an LDS may return,
// which is not a duty to probe the path at register time. The surviving obligation is permissive
// and the requirement's own "(eager mode)" design coverage is where an eager check would belong.

// Part 4 section 5.4.6: the refusal of an unrecognised discoveryConfiguration is per configuration, and
// configurationResults is positional - entry i reports on discoveryConfiguration i. That
// positionality is the whole mechanism: it is how a registering server learns WHICH of the
// configurations it sent was ignored, and an extensible parameter is useless if the answer cannot
// be attributed. Two half-implementations survive a fixture that puts one concrete type first and
// stops after one unknown: a handler that short-circuits on the first unrecognised entry (returning
// a truncated array, or one Bad_NotSupported for the call), and one that reports on the entries it
// recognised and appends the rest, which silently re-orders the answers. Leading with one unknown
// structure, sandwiching a different unsupported concrete type and closing with a second unknown
// falsifies both, and the count-and-order assertions falsify a collapsed service-level answer.
// @verifies AC-SVR-DISC-RS2-003-UNKNOWN-CONFIG-NOTSUPPORTED
TEST(LdsInboundRegistrationValidationTests, EveryUnknownDiscoveryConfigurationIsRefusedInItsOwnEntry)
{
  boost::asio::thread_pool pool(2);
  auto harness = InboundLdsHarness::create(pool.get_executor());

  const std::string serverUri{"urn:test:ordered-configuration-server"};
  ua::RegisterServer2Request request;
  request.server() = make_online_registration(serverUri);

  // Entries 0 and 2 are unrelated structures standing in for unknown extensions. Entry 1 is a real
  // MdnsDiscoveryConfiguration, which this non-LDS-ME also does not interpret.
  {
    ua::RefStructure<ua::Structure> leadingUnknown;
    leadingUnknown = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    ua::RefStructure<ua::Structure> known;
    known = std::unique_ptr<ua::Structure>{std::make_unique<ua::MdnsDiscoveryConfiguration>()};
    ua::RefStructure<ua::Structure> trailingUnknown;
    trailingUnknown = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    request.discovery_configuration().payload().push_back(std::move(leadingUnknown));
    request.discovery_configuration().payload().push_back(std::move(known));
    request.discovery_configuration().payload().push_back(std::move(trailingUnknown));
  }

  const auto response = run_inbound_register2(
    harness.deps, pool.get_executor(), std::move(request), make_matching_registration_context(serverUri));

  // Leading with an unrecognised entry must not fail the call: the refusal is per configuration.
  auto* accepted = dynamic_cast<ua::RegisterServer2Response*>(response.second.get());
  ASSERT_NE(accepted, nullptr)
    << "an unrecognised discoveryConfiguration must not fail the whole RegisterServer2 call, "
       "whatever position it occupies";
  EXPECT_TRUE(accepted->response_header().service_result().is_good())
    << "the registration itself must be accepted; only the unknown configurations are refused";

  const auto& results = accepted->configuration_results().payload();
  ASSERT_EQ(results.size(), 3u) << "configurationResults is positional: exactly one entry per supplied "
                                   "discoveryConfiguration, in order; entries returned: "
                                << results.size();
  for (size_t index = 0; index < results.size(); ++index)
  {
    EXPECT_EQ(results[index], ua::StatusCode{ua::Status::BadNotSupported})
      << "every configuration this non-LDS-ME does not interpret must be refused at its own index";
    ASSERT_NE(results[index].shared_detail(), nullptr);
    EXPECT_EQ(results[index].shared_detail()->code, "DiscoveryConfigurationUnsupported");
    ASSERT_EQ(results[index].shared_detail()->context.size(), 1u);
    EXPECT_EQ(results[index].shared_detail()->context[0].key, ua::ContextKeys::operationIndex.value());
    EXPECT_EQ(results[index].shared_detail()->context[0].value, std::to_string(index));
  }

  // Per-configuration refusal does not roll back the registration.
  EXPECT_TRUE(snapshot_contains(harness.store->snapshot(), serverUri))
    << "a registration carrying one known configuration must be recorded even when the others are "
       "unsupported";

  shutdown_store_sync(*harness.store);
  harness.store.reset();
  harness.deps.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// =============================================================================
// CL-UASC-014 - the RequestHeader of an OpenSecureChannel request carries a null
// AuthenticationToken.
//
// Driven end-to-end: a real client ConnectionProtocol over the fake transport (so
// initialise() -> start_open() -> send_message_internal -> drain_outgoing actually runs) with the
// REAL SecurityPolicy doing the encode - no securityPolicyFactory override here, unlike the
// CL-UASC-020 tests above. The bytes asserted on are therefore the bytes the production client puts
// on the wire, recovered from FakeTransportConnection::writes().
// =============================================================================

namespace
{

/// The UASC message header, sequence header and OpenSecureChannelRequest body recovered from one
/// plaintext OPN chunk taken off the wire.
struct DecodedOpnChunk
{
  ua::stack_utils::UaScMessageHeader header;
  ua::stack_utils::SequenceHeader sequenceHeader;
  ExpandedNodeId typeId;
  OpenSecureChannelRequest request;
};

/// Decodes a plaintext OPN chunk. Valid only for SecurityPolicy None, where the OPN body is neither
/// signed nor encrypted, and where the AsymmetricSecurityHeader's sender-certificate field is empty
/// so the header decode never reaches into the supplied Crypto.
DecodedOpnChunk decode_plaintext_opn_chunk(span<const byte> chunk, const Crypto& crypto)
{
  memory_stream_device::ExternalReadOnly streamDevice{chunk};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  EncodingLimits limits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  UaBinaryDecoder dec(factory.resolver(), stream, limits);

  DecodedOpnChunk out;
  out.header.decode(limits, dec);
  ua::stack_utils::AsymmetricSecurityHeader securityHeader;
  securityHeader.decode(limits, dec, crypto);
  out.sequenceHeader.decode(limits, dec);

  auto depth = limits.stack_depth();
  dec.decode(depth, out.typeId);
  dec.decode(depth, out.request);
  return out;
}

}  // namespace

// Part 6 section 6.7.2 (and section 6.7.4): OpenSecureChannel is exchanged before any Session exists, so its
// RequestHeader.AuthenticationToken shall be null. A plausible implementation gets this wrong by
// routing every outgoing service request through one request-header builder - the builder that
// stamps the current Session's authentication token onto MSG requests - which leaks a token from a
// previous Session onto a channel whose security is not yet established, and onto the OPN-Renew of
// an established one. Both OpenSecureChannel construction sites (Issue at channel open, Renew at
// token renewal) are therefore read back off the wire.
// @verifies AC-CL-UASC-014-OPN-NULL-AUTHTOKEN
TEST(ClientSecureChannelShellTests, OpenSecureChannelRequestHeaderCarriesNoAuthenticationToken)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeClientSecureChannelDeps>(tp.get_executor());
  auto wired = make_wired_client_connection(tp.get_executor());

  // SecurityPolicy None keeps the OPN body plaintext so the RequestHeader can be read back with no
  // key material. A distinctive RequestedLifetime is the decode's non-vacuity witness below.
  SecureChannelImpl::Config config;
  config.securityMode = ua::MessageSecurityMode::None;
  config.securityPolicyId = ua::SecurityPolicyId::None;
  config.requestedLifetimeMs = 654321;

  auto impl = SecureChannelImpl::create(
    deps, wired.connection, wired.negotiatedLimits, config, [](VoidResult) {}, [](VoidResult) {});

  // Write 0 is the handshake HEL; write 1 is the client's OpenSecureChannel (Issue) request.
  ASSERT_TRUE(wired.transport->wait_for_write_count(2, 3s)) << "expected HEL + OPN on the transport";
  auto issueWrites = wired.transport->writes();
  ASSERT_GE(issueWrites.size(), 2u);

  auto crypto = create_default_crypto();
  ASSERT_NE(crypto, nullptr);
  auto issued = decode_plaintext_opn_chunk(span<const byte>{issueWrites[1]}, *crypto);

  // Non-vacuity: prove the decode landed on the client's real OPN body rather than on a mis-parsed
  // or default-constructed request, whose AuthenticationToken would read null for free.
  ASSERT_EQ(issued.header.messageType, ua::stack_utils::UaScMessageHeader::MessageType::Open)
    << "write 1 must be the OpenSecureChannel chunk";
  ASSERT_EQ(issued.request.request_type(), ua::SecurityTokenRequestType::Issue);
  ASSERT_EQ(issued.request.requested_lifetime(), 654321u)
    << "the decoded body must be the request this client built, not a mis-parsed one";

  EXPECT_TRUE(issued.request.request_header().authentication_token().is_null())
    << "the OPN-Issue precedes any Session, so its RequestHeader.AuthenticationToken must be null";

  // Second construction site: the OPN-Renew sent for token renewal on an established channel, where
  // a Session may well exist by now. Same obligation - there is still no Session for THIS channel's
  // security handshake to authenticate against.
  STA::strand_barrier(*impl);
  STA::on_strand(*impl, [](auto& g) { g.set_channel_open(42); });
  STA::on_strand(*impl, [](auto& g) { g.handle_token_renewal(); });

  ASSERT_TRUE(wired.transport->wait_for_write_count(3, 3s))
    << "token renewal must put an OpenSecureChannel (Renew) request on the transport";
  auto renewWrites = wired.transport->writes();
  ASSERT_GE(renewWrites.size(), 3u);

  auto renewed = decode_plaintext_opn_chunk(span<const byte>{renewWrites[2]}, *crypto);
  ASSERT_EQ(renewed.header.messageType, ua::stack_utils::UaScMessageHeader::MessageType::Open)
    << "write 2 must be the OpenSecureChannel renewal chunk";
  ASSERT_EQ(renewed.request.request_type(), ua::SecurityTokenRequestType::Renew)
    << "the decoded body must be the renewal request, not a re-read of the Issue";

  EXPECT_TRUE(renewed.request.request_header().authentication_token().is_null())
    << "the OPN-Renew RequestHeader.AuthenticationToken must be null too - the SecureChannel "
       "handshake never carries a Session token";

  impl.reset();
  wired.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}
