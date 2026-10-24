// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_additional_parameters_type.h"
#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_close_session_request.h"
#include "ua_anonymous_identity_token.h"
#include "ua_close_session_response.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_crypto.h"
#include "ua_data_value.h"
#include "ua_endpoint_description.h"
#include "ua_ephemeral_key_type.h"
#include "ua_ecc_encrypted_secret_decoder.h"
#include "ua_localized_text.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_security_policy.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_issued_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_encryption.h"
#include "ua_security_policy_compatibility.h"
#include "ua_signature_data.h"
#include "ua_structure_factory.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "ua_variant.h"
#include "ua_x509_certificate.h"
#include "channel_bound_signature_test_data.h"
#include "run_async_sync.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <iterator>

#include <future>
#include <string_view>
#include <thread>
#include <tuple>

// Test-only access to client session and secure channel internals.
#include "../sdk/implementation/client/session/ua_client_session_test_access.h"
#include "../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"

#include <condition_variable>
#include <mutex>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

namespace
{
// The strand a bound channel always carries. These entry points marshal every continuation onto it -
// they no longer accept not having one - so the pool has to be running for the blocking helpers
// below to ever see an answer.
boost::asio::strand<boost::asio::any_io_executor> crypto_test_strand()
{
  static boost::asio::thread_pool pool{2};
  return boost::asio::make_strand(boost::asio::any_io_executor{pool.get_executor()});
}
}  // namespace

using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;

namespace
{

// Advertises an ANONYMOUS UserTokenPolicy on @p response so anonymous activation resolves a policy
// (CL-IDENT-002: the client now fails fast when no ANONYMOUS policy is advertised). Empty policy_id keeps the
// emitted AnonymousIdentityToken.policyId empty, exactly as before this pre-flight was built. Harmless on a
// create-only response (no activation).
inline void attach_anonymous_policy(ua::CreateSessionResponse& response)
{
  ua::UserTokenPolicy anon;
  anon.token_type() = ua::UserTokenType::Anonymous;
  ua::EndpointDescription endpoint;
  // The endpoint describes the channel it answers on (SecurityPolicy None, mode None): the user-token
  // policies are taken from the endpoint matching the channel, never from the first one listed.
  endpoint.security_mode() = ua::MessageSecurityMode::None;
  endpoint.user_identity_tokens().payload().push_back(anon);
  response.server_endpoints().payload().push_back(std::move(endpoint));
}

using STA = SessionTestAccess;
using SS = STA::SessionState;

class FakeSessionDeps : public SessionDependencies
{
public:
  explicit FakeSessionDeps(boost::asio::any_io_executor ex)
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
    if (serviceTimeoutFailure.is_bad())
      throw UaException{serviceTimeoutFailure};
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return 0;
  }

  StatusCode serviceTimeoutFailure;

private:
  boost::asio::any_io_executor mExecutor;
  ApplicationConfig mAppCfg;
  StructureFactory mFactory;
};

class FakeChannelDeps : public SecureChannelDependencies
{
public:
  explicit FakeChannelDeps(boost::asio::any_io_executor ex)
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

private:
  boost::asio::any_io_executor mExecutor;
  ApplicationConfig mAppCfg;
  StructureFactory mFactory;
};

/// Synchronization state for callbacks.
struct CallbackSync
{
  std::mutex mx;
  std::condition_variable cv;

  bool created{false};
  StatusCode createdStatus{Status::Good};
  bool errorOccurred{false};
  size_t errorCount{0};
  StatusCode errorStatus{Status::Good};
  std::shared_ptr<const ErrorDetail> errorDetail;
  bool closeFired{false};
  StatusCode closeStatus{Status::Good};

  bool wait_created(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return created; });
  }

  bool wait_error(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return errorOccurred; });
  }

  bool wait_close(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return closeFired; });
  }
};

/// Helper: create a SessionImpl with no real connection (test mode).
struct TestSessionSetup
{
  std::shared_ptr<FakeChannelDeps> channelDeps;
  std::shared_ptr<FakeSessionDeps> sessionDeps;
  std::shared_ptr<SecureChannelImpl> channel;
  std::shared_ptr<SessionImpl> session;
  std::shared_ptr<CallbackSync> sync;
  std::shared_ptr<std::vector<std::unique_ptr<Structure>>> capturedRequests;

  /// Drop every executor-pinned shared_ptr so a subsequent pool.join() drains.
  void release()
  {
    session.reset();
    channel.reset();
    sessionDeps.reset();
    channelDeps.reset();
    sync.reset();
    capturedRequests.reset();
  }

  static TestSessionSetup create(boost::asio::any_io_executor ex, SessionImpl::Config sessionConfig = {})
  {
    TestSessionSetup s;
    s.channelDeps = std::make_shared<FakeChannelDeps>(ex);
    s.sessionDeps = std::make_shared<FakeSessionDeps>(ex);
    s.sync = std::make_shared<CallbackSync>();

    // Create a SecureChannel in test mode (no connection).
    s.channel = SecureChannelImpl::create(
      s.channelDeps,
      nullptr,  // No connection (test mode)
      ua::connection_protocol::NegotiatedLimits{},
      SecureChannelImpl::Config{},
      [](VoidResult) {},
      [](VoidResult) {});

    // Force the channel to open state so session requests can pass through.
    SecureChannelTestAccess::on_strand(
      *s.channel, [](auto& g) { g.channel_state() = SecureChannelImpl::ChannelState::Open; });

    s.capturedRequests = std::make_shared<std::vector<std::unique_ptr<Structure>>>();
    auto capturedRequests = s.capturedRequests;
    SecureChannelTestAccess::on_strand(*s.channel,
      [capturedRequests](auto& g)
      {
        g.outgoing_request_observer() = [capturedRequests](const Structure& request)
        {
          capturedRequests->push_back(request.clone());
        };
      });

    auto syncPtr = s.sync;
    s.session = SessionImpl::create(
      s.sessionDeps,
      s.channel,
      std::move(sessionConfig),
      SessionImpl::SecurityInfo{},
      [syncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->created = true;
          syncPtr->createdStatus = result.status_code();
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          ++syncPtr->errorCount;
          syncPtr->errorStatus = result.status_code();
          syncPtr->errorDetail = result.shared_detail();
        }
        syncPtr->cv.notify_one();
      });

    return s;
  }

  template<typename RequestT>
  std::vector<RequestT> captured()
  {
    return SecureChannelTestAccess::on_strand(*channel,
      [this](auto&)
      {
        std::vector<RequestT> requests;
        for (const auto& request : *capturedRequests)
        {
          if (const auto* typed = dynamic_cast<const RequestT*>(request.get()))
            requests.push_back(*typed);
        }
        return requests;
      });
  }

  /// Helper to inject a channel error on the session's strand and wait.
  void inject_channel_error_sync(StatusCode status)
  {
    STA::on_strand(*session, [status](auto& g) { g.inject_channel_error(status); });
  }

  /// Helper to read session state on the strand.
  SS read_state_on_strand()
  {
    return STA::on_strand(*session, [](auto& g) { return g.session_state(); });
  }

  /// Helper to set session active on strand (safe from data races).
  void set_active_on_strand(
    ua::NodeId sessionId = ua::NodeId{1, 100}, ua::NodeId authToken = ua::NodeId{1, 200})
  {
    STA::on_strand(*session,
      [sessionId = std::move(sessionId), authToken = std::move(authToken)](auto& g) mutable
      { g.set_session_active(std::move(sessionId), std::move(authToken)); });
  }

  /// Helper to set session created on strand (safe from data races).
  void set_created_on_strand(
    ua::NodeId sessionId = ua::NodeId{1, 100}, ua::NodeId authToken = ua::NodeId{1, 200})
  {
    STA::on_strand(*session,
      [sessionId = std::move(sessionId), authToken = std::move(authToken)](auto& g) mutable
      { g.set_session_created(std::move(sessionId), std::move(authToken)); });
  }

  /// Helper to set session state on strand (safe from data races).
  void set_state_on_strand(SS state)
  {
    STA::on_strand(*session, [state](auto& g) { g.set_session_state(state); });
  }

  /// Helper to inject a synthetic response into the session via the channel's pending requests.
  /// The session's create_session_internal() coroutine sends a request through the channel,
  /// which stores the response callback in SecureChannelImpl::mPendingRequests. This helper
  /// finds that callback and invokes it with the given response, causing the coroutine to resume
  /// and process the response through the real code path.
  bool inject_channel_response(std::shared_ptr<ua::Structure> response)
  {
    return SecureChannelTestAccess::on_strand(*channel,
      [resp = std::move(response)](auto& g) mutable
      {
        auto& pending = g.pending_requests();
        if (!pending.empty())
        {
          auto it = pending.begin();
          auto callback = std::move(it->second);
          pending.erase(it);
          callback(SecureChannelImpl::ServiceResponseResult{std::move(resp)});
          return true;
        }
        return false;
      });
  }

  /// Complete the auto-started CreateSession handshake on a None channel so the create coroutine's own
  /// request does NOT linger in the channel's pending map. create() auto-starts create_session_internal(),
  /// which parks a CreateSessionRequest; a test that then forces Active (set_active_on_strand) and grabs
  /// pending.begin() could otherwise hit that leftover instead of its own request (the pending map is
  /// unordered). Call this before forcing Active whenever the test subsequently targets a single pending
  /// request. Returns true once the session reaches Created.
  bool complete_none_create(
    ua::NodeId sessionId = ua::NodeId{1, 42}, ua::NodeId authToken = ua::NodeId{1, 99})
  {
    if (!wait_for_pending_request())
    {
      return false;
    }
    auto createResponse = std::make_shared<CreateSessionResponse>();
    createResponse->response_header().service_result() = Status::Good;
    createResponse->session_id() = std::move(sessionId);
    createResponse->authentication_token() = std::move(authToken);
    createResponse->revised_session_timeout() = 600000.0;
    if (!inject_channel_response(std::move(createResponse)))
    {
      return false;
    }
    return sync->wait_created(1000ms);
  }

  /// Wait for a pending request to appear in the channel's pending map.
  /// Returns true if a request appeared within the timeout.
  bool wait_for_pending_request(std::chrono::milliseconds timeout = 500ms)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      bool found =
        SecureChannelTestAccess::on_strand(*channel, [](auto& g) { return !g.pending_requests().empty(); });
      if (found)
        return true;
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }

  /// Drive the session to Closed and break the strong-self cycle in any in-progress
  /// internal coroutine. The internal coroutines (create/activate/close) capture
  /// shared_from_this() so that user callbacks cannot drop the last external reference
  /// mid-execution; that capture forms a cycle with mActiveTask which only releases
  /// when handle_session_closed posts mActiveTask.reset() on the strand. Tests must
  /// call this before the boost::asio::thread_pool is aborted, otherwise the posted reset is dropped
  /// and the SessionImpl + entire object graph leaks.
  ///
  /// The session's create/activate/close coroutines suspend on responses stored in the
  /// CHANNEL's pending-requests map (not the session's). handle_session_error only
  /// fails session-level pending (subscriptions etc.), so a session-level channel error
  /// is not enough to resume those coroutines.
  ///
  /// Step 1: fail any channel-side pending requests so awaiting coroutines resume,
  /// propagate the error through to handle_session_closed, and queue mActiveTask.reset().
  /// Step 2: drive any remaining non-terminal state to Closed via session-level
  /// injection. Two injects handle the Active/Created path: first transitions to
  /// Disconnected, second drives Disconnected->Closed through the non-recoverable path
  /// that calls handle_session_closed and posts mActiveTask.reset().
  /// Step 3: drain the strand so the posted resets run before the pool is aborted.
  void cleanup_sync()
  {
    if (!session)
      return;
    // Step 1: fail any channel-side pending requests.
    SecureChannelTestAccess::on_strand(*channel,
      [](auto& g)
      {
        auto pending = std::move(g.pending_requests());
        g.pending_requests().clear();
        for (auto& [handle, callback] : pending)
        {
          callback(SecureChannelImpl::ServiceResponseResult{Status::BadConnectionClosed});
        }
      });

    // Step 2: drive any remaining non-terminal state to Closed via session-level injection.
    auto state = read_state_on_strand();
    if (state != SS::Closed && state != SS::Idle)
    {
      inject_channel_error_sync(Status::BadConnectionClosed);
      inject_channel_error_sync(Status::BadConnectionClosed);
    }

    // Step 3: drain the strand so the posted mActiveTask.reset() runs.
    STA::strand_barrier(*session);
  }
};

}  // namespace

// =============================================================================
// Construction and lifecycle tests
// =============================================================================

TEST(ClientSessionShellTests, CreateWithNullConnectionDoesNotCrash)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // The session impl should start in Creating state (logic sent SendCreateSessionRequest).
  EXPECT_FALSE(setup.session->is_active());
  EXPECT_FALSE(setup.session->is_created());
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Create flow
// =============================================================================

// 1. CreateTransitionsToCreating
// After SessionImpl::create(), the session transitions to Creating and sends a
// CreateSessionRequest through the channel. We verify by reading the strand-local
// state which should be Creating (the coroutine is suspended awaiting a response
// from the channel, which has no real connection).
TEST(ClientSessionShellTests, CreateTransitionsToCreating)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // The session was created and the create coroutine was started on the strand.
  // It will transition to Creating and then send a CreateSessionRequest, which
  // blocks at co_await because the null-connection channel never delivers a response.
  // Read the state on strand to verify it entered Creating.
  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Creating);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 2. CreateWhenNotIdleEmitsError - tested indirectly: a second create call is not
// possible because create() is only called from SessionImpl::create() factory.
// Instead we verify that calling activate from an invalid state returns an error.
// (The SessionImpl factory is the only entry point for create, so double-create is
// not reachable through the public API.)

// 4. GoodCreateResponseTransitionsToCreated
// Inject a CreateSessionResponse through the real processing path and verify the
// session transitions to Created.
TEST(ClientSessionShellTests, GoodCreateResponseTransitionsToCreated)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // The session is in Creating state with a pending CreateSessionRequest in the channel.
  ASSERT_TRUE(setup.wait_for_pending_request()) << "CreateSessionRequest should be pending in channel";

  // Inject a good CreateSessionResponse.
  auto response = std::make_shared<ua::CreateSessionResponse>();
  response->response_header().service_result() = Status::Good;
  response->session_id() = NodeId{1, 42};
  response->authentication_token() = NodeId{1, 99};
  response->revised_session_timeout() = 600000.0;
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  // Wait for the session strand to process the response.
  std::this_thread::sleep_for(50ms);

  EXPECT_TRUE(setup.session->is_created());
  EXPECT_FALSE(setup.session->is_active());
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 5. GoodCreateResponseStoresSessionState
// Inject a CreateSessionResponse with known IDs and verify they are stored.
// @verifies CL-SESS-005: no discovery evidence was supplied, so endpoint-set comparison is skipped.
// @relation(CL-SESS-005, scope=function)
TEST(ClientSessionShellTests, GoodCreateResponseStoresSessionState)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = std::make_shared<ua::CreateSessionResponse>();
  response->response_header().service_result() = Status::Good;
  response->session_id() = NodeId{1, 42};
  response->authentication_token() = NodeId{1, 99};
  response->revised_session_timeout() = 30000.0;
  response->server_nonce() = ByteString{std::vector<std::byte>{std::byte{0xCA}, std::byte{0xFE}}};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  std::this_thread::sleep_for(50ms);

  EXPECT_EQ(setup.session->session_id(), NodeId(1, 42));
  EXPECT_EQ(setup.session->authentication_token(), NodeId(1, 99));
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 6. BadCreateResponseClosesSession
// When the create handshake receives a channel error, the session transitions
// to Closed and invokes the error callback.
TEST(ClientSessionShellTests, BadCreateResponseClosesSession)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // The session is stuck in Creating (awaiting a response from the null-connection
  // channel). Inject a channel error to simulate a bad response/connection failure.
  setup.inject_channel_error_sync(Status::BadTooManySessions);

  // Error callback should have been invoked.
  ASSERT_TRUE(setup.sync->wait_error(500ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTooManySessions);

  // Session should be in Closed state after the failed create.
  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Activate flow
// =============================================================================

// 7. ActivateRequestedFromCreatedTransitionsFromCreated
TEST(ClientSessionShellTests, ActivateRequestedFromCreatedTransitionsFromCreated)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_created_on_strand(NodeId{1, 42}, NodeId{1, 99});

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
      }
      cv.notify_one();
    });

  // Give the strand time to process. The activate will send a request which may fail
  // due to null connection, but it must not crash and must transition through Activating.
  std::this_thread::sleep_for(100ms);

  // Verify the session transitioned out of Created state (into Activating or beyond).
  auto state = STA::on_strand(*setup.session, [](auto& g) { return g.session_state(); });
  EXPECT_NE(state, SS::Created) << "Session should transition from Created to Activating";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 8. ActivateRequestedFromIdleIsIgnored
TEST(ClientSessionShellTests, ActivateRequestedFromIdleIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Idle state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Idle); });

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult r)
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

  EXPECT_EQ(resultStatus, Status::BadInvalidState);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 9. ActivateRequestedFromActiveTransitionsToActivating (re-activation)
TEST(ClientSessionShellTests, ActivateRequestedFromActiveTransitionsToActivating)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_active_on_strand(NodeId{1, 42}, NodeId{1, 99});

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
      }
      cv.notify_one();
    });

  // Give strand time to pick up the activate. It should transition to Activating.
  std::this_thread::sleep_for(100ms);

  // Verify re-activation was dispatched (session should not remain in Active).
  auto state = STA::on_strand(*setup.session, [](auto& g) { return g.session_state(); });
  // With null connection the activate coroutine will fail (channel error), so the session
  // should land in Closed. The key assertion is that re-activation was dispatched (state
  // moved out of Active).
  EXPECT_NE(state, SS::Active) << "Re-activation should transition out of Active; got: "
                               << static_cast<int>(state);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 11. GoodActivateResponseTransitionsToActive
// Inject a CreateSessionResponse to reach Created, then call activate, then inject an
// ActivateSessionResponse. Verify the session transitions to Active.
TEST(ClientSessionShellTests, GoodActivateResponseTransitionsToActive)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Stage 1: Inject CreateSessionResponse to reach Created state.
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  attach_anonymous_policy(*createResp);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResp)));
  std::this_thread::sleep_for(50ms);
  ASSERT_TRUE(setup.session->is_created());

  // Stage 2: Start activate.
  std::mutex mx;
  std::condition_variable cv;
  bool activateDone{false};
  StatusCode activateStatus{Status::BadInternalError};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        activateDone = true;
        activateStatus = r.status_code();
      }
      cv.notify_one();
    });

  // Stage 3: Inject ActivateSessionResponse.
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResp = std::make_shared<ua::ActivateSessionResponse>();
  activateResp->response_header().service_result() = Status::Good;
  activateResp->server_nonce() = ByteString{std::vector<std::byte>{std::byte{0xBE}, std::byte{0xEF}}};
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResp)));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return activateDone; }));
  }

  EXPECT_TRUE(activateStatus.is_good());
  EXPECT_TRUE(setup.session->is_active());
  EXPECT_EQ(setup.session->session_id(), NodeId(1, 42));
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A CreateSession response's Good subcode reaches the creation callback, and an ActivateSession response's
// Good subcode reaches the activation callback, rather than a plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientSessionShellTests, CreateAndActivateResponseGoodSubcodesReachTheirCallbacks)
{
  for (const ua::Status createStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{createStatus}.value());
    for (const ua::Status activateResponseStatus :
      {ua::Status::GoodPasswordChangeRequired, ua::Status::GoodLocalOverride})
    {
      SCOPED_TRACE(ua::StatusCode{activateResponseStatus}.value());
      boost::asio::thread_pool tp;
      auto setup = TestSessionSetup::create(tp.get_executor());

      ASSERT_TRUE(setup.wait_for_pending_request());
      auto createResp = std::make_shared<ua::CreateSessionResponse>();
      createResp->response_header().service_result() = StatusCode{createStatus};
      createResp->session_id() = NodeId{1, 42};
      createResp->authentication_token() = NodeId{1, 99};
      attach_anonymous_policy(*createResp);
      ASSERT_TRUE(setup.inject_channel_response(std::move(createResp)));
      ASSERT_TRUE(setup.sync->wait_created());
      {
        std::lock_guard<std::mutex> lk(setup.sync->mx);
        EXPECT_EQ(setup.sync->createdStatus.value(), StatusCode{createStatus}.value());
      }
      ASSERT_TRUE(setup.session->is_created());
      EXPECT_EQ(setup.session->session_id(), (NodeId{1, 42}));

      std::mutex mx;
      std::condition_variable cv;
      bool activateDone{false};
      StatusCode activateStatus{Status::BadInternalError};
      setup.session->activate(Session::ActivateConfig{},
        [&](VoidResult r)
        {
          {
            std::lock_guard<std::mutex> lk(mx);
            activateDone = true;
            activateStatus = r.status_code();
          }
          cv.notify_one();
        });

      ASSERT_TRUE(setup.wait_for_pending_request());
      auto activateResp = std::make_shared<ua::ActivateSessionResponse>();
      activateResp->response_header().service_result() = StatusCode{activateResponseStatus};
      ASSERT_TRUE(setup.inject_channel_response(std::move(activateResp)));
      {
        std::unique_lock<std::mutex> lk(mx);
        ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return activateDone; }));
      }

      EXPECT_EQ(activateStatus.value(), StatusCode{activateResponseStatus}.value());
      EXPECT_TRUE(setup.session->is_active());
      EXPECT_EQ(setup.session->session_id(), (NodeId{1, 42}));
      setup.cleanup_sync();
      setup.release();
      ::ua::test_utils::drain_with_timeout(tp);
    }
  }
}

// A CloseSession response's Good subcode reaches the close callback.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientSessionShellTests, CloseResponseGoodSubcodeReachesTheCloseCallback)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    boost::asio::thread_pool tp;
    auto setup = TestSessionSetup::create(tp.get_executor());
    ASSERT_TRUE(setup.complete_none_create()) << "the CreateSession request no longer waits in the channel";
    setup.set_active_on_strand();

    std::mutex mx;
    std::condition_variable cv;
    bool closeFired{false};
    StatusCode closeStatus{Status::BadInternalError};
    setup.session->close(
      [&](VoidResult r)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          closeFired = true;
          closeStatus = r.status_code();
        }
        cv.notify_one();
      });

    ASSERT_TRUE(setup.wait_for_pending_request());
    auto closeResp = std::make_shared<ua::CloseSessionResponse>();
    closeResp->response_header().service_result() = StatusCode{serviceStatus};
    ASSERT_TRUE(setup.inject_channel_response(std::move(closeResp)));
    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return closeFired; }));
    }

    EXPECT_EQ(closeStatus.value(), StatusCode{serviceStatus}.value());
    EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);
    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// 12. GoodActivateResponseUpdatesServerNonce
// Inject a CreateSessionResponse, then activate with an ActivateSessionResponse that
// contains a known nonce. Verify the nonce was stored.
TEST(ClientSessionShellTests, GoodActivateResponseUpdatesServerNonce)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Stage 1: Inject CreateSessionResponse to reach Created state.
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  attach_anonymous_policy(*createResp);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResp)));
  std::this_thread::sleep_for(50ms);
  ASSERT_TRUE(setup.session->is_created());

  // Stage 2: Start activate.
  std::mutex mx;
  std::condition_variable cv;
  bool activateDone{false};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        activateDone = true;
      }
      cv.notify_one();
    });

  // Stage 3: Inject ActivateSessionResponse with a known nonce.
  ByteString expectedNonce{std::vector<std::byte>{std::byte{0xCA}, std::byte{0xFE}}};
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResp = std::make_shared<ua::ActivateSessionResponse>();
  activateResp->response_header().service_result() = Status::Good;
  activateResp->server_nonce() = expectedNonce;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResp)));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return activateDone; }));
  }

  ASSERT_TRUE(setup.session->is_active());

  // Verify the nonce from the response was stored.
  auto actualNonce = STA::on_strand(*setup.session, [](auto& g) { return g.server_nonce(); });
  EXPECT_EQ(actualNonce, expectedNonce);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 13. GoodActivateResponseZeroTimeoutNoTimer
// When the revised session timeout is 0, no timeout timer should be scheduled.
// Inject CreateSessionResponse with timeout=0, then activate, verify no timer.
TEST(ClientSessionShellTests, GoodActivateResponseZeroTimeoutNoTimer)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Stage 1: Inject CreateSessionResponse with zero timeout.
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = 0.0;
  attach_anonymous_policy(*createResp);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResp)));
  std::this_thread::sleep_for(50ms);
  ASSERT_TRUE(setup.session->is_created());

  // Verify the revised timeout was stored as 0.
  auto revisedTimeout =
    STA::on_strand(*setup.session, [](auto& g) { return g.revised_session_timeout_ms(); });
  EXPECT_DOUBLE_EQ(revisedTimeout, 0.0);

  // Stage 2: Activate.
  std::mutex mx;
  std::condition_variable cv;
  bool activateDone{false};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        activateDone = true;
      }
      cv.notify_one();
    });

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResp = std::make_shared<ua::ActivateSessionResponse>();
  activateResp->response_header().service_result() = Status::Good;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResp)));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return activateDone; }));
  }

  ASSERT_TRUE(setup.session->is_active());

  // Verify no timeout timer was scheduled (timeout is 0).
  auto timerSet =
    STA::on_strand(*setup.session, [](auto& g) { return static_cast<bool>(g.timeout_timer()); });
  EXPECT_FALSE(timerSet) << "No timeout timer should be scheduled when revised timeout is 0";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 14. BadActivateResponseClosesSession
// When activate receives a channel error, the session transitions to Closed and the
// activate callback receives a bad status.
TEST(ClientSessionShellTests, BadActivateResponseClosesSession)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_created_on_strand(NodeId{1, 42}, NodeId{1, 99});

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
      }
      cv.notify_one();
    });

  // Give strand time to transition to Activating and start the coroutine.
  std::this_thread::sleep_for(50ms);

  // Inject channel error to fail the in-progress activate.
  setup.inject_channel_error_sync(Status::BadIdentityTokenInvalid);

  // The activate callback should fire with the error.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return callbackFired; }));
  }

  EXPECT_TRUE(resultStatus.is_bad());

  // Session should be in Closed state after the failed activate.
  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Close per state
// =============================================================================

// 15. CloseWhileActiveTransitionsToClosing
TEST(ClientSessionShellTests, CloseWhileActiveTransitionsToClosing)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_active_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.session->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  // Give strand time to process. The close sends a CloseSessionRequest through
  // the channel, which won't get a response in test mode - but it must not crash.
  std::this_thread::sleep_for(100ms);

  // Verify the session transitioned from Active toward closing.
  auto state = STA::on_strand(*setup.session, [](auto& g) { return g.session_state(); });
  EXPECT_TRUE(state == SS::Closing || state == SS::Closed)
    << "Close should transition from Active to Closing/Closed; got: " << static_cast<int>(state);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 16. CloseWhileCreatedEmitsSendCloseRequest
TEST(ClientSessionShellTests, CloseWhileCreatedTransitionsToClosing)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_created_on_strand();

  setup.session->close([](VoidResult) {});

  std::this_thread::sleep_for(100ms);

  auto state = STA::on_strand(*setup.session, [](auto& g) { return g.session_state(); });
  EXPECT_TRUE(state == SS::Closing || state == SS::Closed)
    << "Close from Created should transition to Closing/Closed; got: " << static_cast<int>(state);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 17. CloseWhileCreatingEmitsSessionClosed
TEST(ClientSessionShellTests, CloseWhileCreatingEmitsSessionClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Creating state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Creating); });

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.session->close(
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

  // Session should be closed.
  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 18. CloseWhileIdleEmitsSessionClosed
TEST(ClientSessionShellTests, CloseWhileIdleEmitsSessionClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Idle state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Idle); });

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.session->close(
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

  EXPECT_EQ(closeStatus, Status::Good);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 19. CloseWhileActivatingEmitsSessionClosed
TEST(ClientSessionShellTests, CloseWhileActivatingEmitsSessionClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Activating state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Activating); });

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.session->close(
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

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 20. CloseWhileClosingIsNoOp
TEST(ClientSessionShellTests, CloseWhileClosingIsNoOp)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Closing state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Closing); });

  // Issue a close - it should go through the Closing branch (no-op in close_internal).
  setup.session->close([](VoidResult) {});

  // Drain the strand to ensure the close post has been processed.
  STA::strand_barrier(*setup.session);

  // Session should still be in Closing state (not advanced to Closed by this call).
  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closing);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 21. CloseWhileClosedEmitsSessionClosed
TEST(ClientSessionShellTests, CloseWhileClosedEmitsSessionClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Closed state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Closed); });

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.session->close(
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

  EXPECT_EQ(closeStatus, Status::Good);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Close response
// =============================================================================

// 22. GoodCloseResponseTransitionsToClosed
// When close is called from Active, a CloseSessionRequest is sent. When the response
// arrives (or fails), the session transitions to Closed.
TEST(ClientSessionShellTests, GoodCloseResponseTransitionsToClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_active_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  StatusCode closeStatus{Status::BadInternalError};

  setup.session->close(
    [&](VoidResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
        closeStatus = r.status_code();
      }
      cv.notify_one();
    });

  // The close sends a CloseSessionRequest through the channel. With a null connection
  // the request will hang, so inject a channel error to force completion.
  std::this_thread::sleep_for(50ms);
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return closeFired; }));
  }

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 23. CloseFromInitialStateTransitionsToClosed
// Close from the initial Creating state (no session established on wire) still transitions
// to Closed and invokes callback via handle_session_closed.
TEST(ClientSessionShellTests, CloseFromInitialStateTransitionsToClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Session is in Idle state (not created/active). close_internal handles this by
  // calling handle_session_closed(Good) immediately.
  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};

  setup.session->close(
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return closeFired; }));
  }

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Channel error per state
// =============================================================================

// 24. ChannelErrorWhileCreatingClosesSession
TEST(ClientSessionShellTests, ChannelErrorWhileCreatingClosesSession)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Creating state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Creating); });

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);

  // Error callback should have been invoked.
  ASSERT_TRUE(setup.sync->wait_error(500ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadConnectionClosed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 25. ChannelErrorWhileCreatedTransitionsToDisconnected
TEST(ClientSessionShellTests, ChannelErrorWhileCreatedTransitionsToDisconnected)
{
  // Spec: Part 4, 6.7 - Created sessions are recoverable; transition to Disconnected.
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.set_created_on_strand(NodeId{1, 42}, NodeId{1, 99});

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Disconnected);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 26. ChannelErrorWhileActivatingClosesSession
TEST(ClientSessionShellTests, ChannelErrorWhileActivatingClosesSession)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Activating state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Activating); });

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);

  // Error callback should have been invoked for non-active/non-closing states.
  ASSERT_TRUE(setup.sync->wait_error(500ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadConnectionClosed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 27. ChannelErrorWhileActiveTransitionsToDisconnected
TEST(ClientSessionShellTests, ChannelErrorWhileActiveTransitionsToDisconnected)
{
  // Spec: Part 4, 6.7 - Active sessions are recoverable; transition to Disconnected.
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Set active on strand, then clear error state on strand to avoid races with the
  // initial create coroutine which may fire the error callback asynchronously.
  auto syncPtr = setup.sync;
  STA::on_strand(*setup.session,
    [syncPtr](auto& g)
    {
      g.set_session_active(NodeId{1, 42}, NodeId{1, 99});
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->errorOccurred = false;
        syncPtr->errorStatus = Status::Good;
      }
    });

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Disconnected);

  // Disconnected should not fire the error callback - the session is not dead.
  STA::strand_barrier(*setup.session);
  EXPECT_FALSE(setup.sync->errorOccurred)
    << "Error callback must not fire for Active -> Disconnected transition";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 28. ChannelErrorWhileClosingClosesWithoutSessionError
TEST(ClientSessionShellTests, ChannelErrorWhileClosingClosesWithoutSessionError)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Clear any previous error state.
  {
    std::lock_guard<std::mutex> lk(setup.sync->mx);
    setup.sync->errorOccurred = false;
    setup.sync->errorStatus = Status::Good;
  }

  // Force to Closing state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Closing); });

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);

  // For Closing state, no SessionError is emitted (only SessionClosed).
  // Drain the strand to ensure all posted work has completed.
  STA::strand_barrier(*setup.session);
  EXPECT_FALSE(setup.sync->errorOccurred) << "Error callback must not fire for Closing -> Closed transition";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 29. ChannelErrorWhileIdleIsIgnored
TEST(ClientSessionShellTests, ChannelErrorWhileIdleIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Idle state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Idle); });

  // Clear previous error.
  {
    std::lock_guard<std::mutex> lk(setup.sync->mx);
    setup.sync->errorOccurred = false;
  }

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Idle);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 30. ChannelErrorWhileClosedIsIgnored
TEST(ClientSessionShellTests, ChannelErrorWhileClosedIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force to Closed state.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Closed); });

  // Clear previous error.
  {
    std::lock_guard<std::mutex> lk(setup.sync->mx);
    setup.sync->errorOccurred = false;
  }

  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Closed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Session timeout
// =============================================================================

// =============================================================================
// Spurious response handling (events in unexpected states)
// =============================================================================

// 34. CreateResponseWhileIdleIsIgnored
// Force the session to Idle (overriding Creating), then deliver the pending
// CreateSessionResponse. The coroutine checks mSessionState != Creating and returns
// without processing the response.
TEST(ClientSessionShellTests, CreateResponseWhileIdleIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Wait for the create request to be pending, then force state to Idle.
  ASSERT_TRUE(setup.wait_for_pending_request());
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Idle); });

  // Inject a good CreateSessionResponse - should be ignored because state is Idle.
  auto response = std::make_shared<ua::CreateSessionResponse>();
  response->response_header().service_result() = Status::Good;
  response->session_id() = NodeId{1, 42};
  response->authentication_token() = NodeId{1, 99};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  std::this_thread::sleep_for(50ms);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Idle) << "CreateSessionResponse while Idle must be ignored";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 35. CreateResponseWhileActiveIsIgnored
// Force the session to Active (overriding Creating), then deliver the pending
// CreateSessionResponse. The coroutine checks mSessionState != Creating and returns
// without processing the response.
TEST(ClientSessionShellTests, CreateResponseWhileActiveIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Wait for the create request to be pending, then force state to Active.
  ASSERT_TRUE(setup.wait_for_pending_request());
  setup.set_active_on_strand(NodeId{1, 42}, NodeId{1, 99});

  // Inject a CreateSessionResponse with different IDs - should be ignored.
  auto response = std::make_shared<ua::CreateSessionResponse>();
  response->response_header().service_result() = Status::Good;
  response->session_id() = NodeId{1, 999};
  response->authentication_token() = NodeId{1, 888};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  std::this_thread::sleep_for(50ms);

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Active) << "CreateSessionResponse while Active must be ignored";
  // Verify the session IDs were NOT overwritten by the spurious response.
  EXPECT_EQ(setup.session->session_id(), NodeId(1, 42));
  EXPECT_TRUE(setup.session->is_active());
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// 36. ActivateResponseWhileCreatingIsIgnored
// Architecture note: spurious ActivateSessionResponses cannot reach the session in
// Creating state because no activate coroutine is running and therefore no activate
// request callback is pending in the channel's request map. The coroutine-based design
// (callback_to_task) ensures only the coroutine that sent a request can receive its
// response - making spurious cross-type responses architecturally impossible.
// This test verifies the state invariant by delivering the pending CREATE response
// (the only response that CAN arrive) and confirming it does not result in Active state.
TEST(ClientSessionShellTests, ActivateResponseWhileCreatingIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  auto state = setup.read_state_on_strand();
  EXPECT_EQ(state, SS::Creating) << "Session should be in Creating state initially";

  // The pending response is for CreateSession, not ActivateSession. Delivering an
  // error response keeps us in a consistent state (Closed), demonstrating that only
  // create responses are processed while Creating.
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = std::make_shared<ua::CreateSessionResponse>();
  response->response_header().service_result() = Status::BadTooManySessions;
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  std::this_thread::sleep_for(50ms);

  auto finalState = setup.read_state_on_strand();
  EXPECT_NE(finalState, SS::Active) << "Must not transition to Active from Creating";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Original tests (retained)
// =============================================================================

TEST(ClientSessionShellTests, ActivateWhenNotCreatedReturnsBadInvalidState)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult r)
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

  EXPECT_EQ(resultStatus, Status::BadInvalidState);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSessionShellTests, CloseWhenNotActiveDoesNotCrash)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  setup.session->close([](VoidResult) {});

  std::this_thread::sleep_for(100ms);

  // Verify session remains in a consistent state (Idle or Closed).
  auto state = STA::on_strand(*setup.session, [](auto& g) { return g.session_state(); });
  EXPECT_TRUE(state == SS::Idle || state == SS::Closed)
    << "Close from Idle should stay Idle or go to Closed; got: " << static_cast<int>(state);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Send request when not active ---

// @verifies CL-SESS-009 (PARTIAL): drives the client-side ordering guard - a non-CloseSession
// service (ReadRequest) issued before the session reaches Active is rejected LOCALLY with
// Bad_SessionClosed via SessionImpl::send_request's `mSessionState != SessionState::Active` branch
// (NOT the dead-session Bad_SessionIdInvalid guard). Deferred: the "other than CloseSession"
// carve-out (CloseSession must be permitted pre-activation) is not asserted here; and the session
// is in Creating rather than the precise Created (post-CreateSession) state - the guard is
// state-uniform across all non-Active states, so the same production branch is exercised.
// @verifies CL-SESS-019 (PARTIAL): drives the real tier-0 send_request gate in
// SessionImpl::send_request (ua_client_session_impl.cpp:1489) - on a non-Active
// (Creating) session the request is rejected locally with BadSessionClosed via the
// mSessionState != Active branch, before the channel is ever touched.
// Scope: verifies the local BadSessionClosed rejection on a non-Active session.
// Does NOT separately assert the "(no wire round-trip)" facet (that no request is
// forwarded to the channel / no PDU is emitted) - deferred to integration
// SessionActivationGate.ReadBeforeActivateReturnsBadSessionNotActivated.
// @relation(CL-SESS-009, CL-SESS-019, scope=function)
TEST(ClientSessionShellTests, SendRequestWhenNotActiveReturnsBadSessionClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.session->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SessionImpl::ServiceResponseResult r)
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

  EXPECT_EQ(resultStatus, Status::BadSessionClosed);
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Channel error propagation ---

TEST(ClientSessionShellTests, ChannelErrorFailsPendingRequests)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Force session active and register a pending request.
  setup.set_active_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool callbackFired{false};
  StatusCode resultStatus{Status::Good};

  setup.session->send_request(std::make_shared<ua::ReadRequest>(),
    [&](SessionImpl::ServiceResponseResult r)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        callbackFired = true;
        resultStatus = r.status_code();
      }
      cv.notify_one();
    });

  // Give strand time to process the send.
  std::this_thread::sleep_for(50ms);

  // Inject channel error using strand-safe helper.
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return callbackFired; }));
  }

  EXPECT_TRUE(resultStatus.is_bad());
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Test #104: Session keep-alive timer scheduled after activation
// =============================================================================

TEST(ClientSessionShellTests, SessionKeepAliveScheduledAfterActivation)
{
  // Spec: Part 4, 5.6.2 - Client shall keep the session alive by issuing
  // service calls before the session timeout expires.
  // Verify that full create->activate with non-zero revised timeout schedules the timer.
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Stage 1: Inject CreateSessionResponse with non-zero timeout.
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = 30000.0;
  attach_anonymous_policy(*createResp);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResp)));
  std::this_thread::sleep_for(50ms);
  ASSERT_TRUE(setup.session->is_created());

  // Stage 2: Activate.
  std::mutex mx;
  std::condition_variable cv;
  bool activateDone{false};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        activateDone = true;
      }
      cv.notify_one();
    });

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResp = std::make_shared<ua::ActivateSessionResponse>();
  activateResp->response_header().service_result() = Status::Good;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResp)));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return activateDone; }));
  }

  ASSERT_TRUE(setup.session->is_active());

  // Verify the timeout timer was scheduled via the production activation path.
  auto timerSet =
    STA::on_strand(*setup.session, [](auto& g) { return static_cast<bool>(g.timeout_timer()); });

  EXPECT_TRUE(timerSet) << "Timeout timer must be scheduled for non-zero revised session timeout";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// FU-1 (project_session_accessor_blocks_on_closed): a service-set accessor is a cheap handle and a sync
// service op on a CLOSED session must FAST-FAIL Bad_SessionClosed, never deadlock. send_request's strand
// body fast-fails when the session is not Active (it never enqueues a pending request whose callback would
// otherwise be the only thing that could release the sync wait), so try_read_sync's f.get() returns
// promptly. The watchdog thread + wait_for bounds the assertion so a regression (a dropped callback that
// makes the sync path hang forever) FAILS the test instead of hanging the suite.
TEST(ClientSessionShellTests, SyncServiceOpOnClosedSessionFastFailsInsteadOfHanging)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Drive the session cleanly to the lifecycle-terminal Closed state (fails the in-flight create, cancels
  // its timer, and settles the strand) - as a real close / timeout would leave it.
  setup.cleanup_sync();
  ASSERT_EQ(setup.read_state_on_strand(), SS::Closed);

  {
    // Wrap the harness impl in the public Session handle - the exact FU-1 surface. Inner scope so the handle
    // (a co-owner of the impl) is dropped before the pool is drained.
    Session session = STA::wrap(setup.session);

    // The service-set accessors are cheap handle constructors - grabbing them must not block or throw on a
    // live (non-null) impl, even when the session is Closed.
    EXPECT_NO_THROW({
      (void)session.attributes();
      (void)session.view();
      (void)session.methods();
      (void)session.subscriptions();
      (void)session.monitored_items();
    });

    // The sync op must return promptly with Bad_SessionClosed, NOT hang. Run it on a watchdog thread so a
    // regression that makes the sync path deadlock fails the assertion rather than wedging the whole suite.
    std::future<ua::Result<ua::ReadResponse>> readResult = std::async(std::launch::async,
      [&session]() -> ua::Result<ua::ReadResponse>
      { return session.attributes().try_read_sync(ua::ReadRequest{}); });
    ASSERT_EQ(readResult.wait_for(3s), std::future_status::ready)
      << "try_read_sync on a Closed session must return promptly, not deadlock (FU-1 guard)";
    const auto result = readResult.get();
    EXPECT_TRUE(result.is_bad()) << "a service op on a Closed session must fail, not succeed";
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSessionClosed});
  }

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-020
// The server's revisedSessionTimeout (not the client's requested value) is the authoritative interval
// that arms the tier-0 timeout watchdog. Drive create -> activate with a revised timeout that
// deliberately DIFFERS from the requested Config value, then assert (a) the stored
// revised_session_timeout_ms is the REVISED value, not the requested one, and (b) the 75% watchdog
// timer is armed on the activation path.
//
// Falsifiable: a client that kept the requested value would store the config default and fail the
// EXPECT_DOUBLE_EQ against the revised value. The ASSERT_NE guards the discriminator so the two values
// cannot silently coincide (e.g. if the config default ever changed to the revised value).
// This test does NOT assert the keep-alive cadence sub-claim (ConnectionImpl uses a fixed
// KeepAlivePolicy interval, not the revised timeout) - only the tier-0 watchdog slice.
// @relation(CL-SESS-020, scope=function)
TEST(ClientSessionShellTests, RevisedSessionTimeoutFromResponseArmsWatchdogNotRequested)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // The requested timeout is what the client asked for (the config value sent on the wire); the
  // revised timeout is a deliberately different value the server negotiates. The two MUST differ for
  // this test to discriminate revised-vs-requested.
  const double requestedTimeoutMs =
    STA::on_strand(*setup.session, [](auto& g) { return g.config().requestedSessionTimeoutMs; });
  const double revisedTimeoutMs = 48000.0;
  ASSERT_NE(revisedTimeoutMs, requestedTimeoutMs)
    << "test precondition: the revised value must differ from the requested value to discriminate them";

  // Stage 1: CreateSessionResponse carrying the negotiated revised timeout (distinct from requested).
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = revisedTimeoutMs;
  attach_anonymous_policy(*createResp);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResp)));
  std::this_thread::sleep_for(50ms);
  ASSERT_TRUE(setup.session->is_created());

  // Stage 2: activate to Active - the watchdog is armed on the activation path.
  std::mutex mx;
  std::condition_variable cv;
  bool activateDone{false};

  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        activateDone = true;
      }
      cv.notify_one();
    });

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResp = std::make_shared<ua::ActivateSessionResponse>();
  activateResp->response_header().service_result() = Status::Good;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResp)));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return activateDone; }));
  }
  ASSERT_TRUE(setup.session->is_active());

  // (a) The stored value must be the REVISED value from the response, not the requested Config value.
  const double storedTimeoutMs =
    STA::on_strand(*setup.session, [](auto& g) { return g.revised_session_timeout_ms(); });
  EXPECT_DOUBLE_EQ(storedTimeoutMs, revisedTimeoutMs)
    << "the negotiated revised timeout must be stored and drive the watchdog, not the requested value";

  // (b) The tier-0 watchdog (75% of the revised timeout) must be armed.
  const bool timerSet =
    STA::on_strand(*setup.session, [](auto& g) { return static_cast<bool>(g.timeout_timer()); });
  EXPECT_TRUE(timerSet) << "the tier-0 timeout watchdog must be armed for a non-zero revised timeout";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-020
// Part 4 section 5.6.2.2 makes revisedSessionTimeout an INACTIVITY limit: issuing a Service request before
// the watchdog deadline must start a fresh inactivity window. The delayed request below lands after more
// than half of the first 75% window. The Session must remain Active past the ORIGINAL activation-based
// deadline, then close at the re-armed deadline if no further request is issued. The latter observation is
// the control arm: merely cancelling the watchdog forever cannot pass.
// @relation(AC-CL-SESS-020-REQUEST-ACTIVITY-REARMS-WATCHDOG, scope=function)
TEST(ClientSessionShellTests, IssuedServiceRequestRearmsRevisedTimeoutInactivityWatchdog)
{
  boost::asio::thread_pool tp{1};
  auto setup = TestSessionSetup::create(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResponse = std::make_shared<CreateSessionResponse>();
  createResponse->response_header().service_result() = Status::Good;
  createResponse->session_id() = NodeId{1, 42};
  createResponse->authentication_token() = NodeId{1, 99};
  createResponse->revised_session_timeout() = 4000.0;  // watchdog interval: 3000 ms
  attach_anonymous_policy(*createResponse);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResponse)));
  ASSERT_TRUE(setup.sync->wait_created(1000ms));

  std::promise<VoidResult> activated;
  setup.session->activate(
    Session::ActivateConfig{}, [&activated](VoidResult result) { activated.set_value(std::move(result)); });
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResponse)));
  ASSERT_TRUE(activated.get_future().get().is_good());
  ASSERT_TRUE(setup.session->is_active());

  // At 1600 ms, only 1400 ms remains on the original watchdog. Issuing Read must re-arm it to 3000 ms.
  {
    Session publicSession = STA::wrap(setup.session);
    std::this_thread::sleep_for(1600ms);
    std::promise<Result<ReadResponse>> readCompleted;
    publicSession.attributes().read_async(ReadRequest{},
      [&readCompleted](Result<ReadResponse> result) { readCompleted.set_value(std::move(result)); });
    ASSERT_TRUE(setup.wait_for_pending_request());
    auto readResponse = std::make_shared<ReadResponse>();
    readResponse->response_header().service_result() = Status::Good;
    ASSERT_TRUE(setup.inject_channel_response(std::move(readResponse)));
    ASSERT_TRUE(readCompleted.get_future().get().is_good());
  }

  // Total age is now >3200 ms, beyond the original 3000 ms deadline, but only ~1600 ms of the
  // re-armed inactivity window has elapsed.
  std::this_thread::sleep_for(1600ms);
  EXPECT_TRUE(setup.session->is_active())
    << "an issued Service request must prevent the activation-based watchdog from closing the Session";

  // No second request follows. The re-armed watchdog must still close the Session, proving the repair did
  // not simply suppress inactivity detection.
  ASSERT_TRUE(setup.sync->wait_error(2000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTimeout});
  EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Secured-session capture harness + CL-SESS crypto/lifecycle tests (rebuilt).
//
// This section drives the REAL create/activate path in ua_client_session_impl.cpp against a
// null-connection channel, with real OpenSSL crypto so the client actually generates a nonce,
// verifies the server's application signature, and produces genuine RSA signatures for
// ActivateSession. Outgoing service requests are cloned through the SecureChannel
// outgoing-request observer interface so tests can assert exactly what the client put on the wire.
// =============================================================================

namespace
{

using namespace std::chrono_literals;

/// Poll @p pred until it returns true or @p timeout elapses.
template<typename Pred>
bool poll_until(Pred pred, std::chrono::milliseconds timeout = 3000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return true;
    }
    std::this_thread::sleep_for(5ms);
  }
  return false;
}

/// Real OpenSSL crypto with a fixed private-key password (mirrors the token-encryption tests).
std::shared_ptr<const Crypto> make_secured_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

/// @p size bytes of real entropy from @p crypto.
ByteString random_bytes(const Crypto& crypto, size_t size)
{
  return crypto.get_entropy_sync(size);
}

/// A self-signed RSA-2048 certificate over @p keys suitable for Basic256Sha256.
std::shared_ptr<const X509Certificate> make_rsa_cert(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const AsymmetricKeyPair>& keys, std::string_view commonName, std::string_view serial,
  std::string_view applicationUri = {})
{
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig params;
  params.subjectKeys = keys;
  params.issuerKeys = keys;
  params.subject.commonName = std::string{commonName};
  params.serialNumber = std::string{serial};
  params.basicConstraint.cA = false;
  params.keyUsage.digitalSignature = true;
  params.keyUsage.keyEncipherment = true;
  if (!applicationUri.empty())
  {
    params.subjectAlternateName.uris.emplace_back(applicationUri);
  }
  params.subjectAlternateName.hostnames.emplace_back("localhost");
  params.subjectAlternateName.ipAddresses.emplace_back(boost::asio::ip::make_address("127.0.0.1"));
  params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  params.from = DateTime::now();
  params.to = DateTime{params.from.value() + std::chrono::days{365}};
  return pki.create_cert(params);
}

/// A self-signed ECC ApplicationInstance certificate over @p keys signed with @p sigAlg (e.g. an
/// EccNistP256 cert with EcDsaSha2256). Mirrors make_rsa_cert for ECC SecurityPolicies.
std::shared_ptr<const X509Certificate> make_ecc_cert(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const AsymmetricKeyPair>& keys, CertificateSignatureAlgorithm sigAlg,
  std::string_view commonName, std::string_view serial)
{
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig params;
  params.subjectKeys = keys;
  params.issuerKeys = keys;
  params.subject.commonName = std::string{commonName};
  params.serialNumber = std::string{serial};
  params.basicConstraint.cA = false;
  params.keyUsage.digitalSignature = true;
  params.subjectAlternateName.hostnames.emplace_back("localhost");
  params.subjectAlternateName.ipAddresses.emplace_back(boost::asio::ip::make_address("127.0.0.1"));
  params.certificateSignatureAlgorithm = sigAlg;
  params.from = DateTime::now();
  params.to = DateTime{params.from.value() + std::chrono::days{365}};
  return pki.create_cert(params);
}

/// The stock client FakeSessionDeps returns a null crypto (which makes the authenticated signing
/// branches skip). This subclass supplies real crypto so the secured create/activate path runs for real.
class CryptoSessionDeps final : public FakeSessionDeps
{
public:
  CryptoSessionDeps(boost::asio::any_io_executor ex, std::shared_ptr<const Crypto> crypto,
    std::shared_ptr<CertificateStore> certStore = nullptr)
    : FakeSessionDeps(ex), mCrypto(std::move(crypto)), mCertStore(std::move(certStore)),
      mLogSink(std::make_shared<RecordingLogSink>()),
      mLogLevel(std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace))
  {}

  shared_ptr<const Crypto> crypto() override
  {
    return mCrypto;
  }

  /// The trust store the session validates the server certificate against before encrypting a user token
  /// on a None channel (CL-IDENT-006). Null by default (secured-channel tests never consult it).
  shared_ptr<CertificateStore> certificate_store() override
  {
    return mCertStore;
  }

  Logger logger() override
  {
    return Logger{mLogSink, mLogLevel, "client_session_test"};
  }

  bool has_log_message(std::string_view text) const
  {
    return mLogSink->contains(text);
  }

  void set_certificate_store(std::shared_ptr<CertificateStore> certificateStore)
  {
    mCertStore = std::move(certificateStore);
  }

private:
  class RecordingLogSink final : public LogSink
  {
  public:
    void log(const LogEntry& entry) override
    {
      std::lock_guard lock(mMutex);
      mMessages.push_back(entry.message);
    }

    bool contains(std::string_view text) const
    {
      std::lock_guard lock(mMutex);
      return std::ranges::any_of(
        mMessages, [text](const std::string& message) { return message.find(text) != std::string::npos; });
    }

  private:
    mutable std::mutex mMutex;
    std::vector<std::string> mMessages;
  };

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<CertificateStore> mCertStore;
  std::shared_ptr<RecordingLogSink> mLogSink;
  std::shared_ptr<std::atomic<LogLevel>> mLogLevel;
};

EndpointDescription make_discovery_endpoint(std::string_view applicationUri)
{
  EndpointDescription endpoint;
  endpoint.endpoint_url() = "opc.tcp://localhost:4840";
  endpoint.server().application_uri() = std::string{applicationUri};
  endpoint.security_mode() = MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() =
    std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};
  UserTokenPolicy anonymous;
  anonymous.token_type() = UserTokenType::Anonymous;
  endpoint.user_identity_tokens().payload().push_back(std::move(anonymous));
  return endpoint;
}

/// A null-connection, authenticated (Basic256Sha256 / SignAndEncrypt) client SessionImpl driven through
/// the real CreateSession/ActivateSession handshakes with real crypto, capturing every outgoing service
/// request and injecting synthetic responses. Sibling of TestSessionSetup with authentication enabled.
struct SecuredSessionSetup
{
  // Crypto material.
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<SecurityPolicy> policy;
  std::shared_ptr<const AsymmetricKeyPair> clientKeys;
  std::shared_ptr<const X509Certificate> clientCert;
  std::shared_ptr<const AsymmetricKeyPair> serverKeys;
  std::shared_ptr<const X509Certificate> serverCert;
  std::shared_ptr<const X509Certificate> serverIssuerCert;
  std::vector<std::shared_ptr<const X509Certificate>> clientIssuerCerts;  ///< decision 24 own chain
  ByteString defaultServerNonce;  // The serverNonce carried by make_good_create_response() (== N1).
  /// The channel's ChannelThumbprint: set by wire_session under a policy with SecureChannelEnhancements, as
  /// the channel hands it to the Session in production; empty otherwise.
  ByteString channelThumbprint;
  std::string endpointUrl;  // The dialed endpoint URL configured on the session (identity binding).

  // Wiring.
  std::shared_ptr<FakeChannelDeps> channelDeps;
  std::shared_ptr<CryptoSessionDeps> sessionDeps;
  std::shared_ptr<SecureChannelImpl> channel;
  std::shared_ptr<SessionImpl> session;
  std::shared_ptr<CallbackSync> sync;
  std::shared_ptr<std::vector<std::unique_ptr<Structure>>> capturedRequests;
  std::vector<EndpointDescription> discoveryEndpoints;
  bool relaxHostNameCheck{false};
  MessageSecurityMode channelMode{MessageSecurityMode::SignAndEncrypt};

  static SecuredSessionSetup create_secured_rsa(boost::asio::any_io_executor ex, SecurityPolicyId policyId,
    std::vector<EndpointDescription> discoveryEndpoints = {}, bool relaxHostNameCheck = false,
    std::optional<std::string> configuredEndpointUrl = std::nullopt)
  {
    SecuredSessionSetup s;
    s.crypto = make_secured_crypto();
    s.policy = SecurityPolicy::create(policyId);
    s.serverKeys = test_keys::key_pair(*s.crypto, test_keys::KeyType::Rsa2048, 40);
    s.serverCert = make_rsa_cert(s.crypto, s.serverKeys, "TestServer", "1", "urn:TestServer");
    s.clientKeys = test_keys::key_pair(*s.crypto, test_keys::KeyType::Rsa2048, 41);
    s.clientCert = make_rsa_cert(s.crypto, s.clientKeys, "TestClient", "2");
    s.defaultServerNonce = random_bytes(*s.crypto, s.policy->nonce_length());
    s.discoveryEndpoints = std::move(discoveryEndpoints);
    s.relaxHostNameCheck = relaxHostNameCheck;

    wire_session(s,
      ex,
      MessageSecurityMode::SignAndEncrypt,
      nullptr,
      configuredEndpointUrl.value_or(s.discoveryEndpoints.empty()
                                       ? std::string{}
                                       : std::string{s.discoveryEndpoints.front().endpoint_url()}));
    return s;
  }

  static SecuredSessionSetup create_secured(boost::asio::any_io_executor ex,
    std::vector<EndpointDescription> discoveryEndpoints = {}, bool relaxHostNameCheck = false,
    std::optional<std::string> configuredEndpointUrl = std::nullopt)
  {
    return create_secured_rsa(ex,
      SecurityPolicyId::Basic256Sha256,
      std::move(discoveryEndpoints),
      relaxHostNameCheck,
      std::move(configuredEndpointUrl));
  }

  static SecuredSessionSetup create_secured_with_server_chain(boost::asio::any_io_executor ex)
  {
    SecuredSessionSetup s;
    s.crypto = make_secured_crypto();
    s.policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

    TestPki pki{s.crypto};
    auto issuerKeys = s.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    s.serverIssuerCert = pki.create_root_ca(issuerKeys, "Session Test Issuer", "10");
    s.serverKeys = s.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    const auto validFrom = DateTime::now();
    const auto validTo = DateTime{validFrom.value() + std::chrono::days{365}};
    s.serverCert = pki.create_leaf_cert(s.serverKeys,
      issuerKeys,
      s.serverIssuerCert,
      validFrom,
      validTo,
      {"urn:TestServer"},
      {"localhost", "127.0.0.1"},
      "TestServer");

    // The client certificate is issued by the same CA, and the client holds that CA as its own issuer
    // chain (decision 24, ApplicationCertificate::issuerCertificates), so CreateSession carries a chain.
    s.clientKeys = s.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    s.clientCert = pki.create_leaf_cert(
      s.clientKeys, issuerKeys, s.serverIssuerCert, validFrom, validTo, {"urn:TestClient"}, {}, "TestClient");
    s.clientIssuerCerts = {s.serverIssuerCert};
    s.defaultServerNonce = random_bytes(*s.crypto, s.policy->nonce_length());
    wire_session(s, ex);
    return s;
  }

  /// Like create_secured but over an ECC SecurityPolicy: ECC certs + keys so the client's ECC code
  /// paths (is_ecc(), ECDHPolicyUri in CreateSession, ECC ephemeral nonce) run for real.
  static SecuredSessionSetup create_secured_ecc(boost::asio::any_io_executor ex, SecurityPolicyId policyId,
    CertificateKeyAlgorithm keyAlg, CertificateSignatureAlgorithm sigAlg, std::string ecdhPolicyUri = {},
    bool requestEphemeralKey = true)
  {
    SecuredSessionSetup s;
    s.crypto = make_secured_crypto();
    s.policy = SecurityPolicy::create(policyId);
    s.serverKeys = s.crypto->create_asymmetric_key_pair_sync(keyAlg, std::nullopt);
    s.serverCert = make_ecc_cert(s.crypto, s.serverKeys, sigAlg, "TestServer", "1");
    s.clientKeys = s.crypto->create_asymmetric_key_pair_sync(keyAlg, std::nullopt);
    s.clientCert = make_ecc_cert(s.crypto, s.clientKeys, sigAlg, "TestClient", "2");
    s.defaultServerNonce = random_bytes(*s.crypto, s.policy->nonce_length());
    wire_session(
      s, ex, MessageSecurityMode::SignAndEncrypt, nullptr, {}, std::move(ecdhPolicyUri), requestEphemeralKey);
    return s;
  }

  /// Like create_secured but the SecureChannel MessageSecurityMode is None, so the CreateSession
  /// server certificate arrives UNPROTECTED (no OPN validation, no channel signing/encryption). A
  /// caller-supplied trust store is installed on the session deps so the test can script whether the
  /// server certificate validates. Models exactly the MITM-exposed path CL-IDENT-006 guards: a client
  /// that would otherwise encrypt a UserName token to an unvalidated server certificate.
  static SecuredSessionSetup create_none_encrypting(boost::asio::any_io_executor ex,
    std::shared_ptr<CertificateStore> certStore, std::string endpointUrl = "opc.tcp://localhost:4840")
  {
    SecuredSessionSetup s;
    s.crypto = make_secured_crypto();
    s.policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    s.serverKeys = s.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    s.serverCert = make_rsa_cert(s.crypto, s.serverKeys, "TestServer", "1");
    s.clientKeys = s.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    s.clientCert = make_rsa_cert(s.crypto, s.clientKeys, "TestClient", "2");
    s.defaultServerNonce = random_bytes(*s.crypto, s.policy->nonce_length());
    wire_session(s, ex, MessageSecurityMode::None, std::move(certStore), std::move(endpointUrl));
    return s;
  }

  /// Shared channel+session wiring for the secured harness, parameterised on the crypto material
  /// already placed in @p s (crypto / policy / keys / certs / defaultServerNonce), the channel
  /// MessageSecurityMode, an optional session trust store, and the dialed endpoint URL.
  static void wire_session(SecuredSessionSetup& s, boost::asio::any_io_executor ex,
    MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt,
    std::shared_ptr<CertificateStore> certStore = nullptr, std::string endpointUrl = {},
    std::string ecdhPolicyUri = {}, bool requestEphemeralKey = true)
  {
    s.endpointUrl = endpointUrl;
    s.channelMode = mode;
    s.channelDeps = std::make_shared<FakeChannelDeps>(ex);
    s.sessionDeps = std::make_shared<CryptoSessionDeps>(ex, s.crypto, std::move(certStore));
    s.sync = std::make_shared<CallbackSync>();

    s.channel = SecureChannelImpl::create(
      s.channelDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      SecureChannelImpl::Config{},
      [](VoidResult) {},
      [](VoidResult) {});
    SecureChannelTestAccess::on_strand(
      *s.channel, [](auto& g) { g.channel_state() = SecureChannelImpl::ChannelState::Open; });

    // Install the outgoing-request capture observer BEFORE the session sends anything.
    s.capturedRequests = std::make_shared<std::vector<std::unique_ptr<Structure>>>();
    auto captured = s.capturedRequests;
    SecureChannelTestAccess::on_strand(*s.channel,
      [captured](auto& g)
      {
        g.outgoing_request_observer() = [captured](const Structure& request)
        {
          captured->push_back(request.clone());
        };
      });

    SessionImpl::SecurityInfo securityInfo;
    securityInfo.clientCertificate = s.clientCert;
    // Decision 24: the client sends its own issuer chain after the leaf in every certificate field.
    securityInfo.clientIssuerCertificates = s.clientIssuerCerts;
    securityInfo.clientKeyPair = s.clientKeys;
    securityInfo.securityPolicy = s.policy;
    securityInfo.messageSecurityMode = mode;
    // Mirror production: the OPN-time (GetEndpoints) server certificate is carried in SecurityInfo only
    // for a secured channel; SecurityPolicy None opens without a server certificate. This drives the
    // CL-SC-012 CreateSession-certificate continuity check exactly as the real channel wiring does.
    securityInfo.serverCertificate = mode == MessageSecurityMode::None ? nullptr : s.serverCert;
    // The session signatures of an enhanced policy cover the ChannelThumbprint (OPC 10000-4 section 6.1.8).
    s.channelThumbprint =
      s.policy->secure_channel_enhancements() ? random_bytes(*s.crypto, 64) : ByteString{};
    securityInfo.channelThumbprint = s.channelThumbprint;

    SessionImpl::Config config;
    config.isAuthenticated = true;
    config.endpointUrl = std::move(endpointUrl);
    config.discoveryEndpoints = s.discoveryEndpoints;
    config.ecdhPolicyUri = std::move(ecdhPolicyUri);
    config.requestEphemeralKey = requestEphemeralKey;
    config.relaxHostNameCheck = s.relaxHostNameCheck;

    auto syncPtr = s.sync;
    s.session = SessionImpl::create(
      s.sessionDeps,
      s.channel,
      config,
      std::move(securityInfo),
      [syncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->created = true;
          syncPtr->createdStatus = result.status_code();
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          ++syncPtr->errorCount;
          syncPtr->errorStatus = result.status_code();
          syncPtr->errorDetail = result.shared_detail();
        }
        syncPtr->cv.notify_one();
      });
  }

  SS read_state_on_strand()
  {
    return STA::on_strand(*session, [](auto& g) { return g.session_state(); });
  }

  /// The client-generated nonce (populated once the CreateSessionRequest has been sent).
  ByteString client_nonce_on_strand()
  {
    return STA::on_strand(*session, [](auto& g) { return g.client_nonce(); });
  }

  /// The server nonce currently stored on the session (verbatim from the last handshake response).
  ByteString stored_server_nonce()
  {
    return STA::on_strand(*session, [](auto& g) { return g.server_nonce(); });
  }

  bool wait_for_pending_request(std::chrono::milliseconds timeout = 3000ms)
  {
    return poll_until(
      [this]()
      {
        return SecureChannelTestAccess::on_strand(
          *channel, [](auto& g) { return !g.pending_requests().empty(); });
      },
      timeout);
  }

  bool inject_channel_response(std::shared_ptr<Structure> response)
  {
    return SecureChannelTestAccess::on_strand(*channel,
      [resp = std::move(response)](auto& g) mutable
      {
        auto& pending = g.pending_requests();
        if (pending.empty())
        {
          return false;
        }
        auto it = pending.begin();
        auto callback = std::move(it->second);
        pending.erase(it);
        callback(SecureChannelImpl::ServiceResponseResult{std::move(resp)});
        return true;
      });
  }

  /// A copy of the first captured outgoing request of type @p ReqT, or nullopt if none was sent.
  template<typename ReqT>
  std::optional<ReqT> first_captured()
  {
    return SecureChannelTestAccess::on_strand(*channel,
      [this](auto&) -> std::optional<ReqT>
      {
        for (const auto& req : *capturedRequests)
        {
          if (const auto* typed = dynamic_cast<const ReqT*>(req.get()))
          {
            return *typed;
          }
        }
        return std::nullopt;
      });
  }

  /// Copies of every captured outgoing request of type @p ReqT, in send order.
  template<typename ReqT>
  std::vector<ReqT> all_captured()
  {
    return SecureChannelTestAccess::on_strand(*channel,
      [this](auto&) -> std::vector<ReqT>
      {
        std::vector<ReqT> out;
        for (const auto& req : *capturedRequests)
        {
          if (const auto* typed = dynamic_cast<const ReqT*>(req.get()))
          {
            out.push_back(*typed);
          }
        }
        return out;
      });
  }

  template<typename ReqT>
  bool wait_for_captured(size_t count = 1, std::chrono::milliseconds timeout = 3000ms)
  {
    return poll_until([this, count]() { return all_captured<ReqT>().size() >= count; }, timeout);
  }

  /// True iff @p signature is a valid Basic256Sha256 signature over @p data by @p publicKey (real verify).
  bool signature_verifies(ua::span<const ua::byte> publicKey, ua::span<const ua::byte> data,
    ua::span<const ua::byte> signature) const
  {
    try
    {
      crypto->asymmetric_verify_sync(policy->asymmetric_signature_algorithm(), publicKey, data, signature);
      return true;
    }
    catch (...)
    {
      return false;
    }
  }

  /// The data a ServerSignature signs: under a policy with SecureChannelEnhancements the Table 101 data of
  /// this channel (OPC 10000-4 section 6.1.8), otherwise (clientCertDER || clientNonce).
  ByteString server_signature_data(const ByteString& serverNonce)
  {
    if (policy->secure_channel_enhancements())
    {
      return ua::test_helpers::channel_bound_data(*crypto,
        *policy,
        ChannelBoundSignature::Server,
        ChannelBoundSignatureInputs{.channelThumbprint = channelThumbprint,
          .clientNonce = client_nonce_on_strand(),
          .serverNonce = serverNonce,
          .serverChannelCertificate =
            channelMode == MessageSecurityMode::None ? ByteString{} : serverCert->der_encoding(),
          .clientChannelCertificate = clientCert->der_encoding()});
    }
    ByteString signedData = clientCert->der_encoding();
    std::ranges::copy(client_nonce_on_strand(), std::back_inserter(signedData));
    return signedData;
  }

  /// A CreateSessionResponse whose serverSignature is a REAL signature by the server key over
  /// server_signature_data, so the client's validate_server_signature_async passes. Must be built after the
  /// CreateSessionRequest has been sent (so the client nonce exists).
  std::shared_ptr<CreateSessionResponse> make_good_create_response(
    ByteString serverNonce, const std::vector<ua::UserTokenPolicy>& userTokenPolicies = {})
  {
    auto signature = crypto->asymmetric_sign_sync(
      policy->asymmetric_signature_algorithm(), serverKeys, server_signature_data(serverNonce));

    auto response = std::make_shared<CreateSessionResponse>();
    response->response_header().service_result() = Status::Good;
    response->session_id() = NodeId{1, 42};
    response->authentication_token() = NodeId{1, 99};
    response->revised_session_timeout() = 600000.0;
    response->server_nonce() = serverNonce;
    response->server_certificate() = serverCert->der_encoding();
    response->server_signature().signature() = signature;
    // Table 174: an enhanced policy's SignatureData carries no algorithm.
    if (!policy->secure_channel_enhancements())
      response->server_signature().algorithm() = policy->asymmetric_signature_algorithm_uri();
    if (!discoveryEndpoints.empty())
    {
      response->server_endpoints().payload() = discoveryEndpoints;
    }
    else if (!userTokenPolicies.empty())
    {
      ua::EndpointDescription endpoint;
      endpoint.endpoint_url() = "opc.tcp://localhost:4840";
      endpoint.security_mode() = channelMode;
      endpoint.security_policy_uri() = std::string{policy->uri()};
      for (const auto& utp : userTokenPolicies)
      {
        endpoint.user_identity_tokens().payload().push_back(utp);
      }
      response->server_endpoints().payload().push_back(std::move(endpoint));
    }
    return response;
  }

  std::shared_ptr<CreateSessionResponse> make_good_create_response()
  {
    // Advertise an ANONYMOUS UserTokenPolicy so anonymous activation resolves a policy (CL-IDENT-002: the
    // client now fails fast when no ANONYMOUS policy is advertised). Empty policy_id keeps the emitted
    // AnonymousIdentityToken.policyId empty, exactly as before - these session tests activate anonymously to
    // reach Active and do not assert the policyId value.
    ua::UserTokenPolicy anon;
    anon.token_type() = UserTokenType::Anonymous;
    return make_good_create_response(defaultServerNonce, {anon});
  }

  /// A CreateSessionResponse whose serverSignature is a well-formed RSA signature over the serverNonce
  /// ALONE (not clientCertDER || clientNonce), so the client MUST reject it as
  /// BadApplicationSignatureInvalid.
  std::shared_ptr<CreateSessionResponse> make_bad_signature_create_response()
  {
    auto signature =
      crypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), serverKeys, defaultServerNonce);

    auto response = std::make_shared<CreateSessionResponse>();
    response->response_header().service_result() = Status::Good;
    response->session_id() = NodeId{1, 42};
    response->authentication_token() = NodeId{1, 99};
    response->revised_session_timeout() = 600000.0;
    response->server_nonce() = defaultServerNonce;
    response->server_certificate() = serverCert->der_encoding();
    response->server_signature().signature() = signature;
    response->server_signature().algorithm() = policy->asymmetric_signature_algorithm_uri();
    return response;
  }

  void cleanup_sync()
  {
    if (!session)
    {
      return;
    }
    SecureChannelTestAccess::on_strand(*channel,
      [](auto& g)
      {
        auto pending = std::move(g.pending_requests());
        g.pending_requests().clear();
        for (auto& [handle, callback] : pending)
        {
          callback(SecureChannelImpl::ServiceResponseResult{Status::BadConnectionClosed});
        }
      });

    auto state = read_state_on_strand();
    if (state != SS::Closed && state != SS::Idle)
    {
      STA::on_strand(*session, [](auto& g) { g.inject_channel_error(Status::BadConnectionClosed); });
      STA::on_strand(*session, [](auto& g) { g.inject_channel_error(Status::BadConnectionClosed); });
    }
    STA::strand_barrier(*session);
  }

  void release()
  {
    session.reset();
    channel.reset();
    sessionDeps.reset();
    channelDeps.reset();
    sync.reset();
    capturedRequests.reset();
  }
};

}  // namespace

// @verifies CL-SESS-001
// The session's create handshake must put a CreateSessionRequest on the wire. Drive the real secured
// create path and assert the outgoing-request capture interface recorded a CreateSessionRequest.
// Falsifiable: a session that never sent CreateSession (or sent a different message) yields no capture.
// @relation(CL-SESS-001, scope=function)
TEST(ClientSessionShellTests, CreateSessionRequestSentThroughChannel)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>())
    << "the session must send a CreateSessionRequest through the channel";
  EXPECT_TRUE(setup.first_captured<CreateSessionRequest>().has_value());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-AUDIT-002
// @relation(CL-AUDIT-002, scope=function)
TEST(ClientSessionShellTests, AuditProviderStampsCreateAndCloseBeforeChannelSend)
{
  boost::asio::thread_pool pool;
  std::size_t providerCalls = 0;
  SessionImpl::Config config;
  config.auditEntryIdProvider = [&providerCalls]
  {
    ++providerCalls;
    return String{"lifecycle-audit"};
  };
  auto setup = TestSessionSetup::create(pool.get_executor(), std::move(config));

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto creates = setup.captured<CreateSessionRequest>();
  ASSERT_EQ(creates.size(), 1U);
  EXPECT_EQ(creates.front().request_header().audit_entry_id(), String{"lifecycle-audit"});
  ASSERT_TRUE(setup.complete_none_create());

  setup.set_active_on_strand();
  setup.session->close([](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto closes = setup.captured<CloseSessionRequest>();
  ASSERT_EQ(closes.size(), 1U);
  EXPECT_EQ(closes.front().request_header().audit_entry_id(), String{"lifecycle-audit"});
  EXPECT_EQ(providerCalls, 2U);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-SESS-002
// Part 4 5.6.2: the client supplies a nonce whose length matches the SecurityPolicy. For Basic256Sha256
// that is 32 bytes. Read it off the captured CreateSessionRequest (what actually went on the wire).
// Falsifiable: an unauthenticated client emits an empty nonce; a wrong length fails both assertions.
// @relation(CL-SESS-002, scope=function)
TEST(ClientSessionShellTests, ClientNonceLengthMatchesPolicyNonceLength)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>());
  auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  EXPECT_EQ(request->client_nonce().size(), setup.policy->nonce_length())
    << "the client nonce length must equal the SecurityPolicy nonce length";
  EXPECT_EQ(request->client_nonce().size(), 32u) << "Basic256Sha256 nonce length is 32 bytes";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Owner decision 11 gave Basic128Rsa15 a 16-byte SecureChannel nonce; the CreateSession clientNonce
// stays at least 32 bytes (Part 4 5.6.2), or an SDK server (and any stack enforcing the Session floor)
// refuses the Session on a channel that opened.
// @verifies AC-CL-SESS-002-SESSION-NONCE-FLOOR-ON-A-SHORT-CHANNEL-NONCE
TEST(ClientSessionShellTests, ABasic128Rsa15SessionKeepsThe32ByteClientNonceFloor)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_rsa(tp.get_executor(), SecurityPolicyId::Basic128Rsa15);

  ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>());
  auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  EXPECT_EQ(setup.policy->nonce_length(), 16u) << "the channel nonce of Basic128Rsa15";
  EXPECT_EQ(request->client_nonce().size(), 32u) << "the Session nonce keeps the 32-byte floor";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// OPC 10000-4 1.05.07 5.7.2: the clientNonce has "a length between 32 and 128 bytes inclusive", and the
// Server checks it. RSA_DH's SecureChannel nonce is 384 bytes (the ffdhe3072 public value), so its Session
// nonce is 128 or a server enforcing the ceiling refuses the Session.
// @relation(AC-CL-SESS-002-SESSION-NONCE-CEILING-ON-A-LONG-CHANNEL-NONCE, scope=function)
TEST(ClientSessionShellTests, AnRsaDhSessionCapsTheClientNonceAt128Bytes)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_rsa(tp.get_executor(), SecurityPolicyId::RsaDhAesGcm);

  ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>());
  auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  EXPECT_EQ(setup.policy->nonce_length(), 384u) << "the channel nonce of RSA_DH";
  EXPECT_EQ(request->client_nonce().size(), 128u) << "the Session nonce keeps the 128-byte ceiling";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The control arm of AC-CL-SESS-002. Its sibling drives Basic256Sha256 alone, where the policy nonce length
// and the Part 4 section 5.6.2 floor are the same number (32) - so a client with a hardcoded 32 satisfies it.
// These runs differ from it in exactly one variable, the SecurityPolicy, and assert the emitted nonce tracks
// each policy's own declared length while still clearing the floor.
// @verifies CL-SESS-002
// @relation(CL-SESS-002, scope=function)
TEST(ClientSessionShellTests, ClientNonceLengthTracksTheEccPolicyNonceLength)
{
  struct Case
  {
    SecurityPolicyId policy;
    CertificateKeyAlgorithm key;
    CertificateSignatureAlgorithm sig;
  };

  const Case cases[] = {
    {SecurityPolicyId::EccNistP256AesGcm,
      CertificateKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256},
    {SecurityPolicyId::EccNistP384AesGcm,
      CertificateKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384},
  };

  for (const auto& testCase : cases)
  {
    boost::asio::thread_pool tp;
    auto setup =
      SecuredSessionSetup::create_secured_ecc(tp.get_executor(), testCase.policy, testCase.key, testCase.sig);

    ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>());
    auto request = setup.first_captured<CreateSessionRequest>();
    ASSERT_TRUE(request.has_value());

    EXPECT_EQ(request->client_nonce().size(), setup.policy->nonce_length())
      << "the emitted nonce length must be this policy's declared nonce length";
    EXPECT_GE(request->client_nonce().size(), 32u)
      << "Part 4 5.6.2 floors the clientNonce at 32 bytes whatever the policy declares";

    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// @verifies CL-SESS-004
// Part 4 5.6.2: the client MUST verify the server application signature over (clientCert || clientNonce)
// before accepting the session. Inject a response carrying a well-formed RSA signature over the serverNonce
// ALONE - a signature that will not verify against the required payload - and the client must reject.
// Falsifiable: a client that skipped verification (or accepted any well-formed signature) would reach
// Created rather than firing BadApplicationSignatureInvalid and closing.
// @relation(CL-SESS-004, scope=function)
TEST(ClientSessionShellTests, InvalidServerSignatureRejectsCreate)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_bad_signature_create_response()));

  ASSERT_TRUE(setup.sync->wait_error(3000ms)) << "an invalid server signature must fire the error callback";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadApplicationSignatureInvalid});
  EXPECT_FALSE(setup.session->is_created()) << "the session must not become Created on a bad signature";
  EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.6.2.2: when leaf verification fails, the Client shall retry the
// serverSignature over the full client Certificate chain before refusing it. The substituted
// signature is independently invalid over leaf||nonce and valid over leaf||issuer||nonce, so
// reaching Created proves the fallback rather than a permissive verifier.
// @relation(AC-SVR-SESS-033-SERVERSIG-LEAF-THEN-CHAIN, scope=function)
TEST(ClientSessionShellTests, ServerSignatureFallsBackFromClientLeafToOrderedFullChain)
{
  boost::asio::thread_pool tp;
  SecuredSessionSetup setup;
  setup.crypto = make_secured_crypto();
  setup.policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  TestPki pki{setup.crypto};
  auto issuerKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto issuerCertificate = pki.create_root_ca(issuerKeys, "Client Signature Issuer", "20");
  setup.clientKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto validFrom = DateTime::now();
  setup.clientCert = pki.create_leaf_cert(setup.clientKeys,
    issuerKeys,
    issuerCertificate,
    validFrom,
    DateTime{validFrom.value() + std::chrono::days{365}},
    {"urn:TestClient"},
    {"localhost", "127.0.0.1"},
    "TestClient");
  setup.serverKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  setup.serverCert = make_rsa_cert(setup.crypto, setup.serverKeys, "TestServer", "21", "urn:TestServer");
  setup.defaultServerNonce = random_bytes(*setup.crypto, setup.policy->nonce_length());

  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->issuerCertificates.push_back(issuerCertificate);
  SecuredSessionSetup::wire_session(
    setup, tp.get_executor(), MessageSecurityMode::SignAndEncrypt, std::move(store));

  ASSERT_TRUE(setup.wait_for_pending_request());
  const auto clientNonce = setup.client_nonce_on_strand();
  ByteString leafInput = setup.clientCert->der_encoding();
  std::ranges::copy(clientNonce, std::back_inserter(leafInput));
  ByteString chainInput = setup.clientCert->der_encoding();
  const auto issuerDer = issuerCertificate->der_encoding();
  std::ranges::copy(issuerDer, std::back_inserter(chainInput));
  std::ranges::copy(clientNonce, std::back_inserter(chainInput));

  auto response = setup.make_good_create_response();
  response->server_signature().signature() = setup.crypto->asymmetric_sign_sync(
    setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, chainInput);
  EXPECT_THROW(setup.crypto->asymmetric_verify_sync(setup.policy->asymmetric_signature_algorithm(),
                 setup.serverCert->public_key(),
                 leafInput,
                 response->server_signature().signature()),
    UaException);
  EXPECT_NO_THROW(setup.crypto->asymmetric_verify_sync(setup.policy->asymmetric_signature_algorithm(),
    setup.serverCert->public_key(),
    chainInput,
    response->server_signature().signature()));

  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-COMP-CL-SESSION-SIGNATURE-VALIDATION-01-ISSUER-FAILURE, scope=function)
TEST(ClientSessionShellTests, IssuerRetrievalFailurePreservesRichResultDuringServerSignatureFallback)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  auto sentinelDetail = std::shared_ptr<const ErrorDetail>(
    make_error_detail("IssuerStoreSentinel", "Injected issuer-store failure", "FakeCertificateStore"));
  store->getIssuerCertificatesResult =
    CertificateListResult{StatusCode{Status::BadResourceUnavailable, sentinelDetail}};
  setup.sessionDeps->set_certificate_store(std::move(store));

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_bad_signature_create_response()));
  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  EXPECT_EQ(setup.sync->errorDetail->code, "ClientIssuerCertificatesUnavailable");
  EXPECT_EQ(setup.sync->errorDetail->innerStatus, StatusCode{Status::BadResourceUnavailable}.value());
  ASSERT_NE(setup.sync->errorDetail->cause, nullptr);
  EXPECT_EQ(setup.sync->errorDetail->cause->code, "IssuerStoreSentinel");
  EXPECT_FALSE(setup.session->is_created());
  SessionTestAccess::strand_barrier(*setup.session);
  {
    const std::lock_guard lock(setup.sync->mx);
    EXPECT_EQ(setup.sync->errorCount, 1u);
  }

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The client issuers answered Uncertain while the server signature falls back to the full chain: the issuers
// are not used, and the CreateSession is refused with Bad_InternalError and the
// CertificateStoreAnswerUncertain detail whose inner status is the store's code.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSessionShellTests, AnUncertainIssuerAnswerIsRefusedDuringServerSignatureFallback)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  store->getIssuerCertificatesResult = CertificateListResult{uncertain};
  setup.sessionDeps->set_certificate_store(std::move(store));

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_bad_signature_create_response()));
  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadInternalError);
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  EXPECT_EQ(setup.sync->errorDetail->code, "CertificateStoreAnswerUncertain");
  EXPECT_EQ(setup.sync->errorDetail->innerStatus, uncertain.value());
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The X509 userTokenSignature answered Uncertain by the crypto provider: the signature is not used, no
// ActivateSession is sent, and the activation fails with Bad_InternalError and the CryptoAnswerUncertain
// detail whose inner status is the provider's code.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSessionShellTests, AnUncertainUserTokenSignatureIsRefusedAndNothingIsSent)
{
  boost::asio::thread_pool tp;
  auto fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
  SecuredSessionSetup setup;
  setup.crypto = fakeCrypto;
  setup.policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  setup.serverKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  setup.serverCert = make_rsa_cert(setup.crypto, setup.serverKeys, "TestServer", "1", "urn:TestServer");
  setup.clientKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  setup.clientCert = make_rsa_cert(setup.crypto, setup.clientKeys, "TestClient", "2");
  setup.defaultServerNonce = random_bytes(*setup.crypto, setup.policy->nonce_length());
  SecuredSessionSetup::wire_session(setup, tp.get_executor());

  ua::UserTokenPolicy certPolicy;
  certPolicy.policy_id() = "cert-1";
  certPolicy.token_type() = ua::UserTokenType::Certificate;
  certPolicy.security_policy_uri() = std::string{setup.policy->uri()};
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {certPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto userKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto userCert = make_rsa_cert(setup.crypto, userKeys, "TestUser", "300");
  fakeCrypto->set_park_async(true);
  auto activated = std::make_shared<std::promise<VoidResult>>();
  auto activatedFuture = activated->get_future();
  Session::ActivateConfig config;
  config.policyId = "cert-1";
  config.identity = ua::client::X509Identity{userCert, userKeys};
  setup.session->activate(
    std::move(config), [activated](VoidResult result) { activated->set_value(result); });

  const auto waitForSign = [&fakeCrypto]
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (fakeCrypto->pending_asymmetric_sign_count() == 0 && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(5ms);
    }
    return fakeCrypto->pending_asymmetric_sign_count() == 1;
  };
  // The client application signature comes first; an empty one is sent without a signature.
  ASSERT_TRUE(waitForSign()) << "the client signature was not requested";
  fakeCrypto->complete_pending_asymmetric_sign(0, ByteStringResult{ByteString{}});
  ASSERT_TRUE(waitForSign()) << "the userTokenSignature was not requested";
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  fakeCrypto->complete_pending_asymmetric_sign(0, ByteStringResult{uncertain});

  ASSERT_EQ(activatedFuture.wait_for(3s), std::future_status::ready) << "the activation must complete";
  const auto result = activatedFuture.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
  EXPECT_FALSE(setup.first_captured<ActivateSessionRequest>().has_value()) << "no ActivateSession is sent";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The client application signature answered Uncertain by the crypto provider: ActivateSession is not sent
// without a signature; the activation fails with Bad_InternalError and the CryptoAnswerUncertain detail whose
// inner status is the provider's code.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSessionShellTests, AnUncertainClientSignatureIsRefusedAndNothingIsSent)
{
  boost::asio::thread_pool tp;
  auto fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
  SecuredSessionSetup setup;
  setup.crypto = fakeCrypto;
  setup.policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  setup.serverKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  setup.serverCert = make_rsa_cert(setup.crypto, setup.serverKeys, "TestServer", "1", "urn:TestServer");
  setup.clientKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  setup.clientCert = make_rsa_cert(setup.crypto, setup.clientKeys, "TestClient", "2");
  setup.defaultServerNonce = random_bytes(*setup.crypto, setup.policy->nonce_length());
  SecuredSessionSetup::wire_session(setup, tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  fakeCrypto->set_park_async(true);
  auto activated = std::make_shared<std::promise<VoidResult>>();
  auto activatedFuture = activated->get_future();
  setup.session->activate(
    Session::ActivateConfig{}, [activated](VoidResult result) { activated->set_value(result); });

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (fakeCrypto->pending_asymmetric_sign_count() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(fakeCrypto->pending_asymmetric_sign_count(), 1U) << "the client signature was not requested";
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  fakeCrypto->complete_pending_asymmetric_sign(0, ByteStringResult{uncertain});

  ASSERT_EQ(activatedFuture.wait_for(3s), std::future_status::ready) << "the activation must complete";
  const auto result = activatedFuture.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
  EXPECT_FALSE(setup.first_captured<ActivateSessionRequest>().has_value()) << "no ActivateSession is sent";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SC-012
// @verifies CL-DISC-004
// @verifies CL-SESS-003
// OPC 10000-4 section 5.6.2 (P4-0004, SHALL): the ApplicationInstanceCertificate in CreateSessionResponse
// must be the SAME certificate the secure channel was opened against (the GetEndpoints/OPN server
// certificate). A server that returns a DIFFERENT certificate is substituting identity mid-handshake and must
// be rejected BEFORE ActivateSession. Inject a Good response (valid serverSignature over
// clientCert||clientNonce) but swap the serverCertificate to a rogue cert. The client must reject with
// BadSecurityChecksFailed and never reach Created. The asserted status is the discriminator: without the
// continuity check the client would proceed to signature validation, which - verifying the (real-key)
// signature against the ROGUE public key - would instead fail with BadApplicationSignatureInvalid. Asserting
// BadSecurityChecksFailed proves the continuity check fired first, not the pre-existing signature check.
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, CL-SC-012, CL-SESS-003, scope=function)
TEST(ClientSessionShellTests, ServerCertMismatchBetweenChannelAndCreateSessionRejected)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());

  // A rogue server certificate whose DER differs from the OPN (channel) certificate held in SecurityInfo.
  auto rogueKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto rogueCert = make_rsa_cert(setup.crypto, rogueKeys, "RogueServer", "99");
  ASSERT_NE(rogueCert->der_encoding(), setup.serverCert->der_encoding())
    << "the rogue certificate must actually differ from the channel certificate";

  auto response = setup.make_good_create_response();
  response->server_certificate() = rogueCert->der_encoding();  // substitute identity in CreateSession
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms))
    << "a CreateSession certificate that differs from the channel certificate must fire the error callback";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadSecurityChecksFailed})
    << "the continuity check (P4-0004) must reject BEFORE signature validation";
  EXPECT_FALSE(setup.session->is_created()) << "the session must not become Created on a cert mismatch";
  EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SC-012
// The continuity check must NOT block the legitimate case: when CreateSessionResponse carries the SAME
// certificate the channel was opened against (make_good_create_response uses setup.serverCert), the client
// passes the check and proceeds to a valid signature validation, reaching Created. Falsifiable: a check that
// wrongly rejected matching certificates would fire the error callback and never reach Created.
// @relation(CL-SC-012, scope=function)
TEST(ClientSessionShellTests, MatchingServerCertAcrossChannelAndCreateSessionProceeds)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_created(3000ms))
    << "a matching CreateSession certificate must pass the continuity check and reach Created";
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-004
// OPC 10000-4 section 5.4.1(a): once unauthenticated discovery evidence selected the channel, the server
// certificate ApplicationUri must equal the EndpointDescription ApplicationUri. Keep the discovery and
// CreateSession EndpointDescriptions identical so only the certificate/ApplicationUri comparison can fail.
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, scope=function)
TEST(ClientSessionShellTests, DiscoveryApplicationUriMismatchClosesChannelAndRejectsCreate)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:RogueServer");
  auto setup = SecuredSessionSetup::create_secured(
    tp.get_executor(), {endpoint}, false, std::string{"opc.tcp://localhost:4840"});

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  EXPECT_NE(to_string(*setup.sync->errorDetail).find("ApplicationUri"), std::string::npos)
    << to_string(*setup.sync->errorDetail);
  EXPECT_FALSE(setup.session->is_created());
  EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);
  EXPECT_EQ(setup.all_captured<CloseSessionRequest>().size(), 1u)
    << "fail-closed discovery rejection must not strand the server-created Session";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-004
// @verifies CL-SESS-005
// OPC 10000-4 section 5.4.1(c): the authenticated CreateSession EndpointDescriptions must equal the
// unauthenticated GetEndpoints set that drove selection. Change one field while retaining a valid
// certificate and server signature; acceptance would prove the discovery substitution was not detected.
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, CL-SESS-005, scope=function)
TEST(ClientSessionShellTests, DiscoveryEndpointMismatchClosesChannelAndRejectsCreate)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {endpoint});

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response();
  response->server_endpoints().payload().front().security_level() = 99;
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  EXPECT_NE(to_string(*setup.sync->errorDetail).find("EndpointDescriptions"), std::string::npos);
  EXPECT_FALSE(setup.session->is_created());
  EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);
  EXPECT_EQ(setup.all_captured<CloseSessionRequest>().size(), 1u)
    << "fail-closed discovery rejection must not strand the server-created Session";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-004
// @verifies CL-SESS-005
// Positive control: matching discovery/CreateSession endpoint sets and a certificate SAN URI matching the
// endpoint's ApplicationUri must pass all three verification clauses and reach Created.
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, CL-SESS-005, scope=function)
TEST(ClientSessionShellTests, MatchingDiscoveryEvidenceProceedsToCreated)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {endpoint});

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created())
    << (setup.sync->errorDetail ? to_string(*setup.sync->errorDetail) : std::string{"no error detail"});
  EXPECT_FALSE(setup.sync->errorOccurred)
    << (setup.sync->errorDetail ? to_string(*setup.sync->errorDetail) : std::string{"no error detail"});

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-004
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, scope=function)
// Part 4 section 5.6.2.2 restricts verification to seven parameters. Milo omits
// the remaining fields in CreateSession; those omissions must not reject a Session.
TEST(ClientSessionShellTests, DiscoveryNonEssentialEndpointFieldsAreNotVerified)
{
  for (int field = 0; field < 8; ++field)
  {
    SCOPED_TRACE(field);
    boost::asio::thread_pool pool{2};
    auto endpoint = make_discovery_endpoint("urn:TestServer");
    endpoint.server().product_uri() = "urn:fixture:product";
    endpoint.server().application_name() = LocalizedText{"en", "Test Server"};
    endpoint.server().application_type() = ApplicationType::Server;
    endpoint.server().gateway_server_uri() = "urn:fixture:gateway";
    endpoint.server().discovery_profile_uri() = "urn:fixture:discovery-profile";
    endpoint.server().discovery_urls().push_back("opc.tcp://localhost:4840/discovery");
    endpoint.server_certificate() = ByteString{std::vector<std::byte>{std::byte{1}, std::byte{2}}};
    auto setup = SecuredSessionSetup::create_secured(pool.get_executor(), {endpoint});
    ASSERT_TRUE(setup.wait_for_pending_request());
    auto response = setup.make_good_create_response();
    auto& authenticated = response->server_endpoints().payload().front();
    switch (field)
    {
    case 0:
      authenticated.server().product_uri() = String{};
      break;
    case 1:
      authenticated.server().application_name() = LocalizedText{};
      break;
    case 2:
      authenticated.server().application_type() = ApplicationType::Client;
      break;
    case 3:
      authenticated.server().gateway_server_uri() = String{};
      break;
    case 4:
      authenticated.server().discovery_profile_uri() = String{};
      break;
    case 5:
      authenticated.server().discovery_urls().payload().clear();
      break;
    case 6:
      authenticated.server_certificate() = ByteString{};
      break;
    case 7:
      authenticated.server() = ApplicationDescription{};
      authenticated.server().application_uri() = "urn:TestServer";
      authenticated.server_certificate() = ByteString{};
      break;
    }
    ASSERT_TRUE(setup.inject_channel_response(std::move(response)));
    EXPECT_TRUE(setup.sync->wait_created(3000ms))
      << (setup.sync->errorDetail ? to_string(*setup.sync->errorDetail) : std::string{"no error detail"});
    EXPECT_TRUE(setup.session->is_created());
    EXPECT_FALSE(setup.sync->errorOccurred);
    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(pool);
  }
}

// @verifies CL-DISC-004
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, scope=function)
TEST(ClientSessionShellTests, EveryEssentialDiscoveryEndpointFieldRejectsSubstitution)
{
  for (int field = 0; field < 7; ++field)
  {
    SCOPED_TRACE(field);
    boost::asio::thread_pool pool{2};
    auto endpoint = make_discovery_endpoint("urn:TestServer");
    auto setup = SecuredSessionSetup::create_secured(pool.get_executor(), {endpoint});
    ASSERT_TRUE(setup.wait_for_pending_request());
    auto response = setup.make_good_create_response();
    auto& authenticated = response->server_endpoints().payload().front();
    switch (field)
    {
    case 0:
      authenticated.server().application_uri() = "urn:substituted:server";
      break;
    case 1:
      authenticated.endpoint_url() = "opc.tcp://other.example:4840";
      break;
    case 2:
      authenticated.security_mode() = MessageSecurityMode::Sign;
      break;
    case 3:
      authenticated.security_policy_uri() = "http://opcfoundation.org/UA/SecurityPolicy#None";
      break;
    case 4:
      authenticated.user_identity_tokens().payload().front().policy_id() = "substituted-token-policy";
      break;
    case 5:
      authenticated.transport_profile_uri() = "urn:substituted:transport";
      break;
    case 6:
      authenticated.security_level() = 99;
      break;
    }
    ASSERT_TRUE(setup.inject_channel_response(std::move(response)));
    ASSERT_TRUE(setup.sync->wait_error(3000ms));
    EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadSecurityChecksFailed});
    ASSERT_NE(setup.sync->errorDetail, nullptr);
    EXPECT_NE(to_string(*setup.sync->errorDetail).find("EndpointDescriptions"), std::string::npos);
    EXPECT_FALSE(setup.session->is_created());
    EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);
    EXPECT_EQ(setup.all_captured<CloseSessionRequest>().size(), 1u);
    EXPECT_TRUE(setup.all_captured<ActivateSessionRequest>().empty());
    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(pool);
  }
}

// @verifies CL-DISC-004
// The SecureChannel must correspond to one record in the retained discovery set; otherwise the evidence is
// unrelated to the channel being authenticated and cannot satisfy section 5.4.1.
// @relation(CL-DISC-004, scope=function)
TEST(ClientSessionShellTests, DiscoveryEvidenceMissingSelectedEndpointRejectsCreate)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://different.example:4840";
  auto setup = SecuredSessionSetup::create_secured(
    tp.get_executor(), {endpoint}, false, std::string{"opc.tcp://localhost:4840"});

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  EXPECT_NE(to_string(*setup.sync->errorDetail).find("selected_endpoint"), std::string::npos);
  EXPECT_EQ(setup.all_captured<CloseSessionRequest>().size(), 1u);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-004
// EndpointDescriptions are a set for verification purposes: a server may reorder otherwise-identical
// records. Multiplicity still matters, but ordering alone must not cause a false security rejection.
// @relation(CL-DISC-004, scope=function)
TEST(ClientSessionShellTests, ReorderedMatchingDiscoveryEndpointSetProceeds)
{
  boost::asio::thread_pool tp;
  auto selected = make_discovery_endpoint("urn:TestServer");
  auto secondary = selected;
  secondary.endpoint_url() = "opc.tcp://secondary.example:4840";
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {selected, secondary});

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response();
  std::ranges::reverse(response->server_endpoints().payload());
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// Part 4 section 5.4.1 requires the HostName in the CreateSession endpointUrl to match the server
// certificate. Default policy closes on mismatch. Discovery/CreateSession sets and ApplicationUri remain
// identical so hostname verification is the only failing discriminator.
// @verifies AC-CL-DISC-005-HOSTNAME-MATCH
// @relation(AC-CL-DISC-005-HOSTNAME-MATCH, CL-DISC-005, scope=function)
TEST(ClientSessionShellTests, DiscoveryHostnameMismatchFailsClosedByDefault)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://host-b.example:4840";
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {endpoint});

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadCertificateHostNameInvalid});
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  EXPECT_NE(to_string(*setup.sync->errorDetail).find("HostName"), std::string::npos);
  EXPECT_EQ(setup.all_captured<CloseSessionRequest>().size(), 1u);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// A CreateSession response can contain several endpoints with the same SecurityPolicy. Hostname
// verification must use the endpoint for the connected port/path resource, not the first same-policy
// record: an unrelated endpoint whose hostname matches the certificate must not mask a mismatch on the
// connected resource.
// @relation(CL-DISC-005, scope=function)
TEST(ClientSessionShellTests, ExactUrlHostnameCheckRejectsUnrelatedSamePolicyEndpointMask)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(
    tp.get_executor(), {}, false, std::string{"opc.tcp://dialed-host.example:4840/connected"});

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response();
  auto unrelated = make_discovery_endpoint("urn:TestServer");
  unrelated.endpoint_url() = "opc.tcp://localhost:4841/unrelated";
  auto connected = make_discovery_endpoint("urn:TestServer");
  connected.endpoint_url() = "opc.tcp://host-b.example:4840/connected";
  response->server_endpoints().payload() = {std::move(unrelated), std::move(connected)};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadCertificateHostNameInvalid});
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  const std::string errorText = to_string(*setup.sync->errorDetail);
  EXPECT_NE(errorText.find("host-b.example"), std::string::npos);
  EXPECT_NE(errorText.find("localhost"), std::string::npos);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// SecurityPolicy None has no OPN-time certificate, but CreateSession may still return the Server
// ApplicationInstanceCertificate. Part 4's HostName comparison applies to that certificate as well; the
// absence of a channel certificate must not silently disable the check.
// @relation(CL-DISC-005, scope=function)
TEST(ClientSessionShellTests, NoneChannelCreateSessionCertificateHostnameMismatchFailsClosed)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  auto setup =
    SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store, "opc.tcp://host-b.example:4840");

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response();
  ASSERT_EQ(response->server_endpoints().size(), 1u);
  response->server_endpoints().payload().front().endpoint_url() = "opc.tcp://host-b.example:4840";
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadCertificateHostNameInvalid});
  ASSERT_NE(setup.sync->errorDetail, nullptr);
  const std::string errorText = to_string(*setup.sync->errorDetail);
  EXPECT_NE(errorText.find("host-b.example"), std::string::npos);
  EXPECT_NE(errorText.find("localhost"), std::string::npos);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// The explicit relax policy implements Part 4's "may close": the mismatch is reported as a warning but
// CreateSession proceeds.
// @verifies AC-CL-DISC-005-HOSTNAME-MATCH
// @relation(AC-CL-DISC-005-HOSTNAME-MATCH, CL-DISC-005, scope=function)
TEST(ClientSessionShellTests, RelaxedDiscoveryHostnameMismatchProceeds)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://host-b.example:4840";
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {endpoint}, true);

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());
  EXPECT_FALSE(setup.sync->errorOccurred);
  EXPECT_TRUE(setup.sessionDeps->has_log_message("relaxHostNameCheck is enabled"))
    << "the relaxed policy may continue, but Part 4 still requires the mismatch to be reported";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// @verifies CL-DISC-014
// `.local` is part of the HostName (owner ruling 2026-10-19): a `.local` URL is not matched by the
// certificate's unqualified DNS SAN, so the session fails closed as for any other mismatch.
// @verifies AC-CL-DISC-005-HOSTNAME-MATCH
// @relation(AC-CL-DISC-005-HOSTNAME-MATCH, CL-DISC-005, CL-DISC-014, scope=function)
TEST(ClientSessionShellTests, DiscoveryHostnameLocalSuffixDoesNotMatchUnqualifiedCertificateSan)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://localhost.local:4840";
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {endpoint});

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadCertificateHostNameInvalid});
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// Numeric endpoint hosts compare against IP-address SAN entries, not DNS SAN strings.
// @relation(CL-DISC-005, scope=function)
TEST(ClientSessionShellTests, DiscoveryIpAddressMatchesCertificateIpSan)
{
  boost::asio::thread_pool tp;
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {endpoint});

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DISC-005
// Part 4 section 5.4.1 includes IP addresses among the possible HostNames in an
// ApplicationInstanceCertificate. Legacy certificates can encode that numeric host as dNSName; exact
// numeric equality remains a valid HostName match and must not reject an otherwise valid Session.
// @relation(CL-DISC-005, scope=function)
TEST(ClientSessionShellTests, DiscoveryIpAddressMatchesNumericDnsSan)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_with_server_chain(tp.get_executor());
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  setup.discoveryEndpoints = {endpoint};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-006
// Over a None SecureChannel with an anonymous, unauthenticated session the client does NOT perform the
// server-certificate / application-signature check (there is no security context to bind). Inject a Good
// CreateSessionResponse whose server_certificate and server_signature are pure garbage; the client must
// still reach Created (and not Active) because it never looked at either field.
// Falsifiable: a client that validated the AIC/signature unconditionally would reject the garbage and
// fail to reach Created.
// @relation(CL-SESS-006, scope=function)
TEST(ClientSessionShellTests, NoneChannelIgnoresServerCertAndSignature)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = std::make_shared<CreateSessionResponse>();
  response->response_header().service_result() = Status::Good;
  response->session_id() = NodeId{1, 42};
  response->authentication_token() = NodeId{1, 99};
  response->revised_session_timeout() = 600000.0;
  response->server_certificate() = ByteString{std::vector<std::byte>(48, std::byte{0xAB})};
  response->server_signature().signature() = ByteString{std::vector<std::byte>(64, std::byte{0xCD})};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_created(1000ms))
    << "None/anonymous create must complete despite garbage AIC/sig";
  EXPECT_TRUE(setup.session->is_created());
  EXPECT_FALSE(setup.session->is_active());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-008
// Part 4 5.6.3: the serverNonce returned by CreateSession is stored verbatim and is the challenge the
// client signs (serverCert || serverNonce) in the ActivateSession clientSignature. Assert (a) the stored
// nonce equals the exact bytes delivered, and (b) the captured ActivateSession clientSignature verifies
// over (serverCert || storedNonce) with the client public key. Anti-tautology: the same signature must NOT
// verify over (serverCert || a fresh random nonce).
// Falsifiable: a client that mangled the stored nonce, or signed a different payload, fails (a) or (b);
// the negative check fails if signature_verifies ignored its data argument.
// @relation(CL-SESS-008, scope=function)
TEST(ClientSessionShellTests, ServerNonceStoredVerbatimAndUsedForActivateSignature)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  const ByteString createNonce = setup.defaultServerNonce;

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  EXPECT_EQ(setup.stored_server_nonce(), createNonce) << "serverNonce must be stored verbatim";

  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  ByteString expected = setup.serverCert->der_encoding();
  std::ranges::copy(createNonce, std::back_inserter(expected));
  EXPECT_TRUE(setup.signature_verifies(
    setup.clientCert->public_key(), expected, request->client_signature().signature()))
    << "clientSignature must be sign(serverCert || createServerNonce) with the client key";

  ByteString wrong = setup.serverCert->der_encoding();
  std::ranges::copy(random_bytes(*setup.crypto, createNonce.size()), std::back_inserter(wrong));
  EXPECT_FALSE(
    setup.signature_verifies(setup.clientCert->public_key(), wrong, request->client_signature().signature()))
    << "a fresh random nonce must NOT verify (anti-tautology)";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-010
// @verifies CL-SESS-012
// @verifies CL-SC-012
// Part 4 5.6.3: the ActivateSession clientSignature must be a valid signature over (serverCert ||
// serverNonce) and its SignatureData.algorithm must be the SecurityPolicy AsymmetricSignatureAlgorithm URI.
// Verify the real OpenSSL signature and match the algorithm URI (which contains "sha256" for Basic256Sha256).
// Falsifiable: a signature that does not verify, or a mismatched/absent algorithm URI, fails.
// CL-SC-012 (Part 4 5.5.2, "the same Certificates are used in CreateSession and ActivateSession"): the
// signedData oracle below is built from the CreateSession server certificate (setup.serverCert, delivered
// via make_good_create_response), and the captured ActivateSession clientSignature verifies against it.
// A client that used a different certificate for ActivateSession would produce a signature that does NOT
// verify over the CreateSession serverCert, failing this test - so this demonstrates the client's
// client-side obligation to reuse the same (stored) server cert across both services (which the client
// does by construction; it receives no cert in ActivateSession, only reuses the stored one).
// @relation(CL-SC-012, CL-SESS-010, CL-SESS-012, scope=function)
TEST(ClientSessionShellTests, ActivateSignatureVerifiesAndAlgorithmMatchesPolicy)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  const ByteString createNonce = setup.defaultServerNonce;

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  ByteString signedData = setup.serverCert->der_encoding();
  std::ranges::copy(createNonce, std::back_inserter(signedData));
  EXPECT_TRUE(setup.signature_verifies(
    setup.clientCert->public_key(), signedData, request->client_signature().signature()))
    << "the ActivateSession clientSignature must verify over (serverCert || serverNonce)";

  EXPECT_EQ(std::string_view{request->client_signature().algorithm()},
    std::string_view{setup.policy->asymmetric_signature_algorithm_uri()})
    << "clientSignature.algorithm must be the SecurityPolicy AsymmetricSignatureAlgorithm URI";
  const std::string algorithm{std::string_view{request->client_signature().algorithm()}};
  EXPECT_NE(algorithm.find("sha256"), std::string::npos)
    << "Basic256Sha256 signature algorithm URI must reference sha256";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-011
// OPC 10000-4 section 5.6.3.2: when the serverCertificate contains a concatenated chain, only its first
// (leaf) certificate participates in the ActivateSession clientSignature calculation. Drive the real
// crypto path with a CA-issued server leaf and append its issuer to the CreateSession certificate bytes.
// The signature must verify over leaf DER || nonce and must not verify over chain DER || nonce.
// @relation(CL-SESS-011, scope=function)
TEST(ClientSessionShellTests, ActivateSignatureUsesServerLeafCertificateOnly)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_with_server_chain(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = setup.make_good_create_response();
  const ByteString leafDer = setup.serverCert->der_encoding();
  ASSERT_NE(setup.serverIssuerCert, nullptr);
  ByteString chainDer = leafDer;
  const ByteString issuerDer = setup.serverIssuerCert->der_encoding();
  std::ranges::copy(issuerDer, std::back_inserter(chainDer));
  ASSERT_GT(chainDer.size(), leafDer.size()) << "fixture must present a leaf plus issuer chain";
  response->server_certificate() = chainDer;

  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  ByteString leafMaterial = leafDer;
  std::ranges::copy(setup.defaultServerNonce, std::back_inserter(leafMaterial));
  EXPECT_TRUE(setup.signature_verifies(
    setup.clientCert->public_key(), leafMaterial, request->client_signature().signature()));

  ByteString chainMaterial = chainDer;
  std::ranges::copy(setup.defaultServerNonce, std::back_inserter(chainMaterial));
  EXPECT_FALSE(setup.signature_verifies(
    setup.clientCert->public_key(), chainMaterial, request->client_signature().signature()));

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-014
// @verifies CL-IDENT-012 (PARTIAL) - Part 4 section 5.6.3.1 lines 2410-2413: the X509 userTokenSignature is a
// signature over (serverCertificate || last serverNonce) with the USER certificate's private key. This
// test falsifiably covers the SIGNATURE COMPOSITION (serverCert || serverNonce, via real-OpenSSL verify +
// nonce anti-tautology) and the USER-PRIVATE-KEY obligation (userKeys is a freshly generated pair distinct
// from the app instance key, and verification uses the user cert public key). Deferred: the "last/latest
// serverNonce on RE-activation" facet (a second userTokenSignature signs over the nonce from the prior
// ActivateSessionResponse, not the stale CreateSession nonce) is not exercised here - see the integration
// test ClientX509.UserTokenSignatureUsesLatestServerNonce.
// Part 4 5.6.3 lines 2493-2494: "If the Client specified a user identity token that supports digital
// signatures, then it shall create a signature and pass it as this parameter." The signature is built the
// same way as the clientSignature - sign(serverCert || last serverNonce) - but with the USER certificate's
// private key. Advertise a Certificate UserTokenPolicy on the created endpoint, activate with an X509
// identity, and assert the captured ActivateSession carries a userTokenSignature that (a) is non-empty and
// (b) actually VERIFIES over (serverCert || serverNonce) with the user certificate's public key.
// Anti-tautology: the same signature must NOT verify over (serverCert || a fresh random nonce).
// Falsifiable: a client that omitted the signature (empty), or wrote bytes that are not a real signature
// over the required payload, fails (a) or (b); the negative check fails if the verifier ignored its data.
// @relation(CL-IDENT-012, CL-SESS-014, scope=function)
TEST(ClientSessionShellTests, X509IdentityCarriesUserTokenSignature)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ua::UserTokenPolicy certPolicy;
  certPolicy.policy_id() = "cert-1";
  certPolicy.token_type() = ua::UserTokenType::Certificate;
  certPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {certPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto userKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto userCert = make_rsa_cert(setup.crypto, userKeys, "TestUser", "300");

  Session::ActivateConfig config;
  config.policyId = "cert-1";
  config.identity = ua::client::X509Identity{userCert, userKeys};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  ASSERT_FALSE(request->user_token_signature().signature().empty())
    << "an X509 user identity must carry a userTokenSignature in ActivateSession";

  ByteString userSigned = setup.serverCert->der_encoding();
  std::ranges::copy(setup.defaultServerNonce, std::back_inserter(userSigned));
  EXPECT_TRUE(
    setup.signature_verifies(userCert->public_key(), userSigned, request->user_token_signature().signature()))
    << "the userTokenSignature must verify over (serverCert || serverNonce) with the user certificate key";

  ByteString userWrong = setup.serverCert->der_encoding();
  std::ranges::copy(
    random_bytes(*setup.crypto, setup.defaultServerNonce.size()), std::back_inserter(userWrong));
  EXPECT_FALSE(
    setup.signature_verifies(userCert->public_key(), userWrong, request->user_token_signature().signature()))
    << "a fresh random nonce must NOT verify the userTokenSignature (anti-tautology)";

  EXPECT_EQ(std::string_view{request->user_token_signature().algorithm()},
    std::string_view{setup.policy->asymmetric_signature_algorithm_uri()})
    << "the userTokenSignature.algorithm must be the SecurityPolicy AsymmetricSignatureAlgorithm URI "
       "(correct signature bytes with a wrong/empty algorithm URI must not pass)";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 v1.05.07 section 7.40.4 selects RSA password format by UTF-8 byte length.
// The algorithm URI is independent of that format (local v1.05.00 section 7.41.4).
class RsaUsernameTokenBoundaryTests
  : public ::testing::TestWithParam<std::tuple<SecurityPolicyId, std::string>>
{};

// @relation(AC-CL-IDENT-005-A-MODERN-RSA-USER-TOKEN-POLICY, scope=function)
TEST_P(RsaUsernameTokenBoundaryTests, UsesByteLengthAndAsymmetricAlgorithmUri)
{
  const auto& [policyId, password] = GetParam();
  auto crypto = make_secured_crypto();
  auto policy = SecurityPolicy::create(policyId);
  auto keys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 40);
  auto certificate = make_rsa_cert(crypto, keys, "TokenServer", "1", "urn:TokenServer");
  auto nonce = random_bytes(*crypto, policy->nonce_length());
  ByteString secret;
  secret.assign(reinterpret_cast<const uint8_t*>(password.data()),
    reinterpret_cast<const uint8_t*>(password.data()) + password.size());
  auto token = std::make_shared<UserNameIdentityToken>();
  token->password() = secret;
  auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto completion)
    {
      encrypt_user_token_async(policy,
        crypto,
        crypto_test_strand(),
        token,
        nonce,
        certificate,
        {},
        {},
        {},
        Logger{},
        std::move(completion));
    });
  ASSERT_TRUE(result.is_good()) << ua::describe(result.status_code());
  const std::string_view expectedAlgorithm = policyId == SecurityPolicyId::Basic128Rsa15
                                               ? "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
                                             : policyId == SecurityPolicyId::Aes256Sha256RsaPss
                                               ? "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256"
                                               : "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
  EXPECT_EQ(std::string_view{token->encryption_algorithm()}, expectedAlgorithm);
  EXPECT_NE(token->password(), secret);
  if (password.size() <= 64)
  {
    ASSERT_FALSE(is_rsa_encrypted_secret(span<const byte>{token->password()}));
    ByteString plaintext;
    plaintext.resize(token->password().size());
    auto decrypted = crypto->asymmetric_decrypt_sync(
      policy->asymmetric_encryption_algorithm(), keys, token->password(), plaintext);
    auto parsed = parse_legacy_encrypted_token_secret(decrypted, nonce);
    ASSERT_TRUE(parsed.is_good()) << ua::describe(parsed.status_code());
    EXPECT_EQ(parsed.value(), secret);
    auto wrongNonce = nonce;
    wrongNonce[0] ^= 1;
    EXPECT_TRUE(parse_legacy_encrypted_token_secret(decrypted, wrongNonce).is_bad());
  }
  else
  {
    ASSERT_TRUE(is_rsa_encrypted_secret(span<const byte>{token->password()}));
    auto decrypted = ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
      [&](auto completion)
      {
        decrypt_rsa_encrypted_secret_async(token->password(),
          policy,
          crypto,
          crypto_test_strand(),
          keys,
          certificate,
          false,
          Logger{},
          std::move(completion));
      });
    ASSERT_TRUE(decrypted.is_good()) << ua::describe(decrypted.status_code());
    EXPECT_EQ(decrypted.value().secret, secret);
    EXPECT_EQ(decrypted.value().nonce, nonce);
  }
}

INSTANTIATE_TEST_SUITE_P(RsaPolicies, RsaUsernameTokenBoundaryTests,
  ::testing::Combine(::testing::Values(SecurityPolicyId::Basic128Rsa15, SecurityPolicyId::Basic256,
                       SecurityPolicyId::Basic256Sha256, SecurityPolicyId::Aes128Sha256RsaOaep,
                       SecurityPolicyId::Aes256Sha256RsaPss),
    ::testing::Values(
      std::string(1, 'a'), std::string(64, 'a'), std::string(65, 'a'), std::string(128, 'a'),
      []
      {
        std::string text;
        for (int i = 0; i < 32; ++i)
          text += "\u00e9";
        return text;
      }(),
      []
      {
        std::string text;
        for (int i = 0; i < 33; ++i)
          text += "\u00e9";
        return text;
      }())));

TEST(RsaUsernameTokenBoundaryTests, NoEncryptionAlgorithmHasNoUri)
{
  EXPECT_TRUE(asymmetric_encryption_algorithm_uri(AsymmetricEncryptionAlgorithm::Invalid).empty());
}

TEST(RsaUsernameTokenBoundaryTests, MissingServerCertificateFailsBothFormatsWithDetails)
{
  auto crypto = make_secured_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  for (const auto length : {64, 65})
  {
    auto token = std::make_shared<UserNameIdentityToken>();
    token->password().resize(length);
    auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto completion)
      {
        encrypt_user_token_async(policy,
          crypto,
          crypto_test_strand(),
          token,
          random_bytes(*crypto, policy->nonce_length()),
          {},
          {},
          {},
          {},
          Logger{},
          std::move(completion));
      });
    EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
    EXPECT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(token->password().size(), length);
    EXPECT_TRUE(token->encryption_algorithm().empty());
  }
}

// CL-IDENT-006 (Part 4 section 7.41.2.1 lines 10255-10256): "Clients shall validate the Server Certificate
// and ensure it is trusted before sending a UserIdentityToken encrypted with the Certificate." The
// client encrypts the UNP password with mServerCertificate - the same server cert the channel validated
// during OPN and carried through the CreateSession response. This drives the real
// SessionImpl::start_encrypt_user_token flow (encrypt_user_token_async, ua_client_session_impl.cpp:717)
// with a UsernamePasswordIdentity and an encrypting UserName UserTokenPolicy, captures the
// ActivateSessionRequest, and decrypts the token with the SERVER's private key: recovering the plaintext
// password proves the client encrypted to the channel-validated server certificate.
// Falsifiable: a client that shipped the password in cleartext leaves encryption_algorithm empty (or the
// password equal to the cleartext); a client that encrypted to the wrong certificate fails the
// server-key decrypt / nonce-checked parse.
// @verifies CL-IDENT-006 (PARTIAL): proves the client encrypts the UNP token to mServerCertificate (the
// CreateSession/OPN-validated server cert) via the real activate encryption flow with real OpenSSL.
// Deferred: distinguishing the validated cert HANDLE from a fresh decode of identical bytes is not
// wire-observable here; the negative "untrusted cert -> no ActivateSession sent" ordering is structurally
// guaranteed (no session activates on an unopened channel) and is CL-UASC-009/CL-SECADMIN-001's OPN-reject.
// @relation(CL-IDENT-006, scope=function)
TEST(ClientSessionShellTests, UnpTokenEncryptedToChannelValidatedServerCert)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  auto toByteString = [](std::string_view text)
  {
    ByteString bs;
    bs.assign(reinterpret_cast<const uint8_t*>(text.data()),
      reinterpret_cast<const uint8_t*>(text.data()) + text.size());
    return bs;
  };

  ua::UserTokenPolicy unpPolicy;
  unpPolicy.policy_id() = "unp-1";
  unpPolicy.token_type() = ua::UserTokenType::UserName;
  unpPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {unpPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  const std::string_view password = "s3cret-password";
  Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"test-user", std::string{password}};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  auto* token = dynamic_cast<ua::UserNameIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr) << "the activate must carry a UserNameIdentityToken";
  EXPECT_EQ(std::string_view{token->encryption_algorithm()},
    std::string_view{"http://www.w3.org/2001/04/xmlenc#rsa-oaep"})
    << "an encrypted RSA UserName token must name its asymmetric encryption algorithm";
  ASSERT_FALSE(token->password().empty());
  EXPECT_NE(token->password(), toByteString(password))
    << "the password must be encrypted, not shipped as cleartext";

  // A short RSA password uses legacy framing; decrypt with the validated server key and
  // verify the server nonce before accepting the recovered password.
  ASSERT_FALSE(ua::is_rsa_encrypted_secret(span<const byte>{token->password()}));
  ByteString plaintext;
  plaintext.resize(token->password().size());
  auto decrypted = setup.crypto->asymmetric_decrypt_sync(
    setup.policy->asymmetric_encryption_algorithm(), setup.serverKeys, token->password(), plaintext);
  auto parsed = parse_legacy_encrypted_token_secret(decrypted, setup.defaultServerNonce);
  ASSERT_TRUE(parsed.is_good()) << ua::describe(parsed.status_code());
  EXPECT_EQ(parsed.value(), toByteString(password));

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-014 (Part 4 section 7.41.6 line 10607): "This token shall be encrypted by the Client if required
// by the SecurityPolicy of the UserTokenPolicy." The issued-token half of the obligation
// UnpTokenEncryptedToChannelValidatedServerCert pins for UserName, and the client half of SVR-IDENT-018.
// It went unrepresented in the corpus because every client obligation naming an issued token sat under
// CL-JWT-*, which WV-JWT-AUTHZ-FACETS-UNCLAIMED waives - so nothing asked the question while the client
// emitted tokenData verbatim, under a public doc comment promising it was "encrypted on the wire by the
// SDK" (ua_user_identity.h:68).
//
// An issued token is a bearer credential: unlike a password, it is tied to no other secret, so whoever
// observes it can act as the user until it expires. That is why this is asserted through a decrypt
// rather than a difference - bytes that merely differ from the input are equally consistent with
// corruption or a stray re-encoding, either of which would destroy the credential while looking
// encrypted. The server-side decrypt passes only if the client enciphered the exact plaintext, to the
// server's public key, against the nonce the server issued.
//
// Falsifiable four ways, each a real failure mode: a client that skipped encryption ships the supplied
// bytes; one that emitted the policy URI in the outer encryptionAlgorithm violates Table 195; one that
// encrypted to the wrong certificate fails the server-key decrypt; one that reused a stale nonce fails
// the nonce assertion.
// @verifies AC-CL-IDENT-014-ISSUEDTOKEN-ENCRYPTED
// @relation(AC-CL-IDENT-014-ISSUEDTOKEN-ENCRYPTED, scope=function)
TEST(ClientSessionShellTests, IssuedTokenDataIsEncryptedToTheServerCertificateWhenThePolicyRequiresIt)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  auto toByteString = [](std::string_view text)
  {
    ByteString bs;
    bs.assign(reinterpret_cast<const uint8_t*>(text.data()),
      reinterpret_cast<const uint8_t*>(text.data()) + text.size());
    return bs;
  };

  ua::UserTokenPolicy issuedPolicy;
  issuedPolicy.policy_id() = "issued-1";
  issuedPolicy.token_type() = ua::UserTokenType::IssuedToken;
  issuedPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {issuedPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  // Opaque bytes: this obligation is about transport, not about what the token says. Nothing here
  // parses it, and CL-IDENT-014 holds whether or not it is ever a JWT.
  const std::string_view issuedTokenText = "opaque-issued-token-bytes";
  const ByteString issuedTokenBytes = toByteString(issuedTokenText);

  Session::ActivateConfig config;
  config.policyId = "issued-1";
  config.identity = ua::client::IssuedTokenIdentity{issuedTokenBytes};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  auto* token = dynamic_cast<ua::IssuedIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr) << "the activate must carry an IssuedIdentityToken";
  ASSERT_FALSE(token->token_data().empty());
  EXPECT_NE(token->token_data(), issuedTokenBytes)
    << "the issued token must be encrypted, not shipped as the supplied bytes";
  EXPECT_TRUE(token->encryption_algorithm().empty())
    << "Part 4 section 7.41.6 Table 195 requires an empty outer encryptionAlgorithm when tokenData "
       "uses EncryptedSecret; the policy URI is carried inside the envelope";

  // Part 4 section 7.41.6 lines 10604-10605: an encrypted issued token uses the section 7.41.2.3
  // EncryptedSecret format. Basic256Sha256 is a modern RSA policy, so the legacy Length||secret||nonce
  // encoding would be a spec violation here even though it also produces bytes that differ from the input.
  ASSERT_TRUE(ua::is_rsa_encrypted_secret(span<const byte>{token->token_data()}))
    << "a modern RSA policy must emit an RsaEncryptedSecret, not the legacy user-token secret form";

  auto decResult = ua::test_helpers::run_async_function_sync<ua::RsaEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      ua::decrypt_rsa_encrypted_secret_async(token->token_data(),
        setup.policy,
        setup.crypto,
        crypto_test_strand(),
        setup.serverKeys,
        setup.serverCert,
        false,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(decResult.is_good()) << to_string(decResult.status_code().as_status());
  EXPECT_EQ(decResult.value().secret, issuedTokenBytes)
    << "decrypting with the server private key must recover the supplied issued-token bytes exactly, "
       "proving the client enciphered the credential rather than mangling it";
  EXPECT_EQ(decResult.value().nonce, setup.defaultServerNonce)
    << "the RsaEncryptedSecret payload must carry the server nonce for freshness";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.41.6 does not inherit the legacy UserName secret exception for deprecated RSA
// SecurityPolicies: every encrypted IssuedIdentityToken shall use EncryptedSecret. This drives the real
// SessionImpl activation under Basic256 (deprecated), verifies the captured wire token is an
// RsaEncryptedSecret rather than `Length || secret || nonce`, requires Table 195's empty outer algorithm,
// and decrypts it with the server private key. The Basic256Sha256 sibling above controls the modern-RSA
// branch, so this test goes red specifically if the generic UserName legacy branch is reused.
// @relation(AC-CL-IDENT-014-ISSUEDTOKEN-ENCRYPTED, scope=function)
TEST(ClientSessionShellTests, DeprecatedRsaIssuedTokenStillUsesEncryptedSecretWithEmptyAlgorithm)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_rsa(tp.get_executor(), SecurityPolicyId::Basic256);
  ASSERT_TRUE(setup.policy->is_deprecated());

  ua::UserTokenPolicy issuedPolicy;
  issuedPolicy.policy_id() = "issued-deprecated-rsa";
  issuedPolicy.token_type() = ua::UserTokenType::IssuedToken;
  issuedPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {issuedPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  const ByteString original = random_bytes(*setup.crypto, 31);
  Session::ActivateConfig config;
  config.policyId = "issued-deprecated-rsa";
  config.identity = ua::client::IssuedTokenIdentity{original};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  auto* token = dynamic_cast<ua::IssuedIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr);
  EXPECT_TRUE(token->encryption_algorithm().empty());
  ASSERT_TRUE(ua::is_rsa_encrypted_secret(span<const byte>{token->token_data()}))
    << "deprecated RSA is not permission to emit the legacy UserName secret for an IssuedIdentityToken";

  auto decrypted = ua::test_helpers::run_async_function_sync<ua::RsaEncryptedSecretFieldsResult>(
    [&](auto callback)
    {
      ua::decrypt_rsa_encrypted_secret_async(token->token_data(),
        setup.policy,
        setup.crypto,
        crypto_test_strand(),
        setup.serverKeys,
        setup.serverCert,
        false,
        ua::Logger{},
        std::move(callback));
    });
  ASSERT_TRUE(decrypted.is_good()) << to_string(decrypted.status_code().as_status());
  EXPECT_EQ(decrypted.value().secret, original);
  EXPECT_EQ(decrypted.value().nonce, setup.defaultServerNonce);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The ECC half of the same Table 195 contract. The CreateSession response supplies a real signed
// ECDHKey, the client emits an EccEncryptedSecret through SessionImpl, and the server-side decoder
// recovers the exact nonce and opaque token. The outer algorithm must nevertheless remain empty.
// @relation(AC-CL-IDENT-014-ISSUEDTOKEN-ENCRYPTED, scope=function)
TEST(ClientSessionShellTests, EccIssuedTokenUsesEncryptedSecretWithEmptyAlgorithm)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_ecc(tp.get_executor(),
    SecurityPolicyId::EccNistP256AesGcm,
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256);
  auto* eccPolicyRaw = dynamic_cast<SecPolEphemeralKey*>(setup.policy.get());
  ASSERT_NE(eccPolicyRaw, nullptr);
  std::shared_ptr<const SecPolEphemeralKey> eccPolicy{setup.policy, eccPolicyRaw};
  const auto serverEphemeral = setup.crypto->create_ephemeral_keys_sync(eccPolicy->ephemeral_key_algorithm());

  ua::UserTokenPolicy issuedPolicy;
  issuedPolicy.policy_id() = "issued-ecc";
  issuedPolicy.token_type() = ua::UserTokenType::IssuedToken;
  issuedPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResponse = setup.make_good_create_response(setup.defaultServerNonce, {issuedPolicy});
  auto ephemeral = std::make_unique<ua::EphemeralKeyType>();
  ephemeral->public_key() = serverEphemeral.publicKey;
  ephemeral->signature() = setup.crypto->asymmetric_sign_sync(
    setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, serverEphemeral.publicKey);
  auto additional = std::make_unique<ua::AdditionalParametersType>();
  ua::KeyValuePair ecdhKey;
  ecdhKey.key() = ua::QualifiedName{0, "ECDHKey"};
  ecdhKey.value() = ua::Variant{std::move(ephemeral)};
  additional->parameters().payload().push_back(std::move(ecdhKey));
  createResponse->response_header().additional_header() = std::move(additional);
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResponse)));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  const ByteString original = random_bytes(*setup.crypto, 29);
  Session::ActivateConfig config;
  config.policyId = "issued-ecc";
  config.identity = ua::client::IssuedTokenIdentity{original};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>())
    << "issued-token activation failed before sending the request: status="
    << to_string(setup.sync->errorStatus.as_status())
    << ", detail=" << (setup.sync->errorDetail ? to_string(*setup.sync->errorDetail) : std::string{"none"});
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  auto* token = dynamic_cast<ua::IssuedIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr);
  EXPECT_TRUE(token->encryption_algorithm().empty());
  ASSERT_NE(token->token_data(), original);

  auto decrypted = ua::test_helpers::run_async_function_sync<ua::EccEncryptedSecretFieldsResult>(
    [&](auto callback)
    {
      ua::decrypt_ecc_encrypted_secret_async(token->token_data(),
        eccPolicy,
        setup.crypto,
        crypto_test_strand(),
        serverEphemeral.privateKey,
        serverEphemeral.publicKey,
        setup.clientCert,
        ua::Logger{},
        std::move(callback));
    });
  ASSERT_TRUE(decrypted.is_good()) << to_string(decrypted.status_code().as_status());
  EXPECT_EQ(decrypted.value().secret, original);
  EXPECT_EQ(decrypted.value().nonce, setup.defaultServerNonce);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-006 (Part 4 section 7.41.2.1 lines 10255-10256): "Clients shall validate the Server Certificate
// and ensure it is trusted before sending a UserIdentityToken encrypted with the Certificate." On a SECURED
// channel the server certificate is validated during OPN and delivered under channel signing/encryption, so
// the token-encryption certificate is already trusted (see UnpTokenEncryptedToChannelValidatedServerCert).
// On a NONE channel there is no OPN validation and the CreateSession server certificate arrives UNPROTECTED:
// a man-in-the-middle that substitutes its own certificate would otherwise have the client encrypt the
// UserName secret to the attacker's key and hand it over. The client must therefore validate the server
// certificate against its trust store BEFORE encrypting the token on a None channel, and REFUSE the
// activation (never emit the ciphertext) when the certificate is untrusted.
// Falsifiable: a client that skipped the trust check encrypts and sends the ActivateSession regardless (an
// ActivateSessionRequest is captured and the activation does not fail); this test asserts NO ActivateSession
// is sent and the session fails Bad_CertificateUntrusted.
// @verifies CL-IDENT-006: None-channel user-token encryption is gated on server-certificate trust
// (fail-closed) - an untrusted server certificate refuses the activation with no ciphertext on the wire.
// @relation(CL-IDENT-006, scope=function)
TEST(ClientSessionShellTests, NoneChannelRefusesUnpEncryptionWhenServerCertUntrusted)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);

  ua::UserTokenPolicy unpPolicy;
  unpPolicy.policy_id() = "unp-1";
  unpPolicy.token_type() = ua::UserTokenType::UserName;
  unpPolicy.security_policy_uri() = std::string{setup.policy->uri()};  // Basic256Sha256 -> encrypting token

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {unpPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"test-user", std::string{"s3cret-password"}};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.sync->wait_error(3000ms))
    << "an untrusted server certificate must fail the activation, not silently proceed";
  EXPECT_EQ(setup.sync->errorStatus, Status::BadCertificateUntrusted)
    << "the refusal must report the trust failure";

  auto request = setup.first_captured<ActivateSessionRequest>();
  EXPECT_FALSE(request.has_value())
    << "the client must NOT send the encrypted UserName token when the server certificate is untrusted";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-006 (positive companion): a TRUSTED server certificate on a None channel passes the
// pre-encryption validation gate, so the client proceeds to encrypt the UserName token and send the
// ActivateSession. Proves the gate is a trust check, not a blanket None-channel refusal, and that a
// genuinely encrypted token still reaches the wire on the trusted path.
// Falsifiable: a gate that refused all None-channel encryption sends no ActivateSession; a gate that
// failed-open with cleartext ships the plaintext password. This asserts an ActivateSession carrying a
// genuinely encrypted (non-cleartext) token is sent.
// @verifies CL-IDENT-006: a trusted server certificate admits None-channel user-token encryption.
// @relation(CL-IDENT-006, scope=function)
TEST(ClientSessionShellTests, NoneChannelEncryptsUnpTokenWhenServerCertTrusted)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->validateCertificateStatus = StatusCode{Status::Good};  // trusted server certificate
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);

  auto toByteString = [](std::string_view text)
  {
    ByteString bs;
    bs.assign(reinterpret_cast<const uint8_t*>(text.data()),
      reinterpret_cast<const uint8_t*>(text.data()) + text.size());
    return bs;
  };

  ua::UserTokenPolicy unpPolicy;
  unpPolicy.policy_id() = "unp-1";
  unpPolicy.token_type() = ua::UserTokenType::UserName;
  unpPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {unpPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  const std::string_view password = "s3cret-password";
  Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"test-user", std::string{password}};
  setup.session->activate(std::move(config), [](VoidResult) {});

  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>())
    << "a trusted server certificate must let the encrypted activation through";
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());

  auto* token = dynamic_cast<ua::UserNameIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr) << "the activate must carry a UserNameIdentityToken";
  EXPECT_EQ(std::string_view{token->encryption_algorithm()},
    std::string_view{"http://www.w3.org/2001/04/xmlenc#rsa-oaep"})
    << "an encrypted RSA UserName token must name its asymmetric encryption algorithm";
  ASSERT_FALSE(token->password().empty());
  EXPECT_NE(token->password(), toByteString(password))
    << "the password must be encrypted, not shipped as cleartext";

  // Identity binding (CL-IDENT-006): a trust check alone (chains to a trusted CA) does not defend against a
  // MITM presenting its own CA-issued certificate - the gate must validate the certificate against the DIALED
  // endpoint. Assert the session threaded its endpoint URL into validation (parity with the OPN path), so a
  // wrong-identity-but-CA-trusted certificate would be checkable. A gate that passed nullopt would leave this
  // captured value empty.
  ASSERT_TRUE(store->lastValidatedEndpointUrl.has_value())
    << "the None-channel trust gate must thread the dialed endpoint URL, not validate anonymously";
  EXPECT_EQ(store->lastValidatedEndpointUrl.value(), setup.endpointUrl);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-006 (teardown-race guard, section 3.1-derived): the server-certificate validation is an async op
// that re-enters the session strand only on liveness, not on activate-flow state. If the session is torn down
// (here: channel disconnect) while the verdict is in flight, the late verdict must be DROPPED - re-driving
// session teardown would spuriously re-fire the persistent error observer. Uses a store that holds the
// verdict (validationDeferral) so the teardown is interleaved before the (untrusted) verdict is released.
// Falsifiable: without the mActivateFlow guard on the refuse path, releasing the late BAD verdict re-fires
// the error observer, overwriting the teardown status with Bad_CertificateUntrusted.
// @verifies CL-IDENT-006: a validation verdict arriving after session teardown is dropped, not re-delivered.
// @relation(CL-IDENT-006, scope=function)
TEST(ClientSessionShellTests, NoneChannelDropsLateValidationVerdictAfterTeardown)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->validationDeferral.defer = true;  // hold the verdict until the teardown has happened
  store->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);

  ua::UserTokenPolicy unpPolicy;
  unpPolicy.policy_id() = "unp-1";
  unpPolicy.token_type() = ua::UserTokenType::UserName;
  unpPolicy.security_policy_uri() = std::string{setup.policy->uri()};

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(setup.defaultServerNonce, {unpPolicy})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"test-user", std::string{"s3cret-password"}};
  setup.session->activate(std::move(config), [](VoidResult) {});

  // Wait until the gate has reached (deferred) validation on the strand.
  ASSERT_TRUE(poll_until(
    [&]()
    {
      STA::strand_barrier(*setup.session);
      return store->validateCallCount > 0;
    },
    3000ms))
    << "the None-channel gate must reach server-certificate validation";

  // Tear the session down (channel disconnect) BEFORE the verdict arrives.
  setup.cleanup_sync();
  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  const StatusCode statusAfterTeardown = setup.sync->errorStatus;
  EXPECT_EQ(statusAfterTeardown, Status::BadConnectionClosed);

  // The late UNTRUSTED verdict now arrives on the torn-down (mActivateFlow-reset) flow.
  store->release_pending_validation();
  STA::strand_barrier(*setup.session);

  // The guard drops the stale refusal: the persistent error observer is NOT re-fired with a spurious status.
  EXPECT_EQ(setup.sync->errorStatus, statusAfterTeardown)
    << "a validation verdict arriving after teardown must be dropped, not re-fire the error observer";
  EXPECT_NE(setup.sync->errorStatus, StatusCode{Status::BadCertificateUntrusted})
    << "the stale untrusted verdict must not overwrite the teardown status";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-ECC-003 (Part 6 section 6.8.3 lines 4181-4201): when a Client opens a Session over an ECC SecurityPolicy
// it specifies the SecurityPolicyUri it plans to use for the UserIdentityToken by placing an ECDHPolicyUri
// key/value in the CreateSession request's AdditionalHeader, so the Server can return a matching
// EphemeralKey. Drives the real SessionImpl create flow over an ECC (nistP256) secured channel and asserts
// the captured CreateSessionRequest's AdditionalHeader carries ECDHPolicyUri == the channel SecurityPolicy
// URI. Contrast: the RSA (Basic256Sha256) create flow attaches NO such header (is_ecc() false), proving the
// header is specifically an ECC obligation, not always-on.
// Falsifiable: a client that omitted the header (or attached it on a non-ECC channel) fails foundEcdh (or
// the RSA null-header check); a wrong URI value fails the equality.
// @verifies CL-ECC-003
// @relation(CL-ECC-003, scope=function)
TEST(ClientSessionShellTests, EccChannelSendsEcdhPolicyUriInCreateSessionAdditionalHeader)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_ecc(tp.get_executor(),
    SecurityPolicyId::EccNistP256AesGcm,
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256);

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value()) << "the client must have sent a CreateSessionRequest";

  const auto* additional =
    dynamic_cast<const ua::AdditionalParametersType*>(request->request_header().additional_header().get());
  ASSERT_NE(additional, nullptr) << "an ECC channel must attach an AdditionalParametersType header";

  bool foundEcdh = false;
  for (const auto& kv : additional->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHPolicyUri")
    {
      foundEcdh = true;
      const auto* uri = kv.value().try_as<ua::String>();
      ASSERT_NE(uri, nullptr) << "the ECDHPolicyUri value must be a String";
      EXPECT_EQ(std::string_view{*uri}, std::string_view{setup.policy->uri()})
        << "ECDHPolicyUri must equal the channel's ECC SecurityPolicy URI";
    }
  }
  EXPECT_TRUE(foundEcdh) << "an ECC CreateSession must carry the ECDHPolicyUri in its AdditionalHeader";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);

  // Contrast: a non-ECC (Basic256Sha256) CreateSession attaches NO AdditionalHeader (is_ecc() false).
  boost::asio::thread_pool tpRsa;
  auto rsa = SecuredSessionSetup::create_secured(tpRsa.get_executor());
  ASSERT_TRUE(rsa.wait_for_pending_request());
  auto rsaRequest = rsa.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(rsaRequest.has_value());
  EXPECT_EQ(rsaRequest->request_header().additional_header().get(), nullptr)
    << "a non-ECC CreateSession must not attach an ECDHPolicyUri AdditionalHeader";
  rsa.cleanup_sync();
  rsa.release();
  ::ua::test_utils::drain_with_timeout(tpRsa);
}

// AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY: with requestEphemeralKey cleared,
// as a managed connect clears it for an endpoint offering no UserName or IssuedToken policy, the
// CreateSession over the same ECC channel carries no ECDHPolicyUri. The contrast is
// EccChannelSendsEcdhPolicyUriInCreateSessionAdditionalHeader, the same channel with the default.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST(ClientSessionShellTests, EccChannelSendsNoEcdhPolicyUriWhenNoEphemeralKeyIsRequested)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_ecc(tp.get_executor(),
    SecurityPolicyId::EccNistP256AesGcm,
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256,
    {},
    false);

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value()) << "the client must have sent a CreateSessionRequest";
  const auto* additional =
    dynamic_cast<const ua::AdditionalParametersType*>(request->request_header().additional_header().get());
  const bool asked =
    additional && std::ranges::any_of(additional->parameters().payload(),
                    [](const auto& kv) { return std::string_view{kv.key().name()} == "ECDHPolicyUri"; });
  EXPECT_FALSE(asked) << "a CreateSession that asks for no EphemeralKey must not carry an ECDHPolicyUri";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSessionShellTests, EccChannelUsesPlannedUserTokenPolicyForEcdhPolicyUri)
{
  boost::asio::thread_pool tp;
  const std::string plannedPolicyUri{ua::utils::get_security_policy_uri(SecurityPolicyId::EccNistP384AesGcm)};
  auto setup = SecuredSessionSetup::create_secured_ecc(tp.get_executor(),
    SecurityPolicyId::EccNistP256AesGcm,
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256,
    plannedPolicyUri);

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  const auto* additional =
    dynamic_cast<const ua::AdditionalParametersType*>(request->request_header().additional_header().get());
  ASSERT_NE(additional, nullptr);

  bool foundEcdh = false;
  for (const auto& parameter : additional->parameters().payload())
  {
    if (std::string_view{parameter.key().name()} != "ECDHPolicyUri")
      continue;
    foundEcdh = true;
    const auto* uri = parameter.value().try_as<ua::String>();
    ASSERT_NE(uri, nullptr);
    EXPECT_EQ(std::string_view{*uri}, plannedPolicyUri)
      << "Part 6 section 6.8.3 requires the policy planned for the UserIdentityToken, not the channel policy";
  }
  EXPECT_TRUE(foundEcdh);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-ECC-004 (Part 7 section 1.05.02 Highlights, Mantis 7041 lines 136-139): the Minimum Client Facet shall
// support ECC-curve25519 or ECC-nist256. Demonstrates the client drives a full CreateSession over BOTH an
// ECC-nistP256 and an ECC-curve25519 SecurityPolicy: each policy reports is_ecc(), and the client builds
// and sends a CreateSessionRequest carrying the ECDHPolicyUri AdditionalHeader - the end-to-end client
// support both required Minimum-Client curves need.
// @verifies AC-CL-ECC-004-CURVE25519-MINIMUM (scope: end-to-end client support for the two Minimum-Client ECC
// curves at the session-create level; the CTT conformance-unit advertising in GetEndpoints selection is
// integration.) Falsifiable: a client lacking ECC support for a curve fails to construct the policy or send
// the request.
// @relation(AC-CL-ECC-004-CURVE25519-MINIMUM, scope=function)
TEST(ClientSessionShellTests, ClientSupportsMinimumFacetEccCurves)
{
  struct EccCurve
  {
    SecurityPolicyId policy;
    CertificateKeyAlgorithm key;
    CertificateSignatureAlgorithm sig;
    const char* label;
  };

  const EccCurve curves[] = {
    {SecurityPolicyId::EccNistP256AesGcm,
      CertificateKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      "ECC-nist256"},
    {SecurityPolicyId::EccCurve25519ChaChaPoly,
      CertificateKeyAlgorithm::EccCurve25519,
      CertificateSignatureAlgorithm::PureEdDsa25519,
      "ECC-curve25519"},
  };

  for (const auto& curve : curves)
  {
    boost::asio::thread_pool tp;
    auto setup =
      SecuredSessionSetup::create_secured_ecc(tp.get_executor(), curve.policy, curve.key, curve.sig);
    EXPECT_TRUE(setup.policy->is_ecc()) << curve.label << " policy must report is_ecc()";

    ASSERT_TRUE(setup.wait_for_pending_request())
      << "the client must send a CreateSession over " << curve.label;
    auto request = setup.first_captured<CreateSessionRequest>();
    ASSERT_TRUE(request.has_value()) << curve.label;
    const auto* additional =
      dynamic_cast<const ua::AdditionalParametersType*>(request->request_header().additional_header().get());
    EXPECT_NE(additional, nullptr) << "ECC CreateSession over " << curve.label
                                   << " must attach the ECDH header";

    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// @verifies CL-SESS-015
// @verifies CL-SESS-026
// Part 4 5.6.3: on re-activation the client signs the challenge with the MOST RECENT serverNonce - the one
// delivered by the previous ActivateSessionResponse (N2), not the CreateSession nonce (N1). Drive
// create(N1) -> activate #1 (response updates the nonce to N2) -> activate #2, and assert the second
// ActivateSession clientSignature verifies over (serverCert || N2) and NOT over (serverCert || N1).
// Falsifiable: a client that kept signing with the stale N1 verifies over N1 and fails over N2.
// @relation(CL-SESS-015, CL-SESS-026, scope=function)
TEST(ClientSessionShellTests, ReactivateSignsWithUpdatedServerNonce)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  const ByteString nonce1 = setup.defaultServerNonce;
  const ByteString nonce2 = random_bytes(*setup.crypto, setup.policy->nonce_length());
  ASSERT_NE(nonce1, nonce2) << "test precondition: the two server nonces must differ";

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  // Activate #1 -> Active, with the ActivateSessionResponse carrying the updated nonce N2.
  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>(1));
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  activateResponse->server_nonce() = nonce2;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResponse)));
  ASSERT_TRUE(poll_until([&]() { return setup.session->is_active(); }))
    << "the session must reach Active after the first ActivateSessionResponse";

  // Activate #2 (re-activation) - must sign with N2.
  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>(2));
  auto requests = setup.all_captured<ActivateSessionRequest>();
  ASSERT_GE(requests.size(), 2u);
  const auto& second = requests[1];

  ByteString overNonce2 = setup.serverCert->der_encoding();
  std::ranges::copy(nonce2, std::back_inserter(overNonce2));
  ByteString overNonce1 = setup.serverCert->der_encoding();
  std::ranges::copy(nonce1, std::back_inserter(overNonce1));

  EXPECT_TRUE(setup.signature_verifies(
    setup.clientCert->public_key(), overNonce2, second.client_signature().signature()))
    << "re-activation must sign with the UPDATED serverNonce (N2)";
  EXPECT_FALSE(setup.signature_verifies(
    setup.clientCert->public_key(), overNonce1, second.client_signature().signature()))
    << "re-activation must NOT sign with the stale CreateSession nonce (N1)";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-027
// Part 4 permits a server to reject an identity change without invalidating the already-active Session.
// Drive a successful first activation followed by BadIdentityChangeNotSupported and prove the exact status
// and diagnostic reach the reactivation caller while the Session remains Active and its persistent error
// observer is not fired.
// @relation(CL-SESS-027, scope=function)
TEST(ClientSessionShellTests, IdentityChangeRejectionPreservesActiveSession)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto firstResponse = std::make_shared<ActivateSessionResponse>();
  firstResponse->response_header().service_result() = Status::Good;
  // A conformant Good ActivateSession on a secured channel carries a fresh nonce of at least 32 bytes
  // (Part 4 section 5.6.3.2); the subject of this test is the later BadIdentityChangeNotSupported.
  firstResponse->server_nonce() = random_bytes(*setup.crypto, 32);
  ASSERT_TRUE(setup.inject_channel_response(std::move(firstResponse)));
  ASSERT_TRUE(poll_until([&]() { return setup.session->is_active(); }));

  std::mutex callbackMutex;
  std::condition_variable callbackCondition;
  bool callbackFired{false};
  VoidResult reactivationResult{Status::BadUnexpectedError};
  setup.session->activate(Session::ActivateConfig{},
    [&](VoidResult result)
    {
      std::lock_guard lock(callbackMutex);
      reactivationResult = std::move(result);
      callbackFired = true;
      callbackCondition.notify_one();
    });
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto rejectedResponse = std::make_shared<ActivateSessionResponse>();
  rejectedResponse->response_header().service_result() = Status::BadIdentityChangeNotSupported;
  ASSERT_TRUE(setup.inject_channel_response(std::move(rejectedResponse)));

  {
    std::unique_lock lock(callbackMutex);
    ASSERT_TRUE(callbackCondition.wait_for(lock, 1000ms, [&]() { return callbackFired; }));
  }
  EXPECT_EQ(reactivationResult.status_code(), StatusCode{Status::BadIdentityChangeNotSupported});
  ASSERT_NE(reactivationResult.shared_detail(), nullptr);
  EXPECT_NE(
    ua::to_string(*reactivationResult.shared_detail()).find("ActivateSessionFailed"), std::string::npos);
  EXPECT_TRUE(setup.session->is_active());
  {
    std::lock_guard lock(setup.sync->mx);
    EXPECT_FALSE(setup.sync->errorOccurred)
      << "a declined identity change is a call failure, not a fatal Session error";
  }

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-017
// Part 4 5.6.4: the client's CloseSession sets deleteSubscriptions = true so the server tears down the
// session's subscriptions. Drive create -> Created, close, and assert the captured CloseSessionRequest
// requests subscription deletion.
// Falsifiable: a client that left deleteSubscriptions false (leaking subscriptions) fails the assertion.
// @relation(CL-SESS-017, scope=function)
TEST(ClientSessionShellTests, CloseSessionRequestsDeleteSubscriptions)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  setup.session->close([](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<CloseSessionRequest>())
    << "close must send a CloseSessionRequest through the channel";
  auto request = setup.first_captured<CloseSessionRequest>();
  ASSERT_TRUE(request.has_value());
  EXPECT_TRUE(request->delete_subscriptions()) << "CloseSession must set deleteSubscriptions = true";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientSessionShellTests, OverlappingClosesCompleteEveryCallerFromOneResponse)
{
  boost::asio::thread_pool pool{1};
  auto setup = TestSessionSetup::create(pool.get_executor());
  ASSERT_TRUE(setup.complete_none_create());
  auto answers = std::make_shared<std::vector<VoidResult>>();

  setup.session->close(false, [answers](VoidResult result) { answers->push_back(std::move(result)); });
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(setup.read_state_on_strand(), SS::Closing);
  setup.session->close(true, [answers](VoidResult result) { answers->push_back(std::move(result)); });
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  STA::strand_barrier(*setup.session);

  const auto requests = setup.captured<CloseSessionRequest>();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_FALSE(requests.front().delete_subscriptions());
  EXPECT_TRUE(answers->empty());
  ASSERT_TRUE(setup.inject_channel_response(std::make_shared<CloseSessionResponse>()));
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(answers->size(), 3u);
  for (const auto& answer : *answers)
    EXPECT_EQ(answer.status_code(), StatusCode{Status::Good});

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSessionShellTests, OverlappingClosesPreserveTheSameRichFailure)
{
  boost::asio::thread_pool pool{1};
  auto setup = TestSessionSetup::create(pool.get_executor());
  ASSERT_TRUE(setup.complete_none_create());
  auto answers = std::make_shared<std::vector<VoidResult>>();
  const StatusCode failure{Status::BadConnectionClosed,
    ErrorDetail::build("HeldCloseFailure", "The held close response failed", "SessionCloseTest")
      .cause(make_error_detail("OriginalCloseCause", "Original close failure", "SessionCloseTest"))};

  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(setup.read_state_on_strand(), SS::Closing);
  ASSERT_TRUE(SecureChannelTestAccess::on_strand(*setup.channel,
    [failure](auto& guard)
    {
      auto& pending = guard.pending_requests();
      if (pending.size() != 1)
        return false;
      auto callback = std::move(pending.begin()->second);
      pending.erase(pending.begin());
      callback(SecureChannelImpl::ServiceResponseResult{failure});
      return true;
    }));
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(answers->size(), 2u);
  for (const auto& answer : *answers)
  {
    EXPECT_EQ(answer.status_code(), failure);
    EXPECT_EQ(answer.shared_detail(), failure.shared_detail());
  }

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSessionShellTests, AnEmptyOverlappingClosePreservesTheExistingWaiter)
{
  boost::asio::thread_pool pool{1};
  auto setup = TestSessionSetup::create(pool.get_executor());
  ASSERT_TRUE(setup.complete_none_create());
  auto answers = std::make_shared<std::vector<VoidResult>>();
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  setup.session->close({});
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(setup.read_state_on_strand(), SS::Closing);
  ASSERT_TRUE(setup.inject_channel_response(std::make_shared<CloseSessionResponse>()));
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(answers->size(), 1u);
  EXPECT_EQ(answers->front().status_code(), StatusCode{Status::Good});

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSessionShellTests, AThrowingCloseWaiterDoesNotSuppressTheOtherWaiters)
{
  boost::asio::thread_pool pool{1};
  auto setup = TestSessionSetup::create(pool.get_executor());
  ASSERT_TRUE(setup.complete_none_create());
  auto answers = std::make_shared<std::vector<VoidResult>>();
  setup.session->close(
    [answers](VoidResult result)
    {
      answers->push_back(std::move(result));
      throw UaException{Status::BadInternalError};
    });
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  STA::strand_barrier(*setup.session);
  ASSERT_TRUE(setup.inject_channel_response(std::make_shared<CloseSessionResponse>()));
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(answers->size(), 2u);
  for (const auto& answer : *answers)
    EXPECT_EQ(answer.status_code(), StatusCode{Status::Good});

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSessionShellTests, AReentrantCloseDoesNotReplaceTheRemainingWaiters)
{
  boost::asio::thread_pool pool{1};
  auto setup = TestSessionSetup::create(pool.get_executor());
  ASSERT_TRUE(setup.complete_none_create());
  auto answers = std::make_shared<std::vector<VoidResult>>();
  setup.session->close(
    [weak = std::weak_ptr{setup.session}, answers](VoidResult result)
    {
      answers->push_back(std::move(result));
      if (auto session = weak.lock())
        session->close([answers](VoidResult nested) { answers->push_back(std::move(nested)); });
    });
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  STA::strand_barrier(*setup.session);
  ASSERT_TRUE(setup.inject_channel_response(std::make_shared<CloseSessionResponse>()));
  STA::strand_barrier(*setup.session);
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(answers->size(), 3u);
  EXPECT_EQ(setup.captured<CloseSessionRequest>().size(), 1u);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSessionShellTests, DestructionCompletesEveryPendingCloseWaiter)
{
  boost::asio::thread_pool pool{1};
  auto setup = TestSessionSetup::create(pool.get_executor());
  ASSERT_TRUE(setup.complete_none_create());
  auto answers = std::make_shared<std::vector<VoidResult>>();
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
  STA::strand_barrier(*setup.session);
  ASSERT_EQ(setup.read_state_on_strand(), SS::Closing);
  setup.session.reset();
  ASSERT_EQ(answers->size(), 2u);
  for (const auto& answer : *answers)
  {
    EXPECT_EQ(answer.status_code(), StatusCode{Status::BadSessionClosed});
    ASSERT_NE(answer.shared_detail(), nullptr);
    EXPECT_EQ(answer.shared_detail()->code, "SessionDestroyed");
  }
  setup.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ClientSessionShellTests, ClosePreparationFailurePreservesRichFailureAndAllowsLaterClose)
{
  for (const bool completionThrows : {false, true})
  {
    SCOPED_TRACE(completionThrows);
    boost::asio::thread_pool pool{1};
    auto setup = TestSessionSetup::create(pool.get_executor());
    ASSERT_TRUE(setup.complete_none_create());
    const StatusCode failure{Status::BadResourceUnavailable,
      ErrorDetail::build("ClosePreparationFailure", "Close preparation failed", "SessionCloseTest")
        .cause(make_error_detail("ClosePreparationCause", "Original failure", "SessionCloseTest"))};
    STA::on_strand(*setup.session,
      [dependencies = setup.sessionDeps, failure](auto&) { dependencies->serviceTimeoutFailure = failure; });
    auto answers = std::make_shared<std::vector<VoidResult>>();
    setup.session->close(
      [answers, completionThrows](VoidResult result)
      {
        answers->push_back(std::move(result));
        if (completionThrows)
          throw UaException{Status::BadInternalError};
      });
    STA::strand_barrier(*setup.session);
    ASSERT_EQ(answers->size(), 1u);
    EXPECT_EQ(answers->front().status_code(), failure);
    EXPECT_EQ(answers->front().shared_detail(), failure.shared_detail());
    EXPECT_EQ(setup.read_state_on_strand(), SS::Closed);
    EXPECT_TRUE(setup.captured<CloseSessionRequest>().empty());

    setup.session->close([answers](VoidResult result) { answers->push_back(std::move(result)); });
    STA::strand_barrier(*setup.session);
    ASSERT_EQ(answers->size(), 2u);
    EXPECT_EQ(answers->back().status_code(), StatusCode{Status::Good});
    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(pool);
  }
}

// The control arm of AC-CL-SESS-017. Its sibling shows a CloseSessionRequest appears when a Created session
// is closed; on its own that cannot separate "the client emits CloseSession when it has a session to close"
// from "the client emits one on every close call". This run differs in exactly one variable - the session
// state at the moment close() is called - and asserts nothing reaches the channel.
// @verifies CL-SESS-017
// @relation(CL-SESS-017, scope=function)
TEST(ClientSessionShellTests, CloseFromIdleEmitsNoCloseSessionRequest)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());

  ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>())
    << "the harness must have driven a CreateSession, so the capture interface is demonstrably live";

  // There is no session on the server to close: drop straight back to Idle without completing the create.
  STA::on_strand(*setup.session, [](auto& g) { g.set_session_state(SS::Idle); });

  std::mutex mx;
  std::condition_variable cv;
  bool closeFired{false};
  setup.session->close(
    [&](VoidResult)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        closeFired = true;
      }
      cv.notify_one();
    });
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return closeFired; })) << "close must complete from Idle";
  }

  EXPECT_FALSE(setup.first_captured<CloseSessionRequest>().has_value())
    << "closing a session that was never established must put no CloseSessionRequest on the channel";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-021
// An in-flight service request must be COMPLETED (never silently dropped) when the server terminates the
// session. Park a Read on an Active session, then deliver a server-side session-closed result to that
// outstanding channel operation; the caller's callback must fire promptly with the terminate status.
// Falsifiable: a regression that dropped the pending callback would hang, timing out the wait and failing
// the ASSERT rather than surfacing a status.
// @relation(CL-SESS-021, scope=function)
TEST(ClientSessionShellTests, OutstandingRequestCompletesWhenSessionTerminated)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  // Complete the CreateSession handshake so the create coroutine's own request does NOT linger in the
  // channel's pending map; otherwise the unordered pending map means the pending.begin() below could grab
  // the CreateSession instead of the Read (erroring the create coroutine and dropping the Read). This makes
  // the Read the single unambiguous outstanding request this test terminates.
  ASSERT_TRUE(setup.complete_none_create()) << "the None create handshake must complete";
  setup.set_active_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  StatusCode resultStatus{Status::Good};
  setup.session->send_request(std::make_shared<ReadRequest>(),
    [&](SessionImpl::ServiceResponseResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        resultStatus = result.status_code();
      }
      cv.notify_one();
    });

  ASSERT_TRUE(setup.wait_for_pending_request())
    << "the Read must be parked as an outstanding channel request";

  // The server terminates the session: its response to the outstanding operation is a session-closed error.
  const bool delivered = SecureChannelTestAccess::on_strand(*setup.channel,
    [](auto& g)
    {
      auto& pending = g.pending_requests();
      if (pending.empty())
      {
        return false;
      }
      auto it = pending.begin();
      auto callback = std::move(it->second);
      pending.erase(it);
      callback(SecureChannelImpl::ServiceResponseResult{Status::BadSessionClosed});
      return true;
    });
  ASSERT_TRUE(delivered);

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }))
      << "the outstanding request must complete (not hang) when the session is terminated";
  }
  EXPECT_TRUE(resultStatus.is_bad());
  EXPECT_EQ(resultStatus, StatusCode{Status::BadSessionClosed});

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-021
// A graceful Session termination must atomically drain every callback that is
// still owned by the Session and translate the Good close result to
// BadSessionClosed for those aborted service operations.
// @relation(CL-SESS-021, scope=function)
TEST(ClientSessionShellTests, GracefulCloseDrainsAllOutstandingRequestsWithBadSessionClosed)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());

  std::vector<StatusCode> statuses;
  SessionTestAccess::on_strand(*setup.session,
    [&](auto& session)
    {
      session.pending_requests().emplace(
        41, [&](SessionImpl::ServiceResponseResult result) { statuses.push_back(result.status_code()); });
      session.pending_requests().emplace(
        42, [&](SessionImpl::ServiceResponseResult result) { statuses.push_back(result.status_code()); });
      session.handle_session_closed(Status::Good, std::shared_ptr<const ErrorDetail>{});
    });

  ASSERT_EQ(statuses.size(), 2u);
  EXPECT_EQ(statuses[0], StatusCode{Status::BadSessionClosed});
  EXPECT_EQ(statuses[1], StatusCode{Status::BadSessionClosed});
  EXPECT_TRUE(SessionTestAccess::on_strand(
    *setup.session, [](auto& session) { return session.pending_requests().empty(); }));

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SESS-022
// A response carrying a LocalizedText in a fallback locale (e.g. the caller asked for "fr" but the server
// returned "en-GB") must be surfaced to the caller unchanged - the client does not rewrite, strip, or
// error on the locale. Inject a ReadResponse whose DataValue holds LocalizedText{"en-GB", "Colour"} and
// assert the caller sees exactly those bytes.
// Falsifiable: a client that dropped the locale, coerced the text, or failed the call fails the assertions.
// @relation(CL-SESS-022, scope=function)
TEST(ClientSessionShellTests, ReadResponseFallbackLocaleSurfacedUnchanged)
{
  boost::asio::thread_pool tp;
  auto setup = TestSessionSetup::create(tp.get_executor());
  // Drain the auto-started CreateSession so the injected ReadResponse below is delivered to the Read, not
  // to a leftover create request in the unordered pending map (see complete_none_create).
  ASSERT_TRUE(setup.complete_none_create());
  setup.set_active_on_strand();

  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  std::shared_ptr<Structure> received;
  setup.session->send_request(std::make_shared<ReadRequest>(),
    [&](SessionImpl::ServiceResponseResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        if (result)
        {
          received = result.value();
        }
      }
      cv.notify_one();
    });

  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = std::make_shared<ReadResponse>();
  DataValue dataValue;
  dataValue.value() = Variant{LocalizedText{LocaleId{"en-GB"}, String{"Colour"}}};
  response->results().payload().push_back(std::move(dataValue));
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
  }

  ASSERT_NE(received, nullptr);
  auto* readResponse = dynamic_cast<ReadResponse*>(received.get());
  ASSERT_NE(readResponse, nullptr);
  ASSERT_FALSE(readResponse->results().payload().empty());
  const auto* localized = readResponse->results().payload().front().value().try_as<LocalizedText>();
  ASSERT_NE(localized, nullptr) << "the LocalizedText must be surfaced unchanged";
  EXPECT_EQ(std::string_view{localized->locale()}, std::string_view{"en-GB"});
  EXPECT_EQ(std::string_view{localized->text()}, std::string_view{"Colour"});

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================================
// Security review 2026-09-28 (client): the server's EphemeralKey is used only when solicited and
// signed by the authenticated server certificate; the serverNonce is a real challenge; the user-token
// policies come from the endpoint the channel is connected to.
// ============================================================================================

namespace
{

/// The AdditionalHeader a server puts an ECDHKey in, with the signature the test chooses.
std::unique_ptr<ua::AdditionalParametersType> ecdh_key_header(ByteString publicKey, ByteString signature)
{
  auto ephemeral = std::make_unique<ua::EphemeralKeyType>();
  ephemeral->public_key() = std::move(publicKey);
  ephemeral->signature() = std::move(signature);
  auto additional = std::make_unique<ua::AdditionalParametersType>();
  ua::KeyValuePair ecdhKey;
  ecdhKey.key() = ua::QualifiedName{0, "ECDHKey"};
  ecdhKey.value() = ua::Variant{std::move(ephemeral)};
  additional->parameters().payload().push_back(std::move(ecdhKey));
  return additional;
}

ua::UserTokenPolicy user_name_policy(std::string policyId, std::string securityPolicyUri)
{
  ua::UserTokenPolicy policy;
  policy.policy_id() = std::move(policyId);
  policy.token_type() = ua::UserTokenType::UserName;
  policy.security_policy_uri() = std::move(securityPolicyUri);
  return policy;
}

std::string detail_text(const SecuredSessionSetup& setup)
{
  return setup.sync->errorDetail ? to_string(*setup.sync->errorDetail) : std::string{"none"};
}

/// An ECC secured session whose CreateSession carried a UserName policy over the channel policy and an
/// ECDHKey signed the way @p sign chooses; returns after the session is Created.
struct EccKeySetup
{
  SecuredSessionSetup setup;
  std::shared_ptr<const SecPolEphemeralKey> eccPolicy;
  Crypto::EphemeralKeyPair serverEphemeral;
};

/// The channel and the token policy an ECC session is built with; the defaults are one P-256 policy for
/// both, the cross-policy arms choose otherwise (Part 6 section 6.8.3).
struct EccSessionShape
{
  SecurityPolicyId channelPolicy{SecurityPolicyId::EccNistP256AesGcm};
  CertificateKeyAlgorithm channelKey{CertificateKeyAlgorithm::EccNistP256};
  CertificateSignatureAlgorithm channelSignature{CertificateSignatureAlgorithm::EcDsaSha2256};
  std::optional<SecurityPolicyId> ecdhPolicy;  ///< the ECDHPolicyUri solicited; the channel policy when unset
  std::optional<SecurityPolicyId>
    tokenPolicy;  ///< the UserName policy's SecurityPolicyUri; the channel policy when unset
};

EccKeySetup create_ecc_session_with_key(boost::asio::any_io_executor ex,
  const std::function<ByteString(const SecuredSessionSetup&, const ByteString& publicKey)>& sign,
  const EccSessionShape& shape = {})
{
  const auto ecdhPolicy = SecurityPolicy::create(shape.ecdhPolicy.value_or(shape.channelPolicy));
  const auto tokenPolicy = SecurityPolicy::create(shape.tokenPolicy.value_or(shape.channelPolicy));
  EccKeySetup out{SecuredSessionSetup::create_secured_ecc(ex,
                    shape.channelPolicy,
                    shape.channelKey,
                    shape.channelSignature,
                    shape.ecdhPolicy ? std::string{ecdhPolicy->uri()} : std::string{}),
    nullptr,
    Crypto::EphemeralKeyPair{}};
  // The server's ephemeral key is generated for the policy the client solicited (the token policy's
  // curve), whatever the channel's.
  auto* ecdhEccRaw = dynamic_cast<const SecPolEphemeralKey*>(ecdhPolicy.get());
  EXPECT_NE(ecdhEccRaw, nullptr);
  out.eccPolicy = std::shared_ptr<const SecPolEphemeralKey>{ecdhPolicy, ecdhEccRaw};
  out.serverEphemeral =
    out.setup.crypto->create_ephemeral_keys_sync(out.eccPolicy->ephemeral_key_algorithm());

  EXPECT_TRUE(out.setup.wait_for_pending_request());
  auto createResponse = out.setup.make_good_create_response(
    out.setup.defaultServerNonce, {user_name_policy("unp-ecc", std::string{tokenPolicy->uri()})});
  createResponse->response_header().additional_header() =
    ecdh_key_header(out.serverEphemeral.publicKey, sign(out.setup, out.serverEphemeral.publicKey));
  EXPECT_TRUE(out.setup.inject_channel_response(std::move(createResponse)));
  EXPECT_TRUE(out.setup.sync->wait_created(3000ms));
  return out;
}

void activate_user_name(SecuredSessionSetup& setup, std::string policyId)
{
  Session::ActivateConfig config;
  config.policyId = std::move(policyId);
  config.identity = ua::client::UsernamePasswordIdentity{"test-user", std::string{"s3cret-password"}};
  setup.session->activate(std::move(config), [](VoidResult) {});
}

}  // namespace

// The server signs the EphemeralKey with its certificate (Part 4 section 7.15); a key without that
// signature cannot be attributed to the server, so the secret is never encrypted to it.
// @relation(AC-CL-ECC-005-UNSIGNED-OR-FORGED-EPHEMERAL-KEY-IS-REFUSED, scope=function)
TEST(ClientSessionShellTests, EccUserTokenRefusedWhenEphemeralKeySignatureMissing)
{
  boost::asio::thread_pool tp;
  auto ecc =
    create_ecc_session_with_key(tp.get_executor(), [](const auto&, const auto&) { return ByteString{}; });
  activate_user_name(ecc.setup, "unp-ecc");

  ASSERT_TRUE(ecc.setup.sync->wait_error(3000ms)) << "an unsigned EphemeralKey must refuse the activation";
  EXPECT_EQ(ecc.setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  EXPECT_NE(detail_text(ecc.setup).find("EphemeralKeySignatureMissing"), std::string::npos)
    << detail_text(ecc.setup);
  EXPECT_FALSE(ecc.setup.first_captured<ActivateSessionRequest>().has_value())
    << "no ActivateSession may carry a secret encrypted to an unattributed key";

  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-ECC-005-UNSIGNED-OR-FORGED-EPHEMERAL-KEY-IS-REFUSED, scope=function)
TEST(ClientSessionShellTests, EccUserTokenRefusedWhenEphemeralKeySignedByAnotherKey)
{
  boost::asio::thread_pool tp;
  auto ecc = create_ecc_session_with_key(tp.get_executor(),
    [](const SecuredSessionSetup& setup, const ByteString& publicKey)
    {
      // A valid signature, from a key that is not the server's: what an on-path attacker can produce.
      const auto attackerKeys =
        setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
      return setup.crypto->asymmetric_sign_sync(
        setup.policy->asymmetric_signature_algorithm(), attackerKeys, publicKey);
    });
  activate_user_name(ecc.setup, "unp-ecc");

  ASSERT_TRUE(ecc.setup.sync->wait_error(3000ms));
  EXPECT_EQ(ecc.setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  EXPECT_NE(detail_text(ecc.setup).find("EphemeralKeySignatureInvalid"), std::string::npos)
    << detail_text(ecc.setup);
  EXPECT_FALSE(ecc.setup.first_captured<ActivateSessionRequest>().has_value());

  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-ECC-005-UNSIGNED-OR-FORGED-EPHEMERAL-KEY-IS-REFUSED, scope=function)  // control arm
TEST(ClientSessionShellTests, EccUserNameTokenEncryptsWithSignedEphemeralKey)
{
  boost::asio::thread_pool tp;
  auto ecc = create_ecc_session_with_key(tp.get_executor(),
    [](const SecuredSessionSetup& setup, const ByteString& publicKey)
    {
      return setup.crypto->asymmetric_sign_sync(
        setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, publicKey);
    });
  activate_user_name(ecc.setup, "unp-ecc");

  ASSERT_TRUE(ecc.setup.wait_for_captured<ActivateSessionRequest>())
    << "control: a key signed by the server is accepted; status="
    << to_string(ecc.setup.sync->errorStatus.as_status()) << " detail=" << detail_text(ecc.setup);
  auto request = ecc.setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  auto* token = dynamic_cast<ua::UserNameIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr);
  const std::string plaintext{"s3cret-password"};
  EXPECT_NE(std::string(token->password().begin(), token->password().end()), plaintext)
    << "the password is encrypted, not sent in the clear";

  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 section 6.8.3: the token policy may differ from the channel policy. The server's certificate
// belongs to the channel's curve family, so its signature over the (token-curve) ephemeral key is made
// with the CHANNEL policy's algorithm, and the client accepts exactly that, in either direction.
// @relation(AC-CL-ECC-005-KEY-IS-FOR-THE-SOLICITED-POLICY, scope=function)  // control arm
TEST(ClientSessionShellTests, EccUserTokenAcceptsAKeySignedWithTheChannelPolicyAcrossPolicies)
{
  boost::asio::thread_pool tp;
  EccSessionShape shape;
  shape.ecdhPolicy = SecurityPolicyId::EccNistP384AesGcm;
  shape.tokenPolicy = SecurityPolicyId::EccNistP384AesGcm;
  auto ecc = create_ecc_session_with_key(
    tp.get_executor(),
    [](const SecuredSessionSetup& setup, const ByteString& publicKey)
    {
      return setup.crypto->asymmetric_sign_sync(
        setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, publicKey);
    },
    shape);
  activate_user_name(ecc.setup, "unp-ecc");
  ASSERT_TRUE(ecc.setup.wait_for_captured<ActivateSessionRequest>())
    << "a P-256 channel with a P-384 token policy activates; status="
    << to_string(ecc.setup.sync->errorStatus.as_status()) << " detail=" << detail_text(ecc.setup);
  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-ECC-005-KEY-IS-FOR-THE-SOLICITED-POLICY, scope=function)  // control arm
TEST(ClientSessionShellTests, EccUserTokenAcceptsAKeySignedWithTheChannelPolicyOnAP384Channel)
{
  boost::asio::thread_pool tp;
  EccSessionShape shape;
  shape.channelPolicy = SecurityPolicyId::EccNistP384AesGcm;
  shape.channelKey = CertificateKeyAlgorithm::EccNistP384;
  shape.channelSignature = CertificateSignatureAlgorithm::EcDsaSha2384;
  shape.ecdhPolicy = SecurityPolicyId::EccNistP256AesGcm;
  shape.tokenPolicy = SecurityPolicyId::EccNistP256AesGcm;
  auto ecc = create_ecc_session_with_key(
    tp.get_executor(),
    [](const SecuredSessionSetup& setup, const ByteString& publicKey)
    {
      return setup.crypto->asymmetric_sign_sync(
        setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, publicKey);
    },
    shape);
  activate_user_name(ecc.setup, "unp-ecc");
  ASSERT_TRUE(ecc.setup.wait_for_captured<ActivateSessionRequest>())
    << "a P-384 channel with a P-256 token policy activates; status="
    << to_string(ecc.setup.sync->errorStatus.as_status()) << " detail=" << detail_text(ecc.setup);
  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A key was solicited for one policy (the ECDHPolicyUri sent); a token policy naming another must not
// use it, even when the signature is the server's.
// @relation(AC-CL-ECC-005-KEY-IS-FOR-THE-SOLICITED-POLICY, scope=function)
TEST(ClientSessionShellTests, EccUserTokenRefusedWhenTokenPolicyDiffersFromSolicitedEcdhPolicy)
{
  boost::asio::thread_pool tp;
  EccSessionShape shape;
  shape.tokenPolicy = SecurityPolicyId::EccNistP384AesGcm;  // solicited: the channel's P-256
  auto ecc = create_ecc_session_with_key(
    tp.get_executor(),
    [](const SecuredSessionSetup& setup, const ByteString& publicKey)
    {
      return setup.crypto->asymmetric_sign_sync(
        setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, publicKey);
    },
    shape);
  activate_user_name(ecc.setup, "unp-ecc");
  ASSERT_TRUE(ecc.setup.sync->wait_error(3000ms));
  EXPECT_EQ(ecc.setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  EXPECT_NE(detail_text(ecc.setup).find("EphemeralKeyPolicyMismatch"), std::string::npos)
    << detail_text(ecc.setup);
  EXPECT_FALSE(ecc.setup.first_captured<ActivateSessionRequest>().has_value());
  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A channel whose policy agrees no ephemeral key never solicits an ECDHKey (no ECDHPolicyUri is sent), so a
// key in the response is a peer choosing the client's encryption for it: ignored, and the ECC token policy
// then has no key. A Basic256Sha256 channel: over a None channel such a token policy is refused before any
// key is looked at (AC-CL-SCE-013, the next test).
// @relation(AC-CL-ECC-005-UNSOLICITED-EPHEMERAL-KEY-IS-IGNORED, scope=function)
TEST(ClientSessionShellTests, UnsolicitedEcdhKeyOnALegacyChannelIsIgnored)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_EQ(setup.policy->ephemeral_key_algorithm(), ua::EphemeralKeyAlgorithm::Invalid);
  const auto eccPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto* eccPolicyRaw = dynamic_cast<const SecPolEphemeralKey*>(eccPolicy.get());
  ASSERT_NE(eccPolicyRaw, nullptr);
  const auto attackerEphemeral =
    setup.crypto->create_ephemeral_keys_sync(eccPolicyRaw->ephemeral_key_algorithm());

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResponse = setup.make_good_create_response(
    setup.defaultServerNonce, {user_name_policy("unp-ecc", std::string{eccPolicy->uri()})});
  createResponse->response_header().additional_header() =
    ecdh_key_header(attackerEphemeral.publicKey, ByteString{});
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResponse)));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  activate_user_name(setup, "unp-ecc");
  ASSERT_TRUE(setup.sync->wait_error(3000ms))
    << "before the fix the password was encrypted to the injected key and sent";
  EXPECT_EQ(setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  EXPECT_NE(detail_text(setup).find("EphemeralKeyNotSolicited"), std::string::npos) << detail_text(setup);
  EXPECT_FALSE(setup.first_captured<ActivateSessionRequest>().has_value());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// OPC 10000-4 7.41 (1.05.07): over a None channel the client does not use a UserName token policy that
// encrypts under an ECC SecurityPolicy, even with an EphemeralKey in the response to encrypt to: the
// activation fails locally and no ActivateSession carries the secret.
// @relation(AC-CL-SCE-013-NO-SECRET-OVER-NONE, scope=function)
TEST(ClientSessionShellTests, AnEccTokenPolicyOverANoneChannelSendsNoSecret)
{
  boost::asio::thread_pool tp;
  auto store =
    ua::test_helpers::FakeCertificateStore::create();  // validates Good: the certificate is trusted
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);
  const auto eccPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto* eccPolicyRaw = dynamic_cast<const SecPolEphemeralKey*>(eccPolicy.get());
  ASSERT_NE(eccPolicyRaw, nullptr);
  const auto offeredEphemeral =
    setup.crypto->create_ephemeral_keys_sync(eccPolicyRaw->ephemeral_key_algorithm());

  ASSERT_TRUE(setup.wait_for_pending_request());
  auto createResponse = setup.make_good_create_response(
    setup.defaultServerNonce, {user_name_policy("unp-ecc", std::string{eccPolicy->uri()})});
  createResponse->response_header().additional_header() =
    ecdh_key_header(offeredEphemeral.publicKey, ByteString{});
  ASSERT_TRUE(setup.inject_channel_response(std::move(createResponse)));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  activate_user_name(setup, "unp-ecc");
  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadSecurityPolicyRejected);
  EXPECT_NE(detail_text(setup).find("EphemeralKeySecretOverNoneChannel"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.first_captured<ActivateSessionRequest>().has_value());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.6.2.2: the serverNonce shall have a minimum length of 32 bytes. On an authenticated
// channel a shorter one is refused like a discovery mismatch: CloseSession, channel closed.
// @relation(AC-CL-SESS-008-SHORT-SERVERNONCE-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, CreateSessionShortServerNonceRejectedOnSecuredChannel)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ua::UserTokenPolicy anon;
  anon.token_type() = UserTokenType::Anonymous;
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(random_bytes(*setup.crypto, 16), {anon})));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("CreateSessionServerNonceInvalid"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_created());
  EXPECT_TRUE(setup.wait_for_captured<CloseSessionRequest>()) << "the allocated server session is closed";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-SESS-015-SHORT-OR-REUSED-SERVERNONCE-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, ActivateSessionShortServerNonceRejectedOnSecuredChannel)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto activated = std::make_shared<std::promise<VoidResult>>();
  auto activateResult = activated->get_future();
  setup.session->activate(
    Session::ActivateConfig{}, [activated](VoidResult result) { activated->set_value(result); });
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  activateResponse->server_nonce() = random_bytes(*setup.crypto, 8);
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResponse)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("ActivateSessionServerNonceInvalid"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_active());
  ASSERT_EQ(activateResult.wait_for(3000ms), std::future_status::ready) << "the activate caller is answered";
  const auto callerResult = activateResult.get();
  EXPECT_EQ(callerResult.status_code(), Status::BadNonceInvalid);
  ASSERT_NE(callerResult.shared_detail(), nullptr);
  EXPECT_NE(
    to_string(*callerResult.shared_detail()).find("ActivateSessionServerNonceInvalid"), std::string::npos);
  EXPECT_TRUE(setup.wait_for_captured<CloseSessionRequest>())
    << "a refused activation closes the server session";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// OPC 10000-4 1.05.07 5.7.2: the CreateSession serverNonce "shall have a length between 32 and 128 bytes
// inclusive. The Client shall check the length." One byte over the ceiling is refused like one under the
// floor.
// @relation(AC-CL-SESS-008-SERVERNONCE-OVER-128-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, CreateSessionLongServerNonceRejectedOnSecuredChannel)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ua::UserTokenPolicy anon;
  anon.token_type() = UserTokenType::Anonymous;
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(random_bytes(*setup.crypto, 129), {anon})));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("CreateSessionServerNonceInvalid"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_created());
  EXPECT_TRUE(setup.wait_for_captured<CloseSessionRequest>()) << "the allocated server session is closed";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The ceiling holds on a None channel too (OPC 10000-4 1.05.07 5.7.2 does not exempt it), where a short or
// empty nonce is still accepted.
// @relation(AC-CL-SESS-008-SERVERNONCE-OVER-128-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, CreateSessionLongServerNonceRejectedOnNoneChannel)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);
  ASSERT_TRUE(setup.wait_for_pending_request());
  ua::UserTokenPolicy anon;
  anon.token_type() = UserTokenType::Anonymous;
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(random_bytes(*setup.crypto, 129), {anon})));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("CreateSessionServerNonceInvalid"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The control: a serverNonce of exactly 128 bytes is within the range.
// @relation(AC-CL-SESS-008-SERVERNONCE-OVER-128-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, CreateSession128ByteServerNonceAcceptedOnSecuredChannel)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ua::UserTokenPolicy anon;
  anon.token_type() = UserTokenType::Anonymous;
  ASSERT_TRUE(
    setup.inject_channel_response(setup.make_good_create_response(random_bytes(*setup.crypto, 128), {anon})));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// OPC 10000-4 1.05.07 5.7.3: the ActivateSession serverNonce has the same range, and the next activation
// signs it.
// @relation(AC-CL-SESS-008-SERVERNONCE-OVER-128-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, ActivateSessionLongServerNonceRejectedOnSecuredChannel)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto activated = std::make_shared<std::promise<VoidResult>>();
  auto activateResult = activated->get_future();
  setup.session->activate(
    Session::ActivateConfig{}, [activated](VoidResult result) { activated->set_value(result); });
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  activateResponse->server_nonce() = random_bytes(*setup.crypto, 129);
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResponse)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("ActivateSessionServerNonceInvalid"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_active());
  ASSERT_EQ(activateResult.wait_for(3000ms), std::future_status::ready) << "the activate caller is answered";
  EXPECT_EQ(activateResult.get().status_code(), Status::BadNonceInvalid);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A challenge is never reused (Part 4 section 5.6.3.2 "should"; SDK hardening): an ActivateSession
// nonce equal to the CreateSession nonce is refused.
// @relation(AC-CL-SESS-015-SHORT-OR-REUSED-SERVERNONCE-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, ActivateSessionReusedServerNonceRejected)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto activated = std::make_shared<std::promise<VoidResult>>();
  auto activateResult = activated->get_future();
  setup.session->activate(
    Session::ActivateConfig{}, [activated](VoidResult result) { activated->set_value(result); });
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  activateResponse->server_nonce() = setup.defaultServerNonce;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResponse)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("ActivateSessionServerNonceReused"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_active());
  ASSERT_EQ(activateResult.wait_for(3000ms), std::future_status::ready) << "the activate caller is answered";
  const auto callerResult = activateResult.get();
  EXPECT_EQ(callerResult.status_code(), Status::BadNonceInvalid);
  ASSERT_NE(callerResult.shared_detail(), nullptr);
  EXPECT_NE(
    to_string(*callerResult.shared_detail()).find("ActivateSessionServerNonceReused"), std::string::npos);
  EXPECT_TRUE(setup.wait_for_captured<CloseSessionRequest>())
    << "a refused activation closes the server session";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// On a None channel an anonymous session tolerates an empty serverNonce (a None endpoint answers with
// none when no token needs it), but a token that is encrypted with the nonce as freshness does not.
// @relation(AC-CL-SESS-008-SHORT-SERVERNONCE-IS-REJECTED, scope=function)
TEST(ClientSessionShellTests, NoneChannelEncryptedTokenRefusedWhenServerNonceShort)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response(
    ByteString{}, {user_name_policy("unp-1", std::string{setup.policy->uri()})})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms))
    << "an anonymous-capable create on None tolerates an empty nonce";

  auto activated = std::make_shared<std::promise<VoidResult>>();
  auto activateResult = activated->get_future();
  Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"test-user", std::string{"s3cret-password"}};
  setup.session->activate(
    std::move(config), [activated](VoidResult result) { activated->set_value(result); });
  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadNonceInvalid);
  EXPECT_NE(detail_text(setup).find("ServerNonceTooShortForUserToken"), std::string::npos)
    << detail_text(setup);
  ASSERT_EQ(activateResult.wait_for(3000ms), std::future_status::ready) << "the activate caller is answered";
  const auto callerResult = activateResult.get();
  EXPECT_EQ(callerResult.status_code(), Status::BadNonceInvalid);
  ASSERT_NE(callerResult.shared_detail(), nullptr);
  EXPECT_NE(
    to_string(*callerResult.shared_detail()).find("ServerNonceTooShortForUserToken"), std::string::npos);
  EXPECT_FALSE(setup.first_captured<ActivateSessionRequest>().has_value())
    << "no secret is encrypted with a challenge that cannot bind it";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-SESS-008-SHORT-SERVERNONCE-IS-REJECTED, scope=function)  // control arm
TEST(ClientSessionShellTests, NoneChannelAnonymousAcceptsEmptyServerNonce)
{
  boost::asio::thread_pool tp;
  auto store = ua::test_helpers::FakeCertificateStore::create();
  auto setup = SecuredSessionSetup::create_none_encrypting(tp.get_executor(), store);
  ASSERT_TRUE(setup.wait_for_pending_request());
  ua::UserTokenPolicy anon;
  anon.token_type() = UserTokenType::Anonymous;
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response(ByteString{}, {anon})));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  EXPECT_TRUE(setup.wait_for_captured<ActivateSessionRequest>())
    << "control: an anonymous activation on a None channel needs no nonce; status="
    << to_string(setup.sync->errorStatus.as_status()) << " detail=" << detail_text(setup);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The user-token policies come from the endpoint the channel is connected to. A response that lists
// endpoints but none matching the channel's policy and mode is refused, not answered with the first
// endpoint's policies.
// @relation(AC-CL-SESS-005-USER-TOKEN-POLICIES-COME-FROM-THE-SELECTED-ENDPOINT, scope=function)
TEST(ClientSessionShellTests, CreateSessionWithNoEndpointMatchingTheChannelIsRejected)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response(
    setup.defaultServerNonce, {user_name_policy("unp-1", std::string{setup.policy->uri()})});
  ASSERT_EQ(response->server_endpoints().size(), 1u);
  response->server_endpoints().payload().front().security_policy_uri() =
    std::string{SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep)->uri()};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  EXPECT_NE(detail_text(setup).find("CreateSessionNoMatchingEndpoint"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The production path (an endpointUrl is always configured) refuses the same response as a missing
// connected endpoint; the policies of another endpoint are never taken in its place.
// @relation(AC-CL-SESS-005-USER-TOKEN-POLICIES-COME-FROM-THE-SELECTED-ENDPOINT, scope=function)
TEST(ClientSessionShellTests, CreateSessionWithNoEndpointMatchingTheChannelIsRejectedOnTheProductionPath)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {}, false, "opc.tcp://localhost:4840");
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response(
    setup.defaultServerNonce, {user_name_policy("unp-1", std::string{setup.policy->uri()})});
  ASSERT_EQ(response->server_endpoints().size(), 1u);
  response->server_endpoints().payload().front().security_policy_uri() =
    std::string{SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep)->uri()};
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, Status::BadSecurityChecksFailed);
  EXPECT_NE(detail_text(setup).find("CreateSessionConnectedEndpointMissing"), std::string::npos)
    << detail_text(setup);
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-ECC-002: the server's EphemeralKey is consumed by the secret it encrypted. An identity change on
// the Active session, after an ActivateSession response that brought no fresh key, is refused (the
// session is kept) rather than encrypting a second secret to the consumed key.
// @relation(AC-CL-ECC-002-THE-EPHEMERAL-KEY-IS-CONSUMED-BY-ONE-ENCRYPTION, scope=function)
TEST(ClientSessionShellTests, EccEphemeralKeyIsSingleUse)
{
  boost::asio::thread_pool tp;
  auto ecc = create_ecc_session_with_key(tp.get_executor(),
    [](const SecuredSessionSetup& setup, const ByteString& publicKey)
    {
      return setup.crypto->asymmetric_sign_sync(
        setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, publicKey);
    });
  activate_user_name(ecc.setup, "unp-ecc");
  ASSERT_TRUE(ecc.setup.wait_for_captured<ActivateSessionRequest>(1)) << detail_text(ecc.setup);
  ASSERT_TRUE(ecc.setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  activateResponse->server_nonce() = random_bytes(*ecc.setup.crypto, ecc.setup.policy->nonce_length());
  // No ECDHKey in this response: the key the client held was consumed by the first encryption.
  ASSERT_TRUE(ecc.setup.inject_channel_response(std::move(activateResponse)));
  ASSERT_TRUE(poll_until([&]() { return ecc.setup.session->is_active(); }));

  auto changed = std::make_shared<std::promise<VoidResult>>();
  auto changeResult = changed->get_future();
  Session::ActivateConfig change;
  change.policyId = "unp-ecc";
  change.identity = ua::client::UsernamePasswordIdentity{"other-user", std::string{"0ther-password"}};
  ecc.setup.session->activate(
    std::move(change), [changed](VoidResult result) { changed->set_value(result); });
  ASSERT_EQ(changeResult.wait_for(3000ms), std::future_status::ready) << "the identity change is answered";
  const auto result = changeResult.get();
  EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_NE(to_string(*result.shared_detail()).find("EphemeralKeySignatureMissing"), std::string::npos)
    << to_string(*result.shared_detail());
  EXPECT_EQ(ecc.setup.all_captured<ActivateSessionRequest>().size(), 1u)
    << "no second secret is encrypted to the consumed key";
  EXPECT_TRUE(ecc.setup.session->is_active()) << "the refused change keeps the Active session";
  EXPECT_FALSE(ecc.setup.sync->wait_error(200ms)) << "a refused identity change is not a session error";

  ecc.setup.cleanup_sync();
  ecc.setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-SESS-005-USER-TOKEN-POLICIES-COME-FROM-THE-SELECTED-ENDPOINT, scope=function)
TEST(ClientSessionShellTests, UserTokenPoliciesComeFromTheSelectedEndpointNotTheFirst)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(), {}, false, "opc.tcp://localhost:4840");
  ASSERT_TRUE(setup.wait_for_pending_request());
  ua::UserTokenPolicy firstAnon;
  firstAnon.policy_id() = "first-anon";
  firstAnon.token_type() = UserTokenType::Anonymous;
  ua::UserTokenPolicy selectedAnon;
  selectedAnon.policy_id() = "selected-anon";
  selectedAnon.token_type() = UserTokenType::Anonymous;
  auto response = setup.make_good_create_response(setup.defaultServerNonce, {selectedAnon});
  ASSERT_EQ(response->server_endpoints().size(), 1u);
  // The same policy and mode on another path, listed FIRST: not the endpoint this channel dialled.
  ua::EndpointDescription other = response->server_endpoints().payload().front();
  other.endpoint_url() = "opc.tcp://localhost:4840/other";
  other.user_identity_tokens().payload().clear();
  other.user_identity_tokens().payload().push_back(firstAnon);
  response->server_endpoints().payload().insert(
    response->server_endpoints().payload().begin(), std::move(other));
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  Session::ActivateConfig selected;
  selected.policyId = "selected-anon";
  setup.session->activate(std::move(selected), [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>())
    << "the dialled endpoint's policy id is known; before the fix the FIRST endpoint's policies were taken";
  auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  auto* token = dynamic_cast<ua::AnonymousIdentityToken*>(request->user_identity_token().get());
  ASSERT_NE(token, nullptr);
  EXPECT_EQ(std::string_view{token->policy_id()}, "selected-anon");

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------------------------------------
// Completeness review C1 (decision 26): the certificate identity checks compare the LEAF, the first
// certificate of a field that may carry a chain (OPC 10000-6 6.2.6), never the raw field bytes.
// ---------------------------------------------------------------------------------------------------------

namespace
{

ByteString concatenate_der(std::initializer_list<std::shared_ptr<const X509Certificate>> certificates)
{
  ByteString bytes;
  for (const auto& certificate : certificates)
  {
    const auto der = certificate->der_encoding();
    std::ranges::copy(der, std::back_inserter(bytes));
  }
  return bytes;
}

/// A GetEndpoints endpoint for the session tests whose serverCertificate field is @p certificateField.
EndpointDescription discovery_endpoint_with_certificate(ByteString certificateField)
{
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.server_certificate() = std::move(certificateField);
  return endpoint;
}

}  // namespace

// Part 4 5.6.2.2: the CreateSession serverCertificate is the channel certificate. Carrying the server's
// issuer after the same leaf is the same certificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-80-LEAF-IDENTITY, scope=function)
TEST(ClientSessionShellTests, CreateSessionServerCertificateWithAChainAfterTheChannelLeafIsAccepted)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_with_server_chain(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = setup.make_good_create_response();
  response->server_certificate() = concatenate_der({setup.serverCert, setup.serverIssuerCert});
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  EXPECT_TRUE(setup.sync->wait_created(3000ms)) << "the leaf equals the channel certificate";
  EXPECT_TRUE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Negative arm: the same issuer appended to a DIFFERENT leaf is a different certificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-80-LEAF-IDENTITY, scope=function)
TEST(ClientSessionShellTests, CreateSessionServerCertificateChainWithAnotherLeafIsSecurityChecksFailed)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_with_server_chain(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());

  const auto rogueKeys = test_keys::key_pair(*setup.crypto, test_keys::KeyType::Rsa2048, 40);
  const auto rogueCert = make_rsa_cert(setup.crypto, rogueKeys, "RogueServer", "98");
  auto response = setup.make_good_create_response();
  response->server_certificate() = concatenate_der({rogueCert, setup.serverIssuerCert});
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadSecurityChecksFailed});
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.6.2.2 excludes the EndpointDescription certificate from comparison.
// Changing its chain therefore does not affect the independently verified channel identity.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-80-LEAF-IDENTITY, scope=function)
TEST(ClientSessionShellTests, EndpointComparisonTreatsALeafAndTheSameLeafWithItsChainAsEqual)
{
  const auto crypto = make_secured_crypto();
  const auto endpointCert = make_rsa_cert(
    crypto, test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 41), "EndpointLeaf", "96");
  const auto endpointIssuer =
    make_rsa_cert(crypto, test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 42), "EndpointCa", "95");

  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(),
    {discovery_endpoint_with_certificate(concatenate_der({endpointCert, endpointIssuer}))});
  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = setup.make_good_create_response();
  ASSERT_EQ(response->server_endpoints().size(), 1u);
  response->server_endpoints().payload().front().server_certificate() = endpointCert->der_encoding();
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  EXPECT_TRUE(setup.sync->wait_created(3000ms)) << "the two copies carry the same leaf";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.6.2.2 excludes even a different EndpointDescription certificate.
// The top-level CreateSession certificate still equals the SecureChannel certificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-80-LEAF-IDENTITY, scope=function)
TEST(ClientSessionShellTests, EndpointComparisonIgnoresNonEssentialCertificateDifferences)
{
  const auto crypto = make_secured_crypto();
  const auto endpointCert = make_rsa_cert(
    crypto, test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 41), "EndpointLeaf", "96");
  const auto endpointIssuer =
    make_rsa_cert(crypto, test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 42), "EndpointCa", "95");

  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured(tp.get_executor(),
    {discovery_endpoint_with_certificate(concatenate_der({endpointCert, endpointIssuer}))});
  ASSERT_TRUE(setup.wait_for_pending_request());

  auto response = setup.make_good_create_response();
  ASSERT_EQ(response->server_endpoints().size(), 1u);
  response->server_endpoints().payload().front().server_certificate() =
    concatenate_der({endpointIssuer, endpointCert});
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());
  EXPECT_FALSE(setup.sync->errorOccurred);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Completeness review C2 (decision 24): CreateSession clientCertificate is the client's leaf followed by its
// issuer chain in order (OPC 10000-6 6.2.6).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-81-SEND-OWN-CHAIN, scope=function)
TEST(ClientSessionShellTests, CreateSessionClientCertificateIsTheLeafThenItsIssuers)
{
  boost::asio::thread_pool tp;
  auto setup = SecuredSessionSetup::create_secured_with_server_chain(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_captured<CreateSessionRequest>());
  const auto request = setup.first_captured<CreateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  EXPECT_EQ(request->client_certificate(), concatenate_der({setup.clientCert, setup.serverIssuerCert}))
    << "leaf first, then mIssuerCertificates in order";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Found by the integration matrix (2026-10-02): the CreateSession HostName check (OPC 10000-4 5.4.1) and
// the certificate validation's Host Name step (OPC 10000-4 Table 106, suppressible by OPC 10000-12
// Table 31 SuppressHostNameInvalid) are one rule. A client whose trust list suppresses HostName errors
// continues after a mismatch with a warning, as with relaxHostNameCheck; it used to close the session.
// ---------------------------------------------------------------------------

namespace
{

// A secured session whose discovery endpoint names host-b.example (the server certificate names
// localhost), its trust store suppressing HostName errors or not. relaxHostNameCheck is off in both.
SecuredSessionSetup make_hostname_mismatch_setup(boost::asio::any_io_executor ex, bool suppressHostName)
{
  auto endpoint = make_discovery_endpoint("urn:TestServer");
  endpoint.endpoint_url() = "opc.tcp://host-b.example:4840";
  auto setup = SecuredSessionSetup::create_secured(ex, {endpoint}, /*relaxHostNameCheck*/ false);
  auto store = ua::test_helpers::FakeCertificateStore::create();
  if (suppressHostName)
  {
    store->set_validation_options(
      TrustListValidationOptions{TrustListValidationOptions::Bit::SuppressHostNameInvalid});
  }
  setup.sessionDeps->set_certificate_store(std::move(store));
  return setup;
}

}  // namespace

// Negative arm (before the fix the session closed): the trust list suppresses HostNameInvalid, so the
// mismatch is reported as a warning and CreateSession proceeds.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-141-SESSION-HOSTNAME-SUPPRESSED, scope=function)
TEST(ClientSessionShellTests, ATrustListSuppressingHostNameErrorsLetsAHostNameMismatchProceed)
{
  boost::asio::thread_pool tp;
  auto setup = make_hostname_mismatch_setup(tp.get_executor(), /*suppressHostName*/ true);

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.session->is_created());
  EXPECT_FALSE(setup.sync->errorOccurred);
  EXPECT_TRUE(setup.sessionDeps->has_log_message("Continuing after a CreateSession HostName mismatch"))
    << "a suppressed mismatch is still reported";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Control arm: the same store and mismatch without the suppression bit closes the session.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-141-SESSION-HOSTNAME-SUPPRESSED, scope=function)
TEST(ClientSessionShellTests, ATrustListNotSuppressingHostNameErrorsRefusesAHostNameMismatch)
{
  boost::asio::thread_pool tp;
  auto setup = make_hostname_mismatch_setup(tp.get_executor(), /*suppressHostName*/ false);

  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));

  ASSERT_TRUE(setup.sync->wait_error(3000ms));
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadCertificateHostNameInvalid});
  EXPECT_EQ(setup.all_captured<CloseSessionRequest>().size(), 1u);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ===================================================================
// 1.05.07 SecureChannelEnhancements: the client's channel bound session signatures (OPC 10000-4 6.1.8)
// ===================================================================

namespace
{

SecuredSessionSetup create_enhanced_session(boost::asio::any_io_executor ex)
{
  return SecuredSessionSetup::create_secured_ecc(ex,
    SecurityPolicyId::EccNistP256AesGcm,
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256);
}

/// The Table 101 inputs of @p setup's channel and Session, with @p serverNonce.
ChannelBoundSignatureInputs session_inputs(SecuredSessionSetup& setup, const ByteString& serverNonce)
{
  return ChannelBoundSignatureInputs{.channelThumbprint = setup.channelThumbprint,
    .clientNonce = setup.client_nonce_on_strand(),
    .serverNonce = serverNonce,
    .serverCertificate = setup.serverCert->der_encoding(),
    .serverChannelCertificate =
      setup.channelMode == MessageSecurityMode::None ? ByteString{} : setup.serverCert->der_encoding(),
    .clientCertificate = setup.clientCert->der_encoding(),
    .clientChannelCertificate = setup.clientCert->der_encoding()};
}

/// True iff @p signature verifies over @p data with @p certificate's key under @p policy's algorithm.
bool verifies_under(const SecuredSessionSetup& setup, const SecurityPolicy& policy,
  const X509Certificate& certificate, const ByteString& data, const ByteString& signature)
{
  try
  {
    setup.crypto->asymmetric_verify_sync(
      policy.asymmetric_signature_algorithm(), certificate.public_key(), data, signature);
    return true;
  }
  catch (...)
  {
    return false;
  }
}

ua::UserTokenPolicy certificate_policy(std::string policyId, std::string_view securityPolicyUri)
{
  ua::UserTokenPolicy policy;
  policy.policy_id() = std::move(policyId);
  policy.token_type() = ua::UserTokenType::Certificate;
  policy.security_policy_uri() = std::string{securityPolicyUri};
  return policy;
}

}  // namespace

// Over an enhanced channel the client verifies the ServerSignature over the Table 101 ServerSignature data:
// one over the legacy ClientCertificate | ClientNonce is refused with Bad_ApplicationSignatureInvalid and
// the Session never becomes Created.
// @relation(AC-CL-SCE-010-SERVER-SIGNATURE-CHECKED, scope=function)
TEST(ClientSessionSignatureValidation, ALegacyServerSignatureOverAnEnhancedChannelIsRefused)
{
  boost::asio::thread_pool tp;
  auto setup = create_enhanced_session(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response();
  ByteString legacy = setup.clientCert->der_encoding();
  std::ranges::copy(setup.client_nonce_on_strand(), std::back_inserter(legacy));
  response->server_signature().signature() = setup.crypto->asymmetric_sign_sync(
    setup.policy->asymmetric_signature_algorithm(), setup.serverKeys, legacy);
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_error(3000ms)) << "the legacy ServerSignature was accepted";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadApplicationSignatureInvalid});
  EXPECT_FALSE(setup.session->is_created());

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The control: a ServerSignature over the Table 101 data, checked here to be that and not the legacy data,
// creates the Session.
// @relation(AC-CL-SCE-010-SERVER-SIGNATURE-CHECKED, scope=function)
TEST(ClientSessionSignatureValidation, AChannelBoundServerSignatureIsAccepted)
{
  boost::asio::thread_pool tp;
  auto setup = create_enhanced_session(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto response = setup.make_good_create_response();
  const auto bound = ua::test_helpers::channel_bound_data(*setup.crypto,
    *setup.policy,
    ChannelBoundSignature::Server,
    session_inputs(setup, setup.defaultServerNonce));
  ASSERT_TRUE(
    verifies_under(setup, *setup.policy, *setup.serverCert, bound, response->server_signature().signature()));
  ASSERT_TRUE(setup.inject_channel_response(std::move(response)));

  ASSERT_TRUE(setup.sync->wait_created(3000ms));
  EXPECT_TRUE(setup.sync->createdStatus.is_good()) << ua::describe(setup.sync->createdStatus);

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The ClientSignature an enhanced channel's Session sends verifies over the Table 101 ClientSignature data
// and not over the legacy ServerCertificate | ServerNonce.
// @relation(AC-CL-SCE-010-CLIENT-SIGNATURES-CHANNEL-BOUND, scope=function)
TEST(ClientSessionSignatureValidation, TheClientSignatureIsChannelBound)
{
  boost::asio::thread_pool tp;
  auto setup = create_enhanced_session(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>());
  const auto request = setup.first_captured<ActivateSessionRequest>();
  ASSERT_TRUE(request.has_value());
  const auto& signature = request->client_signature().signature();
  ASSERT_FALSE(signature.empty());

  const auto bound = ua::test_helpers::channel_bound_data(*setup.crypto,
    *setup.policy,
    ChannelBoundSignature::Client,
    session_inputs(setup, setup.defaultServerNonce));
  EXPECT_TRUE(verifies_under(setup, *setup.policy, *setup.clientCert, bound, signature))
    << "the ClientSignature does not cover the Table 101 data";
  ByteString legacy = setup.serverCert->der_encoding();
  std::ranges::copy(setup.defaultServerNonce, std::back_inserter(legacy));
  EXPECT_FALSE(verifies_under(setup, *setup.policy, *setup.clientCert, legacy, signature))
    << "the ClientSignature covers the legacy data";

  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// SD-6: the UserTokenPolicy's SecurityPolicy decides the X509 UserTokenSignature. An ECC_nistP256 token
// policy over the enhanced SignAndEncrypt channel signs the Table 101 UserTokenSignature data; the same token
// policy over a None channel signs the None-mode layout (ServerNonce | HASH(ServerCertificate) |
// ClientNonce); a Basic256Sha256 token policy over the enhanced channel signs ServerCertificate |
// ServerNonce. The token policy also decides the HASH: an ECC_nistP384 token policy over the ECC_nistP256
// channel hashes the certificates of Table 101 with SHA-384, not with the channel's SHA-256.
// @relation(AC-CL-SCE-010-CLIENT-SIGNATURES-CHANNEL-BOUND, scope=function)
TEST(ClientSessionSignatureValidation, AnX509TokenSignsTheLayoutOfItsTokenPolicy)
{
  const auto eccTokenPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto p384TokenPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP384AesGcm);
  const auto rsaTokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  enum class Channel
  {
    Enhanced,
    None
  };

  struct Arm
  {
    Channel channel;
    std::shared_ptr<SecurityPolicy> tokenPolicy;
    std::optional<ChannelBoundSignature> layout;  ///< the legacy layout when unset
    const char* what;
  };

  const Arm arms[] = {
    {Channel::Enhanced, eccTokenPolicy, ChannelBoundSignature::UserToken, "enhanced token policy"},
    {Channel::None,
      eccTokenPolicy,
      ChannelBoundSignature::UserTokenOverNone,
      "enhanced token policy over None"},
    {Channel::Enhanced, rsaTokenPolicy, std::nullopt, "RSA token policy"},
    {Channel::Enhanced, p384TokenPolicy, ChannelBoundSignature::UserToken, "ECC_nistP384 token policy"},
  };
  for (const auto& arm : arms)
  {
    SCOPED_TRACE(arm.what);
    boost::asio::thread_pool tp;
    auto setup = arm.channel == Channel::Enhanced
                   ? create_enhanced_session(tp.get_executor())
                   : SecuredSessionSetup::create_none_encrypting(
                       tp.get_executor(), ua::test_helpers::FakeCertificateStore::create());
    ASSERT_TRUE(setup.wait_for_pending_request());
    ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response(
      setup.defaultServerNonce, {certificate_policy("cert-1", arm.tokenPolicy->uri())})));
    ASSERT_TRUE(setup.sync->wait_created(3000ms));

    const auto certificateType = arm.tokenPolicy->certificate_type();
    std::shared_ptr<const AsymmetricKeyPair> userKeys;
    std::shared_ptr<const X509Certificate> userCert;
    if (certificateType == CertificateType::EccNistP256Application)
    {
      userKeys =
        setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
      userCert =
        make_ecc_cert(setup.crypto, userKeys, CertificateSignatureAlgorithm::EcDsaSha2256, "TestUser", "301");
    }
    else if (certificateType == CertificateType::EccNistP384Application)
    {
      userKeys =
        setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP384, std::nullopt);
      userCert =
        make_ecc_cert(setup.crypto, userKeys, CertificateSignatureAlgorithm::EcDsaSha2384, "TestUser", "303");
    }
    else
    {
      userKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
      userCert = make_rsa_cert(setup.crypto, userKeys, "TestUser", "302");
    }
    Session::ActivateConfig config;
    config.policyId = "cert-1";
    config.identity = ua::client::X509Identity{userCert, userKeys};
    setup.session->activate(std::move(config), [](VoidResult) {});
    ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>()) << detail_text(setup);
    const auto request = setup.first_captured<ActivateSessionRequest>();
    ASSERT_TRUE(request.has_value());
    const auto& signature = request->user_token_signature().signature();
    ASSERT_FALSE(signature.empty());

    ByteString legacy = setup.serverCert->der_encoding();
    std::ranges::copy(setup.defaultServerNonce, std::back_inserter(legacy));
    if (arm.layout)
    {
      const auto bound = ua::test_helpers::channel_bound_data(
        *setup.crypto, *arm.tokenPolicy, *arm.layout, session_inputs(setup, setup.defaultServerNonce));
      EXPECT_TRUE(verifies_under(setup, *arm.tokenPolicy, *userCert, bound, signature))
        << "the UserTokenSignature does not cover the token policy's Table 101 layout";
      EXPECT_FALSE(verifies_under(setup, *arm.tokenPolicy, *userCert, legacy, signature));
      if (arm.tokenPolicy == p384TokenPolicy)
      {
        const auto channelHash = ua::test_helpers::channel_bound_data(
          *setup.crypto, *eccTokenPolicy, *arm.layout, session_inputs(setup, setup.defaultServerNonce));
        EXPECT_FALSE(verifies_under(setup, *arm.tokenPolicy, *userCert, channelHash, signature))
          << "the certificates were hashed with the channel's HASH";
      }
    }
    else
    {
      EXPECT_TRUE(verifies_under(setup, *arm.tokenPolicy, *userCert, legacy, signature))
        << "the UserTokenSignature does not cover ServerCertificate | ServerNonce";
    }

    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// Table 174: under an enhanced policy the client ignores the algorithm of the received ServerSignature
// (an unrelated URI is accepted) and sends its ClientSignature and UserTokenSignature with an empty one.
// Under Basic256Sha256 both carry the policy's algorithm URI, so the empty algorithm is per policy.
// @relation(AC-CL-SCE-011-ALGORITHM-EMPTY-AND-IGNORED, scope=function)
TEST(ClientSessionSignatureValidation, EnhancedSignaturesCarryNoAlgorithm)
{
  for (const bool enhanced : {true, false})
  {
    SCOPED_TRACE(enhanced ? "enhanced" : "Basic256Sha256");
    boost::asio::thread_pool tp;
    auto setup = enhanced ? create_enhanced_session(tp.get_executor())
                          : SecuredSessionSetup::create_secured(tp.get_executor());
    ASSERT_TRUE(setup.wait_for_pending_request());
    auto response = setup.make_good_create_response(
      setup.defaultServerNonce, {certificate_policy("cert-1", setup.policy->uri())});
    if (enhanced)
      response->server_signature().algorithm() = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    ASSERT_TRUE(setup.inject_channel_response(std::move(response)));
    ASSERT_TRUE(setup.sync->wait_created(3000ms));
    EXPECT_TRUE(setup.sync->createdStatus.is_good()) << ua::describe(setup.sync->createdStatus);

    const auto userKeys =
      enhanced
        ? setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt)
        : setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    const auto userCert =
      enhanced ? make_ecc_cert(
                   setup.crypto, userKeys, CertificateSignatureAlgorithm::EcDsaSha2256, "TestUser", "303")
               : make_rsa_cert(setup.crypto, userKeys, "TestUser", "304");
    Session::ActivateConfig config;
    config.policyId = "cert-1";
    config.identity = ua::client::X509Identity{userCert, userKeys};
    setup.session->activate(std::move(config), [](VoidResult) {});
    ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>()) << detail_text(setup);
    const auto request = setup.first_captured<ActivateSessionRequest>();
    ASSERT_TRUE(request.has_value());
    const std::string expected =
      enhanced ? std::string{} : std::string{setup.policy->asymmetric_signature_algorithm_uri()};
    EXPECT_EQ(std::string{request->client_signature().algorithm()}, expected);
    EXPECT_EQ(std::string{request->user_token_signature().algorithm()}, expected);

    setup.cleanup_sync();
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

/// A second open channel of @p setup's policy and mode with @p thumbprint as its ChannelThumbprint, whose
/// requests are captured into @p captured.
std::shared_ptr<SecureChannelImpl> second_open_channel(const SecuredSessionSetup& setup,
  const ByteString& thumbprint, const std::shared_ptr<std::vector<std::unique_ptr<Structure>>>& captured)
{
  auto channel = SecureChannelImpl::create(
    setup.channelDeps,
    nullptr,
    ua::connection_protocol::NegotiatedLimits{},
    SecureChannelImpl::Config{},
    [](VoidResult) {},
    [](VoidResult) {});
  SecureChannelTestAccess::on_strand(*channel,
    [&](auto& g)
    {
      g.channel_state() = SecureChannelImpl::ChannelState::Open;
      g.security_policy() = setup.policy;
      g.context()->localCertificate = setup.clientCert;
      g.context()->localKeyPair = setup.clientKeys;
      g.context()->remoteCertificate = setup.serverCert;
      g.context()->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      g.context()->channelThumbprint = thumbprint;
      g.outgoing_request_observer() = [captured](const Structure& request)
      {
        captured->push_back(request.clone());
      };
    });
  return channel;
}

/// Whether a link of @p detail's chain has the code @p code.
bool chain_has_code(std::shared_ptr<const ErrorDetail> detail, std::string_view code)
{
  for (; detail; detail = detail->cause)
    if (detail->code == code)
      return true;
  return false;
}

// A Session re-activated over a new channel signs for that channel (guess G-34): its ClientSignature
// verifies over Table 101 data with the new channel's ChannelThumbprint, and not with the old one's.
// @relation(AC-CL-SCE-010-REBIND-SIGNS-FOR-THE-NEW-CHANNEL, scope=function)
TEST(ClientSessionSignatureValidation, ARebindSignsForTheNewChannel)
{
  boost::asio::thread_pool tp;
  auto setup = create_enhanced_session(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  // First activation on the creating channel; its response issues the nonce the re-activation signs with.
  const ByteString secondNonce = random_bytes(*setup.crypto, setup.policy->nonce_length());
  setup.session->activate(Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(setup.wait_for_captured<ActivateSessionRequest>(1));
  ASSERT_TRUE(setup.wait_for_pending_request());
  auto activateResponse = std::make_shared<ActivateSessionResponse>();
  activateResponse->response_header().service_result() = Status::Good;
  activateResponse->server_nonce() = secondNonce;
  ASSERT_TRUE(setup.inject_channel_response(std::move(activateResponse)));
  ASSERT_TRUE(poll_until([&]() { return setup.session->is_active(); }));

  // A second open channel of the same policy and mode with its own ChannelThumbprint, whose requests are
  // captured like the first's.
  const ByteString secondThumbprint = random_bytes(*setup.crypto, 64);
  ASSERT_NE(secondThumbprint, setup.channelThumbprint);
  auto secondCaptured = std::make_shared<std::vector<std::unique_ptr<Structure>>>();
  auto secondChannel = second_open_channel(setup, secondThumbprint, secondCaptured);

  setup.session->activate(secondChannel, Session::ActivateConfig{}, [](VoidResult) {});
  ASSERT_TRUE(poll_until(
    [&]()
    {
      return SecureChannelTestAccess::on_strand(*secondChannel,
        [&](auto&)
        {
          return std::ranges::any_of(*secondCaptured,
            [](const auto& r) { return dynamic_cast<const ActivateSessionRequest*>(r.get()) != nullptr; });
        });
    }))
    << "the re-activation was not sent on the new channel; " << detail_text(setup);
  const auto reactivation = SecureChannelTestAccess::on_strand(*secondChannel,
    [&](auto&)
    {
      for (const auto& r : *secondCaptured)
        if (const auto* typed = dynamic_cast<const ActivateSessionRequest*>(r.get()))
          return *typed;
      return ActivateSessionRequest{};
    });

  auto inputs = session_inputs(setup, secondNonce);
  inputs.channelThumbprint = secondThumbprint;
  const auto overNewChannel =
    ua::test_helpers::channel_bound_data(*setup.crypto, *setup.policy, ChannelBoundSignature::Client, inputs);
  inputs.channelThumbprint = setup.channelThumbprint;
  const auto overOldChannel =
    ua::test_helpers::channel_bound_data(*setup.crypto, *setup.policy, ChannelBoundSignature::Client, inputs);
  const auto& signature = reactivation.client_signature().signature();
  EXPECT_TRUE(verifies_under(setup, *setup.policy, *setup.clientCert, overNewChannel, signature))
    << "the re-activation does not sign with the new channel's ChannelThumbprint";
  EXPECT_FALSE(verifies_under(setup, *setup.policy, *setup.clientCert, overOldChannel, signature))
    << "the re-activation signs with the old channel's ChannelThumbprint";

  SecureChannelTestAccess::on_strand(*secondChannel,
    [](auto& g)
    {
      auto pending = std::move(g.pending_requests());
      g.pending_requests().clear();
      for (auto& [handle, callback] : pending)
        callback(SecureChannelImpl::ServiceResponseResult{Status::BadConnectionClosed});
    });
  setup.cleanup_sync();
  secondChannel.reset();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A rebind onto a channel that has released its security state cannot sign for it: the activation fails with
// Bad_SecureChannelClosed and the cause SecurityStateReleased, no ActivateSession is sent, and the Session is
// closed.
// @relation(AC-CL-SCE-010-REBIND-ENDS-CLEANLY, scope=function)
TEST(ClientSessionSignatureValidation, ARebindOntoAChannelWithoutSecurityStateFails)
{
  boost::asio::thread_pool tp;
  auto setup = create_enhanced_session(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto secondCaptured = std::make_shared<std::vector<std::unique_ptr<Structure>>>();
  auto secondChannel = second_open_channel(setup, random_bytes(*setup.crypto, 64), secondCaptured);
  SecureChannelTestAccess::on_strand(*secondChannel, [](auto& g) { g.context().reset(); });

  std::promise<VoidResult> answered;
  auto answer = answered.get_future();
  setup.session->activate(
    secondChannel, Session::ActivateConfig{}, [&answered](VoidResult result) { answered.set_value(result); });
  ASSERT_EQ(answer.wait_for(3s), std::future_status::ready) << "the rebind was never answered";
  const auto result = answer.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecureChannelClosed);
  EXPECT_TRUE(chain_has_code(result.shared_detail(), "SecurityStateReleased"))
    << (result.shared_detail() ? to_string(*result.shared_detail()) : std::string{"no detail"});
  EXPECT_TRUE(
    SecureChannelTestAccess::on_strand(*secondChannel, [&](auto&) { return secondCaptured->empty(); }))
    << "a request was sent on the channel";
  EXPECT_FALSE(setup.session->is_active());

  setup.cleanup_sync();
  secondChannel.reset();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A close that lands while the rebind reads the new channel's security state ends the activation: the close
// answers it, and the late security state neither sends an ActivateSession nor reports a Session error after
// the clean close.
// @relation(AC-CL-SCE-010-REBIND-ENDS-CLEANLY, scope=function)
TEST(ClientSessionSignatureValidation, ACloseDuringARebindEndsIt)
{
  boost::asio::thread_pool tp;
  auto setup = create_enhanced_session(tp.get_executor());
  ASSERT_TRUE(setup.wait_for_pending_request());
  ASSERT_TRUE(setup.inject_channel_response(setup.make_good_create_response()));
  ASSERT_TRUE(setup.sync->wait_created(3000ms));

  auto secondCaptured = std::make_shared<std::vector<std::unique_ptr<Structure>>>();
  auto secondChannel = second_open_channel(setup, random_bytes(*setup.crypto, 64), secondCaptured);
  // Hold the new channel's strand, so the security state is read only after the close.
  std::promise<void> release;
  auto released = release.get_future().share();
  std::promise<void> holding;
  std::thread holder(
    [&]
    {
      SecureChannelTestAccess::on_strand(*secondChannel,
        [&](auto&)
        {
          holding.set_value();
          released.wait();
        });
    });
  holding.get_future().wait();

  std::promise<VoidResult> activateAnswered;
  auto activateAnswer = activateAnswered.get_future();
  setup.session->activate(secondChannel,
    Session::ActivateConfig{},
    [&activateAnswered](VoidResult result) { activateAnswered.set_value(result); });
  const bool activating = poll_until([&]
    { return STA::on_strand(*setup.session, [](auto& g) { return g.session_state(); }) == SS::Activating; });
  setup.session->close([](VoidResult) {});
  const bool closeAnswered = activateAnswer.wait_for(3s) == std::future_status::ready;
  release.set_value();
  holder.join();
  ASSERT_TRUE(activating) << "the rebind did not start";
  ASSERT_TRUE(closeAnswered) << "the close did not answer the rebind";
  EXPECT_EQ(activateAnswer.get().status_code().as_status(), Status::BadSessionClosed);

  // Long enough for the late security state to reach the Session and, without the guard, be acted on.
  std::this_thread::sleep_for(200ms);
  EXPECT_TRUE(
    SecureChannelTestAccess::on_strand(*secondChannel, [&](auto&) { return secondCaptured->empty(); }))
    << "an ActivateSession was sent after the close";
  {
    const std::lock_guard lock{setup.sync->mx};
    EXPECT_EQ(setup.sync->errorCount, 0u)
      << "a Session error was reported after the clean close: " << detail_text(setup);
  }

  setup.cleanup_sync();
  secondChannel.reset();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
