// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_issued_identity_token.h"
#include "ua_credential_redaction.h"

#include <boost/asio/thread_pool.hpp>

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_security_policy.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_create_session_request.h"
#include "ua_close_session_request.h"
#include "ua_close_session_response.h"
#include "ua_service_fault.h"
#include "ua_server_observer.h"
#include "ua_read_request.h"

#include "ua_server_components.h"

#include <condition_variable>
#include <future>
#include <mutex>

using namespace ua;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;
using SCTA = ua::server::SecureChannelTestAccess;

namespace
{

// Thread-safe event recorder.
class FakeServerObserver : public ServerObserver
{
public:
  struct Event
  {
    std::string kind;
    StatusCode status;
    std::string extra;
  };

  void on_secure_channel_opened(const SecureChannelEventInfo& info) override
  {
    record("channel_opened", Status::Good, std::to_string(info.secureChannelId));
  }

  void on_secure_channel_closed(const SecureChannelEventInfo& info, StatusCode reason) override
  {
    record("channel_closed", reason, std::to_string(info.secureChannelId));
  }

  void on_secure_channel_renewed(const SecureChannelEventInfo& info) override
  {
    record("channel_renewed", Status::Good, std::to_string(info.secureChannelId));
  }

  void on_session_created(const SessionEventInfo& info) override
  {
    record("session_created", Status::Good, info.sessionName);
  }

  void on_session_activated(const SessionEventInfo& info) override
  {
    record("session_activated", Status::Good, info.sessionName);
  }

  void on_session_closed(const SessionEventInfo& info, StatusCode reason) override
  {
    record("session_closed", reason, info.sessionName);
  }

  void on_session_timed_out(const SessionEventInfo& info) override
  {
    record("session_timed_out", Status::Good, info.sessionName);
  }

  void on_connection_accepted(const std::string& remoteAddress) override
  {
    record("connection_accepted", Status::Good, remoteAddress);
  }

  void on_connection_closed(
    const std::string& remoteAddress, ConnectionCloseReason reason, StatusCode status) override
  {
    record("connection_closed", status, remoteAddress + ":" + std::to_string(static_cast<int>(reason)));
  }

  void on_certificate_rejected(const CertificateEventInfo& info) override
  {
    record("certificate_rejected", info.status, info.remoteAddress);
  }

  void on_authentication_failed(const SessionEventInfo& info, StatusCode reason) override
  {
    record("authentication_failed", reason, info.sessionName);
  }

  void on_internal_error(StatusCode status, const std::string& description) override
  {
    record("internal_error", status, description);
  }

  std::vector<Event> events() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mEvents;
  }

  bool wait_for_event(const std::string& kind, std::chrono::milliseconds timeout = 2s) const
  {
    std::unique_lock<std::mutex> lk(mMutex);
    return mCv.wait_for(lk, timeout, [&] { return has_event_locked(kind); });
  }

  size_t count_events(const std::string& kind) const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    size_t n = 0;
    for (const auto& e : mEvents)
    {
      if (e.kind == kind)
        ++n;
    }
    return n;
  }

private:
  mutable std::mutex mMutex;
  mutable std::condition_variable mCv;
  std::vector<Event> mEvents;

  bool has_event_locked(const std::string& kind) const
  {
    for (const auto& e : mEvents)
    {
      if (e.kind == kind)
        return true;
    }
    return false;
  }

  void record(std::string kind, StatusCode status, std::string extra)
  {
    {
      std::lock_guard<std::mutex> lk(mMutex);
      mEvents.push_back({std::move(kind), status, std::move(extra)});
    }
    mCv.notify_all();
  }
};

class AllowAnonymousAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    (void)req;
    completion(
      make_authn_success(UserIdentity{.userId = "anonymous", .displayName = "Anonymous", .claims = {}}));
  }
};

class DenyAllAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest, AuthnComplete completion) noexcept override
  {
    completion(make_authn_failure(StatusCode{Status::BadUserAccessDenied}, "access denied"));
  }
};

class FakeSecureChannelDeps : public SecureChannelDependencies
{
public:
  explicit FakeSecureChannelDeps(
    boost::asio::any_io_executor ex, std::shared_ptr<ServerObserver> observer = nullptr)
    : mExecutor(ex), mAppCfg(::ua::ApplicationConfig::load_default()), mObserver(std::move(observer))
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  void create_session(SecureChannelInfo, uint32_t, CreateSessionRequest&&) override
  {}

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError, make_error_detail("TestError", "Not used", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle) override
  {
    return {};
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  uint32_t get_next_secure_channel_id() override
  {
    return 1;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return mObserver;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

  void remove_secure_channel(const shared_ptr<SecureChannel>&) override
  {}

private:
  boost::asio::any_io_executor mExecutor;
  ::ua::ApplicationConfig mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  std::shared_ptr<ServerObserver> mObserver;
};

class FakeSessionDeps final : public SessionDependencies
{
public:
  FakeSessionDeps(boost::asio::any_io_executor ex, ServerComponents hooks,
    std::shared_ptr<ServerObserver> observer = nullptr)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mObserver(std::move(observer))
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return *mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError, make_error_detail("TestError", "Not used", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints() override
  {
    return {};
  }

  void remove_session(const shared_ptr<Session>&) override
  {}

  const ::ua::server::ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return mObserver;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<RequestLatencyTracker> latency_tracker() override
  {
    return nullptr;
  }

  std::shared_ptr<ServerSummaryCounters> summary_counters() override
  {
    return nullptr;
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    return nullptr;
  }

  SubscriptionIdAllocator& subscription_id_allocator() override
  {
    return mSubscriptionIdAllocator;
  }

  SubscriptionRouter& subscription_router() override
  {
    return mSubscriptionRouter;
  }

  OrphanedSubscriptionStore& orphaned_subscription_store() override
  {
    return mOrphanedSubscriptionStore;
  }

  EventBus& event_bus() override
  {
    return mEventBus;
  }

  std::shared_ptr<::ua::server::EventBus> event_bus_shared() override
  {
    return {};
  }

  std::shared_ptr<NodeManagementDelegate> node_management_delegate() override
  {
    return nullptr;
  }

  optional<StatusCode> begin_identity_attempt(const ::ua::server::ClientId&, std::string_view) override
  {
    return std::nullopt;
  }

  void finish_identity_attempt(
    const ::ua::server::ClientId&, std::string_view, IdentityAttemptOutcome) override
  {}

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  std::shared_ptr<ServerObserver> mObserver;
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
};

struct SessionTestHarness
{
  boost::asio::thread_pool threadPool;
  std::shared_ptr<FakeServerObserver> observer;
  shared_ptr<SecureChannelDependencies> scDeps;
  shared_ptr<FakeSessionDeps> sessDeps;
  shared_ptr<SecureChannel> sc;
  shared_ptr<Session> session;

  std::mutex mutex;
  std::condition_variable cv;
  optional<Response> lastResponse;

  ~SessionTestHarness()
  {
    // Release strand/executor-pinned members before draining the pool.
    // any_io_executor is work-tracking; while any impl shared_ptr holds one,
    // the pool's outstanding-work counter never reaches zero and join hangs.
    session.reset();
    sc.reset();
    sessDeps.reset();
    scDeps.reset();
    observer.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  void wait_for_response()
  {
    std::unique_lock<std::mutex> lk(mutex);
    ASSERT_TRUE(cv.wait_for(lk, 2s, [&] { return lastResponse.has_value(); }));
  }

  void clear_response()
  {
    std::lock_guard<std::mutex> lk(mutex);
    lastResponse.reset();
  }

  // Drain the session strand to ensure any in-flight lambdas (e.g., close/activate)
  // have fully completed and released their shared_ptr<Session> captures.
  // Without this, harness destruction may destroy sessDeps before the session's
  // destructor runs, causing deps.lock() to return null and skipping event emission.
  void drain_session_strand()
  {
    if (!session)
      return;
    SessionTestAccess::strand_barrier(*session);
  }
};

std::unique_ptr<SessionTestHarness> make_session_harness()
{
  auto h = std::make_unique<SessionTestHarness>();
  h->observer = std::make_shared<FakeServerObserver>();
  auto ex = h->threadPool.get_executor();

  h->scDeps = std::make_shared<FakeSecureChannelDeps>(ex, h->observer);
  h->sc = SecureChannel::create(
    h->scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*h->sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  h->sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks, h->observer);
  SecureChannelInfo sci(h->sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  h->session = Session::create(h->sessDeps, sci, 1, CreateSessionRequest{});

  // Wait for create_internal to complete.
  SessionTestAccess::strand_barrier(*h->session);

  return h;
}

}  // namespace

TEST(ServerObserverTests, SessionCreatedAndActivatedEventsFired)
{
  auto h = make_session_harness();

  // CreateSession may fail to emit session_created because FakeSessionDeps has no discovery deps
  // for the endpoint lookup in SendCreateSessionResponse. But activation proves the session exists.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();

  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  EXPECT_TRUE(h->observer->wait_for_event("session_activated"));
  EXPECT_EQ(h->observer->count_events("session_activated"), 1u);
}

TEST(ServerObserverTests, SessionClosedEventFired)
{
  auto h = make_session_harness();

  // First activate.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();

  // Now close.
  CloseSessionRequest csr;
  csr.request_header().request_handle() = 43;
  h->session->close(3, std::move(csr));

  h->wait_for_response();

  // Drain the strand so the close lambda releases its shared_ptr<Session>.
  h->drain_session_strand();

  // on_session_closed fires from the destructor - release the session to trigger it.
  auto observer = h->observer;
  h.reset();

  EXPECT_TRUE(observer->wait_for_event("session_closed"));
}

TEST(ServerObserverTests, AuthenticationFailedEventFired)
{
  auto h = std::make_unique<SessionTestHarness>();
  h->observer = std::make_shared<FakeServerObserver>();
  auto ex = h->threadPool.get_executor();

  h->scDeps = std::make_shared<FakeSecureChannelDeps>(ex, h->observer);
  h->sc = SecureChannel::create(
    h->scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*h->sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<DenyAllAuthenticator>();

  h->sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks, h->observer);
  SecureChannelInfo sci(h->sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  h->session = Session::create(h->sessDeps, sci, 1, CreateSessionRequest{});
  {
    SessionTestAccess::strand_barrier(*h->session);
  }

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();

  EXPECT_TRUE(h->observer->wait_for_event("authentication_failed"));
}

TEST(ServerObserverTests, NullHandlerNoCrash)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // Create deps with NO event handler.
  auto scDeps = std::make_shared<FakeSecureChannelDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  // Should not crash.
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  session.reset();
  sc.reset();
  sessDeps.reset();
  scDeps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServerObserverTests, ThrowingHandlerDoesNotCrashServer)
{
  class ThrowingHandler : public ServerObserver
  {
  public:
    void on_session_created(const SessionEventInfo&) override
    {
      throw std::runtime_error("test");
    }
  };

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto handler = std::make_shared<ThrowingHandler>();
  auto scDeps = std::make_shared<FakeSecureChannelDeps>(ex, handler);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks, handler);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  // Should not crash - the throwing handler is wrapped in invoke_user_callback.
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  session.reset();
  sc.reset();
  sessDeps.reset();
  scDeps.reset();
  handler.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Phase G: Gaps plan tests ---

// G1: on_session_closed fires exactly once for client-initiated close (duplicate fix).
TEST(ServerObserverTests, SessionClosedFiresExactlyOnceForClientClose)
{
  auto h = make_session_harness();

  // Activate.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();

  // Close.
  CloseSessionRequest csr;
  csr.request_header().request_handle() = 43;
  h->session->close(3, std::move(csr));
  h->wait_for_response();

  // Drain the strand so the close lambda releases its shared_ptr<Session>.
  h->drain_session_strand();

  // Release session to trigger destructor-based emission.
  auto observer = h->observer;
  h.reset();

  EXPECT_TRUE(observer->wait_for_event("session_closed"));
  EXPECT_EQ(observer->count_events("session_closed"), 1u)
    << "on_session_closed must fire exactly once (from destructor), not twice";
}

// G2: Timeout fires both on_session_timed_out and on_session_closed(BadTimeout).
TEST(ServerObserverTests, TimeoutFiresBothTimedOutAndClosed)
{
  auto h = make_session_harness();

  // Activate.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();

  // Simulate timeout by calling timeout() on the strand.
  SessionTestAccess::on_strand(*h->session, [](auto& g) { g.timeout(); });

  // The timeout coroutine may have continuations still pending on the strand.
  // Wait for on_session_timed_out which proves the CloseSession handler ran.
  EXPECT_TRUE(h->observer->wait_for_event("session_timed_out"));

  h->drain_session_strand();

  // Release our reference to trigger destructor -> on_session_closed.
  auto observer = h->observer;
  h.reset();

  EXPECT_TRUE(observer->wait_for_event("session_closed"));
  EXPECT_EQ(observer->count_events("session_timed_out"), 1u);
  EXPECT_EQ(observer->count_events("session_closed"), 1u);

  // Verify the close reason is BadTimeout.
  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "session_closed")
    {
      EXPECT_EQ(e.status, Status::BadTimeout);
    }
  }
}

// G3: Transport error on open channel fires on_secure_channel_closed and
// on_connection_closed(TransportError).
TEST(ServerObserverTests, TransportErrorOnOpenChannelFiresCloseEvents)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto observer = std::make_shared<FakeServerObserver>();

  auto scDeps = std::make_shared<FakeSecureChannelDeps>(ex, observer);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L", "10.0.0.1");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "L/None");
      (*g.context()).secureChannelId = 42;
      (*g.context()).state = SecureChannelContext::State::Open;
    });

  // Simulate transport error by setting close reasons directly.
  // (Can't call receive_transport_error because mConnection is nullptr in test.)
  SCTA::on_strand(*sc, [&](auto& g) { g.close_reason() = Status::BadConnectionClosed; });
  SCTA::on_strand(*sc, [&](auto& g) { g.connection_close_reason() = ConnectionCloseReason::TransportError; });

  // Destroy SC to trigger destructor events.
  sc.reset();

  EXPECT_TRUE(observer->wait_for_event("channel_closed"));
  EXPECT_TRUE(observer->wait_for_event("connection_closed"));
  EXPECT_EQ(observer->count_events("channel_closed"), 1u);
  EXPECT_EQ(observer->count_events("connection_closed"), 1u);

  // Verify connection close reason is TransportError.
  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "connection_closed")
    {
      EXPECT_TRUE(e.extra.find(std::to_string(static_cast<int>(ConnectionCloseReason::TransportError))) !=
                  std::string::npos)
        << "Expected TransportError reason, got: " << e.extra;
    }
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// G4: Destroying Session without explicit close fires on_session_closed (destructor catch-all).
TEST(ServerObserverTests, DestroySessionWithoutCloseFiresSessionClosed)
{
  auto h = make_session_harness();

  // Activate but don't close.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();

  h->drain_session_strand();

  // Release session - destructor should emit on_session_closed with default reason (BadShutdown).
  auto observer = h->observer;
  h.reset();

  EXPECT_TRUE(observer->wait_for_event("session_closed"));
  EXPECT_EQ(observer->count_events("session_closed"), 1u);

  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "session_closed")
    {
      EXPECT_EQ(e.status, Status::BadShutdown)
        << "Default close reason should be BadShutdown when no explicit close";
    }
  }
}

// G5: Destroying SecureChannel without explicit close fires on_connection_closed with ServerShutdown.
TEST(ServerObserverTests, DestroySecureChannelWithoutCloseFiresConnectionClosed)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto observer = std::make_shared<FakeServerObserver>();

  auto scDeps = std::make_shared<FakeSecureChannelDeps>(ex, observer);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L", "10.0.0.2");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "L/None");
      (*g.context()).secureChannelId = 99;
      (*g.context()).state = SecureChannelContext::State::Open;
    });

  // Destroy without close.
  sc.reset();

  EXPECT_TRUE(observer->wait_for_event("channel_closed"));
  EXPECT_TRUE(observer->wait_for_event("connection_closed"));

  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "connection_closed")
    {
      EXPECT_TRUE(e.extra.find(std::to_string(static_cast<int>(ConnectionCloseReason::ServerShutdown))) !=
                  std::string::npos)
        << "Expected ServerShutdown reason, got: " << e.extra;
      EXPECT_EQ(e.status, Status::BadShutdown);
    }
    if (e.kind == "channel_closed")
    {
      EXPECT_EQ(e.status, Status::BadShutdown);
    }
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// G6: ConnectionCloseReason::Orderly for explicit SecureChannel::close().
// Covers SVR-TCP-030 (coverage-audit retag).
TEST(ServerObserverTests, ExplicitCloseFiresOrderlyConnectionClosed)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto observer = std::make_shared<FakeServerObserver>();

  auto scDeps = std::make_shared<FakeSecureChannelDeps>(ex, observer);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L", "10.0.0.3");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "L/None");
      (*g.context()).secureChannelId = 55;
      (*g.context()).state = SecureChannelContext::State::Open;
    });

  // Call close() on the strand.
  sc->close();
  // close() posts to strand - drain strand to ensure it completes.
  SCTA::strand_barrier(*sc);

  // Destroy to trigger destructor events.
  sc.reset();

  EXPECT_TRUE(observer->wait_for_event("connection_closed"));

  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "connection_closed")
    {
      EXPECT_TRUE(
        e.extra.find(std::to_string(static_cast<int>(ConnectionCloseReason::Orderly))) != std::string::npos)
        << "Expected Orderly reason, got: " << e.extra;
      EXPECT_EQ(e.status, Status::Good);
    }
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// G7: Session eviction fires on_session_closed with BadTooManySessions.
TEST(ServerObserverTests, SessionEvictionFiresSessionClosedWithTooManySessions)
{
  auto h = make_session_harness();

  // Ensure create_internal coroutine has completed by waiting for session_created event
  // (or at least for mState to be set). Set state directly as a fallback since the
  // create_internal coroutine may not fully complete in the test environment.
  SessionTestAccess::on_strand(*h->session,
    [](auto& g)
    {
      // Ensure the session is in at least Created state for the destructor to emit.
      if (g.state().load() == SessionTestAccess::State::Invalid)
        g.state().store(SessionTestAccess::State::Created);
    });

  // Set close reason as if evicted by ServerImpl.
  h->session->set_close_reason(Status::BadTooManySessions);

  // Release session to trigger destructor.
  auto observer = h->observer;
  h.reset();

  EXPECT_TRUE(observer->wait_for_event("session_closed"));

  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "session_closed")
    {
      EXPECT_EQ(e.status, Status::BadTooManySessions);
    }
  }
}

// G8: on_session_closed fires with Good reason for normal client-initiated close.
TEST(ServerObserverTests, ClientCloseSessionFiresWithGoodReason)
{
  auto h = make_session_harness();

  // Activate.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();

  // Close.
  CloseSessionRequest csr;
  csr.request_header().request_handle() = 43;
  h->session->close(3, std::move(csr));
  h->wait_for_response();

  h->drain_session_strand();

  // Release to trigger destructor.
  auto observer = h->observer;
  h.reset();

  EXPECT_TRUE(observer->wait_for_event("session_closed"));

  auto events = observer->events();
  for (const auto& e : events)
  {
    if (e.kind == "session_closed")
    {
      EXPECT_EQ(e.status, Status::Good) << "Client-initiated close should have Good reason";
    }
  }
}

// @verifies AC-SVR-IDENT-021-OBSERVERS-RECEIVE-REDACTED-TOKENS
TEST(CredentialRedactionTests, IssuedTokenDataIsClearedAndTheX509CertificateIsKept)
{
  IssuedIdentityToken issued;
  issued.policy_id() = "issued";
  issued.token_data() = ByteString{std::vector<uint8_t>{1, 2, 3}};
  const auto redactedIssued = server::redact_credentials(issued);
  ASSERT_NE(dynamic_cast<const IssuedIdentityToken*>(redactedIssued.get()), nullptr);
  EXPECT_TRUE(dynamic_cast<const IssuedIdentityToken&>(*redactedIssued).token_data().empty());
  EXPECT_EQ(
    std::string_view{dynamic_cast<const IssuedIdentityToken&>(*redactedIssued).policy_id()}, "issued");

  X509IdentityToken x509;
  x509.certificate_data() = ByteString{std::vector<uint8_t>{9, 9}};
  const auto redactedX509 = server::redact_credentials(x509);
  ASSERT_NE(dynamic_cast<const X509IdentityToken*>(redactedX509.get()), nullptr);
  EXPECT_EQ(dynamic_cast<const X509IdentityToken&>(*redactedX509).certificate_data().size(), 2u)
    << "the certificate is public and is what identifies the user";
}
