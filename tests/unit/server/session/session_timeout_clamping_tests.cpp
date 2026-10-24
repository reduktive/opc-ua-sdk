// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_timeout_revision.h"
#include <cmath>
#include <limits>
#include <gtest/gtest.h>

#include "test_utilities.h"

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
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_service_fault.h"
#include "ua_server_components.h"

#include <algorithm>
#include <future>
#include <mutex>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// A SessionDependencies fake that allows customisation of StackLimits.
class FakeSessionDeps final : public SessionDependencies
{
public:
  FakeSessionDeps(boost::asio::any_io_executor ex, ApplicationConfig appCfg)
    : mExecutor(ex), mAppCfg(std::make_shared<const ApplicationConfig>(std::move(appCfg)))
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

  const ApplicationConfig& configuration() override
  {
    return *mAppCfg;
  }

  const ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{
      Status::BadInternalError, make_error_detail("TestError", "Not used in this test", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints() override
  {
    return {};
  }

  void remove_session(const shared_ptr<Session>&) override
  {}

  const ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return nullptr;
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
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  boost::asio::any_io_executor mExecutor;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  ServerConfig mServerCfg;
  ServerComponents mHooks;
};

class TimeoutSecureChannelDeps final : public SecureChannelDependencies
{
public:
  explicit TimeoutSecureChannelDeps(boost::asio::any_io_executor executor)
    : mExecutor(std::move(executor)), mAppCfg(ApplicationConfig::load_default())
  {}

  void create_session(SecureChannelInfo, uint32_t, CreateSessionRequest&&) override
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError, make_error_detail("TestError", "Not used", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints(ListenerHandle) override
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

  const ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ServerConfig& server_configuration() override
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
    return nullptr;
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
  ApplicationConfig mAppCfg;
  ServerConfig mServerCfg;
};

struct TimeoutChannelFixture
{
  shared_ptr<TimeoutSecureChannelDeps> dependencies;
  shared_ptr<SecureChannel> channel;
};

TimeoutChannelFixture make_timeout_channel(boost::asio::any_io_executor executor)
{
  auto dependencies = std::make_shared<TimeoutSecureChannelDeps>(executor);
  auto channel = SecureChannel::create(
    dependencies, nullptr, connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "Timeout");
  SecureChannelTestAccess::on_strand(
    *channel, [&](auto& guard) { guard.set_minimal_context_none(executor, "test/None"); });
  return {std::move(dependencies), std::move(channel)};
}

// Build an ApplicationConfig with custom session timeout bounds.
ApplicationConfig make_config(std::chrono::milliseconds minTimeout, std::chrono::milliseconds maxTimeout)
{
  auto cfg = ApplicationConfig::load_default();
  cfg.stack_limits().sessionMinimumTimeout = minTimeout;
  cfg.stack_limits().sessionMaximumTimeout = maxTimeout;
  return cfg;
}

// Create a Session over a live None channel, wait for create_internal on its strand, and return
// the revised timeout. A live channel is an invariant of every valid CreateSession fixture.
std::chrono::milliseconds create_session_and_get_revised_timeout(double requestedTimeoutMs,
  std::chrono::milliseconds minTimeout = 60'000ms, std::chrono::milliseconds maxTimeout = 3'600'000ms)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto cfg = make_config(minTimeout, maxTimeout);
  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, std::move(cfg));

  auto channelFixture = make_timeout_channel(ex);
  SecureChannelInfo sci(channelFixture.channel->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "test/None",
    std::vector<UserTokenPolicy>{});

  CreateSessionRequest csr;
  csr.requested_session_timeout() = requestedTimeoutMs;

  auto session = Session::create(sessDeps, sci, 1, std::move(csr));

  // Wait for the strand to drain (create_internal runs synchronously up to the clamping code).
  SessionTestAccess::strand_barrier(*session);

  auto result = SessionTestAccess::on_strand(*session, [](auto& g) { return g.revised_session_timeout(); });

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
  return result;
}

}  // namespace

// @relation(SVR-SESS-014, scope=function)
TEST(SessionTimeoutClamping, RequestBelowMinimum_RevisedToMinimum)
{
  // Client requests 10s, min=60s, max=1hr => revised = 60000ms
  auto revised = create_session_and_get_revised_timeout(10'000.0);
  EXPECT_EQ(revised, 60'000ms);
}

// @relation(SVR-SESS-014, scope=function)
TEST(SessionTimeoutClamping, RequestAboveMaximum_RevisedToMaximum)
{
  // Client requests 2hr, min=60s, max=1hr => revised = 3600000ms
  auto revised = create_session_and_get_revised_timeout(7'200'000.0);
  EXPECT_EQ(revised, 3'600'000ms);
}

// @relation(SVR-SESS-014, scope=function)
TEST(SessionTimeoutClamping, RequestWithinRange_RevisedToRequested)
{
  // Client requests 5min, min=60s, max=1hr => revised = 300000ms
  auto revised = create_session_and_get_revised_timeout(300'000.0);
  EXPECT_EQ(revised, 300'000ms);
}

// @relation(SVR-SESS-014, scope=function)
TEST(SessionTimeoutClamping, RequestZero_RevisedToMinimum)
{
  // Client requests 0 => treated as "use minimum" => revised = 60000ms
  auto revised = create_session_and_get_revised_timeout(0.0);
  EXPECT_EQ(revised, 60'000ms);
}

// @relation(SVR-SESS-014, scope=function)
TEST(SessionTimeoutClamping, CustomMinMax_ClampsCorrectly)
{
  // Client requests 500ms, min=1000ms, max=5000ms => revised = 1000ms
  auto revised = create_session_and_get_revised_timeout(500.0, 1'000ms, 5'000ms);
  EXPECT_EQ(revised, 1'000ms);
}

// @verifies AC-SVR-SESS-014-A-NON-FINITE-REQUESTED-TIMEOUT-IS-REVISED
// The wire Double can carry NaN and the infinities; each is revised into the window, never converted as
// it is (a NaN reached an undefined integer conversion, +inf threw).
TEST(SessionTimeoutClamping, RequestNaN_RevisedToMinimum)
{
  auto revised = create_session_and_get_revised_timeout(std::nan(""));
  EXPECT_EQ(revised, 60'000ms);
}

// @verifies AC-SVR-SESS-014-A-NON-FINITE-REQUESTED-TIMEOUT-IS-REVISED
TEST(SessionTimeoutClamping, RequestPositiveInfinity_RevisedToMaximum)
{
  auto revised = create_session_and_get_revised_timeout(std::numeric_limits<double>::infinity());
  EXPECT_EQ(revised, 3'600'000ms);
}

// @verifies AC-SVR-SESS-014-A-NON-FINITE-REQUESTED-TIMEOUT-IS-REVISED
TEST(SessionTimeoutClamping, RequestNegativeInfinity_RevisedToMinimum)
{
  auto revised = create_session_and_get_revised_timeout(-std::numeric_limits<double>::infinity());
  EXPECT_EQ(revised, 60'000ms);
}

// @verifies AC-SVR-SESS-014-A-NON-FINITE-REQUESTED-TIMEOUT-IS-REVISED
// The pure revision rule, row by row.
TEST(SessionTimeoutRevision, EveryWireValueLandsInsideTheWindow)
{
  using ua::server::detail::revise_session_timeout;
  const auto minimum = 1'000ms;
  const auto maximum = 5'000ms;
  EXPECT_EQ(revise_session_timeout(std::nan(""), minimum, maximum), minimum);
  EXPECT_EQ(revise_session_timeout(-std::numeric_limits<double>::infinity(), minimum, maximum), minimum);
  EXPECT_EQ(revise_session_timeout(std::numeric_limits<double>::infinity(), minimum, maximum), maximum);
  EXPECT_EQ(revise_session_timeout(0.0, minimum, maximum), minimum);
  EXPECT_EQ(revise_session_timeout(-5.0, minimum, maximum), minimum);
  EXPECT_EQ(revise_session_timeout(2'500.7, minimum, maximum), 2'500ms);
  EXPECT_EQ(revise_session_timeout(1e300, minimum, maximum), maximum) << "clamped in the double domain";
  EXPECT_EQ(revise_session_timeout(2'000.0, 5'000ms, 1'000ms), 5'000ms)
    << "an inverted window is the minimum";
}

// --- Inactivity timeout reset on activity (OPC 10000-4 section 5.6.2) ---

namespace
{
struct IdleSessionFixture
{
  std::shared_ptr<FakeSessionDeps> deps;
  std::shared_ptr<Session> session;
  TimeoutChannelFixture channel;
};

// Build a created (not activated) Session with a live channel. create_internal must seed activity
// and arm the inactivity timer before the fixture inspects either field.
IdleSessionFixture make_idle_session(boost::asio::thread_pool& tp)
{
  auto deps = std::make_shared<FakeSessionDeps>(tp.get_executor(), make_config(60'000ms, 3'600'000ms));
  auto channelFixture = make_timeout_channel(tp.get_executor());
  SecureChannelInfo sci(channelFixture.channel->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "test/None",
    std::vector<UserTokenPolicy>{});
  CreateSessionRequest csr;
  csr.requested_session_timeout() = 60'000.0;
  auto session = Session::create(deps, sci, 1, std::move(csr));
  SessionTestAccess::strand_barrier(*session);
  return {std::move(deps), std::move(session), std::move(channelFixture)};
}
}  // namespace

TEST(SessionInactivityTimeout, FreshActivityKeepsSessionOpenAcrossTick)
{
  // A client request just arrived (mLastActivity = now). An inactivity-timer tick must NOT reap the
  // session - otherwise an actively-used session is closed out from under the client.
  boost::asio::thread_pool tp;
  auto fixture = make_idle_session(tp);
  auto& session = *fixture.session;

  SessionTestAccess::on_strand(
    session, [](auto& g) { g.last_activity() = std::chrono::steady_clock::now(); });
  SessionTestAccess::on_strand(session, [](auto& g) { g.on_inactivity_tick(); });

  auto state = SessionTestAccess::on_strand(session, [](auto& g) { return g.session_state(); });
  EXPECT_NE(state, SessionTestAccess::State::Closed);

  fixture.session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(SessionInactivityTimeout, IdleBeyondTimeoutReapedByTick)
{
  // No request has arrived for longer than the revised timeout (60s); the tick reaps the session.
  boost::asio::thread_pool tp;
  auto fixture = make_idle_session(tp);
  auto& session = *fixture.session;

  SessionTestAccess::on_strand(session,
    [](auto& g)
    { g.last_activity() = std::chrono::steady_clock::now() - std::chrono::milliseconds{120'000}; });
  SessionTestAccess::on_strand(session, [](auto& g) { g.on_inactivity_tick(); });

  auto state = SessionTestAccess::on_strand(session, [](auto& g) { return g.session_state(); });
  EXPECT_EQ(state, SessionTestAccess::State::Closed);

  fixture.session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
// Build a created (not activated) session whose revised timeout is a short, custom value, so the
// real inactivity timer fires within a test's lifetime.
IdleSessionFixture make_idle_session_with_timeout(
  boost::asio::thread_pool& tp, std::chrono::milliseconds timeout)
{
  auto deps = std::make_shared<FakeSessionDeps>(tp.get_executor(), make_config(timeout, 3'600'000ms));
  auto channelFixture = make_timeout_channel(tp.get_executor());
  SecureChannelInfo sci(channelFixture.channel->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "test/None",
    std::vector<UserTokenPolicy>{});
  CreateSessionRequest csr;
  csr.requested_session_timeout() = static_cast<double>(timeout.count());
  auto session = Session::create(deps, sci, 1, std::move(csr));
  SessionTestAccess::strand_barrier(*session);
  return {std::move(deps), std::move(session), std::move(channelFixture)};
}
}  // namespace

TEST(SessionInactivityTimeout, IdleSessionReapedPromptlyByRealTimer)
{
  // Regression for UACTT Session Base 002 (the F82 reap-granularity follow-up): the inactivity timer
  // must reap an idle session within a small fraction of the timeout past its deadline, NOT up to a
  // full extra timeout. With a 1s revised timeout the timer ticks at ~100ms, so a session left idle
  // is Closed well before 1.5s. The pre-fix full-timeout grid only re-checked at ~2s, so the session
  // would still be open here.
  boost::asio::thread_pool tp;
  auto fixture = make_idle_session_with_timeout(tp, 1'000ms);

  // Past the 1s deadline, but before the old full-timeout grid's 2s second tick.
  std::this_thread::sleep_for(1'500ms);

  auto state = SessionTestAccess::on_strand(*fixture.session, [](auto& g) { return g.session_state(); });
  EXPECT_EQ(state, SessionTestAccess::State::Closed);

  fixture.session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Session is idle when its CLIENT has stopped sending; it is not idle while the server is sitting on
// that client's ActivateSession. The server holds every authentication for a fixed interval so credential
// checking cannot be timed from outside, and that interval is not shorter than the smallest session
// timeout the server will hand out - so a client that asks for the minimum and then activates has its
// session reaped, by the server, for work the server itself is doing, and gets no answer to a request it
// did send. Falsified by the tick closing a session with an authentication in flight.
TEST(SessionInactivityTimeout, AuthenticationInFlightIsNotIdleness)
{
  boost::asio::thread_pool tp;
  auto fixture = make_idle_session(tp);
  auto& session = *fixture.session;

  // Idle by the clock - well past the 60s revised timeout - but with the server holding an
  // ActivateSession of this session's own.
  SessionTestAccess::on_strand(session,
    [](auto& g)
    { g.last_activity() = std::chrono::steady_clock::now() - std::chrono::milliseconds{120'000}; });
  SessionTestAccess::on_strand(
    session, [&](auto&) { SessionTestAccess::set_pending_auth_flow_on_strand(session, 7); });

  SessionTestAccess::on_strand(session, [](auto& g) { g.on_inactivity_tick(); });
  EXPECT_NE(SessionTestAccess::on_strand(session, [](auto& g) { return g.session_state(); }),
    SessionTestAccess::State::Closed)
    << "the session was reaped while the server was still holding its ActivateSession, so the client "
       "waits out its own service timeout for a request the server decided not to answer";

  fixture.session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ...and the hold only defers the reap, it does not cancel it: the authentication interval is bounded, so
// the tick after it closes a session that really is idle. Without this arm the row above would be
// satisfied by a session that can never be reaped once it has ever authenticated.
TEST(SessionInactivityTimeout, IdleSessionIsReapedOnceItsAuthenticationSettles)
{
  boost::asio::thread_pool tp;
  auto fixture = make_idle_session(tp);
  auto& session = *fixture.session;

  SessionTestAccess::on_strand(session,
    [](auto& g)
    { g.last_activity() = std::chrono::steady_clock::now() - std::chrono::milliseconds{120'000}; });
  SessionTestAccess::on_strand(
    session, [&](auto&) { SessionTestAccess::set_pending_auth_flow_on_strand(session, 7); });
  SessionTestAccess::on_strand(session, [](auto& g) { g.on_inactivity_tick(); });
  ASSERT_TRUE(SessionTestAccess::on_strand(
    session, [&](auto&) { return SessionTestAccess::has_pending_auth_flow_on_strand(session); }));

  // The authentication settles (the real path clears the flow in finish_authentication).
  SessionTestAccess::on_strand(
    session, [&](auto&) { SessionTestAccess::clear_auth_flow_on_strand(session); });
  SessionTestAccess::on_strand(session, [](auto& g) { g.on_inactivity_tick(); });

  EXPECT_EQ(SessionTestAccess::on_strand(session, [](auto& g) { return g.session_state(); }),
    SessionTestAccess::State::Closed)
    << "an authentication that has settled must stop deferring the reap";

  fixture.session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// However a Session ends, a request it was holding is still owed an answer. The authentication hold is
// the one place where a Session routinely sits on a request it has already accepted, so a close that
// discards the flow leaves the client blocked on a request the server has quietly decided never to
// answer - until its own service timeout expires, which is orders of magnitude later than the fault and
// reports the wrong thing when it arrives. Falsified by a close that sends nothing.
TEST(SessionInactivityTimeout, ClosingASessionAnswersTheActivateSessionItWasHolding)
{
  boost::asio::thread_pool tp;
  auto fixture = make_idle_session(tp);
  auto& session = *fixture.session;

  std::mutex mutex;
  std::vector<Response> responses;
  SecureChannelTestAccess::on_strand(*fixture.channel.channel,
    [&](auto& guard)
    {
      guard.set_response_sink(
        [&mutex, &responses](const Response& response)
        {
          const std::lock_guard<std::mutex> lock(mutex);
          responses.push_back(response);
        });
    });

  constexpr uint32_t heldRequestId = 4242;
  SessionTestAccess::on_strand(
    session, [&](auto&) { SessionTestAccess::set_pending_auth_flow_on_strand(session, heldRequestId); });

  SessionTestAccess::on_strand(session, [](auto& g) { g.timeout(); });
  SessionTestAccess::strand_barrier(session);
  // The answer does not arrive on the Session's strand. `SecureChannel::send_response_message` POSTS
  // to the channel's strand, so barriering the Session only proves the close decided to answer - the
  // sink runs a turn later, on the other strand. Without this second barrier the read below races
  // that turn, and loses whenever the machine is busy enough to delay it.
  SecureChannelTestAccess::strand_barrier(*fixture.channel.channel);

  const std::lock_guard<std::mutex> lock(mutex);
  auto held =
    std::ranges::find_if(responses, [](const Response& response) { return response.first == heldRequestId; });
  ASSERT_NE(held, responses.end())
    << "the Session closed without answering the ActivateSession it was holding";
  auto* fault = dynamic_cast<ServiceFault*>(held->second.get());
  ASSERT_NE(fault, nullptr) << "the held request must be answered with a ServiceFault";
  EXPECT_EQ(fault->response_header().service_result().as_status(), Status::BadSessionIdInvalid)
    << "the client must learn the Session is gone, which is what any later request on this token "
       "would be told";

  fixture.session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// OPC 10000-4 5.6.2.2: maxResponseMessageSize is the largest response body the Client accepts on this
// Session, and zero means it is not used. The Read service bounds its response by it (SVC-12) through
// the SessionInfo interface, whose default answers 0; the server Session must answer with the value its
// CreateSession stored, read through the interface the service sees. The control is a CreateSession that
// did not set it.
// @verifies AC-SVR-ATTR-READ-013-READ-RESPONSE-TOO-LARGE
TEST(SessionInfoMaxResponseMessageSize, ReturnsTheValueCreateSessionStored)
{
  const auto createdWith = [](uint32_t maxResponseMessageSize)
  {
    boost::asio::thread_pool tp;
    auto deps = std::make_shared<FakeSessionDeps>(tp.get_executor(), make_config(60'000ms, 3'600'000ms));
    auto channelFixture = make_timeout_channel(tp.get_executor());
    SecureChannelInfo sci(channelFixture.channel->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::None),
      MessageSecurityMode::None,
      "test/None",
      std::vector<UserTokenPolicy>{});
    CreateSessionRequest csr;
    csr.requested_session_timeout() = 60'000.0;
    csr.max_response_message_size() = maxResponseMessageSize;
    auto session = Session::create(deps, sci, 1, std::move(csr));
    SessionTestAccess::strand_barrier(*session);
    const uint32_t observed = SessionTestAccess::on_strand(*session,
      [](auto& g)
      {
        const ua::server::SessionInfo& seenByServices = *g.session_info();
        return seenByServices.max_response_message_size();
      });
    session->terminate_for_shutdown();
    ::ua::test_utils::drain_with_timeout(tp);
    return observed;
  };

  EXPECT_EQ(createdWith(65'536u), 65'536u)
    << "the Session's SessionInfo must expose the maxResponseMessageSize its CreateSession stored";
  EXPECT_EQ(createdWith(0u), 0u) << "control: a CreateSession that did not set it reports 0 (not used)";
}
