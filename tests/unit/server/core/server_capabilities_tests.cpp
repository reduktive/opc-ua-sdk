// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_security_policy.h"
#include "ua_server_configuration.h"
#include "ua_server_impl.h"
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/strand.hpp>

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_audit_event_payload.h"
#include "ua_audit_url_mismatch_event_payload.h"
#include "ua_base_event.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node_accessor.h"
#include "ua_service_fault.h"
#include "ua_server_secure_channel_info.h"
#include "ua_server_observer.h"
#include "ua_stack_utilities.h"
#include "ua_variable_id.h"

// Test-only access to SecureChannel interfaces/state without exposing them publicly.
#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

#include "test_components.h"
using namespace ua;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;
using SCTA = ua::server::SecureChannelTestAccess;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

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

class SessionCreateFailureObserver final : public ServerObserver
{
public:
  void on_session_create_failed(const SessionEventInfo& info, StatusCode reason) override
  {
    std::lock_guard lock(mMutex);
    mEvents.emplace_back(info, std::move(reason));
  }

  std::vector<std::pair<SessionEventInfo, StatusCode>> events() const
  {
    std::lock_guard lock(mMutex);
    return mEvents;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<SessionEventInfo, StatusCode>> mEvents;
};

shared_ptr<ServerImpl> create_test_server_impl_with_caps(boost::asio::any_io_executor ex,
  ServerConfig::ServerCapabilities caps,
  ServerComponents components = {.crypto = ua::test_helpers::test_crypto()})
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  sc.server_capabilities() = std::move(caps);
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";

    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));

    sc.listeners().push_back(std::move(listener));
  }

  sc.validate();
  frozen.server = std::move(sc);

  auto server = ua::server::ServerImpl::create(ex, std::move(frozen), std::move(components));
  // Test/support: populate listener runtime state without binding sockets.
  TestAccess{*server}.initialise_listeners_from_config();
  return server;
}

struct ScHarness
{
  boost::asio::thread_pool threadPool;
  boost::asio::any_io_executor executor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> strand;

  shared_ptr<ServerImpl> server;
  weak_ptr<SecureChannelDependencies> deps;
  shared_ptr<SecureChannel> sc;

  ~ScHarness()
  {
    // Drop strand/executor-pinned members before draining; otherwise the pool's
    // outstanding-work counter stays >= 1 (any_io_executor is work-tracking) and
    // join hangs.
    sc.reset();
    server.reset();
    strand.reset();
    executor = {};
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
};

std::unique_ptr<ScHarness> create_secure_channel_harness_with_caps(ServerConfig::ServerCapabilities caps,
  ServerComponents components = {.crypto = ua::test_helpers::test_crypto()})
{
  auto h = std::make_unique<ScHarness>();
  h->executor = h->threadPool.get_executor();
  h->strand = boost::asio::make_strand(h->executor);

  h->server = create_test_server_impl_with_caps(h->executor, std::move(caps), std::move(components));
  h->deps = TestAccess{*h->server}.secure_channel_dependencies();

  h->sc = ua::server::SecureChannel::create(
    h->deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");

  // Ensure the server tracks this secure channel for service routing.
  TestAccess{*h->server}.add_secure_channel(h->sc);

  // Minimal context required by the secure channel shell.
  SecureChannelTestAccess::on_strand(
    *h->sc, [&](auto& g) { g.set_minimal_context_none(h->executor, "TestListener/None"); });
  SCTA::on_strand(*h->sc, [](auto& g) { g.channel_state() = SCTA::ChannelState::Open; });

  return h;
}

}  // namespace

// The push service asks the server whether a Session still exists, so a trust-list or push modification
// that lands after its Session closed opens no transaction. The answer is the server's own Session
// list: a created Session exists, an unknown NodeId does not, and a removed Session no longer does.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST(ServerCapabilitiesTests, TheServerAnswersWhetherASessionStillExists)
{
  auto h = create_secure_channel_harness_with_caps({});

  std::mutex responseMutex;
  std::condition_variable responseCv;
  size_t responseCount{};
  SCTA::on_strand(*h->sc,
    [&](auto& channel)
    {
      channel.set_response_sink(
        [&](const Response&)
        {
          {
            std::lock_guard lock(responseMutex);
            ++responseCount;
          }
          responseCv.notify_all();
        });
    });

  CreateSessionRequest request;
  request.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  request.session_name() = "test";
  request.client_description().application_name().text() = "client";
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  TestAccess{*h->server}.create_session(info, 100, std::move(request));
  {
    std::unique_lock lock(responseMutex);
    ASSERT_TRUE(responseCv.wait_for(lock, 10s, [&] { return responseCount >= 1; }));
  }
  auto sessions = TestAccess{*h->server}.sessions();
  ASSERT_EQ(sessions.size(), 1u);
  auto session = sessions[0];
  SessionTestAccess::strand_barrier(*session);

  EXPECT_TRUE(TestAccess{*h->server}.session_exists(session->session_id()));
  EXPECT_FALSE(TestAccess{*h->server}.session_exists(NodeId{1, Guid::create_and_generate()}))
    << "an unknown Session does not exist";

  TestAccess{*h->server}.remove_session(session);
  EXPECT_FALSE(TestAccess{*h->server}.session_exists(session->session_id()))
    << "a removed Session no longer exists";
}

// P4-SS-0005: "the Server shall close the oldest Session that is not activated before
// reaching the maximum number of supported Sessions."
// @relation(AC-SVR-SESS-005-EVICT-UNACTIVATED, scope=function)
TEST(ServerCapabilitiesTests, MaxSessionsEvictsOldestUnactivatedSession)
{
  ServerConfig::ServerCapabilities caps;
  caps.maxSessions = 1;

  auto h = create_secure_channel_harness_with_caps(std::move(caps));

  ASSERT_TRUE(TestAccess{*h->server}.server_configuration().server_capabilities().maxSessions.has_value());
  ASSERT_EQ(*TestAccess{*h->server}.server_configuration().server_capabilities().maxSessions, 1u);

  auto mkReq = []
  {
    CreateSessionRequest req;
    req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
    req.session_name() = "test";
    req.client_description().application_name().text() = "client";
    return req;
  };

  std::mutex responseMutex;
  std::condition_variable responseCv;
  size_t responseCount{};
  SCTA::on_strand(*h->sc,
    [&](auto& channel)
    {
      channel.set_response_sink(
        [&](const Response&)
        {
          {
            std::lock_guard lock(responseMutex);
            ++responseCount;
          }
          responseCv.notify_one();
        });
    });

  // A response is downstream of admission, but the test sink can notify inline while
  // Session::finish_create_response is still inside send_response_message and before it stores the
  // Committed completion state. Drain the admitted Session's strand after each response before
  // issuing the next competing CreateSession; this proves the steady-state eviction rule rather
  // than racing the deliberately protected response-queue boundary.
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  TestAccess{*h->server}.create_session(info, 100, mkReq());
  {
    std::unique_lock lock(responseMutex);
    ASSERT_TRUE(responseCv.wait_for(lock, 10s, [&] { return responseCount >= 1; }));
  }
  auto sessionsAfterFirst = TestAccess{*h->server}.sessions();
  ASSERT_EQ(sessionsAfterFirst.size(), 1u);
  auto firstSession = sessionsAfterFirst[0];
  SessionTestAccess::strand_barrier(*firstSession);

  TestAccess{*h->server}.create_session(info, 101, mkReq());
  {
    std::unique_lock lock(responseMutex);
    ASSERT_TRUE(responseCv.wait_for(lock, 10s, [&] { return responseCount >= 2; }));
  }
  auto sessionsAfterSecond = TestAccess{*h->server}.sessions();
  ASSERT_EQ(sessionsAfterSecond.size(), 1u);

  auto secondSession = sessionsAfterSecond[0];
  EXPECT_NE(sessionsAfterSecond[0], firstSession);
  SessionTestAccess::strand_barrier(*secondSession);

  TestAccess{*h->server}.create_session(info, 102, mkReq());
  {
    std::unique_lock lock(responseMutex);
    ASSERT_TRUE(responseCv.wait_for(lock, 10s, [&] { return responseCount >= 3; }));
  }
  auto sessionsAfterThird = TestAccess{*h->server}.sessions();
  ASSERT_EQ(sessionsAfterThird.size(), 1u);
  EXPECT_NE(sessionsAfterThird[0], secondSession);

  SessionTestAccess::strand_barrier(*firstSession);
  SessionTestAccess::strand_barrier(*secondSession);
  SCTA::on_strand(*h->sc, [](auto&) {});
  auto access = TestAccess{*h->server};
  EXPECT_EQ(access.session_token_count(), 1u);
  EXPECT_EQ(access.summary_counters()->currentSessionCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(access.summary_counters()->cumulatedSessionCount.load(std::memory_order_relaxed), 3u);
  EXPECT_EQ(h->sc->session_count(), 1u);
  {
    std::lock_guard lock(responseMutex);
    EXPECT_EQ(responseCount, 3u);
  }

  // This harness owns a work-tracking executor. Close the surviving Session while the pool is
  // still running so its long timeout timer and SecureChannel registration are drained before
  // ScHarness joins the pool.
  sessionsAfterThird[0]->terminate_for_shutdown();
  SessionTestAccess::strand_barrier(*sessionsAfterThird[0]);
  SCTA::on_strand(*h->sc, [](auto&) {});
}

// Negative test: when all sessions are activated, eviction cannot occur and the request is rejected.
// @relation(AC-SVR-EVT-AUD-008-CREATESESSION-AUDIT, scope=function)
TEST(ServerCapabilitiesTests, MaxSessionsLimitRejectsWhenAllSessionsActivated)
{
  ServerConfig::ServerCapabilities caps;
  caps.maxSessions = 1;

  ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto h = create_secure_channel_harness_with_caps(std::move(caps), std::move(components));
  auto observer = std::make_shared<SessionCreateFailureObserver>();
  h->server->set_observer(observer);

  std::mutex mx;
  std::condition_variable cv;
  std::vector<Response> responses;

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lk(mx);
            responses.push_back(r);
          }
          cv.notify_one();
        });
    });

  // Sanity: ensure the sink is running.
  h->sc->send_response_message(
    std::make_pair(999u, stack_utils::create_service_fault(nullptr, Status::BadUnexpectedError)));
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 2s, [&]() { return !responses.empty(); }));
    responses.clear();
  }

  auto mkReq = []
  {
    CreateSessionRequest req;
    req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
    req.session_name() = "test";
    req.client_description().application_name().text() = "client";
    return req;
  };

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  // Create and activate the first session so it cannot be evicted.
  TestAccess{*h->server}.create_session(info, 100, mkReq());
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 10s, [&]() { return responses.size() >= 1; }));
  }

  // Wait for CreateSession to complete on the session strand before activating.
  auto* r100 = dynamic_cast<CreateSessionResponse*>(responses.back().second.get());
  ASSERT_NE(r100, nullptr);

  // Find the session and activate it via its public API.
  auto sessions = TestAccess{*h->server}.sessions();
  ASSERT_EQ(sessions.size(), 1u);
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  sessions[0]->activate(200, std::move(asr), {});

  // Wait for ActivateSession response.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 10s, [&]() { return responses.size() >= 2; }));
  }

  responses.clear();

  // Now attempt a second CreateSession - should be rejected since the existing session is activated.
  TestAccess{*h->server}.create_session(info, 101, mkReq());
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 10s, [&]() { return responses.size() >= 1; }));
  }

  auto* sf = dynamic_cast<ServiceFault*>(responses.back().second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadTooManySessions);
  // Enriched: the rejection carries the session limit + current count context.
  const auto detail = sf->response_header().service_result().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_TRUE(std::any_of(detail->context.begin(),
    detail->context.end(),
    [](const NamedValue& entry) { return entry.key == ContextKeys::limit.value(); }));

  const auto failureEvents = observer->events();
  ASSERT_EQ(failureEvents.size(), 1u);
  EXPECT_EQ(failureEvents[0].first.sessionName, "test");
  EXPECT_EQ(failureEvents[0].second, Status::BadTooManySessions);
  ASSERT_NE(failureEvents[0].second.shared_detail(), nullptr);
}

// @relation(AC-SVR-EVT-AUD-008-CREATESESSION-AUDIT, scope=function)
TEST(ServerCapabilitiesTests, ShutdownCreateSessionRefusalNotifiesObserverWithRichStatus)
{
  auto h = create_secure_channel_harness_with_caps({});
  auto observer = std::make_shared<SessionCreateFailureObserver>();
  h->server->set_observer(observer);

  std::mutex responseMutex;
  std::condition_variable responseCv;
  std::vector<Response> responses;
  SCTA::on_strand(*h->sc,
    [&](auto& channel)
    {
      channel.set_response_sink(
        [&](const Response& response)
        {
          {
            std::lock_guard lock(responseMutex);
            responses.push_back(response);
          }
          responseCv.notify_one();
        });
    });

  CreateSessionRequest request;
  request.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  request.session_name() = "shutdown-refusal";
  request.request_header().audit_entry_id() = "shutdown-audit";

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*h->sc, [](auto& channel) -> const auto& { return channel.user_identity_tokens(); }));

  TestAccess{*h->server}.dynamic_state()->serverState.store(ServerState::Shutdown);
  TestAccess{*h->server}.create_session(info, 102, std::move(request));

  {
    std::unique_lock lock(responseMutex);
    ASSERT_TRUE(responseCv.wait_for(lock, 2s, [&] { return !responses.empty(); }));
  }
  auto* fault = dynamic_cast<ServiceFault*>(responses.back().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), Status::BadServerHalted);

  const auto failureEvents = observer->events();
  ASSERT_EQ(failureEvents.size(), 1u);
  EXPECT_EQ(failureEvents[0].first.sessionName, "shutdown-refusal");
  EXPECT_EQ(failureEvents[0].first.auditEntryId, "shutdown-audit");
  EXPECT_EQ(failureEvents[0].second, Status::BadServerHalted);
}

namespace
{

/// Thread-safe tally of audit Events seen on the server's EventBus. Held by shared_ptr because the
/// listener may still be invoked on the dispatch strand while the harness drains.
struct AuditEventRecorder
{
  void record(const BaseEvent& event)
  {
    if (dynamic_cast<const AuditEventPayload*>(&event) == nullptr)
    {
      return;
    }
    {
      std::lock_guard<std::mutex> lk(mutex);
      ++auditEvents;
      if (dynamic_cast<const AuditUrlMismatchEventPayload*>(&event) != nullptr)
      {
        ++urlMismatchEvents;
      }
    }
    cv.notify_all();
  }

  void wait_for_audit_event(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lk(mutex);
    cv.wait_for(lk, timeout, [this] { return auditEvents > 0; });
  }

  size_t audit_events() const
  {
    std::lock_guard<std::mutex> lk(mutex);
    return auditEvents;
  }

  size_t url_mismatch_events() const
  {
    std::lock_guard<std::mutex> lk(mutex);
    return urlMismatchEvents;
  }

  mutable std::mutex mutex;
  std::condition_variable cv;
  size_t auditEvents{0};
  size_t urlMismatchEvents{0};
};

std::function<void(const BaseEvent&)> make_audit_listener(std::shared_ptr<AuditEventRecorder> recorder)
{
  return [recorder = std::move(recorder)](const BaseEvent& event)
  {
    recorder->record(event);
  };
}

/// Same single-endpoint server as the harness above, with auditing switched through the real
/// configuration field the product reads - nothing else differs between the two runs.
std::unique_ptr<ScHarness> create_secure_channel_harness_with_auditing(bool auditingEnabled)
{
  auto h = std::make_unique<ScHarness>();
  h->executor = h->threadPool.get_executor();
  h->strand = boost::asio::make_strand(h->executor);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  sc.auditingEnabled = auditingEnabled;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";

    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));

    sc.listeners().push_back(std::move(listener));
  }

  sc.validate();
  frozen.server = std::move(sc);

  h->server = ua::server::ServerImpl::create(
    h->executor, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  TestAccess{*h->server}.initialise_listeners_from_config();

  h->deps = TestAccess{*h->server}.secure_channel_dependencies();

  h->sc = ua::server::SecureChannel::create(
    h->deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");

  TestAccess{*h->server}.add_secure_channel(h->sc);

  SecureChannelTestAccess::on_strand(
    *h->sc, [&](auto& g) { g.set_minimal_context_none(h->executor, "TestListener/None"); });
  SCTA::on_strand(*h->sc, [](auto& g) { g.channel_state() = SCTA::ChannelState::Open; });

  return h;
}

bool read_server_auditing_property(const shared_ptr<ServerImpl>& server)
{
  auto as = server->address_space();
  auto node = as.try_find_node_sync(NodeId{VariableId::Server_Auditing});
  EXPECT_TRUE(node.is_good());
  auto var = node.value().as<VariableAccessor>();
  EXPECT_TRUE(var.has_value());
  auto dv = var->try_read_value_sync();
  EXPECT_TRUE(dv.is_good());
  EXPECT_TRUE(dv.value().value().is_boolean());
  return dv.value().value().as<bool>();
}

struct AuditingOutcome
{
  bool auditingProperty{false};
  bool faultSeen{false};
  StatusCode createStatus{};
  size_t auditEvents{0};
  size_t urlMismatchEvents{0};
};

/// Reads `Server.Auditing`, then drives one audited refusal (CreateSession naming an EndpointUrl no
/// listener advertises - Part 4 AuditUrlMismatchEventType) and reports what the EventBus saw.
AuditingOutcome drive_audited_create_session(bool auditingEnabled)
{
  AuditingOutcome outcome;

  auto h = create_secure_channel_harness_with_auditing(auditingEnabled);

  // Installing a listener arms has_event_interest() synchronously, so the emission gate differs
  // between the two runs only by the configured auditing flag.
  auto recorder = std::make_shared<AuditEventRecorder>();
  h->server->event_bus().set_event_listener(make_audit_listener(recorder));

  outcome.auditingProperty = read_server_auditing_property(h->server);

  std::mutex mx;
  std::condition_variable cv;
  std::vector<Response> responses;

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lk(mx);
            responses.push_back(r);
          }
          cv.notify_one();
        });
    });

  CreateSessionRequest req;
  req.endpoint_url() = "opc.tcp://127.0.0.1:4999";  // no listener advertises this port
  req.session_name() = "auditing";
  req.client_description().application_name().text() = "client";

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  TestAccess{*h->server}.create_session(info, 100, std::move(req));

  {
    std::unique_lock<std::mutex> lk(mx);
    EXPECT_TRUE(cv.wait_for(lk, 10s, [&]() { return !responses.empty(); }));
    if (!responses.empty())
    {
      if (auto* sf = dynamic_cast<ServiceFault*>(responses.back().second.get()))
      {
        outcome.faultSeen = true;
        outcome.createStatus = sf->response_header().service_result();
      }
    }
  }

  // The audit Event is emitted before the fault is sent, but delivery hops the EventBus dispatch
  // strand; give it a bounded window. With auditing off nothing is emitted and the wait expires.
  recorder->wait_for_audit_event(2s);

  outcome.auditEvents = recorder->audit_events();
  outcome.urlMismatchEvents = recorder->url_mismatch_events();

  h->server->event_bus().set_event_listener(nullptr);
  return outcome;
}

}  // namespace

// Part 5 ServerType: the `Server.Auditing` Property tells a client whether the audit surface is worth
// subscribing to, so it must reflect the server's actual emission state, not merely echo a setting.
// A plausible implementation writes the configured Boolean into the node and stops there - the flag
// then reads true while no audit Event is ever raised, or reads false while the server audits anyway.
// Both halves are driven through the same real CreateSession refusal (an EndpointUrl no listener
// advertises), which is an audited operation, so the only difference between the runs is the
// configured auditing state.
// @verifies AC-SVR-AUDIT-001-AUDITING-FLAG
TEST(ServerCapabilitiesTests, AuditingPropertyReflectsWhetherAuditEventsAreRaised)
{
  const AuditingOutcome audited = drive_audited_create_session(/*auditingEnabled=*/true);
  const AuditingOutcome unaudited = drive_audited_create_session(/*auditingEnabled=*/false);

  // The audited code path must actually have been reached in both runs, otherwise comparing the
  // emission counts proves nothing.
  ASSERT_TRUE(audited.faultSeen);
  ASSERT_TRUE(unaudited.faultSeen);
  EXPECT_EQ(audited.createStatus, Status::BadTcpEndpointUrlInvalid);
  EXPECT_EQ(unaudited.createStatus, Status::BadTcpEndpointUrlInvalid);

  // The Property is true when auditing is configured and false when it is not.
  EXPECT_TRUE(audited.auditingProperty);
  EXPECT_FALSE(unaudited.auditingProperty);

  // ... and audit Events are raised exactly when it is true.
  EXPECT_GE(audited.auditEvents, 1u);
  EXPECT_GE(audited.urlMismatchEvents, 1u);
  EXPECT_EQ(unaudited.auditEvents, 0u);
  EXPECT_EQ(unaudited.urlMismatchEvents, 0u);
}
