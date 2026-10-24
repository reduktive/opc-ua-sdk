// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_certificate_validation_paths.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "ua_subscription.h"
#include "ua_subscriptions_pipeline_test_access.h"
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
#include "ua_create_subscription_request.h"

#include "ua_anonymous_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_issued_identity_token.h"
#include "ua_crypto.h"
#include "ua_read_request.h"

#include "ua_server_components.h"

// Part 4 section 7.41.2 UserIdentityToken-validation coverage at the end of this file needs the
// production client-side token encoder, the server's certificate/key plumbing, a real log sink and
// the server's own identity-lockout tracker.
#include "ua_service_fault.h"
#include "ua_x509_certificate.h"
#include "ua_certificate_store.h"
#include "ua_user_token_encryption.h"
// The EncryptedSecret ordering row reads the decoder's own step tag, and the cross-family row drives the
// endpoint-configuration validator; both live beside the session in the same test binary.
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_logger.h"
#include "ua_application_configuration.h"
#include "ua_server_configuration.h"
#include "ua_tcp_transport_connection.h"
#include "ua_server_impl.h"

#include "server_impl_test_access.h"
#include "fake_certificate_store.h"
#include "run_async_sync.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "ua_sec_pol_basic256_sha256.h"

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include "test_components.h"

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
using SCTA = ua::server::SecureChannelTestAccess;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;
using SCTA = ua::server::SecureChannelTestAccess;

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

/// Authenticates every token as the next user id in `mUserIds` (the last one repeats), standing in for an
/// authenticator that derives a subject from an opaque token (an IssuedToken's JWT, for example).
class ScriptedSubjectAuthenticator final : public UserAuthenticator
{
public:
  explicit ScriptedSubjectAuthenticator(
    std::vector<std::string> userIds, std::optional<UserTokenKind> kind = std::nullopt)
    : mUserIds(std::move(userIds)), mKind(kind)
  {}

  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    const auto index = std::min(mNext.fetch_add(1), mUserIds.size() - 1);
    UserIdentity identity{.userId = mUserIds[index], .displayName = mUserIds[index], .claims = {}};
    identity.kind = mKind.value_or(req.identity.kind);
    completion(make_authn_success(std::move(identity)));
  }

private:
  std::vector<std::string> mUserIds;
  std::optional<UserTokenKind> mKind;
  std::atomic<std::size_t> mNext{0};
};

class DenyUnsupportedAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    if (req.identity.kind == UserTokenKind::Unsupported)
    {
      completion(make_authn_failure(StatusCode{Status::BadUserAccessDenied}, "unsupported"));
      return;
    }

    completion(make_authn_success(UserIdentity{.userId = "user", .displayName = "User", .claims = {}}));
  }
};

// The authentication deadline of a test that asserts an activation SUCCEEDS. The harness default of 50 ms
// keeps the many refusal tests fast, since the deadline holds every failure until it passes; a success is
// answered as soon as it is known, but its RSA decryption on a loaded CI host can outlast 50 ms and be
// abandoned as a slow authenticator (measured 2026-10-16: 2 in 96 runs under 12-way load). Those tests
// take the SDK's own default instead, as does make_session_harness, whose tests mostly activate
// successfully: a host stall of a few seconds abandoned a re-activation there too.
const std::chrono::milliseconds successAuthnTimeout = ::ua::server::ServerConfig{}.authnTimeout;

class FakeSessionDeps final : public SessionDependencies
{
public:
  /// `crypto` defaults to null, which is what every refusal-path test here needs and relies on.
  ///
  /// **A test that drives activation to SUCCESS must pass a real one.** The success path builds the
  /// response's next server nonce through `deps->crypto()->get_entropy_async(...)`
  /// (`ua_server_session.cpp`), with no null check, so a null provider segfaults there rather than
  /// failing an assertion. Every test above reaches only refusals, which return before the nonce is
  /// generated -- which is why this has never mattered until a test asserted an acceptance.
  FakeSessionDeps(boost::asio::any_io_executor ex, ServerComponents hooks,
    shared_ptr<const Crypto> crypto = nullptr,
    std::chrono::milliseconds authenticationInterval = std::chrono::milliseconds{50})
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto))
  {
    // Keep unrelated Session-shell tests fast. Public default behavior is covered through the real
    // Server fixture.
    mServerCfg.authnTimeout = authenticationInterval;
  }

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
    return mCrypto;
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
    throw UaException{
      Status::BadInternalError, make_error_detail("TestError", "Not used in this test", "Test")};
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
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  shared_ptr<const Crypto> mCrypto;
};

}  // namespace

// @relation(SVR-IDENT-001, SVR-JWT-015, scope=function)
TEST(SessionShellWiringTests, ActivateSessionAnonymousAllowedWithAuthenticator)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // Create a secure channel shell just to capture responses via the existing sink.
  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  // Create Session directly; we won't run CreateSession pipeline here.
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  // Ensure the create task has been installed before calling activate.
  // `Session::create` posts work onto the session strand.
  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Regression: a malformed message can tear down the secure channel while an
// ActivateSession is still mid-authentication. The activate-response builder then
// ran with a disengaged mSecureChannelInfo and dereferenced it, aborting the server
// (the channel-layer fuzzer reproduced exactly this). The builder must instead fail
// the request cleanly with BadSecureChannelClosed.
TEST(SessionShellWiringTests, ActivateResponseWithClosedChannelFailsCleanlyNoCrash)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
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

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  // Arrange the exact post-race state: an in-flight ActivateSession request whose
  // secure channel has since been torn down (mSecureChannelInfo disengaged).
  constexpr uint32_t requestId = 7;
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.in_flight_requests().emplace(requestId, std::make_shared<ActivateSessionRequest>());
      g.secure_channel_info().reset();
    });

  // Act: build the activate response. Before the fix this dereferenced the disengaged
  // optional and aborted; now it must complete the callback with a clean failure.
  optional<VoidResult> result;
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    { g.send_activate_session_response(requestId, [&](VoidResult r) { result = std::move(r); }); });

  ASSERT_TRUE(result.has_value()) << "callback must fire synchronously on the strand";
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_status(), Status::BadSecureChannelClosed);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(SessionShellWiringTests, ActivateSessionDeniedWhenAnonymousDisabledAndNoAuthenticator)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Endpoint does NOT advertise Anonymous - anonymous tokens should be rejected.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(
        ex, "L/None", {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::None)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // No authenticator set.

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 43;
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadIdentityTokenRejected);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Covers SVR-IDENT-002 (coverage-audit retag).
// @relation(SVR-IDENT-002, scope=function)
TEST(SessionShellWiringTests, ActivateSessionDeniedForUnsupportedToken)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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

    std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle) override
    {
      return {};
    }

    shared_ptr<const Crypto> crypto() override
    {
      return nullptr;
    }  // ensures X509 token becomes Unsupported

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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Advertise X509 with an authenticated policy so it passes the runtime security guard
  // (X509 requires a non-None effective policy for UserTokenSignature verification).
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<DenyUnsupportedAuthenticator>();

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 44;

  // Present a token that will be parsed as Unsupported because DummySecureDeps crypto() == nullptr.
  // The policy_id must match the advertised Certificate policy so it passes policy matching.
  auto token = std::make_unique<X509IdentityToken>();
  token->certificate_data() = ByteString{uint8_t{1}, uint8_t{2}};
  token->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(token);

  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadUserAccessDenied);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==================================================================================
// Helper harness for Session shell requirement tests (P4-SS-0023, 0026, 0027).
// ==================================================================================

namespace
{

struct SessionTestHarness
{
  boost::asio::thread_pool threadPool{2};
  shared_ptr<SecureChannelDependencies> scDeps;  // prevent weak_ptr expiry
  shared_ptr<FakeSessionDeps> sessDeps;  // prevent weak_ptr expiry
  shared_ptr<SecureChannel> sc;
  shared_ptr<Session> session;

  std::mutex mutex;
  std::condition_variable cv;
  optional<Response> lastResponse;

  void wait_for_response()
  {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [&]() { return lastResponse.has_value(); });
  }

  void clear_response()
  {
    std::lock_guard<std::mutex> lk(mutex);
    lastResponse.reset();
  }

  void shutdown()
  {
    if (session)
      session->terminate_for_shutdown();
    if (sc)
      sc->close();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
};

// Creates a SecureChannel, a Session (with CreateSession), and wires the response sink.
std::unique_ptr<SessionTestHarness> make_session_harness(
  SecurityPolicyId policyId, ByteString clientNonce, shared_ptr<UserAuthenticator> authenticator = nullptr)
{
  auto h = std::make_unique<SessionTestHarness>();
  auto ex = h->threadPool.get_executor();

  // -- SecureChannel boilerplate --
  class ScDeps : public SecureChannelDependencies
  {
  public:
    explicit ScDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  h->scDeps = std::make_shared<ScDeps>(ex);
  h->sc = SecureChannel::create(
    h->scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*h->sc,
    [&](auto& g) { g.set_minimal_context_authenticated(ex, "L/Ep", policyId, MessageSecurityMode::None); });

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lock(mx);
            last = r;
          }
          cv.notify_one();
        });
    });

  // -- Session --
  ServerComponents hooks;
  hooks.authenticator =
    authenticator ? std::move(authenticator) : std::make_shared<AllowAnonymousAuthenticator>();

  const auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
  shared_ptr<const X509Certificate> clientCertificate;
  if (policyId != SecurityPolicyId::None)
  {
    Crypto::Name subject;
    subject.commonName = "Session Shell Client";
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back("urn:test:session-shell-client");
    auto certificateResult = crypto->try_create_self_signed_application_instance_certificate_sync(
      subject, UtcTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
    clientCertificate = std::move(certificateResult).value().second;
  }

  h->sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks, crypto, successAuthnTimeout);
  SecureChannelInfo sci(h->sc->weak_from_this(),
    SecurityPolicy::create(policyId),
    MessageSecurityMode::None,
    "L/Ep",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }),
    clientCertificate);

  CreateSessionRequest csr;
  csr.client_nonce() = std::move(clientNonce);
  if (clientCertificate)
  {
    csr.client_description().application_uri() = "urn:test:session-shell-client";
    csr.client_certificate() = clientCertificate->der_encoding();
  }
  h->session = Session::create(h->sessDeps, sci, 1, std::move(csr));

  // Wait for create_internal to complete on the session strand.
  SessionTestAccess::strand_barrier(*h->session);

  return h;
}

// Creates a second SecureChannel for channel-reassociation tests.
shared_ptr<SecureChannel> make_second_channel(
  boost::asio::any_io_executor ex, ApplicationInstanceCertificate clientCert = {})
{
  class ScDeps2 : public SecureChannelDependencies
  {
  public:
    explicit ScDeps2(boost::asio::any_io_executor ex) : mExecutor(ex)
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
      return 2;
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps2 = std::make_shared<ScDeps2>(ex);
  auto sc2 = SecureChannel::create(
    scDeps2, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{2}, "L2");
  SecureChannelTestAccess::on_strand(*sc2, [&](auto& g) { g.set_minimal_context_none(ex, "L2/None"); });
  return sc2;
}

}  // namespace

// --- P4-SS-0023 ---

// Negative: authenticated policy with <32-byte nonce is rejected with the specific Bad_NonceInvalid
// (session services are past SecureChannel establishment, so no error-code masking).
// @relation(SVR-SESS-009, SVR-SESS-023, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, CreateSessionRejectsShortNonceOnAuthenticatedPolicy)
{
  ByteString shortNonce(31, uint8_t{0xBB});
  auto h = make_session_harness(SecurityPolicyId::Basic256Sha256, shortNonce);

  h->wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadNonceInvalid);

  h->shutdown();
}

// Positive: SecurityPolicy::None accepts any nonce up to the 128-byte ceiling, the empty one included.
// We verify the session was created (not rejected) by successfully activating it.
// The CreateSession response itself cannot be observed because FakeSessionDeps lacks discovery deps.
// @relation(SVR-SESS-010, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, CreateSessionAcceptsEmptyNonceOnUnauthenticatedPolicy)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // Activate on same channel - proves CreateSession succeeded internally.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();

  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  h->shutdown();
}

// --- P4-SS-0026 ---

// @relation(SVR-SESS-026, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, FirstActivateOnSameChannelSucceeds)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();

  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  h->shutdown();
}

// @relation(AC-SVR-SESS-026-FIRST-ACTIVATE-SAME-CHANNEL, scope=function)
TEST(SessionShellWiringTests, FirstActivateOnDifferentChannelRejected)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  auto ex = h->threadPool.get_executor();
  auto sc2 = make_second_channel(ex);
  SecureChannelInfo sci2(sc2->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  std::vector<Response> oldChannelResponses;
  std::vector<Response> newChannelResponses;
  SCTA::on_strand(*h->sc,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { oldChannelResponses.push_back(response); }); });
  SCTA::on_strand(*sc2,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { newChannelResponses.push_back(response); }); });

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 43;
  h->session->activate(2, std::move(asr), sci2);

  SessionTestAccess::strand_barrier(*h->session);
  SCTA::strand_barrier(*h->sc);
  SCTA::strand_barrier(*sc2);

  EXPECT_TRUE(oldChannelResponses.empty());
  ASSERT_EQ(newChannelResponses.size(), 1u);
  EXPECT_EQ(std::get<uint32_t>(newChannelResponses.front()), 2u);
  auto* sf = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(newChannelResponses.front()).get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSecureChannelIdInvalid);

  h->shutdown();
}

// @verifies AC-SVR-SESS-026-AN-EXPIRED-ORIGINAL-CHANNEL-IS-A-DIFFERENT-CHANNEL
// The original channel is gone (its weak pointer expired) when the first ActivateSession arrives on a second
// channel. Nothing proves the channels are the same, so the activation is refused as on a different channel;
// before the fix an expired original made the comparison vacuously "same" and the activation went through.
TEST(SessionShellWiringTests, FirstActivateAfterOriginalChannelExpiredIsRejected)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // The session remembers a channel that no longer exists.
  SessionTestAccess::on_strand(*h->session,
    [](auto& g)
    {
      g.secure_channel_info() = SecureChannelInfo(std::weak_ptr<SecureChannel>{},
        SecurityPolicy::create(SecurityPolicyId::None),
        MessageSecurityMode::None,
        "L1/None");
    });

  auto ex = h->threadPool.get_executor();
  auto sc2 = make_second_channel(ex);
  SecureChannelInfo sci2(sc2->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  std::vector<Response> newChannelResponses;
  SCTA::on_strand(*sc2,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { newChannelResponses.push_back(response); }); });

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 43;
  h->session->activate(2, std::move(asr), sci2);

  SessionTestAccess::strand_barrier(*h->session);
  SCTA::strand_barrier(*sc2);

  ASSERT_EQ(newChannelResponses.size(), 1u);
  auto* sf = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(newChannelResponses.front()).get());
  ASSERT_NE(sf, nullptr) << "an activation that cannot prove its channel is the original one is refused";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSecureChannelIdInvalid);

  h->shutdown();
}

// @verifies AC-SVR-UASC-037-A-REQUEST-ID-ALREADY-IN-FLIGHT-IS-REFUSED-NOT-OVERWRITTEN
namespace
{
// Activates the harness session on its own channel and parks a Read under `requestId` the way
// request_received records one (entry + handle), so a later request under the same id collides.
std::shared_ptr<ReadRequest> activate_and_park_request(
  SessionTestHarness& h, uint32_t requestId, uint32_t handle)
{
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 100;
  h.session->activate(2, std::move(asr), {});
  h.wait_for_response();
  auto* resp = dynamic_cast<ActivateSessionResponse*>(h.lastResponse->second.get());
  EXPECT_NE(resp, nullptr);
  if (resp)
  {
    EXPECT_TRUE(resp->response_header().service_result().is_good());
  }
  h.clear_response();
  auto inFlight = std::make_shared<ReadRequest>();  // the first request, still being served
  inFlight->request_header().request_handle() = handle;
  SessionTestAccess::on_strand(*h.session,
    [&](auto& g)
    {
      g.in_flight_requests()[requestId] = inFlight;
      g.request_handles_by_request_id()[requestId] = handle;
    });
  return inFlight;
}

void expect_in_flight_refusal(SessionTestHarness& h, uint32_t requestId, uint32_t newcomerHandle,
  const std::shared_ptr<ReadRequest>& inFlight, uint32_t inFlightHandle)
{
  h.wait_for_response();
  ASSERT_TRUE(h.lastResponse.has_value());
  auto* sf = dynamic_cast<ServiceFault*>(h.lastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "the newcomer under an in-flight requestId is refused";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadServerTooBusy);
  EXPECT_EQ(sf->response_header().request_handle(), newcomerHandle)
    << "the fault echoes the newcomer's own handle, not the holder's";
  const auto stored = SessionTestAccess::on_strand(*h.session,
    [&](auto& g)
    {
      return std::make_pair(std::static_pointer_cast<Structure>(g.in_flight_requests()[requestId]),
        g.request_handles_by_request_id()[requestId]);
    });
  EXPECT_EQ(stored.first.get(), static_cast<Structure*>(inFlight.get()))
    << "the first request's entry is untouched";
  EXPECT_EQ(stored.second, inFlightHandle) << "the first request's recorded handle is untouched";
}
}  // namespace

// @verifies AC-SVR-UASC-037-A-REQUEST-ID-ALREADY-IN-FLIGHT-IS-REFUSED-NOT-OVERWRITTEN
// A second request under a requestId that is still in flight (a reused id) is refused Bad_ServerTooBusy
// with its own handle echoed, and the first request's entry and handle are untouched.
TEST(SessionShellWiringTests, ARequestUnderAnInFlightRequestIdIsRefusedWithItsOwnHandle)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto inFlight = activate_and_park_request(*h, 50000, 1);
  auto newcomer = std::make_shared<ReadRequest>();
  newcomer->request_header().request_handle() = 999;
  Request request = std::make_pair(uint32_t{50000}, std::static_pointer_cast<Structure>(newcomer));
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.request_received(std::move(request)); });
  expect_in_flight_refusal(*h, 50000, 999, inFlight, 1);
  h->shutdown();
}

// @verifies AC-SVR-UASC-037-A-REQUEST-ID-ALREADY-IN-FLIGHT-IS-REFUSED-NOT-OVERWRITTEN
// ActivateSession enters through its own path (Session::activate) and is guarded there.
TEST(SessionShellWiringTests, AnActivateSessionUnderAnInFlightRequestIdIsRefusedWithItsOwnHandle)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto inFlight = activate_and_park_request(*h, 5, 1);
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 77;
  h->session->activate(5, std::move(asr), {});
  expect_in_flight_refusal(*h, 5, 77, inFlight, 1);
  h->shutdown();
}

// @verifies AC-SVR-UASC-037-A-REQUEST-ID-ALREADY-IN-FLIGHT-IS-REFUSED-NOT-OVERWRITTEN
// CloseSession returns early in request_received and would otherwise record over the holder's handle.
TEST(SessionShellWiringTests, ACloseSessionUnderAnInFlightRequestIdIsRefusedWithItsOwnHandle)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto inFlight = activate_and_park_request(*h, 6, 1);
  auto close = std::make_shared<CloseSessionRequest>();
  close->request_header().request_handle() = 88;
  Request request = std::make_pair(uint32_t{6}, std::static_pointer_cast<Structure>(close));
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.request_received(std::move(request)); });
  expect_in_flight_refusal(*h, 6, 88, inFlight, 1);
  const bool closed = SessionTestAccess::on_strand(
    *h->session, [](auto& g) { return g.session_state() == SessionTestAccess::State::Closed; });
  EXPECT_FALSE(closed) << "a refused CloseSession closes nothing";
  h->shutdown();
}

// --- P4-SS-0027 ---

// @relation(SVR-SESS-027, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, ReactivateOnDifferentChannelWithSameCertSucceeds)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // First activate on same channel.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();
  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  h->clear_response();
  // The Session releases its activation claim on its strand after it has sent the response; a
  // re-activation that arrives before then is an overlapping one and is answered BadServerTooBusy.
  SessionTestAccess::strand_barrier(*h->session);

  // Reconnect on second channel with same (empty) client cert.
  auto ex = h->threadPool.get_executor();
  auto sc2 = make_second_channel(ex);

  // Response will be sent via sc2 after reassociation; wire its sink to the harness.
  SCTA::on_strand(*sc2,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lock(mx);
            last = r;
          }
          cv.notify_one();
        });
    });

  SecureChannelInfo sci2(sc2->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  ActivateSessionRequest asr2;
  asr2.request_header().request_handle() = 43;
  h->session->activate(3, std::move(asr2), sci2);

  h->wait_for_response();

  auto* resp2 = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp2, nullptr);
  EXPECT_TRUE(resp2->response_header().service_result().is_good());

  h->shutdown();
}

// Part 4 5.6.3.1: a re-activation over a different SecureChannel must present the identity the Session
// has. A token whose bytes cannot be compared (an IssuedToken's secret is encrypted under a fresh nonce
// every time) is compared by the identity the authenticator derives from it: a second activation whose
// token authenticates as a different subject is refused with Bad_IdentityChangeNotSupported and the
// Session keeps its identity. The control authenticates the same subject again and is accepted.
// @verifies AC-SVR-SESS-027-A-REACTIVATION-ON-A-NEW-CHANNEL-KEEPS-THE-AUTHENTICATED-IDENTITY
TEST(SessionShellWiringTests, AReactivationOnANewChannelThatAuthenticatesAnotherSubjectIsRefused)
{
  struct Outcome
  {
    StatusCode status{Status::Good};
    std::string identity;
    bool stillOnTheFirstChannel{false};
  };

  const auto reactivateOnSecondChannel = [](std::vector<std::string> subjects,
                                           std::optional<UserTokenKind> kind = std::nullopt) -> Outcome
  {
    auto h = make_session_harness(SecurityPolicyId::None,
      ByteString{},
      std::make_shared<ScriptedSubjectAuthenticator>(std::move(subjects), kind));
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 42;
    h->session->activate(2, std::move(asr), {});
    h->wait_for_response();
    EXPECT_NE(dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get()), nullptr);
    h->clear_response();
    // The Session releases its activation claim on its strand after it has sent the response; a
    // re-activation that arrives before then is an overlapping one and is answered BadServerTooBusy.
    SessionTestAccess::strand_barrier(*h->session);

    auto sc2 = make_second_channel(h->threadPool.get_executor());
    SCTA::on_strand(*sc2,
      [&](auto& g)
      {
        g.set_response_sink(
          [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
          {
            {
              std::lock_guard<std::mutex> lock(mx);
              last = r;
            }
            cv.notify_one();
          });
      });
    SecureChannelInfo sci2(sc2->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::None),
      MessageSecurityMode::None,
      "L2/None",
      SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
    ActivateSessionRequest asr2;
    asr2.request_header().request_handle() = 43;
    h->session->activate(3, std::move(asr2), sci2);
    h->wait_for_response();

    Outcome outcome;
    if (auto* fault = dynamic_cast<ServiceFault*>(h->lastResponse->second.get()))
      outcome.status = fault->response_header().service_result();
    else if (auto* response = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get()))
      outcome.status = response->response_header().service_result();
    outcome.identity = SessionTestAccess::on_strand(*h->session,
      [](auto& g)
      {
        const auto user = g.session_info()->user_identity();
        return user ? user->userId : std::string{};
      });
    outcome.stillOnTheFirstChannel = SessionTestAccess::on_strand(*h->session,
      [&h](auto& g)
      {
        const auto& info = g.secure_channel_info();
        return info.has_value() && info->secure_channel().lock() == h->sc;
      });
    h->shutdown();
    return outcome;
  };

  // The authenticator derives another subject from the new token.
  const auto changed = reactivateOnSecondChannel({"alice", "mallory"});
  EXPECT_EQ(changed.status.as_status(), Status::BadIdentityChangeNotSupported);
  EXPECT_EQ(changed.identity, "alice") << "the refused re-activation must not replace the Session's identity";
  EXPECT_TRUE(changed.stillOnTheFirstChannel)
    << "the refused re-activation must not move the Session to the new channel";

  // A Session activated with an IssuedToken, re-activated with a token of another kind: refused before
  // authentication (the kind check replaced an unconditional accept).
  const auto otherKind = reactivateOnSecondChannel({"alice", "alice"}, UserTokenKind::IssuedToken);
  EXPECT_EQ(otherKind.status.as_status(), Status::BadIdentityChangeNotSupported);
  EXPECT_TRUE(otherKind.stillOnTheFirstChannel);

  // control: the same subject and kind re-activates and takes the new channel.
  const auto same = reactivateOnSecondChannel({"alice", "alice"});
  EXPECT_TRUE(same.status.is_good()) << "control: the same subject re-activates";
  EXPECT_EQ(same.identity, "alice");
  EXPECT_FALSE(same.stillOnTheFirstChannel) << "control: an accepted re-activation takes the new channel";
}

// OPC 10000-4 5.6.3.2 Table 17: "The EndpointDescription specifies what UserIdentityTokens the Server
// shall accept." A re-activation over a new SecureChannel is answered by the endpoint that channel
// connects to, so its token is matched against that endpoint's UserTokenPolicies, not the ones captured
// from the CreateSession endpoint (security review SESS-7(d)). The first endpoint offers Anonymous; the
// second endpoint offers only UserName, so an Anonymous re-activation over the second channel is refused
// with Bad_IdentityTokenRejected and the Session stays on the first channel. The control re-activates the
// same way over a second channel whose endpoint offers Anonymous.
// @verifies AC-SVR-SESS-027-SESS7D-REACTIVATION-USES-THE-NEW-CHANNELS-ENDPOINT
TEST(SessionShellWiringTests, AReactivationOnANewChannelIsMatchedAgainstThatChannelsEndpointTokenPolicies)
{
  struct Outcome
  {
    StatusCode status{Status::BadInternalError};
    bool stillOnTheFirstChannel{false};
  };

  const auto reactivateOnSecondChannel = [](
                                           std::optional<std::vector<UserTokenPolicy>> secondEndpointPolicies)
  {
    auto h = make_session_harness(SecurityPolicyId::None, ByteString{});
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 42;
    h->session->activate(2, std::move(asr), {});
    h->wait_for_response();
    EXPECT_NE(dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get()), nullptr)
      << "the first (Anonymous) activation must succeed for the re-activation to be tested";
    h->clear_response();
    // The Session releases its activation claim on its strand after it has sent the response; a
    // re-activation that arrives before then is an overlapping one and is answered BadServerTooBusy.
    SessionTestAccess::strand_barrier(*h->session);

    auto sc2 = make_second_channel(h->threadPool.get_executor());
    SCTA::on_strand(*sc2,
      [&](auto& g)
      {
        g.set_response_sink(
          [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
          {
            {
              std::lock_guard<std::mutex> lock(mx);
              last = r;
            }
            cv.notify_one();
          });
      });
    SecureChannelInfo sci2(sc2->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::None),
      MessageSecurityMode::None,
      "L2/None",
      secondEndpointPolicies.has_value()
        ? *secondEndpointPolicies
        : SCTA::on_strand(
            *sc2, [](auto& g) -> std::vector<UserTokenPolicy> { return g.user_identity_tokens(); }));
    ActivateSessionRequest asr2;
    asr2.request_header().request_handle() = 43;
    h->session->activate(3, std::move(asr2), sci2);
    h->wait_for_response();

    Outcome outcome;
    if (auto* fault = dynamic_cast<ServiceFault*>(h->lastResponse->second.get()))
      outcome.status = fault->response_header().service_result();
    else if (auto* response = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get()))
      outcome.status = response->response_header().service_result();
    outcome.stillOnTheFirstChannel = SessionTestAccess::on_strand(*h->session,
      [&h](auto& g)
      {
        const auto& info = g.secure_channel_info();
        return info.has_value() && info->secure_channel().lock() == h->sc;
      });
    h->shutdown();
    return outcome;
  };

  // negative: the second endpoint does not offer Anonymous.
  const auto refused = reactivateOnSecondChannel(std::vector<UserTokenPolicy>{
    server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)});
  EXPECT_EQ(refused.status.as_status(), Status::BadIdentityTokenRejected)
    << "an Anonymous token the new channel's endpoint does not offer was accepted";
  EXPECT_TRUE(refused.stillOnTheFirstChannel)
    << "the refused re-activation must not move the Session to the new channel";

  // control: the second endpoint offers Anonymous (the channel's default token policies).
  const auto accepted = reactivateOnSecondChannel(std::nullopt);
  EXPECT_TRUE(accepted.status.is_good()) << "control: got " << to_string(accepted.status.as_status());
  EXPECT_FALSE(accepted.stillOnTheFirstChannel) << "control: an accepted re-activation takes the new channel";
}

// A response produced while the session has NO attached secure channel is buffered into
// mResponseMessages. That buffered response carries a requestId scoped to the OLD channel (Part 6:
// requestId is per-SecureChannel). On reconnect the session attaches to a NEW SecureChannel, so
// replaying the buffered response there is futile - the client drops any response whose requestId
// it never issued on the new channel (Part 4 6.7). The reconnect path therefore DISCARDS the
// buffered responses rather than replaying them; the client recovers by re-issuing requests and via
// Republish for subscriptions. This test asserts the discard: the fresh ActivateSession response
// arrives on the new channel, but the buffered response (requestId 99) is NOT replayed there, and
// the buffer is empty afterward.
// @verifies AC-SVR-SESS-027-CHANNEL-TRANSFER-ABANDONS-THE-OLD-CHANNELS-REQUESTS
// Part 4 5.6.3: once the new channel is accepted the old channel's requests are rejected, so what it
// still had in flight is released, and a new-channel request that reuses one of those ids is served on
// its merits rather than refused as a collision.
TEST(SessionShellWiringTests, ReactivatingOnAnotherChannelAbandonsTheOldChannelsRequests)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  ASSERT_NE(dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get()), nullptr);
  h->clear_response();
  // Two requests the old channel still has in flight, recorded the way request_received records them.
  SessionTestAccess::on_strand(*h->session,
    [](auto& g)
    {
      for (const uint32_t id : {300u, 301u})
      {
        g.in_flight_requests()[id] = std::make_shared<ReadRequest>();
        g.request_handles_by_request_id()[id] = id;
      }
    });
  auto ex = h->threadPool.get_executor();
  auto sc2 = make_second_channel(ex);
  SCTA::on_strand(*sc2,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lock(mx);
            last = r;
          }
          cv.notify_one();
        });
    });
  SecureChannelInfo sci2(sc2->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  ActivateSessionRequest asr2;
  asr2.request_header().request_handle() = 43;
  h->session->activate(3, std::move(asr2), sci2);
  h->wait_for_response();
  auto* resp2 = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp2, nullptr);
  ASSERT_TRUE(resp2->response_header().service_result().is_good());
  h->clear_response();
  const bool stale = SessionTestAccess::on_strand(*h->session,
    [](auto& g)
    {
      return g.in_flight_requests().contains(300u) || g.in_flight_requests().contains(301u) ||
             g.request_handles_by_request_id().contains(300u) ||
             g.request_handles_by_request_id().contains(301u);
    });
  EXPECT_FALSE(stale) << "the old channel's in-flight tracking is released at transfer";
  // The new channel reuses id 300: served on its merits (an empty Read is Bad_NothingToDo), never
  // refused as RequestIdInFlight.
  auto reuse = std::make_shared<ReadRequest>();
  reuse->request_header().request_handle() = 7;
  Request request = std::make_pair(uint32_t{300}, std::static_pointer_cast<Structure>(reuse));
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.request_received(std::move(request)); });
  h->wait_for_response();
  ASSERT_TRUE(h->lastResponse.has_value());
  if (auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get()))
  {
    EXPECT_NE(sf->response_header().service_result(), Status::BadServerTooBusy)
      << "a reused old-channel id is not a collision after transfer";
  }
  h->shutdown();
}

TEST(SessionShellWiringTests, BufferedResponsesDiscardedOnChannelReconnect)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // First activate on the original channel and wait for the ActivateSession response.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();
  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  h->clear_response();

  // Make the session channelless, then produce a real response through the production
  // response path. With no attached channel it is buffered into mResponseMessages rather
  // than sent. Assert it actually landed in the buffer.
  constexpr uint32_t bufferedRequestId = 99;
  SessionTestAccess::on_strand(*h->session,
    [&](auto& g)
    {
      g.secure_channel_info().reset();
      g.response_received(std::make_pair(bufferedRequestId, std::make_shared<ReadResponse>()));
    });

  SessionTestAccess::on_strand(*h->session,
    [&](auto& g)
    { EXPECT_TRUE(g.pop_queued_response().has_value()) << "response must buffer while channelless"; });

  // Re-buffer the same response (the pop above consumed it) so the reconnect path has a buffered
  // response to act on. Under the old (drain) behaviour this would be replayed onto sc2; under the
  // discard behaviour it must not be.
  SessionTestAccess::on_strand(*h->session,
    [&](auto& g)
    { g.response_received(std::make_pair(bufferedRequestId, std::make_shared<ReadResponse>())); });

  // Reconnect on a second channel. Wire sc2's response sink to record EVERY response it observes so
  // we can assert (a) the fresh ActivateSession response arrives - signalling reconnect completion -
  // and (b) the buffered response (requestId 99) is never replayed there.
  auto ex = h->threadPool.get_executor();
  auto sc2 = make_second_channel(ex);

  std::mutex sinkMutex;
  std::condition_variable sinkCv;
  std::vector<uint32_t> observedRequestIds;
  bool activateResponseSeen = false;
  SCTA::on_strand(*sc2,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(sinkMutex);
          observedRequestIds.push_back(r.first);
          // Under the old drain behaviour the buffered response drains BEFORE the fresh
          // ActivateSession response in the same flow, and both traverse sc2's send path in order.
          // So by the time the ActivateSession response is seen, a replayed requestId 99 would
          // already be recorded - making the discard assertion below deterministic and falsifiable.
          if (dynamic_cast<ActivateSessionResponse*>(r.second.get()) != nullptr)
          {
            activateResponseSeen = true;
          }
          sinkCv.notify_one();
        });
    });

  SecureChannelInfo sci2(sc2->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  ActivateSessionRequest asr2;
  asr2.request_header().request_handle() = 43;
  h->session->activate(3, std::move(asr2), sci2);

  // Wait for the fresh ActivateSession response to arrive on sc2 (reconnect completion).
  {
    std::unique_lock<std::mutex> lk(sinkMutex);
    ASSERT_TRUE(sinkCv.wait_for(lk, 500ms, [&]() { return activateResponseSeen; }))
      << "fresh ActivateSession response never arrived on the reconnected channel";
  }

  // The buffered response must have been DISCARDED, not replayed: sc2 must never have seen a
  // response carrying the old-channel requestId 99.
  {
    std::lock_guard<std::mutex> lk(sinkMutex);
    EXPECT_EQ(std::count(observedRequestIds.begin(), observedRequestIds.end(), bufferedRequestId), 0)
      << "buffered response (requestId 99) must be discarded on reconnect, not replayed onto the new "
         "channel (its requestId is scoped to the old SecureChannel)";
  }

  // The buffer must be empty after the reconnect discard.
  SessionTestAccess::on_strand(*h->session,
    [&](auto& g)
    { EXPECT_FALSE(g.pop_queued_response().has_value()) << "buffer must be empty after reconnect discard"; });

  h->shutdown();
}

// A refusal belongs to the requestId space of the new channel that carried ActivateSession. Sending
// it on the Session's still-current old channel makes the requester time out and feeds an unknown
// requestId to the old client.
// @relation(AC-SVR-SESS-027-REACTIVATE-CONTINUITY, scope=function)
TEST(SessionShellWiringTests, ReactivateOnDifferentChannelWithDifferentCertRejected)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // First activate on same channel.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  h->session->activate(2, std::move(asr), {});

  h->wait_for_response();
  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  h->clear_response();

  // Reconnect on second channel with DIFFERENT client cert.
  auto ex = h->threadPool.get_executor();
  auto sc2 = make_second_channel(ex);

  auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
  Crypto::Name subject;
  subject.commonName = "Different Client";
  auto certResult = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, UtcTime{2050, 1, 1, 0, 0, 0}, {}, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(certResult.is_good());
  auto [keys, differentCert] = std::move(certResult).value();

  SecureChannelInfo sci2(sc2->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*sc2, [](auto& g) -> const auto& { return g.user_identity_tokens(); }),
    differentCert);

  std::vector<Response> oldChannelResponses;
  std::vector<Response> newChannelResponses;
  SCTA::on_strand(*h->sc,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { oldChannelResponses.push_back(response); }); });
  SCTA::on_strand(*sc2,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { newChannelResponses.push_back(response); }); });

  ActivateSessionRequest asr2;
  asr2.request_header().request_handle() = 43;
  h->session->activate(3, std::move(asr2), sci2);

  SessionTestAccess::strand_barrier(*h->session);
  SCTA::strand_barrier(*h->sc);
  SCTA::strand_barrier(*sc2);

  EXPECT_TRUE(oldChannelResponses.empty())
    << "the old channel did not issue requestId 3 and must receive no continuity fault";
  ASSERT_EQ(newChannelResponses.size(), 1u)
    << "the channel that issued ActivateSession must receive its refusal without timing out";
  EXPECT_EQ(std::get<uint32_t>(newChannelResponses.front()), 3u);
  auto* sf = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(newChannelResponses.front()).get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSecureChannelIdInvalid);

  h->shutdown();
}

// ==================================================================================
// AccessIdentity lifecycle across ActivateSession.
// ==================================================================================

namespace
{

/// Authenticator that returns a configurable user identity.
/// Call set_user() between activations to change the returned identity.
class ConfigurableAuthenticator final : public UserAuthenticator
{
public:
  explicit ConfigurableAuthenticator(std::string userId, std::string displayName = {},
    ua::server::UserTokenKind kind = ua::server::UserTokenKind::Anonymous)
  {
    set_user(std::move(userId), std::move(displayName), kind);
  }

  void authenticate_async(AuthnRequest /*req*/, AuthnComplete completion) noexcept override
  {
    UserIdentity user;
    {
      std::lock_guard<std::mutex> lk(mMutex);
      user = mUser;
    }
    completion(make_authn_success(std::move(user)));
  }

  void set_user(std::string userId, std::string displayName = {},
    ua::server::UserTokenKind kind = ua::server::UserTokenKind::Anonymous)
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mUser.userId = std::move(userId);
    mUser.displayName = displayName.empty() ? mUser.userId : std::move(displayName);
    mUser.kind = kind;
  }

private:
  mutable std::mutex mMutex;
  ua::server::UserIdentity mUser;
};

/// Extended harness that allows configuring authentication and Role hooks.
struct IdentityChangedHarness
{
  boost::asio::thread_pool threadPool{2};
  shared_ptr<SecureChannelDependencies> scDeps;
  shared_ptr<FakeSessionDeps> sessDeps;
  shared_ptr<SecureChannel> sc;
  shared_ptr<Session> session;

  std::mutex mutex;
  std::condition_variable cv;
  optional<Response> lastResponse;

  void wait_for_response()
  {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [&]() { return lastResponse.has_value(); });
  }

  void clear_response()
  {
    std::lock_guard<std::mutex> lk(mutex);
    lastResponse.reset();
  }

  void shutdown()
  {
    if (session)
      session->terminate_for_shutdown();
    if (sc)
      sc->close();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
};

std::unique_ptr<IdentityChangedHarness> make_identity_harness(ServerComponents hooks)
{
  auto h = std::make_unique<IdentityChangedHarness>();
  auto ex = h->threadPool.get_executor();

  class ScDeps : public SecureChannelDependencies
  {
  public:
    explicit ScDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  h->scDeps = std::make_shared<ScDeps>(ex);
  h->sc = SecureChannel::create(
    h->scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*h->sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lock(mx);
            last = r;
          }
          cv.notify_one();
        });
    });

  h->sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(h->sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  CreateSessionRequest csr;
  h->session = Session::create(h->sessDeps, sci, 1, std::move(csr));

  SessionTestAccess::strand_barrier(*h->session);

  return h;
}

}  // namespace

TEST(SessionIdentityChanged, ActivateSessionCommitsAccessIdentity)
{
  auto authenticator = std::make_shared<ConfigurableAuthenticator>("alice", "Alice");

  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_identity_harness(hooks);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 100;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  SessionTestAccess::strand_barrier(*h->session);
  const auto identity = SessionTestAccess::access_identity(*h->session);
  ASSERT_NE(identity, nullptr);
  EXPECT_EQ(identity->user().userId, "alice");

  h->shutdown();
}

TEST(SessionIdentityChanged, ServiceRequestsReuseCommittedAccessIdentity)
{
  auto authenticator = std::make_shared<ConfigurableAuthenticator>("alice", "Alice");

  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_identity_harness(hooks);

  {
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 100;
    h->session->activate(2, std::move(asr), {});
    h->wait_for_response();
    h->clear_response();
  }
  const auto committedIdentity = SessionTestAccess::access_identity(*h->session);
  ASSERT_NE(committedIdentity, nullptr);

  {
    auto readReq = std::make_shared<ReadRequest>();
    readReq->request_header().request_handle() = 200;
    SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, readReq); });
    h->wait_for_response();
    h->clear_response();
  }

  {
    auto readReq = std::make_shared<ReadRequest>();
    readReq->request_header().request_handle() = 201;
    SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(4, readReq); });
    h->wait_for_response();
  }

  SessionTestAccess::strand_barrier(*h->session);
  EXPECT_EQ(SessionTestAccess::access_identity(*h->session), committedIdentity)
    << "service requests must reuse the immutable identity committed at activation";

  h->shutdown();
}

// @relation(AC-SVR-SESS-031-REEVALUATE-ON-IDENTITY-CHANGE, scope=function)
TEST(SessionIdentityChanged, ReactivationReplacesAccessIdentity)
{
  auto authenticator = std::make_shared<ConfigurableAuthenticator>("alice", "Alice");

  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_identity_harness(hooks);

  {
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 100;
    h->session->activate(2, std::move(asr), {});
    h->wait_for_response();
    h->clear_response();
    // The Session releases its activation claim on its strand after it has sent the response; a
    // re-activation that arrives before then is an overlapping one and is answered BadServerTooBusy.
    SessionTestAccess::strand_barrier(*h->session);
  }
  const auto aliceIdentity = SessionTestAccess::access_identity(*h->session);
  ASSERT_NE(aliceIdentity, nullptr);
  ASSERT_EQ(aliceIdentity->user().userId, "alice");

  authenticator->set_user("bob", "Bob", ua::server::UserTokenKind::UserName);
  {
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 101;
    h->session->activate(3, std::move(asr), {});
    h->wait_for_response();
    SessionTestAccess::strand_barrier(*h->session);
  }

  const auto bobIdentity = SessionTestAccess::access_identity(*h->session);
  ASSERT_NE(bobIdentity, nullptr);
  EXPECT_NE(bobIdentity, aliceIdentity);
  EXPECT_NE(bobIdentity->key(), aliceIdentity->key());
  EXPECT_EQ(bobIdentity->user().userId, "bob");

  h->shutdown();
}

// @relation(AC-SVR-SESS-031-REEVALUATE-ON-IDENTITY-CHANGE, scope=function)
TEST(SessionIdentityChanged, NonDenialReauthorizationFailureClosesSessionAndPreservesDetail)
{
  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();
  auto h = make_identity_harness(std::move(hooks));

  ActivateSessionRequest activateRequest;
  activateRequest.request_header().request_handle() = 100;
  h->session->activate(2, std::move(activateRequest), {});
  h->wait_for_response();
  auto* activateResponse = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(activateResponse, nullptr);
  ASSERT_TRUE(activateResponse->response_header().service_result().is_good());
  h->clear_response();

  auto createSubscriptionRequest = std::make_shared<CreateSubscriptionRequest>();
  createSubscriptionRequest->request_header().request_handle() = 101;
  SessionTestAccess::on_strand(
    *h->session, [&](auto& guarded) { guarded.inject_decoded_request(3, createSubscriptionRequest); });
  h->wait_for_response();
  h->clear_response();

  auto subscription = Subscription::create(
    77, 1000, 100, 3, 0, true, 0, h->threadPool.get_executor(), [](IntegerId) {}, [](IntegerId) {});
  auto pipeline = SessionTestAccess::subscriptions_pipeline(*h->session);
  ASSERT_NE(pipeline, nullptr);
  SubscriptionsPipelineTestAccess::on_strand(
    *pipeline, [&](auto& guarded) { guarded.subscriptions().emplace(77, subscription); });
  std::shared_ptr<const ErrorDetail> innerDetail =
    ErrorDetail::build("NestedSessionReauthorizationSentinel", "nested sentinel", "SessionIdentityChanged");
  std::shared_ptr<const ErrorDetail> sentinelDetail =
    ErrorDetail::build("SessionReauthorizationSentinel", "mandatory walk failed", "SessionIdentityChanged")
      .cause(innerDetail);
  std::optional<VoidResult> observedFailure;
  std::atomic<size_t> callbackCalls{0};

  SessionTestAccess::on_strand(*h->session,
    [&](auto&)
    {
      SessionTestAccess::inject_monitored_item_reauthorization_failure(*h->session,
        VoidResult{StatusCode{Status::BadInternalError}, sentinelDetail},
        [&](VoidResult result)
        {
          ++callbackCalls;
          observedFailure.emplace(std::move(result));
        });
    });
  SubscriptionsPipelineTestAccess::on_strand(*pipeline,
    [](auto& guarded)
    { EXPECT_TRUE(guarded.subscriptions().empty()) << "fail-closed teardown must delete subscriptions"; });

  SessionTestAccess::strand_barrier(*h->session);

  ASSERT_TRUE(observedFailure.has_value());
  EXPECT_EQ(observedFailure->status_code(), StatusCode{Status::BadInternalError});
  ASSERT_EQ(observedFailure->shared_detail(), sentinelDetail);
  ASSERT_NE(observedFailure->shared_detail()->cause, nullptr);
  EXPECT_EQ(observedFailure->shared_detail()->cause->code, "NestedSessionReauthorizationSentinel");
  EXPECT_EQ(callbackCalls.load(), 1u);
  EXPECT_FALSE(h->session->is_activated());
  SessionTestAccess::on_strand(*h->session,
    [](auto& guarded)
    {
      EXPECT_EQ(guarded.session_state(), SessionTestAccess::State::Closed);
      EXPECT_EQ(guarded.state().load(std::memory_order_acquire), SessionTestAccess::State::Closed);
    });

  h->shutdown();
}

// ==================================================================================
// S5: Per-session request backpressure
// ==================================================================================

// S5-1: Default maxRequestsPerSession is 100.
TEST(SessionBackpressure, DefaultMaxRequestsPerSessionIs100)
{
  ua::server::ServerConfig cfg;
  ASSERT_TRUE(cfg.maxRequestsPerSession.has_value());
  EXPECT_EQ(*cfg.maxRequestsPerSession, 100u);
}

// S5-2: When in-flight requests reach the limit, new non-Publish requests are rejected
// with BadServerTooBusy (service-level backpressure - too many in-flight requests, a
// transient load condition; distinct from BadTooManyOperations which is too many
// operations within a single request).
TEST(SessionBackpressure, RejectsWhenInFlightLimitReached)
{
  auto authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_identity_harness(hooks);

  // First activate the session.
  {
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 100;
    h->session->activate(2, std::move(asr), {});
    h->wait_for_response();
    auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
    ASSERT_NE(resp, nullptr);
    EXPECT_TRUE(resp->response_header().service_result().is_good());
    h->clear_response();
  }

  // Artificially populate in-flight requests to the limit (100).
  // We do this on the strand to avoid races with the session's internal state.
  {
    SessionTestAccess::on_strand(*h->session,
      [](auto& g)
      {
        for (uint32_t i = 10000; i < 10100; ++i)
        {
          g.in_flight_requests()[i] = std::make_shared<ReadRequest>();
        }
      });
  }

  // Now send a service request on the strand via request_received().
  {
    std::promise<void> sent;
    auto sentFut = sent.get_future();
    auto readReq = std::make_shared<ReadRequest>();
    readReq->request_header().request_handle() = 999;
    Request request = std::make_pair(uint32_t{50000}, std::static_pointer_cast<Structure>(readReq));
    SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.request_received(std::move(request)); });
  }

  // The response should be a ServiceFault with BadServerTooBusy.
  h->wait_for_response();
  auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadServerTooBusy);

  h->shutdown();
}

// ===================================================================================
// Policy validation and anonymous auto-accept tests.
// ===================================================================================

// @relation(SVR-SESS-037, scope=function)
TEST(SessionShellWiringTests, PolicyValidation_NoAuthenticatorRejectsAnonymous)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // No authenticator - secure-by-default rejects all tokens.

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 100;
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadUserAccessDenied);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-SESS-037, scope=function)
TEST(SessionShellWiringTests, PolicyValidation_AnonymousRejectedWhenNotAdvertised)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Only UserName advertised - anonymous should be rejected.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(
        ex, "L/None", {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::None)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // No authenticator.

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 101;
  // Default token is anonymous (no user_identity_token set).
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadIdentityTokenRejected);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-SESS-037, scope=function)
TEST(SessionShellWiringTests, PolicyValidation_NonAnonymousRejectedNoAuthenticator)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Endpoint advertises UserName with an explicit token encryption policy - valid even on None channel.
  // Token type matches, but no authenticator exists.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // No authenticator.

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 102;
  // Present a UserName token with policy_id matching the advertised UserName policy.
  auto token = std::make_unique<UserNameIdentityToken>();
  token->user_name() = "testuser";
  token->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(token);
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadUserAccessDenied);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-SESS-037, scope=function)
TEST(SessionShellWiringTests, PolicyValidation_TokenTypeMismatch)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Only Anonymous advertised - UserName token should be rejected before reaching authenticator.
  SecureChannelTestAccess::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // Authenticator is present, but should never be reached.
  auto authenticator = std::make_shared<AllowAnonymousAuthenticator>();
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 103;
  // Present a UserName token whose policyId names the advertised Anonymous policy: the policyId
  // exists but for a different token type. The token is well-formed and references a real policy, so
  // the server rejects it (BadIdentityTokenRejected) rather than flagging it invalid (which is
  // reserved for a policyId that matches nothing - see PolicyValidation_UnknownPolicyId... below).
  auto token = std::make_unique<UserNameIdentityToken>();
  token->user_name() = "testuser";
  token->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(token);
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadIdentityTokenRejected);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
// Minimal SecureChannelDependencies for the user-token mapping mirrors below. crypto() returns null
// because these paths fault (invalid / rejected token) before any crypto is used.
class PolicyMirrorSecureDeps : public SecureChannelDependencies
{
public:
  explicit PolicyMirrorSecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
  ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
  ::ua::server::ServerConfig mServerCfg;
};
}  // namespace

// A non-anonymous token whose policyId names NO advertised user-token policy references a policy that
// does not exist -> the token is not valid: Bad_IdentityTokenInvalid (OPC 10000-4 Table 182), distinct
// from a well-formed token the server rejects. Contrast PolicyValidation_TokenTypeMismatch above
// (policyId found, wrong type -> Rejected).
// Covers SVR-SEC-UserToken (CTT Security User Name Password/009)
TEST(SessionShellWiringTests, PolicyValidation_UnknownPolicyId_ReturnsIdentityTokenInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto scDeps = std::make_shared<PolicyMirrorSecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Advertise a UserName policy so the token type is supported; the presented policyId still matches
  // nothing.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 201;
  auto token = std::make_unique<UserNameIdentityToken>();
  token->user_name() = "user";
  token->policy_id() = "no-such-policy-id";  // matches no advertised policy
  asr.user_identity_token() = std::move(token);
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadIdentityTokenInvalid);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A UserNameIdentityToken with an empty userName is not a valid token -> Bad_IdentityTokenInvalid,
// decided before the authenticator so it never surfaces as an access-control decision.
// Covers SVR-SEC-UserToken (CTT Security User Name Password/003)
TEST(SessionShellWiringTests, UserNameToken_EmptyUserName_ReturnsIdentityTokenInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto scDeps = std::make_shared<PolicyMirrorSecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Advertise a UserName policy bound to an encrypting security policy so the runtime token guard
  // (no-cleartext-secrets) passes on this None channel and the flow reaches token parsing.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // Authenticator present but must never be reached (empty username is rejected before it).
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 202;
  auto token = std::make_unique<UserNameIdentityToken>();
  token->user_name() = "";  // empty username -> invalid token
  token->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(token);
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadIdentityTokenInvalid);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

class RecordingAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    called.store(true, std::memory_order_relaxed);
    completion(
      make_authn_success(UserIdentity{.userId = "anonymous", .displayName = "Anonymous", .claims = {}}));
  }

  std::atomic<bool> called{false};
};

}  // namespace

// @relation(SVR-SESS-037, scope=function)
TEST(SessionShellWiringTests, PolicyValidation_MatchDelegatesToAuthenticator)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  class DummySecureDeps : public SecureChannelDependencies
  {
  public:
    explicit DummySecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
    ::ua::server::ServerConfig mServerCfg;
  };

  auto scDeps = std::make_shared<DummySecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None"); });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  auto authenticator = std::make_shared<RecordingAuthenticator>();
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<FakeSessionDeps>(ex, hooks);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 104;
  // Default anonymous token - matches the advertised Anonymous policy.
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return last.has_value(); }));
  auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());
  // Verify the authenticator was actually called (not bypassed via auto-accept).
  EXPECT_TRUE(authenticator->called.load(std::memory_order_relaxed));

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Test 1: Service request before activation is rejected for non-discovery
// ---------------------------------------------------------------------------
// @relation(SVR-SESS-004, SVR-SESS-024, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, ServiceRequestBeforeActivationIsRejectedForNonDiscovery)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // Session is created but NOT activated. Inject a ReadRequest.
  auto readReq = std::make_shared<ReadRequest>();
  readReq->request_header().request_handle() = 10;
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, readReq); });

  h->wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionNotActivated);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Test 2: Discovery service request before activation is allowed
// ---------------------------------------------------------------------------
// @relation(SVR-SESS-004, scope=function)
TEST(SessionShellWiringTests, ServiceRequestBeforeActivationIsAllowedForDiscovery)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // Session is created but NOT activated. Inject a GetEndpointsRequest (discovery).
  auto getEndpointsReq = std::make_shared<GetEndpointsRequest>();
  getEndpointsReq->request_header().request_handle() = 11;
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(4, getEndpointsReq); });

  h->wait_for_response();

  // The discovery request must pass through the activation gate (not be rejected with
  // BadSessionNotActivated). It will fail downstream because FakeSessionDeps has null
  // discovery_dependencies(), but the error must NOT be the activation-gate error.
  // This is a meaningful assertion because the paired negative test
  // (ServiceRequestBeforeActivationIsRejectedForNonDiscovery) proves the gate blocks
  // non-discovery requests with BadSessionNotActivated.
  auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
  if (sf)
  {
    EXPECT_NE(sf->response_header().service_result(), Status::BadSessionNotActivated)
      << "Discovery request must not be blocked by the activation gate";
  }
  // If it's not a ServiceFault at all (i.e., a real GetEndpointsResponse), the request
  // passed the activation gate, which is the behavior under test.

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Test 3: Session enters Closed state after close and is_activated returns false
// ---------------------------------------------------------------------------
// Note: In the old pure-logic test, we verified that a ServiceFault with
// BadSessionIdInvalid was emitted. In the real implementation, after close the
// session is removed from the secure channel, so service requests can never
// reach the closed session. We verify the close state transition instead.
// @relation(SVR-SESS-006, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, SessionIsClosedAfterCloseAndNotActivated)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // Activate the session first.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 20;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();

  EXPECT_TRUE(h->session->is_activated());

  // Close the session.
  CloseSessionRequest closeReq;
  closeReq.request_header().request_handle() = 21;
  h->session->close(3, std::move(closeReq));
  h->wait_for_response();

  // After close, is_activated returns false - the session rejects all new work.
  EXPECT_FALSE(h->session->is_activated());

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Test 4: Cancel request before activation returns BadSessionNotActivated
// ---------------------------------------------------------------------------
// @relation(SVR-SESS-041, SVR-SESS-043, scope=function)
TEST(SessionShellWiringTests, CancelBeforeActivationIsBadSessionNotActivated)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // Session is created but NOT activated. Inject a CancelRequest.
  auto cancelReq = std::make_shared<CancelRequest>();
  cancelReq->request_header().request_handle() = 30;
  cancelReq->request_handle() = 99;
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(5, cancelReq); });

  h->wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionNotActivated);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Test 5: Cancel when activated emits CancelResponse
// ---------------------------------------------------------------------------
// @relation(SVR-SESS-041, scope=function)
TEST(SessionShellWiringTests, CancelWhenActivatedEmitsCancelResponse)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // Activate first.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 40;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();

  auto cancelReq = std::make_shared<CancelRequest>();
  cancelReq->request_header().request_handle() = 41;
  cancelReq->request_handle() = 12345;
  SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, cancelReq); });

  h->wait_for_response();

  auto* resp = dynamic_cast<CancelResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());
  // No outstanding ops to cancel, so cancel_count should be 0.
  EXPECT_EQ(resp->cancel_count(), 0u);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Test 6: Reactivate on same channel proceeds
// ---------------------------------------------------------------------------
// @relation(SVR-SESS-027, scope=function)
TEST(SessionShellWiringTests, ReactivateOnSameChannelProceeds)
{
  auto h = make_session_harness(SecurityPolicyId::None, ByteString{});

  // First activation.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 50;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_response();
  h->clear_response();
  // The Session releases its activation claim on its strand after it has sent the response; a
  // re-activation that arrives before then is an overlapping one and is answered BadServerTooBusy.
  SessionTestAccess::strand_barrier(*h->session);

  // Reactivate on the same channel.
  ActivateSessionRequest asr2;
  asr2.request_header().request_handle() = 51;
  h->session->activate(3, std::move(asr2), {});
  h->wait_for_response();

  auto* resp = dynamic_cast<ActivateSessionResponse*>(h->lastResponse->second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Test 7: CreateSession accepts minimum-length nonce on authenticated policy
// ---------------------------------------------------------------------------
// @relation(SVR-SESS-009, scope=function)
TEST(SessionShellWiringTests, CreateSessionAcceptsMinimumLengthNonceOnAuthenticatedPolicy)
{
  // 32-byte nonce is the minimum required for authenticated policies.
  // On an authenticated channel the nonce check happens before crypto operations.
  // With FakeSessionDeps (null crypto), the session can't generate a server signature
  // so create_internal may fail after the nonce check. The key assertion is that it does
  // NOT fail with BadNonceInvalid/BadSecurityChecksFailed (which would mean the nonce was
  // rejected). We use a short wait - if no response arrives, the nonce was accepted and
  // the failure is downstream (crypto). If a response arrives, it must not be a nonce error.
  ByteString nonce(32, uint8_t{0x42});
  auto h = make_session_harness(SecurityPolicyId::Basic256Sha256, std::move(nonce));

  // Drain both strands so the assertion depends on completed work, not scheduler latency.
  SessionTestAccess::strand_barrier(*h->session);
  SCTA::on_strand(*h->sc, [](auto&) {});

  if (h->lastResponse.has_value())
  {
    if (auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get()))
    {
      EXPECT_NE(sf->response_header().service_result(), Status::BadNonceInvalid);
      EXPECT_NE(sf->response_header().service_result(), Status::BadSecurityChecksFailed);
    }
  }
  // If no response arrived, the nonce was accepted (crypto failure happens later).

  h->shutdown();
}

// OPC 10000-4 1.05.07 5.7.2: the clientNonce "shall have a length between 32 and 128 bytes inclusive. The
// Server shall check the length." One byte over the ceiling is refused like one under the floor.
// @relation(AC-SVR-SESS-023-CLIENT-NONCE-OVER-128-IS-REFUSED, scope=function)
TEST(SessionShellWiringTests, CreateSessionRejectsANonceLongerThan128Bytes)
{
  ByteString longNonce(129, uint8_t{0xBB});
  auto h = make_session_harness(SecurityPolicyId::Basic256Sha256, longNonce);

  // The refusal comes before any crypto, so draining both strands bounds the wait: a server that accepts
  // the nonce sends nothing here (the harness has no crypto) and the test fails instead of hanging.
  SessionTestAccess::strand_barrier(*h->session);
  SCTA::on_strand(*h->sc, [](auto&) {});

  std::optional<StatusCode> serviceResult;
  {
    const std::lock_guard<std::mutex> lock(h->mutex);
    ASSERT_TRUE(h->lastResponse.has_value()) << "a 129-byte clientNonce was not refused";
    auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
    ASSERT_NE(sf, nullptr);
    serviceResult = sf->response_header().service_result();
  }
  EXPECT_EQ(*serviceResult, Status::BadNonceInvalid);

  h->shutdown();
}

// The ceiling holds on a None channel too: OPC 10000-4 1.05.07 5.7.2 does not exempt it.
// @relation(AC-SVR-SESS-023-CLIENT-NONCE-OVER-128-IS-REFUSED, scope=function)
TEST(SessionShellWiringTests, CreateSessionRejectsANonceLongerThan128BytesOnANoneChannel)
{
  ByteString longNonce(129, uint8_t{0xBB});
  auto h = make_session_harness(SecurityPolicyId::None, longNonce);

  // A None Session is created without a visible response (the harness has no discovery dependencies), so
  // draining both strands bounds the wait: only a refusal is observed.
  SessionTestAccess::strand_barrier(*h->session);
  SCTA::on_strand(*h->sc, [](auto&) {});

  std::optional<StatusCode> serviceResult;
  {
    const std::lock_guard<std::mutex> lock(h->mutex);
    ASSERT_TRUE(h->lastResponse.has_value()) << "a 129-byte clientNonce on a None channel was not refused";
    auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get());
    ASSERT_NE(sf, nullptr);
    serviceResult = sf->response_header().service_result();
  }
  EXPECT_EQ(*serviceResult, Status::BadNonceInvalid);

  h->shutdown();
}

// The control: a 128-byte nonce is within the range. As for the 32-byte floor (Test 7), the harness has no
// crypto, so the assertion is that no response refuses the nonce.
// @relation(AC-SVR-SESS-023-CLIENT-NONCE-OVER-128-IS-REFUSED, scope=function)
TEST(SessionShellWiringTests, CreateSessionAcceptsA128ByteNonce)
{
  ByteString nonce(128, uint8_t{0x42});
  auto h = make_session_harness(SecurityPolicyId::Basic256Sha256, std::move(nonce));

  SessionTestAccess::strand_barrier(*h->session);
  SCTA::on_strand(*h->sc, [](auto&) {});

  if (h->lastResponse.has_value())
  {
    if (auto* sf = dynamic_cast<ServiceFault*>(h->lastResponse->second.get()))
      EXPECT_NE(sf->response_header().service_result(), Status::BadNonceInvalid);
  }

  h->shutdown();
}

// ===================================================================================
// Endpoint user-token policy completeness, and X509 proof-of-possession.
// ===================================================================================

namespace
{

/// Which user identity token an activation presents. `AnonymousDefault` leaves
/// `userIdentityToken` null, which is the on-the-wire form of an anonymous activation.
enum class PresentedTokenType
{
  AnonymousDefault,
  UserName,
  Certificate
};

/// What the server did with one ActivateSession.
struct ActivationOutcome
{
  optional<StatusCode> serviceResult;
  bool activated{false};
};

/// Returns the advertised policy the presented token should echo: the policy for its own token
/// type when the endpoint publishes one, otherwise the first advertised policy. Echoing a
/// policyId the endpoint really advertises is deliberate - it leaves the token *type* as the only
/// thing that can make the server refuse, rather than an unresolvable policyId.
///
/// @pre `published` is non-empty.
const UserTokenPolicy& policy_for_presented_type(
  const std::vector<UserTokenPolicy>& published, UserTokenType presented)
{
  for (const auto& policy : published)
  {
    if (policy.token_type() == presented)
      return policy;
  }
  return published.front();
}

/// Creates a session on an endpoint that publishes exactly `published`, activates it once with
/// `presented`, and reports what the server did. The authenticator accepts every identity handed
/// to it, so any refusal observed here can only have come from the endpoint's own token gate.
ActivationOutcome activate_against_published_policies(
  std::vector<UserTokenPolicy> published, PresentedTokenType presented)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto scDeps = std::make_shared<PolicyMirrorSecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(
    *sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/None", published); });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  // A REAL crypto provider, unlike every refusal-path helper above. Two of the three directions
  // this helper drives end in an ACCEPTED token, and the accepted path generates the response's
  // next server nonce through `deps->crypto()->get_entropy_async(...)`, dereferenced with no null
  // check -- so the default null provider segfaults instead of failing an assertion.
  auto sessDeps = std::make_shared<FakeSessionDeps>(
    ex, hooks, create_default_crypto([]() { return ua::SecureString{""}; }));
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 300;
  if (presented == PresentedTokenType::UserName)
  {
    auto token = std::make_unique<UserNameIdentityToken>();
    token->user_name() = "testuser";
    token->policy_id() = policy_for_presented_type(published, UserTokenType::UserName).policy_id();
    asr.user_identity_token() = std::move(token);
  }
  else if (presented == PresentedTokenType::Certificate)
  {
    auto token = std::make_unique<X509IdentityToken>();
    token->certificate_data() = ByteString{uint8_t{1}, uint8_t{2}};
    token->policy_id() = policy_for_presented_type(published, UserTokenType::Certificate).policy_id();
    asr.user_identity_token() = std::move(token);
  }
  session->activate(2, std::move(asr), {});

  ActivationOutcome outcome;
  {
    std::unique_lock<std::mutex> lk(mx);
    if (cv.wait_for(lk, 2000ms, [&]() { return last.has_value(); }))
    {
      if (auto* sf = dynamic_cast<ServiceFault*>(last->second.get()))
        outcome.serviceResult = sf->response_header().service_result();
      else if (auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get()))
        outcome.serviceResult = resp->response_header().service_result();
    }
  }
  outcome.activated = session->is_activated();

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
  return outcome;
}

}  // namespace

// Part 4 5.4.4.1: "Each UserIdentityToken allowed by an Endpoint shall have a UserTokenPolicy
// specified in the EndpointDescription." The published `userIdentityTokens` array and the set of
// token types ActivateSession will accept must be the same set, in both directions. A plausible
// implementation keeps the advertisement and the acceptance test in two different places, so it
// drifts one way or the other: publishing a policy it never honours (clients are sent to fail on an
// advertised path), or honouring a type it never published (an undeclared authentication path).
// @verifies AC-SVR-IDENT-002-POLICY-PER-TOKEN
TEST(SessionShellWiringTests, EndpointAcceptsExactlyThePublishedUserTokenTypes)
{
  std::vector<UserTokenPolicy> published{
    server::create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None),
    server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)};

  // This vector is the endpoint's EndpointDescription.userIdentityTokens array. Pin what it holds
  // so neither direction below can pass against an empty or unexpected published set.
  ASSERT_EQ(published.size(), 2u);
  ASSERT_EQ(published[0].token_type(), UserTokenType::Anonymous);
  ASSERT_EQ(published[1].token_type(), UserTokenType::UserName);

  // Direction 1: nothing published is refused. Every advertised type activates.
  {
    auto anonymous = activate_against_published_policies(published, PresentedTokenType::AnonymousDefault);
    ASSERT_TRUE(anonymous.serviceResult.has_value()) << "no response to the anonymous activation";
    EXPECT_TRUE(anonymous.serviceResult->is_good())
      << "Anonymous is published by this endpoint, so it must be accepted at ActivateSession";
    EXPECT_TRUE(anonymous.activated) << "an accepted token must leave the session activated";
  }
  {
    auto userName = activate_against_published_policies(published, PresentedTokenType::UserName);
    ASSERT_TRUE(userName.serviceResult.has_value()) << "no response to the UserName activation";
    EXPECT_TRUE(userName.serviceResult->is_good())
      << "UserName is published by this endpoint, so it must be accepted at ActivateSession";
    EXPECT_TRUE(userName.activated) << "an accepted token must leave the session activated";
  }

  // Direction 2: nothing accepted is unpublished. Certificate is absent from the published set, so
  // it must be refused even though the presented token echoes a policyId the endpoint really
  // advertises - the token type alone is what is missing.
  {
    auto certificate = activate_against_published_policies(published, PresentedTokenType::Certificate);
    ASSERT_TRUE(certificate.serviceResult.has_value()) << "no response to the Certificate activation";
    EXPECT_TRUE(certificate.serviceResult->is_bad())
      << "Certificate is not published by this endpoint, so it must not be accepted";
    EXPECT_FALSE(certificate.activated) << "a refused token must not leave the session activated";
  }
}

namespace
{

/// Session dependencies with a real crypto provider. `FakeSessionDeps` returns a null `crypto()`,
/// which makes the server classify every X509IdentityToken as `UserTokenKind::Unsupported` before
/// the user-token signature is ever considered - so the X509 rules below cannot be reached through
/// it. Everything else matches `FakeSessionDeps`.
class CryptoSessionDeps final : public SessionDependencies
{
public:
  CryptoSessionDeps(boost::asio::any_io_executor ex, ServerComponents hooks, shared_ptr<const Crypto> crypto)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto))
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
    return mCrypto;
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
    throw UaException{
      Status::BadInternalError, make_error_detail("TestError", "Not used in this test", "Test")};
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

  /// The user-token store an X509 user certificate is validated against (null: every certificate refused).
  void set_user_token_certificate_store(shared_ptr<CertificateStore> store)
  {
    mUserTokenCertificateStore = std::move(store);
  }

  shared_ptr<CertificateStore> user_token_certificate_store() override
  {
    return mUserTokenCertificateStore;
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

private:
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  boost::asio::any_io_executor mExecutor;
  shared_ptr<CertificateStore> mUserTokenCertificateStore;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  shared_ptr<const Crypto> mCrypto;
};

}  // namespace

// Part 4 7.41 (and 5.6.3.3): an X509IdentityToken carries a public certificate, which proves
// nothing on its own - anyone the user has ever connected to holds a copy. Possession of the
// matching private key is proved by the userTokenSignature, which the server must require whenever
// the resolved user-token policy is an authenticated one. A plausible implementation verifies a
// signature that IS supplied and never notices one that is absent, turning the certificate into a
// bearer credential. The endpoint here advertises Certificate under Basic256Sha256, an authenticated
// token policy, and the authenticator accepts every identity it is given - so the only thing that
// can refuse this activation is the missing-signature rule itself.
// @verifies AC-SVR-IDENT-016-X509-NEEDS-SIGNATURE
TEST(SessionShellWiringTests, X509IdentityTokenWithoutUserTokenSignatureIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

  // A genuine certificate, so the server parses the token as X509 rather than rejecting the DER.
  Crypto::Name subject;
  subject.commonName = "Token User";
  auto certResult = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, UtcTime{2050, 1, 1, 0, 0, 0}, {}, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(certResult.is_good());
  auto [userKeys, userCert] = std::move(certResult).value();
  ASSERT_TRUE(userCert != nullptr);

  auto scDeps = std::make_shared<PolicyMirrorSecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  // Accepts every identity, so a refusal cannot originate here.
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();

  auto sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto);
  // The user-token store accepts the certificate: the certificate is validated before the signature (owner
  // decision 2026-10-03, BR-16), so with an accepted certificate the missing signature is the only thing that
  // can refuse this activation, as this test intends.
  sessDeps->set_user_token_certificate_store(ua::test_helpers::FakeCertificateStore::create());
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 301;
  auto token = std::make_unique<X509IdentityToken>();
  token->certificate_data() = userCert->der_encoding();
  token->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(token);
  // userTokenSignature is left at its default: no signature, no algorithm.
  ASSERT_TRUE(asr.user_token_signature().signature().empty());

  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 2000ms, [&]() { return last.has_value(); }));
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(sf, nullptr) << "presenting a certificate without proof of possession must not activate";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadUserSignatureInvalid);
  lk.unlock();

  EXPECT_FALSE(session->is_activated()) << "a refused activation must leave the session unactivated";

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==================================================================================
// Part 4 section 7.41.2 UserIdentityToken validation: timing, disclosure, logging, lockout,
// encryption requirement, legacy secret size, appended nonce and padding.
//
// Every test below drives a real ActivateSession through Session::parse_identity_token_async, with
// the presented secret built by the production client-side encoder (encrypt_user_token_async /
// build_legacy_encrypted_token_plaintext), so the only thing that varies between an accepted and a
// refused activation is the secret. The session is given a real Crypto, a server certificate and the
// nonce it last issued: those are the CreateSession-time preconditions a wired CertificateStore
// would have produced (the same injection the sibling session_activate_token_encryption_tests.cpp
// uses), never the decision under test.
// ==================================================================================

namespace
{

/// Crypto provider for the token-validation harness; the callback supplies the private-key
/// passphrase the backend asks for.
std::shared_ptr<const Crypto> make_token_validation_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

ByteString make_token_validation_nonce(const Crypto& crypto, size_t size)
{
  ByteString nonce;
  nonce.resize(size);
  auto entropy = crypto.get_entropy_sync(size);
  std::memcpy(nonce.data(), entropy.data(), size);
  return nonce;
}

ByteString make_token_validation_password(string_view text)
{
  ByteString bs;
  bs.assign(reinterpret_cast<const uint8_t*>(text.data()),
    reinterpret_cast<const uint8_t*>(text.data()) + text.size());
  return bs;
}

/// A printable secret of exactly @p length bytes, so a size-bound test can move the length by one
/// byte and change nothing else about the secret.
ByteString make_token_validation_secret(size_t length)
{
  ByteString secret;
  secret.resize(length);
  for (size_t i = 0; i < length; ++i)
  {
    secret.data()[i] = static_cast<uint8_t>('A' + (i % 26));
  }
  return secret;
}

/// Records the message plus every string-valued field of each log entry, so a test can ask what the
/// server told the operator about a failure it refused to explain to the peer.
class TokenValidationLogSink final : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    std::string combined{entry.message};
    for (const auto& field : entry.fields)
    {
      combined += ' ';
      combined += std::string{field.key};
      combined += '=';
      if (const auto* text = std::get_if<std::string_view>(&field.value))
      {
        combined += std::string{*text};
      }
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    mEntries.push_back(std::move(combined));
  }

  void clear()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mEntries.clear();
  }

  [[nodiscard]] size_t count() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mEntries.size();
  }

  /// Every captured entry joined, so a test can ask whether a detail appears anywhere in the log.
  [[nodiscard]] std::string joined() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::string all;
    for (const auto& entry : mEntries)
    {
      all += entry;
      all += '\n';
    }
    return all;
  }

  [[nodiscard]] optional<std::string> first_entry_with_message(string_view message) const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    auto entry = std::ranges::find_if(
      mEntries, [message](const auto& candidate) { return candidate.starts_with(message); });
    return entry == mEntries.end() ? std::nullopt : optional<std::string>{*entry};
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mEntries;
};

/// `CryptoSessionDeps` with the two additions the token-validation obligations need: a real `Logger`
/// (section 7.41.2.1 requires validation failures to be logged) and identity-lockout calls that can be
/// forwarded to a real `ServerImpl`, whose counting policy is what section 7.41.2 constrains. The
/// forwards default to "no lockout", matching every other session fixture in this file.
class TokenValidationSessionDeps final : public SessionDependencies
{
public:
  using LockoutCheck = std::function<optional<StatusCode>(const ::ua::server::ClientId&, std::string_view)>;
  using LockoutRecord = std::function<void(const ::ua::server::ClientId&, std::string_view)>;

  TokenValidationSessionDeps(boost::asio::any_io_executor ex, ServerComponents hooks,
    shared_ptr<const Crypto> crypto, std::shared_ptr<ua::LogSink> logSink,
    std::chrono::milliseconds authenticationInterval)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto))
  {
    mServerCfg.authnTimeout = authenticationInterval;
    if (logSink)
    {
      mLogger =
        Logger{std::move(logSink), std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"};
    }
  }

  LockoutCheck checkLockout;  ///< begin_identity_attempt: the refusal, or nullopt to admit
  LockoutRecord recordFailure;  ///< finish_identity_attempt(Failure)
  LockoutRecord recordSuccess;  ///< finish_identity_attempt(Success)
  LockoutRecord recordAbandoned;  ///< finish_identity_attempt(Abandoned)
  std::atomic<size_t> removeSessionCount{0};

  void set_user_token_certificate_store(std::shared_ptr<CertificateStore> store)
  {
    mUserTokenCertificateStore = std::move(store);
  }

  void set_application_group_certificate_store(std::shared_ptr<CertificateStore> store)
  {
    mApplicationGroupCertificateStore = std::move(store);
  }

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
    return mCrypto;
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
    return mApplicationGroupCertificateStore;
  }

  shared_ptr<CertificateStore> user_token_certificate_store() override
  {
    return mUserTokenCertificateStore;
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
  {
    ++removeSessionCount;
  }

  const ::ua::server::ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return observerValue;
  }

  std::shared_ptr<ServerObserver> observerValue;  ///< settable by a test that observes the activation

  Logger logger() override
  {
    return mLogger;
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

  optional<StatusCode> begin_identity_attempt(
    const ::ua::server::ClientId& client, std::string_view claimedUserId) override
  {
    if (checkLockout)
      return checkLockout(client, claimedUserId);
    return std::nullopt;
  }

  void finish_identity_attempt(const ::ua::server::ClientId& client, std::string_view claimedUserId,
    IdentityAttemptOutcome outcome) override
  {
    switch (outcome)
    {
    case IdentityAttemptOutcome::Failure:
      if (recordFailure)
        recordFailure(client, claimedUserId);
      break;
    case IdentityAttemptOutcome::Success:
      if (recordSuccess)
        recordSuccess(client, claimedUserId);
      break;
    case IdentityAttemptOutcome::Abandoned:
      if (recordAbandoned)
        recordAbandoned(client, claimedUserId);
      break;
    }
  }

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
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  shared_ptr<const Crypto> mCrypto;
  Logger mLogger;
  std::shared_ptr<CertificateStore> mApplicationGroupCertificateStore;
  std::shared_ptr<CertificateStore> mUserTokenCertificateStore;
};

/// Authenticator holding a credential list. It approves a presented (userName, password) pair only
/// when the list contains it, so a wrong password is refused by application policy rather than by the
/// fixture, and it records what it was handed so a test can prove that a secret the server should
/// have refused never reached it.
class TokenCredentialAuthenticator final : public UserAuthenticator
{
public:
  void add_credential(std::string userName, std::string password)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCredentials.emplace_back(std::move(userName), std::move(password));
  }

  /// Approves every identity, so a refusal cannot originate here.
  void accept_everything()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mAcceptEverything = true;
  }

  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    std::string userName = req.identity.userName.value_or(std::string{});
    std::string password;
    if (req.identity.password.has_value())
    {
      password = std::string(req.identity.password->c_str());
    }

    bool accept = false;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mCallCount++;
      mLastUserName = userName;
      mLastPassword = password;
      mLastSecurity = req.security;
      accept = mAcceptEverything;
      for (const auto& credential : mCredentials)
      {
        if (credential.first == userName && credential.second == password)
        {
          accept = true;
        }
      }
    }

    if (accept)
    {
      completion(make_authn_success(UserIdentity{.userId = userName, .displayName = userName, .claims = {}}));
      return;
    }
    auto failure = make_authn_failure(StatusCode{Status::BadUserAccessDenied}, "credentials rejected");
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mLastFailureDetail = failure.shared_detail();
    }
    completion(std::move(failure));
  }

  void reset_calls()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCallCount = 0;
    mLastUserName.clear();
    mLastPassword.clear();
    mLastFailureDetail.reset();
    mLastSecurity.reset();
  }

  [[nodiscard]] bool called() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mCallCount > 0;
  }

  [[nodiscard]] std::string last_password() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastPassword;
  }

  [[nodiscard]] shared_ptr<const ErrorDetail> last_failure_detail() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastFailureDetail;
  }

  [[nodiscard]] std::shared_ptr<const EndpointSecurityContext> last_security() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastSecurity;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<std::string, std::string>> mCredentials;
  bool mAcceptEverything{false};
  size_t mCallCount{0};
  std::string mLastUserName;
  std::string mLastPassword;
  shared_ptr<const ErrorDetail> mLastFailureDetail;
  std::shared_ptr<const EndpointSecurityContext> mLastSecurity;
};

class NonCompletingAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest request, AuthnComplete) noexcept override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mDeadline = request.deadline;
    if (request.deadline)
      mDeadlineBudget = std::chrono::duration_cast<std::chrono::milliseconds>(
        *request.deadline - std::chrono::steady_clock::now());
    else
      mDeadlineBudget.reset();
  }

  [[nodiscard]] optional<std::chrono::steady_clock::time_point> deadline() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mDeadline;
  }

  [[nodiscard]] optional<std::chrono::milliseconds> deadline_budget() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mDeadlineBudget;
  }

private:
  mutable std::mutex mMutex;
  optional<std::chrono::steady_clock::time_point> mDeadline;
  optional<std::chrono::milliseconds> mDeadlineBudget;
};

class DelayedCompletingAuthenticator final : public UserAuthenticator
{
public:
  explicit DelayedCompletingAuthenticator(std::chrono::milliseconds delay) : mDelay{delay}
  {}

  void authenticate_async(AuthnRequest request, AuthnComplete completion) noexcept override
  {
    {
      const std::lock_guard lock{mMutex};
      mDeadline = request.deadline;
    }
    mWorker = std::jthread(
      [delay = mDelay, completion = std::move(completion)]() mutable
      {
        std::this_thread::sleep_for(delay);
        completion(make_authn_success(UserIdentity{.userId = "delayed-user",
          .displayName = "Delayed User",
          .kind = UserTokenKind::UserName,
          .claims = {}}));
      });
  }

  [[nodiscard]] optional<std::chrono::steady_clock::time_point> deadline() const
  {
    const std::lock_guard lock{mMutex};
    return mDeadline;
  }

private:
  std::chrono::milliseconds mDelay;
  mutable std::mutex mMutex;
  optional<std::chrono::steady_clock::time_point> mDeadline;
  std::jthread mWorker;
};

class DuplicateCompletingAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest, AuthnComplete completion) noexcept override
  {
    auto first = make_authn_failure(
      StatusCode{Status::BadUserAccessDenied,
        make_error_detail(
          "FirstCredentialRefusal", "Injected first credential refusal", "DuplicateCompletingAuthenticator")},
      "first credential refusal");
    mFirstDetail = first.shared_detail();
    completion(std::move(first));
    completion(make_authn_success(
      UserIdentity{.userId = "late-success", .displayName = "Late Success", .claims = {}}));
  }

  [[nodiscard]] shared_ptr<const ErrorDetail> first_detail() const
  {
    return mFirstDetail;
  }

private:
  shared_ptr<const ErrorDetail> mFirstDetail;
};

class ReusedRequestIdAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest, AuthnComplete completion) noexcept override
  {
    if (!mFirstCompletion)
    {
      mFirstCompletion = std::move(completion);
      return;
    }

    auto staleCompletion = std::move(mFirstCompletion);
    mSecondCompletion = std::move(completion);
    staleCompletion(
      make_authn_success(UserIdentity{.userId = "stale-A", .displayName = "Stale A", .claims = {}}));
  }

private:
  AuthnComplete mFirstCompletion;
  AuthnComplete mSecondCompletion;
};

// @relation(AC-SVR-DIAG-002-MANUFACTURED-FAILURES-RICH, scope=function)
TEST(AuthenticationFailureDetailTest, AttachedStatusDetailBecomesTheAuthenticationCause)
{
  StatusCode cause{Status::BadSecurityChecksFailed,
    make_error_detail("DecryptFailed", "User token decryption failed", "TokenValidation")};

  auto failure = make_authn_failure(cause, "encrypted password could not be validated");

  ASSERT_TRUE(failure.is_bad());
  EXPECT_EQ(failure.status_code(), Status::BadSecurityChecksFailed);
  ASSERT_NE(failure.shared_detail(), nullptr);
  EXPECT_EQ(failure.shared_detail()->code, "Authentication");
  EXPECT_EQ(failure.shared_detail()->innerStatus, cause.value());
  ASSERT_NE(failure.shared_detail()->cause, nullptr);
  EXPECT_EQ(failure.shared_detail()->cause->code, "DecryptFailed");
}

/// The server's RSA key pair and certificate. Key usage carries keyEncipherment because the whole
/// point of the legacy secret is that the client encrypts it under this certificate's public key.
struct TokenValidationServerIdentity
{
  shared_ptr<const AsymmetricKeyPair> keys;
  shared_ptr<const X509Certificate> certificate;
};

TokenValidationServerIdentity make_token_validation_server_identity(const shared_ptr<const Crypto>& crypto)
{
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  TestPki pki{crypto};
  Crypto::CreateCertificateConfig params;
  params.subjectKeys = keys;
  params.issuerKeys = keys;
  params.subject.commonName = "TokenValidationServer";
  params.serialNumber = "1";
  params.basicConstraint.cA = false;
  params.keyUsage.digitalSignature = true;
  params.keyUsage.keyEncipherment = true;
  params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  params.from = DateTime::now();
  params.to = DateTime{params.from.value() + std::chrono::days{365}};

  return TokenValidationServerIdentity{keys, pki.create_cert(params)};
}

/// One ActivateSession round, captured after the response has arrived so every field is stable at
/// the point the assertions read it.
struct TokenValidationOutcome
{
  bool gotResponse{false};
  bool isActivateResponse{false};
  bool isFault{false};
  StatusCode serviceResult{Status::BadInternalError};
  size_t stringTableSize{0};
  bool diagnosticsNull{true};
  std::string additionalInfo;
  std::chrono::steady_clock::duration elapsed{};
  size_t responseCount{0};
};

struct TokenValidationHarness
{
  boost::asio::thread_pool threadPool{2};
  std::shared_ptr<TokenValidationLogSink> logSink;
  shared_ptr<SecureChannelDependencies> scDeps;
  shared_ptr<TokenValidationSessionDeps> sessDeps;
  shared_ptr<SecureChannel> sc;
  shared_ptr<Session> session;
  optional<SecureChannelInfo> channelInfo;

  std::mutex mutex;
  std::condition_variable cv;
  optional<Response> lastResponse;
  size_t responseCount{0};

  ~TokenValidationHarness()
  {
    shutdown();
  }

  void shutdown()
  {
    if (mShutdown)
      return;
    mShutdown = true;
    if (session)
      session->terminate_for_shutdown();
    if (sc)
      sc->close();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

private:
  bool mShutdown{false};
};

/// Builds a channel advertising exactly one UserTokenPolicy of @p userTokenType (UserName unless
/// stated) under @p userTokenPolicyId, and a session on it. The channel itself is None/None, so the
/// user-token policy is the only thing that can require the secret be protected - which is exactly what
/// Part 4 Table 193 keys off.
std::unique_ptr<TokenValidationHarness> make_token_validation_harness(SecurityPolicyId userTokenPolicyId,
  const shared_ptr<const Crypto>& crypto, ServerComponents hooks,
  std::shared_ptr<TokenValidationLogSink> logSink, std::chrono::milliseconds authenticationInterval = 50ms,
  UserTokenType userTokenType = UserTokenType::UserName)
{
  auto h = std::make_unique<TokenValidationHarness>();
  h->logSink = std::move(logSink);
  auto ex = h->threadPool.get_executor();

  h->scDeps = std::make_shared<PolicyMirrorSecureDeps>(ex);
  h->sc = SecureChannel::create(
    h->scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(
        ex, "L/None", {server::create_user_token_policy(userTokenType, userTokenPolicyId)});
    });

  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &last = h->lastResponse, &responseCount = h->responseCount](
          const Response& r)
        {
          {
            std::lock_guard<std::mutex> lock(mx);
            last = r;
            ++responseCount;
          }
          cv.notify_one();
        });
    });

  h->sessDeps = std::make_shared<TokenValidationSessionDeps>(
    ex, std::move(hooks), crypto, h->logSink, authenticationInterval);
  h->channelInfo.emplace(h->sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }),
    nullptr,
    77,
    "127.0.0.1:4840",
    "opc.tcp://localhost:4840/token-validation",
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");

  CreateSessionRequest createSessionRequest;
  createSessionRequest.client_description().application_uri() = "urn:test:token-validation-client";
  h->session = Session::create(h->sessDeps, *h->channelInfo, 1, std::move(createSessionRequest));
  SessionTestAccess::strand_barrier(*h->session);
  return h;
}

void configure_x509_reevaluation(TokenValidationHarness& harness,
  const std::shared_ptr<ua::test_helpers::FakeCertificateStore>& store,
  const shared_ptr<const X509Certificate>& certificate)
{
  harness.sessDeps->set_user_token_certificate_store(store);
  SessionTestAccess::on_strand(*harness.session,
    [&](auto& guard)
    {
      guard.state().store(SessionTestAccess::State::Activated, std::memory_order_release);
      guard.user_token_certificate() = certificate;
      // Activation stores the token's certificateData field with the certificate; re-evaluation
      // validates that field (owner review item 8), so the seed carries both.
      guard.user_token_certificate_field() = ua::detail::encode_certificate_field(certificate, {});
    });
}

void drain_correlated_response(TokenValidationHarness& harness)
{
  SCTA::strand_barrier(*harness.sc);
  SessionTestAccess::strand_barrier(*harness.session);
  SessionTestAccess::strand_barrier(*harness.session);
  SCTA::strand_barrier(*harness.sc);
}

shared_ptr<const Crypto> make_user_identity_reevaluation_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, RegistrationInsertionThrowCompletesOnceWithRichFailure)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*harness, store, identity.certificate);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard)
    {
      guard.post_response_action_insert_failure_injector() = []
      {
        throw std::runtime_error{"injected post-response action insertion failure"};
      };
    });

  optional<Result<weak_ptr<SecureChannel>>> revalidationResult;
  size_t revalidationCompletionCount{0};
  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{1, 41},
    [&](Result<weak_ptr<SecureChannel>> result)
    {
      ++revalidationCompletionCount;
      revalidationResult = std::move(result);
    });
  SessionTestAccess::strand_barrier(*harness->session);

  ASSERT_TRUE(revalidationResult.has_value());
  EXPECT_EQ(revalidationCompletionCount, 1u);
  EXPECT_EQ(revalidationResult->status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(revalidationResult->shared_detail(), nullptr);
  EXPECT_EQ(revalidationResult->shared_detail()->code, "StdException");

  optional<Result<weak_ptr<SecureChannel>>> closeResult;
  size_t closeCompletionCount{0};
  harness->session->close_secure_channel_after_response_async(MethodResponseCorrelation{1, 41},
    [&](Result<weak_ptr<SecureChannel>> result)
    {
      ++closeCompletionCount;
      closeResult = std::move(result);
    });
  SessionTestAccess::strand_barrier(*harness->session);

  ASSERT_TRUE(closeResult.has_value());
  EXPECT_EQ(closeCompletionCount, 1u);
  EXPECT_EQ(closeResult->status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(closeResult->shared_detail(), nullptr);
  EXPECT_EQ(closeResult->shared_detail()->code, "StdException");
  SessionTestAccess::on_strand(
    *harness->session, [](auto& guard) { EXPECT_TRUE(guard.post_response_actions().empty()); });
  EXPECT_EQ(store->validateCallCount.load(), 0);

  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SecureChannelResponseEnqueue, QueueInsertionThrowCompletesOnceWithRichFailure)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  SCTA::on_strand(*harness->sc,
    [](auto& guard)
    {
      guard.correlated_response_enqueue_failure_injector() = []
      {
        throw std::runtime_error{"injected outgoing queue insertion failure"};
      };
    });

  optional<VoidResult> enqueueResult;
  size_t completionCount{0};
  harness->sc->send_response_message(Response{41, std::make_shared<ReadResponse>()},
    [&](VoidResult result)
    {
      ++completionCount;
      enqueueResult = std::move(result);
    });
  SCTA::strand_barrier(*harness->sc);

  ASSERT_TRUE(enqueueResult.has_value());
  EXPECT_EQ(completionCount, 1u);
  EXPECT_EQ(enqueueResult->status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(enqueueResult->shared_detail(), nullptr);
  EXPECT_EQ(enqueueResult->shared_detail()->code, "StdException");
  SCTA::on_strand(*harness->sc, [](auto& guard) { EXPECT_FALSE(guard.pop_queued_response().has_value()); });

  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, ExactResponseIsQueuedBeforeRichFailureValidationClosesSession)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto logSink = std::make_shared<TokenValidationLogSink>();
  auto harness = make_token_validation_harness(SecurityPolicyId::None, crypto, {}, logSink);
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted,
    make_error_detail(
      "CertificateChainValidationFailed", "Certificate chain validation failed", "FakeCertificateStore")};
  configure_x509_reevaluation(*harness, store, identity.certificate);

  std::vector<std::pair<uint32_t, int>> queuedResponses;
  SCTA::on_strand(*harness->sc,
    [&](auto& guard)
    {
      guard.set_response_sink([&](const Response& response)
        { queuedResponses.emplace_back(std::get<uint32_t>(response), store->validateCallCount.load()); });
    });

  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{1, 41});
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{40, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);
  EXPECT_EQ(store->validateCallCount.load(), 0);

  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);

  ASSERT_EQ(queuedResponses.size(), 2u);
  EXPECT_EQ(queuedResponses[0], std::make_pair(40u, 0));
  EXPECT_EQ(queuedResponses[1], std::make_pair(41u, 0));
  EXPECT_EQ(store->validateCallCount.load(), 1);
  ASSERT_NE(store->lastValidatedCertificate, nullptr);
  // Re-evaluation parses the stored certificateData field, so the certificate is equal, not the same object.
  EXPECT_EQ(store->lastValidatedCertificate->thumbprint(), identity.certificate->thumbprint());
  EXPECT_EQ(harness->sessDeps->removeSessionCount.load(), 1u);
  auto closeEntry = logSink->first_entry_with_message("Session closed");
  ASSERT_TRUE(closeEntry.has_value());
  EXPECT_NE(closeEntry->find(
              fmt::format("close_reason=0x{:08x}", StatusCode{Status::BadIdentityTokenRejected}.as_uint32())),
    std::string::npos);
  const auto outerCause = closeEntry->find("UserIdentityNoLongerValid");
  const auto injectedCause = closeEntry->find("CertificateChainValidationFailed");
  ASSERT_NE(outerCause, std::string::npos);
  ASSERT_NE(injectedCause, std::string::npos);
  EXPECT_LT(outerCause, injectedCause);

  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, GoodValidationKeepsActivatedSession)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*harness, store, identity.certificate);

  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{1, 41});
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);

  EXPECT_EQ(store->validateCallCount.load(), 1);
  EXPECT_EQ(harness->sessDeps->removeSessionCount.load(), 0u);
  EXPECT_TRUE(harness->session->is_activated());

  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, ImmediateAndDeferredEntryPointsClassifyAffectedSessions)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto origin = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto other = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto anonymous = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto originStore = ua::test_helpers::FakeCertificateStore::create();
  auto otherStore = ua::test_helpers::FakeCertificateStore::create();
  auto anonymousStore = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*origin, originStore, identity.certificate);
  configure_x509_reevaluation(*other, otherStore, identity.certificate);
  anonymous->sessDeps->set_user_token_certificate_store(anonymousStore);
  SessionTestAccess::on_strand(*anonymous->session,
    [](auto& guard) { guard.state().store(SessionTestAccess::State::Activated, std::memory_order_release); });

  origin->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{1, 41});
  other->session->reevaluate_certificates_async();
  anonymous->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{1, 41});
  SessionTestAccess::strand_barrier(*origin->session);
  SessionTestAccess::strand_barrier(*other->session);
  SessionTestAccess::strand_barrier(*anonymous->session);

  EXPECT_EQ(originStore->validateCallCount.load(), 0);
  EXPECT_EQ(otherStore->validateCallCount.load(), 1);
  EXPECT_EQ(anonymousStore->validateCallCount.load(), 0);
  SessionTestAccess::on_strand(
    *anonymous->session, [](auto& guard) { EXPECT_TRUE(guard.post_response_actions().empty()); });

  origin->shutdown();
  other->shutdown();
  anonymous->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, DestructionBeforeResponseRetainsNeitherSessionNorStoreWork)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*harness, store, identity.certificate);

  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{1, 41});
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::on_strand(
    *harness->session, [](auto& guard) { EXPECT_EQ(guard.post_response_actions().size(), 1u); });
  std::weak_ptr<Session> weakSession = harness->session;
  harness->session.reset();

  harness->shutdown();

  EXPECT_TRUE(weakSession.expired());
  EXPECT_EQ(store->validateCallCount.load(), 0);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, LateOldEpochRegistrationCannotReleaseReusedRequestId)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*harness, store, identity.certificate);

  uint64_t oldEpoch{0};
  SessionTestAccess::on_strand(
    *harness->session, [&](auto& guard) { oldEpoch = guard.secure_channel_association_epoch(); });
  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{oldEpoch, 41});
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard)
    {
      guard.error_received_from_secure_channel(
        StatusCode{Status::BadConnectionClosed}, shared_ptr<const ErrorDetail>{});
      EXPECT_TRUE(guard.post_response_actions().empty());
    });
  // RATIFIED (owner report 2026-10-03, BR-13 review): the deferred re-evaluation the channel loss dropped is
  // brought forward, never lost - one validation now.
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::strand_barrier(*harness->session);
  EXPECT_EQ(store->validateCallCount.load(), 1);

  optional<Result<weak_ptr<SecureChannel>>> staleRegistration;
  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{oldEpoch, 41},
    [&](Result<weak_ptr<SecureChannel>> result) { staleRegistration = std::move(result); });
  SessionTestAccess::strand_barrier(*harness->session);
  ASSERT_TRUE(staleRegistration.has_value());
  EXPECT_EQ(staleRegistration->status_code(), StatusCode{Status::BadSecureChannelIdInvalid});

  uint64_t newEpoch{0};
  SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      guard.secure_channel_info() = harness->channelInfo;
      newEpoch = guard.secure_channel_association_epoch();
    });
  EXPECT_NE(newEpoch, oldEpoch);
  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{newEpoch, 41});
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);

  EXPECT_EQ(store->validateCallCount.load(), 2) << "exactly one more: the new epoch's, not the stale one's";
  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, LateOldChannelErrorPreservesNewChannelResponseAction)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});

  ActivateSessionRequest firstActivation;
  firstActivation.request_header().request_handle() = 42;
  harness->session->activate(2, std::move(firstActivation), {});
  harness->wait_for_response();
  ASSERT_NE(dynamic_cast<ActivateSessionResponse*>(harness->lastResponse->second.get()), nullptr);
  harness->clear_response();
  // The Session releases its activation claim on its strand after it has sent the response; a
  // re-activation that arrives before then is an overlapping one and is answered BadServerTooBusy.
  SessionTestAccess::strand_barrier(*harness->session);

  SecureChannel::SendRequestMessageToSession oldChannelRequest;
  SecureChannel::ReportErrorToSession oldChannelReport;
  SCTA::on_strand(*harness->sc,
    [&](auto& guard)
    {
      ASSERT_EQ(guard.session_callbacks().size(), 1u);
      oldChannelRequest = guard.session_callbacks().begin()->second.sendRequest;
      oldChannelReport = guard.session_callbacks().begin()->second.reportError;
    });
  ASSERT_TRUE(oldChannelRequest);
  ASSERT_TRUE(oldChannelReport);

  auto secondChannel = make_second_channel(harness->threadPool.get_executor());
  SCTA::on_strand(*secondChannel,
    [&](auto& guard)
    {
      guard.set_response_sink(
        [&mx = harness->mutex, &cv = harness->cv, &last = harness->lastResponse](const Response& response)
        {
          {
            std::lock_guard<std::mutex> lock(mx);
            last = response;
          }
          cv.notify_one();
        });
    });
  SecureChannelInfo secondChannelInfo(secondChannel->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L2/None",
    SCTA::on_strand(*secondChannel, [](auto& guard) -> const auto& { return guard.user_identity_tokens(); }));
  ActivateSessionRequest secondActivation;
  secondActivation.request_header().request_handle() = 43;
  harness->session->activate(3, std::move(secondActivation), secondChannelInfo);
  harness->wait_for_response();
  auto* secondResponse = dynamic_cast<ActivateSessionResponse*>(harness->lastResponse->second.get());
  ASSERT_NE(secondResponse, nullptr);
  ASSERT_TRUE(secondResponse->response_header().service_result().is_good());

  uint64_t newEpoch{0};
  SessionTestAccess::on_strand(
    *harness->session, [&](auto& guard) { newEpoch = guard.secure_channel_association_epoch(); });
  optional<Result<weak_ptr<SecureChannel>>> closeRegistration;
  harness->session->close_secure_channel_after_response_async(MethodResponseCorrelation{newEpoch, 41},
    [&](Result<weak_ptr<SecureChannel>> result) { closeRegistration = std::move(result); });
  SessionTestAccess::strand_barrier(*harness->session);
  ASSERT_TRUE(closeRegistration.has_value());
  ASSERT_TRUE(*closeRegistration);

  std::vector<Response> oldChannelResponses;
  std::vector<Response> newChannelResponses;
  SCTA::on_strand(*harness->sc,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { oldChannelResponses.push_back(response); }); });
  SCTA::on_strand(*secondChannel,
    [&](auto& guard)
    { guard.set_response_sink([&](const Response& response) { newChannelResponses.push_back(response); }); });
  oldChannelRequest(Request{40, std::make_shared<ReadRequest>()});
  SessionTestAccess::strand_barrier(*harness->session);
  SCTA::strand_barrier(*harness->sc);
  SCTA::strand_barrier(*secondChannel);
  ASSERT_EQ(oldChannelResponses.size(), 1u);
  EXPECT_EQ(std::get<uint32_t>(oldChannelResponses.front()), 40u);
  auto* staleFault =
    dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(oldChannelResponses.front()).get());
  ASSERT_NE(staleFault, nullptr);
  EXPECT_EQ(staleFault->response_header().service_result(), StatusCode{Status::BadSecureChannelIdInvalid});
  EXPECT_TRUE(newChannelResponses.empty());

  oldChannelReport(StatusCode{Status::BadConnectionClosed},
    make_error_detail("LateOldChannelFailure", "Injected old-channel failure", "Test"));
  SessionTestAccess::strand_barrier(*harness->session);

  SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      ASSERT_TRUE(guard.secure_channel_info().has_value());
      EXPECT_EQ(guard.secure_channel_info()->secure_channel().lock(), secondChannel);
      EXPECT_EQ(guard.secure_channel_association_epoch(), newEpoch);
      ASSERT_EQ(guard.post_response_actions().size(), 1u);
      EXPECT_TRUE(guard.post_response_actions().front().closeSecureChannel);
    });
  SCTA::on_strand(
    *secondChannel, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::BadShutdown}); });

  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  SCTA::strand_barrier(*secondChannel);
  SessionTestAccess::strand_barrier(*harness->session);
  SCTA::strand_barrier(*secondChannel);
  SCTA::on_strand(
    *secondChannel, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::Good}); });

  harness->shutdown();
}

// A deferred re-evaluation whose response never crosses the channel's queue (the enqueue failed) is brought
// forward, not dropped: the Session re-evaluates at once (review BR-13). Falsifiable: the failure path only
// logged, and nothing re-evaluated the Session.
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST(SessionCertificateReevaluation, AFailedEnqueueBringsTheDeferredReevaluationForward)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*harness, store, identity.certificate);
  SCTA::on_strand(*harness->sc,
    [](auto& guard)
    {
      guard.correlated_response_enqueue_failure_injector() = []
      {
        throw std::runtime_error{"injected outgoing queue insertion failure"};
      };
    });
  uint64_t epoch{0};
  SessionTestAccess::on_strand(
    *harness->session, [&](auto& guard) { epoch = guard.secure_channel_association_epoch(); });

  harness->session->reevaluate_certificates_after_response_async(MethodResponseCorrelation{epoch, 41});
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);
  SessionTestAccess::strand_barrier(*harness->session);

  EXPECT_EQ(store->validateCallCount.load(), 1) << "re-evaluated although the response did not go out";
  harness->shutdown();
}

// A correlation that no longer matches the origin's channel association defers nothing: the origin Session is
// re-evaluated at once like every other, and the dispatcher reports the stale correlation. Falsifiable: the
// origin's registration failed and nothing re-evaluated it.
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST(SessionCertificateReevaluation, AStaleCorrelationReevaluatesTheOriginAtOnce)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto origin = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto originStore = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*origin, originStore, identity.certificate);
  uint64_t epoch{0};
  SessionTestAccess::on_strand(
    *origin->session, [&](auto& guard) { epoch = guard.secure_channel_association_epoch(); });

  optional<VoidResult> dispatched;
  ua::test_helpers::ServerImplTestAccess::dispatch_certificate_reevaluation({origin->sc},
    {origin->session},
    origin->session->session_id(),
    MethodResponseCorrelation{epoch + 1, 41},
    [&](VoidResult result) { dispatched = std::move(result); });
  SessionTestAccess::strand_barrier(*origin->session);
  SessionTestAccess::strand_barrier(*origin->session);
  SessionTestAccess::strand_barrier(*origin->session);

  ASSERT_TRUE(dispatched.has_value());
  EXPECT_EQ(dispatched->status_code(), StatusCode{Status::BadSecureChannelIdInvalid});
  EXPECT_EQ(originStore->validateCallCount.load(), 1) << "re-evaluated now";
  SessionTestAccess::on_strand(
    *origin->session, [](auto& guard) { EXPECT_TRUE(guard.post_response_actions().empty()); });

  origin->shutdown();
}

namespace
{
/// A session of the token-validation harness that holds a client application certificate, with the issuer
/// it was presented with, in @p state; its application-group store is @p store.
void configure_client_certificate_reevaluation(TokenValidationHarness& harness,
  const std::shared_ptr<ua::test_helpers::FakeCertificateStore>& store,
  const shared_ptr<const X509Certificate>& certificate, const shared_ptr<const X509Certificate>& issuer,
  SessionTestAccess::State state = SessionTestAccess::State::Activated)
{
  harness.sessDeps->set_application_group_certificate_store(store);
  SessionTestAccess::on_strand(*harness.session,
    [&](auto& guard)
    {
      guard.state().store(state, std::memory_order_release);
      guard.client_certificate() = certificate;
      guard.client_issuer_certificates() = {issuer};
      guard.client_certificate_policy() = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    });
}
}  // namespace

// OPC 10000-12 7.8.2.3: "When the TrustList changes the Server shall re-evaluate the Certificate associated
// with any open Sessions. Sessions with an untrusted or revoked Certificate shall be closed." The Session
// validates its client application certificate - with the issuers presented at the OpenSecureChannel and
// that channel's SecurityPolicy - against the DefaultApplicationGroup, and closes when it is refused.
// Falsifiable: the former Session re-checked only an X.509 user identity.
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST(SessionCertificateReevaluation, AClientCertificateNoLongerTrustedClosesTheSession)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto issuer = make_token_validation_server_identity(crypto);
  auto logSink = std::make_shared<TokenValidationLogSink>();
  auto harness = make_token_validation_harness(SecurityPolicyId::None, crypto, {}, logSink);
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->validateCertificateStatus = StatusCode{Status::BadCertificateRevoked,
    make_error_detail("CertificateRevoked", "The certificate is revoked", "FakeCertificateStore")};
  configure_client_certificate_reevaluation(*harness, store, identity.certificate, issuer.certificate);

  harness->session->reevaluate_certificates_async();
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::strand_barrier(*harness->session);

  EXPECT_EQ(store->validateCallCount.load(), 1);
  const auto request = store->last_validation_request();
  ASSERT_TRUE(request.has_value());
  EXPECT_EQ(request->certificate, identity.certificate);
  ASSERT_EQ(request->presentedIssuers.size(), 1u);
  EXPECT_EQ(request->presentedIssuers[0], issuer.certificate) << "the issuers presented with it";
  EXPECT_EQ(request->policyId, SecurityPolicyId::Basic256Sha256) << "under the channel's policy";
  EXPECT_EQ(harness->sessDeps->removeSessionCount.load(), 1u) << "the Session is closed";
  auto closeEntry = logSink->first_entry_with_message("Session closed");
  ASSERT_TRUE(closeEntry.has_value());
  EXPECT_NE(closeEntry->find("ClientCertificateNoLongerValid"), std::string::npos);
  EXPECT_NE(closeEntry->find("CertificateRevoked"), std::string::npos) << "with the validator's cause";

  harness->shutdown();
}

// The control: a certificate still trusted keeps the Session (only Sessions the change invalidates close).
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST(SessionCertificateReevaluation, AClientCertificateStillTrustedKeepsTheSession)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto issuer = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_client_certificate_reevaluation(*harness, store, identity.certificate, issuer.certificate);

  harness->session->reevaluate_certificates_async();
  SessionTestAccess::strand_barrier(*harness->session);
  SessionTestAccess::strand_barrier(*harness->session);

  EXPECT_EQ(store->validateCallCount.load(), 1);
  EXPECT_EQ(harness->sessDeps->removeSessionCount.load(), 0u);
  EXPECT_TRUE(harness->session->is_activated());

  harness->shutdown();
}

// An open Session not yet activated is open too (7.8.2.3 "any open Sessions"): it is re-evaluated and closed.
// A closed one, and one without a client certificate, validate nothing.
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST(SessionCertificateReevaluation, ACreatedSessionIsReevaluatedAndAClosedOneIsNot)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto issuer = make_token_validation_server_identity(crypto);
  auto created = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto closed = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto none = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto createdStore = ua::test_helpers::FakeCertificateStore::create();
  auto closedStore = ua::test_helpers::FakeCertificateStore::create();
  auto noneStore = ua::test_helpers::FakeCertificateStore::create();
  createdStore->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};
  configure_client_certificate_reevaluation(
    *created, createdStore, identity.certificate, issuer.certificate, SessionTestAccess::State::Created);
  configure_client_certificate_reevaluation(
    *closed, closedStore, identity.certificate, issuer.certificate, SessionTestAccess::State::Closed);
  none->sessDeps->set_application_group_certificate_store(noneStore);
  SessionTestAccess::on_strand(*none->session,
    [](auto& guard) { guard.state().store(SessionTestAccess::State::Activated, std::memory_order_release); });

  for (auto* harness : {created.get(), closed.get(), none.get()})
  {
    harness->session->reevaluate_certificates_async();
    SessionTestAccess::strand_barrier(*harness->session);
    SessionTestAccess::strand_barrier(*harness->session);
  }

  EXPECT_EQ(createdStore->validateCallCount.load(), 1);
  EXPECT_EQ(created->sessDeps->removeSessionCount.load(), 1u);
  EXPECT_EQ(closedStore->validateCallCount.load(), 0);
  EXPECT_EQ(noneStore->validateCallCount.load(), 0);
  EXPECT_EQ(none->sessDeps->removeSessionCount.load(), 0u);

  created->shutdown();
  closed->shutdown();
  none->shutdown();
}

// The production wiring of what the re-evaluation validates: CreateSession keeps the issuers its channel was
// opened with and that channel's SecurityPolicy (SecureChannelInfo::client_issuer_certificates).
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST(SessionCertificateReevaluation, CreateSessionKeepsTheIssuersAndPolicyOfItsChannel)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto issuer = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  const auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo channelInfo(harness->sc->weak_from_this(),
    policy,
    MessageSecurityMode::None,
    "L/None",
    harness->channelInfo->user_identity_tokens(),
    identity.certificate,
    78,
    "127.0.0.1:4841",
    "opc.tcp://localhost:4840/token-validation",
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
    {issuer.certificate});
  CreateSessionRequest request;
  request.client_description().application_uri() = "urn:test:token-validation-client";
  auto session = Session::create(harness->sessDeps, channelInfo, 2, std::move(request));
  SessionTestAccess::strand_barrier(*session);

  SessionTestAccess::on_strand(*session,
    [&](auto& guard)
    {
      EXPECT_EQ(guard.client_certificate(), identity.certificate);
      ASSERT_EQ(guard.client_issuer_certificates().size(), 1u);
      EXPECT_EQ(guard.client_issuer_certificates()[0], issuer.certificate);
      EXPECT_EQ(guard.client_certificate_policy(), policy);
    });

  session->terminate_for_shutdown();
  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, CombinedCloseAndRevalidationMergeBehindExactResponse)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto harness = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto store = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*harness, store, identity.certificate);

  uint64_t epoch{0};
  SessionTestAccess::on_strand(
    *harness->session, [&](auto& guard) { epoch = guard.secure_channel_association_epoch(); });
  const MethodResponseCorrelation correlation{epoch, 41};
  optional<Result<weak_ptr<SecureChannel>>> revalidationRegistration;
  optional<Result<weak_ptr<SecureChannel>>> closeRegistration;
  harness->session->reevaluate_certificates_after_response_async(correlation,
    [&](Result<weak_ptr<SecureChannel>> result) { revalidationRegistration = std::move(result); });
  harness->session->close_secure_channel_after_response_async(
    correlation, [&](Result<weak_ptr<SecureChannel>> result) { closeRegistration = std::move(result); });
  SessionTestAccess::strand_barrier(*harness->session);

  ASSERT_TRUE(revalidationRegistration.has_value());
  EXPECT_TRUE(*revalidationRegistration);
  ASSERT_TRUE(closeRegistration.has_value());
  EXPECT_TRUE(*closeRegistration);
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard)
    {
      ASSERT_EQ(guard.post_response_actions().size(), 1u);
      EXPECT_TRUE(guard.post_response_actions().front().reevaluateCertificates);
      EXPECT_TRUE(guard.post_response_actions().front().closeSecureChannel);
    });

  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{40, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);
  EXPECT_EQ(store->validateCallCount.load(), 0);
  SCTA::on_strand(
    *harness->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::BadShutdown}); });

  std::vector<std::pair<uint32_t, int>> queuedResponses;
  SCTA::on_strand(*harness->sc,
    [&](auto& guard)
    {
      guard.set_response_sink([&](const Response& response)
        { queuedResponses.emplace_back(std::get<uint32_t>(response), store->validateCallCount.load()); });
    });
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*harness);

  ASSERT_EQ(queuedResponses.size(), 1u);
  EXPECT_EQ(queuedResponses.front(), std::make_pair(41u, 0));
  EXPECT_EQ(store->validateCallCount.load(), 1);
  SCTA::on_strand(
    *harness->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::Good}); });
  harness->shutdown();
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST(SessionUserIdentityReevaluation, ServerDispatcherActsImmediatelyExceptForExactOriginResponse)
{
  auto crypto = make_user_identity_reevaluation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  auto origin = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto other = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto anonymous = make_token_validation_harness(
    SecurityPolicyId::None, crypto, {}, std::make_shared<TokenValidationLogSink>());
  auto originStore = ua::test_helpers::FakeCertificateStore::create();
  auto otherStore = ua::test_helpers::FakeCertificateStore::create();
  configure_x509_reevaluation(*origin, originStore, identity.certificate);
  configure_x509_reevaluation(*other, otherStore, identity.certificate);
  SessionTestAccess::on_strand(*anonymous->session,
    [](auto& guard) { guard.state().store(SessionTestAccess::State::Activated, std::memory_order_release); });

  uint64_t epoch{0};
  SessionTestAccess::on_strand(
    *origin->session, [&](auto& guard) { epoch = guard.secure_channel_association_epoch(); });
  const MethodResponseCorrelation correlation{epoch, 41};
  std::vector<shared_ptr<Session>> sessions{origin->session, other->session, anonymous->session};
  std::vector<weak_ptr<SecureChannel>> channels{origin->sc, other->sc, anonymous->sc};
  optional<VoidResult> revalidationDispatch;
  optional<VoidResult> closeDispatch;

  // Each Session re-evaluates with the stores its own dependencies supply (here, origin's and other's).
  ua::test_helpers::ServerImplTestAccess::dispatch_certificate_reevaluation(channels,
    sessions,
    origin->session->session_id(),
    correlation,
    [&](VoidResult result) { revalidationDispatch = std::move(result); });
  ua::test_helpers::ServerImplTestAccess::dispatch_apply_changes_channel_close(std::move(channels),
    sessions,
    origin->session->session_id(),
    correlation,
    [&](VoidResult result) { closeDispatch = std::move(result); });

  SessionTestAccess::strand_barrier(*origin->session);
  SessionTestAccess::strand_barrier(*other->session);
  SessionTestAccess::strand_barrier(*anonymous->session);
  SCTA::strand_barrier(*other->sc);
  SCTA::strand_barrier(*anonymous->sc);

  ASSERT_TRUE(revalidationDispatch.has_value());
  EXPECT_TRUE(*revalidationDispatch);
  ASSERT_TRUE(closeDispatch.has_value());
  EXPECT_TRUE(*closeDispatch);
  EXPECT_EQ(originStore->validateCallCount.load(), 0);
  EXPECT_EQ(otherStore->validateCallCount.load(), 1);
  SessionTestAccess::on_strand(*origin->session,
    [](auto& guard)
    {
      ASSERT_EQ(guard.post_response_actions().size(), 1u);
      EXPECT_TRUE(guard.post_response_actions().front().reevaluateCertificates);
      EXPECT_TRUE(guard.post_response_actions().front().closeSecureChannel);
    });
  SessionTestAccess::on_strand(
    *anonymous->session, [](auto& guard) { EXPECT_TRUE(guard.post_response_actions().empty()); });
  SCTA::on_strand(
    *origin->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::BadShutdown}); });
  SCTA::on_strand(*other->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::Good}); });
  SCTA::on_strand(
    *anonymous->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::Good}); });

  std::vector<std::pair<uint32_t, int>> queuedResponses;
  SCTA::on_strand(*origin->sc,
    [&](auto& guard)
    {
      guard.set_response_sink(
        [&](const Response& response) {
          queuedResponses.emplace_back(std::get<uint32_t>(response), originStore->validateCallCount.load());
        });
    });
  SessionTestAccess::on_strand(*origin->session,
    [](auto& guard) { guard.response_received(Response{40, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*origin);
  EXPECT_EQ(originStore->validateCallCount.load(), 0);
  SCTA::on_strand(
    *origin->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::BadShutdown}); });

  SessionTestAccess::on_strand(*origin->session,
    [](auto& guard) { guard.response_received(Response{41, std::make_shared<ReadResponse>()}); });
  drain_correlated_response(*origin);
  ASSERT_EQ(queuedResponses.size(), 2u);
  EXPECT_EQ(queuedResponses[0], std::make_pair(40u, 0));
  EXPECT_EQ(queuedResponses[1], std::make_pair(41u, 0));
  EXPECT_EQ(originStore->validateCallCount.load(), 1);
  SCTA::on_strand(
    *origin->sc, [](auto& guard) { EXPECT_EQ(guard.close_reason(), StatusCode{Status::Good}); });

  origin->shutdown();
  other->shutdown();
  anonymous->shutdown();
}

/// Installs the CreateSession-time state a wired CertificateStore would have produced: the nonce the
/// server last issued, and the certificate/key the client encrypted against. Re-applied before every
/// round so a preceding activation cannot leave a rotated nonce behind.
void seed_token_validation_session(TokenValidationHarness& h, const ByteString& serverNonce,
  const shared_ptr<const SecurityPolicy>& tokenPolicy, const TokenValidationServerIdentity& identity)
{
  SessionTestAccess::on_strand(*h.session,
    [&](auto& g)
    {
      g.server_nonce() = serverNonce;
      g.server_certificates().clear();
      g.server_certificates().push_back(CertificateStore::ApplicationCertificate{
        tokenPolicy->certificate_type(), identity.certificate, identity.keys});
      g.selected_cert_and_key() = g.server_certificates().back();
    });
}

/// Runs one ActivateSession carrying @p token (a UserName or Issued identity token), asking for every
/// diagnostic the server is willing to produce so anything it would disclose is in view, and classifies
/// the response.
template<typename TokenT>
TokenValidationOutcome activate_with_token(TokenValidationHarness& h, uint32_t requestId, const TokenT& token,
  optional<std::string> policyIdOverride = std::nullopt,
  optional<SignatureData> userTokenSignature = std::nullopt)
{
  size_t responseCountBefore = 0;
  {
    const std::lock_guard<std::mutex> lock(h.mutex);
    h.lastResponse.reset();
    responseCountBefore = h.responseCount;
  }

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = requestId;
  asr.request_header().return_diagnostics() = 0x3FFu;
  auto presented = std::make_unique<TokenT>(token);
  if (policyIdOverride.has_value())
  {
    presented->policy_id() = std::move(*policyIdOverride);
  }
  else
  {
    presented->policy_id() =
      SCTA::on_strand(*h.sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); })
        .front()
        .policy_id();
  }
  asr.user_identity_token() = std::move(presented);
  if (userTokenSignature.has_value())
  {
    asr.user_token_signature() = std::move(*userTokenSignature);
  }

  TokenValidationOutcome outcome;
  const auto started = std::chrono::steady_clock::now();
  h.session->activate(requestId, std::move(asr), {});

  std::unique_lock<std::mutex> lock(h.mutex);
  outcome.gotResponse = h.cv.wait_for(lock, 5000ms, [&]() { return h.lastResponse.has_value(); });
  outcome.elapsed = std::chrono::steady_clock::now() - started;
  if (!outcome.gotResponse)
  {
    return outcome;
  }

  const ResponseHeader* header = nullptr;
  if (auto* resp = dynamic_cast<ActivateSessionResponse*>(h.lastResponse->second.get()))
  {
    outcome.isActivateResponse = true;
    header = &resp->response_header();
  }
  else if (auto* fault = dynamic_cast<ServiceFault*>(h.lastResponse->second.get()))
  {
    outcome.isFault = true;
    header = &fault->response_header();
  }

  if (header != nullptr)
  {
    outcome.serviceResult = header->service_result();
    outcome.responseCount = h.responseCount - responseCountBefore;
    outcome.stringTableSize = header->string_table().size();
    outcome.diagnosticsNull = header->service_diagnostics().is_null();
    const auto& additional = header->service_diagnostics().additional_info();
    if (additional.has_value())
    {
      outcome.additionalInfo = *additional;
    }
  }
  return outcome;
}

/// Encrypts @p password into a UserNameIdentityToken through the production client-side encoder, so
/// the secret is built and encrypted the way a conforming client builds it; only the nonce and the
/// password vary between calls.
std::shared_ptr<UserNameIdentityToken> encrypt_user_name_token(const shared_ptr<const SecurityPolicy>& policy,
  const shared_ptr<const Crypto>& crypto, const shared_ptr<const X509Certificate>& serverCert,
  const char* userName, const ByteString& password, const ByteString& serverNonce)
{
  auto tokenPtr = std::make_shared<UserNameIdentityToken>();
  tokenPtr->user_name() = userName;
  tokenPtr->password() = password;

  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policy,
        crypto,
        crypto_test_strand(),
        tokenPtr,
        serverNonce,
        serverCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  EXPECT_TRUE(encResult.is_good()) << "client-side token encryption failed";
  EXPECT_NE(tokenPtr->password(), password) << "the token must actually be encrypted";
  return tokenPtr;
}

std::unique_ptr<IssuedIdentityToken> encrypt_issued_token(const shared_ptr<const SecurityPolicy>& policy,
  const shared_ptr<const Crypto>& crypto, const shared_ptr<const X509Certificate>& serverCert,
  const ByteString& tokenData, const ByteString& serverNonce)
{
  // The production encoder: an encrypted IssuedIdentityToken is always an EncryptedSecret (OPC
  // 10000-4 7.40.6), whatever its length, and its outer encryptionAlgorithm is empty.
  auto encrypted = std::make_shared<IssuedIdentityToken>();
  encrypted->token_data() = tokenData;
  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_issued_token_async(policy,
        crypto,
        crypto_test_strand(),
        encrypted,
        serverNonce,
        serverCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  EXPECT_TRUE(encResult.is_good()) << "client-side issued-token encryption failed";
  EXPECT_NE(encrypted->token_data(), tokenData) << "the token must actually be encrypted";
  auto issued = std::make_unique<IssuedIdentityToken>();
  issued->token_data() = encrypted->token_data();
  issued->encryption_algorithm() = encrypted->encryption_algorithm();
  return issued;
}

/// Builds a legacy Part 4 section 7.41.2.2 secret by hand - `Length(4 LE) || password || serverNonce`
/// followed by @p padding - and RSA-encrypts it under the server certificate exactly as the
/// production encoder does. Trailing padding is the only thing the production encoder cannot express.
std::shared_ptr<UserNameIdentityToken> encrypt_legacy_secret_with_padding(
  const shared_ptr<const SecurityPolicy>& policy, const shared_ptr<const Crypto>& crypto,
  const shared_ptr<const X509Certificate>& serverCert, const char* userName, const ByteString& password,
  const ByteString& serverNonce, const std::vector<uint8_t>& padding)
{
  ByteString plain =
    build_legacy_encrypted_token_plaintext(span<const byte>{password}, span<const byte>{serverNonce});
  std::vector<uint8_t> bytes(plain.begin(), plain.end());
  bytes.insert(bytes.end(), padding.begin(), padding.end());
  ByteString plainWithPadding{std::move(bytes)};

  const size_t cipherBlockSize = policy->asymmetric_ciphertext_block_size(serverCert.get());
  const size_t plainBlockSize = policy->asymmetric_plaintext_block_size(serverCert.get());
  EXPECT_GT(plainBlockSize, 0u);
  EXPECT_GT(cipherBlockSize, 0u);
  const size_t numBlocks =
    (plainBlockSize == 0) ? 1u : (plainWithPadding.size() + plainBlockSize - 1) / plainBlockSize;

  // OPC 10000-6 6.7.2: each PlainTextBlockSize block encrypts to one CipherTextBlockSize block.
  ByteString cipherText;
  cipherText.resize(numBlocks * cipherBlockSize);
  const ByteString publicKey = serverCert->public_key();
  const span<const byte> plainBlocks{plainWithPadding};
  for (size_t block = 0; block < numBlocks; ++block)
  {
    const size_t offset = block * plainBlockSize;
    crypto->asymmetric_encrypt_sync(policy->asymmetric_encryption_algorithm(),
      span<const byte>{publicKey},
      plainBlocks.subspan(offset, std::min(plainBlockSize, plainBlocks.size() - offset)),
      span<byte>{cipherText}.subspan(block * cipherBlockSize, cipherBlockSize));
  }

  auto token = std::make_shared<UserNameIdentityToken>();
  token->user_name() = userName;
  token->password() = std::move(cipherText);
  token->encryption_algorithm() = policy->uri();
  return token;
}

/// One stage of the Part 4 section 7.41.2.1 validation process - "decrypting, check for padding and
/// checking for a valid nonce" - together with the word the server's own internal error text uses for
/// it. That word is the detail the peer must not receive and the operator must.
struct TokenValidationStage
{
  std::string name;
  std::shared_ptr<UserNameIdentityToken> token;
  std::string withheldDetail;
};

/// All three faults are injected into the same correctly-encrypted secret for the same user, so the
/// stages differ only in where validation fails.
std::vector<TokenValidationStage> make_token_validation_stages(const shared_ptr<const SecurityPolicy>& policy,
  const shared_ptr<const Crypto>& crypto, const shared_ptr<const X509Certificate>& serverCert,
  const ByteString& currentNonce, const ByteString& staleNonce, const ByteString& password)
{
  std::vector<TokenValidationStage> stages;

  // Decrypting: a correctly-formed encrypted token with one ciphertext byte flipped, so the
  // asymmetric unwrap fails before any structure is parsed.
  {
    auto token = encrypt_user_name_token(policy, crypto, serverCert, "testuser", password, currentNonce);
    EXPECT_FALSE(token->password().empty());
    if (!token->password().empty())
    {
      token->password().data()[0] = static_cast<uint8_t>(token->password().data()[0] ^ 0xFFu);
    }
    stages.push_back(TokenValidationStage{"undecryptable", token, "decrypt"});
  }

  // Check for padding: a well-formed secret with non-zero bytes after the declared length.
  {
    auto token = encrypt_legacy_secret_with_padding(
      policy, crypto, serverCert, "testuser", password, currentNonce, {0x00, 0x07, 0x00});
    stages.push_back(TokenValidationStage{"non-zero-padding", token, "padding"});
  }

  // Checking for a valid nonce: a well-formed secret carrying a nonce the server never issued.
  {
    auto token = encrypt_user_name_token(policy, crypto, serverCert, "testuser", password, staleNonce);
    stages.push_back(TokenValidationStage{"wrong-nonce", token, "nonce"});
  }

  return stages;
}

double token_validation_median_ms(std::vector<double> samples)
{
  if (samples.empty())
    return 0.0;
  std::sort(samples.begin(), samples.end());
  return samples[samples.size() / 2];
}

}  // namespace

// Part 4 section 7.41.2.1: "Servers shall ensure that the process of validating UserIdentityTokens
// completes in a fixed interval independent of whether an error occurs or not. The process of
// validation includes decrypting, check for padding and checking for a valid nonce. If any errors
// occur the return code is Bad_IdentityTokenInvalid." The natural way to write validation is
// check-fail-return, which separates the stages by both status code and wall-clock duration and so
// hands an attacker a free oracle for where in its guess the secret went wrong. Token-format stages
// retain their mandated common code, credential refusals retain their policy code and rich cause,
// and none of those failures separates from valid credentials by duration.
// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, TokenValidationTakesTheSameTimeAndAnswersTheSameCodeHoweverItFails)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);

  auto currentNonce = make_token_validation_nonce(*crypto, 32);
  auto staleNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_NE(currentNonce, staleNonce);
  const auto password = make_token_validation_password("TestPassword123!");

  auto stages =
    make_token_validation_stages(policy, crypto, identity.certificate, currentNonce, staleNonce, password);
  ASSERT_EQ(stages.size(), 3u) << "all three section 7.41.2.1 validation stages must be exercised";

  stages.push_back(TokenValidationStage{"unknown-user",
    encrypt_user_name_token(policy, crypto, identity.certificate, "missing-user", password, currentNonce),
    "credentials"});
  stages.push_back(TokenValidationStage{"wrong-password",
    encrypt_user_name_token(policy,
      crypto,
      identity.certificate,
      "testuser",
      make_token_validation_password("WrongPassword123!"),
      currentNonce),
    "credentials"});

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("testuser", "TestPassword123!");
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr);
  auto validToken =
    encrypt_user_name_token(policy, crypto, identity.certificate, "testuser", password, currentNonce);

  constexpr size_t rounds = 9;
  std::vector<std::vector<double>> samplesByStage(stages.size() + 1);
  std::vector<StatusCode> codes;
  uint32_t requestId = 100;

  for (size_t round = 0; round < rounds; ++round)
  {
    for (size_t stage = 0; stage < stages.size(); ++stage)
    {
      seed_token_validation_session(*h, currentNonce, policy, identity);
      auto outcome = activate_with_token(*h, ++requestId, *stages[stage].token);
      ASSERT_TRUE(outcome.gotResponse) << "no response for stage " << stages[stage].name;
      ASSERT_FALSE(outcome.isActivateResponse)
        << "stage " << stages[stage].name << " must be refused, not activated";
      EXPECT_EQ(outcome.responseCount, 1u) << "stage " << stages[stage].name;
      samplesByStage[stage].push_back(std::chrono::duration<double, std::milli>(outcome.elapsed).count());
      codes.push_back(outcome.serviceResult);

      if (stage >= 3u)
      {
        EXPECT_EQ(outcome.serviceResult.shared_detail(), authenticator->last_failure_detail())
          << "the fixed-interval gate must retain the authenticator's exact rich failure";
      }
    }

    seed_token_validation_session(*h, currentNonce, policy, identity);
    auto accepted = activate_with_token(*h, ++requestId, *validToken);
    ASSERT_TRUE(accepted.gotResponse) << "valid-credential control produced no response";
    ASSERT_TRUE(accepted.isActivateResponse) << "valid credentials must remain accepted";
    EXPECT_TRUE(accepted.serviceResult.is_good());
    EXPECT_EQ(accepted.responseCount, 1u);
    samplesByStage.back().push_back(std::chrono::duration<double, std::milli>(accepted.elapsed).count());
  }

  ASSERT_EQ(codes.size(), rounds * stages.size()) << "every round must have produced an outcome";

  // First half of the observation: one code, whichever stage failed.
  for (size_t i = 0; i < codes.size(); ++i)
  {
    const size_t stage = i % stages.size();
    const StatusCode expected =
      stage < 3u ? StatusCode{Status::BadIdentityTokenInvalid} : StatusCode{Status::BadUserAccessDenied};
    EXPECT_EQ(codes[i], expected) << "stage " << stages[stage].name
                                  << " must preserve its security classification";
  }

  // Second half: the durations must not separate the stages. Medians over rounds rounds on one live
  // session, so the only work that differs between the samples is the validation path itself.
  // RATIFIED EXPECTATION CHANGE (owner decision 23): the valid-credential control is no longer held, so it is
  // excluded from the equal-time comparison and asserted to answer before the interval instead.
  EXPECT_LT(token_validation_median_ms(samplesByStage.back()), 45.0)
    << "a successful activation must not be held behind the fixed 50ms deadline";
  std::vector<double> medians;
  for (size_t stage = 0; stage + 1 < samplesByStage.size(); ++stage)
  {
    ASSERT_EQ(samplesByStage[stage].size(), rounds);
    medians.push_back(token_validation_median_ms(samplesByStage[stage]));
  }
  ASSERT_FALSE(medians.empty());
  const double slowest = *std::max_element(medians.begin(), medians.end());
  const double fastest = *std::min_element(medians.begin(), medians.end());
  EXPECT_GE(fastest, 45.0) << "every token-validation outcome must be held behind the fixed 50ms deadline";
  // 25% plus 1ms of scheduler slack: an early-return implementation skips a whole asymmetric
  // operation on the decrypt-failure arm and separates the stages by far more than that.
  EXPECT_LE(slowest, fastest * 1.25 + 1.0)
    << "token validation must complete in a fixed interval; stage medians in ms: fastest=" << fastest
    << " slowest=" << slowest;

  h->shutdown();
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, AuthenticatorDeadlineFailureCompletesOnceWithRichOperatorDetail)
{
  // Long enough that token decryption, which runs inside the interval before the authenticator is called,
  // leaves the authenticator well above the 200ms floor below even on a slow 32-bit Debug build.
  constexpr auto configuredAuthenticationInterval = 250ms;

  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<NonCompletingAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto logSink = std::make_shared<TokenValidationLogSink>();
  auto harness = make_token_validation_harness(
    SecurityPolicyId::Basic256, crypto, hooks, logSink, configuredAuthenticationInterval);

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto outcome = activate_with_token(*harness, 200, *token);

  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(outcome.isFault);
  EXPECT_EQ(outcome.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_EQ(outcome.responseCount, 1u);
  EXPECT_TRUE(authenticator->deadline().has_value())
    << "the application authenticator must receive the same fixed deadline";
  ASSERT_TRUE(authenticator->deadline_budget().has_value());
  EXPECT_GE(*authenticator->deadline_budget(), 200ms)
    << "the non-default authentication interval must determine the offered deadline";
  EXPECT_LE(*authenticator->deadline_budget(), configuredAuthenticationInterval);
  EXPECT_GE(outcome.elapsed, 220ms)
    << "the timeout response must be held behind the configured fixed interval";
  EXPECT_NE(logSink->joined().find("AuthenticationDeadlineExceeded"), std::string::npos)
    << "the peer receives an opaque identity-token failure, while the operator retains its cause";

  harness->shutdown();
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, EarlyAuthenticatorSuccessIsAnsweredWithoutTheFixedInterval)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<DelayedCompletingAuthenticator>(40ms);
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  constexpr auto configuredAuthenticationInterval = 125ms;
  auto harness = make_token_validation_harness(
    SecurityPolicyId::Basic256, crypto, hooks, nullptr, configuredAuthenticationInterval);

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto outcome = activate_with_token(*harness, 202, *token);

  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(outcome.isActivateResponse);
  EXPECT_TRUE(outcome.serviceResult.is_good());
  EXPECT_EQ(outcome.responseCount, 1u);
  // RATIFIED EXPECTATION CHANGE (owner decision 23, 2026-10-02): a successful ActivateSession answers
  // immediately; only failures are held to the fixed interval (Part 4 5.6.3.1: "Sporadic failures shall not
  // delay connections with valid tokens"). This test previously asserted the success was held >= 110 ms.
  EXPECT_GE(outcome.elapsed, 35ms) << "the authenticator itself takes 40 ms";
  EXPECT_LT(outcome.elapsed, 110ms) << "a success is not held to the 125 ms interval";
  EXPECT_TRUE(authenticator->deadline().has_value());

  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-AUTH-FLOW-02-ONE-ENDPOINT-SNAPSHOT, scope=function)
TEST(SessionTokenValidationTiming, AuthenticatorAndCommittedIdentityShareCompleteEndpointSecuritySnapshot)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, successAuthnTimeout);
  const auto selectedPolicyId = harness->channelInfo->user_identity_tokens().front().policy_id();

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto outcome = activate_with_token(*harness, 203, *token);

  ASSERT_TRUE(outcome.gotResponse);
  ASSERT_TRUE(outcome.isActivateResponse);
  ASSERT_TRUE(outcome.serviceResult.is_good());
  ASSERT_EQ(outcome.responseCount, 1u);

  const auto authenticatorSecurity = authenticator->last_security();
  ASSERT_NE(authenticatorSecurity, nullptr);
  EXPECT_EQ(authenticatorSecurity->endpointPolicyId, "L/None");
  EXPECT_EQ(authenticatorSecurity->messageSecurityMode, MessageSecurityMode::None);
  EXPECT_EQ(authenticatorSecurity->securityPolicyId, SecurityPolicyId::None);
  ASSERT_TRUE(authenticatorSecurity->userTokenPolicyId.has_value());
  EXPECT_EQ(*authenticatorSecurity->userTokenPolicyId, selectedPolicyId);
  EXPECT_TRUE(authenticatorSecurity->clientApplicationUri.empty())
    << "a claimed ApplicationUri on a None channel is not an authenticated application identity";
  EXPECT_EQ(authenticatorSecurity->endpointUrl, "opc.tcp://localhost:4840/token-validation");
  EXPECT_EQ(authenticatorSecurity->transportProfileUri,
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");

  const auto committedSecurity = SessionTestAccess::endpoint_security(*harness->session);
  const auto accessIdentity = SessionTestAccess::access_identity(*harness->session);
  ASSERT_NE(committedSecurity, nullptr);
  ASSERT_NE(accessIdentity, nullptr);
  EXPECT_EQ(committedSecurity.get(), authenticatorSecurity.get());
  EXPECT_EQ(&accessIdentity->endpoint(), authenticatorSecurity.get());

  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-AUTH-FLOW-03-COMPLETION-TIME-WINS, scope=function)
TEST(SessionTokenValidationTiming, TimelyCompletionWinsWhenDeadlineHandlerRunsFirst)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, 120ms);

  std::function<void(Session&)> parkedNotification;
  SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      guard.authenticator_completion_notification_gate() =
        [&parkedNotification](Session&, std::function<void(Session&)> continuation)
      {
        parkedNotification = std::move(continuation);
      };
    });

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto outcome = activate_with_token(*harness, 204, *token);

  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(outcome.isActivateResponse);
  EXPECT_TRUE(outcome.serviceResult.is_good());
  EXPECT_EQ(outcome.responseCount, 1u);
  EXPECT_GE(outcome.elapsed, 100ms)
    << "the parked strand notification should leave the deadline handler to consume the timely result";

  SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      ASSERT_TRUE(parkedNotification);
      guard.authenticator_completion_notification_gate() = {};
      auto staleNotification = std::move(parkedNotification);
      staleNotification(*harness->session);
    });
  drain_correlated_response(*harness);
  {
    const std::lock_guard<std::mutex> lock(harness->mutex);
    EXPECT_EQ(harness->responseCount, 1u);
  }

  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-AUTH-FLOW-03-COMPLETION-TIME-WINS, scope=function)
TEST(SessionTokenValidationTiming, CompletionAtDeadlineIsTimely)
{
  const auto deadline = std::chrono::steady_clock::now();
  EXPECT_TRUE(SessionTestAccess::authentication_completed_by_for_tests(deadline, deadline));
  EXPECT_FALSE(SessionTestAccess::authentication_completed_by_for_tests(
    deadline + std::chrono::nanoseconds{1}, deadline));
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, DuplicateAuthenticatorCompletionKeepsFirstRichResultAndRespondsOnce)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<DuplicateCompletingAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr);

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto outcome = activate_with_token(*harness, 201, *token);

  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(outcome.isFault);
  EXPECT_EQ(outcome.serviceResult, Status::BadUserAccessDenied);
  EXPECT_EQ(outcome.serviceResult.shared_detail(), authenticator->first_detail())
    << "delaying completion must not copy, replace, or discard the selected ErrorDetail";
  EXPECT_EQ(outcome.responseCount, 1u);
  EXPECT_FALSE(harness->session->is_activated())
    << "the duplicate late success must not replace the first refusal";

  harness->shutdown();
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, PreAuthenticationRefusalsShareTheFixedDeadline)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("testuser", "TestPassword123!");
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness = make_token_validation_harness(SecurityPolicyId::Basic256Sha256, crypto, hooks, nullptr);

  UserNameIdentityToken cleartextToken;
  cleartextToken.user_name() = "testuser";
  cleartextToken.password() = make_token_validation_password("TestPassword123!");

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto cleartext = activate_with_token(*harness, 210, cleartextToken);
  ASSERT_TRUE(cleartext.gotResponse);
  EXPECT_TRUE(cleartext.isFault);
  EXPECT_TRUE(cleartext.serviceResult.is_bad());
  EXPECT_EQ(cleartext.responseCount, 1u);
  EXPECT_GE(cleartext.elapsed, 45ms);
  EXPECT_FALSE(authenticator->called());

  auto encryptedToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);
  seed_token_validation_session(*harness, nonce, policy, identity);
  auto unknownPolicy = activate_with_token(*harness, 211, *encryptedToken, "unknown-policy-id");
  ASSERT_TRUE(unknownPolicy.gotResponse);
  EXPECT_TRUE(unknownPolicy.isFault);
  EXPECT_EQ(unknownPolicy.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_EQ(unknownPolicy.responseCount, 1u);
  EXPECT_GE(unknownPolicy.elapsed, 45ms);
  EXPECT_FALSE(authenticator->called());

  auto lockoutDetail = std::shared_ptr<const ErrorDetail>{
    make_error_detail("InjectedIdentityLockout", "Injected locked-out identity", "TokenValidationTest")};
  const StatusCode lockoutStatus{Status::BadUserAccessDenied, lockoutDetail};
  harness->sessDeps->checkLockout = [lockoutStatus](const auto&, std::string_view)
  {
    return optional<StatusCode>{lockoutStatus};
  };
  seed_token_validation_session(*harness, nonce, policy, identity);
  auto lockedOut = activate_with_token(*harness, 212, *encryptedToken);
  ASSERT_TRUE(lockedOut.gotResponse);
  EXPECT_TRUE(lockedOut.isFault);
  EXPECT_EQ(lockedOut.serviceResult, lockoutStatus);
  ASSERT_NE(lockedOut.serviceResult.shared_detail(), nullptr);
  EXPECT_EQ(lockedOut.serviceResult.shared_detail()->code, "Authentication");
  EXPECT_EQ(lockedOut.serviceResult.shared_detail()->innerStatus, lockoutStatus.value());
  ASSERT_NE(lockedOut.serviceResult.shared_detail()->cause, nullptr);
  EXPECT_EQ(lockedOut.serviceResult.shared_detail()->cause, lockoutDetail);
  EXPECT_EQ(lockedOut.responseCount, 1u);
  EXPECT_GE(lockedOut.elapsed, 45ms);
  EXPECT_FALSE(authenticator->called());

  harness->shutdown();
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, LateCompletionCannotAttachToReusedWireRequestId)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<ReusedRequestIdAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, 120ms);

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto timedOutA = activate_with_token(*harness, 220, *token);
  ASSERT_TRUE(timedOutA.gotResponse);
  EXPECT_TRUE(timedOutA.isFault);
  EXPECT_EQ(timedOutA.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_EQ(timedOutA.responseCount, 1u);

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto parkedB = activate_with_token(*harness, 220, *token);
  ASSERT_TRUE(parkedB.gotResponse);
  EXPECT_TRUE(parkedB.isFault)
    << "activation B consumed activation A's late success after the wire requestId was reused";
  EXPECT_EQ(parkedB.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_EQ(parkedB.responseCount, 1u);
  EXPECT_FALSE(harness->session->is_activated());

  harness->shutdown();
}

void expect_intermediate_auth_completion_not_to_cross_flow(bool parkParsedIdentityCompletion)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, 120ms);

  optional<std::function<void(Session&)>> parkedCompletion;
  auto gate = [&parkedCompletion](Session& current, std::function<void(Session&)> completion)
  {
    if (!parkedCompletion.has_value())
    {
      parkedCompletion.emplace(std::move(completion));
      return;
    }
    auto staleCompletion = std::move(*parkedCompletion);
    parkedCompletion = std::move(completion);
    staleCompletion(current);
  };
  SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      if (parkParsedIdentityCompletion)
        guard.parsed_identity_completion_gate() = gate;
      else
        guard.user_token_signature_completion_gate() = gate;
    });

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto timedOutA = activate_with_token(*harness, 225, *token);
  ASSERT_TRUE(timedOutA.gotResponse);
  ASSERT_TRUE(timedOutA.isFault);

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto parkedB = activate_with_token(*harness, 225, *token);
  ASSERT_TRUE(parkedB.gotResponse);
  EXPECT_TRUE(parkedB.isFault) << "activation B consumed activation A's late intermediate-stage completion";
  EXPECT_EQ(parkedB.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_EQ(parkedB.responseCount, 1u);
  EXPECT_FALSE(harness->session->is_activated());

  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard)
    {
      guard.parsed_identity_completion_gate() = {};
      guard.user_token_signature_completion_gate() = {};
    });
  parkedCompletion.reset();
  harness->shutdown();
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, LateParsedIdentityCannotAttachToNextFlow)
{
  expect_intermediate_auth_completion_not_to_cross_flow(true);
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, LateUserTokenSignatureCannotAttachToNextFlow)
{
  expect_intermediate_auth_completion_not_to_cross_flow(false);
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST(SessionTokenValidationTiming, ThrowingLockoutBookkeepingCannotLoseThePrimaryResultOrCompletion)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("WrongPassword123!"),
    nonce);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr);
  harness->sessDeps->recordFailure = [](const auto&, std::string_view)
  {
    throw UaException{Status::BadInternalError,
      make_error_detail("InjectedBookkeepingFailure", "Injected lockout bookkeeping failure", "Test")};
  };

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto refused = activate_with_token(*harness, 230, *token);
  ASSERT_TRUE(refused.gotResponse);
  EXPECT_TRUE(refused.isFault);
  EXPECT_EQ(refused.serviceResult, Status::BadUserAccessDenied);
  EXPECT_EQ(refused.serviceResult.shared_detail(), authenticator->last_failure_detail());
  EXPECT_EQ(refused.responseCount, 1u);

  harness->sessDeps->recordFailure = {};
  seed_token_validation_session(*harness, nonce, policy, identity);
  auto second = activate_with_token(*harness, 231, *token);
  ASSERT_TRUE(second.gotResponse) << "the throwing secondary hook left AuthFlow stuck";
  EXPECT_EQ(second.serviceResult, Status::BadUserAccessDenied);
  EXPECT_EQ(second.responseCount, 1u);

  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-AUTH-FLOW-01-IDENTITY-STATE-FAILURE, scope=function)
TEST(SessionTokenValidationTiming, AuthenticatedUserInsertionFailureCompletesOnceAndRecovers)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, successAuthnTimeout);

  auto sentinel = std::shared_ptr<const ErrorDetail>{make_error_detail(
    "InjectedIdentityStateFailure", "Injected authenticated-user insertion failure", "Test")};
  SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      guard.authn_user_insert_failure_injector() = [sentinel]()
      {
        throw UaException{Status::BadInternalError, sentinel};
      };
    });

  seed_token_validation_session(*harness, nonce, policy, identity);
  auto failed = activate_with_token(*harness, 240, *token);
  ASSERT_TRUE(failed.gotResponse);
  EXPECT_TRUE(failed.isFault);
  EXPECT_EQ(failed.serviceResult, Status::BadInternalError);
  EXPECT_EQ(failed.responseCount, 1u);
  ASSERT_NE(failed.serviceResult.shared_detail(), nullptr);
  EXPECT_EQ(failed.serviceResult.shared_detail()->code, "Authentication");
  EXPECT_EQ(failed.serviceResult.shared_detail()->innerStatus, StatusCode{Status::BadInternalError}.value());
  EXPECT_EQ(failed.serviceResult.shared_detail()->cause, sentinel);
  EXPECT_FALSE(harness->session->is_activated());
  SessionTestAccess::on_strand(*harness->session,
    [](auto& guard)
    {
      EXPECT_EQ(guard.authn_user_by_request_id().count(240), 0u);
      EXPECT_EQ(guard.authn_endpoint_by_request_id().count(240), 0u);
    });

  SessionTestAccess::on_strand(
    *harness->session, [](auto& guard) { guard.authn_user_insert_failure_injector() = {}; });
  seed_token_validation_session(*harness, nonce, policy, identity);
  auto recovered = activate_with_token(*harness, 241, *token);
  ASSERT_TRUE(recovered.gotResponse);
  EXPECT_TRUE(recovered.isActivateResponse);
  EXPECT_TRUE(recovered.serviceResult.is_good());
  EXPECT_EQ(recovered.responseCount, 1u);
  EXPECT_TRUE(harness->session->is_activated());

  harness->shutdown();
}

namespace
{

/// Authenticator answering every attempt with the severity its test chose, for the one identity
/// "testuser", and counting the attempts it decided, so a test can tell an answer the SDK refused from a
/// refusal made before the authenticator was reached.
class ScriptedSeverityAuthenticator final : public UserAuthenticator
{
public:
  enum class Answer
  {
    UncertainWithoutValue,  ///< Uncertain_LastUsableValue holding no AuthnSuccess
    UncertainWithValue,  ///< Uncertain_LastUsableValue holding the AuthnSuccess for "testuser"
    Good,  ///< Good holding the AuthnSuccess for "testuser"
  };

  void answer_with(Answer answer)
  {
    mAnswer.store(answer);
  }

  [[nodiscard]] size_t calls() const
  {
    return mCalls.load();
  }

  void authenticate_async(AuthnRequest, AuthnComplete completion) noexcept override
  {
    ++mCalls;
    const UserIdentity user{.userId = "testuser", .displayName = "testuser", .claims = {}};
    switch (mAnswer.load())
    {
    case Answer::UncertainWithoutValue:
      completion(AuthnResult{StatusCode{Status::UncertainLastUsableValue}});
      return;
    case Answer::UncertainWithValue:
      completion(AuthnResult{
        AuthnSuccess{.user = user, .audit = "uncertain"}, StatusCode{Status::UncertainLastUsableValue}});
      return;
    case Answer::Good:
      completion(make_authn_success(user, "good"));
      return;
    }
  }

private:
  std::atomic<Answer> mAnswer{Answer::Good};
  std::atomic<size_t> mCalls{0};
};

}  // namespace

// The authenticator's answer decides whether a Session is activated, so the SDK acts on it, and an Uncertain
// answer is a failed attempt whether or not it holds an AuthnSuccess: the ActivateSession is refused
// Bad_InternalError whose cause is the AnswerUncertain refusal carrying the authenticator's code, the Session
// is not activated, the lockout counts a Failure, and the refusal is held to the authentication deadline like
// any failure. The third answer is the control: the same identity answered Good activates the Session and the
// lockout counts a Success.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(SessionAuthenticatorAnswer, AnUncertainAnswerIsAFailedAttemptWithOrWithoutAnAuthnSuccess)
{
  using Answer = ScriptedSeverityAuthenticator::Answer;
  constexpr auto authenticationInterval = 125ms;

  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  // A UserName token, so the attempt is one the identity lockout counts.
  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    nonce);

  std::atomic<size_t> failures{0};
  std::atomic<size_t> successes{0};
  auto authenticator = std::make_shared<ScriptedSeverityAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto harness =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, authenticationInterval);
  harness->sessDeps->recordFailure = [&failures](const auto&, std::string_view)
  {
    ++failures;
  };
  harness->sessDeps->recordSuccess = [&successes](const auto&, std::string_view)
  {
    ++successes;
  };

  struct Arm
  {
    Answer answer;
    const char* name;
  };

  uint32_t requestId = 700;
  for (const auto& arm : {Arm{Answer::UncertainWithoutValue, "an Uncertain answer without an AuthnSuccess"},
         Arm{Answer::UncertainWithValue, "an Uncertain answer holding an AuthnSuccess"}})
  {
    SCOPED_TRACE(arm.name);
    authenticator->answer_with(arm.answer);
    const size_t callsBefore = authenticator->calls();
    failures = 0;
    successes = 0;

    seed_token_validation_session(*harness, nonce, policy, identity);
    const auto refused = activate_with_token(*harness, ++requestId, *token);

    ASSERT_TRUE(refused.gotResponse);
    EXPECT_EQ(authenticator->calls(), callsBefore + 1) << "the authenticator did not decide the attempt";
    EXPECT_TRUE(refused.isFault);
    EXPECT_FALSE(refused.isActivateResponse);
    EXPECT_EQ(refused.serviceResult.as_status(), Status::BadInternalError)
      << to_string(refused.serviceResult);
    const auto& detail = refused.serviceResult.shared_detail();
    ASSERT_NE(detail, nullptr);
    ASSERT_NE(detail->cause, nullptr) << "the failure does not carry the refusal of the Uncertain answer";
    EXPECT_EQ(detail->cause->code, "AnswerUncertain");
    EXPECT_EQ(detail->cause->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
      << "the refusal does not carry the authenticator's Uncertain code";
    EXPECT_FALSE(harness->session->is_activated());
    EXPECT_EQ(failures.load(), 1u) << "the lockout did not count the attempt as a Failure";
    EXPECT_EQ(successes.load(), 0u);
    EXPECT_GE(refused.elapsed, 110ms) << "the refusal was not held to the authentication deadline";
  }

  authenticator->answer_with(Answer::Good);
  failures = 0;
  successes = 0;
  seed_token_validation_session(*harness, nonce, policy, identity);
  const auto accepted = activate_with_token(*harness, ++requestId, *token);
  ASSERT_TRUE(accepted.gotResponse);
  EXPECT_TRUE(accepted.isActivateResponse) << "the control: " << to_string(accepted.serviceResult);
  EXPECT_TRUE(accepted.serviceResult.is_good());
  EXPECT_TRUE(harness->session->is_activated());
  EXPECT_EQ(successes.load(), 1u);
  EXPECT_EQ(failures.load(), 0u);

  harness->sessDeps->recordFailure = {};
  harness->sessDeps->recordSuccess = {};
  harness->shutdown();
}

// Part 4 section 7.41.2.1 with Table 18: one status code for every validation failure, and nothing
// else that separates them. Returning the single code while attaching a helpful description of what
// actually went wrong satisfies the letter of the obligation and defeats it entirely - and a helpful
// diagnostic is exactly what gets added while debugging authentication. The request asks for every
// diagnostic the server is willing to produce, so anything it would disclose is in view here.
// @verifies AC-SVR-IDENT-005-NO-DETAIL-LEAK
TEST(SessionTokenValidationDisclosure, ValidationFailuresReturnOneCodeAndDiscloseNothingFurther)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);

  auto currentNonce = make_token_validation_nonce(*crypto, 32);
  auto staleNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_NE(currentNonce, staleNonce);
  const auto password = make_token_validation_password("TestPassword123!");

  auto stages =
    make_token_validation_stages(policy, crypto, identity.certificate, currentNonce, staleNonce, password);
  ASSERT_EQ(stages.size(), 3u);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr);

  std::vector<TokenValidationOutcome> outcomes;
  uint32_t requestId = 200;
  for (const auto& stage : stages)
  {
    seed_token_validation_session(*h, currentNonce, policy, identity);
    auto outcome = activate_with_token(*h, ++requestId, *stage.token);
    ASSERT_TRUE(outcome.gotResponse) << "no response for stage " << stage.name;
    ASSERT_TRUE(outcome.isFault) << "stage " << stage.name << " must be refused with a ServiceFault";
    outcomes.push_back(std::move(outcome));
  }
  ASSERT_EQ(outcomes.size(), stages.size());

  for (size_t i = 0; i < outcomes.size(); ++i)
  {
    EXPECT_EQ(outcomes[i].serviceResult, Status::BadIdentityTokenInvalid)
      << "stage " << stages[i].name << " must not be distinguishable by its status code";
    EXPECT_EQ(outcomes[i].stringTableSize, 0u)
      << "stage " << stages[i].name << " put a localised message on the wire";
    EXPECT_TRUE(outcomes[i].diagnosticsNull)
      << "stage " << stages[i].name << " attached service diagnostics to a token-validation refusal";
    EXPECT_TRUE(outcomes[i].additionalInfo.empty())
      << "stage " << stages[i].name << " disclosed diagnostic text: " << outcomes[i].additionalInfo;
  }

  // Nothing in the response may separate the stages, so every response must be the same response.
  for (size_t i = 1; i < outcomes.size(); ++i)
  {
    EXPECT_EQ(outcomes[i].serviceResult, outcomes[0].serviceResult)
      << "stage " << stages[i].name << " is distinguishable from stage " << stages[0].name
      << " by status code";
    EXPECT_EQ(outcomes[i].additionalInfo, outcomes[0].additionalInfo)
      << "stage " << stages[i].name << " is distinguishable from stage " << stages[0].name
      << " by diagnostic text";
  }

  h->shutdown();
}

// Part 4 section 7.41.2.1: "Servers shall log details of any failure to validate a UserIdentityToken."
// This is the other half of the masked wire response - the peer learns nothing and the operator
// learns everything - so the log has to carry the detail the response withholds. A plausible
// implementation logs the status code it just returned, which tells the operator only what the
// attacker already knows and leaves the constant-code response invisible from both sides.
// @verifies AC-SVR-IDENT-006-LOG-VALIDATION-FAILURES
TEST(SessionTokenValidationLogging, EveryValidationFailureIsLoggedWithTheDetailWithheldFromThePeer)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);

  auto currentNonce = make_token_validation_nonce(*crypto, 32);
  auto staleNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_NE(currentNonce, staleNonce);
  const auto password = make_token_validation_password("TestPassword123!");

  auto stages =
    make_token_validation_stages(policy, crypto, identity.certificate, currentNonce, staleNonce, password);
  ASSERT_EQ(stages.size(), 3u);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto logSink = std::make_shared<TokenValidationLogSink>();
  // The SDK's default deadline, not the harness's 50 ms: the log names the failed stage only if the stage's
  // decryption finishes inside the deadline, and under a sanitizer it can outlast 50 ms, when the log names
  // the deadline instead.
  auto h =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, logSink, successAuthnTimeout);

  uint32_t requestId = 300;
  for (const auto& stage : stages)
  {
    seed_token_validation_session(*h, currentNonce, policy, identity);
    logSink->clear();

    auto outcome = activate_with_token(*h, ++requestId, *stage.token);
    ASSERT_TRUE(outcome.gotResponse) << "no response for stage " << stage.name;
    ASSERT_TRUE(outcome.isFault) << "stage " << stage.name << " must be refused";

    ASSERT_GT(logSink->count(), 0u) << "stage " << stage.name << " produced no log record at all";

    const std::string logged = logSink->joined();
    EXPECT_NE(logged.find(stage.withheldDetail), std::string::npos)
      << "stage " << stage.name
      << " was refused without logging what failed: the operator log must name the stage (looked for \""
      << stage.withheldDetail << "\"), got:\n"
      << logged;
  }

  h->shutdown();
}

// Part 4 section 7.41.2: "... and shall lock out Client applications after five failures." The scope
// is the Client application. Keying the counter on the (client, user) pair instead lets an attacker
// cycle usernames from one client and never trip it, while keying it on the server as a whole would
// let one client deny service to everyone. The counting policy under test is the server's own
// (ServerImpl::record_auth_failure / check_identity_lockout), reached through the session
// dependencies exactly as production reaches it; the five failures are real refused activations.
// @verifies AC-SVR-IDENT-007-LOCKOUT-AFTER-FIVE
TEST(SessionIdentityLockout, ClientApplicationIsLockedOutAfterFiveTokenValidationFailures)
{
  boost::asio::thread_pool serverPool{1};
  auto serverExecutor = serverPool.get_executor();

  // Default identity throttling: maxFailedAttemptsBeforeLockout is 5, the figure section 7.41.2 fixes.
  ::ua::server::ServerConfig serverConfig;
  ASSERT_TRUE(serverConfig.identityThrottling.enabled);
  ASSERT_EQ(serverConfig.identityThrottling.maxFailedAttemptsBeforeLockout, 5u);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "LockoutListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ::ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));
    serverConfig.listeners().push_back(std::move(listener));
  }
  serverConfig.validate();
  frozen.server = std::move(serverConfig);

  auto server = ua::server::ServerImpl::create(serverExecutor,
    std::move(frozen),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  ASSERT_NE(server, nullptr);

  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("alice", "correct-horse");
  authenticator->add_credential("bob", "correct-horse");
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr);
  // The lockout decision belongs to the server, not to the fixture: these only forward.
  h->sessDeps->checkLockout = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    return ua::test_helpers::ServerImplTestAccess{*server}.begin_identity_attempt(client, user);
  };
  h->sessDeps->recordFailure = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Failure);
  };
  h->sessDeps->recordSuccess = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Success);
  };
  h->sessDeps->recordAbandoned = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Abandoned);
  };

  auto wrongToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "alice",
    make_token_validation_password("wrong-password"),
    serverNonce);
  auto aliceToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "alice",
    make_token_validation_password("correct-horse"),
    serverNonce);
  auto bobToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "bob",
    make_token_validation_password("correct-horse"),
    serverNonce);

  uint32_t requestId = 400;
  for (int attempt = 1; attempt <= 5; ++attempt)
  {
    seed_token_validation_session(*h, serverNonce, policy, identity);
    authenticator->reset_calls();
    auto outcome = activate_with_token(*h, ++requestId, *wrongToken);
    ASSERT_TRUE(outcome.gotResponse) << "no response for failure " << attempt;
    ASSERT_FALSE(outcome.isActivateResponse) << "failure " << attempt << " must be refused";
    ASSERT_TRUE(authenticator->called())
      << "failure " << attempt << " must be a real validation failure that reached the credential check";
  }

  // The sixth attempt carries valid credentials. It must be refused by the lockout, and the lockout
  // must short-circuit before the credential check - otherwise the counter caps nothing.
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto sixth = activate_with_token(*h, ++requestId, *aliceToken);
  ASSERT_TRUE(sixth.gotResponse) << "the sixth attempt produced no response";
  EXPECT_FALSE(sixth.isActivateResponse)
    << "the sixth attempt after five failures must be refused by the lockout, not activated";
  EXPECT_TRUE(sixth.isFault) << "the lockout refusal must surface as a ServiceFault";
  EXPECT_FALSE(authenticator->called())
    << "a locked-out Client application must be refused without consulting the credential store";

  // The lockout is scoped to the Client application: the same client presenting a different user
  // with valid credentials is still locked out. Scoping it to the user instead lets an attacker
  // cycle usernames from one client and never trip the counter.
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto otherUser = activate_with_token(*h, ++requestId, *bobToken);
  ASSERT_TRUE(otherUser.gotResponse) << "the different-user attempt produced no response";
  EXPECT_FALSE(otherUser.isActivateResponse)
    << "the lockout is scoped to the Client application: the same client must stay locked out when it "
       "presents a different user";
  EXPECT_FALSE(authenticator->called())
    << "a locked-out Client application must be refused whichever user it claims";

  // ... and it is not the server as a whole: a different Client application is unaffected.
  ASSERT_TRUE(h->channelInfo.has_value());
  const auto lockedClient = ua::server::derive_client_id(*h->channelInfo);
  EXPECT_TRUE(
    ua::test_helpers::ServerImplTestAccess{*server}.check_identity_lockout(lockedClient, "alice").has_value())
    << "the Client application that failed five times must be locked out";
  const ::ua::server::ClientId otherClient{boost::asio::ip::make_address("203.0.113.7")};
  EXPECT_FALSE(
    ua::test_helpers::ServerImplTestAccess{*server}.check_identity_lockout(otherClient, "alice").has_value())
    << "the lockout must not extend to the server as a whole";

  h->shutdown();
  h->sessDeps->checkLockout = {};
  h->sessDeps->recordFailure = {};
  h->sessDeps->recordSuccess = {};
  h->sessDeps->recordAbandoned = {};
  h.reset();
  server.reset();
  ::ua::test_utils::drain_with_timeout(serverPool);
}

// @verifies AC-SVR-IDENT-007-CONCURRENT-ATTEMPTS-ARE-RESERVED
TEST(SessionIdentityLockout, ARefusedActivationReleasesItsReservationAndCountsOneFailure)
{
  boost::asio::thread_pool serverPool{1};
  auto serverExecutor = serverPool.get_executor();

  // Default identity throttling: maxFailedAttemptsBeforeLockout is 5, the figure section 7.41.2 fixes.
  ::ua::server::ServerConfig serverConfig;
  ASSERT_TRUE(serverConfig.identityThrottling.enabled);
  ASSERT_EQ(serverConfig.identityThrottling.maxFailedAttemptsBeforeLockout, 5u);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "LockoutListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ::ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));
    serverConfig.listeners().push_back(std::move(listener));
  }
  serverConfig.validate();
  frozen.server = std::move(serverConfig);

  auto server = ua::server::ServerImpl::create(serverExecutor,
    std::move(frozen),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  ASSERT_NE(server, nullptr);

  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("alice", "correct-horse");
  authenticator->add_credential("bob", "correct-horse");
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr);
  // The lockout decision belongs to the server, not to the fixture: these only forward.
  h->sessDeps->checkLockout = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    return ua::test_helpers::ServerImplTestAccess{*server}.begin_identity_attempt(client, user);
  };
  h->sessDeps->recordFailure = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Failure);
  };
  h->sessDeps->recordSuccess = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Success);
  };
  h->sessDeps->recordAbandoned = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Abandoned);
  };

  auto wrongToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "alice",
    make_token_validation_password("wrong-password"),
    serverNonce);
  seed_token_validation_session(*h, serverNonce, policy, identity);
  auto outcome = activate_with_token(*h, 500, *wrongToken);
  ASSERT_TRUE(outcome.gotResponse);
  ASSERT_FALSE(outcome.isActivateResponse) << "the wrong password is refused";
  // The reservation taken at flow start is released with the failure: nothing stays in flight, one
  // failure is on the books, the client application is not yet locked out.
  EXPECT_EQ(ua::test_helpers::ServerImplTestAccess{*server}.identity_throttle_size(), 1u);
  EXPECT_EQ(ua::test_helpers::ServerImplTestAccess{*server}.total_identity_attempts_in_flight(), 0u);
  EXPECT_EQ(ua::test_helpers::ServerImplTestAccess{*server}.total_identity_failures(), 1u);
  h->sessDeps->checkLockout = {};
  h->sessDeps->recordFailure = {};
  h->sessDeps->recordSuccess = {};
  h->sessDeps->recordAbandoned = {};
  h->shutdown();
}

// @verifies AC-SVR-IDENT-007-CONCURRENT-ATTEMPTS-ARE-RESERVED
// A VALID activation holds its budget slot only until the authenticator answers: the success is recorded
// (releasing the slot) before the response is sent. Owner decision 23 (2026-10-02): a successful
// ActivateSession is answered immediately - only failures are held to the fixed interval (Part 4 5.6.3.1,
// "Sporadic failures shall not delay connections with valid tokens") - so the response is not held for the
// 600 ms failure hold either.
TEST(SessionIdentityLockout, AValidActivationReleasesItsReservationBeforeItIsAnswered)
{
  boost::asio::thread_pool serverPool{1};
  auto serverExecutor = serverPool.get_executor();

  // Default identity throttling: maxFailedAttemptsBeforeLockout is 5, the figure section 7.41.2 fixes.
  ::ua::server::ServerConfig serverConfig;
  ASSERT_TRUE(serverConfig.identityThrottling.enabled);
  ASSERT_EQ(serverConfig.identityThrottling.maxFailedAttemptsBeforeLockout, 5u);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "LockoutListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ::ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));
    serverConfig.listeners().push_back(std::move(listener));
  }
  serverConfig.validate();
  frozen.server = std::move(serverConfig);

  auto server = ua::server::ServerImpl::create(serverExecutor,
    std::move(frozen),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  ASSERT_NE(server, nullptr);

  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("alice", "correct-horse");
  authenticator->add_credential("bob", "correct-horse");
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(SecurityPolicyId::Basic256,
    crypto,
    hooks,
    nullptr,
    std::chrono::milliseconds{600});  // the failure hold a valid activation is not subject to
  // The lockout decision belongs to the server, not to the fixture: these only forward.
  h->sessDeps->checkLockout = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    return ua::test_helpers::ServerImplTestAccess{*server}.begin_identity_attempt(client, user);
  };
  h->sessDeps->recordFailure = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Failure);
  };
  h->sessDeps->recordSuccess = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Success);
  };
  h->sessDeps->recordAbandoned = [server](const ::ua::server::ClientId& client, std::string_view user)
  {
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Abandoned);
  };

  std::atomic<std::chrono::steady_clock::time_point::rep> successAt{0};
  h->sessDeps->recordSuccess = [server, &successAt](
                                 const ::ua::server::ClientId& client, std::string_view user)
  {
    successAt.store(std::chrono::steady_clock::now().time_since_epoch().count());
    ua::test_helpers::ServerImplTestAccess{*server}.finish_identity_attempt(
      client, user, ua::server::IdentityAttemptOutcome::Success);
  };
  auto aliceToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "alice",
    make_token_validation_password("correct-horse"),
    serverNonce);
  seed_token_validation_session(*h, serverNonce, policy, identity);
  const auto activatedAt = std::chrono::steady_clock::now();
  auto outcome = activate_with_token(*h, 600, *aliceToken);
  const auto respondedAt = std::chrono::steady_clock::now();
  ASSERT_TRUE(outcome.gotResponse);
  ASSERT_TRUE(outcome.isActivateResponse) << "the valid token activates";
  ASSERT_NE(successAt.load(), 0) << "the success was recorded";
  const auto released =
    std::chrono::steady_clock::time_point{std::chrono::steady_clock::duration{successAt.load()}};
  EXPECT_LE(released, respondedAt) << "the slot is released before the response is sent";
  EXPECT_LT(respondedAt - activatedAt, std::chrono::milliseconds{300})
    << "decision 23: a valid activation is answered without the 600 ms failure hold";
  EXPECT_EQ(ua::test_helpers::ServerImplTestAccess{*server}.total_identity_attempts_in_flight(), 0u);
  h->sessDeps->checkLockout = {};
  h->sessDeps->recordFailure = {};
  h->sessDeps->recordSuccess = {};
  h->sessDeps->recordAbandoned = {};
  h->shutdown();
}

// Part 4 section 7.41 Table 193: where the matched UserTokenPolicy names a SecurityPolicy other than
// None, the UserName secret has to arrive encrypted under it. A plausible implementation keys its
// handling off the token's own encryptionAlgorithm field - empty means "not encrypted, just read the
// password" - which makes the clear password the path of least resistance and silently downgrades
// every client that gets the encryption wrong. The control arm runs the same harness with a properly
// encrypted secret and activates, so the refusal cannot be an artefact of the fixture.
// @verifies AC-SVR-IDENT-008-UNP-ENCRYPTION-REQUIRED
TEST(SessionUserNameTokenEncryption, ClearUserNameSecretIsRefusedWhereTheTokenPolicyRequiresEncryption)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("testuser", "TestPassword123!");
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(
    SecurityPolicyId::Basic256Sha256, crypto, hooks, nullptr, successAuthnTimeout);

  // Stimulus first, on a session that has never activated: the secret is the UTF-8 password with no
  // encryption at all, presented against a UserTokenPolicy that names Basic256Sha256.
  UserNameIdentityToken clearToken;
  clearToken.user_name() = "testuser";
  clearToken.password() = make_token_validation_password("TestPassword123!");
  ASSERT_TRUE(clearToken.encryption_algorithm().empty());

  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto refused = activate_with_token(*h, 501, clearToken);
  ASSERT_TRUE(refused.gotResponse) << "the cleartext activation produced no response";
  EXPECT_FALSE(refused.isActivateResponse)
    << "a cleartext UserName password under a UserTokenPolicy naming Basic256Sha256 must be refused";
  EXPECT_TRUE(refused.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_TRUE(refused.serviceResult == Status::BadIdentityTokenInvalid ||
              refused.serviceResult == Status::BadIdentityTokenRejected ||
              refused.serviceResult == Status::BadSecurityPolicyRejected ||
              refused.serviceResult == Status::BadSecurityChecksFailed)
    << "the refusal must name the identity token or its security policy";
  // The other half of the observation: the server must not have read the clear password.
  EXPECT_FALSE(authenticator->called())
    << "the server accepted a secret it should have refused and handed it to the authenticator";
  EXPECT_NE(authenticator->last_password(), "TestPassword123!")
    << "the clear password reached the authenticator, so the encryption requirement was not applied";

  // Control: the same password, encrypted as the policy requires, activates through this harness.
  auto encryptedToken = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    serverNonce);
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto accepted = activate_with_token(*h, 502, *encryptedToken);
  ASSERT_TRUE(accepted.gotResponse) << "the control activation produced no response";
  ASSERT_TRUE(accepted.isActivateResponse)
    << "control: a correctly encrypted secret must activate, or the refusal above proves nothing";
  EXPECT_TRUE(accepted.serviceResult.is_good());
  EXPECT_EQ(authenticator->last_password(), "TestPassword123!");

  h->shutdown();
}

// Part 4 section 7.41.2: "The password secret exchanged with this format shall not exceed 64 bytes."
// The bound belongs to the legacy Table 186 format alone, which is not extensible. A server that
// never applies it accepts a secret the format cannot carry interoperably; one that applied it to the
// newer EncryptedSecret form would reject long passwords that form does support. The 64-byte control
// arm pins the boundary, so a refusal at 65 cannot be a refusal of long secrets in general. Both arms are
// built in the legacy format by the test's own encryptor: the production client sends a password of more
// than 64 bytes as an RsaEncryptedSecret (OPC 10000-4 1.05.07 7.40.4), so it never produces the secret this
// bound refuses.
// @verifies AC-SVR-IDENT-009-PASSWORD-LENGTH-LIMIT
TEST(SessionUserNameTokenLegacySecret, LegacyEncryptedSecretLongerThanSixtyFourBytesIsRefused)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  ASSERT_TRUE(policy->is_deprecated()) << "this bound is on the legacy secret format only";
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, successAuthnTimeout);

  const ByteString atLimit = make_token_validation_secret(64);
  const ByteString overLimit = make_token_validation_secret(65);
  ASSERT_EQ(atLimit.size(), 64u);
  ASSERT_EQ(overLimit.size(), 65u);

  // Control: exactly 64 bytes is within the format's cap and activates.
  auto atLimitToken = encrypt_legacy_secret_with_padding(
    policy, crypto, identity.certificate, "testuser", atLimit, serverNonce, std::vector<uint8_t>{});
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto accepted = activate_with_token(*h, 601, *atLimitToken);
  ASSERT_TRUE(accepted.gotResponse) << "the 64-byte control produced no response";
  ASSERT_TRUE(accepted.isActivateResponse)
    << "control: a 64-byte legacy secret must activate, or the refusal below proves nothing";
  EXPECT_TRUE(accepted.serviceResult.is_good());

  // Stimulus: one byte over the cap.
  auto overLimitToken = encrypt_legacy_secret_with_padding(
    policy, crypto, identity.certificate, "testuser", overLimit, serverNonce, std::vector<uint8_t>{});
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto refused = activate_with_token(*h, 602, *overLimitToken);
  ASSERT_TRUE(refused.gotResponse) << "the 65-byte activation produced no response";
  EXPECT_FALSE(refused.isActivateResponse)
    << "a legacy-format password secret over 64 bytes must be refused, not activated";
  EXPECT_TRUE(refused.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_FALSE(authenticator->called())
    << "a secret the legacy format cannot carry must never reach the authenticator";

  h->shutdown();
}

// Part 4 section 7.41.2.2: "A Client should not add any padding after the secret. If a Client adds
// padding then all bytes shall be zero. A Server shall check for padding added by Clients and ensure
// that all padding bytes are zeros." The padding sits inside the encrypted region, so a server that
// ignores it leaves bytes an attacker who cannot read the plaintext can still work in. The
// zero-padding control arm activates through the same harness, so the refusal is attributable to the
// non-zero bytes and not to the presence of padding.
// @verifies AC-SVR-IDENT-011-PADDING-ZERO-CHECKED
TEST(SessionUserNameTokenLegacySecret, NonZeroPaddingAfterTheEncryptedSecretIsRefused)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);
  const auto password = make_token_validation_password("TestPassword123!");

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, successAuthnTimeout);

  // Control: the same secret with all-zero padding is conforming and activates.
  auto zeroPadded = encrypt_legacy_secret_with_padding(
    policy, crypto, identity.certificate, "testuser", password, serverNonce, std::vector<uint8_t>(8, 0x00));
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto accepted = activate_with_token(*h, 701, *zeroPadded);
  ASSERT_TRUE(accepted.gotResponse) << "the zero-padding control produced no response";
  ASSERT_TRUE(accepted.isActivateResponse)
    << "control: zero padding is conforming and must activate, or the refusal below proves nothing";
  EXPECT_TRUE(accepted.serviceResult.is_good());
  EXPECT_EQ(authenticator->last_password(), "TestPassword123!");

  // Stimulus: the identical secret with one non-zero padding byte.
  auto badPadded = encrypt_legacy_secret_with_padding(policy,
    crypto,
    identity.certificate,
    "testuser",
    password,
    serverNonce,
    std::vector<uint8_t>{0x00, 0x07, 0x00});
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto refused = activate_with_token(*h, 702, *badPadded);
  ASSERT_TRUE(refused.gotResponse) << "the non-zero-padding activation produced no response";
  EXPECT_FALSE(refused.isActivateResponse)
    << "an encrypted secret carrying non-zero padding must be refused, not activated";
  EXPECT_TRUE(refused.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_EQ(refused.serviceResult, Status::BadIdentityTokenInvalid)
    << "every legacy token-validation error must use the non-disclosing status";
  EXPECT_FALSE(authenticator->called()) << "a token with invalid padding must never reach the authenticator";

  h->shutdown();
}

// OPC 10000-4 7.40.4 allows a 64-byte password in the legacy format and 5.7.2 a 128-byte serverNonce, so the
// legacy plaintext is 196 bytes, two RSA-OAEP-SHA256 blocks of the 2048-bit server key (190 bytes each). A
// None endpoint whose token policies include RSA_DH has a 128-byte Session nonce, so this is a real secret.
// @relation(AC-CL-IDENT-005-LEGACY-SECRET-SPANS-RSA-BLOCKS, scope=function)
TEST(SessionUserNameTokenLegacyBlocks, TheServerDecryptsALegacySecretOfTwoBlocks)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  const auto serverNonce = make_token_validation_nonce(*crypto, 128);
  const std::string passwordText(64, 'p');
  const auto password = make_token_validation_password(passwordText);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto h = make_token_validation_harness(
    SecurityPolicyId::Aes256Sha256RsaPss, crypto, hooks, nullptr, successAuthnTimeout);

  auto token = encrypt_legacy_secret_with_padding(
    policy, crypto, identity.certificate, "testuser", password, serverNonce, std::vector<uint8_t>{});
  ASSERT_EQ(
    token->password().size(), 2 * policy->asymmetric_ciphertext_block_size(identity.certificate.get()))
    << "the precondition: the secret is two ciphertext blocks";
  seed_token_validation_session(*h, serverNonce, policy, identity);
  auto accepted = activate_with_token(*h, 801, *token);
  ASSERT_TRUE(accepted.gotResponse);
  ASSERT_TRUE(accepted.isActivateResponse)
    << "a two-block legacy secret was refused: 0x" << std::hex << accepted.serviceResult.as_uint32();
  EXPECT_TRUE(accepted.serviceResult.is_good());
  EXPECT_EQ(authenticator->last_password(), passwordText);

  h->shutdown();
}

// The longest legacy secret is two blocks of this key, so a secret of three is refused before it is
// decrypted - here a 64-byte password, a 128-byte nonce and 200 bytes of zero padding, which the parser
// would otherwise accept.
// @relation(AC-SVR-IDENT-008-LEGACY-SECRET-BLOCKS-ARE-BOUNDED, scope=function)
TEST(SessionUserNameTokenLegacyBlocks, ASecretOfMoreBlocksThanTheLongestLegacySecretIsRefused)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  const auto serverNonce = make_token_validation_nonce(*crypto, 128);
  const auto password = make_token_validation_password(std::string(64, 'p'));

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto h = make_token_validation_harness(SecurityPolicyId::Aes256Sha256RsaPss, crypto, hooks, nullptr);

  auto token = encrypt_legacy_secret_with_padding(
    policy, crypto, identity.certificate, "testuser", password, serverNonce, std::vector<uint8_t>(200, 0x00));
  ASSERT_EQ(
    token->password().size(), 3 * policy->asymmetric_ciphertext_block_size(identity.certificate.get()))
    << "the precondition: the secret is three ciphertext blocks";
  seed_token_validation_session(*h, serverNonce, policy, identity);
  auto refused = activate_with_token(*h, 802, *token);
  ASSERT_TRUE(refused.gotResponse);
  EXPECT_FALSE(refused.isActivateResponse) << "a three-block legacy secret activated the Session";
  EXPECT_TRUE(refused.isFault);
  EXPECT_EQ(refused.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(authenticator->called());

  h->shutdown();
}

// Part 4 section 7.41.2.2: "When encrypting a UserIdentityToken, the Client appends the last
// ServerNonce to the secret." Without it the encrypted secret is a replayable blob - it is encrypted
// under the server's fixed public key, so it decrypts identically on every activation and an observer
// who captures one exchange authenticates as that user forever. A plausible implementation strips a
// fixed-size tail and uses the remainder as the password without ever comparing that tail. Both the
// omitted-nonce and the stale-nonce secret must be refused; the control arm runs the same harness
// with the nonce the server last issued, so neither refusal can be a fixture artefact.
// @verifies AC-SVR-IDENT-010-NONCE-APPENDED
TEST(SessionUserNameTokenNonceBinding, SecretsOmittingTheNonceAndCarryingAStaleNonceAreBothRefused)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);

  auto currentNonce = make_token_validation_nonce(*crypto, 32);
  auto staleNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_NE(currentNonce, staleNonce);
  const auto password = make_token_validation_password("TestPassword123!");

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, successAuthnTimeout);

  auto boundToken =
    encrypt_user_name_token(policy, crypto, identity.certificate, "testuser", password, currentNonce);
  auto omittedNonceToken =
    encrypt_user_name_token(policy, crypto, identity.certificate, "testuser", password, ByteString{});
  auto staleNonceToken =
    encrypt_user_name_token(policy, crypto, identity.certificate, "testuser", password, staleNonce);

  // Control: the secret carrying the nonce the server last issued is accepted.
  seed_token_validation_session(*h, currentNonce, policy, identity);
  authenticator->reset_calls();
  auto bound = activate_with_token(*h, 801, *boundToken);
  ASSERT_TRUE(bound.gotResponse) << "the control activation produced no response";
  ASSERT_TRUE(bound.isActivateResponse)
    << "control: the correctly bound secret must activate, or the refusals below prove nothing";
  EXPECT_TRUE(bound.serviceResult.is_good());
  EXPECT_EQ(authenticator->last_password(), "TestPassword123!");

  // First stimulus: the encrypted secret omits the ServerNonce entirely.
  seed_token_validation_session(*h, currentNonce, policy, identity);
  authenticator->reset_calls();
  auto omitted = activate_with_token(*h, 802, *omittedNonceToken);
  ASSERT_TRUE(omitted.gotResponse) << "the omitted-nonce activation produced no response";
  EXPECT_FALSE(omitted.isActivateResponse)
    << "an encrypted secret with no appended ServerNonce must be refused, not activated";
  EXPECT_TRUE(omitted.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_FALSE(authenticator->called()) << "a secret with no ServerNonce must never reach the authenticator";

  // Second stimulus: the encrypted secret carries a nonce from an earlier exchange - the replay.
  seed_token_validation_session(*h, currentNonce, policy, identity);
  authenticator->reset_calls();
  auto stale = activate_with_token(*h, 803, *staleNonceToken);
  ASSERT_TRUE(stale.gotResponse) << "the stale-nonce activation produced no response";
  EXPECT_FALSE(stale.isActivateResponse)
    << "an encrypted secret carrying a superseded ServerNonce must be refused, not activated";
  EXPECT_TRUE(stale.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_FALSE(authenticator->called()) << "a replayed secret must never reach the authenticator";

  h->shutdown();
}

// Part 4 section 7.41.4 Table 193 row 1 describes the wire form of a None-policy UserName secret: "If the
// SecurityPolicy is None then the password only contains the UTF-8 encoded password" - no
// encryptionAlgorithm and no appended ServerNonce. The token built below is exactly that form, and it is
// the stimulus rather than the observation. Whether the server then honours it is conditional: acceptance
// requires the explicit plaintext opt-in, and this activation configures none. Under either branch open to
// the SDK - supporting the opt-in, or refusing every None-policy UserName policy outright - an activation
// with no opt-in in force must be refused rather than authenticated, so that is what is asserted. The
// refusal is not pinned to a particular status code, since nothing obliges one; what must not happen is a
// cleartext secret being honoured by default. The session is still seeded with a live ServerNonce so the
// refusal cannot be an artefact of missing CreateSession state.
// @verifies AC-SVR-IDENT-014-NONE-POLICY-CLEARTEXT
TEST(SessionUserNameTokenPlaintext, NonePolicyUserNameCleartextSecretIsNotHonouredWithoutAPlaintextOptIn)
{
  auto crypto = make_token_validation_crypto();
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_FALSE(serverNonce.empty()) << "the activation needs the CreateSession nonce a real session holds";
  // Only names which certificate slot the seeded server key occupies; the None-policy secret below is
  // never decrypted, so no part of the decision under test comes from this.
  auto certPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("testuser", "TestPassword123!");
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  // A None channel advertising exactly one UserName UserTokenPolicy whose SecurityPolicy is None, and no
  // plaintext opt-in anywhere in the configuration this harness stands up.
  auto h = make_token_validation_harness(SecurityPolicyId::None, crypto, hooks, nullptr);

  const auto password = make_token_validation_password("TestPassword123!");
  UserNameIdentityToken clearToken;
  clearToken.user_name() = "testuser";
  clearToken.password() = password;
  ASSERT_TRUE(clearToken.encryption_algorithm().empty())
    << "the stimulus is a None-policy secret, which names no encryption algorithm";
  ASSERT_EQ(clearToken.password(), password)
    << "the stimulus is the UTF-8 password itself, with no encryption and no appended nonce";

  seed_token_validation_session(*h, serverNonce, certPolicy, identity);
  authenticator->reset_calls();
  auto outcome = activate_with_token(*h, 901, clearToken);
  ASSERT_TRUE(outcome.gotResponse) << "the None-policy cleartext activation produced no response";
  EXPECT_FALSE(outcome.serviceResult.is_good())
    << "with no plaintext opt-in configured, a cleartext None-policy UserName secret must not activate a "
       "session";
  EXPECT_FALSE(outcome.isActivateResponse)
    << "a refused activation must be answered as a fault, not as a successful ActivateSessionResponse";

  h->shutdown();
}

namespace
{

/// Approves every identity it is handed and records the issued-token bytes that came with it, so a test
/// can prove both that a refusal did not originate in the application and that a tokenData the server
/// should have refused never reached the application at all.
class IssuedTokenRecordingAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mCallCount++;
      if (req.identity.issuedToken.has_value())
      {
        mLastIssuedToken = *req.identity.issuedToken;
      }
    }
    completion(make_authn_success(UserIdentity{.userId = "issued", .displayName = "Issued", .claims = {}}));
  }

  [[nodiscard]] bool called() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mCallCount > 0;
  }

  [[nodiscard]] ByteString last_issued_token() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastIssuedToken;
  }

private:
  mutable std::mutex mMutex;
  size_t mCallCount{0};
  ByteString mLastIssuedToken;
};

}  // namespace

// Part 4 section 7.41.6: "This token shall be encrypted by the Client if required by the SecurityPolicy of
// the UserTokenPolicy. ... If the SecurityPolicy is None then the tokenData only contains the UTF-8 encoded
// tokenData." An IssuedIdentityToken is a bearer credential, so an unencrypted one is reusable by anyone
// who observed it - a stronger consequence than an exposed password tied to one user. The tokenData is
// opaque to the SDK and validated by the application, which makes "forward whatever arrived" the natural
// implementation and leaves the encryption requirement unenforced: the clear bearer token then crosses the
// wire and reaches the application exactly as if it had been protected. The endpoint below advertises
// IssuedToken under Basic256Sha256 - a SecurityPolicy other than None - and the authenticator accepts every
// identity it is given, so the only thing that can refuse this activation is the encryption rule itself.
// @verifies AC-SVR-IDENT-018-ISSUEDTOKEN-ENCRYPTED
TEST(SessionIssuedIdentityToken, UnencryptedIssuedTokenDataIsRefusedWhereTheTokenPolicyIsNotNone)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto crypto = make_token_validation_crypto();
  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_FALSE(serverNonce.empty()) << "the activation needs the CreateSession nonce a real session holds";

  auto scDeps = std::make_shared<PolicyMirrorSecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  // Exactly one advertised user-token policy: IssuedToken under Basic256Sha256. Naming an encrypting
  // policy on the token is what Part 4 Table 193 keys the encryption requirement off, and it is also what
  // lets this run on a None channel without tripping the endpoint's own no-cleartext-secrets guard.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::IssuedToken, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  ServerComponents hooks;
  auto authenticator = std::make_shared<IssuedTokenRecordingAuthenticator>();
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto);
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  // The CreateSession-time state a wired CertificateStore would have produced, so the refusal below cannot
  // be an artefact of a session missing its nonce or its certificate.
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = serverNonce;
      g.server_certificates().clear();
      g.server_certificates().push_back(CertificateStore::ApplicationCertificate{
        tokenPolicy->certificate_type(), identity.certificate, identity.keys});
      g.selected_cert_and_key() = g.server_certificates().back();
    });

  // The stimulus: tokenData in the clear, with no encryptionAlgorithm - the wire form Part 4 section
  // 7.41.6 permits only where the UserTokenPolicy names SecurityPolicy None.
  const auto clearTokenData = make_token_validation_password("issued-bearer-token-payload");
  ASSERT_FALSE(clearTokenData.empty());
  auto token = std::make_unique<IssuedIdentityToken>();
  token->token_data() = clearTokenData;
  token->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  ASSERT_TRUE(token->encryption_algorithm().empty())
    << "the stimulus is unencrypted tokenData, which names no encryption algorithm";

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 1001;
  asr.user_identity_token() = std::move(token);
  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 5000ms, [&]() { return last.has_value(); }))
    << "the unencrypted issued-token activation produced no response";
  auto* activated = dynamic_cast<ActivateSessionResponse*>(last->second.get());
  EXPECT_EQ(activated, nullptr)
    << "an IssuedIdentityToken carrying unencrypted tokenData against a UserTokenPolicy naming "
       "Basic256Sha256 must be refused, not activated";
  auto* sf = dynamic_cast<ServiceFault*>(last->second.get());
  EXPECT_NE(sf, nullptr) << "the refusal must surface as a ServiceFault";
  if (sf != nullptr)
  {
    EXPECT_TRUE(sf->response_header().service_result().is_bad())
      << "the refusal must carry a bad service result";
  }
  lk.unlock();

  EXPECT_FALSE(session->is_activated()) << "a refused activation must leave the session unactivated";
  // The other half of the harm: an unprotected bearer credential must never be handed on to the
  // application as though it had arrived protected.
  EXPECT_FALSE(authenticator->called())
    << "the server accepted a bearer token it should have refused and handed it to the authenticator";
  EXPECT_NE(authenticator->last_issued_token(), clearTokenData)
    << "the clear tokenData reached the authenticator, so the encryption requirement was not applied";

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-IDENT-018-ISSUEDTOKEN-DECRYPTED, scope=function)
// @defect(D-ISSUEDIDENTITYTOKEN-ENCRYPTED-PAYLOAD-REACHES-AUTHENTICATOR-AS-CIPHERTEXT)
TEST(SessionIssuedIdentityToken, EncryptedTokenDataIsDecryptedBeforeAuthentication)
{
  boost::asio::thread_pool threadPool;
  const auto executor = threadPool.get_executor();

  auto crypto = make_token_validation_crypto();
  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  const auto serverNonce = make_token_validation_nonce(*crypto, 32);
  ASSERT_FALSE(serverNonce.empty());

  auto secureChannelDeps = std::make_shared<PolicyMirrorSecureDeps>(executor);
  auto secureChannel = SecureChannel::create(
    secureChannelDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*secureChannel,
    [&](auto& guard)
    {
      guard.set_minimal_context_none(executor,
        "L/None",
        {server::create_user_token_policy(UserTokenType::IssuedToken, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex responseMutex;
  std::condition_variable responseReady;
  optional<Response> response;
  SCTA::on_strand(*secureChannel,
    [&](auto& guard)
    {
      guard.set_response_sink(
        [&](const Response& received)
        {
          {
            const std::lock_guard<std::mutex> lock(responseMutex);
            response = received;
          }
          responseReady.notify_one();
        });
    });

  auto authenticator = std::make_shared<IssuedTokenRecordingAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto sessionDeps = std::make_shared<CryptoSessionDeps>(executor, hooks, crypto);
  SecureChannelInfo channelInfo(secureChannel->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*secureChannel, [](auto& guard) -> const auto& { return guard.user_identity_tokens(); }));
  auto session = Session::create(sessionDeps, channelInfo, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);
  SessionTestAccess::on_strand(*session,
    [&](auto& guard)
    {
      guard.server_nonce() = serverNonce;
      guard.server_certificates().clear();
      guard.server_certificates().push_back(CertificateStore::ApplicationCertificate{
        tokenPolicy->certificate_type(), identity.certificate, identity.keys});
      guard.selected_cert_and_key() = guard.server_certificates().back();
    });

  auto plainToken = make_token_validation_password("issued-bearer-token-payload");
  plainToken.push_back(uint8_t{0});
  plainToken.push_back(uint8_t{0xFF});
  auto token = encrypt_issued_token(tokenPolicy, crypto, identity.certificate, plainToken, serverNonce);
  ASSERT_NE(token->token_data(), plainToken);
  ASSERT_TRUE(token->encryption_algorithm().empty());
  token->policy_id() =
    SCTA::on_strand(*secureChannel, [](auto& guard) -> const auto& { return guard.user_identity_tokens(); })
      .front()
      .policy_id();

  ActivateSessionRequest request;
  request.request_header().request_handle() = 1002;
  request.user_identity_token() = std::move(token);
  session->activate(2, std::move(request), {});

  std::unique_lock<std::mutex> lock(responseMutex);
  ASSERT_TRUE(responseReady.wait_for(lock, 5000ms, [&]() { return response.has_value(); }))
    << "the valid encrypted issued-token activation produced no response";
  ASSERT_NE(dynamic_cast<ActivateSessionResponse*>(response->second.get()), nullptr)
    << "a valid encrypted IssuedIdentityToken must activate";
  lock.unlock();

  ASSERT_TRUE(authenticator->called());
  EXPECT_EQ(authenticator->last_issued_token(), plainToken)
    << "the application authenticator received the EncryptedSecret instead of its opaque plaintext";
  EXPECT_TRUE(session->is_activated());

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 7.40.6 Table 191: ignoring the outer algorithm must still decode tokenData.
// @relation(AC-SVR-IDENT-018-OUTER-ALGORITHM-IGNORED, scope=function)
TEST(SessionIssuedIdentityToken, NamedOuterAlgorithmsStillRequireTheRsaEncryptedEnvelope)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  const auto nonce = make_token_validation_nonce(*crypto, 32);
  auto plaintext = make_token_validation_password("opaque-issued-token");
  plaintext.push_back(uint8_t{0});
  plaintext.push_back(uint8_t{0xFF});

  for (const auto& algorithm : {String{}, String{"abc123"}, policy->uri()})
  {
    SCOPED_TRACE(static_cast<std::string>(algorithm));
    for (const bool malformed : {false, true})
    {
      SCOPED_TRACE(malformed);
      auto authenticator = std::make_shared<IssuedTokenRecordingAuthenticator>();
      ServerComponents hooks;
      hooks.authenticator = authenticator;
      auto harness = make_token_validation_harness(SecurityPolicyId::Basic256Sha256,
        crypto,
        hooks,
        nullptr,
        successAuthnTimeout,
        UserTokenType::IssuedToken);
      seed_token_validation_session(*harness, nonce, policy, identity);
      auto token = encrypt_issued_token(policy, crypto, identity.certificate, plaintext, nonce);
      ASSERT_NE(token->token_data(), plaintext);
      token->encryption_algorithm() = algorithm;
      if (malformed)
      {
        token->token_data() = make_token_validation_password("invalid encrypted token");
      }

      const auto outcome = activate_with_token(*harness, 1003, *token);
      ASSERT_TRUE(outcome.gotResponse);
      EXPECT_EQ(outcome.responseCount, 1u);
      if (malformed)
      {
        EXPECT_TRUE(outcome.isFault);
        EXPECT_EQ(outcome.serviceResult, StatusCode{Status::BadIdentityTokenInvalid});
        EXPECT_FALSE(authenticator->called());
        EXPECT_FALSE(harness->session->is_activated());
      }
      else
      {
        EXPECT_TRUE(outcome.isActivateResponse);
        EXPECT_EQ(outcome.serviceResult, StatusCode{Status::Good});
        EXPECT_TRUE(authenticator->called());
        EXPECT_EQ(authenticator->last_issued_token(), plaintext);
        EXPECT_TRUE(harness->session->is_activated());
      }
    }
  }
}

// Part 4 section 7.41.2.3 fixes the order in which an EncryptedSecret is taken apart: "Deserialize the
// common header; Verify the Signature if the KeyData is not encrypted; Decrypt the KeyData and verify the
// Signature if the KeyData is encrypted; Decrypt the payload; Verify the padding on the payload; Extract
// the Secret." The order is the security property, not the outcome - a server that decrypts the payload
// before authenticating it can be made to run attacker-chosen ciphertext through its own decryption, which
// is the construction this sequence exists to prevent.
//
// SCOPED TO THE BRANCH THIS DATATYPE HAS. For the RsaEncryptedSecret the KeyData is always encrypted -
// section 7.41.2.3: "the RsaEncryptedSecret requires that the KeyData be encrypted with the public key
// associated with the EncryptingCertificate" - so the third bullet governs and the second is unreachable.
// Requiring the Signature to be verified before ANY decryption would therefore fail a conforming
// implementation: the SigningKey only exists once the KeyData has been RSA-unwrapped. What section 7.41.2.3
// does oblige, and what is asserted, is that the Signature is verified before the PAYLOAD is decrypted.
// That is observed on the tampered-payload secret: flipping a byte inside the encrypted payload invalidates
// the MAC that covers it, so a verify-then-decrypt implementation fails at the verify step while a
// decrypt-then-verify one fails downstream in AES/padding, and the two are told apart by where the failure
// was raised.
//
// The four refusals are driven through a real ActivateSession, because "each is refused" is an obligation on
// the server's token handling rather than on the decoder in isolation; each arm additionally requires that
// the secret never reached the application authenticator, and the untampered control activates through the
// same harness so no refusal can be an artefact of the fixture.
TEST(SessionEncryptedSecretValidation, MalformedEncryptedSecretsAreRefusedAndTheSignatureIsVerifiedFirst)
{
  auto crypto = make_token_validation_crypto();
  // An RSA policy and a password longer than 64 bytes: the production encoder emits the EncryptedSecret form
  // for it (OPC 10000-4 7.40.4), and the legacy form for a shorter one.
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  // A second server identity, used to build a secret whose KeyData is wrapped to a public key whose private
  // half the server does not hold - an undecryptable KeyData with every other field well formed.
  auto foreign = make_token_validation_server_identity(crypto);
  ASSERT_NE(foreign.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);
  const auto password = make_token_validation_password(std::string(72, 'p'));

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->accept_everything();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto h = make_token_validation_harness(
    SecurityPolicyId::Basic256Sha256, crypto, hooks, nullptr, successAuthnTimeout);

  auto valid =
    encrypt_user_name_token(policy, crypto, identity.certificate, "testuser", password, serverNonce);
  ASSERT_TRUE(is_rsa_encrypted_secret(span<const byte>{valid->password()}))
    << "the stimulus must be an RsaEncryptedSecret; every arm below is a mutation of one";
  const size_t signatureSize = policy->symmetric_signature_size();
  ASSERT_GT(valid->password().size(), signatureSize + 1u);

  struct EncryptedSecretArm
  {
    std::string name;
    std::shared_ptr<UserNameIdentityToken> token;
  };

  std::vector<EncryptedSecretArm> arms;

  // Bullet 1 - deserialize the common header: a blob cut off inside the framing prefix, whose declared
  // Length matches nothing that follows.
  {
    auto token = std::make_shared<UserNameIdentityToken>(*valid);
    ByteString truncated;
    truncated.resize(8);
    std::memcpy(truncated.data(), valid->password().data(), truncated.size());
    token->password() = std::move(truncated);
    arms.push_back(EncryptedSecretArm{"malformed-header", token});
  }
  // Bullet 3 - decrypt the KeyData: wrapped to a certificate whose private key the server does not have.
  {
    auto token =
      encrypt_user_name_token(policy, crypto, foreign.certificate, "testuser", password, serverNonce);
    arms.push_back(EncryptedSecretArm{"undecryptable-keydata", token});
  }
  // Bullet 4 - decrypt the payload: one flipped byte inside the encrypted payload, which sits before the
  // trailing Signature and is covered by it.
  {
    auto token = std::make_shared<UserNameIdentityToken>(*valid);
    const size_t flipIndex = token->password().size() - signatureSize - 1u;
    token->password()[flipIndex] = static_cast<uint8_t>(token->password()[flipIndex] ^ 0xFFu);
    arms.push_back(EncryptedSecretArm{"tampered-payload", token});
  }
  // Bullet 3's verification half - the Signature itself does not authenticate the blob.
  {
    auto token = std::make_shared<UserNameIdentityToken>(*valid);
    const size_t lastIndex = token->password().size() - 1u;
    token->password()[lastIndex] = static_cast<uint8_t>(token->password()[lastIndex] ^ 0xFFu);
    arms.push_back(EncryptedSecretArm{"tampered-signature", token});
  }
  ASSERT_EQ(arms.size(), 4u) << "every step of the section 7.41.2.3 sequence must be exercised";

  // The refusals run FIRST, on a session that has never activated: presenting a token to an already-activated
  // session is the Part 4 change-user path, and a refusal raised there could be the server declining the
  // change rather than rejecting the secret - the confound the sibling row
  // `SessionUserNameTokenEncryption.ClearUserNameSecretIsRefusedWhereTheTokenPolicyRequiresEncryption` orders
  // around for the same reason. The control activation follows, on the same still-unactivated session.
  uint32_t requestId = 1110;
  for (const auto& arm : arms)
  {
    seed_token_validation_session(*h, serverNonce, policy, identity);
    authenticator->reset_calls();
    auto refused = activate_with_token(*h, ++requestId, *arm.token);
    ASSERT_TRUE(refused.gotResponse) << "arm " << arm.name << " produced no response";
    EXPECT_FALSE(refused.isActivateResponse)
      << "an EncryptedSecret failing at the " << arm.name << " step must be refused, not activated";
    EXPECT_TRUE(refused.isFault) << "arm " << arm.name << ": the refusal must surface as a ServiceFault";
    EXPECT_FALSE(authenticator->called())
      << "arm " << arm.name << ": a secret that failed validation must never reach the authenticator";
  }

  // Control: the untampered secret activates and the password arrives intact, so none of the four refusals
  // above can be an artefact of the harness.
  seed_token_validation_session(*h, serverNonce, policy, identity);
  authenticator->reset_calls();
  auto accepted = activate_with_token(*h, ++requestId, *valid);
  ASSERT_TRUE(accepted.gotResponse) << "the control activation produced no response";
  ASSERT_TRUE(accepted.isActivateResponse)
    << "control: a well-formed EncryptedSecret must activate, or the refusals above prove nothing";
  EXPECT_EQ(authenticator->last_password(), std::string(72, 'p'));

  // The ordering itself, taken on the tampered-payload secret: the MAC covering the payload is invalid, so a
  // server that verifies before it decrypts fails at the verify step. One that decrypted first would have
  // run the attacker's bytes through AES and failed somewhere downstream - in the padding check or in the
  // structure of what came out - and would report that step instead.
  const auto& tamperedPayload = arms[2].token->password();
  auto decoded = ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_rsa_encrypted_secret_async(ByteString{tamperedPayload},
        policy,
        crypto,
        crypto_test_strand(),
        identity.keys,
        identity.certificate,
        false,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(decoded.is_bad()) << "a flipped byte inside the encrypted payload must not decode";
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadIdentityTokenInvalid)
    << "a MAC mismatch is a token failure, not a downstream decoding error";
  ASSERT_NE(decoded.shared_detail(), nullptr) << "the failure must carry a source-tagged ErrorDetail saying "
                                                 "which step raised it";
  EXPECT_NE(decoded.shared_detail()->source.find("verify"), std::string::npos)
    << "the Signature must be verified before the payload is decrypted (Part 4 section 7.41.2.3); this "
       "failure was raised at \""
    << decoded.shared_detail()->source << "\"";

  h->shutdown();
}

// Part 6 section 6.8.3: "all UserTokenPolicies in an EndpointDescription shall specify a SecurityPolicyUri
// that is valid for all Certificates that are valid for SecurityPolicyUri specified in the
// EndpointDescription. For example, an EndpointDescription providing an ECC SecurityPolicyUri shall not
// specify RSA SecurityPolicyUris in the UserTokenPolicies." The rule is a property of the certificate
// families, so it runs in both directions even though the spec spells out only one: an ECC endpoint's
// certificates are not valid under an RSA token policy and an RSA endpoint's are not valid under an ECC one.
// Both are asserted because a check written from the example alone - "reject RSA token policies on an ECC
// endpoint" - passes the reverse by omission, and the reverse is the one that leaves a client holding an ECC
// UserTokenPolicy it can never satisfy: it would need an EphemeralKey the RSA handshake never produces, so
// every activation fails at a configuration the server advertised as usable. The same-family controls pin
// that the refusals come from the family mismatch and not from a blanket refusal of either policy.
// @verifies AC-SVR-IDENT-020-CROSS-FAMILY-REJECTED
TEST(EndpointUserTokenPolicyConfiguration, EccEndpointWithRsaTokenPolicyAndTheReverseAreBothRejected)
{
  constexpr auto rsaPolicy = SecurityPolicyId::Basic256Sha256;
  constexpr auto eccPolicy = SecurityPolicyId::EccNistP256AesGcm;

  ServerEndpointConfig config;
  config.name = "CrossFamilyUserToken";
  config.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;

  // An ECC channel carrying an RSA UserTokenPolicy - the case the clause names.
  config.securityPolicyId = eccPolicy;
  config.userIdentityTokens = {create_user_token_policy(UserTokenType::UserName, rsaPolicy)};
  ASSERT_FALSE(config.userIdentityTokens.empty());
  auto rsaOnEcc = validate_endpoint_user_token_policies(config);
  EXPECT_TRUE(rsaOnEcc.is_bad())
    << "an ECC endpoint must not advertise an RSA UserTokenPolicy (Part 6 section 6.8.3)";

  // Control on the same channel: an ECC UserTokenPolicy is the valid pairing, so the refusal above is
  // attributable to the family mismatch rather than to the ECC endpoint refusing every token policy.
  config.userIdentityTokens = {create_user_token_policy(UserTokenType::UserName, eccPolicy)};
  EXPECT_TRUE(validate_endpoint_user_token_policies(config).is_good())
    << "control: an ECC endpoint carrying an ECC UserTokenPolicy is a valid configuration";

  // The reverse: an RSA channel carrying an ECC UserTokenPolicy.
  config.securityPolicyId = rsaPolicy;
  config.userIdentityTokens = {create_user_token_policy(UserTokenType::UserName, eccPolicy)};
  auto eccOnRsa = validate_endpoint_user_token_policies(config);
  EXPECT_TRUE(eccOnRsa.is_bad())
    << "an RSA endpoint must not advertise an ECC UserTokenPolicy: its certificates are not valid under an "
       "ECC SecurityPolicy either";

  // Control on the RSA channel.
  config.userIdentityTokens = {create_user_token_policy(UserTokenType::UserName, rsaPolicy)};
  EXPECT_TRUE(validate_endpoint_user_token_policies(config).is_good())
    << "control: an RSA endpoint carrying an RSA UserTokenPolicy is a valid configuration";

  // The same rule inside one endpoint: two token policies from different families cannot both be valid for
  // the endpoint's certificates, whichever family the channel itself uses.
  config.securityPolicyId = rsaPolicy;
  config.userIdentityTokens = {create_user_token_policy(UserTokenType::UserName, rsaPolicy),
    create_user_token_policy(UserTokenType::Certificate, eccPolicy)};
  EXPECT_TRUE(validate_endpoint_user_token_policies(config).is_bad())
    << "one endpoint must not mix UserTokenPolicies from two certificate families";
}

namespace
{

using DurableResult = Result<uint32_t>;
using DurableChildCallback = std::function<void(StatusCode, uint32_t)>;
using DurableOperation =
  std::function<void(IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback)>;

class DurableCompletionProbe
{
public:
  void record(DurableResult result)
  {
    {
      const std::lock_guard lock{mMutex};
      ++mCount;
      mResult = std::move(result);
    }
    mCv.notify_all();
  }

  bool wait_for_count(size_t expected)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, 2s, [&]() { return mCount >= expected; });
  }

  size_t count() const
  {
    const std::lock_guard lock{mMutex};
    return mCount;
  }

  StatusCode status_code() const
  {
    const std::lock_guard lock{mMutex};
    return mResult->status_code();
  }

  std::shared_ptr<const ErrorDetail> shared_detail() const
  {
    const std::lock_guard lock{mMutex};
    return mResult->shared_detail();
  }

  uint32_t value() const
  {
    const std::lock_guard lock{mMutex};
    return mResult->value();
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  size_t mCount{0};
  optional<DurableResult> mResult;
};

Session::SetSubscriptionDurableCallback durable_callback(const std::shared_ptr<DurableCompletionProbe>& probe)
{
  return [probe](DurableResult result)
  {
    probe->record(std::move(result));
  };
}

void set_durable_operation(Session& session, DurableOperation operation)
{
  SessionTestAccess::on_strand(session,
    [operation = std::move(operation)](auto& guard) mutable
    { guard.set_subscription_durable_operation() = std::move(operation); });
}

}  // namespace

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-01-RICH-DEPENDENCY-FAILURE, scope=function)
TEST(SessionDurableRouting, ChildFailurePreservesExactRichResult)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto sentinel = std::shared_ptr<const ErrorDetail>{make_error_detail(
    "InjectedDurableChildFailure", "Injected durable child failure", "SessionDurableRoutingTest")};
  StatusCode failure{Status::BadResourceUnavailable, sentinel};
  set_durable_operation(*harness->session,
    [failure](IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback callback) mutable
    { callback(failure, 777u); });

  auto probe = std::make_shared<DurableCompletionProbe>();
  harness->session->set_subscription_durable_async(IntegerId{41}, 8, durable_callback(probe));

  ASSERT_TRUE(probe->wait_for_count(1));
  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->status_code(), failure);
  EXPECT_EQ(probe->shared_detail(), sentinel);
  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-01-RICH-DEPENDENCY-FAILURE, scope=function)
TEST(SessionDurableRouting, GoodChildCompletionReturnsRevisedLifetimeThroughSharedAdapter)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  set_durable_operation(*harness->session,
    [](IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback callback)
    { callback(StatusCode{Status::Good}, 31u); });

  auto probe = std::make_shared<DurableCompletionProbe>();
  harness->session->set_subscription_durable_async(IntegerId{47}, 8, durable_callback(probe));

  ASSERT_TRUE(probe->wait_for_count(1));
  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->value(), 31u);
  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-01-RICH-DEPENDENCY-FAILURE, scope=function)
TEST(SessionDurableRouting, ThrowingChildConvertsExactRichResultOnce)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto sentinel = std::shared_ptr<const ErrorDetail>{make_error_detail(
    "InjectedDurableChildThrow", "Injected durable child throw", "SessionDurableRoutingTest")};
  StatusCode failure{Status::BadInternalError, sentinel};
  set_durable_operation(*harness->session,
    [failure](IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback)
    { throw UaException{failure}; });

  auto probe = std::make_shared<DurableCompletionProbe>();
  harness->session->set_subscription_durable_async(IntegerId{42}, 8, durable_callback(probe));

  ASSERT_TRUE(probe->wait_for_count(1));
  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->status_code(), failure);
  EXPECT_EQ(probe->shared_detail(), sentinel);
  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-01-RICH-DEPENDENCY-FAILURE, scope=function)
TEST(SessionDurableRouting, FireThenThrowCompletesOnlyOnce)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto sentinel = std::shared_ptr<const ErrorDetail>{make_error_detail(
    "InjectedDurablePostFireThrow", "Injected post-completion throw", "SessionDurableRoutingTest")};
  StatusCode failure{Status::BadInternalError, sentinel};
  set_durable_operation(*harness->session,
    [failure](IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback callback)
    {
      callback(StatusCode{Status::Good}, 17u);
      throw UaException{failure};
    });

  auto probe = std::make_shared<DurableCompletionProbe>();
  harness->session->set_subscription_durable_async(IntegerId{43}, 8, durable_callback(probe));

  ASSERT_TRUE(probe->wait_for_count(1));
  SessionTestAccess::strand_barrier(*harness->session);
  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->value(), 17u);
  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-02-COMPLETION-ARITY, scope=function)
TEST(SessionDurableRouting, DuplicateChildCompletionIsConsumedOnce)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  optional<DurableChildCallback> retainedCompletion;
  set_durable_operation(*harness->session,
    [&](IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback callback)
    { retainedCompletion = std::move(callback); });

  auto probe = std::make_shared<DurableCompletionProbe>();
  harness->session->set_subscription_durable_async(IntegerId{44}, 8, durable_callback(probe));
  SessionTestAccess::strand_barrier(*harness->session);
  ASSERT_TRUE(retainedCompletion.has_value());

  (*retainedCompletion)(StatusCode{Status::Good}, 19u);
  (*retainedCompletion)(StatusCode{Status::Good}, 23u);
  SessionTestAccess::strand_barrier(*harness->session);

  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->value(), 19u);
  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-02-LATE-AFTER-DESTRUCTION, scope=function)
TEST(SessionDurableRouting, LateChildCompletionAfterSessionDestructionIsInert)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  optional<DurableChildCallback> retainedCompletion;
  set_durable_operation(*harness->session,
    [&](IntegerId, uint32_t, ServerConfig::SubscriptionLimits, DurableChildCallback callback)
    { retainedCompletion = std::move(callback); });

  auto probe = std::make_shared<DurableCompletionProbe>();
  harness->session->set_subscription_durable_async(IntegerId{45}, 8, durable_callback(probe));
  SessionTestAccess::strand_barrier(*harness->session);
  ASSERT_TRUE(retainedCompletion.has_value());

  std::weak_ptr<Session> weakSession = harness->session;
  harness->session.reset();
  ASSERT_TRUE(weakSession.expired());
  (*retainedCompletion)(StatusCode{Status::Good}, 29u);
  harness->shutdown();

  EXPECT_EQ(probe->count(), 0u);
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-03-MISSING-SUBSCRIPTION, scope=function)
TEST(SessionDurableRouting, MissingSubscriptionReturnsBadSubscriptionIdInvalidOnce)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto probe = std::make_shared<DurableCompletionProbe>();

  harness->session->set_subscription_durable_async(IntegerId{9999}, 8, durable_callback(probe));

  ASSERT_TRUE(probe->wait_for_count(1));
  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  harness->shutdown();
}

// @relation(AC-COMP-SVR-SESSION-DURABLE-ROUTING-03-SESSION-GONE, scope=function)
TEST(SessionDurableRouting, QueuedEntryAfterSessionDestructionReturnsBadSessionIdInvalidOnce)
{
  auto harness = make_session_harness(SecurityPolicyId::None, ByteString{});
  auto probe = std::make_shared<DurableCompletionProbe>();
  auto* session = harness->session.get();

  SessionTestAccess::post_on_strand(std::move(harness->session),
    [session, probe](auto&)
    { session->set_subscription_durable_async(IntegerId{46}, 8, durable_callback(probe)); });

  ASSERT_TRUE(probe->wait_for_count(1));
  EXPECT_EQ(probe->count(), 1u);
  EXPECT_EQ(probe->status_code(), StatusCode{Status::BadSessionIdInvalid});
  harness->shutdown();
}

namespace
{
/// Records the token the server observer receives on activation.
class ActivationTokenRecorder final : public ServerObserver
{
public:
  void on_session_activated(const SessionEventInfo& info) override
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mToken = info.userIdentityToken;
    mActivations++;
  }

  std::shared_ptr<const Structure> token() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mToken;
  }

  size_t activations() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mActivations;
  }

private:
  mutable std::mutex mMutex;
  std::shared_ptr<const Structure> mToken;
  size_t mActivations{0};
};

/// Accepts any credential and records the password bytes it was handed, embedded NULs included.
class PasswordCapturingAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    if (req.identity.password)
    {
      std::lock_guard<std::mutex> lk(mMutex);
      mPassword.assign(req.identity.password->view());
    }
    completion(
      make_authn_success(UserIdentity{.userId = "captured", .displayName = "Captured", .claims = {}}));
  }

  std::string password() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mPassword;
  }

private:
  mutable std::mutex mMutex;
  std::string mPassword;
};
}  // namespace

// SESS-4: the observer is application code; it receives the activating token the way the audit event
// does, with the password removed and the user name kept. Driven through the production observer
// wiring with a properly encrypted UserName token.
// @verifies AC-SVR-IDENT-021-OBSERVERS-RECEIVE-REDACTED-TOKENS
TEST(SessionCredentialHandling, ObserverReceivesTheActivatingTokenWithoutItsPassword)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("testuser", "TestPassword123!");
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto h = make_token_validation_harness(
    SecurityPolicyId::Basic256Sha256, crypto, hooks, nullptr, successAuthnTimeout);
  auto recorder = std::make_shared<ActivationTokenRecorder>();
  h->sessDeps->observerValue = recorder;

  auto token = encrypt_user_name_token(policy,
    crypto,
    identity.certificate,
    "testuser",
    make_token_validation_password("TestPassword123!"),
    serverNonce);
  seed_token_validation_session(*h, serverNonce, policy, identity);
  auto accepted = activate_with_token(*h, 601, *token);
  ASSERT_TRUE(accepted.gotResponse);
  ASSERT_TRUE(accepted.isActivateResponse) << "the control activation must succeed";
  ASSERT_EQ(recorder->activations(), 1u) << "the observer saw the activation";

  const auto observed = recorder->token();
  ASSERT_NE(observed, nullptr) << "the observer receives the token";
  const auto* userName = dynamic_cast<const UserNameIdentityToken*>(observed.get());
  ASSERT_NE(userName, nullptr);
  EXPECT_EQ(std::string_view{userName->user_name()}, "testuser") << "the user name identifies the user";
  EXPECT_TRUE(userName->password().empty()) << "the (encrypted) password never reaches an observer";
  h->shutdown();
}

// DEF-4: a password with an embedded NUL reaches the authenticator at its full length; the old
// conversion through a C string truncated it at the first NUL.
// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SessionCredentialHandling, PasswordWithAnEmbeddedNulReachesTheAuthenticatorAtFullLength)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);
  auto serverNonce = make_token_validation_nonce(*crypto, 32);

  auto authenticator = std::make_shared<PasswordCapturingAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto h = make_token_validation_harness(
    SecurityPolicyId::Basic256Sha256, crypto, hooks, nullptr, successAuthnTimeout);

  const std::string_view secret{"ab\0cd", 5};
  auto token = encrypt_user_name_token(
    policy, crypto, identity.certificate, "testuser", make_token_validation_password(secret), serverNonce);
  seed_token_validation_session(*h, serverNonce, policy, identity);
  auto accepted = activate_with_token(*h, 602, *token);
  ASSERT_TRUE(accepted.gotResponse);
  ASSERT_TRUE(accepted.isActivateResponse) << "the activation must succeed for the password to be observed";
  const auto password = authenticator->password();
  EXPECT_EQ(password.size(), 5u) << "the embedded NUL is part of the password, not its end";
  EXPECT_EQ(password, std::string{secret});
  h->shutdown();
}

namespace
{
// Basic256Sha256 in every algorithm and size, Aes128_Sha256_RsaOaep in the EncryptedSecret CommonHeader it
// writes: a secret it encrypts decrypts under the server's Basic256Sha256 token policy.
class HeaderMislabelledBasic256Sha256 final : public SecPolBasic256Sha256
{
public:
  String uri() const override
  {
    return SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep)->uri();
  }
};
}  // namespace

// Security review SESS-7(e), OPC 10000-4 7.41.2.3 / Table 189, for both token kinds that carry an
// EncryptedSecret (the UserName password and the IssuedToken tokenData decrypt at separate sites). A
// secret whose SecurityPolicyUri names another policy, or whose Certificate is the thumbprint of another
// certificate over the server's own key pair, decrypts cleanly - so only the header check can refuse it.
// Each refusal is Bad_IdentityTokenInvalid, never reaches the authenticator, leaves the Session
// unactivated, and logs the mismatch for the operator. The refusals run before the control on a
// never-activated Session (a presented token on an activated one would be a change of user); the control
// then activates with the correctly labelled secret through the same harness.
// @verifies AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED
TEST(SessionEncryptedSecretHeader, RsaHeaderMismatchesAreRefusedAndLoggedForUserNameAndIssuedTokens)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto identity = make_token_validation_server_identity(crypto);
  ASSERT_NE(identity.certificate, nullptr);

  TestPki pki{crypto};
  Crypto::CreateCertificateConfig params;
  params.subjectKeys = identity.keys;
  params.issuerKeys = identity.keys;
  params.subject.commonName = "TokenValidationServer";
  params.serialNumber = "2";
  params.basicConstraint.cA = false;
  params.keyUsage.digitalSignature = true;
  params.keyUsage.keyEncipherment = true;
  params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  params.from = DateTime::now();
  params.to = DateTime{params.from.value() + std::chrono::days{365}};
  auto siblingCert = pki.create_cert(params);
  ASSERT_NE(siblingCert->thumbprint(), identity.certificate->thumbprint());

  const auto nonce = make_token_validation_nonce(*crypto, 32);
  // Longer than 64 bytes, so the UserName password is an RsaEncryptedSecret too (OPC 10000-4 7.40.4); a
  // shorter one takes the legacy form, which has no header to check.
  const auto secret = make_token_validation_password(std::string(72, 'p'));
  const shared_ptr<const SecurityPolicy> mislabelled = std::make_shared<HeaderMislabelledBasic256Sha256>();

  for (const auto tokenType : {UserTokenType::UserName, UserTokenType::IssuedToken})
  {
    SCOPED_TRACE(tokenType == UserTokenType::UserName ? "UserNameIdentityToken" : "IssuedIdentityToken");
    auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
    authenticator->accept_everything();
    ServerComponents hooks;
    hooks.authenticator = authenticator;
    auto logSink = std::make_shared<TokenValidationLogSink>();
    auto h = make_token_validation_harness(
      SecurityPolicyId::Basic256Sha256, crypto, hooks, logSink, 50ms, tokenType);

    const auto run = [&](const shared_ptr<const SecurityPolicy>& encryptingPolicy,
                       const shared_ptr<const X509Certificate>& encryptingCertificate,
                       uint32_t requestId)
    {
      seed_token_validation_session(*h, nonce, policy, identity);
      logSink->clear();
      authenticator->reset_calls();
      if (tokenType == UserTokenType::UserName)
      {
        auto token =
          encrypt_user_name_token(encryptingPolicy, crypto, encryptingCertificate, "testuser", secret, nonce);
        // The token declares the server's policy whatever the header says, so only the header differs.
        token->encryption_algorithm() = policy->uri();
        return activate_with_token(*h, requestId, *token);
      }
      auto token = encrypt_issued_token(encryptingPolicy, crypto, encryptingCertificate, secret, nonce);
      return activate_with_token(*h, requestId, *token);
    };

    struct Arm
    {
      std::string name;
      shared_ptr<const SecurityPolicy> policy;
      shared_ptr<const X509Certificate> certificate;
      std::string loggedCode;
    };

    const std::vector<Arm> refusals{
      {"policy mismatch", mislabelled, identity.certificate, "EncryptedSecretPolicyMismatch"},
      {"certificate mismatch", policy, siblingCert, "EncryptedSecretCertificateMismatch"}};
    uint32_t requestId = 1300;
    for (const auto& arm : refusals)
    {
      const auto refused = run(arm.policy, arm.certificate, ++requestId);
      ASSERT_TRUE(refused.gotResponse) << arm.name << ": no response";
      EXPECT_TRUE(refused.isFault) << arm.name << ": the secret must be refused";
      EXPECT_EQ(refused.serviceResult, Status::BadIdentityTokenInvalid) << arm.name;
      EXPECT_FALSE(authenticator->called()) << arm.name << ": the secret reached the authenticator";
      EXPECT_FALSE(h->session->is_activated()) << arm.name;
      EXPECT_TRUE(SessionTestAccess::on_strand(
        *h->session, [](auto& g) { return g.session_info()->user_identity() == nullptr; }))
        << arm.name << ": the refused secret gave the Session an identity";
      EXPECT_NE(logSink->joined().find(arm.loggedCode), std::string::npos)
        << arm.name << ": the operator log must name the mismatch (" << arm.loggedCode << "), got:\n"
        << logSink->joined();
    }

    // control: the correctly labelled secret activates.
    const auto accepted = run(policy, identity.certificate, ++requestId);
    ASSERT_TRUE(accepted.gotResponse) << "control: no response";
    EXPECT_TRUE(accepted.isActivateResponse) << "control: a correctly labelled secret must activate, got: "
                                             << to_string(accepted.serviceResult.as_status());
    EXPECT_TRUE(authenticator->called());

    h->shutdown();
  }
}

// ---------------------------------------------------------------------------------------------------------
// Completeness review C6 - owner decision 23: success answers immediately; EVERY failure, including an X509
// user certificate refused by validation, is held to ServerConfig::authnTimeout (Part 4 7.41.2.1,
// 5.6.3.1). Lockout after five failures is unchanged (SessionIdentityLockout tests); the slow authenticator
// is still abandoned at the deadline (AuthenticatorDeadlineFailureCompletesOnceWithRichOperatorDetail). Rule
// assumed and asserted here: an X509 certificate refusal is a failure of user identity token validation and
// so counts towards the 7.41.2.1 lockout ("lock out Client applications after five failures").
// Completeness review C5, session side - decision 27: the refusal reaches
// ServerObserver::on_certificate_rejected with the presented certificate.
// ---------------------------------------------------------------------------------------------------------

namespace
{

constexpr auto decision23Interval = 300ms;

class CertificateRejectionRecorder final : public ServerObserver
{
public:
  void on_certificate_rejected(const ::ua::server::CertificateEventInfo& info) override
  {
    const std::lock_guard lock{mMutex};
    mRejections.push_back(info);
  }

  std::vector<::ua::server::CertificateEventInfo> rejections() const
  {
    const std::lock_guard lock{mMutex};
    return mRejections;
  }

private:
  mutable std::mutex mMutex;
  std::vector<::ua::server::CertificateEventInfo> mRejections;
};

struct X509User
{
  shared_ptr<const AsymmetricKeyPair> keys;
  shared_ptr<const X509Certificate> certificate;
};

X509User make_x509_user(const shared_ptr<const Crypto>& crypto)
{
  X509User user;
  user.keys = ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 60);
  TestPki pki{crypto};
  user.certificate = pki.create_leaf_cert(user.keys,
    user.keys,
    nullptr,
    DateTime{DateTime::now().value() - std::chrono::days{1}},
    DateTime{DateTime::now().value() + std::chrono::days{30}},
    {"urn:token-validation:user"},
    {},
    "Token Validation X509 User");
  return user;
}

/// The userTokenSignature a client computes for an X509 token: the user key's signature over the server
/// certificate followed by the last server nonce (Part 4 5.6.3.1), with the token policy's algorithm.
SignatureData x509_user_token_signature(const shared_ptr<const Crypto>& crypto,
  const shared_ptr<const SecurityPolicy>& policy, const X509User& user,
  const TokenValidationServerIdentity& identity, const ByteString& serverNonce)
{
  ByteString signedData = identity.certificate->der_encoding();
  std::ranges::copy(serverNonce, std::back_inserter(signedData));
  SignatureData signature;
  signature.algorithm() = std::string{policy->asymmetric_signature_algorithm_uri()};
  signature.signature() =
    crypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), user.keys, signedData);
  return signature;
}

X509IdentityToken x509_token(const X509User& user)
{
  X509IdentityToken token;
  token.certificate_data() = user.certificate->der_encoding();
  return token;
}

/// A harness advertising one X509 UserTokenPolicy, its user-token store answering every certificate with
/// @p storeStatus, and an authenticator accepting everything.
struct X509RefusalFixture
{
  shared_ptr<const Crypto> crypto = make_token_validation_crypto();
  shared_ptr<const SecurityPolicy> policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  TokenValidationServerIdentity identity = make_token_validation_server_identity(crypto);
  ByteString nonce = make_token_validation_nonce(*crypto, 32);
  X509User user = make_x509_user(crypto);
  shared_ptr<TokenCredentialAuthenticator> authenticator = std::make_shared<TokenCredentialAuthenticator>();
  shared_ptr<ua::test_helpers::FakeCertificateStore> store = ua::test_helpers::FakeCertificateStore::create();
  std::unique_ptr<TokenValidationHarness> harness;

  explicit X509RefusalFixture(StatusCode storeStatus)
  {
    authenticator->accept_everything();
    store->validateCertificateStatus = storeStatus;
    ServerComponents hooks;
    hooks.authenticator = authenticator;
    harness = make_token_validation_harness(
      SecurityPolicyId::Basic256, crypto, hooks, nullptr, decision23Interval, UserTokenType::Certificate);
    harness->sessDeps->set_user_token_certificate_store(store);
  }

  TokenValidationOutcome activate(uint32_t requestId)
  {
    seed_token_validation_session(*harness, nonce, policy, identity);
    return activate_with_token(*harness,
      requestId,
      x509_token(user),
      std::nullopt,
      x509_user_token_signature(crypto, policy, user, identity, nonce));
  }
};

TokenValidationOutcome activate_user_name(TokenValidationHarness& h, uint32_t requestId,
  const shared_ptr<const Crypto>& crypto, const shared_ptr<const SecurityPolicy>& policy,
  const TokenValidationServerIdentity& identity, const ByteString& nonce, const std::string& user,
  const std::string& password)
{
  seed_token_validation_session(h, nonce, policy, identity);
  const auto token = encrypt_user_name_token(
    policy, crypto, identity.certificate, user.c_str(), make_token_validation_password(password), nonce);
  return activate_with_token(h, requestId, *token);
}

}  // namespace

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-87-ACTIVATE-HOLDS-FAILURES-ONLY, scope=function)
TEST(SessionActivationFailureHold, ASuccessfulActivationAnswersWellUnderTheInterval)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("alice", "correct-horse");
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto h =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, decision23Interval);

  const auto outcome = activate_user_name(*h, 300, crypto, policy, identity, nonce, "alice", "correct-horse");
  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(outcome.serviceResult.is_good());
  EXPECT_LT(outcome.elapsed, decision23Interval / 2) << "decision 23: a success is not held";

  h->shutdown();
}

// Every failure kind is held no earlier than the interval: unknown user, wrong password, an authenticator
// refusal, and the three token-format faults (decrypt, padding, nonce).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-87-ACTIVATE-HOLDS-FAILURES-ONLY, scope=function)
TEST(SessionActivationFailureHold, EveryCredentialFailureIsHeldToTheInterval)
{
  auto crypto = make_token_validation_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  auto identity = make_token_validation_server_identity(crypto);
  auto nonce = make_token_validation_nonce(*crypto, 32);
  auto staleNonce = make_token_validation_nonce(*crypto, 32);
  auto authenticator = std::make_shared<TokenCredentialAuthenticator>();
  authenticator->add_credential("alice", "correct-horse");
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto h =
    make_token_validation_harness(SecurityPolicyId::Basic256, crypto, hooks, nullptr, decision23Interval);

  uint32_t requestId = 310;
  const std::pair<const char*, std::pair<const char*, const char*>> credentialFailures[]{
    {"unknown-user", {"mallory", "correct-horse"}},
    {"wrong-password", {"alice", "wrong-horse"}},
    {"authenticator-refusal", {"bob", "anything"}},
  };
  for (const auto& [name, credentials] : credentialFailures)
  {
    const auto outcome = activate_user_name(
      *h, ++requestId, crypto, policy, identity, nonce, credentials.first, credentials.second);
    ASSERT_TRUE(outcome.gotResponse) << name;
    EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::BadUserAccessDenied}.value()) << name;
    EXPECT_GE(outcome.elapsed, decision23Interval - 10ms) << name << " answered before the interval";
  }
  for (const auto& stage : make_token_validation_stages(policy,
         crypto,
         identity.certificate,
         nonce,
         staleNonce,
         make_token_validation_password("correct-horse")))
  {
    seed_token_validation_session(*h, nonce, policy, identity);
    const auto outcome = activate_with_token(*h, ++requestId, *stage.token);
    ASSERT_TRUE(outcome.gotResponse) << stage.name;
    EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::BadIdentityTokenInvalid}.value())
      << stage.name;
    EXPECT_GE(outcome.elapsed, decision23Interval - 10ms) << stage.name << " answered before the interval";
  }

  h->shutdown();
}

// An X509 user certificate refused by validation (item 8: the session validates before the authenticator) is
// held like every other failure, answers Bad_IdentityTokenRejected, and never reaches the authenticator.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-87-ACTIVATE-HOLDS-FAILURES-ONLY, scope=function)
TEST(SessionActivationFailureHold, AnX509CertificateRefusalIsHeldToTheInterval)
{
  X509RefusalFixture f{StatusCode{Status::BadCertificateUntrusted}};
  const auto outcome = f.activate(330);
  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::BadIdentityTokenRejected}.value());
  EXPECT_GE(outcome.elapsed, decision23Interval - 10ms);
  EXPECT_FALSE(f.authenticator->called());
  f.harness->shutdown();
}

// The certificate is validated before the userTokenSignature (owner decision 2026-10-03, BR-16): a token
// whose certificate is refused AND whose signature is invalid is refused for its certificate -
// Bad_IdentityTokenRejected - never Bad_UserSignatureInvalid. No key the validation refuses is used to verify
// anything. Falsifiable: the former order verified the signature first and answered Bad_UserSignatureInvalid.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-87-ACTIVATE-HOLDS-FAILURES-ONLY, scope=function)
TEST(SessionActivationFailureHold, AnX509CertificateIsValidatedBeforeItsSignature)
{
  X509RefusalFixture f{StatusCode{Status::BadCertificateUntrusted}};
  seed_token_validation_session(*f.harness, f.nonce, f.policy, f.identity);
  auto signature = x509_user_token_signature(f.crypto, f.policy, f.user, f.identity, f.nonce);
  std::vector<byte> tampered(signature.signature().size());
  std::memcpy(tampered.data(), signature.signature().data(), tampered.size());
  ASSERT_FALSE(tampered.empty());
  tampered.front() = static_cast<byte>(std::to_integer<unsigned char>(tampered.front()) ^ 0xFFU);
  signature.signature() = ByteString{std::move(tampered)};
  const auto outcome =
    activate_with_token(*f.harness, 335, x509_token(f.user), std::nullopt, std::move(signature));
  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_EQ(outcome.serviceResult.value(), StatusCode{Status::BadIdentityTokenRejected}.value())
    << "the certificate refusal is reported, not the signature";
  EXPECT_FALSE(f.authenticator->called());
  f.harness->shutdown();
}

// Control: the same X509 token with the store accepting the certificate activates, unheld.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-87-ACTIVATE-HOLDS-FAILURES-ONLY, scope=function)
TEST(SessionActivationFailureHold, AnAcceptedX509CertificateActivatesWithoutTheHold)
{
  X509RefusalFixture f{StatusCode{Status::Good}};
  const auto outcome = f.activate(331);
  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(outcome.serviceResult.is_good()) << to_string(outcome.serviceResult.as_status());
  EXPECT_LT(outcome.elapsed, decision23Interval / 2);
  f.harness->shutdown();
}

// Rule assumed (Part 4 7.41.2.1): a certificate refusal is a token-validation failure and is recorded towards
// the identity lockout exactly once.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-87-ACTIVATE-HOLDS-FAILURES-ONLY, scope=function)
TEST(SessionActivationFailureHold, AnX509CertificateRefusalCountsTowardsTheLockout)
{
  X509RefusalFixture f{StatusCode{Status::BadCertificateUntrusted}};
  auto failures = std::make_shared<std::atomic<int>>(0);
  f.harness->sessDeps->recordFailure = [failures](const ::ua::server::ClientId&, std::string_view)
  {
    failures->fetch_add(1);
  };
  const auto outcome = f.activate(332);
  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_EQ(failures->load(), 1);
  f.harness->shutdown();
}

// C5 session side: the refusal reaches on_certificate_rejected in the decision-27 form, carrying the
// presented user certificate, the Table 106 status and the peer address. Control: an accepted certificate
// raises none.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-94-USER-TOKEN-REFUSAL-OBSERVED, scope=function)
TEST(SessionActivationFailureHold, AnX509CertificateRefusalIsReportedWithTheCertificate)
{
  X509RefusalFixture f{StatusCode{Status::BadCertificateUntrusted}};
  auto recorder = std::make_shared<CertificateRejectionRecorder>();
  f.harness->sessDeps->observerValue = recorder;
  const auto outcome = f.activate(333);
  ASSERT_TRUE(outcome.gotResponse);
  const auto rejections = recorder->rejections();
  ASSERT_EQ(rejections.size(), 1u);
  EXPECT_EQ(rejections[0].status.value(), StatusCode{Status::BadCertificateUntrusted}.value());
  ASSERT_TRUE(rejections[0].certificate);
  EXPECT_EQ(rejections[0].certificate->thumbprint(), f.user.certificate->thumbprint());
  EXPECT_EQ(rejections[0].remoteAddress, "127.0.0.1:4840");
  f.harness->shutdown();
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-94-USER-TOKEN-REFUSAL-OBSERVED, scope=function)
TEST(SessionActivationFailureHold, AnAcceptedX509CertificateIsNotReportedAsRejected)
{
  X509RefusalFixture f{StatusCode{Status::Good}};
  auto recorder = std::make_shared<CertificateRejectionRecorder>();
  f.harness->sessDeps->observerValue = recorder;
  const auto outcome = f.activate(334);
  ASSERT_TRUE(outcome.gotResponse);
  EXPECT_TRUE(recorder->rejections().empty());
  f.harness->shutdown();
}
