// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_SERVICE_GUARD_FIXTURE_H
#define UA_SESSION_SERVICE_GUARD_FIXTURE_H

// Shared fixture for the tier-0 session-service "absent-session guard" unit tests.
//
// Every client session-service accessor (SessionViewServices, SessionAttributeServices, ...) is a
// thin forwarder that holds only a std::weak_ptr<SessionImpl>. Each async method locks that weak
// pointer and, if the owning session has already been destroyed, fast-fails the callback with
// Bad_SessionIdInvalid instead of dereferencing a dangling pointer. That absent-session guard is a
// real, falsifiable lifetime-safety contract (weak-only capture is a core design rule): were the
// guard removed, locking an expired weak_ptr yields a null shared_ptr and the forward would crash.
//
// A service accessor is not independently constructible (its constructor is private, befriended
// only to Session) and Session::view()/attributes()/... throw when their impl is null, so a service
// handle can only be obtained while a live SessionImpl exists. This harness therefore:
//   1. builds a real SessionImpl over a fake, connection-less SecureChannel,
//   2. hands out a live Session (via SessionTestAccess::wrap) so a test can grab the service
//      handles it wants while the impl is still alive, and
//   3. on kill(), breaks the impl's internal shared_from_this cycle, drives it to Closed and
//      destroys it, so every previously-grabbed service handle now holds an EXPIRED weak_ptr.
//
// After kill() the guarded async methods must invoke their callback with Bad_SessionIdInvalid. This
// is falsifiable in the correct direction: if the weak_ptr were NOT expired the forward would reach
// a live (Closed) impl and return Bad_SessionClosed; if the guard were missing the null lock would
// crash or never call back. Only a genuinely dead session plus a working guard yields
// Bad_SessionIdInvalid.

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_client_session.h"
#include "ua_crypto.h"
#include "ua_structure_factory.h"

#include <boost/asio/thread_pool.hpp>

#include <memory>
#include <optional>

#include "test_utilities.h"

// Test-only access to client session and secure channel internals.
#include "../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"
#include "../sdk/implementation/client/session/ua_client_session_test_access.h"

namespace ua::client::guard_test
{

/// Minimal SessionDependencies double: supplies an executor and empty crypto/config so a
/// SessionImpl can be created without any real connection or security stack.
class FakeSessionDeps : public SessionDependencies
{
public:
  explicit FakeSessionDeps(boost::asio::any_io_executor executor)
    : mExecutor(std::move(executor)), mAppCfg(ua::ApplicationConfig::load_default())
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

/// Minimal SecureChannelDependencies double mirroring FakeSessionDeps for the connection-less
/// channel the harness creates the session over.
class FakeChannelDeps : public SecureChannelDependencies
{
public:
  explicit FakeChannelDeps(boost::asio::any_io_executor executor)
    : mExecutor(std::move(executor)), mAppCfg(ua::ApplicationConfig::load_default())
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

/// Builds a real SessionImpl, hands out a live Session for grabbing service-set handles, then on
/// kill() destroys the impl so those handles hold an expired weak_ptr.
class DeadSessionHarness
{
public:
  DeadSessionHarness()
  {
    mChannelDeps = std::make_shared<FakeChannelDeps>(mPool.get_executor());
    mSessionDeps = std::make_shared<FakeSessionDeps>(mPool.get_executor());

    // Connection-less channel forced Open so session requests can be dispatched.
    mChannel = SecureChannelImpl::create(
      mChannelDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      SecureChannelImpl::Config{},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});
    SecureChannelTestAccess::on_strand(
      *mChannel, [](auto& guard) { guard.channel_state() = SecureChannelImpl::ChannelState::Open; });

    mSession = SessionImpl::create(
      mSessionDeps,
      mChannel,
      SessionImpl::Config{},
      SessionImpl::SecurityInfo{},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});

    mLive.emplace(SessionTestAccess::wrap(mSession));
  }

  DeadSessionHarness(const DeadSessionHarness&) = delete;
  DeadSessionHarness& operator=(const DeadSessionHarness&) = delete;

  /// A live Session handle over the harness impl. Grab the service accessors a test needs from this
  /// BEFORE calling kill(); the accessors throw once the impl is gone.
  Session& live()
  {
    return *mLive;
  }

  /// Destroys the SessionImpl so every service handle grabbed from live() now holds an expired
  /// weak_ptr and its absent-session guard fires. Returns whether the impl was actually destroyed
  /// (the weak_ptr expired); tests assert this precondition before exercising the guard.
  [[nodiscard]] bool kill()
  {
    drive_to_closed();
    std::weak_ptr<SessionImpl> watch = mSession;
    mLive.reset();  // drop the wrapped Session's strong ref
    mSession.reset();  // drop the harness strong ref -> impl destroyed
    return watch.expired();
  }

  ~DeadSessionHarness()
  {
    // Defensive: if a test never called kill(), break the cycle so the impl does not leak.
    if (mSession)
    {
      drive_to_closed();
      mLive.reset();
      mSession.reset();
    }
    mChannel.reset();
    mSessionDeps.reset();
    mChannelDeps.reset();
    ua::test_utils::drain_with_timeout(mPool);
  }

private:
  /// Break the impl's internal shared_from_this cycle: fail any channel-side pending request so the
  /// suspended create coroutine resumes, drive any non-terminal state to Closed, and drain the
  /// strand so the posted mActiveTask.reset() runs. Mirrors TestSessionSetup::cleanup_sync.
  void drive_to_closed()
  {
    SecureChannelTestAccess::on_strand(*mChannel,
      [](auto& guard)
      {
        auto pending = std::move(guard.pending_requests());
        guard.pending_requests().clear();
        for (auto& [handle, callback] : pending)
          callback(SecureChannelImpl::ServiceResponseResult{ua::Status::BadConnectionClosed});
      });

    using SessionState = SessionTestAccess::SessionState;
    const auto state =
      SessionTestAccess::on_strand(*mSession, [](auto& guard) { return guard.session_state(); });
    if (state != SessionState::Closed && state != SessionState::Idle)
    {
      SessionTestAccess::on_strand(
        *mSession, [](auto& guard) { guard.inject_channel_error(ua::Status::BadConnectionClosed); });
      SessionTestAccess::on_strand(
        *mSession, [](auto& guard) { guard.inject_channel_error(ua::Status::BadConnectionClosed); });
    }

    SessionTestAccess::strand_barrier(*mSession);
  }

  boost::asio::thread_pool mPool;
  std::shared_ptr<FakeChannelDeps> mChannelDeps;
  std::shared_ptr<FakeSessionDeps> mSessionDeps;
  std::shared_ptr<SecureChannelImpl> mChannel;
  std::shared_ptr<SessionImpl> mSession;
  std::optional<Session> mLive;
};

}  // namespace ua::client::guard_test

#endif  // !UA_SESSION_SERVICE_GUARD_FIXTURE_H
