// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SESSION_TEST_ACCESS_H
#define UA_CLIENT_SESSION_TEST_ACCESS_H

#include "ua_client_session_impl.h"

#include "strand_test_access_base.h"

namespace ua::client
{

/// Test-only access to SessionImpl internals.
class SessionTestAccess : public ua::test::StrandTestAccessBase<SessionTestAccess, SessionImpl>
{
  using Base = ua::test::StrandTestAccessBase<SessionTestAccess, SessionImpl>;

public:
  using SessionState = SessionImpl::SessionState;

  // Bring base overloads into scope.
  using Base::on_strand;
  using Base::strand_barrier;

  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(SessionImpl& impl, StrandKey)
  {
    return *impl.mStrand;
  }

  /// on_strand taking public Session handle - unwraps pimpl internally.
  template<typename F>
  static auto on_strand(Session& session, F&& fn)
  {
    return Base::on_strand(*session.mImpl, std::forward<F>(fn));
  }

  template<typename F>
  static auto on_strand(const std::shared_ptr<Session>& session, F&& fn)
  {
    return Base::on_strand(*session->mImpl, std::forward<F>(fn));
  }

  /// strand_barrier taking public Session handle.
  static void strand_barrier(Session& session)
  {
    Base::strand_barrier(*session.mImpl);
  }

  static void strand_barrier(const std::shared_ptr<Session>& session)
  {
    Base::strand_barrier(*session->mImpl);
  }

  /// Wraps a raw @ref SessionImpl in the public @ref Session handle so a unit test can exercise the
  /// public service-set accessors (`attributes()` / `subscriptions()` / ...) and their sync ops against a
  /// harness-driven impl (e.g. asserting a closed session fast-fails rather than deadlocks).
  static Session wrap(std::shared_ptr<SessionImpl> impl)
  {
    return Session(std::move(impl));
  }

  static void set_return_diagnostics_override(SessionImpl& impl, std::optional<uint32_t> mask)
  {
    impl.set_return_diagnostics_override(mask);
  }

  static uint32_t return_diagnostics_for(const SessionImpl& impl, uint32_t requestValue)
  {
    return impl.return_diagnostics_for(requestValue);
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  // --- Pointer-to-member data constants ---
  static constexpr auto sSessionState = &SessionImpl::mSessionState;
  static constexpr auto sSessionId = &SessionImpl::mSessionId;
  static constexpr auto sAuthenticationToken = &SessionImpl::mAuthenticationToken;
  static constexpr auto sServerNonce = &SessionImpl::mServerNonce;
  static constexpr auto sRevisedSessionTimeoutMs = &SessionImpl::mRevisedSessionTimeoutMs;
  static constexpr auto sSecurityInfo = &SessionImpl::mSecurityInfo;
  static constexpr auto sClientNonce = &SessionImpl::mClientNonce;
  static constexpr auto sServerEphemeralPublicKey = &SessionImpl::mServerEphemeralPublicKey;
  static constexpr auto sPendingRequests = &SessionImpl::mPendingRequests;
  static constexpr auto sNextRequestHandle = &SessionImpl::mNextRequestHandle;
  static constexpr auto sTimeoutTimer = &SessionImpl::mTimeoutTimer;
  static constexpr auto sConfig = &SessionImpl::mConfig;
  static constexpr auto sAtomicState = &SessionImpl::mAtomicState;
  static constexpr auto sAtomicSessionId = &SessionImpl::mAtomicSessionId;
  static constexpr auto sAtomicAuthenticationToken = &SessionImpl::mAtomicAuthenticationToken;

  // --- Pointer-to-member method constants ---
  static constexpr auto sHandleChannelDisconnected = &SessionImpl::handle_channel_disconnected;
  static constexpr auto sHandleSessionClosed = &SessionImpl::handle_session_closed;
  static constexpr auto sScheduleTimeoutTimer = &SessionImpl::schedule_timeout_timer;
};

}  // namespace ua::client

template<>
class ua::test::StrandGuard<ua::client::SessionTestAccess>
{
  using TA = ua::client::SessionTestAccess;

public:
  // --- Data accessors ---
  STRAND_GUARD_DATA(session_state, sSessionState)
  STRAND_GUARD_DATA(session_id, sSessionId)
  STRAND_GUARD_DATA(authentication_token, sAuthenticationToken)
  STRAND_GUARD_DATA(server_nonce, sServerNonce)
  STRAND_GUARD_DATA(revised_session_timeout_ms, sRevisedSessionTimeoutMs)
  STRAND_GUARD_DATA(security_info, sSecurityInfo)
  STRAND_GUARD_DATA(client_nonce, sClientNonce)
  STRAND_GUARD_DATA(server_ephemeral_public_key, sServerEphemeralPublicKey)
  STRAND_GUARD_DATA(pending_requests, sPendingRequests)
  STRAND_GUARD_DATA(next_request_handle, sNextRequestHandle)
  STRAND_GUARD_DATA(timeout_timer, sTimeoutTimer)
  STRAND_GUARD_DATA(config, sConfig)
  STRAND_GUARD_DATA(atomic_state, sAtomicState)
  STRAND_GUARD_DATA(atomic_session_id, sAtomicSessionId)
  STRAND_GUARD_DATA(atomic_authentication_token, sAtomicAuthenticationToken)

  // --- Method accessors ---
  STRAND_GUARD_METHOD(handle_channel_disconnected, sHandleChannelDisconnected)
  STRAND_GUARD_METHOD(handle_session_closed, sHandleSessionClosed)
  STRAND_GUARD_METHOD(schedule_timeout_timer, sScheduleTimeoutTimer)

  // --- Setup helpers (on-strand) ---

  void set_session_created(
    ua::NodeId sessionId = ua::NodeId{1, 100}, ua::NodeId authToken = ua::NodeId{1, 200})
  {
    mTarget.*TA::sSessionState = TA::SessionState::Created;
    mTarget.*TA::sSessionId = sessionId;
    mTarget.*TA::sAuthenticationToken = authToken;
    (mTarget.*TA::sAtomicState)
      .store(utils::to_underlying(TA::SessionState::Created), std::memory_order_release);
    (mTarget.*TA::sAtomicSessionId).store(std::make_shared<const ua::NodeId>(std::move(sessionId)));
    (mTarget.*TA::sAtomicAuthenticationToken).store(std::make_shared<const ua::NodeId>(std::move(authToken)));
  }

  void set_session_active(
    ua::NodeId sessionId = ua::NodeId{1, 100}, ua::NodeId authToken = ua::NodeId{1, 200})
  {
    mTarget.*TA::sSessionState = TA::SessionState::Active;
    mTarget.*TA::sSessionId = sessionId;
    mTarget.*TA::sAuthenticationToken = authToken;
    (mTarget.*TA::sAtomicState)
      .store(utils::to_underlying(TA::SessionState::Active), std::memory_order_release);
    (mTarget.*TA::sAtomicSessionId).store(std::make_shared<const ua::NodeId>(std::move(sessionId)));
    (mTarget.*TA::sAtomicAuthenticationToken).store(std::make_shared<const ua::NodeId>(std::move(authToken)));
  }

  void set_session_state(TA::SessionState state)
  {
    mTarget.*TA::sSessionState = state;
    (mTarget.*TA::sAtomicState).store(utils::to_underlying(state), std::memory_order_release);
  }

  void inject_channel_error(ua::StatusCode status)
  {
    (mTarget.*TA::sHandleChannelDisconnected)(status, {});
  }

private:
  friend struct ua::test::StrandTestAccessBase<ua::client::SessionTestAccess, ua::client::SessionImpl>;

  explicit StrandGuard(ua::client::SessionImpl& a) : mTarget(a)
  {}

  ua::client::SessionImpl& mTarget;
};

#endif  // !UA_CLIENT_SESSION_TEST_ACCESS_H
