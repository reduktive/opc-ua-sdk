// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SECURE_CHANNEL_TEST_ACCESS_H
#define UA_CLIENT_SECURE_CHANNEL_TEST_ACCESS_H

#include "ua_client_secure_channel_impl.h"

#include "strand_test_access_base.h"

namespace ua::client
{

/// Test-only access to SecureChannelImpl internals.
class SecureChannelTestAccess
  : public ua::test::StrandTestAccessBase<SecureChannelTestAccess, SecureChannelImpl>
{
  using Base = ua::test::StrandTestAccessBase<SecureChannelTestAccess, SecureChannelImpl>;

public:
  using ChannelState = SecureChannelImpl::ChannelState;

  // Bring base overloads into scope (derived on_strand/strand_barrier overloads would otherwise hide them).
  using Base::on_strand;
  using Base::strand_barrier;

  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(SecureChannelImpl& impl, StrandKey)
  {
    return *impl.mStrand;
  }

  /// Build a public SecureChannel handle wrapping an existing impl (private ctor interface).
  static SecureChannel make_channel(std::shared_ptr<SecureChannelImpl> impl)
  {
    return SecureChannel{std::move(impl)};
  }

  /// on_strand taking public SecureChannel handle - unwraps pimpl internally.
  template<typename F>
  static auto on_strand(SecureChannel& channel, F&& fn)
  {
    return Base::on_strand(*channel.mImpl, std::forward<F>(fn));
  }

  template<typename F>
  static auto on_strand(const std::shared_ptr<SecureChannel>& channel, F&& fn)
  {
    return Base::on_strand(*channel->mImpl, std::forward<F>(fn));
  }

  /// strand_barrier taking public SecureChannel handle.
  static void strand_barrier(SecureChannel& channel)
  {
    Base::strand_barrier(*channel.mImpl);
  }

  /// The renewal schedule (CL-SC-007), a pure function of the revised lifetime.
  static std::chrono::milliseconds renewal_delay(std::chrono::milliseconds revisedLifetime)
  {
    return SecureChannelImpl::renewal_delay(revisedLifetime);
  }

  /// The id of the OpenSecureChannel request the channel considers outstanding (CL-SC-008); set on the
  /// strand, as the send path does.
  static void set_opn_request_id(
    SecureChannelImpl& impl, std::optional<uint32_t> requestId);  // after the guard

  static void strand_barrier(const std::shared_ptr<SecureChannel>& channel)
  {
    Base::strand_barrier(*channel->mImpl);
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  // --- Pointer-to-member data constants ---
  static constexpr auto sChannelState = &SecureChannelImpl::mChannelState;
  static constexpr auto sContext = &SecureChannelImpl::mContext;
  static constexpr auto sSecurityPolicy = &SecureChannelImpl::mSecurityPolicy;
  static constexpr auto sPendingRequests = &SecureChannelImpl::mPendingRequests;
  static constexpr auto sNextRequestId = &SecureChannelImpl::mNextRequestId;
  static constexpr auto sRenewalTimer = &SecureChannelImpl::mRenewalTimer;
  static constexpr auto sIsAuthenticated = &SecureChannelImpl::mIsAuthenticated;
  static constexpr auto sNonceLength = &SecureChannelImpl::mNonceLength;
  static constexpr auto sServerNonce = &SecureChannelImpl::mServerNonce;
  static constexpr auto sLastClientNonce = &SecureChannelImpl::mLastClientNonce;
  static constexpr auto sRevisedLifetime = &SecureChannelImpl::mRevisedLifetime;
  static constexpr auto sChannelTokenId = &SecureChannelImpl::mChannelTokenId;
  static constexpr auto sCloseCallback = &SecureChannelImpl::mCloseCallback;
  static constexpr auto sNextCreateSessionResponseObserver =
    &SecureChannelImpl::mNextCreateSessionResponseObserver;
  static constexpr auto sOutgoingRequestObserver = &SecureChannelImpl::mOutgoingRequestObserver;
  static constexpr auto sAtomicChannelId = &SecureChannelImpl::mAtomicChannelId;
  static constexpr auto sAtomicIsOpen = &SecureChannelImpl::mAtomicIsOpen;
  static constexpr auto sOnOpened = &SecureChannelImpl::mOnOpened;
  static constexpr auto sIncomingDrainScheduled = &SecureChannelImpl::mIncomingDrainScheduled;
  static constexpr auto sDrainIncoming = &SecureChannelImpl::drain_incoming;

  // --- Pointer-to-member method constants ---
  static constexpr auto sReceiveMessageChunk = &SecureChannelImpl::receive_message_chunk;
  static constexpr auto sReceiveTransportError = &SecureChannelImpl::receive_transport_error;
  static constexpr auto sHandleOpnResponse = &SecureChannelImpl::handle_opn_response_async;
  static constexpr auto sOpnRequestId = &SecureChannelImpl::mOpnRequestId;
  static constexpr auto sHandleTokenRenewal = &SecureChannelImpl::handle_token_renewal_async;
  static constexpr auto sHandleCloseRequested = &SecureChannelImpl::start_close;
};

}  // namespace ua::client

template<>
class ua::test::StrandGuard<ua::client::SecureChannelTestAccess>
{
  using TA = ua::client::SecureChannelTestAccess;

public:
  // --- Data accessors ---
  STRAND_GUARD_DATA(channel_state, sChannelState)
  STRAND_GUARD_DATA(context, sContext)
  STRAND_GUARD_DATA(security_policy, sSecurityPolicy)
  STRAND_GUARD_DATA(pending_requests, sPendingRequests)
  STRAND_GUARD_DATA(next_request_id, sNextRequestId)
  STRAND_GUARD_DATA(renewal_timer, sRenewalTimer)
  STRAND_GUARD_DATA(is_authenticated, sIsAuthenticated)
  STRAND_GUARD_DATA(nonce_length, sNonceLength)
  STRAND_GUARD_DATA(server_nonce, sServerNonce)
  STRAND_GUARD_DATA(last_client_nonce, sLastClientNonce)
  STRAND_GUARD_DATA(revised_lifetime, sRevisedLifetime)
  STRAND_GUARD_DATA(channel_token_id, sChannelTokenId)
  STRAND_GUARD_DATA(close_callback, sCloseCallback)
  STRAND_GUARD_DATA(next_create_session_response_observer, sNextCreateSessionResponseObserver)
  STRAND_GUARD_DATA(outgoing_request_observer, sOutgoingRequestObserver)
  STRAND_GUARD_DATA(atomic_channel_id, sAtomicChannelId)
  STRAND_GUARD_DATA(atomic_is_open, sAtomicIsOpen)
  STRAND_GUARD_DATA(on_opened, sOnOpened)
  STRAND_GUARD_DATA(incoming_drain_scheduled, sIncomingDrainScheduled)

  // --- Method accessors ---
  STRAND_GUARD_METHOD(receive_message_chunk, sReceiveMessageChunk)
  STRAND_GUARD_METHOD(receive_transport_error, sReceiveTransportError)
  STRAND_GUARD_METHOD(drain_incoming, sDrainIncoming)

  /// Delivers an OPN response under the request id the channel considers outstanding (CL-SC-008), which the
  /// test hooks `set_channel_opening` / `set_channel_renewing` model as request 1 the way the send path
  /// records it. `handle_opn_response_for_request` names the id explicitly, for the correlation arms.
  template<typename... Args>
  void handle_opn_response(Args&&... args)
  {
    const auto outstanding = mTarget.*TA::sOpnRequestId;
    (mTarget.*TA::sHandleOpnResponse)(outstanding.value_or(0u), std::forward<Args>(args)...);
  }

  template<typename... Args>
  void handle_opn_response_for_request(uint32_t requestId, Args&&... args)
  {
    (mTarget.*TA::sHandleOpnResponse)(requestId, std::forward<Args>(args)...);
  }

  void set_opn_request_id(std::optional<uint32_t> requestId)
  {
    mTarget.*TA::sOpnRequestId = requestId;
  }
  STRAND_GUARD_METHOD(handle_token_renewal, sHandleTokenRenewal)
  STRAND_GUARD_METHOD(handle_close_requested, sHandleCloseRequested)

  // --- Setup helpers (on-strand) ---

  void set_channel_open(uint32_t channelId = 1)
  {
    mTarget.*TA::sChannelState = ua::client::SecureChannelImpl::ChannelState::Open;
    (mTarget.*TA::sContext)->secureChannelId = channelId;
    (mTarget.*TA::sContext)->state = ua::SecureChannelContext::State::Open;
    (mTarget.*TA::sAtomicChannelId).store(channelId, std::memory_order_release);
    (mTarget.*TA::sAtomicIsOpen).store(true, std::memory_order_release);
    mTarget.*TA::sOnOpened = nullptr;
  }

  void set_channel_opening()
  {
    mTarget.*TA::sChannelState = ua::client::SecureChannelImpl::ChannelState::Opening;
    mTarget.*TA::sOpnRequestId = 1u;  // an OpenSecureChannel request is outstanding, as after a send
  }

  void set_channel_renewing()
  {
    mTarget.*TA::sChannelState = ua::client::SecureChannelImpl::ChannelState::Renewing;
    mTarget.*TA::sOpnRequestId = 1u;
  }

  void set_channel_closed()
  {
    mTarget.*TA::sChannelState = ua::client::SecureChannelImpl::ChannelState::Closed;
    (mTarget.*TA::sAtomicIsOpen).store(false, std::memory_order_release);
  }

  void set_is_authenticated(bool authenticated, uint32_t nonceLength = 0)
  {
    mTarget.*TA::sIsAuthenticated = authenticated;
    mTarget.*TA::sNonceLength = nonceLength;
  }

  void set_server_nonce(ua::ByteString nonce)
  {
    mTarget.*TA::sServerNonce = std::move(nonce);
  }

private:
  friend struct ua::test::StrandTestAccessBase<ua::client::SecureChannelTestAccess,
    ua::client::SecureChannelImpl>;

  explicit StrandGuard(ua::client::SecureChannelImpl& a) : mTarget(a)
  {}

  ua::client::SecureChannelImpl& mTarget;
};

inline void ua::client::SecureChannelTestAccess::set_opn_request_id(
  SecureChannelImpl& impl, std::optional<uint32_t> requestId)
{
  Base::on_strand(impl, [requestId](auto& g) { g.set_opn_request_id(requestId); });
}

#endif  // !UA_CLIENT_SECURE_CHANNEL_TEST_ACCESS_H
