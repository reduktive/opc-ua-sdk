// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_SECURE_CHANNEL_TEST_ACCESS_H
#define UA_SERVER_SECURE_CHANNEL_TEST_ACCESS_H

#include "ua_server_secure_channel.h"

#include "ua_security_policy.h"
#include "ua_server_endpoint_configuration.h"

#include "strand_test_access_base.h"

namespace ua::server
{

class SecureChannelTestAccess : public ua::test::StrandTestAccessBase<SecureChannelTestAccess, SecureChannel>
{
public:
  using ChannelState = SecureChannel::ChannelState;

  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(SecureChannel& sc, StrandKey)
  {
    return *sc.mContext->boundStrand;
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  // --- Pointer-to-member data constants ---
  static constexpr auto sChannelState = &SecureChannel::mChannelState;
  static constexpr auto sDiscoveryOnly = &SecureChannel::mDiscoveryOnly;
  static constexpr auto sContext = &SecureChannel::mContext;
  static constexpr auto sEndpointPolicyId = &SecureChannel::mEndpointPolicyId;
  static constexpr auto sUserIdentityTokens = &SecureChannel::mUserIdentityTokens;
  static constexpr auto sActiveTokenSummary = &SecureChannel::mActiveTokenSummary;
  static constexpr auto sPendingTokenSummary = &SecureChannel::mPendingTokenSummary;
  static constexpr auto sRemovedFromServer = &SecureChannel::mRemovedFromServer;
  static constexpr auto sCloseReason = &SecureChannel::mCloseReason;
  static constexpr auto sConnectionCloseReason = &SecureChannel::mConnectionCloseReason;
  static constexpr auto sResponseSinkForTests = &SecureChannel::mResponseSinkForTests;
  static constexpr auto sCorrelatedResponseEnqueueFailureInjectorForTests =
    &SecureChannel::mCorrelatedResponseEnqueueFailureInjectorForTests;
  static constexpr auto sRequestObserver = &SecureChannel::mRequestObserver;
  static constexpr auto sResponseInterceptor = &SecureChannel::mResponseInterceptor;
  static constexpr auto sValidationFailureObserver = &SecureChannel::mValidationFailureObserver;
  static constexpr auto sLastClientNonce = &SecureChannel::mLastClientNonce;
  static constexpr auto sSessionCallbacks = &SecureChannel::mSessionCallbacks;

  // --- Pointer-to-member method constants ---
  static constexpr auto sInjectDecodedRequest = &SecureChannel::inject_decoded_request_for_tests;
  static constexpr auto sExtractSecurityPolicy =
    &SecureChannel::extract_security_policy_from_opn_message_chunk;
  static constexpr auto sPopQueuedResponse = &SecureChannel::pop_queued_response_for_tests;
  static constexpr auto sSetResponseSink = &SecureChannel::set_response_sink_for_tests;
  static constexpr auto sSetChunkIngestObserver = &SecureChannel::set_chunk_ingest_observer;
  static constexpr auto sSetChunkEgressObserver = &SecureChannel::set_chunk_egress_observer;
  static constexpr auto sSetRequestObserver = &SecureChannel::set_request_observer;
  static constexpr auto sSetResponseInterceptor = &SecureChannel::set_response_interceptor;
  static constexpr auto sSetValidationFailureObserver = &SecureChannel::set_validation_failure_observer;
  static constexpr auto sHandleTokenExpired = &SecureChannel::handle_token_expired;
  static constexpr auto sReceiveMessageChunk = &SecureChannel::receive_message_chunk;
  static constexpr auto sReceiveTransportError = &SecureChannel::receive_transport_error;
  static constexpr auto sHandleRequestDecodeFailure = &SecureChannel::handle_request_decode_failure;
  static constexpr auto sOnChunkDecoded = &SecureChannel::on_chunk_decoded;
};

}  // namespace ua::server

// StrandGuard must be defined AFTER TestAccess so TA:: is complete.
template<>
class ua::test::StrandGuard<ua::server::SecureChannelTestAccess>
{
  using TA = ua::server::SecureChannelTestAccess;

public:
  // --- Data accessors ---
  STRAND_GUARD_DATA(channel_state, sChannelState)
  STRAND_GUARD_DATA(discovery_only, sDiscoveryOnly)
  STRAND_GUARD_DATA(context, sContext)
  STRAND_GUARD_DATA(endpoint_policy_id, sEndpointPolicyId)
  STRAND_GUARD_DATA(user_identity_tokens, sUserIdentityTokens)
  STRAND_GUARD_DATA(active_token_summary, sActiveTokenSummary)
  STRAND_GUARD_DATA(pending_token_summary, sPendingTokenSummary)
  STRAND_GUARD_DATA(removed_from_server, sRemovedFromServer)
  STRAND_GUARD_DATA(close_reason, sCloseReason)
  STRAND_GUARD_DATA(connection_close_reason, sConnectionCloseReason)
  STRAND_GUARD_DATA(response_sink_for_tests, sResponseSinkForTests)
  STRAND_GUARD_DATA(
    correlated_response_enqueue_failure_injector, sCorrelatedResponseEnqueueFailureInjectorForTests)
  STRAND_GUARD_DATA(request_observer, sRequestObserver)
  STRAND_GUARD_DATA(response_interceptor, sResponseInterceptor)
  STRAND_GUARD_DATA(validation_failure_observer, sValidationFailureObserver)
  STRAND_GUARD_DATA(last_client_nonce, sLastClientNonce)
  STRAND_GUARD_DATA(session_callbacks, sSessionCallbacks)

  // --- Method accessors ---
  STRAND_GUARD_METHOD(inject_decoded_request, sInjectDecodedRequest)
  STRAND_GUARD_METHOD(extract_security_policy, sExtractSecurityPolicy)
  STRAND_GUARD_METHOD(pop_queued_response, sPopQueuedResponse)
  STRAND_GUARD_METHOD(set_response_sink, sSetResponseSink)
  STRAND_GUARD_METHOD(set_chunk_ingest_observer, sSetChunkIngestObserver)
  STRAND_GUARD_METHOD(set_chunk_egress_observer, sSetChunkEgressObserver)
  STRAND_GUARD_METHOD(set_request_observer, sSetRequestObserver)
  STRAND_GUARD_METHOD(set_response_interceptor, sSetResponseInterceptor)
  STRAND_GUARD_METHOD(set_validation_failure_observer, sSetValidationFailureObserver)
  STRAND_GUARD_METHOD(handle_token_expired, sHandleTokenExpired)
  STRAND_GUARD_METHOD(receive_message_chunk, sReceiveMessageChunk)
  STRAND_GUARD_METHOD(receive_transport_error, sReceiveTransportError)
  STRAND_GUARD_METHOD(handle_request_decode_failure, sHandleRequestDecodeFailure)
  STRAND_GUARD_METHOD(on_chunk_decoded, sOnChunkDecoded)

  // --- Setup helpers (on-strand) ---

  void set_minimal_context_none(boost::asio::any_io_executor ex, std::string endpointPolicyId,
    std::vector<ua::UserTokenPolicy> userTokens = {})
  {
    reset_context_preserving_strand(ex);
    (mTarget.*TA::sContext)->messageSecurityMode = ua::MessageSecurityMode::None;
    (mTarget.*TA::sContext)->securityPolicy = ua::SecurityPolicy::create(ua::SecurityPolicyId::None);
    (mTarget.*TA::sContext)->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
    mTarget.*TA::sEndpointPolicyId = std::move(endpointPolicyId);
    if (userTokens.empty())
    {
      userTokens.push_back(
        ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    }
    mTarget.*TA::sUserIdentityTokens = std::move(userTokens);
  }

  void set_minimal_context_authenticated(boost::asio::any_io_executor ex, std::string endpointPolicyId,
    ua::SecurityPolicyId policyId, ua::MessageSecurityMode mode,
    std::vector<ua::UserTokenPolicy> userTokens = {})
  {
    reset_context_preserving_strand(ex);
    (mTarget.*TA::sContext)->messageSecurityMode = mode;
    (mTarget.*TA::sContext)->securityPolicy = ua::SecurityPolicy::create(policyId);
    (mTarget.*TA::sContext)->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
    mTarget.*TA::sEndpointPolicyId = std::move(endpointPolicyId);
    if (userTokens.empty())
    {
      userTokens.push_back(
        ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    }
    mTarget.*TA::sUserIdentityTokens = std::move(userTokens);
  }

private:
  // Replace the channel's context with a fresh one for test setup, but PRESERVE its existing strand.
  // create() establishes the strand once and binds the channel's async callbacks to it - notably the
  // transport-error callback, which post_borrowing captures the strand handle for at bind time. In
  // production the strand is never replaced after create() (SecureChannel::create sets it exactly
  // once), so those bindings stay valid. Swapping in a fresh strand here would leave the already-bound
  // transport-error handler posting to the OLD strand while close()/on_strand post to the NEW one -
  // two strands means no mutual serialization, so writes to shared channel state (e.g. mCloseReason,
  // which carries a shared_ptr<ErrorDetail>) race under TSan. Keeping the channel's own strand models
  // production faithfully and keeps every binding on one serializing strand.
  void reset_context_preserving_strand(boost::asio::any_io_executor ex)
  {
    std::optional<boost::asio::strand<boost::asio::any_io_executor>> existingStrand;
    if (mTarget.*TA::sContext)
    {
      existingStrand = (mTarget.*TA::sContext)->boundStrand;
    }
    mTarget.*TA::sContext = std::make_shared<ua::SecureChannelContext>();
    (mTarget.*TA::sContext)->boundStrand =
      existingStrand.has_value() ? existingStrand : std::optional{boost::asio::make_strand(std::move(ex))};
  }

  friend struct ua::test::StrandTestAccessBase<ua::server::SecureChannelTestAccess,
    ua::server::SecureChannel>;

  explicit StrandGuard(ua::server::SecureChannel& a) : mTarget(a)
  {}

  ua::server::SecureChannel& mTarget;
};

#endif  // !UA_SERVER_SECURE_CHANNEL_TEST_ACCESS_H
