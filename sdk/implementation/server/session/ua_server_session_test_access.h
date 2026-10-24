// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_SESSION_TEST_ACCESS_H
#define UA_SERVER_SESSION_TEST_ACCESS_H

#include "ua_server_session.h"

#include "strand_test_access_base.h"

namespace ua::server
{

struct SessionTestAccess : ua::test::StrandTestAccessBase<SessionTestAccess, Session>
{
  using State = Session::State;

  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(Session& session, StrandKey)
  {
    return session.mStrand;
  }

  static std::shared_ptr<SubscriptionsPipeline> subscriptions_pipeline(Session& session)
  {
    return session.mSubscriptionsPipeline.load();
  }

  static std::shared_ptr<const AccessIdentity> access_identity(Session& session)
  {
    return session.mSessionInfo->access_identity();
  }

  static std::shared_ptr<const EndpointSecurityContext> endpoint_security(Session& session)
  {
    return session.mSessionInfo->endpoint_security();
  }

  /// A new security context of the kind a Session holds, over @p dependencies, with no identity committed.
  static std::shared_ptr<SessionSecurityContext> new_security_context(
    weak_ptr<SessionDependencies> dependencies)
  {
    return std::make_shared<Session::SessionInfo>(std::move(dependencies));
  }

  /// Commits an identity to @p context, which @ref new_security_context made, as ActivateSession commits one.
  static void set_security_context(SessionSecurityContext& context, NodeId sessionId,
    std::shared_ptr<const EndpointSecurityContext> endpoint, std::shared_ptr<const UserIdentity> user,
    std::shared_ptr<const AccessIdentity> identity)
  {
    static_cast<Session::SessionInfo&>(context).set_security_context(
      std::move(sessionId), std::move(endpoint), std::move(user), std::move(identity));
  }

  static bool authentication_completed_by_for_tests(std::chrono::steady_clock::time_point completedAt,
    std::chrono::steady_clock::time_point deadline) noexcept
  {
    return Session::authentication_completed_by(completedAt, deadline);
  }

  static void set_create_response_failure_injector_on_strand(Session& session, void (*injector)())
  {
    session.mCreateResponseFailureInjectorForTests = injector;
  }

  /// Parks a Session in the state it holds while it is authenticating an ActivateSession: the request
  /// has arrived and the server is deliberately sitting on it for the configured authentication
  /// interval. Only the presence of the flow matters to the callers of this, so the flow is otherwise
  /// empty; @p requestId is the request the Session then owes an answer to.
  static void set_pending_auth_flow_on_strand(Session& session, uint32_t requestId)
  {
    auto flow = std::make_unique<Session::AuthState>();
    flow->requestId = requestId;
    session.mAuthState = std::move(flow);
    session.mWaitingForAuthn = true;
  }

  static void clear_auth_flow_on_strand(Session& session)
  {
    session.mAuthState.reset();
    session.mWaitingForAuthn = false;
  }

  static bool has_pending_auth_flow_on_strand(const Session& session)
  {
    return session.mAuthState != nullptr;
  }

  static void inject_monitored_item_reauthorization_failure(
    Session& session, VoidResult failure, std::function<void(VoidResult)> callback)
  {
    auto state = std::make_unique<Session::ActivateResponseState>();
    state->requestId = 999;
    state->callback = std::move(callback);
    session.mActivateResponseState = std::move(state);
    session.mSessionState = Session::State::Activated;
    session.mState.store(Session::State::Activated, std::memory_order_release);
    // The response body reaches the fail-closed teardown by falling out of its reauthorization
    // await with a bad result. The step guard that used to protect that entry is now structural -
    // the body can only be at that point in the walk - so the seam enters at the branch itself.
    session.fail_changed_identity_activation(failure.status_code(), failure.shared_detail());
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  // --- Pointer-to-member data constants ---
  static constexpr auto sState = &Session::mState;
  static constexpr auto sSessionState = &Session::mSessionState;
  static constexpr auto sLastActivity = &Session::mLastActivity;
  static constexpr auto sServerNonce = &Session::mServerNonce;
  static constexpr auto sServerCertificates = &Session::mServerCertificates;
  static constexpr auto sSelectedServerCertAndKey = &Session::mSelectedServerCertAndKey;
  static constexpr auto sRevisedSessionTimeout = &Session::mRevisedSessionTimeout;
  static constexpr auto sInFlightRequestsByRequestId = &Session::mInFlightRequestsByRequestId;
  static constexpr auto sServiceCallsByRequestId = &Session::mServiceCallsByRequestId;
  static constexpr auto sRequestHandlesByRequestId = &Session::mRequestHandlesByRequestId;
  static constexpr auto sReturnDiagnosticsByRequestId = &Session::mReturnDiagnosticsByRequestId;
  static constexpr auto sOutstandingRequestHandles = &Session::mOutstandingRequestHandles;
  static constexpr auto sAuthnUserByRequestId = &Session::mAuthnUserByRequestId;
  static constexpr auto sAuthnEndpointByRequestId = &Session::mAuthnEndpointByRequestId;
  static constexpr auto sAuthnUserInsertFailureInjectorForTests =
    &Session::mAuthnUserInsertFailureInjectorForTests;
  static constexpr auto sClientCertificate = &Session::mClientCertificate;
  static constexpr auto sClientIssuerCertificates = &Session::mClientIssuerCertificates;
  static constexpr auto sClientCertificatePolicy = &Session::mClientCertificatePolicy;
  static constexpr auto sEccUserTokenPolicyId = &Session::mEccUserTokenPolicyId;
  static constexpr auto sChannelSecurityPolicyId = &Session::mChannelSecurityPolicyId;
  static constexpr auto sChannelSecurityMode = &Session::mChannelSecurityMode;
  static constexpr auto sEccEphemeralPrivateKey = &Session::mEccEphemeralPrivateKey;
  static constexpr auto sEccEphemeralPublicKey = &Session::mEccEphemeralPublicKey;
  static constexpr auto sSecureChannelInfo = &Session::mSecureChannelInfo;
  static constexpr auto sSessionInfo = &Session::mSessionInfo;
  static constexpr auto sBrowseContinuationPoints = &Session::mBrowseContinuationPoints;
  static constexpr auto sBrowseContinuationPointExpiry = &Session::mBrowseContinuationPointExpiry;
  static constexpr auto sHistoryContinuationPoints = &Session::mHistoryContinuationPoints;
  static constexpr auto sHistoryContinuationPointExpiry = &Session::mHistoryContinuationPointExpiry;
  static constexpr auto sResponseMessages = &Session::mResponseMessages;
  static constexpr auto sMaxBufferedResponses = &Session::mMaxBufferedResponses;
  static constexpr auto sUserTokenCertificate = &Session::mUserTokenCertificate;
  static constexpr auto sUserTokenCertificateField = &Session::mUserTokenCertificateField;
  static constexpr auto sPostResponseActions = &Session::mPostResponseActions;
  static constexpr auto sPostResponseActionInsertFailureInjectorForTests =
    &Session::mPostResponseActionInsertFailureInjectorForTests;
  static constexpr auto sSecureChannelAssociationEpoch = &Session::mSecureChannelAssociationEpoch;
  static constexpr auto sParsedIdentityCompletionGateForTests =
    &Session::mParsedIdentityCompletionGateForTests;
  static constexpr auto sUserTokenSignatureCompletionGateForTests =
    &Session::mUserTokenSignatureCompletionGateForTests;
  static constexpr auto sAuthenticatorCompletionNotificationGateForTests =
    &Session::mAuthenticatorCompletionNotificationGateForTests;
  static constexpr auto sSetSubscriptionDurableOperationForTests =
    &Session::mSetSubscriptionDurableOperationForTests;

  // --- Pointer-to-member method constants ---
  static constexpr auto sInjectDecodedRequest = &Session::inject_decoded_request_for_tests;
  static constexpr auto sEnqueueResponse = &Session::enqueue_response;
  static constexpr auto sPopQueuedResponse = &Session::pop_queued_response_for_tests;
  static constexpr auto sSetResponseSink = &Session::set_response_sink_for_tests;
  static constexpr auto sBrowseResponseReceived = &Session::browse_response_received;
  static constexpr auto sHistoryReadResponseReceived = &Session::history_read_response_received;
  static constexpr auto sResponseReceived = &Session::response_received;
  static constexpr auto sCancelOutstandingOpsEffect = &Session::cancel_outstanding_ops_effect;
  static constexpr auto sTimeout = &Session::timeout;
  static constexpr auto sOnInactivityTick = &Session::on_inactivity_tick;
  static constexpr auto sRequestReceived = &Session::request_received;
  static constexpr auto sSendActivateSessionResponse = &Session::send_activate_session_response_async;
  static constexpr auto sErrorReceivedFromSecureChannel = &Session::error_received_from_secure_channel;
};

}  // namespace ua::server

template<>
class ua::test::StrandGuard<ua::server::SessionTestAccess>
{
  using TA = ua::server::SessionTestAccess;

public:
  // --- Data accessors ---
  STRAND_GUARD_DATA(state, sState)
  STRAND_GUARD_DATA(session_state, sSessionState)
  STRAND_GUARD_DATA(last_activity, sLastActivity)
  STRAND_GUARD_DATA(server_nonce, sServerNonce)
  STRAND_GUARD_DATA(server_certificates, sServerCertificates)
  STRAND_GUARD_DATA(selected_cert_and_key, sSelectedServerCertAndKey)
  STRAND_GUARD_DATA(revised_session_timeout, sRevisedSessionTimeout)
  STRAND_GUARD_DATA(in_flight_requests, sInFlightRequestsByRequestId)
  STRAND_GUARD_DATA(service_calls_by_request_id, sServiceCallsByRequestId)
  STRAND_GUARD_DATA(request_handles_by_request_id, sRequestHandlesByRequestId)
  STRAND_GUARD_DATA(return_diagnostics_by_request_id, sReturnDiagnosticsByRequestId)
  STRAND_GUARD_DATA(outstanding_request_handles, sOutstandingRequestHandles)
  STRAND_GUARD_DATA(authn_user_by_request_id, sAuthnUserByRequestId)
  STRAND_GUARD_DATA(authn_endpoint_by_request_id, sAuthnEndpointByRequestId)
  STRAND_GUARD_DATA(authn_user_insert_failure_injector, sAuthnUserInsertFailureInjectorForTests)
  STRAND_GUARD_DATA(client_certificate, sClientCertificate)
  STRAND_GUARD_DATA(client_issuer_certificates, sClientIssuerCertificates)
  STRAND_GUARD_DATA(client_certificate_policy, sClientCertificatePolicy)
  STRAND_GUARD_DATA(ecc_user_token_policy_id, sEccUserTokenPolicyId)
  STRAND_GUARD_DATA(channel_security_policy_id, sChannelSecurityPolicyId)
  STRAND_GUARD_DATA(channel_security_mode, sChannelSecurityMode)
  STRAND_GUARD_DATA(ecc_ephemeral_private_key, sEccEphemeralPrivateKey)
  STRAND_GUARD_DATA(ecc_ephemeral_public_key, sEccEphemeralPublicKey)
  STRAND_GUARD_DATA(secure_channel_info, sSecureChannelInfo)
  STRAND_GUARD_DATA(session_info, sSessionInfo)
  STRAND_GUARD_DATA(browse_continuation_points, sBrowseContinuationPoints)
  STRAND_GUARD_DATA(browse_continuation_point_expiry, sBrowseContinuationPointExpiry)
  STRAND_GUARD_DATA(history_continuation_points, sHistoryContinuationPoints)
  STRAND_GUARD_DATA(history_continuation_point_expiry, sHistoryContinuationPointExpiry)
  STRAND_GUARD_DATA(response_messages, sResponseMessages)
  STRAND_GUARD_DATA(max_buffered_responses, sMaxBufferedResponses)
  STRAND_GUARD_DATA(user_token_certificate, sUserTokenCertificate)
  STRAND_GUARD_DATA(user_token_certificate_field, sUserTokenCertificateField)
  STRAND_GUARD_DATA(post_response_actions, sPostResponseActions)
  STRAND_GUARD_DATA(
    post_response_action_insert_failure_injector, sPostResponseActionInsertFailureInjectorForTests)
  STRAND_GUARD_DATA(secure_channel_association_epoch, sSecureChannelAssociationEpoch)
  STRAND_GUARD_DATA(parsed_identity_completion_gate, sParsedIdentityCompletionGateForTests)
  STRAND_GUARD_DATA(user_token_signature_completion_gate, sUserTokenSignatureCompletionGateForTests)
  STRAND_GUARD_DATA(
    authenticator_completion_notification_gate, sAuthenticatorCompletionNotificationGateForTests)
  STRAND_GUARD_DATA(set_subscription_durable_operation, sSetSubscriptionDurableOperationForTests)

  // --- Method accessors ---
  STRAND_GUARD_METHOD(inject_decoded_request, sInjectDecodedRequest)
  STRAND_GUARD_METHOD(enqueue_response, sEnqueueResponse)
  STRAND_GUARD_METHOD(pop_queued_response, sPopQueuedResponse)
  STRAND_GUARD_METHOD(set_response_sink, sSetResponseSink)
  STRAND_GUARD_METHOD(browse_response_received, sBrowseResponseReceived)
  STRAND_GUARD_METHOD(history_read_response_received, sHistoryReadResponseReceived)
  STRAND_GUARD_METHOD(response_received, sResponseReceived)
  STRAND_GUARD_METHOD(cancel_outstanding_ops_effect, sCancelOutstandingOpsEffect)
  STRAND_GUARD_METHOD(timeout, sTimeout)
  STRAND_GUARD_METHOD(on_inactivity_tick, sOnInactivityTick)
  STRAND_GUARD_METHOD(request_received, sRequestReceived)
  STRAND_GUARD_METHOD(send_activate_session_response, sSendActivateSessionResponse)
  STRAND_GUARD_METHOD(error_received_from_secure_channel, sErrorReceivedFromSecureChannel)

private:
  friend struct ua::test::StrandTestAccessBase<ua::server::SessionTestAccess, ua::server::Session>;

  explicit StrandGuard(ua::server::Session& a) : mTarget(a)
  {}

  ua::server::Session& mTarget;
};

#endif  // UA_SERVER_SESSION_TEST_ACCESS_H
