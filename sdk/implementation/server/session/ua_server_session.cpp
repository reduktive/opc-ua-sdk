// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Request flow:
//   SecureChannel -> Session::request_received()
//     -> classify request type -> dispatch to internal handler (callback chain)
//       - handle_service_request: state gating, authorization, service dispatch
//       - handle_cancel_request: cancel outstanding ops
//       - activate_internal: channel binding, authentication, state transition
//       - close_internal: send response, close session
//     -> response sent back via SecureChannel
//
// Session lifecycle: Created -> (ActivateSession) -> Activated -> (CloseSession) -> Closed
// ActivateSession triggers authentication; services are gated until Activated.

#include "ua_server_session.h"
#include "ua_session_registered_nodes.h"
#include "ua_session_timeout_revision.h"
#include "ua_callback_safety.h"
#include "ua_claim_keys.h"
#include "ua_certificate_hostname.h"
#include "ua_log_exception.h"
#include "ua_url_parser.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "ua_audit_cancel_event_payload.h"
#include "ua_date_time.h"
#include "ua_event_bus.h"
#include "ua_add_nodes_request.h"
#include "ua_add_references_request.h"
#include "ua_server_impl.h"
#include "ua_timer.h"
#include "secure_channel/ua_server_secure_channel.h"
#include "ua_read_service.h"
#include "ua_browse_request.h"
#include "ua_browse_service.h"
#include "ua_call_request.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_subscription_request.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_references_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_discovery_service_set.h"
#include "ua_history_read_request.h"
#include "ua_history_update_request.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_subscription_request.h"
#include "ua_publish_request.h"
#include "ua_query_first_request.h"
#include "ua_query_next_request.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_register_nodes_service.h"
#include "ua_unregister_nodes_response.h"
#include "ua_register_server2_request.h"
#include "ua_register_server_request.h"
#include "ua_republish_request.h"
#include "ua_security_policy.h"
#include "ua_security_policy_compatibility.h"
#include "ua_security_policy_internal.h"
#include "ua_certificate_validation_paths.h"
#include "ua_user_token_certificate_validation.h"
#include "ua_stack_utilities.h"
#include "ua_status_routing.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_triggering_request.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_unregister_nodes_request.h"

#include "ua_anonymous_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_issued_identity_token.h"

#include "ua_additional_parameters_type.h"
#include "ua_key_value_pair.h"
#include "ua_ephemeral_key_type.h"
#include "ua_credential_redaction.h"
#include "ua_secure_memory.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_ecc_encrypted_secret_decoder.h"
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_user_token_encryption.h"

#include "ua_utilities.h"

#include "openssl/ua_x509_certificate_openssl.h"

#include <ua_method_service_set.h>

#include "ua_node_management_service.h"

#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_on_strand.h"
#include "ua_to_result.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_role_configuration.h"
#include "ua_identity_thumbprint.h"
#include "ua_diagnostic_collector.h"
#include "ua_object_id.h"
#include "ua_diagnostic_policy.h"
#include "ua_server_event_emit.h"
#include "ua_to_string.h"
#include "ua_log_exception.h"

#include "fmt/format.h"

namespace ua::server
{

namespace
{

// The Session's caller for an identity (NR-49 rule 2): the identity with the Session's id, its user's id as
// audit events report it, and the channel's security mode. Null when there is no identity.
std::shared_ptr<const ua::CallerInfo> make_caller(const std::shared_ptr<const ua::AccessIdentity>& identity,
  const ua::NodeId& sessionId, const ua::server::UserIdentity* user,
  const ua::server::EndpointSecurityContext* endpoint)
{
  if (!identity)
  {
    return nullptr;
  }
  auto caller = std::make_shared<ua::CallerInfo>();
  caller->identity = identity;
  caller->sessionId = sessionId;
  if (user)
  {
    caller->clientUserId = String{user->userId};
  }
  if (endpoint)
  {
    caller->channelSecurityMode = endpoint->messageSecurityMode;
  }
  return caller;
}

// The inactivity reaper fires on a fixed grid; a tick reaps only when no request arrived within the
// revised timeout (Session::on_inactivity_tick). With a full-timeout grid the deadline
// (mLastActivity + timeout) falls between ticks, so reaping lags by up to a full timeout - too coarse
// for a client (or UACTT Session Base 002) that probes shortly after the deadline. Tick at a fraction
// of the timeout so an idle session is reaped within ~1/N of the timeout past its deadline, while an
// active session is still never reaped (each tick re-checks mLastActivity). Floored so a very short
// timeout does not schedule a pathologically fast timer.
constexpr int inactivityChecksPerTimeout = 16;
constexpr std::chrono::milliseconds minInactivityCheckPeriod{100};

std::chrono::milliseconds inactivity_check_period(std::chrono::milliseconds revisedSessionTimeout)
{
  return std::max(revisedSessionTimeout / inactivityChecksPerTimeout, minInactivityCheckPeriod);
}

void verify_create_session_certificate_continuity(
  const SecureChannelInfo& secureChannelInfo, const Crypto& crypto, span<const byte> presentedCertificate)
{
  const auto channelCertificate = secureChannelInfo.client_certificate();
  if (!channelCertificate)
  {
    throw UaException{Status::BadSecurityChecksFailed,
      make_error_detail("SecureChannelClientCertificateMissing",
        "Authenticated SecureChannel has no client Application Instance Certificate",
        "Session")};
  }

  if (presentedCertificate.empty())
  {
    throw UaException{Status::BadCertificateInvalid,
      make_error_detail("CreateSessionClientCertificateMissing",
        "CreateSession omitted the client Application Instance Certificate",
        "Session")};
  }

  shared_ptr<const X509Certificate> presentedLeaf;
  try
  {
    // The one chain parser: the field may carry the client's issuers after its leaf (decision 24); the
    // leaf is what is compared with the channel certificate (decision 26).
    auto parsedField = ::ua::detail::parse_certificate_field(crypto, presentedCertificate);
    if (!parsedField.is_good())
    {
      throw UaException{parsedField.status_code()};
    }
    presentedLeaf = std::move(parsedField).value().front();
  }
  catch (...)
  {
    const auto cause = ::ua::exception_to_status_code(std::current_exception());
    throw UaException{Status::BadCertificateInvalid,
      ErrorDetail::build("CreateSessionClientCertificateInvalid",
        "CreateSession client Application Instance Certificate is malformed",
        "Session")
        .cause(cause)};
  }

  if (!presentedLeaf)
  {
    throw UaException{Status::BadCertificateInvalid,
      make_error_detail("CreateSessionClientCertificateInvalid",
        "CreateSession client Application Instance Certificate could not be parsed",
        "Session")};
  }

  if (presentedLeaf->der_encoding() != channelCertificate->der_encoding())
  {
    throw UaException{Status::BadSecurityChecksFailed,
      make_error_detail("CreateSessionClientCertificateMismatch",
        "CreateSession client certificate differs from the SecureChannel certificate",
        "Session")};
  }
}

void verify_create_session_application_uri(
  const X509Certificate& channelCertificate, std::string_view claimedApplicationUri)
{
  const auto certificateUris = channelCertificate.san_uris();
  const bool matches =
    !claimedApplicationUri.empty() && std::ranges::any_of(certificateUris,
                                        [claimedApplicationUri](const std::string& certificateUri)
                                        { return certificateUri == claimedApplicationUri; });
  if (matches)
  {
    return;
  }

  auto detail = ErrorDetail::build("CreateSessionClientApplicationUriMismatch",
    "CreateSession ApplicationUri is absent from the authenticated client certificate URI SANs",
    "Session")
                  .context(ContextKeys::applicationUri, std::string{claimedApplicationUri});
  for (const auto& certificateUri : certificateUris)
  {
    detail.context(ContextKeys::uri, certificateUri);
  }
  throw UaException{Status::BadCertificateUriInvalid, std::move(detail)};
}

// Parse the address out of a `host:port` (or `[v6]:port`) peer address. The peer address is
// formatted from an asio endpoint and so is always numeric.
boost::asio::ip::address peer_address(std::string_view hostPort)
{
  std::string_view host = hostPort;
  if (!host.empty() && host.front() == '[')
  {
    const auto close = host.find(']');
    if (close != std::string_view::npos)
    {
      host = host.substr(1, close - 1);
    }
  }
  else if (const auto colon = host.rfind(':'); colon != std::string_view::npos)
  {
    host = host.substr(0, colon);
  }

  boost::system::error_code ec;
  auto address = boost::asio::ip::make_address(std::string{host}, ec);
  return ec ? boost::asio::ip::address{} : address;
}

}  // namespace

// Part 4 5.6.3: for identity-lockout purposes a Client is identified by IP address on an
// unsecured connection and by its ApplicationInstanceUri on a secured one - the latter carried as
// the certificate's subjectAltName URI (OPC 10000-6 6.2.2). A secured channel presenting no SAN
// URI falls back to the address rather than sharing one empty-URI bucket.
ClientId derive_client_id(const SecureChannelInfo& channelInfo)
{
  if (channelInfo.message_security_mode() != MessageSecurityMode::None)
  {
    if (const auto cert = channelInfo.client_certificate())
    {
      auto sanUris = cert->san_uris();
      if (!sanUris.empty())
      {
        return std::move(sanUris.front());
      }
    }
  }
  return peer_address(channelInfo.remote_address());
}

namespace
{

const char* service_kind_name(Session::ServiceKind kind)
{
  switch (kind)
  {
  case Session::ServiceKind::Read:
    return "Read";
  case Session::ServiceKind::Write:
    return "Write";
  case Session::ServiceKind::Browse:
    return "Browse";
  case Session::ServiceKind::BrowseNext:
    return "BrowseNext";
  case Session::ServiceKind::Call:
    return "Call";
  case Session::ServiceKind::TranslateBrowsePathsToNodeIds:
    return "TranslateBrowsePathsToNodeIds";
  case Session::ServiceKind::RegisterNodes:
    return "RegisterNodes";
  case Session::ServiceKind::UnregisterNodes:
    return "UnregisterNodes";
  case Session::ServiceKind::DiscoveryFindServers:
    return "FindServers";
  case Session::ServiceKind::DiscoveryFindServersOnNetwork:
    return "FindServersOnNetwork";
  case Session::ServiceKind::DiscoveryGetEndpoints:
    return "GetEndpoints";
  case Session::ServiceKind::CreateSubscription:
    return "CreateSubscription";
  case Session::ServiceKind::ModifySubscription:
    return "ModifySubscription";
  case Session::ServiceKind::DeleteSubscriptions:
    return "DeleteSubscriptions";
  case Session::ServiceKind::SetPublishingMode:
    return "SetPublishingMode";
  case Session::ServiceKind::Publish:
    return "Publish";
  case Session::ServiceKind::Republish:
    return "Republish";
  case Session::ServiceKind::CreateMonitoredItems:
    return "CreateMonitoredItems";
  case Session::ServiceKind::DeleteMonitoredItems:
    return "DeleteMonitoredItems";
  case Session::ServiceKind::ModifyMonitoredItems:
    return "ModifyMonitoredItems";
  case Session::ServiceKind::SetMonitoringMode:
    return "SetMonitoringMode";
  case Session::ServiceKind::SetTriggering:
    return "SetTriggering";
  case Session::ServiceKind::TransferSubscriptions:
    return "TransferSubscriptions";
  case Session::ServiceKind::AddNodes:
    return "AddNodes";
  case Session::ServiceKind::AddReferences:
    return "AddReferences";
  case Session::ServiceKind::DeleteNodes:
    return "DeleteNodes";
  case Session::ServiceKind::DeleteReferences:
    return "DeleteReferences";
  case Session::ServiceKind::Unknown:
  default:
    return "Unknown";
  }
}

SessionEventInfo build_session_event_info(const NodeId& sessionId, const std::string& sessionName,
  const optional<SecureChannelInfo>& secureChannelInfo)
{
  SessionEventInfo info;
  info.sessionId = sessionId;
  info.sessionName = sessionName;
  if (secureChannelInfo)
  {
    info.secureChannelId = secureChannelInfo->channel_id();
    info.remoteAddress = secureChannelInfo->remote_address();
  }
  return info;
}

const char* user_identity_kind_name(UserTokenKind kind)
{
  switch (kind)
  {
  case UserTokenKind::Anonymous:
    return "anonymous";
  case UserTokenKind::UserName:
    return "username";
  case UserTokenKind::X509:
    return "x509";
  case UserTokenKind::IssuedToken:
    return "issued_token";
  default:
    return "unknown";
  }
}

}  // namespace

shared_ptr<Session> Session::create(weak_ptr<SessionDependencies> dependencies,
  SecureChannelInfo secureChannelInfo, uint32_t requestId, CreateSessionRequest&& createSessionRequest,
  CreateAdmission admission)
{
  class Wrapper : public Session
  {
  public:
    virtual ~Wrapper() = default;

    // Construction-only helper held solely via shared_ptr<Session>; the base Session
    // already deletes copy/move. Deleting them here too completes Rule-of-5 and keeps
    // the anti-slicing posture explicit.
    Wrapper(const Wrapper&) = delete;
    Wrapper& operator=(const Wrapper&) = delete;
    Wrapper(Wrapper&&) = delete;
    Wrapper& operator=(Wrapper&&) = delete;

    Wrapper(weak_ptr<SessionDependencies> dependencies, boost::asio::any_io_executor executor,
      SecureChannelInfo secureChannelInfo)
      : Session(dependencies, executor, secureChannelInfo)
    {}
  };

  auto deps = dependencies.lock();
  check(deps);

  auto session = make_shared<Wrapper>(dependencies, deps->executor(), secureChannelInfo);

  // The immutable token exists before validation so successful admission can publish the Session
  // without a second cross-strand mutation.
  session->mAuthenticationToken = NodeId(1, Guid::create_and_generate());

  ua::async::post_owning(static_cast<Session*>(session.get()),
    session->mStrand,
    session->mLogger,
    [requestId, csr = std::move(createSessionRequest), admission = std::move(admission)](
      Session& self) mutable
    {
      try
      {
        // Retain the request until create_internal returns so an exception after admission can
        // still emit the one CreateSession-failed event with the original audit fields.
        self.create_internal(requestId, csr, std::move(admission));
      }
      catch (...)
      {
        auto sc = self.handle_unexpected_exception("Session::create", std::current_exception());
        if (self.mCreateCompletionState.load(std::memory_order_acquire) != CreateCompletionState::Suppressed)
        {
          self.notify_create_session_failed(csr, sc);
          self.create_and_send_service_fault(requestId, sc);
        }
        self.rollback_create_admission_on_strand();
      }
    })();
  return session;
}

bool Session::suppress_create_completion_for_eviction() noexcept
{
  auto expected = CreateCompletionState::Pending;
  if (mCreateCompletionState.compare_exchange_strong(
        expected, CreateCompletionState::Suppressed, std::memory_order_acq_rel))
    return true;
  return expected == CreateCompletionState::Committed;
}

void Session::terminate_for_eviction() noexcept
{
  ua::async::post_borrowing(
    this,
    mStrand,
    mLogger,
    [](VoidResult) {},
    VoidResult{Status::BadInternalError},
    [](Session& self, std::function<void(VoidResult)> completion)
    {
      self.terminate_for_eviction_on_strand();
      completion(VoidResult{});
    })();
}

bool Session::creation_committed() const noexcept
{
  return mCreateCompletionState.load(std::memory_order_acquire) == CreateCompletionState::Committed;
}

bool Session::is_activated() const
{
  return mState.load(std::memory_order_acquire) == State::Activated;
}

NodeId Session::session_id() const
{
  auto identity = mIdentity.load();
  return identity ? identity->sessionId : NodeId{};
}

String Session::client_application_uri() const
{
  return mClientApplicationUri;
}

const SessionAuthenticationToken& Session::authentication_token() const
{
  return mAuthenticationToken;
}

void Session::on_inactivity_tick()
{
  if (mSessionState == State::Closed)
  {
    return;
  }

  // A Session whose ActivateSession the server is still holding is not idle. OPC 10000-4 5.6.2 reaps a
  // Session whose CLIENT stopped issuing requests, and this client issued one; what is outstanding is
  // the server's answer. The hold is deliberate - `authnTimeout` keeps a failing credential check off a
  // remotely observable timing grid (a success is not held, owner decision 23), and a slow authenticator
  // is bounded by the same deadline - so reaping through it spends the client's timeout budget on
  // server-side work and answers an outstanding request with a closed Session. It cannot postpone
  // expiry indefinitely either: the authentication interval is bounded and fixed, and the tick that
  // follows it reaps on the ordinary rule below. Without this a revised timeout at or below the
  // authentication interval - which is what the server's own configured minimum is - makes the two a
  // dead heat, and ActivateSession loses it about as often as it wins.
  if (mAuthState)
  {
    return;
  }

  // OPC 10000-4 5.6.2: the session is terminated only after the revised timeout elapses WITHOUT a
  // client request - every Service request (Publish included) is activity that keeps it alive. The
  // timer fires on a fixed grid, so a tick is an actual expiry only when no request has arrived
  // within the revised timeout; otherwise leave the session open and let a later tick reap it. This
  // prevents an actively-used session from being closed out from under the client.
  if (std::chrono::steady_clock::now() - mLastActivity < mRevisedSessionTimeout)
  {
    return;
  }

  timeout();
}

void Session::timeout()
{
  if (mSessionState == State::Closed)
  {
    return;
  }

  mSessionState = State::Closed;
  mOwnedContinuationPointIds.clear();

  try
  {
    // Part 4 5.6.2.1: "If a Server terminates a Session for any other reason, Subscriptions associated
    // with the Session, are not deleted. Each Subscription has its own lifetime to protect against data
    // loss in the case of a Session termination." Orphaning them is what makes the 6.7 reconnect ladder
    // reachable - a client whose Session was reaped while it was away can TransferSubscriptions onto a
    // fresh one. They remain counted against the server-wide subscription limit while parked, and are
    // bounded by their own lifetime and by ResourceLimits::orphanedSubscriptionStore.
    close_session_internal(Status::BadTimeout, {}, /*deleteSubscriptions=*/false);
  }
  catch (...)
  {
    handle_unexpected_exception("Session::timeout", std::current_exception());
  }
}

void Session::activate(uint32_t requestId, ActivateSessionRequest&& activateSessionRequest,
  optional<SecureChannelInfo> secureChannelInfo)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [requestId, asr = std::move(activateSessionRequest), secureChannelInfo](Session& self) mutable
    {
      optional<weak_ptr<SecureChannel>> requestChannel;
      if (secureChannelInfo)
        requestChannel = secureChannelInfo->secure_channel();
      // Precondition: session must have been created (mSessionState transitions to Created
      // synchronously in create_internal before send_create_session_response_async runs).
      if (self.mSessionState == State::Invalid)
      {
        if (auto deps = self.mDependencies.lock())
        {
          deps->logger().warning({{"request_id", std::to_string(requestId)}},
            "Session::activate called in invalid state (session not yet created)");
        }
        self.create_and_send_service_fault(requestId, Status::BadInvalidState, nullptr, 0, requestChannel);
        return;
      }

      try
      {
        self.activate_internal(requestId, std::move(asr), secureChannelInfo);
      }
      catch (...)
      {
        auto sc = self.handle_unexpected_exception("Session::activate", std::current_exception());
        self.create_and_send_service_fault(requestId, sc, nullptr, 0, requestChannel);
      }
    })();
}

void Session::detach_subscription_for_transfer(IntegerId subscriptionId, const UserIdentity& requestingUser,
  const EndpointSecurityContext& requestingSecurity, DetachForTransferCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<SubscriptionDetachResult>{StatusCode{Status::BadSessionIdInvalid}},
    [subscriptionId, requestingUser, requestingSecurity](
      Session& self, DetachForTransferCallback callback) mutable
    {
      try
      {
        auto sessionUser = self.mSessionInfo->user_identity();
        auto sourceSecurity = self.mSessionInfo->endpoint_security();
        if (!sessionUser || !sourceSecurity)
        {
          callback(Result<SubscriptionDetachResult>{StatusCode{Status::BadUserAccessDenied},
            ErrorDetail::build("SubscriptionTransferSourceContextMissing",
              "The source Session has no authenticated transfer context",
              "Session")});
          return;
        }

        SubscriptionTransferContext sourceContext{.owningUser = *sessionUser,
          .verifiedApplicationUri = sourceSecurity->clientApplicationUri,
          .sourceSecurityMode = sourceSecurity->messageSecurityMode};
        auto authorization =
          validate_subscription_transfer(sourceContext, requestingUser, requestingSecurity);
        if (authorization.is_bad())
        {
          callback(Result<SubscriptionDetachResult>{std::move(authorization)});
          return;
        }

        // Check subscription manager exists and has the subscription.
        auto pipeline = self.mSubscriptionsPipeline.load();
        if (!pipeline)
        {
          callback(Result<SubscriptionDetachResult>{StatusCode{Status::BadSubscriptionIdInvalid}});
          return;
        }

        auto detachResult = pipeline->detach_subscription_for_transfer(subscriptionId);
        if (!detachResult)
        {
          callback(Result<SubscriptionDetachResult>{StatusCode{Status::BadSubscriptionIdInvalid}});
          return;
        }

        SubscriptionDetachResult result;
        result.subscription = std::move(detachResult->subscription);
        result.retransmissionEntries = std::move(detachResult->retransmissionEntries);
        callback(Result<SubscriptionDetachResult>{std::move(result)});
      }
      catch (...)
      {
        callback(Result<SubscriptionDetachResult>{StatusCode{Status::BadInternalError}});
      }
    })();
}

void Session::get_monitored_items_async(IntegerId subscriptionId, GetMonitoredItemsCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<MonitoredItemHandles>{StatusCode{Status::BadSessionIdInvalid}},
    [subscriptionId](Session& self, GetMonitoredItemsCallback callback) mutable
    {
      auto pipeline = self.mSubscriptionsPipeline.load();
      if (!pipeline)
      {
        callback(Result<MonitoredItemHandles>{StatusCode{Status::BadSubscriptionIdInvalid}});
        return;
      }

      auto subscription = pipeline->find_subscription(subscriptionId);
      if (!subscription)
      {
        callback(Result<MonitoredItemHandles>{StatusCode{Status::BadSubscriptionIdInvalid}});
        return;
      }

      subscription->get_monitored_item_handles_async(
        [callback = std::move(callback)](MonitoredItemHandles handles) mutable
        { callback(Result<MonitoredItemHandles>{std::move(handles)}); });
    })();
}

void Session::resend_data_async(IntegerId subscriptionId, ResendDataCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadSessionIdInvalid},
    [subscriptionId](Session& self, ResendDataCallback callback)
    {
      auto pipeline = self.mSubscriptionsPipeline.load();
      if (!pipeline)
      {
        callback(StatusCode{Status::BadSubscriptionIdInvalid});
        return;
      }

      auto subscription = pipeline->find_subscription(subscriptionId);
      if (!subscription)
      {
        callback(StatusCode{Status::BadSubscriptionIdInvalid});
        return;
      }

      auto complete = ua::detail::make_fire_once<StatusCode>(ua::async::post_borrowing(&self,
        self.mStrand,
        self.mLogger,
        [callback = std::move(callback)](Session&, StatusCode status) mutable { callback(status); }));
      subscription->resend_initial_values_async(
        [complete](VoidResult result) mutable { complete(result.status_code()); });
    })();
}

void Session::set_subscription_durable_async(
  IntegerId subscriptionId, uint32_t lifetimeInHours, SetSubscriptionDurableCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<uint32_t>{StatusCode{Status::BadSessionIdInvalid}},
    [subscriptionId, lifetimeInHours](Session& self, SetSubscriptionDurableCallback callback) mutable
    {
      // Subscription may complete on its own strand. Consume only the first completion and return
      // to the Session strand with weak lifetime before invoking the public callback.
      auto complete = ::ua::detail::make_fire_once<Result<uint32_t>>(ua::async::post_borrowing(&self,
        self.mStrand,
        self.mLogger,
        [callback = std::move(callback)](Session&, Result<uint32_t> result) mutable
        { callback(std::move(result)); }));

      auto adaptChildCompletion = [complete](StatusCode status, uint32_t revisedHours) mutable
      {
        complete(status.is_bad() ? Result<uint32_t>{status} : Result<uint32_t>{revisedHours});
      };

      try
      {
        if (self.mSetSubscriptionDurableOperationForTests)
        {
          auto subscriptionLimits = self.mSessionInfo->server_configuration().subscriptionLimits;
          self.mSetSubscriptionDurableOperationForTests(
            subscriptionId, lifetimeInHours, std::move(subscriptionLimits), adaptChildCompletion);
          return;
        }

        auto pipeline = self.mSubscriptionsPipeline.load();
        if (!pipeline)
        {
          complete(Result<uint32_t>{StatusCode{Status::BadSubscriptionIdInvalid}});
          return;
        }

        auto subscription = pipeline->find_subscription(subscriptionId);
        if (!subscription)
        {
          complete(Result<uint32_t>{StatusCode{Status::BadSubscriptionIdInvalid}});
          return;
        }

        // Snapshot the durable-subscription policy/limits from config on the session strand and hand
        // them to the subscription (it owns no config of its own). Injected and concrete child
        // operations feed the same Result adapter above.
        auto subscriptionLimits = self.mSessionInfo->server_configuration().subscriptionLimits;
        subscription->set_durable_async(
          lifetimeInHours, std::move(subscriptionLimits), std::move(adaptChildCompletion));
      }
      catch (...)
      {
        complete(Result<uint32_t>{::ua::exception_to_status_code(std::current_exception())});
      }
    })();
}

void Session::close(uint32_t requestId, CloseSessionRequest&& closeSessionRequest)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [requestId, csr = std::move(closeSessionRequest)](Session& self) mutable
    {
      try
      {
        self.close_internal(requestId, std::move(csr));
      }
      catch (...)
      {
        auto sc = self.handle_unexpected_exception("Session::close", std::current_exception());
        self.create_and_send_service_fault(requestId, sc);
      }
    })();
}

void Session::terminate_for_shutdown()
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [](Session& self)
    {
      self.set_close_reason(Status::BadShutdown);
      self.timeout();
    })();
}

void Session::reevaluate_certificates_async()
{
  ua::async::post_borrowing(
    this, mStrand, mLogger, [](Session& self) { self.reevaluate_certificates_on_strand(); })();
}

void Session::reevaluate_certificates_after_response_async(MethodResponseCorrelation correlation)
{
  // This overload deliberately schedules fire-and-forget revalidation after the wire response; its caller has
  // no use for the registration result because no service response remains available to carry it.
  reevaluate_certificates_after_response_async(correlation, [](Result<weak_ptr<SecureChannel>>) {});
}

void Session::reevaluate_certificates_after_response_async(
  MethodResponseCorrelation correlation, std::function<void(Result<weak_ptr<SecureChannel>>)> callback)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    Result<weak_ptr<SecureChannel>>{Status::BadSessionClosed},
    [correlation](Session& self, std::function<void(Result<weak_ptr<SecureChannel>>)> postCallback)
    {
      Result<weak_ptr<SecureChannel>> result{weak_ptr<SecureChannel>{}};
      try
      {
        if (correlation.channelAssociationEpoch != self.mSecureChannelAssociationEpoch)
        {
          result = Result<weak_ptr<SecureChannel>>{Status::BadSecureChannelIdInvalid,
            make_error_detail("StaleMethodResponseCorrelation",
              "Method response correlation belongs to a different SecureChannel association",
              "Session")};
        }
        else
        {
          auto secureChannel =
            self.mSecureChannelInfo ? self.mSecureChannelInfo->secure_channel().lock() : nullptr;
          const bool holdsCertificate =
            (self.mState == State::Created || self.mState == State::Activated) &&
            (self.mClientCertificate || (self.mState == State::Activated && self.mUserTokenCertificate));
          if (holdsCertificate)
          {
            auto entry =
              std::ranges::find(self.mPostResponseActions, correlation, &PostResponseActions::correlation);
            if (entry == self.mPostResponseActions.end())
            {
              if (self.mPostResponseActionInsertFailureInjectorForTests)
                self.mPostResponseActionInsertFailureInjectorForTests();
              self.mPostResponseActions.push_back(PostResponseActions{
                .correlation = correlation,
                .reevaluateCertificates = true,
              });
            }
            else
            {
              entry->reevaluateCertificates = true;
            }
          }
          // The channel is deferred only when its re-evaluation was registered; otherwise the caller
          // re-evaluates it with the others now.
          result = Result<weak_ptr<SecureChannel>>{
            holdsCertificate ? weak_ptr<SecureChannel>{secureChannel} : weak_ptr<SecureChannel>{}};
        }
      }
      catch (...)
      {
        result = Result<weak_ptr<SecureChannel>>{::ua::exception_to_status_code(std::current_exception())};
      }

      postCallback(std::move(result));
    })();
}

void Session::close_secure_channel_after_response_async(
  MethodResponseCorrelation correlation, std::function<void(Result<weak_ptr<SecureChannel>>)> callback)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    Result<weak_ptr<SecureChannel>>{Status::BadSessionClosed},
    [correlation](Session& self, std::function<void(Result<weak_ptr<SecureChannel>>)> postCallback)
    {
      Result<weak_ptr<SecureChannel>> result{Status::BadInternalError};
      try
      {
        if (correlation.channelAssociationEpoch != self.mSecureChannelAssociationEpoch)
        {
          result = Result<weak_ptr<SecureChannel>>{Status::BadSecureChannelIdInvalid,
            make_error_detail("StaleMethodResponseCorrelation",
              "Method response correlation belongs to a different SecureChannel association",
              "Session")};
        }
        else
        {
          auto secureChannel =
            self.mSecureChannelInfo ? self.mSecureChannelInfo->secure_channel().lock() : nullptr;
          if (!secureChannel)
          {
            result = Result<weak_ptr<SecureChannel>>{Status::BadSecureChannelIdInvalid,
              make_error_detail("OriginSecureChannelChanged",
                "ApplyChanges origin SecureChannel no longer matches its response correlation",
                "Session")};
          }
          else
          {
            auto entry =
              std::ranges::find(self.mPostResponseActions, correlation, &PostResponseActions::correlation);
            if (entry == self.mPostResponseActions.end())
            {
              if (self.mPostResponseActionInsertFailureInjectorForTests)
                self.mPostResponseActionInsertFailureInjectorForTests();
              self.mPostResponseActions.push_back(PostResponseActions{
                .correlation = correlation,
                .closeSecureChannel = true,
              });
            }
            else
            {
              entry->closeSecureChannel = true;
            }
            result = Result<weak_ptr<SecureChannel>>{weak_ptr<SecureChannel>{secureChannel}};
          }
        }
      }
      catch (...)
      {
        result = Result<weak_ptr<SecureChannel>>{::ua::exception_to_status_code(std::current_exception())};
      }

      postCallback(std::move(result));
    })();
}

void Session::invalidate_post_response_actions_on_strand(shared_ptr<SecureChannel> previousChannel)
{
  ++mSecureChannelAssociationEpoch;
  if (mSecureChannelAssociationEpoch == 0)
    ++mSecureChannelAssociationEpoch;
  const bool reevaluationDropped = std::ranges::any_of(
    mPostResponseActions, [](const PostResponseActions& actions) { return actions.reevaluateCertificates; });
  mPostResponseActions.clear();
  // A deferred re-evaluation is never dropped, only brought forward: its response will not be written on
  // that association, so the Session and the channel it was correlated with re-evaluate now (review BR-13).
  if (reevaluationDropped)
  {
    reevaluate_certificates_on_strand();
    if (previousChannel)
      previousChannel->reevaluate_certificate_async();
  }
}

void Session::on_response_enqueued_on_strand(
  MethodResponseCorrelation correlation, weak_ptr<SecureChannel> secureChannel, VoidResult enqueueResult)
{
  auto entry = std::ranges::find(mPostResponseActions, correlation, &PostResponseActions::correlation);
  if (entry == mPostResponseActions.end())
    return;

  const auto actions = *entry;
  mPostResponseActions.erase(entry);

  // A deferred re-evaluation whose response did not go out is brought forward, never dropped (review BR-13).
  const auto reevaluateNow = [&]
  {
    if (!actions.reevaluateCertificates)
      return;
    reevaluate_certificates_on_strand();
    if (auto channel = secureChannel.lock())
      channel->reevaluate_certificate_async();
  };

  if (enqueueResult.is_bad())
  {
    mLogger.error({{"request_id", uint64_t{correlation.requestId}},
                    {"status_code", uint64_t{enqueueResult.status_code().value()}}},
      "Correlated response did not cross the SecureChannel outgoing queue boundary: {}",
      enqueueResult.shared_detail() ? to_string(*enqueueResult.shared_detail()) : std::string{"no detail"});
    reevaluateNow();
    return;
  }

  auto currentChannel =
    mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : shared_ptr<SecureChannel>{};
  if (correlation.channelAssociationEpoch != mSecureChannelAssociationEpoch || !currentChannel ||
      currentChannel != secureChannel.lock())
  {
    mLogger.warning({{"request_id", uint64_t{correlation.requestId}}},
      "Ignoring correlated response confirmation from a stale SecureChannel association");
    reevaluateNow();
    return;
  }

  if (actions.reevaluateCertificates)
  {
    reevaluate_certificates_on_strand();
  }

  // actions.closeSecureChannel: the channel closes itself once the response is written, and
  // actions.reevaluateCertificates re-evaluates it then (see the send).
}

void Session::reevaluate_certificates_on_strand()
{
  if (mState != State::Created && mState != State::Activated)
    return;
  auto dependencies = mDependencies.lock();
  if (!dependencies)
    return;
  reevaluate_client_certificate_on_strand(*dependencies);
  reevaluate_user_identity_on_strand(dependencies->user_token_certificate_store());
}

void Session::reevaluate_client_certificate_on_strand(SessionDependencies& dependencies)
{
  auto store = dependencies.default_application_group_certificate_store();
  if (!mClientCertificate || !store)
    return;

  // The same validation the OpenSecureChannel ran: the leaf, the issuers presented with it and the
  // channel's SecurityPolicy, against the DefaultApplicationGroup as it is now. The store files a
  // refused certificate in its rejected list as it does at the open; the SecureChannel that presented
  // it reports the refusal, so a Session (which may outlive that channel) only closes.
  CertificateValidationRequest request;
  request.certificate = mClientCertificate;
  request.presentedIssuers = mClientIssuerCertificates;
  request.use = CertificateUse::ClientApplicationInstance;
  if (mClientCertificatePolicy)
  {
    request.policyId = mClientCertificatePolicy->id();
  }
  store->validate_certificate_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [expectedCertificate = mClientCertificate](Session& session, VoidResult validationResult) mutable
      {
        if ((session.mState != State::Created && session.mState != State::Activated) ||
            session.mClientCertificate != expectedCertificate || validationResult)
        {
          return;
        }
        session.mLogger.with_category("session").warning(
          {{"session_name", std::string_view{session.mSessionName}},
            {"subject", expectedCertificate->subject_common_name()}},
          "Closing session: its client certificate is no longer trusted after a trust-list update");

        // Part 12 7.8.2.3: "Sessions with an untrusted or revoked Certificate shall be closed."
        session.close_session_internal(Status::BadSecurityChecksFailed,
          ErrorDetail::build("ClientCertificateNoLongerValid",
            "Client certificate is no longer trusted after a trust-list update",
            "Session")
            .cause(validationResult.status_code()),
          /*deleteSubscriptions=*/true);
      }));
}

void Session::reevaluate_user_identity_on_strand(shared_ptr<CertificateStore> userTokenCertificateStore)
{
  if (!userTokenCertificateStore || mState != State::Activated || !mUserTokenCertificate)
    return;

  auto dependencies = mDependencies.lock();
  auto crypto = dependencies ? dependencies->crypto() : nullptr;
  auto expectedCertificate = mUserTokenCertificate;
  // The same function as the activation (owner review 2026-10-02, item 8): the stored field and the
  // user-token policy against the current user-token trust material.
  server::detail::validate_user_token_certificate_async(std::move(userTokenCertificateStore),
    std::move(crypto),
    mUserTokenCertificateField,
    mUserTokenPolicy,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [expectedCertificate = std::move(expectedCertificate)](
        Session& session, VoidResult validationResult) mutable
      {
        if (session.mState != State::Activated || session.mUserTokenCertificate != expectedCertificate)
        {
          return;
        }
        auto deps = session.mDependencies.lock();
        auto observer = deps ? deps->observer() : nullptr;
        const std::string remoteAddress =
          session.mSecureChannelInfo ? session.mSecureChannelInfo->remote_address() : std::string{};
        if (validationResult)
        {
          // Item 9: errors the re-evaluation suppressed are reported like an activation's.
          if (auto suppressed = ::ua::detail::suppressed_certificate_errors(validationResult);
              deps && !suppressed.empty())
          {
            detail::emit_event(deps->logger(),
              observer,
              [&] {
                detail::report_suppressed_certificate_errors(
                  observer, remoteAddress, expectedCertificate, suppressed);
              });
          }
          return;
        }
        if (deps)
        {
          // Decision 27: the refused user certificate with its Table 106 fault.
          CertificateEventInfo info;
          info.remoteAddress = remoteAddress;
          info.certificate = expectedCertificate;
          const auto refusal = validationResult.shared_detail();
          info.status = refusal && refusal->innerStatus != utils::to_underlying(Status::Good)
                          ? StatusCode{refusal->innerStatus}
                          : validationResult.status_code();
          detail::emit_event(deps->logger(), observer, [&] { observer->on_certificate_rejected(info); });
        }

        session.mLogger.with_category("session").warning(
          {{"session_name", std::string_view{session.mSessionName}},
            {"subject", expectedCertificate->subject_common_name()}},
          "Closing session: its user certificate is no longer trusted after a trust-list update");

        // Part 12 7.10.6 closes the Session and associated Subscriptions when its UserIdentity is
        // no longer valid after a user-token TrustList change.
        session.close_session_internal(Status::BadIdentityTokenRejected,
          ErrorDetail::build("UserIdentityNoLongerValid",
            "User certificate is no longer trusted after a trust-list update",
            "Session")
            .cause(validationResult.status_code()),
          /*deleteSubscriptions=*/true);
      }));
}

void Session::create_internal(
  uint32_t requestId, CreateSessionRequest createSessionRequest, CreateAdmission admission)
{
  // Record the RequestHandle up front so every CreateSession fault path echoes it (CreateSession is
  // handled before the per-session dispatch that records handles for other services - see
  // create_and_send_service_fault).
  mRequestHandlesByRequestId[requestId] = createSessionRequest.request_header().request_handle();

  // The secure channel info is supplied by value at construction and is always engaged here:
  // create_internal runs from the create() strand post, before any channel-loss path can empty
  // it. Bind a checked reference so subsequent dereferences are statically provable.
  if (!mSecureChannelInfo.has_value())
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("MissingSecureChannel", "Session created without a secure channel", "Session")};
  }
  const auto& secureChannelInfo = *mSecureChannelInfo;

  const auto securityPolicy = secureChannelInfo.security_policy();
  if (securityPolicy && securityPolicy->is_authenticated())
  {
    const auto dependencies = mDependencies.lock();
    const auto crypto = dependencies ? dependencies->crypto() : nullptr;
    if (!crypto)
    {
      StatusCode failure{Status::BadSecurityChecksFailed,
        make_error_detail("CreateSessionCertificateVerificationUnavailable",
          "CreateSession client certificate continuity cannot be verified",
          "Session")};
      notify_create_session_failed(createSessionRequest, failure);
      create_and_send_service_fault(requestId, failure);
      return;
    }

    try
    {
      verify_create_session_certificate_continuity(
        secureChannelInfo, *crypto, createSessionRequest.client_certificate());
      verify_create_session_application_uri(*secureChannelInfo.client_certificate(),
        static_cast<std::string_view>(createSessionRequest.client_description().application_uri()));
    }
    catch (...)
    {
      auto failure = ::ua::exception_to_status_code(std::current_exception());
      if (failure.as_status() == Status::BadCertificateUriInvalid && dependencies)
      {
        // Decision 27 / Part 5 6.4.13: the URI step refused the presented client certificate; reported
        // before the CreateSession audit so that audit can name the certificate event.
        CertificateEventInfo info;
        info.remoteAddress = secureChannelInfo.remote_address();
        info.certificate = secureChannelInfo.client_certificate();
        info.status = failure;
        info.invalidUri = std::string{
          static_cast<std::string_view>(createSessionRequest.client_description().application_uri())};
        auto observer = dependencies->observer();
        detail::emit_event(
          dependencies->logger(), observer, [&] { observer->on_certificate_rejected(info); });
      }
      notify_create_session_failed(createSessionRequest, failure);
      create_and_send_service_fault(requestId, failure);
      return;
    }
  }

  mSessionName = createSessionRequest.session_name();
  if (mSessionName.empty())
    mSessionName = fmt::format("Session_{}", ua::to_string(Guid::create_and_generate()));

  if (mSessionState == State::Closed)
  {
    StatusCode failure{Status::BadSessionIdInvalid};
    notify_create_session_failed(createSessionRequest, failure);
    create_and_send_service_fault(requestId, failure);
    return;
  }

  // P4-SS-0023: "A Server shall check the minimum length of the Client nonce and return
  // Bad_NonceInvalid if the length is below 32 bytes." Part 4 1.05.07 5.7.2 bounds it above too: "between 32
  // and 128 bytes inclusive. The Server shall check the length." The ceiling holds on every SecurityMode; the
  // floor is applied on authenticated policies, where the nonce is a challenge (a None-mode client may send
  // none; plan G-56).
  const bool isAuthenticated = securityPolicy && securityPolicy->is_authenticated();
  const auto clientNonceSize = createSessionRequest.client_nonce().size();
  const bool tooShort = isAuthenticated && clientNonceSize < stack_utils::minimumSessionNonceLength;
  if (tooShort || clientNonceSize > stack_utils::maximumSessionNonceLength)
  {
    StatusCode failure{Status::BadNonceInvalid,
      ua::ErrorDetail::build(tooShort ? "ClientNonceTooShort" : "ClientNonceTooLong",
        tooShort ? "Client nonce shorter than the required minimum length"
                 : "Client nonce longer than the permitted maximum length",
        "Session")
        .context(ua::ContextKeys::sizeActual, std::to_string(clientNonceSize))
        .context(ua::ContextKeys::sizeMin, std::to_string(stack_utils::minimumSessionNonceLength))
        .context(ua::ContextKeys::sizeMax, std::to_string(stack_utils::maximumSessionNonceLength))};
    notify_create_session_failed(createSessionRequest, failure);
    create_and_send_service_fault(requestId, failure);
    return;
  }

  auto sc = secureChannelInfo.secure_channel().lock();
  if (!sc)
  {
    if (auto deps = mDependencies.lock())
    {
      deps->logger().with_category("session").error(
        "Session::create_internal: secure channel expired={}, endpointPolicyId='{}'",
        secureChannelInfo.secure_channel().expired(),
        secureChannelInfo.endpoint_policy_id());
    }
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidSecureChannel", "Secure channel is invalid", "Session")
        .context(ua::ContextKeys::secureChannelExpired,
          secureChannelInfo.secure_channel().expired() ? "true" : "false")
        .context(ua::ContextKeys::endpointPolicyId, std::string{secureChannelInfo.endpoint_policy_id()})};
  }

  mClientCertificate = secureChannelInfo.client_certificate();
  if (mClientCertificate)
  {
    mClientIssuerCertificates = secureChannelInfo.client_issuer_certificates();
    mClientCertificatePolicy = securityPolicy;
  }
  mClientNonce = createSessionRequest.client_nonce();
  mChannelSecurityPolicyId = securityPolicy ? securityPolicy->id() : SecurityPolicyId::Invalid;
  mChannelSecurityMode = secureChannelInfo.message_security_mode();
  // The ApplicationDescription field is attacker-controlled until the URI-SAN comparison above
  // succeeds. A None channel has no authenticated client certificate, so it contributes no verified
  // application identity to Role evaluation or subscription-transfer ownership.
  mClientApplicationUri =
    isAuthenticated ? createSessionRequest.client_description().application_uri() : String{};

  // Revise the client-requested session timeout into the server's min/max window. The value is a
  // wire Double: NaN, infinities and negatives are revised (SVR-SESS-014), never converted as they are.
  if (auto deps = mDependencies.lock())
  {
    const auto& stackLimits = deps->configuration().stack_limits();
    mRevisedSessionTimeout = detail::revise_session_timeout(createSessionRequest.requested_session_timeout(),
      stackLimits.sessionMinimumTimeout,
      stackLimits.sessionMaximumTimeout);
  }
  else
  {
    mRevisedSessionTimeout = detail::revise_session_timeout(createSessionRequest.requested_session_timeout(),
      std::chrono::milliseconds{60'000},
      std::chrono::milliseconds{3'600'000});
  }

  if (auto deps = mDependencies.lock())
  {
    deps->logger().with_category("session").debug(
      {{"session_timeout_ms", int64_t(mRevisedSessionTimeout.count())}}, "Session timeout configured");
  }

  mMaxResponseMessageSize = createSessionRequest.max_response_message_size();
  // Exposed to services through SessionInfo, which bounds a Read response by it (SVC-12).
  mSessionInfo->set_max_response_message_size(mMaxResponseMessageSize);
  mSessionId = NodeId(1, Guid::create_and_generate());
  // mAuthenticationToken is immutable and was assigned before this strand turn.

  // Publish immutable identity snapshot for cross-strand observability (health_snapshot).
  mIdentity.store(std::make_shared<const SessionIdentity>(SessionIdentity{mSessionId, mSessionName}));

  auto me = this->weak_from_this();

  // Seed the inactivity clock at creation so the first interval is measured from now (the next
  // request - ActivateSession - refreshes it via request_received).
  const auto openedAt = std::chrono::steady_clock::now();
  mLastActivity = openedAt;

  // Part 5 12.11: the descriptive half of SessionDiagnosticsDataType. Every value here is already
  // in hand at this point, so the record is a copy rather than new bookkeeping. localeIds arrives
  // later, at ActivateSession.
  {
    const std::lock_guard lock{mDescriptiveState->mutex};
    mDescriptiveState->sessionName = mSessionName;
    mDescriptiveState->clientDescription = createSessionRequest.client_description();
    mDescriptiveState->serverUri = createSessionRequest.server_uri();
    mDescriptiveState->endpointUrl = createSessionRequest.endpoint_url();
    mDescriptiveState->revisedSessionTimeout = mRevisedSessionTimeout;
    mDescriptiveState->clientConnectionTime = DateTime::now();
    mDescriptiveState->connectionSteadyOrigin = openedAt;
  }
  mDescriptiveState->note_activity(openedAt);

  mTimeoutTimer = Timer::schedule_every(mStrand,
    inactivity_check_period(mRevisedSessionTimeout),
    [me](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      auto session = me.lock();
      if (session)
      {
        session->on_inactivity_tick();
      }
    });

  if (admission)
  {
    auto admissionResult = admission(shared_from_this());
    if (admissionResult.is_bad())
    {
      notify_create_session_failed(createSessionRequest, admissionResult.status_code());
      create_and_send_service_fault(requestId, admissionResult.status_code());
      return;
    }
    mCreateAdmissionPublished = true;
  }

  sc->register_session(
    mAuthenticationToken,
    [me, scWeak = secureChannelInfo.secure_channel(), associationEpoch = mSecureChannelAssociationEpoch](
      Request request)
    {
      auto lockedSession = me.lock();
      if (lockedSession)
      {
        ua::async::post_borrowing(lockedSession.get(),
          lockedSession->mStrand,
          lockedSession->mLogger,
          [associationEpoch, scWeak, request](Session& session)
          {
            try
            {
              session.request_received_from_secure_channel_if_current(associationEpoch, scWeak, request);
            }
            catch (...)
            {
              session.handle_unexpected_exception("Session::request_received", std::current_exception());
            }
          })();
        return;
      }

      // Session no longer exists (closed+removed). Reply as unknown session.
      if (auto lockedSc = scWeak.lock())
      {
        lockedSc->send_response_message(std::make_pair(std::get<uint32_t>(request),
          stack_utils::create_service_fault(nullptr, Status::BadSessionIdInvalid)));
      }
    },
    [me,
      reportingChannel = secureChannelInfo.secure_channel(),
      associationEpoch = mSecureChannelAssociationEpoch](
      StatusCode status, shared_ptr<const ErrorDetail> detail)
    {
      auto lockedSession = me.lock();
      if (lockedSession)
      {
        ua::async::post_borrowing(lockedSession.get(),
          lockedSession->mStrand,
          lockedSession->mLogger,
          [associationEpoch, reportingChannel, status, detail = std::move(detail)](Session& session)
          {
            try
            {
              session.error_received_from_secure_channel_if_current(
                associationEpoch, reportingChannel, status, detail);
            }
            catch (...)
            {
              session.handle_unexpected_exception(
                "Session::error_received_from_secure_channel", std::current_exception());
            }
          })();
      }
    });

  // Create per-session diagnostic object if diagnostics are enabled.
  {
    auto deps = mDependencies.lock();
    if (deps)
    {
      auto diagEnabled = deps->diagnostics_enabled();
      if (diagEnabled && diagEnabled->load(std::memory_order_relaxed))
      {
        // Populate initial security state from the client certificate. The Session is already
        // published, so a diagnostics Read can run concurrently. The lock is released before
        // want_diagnostics_object, which takes it again to create the diagnostics object.
        {
          const std::lock_guard lock{mSecurityState->mutex};
          mSecurityState->sessionId = mSessionId;
          if (mClientCertificate)
          {
            mSecurityState->clientCertificate = mClientCertificate->der_encoding();
          }
        }

        want_diagnostics_object(true);
      }
    }
  }

  mSessionState = State::Created;

  // Store request for response building.
  mInFlightRequestsByRequestId[requestId] = std::make_shared<CreateSessionRequest>(createSessionRequest);

  auto meCb = weak_from_this();
  send_create_session_response_async(requestId,
    [meCb](VoidResult result) mutable
    {
      auto lockedSelf = meCb.lock();
      if (!lockedSelf)
        return;
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [result = std::move(result)](Session& self) mutable
        {
          if (result.is_bad())
          {
            if (auto deps = self.mDependencies.lock())
            {
              deps->logger().with_category("session").error(
                {{"session_name", std::string_view{self.mSessionName}},
                  {"status", fmt::format("0x{:08x}", result.status_code().as_uint32())}},
                "Failed to send CreateSession response");
            }
            // fail_create_response inside send_create_session_response_async already routed
            // through create_and_send_service_fault - nothing more to do here.
            self.rollback_create_admission_on_strand();
          }
        })();
    });
}

void Session::notify_create_session_failed(const CreateSessionRequest& request, StatusCode reason)
{
  if (mCreateFailureNotified)
    return;
  mCreateFailureNotified = true;
  auto deps = mDependencies.lock();
  if (!deps)
    return;

  auto eventInfo = build_session_event_info(mSessionId, mSessionName, mSecureChannelInfo);
  eventInfo.auditEntryId = request.request_header().audit_entry_id();
  eventInfo.endpointUrl = request.endpoint_url();
  eventInfo.revisedSessionTimeout = static_cast<double>(mRevisedSessionTimeout.count());
  if (mClientCertificate)
  {
    eventInfo.clientCertificate = mClientCertificate->der_encoding();
    eventInfo.clientCertificateThumbprint = ua::to_string(mClientCertificate->thumbprint());
  }

  auto observer = deps->observer();
  detail::emit_event(
    deps->logger(), observer, [&] { observer->on_session_create_failed(eventInfo, reason); });
}

namespace
{
/// The one detail every RequestIdInFlight refusal carries (SESS-7): a requestId still in flight on the
/// session is refused rather than overwriting the request that holds it.
std::shared_ptr<const ErrorDetail> request_id_in_flight_detail(uint32_t requestId)
{
  return ErrorDetail::build("RequestIdInFlight",
    "a request with this requestId is already in flight on this session; the newcomer is refused rather "
    "than overwriting it",
    "Session")
    .context(ua::ContextKeys::requestId, std::to_string(requestId));
}
}  // namespace

void Session::activate_internal(uint32_t requestId, ActivateSessionRequest&& activateSessionRequest,
  optional<SecureChannelInfo> secureChannelInfo)
{
  optional<weak_ptr<SecureChannel>> requestChannel;
  if (secureChannelInfo)
    requestChannel = secureChannelInfo->secure_channel();
  // SESS-7: an ActivateSession under a requestId still in flight is refused like any other request; it
  // must not overwrite the entry (nor its recorded handle) of the request that holds the id. On a
  // different channel the holder is an old-channel request, and the refusal is retryable
  // (Bad_ServerTooBusy): the client's next attempt carries a fresh id.
  if (mInFlightRequestsByRequestId.contains(requestId))
  {
    create_and_send_service_fault(requestId,
      Status::BadServerTooBusy,
      request_id_in_flight_detail(requestId),
      activateSessionRequest.request_header().return_diagnostics(),
      requestChannel,
      activateSessionRequest.request_header().request_handle());
    return;
  }
  // Record the RequestHandle in the handler (not request_received) so it is captured on every entry
  // path - including Session::activate(), which dispatches here directly - letting every
  // ActivateSession fault echo it (see create_and_send_service_fault).
  mRequestHandlesByRequestId[requestId] = activateSessionRequest.request_header().request_handle();

  auto deps = mDependencies.lock();
  check(deps);

  // Compute channel-binding inputs for P4-SS-0026/0027.
  // mSecureChannelInfo may be empty if the previous channel was lost - the session stays
  // alive for its timeout duration and can be re-activated on a new channel.
  bool isDifferentChannel = false;
  bool isDifferentCertificate = false;
  const bool isChannelless = !mSecureChannelInfo.has_value();

  if (isChannelless && secureChannelInfo.has_value())
  {
    // Session lost its channel - any new channel is "different" for re-registration
    // and P4-SS-0027 enforcement.
    isDifferentChannel = true;

    // P4-SS-0027: certificate must match the original. Use mClientCertificate (stored at
    // CreateSession time) since mSecureChannelInfo is gone.
    auto newCert = secureChannelInfo->client_certificate();
    if (newCert && mClientCertificate)
      isDifferentCertificate = newCert->der_encoding() != mClientCertificate->der_encoding();
    else
      isDifferentCertificate = (newCert != nullptr) != (mClientCertificate != nullptr);
  }
  else if (secureChannelInfo.has_value() && mSecureChannelInfo.has_value())
  {
    auto origSc = mSecureChannelInfo->secure_channel().lock();
    auto newSc = secureChannelInfo->secure_channel().lock();
    // Fail closed (SVR-SESS-026): a channel that cannot be proven the same is different. An expired
    // original channel proves nothing, and a reused address could otherwise match by accident.
    isDifferentChannel = !origSc || !newSc || origSc.get() != newSc.get();
    if (isDifferentChannel)
    {
      auto newCert = secureChannelInfo->client_certificate();
      auto origCert = mClientCertificate;
      if (newCert && origCert)
        isDifferentCertificate = newCert->der_encoding() != origCert->der_encoding();
      else
        isDifferentCertificate = (newCert != nullptr) != (origCert != nullptr);
    }
  }

  // State check (was in SessionLogic::ActivateSessionRequestEvent handler).
  if (mSessionState == State::Closed)
  {
    create_and_send_service_fault(requestId, Status::BadSessionIdInvalid, nullptr, 0, requestChannel);
    return;
  }

  // P4-SS-0026: "When the ActivateSession Service is called for the first time then the Server
  // shall reject the request if the SecureChannel is not same as the one associated with the
  // CreateSession request."
  if (mSessionState == State::Created && isDifferentChannel)
  {
    create_and_send_service_fault(requestId, Status::BadSecureChannelIdInvalid, nullptr, 0, requestChannel);
    return;
  }

  // P4-SS-0027: "the Server shall verify that the Certificate the Client used to create the new
  // SecureChannel is the same as the Certificate used to create the original SecureChannel."
  if (mSessionState == State::Activated && isDifferentChannel && isDifferentCertificate)
  {
    create_and_send_service_fault(requestId, Status::BadSecureChannelIdInvalid, nullptr, 0, requestChannel);
    return;
  }

  // OPC 10000-4 5.7.3.1 (1.05.07; owner decision D-6, every SecurityPolicy): "the Server shall verify that
  // the SecurityPolicy and SecurityMode are the same as the original SecureChannel", and "If an Anonymous
  // UserIdentityToken is used, then ActivateSession over a new SecureChannel shall fail if the SecureChannel
  // is using Sign". Only a move that keeps both succeeds, so the Session's SecureChannel - or, while it has
  // none, the policy and mode recorded at CreateSession - is the original's. Refused before anything changes,
  // so the Session stays where it is. Cost: two compares.
  if (mSessionState == State::Activated && isDifferentChannel && secureChannelInfo.has_value())
  {
    const auto newPolicy = secureChannelInfo->security_policy()->id();
    const auto newMode = secureChannelInfo->message_security_mode();
    const auto originalPolicy =
      mSecureChannelInfo ? mSecureChannelInfo->security_policy()->id() : mChannelSecurityPolicyId;
    const auto originalMode =
      mSecureChannelInfo ? mSecureChannelInfo->message_security_mode() : mChannelSecurityMode;
    if (newPolicy != originalPolicy || newMode != originalMode)
    {
      create_and_send_service_fault(requestId,
        StatusCode{Status::BadSecurityPolicyRejected},
        std::shared_ptr<const ErrorDetail>(ErrorDetail::build("SecurityChangedOnNewChannel",
          "A re-activation over a new SecureChannel uses another SecurityPolicy or SecurityMode than the "
          "Session's original SecureChannel",
          "Session")
                                             .context(ua::ContextKeys::securityPolicy,
                                               std::string{secureChannelInfo->security_policy()->uri()})
                                             .context(ua::ContextKeys::securityMode, ua::to_string(newMode))),
        activateSessionRequest.request_header().return_diagnostics(),
        requestChannel);
      return;
    }
    auto* rawToken = activateSessionRequest.user_identity_token().get();
    const bool anonymous =
      (rawToken == nullptr) || (dynamic_cast<AnonymousIdentityToken*>(rawToken) != nullptr);
    if (anonymous && newMode == MessageSecurityMode::Sign)
    {
      create_and_send_service_fault(requestId,
        StatusCode{Status::BadIdentityTokenRejected},
        make_error_detail("AnonymousOverNewSignChannel",
          "An Anonymous re-activation over a new SecureChannel in Sign mode is not allowed",
          "Session"),
        activateSessionRequest.request_header().return_diagnostics(),
        requestChannel);
      return;
    }
  }

  // P4-SS-0027: "the Server shall verify that the Client supplied a UserIdentityToken that is
  // identical to the token currently associated with the Session."
  bool sameIdentityRequired = false;
  if (mSessionState == State::Activated && isDifferentChannel)
  {
    auto currentUser = mSessionInfo->user_identity();
    if (currentUser)
    {
      // The token itself cannot be compared byte for byte (a secret is encrypted under a fresh nonce on
      // every activation), so the identity the authenticator derives from it is compared with the
      // committed one once authentication completes, before the Session takes the new channel
      // (on_activate_authenticated), for every token kind. Carried with this request only, so an
      // overlapping ActivateSession cannot clear it.
      sameIdentityRequired = true;
      auto* rawToken = activateSessionRequest.user_identity_token().get();
      bool tokenMatches = false;

      switch (currentUser->kind)
      {
      case UserTokenKind::Anonymous:
        tokenMatches = (rawToken == nullptr) || (dynamic_cast<AnonymousIdentityToken*>(rawToken) != nullptr);
        break;
      case UserTokenKind::UserName:
        if (auto* un = dynamic_cast<UserNameIdentityToken*>(rawToken))
          tokenMatches = (std::string{un->user_name()} == currentUser->userId);
        break;
      case UserTokenKind::X509:
        // X509: parse the presented certificate and compare its thumbprint with the thumbprint claim
        // the authenticator stored (the user id is the certificate's common name, not the thumbprint).
        if (auto* x509 = dynamic_cast<X509IdentityToken*>(rawToken))
        {
          auto certData = x509->certificate_data();
          const auto storedThumbprint = currentUser->claims.find(ClaimKeys::thumbprint);
          if (!certData.empty() && storedThumbprint != currentUser->claims.end())
          {
            auto deps2 = mDependencies.lock();
            if (deps2 && deps2->crypto())
            {
              try
              {
                auto parsedField = ua::detail::parse_certificate_field(*deps2->crypto(), certData);
                if (!parsedField.is_good())
                {
                  throw UaException{parsedField.status_code()};
                }
                auto cert = std::move(parsedField).value().front();
                // Both sides through the one normaliser: a custom authenticator may store the claim in
                // any hex form the Thumbprint identity rule accepts.
                const auto thumbprint = cert->thumbprint();
                const auto presented = normalise_identity_thumbprint(
                  utils::bytes_to_hex_string(ua::span<const ua::byte>{thumbprint}));
                const auto stored = normalise_identity_thumbprint(storedThumbprint->second);
                tokenMatches = presented.is_good() && stored.is_good() && presented.value() == stored.value();
              }
              catch (...)
              {
                // Cannot parse certificate - token does not match.
                ua::detail::ignore_expected_exception();
              }
            }
          }
        }
        break;
      case UserTokenKind::IssuedToken:
        // Issued tokens: the token kind must match here; the subject the authenticator derives is compared
        // with the committed one at commit (security review SESS-5: it was accepted unchecked).
        tokenMatches = dynamic_cast<IssuedIdentityToken*>(rawToken) != nullptr;
        break;
      case UserTokenKind::Unsupported:
        break;
      }

      if (!tokenMatches)
      {
        create_and_send_service_fault(
          requestId, Status::BadIdentityChangeNotSupported, nullptr, 0, requestChannel);
        return;
      }
    }
  }

  if (mWaitingForAuthn)
  {
    // A prior ActivateSession's authentication/response emission is still in flight. A second
    // overlapping ActivateSession is a transient backpressure condition the client should retry,
    // not a per-request operation-count violation - so reject with BadServerTooBusy.
    create_and_send_service_fault(requestId,
      Status::BadServerTooBusy,
      ErrorDetail::build(
        "ServerTooBusy", "Overlapping ActivateSession while a prior activation is still in flight", "Session")
        .context(ua::ContextKeys::sessionId, to_string(mSessionId))
        .context(ua::ContextKeys::requestId, std::to_string(requestId)),
      activateSessionRequest.request_header().return_diagnostics(),
      requestChannel);
    return;
  }

  // Store pending reassociation - applied only when activation succeeds.
  mPendingSecureChannelInfo = secureChannelInfo;

  // Update locales eagerly (non-security, deterministic). Part 4 5.6.3.2: an empty list on a
  // re-activation keeps the current locales, so the diagnostic follows mLocales rather than the
  // request.
  if (!activateSessionRequest.locale_ids().empty())
  {
    mLocales = activateSessionRequest.locale_ids().payload();
    const std::lock_guard lock{mDescriptiveState->mutex};
    mDescriptiveState->localeIds.assign(mLocales.begin(), mLocales.end());
  }

  // Store request for correlation (effects & response building).
  auto request = std::make_shared<ActivateSessionRequest>(activateSessionRequest);
  mInFlightRequestsByRequestId[requestId] = request;

  const auto requestHandle = activateSessionRequest.request_header().request_handle();

  // Resolve the effective channel info for authentication. On reassociation (including
  // channelless reconnect), the pending info carries the new channel's security properties.
  // The pending pattern ensures we don't commit to the new channel until auth succeeds.
  if (!mPendingSecureChannelInfo.has_value() && !mSecureChannelInfo.has_value())
  {
    create_and_send_service_fault(requestId, Status::BadInvalidArgument, nullptr, 0, requestChannel);
    return;
  }
  const auto effectiveChannelInfo =
    mPendingSecureChannelInfo.has_value() ? *mPendingSecureChannelInfo : *mSecureChannelInfo;

  // Authenticate via callback chain. The continuation runs back on the session strand.
  mWaitingForAuthn = true;
  auto me = weak_from_this();
  authenticate_async(requestId,
    requestHandle,
    effectiveChannelInfo,
    [me, requestId, sameIdentityRequired](AuthnResult authnResult) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
        return;
      // Post the continuation onto the session strand per the post-discipline rule.
      // authenticate_async may dispatch its
      // final callback on the session strand internally, but the caller still posts.
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [requestId, sameIdentityRequired, authnResult = std::move(authnResult)](Session& self) mutable
        { self.on_activate_authenticated(requestId, std::move(authnResult), sameIdentityRequired); })();
    });
}

void Session::on_activate_authenticated(
  uint32_t requestId, AuthnResult authnResult, bool sameIdentityRequired)
{
  // Note: `mWaitingForAuthn` stays true through the response-build phase (cleared in
  // commit_activate_identity / fail_activate_response below) so a second ActivateSession
  // arriving while we're still emitting the response is rejected with BadServerTooBusy
  // by the synchronous gate in activate_internal. Without this widening, the race window
  // between auth completing and response queuing on the wire was open to overlapping
  // requests despite the AuthState gate.

  if (!authnResult.is_good())
  {
    // `mWaitingForAuthn` is released by refuse_activation, when the fault is sent: on an ECC Session the
    // fault waits for a new EphemeralKey, and the claim keeps a second ActivateSession out until then.
    auto authnStatus = authnResult.status_code();
    auto authnDetail = authnResult.shared_detail();
    std::string_view reason = authnDetail ? std::string_view{authnDetail->summary} : std::string_view{};

    if (auto sessionDeps = mDependencies.lock())
    {
      // A rejected ActivateSession authentication is a session-establishment request rejected for a
      // security reason (OPC 10000-5 12.9 ServerDiagnosticsSummary): it increments both
      // rejectedSessionCount and its securityRejectedSessionCount subset. Gated on the diagnostics
      // flag like the other summary counters so they stay inert when ServerDiagnostics is disabled.
      auto summaryCounters = sessionDeps->summary_counters();
      auto diagnosticsEnabled = sessionDeps->diagnostics_enabled();
      if (summaryCounters && diagnosticsEnabled && diagnosticsEnabled->load(std::memory_order_relaxed))
      {
        summaryCounters->securityRejectedSessionCount.fetch_add(1, std::memory_order_relaxed);
        summaryCounters->rejectedSessionCount.fetch_add(1, std::memory_order_relaxed);
      }

      const std::string error = authnDetail ? to_string(*authnDetail) : std::string{};
      sessionDeps->logger().with_category("session").warning(
        {{"session_name", std::string_view{mSessionName}},
          {"status", fmt::format("0x{:08x}", authnStatus.as_uint32())},
          {"reason", reason},
          {"error", std::string_view{error}}},
        "Authentication failed");
      auto eh = sessionDeps->observer();
      auto evInfo = build_session_event_info(mSessionId, mSessionName, mSecureChannelInfo);
      auto reqIt = mInFlightRequestsByRequestId.find(requestId);
      if (reqIt != mInFlightRequestsByRequestId.end())
      {
        if (auto* req = dynamic_cast<ActivateSessionRequest*>(reqIt->second.get()))
          evInfo.auditEntryId = req->request_header().audit_entry_id();
      }
      detail::emit_event(
        sessionDeps->logger(), eh, [&] { eh->on_authentication_failed(evInfo, authnStatus); });
    }

    const StatusCode wireStatus =
      authnStatus == Status::BadIdentityTokenInvalid ? authnStatus.without_detail() : authnStatus;
    refuse_activation(requestId, wireStatus, nullptr);
    return;
  }

  // Part 4 5.6.3.1: a re-activation over a different SecureChannel keeps the Session's identity. The
  // pre-authentication check compares what the token shows (kind, user name, certificate); this compares
  // what the authenticator made of it, which is the only comparison an issued token allows (review
  // SESS-5). It runs before the Session is marked Activated and before it takes the new channel, so a
  // refusal leaves it on its current channel with its identity (panel L round 1: after the channel was
  // taken, a refusal left the new channel holding the old identity).
  if (sameIdentityRequired)
  {
    const auto committed = mSessionInfo->user_identity();
    const auto authenticatedIt = mAuthnUserByRequestId.find(requestId);
    const UserIdentity* activating = nullptr;
    const std::optional<UserIdentity>* authenticatedUser = nullptr;
    if (authenticatedIt != mAuthnUserByRequestId.end())
      authenticatedUser = &authenticatedIt->second;
    if (authenticatedUser && authenticatedUser->has_value())
      activating = &authenticatedUser->value();
    else if (authnResult.is_good())
      activating = &authnResult.value().user;
    if (committed && (activating == nullptr || committed->kind != activating->kind ||
                       committed->userId != activating->userId))
    {
      mAuthnUserByRequestId.erase(requestId);
      mAuthnEndpointByRequestId.erase(requestId);
      refuse_activation(requestId,
        StatusCode{Status::BadIdentityChangeNotSupported},
        make_error_detail("IdentityChangedOnNewChannel",
          "A re-activation over a different SecureChannel authenticated a different identity",
          "Session"));
      return;
    }
  }

  // Authentication succeeded: build and send the response via the callback chain. The Session is not
  // marked Activated here: it becomes Activated when commit_activate_identity commits the identity, so a
  // response-build failure before that leaves it in the state it had - Created with no identity on a
  // first activation, Activated with its committed identity on a re-activation (security review
  // SESS-7(g): marked here, a failed build left a first activation Activated with no identity; OPC
  // 10000-4 5.6.3.1 - "If no errors occur the Server replaces the user identity for the Session").
  // mWaitingForAuthn stays true and is cleared in the response callback below (after the response has
  // been queued / faulted on the wire), closing the overlap window with another ActivateSession.
  auto me = weak_from_this();
  send_activate_session_response_async(requestId,
    [me, requestId](VoidResult result) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
        return;
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [requestId, result = std::move(result)](Session& self) mutable
        {
          self.mWaitingForAuthn = false;
          if (result.is_bad())
          {
            if (auto deps = self.mDependencies.lock())
            {
              deps->logger().with_category("session").error(
                {{"session_name", std::string_view{self.mSessionName}},
                  {"status", fmt::format("0x{:08x}", result.status_code().as_uint32())}},
                "Failed to send ActivateSession response");
            }
            self.send_service_fault(requestId, result.status_code(), result.shared_detail());
          }
        })();
    });
}

void Session::refuse_activation(uint32_t requestId, StatusCode status, shared_ptr<const ErrorDetail> detail)
{
  if (mEccUserTokenPolicyId == SecurityPolicyId::Invalid)
  {
    mWaitingForAuthn = false;
    send_service_fault(requestId, status, std::move(detail));
    return;
  }

  // Part 6 6.8.3: "The Server always returns a new EphemeralKey in the ResponseHeader ... The
  // EphemeralKey is changed even if the Client did not provide an encrypted UserIdentityToken." A
  // ServiceFault carries a ResponseHeader (Part 4 7.35), so a refused activation on an ECC Session hands
  // the client the key its next attempt encrypts against (security review SESS-7). Cost: one ephemeral
  // key generation and one signature per refused ECC ActivateSession, the same as a successful one pays.
  // The refusal is already past the fixed authentication interval, so the key only adds to it.
  //
  // R19: the single-flight claim for this member is `mWaitingForAuthn`, still held here and released by
  // the body just before it sends. A second ActivateSession is rejected in `activate_internal` until
  // then, so none can reach here to destroy a running frame.
  mRefusedActivateFaultTask = run_refused_activate_fault(requestId, std::move(status), std::move(detail));
}

ua::async::Task<Result<std::unique_ptr<Structure>>> Session::issue_signed_ecdh_key(
  shared_ptr<const Crypto> crypto, shared_ptr<const SecurityPolicy> securityPolicy,
  shared_ptr<const AsymmetricKeyPair> signingKeys, std::string_view signingFailureMessage)
{
  using EcdhKeyResult = Result<std::unique_ptr<Structure>>;

  auto ephemeralResult = co_await await_step<VoidResult>(
    [this](auto completion) { generate_ecc_ephemeral_key_async(std::move(completion)); });
  if (ephemeralResult.is_bad())
    co_return EcdhKeyResult{ephemeralResult.status_code()};

  auto signResult = co_await await_step<ByteStringResult>(
    [this, &crypto, &securityPolicy, &signingKeys](auto completion)
    {
      crypto->asymmetric_sign_async(shared_from_this(),
        securityPolicy->asymmetric_signature_algorithm(),
        signingKeys,
        mEccEphemeralPublicKey,
        std::move(completion));
    });
  if (!signResult.is_good())
  {
    // A key is issued only with a signature the provider answered Good; an Uncertain one is refused.
    const StatusCode failure =
      ua::security_internal::not_good_answer(signResult.status_code(), Status::BadInternalError, "Session");
    if (signingFailureMessage.empty())
      co_return EcdhKeyResult{failure};
    co_return EcdhKeyResult{StatusCode{failure.value(),
      make_error_detail("EphemeralKeySigningFailed",
        std::string{signingFailureMessage},
        "Session",
        failure.shared_detail())}};
  }

  auto ephemeralKeyType = make_unique<EphemeralKeyType>();
  ephemeralKeyType->public_key() = mEccEphemeralPublicKey;
  ephemeralKeyType->signature() = std::move(signResult).value();

  auto responseParams = make_unique<AdditionalParametersType>();
  KeyValuePair ecdhKeyKv;
  ecdhKeyKv.key() = QualifiedName{0, "ECDHKey"};
  ecdhKeyKv.value() = Variant{std::move(ephemeralKeyType)};
  responseParams->parameters().payload().push_back(std::move(ecdhKeyKv));
  co_return EcdhKeyResult{std::unique_ptr<Structure>{std::move(responseParams)}};
}

ua::async::Task<> Session::run_refused_activate_fault(
  uint32_t requestId, StatusCode status, shared_ptr<const ErrorDetail> detail)
{
  std::unique_ptr<Structure> additionalHeader;
  optional<StatusCode> keyFailure;
  try
  {
    // The key is signed with the server key of the SecureChannel this ActivateSession arrived on - the
    // pending channel of a re-activation over a new channel (still held until the fault is sent), else
    // the Session's current channel - as the successful response, which is built after the Session takes
    // that channel, signs it (SESS-7(d)). The old channel of a re-activation may already be gone.
    //
    // Every signing input is confirmed BEFORE the pair is replaced, and a pair whose signature fails is
    // put back: the stored key is only ever replaced by one the fault actually carries, so a refusal that
    // cannot issue a key leaves the client's current key usable (review of owner decision 8(b)).
    const optional<SecureChannelInfo>& requestChannel =
      mPendingSecureChannelInfo.has_value() ? mPendingSecureChannelInfo : mSecureChannelInfo;
    auto deps = mDependencies.lock();
    shared_ptr<const Crypto> crypto = deps ? deps->crypto() : nullptr;
    shared_ptr<const SecurityPolicy> securityPolicy =
      requestChannel.has_value() ? requestChannel->security_policy() : nullptr;
    CertificateStore::ApplicationCertificate certAndKey;
    if (securityPolicy)
      certAndKey = stack_utils::get_local_cert_and_keys(mServerCertificates, securityPolicy->id());

    if (!deps || !crypto || !securityPolicy)
    {
      keyFailure = StatusCode{Status::BadInternalError,
        make_error_detail("DepsExpired", "Session deps/channel info missing", "Session")};
    }
    else if (!certAndKey.keys)
    {
      // As the successful response: no server key for the channel policy, nothing to sign with.
      keyFailure = StatusCode{Status::BadSecurityChecksFailed,
        make_error_detail("NoLocalKey", "No server keypair available for ECC ephemeral signing", "Session")};
    }
    else
    {
      // Moved out, not copied: the one buffer holding the previous private key is the one scrubbed
      // below. The new pair takes the members; every path that does not send it puts this one back.
      ByteString previousPrivateKey = std::move(mEccEphemeralPrivateKey);
      ByteString previousPublicKey = std::move(mEccEphemeralPublicKey);

      // Clears the saved private key whenever this scope ends - including when the Session is destroyed
      // with the frame suspended, which destroys the frame without resuming it (DEF-4).
      const ua::security::ScrubOnExit scrubPrevious{previousPrivateKey};

      mEccEphemeralPrivateKey = ByteString{};
      mEccEphemeralPublicKey = ByteString{};
      const auto restorePrevious = [this, &previousPrivateKey, &previousPublicKey]
      {
        ua::security::secure_clear(mEccEphemeralPrivateKey);
        mEccEphemeralPrivateKey = std::move(previousPrivateKey);
        mEccEphemeralPublicKey = std::move(previousPublicKey);
      };
      try
      {
        // No signing-failure message: the refusal logs the failing step's own status unwrapped.
        auto ecdhKey = co_await issue_signed_ecdh_key(crypto, securityPolicy, certAndKey.keys, {});
        if (!ecdhKey.is_good())
        {
          keyFailure = ecdhKey.status_code();
          restorePrevious();
        }
        else
        {
          additionalHeader = std::move(ecdhKey).value();
        }
      }
      catch (const ua::async::Abandoned&)
      {
        // Withdrawn with the Session: nothing to put back; the guard clears the saved key.
        throw;
      }
      catch (...)
      {
        // A key that was generated but cannot be sent must not replace the one the client holds.
        additionalHeader.reset();
        restorePrevious();
        throw;
      }
    }
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: the Session is going away with its request.
    co_return;
  }
  catch (...)
  {
    keyFailure = ::ua::exception_to_status_code(std::current_exception());
  }

  if (keyFailure)
  {
    // The refusal is the answer the client is owed; a key that could not be issued must not turn it into
    // a different status, so the fault goes without one.
    additionalHeader.reset();
    ua::async::guarded(mLogger,
      [&]
      {
        if (auto deps = mDependencies.lock())
        {
          const std::string error =
            keyFailure->shared_detail() ? to_string(*keyFailure->shared_detail()) : std::string{};
          deps->logger().with_category("session").warning(
            {{"session_name", std::string_view{mSessionName}},
              {"status", fmt::format("0x{:08x}", keyFailure->as_uint32())},
              {"error", std::string_view{error}}},
            "Refused ActivateSession sent without a new ECC EphemeralKey");
        }
      })();
  }

  mWaitingForAuthn = false;
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise nobody
  // reads.
  ua::async::guarded(mLogger,
    [&]
    { send_service_fault(requestId, std::move(status), std::move(detail), std::move(additionalHeader)); })();
}

void Session::close_internal(uint32_t requestId, CloseSessionRequest&& closeSessionRequest)
{
  if (mSessionState == State::Closed)
  {
    create_and_send_service_fault(requestId, Status::BadSessionIdInvalid);
    return;
  }

  mSessionState = State::Closed;
  mOwnedContinuationPointIds.clear();

  mCloseReason.store(StatusCode{Status::Good}.value(), std::memory_order_release);
  mState.store(State::Closed, std::memory_order_release);

  auto closeSessionResponse = make_shared<CloseSessionResponse>();
  stack_utils::prepare_response_header(
    closeSessionRequest.request_header(), closeSessionResponse->response_header());

  mInFlightRequestsByRequestId.erase(requestId);
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mReturnDiagnosticsByRequestId.erase(requestId);

  // The response is the client's evidence that the Session is gone, so it is sent only once it is:
  // outstanding Publish requests answered, Subscriptions deleted or orphaned, and the Session's
  // diagnostics node removed from SessionsDiagnosticsSummary (OPC 10000-5 6.3.4). A client that browses
  // the diagnostics straight after CloseSession returns must not still find it.
  try
  {
    close_session_internal(Status::Good, {}, closeSessionRequest.delete_subscriptions());
  }
  catch (...)
  {
    auto sc = handle_unexpected_exception("Session::close_internal", std::current_exception());
    create_and_send_service_fault(requestId, sc);
    return;
  }

  remove_diagnostics_object_async(
    [self = shared_from_this(), requestId, response = std::move(closeSessionResponse)]() mutable
    {
      auto sc = self->mSecureChannelInfo ? self->mSecureChannelInfo->secure_channel().lock() : nullptr;
      if (sc)
      {
        sc->send_response_message(std::make_pair(requestId, std::move(response)));
      }
      else
      {
        self->enqueue_response(std::make_pair(requestId, std::move(response)));
      }
    });
}

void Session::close_due_to_premature_service_use()
{
  if (mSessionState == State::Closed)
    return;
  mSessionState = State::Closed;
  mState.store(State::Closed, std::memory_order_release);
  close_session_internal(Status::BadSessionNotActivated, {});
}

void Session::response_received(Response response)
{
  try
  {
    const auto requestId = std::get<uint32_t>(response);

    // Record latency for completed service requests.
    {
      auto startIt = mRequestStartTimes.find(requestId);
      if (startIt != mRequestStartTimes.end())
      {
        auto kindIt = mRequestServiceKinds.find(requestId);
        if (kindIt != mRequestServiceKinds.end())
        {
          const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - startIt->second);
          if (auto deps = mDependencies.lock())
          {
            if (auto tracker = deps->latency_tracker())
            {
              tracker->record(kindIt->second, elapsed);
            }
          }

          // A whole-request rejection is delivered on this per-service completion path as a
          // ServiceFault; count it as a service-level error for this Service. The other reject path,
          // Session::send_service_fault, counts errorCount and consumes the service kind itself, so
          // the two are mutually exclusive - no double count.
          note_service_fault_error(requestId, std::get<std::shared_ptr<Structure>>(response));
          mRequestServiceKinds.erase(kindIt);
        }
        mRequestStartTimes.erase(startIt);
      }
    }

    // Release every per-request owner and admission slot before the terminal response leaves the Session.
    // The Browse/BrowseNext and HistoryRead special handlers use this same helper after adopting their
    // continuation points, so no terminal path can permanently consume maxRequestsPerSession capacity.
    release_request_tracking(requestId);

    auto sc = mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr;
    if (sc && !mPostResponseActions.empty())
    {
      const MethodResponseCorrelation correlation{mSecureChannelAssociationEpoch, requestId};
      if (const auto actions =
            std::ranges::find(mPostResponseActions, correlation, &PostResponseActions::correlation);
          actions != mPostResponseActions.end())
      {
        // The channel closes itself once this response is written (OPC 10000-12 7.10.6: the ApplyChanges
        // caller receives the response); closing it from the enqueue confirmation below would cut the
        // response off, because encoding completes after the enqueue.
        const auto afterResponse = actions->closeSecureChannel ? SecureChannel::AfterResponse::CloseChannel
                                   : actions->reevaluateCertificates
                                     ? SecureChannel::AfterResponse::ReevaluateCertificate
                                     : SecureChannel::AfterResponse::Nothing;
        auto me = weak_from_this();
        weak_ptr<SecureChannel> secureChannel = sc;
        sc->send_response_message(
          response,
          [me, correlation, secureChannel](VoidResult enqueueResult) mutable
          {
            auto self = me.lock();
            if (!self)
              return;
            ua::async::post_borrowing(self.get(),
              self->mStrand,
              self->mLogger,
              [correlation, secureChannel, enqueueResult = std::move(enqueueResult)](Session& session) mutable
              {
                session.on_response_enqueued_on_strand(correlation, secureChannel, std::move(enqueueResult));
              })();
          },
          afterResponse);
      }
      else
      {
        sc->send_response_message(response);
      }
    }
    else if (sc)
    {
      sc->send_response_message(response);
    }
    else
    {
      // Buffer until new secure channel is associated with the session
      enqueue_response(response);
    }

    if (mResponseSinkForTests)
    {
      auto depsForLog = mDependencies.lock();
      ::ua::detail::invoke_user_callback(
        depsForLog ? depsForLog->logger() : Logger{}, mResponseSinkForTests, response);
    }
  }
  catch (...)
  {
    handle_unexpected_exception("Session::response_received", std::current_exception());
  }
}

void Session::browse_response_received(
  Response response, std::vector<BrowseContinuationPoint> continuationPoints)
{
  try
  {
    const auto requestId = std::get<uint32_t>(response);

    // A whole-request Browse/BrowseNext rejection is delivered here as a ServiceFault; count it as a
    // service-level error for this Service (this completion path does not go through
    // Session::send_service_fault).
    note_service_fault_error(requestId, std::get<std::shared_ptr<Structure>>(response));

    std::vector<std::string> storedContinuationPointIds;

    // Purge expired continuation points on any browse response.
    {
      const auto timeoutOpt = mSessionInfo->server_configuration().browseContinuationPointTimeout;
      if (timeoutOpt && (*timeoutOpt > std::chrono::milliseconds{0}))
      {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = mBrowseContinuationPointExpiry.begin(); it != mBrowseContinuationPointExpiry.end();)
        {
          if (it->second <= now)
          {
            mBrowseContinuationPoints.erase(it->first);
            it = mBrowseContinuationPointExpiry.erase(it);
          }
          else
          {
            ++it;
          }
        }
      }
    }

    // Index new continuation points by Guid.
    std::unordered_map<Guid, BrowseContinuationPoint> incoming;
    incoming.reserve(continuationPoints.size());
    for (auto& cp : continuationPoints)
    {
      incoming.emplace(cp.identifier(), std::move(cp));
    }

    // Defer continuation point acceptance decisions to the reducer.
    std::vector<std::string> candidateContinuationPointIds;

    auto collectCandidates = [&](auto& results)
    {
      for (auto& r : results)
      {
        if (!r.continuation_point().empty())
        {
          const auto& cp = r.continuation_point();
          candidateContinuationPointIds.emplace_back(reinterpret_cast<const char*>(cp.data()), cp.size());
        }
      }
    };

    if (auto* browseResponse = dynamic_cast<BrowseResponse*>(response.second.get()))
    {
      collectCandidates(browseResponse->results());
    }
    else if (auto* browseNextResponse = dynamic_cast<BrowseNextResponse*>(response.second.get()))
    {
      collectCandidates(browseNextResponse->results());
    }

    std::unordered_set<std::string> acceptSet;
    if (!candidateContinuationPointIds.empty())
    {
      const uint32_t maxCp =
        mSessionInfo->server_configuration().server_capabilities().maxBrowseContinuationPoints;
      auto owned = mOwnedContinuationPointIds.size();

      // Count how many new CPs we need to accept (excluding duplicates).
      size_t needed = 0;
      for (const auto& id : candidateContinuationPointIds)
      {
        if (std::find(mOwnedContinuationPointIds.begin(), mOwnedContinuationPointIds.end(), id) ==
            mOwnedContinuationPointIds.end())
        {
          ++needed;
        }
      }

      // Auto-free: evict oldest owned CPs to make room for new ones.
      std::vector<std::string> evict;
      if (maxCp > 0 && (owned + needed) > numeric_cast<size_t>(maxCp))
      {
        const size_t toEvict = std::min(owned, (owned + needed) - numeric_cast<size_t>(maxCp));
        for (size_t i = 0; i < toEvict && i < mOwnedContinuationPointIds.size(); ++i)
        {
          evict.push_back(mOwnedContinuationPointIds[i]);
        }
        mOwnedContinuationPointIds.erase(mOwnedContinuationPointIds.begin(),
          mOwnedContinuationPointIds.begin() + numeric_cast<std::ptrdiff_t>(evict.size()));
        owned = mOwnedContinuationPointIds.size();
      }

      // Remove evicted CPs from session storage.
      for (const auto& id : evict)
      {
        Guid guid;
        guid.from_ua_binary(ByteString{reinterpret_cast<const uint8_t*>(id.data()),
          reinterpret_cast<const uint8_t*>(id.data() + id.size())});
        mBrowseContinuationPoints.erase(guid);
        mBrowseContinuationPointExpiry.erase(guid);
      }

      // Calculate remaining quota after eviction.
      size_t remaining = 0;
      if (maxCp > 0)
      {
        remaining = owned < numeric_cast<size_t>(maxCp) ? (numeric_cast<size_t>(maxCp) - owned) : 0;
      }

      // Build accept set.
      acceptSet.reserve(std::min(remaining, candidateContinuationPointIds.size()));
      for (const auto& id : candidateContinuationPointIds)
      {
        if (remaining == 0)
        {
          break;
        }
        if (std::find(mOwnedContinuationPointIds.begin(), mOwnedContinuationPointIds.end(), id) !=
            mOwnedContinuationPointIds.end())
        {
          continue;
        }
        acceptSet.insert(id);
        --remaining;
      }
    }

    auto applyAndStore = [&](auto& results)
    {
      for (auto& r : results)
      {
        if (r.continuation_point().empty())
        {
          continue;
        }

        const auto cpBytes = r.continuation_point();
        std::string id(reinterpret_cast<const char*>(cpBytes.data()), cpBytes.size());
        if (!acceptSet.contains(id))
        {
          // A result that is not Bad has References left to return, so with its continuation point refused it
          // could not be processed (Part 4 7.9, Table 183) and is answered Bad_NoContinuationPoints with no
          // References, since a Client uses none of a Bad result (Table 180).
          r.continuation_point().clear();
          if (!r.status_code().is_bad())
          {
            r.status_code() = Status::BadNoContinuationPoints;
            r.references().clear();
          }
          continue;
        }

        Guid guid;
        guid.from_ua_binary(cpBytes);
        auto it = incoming.find(guid);
        if (it == incoming.end())
        {
          continue;
        }

        auto [ins, inserted] = mBrowseContinuationPoints.emplace(guid, std::move(it->second));
        if (inserted)
        {
          storedContinuationPointIds.push_back(std::move(id));

          const auto timeoutOpt = mSessionInfo->server_configuration().browseContinuationPointTimeout;
          if (timeoutOpt && (*timeoutOpt > std::chrono::milliseconds{0}))
          {
            mBrowseContinuationPointExpiry[guid] = std::chrono::steady_clock::now() + *timeoutOpt;
          }
        }
        incoming.erase(it);
      }
    };

    if (auto* browseResponse = dynamic_cast<BrowseResponse*>(response.second.get()))
    {
      applyAndStore(browseResponse->results());
    }
    else if (auto* browseNextResponse = dynamic_cast<BrowseNextResponse*>(response.second.get()))
    {
      applyAndStore(browseNextResponse->results());
    }

    // Track accepted continuation points in the ownership list.
    for (auto& id : storedContinuationPointIds)
    {
      mOwnedContinuationPointIds.push_back(std::move(id));
    }

    auto sc = mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr;
    if (sc)
    {
      sc->send_response_message(response);
    }
    else
    {
      // Buffer until new secure channel is associated with the session
      enqueue_response(response);
    }

    if (mResponseSinkForTests)
    {
      auto depsForLog = mDependencies.lock();
      ::ua::detail::invoke_user_callback(
        depsForLog ? depsForLog->logger() : Logger{}, mResponseSinkForTests, response);
    }

    release_request_tracking(requestId);
  }
  catch (...)
  {
    handle_unexpected_exception("Session::browse_response_received", std::current_exception());
  }
}

void Session::inject_decoded_request_for_tests(uint32_t requestId, shared_ptr<Structure> request)
{
  request_received(std::make_pair(requestId, std::move(request)));
}

optional<Response> Session::pop_queued_response_for_tests()
{
  if (mResponseMessages.empty())
  {
    return std::nullopt;
  }
  auto r = std::move(mResponseMessages.front());
  mResponseMessages.pop();
  return r;
}

void Session::set_response_sink_for_tests(ResponseSinkForTests sink)
{
  mResponseSinkForTests = std::move(sink);
}

// New helper: send_service_fault - replaces handle_action(SendServiceFault).
// Handles error tracking, cleanup, and fault sending.
void Session::send_service_fault(uint32_t requestId, StatusCode status, shared_ptr<const ErrorDetail> detail,
  std::unique_ptr<Structure> additionalHeader)
{
  // Count service errors if this fault is for a dispatched service request.
  {
    auto kindIt = mRequestServiceKinds.find(requestId);
    if (kindIt != mRequestServiceKinds.end())
    {
      if (status.is_bad())
      {
        auto& ctr = counter_for_service(kindIt->second);
        ctr.errorCount.fetch_add(1, std::memory_order_relaxed);
        if (&ctr != &mCounters->totalRequests)
        {
          mCounters->totalRequests.errorCount.fetch_add(1, std::memory_order_relaxed);
        }
      }
      mRequestServiceKinds.erase(kindIt);
    }
    mRequestStartTimes.erase(requestId);
  }

  uint32_t returnDiagnostics = 0;
  {
    auto diagIt = mReturnDiagnosticsByRequestId.find(requestId);
    if (diagIt != mReturnDiagnosticsByRequestId.end())
    {
      returnDiagnostics = diagIt->second;
      mReturnDiagnosticsByRequestId.erase(diagIt);
    }
  }

  optional<weak_ptr<SecureChannel>> responseChannel;
  if (mPendingSecureChannelInfo)
    responseChannel = mPendingSecureChannelInfo->secure_channel();
  mInFlightRequestsByRequestId.erase(requestId);
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mPendingSecureChannelInfo.reset();
  create_and_send_service_fault(
    requestId, status, detail, returnDiagnostics, responseChannel, std::nullopt, std::move(additionalHeader));
}

uint32_t Session::cancel_outstanding_ops_effect(uint32_t targetRequestHandle)
{
  // Best-effort cancel of service calls associated with the target requestHandle.
  // Part 4: a single Cancel targets every in-flight request carrying the given
  // RequestHandle, so we resolve handle -> {requestId...} via the per-request
  // handle index, then cancel each service the session still owns.
  //
  // Do NOT erase the map entries here: the service keeps itself alive via the
  // strong owner stored in mServiceCallsByRequestId until its cancellation
  // completion routes through `*_response_received`, which removes the entry
  // then. Erasing here would drop the last strong reference before the
  // strand-posted cancel lambda runs, expiring the weak captures inside the
  // service and silently dropping the cancellation work.
  uint32_t cancelCount{0};
  for (const auto& [requestId, requestHandle] : mRequestHandlesByRequestId)
  {
    if (requestHandle != targetRequestHandle)
    {
      continue;
    }
    auto callIt = mServiceCallsByRequestId.find(requestId);
    if (callIt != mServiceCallsByRequestId.end() && callIt->second)
    {
      callIt->second->cancel();
      ++cancelCount;
    }
  }
  return cancelCount;
}

void Session::abort_outstanding_ops(StatusCode reason)
{
  // The entries stay, as for a Cancel: each service answers through `*_response_received`, which removes it.
  for (const auto& [requestId, service] : mServiceCallsByRequestId)
  {
    (void)requestId;
    if (service)
    {
      service->abort(reason);
    }
  }
}

void Session::handle_service_request(uint32_t requestId, ServiceKind kind, uint32_t requestHandle)
{
  if (mSessionState == State::Closed)
  {
    create_and_send_service_fault(requestId, Status::BadSessionIdInvalid);
    return;
  }

  const bool isDiscovery = (kind == ServiceKind::DiscoveryFindServers) ||
                           (kind == ServiceKind::DiscoveryFindServersOnNetwork) ||
                           (kind == ServiceKind::DiscoveryGetEndpoints);

  // BrowseNext: unknown continuation points are reported per-result (not as a service fault).
  // The BrowseService handles unrecognised CPs by returning BadContinuationPointInvalid per item.

  // Activation gate (discovery services exempt).
  if (mSessionState != State::Activated && !isDiscovery)
  {
    create_and_send_service_fault(requestId, Status::BadSessionNotActivated);
    close_due_to_premature_service_use();
    return;
  }

  mOutstandingRequestHandles.insert(requestHandle);
  execute_service(requestId, kind);
}

void Session::handle_cancel_request(uint32_t requestId, CancelRequest cancelRequest)
{
  if (mSessionState == State::Closed)
  {
    create_and_send_service_fault(requestId, Status::BadSessionIdInvalid);
    return;
  }
  if (mSessionState != State::Activated)
  {
    create_and_send_service_fault(requestId, Status::BadSessionNotActivated);
    close_due_to_premature_service_use();
    return;
  }

  auto cancelCount = cancel_outstanding_ops_effect(cancelRequest.request_handle());

  auto cancelResponse = make_shared<CancelResponse>();
  stack_utils::prepare_response_header(cancelRequest.request_header(), cancelResponse->response_header());
  cancelResponse->cancel_count() = cancelCount;

  // G18: Emit AuditCancelEventPayload (Part 4 - AuditCancelEventType).
  {
    auto sessionDeps = mDependencies.lock();
    if (sessionDeps && sessionDeps->server_configuration().auditingEnabled &&
        sessionDeps->event_bus().has_event_interest())
    {
      AuditCancelEventPayload auditEvent;
      auditEvent.sourceNode = NodeId{ObjectId::Server};
      auditEvent.sourceName = "Session/Cancel";
      auditEvent.actionTimeStamp = Variant{DateTime::now()};
      auditEvent.status = (cancelCount > 0);
      auditEvent.serverId = sessionDeps->configuration().application_description_part().applicationUri;
      auditEvent.clientAuditEntryId = cancelRequest.request_header().audit_entry_id();
      auditEvent.message = LocalizedText{"", "Cancel"};
      auditEvent.severity = 1;
      auditEvent.sessionId = mSessionId;
      auditEvent.requestHandle = cancelRequest.request_handle();
      if (auto user = mSessionInfo->user_identity())
        auditEvent.clientUserId = user->userId;
      sessionDeps->event_bus().emit(auditEvent);
    }
  }

  auto sc = mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr;
  if (sc)
  {
    sc->send_response_message(std::make_pair(requestId, cancelResponse));
  }
  else
  {
    enqueue_response(std::make_pair(requestId, cancelResponse));
  }

  mInFlightRequestsByRequestId.erase(requestId);
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mReturnDiagnosticsByRequestId.erase(requestId);
}

void Session::register_service_handlers()
{
  // Each handler closure captures `[this]` - safe because `mServiceHandlers` is
  // a member of `Session` and the handler entries cannot outlive `this` (the
  // map's destructor runs as part of `~Session()`).
  //
  // Callback semantics (10.4 ErrorDetail invariant): `cb` fires exactly once
  // for dispatch-level errors (per-arm `dynamic_cast` miss, find miss, missing
  // in-flight entry) - these are origin-of-error sites with no upstream
  // `shared_detail()` to forward, matching pre-flip `create_and_send_service_fault`.
  // On the success path, per-arm `*_request_received` bodies own their response
  // paths via the existing in-flight / response-queue mechanism (which carries
  // `shared_detail` end-to-end for per-arm failures); `cb` is intentionally
  // discarded on the success path. The 4-arg signature is forward infrastructure
  // for a later flip that threads `cb` into per-arm bodies.

  // --- 3 discovery arms (typed template instantiation) ---
  mServiceHandlers.emplace(NodeId{0, FindServersRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<FindServersRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      discovery_service_set_request_received(requestId, FindServersRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, FindServersOnNetworkRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<FindServersOnNetworkRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      discovery_service_set_request_received(requestId, FindServersOnNetworkRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, GetEndpointsRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<GetEndpointsRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      discovery_service_set_request_received(requestId, GetEndpointsRequest{*typed});
    });

  // --- 10 simple typed arms (each dispatches into the matching *_request_received) ---
  mServiceHandlers.emplace(NodeId{0, ReadRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<ReadRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      read_request_received(requestId, ReadRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, WriteRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<WriteRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      write_request_received(requestId, WriteRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, BrowseRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<BrowseRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      browse_request_received(requestId, BrowseRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, BrowseNextRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<BrowseNextRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }

      // Continuation-point release pre-step - preserved verbatim from the pre-flip
      // BrowseNext switch arm.
      if (typed->release_continuation_points())
      {
        for (const auto& cp : typed->continuation_points())
        {
          const std::string id(reinterpret_cast<const char*>(cp.data()), cp.size());
          std::erase(mOwnedContinuationPointIds, id);
        }
      }

      browse_next_request_received(requestId, BrowseNextRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, CallRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<CallRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      call_request_received(requestId, CallRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, TranslateBrowsePathsToNodeIdsRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<TranslateBrowsePathsToNodeIdsRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      translate_browse_paths_request_received(requestId, TranslateBrowsePathsToNodeIdsRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, RegisterNodesRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<RegisterNodesRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      register_nodes_request_received(requestId, RegisterNodesRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, UnregisterNodesRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<UnregisterNodesRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      unregister_nodes_request_received(requestId, UnregisterNodesRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, HistoryReadRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<HistoryReadRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      history_read_request_received(requestId, HistoryReadRequest{*typed});
    });

  mServiceHandlers.emplace(NodeId{0, HistoryUpdateRequest::typeId},
    [this](uint32_t requestId,
      ServiceKind /*kind*/,
      std::shared_ptr<Structure>
        request,
      std::function<void(ServiceResponseResult)>
        cb)
    {
      auto* typed = dynamic_cast<HistoryUpdateRequest*>(request.get());
      if (!typed)
      {
        cb(ServiceResponseResult{Status::BadRequestTypeInvalid});
        return;
      }
      history_update_request_received(requestId, HistoryUpdateRequest{*typed});
    });

  // --- 4 NodeManagement arms (cluster - broker re-switches on `kind` internally) ---
  auto registerNodeManagement = [this](DataTypeId typeId)
  {
    mServiceHandlers.emplace(NodeId{0, typeId},
      [this](uint32_t requestId,
        ServiceKind kind,
        std::shared_ptr<Structure> /*request*/,
        std::function<void(ServiceResponseResult)> /*cb*/)
      { node_management_request_received(requestId, kind); });
  };
  registerNodeManagement(AddNodesRequest::typeId);
  registerNodeManagement(AddReferencesRequest::typeId);
  registerNodeManagement(DeleteNodesRequest::typeId);
  registerNodeManagement(DeleteReferencesRequest::typeId);

  // --- 12 Subscription arms (cluster - broker re-switches on `kind` internally) ---
  auto registerSubscription = [this](DataTypeId typeId)
  {
    mServiceHandlers.emplace(NodeId{0, typeId},
      [this](uint32_t requestId,
        ServiceKind kind,
        std::shared_ptr<Structure> /*request*/,
        std::function<void(ServiceResponseResult)> /*cb*/)
      { subscription_request_received(requestId, kind); });
  };
  registerSubscription(CreateSubscriptionRequest::typeId);
  registerSubscription(ModifySubscriptionRequest::typeId);
  registerSubscription(DeleteSubscriptionsRequest::typeId);
  registerSubscription(SetPublishingModeRequest::typeId);
  registerSubscription(PublishRequest::typeId);
  registerSubscription(RepublishRequest::typeId);
  registerSubscription(CreateMonitoredItemsRequest::typeId);
  registerSubscription(DeleteMonitoredItemsRequest::typeId);
  registerSubscription(ModifyMonitoredItemsRequest::typeId);
  registerSubscription(SetMonitoringModeRequest::typeId);
  registerSubscription(SetTriggeringRequest::typeId);
  registerSubscription(TransferSubscriptionsRequest::typeId);
}

void Session::execute_service(uint32_t requestId, ServiceKind kind)
{
  // Increment per-service and aggregate counters.
  mCounters->totalRequests.totalCount.fetch_add(1, std::memory_order_relaxed);
  auto& sc = counter_for_service(kind);
  if (&sc != &mCounters->totalRequests)
  {
    sc.totalCount.fetch_add(1, std::memory_order_relaxed);
  }

  // Record request start time and service kind for latency/error tracking.
  mRequestStartTimes[requestId] = std::chrono::steady_clock::now();
  mRequestServiceKinds[requestId] = kind;

  if (auto deps = mDependencies.lock())
  {
    deps->logger().with_category("session").trace(
      {{"request_id", uint64_t(requestId)}, {"service", std::string_view{service_kind_name(kind)}}},
      "Service dispatched");
  }

  // 5.3 synchronous-completion paths: the three origin-of-error sites below fire
  // `cb` inline on the strand. `cb` forwards a bad result to the existing fault
  // path (`create_and_send_service_fault`) so the response shape is identical to
  // the pre-flip switch. Per 10.4 the dispatcher never substitutes a good Result
  // for a bad downstream one - `result.shared_detail()` is preserved if set.
  auto cb = [this, requestId](ServiceResponseResult result)
  {
    if (result.is_bad())
    {
      create_and_send_service_fault(requestId, result.status_code(), result.shared_detail());
    }
  };

  auto it = mInFlightRequestsByRequestId.find(requestId);
  if (it == mInFlightRequestsByRequestId.end())
  {
    cb(ServiceResponseResult{Status::BadInternalError});
    return;
  }

  // Typed-table dispatch. The handler entry runs synchronously and either fires
  // `cb` (dynamic_cast miss) or forwards control into the per-arm `*_request_received`
  // body whose existing response/fault path owns the rest of the response.
  auto handlerIt = mServiceHandlers.find(it->second->type_id().node_id());
  if (handlerIt == mServiceHandlers.end())
  {
    cb(ServiceResponseResult{Status::BadServiceUnsupported});
  }
  else
  {
    handlerIt->second(requestId, kind, it->second, std::move(cb));
  }

  // The request has been dispatched, but it is NOT released here. `mInFlightRequestsByRequestId` is also
  // what `maxRequestsPerSession` counts, and releasing it at dispatch made that cap measure the
  // arrival-to-dispatch window - which closes immediately - instead of outstanding work (D19). A client
  // could hold unlimited slow requests open per session, which is precisely what the cap exists to stop.
  // The entry is now released on the response path (`response_received`) and on the abandon path
  // (`release_request_tracking`), matching the channel-level in-flight counters, which release in
  // `send_response_message_internal`.
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mReturnDiagnosticsByRequestId.erase(requestId);
}

void Session::send_create_session_response_async(uint32_t requestId, std::function<void(VoidResult)> callback)
{
  try
  {
    auto it = mInFlightRequestsByRequestId.find(requestId);
    if (it == mInFlightRequestsByRequestId.end())
    {
      std::shared_ptr<const ErrorDetail> detail =
        ErrorDetail::build(
          "RequestNotInFlight", "CreateSession request not found in the in-flight map", "Session")
          .context(ua::ContextKeys::requestId, std::to_string(requestId));
      create_and_send_service_fault(requestId, Status::BadInternalError, detail);
      callback(VoidResult{Status::BadInternalError, std::move(detail)});
      return;
    }

    auto* createSessionRequest = dynamic_cast<CreateSessionRequest*>(it->second.get());
    if (!createSessionRequest)
    {
      std::shared_ptr<const ErrorDetail> detail = make_error_detail("RequestTypeInvalid",
        "In-flight request for CreateSession response build is not a CreateSessionRequest",
        "Session");
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid, detail);
      callback(VoidResult{Status::BadRequestTypeInvalid, std::move(detail)});
      return;
    }

    // Allocate per-flow state.
    mCreateResponseState = std::make_unique<CreateResponseState>();
    mCreateResponseState->requestId = requestId;
    mCreateResponseState->request = std::make_shared<CreateSessionRequest>(*createSessionRequest);
    mCreateResponseState->callback = std::move(callback);

    if (mCreateResponseFailureInjectorForTests)
      mCreateResponseFailureInjectorForTests();

    auto response = make_shared<CreateSessionResponse>();
    stack_utils::prepare_response_header(createSessionRequest->request_header(), response->response_header());
    response->session_id() = mSessionId;
    response->authentication_token() = mAuthenticationToken;
    response->revised_session_timeout() = static_cast<double>(mRevisedSessionTimeout.count());
    // OPC 10000-4 Table 15: maxRequestMessageSize is this server's session-level statement of the
    // largest request body it will accept. DERIVED from the transport limit it already advertises in
    // Acknowledge - the server cannot accept a request larger than that, so a separate configuration
    // knob could only contradict it. Mirrors the client's maxResponseMessageSize exactly. 0 ("not
    // used") propagates unchanged.
    if (auto deps = mDependencies.lock())
    {
      response->max_request_message_size() =
        deps->configuration().stack_limits().connectionProtocolLimits.maxMessageSize;
    }
    mCreateResponseState->response = std::move(response);

    // The channel is bound for the lifetime of CreateSession response building; guard once and bind
    // a reference so the policy/token-list dereferences below are statically provable.
    if (!mSecureChannelInfo.has_value())
    {
      fail_create_response(Status::BadInternalError,
        make_error_detail("MissingSecureChannel", "Session lost its secure channel", "Session"));
      return;
    }
    const auto& secureChannelInfo = *mSecureChannelInfo;

    auto securityPolicy = secureChannelInfo.security_policy();

    // The type the endpoint asks for; on a None channel it is refined against the held certificates once
    // run_create_response has loaded them (mServerCertificates is not loaded yet here).
    mCreateResponseState->resolvedCertType = stack_utils::resolve_certificate_type_for_endpoint(
      securityPolicy->id(), secureChannelInfo.user_identity_tokens());
    mCreateResponseState->nonceLength = numeric_cast<uint32_t>(stack_utils::resolve_nonce_length_for_endpoint(
      securityPolicy->id(), secureChannelInfo.user_identity_tokens()));

    // The body is EAGER, so it runs here, synchronously, exactly as far as the chain ran before
    // its first async call - and suspends in the same place.
    mCreateResponseTask = run_create_response();
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    fail_create_response(er, er.shared_detail());
  }
}

ua::async::Task<> Session::run_create_response()
{
  try
  {
    // --- server nonce and the application certificate that signs with it -------------------
    // The chain reached the endpoints step directly when there was nothing to provision: no
    // resolved certificate type, no nonce length, or no crypto/store to ask. Those are the same
    // condition and they still skip the same way.
    bool provisionNonceAndCertificates = false;
    if (mCreateResponseState->resolvedCertType && mCreateResponseState->nonceLength > 0)
    {
      auto deps = mDependencies.lock();
      if (!deps)
      {
        fail_create_response(Status::BadInternalError,
          make_error_detail("DepsExpired", "Session dependencies expired", "Session"));
        co_return;
      }
      provisionNonceAndCertificates = deps->crypto() && deps->default_application_group_certificate_store();
    }

    if (provisionNonceAndCertificates)
    {
      auto entropyResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          auto deps = mDependencies.lock();
          deps->crypto()->get_entropy_async(mCreateResponseState->nonceLength, std::move(completion));
        });
      if (!mCreateResponseState)
        co_return;
      if (!entropyResult.is_good())
      {
        // A server nonce is taken only from a Good answer; an Uncertain one is refused, not passed on.
        const StatusCode failure = ua::security_internal::not_good_answer(
          entropyResult.status_code(), Status::BadInternalError, "Session");
        fail_create_response(failure,
          make_error_detail("EntropyFailed",
            "Failed to generate server nonce for CreateSession response",
            "Session",
            failure.shared_detail()));
        co_return;
      }
      mServerNonce = std::move(entropyResult).value();
      mCreateResponseState->response->server_nonce() = mServerNonce;

      auto deps = mDependencies.lock();
      if (!deps)
      {
        fail_create_response(
          Status::BadInternalError, make_error_detail("DepsExpired", "Session deps expired", "Session"));
        co_return;
      }
      auto store = deps->default_application_group_certificate_store();
      if (!store)
      {
        fail_create_response(Status::BadSecurityChecksFailed,
          make_error_detail("NoCertStore", "No certificate store available", "Session"));
        co_return;
      }

      auto certResult = co_await await_step<CertificateStore::ApplicationCertificateListResult>(
        [&store](auto completion) { store->get_application_certificates_async(std::move(completion)); });
      if (!mCreateResponseState)
        co_return;
      if (!certResult.is_good())
      {
        fail_create_response(Status::BadUnexpectedError,
          make_error_detail("CertificateRetrievalFailed",
            "Could not retrieve server certificates from certificate store",
            "Session",
            ua::security_internal::not_good_store_answer_detail(certResult.status_code(), "Session")));
        co_return;
      }
      mServerCertificates = std::move(certResult).value();

      // OPC 10000-4 Table 193 / OPC 10000-6 6.8.3 (decision BR-15): on a None channel the certificate is a
      // held one valid for every token policy of the endpoint - the type the prologue resolved when that one
      // is, otherwise another. The start-up check refuses an endpoint none is valid for, so a miss here means
      // the held certificates changed since; the type the prologue resolved is then kept.
      if (mSecureChannelInfo)
      {
        if (auto held =
              stack_utils::resolve_certificate_type_for_endpoint(mSecureChannelInfo->security_policy()->id(),
                mSecureChannelInfo->user_identity_tokens(),
                mServerCertificates))
        {
          mCreateResponseState->resolvedCertType = held;
        }
      }

      // The resolved certificate type is engaged by the prologue, which gates this whole branch on
      // it. Bind the optional to a local reference, then guard and deref it so the access is
      // statically provable.
      const auto& resolvedCertTypeOpt = mCreateResponseState->resolvedCertType;
      if (!resolvedCertTypeOpt.has_value())
      {
        fail_create_response(Status::BadSecurityChecksFailed,
          make_error_detail(
            "NoResolvedCertType", "No certificate type was resolved for the endpoint", "Session"));
        co_return;
      }
      const auto resolvedCertType = *resolvedCertTypeOpt;

      for (const auto& cert : mServerCertificates)
      {
        if (cert.certificateType == resolvedCertType)
        {
          mSelectedServerCertAndKey = cert;
          break;
        }
      }
      if (!mSelectedServerCertAndKey.certificate)
      {
        fail_create_response(Status::BadSecurityChecksFailed,
          make_error_detail(
            "NoMatchingCert", "No application certificate of the resolved type was found", "Session"));
        co_return;
      }
      // Decision 24: the leaf then the own issuer chain in order (OPC 10000-6 section 6.2.6).
      mCreateResponseState->response->server_certificate() = ::ua::detail::encode_certificate_field(
        mSelectedServerCertAndKey.certificate, mSelectedServerCertAndKey.issuerCertificates);

      // --- the server signature, for an authenticated channel -----------------------------
      if (!mSecureChannelInfo.has_value())
      {
        fail_create_response(Status::BadInternalError,
          make_error_detail("MissingSecureChannel", "Session lost its secure channel", "Session"));
        co_return;
      }

      // An unauthenticated channel is not signed, and the chain still ran an EMPTY SignatureData
      // through the check below rather than skipping it - which is why the assignment stays
      // conditional instead of following from "we got here, so we signed".
      SignatureDataResult sigResult{SignatureData{}};
      if (mSecureChannelInfo->security_policy()->is_authenticated())
      {
        sigResult = co_await await_step<SignatureDataResult>(
          [this](auto completion) {
            create_server_signature_async(
              mCreateResponseState->request->client_nonce(), std::move(completion));
          });
        if (!mCreateResponseState)
          co_return;
        if (!sigResult.is_good())
        {
          fail_create_response(sigResult.status_code(),
            make_error_detail("ServerSignatureFailed",
              "Failed to build server signature for CreateSession response",
              "Session",
              sigResult.shared_detail()));
          co_return;
        }
      }

      if (!mSecureChannelInfo.has_value())
      {
        fail_create_response(Status::BadInternalError,
          make_error_detail("MissingSecureChannel", "Session lost its secure channel", "Session"));
        co_return;
      }
      auto securityPolicy = mSecureChannelInfo->security_policy();
      if (securityPolicy->is_authenticated())
      {
        mCreateResponseState->response->server_signature() = std::move(sigResult).value();
      }

      // --- the ephemeral key, when the client asked for one ------------------------------
      if (securityPolicy->ephemeral_key_algorithm() != EphemeralKeyAlgorithm::Invalid)
      {
        if (!co_await provision_ecc_ephemeral_key())
        {
          co_return;
        }
      }
    }

    // --- the endpoints this server advertises -------------------------------------------
    if (!co_await fetch_create_response_endpoints())
    {
      co_return;
    }

    // --- does the endpoint's hostname match a certificate we hold? ----------------------
    if (!co_await check_create_endpoint_hostname())
    {
      co_return;
    }

    finish_create_response();
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    if (mCreateResponseState)
    {
      fail_create_response(er, er.shared_detail());
    }
  }
  co_return;
}

ua::async::Task<bool> Session::provision_ecc_ephemeral_key()
{
  const auto* additionalParams = dynamic_cast<const AdditionalParametersType*>(
    mCreateResponseState->request->request_header().additional_header().get());
  if (!additionalParams)
    co_return true;

  for (const auto& kv : additionalParams->parameters().payload())
  {
    if (std::string_view{kv.key().name()} != "ECDHPolicyUri")
      continue;

    auto policyUri = kv.value().as<String>();
    if (policyUri.empty())
      co_return true;  // the chain broke out of the loop here, leaving no ephemeral key

    // OPC 10000-6 6.8.3: the Client names the SecurityPolicyUri it plans to use for the UserIdentityToken,
    // and "If the SecurityPolicyUri is not valid the Server returns a StatusCode in the ResponseHeader
    // instead of an EphemeralKey" (Table 63: ECDHKey carries "a StatusCode indicating the reason for the
    // error"). A valid one is an ECC policy that a UserTokenPolicy of this endpoint actually uses - the
    // token is encrypted "using a SecurityPolicy specified by a UserTokenPolicy supported by the current
    // Endpoint" (6.8.3). Anything else - an unknown URI, a non-ECC policy, or an ECC policy no token policy
    // of this endpoint uses - is refused here instead of being honoured (security review SESS-7(f): it
    // was used unchecked, and a known non-ECC URI failed the whole CreateSession). The endpoint's list is
    // the CreateSession channel's; the key is only issued here, at CreateSession (6.8.3: "The
    // SecurityPolicyUri passed in CreateSession is used to determine what type of EphemeralKey to
    // return"), so an ECDHPolicyUri in a later ActivateSession header is not read at all.
    // Cost: one pass over the endpoint's user token policies, once per CreateSession.
    SecurityPolicyId requestedPolicyId = SecurityPolicyId::Invalid;
    try
    {
      auto requestedPolicy = SecurityPolicy::create(policyUri);
      if (requestedPolicy->ephemeral_key_algorithm() != EphemeralKeyAlgorithm::Invalid &&
          mSecureChannelInfo.has_value())
      {
        const auto channelPolicy = mSecureChannelInfo->security_policy();
        for (const auto& tokenPolicy : mSecureChannelInfo->user_identity_tokens())
        {
          // An Anonymous token carries nothing to encrypt, so its policy offers no key exchange.
          if (tokenPolicy.token_type() == UserTokenType::Anonymous)
            continue;
          const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
          // An empty securityPolicyUri inherits the SecureChannel's policy (OPC 10000-4 7.41.4).
          const bool offered = tokenPolicyUri.empty()
                                 ? (channelPolicy && channelPolicy->id() == requestedPolicy->id())
                                 : static_cast<std::string_view>(tokenPolicyUri) ==
                                     static_cast<std::string_view>(requestedPolicy->uri());
          if (offered)
          {
            requestedPolicyId = requestedPolicy->id();
            break;
          }
        }
      }
    }
    catch (...)
    {
      // An unknown URI is an invalid one; answered below like every other.
      ua::detail::ignore_expected_exception();
    }

    if (requestedPolicyId != SecurityPolicyId::Invalid)
    {
      mEccUserTokenPolicyId = requestedPolicyId;
    }
    else
    {
      // Invalid ECDHPolicyUri - respond with error status in AdditionalHeader and skip ephemeral
      // generation.
      auto responseParams = make_unique<AdditionalParametersType>();
      KeyValuePair errorKv;
      errorKv.key() = QualifiedName{0, "ECDHKey"};
      errorKv.value() = Variant{StatusCode{Status::BadSecurityPolicyRejected}};
      responseParams->parameters().payload().push_back(std::move(errorKv));
      mCreateResponseState->response->response_header().additional_header() = std::move(responseParams);
      co_return true;
    }

    // The signing inputs are confirmed before the pair is generated, so a missing input generates no
    // pair. A signature that fails fails the CreateSession, so the pair it generated never reaches a
    // client and no Session is left using it.
    if (!mSecureChannelInfo.has_value())
    {
      fail_create_response(Status::BadInternalError,
        make_error_detail("MissingSecureChannel", "Session lost its secure channel", "Session"));
      co_return false;
    }
    auto deps = mDependencies.lock();
    if (!deps)
    {
      fail_create_response(
        Status::BadInternalError, make_error_detail("DepsExpired", "Session deps expired", "Session"));
      co_return false;
    }

    auto ecdhKey = co_await issue_signed_ecdh_key(deps->crypto(),
      mSecureChannelInfo->security_policy(),
      mSelectedServerCertAndKey.keys,
      "Failed to sign ECC ephemeral key for user token encryption");
    if (!mCreateResponseState)
      co_return false;
    if (!ecdhKey.is_good())
    {
      fail_create_response(ecdhKey.status_code(), ecdhKey.shared_detail());
      co_return false;
    }
    mCreateResponseState->response->response_header().additional_header() = std::move(ecdhKey).value();
    co_return true;
  }
  co_return true;
}

ua::async::Task<bool> Session::fetch_create_response_endpoints()
{
  auto deps = mDependencies.lock();
  if (!deps)
  {
    fail_create_response(
      Status::BadInternalError, make_error_detail("DepsExpired", "Session deps expired", "Session"));
    co_return false;
  }
  auto discoveryDeps = deps->discovery_dependencies().lock();
  if (!discoveryDeps)
  {
    if (mCreateAdmissionPublished)
    {
      fail_create_response(Status::BadInternalError,
        make_error_detail(
          "DiscoveryDependenciesUnavailable", "Discovery dependencies unavailable", "Session"));
      co_return false;
    }

    // Pre-flip code threw `check(discoveryDeps)` and the coroutine was silently destroyed without
    // sending a response. Reproduce that behaviour: drop the in-flight create state WITHOUT firing
    // the callback, so the test fixtures (which intentionally pass null discovery deps) do not see
    // a wire fault. Production code always wires up discovery deps, so this is a safety net for
    // misconfigured test scaffolds rather than a real runtime path.
    if (auto sessionDeps = mDependencies.lock())
    {
      sessionDeps->logger().with_category("session").warning(
        {{"session_name", std::string_view{mSessionName}}},
        "Discovery dependencies unavailable; abandoning CreateSession response");
    }
    mCreateResponseState.reset();
    co_return false;
  }

  if (!Discovery::is_endpoint_url_accepted(mCreateResponseState->request->endpoint_url(), *discoveryDeps))
  {
    fail_create_response(Status::BadTcpEndpointUrlInvalid,
      ErrorDetail::build(
        "InvalidEndpointUrl", "CreateSession endpointUrl is not accepted by any listener", "Session")
        .context(ua::ContextKeys::endpointUrl, std::string{mCreateResponseState->request->endpoint_url()}));
    co_return false;
  }

  // `Discovery::get_endpoints_async` runs on Discovery's own internal strand, and `await_step` hops
  // back to the session strand before this body touches session state again. The Discovery
  // shared_ptr is a local of this frame, which is what keeps the stateless service object alive
  // across its own async cert-store fetch.
  auto discovery = Discovery::create();
  auto endpointsResult = co_await await_step<EndpointDescriptionListResult>(
    [this, &discovery, &discoveryDeps](auto completion)
    {
      discovery->get_endpoints_async(
        std::string{mCreateResponseState->request->endpoint_url()}, discoveryDeps, std::move(completion));
    });
  if (!mCreateResponseState)
    co_return false;
  if (!endpointsResult.is_good())
  {
    fail_create_response(endpointsResult.status_code(),
      ErrorDetail::build("GetEndpointsFailed", "Discovery::get_endpoints_async failed", "Session")
        .context(ua::ContextKeys::endpointUrl, std::string{mCreateResponseState->request->endpoint_url()})
        .cause(endpointsResult.shared_detail()));
    co_return false;
  }
  mCreateResponseState->response->server_endpoints() = std::move(endpointsResult).value();
  co_return true;
}

ua::async::Task<bool> Session::check_create_endpoint_hostname()
{
  if (mServerCertificates.empty())
  {
    auto dependencies = mDependencies.lock();
    auto certificateStore =
      dependencies ? dependencies->default_application_group_certificate_store() : nullptr;
    if (!certificateStore)
    {
      // A certificate-less test fixture has no declared HostNames to compare. Production ServerImpl
      // validates its application certificate store before serving endpoints.
      co_return true;
    }

    auto certificatesResult = co_await await_step<CertificateStore::ApplicationCertificateListResult>(
      [&certificateStore](auto completion)
      { certificateStore->get_application_certificates_async(std::move(completion)); });
    if (!mCreateResponseState)
      co_return false;
    if (!certificatesResult.is_good())
    {
      fail_create_response(Status::BadSecurityChecksFailed,
        make_error_detail("EndpointHostnameCertificatesUnavailable",
          "Could not retrieve Server certificates for the CreateSession endpointUrl HostName check",
          "Session",
          certificatesResult.status_code()));
      co_return false;
    }
    mServerCertificates = std::move(certificatesResult).value();
  }

  const std::string endpointUrl{mCreateResponseState->request->endpoint_url()};
  auto parsedUrl = ua::transport::parse_opc_tcp_url(endpointUrl, "server.Session.CreateSession");
  if (!parsedUrl.is_good())
  {
    fail_create_response(parsedUrl.status_code(), parsedUrl.shared_detail());
    co_return false;
  }

  const auto& endpointHostname = parsedUrl.value().hostname;
  bool hasServerCertificate = false;
  bool hostnameMatches = false;
  for (const auto& applicationCertificate : mServerCertificates)
  {
    if (!applicationCertificate.certificate)
      continue;
    hasServerCertificate = true;
    if (ua::detail::certificate_matches_hostname(endpointHostname, *applicationCertificate.certificate))
    {
      hostnameMatches = true;
      break;
    }
  }
  mCreateResponseState->endpointUrlMismatch = hasServerCertificate && !hostnameMatches;
  co_return true;
}

void Session::finish_create_response()
{
  if (!mCreateResponseState)
    return;

  auto expected = CreateCompletionState::Pending;
  if (!mCreateCompletionState.compare_exchange_strong(
        expected, CreateCompletionState::Sending, std::memory_order_acq_rel))
  {
    if (expected == CreateCompletionState::Suppressed)
    {
      fail_create_response(Status::BadTooManySessions,
        make_error_detail(
          "SessionEvictedBeforeCreateCompleted", "Session was evicted before creation completed", "Session"));
    }
    else
    {
      fail_create_response(Status::BadInternalError,
        make_error_detail("CreateSessionCompletionStateInvalid",
          "CreateSession completion entered an invalid state",
          "Session"));
    }
    return;
  }

  const auto requestId = mCreateResponseState->requestId;
  auto response = mCreateResponseState->response;
  auto request = mCreateResponseState->request;

  try
  {
    auto sc = mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr;
    if (sc)
    {
      sc->send_response_message(std::make_pair(requestId, response));
    }
    else
    {
      enqueue_response(std::make_pair(requestId, response));
    }
  }
  catch (...)
  {
    mCreateCompletionState.store(CreateCompletionState::Suppressed, std::memory_order_release);
    auto failure = ::ua::exception_to_status_code(std::current_exception());
    fail_create_response(failure, failure.shared_detail());
    return;
  }

  mCreateCompletionState.store(CreateCompletionState::Committed, std::memory_order_release);
  mState.store(State::Created, std::memory_order_release);

  if (auto sessionDeps = mDependencies.lock())
  {
    auto sessionIdStr = ua::to_string(mSessionId);
    sessionDeps->logger().info(
      {{"session_name", std::string_view{mSessionName}}, {"session_id", std::string_view{sessionIdStr}}},
      "Session created");
    auto eh = sessionDeps->observer();
    auto evInfo = build_session_event_info(mSessionId, mSessionName, mSecureChannelInfo);
    evInfo.auditEntryId = request->request_header().audit_entry_id();
    evInfo.endpointUrl = request->endpoint_url();
    evInfo.endpointUrlMismatch = mCreateResponseState->endpointUrlMismatch;
    if (mClientCertificate)
    {
      evInfo.clientCertificate = mClientCertificate->der_encoding();
      evInfo.clientCertificateThumbprint = ua::to_string(mClientCertificate->thumbprint());
    }
    evInfo.revisedSessionTimeout = static_cast<double>(mRevisedSessionTimeout.count());
    detail::emit_event(sessionDeps->logger(), eh, [&] { eh->on_session_created(evInfo); });
  }

  mInFlightRequestsByRequestId.erase(requestId);
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mReturnDiagnosticsByRequestId.erase(requestId);

  auto cb = std::move(mCreateResponseState->callback);
  mCreateResponseState.reset();
  cb(VoidResult{});
}

void Session::fail_create_response(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
{
  if (!mCreateResponseState)
    return;
  auto requestId = mCreateResponseState->requestId;
  auto request = mCreateResponseState->request;
  auto cb = std::move(mCreateResponseState->callback);
  mCreateResponseState.reset();
  StatusCode failure = detail ? StatusCode{status.value(), std::move(detail)} : std::move(status);
  notify_create_session_failed(*request, failure);
  // Route through create_and_send_service_fault to apply pre-auth StatusCode masking.
  create_and_send_service_fault(requestId, failure);
  rollback_create_admission_on_strand();
  cb(VoidResult{failure});
}

void Session::rollback_create_admission_on_strand()
{
  if (!mCreateAdmissionPublished)
    return;

  mCreateAdmissionPublished = false;
  auto expected = CreateCompletionState::Pending;
  mCreateCompletionState.compare_exchange_strong(
    expected, CreateCompletionState::Suppressed, std::memory_order_acq_rel);
  mSessionState = State::Closed;
  mState.store(State::Closed, std::memory_order_release);
  mTimeoutTimer.cancel();
  destroy_diagnostics_object();

  if (mSecureChannelInfo)
  {
    if (auto secureChannel = mSecureChannelInfo->secure_channel().lock())
      secureChannel->unregister_session(mAuthenticationToken);
  }

  mInFlightRequestsByRequestId.clear();
  mAuthnUserByRequestId.clear();
  mAuthnEndpointByRequestId.clear();
  mReturnDiagnosticsByRequestId.clear();

  if (auto dependencies = mDependencies.lock())
    dependencies->remove_session(shared_from_this());
}

void Session::terminate_for_eviction_on_strand()
{
  StatusCode failure{Status::BadTooManySessions,
    make_error_detail(
      "SessionEvictedBeforeCreateCompleted", "Session was evicted before creation completed", "Session")};

  if (mCreateResponseState)
  {
    fail_create_response(failure, failure.shared_detail());
    return;
  }

  const auto createRequest = std::ranges::find_if(mInFlightRequestsByRequestId,
    [](const auto& entry)
    { return dynamic_cast<const CreateSessionRequest*>(entry.second.get()) != nullptr; });
  if (createRequest != mInFlightRequestsByRequestId.end())
  {
    const auto* request = dynamic_cast<const CreateSessionRequest*>(createRequest->second.get());
    notify_create_session_failed(*request, failure);
    create_and_send_service_fault(createRequest->first, failure);
  }
  rollback_create_admission_on_strand();
}

void Session::close_session_internal(
  StatusCode reason, shared_ptr<const ErrorDetail> detail, bool deleteSubscriptions)
{
  mCloseReason.store(reason.value(), std::memory_order_release);
  // Every way a Session ends comes here, before a CloseSession response is sent (OPC 10000-4 5.6.4.1 (b)).
  abort_outstanding_ops(StatusCode{Status::BadSessionClosed});

  {
    auto sessionDeps = mDependencies.lock();
    if (sessionDeps)
    {
      if (detail)
      {
        sessionDeps->logger().info({{"session_name", std::string_view{mSessionName}},
                                     {"close_reason", fmt::format("0x{:08x}", reason.as_uint32())},
                                     {"error", to_string(*detail)}},
          "Session closed");
      }
      else
      {
        sessionDeps->logger().info({{"session_name", std::string_view{mSessionName}},
                                     {"close_reason", fmt::format("0x{:08x}", reason.as_uint32())}},
          "Session closed");
      }
    }
  }

  // Emit timeout event explicitly; on_session_closed is emitted by the destructor.
  if (mState.load(std::memory_order_acquire) != State::Closed && reason == Status::BadTimeout)
  {
    auto sessionDeps = mDependencies.lock();
    if (sessionDeps)
    {
      sessionDeps->logger().warning({{"session_name", std::string_view{mSessionName}}}, "Session timed out");
      auto eh = sessionDeps->observer();
      auto evInfo = build_session_event_info(mSessionId, mSessionName, mSecureChannelInfo);
      if (auto user = mSessionInfo->user_identity())
        evInfo.clientUserId = user->userId;
      detail::emit_event(sessionDeps->logger(), eh, [&] { eh->on_session_timed_out(evInfo); });

      // A session closed because it timed out increments sessionTimeoutCount (OPC 10000-5
      // ServerDiagnosticsSummary). This is the sole timeout-close path, and the mState guard above
      // prevents a double count, so exactly one increment per timed-out session. Gated on the
      // diagnostics flag like the other summary counters so it stays inert when ServerDiagnostics is
      // disabled.
      auto summaryCounters = sessionDeps->summary_counters();
      auto diagnosticsEnabled = sessionDeps->diagnostics_enabled();
      if (summaryCounters && diagnosticsEnabled && diagnosticsEnabled->load(std::memory_order_relaxed))
      {
        summaryCounters->sessionTimeoutCount.fetch_add(1, std::memory_order_relaxed);
      }
    }
  }

  release_registered_nodes();

  // Close all subscriptions and drain publish queue - unless this is an explicit CloseSession that
  // requested deleteSubscriptions=false, in which case orphan them for a later TransferSubscriptions.
  auto pipeline = mSubscriptionsPipeline.load();
  if (pipeline)
  {
    if (deleteSubscriptions)
    {
      pipeline->close_all();
    }
    else
    {
      UserIdentity owningUser;
      EndpointSecurityContext sourceSecurity;
      if (auto user = mSessionInfo->user_identity())
      {
        owningUser = *user;
      }
      if (auto endpoint = mSessionInfo->endpoint_security())
      {
        sourceSecurity = *endpoint;
      }
      pipeline->orphan_all(SubscriptionTransferContext{.owningUser = std::move(owningUser),
        .verifiedApplicationUri = std::move(sourceSecurity.clientApplicationUri),
        .sourceSecurityMode = sourceSecurity.messageSecurityMode});
    }
  }

  if (mTimeoutTimer)
  {
    mTimeoutTimer.cancel();
  }

  // A held ActivateSession is still owed an answer. Discarding the flow silently leaves the client
  // blocked on a request the server has quietly decided never to answer, until its own service
  // timeout expires - a wait that is orders of magnitude longer than the fault it should have got,
  // and that reports the wrong thing when it ends. Bad_SessionIdInvalid is what any later request on
  // this token would get, so the client learns the same fact either way.
  if (mAuthState)
  {
    auto abandoned = std::move(mAuthState);
    abandoned->completionTimer = {};
    create_and_send_service_fault(abandoned->requestId,
      Status::BadSessionIdInvalid,
      ErrorDetail::build("SessionClosedDuringAuthentication",
        fmt::format("The Session was closed ({}) while its ActivateSession was still being authenticated",
          to_string(reason.as_status())),
        "Session"));
  }
  mAuthState.reset();
  mWaitingForAuthn = false;

  // Unregister from the secure channel. Keep mSecureChannelInfo populated so post-close
  // service-fault paths (e.g. double-close) can still route a wire response back to the
  // channel - SecureChannelInfo holds only a weak_ptr to SecureChannel, so retaining it
  // does not extend SC lifetime.
  if (mSecureChannelInfo)
  {
    if (auto sc = mSecureChannelInfo->secure_channel().lock())
    {
      sc->unregister_session(mAuthenticationToken);
    }
  }

  auto deps = mDependencies.lock();
  if (deps)
  {
    deps->remove_session(shared_from_this());
  }
}

namespace
{
// Helper: move raw password bytes into a SecureString and scrub the source (DEF-4/SESS-4). The
// (pointer, length) constructor keeps an embedded NUL as part of the password, not as its end.
ua::SecureString to_secure_password(ByteString passwordBytes)
{
  ua::SecureString password{utils::bytes_to_chars(passwordBytes.data()), passwordBytes.size()};
  ua::security::secure_clear(passwordBytes);
  return password;
}

StatusCode normalize_identity_token_validation_failure(StatusCode cause)
{
  return StatusCode{Status::BadIdentityTokenInvalid,
    ErrorDetail::build("IdentityTokenValidationFailed", "User identity token validation failed", "Session")
      .cause(std::move(cause))};
}

// The buffers of one asymmetric signature check, owned for as long as the Crypto provider holds the spans it
// was handed: it is passed as the call's resource. The signer's public key is held here too, since the
// certificate returns it by value.
struct PinnedSignatureCheck
{
  ByteString data;
  ByteString signature;
  ByteString publicKey;
};

}  // namespace

shared_ptr<SecurityPolicy> Session::resolve_user_token_decryption_policy(
  std::string_view clientEncryptionAlgorithm) const
{
  // The decryption algorithm + key are dictated by the *negotiated* user-token policy, not by the
  // client-supplied UserNameIdentityToken.encryptionAlgorithm (Part 4 7.41: that field names the
  // asymmetric algorithm, e.g. rsa-oaep-sha2-256, and is attacker-controllable, so it must not
  // select the decryption parameters).
  //
  // 1. Negotiated user-token policy (authoritative). An empty securityPolicyUri means it inherits
  //    the secure channel's policy, handled in step 2.
  if (mAuthState && mAuthState->matchedPolicy && !mAuthState->matchedPolicy->security_policy_uri().empty())
  {
    return SecurityPolicy::create(
      static_cast<std::string_view>(mAuthState->matchedPolicy->security_policy_uri()));
  }
  // 2. Secure channel policy (the user-token policy inherited it). The channel is the one this
  //    ActivateSession arrived on, held by the flow, not the Session's current channel: on a
  //    re-activation over a new SecureChannel the Session still holds the old one until the activation
  //    succeeds, and the token policy was matched against the new channel's endpoint (security review
  //    SESS-7(d); OPC 10000-4 7.41.4: "The SecurityPolicy of the SecureChannel is used if no
  //    SecurityPolicy is specified in the UserTokenPolicy").
  const auto& requestChannel =
    (mAuthState && mAuthState->channelInfo) ? mAuthState->channelInfo : mSecureChannelInfo;
  if (requestChannel && requestChannel->security_policy())
  {
    return SecurityPolicy::create(requestChannel->security_policy()->id());
  }
  // 3. Legacy fallback: older SDK clients put the SecurityPolicy URI in encryptionAlgorithm.
  return SecurityPolicy::create(clientEncryptionAlgorithm);
}

void Session::decrypt_issued_token_async(ByteString tokenData, std::function<void(ByteStringResult)> callback)
{
  auto complete = ::ua::detail::make_fire_once<ByteStringResult>(std::move(callback));
  try
  {
    auto dependencies = mDependencies.lock();
    if (!dependencies)
    {
      complete(ByteStringResult{StatusCode{Status::BadInternalError},
        make_error_detail(
          "DepsExpired", "Session dependencies expired during issued-token decryption", "Session")});
      return;
    }

    auto policy = resolve_user_token_decryption_policy({});
    if (policy->id() == SecurityPolicyId::None)
    {
      complete(ByteStringResult{std::move(tokenData)});
      return;
    }

    if (mServerNonce.empty())
    {
      complete(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
        make_error_detail("IssuedTokenServerNonceUnavailable",
          "Server nonce unavailable for issued-token decryption",
          "Session")});
      return;
    }

    auto crypto = dependencies->crypto();
    if (!crypto)
    {
      complete(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
        make_error_detail("IssuedTokenCryptoUnavailable",
          "Crypto provider unavailable for issued-token decryption",
          "Session")});
      return;
    }

    if (policy->ephemeral_key_algorithm() != EphemeralKeyAlgorithm::Invalid)
    {
      if (mEccEphemeralPrivateKey.empty())
      {
        complete(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
          make_error_detail("IssuedTokenEccPrivateKeyUnavailable",
            "No ECC ephemeral private key is available for issued-token decryption",
            "Session")});
        return;
      }

      auto eccPolicy = std::dynamic_pointer_cast<const SecPolEphemeralKey>(policy);
      if (!eccPolicy)
      {
        mEccEphemeralPrivateKey.clear();
        complete(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
          make_error_detail("IssuedTokenEccPolicyInvalid",
            "The negotiated issued-token policy is not a valid ephemeral-key policy",
            "Session")});
        return;
      }

      auto weakSelf = weak_from_this();
      ua::decrypt_ecc_encrypted_secret_async(std::move(tokenData),
        std::move(eccPolicy),
        std::move(crypto),
        mStrand,
        std::move(mEccEphemeralPrivateKey),
        ByteString{mEccEphemeralPublicKey},
        mClientCertificate,
        mLogger,
        [weakSelf, complete](EccEncryptedSecretFieldsResult decryptResult) mutable
        {
          auto self = weakSelf.lock();
          if (!self)
          {
            complete(ByteStringResult{StatusCode{Status::BadSessionClosed},
              make_error_detail(
                "SessionDestroyed", "Session was destroyed during issued-token ECC decryption", "Session")});
            return;
          }
          ua::async::post_borrowing_or_else(
            self.get(),
            self->mStrand,
            self->mLogger,
            [complete, decryptResult = std::move(decryptResult)](Session& session) mutable
            {
              session.mEccEphemeralPrivateKey.clear();
              if (!decryptResult.is_good())
              {
                complete(
                  ByteStringResult{normalize_identity_token_validation_failure(decryptResult.status_code())});
                return;
              }
              auto fields = std::move(decryptResult).value();
              if (!std::ranges::equal(span<const byte>{fields.nonce}, span<const byte>{session.mServerNonce}))
              {
                complete(ByteStringResult{StatusCode{Status::BadIdentityTokenInvalid},
                  make_error_detail("IssuedTokenNonceMismatch",
                    "Decrypted issued-token ECC nonce does not match the current server nonce",
                    "Session")});
                return;
              }
              complete(ByteStringResult{std::move(fields.secret)});
            },
            [complete]() mutable
            {
              complete(ByteStringResult{StatusCode{Status::BadSessionClosed},
                make_error_detail("SessionDestroyed",
                  "Session was destroyed during issued-token ECC completion",
                  "Session")});
            })();
        });
      return;
    }

    if (policy->is_rsa())
    {
      if (!mSelectedServerCertAndKey.keys)
      {
        complete(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
          make_error_detail("IssuedTokenPrivateKeyUnavailable",
            "No private key is available for issued-token RSA decryption",
            "Session")});
        return;
      }
      if (!ua::is_rsa_encrypted_secret(span<const byte>{tokenData}))
      {
        complete(ByteStringResult{StatusCode{Status::BadIdentityTokenInvalid},
          ErrorDetail::build("IssuedTokenEncryptedSecretMalformed",
            "IssuedIdentityToken tokenData is not an RsaEncryptedSecret",
            "Session")
            .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})});
        return;
      }

      auto weakSelf = weak_from_this();
      ua::decrypt_rsa_encrypted_secret_async(std::move(tokenData),
        std::move(policy),
        std::move(crypto),
        mStrand,
        mSelectedServerCertAndKey.keys,
        mSelectedServerCertAndKey.certificate,
        mSessionInfo->server_configuration().acceptInvalidPadding,
        mLogger,
        [weakSelf, complete](RsaEncryptedSecretFieldsResult decryptResult) mutable
        {
          auto self = weakSelf.lock();
          if (!self)
          {
            complete(ByteStringResult{StatusCode{Status::BadSessionClosed},
              make_error_detail(
                "SessionDestroyed", "Session was destroyed during issued-token RSA decryption", "Session")});
            return;
          }
          ua::async::post_borrowing_or_else(
            self.get(),
            self->mStrand,
            self->mLogger,
            [complete, decryptResult = std::move(decryptResult)](Session& session) mutable
            {
              if (!decryptResult.is_good())
              {
                complete(
                  ByteStringResult{normalize_identity_token_validation_failure(decryptResult.status_code())});
                return;
              }
              auto fields = std::move(decryptResult).value();
              if (!std::ranges::equal(span<const byte>{fields.nonce}, span<const byte>{session.mServerNonce}))
              {
                complete(ByteStringResult{StatusCode{Status::BadIdentityTokenInvalid},
                  make_error_detail("IssuedTokenNonceMismatch",
                    "Decrypted issued-token RSA nonce does not match the current server nonce",
                    "Session")});
                return;
              }
              complete(ByteStringResult{std::move(fields.secret)});
            },
            [complete]() mutable
            {
              complete(ByteStringResult{StatusCode{Status::BadSessionClosed},
                make_error_detail("SessionDestroyed",
                  "Session was destroyed during issued-token RSA completion",
                  "Session")});
            })();
        });
      return;
    }

    complete(ByteStringResult{StatusCode{Status::BadSecurityPolicyRejected},
      ErrorDetail::build("IssuedTokenDecryptionPolicyUnsupported",
        "The negotiated user-token policy cannot decrypt an IssuedIdentityToken",
        "Session")
        .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})});
  }
  catch (...)
  {
    auto error = ::ua::exception_to_status_code(std::current_exception());
    complete(ByteStringResult{error, error.shared_detail()});
  }
}

void Session::parse_identity_token_async(uint32_t requestHandle, ActivateSessionRequest& asr,
  std::function<void(ParsedIdentityTokenResult)> callback)
{
  try
  {
    auto deps = mDependencies.lock();
    if (!deps)
    {
      callback(ParsedIdentityTokenResult{Status::BadInternalError,
        make_error_detail("DepsExpired", "Session dependencies expired during token parse", "Session")});
      return;
    }

    ParsedIdentityToken result;
    result.request.sessionId = mSessionId;
    result.request.requestHandle = requestHandle;

    auto* token = asr.user_identity_token().get();
    const bool isAnonymous = (token == nullptr) || (dynamic_cast<AnonymousIdentityToken*>(token) != nullptr);

    if (isAnonymous)
    {
      result.request.identity.kind = UserTokenKind::Anonymous;
      callback(ParsedIdentityTokenResult{std::move(result)});
      return;
    }

    if (auto* un = dynamic_cast<UserNameIdentityToken*>(token))
    {
      result.request.identity.kind = UserTokenKind::UserName;
      result.request.identity.userName = std::string(un->user_name());

      // A UserNameIdentityToken with an empty userName is not a valid token (OPC 10000-4: the
      // userName identifies the user) -> Bad_IdentityTokenInvalid, decided here before the
      // application authenticator runs so an empty username can never surface as an access-control
      // decision such as Bad_UserAccessDenied. CTT Security User Name Password/003 requires Invalid
      // for an empty username+password.
      if (un->user_name().empty())
      {
        result.failure = make_authn_failure(
          StatusCode{Status::BadIdentityTokenInvalid}, "UserNameIdentityToken has an empty userName");
        callback(ParsedIdentityTokenResult{std::move(result)});
        return;
      }

      ByteString passwordBytes = un->password();

      auto policy = resolve_user_token_decryption_policy(un->encryption_algorithm());
      if (un->encryption_algorithm().empty() &&
          (passwordBytes.empty() || policy->ephemeral_key_algorithm() == EphemeralKeyAlgorithm::Invalid))
      {
        // ECC encryption metadata is inside the negotiated-policy envelope.
        // A nonempty ECC password must always pass the decoder, even with no
        // outer algorithm; empty credential handling remains the authenticator's decision.
        result.request.identity.password = to_secure_password(std::move(passwordBytes));
        callback(ParsedIdentityTokenResult{std::move(result)});
        return;
      }

      // Encrypted: dispatch to async path.
      if (mServerNonce.empty())
      {
        result.failure = make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
          "Server nonce unavailable for encrypted password decryption");
        callback(ParsedIdentityTokenResult{std::move(result)});
        return;
      }

      auto crypto = deps->crypto();
      if (!crypto)
      {
        result.failure = make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
          "Crypto provider unavailable for encrypted password decryption");
        callback(ParsedIdentityTokenResult{std::move(result)});
        return;
      }

      if (policy->ephemeral_key_algorithm() != EphemeralKeyAlgorithm::Invalid)
      {
        if (mEccUserTokenPolicyId == SecurityPolicyId::Invalid)
        {
          result.failure = make_authn_failure(
            StatusCode{Status::BadSecurityChecksFailed}, "ECC user token key negotiation is unavailable");
          callback(ParsedIdentityTokenResult{std::move(result)});
          return;
        }
        // ECC path (Part 4, 7.41.2.5; Part 6, 6.8.3-4).
        if (mEccEphemeralPrivateKey.empty())
        {
          result.failure = make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
            "No ECC ephemeral private key available for user token decryption");
          callback(ParsedIdentityTokenResult{std::move(result)});
          return;
        }

        auto eccPolicy = std::dynamic_pointer_cast<const SecPolEphemeralKey>(policy);
        if (!eccPolicy)
        {
          // Part 6 6.8.3 - the ephemeral private key is single-use per ActivateSession round.
          // Clear it on this error path (and any error path below) so a subsequent malformed
          // request cannot consume it.
          mEccEphemeralPrivateKey.clear();
          result.failure = make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
            "Encryption algorithm does not refer to a valid ephemeral-key policy");
          callback(ParsedIdentityTokenResult{std::move(result)});
          return;
        }

        auto me = weak_from_this();
        auto resultHolder = std::make_shared<ParsedIdentityToken>(std::move(result));

        ua::decrypt_ecc_encrypted_secret_async(std::move(passwordBytes),
          std::move(eccPolicy),
          crypto,
          mStrand,
          std::move(mEccEphemeralPrivateKey),
          ua::ByteString{mEccEphemeralPublicKey},
          mClientCertificate,
          mLogger,
          [me, callback = std::move(callback), resultHolder](
            EccEncryptedSecretFieldsResult decryptResult) mutable
          {
            auto lockedSelf = me.lock();
            if (!lockedSelf)
            {
              resultHolder->failure =
                make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed");
              callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
              return;
            }
            // The failure lives inside the shared resultHolder (ParsedIdentityToken.failure) that
            // whichever path runs finalises and moves out - so the gone value cannot be precomputed;
            // use the lazy alive/gone form of post_borrowing.
            ua::async::post_borrowing_or_else(
              lockedSelf.get(),
              lockedSelf->mStrand,
              lockedSelf->mLogger,
              [callback, resultHolder, decryptResult = std::move(decryptResult)](Session& self) mutable
              {
                // Clear ephemeral private key (consumed by decrypt, but clear member too).
                self.mEccEphemeralPrivateKey.clear();

                if (!decryptResult.is_good())
                {
                  resultHolder->failure = make_authn_failure(
                    normalize_identity_token_validation_failure(decryptResult.status_code()),
                    "ECC encrypted secret decryption failed");
                  callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
                  return;
                }

                auto fields = std::move(decryptResult).value();
                const span<const byte> decryptedNonce = fields.nonce;
                const span<const byte> expectedNonce = self.mServerNonce;
                if (!std::ranges::equal(decryptedNonce, expectedNonce))
                {
                  resultHolder->failure = make_authn_failure(StatusCode{Status::BadIdentityTokenInvalid},
                    "Decrypted ECC nonce does not match server nonce");
                  callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
                  return;
                }

                resultHolder->request.identity.password = to_secure_password(std::move(fields.secret));
                callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
              },
              [callback, resultHolder]() mutable
              {
                resultHolder->failure =
                  make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed");
                callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
              })();
          });
        return;
      }

      // RSA path.
      if (!mSelectedServerCertAndKey.keys)
      {
        result.failure = make_authn_failure(
          StatusCode{Status::BadSecurityChecksFailed}, "No private key available for password decryption");
        callback(ParsedIdentityTokenResult{std::move(result)});
        return;
      }

      // Modern Part 4 7.41.2.4 (RsaEncryptedSecret): the secret is an ExtensionObject whose
      // TypeId|EncodingMask|Length|CommonHeader prefix is cleartext, so detect it by peeking the leading
      // TypeId and decode it (RSA-decrypt KeyData with the server private key -> verify the HMAC over the
      // signed region -> AES-CBC-decrypt the payload). A modern RSA policy (Basic256Sha256+) emits this
      // form; the legacy 7.41.2.2 secret is opaque RSA ciphertext and falls through to the legacy path
      // below. The server therefore accepts BOTH forms (OPEN-IDENT-005-facet resolution).
      if (ua::is_rsa_encrypted_secret(span<const byte>{passwordBytes}))
      {
        auto me = weak_from_this();
        auto resultHolder = std::make_shared<ParsedIdentityToken>(std::move(result));

        ua::decrypt_rsa_encrypted_secret_async(std::move(passwordBytes),
          policy,
          crypto,
          mStrand,
          mSelectedServerCertAndKey.keys,
          mSelectedServerCertAndKey.certificate,
          mSessionInfo->server_configuration().acceptInvalidPadding,
          mLogger,
          [me, callback = std::move(callback), resultHolder](
            RsaEncryptedSecretFieldsResult decryptResult) mutable
          {
            auto lockedSelf = me.lock();
            if (!lockedSelf)
            {
              resultHolder->failure =
                make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed");
              callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
              return;
            }
            // Failure lives inside the shared resultHolder; the gone value cannot be precomputed, so use
            // the lazy alive/gone form (see the ECC path above).
            ua::async::post_borrowing_or_else(
              lockedSelf.get(),
              lockedSelf->mStrand,
              lockedSelf->mLogger,
              [callback, resultHolder, decryptResult = std::move(decryptResult)](Session& self) mutable
              {
                if (!decryptResult.is_good())
                {
                  resultHolder->failure = make_authn_failure(
                    normalize_identity_token_validation_failure(decryptResult.status_code()),
                    "RSA encrypted secret decryption failed");
                  callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
                  return;
                }

                auto fields = std::move(decryptResult).value();
                const span<const byte> decryptedNonce = fields.nonce;
                const span<const byte> expectedNonce = self.mServerNonce;
                if (!std::ranges::equal(decryptedNonce, expectedNonce))
                {
                  resultHolder->failure = make_authn_failure(StatusCode{Status::BadIdentityTokenInvalid},
                    "Decrypted RSA encrypted-secret nonce does not match server nonce");
                  callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
                  return;
                }

                resultHolder->request.identity.password = to_secure_password(std::move(fields.secret));
                callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
              },
              [callback, resultHolder]() mutable
              {
                resultHolder->failure =
                  make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed");
                callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
              })();
          });
        return;
      }

      // Part 4 7.41.2.2 (Legacy): the decrypted secret is
      // `Length(4 LE) || tokenData || serverNonce`. parse_legacy_encrypted_token_secret recovers
      // the password (and validates the trailing nonce + zero padding), also accepting the
      // historical prefix-less `tokenData || serverNonce` form for interop. The secret is decrypted
      // block by block: a 64-byte password with a 128-byte nonce spans two blocks of a 2048-bit
      // RSA-OAEP-SHA256 key.
      // DEF-4: the recovered plaintext is scrubbed when its last owner lets go, on every path - a block
      // that fails after another was recovered, and a Session destroyed during the decryption, included.
      struct ScrubbedBuffer
      {
        ByteString bytes;
        ua::security::ScrubOnExit scrub{bytes};
      };

      auto plainTextBuffer = std::make_shared<ScrubbedBuffer>();
      plainTextBuffer->bytes.resize(passwordBytes.size());
      const size_t plainTextBlockSize =
        policy->asymmetric_plaintext_block_size(mSelectedServerCertAndKey.certificate.get());
      const size_t cipherTextBlockSize =
        policy->asymmetric_ciphertext_block_size(mSelectedServerCertAndKey.certificate.get());

      auto me = weak_from_this();
      auto resultHolder = std::make_shared<ParsedIdentityToken>(std::move(result));
      auto cipherText = std::make_shared<ByteString>(std::move(passwordBytes));

      decrypt_legacy_token_secret_async(policy,
        crypto,
        mStrand,
        mSelectedServerCertAndKey.keys,
        plainTextBlockSize,
        cipherTextBlockSize,
        span<const byte>{*cipherText},
        span<byte>{plainTextBuffer->bytes},
        mLogger,
        [me, callback = std::move(callback), resultHolder, plainTextBuffer, cipherText](
          Result<span<const byte>> dec) mutable
        {
          auto lockedSelf = me.lock();
          if (!lockedSelf)
          {
            resultHolder->failure =
              make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed");
            callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
            return;
          }
          // Failure lives inside the shared resultHolder; the gone value cannot be precomputed, so use
          // the lazy alive/gone form (see the ECC path above).
          ua::async::post_borrowing_or_else(
            lockedSelf.get(),
            lockedSelf->mStrand,
            lockedSelf->mLogger,
            [callback, resultHolder, plainTextBuffer, dec = std::move(dec)](Session& self) mutable
            {
              if (!dec.is_good())
              {
                resultHolder->failure =
                  make_authn_failure(normalize_identity_token_validation_failure(dec.status_code()),
                    "Asymmetric decryption of encrypted password failed");
                callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
                return;
              }

              auto passwordResult =
                parse_legacy_encrypted_token_secret(dec.value(), span<const byte>{self.mServerNonce});
              ua::security::secure_clear(
                plainTextBuffer->bytes);  // DEF-4: the decrypted blocks are copied out
              if (!passwordResult.is_good())
              {
                resultHolder->failure = make_authn_failure(
                  normalize_identity_token_validation_failure(passwordResult.status_code()),
                  "Decrypted UserIdentityToken secret is malformed");
                callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
                return;
              }

              resultHolder->request.identity.password = to_secure_password(std::move(passwordResult).value());
              callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
            },
            [callback, resultHolder]() mutable
            {
              resultHolder->failure =
                make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed");
              callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
            })();
        });
      return;
    }

    if (auto* x509 = dynamic_cast<X509IdentityToken*>(token))
    {
      result.request.identity.kind = UserTokenKind::X509;
      auto crypto = deps->crypto();
      if (!crypto)
      {
        result.request.identity.kind = UserTokenKind::Unsupported;
      }
      else
      {
        try
        {
          // The one chain parser: the field may carry the leaf's issuers after it (decision 24).
          auto parsedField = ua::detail::parse_certificate_field(*crypto, x509->certificate_data());
          if (!parsedField.is_good())
          {
            throw UaException{parsedField.status_code()};
          }
          result.request.identity.x509Certificate = std::move(parsedField).value().front();
          result.x509CertificateField = x509->certificate_data();
        }
        catch (...)
        {
          auto er = ::ua::exception_to_status_code(std::current_exception());
          result.failure = make_authn_failure(StatusCode{Status::BadIdentityTokenInvalid, er.shared_detail()},
            fmt::format("Failed to parse X509 certificate from identity token: {}",
              er.shared_detail() ? er.shared_detail()->summary : "unknown error"),
            "Session");
        }
      }
      callback(ParsedIdentityTokenResult{std::move(result)});
      return;
    }

    if (auto* issued = dynamic_cast<IssuedIdentityToken*>(token))
    {
      result.request.identity.kind = UserTokenKind::IssuedToken;
      auto resultHolder = std::make_shared<ParsedIdentityToken>(std::move(result));
      decrypt_issued_token_async(issued->token_data(),
        [callback = std::move(callback), resultHolder](ByteStringResult decryptResult) mutable
        {
          if (!decryptResult.is_good())
          {
            resultHolder->failure = make_authn_failure(
              decryptResult.status_code(), "IssuedIdentityToken decryption failed", "Session");
          }
          else
          {
            resultHolder->request.identity.issuedToken = std::move(decryptResult).value();
          }
          callback(ParsedIdentityTokenResult{std::move(*resultHolder)});
        });
      return;
    }

    result.request.identity.kind = UserTokenKind::Unsupported;
    callback(ParsedIdentityTokenResult{std::move(result)});
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(ParsedIdentityTokenResult{er, er.shared_detail()});
  }
}

void Session::verify_user_token_signature_async(ActivateSessionRequest& asr,
  const ParsedIdentityToken& parsed, const SecureChannelInfo& channelInfo,
  std::function<void(OptionalAuthnFailure)> callback)
{
  try
  {
    if (asr.user_token_signature().signature().empty())
    {
      // Part 4 5.6.3.3 / 7.41.5: An X509IdentityToken MUST be accompanied by a non-empty
      // userTokenSignature whenever the resolved user-token security policy is authenticated.
      // Reject empty signatures for X509 with BadUserSignatureInvalid; other token kinds
      // (Anonymous, UserName, Issued) do not require a UserTokenSignature.
      if (parsed.request.identity.kind == UserTokenKind::X509)
      {
        SecurityPolicyId tokenPolicyId = SecurityPolicyId::Invalid;
        if (!parsed.tokenSecurityPolicyUri.empty())
        {
          tokenPolicyId = utils::get_security_policy_id(parsed.tokenSecurityPolicyUri);
        }
        else
        {
          tokenPolicyId = channelInfo.security_policy()->id();
        }
        auto tokenPolicy = SecurityPolicy::create(tokenPolicyId);
        if (tokenPolicy->is_authenticated())
        {
          callback(make_authn_failure(StatusCode{Status::BadUserSignatureInvalid},
            "X509 identity token presented without required userTokenSignature"));
          return;
        }
      }
      callback(std::nullopt);
      return;
    }

    auto deps = mDependencies.lock();
    if (!deps)
    {
      callback(make_authn_failure(
        StatusCode{Status::BadInternalError}, "Session dependencies expired during user token verification"));
      return;
    }

    auto crypto = deps->crypto();
    if (!crypto)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "Crypto provider unavailable for user token signature verification"));
      return;
    }

    if (parsed.request.identity.kind != UserTokenKind::X509 || !parsed.request.identity.x509Certificate)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "User token signature present but identity token is not X509"));
      return;
    }

    if (!mSelectedServerCertAndKey.certificate)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "No server certificate available for user token signature verification"));
      return;
    }

    SecurityPolicyId tokenPolicyId = SecurityPolicyId::Invalid;
    if (!parsed.tokenSecurityPolicyUri.empty())
    {
      tokenPolicyId = utils::get_security_policy_id(parsed.tokenSecurityPolicyUri);
    }
    else
    {
      tokenPolicyId = channelInfo.security_policy()->id();
    }
    auto tokenPolicy = SecurityPolicy::create(tokenPolicyId);
    auto userCertificate = *parsed.request.identity.x509Certificate;
    ByteString signature = asr.user_token_signature().signature();

    // OPC 10000-4 section 6.1.8: the UserTokenPolicy's SecurityPolicy decides the layout, the HASH and the
    // signing algorithm (SD-6). With SecureChannelEnhancements the signature is channel bound (Table 101), in
    // the None-mode layout over a None channel; the algorithm URI is then ignored (Table 174). Such a token
    // policy over a secured channel without enhancements was refused by the token-policy guard before this.
    if (tokenPolicy->secure_channel_enhancements())
    {
      const auto layout = channelInfo.message_security_mode() == MessageSecurityMode::None
                            ? ChannelBoundSignature::UserTokenOverNone
                            : ChannelBoundSignature::UserToken;
      auto me = weak_from_this();
      build_channel_bound_data_async(layout,
        *tokenPolicy,
        channelInfo,
        [me,
          tokenPolicy,
          userCertificate = std::move(userCertificate),
          signature = std::move(signature),
          callback = std::move(callback)](ByteStringResult data) mutable
        {
          auto self = me.lock();
          if (!self)
          {
            callback(make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed"));
            return;
          }
          if (!data.is_good())
          {
            callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed, data.shared_detail()},
              "The channel bound UserTokenSignature data could not be built",
              "Session"));
            return;
          }
          self->verify_user_token_signature_over_async(std::move(tokenPolicy),
            std::move(userCertificate),
            std::move(data).value(),
            std::move(signature),
            std::move(callback));
        });
      return;
    }

    // Legacy (Table 102): ServerCertificate | ServerNonce, with the algorithm the token policy names.
    if (asr.user_token_signature().algorithm() != tokenPolicy->asymmetric_signature_algorithm_uri())
    {
      // The user-token proof-of-possession signature is invalid (wrong algorithm) => Part 4 7.41 /
      // ActivateSession requires BadUserSignatureInvalid, not the generic BadSecurityChecksFailed.
      callback(make_authn_failure(StatusCode{Status::BadUserSignatureInvalid},
        "User token signature algorithm does not match security policy"));
      return;
    }

    ByteString dataToVerify = mSelectedServerCertAndKey.certificate->der_encoding();
    std::ranges::copy(mServerNonce, std::back_inserter(dataToVerify));
    verify_user_token_signature_over_async(std::move(tokenPolicy),
      std::move(userCertificate),
      std::move(dataToVerify),
      std::move(signature),
      std::move(callback));
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(make_authn_failure(er, "Exception during user token signature verification", "Session"));
  }
}

void Session::verify_user_token_signature_over_async(shared_ptr<SecurityPolicy> tokenPolicy,
  shared_ptr<const X509Certificate> userCertificate, ByteString dataToVerify, ByteString signature,
  std::function<void(OptionalAuthnFailure)> callback)
{
  try
  {
    auto deps = mDependencies.lock();
    auto crypto = deps ? deps->crypto() : nullptr;
    if (!crypto || !userCertificate)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "Crypto provider or user certificate unavailable for user token signature verification"));
      return;
    }

    auto me = weak_from_this();
    auto pinned = std::make_shared<const PinnedSignatureCheck>(
      PinnedSignatureCheck{std::move(dataToVerify), std::move(signature), userCertificate->public_key()});
    crypto->asymmetric_verify_async(pinned,
      tokenPolicy->asymmetric_signature_algorithm(),
      pinned->publicKey,
      pinned->data,
      pinned->signature,
      [me, callback = std::move(callback)](VoidResult result) mutable
      {
        auto self = me.lock();
        if (!self)
        {
          callback(make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed"));
          return;
        }
        boost::asio::post(self->mStrand,
          ua::async::guarded(self->mLogger,
            [callback = std::move(callback), result = std::move(result)]() mutable
            {
              if (result.is_bad())
              {
                // A failed proof-of-possession verification is reported as BadUserSignatureInvalid
                // (Part 4 7.41 / ActivateSession), not the raw crypto status (e.g.
                // BadSecurityChecksFailed). The underlying status is preserved in the cause chain.
                callback(
                  make_authn_failure(StatusCode{Status::BadUserSignatureInvalid, result.shared_detail()},
                    "Asymmetric verification of X509 user token signature failed",
                    "Session"));
                return;
              }
              callback(std::nullopt);
            }));
      });
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(make_authn_failure(er, "Exception during user token signature verification", "Session"));
  }
}

void Session::verify_client_application_signature_async(ActivateSessionRequest& asr,
  const SecureChannelInfo& channelInfo, std::function<void(OptionalAuthnFailure)> callback)
{
  try
  {
    // Part 4 5.6.3.1: The Client shall prove that it is the same application that called CreateSession
    // by signing (serverCertificate || serverNonce) with the private key of its application instance cert.

    // Skip verification for unauthenticated channels (Part 4 5.5.2).
    if (!channelInfo.security_policy()->is_authenticated())
    {
      callback(std::nullopt);
      return;
    }

    // On an authenticated channel, the client signature is mandatory.
    if (asr.client_signature().signature().empty())
    {
      callback(make_authn_failure(StatusCode{Status::BadApplicationSignatureInvalid},
        "Client application instance signature is missing on authenticated channel"));
      return;
    }

    // Client must have provided a certificate during CreateSession on an authenticated channel.
    if (!mClientCertificate)
    {
      callback(make_authn_failure(StatusCode{Status::BadApplicationSignatureInvalid},
        "No client certificate available for application signature verification"));
      return;
    }

    auto deps = mDependencies.lock();
    if (!deps)
    {
      callback(make_authn_failure(StatusCode{Status::BadInternalError},
        "Session dependencies expired during client application signature verification"));
      return;
    }

    auto crypto = deps->crypto();
    if (!crypto)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "Crypto provider unavailable for client application signature verification"));
      return;
    }

    auto policyId = channelInfo.security_policy()->id();
    auto policy = SecurityPolicy::create(policyId);
    ByteString signature = asr.client_signature().signature();

    // OPC 10000-4 section 6.1.8: a policy with SecureChannelEnhancements binds the ClientSignature to the
    // SecureChannel it arrives on (Table 101); the algorithm URI is empty for such a policy, and a received
    // one is ignored (Table 174).
    if (policy->secure_channel_enhancements())
    {
      auto me = weak_from_this();
      build_channel_bound_data_async(ChannelBoundSignature::Client,
        *policy,
        channelInfo,
        [me, policy, signature = std::move(signature), callback = std::move(callback)](
          ByteStringResult data) mutable
        {
          auto self = me.lock();
          if (!self)
          {
            callback(make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed"));
            return;
          }
          if (!data.is_good())
          {
            callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed, data.shared_detail()},
              "The channel bound ClientSignature data could not be built",
              "Session"));
            return;
          }
          self->verify_client_application_signature_over_async(
            std::move(policy), std::move(data).value(), std::move(signature), std::move(callback));
        });
      return;
    }

    // Legacy (Table 102): ServerCertificate | ServerNonce, with the algorithm the policy names.
    auto certAndKey = stack_utils::get_local_cert_and_keys(mServerCertificates, policyId);
    if (!certAndKey.certificate)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "No server certificate available for client application signature verification"));
      return;
    }

    if (asr.client_signature().algorithm() != policy->asymmetric_signature_algorithm_uri())
    {
      callback(make_authn_failure(StatusCode{Status::BadApplicationSignatureInvalid},
        "Client signature algorithm does not match security policy"));
      return;
    }

    ByteString dataToVerify = certAndKey.certificate->der_encoding();
    std::ranges::copy(mServerNonce, std::back_inserter(dataToVerify));
    verify_client_application_signature_over_async(
      std::move(policy), std::move(dataToVerify), std::move(signature), std::move(callback));
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(make_authn_failure(er, "Exception during client application signature verification", "Session"));
  }
}

void Session::verify_client_application_signature_over_async(shared_ptr<SecurityPolicy> policy,
  ByteString dataToVerify, ByteString signature, std::function<void(OptionalAuthnFailure)> callback)
{
  try
  {
    auto deps = mDependencies.lock();
    auto crypto = deps ? deps->crypto() : nullptr;
    if (!crypto || !mClientCertificate)
    {
      callback(make_authn_failure(StatusCode{Status::BadSecurityChecksFailed},
        "Crypto provider or client certificate unavailable for client application signature verification"));
      return;
    }

    auto me = weak_from_this();
    auto pinned = std::make_shared<const PinnedSignatureCheck>(
      PinnedSignatureCheck{std::move(dataToVerify), std::move(signature), mClientCertificate->public_key()});
    crypto->asymmetric_verify_async(pinned,
      policy->asymmetric_signature_algorithm(),
      pinned->publicKey,
      pinned->data,
      pinned->signature,
      [me, callback = std::move(callback)](VoidResult result) mutable
      {
        auto self = me.lock();
        if (!self)
        {
          callback(make_authn_failure(StatusCode{Status::BadSessionClosed}, "Session destroyed"));
          return;
        }
        boost::asio::post(self->mStrand,
          ua::async::guarded(self->mLogger,
            [callback = std::move(callback), result = std::move(result)]() mutable
            {
              if (result.is_good())
              {
                callback(std::nullopt);
                return;
              }
              // FOLLOW-UP: spec compliance gap - Part 4 5.6.3.2 mandates "the Server shall
              // check the signature with the full chain if the check with the leaf Certificate
              // fails". This retry is currently vacuous because `CreateSessionResponse` only
              // emits the leaf via `mSelectedServerCertAndKey.mCertificate->der_encoding()`
              // (see send_create_session_response_async). If the server is ever changed to
              // emit a chain (multiple concatenated DERs) in CreateSessionResponse, the verify
              // step here MUST retry against the full chain DER before declaring failure.
              // Track under MR2 spec-compliance follow-up.
              callback(
                make_authn_failure(StatusCode{Status::BadApplicationSignatureInvalid, result.shared_detail()},
                  "Asymmetric verification of client application instance signature failed",
                  "Session"));
            }));
      });
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(make_authn_failure(er, "Exception during client application signature verification", "Session"));
  }
}

bool Session::AuthFlowIdentity::record_completion(
  AuthnResult result, std::chrono::steady_clock::time_point completedAt) const noexcept
{
  try
  {
    const std::lock_guard lock(mMutex);
    if (mCompletionRecorded)
    {
      return false;
    }
    mCompletion.emplace(TimedAuthnResult{completedAt, std::move(result)});
    mCompletionRecorded = true;
    return true;
  }
  catch (...)
  {
    return false;
  }
}

std::optional<Session::TimedAuthnResult> Session::AuthFlowIdentity::take_completion() const noexcept
{
  try
  {
    const std::lock_guard lock(mMutex);
    if (!mCompletion)
    {
      return std::nullopt;
    }
    auto result = std::move(mCompletion);
    mCompletion.reset();
    return result;
  }
  catch (...)
  {
    return std::nullopt;
  }
}

bool Session::authentication_completed_by(
  std::chrono::steady_clock::time_point completedAt, std::chrono::steady_clock::time_point deadline) noexcept
{
  return completedAt <= deadline;
}

void Session::authenticate_async(uint32_t requestId, uint32_t requestHandle,
  const SecureChannelInfo& channelInfo, std::function<void(AuthnResult)> callback)
{
  try
  {
    auto deps = mDependencies.lock();
    if (!deps)
    {
      callback(make_authn_failure(
        StatusCode{Status::BadInternalError}, "Session dependencies expired during authentication"));
      return;
    }

    auto it = mInFlightRequestsByRequestId.find(requestId);
    if (it == mInFlightRequestsByRequestId.end())
    {
      callback(make_authn_failure(StatusCode{Status::BadInternalError},
        "ActivateSession request not found in-flight for authentication"));
      return;
    }

    auto* activateSessionRequest = dynamic_cast<ActivateSessionRequest*>(it->second.get());
    if (!activateSessionRequest)
    {
      callback(make_authn_failure(StatusCode{Status::BadRequestTypeInvalid},
        "In-flight request for authentication is not an ActivateSession request"));
      return;
    }

    // Allocate per-flow state.
    mAuthState = std::make_unique<AuthState>();
    mAuthState->identity = std::make_shared<AuthFlowIdentity>();
    mAuthState->requestId = requestId;
    mAuthState->requestHandle = requestHandle;
    mAuthState->channelInfo = channelInfo;
    mAuthState->callback = std::move(callback);
    mAuthState->clientId = derive_client_id(channelInfo);

    // Authentication is session-establishment work, not service hot-path work. Hold every FAILURE
    // behind the host-configured fixed deadline so token-format and credential checks do not become
    // remotely observable timing stages (a success is answered as soon as it is known, owner decision
    // 23), and offer that same deadline to the authenticator, which it abandons when exceeded.
    const auto authenticationInterval = deps->server_configuration().authnTimeout;
    mAuthState->deadline = std::chrono::steady_clock::now() + authenticationInterval;
    const auto authenticationIdentity = mAuthState->identity;
    // The body arms the timer in its first await, so by the time it suspends `completionTimer` is
    // engaged - which is what the setup-exception path below tests to decide whether an outcome must
    // still be held behind the deadline.
    mAuthTask = run_authentication(authenticationIdentity, authenticationInterval);

    // S11: Extract claimed user ID for identity lockout checks.
    {
      auto* token = activateSessionRequest->user_identity_token().get();
      if (auto* un = dynamic_cast<UserNameIdentityToken*>(token))
      {
        mAuthState->claimedUserId = std::string{un->user_name()};
        mAuthState->throttleApplicable = true;
      }
      else if (auto* x509 = dynamic_cast<X509IdentityToken*>(token))
      {
        const auto& certData = x509->certificate_data();
        auto certHash = std::hash<std::string_view>{}(
          std::string_view{reinterpret_cast<const char*>(certData.data()), certData.size()});
        mAuthState->claimedUserId = "x509:" + std::to_string(certHash);
        mAuthState->throttleApplicable = true;
      }
    }

    // S11 / SESS-2: reserve the attempt before authentication. A locked-out client application, or
    // one whose budget of failures plus attempts in flight is spent, is refused here; an admitted
    // attempt holds its reservation until finish_authentication commits the outcome (or the flow is
    // destroyed, which releases it as Abandoned).
    if (mAuthState->throttleApplicable)
    {
      auto refusal = deps->begin_identity_attempt(*mAuthState->clientId, mAuthState->claimedUserId);
      if (refusal.has_value())
      {
        on_authenticator_completed(
          make_authn_failure(std::move(*refusal), "Identity locked out due to prior auth failures"));
        return;
      }
      mAuthState->reservation =
        IdentityAttemptReservation{mDependencies, *mAuthState->clientId, mAuthState->claimedUserId};
    }

    // Match the presented token against the user token policies of the endpoint this ActivateSession
    // arrived on. OPC 10000-4 5.6.3.2 Table 17 (userIdentityToken): "The EndpointDescription specifies
    // what UserIdentityTokens the Server shall accept", and the endpoint is the one the request's
    // SecureChannel connects to - on a re-activation over a new SecureChannel that is the new channel's
    // endpoint, the same channel whose security the token is validated against below and whose policy
    // decrypts it (security review SESS-7(d): the match used the CreateSession endpoint's list while the
    // checks used the new channel's). The list lives in `mAuthState->channelInfo`, as long as
    // `matchedPolicy`, which points into it - both belong to this flow's AuthState.
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - assigned unconditionally above.
    const auto& endpointUserTokenPolicies = mAuthState->channelInfo->user_identity_tokens();
    auto* rawToken = activateSessionRequest->user_identity_token().get();
    const bool isAnonymous =
      (rawToken == nullptr) || (dynamic_cast<AnonymousIdentityToken*>(rawToken) != nullptr);

    const UserTokenPolicy* matchedPolicy = nullptr;
    // Tracks whether the presented (non-anonymous) token's policyId names an advertised policy at
    // all - distinguishing "references an unknown policy" (an invalid token) from "names a real
    // policy of a different token type" (a well-formed token the server rejects). Consumed by the
    // !matchedPolicy branch below.
    bool presentedPolicyIdMatchedAnAdvertisedPolicy = false;
    if (isAnonymous)
    {
      for (const auto& policy : endpointUserTokenPolicies)
      {
        if (policy.token_type() == UserTokenType::Anonymous)
        {
          matchedPolicy = &policy;
          break;
        }
      }
    }
    else
    {
      auto* identityToken = dynamic_cast<UserIdentityToken*>(rawToken);
      auto presentedPolicyId =
        identityToken ? std::string_view{identityToken->policy_id()} : std::string_view{};

      UserTokenType presentedTokenType = UserTokenType::Anonymous;
      if (dynamic_cast<UserNameIdentityToken*>(rawToken))
        presentedTokenType = UserTokenType::UserName;
      else if (dynamic_cast<X509IdentityToken*>(rawToken))
        presentedTokenType = UserTokenType::Certificate;
      else if (dynamic_cast<IssuedIdentityToken*>(rawToken))
        presentedTokenType = UserTokenType::IssuedToken;

      for (const auto& policy : endpointUserTokenPolicies)
      {
        if (std::string_view{policy.policy_id()} == presentedPolicyId)
        {
          presentedPolicyIdMatchedAnAdvertisedPolicy = true;
          if (policy.token_type() == presentedTokenType)
          {
            matchedPolicy = &policy;
          }
          break;
        }
      }
    }

    if (!matchedPolicy)
    {
      // A non-anonymous token whose policyId matches NO advertised user-token policy references a
      // policy that does not exist -> the token is not valid: Bad_IdentityTokenInvalid (OPC 10000-4
      // Table 182, "the user identity token is not valid"). When the policyId IS advertised but for
      // a different token type, or an anonymous token is presented on an endpoint that does not
      // advertise anonymous, the token is well-formed and the server simply rejects it
      // (Bad_IdentityTokenRejected). CTT Security User Name Password/009 requires Invalid for a
      // garbage policyId.
      const auto rejectionStatus = (!isAnonymous && !presentedPolicyIdMatchedAnAdvertisedPolicy)
                                     ? Status::BadIdentityTokenInvalid
                                     : Status::BadIdentityTokenRejected;
      on_authenticator_completed(make_authn_failure(
        StatusCode{rejectionStatus}, "Presented token does not match any endpoint user token policy"));
      return;
    }

    // Runtime guard.
    {
      auto guardResult = validate_user_token_policy(
        *matchedPolicy, channelInfo.security_policy()->id(), channelInfo.message_security_mode());
      if (guardResult.is_bad())
      {
        auto refusal = guardResult.status_code();
        // SVR-SCE-010: an X509 token whose policy has SecureChannelEnhancements, presented over a secured
        // channel without them, is a token that cannot verify (no ChannelThumbprint to sign), answered as
        // Bad_IdentityTokenInvalid; the rule's own status is what refuses such a policy when the server
        // starts.
        const auto& detail = refusal.shared_detail();
        if (detail && detail->code == "EnhancedTokenPolicyOverLegacyChannel")
        {
          refusal = StatusCode{Status::BadIdentityTokenInvalid,
            ErrorDetail::build("UserTokenSignatureCannotBeChannelBound",
              "The X509 token policy needs a SecureChannel with SecureChannelEnhancements",
              "Session")
              .cause(std::move(refusal))};
        }
        on_authenticator_completed(
          make_authn_failure(std::move(refusal), "Token policy security check failed", "Session"));
        return;
      }
    }

    mAuthState->matchedPolicy = matchedPolicy;
    auto endpointSecurity = std::make_shared<EndpointSecurityContext>();
    endpointSecurity->endpointPolicyId = channelInfo.endpoint_policy_id();
    endpointSecurity->messageSecurityMode = channelInfo.message_security_mode();
    endpointSecurity->securityPolicyId = channelInfo.security_policy()->id();
    endpointSecurity->userTokenPolicyId = std::string{matchedPolicy->policy_id()};
    endpointSecurity->clientApplicationUri = mClientApplicationUri;
    endpointSecurity->endpointUrl = String{channelInfo.endpoint_url()};
    endpointSecurity->transportProfileUri = String{channelInfo.transport_profile_uri()};
    mAuthState->endpointSecurity = std::move(endpointSecurity);

    // No authenticator configured: short-circuit per pre-flip behaviour.
    if (!deps->components().authenticator)
    {
      mAuthState->recordOutcome = true;
      AuthnResult res =
        make_authn_failure(StatusCode{Status::BadUserAccessDenied}, "No authenticator configured on server");
      on_authenticator_completed(std::move(res));
      return;
    }

    // The policy guard above validates the CONFIGURATION - a policy that would permit a cleartext
    // secret on a channel that does not encrypt. It never sees the presented token, so it cannot catch
    // a client that simply omits the encryption the matched policy requires. Part 4 section 7.41.4 Table 193
    // makes the encryption a property of the matched UserTokenPolicy, not of a field the client
    // chooses: a Server that reads `encryptionAlgorithm` to decide WHETHER protection applies has let
    // the attacker decide it. Checking the presented token against the policy is what closes that.
    //
    // Placed after the no-authenticator short-circuit deliberately. Both paths refuse, so the ordering
    // changes only which code the client is told; a Server with no authenticator authenticates nobody,
    // and reporting that is more use to an operator than reporting a token defect on a Server that
    // would have refused the token however it was encrypted.
    if (rawToken != nullptr)
    {
      auto presentedResult = validate_presented_user_token(
        *matchedPolicy, channelInfo.security_policy()->id(), channelInfo.message_security_mode(), *rawToken);
      if (presentedResult.is_bad())
      {
        on_authenticator_completed(make_authn_failure(presentedResult.status_code(),
          "Presented user identity token is not encrypted as its token policy requires",
          "Session"));
        return;
      }
    }

    // Begin the auth pipeline: verify client application signature.
    mAuthState->recordOutcome = true;
    auto me = weak_from_this();
    verify_client_application_signature_async(*activateSessionRequest,
      // channelInfo is set unconditionally at AuthState creation (make_unique<AuthState>() then
      // `mAuthState->channelInfo = channelInfo`), so it is always engaged on this path.
      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      *mAuthState->channelInfo,
      [me, authenticationIdentity](OptionalAuthnFailure failure) mutable
      {
        auto lockedSelf = me.lock();
        if (!lockedSelf)
          return;
        ua::async::post_borrowing(lockedSelf.get(),
          lockedSelf->mStrand,
          lockedSelf->mLogger,
          [authenticationIdentity, failure = std::move(failure)](Session& self) mutable
          {
            if (self.mAuthState && self.mAuthState->identity == authenticationIdentity)
              self.on_client_application_signature_verified(std::move(failure));
          })();
      });
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    if (mAuthState)
    {
      auto failure = make_authn_failure(er, "Exception during authenticate_async setup", "Session");
      if (mAuthState->completionTimer)
        on_authenticator_completed(std::move(failure));
      else
        finish_authentication(std::move(failure));
    }
    else
    {
      callback(make_authn_failure(er, "Exception during authenticate_async setup", "Session"));
    }
  }
}

void Session::on_client_application_signature_verified(OptionalAuthnFailure failure)
{
  if (!mAuthState)
    return;
  if (failure)
  {
    on_authenticator_completed(std::move(*failure));
    return;
  }

  auto it = mInFlightRequestsByRequestId.find(mAuthState->requestId);
  if (it == mInFlightRequestsByRequestId.end())
  {
    on_authenticator_completed(make_authn_failure(StatusCode{Status::BadInternalError},
      "ActivateSession request disappeared mid-pipeline (after client app sig verify)"));
    return;
  }
  auto* asr = dynamic_cast<ActivateSessionRequest*>(it->second.get());
  if (!asr)
  {
    on_authenticator_completed(make_authn_failure(
      StatusCode{Status::BadRequestTypeInvalid}, "In-flight request changed type mid-pipeline"));
    return;
  }

  auto me = weak_from_this();
  const auto authenticationIdentity = mAuthState->identity;
  parse_identity_token_async(mAuthState->requestHandle,
    *asr,
    [me, authenticationIdentity](ParsedIdentityTokenResult parsedResult) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
        return;
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [authenticationIdentity, parsedResult = std::move(parsedResult)](Session& self) mutable
        {
          AuthStageContinuationForTests continuation =
            [authenticationIdentity, parsedResult = std::move(parsedResult)](Session& target) mutable
          {
            if (target.mAuthState && target.mAuthState->identity == authenticationIdentity)
              target.on_identity_token_parsed(std::move(parsedResult));
          };
          if (self.mParsedIdentityCompletionGateForTests)
            self.mParsedIdentityCompletionGateForTests(self, std::move(continuation));
          else
            continuation(self);
        })();
    });
}

void Session::on_identity_token_parsed(ParsedIdentityTokenResult parsedResult)
{
  if (!mAuthState)
    return;
  if (!parsedResult.is_good())
  {
    on_authenticator_completed(
      make_authn_failure(parsedResult.status_code(), "parse_identity_token_async failed", "Session"));
    return;
  }
  auto parsed = std::move(parsedResult).value();
  parsed.tokenSecurityPolicyUri = std::string{mAuthState->matchedPolicy->security_policy_uri()};

  if (parsed.failure)
  {
    on_authenticator_completed(std::move(*parsed.failure));
    return;
  }

  mAuthState->parsed = std::move(parsed);
  if (mAuthState->parsed.request.identity.kind == UserTokenKind::X509)
  {
    // An X509 user token certificate is validated BEFORE its userTokenSignature is verified (owner decision
    // 2026-10-03, BR-16): no key the token policy refuses is used to verify anything, and a refused
    // certificate is reported with its own cause.
    begin_user_token_certificate_validation();
    return;
  }
  begin_user_token_signature_verification();
}

void Session::begin_user_token_signature_verification()
{
  if (!mAuthState)
    return;
  auto it = mInFlightRequestsByRequestId.find(mAuthState->requestId);
  if (it == mInFlightRequestsByRequestId.end())
  {
    on_authenticator_completed(make_authn_failure(StatusCode{Status::BadInternalError},
      "ActivateSession request disappeared mid-pipeline (after parse_identity_token)"));
    return;
  }
  auto* asr = dynamic_cast<ActivateSessionRequest*>(it->second.get());
  if (!asr)
  {
    on_authenticator_completed(make_authn_failure(
      StatusCode{Status::BadRequestTypeInvalid}, "In-flight request changed type mid-pipeline"));
    return;
  }

  auto me = weak_from_this();
  const auto authenticationIdentity = mAuthState->identity;
  verify_user_token_signature_async(*asr,
    mAuthState->parsed,
    // channelInfo is set unconditionally at AuthState creation, so it is always engaged here.
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    *mAuthState->channelInfo,
    [me, authenticationIdentity](OptionalAuthnFailure failure) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
        return;
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [authenticationIdentity, failure = std::move(failure)](Session& self) mutable
        {
          AuthStageContinuationForTests continuation = [authenticationIdentity, failure = std::move(failure)](
                                                         Session& target) mutable
          {
            if (target.mAuthState && target.mAuthState->identity == authenticationIdentity)
              target.on_user_token_signature_verified(std::move(failure));
          };
          if (self.mUserTokenSignatureCompletionGateForTests)
            self.mUserTokenSignatureCompletionGateForTests(self, std::move(continuation));
          else
            continuation(self);
        })();
    });
}

void Session::on_user_token_signature_verified(OptionalAuthnFailure failure)
{
  if (!mAuthState)
    return;
  if (failure)
  {
    on_authenticator_completed(std::move(*failure));
    return;
  }

  start_authenticator();
}

void Session::begin_user_token_certificate_validation()
{
  if (!mAuthState)
    return;
  // An X509 user token certificate is validated by the session BEFORE any authenticator (owner review
  // 2026-10-02, item 8): the chain-parsed field, Table 44 use, the user-token policy's SecurityPolicy, the
  // user-token store. A refusal never reaches the authenticator and is an authentication failure (counted
  // toward the lockout like any other).
  auto deps = mDependencies.lock();
  if (!deps)
  {
    on_authenticator_completed(
      make_authn_failure(StatusCode{Status::BadInternalError}, "Session dependencies expired"));
    return;
  }
  SecurityPolicyId tokenPolicyId = SecurityPolicyId::Invalid;
  if (!mAuthState->parsed.tokenSecurityPolicyUri.empty())
  {
    tokenPolicyId = utils::get_security_policy_id(mAuthState->parsed.tokenSecurityPolicyUri);
  }
  else if (const auto& tokenChannel = mAuthState->channelInfo;
           tokenChannel && tokenChannel.value().security_policy())
  {
    tokenPolicyId = tokenChannel.value().security_policy()->id();
  }
  std::shared_ptr<const SecurityPolicy> tokenPolicy;
  if (tokenPolicyId != SecurityPolicyId::Invalid)
  {
    tokenPolicy = SecurityPolicy::create(tokenPolicyId);
  }
  mActivatingUserTokenCertificateField = mAuthState->parsed.x509CertificateField;
  mActivatingUserTokenPolicy = tokenPolicy;
  auto me = weak_from_this();
  const auto authenticationIdentity = mAuthState->identity;
  server::detail::validate_user_token_certificate_async(deps->user_token_certificate_store(),
    deps->crypto(),
    mAuthState->parsed.x509CertificateField,
    std::move(tokenPolicy),
    [me, authenticationIdentity](VoidResult validation) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
        return;
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [authenticationIdentity, validation = std::move(validation)](Session& self) mutable
        {
          if (self.mAuthState && self.mAuthState->identity == authenticationIdentity)
            self.on_user_token_certificate_validated(std::move(validation));
        })();
    });
}

void Session::on_user_token_certificate_validated(VoidResult validation)
{
  if (!mAuthState)
    return;
  if (!validation.is_good())
  {
    // Decision 27: the refused user certificate is reported with its Table 106 fault.
    if (auto deps = mDependencies.lock())
    {
      CertificateEventInfo info;
      if (const auto& tokenChannel = mAuthState->channelInfo; tokenChannel)
      {
        info.remoteAddress = tokenChannel.value().remote_address();
      }
      const auto& identity = mAuthState->parsed.request.identity;
      info.certificate = identity.x509Certificate ? *identity.x509Certificate : nullptr;
      const auto refusal = validation.shared_detail();
      info.status = refusal && refusal->innerStatus != utils::to_underlying(Status::Good)
                      ? StatusCode{refusal->innerStatus}
                      : validation.status_code();
      auto observer = deps->observer();
      detail::emit_event(deps->logger(), observer, [&] { observer->on_certificate_rejected(info); });
    }
    mActivatingUserTokenCertificateField = ByteString{};
    mActivatingUserTokenPolicy = nullptr;
    on_authenticator_completed(AuthnResult{validation.status_code()});
    return;
  }
  // OPC 10000-4 section 6.1.3: a user certificate accepted with suppressed errors is reported (item 9).
  if (auto suppressed = ::ua::detail::suppressed_certificate_errors(validation); !suppressed.empty())
  {
    if (auto deps = mDependencies.lock())
    {
      const auto& identity = mAuthState->parsed.request.identity;
      const auto certificate = identity.x509Certificate ? *identity.x509Certificate : nullptr;
      const auto& tokenChannel = mAuthState->channelInfo;
      const std::string remoteAddress = tokenChannel ? tokenChannel.value().remote_address() : std::string{};
      auto observer = deps->observer();
      detail::emit_event(deps->logger(),
        observer,
        [&]
        { detail::report_suppressed_certificate_errors(observer, remoteAddress, certificate, suppressed); });
    }
  }
  begin_user_token_signature_verification();
}

void Session::start_authenticator()
{
  if (!mAuthState)
    return;

  // Invoke the application authenticator. The authenticator hop is the cross-strand-most
  // callback in the SDK - applications register their own auth hooks that may run on
  // arbitrary executors, so we must explicitly dispatch back to the session strand.
  auto deps = mDependencies.lock();
  if (!deps)
  {
    on_authenticator_completed(
      make_authn_failure(StatusCode{Status::BadInternalError}, "Session dependencies expired"));
    return;
  }

  auto me = weak_from_this();
  // Move the parsed request out of the flow into the authenticator call.
  AuthnRequest authnReq = std::move(mAuthState->parsed.request);
  authnReq.security = mAuthState->endpointSecurity;
  authnReq.deadline = mAuthState->deadline;
  // Offered every time rather than captured once, so a store swapped in by push-certificate
  // management is the one the next activation validates against.
  authnReq.userTokenCertificateStore = deps->user_token_certificate_store();
  // Retained so the identity can be re-checked if the user-token trust list later changes
  // (Part 12 7.10.6). Null for every other token kind, which overwrites any certificate left by a
  // previous activation of this session.
  mActivatingUserTokenCertificate =
    authnReq.identity.kind == UserTokenKind::X509 && authnReq.identity.x509Certificate
      ? *authnReq.identity.x509Certificate
      : nullptr;
  const auto authenticationIdentity = mAuthState->identity;
  deps->components().authenticator->authenticate_async(std::move(authnReq),

    [me, authenticationIdentity](AuthnResult result) mutable
    {
      const auto completedAt = std::chrono::steady_clock::now();
      if (!authenticationIdentity->record_completion(std::move(result), completedAt))
      {
        return;
      }
      auto lockedSelf = me.lock();
      if (!lockedSelf)
        return;
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [authenticationIdentity](Session& self)
        {
          AuthStageContinuationForTests continuation = [authenticationIdentity](Session& target)
          {
            target.on_authenticator_completion_available(authenticationIdentity);
          };
          if (self.mAuthenticatorCompletionNotificationGateForTests)
          {
            self.mAuthenticatorCompletionNotificationGateForTests(self, std::move(continuation));
          }
          else
          {
            continuation(self);
          }
        })();
    });
}

void Session::on_authenticator_completed(AuthnResult result)
{
  if (!mAuthState)
    return;
  const auto identity = mAuthState->identity;
  if (!identity->record_completion(std::move(result), std::chrono::steady_clock::now()))
    return;
  on_authenticator_completion_available(identity);
}

void Session::on_authenticator_completion_available(const std::shared_ptr<const AuthFlowIdentity>& identity)
{
  if (!mAuthState || mAuthState->identity != identity || mAuthState->pendingResult)
    return;

  auto completion = identity->take_completion();
  if (!completion)
    return;
  if (!authentication_completed_by(completion->completedAt, mAuthState->deadline))
  {
    finish_authentication(make_authn_failure(StatusCode{Status::BadIdentityTokenInvalid,
                                               make_error_detail("AuthenticationDeadlineExceeded",
                                                 "Authenticator completed after its configured deadline",
                                                 "Session")},
      "Authenticator completed after its configured deadline"));
    return;
  }

  AuthnResult answer = std::move(completion->result);
  if (answer.is_uncertain())
  {
    // The SDK activates a Session only on an identity the authenticator answered Good: an Uncertain answer,
    // whether or not it holds an AuthnSuccess, is a failed attempt.
    answer = make_authn_failure(server::detail::uncertain_answer_refused(
                                  server::detail::answerUncertain, answer.status_code(), "Session"),
      "The authenticator answered Uncertain");
  }
  mAuthState->pendingResult.emplace(std::move(answer));
  // SESS-2: the attempt's outcome is known now; its reservation against the lockout budget is released
  // here, not at the end of the constant-time hold, so a valid activation holds a budget slot only for
  // the authenticator's latency while a wrong guess is counted before its client hears the answer.
  if (mAuthState->recordOutcome && mAuthState->throttleApplicable)
  {
    try
    {
      mAuthState->reservation.commit(mAuthState->pendingResult->is_bad()
                                       ? SessionDependencies::IdentityAttemptOutcome::Failure
                                       : SessionDependencies::IdentityAttemptOutcome::Success);
    }
    catch (...)
    {
      log_exception(mLogger,
        "Session::on_authenticator_completion_available lockout bookkeeping",
        std::current_exception());
    }
  }

  // Owner decision 23 (Part 4 5.6.3.1: "Sporadic failures shall not delay connections with valid
  // tokens"): a success is answered now; every failure stays buffered until the fixed deadline, so the
  // stage at which a token failed is not remotely observable. finish_authentication releases the
  // deadline timer, whose body then finds no flow and returns.
  if (!mAuthState->pendingResult->is_bad())
  {
    auto success = std::move(*mAuthState->pendingResult);
    finish_authentication(std::move(success));
  }
}

/// Holds every authentication FAILURE behind the host-configured deadline (owner decision 23).
///
/// There is no race to resolve here and no `when_any` needed: the authenticator never completes this
/// operation. It records into the shared @ref AuthFlowIdentity, and
/// @ref on_authenticator_completion_available BUFFERS a failure into `pendingResult`; the deadline is
/// the only thing that delivers it. That is what stops token-format, credential and certificate checks
/// becoming remotely observable timing stages, so the single structural rule for this body is: **no
/// failure answers before the await.** A success is delivered by
/// @ref on_authenticator_completion_available as soon as it is known; the timer is then released and
/// this body returns without answering. A flow still pending at the deadline (a slow authenticator) is
/// abandoned with Bad_IdentityTokenInvalid.
ua::async::Task<> Session::run_authentication(
  std::shared_ptr<const AuthFlowIdentity> identity, std::chrono::milliseconds authenticationInterval)
{
  try
  {
    auto error = co_await await_step<boost::system::error_code>(
      [this, authenticationInterval](auto completion)
      {
        mAuthState->completionTimer =
          Timer::schedule_after(mStrand, authenticationInterval, std::move(completion));
      });

    if (error || !mAuthState || mAuthState->identity != identity)
      co_return;

    on_authenticator_completion_available(identity);
    if (!mAuthState || mAuthState->identity != identity)
      co_return;
    if (auto& pendingResult = mAuthState->pendingResult; pendingResult)
    {
      finish_authentication(std::move(pendingResult.value()));
      co_return;
    }
    finish_authentication(make_authn_failure(StatusCode{Status::BadIdentityTokenInvalid,
                                               make_error_detail("AuthenticationDeadlineExceeded",
                                                 "Authenticator did not complete by its configured deadline",
                                                 "Session")},
      "Authenticator did not complete by its configured deadline"));
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    if (mAuthState)
    {
      finish_authentication(make_authn_failure(::ua::exception_to_status_code(std::current_exception()),
        "Exception while holding the authentication deadline",
        "Session"));
    }
  }
  co_return;
}

void Session::finish_authentication(AuthnResult result)
{
  if (!mAuthState)
    return;

  auto flow = std::move(mAuthState);
  flow->completionTimer = {};
  auto callback = std::move(flow->callback);
  auto dependencies = mDependencies.lock();

  if (!result.is_good())
  {
    mAuthnUserByRequestId.erase(flow->requestId);
    mAuthnEndpointByRequestId.erase(flow->requestId);
  }
  else
  {
    try
    {
      if (!flow->endpointSecurity)
      {
        throw UaException{Status::BadInternalError,
          ErrorDetail::build("EndpointSecurityContextMissing",
            "Authentication completed without its matched endpoint security context",
            "Session")};
      }
      if (mAuthnUserInsertFailureInjectorForTests)
        mAuthnUserInsertFailureInjectorForTests();
      mAuthnUserByRequestId[flow->requestId] = result.value().user;
      mAuthnEndpointByRequestId[flow->requestId] = flow->endpointSecurity;
    }
    catch (...)
    {
      mAuthnUserByRequestId.erase(flow->requestId);
      mAuthnEndpointByRequestId.erase(flow->requestId);
      auto exception = std::current_exception();
      log_exception(mLogger, "Session::finish_authentication identity-state update", exception);
      result = make_authn_failure(::ua::exception_to_status_code(std::move(exception)),
        "Exception while storing the authenticated user",
        "Session");
    }
  }

  if (flow->recordOutcome && flow->throttleApplicable)
  {
    // The reservation taken at flow start is committed with the outcome. When the outcome is not to
    // be recorded, the reservation goes out with the flow, released as Abandoned.
    try
    {
      flow->reservation.commit(!result.is_good() ? SessionDependencies::IdentityAttemptOutcome::Failure
                                                 : SessionDependencies::IdentityAttemptOutcome::Success);
    }
    catch (...)
    {
      log_exception(mLogger, "Session::finish_authentication lockout bookkeeping", std::current_exception());
    }
  }

  callback(std::move(result));
}

void Session::enqueue_response(Response response)
{
  // Memory backstop: a detached session must not buffer undeliverable responses without limit. The
  // queue is normally bounded by the per-session in-flight cap; if it is not (a dead/abandoned
  // session), drop the oldest buffered response so the working set stays bounded.
  if (mResponseMessages.size() >= mMaxBufferedResponses)
  {
    mResponseMessages.pop();  // drop-oldest
    if (auto deps = mDependencies.lock())
    {
      deps->logger().with_category("session").warning(
        {{"session_name", std::string_view{mSessionName}}, {"cap", std::to_string(mMaxBufferedResponses)}},
        "Buffered-response cap exceeded; dropped oldest undelivered response");
    }
  }
  mResponseMessages.push(std::move(response));
}

void Session::discard_buffered_responses()
{
  try
  {
    // Responses buffered while the session was channelless carry requestIds scoped to the OLD
    // secure channel (Part 6: requestId is per-SecureChannel). On reconnect the session attaches to
    // a NEW SecureChannel, so those requestIds are undeliverable there  -  the client drops any
    // response whose requestId it never issued on the new channel (Part 4 6.7). Replaying them is
    // therefore futile; the client recovers by re-issuing normal requests (which it already failed
    // with BadConnectionClosed when the channel dropped) and via Republish for subscriptions
    // (Part 4 5.13.5). Discard the buffer instead of re-sending it. The enqueue_response cap still
    // bounds memory during the channelless window; nothing is sent here, so no response sink or
    // user callback is invoked. Runs on mStrand.
    const size_t discardedCount = mResponseMessages.size();
    std::queue<Response> empty;
    mResponseMessages.swap(empty);

    if (discardedCount > 0)
    {
      if (auto deps = mDependencies.lock())
      {
        deps->logger().with_category("session").warning(
          {{"session_name", std::string_view{mSessionName}},
            {"discarded_count", std::to_string(discardedCount)}},
          "Discarded buffered responses on reconnect (channel-scoped requestIds are invalid on the "
          "new SecureChannel; client recovers via re-request / Republish)");
      }
    }
  }
  catch (...)
  {
    handle_unexpected_exception("Session::discard_buffered_responses", std::current_exception());
  }
}

void Session::send_activate_session_response_async(
  uint32_t requestId, std::function<void(VoidResult)> callback)
{
  try
  {
    // Apply deferred channel reassociation now that the logic has approved activation.
    if (mPendingSecureChannelInfo)
    {
      auto oldSc = mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr;
      auto newSc = mPendingSecureChannelInfo->secure_channel().lock();
      const bool isDifferentChannel = newSc && (!oldSc || oldSc.get() != newSc.get());

      // Transfer the deferred channel into the live slot and disengage the pending optional in one
      // step. std::optional's move-assignment leaves the source *engaged* (only the contained
      // SecureChannelInfo is moved-from), so std::exchange(..., std::nullopt) both moves the value
      // out and resets the source to empty without separately touching a moved-from object.
      mSecureChannelInfo = std::exchange(mPendingSecureChannelInfo, std::nullopt);
      if (mClientCertificate && mSecureChannelInfo)
      {
        // The new channel presented the same certificate (checked at activation); its issuers and
        // policy are the ones a re-evaluation now validates under.
        mClientIssuerCertificates = mSecureChannelInfo->client_issuer_certificates();
        mClientCertificatePolicy = mSecureChannelInfo->security_policy();
      }

      if (isDifferentChannel && newSc)
      {
        invalidate_post_response_actions_on_strand(oldSc);
        abandon_old_channel_requests(requestId);

        auto me = weak_from_this();
        newSc->register_session(
          mAuthenticationToken,
          // mSecureChannelInfo was just populated from the engaged mPendingSecureChannelInfo via
          // std::exchange under the `if (mPendingSecureChannelInfo)` guard above; always engaged here.
          // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
          [me,
            scWeak = mSecureChannelInfo->secure_channel(),
            associationEpoch = mSecureChannelAssociationEpoch](Request request)
          {
            auto session = me.lock();
            if (session)
            {
              ua::async::post_borrowing(session.get(),
                session->mStrand,
                session->mLogger,
                [associationEpoch, scWeak, request](Session& s)
                {
                  try
                  {
                    s.request_received_from_secure_channel_if_current(associationEpoch, scWeak, request);
                  }
                  catch (...)
                  {
                    s.handle_unexpected_exception("Session::request_received", std::current_exception());
                  }
                })();
              return;
            }
            if (auto sc = scWeak.lock())
            {
              sc->send_response_message(std::make_pair(std::get<uint32_t>(request),
                stack_utils::create_service_fault(nullptr, Status::BadSessionIdInvalid)));
            }
          },
          [me,
            reportingChannel = mSecureChannelInfo->secure_channel(),
            associationEpoch = mSecureChannelAssociationEpoch](
            StatusCode status, shared_ptr<const ErrorDetail> detail)
          {
            auto session = me.lock();
            if (session)
            {
              ua::async::post_borrowing(session.get(),
                session->mStrand,
                session->mLogger,
                [associationEpoch, reportingChannel, status, detail = std::move(detail)](Session& s)
                {
                  try
                  {
                    s.error_received_from_secure_channel_if_current(
                      associationEpoch, reportingChannel, status, detail);
                  }
                  catch (...)
                  {
                    s.handle_unexpected_exception(
                      "Session::error_received_from_secure_channel", std::current_exception());
                  }
                })();
            }
          });

        if (oldSc)
        {
          // The session moved to newSc; a request arriving on the old channel must now be rejected
          // with Bad_SecureChannelIdInvalid (Part 4 5.6.3), not Bad_SessionIdInvalid.
          oldSc->mark_session_transferred_away(mAuthenticationToken);
          oldSc->unregister_session(mAuthenticationToken);
        }
      }

      // mSecureChannelInfo was just populated from the engaged mPendingSecureChannelInfo via
      // std::exchange under the guard above; always engaged here.
      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      mCloseEventChannelId = mSecureChannelInfo->channel_id();
      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      mCloseEventRemoteAddress = mSecureChannelInfo->remote_address();

      // Discard any responses buffered while the session was channelless. Their requestIds are
      // scoped to the OLD secure channel (Part 6), so they are undeliverable on the channel just
      // attached  -  the client would drop a response whose requestId it never issued on the new
      // channel (Part 4 6.7). Re-sending them is futile; the client recovers by re-issuing normal
      // requests and via Republish for subscriptions (Part 4 5.13.5). Discard here rather than
      // replay.
      discard_buffered_responses();
    }

    auto deps = mDependencies.lock();
    if (!deps)
    {
      callback(VoidResult{Status::BadInternalError,
        make_error_detail("DepsExpired", "Session dependencies expired", "Session")});
      return;
    }

    auto it = mInFlightRequestsByRequestId.find(requestId);
    if (it == mInFlightRequestsByRequestId.end())
    {
      std::shared_ptr<const ErrorDetail> detail =
        make_error_detail("RequestNotFound", "ActivateSession request not in-flight", "Session");
      create_and_send_service_fault(requestId, Status::BadInternalError, detail);
      callback(VoidResult{Status::BadInternalError, std::move(detail)});
      return;
    }

    auto* activateSessionRequest = dynamic_cast<ActivateSessionRequest*>(it->second.get());
    if (!activateSessionRequest)
    {
      std::shared_ptr<const ErrorDetail> detail =
        make_error_detail("RequestTypeInvalid", "In-flight request is not ActivateSession", "Session");
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid, detail);
      callback(VoidResult{Status::BadRequestTypeInvalid, std::move(detail)});
      return;
    }

    // The secure channel can be torn down (transport/channel error) while the
    // ActivateSession authentication runs asynchronously. Every step below
    // dereferences mSecureChannelInfo for crypto/security details, so bail cleanly
    // if it is gone rather than dereferencing a disengaged optional (server crash).
    if (!mSecureChannelInfo)
    {
      std::shared_ptr<const ErrorDetail> detail = make_error_detail(
        "SecureChannelClosed", "Secure channel closed during ActivateSession authentication", "Session");
      callback(VoidResult{Status::BadSecureChannelClosed, std::move(detail)});
      return;
    }

    // Allocate per-request state; mirrors CreateResponseState pattern. Holding it on the
    // session closes the narrow concurrency window that lambda-captured state would
    // otherwise leave between `on_activate_authenticated` clearing `mWaitingForAuthn`
    // and the identity commit running.
    mActivateResponseState = std::make_unique<ActivateResponseState>();
    mActivateResponseState->requestId = requestId;
    mActivateResponseState->callback = std::move(callback);
    mActivateResponseState->response = make_shared<ActivateSessionResponse>();
    stack_utils::prepare_response_header(
      activateSessionRequest->request_header(), mActivateResponseState->response->response_header());

    // The response opens with a fresh server nonce. Per Part 4 5.6.3 every ActivateSession response returns
    // a new serverNonce, consumed both for SecureChannel request signing AND for UserIdentityToken
    // secret encryption. The required length therefore depends on the endpoint's user-token policies,
    // not just the channel policy: a SecurityPolicy#None channel can still carry an RSA-encrypted user
    // token, which needs a full-length (>=32) nonce. Resolve it the same way CreateSession does so a
    // re-ActivateSession (Change User) over a None channel still hands the client a valid nonce to
    // encrypt its next token against. (Was gated on the channel policy being authenticated, using the
    // channel nonce_length() - 0 for None - which left mServerNonce stale across activations on a None
    // channel and broke Change User: the client's next token encrypted with one nonce, the server
    // validating against another.)
    mActivateResponseState->nonceLength =
      numeric_cast<uint32_t>(stack_utils::resolve_nonce_length_for_endpoint(
        mSecureChannelInfo->security_policy()->id(), mSecureChannelInfo->user_identity_tokens()));

    // The body is EAGER, so it runs here, synchronously, exactly as far as the chain ran before its
    // first async call - and suspends in the same place.
    //
    // R19: the single-flight claim for this member is `mWaitingForAuthn`, taken in
    // `activate_internal` before authentication starts and held across this whole build. A second
    // ActivateSession is rejected there, so none can reach here to destroy a running frame.
    mActivateResponseTask = run_activate_response();
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    if (mActivateResponseState)
    {
      auto cb = std::move(mActivateResponseState->callback);
      mActivateResponseState.reset();
      cb(VoidResult{er, er.shared_detail()});
    }
    else
    {
      callback(VoidResult{er, er.shared_detail()});
    }
  }
}

ua::async::Task<> Session::run_activate_response()
{
  try
  {
    // --- the server nonce -----------------------------------------------------------------
    // The chain reached the ephemeral step directly when no nonce was needed (no authenticated
    // channel and no encrypted user-token policy), and it left `mServerNonce` alone in that case.
    // Both still hold.
    if (mActivateResponseState->nonceLength > 0)
    {
      auto entropyResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          auto deps = mDependencies.lock();
          if (!deps || !deps->crypto())
          {
            completion(ByteStringResult{Status::BadInternalError,
              make_error_detail("DepsExpired", "Session dependencies expired", "Session")});
            return;
          }
          deps->crypto()->get_entropy_async(mActivateResponseState->nonceLength, std::move(completion));
        });
      if (!mActivateResponseState)
        co_return;
      if (!entropyResult.is_good())
      {
        // A server nonce is taken only from a Good answer; an Uncertain one is refused, not passed on.
        const StatusCode failure = ua::security_internal::not_good_answer(
          entropyResult.status_code(), Status::BadInternalError, "Session");
        fail_activate_response(failure,
          make_error_detail("EntropyFailed",
            "Failed to generate server nonce for ActivateSession response",
            "Session",
            failure.shared_detail()));
        co_return;
      }
      if (!entropyResult.value().empty())
      {
        mServerNonce = std::move(entropyResult).value();
        mActivateResponseState->response->server_nonce() = mServerNonce;
      }
    }

    // --- the ECC ephemeral key, and the server signature over it --------------------------
    if (mEccUserTokenPolicyId != SecurityPolicyId::Invalid)
    {
      // The signing inputs are confirmed before the pair is generated. When issuing the new key fails,
      // what happens to the previous pair depends on whether this activation consumed it:
      // - consumed (the token was an ECC-encrypted secret, decrypted with the previous private key,
      //   which is single-use - OPC 10000-6 6.8.3 - and was cleared by the decryption): nothing valid
      //   is left to put back. The orphaned new private key is scrubbed and the stored pair cleared, so
      //   the next activation is refused through the refusal path, which issues a new signed key;
      // - not consumed (an Anonymous, X509 or unencrypted token): the previous pair is still the
      //   client's key, and it is put back exactly as run_refused_activate_fault does.
      auto deps = mDependencies.lock();
      if (!deps || !mSecureChannelInfo)
      {
        fail_activate_response(Status::BadInternalError,
          make_error_detail("DepsExpired", "Session deps/channel info missing", "Session"));
        co_return;
      }

      auto securityPolicy = mSecureChannelInfo->security_policy();
      auto certAndKey = stack_utils::get_local_cert_and_keys(mServerCertificates, securityPolicy->id());
      if (!certAndKey.keys)
      {
        fail_activate_response(Status::BadSecurityChecksFailed,
          make_error_detail(
            "NoLocalKey", "No server keypair available for ECC ephemeral signing", "Session"));
        co_return;
      }

      const bool previousKeyConsumed = mEccEphemeralPrivateKey.empty();
      // Moved out, not copied: the one buffer holding the previous private key is the one scrubbed
      // below. The new pair takes the members; a failure to issue it puts this one back (when it was
      // not consumed) or clears the stored pair (when it was).
      ByteString previousPrivateKey = std::move(mEccEphemeralPrivateKey);
      ByteString previousPublicKey = std::move(mEccEphemeralPublicKey);
      // Clears the saved private key whenever this scope ends - including when the Session is destroyed
      // with the frame suspended, which destroys the frame without resuming it (DEF-4).
      const ua::security::ScrubOnExit scrubPrevious{previousPrivateKey};
      mEccEphemeralPrivateKey = ByteString{};
      mEccEphemeralPublicKey = ByteString{};
      const auto keepNoNewKey = [this, previousKeyConsumed, &previousPrivateKey, &previousPublicKey]
      {
        ua::security::secure_clear(mEccEphemeralPrivateKey);
        if (previousKeyConsumed)
        {
          mEccEphemeralPrivateKey = ByteString{};
          mEccEphemeralPublicKey = ByteString{};
          return;
        }
        mEccEphemeralPrivateKey = std::move(previousPrivateKey);
        mEccEphemeralPublicKey = std::move(previousPublicKey);
      };
      Result<std::unique_ptr<Structure>> ecdhKey{StatusCode{Status::BadInternalError}};
      try
      {
        ecdhKey = co_await issue_signed_ecdh_key(deps->crypto(),
          securityPolicy,
          certAndKey.keys,
          "Failed to sign ECC ephemeral key in ActivateSession response");
      }
      catch (const ua::async::Abandoned&)
      {
        // Withdrawn with the Session: nothing to put back; the guard clears the saved key.
        throw;
      }
      catch (...)
      {
        // A key that was generated but cannot be sent must not replace the one the client holds.
        keepNoNewKey();
        throw;
      }
      if (!ecdhKey.is_good())
      {
        keepNoNewKey();
        if (mActivateResponseState)
          fail_activate_response(ecdhKey.status_code(), ecdhKey.shared_detail());
        co_return;
      }
      if (!mActivateResponseState)
        co_return;
      mActivateResponseState->response->response_header().additional_header() = std::move(ecdhKey).value();
    }

    // --- commit the authenticated identity ------------------------------------------------
    const auto commitOutcome = commit_activate_identity();
    if (commitOutcome == ActivateCommitOutcome::Failed)
      co_return;

    // --- the mandatory MonitoredItem reauthorization walk, on an identity change -----------
    // Every item the previous identity was allowed to see has to be re-evaluated against the new
    // one before the activation is acknowledged (Part 4 5.6.3). A Session with no subscriptions
    // pipeline has nothing to walk.
    if (commitOutcome == ActivateCommitOutcome::IdentityChanged)
    {
      if (auto pipeline = mSubscriptionsPipeline.load())
      {
        VoidResult reauthorizationResult{};
        try
        {
          reauthorizationResult = co_await await_step<VoidResult>(
            [&pipeline](auto completion) { pipeline->reauthorize_all_async(std::move(completion)); });
        }
        catch (const ua::async::Abandoned&)
        {
          throw;
        }
        catch (...)
        {
          // A pipeline that throws out of the CALL has answered nothing. The chain this replaces
          // failed the activation closed on such a throw, and so does this.
          auto failure = ua::exception_to_status_code(std::current_exception());
          fail_changed_identity_activation(failure, failure.shared_detail());
          co_return;
        }
        if (!mActivateResponseState)
          co_return;
        if (reauthorizationResult.is_bad())
        {
          fail_changed_identity_activation(
            reauthorizationResult.status_code(), reauthorizationResult.shared_detail());
          co_return;
        }
      }
    }

    complete_activate_response();
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the activation and answered its caller.
    co_return;
  }
  catch (...)
  {
    // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
    // nobody reads, and the client would wait for its ActivateSessionResponse for ever.
    auto failure = ua::exception_to_status_code(std::current_exception());
    ua::async::guarded(mLogger, [&] { fail_activate_response(failure, failure.shared_detail()); })();
  }
  co_return;
}

Session::ActivateCommitOutcome Session::commit_activate_identity()
{
  if (!mActivateResponseState)
    return ActivateCommitOutcome::Failed;
  const auto requestId = mActivateResponseState->requestId;

  if (mDependencies.expired())
  {
    fail_activate_response(StatusCode{Status::BadInternalError},
      make_error_detail("DepsExpired", "Session deps expired during the identity commit", "Session"));
    return ActivateCommitOutcome::Failed;
  }

  auto requestIt = mInFlightRequestsByRequestId.find(requestId);
  if (requestIt == mInFlightRequestsByRequestId.end())
  {
    fail_activate_response(StatusCode{Status::BadInternalError},
      make_error_detail(
        "RequestVanished", "ActivateSession request gone before response could be built", "Session"));
    return ActivateCommitOutcome::Failed;
  }
  if (!dynamic_cast<ActivateSessionRequest*>(requestIt->second.get()))
  {
    fail_activate_response(StatusCode{Status::BadRequestTypeInvalid},
      make_error_detail(
        "RequestTypeInvalid", "In-flight request changed type during activate response build", "Session"));
    return ActivateCommitOutcome::Failed;
  }
  if (!mSecureChannelInfo)
  {
    fail_activate_response(StatusCode{Status::BadSecureChannelClosed},
      make_error_detail("SecureChannelClosed",
        "Secure channel closed before ActivateSession response could be built",
        "Session"));
    return ActivateCommitOutcome::Failed;
  }

  bool identityChanged = false;
  auto userIt = mAuthnUserByRequestId.find(requestId);
  std::optional<UserIdentity>* authenticatedUser = nullptr;
  if (userIt != mAuthnUserByRequestId.end())
    authenticatedUser = &userIt->second;
  if (authenticatedUser && authenticatedUser->has_value())
  {
    auto& activatingUser = authenticatedUser->value();
    // Activation is itself about to evaluate and commit the current Role configuration. Compare with
    // the previously committed identity without triggering the ordinary request-time refresh: on the
    // first activation there are no authenticated user/endpoint facts yet, and on reactivation an eager
    // refresh here would hide the identity-change edge that requires mandatory MonitoredItem reauthorization.
    auto previousIdentity = mSessionInfo->committed_access_identity();

    const auto endpointIt = mAuthnEndpointByRequestId.find(requestId);
    if (endpointIt == mAuthnEndpointByRequestId.end() || !endpointIt->second)
    {
      fail_activate_response(StatusCode{Status::BadInternalError},
        make_error_detail("EndpointSecurityContextMissing",
          "Authenticated activation has no matched endpoint security context",
          "Session"));
      return ActivateCommitOutcome::Failed;
    }
    auto endpoint = endpointIt->second;

    const bool channelAtLeastSigned = endpoint->messageSecurityMode == MessageSecurityMode::Sign ||
                                      endpoint->messageSecurityMode == MessageSecurityMode::SignAndEncrypt;
    if (channelAtLeastSigned && mSecureChannelInfo->client_certificate() != nullptr)
      activatingUser.claims[ClaimKeys::clientCertificateTrusted] = "true";

    auto user = std::make_shared<const UserIdentity>(std::move(activatingUser));
    RoleConfiguration::AccessEvaluation roleEvaluation;
    try
    {
      if (auto deps = mDependencies.lock(); deps && deps->components().roleConfiguration)
      {
        roleEvaluation = deps->components().roleConfiguration->evaluate_access_identity(*user, *endpoint);
      }
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      fail_activate_response(failure, failure.shared_detail());
      return ActivateCommitOutcome::Failed;
    }
    auto deps = mDependencies.lock();
    if (!deps)
    {
      fail_activate_response(StatusCode{Status::BadInternalError},
        make_error_detail("DepsExpired", "Session deps expired while acquiring access identity", "Session"));
      return ActivateCommitOutcome::Failed;
    }
    auto acquiredIdentity = deps->access_identity_registry().acquire(user,
      endpoint,
      std::move(roleEvaluation.grantedRoles),
      std::move(roleEvaluation.registeredRoles),
      roleEvaluation.configurationEpoch);
    if (!acquiredIdentity.is_good())
    {
      fail_activate_response(acquiredIdentity.status_code(), acquiredIdentity.shared_detail());
      return ActivateCommitOutcome::Failed;
    }
    auto accessIdentity = std::move(acquiredIdentity).value();

    identityChanged = previousIdentity && previousIdentity->key() != accessIdentity->key();
    mSecurityState->update_on_activate(*user, *endpoint);
    // Commit the authenticated identity before the mandatory MonitoredItem reauthorization walk.
    mSessionInfo->set_security_context(
      mSessionId, std::move(endpoint), std::move(user), std::move(accessIdentity));
    mUserTokenCertificate = std::exchange(mActivatingUserTokenCertificate, nullptr);
    mUserTokenCertificateField = std::exchange(mActivatingUserTokenCertificateField, ByteString{});
    mUserTokenPolicy = std::exchange(mActivatingUserTokenPolicy, nullptr);

    // A downgraded identity must not resume a history cursor opened by its predecessor.
    mHistoryContinuationPoints.clear();
    mHistoryContinuationPointExpiry.clear();
  }

  // The identity is committed: only now does the Session become Activated (SESS-7(g)). Every failure
  // above returned first and left the previous state. The cross-strand `mState` follows in
  // complete_activate_response, once the response is queued.
  mSessionState = State::Activated;
  return identityChanged ? ActivateCommitOutcome::IdentityChanged : ActivateCommitOutcome::IdentityUnchanged;
}

void Session::complete_activate_response()
{
  if (!mActivateResponseState)
    return;
  const auto requestId = mActivateResponseState->requestId;
  auto deps = mDependencies.lock();
  if (!deps)
  {
    fail_activate_response(StatusCode{Status::BadInternalError},
      make_error_detail("DepsExpired", "Session deps expired before ActivateSession completion", "Session"));
    return;
  }
  auto requestIt = mInFlightRequestsByRequestId.find(requestId);
  if (requestIt == mInFlightRequestsByRequestId.end())
  {
    fail_activate_response(StatusCode{Status::BadInternalError},
      make_error_detail("RequestVanished",
        "ActivateSession request disappeared during MonitoredItem reauthorization",
        "Session"));
    return;
  }
  auto* activateSessionRequest = dynamic_cast<ActivateSessionRequest*>(requestIt->second.get());
  if (!activateSessionRequest || !mActivateResponseState->response)
  {
    fail_activate_response(StatusCode{Status::BadRequestTypeInvalid},
      make_error_detail("RequestTypeInvalid", "ActivateSession completion state is invalid", "Session"));
    return;
  }
  if (!mSecureChannelInfo)
  {
    fail_activate_response(StatusCode{Status::BadSecureChannelClosed},
      make_error_detail(
        "SecureChannelClosed", "Secure channel closed before ActivateSession could complete", "Session"));
    return;
  }

  mState.store(State::Activated, std::memory_order_release);
  deps->logger().info({{"session_name", std::string_view{mSessionName}}}, "Session activated");

  auto currentUser = mSessionInfo->user_identity();
  {
    auto observer = deps->observer();
    auto eventInfo = build_session_event_info(mSessionId, mSessionName, mSecureChannelInfo);
    eventInfo.auditEntryId = activateSessionRequest->request_header().audit_entry_id();
    if (currentUser)
      eventInfo.clientUserId = currentUser->userId;
    // SESS-4: observers receive the token without its credential (password / issued token data), as
    // the audit event does; an observer is application code the SDK cannot audit.
    if (activateSessionRequest->user_identity_token())
      eventInfo.userIdentityToken = redact_credentials(*activateSessionRequest->user_identity_token());
    detail::emit_event(deps->logger(), observer, [&] { observer->on_session_activated(eventInfo); });
  }

  if (currentUser)
  {
    deps->logger().with_category("session").info(
      {{"session_name", std::string_view{mSessionName}},
        {"user_id", std::string_view{currentUser->userId}},
        {"identity_type", std::string_view{user_identity_kind_name(currentUser->kind)}}},
      "User authenticated");
  }

  auto response = std::move(mActivateResponseState->response);
  if (auto secureChannel = mSecureChannelInfo->secure_channel().lock())
    secureChannel->send_response_message(std::make_pair(requestId, std::move(response)));

  mInFlightRequestsByRequestId.erase(requestId);
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mReturnDiagnosticsByRequestId.erase(requestId);

  auto callback = std::move(mActivateResponseState->callback);
  mActivateResponseState.reset();
  callback(VoidResult{});
}

void Session::fail_changed_identity_activation(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
{
  if (!mActivateResponseState)
    return;

  // The new AccessIdentity is already committed before the mandatory namespace walk begins. A
  // mandatory walk can also have applied earlier item transitions before a later
  // infrastructure failure. Rollback would therefore need to restore security diagnostics,
  // certificate/history state, item queues, and EventBus registrations atomically. Fail closed
  // instead: make the Session immediately non-live, preserve the exact activation failure, then
  // tear down its Subscriptions after the failure callback has queued the ServiceFault.
  mSessionState = State::Closed;
  mState.store(State::Closed, std::memory_order_release);
  const auto closeStatus = status;
  const auto closeDetail = detail;
  try
  {
    fail_activate_response(status, detail);
  }
  catch (...)
  {
    close_session_internal(closeStatus, closeDetail, /*deleteSubscriptions=*/true);
    return;
  }

  try
  {
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [closeStatus, closeDetail](Session& self)
      { self.close_session_internal(closeStatus, closeDetail, /*deleteSubscriptions=*/true); })();
  }
  catch (...)
  {
    close_session_internal(closeStatus, closeDetail, /*deleteSubscriptions=*/true);
  }
}

void Session::fail_activate_response(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
{
  if (!mActivateResponseState)
    return;
  auto cb = std::move(mActivateResponseState->callback);
  mActivateResponseState.reset();
  cb(VoidResult{status, std::move(detail)});
}

void Session::request_received(Request request)
{
  // Any received Service request is activity that resets the inactivity timeout (OPC 10000-4 5.6.2);
  // recorded before dispatch so it counts even for requests that fault or are rejected downstream.
  // The same stamp serves ClientLastContactTime (Part 5 12.11), derived from it at read time.
  mLastActivity = std::chrono::steady_clock::now();
  mDescriptiveState->note_activity(mLastActivity);

  auto requestId = std::get<uint32_t>(request);
  auto requestMessage = std::get<shared_ptr<Structure>>(request);

  if (auto* activateSessionRequest = dynamic_cast<ActivateSessionRequest*>(requestMessage.get()))
  {
    // The RequestHandle is recorded inside activate_internal (covers all entry paths). Nothing is
    // recorded when the id is in flight: activate_internal refuses the request, and the entries belong
    // to the request that holds the id.
    if (!mInFlightRequestsByRequestId.contains(requestId))
    {
      mReturnDiagnosticsByRequestId[requestId] =
        activateSessionRequest->request_header().return_diagnostics();
    }
    activate_internal(requestId, std::move(*activateSessionRequest), {});
    return;
  }

  if (auto* closeSessionRequest = dynamic_cast<CloseSessionRequest*>(requestMessage.get()))
  {
    // SESS-7: a CloseSession under a requestId still in flight is refused; recording its handle or
    // storing it would overwrite the request that holds the id, and close_internal releases the id.
    if (mInFlightRequestsByRequestId.contains(requestId))
    {
      create_and_send_service_fault(requestId,
        Status::BadServerTooBusy,
        request_id_in_flight_detail(requestId),
        closeSessionRequest->request_header().return_diagnostics(),
        std::nullopt,
        closeSessionRequest->request_header().request_handle());
      return;
    }
    // This branch returns early, bypassing the generic handle-fill below; record the handle so a
    // CloseSession fault echoes it (mirrors Cancel).
    mRequestHandlesByRequestId[requestId] = closeSessionRequest->request_header().request_handle();
    mReturnDiagnosticsByRequestId[requestId] = closeSessionRequest->request_header().return_diagnostics();
    close_internal(requestId, std::move(*closeSessionRequest));
    return;
  }

  if (auto* cancelRequest = dynamic_cast<CancelRequest*>(requestMessage.get()))
  {
    if (mInFlightRequestsByRequestId.contains(requestId))
    {
      create_and_send_service_fault(requestId,
        Status::BadServerTooBusy,
        request_id_in_flight_detail(requestId),
        cancelRequest->request_header().return_diagnostics(),
        std::nullopt,
        cancelRequest->request_header().request_handle());
      return;
    }
    mInFlightRequestsByRequestId[requestId] = requestMessage;
    mRequestHandlesByRequestId[requestId] = cancelRequest->request_header().request_handle();
    mReturnDiagnosticsByRequestId[requestId] = cancelRequest->request_header().return_diagnostics();

    try
    {
      handle_cancel_request(requestId, CancelRequest{*cancelRequest});
    }
    catch (...)
    {
      auto sc = handle_unexpected_exception("Session::request_received(cancel)", std::current_exception());
      create_and_send_service_fault(requestId, sc);
    }
    return;
  }

  // S5: Per-session request backpressure - reject if too many in-flight requests (excluding Publish,
  // which is limited separately by mMaxPublishRequestsPerSession).
  {
    auto handler = mDependencies.lock();
    if (handler)
    {
      const auto maxRequests = handler->server_configuration().maxRequestsPerSession;
      if (maxRequests.has_value() && mInFlightRequestsByRequestId.size() >= *maxRequests)
      {
        // Check if this is a Publish request (excluded from the limit).
        if (!dynamic_cast<PublishRequest*>(requestMessage.get()))
        {
          // BadServerTooBusy is the service-level backpressure code ("the server is too busy
          // to complete the operation"). This is a transient load condition - too many
          // in-flight requests - not "too many operations in a single request"
          // (which is BadTooManyOperations and applies to per-service operation limits).
          create_and_send_service_fault(requestId,
            StatusCode{Status::BadServerTooBusy},
            ErrorDetail::build("ServerTooBusy", "Per-session in-flight request limit reached", "Session")
              .context(ua::ContextKeys::limit, std::to_string(*maxRequests))
              .context(ua::ContextKeys::countTotal, std::to_string(mInFlightRequestsByRequestId.size()))
              .context(ua::ContextKeys::sessionId, to_string(mSessionId))
              .context(ua::ContextKeys::requestId, std::to_string(requestId)));
          return;
        }
      }
    }
  }

  // Route all other services through reducer gating.
  Session::ServiceKind kind = Session::ServiceKind::Unknown;
  uint32_t requestHandle{0};
  uint32_t returnDiagnostics{0};

  if (auto* fs = dynamic_cast<FindServersRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DiscoveryFindServers;
    requestHandle = fs->request_header().request_handle();
    returnDiagnostics = fs->request_header().return_diagnostics();
  }
  else if (auto* fson = dynamic_cast<FindServersOnNetworkRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DiscoveryFindServersOnNetwork;
    requestHandle = fson->request_header().request_handle();
    returnDiagnostics = fson->request_header().return_diagnostics();
  }
  else if (auto* ge = dynamic_cast<GetEndpointsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DiscoveryGetEndpoints;
    requestHandle = ge->request_header().request_handle();
    returnDiagnostics = ge->request_header().return_diagnostics();
  }
  else if (auto* rr = dynamic_cast<ReadRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::Read;
    requestHandle = rr->request_header().request_handle();
    returnDiagnostics = rr->request_header().return_diagnostics();
  }
  else if (auto* wr = dynamic_cast<WriteRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::Write;
    requestHandle = wr->request_header().request_handle();
    returnDiagnostics = wr->request_header().return_diagnostics();
  }
  else if (auto* br = dynamic_cast<BrowseRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::Browse;
    requestHandle = br->request_header().request_handle();
    returnDiagnostics = br->request_header().return_diagnostics();
  }
  else if (auto* bn = dynamic_cast<BrowseNextRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::BrowseNext;
    requestHandle = bn->request_header().request_handle();
    returnDiagnostics = bn->request_header().return_diagnostics();
  }
  else if (auto* cr = dynamic_cast<CallRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::Call;
    requestHandle = cr->request_header().request_handle();
    returnDiagnostics = cr->request_header().return_diagnostics();
  }
  else if (auto* tbp = dynamic_cast<TranslateBrowsePathsToNodeIdsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::TranslateBrowsePathsToNodeIds;
    requestHandle = tbp->request_header().request_handle();
    returnDiagnostics = tbp->request_header().return_diagnostics();
  }
  else if (auto* reg = dynamic_cast<RegisterNodesRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::RegisterNodes;
    requestHandle = reg->request_header().request_handle();
    returnDiagnostics = reg->request_header().return_diagnostics();
  }
  else if (auto* unreg = dynamic_cast<UnregisterNodesRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::UnregisterNodes;
    requestHandle = unreg->request_header().request_handle();
    returnDiagnostics = unreg->request_header().return_diagnostics();
  }
  else if (auto* csub = dynamic_cast<CreateSubscriptionRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::CreateSubscription;
    requestHandle = csub->request_header().request_handle();
    returnDiagnostics = csub->request_header().return_diagnostics();
  }
  else if (auto* msub = dynamic_cast<ModifySubscriptionRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::ModifySubscription;
    requestHandle = msub->request_header().request_handle();
    returnDiagnostics = msub->request_header().return_diagnostics();
  }
  else if (auto* dsub = dynamic_cast<DeleteSubscriptionsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DeleteSubscriptions;
    requestHandle = dsub->request_header().request_handle();
    returnDiagnostics = dsub->request_header().return_diagnostics();
  }
  else if (auto* spm = dynamic_cast<SetPublishingModeRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::SetPublishingMode;
    requestHandle = spm->request_header().request_handle();
    returnDiagnostics = spm->request_header().return_diagnostics();
  }
  else if (auto* pub = dynamic_cast<PublishRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::Publish;
    requestHandle = pub->request_header().request_handle();
    returnDiagnostics = pub->request_header().return_diagnostics();
  }
  else if (auto* rpub = dynamic_cast<RepublishRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::Republish;
    requestHandle = rpub->request_header().request_handle();
    returnDiagnostics = rpub->request_header().return_diagnostics();
  }
  else if (auto* cmi = dynamic_cast<CreateMonitoredItemsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::CreateMonitoredItems;
    requestHandle = cmi->request_header().request_handle();
    returnDiagnostics = cmi->request_header().return_diagnostics();
  }
  else if (auto* dmi = dynamic_cast<DeleteMonitoredItemsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DeleteMonitoredItems;
    requestHandle = dmi->request_header().request_handle();
    returnDiagnostics = dmi->request_header().return_diagnostics();
  }
  else if (auto* mmi = dynamic_cast<ModifyMonitoredItemsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::ModifyMonitoredItems;
    requestHandle = mmi->request_header().request_handle();
    returnDiagnostics = mmi->request_header().return_diagnostics();
  }
  else if (auto* smm = dynamic_cast<SetMonitoringModeRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::SetMonitoringMode;
    requestHandle = smm->request_header().request_handle();
    returnDiagnostics = smm->request_header().return_diagnostics();
  }
  else if (auto* st = dynamic_cast<SetTriggeringRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::SetTriggering;
    requestHandle = st->request_header().request_handle();
    returnDiagnostics = st->request_header().return_diagnostics();
  }
  else if (auto* tsub = dynamic_cast<TransferSubscriptionsRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::TransferSubscriptions;
    requestHandle = tsub->request_header().request_handle();
    returnDiagnostics = tsub->request_header().return_diagnostics();
  }
  else if (auto* an = dynamic_cast<AddNodesRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::AddNodes;
    requestHandle = an->request_header().request_handle();
    returnDiagnostics = an->request_header().return_diagnostics();
  }
  else if (auto* ar = dynamic_cast<AddReferencesRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::AddReferences;
    requestHandle = ar->request_header().request_handle();
    returnDiagnostics = ar->request_header().return_diagnostics();
  }
  else if (auto* dn = dynamic_cast<DeleteNodesRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DeleteNodes;
    requestHandle = dn->request_header().request_handle();
    returnDiagnostics = dn->request_header().return_diagnostics();
  }
  else if (auto* dr = dynamic_cast<DeleteReferencesRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::DeleteReferences;
    requestHandle = dr->request_header().request_handle();
    returnDiagnostics = dr->request_header().return_diagnostics();
  }
  else if (auto* hr = dynamic_cast<HistoryReadRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::HistoryRead;
    requestHandle = hr->request_header().request_handle();
    returnDiagnostics = hr->request_header().return_diagnostics();
  }
  else if (auto* hu = dynamic_cast<HistoryUpdateRequest*>(requestMessage.get()))
  {
    kind = Session::ServiceKind::HistoryUpdate;
    requestHandle = hu->request_header().request_handle();
    returnDiagnostics = hu->request_header().return_diagnostics();
  }

  // Store request for effectful service execution. A requestId already in flight (a client reusing an id;
  // the old channel's requests are abandoned at channel transfer) is refused (SESS-7): overwriting the
  // entry would answer the wrong request and orphan the first.
  if (mInFlightRequestsByRequestId.contains(requestId))
  {
    create_and_send_service_fault(requestId,
      Status::BadServerTooBusy,
      request_id_in_flight_detail(requestId),
      returnDiagnostics,
      std::nullopt,
      requestHandle);
    return;
  }
  mInFlightRequestsByRequestId[requestId] = requestMessage;
  mRequestHandlesByRequestId[requestId] = requestHandle;
  mReturnDiagnosticsByRequestId[requestId] = returnDiagnostics;

  try
  {
    handle_service_request(requestId, kind, requestHandle);
  }
  catch (...)
  {
    auto sc = handle_unexpected_exception("Session::request_received(service)", std::current_exception());
    create_and_send_service_fault(requestId, sc);
  }
  return;
}

void Session::read_request_received(uint32_t requestId, ReadRequest&& request)
{
  auto me = this->weak_from_this();

  auto readService = ReadService::create(mSessionInfo,
    mLocales,
    requestId,
    std::move(request),
    mExecutor,
    [me](Response response)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable { session.response_received(response); })();
    });

  mServiceCallsByRequestId.emplace(requestId, readService);
}

void Session::write_request_received(uint32_t requestId, WriteRequest&& request)
{
  auto me = this->weak_from_this();

  auto writeService = AttributeServiceSet::create(mSessionInfo,
    requestId,
    std::move(request),
    mExecutor,
    [me](Response response)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable { session.response_received(response); })();
    });

  mServiceCallsByRequestId.emplace(requestId, writeService);
}

void Session::call_request_received(uint32_t requestId, CallRequest&& request)
{
  auto me = this->weak_from_this();
  auto callService = MethodServiceSet::create(
    mSessionInfo,
    mLocales,
    requestId,
    std::move(request),
    mExecutor,
    [me](Response response)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable { session.response_received(response); })();
    },
    MethodResponseCorrelation{mSecureChannelAssociationEpoch, requestId});

  mServiceCallsByRequestId.emplace(requestId, callService);
}

void Session::translate_browse_paths_request_received(
  uint32_t requestId, TranslateBrowsePathsToNodeIdsRequest&& request)
{
  auto me = this->weak_from_this();

  auto service = TranslateBrowsePathsService::create(mSessionInfo,
    mLocales,
    requestId,
    std::move(request),
    mExecutor,
    [me](Response response)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable { session.response_received(response); })();
    });

  mServiceCallsByRequestId.emplace(requestId, service);
}

void Session::register_nodes_request_received(uint32_t requestId, RegisterNodesRequest&& request)
{
  auto me = this->weak_from_this();

  auto service = RegisterNodesServiceSet::create(mSessionInfo,
    std::move(request),
    mExecutor,
    [me, requestId](RegisterNodesServiceSet::ResponseOrServiceFault responseVariant)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      auto response = std::visit(
        [requestId](auto&& resp) -> Response {
          return {
            requestId, std::make_shared<std::decay_t<decltype(resp)>>(std::forward<decltype(resp)>(resp))};
        },
        std::move(responseVariant));
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable { session.response_received(response); })();
    });

  mServiceCallsByRequestId.emplace(requestId, service);
}

void Session::unregister_nodes_request_received(uint32_t requestId, UnregisterNodesRequest&& request)
{
  auto me = this->weak_from_this();

  auto service = RegisterNodesServiceSet::create(mSessionInfo,
    std::move(request),
    mExecutor,
    [me, requestId](RegisterNodesServiceSet::ResponseOrServiceFault responseVariant)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      auto response = std::visit(
        [requestId](auto&& resp) -> Response {
          return {
            requestId, std::make_shared<std::decay_t<decltype(resp)>>(std::forward<decltype(resp)>(resp))};
        },
        std::move(responseVariant));
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable { session.response_received(response); })();
    });

  mServiceCallsByRequestId.emplace(requestId, service);
}

void Session::node_management_request_received(uint32_t requestId, Session::ServiceKind kind)
{
  auto deps = mDependencies.lock();
  if (!deps)
  {
    create_and_send_service_fault(requestId, Status::BadInternalError);
    return;
  }

  auto handler = deps->node_management_delegate();
  if (!handler)
  {
    create_and_send_service_fault(requestId, Status::BadServiceUnsupported);
    return;
  }

  auto it = mInFlightRequestsByRequestId.find(requestId);
  if (it == mInFlightRequestsByRequestId.end())
  {
    create_and_send_service_fault(requestId, Status::BadInternalError);
    return;
  }

  auto& reqMsg = it->second;
  auto me = this->weak_from_this();

  auto responseCallback = [me](Response response)
  {
    auto lockedSession = me.lock();
    if (!lockedSession)
      return;
    ua::async::post_borrowing(lockedSession.get(),
      lockedSession->mStrand,
      lockedSession->mLogger,
      [response](Session& session) mutable { session.response_received(response); })();
  };

  shared_ptr<Service> service;

  switch (kind)
  {
  case Session::ServiceKind::AddNodes:
  {
    auto* req = dynamic_cast<AddNodesRequest*>(reqMsg.get());
    if (!req)
    {
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
      return;
    }
    service = NodeManagementService::create(
      mSessionInfo, handler, requestId, AddNodesRequest{*req}, mExecutor, std::move(responseCallback));
    mServiceCallsByRequestId.emplace(requestId, service);
    break;
  }
  case Session::ServiceKind::AddReferences:
  {
    auto* req = dynamic_cast<AddReferencesRequest*>(reqMsg.get());
    if (!req)
    {
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
      return;
    }
    service = NodeManagementService::create(
      mSessionInfo, handler, requestId, AddReferencesRequest{*req}, mExecutor, std::move(responseCallback));
    mServiceCallsByRequestId.emplace(requestId, service);
    break;
  }
  case Session::ServiceKind::DeleteNodes:
  {
    auto* req = dynamic_cast<DeleteNodesRequest*>(reqMsg.get());
    if (!req)
    {
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
      return;
    }
    service = NodeManagementService::create(
      mSessionInfo, handler, requestId, DeleteNodesRequest{*req}, mExecutor, std::move(responseCallback));
    mServiceCallsByRequestId.emplace(requestId, service);
    break;
  }
  case Session::ServiceKind::DeleteReferences:
  {
    auto* req = dynamic_cast<DeleteReferencesRequest*>(reqMsg.get());
    if (!req)
    {
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
      return;
    }
    service = NodeManagementService::create(mSessionInfo,
      handler,
      requestId,
      DeleteReferencesRequest{*req},
      mExecutor,
      std::move(responseCallback));
    mServiceCallsByRequestId.emplace(requestId, service);
    break;
  }
  default:
    create_and_send_service_fault(requestId, Status::BadServiceUnsupported);
    break;
  }
}

void Session::subscription_request_received(uint32_t requestId, Session::ServiceKind kind)
{
  // Lazily create the SubscriptionsPipeline on first subscription service call. This is the sole write
  // of the atomic handle (created once, never reset); the store(release) pairs with the load(acquire) in
  // health_snapshot() so the off-strand gauge read never races this create.
  if (!mSubscriptionsPipeline.load())
  {
    auto deps = mDependencies.lock();
    if (!deps)
    {
      create_and_send_service_fault(requestId, Status::BadInternalError);
      return;
    }
    auto me = this->weak_from_this();
    mSubscriptionsPipeline.store(SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = mExecutor,
      .sessionStrand = mStrand,
      .logger = mSessionInfo->logger(),
      .idAllocator = deps->subscription_id_allocator(),
      .summaryCounters = deps->summary_counters(),
      .capabilities = deps->server_configuration().server_capabilities(),
      .subscriptionLimits = deps->server_configuration().subscriptionLimits,
      .monitoredItemAccessRecheckInterval = std::chrono::duration_cast<std::chrono::milliseconds>(
        deps->server_configuration().monitoredItemAccessRecheckInterval),
      .accessControlTimeout = deps->server_configuration().authzTimeout,
      .sendResponse =
        [me](Response response)
      {
        auto session = me.lock();
        if (!session)
          return;
        session->response_received(response);
      },
      .addressSpace = deps->address_space(),
      .subscriptionRouter = deps->subscription_router().weak(),
      .orphanedSubscriptionStore = deps->orphaned_subscription_store().weak(),
      .owningSession = me,
      .securityContext = mSessionInfo,
      .diagnosticSecurityContext =
        [sessionInfo = std::weak_ptr<SessionInfo>{mSessionInfo}]
      {
        auto current = sessionInfo.lock();
        return current ? current->diagnostic_security_context() : DiagnosticSecurityContext{};
      },
      .diagnosticsObject = [me]() -> std::optional<NodeId>
      {
        auto session = me.lock();
        return session ? session->diagnostics_object_id() : std::nullopt;
      },
      .eventBus = deps->event_bus_shared(),
      .maxResponseMessageSize = mMaxResponseMessageSize,
      .auditingEnabled = deps->server_configuration().auditingEnabled,
      .applicationUri = deps->configuration().application_description_part().applicationUri,
    }));
  }

  // Snapshot the handle once for the dispatch below (created above; never reset, so non-null here).
  auto pipeline = mSubscriptionsPipeline.load();

  auto it = mInFlightRequestsByRequestId.find(requestId);
  if (it == mInFlightRequestsByRequestId.end())
  {
    create_and_send_service_fault(requestId, Status::BadInternalError);
    return;
  }

  auto& reqMsg = it->second;

  switch (kind)
  {
  case Session::ServiceKind::CreateSubscription:
  {
    auto* req = dynamic_cast<CreateSubscriptionRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_create_subscription(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::ModifySubscription:
  {
    auto* req = dynamic_cast<ModifySubscriptionRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_modify_subscription(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::DeleteSubscriptions:
  {
    auto* req = dynamic_cast<DeleteSubscriptionsRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_delete_subscriptions(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::SetPublishingMode:
  {
    auto* req = dynamic_cast<SetPublishingModeRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_set_publishing_mode(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::Publish:
  {
    auto* req = dynamic_cast<PublishRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_publish(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::Republish:
  {
    auto* req = dynamic_cast<RepublishRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_republish(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::CreateMonitoredItems:
  {
    auto* req = dynamic_cast<CreateMonitoredItemsRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_create_monitored_items(requestId, *req, mLocales);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::DeleteMonitoredItems:
  {
    auto* req = dynamic_cast<DeleteMonitoredItemsRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_delete_monitored_items(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::ModifyMonitoredItems:
  {
    auto* req = dynamic_cast<ModifyMonitoredItemsRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_modify_monitored_items(requestId, *req, mLocales);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::SetMonitoringMode:
  {
    auto* req = dynamic_cast<SetMonitoringModeRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_set_monitoring_mode(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::SetTriggering:
  {
    auto* req = dynamic_cast<SetTriggeringRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_set_triggering(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  case Session::ServiceKind::TransferSubscriptions:
  {
    auto* req = dynamic_cast<TransferSubscriptionsRequest*>(reqMsg.get());
    if (req)
      pipeline->handle_transfer_subscriptions(requestId, *req);
    else
      create_and_send_service_fault(requestId, Status::BadRequestTypeInvalid);
    break;
  }
  default:
    create_and_send_service_fault(requestId, Status::BadServiceUnsupported);
    break;
  }
}

void Session::browse_request_received(uint32_t requestId, BrowseRequest&& request)
{
  auto me = this->weak_from_this();

  auto browseService = BrowseService::create(mSessionInfo,
    mLocales,
    requestId,
    std::move(request),
    mExecutor,
    [me](BrowseService::BrowseServiceResponse browseServiceResponse)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      // `boost::asio::strand<boost::asio::any_io_executor>::post` stores the callable as
      // `std::function<void()>` (copyable), so avoid capturing a potentially move-only response type
      // directly.
      auto response = make_shared<BrowseService::BrowseServiceResponse>(std::move(browseServiceResponse));
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable
        { session.browse_response_received(response->response, std::move(response->continuationPoints)); })();
    });

  mServiceCallsByRequestId.emplace(requestId, browseService);
}

void Session::browse_next_request_received(uint32_t requestId, BrowseNextRequest&& request)
{
  auto me = this->weak_from_this();

  // Purge expired continuation points before servicing BrowseNext.
  const auto timeoutOpt = mSessionInfo->server_configuration().browseContinuationPointTimeout;
  if (timeoutOpt && (*timeoutOpt > std::chrono::milliseconds{0}))
  {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = mBrowseContinuationPointExpiry.begin(); it != mBrowseContinuationPointExpiry.end();)
    {
      if (it->second <= now)
      {
        mBrowseContinuationPoints.erase(it->first);
        it = mBrowseContinuationPointExpiry.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  auto browseService = BrowseService::create(mSessionInfo,
    mLocales,
    requestId,
    std::move(request),
    mBrowseContinuationPoints,
    mExecutor,
    [me](BrowseService::BrowseServiceResponse browseServiceResponse)
    {
      auto lockedSession = me.lock();
      if (lockedSession)
      {
        auto response = make_shared<BrowseService::BrowseServiceResponse>(std::move(browseServiceResponse));
        ua::async::post_borrowing(lockedSession.get(),
          lockedSession->mStrand,
          lockedSession->mLogger,
          [response](Session& session) mutable {
            session.browse_response_received(response->response, std::move(response->continuationPoints));
          })();
      }
    });

  mServiceCallsByRequestId.emplace(requestId, browseService);
}

void Session::history_read_request_received(uint32_t requestId, HistoryReadRequest&& request)
{
  auto me = this->weak_from_this();

  // Purge expired history CPs before servicing the request.
  purge_expired_history_continuation_points();

  auto service = HistoryReadService::create(mSessionInfo,
    mLocales,
    requestId,
    std::move(request),
    mHistoryContinuationPoints,
    mExecutor,
    [me](HistoryReadService::HistoryReadServiceResponse serviceResponse)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      auto response = make_shared<HistoryReadService::HistoryReadServiceResponse>(std::move(serviceResponse));
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [response](Session& session) mutable
        { session.history_read_response_received(std::move(*response)); })();
    });

  mServiceCallsByRequestId.emplace(requestId, service);
}

void Session::history_read_response_received(HistoryReadService::HistoryReadServiceResponse response)
{
  try
  {
    const auto requestId = std::get<uint32_t>(response.response);

    // A whole-request HistoryRead rejection is delivered here as a ServiceFault; count it as a
    // service-level error for this Service (this completion path does not go through
    // Session::send_service_fault).
    note_service_fault_error(requestId, std::get<std::shared_ptr<Structure>>(response.response));

    // Purge expired history continuation points.
    purge_expired_history_continuation_points();

    // Store new continuation points with budget enforcement.
    const auto& caps = mSessionInfo->server_configuration().server_capabilities();
    const auto timeoutOpt = mSessionInfo->server_configuration().historyContinuationPointTimeout;
    const uint16_t maxCPs = caps.maxHistoryContinuationPoints;

    // If we would exceed budget, evict oldest existing CPs first.
    if (maxCPs > 0 && !response.continuationPoints.empty())
    {
      const size_t currentCount = mHistoryContinuationPoints.size();
      const size_t incomingCount = response.continuationPoints.size();
      if (currentCount + incomingCount > maxCPs)
      {
        // Evict oldest CPs (by expiry time) to make room.
        size_t toEvict = (currentCount + incomingCount) - maxCPs;
        while (toEvict > 0 && !mHistoryContinuationPointExpiry.empty())
        {
          // Find the oldest expiry.
          auto oldest = std::min_element(mHistoryContinuationPointExpiry.begin(),
            mHistoryContinuationPointExpiry.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
          mHistoryContinuationPoints.erase(oldest->first);
          mHistoryContinuationPointExpiry.erase(oldest);
          --toEvict;
        }
      }
    }

    for (auto& cp : response.continuationPoints)
    {
      auto guid = cp.identifier();

      // If still over budget after eviction, reject this CP.
      if (maxCPs > 0 && mHistoryContinuationPoints.size() >= maxCPs)
      {
        // Find the response result that references this CP and clear its continuation_point bytes,
        // setting status to BadNoContinuationPoints.
        auto* histResp =
          dynamic_cast<HistoryReadResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
        if (histResp)
        {
          auto cpBytes = guid.as_ua_binary();
          for (auto& r : histResp->results())
          {
            if (r.continuation_point().size() == cpBytes.size() &&
                std::memcmp(r.continuation_point().data(), cpBytes.data(), cpBytes.size()) == 0)
            {
              r.continuation_point().clear();
              r.status_code() = Status::BadNoContinuationPoints;
              break;
            }
          }
        }
        continue;
      }

      mHistoryContinuationPoints.emplace(guid, std::move(cp));
      if (timeoutOpt && (*timeoutOpt > std::chrono::milliseconds{0}))
      {
        mHistoryContinuationPointExpiry[guid] = std::chrono::steady_clock::now() + *timeoutOpt;
      }
    }

    auto sc = mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr;
    if (sc)
    {
      sc->send_response_message(response.response);
    }
    else
    {
      enqueue_response(response.response);
    }

    if (mResponseSinkForTests)
    {
      auto depsForLog = mDependencies.lock();
      ::ua::detail::invoke_user_callback(
        depsForLog ? depsForLog->logger() : Logger{}, mResponseSinkForTests, response.response);
    }

    release_request_tracking(requestId);
  }
  catch (...)
  {
    handle_unexpected_exception("Session::history_read_response_received", std::current_exception());
  }
}

void Session::history_update_request_received(uint32_t requestId, HistoryUpdateRequest&& request)
{
  auto me = this->weak_from_this();

  auto service = HistoryUpdateService::create(mSessionInfo,
    requestId,
    std::move(request),
    mExecutor,
    [me](Response response)
    {
      auto lockedSession = me.lock();
      if (!lockedSession)
        return;
      auto resp = make_shared<Response>(std::move(response));
      ua::async::post_borrowing(lockedSession.get(),
        lockedSession->mStrand,
        lockedSession->mLogger,
        [resp](Session& session) mutable { session.response_received(std::move(*resp)); })();
    });

  mServiceCallsByRequestId.emplace(requestId, service);
}

void Session::purge_expired_history_continuation_points()
{
  const auto timeoutOpt = mSessionInfo->server_configuration().historyContinuationPointTimeout;
  if (!timeoutOpt || (*timeoutOpt <= std::chrono::milliseconds{0}))
    return;

  const auto now = std::chrono::steady_clock::now();
  for (auto it = mHistoryContinuationPointExpiry.begin(); it != mHistoryContinuationPointExpiry.end();)
  {
    if (it->second <= now)
    {
      mHistoryContinuationPoints.erase(it->first);
      it = mHistoryContinuationPointExpiry.erase(it);
    }
    else
    {
      ++it;
    }
  }
}

template<typename RequestType>
void Session::discovery_service_set_request_received(uint32_t requestId, RequestType&& request)
{
  // No requestHandle local: it existed only to be captured by the dispatch lambda below, which
  // never referenced it. Clang rejected the dead capture (-Wunused-lambda-capture) and GCC then
  // rejected the variable left behind it (-Wunused-variable) - the two warnings are the same dead
  // value seen from either end.
  auto me = this->weak_from_this();

  auto deps = mDependencies.lock();
  check(deps);

  // S12: Track in-flight discovery requests for load-aware throttling.
  auto discoveryCounter = deps->in_flight_discovery_requests();
  uint32_t currentCount = 0;
  if (discoveryCounter)
  {
    currentCount = discoveryCounter->fetch_add(1, std::memory_order_relaxed) + 1;
  }

  const auto& throttleCfg = deps->server_configuration().discoveryThrottling;
  const bool shouldDelay =
    currentCount > throttleCfg.concurrencyThreshold && throttleCfg.delayPerRequest.count() > 0;

  if (shouldDelay)
  {
    deps->logger()
      .with_category("discovery")
      .debug(
        {{"in_flight", uint64_t(currentCount)}, {"threshold", uint64_t(throttleCfg.concurrencyThreshold)}},
        "Discovery throttling: delaying session request");
  }

  // Lambda that creates and dispatches the discovery service.
  auto dispatch = [me, requestId, request = std::forward<RequestType>(request), discoveryCounter]() mutable
  {
    auto dispatchSession = me.lock();
    if (!dispatchSession)
    {
      if (discoveryCounter)
        discoveryCounter->fetch_sub(1, std::memory_order_relaxed);
      return;
    }

    auto d = dispatchSession->mDependencies.lock();
    if (!d)
    {
      if (discoveryCounter)
        discoveryCounter->fetch_sub(1, std::memory_order_relaxed);
      return;
    }

    auto discoveryServiceSet =
      DiscoveryServiceSet<std::decay_t<RequestType>>::create(d->discovery_dependencies(),
        String{},
        requestId,
        std::move(request),
        dispatchSession->mExecutor,
        [me, discoveryCounter](Response response)
        {
          // S12: Decrement in-flight counter when the discovery service completes.
          if (discoveryCounter)
            discoveryCounter->fetch_sub(1, std::memory_order_relaxed);

          auto lockedSession = me.lock();
          if (!lockedSession)
            return;
          ua::async::post_borrowing(lockedSession.get(),
            lockedSession->mStrand,
            lockedSession->mLogger,
            [response](Session& session) mutable { session.response_received(response); })();
        });

    dispatchSession->mServiceCallsByRequestId.emplace(requestId, discoveryServiceSet);
  };

  if (shouldDelay)
  {
    // Schedule the dispatch after the configured delay.

    auto timerPtr = std::make_shared<Timer>();
    *timerPtr = Timer::schedule_after(mStrand,
      std::chrono::duration_cast<std::chrono::steady_clock::duration>(throttleCfg.delayPerRequest),
      [me, dispatch = std::move(dispatch), discoveryCounter, timerPtr](boost::system::error_code ec) mutable
      {
        if (ec)
        {
          // Timer cancelled (e.g. shutdown) - decrement counter and abort.
          if (discoveryCounter)
            discoveryCounter->fetch_sub(1, std::memory_order_relaxed);
          timerPtr.reset();
          return;
        }

        dispatch();
        timerPtr.reset();
      });

    // timerPtr is captured in the lambda closure, keeping it alive until the timer fires.
  }
  else
  {
    // No delay needed - dispatch immediately.
    dispatch();
  }
}

void Session::create_and_send_service_fault(uint32_t requestId, StatusCode statusCode,
  std::shared_ptr<const ErrorDetail> detail, uint32_t returnDiagnostics,
  optional<weak_ptr<SecureChannel>> responseChannel, optional<uint32_t> echoRequestHandle,
  std::unique_ptr<Structure> additionalHeader)
{
  if (detail)
    statusCode = StatusCode{statusCode.value(), std::move(detail)};
  detail = statusCode.shared_detail();

  // No StatusCode masking at the session layer: the generic-error hardening applies only during
  // SecureChannel establishment, not to services over an established channel (OPC 10000-2 6.3;
  // OPC 10000-4 Table 18 enumerates the specific ActivateSession codes). Masking stays in the
  // OpenSecureChannel path.
  const auto& wireStatus = statusCode;

  // Log the fault at debug. Masking is not applied at the session layer (see above), so wireStatus
  // always equals statusCode here - there is no masked-for-wire case to distinguish.
  if (auto deps = mDependencies.lock())
  {
    auto logger = deps->logger().with_category("session");
    if (statusCode.is_bad())
    {
      if (detail)
      {
        logger.debug({{"request_id", std::to_string(requestId)},
                       {"status", fmt::format("0x{:08x}", statusCode.as_uint32())},
                       {"error", to_string(*detail)}},
          "Service fault");
      }
      else
      {
        logger.debug({{"request_id", std::to_string(requestId)},
                       {"status", fmt::format("0x{:08x}", statusCode.as_uint32())}},
          "Service fault");
      }
    }
  }

  // Echo the request's RequestHandle into the fault header (Part 4 7.28: the ResponseHeader
  // RequestHandle must mirror the request). The handle is tracked per requestId for every dispatched
  // service (incl. ActivateSession) and for CreateSession; absent it (truly unknown request) the
  // handle stays 0.
  RequestHeader echoHeader;
  if (echoRequestHandle)
  {
    // A request refused before it was recorded (RequestIdInFlight) echoes its own handle; the handle
    // recorded under that requestId belongs to the request that holds the id.
    echoHeader.request_handle() = *echoRequestHandle;
  }
  else if (auto handleIt = mRequestHandlesByRequestId.find(requestId);
           handleIt != mRequestHandlesByRequestId.end())
  {
    echoHeader.request_handle() = handleIt->second;
  }
  auto serviceFault = stack_utils::create_service_fault(&echoHeader, wireStatus);
  if (additionalHeader)
    serviceFault->response_header().additional_header() = std::move(additionalHeader);

  // Serialize ErrorDetail to DiagnosticInfo if the client requested diagnostics.
  if (detail && returnDiagnostics != 0 && mSessionInfo)
  {
    auto securityCtx = mSessionInfo->diagnostic_security_context();
    DiagnosticCollector collector{returnDiagnostics, securityCtx};
    collector.set_service_detail(wireStatus);
    collector.apply_to(serviceFault->response_header());
  }

  auto sc = responseChannel ? responseChannel->lock()
                            : (mSecureChannelInfo ? mSecureChannelInfo->secure_channel().lock() : nullptr);
  if (sc)
  {
    sc->send_response_message(std::make_pair(requestId, serviceFault));
  }
  else
  {
    // Mirror success-path fallback (close_internal, cancel, etc.): when no live secure
    // channel is attached, queue the fault response so the harness / late polling can
    // still observe it. Avoids silent fault loss when the channel has gone away.
    enqueue_response(std::make_pair(requestId, serviceFault));
  }
}

void Session::build_channel_bound_data_async(ChannelBoundSignature signature,
  const SecurityPolicy& decidingPolicy, const SecureChannelInfo& channel,
  std::function<void(ByteStringResult)> callback)
{
  try
  {
    auto deps = mDependencies.lock();
    check(deps);
    // The channel bound method "always uses the leaf Certificate" (OPC 10000-4 section 6.1.8).
    const auto leaf = [](const shared_ptr<const X509Certificate>& certificate)
    {
      return certificate ? certificate->der_encoding() : ByteString{};
    };
    ChannelBoundSignatureInputs signatureInputs{.channelThumbprint = channel.channel_thumbprint(),
      .clientNonce = mClientNonce,
      .serverNonce = mServerNonce,
      .serverCertificate = leaf(mSelectedServerCertAndKey.certificate),
      .serverChannelCertificate = leaf(channel.server_certificate()),
      .clientCertificate = leaf(mClientCertificate),
      .clientChannelCertificate = leaf(channel.client_certificate())};
    build_channel_bound_signature_data_async(signature,
      decidingPolicy.certificate_thumbprint_algorithm(),
      deps->crypto(),
      mStrand,
      mLogger,
      std::move(signatureInputs),
      std::move(callback));
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(ByteStringResult{er, er.shared_detail()});
  }
}

void Session::create_server_signature_async(
  span<const byte> clientNonce, std::function<void(SignatureDataResult)> callback)
{
  try
  {
    check(mSecureChannelInfo, Status::BadInvalidState);
    const SecureChannelInfo& channelInfo = mSecureChannelInfo.value();
    auto policy = SecurityPolicy::create(channelInfo.security_policy()->id());

    // OPC 10000-4 section 6.1.8: with SecureChannelEnhancements the ServerSignature is channel bound (Table
    // 101).
    if (policy->secure_channel_enhancements())
    {
      auto me = weak_from_this();
      build_channel_bound_data_async(ChannelBoundSignature::Server,
        *policy,
        channelInfo,
        [me, policy, callback = std::move(callback)](ByteStringResult data) mutable
        {
          auto self = me.lock();
          if (!self)
          {
            callback(SignatureDataResult{Status::BadSessionClosed});
            return;
          }
          if (!data.is_good())
          {
            callback(SignatureDataResult{data.status_code(), data.shared_detail()});
            return;
          }
          self->sign_server_signature_async(std::move(policy), std::move(data).value(), std::move(callback));
        });
      return;
    }

    // Legacy (Table 102): ClientCertificate | ClientNonce.
    ByteString dataToSign = mClientCertificate ? mClientCertificate->der_encoding() : ByteString{};
    auto nonceUint =
      span<const uint8_t>{reinterpret_cast<const uint8_t*>(clientNonce.data()), clientNonce.size()};
    std::ranges::copy(nonceUint, std::back_inserter(dataToSign));
    sign_server_signature_async(std::move(policy), std::move(dataToSign), std::move(callback));
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(SignatureDataResult{er, er.shared_detail()});
  }
}

void Session::sign_server_signature_async(
  shared_ptr<SecurityPolicy> policy, ByteString dataToSign, std::function<void(SignatureDataResult)> callback)
{
  try
  {
    auto certAndKeys = stack_utils::get_local_cert_and_keys(mServerCertificates, policy->id());
    check(certAndKeys.keys);

    auto deps = mDependencies.lock();
    check(deps);

    auto me = weak_from_this();
    // Table 174: the algorithm URI is empty for a policy with SecureChannelEnhancements.
    auto algorithmUri =
      policy->secure_channel_enhancements() ? String{} : String{policy->asymmetric_signature_algorithm_uri()};
    auto pinned = std::make_shared<const ByteString>(std::move(dataToSign));
    deps->crypto()->asymmetric_sign_async(pinned,
      policy->asymmetric_signature_algorithm(),
      certAndKeys.keys,
      *pinned,
      [me, algorithmUri, callback = std::move(callback)](ByteStringResult result) mutable
      {
        auto self = me.lock();
        if (!self)
        {
          callback(SignatureDataResult{Status::BadSessionClosed});
          return;
        }
        ua::async::post_borrowing(self.get(),
          self->mStrand,
          self->mLogger,
          std::move(callback),
          SignatureDataResult{Status::BadSessionClosed},
          [algorithmUri = std::move(algorithmUri), result = std::move(result)](
            Session&, std::function<void(SignatureDataResult)> postCallback) mutable
          {
            if (!result.is_good())
            {
              postCallback(SignatureDataResult{Status::BadApplicationSignatureInvalid,
                make_error_detail("SigningFailed",
                  "Could not sign asymmetric message for server signature",
                  "Session",
                  security_internal::not_good_answer_detail(result.status_code(), "Session"))});
              return;
            }
            SignatureData signatureData;
            signatureData.signature() = std::move(result).value();
            signatureData.algorithm() = std::move(algorithmUri);
            postCallback(SignatureDataResult{std::move(signatureData)});
          })();
      });
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(SignatureDataResult{er, er.shared_detail()});
  }
}

void Session::generate_ecc_ephemeral_key_async(std::function<void(VoidResult)> callback)
{
  try
  {
    auto deps = mDependencies.lock();
    check(deps);
    auto crypto = deps->crypto();
    check(crypto);

    const auto ephemeralKeyAlgorithm =
      SecurityPolicy::create(mEccUserTokenPolicyId)->ephemeral_key_algorithm();
    if (ephemeralKeyAlgorithm == EphemeralKeyAlgorithm::Invalid)
    {
      callback(VoidResult{Status::BadInvalidArgument,
        make_error_detail("InvalidEccPolicy",
          "ECDHPolicyUri does not refer to a security policy with an ephemeral key algorithm",
          "Session")});
      return;
    }

    auto me = weak_from_this();
    crypto->create_ephemeral_keys_async(ephemeralKeyAlgorithm,
      [me, callback = std::move(callback)](Crypto::EphemeralKeyPairResult result) mutable
      {
        auto lockedSelf = me.lock();
        if (!lockedSelf)
        {
          callback(VoidResult{Status::BadSessionClosed});
          return;
        }
        ua::async::post_borrowing(lockedSelf.get(),
          lockedSelf->mStrand,
          lockedSelf->mLogger,
          std::move(callback),
          VoidResult{Status::BadSessionClosed},
          [result = std::move(result)](Session& self, std::function<void(VoidResult)> postCallback) mutable
          {
            if (!result.is_good())
            {
              // The pair is stored only from a Good answer. An Uncertain one is refused as a failure, so
              // no caller signs and sends the key the Session held before.
              const StatusCode failure = ua::security_internal::not_good_answer(
                result.status_code(), Status::BadInternalError, "Session");
              postCallback(VoidResult{failure,
                make_error_detail("EphemeralKeyGenerationFailed",
                  "Failed to generate ECC ephemeral key pair for user token encryption",
                  "Session",
                  failure.shared_detail())});
              return;
            }
            auto ephemeral = std::move(result).value();
            // The move frees the previous private key's buffer; clear it first (DEF-4: secrets are
            // scrubbed).
            ua::security::secure_clear(self.mEccEphemeralPrivateKey);
            self.mEccEphemeralPrivateKey = std::move(ephemeral.privateKey);
            self.mEccEphemeralPublicKey = std::move(ephemeral.publicKey);
            postCallback(VoidResult{});
          })();
      });
  }
  catch (...)
  {
    auto er = ::ua::exception_to_status_code(std::current_exception());
    callback(VoidResult{er, er.shared_detail()});
  }
}

void Session::error_received_from_secure_channel(StatusCode status, shared_ptr<const ErrorDetail> detail)
{
  if (auto deps = mDependencies.lock())
  {
    auto logger = deps->logger().with_category("session");
    if (detail)
    {
      logger.warning({{"session_name", std::string_view{mSessionName}},
                       {"status", fmt::format("0x{:08x}", status.as_uint32())},
                       {"error", to_string(*detail)}},
        "Secure channel error");
    }
    else
    {
      logger.warning({{"session_name", std::string_view{mSessionName}},
                       {"status", fmt::format("0x{:08x}", status.as_uint32())}},
        "Secure channel error");
    }
  }

  if (mSessionState == State::Closed)
    return;

  // Detach from the dead channel but keep the session alive (P4-SS-0001, P4-SS-0012).
  // The session remains in Activated state so the client can reconnect on a new channel
  // and re-activate (P4-SS-0027). The existing timeout timer will clean up if no
  // reconnect arrives within the session timeout.
  if (mSecureChannelInfo)
  {
    if (auto sc = mSecureChannelInfo->secure_channel().lock())
      sc->unregister_session(mAuthenticationToken);
    mSecureChannelInfo.reset();
  }

  invalidate_post_response_actions_on_strand();

  // Discard the Publish requests that were queued on the now-dead channel. The client abandons them on
  // the channel break and resends fresh ones on the reconnect channel (Part 4 6.7); if they were left
  // queued, after re-activation a live subscription's NotificationMessage would be dispatched in reply to
  // one of these stale requestIds - which the client no longer has outstanding - so the client would drop
  // the response and the notification would be lost (subscriptions would appear not to survive a reconnect).
  // These requests never reach response_received, so release their per-request tracking here (otherwise it
  // would orphan and accumulate across reconnects).
  if (auto pipeline = mSubscriptionsPipeline.load())
  {
    for (const auto requestId : pipeline->discard_pending_publish_requests())
      release_request_tracking(requestId);
  }
}

void Session::error_received_from_secure_channel_if_current(uint64_t associationEpoch,
  weak_ptr<SecureChannel> reportingChannel, StatusCode status, shared_ptr<const ErrorDetail> detail)
{
  if (associationEpoch != mSecureChannelAssociationEpoch || !mSecureChannelInfo)
    return;

  const auto currentChannel = mSecureChannelInfo->secure_channel();
  if (currentChannel.owner_before(reportingChannel) || reportingChannel.owner_before(currentChannel))
    return;

  error_received_from_secure_channel(status, std::move(detail));
}

void Session::request_received_from_secure_channel_if_current(
  uint64_t associationEpoch, weak_ptr<SecureChannel> sourceChannel, Request request)
{
  const auto currentChannel =
    mSecureChannelInfo ? mSecureChannelInfo->secure_channel() : weak_ptr<SecureChannel>{};
  const bool sameChannel =
    !currentChannel.owner_before(sourceChannel) && !sourceChannel.owner_before(currentChannel);
  if (associationEpoch == mSecureChannelAssociationEpoch && mSecureChannelInfo && sameChannel)
  {
    request_received(std::move(request));
    return;
  }

  if (auto channel = sourceChannel.lock())
  {
    channel->send_response_message(std::make_pair(std::get<uint32_t>(request),
      stack_utils::create_service_fault(nullptr, Status::BadSecureChannelIdInvalid)));
  }
}

void Session::abandon_old_channel_requests(uint32_t activatingRequestId)
{
  // Part 4 5.6.3: once the new SecureChannel is accepted, requests via the old one are rejected. What the
  // old channel still had in flight can only be answered on that channel, so its tracking is released
  // here; the activating request is the new channel's only entry. Left in place, a stale entry would
  // refuse a new-channel request that reuses its id (RequestIdInFlight) and would count against
  // MaxRequestsPerSession. Pending Publish requests are discarded for the reason given at
  // discard_pending_publish_requests; the client resends them on the new channel.
  std::vector<uint32_t> stale;
  stale.reserve(mInFlightRequestsByRequestId.size());
  for (const auto& [requestId, request] : mInFlightRequestsByRequestId)
  {
    if (requestId != activatingRequestId)
    {
      stale.push_back(requestId);
    }
  }
  for (const auto requestId : stale)
  {
    release_request_tracking(requestId);
  }
  if (auto pipeline = mSubscriptionsPipeline.load())
  {
    for (const auto requestId : pipeline->discard_pending_publish_requests())
    {
      release_request_tracking(requestId);
    }
  }
}

void Session::release_request_tracking(uint32_t requestId)
{
  // Single source of truth for releasing a terminal or abandoned request. Callers decide whether to record
  // latency and emit a response; this helper only releases the request's strand-owned bookkeeping.
  mRequestStartTimes.erase(requestId);
  mRequestServiceKinds.erase(requestId);
  mInFlightRequestsByRequestId.erase(requestId);
  mAuthnUserByRequestId.erase(requestId);
  mAuthnEndpointByRequestId.erase(requestId);
  mReturnDiagnosticsByRequestId.erase(requestId);
  if (auto it = mRequestHandlesByRequestId.find(requestId); it != mRequestHandlesByRequestId.end())
  {
    mOutstandingRequestHandles.erase(it->second);
    mRequestHandlesByRequestId.erase(it);
  }
  mServiceCallsByRequestId.erase(requestId);
}

void Session::note_service_fault_error(uint32_t requestId, const std::shared_ptr<Structure>& responseMessage)
{
  if (!responseMessage || dynamic_cast<const ServiceFault*>(responseMessage.get()) == nullptr)
  {
    return;
  }
  auto kindIt = mRequestServiceKinds.find(requestId);
  if (kindIt == mRequestServiceKinds.end())
  {
    return;
  }
  auto& serviceCounter = counter_for_service(kindIt->second);
  serviceCounter.errorCount.fetch_add(1, std::memory_order_relaxed);
  if (&serviceCounter != &mCounters->totalRequests)
  {
    mCounters->totalRequests.errorCount.fetch_add(1, std::memory_order_relaxed);
  }
}

ServiceCounter& Session::counter_for_service(Session::ServiceKind kind)
{
  switch (kind)
  {
  case Session::ServiceKind::Read:
    return mCounters->read;
  case Session::ServiceKind::Write:
    return mCounters->write;
  case Session::ServiceKind::Browse:
    return mCounters->browse;
  case Session::ServiceKind::BrowseNext:
    return mCounters->browseNext;
  case Session::ServiceKind::Call:
    return mCounters->call;
  case Session::ServiceKind::TranslateBrowsePathsToNodeIds:
    return mCounters->translateBrowsePaths;
  case Session::ServiceKind::RegisterNodes:
    return mCounters->registerNodes;
  case Session::ServiceKind::UnregisterNodes:
    return mCounters->unregisterNodes;
  case Session::ServiceKind::CreateSubscription:
    return mCounters->createSubscription;
  case Session::ServiceKind::ModifySubscription:
    return mCounters->modifySubscription;
  case Session::ServiceKind::DeleteSubscriptions:
    return mCounters->deleteSubscriptions;
  case Session::ServiceKind::SetPublishingMode:
    return mCounters->setPublishingMode;
  case Session::ServiceKind::Publish:
    return mCounters->publish;
  case Session::ServiceKind::Republish:
    return mCounters->republish;
  case Session::ServiceKind::CreateMonitoredItems:
    return mCounters->createMonitoredItems;
  case Session::ServiceKind::DeleteMonitoredItems:
    return mCounters->deleteMonitoredItems;
  case Session::ServiceKind::ModifyMonitoredItems:
    return mCounters->modifyMonitoredItems;
  case Session::ServiceKind::SetMonitoringMode:
    return mCounters->setMonitoringMode;
  case Session::ServiceKind::SetTriggering:
    return mCounters->setTriggering;
  case Session::ServiceKind::TransferSubscriptions:
    return mCounters->transferSubscriptions;
  case Session::ServiceKind::AddNodes:
    return mCounters->addNodes;
  case Session::ServiceKind::AddReferences:
    return mCounters->addReferences;
  case Session::ServiceKind::DeleteNodes:
    return mCounters->deleteNodes;
  case Session::ServiceKind::DeleteReferences:
    return mCounters->deleteReferences;
  case Session::ServiceKind::HistoryRead:
    return mCounters->historyRead;
  case Session::ServiceKind::HistoryUpdate:
    return mCounters->historyUpdate;
  case Session::ServiceKind::DiscoveryFindServers:
  case Session::ServiceKind::DiscoveryFindServersOnNetwork:
  case Session::ServiceKind::DiscoveryGetEndpoints:
  case Session::ServiceKind::Unknown:
  default:
    // Discovery services and unknown kinds are counted only in total_requests.
    return mCounters->totalRequests;
  }
}

std::shared_ptr<SessionCounters> Session::counters() const
{
  return mCounters;
}

std::shared_ptr<SessionDescriptiveState> Session::descriptive_state() const
{
  return mDescriptiveState;
}

std::shared_ptr<SessionSecurityState> Session::security_state() const
{
  return mSecurityState;
}

SessionHealthSnapshot Session::health_snapshot() const
{
  SessionHealthSnapshot snap;

  // Read identity from atomic snapshot (safe from any thread).
  auto identity = mIdentity.load();
  if (identity)
  {
    snap.sessionId = identity->sessionId;
    snap.sessionName = identity->sessionName;
  }

  snap.unauthorizedRequestCount = mCounters->unauthorizedRequestCount.load(std::memory_order_relaxed);

  auto loadSc = [](const ServiceCounter& sc) -> SessionHealthSnapshot::ServiceCount
  {
    return {sc.totalCount.load(std::memory_order_relaxed), sc.errorCount.load(std::memory_order_relaxed)};
  };

  snap.totalRequests = loadSc(mCounters->totalRequests);
  snap.read = loadSc(mCounters->read);
  snap.browse = loadSc(mCounters->browse);
  snap.browseNext = loadSc(mCounters->browseNext);
  snap.write = loadSc(mCounters->write);
  snap.call = loadSc(mCounters->call);
  snap.historyRead = loadSc(mCounters->historyRead);
  snap.historyUpdate = loadSc(mCounters->historyUpdate);
  snap.createMonitoredItems = loadSc(mCounters->createMonitoredItems);
  snap.modifyMonitoredItems = loadSc(mCounters->modifyMonitoredItems);
  snap.setMonitoringMode = loadSc(mCounters->setMonitoringMode);
  snap.setTriggering = loadSc(mCounters->setTriggering);
  snap.deleteMonitoredItems = loadSc(mCounters->deleteMonitoredItems);
  snap.createSubscription = loadSc(mCounters->createSubscription);
  snap.modifySubscription = loadSc(mCounters->modifySubscription);
  snap.setPublishingMode = loadSc(mCounters->setPublishingMode);
  snap.publish = loadSc(mCounters->publish);
  snap.republish = loadSc(mCounters->republish);
  snap.transferSubscriptions = loadSc(mCounters->transferSubscriptions);
  snap.deleteSubscriptions = loadSc(mCounters->deleteSubscriptions);
  snap.addNodes = loadSc(mCounters->addNodes);
  snap.addReferences = loadSc(mCounters->addReferences);
  snap.deleteNodes = loadSc(mCounters->deleteNodes);
  snap.deleteReferences = loadSc(mCounters->deleteReferences);
  snap.translateBrowsePaths = loadSc(mCounters->translateBrowsePaths);
  snap.queryFirst = loadSc(mCounters->queryFirst);
  snap.queryNext = loadSc(mCounters->queryNext);
  snap.registerNodes = loadSc(mCounters->registerNodes);
  snap.unregisterNodes = loadSc(mCounters->unregisterNodes);

  // Subscription/MI gauges. health_snapshot() runs OFF the session strand (any thread), so load the
  // atomic handle (acquire) to get a safe shared_ptr copy that cannot race the strand's lazy create;
  // the pointee's counters are themselves atomic.
  if (auto pipeline = mSubscriptionsPipeline.load())
  {
    snap.currentSubscriptionCount = pipeline->atomic_subscription_count();
    snap.currentMonitoredItemsCount = pipeline->atomic_total_monitored_item_count();
  }

  return snap;
}

Session::Session(weak_ptr<SessionDependencies> dependencies, boost::asio::any_io_executor executor,
  SecureChannelInfo secureChannelInfo)
  : mDependencies(dependencies), mCloseEventChannelId(secureChannelInfo.channel_id()),
    mCloseEventRemoteAddress(secureChannelInfo.remote_address()),
    mSessionInfo(make_shared<SessionInfo>(dependencies)), mExecutor(executor),
    mStrand{boost::asio::make_strand(mExecutor)}, mSecureChannelInfo{secureChannelInfo}
{
  // Populate the typed service-dispatch table before any code path that could
  // post to `mStrand`. The map is then effectively const-after-construction.
  register_service_handlers();

  if (auto deps = mDependencies.lock())
  {
    mMaxBufferedResponses = deps->server_configuration().resourceLimits.bufferedResponsesPerSession;
    mLogger = deps->logger().with_category("session");
    mLogger.debug({{"channel_id", uint64_t(secureChannelInfo.channel_id())}}, "Session created");
  }
}

Session::~Session()
{
  // The ECC EphemeralKey's private half is a secret like any other (DEF-4).
  ua::security::secure_clear(mEccEphemeralPrivateKey);

  if (mState.load(std::memory_order_acquire) == State::Invalid)
    return;

  release_registered_nodes();

  auto deps = mDependencies.lock();
  if (!deps)
    return;

  deps->logger().with_category("session").debug({{"session_id", to_string(mSessionId)}}, "Session destroyed");

  auto eh = deps->observer();
  if (!eh)
    return;

  SessionEventInfo info;
  info.sessionId = mSessionId;
  info.sessionName = mSessionName;
  info.secureChannelId = mCloseEventChannelId;
  info.remoteAddress = mCloseEventRemoteAddress;
  if (auto user = mSessionInfo->user_identity())
    info.clientUserId = user->userId;
  detail::emit_event(deps->logger(),
    eh,
    [&] { eh->on_session_closed(info, StatusCode{mCloseReason.load(std::memory_order_acquire)}); });
}

void Session::set_close_reason(StatusCode reason)
{
  mCloseReason.store(reason.value(), std::memory_order_release);
}

StatusCode Session::handle_unexpected_exception(const char* site, std::exception_ptr ex)
{
  auto er = ::ua::exception_to_status_code(std::move(ex));
  auto sc = er;

  if (auto deps = mDependencies.lock())
  {
    auto logger = deps->logger().with_category("session");
    log_exception(logger, LogLevel::Error, site, er);

    auto statusHex = fmt::format("0x{:08x}", sc.as_uint32());
    auto diagnosticDescription = er.shared_detail()
                                   ? fmt::format("{}: {}", site, to_string(*er.shared_detail()))
                                   : fmt::format("{}: {}", site, statusHex);

    auto eh = deps->observer();
    detail::emit_event(deps->logger(), eh, [&] { eh->on_internal_error(sc, diagnosticDescription); });
  }

  return sc;
}

Session::SessionInfo::SessionInfo(weak_ptr<SessionDependencies> dependencies) : mDependencies(dependencies)
{}

AccessIdentityRegistry& SessionDependencies::access_identity_registry()
{
  std::call_once(mAccessIdentityRegistryOnce,
    [this]
    {
      mAccessIdentityRegistry =
        std::make_unique<AccessIdentityRegistry>(address_space(), server_configuration().maxAccessIdentities);
    });
  return *mAccessIdentityRegistry;
}

ua::NodeId Session::SessionInfo::session_id() const
{
  const ReadLock lock(mMutex);
  return mSessionId;
}

std::shared_ptr<const ua::server::EndpointSecurityContext> Session::SessionInfo::endpoint_security() const
{
  const ReadLock lock(mMutex);
  return mEndpointSecurity;
}

std::shared_ptr<const ua::server::UserIdentity> Session::SessionInfo::user_identity() const
{
  const ReadLock lock(mMutex);
  return mUserIdentity;
}

std::shared_ptr<const ua::AccessIdentity> Session::SessionInfo::access_identity() const
{
  auto result = access_identity_result();
  return result.is_good() ? std::move(result).value() : nullptr;
}

std::shared_ptr<const ua::CallerInfo> Session::SessionInfo::caller() const
{
  const ReadLock lock(mMutex);
  return mCaller;
}

std::shared_ptr<const ua::AccessIdentity> Session::SessionInfo::committed_access_identity() const
{
  const ReadLock lock(mMutex);
  return mAccessIdentity;
}

Result<std::shared_ptr<const ua::AccessIdentity>> Session::SessionInfo::access_identity_result() const
{
  for (size_t attempt = 0; attempt < 3; ++attempt)
  {
    std::shared_ptr<const ua::AccessIdentity> current;
    std::shared_ptr<const ua::server::UserIdentity> user;
    std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint;
    ua::NodeId sessionId;
    {
      const ReadLock lock(mMutex);
      current = mAccessIdentity;
      user = mUserIdentity;
      endpoint = mEndpointSecurity;
      sessionId = mSessionId;
    }

    auto sessionDependencies = mDependencies.lock();
    if (!sessionDependencies)
    {
      return Result<std::shared_ptr<const ua::AccessIdentity>>{StatusCode{Status::BadUserAccessDenied},
        ErrorDetail::build("AccessIdentityRefreshDependenciesExpired",
          "The active Session's authorization dependencies are unavailable",
          "Session")};
    }
    const auto& roleConfiguration = sessionDependencies->components().roleConfiguration;
    if (!roleConfiguration)
    {
      if (current)
      {
        return Result<std::shared_ptr<const ua::AccessIdentity>>{std::move(current)};
      }
      return Result<std::shared_ptr<const ua::AccessIdentity>>{StatusCode{Status::BadUserAccessDenied},
        ErrorDetail::build(
          "AccessIdentityMissing", "The active Session has no committed access identity", "Session")};
    }

    auto refreshed =
      sessionDependencies->access_identity_registry().refresh(current, user, endpoint, *roleConfiguration);
    if (!refreshed.is_good())
    {
      const auto failure = refreshed.status_code();
      if (const auto& detail = refreshed.shared_detail())
      {
        sessionDependencies->logger()
          .with_category("authorization")
          .error({{"status", to_string(failure)}, {"detail", to_string(*detail)}},
            "Active Session Role refresh failed closed");
      }
      else
      {
        sessionDependencies->logger()
          .with_category("authorization")
          .error({{"status", to_string(failure)}}, "Active Session Role refresh failed closed");
      }
      return refreshed;
    }
    auto replacement = std::move(refreshed).value();
    // Built before the lock is taken, and only for a new identity; used only when the refresh is committed.
    auto replacementCaller =
      replacement != current ? make_caller(replacement, sessionId, user.get(), endpoint.get()) : nullptr;

    const WriteLock lock(mMutex);
    if (mAccessIdentity != current || mUserIdentity != user || mEndpointSecurity != endpoint)
    {
      continue;
    }
    if (mAccessIdentity != replacement)
    {
      mCaller = std::move(replacementCaller);
    }
    mAccessIdentity = replacement;
    return Result<std::shared_ptr<const ua::AccessIdentity>>{std::move(replacement)};
  }

  return Result<std::shared_ptr<const ua::AccessIdentity>>{StatusCode{Status::BadUserAccessDenied},
    ErrorDetail::build("AccessIdentityRefreshRaced",
      "The Session security context changed repeatedly while Roles were being refreshed",
      "Session")};
}

void Session::SessionInfo::set_security_context(ua::NodeId sessionId,
  std::shared_ptr<const ua::server::EndpointSecurityContext> sec,
  std::shared_ptr<const ua::server::UserIdentity> user, std::shared_ptr<const ua::AccessIdentity> identity)
{
  auto callerInfo = make_caller(identity, sessionId, user.get(), sec.get());
  const WriteLock lock(mMutex);
  mSessionId = std::move(sessionId);
  mEndpointSecurity = std::move(sec);
  mUserIdentity = std::move(user);
  mAccessIdentity = std::move(identity);
  mCaller = std::move(callerInfo);
}

void Session::release_registered_nodes() noexcept
{
  try
  {
    auto deps = mDependencies.lock();
    if (!deps)
    {
      return;
    }
    mSessionInfo->registered_nodes()->release_all(deps->address_space());
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

AddressSpace Session::SessionInfo::address_space() const
{
  const ReadLock lock(mMutex);
  auto deps = mDependencies.lock();
  if (!deps)
  {
    throw UaException{Status::BadInternalError,
      make_error_detail(
        "SessionDependenciesDestroyed", "Session dependencies have been destroyed", "SessionInfo")};
  }
  auto as = deps->address_space().lock();
  if (!as)
  {
    throw UaException{Status::BadInternalError,
      make_error_detail("AddressSpaceDestroyed", "Address space has been destroyed", "SessionInfo")};
  }
  return *as;
}

const ::ua::ApplicationConfig& Session::SessionInfo::configuration() const
{
  const ReadLock lock(mMutex);
  auto deps = mDependencies.lock();
  if (!deps)
  {
    throw UaException{Status::BadInternalError,
      make_error_detail("SessionDependenciesDestroyed",
        "Session dependencies destroyed while retrieving configuration",
        "Session")};
  }
  return deps->configuration();
}

const ::ua::server::ServerConfig& Session::SessionInfo::server_configuration() const
{
  const ReadLock lock(mMutex);
  auto deps = mDependencies.lock();
  if (!deps)
  {
    throw UaException{Status::BadInternalError,
      make_error_detail("SessionDependenciesDestroyed",
        "Session dependencies destroyed while retrieving server configuration",
        "Session")};
  }
  return deps->server_configuration();
}

DiagnosticSecurityContext Session::SessionInfo::diagnostic_security_context() const
{
  const ReadLock lock(mMutex);
  auto deps = mDependencies.lock();
  if (!deps)
  {
    return {};  // default: unauthenticated, no diagnostics
  }

  const auto& policy = deps->server_configuration().diagnosticPolicy;

  // set_security_context() populates mSessionId after activation. A null
  // session ID means the session has not been activated yet (pre-auth).
  if (!mSessionId.is_null() && mEndpointSecurity && mUserIdentity)
  {
    // The Roles this Session was granted (a handful of NodeIds, scanned once per request).
    const bool holdsSecurityAdmin = mAccessIdentity && std::ranges::find(mAccessIdentity->granted_roles(),
                                                         NodeId{ObjectId::WellKnownRole_SecurityAdmin}) !=
                                                         mAccessIdentity->granted_roles().end();
    return detail::make_diagnostic_security_context(
      *mEndpointSecurity, *mUserIdentity, policy, holdsSecurityAdmin);
  }

  // Pre-auth: no diagnostics, masking enabled on secured channels.
  DiagnosticSecurityContext ctx;
  ctx.authenticated = false;
  ctx.securedChannel =
    (mEndpointSecurity && mEndpointSecurity->messageSecurityMode != ua::MessageSecurityMode::None);
  ctx.effectiveLevel = ServerConfig::DiagnosticPolicy::Level::None;
  ctx.maskPreAuthErrors = ctx.securedChannel;
  return ctx;
}

Logger Session::SessionInfo::logger() const
{
  const ReadLock lock(mMutex);
  auto deps = mDependencies.lock();
  if (!deps)
  {
    return {};
  }
  return deps->logger();
}

std::shared_ptr<EventSink> Session::SessionInfo::event_sink() const
{
  const ReadLock lock(mMutex);
  auto deps = mDependencies.lock();
  if (!deps)
    return nullptr;
  return deps->event_bus_shared();
}

uint32_t Session::SessionInfo::max_response_message_size() const
{
  return mMaxResponseMessageSize.load(std::memory_order_acquire);
}

void Session::SessionInfo::set_max_response_message_size(uint32_t maxResponseMessageSize)
{
  mMaxResponseMessageSize.store(maxResponseMessageSize, std::memory_order_release);
}

weak_ptr<SessionDependencies> Session::SessionInfo::dependencies() const
{
  const ReadLock lock(mMutex);
  return mDependencies;
}

void Session::set_diagnostics_enabled(bool enabled, std::shared_ptr<void> settled)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [enabled, settled = std::move(settled)](Session& self) mutable
    {
      try
      {
        // A closed Session keeps no diagnostics object, whatever the flag says.
        self.want_diagnostics_object(enabled && self.mSessionState != State::Closed, std::move(settled));
      }
      catch (...)
      {
        self.handle_unexpected_exception("Session::set_diagnostics_enabled", std::current_exception());
      }
    })();
}

std::shared_ptr<void> Session::release_token(Logger logger, std::function<void()> action)
{
  // A shared_ptr runs its deleter once, when the last copy goes, and does so for a null pointer too.
  return std::shared_ptr<void>(nullptr,
    [run = ua::async::guarded(std::move(logger), std::move(action))](void*) mutable noexcept { run(); });
}

std::optional<NodeId> Session::diagnostics_object_id() const
{
  if (!mDiagnosticsHelper || mDiagnosticsChangeInFlight)
  {
    return std::nullopt;
  }
  return mDiagnosticsHelper->node_id();
}

void Session::want_diagnostics_object(bool wanted, std::shared_ptr<void> settled)
{
  mDiagnosticsWanted = wanted;
  // Kept unconditionally: a release token holds a null pointer, so it tests false however live it is.
  mDiagnosticsSettledWaiters.push_back(std::move(settled));
  reconcile_diagnostics_object();
}

void Session::reconcile_diagnostics_object()
{
  if (mDiagnosticsChangeInFlight)
  {
    return;  // Its completion reconciles again.
  }
  if (mDiagnosticsWanted && !mDiagnosticsHelper)
  {
    if (start_diagnostics_object_creation())
    {
      return;
    }
  }
  else if (!mDiagnosticsWanted && mDiagnosticsHelper)
  {
    start_diagnostics_object_removal();
    return;
  }
  release_diagnostics_waiters();
}

bool Session::start_diagnostics_object_creation()
{
  auto deps = mDependencies.lock();
  auto as = deps ? deps->address_space().lock() : std::optional<AddressSpace>{};
  if (!as)
  {
    return false;
  }

  // Parent: Server.ServerDiagnostics.SessionsDiagnosticsSummary (i=3706)
  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  const auto browseName = QualifiedName{0, mSessionName.empty() ? "Session" : mSessionName};

  {
    const std::lock_guard lock{mSecurityState->mutex};
    mSecurityState->sessionId = mSessionId;
  }

  InstantiationOptions options;
  options.nodeIdAllocator = guid_node_id_allocator();

  // Created asynchronously: a synchronous create would block the Session strand on address-space work
  // posted to that same executor, a deadlock on a single-threaded server.
  mDiagnosticsChangeInFlight = true;
  auto me = weak_from_this();
  SessionDiagnosticsHelper::create_async(*as,
    parent,
    browseName,
    mCounters,
    mSecurityState,
    mDescriptiveState,
    options,
    [me](SessionDiagnosticsHelperResult result) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
      {
        return;
      }
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [result = std::move(result)](Session& self) mutable
        {
          self.mDiagnosticsChangeInFlight = false;
          if (!result.is_good())
          {
            auto sessionDeps = self.mDependencies.lock();
            if (sessionDeps)
            {
              sessionDeps->logger().warning(
                "Failed to create per-session diagnostic object: {}", ua::to_string(result.status_code()));
            }
            // Not retried here: the next change of the flag tries again.
            if (self.mDiagnosticsWanted)
            {
              self.release_diagnostics_waiters();
            }
            else
            {
              self.reconcile_diagnostics_object();
            }
            return;
          }

          // Adopted even when it is no longer wanted, so that its removal is one the reconcile waits for.
          self.mDiagnosticsHelper = std::move(result).value();
          self.reconcile_diagnostics_object();
        })();
    });
  return true;
}

void Session::start_diagnostics_object_removal()
{
  auto deps = mDependencies.lock();
  auto addressSpace = deps ? deps->address_space().lock() : std::optional<AddressSpace>{};
  if (!addressSpace)
  {
    mDiagnosticsHelper.reset();
    release_diagnostics_waiters();
    return;
  }

  // Taken over from the helper, whose destructor would remove the subtree without telling anyone when.
  const NodeId root = mDiagnosticsHelper->node_id();
  mDiagnosticsHelper->release();
  mDiagnosticsHelper.reset();

  mDiagnosticsChangeInFlight = true;
  auto me = weak_from_this();
  addressSpace->delete_node_async(root,
    /*deleteForwardHierarchicallyReferencedNodes=*/true,
    ReferenceHalves::Both,
    [me](VoidResult)
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
      {
        return;
      }
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [](Session& self)
        {
          // A failed removal still settles: the subtree is no longer the Session's, and no waiter may hang.
          self.mDiagnosticsChangeInFlight = false;
          self.reconcile_diagnostics_object();
        })();
    });
}

void Session::release_diagnostics_waiters()
{
  // Moved out first: releasing a waiter may run code that reaches this Session again.
  auto waiters = std::exchange(mDiagnosticsSettledWaiters, {});
}

void Session::remove_diagnostics_object_async(std::function<void()> then)
{
  want_diagnostics_object(false, release_token(mLogger, std::move(then)));
}

void Session::destroy_diagnostics_object()
{
  // Teardown: the helper's destructor removes the subtree, and nothing waits on a Session that is going.
  // A creation still in flight is adopted on completion and then removed by the reconcile.
  mDiagnosticsWanted = false;
  mDiagnosticsHelper.reset();
  release_diagnostics_waiters();
}

}  // namespace ua::server
