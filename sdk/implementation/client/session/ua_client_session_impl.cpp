// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Client Session - strand-serialized component. Lifecycle (Create/Activate/Close) is driven
// by one coroutine body for CreateSession and a named continuation chain for ActivateSession
// start_*/on_* methods, each re-posted to the private strand), not coroutines.
//
// Session lifecycle flow:
//   create() -> strand post -> create_session_internal() (named continuation chain)
//     -> sends CreateSessionRequest through SecureChannel
//     -> processes response (validates server signature for authenticated channels)
//     -> transitions to Created state, fires onCreated callback
//
//   activate() -> strand post -> activate_internal() (named continuation chain)
//     -> builds user token, sends ActivateSessionRequest
//     -> processes response, transitions to Active state, fires activate callback
//
// Service request flow:
//   send_request() -> strand post -> stamp auth token -> SecureChannelImpl::send_request()
//     -> response callback -> deliver to caller

#include "ua_certificate_validation_paths.h"
#include "ua_server_cert_validator.h"
#include "ua_x509_certificate.h"
#include "ua_exceptions.h"
#include "ua_client_session_impl.h"
#include "ua_client_answer_status.h"
#include "ua_security_policy_internal.h"
#include "ua_callback_safety.h"
#include "ua_certificate_hostname.h"

#include "ua_client_secure_channel_impl.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_additional_parameters_type.h"
#include "ua_close_session_request.h"
#include "ua_close_session_response.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_defines.h"
#include "ua_ephemeral_key_type.h"
#include "ua_error_detail.h"
#include "ua_key_value_pair.h"
#include "ua_log_exception.h"
#include "ua_on_strand.h"
#include "ua_qualified_name.h"
#include "ua_signature_data.h"
#include "ua_user_token_encryption.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_url_parser.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_response_diagnostics.h"

#include "fmt/format.h"

#include <algorithm>

namespace ua::client
{

namespace
{

/// Returns the session strand, asserting the construction-time invariant that it is
/// engaged. `mStrand` is emplaced once in the constructor and never reset, so this
/// accessor never throws in practice; it exists to make that invariant provable to the
/// static analyzer at every use site (the `[[noreturn]]` throw narrows the optional so
/// the dereference is checked).
boost::asio::strand<boost::asio::any_io_executor>& engaged_strand(
  std::optional<boost::asio::strand<boost::asio::any_io_executor>>& strand)
{
  if (!strand.has_value())
  {
    ua::throw_empty_optional_check(ua::Status::BadInternalError);
  }
  return *strand;
}

ua::ByteString ordered_certificate_chain_der(
  const ua::X509Certificate& leaf, const ua::CertificateList& issuerCandidates)
{
  ua::ByteString chain = leaf.der_encoding();
  const ua::X509Certificate* current = &leaf;
  std::vector<bool> used(issuerCandidates.size(), false);

  for (size_t depth = 0; depth < issuerCandidates.size(); ++depth)
  {
    size_t issuerIndex = issuerCandidates.size();
    for (size_t candidateIndex = 0; candidateIndex < issuerCandidates.size(); ++candidateIndex)
    {
      const auto& candidate = issuerCandidates[candidateIndex];
      if (!used[candidateIndex] && candidate && candidate->thumbprint() != current->thumbprint() &&
          current->issued_by(*candidate))
      {
        issuerIndex = candidateIndex;
        break;
      }
    }
    if (issuerIndex == issuerCandidates.size())
    {
      break;
    }

    used[issuerIndex] = true;
    const auto& issuer = issuerCandidates[issuerIndex];
    const auto issuerDer = issuer->der_encoding();
    std::ranges::copy(issuerDer, std::back_inserter(chain));
    current = issuer.get();
    if (issuer->self_signed())
    {
      break;
    }
  }
  return chain;
}

struct ServerSignatureVerificationInput
{
  std::shared_ptr<const ua::X509Certificate> serverCertificate;
  ua::ByteString signedData;
  ua::ByteString signature;
};

}  // namespace

namespace
{

/// The server's EphemeralKeyType from a response's AdditionalHeader: the public key and the signature
/// the server placed on it (Part 4 7.15 Table 140). Both empty when the header carries none.
struct ServerEphemeralKey
{
  ua::ByteString publicKey;
  ua::ByteString signature;
};

ServerEphemeralKey extract_server_ephemeral_key(const ua::Structure* additionalHeader)
{
  if (!additionalHeader)
  {
    return {};
  }

  const auto* additionalParams = dynamic_cast<const ua::AdditionalParametersType*>(additionalHeader);
  if (!additionalParams)
  {
    return {};
  }

  for (const auto& kv : additionalParams->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHKey")
    {
      if (const auto* ephemeralKey = kv.value().try_as<ua::EphemeralKeyType>())
      {
        return ServerEphemeralKey{ephemeralKey->public_key(), ephemeralKey->signature()};
      }
    }
  }

  return {};
}

/// Part 4 1.05.07 5.7.2 / 5.7.3: a serverNonce "shall have a length between 32 and 128 bytes inclusive".
constexpr std::size_t minimumServerNonceLength = ua::stack_utils::minimumSessionNonceLength;
constexpr std::size_t maximumServerNonceLength = ua::stack_utils::maximumSessionNonceLength;

}  // namespace

// --- Lifecycle ---

SessionImpl::SessionImpl(std::weak_ptr<SessionDependencies> deps, std::shared_ptr<SecureChannelImpl> channel,
  Config config, SecurityInfo securityInfo, CreatedCallback onCreated, ErrorCallback onError)
  : mDepsOwner(deps.lock()), mDeps(mDepsOwner), mConfig(config), mChannel(channel),
    mSecurityInfo(std::move(securityInfo)), mOnCreated(std::move(onCreated)), mOnError(std::move(onError)),
    mOnSessionError(std::move(config.onSessionError))
{
  set_return_diagnostics_override(mConfig.returnDiagnosticsOverride);
  auto d = mDeps.lock();
  check(d);

  mExecutor = d->executor();
  mStrand.emplace(boost::asio::make_strand(mExecutor));
}

SessionImpl::~SessionImpl()
{
  // RAII registry: unregister from the client-side cascading-shutdown
  // registry. No-op if the client is already gone.
  if (auto deps = mDeps.lock())
    deps->unregister_session(this);

  if (mTimeoutTimer)
  {
    mTimeoutTimer.cancel();
  }

  // Safety net: resolve any pending callbacks so callers (e.g. std::future::get()) never block forever.
  auto d = mDeps.lock();
  if (mOnCreated)
  {
    auto callback = std::move(mOnCreated);
    mOnCreated = nullptr;
    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::make_error_detail("SessionDestroyed", "Session destroyed while creating", "client::Session"));
    if (d)
      ua::detail::invoke_user_callback(
        d->logger(), callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
  }
  if (mActivateCallback)
  {
    auto callback = std::move(mActivateCallback);
    mActivateCallback = nullptr;
    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::make_error_detail("SessionDestroyed", "Session destroyed while activating", "client::Session"));
    if (d)
      ua::detail::invoke_user_callback(
        d->logger(), callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
  }
  if (!mCloseCallbacks.empty())
  {
    auto callbacks = std::exchange(mCloseCallbacks, {});
    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::make_error_detail("SessionDestroyed", "Session destroyed while closing", "client::Session"));
    for (auto& callback : callbacks)
    {
      if (d)
        ua::detail::invoke_user_callback(
          d->logger(), callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
      else
        ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
    }
  }
}

std::shared_ptr<SessionImpl> SessionImpl::create(std::weak_ptr<SessionDependencies> deps,
  std::shared_ptr<SecureChannelImpl> channel, Config config, SecurityInfo securityInfo,
  CreatedCallback onCreated, ErrorCallback onError)
{
  class Wrapper : public SessionImpl
  {
  public:
    Wrapper(std::weak_ptr<SessionDependencies> deps, std::shared_ptr<SecureChannelImpl> channel,
      Config config, SecurityInfo securityInfo, CreatedCallback onCreated, ErrorCallback onError)
      : SessionImpl(std::move(deps), std::move(channel), config, std::move(securityInfo),
          std::move(onCreated), std::move(onError))
    {}
  };

  auto impl = std::make_shared<Wrapper>(std::move(deps),
    std::move(channel),
    config,
    std::move(securityInfo),
    std::move(onCreated),
    std::move(onError));

  // RAII registry: register with the client (via the deps) immediately after
  // construction so cascading shutdown can find this session. The destructor
  // unregisters.
  if (auto lockedDeps = impl->mDeps.lock())
    lockedDeps->register_session(std::weak_ptr<SessionImpl>(impl));

  impl->initialise();
  return impl;
}

boost::asio::strand<boost::asio::any_io_executor>& SessionImpl::session_strand()
{
  return engaged_strand(mStrand);
}

void SessionImpl::initialise()
{
  ua::async::post_borrowing(this,
    engaged_strand(mStrand),
    logger(),
    [](SessionImpl& self)
    {
      try
      {
        self.mSessionState = SessionState::Creating;
        self.update_atomic_snapshots();
        self.create_session_internal();
      }
      catch (...)
      {
        self.handle_unexpected_exception("client::Session::initialise", std::current_exception());
      }
    })();
}

// --- Internal coroutines ---

void SessionImpl::create_session_internal()
{
  auto request = std::make_shared<ua::CreateSessionRequest>();
  request->requested_session_timeout() = mConfig.requestedSessionTimeoutMs;
  request->endpoint_url() = mConfig.endpointUrl;
  // OPC 10000-4 Table 15: sessionName is the human-readable name the server records for this session and
  // reports through its diagnostics and audit events. It is how an operator tells one client's session
  // from another's, so leaving it empty makes every session on the server anonymous.
  request->session_name() = mConfig.sessionName;

  // Fill application description from config.
  auto d = mDeps.lock();
  if (d)
  {
    auto& config = d->configuration();
    // OPC 10000-4 Table 15: maxResponseMessageSize is the session-level statement of the largest
    // response body this client will accept. DERIVED, never separately configured - the client
    // cannot accept a response larger than the MaxMessageSize it already advertised in Hello, so a
    // second settable knob for the same quantity could only contradict the first. 0 ("not used")
    // propagates unchanged. Honouring it is the server's choice (the standard says "should"); the
    // limit that is always enforced, in both directions, is the transport one.
    request->max_response_message_size() = config.stack_limits().connectionProtocolLimits.maxMessageSize;
    request->client_description().application_uri() = config.application_description_part().applicationUri;
    request->client_description().application_type() = ua::ApplicationType::Client;
    request->request_header().return_diagnostics() =
      return_diagnostics_for(request->request_header().return_diagnostics());
  }

  // For authenticated channels, attach the client certificate.
  if (mConfig.isAuthenticated && mSecurityInfo.clientCertificate)
  {
    // Decision 24: the leaf then its issuer chain in order (OPC 10000-6 section 6.2.6).
    request->client_certificate() = ua::detail::encode_certificate_field(
      mSecurityInfo.clientCertificate, mSecurityInfo.clientIssuerCertificates);
  }

  mCreateState = std::make_unique<CreateState>();
  mCreateState->request = std::move(request);

  // Reached once per SessionImpl, from initialise(); nothing can be in flight to destroy.
  mCreateTask = run_create_session();
}

ua::async::Task<> SessionImpl::run_create_session()
{
  try
  {
    // --- the client nonce, when the channel is authenticated and can produce one --------------
    // The chain skipped straight past this for an unauthenticated channel, for missing deps, or for
    // a crypto provider it could not get; all three still skip, and an empty nonce still means
    // "leave the request's clientNonce alone".
    ua::ByteStringResult nonceResult{ua::ByteString{}};
    {
      auto d = mDeps.lock();
      auto crypto = d ? d->crypto() : nullptr;
      if (mConfig.isAuthenticated && d && mSecurityInfo.securityPolicy && crypto)
      {
        nonceResult = co_await await_step<ua::ByteStringResult>(
          [this, crypto](auto completion)
          {
            // Part 4 1.05.07 5.7.2: the CreateSession clientNonce is 32 to 128 bytes, whatever the channel's
            // SecureChannelNonceLength (16 for Basic128Rsa15, owner decision 11; 384 for RSA_DH).
            crypto->get_entropy_async(
              ua::stack_utils::session_nonce_length(mSecurityInfo.securityPolicy->nonce_length()),
              std::move(completion));
          });
      }
    }
    if (!mCreateState)
      co_return;
    if (nonceResult.is_good() && !nonceResult.value().empty())
    {
      mClientNonce = std::move(nonceResult).value();
      mCreateState->request->client_nonce() = mClientNonce;
    }

    // For key-agreement channels (ECC, RSA_DH), request ephemeral-key user token encryption by sending the
    // SecurityPolicyUri planned for the UserIdentityToken. It may differ from the channel policy (Part 6,
    // 6.8.3). The policy sent is remembered: only a key solicited for it is ever adopted from a response.
    // A managed connect clears requestEphemeralKey for an endpoint no activation could use a key on
    // (AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, interoperability finding 021).
    mRequestedEcdhPolicyUri.clear();
    mServerEphemeralPublicKey = {};
    mServerEphemeralKeySignature = {};
    if (mConfig.isAuthenticated && mConfig.requestEphemeralKey && mSecurityInfo.securityPolicy &&
        mSecurityInfo.securityPolicy->ephemeral_key_algorithm() != ua::EphemeralKeyAlgorithm::Invalid)
    {
      auto additionalParams = std::make_unique<ua::AdditionalParametersType>();
      ua::KeyValuePair ecdhKv;
      ecdhKv.key() = ua::QualifiedName{0, "ECDHPolicyUri"};
      const std::string ecdhPolicyUri = mConfig.ecdhPolicyUri.empty()
                                          ? std::string{mSecurityInfo.securityPolicy->uri()}
                                          : mConfig.ecdhPolicyUri;
      mRequestedEcdhPolicyUri = ecdhPolicyUri;
      ecdhKv.value() = ua::Variant{ua::String{ecdhPolicyUri}};
      additionalParams->parameters().payload().push_back(std::move(ecdhKv));
      mCreateState->request->request_header().additional_header() = std::move(additionalParams);
    }

    // --- send it ------------------------------------------------------------------------------
    if (auto d = mDeps.lock())
    {
      d->logger().with_category("client.session").debug({}, "Sending CreateSession request");
    }

    auto responseResult = co_await await_step<ServiceResponseResult>(
      [this](auto completion) { send_session_request(mCreateState->request, std::move(completion)); });

    co_await handle_create_session_response(std::move(responseResult));
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    handle_unexpected_exception("client::Session::create_session", std::current_exception());
  }
  co_return;
}

ua::async::Task<> SessionImpl::handle_create_session_response(ServiceResponseResult responseResult)
{
  if (!mCreateState)
    co_return;

  // Check if we're still in Creating state (could have been closed while waiting).
  if (mSessionState != SessionState::Creating)
  {
    // Resolve the creation callback so external waiters (try_create_session_sync) do not
    // block forever on a future that will never complete. handle_session_closed normally
    // does this, but on the racy path we may not run handle_session_closed.
    if (mOnCreated)
    {
      auto callback = std::move(mOnCreated);
      mOnCreated = nullptr;
      auto detail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail("SessionAborted",
        "CreateSession completed after session was closed; result discarded",
        "client::Session"));
      if (auto d = mDeps.lock())
        ua::detail::invoke_user_callback(
          d->logger(), callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
      else
        ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadSessionClosed, detail});
    }
    mCreateState.reset();
    co_return;
  }

  if (!responseResult)
  {
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    auto status = responseResult.status_code();
    const auto& detail = responseResult.shared_detail();
    mCreateState.reset();
    handle_session_error(status, detail);
    handle_session_closed(status, detail);
    co_return;
  }

  auto* response = dynamic_cast<ua::CreateSessionResponse*>(responseResult.value().get());
  if (!response)
  {
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    auto badCastDetail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
      "CreateSessionBadResponse", "CreateSessionResponse was not the expected type", "client::Session"));
    mCreateState.reset();
    handle_session_error(ua::Status::BadDecodingError, badCastDetail);
    handle_session_closed(ua::Status::BadDecodingError, badCastDetail);
    co_return;
  }

  // Fire test observer if registered (one-shot).
  if (mCreateSessionResponseObserver)
  {
    mCreateSessionResponseObserver(*response);
    mCreateSessionResponseObserver = nullptr;
  }

  auto serviceStatus = response->response_header().service_result();
  if (mCreateState)
  {
    mCreateState->responseServiceResult = serviceStatus;
  }
  if (serviceStatus.is_bad())
  {
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    auto serverDiag = detail::attach_wire_marker(response->response_header());
    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::ErrorDetail::build("CreateSessionFailed", "CreateSession service returned an error", "server")
        .cause(std::move(serverDiag)));
    mCreateState.reset();
    handle_session_error(serviceStatus, detail);
    handle_session_closed(serviceStatus, detail);
    co_return;
  }

  // Parse the first certificate and retain its canonical DER. The CreateSession parameter may carry a
  // concatenated chain, but OPC 10000-4 section 5.6.3.2 requires both ActivateSession signatures to be
  // calculated with the leaf Certificate only. The first certificate is the leaf by OPC UA chain ordering.
  mServerCertificateDer = response->server_certificate();
  if (!mServerCertificateDer.empty())
  {
    if (auto dependencies = mDeps.lock())
    {
      if (auto crypto = dependencies->crypto())
      {
        try
        {
          // The one chain parser; decision 26: the leaf (the first certificate) is what is compared and
          // signed over, the rest are presented issuers.
          auto parsedField = ua::detail::parse_certificate_field(*crypto, mServerCertificateDer);
          if (!parsedField.is_good())
          {
            throw ua::UaException{parsedField.status_code()};
          }
          auto certificates = std::move(parsedField).value();
          mServerCertificate = certificates.front();
          mServerPresentedIssuers.assign(certificates.begin() + 1, certificates.end());
          mServerCertificateDer = mServerCertificate->der_encoding();
        }
        catch (...)
        {
          // Signature or user-token processing below reports malformed certificate material on paths
          // which require it. Hostname verification cannot compare a certificate that did not parse.
          ua::detail::ignore_expected_exception();
        }
      }
    }
  }

  // CL-SC-012 / OPC 10000-4 section 5.6.2 (P4-0004, SHALL): the ApplicationInstanceCertificate returned in
  // CreateSessionResponse MUST be the same certificate the secure channel was opened against (the
  // GetEndpoints/OPN server certificate). A server that returns a DIFFERENT certificate here is
  // substituting identity mid-handshake - and a serverSignature computed over the substitute would
  // still verify against the substitute, so the signature check alone does NOT catch this. Reject
  // before advancing to signature validation / ActivateSession. Only enforced on a secured channel (an
  // OPN server certificate exists); SecurityPolicy None carries no server certificate to compare.
  if (mSecurityInfo.serverCertificate &&
      mServerCertificateDer != mSecurityInfo.serverCertificate->der_encoding())
  {
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    auto detail =
      std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail("CreateSessionServerCertificateMismatch",
        "the CreateSessionResponse server certificate does not match the certificate the secure "
        "channel was opened against (OPC 10000-4 P4-0004)",
        "client::Session"));
    mCreateState.reset();
    handle_session_error(ua::Status::BadSecurityChecksFailed, detail);
    handle_session_closed(ua::Status::BadSecurityChecksFailed, detail);
    co_return;
  }

  const std::shared_ptr<const ua::X509Certificate> verificationCertificate =
    mSecurityInfo.serverCertificate ? mSecurityInfo.serverCertificate : mServerCertificate;

  // CL-DISC-004 / OPC 10000-4 section 5.4.1: GetEndpoints is unauthenticated. When its evidence selected this
  // channel, bind that evidence to the authenticated CreateSession response before accepting the Session.
  // An ordinary caller-supplied ExactUrl has no discovery evidence. Discovery-driven paths, including
  // EasyConnect, connect the selected endpoint verbatim but separately supply the complete GetEndpoints set.
  const ua::EndpointDescription* selectedSessionEndpoint = nullptr;
  if (!mConfig.discoveryEndpoints.empty())
  {
    const auto& authenticatedEndpoints = response->server_endpoints().payload();

    // "The same EndpointDescriptions" is set equality, not response ordering. Preserve duplicate
    // multiplicity: a one-to-one matched bitmap prevents a duplicated authenticated endpoint from masking a
    // missing discovered endpoint.
    // Part 4 section 5.6.2.2 restricts verification to these seven parameters.
    // Servers may omit the remaining fields, including the EndpointDescription certificate.
    // The top-level CreateSession certificate is independently bound to the channel above.
    const auto essentialEndpointsEqual =
      [](const ua::EndpointDescription& authenticated, const ua::EndpointDescription& discovered)
    {
      return authenticated.server().application_uri() == discovered.server().application_uri() &&
             authenticated.endpoint_url() == discovered.endpoint_url() &&
             authenticated.security_mode() == discovered.security_mode() &&
             authenticated.security_policy_uri() == discovered.security_policy_uri() &&
             authenticated.user_identity_tokens() == discovered.user_identity_tokens() &&
             authenticated.transport_profile_uri() == discovered.transport_profile_uri() &&
             authenticated.security_level() == discovered.security_level();
    };
    bool endpointSetsMatch = mConfig.discoveryEndpoints.size() == authenticatedEndpoints.size();
    std::vector<bool> authenticatedMatched(authenticatedEndpoints.size(), false);
    if (endpointSetsMatch)
    {
      for (const auto& discovered : mConfig.discoveryEndpoints)
      {
        bool found = false;
        for (size_t index = 0; index < authenticatedEndpoints.size(); ++index)
        {
          if (!authenticatedMatched[index] &&
              essentialEndpointsEqual(authenticatedEndpoints[index], discovered))
          {
            authenticatedMatched[index] = true;
            found = true;
            break;
          }
        }
        if (!found)
        {
          endpointSetsMatch = false;
          break;
        }
      }
    }
    if (!endpointSetsMatch)
    {
      reject_create_session_verification(response->authentication_token(),
        std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail("DiscoveryEndpointDescriptionsMismatch",
          "the EndpointDescriptions returned by CreateSession differ from the unauthenticated "
          "GetEndpoints evidence used to select the SecureChannel (OPC 10000-4 section 5.4.1(c))",
          "client.session.discovery_verification.endpoint_descriptions")));
      co_return;
    }

    const std::string channelPolicyUri =
      mSecurityInfo.securityPolicy ? std::string{mSecurityInfo.securityPolicy->uri()} : std::string{};
    const auto selectedEndpoint = std::ranges::find_if(mConfig.discoveryEndpoints,
      [this, channelPolicyUri](const ua::EndpointDescription& endpoint)
      {
        return std::string_view{endpoint.endpoint_url()} == mConfig.endpointUrl &&
               endpoint.security_mode() == mSecurityInfo.messageSecurityMode &&
               std::string_view{endpoint.security_policy_uri()} == channelPolicyUri;
      });
    if (selectedEndpoint == mConfig.discoveryEndpoints.end())
    {
      reject_create_session_verification(response->authentication_token(),
        std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail("DiscoverySelectedEndpointMissing",
          "the SecureChannel endpoint is absent from the GetEndpoints evidence supplied for verification",
          "client.session.discovery_verification.selected_endpoint")));
      co_return;
    }
    selectedSessionEndpoint = &*selectedEndpoint;

    // When a server certificate is present, the selected EndpointDescription's ApplicationUri must occur
    // in its SAN URI set exactly. On SecurityPolicy None this is the certificate returned by CreateSession.
    if (verificationCertificate)
    {
      const std::string expectedApplicationUri{selectedEndpoint->server().application_uri()};
      const auto certificateUris = verificationCertificate->san_uris();
      if (std::ranges::find(certificateUris, expectedApplicationUri) == certificateUris.end())
      {
        auto detail = ua::ErrorDetail::build("DiscoveryApplicationUriMismatch",
          "the server certificate ApplicationUri differs from the EndpointDescription used to select the "
          "SecureChannel (OPC 10000-4 section 5.4.1(a))",
          "client.session.discovery_verification.application_uri");
        detail.context(ua::ContextKeys::applicationUri, expectedApplicationUri);
        reject_create_session_verification(
          response->authentication_token(), std::shared_ptr<const ua::ErrorDetail>(detail));
        co_return;
      }
    }
  }
  else
  {
    const std::string channelPolicyUri =
      mSecurityInfo.securityPolicy ? std::string{mSecurityInfo.securityPolicy->uri()} : std::string{};
    const auto exactEndpoint = std::ranges::find_if(response->server_endpoints().payload(),
      [this, &channelPolicyUri](const ua::EndpointDescription& endpoint)
      {
        return std::string_view{endpoint.endpoint_url()} == mConfig.endpointUrl &&
               endpoint.security_mode() == mSecurityInfo.messageSecurityMode &&
               std::string_view{endpoint.security_policy_uri()} == channelPolicyUri;
      });
    if (exactEndpoint != response->server_endpoints().end())
    {
      selectedSessionEndpoint = &*exactEndpoint;
    }
    else if (!mConfig.endpointUrl.empty())
    {
      auto configuredEndpoint =
        ua::transport::parse_opc_tcp_url(mConfig.endpointUrl, "client.Session.configured_endpoint");
      if (!configuredEndpoint.is_good())
      {
        reject_create_session_verification(response->authentication_token(),
          std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build("ConfiguredEndpointUrlInvalid",
            "the endpointUrl used to establish the SecureChannel is invalid",
            "client.session.hostname_verification.configured_endpoint")
                                                   .context(ua::ContextKeys::endpointUrl, mConfig.endpointUrl)
                                                   .cause(configuredEndpoint.shared_detail())));
        co_return;
      }

      const auto resourceEndpoint = std::ranges::find_if(response->server_endpoints().payload(),
        [this, &channelPolicyUri, &configuredEndpoint](const ua::EndpointDescription& endpoint)
        {
          if (endpoint.security_mode() != mSecurityInfo.messageSecurityMode ||
              std::string_view{endpoint.security_policy_uri()} != channelPolicyUri)
          {
            return false;
          }
          auto candidate = ua::transport::parse_opc_tcp_url(
            std::string{endpoint.endpoint_url()}, "client.Session.create_session_endpoint");
          return candidate.is_good() &&
                 ua::transport::matches_port_and_path(configuredEndpoint.value(), candidate.value());
        });
      if (resourceEndpoint == response->server_endpoints().end())
      {
        reject_create_session_verification(response->authentication_token(),
          std::shared_ptr<const ua::ErrorDetail>(
            ua::ErrorDetail::build("CreateSessionConnectedEndpointMissing",
              "CreateSession returned no EndpointDescription for the connected port/path and "
              "SecureChannel security configuration",
              "client.session.hostname_verification.connected_endpoint")
              .context(ua::ContextKeys::endpointUrl, mConfig.endpointUrl)));
        co_return;
      }
      selectedSessionEndpoint = &*resourceEndpoint;
    }
    else
    {
      // A SessionImpl constructed directly without an endpointUrl exists only at the low-level interface.
      // Production managed connections always provide it. Preserve that interface by selecting the matching
      // security configuration; no connected resource is available to disambiguate further.
      const auto policyEndpoint = std::ranges::find_if(response->server_endpoints().payload(),
        [this, &channelPolicyUri](const ua::EndpointDescription& endpoint)
        {
          return endpoint.security_mode() == mSecurityInfo.messageSecurityMode &&
                 std::string_view{endpoint.security_policy_uri()} == channelPolicyUri;
        });
      if (policyEndpoint != response->server_endpoints().end())
      {
        selectedSessionEndpoint = &*policyEndpoint;
      }
    }
  }

  // The user-token policies come from the endpoint the verification above selected: the one this
  // channel is connected to. They were taken from the first endpoint of the list whenever none matched
  // the channel's policy and mode, which let a response name a policy for a different endpoint.
  mEndpointUserTokenPolicies.clear();
  if (selectedSessionEndpoint)
  {
    for (const auto& utp : selectedSessionEndpoint->user_identity_tokens().payload())
    {
      mEndpointUserTokenPolicies.push_back(utp);
    }
  }
  else if (!response->server_endpoints().empty())
  {
    reject_create_session_verification(response->authentication_token(),
      std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build("CreateSessionNoMatchingEndpoint",
        "CreateSession returned no EndpointDescription matching the SecureChannel's security policy "
        "and mode; the user-token policies of another endpoint are not taken in its place",
        "client.session.discovery_verification.selected_endpoint")
                                               .context(ua::ContextKeys::endpointUrl, mConfig.endpointUrl)),
      ua::StatusCode{ua::Status::BadSecurityChecksFailed});
    co_return;
  }

  if (verificationCertificate && selectedSessionEndpoint)
  {
    auto parsedEndpoint = ua::transport::parse_opc_tcp_url(
      std::string{selectedSessionEndpoint->endpoint_url()}, "client.Session");
    if (!parsedEndpoint.is_good())
    {
      reject_create_session_verification(response->authentication_token(),
        std::shared_ptr<const ua::ErrorDetail>(
          ua::ErrorDetail::build("CreateSessionEndpointUrlInvalid",
            "the EndpointDescription returned by CreateSession contains an invalid endpointUrl",
            "client.session.hostname_verification.endpoint_url")
            .context(ua::ContextKeys::endpointUrl, std::string{selectedSessionEndpoint->endpoint_url()})
            .cause(parsedEndpoint.shared_detail())));
      co_return;
    }

    const auto& endpointHostname = parsedEndpoint.value().hostname;
    if (!ua::detail::certificate_matches_hostname(endpointHostname, *verificationCertificate))
    {
      auto mismatch = ua::ErrorDetail::build("CreateSessionHostNameMismatch",
        "the HostName in the CreateSession endpointUrl does not match the server certificate "
        "(OPC 10000-4 section 5.4.1)",
        "client.session.hostname_verification.mismatch");
      mismatch.context(ua::ContextKeys::actual, endpointHostname);
      mismatch.context(
        ua::ContextKeys::expected, ua::detail::certificate_hostname_summary(*verificationCertificate));
      auto detail = std::shared_ptr<const ua::ErrorDetail>(mismatch);
      // The same suppression as the certificate validation's Host Name step (OPC 10000-12 Table 31
      // SuppressHostNameInvalid): one host-name rule, one switch. relaxHostNameCheck relaxes this check
      // alone.
      bool hostNameSuppressed = false;
      if (auto dependencies = mDeps.lock())
      {
        if (const auto store = dependencies->certificate_store())
        {
          hostNameSuppressed =
            store->validation_options().test(ua::TrustListValidationOptions::Bit::SuppressHostNameInvalid);
        }
      }
      if (!mConfig.relaxHostNameCheck && !hostNameSuppressed)
      {
        reject_create_session_verification(response->authentication_token(),
          std::move(detail),
          ua::StatusCode{ua::Status::BadCertificateHostNameInvalid});
        co_return;
      }
      if (auto dependencies = mDeps.lock())
      {
        const std::string errorText = ua::to_string(*detail);
        dependencies->logger()
          .with_category("client.session")
          .warning({{"endpoint_hostname", std::string_view{endpointHostname}},
                     {"error", std::string_view{errorText}}},
            "Continuing after a CreateSession HostName mismatch: relaxHostNameCheck is enabled or the "
            "trust list suppresses HostName errors");
      }
    }
  }

  // Adopt the server's ECC ephemeral key from the AdditionalHeader, if this client solicited one.
  adopt_server_ephemeral_key(response->response_header().additional_header().get(), "CreateSession");

  // Part 4 1.05.07 5.7.2: on a secured channel the serverNonce is the challenge every later signature and
  // encrypted token binds to; one shorter than 32 bytes removes that binding. A None-mode channel may
  // legitimately be answered with no nonce when no token needs one; there the floor applies at use. No
  // nonce is ever longer than 128 bytes.
  if ((mSecurityInfo.messageSecurityMode != ua::MessageSecurityMode::None &&
        response->server_nonce().size() < minimumServerNonceLength) ||
      response->server_nonce().size() > maximumServerNonceLength)
  {
    reject_create_session_verification(response->authentication_token(),
      std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build("CreateSessionServerNonceInvalid",
          "the CreateSession serverNonce is not between the 32 and 128 bytes OPC 10000-4 section 5.7.2 "
          "requires",
          "client.session.create_session.server_nonce")
          .context(ua::ContextKeys::sizeMin, std::to_string(minimumServerNonceLength))
          .context(ua::ContextKeys::sizeMax, std::to_string(maximumServerNonceLength))
          .context(ua::ContextKeys::actual, std::to_string(response->server_nonce().size()))),
      ua::StatusCode{ua::Status::BadNonceInvalid});
    co_return;
  }

  // Cache the response fields needed after signature validation.
  mCreateState->responseSessionId = response->session_id();
  mCreateState->responseAuthenticationToken = response->authentication_token();
  mCreateState->responseServerNonce = response->server_nonce();
  mCreateState->responseRevisedSessionTimeoutMs = response->revised_session_timeout();

  // For authenticated channels, validate the server's signature before accepting the session.
  if (mConfig.isAuthenticated)
  {
    mSessionState = SessionState::ValidatingServerSignature;
    update_atomic_snapshots();

    auto certDer = response->server_certificate();
    auto sig = response->server_signature().signature();
    auto signatureResult = co_await await_step<ua::VoidResult>(
      [this, certDer = std::move(certDer), sig = std::move(sig)](auto completion) mutable
      { validate_server_signature_async(std::move(certDer), std::move(sig), std::move(completion)); });
    on_server_signature_validated(std::move(signatureResult));
    co_return;
  }

  // No validation needed: complete create now.
  complete_create();
}

void SessionImpl::reject_create_session_verification(
  ua::NodeId authenticationToken, std::shared_ptr<const ua::ErrorDetail> detail, ua::StatusCode status)
{
  mSessionState = SessionState::Closed;
  update_atomic_snapshots();
  mCreateState.reset();

  if (!mChannel)
  {
    handle_session_error(status, detail);
    handle_session_closed(status, detail);
    return;
  }

  // The server has already allocated a Session. Queue a best-effort CloseSession before closing the channel
  // so repeated malicious mismatches cannot strand server-side sessions until their timeout. Both operations
  // enter the channel strand in this order; reporting never waits for the CloseSession response.
  auto closeSession = std::make_shared<ua::CloseSessionRequest>();
  closeSession->request_header().authentication_token() = std::move(authenticationToken);
  closeSession->delete_subscriptions() = true;
  send_session_request(std::move(closeSession),
    ua::async::post_borrowing(this,
      engaged_strand(mStrand),
      logger(),
      [](SessionImpl& self, ServiceResponseResult closeSessionResult)
      {
        if (closeSessionResult.is_bad())
        {
          if (auto dependencies = self.mDeps.lock())
          {
            const auto closeStatus = fmt::format("0x{:08x}", closeSessionResult.status_code().as_uint32());
            dependencies->logger()
              .with_category("client.session")
              .warning({{"status", std::string_view{closeStatus}}},
                "Best-effort CloseSession failed after discovery verification rejection");
          }
        }
      }));

  // Part 4 section 5.4.1 requires both reporting the mismatch and closing the SecureChannel. Keep the channel
  // strongly owned by this Session until its close completion arrives; the continuation then reports the
  // ORIGINAL verification ErrorDetail and lets handle_session_error release the channel.
  mChannel->close(ua::async::post_borrowing(this,
    engaged_strand(mStrand),
    logger(),
    [status, detail = std::move(detail)](SessionImpl& self, ua::VoidResult closeResult)
    {
      if (closeResult.is_bad())
      {
        if (auto dependencies = self.mDeps.lock())
        {
          const auto closeStatus = fmt::format("0x{:08x}", closeResult.status_code().as_uint32());
          dependencies->logger()
            .with_category("client.session")
            .error({{"status", std::string_view{closeStatus}}},
              "Failed to close SecureChannel after discovery verification failure");
        }
      }
      self.handle_session_error(status, detail);
      self.handle_session_closed(status, detail);
    }));
}

void SessionImpl::on_server_signature_validated(ua::VoidResult result)
{
  if (!mCreateState)
    return;

  // Check we're still validating (could have been closed).
  if (mSessionState != SessionState::ValidatingServerSignature)
  {
    mCreateState.reset();
    return;
  }

  if (result.is_bad())
  {
    if (auto d = mDeps.lock())
    {
      d->logger()
        .with_category("client.session")
        .warning({}, "Server application signature verification failed");
    }

    mSessionState = SessionState::Closed;
    update_atomic_snapshots();

    auto status = result.status_code();
    auto sigDetail = result.shared_detail();
    if (!sigDetail)
    {
      // Defensive: validate_server_signature_async should always carry detail, but if a
      // call site returned a bare status synthesise one so the user sees a meaningful cause.
      sigDetail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
        "ServerSignatureInvalid", "Server application signature verification failed", "client::Session"));
    }

    // Invoke the creation callback with the error before notifying session error/closed.
    // Without this, try_create_session_sync would block forever on the unfulfilled promise.
    if (mOnCreated)
    {
      auto callback = std::move(mOnCreated);
      mOnCreated = nullptr;
      auto d2 = mDeps.lock();
      if (d2)
        ua::detail::invoke_user_callback(d2->logger(), callback, ua::VoidResult{status, sigDetail});
      else
        ua::detail::invoke_user_callback(callback, ua::VoidResult{status, sigDetail});
    }

    mCreateState.reset();
    handle_session_error(status, sigDetail);
    handle_session_closed(status, sigDetail);
    return;
  }

  complete_create();
}

void SessionImpl::complete_create()
{
  if (!mCreateState)
    return;

  // Transition to Created using the cached response fields.
  mSessionId = std::move(mCreateState->responseSessionId);
  mAuthenticationToken = std::move(mCreateState->responseAuthenticationToken);
  mServerNonce = std::move(mCreateState->responseServerNonce);
  mRevisedSessionTimeoutMs = mCreateState->responseRevisedSessionTimeoutMs;
  // The Session is created; a Good subcode or an Uncertain ServiceResult reaches the caller.
  const ua::StatusCode createStatus = mCreateState->responseServiceResult;
  mSessionState = SessionState::Created;
  update_atomic_snapshots();
  mCreateState.reset();

  // Notify: session created.
  auto d = mDeps.lock();
  if (d)
  {
    auto sessionIdStr = ua::to_string(mSessionId);
    d->logger()
      .with_category("client.session")
      .info({{"session_id", std::string_view{sessionIdStr}},
              {"revised_timeout_ms", uint64_t(mRevisedSessionTimeoutMs)}},
        "Session created (not yet activated)");
  }

  if (mOnCreated)
  {
    auto callback = std::move(mOnCreated);
    mOnCreated = nullptr;
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{createStatus});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{createStatus});
  }
}

void SessionImpl::activate_internal(
  UserIdentity identity, std::string policyId, std::vector<ua::String> localeIds, bool wasActive)
{
  // Build the wire token from the high-level identity (synchronous).
  auto prepared = build_user_token(identity,
    policyId,
    mEndpointUserTokenPolicies,
    mSecurityInfo.securityPolicy,
    mSecurityInfo.messageSecurityMode);
  if (!prepared)
  {
    if (auto d = mDeps.lock())
    {
      d->logger()
        .with_category("client.session")
        .error({}, "Failed to build user identity token: 0x{:08x}", prepared.status_code().as_uint32());
    }
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    handle_session_error(prepared.status_code(), prepared.shared_detail());
    handle_session_closed(prepared.status_code(), prepared.shared_detail());
    return;
  }

  // Allocate per-flow state.
  mActivateState = std::make_unique<ActivateState>();
  mActivateState->identity = std::move(identity);
  mActivateState->policyId = std::move(policyId);
  mActivateState->localeIds = std::move(localeIds);
  mActivateState->prepared = std::move(prepared).value();
  mActivateState->wasActive = wasActive;

  mActivateState->request = std::make_shared<ua::ActivateSessionRequest>();
  mActivateState->request->request_header().authentication_token() = mAuthenticationToken;
  mActivateState->request->locale_ids() = mActivateState->localeIds;
  mActivateState->request->user_identity_token() = mActivateState->prepared.wireToken->clone();

  if (auto d = mDeps.lock())
  {
    mActivateState->request->request_header().return_diagnostics() =
      return_diagnostics_for(mActivateState->request->request_header().return_diagnostics());
  }

  // Single-flight: both call sites reject unless the state is Created/Active/Disconnected and
  // set Activating before calling here, so nothing can be in flight to destroy.
  mActivateTask = run_activate();
}

ua::async::Task<> SessionImpl::run_activate()
{
  try
  {
    // --- client application signature ---------------------------------------------------------
    // Skipped when the channel is unauthenticated, or deps/policy/keypair/crypto are absent - the
    // same four conditions the chain skipped on, and a skip still means "send without a signature".
    {
      auto d = mDeps.lock();
      auto crypto = d ? d->crypto() : nullptr;
      if (mConfig.isAuthenticated && d && mSecurityInfo.securityPolicy && mSecurityInfo.clientKeyPair &&
          crypto)
      {
        // Part 4 5.6.3 and 6.1.8: with SecureChannelEnhancements the Client signs the channel bound data of
        // Table 101, with an empty algorithm URI (Table 174); otherwise (serverCertificate || serverNonce).
        const bool channelBound = mSecurityInfo.securityPolicy->secure_channel_enhancements();
        ua::ByteStringResult dataResult{ua::ByteString{}};
        if (channelBound)
        {
          dataResult = co_await await_step<ua::ByteStringResult>(
            [this](auto completion)
            {
              build_channel_bound_data_async(ua::ChannelBoundSignature::Client,
                *mSecurityInfo.securityPolicy,
                mServerNonce,
                mServerCertificateDer,
                {},
                std::move(completion));
            });
          if (!mActivateState)
            co_return;
        }
        else
        {
          ua::ByteString legacyData = mServerCertificateDer;
          std::ranges::copy(mServerNonce, std::back_inserter(legacyData));
          dataResult = ua::ByteStringResult{std::move(legacyData)};
        }

        ua::ByteStringResult signResult = dataResult;
        if (dataResult.is_good())
        {
          auto dataToSign = std::make_shared<const ua::ByteString>(std::move(dataResult).value());
          signResult = co_await await_step<ua::ByteStringResult>(
            [this, crypto, dataToSign](auto completion) mutable
            {
              crypto->asymmetric_sign_async(dataToSign,
                mSecurityInfo.securityPolicy->asymmetric_signature_algorithm(),
                mSecurityInfo.clientKeyPair,
                *dataToSign,
                std::move(completion));
            });
          if (!mActivateState)
            co_return;
        }

        if (signResult.is_good() && !signResult.value().empty())
        {
          mActivateState->request->client_signature().signature() = std::move(signResult).value();
          if (!channelBound)
          {
            mActivateState->request->client_signature().algorithm() =
              mSecurityInfo.securityPolicy->asymmetric_signature_algorithm_uri();
          }
        }
        else if (signResult.is_uncertain())
        {
          // The signature is used only from a Good answer, and an Uncertain answer is not a reason to send
          // the request unsigned: the activation is refused and nothing is sent.
          if (auto dd = mDeps.lock())
          {
            dd->logger()
              .with_category("client.session")
              .warning({{"status", fmt::format("0x{:08x}", signResult.status_code().as_uint32())}},
                "The crypto provider answered the client application signature for ActivateSession "
                "Uncertain");
          }
          mSessionState = SessionState::Closed;
          update_atomic_snapshots();
          auto signStatus = ua::security_internal::not_good_answer(
            signResult.status_code(), ua::Status::BadInternalError, "client.session.client_signature");
          auto signDetail = signStatus.shared_detail();
          mActivateState.reset();
          handle_session_error(signStatus, signDetail);
          handle_session_closed(signStatus, signDetail);
          co_return;
        }
        else if (signResult.is_bad())
        {
          if (auto dd = mDeps.lock())
          {
            dd->logger()
              .with_category("client.session")
              .warning({{"status", fmt::format("0x{:08x}", signResult.status_code().as_uint32())}},
                "Failed to create client application signature for ActivateSession");
          }
          // Best-effort skip: client app signing failures are non-fatal here because the request is
          // still sent without a signature. The server will reject with BadApplicationSignatureInvalid
          // (Part 4 5.6.3.1) which surfaces a clear failure to the caller. The local sign-failure
          // detail is logged above; we do not propagate it because the server's rejection is the
          // authoritative cause the user ultimately sees.
        }
      }
    }

    // --- user-token encryption (fail-closed; CL-IDENT-003 / CL-IDENT-006) ---------------------
    if (!co_await encrypt_user_token())
    {
      co_return;
    }
    if (!mActivateState)
      co_return;

    // --- X509 user-token signature ------------------------------------------------------------
    {
      auto d = mDeps.lock();
      const auto* x509TokenRaw =
        dynamic_cast<const ua::X509IdentityToken*>(mActivateState->request->user_identity_token().get());
      auto crypto = d ? d->crypto() : nullptr;
      if (d && mActivateState->prepared.signingPolicy && mActivateState->prepared.userKeyPair &&
          x509TokenRaw && crypto)
      {
        if (mServerNonce.size() < minimumServerNonceLength)
        {
          refuse_user_token_encryption(ua::StatusCode{ua::Status::BadNonceInvalid},
            ua::make_error_detail("ServerNonceTooShortForUserToken",
              "the serverNonce is shorter than the 32 bytes the X509 user-token signature binds to (OPC "
              "10000-4 section 5.6.3.2); refusing to send ActivateSession",
              "client.session.user_token_signature.server_nonce"));
          co_return;
        }
        // Part 4 6.1.8: the UserTokenPolicy's SecurityPolicy decides the layout (SD-6). With
        // SecureChannelEnhancements the signature is channel bound (Table 101) - in the None-mode layout over
        // a None channel - with an empty algorithm URI (Table 174); otherwise (serverCertificate ||
        // serverNonce).
        const auto& tokenPolicy = *mActivateState->prepared.signingPolicy;
        const bool channelBound = tokenPolicy.secure_channel_enhancements();
        ua::ByteStringResult dataResult{ua::ByteString{}};
        if (channelBound)
        {
          const auto layout = mSecurityInfo.messageSecurityMode == ua::MessageSecurityMode::None
                                ? ua::ChannelBoundSignature::UserTokenOverNone
                                : ua::ChannelBoundSignature::UserToken;
          dataResult = co_await await_step<ua::ByteStringResult>(
            [this, layout](auto completion)
            {
              build_channel_bound_data_async(layout,
                *mActivateState->prepared.signingPolicy,
                mServerNonce,
                mServerCertificateDer,
                mSecurityInfo.clientCertificate ? mSecurityInfo.clientCertificate->der_encoding()
                                                : ua::ByteString{},
                std::move(completion));
            });
          if (!mActivateState)
            co_return;
        }
        else
        {
          ua::ByteString legacyData = mServerCertificateDer;
          std::ranges::copy(mServerNonce, std::back_inserter(legacyData));
          dataResult = ua::ByteStringResult{std::move(legacyData)};
        }

        ua::ByteStringResult signResult = dataResult;
        if (dataResult.is_good())
        {
          auto dataToSign = std::make_shared<const ua::ByteString>(std::move(dataResult).value());
          signResult = co_await await_step<ua::ByteStringResult>(
            [this, crypto, dataToSign](auto completion) mutable
            {
              crypto->asymmetric_sign_async(dataToSign,
                mActivateState->prepared.signingPolicy->asymmetric_signature_algorithm(),
                mActivateState->prepared.userKeyPair,
                *dataToSign,
                std::move(completion));
            });
          if (!mActivateState)
            co_return;
        }

        if (!signResult.is_good())
        {
          if (auto dd = mDeps.lock())
          {
            dd->logger()
              .with_category("client.session")
              .warning({}, "Failed to create UserTokenSignature for X509 identity token");
          }
          mSessionState = SessionState::Closed;
          update_atomic_snapshots();
          // A Bad answer rejects the identity token; an Uncertain one is refused, since the signature is
          // used only from a Good answer.
          auto tokenStatus = signResult.is_uncertain()
                               ? ua::security_internal::not_good_answer(signResult.status_code(),
                                   ua::Status::BadInternalError,
                                   "client.session.user_token_signature")
                               : ua::StatusCode{ua::Status::BadIdentityTokenRejected,
                                   ua::make_error_detail("UserTokenSignFailed",
                                     "Failed to create UserTokenSignature for X509 identity token",
                                     "client::Session",
                                     signResult.shared_detail())};
          auto tokenDetail = tokenStatus.shared_detail();
          mActivateState.reset();
          handle_session_error(tokenStatus, tokenDetail);
          handle_session_closed(tokenStatus, tokenDetail);
          co_return;
        }

        mActivateState->request->user_token_signature().signature() = std::move(signResult).value();
        if (!channelBound)
        {
          mActivateState->request->user_token_signature().algorithm() =
            mActivateState->prepared.signingPolicy->asymmetric_signature_algorithm_uri();
        }
      }
    }

    // --- send ---------------------------------------------------------------------------------
    if (auto d = mDeps.lock())
    {
      d->logger().with_category("client.session").debug({}, "Sending ActivateSession request");
    }

    auto responseResult = co_await await_step<ServiceResponseResult>(
      [this](auto completion) { send_session_request(mActivateState->request, std::move(completion)); });
    if (!mActivateState)
      co_return;

    on_activate_response_received(std::move(responseResult));
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    handle_unexpected_exception("client::Session::activate", std::current_exception());
  }
  co_return;
}

/// Encrypts the user-token secret when the resolved token policy requires it.
///
/// Returns false when it has already answered - which for this step always means it FAILED CLOSED and
/// tore the session down, never that it proceeded without encrypting. Every check below is in the
/// order the chain applied it; only the way the answers arrive has changed.
ua::async::Task<bool> SessionImpl::encrypt_user_token()
{
  if (!mActivateState)
    co_return false;

  // No per-token encryption policy was resolved for this token -> there is nothing to encrypt.
  if (!mActivateState->prepared.encryptionPolicy)
  {
    co_return true;
  }

  // A per-token encryption policy WAS resolved: the secret MUST be encrypted before ActivateSession is
  // sent. Two token types carry such a secret, and Part 4 Table 187 defines the EncryptedSecret's
  // `Secret` field as "The password when used with UserNameIdentityTokens. The tokenData when used with
  // IssuedIdentityTokens" - one construction over two source fields, which is why the issued token is
  // routed through the same encryption below rather than given a parallel implementation.
  //
  // An IssuedIdentityToken is a bearer credential: whoever holds it can act as the user until it
  // expires. Emitting it verbatim was the fail-open this path used to take, and it was not confined to
  // unsecured channels - the policy resolution above returns a real policy for a None or Sign channel
  // too, so the token travelled as plaintext on the wire.
  auto* rawToken = mActivateState->request->user_identity_token().get();
  auto* userNameTokenRaw = dynamic_cast<ua::UserNameIdentityToken*>(rawToken);
  auto* issuedTokenRaw = dynamic_cast<ua::IssuedIdentityToken*>(rawToken);

  const bool userNameCarriesSecret = userNameTokenRaw && !userNameTokenRaw->password().empty();
  const bool issuedCarriesSecret = issuedTokenRaw && !issuedTokenRaw->token_data().empty();
  if (!userNameCarriesSecret && !issuedCarriesSecret)
  {
    co_return true;
  }

  // From here the token carries a non-empty secret that the resolved policy REQUIRES to be encrypted.
  // If the SDK cannot perform that encryption - the dependencies expired, or no crypto provider is
  // available - fail CLOSED (CL-IDENT-003 defense-in-depth): never fall through and send the secret in
  // the clear.
  auto d = mDeps.lock();
  if (!d)
  {
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      ua::make_error_detail("UserTokenEncryptionUnavailable",
        "the user-token SecurityPolicy requires the password encrypted but the session dependencies are no "
        "longer available to perform it; refusing to send ActivateSession with an unencrypted secret",
        "client.session.user_token_encryption.deps_unavailable"));
    co_return false;
  }
  auto crypto = d->crypto();
  if (!crypto)
  {
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      ua::make_error_detail("UserTokenEncryptionUnavailable",
        "the user-token SecurityPolicy requires the password encrypted but no crypto provider is available "
        "to perform it; refusing to send ActivateSession with an unencrypted secret",
        "client.session.user_token_encryption.no_crypto"));
    co_return false;
  }
  // The secret is encrypted with the serverNonce as freshness: a nonce shorter than 32 bytes (a None
  // endpoint answers with none when no token needs it) cannot bind the encrypted token to this session.
  if (mServerNonce.size() < minimumServerNonceLength)
  {
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadNonceInvalid},
      ua::make_error_detail("ServerNonceTooShortForUserToken",
        "the serverNonce is shorter than the 32 bytes an encrypted user token binds to (OPC 10000-4 "
        "section 5.6.2.2); refusing to send ActivateSession with the secret",
        "client.session.user_token_encryption.server_nonce"));
    co_return false;
  }

  std::shared_ptr<ua::UserNameIdentityToken> userNameToken;
  std::shared_ptr<ua::IssuedIdentityToken> issuedToken;
  if (userNameCarriesSecret)
  {
    userNameToken = std::shared_ptr<ua::UserNameIdentityToken>{mActivateState->request, userNameTokenRaw};
  }
  else
  {
    issuedToken = std::shared_ptr<ua::IssuedIdentityToken>{mActivateState->request, issuedTokenRaw};
  }

  // CL-IDENT-006: on a NONE channel the CreateSession-response server certificate arrived UNPROTECTED (no
  // OPN validation, no channel signing/encryption), so encrypting the user-token secret with it would let
  // a MITM that substituted the certificate decrypt the secret. Validate it against the Session's trust
  // store first and REFUSE the activation (fail-closed) if it cannot be validated/trusted. On a secured
  // (Sign / SignAndEncrypt) channel the certificate arrived over the OPN-validated, signed/encrypted
  // channel, so it is already trusted - encrypt directly.
  //
  // The validation threads the dialed endpoint URL (mConfig.mEndpointUrl) as the endpointUrl argument,
  // exactly as the OPN path does (SecurityPolicy::validate_certificate_async): a trust check alone
  // (chains to a trusted CA) does NOT defend against a MITM that presents its own CA-issued certificate -
  // the store must also bind the certificate to the intended server. applicationUri stays absent to match
  // the OPN call.
  if (mSecurityInfo.messageSecurityMode == ua::MessageSecurityMode::None)
  {
    auto store = d->certificate_store();
    if (!store || !mServerCertificate)
    {
      refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
        ua::make_error_detail("ServerCertificateUnvalidatedForTokenEncryption",
          "cannot validate the server certificate before encrypting the user token on an unsecured (None) "
          "channel: no trust store or no server certificate",
          "client.session.user_token_encryption.no_trust_store"));
      co_return false;
    }
    auto expectedEndpointUrl = mConfig.endpointUrl.empty() ? ua::optional<std::string>{}
                                                           : ua::optional<std::string>{mConfig.endpointUrl};

    auto validation = co_await await_step<ua::VoidResult>(
      [this, &store, expectedEndpointUrl = std::move(expectedEndpointUrl)](auto completion) mutable
      {
        // The same request shape as the OPN path: the leaf, the issuers the server presented with it,
        // the endpoint URL; the Security Policy Check is run under the user-token SecurityPolicy the
        // secret is encrypted with (on this None channel the channel's policy is None). The session
        // trust store adds the certificates accepted for this connection.
        ua::CertificateValidationRequest request;
        request.certificate = mServerCertificate;
        request.presentedIssuers = mServerPresentedIssuers;
        request.use = ua::CertificateUse::ServerApplicationInstance;
        if (mActivateState->prepared.encryptionPolicy)
        {
          request.policyId = mActivateState->prepared.encryptionPolicy->id();
        }
        request.endpointUrl = std::move(expectedEndpointUrl);
        store->validate_certificate_async(std::move(request), std::move(completion));
      });
    if (!mActivateState)
      co_return false;

    if (validation.is_bad())
    {
      refuse_user_token_encryption(ua::StatusCode{ua::Status::BadCertificateUntrusted},
        ua::make_error_detail("ServerCertificateUntrustedForTokenEncryption",
          "the server certificate is not trusted; refusing to encrypt the user token on an unsecured "
          "(None) channel",
          "client.session.user_token_encryption.untrusted_server_cert",
          validation.shared_detail()));
      co_return false;
    }
    // OPC 10000-4 section 6.1.3: errors this validation suppressed are reported, one warning each.
    ua::client::detail::log_suppressed_certificate_errors(d->logger(),
      mServerCertificate->subject_common_name(),
      ua::detail::suppressed_certificate_errors(validation));
  }

  // Key agreement: the key the secret is encrypted to must be the server's, not one a peer slipped into
  // the response. The check binds it to the channel's authenticated certificate (fail-closed).
  if (mActivateState->prepared.encryptionPolicy->ephemeral_key_algorithm() !=
      ua::EphemeralKeyAlgorithm::Invalid)
  {
    if (!co_await verify_server_ephemeral_key())
    {
      co_return false;
    }
    if (!mActivateState)
      co_return false;
  }

  // The dependencies were alive when this step committed to encrypting; re-lock rather than assume,
  // and fail CLOSED if they vanished, exactly as the chain's encrypt_user_token_step did.
  auto encryptDeps = mDeps.lock();
  if (!encryptDeps)
  {
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      ua::make_error_detail("UserTokenEncryptionUnavailable",
        "the user-token SecurityPolicy requires the password encrypted but the session dependencies are no "
        "longer available to perform it; refusing to send ActivateSession with an unencrypted secret",
        "client.session.user_token_encryption.deps_unavailable"));
    co_return false;
  }

  auto encryptResult = co_await await_step<ua::VoidResult>(
    [this,
      &encryptDeps,
      crypto = std::move(crypto),
      userNameToken = std::move(userNameToken),
      issuedToken = std::move(issuedToken)](auto completion) mutable
    {
      if (issuedToken)
      {
        ua::encrypt_issued_token_async(mActivateState->prepared.encryptionPolicy,
          std::move(crypto),
          session_strand(),
          std::move(issuedToken),
          ua::ByteString{mServerNonce},
          mServerCertificate,
          ua::ByteString{mServerEphemeralPublicKey},
          mSecurityInfo.clientCertificate,
          mSecurityInfo.clientKeyPair,
          encryptDeps->logger().with_category("client.session"),
          std::move(completion));
        return;
      }
      ua::encrypt_user_token_async(mActivateState->prepared.encryptionPolicy,
        std::move(crypto),
        session_strand(),
        std::move(userNameToken),
        ua::ByteString{mServerNonce},
        mServerCertificate,
        ua::ByteString{mServerEphemeralPublicKey},
        mSecurityInfo.clientCertificate,
        mSecurityInfo.clientKeyPair,
        encryptDeps->logger().with_category("client.session"),
        std::move(completion));
    });
  if (!mActivateState)
    co_return false;

  if (encryptResult.is_bad())
  {
    // Fail CLOSED (CL-IDENT-003): the user-token SecurityPolicy required the secret to be encrypted (an
    // encryptionPolicy was resolved for this token) but the encryption failed. Proceeding would ship
    // ActivateSession with the credential in the clear - the token policy mandates token-level encryption
    // that channel protection alone does not satisfy - leaking the secret. Refuse the activation instead
    // of sending an unencrypted secret. (Never discard the ErrorDetail: chain the encrypt failure as the
    // cause.)
    if (auto dd = mDeps.lock())
    {
      dd->logger()
        .with_category("client.session")
        .error({}, "Failed to encrypt user token for ActivateSession; refusing to activate (fail-closed)");
    }
    refuse_user_token_encryption(encryptResult.status_code(),
      ua::make_error_detail("UserTokenEncryptionFailed",
        "failed to encrypt the user-token secret required by the user-token SecurityPolicy; refusing to send "
        "ActivateSession with an unencrypted secret",
        "client.session.user_token_encryption.encrypt_failed",
        encryptResult.shared_detail()));
    co_return false;
  }
  if (mActivateState->prepared.encryptionPolicy->ephemeral_key_algorithm() !=
      ua::EphemeralKeyAlgorithm::Invalid)
  {
    // Single use (CL-ECC-002): the ephemeral key is consumed by the secret it encrypted; the next
    // activation needs the fresh key the ActivateSession response carries.
    mServerEphemeralPublicKey = {};
    mServerEphemeralKeySignature = {};
  }
  co_return true;
}

void SessionImpl::adopt_server_ephemeral_key(
  const ua::Structure* additionalHeader, std::string_view responseName)
{
  auto key = extract_server_ephemeral_key(additionalHeader);
  if (key.publicKey.empty())
  {
    return;
  }
  if (mRequestedEcdhPolicyUri.empty())
  {
    // Not solicited: this client sent no ECDHPolicyUri (a None channel never does), so a key here is a
    // peer choosing the client's encryption for it. Ignored, never adopted.
    if (auto d = mDeps.lock())
    {
      d->logger()
        .with_category("client.session")
        .debug({{"response", responseName}}, "Unsolicited ECDHKey in the response AdditionalHeader ignored");
    }
    return;
  }
  mServerEphemeralPublicKey = std::move(key.publicKey);
  mServerEphemeralKeySignature = std::move(key.signature);
}

ua::async::Task<bool> SessionImpl::verify_server_ephemeral_key()
{
  if (!mActivateState)
    co_return false;
  const auto refuse = [this](const char* code, const char* message)
  {
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      ua::make_error_detail(code, message, "client.session.user_token_encryption.ephemeral_key"));
  };

  const auto& policy = mActivateState->prepared.encryptionPolicy;
  const auto* eccPolicy = dynamic_cast<const ua::SecPolEphemeralKey*>(policy.get());
  if (!eccPolicy)
  {
    refuse("EphemeralKeyPolicyNotEcc", "the user-token SecurityPolicy does not agree an ephemeral key");
    co_return false;
  }
  if (mRequestedEcdhPolicyUri.empty())
  {
    refuse("EphemeralKeyNotSolicited",
      "no ECDHPolicyUri was sent in CreateSession, so no server EphemeralKey can be trusted for this token");
    co_return false;
  }
  if (std::string_view{policy->uri()} != mRequestedEcdhPolicyUri)
  {
    refuse("EphemeralKeyPolicyMismatch",
      "the user-token SecurityPolicy differs from the ECDHPolicyUri the server's EphemeralKey was "
      "generated for (OPC 10000-6 section 6.8.3)");
    co_return false;
  }
  if (mServerEphemeralPublicKey.empty() || mServerEphemeralKeySignature.empty())
  {
    auto detail = ua::make_error_detail("EphemeralKeySignatureMissing",
      "the server's EphemeralKey carries no signature (or no key is held: the last one was consumed by "
      "the secret it encrypted, and the ActivateSession response brought no fresh one); an unsigned key "
      "cannot be attributed to the server (OPC 10000-4 section 7.15)",
      "client.session.user_token_encryption.ephemeral_key");
    if (mActivateState->wasActive)
    {
      // An Active session asking for an identity change: the change is refused, the session is kept,
      // exactly as a server's BadIdentityChangeNotSupported is handled. A fresh CreateSession, or an
      // ActivateSession response carrying a new key, precedes the next ECC-encrypted token.
      mActivateState.reset();
      mSessionState = SessionState::Active;
      update_atomic_snapshots();
      auto callback = std::move(mActivateCallback);
      mActivateCallback = nullptr;
      const ua::VoidResult refused{ua::StatusCode{ua::Status::BadSecurityChecksFailed}, std::move(detail)};
      if (auto dd = mDeps.lock())
        ua::detail::invoke_user_callback(dd->logger(), callback, refused);
      else
        ua::detail::invoke_user_callback(callback, refused);
      co_return false;
    }
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed}, std::move(detail));
    co_return false;
  }
  // The channel's OPN-validated certificate, never the CreateSession one: on a None channel the latter
  // arrived unprotected.
  const auto certificate = mSecurityInfo.serverCertificate;
  if (!certificate)
  {
    refuse("EphemeralKeyNoAuthenticatedCertificate",
      "no authenticated server certificate is available to verify the EphemeralKey signature (the "
      "SecureChannel carries none)");
    co_return false;
  }
  // The certificate is the channel's, already validated by OPN for the channel policy. It may belong
  // to the token (ECDH) policy's curve family or to the channel's (Part 6 6.8.3 allows the two to
  // differ, e.g. a P-256 channel with a P-384 token policy); the signature algorithm to verify with
  // follows whichever policy permits the certificate (Part 4 7.15 names the ECDH policy; this SDK's
  // own server signs with the channel policy).
  const auto keyAlgorithm = certificate->key_algorithm();
  // An end-entity certificate uses the policy's own curve (OPC 10000-7 profile database).
  const bool permittedByToken = keyAlgorithm == eccPolicy->certificate_key_algorithm();
  const auto* channelEcc = dynamic_cast<const ua::SecPolEphemeralKey*>(mSecurityInfo.securityPolicy.get());
  const bool permittedByChannel =
    channelEcc != nullptr && keyAlgorithm == channelEcc->certificate_key_algorithm();
  if (!permittedByToken && !permittedByChannel)
  {
    refuse("EphemeralKeyCertificateNotPermitted",
      "the server certificate's key algorithm is permitted neither by the ECC user-token SecurityPolicy "
      "nor by the channel's");
    co_return false;
  }

  auto d = mDeps.lock();
  auto crypto = d ? d->crypto() : nullptr;
  if (!crypto)
  {
    refuse(
      "EphemeralKeyVerificationUnavailable", "no crypto provider is available to verify the EphemeralKey");
    co_return false;
  }

  // The signature is over the public key with the server's certificate; the algorithm tried is the one
  // of each policy that permits the certificate, so a certificate of the wrong curve family for an
  // algorithm is never tried with it. Neither attempt changes the key or the certificate.
  std::vector<ua::AsymmetricSignatureAlgorithm> algorithms;
  if (permittedByToken)
  {
    algorithms.push_back(eccPolicy->asymmetric_signature_algorithm());
  }
  if (permittedByChannel &&
      std::ranges::find(algorithms, channelEcc->asymmetric_signature_algorithm()) == algorithms.end())
  {
    algorithms.push_back(channelEcc->asymmetric_signature_algorithm());
  }
  ua::VoidResult verified{ua::Status::BadSecurityChecksFailed};
  for (const auto algorithm : algorithms)
  {
    auto input = std::make_shared<ServerSignatureVerificationInput>(ServerSignatureVerificationInput{
      certificate, ua::ByteString{mServerEphemeralPublicKey}, ua::ByteString{mServerEphemeralKeySignature}});
    verified = co_await await_step<ua::VoidResult>(
      [&crypto, algorithm, input](auto completion) mutable
      {
        crypto->asymmetric_verify_async(input,
          algorithm,
          input->serverCertificate->public_key(),
          input->signedData,
          input->signature,
          [input, completion = std::move(completion)](ua::VoidResult result) mutable
          { completion(std::move(result)); });
      });
    if (!mActivateState)
      co_return false;
    if (verified.is_good())
    {
      break;
    }
  }
  if (verified.is_bad())
  {
    refuse_user_token_encryption(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      ua::make_error_detail("EphemeralKeySignatureInvalid",
        "the server's EphemeralKey signature does not verify with the authenticated server certificate; "
        "refusing to encrypt the user token to it",
        "client.session.user_token_encryption.ephemeral_key",
        verified.shared_detail()));
    co_return false;
  }
  co_return true;
}

void SessionImpl::refuse_user_token_encryption(
  ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
{
  // Guard the teardown against a stale continuation, matching every sibling activate continuation
  // (encrypt_user_token_step / on_user_token_encrypted / ...). The trust-store validation is an async op
  // that re-enters the strand only on liveness, not on flow state; if a concurrent teardown (user close(),
  // timeout, channel disconnect) already reset mActivateState  -  and, for a clean close, never ran
  // handle_session_error  -  then re-driving handle_session_error/closed here would spuriously re-fire the
  // caller's error observers after they already observed the close. Drop the late refusal instead.
  if (!mActivateState)
    return;
  mSessionState = SessionState::Closed;
  update_atomic_snapshots();
  handle_session_error(status, detail);
  handle_session_closed(status, detail);
}

void SessionImpl::on_activate_response_received(ServiceResponseResult responseResult)
{
  // Check if we're still in Activating state.
  if (mSessionState != SessionState::Activating)
  {
    mActivateState.reset();
    return;
  }

  if (!responseResult)
  {
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    auto status = responseResult.status_code();
    const auto& detail = responseResult.shared_detail();
    mActivateState.reset();
    handle_session_error(status, detail);
    handle_session_closed(status, detail);
    return;
  }

  auto* response = dynamic_cast<ua::ActivateSessionResponse*>(responseResult.value().get());
  if (!response)
  {
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    auto activBadCast = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
      "ActivateSessionBadResponse", "ActivateSessionResponse was not the expected type", "client::Session"));
    mActivateState.reset();
    handle_session_error(ua::Status::BadDecodingError, activBadCast);
    handle_session_closed(ua::Status::BadDecodingError, activBadCast);
    return;
  }

  // Adopt a fresh ECC ephemeral key for the next ActivateSession, if this client solicited one.
  adopt_server_ephemeral_key(response->response_header().additional_header().get(), "ActivateSession");

  auto serviceStatus = response->response_header().service_result();
  if (serviceStatus.is_bad())
  {
    auto serverDiag = detail::attach_wire_marker(response->response_header());
    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::ErrorDetail::build("ActivateSessionFailed", "ActivateSession service returned an error", "server")
        .cause(std::move(serverDiag)));
    const bool preserveActiveSession =
      mActivateState->wasActive && serviceStatus == ua::Status::BadIdentityChangeNotSupported;
    mActivateState.reset();
    if (preserveActiveSession)
    {
      mSessionState = SessionState::Active;
      update_atomic_snapshots();
      auto callback = std::move(mActivateCallback);
      mActivateCallback = nullptr;
      auto d = mDeps.lock();
      if (d)
        ua::detail::invoke_user_callback(
          d->logger(), callback, ua::VoidResult{serviceStatus, std::move(detail)});
      else
        ua::detail::invoke_user_callback(callback, ua::VoidResult{serviceStatus, std::move(detail)});
      return;
    }
    mSessionState = SessionState::Closed;
    update_atomic_snapshots();
    handle_session_error(serviceStatus, detail);
    handle_session_closed(serviceStatus, detail);
    return;
  }

  // Part 4 1.05.07 5.7.3: the ActivateSession serverNonce is the next challenge. On an authenticated channel
  // it must be at least 32 bytes, on any channel at most 128, and a nonce equal to the previous one (any
  // channel) is a replayed challenge; each refusal closes the session, as a discovery mismatch does.
  {
    const auto& nextNonce = response->server_nonce();
    const bool outOfRange = (mSecurityInfo.messageSecurityMode != ua::MessageSecurityMode::None &&
                              nextNonce.size() < minimumServerNonceLength) ||
                            nextNonce.size() > maximumServerNonceLength;
    const bool reused = !nextNonce.empty() && nextNonce == mServerNonce;
    if (outOfRange || reused)
    {
      auto detail = outOfRange
                      ? ua::ErrorDetail::build("ActivateSessionServerNonceInvalid",
                          "the ActivateSession serverNonce is not between the 32 and 128 bytes OPC 10000-4 "
                          "section 5.7.3 requires",
                          "client.session.activate_session.server_nonce")
                          .context(ua::ContextKeys::sizeMin, std::to_string(minimumServerNonceLength))
                          .context(ua::ContextKeys::sizeMax, std::to_string(maximumServerNonceLength))
                          .context(ua::ContextKeys::actual, std::to_string(nextNonce.size()))
                      : ua::ErrorDetail::build("ActivateSessionServerNonceReused",
                          "the ActivateSession serverNonce repeats the previous one; a challenge is never "
                          "reused (OPC 10000-4 section 5.6.3.2)",
                          "client.session.activate_session.server_nonce");
      mActivateState.reset();
      reject_create_session_verification(mAuthenticationToken,
        std::shared_ptr<const ua::ErrorDetail>(std::move(detail)),
        ua::StatusCode{ua::Status::BadNonceInvalid});
      return;
    }
  }

  // Transition to Active.
  mServerNonce = response->server_nonce();
  mSessionState = SessionState::Active;
  update_atomic_snapshots();
  mActivateState.reset();

  // Notify: session activated.
  auto d = mDeps.lock();
  if (d)
  {
    auto sessionIdStr = ua::to_string(mSessionId);
    d->logger()
      .with_category("client.session")
      .info({{"session_id", std::string_view{sessionIdStr}},
              {"revised_timeout_ms", uint64_t(mRevisedSessionTimeoutMs)}},
        "Session activated");
  }

  if (mActivateCallback)
  {
    auto callback = std::move(mActivateCallback);
    mActivateCallback = nullptr;
    // The Session is active; a Good subcode or an Uncertain ServiceResult reaches the caller.
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{serviceStatus});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{serviceStatus});
  }

  // Schedule timeout timer if the server gave us a non-zero timeout.
  if (mRevisedSessionTimeoutMs > 0.0)
  {
    schedule_timeout_timer();
  }
}

void SessionImpl::close_internal(bool deleteSubscriptions)
{
  if (mSessionState == SessionState::Idle || mSessionState == SessionState::Closed)
  {
    // Already idle or closed - nothing to send on the wire, but still emit
    // SessionClosed so the close callback is invoked.
    handle_session_closed(ua::Status::Good, {});
    return;
  }

  if (mSessionState == SessionState::Active || mSessionState == SessionState::Created)
  {
    mSessionState = SessionState::Closing;
    update_atomic_snapshots();

    auto request = std::make_shared<ua::CloseSessionRequest>();
    request->request_header().authentication_token() = mAuthenticationToken;
    // OPC 10000-4 5.6.4: false PARKS this Session's Subscriptions server-side for a later
    // TransferSubscriptions instead of destroying them. Defaulted true by the callers that do not care.
    request->delete_subscriptions() = deleteSubscriptions;

    if (auto d = mDeps.lock())
    {
      request->request_header().return_diagnostics() =
        return_diagnostics_for(request->request_header().return_diagnostics());
      d->logger().with_category("client.session").debug({}, "Sending CloseSession request");
    }

    // Send CloseSession request, bounded by the service timeout. On timeout, proceed
    // to teardown anyway - leaving callbacks parked on a dead server connection
    // blocks io_context drain.
    uint32_t closeTimeoutMs = 10000;
    if (auto d = mDeps.lock())
    {
      auto configured = d->service_timeout_ms();
      if (configured > 0)
      {
        closeTimeoutMs = configured;
      }
    }

    // Single-shot guard so timeout firing first or response firing first delivers exactly once.
    auto fired = std::make_shared<std::atomic<bool>>(false);
    auto deliver = ua::async::post_borrowing(this,
      engaged_strand(mStrand),
      logger(),
      [](SessionImpl& self, ServiceResponseResult result)
      { self.on_close_session_response_received(std::move(result)); });

    // Schedule timeout fallback.

    auto timer = std::make_shared<ua::Timer>(Timer::schedule_after(engaged_strand(mStrand),
      std::chrono::milliseconds{closeTimeoutMs},
      [fired, deliver, closeTimeoutMs](boost::system::error_code ec) mutable
      {
        if (ec)
          return;
        bool expected = false;
        if (!fired->compare_exchange_strong(expected, true, std::memory_order_acq_rel))
          return;
        deliver(ServiceResponseResult{ua::Status::BadTimeout,
          ua::ErrorDetail::build(
            "CloseSessionTimeout", "CloseSession response wait timed out", "client::Session")
            .context(ua::ContextKeys::limit, std::to_string(closeTimeoutMs))});
      }));

    send_session_request(std::move(request),
      [fired, deliver, timer](ServiceResponseResult result) mutable
      {
        bool expected = false;
        if (!fired->compare_exchange_strong(expected, true, std::memory_order_acq_rel))
          return;
        if (*timer)
        {
          timer->cancel();
        }
        deliver(std::move(result));
      });
    return;
  }

  if (mSessionState == SessionState::Closing)
  {
    // Already closing - the close response will complete it.
    return;
  }

  // Creating, ValidatingServerSignature, or Activating - abort the in-progress operation.
  mSessionState = SessionState::Closed;
  update_atomic_snapshots();
  auto abortDetail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
    "SessionAborted", "Session closed during in-progress operation", "client::Session"));
  handle_session_closed(ua::Status::BadSessionClosed, abortDetail);
}

void SessionImpl::on_close_session_response_received(ServiceResponseResult responseResult)
{
  // Check if we're still in Closing state.
  if (mSessionState != SessionState::Closing)
  {
    return;
  }

  mSessionState = SessionState::Closed;
  update_atomic_snapshots();

  // Whether response was good, bad, or timed out, the session is closed.
  ua::StatusCode reason = ua::Status::Good;
  std::shared_ptr<const ua::ErrorDetail> closeDetail;
  if (!responseResult)
  {
    reason = responseResult.status_code();
    closeDetail = responseResult.shared_detail();
  }
  else
  {
    auto* response = dynamic_cast<ua::CloseSessionResponse*>(responseResult.value().get());
    if (response && response->response_header().service_result().is_bad())
    {
      reason = response->response_header().service_result();
      auto serverDiag = detail::attach_wire_marker(response->response_header());
      closeDetail = std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build("CloseSessionFailed", "CloseSession service returned an error", "server")
          .cause(std::move(serverDiag)));
    }
    else if (response)
    {
      // The Session is closed; a Good subcode or an Uncertain ServiceResult reaches the close callback.
      reason = response->response_header().service_result();
    }
  }

  handle_session_closed(reason, closeDetail);
}

void SessionImpl::validate_server_signature_async(ua::ByteString serverCertificateDer,
  ua::ByteString serverSignature, std::function<void(ua::VoidResult)> completionHandler)
{
  try
  {
    // Part 4 Section 5.6.2: Server proves its identity by signing (clientCertificate || clientNonce).
    auto d = mDeps.lock();
    if (!d)
    {
      completionHandler(ua::VoidResult{ua::Status::BadInternalError,
        ua::make_error_detail(
          "DepsExpired", "Session dependencies expired during signature validation", "client::Session")});
      return;
    }

    auto crypto = d->crypto();
    if (!crypto || !mSecurityInfo.securityPolicy)
    {
      d->logger()
        .with_category("client.session")
        .warning({}, "Cannot validate server signature: crypto or security policy unavailable");
      completionHandler(ua::VoidResult{ua::Status::BadSecurityChecksFailed,
        ua::make_error_detail("CryptoUnavailable",
          "Crypto provider or security policy unavailable for server signature verification",
          "client::Session")});
      return;
    }

    // Parse the server certificate to get its public key.
    std::shared_ptr<const ua::X509Certificate> serverCert;
    try
    {
      // The one chain parser: the signature is verified with the leaf's key (decision 26).
      auto parsedField = ua::detail::parse_certificate_field(*crypto, serverCertificateDer);
      if (!parsedField.is_good())
      {
        throw ua::UaException{parsedField.status_code()};
      }
      serverCert = std::move(parsedField).value().front();
    }
    catch (...)
    {
      // read_certificate_from_der throws on invalid/empty DER data - preserve the cause.
      auto er = ua::exception_to_status_code(std::current_exception());
      d->logger()
        .with_category("client.session")
        .warning({},
          "Cannot validate server signature: failed to parse server certificate: {}",
          er.shared_detail() ? er.shared_detail()->summary : "unknown error");
      completionHandler(ua::VoidResult{ua::Status::BadCertificateInvalid,
        ua::make_error_detail("ServerCertificateParseFailed",
          "Failed to parse server certificate for signature verification",
          "client::Session",
          er.shared_detail())});
      return;
    }
    if (!serverCert)
    {
      d->logger()
        .with_category("client.session")
        .warning({}, "Cannot validate server signature: failed to parse server certificate");
      completionHandler(ua::VoidResult{ua::Status::BadCertificateInvalid,
        ua::make_error_detail("ServerCertificateParseFailed",
          "Failed to parse server certificate for signature verification (null result)",
          "client::Session")});
      return;
    }

    // OPC 10000-4 section 6.1.8: with SecureChannelEnhancements the ServerSignature is channel bound (Table
    // 101) and always over the leaf, so there is no chain to fall back to. Its algorithm URI is ignored
    // (Table 174).
    if (mSecurityInfo.securityPolicy->secure_channel_enhancements())
    {
      if (!mCreateState)
      {
        completionHandler(ua::VoidResult{ua::Status::BadInvalidState,
          ua::make_error_detail("NoCreateState",
            "No CreateSession response to verify the ServerSignature of",
            "client::Session")});
        return;
      }
      build_channel_bound_data_async(ua::ChannelBoundSignature::Server,
        *mSecurityInfo.securityPolicy,
        mCreateState->responseServerNonce,
        {},
        {},
        [weakSelf = weak_from_this(),
          serverCert = std::move(serverCert),
          serverSignature = std::move(serverSignature),
          completionHandler = std::move(completionHandler)](ua::ByteStringResult data) mutable
        {
          auto self = weakSelf.lock();
          if (!self)
          {
            completionHandler(ua::VoidResult{ua::Status::BadSessionClosed,
              ua::make_error_detail(
                "SessionDestroyed", "Session destroyed during signature validation", "client::Session")});
            return;
          }
          if (!data.is_good())
          {
            completionHandler(ua::VoidResult{ua::Status::BadSecurityChecksFailed,
              ua::make_error_detail("ServerSignatureDataFailed",
                "The channel bound ServerSignature data could not be built",
                "client::Session",
                data.status_code())});
            return;
          }
          self->verify_channel_bound_server_signature_async(std::move(serverCert),
            std::move(data).value(),
            std::move(serverSignature),
            std::move(completionHandler));
        });
      return;
    }

    // Legacy (Table 102): clientCertificate(DER) || clientNonce.
    ua::ByteString dataToVerify;
    if (mSecurityInfo.clientCertificate)
    {
      dataToVerify = mSecurityInfo.clientCertificate->der_encoding();
    }
    std::ranges::copy(mClientNonce, std::back_inserter(dataToVerify));

    auto verificationInput = std::make_shared<ServerSignatureVerificationInput>(
      ServerSignatureVerificationInput{serverCert, std::move(dataToVerify), std::move(serverSignature)});
    crypto->asymmetric_verify_async(verificationInput,
      mSecurityInfo.securityPolicy->asymmetric_signature_algorithm(),
      verificationInput->serverCertificate->public_key(),
      verificationInput->signedData,
      verificationInput->signature,
      [weakSelf = weak_from_this(),
        strand = engaged_strand(mStrand),
        verificationInput,
        completionHandler = std::move(completionHandler)](ua::VoidResult verifyResult) mutable
      {
        auto goneResult = ua::VoidResult{ua::Status::BadSessionClosed,
          ua::make_error_detail(
            "SessionDestroyed", "Session destroyed during signature validation", "client::Session")};
        auto lockedSelf = weakSelf.lock();
        if (!lockedSelf)
        {
          completionHandler(std::move(goneResult));
          return;
        }
        ua::async::post_borrowing(lockedSelf.get(),
          strand,
          lockedSelf->logger(),
          std::move(completionHandler),
          std::move(goneResult),
          [verificationInput = std::move(verificationInput), verifyResult = std::move(verifyResult)](
            SessionImpl& self, std::function<void(ua::VoidResult)> callback) mutable
          {
            self.on_leaf_server_signature_validated(std::move(verificationInput->serverCertificate),
              std::move(verificationInput->signature),
              std::move(callback),
              std::move(verifyResult));
          })();
      });
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    completionHandler(ua::VoidResult{er, er.shared_detail()});
  }
}

void SessionImpl::on_leaf_server_signature_validated(
  std::shared_ptr<const ua::X509Certificate> serverCertificate, ua::ByteString serverSignature,
  std::function<void(ua::VoidResult)> callback, ua::VoidResult leafVerification)
{
  if (leafVerification.is_good())
  {
    callback(ua::VoidResult{});
    return;
  }

  auto dependencies = mDeps.lock();
  auto certificateStore = dependencies ? dependencies->certificate_store() : nullptr;
  if (!certificateStore)
  {
    complete_invalid_server_signature(std::move(callback), std::move(leafVerification));
    return;
  }

  certificateStore->get_issuer_certificates_async(
    [weakSelf = weak_from_this(),
      strand = engaged_strand(mStrand),
      serverCertificate = std::move(serverCertificate),
      serverSignature = std::move(serverSignature),
      callback = std::move(callback),
      leafVerification = std::move(leafVerification)](ua::CertificateListResult issuers) mutable
    {
      auto goneResult = ua::VoidResult{ua::Status::BadSessionClosed,
        ua::make_error_detail("SessionDestroyed",
          "Session destroyed while loading the client certificate chain",
          "client::Session")};
      auto lockedSelf = weakSelf.lock();
      if (!lockedSelf)
      {
        callback(std::move(goneResult));
        return;
      }
      ua::async::post_borrowing(lockedSelf.get(),
        strand,
        lockedSelf->logger(),
        std::move(callback),
        std::move(goneResult),
        [serverCertificate = std::move(serverCertificate),
          serverSignature = std::move(serverSignature),
          leafVerification = std::move(leafVerification),
          issuers = std::move(issuers)](
          SessionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
        {
          self.on_client_issuer_certificates_loaded(std::move(serverCertificate),
            std::move(serverSignature),
            std::move(completion),
            std::move(leafVerification),
            std::move(issuers));
        })();
    });
}

void SessionImpl::on_client_issuer_certificates_loaded(
  std::shared_ptr<const ua::X509Certificate> serverCertificate, ua::ByteString serverSignature,
  std::function<void(ua::VoidResult)> callback, ua::VoidResult leafVerification,
  ua::CertificateListResult issuerCertificates)
{
  // The issuers are used only from a Good answer: an Uncertain one is refused.
  if (issuerCertificates.is_uncertain())
  {
    callback(ua::VoidResult{ua::client::detail::certificate_store_answer_refused(
      issuerCertificates.status_code(), "client.session.client_issuer_certificates")});
    return;
  }
  if (issuerCertificates.is_bad())
  {
    callback(ua::VoidResult{ua::Status::BadSecurityChecksFailed,
      ua::make_error_detail("ClientIssuerCertificatesUnavailable",
        "Could not load the client issuer Certificates for server signature fallback",
        "client::Session",
        issuerCertificates.status_code())});
    return;
  }

  try
  {
    if (!mSecurityInfo.clientCertificate)
    {
      complete_invalid_server_signature(std::move(callback), std::move(leafVerification));
      return;
    }
    auto fullChain =
      ordered_certificate_chain_der(*mSecurityInfo.clientCertificate, issuerCertificates.value());
    const auto leafSize = mSecurityInfo.clientCertificate->der_encoding().size();
    if (fullChain.size() == leafSize)
    {
      complete_invalid_server_signature(std::move(callback), std::move(leafVerification));
      return;
    }
    std::ranges::copy(mClientNonce, std::back_inserter(fullChain));

    auto dependencies = mDeps.lock();
    auto crypto = dependencies ? dependencies->crypto() : nullptr;
    if (!crypto || !mSecurityInfo.securityPolicy)
    {
      callback(ua::VoidResult{ua::Status::BadSecurityChecksFailed,
        ua::make_error_detail("CryptoUnavailable",
          "Crypto provider or security policy unavailable for full-chain signature verification",
          "client::Session")});
      return;
    }

    auto verificationInput = std::make_shared<ServerSignatureVerificationInput>(
      ServerSignatureVerificationInput{serverCertificate, std::move(fullChain), std::move(serverSignature)});
    crypto->asymmetric_verify_async(verificationInput,
      mSecurityInfo.securityPolicy->asymmetric_signature_algorithm(),
      verificationInput->serverCertificate->public_key(),
      verificationInput->signedData,
      verificationInput->signature,
      [weakSelf = weak_from_this(),
        strand = engaged_strand(mStrand),
        verificationInput,
        callback = std::move(callback)](ua::VoidResult verification) mutable
      {
        verificationInput.reset();
        auto goneResult = ua::VoidResult{ua::Status::BadSessionClosed,
          ua::make_error_detail("SessionDestroyed",
            "Session destroyed during full-chain signature validation",
            "client::Session")};
        auto lockedSelf = weakSelf.lock();
        if (!lockedSelf)
        {
          callback(std::move(goneResult));
          return;
        }
        ua::async::post_borrowing(lockedSelf.get(),
          strand,
          lockedSelf->logger(),
          std::move(callback),
          std::move(goneResult),
          [verification = std::move(verification)](
            SessionImpl& self, std::function<void(ua::VoidResult)> completion) mutable {
            self.on_full_chain_server_signature_validated(std::move(completion), std::move(verification));
          })();
      });
  }
  catch (...)
  {
    auto result = ua::exception_to_status_code(std::current_exception());
    callback(ua::VoidResult{result, result.shared_detail()});
  }
}

void SessionImpl::on_full_chain_server_signature_validated(
  std::function<void(ua::VoidResult)> callback, ua::VoidResult chainVerification)
{
  if (chainVerification.is_good())
  {
    callback(ua::VoidResult{});
    return;
  }
  complete_invalid_server_signature(std::move(callback), std::move(chainVerification));
}

void SessionImpl::build_channel_bound_data_async(ua::ChannelBoundSignature signature,
  const ua::SecurityPolicy& decidingPolicy, ua::ByteString serverNonce, ua::ByteString serverCertificate,
  ua::ByteString clientCertificate, std::function<void(ua::ByteStringResult)> callback)
{
  try
  {
    auto dependencies = mDeps.lock();
    auto crypto = dependencies ? dependencies->crypto() : nullptr;
    if (!crypto)
    {
      callback(ua::ByteStringResult{ua::Status::BadInternalError,
        ua::make_error_detail("CryptoUnavailable",
          "No crypto provider for the channel bound signature data",
          "client::Session")});
      return;
    }
    // The channel this Session is bound to: its ChannelThumbprint and its two certificates.
    const auto leaf = [](const std::shared_ptr<const ua::X509Certificate>& certificate)
    {
      return certificate ? certificate->der_encoding() : ua::ByteString{};
    };
    ua::ChannelBoundSignatureInputs inputs{.channelThumbprint = mSecurityInfo.channelThumbprint,
      .clientNonce = mClientNonce,
      .serverNonce = std::move(serverNonce),
      .serverCertificate = std::move(serverCertificate),
      .serverChannelCertificate = leaf(mSecurityInfo.serverCertificate),
      .clientCertificate = std::move(clientCertificate),
      .clientChannelCertificate = leaf(mSecurityInfo.clientCertificate)};
    ua::build_channel_bound_signature_data_async(signature,
      decidingPolicy.certificate_thumbprint_algorithm(),
      std::move(crypto),
      engaged_strand(mStrand),
      logger(),
      std::move(inputs),
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(ua::ByteStringResult{er, er.shared_detail()});
  }
}

void SessionImpl::verify_channel_bound_server_signature_async(
  std::shared_ptr<const ua::X509Certificate> serverCertificate, ua::ByteString signedData,
  ua::ByteString serverSignature, std::function<void(ua::VoidResult)> callback)
{
  try
  {
    auto input = std::make_shared<ServerSignatureVerificationInput>(ServerSignatureVerificationInput{
      std::move(serverCertificate), std::move(signedData), std::move(serverSignature)});
    auto dependencies = mDeps.lock();
    auto crypto = dependencies ? dependencies->crypto() : nullptr;
    if (!crypto)
    {
      callback(ua::VoidResult{ua::Status::BadSecurityChecksFailed,
        ua::make_error_detail("CryptoUnavailable",
          "Crypto provider unavailable for server signature verification",
          "client::Session")});
      return;
    }
    crypto->asymmetric_verify_async(input,
      mSecurityInfo.securityPolicy->asymmetric_signature_algorithm(),
      input->serverCertificate->public_key(),
      input->signedData,
      input->signature,
      [weakSelf = weak_from_this(), strand = engaged_strand(mStrand), callback = std::move(callback)](
        ua::VoidResult verifyResult) mutable
      {
        auto goneResult = ua::VoidResult{ua::Status::BadSessionClosed,
          ua::make_error_detail(
            "SessionDestroyed", "Session destroyed during signature validation", "client::Session")};
        auto lockedSelf = weakSelf.lock();
        if (!lockedSelf)
        {
          callback(std::move(goneResult));
          return;
        }
        ua::async::post_borrowing(lockedSelf.get(),
          strand,
          lockedSelf->logger(),
          std::move(callback),
          std::move(goneResult),
          [verifyResult = std::move(verifyResult)](
            SessionImpl& self, std::function<void(ua::VoidResult)> completion) mutable
          {
            if (verifyResult.is_good())
            {
              completion(ua::VoidResult{});
              return;
            }
            self.complete_invalid_server_signature(std::move(completion), std::move(verifyResult));
          })();
      });
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(ua::VoidResult{er, er.shared_detail()});
  }
}

void SessionImpl::complete_invalid_server_signature(
  std::function<void(ua::VoidResult)> callback, ua::VoidResult verificationFailure)
{
  if (auto dependencies = mDeps.lock())
  {
    dependencies->logger()
      .with_category("client.session")
      .warning({{"status", std::string_view{"BadApplicationSignatureInvalid"}}},
        "Server application signature verification failed over the leaf and available chain");
  }
  callback(ua::VoidResult{ua::Status::BadApplicationSignatureInvalid,
    ua::make_error_detail("ServerSignatureVerifyFailed",
      "Asymmetric verification of server application signature failed",
      "client::Session",
      verificationFailure.status_code())});
}

// --- Effect helpers ---

void SessionImpl::schedule_timeout_timer()
{
  if (mTimeoutTimer)
  {
    mTimeoutTimer.cancel();
  }

  // Use 75% of the session timeout as the keep-alive interval.
  auto timeoutMs = numeric_cast<int64_t>(mRevisedSessionTimeoutMs * 0.75);
  if (timeoutMs <= 0)
  {
    return;
  }

  auto me = weak_from_this();
  mTimeoutTimer = Timer::schedule_after(engaged_strand(mStrand),
    std::chrono::milliseconds{timeoutMs},
    [me, revisedTimeout = mRevisedSessionTimeoutMs](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }

      auto self = me.lock();
      if (!self)
      {
        return;
      }

      try
      {
        if (self->mSessionState != SessionState::Active)
        {
          return;
        }

        self->mSessionState = SessionState::Closed;
        self->update_atomic_snapshots();
        auto detail = std::shared_ptr<const ua::ErrorDetail>(
          ua::ErrorDetail::build("SessionTimeout", "Session timed out", "client::Session")
            .context(ua::ContextKeys::limit, std::to_string(static_cast<int64_t>(revisedTimeout))));
        self->handle_session_error(ua::Status::BadTimeout, detail);
        self->handle_session_closed(ua::Status::BadTimeout, detail);
      }
      catch (...)
      {
        self->handle_unexpected_exception("client::Session::timeout_timer", std::current_exception());
      }
    });
}

void SessionImpl::handle_session_error(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
{
  auto d = mDeps.lock();
  if (d)
  {
    auto statusHex = fmt::format("0x{:08x}", status.as_uint32());
    if (detail)
    {
      d->logger()
        .with_category("client.session")
        .error({{"status", std::string_view{statusHex}}, {"error", ua::to_string(*detail)}}, "Session error");
    }
    else
    {
      d->logger()
        .with_category("client.session")
        .error({{"status", std::string_view{statusHex}}}, "Session error");
    }
  }

  // Cancel timeout timer so no pending async_waits keep the io_context alive.
  if (mTimeoutTimer)
  {
    mTimeoutTimer.cancel();
  }

  // Release the channel reference - the session is dead and should not keep the channel alive.
  mChannel.reset();

  // Fail all pending service requests. std::exchange leaves mPendingRequests provably
  // empty without reading the moved-from container.
  auto pending = std::exchange(mPendingRequests, {});
  for (auto& [handle, callback] : pending)
  {
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ServiceResponseResult{status, detail});
    else
      ua::detail::invoke_user_callback(callback, ServiceResponseResult{status, detail});
  }

  // Notify opener if still waiting for create.
  if (mOnCreated)
  {
    auto callback = std::move(mOnCreated);
    mOnCreated = nullptr;
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{status, detail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{status, detail});
  }

  // Notify activate waiter if still waiting.
  if (mActivateCallback)
  {
    auto callback = std::move(mActivateCallback);
    mActivateCallback = nullptr;
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{status, detail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{status, detail});
  }

  // Notify error callback.
  if (mOnError)
  {
    if (d)
      ua::detail::invoke_user_callback(d->logger(), mOnError, ua::VoidResult{status, detail});
    else
      ua::detail::invoke_user_callback(mOnError, ua::VoidResult{status, detail});
  }

  // Fire persistent user observer (at-most-once, posted to executor).
  if (mOnSessionError)
  {
    auto userCb = std::move(mOnSessionError);
    mOnSessionError = nullptr;
    auto errorResult = ua::VoidResult{status, detail};
    boost::asio::post(mExecutor,
      ua::async::guarded(logger(),
        [userCb = std::move(userCb), errorResult = std::move(errorResult)]() mutable
        { userCb(std::move(errorResult)); }));
  }
}

void SessionImpl::handle_session_closed(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail)
{
  auto d = mDeps.lock();
  if (d)
  {
    auto statusHex = fmt::format("0x{:08x}", reason.as_uint32());
    if (detail)
    {
      d->logger()
        .with_category("client.session")
        .debug(
          {{"reason", std::string_view{statusHex}}, {"error", ua::to_string(*detail)}}, "Session closed");
    }
    else
    {
      d->logger()
        .with_category("client.session")
        .debug({{"reason", std::string_view{statusHex}}}, "Session closed");
    }
  }

  // Cancel timeout timer and release channel.
  if (mTimeoutTimer)
  {
    mTimeoutTimer.cancel();
  }
  mChannel.reset();

  // Fail any remaining pending service requests. std::exchange leaves mPendingRequests
  // provably empty without reading the moved-from container.
  if (!mPendingRequests.empty())
  {
    auto pending = std::exchange(mPendingRequests, {});
    // A request still pending fails: with the reason when the Session closed on a failure, otherwise (a
    // Good or Uncertain close) with Bad_SessionClosed.
    auto status = !reason.is_bad() ? ua::StatusCode{ua::Status::BadSessionClosed} : reason;
    auto closeDetail = !reason.is_bad() ? std::shared_ptr<const ua::ErrorDetail>{} : detail;
    for (auto& [handle, callback] : pending)
    {
      if (d)
        ua::detail::invoke_user_callback(d->logger(), callback, ServiceResponseResult{status, closeDetail});
      else
        ua::detail::invoke_user_callback(callback, ServiceResponseResult{status, closeDetail});
    }
  }

  // Notify activate waiter if still waiting.
  if (mActivateCallback)
  {
    auto callback = std::move(mActivateCallback);
    mActivateCallback = nullptr;
    auto result =
      !reason.is_bad() ? ua::VoidResult{ua::Status::BadSessionClosed} : ua::VoidResult{reason, detail};
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, std::move(result));
    else
      ua::detail::invoke_user_callback(callback, std::move(result));
  }

  // Detach all waiters before invoking user code; a reentrant close has its own completion.
  auto closeCallbacks = std::exchange(mCloseCallbacks, {});
  for (auto& callback : closeCallbacks)
  {
    // The close callback receives the reason as it is: a Good subcode or an Uncertain code the server
    // answered CloseSession with included.
    auto result = ua::VoidResult{reason, detail};
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, std::move(result));
    else
      ua::detail::invoke_user_callback(callback, std::move(result));
  }

  // Drop any in-flight per-flow state. The post-flip code does not store coroutine
  // frames; the per-flow structs (mCreateState / mActivateState) hold weak captures only,
  // so resetting them inline is safe.
  mCreateState.reset();
  mActivateState.reset();
}

void SessionImpl::handle_channel_disconnected(
  ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
{
  if (mSessionState == SessionState::Closed || mSessionState == SessionState::Idle)
  {
    return;
  }

  // Active (or Created) sessions are recoverable - transition to Disconnected.
  // Sessions in other states (Creating, Activating, Closing) are not recoverable.
  if (mSessionState == SessionState::Active || mSessionState == SessionState::Created)
  {
    mSessionState = SessionState::Disconnected;
    update_atomic_snapshots();

    // Cancel the session timeout timer - it will be rescheduled after reconnection.
    if (mTimeoutTimer)
    {
      mTimeoutTimer.cancel();
    }

    // Release the channel reference - a new channel will be established.
    mChannel.reset();

    // Fail pending service requests - they cannot be completed on the dead channel.
    // std::exchange leaves mPendingRequests provably empty without reading the
    // moved-from container.
    auto pending = std::exchange(mPendingRequests, {});
    for (auto& [handle, callback] : pending)
    {
      auto d = mDeps.lock();
      if (d)
        ua::detail::invoke_user_callback(d->logger(), callback, ServiceResponseResult{status, detail});
      else
        ua::detail::invoke_user_callback(callback, ServiceResponseResult{status, detail});
    }

    if (auto d = mDeps.lock())
    {
      d->logger()
        .with_category("client.session")
        .info({{"status", fmt::format("0x{:08x}", status.as_uint32())}},
          "Channel disconnected - session entered disconnected state");
    }
    return;
  }

  // Non-recoverable states: close permanently.
  const bool wasClosing = (mSessionState == SessionState::Closing);
  mSessionState = SessionState::Closed;
  update_atomic_snapshots();

  // Closing sessions are already shutting down - just complete the close.
  // Other states (Creating, Activating, etc.) represent a real error.
  if (!wasClosing)
  {
    handle_session_error(status, detail);
  }
  handle_session_closed(status, detail);
}

void SessionImpl::update_atomic_snapshots()
{
  mAtomicState.store(utils::to_underlying(mSessionState), std::memory_order_release);
  mAtomicSessionId.store(std::make_shared<const ua::NodeId>(mSessionId));
  mAtomicAuthenticationToken.store(std::make_shared<const ua::NodeId>(mAuthenticationToken));
  mAtomicRevisedSessionTimeoutMs.store(mRevisedSessionTimeoutMs, std::memory_order_release);
}

// --- Public API implementations ---

void SessionImpl::send_request(
  std::shared_ptr<ua::Structure> request, ServiceResponseCallback callback, uint32_t timeoutMs) noexcept
{
  try
  {
    // Capture the callback BY COPY so the surviving original can still report if the post throws.
    ua::async::post_borrowing(this,
      engaged_strand(mStrand),
      logger(),
      [request = std::move(request), callback, timeoutMs](SessionImpl& self) mutable
      {
        try
        {
          auto channel = self.mChannel;
          if (self.mSessionState != SessionState::Active || !channel)
          {
            auto detail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
              "SessionNotActive", "Session is not in Active state for service request", "client::Session"));
            if (auto d = self.mDeps.lock())
              ua::detail::invoke_user_callback(
                d->logger(), callback, ServiceResponseResult{ua::Status::BadSessionClosed, detail});
            else
              ua::detail::invoke_user_callback(
                callback, ServiceResponseResult{ua::Status::BadSessionClosed, detail});
            return;
          }

          auto requestHandle = self.mNextRequestHandle++;
          self.mPendingRequests.emplace(requestHandle, std::move(callback));

          // Send through SecureChannel. The response will come back on the channel's
          // strand - post back to the session strand before accessing session state.
          channel->send_request(std::move(request),
            ua::async::post_borrowing(&self,
              *self.mStrand,
              self.logger(),
              [requestHandle](SessionImpl& postSelf, SecureChannelImpl::ServiceResponseResult result) mutable
              {
                try
                {
                  auto it = postSelf.mPendingRequests.find(requestHandle);
                  if (it == postSelf.mPendingRequests.end())
                  {
                    return;  // Already delivered or cancelled.
                  }

                  auto cb = std::move(it->second);
                  postSelf.mPendingRequests.erase(it);
                  if (auto d = postSelf.mDeps.lock())
                    ua::detail::invoke_user_callback(d->logger(), cb, std::move(result));
                  else
                    ua::detail::invoke_user_callback(cb, std::move(result));
                }
                catch (...)
                {
                  postSelf.handle_unexpected_exception(
                    "client::Session::send_request_response", std::current_exception());
                }
              }),
            timeoutMs);

          // Part 4 section 5.6.2.2 defines revisedSessionTimeout as an inactivity limit: the Server
          // terminates the Session only when the Client fails to ISSUE a Service request within that
          // interval. The watchdog is deliberately early (75%), but it must measure from the latest
          // issued request rather than forever from ActivateSession. This includes Connection keep-alive
          // Reads and Publish requests, so ordinary traffic keeps an otherwise healthy Session active.
          if (self.mRevisedSessionTimeoutMs > 0.0)
          {
            self.schedule_timeout_timer();
          }
        }
        catch (...)
        {
          self.handle_unexpected_exception("client::Session::send_request", std::current_exception());
        }
      })();
  }
  catch (...)
  {
    // Closure construction or post() failed (e.g. bad_alloc) so the work was never queued and the
    // closure's callback will never fire. Report synchronously via the surviving original copy so the
    // error is never silently dropped (never discard an error at a boundary).
    // This catch runs under OOM, so it must NOT allocate: report a BARE status with no ErrorDetail
    // (building one would heap-allocate and could itself throw bad_alloc out of this noexcept function).
    if (auto d = mDeps.lock())
      ua::detail::invoke_user_callback(
        d->logger(), callback, ServiceResponseResult{ua::Status::BadOutOfMemory});
    else
      ua::detail::invoke_user_callback(callback, ServiceResponseResult{ua::Status::BadOutOfMemory});
  }
}

void SessionImpl::activate(Session::ActivateConfig config, ActivateCallback callback) noexcept
{
  try
  {
    // Capture the callback BY COPY so the surviving original can still report if the post throws.
    ua::async::post_borrowing(this,
      engaged_strand(mStrand),
      logger(),
      [config = std::make_shared<Session::ActivateConfig>(std::move(config)), callback](
        SessionImpl& self) mutable
      {
        try
        {
          // ActivateSession may be called from Created (first activation) or Active
          // (re-activation with a different user token - Part 4 5.6.3).
          if (self.mSessionState != SessionState::Created && self.mSessionState != SessionState::Active)
          {
            auto detail =
              std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail("InvalidStateForActivate",
                "Session is not in Created or Active state for ActivateSession",
                "client::Session"));
            if (auto d = self.mDeps.lock())
              ua::detail::invoke_user_callback(
                d->logger(), callback, ua::VoidResult{ua::Status::BadInvalidState, detail});
            else
              ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadInvalidState, detail});
            return;
          }

          const bool wasActive = self.mSessionState == SessionState::Active;
          self.mActivateCallback = std::move(callback);
          self.mSessionState = SessionState::Activating;
          self.update_atomic_snapshots();
          self.activate_internal(std::move(config->identity),
            std::move(config->policyId),
            std::move(config->localeIds),
            wasActive);
        }
        catch (...)
        {
          self.handle_unexpected_exception("client::Session::activate", std::current_exception());
        }
      })();
  }
  catch (...)
  {
    // Closure construction or post() failed (e.g. bad_alloc) so the work was never queued and the
    // closure's callback will never fire. Report synchronously via the surviving original copy so the
    // error is never silently dropped (never discard an error at a boundary).
    // This catch runs under OOM, so it must NOT allocate: report a BARE status with no ErrorDetail
    // (building one would heap-allocate and could itself throw bad_alloc out of this noexcept function).
    if (auto d = mDeps.lock())
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{ua::Status::BadOutOfMemory});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadOutOfMemory});
  }
}

void SessionImpl::activate(std::shared_ptr<SecureChannelImpl> channel, Session::ActivateConfig config,
  ActivateCallback callback) noexcept
{
  try
  {
    // Capture the callback BY COPY so the surviving original can still report if the post throws.
    ua::async::post_borrowing(this,
      engaged_strand(mStrand),
      logger(),
      [channel = std::move(channel),
        config = std::make_shared<Session::ActivateConfig>(std::move(config)),
        callback](SessionImpl& self) mutable
      {
        try
        {
          // Reconnection activate: valid from Disconnected, Created, or Active states.
          if (self.mSessionState != SessionState::Disconnected &&
              self.mSessionState != SessionState::Created && self.mSessionState != SessionState::Active)
          {
            auto detail =
              std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail("InvalidStateForActivate",
                "Session is not in a valid state for ActivateSession with channel rebind",
                "client::Session"));
            if (auto d = self.mDeps.lock())
              ua::detail::invoke_user_callback(
                d->logger(), callback, ua::VoidResult{ua::Status::BadInvalidState, detail});
            else
              ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadInvalidState, detail});
            return;
          }

          // Rebind to the new channel.
          self.mChannel = channel;

          const bool wasActive = self.mSessionState == SessionState::Active;
          self.mActivateCallback = std::move(callback);
          self.mSessionState = SessionState::Activating;
          self.update_atomic_snapshots();

          // The session signatures are bound to the channel they travel on (OPC 10000-4 section 6.1.8), so
          // the Session signs with the new channel's ChannelThumbprint and certificates, read on its strand.
          channel->session_security_info_async(ua::async::post_borrowing(&self,
            engaged_strand(self.mStrand),
            self.logger(),
            [config, wasActive, channelIdentity = channel.get()](
              SessionImpl& session, SecureChannelImpl::SessionSecurityInfoResult info)
            {
              try
              {
                // The read crossed to the channel's strand and back, so a close, a disconnect or another
                // rebind may have ended this activation meanwhile; whoever ended it answered its callback.
                // Cost: three compares.
                if (session.mSessionState != SessionState::Activating ||
                    session.mChannel.get() != channelIdentity || session.mActivateState)
                  return;
                if (!info.is_good())
                {
                  const auto failure = ua::client::detail::answer_refused(
                    info.status_code(), "AnswerUncertain", "client::Session");
                  session.mSessionState = SessionState::Closed;
                  session.update_atomic_snapshots();
                  session.handle_session_error(failure, failure.shared_detail());
                  session.handle_session_closed(failure, failure.shared_detail());
                  return;
                }
                session.mSecurityInfo = std::move(info).value();
                session.activate_internal(std::move(config->identity),
                  std::move(config->policyId),
                  std::move(config->localeIds),
                  wasActive);
              }
              catch (...)
              {
                session.handle_unexpected_exception(
                  "client::Session::activate(channel)", std::current_exception());
              }
            }));
        }
        catch (...)
        {
          self.handle_unexpected_exception("client::Session::activate(channel)", std::current_exception());
        }
      })();
  }
  catch (...)
  {
    // Closure construction or post() failed (e.g. bad_alloc) so the work was never queued and the
    // closure's callback will never fire. Report synchronously via the surviving original copy so the
    // error is never silently dropped (never discard an error at a boundary).
    // This catch runs under OOM, so it must NOT allocate: report a BARE status with no ErrorDetail
    // (building one would heap-allocate and could itself throw bad_alloc out of this noexcept function).
    if (auto d = mDeps.lock())
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{ua::Status::BadOutOfMemory});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{ua::Status::BadOutOfMemory});
  }
}

void SessionImpl::close(bool deleteSubscriptions, CloseCallback callback) noexcept
{
  ua::Logger completionLogger;
  try
  {
    completionLogger = logger();
    if (!callback)
      callback = [](ua::VoidResult) {
      };
    ua::async::post_borrowing(this,
      engaged_strand(mStrand),
      completionLogger,
      std::move(callback),
      ua::VoidResult{},
      [deleteSubscriptions](SessionImpl& self, CloseCallback completion)
      {
        self.mCloseCallbacks.push_back(std::move(completion));
        try
        {
          self.close_internal(deleteSubscriptions);
        }
        catch (...)
        {
          self.mSessionState = SessionState::Closed;
          self.mAtomicState.store(utils::to_underlying(SessionState::Closed), std::memory_order_release);
          self.handle_unexpected_exception("client::Session::close", std::current_exception());
        }
      })();
  }
  catch (...)
  {
    const auto failure = ua::exception_to_status_code(std::current_exception());
    ua::log_exception(completionLogger, ua::LogLevel::Error, "client::Session::close", failure);
    ua::detail::invoke_user_callback(completionLogger, callback, ua::VoidResult{failure});
  }
}

void SessionImpl::close(CloseCallback callback) noexcept
{
  close(true, std::move(callback));
}

ua::NodeId SessionImpl::session_id() const
{
  auto id = mAtomicSessionId.load();
  return id ? *id : ua::NodeId{};
}

double SessionImpl::revised_session_timeout_ms() const
{
  return mAtomicRevisedSessionTimeoutMs.load(std::memory_order_acquire);
}

ua::NodeId SessionImpl::authentication_token() const
{
  auto token = mAtomicAuthenticationToken.load();
  return token ? *token : ua::NodeId{};
}

uint32_t SessionImpl::default_return_diagnostics() const
{
  auto d = mDeps.lock();
  return d ? d->default_return_diagnostics() : 0;
}

uint32_t SessionImpl::timeout_hint_for(uint32_t requestValue) const
{
  if (requestValue != 0)
  {
    return requestValue;
  }
  auto d = mDeps.lock();
  return d ? d->service_timeout_ms() : 0;
}

uint32_t SessionImpl::return_diagnostics_for(uint32_t requestValue) const
{
  const uint64_t override = mReturnDiagnosticsOverride.load(std::memory_order_acquire);
  if (override != UINT64_MAX)
  {
    return static_cast<uint32_t>(override);
  }
  return requestValue == 0 ? default_return_diagnostics() : requestValue;
}

void SessionImpl::set_return_diagnostics_override(std::optional<uint32_t> mask) noexcept
{
  mReturnDiagnosticsOverride.store(
    mask ? static_cast<uint64_t>(*mask) : UINT64_MAX, std::memory_order_release);
}

bool SessionImpl::wrap_tier0() const
{
  auto d = mDeps.lock();
  return d != nullptr && d->wrap_tier0();
}

ua::String SessionImpl::next_audit_entry_id() const
{
  return mConfig.auditEntryIdProvider ? mConfig.auditEntryIdProvider() : ua::String{};
}

bool SessionImpl::is_active() const
{
  return mAtomicState.load(std::memory_order_acquire) == utils::to_underlying(SessionState::Active);
}

bool SessionImpl::is_created() const
{
  return mAtomicState.load(std::memory_order_acquire) == utils::to_underlying(SessionState::Created);
}

bool SessionImpl::is_disconnected() const
{
  return mAtomicState.load(std::memory_order_acquire) == utils::to_underlying(SessionState::Disconnected);
}

// --- Helpers ---

void SessionImpl::send_session_request(
  std::shared_ptr<ua::Structure> request, SecureChannelImpl::ServiceResponseCallback callback)
{
  if (!mChannel)
  {
    callback(ServiceResponseResult{ua::Status::BadSecureChannelClosed});
    return;
  }
  auto* lifecycleRequest = dynamic_cast<ua::CreateSessionRequest*>(request.get());
  ua::RequestHeader* header = lifecycleRequest != nullptr ? &lifecycleRequest->request_header() : nullptr;
  if (auto* activationRequest = dynamic_cast<ua::ActivateSessionRequest*>(request.get()))
    header = &activationRequest->request_header();
  if (auto* closeRequest = dynamic_cast<ua::CloseSessionRequest*>(request.get()))
    header = &closeRequest->request_header();
  uint32_t timeoutMs = 0;
  if (header != nullptr)
  {
    // Lifecycle requests use the same Part 4 section 7.33 timestamp semantics as typed services.
    header->timestamp() = ua::DateTime::now();
    if (header->audit_entry_id().empty())
      header->audit_entry_id() = next_audit_entry_id();
    // The session lifecycle requests are sent before (or while dismantling) the Session that would
    // otherwise resolve the hint, so the channel resolves it - and the resolved value is passed on
    // as the deadline so the hint sent and the deadline enforced stay one number.
    timeoutMs = mChannel->timeout_hint_for(header->timeout_hint());
    header->timeout_hint() = timeoutMs;
  }
  mChannel->send_request(std::move(request), std::move(callback), timeoutMs);
}

void SessionImpl::handle_unexpected_exception(const char* site, std::exception_ptr ex)
{
  auto er = ua::exception_to_status_code(std::move(ex));
  const auto& sc = er;

  auto d = mDeps.lock();
  if (d)
  {
    auto sessionLogger = d->logger().with_category("client.session");
    ua::log_exception(sessionLogger, ua::LogLevel::Error, site, er);
  }

  // Cancel timeout timer and release channel.
  if (mTimeoutTimer)
  {
    mTimeoutTimer.cancel();
  }
  mChannel.reset();

  const auto& exDetail = er.shared_detail();

  // Fail all pending requests. std::exchange leaves mPendingRequests provably empty
  // without reading the moved-from container.
  auto pending = std::exchange(mPendingRequests, {});
  for (auto& [handle, callback] : pending)
  {
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ServiceResponseResult{sc, exDetail});
    else
      ua::detail::invoke_user_callback(callback, ServiceResponseResult{sc, exDetail});
  }

  if (mOnCreated)
  {
    auto callback = std::move(mOnCreated);
    mOnCreated = nullptr;
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{sc, exDetail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{sc, exDetail});
  }

  if (mActivateCallback)
  {
    auto callback = std::move(mActivateCallback);
    mActivateCallback = nullptr;
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{sc, exDetail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{sc, exDetail});
  }

  auto closeCallbacks = std::exchange(mCloseCallbacks, {});
  for (auto& callback : closeCallbacks)
  {
    if (d)
      ua::detail::invoke_user_callback(d->logger(), callback, ua::VoidResult{sc, exDetail});
    else
      ua::detail::invoke_user_callback(callback, ua::VoidResult{sc, exDetail});
  }

  if (mOnError)
  {
    if (d)
      ua::detail::invoke_user_callback(d->logger(), mOnError, ua::VoidResult{sc, exDetail});
    else
      ua::detail::invoke_user_callback(mOnError, ua::VoidResult{sc, exDetail});
  }
}

}  // namespace ua::client
