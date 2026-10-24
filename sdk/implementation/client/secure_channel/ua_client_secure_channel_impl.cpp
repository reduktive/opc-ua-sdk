// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Client SecureChannel - strand-serialized component managing OPN/CLO lifecycle, service request correlation,
// and token renewal directly (no separate logic/shell split).
//
// Request flow (outgoing):
//   send_request() -> strand post -> assign requestId -> queue message -> process_outgoing_messages()
//     -> SecurityPolicy::encode_message() -> ConnectionProtocol::send_message_chunk()
//
// Response flow (incoming):
//   wire bytes -> ConnectionProtocol -> receive_message_chunk()
//     -> queue -> process_incoming_message_chunks()
//       -> SecurityPolicy::decode_message_chunk() -> receive_response_message()
//         -> UA Binary decode -> correlate requestId -> deliver to pending callback

#include "ua_server_cert_validator.h"
#include "ua_certificate_validation_paths.h"
#include "ua_x509_certificate.h"
#include "ua_client_own_cert_validation.h"
#include "ua_client_secure_channel_impl.h"
#include "ua_client_answer_status.h"
#include "ua_security_policy_internal.h"

#include "ua_client_session_impl.h"

#include "ua_binary_codec.h"
#include "ua_client_encoding_limits.h"
#include "ua_defines.h"
#include "ua_close_secure_channel_request.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_log_exception.h"
#include "ua_memory_stream.h"
#include "ua_on_strand.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_security_policy.h"
#include "ua_service_fault.h"
#include "ua_security_token.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_utilities.h"
#include "ua_connection_protocol.h"
#include "ua_connection_protocol_limits.h"
#include "ua_response_diagnostics.h"

#include "fmt/format.h"

#include <algorithm>
#include <utility>

namespace ua::client
{

// --- Lifecycle ---

SecureChannelImpl::SecureChannelImpl(std::weak_ptr<SecureChannelDependencies> deps,
  std::shared_ptr<ua::ConnectionProtocol> connection,
  const ua::connection_protocol::NegotiatedLimits& negotiatedLimits, Config config, OpenedCallback onOpened,
  ErrorCallback onError)
  : mDeps(std::move(deps)), mConfig(config), mConnection(std::move(connection)),
    mOnOpened(std::move(onOpened)), mOnError(std::move(onError)),
    mOnChannelError(std::move(config.onChannelError)), mCloseTransportTimeoutMs(mConfig.closeTransportTimeout)
{
  auto d = mDeps.lock();
  check(d);

  mExecutor = d->executor();
  mStrand.emplace(boost::asio::make_strand(mExecutor));

  mContext = std::make_shared<ua::SecureChannelContext>();
  mContext->role = ua::ChannelRole::Client;
  mContext->boundStrand = mStrand;
  mContext->logger = d->logger().with_category("client.secure_channel");
  mContext->negotiatedLimits = negotiatedLimits;
  mContext->encodingLimits = make_client_encoding_limits(d->configuration(),
    mConfig.maxInboundStringLength,
    mConfig.maxInboundByteStringLength,
    mConfig.maxInboundArrayLength);
  mContext->crypto = d->crypto();
  // W6b-1 (CL-PULLCRT-001): when a per-open trust-store override is configured, OPN server-certificate
  // validation uses THAT store instead of the deps runtime store (bootstrap-trust for a GDS Pull
  // connection). mContext->mCertStore is a weak_ptr, so the override is kept alive by mConfig (a
  // retained member) for the channel's whole lifetime. A null override falls back to the runtime store.
  // NOTE (section 3.1 W6b-1): the override is PER-OPEN. This is a fresh SecureChannelImpl, so a full
  // RECONNECT that rebuilds the OpenChannelConfig without the override would silently revert to the runtime
  // store  -  the reconnect wiring MUST re-thread it (the deferred W6b-2 obligation); today override
  // connections are single-shot (no production reconnect wiring exists). Under SecurityPolicy None no
  // server-cert validation runs at all, so the override is a no-op there.
  if (mConfig.trustStoreOverride)
  {
    // Forensic trace on a MITM-defense surface: record that this channel validates the server certificate
    // against a per-open bootstrap-trust store, NOT the Client's runtime trust store.
    mContext->logger.info({{"trust_source", "bootstrap_override"}},
      "OPN server-certificate validation uses a per-open bootstrap-trust store override, not the runtime "
      "trust store");
    mContext->certStore = mConfig.trustStoreOverride;
  }
  else
  {
    mContext->certStore = d->certificate_store();
  }
  mContext->endpointUrl = mConfig.endpointUrl;
  mContext->relaxHostNameCheck = mConfig.relaxHostNameCheck;
  if (mConfig.validatedServerRequest)
  {
    mContext->onRemoteCertificateValidated = [record = mConfig.validatedServerRequest](
                                               const ua::CertificateValidationRequest& request)
    {
      record->set(request);
    };
  }
  // OPC 10000-4 section 6.1.3: a server certificate accepted with suppressed errors is reported - one
  // warning each through the client's logger (owner review item 9).
  mContext->onRemoteCertificateErrorsSuppressed =
    [logger = mContext->logger](
      const ua::CertificateValidationRequest& request, const std::vector<ua::StatusCode>& suppressed)
  {
    ua::client::detail::log_suppressed_certificate_errors(
      logger, request.certificate ? request.certificate->subject_common_name() : std::string{}, suppressed);
  };

  // Client namespace callback: for wire encoding, the client only uses namespace 0 (OPC UA built-in).
  mContext->namespaceIndexCallback = [](ua::string_view /*uri*/) -> uint16_t
  {
    return 0;
  };

  mServiceTimeoutMs = d->service_timeout_ms();
  mIncomingChunkQueueDepthCap = std::max<uint32_t>(mConfig.incomingChunkQueueDepth, 1);

  if (mConfig.securityPolicyFactory)
  {
    mSecurityPolicy = mConfig.securityPolicyFactory(mConfig.securityPolicyId);
  }
  else
  {
    mSecurityPolicy = ua::SecurityPolicy::create(mConfig.securityPolicyId);
  }
  check(mSecurityPolicy);
  mContext->securityPolicy = mSecurityPolicy;
  mContext->initialise_sequence_numbers(mSecurityPolicy->uses_legacy_sequence_no());
  mContext->messageSecurityMode = mConfig.securityMode;

  // Set remote certificate from config (provided by caller from GetEndpoints).
  if (mConfig.serverCertificate)
  {
    mContext->remoteCertificate = mConfig.serverCertificate;
  }
}

SecureChannelImpl::~SecureChannelImpl()
{
  // RAII registry: unregister from the client-side cascading-shutdown
  // registry. No-op if the client is already gone.
  if (auto deps = mDeps.lock())
    deps->unregister_channel(this);

  // Cancel renewal timer to avoid dangling weak_ptr invocations.
  if (mRenewalTimer)
  {
    mRenewalTimer.cancel();
  }
  if (mOpnTimer)
  {
    mOpnTimer.cancel();
  }
  for (auto& [id, timer] : mRequestTimers)
  {
    timer.cancel();
  }

  // Safety net: resolve any pending callbacks so callers never block forever.
  auto dtorDeps = mDeps.lock();
  auto dtorLogger = dtorDeps ? dtorDeps->logger() : ua::Logger{};

  if (mOnOpened)
  {
    auto callback = std::move(mOnOpened);
    mOnOpened = nullptr;
    auto detail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
      "ChannelDestroyed", "SecureChannel destroyed while opening", "client::SecureChannel"));
    ua::detail::invoke_user_callback(
      dtorLogger, callback, ua::VoidResult{ua::Status::BadSecureChannelClosed, detail});
  }
  if (mCloseCallback)
  {
    auto callback = std::move(mCloseCallback);
    mCloseCallback = nullptr;
    auto detail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
      "ChannelDestroyed", "SecureChannel destroyed while closing", "client::SecureChannel"));
    ua::detail::invoke_user_callback(
      dtorLogger, callback, ua::VoidResult{ua::Status::BadSecureChannelClosed, detail});
  }

  // Fail all pending service requests.
  auto pendingDetail = std::shared_ptr<const ua::ErrorDetail>(
    ua::ErrorDetail::build(
      "ChannelDestroyed", "SecureChannel destroyed with pending requests", "client::SecureChannel")
      .context(ua::ContextKeys::countTotal, std::to_string(mPendingRequests.size())));
  for (auto& [id, cb] : mPendingRequests)
  {
    ua::detail::invoke_user_callback(
      dtorLogger, cb, ServiceResponseResult{ua::Status::BadSecureChannelClosed, pendingDetail});
  }
  mPendingRequests.clear();

  // Fire user observer if channel was opened but destroyed without explicit close.
  if (mOnChannelError && !mOnOpened)
  {
    auto dtorDetail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
      "ChannelDestroyed", "SecureChannel destroyed unexpectedly", "client::SecureChannel"));
    // Cannot post to executor in destructor - invoke inline as last resort.
    ua::detail::invoke_user_callback(
      dtorLogger, mOnChannelError, ua::VoidResult{ua::Status::BadSecureChannelClosed, dtorDetail});
    mOnChannelError = nullptr;
  }

  if (mConnection)
  {
    mConnection->close_async();
  }
}

std::shared_ptr<SecureChannelImpl> SecureChannelImpl::create(std::weak_ptr<SecureChannelDependencies> deps,
  std::shared_ptr<ua::ConnectionProtocol> connection,
  ua::connection_protocol::NegotiatedLimits negotiatedLimits, Config config, OpenedCallback onOpened,
  ErrorCallback onError)
{
  auto impl = create_unstarted(std::move(deps),
    std::move(connection),
    negotiatedLimits,
    std::move(config),
    std::move(onOpened),
    std::move(onError));
  impl->initialise();
  return impl;
}

void SecureChannelImpl::start()
{
  initialise();
}

std::shared_ptr<SecureChannelImpl> SecureChannelImpl::create_unstarted(
  std::weak_ptr<SecureChannelDependencies> deps, std::shared_ptr<ua::ConnectionProtocol> connection,
  ua::connection_protocol::NegotiatedLimits negotiatedLimits, Config config, OpenedCallback onOpened,
  ErrorCallback onError)
{
  class Wrapper : public SecureChannelImpl
  {
  public:
    Wrapper(std::weak_ptr<SecureChannelDependencies> deps, std::shared_ptr<ua::ConnectionProtocol> connection,
      ua::connection_protocol::NegotiatedLimits negotiatedLimits, Config config, OpenedCallback onOpened,
      ErrorCallback onError)
      : SecureChannelImpl(std::move(deps), std::move(connection), negotiatedLimits, config,
          std::move(onOpened), std::move(onError))
    {}
  };

  auto impl = std::make_shared<Wrapper>(std::move(deps),
    std::move(connection),
    negotiatedLimits,
    config,
    std::move(onOpened),
    std::move(onError));

  // RAII registry: register with the client (via the deps) immediately after
  // construction so cascading shutdown can find this channel. The destructor
  // unregisters.
  if (auto lockedDeps = impl->mDeps.lock())
    lockedDeps->register_channel(std::weak_ptr<SecureChannelImpl>(impl));

  return impl;
}

void SecureChannelImpl::initialise()
{
  // Test path: allow constructing without an attached ConnectionProtocol.
  if (!mConnection)
  {
    return;
  }

  auto initDeps = mDeps.lock();
  auto initLogger = initDeps ? initDeps->logger().with_category("client.secure_channel") : ua::Logger{};

  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }

  // Wire up ConnectionProtocol callbacks. Each callback hops onto the channel's own strand with weak
  // lifetime; a stale callback no-ops on its strand turn.
  // The error sink delegates the fatal close (the trailing `true`): after a fatal error on an open
  // channel the protocol leaves the transport writable so this channel can send its CloseSecureChannel
  // request (Part 6 7.1.5).
  mConnection->set_callbacks(
    ua::async::post_borrowing(this,
      *mStrand,
      initLogger,
      [](SecureChannelImpl& self, ua::StatusCode status, std::vector<ua::byte> messageChunk)
      {
        try
        {
          self.receive_message_chunk(status, std::move(messageChunk));
        }
        catch (...)
        {
          self.handle_unexpected_exception(
            "client::SecureChannel::receive_message_chunk", std::current_exception());
        }
      }),
    ua::async::post_borrowing(this,
      *mStrand,
      initLogger,
      [](SecureChannelImpl& self,
        ua::StatusCode status,
        ua::string_view /*errorDescription*/,
        ua::FatalCloseDisposition disposition)
      {
        try
        {
          self.receive_connection_error(status, disposition);
        }
        catch (...)
        {
          self.handle_unexpected_exception(
            "client::SecureChannel::receive_transport_error", std::current_exception());
        }
      }),
    /*delegateFatalClose=*/true);

  // Begin OPN handshake: post start_open onto the strand.
  ua::async::post_borrowing(this, *mStrand, initLogger, [](SecureChannelImpl& self) { self.start_open(); })();
}

void SecureChannelImpl::start_open()
{
  try
  {
    // Store security config up-front so subsequent continuations can read it.
    mIsAuthenticated = mSecurityPolicy->is_authenticated();
    mNonceLength = numeric_cast<uint32_t>(mSecurityPolicy->nonce_length());
    mRequestedLifetimeMs = mConfig.requestedLifetimeMs;
    mChannelSecurityMode = mConfig.securityMode;

    if (mIsAuthenticated)
    {
      auto deps = mDeps.lock();
      check(deps);

      auto certStore = deps->certificate_store();
      if (!certStore)
      {
        // 5.3 inline-completion: fail-fast before any async I/O.
        handle_channel_error(ua::Status::BadSecurityChecksFailed,
          ua::ErrorDetail::build("ClientCertificateRetrievalFailed",
            "No certificate store configured for authenticated security policy",
            "client::SecureChannel")
            .context(ua::ContextKeys::securityPolicy,
              std::string(ua::utils::get_security_policy_uri(mConfig.securityPolicyId)))
            .context(ua::ContextKeys::endpointUrl, mContext->endpointUrl));
        return;
      }

      auto certLogger = deps->logger().with_category("client.secure_channel");
      // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
      // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
      if (!mStrand.has_value())
      {
        mStrand.emplace(boost::asio::make_strand(mExecutor));
      }
      certStore->get_application_certificate_async(mSecurityPolicy->certificate_type(),
        ua::async::post_borrowing(this,
          *mStrand,
          certLogger,
          [](SecureChannelImpl& self, ua::CertificateStore::ApplicationCertificateResult result)
          { self.on_application_certificate_loaded(std::move(result)); }));
      return;
    }

    // Unauthenticated path: skip cert load and nonce; send OPN-Issue inline.
    send_opn_request_and_arm_deadline(ua::ByteString{});
  }
  catch (...)
  {
    handle_unexpected_exception("client::SecureChannel::start_open", std::current_exception());
  }
}

void SecureChannelImpl::on_application_certificate_loaded(
  ua::CertificateStore::ApplicationCertificateResult result)
{
  if (mChannelState == ChannelState::Closed)
  {
    return;
  }

  // The channel presents the own certificate only from a Good answer: an Uncertain one is refused.
  if (result.is_uncertain())
  {
    auto refusal = ua::client::detail::certificate_store_answer_refused(
      result.status_code(), "client.secure_channel.application_certificate");
    handle_channel_error(refusal, refusal.shared_detail());
    return;
  }

  if (result.is_bad())
  {
    handle_channel_error(result.status_code(),
      ua::make_error_detail("ClientCertificateRetrievalFailed",
        "Could not retrieve client application certificate from certificate store",
        "client::SecureChannel",
        result.shared_detail()));
    return;
  }

  try
  {
    auto cert = std::move(result).value();
    mContext->localCertificate = cert.certificate;
    mContext->localKeyPair = cert.keys;
    mContext->localIssuerCertificates = cert.issuerCertificates;

    // C13: the own certificate must comply with this endpoint's SecurityPolicy (OPC 10000-7 profile
    // database) before it is presented; a non-compliant one is refused here with the rule named.
    if (mSecurityPolicy && mSecurityPolicy->is_authenticated() && cert.certificate)
    {
      const ua::X509Certificate& signer = cert.issuerCertificates.empty() || !cert.issuerCertificates.front()
                                            ? *cert.certificate
                                            : *cert.issuerCertificates.front();
      auto compliance =
        detail::check_own_certificate_for_endpoint(*cert.certificate, signer, *mSecurityPolicy);
      if (compliance.is_bad())
      {
        handle_channel_error(compliance.status_code(),
          ua::make_error_detail("OwnCertificateViolatesEndpointPolicy",
            "The client application certificate does not comply with the endpoint's SecurityPolicy",
            "client::SecureChannel",
            compliance.shared_detail()));
        return;
      }
    }

    start_nonce_generation_for_open();
  }
  catch (...)
  {
    handle_unexpected_exception(
      "client::SecureChannel::on_application_certificate_loaded", std::current_exception());
  }
}

void SecureChannelImpl::start_nonce_generation_for_open()
{
  try
  {
    const uint32_t nonceLen = mNonceLength > 0 ? mNonceLength : 32;
    auto nonceDeps = mDeps.lock();
    auto nonceLogger = nonceDeps ? nonceDeps->logger().with_category("client.secure_channel") : ua::Logger{};
    // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
    // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
    if (!mStrand.has_value())
    {
      mStrand.emplace(boost::asio::make_strand(mExecutor));
    }
    generate_nonce_async(nonceLen,
      ua::async::post_borrowing(this,
        *mStrand,
        nonceLogger,
        [](SecureChannelImpl& self, ua::ByteStringResult nonceResult)
        { self.on_open_nonce_generated(std::move(nonceResult)); }));
  }
  catch (...)
  {
    handle_unexpected_exception(
      "client::SecureChannel::start_nonce_generation_for_open", std::current_exception());
  }
}

void SecureChannelImpl::on_open_nonce_generated(ua::ByteStringResult nonce)
{
  if (mChannelState == ChannelState::Closed)
  {
    return;
  }

  // The OpenSecureChannel request carries a nonce only from a Good crypto answer: an Uncertain one is
  // refused.
  if (nonce.is_uncertain())
  {
    auto refusal = ua::security_internal::not_good_answer(
      nonce.status_code(), ua::Status::BadInternalError, "client.secure_channel.open_nonce");
    handle_channel_error(refusal, refusal.shared_detail());
    return;
  }

  if (nonce.is_bad())
  {
    handle_channel_error(nonce.status_code(),
      ua::ErrorDetail::build("EphemeralKeyGenerationFailed",
        "Failed to generate client nonce for OPN-Issue",
        "client::SecureChannel")
        .context(ua::ContextKeys::sizeExpected, std::to_string(mNonceLength))
        .cause(nonce.shared_detail()));
    return;
  }

  try
  {
    send_opn_request_and_arm_deadline(std::move(nonce).value());
  }
  catch (...)
  {
    handle_unexpected_exception("client::SecureChannel::on_open_nonce_generated", std::current_exception());
  }
}

void SecureChannelImpl::send_opn_request_and_arm_deadline(ua::ByteString clientNonce)
{
  mChannelState = ChannelState::Opening;
  mLastClientNonce = clientNonce;

  auto request = std::make_shared<ua::OpenSecureChannelRequest>();
  request->client_protocol_version() = 0;
  request->request_type() = ua::SecurityTokenRequestType::Issue;
  request->security_mode() = mChannelSecurityMode;
  request->client_nonce() = clientNonce;
  request->requested_lifetime() = mRequestedLifetimeMs;
  if (mConfig.auditEntryIdProvider)
    request->request_header().audit_entry_id() = mConfig.auditEntryIdProvider();

  if (auto d = mDeps.lock())
  {
    d->logger()
      .with_category("client.secure_channel")
      .debug({{"request_type", "Issue"}}, "Sending OpenSecureChannel request");
  }

  auto requestId = mNextRequestId++;
  mOpnRequestId = requestId;
  send_message_internal(requestId, std::move(request));

  // Schedule OPN handshake deadline timer.
  if (mServiceTimeoutMs > 0)
  {

    auto opnMe = weak_from_this();
    // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
    // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
    if (!mStrand.has_value())
    {
      mStrand.emplace(boost::asio::make_strand(mExecutor));
    }
    mOpnTimer = Timer::schedule_after(*mStrand,
      std::chrono::milliseconds{mServiceTimeoutMs},
      [opnMe](boost::system::error_code ec)
      {
        if (ec)
          return;
        auto s = opnMe.lock();
        if (!s)
          return;
        try
        {
          auto detail = std::shared_ptr<const ua::ErrorDetail>(
            ua::ErrorDetail::build(
              "OPNTimeout", "OpenSecureChannel handshake timed out", "client::SecureChannel")
              .context(ua::ContextKeys::limit, std::to_string(s->mServiceTimeoutMs))
              .context(ua::ContextKeys::endpointUrl, s->mContext->endpointUrl));
          s->handle_channel_error(ua::Status::BadTimeout, std::move(detail));
        }
        catch (...)
        {
          s->handle_unexpected_exception("client::SecureChannel::opn_timeout", std::current_exception());
        }
      });
  }
}

// --- Wire callbacks ---

void SecureChannelImpl::receive_message_chunk(ua::StatusCode status, std::vector<ua::byte>&& messageChunk)
{
  if (status.is_bad())
  {
    if (mChannelState != ChannelState::Closed)
    {
      auto detail = std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build(
        "ChunkReceiveError", "Message chunk received with transport error", "client::SecureChannel")
                                                             .cause(status));
      if (mChannelState == ChannelState::Open && incoming_pending())
      {
        // Chunks that arrived before the failure are processed first (see mDeferredTransportFailure).
        if (!mDeferredTransportFailure)
          mDeferredTransportFailure.emplace(status, std::move(detail));
        return;
      }
      mChannelState = ChannelState::Closed;
      handle_channel_error(status, std::move(detail));
    }
    return;
  }

  mIncomingMessageChunks.push(std::move(messageChunk));

  // Backpressure: once the queue reaches its depth cap, ask the transport to stop reading further
  // messages. No chunk is dropped - the transport finishes any in-flight message and withholds the next
  // header read until resume_reads() (in drain_incoming) is called as the queue drains. mReadPaused
  // guards against repeated pause calls.
  if (!mReadPaused && mIncomingMessageChunks.size() >= mIncomingChunkQueueDepthCap)
  {
    mReadPaused = true;
    if (mConnection)
    {
      mConnection->pause_reads();
    }
  }

  if (!mIncomingDrainScheduled)
  {
    mIncomingDrainScheduled = true;
    drain_incoming();
  }
}

void SecureChannelImpl::receive_transport_error(ua::StatusCode status, ua::string_view errorDescription)
{
  if (mChannelState == ChannelState::Closed)
    return;

  // If we are gracefully closing and waiting for the server to close the transport,
  // this signals success of that wait - let the close coroutine drive teardown.
  if (mChannelState == ChannelState::Closing && mTransportClosedCallback)
  {
    auto callback = std::move(mTransportClosedCallback);
    mTransportClosedCallback = nullptr;
    callback(ua::VoidResult{});
    return;
  }

  std::shared_ptr<const ua::ErrorDetail> detail;
  if (!errorDescription.empty())
  {
    detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::ErrorDetail::build("TransportError", "Transport reported an error", "transport")
        .context(ua::ContextKeys::errorMessage, std::string{errorDescription}));
  }
  if (mChannelState == ChannelState::Open && incoming_pending())
  {
    // A server may answer and then close (ApplyChanges, OPC 10000-12 7.10.6): the response it sent before
    // the close is still queued or decoding here, and is delivered before the failure. Cost: one check per
    // transport failure; the wait is bounded by the incoming-chunk queue cap.
    if (!mDeferredTransportFailure)
      mDeferredTransportFailure.emplace(status, std::move(detail));
    return;
  }
  mChannelState = ChannelState::Closed;
  handle_channel_error(status, std::move(detail));
}

void SecureChannelImpl::deliver_deferred_transport_failure()
{
  if (!mDeferredTransportFailure || incoming_pending())
    return;
  auto [status, detail] = std::move(*mDeferredTransportFailure);
  mDeferredTransportFailure.reset();
  if (mChannelState == ChannelState::Closed)
    return;  // a decode failure already closed the channel
  if (mChannelState == ChannelState::Closing && mTransportClosedCallback)
  {
    // A response handler began an orderly close meanwhile: the transport's close completes it.
    auto callback = std::move(mTransportClosedCallback);
    mTransportClosedCallback = nullptr;
    callback(ua::VoidResult{});
    return;
  }
  mChannelState = ChannelState::Closed;
  handle_channel_error(status, std::move(detail));
}

void SecureChannelImpl::receive_connection_error(ua::StatusCode status, ua::FatalCloseDisposition disposition)
{
  if (disposition == ua::FatalCloseDisposition::TransportClosed)
  {
    receive_transport_error(status, "");
    return;
  }

  if (mChannelState == ChannelState::Closed)
    return;

  // An orderly close waiting for the transport to close takes this as that close, as for a dead socket.
  if (mChannelState == ChannelState::Closing && mTransportClosedCallback)
  {
    receive_transport_error(status, "");
    return;
  }

  // The transport is still writable: handle_channel_error sends the CloseSecureChannel an open channel
  // owes and closes the transport after it; any other state closes the transport at once.
  handle_channel_error(status, nullptr);
}

// --- Drain incoming chunks ---

void SecureChannelImpl::drain_incoming()
{
  if (mChannelState == ChannelState::Closed)
  {
    mIncomingDrainScheduled = false;
    return;
  }

  if (mIncomingMessageChunks.empty())
  {
    mIncomingDrainScheduled = false;
    deliver_deferred_transport_failure();
    return;
  }

  auto messageChunk = std::move(mIncomingMessageChunks.front());
  mIncomingMessageChunks.pop();

  // Backpressure release: once the queue drains below half the cap (hysteresis), resume the transport
  // read pump if this channel paused it. Paired with the pause in receive_message_chunk.
  if (mReadPaused && mIncomingMessageChunks.size() <= mIncomingChunkQueueDepthCap / 2)
  {
    mReadPaused = false;
    if (mConnection)
    {
      mConnection->resume_reads();
    }
  }

  try
  {
    auto decodeDeps = mDeps.lock();
    auto decodeLogger =
      decodeDeps ? decodeDeps->logger().with_category("client.secure_channel") : ua::Logger{};
    // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
    // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
    if (!mStrand.has_value())
    {
      mStrand.emplace(boost::asio::make_strand(mExecutor));
    }
    mSecurityPolicy->decode_message_chunk_async(mContext,
      ByteString{span<const byte>{messageChunk}},
      ua::async::post_borrowing(this,
        *mStrand,
        decodeLogger,
        [](SecureChannelImpl& self, ua::DecodedMessageChunkResult result)
        { self.on_chunk_decoded(std::move(result)); }));
  }
  catch (...)
  {
    handle_chunk_decode_failure(std::current_exception());
  }
}

void SecureChannelImpl::on_chunk_decoded(ua::DecodedMessageChunkResult result)
{
  if (mChannelState == ChannelState::Closed)
  {
    mIncomingDrainScheduled = false;
    return;
  }

  if (!result.is_good())
  {
    handle_chunk_decode_failure(std::make_exception_ptr(ua::UaException{result.status_code().as_status(),
      ua::make_error_detail("MessageChunkDecodeFailed",
        "SecurityPolicy failed to decode incoming message chunk",
        "client::SecureChannel",
        result.shared_detail())}));
    return;
  }

  optional<std::pair<uint32_t, ua::ByteString>> decoded;
  try
  {
    decoded = std::move(result).value();
  }
  catch (...)
  {
    handle_chunk_decode_failure(std::current_exception());
    return;
  }

  if (decoded.has_value())
  {
    const span<const byte> bodySpan = decoded->second;
    try
    {
      receive_response_message(decoded->first, std::vector<byte>{bodySpan.begin(), bodySpan.end()});
    }
    catch (...)
    {
      handle_chunk_decode_failure(std::current_exception());
      return;
    }
  }

  // A server ABORT chunk (Part 6 6.7.3) fails ONE request without closing the channel. The decode
  // finalizer recorded {RequestId, Error StatusCode} on the context side-channel (safe because chunks
  // drain one-at-a-time on this same strand); consume it here and fail exactly that pending request.
  // The channel state is deliberately left untouched - the abort aborts the request, not the channel.
  auto& receivedAbort = mContext->receivedAbort;
  if (receivedAbort.has_value())
  {
    auto [abortRequestId, abortStatus] = std::move(receivedAbort.value());
    receivedAbort.reset();

    auto it = mPendingRequests.find(abortRequestId);
    if (it != mPendingRequests.end())
    {
      auto callback = std::move(it->second);
      mPendingRequests.erase(it);

      auto timerIt = mRequestTimers.find(abortRequestId);
      if (timerIt != mRequestTimers.end())
      {
        timerIt->second.cancel();
        mRequestTimers.erase(timerIt);
      }

      std::unique_ptr<ua::ErrorDetail> detail =
        ua::ErrorDetail::build("ServerAbortedRequest",
          "Server aborted the request via an abort message chunk (OPC 10000-6 6.7.3); the secure channel "
          "remains open",
          "client::SecureChannel")
          .context(ua::ContextKeys::requestId, std::to_string(abortRequestId));
      ServiceResponseResult abortResult{abortStatus, std::move(detail)};

      // Always deliver the outcome - the request has been removed from mPendingRequests, so if we did not
      // invoke the callback the caller would hang. Use the logger overload when the deps are still alive.
      if (auto d = mDeps.lock())
      {
        ua::detail::invoke_user_callback(d->logger(), callback, std::move(abortResult));
      }
      else
      {
        ua::detail::invoke_user_callback(callback, std::move(abortResult));
      }
    }
  }

  drain_incoming();
}

void SecureChannelImpl::handle_chunk_decode_failure(std::exception_ptr ex)
{
  auto er = ua::exception_to_status_code(std::move(ex));

  if (auto d = mDeps.lock())
  {
    ua::log_exception(d->logger().with_category("client.secure_channel"),
      ua::LogLevel::Error,
      "client::SecureChannel::drain_incoming",
      er);
  }

  if (mChannelState != ChannelState::Closed)
  {
    // The state is left for handle_channel_error to read (an open channel sends its CloseSecureChannel
    // first); close_transport sets it Closed before anything else can run.
    handle_channel_error(er, er.shared_detail());
  }
  // Decode failure terminates the drain; mIncomingDrainScheduled stays true to inhibit
  // re-entry by an inbound chunk (the channel is closing).
}

void SecureChannelImpl::receive_response_message(uint32_t requestId, std::vector<ua::byte> messageBody)
{
  auto d = mDeps.lock();
  check(d);

  ua::memory_stream_device::ExternalReadOnly streamDevice{messageBody};
  ua::MemoryStream stream{streamDevice};
  auto& factory = d->structure_factory();
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, mContext->encodingLimits};

  auto depth = mContext->encodingLimits.stack_depth();

  ua::ExpandedNodeId typeId;
  decoder.decode(depth, typeId);

  // For standard OPC UA response types (all NS0), the NodeId within the ExpandedNodeId
  // is correct as-is (namespace index 0, no namespace URI translation needed).
  auto message = factory.create_instance(typeId.node_id());
  if (!message)
  {
    // Unknown type - fail any pending request with this requestId.
    auto it = mPendingRequests.find(requestId);
    if (it != mPendingRequests.end())
    {
      auto callback = std::move(it->second);
      mPendingRequests.erase(it);
      std::unique_ptr<ua::ErrorDetail> detail =
        ua::ErrorDetail::build(
          "UnknownResponseType", "Could not create instance for response type", "client::SecureChannel")
          .context(ua::ContextKeys::typeId, ua::to_string(typeId.node_id()))
          .context(ua::ContextKeys::requestId, std::to_string(requestId));
      ua::detail::invoke_user_callback(
        d->logger(), callback, ServiceResponseResult{ua::Status::BadDecodingError, std::move(detail)});
    }
    return;
  }
  decoder.decode(depth, *message);

  d->logger()
    .with_category("client.secure_channel")
    .trace({{"request_id", uint64_t(requestId)}, {"type", std::string{message->type_name()}}},
      "Response received");

  // Check if this is an OPN response.
  if (auto* opnResponse = dynamic_cast<ua::OpenSecureChannelResponse*>(message.get()))
  {
    auto serviceStatus = opnResponse->response_header().service_result();
    auto& token = opnResponse->security_token();

    std::shared_ptr<const ua::ErrorDetail> detail;
    // Part 6 6.7.4: the ServerProtocolVersion of the response shall be the ProtocolVersion of the
    // Acknowledge (always 0: an Acknowledge naming another version was refused), and the receiver
    // closes the channel and reports Bad_ProtocolVersionUnsupported on a mismatch.
    if (serviceStatus.is_good() && opnResponse->server_protocol_version() != 0)
    {
      serviceStatus = ua::Status::BadProtocolVersionUnsupported;
      detail = std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build("ProtocolVersionMismatch",
          "The OpenSecureChannel response names a ServerProtocolVersion other than the Acknowledge's",
          "SecureChannel")
          .context(ua::ContextKeys::actual, std::to_string(opnResponse->server_protocol_version()))
          .context(ua::ContextKeys::expected, "0"));
    }
    else if (serviceStatus.is_bad())
    {
      auto serverDiag = detail::attach_wire_marker(opnResponse->response_header());
      detail = std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build(
        "ServerOPNFault", "Server returned an error in the OpenSecureChannel response", "server")
                                                        .cause(std::move(serverDiag)));
    }

    handle_opn_response_async(requestId,
      serviceStatus,
      token.channel_id(),
      token.token_id(),
      std::chrono::milliseconds{token.revised_lifetime()},
      opnResponse->server_nonce(),
      std::move(detail));
    return;
  }

  // Check for ServiceFault - convert to error Result so callers don't need to handle it.
  // A ServiceFault may also arrive in response to an OPN request that we handled specially.
  if (auto* fault = dynamic_cast<ua::ServiceFault*>(message.get()))
  {
    auto faultStatus = fault->response_header().service_result();
    if (faultStatus.is_good())
    {
      faultStatus = ua::Status::BadUnexpectedError;
    }

    auto it = mPendingRequests.find(requestId);
    if (it != mPendingRequests.end())
    {
      auto callback = std::move(it->second);
      mPendingRequests.erase(it);

      auto timerIt = mRequestTimers.find(requestId);
      if (timerIt != mRequestTimers.end())
      {
        timerIt->second.cancel();
        mRequestTimers.erase(timerIt);
      }

      auto serverDiag = detail::attach_wire_marker(fault->response_header());
      std::unique_ptr<ua::ErrorDetail> detail =
        ua::ErrorDetail::build("ServiceFault", "Server returned a ServiceFault", "server")
          .context(ua::ContextKeys::requestId, std::to_string(requestId))
          .cause(std::move(serverDiag));
      ua::detail::invoke_user_callback(
        d->logger(), callback, ServiceResponseResult{faultStatus, std::move(detail)});
    }
    else
    {
      // ServiceFault not correlated to any pending request - likely a response to an OPN request.
      // Route it as an OPN response error so the channel error is properly reported.
      if (mChannelState == ChannelState::Opening || mChannelState == ChannelState::Renewing)
      {
        auto serverDiag = detail::attach_wire_marker(fault->response_header());
        auto detail = std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build(
          "ServerServiceFault", "Server returned a ServiceFault for the OpenSecureChannel request", "server")
                                                               .cause(std::move(serverDiag)));

        // A ServiceFault carries no security token, so it never opens the channel: an Uncertain fault is
        // refused (Bad_InternalError, its cause the Uncertain code and the server's diagnostics).
        if (!faultStatus.is_bad())
        {
          faultStatus = ua::StatusCode{faultStatus.value(), std::move(detail)};
          faultStatus = ua::client::detail::uncertain_answer_refused(
            faultStatus, "ServiceAnswerUncertain", "client.secure_channel.open_secure_channel");
          detail = faultStatus.shared_detail();
        }
        handle_opn_response_async(
          requestId, faultStatus, 0, 0, std::chrono::milliseconds{0}, {}, std::move(detail));
      }
    }
    return;
  }

  // Regular service response - correlate by requestId.
  auto it = mPendingRequests.find(requestId);
  if (it != mPendingRequests.end())
  {
    auto callback = std::move(it->second);
    mPendingRequests.erase(it);

    auto timerIt = mRequestTimers.find(requestId);
    if (timerIt != mRequestTimers.end())
    {
      timerIt->second.cancel();
      mRequestTimers.erase(timerIt);
    }

    std::shared_ptr<ua::Structure> sharedMsg{message.release()};
    ua::detail::invoke_user_callback(d->logger(), callback, ServiceResponseResult{std::move(sharedMsg)});
  }
}

void SecureChannelImpl::drain_outgoing()
{
  // Test path: no connection means we cannot send wire messages. Silently drop the queue
  // and notify any close-waiter so the close flow proceeds.
  if (!mConnection)
  {
    while (!mOutgoingMessages.empty())
    {
      mOutgoingMessages.pop();
    }
    mOutgoingDrainScheduled = false;
    if (mDrainCompleteCallback)
    {
      auto callback = std::move(mDrainCompleteCallback);
      mDrainCompleteCallback = nullptr;
      callback(ua::VoidResult{});
    }
    return;
  }

  if (mOutgoingMessages.empty())
  {
    mOutgoingDrainScheduled = false;
    if (mCloseSecureChannelPending)
    {
      on_close_secure_channel_encoded();
      return;
    }
    if (mDrainCompleteCallback)
    {
      auto callback = std::move(mDrainCompleteCallback);
      mDrainCompleteCallback = nullptr;
      callback(ua::VoidResult{});
    }
    return;
  }

  auto msg = std::move(mOutgoingMessages.front());
  mOutgoingMessages.pop();

  try
  {
    auto encodeDeps = mDeps.lock();
    auto encodeLogger =
      encodeDeps ? encodeDeps->logger().with_category("client.secure_channel") : ua::Logger{};
    // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
    // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
    if (!mStrand.has_value())
    {
      mStrand.emplace(boost::asio::make_strand(mExecutor));
    }
    mSecurityPolicy->encode_message_async(
      mContext,
      msg.requestId,
      std::move(msg.message),
      [connection = mConnection](ua::ByteString messageChunk)
      {
        const span<const byte> s = messageChunk;
        connection->send_message_chunk(std::vector<byte>{s.begin(), s.end()});
      },
      ua::async::post_borrowing(this,
        *mStrand,
        encodeLogger,
        [](SecureChannelImpl& self, ua::VoidResult result) { self.on_message_encoded(std::move(result)); }));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    on_message_encoded(ua::VoidResult{er, er.shared_detail()});
  }
}

void SecureChannelImpl::on_message_encoded(ua::VoidResult result)
{
  if (result.is_bad())
  {
    auto er = result.status_code();
    if (auto d = mDeps.lock())
    {
      ua::log_exception(d->logger().with_category("client.secure_channel"),
        ua::LogLevel::Error,
        "client::SecureChannel::on_message_encoded",
        er);
    }
    handle_unexpected_exception("client::SecureChannel::on_message_encoded",
      std::make_exception_ptr(ua::UaException{result.status_code().as_status(), result.shared_detail()}));
    mOutgoingDrainScheduled = false;
    return;
  }

  drain_outgoing();
}

// --- Internal state machine methods ---

std::chrono::milliseconds SecureChannelImpl::renewal_delay(std::chrono::milliseconds revisedLifetime)
{
  // CL-SC-007: three quarters of the revised lifetime, never below the floor. A server that revises the
  // lifetime down to a few milliseconds would otherwise have the client renew continuously (a renewal
  // storm the server chose the rate of); at the floor a lifetime below twice the floor still expires
  // before the renewal lands, which the channel reports like any other expiry.
  return std::max(std::chrono::milliseconds{revisedLifetime.count() * 3 / 4}, sMinimumRenewalDelay);
}

void SecureChannelImpl::handle_opn_response_async(uint32_t requestId, ua::StatusCode serviceStatus,
  uint32_t secureChannelId, uint32_t tokenId, std::chrono::milliseconds revisedLifetime,
  ua::ByteString serverNonce, std::shared_ptr<const ua::ErrorDetail> detail)
{
  const bool isRenewing = (mChannelState == ChannelState::Renewing);

  if (mChannelState != ChannelState::Opening && !isRenewing)
  {
    // OPN response in unexpected state - ignore.
    return;
  }

  // CL-SC-008: the response answers the OpenSecureChannel request in flight, or it answers nothing. A
  // response under another id (or a second one for the same request) would otherwise install whatever
  // token it carries.
  if (!mOpnRequestId || requestId != *mOpnRequestId)
  {
    mChannelState = ChannelState::Closed;
    close_transport(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build("OpnResponseRequestIdMismatch",
          "an OpenSecureChannel response arrived under a request id that is not the outstanding "
          "OpenSecureChannel request's",
          "client.secure_channel.opn")
          .context(ua::ContextKeys::requestId, std::to_string(requestId))));
    return;
  }
  mOpnRequestId.reset();

  if (serviceStatus.is_bad())
  {
    mChannelState = ChannelState::Closed;
    auto errorDetail =
      detail ? detail
             : std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build(
                 "ServerOPNFault", "Server returned an error in the OpenSecureChannel response", "server")
                                                        .cause(serviceStatus));
    close_transport(serviceStatus, errorDetail);
    return;
  }

  // CL-SC-009: a Good renewal answers for THIS channel (a fault carries no token, so no id to compare). The
  // server's new token is bound to the channel id it names; a different id would have the client sign and
  // encrypt under a token issued to another channel.
  if (isRenewing && secureChannelId != mContext->secureChannelId)
  {
    mChannelState = ChannelState::Closed;
    close_transport(ua::StatusCode{ua::Status::BadSecureChannelIdInvalid},
      std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build("OpnRenewChannelIdMismatch",
          "the OpenSecureChannel renewal response names a SecureChannelId other than this channel's",
          "client.secure_channel.opn")
          .context(ua::ContextKeys::channelId, std::to_string(secureChannelId))));
    return;
  }

  // Server nonce validation for authenticated channels.
  if (mIsAuthenticated)
  {
    // Part 4 Table 12's 32-byte minimum, except for the one policy whose SecureChannelNonceLength is
    // shorter (Basic128Rsa15, 16), whose own length is its minimum; the exact-length check follows.
    const uint32_t minimumNonceLength = mNonceLength != 0 ? std::min<uint32_t>(32, mNonceLength) : 32;
    if (serverNonce.empty() || serverNonce.size() < minimumNonceLength)
    {
      mChannelState = ChannelState::Closed;
      auto nonceDetail = std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build(
          "ServerNonceInvalid", "Server nonce is shorter than the minimum required length", "server")
          .context(ua::ContextKeys::sizeActual, std::to_string(serverNonce.size()))
          .context(ua::ContextKeys::sizeMin, std::to_string(minimumNonceLength)));
      close_transport(ua::Status::BadNonceInvalid, nonceDetail);
      return;
    }

    if (mNonceLength != 0 && serverNonce.size() != mNonceLength)
    {
      mChannelState = ChannelState::Closed;
      auto nonceDetail = std::shared_ptr<const ua::ErrorDetail>(
        ua::ErrorDetail::build("ServerNonceInvalid",
          "Server nonce length does not match the length expected for the security policy",
          "server")
          .context(ua::ContextKeys::sizeActual, std::to_string(serverNonce.size()))
          .context(ua::ContextKeys::sizeExpected, std::to_string(mNonceLength)));
      close_transport(ua::Status::BadNonceInvalid, nonceDetail);
      return;
    }

    if (isRenewing && serverNonce == mServerNonce)
    {
      mChannelState = ChannelState::Closed;
      auto nonceDetail = std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
        "ServerNonceInvalid", "Server returned the same nonce on renewal (nonce reuse)", "server"));
      close_transport(ua::Status::BadNonceInvalid, nonceDetail);
      return;
    }
  }

  // The opener receives the ServiceResult of the response that opened the channel.
  if (!isRenewing)
  {
    mOpnServiceResult = serviceStatus;
  }

  // Store token state.
  mChannelTokenId = tokenId;
  mRevisedLifetime = revisedLifetime;
  mServerNonce = serverNonce;

  // Create the new SecurityToken (callback-shape). Renewing path does not change
  // secureChannelId; Issue path stores it now so the token-creation code path can rely on
  // mContext->secureChannelId having been set if it ever needs it.
  if (!isRenewing)
  {
    mChannelSecureChannelId = secureChannelId;
    mChannelState = ChannelState::Open;
    if (mOpnTimer)
    {
      mOpnTimer.cancel();
    }
    mContext->secureChannelId = secureChannelId;
    mAtomicChannelId.store(secureChannelId, std::memory_order_release);
  }
  else
  {
    mChannelState = ChannelState::Open;
  }

  auto opnDeps = mDeps.lock();
  auto opnLogger = opnDeps ? opnDeps->logger().with_category("client.secure_channel") : ua::Logger{};
  const ua::SecurityTokenRequestType requestType =
    isRenewing ? ua::SecurityTokenRequestType::Renew : ua::SecurityTokenRequestType::Issue;

  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  ua::SecurityToken::create_async(
    requestType,
    mContext,
    tokenId,
    revisedLifetime,
    mLastClientNonce,
    serverNonce,
    ua::ChannelRole::Client,
    []() {},  // token-timeout callback (no-op on client; renewal driven by mRenewalTimer).
    ua::async::post_borrowing(this,
      *mStrand,
      opnLogger,
      [isRenewing, secureChannelId, tokenId, revisedLifetime](
        SecureChannelImpl& self, ua::SecurityToken::CreateResult tokenResult)
      {
        if (isRenewing)
        {
          self.on_security_token_created_for_renew(std::move(tokenResult), tokenId, revisedLifetime);
        }
        else
        {
          self.on_security_token_created_for_open(
            std::move(tokenResult), secureChannelId, tokenId, revisedLifetime);
        }
      }));
}

void SecureChannelImpl::on_security_token_created_for_open(ua::SecurityToken::CreateResult result,
  uint32_t secureChannelId, uint32_t tokenId, std::chrono::milliseconds revisedLifetime)
{
  // A close released the security state while the keys were derived (release_security_state runs as its own
  // strand turn): the close has answered the open, and there is no context left to open.
  if (!mContext)
  {
    return;
  }
  if (result.is_bad())
  {
    handle_channel_error(result.status_code(),
      ua::make_error_detail("SecurityTokenCreateFailed",
        "Failed to derive symmetric keys for new security token (Issue)",
        "client::SecureChannel",
        result.shared_detail()));
    return;
  }

  mContext->state = ua::SecureChannelContext::State::Open;

  if (auto d = mDeps.lock())
  {
    d->logger()
      .with_category("client.secure_channel")
      .info({{"channel_id", uint64_t(secureChannelId)},
              {"token_id", uint64_t(tokenId)},
              {"revised_lifetime_ms", uint64_t(revisedLifetime.count())}},
        "Secure channel opened");
  }

  finalise_open(tokenId, revisedLifetime, /*isRenewing=*/false);
}

void SecureChannelImpl::on_security_token_created_for_renew(
  ua::SecurityToken::CreateResult result, uint32_t tokenId, std::chrono::milliseconds revisedLifetime)
{
  // As for the open: a close that released the security state first leaves nothing to renew.
  if (!mContext)
  {
    return;
  }
  if (result.is_bad())
  {
    handle_channel_error(result.status_code(),
      ua::make_error_detail("SecurityTokenCreateFailed",
        "Failed to derive symmetric keys for new security token (Renew)",
        "client::SecureChannel",
        result.shared_detail()));
    return;
  }

  // OPC 10000-6 6.7.4 (CL-SC-009 / CL-SC-010): the client secures what it sends with the renewed token from
  // this response on (owner decision BR-11, 2026-10-03; waiting for a message under the new token instead,
  // the server-side rule, would leave both ends on the old token). It "shall continue to accept the old
  // SecurityToken until it expires or it receives a Message from the Server secured with the new
  // SecurityToken" (1.05.06; CL-SC-010, interoperability finding 014): a Server keeps sending under the old
  // token until it receives a message under the new one, so the answer to a request in flight across this
  // renewal arrives under the old token after this response. The old token is kept for receiving only; the
  // decoders drop it.
  mContext->retiredSecurityToken = std::move(mContext->activeSecurityToken);
  mContext->activeSecurityToken = std::move(mContext->pendingSecurityToken);

  if (auto d = mDeps.lock())
  {
    d->logger()
      .with_category("client.secure_channel")
      .info({{"channel_id", uint64_t(mContext->secureChannelId)},
              {"new_token_id", uint64_t(tokenId)},
              {"revised_lifetime_ms", uint64_t(revisedLifetime.count())}},
        "Secure channel renewed");
  }

  finalise_open(tokenId, revisedLifetime, /*isRenewing=*/true);
}

void SecureChannelImpl::finalise_open(
  uint32_t /*tokenId*/, std::chrono::milliseconds revisedLifetime, bool isRenewing)
{
  // Update atomic isOpen.
  const bool isOpen = (mChannelState == ChannelState::Open || mChannelState == ChannelState::Renewing);
  mAtomicIsOpen.store(isOpen, std::memory_order_release);

  // Schedule renewal timer before notifying the opener - observers may check the timer
  // immediately on notification, and this code runs on the strand so there is no data race.
  if (revisedLifetime > std::chrono::milliseconds{0})
  {
    schedule_renewal_timer(renewal_delay(revisedLifetime));
  }

  // Notify opener after all state is finalized (atomic, timer, etc.).
  if (!isRenewing && mOnOpened)
  {
    auto openedLogger = ua::Logger{};
    if (auto d = mDeps.lock())
    {
      openedLogger = d->logger();
    }
    auto callback = std::move(mOnOpened);
    mOnOpened = nullptr;
    // mOnError and mOnOpened are bound to the same one-shot handler in the caller
    // (CoreClientImpl::open_channel_async wires both to OpenChannelFlow::onComplete; first
    // fire wins). Now that the open has resolved, firing mOnError too would redundantly
    // re-enter that handler, so clear it here; post-open errors are reported via
    // mOnChannelError instead.
    mOnError = nullptr;
    // A Good subcode or an Uncertain ServiceResult of the OpenSecureChannel response reaches the opener.
    ua::detail::invoke_user_callback(openedLogger, callback, ua::VoidResult{mOpnServiceResult});
  }
}

void SecureChannelImpl::handle_channel_error(
  ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
{
  auto errorDeps = mDeps.lock();
  auto errorLogger = errorDeps ? errorDeps->logger() : ua::Logger{};

  if (errorDeps)
  {
    auto catLogger = errorLogger.with_category("client.secure_channel");
    auto channelIdStr = fmt::format("{}", uint64_t(mAtomicChannelId.load(std::memory_order_relaxed)));
    if (detail)
    {
      auto detailStr = ua::to_string(*detail);
      catLogger.error({{"channel_id", std::string_view{channelIdStr}},
                        {"status", std::string_view{ua::to_string(status)}},
                        {"error", std::string_view{detailStr}}},
        "Channel error");
    }
    else
    {
      catLogger.error(
        {{"channel_id", std::string_view{channelIdStr}}, {"status", std::string_view{ua::to_string(status)}}},
        "Channel error");
    }
  }

  // Use the detail from the caller if available, otherwise create a generic one.
  auto errorDetail = detail ? detail
                            : std::shared_ptr<const ua::ErrorDetail>(ua::ErrorDetail::build(
                                "ChannelError", "Secure channel error", "client::SecureChannel")
                                                                       .cause(status));

  // Part 6 7.1.5: a client that encounters a fatal error reports it and sends a CloseSecureChannel. That
  // message exists only on an open channel (6.7.2: it carries the SecureChannelId and current TokenId and
  // is signed with the current token's keys, Part 4 5.5.3.1); before the open completes, or once the
  // socket has failed (receive_transport_error sets Closed first), the transport is closed without it.
  if ((mChannelState == ChannelState::Open || mChannelState == ChannelState::Renewing) && mConnection &&
      mContext && mSecurityPolicy)
  {
    close_with_close_secure_channel(status, errorDetail);
    return;
  }

  // Tear everything down through the unified sink.
  close_transport(status, errorDetail);
}

void SecureChannelImpl::close_transport(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail)
{
  report_close(reason, std::move(detail));
  release_transport();
}

void SecureChannelImpl::close_with_close_secure_channel(
  ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail)
{
  report_close(reason, std::move(detail));

  // A callback run by report_close may have released the transport already (a close from inside it).
  if (!mConnection)
  {
    return;
  }

  // The requests report_close failed are not sent; a message already being encoded completes first, so
  // the CloseSecureChannel's sequence number follows it.
  mOutgoingMessages = {};

  auto request = std::make_shared<ua::CloseSecureChannelRequest>();
  if (mConfig.auditEntryIdProvider)
    request->request_header().audit_entry_id() = mConfig.auditEntryIdProvider();
  if (auto d = mDeps.lock())
  {
    d->logger()
      .with_category("client.secure_channel")
      .debug({}, "Sending CloseSecureChannel request after a fatal error");
  }

  // Bound the wait for the encode by the protocol's fallback timer, as for an error the protocol detected
  // (a no-op when the protocol began the close itself). Without it a crypto provider that never answers
  // the sign/encrypt would keep the socket open and reading.
  mConnection->begin_close_after_channel_error();

  // The security context and policy stay until the request is encoded; an encode failure takes the
  // handle_unexpected_exception path, which releases the transport without it.
  mCloseSecureChannelPending = true;
  send_message_internal(mNextRequestId++, std::move(request));
}

void SecureChannelImpl::on_close_secure_channel_encoded()
{
  mCloseSecureChannelPending = false;
  if (mConnection)
  {
    // The protocol closes the transport once the request's chunks are written (bounded by its fallback
    // timer) and keeps itself alive until then, so the reference can be dropped now.
    mConnection->close_after_pending_writes();
    mConnection.reset();
  }
  release_security_state();
}

void SecureChannelImpl::report_close(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail)
{
  auto closeDeps = mDeps.lock();
  auto closeLogger = closeDeps ? closeDeps->logger() : ua::Logger{};

  if (closeDeps)
  {
    auto statusHex = fmt::format("0x{:08x}", reason.as_uint32());
    closeLogger.with_category("client.secure_channel")
      .debug({{"reason", std::string_view{statusHex}}}, "Closing transport");
  }

  // Track whether the channel had been opened successfully - observed via mOnOpened being
  // already cleared. Captured before we touch any callbacks below so the post-open observer
  // (mOnChannelError) can be guarded against firing for handshake failures.
  const bool wasOpenedOk = (mOnOpened == nullptr);

  mChannelState = ChannelState::Closed;
  mAtomicIsOpen.store(false, std::memory_order_release);

  // Cancel all timers - once the transport is closing, no token renewal, OPN handshake,
  // or per-request deadline can still complete. Leaving these scheduled keeps async work
  // outstanding on the executor.
  if (mRenewalTimer)
  {
    mRenewalTimer.cancel();
  }
  if (mOpnTimer)
  {
    mOpnTimer.cancel();
  }
  for (auto& [id, timer] : mRequestTimers)
  {
    timer.cancel();
  }
  mRequestTimers.clear();

  // Resolve any in-flight close-coroutine waiters so the close coroutine can complete
  // its teardown rather than blocking on a wait that can no longer be satisfied.
  if (mDrainCompleteCallback)
  {
    auto callback = std::move(mDrainCompleteCallback);
    mDrainCompleteCallback = nullptr;
    callback(ua::VoidResult{});
  }
  if (mTransportClosedCallback)
  {
    auto callback = std::move(mTransportClosedCallback);
    mTransportClosedCallback = nullptr;
    callback(ua::VoidResult{});
  }

  // Fail any pending service requests with the close reason. Extract the map and reset the
  // member to a fresh empty map in one step (std::exchange) so the member is never read while
  // in a moved-from state.
  if (!mPendingRequests.empty())
  {
    auto pending = std::exchange(mPendingRequests, {});
    auto failStatus = reason.is_good() ? ua::StatusCode{ua::Status::BadSecureChannelClosed} : reason;
    auto failDetail =
      reason.is_good()
        ? std::shared_ptr<const ua::ErrorDetail>(ua::make_error_detail(
            "ChannelClosed", "Pending request cancelled by channel close", "client::SecureChannel"))
        : detail;
    for (auto& [id, callback] : pending)
    {
      ua::detail::invoke_user_callback(closeLogger, callback, ServiceResponseResult{failStatus, failDetail});
    }
  }

  // Notify the OPN-opener if it is still waiting (open did not complete).
  if (mOnOpened)
  {
    auto callback = std::move(mOnOpened);
    mOnOpened = nullptr;
    // mOnError shares the same completion sink; clear it so we don't double-complete.
    mOnError = nullptr;
    auto status = reason.is_good() ? ua::StatusCode{ua::Status::BadSecureChannelClosed} : reason;
    ua::detail::invoke_user_callback(closeLogger, callback, ua::VoidResult{status, detail});
  }

  // Notify the close caller.
  if (mCloseCallback)
  {
    auto callback = std::move(mCloseCallback);
    mCloseCallback = nullptr;
    auto result = reason.is_good() ? ua::VoidResult{} : ua::VoidResult{reason, detail};
    ua::detail::invoke_user_callback(closeLogger, callback, std::move(result));
  }

  // Notify the OPN error sink if it is still set (defensive - should be cleared above when
  // mOnOpened was, but handles paths that bypass open).
  if (mOnError)
  {
    auto callback = std::move(mOnError);
    mOnError = nullptr;
    auto status = reason.is_good() ? ua::StatusCode{ua::Status::BadSecureChannelClosed} : reason;
    ua::detail::invoke_user_callback(closeLogger, callback, ua::VoidResult{status, detail});
  }

  // Persistent post-open observer - fire only on bad reason (not on a clean user-initiated close).
  if (reason.is_bad() && wasOpenedOk && mOnChannelError)
  {
    auto userCb = std::move(mOnChannelError);
    mOnChannelError = nullptr;
    auto errorResult = ua::VoidResult{reason, detail};
    boost::asio::post(mExecutor,
      ua::async::guarded(closeLogger.with_category("client.secure_channel"),
        [userCb = std::move(userCb), errorResult = std::move(errorResult)]() mutable
        { userCb(std::move(errorResult)); }));
  }
}

void SecureChannelImpl::release_transport()
{
  mCloseSecureChannelPending = false;

  // Close and release the transport.
  if (mConnection)
  {
    mConnection->close_async();
    mConnection.reset();
  }

  release_security_state();
}

void SecureChannelImpl::release_security_state()
{
  auto closeDeps = mDeps.lock();
  auto closeLogger = closeDeps ? closeDeps->logger() : ua::Logger{};

  // Defer the release of strand-bound state (security context, security policy) to a posted
  // continuation. close_transport is sometimes invoked from inside the drain pumps (e.g.,
  // drain_incoming -> handle_channel_error -> here); resetting them inline could observe
  // partially-torn-down state in the immediate caller.
  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  ua::async::post_borrowing(this,
    *mStrand,
    closeLogger.with_category("client.secure_channel"),
    [](SecureChannelImpl& self)
    {
      self.mIncomingDrainScheduled = false;
      self.mOutgoingDrainScheduled = false;
      // An operation may still hold the context; the key-agreement secrets go now regardless.
      if (self.mContext)
      {
        self.mContext->release_key_agreement_secrets();
      }
      self.mContext.reset();
      self.mSecurityPolicy.reset();
    })();
}

void SecureChannelImpl::handle_token_renewal_async()
{
  if (mChannelState != ChannelState::Open)
    return;

  if (mIsAuthenticated)
  {
    try
    {
      const uint32_t nonceLen = mNonceLength > 0 ? mNonceLength : 32;
      auto renewDeps = mDeps.lock();
      auto renewLogger =
        renewDeps ? renewDeps->logger().with_category("client.secure_channel") : ua::Logger{};
      // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
      // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
      if (!mStrand.has_value())
      {
        mStrand.emplace(boost::asio::make_strand(mExecutor));
      }
      generate_nonce_async(nonceLen,
        ua::async::post_borrowing(this,
          *mStrand,
          renewLogger,
          [](SecureChannelImpl& self, ua::ByteStringResult nonceResult)
          { self.on_renew_nonce_generated(std::move(nonceResult)); }));
      return;
    }
    catch (...)
    {
      auto er = ua::exception_to_status_code(std::current_exception());
      if (mChannelState != ChannelState::Closed)
      {
        mChannelState = ChannelState::Closed;
        handle_channel_error(er, er.shared_detail());
      }
      return;
    }
  }

  // Unauthenticated: skip nonce; send OPN-Renew inline.
  on_renew_nonce_generated(ua::ByteStringResult{ua::ByteString{}});
}

void SecureChannelImpl::on_renew_nonce_generated(ua::ByteStringResult nonceResult)
{
  if (mChannelState == ChannelState::Closed)
  {
    return;
  }

  if (!nonceResult.is_good())
  {
    // mChannelState != Closed is guaranteed by the early return at the top of this function.
    mChannelState = ChannelState::Closed;
    // A Bad answer closes the channel with its code; an Uncertain one is refused, so the channel error
    // observer learns of the close.
    auto status = ua::security_internal::not_good_answer(
      nonceResult.status_code(), ua::Status::BadInternalError, "client.secure_channel.renew_nonce");
    handle_channel_error(status, status.shared_detail());
    return;
  }

  auto clientNonce = std::move(nonceResult).value();

  mChannelState = ChannelState::Renewing;
  mLastClientNonce = clientNonce;

  auto request = std::make_shared<ua::OpenSecureChannelRequest>();
  request->client_protocol_version() = 0;
  request->request_type() = ua::SecurityTokenRequestType::Renew;
  request->security_mode() = mChannelSecurityMode;
  request->client_nonce() = clientNonce;
  request->requested_lifetime() = mRequestedLifetimeMs;
  if (mConfig.auditEntryIdProvider)
    request->request_header().audit_entry_id() = mConfig.auditEntryIdProvider();

  if (auto d = mDeps.lock())
  {
    d->logger()
      .with_category("client.secure_channel")
      .debug({{"request_type", "Renew"}}, "Sending OpenSecureChannel request");
  }

  auto requestId = mNextRequestId++;
  mOpnRequestId = requestId;
  send_message_internal(requestId, std::move(request));
}

void SecureChannelImpl::start_close()
{
  if (mChannelState == ChannelState::Idle || mChannelState == ChannelState::Closed)
  {
    close_transport(ua::Status::Good, nullptr);
    return;
  }

  if (mChannelState != ChannelState::Open && mChannelState != ChannelState::Renewing)
  {
    // Opening / Closing / other intermediate states - fail the open and tear down.
    close_transport(ua::Status::BadSecureChannelClosed, nullptr);
    return;
  }

  mChannelState = ChannelState::Closing;
  mAtomicIsOpen.store(false, std::memory_order_release);

  // Cancel the OPN deadline timer defensively - should not be active in Open/Renewing,
  // but covers the case where an OPN renewal request was just dispatched.
  if (mOpnTimer)
  {
    mOpnTimer.cancel();
  }

  // Enqueue CLO. drain_outgoing will pick it up and write it to the wire.
  auto request = std::make_shared<ua::CloseSecureChannelRequest>();
  if (mConfig.auditEntryIdProvider)
    request->request_header().audit_entry_id() = mConfig.auditEntryIdProvider();
  auto requestId = mNextRequestId++;
  if (auto d = mDeps.lock())
  {
    d->logger().with_category("client.secure_channel").debug({}, "Sending CloseSecureChannel request");
  }
  send_message_internal(requestId, std::move(request));

  // If the queue is already empty (no in-flight encode), proceed to step B inline.
  const bool drainImmediate = mOutgoingMessages.empty() && !mOutgoingDrainScheduled;
  if (drainImmediate)
  {
    on_outgoing_drained_for_close();
    return;
  }

  // Arm drain-deadline timer; the drain callback fires once drain_outgoing observes
  // an empty queue.
  auto drainTimeout = std::chrono::milliseconds{mServiceTimeoutMs > 0 ? mServiceTimeoutMs : 10000};

  auto me = weak_from_this();
  mCloseDrainTimer = Timer::schedule_after(*mStrand,
    drainTimeout,
    [me, drainTimeout](boost::system::error_code ec)
    {
      if (ec)
        return;
      auto self = me.lock();
      if (!self)
        return;
      if (!self->mDrainCompleteCallback)
        return;
      auto callback = std::move(self->mDrainCompleteCallback);
      self->mDrainCompleteCallback = nullptr;
      callback(ua::VoidResult{ua::Status::BadTimeout,
        ua::ErrorDetail::build("CloseDrainTimeout",
          "Timed out flushing CloseSecureChannel request to the wire",
          "client::SecureChannel")
          .context(ua::ContextKeys::limit, std::to_string(drainTimeout.count()))});
    });

  mDrainCompleteCallback = [me = weak_from_this()](ua::VoidResult result) mutable
  {
    auto self = me.lock();
    if (!self)
      return;
    if (self->mCloseDrainTimer)
      self->mCloseDrainTimer.cancel();
    if (result.is_bad())
    {
      self->close_transport(result.status_code(), result.shared_detail());
      return;
    }
    self->on_outgoing_drained_for_close();
  };
}

void SecureChannelImpl::on_outgoing_drained_for_close()
{
  if (!mConnection)
  {
    close_transport(ua::Status::Good, nullptr);
    return;
  }

  // Wait for the server to close the transport (signalled via receive_transport_error),
  // bounded by mCloseTransportTimeoutMs. Timeout is non-fatal - proceed to teardown.

  auto me = weak_from_this();
  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  mCloseTransportWaitTimer = Timer::schedule_after(*mStrand,
    mCloseTransportTimeoutMs,
    [me](boost::system::error_code ec)
    {
      if (ec)
        return;
      auto self = me.lock();
      if (!self)
        return;
      if (!self->mTransportClosedCallback)
        return;
      // Timeout - fire the slot with Good (timeout is non-fatal, matches pre-flip behaviour).
      auto callback = std::move(self->mTransportClosedCallback);
      self->mTransportClosedCallback = nullptr;
      callback(ua::VoidResult{});
    });

  mTransportClosedCallback = [me = weak_from_this()](ua::VoidResult /*result*/) mutable
  {
    auto self = me.lock();
    if (!self)
      return;
    if (self->mCloseTransportWaitTimer)
      self->mCloseTransportWaitTimer.cancel();
    self->on_transport_closed_for_close();
  };
}

void SecureChannelImpl::on_transport_closed_for_close()
{
  close_transport(ua::Status::Good, nullptr);
}

void SecureChannelImpl::schedule_renewal_timer(std::chrono::milliseconds delay)
{
  if (mRenewalTimer)
  {
    mRenewalTimer.cancel();
  }

  auto me = weak_from_this();
  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  mRenewalTimer = Timer::schedule_after(*mStrand,
    delay,
    [me](boost::system::error_code ec)
    {
      if (ec)
        return;
      auto self = me.lock();
      if (!self)
        return;
      try
      {
        self->handle_token_renewal_async();
      }
      catch (...)
      {
        self->handle_unexpected_exception("client::SecureChannel::renewal_timer", std::current_exception());
      }
    });
}

void SecureChannelImpl::generate_nonce_async(uint32_t bytes, NonceCallback callback)
{
  auto deps = mDeps.lock();
  check(deps);

  auto crypto = deps->crypto();

  if (const auto ephemeralKeyAlgorithm = mSecurityPolicy->ephemeral_key_algorithm();
      ephemeralKeyAlgorithm != ua::EphemeralKeyAlgorithm::Invalid)
  {
    // Key agreement: the nonce is an ephemeral public key; store the private key for the shared secret.

    auto eccLogger = deps->logger().with_category("client.secure_channel");
    // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
    // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
    if (!mStrand.has_value())
    {
      mStrand.emplace(boost::asio::make_strand(mExecutor));
    }
    crypto->create_ephemeral_keys_async(ephemeralKeyAlgorithm,
      ua::async::post_borrowing(this,
        *mStrand,
        eccLogger,
        [callback = std::move(callback)](
          SecureChannelImpl& self, ua::Crypto::EphemeralKeyPairResult result) mutable
        {
          if (result.is_bad())
          {
            callback(ua::ByteStringResult{result.status_code(),
              ua::make_error_detail("EphemeralKeyGenerationFailed",
                "Failed to generate the ephemeral key pair for the nonce",
                "client::SecureChannel",
                result.shared_detail())});
            return;
          }
          if (result.is_uncertain())
          {
            // The nonce's consumer refuses an Uncertain answer; its code and detail are passed on as they
            // are.
            callback(ua::ByteStringResult{result.status_code()});
            return;
          }
          // A close released the security state while the key pair was generated: there is no channel to
          // send the nonce on, and the private key goes with the result.
          if (!self.mContext)
          {
            callback(ua::ByteStringResult{StatusCode{Status::BadSecureChannelClosed},
              ua::make_error_detail("SecurityStateReleased",
                "The channel released its security state while the ephemeral key pair was generated",
                "client::SecureChannel")});
            return;
          }
          try
          {
            auto ephemeral = std::move(result).value();
            // A key an earlier exchange left behind (it never reached a derivation) is scrubbed, not just
            // freed.
            ua::security::secure_clear(self.mContext->localEphemeralPrivateKey);
            self.mContext->localEphemeralPrivateKey = std::move(ephemeral.privateKey);
            callback(ua::ByteStringResult{std::move(ephemeral.publicKey)});
          }
          catch (...)
          {
            auto er = ua::exception_to_status_code(std::current_exception());
            callback(ua::ByteStringResult{er, er.shared_detail()});
          }
        }));
    return;
  }

  // RSA: nonce is random entropy.
  crypto->get_entropy_async(bytes,
    [bytes, callback = std::move(callback)](ua::ByteStringResult result) mutable
    {
      if (result.is_bad())
      {
        callback(ua::ByteStringResult{result.status_code(),
          ua::ErrorDetail::build(
            "EntropyGenerationFailed", "Failed to generate entropy for nonce", "client::SecureChannel")
            .context(ua::ContextKeys::sizeExpected, std::to_string(bytes))
            .cause(result.shared_detail())});
        return;
      }
      callback(std::move(result));
    });
}

// --- Public API implementations ---

void SecureChannelImpl::send_request(std::shared_ptr<ua::Structure> request,
  ServiceResponseCallback completionHandler, uint32_t timeoutMs) noexcept
{
  auto dispatchDeps = mDeps.lock();
  auto dispatchLogger =
    dispatchDeps ? dispatchDeps->logger().with_category("client.secure_channel") : ua::Logger{};

  // Completion-owning post: the channel owns `callback` and must fire it exactly once. post_borrowing
  // delivers the goneResult below when the channel is gone OR the post itself cannot be queued (e.g.
  // bad_alloc), so the error is never silently dropped (never discard at a boundary).
  auto goneDetail = std::shared_ptr<const ua::ErrorDetail>(
    ua::make_error_detail("ChannelDestroyed", "SecureChannel no longer exists", "client::SecureChannel"));

  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  ua::async::post_borrowing(this,
    *mStrand,
    dispatchLogger,
    std::move(completionHandler),
    ServiceResponseResult{ua::Status::BadSecureChannelClosed, goneDetail},
    [request = std::move(request), timeoutMs](
      SecureChannelImpl& self, ServiceResponseCallback callback) mutable
    {
      try
      {
        auto reqDeps = self.mDeps.lock();
        auto reqLogger = reqDeps ? reqDeps->logger() : ua::Logger{};

        if (self.mChannelState != ChannelState::Open && self.mChannelState != ChannelState::Renewing)
        {
          auto detail = std::shared_ptr<const ua::ErrorDetail>(
            ua::ErrorDetail::build(
              "ChannelNotOpen", "Channel is not in Open state for service request", "client::SecureChannel")
              .context(ua::ContextKeys::stateChannel, std::to_string(static_cast<int>(self.mChannelState))));
          ua::detail::invoke_user_callback(
            reqLogger, callback, ServiceResponseResult{ua::Status::BadSecureChannelClosed, detail});
          return;
        }

        auto requestId = self.mNextRequestId++;
        self.mPendingRequests.emplace(requestId, std::move(callback));
        // Test-only capture interface (null in production): surface the decoded outgoing request before
        // framing.
        if (self.mOutgoingRequestObserver && request)
        {
          self.mOutgoingRequestObserver(*request);
        }
        self.send_message_internal(requestId, std::move(request));

        // Schedule per-request deadline timer, past the hint the Server was sent so that an answer it
        // sends at the hint is still received.
        auto effectiveTimeout = response_wait_for(timeoutMs > 0 ? timeoutMs : self.mServiceTimeoutMs);
        if (effectiveTimeout > 0)
        {
          self.mRequestTimers[requestId] = Timer::schedule_after(*self.mStrand,
            std::chrono::milliseconds{effectiveTimeout},
            [me = self.weak_from_this(), requestId, effectiveTimeout](boost::system::error_code ec)
            {
              if (ec)
              {
                return;
              }
              auto s = me.lock();
              if (!s)
              {
                return;
              }
              auto timerDeps = s->mDeps.lock();
              auto timerLogger = timerDeps ? timerDeps->logger() : ua::Logger{};
              auto it = s->mPendingRequests.find(requestId);
              if (it != s->mPendingRequests.end())
              {
                auto cb = std::move(it->second);
                s->mPendingRequests.erase(it);
                s->mRequestTimers.erase(requestId);
                auto detail = std::shared_ptr<const ua::ErrorDetail>(
                  ua::ErrorDetail::build(
                    "RequestTimeout", "Service request timed out", "client::SecureChannel")
                    .context(ua::ContextKeys::limit, std::to_string(effectiveTimeout))
                    .context(ua::ContextKeys::requestId, std::to_string(requestId)));
                ua::detail::invoke_user_callback(
                  timerLogger, cb, ServiceResponseResult{ua::Status::BadTimeout, detail});
              }
            });
        }
      }
      catch (...)
      {
        self.handle_unexpected_exception("client::SecureChannel::send_request", std::current_exception());
      }
    })();
}

namespace
{

/// Adapter: derives SessionDependencies from SecureChannelDependencies.
class ChannelSessionDeps : public SessionDependencies
{
public:
  explicit ChannelSessionDeps(std::shared_ptr<SecureChannelDependencies> channelDeps)
    : mChannelDeps(std::move(channelDeps))
  {}

  boost::asio::any_io_executor executor() override
  {
    return mChannelDeps->executor();
  }

  std::shared_ptr<const ua::Crypto> crypto() override
  {
    return mChannelDeps->crypto();
  }

  std::shared_ptr<ua::CertificateStore> certificate_store() override
  {
    return mChannelDeps->certificate_store();
  }

  const ua::ApplicationConfig& configuration() override
  {
    return mChannelDeps->configuration();
  }

  ua::StructureFactory& structure_factory() override
  {
    return mChannelDeps->structure_factory();
  }

  ua::Logger logger() override
  {
    return mChannelDeps->logger();
  }

  uint32_t service_timeout_ms() override
  {
    return mChannelDeps->service_timeout_ms();
  }

  uint32_t default_return_diagnostics() override
  {
    return mChannelDeps->default_return_diagnostics();
  }

  bool wrap_tier0() override
  {
    return mChannelDeps->wrap_tier0();
  }

  // Forward session registration to the underlying SecureChannelDependencies
  // (which is implemented by ClientDependencies and routes to CoreClientImpl).
  void register_session(std::weak_ptr<SessionImpl> session) override
  {
    mChannelDeps->register_session(std::move(session));
  }

  void unregister_session(SessionImpl* session) override
  {
    mChannelDeps->unregister_session(session);
  }

private:
  std::shared_ptr<SecureChannelDependencies> mChannelDeps;
};

}  // namespace

SessionSecurityInfo SecureChannelImpl::session_security_info() const
{
  return SessionSecurityInfo{.clientCertificate = mContext->localCertificate,
    .clientKeyPair = mContext->localKeyPair,
    .securityPolicy = mSecurityPolicy,
    .messageSecurityMode = mContext->messageSecurityMode,
    // CL-SC-012: hand the session the OPN-time server certificate so it can enforce that the
    // CreateSessionResponse certificate is the same one the channel was opened against (P4-0004).
    .serverCertificate = mContext->remoteCertificate,
    .clientIssuerCertificates = mContext->localIssuerCertificates,
    .channelThumbprint = mContext->channelThumbprint};
}

void SecureChannelImpl::session_security_info_async(
  std::function<void(SessionSecurityInfoResult)> callback) noexcept
{
  try
  {
    auto dispatchDeps = mDeps.lock();
    auto dispatchLogger =
      dispatchDeps ? dispatchDeps->logger().with_category("client.secure_channel") : ua::Logger{};
    // mStrand is engaged in the constructor and never reset; the emplace keeps the reference provably
    // engaged.
    if (!mStrand.has_value())
    {
      mStrand.emplace(boost::asio::make_strand(mExecutor));
    }
    ua::async::post_borrowing(this,
      *mStrand,
      dispatchLogger,
      std::move(callback),
      SessionSecurityInfoResult{ua::StatusCode{ua::Status::BadSecureChannelClosed},
        ua::make_error_detail("SecureChannelDestroyed",
          "The channel was destroyed before the Session read its security state",
          "client::SecureChannel")},
      [](SecureChannelImpl& self, std::function<void(SessionSecurityInfoResult)> completion)
      {
        if (!self.mContext)
        {
          completion(SessionSecurityInfoResult{ua::StatusCode{ua::Status::BadSecureChannelClosed},
            ua::make_error_detail("SecurityStateReleased",
              "The channel released its security state before the Session read it",
              "client::SecureChannel")});
          return;
        }
        // Built before the completion runs, so a throw from the completion is not answered twice.
        auto info = [&self]
        {
          try
          {
            return SessionSecurityInfoResult{self.session_security_info()};
          }
          catch (...)
          {
            auto er = ua::exception_to_status_code(std::current_exception());
            return SessionSecurityInfoResult{er, er.shared_detail()};
          }
        }();
        completion(std::move(info));
      })();
  }
  catch (...)
  {
    // Only a throw before post_borrowing took the callback leaves it here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (callback)
    {
      callback(SessionSecurityInfoResult{er, er.shared_detail()});
    }
  }
}

void SecureChannelImpl::create_session(
  SecureChannel::CreateSessionConfig config, CreateSessionImplCallback completionHandler) noexcept
{
  auto dispatchDeps = mDeps.lock();
  auto dispatchLogger =
    dispatchDeps ? dispatchDeps->logger().with_category("client.secure_channel") : ua::Logger{};

  // Completion-owning post: the channel owns `callback` and must fire it exactly once. post_borrowing
  // delivers the goneResult below when the channel is gone OR the post itself cannot be queued (e.g.
  // bad_alloc), so the error is never silently dropped (never discard at a boundary).
  // Posting to the strand: mContext members (localCertificate, localKeyPair) are strand-owned mutable
  // state set during setup_and_open(); reading them requires strand serialization.
  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  ua::async::post_borrowing(this,
    *mStrand,
    dispatchLogger,
    std::move(completionHandler),
    CreateSessionImplResult{ua::Status::BadSecureChannelClosed},
    [config = std::move(config)](SecureChannelImpl& self, CreateSessionImplCallback callback) mutable
    {
      try
      {
        auto channelDeps = self.mDeps.lock();
        if (!channelDeps)
        {
          ua::detail::invoke_user_callback(
            ua::Logger{}, callback, CreateSessionImplResult{ua::Status::BadInternalError});
          return;
        }

        // Guard against a closed / torn-down channel. The close-drain resets mContext and mSecurityPolicy to
        // null (see close_channel_async), but a create_session can still be posted onto the strand AFTER that
        // drain ran - the disconnect-then-create-session ordering the reconnect / session machinery can hit
        // (e.g. a renewal-validation failure disconnects the channel, then a queued create-session fires).
        // Reading mSecurityPolicy / mContext below would then dereference null (a crash). Fast-fail with a
        // source-tagged Bad_SecureChannelClosed instead - the ErrorDetail is carried in the Result so the
        // caller learns WHY (priority #1), and the channel is left untouched.
        if (!self.mSecurityPolicy || !self.mContext)
        {
          ua::detail::invoke_user_callback(ua::Logger{},
            callback,
            CreateSessionImplResult{ua::StatusCode{ua::Status::BadSecureChannelClosed},
              ua::make_error_detail("SecureChannelClosed",
                "cannot create a session on a closed secure channel (it was torn down before the "
                "create-session request reached its strand)",
                "client.tier0.secure_channel.create_session.channel_closed")});
          return;
        }

        // A Session carries user identity and authorization, so it is refused on an unsecured channel
        // unless the application opted in - the same `allowInsecureEndpoints` gate the Server applies
        // when exposing a None endpoint. Enforced at CreateSession, not at channel open, so session-less
        // discovery (GetEndpoints / FindServers, which the SDK itself performs over a None channel)
        // remains available.
        if ((self.mConfig.securityPolicyId == ua::SecurityPolicyId::None ||
              self.mContext->messageSecurityMode == ua::MessageSecurityMode::None) &&
            !channelDeps->configuration().allowInsecureEndpoints)
        {
          ua::detail::invoke_user_callback(ua::Logger{},
            callback,
            CreateSessionImplResult{ua::StatusCode{ua::Status::BadSecurityModeRejected},
              ua::make_error_detail("InsecureSessionRejected",
                "cannot create a Session on a channel with SecurityPolicy None or MessageSecurityMode None: "
                "set ApplicationConfig::allowInsecureEndpoints to permit it",
                "client.tier0.secure_channel.create_session.insecure_channel")});
          return;
        }

        auto sessionDeps = std::make_shared<ChannelSessionDeps>(channelDeps);

        // The per-call override wins; otherwise the client-wide default from ClientConfig.
        // This was a hard-coded 1200000.0 - numerically identical to that field's own 20-minute
        // default, so the field appeared to work right up until somebody changed it.
        auto resolvedSessionTimeoutMs = config.requestedSessionTimeout.has_value()
                                          ? static_cast<double>(config.requestedSessionTimeout->count())
                                          : static_cast<double>(self.mConfig.defaultSessionTimeout.count());

        const SessionImpl::Config logicConfig{.requestedSessionTimeoutMs = resolvedSessionTimeoutMs,
          .endpointUrl = self.mConfig.endpointUrl,
          .sessionName = std::move(config.sessionName),
          .isAuthenticated = self.mSecurityPolicy->is_authenticated(),
          .discoveryEndpoints = std::move(config.discoveryEndpoints),
          .ecdhPolicyUri = std::move(config.ecdhPolicyUri),
          .requestEphemeralKey = config.requestEphemeralKey,
          .relaxHostNameCheck = config.relaxHostNameCheck,
          .auditEntryIdProvider = std::move(config.auditEntryIdProvider),
          .returnDiagnosticsOverride = config.returnDiagnosticsOverride,
          .onSessionError = std::move(config.onSessionError)};

        // Safe to read mContext members here - we are on the strand.
        SessionImpl::SecurityInfo securityInfo = self.session_security_info();

        auto slot = std::make_shared<std::shared_ptr<SessionImpl>>();

        *slot = SessionImpl::create(
          sessionDeps,
          self.shared_from_this(),
          logicConfig,
          std::move(securityInfo),
          [slot, callback = std::move(callback)](ua::VoidResult result) mutable
          {
            if (result.is_bad())
            {
              callback(CreateSessionImplResult{result.status_code(), result.shared_detail()});
              return;
            }
            // The Session exists: a Good subcode or an Uncertain CreateSession ServiceResult stays with it.
            callback(ua::detail::held(*slot, result.status_code()));
          },
          [](ua::VoidResult) {});

        // Transfer test observer to new session (one-shot).
        if (self.mNextCreateSessionResponseObserver)
        {
          (*slot)->mCreateSessionResponseObserver = std::move(self.mNextCreateSessionResponseObserver);
          self.mNextCreateSessionResponseObserver = nullptr;
        }
      }
      catch (...)
      {
        self.handle_unexpected_exception("client::SecureChannel::create_session", std::current_exception());
      }
    })();
}

void SecureChannelImpl::close(CloseCallback completionHandler) noexcept
{
  auto dispatchDeps = mDeps.lock();
  auto dispatchLogger =
    dispatchDeps ? dispatchDeps->logger().with_category("client.secure_channel") : ua::Logger{};

  // Completion-owning post: the channel owns `callback` and must fire it exactly once. A gone channel
  // is treated as already-closed, so the goneResult is Good (matches the dead-self path's behaviour);
  // post_borrowing also delivers it if the post itself cannot be queued.
  // mStrand is engaged in the constructor and never reset; the emplace re-establishes it in the
  // (unreachable) empty case so the strand reference below is provably engaged for static analysis.
  if (!mStrand.has_value())
  {
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }
  ua::async::post_borrowing(this,
    *mStrand,
    dispatchLogger,
    std::move(completionHandler),
    ua::VoidResult{},
    [](SecureChannelImpl& self, CloseCallback callback)
    {
      try
      {
        self.mCloseCallback = std::move(callback);
        self.start_close();
      }
      catch (...)
      {
        self.handle_unexpected_exception("client::SecureChannel::close", std::current_exception());
      }
    })();
}

uint32_t SecureChannelImpl::secure_channel_id() const
{
  return mAtomicChannelId.load(std::memory_order_acquire);
}

bool SecureChannelImpl::is_open() const
{
  return mAtomicIsOpen.load(std::memory_order_acquire);
}

// --- Helpers ---

void SecureChannelImpl::send_message_internal(uint32_t requestId, std::shared_ptr<ua::Structure> message)
{
  mOutgoingMessages.push(OutgoingMessage{requestId, std::move(message)});

  if (!mOutgoingDrainScheduled)
  {
    mOutgoingDrainScheduled = true;
    drain_outgoing();
  }
}

void SecureChannelImpl::handle_unexpected_exception(const char* site, std::exception_ptr ex)
{
  auto er = ua::exception_to_status_code(std::move(ex));

  if (auto exDeps = mDeps.lock())
  {
    auto catLogger = exDeps->logger().with_category("client.secure_channel");
    ua::log_exception(catLogger, ua::LogLevel::Error, site, er);
  }

  // Tear everything down through the unified sink.
  close_transport(er, er.shared_detail());
}

}  // namespace ua::client
