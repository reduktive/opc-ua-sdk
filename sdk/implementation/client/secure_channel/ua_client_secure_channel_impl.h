// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SECURE_CHANNEL_IMPL_H
#define UA_CLIENT_SECURE_CHANNEL_IMPL_H

#include "ua_client_secure_channel.h"
#include "ua_client_session_security_info.h"
#include "ua_instance_tracker.h"

#include "ua_byte_string.h"
#include "ua_connection_protocol_limits.h"
#include "ua_encoding_limits.h"
#include "ua_message_security_mode.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"
#include "ua_timer.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <functional>
#include <optional>
#include <queue>
#include <unordered_map>
#include <utility>

namespace ua
{
class ConnectionProtocol;
class CreateSessionResponse;
enum class FatalCloseDisposition;
}  // namespace ua

namespace ua::client::detail
{
class ValidatedServerRequest;
}  // namespace ua::client::detail

namespace ua::client
{

class SessionImpl;
class SecureChannelTestAccess;

class SecureChannelImpl;
class SessionImpl;

/// Internal dependencies interface for client SecureChannel.
/// Lives in the implementation layer - not part of the public API.
class SecureChannelDependencies
{
public:
  SecureChannelDependencies() = default;
  virtual ~SecureChannelDependencies() = default;

  // Polymorphic interface - held only by shared_ptr/weak_ptr, never value-copied.
  // Delete copy/move to prevent slicing (C.67) and complete the Rule of 5.
  SecureChannelDependencies(const SecureChannelDependencies&) = delete;
  SecureChannelDependencies& operator=(const SecureChannelDependencies&) = delete;
  SecureChannelDependencies(SecureChannelDependencies&&) = delete;
  SecureChannelDependencies& operator=(SecureChannelDependencies&&) = delete;

  virtual boost::asio::any_io_executor executor() = 0;
  virtual std::shared_ptr<const ua::Crypto> crypto() = 0;
  virtual std::shared_ptr<ua::CertificateStore> certificate_store() = 0;
  virtual const ua::ApplicationConfig& configuration() = 0;
  virtual ua::StructureFactory& structure_factory() = 0;
  virtual ua::Logger logger() = 0;
  virtual uint32_t service_timeout_ms() = 0;
  virtual uint32_t default_return_diagnostics() = 0;

  virtual bool wrap_tier0()
  {
    return false;
  }

  // Cascading-shutdown registry. Channels and sessions register themselves
  // here on construction (RAII) and unregister in their destructors. Default
  // no-op so unit tests using simplified deps don't have to care.
  virtual void register_channel(std::weak_ptr<SecureChannelImpl>)
  {}

  virtual void unregister_channel(SecureChannelImpl*)
  {}

  virtual void register_session(std::weak_ptr<SessionImpl>)
  {}

  virtual void unregister_session(SessionImpl*)
  {}
};

/// Client-side OPC UA Secure Channel - strand-serialized component.
///
/// Runs on a boost::asio::strand<boost::asio::any_io_executor>; manages OPN request/response encoding,
/// service request correlation, token renewal, and channel lifecycle directly (no separate logic/shell
/// split).
class SecureChannelImpl : public std::enable_shared_from_this<SecureChannelImpl>
{
public:
  /// The executor this component's operations complete on; a blocking wrapper must not wait on it from
  /// one of its threads.
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept
  {
    return mExecutor;
  }

  // Channel state machine (public for test access).
  enum class ChannelState
  {
    Idle,
    Closed,
    Opening,
    Open,
    Renewing,
    Closing
  };
  SecureChannelImpl() = delete;
  SecureChannelImpl(const SecureChannelImpl&) = delete;
  SecureChannelImpl(SecureChannelImpl&&) noexcept = delete;
  SecureChannelImpl& operator=(const SecureChannelImpl&) = delete;
  SecureChannelImpl& operator=(SecureChannelImpl&&) noexcept = delete;
  ~SecureChannelImpl();

  struct Config
  {
    ua::MessageSecurityMode securityMode{ua::MessageSecurityMode::None};
    ua::SecurityPolicyId securityPolicyId{ua::SecurityPolicyId::None};
    uint32_t requestedLifetimeMs{3600000};
    std::string endpointUrl;
    std::function<ua::String()> auditEntryIdProvider;

    /// Server certificate (from a prior GetEndpoints call). Required for authenticated policies.
    std::shared_ptr<const ua::X509Certificate> serverCertificate;

    /// Optional per-open trust-store override - when set, the OPN server-certificate validation uses
    /// THIS store instead of the deps runtime store (bootstrap-trust for a GDS Pull connection,
    /// CL-PULLCRT-001). `nullptr` (the default) falls back to the deps runtime store. Held here (a
    /// Config member) so it stays alive for the channel's whole life, because context.mCertStore is a
    /// weak_ptr (ua_secure_channel_context.h) and would not otherwise keep the override store alive.
    /// PER-OPEN: does NOT survive a full reconnect (a fresh SecureChannelImpl is built)  -  the reconnect
    /// wiring must re-thread it (deferred W6b-2); a no-op under SecurityPolicy None.
    std::shared_ptr<ua::CertificateStore> trustStoreOverride;

    /// Optional SecurityPolicy factory override (set via CoreClientTestAccess, not public API).
    using SecurityPolicyFactory = std::function<std::shared_ptr<ua::SecurityPolicy>(ua::SecurityPolicyId)>;
    SecurityPolicyFactory securityPolicyFactory;

    /// Persistent user-facing error observer. Fires post-open when the channel dies unexpectedly.
    std::function<void(ua::VoidResult)> onChannelError;

    /// Receives the exact request the server certificate was validated with (connection revalidation).
    std::shared_ptr<detail::ValidatedServerRequest> validatedServerRequest;

    /// How long close() will wait for the server to close the transport after the CLO request
    /// is sent on the wire. On timeout, the client tears down the transport unilaterally.
    std::chrono::milliseconds closeTransportTimeout{1000};

    /// Client-wide default requested session timeout, used by `create_session_*` when
    /// `CreateSessionConfig::requestedSessionTimeout` is not set. Sourced from
    /// `ClientConfig::defaultSessionTimeout`; the default mirrors that field.
    std::chrono::milliseconds defaultSessionTimeout{std::chrono::minutes{20}};

    /// Incoming-chunk queue depth before the transport read-pauses (inbound backpressure). Sourced from
    /// `ClientConfig::incomingChunkQueueDepth`; the default mirrors that field. Treated as >= 1.
    uint32_t incomingChunkQueueDepth{64};

    /// Inbound (server-response) decode size-cap overrides. `nullopt` keeps the bounded floor. Sourced
    /// from `ClientConfig::mMaxInbound{String,ByteString,Array}Length`; applied via
    /// `make_client_encoding_limits`.
    ua::optional<uint32_t> maxInboundStringLength;
    ua::optional<uint32_t> maxInboundByteStringLength;
    ua::optional<uint32_t> maxInboundArrayLength;

    /// The HostName binding is left to CreateSession (ConnectionConfig::relaxHostNameCheck).
    bool relaxHostNameCheck = false;
  };

  using ServiceResponseResult = ua::Result<std::shared_ptr<ua::Structure>>;
  using ServiceResponseCallback = std::function<void(ServiceResponseResult)>;
  using CloseCallback = std::function<void(ua::VoidResult)>;

  using OpenedCallback = std::function<void(ua::VoidResult)>;
  using ErrorCallback = std::function<void(ua::VoidResult)>;

  /// Factory: creates the impl, begins OPN handshake.
  /// @param onOpened  Called (on strand) when channel is open and ready.
  /// @param onError   Called (on strand) on fatal channel error.
  static std::shared_ptr<SecureChannelImpl> create(std::weak_ptr<SecureChannelDependencies> deps,
    std::shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits, Config config, OpenedCallback onOpened,
    ErrorCallback onError);

  /// As create(), but the OPN handshake begins only when start() is called, so the caller can store the
  /// returned pointer where @p onOpened and @p onError read it before either can fire.
  static std::shared_ptr<SecureChannelImpl> create_unstarted(std::weak_ptr<SecureChannelDependencies> deps,
    std::shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits, Config config, OpenedCallback onOpened,
    ErrorCallback onError);

  /// Begins the OPN handshake of a channel made by create_unstarted(). Called once.
  void start();

  // --- Public API (called from SecureChannel forwarding methods) ---

  /// Send a service request through the channel.
  /// @param timeoutMs  Per-request timeout override (0 = use default from config).
  void send_request(std::shared_ptr<ua::Structure> request, ServiceResponseCallback callback,
    uint32_t timeoutMs = 0) noexcept;

  /// Resolves the RequestHeader timeoutHint to send, defaulting an unset (`0`) hint to the client's
  /// configured service timeout. Channel-level services (discovery, registration) and the session
  /// lifecycle requests carry no Session to resolve it for them.
  uint32_t timeout_hint_for(uint32_t requestValue) const noexcept
  {
    return requestValue != 0 ? requestValue : mServiceTimeoutMs;
  }

  /// How long the Client waits for the response to a request carrying @p timeoutHintMs before failing it
  /// locally with Bad_Timeout: the hint plus a tenth of it, and at least 500 ms more. A Server may answer at
  /// the hint itself - OPC 10000-4 section 7.33 lets it cancel a long-running operation there, and this
  /// SDK's Server answers unfinished Read, Write and Call operations Bad_Timeout at the hint - and that
  /// answer needs time to arrive; a local deadline equal to the hint would discard it. 0 stays 0.
  static uint32_t response_wait_for(uint32_t timeoutHintMs) noexcept
  {
    if (timeoutHintMs == 0)
    {
      return 0;
    }
    const uint64_t margin = std::max<uint64_t>(timeoutHintMs / 10, 500);
    return static_cast<uint32_t>(
      std::min<uint64_t>(uint64_t{timeoutHintMs} + margin, std::numeric_limits<uint32_t>::max()));
  }

  using CreateSessionImplResult = ua::Result<std::shared_ptr<SessionImpl>>;
  using CreateSessionImplCallback = std::function<void(CreateSessionImplResult)>;

  void create_session(SecureChannel::CreateSessionConfig config, CreateSessionImplCallback callback) noexcept;

  using SessionSecurityInfoResult = ua::Result<SessionSecurityInfo>;

  /// The security state a Session signs with on this channel: the certificates, key pair, policy and mode,
  /// and the ChannelThumbprint that binds the session signatures to this channel (OPC 10000-4 section 6.1.8).
  /// A Session re-activated over this channel reads it here, since its own copy belongs to the channel it
  /// came from. Read on the channel strand; @p callback runs there, with Bad_SecureChannelClosed once a close
  /// has released the security state.
  void session_security_info_async(std::function<void(SessionSecurityInfoResult)> callback) noexcept;

  void close(CloseCallback callback) noexcept;

  uint32_t secure_channel_id() const;

  bool is_open() const;

private:
  friend class SecureChannelTestAccess;

  SecureChannelImpl(std::weak_ptr<SecureChannelDependencies> deps,
    std::shared_ptr<ua::ConnectionProtocol> connection,
    const ua::connection_protocol::NegotiatedLimits& negotiatedLimits, Config config, OpenedCallback onOpened,
    ErrorCallback onError);

  void initialise();

  /// Kick off OPN handshake: cert load (if authenticated) -> nonce generation -> OPN-Issue send.
  void start_open();
  void on_application_certificate_loaded(ua::CertificateStore::ApplicationCertificateResult result);
  void start_nonce_generation_for_open();
  void on_open_nonce_generated(ua::ByteStringResult nonce);
  void send_opn_request_and_arm_deadline(ua::ByteString clientNonce);

  // --- Wire callbacks ---

  void receive_message_chunk(ua::StatusCode status, std::vector<ua::byte>&& messageChunk);

  void receive_transport_error(ua::StatusCode status, ua::string_view errorDescription);

  /// The ConnectionProtocol's fatal-error report. AwaitingClose leaves the transport writable for the
  /// CloseSecureChannel request an open channel owes (Part 6 7.1.5); TransportClosed is a dead socket.
  void receive_connection_error(ua::StatusCode status, ua::FatalCloseDisposition disposition);

  // --- Drain pumps (replace process_incoming_message_chunks / process_outgoing_messages). ---

  void drain_incoming();
  void on_chunk_decoded(ua::DecodedMessageChunkResult result);
  void receive_response_message(uint32_t requestId, std::vector<ua::byte> messageBody);
  void handle_chunk_decode_failure(std::exception_ptr ex);

  void drain_outgoing();
  void on_message_encoded(ua::VoidResult result);

  // --- Internal state machine methods ---

  void handle_channel_error(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail);
  /// Report the close (report_close) and release the transport and the security state (release_transport).
  void close_transport(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail);
  /// The reporting half of close_transport: state, timers, and every waiting callback.
  void report_close(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail);
  /// The releasing half: close the transport at once, then drop the security context and policy.
  void release_transport();
  /// Drop the security context and policy on a later strand turn.
  void release_security_state();
  /// Part 6 7.1.5 on an open channel: report, then send a secured CloseSecureChannel request and close
  /// the transport once it is written (on_close_secure_channel_encoded).
  void close_with_close_secure_channel(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail);
  void on_close_secure_channel_encoded();
  /// @p requestId is the id the response arrived under; it must be the id the outstanding
  /// OpenSecureChannel request was sent with (CL-SC-008), and on a renewal @p secureChannelId must be this
  /// channel's id (CL-SC-009). Either mismatch closes the transport.
  void handle_opn_response_async(uint32_t requestId, ua::StatusCode serviceStatus, uint32_t secureChannelId,
    uint32_t tokenId, std::chrono::milliseconds revisedLifetime, ua::ByteString serverNonce,
    std::shared_ptr<const ua::ErrorDetail> detail);
  void on_security_token_created_for_open(ua::SecurityToken::CreateResult result, uint32_t secureChannelId,
    uint32_t tokenId, std::chrono::milliseconds revisedLifetime);
  void on_security_token_created_for_renew(
    ua::SecurityToken::CreateResult result, uint32_t tokenId, std::chrono::milliseconds revisedLifetime);
  void finalise_open(uint32_t tokenId, std::chrono::milliseconds revisedLifetime, bool isRenewing);
  void handle_token_renewal_async();
  void on_renew_nonce_generated(ua::ByteStringResult nonce);
  void start_close();
  void on_outgoing_drained_for_close();
  void on_transport_closed_for_close();
  void schedule_renewal_timer(std::chrono::milliseconds delay);
  /// The renewal is scheduled at three quarters of the revised lifetime, never sooner than this (CL-SC-007).
  /// Kept below 750 ms so a 1 s lifetime still renews before it expires.
  static constexpr std::chrono::milliseconds sMinimumRenewalDelay{500};
  static std::chrono::milliseconds renewal_delay(std::chrono::milliseconds revisedLifetime);

  // --- Helpers ---

  /// The security state a Session signs with, from mContext. Strand-only; mContext must be engaged.
  SessionSecurityInfo session_security_info() const;

  /// Generate a nonce: ephemeral key pair for ECC, random entropy for RSA. Callback-shape. A Bad provider
  /// answer is passed on with this step's ErrorDetail; an Uncertain one is passed on as it is, and the
  /// callback refuses it.
  using NonceCallback = std::function<void(ua::ByteStringResult)>;
  void generate_nonce_async(uint32_t bytes, NonceCallback callback);

  void send_message_internal(uint32_t requestId, std::shared_ptr<ua::Structure> message);

  void handle_unexpected_exception(const char* site, std::exception_ptr ex);

  // --- Members ---

  const std::weak_ptr<SecureChannelDependencies> mDeps;
  const Config mConfig;

  boost::asio::any_io_executor mExecutor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  std::shared_ptr<ua::ConnectionProtocol> mConnection;
  std::shared_ptr<ua::SecureChannelContext> mContext;
  std::shared_ptr<ua::SecurityPolicy> mSecurityPolicy;

  // Channel state machine (replaces SecureChannelLogic).
  ChannelState mChannelState{ChannelState::Idle};

  // Security config (set during open).
  bool mIsAuthenticated{false};
  uint32_t mNonceLength{0};
  uint32_t mRequestedLifetimeMs{3600000};
  ua::MessageSecurityMode mChannelSecurityMode{ua::MessageSecurityMode::None};

  // Token state.
  uint32_t mChannelSecureChannelId{0};
  uint32_t mChannelTokenId{0};
  std::chrono::milliseconds mRevisedLifetime{0};
  ua::ByteString mServerNonce;

  // Lifecycle callbacks.
  OpenedCallback mOnOpened;
  ErrorCallback mOnError;

  /// Persistent user-facing error observer. Fires post-open, at-most-once, posted to executor.
  std::function<void(ua::VoidResult)> mOnChannelError;

  // Default service timeout (ms) from client configuration.
  uint32_t mServiceTimeoutMs{10000};

  // Request correlation.
  uint32_t mNextRequestId{1};
  /// The request id of the OpenSecureChannel request in flight (Issue or Renew); cleared when its response
  /// is handled, so a second OPN response, or one under another id, is refused (CL-SC-008).
  std::optional<uint32_t> mOpnRequestId;
  /// The ServiceResult of the OpenSecureChannel response that opened the channel, given to the opener: a Good
  /// subcode or an Uncertain code the server answered with reaches it.
  ua::StatusCode mOpnServiceResult{ua::Status::Good};
  std::unordered_map<uint32_t, ServiceResponseCallback> mPendingRequests;

  // Per-request deadline timers.
  std::unordered_map<uint32_t, ua::Timer> mRequestTimers;

  // OPN handshake deadline timer.
  ua::Timer mOpnTimer;

  // Close callback (set when close is requested).
  CloseCallback mCloseCallback;

  // Notification slots used by the close flow. Fired by:
  //   mDrainCompleteCallback     - drain_outgoing on queue drain
  //   mTransportClosedCallback   - receive_transport_error when state == Closing
  std::function<void(ua::VoidResult)> mDrainCompleteCallback;
  std::function<void(ua::VoidResult)> mTransportClosedCallback;

  // Close-flow timers.
  ua::Timer mCloseDrainTimer;
  ua::Timer mCloseTransportWaitTimer;

  // Configured close-time waits.
  std::chrono::milliseconds mCloseTransportTimeoutMs{1000};

  // Message queues drained by drain_incoming / drain_outgoing.
  std::queue<std::vector<ua::byte>> mIncomingMessageChunks;

  struct OutgoingMessage
  {
    uint32_t requestId;
    std::shared_ptr<ua::Structure> message;
  };

  std::queue<OutgoingMessage> mOutgoingMessages;
  bool mIncomingDrainScheduled{false};
  /// A transport failure that arrived while received chunks were still queued or decoding: it is delivered
  /// once they are, so a response the server sent before closing (e.g. ApplyChanges, OPC 10000-12 7.10.6)
  /// reaches its caller. Strand-owned.
  std::optional<std::pair<ua::StatusCode, std::shared_ptr<const ua::ErrorDetail>>> mDeferredTransportFailure;

  /// True while received chunks are queued or one is being decoded.
  [[nodiscard]] bool incoming_pending() const noexcept
  {
    return mIncomingDrainScheduled || !mIncomingMessageChunks.empty();
  }

  /// Delivers @ref mDeferredTransportFailure once nothing received is left to process.
  void deliver_deferred_transport_failure();
  bool mOutgoingDrainScheduled{false};
  // True from close_with_close_secure_channel until the CloseSecureChannel request it queued has been
  // encoded (drain_outgoing finds the queue empty) or the transport is released another way.
  bool mCloseSecureChannelPending{false};

  // Incoming-chunk backpressure (mirror of the server-side mechanism). mIncomingChunkQueueDepthCap is
  // snapshotted from ClientConfig::incomingChunkQueueDepth (clamped >= 1) at construction. When
  // mIncomingMessageChunks reaches the cap the channel read-pauses the transport (no chunk dropped); it
  // resumes once the queue drains below half the cap. mReadPaused (strand-owned) tracks the paused state.
  uint32_t mIncomingChunkQueueDepthCap{1};
  bool mReadPaused{false};

  // Last client nonce sent in OPN request, needed for SecurityToken creation on response.
  ua::ByteString mLastClientNonce;

  // Renewal timer.
  ua::Timer mRenewalTimer;

  // Atomic snapshots for cross-strand getter access (Rule 4: info-object pattern).
  std::atomic<uint32_t> mAtomicChannelId{0};
  std::atomic<bool> mAtomicIsOpen{false};

  // Test-only: observer forwarded to the next SessionImpl created via create_session().
  // One-shot - cleared after use. Set via SecureChannelTestAccess.
  std::function<void(const ua::CreateSessionResponse&)> mNextCreateSessionResponseObserver;

  // Test-only: persistent observer invoked on-strand with every outgoing service request (the decoded
  // request object) at send time, before it is framed onto the wire. Null in production (no behaviour
  // change); set via SecureChannelTestAccess so a unit test can capture what the client actually sends
  // (e.g. the CreateSession clientNonce length, the ActivateSession clientSignature) without decoding wire
  // bytes. Persistent (not one-shot) so a single session's CreateSession + ActivateSession are both seen.
  std::function<void(const ua::Structure&)> mOutgoingRequestObserver;

  /// Live-instance counter for leak diagnostics. Zero-sized and inert in a release build; in
  /// debug and sanitizer builds a test can assert `InstanceTracker<ClientSecureChannelTag>::live() == 0`
  /// after churning secure channels, which names the type that leaked instead of a byte count.
  [[no_unique_address]] ua::diagnostics::InstanceTracker<ua::diagnostics::ClientSecureChannelTag>
    mInstanceTracker;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_SECURE_CHANNEL_IMPL_H
