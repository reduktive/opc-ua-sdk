// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SESSION_IMPL_H
#define UA_CLIENT_SESSION_IMPL_H

#include "ua_await_callback.h"
#include "ua_client_session.h"
#include "ua_client_session_security_info.h"
#include "ua_client_token_builder.h"
#include "ua_instance_tracker.h"
#include "ua_user_token_encryption.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_channel_bound_signature_data.h"
#include "ua_crypto.h"
#include "ua_endpoint_description.h"
#include "ua_issued_identity_token.h"
#include "ua_logger.h"
#include "ua_security_policy.h"
#include "ua_structure_factory.h"
#include "ua_timer.h"
#include "ua_user_token_policy.h"
#include "ua_x509_certificate.h"

#include <atomic>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

namespace ua
{
class CreateSessionRequest;
class CreateSessionResponse;
class ActivateSessionRequest;
}  // namespace ua

namespace ua::client
{

class SecureChannelImpl;
class SessionTestAccess;

/// Internal dependencies interface for client Session.
/// The channel's deps provide all of these - no need to expose publicly.
class SessionImpl;

class SessionDependencies
{
public:
  SessionDependencies() = default;
  SessionDependencies(const SessionDependencies&) = delete;
  SessionDependencies& operator=(const SessionDependencies&) = delete;
  SessionDependencies(SessionDependencies&&) = delete;
  SessionDependencies& operator=(SessionDependencies&&) = delete;
  virtual ~SessionDependencies() = default;

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

  // Cascading-shutdown registry. SessionImpl registers itself here on
  // construction (RAII via SessionImpl::create) and unregisters in its
  // destructor. Default no-op so test deps don't have to care.
  virtual void register_session(std::weak_ptr<SessionImpl>)
  {}

  virtual void unregister_session(SessionImpl*)
  {}
};

/// boost::asio::strand<boost::asio::any_io_executor>-serialized component for client-side OPC UA Session.
///
/// Manages the full session lifecycle (CreateSession, ActivateSession, service dispatch,
/// timeout, close) via named continuation chains on a private strand. State machine logic is
/// inlined into the continuation methods (start_*/on_*) - no separate logic/shell split.
class SessionImpl : public std::enable_shared_from_this<SessionImpl>
{
public:
  /// The executor this component's operations complete on; a blocking wrapper must not wait on it from
  /// one of its threads.
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept
  {
    return mExecutor;
  }

  SessionImpl() = delete;
  SessionImpl(const SessionImpl&) = delete;
  SessionImpl(SessionImpl&&) noexcept = delete;
  SessionImpl& operator=(const SessionImpl&) = delete;
  SessionImpl& operator=(SessionImpl&&) noexcept = delete;
  ~SessionImpl();

  using ServiceResponseResult = ua::Result<std::shared_ptr<ua::Structure>>;
  using ServiceResponseCallback = std::function<void(ServiceResponseResult)>;
  using CloseCallback = std::function<void(ua::VoidResult)>;
  using ActivateCallback = std::function<void(ua::VoidResult)>;

  using CreatedCallback = std::function<void(ua::VoidResult)>;
  using ErrorCallback = std::function<void(ua::VoidResult)>;

  /// Security parameters passed from the secure channel to the session.
  using SecurityInfo = SessionSecurityInfo;

  /// Configuration for session creation.
  struct Config
  {
    double requestedSessionTimeoutMs{1200000.0};  // 20 minutes default
    std::string endpointUrl;
    std::string sessionName;  ///< Human-readable name recorded by the server for this session.
    bool isAuthenticated{false};
    /// Unauthenticated GetEndpoints evidence used to select this channel. Empty means the caller selected
    /// an ExactUrl without discovery; non-empty activates the mandatory Part 4 section 5.4.1 comparisons.
    std::vector<ua::EndpointDescription> discoveryEndpoints;
    std::string ecdhPolicyUri;
    bool requestEphemeralKey{true};  ///< See CreateSessionConfig::requestEphemeralKey.
    bool relaxHostNameCheck = false;
    std::function<ua::String()> auditEntryIdProvider;
    std::optional<uint32_t> returnDiagnosticsOverride;

    /// Persistent user-facing error observer. Fires post-activate when session dies unexpectedly.
    std::function<void(ua::VoidResult)> onSessionError;
  };

  /// Factory: creates the impl, begins CreateSession handshake.
  /// @param onCreated  Called (on strand) when CreateSession succeeds (session is created but not active).
  /// @param onError    Called (on strand) on fatal session error.
  static std::shared_ptr<SessionImpl> create(std::weak_ptr<SessionDependencies> deps,
    std::shared_ptr<SecureChannelImpl> channel, Config config, SecurityInfo securityInfo,
    CreatedCallback onCreated, ErrorCallback onError);

  // --- Public API (called from Session forwarding methods) ---

  /// Send a service request through the channel.
  /// @param timeoutMs  Per-request timeout override (0 = use default from config).
  void send_request(std::shared_ptr<ua::Structure> request, ServiceResponseCallback callback,
    uint32_t timeoutMs = 0) noexcept;

  void activate(Session::ActivateConfig config, ActivateCallback callback) noexcept;

  /// Activate on a new channel (reconnection flow).
  /// Rebinds the session to the given channel, then sends ActivateSession.
  /// Valid from Disconnected, Created, or Active states.
  void activate(std::shared_ptr<SecureChannelImpl> channel, Session::ActivateConfig config,
    ActivateCallback callback) noexcept;

  void close(CloseCallback callback) noexcept;

  /// As above, but controls whether the server destroys this Session's Subscriptions (OPC 10000-4 5.6.4).
  void close(bool deleteSubscriptions, CloseCallback callback) noexcept;

  ua::NodeId session_id() const;

  /// Server's revised session timeout (milliseconds) from the CreateSession response; 0 before the session
  /// is created. Thread-safe (atomic snapshot).
  double revised_session_timeout_ms() const;

  /// Authentication token for stamping on outgoing service requests.
  /// Thread-safe (atomic snapshot).
  ua::NodeId authentication_token() const;

  /// Default returnDiagnostics bitmask from client configuration.
  uint32_t default_return_diagnostics() const;
  uint32_t return_diagnostics_for(uint32_t requestValue) const;

  /// Resolves the RequestHeader timeoutHint to send, defaulting an unset (`0`) hint to the client's
  /// configured service timeout. The same value bounds the request locally, so the deadline the
  /// client enforces and the hint the Server is given are one number rather than two.
  uint32_t timeout_hint_for(uint32_t requestValue) const;
  void set_return_diagnostics_override(std::optional<uint32_t> mask) noexcept;
  bool wrap_tier0() const;

  /// Returns the next configured audit entry id. Called synchronously by the request-header stamper before
  /// send_request; an empty provider/value means auditing is not used.
  ua::String next_audit_entry_id() const;

  bool is_active() const;

  bool is_created() const;

  bool is_disconnected() const;

private:
  friend class SecureChannelImpl;
  friend class SessionTestAccess;

  /// Null-safe logger for this session's async continuations.
  ///
  /// The session has no stored logger; its logger lives on the (weak) dependencies. This returns the
  /// dependencies' `client.session`-categorised logger, or a no-op @ref ua::Logger if the dependencies
  /// are already gone - so it is safe to hand into the post helpers / guarded at any call site without
  /// a separate null check. A @ref ua::Logger is a value handle that survives teardown.
  ua::Logger logger() const
  {
    auto deps = mDeps.lock();
    return deps ? deps->logger().with_category("client.session") : ua::Logger{};
  }

  /// Session lifecycle states.
  enum class SessionState
  {
    Idle,
    Creating,
    ValidatingServerSignature,
    Created,
    Activating,
    Active,
    Disconnected,
    Closing,
    Closed
  };

  SessionImpl(std::weak_ptr<SessionDependencies> deps, std::shared_ptr<SecureChannelImpl> channel,
    Config config, SecurityInfo securityInfo, CreatedCallback onCreated, ErrorCallback onError);

  void initialise();

  // --- Internal continuation chains (run on strand) ---

  /// Per-flow state for CreateSession. Saves the response fields between
  /// signature validation and final state mutation.
  struct CreateState
  {
    std::shared_ptr<ua::CreateSessionRequest> request;
    // Fields cached from the CreateSessionResponse for use after validate_server_signature_async.
    ua::NodeId responseSessionId;
    ua::NodeId responseAuthenticationToken;
    ua::ByteString responseServerNonce;
    double responseRevisedSessionTimeoutMs{0.0};
    /// The CreateSessionResponse's ServiceResult, given to the creation callback.
    ua::StatusCode responseServiceResult{ua::Status::Good};
  };

  /// CreateSession handshake: sends request, processes response, validates server signature
  /// (for authenticated channels), transitions to Created state.
  void create_session_internal();

  /// The session strand, checked engaged. Defined in the .cpp so the one `engaged_strand` guard -
  /// which exists to make the invariant provable to the static analyzer - stays the only place that
  /// narrows the optional.
  boost::asio::strand<boost::asio::any_io_executor>& session_strand();

  /// Awaits one collaborator call of this session's own body, back on its strand.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(session_strand(),
      logger(),
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          session_strand(),
          logger(),
          [completion = std::move(completion)](SessionImpl&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  /// The CreateSession handshake: client nonce, send, then everything the response has to survive.
  ua::async::Task<> run_create_session();

  /// Verifies the CreateSessionResponse and, on an authenticated channel, the server signature.
  ua::async::Task<> handle_create_session_response(ServiceResponseResult responseResult);
  void reject_create_session_verification(ua::NodeId authenticationToken,
    std::shared_ptr<const ua::ErrorDetail> detail,
    ua::StatusCode status = ua::StatusCode{ua::Status::BadSecurityChecksFailed});
  void on_server_signature_validated(ua::VoidResult result);
  void complete_create();

  /// Per-flow state for ActivateSession. Allocated in activate_internal, threaded through
  /// the named continuation chain, cleared in complete/fail completion points.
  struct ActivateState
  {
    UserIdentity identity;
    std::string policyId;
    std::vector<ua::String> localeIds;
    std::shared_ptr<ua::ActivateSessionRequest> request;
    PreparedToken prepared;
    bool wasActive{false};
  };

  /// ActivateSession handshake: builds user token, sends request, processes response,
  /// transitions to Active state. Per-flow state lives on mActivateState.
  void activate_internal(
    UserIdentity identity, std::string policyId, std::vector<ua::String> localeIds, bool wasActive);

  /// The ActivateSession handshake: client signature, user-token encryption, X509 signature, send.
  ua::async::Task<> run_activate();

  /// Encrypts the user-token secret when the resolved policy requires it. Returns false only when it
  /// has already FAILED CLOSED - never when it proceeded without encrypting.
  ua::async::Task<bool> encrypt_user_token();
  /// Before an ECC user-token encryption: the server's EphemeralKey must have been solicited by this
  /// client for the token policy in use, and its signature must verify with the channel's authenticated
  /// certificate (Part 4 7.15). Refuses the activation (fail-closed) otherwise; returns false when it
  /// has answered.
  ua::async::Task<bool> verify_server_ephemeral_key();
  /// Adopts the ECDHKey an authenticated response carries, but only when this client solicited one
  /// (an unsolicited key is the mark of a peer choosing the client's encryption for it).
  void adopt_server_ephemeral_key(const ua::Structure* additionalHeader, std::string_view responseName);
  /// Issues the actual user-token encryption (shared by the secure-channel-direct and the None-channel
  /// post-cert-validation paths). @p crypto and the token aliases were resolved by @ref
  /// start_encrypt_user_token.
  ///
  /// @param userNameToken The request's UserNameIdentityToken, or null for an issued-token activation.
  /// @param issuedToken   The request's IssuedIdentityToken, or null for a user-name activation. It is
  ///                      encrypted through the dedicated Table 195 EncryptedSecret path so the outer
  ///                      encryptionAlgorithm stays empty and deprecated RSA cannot select legacy form.
  /// Refuses the activation (CL-IDENT-006): the server certificate could not be validated/trusted before
  /// encrypting the user token on an unsecured channel. Fails the flow closed (mirrors the build_user_token
  /// refuse): Closed state + `handle_session_error` + `handle_session_closed`.
  void refuse_user_token_encryption(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail);
  void on_activate_response_received(ServiceResponseResult responseResult);

  /// CloseSession: sends request, processes response, transitions to Closed state.
  void close_internal(bool deleteSubscriptions);
  /// Continuation: receives the CloseSessionResponse (or send-failure result).
  void on_close_session_response_received(ServiceResponseResult responseResult);

  /// Validate server signature (Part 4 Section 5.6.2) and return the status.
  void validate_server_signature_async(ua::ByteString serverCertificateDer, ua::ByteString serverSignature,
    std::function<void(ua::VoidResult)> callback);
  void on_leaf_server_signature_validated(std::shared_ptr<const ua::X509Certificate> serverCertificate,
    ua::ByteString serverSignature, std::function<void(ua::VoidResult)> callback,
    ua::VoidResult leafVerification);
  void on_client_issuer_certificates_loaded(std::shared_ptr<const ua::X509Certificate> serverCertificate,
    ua::ByteString serverSignature, std::function<void(ua::VoidResult)> callback,
    ua::VoidResult leafVerification, ua::CertificateListResult issuerCertificates);
  void on_full_chain_server_signature_validated(
    std::function<void(ua::VoidResult)> callback, ua::VoidResult chainVerification);
  /// Builds the data a channel bound session signature covers (OPC 10000-4 section 6.1.8 Table 101) from this
  /// Session's ClientNonce and its channel's ChannelThumbprint and certificates. HASH is @p decidingPolicy's
  /// CertificateThumbprintAlgorithm; @p serverCertificate and @p clientCertificate are leaf DER, empty where
  /// the row does not use them. The callback runs on the Session strand.
  void build_channel_bound_data_async(ua::ChannelBoundSignature signature,
    const ua::SecurityPolicy& decidingPolicy, ua::ByteString serverNonce, ua::ByteString serverCertificate,
    ua::ByteString clientCertificate, std::function<void(ua::ByteStringResult)> callback);

  /// Verifies a channel bound ServerSignature over @p signedData with the leaf @p serverCertificate; a
  /// failure answers Bad_ApplicationSignatureInvalid, with no chain fallback (the channel bound method uses
  /// the leaf).
  void verify_channel_bound_server_signature_async(
    std::shared_ptr<const ua::X509Certificate> serverCertificate, ua::ByteString signedData,
    ua::ByteString serverSignature, std::function<void(ua::VoidResult)> callback);

  void complete_invalid_server_signature(
    std::function<void(ua::VoidResult)> callback, ua::VoidResult verificationFailure);

  // --- Effect helpers (run on strand) ---

  /// Schedule or re-arm the inactivity watchdog (75% of revised timeout).
  ///
  /// Called after activation and after every issued Session Service request, because Part 4 section
  /// 5.6.2.2 defines the timeout in terms of the Client failing to issue requests, not elapsed Session age.
  void schedule_timeout_timer();

  /// Handle a fatal session error: log, cancel timer, fail pending requests/callbacks.
  void handle_session_error(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail);

  /// Handle session closed: log, cancel timer, fail pending requests, invoke close callback.
  void handle_session_closed(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail);

  /// Handle channel disconnect: transition Active sessions to Disconnected state.
  /// Sessions in other states are closed permanently.
  void handle_channel_disconnected(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail);

  /// Send a request through SecureChannel (no auth token stamping for lifecycle requests).
  void send_session_request(std::shared_ptr<ua::Structure> request, ServiceResponseCallback callback);

  void handle_unexpected_exception(const char* site, std::exception_ptr ex);

  /// Update the atomic state snapshots for cross-strand getters.
  void update_atomic_snapshots();

  // --- Members ---

  const std::shared_ptr<SessionDependencies> mDepsOwner;  // Keeps deps alive for session lifetime.
  const std::weak_ptr<SessionDependencies> mDeps;
  const Config mConfig;

  boost::asio::any_io_executor mExecutor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  // Session owns the channel strongly for the session's lifetime. The user passes
  // channel ownership via SecureChannel::create_session / Session::activate(channel);
  // the session may outlive any external strong ref the user held (e.g. when the
  // user moved their `SecureChannel` into activate). Cleared on close / disconnect /
  // rebind.
  std::shared_ptr<SecureChannelImpl> mChannel;

  // --- Session state (strand-local) ---

  SessionState mSessionState{SessionState::Idle};
  ua::NodeId mSessionId;
  ua::NodeId mAuthenticationToken;
  ua::ByteString mServerNonce;
  double mRevisedSessionTimeoutMs{0.0};

  // Security context from the secure channel.
  SecurityInfo mSecurityInfo;
  ua::ByteString mClientNonce;
  ua::ByteString mServerCertificateDer;  // Canonical leaf DER used for ActivateSession signing.
  std::shared_ptr<const ua::X509Certificate> mServerCertificate;  // Parsed from mServerCertificateDer.
  // The issuers the server presented after its leaf in CreateSession serverCertificate (decision 24).
  std::vector<std::shared_ptr<const ua::X509Certificate>> mServerPresentedIssuers;

  // User token policies from the matching endpoint in CreateSessionResponse.
  // Used to resolve per-token security policies for encryption/signing.
  std::vector<ua::UserTokenPolicy> mEndpointUserTokenPolicies;

  // ECC user token encryption state (Part 6, 6.8.3).
  ua::ByteString mServerEphemeralPublicKey;
  /// The signature the server placed on that key (Part 4 7.15 EphemeralKeyType.signature); verified
  /// against the channel certificate before the key is used.
  ua::ByteString mServerEphemeralKeySignature;
  /// The ECDHPolicyUri this client sent in CreateSession; empty when none was solicited, in which case
  /// any ECDHKey a response carries is ignored.
  std::string mRequestedEcdhPolicyUri;

  // Lifecycle callbacks.
  CreatedCallback mOnCreated;
  ErrorCallback mOnError;

  /// Persistent user-facing error observer. Fires post-activate, at-most-once, posted to executor.
  std::function<void(ua::VoidResult)> mOnSessionError;

  // Test-only: observer called with the full CreateSessionResponse before fields are extracted.
  // One-shot - cleared after firing. Set via SecureChannelImpl during session creation.
  using CreateSessionResponseObserver = std::function<void(const ua::CreateSessionResponse&)>;
  CreateSessionResponseObserver mCreateSessionResponseObserver;

  // Activate callback (set when activate is requested).
  ActivateCallback mActivateCallback;

  // Request correlation: requestHandle -> callback.
  uint32_t mNextRequestHandle{1};
  std::unordered_map<uint32_t, ServiceResponseCallback> mPendingRequests;

  // Every caller waiting for the current close operation.
  std::vector<CloseCallback> mCloseCallbacks;

  // Per-flow state for in-flight CreateSession (single-instance per Session).
  std::unique_ptr<CreateState> mCreateState;
  /// The CreateSession body. Lives on the session, so it dies with it.
  ua::async::Task<> mCreateTask;

  // Per-flow state for in-flight ActivateSession (single-instance per Session).
  std::unique_ptr<ActivateState> mActivateState;
  /// The ActivateSession body. Lives on the session, so it dies with it.
  ua::async::Task<> mActivateTask;

  // Session timeout timer.
  ua::Timer mTimeoutTimer;

  // Atomic snapshots for cross-strand getter access (Rule 4: info-object pattern).
  std::atomic<int> mAtomicState{0};  // Mirrors SessionState as int.
  std::atomic<std::shared_ptr<const ua::NodeId>> mAtomicSessionId;
  std::atomic<std::shared_ptr<const ua::NodeId>> mAtomicAuthenticationToken;
  std::atomic<double> mAtomicRevisedSessionTimeoutMs{0.0};  // Mirrors mRevisedSessionTimeoutMs.
  // UINT64_MAX means no per-Connection override; every uint32_t value, including zero, is representable.
  std::atomic<uint64_t> mReturnDiagnosticsOverride{UINT64_MAX};

  // Live-instance counter for leak diagnostics (RAII; zero-cost in release).
  [[no_unique_address]] ua::diagnostics::InstanceTracker<ua::diagnostics::ClientSessionTag> mInstanceTracker;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_SESSION_IMPL_H
