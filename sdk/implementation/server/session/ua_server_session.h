// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// clang-format Language: Cpp

#ifndef UA_SERVER_SESSION_H
#define UA_SERVER_SESSION_H

#include <atomic>
#include <chrono>
#include <queue>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include "ua_await_callback.h"
#include "ua_callback_safety.h"
#include "ua_identity_attempt_outcome.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_address_space.h"
#include "ua_service_fault.h"
#include "ua_instance_tracker.h"
#include "ua_timer.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_close_session_request.h"
#include "ua_close_session_response.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_server_session_info.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_write_request.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_continuation_points.h"
#include "ua_history_read_service.h"
#include "ua_history_update_service.h"
#include "ua_certificate_store.h"
#include "ua_channel_bound_signature_data.h"
#include "ua_crypto_types.h"
#include "ua_find_servers_on_network_request.h"
#include "ua_find_servers_request.h"
#include "ua_get_endpoints_request.h"
#include "ua_client_id.h"
#include "ua_server_secure_channel_info.h"
#include "ua_method_response_correlation.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_create_subscription_request.h"
#include "ua_modify_subscription_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_publish_request.h"
#include "ua_republish_request.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "services/ua_discovery_service_set.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

#include "ua_logger.h"
#include "ua_server_authentication.h"
#include "ua_server_components.h"
#include "ua_server_observer.h"

#include "ua_error_detail.h"
#include "ua_result.h"
#include "security/ua_server_authentication.h"
#include "ua_server_counters.h"
#include "ua_request_latency_tracker.h"
#include "ua_service_kind.h"
#include "ua_session_diagnostics_helper.h"
#include "ua_session_description.h"
#include "ua_session_security.h"
#include "ua_access_identity_registry.h"
#include "ua_subscriptions_pipeline.h"
#include "ua_subscription_router.h"

namespace ua
{
class TranslateBrowsePathsToNodeIdsRequest;
class SecurityPolicy;
}  // namespace ua

namespace ua::server
{

class ServerImpl;
class SecureChannel;
class Service;
class Session;
class NodeManagementDelegate;
class SubscriptionIdAllocator;
class SubscriptionsPipeline;
class OrphanedSubscriptionStore;

class SessionDependencies
{
public:
  SessionDependencies() = default;
  virtual ~SessionDependencies() = default;

  // Polymorphic interface: held only by weak_ptr/shared_ptr, never value-copied.
  // Deleting copy/move prevents slicing (C.67) and completes Rule-of-5.
  SessionDependencies(const SessionDependencies&) = delete;
  SessionDependencies& operator=(const SessionDependencies&) = delete;
  SessionDependencies(SessionDependencies&&) = delete;
  SessionDependencies& operator=(SessionDependencies&&) = delete;

  virtual weak_ptr<DiscoveryDependencies> discovery_dependencies() = 0;
  virtual boost::asio::any_io_executor executor() = 0;
  virtual shared_ptr<const Crypto> crypto() = 0;
  virtual WeakAddressSpace address_space() = 0;
  virtual const ::ua::ApplicationConfig& configuration() = 0;
  virtual const ::ua::server::ServerConfig& server_configuration() = 0;
  virtual shared_ptr<CertificateStore> default_application_group_certificate_store() = 0;

  // Trust anchors for X.509 user identity tokens; null when the deployment configured none, which
  // is a supported configuration rather than an error. Defaulted so that test fakes that never activate an
  // X.509 token need not override it.
  virtual shared_ptr<CertificateStore> user_token_certificate_store()
  {
    return nullptr;
  }

  virtual StructureFactory& structure_factory() = 0;
  virtual std::vector<ServerEndpointConfig> endpoints() = 0;

  // Remove a session from server ownership (closed sessions are removed).
  virtual void remove_session(const shared_ptr<Session>& session) = 0;

  // The components AS SUPPLIED to the server: the session layer reads ONLY the authenticator (null
  // rejects every activation) and the Part-18 Role configuration from here. The other members are not
  // the server's effective ones - mApplicationGroupCertificateStore may be null where the server created
  // a store of its own, and neither it nor mCrypto need be the instance the server uses - so read crypto()
  // and default_application_group_certificate_store() instead. The authentication interval is
  // `server_configuration().authnTimeout`.
  virtual const ::ua::server::ServerComponents& components() const = 0;

  virtual std::shared_ptr<ServerObserver> observer() = 0;
  virtual Logger logger() = 0;

  // Diagnostic counters (shared from ServerImpl).
  virtual std::shared_ptr<RequestLatencyTracker> latency_tracker() = 0;
  virtual std::shared_ptr<ServerSummaryCounters> summary_counters() = 0;
  virtual std::shared_ptr<std::atomic<bool>> diagnostics_enabled() = 0;

  // Server-wide subscription ID allocator.
  virtual SubscriptionIdAllocator& subscription_id_allocator() = 0;

  // Server-wide subscription registry (maps subscription IDs to owning sessions).
  virtual SubscriptionRouter& subscription_router() = 0;

  // Server-wide holder for subscriptions orphaned by CloseSession(deleteSubscriptions=false),
  // kept alive until transferred to a new session or their lifetime expires (Part 4 5.7.4).
  virtual OrphanedSubscriptionStore& orphaned_subscription_store() = 0;

  // Server-wide event bus for event routing.
  virtual EventBus& event_bus() = 0;

  // Shared ownership view of the event bus - used by long-lived components
  // (e.g. SubscriptionsPipeline) that store the bus across async boundaries.
  // Lock as weak_ptr at the storage site to avoid member-destruction-order
  // hazards.
  virtual std::shared_ptr<EventBus> event_bus_shared() = 0;

  // Application-provided node management handler (may be null if unsupported).
  virtual std::shared_ptr<NodeManagementDelegate> node_management_delegate() = 0;

  // S11 / SESS-2: identity token attack protection (Part 4 5.6.3, 7.41.2.1). An authentication
  // attempt is RESERVED before it starts and RELEASED with its outcome when it ends, so the lockout
  // counts what is in flight: parallel guesses cannot exceed the threshold, and an attempt the client
  // never got an answer for (abandoned) is no guess. `begin_identity_attempt` returns
  // BadIdentityTokenInvalid when the client application is locked out or its budget (failures plus
  // attempts in flight) is spent - deliberately the same code as a normal validation failure, to avoid
  // leaking lockout state (see the impl); nullopt admits the attempt and takes its reservation.
  using IdentityAttemptOutcome = ua::server::IdentityAttemptOutcome;
  virtual optional<StatusCode> begin_identity_attempt(
    const ClientId& client, std::string_view claimedUserId) = 0;
  virtual void finish_identity_attempt(
    const ClientId& client, std::string_view claimedUserId, IdentityAttemptOutcome outcome) = 0;

  // S12: Server-wide in-flight discovery request counter for load-aware throttling.
  virtual std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() = 0;

  /// Server-scoped table that interns equal live access identities.
  AccessIdentityRegistry& access_identity_registry();

private:
  std::once_flag mAccessIdentityRegistryOnce;
  std::unique_ptr<AccessIdentityRegistry> mAccessIdentityRegistry;
};

class Session : public std::enable_shared_from_this<Session>
{
  // Test-only access to Session interfaces/state without exposing them publicly.
  friend struct SessionTestAccess;

public:
  Session() = delete;
  Session(const Session&) = delete;
  Session(Session&& other) noexcept = delete;
  Session& operator=(const Session& other) = delete;
  Session& operator=(Session&& other) noexcept = delete;
  ~Session();

  // P4-SS-0005: Used by ServerImpl to identify eviction candidates at max-sessions limit.
  bool is_activated() const;

  // The session NodeId. Thread-safe: reads from the atomic identity snapshot.
  // Returns empty NodeId if called before create_internal() completes.
  NodeId session_id() const;

  // ApplicationUri of the calling Client (from CreateSessionRequest.ClientDescription), captured at
  // create time and immutable thereafter - safe to read from any thread. Used to classify
  // subscription transfers as same-client vs alternate-client.
  String client_application_uri() const;

  // The authentication token assigned to this session (immutable after creation).
  // Used by ServerImpl for session-by-token lookup (cross-channel ActivateSession).
  const SessionAuthenticationToken& authentication_token() const;

  // Pull health: snapshot per-session counters.
  SessionHealthSnapshot health_snapshot() const;

  // Counter accessor for ServerImpl to share with diagnostic node handlers.
  std::shared_ptr<SessionCounters> counters() const;

  // Security-state accessor for ServerImpl to share with diagnostic node handlers.
  std::shared_ptr<SessionSecurityState> security_state() const;

  // Descriptive-state accessor for ServerImpl to share with diagnostic node handlers.
  std::shared_ptr<SessionDescriptiveState> descriptive_state() const;

  // Set the close reason before destruction (used by ServerImpl for eviction).
  void set_close_reason(StatusCode reason);

  // Brings the Session's diagnostics object in line with @p enabled, on the Session strand. @p settled is
  // released once the object matches, or once the Session has gone: a caller that gives each Session a
  // copy of one token (see release_token) learns when every Session has caught up.
  void set_diagnostics_enabled(bool enabled, std::shared_ptr<void> settled);

  // The NodeId of the Session's SessionDiagnostics Object once the Session has finished creating it, else
  // nullopt (diagnostics off, or the Object still being created or removed; its Nodes are visible in the
  // address space before its creation finishes). Must run on the Session strand.
  [[nodiscard]] std::optional<NodeId> diagnostics_object_id() const;

  // A token that runs @p action, guarded by @p logger, when its last copy is released.
  static std::shared_ptr<void> release_token(Logger logger, std::function<void()> action);

  /// Transfer support: result of detaching a subscription for transfer.
  struct SubscriptionDetachResult
  {
    std::shared_ptr<Subscription> subscription;
    std::vector<SubscriptionsPipeline::RetransmissionEntry> retransmissionEntries;
  };

  using DetachForTransferCallback = std::function<void(Result<SubscriptionDetachResult>)>;

  /// Transfer support: detach a subscription for transfer to another session.
  /// Validates that the requesting user matches this session's user.
  /// Posts to session strand internally. Invokes callback with result.
  void detach_subscription_for_transfer(IntegerId subscriptionId, const UserIdentity& requestingUser,
    const EndpointSecurityContext& requestingSecurity, DetachForTransferCallback callback);

  /// GetMonitoredItems support: query the server/client handles for all monitored items
  /// in a subscription owned by this session. Posts to session strand -> subscription strand.
  using GetMonitoredItemsCallback = std::function<void(Result<MonitoredItemHandles>)>;
  void get_monitored_items_async(IntegerId subscriptionId, GetMonitoredItemsCallback callback);

  /// ResendData support: trigger a full data resend on a subscription owned by this session
  /// (Part 4 5.12.2.3). Posts to session strand -> subscription strand.
  using ResendDataCallback = std::function<void(StatusCode)>;
  void resend_data_async(IntegerId subscriptionId, ResendDataCallback callback);

  /// SetSubscriptionDurable support: mark a subscription owned by this session durable
  /// (Part 4 5.13.9). Posts to session strand -> subscription strand. The callback receives a
  /// Result carrying, on success, the revised lifetime in hours (>= 1).
  using SetSubscriptionDurableCallback = std::function<void(Result<uint32_t>)>;
  void set_subscription_durable_async(
    IntegerId subscriptionId, uint32_t lifetimeInHours, SetSubscriptionDurableCallback callback);

  void activate(uint32_t requestId, ActivateSessionRequest&& activateSessionRequest,
    optional<SecureChannelInfo> secureChannelInfo);

  void close(uint32_t requestId, CloseSessionRequest&& closeSessionRequest);

  /// Re-checks the Certificates this Session holds against the current trust lists, closing it when
  /// one is no longer valid.
  ///
  /// Part 12 7.8.2.3: "When the TrustList changes the Server shall re-evaluate the Certificate
  /// associated with any open Sessions. Sessions with an untrusted or revoked Certificate shall be
  /// closed." 7.10.6: "If a TrustList change only affects UserIdentity associated with a Session then
  /// Servers shall re-evaluate the UserIdentity and if it is no longer valid the Session and
  /// associated Subscriptions are closed." The Client's application instance Certificate (with the
  /// issuers it presented) is validated against the DefaultApplicationGroup, the X.509 user identity
  /// an activated Session holds against the DefaultUserTokenGroup, each with the SecurityPolicy it was
  /// first validated under. Posts to the session strand; a no-op for a Certificate the Session does not
  /// hold, and once it is closed. Cost: one validation per held Certificate, per TrustList change.
  void reevaluate_certificates_async();

  /// Defers reevaluate_certificates_async, and the re-evaluation of this Session's SecureChannel, until
  /// the exactly correlated response has been written to that channel (the ApplyChanges caller
  /// receives its response before either closes). Stale association epochs are rejected. The callback
  /// receives the SecureChannel the response is correlated with (empty when the Session has none), so
  /// the caller re-evaluates every other channel at once.
  void reevaluate_certificates_after_response_async(MethodResponseCorrelation correlation);

  void reevaluate_certificates_after_response_async(
    MethodResponseCorrelation correlation, std::function<void(Result<weak_ptr<SecureChannel>>)> callback);
  /// Defers closing the exact origin SecureChannel association until its correlated response has
  /// crossed the outgoing queue boundary. Stale association epochs are rejected.
  void close_secure_channel_after_response_async(
    MethodResponseCorrelation correlation, std::function<void(Result<weak_ptr<SecureChannel>>)> callback);

  /// Server-initiated session termination for graceful shutdown.
  /// Posts to the session strand, sets close reason, runs the timeout/close state machine
  /// (which drains publish queues and sends ServiceFault responses), and fires observer events.
  void terminate_for_shutdown();

  using CreateAdmission = std::function<VoidResult(shared_ptr<Session>)>;
  static shared_ptr<Session> create(weak_ptr<SessionDependencies> dependencies,
    SecureChannelInfo secureChannelInfo, uint32_t requestId, CreateSessionRequest&& createSessionRequest,
    CreateAdmission admission = {});

  // MaxSessions eviction suppresses a pending CreateSession success before the victim leaves the
  // Server registry; teardown itself is posted separately and never runs under the Server mutex.
  bool suppress_create_completion_for_eviction() noexcept;
  void terminate_for_eviction() noexcept;
  bool creation_committed() const noexcept;

private:
  using BrowseContinuationPoints = std::unordered_map<Guid, BrowseContinuationPoint>;

  // Test-only: register a response sink invoked for every response.
  // Called on the session strand.
  using ResponseSinkForTests = std::function<void(const Response&)>;

  class SessionInfo : public ua::server::SessionInfo, public ua::server::SessionSecurityContext
  {
  public:
    explicit SessionInfo(weak_ptr<SessionDependencies> dependencies);

    virtual AddressSpace address_space() const override;
    virtual const ::ua::ApplicationConfig& configuration() const override;
    virtual const ::ua::server::ServerConfig& server_configuration() const override;
    DiagnosticSecurityContext diagnostic_security_context() const override;
    Logger logger() const override;
    std::shared_ptr<EventSink> event_sink() const override;

    // SessionSecurityContext
    ua::NodeId session_id() const override;
    std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint_security() const override;
    std::shared_ptr<const ua::server::UserIdentity> user_identity() const override;
    std::shared_ptr<const ua::AccessIdentity> access_identity() const override;
    Result<std::shared_ptr<const ua::AccessIdentity>> access_identity_result() const override;
    std::shared_ptr<const ua::CallerInfo> caller() const override;
    std::shared_ptr<const ua::AccessIdentity> committed_access_identity() const;
    // The maxResponseMessageSize the Client requested in CreateSession (0 = not used); services bound
    // their responses by it (OPC 10000-4 5.6.2.2, SVC-12).
    uint32_t max_response_message_size() const override;
    // Called by Session once, from CreateSession, with the value it stored.
    void set_max_response_message_size(uint32_t maxResponseMessageSize);
    // Called by Session to update security context after activation.
    void set_security_context(ua::NodeId sessionId,
      std::shared_ptr<const ua::server::EndpointSecurityContext> sec,
      std::shared_ptr<const ua::server::UserIdentity> user,
      std::shared_ptr<const ua::AccessIdentity> identity);

    weak_ptr<SessionDependencies> dependencies() const;

  private:
    mutable std::shared_mutex mMutex;
    weak_ptr<SessionDependencies> mDependencies;

    ua::NodeId mSessionId;
    std::shared_ptr<const ua::server::EndpointSecurityContext> mEndpointSecurity;
    std::shared_ptr<const ua::server::UserIdentity> mUserIdentity;
    mutable std::shared_ptr<const ua::AccessIdentity> mAccessIdentity;
    // The caller built from the four fields above, replaced with them (NR-49 rule 2): one object that the
    // Session's subscriptions share, so their samples are read for one caller.
    mutable std::shared_ptr<const ua::CallerInfo> mCaller;
    // Written on the session strand at CreateSession, read by services on other strands.
    std::atomic<uint32_t> mMaxResponseMessageSize{0};
  };

  /// Unregisters what this Session still holds registered; the Session's end, whether closed or destroyed.
  void release_registered_nodes() noexcept;

  enum class State
  {
    Invalid,
    Created,
    Activated,
    Closed
  };

public:
  using ServiceKind = ::ua::server::ServiceKind;

private:
  // Cross-strand observable identity snapshot (written once on strand in create_internal,
  // read from any thread in health_snapshot). C++20 atomic<shared_ptr>.
  struct SessionIdentity
  {
    NodeId sessionId;
    std::string sessionName;
  };

  // Cross-strand observable state (atomic). Read by `is_activated()`, eviction logic, and
  // other code paths that may run on threads other than the session strand.
  //
  // Ordering vs the strand-local `mSessionState` below: when the auth pipeline succeeds,
  // `mSessionState` flips to State::Activated when the identity is committed (in
  // `commit_activate_identity`, part-way through building the response - never before, so a failed
  // build leaves the previous state, security review SESS-7(g)) but `mState` (atomic) only flips to
  // State::Activated *late* (in `complete_activate_response`, after the wire response has been
  // queued). Cross-strand observers therefore see Activated only once a response has actually been
  // sent. This staggering is intentional - strand-local code gates on `mSessionState` because it
  // needs to know "identity committed" to finish the response chain; cross-strand observers gate on
  // `mState` because they need "activation visible to peers".
  std::atomic<State> mState{State::Invalid};
  const weak_ptr<SessionDependencies> mDependencies;
  std::atomic<StatusCodeValue> mCloseReason{StatusCode{Status::BadShutdown}.value()};
  std::atomic<std::shared_ptr<const SessionIdentity>> mIdentity;
  uint32_t mCloseEventChannelId{};
  std::string mCloseEventRemoteAddress;
  shared_ptr<SessionInfo> mSessionInfo;
  std::vector<LocaleId> mLocales;
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  /// Logger for this session's async continuations, captured from the dependencies at construction
  /// (a value handle that survives the session's and the server's destruction). Passed into the post
  /// helpers at each call site. Distinct from the deps-locking SessionInfo::logger() override, which
  /// returns {} once the server is gone and so is unsafe for a drain-time continuation.
  ua::Logger mLogger;
  std::string mSessionName;
  shared_ptr<const X509Certificate> mClientCertificate;
  // The issuers presented with mClientCertificate and the SecurityPolicy it was validated under at the
  // OpenSecureChannel; reevaluate_certificates_async validates the three again when the TrustList changes.
  std::vector<shared_ptr<const X509Certificate>> mClientIssuerCertificates;
  shared_ptr<const SecurityPolicy> mClientCertificatePolicy;
  // ApplicationUri of the calling Client from CreateSessionRequest.ClientDescription.
  // Captured at create time so it is available when EndpointSecurityContext is
  // populated during activation.
  ua::String mClientApplicationUri;
  std::chrono::milliseconds mRevisedSessionTimeout{};
  uint32_t mMaxResponseMessageSize{};
  optional<SecureChannelInfo> mSecureChannelInfo;
  optional<SecureChannelInfo> mPendingSecureChannelInfo;  // Deferred until logic approves activation.
  NodeId mSessionId;
  SessionAuthenticationToken mAuthenticationToken;
  Timer mTimeoutTimer;
  bool mCreateAdmissionPublished{false};  // mStrand only
  bool mCreateFailureNotified{false};  // mStrand only
  enum class CreateCompletionState : uint8_t
  {
    Pending,
    Sending,
    Committed,
    Suppressed,
  };
  std::atomic<CreateCompletionState> mCreateCompletionState{CreateCompletionState::Pending};
  // Timestamp of the most recent client request on this session (strand-confined; touched by
  // request_received and consulted by timeout()). Drives the OPC 10000-4 5.6.2 inactivity reset:
  // the session is reaped only after mRevisedSessionTimeout elapses since this point.
  std::chrono::steady_clock::time_point mLastActivity{};
  std::vector<CertificateStore::ApplicationCertificate> mServerCertificates;

  // The server certificate selected for this session's endpoint (cached at CreateSession time).
  // Used for user token signature verification and password decryption at ActivateSession time.
  // On None channels this may differ from the channel's security policy certificate.
  CertificateStore::ApplicationCertificate mSelectedServerCertAndKey;

  // Current server nonce for this session (the nonce most recently sent to the client).
  // Used to decrypt/enforce UserIdentityToken contents in ActivateSession.
  ByteString mServerNonce;

  // The ClientNonce of the CreateSession request. Every channel bound session signature covers it (OPC
  // 10000-4 section 6.1.8 Table 101), the ClientSignature of each later ActivateSession included.
  ByteString mClientNonce;

  // The SecurityPolicy and SecurityMode of the SecureChannel the Session was created on, for when it has lost
  // its SecureChannel. A re-activation over a new SecureChannel must keep both (OPC 10000-4 5.7.3.1, decision
  // D-6), so they never change.
  SecurityPolicyId mChannelSecurityPolicyId{SecurityPolicyId::Invalid};
  MessageSecurityMode mChannelSecurityMode{MessageSecurityMode::Invalid};

  // ECC UserIdentityToken encryption state (Part 6, 6.8.3).
  // When the secure channel uses an ECC policy and the client provides ECDHPolicyUri in
  // CreateSession, the server generates a single-use ephemeral key pair for ECDH-based
  // user token encryption. The private key is consumed on ActivateSession; a fresh key
  // pair is returned in each ActivateSession response.
  SecurityPolicyId mEccUserTokenPolicyId{SecurityPolicyId::Invalid};
  ByteString mEccEphemeralPrivateKey;
  ByteString mEccEphemeralPublicKey;

  // Session state (was in SessionLogic). The strand-local session state tracks the
  // reducer-equivalent state machine. mState (atomic) is for cross-strand observation.
  State mSessionState{State::Created};
  bool mWaitingForAuthn{false};

  // Outstanding service request tracking by requestHandle (was in SessionLogic).
  std::unordered_set<uint32_t> mOutstandingRequestHandles;

  // Owned Browse continuation point ids, ordered by insertion time for oldest-first eviction
  // (was in SessionLogic).
  std::vector<std::string> mOwnedContinuationPointIds;

  // Diagnostic counters (heap-allocated, shared for safe handler capture).
  std::shared_ptr<SessionCounters> mCounters{std::make_shared<SessionCounters>()};

  // Per-session security state for SessionSecurityDiagnosticsDataType.
  std::shared_ptr<SessionSecurityState> mSecurityState{std::make_shared<SessionSecurityState>()};
  std::shared_ptr<SessionDescriptiveState> mDescriptiveState{std::make_shared<SessionDescriptiveState>()};

  // Per-session diagnostic object in address space (RAII: cleaned up on destruction).
  optional<SessionDiagnosticsHelper> mDiagnosticsHelper;
  // Whether the object should exist; reconcile_diagnostics_object() works towards it. mStrand only.
  bool mDiagnosticsWanted{false};
  // True while a creation or a removal of the object is in flight. One runs at a time, and its
  // completion reconciles again, so toggles in quick succession cannot leave two objects. mStrand only.
  bool mDiagnosticsChangeInFlight{false};
  // Released once the object matches mDiagnosticsWanted. mStrand only.
  std::vector<std::shared_ptr<void>> mDiagnosticsSettledWaiters;

  // Live-instance counter for leak diagnostics (RAII; zero-cost in release).
  [[no_unique_address]] ua::diagnostics::InstanceTracker<ua::diagnostics::ServerSessionTag> mInstanceTracker;

  // Map ServiceKind to the corresponding SessionCounters field.
  ServiceCounter& counter_for_service(ServiceKind kind);

  /// Counts a service-level error for a completed request whose response is a ServiceFault - a
  /// whole-request rejection (OPC 10000-4 5.3/7.35): increments the Service's errorCount and the
  /// aggregate totalRequests.errorCount. No-op for a non-fault response or an unknown requestId.
  /// Called from every service-completion path so per-service errorCount is correct regardless of
  /// which path (response_received / browse / history variants) delivered the response.
  void note_service_fault_error(uint32_t requestId, const std::shared_ptr<Structure>& responseMessage);

  // Request start times and service kinds for latency/error tracking (keyed by requestId).
  std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> mRequestStartTimes;
  std::unordered_map<uint32_t, ServiceKind> mRequestServiceKinds;

  ResponseSinkForTests mResponseSinkForTests;

  // Typed service-dispatch handler table.
  // Keyed by the request type's NodeId (Structure::type_id()). Populated once in
  // `register_service_handlers()` during construction and never mutated thereafter,
  // so cross-strand reads are race-free (effectively const-after-construction).
  using ServiceResponseResult = Result<std::shared_ptr<Structure>>;
  using ServiceHandler = std::function<void(uint32_t requestId, ServiceKind kind,
    std::shared_ptr<Structure> request, std::function<void(ServiceResponseResult)> cb)>;
  std::unordered_map<NodeId, ServiceHandler> mServiceHandlers;

  // Shell-only storage for in-flight requests and their effect results.
  // Logic stays pure and only uses `RequestContext` to correlate completions.
  std::unordered_map<uint32_t, shared_ptr<Structure>> mInFlightRequestsByRequestId;
  std::unordered_map<uint32_t, uint32_t> mRequestHandlesByRequestId;
  std::unordered_map<uint32_t, uint32_t> mReturnDiagnosticsByRequestId;
  std::unordered_map<uint32_t, optional<ua::server::UserIdentity>> mAuthnUserByRequestId;
  std::unordered_map<uint32_t, std::shared_ptr<const EndpointSecurityContext>> mAuthnEndpointByRequestId;
  std::function<void()> mAuthnUserInsertFailureInjectorForTests;

  // Certificate presented by the activation currently being authenticated, and the one the last
  // SUCCESSFUL activation used. Both null unless the token kind was X509. The second is what
  // reevaluate_certificates_async re-validates when the user-token trust list changes.
  shared_ptr<const X509Certificate> mActivatingUserTokenCertificate;
  shared_ptr<const X509Certificate> mUserTokenCertificate;
  // The certificateData field (leaf + presented issuers) and the user-token policy's SecurityPolicy the
  // certificate above was validated with; re-evaluation resubmits them through the same function.
  ByteString mActivatingUserTokenCertificateField;
  shared_ptr<const SecurityPolicy> mActivatingUserTokenPolicy;
  ByteString mUserTokenCertificateField;
  shared_ptr<const SecurityPolicy> mUserTokenPolicy;

  struct PostResponseActions
  {
    MethodResponseCorrelation correlation;
    bool reevaluateCertificates{false};
    bool closeSecureChannel{false};
  };

  uint64_t mSecureChannelAssociationEpoch{1};
  void (*mPostResponseActionInsertFailureInjectorForTests)() = nullptr;
  std::vector<PostResponseActions> mPostResponseActions;

  // Session owns its in-flight services strongly. Entries are inserted by the
  // per-service `*_request_received` methods and removed by the corresponding
  // `*_response_received` paths once the service has fired its response, or
  // dropped wholesale when the session itself is destroyed. The strong owner
  // is what keeps the service alive across its async chain - strand-posted
  // continuations inside the service may capture `weak_from_this()` because
  // this map holds the strong reference for the request's lifetime.
  //
  // Keyed by the server-assigned per-request id (unique per in-flight request),
  // NOT by the client-supplied RequestHandle. Part 4 does not require
  // RequestHandle to be unique across concurrent requests (a single Cancel may
  // target several in-flight requests sharing one handle), and clients are free
  // to reuse - or never set - the handle, so multiple concurrent requests can
  // carry the same handle (e.g. handle 0). Keying by handle let one request's
  // completion erase a *different* concurrent request's still-in-flight service,
  // destroying it mid-flow so its response was never sent (client BadTimeout).
  // requestId is the unique correlation key the session already assigns, so each
  // entry maps to exactly one in-flight request.
  using ServiceCallsByRequestId = std::unordered_map<IntegerId, shared_ptr<Service>>;
  ServiceCallsByRequestId mServiceCallsByRequestId;

  // Subscription manager - created lazily on the session strand (once; never reset) and otherwise
  // touched only on the strand. It is ALSO read off-strand by health_snapshot() (the gauges), so the
  // shared_ptr HANDLE is held in a std::atomic to avoid a data race between that read and the strand's
  // lazy create - exactly as the cross-strand-read mIdentity field is. The pointee's own counters are
  // already atomic. shared_ptr-managed so strand-posted continuations can keep it alive across hops.
  std::atomic<std::shared_ptr<SubscriptionsPipeline>> mSubscriptionsPipeline;

  using SetSubscriptionDurableChildCallbackForTests = std::function<void(StatusCode, uint32_t)>;
  using SetSubscriptionDurableOperationForTests = std::function<void(
    IntegerId, uint32_t, ServerConfig::SubscriptionLimits, SetSubscriptionDurableChildCallbackForTests)>;
  SetSubscriptionDurableOperationForTests mSetSubscriptionDurableOperationForTests;

  BrowseContinuationPoints mBrowseContinuationPoints;
  std::unordered_map<Guid, std::chrono::steady_clock::time_point> mBrowseContinuationPointExpiry;

  HistoryContinuationPoints mHistoryContinuationPoints;
  std::unordered_map<Guid, std::chrono::steady_clock::time_point> mHistoryContinuationPointExpiry;

  std::queue<Response> mResponseMessages;
  // Hard cap on responses buffered while the session has no attached channel. In normal operation the
  // queue is bounded by the per-session in-flight request cap; this is a memory backstop against a
  // detached session accumulating undeliverable responses without limit. Drop-oldest on overflow.
  size_t mMaxBufferedResponses{1000};

  // Buffers a response for later delivery (used only while no channel is attached), enforcing
  // mMaxBufferedResponses by dropping the oldest buffered response on overflow. Call on mStrand.
  void enqueue_response(Response response);

  // Test-only: inject already-decoded UA service requests directly (bypasses UA Binary decoding).
  // Intended for in-process unit tests of strand-based code.
  void inject_decoded_request_for_tests(uint32_t requestId, shared_ptr<Structure> request);

  // Test-only: pop a queued response when no secure-channel connection is attached.
  optional<Response> pop_queued_response_for_tests();

  // Test-only: register a response sink invoked for every response.
  void set_response_sink_for_tests(ResponseSinkForTests sink);

  Session(weak_ptr<SessionDependencies> dependencies, boost::asio::any_io_executor executor,
    SecureChannelInfo secureChannelInfo);

  void timeout();

  // Periodic inactivity-timer tick: reaps the session (via timeout()) only if no client request has
  // arrived within mRevisedSessionTimeout. Distinct from timeout(), which closes unconditionally and
  // is also used for forced shutdown.
  void on_inactivity_tick();

  void create_internal(
    uint32_t requestId, CreateSessionRequest createSessionRequest, CreateAdmission admission);
  void notify_create_session_failed(const CreateSessionRequest& request, StatusCode reason);

  void activate_internal(uint32_t requestId, ActivateSessionRequest&& activateSessionRequest,
    optional<SecureChannelInfo> secureChannelInfo);
  // `sameIdentityRequired`: the activation re-activates this Session over a different SecureChannel, so the
  // identity the authenticator derived must be the committed one (Part 4 5.6.3.1), checked before the
  // Session takes the new channel.
  void on_activate_authenticated(uint32_t requestId, AuthnResult authnResult, bool sameIdentityRequired);

  void close_internal(uint32_t requestId, CloseSessionRequest&& closeSessionRequest);

  void request_received(Request request);

  void error_received_from_secure_channel(StatusCode status, shared_ptr<const ErrorDetail> detail);
  void error_received_from_secure_channel_if_current(uint64_t associationEpoch,
    weak_ptr<SecureChannel> reportingChannel, StatusCode status, shared_ptr<const ErrorDetail> detail);
  void request_received_from_secure_channel_if_current(
    uint64_t associationEpoch, weak_ptr<SecureChannel> sourceChannel, Request request);

  /// Releases the per-request tracking maps for a request that will never receive a response (its Publish
  /// was discarded on channel loss, so it never reaches @ref response_received which normally reaps them).
  void release_request_tracking(uint32_t requestId);
  /// Part 4 5.6.3: once a new SecureChannel is accepted, requests via the old one are rejected. Releases the
  /// tracking of every request the old channel still had in flight (all but the activating request) and
  /// discards its pending Publish requests, as on channel loss. One pass over the in-flight map.
  void abandon_old_channel_requests(uint32_t activatingRequestId);

  void response_received(Response response);

  void browse_response_received(Response response, std::vector<BrowseContinuationPoint> continuationPoints);

  void history_read_request_received(uint32_t requestId, HistoryReadRequest&& request);

  void history_read_response_received(HistoryReadService::HistoryReadServiceResponse response);

  void history_update_request_received(uint32_t requestId, HistoryUpdateRequest&& request);

  void purge_expired_history_continuation_points();

  void read_request_received(uint32_t requestId, ReadRequest&& request);

  void write_request_received(uint32_t requestId, WriteRequest&& request);

  void browse_request_received(uint32_t requestId, BrowseRequest&& request);

  void browse_next_request_received(uint32_t requestId, BrowseNextRequest&& request);

  void call_request_received(uint32_t requestId, CallRequest&& request);

  void translate_browse_paths_request_received(
    uint32_t requestId, TranslateBrowsePathsToNodeIdsRequest&& request);

  void register_nodes_request_received(uint32_t requestId, RegisterNodesRequest&& request);

  void unregister_nodes_request_received(uint32_t requestId, UnregisterNodesRequest&& request);

  void subscription_request_received(uint32_t requestId, ServiceKind kind);

  void node_management_request_received(uint32_t requestId, ServiceKind kind);

  template<typename RequestType>
  void discovery_service_set_request_received(uint32_t requestId, RequestType&& request);

  /// @param echoRequestHandle The handle to echo for a request that was refused BEFORE it was recorded
  ///        (RequestIdInFlight): the recorded handle under that requestId belongs to another request.
  /// @param additionalHeader Placed in the fault's ResponseHeader.additionalHeader when set; only a
  ///        refused ActivateSession on an ECC Session carries one (its new EphemeralKey).
  void create_and_send_service_fault(uint32_t requestId, StatusCode statusCode,
    std::shared_ptr<const ErrorDetail> detail = nullptr, uint32_t returnDiagnostics = 0,
    optional<weak_ptr<SecureChannel>> responseChannel = std::nullopt,
    optional<uint32_t> echoRequestHandle = std::nullopt,
    std::unique_ptr<Structure> additionalHeader = nullptr);

  using SignatureDataResult = Result<SignatureData>;
  void create_server_signature_async(
    span<const byte> clientNonce, std::function<void(SignatureDataResult)> callback);

  /// Signs @p dataToSign with the server's key for @p policy and answers the CreateSession ServerSignature.
  void sign_server_signature_async(shared_ptr<SecurityPolicy> policy, ByteString dataToSign,
    std::function<void(SignatureDataResult)> callback);

  /// Builds the data a channel bound session signature covers (OPC 10000-4 section 6.1.8 Table 101) from this
  /// Session's certificates and nonces and @p channel's ChannelThumbprint and certificates. HASH is
  /// @p decidingPolicy's CertificateThumbprintAlgorithm. The callback runs on the Session strand.
  void build_channel_bound_data_async(ChannelBoundSignature signature, const SecurityPolicy& decidingPolicy,
    const SecureChannelInfo& channel, std::function<void(ByteStringResult)> callback);

  // ECC UserIdentityToken: generate a signed ephemeral key and store the private half.
  void generate_ecc_ephemeral_key_async(std::function<void(VoidResult)> callback);

  // Handles a service request through state gating, authz-context freshness, and dispatch.
  void handle_service_request(uint32_t requestId, ServiceKind kind, uint32_t requestHandle);

  // Continuation: receives the resolve result; on success, dispatches via execute_service.
  // Handles a Cancel request.
  void handle_cancel_request(uint32_t requestId, CancelRequest cancelRequest);

  // Common close-session logic (logging, subscriptions, timer, unregister, remove).
  // deleteSubscriptions=false (only from an explicit CloseSession that requests it) orphans this
  // session's subscriptions into the server-level store for later transfer (Part 4 5.7.4) instead
  // of deleting them. The inactivity-timeout path also orphans, per Part 4 5.6.2.1 ("If a Server
  // terminates a Session for any other reason, Subscriptions ... are not deleted"). Only an explicit
  // CloseSession(deleteSubscriptions=true) deletes.
  void close_session_internal(
    StatusCode reason, shared_ptr<const ErrorDetail> detail, bool deleteSubscriptions = true);

  void reevaluate_certificates_on_strand();
  void reevaluate_client_certificate_on_strand(SessionDependencies& dependencies);
  void reevaluate_user_identity_on_strand(shared_ptr<CertificateStore> userTokenCertificateStore);
  void invalidate_post_response_actions_on_strand(shared_ptr<SecureChannel> previousChannel = nullptr);
  void on_response_enqueued_on_strand(
    MethodResponseCorrelation correlation, weak_ptr<SecureChannel> secureChannel, VoidResult enqueueResult);

  // Part 4 5.6.3: a Service request other than CloseSession issued before ActivateSession shall
  // cause the Server to close the Session. Tears the session down so a later ActivateSession with
  // the same token is rejected (Bad_SessionIdInvalid).
  void close_due_to_premature_service_use();

  // Builds and sends CreateSessionResponse via a per-flow continuation chain.
  void send_create_session_response_async(uint32_t requestId, std::function<void(VoidResult)> callback);

  /// Builds the CreateSessionResponse: nonce and certificate, signature, ECC ephemeral key,
  /// endpoints, hostname check, send. One straight line - it has no loops and never has more than
  /// one answer outstanding.
  ua::async::Task<> run_create_response();

  /// Each returns false when it has already answered and the body must stop.
  ua::async::Task<bool> provision_ecc_ephemeral_key();
  ua::async::Task<bool> fetch_create_response_endpoints();
  ua::async::Task<bool> check_create_endpoint_hostname();

  void finish_create_response();
  void fail_create_response(StatusCode status, std::shared_ptr<const ErrorDetail> detail);

  /// Awaits one collaborator call of one of this Session's own bodies, back on its strand.
  ///
  /// The chain did this by hand at every step: `me.lock()` in the collaborator's callback, then
  /// `post_borrowing` onto `mStrand` before touching any session state. `post_borrowing` is what
  /// handles the gone-session case, and it drops the answer exactly as the hand-written
  /// `if (!lockedSelf) return;` did.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(mStrand,
      mLogger,
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          mStrand,
          mLogger,
          [completion = std::move(completion)](Session&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  void rollback_create_admission_on_strand();
  void terminate_for_eviction_on_strand();

  // Per-request state for the in-flight CreateSession response (single-instance per Session).
  struct CreateResponseState
  {
    uint32_t requestId{};
    std::shared_ptr<CreateSessionRequest> request;
    std::shared_ptr<CreateSessionResponse> response;
    std::optional<CertificateType> resolvedCertType;
    uint32_t nonceLength{0};
    bool endpointUrlMismatch{false};
    std::function<void(VoidResult)> callback;
  };

  std::unique_ptr<CreateResponseState> mCreateResponseState;
  /// The CreateSession response body. Lives on the Session, so it dies with it.
  ua::async::Task<> mCreateResponseTask;
  void (*mCreateResponseFailureInjectorForTests)() = nullptr;

  // Discards the buffered service responses (mResponseMessages) accumulated while the session had
  // no attached secure channel. Called on reconnect, once the session (re)attaches to a NEW
  // channel. The buffered responses carry requestIds scoped to the OLD channel (Part 6: requestId
  // is per-SecureChannel), so they are undeliverable on the new channel  -  the client drops any
  // response whose requestId it never issued there (Part 4 6.7). They are therefore discarded, not
  // replayed: the client recovers by re-issuing normal requests (already failed with
  // BadConnectionClosed on the drop) and via Republish for subscriptions (Part 4 5.13.5). Runs on
  // mStrand. Sends nothing, so no response sink or user callback is invoked.
  void discard_buffered_responses();

  // Builds and sends ActivateSessionResponse.
  void send_activate_session_response_async(uint32_t requestId, std::function<void(VoidResult)> callback);

  /// Builds the ActivateSessionResponse: server nonce, ECC ephemeral key and its signature, the
  /// identity commit, the mandatory MonitoredItem reauthorization when the identity changed, send.
  /// One straight line - it has no loops and never has more than one answer outstanding.
  ua::async::Task<> run_activate_response();

  /// What the identity commit decided. `Failed` means it has already answered and the body must
  /// stop; the chain this replaces expressed that by returning after calling `fail_*`.
  enum class ActivateCommitOutcome
  {
    Failed,
    IdentityUnchanged,
    IdentityChanged,
  };
  ActivateCommitOutcome commit_activate_identity();

  void complete_activate_response();
  void fail_changed_identity_activation(StatusCode status, std::shared_ptr<const ErrorDetail> detail);
  void fail_activate_response(StatusCode status, std::shared_ptr<const ErrorDetail> detail);

  // Per-request state for the in-flight ActivateSession response (single-instance per Session).
  // Mirrors `CreateResponseState` for consistency with the 4.7+4.8 SecureChannel pattern. Holding
  // it on the Session rather than in the body's frame is what lets `fail_activate_response` answer
  // from outside the body, and is what closes the narrow race that lambda-captured state would
  // otherwise leave open between `on_activate_authenticated` clearing `mWaitingForAuthn` and the
  // identity commit running.
  struct ActivateResponseState
  {
    uint32_t requestId{};
    std::shared_ptr<ActivateSessionResponse> response;
    uint32_t nonceLength{0};
    std::function<void(VoidResult)> callback;
  };

  std::unique_ptr<ActivateResponseState> mActivateResponseState;
  /// The ActivateSession response body. Lives on the Session, so it dies with it.
  ua::async::Task<> mActivateResponseTask;

  /// Answers an ActivateSession refused after authentication with a ServiceFault, and releases the
  /// single-flight claim (`mWaitingForAuthn`) as it does. On a Session whose user-token policy is ECC
  /// the fault is sent by @ref run_refused_activate_fault, carrying a new EphemeralKey (Part 6 6.8.3).
  void refuse_activation(uint32_t requestId, StatusCode status, shared_ptr<const ErrorDetail> detail);

  /// Generates a new ECC ephemeral pair (replacing the stored one), signs its public key with
  /// `signingKeys` under `securityPolicy`'s asymmetric signature algorithm, and wraps it as the
  /// EphemeralKeyType of an AdditionalParametersType "ECDHKey" (Part 4 7.29 / Part 6 6.8.3). Shared by
  /// the CreateSession response, the ActivateSession response and the refused-activation fault; the
  /// caller confirms the signing inputs first and handles a failure (the refusal restores the previous
  /// pair). A generation failure is returned as the step's own status; a signing failure is wrapped in
  /// an `EphemeralKeySigningFailed` detail carrying `signingFailureMessage`, or returned unwrapped when
  /// the message is empty. Withdrawal (`ua::async::Abandoned`) propagates.
  ua::async::Task<Result<std::unique_ptr<Structure>>> issue_signed_ecdh_key(shared_ptr<const Crypto> crypto,
    shared_ptr<const SecurityPolicy> securityPolicy, shared_ptr<const AsymmetricKeyPair> signingKeys,
    std::string_view signingFailureMessage);

  /// Generates and signs a new ECC EphemeralKey, replaces the stored one with it, and sends the refusal
  /// fault with the key in its ResponseHeader.additionalHeader. A key that cannot be issued is logged
  /// and the fault goes without it, carrying the same status.
  ua::async::Task<> run_refused_activate_fault(
    uint32_t requestId, StatusCode status, shared_ptr<const ErrorDetail> detail);

  /// The refused-ActivateSession fault body. Lives on the Session, so it dies with it.
  ua::async::Task<> mRefusedActivateFaultTask;

  // Internal: sends a service fault with error tracking and cleanup.
  void send_service_fault(uint32_t requestId, StatusCode status,
    shared_ptr<const ErrorDetail> detail = nullptr, std::unique_ptr<Structure> additionalHeader = nullptr);

  // Internal: dispatches a classified service request to the typed handler.
  void execute_service(uint32_t requestId, ServiceKind kind);

  // Populates `mServiceHandlers` with one entry per dispatched ServiceKind. Called
  // once from the constructor. Handler closures capture `[this]` - safe because the
  // map is a member of `Session` and its entries cannot outlive `this`.
  void register_service_handlers();

  // ParsedIdentityToken is the per-token product of identity-token parsing; consumed by the
  // user-token-signature verification step and the authenticator hop.
  struct ParsedIdentityToken
  {
    ua::server::AuthnRequest request;
    std::optional<AuthnResult> failure;
    // The security_policy_uri from the matched UserTokenPolicy (may be empty if inheriting channel).
    std::string tokenSecurityPolicyUri;
    // X509 only: the token's certificateData field as received (leaf + presented issuers).
    ByteString x509CertificateField;
  };

  using ParsedIdentityTokenResult = Result<ParsedIdentityToken>;
  using OptionalAuthnFailure = std::optional<AuthnResult>;

  struct TimedAuthnResult
  {
    std::chrono::steady_clock::time_point completedAt;
    AuthnResult result;
  };

  struct AuthFlowIdentity
  {
    bool record_completion(
      AuthnResult result, std::chrono::steady_clock::time_point completedAt) const noexcept;
    std::optional<TimedAuthnResult> take_completion() const noexcept;

  private:
    mutable std::mutex mMutex;
    mutable std::optional<TimedAuthnResult> mCompletion;
    mutable bool mCompletionRecorded{false};
  };

  // Effect helpers for authentication, authorization, and cancel.
  // Authentication runs through a per-step continuation chain managed by AuthState.
  void authenticate_async(uint32_t requestId, uint32_t requestHandle, const SecureChannelInfo& channelInfo,
    std::function<void(AuthnResult)> callback);
  // Continuations for the auth pipeline.
  void on_client_application_signature_verified(OptionalAuthnFailure failure);
  void on_identity_token_parsed(ParsedIdentityTokenResult parsedResult);
  void begin_user_token_signature_verification();
  void begin_user_token_certificate_validation();
  void on_user_token_signature_verified(OptionalAuthnFailure failure);
  void on_user_token_certificate_validated(VoidResult validation);
  void start_authenticator();
  void on_authenticator_completed(AuthnResult result);
  void on_authenticator_completion_available(const std::shared_ptr<const AuthFlowIdentity>& identity);
  /// Holds every authentication outcome behind the host-configured deadline (constant-time authn).
  /// Nothing in this body answers before its await. @see run_authentication in the .cpp
  ua::async::Task<> run_authentication(
    std::shared_ptr<const AuthFlowIdentity> identity, std::chrono::milliseconds authenticationInterval);
  void finish_authentication(AuthnResult result);
  static bool authentication_completed_by(std::chrono::steady_clock::time_point completedAt,
    std::chrono::steady_clock::time_point deadline) noexcept;

  uint32_t cancel_outstanding_ops_effect(uint32_t targetRequestHandle);
  /// Aborts every service call the Session still owns with @p reason (OPC 10000-4 5.6.2.1: "When a Session is
  /// terminated, all outstanding requests on the Session are aborted and Bad_SessionClosed StatusCodes are
  /// returned to the Client"). On the strand.
  void abort_outstanding_ops(StatusCode reason);

  // Per-flow state for the in-flight authentication pipeline (single-instance per Session).
  /// The in-flight reservation an admitted authentication attempt holds (SESS-2). Committed with the
  /// attempt's outcome by finish_authentication; destroyed uncommitted (session closed during
  /// authentication, setup exception, dependencies gone, outcome not recorded) it releases the slot as
  /// Abandoned, so no path can leak a reservation.
  class IdentityAttemptReservation
  {
  public:
    IdentityAttemptReservation() = default;

    IdentityAttemptReservation(
      std::weak_ptr<SessionDependencies> dependencies, ClientId client, std::string claimedUserId)
      : mDependencies(std::move(dependencies)), mClient(std::move(client)),
        mClaimedUserId(std::move(claimedUserId)), mHeld(true)
    {}

    IdentityAttemptReservation(const IdentityAttemptReservation&) = delete;
    IdentityAttemptReservation& operator=(const IdentityAttemptReservation&) = delete;

    IdentityAttemptReservation(IdentityAttemptReservation&& other) noexcept
    {
      *this = std::move(other);
    }

    IdentityAttemptReservation& operator=(IdentityAttemptReservation&& other) noexcept
    {
      if (this != &other)
      {
        abandon();
        mDependencies = std::move(other.mDependencies);
        mClient = std::move(other.mClient);
        mClaimedUserId = std::move(other.mClaimedUserId);
        mHeld = std::exchange(other.mHeld, false);
      }
      return *this;
    }

    ~IdentityAttemptReservation()
    {
      abandon();
    }

    /// Releases the reservation with the attempt's outcome. May throw what the dependencies throw.
    void commit(SessionDependencies::IdentityAttemptOutcome outcome)
    {
      if (!mHeld)
      {
        return;
      }
      mHeld = false;
      if (auto dependencies = mDependencies.lock())
      {
        dependencies->finish_identity_attempt(*mClient, mClaimedUserId, outcome);
      }
    }

  private:
    void abandon() noexcept
    {
      try
      {
        commit(SessionDependencies::IdentityAttemptOutcome::Abandoned);
      }
      catch (...)
      {
        ::ua::detail::ignore_expected_exception();
      }
    }

    std::weak_ptr<SessionDependencies> mDependencies;
    std::optional<ClientId> mClient;
    std::string mClaimedUserId;
    bool mHeld{false};
  };

  struct AuthState
  {
    std::shared_ptr<const AuthFlowIdentity> identity;
    uint32_t requestId{};
    uint32_t requestHandle{};
    std::optional<SecureChannelInfo> channelInfo;
    std::optional<ClientId> clientId;
    std::string claimedUserId;
    bool throttleApplicable{false};
    bool recordOutcome{false};
    IdentityAttemptReservation reservation;
    const UserTokenPolicy* matchedPolicy{nullptr};
    std::shared_ptr<const EndpointSecurityContext> endpointSecurity;
    ParsedIdentityToken parsed;
    std::function<void(AuthnResult)> callback;
    std::chrono::steady_clock::time_point deadline;
    std::optional<AuthnResult> pendingResult;
    Timer completionTimer;
  };

  std::unique_ptr<AuthState> mAuthState;
  /// The authentication deadline body. Lives on the session, so it dies with it.
  ua::async::Task<> mAuthTask;

  using AuthStageContinuationForTests = std::function<void(Session&)>;
  using AuthStageCompletionGateForTests = std::function<void(Session&, AuthStageContinuationForTests)>;
  AuthStageCompletionGateForTests mParsedIdentityCompletionGateForTests;
  AuthStageCompletionGateForTests mUserTokenSignatureCompletionGateForTests;
  AuthStageCompletionGateForTests mAuthenticatorCompletionNotificationGateForTests;

  void parse_identity_token_async(uint32_t requestHandle, ActivateSessionRequest& asr,
    std::function<void(ParsedIdentityTokenResult)> callback);

  // Resolve the SecurityPolicy governing user-token decryption. The client-supplied
  // UserNameIdentityToken.encryptionAlgorithm names the asymmetric algorithm (Part 4 7.41), not
  // the policy, so the decryption parameters are taken from the negotiated user-token policy
  // (falling back to the secure channel policy, then to interpreting the client string as a policy
  // URI for legacy SDK clients). May throw UaException on an unresolvable policy.
  shared_ptr<SecurityPolicy> resolve_user_token_decryption_policy(
    std::string_view clientEncryptionAlgorithm) const;

  /// Decrypt the Part 4 7.41.6 EncryptedSecret carried by IssuedIdentityToken.tokenData. The
  /// negotiated UserTokenPolicy selects RSA/ECC; the outer encryptionAlgorithm is deliberately
  /// empty for this wire shape. Completion is exactly once and safe across Session destruction.
  void decrypt_issued_token_async(ByteString tokenData, std::function<void(ByteStringResult)> callback);

  void verify_user_token_signature_async(ActivateSessionRequest& asr, const ParsedIdentityToken& parsed,
    const SecureChannelInfo& channelInfo, std::function<void(OptionalAuthnFailure)> callback);

  /// Verifies the X509 UserTokenSignature @p signature over @p dataToVerify, the data @p tokenPolicy
  /// prescribes, with @p userCertificate.
  void verify_user_token_signature_over_async(shared_ptr<SecurityPolicy> tokenPolicy,
    shared_ptr<const X509Certificate> userCertificate, ByteString dataToVerify, ByteString signature,
    std::function<void(OptionalAuthnFailure)> callback);

  void verify_client_application_signature_async(ActivateSessionRequest& asr,
    const SecureChannelInfo& channelInfo, std::function<void(OptionalAuthnFailure)> callback);

  /// Verifies the ClientSignature @p signature over @p dataToVerify, the data @p policy prescribes, with the
  /// client certificate of CreateSession.
  void verify_client_application_signature_over_async(shared_ptr<SecurityPolicy> policy,
    ByteString dataToVerify, ByteString signature, std::function<void(OptionalAuthnFailure)> callback);

  StatusCode handle_unexpected_exception(const char* site, std::exception_ptr ex);

  // Per-session diagnostics object (run on strand). want_diagnostics_object() records whether the object
  // should exist and reconciles; reconcile_diagnostics_object() starts the next creation or removal, or,
  // with the object as wanted, releases the waiters. destroy_diagnostics_object() is for teardown: it
  // drops the object without waiting for its removal.
  void want_diagnostics_object(bool wanted, std::shared_ptr<void> settled = {});
  void reconcile_diagnostics_object();
  bool start_diagnostics_object_creation();
  void start_diagnostics_object_removal();
  void release_diagnostics_waiters();
  void destroy_diagnostics_object();

  /// Removes the Session's diagnostics subtree and invokes @p then on the Session strand once it is gone
  /// (also when there is none, or the removal fails). Must run on the Session strand.
  void remove_diagnostics_object_async(std::function<void()> then);
};

}  // namespace ua::server

#endif  // !UA_SERVER_SESSION_H
