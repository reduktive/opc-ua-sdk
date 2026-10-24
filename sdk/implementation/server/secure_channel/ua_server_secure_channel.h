// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_SECURE_CHANNEL_H
#define UA_SERVER_SECURE_CHANNEL_H

#include <atomic>
#include "ua_instance_tracker.h"
#include <chrono>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <boost/asio/strand.hpp>
#include "ua_await_callback.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_address_space.h"
#include "ua_service_fault.h"
#include "ua_timer.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_close_secure_channel_request.h"
#include "ua_close_secure_channel_response.h"
#include "ua_connection_protocol_limits.h"
#include "ua_get_endpoints_request.h"
#include "ua_memory_stream.h"
#include "ua_binary_codec.h"
#include "ua_certificate_store.h"
#include "ua_endpoint_description.h"
#include "ua_secure_channel_context.h"
#include "ua_application_configuration.h"
#include "ua_server_configuration.h"
#include "ua_create_session_request.h"
#include "ua_server_endpoint_configuration.h"
#include "../services/ua_discovery_service_set.h"

#include "ua_logger.h"
#include "ua_security_policy.h"
#include "ua_server.h"
#include "ua_server_observer.h"

namespace ua
{
class ActivateSessionRequest;
class ConnectionProtocol;
class TransportConnection;
class SecurityPolicy;

namespace server
{

// Test-only access to SecureChannel internals.
//
// This is intentionally declared in the implementation header (not the public interface), and SecureChannel
// does not expose any test hooks as public methods.
class SecureChannelTestAccess;
class SecureChannelInfo;
}  // namespace server

namespace asio = boost::asio;

namespace server
{

class ServerImpl;
class SecureChannel;
struct SecureChannelCounters;
struct ServerSummaryCounters;

class SecureChannelDependencies
{
public:
  SecureChannelDependencies() = default;
  SecureChannelDependencies(const SecureChannelDependencies&) = delete;
  SecureChannelDependencies& operator=(const SecureChannelDependencies&) = delete;
  SecureChannelDependencies(SecureChannelDependencies&&) = delete;
  SecureChannelDependencies& operator=(SecureChannelDependencies&&) = delete;
  virtual ~SecureChannelDependencies() = default;
  virtual weak_ptr<DiscoveryDependencies> discovery_dependencies() = 0;
  virtual boost::asio::any_io_executor executor() = 0;
  virtual shared_ptr<const Crypto> crypto() = 0;
  virtual WeakAddressSpace address_space() = 0;
  virtual const ::ua::ApplicationConfig& configuration() = 0;
  virtual const ::ua::server::ServerConfig& server_configuration() = 0;
  virtual shared_ptr<CertificateStore> default_application_group_certificate_store() = 0;
  virtual uint32_t get_next_secure_channel_id() = 0;
  virtual void create_session(
    SecureChannelInfo secureChannelInfo, uint32_t requestId, CreateSessionRequest&& request) = 0;
  virtual StructureFactory& structure_factory() = 0;
  virtual std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle listener) = 0;
  virtual std::shared_ptr<ServerObserver> observer() = 0;
  virtual Logger logger() = 0;

  // Diagnostics accessors. These are an OPTIONAL capability with a safe default (null = "no
  // diagnostics"): the real server dependency overrides them, and the many lightweight test doubles
  // inherit the null default rather than each having to stub them.
  //
  // secure_channel_counters(): server-wide secure-channel counters, for counting a refused
  // OpenSecureChannel (rejectedSecureChannelCount). The real impl returns null when ServerDiagnostics
  // is disabled, so the reject path stays inert then.
  virtual std::shared_ptr<SecureChannelCounters> secure_channel_counters()
  {
    return nullptr;
  }

  // summary_counters() + diagnostics_enabled(): used at send_response_message to count a rejected
  // request (rejectedRequestsCount) whenever a ServiceFault is delivered - per OPC 10000-4 5.3/7.35 a
  // ServiceFault is exactly a whole-request service-level rejection, so that is the single
  // request-level reject point. These are NOT gated (matching the SessionDependencies accessors of
  // the same name); the caller checks diagnostics_enabled().
  virtual std::shared_ptr<ServerSummaryCounters> summary_counters()
  {
    return nullptr;
  }

  virtual std::shared_ptr<std::atomic<bool>> diagnostics_enabled()
  {
    return nullptr;
  }

  virtual void remove_secure_channel(const shared_ptr<SecureChannel>& channel) = 0;

  // Cross-channel ActivateSession: route an ActivateSessionRequest that arrived on a channel
  // that does not own the target session. ServerImpl looks up the session by token and calls
  // session->activate() with the new SecureChannelInfo.
  // Default: no-op (test doubles that don't test cross-channel activation can ignore this).
  virtual void activate_session_on_channel(
    SecureChannelInfo newChannelInfo, uint32_t requestId, ActivateSessionRequest&& request);

  // S12: Server-wide in-flight discovery request counter for load-aware throttling.
  virtual std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() = 0;

  // Server-wide in-flight (non-Publish) service-request counter, used by the channel to enforce the
  // `ServerConfig::maxInFlightRequests` admission cap. Default returns nullptr (no server-wide
  // cap) so test doubles that do not exercise the cap need not override it.
  virtual std::shared_ptr<std::atomic<uint32_t>> in_flight_requests();
};

class SecureChannel : public std::enable_shared_from_this<SecureChannel>
{
public:
  using SendRequestMessageToSession = std::function<void(Request)>;
  using ReportErrorToSession = std::function<void(StatusCode, shared_ptr<const ErrorDetail>)>;

  SecureChannel() = delete;
  SecureChannel(const SecureChannel&) = delete;
  SecureChannel(SecureChannel&& other) noexcept = delete;
  SecureChannel& operator=(const SecureChannel& other) = delete;
  SecureChannel& operator=(SecureChannel&& other) noexcept = delete;
  ~SecureChannel();

  weak_ptr<SecureChannelDependencies> handler();

  void send_response_message(Response response);

  /// Rare response-boundary variant used by ApplyChanges ordering. The callback is invoked on the
  /// SecureChannel strand only after the response has crossed the outgoing sink/queue boundary, or
  /// with a rich failure if the channel disappears first. Ordinary responses use the overload above.
  ///
  /// What the channel does once a correlated response has been encoded and its chunks handed to the
  /// transport (OPC 10000-12 7.10.6: the ApplyChanges caller receives the response before the channel
  /// the change affects is closed or re-evaluated).
  enum class AfterResponse
  {
    Nothing,
    /// Close the channel; responses queued behind it are not sent.
    CloseChannel,
    /// Re-evaluate the client certificate (reevaluate_certificate_async).
    ReevaluateCertificate,
  };

  void send_response_message(Response response, std::function<void(VoidResult)> enqueuedCallback,
    AfterResponse afterResponse = AfterResponse::Nothing);

  /// Validates the client certificate this channel was opened with (and the issuers presented with it)
  /// again, under the channel's SecurityPolicy, against the DefaultApplicationGroup as it is now. On
  /// failure the refusal is reported (on_certificate_rejected; the store files the certificate as
  /// rejected), the channel's Sessions are told, an Error message is sent and the connection closes
  /// after its pending writes (OPC 10000-12 7.8.2.3, 7.10.6: SecureChannels affected by a TrustList
  /// change renegotiate, and a client no longer trusted cannot). Posts to the channel strand; a no-op
  /// without a client certificate or once the channel is closing. Cost: one validation per call.
  void reevaluate_certificate_async();

  /// Register a session's callbacks for token-based request dispatch.
  /// Must be called from any thread - internally strand-posted.
  void register_session(
    NodeId authenticationToken, SendRequestMessageToSession sendRequest, ReportErrorToSession reportError);

  /// Unregister a session's callbacks. Subsequent requests for this token will
  /// receive a BadSessionIdInvalid ServiceFault. boost::asio::strand<boost::asio::any_io_executor>-posted.
  void unregister_session(const NodeId& authenticationToken);

  /// Record that a session previously registered on this channel was transferred to another channel
  /// (Part 4 5.6.3). A request arriving here for such a token is rejected with
  /// Bad_SecureChannelIdInvalid (the channel "knew" the session but it moved), distinct from a token
  /// this channel never hosted (Bad_SessionIdInvalid). strand-posted.
  void mark_session_transferred_away(const NodeId& authenticationToken);

  /// Returns the number of sessions currently registered on this channel.
  /// Thread-safe: backed by an atomic counter updated alongside mSessionCallbacks.
  uint32_t session_count() const
  {
    return mSessionCount.load(std::memory_order_relaxed);
  }

  /// Identity of the transport connection this channel was created on (null in tests that create a
  /// channel without one). Only compared, never dereferenced: it keys the per-IP admission slot the
  /// connection reserved at accept, which ServerImpl releases when the channel is removed.
  const TransportConnection* transport_identity() const noexcept;

  /// Returns when this channel was last used by its peer: the accepted OpenSecureChannel (issue or
  /// renew) and every service request the open channel accepts stamp it; a channel whose OPN has not
  /// been accepted (still being validated, refused, or never sent) reports the clock's minimum.
  ///
  /// Thread-safe: the channel strand updates an atomic steady-clock tick count and ServerImpl reads
  /// it while choosing a session-less channel to reclaim at the configured channel ceiling, so the
  /// never-opened channels (HEL/ACK only) go first, then the opened-but-idle ones by OPN time.
  std::chrono::steady_clock::time_point last_used_time() const noexcept
  {
    using Clock = std::chrono::steady_clock;
    return Clock::time_point{Clock::duration{mLastUsedTicks.load(std::memory_order_relaxed)}};
  }

  static shared_ptr<SecureChannel> create(weak_ptr<SecureChannelDependencies> handler,
    shared_ptr<ConnectionProtocol> connectionProtocol,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits, ::ua::server::ListenerHandle listener,
    std::string listenerName, std::string remoteAddress = {},
    std::optional<std::string> reverseTargetName = std::nullopt);

  /// Orderly close: close the transport connection and mark as closed.
  /// Called by ServerImpl during shutdown to ensure connections are closed before
  /// dropping shared_ptr references (strand-posted lambdas may hold additional refs).
  void close();

private:
  friend class SecureChannelTestAccess;

  // Test-only: inject already-decoded UA service requests directly (bypasses UA Binary decoding).
  // Intended for in-process unit tests of strand-based code.
  // The authenticationToken parameter is used for token-based session dispatch;
  // callers that don't need session routing can omit it (defaults to null NodeId).
  void inject_decoded_request_for_tests(
    uint32_t requestId, shared_ptr<Structure> request, NodeId authenticationToken = {});

  // Test-only: pop a queued response when no wire connection is attached.
  optional<Response> pop_queued_response_for_tests();

  // Test-only: register a response sink invoked for every response.
  // Called on the secure-channel strand.
  using ResponseSinkForTests = std::function<void(const Response&)>;
  void set_response_sink_for_tests(ResponseSinkForTests sink);

  // Test/fuzz hooks - installed via SecureChannelTestAccess, never exposed publicly.
  // RequestObserver: fires at top of handle_decoded_request with the decoded request.
  // ResponseInterceptor: fires in send_response_message_internal with a mutable Response
  //   (before signing/encryption), allowing tests to corrupt content for negative testing.
  // ValidationFailureObserver: fires at entry of send_service_fault_with_hooks with the
  //   rich pre-wire StatusCode. Lets tests observe ErrorDetail at the SDK boundary
  //   before wire encoding strips it from ResponseHeader / DiagnosticInfo.
  using RequestObserver = std::function<void(uint32_t requestId, const Structure& request)>;
  using ResponseInterceptor = std::function<void(Response& response)>;
  using ValidationFailureObserver = std::function<void(StatusCode status)>;

  // Wire-boundary observers, for measuring the server from ingest to egress.
  //
  // A benchmark that hands the service a decoded request and takes back a response object measures
  // neither decode nor encode, and cannot honestly be called a server measurement. These two fire at
  // the points where bytes actually cross: an inbound message chunk arriving from the transport, and
  // an outbound chunk being handed back to it. Both are on the per-MESSAGE path, not the
  // per-operation one, so a Read carrying a thousand operations pays for them once.
  //
  // Ingest carries no request id - the chunk has not been decoded yet, and that is the point. A
  // caller pairing the two must either drive one request at a time or correlate by other means.
  using ChunkIngestObserver = std::function<void(std::chrono::steady_clock::time_point at)>;
  using ChunkEgressObserver =
    std::function<void(uint32_t requestId, std::chrono::steady_clock::time_point at)>;

  void set_chunk_ingest_observer(ChunkIngestObserver observer);
  void set_chunk_egress_observer(ChunkEgressObserver observer);

  void set_request_observer(RequestObserver observer);
  void set_response_interceptor(ResponseInterceptor interceptor);
  void set_validation_failure_observer(ValidationFailureObserver observer);
  const weak_ptr<SecureChannelDependencies> mHandler;
  const ::ua::server::ListenerHandle mListenerHandle;
  const std::string mListenerName;
  /// Configured reverse-connect target name when this channel arrived over an outbound
  /// (server-initiated) connection; empty for an ordinary inbound one. It is what lets the
  /// shared open/close paths raise the reverse-connect observer hooks for the right target.
  const std::optional<std::string> mReverseTargetName;
  const std::string mRemoteAddress;
  bool mRemovedFromServer{false};
  bool mTerminalFailureCommitted{false};
  StatusCode mCloseReason{Status::BadShutdown};
  ConnectionCloseReason mConnectionCloseReason{ConnectionCloseReason::ServerShutdown};
  std::string mEndpointPolicyId;
  std::string mEndpointUrl;
  std::string mTransportProfileUri;
  std::vector<UserTokenPolicy> mUserIdentityTokens;
  shared_ptr<ConnectionProtocol> mConnection;
  Timer mTimeoutTimer;
  boost::asio::any_io_executor mExecutor;

  struct SessionCallbacks
  {
    SendRequestMessageToSession sendRequest;
    ReportErrorToSession reportError;
  };

  ChunkIngestObserver mChunkIngestObserver;
  ChunkEgressObserver mChunkEgressObserver;

  std::unordered_map<NodeId, SessionCallbacks> mSessionCallbacks;
  std::atomic<uint32_t> mSessionCount{0};
  // The clock's minimum until the OPN is accepted (see last_used_time).
  std::atomic<std::chrono::steady_clock::rep> mLastUsedTicks{
    std::chrono::steady_clock::duration::min().count()};
  // The HEL negotiated buffers below the 8192-byte minimum the RSA policies need (Part 6 7.1.2.3):
  // only an ECC policy or None may be opened on this connection. Snapshot of the connection's flag
  // at construction (the HEL precedes the channel).
  const bool mEccOnlyTransport;

  // Tokens of sessions that were registered here and then transferred to another channel. Accessed
  // only on mContext->mStrand. Lets handle_forward_to_session return Bad_SecureChannelIdInvalid for a
  // transferred-away session vs Bad_SessionIdInvalid for a token this channel never hosted.
  std::unordered_set<NodeId> mTransferredAwayTokens;

  shared_ptr<SecureChannelContext> mContext;

  ResponseSinkForTests mResponseSinkForTests;
  void (*mCorrelatedResponseEnqueueFailureInjectorForTests)() = nullptr;
  RequestObserver mRequestObserver;
  ResponseInterceptor mResponseInterceptor;
  ValidationFailureObserver mValidationFailureObserver;
  std::unordered_multimap<Guid, shared_ptr<void>> mDiscoveryCalls;
  std::queue<std::vector<byte>> mIncomingMessageChunks;
  // Whether the chunk being decoded is an OPN chunk (its MessageType bytes), read before the policy
  // decodes it, so the decoded request can be held to its chunk type: an OpenSecureChannelRequest is
  // accepted from an OPN chunk only and an OPN chunk carries nothing else (Part 6 6.7.2). Strand-only.
  bool mDecodingOpnChunk{false};
  std::queue<Response> mOutgoingMessages;
  bool mIncomingDrainScheduled{false};
  bool mOutgoingDrainScheduled{false};
  /// The response after which the channel closes (send_response_message's closeChannelAfterResponse);
  /// strand-owned.
  std::optional<uint32_t> mCloseAfterResponseRequestId;
  /// The response after which the client certificate is re-evaluated (AfterResponse::ReevaluateCertificate);
  /// strand-owned.
  std::optional<uint32_t> mReevaluateAfterResponseRequestId;
  /// Set once that response has been handed to the connection and the close ordered: nothing more is
  /// encoded or sent on this channel. Strand-owned.
  bool mClosingAfterResponse{false};

  // Incoming-chunk backpressure. mIncomingChunkQueueDepthCap is snapshotted from
  // ServerConfig::resourceLimits.incomingChunkQueueDepth at construction (>= 1, validated).
  // When mIncomingMessageChunks reaches the cap the channel read-pauses the transport (no chunk is
  // dropped); it resumes once the queue drains below half the cap. mReadPaused (strand-owned) tracks
  // whether this channel currently holds the transport in a read-paused state.
  uint32_t mIncomingChunkQueueDepthCap{1};
  bool mReadPaused{false};

  // In-flight request admission caps (maxInFlightRequests). All snapshotted in the constructor from
  // ServerConfig. A request is "counted" from when it is forwarded to a session
  // (handle_forward_to_session, non-Publish) until its response is sent
  // (send_response_message_internal). Over either cap -> Bad_ServerTooBusy.
  //   - mInFlightCountedRequestIds: the counted requestIds on this channel (strand-owned). Its size
  //     is the per-connection in-flight count; matching it on response send drives the decrement.
  //   - mMaxInFlightRequestsPerConnection: per-connection cap (0 = unbounded).
  //   - mServerWideInFlightRequests: shared server-wide counter (null = no server-wide cap).
  //   - mServerWideInFlightRequestCap: server-wide cap (0 = unbounded).
  std::unordered_set<uint32_t> mInFlightCountedRequestIds;
  uint32_t mMaxInFlightRequestsPerConnection{0};
  std::shared_ptr<std::atomic<uint32_t>> mServerWideInFlightRequests;
  uint32_t mServerWideInFlightRequestCap{0};

  // Per-flow state for an in-flight OpenChannel / RenewToken (single-instance).
  // Holds cross-callback locals that previously survived `await` boundaries in
  // handle_open_secure_channel. Allocated on entry to handle_open_secure_channel_async,
  // reset by complete_open / fail_open. A second OPN while mOpenState is non-null is
  // rejected with BadInvalidState.
  struct OpenChannelState
  {
    uint32_t requestId{0};
    OpenSecureChannelRequest request;
    bool isRenew{false};
    uint32_t returnDiag{0};
    bool isAuthenticated{false};
    uint32_t nonceLength{0};
    uint32_t tokenId{0};
    std::chrono::milliseconds revisedLifetime{0};
    ByteString serverNonce;
  };

  std::unique_ptr<OpenChannelState> mOpenState;
  /// The OpenSecureChannel body. Lives on the channel, so it dies with it.
  ua::async::Task<> mOpenChannelTask;

  enum class ChannelState
  {
    Closed,
    Open
  };
  ChannelState mChannelState{ChannelState::Closed};
  bool mDiscoveryOnly{false};

  struct TokenSummary
  {
    uint32_t tokenId{};
    std::chrono::milliseconds revisedLifetime{0};
  };

  std::optional<TokenSummary> mActiveTokenSummary;
  std::optional<TokenSummary> mPendingTokenSummary;
  ByteString mLastClientNonce;
  uint32_t mNextTokenId{1};

  // OpenChannelState kick-off + continuations. Sync rejection paths complete inline before
  // allocating mOpenState; allocation gates the per-OPN single-flight invariant.
  void handle_open_secure_channel_async(uint32_t requestId, OpenSecureChannelRequest request);
  void on_entropy_received(ByteStringResult result);
  /// Builds the new security token: the server nonce (an ECC ephemeral public key where the policy
  /// wants one), then the token itself. The chain wrote the token-creation block out three times, once
  /// per way of arriving at it.
  ua::async::Task<> run_open_channel(uint32_t nonceLength);

  /// This channel's strand and logger, for the header-inline @ref await_step. Defined in the .cpp,
  /// where the one `channel_strand` guard and the handler-derived logger already live.
  boost::asio::strand<boost::asio::any_io_executor>& open_channel_strand();
  Logger open_channel_logger() const;

  /// Awaits one collaborator call of this channel's own body, back on its strand.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(open_channel_strand(),
      open_channel_logger(),
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          open_channel_strand(),
          open_channel_logger(),
          [completion = std::move(completion)](SecureChannel&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  void complete_open();
  void fail_open(StatusCode status, bool isOpnFailure, bool isRenewFailure, uint32_t returnDiagnostics);

  void handle_close_secure_channel(uint32_t requestId, CloseSecureChannelRequest request);
  void handle_get_endpoints(uint32_t requestId, GetEndpointsRequest request);
  void handle_find_servers(uint32_t requestId, FindServersRequest request);
  void handle_find_servers_on_network(uint32_t requestId, FindServersOnNetworkRequest request);
  void handle_register_server(uint32_t requestId, RegisterServerRequest request);
  void handle_register_server2(uint32_t requestId, RegisterServer2Request request);
  void handle_create_session(uint32_t requestId, CreateSessionRequest request);
  void handle_forward_to_session(uint32_t requestId, std::shared_ptr<Structure> request,
    NodeId authenticationToken, uint32_t requestHandle = 0);
  /// Brings the token summaries in line with the context after a policy-side promotion.
  void sync_token_summaries_with_context();

  void handle_token_expired(uint32_t tokenId);

  std::chrono::milliseconds clamp_channel_lifetime(std::chrono::milliseconds requested) const;
  bool select_security_mode(MessageSecurityMode requestedMode);
  void send_service_fault_with_hooks(uint32_t requestId, StatusCode status, bool isOpnFailure = false,
    bool isRenewFailure = false, uint32_t returnDiagnostics = 0);

  std::vector<CertificateStore::ApplicationCertificate> mApplicationCertificates;

  SecureChannel(weak_ptr<SecureChannelDependencies> handler,
    shared_ptr<ConnectionProtocol> connectionProtocol,
    const connection_protocol::NegotiatedLimits& negotiatedLimits, ::ua::server::ListenerHandle listener,
    std::string listenerName, std::string remoteAddress,
    std::optional<std::string> reverseTargetName = std::nullopt);

  void initialise();

  void receive_message_chunk(StatusCode status, std::vector<byte>&& messageChunk);

  void receive_transport_error(StatusCode status, string_view errorDescription);

  void receive_request_message(uint32_t requestId, std::vector<byte> messageBody);

  // Common decoded-request dispatch point.
  // Returns true when dispatch starts an asynchronous handler (OPN flow); the drain pump must
  // not advance until the flow's terminal continuation re-arms it. Returns false when dispatch
  // routes to a synchronous handler that completes inline.
  bool handle_decoded_request(uint32_t requestId, unique_ptr<Structure> message, NodeId authenticationToken,
    uint32_t requestHandle = 0);

  // Report a rich channel-fatal error to every registered Session.
  void report_fatal_error_to_sessions(StatusCode status);

  // Channel-fatal errors are reported before registrations are cleared.
  void report_fatal_error_to_sessions_and_clear(StatusCode status);

  void handle_request_decode_failure(uint32_t requestId, StatusCode status);

  // Build a SecureChannelInfo snapshot for this channel (used for cross-channel ActivateSession).
  SecureChannelInfo build_secure_channel_info() const;

  void receive_close_request(uint32_t requestId, CloseSecureChannelRequest&& request);

  template<typename RequestType>
  void discovery_service_set_request_received(
    uint32_t requestId, RequestType&& request, InboundRegistrationContext registrationContext = {});

  // Build the inbound-registration context (message security mode + peer-cert applicationUri)
  // from the current channel state, for RegisterServer / RegisterServer2 validation.
  InboundRegistrationContext build_inbound_registration_context() const;

  void send_response_message_internal(Response response);

  shared_ptr<SecurityPolicy> extract_security_policy_from_opn_message_chunk(
    const std::vector<byte>& messageChunk) const;

  bool is_uninitialised() const;

  bool is_open() const;

  // Drain pumps. Replace the pre-flip mProcessRequests / mProcessResponses coroutine coroutines.
  // Self-tail-call: each step posts the next iteration onto the strand via on-strand callbacks.
  // mIncomingDrainScheduled / mOutgoingDrainScheduled gate single-flight per pump.
  void drain_incoming();
  void start_first_opn_cert_load(std::vector<byte> messageChunk);
  void on_first_opn_cert_loaded(
    CertificateStore::ApplicationCertificateListResult result, std::vector<byte> messageChunk);
  void start_decode_chunk(std::vector<byte> messageChunk);
  void on_chunk_decoded(DecodedMessageChunkResult result);

  void drain_outgoing();
  /// @p isOpenSecureChannelResponse: the message that was encoded is an OpenSecureChannel response, whose
  /// failure is reported with an Error message rather than a ServiceFault (OPC 10000-6 7.1.5).
  void on_message_encoded(VoidResult result, uint32_t requestId, bool isOpenSecureChannelResponse = false);
  /// True, and the close begun, when @p requestId is the response the channel closes after.
  bool close_if_response_was_the_last(uint32_t requestId);
  void reevaluate_certificate_on_strand();
  void on_certificate_reevaluated(shared_ptr<const X509Certificate> certificate, VoidResult result);

  void handle_unexpected_exception(const char* site, std::exception_ptr ex);
  void handle_chunk_decode_failure(std::exception_ptr ex);

  /// Live-instance counter for leak diagnostics. Zero-sized and inert in a release build; in debug
  /// and sanitizer builds a test can assert `InstanceTracker<ServerSecureChannelTag>::live() == 0` after
  /// churning secure channels, which names the type that leaked instead of a byte count.
  [[no_unique_address]] ua::diagnostics::InstanceTracker<ua::diagnostics::ServerSecureChannelTag>
    mInstanceTracker;
};

}  // namespace server
}  // namespace ua

#endif  // !UA_SERVER_SECURE_CHANNEL_H
