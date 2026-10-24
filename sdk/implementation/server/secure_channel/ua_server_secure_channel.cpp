// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Request flow:
//   wire bytes -> ConnectionProtocol -> receive_message_chunk()
//     -> decode security layer -> receive_request_message()
//       -> UA Binary decode -> handle_decoded_request()
//         -> dispatch to typed async handler (e.g. handle_open_secure_channel_async)
//         -> response encoded and sent via ConnectionProtocol

#include "ua_server_secure_channel.h"
#include "ua_server_impl.h"
#include "ua_server_counters.h"
#include "ua_service_fault.h"
#include "ua_timer.h"
#include "ua_memory_stream.h"
#include "ua_binary_codec.h"
#include "ua_discovery_service_set.h"
#include "ua_publish_request.h"
#include "ua_random.h"
#include "ua_stack_utilities.h"
#include "ua_application_configuration.h"
#include "ua_security_policy.h"
#include "ua_security_policy_internal.h"
#include "ua_utilities.h"
#include "ua_security_token.h"
#include <algorithm>
#include <optional>
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_server_encoding_limits.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_callback_safety.h"
#include "ua_error_chain.h"
#include "ua_on_strand.h"
#include "ua_certificate_validation_paths.h"
#include "ua_user_token_certificate_validation.h"
#include "ua_server_event_emit.h"
#include "ua_log_exception.h"
#include "ua_connection_protocol_limits.h"
#include "ua_status_code_masking.h"
#include "ua_diagnostic_collector.h"
#include "ua_diagnostic_security_context.h"

#include "fmt/format.h"

using namespace ua;

namespace ua::server
{

namespace
{

bool is_certificate_error(StatusCode sc)
{
  // OPC UA certificate errors span 0x8012xxxx-0x801Exxxx, plus 0x810Dxxxx and 0x8114xxxx.
  // The code field (upper 16 bits) covers all of them within the 0x80120000-0x811FFFFF range.
  const auto code = sc.as_uint32() & 0xFFFF0000U;
  return (code >= 0x80120000U && code <= 0x801E0000U) || code == 0x810D0000U || code == 0x81140000U;
}

SecureChannelEventInfo build_channel_event_info(
  const SecureChannelContext& ctx, const std::string& remoteAddress)
{
  SecureChannelEventInfo info;
  info.secureChannelId = ctx.secureChannelId;
  if (ctx.securityPolicy)
  {
    info.securityPolicyUri = std::string{ctx.securityPolicy->uri()};
  }
  info.messageSecurityMode = ctx.messageSecurityMode;
  info.remoteAddress = remoteAddress;
  return info;
}

// Returns the channel strand, asserting the construction-time invariant that it is engaged.
// The SecureChannel constructor engages mContext->mStrand and never resets it, so every method
// that posts directly to it can rely on engagement; this binds it behind an explicit precondition
// so the deref is provably on an engaged optional.
boost::asio::strand<boost::asio::any_io_executor>& channel_strand(SecureChannelContext& context)
{
  if (!context.boundStrand.has_value())
  {
    throw_empty_optional_check(Status::BadInvalidState, UA_CURRENT_LOCATION);
  }
  return *context.boundStrand;
}

}  // namespace

shared_ptr<SecureChannel> SecureChannel::create(weak_ptr<SecureChannelDependencies> handler,
  shared_ptr<ConnectionProtocol> connectionProtocol,
  ua::connection_protocol::NegotiatedLimits negotiatedLimits, ::ua::server::ListenerHandle listener,
  std::string listenerName, std::string remoteAddress, std::optional<std::string> reverseTargetName)
{
  class Wrapper : public SecureChannel
  {
  public:
    Wrapper(weak_ptr<SecureChannelDependencies> handler, shared_ptr<ConnectionProtocol> connectionProtocol,
      ua::connection_protocol::NegotiatedLimits negotiatedLimits, ::ua::server::ListenerHandle listener,
      std::string listenerName, std::string remoteAddress, std::optional<std::string> reverseTargetName)
      : SecureChannel(handler, connectionProtocol, negotiatedLimits, listener, std::move(listenerName),
          std::move(remoteAddress), std::move(reverseTargetName))
    {}
  };

  auto channel = make_shared<Wrapper>(handler,
    connectionProtocol,
    negotiatedLimits,
    listener,
    std::move(listenerName),
    std::move(remoteAddress),
    std::move(reverseTargetName));
  channel->initialise();
  return channel;
}

SecureChannel::SecureChannel(weak_ptr<SecureChannelDependencies> handler,
  shared_ptr<ConnectionProtocol> connectionProtocol,
  const ua::connection_protocol::NegotiatedLimits& negotiatedLimits, ::ua::server::ListenerHandle listener,
  std::string listenerName, std::string remoteAddress, std::optional<std::string> reverseTargetName)
  : mHandler(handler), mListenerHandle(listener), mListenerName(std::move(listenerName)),
    mReverseTargetName(std::move(reverseTargetName)), mRemoteAddress(std::move(remoteAddress)),
    mConnection(connectionProtocol), mEccOnlyTransport(connectionProtocol && connectionProtocol->is_ecc())
{
  // Seed mNextTokenId with a random value (avoid predictable token IDs).
  mNextTokenId = Random<uint32_t>{}();
  if (mNextTokenId == 0)
    mNextTokenId = 1;

  mContext = make_shared<SecureChannelContext>();
  mContext->role = ChannelRole::Server;
  auto handlerPtr = mHandler.lock();
  check(handlerPtr);
  mExecutor = handlerPtr->executor();
  mContext->boundStrand = boost::asio::make_strand(mExecutor);
  mContext->logger = handlerPtr->logger().with_category("secure_channel");
  mContext->negotiatedLimits = negotiatedLimits;
  mContext->encodingLimits =
    ua::server::make_server_encoding_limits(handlerPtr->configuration(), handlerPtr->server_configuration());
  mContext->secureChannelId = handlerPtr->get_next_secure_channel_id();
  mContext->crypto = handlerPtr->crypto();
  mContext->certStore = handlerPtr->default_application_group_certificate_store();
  mIncomingChunkQueueDepthCap = handlerPtr->server_configuration().resourceLimits.incomingChunkQueueDepth;
  mMaxInFlightRequestsPerConnection =
    handlerPtr->server_configuration().maxInFlightRequestsPerConnection.value_or(0);
  mServerWideInFlightRequestCap = handlerPtr->server_configuration().maxInFlightRequests.value_or(0);
  mServerWideInFlightRequests = handlerPtr->in_flight_requests();
  mContext->namespaceIndexCallback =
    namespace_array_utils::get_index_lookup_function(handlerPtr->address_space());
  // OPC 10000-4 section 6.1.3: an OPN client certificate accepted with suppressed errors is reported,
  // one observer call per error (owner review item 9).
  mContext->onRemoteCertificateErrorsSuppressed =
    [handler = mHandler, remoteAddress = mRemoteAddress](
      const CertificateValidationRequest& request, const std::vector<StatusCode>& suppressed)
  {
    auto h = handler.lock();
    if (!h)
      return;
    auto observer = h->observer();
    detail::emit_event(h->logger(),
      observer,
      [&] {
        detail::report_suppressed_certificate_errors(
          observer, remoteAddress, request.certificate, suppressed);
      });
  };

  handlerPtr->logger()
    .with_category("secure_channel")
    .debug({{"channel_id", uint64_t(mContext->secureChannelId)},
             {"remote_address", std::string_view{mRemoteAddress}}},
      "SecureChannel created");
}

void SecureChannelDependencies::activate_session_on_channel(
  SecureChannelInfo /*newChannelInfo*/, uint32_t /*requestId*/, ActivateSessionRequest&& /*request*/)
{
  // Default no-op for test doubles that don't test cross-channel activation.
}

std::shared_ptr<std::atomic<uint32_t>> SecureChannelDependencies::in_flight_requests()
{
  // Default: no server-wide in-flight counter (the per-connection cap still applies). Test doubles
  // that exercise the server-wide cap override this to return a shared counter.
  return nullptr;
}

SecureChannel::~SecureChannel()
{
  // maxInFlightRequests leak-sweep: any request still counted at teardown never had its response
  // sent (e.g. the session was destroyed mid-flight), so release its server-wide reservation here.
  // By destruction no strand callback references this channel, so the set is stable; the atomic op
  // is safe off-strand. The per-connection count dies with the channel.
  if (mServerWideInFlightRequests && !mInFlightCountedRequestIds.empty())
  {
    mServerWideInFlightRequests->fetch_sub(
      static_cast<uint32_t>(mInFlightCountedRequestIds.size()), std::memory_order_relaxed);
  }

  // Close the transport connection to cancel any pending async_read/async_write operations.
  // This ensures the io_context can drain and the thread pool can shut down gracefully.
  if (mConnection)
  {
    mConnection->close_async();
  }

  auto h = mHandler.lock();
  if (!h)
    return;

  h->logger()
    .with_category("secure_channel")
    .debug({{"channel_id", uint64_t(mContext ? mContext->secureChannelId : 0)},
             {"remote_address", std::string_view{mRemoteAddress}}},
      "SecureChannel destroyed");

  auto eh = h->observer();
  if (!eh)
    return;

  if (mContext && !mContext->is_uninitialised())
  {
    auto info = build_channel_event_info(*mContext, mRemoteAddress);
    detail::emit_event(h->logger(), eh, [&] { eh->on_secure_channel_closed(info, mCloseReason); });
  }

  if (mReverseTargetName)
  {
    detail::emit_event(h->logger(),
      eh,
      [&] { eh->on_reverse_connect_closed(*mReverseTargetName, mRemoteAddress, mCloseReason); });
  }

  detail::emit_event(
    h->logger(), eh, [&] { eh->on_connection_closed(mRemoteAddress, mConnectionCloseReason, mCloseReason); });
}

void SecureChannel::handle_unexpected_exception(const char* site, std::exception_ptr ex)
{
  auto er = ::ua::exception_to_status_code(std::move(ex));
  auto sc = er;

  auto errorDescription = er.shared_detail() ? fmt::format("{}: {}", site, to_string(*er.shared_detail()))
                                             : fmt::format("{}: {}", site, to_string(sc));

  if (auto h = mHandler.lock())
  {
    auto logger = h->logger().with_category("secure_channel");
    log_exception(logger, LogLevel::Error, site, er);

    auto eh = h->observer();
    detail::emit_event(logger, eh, [&] { eh->on_internal_error(sc, errorDescription); });
  }

  mCloseReason = sc;
  mConnectionCloseReason = ConnectionCloseReason::InternalError;
  if (mConnection)
  {
    // Part 6 6.7.6: server SHALL send a transport error message before closing.
    // Mask status to avoid leaking internal details to unauthenticated clients.
    mConnection->send_error(detail::mask_pre_auth_status(sc), "");
  }
}

weak_ptr<SecureChannelDependencies> SecureChannel::handler()
{
  return mHandler;
}

void SecureChannel::initialise()
{
  // Test/support path: allow constructing a SecureChannel without an attached ConnectionProtocol.
  // This is used by in-process unit tests to inject decoded requests and capture responses.
  if (!mConnection)
  {
    return;
  }

  auto me = this->weak_from_this();

  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};

  // The message-chunk callback delivers an owning std::vector<byte>, so post_borrowing can pack it
  // straight onto the strand. The error callback delivers a non-owning string_view that would dangle
  // across the strand hop, so a thin adapter copies it to a std::string before the borrowing post.
  mConnection->set_callbacks(ua::async::post_borrowing(this,
                               channel_strand(*mContext),
                               logger,
                               [](SecureChannel& self, StatusCode status, std::vector<byte> messageChunk)
                               {
                                 try
                                 {
                                   self.receive_message_chunk(status, std::move(messageChunk));
                                 }
                                 catch (...)
                                 {
                                   self.handle_unexpected_exception(
                                     "SecureChannel::receive_message_chunk", std::current_exception());
                                 }
                               }),
    [receiveTransportError = ua::async::post_borrowing(this,
       channel_strand(*mContext),
       logger,
       [](SecureChannel& self, StatusCode status, std::string errorDescription)
       {
         try
         {
           self.receive_transport_error(status, errorDescription);
         }
         catch (...)
         {
           self.handle_unexpected_exception(
             "SecureChannel::receive_transport_error", std::current_exception());
         }
       })](StatusCode status, string_view errorDescription, FatalCloseDisposition) mutable
    { receiveTransportError(status, std::string{errorDescription}); });

  // Start a timer for the first OpenSecureChannel request. If no OPN arrives within the
  // configured timeout, close the connection to prevent idle slot exhaustion.
  auto dependencies = mHandler.lock();
  if (dependencies)
  {
    auto firstOpnTimeout = dependencies->configuration().stack_limits().firstOpnTimeout;
    if (firstOpnTimeout.count() > 0)
    {
      // The channel strand is engaged in the constructor and never reset; assert that invariant
      // explicitly so the deref is provably on an engaged optional.
      const auto& strand = mContext->boundStrand;
      if (!strand.has_value())
        throw_empty_optional_check(Status::BadInvalidState, UA_CURRENT_LOCATION);
      mTimeoutTimer = Timer::schedule_after(*strand,
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(firstOpnTimeout),
        [me](boost::system::error_code ec)
        {
          if (ec)
            return;  // Timer was cancelled.

          auto self = me.lock();
          if (!self)
            return;

          if (auto h = self->mHandler.lock())
          {
            h->logger()
              .with_category("secure_channel")
              .warning({{"channel_id", uint64_t(self->mContext ? self->mContext->secureChannelId : 0)}},
                "First OPN timeout - closing connection");
          }

          self->mCloseReason = StatusCode{Status::BadTimeout};
          self->mConnectionCloseReason = ConnectionCloseReason::ProtocolError;
          if (self->mConnection)
          {
            // Part 6 6.7.6: server SHALL send a transport error message before closing.
            self->mConnection->send_error(StatusCode{Status::BadTimeout}, "");
          }
        });
    }
  }
}

void SecureChannel::receive_message_chunk(StatusCode status, std::vector<byte>&& messageChunk)
{
  if (status.is_bad())
  {
    if (!mTerminalFailureCommitted)
    {
      mTerminalFailureCommitted = true;
      mCloseReason = status;
      report_fatal_error_to_sessions_and_clear(status);
      mConnectionCloseReason = ConnectionCloseReason::TransportError;
      if (mConnection)
        mConnection->close_async();
    }
    return;
  }

  if (mChunkIngestObserver)
  {
    mChunkIngestObserver(std::chrono::steady_clock::now());
  }

  mIncomingMessageChunks.push(std::move(messageChunk));

  // Backpressure: once the queue reaches its depth cap, ask the transport to stop reading further
  // messages. No chunk is dropped - the transport finishes any in-flight message and then withholds
  // the next header read until resume_reads() (in drain_incoming) is called as the queue drains.
  // mReadPaused guards against repeated pause calls; mConnection is non-null on the wire path.
  if (!mReadPaused && mIncomingMessageChunks.size() >= mIncomingChunkQueueDepthCap)
  {
    mReadPaused = true;
    if (mConnection)
    {
      mConnection->pause_reads();
    }
  }

  // Re-arm the drain pump if no drain is currently scheduled. While mIncomingDrainScheduled
  // is true the pump (or an in-flight async step it kicked off - e.g. a pending OPN flow)
  // owns the next iteration; new chunks merely enqueue.
  if (!mIncomingDrainScheduled)
  {
    mIncomingDrainScheduled = true;
    drain_incoming();
  }
}

void SecureChannel::receive_transport_error(StatusCode status, string_view errorDescription)
{
  // Every close of the transport is reported here (the protocol reports an orderly close as Bad_Shutdown).
  // No renewal can follow, so the key-agreement secrets go now, not when the last holder of the context
  // lets it go.
  mContext->release_key_agreement_secrets();

  const bool ownsTerminalFailure = !mTerminalFailureCommitted;
  if (ownsTerminalFailure)
  {
    StatusCode terminalStatus{status.value(),
      ErrorDetail::build("TransportError", "Secure channel transport error", "SecureChannel")
        .context(ua::ContextKeys::errorMessage, std::string(errorDescription))
        .cause(status)};
    mTerminalFailureCommitted = true;
    mCloseReason = terminalStatus;
    report_fatal_error_to_sessions_and_clear(terminalStatus);
  }

  if (!mRemovedFromServer)
  {
    mRemovedFromServer = true;
    if (auto h = mHandler.lock())
    {
      h->remove_secure_channel(shared_from_this());
    }
  }

  if (!ownsTerminalFailure)
  {
    // ConnectionProtocol synthesizes Bad_Shutdown while completing a close that an earlier
    // SecureChannel failure already initiated. Removal above is still required, but the secondary
    // signal neither owns the terminal diagnosis nor needs to close the protocol again.
    return;
  }

  mConnectionCloseReason = ConnectionCloseReason::TransportError;
  mConnection->close_async();
}

void SecureChannel::receive_request_message(uint32_t requestId, std::vector<byte> messageBody)
{
  bool asyncDispatchStarted = false;
  try
  {
    memory_stream_device::ExternalReadOnly streamDevice{messageBody};
    MemoryStream stream{streamDevice};
    auto dependencies = mHandler.lock();
    check(dependencies);

    dependencies->logger()
      .with_category("secure_channel")
      .trace({{"request_id", uint64_t(requestId)}, {"body_size", uint64_t(messageBody.size())}},
        "Request message received");
    auto& factory = dependencies->structure_factory();
    UaBinaryDecoder decoder{factory.resolver(), stream, mContext->encodingLimits};

    auto depth = mContext->encodingLimits.stack_depth();

    ExpandedNodeId typeId;
    decoder.decode(depth, typeId);

    auto addressSpace = dependencies->address_space().lock();
    if (!addressSpace)
    {
      handle_request_decode_failure(requestId,
        StatusCode{Status::BadInternalError,
          make_error_detail("AddressSpaceUnavailable",
            "Request decoding requires the server address space",
            "SecureChannel")});
    }
    else
    {
      auto& namespaceArray = addressSpace->namespace_array();

      const NodeId encodingId = typeId.to_node_id(
        [&namespaceArray](string_view uri) { return namespaceArray.get_namespace_index(uri); });
      unique_ptr<Structure> message = factory.create_instance(encodingId);
      // The request type must agree with the chunk type it arrived in (Part 6 6.7.2): an
      // OpenSecureChannelRequest inside a MSG chunk would be a renewal handled under symmetric
      // security, and a MSG body inside an OPN chunk a request serviced under the opening
      // handshake's rules. The channel state gate refuses the first only on a closed channel; the
      // type gate refuses both on every channel (group A panel D5). The body is judged by the
      // instance the factory made, not by its id: the factory maps both of a type's encoding ids to
      // it (panel K round 1). Only an open channel can encode the refusal as a ServiceFault; before the
      // channel opens, a body in the wrong chunk reaches the not-open gate in handle_decoded_request,
      // which answers with an ERR and a close (panel K round 2).
      const bool opnBody = dynamic_cast<const OpenSecureChannelRequest*>(message.get()) != nullptr;
      if (!message)
      {
        handle_request_decode_failure(requestId,
          StatusCode{Status::BadDecodingError,
            make_error_detail("UnknownRequestEncodingId",
              "The request encoding identifier is not registered",
              "SecureChannel")});
      }
      else if (mChannelState == ChannelState::Open && opnBody != mDecodingOpnChunk)
      {
        handle_request_decode_failure(requestId,
          StatusCode{Status::BadSecurityChecksFailed,
            make_error_detail(opnBody ? "OpenSecureChannelBodyInMessageChunk" : "MessageBodyInOpenChunk",
              "The request's type does not match the chunk type it arrived in",
              "SecureChannel")});
      }
      else
      {
        // Pre-extract the authentication token before full decode.
        // UA Binary invariant: every service request starts with a RequestHeader, and the first
        // field of RequestHeader is the SessionAuthenticationToken (a NodeId). Reading one NodeId
        // from the current stream position extracts it without knowing the concrete request type.
        auto savedPos = stream.get_position();
        NodeId authenticationToken;
        decoder.decode(depth, authenticationToken);
        // The requestHandle is the 3rd RequestHeader field (after the timestamp). Pre-extract it too,
        // so a ServiceFault built before the typed request is available (e.g. unknown-session rejects)
        // can still echo it - Part 4: the ResponseHeader shall return the request's requestHandle.
        DateTime requestTimestamp;
        decoder.decode(depth, requestTimestamp);
        uint32_t requestHandle{0};
        decoder.decode(depth, requestHandle);
        stream.seek_from_start(savedPos);

        decoder.decode(depth, *message);

        asyncDispatchStarted = handle_decoded_request(
          requestId, std::move(message), std::move(authenticationToken), requestHandle);
      }
    }
  }
  catch (...)
  {
    handle_request_decode_failure(requestId, ::ua::exception_to_status_code(std::current_exception()));
  }

  // The drain pump's caller advances iteration only when no async handler started - OPN owns
  // the next drain step until complete_open / fail_open re-arms it.
  if (!asyncDispatchStarted)
  {
    drain_incoming();
  }
}

void SecureChannel::handle_request_decode_failure(uint32_t requestId, StatusCode status)
{
  // A malformed service request fails independently; the established channel and its Sessions
  // remain available for a subsequent well-formed request.
  if (auto channelHandler = mHandler.lock())
  {
    auto logger = channelHandler->logger().with_category("secure_channel");
    log_exception(logger, LogLevel::Warning, "SecureChannel::receive_request_message decoding", status);
  }

  auto serviceFault = stack_utils::create_service_fault(nullptr, status);
  send_response_message_internal(Response{requestId, serviceFault});
}

bool SecureChannel::handle_decoded_request(
  uint32_t requestId, unique_ptr<Structure> message, NodeId authenticationToken, uint32_t requestHandle)
{
  auto dependencies = mHandler.lock();
  check(dependencies);

  check(mContext);
  check(mContext->securityPolicy);

  // Test hook: notify request observer before dispatch.
  if (mRequestObserver)
  {
    ::ua::detail::invoke_user_callback(dependencies->logger(), mRequestObserver, requestId, *message);
  }

  // Log request dispatch at debug level.
  dependencies->logger()
    .with_category("secure_channel")
    .debug({{"channel_id", uint64_t(mContext->secureChannelId)},
             {"request_type", std::string_view{message->type_name()}}},
      "Request dispatched");

  if (auto* req = dynamic_cast<OpenSecureChannelRequest*>(message.get()))
  {
    handle_open_secure_channel_async(requestId, std::move(*req));
    return true;  // OPN owns the next drain step until complete_open / fail_open.
  }

  if (auto* req = dynamic_cast<CloseSecureChannelRequest*>(message.get()))
  {
    handle_close_secure_channel(requestId, std::move(*req));
    return false;
  }

  // Part 6 section 7.1.3 establishes the SecureChannel with the OpenSecureChannel exchange, and
  // section 6.7.4 makes the negotiated token the security of every later Message; before that
  // exchange completes the channel carries no service Message. A body arriving earlier (an OPN-typed
  // chunk carrying some other request) is refused the way a premature CreateSession is, so the
  // endpoint policy and discovery gates that OPN establishes cannot be bypassed by never opening.
  if (mChannelState != ChannelState::Open)
  {
    send_service_fault_with_hooks(requestId, Status::BadInvalidState);
    return false;
  }

  // Part 4 5.5.2.1: session-less channel reclamation is ordered by last use, not creation. This
  // common dispatch point advances the cross-strand timestamp once per service request an open
  // channel accepts. Only an accepted OPN is use (complete_open stamps it): a channel whose OPN is
  // still being validated or was refused, or which sent a body before opening, keeps the clock's
  // minimum and is reclaimed before an opened one. A CloseSecureChannel removes the channel.
  mLastUsedTicks.store(
    std::chrono::steady_clock::now().time_since_epoch().count(), std::memory_order_relaxed);

  if (auto* req = dynamic_cast<GetEndpointsRequest*>(message.get()))
  {
    handle_get_endpoints(requestId, std::move(*req));
    return false;
  }
  if (auto* req = dynamic_cast<FindServersRequest*>(message.get()))
  {
    handle_find_servers(requestId, std::move(*req));
    return false;
  }
  if (auto* req = dynamic_cast<FindServersOnNetworkRequest*>(message.get()))
  {
    handle_find_servers_on_network(requestId, std::move(*req));
    return false;
  }
  if (auto* req = dynamic_cast<RegisterServerRequest*>(message.get()))
  {
    handle_register_server(requestId, std::move(*req));
    return false;
  }
  if (auto* req = dynamic_cast<RegisterServer2Request*>(message.get()))
  {
    handle_register_server2(requestId, std::move(*req));
    return false;
  }
  if (auto* req = dynamic_cast<CreateSessionRequest*>(message.get()))
  {
    handle_create_session(requestId, std::move(*req));
    return false;
  }

  // Everything else is a session-level service request.
  handle_forward_to_session(
    requestId, std::shared_ptr<Structure>(message.release()), std::move(authenticationToken), requestHandle);
  return false;
}

void SecureChannel::handle_open_secure_channel_async(uint32_t requestId, OpenSecureChannelRequest request)
{
  // Per-OPN single-flight gate. The drain pump suspends across an in-flight OPN; receiving a
  // second OPN before the first concludes is a protocol violation.
  if (mOpenState)
  {
    send_service_fault_with_hooks(requestId,
      StatusCode{Status::BadInvalidState,
        make_error_detail("ConcurrentOpnRejected",
          "OpenSecureChannel rejected: another OpenSecureChannel flow is already in progress",
          "SecureChannel")},
      true,
      false,
      request.request_header().return_diagnostics());
    return;
  }

  auto dependencies = mHandler.lock();
  check(dependencies);

  const bool isRenew = (request.request_type() == SecurityTokenRequestType::Renew);
  const bool isOpn = !isRenew;
  const auto returnDiag = request.request_header().return_diagnostics();

  auto failInline = [&](StatusCode status, bool opnFlag, bool renewFlag, shared_ptr<const ErrorDetail> detail)
  {
    send_service_fault_with_hooks(
      requestId, StatusCode{status.value(), std::move(detail)}, opnFlag, renewFlag, returnDiag);
  };

  // --- Synchronous validation. Each rejection completes inline before mOpenState is allocated. ---

  // Part 6: AuthenticationToken in the RequestHeader must be null.
  if (!request.request_header().authentication_token().is_null())
  {
    failInline(Status::BadInvalidArgument,
      isOpn,
      isRenew,
      make_error_detail("AuthTokenNotNull",
        "OpenSecureChannel request must have null authentication token",
        "SecureChannel"));
    return;
  }

  // Part 6 6.7.4: "the ClientProtocolVersion specified in the OpenSecureChannel Request shall be the same as
  // the ProtocolVersion specified in the Hello Message ... The receiver shall close the channel and report a
  // Bad_ProtocolVersionUnsupported error if there is a mismatch."
  const auto helloProtocolVersion = mContext->negotiatedLimits.helloProtocolVersion;
  if (request.client_protocol_version() != helloProtocolVersion)
  {
    failInline(Status::BadProtocolVersionUnsupported,
      isOpn,
      isRenew,
      ErrorDetail::build("ProtocolVersionMismatch",
        "The OpenSecureChannel ClientProtocolVersion differs from the Hello ProtocolVersion",
        "SecureChannel")
        .context(ua::ContextKeys::actual, std::to_string(request.client_protocol_version()))
        .context(ua::ContextKeys::expected, std::to_string(helloProtocolVersion)));
    return;
  }

  // Issue/Renew legality by channel state.
  if (mChannelState == ChannelState::Open && request.request_type() == SecurityTokenRequestType::Issue)
  {
    failInline(Status::BadInvalidState,
      true,
      false,
      make_error_detail(
        "DuplicateIssue", "Cannot issue a new channel on an already-open channel", "SecureChannel"));
    return;
  }
  if (mChannelState == ChannelState::Closed && isRenew)
  {
    failInline(Status::BadInvalidState,
      false,
      true,
      make_error_detail("RenewOnClosed", "Cannot renew a closed channel", "SecureChannel"));
    return;
  }

  const bool isAuthenticated = mContext->securityPolicy->is_authenticated();
  const auto nonceLength = numeric_cast<uint32_t>(mContext->securityPolicy->nonce_length());

  // Security mode selection/validation (only on initial Issue).
  if (mChannelState == ChannelState::Closed)
  {
    if (!select_security_mode(request.security_mode()))
    {
      // SecurityPolicy None + Mode None always accepted for discovery (Part 4 5.4.1).
      if (mContext->securityPolicy->id() == SecurityPolicyId::None &&
          request.security_mode() == MessageSecurityMode::None)
      {
        if (!dependencies->server_configuration().discoveryEndpointEnabled)
        {
          failInline(Status::BadSecurityPolicyRejected,
            isOpn,
            isRenew,
            make_error_detail("DiscoveryEndpointDisabled",
              "The server's discovery-only endpoint is disabled by configuration",
              "SecureChannel"));
          return;
        }
        mContext->messageSecurityMode = MessageSecurityMode::None;
        mEndpointPolicyId = fmt::format("{}/{}", mListenerName, "discovery");
        mUserIdentityTokens = {};
        mDiscoveryOnly = true;
      }
      else
      {
        failInline(Status::BadSecurityModeRejected,
          isOpn,
          isRenew,
          ErrorDetail::build("SecurityModeRejected",
            "Requested security mode is not supported by this endpoint",
            "SecureChannel")
            .context(ua::ContextKeys::securityMode, to_string(request.security_mode())));
        return;
      }
    }
  }
  else
  {
    if (request.security_mode() != mContext->messageSecurityMode)
    {
      failInline(Status::BadSecurityModeRejected,
        isOpn,
        isRenew,
        ErrorDetail::build(
          "SecurityModeChanged", "Security mode cannot change during channel renew", "SecureChannel")
          .context(ua::ContextKeys::securityMode, to_string(request.security_mode()))
          .context(ua::ContextKeys::expected, to_string(mContext->messageSecurityMode)));
      return;
    }
  }

  // Nonce rules.
  if (isAuthenticated && request.client_nonce().empty())
  {
    failInline(Status::BadNonceInvalid,
      isOpn,
      isRenew,
      make_error_detail(
        "NonceEmpty", "Client nonce must not be empty for authenticated channels", "SecureChannel"));
    return;
  }

  if (isAuthenticated)
  {
    // Part 4 Table 12: a client nonce below 32 bytes is refused. The one policy whose
    // SecureChannelNonceLength is shorter (Basic128Rsa15, 16) has that length as its minimum instead;
    // the exact-length check below applies to every policy.
    const auto minimumNonceLength = std::min<uint32_t>(32, nonceLength);
    if (request.client_nonce().size() < minimumNonceLength)
    {
      failInline(Status::BadNonceInvalid,
        isOpn,
        isRenew,
        ErrorDetail::build(
          "NonceTooShort", "Client nonce is shorter than the policy's minimum", "SecureChannel")
          .context(ua::ContextKeys::sizeActual, std::to_string(request.client_nonce().size()))
          .context(ua::ContextKeys::sizeMin, std::to_string(minimumNonceLength)));
      return;
    }

    // Part 4 5.5.2.2 / SVR-SC-012: the nonce has exactly the policy's SecureChannelNonceLength, on
    // every authenticated policy (B2-5: the RSA policies accepted any length of 32 or more). For
    // ECC the nonce is the ephemeral public key, whose size the curve fixes.
    if (request.client_nonce().size() != nonceLength)
    {
      failInline(Status::BadNonceInvalid,
        isOpn,
        isRenew,
        ErrorDetail::build(
          "NonceWrongSize", "Client nonce size does not match the policy's nonce length", "SecureChannel")
          .context(ua::ContextKeys::sizeActual, std::to_string(request.client_nonce().size()))
          .context(ua::ContextKeys::sizeExpected, std::to_string(nonceLength)));
      return;
    }

    // A new clientNonce shall be generated for each time a SecureChannel is renewed.
    if (isRenew && !mLastClientNonce.empty() && (request.client_nonce() == mLastClientNonce))
    {
      failInline(Status::BadNonceInvalid,
        false,
        true,
        make_error_detail("NonceReused", "Client nonce must change on each renew", "SecureChannel"));
      return;
    }
  }

  // Record last client nonce (used for renew duplicate detection).
  mLastClientNonce = request.client_nonce();

  // --- Allocate per-flow state. From here on, terminal continuations are complete_open / fail_open. ---

  mOpenState = std::make_unique<OpenChannelState>();
  mOpenState->requestId = requestId;
  mOpenState->isRenew = isRenew;
  mOpenState->returnDiag = returnDiag;
  mOpenState->isAuthenticated = isAuthenticated;
  mOpenState->nonceLength = nonceLength;
  mOpenState->tokenId = mNextTokenId++;
  mOpenState->revisedLifetime =
    clamp_channel_lifetime(std::chrono::milliseconds{request.requested_lifetime()});
  mOpenState->request = std::move(request);

  // Eager, so this runs here on the strand exactly as far as the chain ran before its first async
  // call. Admission was decided above, before the state was allocated.
  mOpenChannelTask = run_open_channel(nonceLength);
}

boost::asio::strand<boost::asio::any_io_executor>& SecureChannel::open_channel_strand()
{
  return channel_strand(*mContext);
}

Logger SecureChannel::open_channel_logger() const
{
  auto dependencies = mHandler.lock();
  return dependencies ? dependencies->logger().with_category("secure_channel") : Logger{};
}

ua::async::Task<> SecureChannel::run_open_channel(uint32_t nonceLength)
{
  try
  {
    // --- the server nonce, which for a key-agreement policy is an ephemeral public key ---------
    if (nonceLength > 0)
    {
      if (const auto algo = mContext->securityPolicy->ephemeral_key_algorithm();
          algo != EphemeralKeyAlgorithm::Invalid)
      {

        auto ephemeralResult =
          co_await await_step<Crypto::EphemeralKeyPairResult>([this, algo](auto completion)
            { mContext->crypto->create_ephemeral_keys_async(algo, std::move(completion)); });
        if (!mOpenState)
          co_return;
        if (!ephemeralResult.is_good())
        {
          // An Uncertain answer is not acted on either, and is no code a fault can carry.
          fail_open(StatusCode{ephemeralResult.is_bad() ? ephemeralResult.status_code().value()
                                                        : StatusCode{Status::BadInternalError}.value(),
                      make_error_detail("EntropyGenerationFailed",
                        "Failed to generate the ephemeral key pair for the nonce",
                        "SecureChannel",
                        security_internal::not_good_answer(
                          ephemeralResult.status_code(), Status::BadInternalError, "SecureChannel"))},
            !mOpenState->isRenew,
            mOpenState->isRenew,
            mOpenState->returnDiag);
          co_return;
        }
        auto ephemeral = std::move(ephemeralResult).value();
        // A key an earlier exchange left behind (it never reached a derivation) is scrubbed, not just freed.
        security::secure_clear(mContext->localEphemeralPrivateKey);
        mContext->localEphemeralPrivateKey = std::move(ephemeral.privateKey);
        mOpenState->serverNonce = std::move(ephemeral.publicKey);
      }
      else
      {
        auto entropyResult = co_await await_step<ByteStringResult>([this, nonceLength](auto completion)
          { mContext->crypto->get_entropy_async(nonceLength, std::move(completion)); });
        if (!mOpenState)
          co_return;
        if (!entropyResult.is_good())
        {
          // An Uncertain answer is not acted on either, and is no code a fault can carry.
          fail_open(StatusCode{entropyResult.is_bad() ? entropyResult.status_code().value()
                                                      : StatusCode{Status::BadInternalError}.value(),
                      make_error_detail("EntropyGenerationFailed",
                        "Failed to generate server nonce entropy",
                        "SecureChannel",
                        security_internal::not_good_answer(
                          entropyResult.status_code(), Status::BadInternalError, "SecureChannel"))},
            !mOpenState->isRenew,
            mOpenState->isRenew,
            mOpenState->returnDiag);
          co_return;
        }
        mOpenState->serverNonce = std::move(entropyResult).value();
      }
    }
    // No nonce required (SecurityPolicy::None) - the server nonce stays empty and we fall straight
    // through to token creation, which the chain expressed by writing this block out three times.

    // --- the security token -------------------------------------------------------------------
    auto dependencies = mHandler.lock();
    check(dependencies);

    SecurityToken::TokenTimeoutCallback tokenCallback = ua::async::post_borrowing(this,
      channel_strand(*mContext),
      dependencies->logger().with_category("secure_channel"),
      [tid = mOpenState->tokenId](SecureChannel& self)
      {
        try
        {
          self.handle_token_expired(tid);
        }
        catch (...)
        {
          self.handle_unexpected_exception("SecureChannel::token_expiry", std::current_exception());
        }
      });

    auto tokenResult = co_await await_step<SecurityToken::CreateResult>(
      [this, tokenCallback = std::move(tokenCallback)](auto completion) mutable
      {
        SecurityToken::create_async(mOpenState->request.request_type(),
          mContext,
          mOpenState->tokenId,
          mOpenState->revisedLifetime,
          mOpenState->serverNonce,
          mOpenState->request.client_nonce(),
          ChannelRole::Server,
          std::move(tokenCallback),
          std::move(completion));
      });
    if (!mOpenState)
      co_return;

    if (!tokenResult.is_good())
    {
      // An Uncertain answer is not acted on either, and is no code a fault can carry.
      fail_open(StatusCode{tokenResult.is_bad() ? tokenResult.status_code().value()
                                                : StatusCode{Status::BadInternalError}.value(),
                  make_error_detail("SecurityTokenCreateFailed",
                    "Failed to derive symmetric keys for new security token",
                    "SecureChannel",
                    security_internal::not_good_answer(
                      tokenResult.status_code(), Status::BadInternalError, "SecureChannel"))},
        !mOpenState->isRenew,
        mOpenState->isRenew,
        mOpenState->returnDiag);
      co_return;
    }

    complete_open();
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    if (mOpenState)
    {
      auto er = ::ua::exception_to_status_code(std::current_exception());
      fail_open(er, !mOpenState->isRenew, mOpenState->isRenew, mOpenState->returnDiag);
    }
  }
  co_return;
}

void SecureChannel::complete_open()
{
  // Move-out -> state mutate -> fire pattern. The move leaves mOpenState null, so subsequent
  // OPN attempts pass the single-flight gate.
  auto flow = std::move(mOpenState);

  try
  {
    auto dependencies = mHandler.lock();
    check(dependencies);

    SecurityToken* token = nullptr;
    if (flow->request.request_type() == SecurityTokenRequestType::Issue)
    {
      token = mContext->activeSecurityToken.get();
    }
    else
    {
      token = mContext->pendingSecurityToken.get();
    }
    check(token);

    mContext->state = SecureChannelContext::State::Open;
    // The first-OPN timeout ends here, when an OpenSecureChannel is accepted, and not when the first chunk
    // arrives: a peer that sends one intermediate OPN chunk, or an OPN that is refused, and then nothing,
    // still has its connection closed when the timeout fires.
    mTimeoutTimer = {};

    // An accepted OPN (issue or renew) is use by the peer: it orders this channel after the
    // never-opened ones in the session-less reclaim (see last_used_time).
    mLastUsedTicks.store(
      std::chrono::steady_clock::now().time_since_epoch().count(), std::memory_order_relaxed);

    // Emit channel opened or renewed event.
    {
      auto logger = dependencies->logger();
      auto eh = dependencies->observer();
      auto evInfo = build_channel_event_info(*mContext, mRemoteAddress);
      evInfo.auditEntryId = flow->request.request_header().audit_entry_id();
      if (mContext->remoteCertificate)
      {
        evInfo.clientCertificate = mContext->remoteCertificate->der_encoding();
        evInfo.clientCertificateThumbprint = ua::to_string(mContext->remoteCertificate->thumbprint());
      }
      evInfo.requestedLifetime = flow->request.requested_lifetime();
      if (flow->request.request_type() == SecurityTokenRequestType::Issue)
      {
        auto securityPolicyStr = mContext->securityPolicy->uri();
        auto securityModeStr = to_string(mContext->messageSecurityMode);
        logger.info({{"channel_id", uint64_t(mContext->secureChannelId)},
                      {"security_policy", std::string_view{securityPolicyStr}},
                      {"security_mode", std::string_view{securityModeStr}}},
          "Secure channel opened");
        detail::emit_event(logger, eh, [&] { eh->on_secure_channel_opened(evInfo); });
        // The reverse-connect view of the same moment. Raised here rather than at channel
        // construction because the SecureChannelId is not assigned until OPN completes.
        if (mReverseTargetName)
        {
          const auto channelId = mContext->secureChannelId;
          detail::emit_event(
            logger, eh, [&] { eh->on_reverse_connect_channel_established(*mReverseTargetName, channelId); });
        }
      }
      else
      {
        logger.info({{"channel_id", uint64_t(mContext->secureChannelId)}}, "Secure channel renewed");
        detail::emit_event(logger, eh, [&] { eh->on_secure_channel_renewed(evInfo); });
      }
    }

    // Update token summaries and channel state. A Renew after a policy-side promotion must not
    // overwrite the promoted token's summary, so bring the summaries in line with the context first.
    sync_token_summaries_with_context();
    if (flow->request.request_type() == SecurityTokenRequestType::Issue)
    {
      mActiveTokenSummary =
        TokenSummary{.tokenId = token->id(), .revisedLifetime = token->revised_lifetime()};
      mPendingTokenSummary.reset();
      mChannelState = ChannelState::Open;
    }
    else
    {
      mPendingTokenSummary =
        TokenSummary{.tokenId = token->id(), .revisedLifetime = token->revised_lifetime()};
      mChannelState = ChannelState::Open;
    }

    // Build and send OpenSecureChannelResponse.
    auto response = make_shared<OpenSecureChannelResponse>();
    stack_utils::prepare_response_header(flow->request.request_header(), response->response_header());
    response->server_protocol_version() = 0;
    response->server_nonce() = flow->serverNonce;
    response->security_token().channel_id() = mContext->secureChannelId;
    response->security_token().token_id() = token->id();
    response->security_token().created_at() = token->created_at();
    response->security_token().revised_lifetime() = numeric_cast<uint32_t>(token->revised_lifetime().count());
    send_response_message_internal(Response{flow->requestId, response});
  }
  catch (...)
  {
    handle_unexpected_exception("SecureChannel::complete_open", std::current_exception());
  }

  // Re-arm the drain pump now that the OPN flow is no longer in flight.
  drain_incoming();
}

void SecureChannel::fail_open(
  StatusCode status, bool isOpnFailure, bool isRenewFailure, uint32_t returnDiagnostics)
{
  // Move-out -> fire. The move leaves mOpenState null before sending the fault so a second OPN
  // posted by the user (e.g. via the wire) passes the single-flight gate.
  auto flow = std::move(mOpenState);

  const uint32_t requestId = flow ? flow->requestId : 0;
  send_service_fault_with_hooks(
    requestId, std::move(status), isOpnFailure, isRenewFailure, returnDiagnostics);

  drain_incoming();
}

void SecureChannel::handle_close_secure_channel(uint32_t requestId, CloseSecureChannelRequest request)
{
  mCloseReason = Status::Good;
  mConnectionCloseReason = ConnectionCloseReason::Orderly;

  if (!mRemovedFromServer)
  {
    mRemovedFromServer = true;
    if (auto h = mHandler.lock())
    {
      h->remove_secure_channel(shared_from_this());
    }
  }

  receive_close_request(requestId, std::move(request));
}

void SecureChannel::handle_get_endpoints(uint32_t requestId, GetEndpointsRequest request)
{
  discovery_service_set_request_received(requestId, std::move(request));
}

void SecureChannel::handle_find_servers(uint32_t requestId, FindServersRequest request)
{
  discovery_service_set_request_received(requestId, std::move(request));
}

void SecureChannel::handle_find_servers_on_network(uint32_t requestId, FindServersOnNetworkRequest request)
{
  discovery_service_set_request_received(requestId, std::move(request));
}

void SecureChannel::handle_register_server(uint32_t requestId, RegisterServerRequest request)
{
  discovery_service_set_request_received(requestId, std::move(request), build_inbound_registration_context());
}

void SecureChannel::handle_register_server2(uint32_t requestId, RegisterServer2Request request)
{
  discovery_service_set_request_received(requestId, std::move(request), build_inbound_registration_context());
}

// Snapshot the channel-derived state the inbound RegisterServer / RegisterServer2 validation needs
// (Part 4 5.4.5.1 / 7.32): the negotiated message security mode and the peer-certificate
// applicationUri (subjectAltName URI). A None-mode channel has no remote certificate, leaving
// peerApplicationUri empty - the service then rejects the registration.
InboundRegistrationContext SecureChannel::build_inbound_registration_context() const
{
  InboundRegistrationContext context;
  context.messageSecurityMode = mContext->messageSecurityMode;
  if (mContext->remoteCertificate)
  {
    // The application instance URI is carried in the certificate's subjectAltName URI entries
    // (OPC 10000-6 6.2.2), NOT the subject DN. Use the first SAN URI as the applicationUri the
    // serverUri must match (Part 4 5.4.5.1).
    auto sanUris = mContext->remoteCertificate->san_uris();
    if (!sanUris.empty())
    {
      context.peerApplicationUri = std::move(sanUris.front());
    }
  }
  return context;
}

void SecureChannel::handle_create_session(uint32_t requestId, CreateSessionRequest request)
{
  if (mChannelState != ChannelState::Open)
  {
    send_service_fault_with_hooks(requestId, Status::BadInvalidState);
    return;
  }
  if (mDiscoveryOnly)
  {
    send_service_fault_with_hooks(requestId, Status::BadSecurityPolicyRejected);
    return;
  }

  auto dependencies = mHandler.lock();
  check(dependencies);
  auto info = build_secure_channel_info();
  dependencies->create_session(info, requestId, std::move(request));
}

void SecureChannel::handle_forward_to_session(
  uint32_t requestId, std::shared_ptr<Structure> request, NodeId authenticationToken, uint32_t requestHandle)
{
  // Build a RequestHeader carrying just the requestHandle so faults raised here (before the typed
  // request is available) echo it back, per Part 4 (ResponseHeader.requestHandle).
  RequestHeader faultHeader;
  faultHeader.request_handle() = requestHandle;

  if (mDiscoveryOnly)
  {
    send_service_fault_with_hooks(requestId, Status::BadSecurityPolicyRejected);
    return;
  }

  auto it = mSessionCallbacks.find(authenticationToken);
  if (it != mSessionCallbacks.end())
  {
    // maxInFlightRequests admission. Publish requests are parked flow-control bounded by the
    // publish-queue limits, so they are excluded from these caps. A request is admitted (counted)
    // here and released when its response is sent (send_response_message_internal). The rejection
    // fault below is sent before counting, so its own response does not trigger a spurious decrement.
    if (!dynamic_cast<PublishRequest*>(request.get()))
    {
      const auto perConnectionInFlight = static_cast<uint32_t>(mInFlightCountedRequestIds.size());
      const uint32_t serverWideInFlight =
        mServerWideInFlightRequests ? mServerWideInFlightRequests->load(std::memory_order_relaxed) : 0;
      const bool overPerConnection =
        mMaxInFlightRequestsPerConnection != 0 && perConnectionInFlight >= mMaxInFlightRequestsPerConnection;
      const bool overServerWide = mServerWideInFlightRequestCap != 0 && mServerWideInFlightRequests &&
                                  serverWideInFlight >= mServerWideInFlightRequestCap;
      if (overPerConnection || overServerWide)
      {
        // Report the actual/limit pair for whichever cap tripped (per-connection takes
        // precedence when both are exceeded).
        const uint32_t triggeredLimit =
          overPerConnection ? mMaxInFlightRequestsPerConnection : mServerWideInFlightRequestCap;
        const uint32_t triggeredCount = overPerConnection ? perConnectionInFlight : serverWideInFlight;
        send_response_message_internal(Response{requestId,
          stack_utils::create_service_fault(&faultHeader,
            StatusCode{Status::BadServerTooBusy,
              ErrorDetail::build(
                "ServerTooBusy", "In-flight request admission limit reached", "SecureChannel")
                .context(ua::ContextKeys::limit, std::to_string(triggeredLimit))
                .context(ua::ContextKeys::countTotal, std::to_string(triggeredCount))
                .context(ua::ContextKeys::channelId, std::to_string(mContext ? mContext->secureChannelId : 0))
                .context(ua::ContextKeys::requestId, std::to_string(requestId))})});
        return;
      }

      mInFlightCountedRequestIds.insert(requestId);
      if (mServerWideInFlightRequests)
        mServerWideInFlightRequests->fetch_add(1, std::memory_order_relaxed);
    }

    it->second.sendRequest(std::make_pair(requestId, request ? request->clone() : nullptr));
    return;
  }

  // Token not registered on this channel.
  // ActivateSession may be a cross-channel transfer - delegate to ServerImpl for session lookup.
  if (auto* asr = dynamic_cast<ActivateSessionRequest*>(request.get()))
  {
    auto dependencies = mHandler.lock();
    if (dependencies)
    {
      dependencies->activate_session_on_channel(build_secure_channel_info(), requestId, std::move(*asr));
    }
    else
    {
      send_response_message_internal(
        Response{requestId, stack_utils::create_service_fault(&faultHeader, Status::BadSessionIdInvalid)});
    }
    return;
  }

  // Token not registered on this channel and not a transfer attempt. If this channel previously
  // hosted the session and it was transferred elsewhere, requests on the old channel are rejected
  // with Bad_SecureChannelIdInvalid (Part 4 5.6.3). A token this channel never hosted is unknown
  // here - Bad_SessionIdInvalid (e.g. closing another channel's session, Session Multiple Err-001).
  const auto status = mTransferredAwayTokens.contains(authenticationToken) ? Status::BadSecureChannelIdInvalid
                                                                           : Status::BadSessionIdInvalid;

  send_response_message_internal(
    Response{requestId, stack_utils::create_service_fault(&faultHeader, status)});
}

void SecureChannel::sync_token_summaries_with_context()
{
  // The SecurityPolicy promotes the pending token itself when the first chunk under the new TokenId
  // arrives (SecurityPolicy::decode_message_chunk_async), without telling the channel. The context is
  // therefore the authority on which token is active; every reader or writer of the summaries brings
  // them in line first, or a promoted token's expiry would match a stale pending summary and close
  // nothing, and a later Renew would overwrite that stale summary and hide the promotion for good.
  if (!mContext || !mContext->activeSecurityToken || !mPendingTokenSummary)
  {
    return;
  }
  if (mPendingTokenSummary->tokenId != mContext->activeSecurityToken->id())
  {
    return;
  }
  mActiveTokenSummary = *mPendingTokenSummary;
  mPendingTokenSummary.reset();
}

void SecureChannel::handle_token_expired(uint32_t tokenId)
{
  sync_token_summaries_with_context();

  if (mActiveTokenSummary && mActiveTokenSummary->tokenId == tokenId)
  {
    if (mPendingTokenSummary)
    {
      // Promote pending -> active.
      mActiveTokenSummary = *mPendingTokenSummary;
      mPendingTokenSummary.reset();

      auto& pendingToken = mContext->pendingSecurityToken;
      if (pendingToken)
      {
        mContext->activeSecurityToken = std::move(pendingToken);
        pendingToken.reset();

        if (auto h = mHandler.lock())
        {
          h->logger()
            .with_category("secure_channel")
            .debug({{"channel_id", uint64_t(mContext->secureChannelId)}}, "Security token promoted");
        }
      }
    }
    else
    {
      // No pending token - close transport.
      if (auto h = mHandler.lock())
      {
        auto reason = StatusCode{Status::BadSecureChannelClosed};
        auto statusHex = fmt::format("0x{:08x}", reason.as_uint32());
        h->logger()
          .with_category("secure_channel")
          .warning(
            {{"channel_id", uint64_t(mContext->secureChannelId)}, {"status", std::string_view{statusHex}}},
            "Closing transport");

        if (!mRemovedFromServer)
        {
          mRemovedFromServer = true;
          h->remove_secure_channel(shared_from_this());
        }
      }

      mCloseReason = Status::BadSecureChannelClosed;
      mConnectionCloseReason = ConnectionCloseReason::ProtocolError;
      if (mConnection)
      {
        mConnection->send_error(detail::mask_pre_auth_status(StatusCode{Status::BadSecureChannelClosed}), "");
      }
    }
  }
  else if (mPendingTokenSummary && mPendingTokenSummary->tokenId == tokenId)
  {
    mPendingTokenSummary.reset();
  }
}

std::chrono::milliseconds SecureChannel::clamp_channel_lifetime(std::chrono::milliseconds requested) const
{
  auto dependencies = mHandler.lock();
  check(dependencies);
  const auto& limits = dependencies->configuration().stack_limits();
  if (requested < limits.secureChannelMinimumLifetime)
    return limits.secureChannelMinimumLifetime;
  if (requested > limits.secureChannelMaximumLifetime)
    return limits.secureChannelMaximumLifetime;
  return requested;
}

bool SecureChannel::select_security_mode(MessageSecurityMode requestedMode)
{
  auto dependencies = mHandler.lock();
  check(dependencies);
  for (auto& endpoint : dependencies->endpoints(mListenerHandle))
  {
    if ((endpoint.transportProfile == TransportProfileId::UaTcpUaScUaBinary) &&
        (endpoint.securityPolicyId == mContext->securityPolicy->id()) &&
        (endpoint.messageSecurityMode == requestedMode))
    {
      mContext->messageSecurityMode = requestedMode;
      mEndpointPolicyId = fmt::format("{}/{}", mListenerName, endpoint.name);
      mUserIdentityTokens = endpoint.userIdentityTokens;
      mTransportProfileUri = std::string{utils::get_transport_profile_uri(endpoint.transportProfile)};
      // Endpoint URL: take the first listener-advertised URL as the stable
      // server-side identifier (Part-18 4.4.2 narrowing compares against it).
      // Advertised URLs are listener-level (not per-endpoint), so the first
      // entry is the canonical one. The Discovery service handles per-client
      // rewriting; the RBAC filter wants the server-stable form.
      if (auto disc = dependencies->discovery_dependencies().lock())
      {
        auto urls = disc->advertised_urls(mListenerHandle);
        if (!urls.empty())
        {
          mEndpointUrl = urls.front().str();
        }
      }
      return true;
    }
  }
  return false;
}

void SecureChannel::send_service_fault_with_hooks(
  uint32_t requestId, StatusCode status, bool isOpnFailure, bool isRenewFailure, uint32_t)
{
  const auto& detail = status.shared_detail();

  // Record the reject BEFORE anything strips it. On a pre-authentication failure the wire
  // carries only a masked status (mask_pre_auth_status). The rich StatusCode remains the single
  // SDK-side carrier for the observer, log, and any authenticated diagnostic projection.
  // Emitted here, ahead of the connection branch below, so a reject is recorded whether or not
  // there is still a connection to answer on.
  if (detail)
  {
    if (auto h = mHandler.lock())
    {
      h->logger()
        .with_category("secure_channel")
        .warning({{"status", to_string(status)},
                   {"remote_address", mRemoteAddress},
                   {"reject.code", detail->code},
                   {"reject.detail", to_string(*detail)}},
          "OpenSecureChannel rejected");
    }
  }

  // Fire the test-only observer before wire encoding strips ErrorDetail from ResponseHeader /
  // DiagnosticInfo. The hook consumes the same rich StatusCode as every production observer.
  if (mValidationFailureObserver)
  {
    auto dependencies = mHandler.lock();
    auto loggerForCallback = dependencies ? dependencies->logger() : Logger{};
    ::ua::detail::invoke_user_callback(loggerForCallback, mValidationFailureObserver, status);
  }

  // If there is no active security token, the channel is not yet established.
  // Encoding a symmetric message requires a token - attempting it would crash.
  if (mConnection && (!mContext || !mContext->activeSecurityToken))
  {
    if (auto h = mHandler.lock())
    {
      h->logger()
        .with_category("secure_channel")
        .warning({{"status", to_string(status)}, {"remote_address", mRemoteAddress}},
          "Closing connection: OPN service fault cannot be sent without an active security token");
    }
    mConnection->send_error(detail::mask_pre_auth_status(status), "");

    if (isOpnFailure || isRenewFailure)
    {
      auto h = mHandler.lock();
      if (h)
      {
        // A refused OpenSecureChannel Issue is a rejected secure channel (OPC 10000-5
        // ServerDiagnosticsSummary rejectedSecureChannelCount). Renew failures are on an
        // already-open channel, not a new open, so they are not counted. secure_channel_counters()
        // returns null when ServerDiagnostics is disabled, keeping this inert then.
        if (isOpnFailure)
        {
          if (auto ctrs = h->secure_channel_counters())
            ctrs->rejectedCount.fetch_add(1, std::memory_order_relaxed);
        }
        auto eh = h->observer();
        if (eh && mContext)
        {
          auto info = build_channel_event_info(*mContext, mRemoteAddress);
          if (isOpnFailure)
            detail::emit_event(h->logger(), eh, [&] { eh->on_secure_channel_open_failed(info, status); });
          else
            detail::emit_event(h->logger(), eh, [&] { eh->on_secure_channel_renew_failed(info, status); });
        }
      }
    }
    return;
  }

  auto fault = stack_utils::create_service_fault(nullptr, status);

  // OpenSecureChannel has no authenticated Session. A signed channel alone does not authorize
  // diagnostic disclosure, including on Renew. The original rich failure was logged above.

  send_response_message_internal(Response{requestId, fault});

  if (isOpnFailure || isRenewFailure)
  {
    auto h = mHandler.lock();
    if (h)
    {
      auto eh = h->observer();
      if (eh && mContext)
      {
        auto info = build_channel_event_info(*mContext, mRemoteAddress);
        if (isOpnFailure)
          detail::emit_event(h->logger(), eh, [&] { eh->on_secure_channel_open_failed(info, status); });
        else
          detail::emit_event(h->logger(), eh, [&] { eh->on_secure_channel_renew_failed(info, status); });
      }
    }
  }
}

void SecureChannel::inject_decoded_request_for_tests(
  uint32_t requestId, shared_ptr<Structure> request, NodeId authenticationToken)
{
  // Run on the secure channel strand so behavior matches real code.
  check(mContext);
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
  ua::async::post_owning(this,
    channel_strand(*mContext),
    logger,
    [requestId, request = std::move(request), authenticationToken = std::move(authenticationToken)](
      SecureChannel& self) mutable
    {
      try
      {
        // Sync handlers complete inline. The OPN arm starts the OpenSecureChannel body and returns
        // true; the flow eventually fires complete_open / fail_open. Either way, no coroutine
        // member is required.
        (void)self.handle_decoded_request(requestId, request->clone(), std::move(authenticationToken));
      }
      catch (...)
      {
        self.handle_unexpected_exception(
          "SecureChannel::inject_decoded_request_for_tests", std::current_exception());
      }
    })();
}

optional<Response> SecureChannel::pop_queued_response_for_tests()
{
  if (mOutgoingMessages.empty())
  {
    return {};
  }
  auto resp = std::move(mOutgoingMessages.front());
  mOutgoingMessages.pop();
  return resp;
}

void SecureChannel::receive_close_request(uint32_t requestId, CloseSecureChannelRequest&& request)
{
  UA_UNUSED(requestId);
  UA_UNUSED(request);
  if (mConnection)
  {
    mConnection->close_async();
  }
}

template<typename RequestType>
void SecureChannel::discovery_service_set_request_received(
  uint32_t requestId, RequestType&& request, InboundRegistrationContext registrationContext)
{
  auto dependencies = mHandler.lock();
  check(dependencies);

  // S12: Track in-flight discovery requests for load-aware throttling.
  auto discoveryCounter = dependencies->in_flight_discovery_requests();
  uint32_t currentCount = 0;
  if (discoveryCounter)
  {
    currentCount = discoveryCounter->fetch_add(1, std::memory_order_relaxed) + 1;
  }

  const auto& throttleCfg = dependencies->server_configuration().discoveryThrottling;
  const bool shouldDelay =
    currentCount > throttleCfg.concurrencyThreshold && throttleCfg.delayPerRequest.count() > 0;

  if (shouldDelay)
  {
    dependencies->logger()
      .with_category("discovery")
      .debug(
        {{"in_flight", uint64_t(currentCount)}, {"threshold", uint64_t(throttleCfg.concurrencyThreshold)}},
        "Discovery throttling: delaying request");
  }

  // Lambda that creates and dispatches the discovery service.
  auto me = this->weak_from_this();
  auto dispatch = [me,
                    requestId,
                    request = std::forward<RequestType>(request),
                    discoveryCounter,
                    registrationContext = std::move(registrationContext)]() mutable
  {
    auto self = me.lock();
    if (!self)
    {
      // Channel gone - decrement counter and bail.
      if (discoveryCounter)
        discoveryCounter->fetch_sub(1, std::memory_order_relaxed);
      return;
    }

    auto h = self->mHandler.lock();
    if (!h)
    {
      if (discoveryCounter)
        discoveryCounter->fetch_sub(1, std::memory_order_relaxed);
      return;
    }

    auto id = Guid::create_and_generate();

    auto discoveryServiceSet = DiscoveryServiceSet<std::decay_t<RequestType>>::create(
      h->discovery_dependencies(),
      String{},
      requestId,
      std::move(request),
      h->executor(),
      [me, id, discoveryCounter](Response response)
      {
        // S12: Decrement in-flight counter when the discovery service completes. This must run
        // regardless of channel liveness, so it stays outside the borrowing post below.
        if (discoveryCounter)
          discoveryCounter->fetch_sub(1, std::memory_order_relaxed);

        auto secureChannel = me.lock();
        if (!secureChannel)
          return;
        auto handlerForLog = secureChannel->mHandler.lock();
        auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
        ua::async::post_borrowing(secureChannel.get(),
          channel_strand(*secureChannel->mContext),
          logger,
          [guid = id](SecureChannel& channel, Response outgoingResponse)
          {
            channel.send_response_message_internal(std::move(outgoingResponse));
            channel.mDiscoveryCalls.erase(guid);
          })(std::move(response));
      },
      std::move(registrationContext));

    self->mDiscoveryCalls.emplace(id, discoveryServiceSet);
  };

  if (shouldDelay)
  {
    // Schedule the dispatch after the configured delay.

    // Store the timer so it stays alive until it fires. Use mDiscoveryCalls with a unique key.
    auto timerId = Guid::create_and_generate();
    auto timerPtr = std::make_shared<Timer>();
    *timerPtr = Timer::schedule_after(channel_strand(*mContext),
      std::chrono::duration_cast<std::chrono::steady_clock::duration>(throttleCfg.delayPerRequest),
      [me, dispatch = std::move(dispatch), discoveryCounter, timerId, timerPtr](
        boost::system::error_code ec) mutable
      {
        if (ec)
        {
          // Timer cancelled (e.g. shutdown) - decrement counter and clean up.
          if (discoveryCounter)
            discoveryCounter->fetch_sub(1, std::memory_order_relaxed);
          if (auto self = me.lock())
            self->mDiscoveryCalls.erase(timerId);
          timerPtr.reset();
          return;
        }

        dispatch();

        // Remove the timer from mDiscoveryCalls.
        if (auto self = me.lock())
          self->mDiscoveryCalls.erase(timerId);
        timerPtr.reset();
      });

    mDiscoveryCalls.emplace(timerId, timerPtr);
  }
  else
  {
    // No delay needed - dispatch immediately.
    dispatch();
  }
}

void SecureChannel::send_response_message(Response response)
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};

  // Single request-level reject point. A ServiceFault is, by definition (OPC 10000-4 5.3 / 7.35), a
  // whole Service request rejected at the service level - every service and session path delivers a
  // whole-request rejection as a ServiceFault, and they all converge here. So count
  // rejectedRequestsCount exactly once, here, for any ServiceFault. A per-item denial is a typed
  // response carrying a Good serviceResult (not a ServiceFault), so it is correctly not counted.
  if (handlerForLog && response.second != nullptr &&
      dynamic_cast<const ua::ServiceFault*>(response.second.get()) != nullptr)
  {
    auto enabled = handlerForLog->diagnostics_enabled();
    if (enabled && enabled->load(std::memory_order_relaxed))
    {
      if (auto counters = handlerForLog->summary_counters())
        counters->rejectedRequestsCount.fetch_add(1, std::memory_order_relaxed);
    }
  }

  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    [response = std::move(response)](SecureChannel& self) mutable
    { self.send_response_message_internal(std::move(response)); })();
}

void SecureChannel::send_response_message(
  Response response, std::function<void(VoidResult)> enqueuedCallback, AfterResponse afterResponse)
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};

  // This overload is used only by responses carrying post-response actions. Keep the ordinary
  // response overload free of callback storage and invocation overhead.
  if (handlerForLog && response.second != nullptr &&
      dynamic_cast<const ua::ServiceFault*>(response.second.get()) != nullptr)
  {
    auto enabled = handlerForLog->diagnostics_enabled();
    if (enabled && enabled->load(std::memory_order_relaxed))
    {
      if (auto counters = handlerForLog->summary_counters())
        counters->rejectedRequestsCount.fetch_add(1, std::memory_order_relaxed);
    }
  }

  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    std::move(enqueuedCallback),
    VoidResult{Status::BadSecureChannelClosed,
      make_error_detail("ResponseEnqueueAbandoned",
        "SecureChannel disappeared before the correlated response crossed its outgoing queue boundary",
        "SecureChannel")},
    [response = std::move(response), afterResponse](
      SecureChannel& self, std::function<void(VoidResult)> callback) mutable
    {
      VoidResult result{};
      try
      {
        if (self.mCorrelatedResponseEnqueueFailureInjectorForTests)
          self.mCorrelatedResponseEnqueueFailureInjectorForTests();
        const uint32_t requestId = response.first;
        if (afterResponse == AfterResponse::CloseChannel)
          self.mCloseAfterResponseRequestId = requestId;
        else if (afterResponse == AfterResponse::ReevaluateCertificate)
          self.mReevaluateAfterResponseRequestId = requestId;
        self.send_response_message_internal(std::move(response));
        // Without a connection nothing is encoded or written (the in-process test path), so there is
        // nothing to wait for: the channel closes or re-evaluates at once.
        if (afterResponse != AfterResponse::Nothing && !self.mConnection)
          self.close_if_response_was_the_last(requestId);
      }
      catch (...)
      {
        result = VoidResult{::ua::exception_to_status_code(std::current_exception())};
      }
      callback(std::move(result));
    })();
}

void SecureChannel::send_response_message_internal(Response response)
{
  // Test hook: allow interceptor to mutate the response before signing/encryption.
  // This enables negative testing by corrupting fields the server would otherwise sign correctly.
  if (mResponseInterceptor)
  {
    auto loggerForCallback = [&]() -> Logger
    {
      if (auto h = mHandler.lock())
        return h->logger();
      return Logger{};
    }();
    ::ua::detail::invoke_user_callback(loggerForCallback, mResponseInterceptor, response);
  }

  // Test hook: notify sink immediately (still on the secure-channel strand).
  // Do this before moving into the queue so the sink sees the original object.
  if (mResponseSinkForTests)
  {
    auto loggerForCallback = [&]() -> Logger
    {
      if (auto h = mHandler.lock())
        return h->logger();
      return Logger{};
    }();
    ::ua::detail::invoke_user_callback(loggerForCallback, mResponseSinkForTests, response);
  }

  // Add response to queue
  auto responseRequestId = response.first;

  // maxInFlightRequests release: if this response answers a counted request, drop it from the
  // per-connection set and decrement the server-wide counter. Uncounted ids (Publish, discovery,
  // CreateSession, the over-cap rejection itself) are not present, so this is a no-op for them.
  if (mInFlightCountedRequestIds.erase(responseRequestId) != 0 && mServerWideInFlightRequests)
    mServerWideInFlightRequests->fetch_sub(1, std::memory_order_relaxed);

  // The channel is closing after a response it was told to close after (ApplyChanges): a later response is
  // not sent - the close is already ordered after the writes that response made.
  if (mClosingAfterResponse)
  {
    if (auto h = mHandler.lock())
    {
      h->logger()
        .with_category("secure_channel")
        .debug({{"request_id", uint64_t(responseRequestId)}},
          "Response dropped: the channel is closing after an earlier response");
    }
    return;
  }

  mOutgoingMessages.push(std::move(response));

  // Only log if we have a handler
  if (auto h = mHandler.lock())
  {
    h->logger()
      .with_category("secure_channel")
      .trace({{"request_id", uint64_t(responseRequestId)}}, "Response queued for encoding");
  }

  // Re-arm the outgoing drain pump if no drain is currently in flight.
  if (!mOutgoingDrainScheduled)
  {
    mOutgoingDrainScheduled = true;
    drain_outgoing();
  }
}

void SecureChannel::set_response_sink_for_tests(ResponseSinkForTests sink)
{
  mResponseSinkForTests = std::move(sink);
}

void SecureChannel::set_chunk_ingest_observer(ChunkIngestObserver observer)
{
  mChunkIngestObserver = std::move(observer);
}

void SecureChannel::set_chunk_egress_observer(ChunkEgressObserver observer)
{
  mChunkEgressObserver = std::move(observer);
}

void SecureChannel::set_request_observer(RequestObserver observer)
{
  mRequestObserver = std::move(observer);
}

void SecureChannel::set_response_interceptor(ResponseInterceptor interceptor)
{
  mResponseInterceptor = std::move(interceptor);
}

void SecureChannel::set_validation_failure_observer(ValidationFailureObserver observer)
{
  mValidationFailureObserver = std::move(observer);
}

shared_ptr<SecurityPolicy> SecureChannel::extract_security_policy_from_opn_message_chunk(
  const std::vector<byte>& messageChunk) const
{
  using namespace stack_utils;

  memory_stream_device::ExternalReadOnly streamDevice{messageChunk};
  MemoryStream stream{streamDevice};
  UaBinaryDecoder decoder(StructureResolver{}, stream, mContext->encodingLimits);

  UaScMessageHeader messageHeader;
  messageHeader.decode(mContext->encodingLimits, decoder);
  if (messageHeader.messageType != UaScMessageHeader::MessageType::Open)
  {
    throw UaException{Status::BadInvalidState,
      ErrorDetail::build("SecureChannelError",
        "Expected OPN (OpenSecureChannel) message but received different message type",
        "SecureChannel")
        .context(ua::ContextKeys::actual, std::to_string(static_cast<int>(messageHeader.messageType)))
        .context(ua::ContextKeys::expected, "Open")};
  }

  auto dependencies = mHandler.lock();
  check(dependencies);

  // H-D2 (B2-4): the listener's endpoint list is the allow-list, consulted on the URI alone BEFORE
  // the rest of the security header (the peer's certificate chain) is parsed, before the policy
  // object exists and before any certificate or private-key work runs on the chunk. None is also
  // accepted when the discovery-only endpoint is enabled (Part 4 5.4.1), which is the rule
  // select_security_mode applies once the request is decoded.
  const auto securityHeaderPosition = stream.get_position();
  String securityPolicyUri;
  decoder.decode(mContext->encodingLimits.stack_depth(), securityPolicyUri);
  // A URI the SDK does not implement - one of the six ECC policies OPC UA 1.05.07 removed, or any other
  // string - is a policy no endpoint offers: SecurityPolicy::create refuses it with Bad_InvalidArgument,
  // which here means "not offered", not a fault of the server.
  std::optional<SecurityPolicyId> requestedPolicy;
  try
  {
    requestedPolicy = utils::get_security_policy_id(securityPolicyUri);
  }
  catch (const UaException& error)
  {
    if (error.status() != Status::BadInvalidArgument)
      throw;
  }
  bool offered = false;
  for (const auto& endpoint : dependencies->endpoints(mListenerHandle))
  {
    if (requestedPolicy && (endpoint.transportProfile == TransportProfileId::UaTcpUaScUaBinary) &&
        (endpoint.securityPolicyId == *requestedPolicy))
    {
      offered = true;
      break;
    }
  }
  if (!offered && requestedPolicy == SecurityPolicyId::None &&
      dependencies->server_configuration().discoveryEndpointEnabled)
  {
    offered = true;
  }
  if (!offered)
  {
    throw UaException{Status::BadSecurityPolicyRejected,
      ErrorDetail::build("SecurityPolicyNotOffered",
        "The OpenSecureChannel names a security policy no endpoint on this listener offers",
        "SecureChannel")
        .context(ua::ContextKeys::securityPolicy, std::string{securityPolicyUri})};
  }

  // The HEL fixed what this connection can carry (Part 6 7.1.2.3): buffers below 8192 bytes are
  // allowed for the ECC policies only, so an RSA policy is refused here, before its certificate
  // work, as the allow-list refusal above is. None carries no signature and fits any buffer.
  auto policy = SecurityPolicy::create(securityPolicyUri);
  if (mEccOnlyTransport && requestedPolicy != SecurityPolicyId::None && !policy->is_ecc())
  {
    throw UaException{Status::BadSecurityPolicyRejected,
      ErrorDetail::build("SecurityPolicyNeedsLargerBuffers",
        "The HEL negotiated buffers below the 8192-byte minimum this security policy requires; only an "
        "ECC policy or None can be opened on this connection",
        "SecureChannel")
        .context(ua::ContextKeys::securityPolicy, std::string{securityPolicyUri})};
  }

  stream.seek_from_start(securityHeaderPosition);
  AsymmetricSecurityHeader securityHeader;
  securityHeader.decode(mContext->encodingLimits, decoder, *dependencies->crypto());

  return policy;
}

const TransportConnection* SecureChannel::transport_identity() const noexcept
{
  return mConnection ? mConnection->transport_identity() : nullptr;
}

bool SecureChannel::is_uninitialised() const
{
  return mContext->is_uninitialised();
}

bool SecureChannel::is_open() const
{
  return mContext->is_open();
}

void SecureChannel::close()
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    [](SecureChannel& self)
    {
      // If the channel is already gone the post no-ops; the destructor handles cleanup.
      self.mCloseReason = Status::Good;
      self.mConnectionCloseReason = ConnectionCloseReason::Orderly;
      if (self.mConnection)
      {
        try
        {
          self.mConnection->close_async();
        }
        catch (...)
        {
          self.handle_unexpected_exception("SecureChannel::close", std::current_exception());
        }
      }
    })();
}

void SecureChannel::reevaluate_certificate_async()
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    [](SecureChannel& self) { self.reevaluate_certificate_on_strand(); })();
}

void SecureChannel::reevaluate_certificate_on_strand()
{
  if (mClosingAfterResponse || mTerminalFailureCommitted || !mContext || !mContext->remoteCertificate ||
      !mContext->securityPolicy)
  {
    return;
  }
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
  // The same validation as the OpenSecureChannel (SecurityPolicy::validate_certificate_async): the
  // presented leaf and issuers, this channel's policy, the DefaultApplicationGroup as it is now. A channel
  // still opening holds the certificate already, so it is judged against the new lists too; whichever
  // verdict arrives second finds the channel closed or open and acts on that.
  mContext->securityPolicy->validate_certificate_async(*mContext,
    ua::async::post_borrowing(this,
      channel_strand(*mContext),
      logger,
      [certificate = mContext->remoteCertificate](SecureChannel& self, VoidResult result) mutable
      { self.on_certificate_reevaluated(std::move(certificate), std::move(result)); }));
}

void SecureChannel::on_certificate_reevaluated(
  shared_ptr<const X509Certificate> certificate, VoidResult result)
{
  if (result.is_good() || mClosingAfterResponse || mTerminalFailureCommitted || !mContext ||
      mContext->remoteCertificate != certificate)
  {
    return;
  }
  mTerminalFailureCommitted = true;
  const StatusCode status = result.status_code();
  mCloseReason = status;
  mConnectionCloseReason = ConnectionCloseReason::SecurityError;
  if (auto h = mHandler.lock())
  {
    auto logger = h->logger().with_category("secure_channel");
    log_exception(
      logger, LogLevel::Warning, "client certificate no longer trusted after a trust-list update", status);
    auto eh = h->observer();
    // Decision 27: the presented certificate with its Table 106 status.
    CertificateEventInfo info;
    info.remoteAddress = mRemoteAddress;
    info.certificate = certificate;
    const auto refusal = result.shared_detail();
    info.status = refusal && refusal->innerStatus != utils::to_underlying(Status::Good)
                    ? StatusCode{refusal->innerStatus}
                    : status;
    detail::emit_event(logger, eh, [&] { eh->on_certificate_rejected(info); });
  }
  report_fatal_error_to_sessions_and_clear(status);
  if (mConnection)
  {
    try
    {
      // Part 6 6.7.6: an Error message before the close; the status is masked as at the open.
      mConnection->send_error(detail::mask_pre_auth_status(status), "");
    }
    catch (...)
    {
      handle_unexpected_exception("SecureChannel::on_certificate_reevaluated", std::current_exception());
    }
  }
}

// Drain incoming message chunks. Self-tail-call: each step posts the next iteration onto the
// strand via the SecurityPolicy::decode_message_chunk_async / CertStore on-strand callbacks.
// Replaces the pre-flip mProcessRequests coroutine coroutine. mIncomingDrainScheduled gates
// single-flight per pump; an in-flight OPN flow keeps the drain paused until complete_open /
// fail_open re-arms it.
void SecureChannel::drain_incoming()
{
  // OPN owns the drain step until complete_open / fail_open re-arms.
  if (mOpenState)
  {
    return;
  }

  if (mIncomingMessageChunks.empty())
  {
    mIncomingDrainScheduled = false;
    return;
  }

  auto messageChunk = std::move(mIncomingMessageChunks.front());
  mIncomingMessageChunks.pop();

  // Backpressure release: once the queue drains below half the cap (hysteresis to avoid flapping),
  // resume the transport read pump if this channel paused it. Paired with the pause in
  // receive_message_chunk; safe to call once per drop because mReadPaused gates it.
  if (mReadPaused && mIncomingMessageChunks.size() <= mIncomingChunkQueueDepthCap / 2)
  {
    mReadPaused = false;
    if (mConnection)
    {
      mConnection->resume_reads();
    }
  }

  if (is_uninitialised())
  {
    try
    {
      mContext->securityPolicy = extract_security_policy_from_opn_message_chunk(messageChunk);
      check(mContext->securityPolicy);
      mContext->initialise_sequence_numbers(mContext->securityPolicy->uses_legacy_sequence_no());
    }
    catch (...)
    {
      handle_chunk_decode_failure(std::current_exception());
      return;
    }

    if (mContext->securityPolicy->is_authenticated())
    {
      start_first_opn_cert_load(std::move(messageChunk));
      return;
    }
  }

  start_decode_chunk(std::move(messageChunk));
}

void SecureChannel::start_first_opn_cert_load(std::vector<byte> messageChunk)
{
  try
  {
    auto channelHandler = mHandler.lock();
    check(channelHandler);
    auto store = channelHandler->default_application_group_certificate_store();
    check(store);

    store->get_application_certificates_async(ua::async::post_borrowing(this,
      channel_strand(*mContext),
      channelHandler->logger().with_category("secure_channel"),
      [chunk = std::move(messageChunk)](
        SecureChannel& self, CertificateStore::ApplicationCertificateListResult result) mutable
      { self.on_first_opn_cert_loaded(std::move(result), std::move(chunk)); }));
  }
  catch (...)
  {
    handle_chunk_decode_failure(std::current_exception());
  }
}

void SecureChannel::on_first_opn_cert_loaded(
  CertificateStore::ApplicationCertificateListResult result, std::vector<byte> messageChunk)
{
  if (!result.is_good())
  {
    handle_chunk_decode_failure(std::make_exception_ptr(UaException{Status::BadUnexpectedError,
      make_error_detail("CertificateRetrievalFailed",
        "Could not retrieve application certificates from certificate store",
        "SecureChannel",
        ua::security_internal::not_good_store_answer_detail(result.status_code(), "SecureChannel"))}));
    return;
  }

  try
  {
    mApplicationCertificates = std::move(result).value();

    // Get corresponding local certificate and key pair
    auto certAndKeys =
      stack_utils::get_local_cert_and_keys(mApplicationCertificates, mContext->securityPolicy->id());
    mContext->localCertificate = certAndKeys.certificate;
    mContext->localKeyPair = certAndKeys.keys;
    mContext->localIssuerCertificates = certAndKeys.issuerCertificates;
  }
  catch (...)
  {
    handle_chunk_decode_failure(std::current_exception());
    return;
  }

  start_decode_chunk(std::move(messageChunk));
}

void SecureChannel::start_decode_chunk(std::vector<byte> messageChunk)
{
  mDecodingOpnChunk = messageChunk.size() >= 3 && static_cast<char>(messageChunk[0]) == 'O' &&
                      static_cast<char>(messageChunk[1]) == 'P' && static_cast<char>(messageChunk[2]) == 'N';
  try
  {
    auto handlerForLog = mHandler.lock();
    auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
    mContext->securityPolicy->decode_message_chunk_async(mContext,
      ByteString{span<const byte>{messageChunk}},
      ua::async::post_borrowing(this,
        channel_strand(*mContext),
        logger,
        [](SecureChannel& self, DecodedMessageChunkResult result)
        { self.on_chunk_decoded(std::move(result)); }));
  }
  catch (...)
  {
    handle_chunk_decode_failure(std::current_exception());
  }
}

void SecureChannel::on_chunk_decoded(DecodedMessageChunkResult result)
{
  // A channel that has committed a terminal failure acts on nothing more it receives: notably an
  // OpenSecureChannel whose certificate a trust-list re-evaluation refused while the open-time
  // validation was still running (on_certificate_reevaluated) is not answered. Cost: one bool test per
  // decoded chunk.
  if (mTerminalFailureCommitted)
    return;
  if (!result.is_good())
  {
    handle_chunk_decode_failure(std::make_exception_ptr(
      UaException{result.is_bad() ? result.status_code().as_status() : Status::BadInternalError,
        make_error_detail("MessageChunkDecodeFailed",
          "SecurityPolicy failed to decode incoming message chunk",
          "SecureChannel",
          result.status_code())}));
    return;
  }

  optional<std::pair<uint32_t, ByteString>> messageBody;
  try
  {
    messageBody = std::move(result).value();
  }
  catch (...)
  {
    handle_chunk_decode_failure(std::current_exception());
    return;
  }

  if (messageBody.has_value())
  {
    const span<const byte> bodySpan = messageBody->second;
    receive_request_message(messageBody->first, std::vector<byte>{bodySpan.begin(), bodySpan.end()});
    // receive_request_message decides whether to advance the drain (sync handler) or pause
    // it (OPN flow); do nothing here.
    return;
  }

  // Chunk decoded but no complete body yet - continue draining.
  drain_incoming();
}

void SecureChannel::handle_chunk_decode_failure(std::exception_ptr ex)
{
  auto er = ::ua::exception_to_status_code(ex);
  auto sc = er;

  if (mTerminalFailureCommitted)
    return;
  mTerminalFailureCommitted = true;

  // A failed secure-chunk decode invalidates the channel's framing/security state. Sessions must
  // observe the rich cause before their channel registrations are discarded. Commit the reason
  // before fanout, then restore it after secondary transport/observer handling because those
  // callbacks may synchronously report a generic shutdown reason.
  mCloseReason = sc;
  report_fatal_error_to_sessions_and_clear(sc);

  if ((sc.as_status() == Status::BadSecurityPolicyRejected ||
        sc.as_status() == Status::BadSecurityModeRejected) &&
      mContext && mContext->is_uninitialised())
  {
    // A refused FIRST OpenSecureChannel is the peer's doing, not an internal error (H-D2): it is
    // counted as a rejected secure channel, reported through on_secure_channel_open_failed, logged
    // at Warning and answered with the masked ERR, as a refusal decided after the request is decoded
    // is. A renewal on an open channel is not an open failure and keeps its existing handling.
    if (auto h = mHandler.lock())
    {
      auto logger = h->logger().with_category("secure_channel");
      log_exception(logger, LogLevel::Warning, "OpenSecureChannel rejected", er);
      if (auto ctrs = h->secure_channel_counters())
        ctrs->rejectedCount.fetch_add(1, std::memory_order_relaxed);
      auto eh = h->observer();
      if (eh && mContext)
      {
        auto info = build_channel_event_info(*mContext, mRemoteAddress);
        detail::emit_event(logger, eh, [&] { eh->on_secure_channel_open_failed(info, sc); });
      }
    }
    mConnectionCloseReason = ConnectionCloseReason::SecurityError;
    if (mConnection)
    {
      mConnection->send_error(detail::mask_pre_auth_status(sc), "");
    }
  }
  else if (is_certificate_error(sc))
  {
    // Certificate errors are client-caused, not internal SDK errors.
    // Emit on_certificate_rejected but not on_internal_error.
    if (auto h = mHandler.lock())
    {
      auto logger = h->logger().with_category("secure_channel");
      log_exception(logger, LogLevel::Warning, "certificate rejected", er);

      auto eh = h->observer();
      // Decision 27: the presented OPN sender certificate with its Table 106 status (the server checks no
      // host name or URI at OPN).
      CertificateEventInfo info;
      info.remoteAddress = mRemoteAddress;
      info.certificate = mContext ? mContext->remoteCertificate : nullptr;
      info.status = sc;
      detail::emit_event(logger, eh, [&] { eh->on_certificate_rejected(info); });
    }
    mConnectionCloseReason = ConnectionCloseReason::SecurityError;
    if (mConnection)
    {
      // Part 6 6.7.6: server SHALL send a transport error message before closing. Mask the status to avoid
      // leaking certificate validation details - except an unrecognised ReceiverCertificateThumbprint, which
      // Part 6 6.7.6 reports as Bad_CertificateInvalid and Part 4 6.7 makes the client's cue to fetch the new
      // Server Certificate with GetEndpoints. It names only the server's own certificate, which GetEndpoints
      // publishes, never the client's (owner decision D-d). Cost: one walk of the refusal's detail chain.
      bool unknownReceiverThumbprint = false;
      for (const auto& link : ErrorChainView{sc})
        unknownReceiverThumbprint =
          unknownReceiverThumbprint || link.code == "ReceiverCertificateThumbprintUnknown";
      mConnection->send_error(unknownReceiverThumbprint ? StatusCode{Status::BadCertificateInvalid}
                                                        : detail::mask_pre_auth_status(sc),
        "");
    }
  }
  else
  {
    handle_unexpected_exception("SecureChannel::process_request_message_chunks", ex);
  }
  mCloseReason = sc;
  // Decode failure terminates the drain; mIncomingDrainScheduled is left true to inhibit
  // re-entry by an inbound chunk (the channel is closing).
}

// Drain outgoing responses. Self-tail-call via SecurityPolicy::encode_message_async callbacks.
// Replaces the pre-flip mProcessResponses coroutine coroutine. mOutgoingDrainScheduled gates
// single-flight; new responses queued mid-pump enqueue without re-arming.
void SecureChannel::drain_outgoing()
{
  // Test/support path: allow a SecureChannel to exist without an attached ConnectionProtocol.
  // Leave queued responses available for in-process tests.
  if (!mConnection)
  {
    mOutgoingDrainScheduled = false;
    return;
  }

  if (mOutgoingMessages.empty())
  {
    mOutgoingDrainScheduled = false;
    return;
  }

  auto message = std::move(mOutgoingMessages.front());
  mOutgoingMessages.pop();

  // An OpenSecureChannel response is identified by its type, not by the channel state: complete_open
  // marks the channel Open before the response is queued.
  const bool isOpenSecureChannelResponse =
    std::dynamic_pointer_cast<const OpenSecureChannelResponse>(message.second) != nullptr;
  try
  {
    auto requestId = message.first;
    auto handlerForLog = mHandler.lock();
    auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
    mContext->securityPolicy->encode_message_async(
      mContext,
      requestId,
      message.second,
      // The observer is copied, not referenced: this sink is handed to the encoder and may outlive
      // the channel, which is why its sibling capture of mConnection is by value too.
      [connection = mConnection, observer = mChunkEgressObserver, requestId](ByteString messageChunk)
      {
        if (observer)
        {
          observer(requestId, std::chrono::steady_clock::now());
        }
        const span<const byte> s = messageChunk;
        connection->send_message_chunk(std::vector<byte>{s.begin(), s.end()});
      },
      ua::async::post_borrowing(this,
        channel_strand(*mContext),
        logger,
        [requestId, isOpenSecureChannelResponse](SecureChannel& self, VoidResult result)
        { self.on_message_encoded(std::move(result), requestId, isOpenSecureChannelResponse); }));
  }
  catch (...)
  {
    // Encode kick-off failed before the async layer took ownership. Treat as encode failure
    // and try to send a ServiceFault for this requestId.
    auto er = ::ua::exception_to_status_code(std::current_exception());
    on_message_encoded(VoidResult{er, er.shared_detail()}, message.first, isOpenSecureChannelResponse);
  }
}

void SecureChannel::on_message_encoded(
  VoidResult result, uint32_t requestId, bool isOpenSecureChannelResponse)
{
  if (result.is_bad())
  {
    // Encoding failure (e.g. BadEncodingLimitsExceeded for very large responses).
    // The failure occurs during body serialization into a local buffer, before any
    // chunks are sent and before context state (sequence numbers, etc.) is modified.
    // It is safe to send a ServiceFault and continue encoding remaining messages.
    if (auto h = mHandler.lock())
    {
      auto logger = h->logger().with_category("secure_channel");
      auto er = result.status_code();
      log_exception(logger, LogLevel::Warning, "SecureChannel::on_message_encoded encoding", er);
    }

    // The OpenSecureChannel response itself failed (for example an own certificate chain too large for
    // one chunk): the client cannot read a ServiceFault in its place - it holds no token for this channel
    // yet - so the failure is reported with an Error message and the connection is closed (OPC 10000-6
    // 7.1.5). The same for a renewal's response: the OPN exchange is fatal to fail.
    if (isOpenSecureChannelResponse)
    {
      mCloseReason = result.status_code();
      if (mConnection)
      {
        mConnection->send_error(detail::mask_pre_auth_status(result.status_code()), "");
      }
      mOutgoingDrainScheduled = false;
      return;
    }

    try
    {
      auto fault = stack_utils::create_service_fault(nullptr, result.status_code());
      auto handlerForLog = mHandler.lock();
      auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};
      mContext->securityPolicy->encode_message_async(
        mContext,
        requestId,
        fault,
        [connection = mConnection](ByteString messageChunk)
        {
          const span<const byte> s = messageChunk;
          connection->send_message_chunk(std::vector<byte>{s.begin(), s.end()});
        },
        ua::async::post_borrowing(this,
          channel_strand(*mContext),
          logger,
          [requestId](SecureChannel& self, VoidResult faultResult)
          {
            if (faultResult.is_bad())
            {
              // Even the ServiceFault failed to encode - last resort: close the connection.
              self.handle_unexpected_exception("SecureChannel::on_message_encoded fault",
                std::make_exception_ptr(
                  UaException{faultResult.status_code().as_status(), faultResult.shared_detail()}));
              self.mOutgoingDrainScheduled = false;
              return;
            }
            if (self.close_if_response_was_the_last(requestId))
              return;
            self.drain_outgoing();
          }));
      return;
    }
    catch (...)
    {
      handle_unexpected_exception("SecureChannel::on_message_encoded", std::current_exception());
      mOutgoingDrainScheduled = false;
      return;
    }
  }

  if (close_if_response_was_the_last(requestId))
    return;
  drain_outgoing();
}

bool SecureChannel::close_if_response_was_the_last(uint32_t requestId)
{
  // The encoder handed every chunk of this response to the connection before its completion was posted
  // here, and the connection processes its submissions in order, so a close after pending writes now
  // follows the last of them. Cost: two optional compares per response.
  if (mReevaluateAfterResponseRequestId == requestId)
  {
    // The response is on its way; a refusal now closes after it (reevaluate_certificate_async).
    mReevaluateAfterResponseRequestId.reset();
    reevaluate_certificate_on_strand();
  }
  if (mCloseAfterResponseRequestId != requestId)
    return false;
  mCloseAfterResponseRequestId.reset();
  mClosingAfterResponse = true;
  mOutgoingDrainScheduled = false;
  std::queue<Response>{}.swap(mOutgoingMessages);  // responses queued behind it are not sent.
  mCloseReason = Status::Good;
  mConnectionCloseReason = ConnectionCloseReason::Orderly;
  if (mConnection)
  {
    try
    {
      mConnection->close_async({}, TransportConnection::CloseMode::AfterPendingWrites);
    }
    catch (...)
    {
      handle_unexpected_exception("SecureChannel::close_if_response_was_the_last", std::current_exception());
    }
  }
  return true;
}

void SecureChannel::register_session(
  NodeId authenticationToken, SendRequestMessageToSession sendRequest, ReportErrorToSession reportError)
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};

  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    [token = std::move(authenticationToken), send = std::move(sendRequest), error = std::move(reportError)](
      SecureChannel& self) mutable
    {
      // The session is (re)hosted here now - clear any stale transferred-away marker.
      self.mTransferredAwayTokens.erase(token);
      const bool isNew =
        self.mSessionCallbacks.emplace(token, SessionCallbacks{std::move(send), std::move(error)}).second;
      if (isNew)
        self.mSessionCount.fetch_add(1, std::memory_order_relaxed);
    })();
}

void SecureChannel::mark_session_transferred_away(const NodeId& authenticationToken)
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};

  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    [token = authenticationToken](SecureChannel& self) { self.mTransferredAwayTokens.insert(token); })();
}

void SecureChannel::unregister_session(const NodeId& authenticationToken)
{
  auto handlerForLog = mHandler.lock();
  auto logger = handlerForLog ? handlerForLog->logger().with_category("secure_channel") : Logger{};

  ua::async::post_borrowing(this,
    channel_strand(*mContext),
    logger,
    [token = authenticationToken](SecureChannel& self)
    {
      const auto erased = self.mSessionCallbacks.erase(token);
      if (erased > 0)
        self.mSessionCount.fetch_sub(1, std::memory_order_relaxed);
    })();
}

void SecureChannel::report_fatal_error_to_sessions(StatusCode status)
{
  const auto& detail = status.shared_detail();
  auto channelHandler = mHandler.lock();
  auto logger = channelHandler ? channelHandler->logger().with_category("secure_channel") : Logger{};
  for (auto& [token, callbacks] : mSessionCallbacks)
  {
    (void)token;
    ::ua::detail::invoke_user_callback(logger, callbacks.reportError, status, detail);
  }
}

void SecureChannel::report_fatal_error_to_sessions_and_clear(StatusCode status)
{
  report_fatal_error_to_sessions(std::move(status));
  mSessionCallbacks.clear();
  mSessionCount.store(0, std::memory_order_relaxed);
}

SecureChannelInfo SecureChannel::build_secure_channel_info() const
{
  auto policy = mContext->securityPolicy;
  shared_ptr<const X509Certificate> clientCert;
  std::vector<shared_ptr<const X509Certificate>> clientIssuers;
  if (mContext && mContext->remoteCertificate)
  {
    clientCert = mContext->remoteCertificate;
    clientIssuers = mContext->remoteIssuerCertificates;
  }
  return SecureChannelInfo(const_cast<SecureChannel*>(this)->weak_from_this(),
    policy,
    mContext->messageSecurityMode,
    mEndpointPolicyId,
    mUserIdentityTokens,
    std::move(clientCert),
    mContext->secureChannelId,
    mRemoteAddress,
    mEndpointUrl,
    mTransportProfileUri,
    std::move(clientIssuers),
    mContext->channelThumbprint,
    mContext->localCertificate);
}

}  // namespace ua::server
