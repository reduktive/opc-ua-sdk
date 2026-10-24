// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Observer interface for server lifecycle, security, and transport events.
/// @ingroup server

#ifndef UA_SERVER_OBSERVER_H
#define UA_SERVER_OBSERVER_H

#include "ua_built_in_types_fwd_decl.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_status_code.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace ua
{
class X509Certificate;
}

namespace ua::server
{

/// What a server observer is told about one certificate event: a certificate refused, or a
/// validation error suppressed by the configured trust-list options (decision 27).
///
/// Carries the certificate itself because the AuditCertificateEventType's Certificate property is
/// Mandatory (OPC 10000-5 section 6.4.12), and the host name or URI that failed to match because
/// AuditCertificateDataMismatchEventType reports them (section 6.4.13).
/// @ingroup server
struct CertificateEventInfo
{
  std::string remoteAddress;  ///< Peer transport address (host:port); empty when not known.
  /// The certificate the event concerns (the leaf the peer presented); null when it could not be
  /// decoded.
  std::shared_ptr<const ua::X509Certificate> certificate;
  /// The refusal, or the suppressed error, as an OPC UA certificate status (Table 106).
  StatusCode status;
  /// The host name the certificate failed to match, for Bad_CertificateHostNameInvalid.
  std::optional<std::string> invalidHostname;
  /// The application URI the certificate failed to match, for Bad_CertificateUriInvalid.
  std::optional<std::string> invalidUri;
};

/// Context describing a secure channel for a channel-lifecycle event.
///
/// Snapshot of the channel state at the moment the event fired. Fields sourced
/// from the OpenSecureChannel (OPN) request reflect the values seen on the wire
/// at that time; later requests on the same channel do not retroactively update
/// a previously delivered snapshot.
/// @ingroup server
struct SecureChannelEventInfo
{
  uint32_t secureChannelId{};  ///< Server-assigned secure channel identifier.
  std::string securityPolicyUri;  ///< Negotiated security policy URI.
  MessageSecurityMode messageSecurityMode{};  ///< Negotiated message security mode.
  std::string remoteAddress;  ///< Peer transport address (host:port).
  std::string auditEntryId;  ///< Audit entry id from the request header (may be empty).
  ByteString clientCertificate;  ///< DER-encoded client certificate from the OPN request.
  std::string clientCertificateThumbprint;  ///< SHA-1 thumbprint of the client certificate.
  uint32_t requestedLifetime{0};  ///< Channel lifetime requested in the OPN request, in ms.
};

/// Context describing a session for a session-lifecycle or authentication event.
///
/// Snapshot of the session state at the moment the event fired. Some fields are
/// only populated once the corresponding handshake step has run: identity-related
/// fields are empty before authentication, and the ActivateSession fields are set
/// only after activation.
/// @ingroup server
struct SessionEventInfo
{
  NodeId sessionId;  ///< Server-assigned session identifier.
  std::string sessionName;  ///< Human-readable session name from CreateSession.
  uint32_t secureChannelId{};  ///< Identifier of the secure channel carrying the session.
  std::string remoteAddress;  ///< Peer transport address (host:port).
  std::string auditEntryId;  ///< Audit entry id from the request header (may be empty).
  std::string clientUserId;  ///< Authenticated user identity; empty before authentication.

  // G8: CreateSession-specific fields
  ByteString clientCertificate;  ///< DER-encoded client certificate from CreateSession.
  std::string clientCertificateThumbprint;  ///< SHA-1 thumbprint of the client certificate.
  double revisedSessionTimeout{0.0};  ///< Session timeout granted by the server, in ms.
  std::string endpointUrl;  ///< EndpointUrl supplied to CreateSession; empty for other events.
  bool endpointUrlMismatch{false};  ///< The URL HostName was outside the Server certificate HostNames.

  // G9: ActivateSession-specific fields
  std::shared_ptr<const Structure> userIdentityToken;  ///< User identity token (ExtensionObject
                                                       ///< body); null before activation.
};

/// Reason a transport connection was closed.
///
/// Conveyed to `ServerObserver::on_connection_closed` alongside the wire
/// `StatusCode` for the failure.
enum class ConnectionCloseReason
{
  Orderly,  ///< Normal channel close (CloseSecureChannel or token expiry).
  TransportError,  ///< TCP connection dropped unexpectedly.
  ProtocolError,  ///< HEL/ACK or UASC protocol violation.
  SecurityError,  ///< Certificate or security policy error.
  MaxConnections,  ///< Rejected because the maximum connection limit was reached.
  ServerShutdown,  ///< Connection closed because the server is shutting down.
  InternalError  ///< Unexpected exception during processing.
};

/// Identity of an event the server dropped from its internal dispatch backlog.
///
/// Conveyed to @ref ServerObserver::on_event_dispatch_dropped when the EventBus's pending-dispatch
/// cap is exceeded under sustained overload and the oldest queued event is discarded before it
/// reaches any MonitoredItem. Carries enough to identify and classify the lost event - in particular
/// @ref eventType lets the host detect an audit event (an `AuditEventType` subtype) and persist the
/// record out-of-band if audit integrity matters.
/// @ingroup server
struct DroppedEventInfo
{
  NodeId eventType;  ///< EventType NodeId of the dropped event (used to classify, e.g. audit).
  NodeId sourceNode;  ///< NodeId of the node that was the source of the dropped event.
  std::string sourceName;  ///< Source name of the dropped event (may be empty).
  uint16_t severity{0};  ///< Severity of the dropped event.
};

/// Receives notifications of server lifecycle, security, and transport events.
///
/// Implement this interface and register it with the server to observe secure
/// channel and session lifecycle, transport connections, security rejections,
/// reverse-connect activity, shutdown, and internal errors. Every hook has an
/// empty default, so a subclass overrides only the events it cares about.
///
/// Hooks are invoked by the server on an unspecified internal thread or strand;
/// an override must not block and must not assume any particular calling
/// context.
///
/// Lifetime: @ref Server::set_observer takes a `std::shared_ptr` and retains it, so
/// the server CO-OWNS the observer and it cannot be destroyed while registered. The
/// hazard is the reverse cycle: an observer that captures the `Server` handle (or
/// anything the server owns) keeps the server alive past its intended shutdown.
/// Capture weakly, or capture only what a hook needs; `set_observer(nullptr)`
/// releases the server's reference.
/// @ingroup server
class ServerObserver
{
public:
  ServerObserver() = default;
  ServerObserver(const ServerObserver&) = delete;
  ServerObserver& operator=(const ServerObserver&) = delete;
  ServerObserver(ServerObserver&&) = delete;
  ServerObserver& operator=(ServerObserver&&) = delete;
  virtual ~ServerObserver() = default;

  // Secure channel lifecycle

  /// Called when a secure channel has been successfully opened.
  ///
  /// @param info Snapshot of the newly opened channel.
  virtual void on_secure_channel_opened([[maybe_unused]] const SecureChannelEventInfo& info)
  {}

  /// Called when a secure channel has been closed.
  ///
  /// @param info   Snapshot of the channel being closed.
  /// @param reason Status code describing the close cause; good on an orderly close.
  virtual void on_secure_channel_closed(
    [[maybe_unused]] const SecureChannelEventInfo& info, [[maybe_unused]] StatusCode reason)
  {}

  /// Called when an existing secure channel's security token has been renewed.
  ///
  /// @param info Snapshot of the renewed channel.
  virtual void on_secure_channel_renewed([[maybe_unused]] const SecureChannelEventInfo& info)
  {}

  /// Called when an attempt to open a secure channel failed.
  ///
  /// @param info   Snapshot of the channel as far as it was established.
  /// @param reason Status code describing the failure.
  virtual void on_secure_channel_open_failed(
    [[maybe_unused]] const SecureChannelEventInfo& info, [[maybe_unused]] StatusCode reason)
  {}

  /// Called when an attempt to renew a secure channel's token failed.
  ///
  /// @param info   Snapshot of the channel whose renewal failed.
  /// @param reason Status code describing the failure.
  virtual void on_secure_channel_renew_failed(
    [[maybe_unused]] const SecureChannelEventInfo& info, [[maybe_unused]] StatusCode reason)
  {}

  // Session lifecycle

  /// Called when a session has been created (CreateSession completed).
  ///
  /// The session is not yet usable for general service calls until activated.
  ///
  /// @param info Snapshot of the created session.
  virtual void on_session_created([[maybe_unused]] const SessionEventInfo& info)
  {}

  /// Called when a CreateSession invocation has failed.
  ///
  /// @param info   Snapshot of the attempted session as far as it was established.
  /// @param reason Rich status describing the failure; any ErrorDetail is attached to this value.
  virtual void on_session_create_failed(
    [[maybe_unused]] const SessionEventInfo& info, [[maybe_unused]] StatusCode reason)
  {}

  /// Called when a session has been activated (ActivateSession completed).
  ///
  /// @param info Snapshot of the activated session, including user identity.
  virtual void on_session_activated([[maybe_unused]] const SessionEventInfo& info)
  {}

  /// Called when a session has been closed.
  ///
  /// @param info   Snapshot of the closed session.
  /// @param reason Status code describing the close cause; good on an orderly close.
  virtual void on_session_closed(
    [[maybe_unused]] const SessionEventInfo& info, [[maybe_unused]] StatusCode reason)
  {}

  /// Called when a session has been terminated for exceeding its timeout.
  ///
  /// @param info Snapshot of the timed-out session.
  virtual void on_session_timed_out([[maybe_unused]] const SessionEventInfo& info)
  {}

  // Transport

  /// Called when an inbound transport connection has been accepted.
  ///
  /// Fires before any secure channel is established on the connection.
  ///
  /// @param remoteAddress Peer transport address (host:port).
  virtual void on_connection_accepted([[maybe_unused]] const std::string& remoteAddress)
  {}

  /// Called when a transport connection has been closed.
  ///
  /// @param remoteAddress Peer transport address (host:port).
  /// @param reason        Categorised cause of the close.
  /// @param status        Wire status code associated with the close.
  virtual void on_connection_closed([[maybe_unused]] const std::string& remoteAddress,
    [[maybe_unused]] ConnectionCloseReason reason, [[maybe_unused]] StatusCode status)
  {}

  // Security

  /// Called when a client certificate has been rejected during validation.
  ///
  /// @param info The peer address, the refused certificate and the refusal status (with the
  ///             mismatched host name or URI where that was the refusal).
  virtual void on_certificate_rejected([[maybe_unused]] const CertificateEventInfo& info)
  {}

  /// Called when a certificate was accepted although validation found an error, because the
  /// configured trust-list options suppress that error. OPC 10000-4 section 6.1.3: a suppressed error
  /// is still reported through auditing. Called once per suppressed error.
  ///
  /// @param info The peer address, the accepted certificate and the suppressed error.
  virtual void on_certificate_error_suppressed([[maybe_unused]] const CertificateEventInfo& info)
  {}

  /// Called when authentication of a session's user identity failed.
  ///
  /// @param info   Snapshot of the session; @ref SessionEventInfo::clientUserId may be empty.
  /// @param reason Status code describing the authentication failure.
  virtual void on_authentication_failed(
    [[maybe_unused]] const SessionEventInfo& info, [[maybe_unused]] StatusCode reason)
  {}

  // Reverse connect

  /// Called when an outbound reverse-connect connection has been opened.
  ///
  /// @param targetName    Configured name of the reverse-connect target.
  /// @param remoteAddress Address of the client to which the server connected.
  virtual void on_reverse_connect_opened(
    [[maybe_unused]] const std::string& targetName, [[maybe_unused]] const std::string& remoteAddress)
  {}

  /// Called when a reverse-connect connection has been closed.
  ///
  /// @param targetName    Configured name of the reverse-connect target.
  /// @param remoteAddress Address of the client the connection was to.
  /// @param reason        Status code describing the close cause.
  virtual void on_reverse_connect_closed([[maybe_unused]] const std::string& targetName,
    [[maybe_unused]] const std::string& remoteAddress, [[maybe_unused]] StatusCode reason)
  {}

  /// Called when a secure channel has been established over a reverse-connect connection.
  ///
  /// @param targetName      Configured name of the reverse-connect target.
  /// @param secureChannelId Server-assigned identifier of the established channel.
  virtual void on_reverse_connect_channel_established(
    [[maybe_unused]] const std::string& targetName, [[maybe_unused]] uint32_t secureChannelId)
  {}

  // Shutdown

  /// Called when a server shutdown has been initiated.
  ///
  /// @param secondsTillShutdown Time remaining until shutdown completes, in seconds.
  /// @param reason              Localized reason for the shutdown.
  virtual void on_shutdown_initiated(
    [[maybe_unused]] uint32_t secondsTillShutdown, [[maybe_unused]] const LocalizedText& reason)
  {}

  /// Called when server shutdown has completed.
  virtual void on_shutdown_complete()
  {}

  // Infrastructure

  /// Called when an internal error has occurred that is not tied to a specific channel or session.
  ///
  /// @param status      Status code categorising the error.
  /// @param description Human-readable description of the error.
  virtual void on_internal_error(
    [[maybe_unused]] StatusCode status, [[maybe_unused]] const std::string& description)
  {}

  /// Called when the server drops an event from its internal dispatch backlog because the
  /// pending-dispatch cap was exceeded under sustained overload. The dropped event never reaches any
  /// MonitoredItem and is not signalled to clients (the per-MonitoredItem `EventQueueOverflowEventType`
  /// is a separate downstream mechanism). Fires once per dropped event. Use it to surface the loss
  /// (log/meter) or, when @ref DroppedEventInfo::eventType is an audit type, to persist the record to
  /// a durable audit log out-of-band.
  ///
  /// @param info Identity of the dropped event.
  virtual void on_event_dispatch_dropped([[maybe_unused]] const DroppedEventInfo& info)
  {}
};

}  // namespace ua::server

#endif  // !UA_SERVER_OBSERVER_H
