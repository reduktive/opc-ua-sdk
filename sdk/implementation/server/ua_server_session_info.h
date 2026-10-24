// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-session execution context handed to server service implementations.
/// @ingroup server

#ifndef UA_SERVER_SESSION_INFO_H
#define UA_SERVER_SESSION_INFO_H

#include "ua_server.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_server_configuration.h"
#include "ua_diagnostic_security_context.h"
#include "ua_session_registered_nodes.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace ua
{
class EventSink;
}

namespace ua::server
{

/// Read-only execution context that the server hands to a service for one session's requests.
///
/// Bundles the per-session dependencies a service implementation needs: the executor on which to
/// schedule asynchronous work, the @ref AddressSpace handle to read and mutate, the application and
/// server configuration, the request's security posture, a logger, and the optional event sink. Implemented
/// by the Session/SecureChannel shell; a service holds the context only for the lifetime of the request and
/// never owns the underlying server.
///
/// @ingroup server
class SessionInfo
{
public:
  SessionInfo() = default;
  SessionInfo(const SessionInfo&) = delete;
  SessionInfo& operator=(const SessionInfo&) = delete;
  SessionInfo(SessionInfo&&) = delete;
  SessionInfo& operator=(SessionInfo&&) = delete;

  virtual ~SessionInfo()
  {}

  /// Returns a handle to the server's address space for reading and mutating nodes.
  ///
  /// The handle is a lightweight value; the underlying graph is owned by the server and outlives the
  /// returned handle.
  ///
  /// @return A handle to the server's address space.
  virtual AddressSpace address_space() const = 0;

  /// Returns the application-wide configuration in effect for this session.
  ///
  /// The reference is owned by the server and remains valid for the duration of the request.
  ///
  /// @return The application-wide configuration in effect for this session.
  virtual const ::ua::ApplicationConfig& configuration() const = 0;

  /// Returns the server-specific configuration in effect for this session.
  ///
  /// The reference is owned by the server and remains valid for the duration of the request.
  ///
  /// @return The server-specific configuration in effect for this session.
  virtual const ::ua::server::ServerConfig& server_configuration() const = 0;

  /// Returns the request's security posture used to gate diagnostic exposure.
  ///
  /// Captures whether the session is authenticated and channel-secured and the effective diagnostic
  /// level, resolved at the Session/SecureChannel shell before the service runs.
  ///
  /// @return The request's security posture for gating diagnostic exposure.
  virtual DiagnosticSecurityContext diagnostic_security_context() const = 0;

  /// Returns the logger to use for this session's service work.
  ///
  /// @return The logger for this session's service work.
  virtual Logger logger() const = 0;

  /// Returns the server's event sink for audit-event emission, or null if unavailable.
  ///
  /// Shared, so that work which outlives the request - a StateMachine transition that completes after
  /// the Call's response - can hold it weakly and raise nothing once it has gone. Null once the server
  /// has been destroyed. Defaults to null; override to expose an event sink.
  ///
  /// @return The server's event sink, or null when unavailable.
  virtual std::shared_ptr<EventSink> event_sink() const
  {
    return nullptr;
  }

  /// Returns the maxResponseMessageSize the Client requested in CreateSession, or 0 when not used.
  ///
  /// OPC 10000-4 5.6.2.2: the maximum size, in bytes, of the body of any response message on this
  /// Session; the Server should answer a response that would exceed it with Bad_ResponseTooLarge. The
  /// value zero indicates that the parameter is not used, and services then bound their responses by
  /// the configured maximum message size instead. Defaults to 0; override to expose the negotiated
  /// value.
  ///
  /// @return The negotiated maxResponseMessageSize in bytes, or 0 when the Client did not set one.
  virtual uint32_t max_response_message_size() const
  {
    return 0;
  }

  /// The NodeIds this Session registered through namespaces' RegisterNodes delegates; created on first
  /// use, never null, and the same object for the SessionInfo's lifetime.
  std::shared_ptr<SessionRegisteredNodes> registered_nodes() const
  {
    const std::lock_guard lock{mRegisteredNodesMutex};
    if (!mRegisteredNodes)
    {
      mRegisteredNodes = std::make_shared<SessionRegisteredNodes>(logger());
    }
    return mRegisteredNodes;
  }

private:
  mutable std::mutex mRegisteredNodesMutex;
  mutable std::shared_ptr<SessionRegisteredNodes> mRegisteredNodes;
};

}  // namespace ua::server

#endif  // !UA_SERVER_SESSION_INFO_H
