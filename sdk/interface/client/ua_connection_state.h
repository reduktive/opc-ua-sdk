// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_STATE_H
#define UA_CONNECTION_STATE_H

/// @file
/// @brief The public lifecycle state of a tier-1 Connection (client, section 8.2A.3).
///
/// A public interface header: it is the return type of the public @ref ua::client::Connection::state()
/// (section 7.2, aliased there as @ref ua::client::ConnectionState). It also lets the upward
/// `ua::client::detail::SupportOps` interface (`ua_connection_ops.h`) and the
/// `ua::client::detail::ConnectionImpl` orchestrator (`ua_connection_impl.h`) name the enum without
/// an include cycle between them.
/// @ingroup client

namespace ua::client::detail
{

/// The public lifecycle state of a Connection (section 8.2A.3). A projection of the orchestrator's strand
/// state that is republished into `ConnectionInfo` on every visible transition.
enum class ConnectionState
{
  /// Constructed; the NamespaceArray bootstrap Read is in flight.
  Connecting,
  /// Bootstrap succeeded: wire ops dispatch through to the tier-0 session.
  Active,
  /// A reconnect is in flight (later slices own the FSM); wire ops queue in the dispatch gate.
  Reconnecting,
  /// Bootstrap or reconnect terminally failed.
  Failed,
  /// `close_async` is draining the gate / tier-0 session.
  Closing,
  /// Terminal: the Connection is closed; wire ops fail immediately.
  Closed,
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_STATE_H
