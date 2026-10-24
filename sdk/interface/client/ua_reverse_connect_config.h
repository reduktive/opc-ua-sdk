// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Configuration and handle types for client-side reverse connect listeners.
/// @ingroup client

#ifndef UA_REVERSE_CONNECT_CONFIG_H
#define UA_REVERSE_CONNECT_CONFIG_H

#include "ua_result.h"
#include "ua_transport_address.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace ua::client
{

/// A Server permitted to reverse-connect to this listener.
///
/// Describes one entry in the listener's allow-list: an incoming ReverseHello is
/// accepted only if its `ServerUri` matches @ref serverUri and the advertised
/// `EndpointUrl` is one of @ref endpointUrls.
///
/// @ingroup client
struct ExpectedServer
{
  /// ApplicationUri of the Server, matched against the ReverseHello `ServerUri`.
  std::string serverUri;

  /// EndpointUrls the Server may advertise in its ReverseHello `EndpointUrl` field.
  ///
  /// An incoming connection is accepted only when its advertised EndpointUrl
  /// equals one of these entries.
  std::vector<std::string> endpointUrls;
};

/// Settings for a reverse connect listener that accepts Server-initiated connections.
///
/// Passed to @ref ua::client::CoreClient::start_reverse_connect_async (and its sync
/// variants) to open a listener that binds locally and waits for Servers in
/// @ref expectedServers to dial in with a ReverseHello.
///
/// @ingroup client
struct ReverseConnectListenerConfig
{
  /// Transport-qualified local address the listener binds to and accepts on.
  ua::transport::BindAddress bind;

  /// Allow-list of Servers permitted to reverse-connect to this listener.
  ///
  /// A reverse connection is accepted only if its ReverseHello matches one of
  /// these entries; an empty list accepts no Server.
  std::vector<ExpectedServer> expectedServers;

  /// Maximum number of validated reverse connections queued awaiting `open_channel`.
  ///
  /// Connections beyond this bound are rejected until the queue drains.
  uint32_t maxQueuedConnections{10};

  /// Maximum number of accepted connections that have not yet completed the ReverseHello/Hello/Acknowledge
  /// handshake, in total (CL-RC-007).
  ///
  /// A socket accepted beyond this bound is closed at accept. Each pending handshake holds a connection,
  /// buffers and a timer for up to @ref initialMessageTimeout, so without a bound any peer that can reach
  /// the listener could hold them open in numbers. Must be at least 1; `start` refuses 0.
  uint32_t maxPendingHandshakes{64};

  /// The same bound per remote IP address (CL-RC-007): a single peer cannot use the whole of
  /// @ref maxPendingHandshakes. It also bounds the connections from one address waiting in the queue
  /// of @ref maxQueuedConnections, so one peer cannot fill the queue either. Must be at least 1; `start`
  /// refuses 0.
  uint32_t maxPendingHandshakesPerAddress{8};

  /// Time allowed to receive the initial ReverseHello after TCP accept (spec C4).
  ///
  /// Measured in seconds. A connection that does not deliver a ReverseHello
  /// within this window is dropped.
  std::chrono::seconds initialMessageTimeout{30};
};

/// Opaque handle identifying an active reverse connect listener.
///
/// Returned by @ref ua::client::CoreClient::start_reverse_connect_async (and its sync
/// variants) and passed back to stop a specific listener. The handle is a small
/// value type that may be freely copied, stored, and compared; it owns no
/// resources and remains valid until the corresponding listener is stopped. A
/// default-constructed handle (`value == 0`) refers to no listener.
///
/// @ingroup client
struct ReverseConnectHandle
{
  std::uint64_t value{};  ///< Opaque listener identifier; `0` denotes no listener.

  /// Compares two handles for equality by their identifier value.
  ///
  /// @return `true` if both handles identify the same listener.
  friend bool operator==(ReverseConnectHandle, ReverseConnectHandle) = default;
};

/// Result of a reverse connect start operation: a @ref ReverseConnectHandle or an @ref ErrorDetail.
using ReverseConnectHandleResult = Result<ReverseConnectHandle>;

}  // namespace ua::client

#endif  // !UA_REVERSE_CONNECT_CONFIG_H
