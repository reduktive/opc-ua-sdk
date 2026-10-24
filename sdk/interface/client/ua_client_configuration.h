// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-wide configuration defaults applied to channels, sessions, and requests.
/// @ingroup client

#ifndef UA_CLIENT_CONFIGURATION_H
#define UA_CLIENT_CONFIGURATION_H

#include "ua_includes.h"
#include "ua_client_diagnostic_policy.h"
#include "ua_reverse_connect_config.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace ua::client
{

/// Client-wide configuration defaults.
///
/// Each field supplies the default used when a per-call configuration struct leaves the
/// corresponding option unset; an explicit per-call value always takes precedence. The
/// struct is plain configuration data with no behaviour and no ownership of external
/// resources - it is copied into the @ref Client at construction time.
/// @ingroup client
struct ClientConfig
{
  /// Default timeout applied to every service call, in milliseconds.
  ///
  /// Sent as the request's `timeoutHint` when the caller leaves it 0; overridable per request via
  /// `RequestHeader::timeout_hint`. The Client waits for the response for the hint plus a tenth of it,
  /// and at least 500 ms more, before failing the call with Bad_Timeout, so that a Server answering at
  /// the hint (OPC 10000-4 section 7.33) is still heard.
  std::chrono::milliseconds defaultServiceTimeout{std::chrono::seconds{10}};

  /// Default requested session timeout, in milliseconds.
  ///
  /// The actual session lifetime is negotiated with the server, which may return a shorter
  /// value. Overridable per call via `CreateSessionConfig`.
  std::chrono::milliseconds defaultSessionTimeout{std::chrono::minutes{20}};

  /// Default requested secure channel lifetime, in milliseconds.
  ///
  /// The actual lifetime is negotiated with the server and the channel is renewed before it
  /// expires. Overridable per call via `OpenChannelConfig`.
  std::chrono::milliseconds defaultChannelLifetime{std::chrono::hours{1}};

  /// Maximum incoming message chunks buffered per channel awaiting decode before the client
  /// **read-pauses** the transport (stops re-arming the socket read until the queue drains below half
  /// this depth). Graceful backpressure against a server that floods responses faster than the client
  /// decodes - no chunk is dropped, no error is raised. Bounds per-channel memory to roughly this many
  /// times the negotiated ReceiveBufferSize. Values below 1 are treated as 1.
  uint32_t incomingChunkQueueDepth{64};

  /// Maximum buffers queued for transmission per outbound connection before `async_write` fails closed
  /// with `Bad_TcpNotEnoughResources`. Bounds client-side send-queue growth when a server reads slowly.
  /// Mirrors the server's `ResourceLimits::writeQueueDepthPerConnection`; `WriteQueueDepthPerConnection`
  /// in the process configuration file.
  uint32_t writeQueueDepthPerConnection{4096};

  /// Bytes queued or in flight for transmission per outbound (and reverse-accepted) connection at or
  /// beyond which a NEW message is refused (`Bad_TcpNotEnoughResources`); the depth cap bounds the
  /// buffer count, this bounds the bytes. Applied at a message's first chunk only, so a message that
  /// was admitted is sent whole. Values below 1 are treated as 1, which admits one message at a time.
  /// Mirrors the server's `ResourceLimits::writeQueueBytesPerConnection`; `WriteQueueBytesPerConnection`
  /// in the process configuration file.
  uint32_t writeQueueBytesPerConnection{16u * 1024u * 1024u};

  /// Optional overrides for the client's inbound (server-response) decode size caps. `nullopt` keeps the
  /// bounded-floor defaults from `make_encoding_limits` (1 MB string / 16 MB byte-string / 65535 array).
  /// Raise these to accept larger payloads from a trusted server; lower them to harden against a hostile
  /// one. The mandatory decode-bomb protection (the floor) applies regardless - these only tune it.
  optional<uint32_t> maxInboundStringLength;
  /// Optional inbound byte-string size cap (bytes); `nullopt` keeps the bounded-floor default (16 MB).
  optional<uint32_t> maxInboundByteStringLength;
  /// Optional inbound array element-count cap; `nullopt` keeps the bounded-floor default (65535).
  optional<uint32_t> maxInboundArrayLength;

  /// Default `returnDiagnostics` bitmask stamped on every request header.
  ///
  /// A value of `0` requests no diagnostics; `0xFFFF` requests all diagnostic fields. The
  /// default is not applied to a request whose `return_diagnostics` field is already
  /// non-zero, so per-request overrides are preserved.
  uint32_t defaultReturnDiagnostics{0};

  /// Client-wide defaults for diagnostic handling on direct tier-0 Session service calls.
  ClientDiagnosticPolicy diagnostics;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_CONFIGURATION_H
