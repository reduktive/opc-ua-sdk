// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_PROTOCOL_LIMITS_H
#define UA_CONNECTION_PROTOCOL_LIMITS_H

/// @file
/// @brief Connection-protocol buffer/message limits, callbacks, and framing constants.
/// @ingroup transport

#include "ua_built_in_types_fwd_decl.h"

namespace ua
{

/// What a client-role connection protocol has done with the transport when it reports a fatal error
/// (the third argument of @ref ua::connection_protocol::ErrorCallback). A server-role protocol always
/// reports TransportClosed.
///
/// @ingroup transport
enum class FatalCloseDisposition
{
  /// The transport is closed or closing and nothing more can be written: the handshake had not
  /// completed, the socket failed, or the server sent ERR.
  TransportClosed,
  /// The transport is still writable and its reads have stopped. The SecureChannel that delegated the
  /// close may send a secured CloseSecureChannel request (Part 6 7.1.5) and then ask for the close; a
  /// fallback timer closes the transport if it does not.
  AwaitingClose
};

namespace connection_protocol
{

/// User-facing configuration limits offered during the Hello/ACK handshake.
///
/// These are the local side's proposed limits before negotiation. A single
/// @ref maxBufferSize is used symmetrically for both the send and receive
/// buffer in the Hello/ACK exchange. All sizes are in bytes except
/// @ref maxChunkCount, which is a count.
///
/// @ingroup transport
struct Limits
{
  constexpr static uint32_t defaultBufferSize{65536};  ///< Default send/receive buffer size, in bytes.
  constexpr static uint32_t defaultMaxMessageSize{
    16 * 1024 * 1024};  ///< Default maximum message size, in bytes.
  constexpr static uint32_t defaultMaxChunkCount{5000};  ///< Default maximum number of chunks per message.

  /// Compares two limit sets field by field.
  /// @return true when all fields are equal; false otherwise.
  bool operator==(const Limits&) const = default;

  uint32_t maxBufferSize{defaultBufferSize};  ///< Proposed send/receive buffer size, in bytes.
  uint32_t maxMessageSize{defaultMaxMessageSize};  ///< Maximum assembled message size, in bytes.
  uint32_t maxChunkCount{defaultMaxChunkCount};  ///< Maximum number of chunks per message.
};

/// Effective limits agreed by the Hello/ACK exchange and reported to the SecureChannel layer.
///
/// Unlike @ref Limits, the values here are directional: they distinguish the
/// constraints that apply to outgoing traffic from those that apply to
/// incoming traffic, as resolved from the local proposal and the peer's reply.
/// Size fields are in bytes; chunk-count fields are counts. A value of `0` in a
/// maximum field means "no limit".
///
/// @ingroup transport
struct NegotiatedLimits
{
  /// Compares two negotiated limit sets field by field.
  /// @return true when all fields are equal; false otherwise.
  bool operator==(const NegotiatedLimits&) const = default;

  uint32_t sendBufferSize{0};  ///< Negotiated outgoing buffer size, in bytes.
  uint32_t receiveBufferSize{0};  ///< Negotiated incoming buffer size, in bytes.
  uint32_t sendMaxMessageSize{0};  ///< Peer's limit on outgoing message size, in bytes (0 = no limit).
  uint32_t sendMaxChunkCount{0};  ///< Peer's limit on outgoing chunk count (0 = no limit).
  uint32_t recvMaxMessageSize{0};  ///< Local limit on incoming message size, in bytes (0 = no limit).
  uint32_t recvMaxChunkCount{0};  ///< Local limit on incoming chunk count (0 = no limit).
  /// ProtocolVersion the client's Hello named. The Acknowledge answers with version 0 whatever was asked
  /// (0 is the only version and the lowest), and the OpenSecureChannel request must name the same version
  /// as the Hello (Part 6 6.7.4).
  uint32_t helloProtocolVersion{0};
};

/// Invoked when a complete message chunk has been received.
///
/// The `StatusCode` reports the outcome; on success the moved-in buffer
/// holds the chunk bytes, whose ownership transfers to the callback.
using MessageChunkReceivedCallback = std::function<void(StatusCode, std::vector<byte>&&)>;

/// Invoked when the connection protocol encounters an error.
///
/// The `StatusCode` identifies the failure and the `string_view` carries a
/// human-readable reason. The referenced text is borrowed: it is only valid for
/// the duration of the call, so a handler that needs to retain the reason must
/// copy it into owned storage before returning. The @ref ua::FatalCloseDisposition
/// says whether the transport is already closing or is left writable for a
/// CloseSecureChannel request; a handler that did not delegate the close ignores it.
using ErrorCallback = std::function<void(StatusCode, string_view, FatalCloseDisposition)>;

constexpr size_t headerSize{8};  ///< Size of the message header, in bytes.
constexpr size_t messageTypeSize{3};  ///< Size of the message-type field, in bytes.
constexpr size_t acknowledgeSize{28};  ///< Size of an Acknowledge (ACK) message body, in bytes.
constexpr size_t maxUrlSize{4096};  ///< Maximum length of an endpoint URL, in bytes.

/// Maximum ReverseHello message size, in bytes.
///
/// Header (8 bytes) plus two UA Binary strings, each a 4-byte length prefix
/// followed by up to `maxUrlSize` bytes.
constexpr size_t maxReverseHelloSize{headerSize + 2 * (sizeof(uint32_t) + maxUrlSize)};

constexpr uint32_t eccMinBufferSize{1024};  ///< Minimum buffer size for ECC security policies, in bytes.
constexpr uint32_t nonEccMinBufferSize{
  8192};  ///< Minimum buffer size for non-ECC security policies, in bytes.

}  // namespace connection_protocol

}  // namespace ua

#endif  // !UA_CONNECTION_PROTOCOL_LIMITS_H
