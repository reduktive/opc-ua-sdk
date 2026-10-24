// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CHANNEL_ROLE_H
#define UA_CHANNEL_ROLE_H

/// @file
/// @brief Which side of a secure channel a participant is.
///
/// Split into its own header so that both @ref ua::SecureChannelContext (which stores the role) and
/// @ref ua::SecurityPolicy (which takes it as a key-derivation parameter) can name the type without
/// one including the other.

#include "ua_status.h"

namespace ua
{

/// Identifies whether a secure channel participant is the server or the client.
///
/// Two uses, both direction-dependent:
///
/// - **Symmetric key derivation.** The server and client derive complementary key sets from the same
///   nonce pair, and the role selects which half each side owns.
/// - **Reporting an over-size outgoing message.** OPC 10000-4 section 5.3 names a different status for each
///   direction: the Server returns `Bad_ResponseTooLarge` for a response that exceeds the limit the
///   Client stated, and the Client Communication Stack reports `Bad_RequestTooLarge` before sending a
///   request that exceeds the Server's. The size check itself is shared by both sides, so the role is
///   what keeps the reported status honest.
/// @ingroup security
enum class ChannelRole
{
  Server,  ///< This participant is the secure channel server.
  Client  ///< This participant is the secure channel client.
};

/// The status to report when an outgoing message exceeds the peer's stated maximum.
///
/// OPC 10000-4 section 5.3 names a different code for each direction, and the size check is shared by both
/// sides, so this is what keeps the reported status honest: a caller whose REQUEST was too large must
/// not be told "response too large".
///
/// @param role Which side is sending.
/// @return `Bad_RequestTooLarge` when the client is sending a request, `Bad_ResponseTooLarge` when
///         the server is sending a response.
[[nodiscard]] constexpr Status outgoing_too_large_status(ChannelRole role) noexcept
{
  return (role == ChannelRole::Client) ? Status::BadRequestTooLarge : Status::BadResponseTooLarge;
}

}  // namespace ua

#endif  // UA_CHANNEL_ROLE_H
