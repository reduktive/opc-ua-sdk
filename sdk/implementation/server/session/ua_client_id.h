// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief How a Client is identified for identity-token attack protection.

#ifndef UA_CLIENT_ID_H
#define UA_CLIENT_ID_H

#include <boost/asio/ip/address.hpp>
#include <string>
#include <variant>

namespace ua::server
{

class SecureChannelInfo;

/// The identity an identity lockout accumulates against.
///
/// OPC 10000-4 5.6.3 permits two identifiers and no others: the IP address of a Client on an
/// unsecured connection, and its ApplicationInstanceUri on a secured one. The address alternative
/// is an `asio::ip::address` rather than a string because that type cannot represent a port - a
/// port identifies the connection, so counting failures against one never accumulates across the
/// reconnects a password-guessing attack makes.
using ClientId = std::variant<boost::asio::ip::address, std::string>;

/// Derives the ClientId of a channel per Part 4 5.6.3.
ClientId derive_client_id(const SecureChannelInfo& channelInfo);

/// Renders a ClientId for logging.
inline std::string describe(const ClientId& client)
{
  if (const auto* address = std::get_if<boost::asio::ip::address>(&client))
  {
    return address->to_string();
  }
  return std::get<std::string>(client);
}

}  // namespace ua::server

#endif  // !UA_CLIENT_ID_H
