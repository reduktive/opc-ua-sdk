// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Conversions between @ref ua::TcpEndpoint and the Boost.Asio TCP endpoint type.
/// @ingroup transport

#ifndef UA_TCP_ENDPOINT_ASIO_H
#define UA_TCP_ENDPOINT_ASIO_H

#include "ua_tcp_endpoint.h"

#include <boost/asio/ip/tcp.hpp>

namespace ua::detail
{

namespace asio = boost::asio;

/// Converts a Boost.Asio TCP endpoint into the SDK's transport-agnostic @ref ua::TcpEndpoint.
///
/// The address family of @p endpoint selects the result's @ref ua::TcpEndpoint::IpVersion (V4 or
/// V6); the address bytes and port are copied by value, so the returned endpoint shares no state
/// with @p endpoint. Keeps Boost.Asio types out of the SDK's public transport surface.
///
/// @param endpoint Asio endpoint to convert.
/// @return The equivalent @ref ua::TcpEndpoint.
/// @see to_asio
/// @ingroup transport
[[nodiscard]] TcpEndpoint from_asio(const asio::ip::tcp::endpoint& endpoint);

/// Converts an SDK @ref ua::TcpEndpoint into a Boost.Asio TCP endpoint.
///
/// This is the inverse of @ref from_asio. The endpoint's @ref ua::TcpEndpoint::IpVersion selects
/// the Asio address family, and the address bytes and port are copied by value. Used at the
/// transport boundary where Asio sockets and acceptors are bound or connected.
///
/// @param endpoint SDK endpoint to convert.
/// @return The equivalent Boost.Asio endpoint.
/// @see from_asio
[[nodiscard]] asio::ip::tcp::endpoint to_asio(const TcpEndpoint& endpoint);

}  // namespace ua::detail

#endif  // !UA_TCP_ENDPOINT_ASIO_H
