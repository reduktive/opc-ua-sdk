// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_tcp_endpoint_asio.h"

#include <algorithm>

namespace ua::detail
{

TcpEndpoint from_asio(const asio::ip::tcp::endpoint& endpoint)
{
  const auto address = endpoint.address();

  if (address.is_v4())
  {
    const auto bytes = address.to_v4().to_bytes();
    return TcpEndpoint::v4(std::span<const std::uint8_t>{bytes.data(), bytes.size()}, endpoint.port());
  }

  const auto bytes = address.to_v6().to_bytes();
  return TcpEndpoint::v6(std::span<const std::uint8_t>{bytes.data(), bytes.size()}, endpoint.port());
}

asio::ip::tcp::endpoint to_asio(const TcpEndpoint& endpoint)
{
  if (endpoint.version() == TcpEndpoint::IpVersion::V4)
  {
    asio::ip::address_v4::bytes_type bytes{};
    const auto addr = endpoint.address();
    std::copy(addr.begin(), addr.end(), bytes.begin());
    return asio::ip::tcp::endpoint{asio::ip::address_v4{bytes}, endpoint.port()};
  }

  asio::ip::address_v6::bytes_type bytes{};
  const auto addr = endpoint.address();
  std::copy(addr.begin(), addr.end(), bytes.begin());
  return asio::ip::tcp::endpoint{asio::ip::address_v6{bytes}, endpoint.port()};
}

}  // namespace ua::detail
