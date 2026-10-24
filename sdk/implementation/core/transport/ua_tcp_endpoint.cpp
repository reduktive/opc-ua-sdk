// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_tcp_endpoint.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"

#include <algorithm>
#include <charconv>
#include <string>

#include <boost/asio/ip/address.hpp>

namespace ua
{

namespace
{

[[nodiscard]] std::uint16_t parse_port(std::string_view portText)
{
  std::uint16_t port{};
  const auto* first = portText.data();
  const auto* last = portText.data() + portText.size();
  const auto [ptr, ec] = std::from_chars(first, last, port);
  if (ec != std::errc{} || ptr != last)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidEndpointUrl", "Invalid port text", "TcpEndpoint")
        .context(ua::ContextKeys::endpointPort, std::string{portText})};
  }
  return port;
}

}  // namespace

TcpEndpoint TcpEndpoint::v4(std::span<const std::uint8_t> addr, std::uint16_t port)
{
  if (addr.size() != 4)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidEndpointUrl", "IPv4 address requires 4 bytes", "TcpEndpoint")
        .context(ua::ContextKeys::sizeExpected, "4")
        .context(ua::ContextKeys::sizeActual, std::to_string(addr.size()))};
  }

  TcpEndpoint ep;
  ep.mVersion = IpVersion::V4;
  ep.mPort = port;
  std::copy_n(addr.begin(), 4, ep.mAddr.begin());
  return ep;
}

TcpEndpoint TcpEndpoint::v6(std::span<const std::uint8_t> addr, std::uint16_t port)
{
  if (addr.size() != 16)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidEndpointUrl", "IPv6 address requires 16 bytes", "TcpEndpoint")
        .context(ua::ContextKeys::sizeExpected, "16")
        .context(ua::ContextKeys::sizeActual, std::to_string(addr.size()))};
  }

  TcpEndpoint ep;
  ep.mVersion = IpVersion::V6;
  ep.mPort = port;
  std::copy_n(addr.begin(), 16, ep.mAddr.begin());
  return ep;
}

TcpEndpoint TcpEndpoint::from_bytes(std::span<const std::uint8_t> addr, std::uint16_t port)
{
  if (addr.size() == 4)
  {
    return v4(addr, port);
  }

  if (addr.size() == 16)
  {
    return v6(addr, port);
  }

  throw UaException{Status::BadInvalidArgument,
    ErrorDetail::build("InvalidEndpointUrl", "Address must be 4 (IPv4) or 16 (IPv6) bytes", "TcpEndpoint")
      .context(ua::ContextKeys::sizeActual, std::to_string(addr.size()))};
}

TcpEndpoint TcpEndpoint::from_string(std::string_view address, std::uint16_t port)
{
  namespace asio = boost::asio;

  boost::system::error_code ec;
  const auto addr = asio::ip::make_address(std::string{address}, ec);
  if (ec)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidEndpointUrl", "Invalid IP address", "TcpEndpoint")
        .context(ua::ContextKeys::endpointAddress, std::string{address})};
  }

  if (addr.is_v4())
  {
    const auto bytes = addr.to_v4().to_bytes();
    return TcpEndpoint::v4(std::span<const std::uint8_t>{bytes.data(), bytes.size()}, port);
  }

  const auto bytes = addr.to_v6().to_bytes();
  return TcpEndpoint::v6(std::span<const std::uint8_t>{bytes.data(), bytes.size()}, port);
}

TcpEndpoint TcpEndpoint::from_string(std::string_view endpoint)
{
  // Supported forms:
  //   - IPv4: "127.0.0.1:4840"
  //   - IPv6: "[::1]:4840"

  if (endpoint.starts_with('['))
  {
    const auto close = endpoint.find(']');
    if (close == std::string_view::npos)
    {
      throw UaException{Status::BadInvalidArgument,
        ErrorDetail::build("InvalidEndpointUrl", "Missing closing ']' in IPv6 endpoint", "TcpEndpoint")
          .context(ua::ContextKeys::endpointUrl, std::string{endpoint})};
    }

    const auto addressText = endpoint.substr(1, close - 1);
    const auto remainder = endpoint.substr(close + 1);
    if (!remainder.starts_with(':') || remainder.size() == 1)
    {
      throw UaException{Status::BadInvalidArgument,
        ErrorDetail::build("InvalidEndpointUrl", "Missing port after IPv6 address in endpoint", "TcpEndpoint")
          .context(ua::ContextKeys::endpointUrl, std::string{endpoint})};
    }

    const auto portNumber = parse_port(remainder.substr(1));
    return from_string(addressText, portNumber);
  }

  const auto colon = endpoint.rfind(':');
  if (colon == std::string_view::npos)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidEndpointUrl", "Missing port separator ':' in endpoint", "TcpEndpoint")
        .context(ua::ContextKeys::endpointUrl, std::string{endpoint})};
  }

  // If there are multiple ':' it is ambiguous (IPv6 without brackets). Require bracketed form.
  if (endpoint.find(':') != colon)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidEndpointUrl",
        "Ambiguous IPv6 address without brackets in endpoint; use [addr]:port form",
        "TcpEndpoint")
        .context(ua::ContextKeys::endpointUrl, std::string{endpoint})};
  }

  const auto addressText = endpoint.substr(0, colon);
  const auto portNumber = parse_port(endpoint.substr(colon + 1));
  return from_string(addressText, portNumber);
}

TcpEndpoint::IpVersion TcpEndpoint::version() const
{
  return mVersion;
}

std::uint16_t TcpEndpoint::port() const
{
  return mPort;
}

std::span<const std::uint8_t> TcpEndpoint::address() const
{
  return (mVersion == IpVersion::V4) ? std::span<const std::uint8_t>{mAddr.data(), 4}
                                     : std::span<const std::uint8_t>{mAddr.data(), 16};
}

}  // namespace ua
