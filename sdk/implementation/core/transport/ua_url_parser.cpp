// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_url_parser.h"

#include "ua_error_detail.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>

namespace ua::transport
{

ParsedOpcTcpUrlResult parse_opc_tcp_url(const std::string& url, const std::string& sourceComponent)
{
  using R = ParsedOpcTcpUrlResult;

  // The scheme is case-insensitive (RFC 3986 3.1): "OPC.TCP://" names the same scheme as "opc.tcp://".
  constexpr std::string_view prefix = "opc.tcp://";
  const auto lowerAscii = [](char c)
  {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  };
  if (url.size() < prefix.size() ||
      !std::equal(
        prefix.begin(), prefix.end(), url.begin(), [&](char p, char u) { return p == lowerAscii(u); }))
  {
    return R{ua::Status::BadTcpEndpointUrlInvalid,
      ua::ErrorDetail::build(
        "InvalidEndpointUrl", "Endpoint URL must start with 'opc.tcp://'", sourceComponent)
        .context(ua::ContextKeys::endpointUrl, url)};
  }

  auto remainder = std::string_view{url}.substr(prefix.size());

  // Separate host:port from path (e.g. /discovery).
  std::string path;
  auto pathPos = remainder.find('/');
  if (pathPos != std::string_view::npos)
  {
    path = std::string{remainder.substr(pathPos)};
    remainder = remainder.substr(0, pathPos);
  }
  auto hostPort = remainder;

  std::string hostname;
  uint16_t port = 4840;

  if (!hostPort.empty() && hostPort.front() == '[')
  {
    // IPv6 literal: [::1]:4840
    auto close = hostPort.find(']');
    if (close == std::string_view::npos)
    {
      return R{ua::Status::BadTcpEndpointUrlInvalid,
        ua::ErrorDetail::build("InvalidEndpointUrl", "Malformed IPv6 endpoint URL", sourceComponent)
          .context(ua::ContextKeys::endpointUrl, url)};
    }
    hostname = std::string{hostPort.substr(1, close - 1)};
    if (close + 1 < hostPort.size() && hostPort[close + 1] == ':')
    {
      auto portStr = std::string{hostPort.substr(close + 2)};
      try
      {
        auto portVal = std::stoul(portStr);
        if (portVal > 65535)
        {
          return R{ua::Status::BadTcpEndpointUrlInvalid,
            ua::ErrorDetail::build("InvalidEndpointUrl", "Port out of range in endpoint URL", sourceComponent)
              .context(ua::ContextKeys::endpointUrl, url)
              .context(ua::ContextKeys::endpointPort, portStr)};
        }
        port = numeric_cast<uint16_t>(portVal);
      }
      catch (const std::exception&)
      {
        return R{ua::Status::BadTcpEndpointUrlInvalid,
          ua::ErrorDetail::build("InvalidEndpointUrl", "Invalid port in endpoint URL", sourceComponent)
            .context(ua::ContextKeys::endpointUrl, url)
            .context(ua::ContextKeys::endpointPort, portStr)};
      }
    }
  }
  else
  {
    auto colon = hostPort.rfind(':');
    if (colon != std::string_view::npos)
    {
      hostname = std::string{hostPort.substr(0, colon)};
      auto portStr = std::string{hostPort.substr(colon + 1)};
      try
      {
        auto portVal = std::stoul(portStr);
        if (portVal > 65535)
        {
          return R{ua::Status::BadTcpEndpointUrlInvalid,
            ua::ErrorDetail::build("InvalidEndpointUrl", "Port out of range in endpoint URL", sourceComponent)
              .context(ua::ContextKeys::endpointUrl, url)
              .context(ua::ContextKeys::endpointPort, portStr)};
        }
        port = numeric_cast<uint16_t>(portVal);
      }
      catch (const std::exception&)
      {
        return R{ua::Status::BadTcpEndpointUrlInvalid,
          ua::ErrorDetail::build("InvalidEndpointUrl", "Invalid port in endpoint URL", sourceComponent)
            .context(ua::ContextKeys::endpointUrl, url)
            .context(ua::ContextKeys::endpointPort, portStr)};
      }
    }
    else
    {
      hostname = std::string{hostPort};
    }
  }

  if (hostname.empty())
  {
    return R{ua::Status::BadTcpEndpointUrlInvalid,
      ua::ErrorDetail::build("InvalidEndpointUrl", "Empty hostname in endpoint URL", sourceComponent)
        .context(ua::ContextKeys::endpointUrl, url)};
  }

  return R{ParsedOpcTcpUrl{std::move(hostname), port, std::move(path)}};
}

bool matches_port_and_path(const ParsedOpcTcpUrl& a, const ParsedOpcTcpUrl& b)
{
  return a.port == b.port && a.path == b.path;
}

bool matches_host(const ParsedOpcTcpUrl& a, const ParsedOpcTcpUrl& b)
{
  return std::ranges::equal(a.hostname,
    b.hostname,
    [](unsigned char left, unsigned char right) { return std::tolower(left) == std::tolower(right); });
}

std::string rewrite_host(std::string_view url, std::string_view newHost)
{
  constexpr std::string_view prefix = "opc.tcp://";
  if (url.size() < prefix.size() || url.substr(0, prefix.size()) != prefix)
  {
    return std::string{url};
  }

  auto remainder = url.substr(prefix.size());

  // Find where the host:port ends (at '/' or end of string).
  auto pathPos = remainder.find('/');
  auto hostPort = (pathPos != std::string_view::npos) ? remainder.substr(0, pathPos) : remainder;
  auto pathPart = (pathPos != std::string_view::npos) ? remainder.substr(pathPos) : std::string_view{};

  // Extract the port portion from the original URL.
  std::string_view portSuffix;
  if (!hostPort.empty() && hostPort.front() == '[')
  {
    // IPv6: [host]:port
    auto close = hostPort.find(']');
    if (close != std::string_view::npos && close + 1 < hostPort.size() && hostPort[close + 1] == ':')
    {
      portSuffix = hostPort.substr(close + 1);  // includes ':'
    }
  }
  else
  {
    auto colon = hostPort.rfind(':');
    if (colon != std::string_view::npos)
    {
      portSuffix = hostPort.substr(colon);  // includes ':'
    }
  }

  // Wrap IPv6 newHost in brackets if needed.
  const bool needsBrackets = newHost.find(':') != std::string_view::npos;
  std::string result{prefix};
  if (needsBrackets)
  {
    result += '[';
  }
  result += newHost;
  if (needsBrackets)
  {
    result += ']';
  }
  result += portSuffix;
  result += pathPart;
  return result;
}

}  // namespace ua::transport
