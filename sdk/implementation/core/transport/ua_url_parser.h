// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_URL_PARSER_H
#define UA_URL_PARSER_H

#include "ua_result.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace ua::transport
{

struct ParsedOpcTcpUrl
{
  std::string hostname;
  uint16_t port{4840};
  std::string path;
};

using ParsedOpcTcpUrlResult = ua::Result<ParsedOpcTcpUrl>;

/// Parse an opc.tcp:// URL into hostname, port, and path.
/// Returns BadTcpEndpointUrlInvalid on malformed URLs with descriptive ErrorDetail.
ParsedOpcTcpUrlResult parse_opc_tcp_url(const std::string& url, const std::string& sourceComponent);

/// Returns true if both URLs identify the same resource (same port and path, ignoring hostname).
bool matches_port_and_path(const ParsedOpcTcpUrl& a, const ParsedOpcTcpUrl& b);

/// Returns true if both URLs name the same host (DNS names compare case-insensitively; port and path are
/// ignored).
bool matches_host(const ParsedOpcTcpUrl& a, const ParsedOpcTcpUrl& b);

/// Returns a new URL string with the host portion replaced by \p newHost,
/// preserving scheme, port, and path. If the URL cannot be parsed, returns it unchanged.
std::string rewrite_host(std::string_view url, std::string_view newHost);

}  // namespace ua::transport

#endif  // UA_URL_PARSER_H
