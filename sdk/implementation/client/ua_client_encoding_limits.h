// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_ENCODING_LIMITS_H
#define UA_CLIENT_ENCODING_LIMITS_H

#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"

namespace ua::client
{

/// Builds the inbound (server-response) decode limits for a client channel.
///
/// Starts from @ref ua::make_encoding_limits (execution limits from the application configuration plus
/// the bounded-floor size caps - 1 MB string / 16 MB byte-string / 65535 array) and applies any
/// per-client overrides. A `nullopt` override leaves the corresponding floor in place. This mirrors the
/// server's @ref ua::server::make_server_encoding_limits: the floor is the mandatory decode-bomb
/// protection; the overrides only tune it (up for a trusted server, down to harden against a hostile
/// one). Threaded from @ref ua::client::ClientConfig.
[[nodiscard]] inline ua::EncodingLimits make_client_encoding_limits(const ua::ApplicationConfig& appCfg,
  ua::optional<uint32_t> maxStringLength, ua::optional<uint32_t> maxByteStringLength,
  ua::optional<uint32_t> maxArrayLength)
{
  auto out = ua::make_encoding_limits(appCfg);
  if (maxStringLength)
  {
    out.maxStringLength = *maxStringLength;
  }
  if (maxByteStringLength)
  {
    out.maxByteStringLength = *maxByteStringLength;
  }
  if (maxArrayLength)
  {
    out.maxArrayLength = *maxArrayLength;
  }
  return out;
}

}  // namespace ua::client

#endif  // UA_CLIENT_ENCODING_LIMITS_H
