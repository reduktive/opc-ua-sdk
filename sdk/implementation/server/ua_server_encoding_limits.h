// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_ENCODING_LIMITS_H
#define UA_SERVER_ENCODING_LIMITS_H

#include "ua_encoding_limits.h"
#include "ua_server_configuration.h"

namespace ua::server
{

[[nodiscard]] inline ua::EncodingLimits make_server_encoding_limits(
  const ::ua::ApplicationConfig& appCfg, const ::ua::server::ServerConfig& serverCfg)
{
  auto out = ua::make_encoding_limits(appCfg);

  const auto& caps = serverCfg.server_capabilities();
  if (caps.maxStringLength)
  {
    out.maxStringLength = *caps.maxStringLength;
  }
  if (caps.maxByteStringLength)
  {
    out.maxByteStringLength = *caps.maxByteStringLength;
  }
  if (caps.maxArrayLength)
  {
    out.maxArrayLength = *caps.maxArrayLength;
  }

  return out;
}

}  // namespace ua::server

#endif  // UA_SERVER_ENCODING_LIMITS_H
