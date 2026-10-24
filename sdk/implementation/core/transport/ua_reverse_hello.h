// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#pragma once

#include "ua_result.h"
#include "ua_status_code.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace ua::detail
{

struct ReverseHelloMessage
{
  std::string serverUri;
  std::string endpointUrl;
};

/// Encode a ReverseHello message: [R][H][E][F] + uint32 size + String serverUri + String endpointUrl.
std::vector<std::byte> encode_reverse_hello(const ReverseHelloMessage& msg);

/// Decode a ReverseHello message from the full raw message bytes (including header).
using ReverseHelloMessageResult = Result<ReverseHelloMessage>;
ReverseHelloMessageResult decode_reverse_hello(std::span<const std::byte> data);

/// Validate field lengths (each must be less than 4096 bytes encoded).
StatusCode validate_reverse_hello_fields(const ReverseHelloMessage& msg);

}  // namespace ua::detail
