// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Decodes the hex strings of sce_vectors.h into the SDK's byte types.

#pragma once

#include "ua_byte_string.h"
#include <stdexcept>
#include <string_view>

namespace ua::test::sce_vectors
{

/// The bytes a lowercase or uppercase hex string spells; throws on an odd length or a non-hex digit.
inline ByteString hex_bytes(std::string_view hex)
{
  if (hex.size() % 2 != 0)
  {
    throw std::invalid_argument("odd-length hex string");
  }
  const auto nibble = [](char c) -> uint8_t
  {
    if (c >= '0' && c <= '9')
      return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f')
      return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
      return static_cast<uint8_t>(c - 'A' + 10);
    throw std::invalid_argument("non-hex digit");
  };
  ByteString out;
  out.resize(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i)
  {
    out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
  }
  return out;
}

}  // namespace ua::test::sce_vectors
