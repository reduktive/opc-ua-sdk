// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Internal parsing and matching of a certificate thumbprint String (not public API).

#ifndef UA_CERTIFICATE_THUMBPRINT_H
#define UA_CERTIFICATE_THUMBPRINT_H

#include "ua_x509_certificate.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ua::detail
{

/// Decision 28: a thumbprint String is the SHA-1 thumbprint as 40 hexadecimal digits, either case. Returns
/// its 20 bytes, or nullopt when the string is not exactly that.
inline std::optional<std::vector<uint8_t>> decode_thumbprint(const std::string& thumbprint)
{
  constexpr size_t thumbprintBytes = 20;
  if (thumbprint.size() != thumbprintBytes * 2)
  {
    return std::nullopt;
  }
  const auto nibble = [](char c) -> int
  {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  std::vector<uint8_t> bytes;
  bytes.reserve(thumbprintBytes);
  for (size_t i = 0; i < thumbprint.size(); i += 2)
  {
    const int high = nibble(thumbprint[i]);
    const int low = nibble(thumbprint[i + 1]);
    if (high < 0 || low < 0)
    {
      return std::nullopt;
    }
    bytes.push_back(static_cast<uint8_t>((high << 4) | low));
  }
  return bytes;
}

/// Compares @p certificate's thumbprint with decoded @p thumbprint bytes (decision 28: bytes, not text).
inline bool thumbprint_matches(const X509Certificate& certificate, const std::vector<uint8_t>& thumbprint)
{
  const auto actual = certificate.thumbprint();
  return std::equal(actual.begin(), actual.end(), thumbprint.begin(), thumbprint.end());
}

}  // namespace ua::detail

#endif  // UA_CERTIFICATE_THUMBPRINT_H
