// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_option_set_merge.h"

#include "ua_error_detail.h"
#include "ua_option_set.h"

#include <algorithm>
#include <fmt/format.h>

namespace ua::server
{

ByteString build_server_valid_bits_mask(const Array<EnumField>& fields, size_t byteLength)
{
  ByteString mask(byteLength, 0);

  for (size_t i = 0; i < fields.size(); ++i)
  {
    auto bitNumber = fields[i].value();
    if (bitNumber < 0)
      continue;

    auto byteIndex = numeric_cast<size_t>(bitNumber) / 8;
    auto bitIndex = numeric_cast<size_t>(bitNumber) % 8;

    if (byteIndex < byteLength)
    {
      mask[byteIndex] = static_cast<uint8_t>(mask[byteIndex] | (1u << bitIndex));
    }
  }

  return mask;
}

VoidResult validate_client_valid_bits(
  const ByteString& clientValidBits, const ByteString& serverValidBitsMask)
{
  for (size_t i = 0; i < clientValidBits.size(); ++i)
  {
    uint8_t serverMask = i < serverValidBitsMask.size() ? serverValidBitsMask[i] : 0;

    if ((clientValidBits[i] & ~serverMask) != 0)
    {
      return VoidResult{StatusCode{Status::BadOutOfRange},
        ErrorDetail::build("OptionSetInvalidValidBit",
          "Client ValidBits sets bit(s) that the server does not define",
          "validate_client_valid_bits")
          .context(ua::ContextKeys::bitIndex, std::to_string(i))
          .context(ua::ContextKeys::bitClientValue, fmt::format("{:#06x}", clientValidBits[i]))
          .context(ua::ContextKeys::bitServerMask, fmt::format("{:#06x}", serverMask))};
    }
  }

  return VoidResult{};
}

}  // namespace ua::server
