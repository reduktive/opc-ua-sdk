// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_option_set_value_merge.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_option_set.h"

#include <algorithm>
#include <string>

namespace ua
{

ByteStringResult merge_option_set_value(const OptionSet& writtenOptionSet, const OptionSet& currentOptionSet)
{
  const auto& writtenValue = writtenOptionSet.value();
  const auto& validBits = writtenOptionSet.valid_bits();
  const auto& currentValue = currentOptionSet.value();

  if (validBits.size() != writtenValue.size())
  {
    return ByteStringResult{StatusCode{Status::BadOutOfRange},
      ErrorDetail::build("OptionSetValidBitsSizeMismatch",
        "OptionSet ValidBits size does not match Value size",
        "merge_option_set_value")
        .context(ua::ContextKeys::sizeActual, std::to_string(validBits.size()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(writtenValue.size()))};
  }

  auto mergeLength = std::max(writtenValue.size(), currentValue.size());
  ByteString merged(mergeLength, 0);

  for (size_t i = 0; i < mergeLength; ++i)
  {
    const uint8_t written = i < writtenValue.size() ? writtenValue[i] : 0;
    const uint8_t valid = i < validBits.size() ? validBits[i] : 0;
    const uint8_t current = i < currentValue.size() ? currentValue[i] : 0;

    merged[i] = numeric_cast<uint8_t>((written & valid) | (current & ~valid));
  }

  return merged;
}

}  // namespace ua
