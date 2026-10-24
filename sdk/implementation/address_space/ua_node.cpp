// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_batch_support.h"

#include <cstring>

namespace ua
{

namespace detail
{

uint32_t decode_offset(const ByteString& token)
{
  if (token.size() != sizeof(uint32_t))
  {
    return 0;
  }
  uint32_t offset = 0;
  std::memcpy(&offset, token.data(), sizeof(uint32_t));
  return offset;
}

ByteString encode_offset(uint32_t offset)
{
  ByteString token(sizeof(uint32_t), uint8_t{0});
  std::memcpy(token.data(), &offset, sizeof(uint32_t));
  return token;
}

}  // namespace detail

}  // namespace ua
