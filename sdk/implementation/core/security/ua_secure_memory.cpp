// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_secure_memory.h"

#include <openssl/crypto.h>

namespace ua::security
{

void secure_zero(void* data, size_t size) noexcept
{
  if (data != nullptr && size > 0)
    OPENSSL_cleanse(data, size);
}

void secure_clear(ByteString& bytes) noexcept
{
  if (!bytes.empty())
    secure_zero(bytes.data(), bytes.size());
  bytes.clear();
}

}  // namespace ua::security
