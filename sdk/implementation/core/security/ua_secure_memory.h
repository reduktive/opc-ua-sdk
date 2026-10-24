// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Non-elidable scrubbing of secret material (DEF-4, CRY-5).
///
/// A plain `memset` before a buffer is released is dead-store-eliminated; these helpers use a wipe the
/// optimiser cannot remove. They bound how long a decrypted secret stays resident; they do not scrub
/// copies made by lower layers, paging, or a container's earlier, smaller allocations.

#ifndef UA_SECURE_MEMORY_H
#define UA_SECURE_MEMORY_H

#include "ua_includes.h"
#include "ua_byte_string.h"

namespace ua::security
{

/// Zeroes `size` bytes at `data` with a wipe the optimiser cannot elide. Null `data` with size 0 is a no-op.
void secure_zero(void* data, size_t size) noexcept;

/// Zeroes the bytes of `bytes`, then empties it. The released allocation held zeros.
void secure_clear(ByteString& bytes) noexcept;

/// Scrubs one secret buffer when the enclosing scope ends, on every exit: a return, an exception, or a
/// coroutine frame destroyed while suspended (which ends the scope without resuming it). A
/// @ref ByteString is cleared with @ref secure_clear; a raw byte range is zeroed with @ref secure_zero.
/// The guard refers to the buffer; the buffer must outlive it.
class ScrubOnExit
{
public:
  /// Clears `secret` with @ref secure_clear when the guard is destroyed.
  explicit ScrubOnExit(ByteString& secret) noexcept : mSecret{&secret}
  {}

  /// Zeroes the `size` bytes at `data` with @ref secure_zero when the guard is destroyed.
  ScrubOnExit(void* data, size_t size) noexcept : mData{data}, mSize{size}
  {}

  ScrubOnExit(const ScrubOnExit&) = delete;
  ScrubOnExit& operator=(const ScrubOnExit&) = delete;
  ScrubOnExit(ScrubOnExit&&) = delete;
  ScrubOnExit& operator=(ScrubOnExit&&) = delete;

  ~ScrubOnExit()
  {
    if (mSecret != nullptr)
      secure_clear(*mSecret);
    else
      secure_zero(mData, mSize);
  }

private:
  ByteString* mSecret = nullptr;
  void* mData = nullptr;
  size_t mSize = 0;
};

}  // namespace ua::security

#endif  //! UA_SECURE_MEMORY_H
