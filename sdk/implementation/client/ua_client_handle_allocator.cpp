// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_client_handle_allocator.h"

namespace ua::client::detail
{

ClientHandleAllocator::ClientHandleAllocator(std::uint32_t firstHandle) noexcept
  : mNext(firstHandle == 0 ? 1 : firstHandle)
{}

std::uint32_t ClientHandleAllocator::allocate() noexcept
{
  const std::uint32_t handle = mNext;
  // The successor of the maximum handle is 1, not 0 (0 is the "unknown handle" sentinel).
  mNext = (mNext == maxHandle) ? 1u : mNext + 1u;
  return handle;
}

}  // namespace ua::client::detail
