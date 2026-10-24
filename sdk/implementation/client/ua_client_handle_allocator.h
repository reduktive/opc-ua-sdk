// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_HANDLE_ALLOCATOR_H
#define UA_CLIENT_HANDLE_ALLOCATOR_H

/// @file
/// @brief Per-Connection unique client-handle allocator for monitored items (CL-MI-003).
/// @ingroup client

#include <cstdint>

namespace ua::client::detail
{

/// Issues unique 32-bit client handles for monitored items within one Connection (CL-MI-003).
///
/// Each `monitor_async` gets a fresh handle used to demux Publish notifications back to the item. Handles
/// increase monotonically and wrap from the maximum back to 1 - the value 0 is never issued (it is a
/// sentinel for "unknown handle").
class ClientHandleAllocator
{
public:
  /// The largest handle; its successor is 1, not 0.
  static constexpr std::uint32_t maxHandle = 0xFFFFFFFFu;

  /// Constructs an allocator whose first handle is @p firstHandle (default 1).
  ///
  /// @param firstHandle The handle to issue first (0 is treated as 1).
  explicit ClientHandleAllocator(std::uint32_t firstHandle = 1) noexcept;

  /// Issues the next unique handle (never 0; wraps past the maximum to 1).
  ///
  /// @return A fresh client handle.
  [[nodiscard]] std::uint32_t allocate() noexcept;

private:
  std::uint32_t mNext;
};

}  // namespace ua::client::detail

#endif  // UA_CLIENT_HANDLE_ALLOCATOR_H
