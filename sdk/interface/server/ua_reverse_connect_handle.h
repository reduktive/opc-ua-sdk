// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Opaque handle identifying a server-side reverse connect target.
/// @ingroup server

#ifndef UA_REVERSE_CONNECT_HANDLE_H
#define UA_REVERSE_CONNECT_HANDLE_H

#include "ua_result.h"

#include <cstdint>

namespace ua::server
{

/// Opaque handle identifying an active reverse connect target.
///
/// Returned by @ref ua::server::Server::start_reverse_connect_async (and its sync
/// variants) and passed back to stop a specific target. The handle is a small value
/// type that may be freely copied, stored, and compared; it owns no resources and
/// remains valid until the corresponding target is stopped. A default-constructed
/// handle (`value == 0`) refers to no target.
///
/// @ingroup server
struct ReverseConnectHandle
{
  std::uint64_t value{};  ///< Opaque target identifier; `0` denotes no target.

  /// Compares two handles for equality by their identifier value.
  ///
  /// @return `true` if both handles identify the same target.
  friend bool operator==(ReverseConnectHandle, ReverseConnectHandle) = default;
};

/// Result of a reverse connect start operation: a @ref ReverseConnectHandle or an @ref ErrorDetail.
using ReverseConnectHandleResult = Result<ReverseConnectHandle>;

}  // namespace ua::server

#endif  // !UA_REVERSE_CONNECT_HANDLE_H
