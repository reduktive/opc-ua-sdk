// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tuning options for the server's listen operations.
/// @ingroup server

#ifndef UA_LISTEN_OPTIONS_H
#define UA_LISTEN_OPTIONS_H

#include <chrono>
#include <optional>

namespace ua::server
{

/// Options controlling how a server starts listening on an endpoint.
///
/// Passed by value to the `Server` listen family (`listen_async`, `listen_sync`,
/// `try_listen_sync`); a default-constructed instance selects the conventional
/// behaviour. The struct owns no external resources and may be copied freely.
///
/// @ingroup server
struct ListenOptions
{
  /// Upper bound on how long the listen operation may take, in seconds.
  ///
  /// Applies to hostname resolution and any async setup work. Disengaged
  /// (the default) means no caller-imposed deadline; the operation runs to
  /// completion or fails on its own terms.
  std::optional<std::chrono::seconds> timeout{};

  /// Whether listening on an already-active endpoint is treated as an error.
  ///
  /// When `true` (the default), attempting to listen on an endpoint that is
  /// already active fails. When `false`, that case is treated as success,
  /// making the listen call idempotent for an already-listening endpoint.
  bool failIfAlreadyListening{true};
};

}  // namespace ua::server

#endif  // !UA_LISTEN_OPTIONS_H
