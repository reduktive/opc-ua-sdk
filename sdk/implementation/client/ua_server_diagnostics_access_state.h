// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_DIAGNOSTICS_ACCESS_STATE_H
#define UA_SERVER_DIAGNOSTICS_ACCESS_STATE_H

/// @file
/// @brief The shared `EnabledFlag` TTL cache the @ref ua::client::ServerDiagnosticsAccessor carries (client
///        design section 8.18.2). Held behind a `std::shared_ptr` so every copy of the accessor observes one
///        cache, and strong-captured across an in-flight Read so a temporary
///        `connection.server_diagnostics().sessions_async(cb)` completes correctly (the temporary accessor is
///        destroyed at the end of the full expression, before the async Read lands). The cache is a leaf: it
///        holds no back-reference to the accessor, the interface, or `ConnectionImpl`, so strong-capturing it
///        forms no cycle.
/// @ingroup client

#include "ua_date_time.h"

#include <functional>
#include <mutex>
#include <optional>

namespace ua::client::detail
{

/// The `EnabledFlag` value observed at a point in time (client design section 8.18.2). `readAt` is stamped by
/// the accessor's injectable now-provider so the 60 s TTL is deterministically testable.
struct CachedEnabledFlag
{
  bool value = false;  ///< the EnabledFlag value read from the server
  ua::DateTime readAt;  ///< when the flag was read (per the now-provider), for the TTL staleness check
};

/// The shared, mutex-protected `EnabledFlag` TTL cache (client design section 8.18.2, section 9.6.26.4). One
/// instance is shared by every copy of a @ref ua::client::ServerDiagnosticsAccessor. The mutex guards the
/// brief cache read (op start) and update (Read completion) only  -  it is never held across a user callback
/// (the design specification).
struct ServerDiagnosticsCacheState
{
  /// The now-provider (defaulted to the real wall clock). Injectable so the 60 s TTL behaviour is
  /// deterministic under test.
  std::function<ua::DateTime()> now = []
  {
    return ua::DateTime::now();
  };

  std::mutex mutex;  ///< guards @ref cachedFlag (never held across a user callback)
  std::optional<CachedEnabledFlag> cachedFlag;  ///< the cached EnabledFlag + its read time (absent = unknown)

  /// @return `true` when the cached flag is present and younger than the 60 s TTL relative to the provided
  ///         @p current instant. Not thread-safe on its own; callers hold @ref mutex.
  [[nodiscard]] bool fresh_at(ua::DateTime current) const;

  /// @return The freshly-usable cached flag value when @ref fresh_at is `true`, else `nullopt`. Takes the
  ///         lock internally.
  [[nodiscard]] std::optional<bool> fresh_value();

  /// Stores @p value stamped at the now-provider's current instant. Takes the lock internally.
  void store(bool value);
};

}  // namespace ua::client::detail

#endif  // UA_SERVER_DIAGNOSTICS_ACCESS_STATE_H
