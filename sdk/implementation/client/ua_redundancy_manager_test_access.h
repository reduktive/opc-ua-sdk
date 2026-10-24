// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Friend test interface for @ref ua::client::detail::RedundancyManagerImpl (the design specification "no
/// public API
///        pollution for testing"). Exposes the strand-private FSM bookkeeping (`mState`, `mGeneration`,
///        `mCandidates`, `mServiceLevelHistory`, `mPendingProbes`, ...) and the injectable clock so unit
///        tests can drive every section 8.11.4 transition deterministically without a public getter. Tests
///        read these only after draining the (single-threaded) io_context, so there is no cross-strand race.
/// @ingroup client

#ifndef UA_REDUNDANCY_MANAGER_TEST_ACCESS_H
#define UA_REDUNDANCY_MANAGER_TEST_ACCESS_H

#include "ua_date_time.h"
#include "ua_redundancy_manager.h"
#include "ua_redundancy_manager_impl.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ua::client::detail
{

struct RedundancyManagerTestAccess
{
  [[nodiscard]] static RedundancyManagerState state(const RedundancyManagerImpl& impl)
  {
    return impl.mState;
  }

  [[nodiscard]] static std::uint64_t generation(const RedundancyManagerImpl& impl)
  {
    return impl.mGeneration;
  }

  [[nodiscard]] static std::uint64_t failover_count(const RedundancyManagerImpl& impl)
  {
    return impl.mFailoverCount;
  }

  [[nodiscard]] static ua::RedundancySupport effective_mode(const RedundancyManagerImpl& impl)
  {
    return impl.mEffectiveMode;
  }

  [[nodiscard]] static std::string active_uri(const RedundancyManagerImpl& impl)
  {
    return impl.mActiveUri;
  }

  [[nodiscard]] static const std::vector<std::string>& server_uri_array(const RedundancyManagerImpl& impl)
  {
    return impl.mServerUriArray;
  }

  [[nodiscard]] static std::size_t candidate_count(const RedundancyManagerImpl& impl)
  {
    return impl.mCandidates.size();
  }

  [[nodiscard]] static std::optional<RedundantCandidate> candidate(
    const RedundancyManagerImpl& impl, const std::string& serverUri)
  {
    auto found = impl.mCandidates.find(serverUri);
    if (found == impl.mCandidates.end())
    {
      return std::nullopt;
    }
    return found->second;
  }

  [[nodiscard]] static std::size_t history_size(const RedundancyManagerImpl& impl)
  {
    return impl.mServiceLevelHistory.size();
  }

  [[nodiscard]] static std::size_t pending_probe_count(const RedundancyManagerImpl& impl)
  {
    return impl.mPendingProbes.size();
  }

  [[nodiscard]] static bool has_service_level_handle(const RedundancyManagerImpl& impl)
  {
    return impl.mServiceLevelHandle.has_value();
  }

  [[nodiscard]] static bool has_force_switch_pending(const RedundancyManagerImpl& impl)
  {
    return impl.mForceSwitchPending.has_value();
  }

  /// Overrides the injectable clock  -  lets tests advance virtual time for the time-based hysteresis window
  /// and the probe / failover timestamps without sleeping.
  static void set_now_fn(RedundancyManagerImpl& impl, std::function<ua::DateTime()> now)
  {
    impl.mNowFn = std::move(now);
  }
};

}  // namespace ua::client::detail

#endif  // UA_REDUNDANCY_MANAGER_TEST_ACCESS_H
