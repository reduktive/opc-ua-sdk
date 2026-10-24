// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Friend test interface for @ref ua::client::detail::PullCertificateManagerImpl (the design
/// specification "no public API
///        pollution for testing"). Exposes the strand-private cycle-FSM bookkeeping (`mState`, `mGeneration`,
///        `mPendingRequests`, `mPollAttempt`, `mGdsConnected`, the last-armed timer delays, ...) and the
///        injectable clock so unit tests can drive every section 8.1A.4 transition deterministically without
///        a public getter. Because the cycle / poll timers are seconds- / large-ms-typed, the trigger hooks
///        post the identical strand action so the timed cascades run without any real wall wait. Tests read
///        this state only after draining the (single-threaded) io_context, so there is no cross-strand race.
/// @ingroup client

#ifndef UA_PULL_CERTIFICATE_MANAGER_TEST_ACCESS_H
#define UA_PULL_CERTIFICATE_MANAGER_TEST_ACCESS_H

#include "ua_date_time.h"
#include "ua_pull_certificate_manager.h"
#include "ua_pull_certificate_manager_impl.h"

#include <boost/asio/post.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client::detail
{

struct PullCertificateManagerTestAccess
{
  [[nodiscard]] static std::shared_ptr<PullCertificateManagerImpl> impl(
    const ua::client::PullCertificateManager& manager)
  {
    return manager.mImpl;
  }

  [[nodiscard]] static ua::client::PullCertManagementState state(const PullCertificateManagerImpl& impl)
  {
    return impl.mState;
  }

  [[nodiscard]] static std::uint64_t generation(const PullCertificateManagerImpl& impl)
  {
    return impl.mGeneration;
  }

  [[nodiscard]] static std::uint32_t failure_count(const PullCertificateManagerImpl& impl)
  {
    return impl.mFailureCount;
  }

  [[nodiscard]] static std::size_t poll_attempt(const PullCertificateManagerImpl& impl)
  {
    return impl.mPollAttempt;
  }

  [[nodiscard]] static bool gds_connected(const PullCertificateManagerImpl& impl)
  {
    return impl.mGdsConnected;
  }

  [[nodiscard]] static std::size_t pending_request_count(const PullCertificateManagerImpl& impl)
  {
    return impl.mPendingRequests.size();
  }

  [[nodiscard]] static const std::vector<PersistedRequest>& pending_requests(
    const PullCertificateManagerImpl& impl)
  {
    return impl.mPendingRequests;
  }

  /// The LastUpdateTime of the TrustList last committed for @p certificateGroupId.
  [[nodiscard]] static std::optional<ua::DateTime> last_trust_list_update(
    const PullCertificateManagerImpl& impl, const ua::NodeId& certificateGroupId)
  {
    for (const auto& [groupId, lastUpdate] : impl.mLastTrustListUpdates)
    {
      if (groupId == certificateGroupId)
        return lastUpdate;
    }
    return std::nullopt;
  }

  /// The same, for the first configured group.
  [[nodiscard]] static std::optional<ua::DateTime> last_trust_list_update(
    const PullCertificateManagerImpl& impl)
  {
    return last_trust_list_update(impl, impl.mCertificateGroups.front().certificateGroupId);
  }

  [[nodiscard]] static std::optional<std::chrono::milliseconds> last_armed_cycle_delay(
    const PullCertificateManagerImpl& impl)
  {
    return impl.mLastArmedCycleDelay;
  }

  [[nodiscard]] static std::optional<std::uint64_t> last_armed_cycle_generation(
    const PullCertificateManagerImpl& impl)
  {
    return impl.mLastArmedCycleGeneration;
  }

  [[nodiscard]] static std::optional<std::chrono::milliseconds> last_armed_poll_delay(
    const PullCertificateManagerImpl& impl)
  {
    return impl.mLastArmedPollDelay;
  }

  static void seed_jitter_rng(PullCertificateManagerImpl& impl, std::uint32_t seed)
  {
    impl.mJitterRng.seed(seed);
  }

  [[nodiscard]] static std::chrono::milliseconds regular_cycle_delay(PullCertificateManagerImpl& impl)
  {
    return impl.regular_cycle_delay();
  }

  static void last_armed_cycle_delay_async(const std::shared_ptr<PullCertificateManagerImpl>& impl,
    std::function<void(std::optional<std::chrono::milliseconds>)> callback)
  {
    boost::asio::post(impl->mStrand,
      ua::async::guarded(ua::Logger{},
        [impl, callback = std::move(callback)]() mutable { callback(impl->mLastArmedCycleDelay); }));
  }

  /// M6: whether the per-cycle private-key scratch still holds a value (must be wiped at each cycle
  /// terminus).
  [[nodiscard]] static bool cycle_new_key_present(const PullCertificateManagerImpl& impl)
  {
    return impl.mCycleNewKey.has_value();
  }

  /// Overrides the injectable clock  -  lets tests fix "now" for the persisted-at / commit timestamps without
  /// a real wall-clock dependency.
  static void set_now_fn(PullCertificateManagerImpl& impl, std::function<ua::DateTime()> now)
  {
    impl.mNowFn = std::move(now);
  }

  /// Posts the cycle-timer action onto the manager's strand (the cycle timer is seconds-typed, so it cannot
  /// be shaped to a sub-second real delay; this drives the identical cycle-entry path deterministically).
  /// Drive with the fixture's `drain()` afterwards.
  static void trigger_cycle(const std::shared_ptr<PullCertificateManagerImpl>& impl)
  {
    boost::asio::post(impl->mStrand,
      ua::async::guarded(ua::Logger{},
        [impl]
        {
          if (impl->mState == ua::client::PullCertManagementState::Idle ||
              impl->mState == ua::client::PullCertManagementState::Failed)
          {
            impl->start_cycle(impl->mGeneration);
          }
        }));
  }

  /// Posts the poll-timer action onto the manager's strand (the poll timer is armed above the test drain
  /// window; this fires the identical `FinishRequest` poll deterministically). Drive with `drain()` after.
  static void trigger_poll(const std::shared_ptr<PullCertificateManagerImpl>& impl)
  {
    boost::asio::post(
      impl->mStrand, ua::async::guarded(ua::Logger{}, [impl] { impl->do_poll(impl->mGeneration); }));
  }
};

}  // namespace ua::client::detail

#endif  // UA_PULL_CERTIFICATE_MANAGER_TEST_ACCESS_H
