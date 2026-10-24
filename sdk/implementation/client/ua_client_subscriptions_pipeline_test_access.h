// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SUBSCRIPTIONS_PIPELINE_TEST_ACCESS_H
#define UA_CLIENT_SUBSCRIPTIONS_PIPELINE_TEST_ACCESS_H

/// @file
/// @brief Test-only access to @ref ua::client::detail::SubscriptionsPipeline private state (see
///        the design specification).
///
/// A friend of @ref ua::client::detail::SubscriptionsPipeline. Adds NO public members to the pipeline for
/// testing.

#include "ua_client_subscriptions_pipeline.h"
#include "ua_on_strand.h"

namespace ua::client::detail
{

/// Friend accessor for @ref SubscriptionsPipeline unit / wiring tests.
class SubscriptionsPipelineTestAccess
{
public:
  /// Whether the pipeline was constructed with a NON-empty `onSubscriptionEventLoss` callback (Finding 2 /
  /// CL-AC-003). The field is immutable after construction (const like `mSubOps`), so this is a plain
  /// synchronous read  -  no strand hop needed. Lets a ConnectionImpl wiring test assert that the pipeline
  /// `wire_pipeline_and_ops` built actually received the loss interface (a 5-arg `create` would leave it empty).
  [[nodiscard]] static bool has_subscription_event_loss_callback(const SubscriptionsPipeline& pipeline)
  {
    return static_cast<bool>(pipeline.mOnSubscriptionEventLoss);
  }

  /// Drives exactly ONE polled-Read fallback poll cycle for @p subscriptionId (CL-SUB-019), on the pipeline
  /// strand. Lets a unit test poll deterministically WITHOUT waiting on the real periodic timer (which would
  /// never let a bounded `io_context::run()` return). A no-op if the Subscription is gone / not a fallback.
  static void poll_fallback_tick_once(SubscriptionsPipeline& pipeline, std::uint32_t subscriptionId)
  {
    ua::async::post_borrowing_or_else(
      &pipeline,
      pipeline.mStrand,
      pipeline.mLogger,
      [subscriptionId](SubscriptionsPipeline& self) { self.poll_fallback_tick(subscriptionId); },
      []() {})();
  }

  /// Whether @p subscriptionId is registered as a polled-Read fallback Subscription (strand-only state; call
  /// only when the strand is quiescent, e.g. after `ctx.poll()`).
  [[nodiscard]] static bool is_fallback_subscription(
    const SubscriptionsPipeline& pipeline, std::uint32_t subscriptionId)
  {
    return pipeline.mFallbackSubs.find(subscriptionId) != pipeline.mFallbackSubs.end();
  }
};

}  // namespace ua::client::detail

#endif  // UA_CLIENT_SUBSCRIPTIONS_PIPELINE_TEST_ACCESS_H
