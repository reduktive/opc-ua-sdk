// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ACK_QUEUE_H
#define UA_ACK_QUEUE_H

/// @file
/// @brief Publish-acknowledgement batching + retransmission-support latch (SubscriptionsPipeline).
/// @ingroup client

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace ua::client::detail
{

/// One Subscription acknowledgement carried on an outgoing Publish request.
struct SubscriptionAcknowledgement
{
  std::uint32_t subscriptionId = 0;
  std::uint32_t sequenceNumber = 0;
};

/// Batches Publish acknowledgements across Subscriptions and tracks per-Subscription retransmission
/// support (CL-SUB-006 / CL-SUB-007).
///
/// Each processed notification is acknowledged on the next outgoing Publish, batched across all
/// Subscriptions (CL-SUB-006). Whether a Subscription's server keeps a retransmission queue is decided
/// by its **first** Publish response: an empty `availableSequenceNumbers` latches "unsupported", and
/// acks for that Subscription are then suppressed. The decision is sticky - it is made once and never
/// re-evaluated (CL-SUB-007, section 9.6.16.1).
class AckQueue
{
public:
  /// Records a processed notification for @p subscriptionId at @p sequenceNumber.
  ///
  /// The first call for a Subscription latches its retransmission support from
  /// @p serverReportedAvailableSequenceNumbers (true = the response carried a non-empty
  /// `availableSequenceNumbers`). If supported, the ack is queued for the next Publish; if not, it is
  /// suppressed.
  ///
  /// @param subscriptionId The Subscription the notification belongs to.
  /// @param sequenceNumber The processed notification's sequence number.
  /// @param serverReportedAvailableSequenceNumbers Whether the response's `availableSequenceNumbers`
  ///        was non-empty.
  void acknowledge(
    std::uint32_t subscriptionId, std::uint32_t sequenceNumber, bool serverReportedAvailableSequenceNumbers);

  /// Removes and returns the queued acknowledgements for the next outgoing Publish (FIFO).
  ///
  /// @return The batched acknowledgements; the queue is then empty.
  [[nodiscard]] std::vector<SubscriptionAcknowledgement> drain();

  /// Releases all acknowledgement and retransmission-latch state for one terminated Subscription.
  void remove_subscription(std::uint32_t subscriptionId);

  /// Returns whether @p subscriptionId's server is known to support a retransmission queue.
  ///
  /// @param subscriptionId The Subscription to query.
  /// @return `true` if supported (or not yet decided); `false` once latched unsupported.
  [[nodiscard]] bool retransmission_supported(std::uint32_t subscriptionId) const;

  /// Returns the number of queued acknowledgements.
  ///
  /// @return The pending acknowledgement count.
  [[nodiscard]] std::size_t pending() const noexcept;

private:
  std::vector<SubscriptionAcknowledgement> mQueue;
  std::unordered_map<std::uint32_t, bool> mRetransmissionSupported;  // subId -> supported (latched)
};

}  // namespace ua::client::detail

#endif  // UA_ACK_QUEUE_H
