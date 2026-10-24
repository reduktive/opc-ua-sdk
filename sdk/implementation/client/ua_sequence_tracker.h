// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SEQUENCE_TRACKER_H
#define UA_SEQUENCE_TRACKER_H

/// @file
/// @brief Per-Subscription publish sequence-number tracker (client tier-1, detail).
/// @ingroup client

#include <cstdint>

namespace ua::client::detail
{

/// Classification of an incoming Publish sequence number relative to what was expected next.
enum class SequenceClass
{
  /// The sequence number is 0, which the protocol never uses (CL-SUB-002) - reject with advisory.
  Invalid,
  /// The sequence number was already processed (it lies behind the expected one) - reject, no dispatch.
  Duplicate,
  /// The sequence number is exactly the one expected next - process and advance.
  InOrder,
  /// The sequence number is ahead of the expected one - one or more were missed; drive Republish.
  Gap,
};

/// Whether a Publish notification with the given sequence classification may be delivered to user
/// monitored-item callbacks.
///
/// Delivery is gated on the classification so the pipeline's documented "Duplicate / Invalid -> no
/// dispatch" contract is honoured at the delivery site (CL-SUB-002): a @ref SequenceClass::Duplicate
/// (a re-sent message the client already processed) must not double-deliver, and a
/// @ref SequenceClass::Invalid (sequence number 0, or the default assigned when no Subscription matches -
/// a spoofed/unknown subscriptionId) must not spoof-deliver. Only an @ref SequenceClass::InOrder message
/// or a @ref SequenceClass::Gap message is delivered; Gap keeps delivering its live payload as today (the
/// in-order gap-recovery refinement is out of this scope).
///
/// @param classification The sequence classification the pipeline computed for the message.
/// @return `true` iff the message's notifications should reach user callbacks.
[[nodiscard]] bool should_deliver(SequenceClass classification) noexcept;

/// Tracks the next expected Publish sequence number for one Subscription (CL-SUB-002 / CL-SUB-017).
///
/// OPC UA Publish sequence numbers are 32-bit and increase by one per notification message, **wrapping
/// from the maximum back to 1** - the value 0 is never valid. This tracker classifies each received
/// number as in-order, a gap (some were missed), a duplicate/replay, or invalid, using a signed
/// 32-bit distance so the classification stays correct across the wrap boundary. It holds no
/// Subscription state beyond the expected number, so each Subscription owns its own instance and a gap
/// on one never perturbs another (CL-SUB-017).
class SequenceTracker
{
public:
  /// The largest valid sequence number; the successor of this value is 1, not 0.
  static constexpr std::uint32_t maxSequenceNumber = 0xFFFFFFFFu;

  /// Constructs a tracker expecting sequence number 1 (a freshly created Subscription).
  SequenceTracker() noexcept = default;

  /// Constructs a tracker expecting @p firstExpected (e.g. a Subscription taken over by transfer).
  ///
  /// @param firstExpected The first sequence number this tracker should treat as in-order.
  explicit SequenceTracker(std::uint32_t firstExpected) noexcept;

  /// Classifies @p received against the expected number without mutating the tracker.
  ///
  /// @param received The Publish sequence number that arrived.
  /// @return Its @ref SequenceClass.
  [[nodiscard]] SequenceClass classify(std::uint32_t received) const noexcept;

  /// Advances the expected number to the successor of @p received (wrapping past the maximum to 1).
  ///
  /// Called after a number has been accepted - either in-order, or as the far edge of a recovered gap.
  ///
  /// @param received The sequence number that was just processed.
  void advance_past(std::uint32_t received) noexcept;

  /// Returns the sequence number currently expected next.
  ///
  /// @return The next expected sequence number.
  [[nodiscard]] std::uint32_t next_expected() const noexcept;

private:
  std::uint32_t mNextExpected = 1;
};

}  // namespace ua::client::detail

#endif  // UA_SEQUENCE_TRACKER_H
