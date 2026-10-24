// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_ack_queue.h"

#include <algorithm>
#include <utility>

namespace ua::client::detail
{

void AckQueue::acknowledge(
  std::uint32_t subscriptionId, std::uint32_t sequenceNumber, bool serverReportedAvailableSequenceNumbers)
{
  // The FIRST response for a Subscription latches its retransmission support; try_emplace is a no-op on
  // every later call, so the decision is sticky (CL-SUB-007) and never re-evaluated.
  const auto [entry, inserted] =
    mRetransmissionSupported.try_emplace(subscriptionId, serverReportedAvailableSequenceNumbers);
  static_cast<void>(inserted);
  if (entry->second)
  {
    mQueue.push_back(SubscriptionAcknowledgement{subscriptionId, sequenceNumber});
  }
  // else: no retransmission queue on the server for this Subscription - suppress the ack.
}

std::vector<SubscriptionAcknowledgement> AckQueue::drain()
{
  return std::exchange(mQueue, {});
}

void AckQueue::remove_subscription(std::uint32_t subscriptionId)
{
  std::erase_if(mQueue,
    [subscriptionId](const SubscriptionAcknowledgement& acknowledgement)
    { return acknowledgement.subscriptionId == subscriptionId; });
  mRetransmissionSupported.erase(subscriptionId);
}

bool AckQueue::retransmission_supported(std::uint32_t subscriptionId) const
{
  const auto entry = mRetransmissionSupported.find(subscriptionId);
  return entry == mRetransmissionSupported.end() ? true : entry->second;
}

std::size_t AckQueue::pending() const noexcept
{
  return mQueue.size();
}

}  // namespace ua::client::detail
