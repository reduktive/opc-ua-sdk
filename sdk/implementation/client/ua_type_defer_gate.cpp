// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_type_defer_gate.h"

#include <utility>

namespace ua::client::detail
{

TypeDeferGate::TypeDeferGate(TypeDeferPolicy policy)
  : mPolicy(std::move(policy)), mAdvisorySeen(mPolicy.advisoryDedupCap)
{}

DeferDecision TypeDeferGate::classify(
  MessageClass messageClass, std::size_t distinctUnresolvedCount) const noexcept
{
  if (messageClass == MessageClass::SecurityCritical)
  {
    // Fail-closed: a security/handshake body is decoded strictly. It must never emit a placeholder  -  a
    // deferred check on attacker-influenced bytes is a security hole (the design specification; OWASP).
    return DeferDecision::StrictFail;
  }
  // Application data: defer while within the distinct-type budget, else surface terminal placeholders
  // (the decode still succeeds  -  over-budget is never a hard failure, section 9.8 override 2).
  if (distinctUnresolvedCount > mPolicy.maxDistinctUnresolvedTypesPerMessage)
  {
    return DeferDecision::Placeholder;
  }
  return DeferDecision::Defer;
}

bool TypeDeferGate::may_redecode(std::size_t passIndex) const noexcept
{
  return passIndex < mPolicy.maxReDecodePasses;
}

bool TypeDeferGate::record_advisory_first_seen(const ua::NodeId& dataTypeId)
{
  // peek does not reorder; a hit means "already advised" (coalesce). A miss records it and, past the
  // cap, evicts the least-recently-seen entry so the set is bounded regardless of type cardinality.
  if (mAdvisorySeen.peek(dataTypeId) != nullptr)
  {
    // Touch it so the coalescing window follows recency (get reorders to front).
    (void)mAdvisorySeen.get(dataTypeId);
    return false;
  }
  mAdvisorySeen.put(dataTypeId, true);
  return true;
}

}  // namespace ua::client::detail
