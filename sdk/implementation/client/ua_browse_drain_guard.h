// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#ifndef UA_BROWSE_DRAIN_GUARD_H
#define UA_BROWSE_DRAIN_GUARD_H

#include "ua_browse_result.h"
#include "ua_continuation_limits.h"
#include "ua_continuation_point.h"
#include "ua_result.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace ua::client::detail
{
class WireOps;

/// Bounds for one continuation drain (a Browse followed by BrowseNext until the server stops returning a
/// continuation point). The page budget matches the Republish drain's iteration cap; the reference budget
/// bounds the memory one drain may accumulate from a server that never runs out of references; the
/// empty-page bound is the cursors' rule (API-D1.4, @ref ContinuationLimits).
struct BrowseDrainLimits
{
  std::size_t maxPages = 4096;
  std::size_t maxReferences = 100'000;
  std::uint32_t maxConsecutiveEmptyPages = ContinuationLimits{}.maxConsecutiveEmptyPages;
};

/// One guard per drain, carried with the drain's state. Every page a BrowseNext returns is admitted through
/// @ref admit_page before its references are kept; a refusal ends the drain with the reason.
class BrowseDrainGuard
{
public:
  /// @p referencesSoFar is what the drain already holds when the guard is created (the first Browse page),
  /// so the reference budget bounds the whole drain, not only the BrowseNext pages.
  explicit BrowseDrainGuard(
    std::string source, BrowseDrainLimits limits = {}, std::size_t referencesSoFar = 0);

  /// Admits a page the drain received. Refuses with Bad_Timeout (`BrowseDrainEmptyPageLimitExceeded`) once
  /// more empty pages with a continuation point arrive in a row than the limit allows, and with
  /// Bad_ResponseTooLarge (`BrowseDrainPageBudgetExceeded` / `BrowseDrainReferenceBudgetExceeded`) once the
  /// drain exceeds its page or reference budget. Counts the page and its references either way. After any
  /// refusal the caller releases the point the page carried (@ref release_continuation_point_best_effort).
  [[nodiscard]] ua::VoidResult admit_page(const ua::BrowseResult& page);

  [[nodiscard]] std::size_t pages() const noexcept
  {
    return mPages;
  }

  [[nodiscard]] std::size_t references() const noexcept
  {
    return mReferences;
  }

private:
  std::string mSource;
  BrowseDrainLimits mLimits;
  std::size_t mPages = 0;
  std::size_t mReferences = 0;
  std::uint32_t mConsecutiveEmptyPages = 0;
};

/// After a refusal, the server still holds the continuation point the refused page carried (CL-VIEW-002):
/// release it with a release-only BrowseNext whose outcome nobody waits for.
void release_continuation_point_best_effort(WireOps& wireOps, const ua::ContinuationPoint& continuationPoint);

}  // namespace ua::client::detail

#endif  // UA_BROWSE_DRAIN_GUARD_H
