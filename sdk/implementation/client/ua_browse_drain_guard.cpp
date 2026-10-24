// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#include "ua_browse_drain_guard.h"

#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_connection_ops.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"

#include <utility>

namespace ua::client::detail
{

BrowseDrainGuard::BrowseDrainGuard(std::string source, BrowseDrainLimits limits, std::size_t referencesSoFar)
  : mSource(std::move(source)), mLimits(limits), mReferences(referencesSoFar)
{}

ua::VoidResult BrowseDrainGuard::admit_page(const ua::BrowseResult& page)
{
  ++mPages;
  mReferences += page.references().payload().size();
  if (page.references().payload().empty() && !page.continuation_point().empty())
  {
    if (++mConsecutiveEmptyPages > mLimits.maxConsecutiveEmptyPages)
    {
      return ua::VoidResult{ua::Status::BadTimeout,
        ua::ErrorDetail::build("BrowseDrainEmptyPageLimitExceeded",
          "the server returned more empty pages with a continuation point in a row than the drain allows",
          mSource)
          .context(ua::ContextKeys::countActual, mConsecutiveEmptyPages)
          .context(ua::ContextKeys::limit, mLimits.maxConsecutiveEmptyPages)};
    }
  }
  else
  {
    mConsecutiveEmptyPages = 0;
  }
  if (mPages > mLimits.maxPages)
  {
    return ua::VoidResult{ua::Status::BadResponseTooLarge,
      ua::ErrorDetail::build("BrowseDrainPageBudgetExceeded",
        "the continuation drain exceeded its page budget; the server keeps returning continuation points",
        mSource)
        .context(ua::ContextKeys::actual, std::to_string(mPages))
        .context(ua::ContextKeys::limit, std::to_string(mLimits.maxPages))};
  }
  if (mReferences > mLimits.maxReferences)
  {
    return ua::VoidResult{ua::Status::BadResponseTooLarge,
      ua::ErrorDetail::build("BrowseDrainReferenceBudgetExceeded",
        "the continuation drain exceeded its reference budget; the server keeps returning references",
        mSource)
        .context(ua::ContextKeys::actual, std::to_string(mReferences))
        .context(ua::ContextKeys::limit, std::to_string(mLimits.maxReferences))};
  }
  return ua::VoidResult{};
}

void release_continuation_point_best_effort(WireOps& wireOps, const ua::ContinuationPoint& continuationPoint)
{
  if (continuationPoint.empty())
  {
    return;
  }
  ua::BrowseNextRequest release;
  release.release_continuation_points() = true;
  release.continuation_points().push_back(continuationPoint);
  wireOps.browse_next_async(std::move(release), [](ua::Result<ua::BrowseNextResponse>) {});
}

}  // namespace ua::client::detail
