// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
/// @file
/// @brief Unit tests for the continuation-drain guard (CL-VIEW-005 / CL-VIEW-002): every branch of
///        BrowseDrainGuard::admit_page, including the consecutive-empty-page rule the cursors share with the
///        drains (public API review D1, API-D1.4).
#include "ua_browse_drain_guard.h"

#include "ua_browse_result.h"
#include "ua_continuation_point.h"
#include "ua_reference_description.h"
#include "ua_status.h"

#include "fake_connection_ops.h"

#include <gtest/gtest.h>

namespace
{

using ua::client::detail::BrowseDrainGuard;
using ua::client::detail::BrowseDrainLimits;

ua::ContinuationPoint cp(std::uint8_t tag)
{
  return ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{tag}}};
}

ua::BrowseResult page(std::size_t references, ua::ContinuationPoint continuationPoint)
{
  ua::BrowseResult result;
  result.references().payload().resize(references);
  result.continuation_point() = std::move(continuationPoint);
  return result;
}

std::string code_of(const ua::VoidResult& result)
{
  return result.shared_detail() ? result.shared_detail()->code : std::string{};
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// API-D1.4: empty pages with a continuation point are admitted up to the limit, whether or not the server
// echoes the point it was sent (a server may stop early with nothing to show, Part 4 5.8.2.1); one more in a
// row is refused as Bad_Timeout with the count.
TEST(BrowseDrainGuard, RefusesOneMoreEmptyPageInARowThanTheLimit)
{
  BrowseDrainGuard guard{"test", BrowseDrainLimits{.maxConsecutiveEmptyPages = 3}};
  EXPECT_TRUE(guard.admit_page(page(3, cp(2))).is_good());
  EXPECT_TRUE(guard.admit_page(page(0, cp(2))).is_good()) << "the same point, empty: still admitted";
  EXPECT_TRUE(guard.admit_page(page(0, cp(3))).is_good());
  EXPECT_TRUE(guard.admit_page(page(0, cp(3))).is_good()) << "3 of 3 empty pages";
  const auto refused = guard.admit_page(page(0, cp(3)));
  EXPECT_EQ(refused.status_code().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(code_of(refused), "BrowseDrainEmptyPageLimitExceeded");
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(BrowseDrainGuard, APageWithReferencesResetsTheEmptyPageCount)
{
  BrowseDrainGuard guard{"test", BrowseDrainLimits{.maxConsecutiveEmptyPages = 2}};
  EXPECT_TRUE(guard.admit_page(page(0, cp(1))).is_good());
  EXPECT_TRUE(guard.admit_page(page(0, cp(1))).is_good());
  EXPECT_TRUE(guard.admit_page(page(1, cp(1))).is_good()) << "progress";
  EXPECT_TRUE(guard.admit_page(page(0, cp(1))).is_good());
  EXPECT_TRUE(guard.admit_page(page(0, cp(1))).is_good()) << "two in a row again";
  EXPECT_TRUE(guard.admit_page(page(0, ua::ContinuationPoint{})).is_good()) << "the last page ends the drain";
  EXPECT_EQ(guard.pages(), 6u);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(BrowseDrainGuard, AdmitsExactlyThePageBudgetAndRefusesTheNextPage)
{
  BrowseDrainGuard guard{"test", BrowseDrainLimits{.maxPages = 3, .maxReferences = 1000}};
  EXPECT_TRUE(guard.admit_page(page(1, cp(2))).is_good());
  EXPECT_TRUE(guard.admit_page(page(1, cp(3))).is_good());
  EXPECT_TRUE(guard.admit_page(page(1, cp(4))).is_good()) << "page 3 of 3 is admitted";
  const auto refused = guard.admit_page(page(1, cp(5)));
  EXPECT_EQ(refused.status_code().as_status(), ua::Status::BadResponseTooLarge);
  EXPECT_EQ(code_of(refused), "BrowseDrainPageBudgetExceeded");
  EXPECT_EQ(guard.pages(), 4u);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(BrowseDrainGuard, AdmitsExactlyTheReferenceBudgetAndRefusesTheReferenceBeyondIt)
{
  BrowseDrainGuard guard{"test", BrowseDrainLimits{.maxPages = 1000, .maxReferences = 5}};
  EXPECT_TRUE(guard.admit_page(page(3, cp(2))).is_good());
  EXPECT_TRUE(guard.admit_page(page(2, cp(3))).is_good()) << "5 of 5 references are admitted";
  const auto refused = guard.admit_page(page(1, cp(4)));
  EXPECT_EQ(refused.status_code().as_status(), ua::Status::BadResponseTooLarge);
  EXPECT_EQ(code_of(refused), "BrowseDrainReferenceBudgetExceeded");
  EXPECT_EQ(guard.references(), 6u);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// The first Browse page is already held when the drain starts; it counts toward the reference budget.
TEST(BrowseDrainGuard, TheReferencesHeldBeforeTheDrainCountTowardTheBudget)
{
  BrowseDrainGuard guard{
    "test", BrowseDrainLimits{.maxPages = 1000, .maxReferences = 5}, /*referencesSoFar=*/4};
  EXPECT_TRUE(guard.admit_page(page(1, cp(2))).is_good()) << "5 of 5";
  EXPECT_EQ(code_of(guard.admit_page(page(1, cp(3)))), "BrowseDrainReferenceBudgetExceeded");
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(BrowseDrainGuard, ASameNonEmptyPointWithReferencesIsProgressNotALoop)
{
  BrowseDrainGuard guard{"test"};
  EXPECT_TRUE(guard.admit_page(page(2, cp(1))).is_good());
  EXPECT_TRUE(guard.admit_page(page(2, cp(1))).is_good());
  EXPECT_EQ(guard.references(), 4u);
}

// @verifies AC-CL-VIEW-002-A-BUDGET-REFUSAL-RELEASES-THE-CONTINUATION-POINT
TEST(BrowseDrainGuard, ABudgetRefusalReleasesTheContinuationPointBestEffort)
{
  auto wireOps = std::make_shared<ua::test_helpers::FakeWireOps>();
  ua::client::detail::release_continuation_point_best_effort(*wireOps, cp(7));
  ASSERT_EQ(wireOps->browseNextRequests.size(), 1u) << "one release-only BrowseNext";
  EXPECT_TRUE(wireOps->browseNextRequests[0].release_continuation_points());
  ASSERT_EQ(wireOps->browseNextRequests[0].continuation_points().size(), 1u);
  EXPECT_EQ(wireOps->browseNextRequests[0].continuation_points()[0], cp(7));

  ua::client::detail::release_continuation_point_best_effort(*wireOps, ua::ContinuationPoint{});
  EXPECT_EQ(wireOps->browseNextRequests.size(), 1u) << "nothing to release for an empty point";
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(BrowseDrainGuard, TheDefaultBudgetsAdmitAnOrdinaryLargeDrain)
{
  BrowseDrainGuard guard{"test"};
  for (std::uint8_t i = 1; i <= 100; ++i)
  {
    ASSERT_TRUE(guard.admit_page(page(500, cp(static_cast<std::uint8_t>(i + 1)))).is_good()) << int{i};
  }
  EXPECT_EQ(guard.pages(), 100u);
  EXPECT_EQ(guard.references(), 50'000u);
}

}  // namespace
