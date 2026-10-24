// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fire_and_forget_scanner.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace
{

using ua::test_helpers::fire_and_forget::DeclarationDocumentation;
using ua::test_helpers::fire_and_forget::scan_source;

// @relation(AC-SVR-DIAG-004-FIRE-AND-FORGET-JUSTIFIED, scope=function)
TEST(FireAndForgetScannerTest, MultilineCallbacksAndLexicalDecoysAreClassified)
{
  constexpr std::string_view source = R"SOURCE(
void Owner::broken_async()
{
  const bool bestEffortMode = true;
  consume(bestEffortMode);
  child_async(
    [](
      VoidResult result
    )
    {
    });
}

void Owner::immediate_async()
{
  // fire-and-forget: the downstream observer owns this advisory result.
  child_async(
    []([[maybe_unused]] auto result)
    {
    });
}

void Owner::declared_async()
{
  child_async([](const Result<int>& result) {});
}

void Owner::synchronous()
{
  child_async([](VoidResult result) {});
}

// [](VoidResult result) {}
constexpr std::string_view decoy = "[](VoidResult result) {}";
constexpr std::string_view rawDecoy = R"DECOY([](VoidResult result) {})DECOY";
)SOURCE";

  DeclarationDocumentation declarations;
  declarations["declared_async"].push_back("No use for the result: lifecycle observation happens elsewhere.");
  const auto scan = scan_source(source, "fixture.cpp", declarations);

  EXPECT_EQ(scan.stubs.size(), 4u);
  EXPECT_EQ(scan.governed.size(), 3u);
  EXPECT_THAT(scan.unjustified, ::testing::ElementsAre("fixture.cpp:7"));

  // Header lookup is intentionally fail-closed for an unqualified name shared by more than one
  // declaration. Otherwise a comment on an unrelated overload or generated type could justify the
  // broken callback merely because both functions happen to be named broken_async.
  auto ambiguousDeclarations = declarations;
  ambiguousDeclarations["broken_async"] = {
    "Fire-and-forget: an unrelated overload owns its advisory result.",
    "A second declaration with the same unqualified name.",
  };
  const auto ambiguousScan = scan_source(source, "fixture.cpp", ambiguousDeclarations);
  EXPECT_THAT(ambiguousScan.unjustified, ::testing::Contains("fixture.cpp:7"));
}

}  // namespace
