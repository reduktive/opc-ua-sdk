// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "server_async_surface_catalogue.h"

#include <filesystem>

namespace ua::test
{
namespace
{

using test_helpers::server_async_catalogue::derive_from_source;
using test_helpers::server_async_catalogue::Row;
using test_helpers::server_async_catalogue::test_relations_from_source;
using test_helpers::server_async_catalogue::TestRelations;
using test_helpers::server_async_catalogue::validate;
using test_helpers::server_async_catalogue::validate_inventory;
using ::testing::Contains;
using ::testing::IsEmpty;

std::filesystem::path repository_root()
{
  // UASDK_TEST_SOURCE_DIR (absolute; see tests/CMakeLists.txt), not __FILE__, anchors the walk.
  auto candidate = std::filesystem::path{UASDK_TEST_SOURCE_DIR};
  // parent_path() of the filesystem root is the root itself, so an empty-path test never fires. If the
  // marker cannot be found the walk spins on "/" at full CPU and hangs the whole test binary rather than
  // failing it. Stop when the walk stops moving and let the caller's assertion report the absence.
  while (!std::filesystem::exists(candidate / "internal" / "requirements" / "grammar.sgra"))
  {
    auto parent = candidate.parent_path();
    if (parent == candidate)
      return {};
    candidate = std::move(parent);
  }
  return candidate;
}

// @relation(AC-SVR-DIAG-008-ASYNC-INVENTORY-COMPLETE, scope=function)
TEST(ServerAsyncSurfaceCatalogueTest, QualifiesDeclarationsByOwningClassAndOverload)
{
  constexpr std::string_view header = R"(
    class FirstOwner {
      void route_async(Completion);
      void route_async(OtherCompletion);
    };
    struct SecondOwner {
      void route_async(Completion);
    };
    enum class NotAnOwner { route_async };
    void free_async(Completion);
    void caller() { first.route_async(completion); }
  )";

  EXPECT_THAT(derive_from_source(header, "owner.h"),
    ::testing::ElementsAre("owner.h::FirstOwner::route_async#1",
      "owner.h::FirstOwner::route_async#2",
      "owner.h::SecondOwner::route_async#1",
      "owner.h::<free>::free_async#1"));
}

// @relation(AC-SVR-DIAG-008-PARAMETERISED-CATALOGUE-COMPLETE, scope=function)
TEST(ServerAsyncSurfaceCatalogueTest, AssignsOnlyTheContiguousCriterionRelationToEachTest)
{
  constexpr std::string_view relationToken =
    "@rela"
    "tion";
  const std::string source = "// " + std::string{relationToken} +
                             "(AC-OWNER, scope=function)\n"
                             "// obligation invariant\n"
                             "TEST_F(OwnerTest, ForwardsFailure) {}\n"
                             "const auto markerData = \"" +
                             std::string{relationToken} +
                             "(AC-NOT-A-COMMENT, scope=function)\";\n"
                             "TEST(OtherTest, HasNoRelation) {}\n";

  const auto relations = test_relations_from_source(source);
  ASSERT_TRUE(relations.contains("OwnerTest.ForwardsFailure"));
  EXPECT_THAT(relations.at("OwnerTest.ForwardsFailure"), ::testing::ElementsAre("AC-OWNER"));
  ASSERT_TRUE(relations.contains("OtherTest.HasNoRelation"));
  EXPECT_THAT(relations.at("OtherTest.HasNoRelation"), IsEmpty());
}

// @relation(AC-SVR-DIAG-008-PARAMETERISED-CATALOGUE-COMPLETE, scope=function)
TEST(ServerAsyncSurfaceCatalogueTest, RejectsUnclassifiedDuplicateAndUnresolvedOwnershipRows)
{
  const std::vector<std::string> derived{"owner.h::first_async#1", "owner.h::second_async#1"};
  const std::set<std::string> criteria{"AC-OWNER"};
  const TestRelations testRelations{
    {"OwnerTest.ForwardsFailure", {"AC-OWNER"}}, {"OwnerTest.MissingRelation", {"AC-OTHER"}}};

  EXPECT_THAT(validate(derived,
                {Row{"owner.h::first_async#1", "propagates_result", "AC-OWNER", "OwnerTest.ForwardsFailure"},
                  Row{"owner.h::second_async#1", "fire_and_forget", {}, {}}},
                criteria,
                testRelations),
    IsEmpty());

  const auto errors = validate(derived,
    {Row{"owner.h::first_async#1", "propagates_result", "AC-MISSING", "OwnerTest.Missing"},
      Row{"owner.h::first_async#1", "propagates_result", "AC-OWNER", "OwnerTest.ForwardsFailure"},
      Row{"stale.h::old_async#1", "private_continuation", {}, {}},
      Row{"owner.h::third_async#1", "not-a-class", {}, {}},
      Row{"owner.h::fourth_async#1", "fire_and_forget", "AC-OWNER", "OwnerTest.ForwardsFailure"}},
    criteria,
    testRelations);

  EXPECT_THAT(errors, Contains("duplicate:owner.h::first_async#1"));
  EXPECT_THAT(errors, Contains("criterion:owner.h::first_async#1"));
  EXPECT_THAT(errors, Contains("test:owner.h::first_async#1"));
  EXPECT_THAT(errors, Contains("stale:stale.h::old_async#1"));
  EXPECT_THAT(errors, Contains("classification:owner.h::third_async#1"));
  EXPECT_THAT(errors, Contains("nonpropagating-owner:owner.h::fourth_async#1"));
  EXPECT_THAT(errors, Contains("unclassified:owner.h::second_async#1"));

  const auto relationErrors = validate(derived,
    {Row{"owner.h::first_async#1", "propagates_result", "AC-OWNER", "OwnerTest.MissingRelation"},
      Row{"owner.h::second_async#1", "fire_and_forget", {}, {}}},
    criteria,
    testRelations);
  EXPECT_THAT(relationErrors, Contains("relation:owner.h::first_async#1"));
}

// A locally generated result has no downstream result identity and therefore no propagation owner.
// @relation(AC-SVR-DIAG-008-ASYNC-INVENTORY-COMPLETE, scope=function)
TEST(ServerAsyncSurfaceCatalogueTest, AcceptsOwnerlessLocallyGeneratedResultsAndRejectsUnknownClassification)
{
  const std::vector<std::string> derived{"owner.h::local_async#1"};

  EXPECT_THAT(validate(derived, {Row{"owner.h::local_async#1", "locally_generated_result", {}, {}}}, {}, {}),
    IsEmpty());

  const auto unknownErrors =
    validate_inventory(derived, {Row{"owner.h::local_async#1", "locally-generated-result", {}, {}}});
  EXPECT_THAT(unknownErrors, Contains("classification:owner.h::local_async#1"));

  const auto ownerErrors = validate(derived,
    {Row{"owner.h::local_async#1", "locally_generated_result", "AC-OWNER", "OwnerTest.Local"}},
    {"AC-OWNER"},
    {{"OwnerTest.Local", {"AC-OWNER"}}});
  EXPECT_THAT(ownerErrors, Contains("nonpropagating-owner:owner.h::local_async#1"));
}

// Repository invariant: every qualified server async declaration has one explicit classification
// in the checked-in catalogue. Runtime propagation ownership remains enforced separately by
// validate() and its full-owner criterion; this inventory arm does not accept missing rows or an
// unknown classification.
// @relation(AC-SVR-DIAG-008-ASYNC-INVENTORY-COMPLETE, scope=function)
TEST(ServerAsyncSurfaceCatalogueTest, EveryServerAsyncEntryPointHasACatalogueRow)
{
  const auto root = repository_root();
  // This test reads the SDK's own sources to check a structural property, and finds them by walking
  // up to a marker that exists only in the full development checkout. Without that checkout it fails
  // and names what is missing; a tree that cannot carry the sources leaves this test out of its run
  // through tests/development_only_tests.txt, not by a skip.
  ASSERT_FALSE(root.empty()) << "missing the full development checkout: no repository-root marker "
                                "above UASDK_TEST_SOURCE_DIR (" UASDK_TEST_SOURCE_DIR
                                "), so the audited SDK sources are absent";
  const auto manifest = root / "internal" / "tooling" / "traceability" / "server_async_surface_catalogue.tsv";
  ASSERT_TRUE(std::filesystem::exists(manifest));
  const auto derived = test_helpers::server_async_catalogue::derive(root);
  ASSERT_FALSE(derived.empty());
  EXPECT_THAT(
    validate_inventory(derived, test_helpers::server_async_catalogue::read_manifest(manifest)), IsEmpty());
}

}  // namespace
}  // namespace ua::test
