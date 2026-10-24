// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "test_log_sink.h"

#include "test_utilities.h"
#include "ua_instance_tracker.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#ifndef UASDK_TEST_REPORT_DIR
#define UASDK_TEST_REPORT_DIR ""
#endif

namespace
{
// -- Execution evidence -------------------------------------------------------------------------------------
//
// A traceability marker proves a test exists. Only a JUnit report proves it ran and passed, and the
// traceability gate reads `build/test-reports/*.gtest.junit.xml` to tell the two apart. Rather than
// require every caller - CI, the shard runner, a developer - to remember `--gtest_output`, a
// whole-suite run names its own report. The suites are already run; this is what turns those runs
// into evidence.
//
// Two rules keep the artefact honest rather than merely present.

// A filter that selects a subset must not write. GoogleTest's filter is a ':'-separated list of
// positive patterns, optionally followed by '-' and a list of negative ones; an empty or '*'
// positive list is the whole suite. So `--gtest_filter=-*LeakLoop*` - how CI runs the integration
// suite - still writes, while `--gtest_filter=ConnectionImplTest.*` does not. Without this, a
// three-test dev loop would overwrite the whole-suite report with a three-test file and the corpus
// would read it as the suite having passed.
bool filter_selects_a_subset(std::string_view filter)
{
  const std::string_view positives = filter.substr(0, filter.find('-'));
  for (size_t start = 0; start <= positives.size();)
  {
    const size_t end = std::min(positives.find(':', start), positives.size());
    const std::string_view pattern = positives.substr(start, end - start);
    if (!pattern.empty() && pattern != "*")
    {
      return true;
    }
    start = end + 1;
  }
  return false;
}

// Remove the per-shard reports left by an earlier sharded run of the same suite.
void discard_stale_reports(const std::string& dir, const std::string& suite)
{
  std::error_code ec;
  const std::string prefix = suite + ".shard-";
  for (const auto& entry : std::filesystem::directory_iterator(dir, ec))
  {
    const std::string name = entry.path().filename().string();
    if (name.rfind(prefix, 0) == 0 && name.size() > prefix.size() &&
        name.find(".gtest.junit.xml") != std::string::npos)
    {
      std::filesystem::remove(entry.path(), ec);
    }
  }
}

// The `--gtest_filter=` value on the command line, or nothing if it was not passed there.
// GoogleTest folds the GTEST_FILTER *environment* variable into the flag's default at static
// initialisation, so the flag is already right for that route; the command line is the one this has
// to read for itself, because it is only parsed by InitGoogleTest - which is too late (see below).
std::optional<std::string_view> filter_from_command_line(int argc, char** argv)
{
  std::optional<std::string_view> found;
  for (int i = 1; i < argc; ++i)
  {
    const std::string_view arg = argv[i];
    for (const std::string_view prefix : {"--gtest_filter=", "-gtest_filter="})
    {
      if (arg.substr(0, prefix.size()) == prefix)
      {
        found = arg.substr(prefix.size());  // last one wins, as GoogleTest's own parser does
      }
    }
  }
  return found;
}

// Where this process should write its report, or empty for "do not write".
//
// Called BEFORE InitGoogleTest, which is the whole subtlety here: InitGoogleTest ends by running
// PostFlagParsingInit(), and that is what installs the XML printer from the output flag. A value
// set afterwards is stored and never read, so the suite runs and writes nothing. Setting it first
// also gives the right precedence for free - a `--gtest_output` on the command line is parsed after
// this and overwrites it, so an explicit destination still wins.
std::string default_report_path(int argc, char** argv)
{
  const char* const disabled = std::getenv("UA_TEST_REPORT");
  if (disabled != nullptr && std::string_view(disabled) == "0")
  {
    return {};
  }
  // GTEST_FLAG_GET rather than GTEST_FLAG: the latter is the raw variable and does not compile
  // against a googletest built on absl flags. Non-empty here means GTEST_OUTPUT was set in the
  // environment, which is a caller naming a destination.
  if (!GTEST_FLAG_GET(output).empty())
  {
    return {};
  }
  const std::optional<std::string_view> fromArgv = filter_from_command_line(argc, argv);
  if (filter_selects_a_subset(fromArgv.value_or(GTEST_FLAG_GET(filter))))
  {
    return {};
  }
  // A listing is not an execution. `gtest_discover_tests` runs the freshly-built binary with
  // `--gtest_list_tests` after every build, and GoogleTest honours the output flag for that too -
  // producing a report of every test in the suite, with no `failures` attribute and no result on
  // any case. StrictDoc cannot read it, and a reader who could would see six tests and no failures
  // for a run that executed nothing. Manufacturing evidence for tests that never ran is the exact
  // defect this mechanism exists to prevent, so the listing writes nothing.
  for (int i = 1; i < argc; ++i)
  {
    const std::string_view arg = argv[i];
    if (arg == "--gtest_list_tests" || arg == "-gtest_list_tests")
    {
      return {};
    }
  }

  const char* const fromEnv = std::getenv("UA_TEST_REPORT_DIR");
  const std::string dir = fromEnv != nullptr ? fromEnv : UASDK_TEST_REPORT_DIR;
  if (dir.empty())
  {
    return {};
  }

  // The binary names its own report, so a suite added later needs no build plumbing to be covered.
  std::string suite = argc > 0 && argv[0] != nullptr ? argv[0] : "";
  suite = suite.substr(suite.find_last_of("/\\") + 1);
  if (suite.size() > 4 && suite.compare(suite.size() - 4, 4, ".exe") == 0)
  {
    suite.resize(suite.size() - 4);
  }
  if (suite.empty())
  {
    return {};
  }

  // One report per shard. `run_sharded_tests.sh` starts one process per shard over a disjoint slice
  // of the suite; a single path would have them race for the file, and the consumers glob the
  // directory and merge, so disjoint reports compose without a join step. Sharding has no
  // GoogleTest flag - it is environment-only - so the environment is where it is read from.
  const char* const totalShards = std::getenv("GTEST_TOTAL_SHARDS");
  const char* const shardIndex = std::getenv("GTEST_SHARD_INDEX");
  if (totalShards != nullptr && shardIndex != nullptr && std::atoi(totalShards) > 1)
  {
    suite += ".shard-";
    suite += shardIndex;
  }
  else
  {
    // An unsharded run supersedes whatever an earlier sharded run of this suite left behind. Those
    // files are not overwritten by this one, and the consumers glob the directory, so leaving them
    // would have last week's shard reporting PASSED for a test that this run did not execute - the
    // stale-evidence failure that makes a report worse than no report. The sharded runner does the
    // same in the other direction before it launches, which is where it can be done without the
    // shards racing to prune each other.
    discard_stale_reports(dir, suite);
  }
  return "xml:" + dir + "/" + suite + ".gtest.junit.xml";
}

// Reclaims the per-test trust-list directories that create_test_config roots at
// ./temp/test_pki/{app,user}/<guid>/. Nothing else deletes them, and the SDK
// materialises seven subdirectories under each, so an unswept tree grows by
// hundreds of thousands of directories over a few weeks of local runs - enough to
// exhaust fs.inotify.max_user_watches, which silently demotes IDE file watching to
// polling the entire repository.
//
// A global environment rather than a fixture teardown because the directories are
// allocated by a free function with call sites across the whole suite; per-fixture
// cleanup would have to be opted into by every one of them, and would be missed by
// the next fixture that calls create_test_config.
class TrustListDirCleanup : public ::testing::Environment
{
  void TearDown() override
  {
    ua::test_utils::cleanup_process_trust_list_dirs();
  }
};

// Diagnostic (env-gated, inert unless UA_TRACK_NODES is set): logs the live
// DefaultBaseNode count at each test boundary so a leaked NS0 graph shows up as
// a step-up in the at-test-end count that never comes back down - pinpointing the
// triggering test.
class NodeCountListener : public ::testing::EmptyTestEventListener
{
  void OnTestEnd(const ::testing::TestInfo& info) override
  {
    const auto live = ua::diagnostics::InstanceTracker<ua::diagnostics::DefaultBaseNodeTag>::live();
    std::fprintf(
      stderr, "[NODES] %zu after %s.%s\n", static_cast<size_t>(live), info.test_suite_name(), info.name());
  }
};
}  // namespace

int main(int argc, char** argv)
{
  // Before InitGoogleTest, not after: InitGoogleTest installs the XML printer from this flag, so a
  // value set afterwards is stored and never acted on.
  const std::string report = default_report_path(argc, argv);
  if (!report.empty())
  {
    GTEST_FLAG_SET(output, report);
  }
  testing::InitGoogleTest(&argc, argv);
  ua::test_helpers::install_test_log_listener();
  testing::AddGlobalTestEnvironment(new TrustListDirCleanup);
  if (std::getenv("UA_TRACK_NODES") != nullptr)
  {
    testing::UnitTest::GetInstance()->listeners().Append(new NodeCountListener);
  }
  return RUN_ALL_TESTS();
}
