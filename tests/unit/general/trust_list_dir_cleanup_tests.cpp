// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <filesystem>
#include <fstream>
#include <string_view>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace
{

/// Sandbox mirroring the on-disk layout `create_test_config` produces:
/// `<sandbox>/temp/test_pki/{app,user}/<id>/TrustList/TrustedCertificates/cert.der`.
///
/// Built under the system temp dir rather than `./temp` so these tests never touch
/// the tree the live suite is writing to, and torn down in the destructor so a
/// failed assertion cannot leak into the next test.
class PkiSandbox
{
public:
  PkiSandbox() : mRoot{ua::test_utils::unique_temp_path("pki_cleanup")}
  {
    fs::create_directories(mRoot);
  }

  ~PkiSandbox()
  {
    std::error_code ec;
    fs::remove_all(mRoot, ec);
  }

  PkiSandbox(const PkiSandbox&) = delete;
  PkiSandbox& operator=(const PkiSandbox&) = delete;

  /// One trust-list root holding nested directories and a file, so removal is
  /// exercised recursively rather than as an empty-directory delete.
  fs::path make_trust_list(std::string_view group, std::string_view id) const
  {
    const auto root = mRoot / "temp" / "test_pki" / group / id;
    fs::create_directories(root / "TrustList" / "TrustedCertificates");
    std::ofstream{root / "TrustList" / "TrustedCertificates" / "cert.der"} << "x";
    return root;
  }

  /// The shared scaffolding, innermost first - the sandbox-local equivalent of the
  /// parent list `cleanup_process_trust_list_dirs` passes in production.
  std::vector<fs::path> parents() const
  {
    return {mRoot / "temp" / "test_pki" / "app",
      mRoot / "temp" / "test_pki" / "user",
      mRoot / "temp" / "test_pki",
      mRoot / "temp"};
  }

  const fs::path& root() const
  {
    return mRoot;
  }

private:
  fs::path mRoot;
};

}  // namespace

TEST(TrustListDirCleanup, RemovesRegisteredRootWithItsContents)
{
  const PkiSandbox sandbox;
  const auto app = sandbox.make_trust_list("app", "id-1");
  ASSERT_TRUE(fs::exists(app / "TrustList" / "TrustedCertificates" / "cert.der"));

  ua::test_utils::detail::remove_trust_list_dirs({app}, sandbox.parents());

  EXPECT_FALSE(fs::exists(app));
}

TEST(TrustListDirCleanup, RemovesScaffoldingOnceLastRootIsReclaimed)
{
  const PkiSandbox sandbox;
  const auto app = sandbox.make_trust_list("app", "id-1");
  const auto user = sandbox.make_trust_list("user", "id-1");

  ua::test_utils::detail::remove_trust_list_dirs({app, user}, sandbox.parents());

  EXPECT_FALSE(fs::exists(sandbox.root() / "temp"))
    << "scaffolding must not survive the last GUID root, or it accumulates across runs";
}

/// The guard that makes end-of-run cleanup safe when several shards share a working
/// directory. Fails if the parents are ever reclaimed with `remove_all` instead of
/// `remove`, which would delete a concurrently running shard's live trust list.
TEST(TrustListDirCleanup, LeavesParentsHoldingAnotherProcessesRoots)
{
  const PkiSandbox sandbox;
  const auto mine = sandbox.make_trust_list("app", "mine");
  const auto theirs = sandbox.make_trust_list("app", "theirs");

  // Only "mine" is registered; "theirs" models a sibling process still running.
  ua::test_utils::detail::remove_trust_list_dirs({mine}, sandbox.parents());

  EXPECT_FALSE(fs::exists(mine));
  EXPECT_TRUE(fs::exists(theirs / "TrustList" / "TrustedCertificates" / "cert.der"))
    << "a sibling process's live trust list must survive our cleanup";
  EXPECT_TRUE(fs::exists(sandbox.root() / "temp" / "test_pki" / "app"))
    << "a non-empty parent must be left in place for the sibling to finish with";
}

/// A crashed prior run leaves registered paths that no longer exist, and the gtest
/// environment calling this must not turn that into a failure or a thrown exception.
TEST(TrustListDirCleanup, ToleratesMissingPaths)
{
  const PkiSandbox sandbox;
  const auto absent = sandbox.root() / "temp" / "test_pki" / "app" / "never-created";

  EXPECT_NO_THROW(ua::test_utils::detail::remove_trust_list_dirs({absent}, sandbox.parents()));
}
