// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The two directory policies of ua_owner_only_directory.h: a fresh per-use subdirectory that is owner-only
// and never handed out twice, and the lenient create for an operator-configured location, which locks down
// only what it creates.

#include "ua_owner_only_directory.h"

#include "test_utilities.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <system_error>

namespace
{

std::filesystem::path fresh_parent(const char* name)
{
  const auto parent = ua::test_utils::unique_temp_path(name);
  std::error_code ignored;
  std::filesystem::remove_all(parent, ignored);
  std::filesystem::create_directories(parent);
  return parent;
}

}  // namespace

// Each call gives a new, empty directory of its own inside the parent, owner-only from the start, so two
// users of the parent never share one (the registrar store of each ServerWithDiscovery).
// @verifies AC-COMP-OWNER-ONLY-DIRECTORY-POLICIES
TEST(OwnerOnlyDirectory, EachSubdirectoryIsNewOwnerOnlyAndDistinct)
{
  const auto parent = fresh_parent("owner_only_subdirectory");
  const auto first = ua::security::create_owner_only_subdirectory(parent, "instance-", "Test");
  const auto second = ua::security::create_owner_only_subdirectory(parent, "instance-", "Test");

  EXPECT_NE(first, second);
  EXPECT_EQ(first.parent_path(), parent);
  EXPECT_TRUE(std::filesystem::is_directory(first));
  EXPECT_TRUE(std::filesystem::is_empty(first));
  EXPECT_EQ(first.filename().string().rfind("instance-", 0), 0u) << "the prefix names the directory";
#ifndef _WIN32
  const auto permissions = std::filesystem::status(first).permissions();
  EXPECT_EQ(permissions & (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
    std::filesystem::perms::none);
#endif
  std::error_code ignored;
  std::filesystem::remove_all(parent, ignored);
}

// The lenient create locks down a directory it creates, and leaves an existing one - an operator's choice,
// possibly shared - exactly as it was.
// @verifies AC-COMP-OWNER-ONLY-DIRECTORY-POLICIES
TEST(OwnerOnlyDirectory, TheLenientCreateLocksDownOnlyWhatItCreates)
{
  const auto parent = fresh_parent("owner_only_lenient");
  const auto created = parent / "a" / "b";
  std::error_code error;
  EXPECT_TRUE(ua::security::create_directories_owner_only(created, error));
  EXPECT_FALSE(error) << error.message();
  EXPECT_TRUE(std::filesystem::is_directory(created));
#ifndef _WIN32
  EXPECT_EQ(std::filesystem::status(created).permissions() &
              (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
    std::filesystem::perms::none);

  const auto existing = parent / "shared";
  std::filesystem::create_directories(existing);
  std::filesystem::permissions(existing,
    std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
      std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
      std::filesystem::perms::others_exec);
  const auto before = std::filesystem::status(existing).permissions();
  EXPECT_FALSE(ua::security::create_directories_owner_only(existing, error));
  EXPECT_FALSE(error) << error.message();
  EXPECT_EQ(std::filesystem::status(existing).permissions(), before)
    << "an existing directory was changed; it is the operator's, and may be shared";
#endif
  std::error_code ignored;
  std::filesystem::remove_all(parent, ignored);
}
