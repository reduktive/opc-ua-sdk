// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "example_pki.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <stdexcept>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>

namespace
{
std::filesystem::path fresh_root(const char* tag)
{
  const auto root = std::filesystem::temp_directory_path() /
                    ("uasdk-example-pki-test-" + std::string{tag} + "-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  return root;
}

struct Removal
{
  std::filesystem::path path;

  ~Removal()
  {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
};
}  // namespace

// DEF-8: the example PKI root is created for this user alone, whatever the umask says.
// @verifies AC-SVR-SECADMIN-071-EXAMPLE-PKI-ROOT-IS-OWNER-ONLY
TEST(ExamplePki, CreatesAnOwnerOnlyRoot)
{
  const auto root = fresh_root("create");
  const Removal cleanup{root};

  struct UmaskGuard
  {
    mode_t previous{::umask(0)};

    ~UmaskGuard()
    {
      ::umask(previous);
    }
  };

  {
    const UmaskGuard permissive;  // restored on every path, a throwing prepare included
    examples::prepare_development_pki_root(root);
  }

  struct stat info
  {};

  ASSERT_EQ(::lstat(root.c_str(), &info), 0);
  EXPECT_TRUE(S_ISDIR(info.st_mode));
  EXPECT_EQ(info.st_mode & 0777, 0700u) << "created 0700 regardless of the umask";
  EXPECT_NO_THROW(examples::prepare_development_pki_root(root)) << "an owner-only root is accepted again";
}

// @verifies AC-SVR-SECADMIN-071-EXAMPLE-PKI-ROOT-IS-OWNER-ONLY
TEST(ExamplePki, RefusesAGroupWritableRoot)
{
  const auto root = fresh_root("group");
  const Removal cleanup{root};
  ASSERT_EQ(::mkdir(root.c_str(), 0770), 0);
  ::chmod(root.c_str(), 0770);
  EXPECT_THROW(examples::prepare_development_pki_root(root), std::runtime_error)
    << "a root another user can enter is refused, not silently used";
}

// @verifies AC-SVR-SECADMIN-071-EXAMPLE-PKI-ROOT-IS-OWNER-ONLY
TEST(ExamplePki, RefusesASymlinkedRoot)
{
  const auto target = fresh_root("symlink-target");
  const auto root = fresh_root("symlink");
  const Removal cleanupTarget{target};
  const Removal cleanupRoot{root};
  ASSERT_EQ(::mkdir(target.c_str(), 0700), 0);
  std::filesystem::create_directory_symlink(target, root);
  EXPECT_THROW(examples::prepare_development_pki_root(root), std::runtime_error)
    << "a planted symlink at the PKI path is refused";
}

// The per-user suffix keeps two users' PKI roots apart in the shared temporary directory.
// @verifies AC-SVR-SECADMIN-071-EXAMPLE-PKI-ROOT-IS-OWNER-ONLY
TEST(ExamplePki, RootNameCarriesTheUserId)
{
  const auto name = examples::development_pki_root().filename().string();
  EXPECT_NE(name.find(std::to_string(::geteuid())), std::string::npos) << name;
}
#endif  // !_WIN32
