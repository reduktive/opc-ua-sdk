// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The shared test key cache (tests/helpers/test_key_cache.h), against the owner's contract in
// the certificate coverage review "Test key and certificate creation": one key per (type, slot), in
// process and across processes; distinct slots differ; a corrupt file is regenerated; the directory is
// 0700 and every file 0600; UASDK_TEST_KEY_CACHE names the directory; concurrent first use yields one key.

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <openssl/evp.h>

#include "certificate_store_test_backends.h"
#include "test_key_cache.h"
#include "test_utilities.h"
#include "ua_crypto.h"

namespace
{

namespace fs = std::filesystem;
using ua::test_keys::KeyType;

/// Sets an environment variable for the life of the object and restores the previous value after.
class ScopedEnvironment
{
public:
  ScopedEnvironment(const char* name, const std::string& value) : mName{name}
  {
    if (const char* previous = std::getenv(name); previous != nullptr)
    {
      mPrevious = std::string{previous};
    }
    set(value);
  }

  ~ScopedEnvironment()
  {
    if (mPrevious)
    {
      set(*mPrevious);
    }
    else
    {
#if defined(_WIN32)
      ::_putenv_s(mName.c_str(), "");
#else
      ::unsetenv(mName.c_str());
#endif
    }
  }

  ScopedEnvironment(const ScopedEnvironment&) = delete;
  ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

private:
  void set(const std::string& value)
  {
#if defined(_WIN32)
    ::_putenv_s(mName.c_str(), value.c_str());
#else
    ::setenv(mName.c_str(), value.c_str(), 1);
#endif
  }

  std::string mName;
  std::optional<std::string> mPrevious;
};

/// Each case owns a fresh cache directory, so what it observes is its own generation and nothing a
/// previous run left in the machine-wide cache. Ed25519 keeps generation cheap.
class TestKeyCacheTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mParent = ua::test_utils::unique_temp_path("test_key_cache");
    mDirectory = mParent / "keys";
  }

  void TearDown() override
  {
    ua::test_keys::clear_in_process_cache();
    std::error_code ignored;
    fs::remove_all(mParent, ignored);
  }

  fs::path file_of(KeyType type, unsigned slot) const
  {
    return mDirectory / (ua::test_keys::type_name(type) + "-" + std::to_string(slot) + ".pem");
  }

  fs::path mParent;
  fs::path mDirectory;
};

TEST_F(TestKeyCacheTest, TheSameTypeAndSlotReturnTheSameKeyInProcess)
{
  const auto first = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  const auto second = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  EXPECT_EQ(first, second);
}

TEST_F(TestKeyCacheTest, ASecondProcessLoadsTheKeyTheFirstStoredOnDisk)
{
  const auto first = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  ua::test_keys::clear_in_process_cache();  // As a second process starts: nothing in memory.
  const auto second = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  EXPECT_EQ(first, second);
}

TEST_F(TestKeyCacheTest, DistinctSlotsAreDistinctKeys)
{
  const auto slot0 = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  const auto slot1 = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 1);
  EXPECT_NE(slot0, slot1);
}

TEST_F(TestKeyCacheTest, ACorruptCacheFileIsRegeneratedAsAValidKey)
{
  static_cast<void>(ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0));
  ua::test_keys::clear_in_process_cache();
  {
    std::ofstream corrupt{file_of(KeyType::Ed25519, 0), std::ios::binary | std::ios::trunc};
    corrupt << "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n";
  }
  const auto regenerated = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  std::ifstream onDisk{file_of(KeyType::Ed25519, 0), std::ios::binary};
  const std::string stored{std::istreambuf_iterator<char>{onDisk}, std::istreambuf_iterator<char>{}};
  EXPECT_EQ(stored, regenerated);
  EXPECT_EQ(regenerated.find("not a key"), std::string::npos);
}

TEST_F(TestKeyCacheTest, AFileOfTheWrongKeyTypeIsRegenerated)
{
  // A valid key of another type under this type's name is as corrupt as garbage: the type is the contract.
  const auto ed448 = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed448, 0);
  {
    std::ofstream wrong{file_of(KeyType::Ed25519, 0), std::ios::binary | std::ios::trunc};
    wrong << ed448;
  }
  const auto ed25519 = ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
  EXPECT_NE(ed25519, ed448);
}

#if !defined(_WIN32)
TEST_F(TestKeyCacheTest, TheDirectoryIsOwnerOnlyAndEveryKeyFileIsOwnerReadWriteOnly)
{
  static_cast<void>(ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0));
  const auto all = fs::perms::all;
  EXPECT_EQ(fs::status(mDirectory).permissions() & all, fs::perms::owner_all);
  EXPECT_EQ(fs::status(file_of(KeyType::Ed25519, 0)).permissions() & all,
    fs::perms::owner_read | fs::perms::owner_write);
}
#endif

TEST_F(TestKeyCacheTest, NoTemporaryFileIsLeftBehind)
{
  static_cast<void>(ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0));
  std::vector<std::string> names;
  for (const auto& entry : fs::directory_iterator{mDirectory})
  {
    names.push_back(entry.path().filename().string());
  }
  EXPECT_EQ(names, std::vector<std::string>{"ed25519-0.pem"});
}

TEST_F(TestKeyCacheTest, TheEnvironmentOverrideNamesTheCacheDirectory)
{
  const ScopedEnvironment environment{"UASDK_TEST_KEY_CACHE", mDirectory.string()};
  EXPECT_EQ(ua::test_keys::cache_directory(), mDirectory);
  static_cast<void>(ua::test_keys::private_key_pem(KeyType::Ed25519, 0));
  EXPECT_TRUE(fs::exists(file_of(KeyType::Ed25519, 0)));
}

TEST_F(TestKeyCacheTest, WithoutTheOverrideTheCacheIsTheVersionedDirectoryUnderXdgCacheHome)
{
  const ScopedEnvironment noOverride{"UASDK_TEST_KEY_CACHE", ""};
  const ScopedEnvironment xdg{"XDG_CACHE_HOME", mParent.string()};
  EXPECT_EQ(ua::test_keys::cache_directory(), mParent / "reduktive-uasdk" / "test-keys" / "v1");
}

TEST_F(TestKeyCacheTest, ConcurrentFirstUseFromSeveralThreadsYieldsOneKey)
{
  constexpr int threadCount = 8;
  std::vector<std::string> seen(threadCount);
  {
    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; ++i)
    {
      threads.emplace_back(
        [this, &seen, i] {
          seen[static_cast<std::size_t>(i)] =
            ua::test_keys::private_key_pem_in(mDirectory, KeyType::Ed25519, 0);
        });
    }
    for (auto& thread : threads)
    {
      thread.join();
    }
  }
  EXPECT_EQ(std::set<std::string>(seen.begin(), seen.end()).size(), 1U);
}

TEST_F(TestKeyCacheTest, EveryKeyTypeIsCreatedOrRefusedWithAClearError)
{
  const ScopedEnvironment environment{"UASDK_TEST_KEY_CACHE", mDirectory.string()};
  for (const auto type : {KeyType::Rsa1024,
         KeyType::P256,
         KeyType::P384,
         KeyType::P521,
         KeyType::Bp256,
         KeyType::Bp384,
         KeyType::Bp512,
         KeyType::Ed25519,
         KeyType::Ed448})
  {
    try
    {
      const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
        ua::test_keys::new_evp_pkey(type, 0), &EVP_PKEY_free};
      EXPECT_NE(key, nullptr) << ua::test_keys::type_name(type);
    }
    catch (const std::runtime_error& error)
    {
      EXPECT_NE(std::string{error.what()}.find(ua::test_keys::type_name(type)), std::string::npos);
    }
  }
}

TEST_F(TestKeyCacheTest, TheKeyPairLoadedThroughCryptoCarriesTheCachedKey)
{
  const ScopedEnvironment environment{"UASDK_TEST_KEY_CACHE", mDirectory.string()};
  const auto crypto = ua::BackendOpenSslFiles::create_crypto();
  const auto first = ua::test_keys::key_pair(*crypto, KeyType::P256, 0);
  const auto again = ua::test_keys::key_pair(*crypto, KeyType::P256, 0);
  const auto other = ua::test_keys::key_pair(*crypto, KeyType::P256, 1);
  ASSERT_NE(first, nullptr);
  EXPECT_EQ(first->public_key_der(), again->public_key_der());
  EXPECT_NE(first->public_key_der(), other->public_key_der());
}

}  // namespace
