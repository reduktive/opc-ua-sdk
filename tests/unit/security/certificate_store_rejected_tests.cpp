// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "certificate_validation_request_helpers.h"
#include "test_utilities.h"
#include "ua_logger.h"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <mutex>
#include <boost/asio/thread_pool.hpp>
#include "certificate_store_test_backends.h"
#include "test_pki_helpers.h"

namespace fs = std::filesystem;
using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// LogSink that records entries for test verification.
class RecordingSink : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    std::lock_guard lk(mMutex);
    mEntries.push_back(Entry{entry.level, entry.message});
  }

  struct Entry
  {
    LogLevel level;
    std::string message;
  };

  bool has_error_containing(const std::string& substr) const
  {
    std::lock_guard lk(mMutex);
    for (const auto& entry : mEntries)
    {
      if (entry.level == LogLevel::Error && entry.message.find(substr) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

Logger make_recording_logger(std::shared_ptr<RecordingSink> sink)
{
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  return Logger{std::move(sink), std::move(level), "test"};
}

}  // namespace

/// Tests for the store-to-rejected filtering logic (S1a).
/// The `CertificateStoreFiles::store_to_rejected` method is private static,
/// so it is exercised indirectly through `try_validate_certificate_sync` and
/// then inspected via `try_get_rejected_certificates_sync`.
template<typename TBackend>
class CertificateStoreStoreRejectedTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = TBackend::create_crypto();
    // Unique per test instance so parallel shards sharing a cwd don't collide on this store.
    mRootPath =
      test_utils::unique_temp_path(std::string("cert_store_rejected_") + std::string(TBackend::name));
    fs::remove_all(mRootPath);

    mPki = std::make_unique<TestPki>(mCrypto);

    mRootKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mRootCert = mPki->create_root_ca(mRootKeys);
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
    if constexpr (TBackend::supportsFilesystem)
    {
      fs::remove_all(mRootPath);
    }
  }

  /// Create a store with the given storeRejected flag, pre-populated with the root CA as trusted.
  std::shared_ptr<CertificateStore> create_store_with_rejected_flag(
    bool storeRejected, const std::string& suffix = "", Logger logger = Logger{})
  {
    auto storePath = mRootPath / ("store" + suffix);
    auto store = CertificateStoreFiles::create(mThreadPool.get_executor(),
      mCrypto,
      {.trustListPath = storePath, .storeRejectedCertificates = storeRejected, .logger = std::move(logger)});
    store->add_to_trusted_certificates_sync(mRootCert);
    return store;
  }

  /// Create a self-signed (untrusted) certificate.
  std::shared_ptr<const X509Certificate> create_untrusted_cert()
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    return mPki->create_root_ca(keys);
  }

  /// Create a leaf cert signed by the trusted root.
  std::shared_ptr<const X509Certificate> create_trusted_leaf()
  {
    auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    return mPki->create_leaf_cert(leafKeys,
      mRootKeys,
      mRootCert,
      DateTime::now(),
      DateTime{DateTime::now().value() + std::chrono::days{10}});
  }

  fs::path mRootPath;
  std::shared_ptr<const Crypto> mCrypto;
  boost::asio::thread_pool mThreadPool;
  std::unique_ptr<TestPki> mPki;
  std::shared_ptr<const AsymmetricKeyPair> mRootKeys;
  std::shared_ptr<const X509Certificate> mRootCert;
};

TYPED_TEST_SUITE(CertificateStoreStoreRejectedTests, Backends);

TYPED_TEST(CertificateStoreStoreRejectedTests, UntrustedCertStoredWhenStoreRejectedEnabled)
{
  auto store = this->create_store_with_rejected_flag(true, "_untrusted_on");
  auto untrusted = this->create_untrusted_cert();

  auto status =
    store->try_validate_certificate_sync(ua::test::make_validation_request(untrusted, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateUntrusted);

  // Give the async store-to-rejected a moment to complete.
  std::this_thread::sleep_for(200ms);

  auto rejected = store->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good());
  EXPECT_EQ(rejected.value().size(), 1u);
  EXPECT_EQ(rejected.value()[0]->thumbprint(), untrusted->thumbprint());
}

TYPED_TEST(CertificateStoreStoreRejectedTests, UntrustedCertNotStoredWhenStoreRejectedDisabled)
{
  auto store = this->create_store_with_rejected_flag(false, "_untrusted_off");
  auto untrusted = this->create_untrusted_cert();

  auto status =
    store->try_validate_certificate_sync(ua::test::make_validation_request(untrusted, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateUntrusted);

  std::this_thread::sleep_for(200ms);

  auto rejected = store->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good());
  EXPECT_EQ(rejected.value().size(), 0u);
}

// A CA-issued certificate whose issuer the store does not hold reports Bad_CertificateChainIncomplete
// (Part 4 Table 106) where it reported Bad_CertificateUntrusted, and is still recorded in the rejected
// list for the administrator to review and trust.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-05-CHAIN-INCOMPLETE-KEEPS-ITS-CONSUMERS, scope=function)
TYPED_TEST(CertificateStoreStoreRejectedTests, CertificateWithAnUnknownIssuerIsStoredToRejected)
{
  auto store = this->create_store_with_rejected_flag(true, "_unknown_issuer");
  auto otherCaKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = this->mPki->create_root_ca(otherCaKeys, "Unknown Issuer CA", "9301");
  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(leafKeys,
    otherCaKeys,
    otherCa,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  auto status =
    store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateChainIncomplete);

  std::this_thread::sleep_for(200ms);

  auto rejected = store->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good());
  ASSERT_EQ(rejected.value().size(), 1u);
  EXPECT_EQ(rejected.value()[0]->thumbprint(), leaf->thumbprint());
}

TYPED_TEST(CertificateStoreStoreRejectedTests, ValidCertNotStoredToRejected)
{
  auto store = this->create_store_with_rejected_flag(true, "_valid");
  auto leaf = this->create_trusted_leaf();

  auto status =
    store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_TRUE(status.is_good());

  std::this_thread::sleep_for(200ms);

  auto rejected = store->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good());
  EXPECT_EQ(rejected.value().size(), 0u);
}

/// The rejected-store tests that break the on-disk store, instantiated only for the backends that
/// persist to the filesystem.
template<typename TBackend>
class CertificateStoreFilesystemRejectedTests : public CertificateStoreStoreRejectedTests<TBackend>
{};

TYPED_TEST_SUITE(CertificateStoreFilesystemRejectedTests, FilesystemBackends);

TYPED_TEST(CertificateStoreFilesystemRejectedTests, PersistFailureToRejectedStoreIsLogged)
{
  auto sink = std::make_shared<RecordingSink>();
  auto store = this->create_store_with_rejected_flag(true, "_persist_fail", make_recording_logger(sink));

  // Break the RejectedCertificates store so the best-effort persist fails: replace the
  // directory with a regular file. write_cert then opens a path under a non-directory and
  // throws (ENOTDIR), even when the test runs as root (chmod read-only would be bypassed).
  auto rejectedDir = this->mRootPath / "store_persist_fail" / "TrustList" / "RejectedCertificates";
  fs::remove_all(rejectedDir);
  {
    std::ofstream blocker(rejectedDir);
  }
  ASSERT_TRUE(fs::is_regular_file(rejectedDir));

  auto untrusted = this->create_untrusted_cert();

  auto status =
    store->try_validate_certificate_sync(ua::test::make_validation_request(untrusted, {}, std::nullopt));
  // The validation verdict must remain unchanged regardless of the persist failure.
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateUntrusted);

  // Give the async store-to-rejected a moment to complete and emit its failure log.
  std::this_thread::sleep_for(200ms);

  EXPECT_TRUE(sink->has_error_containing("persist rejected certificate"))
    << "Expected an Error log entry when persisting a rejected certificate to the store fails";

  // Restore the path so TearDown's fs::remove_all succeeds cleanly.
  fs::remove_all(rejectedDir);
}

TYPED_TEST(CertificateStoreStoreRejectedTests, UriInvalidCertStoredToRejected)
{
  auto store = this->create_store_with_rejected_flag(true, "_uri_invalid");

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(leafKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}},
    {"urn:wrong:uri"});

  auto status = store->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, std::nullopt, "urn:correct:uri", std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateUriInvalid);

  std::this_thread::sleep_for(200ms);

  auto rejected = store->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good());
  EXPECT_EQ(rejected.value().size(), 1u);
  EXPECT_EQ(rejected.value()[0]->thumbprint(), leaf->thumbprint());
}

// Security regression (anti pre-auth cert-flood DoS): the rejected store is bounded. A remote,
// unauthenticated peer can present unlimited distinct certificates during OpenSecureChannel - each a
// fresh self-signed cert with a unique thumbprint that defeats the dedup - so without a cap the store
// (and the on-disk RejectedCertificates/ directory) grows without bound. With a cap of 2, adding 3
// distinct certificates must evict the oldest (FIFO) and leave exactly 2.
TYPED_TEST(CertificateStoreStoreRejectedTests, RejectedStoreIsBoundedAndEvictsOldest)
{
  auto storePath = this->mRootPath / "store_cap";
  auto store = CertificateStoreFiles::create(this->mThreadPool.get_executor(),
    this->mCrypto,
    {.trustListPath = storePath,
      .storeRejectedCertificates = true,
      .maxRejectedCertificates = 2});

  auto first = this->create_untrusted_cert();
  auto second = this->create_untrusted_cert();
  auto third = this->create_untrusted_cert();

  store->add_to_rejected_certificates_sync(first);
  store->add_to_rejected_certificates_sync(second);
  store->add_to_rejected_certificates_sync(third);

  auto rejected = store->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good());
  ASSERT_EQ(rejected.value().size(), 2u) << "rejected store must be capped at maxRejectedCertificates";

  bool hasFirst = false;
  bool hasThird = false;
  for (const auto& cert : rejected.value())
  {
    if (cert->thumbprint() == first->thumbprint())
    {
      hasFirst = true;
    }
    if (cert->thumbprint() == third->thumbprint())
    {
      hasThird = true;
    }
  }
  EXPECT_FALSE(hasFirst) << "the oldest rejected certificate must be evicted at the cap";
  EXPECT_TRUE(hasThird) << "the newest rejected certificate must be retained";
}
