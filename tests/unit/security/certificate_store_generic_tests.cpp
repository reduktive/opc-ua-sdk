// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "certificate_validation_request_helpers.h"
#include "ua_session_trust_store.h"
#include <gtest/gtest.h>

#include "test_utilities.h"
#include <algorithm>
#include <filesystem>
#include <future>
#include <optional>
#include <thread>
#include <boost/asio/thread_pool.hpp>
#include "certificate_store_test_backends.h"
#include "ua_error_chain.h"
#include "test_pki_helpers.h"

namespace fs = std::filesystem;
using namespace ua;
using namespace std::chrono_literals;

template<typename TBackend>
class CertificateStoreGenericTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = TBackend::create_crypto();
    // Unique per test instance so parallel shards sharing a cwd don't collide on this store.
    mRootPath = test_utils::unique_temp_path(std::string("cert_store_") + std::string(TBackend::name));
    fs::remove_all(mRootPath);

    ua::TrustListValidationOptions opts{};
    mStore = TBackend::create_store(mRootPath, mThreadPool.get_executor(), mCrypto, opts);

    mPki = std::make_unique<TestPki>(mCrypto);

    mCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mClientKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mCaCert = mPki->create_root_ca(mCaKeys);
    mClientCert = mPki->create_leaf_cert(mClientKeys,
      mCaKeys,
      mCaCert,
      DateTime::now(),
      DateTime{DateTime::now().value() + std::chrono::hours(24 * 365)});
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
    if constexpr (TBackend::supportsFilesystem)
      fs::remove_all(mRootPath);
  }

  fs::path mRootPath;
  std::shared_ptr<const ua::Crypto> mCrypto;
  boost::asio::thread_pool mThreadPool;
  std::shared_ptr<ua::CertificateStore> mStore;
  std::unique_ptr<TestPki> mPki;
  shared_ptr<const AsymmetricKeyPair> mCaKeys;
  shared_ptr<const AsymmetricKeyPair> mClientKeys;
  shared_ptr<const X509Certificate> mCaCert;
  shared_ptr<const X509Certificate> mClientCert;
};

TYPED_TEST_SUITE(CertificateStoreGenericTests, Backends);

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The trust list is empty, so the leaf is untrusted; with its issuer as additional trust for the one
// validation it is admitted, and the store's own trust list stays empty.
TYPED_TEST(CertificateStoreGenericTests, AdditionalTrustAdmitsALeafWhoseIssuerIsNotInTheTrustList)
{
  auto plain = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(this->mClientCert, {}, std::nullopt));
  ASSERT_TRUE(plain.is_bad()) << "the control: without additional trust the leaf is untrusted";

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  this->mStore->validate_certificate_async(
    ua::test::make_validation_request_with_connection_trust(
      this->mClientCert, {this->mCaCert}, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_TRUE(verdict.is_good()) << ua::to_string(verdict.status_code().as_status());
  EXPECT_TRUE(this->mStore->try_get_trusted_certificates_sync().value().empty())
    << "additional trust is for the one validation, never persisted";
}

// A CA-issued leaf in the ordinary trust list whose CA is absent needs its complete chain (Part 4 6.1.3,
// Build Certificate Chain); another certificate having been accepted for the session does not change
// that. No certificate is its own anchor (owner decision 22.5, reversing decision 13): the accepted
// certificate, whose CA is also absent, is refused as chain-incomplete as well.
// @verifies AC-CL-SECADMIN-003-ONLY-THE-ACCEPTED-CERTIFICATE-IS-ITS-OWN-ANCHOR
TYPED_TEST(CertificateStoreGenericTests, AnotherAcceptedCertificateDoesNotAnchorATrustedLeafWhoseCaIsAbsent)
{
  ASSERT_TRUE(this->mStore->try_add_to_trusted_certificates_sync(this->mClientCert).is_good());
  const auto plain = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(this->mClientCert, {}, std::nullopt));
  ASSERT_TRUE(plain.is_bad()) << "the control: a trusted leaf whose CA is absent has an incomplete chain";

  // The certificate the user accepted for this session: an ordinary leaf of another CA that is in
  // neither list, the shape a trust prompt produces.
  const auto otherCaKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto otherCa = this->mPki->create_root_ca(otherCaKeys, "Other CA", "7000");
  const auto otherKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto otherAccepted = this->mPki->create_leaf_cert(otherKeys,
    otherCaKeys,
    otherCa,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::hours(24 * 365)},
    {},
    {},
    "AcceptedForTheSession");

  const auto validateWithSessionTrust = [&](shared_ptr<const X509Certificate> certificate)
  {
    std::promise<ua::VoidResult> promise;
    auto future = promise.get_future();
    this->mStore->validate_certificate_async(
      ua::test::make_validation_request_with_connection_trust(
        std::move(certificate), {otherAccepted}, {}, std::nullopt, std::nullopt, std::nullopt),
      [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
    return future.get();
  };

  const auto verdict = validateWithSessionTrust(this->mClientCert);
  EXPECT_TRUE(verdict.is_bad()) << "another session acceptance must not anchor this leaf";
  EXPECT_EQ(verdict.status_code().as_status(), plain.status_code().as_status())
    << "the verdict is the one the plain validation gives";

  const auto accepted = validateWithSessionTrust(otherAccepted);
  EXPECT_EQ(accepted.status_code().as_status(), ua::Status::BadCertificateChainIncomplete)
    << "acceptance makes the certificate trusted, not its own anchor: "
    << ua::to_string(accepted.status_code().as_status());
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The shape a trust prompt produces: a CA-issued leaf whose CA is in neither list, accepted for this
// session. Acceptance makes the leaf trusted, but its chain cannot be built (Part 4 6.1.3: "Processing
// fails ... if an element in the chain cannot be found"), so it is refused as chain-incomplete and the
// refusal names the missing issuer (owner decision 22.5).
TYPED_TEST(
  CertificateStoreGenericTests, AnAcceptedCaIssuedLeafWhoseCaIsAbsentIsChainIncompleteNamingItsIssuer)
{
  ua::client::detail::SessionTrustStore session{this->mStore, this->mClientCert};

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  session.validate_certificate_async(
    ua::test::make_validation_request(this->mClientCert, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_EQ(verdict.status_code().as_status(), ua::Status::BadCertificateChainIncomplete)
    << ua::to_string(verdict.status_code().as_status());
  EXPECT_NE(ua::format(verdict.status_code()).find(this->mCaCert->subject_common_name()), std::string::npos)
    << "the refusal names the missing issuer: " << ua::format(verdict.status_code());
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The client's default configuration checks revocation offline. The CA and its CRL sit in the issuer list
// (untrusted); the accepted leaf is on that CRL. The session decision covers the chain, so the CRL is
// consulted and the leaf is refused as REVOKED (not as revocation-unknown, and not admitted).
TYPED_TEST(CertificateStoreGenericTests, AnAcceptedRevokedLeafIsRefusedAsRevokedWhenItsCaAndCrlAreKnown)
{
  ua::TrustListValidationOptions revocationOptions{};
  revocationOptions.set(ua::TrustListValidationOptions::Bit::CheckRevocationStatusOffline);
  auto store = TypeParam::create_store(
    this->mRootPath / "revocation", this->mThreadPool.get_executor(), this->mCrypto, revocationOptions);
  ASSERT_TRUE(store->try_add_to_issuer_certificates_sync(this->mCaCert).is_good());
  auto crl =
    this->mCrypto->create_crl_sync(this->mCaCert, this->mCaKeys, {this->mClientCert->serial_number()});
  ASSERT_TRUE(store->try_add_to_issuer_crls_sync(crl).is_good());
  ua::client::detail::SessionTrustStore session{store, this->mClientCert};

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  session.validate_certificate_async(
    ua::test::make_validation_request(this->mClientCert, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_EQ(verdict.status_code().as_status(), ua::Status::BadCertificateRevoked)
    << "revocation is checked as configured: " << ua::to_string(verdict.status_code().as_status());
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// Under offline revocation checking, an accepted leaf with NO known CA is refused at the earlier Build
// Certificate Chain step (owner decision 22.5): no chain, so no revocation verdict is reached.
TYPED_TEST(
  CertificateStoreGenericTests, AnAcceptedLeafWithNoKnownCaIsChainIncompleteUnderOfflineRevocationChecking)
{
  ua::TrustListValidationOptions revocationOptions{};
  revocationOptions.set(ua::TrustListValidationOptions::Bit::CheckRevocationStatusOffline);
  auto store = TypeParam::create_store(
    this->mRootPath / "revocation_no_ca", this->mThreadPool.get_executor(), this->mCrypto, revocationOptions);
  ua::client::detail::SessionTrustStore session{store, this->mClientCert};

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  session.validate_certificate_async(
    ua::test::make_validation_request(this->mClientCert, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_EQ(verdict.status_code().as_status(), ua::Status::BadCertificateChainIncomplete)
    << ua::to_string(verdict.status_code().as_status());
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The same configuration with a CRL that does not list the accepted leaf: admitted.
TYPED_TEST(CertificateStoreGenericTests, AnAcceptedUnrevokedLeafIsAdmittedWhenItsCaAndCrlAreKnown)
{
  ua::TrustListValidationOptions revocationOptions{};
  revocationOptions.set(ua::TrustListValidationOptions::Bit::CheckRevocationStatusOffline);
  auto store = TypeParam::create_store(
    this->mRootPath / "revocation_clean", this->mThreadPool.get_executor(), this->mCrypto, revocationOptions);
  ASSERT_TRUE(store->try_add_to_issuer_certificates_sync(this->mCaCert).is_good());
  auto crl = this->mCrypto->create_crl_sync(this->mCaCert, this->mCaKeys, {});
  ASSERT_TRUE(store->try_add_to_issuer_crls_sync(crl).is_good());
  ua::client::detail::SessionTrustStore session{store, this->mClientCert};

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  session.validate_certificate_async(
    ua::test::make_validation_request(this->mClientCert, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_TRUE(verdict.is_good()) << ua::to_string(verdict.status_code().as_status());
  EXPECT_TRUE(
    store
      ->try_validate_certificate_sync(ua::test::make_validation_request(this->mClientCert, {}, std::nullopt))
      .is_bad())
    << "the control: the plain validation still refuses the leaf (its CA is not trusted)";
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The accepted leaf expired yesterday: acceptance settles trust, not expiry. With its CA in neither list
// the chain step refuses it first (owner decision 22.5); with the CA in the issuer list the chain is
// complete and the leaf is refused as expired.
TYPED_TEST(CertificateStoreGenericTests, AnAcceptedExpiredCaIssuedLeafIsRefusedAsExpired)
{
  auto expired = this->mPki->create_leaf_cert(this->mClientKeys,
    this->mCaKeys,
    this->mCaCert,
    DateTime{DateTime::now().value() - std::chrono::hours(48)},
    DateTime{DateTime::now().value() - std::chrono::hours(24)});
  ua::client::detail::SessionTrustStore session{this->mStore, expired};

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  session.validate_certificate_async(
    ua::test::make_validation_request(expired, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_EQ(verdict.status_code().as_status(), ua::Status::BadCertificateChainIncomplete)
    << "with its CA in neither list the chain step refuses it first";

  ASSERT_TRUE(this->mStore->try_add_to_issuer_certificates_sync(this->mCaCert).is_good());
  std::promise<ua::VoidResult> completePromise;
  auto completeFuture = completePromise.get_future();
  session.validate_certificate_async(
    ua::test::make_validation_request(expired, {}, std::nullopt, std::nullopt, std::nullopt),
    [&completePromise](ua::VoidResult result) { completePromise.set_value(std::move(result)); });
  ASSERT_EQ(completeFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  EXPECT_EQ(completeFuture.get().status_code().as_status(), ua::Status::BadCertificateTimeInvalid)
    << "an expired certificate is refused whatever trust the session granted it";
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The same issuer as additional trust, but the leaf expired yesterday: trust is overridden, expiry is not.
TYPED_TEST(CertificateStoreGenericTests, AnExpiredCertificateIsRefusedEvenWithItsIssuerAsAdditionalTrust)
{
  auto expired = this->mPki->create_leaf_cert(this->mClientKeys,
    this->mCaKeys,
    this->mCaCert,
    DateTime{DateTime::now().value() - std::chrono::hours(48)},
    DateTime{DateTime::now().value() - std::chrono::hours(24)});

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  this->mStore->validate_certificate_async(
    ua::test::make_validation_request_with_connection_trust(
      expired, {this->mCaCert}, {}, std::nullopt, std::nullopt, std::nullopt),
    [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_EQ(verdict.status_code().as_status(), ua::Status::BadCertificateTimeInvalid)
    << "an expired certificate is refused whatever trust the session granted it";
}

TYPED_TEST(CertificateStoreGenericTests, TrustedCertificatesSync)
{
  auto status = this->mStore->try_add_to_trusted_certificates_sync(this->mCaCert);
  EXPECT_TRUE(status.is_good());

  auto result = this->mStore->try_get_trusted_certificates_sync();
  EXPECT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1);
  EXPECT_EQ(result.value()[0]->thumbprint(), this->mCaCert->thumbprint());
}

TYPED_TEST(CertificateStoreGenericTests, ApplicationCertificatesSync)
{
  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaMinApplication;
  appCert.certificate = this->mClientCert;
  appCert.keys = this->mClientKeys;

  auto status = this->mStore->try_add_to_application_certificates_sync(appCert);
  EXPECT_TRUE(status.is_good());

  auto certsResult = this->mStore->try_get_application_certificates_sync();
  ASSERT_TRUE(certsResult.is_good());
  ASSERT_EQ(certsResult.value().size(), 1);
  EXPECT_EQ(certsResult.value()[0].certificate->thumbprint(), this->mClientCert->thumbprint());

  auto singleResult = this->mStore->try_get_application_certificate_sync(CertificateType::RsaMinApplication);
  EXPECT_TRUE(singleResult.is_good());
  EXPECT_EQ(singleResult.value().certificate->thumbprint(), this->mClientCert->thumbprint());
}

TYPED_TEST(CertificateStoreGenericTests, ValidationSync)
{
  // The request's default use is ApplicationInstance, so the trusted self-signed certificate carries the
  // OPC 10000-6 Table 43 bits; the fixture's mCaCert is a plain CA.
  const auto appRoot = this->mPki->create_self_signed_application_root(this->mCaKeys);
  this->mStore->add_to_trusted_certificates_sync(appRoot);
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(appRoot, {}, std::nullopt));
  EXPECT_TRUE(status.is_good());
}

TYPED_TEST(CertificateStoreGenericTests, TrustedCertificatesAsync)
{
  std::atomic<bool> completed{false};
  this->mStore->add_to_trusted_certificates_async(this->mCaCert,

    [&](VoidResult status)
    {
      EXPECT_TRUE(status.is_good());
      this->mStore->get_trusted_certificates_async(
        [&](CertificateListResult result)
        {
          EXPECT_TRUE(result.is_good());
          EXPECT_EQ(result.value().size(), 1);
          completed = true;
        });
    });

  for (int i = 0; i < 1000 && !completed; ++i)
    std::this_thread::sleep_for(1ms);
  EXPECT_TRUE(completed);
}

TYPED_TEST(CertificateStoreGenericTests, ConcurrencyStress)
{
  const int iterations = 100;
  std::atomic<int> completed{0};

  // Run the `iterations` concurrent sync reads over a BOUNDED pool of OS threads.
  // Spawning `iterations` simultaneous std::threads (each blocked on a sync future
  // while the store's strand serialises the op) keeps ~100 thread stacks alive at
  // once, which exhausts the constrained 32-bit address space under ASan (stacks +
  // ASan shadow) and aborts. A small worker pool preserves the concurrency stress on
  // the strand-serialised store while staying within 32-bit limits; the total work
  // (100 reads + 100 async writes) and the assertion below are unchanged.
  const unsigned readerCount = std::clamp(std::thread::hardware_concurrency(), 2u, 16u);
  std::atomic<int> nextRead{0};
  std::vector<std::thread> readers;
  readers.reserve(readerCount);
  for (unsigned t = 0; t < readerCount; ++t)
  {
    readers.emplace_back(
      [&]()
      {
        while (nextRead.fetch_add(1) < iterations)
        {
          if (this->mStore->try_get_trusted_certificates_sync().is_good())
            completed++;
        }
      });
  }

  for (int i = 0; i < iterations; ++i)
  {
    this->mStore->add_to_trusted_certificates_async({this->mCaCert},

      [&](VoidResult status)
      {
        if (status.is_good())
          completed++;
      });
  }

  for (auto& t : readers)
  {
    if (t.joinable())
      t.join();
  }

  for (int i = 0; i < 1000 && completed < (iterations * 2); ++i)
    std::this_thread::sleep_for(10ms);

  EXPECT_EQ(completed, iterations * 2);
}
