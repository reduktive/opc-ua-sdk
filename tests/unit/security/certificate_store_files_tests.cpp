// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>
#include <gtest/gtest.h>
#include <string_view>
#include <stdexcept>
#include <future>
#ifndef _WIN32
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/stat.h>
#endif
#include <optional>

#include "certificate_validation_request_helpers.h"
#include "test_utilities.h"
#include "fmt/format.h"
#include "fmt/ranges.h"

#include "ua_byte_format.h"
#include <filesystem>
#include <fstream>
#include "ua_certificate_store_files.h"
#include "ua_certificate_store_files_detail.h"
#include "ua_crypto.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>
#include "test_pki_helpers.h"
#include "ua_to_string.h"

namespace fs = std::filesystem;
using namespace ua;
using namespace std::chrono_literals;

class CertificateStoreFilesTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Unique per test instance: a fixed path collides when parallel shards share a working
    // directory (one shard's SetUp/TearDown remove_all wipes another's store mid-operation).
    mTestPath = test_utils::unique_temp_path("cert_store_files_spec");
    fs::remove_all(mTestPath);

    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    mPki = std::make_unique<TestPki>(mCrypto);

    mCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mCaCert = mPki->create_root_ca(mCaKeys);

    TrustListValidationOptions options;
    mStore = CertificateStoreFiles::create(mThreadPool.get_executor(),
      mCrypto,
      {.trustListPath = mTestPath, .validationOptions = options, .storeRejectedCertificates = false});
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
    fs::remove_all(mTestPath);
  }

  fs::path mTestPath;
  shared_ptr<const Crypto> mCrypto;
  boost::asio::thread_pool mThreadPool;
  shared_ptr<CertificateStore> mStore;
  std::unique_ptr<TestPki> mPki;
  shared_ptr<const AsymmetricKeyPair> mCaKeys;
  shared_ptr<const X509Certificate> mCaCert;

  void write_der_file(const fs::path& folder, const ByteString& der)
  {
    std::ofstream ofs(
      folder / (fmt::format("{:02X}", fmt::join(mCaCert->thumbprint(), "")) + ".der"), std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(der.data()), der.size());
  }
};

// Decision 28 (OPC 10000-12 7.8.2.5: the thumbprint names the CertificateDigest): the RemoveCertificate
// thumbprint String is decoded to bytes - exactly 40 hexadecimal digits, either case - and compared with the
// certificate's thumbprint as bytes.

/// A certificate (signed by mCaKeys) whose SHA-1 thumbprint has a byte below 0x10, which an unpadded hex
/// rendering would shorten.
static shared_ptr<const X509Certificate> certificate_with_a_small_thumbprint_byte(
  TestPki& pki, const shared_ptr<const AsymmetricKeyPair>& keys)
{
  for (int serial = 9001; serial < 9101; ++serial)
  {
    auto certificate =
      pki.create_root_ca(keys, "Thumbprint " + std::to_string(serial), std::to_string(serial));
    const auto thumbprint = certificate->thumbprint();
    if (std::any_of(
          thumbprint.begin(), thumbprint.end(), [](auto b) { return static_cast<uint8_t>(b) < 0x10; }))
    {
      return certificate;
    }
  }
  return nullptr;
}

static std::string hex_thumbprint(const X509Certificate& certificate, bool upperCase)
{
  std::string out;
  for (const auto b : certificate.thumbprint())
  {
    out += upperCase ? fmt::format("{:02X}", static_cast<uint8_t>(b))
                     : fmt::format("{:02x}", static_cast<uint8_t>(b));
  }
  return out;
}

static std::string legacy_file_name(const X509Certificate& certificate)
{
  return fmt::format("{:X}", fmt::join(certificate.thumbprint(), "")) + ".der";
}

static void write_der(const fs::path& file, const X509Certificate& certificate)
{
  const auto der = certificate.der_encoding();
  std::ofstream out{file, std::ios::binary};
  out.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
}

// A trusted certificate's file is named by its 40-digit thumbprint, so no two certificates share a name.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-138-STORE-FILE-NAMES, scope=function)
TEST_F(CertificateStoreFilesTests, ATrustedFileIsNamedByTheFortyDigitThumbprint)
{
  const auto certificate = certificate_with_a_small_thumbprint_byte(*mPki, mCaKeys);
  ASSERT_NE(certificate, nullptr);
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(certificate).is_good());
  const auto trustedDir = mTestPath / "TrustList" / "TrustedCertificates";
  EXPECT_TRUE(fs::exists(trustedDir / (hex_thumbprint(*certificate, true) + ".der")));
  EXPECT_FALSE(fs::exists(trustedDir / legacy_file_name(*certificate)))
    << "the unpadded name is shorter and can belong to another certificate";
}

// A store written by an earlier release names a file without zero padding; removing the certificate also
// removes that file, so the certificate does not come back when the store is read again.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-138-STORE-FILE-NAMES, scope=function)
TEST_F(CertificateStoreFilesTests, RemoveDeletesTheFileAnEarlierReleaseNamedWithoutPadding)
{
  const auto certificate = certificate_with_a_small_thumbprint_byte(*mPki, mCaKeys);
  ASSERT_NE(certificate, nullptr);
  const auto path = mTestPath / "legacy_names";
  const auto trustedDir = path / "TrustList" / "TrustedCertificates";
  fs::create_directories(trustedDir);
  write_der(trustedDir / legacy_file_name(*certificate), *certificate);

  auto store = CertificateStoreFiles::create(
    mThreadPool.get_executor(), mCrypto, {.trustListPath = path, .storeRejectedCertificates = false});
  ASSERT_TRUE(store->try_remove_from_trusted_certificates_sync(hex_thumbprint(*certificate, true)).is_good());
  EXPECT_FALSE(fs::exists(trustedDir / legacy_file_name(*certificate)));

  auto reread = CertificateStoreFiles::create(
    mThreadPool.get_executor(), mCrypto, {.trustListPath = path, .storeRejectedCertificates = false});
  const auto trusted = reread->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  EXPECT_TRUE(trusted.value().empty()) << "the removed certificate must not return";
}

// Control for the content check: a file under the removed certificate's unpadded name that holds another
// certificate is left alone.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-138-STORE-FILE-NAMES, scope=function)
TEST_F(CertificateStoreFilesTests, RemoveLeavesAnotherCertificateUnderTheUnpaddedName)
{
  const auto certificate = certificate_with_a_small_thumbprint_byte(*mPki, mCaKeys);
  ASSERT_NE(certificate, nullptr);
  const auto path = mTestPath / "legacy_other";
  const auto trustedDir = path / "TrustList" / "TrustedCertificates";
  fs::create_directories(trustedDir);
  write_der(trustedDir / "certificate.der", *certificate);
  write_der(trustedDir / legacy_file_name(*certificate), *mCaCert);

  auto store = CertificateStoreFiles::create(
    mThreadPool.get_executor(), mCrypto, {.trustListPath = path, .storeRejectedCertificates = false});
  ASSERT_TRUE(store->try_remove_from_trusted_certificates_sync(hex_thumbprint(*certificate, true)).is_good());
  EXPECT_TRUE(fs::exists(trustedDir / legacy_file_name(*certificate)))
    << "a file holding a different certificate is not removed";
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-137-THUMBPRINT-BYTES, scope=function)
TEST_F(CertificateStoreFilesTests, RemoveFindsAThumbprintWithAByteBelow0x10)
{
  const auto certificate = certificate_with_a_small_thumbprint_byte(*mPki, mCaKeys);
  ASSERT_NE(certificate, nullptr);
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(certificate).is_good());
  EXPECT_TRUE(
    mStore->try_remove_from_trusted_certificates_sync(hex_thumbprint(*certificate, true)).is_good());
  const auto trusted = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  EXPECT_TRUE(trusted.value().empty()) << "the zero-padded 40-digit thumbprint names the certificate";
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-137-THUMBPRINT-BYTES, scope=function)
TEST_F(CertificateStoreFilesTests, RemoveAcceptsTheLowerCaseThumbprint)
{
  const auto certificate = certificate_with_a_small_thumbprint_byte(*mPki, mCaKeys);
  ASSERT_NE(certificate, nullptr);
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(certificate).is_good());
  EXPECT_TRUE(
    mStore->try_remove_from_trusted_certificates_sync(hex_thumbprint(*certificate, false)).is_good());
  const auto trusted = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  EXPECT_TRUE(trusted.value().empty());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-137-THUMBPRINT-BYTES, scope=function)
TEST_F(CertificateStoreFilesTests, RemoveRefusesAMalformedThumbprintAsInvalidArgument)
{
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(mCaCert).is_good());
  const auto valid = hex_thumbprint(*mCaCert, true);
  auto nonHex = valid;
  nonHex.back() = 'G';
  for (const auto& malformed : {valid.substr(0, 39), valid + "0", nonHex, std::string{}})
  {
    EXPECT_EQ(mStore->try_remove_from_trusted_certificates_sync(malformed).status_code().as_status(),
      Status::BadInvalidArgument)
      << "'" << malformed << "'";
  }
  const auto trusted = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  EXPECT_EQ(trusted.value().size(), 1u) << "nothing was removed";
}

// Public API review item 9 (API-9.4): the store is created from a named config, and the validation options
// it names are the store's from the start, before any set_validation_options.
TEST_F(CertificateStoreFilesTests, TheConfiguredValidationOptionsAreTheStoresFromTheStart)
{
  const TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOffline,
    TrustListValidationOptions::Bit::SuppressHostNameInvalid};
  auto store = CertificateStoreFiles::create(mThreadPool.get_executor(),
    mCrypto,
    {.trustListPath = mTestPath / "configured_options",
      .validationOptions = options,
      .storeRejectedCertificates = false});
  EXPECT_EQ(store->validation_options(), options);
}

TEST_F(CertificateStoreFilesTests, Persistence)
{
  mStore->add_to_trusted_certificates_sync(mCaCert);

  TrustListValidationOptions options;
  auto newStore = CertificateStoreFiles::create(mThreadPool.get_executor(),
    mCrypto,
    {.trustListPath = mTestPath, .validationOptions = options, .storeRejectedCertificates = false});

  auto result = newStore->try_get_trusted_certificates_sync();
  EXPECT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1);
  EXPECT_EQ(result.value()[0]->thumbprint(), mCaCert->thumbprint());
}

TEST_F(CertificateStoreFilesTests, AutoDirectoryCreation)
{
  fs::path anotherPath = mTestPath / "auto_dir";
  fs::remove_all(anotherPath);

  TrustListValidationOptions options;
  auto newStore = CertificateStoreFiles::create(mThreadPool.get_executor(),
    mCrypto,
    {.trustListPath = anotherPath, .validationOptions = options, .storeRejectedCertificates = false});

  auto root = anotherPath / "TrustList";
  EXPECT_TRUE(fs::exists(anotherPath));
  EXPECT_TRUE(fs::exists(root));
  EXPECT_TRUE(fs::exists(root / "ApplicationCertificates"));
  EXPECT_TRUE(fs::exists(root / "ApplicationKeys"));
  EXPECT_TRUE(fs::exists(root / "TrustedCertificates"));
  EXPECT_TRUE(fs::exists(root / "TrustedCrls"));
  EXPECT_TRUE(fs::exists(root / "IssuerCertificates"));
  EXPECT_TRUE(fs::exists(root / "IssuerCrls"));
  EXPECT_TRUE(fs::exists(root / "RejectedCertificates"));
}

TEST_F(CertificateStoreFilesTests, HotReload)
{
  auto result = mStore->try_get_trusted_certificates_sync();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.value().size(), 0);

  auto trustedFolder = mTestPath / "TrustList" / "TrustedCertificates";
  write_der_file(trustedFolder, mCaCert->der_encoding());

  std::promise<VoidResult> p;
  mStore->refresh_cache([&p](VoidResult s) { p.set_value(std::move(s)); });
  EXPECT_TRUE(p.get_future().get().is_good());

  auto result2 = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(result2.is_good());
  EXPECT_EQ(result2.value().size(), 1);
  EXPECT_EQ(result2.value()[0]->thumbprint(), mCaCert->thumbprint());
}

// A file the store cannot parse (a PEM file, a file still being copied) is left out of its list; the other
// files of that directory and every later directory still load.
// @relation(AC-SVR-SECADMIN-009-UNREADABLE-STORE-FILE-LEFT-OUT, scope=function)
TEST_F(CertificateStoreFilesTests, AnUnreadableFileIsLeftOutAndTheRestOfTheStoreLoads)
{
  const auto trustList = mTestPath / "TrustList";
  write_der_file(trustList / "TrustedCertificates", mCaCert->der_encoding());
  {
    std::ofstream pem(trustList / "TrustedCertificates" / "operator-drop.pem");
    pem << "-----BEGIN CERTIFICATE-----\nnot DER\n-----END CERTIFICATE-----\n";
  }
  auto issuerKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto issuerCert = mPki->create_root_ca(issuerKeys, "Issuer Only", "77");
  {
    const auto der = issuerCert->der_encoding();
    std::ofstream ofs(trustList / "IssuerCertificates" / "issuer.der", std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
  }

  std::promise<VoidResult> refreshed;
  mStore->refresh_cache([&refreshed](VoidResult s) { refreshed.set_value(std::move(s)); });
  EXPECT_TRUE(refreshed.get_future().get().is_good());

  auto trusted = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  ASSERT_EQ(trusted.value().size(), 1u);
  EXPECT_EQ(trusted.value()[0]->thumbprint(), mCaCert->thumbprint());
  auto issuers = mStore->try_get_issuer_certificates_sync();
  ASSERT_TRUE(issuers.is_good());
  ASSERT_EQ(issuers.value().size(), 1u);
  EXPECT_EQ(issuers.value()[0]->thumbprint(), issuerCert->thumbprint());
}

// An unreadable CRL is not left out like a certificate: an older CRL of the same issuer could still load
// and pass a certificate the unread one revokes, so the refresh fails and says why.
// @relation(AC-SVR-SECADMIN-009-UNREADABLE-STORE-FILE-LEFT-OUT, scope=function)
TEST_F(CertificateStoreFilesTests, AnUnreadableCrlFailsTheRefresh)
{
  const auto trustList = mTestPath / "TrustList";
  write_der_file(trustList / "TrustedCertificates", mCaCert->der_encoding());
  {
    std::ofstream crl(trustList / "TrustedCrls" / "partial.crl", std::ios::binary);
    crl << "\x30\x82";
  }

  std::promise<VoidResult> refreshed;
  mStore->refresh_cache([&refreshed](VoidResult s) { refreshed.set_value(std::move(s)); });
  const auto result = refreshed.get_future().get();
  EXPECT_TRUE(result.is_bad()) << "a CRL the store cannot read must not be silently skipped";
  auto trusted = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  EXPECT_TRUE(trusted.value().empty()) << "no certificate is trusted while a CRL cannot be read";

  // Control: once the CRL directory holds only readable files, the trust list loads again.
  std::filesystem::remove(trustList / "TrustedCrls" / "partial.crl");
  std::promise<VoidResult> repaired;
  mStore->refresh_cache([&repaired](VoidResult s) { repaired.set_value(std::move(s)); });
  EXPECT_TRUE(repaired.get_future().get().is_good());
  auto restored = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(restored.is_good());
  EXPECT_EQ(restored.value().size(), 1u);
}

// @verifies CL-SECADMIN-002
// @relation(CL-SECADMIN-002, scope=function)
TEST_F(CertificateStoreFilesTests, DefaultPolicyRejectsUnknownCertificate)
{
  // The fixture store starts with an empty TrustedCertificates directory. The default policy must
  // reject a certificate whose issuing CA is not present in the trust store - there is no
  // accept-all / trust-on-first-use behaviour.
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto now = DateTime::now();
  auto untrustedLeaf =
    mPki->create_leaf_cert(leafKeys, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{10}});

  // mCaCert is in neither the trust list nor the issuer list, so no chain can be built for the leaf: Part 4
  // Table 106's Build Certificate Chain step refuses it (Bad_CertificateChainIncomplete) before the Trust
  // List Check is reached.
  auto rejected =
    mStore->try_validate_certificate_sync(ua::test::make_validation_request(untrustedLeaf, {}, std::nullopt));
  EXPECT_EQ(rejected.status_code().as_status(), Status::BadCertificateChainIncomplete);

  // Positive control (proves the reject branch above is non-vacuous): once the issuing CA is added
  // to the trust store, the very same leaf validates Good.
  mStore->add_to_trusted_certificates_sync(mCaCert);
  auto accepted =
    mStore->try_validate_certificate_sync(ua::test::make_validation_request(untrustedLeaf, {}, std::nullopt));
  EXPECT_TRUE(accepted.is_good());
}

// Part 4 6.1.3: "A Certificate is trusted if the Certificate or at least one of the Certificates in the
// chain are in the list of trusted Certificates ... and the chain is valid." A trusted leaf whose issuing
// CA sits only in the issuer list is trusted, with the chain still validated to that root.
TEST_F(CertificateStoreFilesTests, TrustedLeafWhoseCaIsOnlyAnIssuerValidates)
{
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto now = DateTime::now();
  auto leaf =
    mPki->create_leaf_cert(leafKeys, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{10}});

  mStore->add_to_issuer_certificates_sync(mCaCert);
  mStore->add_to_trusted_certificates_sync(leaf);

  const auto result =
    mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
}

// The other half: an issuer terminates a chain but does not make it trusted. With the CA only in the
// issuer list and nothing in the trusted list, the same leaf is still untrusted.
TEST_F(CertificateStoreFilesTests, IssuerOnlyCaDoesNotTrustAnUntrustedLeaf)
{
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto now = DateTime::now();
  auto leaf =
    mPki->create_leaf_cert(leafKeys, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{10}});

  mStore->add_to_issuer_certificates_sync(mCaCert);

  const auto result =
    mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUntrusted);
}

// @verifies CL-SECADMIN-002
// @relation(CL-SECADMIN-002, scope=function)
TEST_F(CertificateStoreFilesTests, RejectedCertWrittenToQuarantineAsExactDer)
{
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto now = DateTime::now();
  auto untrustedLeaf =
    mPki->create_leaf_cert(leafKeys, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{10}});
  const auto expectedFileName = fmt::format("{:02X}", fmt::join(untrustedLeaf->thumbprint(), "")) + ".der";

  // A store constructed with storeRejectedCertificates=true quarantines a rejected certificate to
  // the RejectedCertificates directory, byte-for-byte as the presented DER.
  TrustListValidationOptions options;
  auto quarantinePath = mTestPath / "quarantine_on";
  auto quarantiningStore = CertificateStoreFiles::create(
    mThreadPool.get_executor(), mCrypto, {.trustListPath = quarantinePath, .validationOptions = options});

  auto rejected = quarantiningStore->try_validate_certificate_sync(
    ua::test::make_validation_request(untrustedLeaf, {}, std::nullopt));
  ASSERT_TRUE(rejected.is_bad());

  auto quarantineFile = quarantinePath / "TrustList" / "RejectedCertificates" / expectedFileName;
  ASSERT_TRUE(fs::exists(quarantineFile));

  // Byte-for-byte DER: the quarantined file is exactly the presented certificate's DER encoding.
  const auto der = untrustedLeaf->der_encoding();
  const auto fileSize = static_cast<size_t>(fs::file_size(quarantineFile));
  std::string onDisk(fileSize, '\0');
  {
    std::ifstream ifs(quarantineFile, std::ios::binary);
    ifs.read(onDisk.data(), static_cast<std::streamsize>(fileSize));
  }
  std::string expected(reinterpret_cast<const char*>(der.data()), der.size());
  EXPECT_EQ(onDisk, expected);

  // Negative control: a store constructed with storeRejectedCertificates=false must NOT persist a
  // quarantine file for the same rejected certificate.
  auto noQuarantinePath = mTestPath / "quarantine_off";
  auto nonStoringStore = CertificateStoreFiles::create(mThreadPool.get_executor(),
    mCrypto,
    {.trustListPath = noQuarantinePath, .validationOptions = options, .storeRejectedCertificates = false});
  auto rejected2 = nonStoringStore->try_validate_certificate_sync(
    ua::test::make_validation_request(untrustedLeaf, {}, std::nullopt));
  ASSERT_TRUE(rejected2.is_bad());
  auto noQuarantineFile = noQuarantinePath / "TrustList" / "RejectedCertificates" / expectedFileName;
  EXPECT_FALSE(fs::exists(noQuarantineFile));
}

#ifndef _WIN32
namespace
{
/// The private key file the store wrote: the one PEM under the store root that holds a private key.
std::optional<fs::path> find_private_key_file(const fs::path& root)
{
  for (const auto& entry : fs::recursive_directory_iterator(root))
  {
    if (!entry.is_regular_file())
      continue;
    std::ifstream in{entry.path()};
    std::string head((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (head.find("PRIVATE KEY-----") != std::string::npos)
      return entry.path();
  }
  return std::nullopt;
}
}  // namespace

// DEF-5: the private key file is created owner-only from the first byte, whatever the umask, and
// never through a planted symlink; a write that cannot complete is an error, not an info-level log.
// @verifies AC-SVR-SECADMIN-071-PRIVATE-KEY-FILE-IS-CREATED-OWNER-ONLY
TEST_F(CertificateStoreFilesTests, PrivateKeyIsCreatedOwnerOnlyRegardlessOfUmask)
{
  auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto cert = mPki->create_root_ca(keys);
  CertificateStore::ApplicationCertificate application;
  application.certificateType = CertificateType::RsaSha256Application;
  application.certificate = cert;
  application.keys = keys;

  struct UmaskGuard
  {
    mode_t previous{::umask(0)};

    ~UmaskGuard()
    {
      ::umask(previous);
    }
  };

  // The store creates the key directory itself, so it is constructed under the permissive umask
  // too: the directory's mode is the store's doing, not the fixture's.
  const fs::path storePath = mTestPath / "umask0";
  VoidResult added;
  {
    const UmaskGuard permissive;  // restored on every path, a throwing store included
    auto store = CertificateStoreFiles::create(
      mThreadPool.get_executor(), mCrypto, {.trustListPath = storePath, .storeRejectedCertificates = false});
    added = store->try_add_to_application_certificates_sync(application);
  }
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code().as_status());

  const auto keyFile = find_private_key_file(storePath);
  ASSERT_TRUE(keyFile.has_value()) << "the store wrote a private key file";

  struct stat info
  {};

  ASSERT_EQ(::lstat(keyFile->c_str(), &info), 0);
  EXPECT_TRUE(S_ISREG(info.st_mode));
  EXPECT_EQ(info.st_mode & 0777, 0600u) << "owner read/write only, with umask 0";

  struct stat dirInfo
  {};

  ASSERT_EQ(::lstat(keyFile->parent_path().c_str(), &dirInfo), 0);
  EXPECT_EQ(dirInfo.st_mode & 077, 0u) << "the key directory admits no other user";
}

// @verifies AC-SVR-SECADMIN-071-PRIVATE-KEY-FILE-IS-CREATED-OWNER-ONLY
TEST_F(CertificateStoreFilesTests, PreplantedSymlinkAtKeyPathIsReplacedNotFollowed)
{
  auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto cert = mPki->create_root_ca(keys);
  CertificateStore::ApplicationCertificate application;
  application.certificateType = CertificateType::RsaSha256Application;
  application.certificate = cert;
  application.keys = keys;
  ASSERT_TRUE(mStore->try_add_to_application_certificates_sync(application).is_good());
  const auto keyFile = find_private_key_file(mTestPath);
  ASSERT_TRUE(keyFile.has_value());

  // Replace the key file with a symlink to a victim file, as a local attacker with write access to
  // the directory would, then write the key again.
  const auto victim = mTestPath / "victim.txt";
  {
    std::ofstream out{victim};
    out << "untouched";
  }
  fs::remove(*keyFile);
  fs::create_symlink(victim, *keyFile);
  ASSERT_TRUE(fs::is_symlink(fs::symlink_status(*keyFile)));
  ASSERT_TRUE(mStore->try_add_to_application_certificates_sync(application).is_good());

  EXPECT_FALSE(fs::is_symlink(fs::symlink_status(*keyFile))) << "the symlink was replaced by the rename";
  EXPECT_TRUE(fs::is_regular_file(*keyFile));
  std::ifstream in{victim};
  std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  EXPECT_EQ(contents, "untouched") << "the victim file was never written through";
}

// @verifies AC-SVR-SECADMIN-071-PRIVATE-KEY-FILE-IS-CREATED-OWNER-ONLY
TEST_F(CertificateStoreFilesTests, KeyWriteFailureIsAnError)
{
  auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto cert = mPki->create_root_ca(keys);
  CertificateStore::ApplicationCertificate application;
  application.certificateType = CertificateType::RsaSha256Application;
  application.certificate = cert;
  application.keys = keys;
  ASSERT_TRUE(mStore->try_add_to_application_certificates_sync(application).is_good());
  const auto keyFile = find_private_key_file(mTestPath);
  ASSERT_TRUE(keyFile.has_value());

  const auto expectWriteRefused = [&](const char* stimulus)
  {
    const auto refused = mStore->try_add_to_application_certificates_sync(application);
    ASSERT_TRUE(refused.is_bad()) << stimulus
                                  << ": a key that could not be written is an error, not a log line";
    EXPECT_EQ(refused.status_code(), Status::BadConfigurationError) << stimulus;
    ASSERT_NE(refused.shared_detail(), nullptr) << stimulus;
    EXPECT_EQ(refused.shared_detail()->code, "PrivateKeyWriteFailed") << stimulus;
  };

  // A read-only key directory refuses the temporary file. Root ignores directory permissions, so
  // this case runs only for another account; the next case fails for every account.
  if (::geteuid() != 0)
  {
    const auto keyDirectory = keyFile->parent_path();
    ASSERT_EQ(::chmod(keyDirectory.c_str(), 0500), 0) << "the key directory is made read-only";
    expectWriteRefused("read-only key directory");
    ::chmod(keyDirectory.c_str(), 0700);
  }

  // A directory occupying the key path refuses the rename that puts the key in place.
  fs::remove(*keyFile);
  fs::create_directory(*keyFile);
  {
    std::ofstream occupant{*keyFile / "occupant"};
    occupant << "x";
  }
  expectWriteRefused("directory at the key path");
}
#endif  // !_WIN32

// A replacement that cannot complete (here: a directory planted where a new certificate's file would
// go) leaves the CURRENT list intact instead of a deleted-then-half-written one: the new list is
// written beside the old one and swapped in by rename, so at every point one whole list exists.
// @verifies AC-SVR-SECADMIN-009-A-TRUST-LIST-REPLACEMENT-IS-ATOMIC-ON-DISK
TEST_F(CertificateStoreFilesTests, AReplacementAroundAPlantedObstacleLeavesNoPartialList)
{
  const auto now = DateTime::now();
  auto keysA = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafA =
    mPki->create_leaf_cert(keysA, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{10}});
  auto keysB = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafB =
    mPki->create_leaf_cert(keysB, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{10}});

  const auto replace = [&](CertificateList certificates)
  {
    std::promise<VoidResult> done;
    mStore->replace_trusted_certificates_async(
      std::move(certificates), {}, [&](VoidResult result) { done.set_value(std::move(result)); });
    return done.get_future().get();
  };
  ASSERT_TRUE(replace({leafA}).is_good());
  auto listed = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(listed.is_good());
  ASSERT_EQ(listed.value().size(), 1u);

  // Plant a directory where leafB's file would be written in the live list directory.
  const auto trustedDir = mTestPath / "TrustList" / "TrustedCertificates";
  const auto obstacle = trustedDir / (fmt::format("{:02X}", fmt::join(leafB->thumbprint(), "")) + ".der");
  fs::create_directories(obstacle);

  const auto result = replace({leafB});
  listed = mStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(listed.is_good());
  ASSERT_EQ(listed.value().size(), 1u)
    << "one whole list exists whatever the outcome (" << to_string(result.status_code()) << ")";
  const auto onDisk = listed.value().front()->der_encoding();
  EXPECT_TRUE(onDisk == leafB->der_encoding() || onDisk == leafA->der_encoding());
  if (result.is_good())
  {
    EXPECT_EQ(onDisk, leafB->der_encoding()) << "the new list was swapped in around the obstacle";
  }
  EXPECT_FALSE(fs::exists(trustedDir.string() + ".new")) << "no leftovers";
  EXPECT_FALSE(fs::exists(trustedDir.string() + ".old"));
}

// The swap itself: when writing a new list fails part-way, every directory keeps its current content
// and no fresh or retired sibling is left; a crash between the two renames leaves the list under
// "<dir>.old", which the recovery puts back before the store would create an empty directory.
// @verifies AC-SVR-SECADMIN-009-A-TRUST-LIST-REPLACEMENT-IS-ATOMIC-ON-DISK
TEST_F(CertificateStoreFilesTests, ReplaceListDirectoriesRestoresTheOldListsWhenAWriteFails)
{
  const auto certs = mTestPath / "swap" / "Certs";
  const auto crls = mTestPath / "swap" / "Crls";
  fs::create_directories(certs);
  fs::create_directories(crls);
  const auto write = [](const fs::path& file, std::string_view content)
  {
    std::ofstream out{file};
    out << content;
  };
  write(certs / "old.der", "old cert");
  write(crls / "old.crl", "old crl");

  using ua::certificate_store_files_detail::ListReplacement;
  using ua::certificate_store_files_detail::replace_list_directories;
  EXPECT_THROW(replace_list_directories({
                 {certs, [&](const fs::path& into) { write(into / "new.der", "new cert"); }, {}},
                 {crls, [&](const fs::path&) { throw std::runtime_error{"disk full"}; }, {}},
               }),
    std::runtime_error);
  EXPECT_TRUE(fs::exists(certs / "old.der")) << "the certificate list is untouched";
  EXPECT_FALSE(fs::exists(certs / "new.der"));
  EXPECT_TRUE(fs::exists(crls / "old.crl"));
  EXPECT_FALSE(fs::exists(certs.string() + ".new")) << "no fresh sibling left";
  EXPECT_FALSE(fs::exists(certs.string() + ".old"));
  EXPECT_FALSE(fs::exists(crls.string() + ".new"));

  // Control: a replacement that completes leaves the new content and no siblings.
  replace_list_directories({
    {certs, [&](const fs::path& into) { write(into / "new.der", "new cert"); }, {}},
    {crls, [&](const fs::path& into) { write(into / "new.crl", "new crl"); }, {}},
  });
  EXPECT_TRUE(fs::exists(certs / "new.der"));
  EXPECT_FALSE(fs::exists(certs / "old.der"));
  EXPECT_TRUE(fs::exists(crls / "new.crl"));
  EXPECT_FALSE(fs::exists(certs.string() + ".old"));
  EXPECT_FALSE(fs::exists(crls.string() + ".old"));
}

// A crash between the swaps of a pair (certificates swapped in, CRLs not yet) leaves the pair torn; the
// recovery rolls the whole pair back, so certificates and CRLs are never from different updates.
// @verifies AC-SVR-SECADMIN-009-A-TRUST-LIST-REPLACEMENT-IS-ATOMIC-ON-DISK
TEST_F(CertificateStoreFilesTests, RecoveryRollsATornPairBackToTheOldLists)
{
  const auto certs = mTestPath / "torn" / "Certs";
  const auto crls = mTestPath / "torn" / "Crls";
  const auto put = [](const fs::path& dir, std::string_view name)
  {
    fs::create_directories(dir);
    std::ofstream out{dir / std::string{name}};
    out << name;
  };
  put(certs, "new.der");  // swapped in
  put(fs::path{certs.string() + ".old"}, "old.der");  // the old list renamed aside
  put(crls, "old.crl");  // not yet swapped
  put(fs::path{crls.string() + ".new"}, "new.crl");  // the fresh list still waiting
  ua::certificate_store_files_detail::recover_list_directories({certs, crls});
  EXPECT_TRUE(fs::exists(certs / "old.der")) << "the certificates are rolled back with the CRLs";
  EXPECT_FALSE(fs::exists(certs / "new.der"));
  EXPECT_TRUE(fs::exists(crls / "old.crl"));
  EXPECT_FALSE(fs::exists(certs.string() + ".old"));
  EXPECT_FALSE(fs::exists(crls.string() + ".new"));

  // Control: a crash after both swaps (only the ".old" siblings left) keeps the new lists.
  put(fs::path{certs.string() + ".old"}, "older.der");
  ua::certificate_store_files_detail::recover_list_directories({certs, crls});
  EXPECT_TRUE(fs::exists(certs / "old.der"));
  EXPECT_FALSE(fs::exists(certs.string() + ".old"));
}

// A failure in the rename phase (the second list's fresh directory has vanished) rolls back the list
// already swapped in.
// @verifies AC-SVR-SECADMIN-009-A-TRUST-LIST-REPLACEMENT-IS-ATOMIC-ON-DISK
TEST_F(CertificateStoreFilesTests, ARenamePhaseFailureRollsBackTheListsAlreadySwapped)
{
  const auto certs = mTestPath / "rename" / "Certs";
  const auto crls = mTestPath / "rename" / "Crls";
  fs::create_directories(certs);
  fs::create_directories(crls);
  {
    std::ofstream out{certs / "old.der"};
    out << "old";
  }
  EXPECT_ANY_THROW(ua::certificate_store_files_detail::replace_list_directories({
    {certs, [](const fs::path& into) { std::ofstream{into / "new.der"} << "new"; }, {}},
    {crls,
      [](const fs::path& into)
      {
        fs::remove_all(into);
      }},  // its fresh directory will be missing
  }));
  EXPECT_TRUE(fs::exists(certs / "old.der")) << "the first list was rolled back";
  EXPECT_FALSE(fs::exists(certs / "new.der"));
  EXPECT_FALSE(fs::exists(certs.string() + ".old"));
  EXPECT_FALSE(fs::exists(certs.string() + ".new"));
  EXPECT_TRUE(fs::is_directory(crls)) << "the list whose swap failed is restored too";
  EXPECT_FALSE(fs::exists(crls.string() + ".old"));
  EXPECT_FALSE(fs::exists(crls.string() + ".new"));
}

// The failing list's own restore can fail too (here: a directory appears where the list was renamed
// from, so neither the fresh list nor the old one can be renamed back). The swap then leaves ".new"
// markers, and the next recovery rolls the pair back from ".old" instead of deleting the only copy.
// @verifies AC-SVR-SECADMIN-009-A-TRUST-LIST-REPLACEMENT-IS-ATOMIC-ON-DISK
TEST_F(CertificateStoreFilesTests, AFailedRestoreLeavesMarkersSoRecoveryKeepsTheOldList)
{
  const auto certs = mTestPath / "restore" / "Certs";
  const auto crls = mTestPath / "restore" / "Crls";
  fs::create_directories(certs);
  fs::create_directories(crls);
  std::ofstream{certs / "old.der"} << "old";
  std::ofstream{crls / "old.crl"} << "old";

  using ua::certificate_store_files_detail::ListReplacement;
  ListReplacement certList{certs, [](const fs::path& into) { std::ofstream{into / "new.der"} << "new"; }, {}};
  ListReplacement crlList{crls,
    [](const fs::path& into) { std::ofstream{into / "new.crl"} << "new"; },
    [](const fs::path& directory)
    {
      fs::create_directories(directory / "blocker");  // non-empty: both renames onto it fail
    }};
  EXPECT_ANY_THROW(ua::certificate_store_files_detail::replace_list_directories({certList, crlList}));
  EXPECT_TRUE(fs::exists(fs::path{crls.string() + ".old"} / "old.crl")) << "the old CRLs survive aside";
  EXPECT_TRUE(fs::exists(crls.string() + ".new")) << "a marker says the swap did not finish";

  fs::remove_all(crls);  // the blocker goes away (a later start)
  ua::certificate_store_files_detail::recover_list_directories({certs, crls});
  EXPECT_TRUE(fs::exists(crls / "old.crl")) << "recovery restored the old CRLs";
  EXPECT_TRUE(fs::exists(certs / "old.der")) << "and the pair stays whole";
  EXPECT_FALSE(fs::exists(crls.string() + ".old"));
  EXPECT_FALSE(fs::exists(crls.string() + ".new"));
}
