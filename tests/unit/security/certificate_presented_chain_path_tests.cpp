// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Presented chains on every path (certificate-validation test plan U11, OPC 10000-6 section 6.2.6) and the
// security policy check on the user-token path (U12, OPC 10000-4 Table 106 step 4, U7 oracle).
//
// Each expected status comes from the specification. Each arm has a control that differs in one variable:
// the presented intermediate, the trailing bytes, the key length.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <system_error>
#include <vector>
#include <boost/asio/thread_pool.hpp>

#include "certificate_store_test_backends.h"
#include "fake_certificate_store.h"
#include "test_pki_helpers.h"
#include "test_key_cache.h"
#include "test_utilities.h"
#include "ua_built_in_authenticators.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_security_policy.h"
#include "ua_server_authentication.h"
#include "ua_server_cert_validator.h"
#include "ua_user_token_certificate_validation.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"

namespace fs = std::filesystem;
using namespace ua;

namespace
{

/// Whether any link of the result's ErrorDetail chain carries @p cause as its inner status.
template<typename R>
bool has_cause(const R& result, Status cause)
{
  for (const ErrorDetail* detail = result.shared_detail().get(); detail != nullptr;
       detail = detail->cause.get())
  {
    if (detail->innerStatus == StatusCode{cause}.value())
    {
      return true;
    }
  }
  return false;
}

/// leaf <- intermediate <- root (RSA 2048), and weakLeaf (RSA 1024) and strongLeaf (RSA 2048) issued by
/// the root directly. The leaves carry localhost in their subjectAltName.
struct ChainPki
{
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<const X509Certificate> root;
  std::shared_ptr<const X509Certificate> intermediate;
  std::shared_ptr<const X509Certificate> leaf;
  std::shared_ptr<const X509Certificate> weakLeaf;
  std::shared_ptr<const X509Certificate> strongLeaf;
};

std::unique_ptr<ChainPki> build_chain_pki()
{
  auto pki = std::make_unique<ChainPki>();
  pki->crypto = BackendOpenSslFiles::create_crypto();
  TestPki helper{pki->crypto};
  const auto& crypto = pki->crypto;
  const auto now = DateTime::now();
  const DateTime inAYear{now.value() + std::chrono::days{365}};
  const DateTime inThirtyDays{now.value() + std::chrono::days{30}};

  // Keys from the shared test key cache, a slot per key.
  const auto rootKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  const auto intermediateKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 1);
  pki->root = helper.create_root_ca(rootKeys, "Chain Root CA", "9600");

  Crypto::CreateCertificateConfig p;
  p.subjectKeys = intermediateKeys;
  p.issuerKeys = rootKeys;
  p.issuer = pki->root;
  p.subject.commonName = "Chain Intermediate CA";
  p.serialNumber = "9601";
  p.basicConstraint.cA = true;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.crlSign = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = now;
  p.to = inAYear;
  pki->intermediate = helper.create_cert(p);

  pki->leaf = helper.create_leaf_cert(test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 2),
    intermediateKeys,
    pki->intermediate,
    now,
    inThirtyDays,
    {"urn:reduktive:chain:leaf"},
    {"localhost"},
    "Chain Leaf");
  pki->weakLeaf = helper.create_leaf_cert(test_keys::key_pair(*crypto, test_keys::KeyType::Rsa1024, 0),
    rootKeys,
    pki->root,
    now,
    inThirtyDays,
    {},
    {"localhost"},
    "Chain Weak Leaf");
  pki->strongLeaf = helper.create_leaf_cert(test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 3),
    rootKeys,
    pki->root,
    now,
    inThirtyDays,
    {},
    {"localhost"},
    "Chain Strong Leaf");
  return pki;
}

class CertificatePresentedChainPaths : public ::testing::Test
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sPki = build_chain_pki();
  }

  static void TearDownTestSuite()
  {
    test_utils::drain_with_timeout(*sThreadPool);
    sThreadPool.reset();
    sPki.reset();
  }

protected:
  void SetUp() override
  {
    ASSERT_NE(sPki, nullptr);
    mRootPath = test_utils::unique_temp_path("cert_presented_chain_paths");
    fs::remove_all(mRootPath);
    mStore = BackendOpenSslFiles::create_store(
      mRootPath, sThreadPool->get_executor(), sPki->crypto, TrustListValidationOptions{});
    ASSERT_NE(mStore, nullptr);
    ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(sPki->root).is_good());
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  /// The X509 user certificate as the session validates it before the authenticator (owner review 2026-10-02,
  /// item 8): the token's certificate field parsed into leaf + presented issuers by the one chain parser,
  /// mUse = User, mPolicy = the user-token policy's SecurityPolicy (null when none), the user-token store. A
  /// refusal is Bad_IdentityTokenRejected carrying the Table 106 fault as its cause. SEAM:
  /// server::detail::validate_user_token_certificate_async(store, crypto, certificateData, policy, callback)
  /// is the session's function (also used by re-evaluation after a trust-list change); the name is the one
  /// this test fixes for the implementation.
  VoidResult validate_user_token(const std::vector<std::shared_ptr<const X509Certificate>>& chain,
    std::optional<SecurityPolicyId> userTokenPolicy = std::nullopt)
  {
    std::vector<uint8_t> bytes;
    for (const auto& certificate : chain)
    {
      const auto der = certificate->der_encoding();
      bytes.insert(bytes.end(), der.begin(), der.end());
    }
    const ByteString certificateData{std::move(bytes)};
    std::shared_ptr<const SecurityPolicy> policy =
      userTokenPolicy.has_value()
        ? std::shared_ptr<const SecurityPolicy>{SecurityPolicy::create(*userTokenPolicy)}
        : nullptr;
    std::promise<VoidResult> promise;
    server::detail::validate_user_token_certificate_async(mStore,
      sPki->crypto,
      certificateData,
      std::move(policy),
      [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }

  static std::unique_ptr<ChainPki> sPki;

  fs::path mRootPath;
  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  std::shared_ptr<CertificateStore> mStore;
};

std::unique_ptr<ChainPki> CertificatePresentedChainPaths::sPki;

// The X509 user identity token's certificate is validated with the issuers presented with it as chain
// material, as the OPN path does (OPC 10000-6 section 6.2.6). Control: without the intermediate the chain
// cannot be built.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-31-PRESENTED-CHAIN-PATHS, scope=function)
TEST_F(CertificatePresentedChainPaths, AnX509UserTokenCompletesItsChainFromThePresentedIssuers)
{
  const auto accepted = validate_user_token({sPki->leaf, sPki->intermediate});
  EXPECT_TRUE(accepted.is_good()) << to_string(accepted.status_code().as_status());

  const auto refused = validate_user_token({sPki->leaf});
  EXPECT_EQ(refused.status_code().as_status(), Status::BadIdentityTokenRejected);
  EXPECT_TRUE(has_cause(refused, Status::BadCertificateChainIncomplete))
    << "the Table 106 cause is preserved in the ErrorDetail";
}

// Every certificate-validation failure of an X509 user token is reported as Bad_IdentityTokenRejected (OPC
// 10000-4 ActivateSession: the token is well-formed but rejected), never the raw Table 106 code, which would
// describe an application-instance certificate failure; the Table 106 code is preserved as the cause.
// Ported from X509UserAuthenticatorTest.AllCertFailureStatusesMapToIdentityTokenRejected and
// MapsCertValidationFailureToIdentityTokenRejected: the mapping moved to the session with the validation.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-35-USER-TOKEN-SESSION-VALIDATES, scope=function)
TEST_F(CertificatePresentedChainPaths, EveryCertificateFaultMapsToIdentityTokenRejectedWithItsCause)
{
  for (const auto fault : {Status::BadCertificateUntrusted,
         Status::BadCertificateTimeInvalid,
         Status::BadCertificateRevoked,
         Status::BadCertificateRevocationUnknown,
         Status::BadCertificateUseNotAllowed,
         Status::BadSecurityChecksFailed})
  {
    const auto store = test_helpers::FakeCertificateStore::create();
    store->validateCertificateStatus = StatusCode{fault};
    const auto certificateData = sPki->strongLeaf->der_encoding();
    std::promise<VoidResult> promise;
    server::detail::validate_user_token_certificate_async(store,
      sPki->crypto,
      ByteString{certificateData.begin(), certificateData.end()},
      nullptr,
      [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    const auto result = promise.get_future().get();
    EXPECT_EQ(result.status_code().as_status(), Status::BadIdentityTokenRejected) << to_string(fault);
    EXPECT_TRUE(has_cause(result, fault)) << to_string(fault) << " must be preserved as the cause";
    const auto request = store->last_validation_request();
    ASSERT_TRUE(request.has_value());
    EXPECT_EQ(request->use, CertificateUse::User) << "a user token is validated for Table 44 use";
  }
}

// The client's periodic revalidation validates the pinned server certificate with the chain the server
// presented: a store that trusts only the root completes the chain from it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-31-PRESENTED-CHAIN-PATHS, scope=function)
TEST_F(CertificatePresentedChainPaths, TheClientRevalidationCompletesTheChainFromThePresentedIssuers)
{
  const auto store = mStore;
  CertificateValidationRequest stored;
  stored.certificate = sPki->leaf;
  stored.presentedIssuers = {sPki->intermediate};
  stored.endpointUrl = "opc.tcp://localhost:4840";
  const auto validator = client::detail::make_server_cert_revalidation(
    [store]() -> std::shared_ptr<CertificateStore> { return store; }, stored);
  std::promise<VoidResult> verdict;
  validator([&verdict](VoidResult result) { verdict.set_value(std::move(result)); });
  const auto result = verdict.get_future().get();
  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code().as_status());
}

// OPC 10000-6 section 6.2.6: a certificate field holds DER certificates back to back and nothing else.
// Control: the same chain without the trailing bytes yields its three certificates in order.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-32-CHAIN-TRAILING-GARBAGE, scope=function)
TEST_F(CertificatePresentedChainPaths, AChainWithTrailingBytesIsCertificateInvalid)
{
  std::vector<ua::byte> chain;
  for (const auto& certificate : {sPki->leaf, sPki->intermediate, sPki->root})
  {
    const auto der = certificate->der_encoding();
    std::transform(
      der.begin(), der.end(), std::back_inserter(chain), [](auto c) { return static_cast<ua::byte>(c); });
  }
  const auto parsed = sPki->crypto->read_certificates_from_der(span<const ua::byte>{chain});
  ASSERT_EQ(parsed.size(), 3u);
  EXPECT_EQ(parsed[0]->thumbprint(), sPki->leaf->thumbprint());
  EXPECT_EQ(parsed[1]->thumbprint(), sPki->intermediate->thumbprint());
  EXPECT_EQ(parsed[2]->thumbprint(), sPki->root->thumbprint());

  auto withGarbage = chain;
  withGarbage.push_back(ua::byte{0x30});
  withGarbage.push_back(ua::byte{0x01});
  withGarbage.push_back(ua::byte{0xFF});
  Status refusal = Status::Good;
  try
  {
    (void)sPki->crypto->read_certificates_from_der(span<const ua::byte>{withGarbage});
  }
  catch (const UaException& e)
  {
    refusal = e.status();
  }
  EXPECT_EQ(refusal, Status::BadCertificateInvalid) << to_string(refusal);
}

// U12: Table 106 step 4 applies to an X509 user token under its user-token policy's SecurityPolicy. The U7
// oracle for Basic256Sha256 is RSA 2048 to 4096 bits; a 1024-bit key fails, the 2048-bit control passes.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-33-POLICY-USER-TOKEN, scope=function)
TEST_F(CertificatePresentedChainPaths, AnX509UserTokenViolatingItsSecurityPolicyIsRejected)
{
  const auto refused = validate_user_token({sPki->weakLeaf}, SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadIdentityTokenRejected);
  EXPECT_TRUE(has_cause(refused, Status::BadCertificatePolicyCheckFailed))
    << "the cause is the Security Policy Check";

  const auto accepted = validate_user_token({sPki->strongLeaf}, SecurityPolicyId::Basic256Sha256);
  EXPECT_TRUE(accepted.is_good()) << to_string(accepted.status_code().as_status());
}

}  // namespace
