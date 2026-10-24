// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Validates the CTT's user identity certificates against the compliance_test_server's own user-token
// trust list, built by its own make_user_certificate_store.
//
// The store was created with the default ApplicationInstance purpose, so OPC 10000-6 Table 43 was
// applied to user certificates: every CTT user certificate carries no serverAuth/clientAuth
// extendedKeyUsage and was refused, and ActivateSession answered BadIdentityTokenRejected for almost
// every Security User X509 case. Table 44 governs user certificates and asks for no such extension.

#include <gtest/gtest.h>

#include "authenticators.h"
#include "certificate_validation_request_helpers.h"

#include "ua_crypto.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <vector>

namespace
{

const std::filesystem::path runtimeUsers =
  std::filesystem::path{COMPLIANCE_SERVER_RUNTIME_DIR} / "pki" / "users";

std::vector<ua::byte> read_file(const std::filesystem::path& path)
{
  std::ifstream in{path, std::ios::binary};
  const std::vector<char> raw{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
  std::vector<ua::byte> bytes(raw.size());
  std::memcpy(bytes.data(), raw.data(), raw.size());
  return bytes;
}

class ComplianceUserTokenTrust : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPrevious = std::filesystem::current_path();
    mDirectory =
      std::filesystem::temp_directory_path() / ("compliance_user_trust_" + std::to_string(::getpid()));
    std::filesystem::create_directories(mDirectory / "pki");
    std::filesystem::copy(
      runtimeUsers, mDirectory / "pki" / "users", std::filesystem::copy_options::recursive);
    std::filesystem::current_path(mDirectory);
    mCrypto = ua::create_default_crypto();
    mStore = ua::compliance_test_server::make_user_certificate_store(mPool.get_executor(), mCrypto);
  }

  void TearDown() override
  {
    mStore.reset();
    mPool.join();
    std::error_code ignored;
    std::filesystem::current_path(mPrevious, ignored);
    std::filesystem::remove_all(mDirectory, ignored);
  }

  ua::VoidResult validate(const std::string& file)
  {
    const auto der = read_file(runtimeUsers / "TrustList" / "TrustedCertificates" / file);
    const auto certificate = mCrypto->read_certificate_from_der(ua::span<const ua::byte>{der});
    return mStore->try_validate_certificate_sync(
      ua::test::make_validation_request(certificate, {}, std::nullopt));
  }

  std::filesystem::path mPrevious;
  std::filesystem::path mDirectory;
  boost::asio::thread_pool mPool{1};
  std::shared_ptr<const ua::Crypto> mCrypto;
  std::shared_ptr<ua::CertificateStore> mStore;
};

}  // namespace

TEST_F(ComplianceUserTokenTrust, SelfSignedTrustedUserCertificateValidates)
{
  const auto result = validate("ctt_usrT.der");
  EXPECT_TRUE(result.is_good()) << ua::to_string(result.status_code());
}

TEST_F(ComplianceUserTokenTrust, CaIssuedTrustedUserCertificateValidates)
{
  const auto result = validate("ctt_ca1I_usrT.der");
  EXPECT_TRUE(result.is_good()) << ua::to_string(result.status_code());
}
