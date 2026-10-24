// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_hostname.h"

#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "ua_crypto.h"
#include "ua_x509_certificate.h"

#include <chrono>
#include <string>
#include <vector>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <gtest/gtest.h>

using namespace ua;

namespace
{

std::shared_ptr<const Crypto> make_crypto()
{
  return create_default_crypto(
    []()
    {
      constexpr std::string_view password{"password"};
      return ua::SecureString{password.data(), password.size()};
    });
}

std::shared_ptr<const X509Certificate> make_hostname_certificate(std::shared_ptr<const Crypto> crypto,
  std::vector<std::string> hostnames, std::vector<boost::asio::ip::address> addresses = {})
{
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig parameters;
  parameters.subjectKeys = parameters.issuerKeys =
    test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  parameters.subject.commonName = "Hostname Test";
  parameters.serialNumber = "9800";
  parameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
  parameters.to = DateTime{DateTime::now().value() + std::chrono::days{30}};
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.keyCertSign = true;
  parameters.basicConstraint.cA = false;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.subjectAlternateName.hostnames = std::move(hostnames);
  parameters.subjectAlternateName.ipAddresses = std::move(addresses);
  parameters.subjectAlternateName.uris = {"urn:test:hostname"};
  return pki.create_cert(parameters);
}

}  // namespace

// The Part 4 section 5.6.2.2 audit antecedent compares the requested HostName against the Server
// ApplicationInstanceCertificate. The control pair covers DNS canonicalisation, true IP SAN
// matching, and a foreign host; accepting the foreign host would suppress the required Event.
// @relation(AC-SVR-SESS-008-URLMISMATCH-EVENT, scope=function)
TEST(CertificateHostnameTests, MatchesDeclaredDnsAndIpNamesAndRejectsForeignHost)
{
  auto crypto = make_crypto();
  const auto certificate =
    make_hostname_certificate(crypto, {"Server.Example"}, {boost::asio::ip::make_address("127.0.0.1")});
  ASSERT_NE(certificate, nullptr);

  EXPECT_TRUE(detail::certificate_matches_hostname("server.example.", *certificate));
  EXPECT_TRUE(detail::certificate_matches_hostname("127.0.0.1", *certificate));
  EXPECT_FALSE(detail::certificate_matches_hostname("not-declared.invalid", *certificate));
}

// The one host-name rule is also the validator's Host Name step (OPC 10000-4 6.1.3): the HostName used
// to connect is one of the certificate's - names compare without case, an address matches an address. A
// localhost endpoint is not this host's name, and a loopback address is not localhost.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-16-ERROR-HOST-NAME-AND-URI, scope=function)
TEST(CertificateHostnameTests, LocalhostMatchesOnlyLocalhostAndAnAddressOnlyAnAddress)
{
  auto crypto = make_crypto();
  const auto thisHost = make_hostname_certificate(crypto, {boost::asio::ip::host_name()});
  const auto localhost = make_hostname_certificate(crypto, {"LocalHost"});

  EXPECT_TRUE(detail::certificate_matches_hostname("localhost", *localhost)) << "names compare without case";
  EXPECT_FALSE(detail::certificate_matches_hostname("127.0.0.1", *localhost))
    << "a loopback address is not the name localhost";
  EXPECT_FALSE(detail::certificate_matches_hostname("::1", *localhost));
  EXPECT_FALSE(detail::certificate_matches_hostname("localhost", *thisHost))
    << "localhost is not this host's name";
}

// Part 4 sections 6.1.3 and 5.5.1 require every accepted hostname to be declared by the certificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-147-DNS-LABEL-PRESERVATION, scope=function)
TEST(CertificateHostnameTests, AShortDnsNameDoesNotDeclareItsLocalName)
{
  const auto certificate = make_hostname_certificate(make_crypto(), {"controller"});
  EXPECT_TRUE(detail::certificate_matches_hostname("controller", *certificate));
  EXPECT_FALSE(detail::certificate_matches_hostname("controller.local", *certificate));
  EXPECT_FALSE(detail::certificate_matches_hostname("CONTROLLER.LOCAL.", *certificate));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-147-DNS-LABEL-PRESERVATION, scope=function)
TEST(CertificateHostnameTests, ALocalDnsNameDoesNotDeclareItsShortName)
{
  const auto certificate = make_hostname_certificate(make_crypto(), {"controller.local"});
  EXPECT_TRUE(detail::certificate_matches_hostname("controller.local", *certificate));
  EXPECT_FALSE(detail::certificate_matches_hostname("controller", *certificate));
  EXPECT_FALSE(detail::certificate_matches_hostname("CONTROLLER.", *certificate));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-147-DNS-LABEL-PRESERVATION, scope=function)
TEST(CertificateHostnameTests, ExplicitDnsNamesRetainCaseAndRootDotEquivalence)
{
  const auto certificate = make_hostname_certificate(make_crypto(), {"Controller", "Controller.Local."});
  EXPECT_TRUE(detail::certificate_matches_hostname("controller", *certificate));
  EXPECT_TRUE(detail::certificate_matches_hostname("CONTROLLER.", *certificate));
  EXPECT_TRUE(detail::certificate_matches_hostname("controller.local", *certificate));
  EXPECT_TRUE(detail::certificate_matches_hostname("CONTROLLER.LOCAL.", *certificate));
  EXPECT_FALSE(detail::certificate_matches_hostname("controller.example", *certificate));
}
