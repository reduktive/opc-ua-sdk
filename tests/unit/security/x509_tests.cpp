// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <openssl/x509v3.h>
#include <gtest/gtest.h>
#include <future>  // std::promise, used below; previously only reached via the precompiled header
#include "ua_crypto.h"
#include "ua_x509_certificate.h"
#include "ua_x509_certificate_openssl.h"
#include "ua_x509_crl.h"

using namespace ua;

TEST(X509OpenSslTests, CreateCertificate)
{
  StatusCode status;
  shared_ptr<const AsymmetricKeyPair> keys;
  auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

  size_t keyLengthInBits{1024};
  crypto->create_asymmetric_key_pair_async(CertificateKeyAlgorithm::Rsa,
    keyLengthInBits,
    [&status, &keys](KeyPairResult result)
    {
      status = result.status_code();
      if (result.is_good())
        keys = std::move(result).value();
    });

  shared_ptr<const X509Certificate> certificate;
  Crypto::CreateCertificateConfig parameters;
  parameters.subjectKeys = parameters.issuerKeys = keys;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.serialNumber = "1234";
  parameters.from = DateTime::now();
  parameters.to = DateTime{parameters.from.value() + std::chrono::days{10 * 365}};
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.nonRepudiation = true;
  parameters.keyUsage.keyEncipherment = true;
  parameters.keyUsage.dataEncipherment = true;
  parameters.keyUsage.keyCertSign = true;
  parameters.keyUsage.clientAuth = true;
  parameters.keyUsage.serverAuth = true;
  parameters.basicConstraint.cA = true;
  parameters.basicConstraint.pathLength = 0;
  parameters.subject.distinguishedName = "reduktive";
  parameters.subjectAlternateName.hostnames.push_back("reduktive.com");
  parameters.subjectAlternateName.ipAddresses.push_back(asio::ip::make_address("127.0.0.1"));
  parameters.subjectAlternateName.ipAddresses.push_back(asio::ip::make_address("2001:db8::1"));

  crypto->create_certificate_async(parameters,
    [&status, &certificate](CertificateResult result)
    {
      status = result.status_code();
      if (result.is_good())
        certificate = std::move(result).value();
    });

  ASSERT_EQ(certificate->subject_distinguished_name(), parameters.subject.distinguishedName);
  ASSERT_EQ(certificate->issuer_distinguished_name(), parameters.subject.distinguishedName);
  ASSERT_EQ(certificate->serial_number(), parameters.serialNumber);
  // X.509 validity is encoded at second precision; round-trip compares at that precision.
  using std::chrono::seconds;
  using std::chrono::time_point_cast;
  ASSERT_EQ(time_point_cast<seconds>(certificate->validity_from().value()),
    time_point_cast<seconds>(parameters.from.value()));
  ASSERT_EQ(time_point_cast<seconds>(certificate->validity_to().value()),
    time_point_cast<seconds>(parameters.to.value()));
  ASSERT_TRUE(!certificate->public_key().empty());
  ASSERT_EQ(certificate->public_key(), parameters.subjectKeys->public_key_der());
  ASSERT_TRUE(!certificate->subject_key_identifier().empty());
  ASSERT_EQ(certificate->subject_key_identifier(), certificate->authority_key_identifier());
  ASSERT_EQ(certificate->san_hostnames(), parameters.subjectAlternateName.hostnames);
  ASSERT_EQ(certificate->san_ip_addresses(), parameters.subjectAlternateName.ipAddresses);
  ASSERT_EQ(certificate->san_uris(), parameters.subjectAlternateName.uris);

  ASSERT_EQ(certificate->key_usage_digital_signature(), parameters.keyUsage.digitalSignature);
  ASSERT_EQ(certificate->key_usage_non_repudiation(), parameters.keyUsage.nonRepudiation);
  ASSERT_EQ(certificate->key_usage_key_encipherment(), parameters.keyUsage.keyEncipherment);
  ASSERT_EQ(certificate->key_usage_data_encipherment(), parameters.keyUsage.dataEncipherment);
  ASSERT_EQ(certificate->key_usage_key_cert_sign(), parameters.keyUsage.keyCertSign);
  ASSERT_EQ(certificate->key_usage_key_agreement(), parameters.keyUsage.keyAgreement);
  ASSERT_EQ(certificate->key_usage_crl_sign(), parameters.keyUsage.crlSign);
  ASSERT_EQ(certificate->key_usage_encipher_only(), parameters.keyUsage.encipherOnly);
  ASSERT_EQ(certificate->key_usage_decipher_only(), parameters.keyUsage.decipherOnly);
  ASSERT_EQ(certificate->extended_key_usage_client_auth(), parameters.keyUsage.clientAuth);
  ASSERT_EQ(certificate->extended_key_usage_server_auth(), parameters.keyUsage.serverAuth);

  ASSERT_EQ(certificate->signature().size(), keyLengthInBits / 8);
  ASSERT_EQ(certificate->signature_algorithm(), CertificateSignatureAlgorithm::RsaPkcs15Sha2256);
}

// Part 6 section 6.2.5 and Table 46 require every CRL to carry authorityKeyIdentifier so it remains
// attributable to a specific issuer key across CA key rollover.
// @verifies AC-SVR-SECADMIN-023-AUTHORITY-KEY-IDENTIFIER
// @relation(AC-SVR-SECADMIN-023-AUTHORITY-KEY-IDENTIFIER, scope=function)
TEST(X509OpenSslTests, CreatedCrlCarriesIssuersAuthorityKeyIdentifier)
{
  auto crypto = create_default_crypto(
    []()
    {
      constexpr string_view password{"password"};
      return ua::SecureString{password.data(), password.size()};
    });
  const auto issuerKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  Crypto::CreateCertificateConfig parameters;
  parameters.subjectKeys = parameters.issuerKeys = issuerKeys;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.serialNumber = "2345";
  parameters.from = DateTime::now();
  parameters.to = DateTime{parameters.from.value() + std::chrono::days{365}};
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.keyCertSign = true;
  parameters.keyUsage.crlSign = true;
  parameters.basicConstraint.cA = true;
  parameters.basicConstraint.pathLength = 0;
  parameters.subject.commonName = "CRL issuer";
  std::promise<CertificateResult> issuerPromise;
  crypto->create_certificate_async(
    parameters, [&issuerPromise](CertificateResult result) { issuerPromise.set_value(std::move(result)); });
  auto issuerResult = issuerPromise.get_future().get();
  ASSERT_TRUE(issuerResult.is_good());
  const auto issuer = std::move(issuerResult).value();
  ASSERT_TRUE(issuer);
  ASSERT_FALSE(issuer->subject_key_identifier().empty());

  const auto crl = crypto->create_crl_sync(issuer, issuerKeys, {});
  ASSERT_TRUE(crl);
  const auto der = crl->der_encoding();
  ASSERT_FALSE(der.empty());

  const unsigned char* cursor = der.data();
  auto decoded = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>{
    d2i_X509_CRL(nullptr, &cursor, numeric_cast<long>(der.size())), &X509_CRL_free};
  ASSERT_TRUE(decoded);
  const int extensionIndex = X509_CRL_get_ext_by_NID(decoded.get(), NID_authority_key_identifier, -1);
  ASSERT_GE(extensionIndex, 0);
  X509_EXTENSION* extension = X509_CRL_get_ext(decoded.get(), extensionIndex);
  ASSERT_NE(extension, nullptr);
  auto authorityKeyIdentifier = std::unique_ptr<AUTHORITY_KEYID, decltype(&AUTHORITY_KEYID_free)>{
    static_cast<AUTHORITY_KEYID*>(X509V3_EXT_d2i(extension)), &AUTHORITY_KEYID_free};
  ASSERT_TRUE(authorityKeyIdentifier);
  ASSERT_NE(authorityKeyIdentifier->keyid, nullptr);
  EXPECT_GT(ASN1_STRING_length(authorityKeyIdentifier->keyid), 0);
}

// @relation(AC-COMP-SDK-POST-X509-IP-SAN, scope=function)
TEST(X509OpenSslTests, MalformedIpSanReportsDetailWithoutLeakingDecodedExtension)
{
  auto rawCertificate = std::unique_ptr<X509, decltype(&X509_free)>{X509_new(), X509_free};
  ASSERT_TRUE(rawCertificate);

  auto names = std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>{
    sk_GENERAL_NAME_new_null(), GENERAL_NAMES_free};
  ASSERT_TRUE(names);

  auto name =
    std::unique_ptr<GENERAL_NAME, decltype(&GENERAL_NAME_free)>{GENERAL_NAME_new(), GENERAL_NAME_free};
  ASSERT_TRUE(name);
  auto address = std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>{
    ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free};
  ASSERT_TRUE(address);

  constexpr std::array<unsigned char, 5> malformedAddress{127, 0, 0, 1, 0};
  ASSERT_EQ(
    ASN1_OCTET_STRING_set(address.get(), malformedAddress.data(), numeric_cast<int>(malformedAddress.size())),
    1);
  GENERAL_NAME_set0_value(name.get(), GEN_IPADD, address.release());
  ASSERT_EQ(sk_GENERAL_NAME_push(names.get(), name.get()), 1);
  static_cast<void>(name.release());
  ASSERT_EQ(
    X509_add1_ext_i2d(rawCertificate.get(), NID_subject_alt_name, names.get(), 0, X509V3_ADD_DEFAULT), 1);

  X509CertificateOpenSsl certificate{*rawCertificate.release()};
  try
  {
    static_cast<void>(certificate.san_ip_addresses());
    FAIL() << "Expected UaException";
  }
  catch (const UaException& exception)
  {
    // Ratified expectation change (security review B3-12(b)): a malformed IP SAN is a certificate
    // defect, reported as Bad_CertificateInvalid; BadInternalError hid the cause.
    EXPECT_EQ(exception.status(), Status::BadCertificateInvalid);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "InvalidIpAddressLength");
  }
}

// Regression: ensure cert validity dates beyond the 32-bit time_t rollover (2038-01-19) round-trip
// correctly. Older code passed a time_t into X509_time_adj, which silently wraps on 32-bit and
// produced a notAfter in 1901, making freshly-allocated certs appear already expired.
TEST(X509OpenSslTests, CreateCertificateWithPost2038Expiry)
{
  auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

  shared_ptr<const AsymmetricKeyPair> keys;
  crypto->create_asymmetric_key_pair_async(CertificateKeyAlgorithm::Rsa,
    2048,
    [&keys](KeyPairResult result)
    {
      ASSERT_TRUE(result.is_good());
      keys = std::move(result).value();
    });

  Crypto::CreateCertificateConfig parameters;
  parameters.subjectKeys = parameters.issuerKeys = keys;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.serialNumber = "1";
  parameters.from = DateTime{2026, 1, 1, 0, 0, 0.0, 0};
  parameters.to = DateTime{2050, 1, 1, 0, 0, 0.0, 0};
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.keyEncipherment = true;
  parameters.keyUsage.keyCertSign = true;
  parameters.basicConstraint.cA = true;
  parameters.basicConstraint.pathLength = 0;
  parameters.subject.distinguishedName = "TestCert";
  parameters.subjectAlternateName.hostnames.push_back("localhost");

  shared_ptr<const X509Certificate> certificate;
  StatusCode status;
  crypto->create_certificate_async(parameters,
    [&certificate, &status](CertificateResult result)
    {
      status = result.status_code();
      if (result.is_good())
        certificate = std::move(result).value();
    });
  ASSERT_TRUE(status.is_good()) << "create_certificate_async failed: 0x" << std::hex << status.as_uint32();

  ASSERT_TRUE(certificate);
  using std::chrono::seconds;
  using std::chrono::time_point_cast;
  EXPECT_EQ(time_point_cast<seconds>(certificate->validity_from().value()),
    time_point_cast<seconds>(parameters.from.value()));
  EXPECT_EQ(time_point_cast<seconds>(certificate->validity_to().value()),
    time_point_cast<seconds>(parameters.to.value()));
}
