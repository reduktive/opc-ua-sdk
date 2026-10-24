// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_PKI_HELPERS_H
#define UA_TEST_PKI_HELPERS_H

#include <memory>
#include <string>
#include <vector>
#include <future>
#include "ua_crypto.h"
#include "ua_status_code.h"
#include "ua_utc_time.h"

namespace ua
{

struct TestPki
{
  std::shared_ptr<const Crypto> crypto;

  explicit TestPki(std::shared_ptr<const Crypto> c) : crypto(std::move(c))
  {}

  std::shared_ptr<const X509Certificate> create_cert(const Crypto::CreateCertificateConfig& params)
  {
    std::promise<CertificateResult> p;
    crypto->create_certificate_async(
      params, [&p](CertificateResult result) { p.set_value(std::move(result)); });
    auto result = p.get_future().get();
    if (result.is_bad())
      throw std::runtime_error("Failed to create certificate " + params.subject.commonName + ": " +
                               ua::describe(result.status_code()));
    return std::move(result).value();
  }

  std::shared_ptr<const X509Certificate> create_root_ca(std::shared_ptr<const AsymmetricKeyPair> keys,
    const std::string& name = "Root CA", const std::string& sn = "100")
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = keys;
    p.subject.commonName = name;
    p.serialNumber = sn;
    p.basicConstraint.cA = true;
    p.keyUsage.keyCertSign = true;
    p.keyUsage.crlSign = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    return create_cert(p);
  }

  /// A self-signed root that is also a conformant RSA ApplicationInstance Certificate, for a test that
  /// validates a root as an application certificate. OPC 10000-6 section 6.2.2 Table 43: keyUsage includes
  /// digitalSignature, nonRepudiation, keyEncipherment and dataEncipherment, extendedKeyUsage specifies
  /// serverAuth and/or clientAuth, and a self-signed certificate with cA TRUE "shall also include
  /// keyCertSign". create_root_ca stays a plain CA (Table 45), which is not an ApplicationInstance
  /// Certificate.
  std::shared_ptr<const X509Certificate> create_self_signed_application_root(
    std::shared_ptr<const AsymmetricKeyPair> keys, const std::string& name = "Root CA",
    const std::string& sn = "100")
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = keys;
    p.subject.commonName = name;
    p.serialNumber = sn;
    p.basicConstraint.cA = true;
    p.keyUsage.keyCertSign = true;
    p.keyUsage.crlSign = true;
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyEncipherment = true;
    p.keyUsage.dataEncipherment = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    return create_cert(p);
  }

  /// A self-signed RSA ApplicationInstance Certificate that OPC 10000-6 Table 43 accepts: every keyUsage bit
  /// it names for an RSA key, keyCertSign because the certificate signs itself, and both extendedKeyUsage
  /// purposes. The certificate to present as a SecureChannel peer's own; a root CA from
  /// @ref create_root_ca is refused there for its use, as it lacks the encipherment bits.
  std::shared_ptr<const X509Certificate> create_self_signed_application_cert(
    std::shared_ptr<const AsymmetricKeyPair> keys, const std::string& name = "Application",
    const std::string& sn = "100")
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = keys;
    p.subject.commonName = name;
    p.serialNumber = sn;
    p.basicConstraint.cA = false;
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyEncipherment = true;
    p.keyUsage.dataEncipherment = true;
    p.keyUsage.keyCertSign = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    return create_cert(p);
  }

  std::shared_ptr<const X509Certificate> create_leaf_cert(
    std::shared_ptr<const AsymmetricKeyPair> subjectKeys, std::shared_ptr<const AsymmetricKeyPair> issuerKeys,
    std::shared_ptr<const X509Certificate> issuerCert, DateTime from, DateTime to,
    std::vector<std::string> uris = {}, std::vector<std::string> hostnames = {},
    const std::string& name = "Leaf")
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = subjectKeys;
    p.issuerKeys = std::move(issuerKeys);
    p.subject.commonName = name;
    p.serialNumber = std::to_string(DateTime::now().value().time_since_epoch().count());
    // OPC 10000-6 section 6.2.2 Table 43: an RSA ApplicationInstance Certificate's keyUsage "shall include
    // digitalSignature, nonRepudiation, keyEncipherment and dataEncipherment" and its
    // extendedKeyUsage "shall specify serverAuth and/or clientAuth". This helper previously set
    // digitalSignature alone, which is what the handshake signature happens to need and is not a
    // conformant certificate. That went unnoticed for as long as nothing checked - and when the
    // Table 43 enforcement landed, ten certificate-store tests failed and read as a regression in
    // the validator rather than as non-conformant fixtures. The SDK's own issuing path
    // (sign_certificate_request_sync) has always set all four bits plus both EKU purposes, so this
    // now matches the certificates the SDK actually produces.
    //
    // A test that needs a deliberately short keyUsage should build its own parameters rather than
    // weaken this one, which every fixture wanting "an ordinary valid leaf" depends on.
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyEncipherment = true;
    p.keyUsage.dataEncipherment = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    p.from = from;
    p.to = to;
    p.issuer = std::move(issuerCert);
    p.subjectAlternateName.uris = std::move(uris);
    p.subjectAlternateName.hostnames = std::move(hostnames);
    return create_cert(p);
  }

  std::shared_ptr<const X509Certificate> sign_csr(ByteString csrDer,
    std::shared_ptr<const AsymmetricKeyPair> caKeys, std::shared_ptr<const X509Certificate> caCert,
    CertificateSignatureAlgorithm sigAlgo = CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    Crypto::SubjectAlternateName san = {})
  {
    Crypto::SignCsrConfig params;
    params.csrDer = std::move(csrDer);
    params.issuer = std::move(caCert);
    params.issuerKeys = std::move(caKeys);
    params.signatureAlgorithm = sigAlgo;
    params.from = DateTime::now();
    params.to = DateTime{params.from.value() + std::chrono::days{365}};
    params.subjectAlternateName = std::move(san);
    return crypto->sign_certificate_request_sync(params);
  }

  std::shared_ptr<const X509Crl> create_crl(std::shared_ptr<const X509Certificate> issuer,
    std::shared_ptr<const AsymmetricKeyPair> issuerKeys, std::vector<std::string> revokedSerialNumbers)
  {
    std::promise<CrlResult> p;
    crypto->create_crl_async(issuer,
      issuerKeys,
      std::move(revokedSerialNumbers),
      [&p](CrlResult result) { p.set_value(std::move(result)); });
    auto result = p.get_future().get();
    if (result.is_bad())
      throw std::runtime_error("Failed to create CRL: " + ua::describe(result.status_code()));
    return std::move(result).value();
  }
};

}  // namespace ua

#endif  // UA_TEST_PKI_HELPERS_H
