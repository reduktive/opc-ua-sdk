// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef REDUKTIVE_REFERENCE_PKI_H
#define REDUKTIVE_REFERENCE_PKI_H

#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_logger.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/address.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace reduktive::reference
{

/// Inputs used when a reference application needs to create or rotate its own certificate.
struct CertificateProfile
{
  std::string commonName;
  std::string applicationUri;
  std::vector<std::string> dnsNames;
  std::vector<boost::asio::ip::address> ipAddresses;
};

/// Persistent cryptographic state shared with the SDK application handle.
struct ApplicationPki
{
  std::shared_ptr<const ua::Crypto> crypto;
  std::shared_ptr<ua::CertificateStore> store;
  ua::CertificateStore::ApplicationCertificate applicationCertificate;
};

/// Creates a file-backed trust store, loading or generating one application certificate.
///
/// The private-key credential is read from @p credentialEnvironmentVariable. It is never accepted
/// on the command line or logged. Existing certificate/key material is reused when its application
/// URI and SAN names still match @p profile; otherwise it is replaced in the same store.
ApplicationPki prepare_application_pki(boost::asio::any_io_executor executor, std::filesystem::path pkiRoot,
  std::string credentialEnvironmentVariable, CertificateProfile profile, ua::Logger logger = {});

/// Writes only the public DER certificate; no private key material is exported.
void export_public_certificate(
  const ua::X509Certificate& certificate, const std::filesystem::path& destination);

/// Parses an operator-named DER certificate and persists it as a trust anchor.
///
/// Naming this file is an explicit provisioning action. Callers should display and independently
/// verify @ref certificate_sha256 before invoking this function in an unattended deployment.
std::shared_ptr<const ua::X509Certificate> trust_public_certificate(
  const ua::Crypto& crypto, ua::CertificateStore& store, const std::filesystem::path& source);

/// Renders a SHA-256 fingerprint of the complete DER certificate in uppercase hexadecimal.
std::string certificate_sha256(const ua::Crypto& crypto, const ua::X509Certificate& certificate);

}  // namespace reduktive::reference

#endif  // REDUKTIVE_REFERENCE_PKI_H
