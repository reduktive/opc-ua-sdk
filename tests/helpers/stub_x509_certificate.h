// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef STUB_X509_CERTIFICATE_H
#define STUB_X509_CERTIFICATE_H

/// @file
/// @brief A minimal concrete @ref ua::X509Certificate for tests that only need a non-null certificate handle
///        to pass through an API (e.g. the tier-2 pull-cert manager, which carries the renewed cert as an
///        opaque `shared_ptr<const X509Certificate>` and never inspects its fields). Every accessor returns a
///        fixed placeholder; construct via @ref ua::testing::make_stub_certificate.

#include "ua_x509_certificate.h"

#include <boost/asio/ip/address.hpp>

#include <memory>
#include <string>
#include <vector>

namespace ua::testing
{

/// A concrete but inert @ref ua::X509Certificate. Not cryptographically meaningful - a placeholder object.
class StubX509Certificate : public ua::X509Certificate
{
public:
  bool operator==(const ua::X509Certificate& other) const override
  {
    return this == &other;
  }

  int version() const override
  {
    return 3;
  }

  std::string serial_number() const override
  {
    return "1";
  }

  ua::ByteString signature() const override
  {
    return {};
  }

  std::string issuer() const override
  {
    return "";
  }

  std::string issuer_country() const override
  {
    return "";
  }

  std::string issuer_organization() const override
  {
    return "";
  }

  std::string issuer_organizational_unit() const override
  {
    return "";
  }

  std::string issuer_distinguished_name() const override
  {
    return "";
  }

  std::string issuer_state() const override
  {
    return "";
  }

  std::string issuer_common_name() const override
  {
    return "";
  }

  std::string issuer_domain_component() const override
  {
    return "";
  }

  std::string issuer_locality() const override
  {
    return "";
  }

  ua::UtcTime validity_from() const override
  {
    return {};
  }

  ua::UtcTime validity_to() const override
  {
    return {};
  }

  std::string subject() const override
  {
    return "";
  }

  std::string subject_country() const override
  {
    return "";
  }

  std::string subject_organization() const override
  {
    return "";
  }

  std::string subject_organizational_unit() const override
  {
    return "";
  }

  std::string subject_distinguished_name() const override
  {
    return "";
  }

  std::string subject_state() const override
  {
    return "";
  }

  std::string subject_common_name() const override
  {
    return "";
  }

  std::string subject_domain_component() const override
  {
    return "";
  }

  std::string subject_locality() const override
  {
    return "";
  }

  ua::ByteString public_key() const override
  {
    return {};
  }

  size_t public_key_bit_length() const override
  {
    return 2048;
  }

  ua::CertificateKeyAlgorithm key_algorithm() const override
  {
    return ua::CertificateKeyAlgorithm::Rsa;
  }

  ua::ByteString authority_key_identifier() const override
  {
    return {};
  }

  ua::ByteString subject_key_identifier() const override
  {
    return {};
  }

  bool key_usage_digital_signature() const override
  {
    return true;
  }

  bool key_usage_non_repudiation() const override
  {
    return false;
  }

  bool key_usage_key_encipherment() const override
  {
    return true;
  }

  // The key-usage defaults form an RSA ApplicationInstance Certificate that OPC 10000-6 Table 43
  // accepts: digitalSignature, keyEncipherment and dataEncipherment, with clientAuth below.
  bool key_usage_data_encipherment() const override
  {
    return true;
  }

  bool key_usage_key_agreement() const override
  {
    return false;
  }

  bool key_usage_key_cert_sign() const override
  {
    return false;
  }

  bool key_usage_crl_sign() const override
  {
    return false;
  }

  bool key_usage_encipher_only() const override
  {
    return false;
  }

  bool key_usage_decipher_only() const override
  {
    return false;
  }

  std::vector<boost::asio::ip::address> san_ip_addresses() const override
  {
    return {};
  }

  std::vector<std::string> san_hostnames() const override
  {
    return {};
  }

  std::vector<std::string> san_uris() const override
  {
    return {};
  }

  bool basic_constraints_ca() const override
  {
    return false;
  }

  uint32_t basic_constraints_path_length() const override
  {
    return 0;
  }

  bool extended_key_usage_client_auth() const override
  {
    return true;
  }

  bool extended_key_usage_server_auth() const override
  {
    return false;
  }

  ua::ByteString thumbprint() const override
  {
    return {};
  }

  ua::ByteString der_encoding() const override
  {
    return ua::ByteString{0x30, 0x82, 0x01};
  }

  bool issued_by(const ua::X509Certificate&) const override
  {
    return false;
  }

  bool issuer_of(const ua::X509Certificate&) const override
  {
    return false;
  }

  bool self_signed() const override
  {
    return true;
  }

  ua::CertificateSignatureAlgorithm signature_algorithm() const override
  {
    return ua::CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  }
};

/// Constructs an inert stub certificate as a shared handle.
[[nodiscard]] inline std::shared_ptr<const ua::X509Certificate> make_stub_certificate()
{
  return std::make_shared<const StubX509Certificate>();
}

}  // namespace ua::testing

#endif  // STUB_X509_CERTIFICATE_H
