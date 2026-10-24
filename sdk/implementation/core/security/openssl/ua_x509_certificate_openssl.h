// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_X509_CERTIFICATE_OPENSSL_H
#define UA_X509_CERTIFICATE_OPENSSL_H

#include "openssl/x509.h"
#include "ua_x509_certificate.h"

namespace ua
{

class X509CertificateOpenSsl : public X509Certificate
{
public:
  explicit X509CertificateOpenSsl(X509& cert);
  ~X509CertificateOpenSsl();

  // mCert is owned (freed with X509_free in the destructor) but held by reference, so the
  // compiler-generated copy/move would alias the same X509* and double-free it. The type is
  // only ever held via shared_ptr; forbid value semantics.
  X509CertificateOpenSsl(const X509CertificateOpenSsl&) = delete;
  X509CertificateOpenSsl& operator=(const X509CertificateOpenSsl&) = delete;
  X509CertificateOpenSsl(X509CertificateOpenSsl&&) = delete;
  X509CertificateOpenSsl& operator=(X509CertificateOpenSsl&&) = delete;

  bool operator==(const X509Certificate& obj) const override;

  int version() const override;
  std::string serial_number() const override;
  ByteString signature() const override;
  std::string issuer() const override;
  std::string issuer_country() const override;
  std::string issuer_organization() const override;
  std::string issuer_organizational_unit() const override;
  std::string issuer_distinguished_name() const override;
  std::string issuer_state() const override;
  std::string issuer_common_name() const override;
  std::string issuer_domain_component() const override;
  std::string issuer_locality() const override;
  UtcTime validity_from() const override;
  UtcTime validity_to() const override;
  std::string subject() const override;
  std::string subject_country() const override;
  std::string subject_organization() const override;
  std::string subject_organizational_unit() const override;
  std::string subject_distinguished_name() const override;
  std::string subject_state() const override;
  std::string subject_common_name() const override;
  std::string subject_domain_component() const override;
  std::string subject_locality() const override;
  ByteString public_key() const override;
  size_t public_key_bit_length() const override;
  CertificateKeyAlgorithm key_algorithm() const override;
  ByteString authority_key_identifier() const override;
  ByteString subject_key_identifier() const override;
  bool key_usage_digital_signature() const override;
  bool key_usage_non_repudiation() const override;
  bool key_usage_key_encipherment() const override;
  bool key_usage_data_encipherment() const override;
  bool key_usage_key_agreement() const override;
  bool key_usage_key_cert_sign() const override;
  bool key_usage_crl_sign() const override;
  bool key_usage_encipher_only() const override;
  bool key_usage_decipher_only() const override;
  std::vector<asio::ip::address> san_ip_addresses() const override;
  std::vector<std::string> san_hostnames() const override;
  std::vector<std::string> san_uris() const override;
  bool basic_constraints_ca() const override;
  uint32_t basic_constraints_path_length() const override;
  bool extended_key_usage_client_auth() const override;
  bool extended_key_usage_server_auth() const override;
  ByteString thumbprint() const override;
  ByteString der_encoding() const override;
  bool issued_by(const X509Certificate& issuer) const override;
  bool issuer_of(const X509Certificate& issued) const override;
  bool self_signed() const override;
  CertificateSignatureAlgorithm signature_algorithm() const override;

  const X509& cert() const;

private:
  X509& mCert;

  std::string get_name_component_by_nid(const X509_NAME& name, int nid) const;
  std::string get_name_as_string(const X509_NAME& name) const;
  UtcTime get_time_from_asn1(const ASN1_TIME& time) const;
  bool get_key_usage(int usage) const;
  bool get_ext_key_usage(int usage) const;
  /// True when @p signer's public key verifies this certificate's signature; the error queue is cleared.
  bool verifies_with_key_of(const X509Certificate& signer) const;
  static ByteString octet_string_to_bytes(const ASN1_OCTET_STRING& octetString);
};

}  // namespace ua

#endif  //! UA_X509_CERTIFICATE_OPENSSL_H
