// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Shared fixture of the integration certificate-validation matrices I1-I3
///        (certificate coverage review "Integration scope (owner 2026-10-02)").
///
/// One PKI per key family (root, intermediate, end-entity leaves for each certificate case, CRLs), a real
/// server built per test with ONE endpoint, and a real client at the highest public tier
/// (`Client::try_connect_sync`). Every expected outcome comes from `expected_outcome`, which encodes
/// OPC 10000-4 Table 106 (codes, audit event types) and the owner decisions in
/// the certificate-validation test plan ("Oracle corrections", "Owner decisions", "U7 ORACLE"); it calls no
/// SDK code.
///
/// Approved API used (not yet implemented when written):
///   - `CertificateStore::ApplicationCertificate::issuerCertificates` (decision 24): the issuer certificates
///     an application presents with its own certificate (OPC 10000-6 6.2.6), the production stimulus of every
///     "chain presented" row;
///   - `ServerObserver::on_certificate_rejected` / `on_certificate_error_suppressed` taking
///     `server::CertificateEventInfo` (decision 27, item 9): the hooks carry the presented certificate, so
///     the recorders below assert WHICH certificate was refused, not only the code.

#ifndef UA_TEST_CERTIFICATE_VALIDATION_INTEGRATION_FIXTURE_H
#define UA_TEST_CERTIFICATE_VALIDATION_INTEGRATION_FIXTURE_H

#include "test_certificate_rewrite.h"
#include "test_key_cache.h"
#include "test_log_sink.h"
#include "test_pki_helpers.h"
#include "test_utilities.h"

#include "ua_audit_certificate_data_mismatch_event_payload.h"
#include "ua_audit_certificate_event_payload.h"
#include "ua_base_event.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_client_observers.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_discovery.h"
#include "ua_service_set.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_log_sink.h"
#include "ua_objecttype_id.h"
#include "ua_role_configuration.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_observer.h"
#include "ua_user_token_policy.h"
#include "ua_status.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"
#include "sanitizer_budget.h"

#include <iostream>
#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace ua::test_helpers::certificate_validation
{

using CertificatePointer = std::shared_ptr<const X509Certificate>;
using KeysPointer = std::shared_ptr<const AsymmetricKeyPair>;
using CrlPointer = std::shared_ptr<const X509Crl>;

/// The result of Client::try_connect_sync / try_easy_connect_sync.
using ConnectResult = client::Client::ConnectResult;

inline constexpr const char* clientUri = "urn:test:certificate-validation:client";
inline constexpr const char* serverUri = "urn:test:certificate-validation:server";
inline constexpr const char* userUri = "urn:test:certificate-validation:user";

// ====================== Cases and channel configurations ======================

/// The core certificate set (owner 2026-10-02). The faulty certificate is the peer's own certificate.
enum class CertificateCase
{
  Valid,  ///< Leaf issued by the trusted root.
  ValidWithPresentedChain,  ///< Leaf issued by an intermediate only the peer sends.
  Untrusted,  ///< Self-signed leaf nothing trusts.
  Expired,  ///< Leaf past notAfter, no suppression.
  ExpiredSuppressed,  ///< Same leaf, validator configured with SuppressCertificateExpired.
  Revoked,  ///< Leaf listed on the root's CRL.
  ChainIncomplete,  ///< The ValidWithPresentedChain leaf sent WITHOUT its intermediate.
  PolicyKeyLength,  ///< RSA below the policy minimum / ECC or EdDSA key on another curve.
  PolicySignature,  ///< Signature algorithm (RSA) or curve-hash (ECDSA) or signer type (EdDSA) not permitted.
};

inline const std::vector<CertificateCase>& all_cases()
{
  static const std::vector<CertificateCase> cases{CertificateCase::Valid,
    CertificateCase::ValidWithPresentedChain,
    CertificateCase::Untrusted,
    CertificateCase::Expired,
    CertificateCase::ExpiredSuppressed,
    CertificateCase::Revoked,
    CertificateCase::ChainIncomplete,
    CertificateCase::PolicyKeyLength,
    CertificateCase::PolicySignature};
  return cases;
}

inline std::string case_name(CertificateCase certificateCase)
{
  switch (certificateCase)
  {
  case CertificateCase::Valid:
    return "Valid";
  case CertificateCase::ValidWithPresentedChain:
    return "ValidWithPresentedChain";
  case CertificateCase::Untrusted:
    return "Untrusted";
  case CertificateCase::Expired:
    return "Expired";
  case CertificateCase::ExpiredSuppressed:
    return "ExpiredSuppressed";
  case CertificateCase::Revoked:
    return "Revoked";
  case CertificateCase::ChainIncomplete:
    return "ChainIncomplete";
  case CertificateCase::PolicyKeyLength:
    return "PolicyKeyLength";
  case CertificateCase::PolicySignature:
    return "PolicySignature";
  }
  return "Unknown";
}

/// The 19 secured SecurityPolicies the SDK implements: the five RSA policies and the fourteen with
/// SecureChannelEnhancements (each curve with AES-GCM and with ChaCha20-Poly1305, and RSA_DH).
inline const std::vector<SecurityPolicyId>& all_policies()
{
  static const std::vector<SecurityPolicyId> policies{SecurityPolicyId::Basic128Rsa15,
    SecurityPolicyId::Basic256,
    SecurityPolicyId::Basic256Sha256,
    SecurityPolicyId::Aes128Sha256RsaOaep,
    SecurityPolicyId::Aes256Sha256RsaPss,
    SecurityPolicyId::EccNistP256AesGcm,
    SecurityPolicyId::EccNistP384AesGcm,
    SecurityPolicyId::EccBrainpoolP256r1AesGcm,
    SecurityPolicyId::EccBrainpoolP384r1AesGcm,
    SecurityPolicyId::EccCurve25519ChaChaPoly,
    SecurityPolicyId::EccCurve448ChaChaPoly,
    SecurityPolicyId::EccNistP256ChaChaPoly,
    SecurityPolicyId::EccNistP384ChaChaPoly,
    SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
    SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
    SecurityPolicyId::EccCurve25519AesGcm,
    SecurityPolicyId::EccCurve448AesGcm,
    SecurityPolicyId::RsaDhAesGcm,
    SecurityPolicyId::RsaDhChaChaPoly};
  return policies;
}

inline std::string policy_name(SecurityPolicyId policy)
{
  switch (policy)
  {
  case SecurityPolicyId::Basic128Rsa15:
    return "Basic128Rsa15";
  case SecurityPolicyId::Basic256:
    return "Basic256";
  case SecurityPolicyId::Basic256Sha256:
    return "Basic256Sha256";
  case SecurityPolicyId::Aes128Sha256RsaOaep:
    return "Aes128Sha256RsaOaep";
  case SecurityPolicyId::Aes256Sha256RsaPss:
    return "Aes256Sha256RsaPss";
  case SecurityPolicyId::EccNistP256AesGcm:
    return "EccNistP256";
  case SecurityPolicyId::EccNistP384AesGcm:
    return "EccNistP384";
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
    return "EccBrainpoolP256r1";
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
    return "EccBrainpoolP384r1";
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
    return "EccCurve25519ChaChaPoly";
  case SecurityPolicyId::EccCurve448ChaChaPoly:
    return "EccCurve448ChaChaPoly";
  case SecurityPolicyId::EccNistP256ChaChaPoly:
    return "EccNistP256ChaChaPoly";
  case SecurityPolicyId::EccNistP384ChaChaPoly:
    return "EccNistP384ChaChaPoly";
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
    return "EccBrainpoolP256r1ChaChaPoly";
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
    return "EccBrainpoolP384r1ChaChaPoly";
  case SecurityPolicyId::EccCurve25519AesGcm:
    return "EccCurve25519AesGcm";
  case SecurityPolicyId::EccCurve448AesGcm:
    return "EccCurve448AesGcm";
  case SecurityPolicyId::RsaDhAesGcm:
    return "RsaDhAesGcm";
  case SecurityPolicyId::RsaDhChaChaPoly:
    return "RsaDhChaChaPoly";
  default:
    return "Unknown";
  }
}

inline std::string mode_name(MessageSecurityMode mode)
{
  return mode == MessageSecurityMode::Sign ? "Sign" : "SignAndEncrypt";
}

struct MatrixParam
{
  SecurityPolicyId policy{SecurityPolicyId::None};
  MessageSecurityMode mode{MessageSecurityMode::None};
  CertificateCase certificateCase{CertificateCase::Valid};
};

/// Basic128Rsa15 and Basic256: RSA 1024-2048, SHA-1 or SHA-2 PKCS#1 v1.5 signatures.
inline bool is_rsa_min_policy(SecurityPolicyId policy)
{
  return policy == SecurityPolicyId::Basic128Rsa15 || policy == SecurityPolicyId::Basic256;
}

/// Every policy x {Sign, SignAndEncrypt} x each of @p cases.
inline std::vector<MatrixParam> matrix_params(const std::vector<CertificateCase>& cases)
{
  std::vector<MatrixParam> params;
  for (auto policy : all_policies())
  {
    for (auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
    {
      for (auto certificateCase : cases)
      {
        // Basic128Rsa15 and Basic256 permit every PKCS#1 v1.5 RSA signature, so only an RSA-PSS signature
        // violates them, and the SDK does not create RSASSA-PSS certificates. Not instantiated here; the
        // rule is proven by the unit policy matrix (U7, the RsaPss signature rows of these policies).
        if (certificateCase == CertificateCase::PolicySignature && is_rsa_min_policy(policy))
        {
          continue;
        }
        params.push_back(MatrixParam{.policy = policy, .mode = mode, .certificateCase = certificateCase});
      }
    }
  }
  return params;
}

/// Every policy x {Sign, SignAndEncrypt} with the case fixed (for the I3 rows).
inline std::vector<MatrixParam> channel_params()
{
  return matrix_params({CertificateCase::Valid});
}

/// Policy_Mode_Case.
inline std::string matrix_param_name(const ::testing::TestParamInfo<MatrixParam>& info)
{
  return policy_name(info.param.policy) + "_" + mode_name(info.param.mode) + "_" +
         case_name(info.param.certificateCase);
}

/// Policy_Mode (for rows where the case is fixed by the test).
inline std::string channel_param_name(const ::testing::TestParamInfo<MatrixParam>& info)
{
  return policy_name(info.param.policy) + "_" + mode_name(info.param.mode);
}

// ====================== Key families (U7 ORACLE, profile database) ======================

enum class Family
{
  Rsa,
  NistP256,
  NistP384,
  BrainpoolP256r1,
  BrainpoolP384r1,
  Curve25519,
  Curve448
};

inline Family family_of(SecurityPolicyId policy)
{
  switch (policy)
  {
  case SecurityPolicyId::EccNistP256AesGcm:
  case SecurityPolicyId::EccNistP256ChaChaPoly:
    return Family::NistP256;
  case SecurityPolicyId::EccNistP384AesGcm:
  case SecurityPolicyId::EccNistP384ChaChaPoly:
    return Family::NistP384;
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
    return Family::BrainpoolP256r1;
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
    return Family::BrainpoolP384r1;
  case SecurityPolicyId::EccCurve25519AesGcm:
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
    return Family::Curve25519;
  case SecurityPolicyId::EccCurve448AesGcm:
  case SecurityPolicyId::EccCurve448ChaChaPoly:
    return Family::Curve448;
  default:
    return Family::Rsa;
  }
}

/// OPC 10000-4 7.41 (1.05.07): "If the SecurityMode is None, SecurityPolicies based on ECC or RSA_DH are not
/// allowed and Clients shall not use UserTokenPolicies that require encryption with these SecurityPolicies".
/// True for a policy under which a UserName or IssuedToken secret may be encrypted on a None endpoint: the
/// RSA policies without ephemeral key agreement. A CERTIFICATE token "may be any valid SecurityPolicy".
inline bool secret_token_allowed_on_none_endpoint(SecurityPolicyId policy)
{
  switch (policy)
  {
  case SecurityPolicyId::Basic128Rsa15:
  case SecurityPolicyId::Basic256:
  case SecurityPolicyId::Basic256Sha256:
  case SecurityPolicyId::Aes128Sha256RsaOaep:
  case SecurityPolicyId::Aes256Sha256RsaPss:
    return true;
  default:
    return false;
  }
}

inline CertificateKeyAlgorithm key_algorithm_of(Family family)
{
  switch (family)
  {
  case Family::NistP256:
    return CertificateKeyAlgorithm::EccNistP256;
  case Family::NistP384:
    return CertificateKeyAlgorithm::EccNistP384;
  case Family::BrainpoolP256r1:
    return CertificateKeyAlgorithm::EccBrainpoolP256r1;
  case Family::BrainpoolP384r1:
    return CertificateKeyAlgorithm::EccBrainpoolP384r1;
  case Family::Curve25519:
    return CertificateKeyAlgorithm::EccCurve25519;
  case Family::Curve448:
    return CertificateKeyAlgorithm::EccCurve448;
  case Family::Rsa:
    return CertificateKeyAlgorithm::Rsa;
  }
  return CertificateKeyAlgorithm::Rsa;
}

/// The curve an end-entity certificate of the family must NOT use (profile database: "An end entity
/// Certificate shall use <curve>").
inline CertificateKeyAlgorithm wrong_curve_of(Family family)
{
  switch (family)
  {
  case Family::NistP256:
    return CertificateKeyAlgorithm::EccNistP384;
  case Family::NistP384:
    return CertificateKeyAlgorithm::EccNistP256;
  case Family::BrainpoolP256r1:
    return CertificateKeyAlgorithm::EccBrainpoolP384r1;
  case Family::BrainpoolP384r1:
    return CertificateKeyAlgorithm::EccBrainpoolP256r1;
  case Family::Curve25519:
    return CertificateKeyAlgorithm::EccCurve448;
  case Family::Curve448:
    return CertificateKeyAlgorithm::EccCurve25519;
  case Family::Rsa:
    return CertificateKeyAlgorithm::Rsa;
  }
  return CertificateKeyAlgorithm::Rsa;
}

/// The permitted signature of the family's CAs: SHA-256 for a 256-bit ECDSA signer, SHA-384 for a 384-bit
/// one.
inline CertificateSignatureAlgorithm signature_of(Family family)
{
  switch (family)
  {
  case Family::NistP256:
  case Family::BrainpoolP256r1:
    return CertificateSignatureAlgorithm::EcDsaSha2256;
  case Family::NistP384:
  case Family::BrainpoolP384r1:
    return CertificateSignatureAlgorithm::EcDsaSha2384;
  case Family::Curve25519:
    return CertificateSignatureAlgorithm::PureEdDsa25519;
  case Family::Curve448:
    return CertificateSignatureAlgorithm::PureEdDsa448;
  case Family::Rsa:
    return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  }
  return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
}

inline CertificateType application_certificate_type(SecurityPolicyId policy)
{
  switch (policy)
  {
  case SecurityPolicyId::Basic128Rsa15:
  case SecurityPolicyId::Basic256:
    return CertificateType::RsaMinApplication;
  case SecurityPolicyId::EccNistP256AesGcm:
  case SecurityPolicyId::EccNistP256ChaChaPoly:
    return CertificateType::EccNistP256Application;
  case SecurityPolicyId::EccNistP384AesGcm:
  case SecurityPolicyId::EccNistP384ChaChaPoly:
    return CertificateType::EccNistP384Application;
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
    return CertificateType::EccBrainpoolP256r1Application;
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
    return CertificateType::EccBrainpoolP384r1Application;
  case SecurityPolicyId::EccCurve25519AesGcm:
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
    return CertificateType::EccCurve25519Application;
  case SecurityPolicyId::EccCurve448AesGcm:
  case SecurityPolicyId::EccCurve448ChaChaPoly:
    return CertificateType::EccCurve448Application;
  default:
    return CertificateType::RsaSha256Application;
  }
}

// ====================== Oracle (Table 106 + owner decisions; no SDK calls) ======================

/// What the validating side must conclude about the peer's certificate.
struct ExpectedOutcome
{
  bool accepted{false};  ///< The connection is established.
  StatusCode table106{Status::Good};  ///< The validator's Table 106 code (refused cases).
  /// What a refused Client sees: Bad_SecurityChecksFailed where the Table 106 row says it "shall" (or
  /// "should") be reported back to the Client, the row's own code where the row says nothing (OPC
  /// 10000-4 6.1.3).
  StatusCode wire{Status::BadSecurityChecksFailed};
  std::optional<NodeId> auditEventType;  ///< The Table 106 audit event type, if one is raised.
  std::optional<StatusCode> suppressedError;  ///< Suppressed-but-reported fault (accepted cases).
  bool inRejectedStore{false};  ///< Rule: untrusted and chain-incomplete certificates go to Rejected.
};

inline ExpectedOutcome expected_outcome(CertificateCase certificateCase)
{
  switch (certificateCase)
  {
  case CertificateCase::Valid:
  case CertificateCase::ValidWithPresentedChain:
    return ExpectedOutcome{.accepted = true,
      .table106 = StatusCode{Status::Good},
      .auditEventType = std::nullopt,
      .suppressedError = std::nullopt,
      .inRejectedStore = false};
  case CertificateCase::Untrusted:
    return ExpectedOutcome{.accepted = false,
      .table106 = StatusCode{Status::BadCertificateUntrusted},
      .auditEventType = NodeId{ObjectTypeId::AuditCertificateUntrustedEventType},
      .suppressedError = std::nullopt,
      .inRejectedStore = true};
  case CertificateCase::Expired:
    // Trusted, so the Trust List Check passes; the Validity Period row has no masking sentence.
    return ExpectedOutcome{.accepted = false,
      .table106 = StatusCode{Status::BadCertificateTimeInvalid},
      .wire = StatusCode{Status::BadCertificateTimeInvalid},
      .auditEventType = NodeId{ObjectTypeId::AuditCertificateExpiredEventType},
      .suppressedError = std::nullopt,
      .inRejectedStore = false};
  case CertificateCase::ExpiredSuppressed:
    // "Suppressed errors are always reported via auditing" (Oracle corrections; owner decision).
    return ExpectedOutcome{.accepted = true,
      .table106 = StatusCode{Status::Good},
      .auditEventType = NodeId{ObjectTypeId::AuditCertificateExpiredEventType},
      .suppressedError = StatusCode{Status::BadCertificateTimeInvalid},
      .inRejectedStore = false};
  case CertificateCase::Revoked:
    return ExpectedOutcome{.accepted = false,
      .table106 = StatusCode{Status::BadCertificateRevoked},
      .auditEventType = NodeId{ObjectTypeId::AuditCertificateRevokedEventType},
      .suppressedError = std::nullopt,
      .inRejectedStore = false};
  case CertificateCase::ChainIncomplete:
    return ExpectedOutcome{.accepted = false,
      .table106 = StatusCode{Status::BadCertificateChainIncomplete},
      .auditEventType = NodeId{ObjectTypeId::AuditCertificateInvalidEventType},
      .suppressedError = std::nullopt,
      .inRejectedStore = true};
  case CertificateCase::PolicyKeyLength:
  case CertificateCase::PolicySignature:
    // Step 4, not suppressible (owner 22.3), AuditCertificateInvalid.
    return ExpectedOutcome{.accepted = false,
      .table106 = StatusCode{Status::BadCertificatePolicyCheckFailed},
      .auditEventType = NodeId{ObjectTypeId::AuditCertificateInvalidEventType},
      .suppressedError = std::nullopt,
      .inRejectedStore = false};
  }
  return ExpectedOutcome{};
}

/// The cases the validating side accepts.
inline std::vector<CertificateCase> accepted_cases()
{
  std::vector<CertificateCase> cases;
  for (auto certificateCase : all_cases())
  {
    if (expected_outcome(certificateCase).accepted)
      cases.push_back(certificateCase);
  }
  return cases;
}

/// The cases the validating side refuses.
inline std::vector<CertificateCase> refused_cases()
{
  std::vector<CertificateCase> cases;
  for (auto certificateCase : all_cases())
  {
    if (!expected_outcome(certificateCase).accepted)
      cases.push_back(certificateCase);
  }
  return cases;
}

/// The options the validating side's store uses: revocation offline ON (owner decision), plus the
/// suppression bit for the suppressed case.
inline TrustListValidationOptions validation_options_for(CertificateCase certificateCase)
{
  using Bit = TrustListValidationOptions::Bit;
  if (certificateCase == CertificateCase::ExpiredSuppressed)
    return TrustListValidationOptions{Bit::CheckRevocationStatusOffline, Bit::SuppressCertificateExpired};
  return TrustListValidationOptions{Bit::CheckRevocationStatusOffline};
}

// ====================== PKI ======================

/// The issuer fault of an UpdateCertificate issuer chain (C9; OPC 10000-12 7.10.4 "all normal integrity
/// checks on the Certificate and all of the issuer Certificates").
enum class IssuerFault
{
  Expired,  ///< The issuing CA is past notAfter.
  NotTheSigner,  ///< The chain sent names a CA that did not sign the leaf.
  NotCa,  ///< The issuing certificate has cA FALSE.
  PolicyViolation,  ///< The issuing CA's key violates the endpoint policy.
  TrailingBytes  ///< The issuer's DER is followed by bytes that are not a certificate.
};

/// The permitted signature algorithm of a signer holding a key of @p algorithm.
inline CertificateSignatureAlgorithm signature_for_signer(CertificateKeyAlgorithm algorithm)
{
  switch (algorithm)
  {
  case CertificateKeyAlgorithm::EccNistP256:
  case CertificateKeyAlgorithm::EccBrainpoolP256r1:
    return CertificateSignatureAlgorithm::EcDsaSha2256;
  case CertificateKeyAlgorithm::EccNistP384:
  case CertificateKeyAlgorithm::EccBrainpoolP384r1:
    return CertificateSignatureAlgorithm::EcDsaSha2384;
  case CertificateKeyAlgorithm::EccCurve25519:
    return CertificateSignatureAlgorithm::PureEdDsa25519;
  case CertificateKeyAlgorithm::EccCurve448:
    return CertificateSignatureAlgorithm::PureEdDsa448;
  default:
    return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  }
}

enum class Role
{
  Client,
  Server,
  User
};

/// The role as a word, for a certificate commonName (the ApplicationUri is in the subjectAltName; RFC 5280
/// bounds a commonName to 64 characters).
inline std::string role_name(Role role)
{
  switch (role)
  {
  case Role::Client:
    return "Client";
  case Role::Server:
    return "Server";
  case Role::User:
    return "User";
  }
  return "Unknown";
}

inline const char* uri_of(Role role)
{
  switch (role)
  {
  case Role::Client:
    return clientUri;
  case Role::Server:
    return serverUri;
  case Role::User:
    return userUri;
  }
  return clientUri;
}

/// A peer's own certificate and the issuer certificates it presents with it.
struct LeafMaterial
{
  CertificatePointer certificate;
  KeysPointer keys;
  std::vector<CertificatePointer> presentedIssuers;
};

/// What the validating side holds: trusted certificates, trusted CRLs and issuer CRLs.
struct TrustMaterial
{
  std::vector<CertificatePointer> trusted;
  std::vector<CrlPointer> trustedCrls;
  std::vector<CrlPointer> issuerCrls;
};

/// Per-family PKI built on first use and cached for the process (see shared_pki). Not thread-safe.
class MatrixPki
{
public:
  explicit MatrixPki(std::shared_ptr<const Crypto> crypto) : mCrypto(std::move(crypto))
  {}

  const std::shared_ptr<const Crypto>& crypto() const
  {
    return mCrypto;
  }

  /// Whether this OpenSSL build generates keys on the family's curve and on its wrong curve.
  /// The peer's own certificate for @p certificateCase under @p policy.
  const LeafMaterial& leaf(SecurityPolicyId policy, CertificateCase certificateCase, Role role)
  {
    const auto key =
      std::make_tuple(static_cast<int>(policy), static_cast<int>(certificateCase), static_cast<int>(role));
    auto found = mLeaves.find(key);
    if (found != mLeaves.end())
      return found->second;
    return mLeaves.emplace(key, build_leaf(policy, certificateCase, role)).first->second;
  }

  /// The trust material a validator of the family's certificates holds.
  TrustMaterial trust_material(Family family)
  {
    auto& material = family_material(family);
    TrustMaterial trust{.trusted = {material.root},
      .trustedCrls = {material.rootCrl},
      .issuerCrls = {material.intermediateCrl}};
    if (material.altRoot)
    {
      trust.trusted.push_back(material.altRoot);
      trust.trustedCrls.push_back(material.altRootCrl);
    }
    return trust;
  }

  /// The family's CRLs with nothing trusted: what a validator needs to check revocation (on by default,
  /// owner decision 22.1) for a chain it is told to accept for this connection only.
  TrustMaterial revocation_material(Family family)
  {
    auto& material = family_material(family);
    return TrustMaterial{
      .trusted = {}, .trustedCrls = {}, .issuerCrls = {material.rootCrl, material.intermediateCrl}};
  }

  CertificatePointer root(Family family)
  {
    return family_material(family).root;
  }

  CertificatePointer intermediate(Family family)
  {
    return family_material(family).intermediate;
  }

  CrlPointer root_crl(Family family)
  {
    return family_material(family).rootCrl;
  }

  /// A CRL from the family root that revokes @p certificate (built on demand, for the I3 CRL push).
  CrlPointer root_crl_revoking(Family family, const X509Certificate& certificate)
  {
    auto& material = family_material(family);
    auto serials = material.revokedSerials;
    serials.push_back(certificate.serial_number());
    return TestPki{mCrypto}.create_crl(material.root, material.rootKeys, std::move(serials));
  }

  /// A leaf issued by the family root for @p uri with the family's permitted algorithms.
  LeafMaterial issue_leaf(Family family, const std::string& commonName, const std::string& uri)
  {
    auto& material = family_material(family);
    auto certificate = make_certificate(material.root,
      material.rootKeys,
      material.leafKeys,
      signature_of(family),
      commonName,
      uri,
      valid_from(),
      valid_to(),
      key_algorithm_of(family));
    return LeafMaterial{
      .certificate = std::move(certificate), .keys = material.leafKeys, .presentedIssuers = {}};
  }

  /// A self-signed leaf for @p uri on a key slot no case certificate uses.
  LeafMaterial issue_self_signed(Family family, const std::string& commonName, const std::string& uri)
  {
    const auto algorithm = key_algorithm_of(family);
    const auto keys = cached_keys(algorithm, std::nullopt, sSpareSlot);
    auto certificate = make_certificate(
      nullptr, keys, keys, signature_of(family), commonName, uri, valid_from(), valid_to(), algorithm);
    return LeafMaterial{.certificate = std::move(certificate), .keys = keys, .presentedIssuers = {}};
  }

  /// A server leaf on the family's leaf key (the key every server case certificate uses, so UpdateCertificate
  /// needs no new private key) and the issuer chain to send with it, the issuer carrying @p fault.
  /// TrailingBytes returns the valid chain: the caller appends the bytes to the issuer's DER.
  LeafMaterial leaf_with_faulty_issuer(SecurityPolicyId policy, IssuerFault fault)
  {
    const Family family = family_of(policy);
    auto& material = family_material(family);
    const auto algorithm = key_algorithm_of(family);
    const auto signature = signature_of(family);
    const std::string name = policy_name(policy) + " IssuerFault" + std::to_string(static_cast<int>(fault));
    KeysPointer issuerKeys = material.intermediateKeys;
    CertificatePointer issuer = material.intermediate;
    CertificatePointer presented = material.intermediate;
    CertificateSignatureAlgorithm leafSignature = signature;
    switch (fault)
    {
    case IssuerFault::Expired:
      issuer = make_ca(material.root,
        material.rootKeys,
        material.intermediateKeys,
        signature,
        name + " Expired CA",
        DateTime{DateTime::now().value() - std::chrono::days{60}},
        DateTime{DateTime::now().value() - std::chrono::days{30}},
        true);
      presented = issuer;
      break;
    case IssuerFault::NotTheSigner:
      // The leaf is signed by the family intermediate; the chain sent names another CA of the same root.
      presented = make_ca(material.root,
        material.rootKeys,
        cached_keys(algorithm, std::nullopt, sSpareCaSlot),
        signature,
        name + " Other CA",
        valid_from(),
        valid_to(),
        true);
      break;
    case IssuerFault::NotCa:
      // Crypto::create_certificate refuses keyCertSign with cA FALSE unless the certificate is self-signed,
      // so the issuer that is not a CA is a CA certificate signed again with cA FALSE.
      issuer = test_certificates::resign_with_ca_false(*mCrypto,
        *make_ca(material.root,
          material.rootKeys,
          material.intermediateKeys,
          signature,
          name + " Not A CA",
          valid_from(),
          valid_to(),
          true),
        *material.rootKeys);
      presented = issuer;
      break;
    case IssuerFault::PolicyViolation:
    {
      // RSA: a 512-bit issuing CA (below every RSA policy minimum); ECC/EdDSA: the issuing CA on the wrong
      // curve (the issuing CA must use the end-entity curve).
      const auto weakAlgorithm =
        family == Family::Rsa ? CertificateKeyAlgorithm::Rsa : wrong_curve_of(family);
      const std::optional<size_t> bits = family == Family::Rsa ? std::optional<size_t>{512} : std::nullopt;
      issuerKeys = cached_keys(weakAlgorithm, bits, sSpareCaSlot);
      issuer = make_ca(material.root,
        material.rootKeys,
        issuerKeys,
        signature,
        name + " Weak CA",
        valid_from(),
        valid_to(),
        true);
      presented = issuer;
      leafSignature = signature_for_signer(weakAlgorithm);
      break;
    }
    case IssuerFault::TrailingBytes:
      break;
    }
    auto certificate = make_certificate(issuer,
      issuerKeys,
      material.leafKeys,
      leafSignature,
      name,
      serverUri,
      valid_from(),
      valid_to(),
      algorithm);
    return LeafMaterial{
      .certificate = std::move(certificate), .keys = material.leafKeys, .presentedIssuers = {presented}};
  }

  /// A server leaf behind @p depth distinct CAs below the family root (each signed by the one above it), the
  /// chain sent in Part 6 6.2.6 order (the leaf's issuer first). Used to make an own chain larger than any
  /// peer's MaxSenderCertificateSize.
  LeafMaterial deep_chain_leaf(SecurityPolicyId policy, size_t depth)
  {
    const Family family = family_of(policy);
    auto& material = family_material(family);
    const auto signature = signature_of(family);
    std::vector<CertificatePointer> cas;
    CertificatePointer issuer = material.root;
    KeysPointer issuerKeys = material.rootKeys;
    for (size_t level = 0; level < depth; ++level)
    {
      issuer = make_ca(issuer,
        issuerKeys,
        material.intermediateKeys,
        signature,
        policy_name(policy) + " Deep CA " + std::to_string(level),
        valid_from(),
        valid_to(),
        true);
      issuerKeys = material.intermediateKeys;
      cas.push_back(issuer);
    }
    auto certificate = make_certificate(issuer,
      issuerKeys,
      material.leafKeys,
      signature,
      policy_name(policy) + " Deep Chain Leaf",
      serverUri,
      valid_from(),
      valid_to(),
      key_algorithm_of(family));
    std::reverse(cas.begin(), cas.end());
    return LeafMaterial{
      .certificate = std::move(certificate), .keys = material.leafKeys, .presentedIssuers = cas};
  }

private:
  static constexpr unsigned sSpareSlot = 9;  ///< issue_self_signed.
  static constexpr unsigned sSpareCaSlot = 10;  ///< leaf_with_faulty_issuer's other / weak CA.
  static constexpr unsigned sRootSlot = 0;
  static constexpr unsigned sIntermediateSlot = 1;
  static constexpr unsigned sLeafSlot = 2;
  static constexpr unsigned sSelfSignedSlot = 3;  ///< + Role: one self-signed key per role.
  static constexpr unsigned sAltRootSlot = 7;

  struct FamilyMaterial
  {
    KeysPointer rootKeys;
    CertificatePointer root;
    KeysPointer intermediateKeys;
    CertificatePointer intermediate;
    KeysPointer leafKeys;
    std::map<int, LeafMaterial> revokedLeaves;  ///< Per Role, issued before the root CRL lists them.
    std::vector<std::string> revokedSerials;
    CrlPointer rootCrl;
    CrlPointer intermediateCrl;
    KeysPointer altRootKeys;  ///< EdDSA families: an ECDSA nistP256 root the validator trusts.
    CertificatePointer altRoot;
    CrlPointer altRootCrl;
  };

  static DateTime valid_from()
  {
    return DateTime{DateTime::now().value() - std::chrono::days{1}};
  }

  static DateTime valid_to()
  {
    return DateTime{DateTime::now().value() + std::chrono::days{365}};
  }

  /// Keys come ONLY from the machine-wide test key cache (owner rule): no key generation in this fixture.
  /// @p slot selects a distinct key of the same type.
  KeysPointer cached_keys(CertificateKeyAlgorithm algorithm, std::optional<size_t> bits, unsigned slot) const
  {
    using test_keys::KeyType;
    KeyType type = KeyType::Rsa2048;
    switch (algorithm)
    {
    case CertificateKeyAlgorithm::Rsa:
    {
      const size_t rsaBits = bits.value_or(2048);
      type = rsaBits == 512 ? KeyType::Rsa512 : rsaBits == 1024 ? KeyType::Rsa1024 : KeyType::Rsa2048;
      break;
    }
    case CertificateKeyAlgorithm::EccNistP256:
      type = KeyType::P256;
      break;
    case CertificateKeyAlgorithm::EccNistP384:
      type = KeyType::P384;
      break;
    case CertificateKeyAlgorithm::EccNistP521:
      type = KeyType::P521;
      break;
    case CertificateKeyAlgorithm::EccBrainpoolP256r1:
      type = KeyType::Bp256;
      break;
    case CertificateKeyAlgorithm::EccBrainpoolP384r1:
      type = KeyType::Bp384;
      break;
    case CertificateKeyAlgorithm::EccBrainpoolP512r1:
      type = KeyType::Bp512;
      break;
    case CertificateKeyAlgorithm::EccCurve25519:
      type = KeyType::Ed25519;
      break;
    case CertificateKeyAlgorithm::EccCurve448:
      type = KeyType::Ed448;
      break;
    case CertificateKeyAlgorithm::Invalid:
      break;
    }
    return test_keys::key_pair(*mCrypto, type, slot);
  }

  std::string next_serial()
  {
    return std::to_string(++mSerial);
  }

  CertificatePointer make_ca(const CertificatePointer& issuer, const KeysPointer& issuerKeys,
    const KeysPointer& subjectKeys, CertificateSignatureAlgorithm signature, const std::string& commonName)
  {
    return make_ca(issuer, issuerKeys, subjectKeys, signature, commonName, valid_from(), valid_to(), true);
  }

  /// A CA certificate with explicit validity and cA flag (the issuer-fault chains).
  CertificatePointer make_ca(const CertificatePointer& issuer, const KeysPointer& issuerKeys,
    const KeysPointer& subjectKeys, CertificateSignatureAlgorithm signature, const std::string& commonName,
    DateTime from, DateTime to, bool ca)
  {
    Crypto::CreateCertificateConfig parameters;
    parameters.serialNumber = next_serial();
    parameters.subject.commonName = commonName;
    parameters.issuer = issuer;
    parameters.issuerKeys = issuerKeys;
    parameters.subjectKeys = subjectKeys;
    parameters.certificateSignatureAlgorithm = signature;
    parameters.from = from;
    parameters.to = to;
    parameters.basicConstraint.cA = ca;
    parameters.keyUsage.keyCertSign = true;
    parameters.keyUsage.crlSign = true;
    parameters.keyUsage.digitalSignature = true;
    return TestPki{mCrypto}.create_cert(parameters);
  }

  /// An ApplicationInstance (Table 43) or User (Table 44) end-entity certificate.
  CertificatePointer make_certificate(const CertificatePointer& issuer, const KeysPointer& issuerKeys,
    const KeysPointer& subjectKeys, CertificateSignatureAlgorithm signature, const std::string& commonName,
    const std::string& uri, DateTime from, DateTime to, CertificateKeyAlgorithm subjectAlgorithm)
  {
    Crypto::CreateCertificateConfig parameters;
    parameters.serialNumber = next_serial();
    parameters.subject.commonName = commonName;
    parameters.issuer = issuer;
    parameters.issuerKeys = issuerKeys;
    parameters.subjectKeys = subjectKeys;
    parameters.certificateSignatureAlgorithm = signature;
    parameters.from = from;
    parameters.to = to;
    parameters.keyUsage.digitalSignature = true;
    parameters.keyUsage.nonRepudiation = true;
    if (subjectAlgorithm == CertificateKeyAlgorithm::Rsa)
    {
      parameters.keyUsage.keyEncipherment = true;
      parameters.keyUsage.dataEncipherment = true;
    }
    parameters.keyUsage.serverAuth = true;
    parameters.keyUsage.clientAuth = true;
    parameters.subjectAlternateName.uris = {uri};
    parameters.subjectAlternateName.hostnames = {"localhost"};
    return TestPki{mCrypto}.create_cert(parameters);
  }

  FamilyMaterial& family_material(Family family)
  {
    auto found = mFamilies.find(family);
    if (found != mFamilies.end())
      return found->second;

    FamilyMaterial material;
    const auto algorithm = key_algorithm_of(family);
    const auto signature = signature_of(family);
    const std::string prefix =
      "CertificateValidationMatrix Family" + std::to_string(static_cast<int>(family));
    material.rootKeys = cached_keys(algorithm, std::nullopt, sRootSlot);
    material.root = make_ca(nullptr, material.rootKeys, material.rootKeys, signature, prefix + " Root");
    material.intermediateKeys = cached_keys(algorithm, std::nullopt, sIntermediateSlot);
    material.intermediate = make_ca(
      material.root, material.rootKeys, material.intermediateKeys, signature, prefix + " Intermediate");
    material.leafKeys = cached_keys(algorithm, std::nullopt, sLeafSlot);
    for (auto role : {Role::Client, Role::Server, Role::User})
    {
      auto revoked = make_certificate(material.root,
        material.rootKeys,
        material.leafKeys,
        signature,
        prefix + " Revoked " + role_name(role),
        uri_of(role),
        valid_from(),
        valid_to(),
        algorithm);
      material.revokedSerials.push_back(revoked->serial_number());
      material.revokedLeaves.emplace(static_cast<int>(role),
        LeafMaterial{.certificate = std::move(revoked), .keys = material.leafKeys, .presentedIssuers = {}});
    }
    TestPki helper{mCrypto};
    material.rootCrl = helper.create_crl(material.root, material.rootKeys, material.revokedSerials);
    material.intermediateCrl = helper.create_crl(material.intermediate, material.intermediateKeys, {});
    if (family == Family::Curve25519 || family == Family::Curve448)
    {
      material.altRootKeys = cached_keys(CertificateKeyAlgorithm::EccNistP256, std::nullopt, sAltRootSlot);
      material.altRoot = make_ca(nullptr,
        material.altRootKeys,
        material.altRootKeys,
        CertificateSignatureAlgorithm::EcDsaSha2256,
        prefix + " Ecdsa Root");
      material.altRootCrl = helper.create_crl(material.altRoot, material.altRootKeys, {});
    }
    return mFamilies.emplace(family, std::move(material)).first->second;
  }

  LeafMaterial build_leaf(SecurityPolicyId policy, CertificateCase certificateCase, Role role)
  {
    const Family family = family_of(policy);
    auto& material = family_material(family);
    const auto algorithm = key_algorithm_of(family);
    const auto signature = signature_of(family);
    const std::string uri = uri_of(role);
    // The commonName (at most 64 characters, RFC 5280 ub-common-name) names the case and the role; the
    // ApplicationUri is in the subjectAltName.
    const std::string name =
      policy_name(policy) + " " + case_name(certificateCase) + (role == Role::Server ? " Server" : " Client");
    const auto rootIssued = [&](const KeysPointer& subjectKeys,
                              CertificateSignatureAlgorithm algorithmUsed,
                              CertificateKeyAlgorithm subjectAlgorithm,
                              DateTime from,
                              DateTime to)
    {
      return LeafMaterial{.certificate = make_certificate(material.root,
                            material.rootKeys,
                            subjectKeys,
                            algorithmUsed,
                            name,
                            uri,
                            from,
                            to,
                            subjectAlgorithm),
        .keys = subjectKeys,
        .presentedIssuers = {}};
    };

    switch (certificateCase)
    {
    case CertificateCase::Valid:
      return rootIssued(material.leafKeys, signature, algorithm, valid_from(), valid_to());
    case CertificateCase::ValidWithPresentedChain:
    case CertificateCase::ChainIncomplete:
    {
      // The same certificate in both cases: the only variable is whether the intermediate is presented.
      const auto& chained = chained_leaf(family, role);
      LeafMaterial leafMaterial = chained;
      if (certificateCase == CertificateCase::ValidWithPresentedChain)
        leafMaterial.presentedIssuers = {material.intermediate};
      return leafMaterial;
    }
    case CertificateCase::Untrusted:
    {
      const auto keys = cached_keys(algorithm, std::nullopt, sSelfSignedSlot + static_cast<unsigned>(role));
      return LeafMaterial{.certificate = make_certificate(
                            nullptr, keys, keys, signature, name, uri, valid_from(), valid_to(), algorithm),
        .keys = keys,
        .presentedIssuers = {}};
    }
    case CertificateCase::Expired:
    case CertificateCase::ExpiredSuppressed:
      return rootIssued(material.leafKeys,
        signature,
        algorithm,
        DateTime{DateTime::now().value() - std::chrono::days{60}},
        DateTime{DateTime::now().value() - std::chrono::days{30}});
    case CertificateCase::Revoked:
      return material.revokedLeaves.at(static_cast<int>(role));
    case CertificateCase::PolicyKeyLength:
    {
      if (family == Family::Rsa)
      {
        // Below the minimum: 1024-2048 for Basic128Rsa15/Basic256, 2048-4096 for the SHA-256 policies.
        const size_t bits = is_rsa_min_policy(policy) ? 512 : 1024;
        return rootIssued(cached_keys(CertificateKeyAlgorithm::Rsa, bits, sLeafSlot),
          signature,
          CertificateKeyAlgorithm::Rsa,
          valid_from(),
          valid_to());
      }
      return rootIssued(cached_keys(wrong_curve_of(family), std::nullopt, sLeafSlot),
        signature,
        wrong_curve_of(family),
        valid_from(),
        valid_to());
    }
    case CertificateCase::PolicySignature:
    {
      switch (family)
      {
      case Family::Rsa:
        // SHA-1 is not permitted by the SHA-256 policies; RSA-PSS is permitted by neither family.
        return rootIssued(material.leafKeys,
          is_rsa_min_policy(policy) ? CertificateSignatureAlgorithm::RsaPssSha2256
                                    : CertificateSignatureAlgorithm::RsaPkcs15Sha1,
          algorithm,
          valid_from(),
          valid_to());
      case Family::NistP256:
      case Family::BrainpoolP256r1:
        // A 256-bit signer must use SHA-256.
        return rootIssued(material.leafKeys,
          CertificateSignatureAlgorithm::EcDsaSha2384,
          algorithm,
          valid_from(),
          valid_to());
      case Family::NistP384:
      case Family::BrainpoolP384r1:
        // A 384-bit signer must use SHA-384.
        return rootIssued(material.leafKeys,
          CertificateSignatureAlgorithm::EcDsaSha2256,
          algorithm,
          valid_from(),
          valid_to());
      case Family::Curve25519:
      case Family::Curve448:
        // An EdDSA leaf signed with ECDSA by a trusted nistP256 root: neither PureEdDSA nor the policy's
        // curve.
        return LeafMaterial{.certificate = make_certificate(material.altRoot,
                              material.altRootKeys,
                              material.leafKeys,
                              CertificateSignatureAlgorithm::EcDsaSha2256,
                              name,
                              uri,
                              valid_from(),
                              valid_to(),
                              algorithm),
          .keys = material.leafKeys,
          .presentedIssuers = {}};
      }
      break;
    }
    }
    return rootIssued(material.leafKeys, signature, algorithm, valid_from(), valid_to());
  }

  const LeafMaterial& chained_leaf(Family family, Role role)
  {
    const auto key = std::make_pair(static_cast<int>(family), static_cast<int>(role));
    auto found = mChainedLeaves.find(key);
    if (found != mChainedLeaves.end())
      return found->second;
    auto& material = family_material(family);
    auto certificate = make_certificate(material.intermediate,
      material.intermediateKeys,
      material.leafKeys,
      signature_of(family),
      "Chained " + role_name(role) + " Family" + std::to_string(static_cast<int>(family)),
      uri_of(role),
      valid_from(),
      valid_to(),
      key_algorithm_of(family));
    return mChainedLeaves
      .emplace(key,
        LeafMaterial{
          .certificate = std::move(certificate), .keys = material.leafKeys, .presentedIssuers = {}})
      .first->second;
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::map<Family, FamilyMaterial> mFamilies;
  std::map<std::tuple<int, int, int>, LeafMaterial> mLeaves;
  std::map<std::pair<int, int>, LeafMaterial> mChainedLeaves;
  uint64_t mSerial{static_cast<uint64_t>(DateTime::now().value().time_since_epoch().count())};
};

// ====================== Stores ======================

/// A file store holding @p own as its application certificate (with its presented chain) and @p trust.
inline std::shared_ptr<CertificateStore> make_store(const std::filesystem::path& directory,
  const boost::asio::any_io_executor& executor, const std::shared_ptr<const Crypto>& crypto,
  TrustListValidationOptions options, const TrustMaterial& trust, const LeafMaterial* own,
  CertificateType type)
{
  std::filesystem::create_directories(directory);
  auto store = CertificateStoreFiles::create(
    executor, crypto, {.trustListPath = directory, .validationOptions = options});
  if (own != nullptr)
  {
    CertificateStore::ApplicationCertificate applicationCertificate;
    applicationCertificate.certificateType = type;
    applicationCertificate.certificate = own->certificate;
    applicationCertificate.keys = own->keys;
    applicationCertificate.issuerCertificates = own->presentedIssuers;  // ASSUMED API (see file comment).
    store->add_to_application_certificates_sync(applicationCertificate);
  }
  for (const auto& certificate : trust.trusted)
    store->add_to_trusted_certificates_sync(certificate);
  for (const auto& crl : trust.trustedCrls)
    store->add_to_trusted_crls_sync(crl);
  for (const auto& crl : trust.issuerCrls)
    store->add_to_issuer_crls_sync(crl);
  return store;
}

/// Whether @p store's Rejected list holds @p certificate (compared by DER).
inline bool rejected_store_contains(CertificateStore& store, const X509Certificate& certificate)
{
  auto rejected = store.try_get_rejected_certificates_sync();
  if (rejected.is_bad())
    return false;
  const auto der = certificate.der_encoding();
  return std::any_of(rejected.value().begin(),
    rejected.value().end(),
    [&](const CertificatePointer& entry) { return entry && entry->der_encoding() == der; });
}

/// Whether @p candidate is @p certificate (compared by DER).
inline bool same_certificate(const CertificatePointer& candidate, const X509Certificate& certificate)
{
  return candidate && candidate->der_encoding() == certificate.der_encoding();
}

/// The hexadecimal SHA-1 thumbprint CertificateStore::remove_from_trusted_certificates_sync takes.
inline std::string thumbprint_hex(const X509Certificate& certificate)
{
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string text;
  for (const uint8_t value : certificate.thumbprint())
  {
    text.push_back(digits[value >> 4]);
    text.push_back(digits[value & 0x0F]);
  }
  return text;
}

/// The certificate field an application sends for @p material: the leaf DER followed by each issuer's DER in
/// order (OPC 10000-6 6.2.6).
inline ByteString chain_der(const LeafMaterial& material)
{
  const auto leaf = material.certificate->der_encoding();
  std::vector<uint8_t> bytes(leaf.begin(), leaf.end());
  for (const auto& issuer : material.presentedIssuers)
  {
    const auto der = issuer->der_encoding();
    bytes.insert(bytes.end(), der.begin(), der.end());
  }
  return ByteString{std::move(bytes)};
}

// ====================== Server-side recorders ======================

/// Records the certificate hooks of ServerObserver in their decision-27 form: each call carries a
/// server::CertificateEventInfo with the presented certificate.
class CertificateHookRecorder : public server::ServerObserver
{
public:
  void on_certificate_rejected(const server::CertificateEventInfo& info) override
  {
    std::lock_guard lock(mMutex);
    mRejected.push_back(info);
  }

  void on_certificate_error_suppressed(const server::CertificateEventInfo& info) override
  {
    std::lock_guard lock(mMutex);
    mSuppressed.push_back(info);
  }

  /// The Table 106 code of every rejection, in order.
  std::vector<StatusCode> rejected() const
  {
    std::lock_guard lock(mMutex);
    std::vector<StatusCode> codes;
    for (const auto& info : mRejected)
      codes.push_back(info.status);
    return codes;
  }

  std::vector<server::CertificateEventInfo> rejected_events() const
  {
    std::lock_guard lock(mMutex);
    return mRejected;
  }

  std::vector<server::CertificateEventInfo> suppressed() const
  {
    std::lock_guard lock(mMutex);
    return mSuppressed;
  }

  /// Whether a rejection reported @p status for exactly @p certificate.
  bool rejected_with(StatusCode status, const X509Certificate& certificate) const
  {
    std::lock_guard lock(mMutex);
    return std::any_of(mRejected.begin(),
      mRejected.end(),
      [&](const server::CertificateEventInfo& info)
      { return info.status == status && same_certificate(info.certificate, certificate); });
  }

  /// How many suppressed-error reports named @p status for exactly @p certificate.
  size_t suppressed_count(StatusCode status, const X509Certificate& certificate) const
  {
    std::lock_guard lock(mMutex);
    return static_cast<size_t>(std::count_if(mSuppressed.begin(),
      mSuppressed.end(),
      [&](const server::CertificateEventInfo& info)
      { return info.status == status && same_certificate(info.certificate, certificate); }));
  }

  void clear()
  {
    std::lock_guard lock(mMutex);
    mRejected.clear();
    mSuppressed.clear();
  }

private:
  mutable std::mutex mMutex;
  std::vector<server::CertificateEventInfo> mRejected;
  std::vector<server::CertificateEventInfo> mSuppressed;
};

/// Counts authenticator calls; maps every identity it is asked about (the session validates the X509 user
/// certificate BEFORE the authenticator, approved item 8, so a refused certificate never reaches it). It also
/// serves the UserName token offered beside a secured X509 token on a None channel (C8).
class CountingX509Authenticator : public server::UserAuthenticator
{
public:
  void authenticate_async(server::AuthnRequest request, server::AuthnComplete completion) noexcept override
  {
    mCalls.fetch_add(1);
    completion(server::make_authn_success(server::UserIdentity{
      .userId = "x509-user", .displayName = "X509 User", .kind = request.identity.kind}));
  }

  int calls() const
  {
    return mCalls.load();
  }

private:
  std::atomic<int> mCalls{0};
};

/// The content of one AuditCertificateEventType subtype event (OPC 10000-5 6.4.12 / 6.4.13).
struct CertificateAuditRecord
{
  NodeId type;
  ByteString certificate;  ///< The mandatory Certificate property.
  std::string invalidHostname;  ///< DataMismatch only.
  std::string invalidUri;  ///< DataMismatch only.
};

/// Records the type of every event the server emits (Server::set_event_listener), audit events included, and
/// the content of every certificate audit event.
class EventTypeRecorder
{
public:
  std::function<void(const BaseEvent&)> listener()
  {
    return [this](const BaseEvent& event)
    {
      std::lock_guard lock(mMutex);
      mTypes.push_back(event.eventType);
      if (const auto* audit = dynamic_cast<const AuditCertificateEventPayload*>(&event))
      {
        CertificateAuditRecord record{.type = event.eventType,
          .certificate = audit->certificate,
          .invalidHostname = {},
          .invalidUri = {}};
        if (const auto* mismatch = dynamic_cast<const AuditCertificateDataMismatchEventPayload*>(&event))
        {
          record.invalidHostname = std::string{static_cast<std::string_view>(mismatch->invalidHostname)};
          record.invalidUri = std::string{static_cast<std::string_view>(mismatch->invalidUri)};
        }
        mCertificateEvents.push_back(std::move(record));
      }
    };
  }

  /// Whether an event of @p type carried exactly @p certificate in its Certificate property.
  bool saw_certificate_event(const NodeId& type, const X509Certificate& certificate) const
  {
    std::lock_guard lock(mMutex);
    const auto der = certificate.der_encoding();
    return std::any_of(mCertificateEvents.begin(),
      mCertificateEvents.end(),
      [&](const CertificateAuditRecord& record) { return record.type == type && record.certificate == der; });
  }

  /// The first certificate audit event of @p type, if any.
  std::optional<CertificateAuditRecord> certificate_event(const NodeId& type) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& record : mCertificateEvents)
    {
      if (record.type == type)
        return record;
    }
    return std::nullopt;
  }

  bool saw(const NodeId& type) const
  {
    std::lock_guard lock(mMutex);
    return std::find(mTypes.begin(), mTypes.end(), type) != mTypes.end();
  }

  void clear()
  {
    std::lock_guard lock(mMutex);
    mTypes.clear();
    mCertificateEvents.clear();
  }

private:
  mutable std::mutex mMutex;
  std::vector<NodeId> mTypes;
  std::vector<CertificateAuditRecord> mCertificateEvents;
};

/// Records every log entry at Warning or above (the client's suppressed-error warnings, approved item 9).
class WarningRecorder : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    if (entry.level < LogLevel::Warning)
      return;
    // The message and its string fields: the SDK names the suppressed status in a structured field.
    std::string text = entry.message;
    for (const auto& field : entry.fields)
    {
      if (const auto* value = std::get_if<std::string_view>(&field.value))
      {
        text += " ";
        text += field.key;
        text += "=";
        text += *value;
      }
    }
    std::lock_guard lock(mMutex);
    mMessages.push_back(std::move(text));
  }

  bool any_contains(const std::string& text) const
  {
    std::lock_guard lock(mMutex);
    return std::any_of(mMessages.begin(),
      mMessages.end(),
      [&](const std::string& message) { return message.find(text) != std::string::npos; });
  }

  void clear()
  {
    std::lock_guard lock(mMutex);
    mMessages.clear();
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mMessages;
};

/// Polls @p predicate until it holds or the (sanitizer-scaled) deadline passes.
inline bool eventually(
  const std::function<bool()>& predicate, std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
{
  const auto deadline = std::chrono::steady_clock::now() + ua::test_utils::scaled(timeout);
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  return predicate();
}

/// Whether any link of @p detail's chain carries @p status as its inner status, or names @p text.
inline bool detail_chain_has(const std::shared_ptr<const ErrorDetail>& detail, std::optional<Status> status,
  const std::string& text = {})
{
  for (const ErrorDetail* link = detail.get(); link != nullptr; link = link->cause.get())
  {
    if (status.has_value() && link->innerStatus == StatusCode{*status}.value())
      return true;
    if (!text.empty())
    {
      if (link->summary.find(text) != std::string::npos || link->detail.find(text) != std::string::npos)
        return true;
      for (const auto& value : link->context)
      {
        if (value.value.find(text) != std::string::npos)
          return true;
      }
    }
  }
  return false;
}

// ====================== Server and client harness ======================

/// A real server with ONE secured endpoint (policy, mode), Anonymous and, optionally, an X509 user token.
class MatrixServer
{
public:
  struct Options
  {
    SecurityPolicyId policy{SecurityPolicyId::None};
    MessageSecurityMode mode{MessageSecurityMode::None};
    std::shared_ptr<CertificateStore> applicationStore;
    std::shared_ptr<CertificateStore> userTokenStore;  ///< Null: no X509 user token offered.
    std::shared_ptr<server::UserAuthenticator> x509Authenticator;  ///< Used when userTokenStore is set.
    bool auditing{true};
    /// The X509 UserTokenPolicy's own SecurityPolicy (C8: a secured token policy on a None channel). The
    /// endpoint also offers a UserName token policy ("username") under it where @ref
    /// secret_token_allowed_on_none_endpoint allows one, or where the endpoint is not None (a secured RSA
    /// endpoint still refuses a UserName policy under an EphemeralKey policy:
    /// EphemeralKeySecretWithoutKeyAgreement).
    std::optional<SecurityPolicyId> userTokenSecurityPolicy;
    bool localDiscoveryServer{false};  ///< Serve as a Local Discovery Server (LDS registration rows).
    /// When set, the endpoint also offers a UserName token policy ("username-secret") that this
    /// authenticator decides, naming @ref userNameSecurityPolicy (the endpoint's policy when unset).
    std::shared_ptr<server::UserAuthenticator> userNameAuthenticator;
    std::optional<SecurityPolicyId> userNameSecurityPolicy;
    /// Further token policies the endpoint offers, after the ones above. An X509 one is decided by
    /// @ref x509Authenticator, which is registered only with a @ref userTokenStore.
    std::vector<UserTokenPolicy> extraTokenPolicies;
  };

  MatrixServer(boost::asio::thread_pool& pool, const std::shared_ptr<const Crypto>& crypto, Options options)
    : mObserver(std::make_shared<CertificateHookRecorder>()), mEvents(std::make_shared<EventTypeRecorder>())
  {
    // OPC 10000-4 7.41: an endpoint offers at most one USERNAME token policy, and a UserName token is decided
    // by the first authenticator registered for it.
    if (options.userNameAuthenticator && options.userTokenStore &&
        options.userTokenSecurityPolicy.has_value())
      throw std::logic_error(
        "fixture: userNameAuthenticator and userTokenSecurityPolicy both offer a UserName "
        "token policy");
    auto authenticator = std::make_shared<server::CompositeAuthenticator>();
    authenticator->add(server::UserTokenKind::Anonymous, std::make_shared<server::AnonymousAuthenticator>());
    if (options.userTokenStore && options.x509Authenticator)
    {
      authenticator->add(server::UserTokenKind::X509, options.x509Authenticator);
      if (options.userTokenSecurityPolicy.has_value())
        authenticator->add(server::UserTokenKind::UserName, options.x509Authenticator);
    }
    if (options.userNameAuthenticator)
      authenticator->add(server::UserTokenKind::UserName, options.userNameAuthenticator);

    server::ServerComponents components{.crypto = crypto,
      .applicationGroupCertificateStore = options.applicationStore,
      .logSink = ua::test_helpers::test_log_sink(),
      .logLevel = LogLevel::Warning};
    components.userTokenCertificateStore = options.userTokenStore;
    components.authenticator = authenticator;
    components.roleConfiguration = server::RoleConfiguration::from_well_known_grants(
      {{server::WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    auto applicationConfiguration = ua::test_utils::create_test_config();
    applicationConfiguration.application_description_part().applicationUri = serverUri;
    applicationConfiguration.allowDeprecatedSecurityPolicies = true;
    applicationConfiguration.allowInsecureEndpoints = options.policy == SecurityPolicyId::None;
    applicationConfiguration.stack_limits().secureChannelMinimumLifetime = std::chrono::milliseconds{1000};
    server::ServerConfig serverConfiguration;
    serverConfiguration.connectionThrottling.enabled = false;
    serverConfiguration.auditingEnabled = options.auditing;
    serverConfiguration.localDiscoveryServer.enabled = options.localDiscoveryServer;
    serverConfiguration.authnTimeout = ua::test_utils::scaled(server::ServerConfig{}.authnTimeout);
    server::CreateConfig createConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(applicationConfiguration),
      .server = std::move(serverConfiguration)};
    mServer.emplace(server::Server::create(pool.executor(), std::move(createConfig), std::move(components)));
    mServer->set_observer(mObserver);
    mServer->set_event_listener(mEvents->listener());

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListener = mServer->listen_sync(std::move(bind), {});

    server::ServerEndpointConfig endpoint;
    endpoint.name = policy_name(options.policy) + "_" + mode_name(options.mode);
    endpoint.messageSecurityMode = options.mode;
    endpoint.securityPolicyId = options.policy;
    {
      UserTokenPolicy anonymous;
      anonymous.policy_id() = "anonymous";
      anonymous.token_type() = UserTokenType::Anonymous;
      endpoint.userIdentityTokens.push_back(std::move(anonymous));
    }
    if (options.userTokenStore)
    {
      UserTokenPolicy x509;
      x509.policy_id() = "x509";
      x509.token_type() = UserTokenType::Certificate;
      if (options.userTokenSecurityPolicy.has_value())
        x509.security_policy_uri() = ua::utils::get_security_policy_uri(*options.userTokenSecurityPolicy);
      endpoint.userIdentityTokens.push_back(std::move(x509));
      // C8: a UserName token under the same secured policy - the token whose secret the client encrypts
      // with the server certificate (OPC 10000-4 7.41.2.2), which an X509 token is not. A None endpoint
      // offers it only under a policy 7.41 allows there.
      if (options.userTokenSecurityPolicy.has_value() &&
          (options.mode != MessageSecurityMode::None ||
            secret_token_allowed_on_none_endpoint(*options.userTokenSecurityPolicy)))
      {
        UserTokenPolicy userName;
        userName.policy_id() = "username";
        userName.token_type() = UserTokenType::UserName;
        userName.security_policy_uri() = ua::utils::get_security_policy_uri(*options.userTokenSecurityPolicy);
        endpoint.userIdentityTokens.push_back(std::move(userName));
      }
    }
    if (options.userNameAuthenticator)
    {
      UserTokenPolicy userName;
      userName.policy_id() = "username-secret";
      userName.token_type() = UserTokenType::UserName;
      if (options.userNameSecurityPolicy.has_value())
        userName.security_policy_uri() = ua::utils::get_security_policy_uri(*options.userNameSecurityPolicy);
      endpoint.userIdentityTokens.push_back(std::move(userName));
    }
    for (auto& tokenPolicy : options.extraTokenPolicies)
      endpoint.userIdentityTokens.push_back(std::move(tokenPolicy));
    // A refused endpoint throws out of this constructor, so ~MatrixServer does not run: the listening server
    // is shut down here before the exception leaves.
    try
    {
      mServer->add_endpoint(mListener, endpoint);
      // OPC 10000-12 7.8.2: the TrustList and certificate-management Methods are refused on a channel that
      // is not encrypted, so a Sign-mode server also offers the same policy with SignAndEncrypt, through
      // which an administrator makes its changes. The client under test still uses the Sign endpoint.
      if (options.mode == MessageSecurityMode::Sign)
      {
        endpoint.name = policy_name(options.policy) + "_" + mode_name(MessageSecurityMode::SignAndEncrypt);
        endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
        mServer->add_endpoint(mListener, std::move(endpoint));
      }
    }
    catch (...)
    {
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
      throw;
    }
  }

  ~MatrixServer()
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  }

  MatrixServer(const MatrixServer&) = delete;
  MatrixServer& operator=(const MatrixServer&) = delete;

  /// Starts the server; Bad_ConfigurationError when its own certificate violates the endpoint (decision F).
  VoidResult start()
  {
    auto result = mServer->try_start_sync();
    if (result.is_good())
    {
      auto urls = mServer->advertised_urls(mListener);
      if (!urls.empty())
      {
        mEndpointUrl = urls.front().str();
        const auto loopback = mEndpointUrl.find("127.0.0.1");
        if (loopback != std::string::npos)
          mEndpointUrl.replace(loopback, std::string_view{"127.0.0.1"}.size(), "localhost");
      }
    }
    return result;
  }

  server::Server& server()
  {
    return *mServer;
  }

  const std::string& endpoint_url() const
  {
    return mEndpointUrl;
  }

  const CertificateHookRecorder& hooks() const
  {
    return *mObserver;
  }

  const EventTypeRecorder& events() const
  {
    return *mEvents;
  }

  /// Per-case reset of a reused server: forgets the hooks and events recorded for earlier cases.
  void reset_observations()
  {
    mObserver->clear();
    mEvents->clear();
  }

  /// The listener the endpoints are on, for a test that adds one of its own before start().
  server::ListenerHandle listener() const
  {
    return mListener;
  }

private:
  std::shared_ptr<CertificateHookRecorder> mObserver;
  std::shared_ptr<EventTypeRecorder> mEvents;
  std::optional<server::Server> mServer;
  server::ListenerHandle mListener{};
  std::string mEndpointUrl;
};

/// A real client at the highest public tier.
inline client::Client make_matrix_client(boost::asio::thread_pool& pool,
  const std::shared_ptr<const Crypto>& crypto, std::shared_ptr<CertificateStore> store,
  std::shared_ptr<LogSink> logSink = nullptr, bool allowInsecure = false)
{
  auto applicationConfiguration = ua::test_utils::create_test_config();
  applicationConfiguration.application_description_part().applicationUri = clientUri;
  applicationConfiguration.allowDeprecatedSecurityPolicies = true;
  applicationConfiguration.allowInsecureEndpoints = allowInsecure;
  client::CreateConfig createConfig{
    .identity = ApplicationIdentity::load_default(), .application = std::move(applicationConfiguration)};
  return client::Client::create(pool.executor(),
    std::move(createConfig),
    client::ClientComponents{.crypto = crypto,
      .applicationGroupCertificateStore = std::move(store),
      .logSink = logSink ? std::move(logSink) : ua::test_helpers::test_log_sink(),
      .logLevel = LogLevel::Warning});
}

/// The ConnectionConfig of one matrix case: exact endpoint, no reconnect (a refusal must surface as-is).
/// Prints a failed connect's whole ErrorDetail chain into the test output, so a failure shows its cause and
/// not only its status. Returns @p result unchanged.
template<typename Result>
Result&& reported(Result&& result)
{
  if (result.is_bad())
  {
    std::cout << "[connect failed] " << ua::describe(result.status_code());
    if (const auto* detail = result.error_detail())
    {
      std::cout << "\n" << ua::to_string(*detail, 1);
    }
    std::cout << std::endl;
  }
  return std::forward<Result>(result);
}

inline client::ConnectionConfig matrix_connection_config(
  const std::string& endpointUrl, SecurityPolicyId policy, MessageSecurityMode mode)
{
  client::ConnectionConfig config;
  config.endpointUrl = endpointUrl;
  config.securityMode = mode;
  config.securityPolicyId = policy;
  // The client discovers the endpoint (GetEndpoints) and takes the server certificate from it, as an
  // application does; the matrix fixes only the policy and mode. ExactUrl would need the certificate
  // supplied by the test, which would bypass the path under test.
  config.endpointSelection = client::EndpointSelection::FirstMatching;
  config.reconnect = std::nullopt;
  return config;
}

// ====================== Process-wide reuse (owner efficiency rule) ======================

/// The PKI, built once per test binary.
inline MatrixPki& shared_pki()
{
  // The key cache loads its keys through the Crypto, which reads a PEM private key only with a
  // passphrase callback (the cached keys are unencrypted, so the passphrase is not used).
  static MatrixPki pki{create_default_crypto([]() { return ua::SecureString{"password"}; })};
  return pki;
}

inline uint32_t options_key(TrustListValidationOptions options)
{
  return static_cast<uint32_t>(options.value().to_ulong());
}

/// One server per channel configuration (policy x mode x validator options), reused across that
/// configuration's certificate cases, and one client per configuration where the client is not the variable.
/// The certificate case varies the PEER certificate, not the process; per-case state (hooks, events,
/// warnings) is reset by the fixtures. The suppressed-expiry case needs a validator configured with
/// SuppressCertificateExpired, which a store fixes at creation, so it has its own entry.
class MatrixCache
{
public:
  struct ServerEntry
  {
    std::shared_ptr<CertificateStore> store;
    std::unique_ptr<MatrixServer> server;
    std::shared_ptr<CertificateStore> userStore;  ///< user_token_server_for only.
    std::shared_ptr<CountingX509Authenticator> authenticator;  ///< user_token_server_for only.
  };

  struct ClientEntry
  {
    std::shared_ptr<CertificateStore> store;
    std::shared_ptr<WarningRecorder> warnings;
    std::optional<client::Client> client;
  };

  static MatrixCache& instance()
  {
    static MatrixCache cache;
    return cache;
  }

  boost::asio::thread_pool& server_pool()
  {
    return *mServerPool;
  }

  boost::asio::thread_pool& client_pool()
  {
    return *mClientPool;
  }

  /// A fresh directory for one test's own stores.
  std::filesystem::path new_directory(const std::string& prefix)
  {
    return mDirectory / (prefix + std::to_string(++mDirectoryCounter));
  }

  /// The server presenting the family's valid server certificate and trusting the family PKI.
  ServerEntry& server_for(
    SecurityPolicyId policy, MessageSecurityMode mode, TrustListValidationOptions options)
  {
    const auto key = std::make_tuple(static_cast<int>(policy), static_cast<int>(mode), options_key(options));
    auto found = mServers.find(key);
    if (found != mServers.end())
      return found->second;
    auto& pki = shared_pki();
    ServerEntry entry;
    entry.store = make_store(new_directory("server"),
      mServerPool->executor(),
      pki.crypto(),
      options,
      pki.trust_material(family_of(policy)),
      &pki.leaf(policy, CertificateCase::Valid, Role::Server),
      application_certificate_type(policy));
    entry.server = std::make_unique<MatrixServer>(*mServerPool,
      pki.crypto(),
      MatrixServer::Options{.policy = policy,
        .mode = mode,
        .applicationStore = entry.store,
        .userTokenStore = nullptr,
        .x509Authenticator = nullptr,
        .auditing = true,
        .userTokenSecurityPolicy = std::nullopt,
        .localDiscoveryServer = false});
    if (entry.server->start().is_bad())
      throw std::runtime_error("fixture: the cached matrix server did not start");
    return mServers.emplace(key, std::move(entry)).first->second;
  }

  /// As server_for, plus an X509 UserTokenPolicy ("x509") whose user-token group trusts the family PKI: the
  /// server for the X509 rows whose variable is the USER certificate.
  ServerEntry& user_token_server_for(SecurityPolicyId policy, MessageSecurityMode mode)
  {
    const auto key = std::make_pair(static_cast<int>(policy), static_cast<int>(mode));
    auto found = mUserTokenServers.find(key);
    if (found != mUserTokenServers.end())
      return found->second;
    auto& pki = shared_pki();
    const auto options = validation_options_for(CertificateCase::Valid);
    ServerEntry entry;
    entry.store = make_store(new_directory("user_token_server"),
      mServerPool->executor(),
      pki.crypto(),
      options,
      pki.trust_material(family_of(policy)),
      &pki.leaf(policy, CertificateCase::Valid, Role::Server),
      application_certificate_type(policy));
    entry.userStore = make_store(new_directory("user_token_group"),
      mServerPool->executor(),
      pki.crypto(),
      options,
      pki.trust_material(family_of(policy)),
      nullptr,
      CertificateType::Invalid);
    entry.authenticator = std::make_shared<CountingX509Authenticator>();
    entry.server = std::make_unique<MatrixServer>(*mServerPool,
      pki.crypto(),
      MatrixServer::Options{.policy = policy,
        .mode = mode,
        .applicationStore = entry.store,
        .userTokenStore = entry.userStore,
        .x509Authenticator = entry.authenticator,
        .auditing = true,
        .userTokenSecurityPolicy = std::nullopt,
        .localDiscoveryServer = false});
    if (entry.server->start().is_bad())
      throw std::runtime_error("fixture: the cached user-token server did not start");
    return mUserTokenServers.emplace(key, std::move(entry)).first->second;
  }

  /// The client presenting the family's valid client certificate and trusting the family PKI.
  ClientEntry& client_for(
    SecurityPolicyId policy, MessageSecurityMode mode, TrustListValidationOptions options)
  {
    const auto key = std::make_tuple(static_cast<int>(policy), static_cast<int>(mode), options_key(options));
    auto found = mClients.find(key);
    if (found != mClients.end())
      return found->second;
    auto& pki = shared_pki();
    ClientEntry entry;
    entry.store = make_store(new_directory("client"),
      mClientPool->executor(),
      pki.crypto(),
      options,
      pki.trust_material(family_of(policy)),
      &pki.leaf(policy, CertificateCase::Valid, Role::Client),
      application_certificate_type(policy));
    entry.warnings = std::make_shared<WarningRecorder>();
    entry.client.emplace(make_matrix_client(*mClientPool, pki.crypto(), entry.store, entry.warnings));
    return mClients.emplace(key, std::move(entry)).first->second;
  }

  /// Shuts every cached server down and releases the stores BEFORE the pools they are bound to.
  void clear()
  {
    mClients.clear();
    mServers.clear();
    mUserTokenServers.clear();
    mServerPool->join();
    mClientPool->join();
    std::error_code ignored;
    std::filesystem::remove_all(mDirectory, ignored);
  }

private:
  MatrixCache()
    : mServerPool(std::make_unique<boost::asio::thread_pool>(4)),
      mClientPool(std::make_unique<boost::asio::thread_pool>(4)),
      mDirectory(std::filesystem::temp_directory_path() /
                 ("ua_cert_matrix_" + Guid::create_and_generate().as_string()))
  {}

  std::unique_ptr<boost::asio::thread_pool> mServerPool;
  std::unique_ptr<boost::asio::thread_pool> mClientPool;
  std::filesystem::path mDirectory;
  unsigned mDirectoryCounter{0};
  std::map<std::tuple<int, int, uint32_t>, ServerEntry> mServers;
  std::map<std::tuple<int, int, uint32_t>, ClientEntry> mClients;
  std::map<std::pair<int, int>, ServerEntry> mUserTokenServers;
};

/// Tears the cache down after the last test of the binary, before static destruction.
class MatrixCacheEnvironment : public ::testing::Environment
{
public:
  void TearDown() override
  {
    MatrixCache::instance().clear();
  }
};

inline ::testing::Environment* const matrixCacheEnvironment =
  ::testing::AddGlobalTestEnvironment(new MatrixCacheEnvironment);

}  // namespace ua::test_helpers::certificate_validation

#endif  // UA_TEST_CERTIFICATE_VALIDATION_INTEGRATION_FIXTURE_H
