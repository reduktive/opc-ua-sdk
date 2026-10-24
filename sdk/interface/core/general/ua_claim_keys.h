// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLAIM_KEYS_H
#define UA_CLAIM_KEYS_H

/// @file
/// @brief Published keys interpreted from an authenticated user's claim set.
/// @ingroup general

#include <string>

namespace ua
{

/// Stable claim-key vocabulary interpreted by the SDK.
///
/// Authenticators may attach deployment-specific claims in addition to these. These constants name
/// only claims consumed by SDK policy, so applications never need to duplicate a wire literal.
struct ClaimKeys
{
  ClaimKeys() = delete;

  /// Calling application's URI fallback used by Role application criteria.
  static inline const std::string applicationUri{"app:uri"};

  /// SDK-owned signal that the signed channel's client certificate is trusted.
  static inline const std::string clientCertificateTrusted{"client_cert_trusted"};

  /// Grants the full diagnostic level, bounded by the server's diagnostic policy ceiling.
  static inline const std::string diagnosticsFull{"diagnostics:full"};

  /// Grants the summary diagnostic level, bounded by the server's diagnostic policy ceiling.
  static inline const std::string diagnosticsSummary{"diagnostics:summary"};

  /// Generic authorization-service group identifier used by `IdentityCriteriaType::GroupId`.
  static inline const std::string group{"group"};

  /// Access-token restriction name used by `IdentityCriteriaType::Role`.
  static inline const std::string role{"role"};

  /// User-certificate thumbprint used by `IdentityCriteriaType::Thumbprint`.
  static inline const std::string thumbprint{"thumbprint"};

  /// User-certificate subject used by `IdentityCriteriaType::X509Subject`.
  static inline const std::string x509Subject{"x509:subject"};
};

}  // namespace ua

#endif  // UA_CLAIM_KEYS_H
