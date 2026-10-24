// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EASY_CONNECT_H
#define UA_EASY_CONNECT_H

/// @file
/// @brief Resolves an @ref ua::client::EasyConnectConfig into a ready-to-connect ConnectionConfig
///        (client design section 7.3A steps 1-4).
/// @ingroup client

#include "ua_connection_config.h"
#include "ua_discovery.h"
#include "ua_easy_connect_policy.h"
#include "ua_endpoint_description.h"

#include "ua_logger.h"
#include "ua_result.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua
{
class ByteString;
class CertificateStore;
class X509Certificate;
}  // namespace ua

namespace ua::client::detail
{

/// The public connect configuration selected by EasyConnect together with the complete unsecured
/// GetEndpoints response that must be verified against the secured CreateSession response.
///
/// Discovery evidence is deliberately not a public ConnectionConfig field: applications cannot
/// manufacture it, and the ordinary explicit-connect path remains unchanged.
struct EasyConnectResolution
{
  ua::client::ConnectionConfig config;
  std::vector<ua::EndpointDescription> discoveryEndpoints;
};

using EasyConnectResolutionResult = ua::Result<EasyConnectResolution>;
using EasyConnectResolutionCallback = std::function<void(EasyConnectResolutionResult)>;

/// The collaborators `resolve_easy_connect_async` needs, injected so the whole decision surface -
/// ranking, certificate decode, validation, and the trust-prompt exchange - is unit-testable without
/// a live Client, a real server, or a real certificate store.
struct EasyConnectDeps
{
  /// Issues the session-less GetEndpoints (normally `Discovery::get_endpoints_async`).
  std::function<void(std::string, ua::client::GetEndpointsOptions, Discovery::GetEndpointsCallback)>
    getEndpoints;

  /// Decodes the serverCertificate field advertised by GetEndpoints into the leaf followed by the issuers
  /// the server presented with it (OPC 10000-6 6.2.6; normally the one chain parser).
  std::function<ua::Result<std::vector<std::shared_ptr<const ua::X509Certificate>>>(const ua::ByteString&)>
    decodeCertificate;

  /// Resolves the client's CURRENT certificate store at validation time. May return null.
  std::function<std::shared_ptr<ua::CertificateStore>()> storeAccessor;

  /// Builds a validation interface for a decoded server certificate + endpoint URL. Mirrors
  /// @ref make_server_cert_revalidation so production wiring is a direct hand-off. Good = trusted.
  std::function<void(std::shared_ptr<const ua::X509Certificate>,
    std::vector<std::shared_ptr<const ua::X509Certificate>>, std::string,
    std::function<void(ua::VoidResult)>)>
    validate;

  ua::Logger logger;
};

/// Resolves @p policy into a connectable @ref ua::client::ConnectionConfig plus the discovery
/// evidence required by OPC 10000-4 section 5.4.1 (client design section 7.3A steps 1-5,
/// excluding the final connect).
///
/// Performs discovery, ranks the endpoints, decodes and validates the chosen server certificate,
/// runs the trust-prompt exchange on a trust-class validation failure, and finally applies
/// `policy.customize`. Deliberately stops short of connecting: the caller
/// (@ref ua::client::Client::easy_connect_async) hands the resolved config to `connect_async`, which
/// keeps every decision in this function observable in its result.
///
/// @param deps     Injected collaborators.
/// @param policy   The user's easy-connect policy.
/// @param callback Receives the resolved config and complete GetEndpoints response, or a
///                 source-tagged @ref ua::ErrorDetail naming the failing step. Invoked EXACTLY ONCE;
///                 never throws.
void resolve_easy_connect_async(EasyConnectDeps deps, ua::client::EasyConnectConfig policy,
  EasyConnectResolutionCallback callback) noexcept;

/// Whether @p status is a **trust-class** validation failure - the only class that may be escalated
/// to @ref ua::client::EasyConnectConfig::trustPrompt. Every other failure fails straight through,
/// so a malformed or expired certificate can never be waved past by a permissive prompt.
///
/// @param status The validation failure StatusCode.
/// @return True for `Bad_CertificateUntrusted` / `Bad_CertificateChainIncomplete`.
[[nodiscard]] bool is_trust_class_failure(ua::StatusCode status) noexcept;

}  // namespace ua::client::detail

#endif  // !UA_EASY_CONNECT_H
