// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_CERT_VALIDATOR_H
#define UA_SERVER_CERT_VALIDATOR_H

/// @file
/// @brief Builds the server-certificate re-validation interface for a client Connection (CL-SECADMIN-004
///        immediate revalidation / CL-PULLCRT-006 / CL-RECONN-006).
/// @ingroup client

#include "ua_certificate_store.h"
#include "ua_logger.h"
#include "ua_result.h"

#include <functional>
#include <mutex>
#include <optional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ua
{
class CertificateStore;
class X509Certificate;
}  // namespace ua

namespace ua::client::detail
{

/// Logs one warning per suppressed certificate validation error (OPC 10000-4 section 6.1.3: suppressed
/// errors are still reported; a client reports them through its logger). Every client validation path
/// (OPN, CreateSession, revalidation) calls it with @ref ua::detail::suppressed_certificate_errors of
/// its Good verdict.
///
/// @param logger     The client's logger.
/// @param subject    The validated certificate's subject, for the message.
/// @param suppressed The suppressed statuses; empty logs nothing.
void log_suppressed_certificate_errors(
  const Logger& logger, std::string_view subject, const std::vector<StatusCode>& suppressed) noexcept;

/// Yields a server-cert re-validation interface (a @ref ServerCertValidator, spelled out here as
/// `std::function<void(std::function<void(ua::VoidResult)>)>` so this header need not pull in
/// `ua_connection_impl.h`) that, on demand, resubmits @p request - the request the connection validated
/// the server with - to the store returned by @p storeAccessor and delivers the verdict unchanged (Good,
/// possibly carrying suppressed faults = still trusted; Bad = no longer trusted, the Connection routes to a
/// CertRotated reconnect). It is not a validator: the store's validation runs against the CURRENT trust
/// material with the stored presented issuers, policy, endpoint URL and connection trust.
///
/// @param storeAccessor Resolves the CURRENT Client certificate store at validation time. Returns null
///                      when unavailable (Client gone / unconfigured): the verdict is Good (advisory).
/// @param request       The stored request. A null mCertificate (a None channel or an un-pinned server)
///                      makes the interface a Good no-op that never consults the store.
///
/// The returned interface invokes its verdict callback EXACTLY ONCE per call, never throws synchronously,
/// and may be called any number of times (the stored request is copied per call, never moved out).
///
/// A Good verdict that suppressed errors (owner decision 22.6) logs one warning per error through
/// @p logger (log_suppressed_certificate_errors) before the verdict is delivered.
[[nodiscard]] std::function<void(std::function<void(ua::VoidResult)>)> make_server_cert_revalidation(
  std::function<std::shared_ptr<ua::CertificateStore>()> storeAccessor,
  ua::CertificateValidationRequest request, ua::Logger logger = {});

/// The request a connection's SecureChannel validated the server certificate with at OPN (presented
/// issuers, policy, endpoint URL), recorded by the channel on each successful validation (every open and
/// reopen) and read by the connection's revalidation. Thread-safe.
class ValidatedServerRequest
{
public:
  /// Records @p request as the latest validated request.
  void set(ua::CertificateValidationRequest request)
  {
    const std::lock_guard lock{mMutex};
    mRequest = std::move(request);
  }

  /// @return The latest validated request, or nullopt before the first successful validation.
  [[nodiscard]] std::optional<ua::CertificateValidationRequest> get() const
  {
    const std::lock_guard lock{mMutex};
    return mRequest;
  }

private:
  mutable std::mutex mMutex;
  std::optional<ua::CertificateValidationRequest> mRequest;
};

/// The connection's revalidation: resubmits the request recorded in @p validated (the exact OPN request)
/// through @ref make_server_cert_revalidation, or @p beforeFirstOpen while nothing has been recorded.
///
/// @param storeAccessor   As for @ref make_server_cert_revalidation (the store the channel validates with).
/// @param validated       Filled by the channel; null behaves as never filled.
/// @param beforeFirstOpen The request built from the channel configuration.
/// @param logger          Receives a warning per suppressed error of a Good verdict.
[[nodiscard]] std::function<void(std::function<void(ua::VoidResult)>)>
  make_connection_server_cert_revalidation(
    std::function<std::shared_ptr<ua::CertificateStore>()> storeAccessor,
    std::shared_ptr<const ValidatedServerRequest> validated, ua::CertificateValidationRequest beforeFirstOpen,
    ua::Logger logger = {});

}  // namespace ua::client::detail

#endif  // UA_SERVER_CERT_VALIDATOR_H
