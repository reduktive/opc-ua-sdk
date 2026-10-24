// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_cert_validator.h"

#include "ua_callback_safety.h"
#include "ua_certificate_store.h"
#include "ua_certificate_validation_paths.h"
#include "ua_to_string.h"
#include "ua_x509_certificate.h"

#include <optional>
#include <string>
#include <utility>

namespace ua::client::detail
{

void log_suppressed_certificate_errors(
  const Logger& logger, std::string_view subject, const std::vector<StatusCode>& suppressed) noexcept
{
  for (const auto& status : suppressed)
  {
    try
    {
      const std::string statusText = to_string(status);
      logger.warning({{"certificate_subject", subject}, {"status", std::string_view{statusText}}},
        "Certificate accepted with a validation error suppressed by the validation options");
    }
    catch (...)
    {
      // Logging is best-effort; a failing sink must not fail the validation path.
      ::ua::detail::ignore_expected_exception();
    }
  }
}

std::function<void(std::function<void(ua::VoidResult)>)> make_server_cert_revalidation(
  std::function<std::shared_ptr<ua::CertificateStore>()> storeAccessor,
  ua::CertificateValidationRequest request, ua::Logger logger)
{
  return [storeAccessor = std::move(storeAccessor), request = std::move(request), logger = std::move(logger)](
           std::function<void(ua::VoidResult)> verdict)
  {
    // No pinned server cert (a None channel / accept-any-trusted): nothing to re-validate, still trusted.
    if (!request.certificate)
    {
      verdict(ua::VoidResult{});
      return;
    }
    std::shared_ptr<ua::CertificateStore> store = storeAccessor ? storeAccessor() : nullptr;
    if (!store)
    {
      // Client gone or no store configured: nothing to validate against, ack Good (advisory).
      verdict(ua::VoidResult{});
      return;
    }
    // Resubmit a COPY of the stored request: the interface is long-lived and invoked once per
    // revalidation cycle, so moving the stored request out would empty it and every later cycle would
    // short-circuit to the Good no-op above (the revocation control would fail open).
    store->validate_certificate_async(request,
      [logger, certificate = request.certificate, verdict = std::move(verdict)](ua::VoidResult result)
      {
        // OPC 10000-4 section 6.1.3: errors the revalidation suppressed are reported (one warning each).
        log_suppressed_certificate_errors(
          logger, certificate->subject_common_name(), ua::detail::suppressed_certificate_errors(result));
        verdict(std::move(result));
      });
  };
}

std::function<void(std::function<void(ua::VoidResult)>)> make_connection_server_cert_revalidation(
  std::function<std::shared_ptr<ua::CertificateStore>()> storeAccessor,
  std::shared_ptr<const ValidatedServerRequest> validated, ua::CertificateValidationRequest beforeFirstOpen,
  ua::Logger logger)
{
  return [storeAccessor = std::move(storeAccessor),
           validated = std::move(validated),
           beforeFirstOpen = std::move(beforeFirstOpen),
           logger = std::move(logger)](std::function<void(ua::VoidResult)> verdict)
  {
    auto request = validated ? validated->get() : std::nullopt;
    make_server_cert_revalidation(storeAccessor, request ? std::move(*request) : beforeFirstOpen, logger)(
      std::move(verdict));
  };
}

}  // namespace ua::client::detail
