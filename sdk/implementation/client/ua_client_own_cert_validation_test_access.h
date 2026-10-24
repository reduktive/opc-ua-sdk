// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Test-only access to the client's own-certificate policy check. An implementation header (not
///        installed): integration tests use it to build a client that presents a certificate the client's own
///        Security Policy Check refuses, so the SERVER's handling of such a peer can be exercised.

#ifndef UA_CLIENT_OWN_CERT_VALIDATION_TEST_ACCESS_H
#define UA_CLIENT_OWN_CERT_VALIDATION_TEST_ACCESS_H

namespace ua::client::detail
{

/// Process-wide; product code never calls it.
void set_skip_own_certificate_policy_checks_for_tests(bool skip) noexcept;

/// Skips the client's own-certificate Security Policy Check (at create and at channel open) for its lifetime.
class SkipOwnCertificatePolicyChecksForTests
{
public:
  SkipOwnCertificatePolicyChecksForTests() noexcept
  {
    set_skip_own_certificate_policy_checks_for_tests(true);
  }

  ~SkipOwnCertificatePolicyChecksForTests()
  {
    set_skip_own_certificate_policy_checks_for_tests(false);
  }

  SkipOwnCertificatePolicyChecksForTests(const SkipOwnCertificatePolicyChecksForTests&) = delete;
  SkipOwnCertificatePolicyChecksForTests& operator=(const SkipOwnCertificatePolicyChecksForTests&) = delete;
};

}  // namespace ua::client::detail

#endif  // UA_CLIENT_OWN_CERT_VALIDATION_TEST_ACCESS_H
