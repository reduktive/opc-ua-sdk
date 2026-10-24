// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientCertValidation cluster of the client integration-test matrix (the 7 `ClientCertValidation.*`
///        rows).
///
/// These rows exercise the SECURITY-CRITICAL client certificate-validation pipeline: Table-106
/// (OPC 10000-4 section 6.1.3) per-step status mapping, halt-on-first-failing-step, administrator-opt-in
/// suppression (and which steps are NEVER suppressible), and re-validation of the SERVER certificate at
/// SecureChannel RENEWAL. They run against the real in-tree secured server + PKI built by the
/// `ComplianceSecureChannel` fixture (short SecureChannel minimum lifetime, real client/server
/// `CertificateStore`), and drive the REAL validation engine - the same
/// `CryptoOpenSsl::validate_certificate_impl` the client invokes on the wire.
///
/// -------------------------------------------------------------------------------------------------
/// FORENSIC FINDINGS (where the wire actually runs the checks; file:line pinned so a future refactor
/// that moves the check cannot silently drop it):
///
///  * WHERE THE CLIENT VALIDATES THE SERVER CERT: every asymmetric (OPN) message the client decodes runs
///    `SecurityPolicy::decode_message_chunk_async` -> (MessageType::Open) ->
///    `decode_asymmetric_message_chunk_async` -> `SecurityPolicy::validate_certificate_async`
///    (ua_security_policy.cpp:1465->1467, then :1067) -> `CertificateStore::validate_certificate_async` ->
///    `CryptoOpenSsl::validate_certificate_impl` (ua_crypto_openssl.cpp:4235). The store's LIVE trust
///    material and the store-DEFAULT `TrustListValidationOptions` are used; `applicationUri` is passed as
///    `std::nullopt` and `endpointUrl` = the channel's endpoint (ua_security_policy.cpp:3077-3088).
///
///  * OPN-RENEW **DOES** RE-VALIDATE THE SERVER CERT (this was the security question). A
///    RenewSecureChannel response is an OPN (asymmetric) message, so it flows through the SAME
///    `decode_asymmetric_message_chunk_async` path and re-runs `validate_certificate_async`
///    (ua_security_policy.cpp:1465-1469) against the store's CURRENT trust material BEFORE the renewed
///    token is adopted in `handle_opn_response_async` (ua_client_secure_channel_impl.cpp:1036). A server
///    cert that becomes untrusted between the initial open and a renewal is therefore REJECTED at
///    renewal and the channel is torn down (`handle_chunk_decode_failure` sets Closed + close_transport,
///    ua_client_secure_channel_impl.cpp:718-734). `RevalidatesServerCertOnRenew` and
///    `DisconnectsOnRenewalValidationFailure` PROVE this end-to-end (remove trust between open and a
///    interface-triggered renewal -> the renewal is rejected and the channel disconnects). This is the SECURE
///    behaviour; the flip-guard (EXPECT the channel to disconnect) RED-pins the bug were revalidation
///    ever skipped at renewal (a revoked/untrusted server cert silently kept in service).
///
///  * A SEPARATE, ADDITIONAL revalidation mechanism exists at tier-1
///    (`CoreClientImpl::revalidate_connections_async` -> `ConnectionImpl::revalidate_server_cert_async`,
///    ua_connection_impl.cpp:2141) that re-validates open Connections IMMEDIATELY when the trust
///    list/cert store changes (pull-cert driven). It is unit-covered
///    (tests/unit/client/connection/connection_cert_revalidate_tests.cpp) but the production
///    `serverCertValidator` interface is still empty on the bootstrap connect path
///    (ua_connection_impl.cpp:527-530) - i.e. IMMEDIATE (non-renewal) revalidation-on-trust-change is not
///    yet wired end-to-end. That is a COVERAGE gap, not a security hole: the renewal path above already
///    revalidates, so a trust change is caught at the next renewal. Documented, not asserted here.
///
/// -------------------------------------------------------------------------------------------------
/// SUPPRESSION AUDIT (the security bug-hunt - every `TrustListValidationOptions::Bit`,
/// ua_crypto_openssl.cpp:4235-4564):
///   SUPPRESSIBLE (admin opt-in only, narrowly scoped):
///     - SuppressCertificateExpired          -> leaf time-invalid only            (:4454-4476)
///     - SuppressIssuerCertificateExpired    -> issuer time-invalid only          (:4454-4476)
///     - SuppressRevocationStatusUnknown     -> leaf CRL-unavailable only         (:4498-4529)
///     - SuppressIssuerRevocationStatusUnknown -> issuer CRL-unavailable only     (:4498-4529)
///     - SuppressHostNameInvalid             -> HOSTNAME mismatch only            (:4419)
///   NEVER SUPPRESSIBLE (no flag guards them - a validation BYPASS if they were):
///     - chain (issuer in neither list)      -> BadCertificateChainIncomplete     (unconditional)
///     - trust (complete chain, none trusted) -> BadCertificateUntrusted          (unconditional)
///     - revocation (on a CRL)               -> BadCertificateRevoked             (:4535, unconditional)
///     - URI mismatch                        -> BadCertificateUriInvalid          (:4342-4351, unconditional)
///     - key-usage / purpose                 -> BadCertificateUseNotAllowed       (:4318-4326, :4544-4549)
///   KEY RESULT: `SuppressHostNameInvalid` is documented "host name OR ApplicationUri" in the generated
///   options header, but the engine applies it to HOSTNAME ONLY; the URI check (:4342) is UNGUARDED, so a
///   URI mismatch is never suppressed. That matches Table 106 ("URI may not be suppressed") - SECURE.
///   `DoesNotSuppressUriMismatch` pins it (flip-guard: were URI suppressible the validation would pass).
///
/// CALIBRATIONS / FIXTURE LIMITS:
///   - The Table-106 rows drive `CertificateStore::try_validate_certificate_sync` on the real client store
///     directly. That is the same engine the wire path calls (above); a full end-to-end OPN per step is
///     impossible (the fixture server presents one fixed cert), so per-step certs are allocated with the
///     fixture crypto/PKI and validated through the store - real code path, isolated stimulus.
///   - A missing issuer is the Build Certificate Chain step's fault (Bad_CertificateChainIncomplete),
///   distinct
///     from the Trust List Check's Bad_CertificateUntrusted for a complete chain nothing in which is trusted
///     (Part 4 Table 106; owner decision 21.6).
///   - `PicksUpRefreshedCrlAtRenewal`: the fixture SERVER cert is SELF-SIGNED, and self-signed certs are
///     CRL-exempt (Part 4 section 6.1.3 / Part 6 Annex E.6; ua_crypto_openssl.cpp:4500-4506), so a CRL cannot
///     revoke it end-to-end. The CRL-refresh REVALIDATION is proven at the store level on a CA-issued cert
///     (real engine); the renewal-revalidation TRIGGER itself is proven end-to-end by
///     `RevalidatesServerCertOnRenew`. A full end-to-end CRL-at-renewal needs a CA-issued server cert +
///     `CheckRevocationStatusOffline` in the store default - a fixture extension, not a product gap.
///   - `SuppressesOnlyAdministratorEnabledSteps`: the engine suppresses SILENTLY - when a soft-fail step is
///     suppressed it simply returns Good with NO audit/log record at the crypto layer
///     (ua_crypto_openssl.cpp:4475). The matrix oracle expected an audit entry; that audit belongs to a
///     higher tier (ClientObserver) that is not on this validation path. The security-required property
///     (suppression is admin opt-in, never default, never bypasses trust/revocation) IS asserted; the
///     missing audit trail is reported as an observability gap (low severity), not asserted here.

#include "certificate_validation_request_helpers.h"
#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_client_secure_channel_test_access.h"

#include "test_pki_helpers.h"

#include "ua_certificate_store_files.h"
#include "ua_crypto.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_status.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;
using ::testing::HasSubstr;

namespace
{

using CSCTA = ua::client::SecureChannelTestAccess;
using Bit = ua::TrustListValidationOptions::Bit;

// Reads the current SecureChannel token id on the channel strand (a fresh, non-zero id per accepted
// SecurityToken; it advances only after a renewal decode succeeds - see handle_opn_response_async:1036).
uint32_t read_token_id(SecureChannel& channel)
{
  return CSCTA::on_strand(channel, [](auto& guard) { return guard.channel_token_id(); });
}

enum class RenewOutcome
{
  Renewed,  ///< the token advanced - the renewal was accepted (server cert re-validated Good)
  Disconnected,  ///< the channel closed - the renewal was rejected (server cert re-validated Bad)
  TimedOutStillOpen  ///< neither within the bound (would itself be a defect: a renewal that never resolves)
};

// Triggers a token renewal through the CONTROLLABLE interface (handle_token_renewal_async - NOT a wall-clock
// timer, per the "no real 0ms/0s asio timers" rule) and waits, bounded, for the real OPN-Renew round-trip
// against the in-process server to resolve one way or the other. Because the renewal response is an OPN
// (asymmetric) message, its decode re-runs SecurityPolicy::validate_certificate_async against the store's
// CURRENT trust material before the new token is adopted - so the outcome directly reports the renewal-time
// server-cert verdict.
RenewOutcome trigger_renewal_and_wait(
  SecureChannel& channel, uint32_t oldTokenId, std::chrono::milliseconds timeout = 5s)
{
  // Return a value (not void) from the strand functor to avoid any void-return edge in on_strand.
  CSCTA::on_strand(channel,
    [](auto& guard)
    {
      guard.handle_token_renewal();
      return 0;
    });

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (!channel.is_open())
    {
      return RenewOutcome::Disconnected;
    }
    const auto token = read_token_id(channel);
    if (token != oldTokenId && token != 0)
    {
      return RenewOutcome::Renewed;
    }
    std::this_thread::sleep_for(50ms);
  }
  return RenewOutcome::TimedOutStillOpen;
}

// ---------------------------------------------------------------------------
// Fixture: secured server + PKI (short channel lifetime for renewal), plus helpers to allocate shaped certs
// and drive the REAL client-store validation engine.
// ---------------------------------------------------------------------------
class ClientCertValidation : public ComplianceSecureChannel
{
protected:
  void SetUp() override
  {
    ComplianceSecureChannel::SetUp();
    mPki.emplace(mCrypto);
  }

  std::optional<TestPki> mPki;
  int mStoreCounter{0};

  std::shared_ptr<const AsymmetricKeyPair> new_rsa_keys()
  {
    return mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  }

  // A fresh, empty file-backed store of the SAME concrete type the client uses (CertificateStoreFiles),
  // under a unique root. The caller populates trust/CRL material and validates through it.
  std::shared_ptr<CertificateStore> new_store()
  {
    auto root = mTempDir / ("cv_store_" + std::to_string(mStoreCounter++));
    std::filesystem::create_directories(root);
    return CertificateStoreFiles::create(mClientThreadPool.executor(), mCrypto, {.trustListPath = root});
  }

  // A CA-issued leaf (server-like) with caller-controlled validity/SAN. digitalSignature is set by the
  // helper (a conformant application-instance leaf).
  std::shared_ptr<const X509Certificate> mint_leaf(const std::shared_ptr<const AsymmetricKeyPair>& caKeys,
    const std::shared_ptr<const X509Certificate>& caCert, DateTime from, DateTime to,
    std::vector<std::string> uris = {}, std::vector<std::string> hostnames = {})
  {
    return mPki->create_leaf_cert(
      new_rsa_keys(), caKeys, caCert, from, to, std::move(uris), std::move(hostnames), "CV Leaf");
  }

  static std::string detail_of(const VoidResult& result)
  {
    return result.shared_detail() ? ua::to_string(*result.shared_detail()) : std::string{};
  }

  // Opens a real SignAndEncrypt/Basic256Sha256 channel with a LONG requested lifetime so the auto-renew
  // timer never fires during the test - renewal is driven deterministically via the interface instead.
  SecureChannel open_secured_long_lifetime()
  {
    return open_channel_short_lifetime(
      MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 60000ms);
  }
};

}  // namespace

// ===========================================================================
// Row 1 - UsesTable106StatusCodes
// Each failing validation step surfaces its EXACT Table-106 Bad_Certificate* status, carried on a
// source-tagged ErrorDetail from the "CertificateValidation" stage; the statuses are pairwise distinct
// (Table 106: "each validation step has a unique error status"). A generic/collapsed code fails the test.
// [neg: per-step status-code mapping]
// @verifies CL-SECADMIN-003
// @verifies CL-SECADMIN-001
// @verifies CL-SECADMIN-002
// ===========================================================================
// @relation(CL-SECADMIN-001, CL-SECADMIN-002, CL-SECADMIN-003, scope=function)
TEST_F(ClientCertValidation, UsesTable106StatusCodes)
{
  const auto now = DateTime::now();
  const auto past = DateTime{now.value() - std::chrono::days{1}};
  const auto future = DateTime{now.value() + std::chrono::days{30}};

  std::vector<Status> observed;

  // -- chain incomplete: leaf issued by a CA that is in neither the store's trust nor its issuer set -----
  {
    SCOPED_TRACE("chain step -> Bad_CertificateChainIncomplete");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV Untrusted CA", "9001");
    auto leaf = mint_leaf(caKeys, ca, past, future);
    auto store = new_store();  // deliberately holds `ca` in neither list
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateChainIncomplete);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- untrusted: a self-signed certificate is its own complete chain, and nothing in it is trusted -------
  {
    SCOPED_TRACE("trust step -> Bad_CertificateUntrusted");
    auto selfSignedKeys = new_rsa_keys();
    auto selfSigned = mPki->create_root_ca(selfSignedKeys, "CV Unknown Self-Signed", "9201");
    auto store = new_store();  // trusts nothing
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(selfSigned, {}, std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUntrusted);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- time invalid: leaf issued by a TRUSTED CA but expired --------------------------------------------
  {
    SCOPED_TRACE("validity step -> Bad_CertificateTimeInvalid");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV Time CA", "9002");
    auto leaf = mint_leaf(caKeys,
      ca,
      DateTime{now.value() - std::chrono::days{30}},
      DateTime{now.value() - std::chrono::days{1}});
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateTimeInvalid);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateTimeInvalid"));
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- revoked: trusted CA, in-date leaf, on the CRL, with offline revocation checking ------------------
  {
    SCOPED_TRACE("revocation step -> Bad_CertificateRevoked");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV Revoked CA", "9003");
    auto leaf = mint_leaf(caKeys, ca, past, future);
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    store->add_to_trusted_crls_sync(mPki->create_crl(ca, caKeys, {leaf->serial_number()}));
    TrustListValidationOptions crlCheck{Bit::CheckRevocationStatusOffline};
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, crlCheck));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateRevoked);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- revocation unknown: trusted CA, in-date leaf, revocation checking on but NO CRL present ----------
  {
    SCOPED_TRACE("find-revocation step -> Bad_CertificateRevocationUnknown");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV RevUnknown CA", "9004");
    auto leaf = mint_leaf(caKeys, ca, past, future);
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    TrustListValidationOptions crlCheck{Bit::CheckRevocationStatusOffline};
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, crlCheck));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateRevocationUnknown);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateRevocationUnknown"));
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- URI mismatch: trusted CA, in-date leaf, wrong SAN URI vs the expected applicationUri -------------
  {
    SCOPED_TRACE("URI step -> Bad_CertificateUriInvalid");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV Uri CA", "9005");
    auto leaf = mint_leaf(caKeys, ca, past, future, {"urn:cert:wrong-uri"});
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(
      leaf, {}, std::nullopt, /*applicationUri=*/"urn:expected:app", /*endpointUrl=*/std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUriInvalid);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateUriMismatch"));
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- hostname mismatch: trusted CA, in-date leaf, wrong SAN hostname vs the endpoint host -------------
  {
    SCOPED_TRACE("hostname step -> Bad_CertificateHostNameInvalid");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV Host CA", "9006");
    auto leaf = mint_leaf(caKeys, ca, past, future, {}, {"wronghost"});
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(
      leaf, {}, std::nullopt, /*applicationUri=*/std::nullopt, /*endpointUrl=*/"opc.tcp://righthost:4840"));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateHostNameInvalid);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateHostNameMismatch"));
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // -- usage: trusted CA, in-date leaf that lacks digitalSignature and is not a CA --------------------
  {
    SCOPED_TRACE("usage step -> Bad_CertificateUseNotAllowed");
    auto caKeys = new_rsa_keys();
    auto ca = mPki->create_root_ca(caKeys, "CV Usage CA", "9007");
    Crypto::CreateCertificateConfig params;
    params.subjectKeys = new_rsa_keys();
    params.issuerKeys = caKeys;
    params.issuer = ca;
    params.subject.commonName = "CV No DigSig Leaf";
    params.serialNumber = "9107";
    params.keyUsage.digitalSignature = false;  // the deliberate defect
    params.keyUsage.keyEncipherment = true;
    params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    params.from = past;
    params.to = future;
    auto leaf = mPki->create_cert(params);
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUseNotAllowed);
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateValidation"));
    observed.push_back(result.status_code().as_status());
  }

  // The seven step statuses must be pairwise distinct (Table 106: unique error status per step). A regression
  // that collapsed steps onto one generic code (e.g. Bad_SecurityChecksFailed) would shrink this set.
  std::vector<Status> distinct = observed;
  std::sort(distinct.begin(), distinct.end());
  distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());
  EXPECT_EQ(distinct.size(), observed.size()) << "each Table-106 step must report a unique status";
}

// ===========================================================================
// Row 2 - StopsAtFirstFailingStep
// A cert failing TWO Table-106 steps at once (an EARLIER trust/chain step AND a LATER validity step) must
// report the EARLIER step's status and never the later one. The control (SAME expired leaf, but issued by a
// TRUSTED CA) proves the validity step DOES fire once reachable - so surfacing the trust status for the
// untrusted variant can only mean the engine halted before ever reaching validity.
// [neg: two simultaneous failures; the later error must never surface]
// @verifies CL-SECADMIN-003
// ===========================================================================
// @relation(CL-SECADMIN-003, scope=function)
TEST_F(ClientCertValidation, StopsAtFirstFailingStep)
{
  const auto now = DateTime::now();
  const auto expiredFrom = DateTime{now.value() - std::chrono::days{30}};
  const auto expiredTo = DateTime{now.value() - std::chrono::days{1}};

  auto caKeys = new_rsa_keys();
  auto ca = mPki->create_root_ca(caKeys, "CV FirstStep CA", "9008");

  // Control: expired leaf under a TRUSTED issuer -> the trust step passes, so the LATER validity step fires.
  {
    auto expiredTrusted = mint_leaf(caKeys, ca, expiredFrom, expiredTo);
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result = store->try_validate_certificate_sync(
      ua::test::make_validation_request(expiredTrusted, {}, std::nullopt));
    ASSERT_EQ(result.status_code().as_status(), Status::BadCertificateTimeInvalid)
      << "control: the validity step must fire when the trust step is satisfied";
  }

  // Two-fault: the SAME expiry, but the issuing CA is in neither list -> chain AND validity both fail.
  {
    auto expiredUntrusted = mint_leaf(caKeys, ca, expiredFrom, expiredTo);
    auto store = new_store();  // deliberately holds `ca` in neither list
    auto result = store->try_validate_certificate_sync(
      ua::test::make_validation_request(expiredUntrusted, {}, std::nullopt));
    // The earlier chain step wins; the later validity error must NEVER be surfaced.
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateChainIncomplete)
      << "the earlier failing step (chain) must be reported";
    EXPECT_NE(result.status_code().as_status(), Status::BadCertificateTimeInvalid)
      << "the later failing step (validity) must never surface - validation halts on first";
  }
}

// ===========================================================================
// Row 3 - SuppressesOnlyAdministratorEnabledSteps
// A soft-fail step (expired cert) is suppressed ONLY when the administrator explicitly enabled the matching
// bit, and NEVER by default. Crucially, suppression is narrowly scoped: it must NEVER bypass the hard
// trust/revocation steps - with EVERY suppression bit set an untrusted cert still fails Untrusted and a
// revoked cert still fails Revoked. (Over-suppression here would be a validation bypass.)
// [neg: opt-in suppression honoured; hard steps never suppressed]
// @verifies CL-SECADMIN-003
// ===========================================================================
// @relation(CL-SECADMIN-003, scope=function)
TEST_F(ClientCertValidation, SuppressesOnlyAdministratorEnabledSteps)
{
  const auto now = DateTime::now();
  const auto past = DateTime{now.value() - std::chrono::days{1}};
  const auto future = DateTime{now.value() + std::chrono::days{30}};
  const auto expiredFrom = DateTime{now.value() - std::chrono::days{30}};
  const auto expiredTo = DateTime{now.value() - std::chrono::days{1}};

  auto caKeys = new_rsa_keys();
  auto ca = mPki->create_root_ca(caKeys, "CV Suppress CA", "9009");
  auto expiredLeaf = mint_leaf(caKeys, ca, expiredFrom, expiredTo);

  // NOT suppressed by default: a fresh store default (no bits) rejects the expired cert.
  {
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(expiredLeaf, {}, std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateTimeInvalid)
      << "expiry must NOT be suppressed unless the administrator enabled it";
  }

  // Suppressed only when the administrator sets the store default (the OPN path uses the store default).
  {
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    store->set_validation_options(TrustListValidationOptions{Bit::SuppressCertificateExpired});
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(expiredLeaf, {}, std::nullopt));
    EXPECT_THAT(result, Good()) << "admin-enabled SuppressCertificateExpired must open the expired cert";
  }

  // Assemble EVERY suppression bit - the broadest possible admin over-configuration.
  TrustListValidationOptions allSuppress;
  allSuppress.set(Bit::SuppressCertificateExpired);
  allSuppress.set(Bit::SuppressHostNameInvalid);
  allSuppress.set(Bit::SuppressRevocationStatusUnknown);
  allSuppress.set(Bit::SuppressIssuerCertificateExpired);
  allSuppress.set(Bit::SuppressIssuerRevocationStatusUnknown);

  // Hard step 1 - CHAIN BUILDING is never suppressible: a leaf whose issuer is unknown still fails even with
  // all bits set.
  {
    auto untrustedCaKeys = new_rsa_keys();
    auto untrustedCa = mPki->create_root_ca(untrustedCaKeys, "CV Untrusted-AllSuppress CA", "9109");
    auto leaf = mint_leaf(untrustedCaKeys, untrustedCa, past, future);
    auto store = new_store();  // holds the issuer in neither list
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, allSuppress));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateChainIncomplete)
      << "chain building must NEVER be suppressed - a suppressed chain check would be a validation bypass";
  }

  // Hard step 1b - TRUST is never suppressible: an untrusted self-signed cert still fails with all bits set.
  {
    auto selfSignedKeys = new_rsa_keys();
    auto selfSigned = mPki->create_root_ca(selfSignedKeys, "CV Unknown Self-Signed-AllSuppress", "9202");
    auto store = new_store();  // trusts nothing
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(selfSigned, {}, allSuppress));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUntrusted)
      << "trust must NEVER be suppressed - a suppressed trust check would be a validation bypass";
  }

  // Hard step 2 - REVOCATION is never suppressible: a revoked cert still fails even with all bits set.
  {
    auto revCaKeys = new_rsa_keys();
    auto revCa = mPki->create_root_ca(revCaKeys, "CV Revoked-AllSuppress CA", "9209");
    auto leaf = mint_leaf(revCaKeys, revCa, past, future);
    auto store = new_store();
    store->add_to_trusted_certificates_sync(revCa);
    store->add_to_trusted_crls_sync(mPki->create_crl(revCa, revCaKeys, {leaf->serial_number()}));
    TrustListValidationOptions allSuppressWithCrl = allSuppress;
    allSuppressWithCrl.set(Bit::CheckRevocationStatusOffline);
    auto result =
      store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, allSuppressWithCrl));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateRevoked)
      << "revocation must NEVER be suppressed - a suppressed revocation check would be a validation bypass";
  }
}

// @relation(AC-SVR-SECADMIN-008-URI-MISMATCH-NOT-SUPPRESSIBLE, scope=function)

// ===========================================================================
// Row 4 - DoesNotSuppressUriMismatch
// A URI mismatch must fail Bad_CertificateUriInvalid even with SuppressHostNameInvalid configured (Table 106
// marks URI "may not be suppressed"). Strengthened: with BOTH the URI and the hostname wrong AND
// SuppressHostNameInvalid set, the URI status still surfaces - the (unsuppressible) URI check runs before
// the (suppressed) hostname check.
// [neg: URI mismatch un-suppressible even with suppression on]
// @verifies CL-SECADMIN-003
// ===========================================================================
// @relation(CL-SECADMIN-003, scope=function)
TEST_F(ClientCertValidation, DoesNotSuppressUriMismatch)
{
  const auto now = DateTime::now();
  const auto past = DateTime{now.value() - std::chrono::days{1}};
  const auto future = DateTime{now.value() + std::chrono::days{30}};
  const auto expiredFrom = DateTime{now.value() - std::chrono::days{30}};
  const auto expiredTo = DateTime{now.value() - std::chrono::days{1}};

  auto caKeys = new_rsa_keys();
  auto ca = mPki->create_root_ca(caKeys, "CV UriSuppress CA", "9010");

  TrustListValidationOptions suppressHostName{Bit::SuppressHostNameInvalid};

  // URI mismatch alone, with SuppressHostNameInvalid set -> still Bad_CertificateUriInvalid (never
  // suppressed).
  {
    auto leaf = mint_leaf(caKeys, ca, past, future, {"urn:cert:wrong-uri"});
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(
      leaf, {}, suppressHostName, /*applicationUri=*/"urn:expected:app", /*endpointUrl=*/std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUriInvalid)
      << "URI mismatch must not be suppressed by SuppressHostNameInvalid (Table 106: URI never suppressed)";
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateUriMismatch"));
  }

  // URI AND hostname both wrong, SuppressHostNameInvalid set -> the URI status still wins (checked first,
  // unsuppressed). Were URI folded into the hostname-suppression flag, this would pass validation - bypass.
  {
    auto leaf = mint_leaf(caKeys, ca, past, future, {"urn:cert:wrong-uri"}, {"wronghost"});
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(leaf,
      {},
      suppressHostName,
      /*applicationUri=*/"urn:expected:app",
      /*endpointUrl=*/"opc.tcp://righthost:4840"));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUriInvalid)
      << "even with the hostname also wrong and suppressed, the unsuppressible URI check must fail first";
  }

  // Expiry AND URI are wrong, with only expiry suppressed. Table 106 requires validation to continue after
  // the suppressed non-critical error, so the later non-suppressible URI mismatch must still reject the
  // certificate. This is the regression arm for D-CORE-CRYPTO-OPENSSL-SUPPRESSION-EARLY-SUCCESS.
  {
    auto leaf = mint_leaf(caKeys, ca, expiredFrom, expiredTo, {"urn:cert:wrong-uri"});
    auto store = new_store();
    store->add_to_trusted_certificates_sync(ca);
    TrustListValidationOptions suppressExpiry{Bit::SuppressCertificateExpired};
    auto result = store->try_validate_certificate_sync(ua::test::make_validation_request(
      leaf, {}, suppressExpiry, /*applicationUri=*/"urn:expected:app", /*endpointUrl=*/std::nullopt));
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUriInvalid)
      << "a suppressed expiry must continue to and expose the non-suppressible URI mismatch";
    EXPECT_THAT(detail_of(result), HasSubstr("CertificateUriMismatch"));
  }
}

// ===========================================================================
// Row 5 - RevalidatesServerCertOnRenew
// The server certificate is re-validated at EVERY SecureChannel renewal (the RenewSecureChannel response is
// an OPN/asymmetric message whose decode re-runs validate_certificate_async). Proof on a single live channel:
// renewal #1 with trust intact is ACCEPTED (token advances); after the server cert is removed from the
// client trust store, renewal #2 is REJECTED and the channel disconnects - so the cert was re-validated
// again, against CURRENT trust, and not merely trusted-because-the-channel-already-exists.
// [neg: trust valid at open, revoked before renew -> renewal must re-check]
// @verifies CL-SECADMIN-004
// ===========================================================================
// @relation(CL-SECADMIN-004, scope=function)
TEST_F(ClientCertValidation, RevalidatesServerCertOnRenew)
{
  auto channel = open_secured_long_lifetime();
  ASSERT_TRUE(channel.is_open());
  const uint32_t token0 = read_token_id(channel);
  ASSERT_NE(token0, 0u);

  // Renewal #1 - trust intact: the server cert re-validates Good, the renewal is accepted, token advances.
  const auto firstRenew = trigger_renewal_and_wait(channel, token0);
  ASSERT_EQ(firstRenew, RenewOutcome::Renewed)
    << "with trust intact the renewal must be accepted (server cert re-validated Good)";
  const uint32_t token1 = read_token_id(channel);
  ASSERT_NE(token1, token0);
  ASSERT_TRUE(channel.is_open());

  // Between renewals the administrator drops the server cert from the client trust store.
  mClientCertStore->replace_trusted_certificates_sync(/*certificates=*/{}, /*crls=*/{});

  // Renewal #2 - now untrusted: the re-validation at renewal REJECTS the (now-untrusted) server cert and the
  // channel disconnects. If the renewal path did NOT re-validate, this would be accepted (token would advance
  // on a now-untrusted cert) - the flip-guard that RED-pins a revalidation bypass at renewal.
  const auto secondRenew = trigger_renewal_and_wait(channel, token1);
  EXPECT_EQ(secondRenew, RenewOutcome::Disconnected)
    << "the server cert must be RE-validated at renewal; an untrusted cert must be rejected, not renewed";
  EXPECT_FALSE(channel.is_open()) << "a rejected renewal must tear the channel down";

  (void)channel.try_close_sync();
}

// ===========================================================================
// Row 6 - PicksUpRefreshedCrlAtRenewal
// Re-validation consults the store's CURRENT CRL set, so a CRL refreshed to list the cert's serial flips the
// verdict from Good to Bad_CertificateRevoked on the very next validation - the same engine the renewal
// decode invokes. (Fixture limit: the self-signed fixture server cert is CRL-exempt, so this is proven on a
// CA-issued cert at the store level; the renewal-revalidation TRIGGER is proven end-to-end by
// RevalidatesServerCertOnRenew.)
// [neg: CRL advances mid-session -> revocation now caught]
// @verifies CL-SECADMIN-004
// ===========================================================================
// @relation(CL-SECADMIN-004, scope=function)
TEST_F(ClientCertValidation, PicksUpRefreshedCrlAtRenewal)
{
  const auto now = DateTime::now();
  const auto past = DateTime{now.value() - std::chrono::days{1}};
  const auto future = DateTime{now.value() + std::chrono::days{30}};

  auto caKeys = new_rsa_keys();
  auto ca = mPki->create_root_ca(caKeys, "CV Crl CA", "9011");
  auto serverLike = mint_leaf(caKeys, ca, past, future, {}, {"localhost"});

  auto store = new_store();
  store->add_to_trusted_certificates_sync(ca);
  // A present-but-empty CRL so revocation status is KNOWN (not RevocationUnknown) and the cert validates.
  store->add_to_trusted_crls_sync(mPki->create_crl(ca, caKeys, {}));

  TrustListValidationOptions crlCheck{Bit::CheckRevocationStatusOffline};

  const auto before =
    store->try_validate_certificate_sync(ua::test::make_validation_request(serverLike, {}, crlCheck));
  ASSERT_THAT(before, Good()) << "in-date, not-yet-revoked cert with a present CRL must validate";

  // Refresh the CRL to list the cert's serial (atomic CloseAndUpdate of the trusted certs + CRLs).
  store->replace_trusted_certificates_sync(
    /*certificates=*/{ca}, /*crls=*/{mPki->create_crl(ca, caKeys, {serverLike->serial_number()})});

  const auto after =
    store->try_validate_certificate_sync(ua::test::make_validation_request(serverLike, {}, crlCheck));
  EXPECT_EQ(after.status_code().as_status(), Status::BadCertificateRevoked)
    << "a refreshed CRL must be picked up - a cached/one-shot CRL would leave the revoked cert valid";
}

// ===========================================================================
// Row 7 - DisconnectsOnRenewalValidationFailure
// When the server cert becomes untrusted between open and a renewal, the renewal validation fails and the
// channel is torn down - the client does NOT keep serving on a now-untrusted cert. The disconnect (the
// channel closes rather than adopting the renewed token) is the required security property.
// [neg: trust revoked between open and renew]
//
// PRODUCT BUG FOUND WHILE AUTHORING THIS ROW (reported, NOT worked around in product code):
//   Probing the disconnected channel with try_create_session_sync SIGSEGVs. On teardown the close-drain
//   resets mSecurityPolicy and mContext to null (ua_client_secure_channel_impl.cpp:1358-1359), but the
//   create_session strand body dereferences them with NO terminal-state guard -
//   self.mSecurityPolicy->is_authenticated() (:1893) and self.mContext->localCertificate (:1897) - so
//   creating a session on a CLOSED channel is a null-pointer crash. A renewal-validation-failure disconnect
//   (exactly this scenario) followed by a create-session (e.g. from reconnect/session code) crashes the
//   process. That is a genuine robustness defect and is reported to the maintainer; it is a SEPARATE bug
//   from this row's subject, so the crashing probe is omitted here (a SIGSEGV cannot be asserted and would
//   take down the shared harness) rather than the product being edited. The disconnect itself IS built and
//   secure, and is asserted below.
// @verifies CL-SECADMIN-004
// ===========================================================================
// @relation(CL-SECADMIN-004, scope=function)
TEST_F(ClientCertValidation, DisconnectsOnRenewalValidationFailure)
{
  auto channel = open_secured_long_lifetime();
  ASSERT_TRUE(channel.is_open());
  const uint32_t token0 = read_token_id(channel);
  ASSERT_NE(token0, 0u);

  // Remove the server's certificate (its own self-signed trust anchor) from the client trust store.
  mClientCertStore->replace_trusted_certificates_sync(/*certificates=*/{}, /*crls=*/{});

  // Force a renewal via the controllable interface: the renewal-time re-validation rejects the now-untrusted
  // server cert and the channel disconnects. A channel that stayed open (kept serving on the untrusted cert)
  // is the security defect this flip-guard RED-pins.
  const auto outcome = trigger_renewal_and_wait(channel, token0);
  EXPECT_EQ(outcome, RenewOutcome::Disconnected)
    << "a renewal-time validation failure must disconnect, not silently keep the channel alive";
  EXPECT_FALSE(channel.is_open()) << "the channel must be closed after a rejected renewal";

  (void)channel.try_close_sync();
}

// ===========================================================================
// CL-RECONN-005 - GetEndpoints on the security-failure recovery path fetches fresh security info.
//
// On a security-class reconnect the client issues a GetEndpoints on a freshly-opened channel and refreshes
// its stored endpoint description (picking up a rotated server certificate) before retrying the channel
// open. The ConnectionImpl host primitive that drives this - reconnect_get_endpoints - and the endpoint
// selection in refresh_endpoint_from_get_endpoints are unit-covered
// (ConnectionImplTest.ReconnectGetEndpoints* over the real tier-0 interface). This real-stack row pins the
// tier-0 half the primitive depends on: a REAL GetEndpoints issued over a SECURED channel (the same
// SecureChannel::get_endpoints_async that RealChannelOps delegates to) returns endpoints carrying the
// server's certificate - the "fresh security info" the refresh selects and republishes. The full FSM-driven
// end-to-end reconnect observation (drive a security-class drop, observe GetEndpoints on the wire before the
// next OPN) is deferred to the tier-2 integration authoring pass, tracked as
// OPEN-RECONN-005-e2e-integration.
//
// Falsifiable: a GetEndpoints that failed, returned no endpoints, or advertised only endpoints with an empty
// server certificate would leave the security-failure refresh nothing to consume - every assertion fails.
// @verifies CL-RECONN-005
// @verifies CL-RECONN-008
// ===========================================================================
// @relation(CL-RECONN-005, CL-RECONN-008, scope=function)
TEST_F(ClientCertValidation, GetEndpointsOnSecuredChannelReturnsServerCertificate)
{
  auto channel = open_secured_long_lifetime();
  ASSERT_TRUE(channel.is_open());

  ua::GetEndpointsRequest request;
  request.endpoint_url() = mEndpointUrl;
  const auto result = channel.try_get_endpoints_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "GetEndpoints on a secured channel must succeed (no session required)";

  const auto& endpoints = result.value().endpoints();
  ASSERT_FALSE(endpoints.empty()) << "the server must advertise at least one endpoint";

  // At least one advertised (secured) endpoint must carry a non-empty server certificate - the fresh
  // security material the security-failure refresh (refresh_endpoint_from_get_endpoints) selects and
  // republishes into the endpoint snapshot the client re-validates against.
  bool sawServerCertificate = false;
  for (const auto& endpoint : endpoints)
  {
    if (!endpoint.server_certificate().empty())
    {
      sawServerCertificate = true;
      break;
    }
  }
  EXPECT_TRUE(sawServerCertificate)
    << "a refreshed endpoint must carry the server certificate the security-failure path re-fetches";

  (void)channel.try_close_sync();
}
