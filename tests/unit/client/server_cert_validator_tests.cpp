// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for detail::make_server_cert_revalidation (formerly make_server_cert_validator; owner review
// 2026-10-02 "Client revalidation") - the server-cert re-validation interface wired into every
// managed Connection's reconnect wiring (CL-SECADMIN-004 immediate revalidation / CL-PULLCRT-006 /
// CL-RECONN-006). The interface re-validates the connection's pinned server certificate against the CURRENT
// Client store on demand by resubmitting the exact CertificateValidationRequest the connection validated the
// server with (presented issuers, policy, endpoint URL, connection trust), and delivers a Good/Bad verdict; a
// Bad verdict routes the Connection to a CertRotated reconnect. These exercise the REAL production function
// (CoreClientImpl::create builds its factory from it).

#include <gtest/gtest.h>

#include "ua_server_cert_validator.h"

#include "ua_certificate_store.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"

#include "fake_certificate_store.h"

#include "ua_crypto.h"
#include "ua_status.h"
#include "ua_x509_certificate.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace ua;
using ua::client::detail::make_server_cert_revalidation;
using ua::test_helpers::FakeCertificateStore;

namespace
{

class ServerCertValidator : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // A private-key credential callback is required so the OpenSSL backend can encrypt the generated PEM
    // private key (create_self_signed_... fails without one).
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    ASSERT_TRUE(mCrypto);
    Crypto::Name name;
    name.commonName = "ServerCertValidator Test";
    Crypto::SubjectAlternateName san;
    san.hostnames.push_back("localhost");
    san.uris.push_back("urn:test:server");
    auto result = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      name, UtcTime{2050, 1, 1, 0, 0, 0}, san, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(result.is_good()) << "test cert generation must succeed";
    mServerCert = std::move(result).value().second;
    ASSERT_TRUE(mServerCert);
  }

  std::shared_ptr<const ua::Crypto> mCrypto;
  std::shared_ptr<const X509Certificate> mServerCert;

  // The request the client's OPN path stores for the connection: the server certificate, the endpoint URL
  // for the host-name binding, no ApplicationUri (OPN parity).
  static CertificateValidationRequest stored_request(
    std::shared_ptr<const X509Certificate> serverCertificate, std::optional<std::string> endpointUrl)
  {
    CertificateValidationRequest request;
    request.certificate = std::move(serverCertificate);
    request.endpointUrl = std::move(endpointUrl);
    return request;
  }

  static std::function<std::shared_ptr<ua::CertificateStore>()> accessor(
    const std::shared_ptr<FakeCertificateStore>& store)
  {
    return [store]() -> std::shared_ptr<ua::CertificateStore>
    {
      return store;
    };
  }

  // Drives the interface synchronously (the fake store completes inline) and returns the delivered verdict.
  static VoidResult run(const std::function<void(std::function<void(VoidResult)>)>& validator)
  {
    std::optional<VoidResult> captured;
    validator([&captured](VoidResult verdict) { captured = std::move(verdict); });
    EXPECT_TRUE(captured.has_value()) << "the interface must invoke its verdict callback exactly once";
    return captured.value_or(VoidResult{StatusCode{Status::BadInternalError}});
  }
};

// A null pinned server certificate (a None channel / an un-pinned server) is a Good no-op - the store is
// NEVER consulted. Falsifiable: forwarding a null cert to the store would bump the call count.
TEST_F(ServerCertValidator, NullServerCertIsGoodNoOpAndDoesNotConsultStore)
{
  auto store = FakeCertificateStore::create();
  store->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};  // would fail IF consulted

  auto validator = make_server_cert_revalidation(
    accessor(store), stored_request(/*serverCertificate=*/nullptr, "opc.tcp://server:4840"));

  EXPECT_TRUE(run(validator).is_good()) << "a null server cert must be a Good no-op";
  EXPECT_EQ(store->validateCallCount, 0) << "the store must not be consulted when there is no cert";
}

// A store trust rejection is surfaced VERBATIM as the interface verdict (the Connection acts on it ->
// CertRotated), and the request threads the endpoint URL for identity binding with applicationUri = nullopt
// (OPN parity). Falsifiable: swallowing the rejection (Good) fails is_bad; a wrong status fails the code
// check.
// @verifies CL-SC-003
// @relation(CL-SC-003, scope=function)
TEST_F(ServerCertValidator, ForwardsStoreRejectionAsVerdictWithEndpointIdentity)
{
  auto store = FakeCertificateStore::create();
  store->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};

  auto validator =
    make_server_cert_revalidation(accessor(store), stored_request(mServerCert, "opc.tcp://server:4840"));

  const auto verdict = run(validator);
  EXPECT_TRUE(verdict.is_bad()) << "a now-untrusted server cert must surface a Bad verdict";
  EXPECT_EQ(verdict.status_code().as_status(), Status::BadCertificateUntrusted);
  EXPECT_EQ(store->validateCallCount, 1);
  ASSERT_TRUE(store->lastValidatedEndpointUrl.has_value());
  EXPECT_EQ(store->lastValidatedEndpointUrl.value(), "opc.tcp://server:4840")
    << "the endpoint URL must be threaded for identity binding (parity with OPN)";
  EXPECT_FALSE(store->lastValidatedApplicationUri.has_value())
    << "applicationUri must be nullopt (OPN parity - the URI is not re-checked here)";
}

// A store acceptance yields a Good verdict (the cert is still trusted; no reconnect). Falsifiable: a spurious
// Bad would fail is_good.
TEST_F(ServerCertValidator, ForwardsStoreAcceptanceAsGood)
{
  auto store = FakeCertificateStore::create();  // defaults to Good
  auto validator =
    make_server_cert_revalidation(accessor(store), stored_request(mServerCert, "opc.tcp://server:4840"));

  EXPECT_TRUE(run(validator).is_good());
  EXPECT_EQ(store->validateCallCount, 1) << "a pinned cert must be re-validated against the store";
}

// A null store (Client gone / no store configured) is a Good no-op - nothing to validate against.
// Falsifiable: dereferencing a null store would crash.
TEST_F(ServerCertValidator, NullStoreAccessorResultIsGoodNoOp)
{
  auto validator =
    make_server_cert_revalidation([]() -> std::shared_ptr<ua::CertificateStore> { return nullptr; },
      stored_request(mServerCert, "opc.tcp://server:4840"));

  EXPECT_TRUE(run(validator).is_good()) << "no store to validate against must be a Good no-op";
}

// section 3.1 (unanimous HIGH): the interface is stored long-lived and invoked ONCE PER revalidation cycle,
// so it must re-validate on EVERY invocation, not just the first. A prior bug std::move-d the captured cert
// into the by-value store parameter, nulling it after the first call -> every later cycle short-circuited to
// the Good no-op without consulting the store (the revocation control failed OPEN). This drives the SAME
// interface twice (Good then Bad) and asserts the 2nd invocation still consults the store and surfaces the
// rejection. Falsifiable: with the move-out bug, validateCallCount stays 1 and the 2nd verdict is a spurious
// Good.
TEST_F(ServerCertValidator, RepeatedInvocationsKeepConsultingTheStore)
{
  auto store = FakeCertificateStore::create();  // starts Good (still trusted)
  auto validator =
    make_server_cert_revalidation(accessor(store), stored_request(mServerCert, "opc.tcp://server:4840"));

  // Cycle 1: an unrelated trust update - the cert is still trusted.
  EXPECT_TRUE(run(validator).is_good());
  EXPECT_EQ(store->validateCallCount, 1) << "the first cycle must consult the store";

  // Cycle 2: the operator revokes trust - the SAME interface must re-consult the store and surface Bad.
  store->validateCertificateStatus = StatusCode{Status::BadCertificateRevoked};
  const auto secondVerdict = run(validator);
  EXPECT_EQ(store->validateCallCount, 2)
    << "every revalidation cycle must consult the store (the cert capture must survive the first call)";
  EXPECT_TRUE(secondVerdict.is_bad()) << "a later revocation must be detected on a repeat invocation";
  EXPECT_EQ(secondVerdict.status_code().as_status(), Status::BadCertificateRevoked);
}

// A stored request without an endpoint URL is resubmitted without one (not an empty string that would
// spuriously fail an identity match). The ""->nullopt conversion moved to where the client's OPN path builds
// the request (client_secure_channel_crypto_tests.cpp, ClientOpnBuildsTheValidationRequest...); here the
// obligation is that the revalidation does not invent a URL. Falsifiable: substituting "" makes
// lastValidatedEndpointUrl engaged.
TEST_F(ServerCertValidator, EmptyEndpointUrlPassedAsNullopt)
{
  auto store = FakeCertificateStore::create();
  auto validator = make_server_cert_revalidation(accessor(store), stored_request(mServerCert, std::nullopt));

  EXPECT_TRUE(run(validator).is_good());
  EXPECT_EQ(store->validateCallCount, 1);
  EXPECT_FALSE(store->lastValidatedEndpointUrl.has_value())
    << "a request without an endpoint URL must be resubmitted without one";
}

// Owner review 2026-10-02 (client revalidation, DEFECT fixed by design): the revalidation resubmits the EXACT
// request the connection validated the server with - the presented issuers the server sent in its OPN, the
// channel's SecurityPolicy (step 4), the endpoint URL and the certificates accepted for this connection only
// - against the current trust material. The old form re-ran the leaf alone, so a server whose chain needed
// its presented intermediate was refused at the first revalidation, and the policy check was skipped.
// Falsifiable: dropping any member from the resubmitted request fails the matching assertion.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-34-REVALIDATION-RESUBMITS, scope=function)
TEST_F(ServerCertValidator, RevalidationResubmitsTheStoredRequestUnchanged)
{
  auto store = FakeCertificateStore::create();
  auto issuerResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(Crypto::Name{},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_TRUE(issuerResult.is_good());
  const std::shared_ptr<const X509Certificate> presentedIssuer = std::move(issuerResult).value().second;
  auto request = stored_request(mServerCert, "opc.tcp://server:4840");
  request.presentedIssuers = {presentedIssuer};
  request.policyId = SecurityPolicyId::Basic256Sha256;
  request.use = CertificateUse::ApplicationInstance;
  auto validator = make_server_cert_revalidation(accessor(store), request);

  EXPECT_TRUE(run(validator).is_good());
  const auto resubmitted = store->last_validation_request();
  ASSERT_TRUE(resubmitted.has_value()) << "the revalidation must consult the store";
  EXPECT_EQ(resubmitted->certificate.get(), mServerCert.get());
  ASSERT_EQ(resubmitted->presentedIssuers.size(), 1u) << "the presented issuers must be resubmitted";
  EXPECT_EQ(resubmitted->presentedIssuers.front().get(), presentedIssuer.get());
  EXPECT_EQ(resubmitted->policyId, SecurityPolicyId::Basic256Sha256)
    << "the channel's policy must be resubmitted (step 4)";
  ASSERT_TRUE(resubmitted->endpointUrl.has_value());
  EXPECT_EQ(*resubmitted->endpointUrl, "opc.tcp://server:4840");
  EXPECT_FALSE(resubmitted->applicationUri.has_value());
  EXPECT_TRUE(resubmitted->trustedForThisConnection.empty());
}

// The connection-only trust (CL-SECADMIN-003 AcceptForThisSession) the connection was established with is
// part of the stored request, so a revalidation after an unrelated trust-list change does not refuse a server
// the application accepted for this connection. Falsifiable: dropping trustedForThisConnection routes the
// request to the plain path (validateCallCount) and leaves lastAdditionalTrustedCertificates empty.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-34-REVALIDATION-RESUBMITS, scope=function)
TEST_F(ServerCertValidator, RevalidationResubmitsTheConnectionOnlyTrust)
{
  auto store = FakeCertificateStore::create();
  auto request = stored_request(mServerCert, "opc.tcp://server:4840");
  request.trustedForThisConnection = {mServerCert};
  auto validator = make_server_cert_revalidation(accessor(store), request);

  EXPECT_TRUE(run(validator).is_good());
  EXPECT_EQ(store->validateWithAdditionalTrustCallCount, 1);
  ASSERT_EQ(store->lastAdditionalTrustedCertificates.size(), 1u);
  EXPECT_EQ(store->lastAdditionalTrustedCertificates.front().get(), mServerCert.get());
}

// The connect path records the request: the channel's OPN validation
// (SecurityPolicy::validate_certificate_async, the production entry) hands the exact request it validated
// with - the intermediate the server presented in its OPN header, the channel policy and the endpoint URL -
// to the connection's record, and the connection's revalidation resubmits THAT request. Falsifiable: a
// revalidation built from the channel configuration alone (the leaf, no presented issuers) fails the
// presented-issuer assertion.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-34-REVALIDATION-RESUBMITS, scope=function)
TEST_F(ServerCertValidator, TheConnectionRevalidationResubmitsTheRequestTheOpnValidated)
{
  auto store = FakeCertificateStore::create();
  auto issuerResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(Crypto::Name{},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_TRUE(issuerResult.is_good());
  const std::shared_ptr<const X509Certificate> presentedIntermediate = std::move(issuerResult).value().second;
  const std::shared_ptr<const SecurityPolicy> policy =
    SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // The channel side: the context the OPN decode fills, and the record the establisher threads into it.
  const auto record = std::make_shared<ua::client::detail::ValidatedServerRequest>();
  SecureChannelContext context;
  context.certStore = store;
  context.remoteCertificate = mServerCert;
  context.remoteIssuerCertificates = {presentedIntermediate};
  context.endpointUrl = "opc.tcp://server:4840";
  context.onRemoteCertificateValidated = [record](const CertificateValidationRequest& request)
  {
    record->set(request);
  };
  std::optional<VoidResult> opn;
  policy->validate_certificate_async(context, [&opn](VoidResult result) { opn = std::move(result); });
  ASSERT_TRUE(opn.has_value() && opn->is_good()) << "the OPN validation completes Good (fake store)";

  // The connection side: built before the open from the configuration alone (leaf, no issuers).
  const auto validator = ua::client::detail::make_connection_server_cert_revalidation(
    accessor(store), record, stored_request(mServerCert, "opc.tcp://server:4840"));
  EXPECT_TRUE(run(validator).is_good());
  const auto resubmitted = store->last_validation_request();
  ASSERT_TRUE(resubmitted.has_value());
  EXPECT_EQ(resubmitted->certificate.get(), mServerCert.get());
  ASSERT_EQ(resubmitted->presentedIssuers.size(), 1u)
    << "the intermediate presented in the OPN is resubmitted";
  EXPECT_EQ(resubmitted->presentedIssuers.front().get(), presentedIntermediate.get());
  EXPECT_EQ(resubmitted->policyId, SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(resubmitted->endpointUrl, std::optional<std::string>{"opc.tcp://server:4840"});
}

}  // namespace
