// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the discovery-driven easy-connect resolver (client design section 7.3A) -
// ua::client::detail::resolve_easy_connect_async, ua::client::default_easy_connect_ranker, and the
// session-scoped trust override ua::client::detail::SessionTrustStore.
//
// The resolver deliberately stops at an EasyConnectResolution rather than connecting, so every
// decision it makes is directly observable: which endpoint won the ranking, whether the full
// discovery response survives for CreateSession verification, whether the trust prompt was asked
// and with what, whether the answer produced a session override or a persisted certificate, and
// which ErrorDetail source tag names the failing step.
//
// Falsifiability: each test asserts a specific field of the resolved config or a specific
// (StatusCode, source) pair, so a resolver that skipped validation, prompted on a non-trust failure,
// silently downgraded to an unsecured endpoint, or persisted when asked to accept only for the
// session fails a concrete assertion rather than passing vacuously.

#include "ua_easy_connect.h"

#include "ua_session_trust_store.h"

#include "ua_connection_config.h"
#include "ua_crypto_types.h"
#include "ua_easy_connect_policy.h"
#include "ua_security_policy.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "ua_utilities.h"

#include "fake_certificate_store.h"
#include "stub_x509_certificate.h"

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{
using ua::client::ConnectionConfig;
using ua::client::EasyConnectConfig;
using ua::client::TrustDecision;
using ua::client::detail::EasyConnectDeps;
using ua::client::detail::EasyConnectResolution;
using ua::client::detail::EasyConnectResolutionResult;
using ua::client::detail::resolve_easy_connect_async;
using ua::client::detail::SessionTrustStore;

constexpr std::string_view exampleUrl = "opc.tcp://server.example:4840";

/// A stub certificate with a caller-chosen thumbprint, so SessionTrustStore's by-thumbprint matching
/// can be exercised (the shared stub returns an empty thumbprint).
class ThumbprintCertificate final : public ua::testing::StubX509Certificate
{
public:
  explicit ThumbprintCertificate(ua::ByteString thumbprint) : mThumbprint(std::move(thumbprint))
  {}

  ua::ByteString thumbprint() const override
  {
    return mThumbprint;
  }

private:
  ua::ByteString mThumbprint;
};

std::shared_ptr<const ua::X509Certificate> cert_with_thumbprint(std::uint8_t tag)
{
  return std::make_shared<const ThumbprintCertificate>(ua::ByteString{tag, 0x02, 0x03});
}

ua::EndpointDescription make_endpoint(
  std::string url, ua::SecurityPolicyId policy, ua::MessageSecurityMode mode, bool withCertificate = true)
{
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = ua::String{std::move(url)};
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(policy);
  endpoint.security_mode() = mode;
  if (withCertificate)
  {
    endpoint.server_certificate() = ua::ByteString{0x30, 0x82, 0x01};
  }
  return endpoint;
}

/// Appends one advertised UserTokenPolicy, so the resolver has something to select from.
///
/// @p tokenSecurityPolicyUri is the policy's OWN SecurityPolicy, which is separate from the channel's. An
/// empty URI means "inherit the channel's" (Part 4 section 7.42); the None URI means the secret travels as
/// plaintext.
void advertise_token_policy(ua::EndpointDescription& endpoint, ua::UserTokenType type,
  std::string_view policyId, std::string_view tokenSecurityPolicyUri = {})
{
  ua::UserTokenPolicy token;
  token.policy_id() = ua::String{std::string{policyId}};
  token.token_type() = type;
  token.security_policy_uri() = ua::String{std::string{tokenSecurityPolicyUri}};
  endpoint.user_identity_tokens().push_back(std::move(token));
}

/// Builds deps whose collaborators all succeed; individual tests override the one under test.
struct Harness
{
  std::vector<ua::EndpointDescription> endpoints;
  /// The status discovery answers with: no endpoints for a Bad one, or when `discoveryHoldsEndpoints` is
  /// false; otherwise `endpoints` with this status.
  ua::StatusCode discoveryStatus{ua::Status::Good};
  bool discoveryHoldsEndpoints{true};
  ua::StatusCode validationStatus{ua::Status::Good};
  std::shared_ptr<const ua::X509Certificate> decoded = cert_with_thumbprint(0xAA);
  /// Issuers the GetEndpoints serverCertificate field carries after the leaf (decision 24).
  std::vector<std::shared_ptr<const ua::X509Certificate>> decodedIssuers;
  /// The presented issuers the last validation received.
  std::vector<std::shared_ptr<const ua::X509Certificate>> lastPresentedIssuers;
  std::optional<ua::StatusCode> decodeFailure;
  std::shared_ptr<ua::test_helpers::FakeCertificateStore> store =
    ua::test_helpers::FakeCertificateStore::create();

  int validateCalls{0};
  int persistCalls{0};
  /// Validation verdicts are served in order, so an AcceptAndPersist re-validation can differ from
  /// the first attempt.
  std::vector<ua::StatusCode> validationSequence;

  EasyConnectDeps build()
  {
    EasyConnectDeps deps;
    deps.getEndpoints =
      [this](std::string, ua::client::GetEndpointsOptions, ua::client::Discovery::GetEndpointsCallback cb)
    {
      if (discoveryStatus.is_bad() || !discoveryHoldsEndpoints)
      {
        cb(ua::client::Discovery::GetEndpointsResult{
          discoveryStatus.as_status(), ua::make_error_detail("Boom", "discovery failed", "test")});
        return;
      }
      cb(ua::client::Discovery::GetEndpointsResult{endpoints, discoveryStatus});
    };
    deps.decodeCertificate =
      [this](const ua::ByteString&) -> ua::Result<std::vector<std::shared_ptr<const ua::X509Certificate>>>
    {
      using ChainResult = ua::Result<std::vector<std::shared_ptr<const ua::X509Certificate>>>;
      if (decodeFailure)
      {
        return ChainResult{
          decodeFailure->as_status(), ua::make_error_detail("Boom", "decode failed", "test")};
      }
      std::vector<std::shared_ptr<const ua::X509Certificate>> chain{decoded};
      chain.insert(chain.end(), decodedIssuers.begin(), decodedIssuers.end());
      return ChainResult{std::move(chain)};
    };
    deps.storeAccessor = [this]
    {
      return std::static_pointer_cast<ua::CertificateStore>(store);
    };
    deps.validate = [this](std::shared_ptr<const ua::X509Certificate>,
                      std::vector<std::shared_ptr<const ua::X509Certificate>>
                        presentedIssuers,
                      std::string,
                      std::function<void(ua::VoidResult)>
                        verdict)
    {
      lastPresentedIssuers = std::move(presentedIssuers);
      const auto index = static_cast<std::size_t>(validateCalls);
      ++validateCalls;
      const auto status = index < validationSequence.size() ? validationSequence[index] : validationStatus;
      if (status.is_bad())
      {
        verdict(ua::VoidResult{status.as_status(), ua::make_error_detail("Boom", "invalid", "test")});
        return;
      }
      verdict(ua::VoidResult{});
    };
    return deps;
  }
};

/// Runs the resolver synchronously (every collaborator above completes inline) and returns the result.
EasyConnectResolutionResult resolve(Harness& harness, EasyConnectConfig policy)
{
  std::optional<EasyConnectResolutionResult> captured;
  resolve_easy_connect_async(harness.build(),
    std::move(policy),
    [&captured](EasyConnectResolutionResult result) { captured = std::move(result); });
  EXPECT_TRUE(captured.has_value()) << "the resolver must complete its callback exactly once";
  return std::move(*captured);
}

std::string source_of(const EasyConnectResolutionResult& result)
{
  const auto detail = result.shared_detail();
  return detail ? detail->source : std::string{};
}

std::string detail_code_of(const EasyConnectResolutionResult& result)
{
  const auto detail = result.shared_detail();
  return detail ? detail->code : std::string{};
}

EasyConnectConfig policy_for(std::string url = std::string{exampleUrl})
{
  EasyConnectConfig policy;
  policy.endpointUrl = std::move(url);
  return policy;
}

/// Checks that @p result is the refusal of the server's Uncertain @p answer: Bad_InternalError whose
/// ErrorDetail chain holds ServiceAnswerUncertain, with its summary and @p answer as its inner status.
void expect_uncertain_answer_refused(const EasyConnectResolutionResult& result, ua::Status answer)
{
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  const ua::ErrorDetail* refusal = result.error_detail();
  while (refusal != nullptr && refusal->code != "ServiceAnswerUncertain")
  {
    refusal = refusal->cause.get();
  }
  ASSERT_NE(refusal, nullptr) << "the refusal must name the Uncertain answer; top detail: "
                              << detail_code_of(result);
  EXPECT_EQ(refusal->summary, "The SDK does not act on an answer the server is uncertain of");
  EXPECT_EQ(refusal->innerStatus, ua::StatusCode{answer}.value());
}

// --- Input guards --------------------------------------------------------------------------------

TEST(EasyConnectResolve, EmptyEndpointUrlIsRejectedBeforeDiscovery)
{
  Harness harness;
  auto result = resolve(harness, policy_for(""));

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInvalidArgument);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.discovery");
}

TEST(EasyConnectResolve, DiscoveryFailurePropagatesWithItsSourceTag)
{
  Harness harness;
  harness.discoveryStatus = ua::StatusCode{ua::Status::BadNotConnected};

  auto result = resolve(harness, policy_for());

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNotConnected);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.discovery");
}

// An endpoint is not selected from an Uncertain GetEndpoints answer, though it holds endpoints.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(EasyConnectResolve, AnUncertainDiscoveryAnswerIsRefusedBeforeSelection)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.discoveryStatus = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};

  auto result = resolve(harness, policy_for());

  expect_uncertain_answer_refused(result, ua::Status::UncertainNotAllNodesAvailable);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.discovery");
  EXPECT_EQ(harness.validateCalls, 0) << "no endpoint may be selected and validated";
}

// An Uncertain GetEndpoints answer without endpoints is refused in the same way.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(EasyConnectResolve, AnUncertainDiscoveryAnswerWithoutEndpointsIsRefused)
{
  Harness harness;
  harness.discoveryStatus = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
  harness.discoveryHoldsEndpoints = false;

  auto result = resolve(harness, policy_for());

  expect_uncertain_answer_refused(result, ua::Status::UncertainNotAllNodesAvailable);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.discovery");
}

// Control for the refusals above: a Good subcode on the GetEndpoints answer is Good, so an endpoint is
// selected from it.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(EasyConnectResolve, AGoodSubcodeDiscoveryAnswerIsSelectedFrom)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.discoveryStatus = ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good()) << detail_code_of(result);
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://strong");
}

TEST(EasyConnectResolve, NoEndpointsIsBadNotFound)
{
  Harness harness;
  auto result = resolve(harness, policy_for());

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNotFound);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
}

// --- Ranking -------------------------------------------------------------------------------------

TEST(EasyConnectResolve, RankingPrefersTheStrongestSupportedEndpoint)
{
  Harness harness;
  harness.endpoints = {
    make_endpoint("opc.tcp://weak", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None),
    make_endpoint(
      "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt),
    make_endpoint("opc.tcp://mid", ua::SecurityPolicyId::Basic256, ua::MessageSecurityMode::Sign),
  };

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good()) << ua::to_string(*result.shared_detail());
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://strong");
  EXPECT_EQ(result.value().config.securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(result.value().config.securityPolicyId, ua::SecurityPolicyId::Basic256Sha256);
}

TEST(EasyConnectResolve, CustomRankerReplacesTheDefaultEntirely)
{
  Harness harness;
  harness.endpoints = {
    make_endpoint(
      "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt),
    make_endpoint("opc.tcp://chosen", ua::SecurityPolicyId::Basic256, ua::MessageSecurityMode::Sign),
  };
  auto policy = policy_for();
  // Invert the default preference: the weaker endpoint must win when the caller says so.
  policy.ranker = [](const ua::EndpointDescription& endpoint)
  {
    return std::string{endpoint.endpoint_url()} == "opc.tcp://chosen" ? 500 : 1;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://chosen");
}

TEST(EasyConnectResolve, EndpointsWithNoSupportedPolicyAreRejected)
{
  Harness harness;
  ua::EndpointDescription bogus;
  bogus.endpoint_url() = ua::String{"opc.tcp://bogus"};
  bogus.security_policy_uri() = ua::String{"http://example.invalid/NotAPolicy"};
  bogus.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  harness.endpoints = {bogus};

  auto result = resolve(harness, policy_for());

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityPolicyRejected);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
}

// --- Downgrade protection ------------------------------------------------------------------------

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
TEST(EasyConnectResolve, UnsecuredWinnerIsRefusedWhenASecuredEndpointWasOffered)
{
  Harness harness;
  harness.endpoints = {
    // On the dialled host: an unsecured copy elsewhere is not a candidate at all (see the host arms).
    make_endpoint(
      "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None),
    make_endpoint(
      "opc.tcp://secure", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt),
  };
  auto policy = policy_for();
  // A ranker that (wrongly, or maliciously) prefers the unsecured endpoint must not be able to
  // silently downgrade the connection.
  policy.ranker = [](const ua::EndpointDescription& endpoint)
  {
    return endpoint.security_mode() == ua::MessageSecurityMode::None ? 999 : 1;
  };

  auto result = resolve(harness, policy);

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
  EXPECT_EQ(detail_code_of(result), "EasyConnectRefusedDowngrade");
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// The None endpoint sits on the dialled host: an unsecured winner elsewhere is refused on its own account
// (AnUnsecuredWinnerOnAnotherHostIsRefused), and this control is about the opt-in alone.
TEST(EasyConnectResolve, AllowAnonymousFirstConnectPermitsTheUnsecuredWinner)
{
  Harness harness;
  harness.endpoints = {
    make_endpoint(
      "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false),
    make_endpoint(
      "opc.tcp://secure", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt),
  };
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;
  policy.ranker = [](const ua::EndpointDescription& endpoint)
  {
    return endpoint.security_mode() == ua::MessageSecurityMode::None ? 999 : 1;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good()) << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "");
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://server.example:4840/none");
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// Restated with CL-DISC-019: this arm used to assert that "a server offering only None is not a downgrade".
// The list is unauthenticated, so a list showing only None is exactly what a stripped list looks like; the
// default policy refuses it and names the reason.
TEST(EasyConnectResolve, UnsecuredOnlyServerIsRefusedWithoutTheOptIn)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false)};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
  EXPECT_EQ(detail_code_of(result), "EasyConnectRefusedUnsecured");
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// The gate must run on what will be connected: the secured winner passes the selection check, then
// `customize` lowers the mode. A resolver that checks the ranked winner only would hand back a None config.
// The refusal is the downgrade code: a secured endpoint WAS offered and the configuration fell below it.
TEST(EasyConnectResolve, CustomizeCannotReintroduceAnUnsecuredEndpointWithoutTheOptIn)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    std::string{exampleUrl}, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  auto policy = policy_for();
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    config.securityMode = ua::MessageSecurityMode::None;
    config.securityPolicyId = ua::SecurityPolicyId::None;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
  EXPECT_EQ(detail_code_of(result), "EasyConnectRefusedDowngrade");
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// The development factory keeps working for the anonymous bootstrap it exists for.
TEST(EasyConnectResolve, AcceptAllForDevelopmentStillConnectsAnonymouslyToAnUnsecuredOnlyServer)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false)};

  auto result = resolve(harness, EasyConnectConfig::accept_all_for_development(std::string{exampleUrl}));

  ASSERT_TRUE(result.is_good()) << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "");
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://server.example:4840/none");
  EXPECT_EQ(result.value().config.securityMode, ua::MessageSecurityMode::None);
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// "Unsecured" is mode None OR policy None: policy None under a signing mode scores above zero and would win
// on the mode-only rule this change replaced.
TEST(EasyConnectResolve, APolicyNoneWinnerIsUnsecuredWhateverItsMode)
{
  Harness harness;
  harness.endpoints = {make_endpoint("opc.tcp://server.example:4840/none",
    ua::SecurityPolicyId::None,
    ua::MessageSecurityMode::SignAndEncrypt,
    false)};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(detail_code_of(result), "EasyConnectRefusedUnsecured");
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// The post-customize gate runs inside a completion, so it must compare the policy id and never convert it:
// an id no policy implements (Invalid, "unset") would throw out of the flow. The resolver completes and
// the bad id is reported by the guarded connect path, as before the gate existed.
TEST(EasyConnectResolve, CustomizeSettingAnUnknownPolicyIdDoesNotThrow)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    std::string{exampleUrl}, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  auto policy = policy_for();
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    config.securityPolicyId = ua::SecurityPolicyId::Invalid;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good()) << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "");
  EXPECT_EQ(result.value().config.securityPolicyId, ua::SecurityPolicyId::Invalid);
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// The refusal happens on the ranked winner, before its certificate is decoded, validated or shown to the
// trust prompt: a refused connect must never persist a trust decision. The winner is unsecured (mode None)
// yet carries a certificate; validation would fail and the prompt would persist it.
TEST(EasyConnectResolve, AnUnsecuredWinnerIsRefusedBeforeItsCertificateIsValidatedOrTrusted)
{
  Harness harness;
  harness.endpoints = {make_endpoint("opc.tcp://server.example:4840/none",
    ua::SecurityPolicyId::Basic256Sha256,
    ua::MessageSecurityMode::None)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};
  bool prompted = false;
  auto policy = policy_for();
  policy.trustPrompt = [&prompted](const ua::X509Certificate&, ua::StatusCode)
  {
    prompted = true;
    return TrustDecision::AcceptAndPersist;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(detail_code_of(result), "EasyConnectRefusedUnsecured");
  EXPECT_EQ(harness.validateCalls, 0) << "refused before validation";
  EXPECT_FALSE(prompted) << "refused before the trust prompt, so nothing can be persisted";
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-IS-ANONYMOUS-ONLY
// The gate after customize sees the identity customize set, not the one the policy carried.
TEST(EasyConnectResolve, CustomizeCannotSwapInAUserNameOverAnUnsecuredWinner)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false)};
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    config.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(detail_code_of(result), "EasyConnectUnsecuredRequiresAnonymous");
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-STAYS-ON-THE-DIALLED-HOST
// The gate after customize sees the URL customize set, not the winner's.
TEST(EasyConnectResolve, CustomizeCannotMoveAnUnsecuredWinnerToAnotherHost)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false)};
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    config.endpointUrl = "opc.tcp://elsewhere.example:4840";
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(detail_code_of(result), "UnsecuredEndpointHostChanged");
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-STAYS-ON-THE-DIALLED-HOST
// A multi-homed server lists one unsecured copy per host name; the other-host copy is listed first and
// ties on every ranking key. The dialled-host copy is the winner.
TEST(EasyConnectResolve, AnUnsecuredCopyOnTheDialledHostIsPreferredOverAnotherHosts)
{
  Harness harness;
  harness.endpoints = {
    make_endpoint(
      "opc.tcp://plc-a.example:4840", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false),
    make_endpoint("opc.tcp://server.example:4840/none",
      ua::SecurityPolicyId::None,
      ua::MessageSecurityMode::None,
      false)};
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good()) << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "");
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://server.example:4840/none");
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// Two endpoints the table scores the same (two policies of one tier, both 420): the advertised level decides,
// as it does for AutoBest, so both entry points open the same endpoint from the same list. The tuple order
// alone would pick the other one (its policy URI sorts first).
TEST(EasyConnectResolve, EqualScoresAreBrokenByTheAdvertisedSecurityLevel)
{
  Harness harness;
  auto lower = make_endpoint(
    "opc.tcp://a", ua::SecurityPolicyId::EccNistP256AesGcm, ua::MessageSecurityMode::SignAndEncrypt);
  lower.security_level() = 1;
  auto higher = make_endpoint(
    "opc.tcp://b", ua::SecurityPolicyId::EccNistP256ChaChaPoly, ua::MessageSecurityMode::SignAndEncrypt);
  higher.security_level() = 10;
  harness.endpoints = {lower, higher};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good()) << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "");
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://b");
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// Opted in, default ranker: an unsecured endpoint labelled with an ECC policy scores as None/None, so the
// RSA SignAndEncrypt offer beside it wins.
TEST(EasyConnectResolve, ASecuredEndpointOutranksAnOptedInUnsecuredEccEndpoint)
{
  Harness harness;
  harness.endpoints = {make_endpoint("opc.tcp://server.example:4840/ecc-none",
                         ua::SecurityPolicyId::EccNistP256AesGcm,
                         ua::MessageSecurityMode::None,
                         false),
    make_endpoint("opc.tcp://server.example:4840/secure",
      ua::SecurityPolicyId::Basic256Sha256,
      ua::MessageSecurityMode::SignAndEncrypt)};
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good()) << (result.shared_detail() ? ua::to_string(*result.shared_detail()) : "");
  EXPECT_EQ(result.value().config.endpointUrl, "opc.tcp://server.example:4840/secure");
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-IS-ANONYMOUS-ONLY
TEST(EasyConnectResolve, OptInWithAUsernameIdentityIsRefusedOverAnUnsecuredWinner)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://server.example:4840/none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false)};
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;
  policy.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
  EXPECT_EQ(detail_code_of(result), "EasyConnectUnsecuredRequiresAnonymous");
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-STAYS-ON-THE-DIALLED-HOST
// Opted in and anonymous, so the gate is open; the host the endpoint names is what refuses it.
TEST(EasyConnectResolve, AnUnsecuredWinnerOnAnotherHostIsRefused)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://elsewhere.example:4840", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false)};
  auto policy = policy_for();
  policy.allowAnonymousFirstConnect = true;

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityChecksFailed);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.selection");
  EXPECT_EQ(detail_code_of(result), "UnsecuredEndpointHostChanged");
}

// --- Certificate handling ------------------------------------------------------------------------

TEST(EasyConnectResolve, CertificateDecodeFailureIsTagged)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.decodeFailure = ua::StatusCode{ua::Status::BadCertificateInvalid};

  auto result = resolve(harness, policy_for());

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadCertificateInvalid);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.certificate_decode");
}

TEST(EasyConnectResolve, TrustedCertificateProducesAConnectableConfig)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  auto policy = policy_for();
  policy.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  const auto& config = result.value().config;
  EXPECT_EQ(config.serverCertificate, harness.decoded) << "the decoded certificate must be pinned";
  EXPECT_EQ(config.trustStoreOverride, nullptr) << "a trusted server needs no override";
  EXPECT_EQ(config.endpointSelection, ua::client::EndpointSelection::ExactUrl)
    << "the endpoint is already chosen; re-running discovery inside connect would be wasteful";
  EXPECT_TRUE(std::holds_alternative<ua::client::UsernamePasswordIdentity>(config.identity));
  EXPECT_EQ(harness.validateCalls, 1);
}

// A non-anonymous identity is unusable unless the UserTokenPolicy it activates under is named. The
// resolver has just chosen the endpoint and therefore holds its advertised policies, so it is the
// one place that can name it; leaving the field empty makes `easy_connect` reject every
// authenticated Session before any wire traffic ("a non-anonymous user identity requires an
// explicit UserTokenPolicy id").
TEST(EasyConnectResolve, SelectsTheUserTokenPolicyMatchingAUsernameIdentity)
{
  Harness harness;
  auto endpoint = make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt);
  advertise_token_policy(endpoint, ua::UserTokenType::Anonymous, "anon-0");
  advertise_token_policy(endpoint, ua::UserTokenType::UserName, "user-pass-1");
  advertise_token_policy(endpoint, ua::UserTokenType::Certificate, "cert-2");
  harness.endpoints = {std::move(endpoint)};
  auto policy = policy_for();
  policy.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().config.userTokenPolicyId, "user-pass-1")
    << "the resolver must name the UserName policy the chosen endpoint advertises";
}

TEST(EasyConnectResolve, SelectsTheUserTokenPolicyMatchingAnX509Identity)
{
  Harness harness;
  auto endpoint = make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt);
  advertise_token_policy(endpoint, ua::UserTokenType::Anonymous, "anon-0");
  advertise_token_policy(endpoint, ua::UserTokenType::Certificate, "cert-2");
  harness.endpoints = {std::move(endpoint)};
  auto policy = policy_for();
  policy.identity = ua::client::X509Identity{};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().config.userTokenPolicyId, "cert-2");
}

// section 3.1 finding, fixed: advertised order must not decide whether the password travels in the clear. A
// UserName policy naming the None SecurityPolicy sends the secret as plaintext, which the token builder
// refuses unless the application opted in, so naming one because the Server listed it first would hand the
// caller a policy it cannot use. The plaintext policy is advertised FIRST here, so a first-match resolver
// fails on the value.
TEST(EasyConnectResolve, PrefersASecuredUserTokenPolicyOverAPlaintextOne)
{
  Harness harness;
  auto endpoint = make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt);
  advertise_token_policy(endpoint,
    ua::UserTokenType::UserName,
    "user-plain",
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None));
  advertise_token_policy(endpoint,
    ua::UserTokenType::UserName,
    "user-secured",
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256));
  harness.endpoints = {std::move(endpoint)};
  auto policy = policy_for();
  policy.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().config.userTokenPolicyId, "user-secured");
}

// The fallback stands: when a plaintext policy is the ONLY one of its kind, name it, so the refusal comes
// from the token builder's opt-in gate with its own diagnosis rather than from an empty id.
TEST(EasyConnectResolve, StillNamesAPlaintextUserTokenPolicyWhenItIsTheOnlyOne)
{
  Harness harness;
  auto endpoint = make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt);
  advertise_token_policy(endpoint,
    ua::UserTokenType::UserName,
    "user-plain",
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None));
  harness.endpoints = {std::move(endpoint)};
  auto policy = policy_for();
  policy.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().config.userTokenPolicyId, "user-plain");
}

// An anonymous identity keeps its long-standing tier-0 auto-selection, which happens at activation
// against the endpoint the session was actually created on. Naming it here too would be harmless but
// it is not this resolver's job, and an empty field is what every existing caller expects.
TEST(EasyConnectResolve, LeavesTheTokenPolicyUnnamedForAnAnonymousIdentity)
{
  Harness harness;
  auto endpoint = make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt);
  advertise_token_policy(endpoint, ua::UserTokenType::Anonymous, "anon-0");
  harness.endpoints = {std::move(endpoint)};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().config.userTokenPolicyId.empty());
}

// The endpoint that won the ranking advertises no policy for this identity kind. The resolver leaves
// the field empty rather than guessing, so the refusal carries the token builder's own diagnosis
// instead of a policy id the endpoint never offered.
TEST(EasyConnectResolve, LeavesTheTokenPolicyUnnamedWhenTheEndpointAdvertisesNoMatchingKind)
{
  Harness harness;
  auto endpoint = make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt);
  advertise_token_policy(endpoint, ua::UserTokenType::Anonymous, "anon-0");
  harness.endpoints = {std::move(endpoint)};
  auto policy = policy_for();
  policy.identity = ua::client::UsernamePasswordIdentity{"alice", "secret"};

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().config.userTokenPolicyId.empty());
}

// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, scope=function)
TEST(EasyConnectResolve, RetainsTheCompleteDiscoveryResponseForCreateSessionVerification)
{
  Harness harness;
  harness.endpoints = {
    make_endpoint("opc.tcp://none", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, false),
    make_endpoint(
      "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt),
  };

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good());
  const EasyConnectResolution& resolution = result.value();
  ASSERT_EQ(resolution.discoveryEndpoints.size(), 2u);
  EXPECT_EQ(resolution.discoveryEndpoints[0].endpoint_url(), ua::String{"opc.tcp://none"});
  EXPECT_EQ(resolution.discoveryEndpoints[1].endpoint_url(), ua::String{"opc.tcp://strong"});
  EXPECT_EQ(resolution.config.endpointUrl, "opc.tcp://strong");
}

TEST(EasyConnectResolve, NonTrustFailureIsNeverEscalatedToThePrompt)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateTimeInvalid};
  bool prompted = false;
  auto policy = policy_for();
  policy.trustPrompt = [&prompted](const ua::X509Certificate&, ua::StatusCode)
  {
    prompted = true;
    return TrustDecision::AcceptAndPersist;
  };

  auto result = resolve(harness, policy);

  EXPECT_FALSE(prompted) << "an expired certificate is not a trust decision the user may wave past";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadCertificateTimeInvalid);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.certificate_validation");
}

// --- The trust-prompt exchange -------------------------------------------------------------------

TEST(EasyConnectResolve, UntrustedWithNoPromptFailsRatherThanTrustingSilently)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};

  auto result = resolve(harness, policy_for());

  EXPECT_TRUE(result.is_bad()) << "the safe default must never be a silent accept";
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.trust_unconfigured");
}

TEST(EasyConnectResolve, PromptReceivesTheCertificateAndTheFailureReason)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateChainIncomplete};
  std::optional<ua::StatusCode> seenReason;
  const ua::X509Certificate* seenCertificate = nullptr;
  auto policy = policy_for();
  policy.trustPrompt = [&](const ua::X509Certificate& certificate, ua::StatusCode reason)
  {
    seenCertificate = &certificate;
    seenReason = reason;
    return TrustDecision::Reject;
  };

  resolve(harness, policy);

  ASSERT_TRUE(seenReason.has_value());
  EXPECT_EQ(seenReason->as_status(), ua::Status::BadCertificateChainIncomplete);
  EXPECT_EQ(seenCertificate, harness.decoded.get());
}

TEST(EasyConnectResolve, RejectFailsWithBadSecurityChecksFailed)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};
  auto policy = policy_for();
  policy.trustPrompt = [](const ua::X509Certificate&, ua::StatusCode)
  {
    return TrustDecision::Reject;
  };

  auto result = resolve(harness, policy);

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityChecksFailed);
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.user_rejected");
}

TEST(EasyConnectResolve, AcceptForThisSessionInstallsAnOverrideAndPersistsNothing)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};
  auto policy = policy_for();
  policy.trustPrompt = [](const ua::X509Certificate&, ua::StatusCode)
  {
    return TrustDecision::AcceptForThisSession;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_NE(result.value().config.trustStoreOverride, nullptr)
    << "the connect must use a store that accepts the certificate the user just approved";
  EXPECT_TRUE(harness.store->trustedCertificates.empty())
    << "AcceptForThisSession must leave no trace in the runtime store";
}

TEST(EasyConnectResolve, AcceptAndPersistWritesToTheStoreAndRevalidates)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  // Untrusted first, trusted once the certificate has been written.
  harness.validationSequence = {
    ua::StatusCode{ua::Status::BadCertificateUntrusted}, ua::StatusCode{ua::Status::Good}};
  auto policy = policy_for();
  policy.trustPrompt = [](const ua::X509Certificate&, ua::StatusCode)
  {
    return TrustDecision::AcceptAndPersist;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(harness.validateCalls, 2) << "the certificate must be re-validated after being persisted";
  EXPECT_EQ(harness.store->trustedCertificates.size(), 1u);
  EXPECT_EQ(result.value().config.trustStoreOverride, nullptr)
    << "a persisted certificate validates against the real store; no override is needed";
}

TEST(EasyConnectResolve, PersistThatStillFailsValidationDoesNotLoop)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  harness.validationStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};
  int prompts = 0;
  auto policy = policy_for();
  policy.trustPrompt = [&prompts](const ua::X509Certificate&, ua::StatusCode)
  {
    ++prompts;
    return TrustDecision::AcceptAndPersist;
  };

  auto result = resolve(harness, policy);

  EXPECT_EQ(prompts, 1) << "the user must be asked once, not once per validation attempt";
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(source_of(result), "client.tier1.easy_connect.trust_persist");
}

// --- Composability -------------------------------------------------------------------------------

TEST(EasyConnectResolve, CustomizeRunsLastAndCanOverrideResolvedFields)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://strong", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  auto policy = policy_for();
  policy.customize = [](ConnectionConfig& config)
  {
    config.sessionName = "customized";
    config.queueOnReconnect = false;
  };

  auto result = resolve(harness, policy);

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().config.sessionName.has_value());
  EXPECT_EQ(*result.value().config.sessionName, "customized");
  EXPECT_FALSE(result.value().config.queueOnReconnect);
}

// --- The default ranker --------------------------------------------------------------------------

// @verifies AC-CL-DISC-019-RANKER-USES-THE-SDK-SECURITY-ORDER
TEST(EasyConnectDefaultRanker, ScoresSecurityStrengthInTheDocumentedOrder)
{
  const auto score = [](ua::SecurityPolicyId policy, ua::MessageSecurityMode mode)
  {
    return ua::client::default_easy_connect_ranker(make_endpoint("opc.tcp://x", policy, mode));
  };

  // Decision D-7: 100 per tier of the SDK's security ordering, plus 20 for SignAndEncrypt or 10 for Sign.
  EXPECT_EQ(score(ua::SecurityPolicyId::EccNistP256AesGcm, ua::MessageSecurityMode::SignAndEncrypt), 420);
  EXPECT_EQ(score(ua::SecurityPolicyId::EccCurve448ChaChaPoly, ua::MessageSecurityMode::SignAndEncrypt), 920);
  EXPECT_EQ(score(ua::SecurityPolicyId::RsaDhAesGcm, ua::MessageSecurityMode::Sign), 510);
  EXPECT_EQ(score(ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt), 120);
  EXPECT_EQ(score(ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::Sign), 110);
  EXPECT_EQ(score(ua::SecurityPolicyId::EccCurve448ChaChaPoly, ua::MessageSecurityMode::Invalid), 0)
    << "a mode outside the enumeration never wins on its policy";
  EXPECT_EQ(score(ua::SecurityPolicyId::Basic256, ua::MessageSecurityMode::Sign), 20);
  EXPECT_EQ(score(ua::SecurityPolicyId::None, ua::MessageSecurityMode::None), 2);
  EXPECT_EQ(score(ua::SecurityPolicyId::EccNistP256AesGcm, ua::MessageSecurityMode::None), 2)
    << "an unsecured endpoint scores as None/None whatever its policy (CL-DISC-019)";
  EXPECT_EQ(score(ua::SecurityPolicyId::None, ua::MessageSecurityMode::SignAndEncrypt), 2)
    << "an unsecured endpoint scores as None/None whatever its mode (CL-DISC-019)";

  EXPECT_GT(score(ua::SecurityPolicyId::EccNistP256AesGcm, ua::MessageSecurityMode::Sign),
    score(ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt))
    << "policy strength must dominate mode strength";
  EXPECT_GT(score(ua::SecurityPolicyId::EccBrainpoolP256r1AesGcm, ua::MessageSecurityMode::Sign),
    score(ua::SecurityPolicyId::EccNistP256AesGcm, ua::MessageSecurityMode::SignAndEncrypt))
    << "the NIST penalty applies on the client as on the server";
}

// Decision D-7: the client ranks policies in the order the server's securityLevel gives them, so a client
// and an SDK server agree on which of two secured endpoints is stronger. Every pair of secured policies, in
// each mode, compares the same way under both.
// @verifies AC-CL-DISC-019-RANKER-USES-THE-SDK-SECURITY-ORDER
TEST(EasyConnectDefaultRanker, RanksPoliciesInTheOrderOfTheServersSecurityLevel)
{
  std::vector<ua::SecurityPolicyId> secured;
  for (const auto id : ua::SecurityPolicy::supported_policy_ids())
  {
    if (ua::compute_security_level(ua::MessageSecurityMode::Sign, id) > 0)
      secured.push_back(id);
  }
  ASSERT_EQ(secured.size(), 17u) << "the three legacy RSA policies and the fourteen with enhancements";

  const auto order = [](int x, int y)
  {
    return x < y ? -1 : (x == y ? 0 : 1);
  };
  for (const auto mode : {ua::MessageSecurityMode::Sign, ua::MessageSecurityMode::SignAndEncrypt})
  {
    for (const auto a : secured)
    {
      for (const auto b : secured)
      {
        const int levelOrder =
          order(ua::compute_security_level(mode, a), ua::compute_security_level(mode, b));
        const int rankOrder =
          order(ua::client::default_easy_connect_ranker(make_endpoint("opc.tcp://x", a, mode)),
            ua::client::default_easy_connect_ranker(make_endpoint("opc.tcp://x", b, mode)));
        EXPECT_EQ(rankOrder, levelOrder)
          << static_cast<int>(a) << " vs " << static_cast<int>(b) << " in mode " << static_cast<int>(mode);
      }
    }
  }
}

TEST(EasyConnectDefaultRanker, UnsupportedPolicyScoresZero)
{
  ua::EndpointDescription endpoint;
  endpoint.security_policy_uri() = ua::String{"http://example.invalid/NotAPolicy"};
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;

  EXPECT_EQ(ua::client::default_easy_connect_ranker(endpoint), 0);
}

}  // namespace

// Decision 24: a server's GetEndpoints serverCertificate carries its issuer chain after the leaf. The
// easy-connect validation (and so the trust prompt's reason) must use that chain: validated without it, a
// server presenting its whole chain would be reported as ChainIncomplete instead of Untrusted. Found by the
// certificate-validation integration matrix (2026-10-02).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-144-EASY-CONNECT-PRESENTED-CHAIN, scope=function)
TEST(EasyConnectResolve, TheValidationReceivesTheIssuersPresentedAfterTheLeaf)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://chained", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};
  const auto intermediate = cert_with_thumbprint(0xBB);
  const auto root = cert_with_thumbprint(0xCC);
  harness.decodedIssuers = {intermediate, root};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good()) << ua::to_string(*result.shared_detail());
  EXPECT_EQ(harness.validateCalls, 1);
  ASSERT_EQ(harness.lastPresentedIssuers.size(), 2u);
  EXPECT_EQ(harness.lastPresentedIssuers[0], intermediate);
  EXPECT_EQ(harness.lastPresentedIssuers[1], root);
  EXPECT_EQ(result.value().config.serverCertificate, harness.decoded) << "the leaf is the server certificate";
}

// Control: a field holding the leaf alone presents no issuers.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-144-EASY-CONNECT-PRESENTED-CHAIN, scope=function)
TEST(EasyConnectResolve, ALeafAlonePresentsNoIssuers)
{
  Harness harness;
  harness.endpoints = {make_endpoint(
    "opc.tcp://leaf", ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt)};

  auto result = resolve(harness, policy_for());

  ASSERT_TRUE(result.is_good()) << ua::to_string(*result.shared_detail());
  EXPECT_EQ(harness.validateCalls, 1);
  EXPECT_TRUE(harness.lastPresentedIssuers.empty());
}
