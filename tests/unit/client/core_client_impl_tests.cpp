// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::CoreClientImpl reached through the public Client facade.
//
// CoreClientImpl is the client factory and per-connection owner; most of its work needs a live server. These
// tests exercise the synchronous-completion decision points that require no I/O: the open-channel URL-parse
// rejection, the reverse-connect open with no matching listener, and stopping an unknown reverse-connect
// handle. Each fires its result inline, so the blocking sync wrappers return a concrete error without any
// network activity.

#include <gtest/gtest.h>

#include "dev_factories.h"

#include "ua_core_client.h"

#include <boost/asio/thread_pool.hpp>

#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// A malformed endpoint URL is rejected at the synchronous URL-parse step, before any network work, with an
// ErrorDetail that names the failure.
TEST(ClientImplOpenChannel, MalformedEndpointUrlFailsSynchronously)
{
  boost::asio::thread_pool tp;
  auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

  ua::client::CoreClient::OpenChannelConfig config;
  config.endpointUrl = "http://not-an-opc-tcp-endpoint:4840";  // wrong scheme -> parse failure

  auto result = client.try_open_channel_sync(config);

  EXPECT_TRUE(result.is_bad()) << "a non opc.tcp URL must be rejected";
  EXPECT_NE(result.shared_detail(), nullptr)
    << "the parse failure must carry an ErrorDetail, not a bare status";

  // tp.join() would hang: Client holds perpetual executor work; the pool dtor stop()+join()s instead.
}

// Direct tier-0 channel opening is also a client-owned policy selection boundary. A deprecated policy is
// rejected before URL parsing / transport setup and carries the same actionable configuration detail.
// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientImplOpenChannel, DeprecatedPolicyRejectedByDefaultBeforeTransport)
{
  boost::asio::thread_pool tp;
  auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

  ua::client::CoreClient::OpenChannelConfig config;
  config.endpointUrl = "opc.tcp://must-not-be-opened.invalid:4840";
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::Basic256;

  auto result = client.try_open_channel_sync(config);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSecurityPolicyRejected});
  ASSERT_TRUE(result.shared_detail());
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_NE(detail.find("Basic256"), std::string::npos);
  EXPECT_NE(detail.find("AllowDeprecatedSecurityPolicies"), std::string::npos);
}

// A reverse-connect open with no listener registered for the endpoint fails inline with
// Bad_TcpEndpointUrlInvalid (the "no matching listener" synchronous-completion path).
TEST(ClientImplOpenChannel, ReverseConnectWithNoMatchingListenerFailsSynchronously)
{
  boost::asio::thread_pool tp;
  auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

  ua::client::CoreClient::OpenChannelConfig config;
  config.endpointUrl = "opc.tcp://localhost:4840";  // parses, but no reverse listener matches
  config.connectMode = ua::client::ConnectMode::Reverse;

  auto result = client.try_open_channel_sync(config);

  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadTcpEndpointUrlInvalid})
    << "reverse open must fail when no listener matches the endpoint";

  // tp.join() would hang: Client holds perpetual executor work; the pool dtor stop()+join()s instead.
}

// Stopping a reverse-connect listener by an unknown handle returns Bad_NotFound (the registry lookup miss
// path), with an ErrorDetail rather than a bare status.
TEST(ClientImplReverseConnect, StopUnknownHandleReturnsBadNotFound)
{
  boost::asio::thread_pool tp;
  auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

  ua::client::ReverseConnectHandle unknownHandle;
  unknownHandle.value = 4242;  // never returned by start_reverse_connect

  auto result = client.try_stop_reverse_connect_sync(unknownHandle);

  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadNotFound})
    << "an unknown reverse-connect handle must be reported as not found";
  EXPECT_NE(result.shared_detail(), nullptr) << "the not-found result must carry an ErrorDetail";

  // tp.join() would hang: Client holds perpetual executor work; the pool dtor stop()+join()s instead.
}

namespace
{

// Returns the value stored under ErrorDetail context key `key`, or nullopt if absent.
// (Mirrors the helper in tests/unit/client/namespace_table/namespace_table_tests.cpp:48.)
std::optional<std::string> context_value(const ua::ErrorDetail& detail, std::string_view key)
{
  for (const auto& namedValue : detail.context)
  {
    if (namedValue.key == key)
    {
      return namedValue.value;
    }
  }
  return std::nullopt;
}

}  // namespace

// @relation(AC-SVR-DISC-ADDR-002-CONFIGURABLE, scope=function)

// The endpoint URL that reaches the transport is the caller-supplied OpenChannelConfig::endpointUrl,
// threaded verbatim through the real open_channel_async path with NO hard-coded well-known LDS
// (opc.tcp://localhost:4840/UADiscovery) substitution: neither conjured from an empty URL nor
// rewritten over a distinctive administrator-supplied address.
// @verifies AC-CL-DISC-002-LDS-ADDRESS-CONFIGURABLE [PARTIAL] - the client's connect path
// (open_channel_async) honours the caller-supplied endpoint address verbatim and substitutes NO hard-coded
// well-known default (an administrator can therefore change the address). The requirement's LDS discovery
// facade (find_servers / find_servers_on_network) is unbuilt (tier-2/Phase-C), so the discovery-helper
// no-default facet is deferred to that phase - residual.
// @relation(AC-CL-DISC-002-LDS-ADDRESS-CONFIGURABLE, scope=function)
TEST(ClientImplOpenChannel, CallerSuppliedDiscoveryUrlHonouredNoHardcodedLdsDefault)
{
  boost::asio::thread_pool tp;
  auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

  // (A) Empty URL in Normal mode: the real open path rejects it synchronously at the URL-parse step. An
  // impl that quietly substitutes a well-known LDS default on empty input would instead try to connect
  // (and would not return a synchronous BadTcpEndpointUrlInvalid parse error).
  {
    ua::client::CoreClient::OpenChannelConfig config;
    config.endpointUrl = "";  // no default may be conjured from an empty URL

    auto result = client.try_open_channel_sync(config);

    EXPECT_TRUE(result.is_bad()) << "an empty endpoint URL must be rejected, not defaulted";
    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadTcpEndpointUrlInvalid})
      << "empty URL must fail synchronously at the parse step, not be replaced by a well-known LDS default";
    EXPECT_NE(result.shared_detail(), nullptr)
      << "the parse rejection must carry an ErrorDetail, not a bare status";
  }

  // (B) A distinctive administrator-supplied reverse-connect URL (non-well-known host lds.example.com,
  // port 14840) is threaded through unchanged. Reverse mode with no matching listener completes
  // synchronously via the NoMatchingListener path, which stamps the caller URL into the endpoint.url
  // ErrorDetail context. Exact-string equality FAILS against any impl that rewrites/substitutes the
  // well-known opc.tcp://localhost:4840/UADiscovery default (it would report localhost/4840 instead).
  {
    const std::string callerUrl = "opc.tcp://lds.example.com:14840/UADiscovery";
    ua::client::CoreClient::OpenChannelConfig config;
    config.endpointUrl = callerUrl;
    config.connectMode = ua::client::ConnectMode::Reverse;

    auto result = client.try_open_channel_sync(config);

    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadTcpEndpointUrlInvalid})
      << "reverse open with no matching listener must fail synchronously";
    ASSERT_NE(result.error_detail(), nullptr) << "the failure must carry an ErrorDetail";
    EXPECT_EQ(context_value(*result.error_detail(), "endpoint.url"), callerUrl)
      << "the administrator's LDS address must be honoured verbatim, never replaced by a hard-coded "
         "opc.tcp://localhost:4840/UADiscovery default";
  }

  // tp.join() would hang: Client holds perpetual executor work; the pool dtor stop()+join()s instead.
}

// Part 12 section 5.3.5: an application must not append the mDNS `local` top-level domain to any domain
// declared in its ApplicationInstance Certificate - the unqualified name is used instead. The reciprocal
// clause is what makes this bite: a client that reached the application through an LDS-ME is required to
// IGNORE `.local` when matching the discovered URL against the certificate, so a certificate declaring
// `opcua-host.local` is never matched against `opcua-host` and a correctly-provisioned pair fails
// certificate validation at the client. On an mDNS host the name handed to provisioning IS the `.local`
// name, and the plausible implementation copies the supplied host names into the subjectAltName verbatim -
// the provisioning call is the last place that can drop the suffix.
// @verifies AC-SVR-DISC-ADDR-005-NO-LOCAL-TLD
TEST(ClientImplCertificateProvisioning, ProvisionedCertificateDeclaresNoLocalTopLevelDomain)
{
  // The SDK's own provisioning provider. A private-key credential callback is required so the backend can
  // encrypt the generated PEM private key (the self-signed call fails without one).
  auto crypto = ua::create_default_crypto([]() { return ua::SecureString{"password"}; });
  ASSERT_TRUE(crypto);

  ua::Crypto::Name subject;
  subject.commonName = "DotLocal Provisioning Test";
  ua::Crypto::SubjectAlternateName san;
  san.hostnames.push_back("opcua-host.local");  // the mDNS name of the host being provisioned
  san.hostnames.push_back("OPCUA-ALT.LOCAL.");  // DNS comparison is case-insensitive; a final dot is legal
  san.uris.push_back("urn:opcua-host:test:application");

  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, ua::UtcTime{2050, 1, 1, 0, 0, 0}, san, ua::CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(result.is_good()) << "provisioning the application instance certificate must succeed";
  const auto certificate = std::move(result).value().second;
  ASSERT_NE(certificate, nullptr);

  const auto declaredDomains = certificate->san_hostnames();
  ASSERT_FALSE(declaredDomains.empty()) << "the certificate must declare the host it was provisioned for";

  // (A) No declared domain carries the `.local` top-level domain.
  constexpr std::string_view localSuffix{".local"};
  for (const auto& domain : declaredDomains)
  {
    const bool carriesLocalTld =
      domain.size() >= localSuffix.size() &&
      std::string_view{domain}.substr(domain.size() - localSuffix.size()) == localSuffix;
    EXPECT_FALSE(carriesLocalTld) << "declared domain '" << domain
                                  << "' carries the mDNS .local top-level domain";
  }

  // (B) The unqualified host name is declared in its place.
  bool unqualifiedDeclared = false;
  for (const auto& domain : declaredDomains)
  {
    if (domain == "opcua-host")
    {
      unqualifiedDeclared = true;
    }
  }
  EXPECT_TRUE(unqualifiedDeclared)
    << "the unqualified host name must be declared where the mDNS name was supplied";
  EXPECT_NE(std::find(declaredDomains.begin(), declaredDomains.end(), "OPCUA-ALT"), declaredDomains.end())
    << "the .local rule must also handle DNS case and the fully-qualified trailing dot";
}
