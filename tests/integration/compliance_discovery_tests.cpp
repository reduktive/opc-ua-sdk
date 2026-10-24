// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_application_description.h"
#include "ua_application_type.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_locale_id.h"
#include "ua_message_security_mode.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_registered_server.h"
#include "ua_session_discovery_services.h"
#include "ua_string.h"
#include "ua_user_token_policy.h"
#include "ua_x509_certificate.h"

#include "ua_client_secure_channel_test_access.h"

using ComplianceDiscovery = ComplianceBase;
using ComplianceDiscoverySecured = ComplianceSecured;

// ===========================================================================
// ComplianceDiscovery (basic None/None fixture)
// ===========================================================================

// Requirement: SVR-DISC-GEN-001 (SHALL)
// Every Server shall have a DiscoveryEndpoint that Clients can access without
// establishing a Session.
// Spec ref: Part 4, 5.4
// @relation(SVR-DISC-GEN-001, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GEN_001_DiscoveryEndpointAvailableWithoutSession)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  // Call GetEndpoints without creating a session
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_GE(resp.endpoints().size(), 1u);
  channel.close_sync();
}

// Requirement: SVR-DISC-GEN-004 (SHALL)
// The endpointUrl is used to provide the connection information.
// Spec ref: Part 4, 5.4
// @relation(SVR-DISC-GEN-004, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GEN_004_EndpointUrlProvidesConnectionInfo)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    std::string url = resp.endpoints()[i].endpoint_url();
    EXPECT_TRUE(url.find("opc.tcp://") == 0) << "Endpoint " << i << " URL: " << url;
    // URL should contain host:port
    EXPECT_NE(url.find(':'), std::string::npos) << "Endpoint " << i << " URL missing port: " << url;
  }
  channel.close_sync();
}

// Requirement: SVR-DISC-GEN-005 (SHALL)
// Discovery services shall operate without message security.
// Spec ref: Part 4, 5.4
// @relation(SVR-DISC-GEN-005, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GEN_005_NoMessageSecurityRequired)
{
  // We are on a None security channel
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  FindServersRequest fsReq;
  fsReq.endpoint_url() = mEndpointUrl;
  auto fsResp = channel.find_servers_sync(std::move(fsReq));
  EXPECT_THAT(fsResp, ::ua::test_helpers::ServiceResultIsGood());
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-002 (SHALL)
// FindServers endpoint shall exist.
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-002, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_002_FindServersEndpointExists)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-003 (SHALL)
// FindServers shall return an ApplicationDescription for the Server itself.
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-003, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_003_ServerReturnsSelfDescription)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.servers().size(), 1u) << "Server must return at least one ApplicationDescription";
  // First entry should be the server itself
  auto& server = resp.servers()[0];
  EXPECT_FALSE(server.application_uri().empty());
  EXPECT_EQ(server.application_type(), ApplicationType::Server);
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-006 (SHALL)
// The serverUri shall be globally unique. At minimum it must not be empty.
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-006, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_006_ServerUriNotEmpty)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.servers().size(), 1u);
  EXPECT_FALSE(resp.servers()[0].application_uri().empty()) << "ServerUri (applicationUri) must not be empty";
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-009 (SHALL)
// The serverUri returned by FindServers shall match ServerArray[0].
// Spec ref: Part 4, 5.4.2
// @relation(AC-SVR-DISC-FS-009-SERVERURI-MATCHES-ARRAY, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_009_ServerUriMatchesServerArrayIndex0)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // Get ServerUri from FindServers
  FindServersRequest fsReq;
  fsReq.endpoint_url() = mEndpointUrl;
  auto fsResp = channel.find_servers_sync(std::move(fsReq));
  ASSERT_THAT(fsResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(fsResp.servers().size(), 1u);
  std::string serverUri = fsResp.servers()[0].application_uri();

  // Get ServerArray[0] from the address space
  std::string serverArrayUri = mServer.server().address_space().server_array().get_server_uri(0);

  EXPECT_EQ(serverUri, serverArrayUri) << "FindServers applicationUri must match ServerArray[0]";
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-010 (SHALL)
// The Server shall have a human readable ServerName.
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-010, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_010_ServerNameNotEmpty)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.servers().size(), 1u);
  // application_name() is LocalizedText - check the text part
  EXPECT_FALSE(resp.servers()[0].application_name().text().empty()) << "ServerName must not be empty";
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-014 (SHALL)
// The Server shall use the endpointUrl to return accessible discoveryUrls.
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-014, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_014_DiscoveryUrlsContainAccessibleUrl)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.servers().size(), 1u);

  // discoveryUrls should contain at least one URL
  auto& urls = resp.servers()[0].discovery_urls();
  ASSERT_GE(urls.size(), 1u) << "discoveryUrls must not be empty";

  // At least one discovery URL should be opc.tcp
  bool found = false;
  for (size_t i = 0; i < urls.size(); ++i)
  {
    std::string url = urls[i];
    if (url.find("opc.tcp://") == 0)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "discoveryUrls should contain an opc.tcp:// URL";
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-015 (SHALL)
// FindServers shall not require message security.
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-015, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_015_FindServersNoMessageSecurityRequired)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  channel.close_sync();
}

// Requirement: SVR-DISC-FS-021 (SHALL)
// The Server shall ignore the authenticationToken if provided.
// We verify FindServers works without any session (no authenticationToken).
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-021, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_021_AuthenticationTokenIgnored)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_GE(resp.servers().size(), 1u);
  channel.close_sync();
}

// Requirement: SVR-DISC-GE-001 (SHALL)
// GetEndpoints shall not require message security.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-001, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GE_001_GetEndpointsNoMessageSecurityRequired)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  channel.close_sync();
}

// Requirement: SVR-DISC-GE-007 (SHALL)
// Each EndpointDescription shall include at least one UserIdentityToken.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-007, SVR-DISC-GE-UTP-001, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GE_007_UserIdentityTokensPresent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    EXPECT_GE(resp.endpoints()[i].user_identity_tokens().size(), 1u)
      << "Endpoint " << i << " must have at least one UserIdentityToken";
  }
  channel.close_sync();
}

// Requirement: SVR-DISC-GE-010 (SHALL)
// The Server shall use the endpointUrl to return accessible endpoint URLs.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-010, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GE_010_EndpointUrlAccessible)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    std::string url = resp.endpoints()[i].endpoint_url();
    EXPECT_FALSE(url.empty()) << "Endpoint " << i << " has empty URL";
    // The returned URL should be accessible - it should be opc.tcp
    EXPECT_TRUE(url.find("opc.tcp://") == 0) << "Endpoint " << i << " URL not opc.tcp: " << url;
  }
  channel.close_sync();
}

// Requirement: SVR-DISC-GE-018 (SHALL)
// The Server shall ignore the authenticationToken if provided for GetEndpoints.
// We verify GetEndpoints works without any session.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-018, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GE_018_AuthenticationTokenIgnored)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_GE(resp.endpoints().size(), 1u);
  channel.close_sync();
}

// Requirement: SVR-DISC-GE-020 (SHALL)
// If profileUris is specified, the Server shall return only endpoints matching
// the requested transport profile.
// This test may fail if profileUri filtering is not yet implemented.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-020, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_GE_020_ProfileUriFiltering)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // Request with matching profile URI
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  req.profile_uris().push_back(String{"http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"});
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_GE(resp.endpoints().size(), 1u) << "Should return endpoints matching the profile URI";

  // All returned endpoints should match the requested profile
  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    std::string profileUri = resp.endpoints()[i].transport_profile_uri();
    EXPECT_EQ(profileUri, "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
      << "Endpoint " << i << " has wrong transport profile";
  }

  // Request with non-matching profile URI - should return empty
  GetEndpointsRequest reqNoMatch;
  reqNoMatch.endpoint_url() = mEndpointUrl;
  reqNoMatch.profile_uris().push_back(String{"http://opcfoundation.org/UA-Profile/Transport/https-uabinary"});
  auto respNoMatch = channel.get_endpoints_sync(std::move(reqNoMatch));
  ASSERT_THAT(respNoMatch, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(respNoMatch.endpoints().size(), 0u) << "Should return no endpoints for non-matching profile URI";

  channel.close_sync();
}

// Requirement: SVR-DISC-FS-024 (SHALL)
// If the Server supports more than one of the requested locales then the Server
// shall use the locale that appears first in this list.
// This test may fail if locale filtering is not yet implemented.
// Spec ref: Part 4, section 5.4.2.2, line 1395
// @relation(SVR-DISC-FS-024, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscovery, DISC_FS_024_FirstMatchingLocaleUsed)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // Request with multiple locales - the server should prefer the first one it supports.
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  req.locale_ids().push_back(LocaleId{"en"});
  req.locale_ids().push_back(LocaleId{"de"});
  auto resp = channel.find_servers_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.servers().size(), 1u);

  auto firstLocaleResult = resp.servers()[0].application_name().locale();

  // Now request with reversed order
  FindServersRequest req2;
  req2.endpoint_url() = mEndpointUrl;
  req2.locale_ids().push_back(LocaleId{"de"});
  req2.locale_ids().push_back(LocaleId{"en"});
  auto resp2 = channel.find_servers_sync(std::move(req2));
  ASSERT_THAT(resp2, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp2.servers().size(), 1u);

  auto secondLocaleResult = resp2.servers()[0].application_name().locale();

  // If the server supports both locales, the results should differ (first match wins).
  // If the server only supports one locale, both results will be the same - that's acceptable
  // but we at least verify the server returned a non-empty application name.
  EXPECT_FALSE(resp.servers()[0].application_name().text().empty());
  EXPECT_FALSE(resp2.servers()[0].application_name().text().empty());

  // The key assertion: if results differ, the locale should match the first requested locale.
  // If they don't differ, the server only supports one locale - still compliant.
  if (firstLocaleResult != secondLocaleResult)
  {
    EXPECT_EQ(std::string{firstLocaleResult}, "en") << "When 'en' is first, server should return 'en' locale";
    EXPECT_EQ(std::string{secondLocaleResult}, "de")
      << "When 'de' is first, server should return 'de' locale";
  }
  channel.close_sync();
}

// ===========================================================================
// ComplianceDiscoverySecured (PKI fixture with multiple security endpoints)
// ===========================================================================

// Requirement: SVR-DISC-GE-005 (SHALL)
// The Server shall return a separate EndpointDescription for each security
// configuration.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-005, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_005_SeparateEndpointPerSecurityConfig)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  // Should have at least 3 endpoints (None, Sign, SignAndEncrypt)
  EXPECT_GE(resp.endpoints().size(), 3u) << "Expected at least 3 endpoints for different security configs";

  // Verify we have distinct security modes
  bool hasNone = false;
  bool hasSign = false;
  bool hasSignAndEncrypt = false;
  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto mode = resp.endpoints()[i].security_mode();
    if (mode == MessageSecurityMode::None)
      hasNone = true;
    if (mode == MessageSecurityMode::Sign)
      hasSign = true;
    if (mode == MessageSecurityMode::SignAndEncrypt)
      hasSignAndEncrypt = true;
  }
  EXPECT_TRUE(hasNone) << "Missing None endpoint";
  EXPECT_TRUE(hasSign) << "Missing Sign endpoint";
  EXPECT_TRUE(hasSignAndEncrypt) << "Missing SignAndEncrypt endpoint";
  channel.close_sync();
}

// Requirement: SVR-DISC-GE-005 (SHALL) - security policy URI correctness
// SecurityPolicyUri must be consistent with the security mode.
// Spec ref: Part 4, 5.4.4
// @relation(SVR-DISC-GE-005, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_005_SecurityPolicyUriCorrect)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto& ep = resp.endpoints()[i];
    std::string policyUri = ep.security_policy_uri();
    EXPECT_FALSE(policyUri.empty()) << "Endpoint " << i << " has empty securityPolicyUri";

    // Verify security policy matches security mode
    if (ep.security_mode() == MessageSecurityMode::None)
    {
      EXPECT_EQ(policyUri, "http://opcfoundation.org/UA/SecurityPolicy#None")
        << "None endpoint should have None security policy";
    }
    else
    {
      EXPECT_NE(policyUri, "http://opcfoundation.org/UA/SecurityPolicy#None")
        << "Signed/encrypted endpoint should not have None security policy";
    }
  }
  channel.close_sync();
}

// Server certificate must be present for secured endpoints.
// Spec ref: Part 4, 7.10
// @relation(SVR-DISC-GE-005, SVR-DISC-GE-EPD-003, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_ServerCertificatePresentForSecuredEndpoints)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto& ep = resp.endpoints()[i];
    if (ep.security_mode() != MessageSecurityMode::None)
    {
      EXPECT_FALSE(ep.server_certificate().empty())
        << "Endpoint " << i << " (secured) must have a server certificate";
    }
  }
  channel.close_sync();
}

// SecurityLevel should be > 0 for secured endpoints.
// This test may fail if security_level is not yet implemented (always returns 0).
// Spec ref: Part 4, 7.10
// @relation(SVR-DISC-GE-005, SVR-DISC-GE-EPD-001, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_SecurityLevelNonZeroForSecuredEndpoints)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto& ep = resp.endpoints()[i];
    if (ep.security_mode() == MessageSecurityMode::SignAndEncrypt)
    {
      EXPECT_GT(ep.security_level(), 0u)
        << "SignAndEncrypt endpoint " << i << " should have SecurityLevel > 0";
    }
  }
  channel.close_sync();
}

// TransportProfileUri should be present on all endpoints.
// Spec ref: Part 4, 7.10
// Covers SVR-TCP-031 (coverage-audit retag).
// @relation(SVR-DISC-GE-005, SVR-DISC-GE-EPD-002, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_TransportProfileUriPresent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    std::string profileUri = resp.endpoints()[i].transport_profile_uri();
    EXPECT_EQ(profileUri, "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
      << "Endpoint " << i << " should have UA TCP transport profile";
  }
  channel.close_sync();
}

// ApplicationDescription must be consistent between FindServers and GetEndpoints.
// Spec ref: Part 4, 5.4
// @relation(SVR-DISC-GEN-011, SVR-DISC-GEN-017, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_ApplicationDescriptionConsistentBetweenServices)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  FindServersRequest fsReq;
  fsReq.endpoint_url() = mEndpointUrl;
  auto fsResp = channel.find_servers_sync(std::move(fsReq));
  ASSERT_THAT(fsResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(fsResp.servers().size(), 1u);

  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = channel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(geResp.endpoints().size(), 1u);

  // ApplicationUri should match
  std::string findUri = fsResp.servers()[0].application_uri();
  std::string epUri = geResp.endpoints()[0].server().application_uri();
  EXPECT_EQ(findUri, epUri) << "ApplicationUri must be consistent between FindServers and GetEndpoints";

  // ProductUri should match
  std::string findProduct = fsResp.servers()[0].product_uri();
  std::string epProduct = geResp.endpoints()[0].server().product_uri();
  EXPECT_EQ(findProduct, epProduct);

  channel.close_sync();
}

// Requirement: SVR-DISC-FS-009 (SHALL) on secured fixture
// The serverUri returned by FindServers shall match ServerArray[0].
// Spec ref: Part 4, 5.4.2
// @relation(SVR-DISC-FS-009, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_FS_009_ServerUriMatchesServerArrayIndex0)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  FindServersRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.find_servers_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.servers().size(), 1u);

  std::string serverUri = resp.servers()[0].application_uri();
  std::string serverArrayUri = mServer->address_space().server_array().get_server_uri(0);
  EXPECT_EQ(serverUri, serverArrayUri);
  channel.close_sync();
}

// Requirement: SVR-DISC-GEN-016 (SHALL)
// Servers shall add all possible HostNames (including IP addresses) into the
// Server Certificate. The endpoint URL hostname should appear in the cert SAN.
// Spec ref: Part 4, section 5.4.1, line 1329
// @relation(SVR-DISC-GEN-016, SVR-DISC-MDL-003, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GEN_016_ServerCertContainsEndpointHostname)
{
  ASSERT_NE(mServerCert, nullptr);

  // Extract hostname from endpoint URL (e.g. "opc.tcp://127.0.0.1:12345" -> "127.0.0.1")
  auto urlStr = mEndpointUrl;
  // Strip scheme
  auto hostStart = urlStr.find("://");
  ASSERT_NE(hostStart, std::string::npos);
  hostStart += 3;
  auto hostEnd = urlStr.find(':', hostStart);
  if (hostEnd == std::string::npos)
    hostEnd = urlStr.size();
  auto hostname = urlStr.substr(hostStart, hostEnd - hostStart);

  // Check if the hostname appears in the cert SAN (either as hostname or IP)
  auto sanHostnames = mServerCert->san_hostnames();
  auto sanIps = mServerCert->san_ip_addresses();

  bool found = false;
  for (const auto& h : sanHostnames)
  {
    if (h == hostname)
    {
      found = true;
      break;
    }
  }
  if (!found)
  {
    // Check IP addresses
    for (const auto& ip : sanIps)
    {
      if (ip.to_string() == hostname)
      {
        found = true;
        break;
      }
    }
  }

  EXPECT_TRUE(found) << "Server certificate SAN should contain endpoint hostname '" << hostname
                     << "'. SANs: hostnames=" << sanHostnames.size() << ", IPs=" << sanIps.size();
}

// GetEndpoints ApplicationDescription fields should be fully populated.
// Spec ref: Part 4, 7.1, 7.10
// @relation(SVR-DISC-GEN-011, scope=function)
TEST_F(ComplianceDiscoverySecured, DISC_GE_ApplicationDescriptionFieldsPopulated)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto& server = resp.endpoints()[i].server();
    EXPECT_FALSE(server.application_uri().empty()) << "Endpoint " << i << " missing applicationUri";
    EXPECT_FALSE(server.product_uri().empty()) << "Endpoint " << i << " missing productUri";
    EXPECT_FALSE(server.application_name().text().empty()) << "Endpoint " << i << " missing applicationName";
    EXPECT_EQ(server.application_type(), ApplicationType::Server)
      << "Endpoint " << i << " wrong applicationType";
  }
  channel.close_sync();
}

// UACTT mirror - fast native reproduction of a compliance-tool finding.

// Covers DISC-FS (serverUris filter) (CTT Discovery Find Servers Filter/004,007,008)
//
// UACTT finding F2: FindServers must apply the optional serverUris filter to the server's OWN
// ApplicationDescription, not just to registered (LDS) servers. The server previously always pushed
// its own entry, so a non-matching filter still returned it (CTT: "Expected <0> but got <1>").
// Part 4 section 5.4.2 / Part 12 section 4.3: a serverUris filter returns only servers whose ServerUri
// matches.
TEST_F(ComplianceDiscovery, Mirror_FindServers_ServerUriFilter_ExcludesNonMatching)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // Learn the server's own ServerUri (applicationUri).
  FindServersRequest selfReq;
  selfReq.endpoint_url() = mEndpointUrl;
  auto selfResp = channel.find_servers_sync(std::move(selfReq));
  ASSERT_THAT(selfResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(selfResp.servers().size(), 1u);
  const std::string ownUri{selfResp.servers()[0].application_uri()};

  // A non-matching serverUris filter must exclude the server itself -> zero results.
  FindServersRequest noMatch;
  noMatch.endpoint_url() = mEndpointUrl;
  noMatch.server_uris().payload().push_back(String{"urn:reduktive:no-such-server:does-not-match"});
  auto noMatchResp = channel.find_servers_sync(std::move(noMatch));
  ASSERT_THAT(noMatchResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(noMatchResp.servers().size(), 0u)
    << "FindServers with a non-matching serverUris filter must return no servers (UACTT F2)";

  // A matching serverUris filter must still return the server.
  FindServersRequest match;
  match.endpoint_url() = mEndpointUrl;
  match.server_uris().payload().push_back(String{ownUri});
  auto matchResp = channel.find_servers_sync(std::move(match));
  ASSERT_THAT(matchResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(matchResp.servers().size(), 1u)
    << "FindServers with a matching serverUris filter must return the server";

  channel.close_sync();
}

// Covers DISC-GE (endpointUrl is a hint) (CTT Discovery Get Endpoints/010,012)
// Part 4 section 5.4.4: an endpointUrl matching no listener must return the default endpoint set.
TEST_F(ComplianceDiscovery, Mirror_GetEndpoints_InvalidEndpointUrl_ReturnsDefaults)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // Baseline: a matching endpointUrl returns the full endpoint set.
  GetEndpointsRequest matchReq;
  matchReq.endpoint_url() = mEndpointUrl;
  auto matchResp = channel.get_endpoints_sync(std::move(matchReq));
  ASSERT_THAT(matchResp, ::ua::test_helpers::ServiceResultIsGood());
  const auto defaultCount = matchResp.endpoints().size();
  ASSERT_GE(defaultCount, 1u);

  // An endpointUrl that matches no listener (different port + path) must fall back to the
  // default set rather than returning nothing.
  GetEndpointsRequest noMatch;
  noMatch.endpoint_url() = String{"opc.tcp://127.0.0.1:59999/no-such-endpoint"};
  auto noMatchResp = channel.get_endpoints_sync(std::move(noMatch));
  ASSERT_THAT(noMatchResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(noMatchResp.endpoints().size(), defaultCount)
    << "GetEndpoints with an unmatched endpointUrl must return the default endpoint set (UACTT F3)";

  channel.close_sync();
}

// ===========================================================================
// Session-less services must ignore an authenticationToken (FindServers / GetEndpoints)
// ===========================================================================

// Part 4 section 5.4.2.2: FindServers is a Session-less service, so an authenticationToken carried in
// the RequestHeader is ignored - never validated. A plausible implementation routes every request
// that carries a token through session lookup first and answers Bad_SessionIdInvalid when the token
// names no session; that breaks discovery for exactly the client whose session has just expired and
// is re-discovering. The falsifying case is therefore a token the server cannot resolve, asserted
// alongside a token that IS resolvable so that "served identically" is observed, not assumed.
// @verifies AC-SVR-DISC-FS-021-AUTHTOKEN-IGNORED
TEST_F(ComplianceDiscovery, DISC_FS_021_FindServersServedIdenticallyWithValidAndInvalidAuthenticationToken)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // Baseline: no authenticationToken at all.
  FindServersRequest bare;
  bare.endpoint_url() = mEndpointUrl;
  auto bareResp = channel.find_servers_sync(std::move(bare));
  ASSERT_THAT(bareResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(bareResp.servers().size(), 1u) << "baseline FindServers must return the server itself";

  // Invalid token: an opaque NodeId that names no session on this server.
  FindServersRequest bogusToken;
  bogusToken.endpoint_url() = mEndpointUrl;
  bogusToken.request_header().authentication_token() = NodeId{uint16_t{0}, Guid::create_and_generate()};
  auto bogusResp = channel.find_servers_sync(std::move(bogusToken));
  EXPECT_THAT(bogusResp, ::ua::test_helpers::ServiceResultIsGood())
    << "FindServers must ignore an unresolvable authenticationToken, not reject on it";
  ASSERT_EQ(bogusResp.servers().size(), bareResp.servers().size())
    << "an ignored token must not change the FindServers result";
  for (size_t i = 0; i < bareResp.servers().size(); ++i)
  {
    EXPECT_EQ(std::string{bogusResp.servers()[i].application_uri()},
      std::string{bareResp.servers()[i].application_uri()})
      << "server " << i << " differs when an invalid authenticationToken is supplied";
  }

  // Valid token: the session service accessor stamps the live session's authenticationToken on the
  // outbound header, so this is a genuinely resolvable token rather than one fabricated by the test.
  auto session = channel.create_session_sync({.sessionName = "DiscoveryAuthTokenFindServers"});
  session.activate_sync();

  FindServersRequest validToken;
  validToken.endpoint_url() = mEndpointUrl;
  auto validResp = session.discovery().find_servers_sync(std::move(validToken));
  EXPECT_THAT(validResp, ::ua::test_helpers::ServiceResultIsGood())
    << "FindServers must be served when a valid authenticationToken is supplied";
  ASSERT_EQ(validResp.servers().size(), bareResp.servers().size())
    << "a valid token must be ignored, giving the same FindServers result";
  for (size_t i = 0; i < bareResp.servers().size(); ++i)
  {
    EXPECT_EQ(std::string{validResp.servers()[i].application_uri()},
      std::string{bareResp.servers()[i].application_uri()})
      << "server " << i << " differs when a valid authenticationToken is supplied";
  }

  (void)session.try_close_sync();
  channel.close_sync();
}

// Part 4 section 5.4.4.2: GetEndpoints is Session-less; the authenticationToken is null in a conforming
// request and must be ignored when a client supplies one anyway. The same session-lookup-first
// implementation error that breaks FindServers breaks GetEndpoints, and there it is worse: a client
// re-reading endpoints after a session drops cannot recover. Both a resolvable and an unresolvable
// token are driven, and the whole endpoint set is compared - a server that answers but silently
// narrows the set under a token is not serving the call identically.
// @verifies AC-SVR-DISC-GE-018-AUTHTOKEN-IGNORED
TEST_F(ComplianceDiscovery, DISC_GE_018_GetEndpointsServedIdenticallyWithValidAndInvalidAuthenticationToken)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  GetEndpointsRequest bare;
  bare.endpoint_url() = mEndpointUrl;
  auto bareResp = channel.get_endpoints_sync(std::move(bare));
  ASSERT_THAT(bareResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(bareResp.endpoints().size(), 1u) << "baseline GetEndpoints must return at least one endpoint";

  GetEndpointsRequest bogusToken;
  bogusToken.endpoint_url() = mEndpointUrl;
  bogusToken.request_header().authentication_token() = NodeId{uint16_t{0}, Guid::create_and_generate()};
  auto bogusResp = channel.get_endpoints_sync(std::move(bogusToken));
  EXPECT_THAT(bogusResp, ::ua::test_helpers::ServiceResultIsGood())
    << "GetEndpoints must ignore an unresolvable authenticationToken, not reject on it";
  ASSERT_EQ(bogusResp.endpoints().size(), bareResp.endpoints().size())
    << "an ignored token must not change the endpoint set";
  for (size_t i = 0; i < bareResp.endpoints().size(); ++i)
  {
    EXPECT_EQ(std::string{bogusResp.endpoints()[i].endpoint_url()},
      std::string{bareResp.endpoints()[i].endpoint_url()})
      << "endpoint " << i << " url differs when an invalid authenticationToken is supplied";
    EXPECT_EQ(bogusResp.endpoints()[i].security_mode(), bareResp.endpoints()[i].security_mode())
      << "endpoint " << i << " security mode differs when an invalid authenticationToken is supplied";
  }

  auto session = channel.create_session_sync({.sessionName = "DiscoveryAuthTokenGetEndpoints"});
  session.activate_sync();

  GetEndpointsRequest validToken;
  validToken.endpoint_url() = mEndpointUrl;
  auto validResp = session.discovery().get_endpoints_sync(std::move(validToken));
  EXPECT_THAT(validResp, ::ua::test_helpers::ServiceResultIsGood())
    << "GetEndpoints must be served when a valid authenticationToken is supplied";
  ASSERT_EQ(validResp.endpoints().size(), bareResp.endpoints().size())
    << "a valid token must be ignored, giving the same endpoint set";
  for (size_t i = 0; i < bareResp.endpoints().size(); ++i)
  {
    EXPECT_EQ(std::string{validResp.endpoints()[i].endpoint_url()},
      std::string{bareResp.endpoints()[i].endpoint_url()})
      << "endpoint " << i << " url differs when a valid authenticationToken is supplied";
    EXPECT_EQ(validResp.endpoints()[i].security_mode(), bareResp.endpoints()[i].security_mode())
      << "endpoint " << i << " security mode differs when a valid authenticationToken is supplied";
  }

  (void)session.try_close_sync();
  channel.close_sync();
}

// Part 4 section 5.4.4.1: a UserTokenPolicy in an EndpointDescription exists so a client can build a
// token ActivateSession will accept. Presence of the array is not enough - a description that omits
// the policyId the client must echo back, or leaves the user-token security policy unstated, tells
// the client nothing it can act on. This drives the description end to end: every advertised policy
// is read, its three required fields are asserted, and the advertised policyId is then used to
// activate a session, so the "sufficient to construct an accepted token" claim is observed rather
// than inferred from a non-empty array.
// @verifies AC-SVR-DISC-GE-007-TOKEN-TYPES-DESCRIBED
TEST_F(ComplianceDiscovery, DISC_GE_007_EveryDescribedUserIdentityTokenIsSufficientToActivate)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.endpoints().size(), 1u) << "the server must advertise at least one endpoint";

  size_t describedPolicies = 0;
  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto& tokens = resp.endpoints()[i].user_identity_tokens();
    ASSERT_GE(tokens.size(), 1u) << "Endpoint " << i << " describes no user identity token";

    for (size_t j = 0; j < tokens.size(); ++j)
    {
      auto& policy = tokens[j];
      ++describedPolicies;

      std::string policyId = policy.policy_id();
      EXPECT_FALSE(policyId.empty()) << "Endpoint " << i << " token " << j
                                     << " has no policyId for the client to echo back";

      // The fixture endpoint advertises exactly one configured policy: Anonymous over the None
      // user-token security policy. Both must be reported as configured, not left at a placeholder.
      EXPECT_EQ(policy.token_type(), UserTokenType::Anonymous)
        << "Endpoint " << i << " token " << j << " reports a token type the endpoint does not accept";
      EXPECT_EQ(std::string{policy.security_policy_uri()}, "http://opcfoundation.org/UA/SecurityPolicy#None")
        << "Endpoint " << i << " token " << j << " does not name the user-token security policy";

      if (policyId.empty())
        continue;

      // Use the description: activate with the advertised policyId. A description is only
      // sufficient if a token built from it is accepted.
      auto session = channel.create_session_sync({.sessionName = "DiscoveryTokenPolicy"});
      ua::client::Session::ActivateConfig activateConfig;
      activateConfig.policyId = policyId;
      activateConfig.identity = ua::client::AnonymousIdentity{};
      auto activated = session.try_activate_sync(std::move(activateConfig));
      EXPECT_THAT(activated, ::ua::test_helpers::Good())
        << "activation with the advertised policyId '" << policyId << "' (endpoint " << i << ", token " << j
        << ") must be accepted";
      (void)session.try_close_sync();
    }
  }
  ASSERT_GT(describedPolicies, 0u) << "no user token policy was described, nothing was asserted";

  channel.close_sync();
}

// ===========================================================================
// ComplianceDiscoveryNamedServer - the operator-configured ServerName, on the wire
// ===========================================================================

// The ApplicationIdentity is immutable once the server exists, so a distinctive, deliberately
// non-unique human-readable name has to be set through the creation-time identity hook.
class ComplianceDiscoveryNamedServer : public ComplianceBase
{
protected:
  // A name an operator would recognise on a plant floor. Deliberately unrelated to the
  // applicationUri: a server that derives the name from the URI to make it unique is the failure
  // this criterion is about.
  static constexpr std::string_view sServerName{"Reduktive Line 4 Bottling Server"};

  void configure_application_identity(ua::ApplicationIdentity& identity) override
  {
    identity.applicationName = ua::LocalizedText{"en", std::string{sServerName}};
  }
};

// Part 4 section 5.4.2.1: the ServerName is the human-readable ApplicationDescription.applicationName,
// and it is explicitly NOT required to be unique - uniqueness is the serverUri's job. An
// implementation that synthesises a name (from the URI, the host, or a GUID) to be safe satisfies
// "non-empty" while producing a name no operator recognises, which defeats the field's only purpose.
// The check is therefore that the configured text is what reaches the wire, on both discovery
// surfaces, and that it is not the applicationUri wearing a name's clothes.
// @verifies AC-SVR-DISC-FS-010-SERVERNAME
TEST_F(ComplianceDiscoveryNamedServer, DISC_FS_010_ServerNameIsTheConfiguredHumanReadableName)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  FindServersRequest fsReq;
  fsReq.endpoint_url() = mEndpointUrl;
  auto fsResp = channel.find_servers_sync(std::move(fsReq));
  ASSERT_THAT(fsResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(fsResp.servers().size(), 1u) << "FindServers must describe the server itself";

  auto& self = fsResp.servers()[0];
  EXPECT_FALSE(std::string{self.application_name().text()}.empty()) << "ServerName must not be empty";
  EXPECT_EQ(std::string{self.application_name().text()}, std::string{sServerName})
    << "FindServers must report the operator-configured ServerName verbatim";
  EXPECT_NE(std::string{self.application_name().text()}, std::string{self.application_uri()})
    << "ServerName must be a human-readable name, not the applicationUri restated for uniqueness";

  // The same name has to reach the other surface that carries an ApplicationDescription.
  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = channel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(geResp.endpoints().size(), 1u);
  for (size_t i = 0; i < geResp.endpoints().size(); ++i)
  {
    EXPECT_EQ(std::string{geResp.endpoints()[i].server().application_name().text()}, std::string{sServerName})
      << "Endpoint " << i << " reports a different ServerName than FindServers";
  }

  channel.close_sync();
}

// ===========================================================================
// ComplianceDiscoveryLds - a server-as-LDS holding a record with several localised names
// ===========================================================================

// Locale selection is only observable where more than one localised name exists for one described
// server. The self-description carries a single LocalizedText, so the record under test is an
// inbound LDS registration, which carries a serverNames array.
class ComplianceDiscoveryLds : public ComplianceSecured
{
protected:
  // The applicationUri in the ComplianceSecured client certificate SAN. An inbound registration is
  // accepted only when the registered serverUri equals the peer certificate's applicationUri
  // (Part 4 section 5.4.5.1), so the registered record must carry exactly this URI.
  static constexpr std::string_view sRegisteredServerUri{"urn:test:compliance:client"};
  static constexpr std::string_view sGermanName{"Abfuellanlage Linie 4"};
  static constexpr std::string_view sFrenchName{"Ligne d'embouteillage 4"};

  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.localDiscoveryServer.enabled = true;
  }
};

// Part 4 section 5.4.2.1: when the server supports more than one of the requested locales it shall use
// the one appearing FIRST in the client's list - priority order, not the server's own preference and
// not the best match by any other measure. A plausible implementation returns the first name it
// holds (or its own default locale) and looks correct whenever the two orders happen to agree, so
// the record here declares "de" before "fr" and the request asks for an unsupported locale first:
// "first declared" and "first requested" give different answers, and the request order is then
// reversed so a fixed preference cannot pass both halves.
// @verifies AC-SVR-DISC-FS-024-FIRST-MATCHING-LOCALE
TEST_F(ComplianceDiscoveryLds, DISC_FS_024_FirstRequestedLocaleTheServerSupportsIsUsed)
{
  // Register a server whose name exists in German and in French, declared in that order.
  {
    auto secured = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = mServerCert});

    ua::RegisteredServer registered;
    registered.server_uri() = ua::String{std::string{sRegisteredServerUri}};
    registered.product_uri() = ua::String{"urn:test:compliance:registered:product"};
    registered.server_type() = ua::ApplicationType::Server;
    registered.server_names().payload().push_back(
      ua::LocalizedText{ua::String{"de"}, ua::String{std::string{sGermanName}}});
    registered.server_names().payload().push_back(
      ua::LocalizedText{ua::String{"fr"}, ua::String{std::string{sFrenchName}}});
    registered.discovery_urls().payload().push_back(ua::String{"opc.tcp://registered-server:4840"});
    registered.is_online() = true;

    RegisterServerRequest regReq;
    regReq.server() = std::move(registered);
    auto regResp = secured.register_server_sync(std::move(regReq));
    ASSERT_THAT(regResp, ::ua::test_helpers::ServiceResultIsGood())
      << "the registration the locale assertions rely on must be accepted";
    secured.close_sync();
  }

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  // "es" is not supported; "fr" is the first supported locale in this list, so "fr" must be used
  // even though "de" is the first name the record declares.
  FindServersRequest frFirst;
  frFirst.endpoint_url() = mEndpointUrl;
  frFirst.locale_ids().push_back(LocaleId{"es"});
  frFirst.locale_ids().push_back(LocaleId{"fr"});
  frFirst.locale_ids().push_back(LocaleId{"de"});
  auto frResp = channel.find_servers_sync(std::move(frFirst));
  ASSERT_THAT(frResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(frResp.servers().size(), 1u);

  ApplicationDescription* frEntry = nullptr;
  for (size_t i = 0; i < frResp.servers().size(); ++i)
  {
    if (std::string{frResp.servers()[i].application_uri()} == std::string{sRegisteredServerUri})
      frEntry = &frResp.servers()[i];
  }
  ASSERT_NE(frEntry, nullptr) << "the registered server must be listed by FindServers";
  EXPECT_EQ(std::string{frEntry->application_name().locale()}, "fr")
    << "the first requested locale the server supports ('fr') must be the one used";
  EXPECT_EQ(std::string{frEntry->application_name().text()}, std::string{sFrenchName})
    << "the name returned must be the one belonging to the selected locale";

  // Reverse the priority: now "de" is the first supported locale, so "de" must be used.
  FindServersRequest deFirst;
  deFirst.endpoint_url() = mEndpointUrl;
  deFirst.locale_ids().push_back(LocaleId{"es"});
  deFirst.locale_ids().push_back(LocaleId{"de"});
  deFirst.locale_ids().push_back(LocaleId{"fr"});
  auto deResp = channel.find_servers_sync(std::move(deFirst));
  ASSERT_THAT(deResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(deResp.servers().size(), 1u);

  ApplicationDescription* deEntry = nullptr;
  for (size_t i = 0; i < deResp.servers().size(); ++i)
  {
    if (std::string{deResp.servers()[i].application_uri()} == std::string{sRegisteredServerUri})
      deEntry = &deResp.servers()[i];
  }
  ASSERT_NE(deEntry, nullptr) << "the registered server must be listed by FindServers";
  EXPECT_EQ(std::string{deEntry->application_name().locale()}, "de")
    << "with the priority reversed, 'de' is the first supported locale and must be the one used";
  EXPECT_EQ(std::string{deEntry->application_name().text()}, std::string{sGermanName})
    << "the name returned must be the one belonging to the selected locale";

  channel.close_sync();
}

// ===========================================================================
// ComplianceDiscoveryTokenPolicies - one endpoint publishing every user token type
// ===========================================================================

// The shared fixtures advertise a single Anonymous policy per endpoint, which can show neither a
// policyId collision nor an issued-token field. This adds a fourth endpoint carrying four policies:
// Anonymous, UserName, Certificate, and an IssuedToken whose issuedTokenType and issuerEndpointUrl
// the operator supplied. The endpoint is added through the ordinary configuration API, so the
// published description is the server's own rendering of that configuration, not the test's.
class ComplianceDiscoveryTokenPolicies : public ComplianceSecured
{
protected:
  static constexpr std::string_view sIssuedTokenType{"http://opcfoundation.org/UA/UserToken#JWT"};
  static constexpr std::string_view sIssuerEndpointUrl{"https://issuer.reduktive.test/oauth2/token"};

  void SetUp() override
  {
    ComplianceSecured::SetUp();
    ASSERT_TRUE(mServer.has_value());

    ServerEndpointConfig endpoint;
    endpoint.name = "Basic256Sha256_SignAndEncrypt_AllTokenTypes";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256));
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256));

    UserTokenPolicy issued =
      create_user_token_policy(UserTokenType::IssuedToken, SecurityPolicyId::Basic256Sha256);
    issued.issued_token_type() = String{std::string{sIssuedTokenType}};
    issued.issuer_endpoint_url() = String{std::string{sIssuerEndpointUrl}};
    endpoint.userIdentityTokens.push_back(std::move(issued));

    mServer->add_endpoint(mListenerHandle, std::move(endpoint));
  }
};

// Part 4 section 7.42: a UserTokenPolicy is only usable if every field its token type requires is
// filled in. policyId is what the client echoes back in its identity token, so it must be present and
// unique WITHIN the endpoint - a server that derives the id from the token type alone, or reuses one
// literal across the policies of an endpoint, cannot tell which policy the client selected, and the
// endpoint still looks well formed to a test that only counts policies. The issued-token pair is the
// mirror image: issuedTokenType and issuerEndpointUrl tell the client where to obtain the token, so an
// implementation that rebuilds the published policy from (tokenType, securityPolicyUri) silently drops
// them, and one that copies a template onto every policy names an issuer on Anonymous. Both halves are
// asserted here - populated for the issued policy, absent on every other policy the server publishes.
// @verifies AC-SVR-DISC-GE-UTP-001-POLICY-FIELDS
TEST_F(ComplianceDiscoveryTokenPolicies, DISC_GE_UTP_001_EveryPublishedUserTokenPolicyIsFullyDescribed)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.endpoints().size(), 1u) << "no endpoint was published, so nothing would be asserted";

  size_t inspectedPolicies = 0;
  bool foundRichEndpoint = false;
  size_t richEndpointIndex = 0;

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    auto& ep = resp.endpoints()[i];
    auto& tokens = ep.user_identity_tokens();
    ASSERT_GE(tokens.size(), 1u) << "Endpoint " << i << " publishes no user token policy";

    std::vector<std::string> seenPolicyIds;
    for (size_t j = 0; j < tokens.size(); ++j)
    {
      auto& policy = tokens[j];
      ++inspectedPolicies;

      const std::string policyId{policy.policy_id()};
      EXPECT_FALSE(policyId.empty()) << "Endpoint " << i << " token " << j
                                     << " publishes no policyId for the client to echo back";
      for (const auto& seen : seenPolicyIds)
      {
        EXPECT_NE(seen, policyId) << "Endpoint " << i << " publishes policyId '" << policyId
                                  << "' twice; the server cannot tell which policy a client selected";
      }
      seenPolicyIds.push_back(policyId);

      const std::string issuedTokenType{policy.issued_token_type()};
      const std::string issuerEndpointUrl{policy.issuer_endpoint_url()};
      if (policy.token_type() == UserTokenType::IssuedToken)
      {
        foundRichEndpoint = true;
        richEndpointIndex = i;
        EXPECT_EQ(issuedTokenType, std::string{sIssuedTokenType})
          << "Endpoint " << i << " token " << j
          << " is an issued token but does not name the configured issuedTokenType";
        EXPECT_EQ(issuerEndpointUrl, std::string{sIssuerEndpointUrl})
          << "Endpoint " << i << " token " << j
          << " is an issued token but does not name the configured issuerEndpointUrl";
      }
      else
      {
        EXPECT_TRUE(issuedTokenType.empty())
          << "Endpoint " << i << " token " << j << " is not an issued token but names issuedTokenType '"
          << issuedTokenType << "'";
        EXPECT_TRUE(issuerEndpointUrl.empty())
          << "Endpoint " << i << " token " << j << " is not an issued token but names issuerEndpointUrl '"
          << issuerEndpointUrl << "'";
      }
    }
  }
  ASSERT_GT(inspectedPolicies, 0u) << "no user token policy was inspected, nothing was asserted";
  ASSERT_TRUE(foundRichEndpoint)
    << "the endpoint configured with an IssuedToken policy was not published at all";

  // tokenType must name the type that was configured: the four configured policies appear on the
  // published endpoint exactly once each, paired with the security policy each was configured with.
  auto& richTokens = resp.endpoints()[richEndpointIndex].user_identity_tokens();
  ASSERT_EQ(richTokens.size(), 4u) << "the endpoint configured with four user token policies published "
                                   << richTokens.size();
  EXPECT_EQ(resp.endpoints()[richEndpointIndex].security_mode(), MessageSecurityMode::SignAndEncrypt)
    << "the endpoint carrying the four token policies is the SignAndEncrypt one";

  size_t anonymousCount = 0;
  size_t userNameCount = 0;
  size_t certificateCount = 0;
  size_t issuedTokenCount = 0;
  for (size_t j = 0; j < richTokens.size(); ++j)
  {
    auto& policy = richTokens[j];
    const std::string tokenSecurityPolicy{policy.security_policy_uri()};
    switch (policy.token_type())
    {
    case UserTokenType::Anonymous:
      ++anonymousCount;
      EXPECT_EQ(tokenSecurityPolicy, "http://opcfoundation.org/UA/SecurityPolicy#None")
        << "token " << j << " is reported as Anonymous but not with the policy it was configured with";
      break;
    case UserTokenType::UserName:
      ++userNameCount;
      EXPECT_EQ(tokenSecurityPolicy, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
        << "token " << j << " is reported as UserName but not with the policy it was configured with";
      break;
    case UserTokenType::Certificate:
      ++certificateCount;
      EXPECT_EQ(tokenSecurityPolicy, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
        << "token " << j << " is reported as Certificate but not with the policy it was configured with";
      break;
    case UserTokenType::IssuedToken:
      ++issuedTokenCount;
      EXPECT_EQ(tokenSecurityPolicy, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
        << "token " << j << " is reported as IssuedToken but not with the policy it was configured with";
      break;
    }
  }
  EXPECT_EQ(anonymousCount, 1u) << "the configured Anonymous policy is not published exactly once";
  EXPECT_EQ(userNameCount, 1u) << "the configured UserName policy is not published exactly once";
  EXPECT_EQ(certificateCount, 1u) << "the configured Certificate policy is not published exactly once";
  EXPECT_EQ(issuedTokenCount, 1u) << "the configured IssuedToken policy is not published exactly once";

  channel.close_sync();
}

// ===========================================================================
// CreateSession's serverEndpoints against the unsecured GetEndpoints result
// ===========================================================================

namespace
{

// The serverEndpoints array only exists on the raw CreateSessionResponse, so the response is captured
// through the channel's one-shot observer while the ordinary create_session_sync call runs.
struct DiscoveryCreateSessionCapture
{
  Session session;
  CreateSessionResponse response;
};

DiscoveryCreateSessionCapture create_session_capturing_response(
  SecureChannel& channel, SecureChannel::CreateSessionConfig config)
{
  std::optional<CreateSessionResponse> captured;
  ua::client::SecureChannelTestAccess::on_strand(channel,
    [&](auto& g)
    {
      g.next_create_session_response_observer() = [&captured](const CreateSessionResponse& resp)
      {
        captured = resp;
      };
    });

  auto session = channel.create_session_sync(std::move(config));
  EXPECT_TRUE(captured.has_value()) << "CreateSessionResponse observer did not fire";
  return {std::move(session), captured.has_value() ? std::move(*captured) : CreateSessionResponse{}};
}

}  // namespace

// Part 4 section 5.6.2: CreateSession returns the EndpointDescriptions available for the requested
// serverUri, and the client's only defence against a tampered unsecured discovery result is to compare
// that authenticated list against what GetEndpoints told it. The comparison only defends anything if
// the two lists agree in the fields the client decides on - a server that answers CreateSession from a
// second, independently built endpoint table, or that trims securityLevel, the server certificate or
// the user token policies out of the session copy, passes a count-and-security-mode check while
// destroying the very check unsecured discovery relies on. Discovery is therefore read over an
// UNSECURED channel and the session created over a SignAndEncrypt one, and every field a client acts
// on is compared, element by element.
// @verifies AC-SVR-DISC-GEN-017-CREATESESSION-ENDPOINTS
TEST_F(ComplianceDiscoverySecured, DISC_GEN_017_CreateSessionServerEndpointsAgreeWithGetEndpoints)
{
  // The unsecured discovery result - what a client has before it can authenticate anything.
  auto discoveryChannel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = discoveryChannel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(geResp.endpoints().size(), 3u)
    << "the fixture publishes None, Sign and SignAndEncrypt; without them nothing is compared";

  // The authenticated copy, obtained over a secured channel to the same server.
  auto securedChannel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});

  auto [session, createResp] =
    create_session_capturing_response(securedChannel, {.sessionName = "DiscoveryEndpointAgreement"});

  auto& sessionEndpoints = createResp.server_endpoints();
  ASSERT_GT(sessionEndpoints.size(), 0u) << "CreateSession returned no serverEndpoints to compare";
  ASSERT_EQ(sessionEndpoints.size(), geResp.endpoints().size())
    << "CreateSession must return the same endpoints GetEndpoints does for this endpointUrl";

  for (size_t i = 0; i < geResp.endpoints().size(); ++i)
  {
    auto& disc = geResp.endpoints()[i];
    auto& sess = sessionEndpoints[i];

    EXPECT_EQ(std::string{sess.endpoint_url()}, std::string{disc.endpoint_url()})
      << "endpoint " << i << " endpointUrl differs between CreateSession and GetEndpoints";
    EXPECT_EQ(sess.security_mode(), disc.security_mode())
      << "endpoint " << i << " securityMode differs between CreateSession and GetEndpoints";
    EXPECT_EQ(std::string{sess.security_policy_uri()}, std::string{disc.security_policy_uri()})
      << "endpoint " << i << " securityPolicyUri differs between CreateSession and GetEndpoints";
    EXPECT_EQ(std::string{sess.transport_profile_uri()}, std::string{disc.transport_profile_uri()})
      << "endpoint " << i << " transportProfileUri differs between CreateSession and GetEndpoints";
    EXPECT_EQ(sess.security_level(), disc.security_level())
      << "endpoint " << i << " securityLevel differs; the client's endpoint choice would not survive"
      << " the comparison";
    EXPECT_TRUE(sess.server_certificate() == disc.server_certificate())
      << "endpoint " << i << " serverCertificate differs; this is the field the comparison exists to"
      << " protect";
    EXPECT_EQ(std::string{sess.server().application_uri()}, std::string{disc.server().application_uri()})
      << "endpoint " << i << " applicationUri differs between CreateSession and GetEndpoints";

    ASSERT_EQ(sess.user_identity_tokens().size(), disc.user_identity_tokens().size())
      << "endpoint " << i << " publishes a different number of user token policies to the session copy";
    ASSERT_GE(disc.user_identity_tokens().size(), 1u)
      << "endpoint " << i << " publishes no user token policy, so none is compared";
    for (size_t j = 0; j < disc.user_identity_tokens().size(); ++j)
    {
      auto& discPolicy = disc.user_identity_tokens()[j];
      auto& sessPolicy = sess.user_identity_tokens()[j];
      EXPECT_EQ(std::string{sessPolicy.policy_id()}, std::string{discPolicy.policy_id()})
        << "endpoint " << i << " token " << j << " policyId differs between the two answers";
      EXPECT_EQ(sessPolicy.token_type(), discPolicy.token_type())
        << "endpoint " << i << " token " << j << " tokenType differs between the two answers";
      EXPECT_EQ(std::string{sessPolicy.security_policy_uri()}, std::string{discPolicy.security_policy_uri()})
        << "endpoint " << i << " token " << j << " securityPolicyUri differs between the two answers";
    }
  }

  session.activate_sync();
  (void)session.try_close_sync();
  securedChannel.close_sync();
  discoveryChannel.close_sync();
}

// Part 4 section 7.14: transportProfileUri names the transport an endpoint speaks (protocol plus
// encoding), and it is the field a client filters on before it commits to a connection, so an empty
// value - or one constant that has nothing to do with the endpoint - sends a binary-only client at a
// transport it cannot speak. Two plausible implementations get this wrong and still look healthy:
// one stamps the field only where a client is expected to read it (GetEndpoints) and rebuilds the
// CreateSession copy from an endpoint table that never carried it, so the authenticated list a client
// compares against loses the field; the other fills the field with a literal that is never consulted,
// which a presence check cannot tell from a derived value. Both surfaces that return an
// EndpointDescription are therefore read, and the value is exercised through the profileUris filter -
// which matches on exactly this field - in both directions, so a value that does not actually track
// the endpoint's transport is caught rather than assumed.
// @verifies AC-SVR-DISC-GE-EPD-002-TRANSPORTPROFILEURI
TEST_F(ComplianceDiscoverySecured, DISC_GE_EPD_002_EveryEndpointDescriptionNamesItsOwnTransportProfile)
{
  // The profile of the transport the fixture's listener is bound with (TransportProfileId::
  // UaTcpUaScUaBinary), and the profile of a transport this server does not speak.
  static constexpr std::string_view uaTcpProfile{
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"};
  static constexpr std::string_view foreignProfile{
    "http://opcfoundation.org/UA-Profile/Transport/https-uabinary"};

  auto discoveryChannel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = discoveryChannel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(geResp.endpoints().size(), 3u)
    << "the fixture publishes None, Sign and SignAndEncrypt; without them no description is inspected";

  for (size_t i = 0; i < geResp.endpoints().size(); ++i)
  {
    std::string profileUri = geResp.endpoints()[i].transport_profile_uri();
    EXPECT_FALSE(profileUri.empty()) << "Endpoint " << i
                                     << " names no transport profile, so a client cannot tell what it speaks";
    EXPECT_EQ(profileUri, std::string{uaTcpProfile})
      << "Endpoint " << i << " must name the profile of the transport its listener is bound with";
    EXPECT_NE(profileUri, std::string{foreignProfile})
      << "Endpoint " << i << " claims a transport this server does not speak";
  }

  // The field is what profileUris matches on, so filtering by the transport the endpoints report must
  // select all of them, and filtering by another transport's profile must select none. A field that
  // does not actually carry the endpoint's transport fails one half or the other.
  GetEndpointsRequest ownProfileReq;
  ownProfileReq.endpoint_url() = mEndpointUrl;
  ownProfileReq.profile_uris().push_back(String{std::string{uaTcpProfile}});
  auto ownProfileResp = discoveryChannel.get_endpoints_sync(std::move(ownProfileReq));
  ASSERT_THAT(ownProfileResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(ownProfileResp.endpoints().size(), geResp.endpoints().size())
    << "every endpoint reports the UA-TCP profile, so a filter naming it must return all of them";

  GetEndpointsRequest foreignProfileReq;
  foreignProfileReq.endpoint_url() = mEndpointUrl;
  foreignProfileReq.profile_uris().push_back(String{std::string{foreignProfile}});
  auto foreignProfileResp = discoveryChannel.get_endpoints_sync(std::move(foreignProfileReq));
  ASSERT_THAT(foreignProfileResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(foreignProfileResp.endpoints().size(), 0u)
    << "no endpoint speaks that transport, so a filter naming it must return none";

  // The other surface that returns EndpointDescriptions: the authenticated copy in CreateSession.
  auto securedChannel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});

  auto [session, createResp] =
    create_session_capturing_response(securedChannel, {.sessionName = "DiscoveryTransportProfile"});

  auto& sessionEndpoints = createResp.server_endpoints();
  ASSERT_GT(sessionEndpoints.size(), 0u)
    << "CreateSession returned no serverEndpoints, so no description is inspected on that surface";
  for (size_t i = 0; i < sessionEndpoints.size(); ++i)
  {
    std::string profileUri = sessionEndpoints[i].transport_profile_uri();
    EXPECT_FALSE(profileUri.empty()) << "CreateSession endpoint " << i << " names no transport profile";
    EXPECT_EQ(profileUri, std::string{uaTcpProfile})
      << "CreateSession endpoint " << i << " must name the same transport profile discovery reports";
  }

  session.activate_sync();
  (void)session.try_close_sync();
  securedChannel.close_sync();
  discoveryChannel.close_sync();
}
