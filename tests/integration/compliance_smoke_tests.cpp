// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "compliance_helpers.h"

#include "ua_session_attribute_services.h"

#include "ua_attribute_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"

// ---------------------------------------------------------------------------
// ComplianceBase: can open a channel
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, Smoke_OpenAndCloseChannel)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  EXPECT_TRUE(channel.is_open());
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// ComplianceWithSession: session is active
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithSession, Smoke_SessionIsActive)
{
  EXPECT_TRUE(mSession->is_active());
}

// ---------------------------------------------------------------------------
// ComplianceWithNodes: can read the writable variable
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithNodes, Smoke_ReadWritableVariable)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = mWritableVariableId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_FALSE(resp.results()[0].status().has_value())
    << "Non-null status means error: " << resp.results()[0].status().value().as_uint32();
  EXPECT_EQ(resp.results()[0].value().as<int32_t>(), 42);
}

// ---------------------------------------------------------------------------
// ComplianceSecured: can open authenticated channel
// ---------------------------------------------------------------------------
TEST_F(ComplianceSecured, Smoke_OpenAuthenticatedChannel)
{
  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mServerCert;

  auto channelResult = mClient->core().try_open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channelResult.is_good()) << "0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  EXPECT_TRUE(channel.is_open());
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// ComplianceSecuredWithSession: secured session is active
// ---------------------------------------------------------------------------
TEST_F(ComplianceSecuredWithSession, Smoke_SecuredSessionIsActive)
{
  EXPECT_TRUE(mSession->is_active());
}
