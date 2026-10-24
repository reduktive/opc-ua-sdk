// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_client_encoding_limits.h"

using namespace ua;

namespace
{
// The bounded-floor defaults from make_encoding_limits / EncodingLimits (mirror server P0.2).
constexpr size_t floorString = 1u * 1024u * 1024u;
constexpr size_t floorByteString = 16u * 1024u * 1024u;
constexpr size_t floorArray = 65535u;
}  // namespace

// nullopt overrides leave the bounded floor in place - the mandatory decode-bomb protection.
// @verifies CL-ADDRSP-007
// @relation(CL-ADDRSP-007, scope=function)
TEST(ClientEncodingLimitsTests, NoOverridesKeepsBoundedFloor)
{
  auto appCfg = ApplicationConfig::load_default();
  auto limits = client::make_client_encoding_limits(appCfg, std::nullopt, std::nullopt, std::nullopt);
  EXPECT_EQ(limits.maxStringLength, floorString);
  EXPECT_EQ(limits.maxByteStringLength, floorByteString);
  EXPECT_EQ(limits.maxArrayLength, floorArray);
  // Execution limits must still come from the application configuration.
  EXPECT_EQ(limits.execution.decodeWorkLimit, appCfg.execution_limits().decodeWorkLimit);
  EXPECT_EQ(limits.execution.decodeRecursionDepthLimit, appCfg.execution_limits().decodeRecursionDepthLimit);
}

// A trusted-server client can raise the caps above the floor.
TEST(ClientEncodingLimitsTests, OverridesRaiseCapsAboveFloor)
{
  auto appCfg = ApplicationConfig::load_default();
  auto limits = client::make_client_encoding_limits(
    appCfg, /*string*/ 8u * 1024u * 1024u, /*byteString*/ 64u * 1024u * 1024u, /*array*/ 1'000'000u);
  EXPECT_EQ(limits.maxStringLength, 8u * 1024u * 1024u);
  EXPECT_EQ(limits.maxByteStringLength, 64u * 1024u * 1024u);
  EXPECT_EQ(limits.maxArrayLength, 1'000'000u);
}

// An embedded/hardened client can lower the caps below the floor.
TEST(ClientEncodingLimitsTests, OverridesLowerCapsBelowFloor)
{
  auto appCfg = ApplicationConfig::load_default();
  auto limits = client::make_client_encoding_limits(appCfg, /*string*/ 4096u, std::nullopt, /*array*/ 256u);
  EXPECT_EQ(limits.maxStringLength, 4096u);  // overridden
  EXPECT_EQ(limits.maxByteStringLength, floorByteString);  // left at the floor (nullopt)
  EXPECT_EQ(limits.maxArrayLength, 256u);  // overridden
}
