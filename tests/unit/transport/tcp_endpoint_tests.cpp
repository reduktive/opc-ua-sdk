// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>
#include <array>

#include <gtest/gtest.h>

#include "ua_exceptions.h"
#include "ua_tcp_endpoint.h"

using namespace ua;

namespace
{

void expect_bytes_eq(std::span<const std::uint8_t> actual, std::span<const std::uint8_t> expected)
{
  ASSERT_EQ(actual.size(), expected.size());
  EXPECT_TRUE(std::equal(actual.begin(), actual.end(), expected.begin()));
}

}  // namespace

TEST(TcpEndpointTests, FromString_AddressOnly_V4)
{
  const auto ep = TcpEndpoint::from_string("127.0.0.1", 4840);

  EXPECT_EQ(ep.version(), TcpEndpoint::IpVersion::V4);
  EXPECT_EQ(ep.port(), 4840);

  const std::array<std::uint8_t, 4> expected{127, 0, 0, 1};
  expect_bytes_eq(ep.address(), expected);
}

TEST(TcpEndpointTests, FromString_AddressOnly_V6)
{
  const auto ep = TcpEndpoint::from_string("::1", 4840);

  EXPECT_EQ(ep.version(), TcpEndpoint::IpVersion::V6);
  EXPECT_EQ(ep.port(), 4840);

  const std::array<std::uint8_t, 16> expected{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  expect_bytes_eq(ep.address(), expected);
}

TEST(TcpEndpointTests, FromString_Endpoint_V4)
{
  const auto ep = TcpEndpoint::from_string("127.0.0.1:4840");

  EXPECT_EQ(ep.version(), TcpEndpoint::IpVersion::V4);
  EXPECT_EQ(ep.port(), 4840);

  const std::array<std::uint8_t, 4> expected{127, 0, 0, 1};
  expect_bytes_eq(ep.address(), expected);
}

TEST(TcpEndpointTests, FromString_Endpoint_V6)
{
  const auto ep = TcpEndpoint::from_string("[::1]:4840");

  EXPECT_EQ(ep.version(), TcpEndpoint::IpVersion::V6);
  EXPECT_EQ(ep.port(), 4840);

  const std::array<std::uint8_t, 16> expected{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  expect_bytes_eq(ep.address(), expected);
}

TEST(TcpEndpointTests, FromString_Invalid_Throws)
{
  EXPECT_THROW((void)TcpEndpoint::from_string("not-an-ip", 4840), UaException);
  EXPECT_THROW((void)TcpEndpoint::from_string("127.0.0.1:abc"), UaException);
  EXPECT_THROW((void)TcpEndpoint::from_string("::1:4840"), UaException);  // require bracketed form
  EXPECT_THROW((void)TcpEndpoint::from_string("[::1]"), UaException);
}
