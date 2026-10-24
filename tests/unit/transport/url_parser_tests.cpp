// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_url_parser.h"

using namespace ua::transport;

// --- parse_opc_tcp_url ---

TEST(UrlParserTests, ParseSimpleUrl)
{
  auto result = parse_opc_tcp_url("opc.tcp://localhost:4840", "Test");
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().hostname, "localhost");
  EXPECT_EQ(result.value().port, 4840);
  EXPECT_EQ(result.value().path, "");
}

TEST(UrlParserTests, ParseUrlWithPath)
{
  auto result = parse_opc_tcp_url("opc.tcp://myhost:4840/discovery", "Test");
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().hostname, "myhost");
  EXPECT_EQ(result.value().port, 4840);
  EXPECT_EQ(result.value().path, "/discovery");
}

TEST(UrlParserTests, ParseUrlWithMultiSegmentPath)
{
  auto result = parse_opc_tcp_url("opc.tcp://myhost:4840/ua/discovery", "Test");
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().path, "/ua/discovery");
}

TEST(UrlParserTests, ParseUrlDefaultPort)
{
  auto result = parse_opc_tcp_url("opc.tcp://myhost", "Test");
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().hostname, "myhost");
  EXPECT_EQ(result.value().port, 4840);
  EXPECT_EQ(result.value().path, "");
}

TEST(UrlParserTests, ParseIpv6Url)
{
  auto result = parse_opc_tcp_url("opc.tcp://[::1]:4840", "Test");
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().hostname, "::1");
  EXPECT_EQ(result.value().port, 4840);
}

TEST(UrlParserTests, ParseIpv6UrlWithPath)
{
  auto result = parse_opc_tcp_url("opc.tcp://[::1]:4840/discovery", "Test");
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().hostname, "::1");
  EXPECT_EQ(result.value().port, 4840);
  EXPECT_EQ(result.value().path, "/discovery");
}

// The scheme is case-insensitive (RFC 3986 3.1): an upper- or mixed-case "opc.tcp" parses as the
// lower-case form does, and the host keeps its own case.
TEST(UrlParserTests, ParseUpperAndMixedCaseScheme)
{
  for (const auto* url : {"OPC.TCP://MyHost:4840/ua", "Opc.Tcp://MyHost:4840/ua"})
  {
    SCOPED_TRACE(url);
    auto result = parse_opc_tcp_url(url, "Test");
    ASSERT_TRUE(result.is_good());
    EXPECT_EQ(result.value().hostname, "MyHost");
    EXPECT_EQ(result.value().port, 4840);
    EXPECT_EQ(result.value().path, "/ua");
  }
}

TEST(UrlParserTests, ParseInvalidScheme)
{
  auto result = parse_opc_tcp_url("http://localhost:4840", "Test");
  EXPECT_TRUE(result.is_bad());
}

TEST(UrlParserTests, ParseEmptyHostname)
{
  auto result = parse_opc_tcp_url("opc.tcp://:4840", "Test");
  EXPECT_TRUE(result.is_bad());
}

// --- matches_port_and_path ---

TEST(UrlParserTests, MatchesPortAndPath_SamePortEmptyPath)
{
  ParsedOpcTcpUrl a{"hostA", 4840, ""};
  ParsedOpcTcpUrl b{"hostB", 4840, ""};
  EXPECT_TRUE(matches_port_and_path(a, b));
}

TEST(UrlParserTests, MatchesPortAndPath_DifferentPort)
{
  ParsedOpcTcpUrl a{"host", 4840, ""};
  ParsedOpcTcpUrl b{"host", 4841, ""};
  EXPECT_FALSE(matches_port_and_path(a, b));
}

TEST(UrlParserTests, MatchesPortAndPath_SamePortDifferentPath)
{
  ParsedOpcTcpUrl a{"host", 4840, "/foo"};
  ParsedOpcTcpUrl b{"host", 4840, "/bar"};
  EXPECT_FALSE(matches_port_and_path(a, b));
}

TEST(UrlParserTests, MatchesPortAndPath_SamePortSamePath)
{
  ParsedOpcTcpUrl a{"hostA", 4840, "/discovery"};
  ParsedOpcTcpUrl b{"hostB", 4840, "/discovery"};
  EXPECT_TRUE(matches_port_and_path(a, b));
}

TEST(UrlParserTests, MatchesPortAndPath_DifferentHostIgnored)
{
  ParsedOpcTcpUrl a{"localhost", 4840, ""};
  ParsedOpcTcpUrl b{"myhostname.example.com", 4840, ""};
  EXPECT_TRUE(matches_port_and_path(a, b));
}

// --- rewrite_host ---

TEST(UrlParserTests, RewriteHost_Simple)
{
  EXPECT_EQ(rewrite_host("opc.tcp://oldhost:4840", "newhost"), "opc.tcp://newhost:4840");
}

TEST(UrlParserTests, RewriteHost_WithPath)
{
  EXPECT_EQ(rewrite_host("opc.tcp://oldhost:4840/discovery", "newhost"), "opc.tcp://newhost:4840/discovery");
}

TEST(UrlParserTests, RewriteHost_Ipv4ToHostname)
{
  EXPECT_EQ(rewrite_host("opc.tcp://192.168.1.1:4840", "localhost"), "opc.tcp://localhost:4840");
}

TEST(UrlParserTests, RewriteHost_HostnameToIpv6)
{
  EXPECT_EQ(rewrite_host("opc.tcp://myhost:4840", "::1"), "opc.tcp://[::1]:4840");
}

TEST(UrlParserTests, RewriteHost_Ipv6ToHostname)
{
  EXPECT_EQ(rewrite_host("opc.tcp://[::1]:4840", "myhost"), "opc.tcp://myhost:4840");
}

TEST(UrlParserTests, RewriteHost_Ipv6ToIpv6)
{
  EXPECT_EQ(rewrite_host("opc.tcp://[::1]:4840", "fe80::1"), "opc.tcp://[fe80::1]:4840");
}

TEST(UrlParserTests, RewriteHost_PreservesPort)
{
  EXPECT_EQ(rewrite_host("opc.tcp://oldhost:12345", "newhost"), "opc.tcp://newhost:12345");
}

TEST(UrlParserTests, RewriteHost_InvalidSchemeReturnsUnchanged)
{
  EXPECT_EQ(rewrite_host("http://oldhost:4840", "newhost"), "http://oldhost:4840");
}

TEST(UrlParserTests, RewriteHost_NoPort)
{
  EXPECT_EQ(rewrite_host("opc.tcp://oldhost", "newhost"), "opc.tcp://newhost");
}
