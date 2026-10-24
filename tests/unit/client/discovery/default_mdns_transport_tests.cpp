// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the built-in mDNS transport leaf. The discovery facade has separate injected-transport
// tests; these tests exercise the production scheme mapping and the current explicitly inert default browser.

#include "ua_default_mdns_transport.h"

#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace
{

struct RecordingLogSink : ua::LogSink
{
  std::vector<std::string> messages;

  void log(const ua::LogEntry& entry) override
  {
    messages.push_back(entry.message);
  }

  [[nodiscard]] bool contains(std::string_view text) const
  {
    for (const auto& message : messages)
    {
      if (message.find(text) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
};

ua::Logger make_logger(const std::shared_ptr<RecordingLogSink>& sink)
{
  return ua::Logger{
    sink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "default_mdns_test"};
}

// @verifies AC-CL-DISC-015-MDNS-SERVICE-NAME
// @relation(AC-CL-DISC-015-MDNS-SERVICE-NAME, scope=function)
TEST(DefaultMdnsTransport, ServiceTypeForSchemeFollowsPart12Annex)
{
  EXPECT_EQ(ua::mdns::service_type_for_scheme(ua::mdns::OpcUaTransportScheme::Tcp), "_opcua-tcp._tcp.local.");
  EXPECT_EQ(ua::mdns::service_type_for_scheme(ua::mdns::OpcUaTransportScheme::Wss), "_opcua-tls._tcp.local.");
  EXPECT_EQ(
    ua::mdns::service_type_for_scheme(ua::mdns::OpcUaTransportScheme::Https), "_opcua-https._tcp.local.");
}

TEST(DefaultMdnsTransport, StartBrowseReturnsCloseableBrowserAndNamesStubInWarning)
{
  boost::asio::io_context context;
  auto sink = std::make_shared<RecordingLogSink>();
  ua::mdns::DefaultMdnsTransport transport{context.get_executor(), make_logger(sink)};

  auto result = transport.start_browse("_opcua-tcp._tcp.local.", ua::mdns::MdnsBrowseConfig{});

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value(), nullptr);
  EXPECT_TRUE(sink->contains("default mDNS transport is a stub"));
  EXPECT_TRUE(sink->contains("_opcua-tcp._tcp.local."));

  bool closeCalled = false;
  result.value()->close_async(
    [&closeCalled](ua::VoidResult closeResult)
    {
      EXPECT_TRUE(closeResult.is_good());
      closeCalled = true;
    });
  EXPECT_TRUE(closeCalled);
}

TEST(DefaultMdnsTransport, CloseAfterCallbacksAreInstalledCompletesAndIsIdempotent)
{
  boost::asio::io_context context;
  ua::mdns::DefaultMdnsTransport transport{context.get_executor(), ua::Logger{}};
  auto result = transport.start_browse("_opcua-tls._tcp.local.", ua::mdns::MdnsBrowseConfig{});
  ASSERT_TRUE(result.is_good());
  auto browser = result.value();
  browser->set_callbacks([](ua::mdns::ServiceRecord) {}, [](std::string) {});

  std::size_t closeCount = 0;
  browser->close_async(
    [&closeCount](ua::VoidResult closeResult)
    {
      EXPECT_TRUE(closeResult.is_good());
      ++closeCount;
    });
  browser->close_async(
    [&closeCount](ua::VoidResult closeResult)
    {
      EXPECT_TRUE(closeResult.is_good());
      ++closeCount;
    });

  EXPECT_EQ(closeCount, 2u);
  EXPECT_NO_THROW(browser->close_async({}));
}

}  // namespace
