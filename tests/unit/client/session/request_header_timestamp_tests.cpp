// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "ua_activate_session_request.h"
#include "ua_browse_request.h"
#include "ua_close_session_request.h"
#include "ua_create_session_request.h"
#include "ua_error_detail.h"
#include "ua_read_request.h"
#include "ua_service_fault.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_write_request.h"

#include <chrono>
#include <future>
#include <tuple>

namespace
{

using namespace std::chrono_literals;
using ua::client::test_capture::CaptureHarness;
using ChannelAccess = ua::client::SecureChannelTestAccess;
using SessionAccess = ua::client::SessionTestAccess;

class RequestTimestampFixture : public testing::Test
{
protected:
  void SetUp() override
  {
    mStarted = ua::DateTime::now();
    mHarness.channelDeps = std::make_shared<ua::client::test_capture::FakeChannelDeps>(mPool.get_executor());
    mHarness.channel = ua::client::SecureChannelImpl::create(
      mHarness.channelDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      {},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});
    mHarness.capturedRequests = std::make_shared<std::vector<std::unique_ptr<ua::Structure>>>();
    ChannelAccess::on_strand(*mHarness.channel,
      [captured = mHarness.capturedRequests](auto& guard)
      {
        guard.set_channel_open();
        guard.outgoing_request_observer() = [captured](const ua::Structure& request)
        {
          captured->push_back(request.clone());
        };
      });
    mHarness.sessionDeps = std::make_shared<ua::client::test_capture::FakeSessionDeps>(mPool.get_executor());
    mHarness.session = ua::client::SessionImpl::create(
      mHarness.sessionDeps, mHarness.channel, {}, {}, [](ua::VoidResult) {}, [](ua::VoidResult) {});
    ASSERT_TRUE(mHarness.wait_for_pending_request());
    auto response = std::make_shared<ua::CreateSessionResponse>();
    response->session_id() = ua::NodeId{1, 42};
    response->authentication_token() = ua::NodeId{1, 99};
    response->revised_session_timeout() = 600000.0;
    ua::UserTokenPolicy anonymous;
    anonymous.token_type() = ua::UserTokenType::Anonymous;
    ua::EndpointDescription endpoint;
    endpoint.security_mode() = ua::MessageSecurityMode::None;
    endpoint.user_identity_tokens().push_back(std::move(anonymous));
    response->server_endpoints().push_back(std::move(endpoint));
    ASSERT_TRUE(mHarness.inject_channel_response(std::move(response)));
    ASSERT_TRUE(ua::client::test_capture::wait_until([this] { return mHarness.session->is_created(); }));
    mHarness.set_active();
  }

  void TearDown() override
  {
    mHarness.cleanup_sync();
    mHarness.release();
    mPool.stop();
    mPool.join();
  }

  template<typename Request>
  void verify_request(const ua::DateTime& before, bool explicitTimeout, bool session)
  {
    ASSERT_TRUE(mHarness.wait_for_pending_request());
    auto captured = mHarness.first_captured<Request>();
    ASSERT_TRUE(captured.has_value());
    const auto after = ua::DateTime::now();
    const auto& header = captured->request_header();
    EXPECT_FALSE(header.timestamp().is_null());
    EXPECT_GE(header.timestamp(), before);
    EXPECT_LE(header.timestamp(), after);
    EXPECT_EQ(header.request_handle(), 4321U);
    EXPECT_EQ(header.return_diagnostics(), 0x33U);
    EXPECT_EQ(header.audit_entry_id(), ua::String{"caller-audit"});
    EXPECT_EQ(header.timeout_hint(), explicitTimeout ? 1234U : 10000U);
    EXPECT_EQ(header.authentication_token(), session ? ua::NodeId(1, 99) : ua::NodeId{});
  }

  template<typename Request>
  Request request(bool stale, bool explicitTimeout)
  {
    Request outgoing;
    auto& header = outgoing.request_header();
    header.timestamp() = stale ? ua::DateTime{2000, 1, 1, 0, 0, 0.0} : ua::DateTime{};
    header.request_handle() = 4321U;
    header.return_diagnostics() = 0x33U;
    header.audit_entry_id() = "caller-audit";
    header.timeout_hint() = explicitTimeout ? 1234U : 0U;
    return outgoing;
  }

  boost::asio::thread_pool mPool{2};
  CaptureHarness mHarness;
  ua::DateTime mStarted;
};

class ChannelRequestTimestamp : public RequestTimestampFixture,
                                public testing::WithParamInterface<std::tuple<int, bool, bool>>
{};

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_P(ChannelRequestTimestamp, AllTypedServicesStampUtcAndPreserveOtherHeaderFields)
{
  const auto [service, stale, explicitTimeout] = GetParam();
  auto channel = ChannelAccess::make_channel(mHarness.channel);
  const auto before = ua::DateTime::now();
  switch (service)
  {
  case 0:
    channel.find_servers_async(request<ua::FindServersRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::FindServersRequest>(before, explicitTimeout, false);
    break;
  case 1:
    channel.get_endpoints_async(request<ua::GetEndpointsRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::GetEndpointsRequest>(before, explicitTimeout, false);
    break;
  case 2:
    channel.find_servers_on_network_async(
      request<ua::FindServersOnNetworkRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::FindServersOnNetworkRequest>(before, explicitTimeout, false);
    break;
  case 3:
    channel.register_server_async(request<ua::RegisterServerRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::RegisterServerRequest>(before, explicitTimeout, false);
    break;
  case 4:
    channel.register_server2_async(request<ua::RegisterServer2Request>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::RegisterServer2Request>(before, explicitTimeout, false);
    break;
  default:
    FAIL() << "Unknown service";
  }
}

INSTANTIATE_TEST_SUITE_P(
  All, ChannelRequestTimestamp, testing::Combine(testing::Range(0, 5), testing::Bool(), testing::Bool()));

class SessionRequestTimestamp : public RequestTimestampFixture,
                                public testing::WithParamInterface<std::tuple<int, bool, bool>>
{};

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_P(SessionRequestTimestamp, TypedServicesStampUtcAndPreserveOtherHeaderFields)
{
  const auto [service, stale, explicitTimeout] = GetParam();
  auto session = mHarness.session_handle();
  const auto before = ua::DateTime::now();
  switch (service)
  {
  case 0:
    session.attributes().read_async(request<ua::ReadRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::ReadRequest>(before, explicitTimeout, true);
    break;
  case 1:
    session.attributes().write_async(request<ua::WriteRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::WriteRequest>(before, explicitTimeout, true);
    break;
  case 2:
    session.view().browse_async(request<ua::BrowseRequest>(stale, explicitTimeout), [](auto) {});
    verify_request<ua::BrowseRequest>(before, explicitTimeout, true);
    break;
  default:
    FAIL() << "Unknown service";
  }
}

INSTANTIATE_TEST_SUITE_P(
  All, SessionRequestTimestamp, testing::Combine(testing::Range(0, 3), testing::Bool(), testing::Bool()));

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_F(RequestTimestampFixture, CreateSessionStampsUtcBeforeDispatch)
{
  auto captured = mHarness.first_captured<ua::CreateSessionRequest>();
  ASSERT_TRUE(captured.has_value());
  EXPECT_FALSE(captured->request_header().timestamp().is_null());
  EXPECT_GE(captured->request_header().timestamp(), mStarted);
  EXPECT_LE(captured->request_header().timestamp(), ua::DateTime::now());
  EXPECT_TRUE(captured->request_header().authentication_token().is_null());
}

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_F(RequestTimestampFixture, ActivateSessionStampsUtcBeforeDispatch)
{
  SessionAccess::on_strand(*mHarness.session, [](auto& guard) { guard.set_session_created(); });
  const auto before = ua::DateTime::now();
  mHarness.session_handle().activate_async({}, [](ua::VoidResult) {});
  ASSERT_TRUE(mHarness.wait_for_pending_request());
  auto captured = mHarness.first_captured<ua::ActivateSessionRequest>();
  ASSERT_TRUE(captured.has_value());
  EXPECT_FALSE(captured->request_header().timestamp().is_null());
  EXPECT_GE(captured->request_header().timestamp(), before);
  EXPECT_LE(captured->request_header().timestamp(), ua::DateTime::now());
  EXPECT_EQ(captured->request_header().authentication_token(), ua::NodeId(1, 200));
}

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_F(RequestTimestampFixture, CloseSessionStampsUtcBeforeDispatch)
{
  const auto before = ua::DateTime::now();
  mHarness.session_handle().close_async([](ua::VoidResult) {});
  ASSERT_TRUE(mHarness.wait_for_pending_request());
  auto captured = mHarness.first_captured<ua::CloseSessionRequest>();
  ASSERT_TRUE(captured.has_value());
  EXPECT_FALSE(captured->request_header().timestamp().is_null());
  EXPECT_GE(captured->request_header().timestamp(), before);
  EXPECT_LE(captured->request_header().timestamp(), ua::DateTime::now());
  EXPECT_EQ(captured->request_header().authentication_token(), ua::NodeId(1, 99));
}

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_F(RequestTimestampFixture, FailedChannelResponsePreservesRichStatus)
{
  auto detail = std::shared_ptr<const ua::ErrorDetail>{
    ua::ErrorDetail::build("TimestampPeerFailure", "Synthetic peer failure", "test.peer")};
  const ua::StatusCode status{ua::Status::BadInvalidTimestamp, detail};
  auto completion = std::make_shared<std::promise<ua::Result<ua::FindServersResponse>>>();
  auto received = completion->get_future();
  auto channel = ChannelAccess::make_channel(mHarness.channel);
  channel.find_servers_async({}, [completion](auto result) { completion->set_value(std::move(result)); });
  ASSERT_TRUE(mHarness.wait_for_pending_request());
  ASSERT_TRUE(mHarness.inject_channel_failure(status));
  ASSERT_EQ(received.wait_for(1s), std::future_status::ready);
  const auto result = received.get();
  EXPECT_EQ(result.status_code().as_uint32(), status.as_uint32());
  EXPECT_EQ(result.shared_detail(), detail);
}

// @relation(AC-COMP-CLIENT-REQUEST-TIMESTAMP-UNIT, scope=function)
TEST_F(RequestTimestampFixture, FailedSessionResponsePreservesRichStatus)
{
  auto detail = std::shared_ptr<const ua::ErrorDetail>{
    ua::ErrorDetail::build("TimestampPeerFailure", "Synthetic peer failure", "test.peer")};
  const ua::StatusCode status{ua::Status::BadInvalidTimestamp, detail};
  auto completion = std::make_shared<std::promise<ua::Result<ua::ReadResponse>>>();
  auto received = completion->get_future();
  mHarness.session_handle().attributes().read_async(
    {}, [completion](auto result) { completion->set_value(std::move(result)); });
  ASSERT_TRUE(mHarness.wait_for_pending_request());
  ASSERT_TRUE(mHarness.inject_channel_failure(status));
  ASSERT_EQ(received.wait_for(1s), std::future_status::ready);
  const auto result = received.get();
  EXPECT_EQ(result.status_code().as_uint32(), status.as_uint32());
  EXPECT_EQ(result.shared_detail(), detail);
}

}  // namespace
