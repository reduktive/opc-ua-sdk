// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for first-OPN timeout (S3).
///
/// Verifies:
/// 1. Default first-OPN timeout is 30 seconds and is configurable.
/// 2. Timer fires and closes the connection when no OPN arrives within the timeout.
/// 3. Timer does not fire when timeout is set to zero (disabled).

#include <gtest/gtest.h>

#include <future>

#include "test_utilities.h"

#include "ua_connection_protocol.h"
#include "ua_reverse_hello.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_info.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_application_configuration.h"
#include "ua_error_detail.h"
#include "ua_server_configuration.h"

#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"

using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

static std::vector<byte> build_hello(
  uint32_t protocolVersion, uint32_t recvBuf, uint32_t sendBuf, std::string endpointUrl)
{
  memory_stream_device::Dynamic streamDevice{ua::connection_protocol::maxUrlSize + 128, true};
  MemoryStream stream{streamDevice};

  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'H'});
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'L'});
  enc.encode(limit, uint8_t{'F'});

  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});

  enc.encode(limit, protocolVersion);
  enc.encode(limit, recvBuf);
  enc.encode(limit, sendBuf);
  enc.encode(limit, uint32_t{0});  // maxMessageSize
  enc.encode(limit, uint32_t{0});  // maxChunkCount
  enc.encode(limit, endpointUrl);

  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);

  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

/// Minimal SecureChannelDependencies for first-OPN timeout tests.
class FakeSecureChannelDeps : public SecureChannelDependencies
{
public:
  explicit FakeSecureChannelDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(::ua::ApplicationConfig::load_default())
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  void create_session(SecureChannelInfo, uint32_t, CreateSessionRequest&&) override
  {}

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError,
      make_error_detail("TestError", "Not used in first-OPN timeout tests", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle) override
  {
    return {};
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  uint32_t get_next_secure_channel_id() override
  {
    return 1;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return nullptr;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

  void remove_secure_channel(const shared_ptr<SecureChannel>&) override
  {}

  void set_first_opn_timeout(std::chrono::seconds timeout)
  {
    mAppCfg.stack_limits().firstOpnTimeout = timeout;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ::ua::ApplicationConfig mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
};

/// Complete HEL/ACK handshake and return the ConnectionProtocol.
/// Puts FakeTransportConnection into stall_reads() mode so that
/// subsequent reads (post-HEL/ACK MSG frame reads) do not error.
shared_ptr<ConnectionProtocol> complete_handshake(
  shared_ptr<FakeConnectionProtocolDeps> cpDeps, shared_ptr<FakeTransportConnection> transport)
{
  transport->enqueue_hello_message(build_hello(0, 8192, 8192, "opc.tcp://127.0.0.1:4840"));

  // Enable stall mode BEFORE creating ConnectionProtocol so that the post-HEL/ACK
  // read for the first MSG frame header does not crash.
  transport->stall_reads();

  // Use a promise/future rather than a condition_variable: the completion callback runs on a worker
  // thread, and destroying a condition_variable (when this helper returns) while that worker is still
  // inside notify_one() is a data race (TSAN-reported). A promise's shared state is refcounted and
  // safe to satisfy concurrently with destruction; capturing it by value keeps it alive even if the
  // callback fires late. Prefer futures over CVs.
  auto completion = std::make_shared<std::promise<shared_ptr<ConnectionProtocol>>>();
  auto completed = completion->get_future();

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    cpDeps,
    transport,
    false,
    60s,
    [completion](StatusCode st,
      shared_ptr<ConnectionProtocol>
        conn,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      EXPECT_TRUE(st.is_good());
      completion->set_value(std::move(conn));
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) { FAIL() << "Unexpected handshake error"; },
    {},
    [](string_view) { return true; });

  if (completed.wait_for(2s) != std::future_status::ready)
  {
    ADD_FAILURE() << "Handshake did not complete within 2s";
    return nullptr;
  }
  return completed.get();
}

}  // namespace

// ---------------------------------------------------------------------------
// Config tests
// ---------------------------------------------------------------------------

// @relation(SVR-TCP-019, scope=function)
TEST(FirstOpnTimeoutTests, DefaultTimeoutIs30Seconds)
{
  auto cfg = ApplicationConfig::load_default();
  EXPECT_EQ(cfg.stack_limits().firstOpnTimeout, 30s);
}

// Smoke test: verifies the config field is writable and readable.
// The behavioral tests below rely on this capability to set short timeouts.
// @relation(SVR-TCP-019, scope=function)
TEST(FirstOpnTimeoutTests, TimeoutIsConfigurable)
{
  auto cfg = ApplicationConfig::load_default();
  cfg.stack_limits().firstOpnTimeout = 60s;
  EXPECT_EQ(cfg.stack_limits().firstOpnTimeout, 60s);
}

// ---------------------------------------------------------------------------
// Behavioral tests
// ---------------------------------------------------------------------------

// @relation(AC-SVR-TCP-019-IDLE, scope=function)
TEST(FirstOpnTimeoutTests, ConnectionClosedWhenNoOpnArrivesWithinTimeout)
{
  boost::asio::thread_pool tp;
  // Complete HEL/ACK handshake; transport stalls subsequent reads.
  auto cpDeps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  cpDeps->set_server_limits(ua::connection_protocol::Limits{});
  auto transport = std::make_shared<FakeTransportConnection>();
  auto cp = complete_handshake(cpDeps, transport);
  ASSERT_NE(cp, nullptr);

  // Create SecureChannel with a very short first-OPN timeout (1 second).
  auto scDeps = std::make_shared<FakeSecureChannelDeps>(tp.get_executor());
  scDeps->set_first_opn_timeout(std::chrono::seconds{1});

  size_t closesBefore = transport->close_count();

  auto sc =
    SecureChannel::create(scDeps, cp, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");

  // Do NOT send any OPN request. Wait for the timeout to fire and close the connection.
  EXPECT_TRUE(transport->wait_for_close(5s)) << "Connection should be closed after first-OPN timeout";
  EXPECT_GT(transport->close_count(), closesBefore);

  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-019-IDLE, scope=function)
TEST(FirstOpnTimeoutTests, ConnectionNotClosedWhenTimeoutIsZero)
{
  boost::asio::thread_pool tp;
  auto cpDeps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  cpDeps->set_server_limits(ua::connection_protocol::Limits{});
  auto transport = std::make_shared<FakeTransportConnection>();
  auto cp = complete_handshake(cpDeps, transport);
  ASSERT_NE(cp, nullptr);

  // Create SecureChannel with timeout disabled.
  auto scDeps = std::make_shared<FakeSecureChannelDeps>(tp.get_executor());
  scDeps->set_first_opn_timeout(std::chrono::seconds{0});

  auto sc =
    SecureChannel::create(scDeps, cp, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");

  // Wait 1.5 seconds - connection should remain open because timer is disabled.
  EXPECT_FALSE(transport->wait_for_close(1500ms))
    << "Connection should remain open when first-OPN timeout is zero";
}
