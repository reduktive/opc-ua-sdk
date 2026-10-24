// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientDecodeCaps cluster of the client integration-test matrix (the six `ClientDecodeCaps.*` rows).
///        SECURITY / ROBUSTNESS: the CLIENT's inbound (server-response) decode-size caps and read-queue
///        backpressure. An inbound cap that is DECLARED but NOT ENFORCED on the RX path is a decode-bomb /
///        DoS gap, so every row asserts the REAL wire-observable behaviour and RED-pins any inert cap.
///
/// Harness: a real `Client` bound to a `MisbehavingServer`'s crypto + trusted store over ephemeral TCP, an
/// activated Session wrapped into a started `ConnectionImpl`, then wrapped into the public tier-2
/// `ua::client::Connection` (via `ConnectionHandleFactory`) so reads run through the genuine managed
/// read path (`Connection::try_read_value_sync`). The `MisbehavingServer` semantic interface
/// (`set_response_mutator`) rewrites the TYPED `ua::ReadResponse` BEFORE signing/encryption, so the client
/// decodes a genuinely-oversized value off a real secure channel. The per-client inbound caps
/// (`ClientConfig::mMaxInbound{String,ByteString,Array}Length`, `incomingChunkQueueDepth`,
/// `mMaxResponseMessageSize`) are threaded through `CreateConfig::client`.
///
/// KEY INVESTIGATION FINDINGS (the required forensic results this file pins):
///   1. THE CLIENT INBOUND DECODE PATH **IS CAPPED**. `SecureChannelImpl` builds its RX `UaBinaryDecoder`
///      with `make_client_encoding_limits(...)` (ua_client_secure_channel_impl.cpp:83, consumed at :747),
///      seeded from the bounded-floor defaults and the per-client overrides. The `UaBinaryCodec` enforces
///      the String / ByteString / Array caps BEFORE allocating (ua_binary_codec.cpp:1066/1133,
///      ua_binary_codec.h:374), throwing `Bad_EncodingLimitsExceeded` with `size.actual`/`size.max`
///      ErrorDetail context. An oversized inbound value therefore aborts the decode; that decode failure
///      tears the channel down (handle_chunk_decode_failure -> close_transport) and fails the in-flight
///      read with `Bad_EncodingLimitsExceeded` + the codec's size-context detail. NOT a decode bomb: the
///      cap fires before the attacker-declared size is ever reserved. Rows 1-4 pin this.
///
///   2. `ClientConfig::mMaxResponseMessageSize` IS **INERT** (CANDIDATE PRODUCT GAP - reported, not
///      fixed here). The client never writes `max_response_message_size` onto the CreateSessionRequest
///      (ua_client_session_impl.cpp:238-262 sets timeout / endpoint / description only), so the configured
///      value is not even NEGOTIATED to the server (it stays the wire default 0); and there is no
///      client-side inbound total-response-size check keyed off it. The genuine inbound total-message DoS
///      bound is the TRANSPORT `ConnectionProtocolLimits::mMaxMessageSize` (-> `recvMaxMessageSize`),
///      enforced in the SecurityPolicy chunk-assembly path as `Bad_TcpMessageTooLarge`
///      (ua_security_policy.cpp:3024), NOT `Bad_ResponseTooLarge` and NOT `mMaxResponseMessageSize`.
///      Row 5 RED-pins the inertness (the matrix oracle's `Bad_ResponseTooLarge` is unreachable via this
///      knob) and asserts the real accept-and-decode behaviour.
///
///   3. `incomingChunkQueueDepth` is a GRACEFUL READ-PAUSE backpressure, not a hard cap. On queue
///      saturation the client `pause_reads()` on the transport and resumes below half-depth
///      (ua_client_secure_channel_impl.cpp:531/595); no chunk is dropped, no error is raised, the channel
///      is NEVER closed. The matrix oracle's strengthened "channel closed with Bad_TcpMessageTooLarge"
///      describes a DIFFERENT mechanism (`recvMaxChunkCount`/`recvMaxMessageSize`), not this field. Row 6
///      drives a real multi-chunk response with depth==1 and asserts the REAL guarantee: the full value
///      round-trips intact and the channel survives (refuting a drop-a-chunk OR a hard-close regression).
///
/// Falsifiability: every row encodes its matrix `[neg: ...]` falsifier and asserts the EXACT observable.
/// No fixed sleeps; the tier-2 sync reads block the test thread on a completion bridged off the executor.

#include "ua_history_facade.h"
#include "ua_browse_response.h"
#include "ua_browse_next_response.h"
#include "ua_browse_next_request.h"
#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_config_bundle.h"
#include "ua_client_configuration.h"
#include "ua_create_session_request.h"
#include "ua_data_value.h"
#include "ua_diagnostic_info.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;

namespace
{

// A standard NS0 Variable present on every server and readable. The rows overwrite results[0].value() in
// the ReadResponse regardless of this node's real type, so any existing readable node serves as the vehicle.
const NodeId readNode{VariableId::Server_ServerStatus_State};

// Walks the ErrorDetail cause chain looking for context key @p key; returns its value if found anywhere in
// the chain (the codec's size-context detail may be wrapped by an outer channel/close detail).
std::optional<std::string> find_context_in_chain(const ErrorDetail* detail, std::string_view key)
{
  while (detail != nullptr)
  {
    for (const auto& namedValue : detail->context)
    {
      if (namedValue.key == key)
      {
        return namedValue.value;
      }
    }
    detail = detail->cause.get();
  }
  return std::nullopt;
}

// A managed tier-2 Connection over a MisbehavingServer built with a specific ClientConfig (so the
// inbound decode caps under test are actually threaded onto the RX path). Mirrors the MisbehavingServer
// connection fixtures in client_data_access_matrix_tests.cpp / client_nodeid_namespace_matrix_tests.cpp: a
// real Client + SecureChannel + activated Session wrapped into a started ConnectionImpl and then into the
// public Connection handle. No reconnect wiring and no keep-alive poll -> single-shot, so the only inbound
// responses are the ones each row's read provokes.
class CapConnection
{
public:
  CapConnection(MisbehavingServer& server, ClientConfig clientConfig,
    std::optional<std::size_t> decodeRecursionDepth = std::nullopt,
    std::optional<std::uint32_t> transportMaxMessageSize = std::nullopt)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    if (decodeRecursionDepth)
    {
      appConfig.execution_limits().decodeRecursionDepthLimit = *decodeRecursionDepth;
    }
    if (transportMaxMessageSize)
    {
      appConfig.stack_limits().connectionProtocolLimits.maxMessageSize = *transportMaxMessageSize;
    }
    ua::client::CreateConfig createConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appConfig),
      .client = std::move(clientConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(createConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    mChannel.emplace(mClient->core().open_channel_sync(openConfig));
    auto session = mChannel->create_session_sync({.sessionName = "ClientDecodeCaps"});
    session.activate_sync();

    auto impl = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~CapConnection()
  {
    if (mConnection)
    {
      (void)mConnection->try_close_sync();
    }
    mConnection.reset();
    mChannel.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  CapConnection(const CapConnection&) = delete;
  CapConnection& operator=(const CapConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Connection> mConnection;
  VoidResult mStartStatus{};
};

// Installs a response mutator that, once @p armed is set, overwrites the first result value of every
// ReadResponse with the Variant produced by @p makeInjected. Gating on @p armed keeps the connection
// bootstrap (namespace-array read, handshake) untouched: the row arms only after start completes.
void install_read_value_injector(
  MisbehavingServer& server, std::shared_ptr<std::atomic<bool>> armed, std::function<Variant()> makeInjected)
{
  server.set_response_mutator(
    [armed = std::move(armed), makeInjected = std::move(makeInjected)](ua::Response& response)
    {
      if (!armed->load(std::memory_order_acquire))
      {
        return;
      }
      if (auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
        {
          read->results()[0].value() = makeInjected();
        }
      }
    });
}

DiagnosticInfo make_nested_diagnostic_info(std::size_t innerLevels)
{
  auto current = std::make_unique<DiagnosticInfo>();
  for (std::size_t level = 0; level < innerLevels; ++level)
  {
    DiagnosticInfo outer;
    outer.inner_diagnostic_info() = std::move(current);
    current = std::make_unique<DiagnosticInfo>(std::move(outer));
  }
  return std::move(*current);
}

// Client config carrying only the given inbound String cap override.
ClientConfig with_string_cap(uint32_t cap)
{
  ClientConfig config;
  config.maxInboundStringLength = cap;
  return config;
}

}  // namespace

// =============================================================================================
// ClientDecodeCaps.InboundStringWithinCapDecodes - maxInboundStringLength (boundary)
// With maxInboundStringLength==1024, a server String of EXACTLY 1024 bytes decodes Good and round-trips
// verbatim, while 1025 bytes (cap+1) is rejected - so an off-by-one in the cap check (>= vs >) fails the
// suite in one direction or the other. Both boundary reads run on ONE channel: the exact-cap read leaves
// the channel open, the cap+1 read then trips the cap. [neg: boundary: within cap]
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, InboundStringWithinCapDecodes)
{
  constexpr uint32_t cap = 1024;

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  auto injectLength = std::make_shared<std::atomic<uint32_t>>(cap);
  install_read_value_injector(server,
    armed,
    [injectLength]
    { return Variant{String{std::string(injectLength->load(std::memory_order_acquire), 'a')}}; });

  CapConnection connection{server, with_string_cap(cap)};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap must succeed with a 1 KiB inbound string cap: 0x" << std::hex
    << connection.start_status().status_code().as_uint32();
  armed->store(true, std::memory_order_release);

  // Exactly-at-cap (length == 1024): must decode Good and preserve every byte.
  injectLength->store(cap, std::memory_order_release);
  auto atCap = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(atCap.is_good()) << "a String of exactly maxInboundStringLength bytes must decode, got 0x"
                               << std::hex << atCap.status_code().as_uint32();
  EXPECT_EQ(atCap.value().value().as<String>().size(), cap)
    << "the exact-cap String must round-trip its full length verbatim";

  // cap+1 (length == 1025): must be rejected by the inbound cap.
  injectLength->store(cap + 1, std::memory_order_release);
  auto overCap = connection->try_read_value_sync(readNode);
  EXPECT_TRUE(overCap.is_bad())
    << "a String one byte over the cap must be rejected; a >= check would wrongly accept exactly-at-cap and "
       "an off-by-one would accept this";
  EXPECT_EQ(overCap.status_code().as_status(), Status::BadEncodingLimitsExceeded)
    << "cap+1 must surface Bad_EncodingLimitsExceeded, got 0x" << std::hex
    << overCap.status_code().as_uint32();
}

// =============================================================================================
// ClientDecodeCaps.InboundStringExceedingCapRejected - maxInboundStringLength; CL-TCP decode-bomb hardening
// With maxInboundStringLength==1024, a server String declaring a length FAR above the cap (64 KiB) is
// refused: the read surfaces Bad_EncodingLimitsExceeded and the codec's size.actual/size.max context, and
// the oversized buffer is never returned as a Good value. [neg: String length > inbound cap]
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, InboundStringExceedingCapRejected)
{
  constexpr uint32_t cap = 1024;
  constexpr uint32_t oversized = 64u * 1024u;

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_read_value_injector(server, armed, [] { return Variant{String{std::string(oversized, 'x')}}; });

  CapConnection connection{server, with_string_cap(cap)};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad()) << "a 64 KiB inbound String must NOT be accepted under a 1 KiB cap";
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded)
    << "the oversized String must surface Bad_EncodingLimitsExceeded, got 0x" << std::hex
    << result.status_code().as_uint32();

  const auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr) << "the rejection must carry a source-tagged ErrorDetail";
  EXPECT_EQ(find_context_in_chain(detail, ContextKeys::sizeMax.value()), std::to_string(cap))
    << "the ErrorDetail must record the configured cap as size.max";
  EXPECT_EQ(find_context_in_chain(detail, ContextKeys::sizeActual.value()), std::to_string(oversized))
    << "the ErrorDetail must record the attacker-declared length as size.actual";
}

// =============================================================================================
// ClientDecodeCaps.InboundByteStringExceedingCapRejected - maxInboundByteStringLength
// With a small inbound ByteString cap, a server ByteString declaring a length above the cap surfaces
// Bad_EncodingLimitsExceeded and no oversized allocation occurs (the cap check precedes the resize).
// The cap is set ABOVE the server-certificate DER carried in the handshake so the session still opens.
// [neg: ByteString length > inbound cap]
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, InboundByteStringExceedingCapRejected)
{
  constexpr uint32_t cap = 8u * 1024u;  // comfortably above any handshake server-certificate DER
  constexpr uint32_t oversized = 100u * 1024u;

  ClientConfig config;
  config.maxInboundByteStringLength = cap;

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_read_value_injector(
    server, armed, [] { return Variant{ByteString(static_cast<size_t>(oversized), uint8_t{0xAB})}; });

  CapConnection connection{server, config};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap must succeed with an 8 KiB inbound byte-string cap (server cert must fit): 0x" << std::hex
    << connection.start_status().status_code().as_uint32();
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad()) << "a 100 KiB inbound ByteString must NOT be accepted under an 8 KiB cap";
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded)
    << "the oversized ByteString must surface Bad_EncodingLimitsExceeded, got 0x" << std::hex
    << result.status_code().as_uint32();

  const auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr) << "the rejection must carry a source-tagged ErrorDetail";
  EXPECT_EQ(find_context_in_chain(detail, ContextKeys::sizeMax.value()), std::to_string(cap))
    << "the ErrorDetail must record the configured byte-string cap as size.max";
  EXPECT_EQ(find_context_in_chain(detail, ContextKeys::sizeActual.value()), std::to_string(oversized))
    << "the ErrorDetail must record the attacker-declared length as size.actual";
}

// =============================================================================================
// ClientDecodeCaps.InboundArrayLengthExceedingCapRejected - maxInboundArrayLength
// With a small inbound array element-count cap, a server response whose Variant carries an array declaring
// more elements than the cap is rejected with Bad_EncodingLimitsExceeded BEFORE the declared count is
// reserved (the length check precedes the resize/decode loop). [neg: array element count > inbound cap]
//
// CALIBRATION: the semantic MisbehavingServer emits an HONEST oversized array (a real N-element array),
// not a wire length-lie (declared-huge / short-body). It nonetheless exercises the exact cap-check-before-
// reserve code the length-lie protection lives in (ua_binary_codec.h:374 / .cpp:1834). The pure wire
// length-lie is a codec unit-test concern. The cap is set ABOVE the handshake arrays (server endpoints,
// namespace array) so the session still opens.
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, InboundArrayLengthExceedingCapRejected)
{
  constexpr uint32_t cap = 64;  // above any handshake array (endpoints / namespaces)
  constexpr uint32_t oversized = 200;

  ClientConfig config;
  config.maxInboundArrayLength = cap;

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_read_value_injector(server,
    armed,
    []
    {
      Array<int32_t> array;
      for (uint32_t i = 0; i < oversized; ++i)
      {
        array.push_back(static_cast<int32_t>(i));
      }
      return Variant{std::move(array)};
    });

  CapConnection connection{server, config};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap must succeed with a 64-element inbound array cap: 0x" << std::hex
    << connection.start_status().status_code().as_uint32();
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad()) << "a 200-element inbound array must NOT be accepted under a 64-element cap";
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded)
    << "the oversized array must surface Bad_EncodingLimitsExceeded, got 0x" << std::hex
    << result.status_code().as_uint32();

  const auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr) << "the rejection must carry a source-tagged ErrorDetail";
  EXPECT_EQ(find_context_in_chain(detail, ContextKeys::sizeMax.value()), std::to_string(cap))
    << "the ErrorDetail must record the configured array cap as size.max";
  EXPECT_EQ(find_context_in_chain(detail, ContextKeys::sizeActual.value()), std::to_string(oversized))
    << "the ErrorDetail must record the attacker-declared element count as size.actual";
}

// @verifies CL-ADDRSP-007
// @relation(CL-ADDRSP-007, scope=function)
TEST(ClientDecodeCaps, InboundNestedDiagnosticExceedingConfiguredDepthRejected)
{
  constexpr std::size_t clientDepthCap = 32;
  constexpr std::size_t nestedInnerLevels = 64;

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  server.set_response_mutator(
    [armed](ua::Response& response)
    {
      if (!armed->load(std::memory_order_acquire))
      {
        return;
      }
      if (auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get()))
      {
        read->response_header().service_diagnostics() = make_nested_diagnostic_info(nestedInnerLevels);
      }
    });

  CapConnection connection{server, ClientConfig{}, clientDepthCap};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded);
  const auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  bool foundRecursionDetail = false;
  for (; detail != nullptr; detail = detail->cause.get())
  {
    foundRecursionDetail = foundRecursionDetail || detail->code == "RecursionDepthExceeded";
  }
  EXPECT_TRUE(foundRecursionDetail);
}

// =============================================================================================
// ClientDecodeCaps.SessionMaxResponseSizeIsDerivedFromTheTransportLimit -
//   maxResponseMessageSize (OPC 10000-4 Table 15)
// This row previously RED-pinned a product gap: `ClientConfig::mMaxResponseMessageSize` was
// never written onto CreateSessionRequest, and never enforced inbound. HALF of that is now fixed and
// half is a settled design decision, so the row asserts the new truth in both directions.
//
// (a) The client DOES now state the session limit, DERIVED from the transport MaxMessageSize it
//     already advertises in Hello - it cannot accept a response larger than that, so a separately
//     settable client field could only contradict it, and the field was removed.
// (b) It still does not ENFORCE a per-session inbound cap, deliberately: Table 15's obligation is a
//     `should` on the SERVER, and the bound that actually protects this client is the transport
//     ConnectionProtocolLimits::mMaxMessageSize -> Bad_TcpMessageTooLarge, which is enforced in both
//     directions by the shared encode path.
// [neg: response far larger than any per-session cap is still accepted under the transport limit]
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, SessionMaxResponseSizeIsDerivedFromTheTransportLimit)
{
  constexpr uint32_t responseValueBytes = 4096;  // well under every real cap

  // NON-DEFAULT transport limit, so the assertion below can tell a derivation from a constant: if
  // the client ever went back to sending 0, or to a hard-coded 16 MiB, this fails.
  constexpr uint32_t transportMaxMessage = 2u * 1024u * 1024u;
  ClientConfig config;

  MisbehavingServer server;

  auto sawCreateSession = std::make_shared<std::atomic<bool>>(false);
  auto negotiatedMaxResponse = std::make_shared<std::atomic<uint32_t>>(0xFFFFFFFFu);
  server.set_request_observer(
    [sawCreateSession, negotiatedMaxResponse](const ua::Structure& request)
    {
      if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
      {
        negotiatedMaxResponse->store(create->max_response_message_size(), std::memory_order_release);
        sawCreateSession->store(true, std::memory_order_release);
      }
    });

  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_read_value_injector(
    server, armed, [] { return Variant{String{std::string(responseValueBytes, 'z')}}; });

  CapConnection connection{server, config, std::nullopt, transportMaxMessage};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  // (a) The client STATES the session limit, and it equals the transport limit it advertised.
  ASSERT_TRUE(sawCreateSession->load(std::memory_order_acquire))
    << "the CreateSessionRequest must be observable on the wire";
  EXPECT_EQ(negotiatedMaxResponse->load(std::memory_order_acquire), transportMaxMessage)
    << "maxResponseMessageSize must be DERIVED from mConnectionProtocolLimits.mMaxMessageSize; 0 means "
       "the derivation was dropped, 16 MiB means it was replaced by a constant";

  // (b) It is still not enforced per-session on the inbound path, by design: a response comfortably
  // under the transport limit is decoded and delivered intact.
  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_good()) << "a response under the transport limit must be accepted, got 0x" << std::hex
                                << result.status_code().as_uint32();
  EXPECT_EQ(result.value().value().as<String>().size(), responseValueBytes)
    << "the full value must be delivered intact";
}

// =============================================================================================
// ClientDecodeCaps.ClientWideDefaultSessionTimeoutReachesCreateSession - defaultSessionTimeout
// `ClientConfig::defaultSessionTimeout` was read by nothing: the connect path hard-coded
// 1200000.0, which is numerically identical to the field's own 20-minute default, so every test
// that asserted "the request carried 20 minutes" passed whether or not the field was consulted.
// This sets a NON-DEFAULT value, which is the only thing that can tell a wired field from a dead
// one. [neg: a regression to the literal makes this fail]
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, ClientWideDefaultSessionTimeoutReachesCreateSession)
{
  constexpr double sessionTimeoutMs = 300'000.0;  // 5 minutes - NOT the 20-minute default

  ClientConfig config;
  config.defaultSessionTimeout = std::chrono::milliseconds{static_cast<int64_t>(sessionTimeoutMs)};

  MisbehavingServer server;

  auto sawCreateSession = std::make_shared<std::atomic<bool>>(false);
  auto requestedTimeout = std::make_shared<std::atomic<double>>(-1.0);
  server.set_request_observer(
    [sawCreateSession, requestedTimeout](const ua::Structure& request)
    {
      if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
      {
        requestedTimeout->store(create->requested_session_timeout(), std::memory_order_release);
        sawCreateSession->store(true, std::memory_order_release);
      }
    });

  CapConnection connection{server, config};
  ASSERT_TRUE(connection.start_status().is_good());

  ASSERT_TRUE(sawCreateSession->load(std::memory_order_acquire))
    << "the CreateSessionRequest must be observable on the wire";
  EXPECT_DOUBLE_EQ(requestedTimeout->load(std::memory_order_acquire), sessionTimeoutMs)
    << "defaultSessionTimeout must reach requestedSessionTimeout; 1200000 means the connect path "
       "went back to its hard-coded literal";
}

// =============================================================================================
// ClientDecodeCaps.IncomingChunkQueueDepthCapBackpressures - incomingChunkQueueDepth
// A server response large enough to span several secure-channel chunks is delivered to a client configured
// with the minimum queue depth (1), maximally engaging the read-pause / resume backpressure path. REAL
// behaviour: the pause is GRACEFUL - no chunk is dropped, no error is raised, the channel is not closed -
// so the full value round-trips intact and a subsequent read still succeeds. [neg: chunk backlog > queue
// depth]
//
// CALIBRATION: the matrix's strengthened oracle ("channel closed with Bad_TcpMessageTooLarge") describes a
// DIFFERENT mechanism (the SecurityPolicy recvMaxChunkCount / recvMaxMessageSize hard caps), NOT
// incomingChunkQueueDepth, which never closes. This asserts the real graceful-backpressure guarantee: a
// drop-a-chunk regression corrupts/shortens the value; a hard-close-on-overflow regression fails the read
// or the follow-up read. The full raw-chunk-flood-faster-than-drain race is a strand-component unit concern.
// =============================================================================================
// @verifies CL-TCP-012
// @relation(CL-TCP-012, scope=function)
TEST(ClientDecodeCaps, IncomingChunkQueueDepthCapBackpressures)
{
  constexpr uint32_t multiChunkBytes = 300u * 1024u;  // > one 64 KiB send buffer -> multiple chunks

  ClientConfig config;
  config.incomingChunkQueueDepth = 1;  // minimum: read-pause on every queued chunk

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_read_value_injector(
    server, armed, [] { return Variant{String{std::string(multiChunkBytes, 'q')}}; });

  CapConnection connection{server, std::move(config)};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  // A ~300 KiB response spans several chunks; backpressure (depth 1) must not drop a chunk or close.
  auto large = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(large.is_good())
    << "a multi-chunk response under read-pause backpressure must round-trip Good, got 0x" << std::hex
    << large.status_code().as_uint32();
  EXPECT_EQ(large.value().value().as<String>().size(), multiChunkBytes)
    << "graceful backpressure must deliver every byte (no chunk dropped)";

  // The channel must have survived the multi-chunk flood: a follow-up (normal-size) read still succeeds.
  armed->store(false, std::memory_order_release);
  auto followUp = connection->try_read_value_sync(readNode);
  EXPECT_TRUE(followUp.is_good())
    << "the channel must stay open after backpressure - a hard-close regression fails this follow-up read, "
       "got 0x"
    << std::hex << followUp.status_code().as_uint32();
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// The server's Browse answer is rewritten to carry a continuation point, and every BrowseNext answer to echo
// that point with no references: a server that never makes progress. The history configuration drain (tier 2,
// a real Connection) asks again ten times, then ends with Bad_Timeout on the eleventh empty page (public API
// review D1, API-D1.4) and releases the point.
TEST(ClientDecodeCaps, AHistoryConfigurationDrainEndsWhenTheServerEchoesItsContinuationPoint)
{
  MisbehavingServer server;
  auto browseNextRequests = std::make_shared<std::atomic<int>>(0);
  server.set_request_observer(
    [browseNextRequests](const ua::Structure& request)
    {
      if (dynamic_cast<const ua::BrowseNextRequest*>(&request) != nullptr)
      {
        browseNextRequests->fetch_add(1, std::memory_order_acq_rel);
      }
    });
  const ua::ContinuationPoint echoed{ua::ByteString{std::vector<std::uint8_t>{0x2A}}};
  server.set_response_mutator(
    [echoed](ua::Response& response)
    {
      if (auto* browse = dynamic_cast<ua::BrowseResponse*>(response.second.get()))
      {
        if (!browse->results().empty())
        {
          browse->results()[0].continuation_point() = echoed;  // "there is more": the client drains
        }
        return;
      }
      if (auto* browseNext = dynamic_cast<ua::BrowseNextResponse*>(response.second.get()))
      {
        browseNext->results().clear();
        ua::BrowseResult looping;
        looping.status_code() = ua::Status::Good;
        looping.continuation_point() = echoed;  // the same point, nothing else, forever
        browseNext->results().push_back(std::move(looping));
      }
    });

  CapConnection connection{server, ClientConfig{}};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result =
    connection->history().try_historical_configurations_sync(NodeId{VariableId::Server_ServerStatus_State});

  ASSERT_TRUE(result.is_bad()) << "a drain that never makes progress must end, not spin";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTimeout);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (
    browseNextRequests->load(std::memory_order_acquire) < 12 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  EXPECT_EQ(browseNextRequests->load(std::memory_order_acquire), 12)
    << "eleven reads, then one release of the point the server still holds";
}
