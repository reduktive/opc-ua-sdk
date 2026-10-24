// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `StackLimits` rows of the configuration coverage matrix
///        (configuration coverage matrix section 9, section 11).
///
/// These are the connection-protocol timeouts that defend a server against sockets that connect and then
/// go quiet - the cheapest denial of service there is, since an idle socket costs the attacker nothing and
/// costs the server a slot. Every row here asserts that the server HANGS UP, and hangs up on time.
///
/// HARNESS. A hand-rolled TCP client, not the SDK client. That is deliberate: two of the three rows
/// require the peer to misbehave in ways the product client cannot be made to (never send HEL at all; send
/// a HEL header and then stop mid-body). A `RawPeer` dials the real `TestServer`, writes bytes chosen
/// here, and then waits for the server to close - so the oracle is a socket event a real peer observes,
/// not an internal state read.
///
/// ONE FIELD PER FIXTURE. The three timeouts overlap in what they can close, so a fixture that shortened
/// all three would prove only that SOME timer fired. Each fixture below moves exactly ONE field and leaves
/// the other two at their defaults (10 s, 10 s, 30 s), all far outside the observation window - so the
/// close is attributable to the field under test and to nothing else. Each row's comment names the
/// default's behaviour, which is uniformly "the socket is still open when the test gives up".
///
/// TIMING DISCIPLINE. Timeout rows are asserted as a BAND, never an equality: a lower bound that the
/// server did not close EARLY (which would mean a different, shorter timer fired) and an upper bound that
/// it closed at all. The bounds are wide enough to survive a loaded CI box and still exclude every
/// default.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "requests.h"
#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_data_value.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace
{
using namespace std::chrono_literals;

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value)
{
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

/// A complete, well-formed HEL frame (Part 6 section 7.1.2.3) for @p endpointUrl.
///
/// Hand-rolled rather than taken from the product encoder: these rows are about what the server does with
/// a conforming HEL, so encoding it independently means a framing bug cannot hide behind itself.
std::vector<std::uint8_t> make_hello(const std::string& endpointUrl)
{
  std::vector<std::uint8_t> body;
  append_u32(body, 0);  // protocol version
  append_u32(body, 65536);  // receive buffer
  append_u32(body, 65536);  // send buffer
  append_u32(body, 16777216);  // max message size
  append_u32(body, 0);  // max chunk count (0 = no limit)
  append_u32(body, static_cast<std::uint32_t>(endpointUrl.size()));
  body.insert(body.end(), endpointUrl.begin(), endpointUrl.end());

  std::vector<std::uint8_t> frame{'H', 'E', 'L', 'F'};
  append_u32(frame, static_cast<std::uint32_t>(body.size() + 8));
  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

void append_string(std::vector<std::uint8_t>& out, std::string_view text)
{
  append_u32(out, static_cast<std::uint32_t>(text.size()));
  out.insert(out.end(), text.begin(), text.end());
}

void append_null_bytestring(std::vector<std::uint8_t>& out)
{
  append_u32(out, 0xFFFFFFFF);  // length -1 encodes a null ByteString
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, size_t offset)
{
  return static_cast<std::uint32_t>(bytes[offset]) | (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

/// A minimal, conforming `OpenSecureChannel` request under SecurityPolicy None (Part 6 section 7.3.2).
///
/// Hand-rolled for the same reason as the HEL: the row is about the server's answer, so encoding the
/// question with the product encoder would leave a shared bug invisible. None is the right policy here
/// because it leaves the body in the clear - no signature or encryption to reproduce - and the lifetime
/// negotiation under test is policy-independent.
std::vector<std::uint8_t> make_open_secure_channel(std::uint32_t requestedLifetime)
{
  std::vector<std::uint8_t> body;
  // TypeId: OpenSecureChannelRequest_Encoding_DefaultBinary (i=446), four-byte NodeId encoding.
  body.insert(body.end(), {0x01, 0x00, 0xBE, 0x01});
  // RequestHeader.
  body.insert(body.end(), {0x00, 0x00});  // AuthenticationToken: two-byte null NodeId
  for (int i = 0; i < 8; ++i)
    body.push_back(0);  // Timestamp
  append_u32(body, 1);  // RequestHandle
  append_u32(body, 0);  // ReturnDiagnostics
  append_null_bytestring(body);  // AuditEntryId
  append_u32(body, 0);  // TimeoutHint
  body.insert(body.end(), {0x00, 0x00, 0x00});  // AdditionalHeader: null ExtensionObject
  // Request body.
  append_u32(body, 0);  // ClientProtocolVersion
  append_u32(body, 0);  // RequestType: Issue
  append_u32(body, 1);  // SecurityMode: None
  append_null_bytestring(body);  // ClientNonce
  append_u32(body, requestedLifetime);

  std::vector<std::uint8_t> security;
  append_u32(security, 0);  // SecureChannelId: 0 until the server assigns one
  append_string(security, "http://opcfoundation.org/UA/SecurityPolicy#None");
  append_null_bytestring(security);  // SenderCertificate
  append_null_bytestring(security);  // ReceiverCertificateThumbprint
  append_u32(security, 1);  // SequenceNumber
  append_u32(security, 1);  // RequestId

  std::vector<std::uint8_t> frame{'O', 'P', 'N', 'F'};
  append_u32(frame, static_cast<std::uint32_t>(8 + security.size() + body.size()));
  frame.insert(frame.end(), security.begin(), security.end());
  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

struct DecodedOpenSecureChannelResponse
{
  std::uint32_t serviceResult{};
  std::uint32_t revisedLifetime{};
};

/// Walk an OPN response far enough to reach the granted lifetime.
///
/// Returns `nullopt` if the frame is shorter than the walk needs, so a malformed or truncated response
/// fails the row rather than reading past the end of the buffer.
std::optional<DecodedOpenSecureChannelResponse> decode_open_secure_channel_response(
  const std::vector<std::uint8_t>& bytes)
{
  size_t cursor = 8;  // message header
  const auto skipBytes = [&](size_t count)
  {
    cursor += count;
  };
  const auto skipLengthPrefixed = [&]()
  {
    if (cursor + 4 > bytes.size())
      return false;
    const auto length = read_u32(bytes, cursor);
    cursor += 4;
    if (length != 0xFFFFFFFF)
      cursor += length;
    return true;
  };

  skipBytes(4);  // SecureChannelId
  if (!skipLengthPrefixed())  // SecurityPolicyUri
    return std::nullopt;
  if (!skipLengthPrefixed())  // SenderCertificate
    return std::nullopt;
  if (!skipLengthPrefixed())  // ReceiverCertificateThumbprint
    return std::nullopt;
  skipBytes(8);  // SequenceHeader
  skipBytes(4);  // TypeId (four-byte NodeId)

  // ResponseHeader: Timestamp(8) RequestHandle(4) ServiceResult(4) ServiceDiagnostics(1, empty mask)
  //                 StringTable(4, null array) AdditionalHeader(3, null ExtensionObject)
  skipBytes(8);
  skipBytes(4);
  if (cursor + 4 > bytes.size())
    return std::nullopt;
  DecodedOpenSecureChannelResponse decoded;
  decoded.serviceResult = read_u32(bytes, cursor);
  skipBytes(4);
  skipBytes(1 + 4 + 3);

  skipBytes(4);  // ServerProtocolVersion
  // ChannelSecurityToken: ChannelId(4) TokenId(4) CreatedAt(8) RevisedLifetime(4)
  skipBytes(4 + 4 + 8);
  if (cursor + 4 > bytes.size())
    return std::nullopt;
  decoded.revisedLifetime = read_u32(bytes, cursor);
  return decoded;
}

/// Split `opc.tcp://host:port/path` into host and port.
std::pair<std::string, std::string> split_endpoint(const std::string& url)
{
  const auto afterScheme = url.find("://");
  const auto hostStart = (afterScheme == std::string::npos) ? 0 : afterScheme + 3;
  const auto pathStart = url.find('/', hostStart);
  const auto authority = url.substr(hostStart, pathStart - hostStart);
  const auto colon = authority.rfind(':');
  return {authority.substr(0, colon), authority.substr(colon + 1)};
}

/// A raw TCP peer that can be made to misbehave in ways the product client cannot.
class RawPeer
{
public:
  /// @param sourceAddress optional local address to bind before connecting. The per-IP throttle map is
  ///        keyed by REMOTE address, so distinct keys need distinct source addresses - 127.0.0.0/8 is all
  ///        local on Linux, which is what makes a per-IP eviction row possible on one machine.
  explicit RawPeer(const std::string& endpointUrl, const std::string& sourceAddress = {}) : mSocket(mIo)
  {
    const auto [host, port] = split_endpoint(endpointUrl);
    boost::asio::ip::tcp::resolver resolver(mIo);
    const auto endpoints = resolver.resolve(host, port);
    if (sourceAddress.empty())
    {
      boost::asio::connect(mSocket, endpoints);
      return;
    }
    // Single-endpoint connect, NOT the range form: `boost::asio::connect(socket, range)` closes and
    // reopens the socket for each candidate, which silently discards the bind - so every peer would reach
    // the server as 127.0.0.1 and share one throttle budget.
    mSocket.open(boost::asio::ip::tcp::v4());
    mSocket.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(sourceAddress), 0));
    mSocket.connect(*endpoints.begin());
  }

  void write(const std::vector<std::uint8_t>& bytes)
  {
    boost::asio::write(mSocket, boost::asio::buffer(bytes));
  }

  struct Message
  {
    std::string type;
    std::vector<std::uint8_t> bytes;  ///< The complete frame, header included.
  };

  /// Read one complete framed message (header plus the body its MessageSize announces).
  Message read_full_message()
  {
    Message message;
    message.bytes.resize(8);
    boost::system::error_code ec;
    boost::asio::read(mSocket, boost::asio::buffer(message.bytes), ec);
    if (ec)
    {
      message.type = "<closed: " + ec.message() + ">";
      return message;
    }
    message.type.assign(reinterpret_cast<const char*>(message.bytes.data()), 3);

    const auto messageSize = read_u32(message.bytes, 4);
    if (messageSize < 8 || messageSize > 1'000'000)
      return message;
    message.bytes.resize(messageSize);
    boost::asio::read(mSocket, boost::asio::buffer(message.bytes.data() + 8, messageSize - 8), ec);
    return message;
  }

  /// Block until the server closes the connection, and report how long that took.
  ///
  /// Returns `nullopt` if @p limit elapsed with the socket still open - which is what a server that
  /// ignored the timeout under test does, and is therefore the failing outcome for every row here.
  /// A server-sent ERR frame counts as a close: Part 6 section 7.1.2.5 has the server report the fault before
  /// hanging up, so the bytes and the FIN are two halves of one event.
  std::optional<std::chrono::milliseconds> wait_for_close(std::chrono::milliseconds limit)
  {
    const auto start = std::chrono::steady_clock::now();
    mSocket.non_blocking(true);
    while (std::chrono::steady_clock::now() - start < limit)
    {
      std::array<std::uint8_t, 512> scratch{};
      boost::system::error_code ec;
      const auto n = mSocket.read_some(boost::asio::buffer(scratch), ec);
      if (ec == boost::asio::error::would_block)
      {
        std::this_thread::sleep_for(10ms);
        continue;
      }
      if (ec || n == 0)
        return std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - start);
      // Bytes arrived (an ERR frame); keep reading until the FIN so the elapsed time is time-to-CLOSE.
    }
    return std::nullopt;
  }

  /// Read one framed message and return its 3-character type tag, or "" if the peer closed first.
  ///
  /// Consumes the WHOLE frame, not just its header - otherwise the body is left in the socket buffer and
  /// the next read starts mid-frame, which decodes as garbage rather than as an obvious error.
  std::string read_message_type()
  {
    return read_full_message().type;
  }

private:
  boost::asio::io_context mIo;
  boost::asio::ip::tcp::socket mSocket;
};

// ---------------------------------------------------------------------------------------------------
// mConnectionProtocolTimeout - the socket that connects and never says HEL.
// ---------------------------------------------------------------------------------------------------

class ConfigurationConnectionProtocolTimeout : public ComplianceBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    // ONLY this field moves. mConnectionProtocolMessageReadTimeout (10 s) and firstOpnTimeout (30 s)
    // stay at their defaults, both far beyond the window below, so neither can be what closes the socket.
    appCfg.stack_limits().connectionProtocolTimeout = 1s;  // default 10 s
  }
};

// A peer that completes the TCP handshake and then sends nothing at all. The server must reclaim the slot
// on its own initiative. DEFAULT (10 s): the socket is still open when this test gives up at 4 s.
TEST_F(ConfigurationConnectionProtocolTimeout, SilentPeerIsDisconnectedWhenTheHandshakeBudgetExpires)
{
  RawPeer peer(mEndpointUrl);

  const auto closedAfter = peer.wait_for_close(4000ms);

  ASSERT_TRUE(closedAfter.has_value()) << "server never closed a silent connection; the 1 s handshake "
                                          "budget was not applied (default 10 s would also not close here)";
  // Lower bound: a close much before the budget would mean some other, shorter timer fired.
  EXPECT_GE(closedAfter->count(), 500) << "closed too early to be the 1 s handshake budget";
  EXPECT_LT(closedAfter->count(), 3500) << "close was not bounded by the configured budget";
}

// ---------------------------------------------------------------------------------------------------
// firstOpnTimeout - the peer that completes HEL/ACK and then stalls before OPN.
// ---------------------------------------------------------------------------------------------------

class ConfigurationFirstOpnTimeout : public ComplianceBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    // ONLY this field moves. The handshake budget stays at its 10 s default and is in any case satisfied
    // by the HEL below, so the close observed here can only be the first-OPN timer.
    appCfg.stack_limits().firstOpnTimeout = 1s;  // default 30 s
  }
};

// This is the more expensive idle socket of the two: the peer has completed the connection protocol, so
// the server has committed a channel slot to it, and it then never opens a channel.
// DEFAULT (30 s): the socket is still open when this test gives up at 4 s.
TEST_F(ConfigurationFirstOpnTimeout, PeerThatNeverOpensAChannelIsDisconnectedAfterTheFirstOpnBudget)
{
  RawPeer peer(mEndpointUrl);
  peer.write(make_hello(mEndpointUrl));

  // Establish the precondition rather than assuming it: the row is only about the post-ACK state, so a
  // rejected HEL would make the close below mean something else entirely.
  ASSERT_EQ(peer.read_message_type(), "ACK") << "server did not accept the hand-rolled HEL";

  const auto closedAfter = peer.wait_for_close(4000ms);

  ASSERT_TRUE(closedAfter.has_value())
    << "server held an ACKed connection that never sent OPN; the 1 s first-OPN budget was not applied";
  EXPECT_GE(closedAfter->count(), 500) << "closed too early to be the 1 s first-OPN budget";
  EXPECT_LT(closedAfter->count(), 3500) << "close was not bounded by the configured budget";
}

// The first-OPN budget runs until an OpenSecureChannel is accepted, not until the first chunk arrives. Part 6
// lets an OPN span several chunks, so a peer can send one intermediate chunk ('C') and then nothing: the
// server waits for the rest of the message with no read timer of its own.
// @relation(AC-SVR-TCP-019-INTERMEDIATE-OPN-CHUNK, scope=function)
TEST_F(ConfigurationFirstOpnTimeout, PeerThatSendsOneIntermediateOpnChunkIsDisconnectedAfterTheFirstOpnBudget)
{
  RawPeer peer(mEndpointUrl);
  peer.write(make_hello(mEndpointUrl));
  ASSERT_EQ(peer.read_message_type(), "ACK") << "server did not accept the hand-rolled HEL";

  std::vector<std::uint8_t> body;
  append_u32(body, 0);  // secure channel id
  append_string(body, "http://opcfoundation.org/UA/SecurityPolicy#None");
  append_null_bytestring(body);  // sender certificate
  append_null_bytestring(body);  // receiver certificate thumbprint
  append_u32(body, 1);  // sequence number
  append_u32(body, 1);  // request id
  body.insert(body.end(), {0x01, 0x00, 0xBE, 0x01});  // the first bytes of an OpenSecureChannelRequest
  std::vector<std::uint8_t> chunk{'O', 'P', 'N', 'C'};
  append_u32(chunk, static_cast<std::uint32_t>(body.size() + 8));
  chunk.insert(chunk.end(), body.begin(), body.end());
  peer.write(chunk);

  const auto closedAfter = peer.wait_for_close(4000ms);

  ASSERT_TRUE(closedAfter.has_value()) << "server held a connection that sent one intermediate OPN chunk; "
                                          "the 1 s first-OPN budget was not applied";
  EXPECT_GE(closedAfter->count(), 500) << "closed too early to be the 1 s first-OPN budget";
  EXPECT_LT(closedAfter->count(), 3500) << "close was not bounded by the configured budget";
}

// ---------------------------------------------------------------------------------------------------
// mConnectionProtocolMessageReadTimeout - the peer that stops mid-message.
// ---------------------------------------------------------------------------------------------------

class ConfigurationMessageReadTimeout : public ComplianceBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    // ONLY this field moves. The handshake budget stays at 10 s - which matters more here than elsewhere,
    // because a shortened handshake budget would close this same socket for a DIFFERENT reason and the row
    // would pass without the field under test doing anything.
    appCfg.stack_limits().connectionProtocolMessageReadTimeout = 500ms;  // default 10 s
  }
};

// The partial-message attack: a header promising a body, then silence. The server has already sized a
// buffer to the announced MessageSize, so holding it is strictly worse than holding an idle socket.
//
// THE MESSAGE MUST BE POST-HANDSHAKE. The budget governs the connection protocol's own message framing,
// which only becomes the reader once HEL/ACK is done; while the handshake is in flight the separate
// handshake deadline owns the socket. A truncated HEL therefore exercises the wrong timer entirely - it
// sits until the handshake budget expires, which is how the first version of this row failed. The
// truncated frame here is an OPN, sent after a completed handshake.
//
// DEFAULT (10 s): the buffer is still held and the socket still open when this test gives up at 3 s.
TEST_F(ConfigurationMessageReadTimeout, PeerThatStopsMidMessageIsAbandonedWhenTheReadBudgetExpires)
{
  RawPeer peer(mEndpointUrl);
  peer.write(make_hello(mEndpointUrl));
  ASSERT_EQ(peer.read_message_type(), "ACK") << "server did not accept the hand-rolled HEL";

  // An OPN header announcing a 200-byte message, followed by 4 bytes of body and nothing more. The size
  // stays well inside the negotiated receive buffer so the server accepts the header and waits for a body
  // that will never arrive - rather than rejecting the frame outright, which would prove nothing.
  std::vector<std::uint8_t> truncatedOpn{'O', 'P', 'N', 'F'};
  append_u32(truncatedOpn, 200);
  append_u32(truncatedOpn, 0);  // secure channel id - 4 bytes of a body the peer never finishes
  peer.write(truncatedOpn);

  const auto closedAfter = peer.wait_for_close(3000ms);

  ASSERT_TRUE(closedAfter.has_value())
    << "server waited indefinitely on an incomplete message; the 500 ms read budget was not applied";
  EXPECT_LT(closedAfter->count(), 2500) << "close was not bounded by the configured read budget";
}

// ---------------------------------------------------------------------------------------------------
// secureChannelMaximumLifetime - the lifetime the server grants a greedy peer.
// ---------------------------------------------------------------------------------------------------

class ConfigurationSecureChannelMaximumLifetime : public ComplianceBase
{
protected:
  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    // The minimum moves too, but only because the configuration invariant requires max >= min and the
    // default minimum (300 s) exceeds the maximum under test. It cannot account for the oracle: a minimum
    // raises SMALL requests, and the request below is far ABOVE the maximum, so only the maximum can be
    // what revises it down. The minimum has its own row elsewhere.
    appCfg.stack_limits().secureChannelMinimumLifetime = 1000ms;  // default 300'000
    appCfg.stack_limits().secureChannelMaximumLifetime = 5000ms;  // default 3'600'000
  }
};

// A peer that asks for a two-hour channel. Granting it would let one client pin a channel slot - and its
// session key - long past any reasonable rekey interval, which is why Part 4 has the server revise the
// lifetime down rather than honour the request.
//
// The oracle is the OPN RESPONSE off the wire, hand-decoded here. It has to be: no client-side accessor
// surfaces the granted channel lifetime (only the requested one is reachable, via the client config), so
// a test built on the SDK client could observe the request but never the server's answer to it.
//
// DEFAULT (3'600'000 ms): the same request is revised to one hour, not to 5000 ms.
TEST_F(ConfigurationSecureChannelMaximumLifetime, GreedyLifetimeRequestIsRevisedDownToTheConfiguredCeiling)
{
  RawPeer peer(mEndpointUrl);
  peer.write(make_hello(mEndpointUrl));
  ASSERT_EQ(peer.read_message_type(), "ACK") << "server did not accept the hand-rolled HEL";

  constexpr std::uint32_t requestedLifetime = 7'200'000;  // two hours - far above both ceilings
  peer.write(make_open_secure_channel(requestedLifetime));

  const auto response = peer.read_full_message();
  ASSERT_EQ(response.type, "OPN") << "expected an OpenSecureChannel response";

  const auto decoded = decode_open_secure_channel_response(response.bytes);
  // Decoding is offset-based, so confirm the walk landed where it should before trusting the lifetime:
  // a Good service result at the expected offset is what says the cursor is aligned.
  ASSERT_TRUE(decoded.has_value()) << "could not decode the OPN response";
  ASSERT_EQ(decoded->serviceResult, 0u) << "server refused the channel; the lifetime below is meaningless";

  EXPECT_EQ(decoded->revisedLifetime, 5000u)
    << "server granted " << decoded->revisedLifetime << " ms for a " << requestedLifetime
    << " ms request; the configured 5000 ms ceiling was not applied (the default would grant 3600000)";
}

// ---------------------------------------------------------------------------------------------------
// ExecutionLimits::decodeRecursionDepthLimit - the deep-narrow decode bomb.
// ---------------------------------------------------------------------------------------------------

// A Variant may hold an `Array<Variant>`, so Variants nest arbitrarily deep on the wire. That makes a
// nested Variant chain the cheapest hostile input there is: a few hundred bytes that costs the server one
// native stack frame per level. This limit is what stops it from reaching the bottom of the stack.
ua::Variant nested_variant(size_t depth)
{
  ua::Variant value{std::int32_t{1}};
  for (size_t level = 0; level < depth; ++level)
  {
    ua::Array<ua::Variant> wrapper;
    wrapper.payload().push_back(std::move(value));
    value = ua::Variant{std::move(wrapper)};
  }
  return value;
}

class ConfigurationDecodeRecursionDepth : public ComplianceWithNodes
{
protected:
  ua::NodeId mAnyTypeNode;

  void configure_application_config(ua::ApplicationConfig& appCfg) override
  {
    // Well below the default of 100, and below any nesting the SDK's own traffic produces.
    appCfg.execution_limits().decodeRecursionDepthLimit = 8;
  }

  // A BaseDataType variable of any rank, so a nested Variant is a TYPE-LEGAL value. Writing one to the
  // fixture's Int32 node instead returns BadTypeMismatch for every depth, which masks the limit completely -
  // the shallow control "passed" that way while proving nothing.
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    auto ns = default_ns::Namespace::create("urn:test:decode-depth", mServer.thread_pool().executor());
    const auto nsIndex = addressSpace.add_namespace_sync(ns);
    mAnyTypeNode = ua::NodeId{nsIndex, uint32_t{9100}};

    auto node = addressSpace.create_node_sync(mAnyTypeNode, ua::NodeClass::Variable);
    auto variable = node.as<ua::VariableAccessor>();
    variable->set_browse_name(ua::QualifiedName{nsIndex, "AnyValue"});
    variable->set_data_type(ua::NodeId{ua::DataTypeId::BaseDataType});
    // Any rank too: the nested values are arrays, and an unset ValueRank reads as Scalar.
    variable->set_value_rank(ua::ValueRank{ua::ValueRank::any});
    variable->set_access_level(
      ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(ua::Variant{std::int32_t{0}});
    auto objects = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder});
    objects.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, mAnyTypeNode);
  }

  // The service-level result of writing a Variant nested @p depth levels deep.
  ua::StatusCode write_nested(size_t depth)
  {
    auto response =
      mSession->attributes().try_write_sync(WriteRequestBuilder().write(mAnyTypeNode, nested_variant(depth)));
    if (response.is_bad())
      return response.status_code();
    if (!response.value().response_header().service_result().is_good())
      return response.value().response_header().service_result();
    if (response.value().results().empty())
      return ua::StatusCode{ua::Status::BadInternalError};
    return response.value().results()[0];
  }
};

// DEFAULT (100): a 40-deep chain is comfortably inside the budget and decodes, so the server would answer
// this write on its merits instead of refusing to decode it at all.
TEST_F(ConfigurationDecodeRecursionDepth, DeeplyNestedValueIsRefusedByTheDecoder)
{
  const auto deep = write_nested(40);
  EXPECT_EQ(deep.as_status(), ua::Status::BadEncodingLimitsExceeded)
    << "a 40-level nested Variant must be refused by the decoder under an 8-level budget; the default of "
       "100 decodes this same value and the write succeeds";

  // The control is what makes this a DEPTH row rather than "the server rejects nested Variants": the same
  // shape, shallow enough to fit, must decode AND be accepted.
  const auto shallow = write_nested(3);
  EXPECT_TRUE(shallow.is_good())
    << "a 3-level nested Variant is inside the budget and must be written normally";
}

// ExecutionLimits::decodeWorkLimit is NOT covered here, deliberately. See the matrix row and D17: the
// budget it seeds (`EncodingLimits::work_budget()`) is consumed only by the NodeSet import/export engines,
// never by the wire codec, so no value a peer can send is bounded by it. A row was written and withdrawn
// rather than left asserting something the field does not control.

// ResourceLimits::writeQueueDepthPerConnection is NOT covered here. A raw peer with a 1 KB SO_RCVBUF that
// never reads, plus a burst of 200 OPN requests, DOES close the connection - but only 4 runs in 5, and the
// close is not attributable: 200 OPNs on one channel is protocol abuse the server may close for on its own.
// A flaky row with an ambiguous oracle is worse than no row. See the matrix entry for what a real one needs.

// ---------------------------------------------------------------------------------------------------
// ConnectionThrottling::maxTrackedEndpoints - the bound on the throttle map itself.
// ---------------------------------------------------------------------------------------------------

// The per-IP throttle state is keyed by attacker-controlled data, so the map itself needs a bound or it
// becomes the memory-exhaustion vector it exists to prevent. At the cap the LRU entry is evicted - and an
// evicted IP loses its accumulated attempt history, so it is admitted again.
//
// THAT LOSS IS THE ORACLE, and it is also the field's cost: a small cap makes the rate limiter forgetful,
// which an attacker with many source addresses can exploit. Asserting it directly is what stops the row
// from being a memory-usage claim nobody can check.
//
// Distinct source addresses out of 127.0.0.0/8 give distinct map keys on one machine.
class ConfigurationMaxTrackedEndpoints : public ComplianceBase
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.connectionThrottling.enabled = true;
    cfg.connectionThrottling.maxTrackedEndpoints = 1;  // default 256: only ONE IP is remembered
    // 3, not 2: the current attempt is pushed onto the history BEFORE the comparison
    // (`ua_server_impl.cpp`), so a limit of N admits N-1 attempts. Two admitted attempts is what this row
    // needs in order to have a history worth losing.
    cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 3;
    cfg.connectionThrottling.maxConnectionsPerEndpoint = 50;  // high, so only the RATE branch can fire
  }

  // Connect once from @p source and report whether the server kept the connection.
  bool connect_survives(const std::string& source)
  {
    RawPeer peer(mEndpointUrl, source);
    return !peer.wait_for_close(400ms).has_value();
  }
};

// DEFAULT (256): both source addresses stay tracked, so the third attempt from the first address is still
// over its rate budget and is refused.
TEST_F(ConfigurationMaxTrackedEndpoints, EvictedEndpointLosesItsAccumulatedAttemptHistory)
{
  // Spend the first address's rate budget.
  EXPECT_TRUE(connect_survives("127.0.0.2")) << "first attempt is within budget";
  EXPECT_TRUE(connect_survives("127.0.0.2")) << "second attempt is within budget";
  EXPECT_FALSE(connect_survives("127.0.0.2"))
    << "the third attempt exhausts the rate budget and must be refused - without this the row could not "
       "tell eviction from a rate limiter that never fires";

  // Several DIFFERENT addresses. Eviction removes ONE entry per insert-at-cap, and the fixture's own
  // client already occupies a 127.0.0.1 entry, so a single new address is not guaranteed to displace
  // 127.0.0.2 - it may evict the older 127.0.0.1 instead. Three inserts make the displacement certain
  // because 127.0.0.2's timestamp is the oldest of the candidates by then.
  //
  // Only an entry holding no live connection is evicted; while every tracked entry holds one, an untracked
  // address is refused and leaves no history (security review PAB-2). The server releases a closed peer's
  // connection asynchronously, so each new address is retried until the previous one's release lands.
  const auto admitted_once_released = [this](const std::string& source)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!connect_survives(source))
    {
      if (std::chrono::steady_clock::now() > deadline)
        return false;
      std::this_thread::sleep_for(50ms);
    }
    return true;
  };
  for (const auto* source : {"127.0.0.3", "127.0.0.4", "127.0.0.5"})
    EXPECT_TRUE(admitted_once_released(source)) << "a new source address is within its own budget";

  // The evicted address is admitted again: its history went with the entry. Retrying cannot hide a retained
  // history: a tracked address over its rate budget is refused on every attempt.
  EXPECT_TRUE(admitted_once_released("127.0.0.2"))
    << "after eviction the first address must be admitted again; under the default cap of 256 both "
       "addresses stay tracked and this attempt is still refused";
}

}  // namespace

// =============================================================================================
// Row: ConnectionConfig::connectTimeout - the client's own deadline on a connect that hangs.
//
// The peer is a bare acceptor: it completes the TCP handshake and then writes nothing, so the
// client sits in AwaitingAcknowledge with no header ever arriving. Two deadlines can end that wait
// and they must not be confused. StackLimits::connectionProtocolTimeout is the transport's
// handshake deadline; connectTimeout is the tier-1 deadline over the whole connect. The fixture
// holds the transport deadline at 3 s so it is far outside the short half's observation window,
// which makes the early return attributable to connectTimeout and nothing else.
//
// The default (nullopt) leaves the connect bounded only by the transport deadline, which is what
// the control half measures.
// =============================================================================================

namespace
{

/// Accepts one TCP connection and then does nothing with it - the peer that never answers HELLO.
class SilentAcceptor
{
public:
  // Every acceptor and socket operation happens on the io_context thread, and nothing touches
  // either object from the thread that owns this fixture. Boost.Asio objects are not safe for
  // concurrent use: the earlier shape ran a BLOCKING accept() on the worker while the destructor
  // closed the same acceptor here, which is a race on the acceptor, on the reactor's descriptor
  // state and on `mHeld` itself - ThreadSanitizer reported it seven times from this one class
  // (pipeline 2853776712). The port is cached before the thread starts for the same reason:
  // endpoint_url() ran local_endpoint() on a live acceptor from the caller's thread.
  SilentAcceptor()
    : mAcceptor(mIo, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0)),
      mWork(boost::asio::make_work_guard(mIo))
  {
    mAcceptor.listen();
    mPort = mAcceptor.local_endpoint().port();
    mHeld.emplace(mIo);
    // Async, so the worker owns a run() loop rather than blocking in accept(): that is what makes
    // the close below expressible as work ON that thread instead of a reach-in from this one.
    mAcceptor.async_accept(*mHeld,
      [this](const boost::system::error_code&)
      {
        mAccepted.set_value();  // hold the socket open; never write to it
      });
    mThread = std::thread([this] { mIo.run(); });
  }

  ~SilentAcceptor()
  {
    boost::asio::post(mIo,
      [this]
      {
        boost::system::error_code ec;
        mAcceptor.close(ec);
        if (mHeld)
        {
          mHeld->close(ec);
        }
        mWork.reset();  // let run() return once the aborted accept handler has been delivered
      });
    if (mThread.joinable())
    {
      mThread.join();
    }
  }

  SilentAcceptor(const SilentAcceptor&) = delete;
  SilentAcceptor& operator=(const SilentAcceptor&) = delete;

  std::string endpoint_url() const
  {
    return "opc.tcp://127.0.0.1:" + std::to_string(mPort);
  }

private:
  boost::asio::io_context mIo;
  boost::asio::ip::tcp::acceptor mAcceptor;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> mWork;
  std::uint16_t mPort{};
  std::optional<boost::asio::ip::tcp::socket> mHeld;
  std::promise<void> mAccepted;
  std::thread mThread;
};

}  // namespace

class ConfigurationConnectTimeout : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    mTempDir = std::filesystem::temp_directory_path() /
               ("cfg-connect-timeout-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
    std::filesystem::create_directories(mTempDir);
    mStore = CertificateStoreFiles::create(mPool.executor(), mCrypto, {.trustListPath = mTempDir});

    auto appCfg = ua::test_utils::create_test_config();
    // Held well above the short half's window so only connectTimeout can end that connect, and well
    // below the 5 s pool-drain budget so its armed timer cannot outlive teardown.
    appCfg.stack_limits().connectionProtocolTimeout = std::chrono::seconds{3};
    ua::client::CreateConfig cfg{
      .identity = ua::ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    mClient.emplace(Client::create(mPool.executor(),
      std::move(cfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Warning}));
  }

  void TearDown() override
  {
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mPool, "cfg-connect-timeout");
    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  /// Dials the silent peer and returns how long the connect took to give up.
  std::chrono::milliseconds time_connect(std::optional<std::chrono::milliseconds> connectTimeout)
  {
    SilentAcceptor peer;
    ua::client::ConnectionConfig config;
    config.endpointUrl = peer.endpoint_url();
    config.connectTimeout = connectTimeout;

    const auto started = std::chrono::steady_clock::now();
    auto result = mClient->try_connect_sync(std::move(config));
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_TRUE(result.is_bad()) << "a peer that never answers HELLO must not yield a Connection";
    return std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  }

  std::shared_ptr<const Crypto> mCrypto;
  boost::asio::thread_pool mPool{2};
  std::filesystem::path mTempDir;
  std::shared_ptr<CertificateStore> mStore;
  std::optional<Client> mClient;
};

TEST_F(ConfigurationConnectTimeout, ConnectTimeoutAbandonsAheadOfTheTransportHandshakeDeadline)
{
  const auto configured = time_connect(std::chrono::milliseconds{400});
  EXPECT_LT(configured, std::chrono::milliseconds{1500})
    << "a 400 ms connectTimeout took " << configured.count()
    << " ms, which is the 3 s transport handshake deadline firing instead";

  // Control: with no connectTimeout the connect is bounded only by the transport deadline, so the
  // same peer holds the client for measurably longer.
  const auto unbounded = time_connect(std::nullopt);
  EXPECT_GT(unbounded, std::chrono::milliseconds{2000})
    << "without connectTimeout the connect ended after only " << unbounded.count()
    << " ms, so something other than the transport handshake deadline is ending it";
}
