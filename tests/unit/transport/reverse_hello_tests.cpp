// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_error_detail.h"
#include "ua_reverse_hello.h"

#include <cstring>

using namespace ua;
using namespace ua::detail;

namespace
{

void expect_encoded_length_error(const StatusCode& status, string_view expectedCode, size_t encodedLength)
{
  EXPECT_EQ(status.as_status(), Status::BadTcpEndpointUrlInvalid);
  const auto& detail = status.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, expectedCode);

  auto contextValue = [&](ContextKey key) -> std::string
  {
    for (const auto& entry : detail->context)
    {
      if (entry.key == key.value())
      {
        return entry.value;
      }
    }
    return {};
  };

  EXPECT_EQ(contextValue(ContextKeys::sizeActual), std::to_string(encodedLength));
  EXPECT_EQ(contextValue(ContextKeys::sizeMax), "4095");
}

}  // namespace

TEST(ReverseHelloTests, EncodeDecodeRoundTrip)
{
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = "opc.tcp://localhost:4840";

  auto encoded = encode_reverse_hello(msg);
  ASSERT_FALSE(encoded.empty());

  auto result = decode_reverse_hello(encoded);
  ASSERT_TRUE(result.is_good()) << "Decode failed: 0x" << std::hex << result.status_code().as_uint32();

  EXPECT_EQ(result.value().serverUri, "urn:example:server");
  EXPECT_EQ(result.value().endpointUrl, "opc.tcp://localhost:4840");
}

TEST(ReverseHelloTests, EncodeDecodeEmptyFields)
{
  ReverseHelloMessage msg;
  msg.serverUri = "";
  msg.endpointUrl = "";

  auto encoded = encode_reverse_hello(msg);
  ASSERT_FALSE(encoded.empty());

  auto result = decode_reverse_hello(encoded);
  ASSERT_TRUE(result.is_good()) << "Decode failed: 0x" << std::hex << result.status_code().as_uint32();

  EXPECT_EQ(result.value().serverUri, "");
  EXPECT_EQ(result.value().endpointUrl, "");
}

TEST(ReverseHelloTests, EncodeDecodeLastLegalLengthFields)
{
  ReverseHelloMessage msg;
  msg.serverUri = std::string(4091, 'A');
  msg.endpointUrl = std::string(4091, 'B');

  auto encoded = encode_reverse_hello(msg);
  ASSERT_FALSE(encoded.empty());

  auto result = decode_reverse_hello(encoded);
  ASSERT_TRUE(result.is_good()) << "Decode failed: 0x" << std::hex << result.status_code().as_uint32();

  EXPECT_EQ(result.value().serverUri.size(), 4091u);
  EXPECT_EQ(result.value().endpointUrl.size(), 4091u);
}

// Part 6 section section 5.2.2.4 and 7.1.2.6: the four-byte String length prefix counts toward the strict
// 4 096-byte RHE field bound. This is distinct from the HEL EndpointUrl rule in section 7.1.2.3.
// @relation(AC-SVR-RC-005-RHE-SERVERURI-LENGTH, scope=function)
TEST(ReverseHelloTests, LastLegalServerUriEncodedLengthAccepted)
{
  ReverseHelloMessage msg;
  msg.serverUri = std::string(4091, 'S');
  msg.endpointUrl = "opc.tcp://localhost:4840";

  ASSERT_EQ(sizeof(uint32_t) + msg.serverUri.size(), 4095u);
  EXPECT_TRUE(validate_reverse_hello_fields(msg).is_good());
}

// @relation(AC-SVR-RC-005-RHE-SERVERURI-LENGTH, scope=function)
TEST(ReverseHelloTests, ServerUriEncodedLengthAtBoundRejected)
{
  ReverseHelloMessage msg;
  msg.serverUri = std::string(4092, 'S');
  msg.endpointUrl = "opc.tcp://localhost:4840";

  const size_t encodedLength = sizeof(uint32_t) + msg.serverUri.size();
  ASSERT_EQ(encodedLength, 4096u);
  expect_encoded_length_error(
    validate_reverse_hello_fields(msg), "ReverseHelloServerUriTooLong", encodedLength);
}

// Part 6 section section 5.2.2.4 and 7.1.2.6: the four-byte String length prefix counts toward the strict
// 4 096-byte RHE field bound. This is distinct from the HEL EndpointUrl rule in section 7.1.2.3.
// @relation(AC-SVR-RC-006-RHE-URL-LENGTH, scope=function)
TEST(ReverseHelloTests, LastLegalEndpointUrlEncodedLengthAccepted)
{
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = std::string(4091, 'E');

  ASSERT_EQ(sizeof(uint32_t) + msg.endpointUrl.size(), 4095u);
  EXPECT_TRUE(validate_reverse_hello_fields(msg).is_good());
}

// @relation(AC-SVR-RC-006-RHE-URL-LENGTH, scope=function)
TEST(ReverseHelloTests, EndpointUrlEncodedLengthAtBoundRejected)
{
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = std::string(4092, 'E');

  const size_t encodedLength = sizeof(uint32_t) + msg.endpointUrl.size();
  ASSERT_EQ(encodedLength, 4096u);
  expect_encoded_length_error(
    validate_reverse_hello_fields(msg), "ReverseHelloEndpointUrlTooLong", encodedLength);
}

// The decoder bounds each RHE string at maxUrlSize (4 096) so a forged length prefix cannot drive a
// large allocation. A field over that bound breaks the same grammar rule as the two tests above, so
// decode_reverse_hello must report the rule's status, detail code and encoded length - not a generic
// decoding failure. The 4 096-byte arms are the control: they clear the decoder bound and are refused
// by validate_reverse_hello_fields with the same shape.
// @relation(AC-SVR-RC-005-RHE-SERVERURI-LENGTH, scope=function)
TEST(ReverseHelloTests, DecodeOfAServerUriOverTheDecoderBoundReportsTheGrammarRule)
{
  ReverseHelloMessage msg;
  msg.serverUri = std::string(4097, 'S');
  msg.endpointUrl = "opc.tcp://localhost:4840";

  auto result = decode_reverse_hello(encode_reverse_hello(msg));
  ASSERT_FALSE(result.is_good());
  expect_encoded_length_error(result.status_code(), "ReverseHelloServerUriTooLong", 4101u);

  msg.serverUri = std::string(4096, 'S');
  auto control = decode_reverse_hello(encode_reverse_hello(msg));
  ASSERT_FALSE(control.is_good());
  expect_encoded_length_error(control.status_code(), "ReverseHelloServerUriTooLong", 4100u);
}

// @relation(AC-SVR-RC-006-RHE-URL-LENGTH, scope=function)
TEST(ReverseHelloTests, DecodeOfAnEndpointUrlOverTheDecoderBoundReportsTheGrammarRule)
{
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = std::string(4097, 'E');

  auto result = decode_reverse_hello(encode_reverse_hello(msg));
  ASSERT_FALSE(result.is_good());
  expect_encoded_length_error(result.status_code(), "ReverseHelloEndpointUrlTooLong", 4101u);

  msg.endpointUrl = std::string(4096, 'E');
  auto control = decode_reverse_hello(encode_reverse_hello(msg));
  ASSERT_FALSE(control.is_good());
  expect_encoded_length_error(control.status_code(), "ReverseHelloEndpointUrlTooLong", 4100u);
}

TEST(ReverseHelloTests, ValidateGoodFields)
{
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = "opc.tcp://localhost:4840";

  auto status = validate_reverse_hello_fields(msg);
  EXPECT_TRUE(status.is_good());
}

TEST(ReverseHelloTests, DecodeTruncatedHeader)
{
  // Less than 8 bytes - cannot even parse header.
  std::vector<std::byte> truncated(5, std::byte{0});
  auto result = decode_reverse_hello(truncated);
  EXPECT_FALSE(result.is_good());
  EXPECT_TRUE(result.status_code().is_bad());
}

TEST(ReverseHelloTests, DecodeTruncatedBody)
{
  // Encode a valid message, then truncate the body.
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = "opc.tcp://localhost:4840";

  auto encoded = encode_reverse_hello(msg);
  ASSERT_GT(encoded.size(), 12u);

  // Keep the header intact but truncate body severely.
  // The header says the full size, but we only provide header + 2 bytes.
  std::vector<std::byte> truncated(encoded.begin(), encoded.begin() + 10);

  auto result = decode_reverse_hello(truncated);
  EXPECT_FALSE(result.is_good());
  EXPECT_TRUE(result.status_code().is_bad());
}

// Covers SVR-RC-002 (coverage-audit retag).
TEST(ReverseHelloTests, DecodeWrongMessageType)
{
  // Encode a valid ReverseHello, then overwrite the message type bytes with HEL.
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = "opc.tcp://localhost:4840";

  auto encoded = encode_reverse_hello(msg);
  ASSERT_GE(encoded.size(), 8u);

  // Overwrite first 3 bytes from RHE to HEL.
  encoded[0] = std::byte{'H'};
  encoded[1] = std::byte{'E'};
  encoded[2] = std::byte{'L'};

  auto result = decode_reverse_hello(encoded);
  EXPECT_FALSE(result.is_good());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{Status::BadTcpMessageTypeInvalid}.as_uint32());
}

TEST(ReverseHelloTests, MessageSizeMatchesEncoded)
{
  ReverseHelloMessage msg;
  msg.serverUri = "urn:example:server";
  msg.endpointUrl = "opc.tcp://localhost:4840";

  auto encoded = encode_reverse_hello(msg);
  ASSERT_GE(encoded.size(), 8u);

  // Read the message size field (bytes 4-7, little-endian uint32).
  uint32_t messageSize = 0;
  std::memcpy(&messageSize, &encoded[4], sizeof(uint32_t));

  EXPECT_EQ(messageSize, static_cast<uint32_t>(encoded.size()));
}
