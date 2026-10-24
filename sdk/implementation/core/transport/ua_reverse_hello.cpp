// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reverse_hello.h"

#include "ua_binary_codec.h"
#include "ua_connection_protocol_limits.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_stack_utilities.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"

namespace ua::detail
{

std::vector<std::byte> encode_reverse_hello(const ReverseHelloMessage& msg)
{
  // Initial capacity: header (8) + two UA strings (4-byte length prefix + data each).
  const size_t estimatedSize = stack_utils::UaCpMessageHeader::sizeInBytes + sizeof(uint32_t) +
                               msg.serverUri.size() + sizeof(uint32_t) + msg.endpointUrl.size();

  memory_stream_device::Dynamic streamDevice{estimatedSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  const EncodingLimits limits;
  const StackDepth depth = limits.stack_depth();

  // Encode the header with a placeholder size.
  stack_utils::UaCpMessageHeader header;
  header.messageType = stack_utils::UaCpMessageHeader::MessageType::ReverseHello;
  header.messageSize = 0;
  header.encode(limits, encoder);

  // Encode the two string fields.
  const String serverUri{msg.serverUri};
  encoder.encode(depth, serverUri);

  const String endpointUrl{msg.endpointUrl};
  encoder.encode(depth, endpointUrl);

  // Write the actual message size back into the header.
  const auto messageSize = numeric_cast<uint32_t>(stream.get_position());
  // Message size field starts at byte 4 (after the 3-byte message type + 1-byte reserved).
  stream.seek_from_start(4);
  encoder.encode(depth, messageSize);

  auto buffer = streamDevice.move_storage_out();
  buffer.resize(messageSize);
  return buffer;
}

ReverseHelloMessageResult decode_reverse_hello(std::span<const std::byte> data)
{
  if (data.size() < stack_utils::UaCpMessageHeader::sizeInBytes)
  {
    return StatusCode{Status::BadDecodingError};
  }

  // The two RHE strings are bounded by the protocol grammar (validate_reverse_hello_fields), so the
  // decoder runs under that bound: a forged length prefix allocates at most maxUrlSize bytes before
  // it is refused, not up to the default byte-string limit (16 MiB; the String decoder reserves the
  // claimed length under that limit before the string limit is checked).
  EncodingLimits limits;
  limits.maxStringLength = connection_protocol::maxUrlSize;
  limits.maxByteStringLength = connection_protocol::maxUrlSize;

  // Decode the header.
  memory_stream_device::ExternalReadOnly headerDevice{
    data.subspan(0, stack_utils::UaCpMessageHeader::sizeInBytes)};
  MemoryStream headerStream{headerDevice};
  UaBinaryDecoder headerDecoder(StructureResolver{}, headerStream, limits);

  stack_utils::UaCpMessageHeader header;
  try
  {
    header.decode(limits, headerDecoder);
  }
  catch (...)
  {
    return StatusCode{Status::BadDecodingError};
  }

  if (header.messageType != stack_utils::UaCpMessageHeader::MessageType::ReverseHello)
  {
    return StatusCode{Status::BadTcpMessageTypeInvalid};
  }

  if (header.messageSize != numeric_cast<uint32_t>(data.size()))
  {
    return StatusCode{Status::BadDecodingError};
  }

  // Decode the body (everything after the 8-byte header).
  auto body = data.subspan(stack_utils::UaCpMessageHeader::sizeInBytes);
  memory_stream_device::ExternalReadOnly bodyDevice{body};
  MemoryStream bodyStream{bodyDevice};
  UaBinaryDecoder bodyDecoder(StructureResolver{}, bodyStream, limits);

  const StackDepth depth = limits.stack_depth();

  // A string over the decoder bound breaks the same grammar rule validate_reverse_hello_fields
  // enforces, so it reports that rule's status and encoded length rather than a generic decoding
  // failure. The decoder raises the limit only for a positive claimed length, read here from the
  // field's Int32 prefix at fieldOffset. The mapping runs only on the refusal path; an accepted RHE
  // pays nothing for it.
  const auto decodeField =
    [&](String& field, size_t fieldOffset, const char* tooLongName, const char* tooLongText) -> StatusCode
  {
    try
    {
      bodyDecoder.decode(depth, field);
    }
    catch (...)
    {
      const StatusCode caught = exception_to_status_code(std::current_exception());
      if (caught.as_status() == Status::BadEncodingLimitsExceeded &&
          body.size() >= fieldOffset + sizeof(int32_t))
      {
        uint32_t claimedLength = 0;
        for (size_t i = 0; i < sizeof(int32_t); ++i)
        {
          claimedLength |= std::to_integer<uint32_t>(body[fieldOffset + i]) << (8 * i);
        }
        return StatusCode{Status::BadTcpEndpointUrlInvalid,
          ErrorDetail::build(tooLongName, tooLongText, "ReverseHello")
            .context(ContextKeys::sizeActual, sizeof(int32_t) + claimedLength)
            .context(ContextKeys::sizeMax, connection_protocol::maxUrlSize - 1)};
      }
      return StatusCode{Status::BadDecodingError,
        make_error_detail("ReverseHelloFieldUndecodable",
          "A ReverseHello string field could not be decoded",
          "ReverseHello",
          caught)};
    }
    return StatusCode{Status::Good};
  };

  String serverUri;
  String endpointUrl;
  if (auto status = decodeField(serverUri,
        0,
        "ReverseHelloServerUriTooLong",
        "Encoded ReverseHello ServerUri exceeds the maximum size");
      status.is_bad())
  {
    return status;
  }
  if (auto status = decodeField(endpointUrl,
        sizeof(int32_t) + serverUri.size(),
        "ReverseHelloEndpointUrlTooLong",
        "Encoded ReverseHello EndpointUrl exceeds the maximum size");
      status.is_bad())
  {
    return status;
  }

  ReverseHelloMessage msg;
  msg.serverUri = std::string{serverUri};
  msg.endpointUrl = std::string{endpointUrl};

  auto validationStatus = validate_reverse_hello_fields(msg);
  if (validationStatus.is_bad())
  {
    return validationStatus;
  }

  return msg;
}

StatusCode validate_reverse_hello_fields(const ReverseHelloMessage& msg)
{
  // Part 6 sections 5.2.2.4 and 7.1.2.6: each encoded RHE String, including its four-byte Int32
  // length prefix, must be strictly less than 4 096 bytes. This is distinct from the HEL rule.
  constexpr size_t maxPermittedEncodedFieldSize = connection_protocol::maxUrlSize - 1;

  const size_t encodedServerUriSize = sizeof(int32_t) + msg.serverUri.size();
  if (encodedServerUriSize >= connection_protocol::maxUrlSize)
  {
    return StatusCode{Status::BadTcpEndpointUrlInvalid,
      ErrorDetail::build("ReverseHelloServerUriTooLong",
        "Encoded ReverseHello ServerUri exceeds the maximum size",
        "ReverseHello")
        .context(ContextKeys::sizeActual, encodedServerUriSize)
        .context(ContextKeys::sizeMax, maxPermittedEncodedFieldSize)};
  }

  const size_t encodedEndpointUrlSize = sizeof(int32_t) + msg.endpointUrl.size();
  if (encodedEndpointUrlSize >= connection_protocol::maxUrlSize)
  {
    return StatusCode{Status::BadTcpEndpointUrlInvalid,
      ErrorDetail::build("ReverseHelloEndpointUrlTooLong",
        "Encoded ReverseHello EndpointUrl exceeds the maximum size",
        "ReverseHello")
        .context(ContextKeys::sizeActual, encodedEndpointUrlSize)
        .context(ContextKeys::sizeMax, maxPermittedEncodedFieldSize)};
  }
  return StatusCode{Status::Good};
}

}  // namespace ua::detail
