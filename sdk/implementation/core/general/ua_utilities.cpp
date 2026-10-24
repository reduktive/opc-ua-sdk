// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_utilities.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_error_detail.h"
#include "ua_security_policy.h"
#include "fmt/format.h"
#include "fmt/ranges.h"

#include "ua_byte_format.h"

namespace ua::utils
{

static size_t base64_decode_calculate_no_of_bytes(string_view encodedData)
{
  const size_t inputSize{encodedData.size()};

  if ((inputSize < 4) || ((inputSize % 4) != 0))
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("Base64InvalidLength", "Base64 encoded data has invalid length", "ua::utils::base64")
        .context(ua::ContextKeys::sizeActual, std::to_string(inputSize))};
  }

  size_t noOfBytes = (inputSize / 4) * 3;

  if (encodedData.back() == '=')
  {
    --noOfBytes;
  }
  if (encodedData.at(inputSize - 2) == '=')
  {
    --noOfBytes;
  }

  return noOfBytes;
}

static uint8_t base64_decode_character(const char input)
{
  uint8_t output{};

  if ((input >= 'A') && (input <= 'Z'))
  {
    // Guard above proves 'A' <= input <= 'Z', so input - 'A' is in [0, 25].
    output = static_cast<uint8_t>(input - 'A');
  }
  else if ((input >= 'a') && (input <= 'z'))
  {
    // Guard above proves 'a' <= input <= 'z', so 26 + input - 'a' is in [26, 51].
    output = static_cast<uint8_t>(26 + input - 'a');
  }
  else if ((input >= '0') && (input <= '9'))
  {
    // Guard above proves '0' <= input <= '9', so 52 + input - '0' is in [52, 61].
    output = static_cast<uint8_t>(52 + input - '0');
  }
  else if (input == '+')
  {
    output = 62;
  }
  else if (input == '/')
  {
    output = 63;
  }
  else
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("Base64InvalidCharacter", "Base64 could not decode character", "ua::utils::base64")
        .context(ua::ContextKeys::value, std::string(1, input))};
  }

  return output;
}

std::string base64_encode(span<const byte> input)
{
  if (input.empty())
  {
    return {};
  }

  static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  const size_t inLen = input.size();
  // 4 output chars for every 3 input bytes (rounded up)
  const size_t outLen = ((inLen + 2) / 3) * 4;
  std::string out;
  out.resize(outLen);

  size_t i = 0;  // input index
  size_t o = 0;  // output index

  while (i + 3 <= inLen)
  {
    const uint32_t group = (static_cast<uint32_t>(input[i]) << 16) |
                           (static_cast<uint32_t>(input[i + 1]) << 8) | (static_cast<uint32_t>(input[i + 2]));

    out[o++] = alphabet[(group >> 18) & 0x3F];
    out[o++] = alphabet[(group >> 12) & 0x3F];
    out[o++] = alphabet[(group >> 6) & 0x3F];
    out[o++] = alphabet[(group) & 0x3F];
    i += 3;
  }

  const size_t remain = inLen - i;
  if (remain == 1)
  {
    const uint32_t group = (static_cast<uint32_t>(input[i]) << 16);
    out[o++] = alphabet[(group >> 18) & 0x3F];
    out[o++] = alphabet[(group >> 12) & 0x3F];
    out[o++] = '=';
    out[o++] = '=';
  }
  else if (remain == 2)
  {
    const uint32_t group =
      (static_cast<uint32_t>(input[i]) << 16) | (static_cast<uint32_t>(input[i + 1]) << 8);
    out[o++] = alphabet[(group >> 18) & 0x3F];
    out[o++] = alphabet[(group >> 12) & 0x3F];
    out[o++] = alphabet[(group >> 6) & 0x3F];
    out[o++] = '=';
  }

  return out;
}

ByteString base64_decode(string_view input)
{
  const size_t noOfBytes = base64_decode_calculate_no_of_bytes(input);
  ByteString output;
  output.resize(noOfBytes);

  const span<const char> totalInput(input);

  const size_t noOfChars = totalInput.size();
  for (size_t i = 0, j = 0; i < noOfChars; i += 4, j += 3)
  {
    const span<const char> inputString = safe_sub_span(totalInput, i, 4);

    uint32_t group = 0;
    for (size_t k = 0; k < 4; ++k)
    {
      group <<= 6;

      if (((input.size() - i) == 4) && (k > 1) && (inputString[k] == '='))
      {
        continue;
      }

      const uint8_t val = base64_decode_character(inputString[k]);

      group |= val;
    }

    const span<byte> op{reinterpret_cast<byte*>(output.data()), output.size()};
    size_t lengthOfGroup = 3;
    const size_t spaceRemaining = op.size() - j;
    if (lengthOfGroup > spaceRemaining)
    {
      lengthOfGroup = spaceRemaining;
    }
    const span<byte> outputGroup = safe_sub_span(op, j, lengthOfGroup);

    const byte* grp = reinterpret_cast<byte*>(&group);
    outputGroup[0] = grp[2];
    if (outputGroup.size() == 1)
    {
      continue;
    }
    outputGroup[1] = grp[1];
    if (outputGroup.size() == 2)
    {
      continue;
    }
    outputGroup[2] = grp[0];
  }

  return output;
}

void throw_sub_span_out_of_range(size_t offset, size_t count, size_t spanSize, source_location location)
{
  throw UaException{Status::BadOutOfRange,
    ErrorDetail::build("SubSpanOutOfRange", "Subspan offset and count are out of range for span", "ua::utils")
      .context(ua::ContextKeys::offset, std::to_string(offset))
      .context(ua::ContextKeys::sizeExpected, std::to_string(count))
      .context(ua::ContextKeys::sizeActual, std::to_string(spanSize)),
    location};
}

void Timer::start()
{
  mStartTime = std::chrono::steady_clock::now();
}

void Timer::stop(string_view message)
{
  auto endTime = std::chrono::steady_clock::now();
  fmt::print("{} took {}us\n",
    message,
    std::chrono::duration_cast<std::chrono::microseconds>(endTime - mStartTime).count());
  (void)fflush(stdout);  // best-effort flush of timing output; nothing actionable on failure
}

std::string boost_error_to_string(boost::system::error_code ec)
{
  return fmt::format("{} : {} : {}", ec.category().name(), ec.value(), ec.message());
}

bool is_deprecated_security_policy(SecurityPolicyId securityPolicyId)
{
  return SecurityPolicy::create(securityPolicyId)->is_deprecated();
}

String get_security_policy_uri(SecurityPolicyId id)
{
  return SecurityPolicy::create(id)->uri();
}

SecurityPolicyId get_security_policy_id(String uri)
{
  return SecurityPolicy::create(uri)->id();
}

String get_transport_profile_uri(TransportProfileId id)
{
  static constexpr char uaTransportProfileUaTcpUaScUaBinaryUri[] =
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";

  switch (id)
  {
  case TransportProfileId::UaTcpUaScUaBinary:
    return String{uaTransportProfileUaTcpUaScUaBinaryUri};

  default:
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("UnknownTransportProfile", "Unknown transport profile ID", "ua::utils")
        .context(ua::ContextKeys::typeId, std::to_string(static_cast<int>(id)))};
  }
}

std::vector<std::string> split(string_view input, char delimiter)
{
  std::istringstream inputStream;
  inputStream.str(std::string{input});

  std::vector<std::string> output;
  for (std::string part; std::getline(inputStream, part, delimiter);)
  {
    output.push_back(part);
  }

  return output;
}

std::string bytes_to_hex_string(span<const byte> bytes)
{
  return fmt::format("{:02x}", fmt::join(bytes, " "));
}

std::vector<uint32_t> span_of_int32_to_uint32(span<const int32_t> input)
{
  std::vector<uint32_t> output;
  for (auto element : input)
  {
    output.push_back(numeric_cast<uint32_t>(element));
  }
  return output;
}

std::vector<int32_t> span_of_uint32_to_int32(span<const uint32_t> input)
{
  std::vector<int32_t> output;
  for (auto element : input)
  {
    output.push_back(numeric_cast<int32_t>(element));
  }
  return output;
}

}  // namespace ua::utils
