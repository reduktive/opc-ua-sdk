// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <cctype>
#include <exception>
#include <boost/container_hash/hash.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/endian/conversion.hpp>
#include "ua_to_result.h"
#include "ua_guid.h"
#include "ua_error_detail.h"

namespace ua
{

const size_t Guid::length;

Guid::Guid() : mValue{}
{
  // Constructs the null (all-zero) Guid, per the ua_guid.h contract and OPC 10000-6 section 5.2.2.9 (a NodeId
  // holding an all-zero Guid is the null NodeId). A fresh RANDOM identifier is obtained explicitly via
  // generate() / create_and_generate()  -  never from the default constructor (a random default would make
  // every default-constructed Guid non-null and non-deterministic, breaking the null-NodeId contract and
  // value-semantics expectations).
}

size_t Guid::hash() const
{
  const boost::hash<boost::uuids::uuid> hash;
  return hash(mValue);
}

bool Guid::is_null() const
{
  return mValue.is_nil();
}

std::string Guid::as_string() const
{
  return to_string(mValue);
}

namespace
{
/// True for the canonical hyphenated form as_string writes: 8-4-4-4-12 hexadecimal digits, either case.
/// boost's string_generator alone also takes braces and the unhyphenated form, which as_string never
/// writes.
bool is_canonical_guid_text(string_view text)
{
  if (text.size() != 36)
  {
    return false;
  }
  for (size_t i = 0; i < text.size(); ++i)
  {
    const bool hyphenPosition = (i == 8) || (i == 13) || (i == 18) || (i == 23);
    const char c = text[i];
    if (hyphenPosition)
    {
      if (c != '-')
      {
        return false;
      }
    }
    else if (std::isxdigit(static_cast<unsigned char>(c)) == 0)
    {
      return false;
    }
  }
  return true;
}
}  // namespace

Guid Guid::parse(string_view text)
{
  if (!is_canonical_guid_text(text))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidGuidFormat", "A Guid is 8-4-4-4-12 hexadecimal digits", "Guid")
        .context(ua::ContextKeys::value, std::string(text)));
  }
  const boost::uuids::string_generator generator;
  const boost::uuids::uuid uuid = generator(std::string(text));
  Guid guid;
  std::copy(uuid.begin(), uuid.end(), guid.mValue.begin());
  return guid;
}

GuidResult Guid::try_parse(string_view text) noexcept
{
  try
  {
    return parse(text);
  }
  catch (...)
  {
    return GuidResult{exception_to_status_code(std::current_exception())};
  }
}

void Guid::swap(Guid& obj) noexcept
{
  std::swap(mValue, obj.mValue);
}

void Guid::clear()
{
  mValue = boost::uuids::uuid{};
}

void Guid::generate()
{
  mValue = boost::uuids::uuid{boost::uuids::random_generator()()};
}

std::array<byte, Guid::length> Guid::as_ua_binary() const
{
  std::array<byte, Guid::length> encoding{};
  uuid_to_bytes(mValue, encoding);
  return encoding;
}

void Guid::from_ua_binary(span<const byte> encoding)
{
  bytes_to_uuid(encoding, mValue);
}

void Guid::bytes_to_uuid(span<const byte> bytes, boost::uuids::uuid& uuid)
{
  if (bytes.empty() || (bytes.size() != length))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("GuidParseError", "Encoding length does not equal expected", "Guid")
        .context(ua::ContextKeys::sizeActual, std::to_string(bytes.size()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(length)));
  }

  using boost::endian::endian_reverse;

  uint32_t data1 = 0;
  uint16_t data2 = 0;
  uint16_t data3 = 0;

  memcpy(&data1, bytes.data(), sizeof(data1));
  data1 = endian_reverse(data1);

  constexpr size_t data2Offset{sizeof(data1)};
  memcpy(&data2, bytes.data() + data2Offset, sizeof(data2));
  data2 = endian_reverse(data2);

  constexpr size_t data3Offset{data2Offset + sizeof(data2)};
  memcpy(&data3, bytes.data() + data3Offset, sizeof(data3));
  data3 = endian_reverse(data3);

  constexpr size_t data4Offset{data3Offset + sizeof(data3)};
  constexpr size_t data4Size{length - data4Offset};

  byte* dest = reinterpret_cast<byte*>(&uuid);
  memcpy(&dest[0], &data1, sizeof(data1));
  memcpy(&dest[data2Offset], &data2, sizeof(data2));
  memcpy(&dest[data3Offset], &data3, sizeof(data3));
  memcpy(&dest[data4Offset], bytes.data() + data4Offset, data4Size);
}

void Guid::uuid_to_bytes(const boost::uuids::uuid& uuid, span<byte> bytes)
{
  using boost::endian::endian_reverse;

  uint32_t data1 = 0;
  uint16_t data2 = 0;
  uint16_t data3 = 0;

  const byte* source = reinterpret_cast<const byte*>(&uuid);
  memcpy(&data1, source, sizeof(data1));
  data1 = endian_reverse(data1);

  constexpr size_t data2Offset{sizeof(data1)};
  memcpy(&data2, source + data2Offset, sizeof(data2));
  data2 = endian_reverse(data2);

  constexpr size_t data3Offset{data2Offset + sizeof(data2)};
  memcpy(&data3, source + data3Offset, sizeof(data3));
  data3 = endian_reverse(data3);

  constexpr size_t data4Offset{data3Offset + sizeof(data3)};
  constexpr size_t data4Size{length - data4Offset};

  memcpy(&bytes[0], &data1, sizeof(data1));
  memcpy(&bytes[data2Offset], &data2, sizeof(data2));
  memcpy(&bytes[data3Offset], &data3, sizeof(data3));
  memcpy(&bytes[data4Offset], source + data4Offset, data4Size);
}

std::strong_ordering Guid::operator<=>(const Guid& other) const
{
  if (mValue < other.mValue)
  {
    return std::strong_ordering::less;
  }
  if (other.mValue < mValue)
  {
    return std::strong_ordering::greater;
  }
  return std::strong_ordering::equal;
}

BuiltInTypeId Guid::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::Guid};
}

Guid Guid::create_and_generate()
{
  Guid guid;
  guid.generate();
  return guid;
}

}  // namespace ua
