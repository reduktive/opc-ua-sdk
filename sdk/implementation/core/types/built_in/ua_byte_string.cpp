// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_byte_string.h"

namespace ua
{

ByteString::ByteString(std::initializer_list<uint8_t> init) : mValue(init)
{}

ByteString::ByteString(size_t count, uint8_t value) : mValue(count, value)
{}

ByteString::ByteString(std::vector<uint8_t> data) : mValue(std::move(data))
{}

ByteString::ByteString(span<const uint8_t> data) : mValue(data.begin(), data.end())
{}

ByteString::ByteString(span<const byte> data)
  : mValue(reinterpret_cast<const uint8_t*>(data.data()),
      reinterpret_cast<const uint8_t*>(data.data()) + data.size())
{}

bool ByteString::is_null() const
{
  return mValue.empty();
}

bool ByteString::empty() const
{
  return mValue.empty();
}

size_t ByteString::size() const
{
  return mValue.size();
}

void ByteString::resize(size_t count)
{
  mValue.resize(count);
}

void ByteString::resize(size_t count, uint8_t value)
{
  mValue.resize(count, value);
}

void ByteString::reserve(size_t capacity)
{
  mValue.reserve(capacity);
}

void ByteString::clear()
{
  mValue.clear();
}

uint8_t& ByteString::operator[](size_t index)
{
  return mValue[index];
}

const uint8_t& ByteString::operator[](size_t index) const
{
  return mValue[index];
}

uint8_t* ByteString::data()
{
  return mValue.data();
}

const uint8_t* ByteString::data() const
{
  return mValue.data();
}

std::vector<uint8_t>::iterator ByteString::begin()
{
  return mValue.begin();
}

std::vector<uint8_t>::const_iterator ByteString::begin() const
{
  return mValue.begin();
}

std::vector<uint8_t>::iterator ByteString::end()
{
  return mValue.end();
}

std::vector<uint8_t>::const_iterator ByteString::end() const
{
  return mValue.end();
}

void ByteString::push_back(uint8_t value)
{
  mValue.push_back(value);
}

void ByteString::assign(const uint8_t* first, const uint8_t* last)
{
  mValue.assign(first, last);
}

ByteString::operator span<uint8_t>()
{
  return mValue;
}

ByteString::operator span<const uint8_t>() const
{
  return mValue;
}

ByteString::operator span<byte>()
{
  return span<byte>{reinterpret_cast<byte*>(mValue.data()), mValue.size()};
}

ByteString::operator span<const byte>() const
{
  return span<const byte>{reinterpret_cast<const byte*>(mValue.data()), mValue.size()};
}

std::vector<uint8_t>& ByteString::payload()
{
  return mValue;
}

const std::vector<uint8_t>& ByteString::payload() const
{
  return mValue;
}

BuiltInTypeId ByteString::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ByteString};
}

}  // namespace ua
