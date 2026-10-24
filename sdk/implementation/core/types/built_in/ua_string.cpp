// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/container_hash/hash.hpp>
#include "ua_string.h"

namespace ua
{

bool String::empty() const
{
  return mValue.empty();
}

bool String::is_null() const
{
  return mValue.empty();
}

void String::clear()
{
  mValue.clear();
}

String::String(const char* value) : mValue(value ? value : "")
{}

String::String(string_view value) : mValue(value)
{}

String::String(const std::string& value) : mValue(value)
{}

String& String::operator=(const std::string& other)
{
  mValue = other;
  return *this;
}

String& String::operator=(string_view other)
{
  mValue = other;
  return *this;
}

String& String::operator=(const char* other)
{
  mValue = other ? other : "";
  return *this;
}

String::operator string_view() const
{
  return mValue;
}

String::operator std::string() const
{
  return mValue;
}

BuiltInTypeId String::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::String};
}

size_t String::size() const
{
  return mValue.size();
}

size_t hash_value(const ua::String& s)
{
  const boost::hash<string_view> hasher;
  return hasher(s);
}

}  // namespace ua
