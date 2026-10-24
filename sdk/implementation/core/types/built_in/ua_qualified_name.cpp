// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/container_hash/hash.hpp>
#include "ua_qualified_name.h"

#include <charconv>
#include <exception>
#include <string>

#include "ua_to_result.h"

namespace ua
{

uint16_t QualifiedName::namespace_index() const
{
  return mNamespaceIndex;
}

uint16_t& QualifiedName::namespace_index()
{
  return mNamespaceIndex;
}

const String& QualifiedName::name() const
{
  return mName;
}

String& QualifiedName::name()
{
  return mName;
}

bool QualifiedName::is_null() const
{
  return ((mNamespaceIndex == 0) && mName.empty());
}

void QualifiedName::clear()
{
  mNamespaceIndex = 0;
  mName.clear();
}

std::strong_ordering QualifiedName::operator<=>(const QualifiedName& other) const
{
  if (auto cmp = mNamespaceIndex <=> other.mNamespaceIndex; cmp != 0)
  {
    return cmp;
  }
  return mName <=> other.mName;
}

size_t QualifiedName::hash() const
{
  size_t seed{0};
  boost::hash_combine(seed, mNamespaceIndex);
  boost::hash_combine(seed, hash_value(mName));
  return seed;
}

BuiltInTypeId QualifiedName::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::QualifiedName};
}

QualifiedName::QualifiedName(string_view name) : mNamespaceIndex(0), mName(name)
{}

QualifiedName::QualifiedName(uint16_t namespaceIndex, string_view name)
  : mNamespaceIndex(namespaceIndex), mName(name)
{}

namespace
{
/// The characters OPC 10000-4 Annex A reserves in a BrowseName: `<reserved-char>`.
bool is_reserved_name_char(char c)
{
  return c == '/' || c == '.' || c == '<' || c == '>' || c == ':' || c == '#' || c == '!' || c == '&';
}

UaException qualified_name_parse_error(const char* summary, string_view text)
{
  return UaException(Status::BadDecodingError,
    ErrorDetail::build("QualifiedNameParseFailed", summary, "QualifiedName")
      .context(ua::ContextKeys::value, std::string{text}));
}
}  // namespace

QualifiedName QualifiedName::parse(string_view text)
{
  // `[<namespace-index> ':'] <name>`: leading digits followed by ':' are the index; anything else is a
  // namespace-0 name (`12` is a name, and `2&:Foo` is the escaped name `2:Foo`).
  uint16_t namespaceIndex = 0;
  string_view rest = text;
  size_t digits = 0;
  while (digits < text.size() && text[digits] >= '0' && text[digits] <= '9')
  {
    ++digits;
  }
  if (digits > 0 && digits < text.size() && text[digits] == ':')
  {
    const auto parsed = std::from_chars(text.data(), text.data() + digits, namespaceIndex);
    if (parsed.ec != std::errc{})
    {
      throw qualified_name_parse_error("The namespace index is above 65535", text);
    }
    rest = text.substr(digits + 1);
  }

  std::string decodedName;
  decodedName.reserve(rest.size());
  for (size_t i = 0; i < rest.size(); ++i)
  {
    const char c = rest[i];
    if (c == '&')
    {
      if (i + 1 == rest.size() || !is_reserved_name_char(rest[i + 1]))
      {
        throw qualified_name_parse_error("'&' escapes only a reserved character (/ . < > : # ! &)", text);
      }
      decodedName.push_back(rest[i + 1]);
      ++i;
    }
    else if (is_reserved_name_char(c))
    {
      throw qualified_name_parse_error("A reserved character in the name is not escaped with '&'", text);
    }
    else
    {
      decodedName.push_back(c);
    }
  }
  return QualifiedName{namespaceIndex, decodedName};
}

QualifiedNameResult QualifiedName::try_parse(string_view text) noexcept
{
  try
  {
    return parse(text);
  }
  catch (...)
  {
    return QualifiedNameResult{exception_to_status_code(std::current_exception())};
  }
}

}  // namespace ua
