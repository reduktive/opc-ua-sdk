// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_XML_ESCAPE_H
#define UA_XML_ESCAPE_H

#include <string>
#include "ua_includes.h"
#include "ua_stream.h"

namespace ua::xml_detail
{

// Writes the raw bytes of `s` to `stream` verbatim, with no escaping. Used to emit literal markup
// (tags, already-escaped text) byte-for-byte.
inline void write_raw(ua::Stream& stream, string_view s)
{
  if (s.empty())
  {
    return;
  }
  for (const char c : s)
  {
    const byte b = static_cast<byte>(c);
    stream.write_all({&b, 1});
  }
}

// The length of the well-formed UTF-8 sequence starting at @p i (1..4), or 0 when the bytes there
// are not one: a bad lead or continuation byte, an overlong form, a surrogate, or a code point
// above U+10FFFF. Also 0 for the two non-characters U+FFFE and U+FFFF, which XML 1.0 forbids.
inline std::size_t utf8_sequence_length(string_view in, std::size_t i)
{
  const auto at = [&](std::size_t k)
  {
    return static_cast<unsigned char>(in[k]);
  };
  const auto cont = [&](std::size_t k)
  {
    return k < in.size() && (at(k) & 0xC0u) == 0x80u;
  };
  const unsigned lead = at(i);
  if (lead < 0x80u)
    return 1;
  if (lead >= 0xC2u && lead <= 0xDFu)
    return cont(i + 1) ? 2 : 0;
  if (lead >= 0xE0u && lead <= 0xEFu)
  {
    if (!cont(i + 1) || !cont(i + 2))
      return 0;
    const unsigned second = at(i + 1);
    if (lead == 0xE0u && second < 0xA0u)
      return 0;  // overlong
    if (lead == 0xEDu && second >= 0xA0u)
      return 0;  // surrogate
    if (lead == 0xEFu && second == 0xBFu && (at(i + 2) == 0xBEu || at(i + 2) == 0xBFu))
      return 0;  // U+FFFE / U+FFFF
    return 3;
  }
  if (lead >= 0xF0u && lead <= 0xF4u)
  {
    if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3))
      return 0;
    const unsigned second = at(i + 1);
    if (lead == 0xF0u && second < 0x90u)
      return 0;  // overlong
    if (lead == 0xF4u && second >= 0x90u)
      return 0;  // above U+10FFFF
    return 4;
  }
  return 0;
}

// Escapes @p in for element text, or for a double-quoted attribute value when @p attribute is set,
// so the result is well-formed XML 1.0: the five predefined entities are escaped; a control
// character XML forbids (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F) and any byte sequence that is not
// well-formed UTF-8 become U+FFFD, since neither can be written even as a character reference; a
// carriage return becomes a character reference everywhere, since a parser folds a literal one into
// a line feed; in an attribute the tab and line feed become character references too, so a
// conforming parser does not normalise them to spaces (security review XML-5). One pass.
inline std::string xml_escape(string_view in, bool attribute = false)
{
  static constexpr string_view replacement{"\xEF\xBF\xBD"};  // U+FFFD
  std::string out;
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size();)
  {
    const auto ch = static_cast<unsigned char>(in[i]);
    if (ch >= 0x80u)
    {
      const auto length = utf8_sequence_length(in, i);
      if (length == 0)
      {
        out += replacement;
        ++i;
      }
      else
      {
        out.append(in.data() + i, length);
        i += length;
      }
      continue;
    }
    ++i;
    switch (ch)
    {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    case '\'':
      out += "&apos;";
      break;
    case '\t':
      out += attribute ? "&#x9;" : "\t";
      break;
    case '\n':
      out += attribute ? "&#xA;" : "\n";
      break;
    case '\r':
      out += "&#xD;";
      break;
    default:
      if (ch < 0x20u)
        out += replacement;
      else
        out.push_back(static_cast<char>(ch));
      break;
    }
  }
  return out;
}

}  // namespace ua::xml_detail

#endif  //! UA_XML_ESCAPE_H
