// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_log_format.h"

#include "fmt/chrono.h"
#include "fmt/format.h"

#include <chrono>
#include <ctime>
#include <iterator>
#include <utility>

namespace ua::detail
{

namespace
{

// A string that reaches a log line may be peer-supplied (an endpoint URL, an ERR reason, an
// application name, a certificate subject). A control character in it would end the line and
// forge a further entry; a quote would end the value. Both are escaped in place, in the one pass
// the formatter already makes over the string, so a line is exactly one entry and a quoted value
// is exactly one value. The three UTF-8 line separators that some viewers honour (U+0085, U+2028,
// U+2029) are escaped as well; other non-ASCII bytes pass through so UTF-8 text stays readable.
bool needs_escaping(unsigned char c)
{
  return c < 0x20 || c == 0x7f || c == '"' || c == '\\';
}

// The escaped spelling of a UTF-8 line separator starting at @p i, with its byte length, or 0.
std::pair<size_t, const char*> unicode_line_separator_at(std::string_view value, size_t i)
{
  const auto at = [&](size_t k)
  {
    return k < value.size() ? static_cast<unsigned char>(value[k]) : 0u;
  };
  if (at(i) == 0xC2 && at(i + 1) == 0x85)
    return {2, "\\u0085"};
  if (at(i) == 0xE2 && at(i + 1) == 0x80 && at(i + 2) == 0xA8)
    return {3, "\\u2028"};
  if (at(i) == 0xE2 && at(i + 1) == 0x80 && at(i + 2) == 0xA9)
    return {3, "\\u2029"};
  return {0, nullptr};
}

void append_escaped(std::string& out, std::string_view value)
{
  for (size_t i = 0; i < value.size(); ++i)
  {
    const auto c = static_cast<unsigned char>(value[i]);
    if (c >= 0x80)
    {
      if (const auto [length, spelling] = unicode_line_separator_at(value, i); length > 0)
      {
        out += spelling;
        i += length - 1;
      }
      else
      {
        out.push_back(static_cast<char>(c));
      }
      continue;
    }
    switch (c)
    {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (needs_escaping(c))
      {
        fmt::format_to(std::back_inserter(out), "\\x{:02x}", c);
      }
      else
      {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
}

// A field value is quoted when it contains a space (it would bleed into the next field) or anything
// that had to be escaped (so the quoting rule is visible in the line).
bool needs_quoting(std::string_view value)
{
  for (size_t i = 0; i < value.size(); ++i)
  {
    const auto c = static_cast<unsigned char>(value[i]);
    if (c == ' ' || needs_escaping(c) || unicode_line_separator_at(value, i).first > 0)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

std::string format_log_line(const LogEntry& entry)
{
  auto now = std::chrono::system_clock::now();

  // Format the timestamp from broken-down integer fields rather than a chrono format spec. The chrono
  // "%S" (and "%H:%M:%S") formatter unconditionally instantiates fmt's write_floating_seconds path,
  // whose internal FMT_STRING("{:.{}f}") (basic_format_string<char, double, int&>) is evaluated at
  // compile time regardless of the value's precision. clang-20's stricter consteval rejects it (fmt
  // 10.2.1), so even a whole-second time_point trips it; clang-19 happens to tolerate it. Extracting
  // Y/M/D/H/M/S via fmt::gmtime (a thread-safe std::tm wrapper, UTC, matching fmt's sys_time default)
  // and formatting only integers keeps the floating-seconds formatter out of the translation unit, so
  // this compiles identically on every supported compiler.
  auto seconds = std::chrono::floor<std::chrono::seconds>(now);
  auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
  std::tm utc = fmt::gmtime(std::chrono::system_clock::to_time_t(seconds));

  auto line = fmt::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03d} [{:>8}] [{}]",
    utc.tm_year + 1900,
    utc.tm_mon + 1,
    utc.tm_mday,
    utc.tm_hour,
    utc.tm_min,
    utc.tm_sec,
    millis,
    to_string(entry.level),
    entry.category);

  for (const auto& field : entry.fields)
  {
    line += fmt::format(" {}=", field.key);
    std::visit(
      [&line](const auto& v)
      {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::string_view>)
        {
          if (needs_quoting(v))
          {
            line += '"';
            append_escaped(line, v);
            line += '"';
          }
          else
          {
            line += v;
          }
        }
        else
        {
          line += fmt::format("{}", v);
        }
      },
      field.value);
  }

  line += ' ';
  append_escaped(line, entry.message);
  line += '\n';

  return line;
}

}  // namespace ua::detail
