// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_string_lexical_validation.h"

#include "ua_string.h"

#include <array>
#include <cstdint>
#include <string_view>

namespace ua::server::string_lexical_validation
{

namespace
{

// NS0 numeric identifiers of the lexically-constrained String subtypes. Named here rather than taken
// from a generated enum because the generated `DataTypeId` table does not carry them.
constexpr uint32_t normalizedString = 12877u;
constexpr uint32_t decimalString = 12878u;
constexpr uint32_t durationString = 12879u;
constexpr uint32_t timeString = 12880u;
constexpr uint32_t dateString = 12881u;
constexpr uint32_t semanticVersionString = 24263u;
constexpr uint32_t trimmedString = 31918u;

bool is_digit(char c) noexcept
{
  return c >= '0' && c <= '9';
}

bool all_digits(std::string_view s) noexcept
{
  if (s.empty())
    return false;
  for (char c : s)
    if (!is_digit(c))
      return false;
  return true;
}

/// Consume exactly @p count digits from the front of @p s, yielding their value.
bool take_digits(std::string_view& s, size_t count, int& out) noexcept
{
  if (s.size() < count)
    return false;
  const std::string_view head = s.substr(0, count);
  if (!all_digits(head))
    return false;
  out = 0;
  for (char c : head)
    out = out * 10 + (c - '0');
  s.remove_prefix(count);
  return true;
}

bool take_char(std::string_view& s, char c) noexcept
{
  if (s.empty() || s.front() != c)
    return false;
  s.remove_prefix(1);
  return true;
}

bool is_leap_year(int year) noexcept
{
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

int days_in_month(int year, int month) noexcept
{
  constexpr std::array<int, 12> lengths{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12)
    return 0;
  if (month == 2 && is_leap_year(year))
    return 29;
  return lengths[static_cast<size_t>(month - 1)];
}

/// ISO 8601-1:2019 calendar date, extended format: `YYYY-MM-DD`.
///
/// The day is checked against the month and the year, not merely against 31: `2026-02-30` is exactly
/// the value a range-only check admits and a calendar cannot hold.
bool is_iso_calendar_date(std::string_view s) noexcept
{
  int year = 0;
  int month = 0;
  int day = 0;
  if (!take_digits(s, 4, year) || !take_char(s, '-') || !take_digits(s, 2, month) || !take_char(s, '-') ||
      !take_digits(s, 2, day))
    return false;
  if (!s.empty())
    return false;
  return month >= 1 && month <= 12 && day >= 1 && day <= days_in_month(year, month);
}

/// The `Z` or `+/-hh:mm` zone offset ISO 8601 allows on a time of day. An absent zone is permitted.
bool consume_zone_offset(std::string_view& s) noexcept
{
  if (s.empty())
    return true;
  if (s.front() == 'Z')
  {
    s.remove_prefix(1);
    return s.empty();
  }
  if (s.front() != '+' && s.front() != '-')
    return false;
  s.remove_prefix(1);
  int hours = 0;
  int minutes = 0;
  if (!take_digits(s, 2, hours) || !take_char(s, ':') || !take_digits(s, 2, minutes))
    return false;
  return s.empty() && hours <= 14 && minutes <= 59;
}

/// ISO 8601-1:2019 time of day, extended format: `hh:mm:ss`, an optional fractional second, and an
/// optional zone. 24:00:00 is the one hour value above 23 the standard admits, as end-of-day.
bool is_iso_time_of_day(std::string_view s) noexcept
{
  int hours = 0;
  int minutes = 0;
  int seconds = 0;
  if (!take_digits(s, 2, hours) || !take_char(s, ':') || !take_digits(s, 2, minutes) || !take_char(s, ':') ||
      !take_digits(s, 2, seconds))
    return false;
  if (!s.empty() && s.front() == '.')
  {
    s.remove_prefix(1);
    size_t fraction = 0;
    while (fraction < s.size() && is_digit(s[fraction]))
      ++fraction;
    if (fraction == 0)
      return false;
    s.remove_prefix(fraction);
  }
  if (!consume_zone_offset(s))
    return false;
  if (hours == 24)
    return minutes == 0 && seconds == 0;
  return hours <= 23 && minutes <= 59 && seconds <= 60;  // 60 is the leap second
}

/// ISO 8601-1:2019 duration: `PnYnMnDTnHnMnS`, with a `W` week form as the alternative. At least one
/// component is required, a `T` must be followed by at least one time component, and only the final
/// component may carry a fraction.
bool is_iso_duration(std::string_view s) noexcept
{
  if (!take_char(s, 'P') || s.empty())
    return false;

  const auto consumeNumber = [](std::string_view& in, bool& sawFraction) noexcept
  {
    size_t digits = 0;
    while (digits < in.size() && is_digit(in[digits]))
      ++digits;
    if (digits == 0)
      return false;
    in.remove_prefix(digits);
    if (!in.empty() && (in.front() == '.' || in.front() == ','))
    {
      in.remove_prefix(1);
      size_t fraction = 0;
      while (fraction < in.size() && is_digit(in[fraction]))
        ++fraction;
      if (fraction == 0)
        return false;
      in.remove_prefix(fraction);
      sawFraction = true;
    }
    return true;
  };

  // The week form does not combine with any other component.
  {
    std::string_view weeks = s;
    bool fraction = false;
    if (consumeNumber(weeks, fraction) && !weeks.empty() && weeks.front() == 'W' && weeks.size() == 1)
      return true;
  }

  constexpr std::string_view datePart{"YMD"};
  constexpr std::string_view timePart{"HMS"};
  size_t dateNext = 0;
  size_t timeNext = 0;
  bool inTime = false;
  bool sawComponent = false;
  bool sawTimeComponent = false;
  bool sawFraction = false;

  while (!s.empty())
  {
    if (s.front() == 'T')
    {
      if (inTime)
        return false;
      inTime = true;
      s.remove_prefix(1);
      continue;
    }
    if (sawFraction)
      return false;  // a fraction may only appear on the last component
    if (!consumeNumber(s, sawFraction) || s.empty())
      return false;
    const std::string_view designators = inTime ? timePart : datePart;
    size_t& next = inTime ? timeNext : dateNext;
    const size_t at = designators.find(s.front(), next);
    if (at == std::string_view::npos)
      return false;  // unknown designator, or one out of order / repeated
    next = at + 1;
    s.remove_prefix(1);
    sawComponent = true;
    if (inTime)
      sawTimeComponent = true;
  }
  return sawComponent && (!inTime || sawTimeComponent);
}

/// W3C XSD 1.1 Part 2 decimal: an optional sign, then digits with at most one period. No grouping
/// separators, no comma as the decimal separator, no exponent -- those belong to `double`, not to
/// `decimal`, and each of them parses differently in a different locale.
bool is_xsd_decimal(std::string_view s) noexcept
{
  if (!s.empty() && (s.front() == '+' || s.front() == '-'))
    s.remove_prefix(1);
  if (s.empty())
    return false;
  size_t periods = 0;
  size_t digits = 0;
  for (char c : s)
  {
    if (c == '.')
    {
      if (++periods > 1)
        return false;
      continue;
    }
    if (!is_digit(c))
      return false;
    ++digits;
  }
  return digits > 0;
}

/// Whether @p s is in Unicode Normalization Form C.
///
/// Checked, deliberately, by the one rule that needs no normalisation table: a combining mark that
/// follows a character it could have been composed with is a decomposed sequence, and NFC has none.
/// A full NFC check needs the composition data, and the SDK carries none -- so this recognises the
/// decomposed sequences it can prove and admits the rest rather than guessing. It refuses what the
/// obligation is about (a caller sending base + combining mark where a precomposed character exists)
/// without inventing a verdict on strings it cannot decide.
bool has_no_combining_mark(std::string_view s) noexcept
{
  for (size_t i = 0; i < s.size();)
  {
    const auto byte = static_cast<unsigned char>(s[i]);
    size_t length = 1;
    uint32_t code = byte;
    if (byte >= 0xF0)
    {
      length = 4;
      code = byte & 0x07u;
    }
    else if (byte >= 0xE0)
    {
      length = 3;
      code = byte & 0x0Fu;
    }
    else if (byte >= 0xC0)
    {
      length = 2;
      code = byte & 0x1Fu;
    }
    if (i + length > s.size())
      return true;  // truncated UTF-8 is not this check's business
    for (size_t k = 1; k < length; ++k)
      code = (code << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3Fu);
    i += length;

    // The combining ranges: Combining Diacritical Marks and their supplement/extended blocks, plus
    // the Cyrillic and Hebrew-facing block. A character from any of them following a base character
    // is a decomposed sequence.
    const bool combining = (code >= 0x0300 && code <= 0x036F) || (code >= 0x1AB0 && code <= 0x1AFF) ||
                           (code >= 0x1DC0 && code <= 0x1DFF) || (code >= 0x20D0 && code <= 0x20FF) ||
                           (code >= 0xFE20 && code <= 0xFE2F);
    if (combining)
      return false;
  }
  return true;
}

/// SemVer 2.0.0 as OPC 10000-5 section 12.41 Table 289's BNF gives it: three dot-separated numeric
/// identifiers with no leading zeroes, then an optional `-prerelease` and an optional `+build`.
///
/// Ordering is the whole point of the type -- a Client compares two versions to decide which is newer
/// -- and a value outside the grammar has no position in that order. `1.2`, `v1.2.3`, `01.2.3` and
/// `1.2.3.4` each sit somewhere undefined relative to a conforming release.
bool is_semantic_version(std::string_view s) noexcept
{
  const auto numericIdentifier = [](std::string_view part) noexcept
  {
    if (part.empty() || !all_digits(part))
      return false;
    return part.size() == 1 || part.front() != '0';  // no leading zeroes
  };
  const auto dotSeparatedIdentifiers = [](std::string_view text, bool numericOnly) noexcept
  {
    if (text.empty())
      return false;
    size_t start = 0;
    while (start <= text.size())
    {
      const size_t dot = text.find('.', start);
      const std::string_view part =
        text.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
      if (part.empty())
        return false;
      for (char c : part)
      {
        const bool allowed =
          is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || !numericOnly;
        if (!allowed)
          return false;
      }
      if (dot == std::string_view::npos)
        break;
      start = dot + 1;
    }
    return true;
  };

  // Split off build metadata, then pre-release; what remains is the version core.
  std::string_view core = s;
  if (const size_t plus = core.find('+'); plus != std::string_view::npos)
  {
    const std::string_view build = core.substr(plus + 1);
    if (!dotSeparatedIdentifiers(build, false))
      return false;
    core = core.substr(0, plus);
  }
  if (const size_t dash = core.find('-'); dash != std::string_view::npos)
  {
    const std::string_view pre = core.substr(dash + 1);
    if (!dotSeparatedIdentifiers(pre, false))
      return false;
    core = core.substr(0, dash);
  }

  size_t start = 0;
  for (int component = 0; component < 3; ++component)
  {
    const size_t dot = core.find('.', start);
    const bool last = component == 2;
    if (last != (dot == std::string_view::npos))
      return false;  // exactly two dots, so exactly three components
    const std::string_view part = core.substr(start, last ? std::string_view::npos : dot - start);
    if (!numericIdentifier(part))
      return false;
    if (!last)
      start = dot + 1;
  }
  return true;
}

/// A TrimmedString carrying leading or trailing whitespace.
///
/// OPC 10000-5 section 12.43 lets a Server either refuse with `Bad_TypeMismatch` or trim before processing,
/// and requires it to pick one and apply it consistently. Refusing is the choice made here: trimming
/// silently changes a value the Client sent, and a Client that cannot see the change cannot tell its
/// write was altered. Storing it untrimmed is the one outcome the clause excludes, because the type
/// exists so string comparison works.
bool has_padding(std::string_view s) noexcept
{
  const auto isSpace = [](char c) noexcept
  {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
  };
  return !s.empty() && (isSpace(s.front()) || isSpace(s.back()));
}

}  // namespace

bool constrains(const NodeId& dataType) noexcept
{
  if (dataType.namespace_index() != 0 || !dataType.is_numeric())
    return false;
  switch (dataType.identifier().get_numeric())
  {
  case normalizedString:
  case decimalString:
  case durationString:
  case timeString:
  case dateString:
  case semanticVersionString:
  case trimmedString:
    return true;
  default:
    return false;
  }
}

StatusCode validate(const NodeId& dataType, const Variant& value)
{
  if (!constrains(dataType))
    return StatusCode{Status::Good};
  const String* text = value.try_as<String>();
  if (text == nullptr)
    return StatusCode{Status::Good};  // not a String at all: the built-in type check answers this

  const std::string_view s = static_cast<std::string_view>(*text);
  bool conforms = true;
  switch (dataType.identifier().get_numeric())
  {
  case normalizedString:
    conforms = has_no_combining_mark(s);
    break;
  case decimalString:
    conforms = is_xsd_decimal(s);
    break;
  case durationString:
    conforms = is_iso_duration(s);
    break;
  case timeString:
    conforms = is_iso_time_of_day(s);
    break;
  case dateString:
    conforms = is_iso_calendar_date(s);
    break;
  case semanticVersionString:
    conforms = is_semantic_version(s);
    break;
  case trimmedString:
    conforms = !has_padding(s);
    break;
  default:
    break;
  }
  return conforms ? StatusCode{Status::Good} : StatusCode{Status::BadTypeMismatch};
}

}  // namespace ua::server::string_lexical_validation
