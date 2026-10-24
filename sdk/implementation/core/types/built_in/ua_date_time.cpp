// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <exception>
#include "ua_to_result.h"
#include "ua_date_time.h"

#include "ua_error_detail.h"
#include "fmt/format.h"

namespace ua
{

DateTime DateTime::now()
{
  auto tp = std::chrono::time_point_cast<datetime::OneHundredNanoSeconds>(std::chrono::system_clock::now());
  return DateTime{tp};
}

bool DateTime::is_null() const
{
  return (mValue <= min());
}

DateTime::DateTime(std::chrono::sys_time<datetime::OneHundredNanoSeconds> timePoint) : mValue(timePoint)
{}

DateTime::DateTime(int year, int month, int day, int hours, int minutes, double seconds, int offset)
  : DateTime{std::chrono::year{year},
      std::chrono::month{numeric_cast<unsigned int>(month)},
      std::chrono::day{numeric_cast<unsigned int>(day)},
      std::chrono::hours{hours},
      std::chrono::minutes{minutes},
      seconds,
      std::chrono::minutes{offset}}
{}

DateTime::DateTime(std::chrono::year year, std::chrono::month month, std::chrono::day day,
  std::chrono::hours hours, std::chrono::minutes minutes, double seconds,
  std::chrono::minutes offset /*= std::chrono::minutes{0}*/)
{
  const datetime::PicoSeconds picoSeconds{numeric_cast<int64_t>(seconds * 1e12)};
  const datetime::OneHundredNanoSeconds secs{round<datetime::OneHundredNanoSeconds>(picoSeconds)};

  const std::chrono::year_month_day ymd{year, month, day};
  if (!ymd.ok())
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidDateTimeFormat", "Calendar date (year/month/day) is not a valid date.", "DateTime")
        .context(ua::ContextKeys::value,
          fmt::format(
            "{}-{}-{}", static_cast<int>(year), static_cast<unsigned>(month), static_cast<unsigned>(day))));
  }

  if (abs(offset) > std::chrono::hours{14})
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "DateTimeParseError", "Timezone offset exceeds the maximum permitted of +/-840 minutes.", "DateTime")
        .context(ua::ContextKeys::actual, std::to_string(offset.count()))
        .context(ua::ContextKeys::max, std::to_string(840)));
  }

  mValue = std::chrono::sys_days{ymd} + hours + minutes + secs + offset;
}

DateTime::DateTime() : mValue(min())
{}

BuiltInTypeId DateTime::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::DateTime};
}

std::chrono::sys_time<datetime::OneHundredNanoSeconds>& DateTime::value()
{
  return mValue;
}

const std::chrono::sys_time<datetime::OneHundredNanoSeconds>& DateTime::value() const
{
  return mValue;
}

std::string DateTime::as_iso_string() const
{
  auto sysTime = mValue;
  if (is_null())
  {
    sysTime = min();
  }

  auto dp = std::chrono::floor<std::chrono::days>(sysTime);
  const std::chrono::year_month_day ymd{dp};
  auto timeOfDay = sysTime - dp;
  auto totalSeconds = std::chrono::duration_cast<std::chrono::seconds>(timeOfDay);
  const std::chrono::hh_mm_ss hms{totalSeconds};
  auto sub100ns =
    std::chrono::duration_cast<datetime::OneHundredNanoSeconds>(timeOfDay - totalSeconds).count();

  std::string s = fmt::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
    static_cast<int>(ymd.year()),
    static_cast<unsigned>(ymd.month()),
    static_cast<unsigned>(ymd.day()),
    hms.hours().count(),
    hms.minutes().count(),
    hms.seconds().count());

  if (sub100ns > 0)
  {
    s += fmt::format(".{:07d}", numeric_cast<int>(sub100ns));
  }
  s += "Z";
  return s;
}

DateTimeResult DateTime::try_parse(string_view text) noexcept
{
  try
  {
    return parse(text);
  }
  catch (...)
  {
    return DateTimeResult{exception_to_status_code(std::current_exception())};
  }
}

DateTime DateTime::parse(string_view iso)
{
  // Expected format: YYYY-MM-DDTHH:MM:SS[.fffffff]Z
  // Minimum: "YYYY-MM-DDTHH:MM:SSZ" (20 chars)
  if (iso.size() < 20 || iso.back() != 'Z')
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DateTimeParseError",
        "Invalid ISO 8601 DateTime string: too short or missing trailing 'Z'.",
        "DateTime")
        .context(ua::ContextKeys::value, std::string{iso}));
  }

  auto parseInt = [&](size_t pos, size_t len) -> int
  {
    int result = 0;
    for (size_t i = pos; i < pos + len; ++i)
    {
      if (iso[i] < '0' || iso[i] > '9')
      {
        throw UaException(Status::BadDecodingError,
          ErrorDetail::build("DateTimeParseError",
            "Non-digit character encountered while parsing a numeric field of the ISO 8601 "
            "DateTime string.",
            "DateTime")
            .context(ua::ContextKeys::index, std::to_string(i))
            .context(ua::ContextKeys::value, std::string{iso}));
      }
      result = result * 10 + (iso[i] - '0');
    }
    return result;
  };

  // Validate separator characters: YYYY-MM-DDTHH:MM:SS
  if (iso[4] != '-' || iso[7] != '-' || iso[10] != 'T' || iso[13] != ':' || iso[16] != ':')
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "DateTimeParseError", "Invalid separator characters in ISO 8601 DateTime string.", "DateTime")
        .context(ua::ContextKeys::value, std::string{iso}));
  }

  const int year = parseInt(0, 4);
  const int month = parseInt(5, 2);
  const int day = parseInt(8, 2);
  const int hours = parseInt(11, 2);
  const int minutes = parseInt(14, 2);
  const int wholeSeconds = parseInt(17, 2);

  double seconds = static_cast<double>(wholeSeconds);

  // Parse optional fractional seconds: ".fffffff"
  if (iso.size() > 20 && iso[19] == '.')
  {
    const size_t fracStart = 20;
    const size_t fracEnd = iso.size() - 1;  // Before 'Z'
    if (fracEnd > fracStart)
    {
      double frac = 0.0;
      double divisor = 10.0;
      for (size_t i = fracStart; i < fracEnd; ++i)
      {
        if (iso[i] < '0' || iso[i] > '9')
        {
          throw UaException(Status::BadDecodingError,
            ErrorDetail::build("DateTimeParseError",
              "Non-digit character encountered while parsing the fractional-seconds field of the "
              "ISO 8601 DateTime string.",
              "DateTime")
              .context(ua::ContextKeys::index, std::to_string(i))
              .context(ua::ContextKeys::value, std::string{iso}));
        }
        frac += (iso[i] - '0') / divisor;
        divisor *= 10.0;
      }
      seconds += frac;
    }
  }

  return DateTime{year, month, day, hours, minutes, seconds};
}

}  // namespace ua
