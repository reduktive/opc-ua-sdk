// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA @c DateTime built-in type: a UTC instant at 100-nanosecond resolution.
/// @ingroup core_types

#ifndef UA_DATE_TIME_H
#define UA_DATE_TIME_H

#include <chrono>
#include "ua_includes.h"
#include "ua_built_in_type_id.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_result.h"

namespace ua
{

/// Chrono duration aliases for the resolutions used by @ref ua::DateTime.
namespace datetime
{
/// A signed count of picoseconds.
using PicoSeconds = std::chrono::duration<int64_t, std::pico>;

/// A signed count of 100-nanosecond ticks - the OPC UA @c DateTime wire resolution.
///
/// One tick is 100 ns; on the wire a @c DateTime is an @c int64_t count of these ticks
/// measured from the OPC UA epoch 1601-01-01T00:00:00Z.
using OneHundredNanoSeconds = std::chrono::duration<int64_t, std::ratio_multiply<std::hecto, std::nano>>;
}  // namespace datetime

/// An OPC UA @c DateTime: a UTC instant stored at 100-nanosecond resolution.
///
/// Wraps a @c std::chrono::sys_time measured in @ref datetime::OneHundredNanoSeconds (UTC,
/// no time-zone offset is retained). Values are totally ordered by their underlying instant
/// via the defaulted three-way comparison. The representable range runs from @ref min
/// (1601-01-01T00:00:00Z, the OPC UA epoch) to @ref max (9999-12-31T23:59:59Z).
/// @ingroup core_types
class DateTime
{
public:
  /// Constructs the null @c DateTime (@ref min, the OPC UA epoch), for which @ref is_null is true.
  DateTime();

  /// Constructs from an absolute UTC instant at 100-nanosecond resolution.
  ///
  /// @param timePoint UTC instant; any sub-100 ns precision is already excluded by the tick type.
  explicit DateTime(std::chrono::sys_time<datetime::OneHundredNanoSeconds> timePoint);

  /// Constructs from broken-down calendar fields in a fixed UTC offset.
  ///
  /// @param year    Calendar year.
  /// @param month   Calendar month (1-12).
  /// @param day     Day of month (1-31).
  /// @param hours   Hour of day (0-23) in the supplied offset.
  /// @param minutes Minute of hour (0-59) in the supplied offset.
  /// @param seconds Seconds within the minute; the fractional part carries sub-second precision.
  /// @param offset  Offset of the supplied fields from UTC; subtracted to normalise to UTC.
  DateTime(std::chrono::year year, std::chrono::month month, std::chrono::day day, std::chrono::hours hours,
    std::chrono::minutes minutes, double seconds, std::chrono::minutes offset = std::chrono::minutes{0});

  /// Constructs from broken-down calendar fields given as plain integers in a fixed UTC offset.
  ///
  /// @param year    Calendar year.
  /// @param month   Calendar month (1-12).
  /// @param day     Day of month (1-31).
  /// @param hours   Hour of day (0-23) in the supplied offset.
  /// @param minutes Minute of hour (0-59) in the supplied offset.
  /// @param seconds Seconds within the minute; the fractional part carries sub-second precision.
  /// @param offset  Offset in minutes from UTC; subtracted to normalise to UTC.
  DateTime(int year, int month, int day, int hours, int minutes, double seconds, int offset = 0);

  /// Copies the wrapped instant. @c DateTime is a trivially copyable value.
  /// @param dateTime The value to copy from.
  DateTime(const DateTime& dateTime) = default;
  /// Copies the wrapped instant (the value type is trivially copyable; nothing is stolen).
  /// @param dateTime The value to move from (copied, as the type is trivially copyable).
  DateTime(DateTime&& dateTime) noexcept = default;
  /// Copy-assigns the wrapped instant.
  /// @param dateTime The value to copy from.
  /// @return `*this`.
  DateTime& operator=(const DateTime& dateTime) = default;
  /// Copy-assigns the wrapped instant (the value type is trivially copyable; nothing is stolen).
  /// @param dateTime The value to move from (copied, as the type is trivially copyable).
  /// @return `*this`.
  DateTime& operator=(DateTime&& dateTime) noexcept = default;
  /// Destroys the @c DateTime value.
  ~DateTime() = default;

  /// Orders two values by their underlying UTC instant.
  /// @param obj The value to compare against.
  /// @return The ordering of the two underlying UTC instants.
  auto operator<=>(const DateTime& obj) const = default;

  /// Returns a mutable reference to the underlying UTC instant.
  ///
  /// @return Reference to the wrapped @c sys_time; valid for the lifetime of this @c DateTime.
  std::chrono::sys_time<datetime::OneHundredNanoSeconds>& value();

  /// Returns the underlying UTC instant.
  ///
  /// @return Reference to the wrapped @c sys_time; valid for the lifetime of this @c DateTime.
  const std::chrono::sys_time<datetime::OneHundredNanoSeconds>& value() const;

  /// Reports whether this value is the OPC UA null sentinel (@ref min, the epoch instant).
  /// @return `true` if this value equals @ref min (the OPC UA null sentinel); `false` otherwise.
  bool is_null() const;

  /// Formats the instant as an ISO 8601 UTC string @c YYYY-MM-DDTHH:MM:SS[.fffffff]Z.
  /// @return The instant as an ISO 8601 UTC string.
  std::string as_iso_string() const;

  /// Parses the text @ref as_iso_string and @ref ua::to_string write: ISO 8601 UTC,
  /// @c YYYY-MM-DDTHH:MM:SS[.fffffff]Z, the trailing @c Z required. `parse(to_string(t)) == t` for
  /// every DateTime.
  ///
  /// @param text The ISO 8601 UTC text.
  /// @return The instant @p text names.
  /// @throws UaException with @ref Status::BadDecodingError if @p text is not that form or names an
  ///         instant outside the representable range.
  /// @see try_parse
  static DateTime parse(string_view text);

  /// Parses like @ref parse and reports a malformed text as a bad result instead of throwing.
  ///
  /// @param text The ISO 8601 UTC text.
  /// @return The DateTime, or Bad_DecodingError with an @ref ErrorDetail naming the fault.
  [[nodiscard]] static DateTimeResult try_parse(string_view text) noexcept;

  /// Returns the current UTC time, truncated to 100-nanosecond resolution.
  /// @return The current UTC time, truncated to 100-nanosecond resolution.
  static DateTime now();

  /// Returns the smallest representable instant: the OPC UA epoch 1601-01-01T00:00:00Z.
  /// @return The OPC UA epoch 1601-01-01T00:00:00Z.
  static consteval std::chrono::sys_time<datetime::OneHundredNanoSeconds> min();

  /// Returns the largest representable instant: 9999-12-31T23:59:59Z.
  /// @return The largest representable instant, 9999-12-31T23:59:59Z.
  static consteval std::chrono::sys_time<datetime::OneHundredNanoSeconds> max();

  /// Returns the OPC UA built-in type identifier for @c DateTime.
  /// @return @ref BuiltInTypeId::DateTime.
  static BuiltInTypeId built_in_type_id();

private:
  std::chrono::sys_time<datetime::OneHundredNanoSeconds> mValue;
};

inline consteval std::chrono::sys_time<datetime::OneHundredNanoSeconds> DateTime::min()
{
  using std::chrono::sys_days;
  using namespace std::chrono;
  using namespace std::chrono_literals;

  auto epoch = sys_days{1601y / 1 / 1};
  return sys_time<datetime::OneHundredNanoSeconds>{epoch.time_since_epoch()};
}

inline consteval std::chrono::sys_time<datetime::OneHundredNanoSeconds> DateTime::max()
{
  using std::chrono::sys_days;
  using namespace std::chrono;
  using namespace std::chrono_literals;

  auto maxDate = sys_days{9999y / 12 / 31};
  const sys_time<seconds> secs = sys_time<seconds>{maxDate} + 23h + 59min + 59s;
  return sys_time<datetime::OneHundredNanoSeconds>{secs.time_since_epoch()};
}

/// Returns the OPC UA type name @c "DateTime".
/// @return The literal `"DateTime"`.
template<>
inline string_view get_typename<DateTime>()
{
  return "DateTime";
}

}  // namespace ua

#endif  // !UA_DATE_TIME_H
