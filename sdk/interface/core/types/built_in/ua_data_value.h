// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA `DataValue` built-in type: a value paired with quality and timestamps.
/// @ingroup core_types

#ifndef UA_DATA_VALUE_H
#define UA_DATA_VALUE_H

#include "ua_date_time.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_built_in_type_id.h"
#include "ua_resource_budgets.h"
#include <cstddef>
#include <optional>

namespace ua
{

class Variant;

/// A value together with its quality status and source/server timestamps.
///
/// Models the OPC UA `DataValue` built-in type: the @ref Variant payload plus the
/// optional metadata that accompanies it on the wire - a quality @ref StatusCode and
/// the source- and server-side timestamps (each with optional picosecond precision).
/// Every metadata field is optional and absent by default; only the value is always
/// present (a default-constructed instance holds a null @ref Variant). This is a plain
/// value type with no thread-affinity: copies are independent and any thread may use a
/// given instance, but concurrent access to the same instance is not synchronized.
///
/// @ingroup core_types
class DataValue
{
public:
  /// Maximum representable picosecond offset for either picosecond field, in picoseconds.
  ///
  /// Picosecond fields refine the corresponding timestamp by `0`..`maxPicoSeconds`
  /// picoseconds; values above this bound are out of range.
  inline static const uint16_t maxPicoSeconds{9999};

  /// Constructs a null data value: a null @ref Variant with no status or timestamps.
  DataValue();
  ~DataValue();
  /// Deep-copies @p other, independently cloning its @ref Variant payload and metadata.
  /// @param other The data value to copy from.
  DataValue(const DataValue& other);
  /// Move-constructs from @p other, transferring its payload; @p other is left holding a null value.
  /// @param other The data value to move from; left holding a null value.
  DataValue(DataValue&& other) noexcept;
  /// Deep-copies @p other, independently cloning its @ref Variant payload and metadata.
  /// @param other The data value to copy from.
  /// @return `*this`.
  DataValue& operator=(const DataValue& other);
  /// Move-assigns from @p other, transferring its payload; @p other is left holding a null value.
  /// @param other The data value to move from; left holding a null value.
  /// @return `*this`.
  DataValue& operator=(DataValue&& other) noexcept;

  /// Constructs a data value carrying only the given value, with no status or timestamps.
  ///
  /// @param value The payload; moved into the new instance.
  explicit DataValue(Variant value);

  /// Constructs a data value carrying the given value and quality status.
  ///
  /// @param value  The payload; moved into the new instance.
  /// @param status The quality @ref StatusCode for the value.
  DataValue(Variant value, StatusCode status);

  /// Constructs a data value carrying the given value and source timestamp.
  ///
  /// @param value           The payload; moved into the new instance.
  /// @param sourceTimestamp The instant at which the source produced the value.
  DataValue(Variant value, DateTime sourceTimestamp);

  /// Constructs a data value carrying the given value, quality status, and source timestamp.
  ///
  /// @param value           The payload; moved into the new instance.
  /// @param status          The quality @ref StatusCode for the value.
  /// @param sourceTimestamp The instant at which the source produced the value.
  DataValue(Variant value, StatusCode status, DateTime sourceTimestamp);

  /// Constructs a data value carrying only a quality status, with a null @ref Variant.
  ///
  /// @param status The quality @ref StatusCode, typically a bad code reporting why no
  ///               value is present.
  explicit DataValue(StatusCode status);

  /// Compares two data values for equality across the value and all metadata fields.
  /// @param obj The data value to compare against.
  /// @return `true` if the value and every metadata field are equal; `false` otherwise.
  bool operator==(const DataValue& obj) const;

  /// Returns the contained value.
  /// @return The contained @ref Variant payload.
  const Variant& value() const;

  /// Returns a mutable reference to the contained value.
  /// @return Mutable reference to the contained @ref Variant payload.
  Variant& value();

  /// Returns the quality status, or an empty optional if none is set.
  /// @return The quality @ref StatusCode, or an empty optional if none is set.
  const optional<StatusCode>& status() const;

  /// Returns a mutable reference to the optional quality status.
  /// @return Mutable reference to the optional quality @ref StatusCode.
  optional<StatusCode>& status();

  /// Returns the source timestamp, or an empty optional if none is set.
  /// @return The source timestamp, or an empty optional if none is set.
  const optional<DateTime>& source_timestamp() const;

  /// Returns a mutable reference to the optional source timestamp.
  /// @return Mutable reference to the optional source timestamp.
  optional<DateTime>& source_timestamp();

  /// Returns the source picosecond refinement, or an empty optional if none is set.
  ///
  /// @return The source-timestamp refinement in picoseconds (`0`..@ref maxPicoSeconds),
  ///         or `nullopt`.
  const optional<uint16_t>& source_pico_seconds() const;

  /// Returns a mutable reference to the optional source picosecond refinement.
  ///
  /// @return Mutable reference to the optional source-timestamp picosecond refinement.
  /// @warning The caller is responsible for keeping the value within
  ///          `0`..@ref maxPicoSeconds; values above the bound are out of range.
  optional<uint16_t>& source_pico_seconds();

  /// Returns the server timestamp, or an empty optional if none is set.
  /// @return The server timestamp, or an empty optional if none is set.
  const optional<DateTime>& server_timestamp() const;

  /// Returns a mutable reference to the optional server timestamp.
  /// @return Mutable reference to the optional server timestamp.
  optional<DateTime>& server_timestamp();

  /// Returns the server picosecond refinement, or an empty optional if none is set.
  ///
  /// @return The server-timestamp refinement in picoseconds (`0`..@ref maxPicoSeconds),
  ///         or `nullopt`.
  const optional<uint16_t>& server_pico_seconds() const;

  /// Returns a mutable reference to the optional server picosecond refinement.
  ///
  /// @return Mutable reference to the optional server-timestamp picosecond refinement.
  /// @warning The caller is responsible for keeping the value within
  ///          `0`..@ref maxPicoSeconds; values above the bound are out of range.
  optional<uint16_t>& server_pico_seconds();

  /// Returns whether the contained value is null.
  ///
  /// @return `true` if the @ref Variant payload is null; the status and timestamp
  ///         metadata do not affect this result.
  bool is_null() const;

  /// Resets to the null, metadata-free state of a default-constructed instance.
  ///
  /// @post @ref value is null and every status/timestamp field is empty.
  void clear();

  /// Returns the built-in type identifier of this type (@ref BuiltInTypeId::DataValue).
  /// @return @ref BuiltInTypeId::DataValue.
  static BuiltInTypeId built_in_type_id();

private:
  // The contained Variant is stored INLINE in an opaque, suitably-aligned buffer, so a scalar
  // DataValue allocates nothing (the common case). Variant is incomplete in this header; every
  // lifecycle operation (construct / copy / move / destroy / access) is defined out-of-line in
  // ua_data_value.cpp where Variant is complete. The buffer size/alignment are fixed literals,
  // verified against the real Variant by static_asserts in ua_data_value.cpp.
  //
  // Trade-off vs. the old unique_ptr<Variant>: a reference obtained from value() does NOT survive a
  // move of the owning DataValue (the Variant is relocated into the destination's buffer), whereas a
  // boxed Variant kept a stable address. Callers must not hold a value() reference across a move of
  // its DataValue.
  //
  // Size note: sizeof(Variant) is 104 with libstdc++/libc++, but LARGER under the MSVC Debug STL,
  // where every std::string/std::vector carries an extra _Container_proxy pointer
  // (_ITERATOR_DEBUG_LEVEL=2). The largest Variant alternative (an ExpandedNodeId: a NodeId plus a
  // namespace-URI string - two strings) grows ~16 bytes there, taking sizeof(Variant) to ~120. The
  // buffer is sized to cover that worst case with headroom; the static_asserts in ua_data_value.cpp
  // are the real guard. Keep this >= sizeof(Variant) on every target - do not trim it to the
  // libstdc++ size.
  static constexpr std::size_t sVariantBufferSize = 128;
  static constexpr std::size_t sVariantBufferAlign = 16;
  alignas(sVariantBufferAlign) std::byte mValueBuffer[sVariantBufferSize]{};
  optional<StatusCode> mStatus;
  optional<DateTime> mSourceTimestamp;
  optional<DateTime> mServerTimestamp;
  optional<uint16_t> mSourcePicoSeconds;
  optional<uint16_t> mServerPicoSeconds;

  // Typed view over the inline buffer (the contained Variant). Defined in ua_data_value.cpp.
  Variant* value_ptr() noexcept;
  const Variant* value_ptr() const noexcept;
};

/// Returns the OPC UA type name `"DataValue"` for `DataValue`.
/// @return The literal `"DataValue"`.
template<>
inline string_view get_typename<DataValue>()
{
  return "DataValue";
}

namespace detail
{

/// The DataValue a throwing `*_sync` read returns: the held DataValue of a Good @p result, its status
/// set to the code `combined_status` gives for the result's code and its own, so a Good subcode on
/// the result reaches the caller. Throws a @ref UaException for a result that is not Good, as
/// `good_value` does.
///
/// @param result The result of the read's `try_` form.
/// @return The DataValue.
/// @throws UaException carrying the status and its detail when the status is not Good.
inline DataValue good_data_value(Result<DataValue>&& result)
{
  const StatusCode outer = result.status_code();
  DataValue value = good_value(std::move(result));
  if (outer_status_answered(outer, value.status().value_or(StatusCode{Status::Good})))
  {
    value.status() = outer;
  }
  return value;
}

}  // namespace detail

}  // namespace ua

#endif  // !UA_DATA_VALUE_H
