// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA StatusCode built-in type and its bare 32-bit value alias.
/// @ingroup core_types

#ifndef UA_STATUS_CODE_H
#define UA_STATUS_CODE_H

#include "ua_includes.h"
#include "ua_status.h"
#include "ua_utilities.h"

#include <cstdint>
#include <memory>

namespace ua
{

/// Bare wire-format StatusCode value: the raw 32-bit numeric status with no
/// attached detail.
///
/// Use this where only the numeric status matters and the `ErrorDetail`
/// payload of a full `StatusCode` would be dead weight: atomics, codecs, and
/// comparison-only state.
using StatusCodeValue = std::uint32_t;

struct ErrorDetail;

/// An OPC UA StatusCode: a 32-bit status value optionally paired with structured
/// `ErrorDetail` context.
///
/// The 32-bit value follows OPC 10000-6 5.1.2: the top two bits encode severity
/// (Good / Uncertain / Bad), the upper 16 bits the status code proper, and the
/// lower bits a set of info bits (StructureChanged, SemanticsChanged, and the
/// DataValue InfoBits such as Overflow). The optional `ErrorDetail` is an
/// out-of-band diagnostic payload that travels with the code in-process; it is
/// not part of the wire encoding and does not participate in identity.
///
/// @note The attached detail is held by `shared_ptr<const ErrorDetail>` and is
///       shared, not copied, between StatusCode instances.
/// @ingroup core_types
class StatusCode
{
public:
  /// Constructs a Good (zero-valued) StatusCode with no detail.
  constexpr StatusCode() noexcept = default;

  /// Constructs a StatusCode from a raw 32-bit wire value, with no detail.
  ///
  /// @param value The full 32-bit status value, including any info bits.
  explicit StatusCode(StatusCodeValue value) noexcept : mValue(value)
  {}

  /// Constructs a StatusCode from a named @ref Status enumerator, with no detail.
  ///
  /// Implicit so that named status constants convert directly to StatusCode.
  ///
  /// @param value The named status; its underlying value becomes the code.
  StatusCode(Status value) noexcept : mValue(utils::to_underlying(value))
  {}

  /// Constructs a StatusCode pairing a named status with structured detail.
  ///
  /// @param value  The named status.
  /// @param detail Diagnostic context to attach; may be null, in which case this
  ///               is equivalent to `StatusCode{value}`. Ownership is shared.
  StatusCode(Status value, std::shared_ptr<const ErrorDetail> detail) noexcept;

  /// Constructs a StatusCode pairing a raw 32-bit value with structured detail.
  ///
  /// @param value  The full 32-bit status value, including any info bits.
  /// @param detail Diagnostic context to attach; may be null, in which case this
  ///               is equivalent to `StatusCode{value}`. Ownership is shared.
  StatusCode(StatusCodeValue value, std::shared_ptr<const ErrorDetail> detail) noexcept;

  // Special members are out-of-line because they touch shared_ptr<ErrorDetail>,
  // which is forward-declared in this header.

  /// Destroys the StatusCode, releasing its share of any attached detail.
  ~StatusCode();

  /// Copy-constructs, sharing the source's detail (no deep copy of detail).
  ///
  /// @param other The StatusCode to copy.
  StatusCode(const StatusCode& other) noexcept;

  /// Move-constructs, transferring the source's detail and leaving it detached.
  ///
  /// @param other The StatusCode to move from; left detached.
  StatusCode(StatusCode&& other) noexcept;

  /// Copy-assigns, sharing the source's detail (no deep copy of detail).
  ///
  /// @param other The StatusCode to copy.
  /// @return Reference to this StatusCode.
  StatusCode& operator=(const StatusCode& other) noexcept;

  /// Move-assigns, transferring the source's detail and leaving it detached.
  ///
  /// @param other The StatusCode to move from; left detached.
  /// @return Reference to this StatusCode.
  StatusCode& operator=(StatusCode&& other) noexcept;

  /// Assigns a named @ref Status, replacing the code and clearing any detail.
  ///
  /// @param other The named status to assign.
  /// @return Reference to this StatusCode.
  StatusCode& operator=(Status other) noexcept;

  /// Compares two StatusCodes for equality of their full 32-bit value.
  ///
  /// Detail is informational, not identity: two StatusCodes with the same value
  /// but different (or differently-present) detail compare equal. Info bits are
  /// part of the value and therefore part of the comparison.
  ///
  /// @param obj The StatusCode to compare against.
  /// @return True if both 32-bit values are identical.
  /// @see equivalent
  bool operator==(const StatusCode& obj) const noexcept
  {
    return mValue == obj.mValue;
  }

  /// Tests whether two StatusCodes share the same underlying @ref Status.
  ///
  /// Unlike `operator==`, this masks off the info bits and compares only the
  /// status code proper, so codes that differ only in info bits are equivalent.
  ///
  /// @param obj The StatusCode to compare against.
  /// @return True if both reduce to the same @ref Status.
  /// @see operator==
  bool equivalent(const StatusCode& obj) const
  {
    return (as_status() == obj.as_status());
  }

  /// Returns the named @ref Status, with the info bits masked off.
  ///
  /// @return The status code proper (upper 16 bits) as a @ref Status enumerator.
  Status as_status() const
  {
    return utils::from_underlying<Status>(mask_status_bits(mValue));
  }

  /// Returns the full 32-bit value, including all info bits.
  ///
  /// @return The raw wire-format status value.
  /// @see value
  uint32_t as_uint32() const
  {
    return mValue;
  }

  /// Returns the full 32-bit value as a typed @ref StatusCodeValue.
  ///
  /// Identical to as_uint32() but with the domain alias as its return type.
  ///
  /// @return The raw wire-format status value.
  /// @see as_uint32
  StatusCodeValue value() const noexcept
  {
    return mValue;
  }

  /// Returns the attached `ErrorDetail` by shared ownership, if any.
  ///
  /// @return The shared detail pointer; null on Good and on detail-less Bad. The
  ///         returned reference is valid for the lifetime of this StatusCode.
  /// @see detail
  const std::shared_ptr<const ErrorDetail>& shared_detail() const noexcept
  {
    return mDetail;
  }

  /// Returns a non-owning pointer to the attached `ErrorDetail`, if any.
  ///
  /// @return Pointer to the detail, or null if none is attached. The pointee is
  ///         owned by this StatusCode (and any that share the detail); do not
  ///         retain it beyond their lifetime.
  /// @see shared_detail
  const ErrorDetail* detail() const noexcept;

  /// Returns a copy of this StatusCode with the `ErrorDetail` stripped.
  ///
  /// Used to mask diagnostic detail before it crosses a trust boundary (e.g.
  /// pre-authentication responses).
  ///
  /// @return A StatusCode with the same 32-bit value and no detail.
  StatusCode without_detail() const noexcept
  {
    return StatusCode{mValue};
  }

  /// Reports whether the severity is Good (neither Bad nor Uncertain).
  ///
  /// @return True if the code carries Good severity.
  bool is_good() const noexcept
  {
    return is_not_bad() && is_not_uncertain();
  }

  /// Reports whether the severity is Bad (top severity bit set).
  ///
  /// @return True if the code carries Bad severity.
  bool is_bad() const noexcept
  {
    return (mValue & (1U << sSeverityBit31)) != 0;
  }

  /// Reports whether the severity is Uncertain (and not Bad).
  ///
  /// @return True if the code carries Uncertain severity.
  bool is_uncertain() const noexcept
  {
    return (mValue & (1U << sSeverityBit30)) != 0 && is_not_bad();
  }

  /// Reports whether the severity is anything other than Good.
  ///
  /// @return True if the code is Bad or Uncertain.
  bool is_not_good() const noexcept
  {
    return !is_good();
  }

  /// Reports whether the severity is anything other than Bad.
  ///
  /// @return True if the code is Good or Uncertain.
  bool is_not_bad() const noexcept
  {
    return !is_bad();
  }

  /// Reports whether the severity is anything other than Uncertain.
  ///
  /// @return True if the code is Good or Bad.
  bool is_not_uncertain() const noexcept
  {
    return !is_uncertain();
  }

  /// Reports whether the StructureChanged info bit is set.
  ///
  /// @return True if the structure of the associated value has changed.
  bool structure_changed() const
  {
    return test_bit(sStructureChangedBit);
  }

  /// Sets or clears the StructureChanged info bit.
  ///
  /// @param value True to set the bit, false to clear it.
  void structure_changed(bool value)
  {
    set_bit(sStructureChangedBit, value);
  }

  /// Reports whether the SemanticsChanged info bit is set.
  ///
  /// @return True if the semantics of the associated value have changed.
  bool semantics_changed() const
  {
    return test_bit(sSemanticsChangedBit);
  }

  /// Sets or clears the SemanticsChanged info bit.
  ///
  /// @param value True to set the bit, false to clear it.
  void semantics_changed(bool value)
  {
    set_bit(sSemanticsChangedBit, value);
  }

  // InfoType is the 2-bit field at bits 10-11 (OPC 10000-6 5.1.2 Table 3). Value 01 = DataValue
  // (bit 10 set, bit 11 clear); the DataValue InfoBits (Overflow, Limit, Historian) are only valid
  // when InfoType = DataValue.

  /// Reports whether the InfoType field selects DataValue.
  ///
  /// The InfoType is the 2-bit field at bits 10-11 (OPC 10000-6 5.1.2 Table 3);
  /// value `01` (bit 10 set, bit 11 clear) means DataValue. The DataValue
  /// InfoBits (such as Overflow) are only meaningful when this holds.
  ///
  /// @return True if InfoType == DataValue.
  bool info_type_data_value() const
  {
    return test_bit(sInfoTypeBit10) && !test_bit(sInfoTypeBit11);
  }

  /// Sets or clears the DataValue InfoType selection.
  ///
  /// @param value True to select InfoType == DataValue (which also clears the
  ///              high InfoType bit); false clears the low InfoType bit only.
  void info_type_data_value(bool value)
  {
    set_bit(sInfoTypeBit10, value);
    if (value)
      set_bit(sInfoTypeBit11, false);
  }

  /// Reports whether the Overflow info bit is set.
  ///
  /// @return True if the Overflow DataValue InfoBit is set.
  bool overflow() const
  {
    return test_bit(sOverflowBit);
  }

  /// Sets or clears the Overflow DataValue InfoBit.
  ///
  /// Setting Overflow implies InfoType == DataValue, so this also selects that
  /// InfoType; the resulting wire value carries both (e.g. `0x00000480`), never
  /// Overflow alone.
  ///
  /// @param value True to set the Overflow bit, false to clear it.
  void overflow(bool value)
  {
    set_bit(sOverflowBit, value);
    // The Overflow InfoBit is only meaningful with InfoType = DataValue; setting it implies that
    // InfoType, so the on-wire StatusCode carries both (e.g. 0x00000480), not Overflow alone.
    if (value)
      info_type_data_value(true);
  }

  /// Reports whether the ExtraData historian info bit is set.
  ///
  /// @return True if the ExtraData DataValue InfoBit is set.
  bool extra_data() const
  {
    return test_bit(sExtraDataBit);
  }

  /// Sets or clears the ExtraData historian info bit.
  ///
  /// A history Server sets this bit on a returned value when it holds additional data for that entry
  /// (e.g. a modification record reachable via ReadModified), per OPC 10000-11 3.1 / 6.4.3.2. Like
  /// Overflow it is only meaningful with InfoType == DataValue, so setting it also selects that InfoType.
  ///
  /// @param value True to set the ExtraData bit, false to clear it.
  void extra_data(bool value)
  {
    set_bit(sExtraDataBit, value);
    if (value)
      info_type_data_value(true);
  }

  /// Returns the OPC UA built-in type identifier for StatusCode.
  ///
  /// @return The @ref BuiltInTypeId tag for this built-in type.
  static BuiltInTypeId built_in_type_id();

private:
  // DataValue InfoBits, valid only when InfoType == DataValue (Part 4 7.34 / Part 8). The historian
  // bits live in the low nibble: bits 1:0 = Raw/Calculated/Interpolated, bit 2 = Partial, bit 3 =
  // ExtraData, bit 4 = MultiValue.
  static const uint32_t sExtraDataBit{3};
  static const uint32_t sOverflowBit{7};

  static const uint32_t sSemanticsChangedBit{14};
  static const uint32_t sStructureChangedBit{15};

  static const uint32_t sInfoTypeBit10{10};
  static const uint32_t sInfoTypeBit11{11};

  static const uint32_t sSeverityBit30{30};
  static const uint32_t sSeverityBit31{31};

  StatusCodeValue mValue{0};
  std::shared_ptr<const ErrorDetail> mDetail;

  static uint32_t mask_status_bits(uint32_t value)
  {
    const uint32_t mask = 0xFFFF0000U;
    return value & mask;
  }

  bool test_bit(uint32_t bit) const;

  void set_bit(uint32_t bit, bool value);
};

/// Returns the type name `"StatusCode"` for the StatusCode built-in type.
///
/// @return The fixed type-name string view `"StatusCode"`.
template<>
inline string_view get_typename<StatusCode>()
{
  return "StatusCode";
}

namespace detail
{

/// The severity of @p status as a rank that orders it: 0 for Good, 1 for Uncertain, 2 for Bad.
///
/// @param status The status code.
/// @return The rank of its severity.
inline int severity_rank(const StatusCode& status) noexcept
{
  if (status.is_bad())
  {
    return 2;
  }
  return status.is_uncertain() ? 1 : 0;
}

/// Whether @p status has a SubCode (bits 16 to 27, OPC 10000-4 7.39.1), such as Good_Clamped or
/// Uncertain_LastUsableValue, rather than its severity alone.
///
/// @param status The status code.
/// @return True when the SubCode is not zero.
inline bool has_subcode(const StatusCode& status) noexcept
{
  constexpr StatusCodeValue subCodeMask = 0x0FFF0000U;
  return (status.value() & subCodeMask) != 0U;
}

/// Whether `combined_status` answers @p outer rather than @p inner.
///
/// @param outer The code of the result that holds the item, or of the earlier step.
/// @param inner The item's own status, or the code of the later step.
/// @return True when @p outer is answered.
inline bool outer_status_answered(const StatusCode& outer, const StatusCode& inner) noexcept
{
  const int outerRank = severity_rank(outer);
  const int innerRank = severity_rank(inner);
  if (outerRank != innerRank)
  {
    return outerRank > innerRank;
  }
  return has_subcode(outer) && !has_subcode(inner);
}

/// The one code answered when an answer carries two and has room for one: @p outer, the code of the
/// result that holds the item (or of an earlier step), and @p inner, the item's own status (a DataValue's
/// status, a CallMethodResult's statusCode, or the code of a later step).
///
/// The worse severity is answered (Good, then Uncertain, then Bad). At the same severity a code with a
/// SubCode is answered before one without, so neither a Good subcode nor an Uncertain code is lost to a
/// plain code; when both have one, @p inner is answered. The code is answered with its own ErrorDetail.
///
/// @param outer The code of the result that holds the item, or of the earlier step.
/// @param inner The item's own status, or the code of the later step.
/// @return The code answered.
inline StatusCode combined_status(const StatusCode& outer, const StatusCode& inner)
{
  return outer_status_answered(outer, inner) ? outer : inner;
}

}  // namespace detail

}  // namespace ua

/// Hash specialization for @ref ua::StatusCode, keyed on its 32-bit value.
///
/// Consistent with @ref ua::StatusCode::operator==: only the value is hashed, so
/// codes that compare equal hash equal regardless of their attached detail.
template<>
struct std::hash<ua::StatusCode>
{
  /// Hashes the StatusCode by its 32-bit value.
  ///
  /// @param obj The StatusCode to hash.
  /// @return The hash of its @ref ua::StatusCode::value.
  size_t operator()(const ua::StatusCode& obj) const noexcept
  {
    return std::hash<ua::StatusCodeValue>{}(obj.value());
  }
};

#endif  // !UA_STATUS_CODE_H
