// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_ACCESS_UTILS_H
#define UA_DATA_ACCESS_UTILS_H

#include <span>
#include "ua_access_level_ex_type.h"
#include "ua_enum_value_type.h"
#include "ua_localized_text.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_result.h"
#include "ua_variant.h"

namespace ua
{

/// What a write of an AnalogItem value outside its range does (OPC 10000-8 5.3.2.2).
///
/// @ingroup core_types
enum class DataAccessOutOfRangePolicy
{
  Reject,  ///< The write is refused with Bad_OutOfRange.
  Clamp,  ///< The value is clamped into the range; @ref data_access_utils::apply_analog_range answers
          ///< Good_Clamped.
};

/// The Data Access write checks of OPC 10000-8, as functions a Write path or a value source applies to
/// the value it is about to store.
///
/// Each function is pure and synchronous, never throws, and reports a refusal as a bad
/// @ref VoidResult carrying an @ref ErrorDetail. A value whose elements are not numeric is not checked:
/// its type is decided by the Write service's DataType checks.
namespace data_access_utils
{

/// Checks an AnalogItem or ArrayItem write against its range (OPC 10000-8 5.3.2.2, 5.3.4.1).
///
/// Every element of @p value is checked; a scalar is one element. A limit that is NaN leaves that side
/// unbounded (OPC 10000-8 5.6.2: "If a limit is not known a NaN shall be used"); a range with no known limit,
/// or whose high limit is below its low limit, checks nothing. Each element is compared in its own type, so
/// an Int64 or UInt64 is never rounded through a Double: an integer element is inside the range when it is
/// at or above the low limit's ceiling and at or below the high limit's floor. A NaN element is outside a
/// range that has a known limit. The specification says neither how an integer is compared with a
/// fractional limit nor whether a NaN is inside a range; these are the SDK's rules.
///
/// Under Clamp an element outside the range is replaced by the value of its type nearest to it inside the
/// range, and every other element is kept exactly as written. Clamp refuses, as Reject does, an element it
/// has no value for: a NaN, or an element whose type has no value inside the range (a Byte against the
/// range 300 to 400, an Int32 against 0.4 to 0.6). Clamp never stores an infinity it was not given: a finite
/// Float against a range whose low limit is above the largest Float, or whose high limit is below the lowest
/// Float, is refused, while an infinity written inside such a range is kept.
///
/// @param value  The value to be written; replaced by the clamped value when @p policy is Clamp and an
///               element was clamped. Each element keeps its type, and an array keeps its dimensions.
/// @param range  The InstrumentRange, or the EURange where no InstrumentRange is present.
/// @param policy What an element outside the range does.
/// @return Good when every element is inside the range; Good_Clamped when @p policy is Clamp and an
///         element was clamped; Bad_OutOfRange when @p policy is Reject and an element is outside the
///         range, or when an element cannot be clamped, with the element, the limits and the element index
///         in the ErrorDetail "AnalogOutOfRange", @p value unchanged.
VoidResult apply_analog_range(Variant& value, const Range& range, DataAccessOutOfRangePolicy policy);

/// Checks a MultiStateDiscrete write (OPC 10000-8 5.3.3.3): every element is an index into @p enumStrings.
///
/// A Float or Double element is an index when it is integral; a NaN, fractional or infinite one indexes no
/// entry.
///
/// @param value       The value to be written.
/// @param enumStrings The Variable's EnumStrings Property.
/// @return Good when every element indexes an entry; otherwise Bad_OutOfRange with the index, the
///         number of entries and the element index in the ErrorDetail "MultiStateIndexOutOfRange".
VoidResult check_enum_strings_index(const Variant& value, std::span<const LocalizedText> enumStrings);

/// Checks a MultiStateValueDiscrete write (OPC 10000-8 5.3.3.4): every element equals the Value of an
/// entry of @p enumValues.
///
/// An EnumValue's Value is an Int64, so a UInt64 element above the Int64 range matches none: the
/// specification allows UInt64 for this type (OPC 10000-8 5.3.3.4) but does not say how such a value would
/// be represented. The type's DataType is Number, so a Float or Double may be written: an integral one is
/// matched by its value, and a NaN, fractional or infinite one, or one outside the Int64 range, matches none.
///
/// @param value      The value to be written.
/// @param enumValues The Variable's EnumValues Property.
/// @return Good when every element is a defined Value; otherwise Bad_OutOfRange with the value and the
///         element index in the ErrorDetail "MultiStateValueInvalid".
VoidResult check_enum_values_member(const Variant& value, std::span<const EnumValueType> enumValues);

/// True if a change of this Property's Value changes the meaning of its owner's Value, so that a
/// MonitoredItem on the owner's Value gets the SemanticsChanged bit (OPC 10000-4 7.39.1, Table 180): the
/// Property has the SemanticChange bit of AccessLevelEx (OPC 10000-3 5.6.2, 8.58), or its BrowseName is one
/// for which OPC 10000-8 requires the bit (EURange, EngineeringUnits, InstrumentRange, Title, AxisDefinition,
/// XAxisDefinition, YAxisDefinition, ZAxisDefinition, FalseState, TrueState, EnumStrings and EnumValues, in
/// namespace 0).
///
/// The owner's type is not checked: Table 180 permits a Server to set the bit on further conditions, so a
/// Property with one of these names sets it on any Variable.
///
/// @param browseName    The Property's BrowseName.
/// @param accessLevelEx The Property's AccessLevelEx.
/// @return True when changes to this Property carry the owner's semantic-change meaning.
bool is_semantic_property(const QualifiedName& browseName, const AccessLevelExType& accessLevelEx) noexcept;

}  // namespace data_access_utils

}  // namespace ua

#endif  // UA_DATA_ACCESS_UTILS_H
