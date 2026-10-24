// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_data_access.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_connection_ops.h"
#include "ua_continuation_point.h"
#include "ua_browse_drain_guard.h"
#include "ua_client_answer_status.h"
#include "ua_data_access_state.h"
#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_range.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_semantic_change_cache.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-DIAG-002/-015).
constexpr std::string_view connClosedSource = "client.tier2.data_access.connection_closed";
constexpr std::string_view resolveSource = "client.tier2.data_access.property_resolution_failed";
constexpr std::string_view readSource = "client.tier2.data_access.read";
constexpr std::string_view writeSource = "client.tier2.data_access.write";
constexpr std::string_view deadbandSource = "client.tier2.data_access.percent_deadband";
constexpr std::string_view msdeResolveSource = "client.tier2.data_access.write_via_dictionary";

// The resolved DA Property Values, keyed by their (ns0) BrowseName. The immutable snapshot the typed handles
// share is a `shared_ptr<const Props>` swapped atomically on @ref detail::DataAccessHandleBase (H2 /
// section 8.18.2).
using Props = ua::client::detail::ResolvedProperties;

/// Posts @p result to @p executor for a callback (callbacks always run on the executor); inline when no
/// executor is set (a moved-from handle's inert path).
template<typename Result>
void deliver(
  const boost::asio::any_io_executor& executor, std::function<void(Result)> callback, Result result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// @return A single-node Read of @p nodeId's Value Attribute.
ua::ReadRequest make_value_read(const ua::NodeId& nodeId)
{
  ua::ReadValueId readValue;
  readValue.node_id() = nodeId;
  readValue.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  ua::ReadRequest request;
  request.nodes_to_read().push_back(std::move(readValue));
  return request;
}

/// Whether the server answered @p value with a value the typed decoders may use: not Bad, and not Uncertain
/// without a value.
bool decodable_answer(const ua::DataValue& value)
{
  const ua::StatusCode status = value.status().value_or(ua::StatusCode{ua::Status::Good});
  if (status.is_bad())
  {
    return false;
  }
  return !(status.is_uncertain() && value.value().empty());
}

/// @return A pointer to the resolved DataValue for @p name, or null when @p name was not resolved or the
///         server answered it with a Bad code or an Uncertain code without a value.
const ua::DataValue* find_property(const Props& props, std::string_view name)
{
  auto it = props.find(std::string{name});
  if (it == props.end() || !decodable_answer(it->second))
  {
    return nullptr;
  }
  return &it->second;
}

/// The code of the resolved Properties a typed value is decoded from: the status of every Property whose
/// value the decoders use, combined (@ref ua::detail::combined_status), so a Good subcode or an Uncertain
/// code the server answered a Property with reaches the caller on the typed value's Result.
ua::StatusCode resolved_properties_code(const Props& props)
{
  ua::StatusCode code{ua::Status::Good};
  for (const auto& entry : props)
  {
    if (decodable_answer(entry.second))
    {
      code =
        ua::detail::combined_status(code, entry.second.status().value_or(ua::StatusCode{ua::Status::Good}));
    }
  }
  return code;
}

/// The refusal for a Property the SDK decides on itself (a Mandatory Property, the PercentDeadband EURange
/// precondition, the EnumDictionaryEntries table) when the server answered it Uncertain: such a decision uses
/// only a Good answer. Good when none of @p names is Uncertain.
ua::StatusCode refuse_uncertain_properties(
  const Props& props, std::initializer_list<std::string_view> names, std::string_view source)
{
  for (const auto name : names)
  {
    auto it = props.find(std::string{name});
    if (it != props.end())
    {
      const auto& propertyStatus = it->second.status();
      if (propertyStatus.has_value() && propertyStatus.value().is_uncertain())
      {
        return ua::client::detail::uncertain_answer_refused(
          propertyStatus.value(), "ReadAnswerUncertain", source);
      }
    }
  }
  return ua::StatusCode{ua::Status::Good};
}

/// Coerces @p value to an unsigned integer across every built-in integer width (exact type; a non-negative
/// signed value is accepted). `nullopt` when the Variant does not hold an integer.
std::optional<std::uint64_t> to_unsigned(const ua::Variant& value)
{
  if (auto r = value.to<std::uint8_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint16_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint32_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint64_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::int8_t>(); r.is_good() && r.value() >= 0)
    return static_cast<std::uint64_t>(r.value());
  if (auto r = value.to<std::int16_t>(); r.is_good() && r.value() >= 0)
    return static_cast<std::uint64_t>(r.value());
  if (auto r = value.to<std::int32_t>(); r.is_good() && r.value() >= 0)
    return static_cast<std::uint64_t>(r.value());
  if (auto r = value.to<std::int64_t>(); r.is_good() && r.value() >= 0)
    return static_cast<std::uint64_t>(r.value());
  return std::nullopt;
}

/// Coerces @p value to a signed integer across every built-in integer width (exact type). `nullopt` when the
/// Variant does not hold an integer.
std::optional<std::int64_t> to_signed(const ua::Variant& value)
{
  if (auto r = value.to<std::int8_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::int16_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::int32_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::int64_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint8_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint16_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint32_t>(); r.is_good())
    return r.value();
  if (auto r = value.to<std::uint64_t>(); r.is_good())
    return static_cast<std::int64_t>(r.value());
  return std::nullopt;
}

/// Decodes a `ListOfEnumValueType` Variant to a vector of @ref ua::EnumValueType. `nullopt` when the Variant
/// is not an array of `EnumValueType` structures.
std::optional<std::vector<ua::EnumValueType>> decode_enum_values(const ua::Variant& value)
{
  if (!value.is_array_of_structure())
  {
    return std::nullopt;
  }
  try
  {
    const auto& array = value.as<ua::Array<ua::RefStructure<ua::Structure>>>();
    std::vector<ua::EnumValueType> result;
    for (const auto& element : array.payload())
    {
      const auto* entry = dynamic_cast<const ua::EnumValueType*>(element.get());
      if (!entry)
      {
        return std::nullopt;  // heterogeneous / not an EnumValueType array
      }
      result.push_back(*entry);
    }
    return result;
  }
  catch (...)
  {
    return std::nullopt;  // not an Array<RefStructure<Structure>>
  }
}

// ---- Pure typed extractors (immutable Property snapshot -> typed optional) ----
//
// Every typed read (decode), the deadband precondition, and the dictionary match extract their typed values
// from the immutable @ref Props snapshot with these helpers  -  they NEVER mutate the shared state (H2). The
// `apply_*` publishers below reuse the same extractors to decide whether the Mandatory Property(ies)
// resolved.

/// @return `Definition` decoded to an opaque string (CL-DA-017), or nullopt when absent/undecodable.
std::optional<std::string> extract_definition(const Props& props)
{
  if (const auto* dv = find_property(props, "Definition"))
  {
    if (auto text = dv->value().to<ua::String>(); text.is_good())
    {
      return static_cast<std::string>(text.value());
    }
  }
  return std::nullopt;
}

/// @return `ValuePrecision` surfaced as the informational `int16_t` digit-count (CL-DA-002  -  surfaced, not
/// applied), or nullopt when absent/undecodable. The wire value is a server-controlled Double; per Part 8
/// section 5.3.1 it "shall always be interpreted as a whole number by rounding it to the nearest whole
/// number", so a finite value is rounded to nearest (`std::rint`, round-half-to-even under the default
/// FE_TONEAREST mode  - the matrix's strengthened tie oracle: 1.5 -> 2, 2.5 -> 2). Narrowing a NaN / infinity
/// / out-of-int16 value is undefined behaviour ([conv.fpint]), so the raw value is guarded
/// finite-and-in-range first; for any p in [INT16_MIN, INT16_MAX], `rint(p)` is also in range, so the rounded
/// narrowing is well-defined.
std::optional<std::int16_t> extract_value_precision(const Props& props)
{
  if (const auto* dv = find_property(props, "ValuePrecision"))
  {
    if (auto precision = dv->value().to<double>(); precision.is_good())
    {
      const double p = precision.value();
      if (std::isfinite(p) && p >= static_cast<double>(std::numeric_limits<std::int16_t>::min()) &&
          p <= static_cast<double>(std::numeric_limits<std::int16_t>::max()))
      {
        return static_cast<std::int16_t>(std::rint(p));
      }
    }
  }
  return std::nullopt;
}

/// @return the named Property decoded to a @ref ua::Range (e.g. `EURange` / `InstrumentRange`), or nullopt.
std::optional<ua::Range> extract_range(const Props& props, std::string_view name)
{
  if (const auto* dv = find_property(props, name))
  {
    if (const auto* range = dv->value().try_as<ua::Range>())
    {
      return *range;
    }
  }
  return std::nullopt;
}

/// @return the named Property decoded to a @ref ua::EUInformation (e.g. `EngineeringUnits`), or nullopt.
std::optional<ua::EUInformation> extract_eu(const Props& props, std::string_view name)
{
  if (const auto* dv = find_property(props, name))
  {
    if (const auto* eu = dv->value().try_as<ua::EUInformation>())
    {
      return *eu;
    }
  }
  return std::nullopt;
}

/// @return the named Property decoded to a @ref ua::LocalizedText (e.g. `TrueState` / `FalseState`), or
/// nullopt.
std::optional<ua::LocalizedText> extract_localized(const Props& props, std::string_view name)
{
  if (const auto* dv = find_property(props, name))
  {
    if (auto text = dv->value().to<ua::LocalizedText>(); text.is_good())
    {
      return text.value();
    }
  }
  return std::nullopt;
}

/// @return the named Property decoded to a `LocalizedText` array (e.g. `EnumStrings`), or nullopt.
std::optional<std::vector<ua::LocalizedText>> extract_localized_vector(
  const Props& props, std::string_view name)
{
  if (const auto* dv = find_property(props, name))
  {
    if (auto strings = dv->value().to_vector<ua::LocalizedText>(); strings.is_good())
    {
      return std::move(strings).value();
    }
  }
  return std::nullopt;
}

/// @return the named Property decoded to a `ListOfEnumValueType` (e.g. `EnumValues`), or nullopt.
std::optional<std::vector<ua::EnumValueType>> extract_enum_values(const Props& props, std::string_view name)
{
  if (const auto* dv = find_property(props, name))
  {
    return decode_enum_values(dv->value());
  }
  return std::nullopt;
}

/// The decoded `EnumDictionaryEntries` table (CL-DA-012, OPC 10000-19 section 7.1): a 2-D `NodeId[][]`
/// flattened row-major. Dimension 0 is the state (enum-value) index; dimension 1 is the dictionary index. The
/// entry for state @c s in dictionary @c d is `flat[s * dictionaries + d]`.
struct DictionaryEntries2D
{
  std::vector<ua::NodeId> flat;  ///< the flattened row-major payload (size == states * dictionaries)
  std::size_t states = 0;  ///< dimension 0 (state / enum-value index; == |EnumValues|)
  std::size_t dictionaries = 0;  ///< dimension 1 (dictionary index: CDD, eCl\@ss, ...)
};

/// Decodes the `EnumDictionaryEntries` Property as a 2-D `NodeId[][]` (CL-DA-012). `nullopt` when the
/// Property is absent, is not a `NodeId` array (e.g. a scalar NodeId  -  the known generator gap), carries no
/// rank-2 ArrayDimensions, or has dimensions inconsistent with the flat payload. This never throws:
/// `get_array_base` is consulted only after `is_array_of_node_id` confirms an array is held (its throwing
/// precondition met).
std::optional<DictionaryEntries2D> extract_dictionary_entries(const Props& props)
{
  const ua::DataValue* dv = find_property(props, "EnumDictionaryEntries");
  if (dv == nullptr)
  {
    return std::nullopt;
  }
  const ua::Variant& value = dv->value();
  if (!value.is_array_of_node_id())
  {
    return std::nullopt;  // absent / scalar NodeId / wrong element type -> not the 2-D table
  }
  auto flat = value.to_vector<ua::NodeId>();
  if (!flat.is_good())
  {
    return std::nullopt;
  }
  const auto& dimensions = value.get_array_base().dimensions();
  if (!dimensions.has_value() || dimensions->size() != 2)
  {
    return std::nullopt;  // rank != 2 (a plain NodeId[] view, or no dimension metadata)
  }
  const std::int32_t rows = (*dimensions)[0];
  const std::int32_t columns = (*dimensions)[1];
  if (rows < 0 || columns < 0)
  {
    return std::nullopt;
  }
  DictionaryEntries2D table;
  table.flat = std::move(flat).value();
  table.states = static_cast<std::size_t>(rows);
  table.dictionaries = static_cast<std::size_t>(columns);
  // Overflow-safe consistency check (the flat payload size MUST equal states * dictionaries). Guard the
  // multiply BEFORE performing it: on a 32-bit build `size_t` is 32-bit, so a server-controlled
  // ArrayDimensions such as [65536, 65536] would wrap `states * dictionaries` to a small value that could
  // spuriously equal `flat.size()`, admitting a table whose real element count is far smaller than its
  // declared bounds and driving an out-of-bounds read in write_via_dictionary_async. The division form never
  // overflows: if `dictionaries` exceeds `flat.size() / states` the product cannot equal `flat.size()`, so
  // the multiply below is guaranteed <= flat.size() and cannot wrap.
  if (table.states != 0 && table.dictionaries > table.flat.size() / table.states)
  {
    return std::nullopt;  // declared dimensions exceed the flat payload (or would overflow)
  }
  if (table.flat.size() != table.states * table.dictionaries)
  {
    return std::nullopt;  // dimensions inconsistent with the flat payload
  }
  return table;
}

/// Publishes @p props as the state's new IMMUTABLE resolved-Property snapshot by an atomic swap (H2 /
/// section 8.18.2): builds a fresh `shared_ptr<const Props>` and `store`s it (release). It never mutates the
/// previous snapshot in place, so a concurrent reader (a copy of the handle mid-decode on another executor
/// thread) always observes one whole, self-consistent snapshot.
void publish_properties(ua::client::detail::DataAccessHandleBase& state, const Props& props)
{
  state.resolvedProperties.store(std::make_shared<const Props>(props), std::memory_order_release);
}

/// The outcome every `apply_*` gives: Good when the Mandatory Properties resolved (and @p props was
/// published), Bad_NotFound when one is absent or undecodable, or the refusal of
/// @ref refuse_uncertain_properties when the server answered one Uncertain.
using MandatoryOutcome = ua::StatusCode;

/// @return Good, the published outcome of an `apply_*` whose Mandatory Properties resolved.
MandatoryOutcome mandatory_resolved()
{
  return ua::StatusCode{ua::Status::Good};
}

/// @return Bad_NotFound, the outcome of an `apply_*` whose Mandatory Property is absent or undecodable.
MandatoryOutcome mandatory_missing()
{
  return ua::StatusCode{ua::Status::BadNotFound};
}

/// The status a handle construction, re-resolve or refresh fails with when @p outcome is not Good: the
/// refusal of an Uncertain Mandatory Property as it is, or Bad_NotFound
/// (`DataAccessMandatoryPropertyMissing`) with @p summary for an absent or undecodable one.
ua::StatusCode mandatory_failure(
  const MandatoryOutcome& outcome, std::string_view summary, std::shared_ptr<const ua::ErrorDetail> cause)
{
  if (outcome.as_status() != ua::Status::BadNotFound)
  {
    return outcome;
  }
  return ua::StatusCode{ua::Status::BadNotFound,
    ua::make_error_detail("DataAccessMandatoryPropertyMissing",
      std::string{summary},
      std::string{resolveSource},
      std::move(cause))};
}

/// Validates the Mandatory `EURange` (CL-DA-001) and, when present, publishes @p props as the new immutable
/// snapshot.
MandatoryOutcome apply_analog(ua::client::detail::AnalogItemState& state, const Props& props)
{
  if (auto refused = refuse_uncertain_properties(props, {"EURange"}, resolveSource); !refused.is_good())
  {
    return refused;
  }
  if (!extract_range(props, "EURange").has_value())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// BaseAnalogType (OPC 10000-8 section 5.3.2) has NO Mandatory Property  -  EURange, EngineeringUnits and
/// InstrumentRange are all Optional on the base type. So the handle always resolves; it simply publishes
/// whatever Optional Properties the node happened to expose (CL-DA-001). Contrast apply_analog, which makes
/// EURange Mandatory for the AnalogItemType subtype.
MandatoryOutcome apply_base_analog(ua::client::detail::AnalogItemState& state, const Props& props)
{
  publish_properties(state, props);
  return mandatory_resolved();
}

/// AnalogUnitType (OPC 10000-8 section 5.3.2.4, Table 4) derives from BaseAnalogType and mandates ONLY
/// EngineeringUnits (CL-DA-001). EURange is inherited from BaseAnalogType and remains Optional here  -  so,
/// unlike apply_analog / apply_analog_unit_range, EURange is NOT required.
MandatoryOutcome apply_analog_unit(ua::client::detail::AnalogItemState& state, const Props& props)
{
  if (auto refused = refuse_uncertain_properties(props, {"EngineeringUnits"}, resolveSource);
      !refused.is_good())
  {
    return refused;
  }
  if (!extract_eu(props, "EngineeringUnits").has_value())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// AnalogUnitRangeType (OPC 10000-8 section 5.3.2.5, Table 5) derives from AnalogItemType and additionally
/// mandates EngineeringUnits, so BOTH EURange (inherited-Mandatory from AnalogItemType) and EngineeringUnits
/// (own Mandatory) must resolve (CL-DA-001).
MandatoryOutcome apply_analog_unit_range(ua::client::detail::AnalogItemState& state, const Props& props)
{
  if (auto refused = refuse_uncertain_properties(props, {"EURange", "EngineeringUnits"}, resolveSource);
      !refused.is_good())
  {
    return refused;
  }
  if (!extract_range(props, "EURange").has_value() || !extract_eu(props, "EngineeringUnits").has_value())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// Validates the Mandatory `TrueState` + `FalseState` and, when both present, publishes @p props.
MandatoryOutcome apply_two_state(ua::client::detail::TwoStateDiscreteState& state, const Props& props)
{
  if (auto refused = refuse_uncertain_properties(props, {"TrueState", "FalseState"}, resolveSource);
      !refused.is_good())
  {
    return refused;
  }
  if (!extract_localized(props, "TrueState").has_value() ||
      !extract_localized(props, "FalseState").has_value())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// Validates the Mandatory `EnumStrings` and, when present, publishes @p props.
MandatoryOutcome apply_multi_state_discrete(
  ua::client::detail::MultiStateDiscreteState& state, const Props& props)
{
  if (auto refused = refuse_uncertain_properties(props, {"EnumStrings"}, resolveSource); !refused.is_good())
  {
    return refused;
  }
  if (!extract_localized_vector(props, "EnumStrings").has_value())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// Validates the Mandatory `EnumValues` and, when present, publishes @p props.
MandatoryOutcome apply_multi_state_value(
  ua::client::detail::MultiStateValueDiscreteState& state, const Props& props)
{
  // MultiStateValueDiscreteType (OPC 10000-8 section 5.3.3.4) mandates BOTH EnumValues and ValueAsText
  // (CL-DA-001).
  if (auto refused = refuse_uncertain_properties(props, {"EnumValues", "ValueAsText"}, resolveSource);
      !refused.is_good())
  {
    return refused;
  }
  if (!extract_enum_values(props, "EnumValues").has_value() ||
      !extract_localized(props, "ValueAsText").has_value())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// MultiStateDictionaryEntryDiscreteBaseType (OPC 10000-19 section 7.1) is a subtype of
/// MultiStateValueDiscreteType that additionally mandates EnumDictionaryEntries, on top of the
/// inherited-Mandatory EnumValues (CL-DA-001). EnumDictionaryEntries is a `NodeId[][]` reference table the
/// typed handle does not decode here; the Mandatory gate checks that the Property resolved to a non-empty
/// value  -  an absent EnumDictionaryEntries child is never matched during the Browse pre-flight, so it is
/// simply not in @p props and this rejects.
MandatoryOutcome apply_msde_dbt(ua::client::detail::MultiStateValueDiscreteState& state, const Props& props)
{
  if (auto refused = refuse_uncertain_properties(
        props, {"EnumValues", "ValueAsText", "EnumDictionaryEntries"}, resolveSource);
      !refused.is_good())
  {
    return refused;
  }
  // Inherited-Mandatory from MultiStateValueDiscreteType: EnumValues + ValueAsText (CL-DA-001).
  if (!extract_enum_values(props, "EnumValues").has_value() ||
      !extract_localized(props, "ValueAsText").has_value())
  {
    return mandatory_missing();
  }
  const ua::DataValue* dictionaryEntries = find_property(props, "EnumDictionaryEntries");
  if (dictionaryEntries == nullptr || dictionaryEntries->value().empty())
  {
    return mandatory_missing();
  }
  publish_properties(state, props);
  return mandatory_resolved();
}

/// The children accumulated from a one-level Browse (across all continuation pages).
using ReferenceList = std::vector<ua::ReferenceDescription>;

/// Builds a one-level forward Browse of @p nodeId along @p referenceType (subtypes included), requesting the
/// BrowseName result mask (the only field the DA Property match needs).
ua::BrowseRequest make_property_browse(const ua::NodeId& nodeId, ua::ReferenceTypeId referenceType)
{
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = nodeId;
  browseDescription.browse_direction() = ua::BrowseDirection::Forward;
  browseDescription.reference_type_id() = ua::NodeId{std::uint16_t{0}, referenceType};
  browseDescription.include_subtypes() = true;
  browseDescription.result_mask() = static_cast<std::uint32_t>(ua::BrowseResultMask::BrowseName);
  ua::BrowseRequest browse;
  browse.nodes_to_browse().push_back(std::move(browseDescription));
  return browse;
}

/// Builds a continuing (non-release) BrowseNext for @p continuationPoint.
ua::BrowseNextRequest make_property_browse_next(const ua::ContinuationPoint& continuationPoint)
{
  ua::BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().push_back(continuationPoint);
  return request;
}

/// Continuation of @ref browse_property_children: drains the remaining continuation pages via BrowseNext,
/// appending references into @p accumulated, until the server returns an empty continuation point (it
/// releases the continuation point on exhaustion). @p interface is held strong across the page walk.
void drain_property_children(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps,
  std::shared_ptr<ReferenceList> accumulated, ua::ContinuationPoint continuationPoint, std::string source,
  std::function<void(ua::Result<ReferenceList>)> done,
  std::shared_ptr<ua::client::detail::BrowseDrainGuard> guard = {})
{
  if (!guard)
  {
    guard = std::make_shared<ua::client::detail::BrowseDrainGuard>(
      source, ua::client::detail::BrowseDrainLimits{}, accumulated->size());
  }
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_next_async(make_property_browse_next(continuationPoint),
    [lockedWireOps = std::move(lockedWireOps),
      accumulated = std::move(accumulated),
      source = std::move(source),
      done = std::move(done),
      guard](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      // The SDK selects the Properties it reads from these References, so only a Good answer is used: an
      // Uncertain one is refused (ReferencesAnswerUncertain), as a Bad one fails the walk.
      if (response.is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          response.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (!response.has_value())
      {
        done(ua::Result<ReferenceList>{response.status_code(),
          ua::make_error_detail("DataAccessPropertyBrowseNextFailed",
            "a BrowseNext continuing the HasProperty Browse for the DA Variable failed",
            source,
            response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the BrowseNextResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_uncertain())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReferencesAnswerUncertain", source)});
        return;
      }
      if (serviceResult.is_bad())
      {
        done(ua::Result<ReferenceList>{serviceResult,
          ua::make_error_detail("DataAccessPropertyBrowseNextServiceFault",
            "a BrowseNext continuing the HasProperty Browse returned a service-level error",
            source,
            serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        done(ua::Result<ReferenceList>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("DataAccessPropertyBrowseNextEmpty",
            "the server returned a Good BrowseNext response with no result",
            source)});
        return;
      }
      const ua::BrowseResult& browseResult = results[0];
      if (browseResult.status_code().is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          browseResult.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (browseResult.status_code().is_bad())
      {
        done(ua::Result<ReferenceList>{browseResult.status_code(),
          ua::make_error_detail("DataAccessPropertyBrowseNextBad",
            "a BrowseNext continuing the HasProperty Browse returned a Bad per-node status",
            source)});
        return;
      }
      // CL-VIEW-005: the page is admitted before its references are kept; a self-loop or an exhausted
      // budget ends the drain (a budget refusal releases the server's continuation point best-effort).
      if (auto admitted = guard->admit_page(browseResult); admitted.is_bad())
      {
        ua::client::detail::release_continuation_point_best_effort(
          *lockedWireOps, browseResult.continuation_point());
        done(ua::Result<ReferenceList>{admitted.status_code(), admitted.shared_detail()});
        return;
      }
      for (const auto& reference : browseResult.references())
      {
        accumulated->push_back(reference);
      }
      if (!browseResult.continuation_point().empty())
      {
        drain_property_children(std::move(lockedWireOps),
          std::move(accumulated),
          browseResult.continuation_point(),
          std::move(source),
          std::move(done),
          guard);
        return;
      }
      done(ua::Result<ReferenceList>{std::move(*accumulated)});
    });
}

/// Browses @p nodeId one level along @p referenceType and accumulates EVERY child reference across all
/// continuation pages (H2  -  a Mandatory Property landing on page 2+ must not be silently dropped, nor the
/// server continuation point leaked). Delivers the full reference list (or a Bad Result chaining the wire
/// detail under @p source). @p interface is held strong for the whole page walk.
void browse_property_children(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  ua::ReferenceTypeId referenceType, std::string source, std::function<void(ua::Result<ReferenceList>)> done)
{
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_async(make_property_browse(nodeId, referenceType),
    [lockedWireOps = std::move(lockedWireOps), source = std::move(source), done = std::move(done)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      // The SDK selects the Properties it reads from these References, so only a Good answer is used: an
      // Uncertain one is refused (ReferencesAnswerUncertain), as a Bad one fails the walk.
      if (response.is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          response.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (!response.has_value())
      {
        done(ua::Result<ReferenceList>{response.status_code(),
          ua::make_error_detail("DataAccessPropertyBrowseFailed",
            "the HasProperty Browse for the DA Variable failed",
            source,
            response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the BrowseResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_uncertain())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReferencesAnswerUncertain", source)});
        return;
      }
      if (serviceResult.is_bad())
      {
        done(ua::Result<ReferenceList>{serviceResult,
          ua::make_error_detail("DataAccessPropertyBrowseServiceFault",
            "the HasProperty Browse for the DA Variable returned a service-level error",
            source,
            serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        done(ua::Result<ReferenceList>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("DataAccessPropertyBrowseEmpty",
            "the server returned a Good Browse response with no result",
            source)});
        return;
      }
      const ua::BrowseResult& browseResult = results[0];
      if (browseResult.status_code().is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          browseResult.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (browseResult.status_code().is_bad())
      {
        done(ua::Result<ReferenceList>{browseResult.status_code(),
          ua::make_error_detail("DataAccessPropertyBrowseBad",
            "the HasProperty Browse for the DA Variable returned a Bad per-node status",
            source)});
        return;
      }
      auto accumulated = std::make_shared<ReferenceList>();
      for (const auto& reference : browseResult.references())
      {
        accumulated->push_back(reference);
      }
      if (!browseResult.continuation_point().empty())
      {
        drain_property_children(std::move(lockedWireOps),
          std::move(accumulated),
          browseResult.continuation_point(),
          std::move(source),
          std::move(done));
        return;
      }
      done(ua::Result<ReferenceList>{std::move(*accumulated)});
    });
}

/// Browses @p nodeId one level for `HasProperty` children (across all pages), matches the ns0 BrowseNames in
/// @p wantedNames, and Reads every matched child's Value Attribute in one batched Read. Delivers the
/// name to Value map (only matched children present). Any browse/read service failure delivers a Bad Result
/// chaining the wire detail under @p source. @p interface is held strong across the round-trips so the
/// Connection cannot drop it mid-resolve.
void resolve_properties(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  std::vector<std::string> wantedNames, std::string source, std::function<void(ua::Result<Props>)> done)
{
  auto wireOpsForRead = lockedWireOps;  // held for the batched Read after the (paged) Browse resolves
  browse_property_children(std::move(lockedWireOps),
    std::move(nodeId),
    ua::ReferenceTypeId::HasProperty,
    source,
    [wireOpsForRead = std::move(wireOpsForRead),
      wanted = std::move(wantedNames),
      source,
      done = std::move(done)](ua::Result<ReferenceList> references) mutable
    {
      if (!references.is_good())
      {
        done(ua::Result<Props>{references.status_code(), references.shared_detail()});
        return;
      }
      std::vector<std::string> matchedNames;
      ua::ReadRequest read;
      for (const auto& reference : references.value())
      {
        const ua::QualifiedName& browseName = reference.browse_name();
        if (browseName.namespace_index() != 0)
        {
          continue;
        }
        std::string name = static_cast<std::string>(browseName.name());
        const bool wantedName = std::find(wanted.begin(), wanted.end(), name) != wanted.end();
        if (!wantedName)
        {
          continue;
        }
        ua::ReadValueId readValue;
        readValue.node_id() = reference.node_id().node_id();  // ExpandedNodeId -> local NodeId
        readValue.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
        read.nodes_to_read().push_back(std::move(readValue));
        matchedNames.push_back(std::move(name));
      }

      if (matchedNames.empty())
      {
        // No matched Property children: the caller decides whether a Mandatory Property was expected.
        done(ua::Result<Props>{Props{}});
        return;
      }

      wireOpsForRead->read_async(std::move(read),
        [names = std::move(matchedNames), source = std::move(source), done = std::move(done)](
          ua::Result<ua::ReadResponse> readResponse) mutable
        {
          // The handle decides from these values (its Mandatory Properties), so an Uncertain answer to the
          // whole Read is refused (ReadAnswerUncertain); each Property's own status stays on its DataValue.
          if (readResponse.is_uncertain())
          {
            done(ua::Result<Props>{ua::client::detail::uncertain_answer_refused(
              readResponse.status_code(), "ReadAnswerUncertain", source)});
            return;
          }
          if (!readResponse.has_value())
          {
            done(ua::Result<Props>{readResponse.status_code(),
              ua::make_error_detail("DataAccessPropertyReadFailed",
                "the batched Read of the DA Property Values failed",
                source,
                readResponse.shared_detail())});
            return;
          }
          // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad
          // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving
          // the exact service status + ErrorDetail. Without this an empty values[] trips the count-mismatch
          // branch below and masks the fault as Bad_UnexpectedError.
          const ua::StatusCode serviceResult = readResponse.value().response_header().service_result();
          if (serviceResult.is_uncertain())
          {
            done(ua::Result<Props>{
              ua::client::detail::uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", source)});
            return;
          }
          if (serviceResult.is_bad())
          {
            done(ua::Result<Props>{serviceResult,
              ua::make_error_detail("DataAccessPropertyReadServiceFault",
                "the batched Property-Value Read returned a service-level error",
                source,
                serviceResult)});
            return;
          }
          auto& values = readResponse.value().results();
          // W1  -  a batched Read MUST return exactly one DataValue per ReadValueId. A length mismatch means
          // the response cannot be positionally stitched to the requested Property names; reject it rather
          // than silently mis-mapping (which would mis-attribute or drop a Property).
          if (values.size() != names.size())
          {
            done(ua::Result<Props>{ua::Status::BadUnexpectedError,
              ua::make_error_detail("DataAccessPropertyReadCountMismatch",
                "the batched Property-Value Read returned a result count different from the number of "
                "ReadValueIds sent",
                source,
                readResponse.shared_detail())});
            return;
          }
          Props resolved;
          for (std::size_t i = 0; i < names.size(); ++i)
          {
            resolved.emplace(names[i], values[i]);
          }
          done(ua::Result<Props>{std::move(resolved)});
        });
    });
}

/// Resolves the NodeId of the ns0 @p browseName `HasProperty` child of @p parent (CL-DA-012: e.g.
/// `ValueAsDictionaryEntries` on the MSDE Variable). Browses @p parent one level (all pages) and returns the
/// matched child's NodeId  -  a Browse-only helper (no Value Read). `Bad_NotFound` (source-tagged @p source)
/// when no child matches. @p interface is held strong for the page walk; @p done is invoked inline (the
/// caller delivers on the executor).
void resolve_child_property_node(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps,
  ua::NodeId parent, std::string browseName, std::string source,
  std::function<void(ua::Result<ua::NodeId>)> done)
{
  using NodeResult = ua::Result<ua::NodeId>;
  // `source` is captured BY COPY (not std::move): it is ALSO passed as an argument to
  // browse_property_children on the same call, and sibling function-argument evaluation is unsequenced  -  a
  // std::move capture could empty `source` before the argument copy is read, dropping the ErrorDetail source
  // tag. (Matches resolve_properties / resolve_child_property_value.)
  browse_property_children(std::move(lockedWireOps),
    std::move(parent),
    ua::ReferenceTypeId::HasProperty,
    source,
    [browseName = std::move(browseName), source, done = std::move(done)](
      ua::Result<ReferenceList> references) mutable
    {
      if (!references.is_good())
      {
        done(NodeResult{references.status_code(), references.shared_detail()});
        return;
      }
      for (const auto& reference : references.value())
      {
        const ua::QualifiedName& candidate = reference.browse_name();
        if (candidate.namespace_index() != 0 || static_cast<std::string_view>(candidate.name()) != browseName)
        {
          continue;
        }
        done(NodeResult{reference.node_id().node_id()});  // ExpandedNodeId -> local NodeId
        return;
      }
      done(NodeResult{ua::Status::BadNotFound,
        ua::make_error_detail(
          "DataAccessChildPropertyNotFound", "no child Property matched the requested BrowseName", source)});
    });
}

/// Locks the interface roles + resolves the Properties + applies @p apply, delivering the populated
/// `shared_ptr<StateType>` (or a Bad Result) on the executor. On a Mandatory Property miss (`apply` returns
/// false) delivers `Bad_NotFound` with source `client.tier2.data_access.property_resolution_failed`
/// (CL-DA-001).
template<typename StateType, typename ApplyFn>
void resolve_and_build_state(std::weak_ptr<ua::client::detail::WireOps> wireWeak,
  std::weak_ptr<ua::client::detail::SupportOps> supportWeak, boost::asio::any_io_executor executor,
  ua::Logger logger, ua::NodeId nodeId, std::vector<std::string> wanted, ApplyFn apply,
  std::function<void(ua::Result<std::shared_ptr<StateType>>)> done)
{
  using StateResult = ua::Result<std::shared_ptr<StateType>>;
  auto lockedWireOps = wireWeak.lock();
  auto support = supportWeak.lock();
  if (!lockedWireOps || !support)
  {
    deliver<StateResult>(executor,
      std::move(done),
      StateResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("DataAccessConnectionGone",
          "the Connection was dropped before the DA handle could be built",
          std::string{connClosedSource})});
    return;
  }

  // Build the shared state + its interfaces up front so it can be REGISTERED with the per-Connection
  // SemanticChangeCache BEFORE the construction resolve is issued (M1). CL-DA-010 auto path: a
  // SemanticsChanged bit / a SemanticChangeEventType naming this NodeId flips invalidated so the next read
  // re-resolves. If the registration ran only AFTER the construction resolve (as it once did), a semantic
  // change that landed between the resolve snapshot and the register would be lost  -  the entry would not
  // yet exist to flip. Registering first closes that gap: a change during the build then flips the flag and
  // the FIRST read re-resolves. Best-effort: a gone/absent cache leaves the Ticket empty (the manual refresh
  // path still works). The Ticket lives on the shared state, so the cache's weak entry prunes lazily once the
  // last handle copy drops the state.
  auto state = std::make_shared<StateType>();
  state->wireOps = wireWeak;
  state->supportOps = supportWeak;
  state->executor = executor;
  state->logger = std::move(logger);
  state->nodeId = nodeId;
  if (auto cache = support->semantic_change_cache())
  {
    state->cacheTicket = cache->register_state(state->nodeId, state);
  }

  resolve_properties(std::move(lockedWireOps),
    std::move(nodeId),
    std::move(wanted),
    std::string{resolveSource},
    [state, executor, apply, done = std::move(done)](ua::Result<Props> props) mutable
    {
      if (!props.is_good())
      {
        // The state (and its cache registration) is discarded here; the cache's weak entry prunes lazily.
        deliver<StateResult>(
          executor, std::move(done), StateResult{props.status_code(), props.shared_detail()});
        return;
      }
      const MandatoryOutcome applied = apply(*state, props.value());  // publishes the immutable snapshot
      if (!applied.is_good())
      {
        deliver<StateResult>(executor,
          std::move(done),
          StateResult{mandatory_failure(applied,
            "a Mandatory DataAccess Property was absent or undecodable during handle construction",
            props.shared_detail())});
        return;
      }
      deliver<StateResult>(executor, std::move(done), StateResult{std::move(state)});
    });
}

/// The shared Value-read plumbing for every typed handle: locks the interface, Reads the Variable Value,
/// weak-captures the state (bailing if the handle dropped mid-flight, section 9.8.3), and hands the combined
/// typed value from @p decode back on the executor. @p decode is passed the state's IMMUTABLE
/// resolved-Property snapshot (loaded acquire) + the freshly-read Value, so it reads a whole, consistent
/// snapshot even if a re-resolve on another thread swaps in a newer one concurrently (H2). Assumes @p state
/// is non-null and its Properties are current (the @ref do_typed_read wrapper handles the moved-from guard
/// and the CL-DA-010 re-resolve first).
template<typename StateType, typename ValueType, typename DecodeFn>
void read_value_and_decode(const std::shared_ptr<StateType>& state, DecodeFn decode,
  std::function<void(ua::Result<ValueType>)> callback)
{
  using R = ua::Result<ValueType>;
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<R>(state->executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("DataAccessConnectionGone",
          "the Connection was dropped before the DA read could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto executor = state->executor;
  std::weak_ptr<StateType> weak = state;
  lockedWireOps->read_async(make_value_read(state->nodeId),
    [weak, executor, decode, callback = std::move(callback)](ua::Result<ua::ReadResponse> response) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!response.has_value())
      {
        // Surface the server's status verbatim but tag the boundary with the read source and chain the wire
        // detail (the design specification: forwarding a bad wire result carries a source-tagged detail,
        // never a bare status that loses the read context  -  W2).
        deliver<R>(executor,
          std::move(callback),
          R{response.status_code(),
            ua::make_error_detail("DataAccessReadFailed",
              "the Read of the DA Variable Value failed",
              std::string{readSource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{serviceResult,
            ua::make_error_detail("DataAccessReadServiceFault",
              "the Read of the DA Variable Value returned a service-level error",
              std::string{readSource},
              serviceResult)});
        return;
      }
      auto& results = response.value().results();
      if (results.empty())
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadUnexpectedError,
            ua::make_error_detail("DataAccessReadEmpty",
              "the server returned a Good Read response with no result",
              std::string{readSource})});
        return;
      }
      // Load the immutable resolved-Property snapshot (acquire pairs with publish_properties' release) and
      // hand the immutable pointee to the decoder alongside the freshly-read Value (H2  -  never read the
      // shared state's Properties in place). The snapshot is default-initialised non-null, so no null guard
      // is needed for a built handle.
      const auto snapshot = locked->resolvedProperties.load(std::memory_order_acquire);
      // The typed value's code: the Read's ServiceResult and the code of the resolved Properties it is
      // decoded from, combined, so a Good subcode or an Uncertain code of either reaches the caller. The
      // Value's own status stays on `value.status()`.
      deliver<R>(executor,
        std::move(callback),
        ua::detail::held(decode(*snapshot, results[0]),
          ua::detail::combined_status(serviceResult, resolved_properties_code(*snapshot))));
    });
}

/// The typed-read entry every handle's `read_async` calls (CL-DA-001 + CL-DA-010). Guards the moved-from
/// handle, then: if the @ref detail::TypedPropertiesState::invalidated flag the SemanticChangeCache flips is
/// set, RE-RESOLVES the Properties in place (Browse `HasProperty` + batched Read via @p wanted / @p apply),
/// clears the flag, and only then reads the Variable Value; otherwise it goes straight to the Value read. A
/// re-resolve that fails  -  or that no longer surfaces a Mandatory Property  -  surfaces Bad and does NOT
/// yield a stale value (section 8.18.5). The re-resolve mutates the shared state in place, so every copy of
/// the handle observes the refreshed snapshot (matching the manual `refresh_properties_async` path).
template<typename StateType, typename ValueType, typename ApplyFn, typename DecodeFn>
void do_typed_read(const std::shared_ptr<StateType>& state, std::vector<std::string> wanted, ApplyFn apply,
  DecodeFn decode, std::function<void(ua::Result<ValueType>)> callback)
{
  using R = ua::Result<ValueType>;
  if (!state)
  {
    callback(R{ua::Status::BadInvalidState,
      ua::make_error_detail(
        "DataAccessMovedFrom", "read issued on a moved-from DA handle", std::string{readSource})});
    return;
  }
  if (!state->invalidated.load(std::memory_order_acquire))
  {
    // Properties current: the common path is a single Value Read (no extra round trips).
    read_value_and_decode<StateType, ValueType>(state, decode, std::move(callback));
    return;
  }
  // CL-DA-010 auto path: the SemanticChangeCache flagged this NodeId's Properties stale (a SemanticsChanged
  // bit or a SemanticChangeEventType named it). Re-resolve BEFORE the Value read so the combined value never
  // carries stale Properties.
  //
  // H1: CLEAR the flag NOW  -  at the slow-path entry, BEFORE issuing the re-resolve  -  not after it
  // completes. A semantic change that lands DURING the re-resolve window (the browse/read round trips) then
  // re-sets the flag, and the NEXT read re-resolves again. Clearing it only after a successful re-resolve
  // would swallow such a raced invalidation and serve a stale snapshot. Every FAILURE exit below re-sets the
  // flag so the re-resolve is retried rather than silently abandoned (leaving the handle wrongly "current").
  state->invalidated.store(false, std::memory_order_release);
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    state->invalidated.store(true, std::memory_order_release);  // re-resolve could not start: retry next read
    deliver<R>(state->executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("DataAccessConnectionGone",
          "the Connection was dropped before the DA properties could be re-resolved",
          std::string{connClosedSource})});
    return;
  }
  auto executor = state->executor;
  std::weak_ptr<StateType> weak = state;
  resolve_properties(std::move(lockedWireOps),
    state->nodeId,
    std::move(wanted),
    std::string{resolveSource},
    [weak, executor, apply, decode, callback = std::move(callback)](ua::Result<Props> props) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!props.is_good())
      {
        // Re-resolve failed: do not yield a stale value (section 8.18.5). Surface Bad and re-set invalidated
        // so a later read retries the re-resolve (H1).
        locked->invalidated.store(true, std::memory_order_release);
        deliver<R>(executor, std::move(callback), R{props.status_code(), props.shared_detail()});
        return;
      }
      const MandatoryOutcome applied =
        apply(*locked, props.value());  // publishes the fresh snapshot on success
      if (!applied.is_good())
      {
        // The Mandatory Property vanished (or was answered Uncertain) on re-resolve: surface the failure,
        // deliver NO stale value, and re-set invalidated so a later read retries (H1). The previous snapshot
        // is left untouched (apply publishes only on success), but the invalidation gate keeps the handle
        // from serving it as current.
        locked->invalidated.store(true, std::memory_order_release);
        deliver<R>(executor,
          std::move(callback),
          R{mandatory_failure(applied,
            "a Mandatory DataAccess Property was absent or undecodable during the SemanticChange re-resolve",
            props.shared_detail())});
        return;
      }
      // Re-resolve succeeded: the flag was cleared at slow-path entry. Do NOT clear it again here  -  a
      // concurrent invalidate during the re-resolve window may have re-set it, and we want the NEXT read to
      // re-resolve again (H1). Read the Value against the freshly-published snapshot.
      read_value_and_decode<StateType, ValueType>(locked, decode, std::move(callback));
    });
}

/// The shared Value-Write plumbing for the analog / two-state / multi-state-discrete writers (CL-DA-007): a
/// thin passthrough that surfaces the server's accept / reject / clamp status verbatim, chaining any server
/// detail under @p source. Writes @p newValue to @p targetNodeId's Value attribute  -  @p targetNodeId is a
/// parameter (not always `state->nodeId`) so the CL-DA-012 dictionary path can target the
/// `ValueAsDictionaryEntries` Property node rather than the Variable's own Value. @p source tags every
/// manufactured failure so the boundary reads legibly for whichever writer drives it.
template<typename StatePtr>
void do_write_node_value(const StatePtr& state, ua::NodeId targetNodeId, ua::Variant newValue,
  std::string_view source, std::function<void(ua::VoidResult)> callback)
{
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<ua::VoidResult>(state->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("DataAccessConnectionGone",
          "the Connection was dropped before the DA write could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto executor = state->executor;
  std::weak_ptr<ua::client::detail::DataAccessHandleBase> weak = state;
  ua::WriteValue writeValue;
  writeValue.node_id() = std::move(targetNodeId);
  writeValue.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  writeValue.value() = ua::DataValue{std::move(newValue)};
  ua::WriteRequest request;
  request.nodes_to_write().push_back(std::move(writeValue));
  lockedWireOps->write_async(std::move(request),
    [weak, executor, source = std::string{source}, callback = std::move(callback)](
      ua::Result<ua::WriteResponse> response) mutable
    {
      if (!weak.lock())
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!response.has_value())
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), ua::VoidResult{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten: the wire funnel returns the WriteResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{serviceResult,
            ua::make_error_detail("DataAccessWriteServiceFault",
              "the Write service returned a service-level error",
              source,
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail(
              "DataAccessWriteEmpty", "the server returned a Good Write response with no result", source)});
        return;
      }
      const ua::StatusCode status = results[0];
      if (status.is_bad())
      {
        // Surface the server's per-write status verbatim (accept / reject / clamp is server-defined,
        // CL-DA-007), chained on any server detail.
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{status,
            ua::make_error_detail("DataAccessWriteRejected",
              "the server rejected or clamped the Value write",
              source,
              response.shared_detail())});
        return;
      }
      // The write's own status and the ServiceResult combined: a Good subcode such as Good_Clamped or
      // Good_CompletesAsynchronously, or an Uncertain code, of either reaches the caller.
      deliver<ua::VoidResult>(
        executor, std::move(callback), ua::VoidResult{ua::detail::combined_status(serviceResult, status)});
    });
}

/// The Value-write for the analog / two-state / multi-state-discrete writers (CL-DA-007): writes @p newValue
/// to the Variable's OWN Value attribute under the `client.tier2.data_access.write` source. A thin delegate
/// to
/// @ref do_write_node_value, unchanged in behaviour.
template<typename StatePtr>
void do_write_value(const StatePtr& state, ua::Variant newValue, std::function<void(ua::VoidResult)> callback)
{
  do_write_node_value(state, state->nodeId, std::move(newValue), writeSource, std::move(callback));
}

/// The shared refresh plumbing: re-resolves the Properties and publishes them via @p apply as a fresh
/// immutable snapshot on the shared state (an atomic swap, never in place  -  H2), so every copy of the
/// handle observes the refreshed snapshot the instant it is published (CL-DA-010 manual path). Delivers Good
/// on a successful re-resolve; a browse/read service failure  -  or a re-resolve that no longer surfaces a
/// Mandatory Property (H3: `apply` returns false, mirroring construction)  -  surfaces Bad.
template<typename StateType, typename ApplyFn>
void do_refresh_properties(const std::shared_ptr<StateType>& state, std::vector<std::string> wanted,
  ApplyFn apply, std::function<void(ua::VoidResult)> callback)
{
  if (!state)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("DataAccessMovedFrom",
        "refresh_properties issued on a moved-from DA handle",
        std::string{resolveSource})});
    return;
  }
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<ua::VoidResult>(state->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("DataAccessConnectionGone",
          "the Connection was dropped before the DA properties could be refreshed",
          std::string{connClosedSource})});
    return;
  }
  auto executor = state->executor;
  std::weak_ptr<StateType> weak = state;
  resolve_properties(std::move(lockedWireOps),
    state->nodeId,
    std::move(wanted),
    std::string{resolveSource},
    [weak, executor, apply, callback = std::move(callback)](ua::Result<Props> props) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!props.is_good())
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), ua::VoidResult{props.status_code(), props.shared_detail()});
        return;
      }
      // Publish the fresh snapshot by an atomic swap (never in place  -  H2). `apply` reports whether the
      // Mandatory Property(ies) re-resolved; if not, refresh mirrors construction and delivers Bad_NotFound
      // (H3  -  the handle must not report Good with a vanished Mandatory Property), leaving the prior
      // snapshot untouched.
      const MandatoryOutcome applied = apply(*locked, props.value());
      if (!applied.is_good())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{mandatory_failure(applied,
            "a Mandatory DataAccess Property was absent or undecodable during refresh",
            props.shared_detail())});
        return;
      }
      deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{});
    });
}

// ---- Typed-value decoders (immutable Property snapshot + freshly-read Value -> typed struct) ----
//
// Each decoder is handed the state's IMMUTABLE resolved-Property snapshot (loaded acquire by
// read_value_and_decode)  -  never the mutable shared state  -  and extracts its typed Properties from it
// (H2).

AnalogItemValue decode_analog_value(const Props& props, const ua::DataValue& value)
{
  AnalogItemValue out;
  out.value = value;  // status surfaced verbatim (CL-DA-015)
  out.definition = extract_definition(props);
  out.valuePrecision = extract_value_precision(props);
  out.euRange = extract_range(props, "EURange");
  out.instrumentRange = extract_range(props, "InstrumentRange");
  out.engineeringUnits = extract_eu(props, "EngineeringUnits");
  return out;
}

TwoStateDiscreteValue decode_two_state_value(const Props& props, const ua::DataValue& value)
{
  TwoStateDiscreteValue out;
  out.value = value;
  out.definition = extract_definition(props);
  out.valuePrecision = extract_value_precision(props);
  if (auto trueState = extract_localized(props, "TrueState"))
  {
    out.trueState = std::move(*trueState);
  }
  if (auto falseState = extract_localized(props, "FalseState"))
  {
    out.falseState = std::move(*falseState);
  }
  // The Value is decoded only when its status allows it: a Bad Value, or an Uncertain one without a value,
  // leaves the decoded field at its default; the status itself is on `out.value`.
  if (!decodable_answer(value))
  {
    return out;
  }
  if (auto boolean = value.value().to<bool>(); boolean.is_good())
  {
    out.state = boolean.value();
  }
  return out;
}

MultiStateDiscreteValue decode_multi_state_discrete_value(const Props& props, const ua::DataValue& value)
{
  MultiStateDiscreteValue out;
  out.value = value;
  out.definition = extract_definition(props);
  out.valuePrecision = extract_value_precision(props);
  if (auto enumStrings = extract_localized_vector(props, "EnumStrings"))
  {
    out.enumStrings = std::move(*enumStrings);
  }
  if (!decodable_answer(value))
  {
    return out;  // a Bad Value, or an Uncertain one without a value: the status is on `out.value`
  }
  if (auto index = to_unsigned(value.value()))
  {
    out.rawIndex = static_cast<std::uint32_t>(*index);  // always surfaced (CL-DA-008)
    if (*index < out.enumStrings.size())
    {
      out.currentName = out.enumStrings[static_cast<std::size_t>(*index)];
    }
  }
  return out;
}

MultiStateValueDiscreteValue decode_multi_state_value_value(const Props& props, const ua::DataValue& value)
{
  MultiStateValueDiscreteValue out;
  out.value = value;
  out.definition = extract_definition(props);
  out.valuePrecision = extract_value_precision(props);
  if (auto enumValues = extract_enum_values(props, "EnumValues"))
  {
    out.enumValues = std::move(*enumValues);
  }
  if (!decodable_answer(value))
  {
    return out;  // a Bad Value, or an Uncertain one without a value: the status is on `out.value`
  }
  if (auto raw = to_signed(value.value()))
  {
    out.rawValue = *raw;  // always surfaced (CL-DA-008)
    for (const auto& entry : out.enumValues)
    {
      if (entry.value() == *raw)
      {
        out.currentName = entry.display_name();
        break;
      }
    }
  }
  return out;
}

}  // namespace

// ============================================================================
// DataAccessAccessor
// ============================================================================

DataAccessAccessor::DataAccessAccessor(std::weak_ptr<detail::WireOps> wireOps,
  std::weak_ptr<detail::SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger)
  : mWireOps(std::move(wireOps)), mSupportOps(std::move(supportOps)), mExecutor(std::move(executor)),
    mLogger(std::move(logger))
{}

void DataAccessAccessor::analog_item_async(
  ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept
{
  resolve_and_build_state<detail::AnalogItemState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EURange", "EngineeringUnits", "InstrumentRange", "ValuePrecision", "Definition"},
    &apply_analog,
    [callback = std::move(callback)](ua::Result<std::shared_ptr<detail::AnalogItemState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(AnalogItemHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(AnalogItemHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::base_analog_async(
  ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept
{
  // BaseAnalogType shares AnalogItemHandle's value/property shape but relaxes the Mandatory-EURange
  // pre-flight (apply_base_analog): a BaseAnalogType node with none of the Optional Properties still
  // resolves a usable handle (CL-DA-001).
  resolve_and_build_state<detail::AnalogItemState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EURange", "EngineeringUnits", "InstrumentRange", "ValuePrecision", "Definition"},
    &apply_base_analog,
    [callback = std::move(callback)](ua::Result<std::shared_ptr<detail::AnalogItemState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(AnalogItemHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(AnalogItemHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::analog_unit_async(
  ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept
{
  // AnalogUnitType mandates EngineeringUnits (apply_analog_unit); EURange stays Optional (it derives from
  // BaseAnalogType, not AnalogItemType  -  CL-DA-001).
  resolve_and_build_state<detail::AnalogItemState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EURange", "EngineeringUnits", "InstrumentRange", "ValuePrecision", "Definition"},
    &apply_analog_unit,
    [callback = std::move(callback)](ua::Result<std::shared_ptr<detail::AnalogItemState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(AnalogItemHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(AnalogItemHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::analog_unit_range_async(
  ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept
{
  // AnalogUnitRangeType mandates BOTH EURange (inherited-Mandatory from AnalogItemType) and EngineeringUnits
  // (apply_analog_unit_range  -  CL-DA-001).
  resolve_and_build_state<detail::AnalogItemState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EURange", "EngineeringUnits", "InstrumentRange", "ValuePrecision", "Definition"},
    &apply_analog_unit_range,
    [callback = std::move(callback)](ua::Result<std::shared_ptr<detail::AnalogItemState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(AnalogItemHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(AnalogItemHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::two_state_discrete_async(
  ua::NodeId nodeId, std::function<void(TwoStateDiscreteHandleResult)> callback) noexcept
{
  resolve_and_build_state<detail::TwoStateDiscreteState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"TrueState", "FalseState", "ValuePrecision", "Definition"},
    &apply_two_state,
    [callback = std::move(callback)](
      ua::Result<std::shared_ptr<detail::TwoStateDiscreteState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(TwoStateDiscreteHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(TwoStateDiscreteHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::multi_state_discrete_async(
  ua::NodeId nodeId, std::function<void(MultiStateDiscreteHandleResult)> callback) noexcept
{
  resolve_and_build_state<detail::MultiStateDiscreteState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EnumStrings", "ValuePrecision", "Definition"},
    &apply_multi_state_discrete,
    [callback = std::move(callback)](
      ua::Result<std::shared_ptr<detail::MultiStateDiscreteState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(MultiStateDiscreteHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(MultiStateDiscreteHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::multi_state_value_discrete_async(
  ua::NodeId nodeId, std::function<void(MultiStateValueDiscreteHandleResult)> callback) noexcept
{
  resolve_and_build_state<detail::MultiStateValueDiscreteState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EnumValues", "ValueAsText", "ValuePrecision", "Definition"},
    &apply_multi_state_value,
    [callback = std::move(callback)](
      ua::Result<std::shared_ptr<detail::MultiStateValueDiscreteState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(MultiStateValueDiscreteHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(MultiStateValueDiscreteHandle{std::move(result).value()}, answered));
    });
}

void DataAccessAccessor::multi_state_dictionary_entry_async(
  ua::NodeId nodeId, std::function<void(MultiStateValueDiscreteHandleResult)> callback) noexcept
{
  // MSDE-DBT (Part 19) mandates EnumDictionaryEntries in addition to the inherited MSVD EnumValues
  // (apply_msde_dbt). It reuses MultiStateValueDiscreteHandle  -  MSDE-DBT is a MultiStateValueDiscreteType
  // subtype  -  with EnumDictionaryEntries added to the pre-flight browse/read set.
  resolve_and_build_state<detail::MultiStateValueDiscreteState>(mWireOps,
    mSupportOps,
    mExecutor,
    mLogger,
    std::move(nodeId),
    {"EnumValues", "EnumDictionaryEntries", "ValueAsText", "ValuePrecision", "Definition"},
    &apply_msde_dbt,
    [callback = std::move(callback)](
      ua::Result<std::shared_ptr<detail::MultiStateValueDiscreteState>> result) mutable
    {
      if (!result.has_value())
      {
        callback(MultiStateValueDiscreteHandleResult{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode answered = result.status_code();
      callback(ua::detail::held(MultiStateValueDiscreteHandle{std::move(result).value()}, answered));
    });
}

// ============================================================================
// AnalogItemHandle
// ============================================================================

void AnalogItemHandle::read_async(std::function<void(AnalogItemValueResult)> callback) noexcept
{
  do_typed_read<detail::AnalogItemState, AnalogItemValue>(mState,
    {"EURange", "EngineeringUnits", "InstrumentRange", "ValuePrecision", "Definition"},
    &apply_analog,
    &decode_analog_value,
    std::move(callback));
}

void AnalogItemHandle::write_value_async(
  ua::Variant newValue, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("DataAccessMovedFrom",
        "write_value issued on a moved-from AnalogItemHandle",
        std::string{writeSource})});
    return;
  }
  do_write_value(mState, std::move(newValue), std::move(callback));
}

void AnalogItemHandle::refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  do_refresh_properties(mState,
    {"EURange", "EngineeringUnits", "InstrumentRange", "ValuePrecision", "Definition"},
    &apply_analog,
    std::move(callback));
}

ua::Result<ua::DataChangeFilter> AnalogItemHandle::make_percent_deadband_filter(double percent) const noexcept
{
  using R = ua::Result<ua::DataChangeFilter>;
  if (!mState)
  {
    return R{ua::Status::BadInvalidState,
      ua::make_error_detail("DataAccessMovedFrom",
        "make_percent_deadband_filter on a moved-from AnalogItemHandle",
        std::string{deadbandSource})};
  }
  // NaN slips past a bare `percent < 0 || percent > 100` check (both comparisons are false for NaN, M1);
  // reject it explicitly so a Good filter never carries a NaN deadband.
  if (std::isnan(percent) || percent < 0.0 || percent > 100.0)
  {
    return R{ua::Status::BadDeadbandFilterInvalid,
      ua::make_error_detail("PercentDeadbandOutOfRange",
        "the PercentDeadband must be a finite value within [0, 100]",
        std::string{deadbandSource})};
  }
  // EURange is read from the IMMUTABLE resolved-Property snapshot (acquire), never the mutable shared state
  // (H2). A re-resolve on another thread swaps in a whole new snapshot, so this precondition check always
  // sees a consistent view.
  const auto snapshot = mState->resolvedProperties.load(std::memory_order_acquire);
  // The precondition is a decision the SDK takes from EURange, so only a Good answer is used: an Uncertain
  // EURange is refused (ReadAnswerUncertain).
  if (snapshot)
  {
    if (auto refused = refuse_uncertain_properties(*snapshot, {"EURange"}, deadbandSource);
        !refused.is_good())
    {
      return R{std::move(refused)};
    }
  }
  if (!snapshot || !extract_range(*snapshot, "EURange").has_value())
  {
    return R{ua::Status::BadFilterNotAllowed,
      ua::make_error_detail("PercentDeadbandRequiresEuRange",
        "EURange Property is required for PercentDeadband but is absent",
        std::string{deadbandSource})};
  }
  // The wire carries PercentDeadband; the server is the authoritative computer (CL-DA-003). The SDK does not
  // translate to an absolute band locally  -  EURange presence is a precondition only. For an array Variable
  // the same single filter is used (CL-DA-006).
  ua::DataChangeFilter filter;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Percent);
  filter.deadband_value() = percent;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  return R{std::move(filter)};
}

ua::NodeId AnalogItemHandle::node_id() const noexcept
{
  return mState ? mState->nodeId : ua::NodeId{};
}

// ============================================================================
// TwoStateDiscreteHandle
// ============================================================================

void TwoStateDiscreteHandle::read_async(std::function<void(TwoStateDiscreteValueResult)> callback) noexcept
{
  do_typed_read<detail::TwoStateDiscreteState, TwoStateDiscreteValue>(mState,
    {"TrueState", "FalseState", "ValuePrecision", "Definition"},
    &apply_two_state,
    &decode_two_state_value,
    std::move(callback));
}

void TwoStateDiscreteHandle::write_value_async(
  ua::Variant newValue, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("DataAccessMovedFrom",
        "write_value issued on a moved-from TwoStateDiscreteHandle",
        std::string{writeSource})});
    return;
  }
  do_write_value(mState, std::move(newValue), std::move(callback));
}

void TwoStateDiscreteHandle::refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  do_refresh_properties(mState,
    {"TrueState", "FalseState", "ValuePrecision", "Definition"},
    &apply_two_state,
    std::move(callback));
}

ua::NodeId TwoStateDiscreteHandle::node_id() const noexcept
{
  return mState ? mState->nodeId : ua::NodeId{};
}

// ============================================================================
// MultiStateDiscreteHandle
// ============================================================================

void MultiStateDiscreteHandle::read_async(
  std::function<void(MultiStateDiscreteValueResult)> callback) noexcept
{
  do_typed_read<detail::MultiStateDiscreteState, MultiStateDiscreteValue>(mState,
    {"EnumStrings", "ValuePrecision", "Definition"},
    &apply_multi_state_discrete,
    &decode_multi_state_discrete_value,
    std::move(callback));
}

void MultiStateDiscreteHandle::write_value_async(
  ua::Variant newValue, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("DataAccessMovedFrom",
        "write_value issued on a moved-from MultiStateDiscreteHandle",
        std::string{writeSource})});
    return;
  }
  do_write_value(mState, std::move(newValue), std::move(callback));
}

void MultiStateDiscreteHandle::refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  do_refresh_properties(mState,
    {"EnumStrings", "ValuePrecision", "Definition"},
    &apply_multi_state_discrete,
    std::move(callback));
}

ua::NodeId MultiStateDiscreteHandle::node_id() const noexcept
{
  return mState ? mState->nodeId : ua::NodeId{};
}

// ============================================================================
// MultiStateValueDiscreteHandle
// ============================================================================

void MultiStateValueDiscreteHandle::read_async(
  std::function<void(MultiStateValueDiscreteValueResult)> callback) noexcept
{
  do_typed_read<detail::MultiStateValueDiscreteState, MultiStateValueDiscreteValue>(mState,
    {"EnumValues", "ValueAsText", "ValuePrecision", "Definition"},
    &apply_multi_state_value,
    &decode_multi_state_value_value,
    std::move(callback));
}

void MultiStateValueDiscreteHandle::write_via_dictionary_async(
  std::size_t stateIndex, std::function<void(ua::VoidResult)> callback) noexcept
{
  // Every dictionary column of a state's row identifies the same state; column 0 is the safe default.
  write_via_dictionary_async(stateIndex, 0, std::move(callback));
}

void MultiStateValueDiscreteHandle::write_via_dictionary_async(
  std::size_t stateIndex, std::size_t dictionaryIndex, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("DataAccessMovedFrom",
        "write_via_dictionary issued on a moved-from MultiStateValueDiscreteHandle",
        std::string{msdeResolveSource})});
    return;
  }
  auto lockedWireOps = mState->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("DataAccessConnectionGone",
          "the Connection was dropped before the dictionary write could be issued",
          std::string{connClosedSource})});
    return;
  }
  // CL-DA-012 (OPC 10000-19 section 7.1): select EnumDictionaryEntries[state_index][dictionary_index] from
  // the cached 2-D NodeId table and Write it (as a one-element NodeId[]) to the resolved
  // ValueAsDictionaryEntries Property. The table is decoded from the IMMUTABLE resolved-Property snapshot
  // (acquire), never the mutable shared state (H2). Every bounds/validity failure is LOCAL  -  decided here
  // before any wire request  -  so an out-of-range index or an absent/undecodable table touches the wire for
  // nothing (the negative matrix row).
  const auto snapshot = mState->resolvedProperties.load(std::memory_order_acquire);
  // The SDK selects the NodeId it writes from this table, so only a Good answer is used: an Uncertain
  // EnumDictionaryEntries is refused (ReadAnswerUncertain).
  if (snapshot)
  {
    if (auto refused = refuse_uncertain_properties(*snapshot, {"EnumDictionaryEntries"}, msdeResolveSource);
        !refused.is_good())
    {
      deliver<ua::VoidResult>(mState->executor, std::move(callback), ua::VoidResult{std::move(refused)});
      return;
    }
  }
  const auto table = snapshot ? extract_dictionary_entries(*snapshot) : std::optional<DictionaryEntries2D>{};
  if (!table)
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadNotFound,
        ua::make_error_detail("DataAccessDictionaryEntriesUnavailable",
          "the resolved EnumDictionaryEntries Property is absent or not a 2-D NodeId array",
          std::string{msdeResolveSource})});
    return;
  }
  if (stateIndex >= table->states || dictionaryIndex >= table->dictionaries)
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadOutOfRange,
        ua::make_error_detail("DataAccessDictionaryIndexOutOfRange",
          "the requested state/dictionary index is outside the resolved EnumDictionaryEntries bounds",
          std::string{msdeResolveSource})});
    return;
  }
  ua::NodeId selected = table->flat[stateIndex * table->dictionaries + dictionaryIndex];
  if (selected == ua::NodeId{})
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadNotFound,
        ua::make_error_detail("DataAccessDictionaryEntryNull",
          "the selected EnumDictionaryEntries NodeId is null",
          std::string{msdeResolveSource})});
    return;
  }
  // Resolve the ValueAsDictionaryEntries Property NodeId (a one-level HasProperty Browse of the Variable),
  // then Write the selected entry to it. Per Part 19 section 7.1 a Write of one EnumDictionaryEntries NodeId
  // to ValueAsDictionaryEntries has the same result as writing the Value attribute; the declared rank is 1,
  // so the entry is encoded as a single-element NodeId[]. The interface is held strong across the Browse; the
  // state is weak-captured and re-locked for the Write (UAF guard, section 9.8.3).
  auto executor = mState->executor;
  std::weak_ptr<detail::MultiStateValueDiscreteState> weak = mState;
  resolve_child_property_node(std::move(lockedWireOps),
    mState->nodeId,
    "ValueAsDictionaryEntries",
    std::string{msdeResolveSource},
    [weak, executor, selected = std::move(selected), callback = std::move(callback)](
      ua::Result<ua::NodeId> nodeResult) mutable
    {
      auto state = weak.lock();
      if (!state)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!nodeResult.is_good())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{nodeResult.status_code(), nodeResult.shared_detail()});
        return;
      }
      // Encode the selected entry as a single-element NodeId[] (declared ValueRank 1).
      ua::Array<ua::NodeId> entryArray;
      entryArray.push_back(std::move(selected));
      do_write_node_value(state,
        nodeResult.value(),
        ua::Variant{std::move(entryArray)},
        msdeResolveSource,
        std::move(callback));
    });
}

void MultiStateValueDiscreteHandle::refresh_properties_async(
  std::function<void(ua::VoidResult)> callback) noexcept
{
  do_refresh_properties(mState,
    {"EnumValues", "ValueAsText", "ValuePrecision", "Definition"},
    &apply_multi_state_value,
    std::move(callback));
}

ua::NodeId MultiStateValueDiscreteHandle::node_id() const noexcept
{
  return mState ? mState->nodeId : ua::NodeId{};
}

// ============================================================================
// Blocking wrappers
//
// One mechanical promise/future bridge per asynchronous operation, the same shape every other
// tier-2 facade uses (ua_sync_wait.h, blocking_call). The throwing form returns the value of a Good answer of
// `try_*_sync(...)` (ua::detail::good_value; a void form calls `.value()`), so there is exactly one place per
// operation where the wire call is armed.
//
// These block the calling thread on the completion, so they must not be called from the
// Connection's executor thread - the thread that would have run the completion is the one waiting
// for it. Every example that registers a callback says so where it registers it.
// ============================================================================

AnalogItemHandle DataAccessAccessor::analog_item_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_analog_item_sync(std::move(nodeId)));
}

ua::Result<AnalogItemHandle> DataAccessAccessor::try_analog_item_sync(ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<AnalogItemHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { analog_item_async(std::move(nodeId), std::move(completion)); });
}

AnalogItemHandle DataAccessAccessor::base_analog_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_base_analog_sync(std::move(nodeId)));
}

ua::Result<AnalogItemHandle> DataAccessAccessor::try_base_analog_sync(ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<AnalogItemHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { base_analog_async(std::move(nodeId), std::move(completion)); });
}

AnalogItemHandle DataAccessAccessor::analog_unit_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_analog_unit_sync(std::move(nodeId)));
}

ua::Result<AnalogItemHandle> DataAccessAccessor::try_analog_unit_sync(ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<AnalogItemHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { analog_unit_async(std::move(nodeId), std::move(completion)); });
}

AnalogItemHandle DataAccessAccessor::analog_unit_range_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_analog_unit_range_sync(std::move(nodeId)));
}

ua::Result<AnalogItemHandle> DataAccessAccessor::try_analog_unit_range_sync(ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<AnalogItemHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { analog_unit_range_async(std::move(nodeId), std::move(completion)); });
}

TwoStateDiscreteHandle DataAccessAccessor::two_state_discrete_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_two_state_discrete_sync(std::move(nodeId)));
}

ua::Result<TwoStateDiscreteHandle> DataAccessAccessor::try_two_state_discrete_sync(ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<TwoStateDiscreteHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { two_state_discrete_async(std::move(nodeId), std::move(completion)); });
}

MultiStateDiscreteHandle DataAccessAccessor::multi_state_discrete_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_multi_state_discrete_sync(std::move(nodeId)));
}

ua::Result<MultiStateDiscreteHandle> DataAccessAccessor::try_multi_state_discrete_sync(
  ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MultiStateDiscreteHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { multi_state_discrete_async(std::move(nodeId), std::move(completion)); });
}

MultiStateValueDiscreteHandle DataAccessAccessor::multi_state_value_discrete_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_multi_state_value_discrete_sync(std::move(nodeId)));
}

ua::Result<MultiStateValueDiscreteHandle> DataAccessAccessor::try_multi_state_value_discrete_sync(
  ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MultiStateValueDiscreteHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { multi_state_value_discrete_async(std::move(nodeId), std::move(completion)); });
}

MultiStateValueDiscreteHandle DataAccessAccessor::multi_state_dictionary_entry_sync(ua::NodeId nodeId)
{
  return ua::detail::good_value(try_multi_state_dictionary_entry_sync(std::move(nodeId)));
}

ua::Result<MultiStateValueDiscreteHandle> DataAccessAccessor::try_multi_state_dictionary_entry_sync(
  ua::NodeId nodeId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MultiStateValueDiscreteHandle>>(mExecutor,
    [this, nodeId = std::move(nodeId)](auto completion) mutable
    { multi_state_dictionary_entry_async(std::move(nodeId), std::move(completion)); });
}

AnalogItemValue AnalogItemHandle::read_sync()
{
  return ua::detail::good_value(try_read_sync());
}

ua::Result<AnalogItemValue> AnalogItemHandle::try_read_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<AnalogItemValue>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { read_async(std::move(completion)); });
}

void AnalogItemHandle::refresh_properties_sync()
{
  try_refresh_properties_sync().value();
}

ua::VoidResult AnalogItemHandle::try_refresh_properties_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { refresh_properties_async(std::move(completion)); });
}

void AnalogItemHandle::write_value_sync(ua::Variant newValue)
{
  try_write_value_sync(std::move(newValue)).value();
}

ua::VoidResult AnalogItemHandle::try_write_value_sync(ua::Variant newValue) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, newValue = std::move(newValue)](auto completion) mutable
    { write_value_async(std::move(newValue), std::move(completion)); });
}

TwoStateDiscreteValue TwoStateDiscreteHandle::read_sync()
{
  return ua::detail::good_value(try_read_sync());
}

ua::Result<TwoStateDiscreteValue> TwoStateDiscreteHandle::try_read_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<TwoStateDiscreteValue>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { read_async(std::move(completion)); });
}

void TwoStateDiscreteHandle::refresh_properties_sync()
{
  try_refresh_properties_sync().value();
}

ua::VoidResult TwoStateDiscreteHandle::try_refresh_properties_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { refresh_properties_async(std::move(completion)); });
}

void TwoStateDiscreteHandle::write_value_sync(ua::Variant newValue)
{
  try_write_value_sync(std::move(newValue)).value();
}

ua::VoidResult TwoStateDiscreteHandle::try_write_value_sync(ua::Variant newValue) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, newValue = std::move(newValue)](auto completion) mutable
    { write_value_async(std::move(newValue), std::move(completion)); });
}

MultiStateDiscreteValue MultiStateDiscreteHandle::read_sync()
{
  return ua::detail::good_value(try_read_sync());
}

ua::Result<MultiStateDiscreteValue> MultiStateDiscreteHandle::try_read_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MultiStateDiscreteValue>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { read_async(std::move(completion)); });
}

void MultiStateDiscreteHandle::refresh_properties_sync()
{
  try_refresh_properties_sync().value();
}

ua::VoidResult MultiStateDiscreteHandle::try_refresh_properties_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { refresh_properties_async(std::move(completion)); });
}

void MultiStateDiscreteHandle::write_value_sync(ua::Variant newValue)
{
  try_write_value_sync(std::move(newValue)).value();
}

ua::VoidResult MultiStateDiscreteHandle::try_write_value_sync(ua::Variant newValue) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, newValue = std::move(newValue)](auto completion) mutable
    { write_value_async(std::move(newValue), std::move(completion)); });
}

MultiStateValueDiscreteValue MultiStateValueDiscreteHandle::read_sync()
{
  return ua::detail::good_value(try_read_sync());
}

ua::Result<MultiStateValueDiscreteValue> MultiStateValueDiscreteHandle::try_read_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MultiStateValueDiscreteValue>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { read_async(std::move(completion)); });
}

void MultiStateValueDiscreteHandle::refresh_properties_sync()
{
  try_refresh_properties_sync().value();
}

ua::VoidResult MultiStateValueDiscreteHandle::try_refresh_properties_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { refresh_properties_async(std::move(completion)); });
}

void MultiStateValueDiscreteHandle::write_via_dictionary_sync(
  std::size_t stateIndex, std::size_t dictionaryIndex)
{
  try_write_via_dictionary_sync(stateIndex, dictionaryIndex).value();
}

ua::VoidResult MultiStateValueDiscreteHandle::try_write_via_dictionary_sync(
  std::size_t stateIndex, std::size_t dictionaryIndex) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, stateIndex, dictionaryIndex](auto completion) mutable
    { write_via_dictionary_async(stateIndex, dictionaryIndex, std::move(completion)); });
}

void MultiStateValueDiscreteHandle::write_via_dictionary_sync(std::size_t stateIndex)
{
  try_write_via_dictionary_sync(stateIndex).value();
}

ua::VoidResult MultiStateValueDiscreteHandle::try_write_via_dictionary_sync(std::size_t stateIndex) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, stateIndex](auto completion) mutable
    { write_via_dictionary_async(stateIndex, std::move(completion)); });
}

}  // namespace ua::client
