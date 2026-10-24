// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_ACCESS_H
#define UA_DATA_ACCESS_H

/// @file
/// @brief Tier-2 public `DataAccess` facade (client design section 8.18.1.a): the per-`Connection` accessor
/// for the
///        OPC-UA Data Access variable types (Part 8)  -  `AnalogItemType`, `TwoStateDiscreteType`,
///        `MultiStateDiscreteType`, `MultiStateValueDiscreteType`. Each typed factory performs the
///        address-space Property pre-flight (Browse `HasProperty` + Read each Property Value) and yields a
///        cheap, copyable value handle that combines the Variable's typed Value with its resolved DA
///        Properties. Returned by `Connection::data_access()`.
/// @ingroup client

#include "ua_data_change_filter.h"
#include "ua_data_value.h"
#include "ua_enum_value_type.h"
#include "ua_eu_information.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_range.h"
#include "ua_result.h"
#include "ua_variant.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::client
{

namespace detail
{
class WireOps;
class SupportOps;
struct AnalogItemState;
struct TwoStateDiscreteState;
struct MultiStateDiscreteState;
struct MultiStateValueDiscreteState;
struct DataAccessClientTestAccess;
}  // namespace detail

class Connection;
class DataAccessAccessor;

// ============================================================================
// 8.18.1.a Typed value structs
// ============================================================================

/// The base fields shared by every DA typed value (client design section 8.18.1.a). @ref value carries the
/// decoded Variable Value Attribute plus its quality StatusCode verbatim (CL-DA-015  -  DA StatusCodes are
/// never remapped by the typed accessor).
/// @ingroup client
struct DataItemValue
{
  ua::DataValue value;  ///< CL-DA-001  -  typed Value + quality StatusCode (surfaced verbatim, CL-DA-015)
  std::optional<std::string> definition;  ///< CL-DA-017  -  vendor-opaque pass-through (never parsed)
  std::optional<std::int16_t> valuePrecision;  ///< CL-DA-002  -  informational rounding bound (not applied)
};

/// `AnalogItemType` typed value (client design section 8.18.1.a). @ref euRange is Mandatory on the type;
/// @ref instrumentRange (CL-DA-016) and @ref engineeringUnits (CL-DA-014) are Optional and left `nullopt`
/// when absent.
/// @ingroup client
struct AnalogItemValue : DataItemValue
{
  std::optional<ua::Range> euRange;  ///< CL-DA-001  -  Mandatory; typical operating range
  std::optional<ua::Range>
    instrumentRange;  ///< CL-DA-016  -  distinct from euRange; physical instrument bounds
  std::optional<ua::EUInformation>
    engineeringUnits;  ///< CL-DA-014  -  decoded EUInformation (units not translated)
};

/// `TwoStateDiscreteType` typed value (client design section 8.18.1.a). @ref trueState / @ref falseState are
/// the Mandatory display texts for the two boolean states.
/// @ingroup client
struct TwoStateDiscreteValue : DataItemValue
{
  bool state = false;  ///< the decoded boolean Value
  ua::LocalizedText trueState;  ///< display text for the `true` state (Mandatory Property)
  ua::LocalizedText falseState;  ///< display text for the `false` state (Mandatory Property)
};

/// `MultiStateDiscreteType` typed value (client design section 8.18.1.a). @ref currentName is `nullopt` when
/// @ref rawIndex is outside the resolved @ref enumStrings range (CL-DA-008); @ref rawIndex is always
/// surfaced.
/// @ingroup client
struct MultiStateDiscreteValue : DataItemValue
{
  std::uint32_t rawIndex = 0;  ///< the decoded UInteger Value (always surfaced)
  std::vector<ua::LocalizedText>
    enumStrings;  ///< the Mandatory EnumStrings Property (scalar array, CL-DA-009)
  std::optional<ua::LocalizedText>
    currentName;  ///< CL-DA-008  -  nullopt when rawIndex >= enumStrings.size()
};

/// `MultiStateValueDiscreteType` typed value (client design section 8.18.1.a). @ref currentName is `nullopt`
/// when
/// @ref rawValue matches no @ref enumValues entry (CL-DA-008); @ref rawValue is always surfaced.
/// @ingroup client
struct MultiStateValueDiscreteValue : DataItemValue
{
  std::int64_t rawValue = 0;  ///< the decoded Number Value (always surfaced)
  std::vector<ua::EnumValueType> enumValues;  ///< the Mandatory EnumValues Property (value + display text)
  std::optional<ua::LocalizedText> currentName;  ///< CL-DA-008  -  nullopt when rawValue matches no entry
};

/// Callback invoked for analog item value result notifications.
using AnalogItemValueResult = ua::Result<AnalogItemValue>;
/// Callback invoked for two state discrete value result notifications.
using TwoStateDiscreteValueResult = ua::Result<TwoStateDiscreteValue>;
/// Callback invoked for multi state discrete value result notifications.
using MultiStateDiscreteValueResult = ua::Result<MultiStateDiscreteValue>;
/// Callback invoked for multi state value discrete value result notifications.
using MultiStateValueDiscreteValueResult = ua::Result<MultiStateValueDiscreteValue>;

// ============================================================================
// 8.18.1.a Typed handles
// ============================================================================

/// A copyable value handle to an `AnalogItemType` Variable (client design section 8.18.1.a). Built async by
/// @ref DataAccessAccessor::analog_item_async after the DA Property pre-flight; copies share the resolved
/// Property snapshot. The handle binds to its originating Connection's wire interface by a `weak_ptr` (never
/// a `weak_ptr<ConnectionImpl>`, section 8.2A.13): every op locks it and completes `Bad_ConnectionClosed` if
/// the Connection is gone. Not strand-serialized: each op posts through the tier-1 wire interface (which
/// serializes on the Connection strand internally) and delivers its completion on the Connection executor.
/// @ingroup client
class AnalogItemHandle
{
public:
  /// Constructs an invalid sentinel handle (every op fast-fails `Bad_InvalidState`).
  AnalogItemHandle() = default;

  /// Reads the Variable's Value Attribute and combines it with the cached DA Properties into a typed
  /// @param callback Completion callback that receives the operation result.
  /// @ref AnalogItemValue. The DA quality StatusCode is surfaced verbatim in `value.value.status()`
  /// (CL-DA-015). The Result carries the Read's ServiceResult and the code of the resolved Properties
  /// combined, so a Good subcode or an Uncertain Optional Property is kept (see @ref DataAccessAccessor).
  void read_async(std::function<void(AnalogItemValueResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously read. Blocks until the operation completes. A Good subcode on the answer is not returned;
  /// try_read_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  AnalogItemValue read_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read sync without throwing.
  ua::Result<AnalogItemValue> try_read_sync() noexcept;

  /// @param newValue The new value.
  /// @param callback Completion callback that receives the operation result.
  /// Writes @p newValue to the Variable's Value Attribute (CL-DA-007). A thin passthrough  -  the server's
  /// accept / reject / clamp behaviour is server-defined and surfaced verbatim (chained beneath the write
  /// source tag on a Bad response): the write's status and the ServiceResult are combined, so Good_Clamped or
  /// another Good subcode, or an Uncertain code, is the Result's status.
  void write_value_async(ua::Variant newValue, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param newValue The value to write.
  /// Synchronously write value. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void write_value_sync(ua::Variant newValue);
  /// @param newValue The value to write.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write value sync without throwing.
  ua::VoidResult try_write_value_sync(ua::Variant newValue) noexcept;

  /// Explicitly re-resolves the DA Properties (the MANUAL refresh path), alongside the automatic
  /// SemanticChange invalidation now wired via the in-band `SemanticsChanged` status bit (CL-DA-010) and the
  /// @param callback Completion callback that receives the operation result.
  /// `SemanticChangeEventType` event path (CL-DA-011). Atomically replaces the cached snapshot shared by
  /// every copy of this handle.
  void refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously refresh properties. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void refresh_properties_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to refresh properties sync without throwing.
  ua::VoidResult try_refresh_properties_sync() noexcept;

  /// @param percent The percent.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Builds a `PercentDeadband`-typed @ref ua::DataChangeFilter (CL-DA-003..006). @p percent outside
  /// `[0, 100]`  to  `Bad_DeadbandFilterInvalid` (CL-DA-004); a resolved EURange absent  to
  /// `Bad_FilterNotAllowed` (CL-DA-005); an EURange the server answered Uncertain  to  `Bad_InternalError`
  /// (`ReadAnswerUncertain`). The SDK does NOT compute an absolute band locally  -  the wire
  /// carries `PercentDeadband` and the server is the authoritative computer; EURange presence is a
  /// precondition only. For an array Variable the same single filter is used (CL-DA-006).
  [[nodiscard]] ua::Result<ua::DataChangeFilter> make_percent_deadband_filter(double percent) const noexcept;

  /// @return The Variable NodeId this handle targets (empty NodeId when the handle is a sentinel).
  [[nodiscard]] ua::NodeId node_id() const noexcept;

private:
  friend class DataAccessAccessor;
  friend struct ua::client::detail::DataAccessClientTestAccess;

  explicit AnalogItemHandle(std::shared_ptr<detail::AnalogItemState> state) : mState(std::move(state))
  {}

  std::shared_ptr<detail::AnalogItemState> mState;
};

/// A copyable value handle to a `TwoStateDiscreteType` Variable (client design section 8.18.1.a). See
/// @ref AnalogItemHandle for the shared lifetime / interface-locking contract.
/// @ingroup client
class TwoStateDiscreteHandle
{
public:
  TwoStateDiscreteHandle() = default;

  /// @param callback Completion callback that receives the operation result.
  /// Reads the Variable's Value Attribute and combines it with the cached DA Properties. The Value's status
  /// is on `value.value.status()`; the Result carries the Read's ServiceResult and the code of the resolved
  /// Properties combined (see @ref DataAccessAccessor). A Bad Value, or an Uncertain one without a value, is
  /// not decoded.
  void read_async(std::function<void(TwoStateDiscreteValueResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously read. Blocks until the operation completes. A Good subcode on the answer is not returned;
  /// try_read_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  TwoStateDiscreteValue read_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read sync without throwing.
  ua::Result<TwoStateDiscreteValue> try_read_sync() noexcept;
  /// @param newValue The new value.
  /// @param callback Completion callback that receives the operation result.
  /// Writes @p newValue to the Variable's Value Attribute (CL-DA-007); the write's status and the
  /// ServiceResult are combined, so a Good subcode such as Good_Clamped, or an Uncertain code, is the
  /// Result's status.
  void write_value_async(ua::Variant newValue, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param newValue The value to write.
  /// Synchronously write value. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void write_value_sync(ua::Variant newValue);
  /// @param newValue The value to write.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write value sync without throwing.
  ua::VoidResult try_write_value_sync(ua::Variant newValue) noexcept;
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously refresh properties.
  void refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously refresh properties. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void refresh_properties_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to refresh properties sync without throwing.
  ua::VoidResult try_refresh_properties_sync() noexcept;
  /// @return The requested value.
  /// Returns or updates the node id.
  [[nodiscard]] ua::NodeId node_id() const noexcept;

private:
  friend class DataAccessAccessor;
  friend struct ua::client::detail::DataAccessClientTestAccess;

  explicit TwoStateDiscreteHandle(std::shared_ptr<detail::TwoStateDiscreteState> state)
    : mState(std::move(state))
  {}

  std::shared_ptr<detail::TwoStateDiscreteState> mState;
};

/// A copyable value handle to a `MultiStateDiscreteType` Variable (client design section 8.18.1.a). See
/// @ref AnalogItemHandle for the shared lifetime / interface-locking contract.
/// @ingroup client
class MultiStateDiscreteHandle
{
public:
  MultiStateDiscreteHandle() = default;

  /// @param callback Completion callback that receives the operation result.
  /// Reads the Variable's Value Attribute and combines it with the cached DA Properties. The Value's status
  /// is on `value.value.status()`; the Result carries the Read's ServiceResult and the code of the resolved
  /// Properties combined (see @ref DataAccessAccessor). A Bad Value, or an Uncertain one without a value, is
  /// not decoded.
  void read_async(std::function<void(MultiStateDiscreteValueResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously read. Blocks until the operation completes. A Good subcode on the answer is not returned;
  /// try_read_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  MultiStateDiscreteValue read_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read sync without throwing.
  ua::Result<MultiStateDiscreteValue> try_read_sync() noexcept;
  /// @param newValue The new value.
  /// @param callback Completion callback that receives the operation result.
  /// Writes @p newValue to the Variable's Value Attribute (CL-DA-007); the write's status and the
  /// ServiceResult are combined, so a Good subcode such as Good_Clamped, or an Uncertain code, is the
  /// Result's status.
  void write_value_async(ua::Variant newValue, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param newValue The value to write.
  /// Synchronously write value. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void write_value_sync(ua::Variant newValue);
  /// @param newValue The value to write.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write value sync without throwing.
  ua::VoidResult try_write_value_sync(ua::Variant newValue) noexcept;
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously refresh properties.
  void refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously refresh properties. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void refresh_properties_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to refresh properties sync without throwing.
  ua::VoidResult try_refresh_properties_sync() noexcept;
  /// @return The requested value.
  /// Returns or updates the node id.
  [[nodiscard]] ua::NodeId node_id() const noexcept;

private:
  friend class DataAccessAccessor;
  friend struct ua::client::detail::DataAccessClientTestAccess;

  explicit MultiStateDiscreteHandle(std::shared_ptr<detail::MultiStateDiscreteState> state)
    : mState(std::move(state))
  {}

  std::shared_ptr<detail::MultiStateDiscreteState> mState;
};

/// A copyable value handle to a `MultiStateValueDiscreteType` Variable (client design section 8.18.1.a). When
/// the resolved node is a `MultiStateDictionaryEntryDiscreteBaseType` (OPC 10000-19 section 7.1) it
/// additionally exposes
/// @ref write_via_dictionary_async (CL-DA-012), which selects a state from the cached `EnumDictionaryEntries`
/// reference table and writes it through the `ValueAsDictionaryEntries` Property. See @ref AnalogItemHandle
/// for the shared lifetime / interface-locking contract.
/// @ingroup client
class MultiStateValueDiscreteHandle
{
public:
  MultiStateValueDiscreteHandle() = default;

  /// @param callback Completion callback that receives the operation result.
  /// Reads the Variable's Value Attribute and combines it with the cached DA Properties. The Value's status
  /// is on `value.value.status()`; the Result carries the Read's ServiceResult and the code of the resolved
  /// Properties combined (see @ref DataAccessAccessor). A Bad Value, or an Uncertain one without a value, is
  /// not decoded.
  void read_async(std::function<void(MultiStateValueDiscreteValueResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously read. Blocks until the operation completes. A Good subcode on the answer is not returned;
  /// try_read_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  MultiStateValueDiscreteValue read_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read sync without throwing.
  ua::Result<MultiStateValueDiscreteValue> try_read_sync() noexcept;

  /// CL-DA-012  -  writes one state via the `MultiStateDictionaryEntryDiscreteBaseType` dictionary path
  /// (OPC 10000-19 section 7.1). Selects `EnumDictionaryEntries[@p stateIndex][@p dictionaryIndex]`  -
  /// dimension 0 is the state (enum-value) index, dimension 1 is the dictionary (CDD, eCl\@ss, ...) index  -
  /// from the cached 2-D reference table, then Writes that single NodeId (as a one-element `NodeId[]`) to the
  /// resolved `ValueAsDictionaryEntries` Property node's Value attribute. Because all columns of a state's
  /// row identify the SAME state, the dictionary column merely picks which representation is transmitted; per
  /// the spec such a write "has the same result as writing the Value attribute". A missing/undecodable table
  /// or an out-of-range index is rejected LOCALLY (`Bad`, source
  /// `client.tier2.data_access.write_via_dictionary`) with ZERO wire requests; the server's per-write status
  /// is otherwise surfaced verbatim under that source, combined with the ServiceResult (a Good subcode or an
  /// Uncertain code kept). An `EnumDictionaryEntries` the server answered Uncertain is refused with
  /// `Bad_InternalError` (`ReadAnswerUncertain`) before any write.
  /// @param stateIndex Row in the cached state dictionary.
  /// @param dictionaryIndex Dictionary representation column.
  /// @param callback Completion callback receiving the write result.
  void write_via_dictionary_async(std::size_t stateIndex, std::size_t dictionaryIndex,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param stateIndex The state index.
  /// @param dictionaryIndex Dictionary representation column.
  /// Synchronously write via dictionary. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void write_via_dictionary_sync(std::size_t stateIndex, std::size_t dictionaryIndex);
  /// @param stateIndex The state index.
  /// @param dictionaryIndex Dictionary representation column.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write via dictionary sync without throwing.
  ua::VoidResult try_write_via_dictionary_sync(std::size_t stateIndex, std::size_t dictionaryIndex) noexcept;

  /// @param stateIndex The state index.
  /// @param callback Completion callback that receives the operation result.
  /// CL-DA-012 convenience overload  -  forwards to the two-index form with `dictionary_index = 0`. All
  /// dictionary columns of a state's row identify the same state, so column 0 is a safe default.
  void write_via_dictionary_async(
    std::size_t stateIndex, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param stateIndex The state index.
  /// Synchronously write via dictionary. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void write_via_dictionary_sync(std::size_t stateIndex);
  /// @param stateIndex The state index.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write via dictionary sync without throwing.
  ua::VoidResult try_write_via_dictionary_sync(std::size_t stateIndex) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously refresh properties.
  void refresh_properties_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously refresh properties. Blocks until the operation completes.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void refresh_properties_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to refresh properties sync without throwing.
  ua::VoidResult try_refresh_properties_sync() noexcept;
  /// @return The requested value.
  /// Returns or updates the node id.
  [[nodiscard]] ua::NodeId node_id() const noexcept;

private:
  friend class DataAccessAccessor;
  friend struct ua::client::detail::DataAccessClientTestAccess;

  explicit MultiStateValueDiscreteHandle(std::shared_ptr<detail::MultiStateValueDiscreteState> state)
    : mState(std::move(state))
  {}

  std::shared_ptr<detail::MultiStateValueDiscreteState> mState;
};

/// Callback invoked for analog item handle result notifications.
using AnalogItemHandleResult = ua::Result<AnalogItemHandle>;
/// Callback invoked for two state discrete handle result notifications.
using TwoStateDiscreteHandleResult = ua::Result<TwoStateDiscreteHandle>;
/// Callback invoked for multi state discrete handle result notifications.
using MultiStateDiscreteHandleResult = ua::Result<MultiStateDiscreteHandle>;
/// Callback invoked for multi state value discrete handle result notifications.
using MultiStateValueDiscreteHandleResult = ua::Result<MultiStateValueDiscreteHandle>;

// ============================================================================
// 8.18.1.a DataAccessAccessor
// ============================================================================

/// The per-`Connection` tier-2 factory for the DA typed handles (client design section 8.18.1.a). A
/// lightweight, copyable value handle over the same tier-1 wire interface as its parent @ref Connection,
/// reached via `Connection::data_access()`. Each factory performs the address-space pre-flight (Browse for
/// the Variable's `HasProperty` children + one batched Read of the matched Property Values) then yields a
/// fully-populated typed handle. A Mandatory Property missing  to  `Bad` with source
/// `client.tier2.data_access.property_resolution_failed` (CL-DA-001).
///
/// **Status codes.** The handle decides from its Mandatory Properties and from the Browse and Read that
/// resolve them, so it uses only a Good answer: an Uncertain answer to that Browse or Read, or an Uncertain
/// Mandatory Property, refuses the handle with Bad_InternalError (`ReferencesAnswerUncertain` /
/// `ReadAnswerUncertain`). A typed read's Result carries the Read's ServiceResult and the code of the
/// resolved Properties it decodes combined (`ua::detail::combined_status`), so a Good subcode or an
/// Uncertain Optional Property reaches the caller; a Property answered Bad, or Uncertain without a value, is
/// left unset. A write's Result carries the write's status and the ServiceResult combined, so Good_Clamped or
/// Good_CompletesAsynchronously is kept. Each `*_sync` form throws unless the Result is Good; a Good subcode
/// on the answer is not returned by it, the `try_*_sync` form returns it.
///
/// **Cycle-safe (section 9.8.3).** The accessor and every handle hold only `weak_ptr` interface roles
/// (`detail::WireOps` + `detail::SupportOps`), never a `weak_ptr<ConnectionImpl>`: a Phase-2 fake need
/// only implement the two roles (section 8.2A.13). Locks are taken per op and bailed if gone.
/// @ingroup client
class DataAccessAccessor
{
public:
  /// Returns or updates the data access accessor.
  DataAccessAccessor(const DataAccessAccessor&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  DataAccessAccessor& operator=(const DataAccessAccessor&) = default;
  /// Returns or updates the data access accessor.
  DataAccessAccessor(DataAccessAccessor&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  DataAccessAccessor& operator=(DataAccessAccessor&&) noexcept = default;
  ~DataAccessAccessor() = default;

  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously analog item.
  void analog_item_async(ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously analog item. Blocks until the operation completes. A Good subcode on the answer is not
  /// returned; try_analog_item_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  AnalogItemHandle analog_item_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to analog item sync without throwing.
  ua::Result<AnalogItemHandle> try_analog_item_sync(ua::NodeId nodeId) noexcept;
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Resolves a @ref AnalogItemHandle for a `BaseAnalogType` Variable (CL-DA-001). BaseAnalogType has no
  /// Mandatory Property (EURange / EngineeringUnits / InstrumentRange are all Optional on the base type), so
  /// unlike @ref analog_item_async this succeeds even when the node exposes none of them.
  void base_analog_async(ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously base analog. Blocks until the operation completes. A Good subcode on the answer is not
  /// returned; try_base_analog_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  AnalogItemHandle base_analog_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to base analog sync without throwing.
  ua::Result<AnalogItemHandle> try_base_analog_sync(ua::NodeId nodeId) noexcept;
  /// Resolves a @ref AnalogItemHandle for an `AnalogUnitType` Variable (CL-DA-001, OPC 10000-8
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// section 5.3.2.4). AnalogUnitType derives from BaseAnalogType and mandates ONLY EngineeringUnits  -
  /// EURange is Optional here (contrast @ref analog_item_async / @ref analog_unit_range_async, which require
  /// EURange).
  void analog_unit_async(ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously analog unit. Blocks until the operation completes. A Good subcode on the answer is not
  /// returned; try_analog_unit_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  AnalogItemHandle analog_unit_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to analog unit sync without throwing.
  ua::Result<AnalogItemHandle> try_analog_unit_sync(ua::NodeId nodeId) noexcept;
  /// Resolves a @ref AnalogItemHandle for an `AnalogUnitRangeType` Variable (CL-DA-001, OPC 10000-8
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// section 5.3.2.5). Derives from AnalogItemType and additionally mandates EngineeringUnits, so BOTH
  /// EURange and EngineeringUnits must resolve.
  void analog_unit_range_async(
    ua::NodeId nodeId, std::function<void(AnalogItemHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously analog unit range. Blocks until the operation completes. A Good subcode on the answer is
  /// not returned; try_analog_unit_range_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  AnalogItemHandle analog_unit_range_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to analog unit range sync without throwing.
  ua::Result<AnalogItemHandle> try_analog_unit_range_sync(ua::NodeId nodeId) noexcept;
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously two state discrete.
  void two_state_discrete_async(
    ua::NodeId nodeId, std::function<void(TwoStateDiscreteHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously two state discrete. Blocks until the operation completes. A Good subcode on the answer is
  /// not returned; try_two_state_discrete_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  TwoStateDiscreteHandle two_state_discrete_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to two state discrete sync without throwing.
  ua::Result<TwoStateDiscreteHandle> try_two_state_discrete_sync(ua::NodeId nodeId) noexcept;
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously multi state discrete.
  void multi_state_discrete_async(
    ua::NodeId nodeId, std::function<void(MultiStateDiscreteHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously multi state discrete. Blocks until the operation completes. A Good subcode on the answer
  /// is not returned; try_multi_state_discrete_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  MultiStateDiscreteHandle multi_state_discrete_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to multi state discrete sync without throwing.
  ua::Result<MultiStateDiscreteHandle> try_multi_state_discrete_sync(ua::NodeId nodeId) noexcept;
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously multi state value discrete.
  void multi_state_value_discrete_async(
    ua::NodeId nodeId, std::function<void(MultiStateValueDiscreteHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously multi state value discrete. Blocks until the operation completes. A Good subcode on the
  /// answer is not returned; try_multi_state_value_discrete_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  MultiStateValueDiscreteHandle multi_state_value_discrete_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to multi state value discrete sync without throwing.
  ua::Result<MultiStateValueDiscreteHandle> try_multi_state_value_discrete_sync(ua::NodeId nodeId) noexcept;
  /// Resolves a @ref MultiStateValueDiscreteHandle for a `MultiStateDictionaryEntryDiscreteBaseType` Variable
  /// @param nodeId Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// (CL-DA-001, OPC 10000-19 section 7.1). MSDE-DBT is a `MultiStateValueDiscreteType` subtype that
  /// additionally mandates `EnumDictionaryEntries`, so unlike @ref multi_state_value_discrete_async this
  /// rejects a node lacking that Property (in addition to the inherited Mandatory `EnumValues`).
  void multi_state_dictionary_entry_async(
    ua::NodeId nodeId, std::function<void(MultiStateValueDiscreteHandleResult)> callback) noexcept;
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Synchronously multi state dictionary entry. Blocks until the operation completes. A Good subcode on the
  /// answer is not returned; try_multi_state_dictionary_entry_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail on failure.
  MultiStateValueDiscreteHandle multi_state_dictionary_entry_sync(ua::NodeId nodeId);
  /// @param nodeId Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to multi state dictionary entry sync without throwing.
  ua::Result<MultiStateValueDiscreteHandle> try_multi_state_dictionary_entry_sync(ua::NodeId nodeId) noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::DataAccessClientTestAccess;

  DataAccessAccessor(std::weak_ptr<detail::WireOps> wireOps, std::weak_ptr<detail::SupportOps> supportOps,
    boost::asio::any_io_executor executor, ua::Logger logger = {});

  std::weak_ptr<detail::WireOps>
    mWireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  std::weak_ptr<detail::SupportOps>
    mSupportOps;  ///< upward support interface (section 8.2A.13); locked per op
  boost::asio::any_io_executor mExecutor;  ///< where handles / boundary failures are delivered
  ua::Logger mLogger;  ///< logs advisory outcomes at the wire boundary (CL-DIAG-002/-015)
};

}  // namespace ua::client

#endif  // UA_DATA_ACCESS_H
