// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 public @ref ua::client::AlarmConditionTracker value handle + the per-condition
///        @ref ua::client::AlarmHandle (client design section 8.8). The tracker is the per-`Connection`
///        consumer of every Condition / Alarm event delivered by @ref ua::client::EventSubscriber
///        (section 8.13): it maintains the `(ConditionId, BranchId)  to  TrackedCondition` map, drives the
///        `ConditionRefresh` demultiplexer (collect-until-`RefreshEnd`; re-entrant refresh  to
///        `Bad_RefreshInProgress`), and exposes the typed method wrappers (acknowledge / confirm /
///        add-comment / enable / disable / shelve / ...).
///
/// The strand-bearing logic lives in the PRIVATE `ua::client::detail::AlarmConditionTrackerImpl`  -  a
/// NO-OWN-STRAND 1:1 sub-object of `ua::client::detail::EventSubscriberImpl` (constructed by + co-owned
/// with it, running on ITS strand per section 1.3 / section 9.8 / section 12-S2). This handle forwards its
/// consumer surface one-hop to that co-owned Impl.
/// @ingroup client

#ifndef UA_ALARM_CONDITION_TRACKER_H
#define UA_ALARM_CONDITION_TRACKER_H

#include "ua_audio_data_type.h"
#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_duration.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_variant.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace ua::client
{

namespace detail
{
class AlarmConditionTrackerImpl;
class EventSubscriberImpl;
struct AlarmConditionTrackerHandleFactory;
struct AlarmMetricsViewFactory;
}  // namespace detail

/// Per-Connection knobs for the tracker (section 8.8.1).
/// @ingroup client
struct AlarmConditionTrackerPolicy
{
  /// The prefer condition refresh2.
  bool preferConditionRefresh2 = false;
  /// The method cache capacity.
  std::size_t methodCacheCapacity = 32;
  /// The max time shelved cache capacity.
  std::size_t maxTimeShelvedCacheCapacity = 256;
  /// The refresh on redundancy switch.
  bool refreshOnRedundancySwitch = true;
};

/// A tracked condition/branch key: trunk (`branchId` empty == NULL) and prior-state branches are INDEPENDENT
/// entries (CL-AC-002).
/// @ingroup client
struct TrackedKey
{
  /// The condition id.
  ua::NodeId conditionId;
  /// The ConditionBranch this entry tracks; a NULL NodeId is the trunk (the condition's current
  /// state). OPC 10000-9 defines BranchId as a **NodeId** Property, Mandatory on ConditionType.
  ///
  /// This was a `ByteString`. The decode asked `to<ByteString>()`, which failed on every event from
  /// every server, and the `is_good()` guard skipped the assignment - leaving the field empty, which
  /// this type documents as "trunk". So every branch collapsed onto the trunk row and overwrote it,
  /// and prior-state branches never appeared at all. Branch support is optional for servers, so
  /// nothing looked wrong.
  ua::NodeId branchId;  ///< null == NULL BranchId == trunk
  /// @return True when the requested condition is satisfied.
  /// Supports value-handle comparison or assignment.
  bool operator==(const TrackedKey&) const = default;
};

/// A `TwoStateVariableType` sub-state value (CL-AC-016). `id == true` means the "true" state is current.
/// @ingroup client
struct TwoStateValue
{
  /// The id.
  std::optional<bool> id;
  /// The transition time.
  std::optional<ua::DateTime> transitionTime;
  /// The effective display name.
  std::optional<ua::LocalizedText> effectiveDisplayName;
};

/// Marker payload for DiscreteAlarmType itself, which adds no properties beyond AlarmConditionType
/// (CL-AC-021).
/// @ingroup client
struct DiscreteAlarmInfo
{};

/// OffNormalAlarmType-family payload (also Trip, SystemOffNormal, and CertificateExpiration). The property
/// is mandatory in a conforming event model; optionality preserves the distinction when a malformed or
/// incomplete server event omitted it (CL-AC-021).
/// @ingroup client
struct OffNormalAlarmInfo
{
  /// The normal state.
  std::optional<ua::NodeId> normalState;
};

/// DiscrepancyAlarmType payload. TargetValueNode and ExpectedTime are mandatory server properties;
/// Tolerance is optional. Optional members preserve wire absence/malformed-type information (CL-AC-021).
/// @ingroup client
struct DiscrepancyAlarmInfo
{
  /// The target value node.
  std::optional<ua::NodeId> targetValueNode;
  /// The expected time.
  std::optional<ua::Duration> expectedTime;
  /// The tolerance.
  std::optional<double> tolerance;
};

/// Callback invoked for alarm subtype info notifications.
using AlarmSubtypeInfo =
  std::variant<std::monostate, DiscreteAlarmInfo, OffNormalAlarmInfo, DiscrepancyAlarmInfo>;

/// Public alarm rate metric API.
/// @ingroup client
struct AlarmRateMetric
{
  /// The value.
  double value = 0.0;
  /// The rate minutes.
  std::uint16_t rateMinutes = 0;
};

/// Public alarm metrics snapshot API.
/// @ingroup client
struct AlarmMetricsSnapshot
{
  /// The alarm count.
  std::uint32_t alarmCount = 0;
  /// The start time.
  ua::DateTime startTime;
  /// The maximum active state.
  ua::Duration maximumActiveState = 0.0;
  /// The maximum un ack.
  ua::Duration maximumUnAck = 0.0;
  /// The current alarm rate.
  AlarmRateMetric currentAlarmRate;
  /// The maximum alarm rate.
  AlarmRateMetric maximumAlarmRate;
  /// The maximum re alarm count.
  std::uint32_t maximumReAlarmCount = 0;
  /// The average alarm rate.
  AlarmRateMetric averageAlarmRate;
};

/// Public alarm metrics view API.
///
/// **Status codes.** read_all's Result carries the Read's ServiceResult and every metric value's status
/// combined (`ua::detail::combined_status`), so a Good subcode or an Uncertain code the server answers
/// reaches the caller with the snapshot; a Bad value fails the read, and a value that is not Good and carries
/// no value is answered with the code and no snapshot. reset's Result is the Reset Call's ServiceResult and
/// statusCode combined. The AlarmMetrics browse paths the view resolves first are used only when the server
/// answers them Good: an Uncertain answer is refused with `Bad_InternalError` (`ReferencesAnswerUncertain`).
/// @ingroup client
class AlarmMetricsView
{
public:
  AlarmMetricsView() = default;

  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously read all.
  void read_all_async(std::function<void(ua::Result<AlarmMetricsSnapshot>)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously read all. A Good subcode on the answer is not returned; try_read_all_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  [[nodiscard]] AlarmMetricsSnapshot read_all_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read all sync without throwing.
  [[nodiscard]] ua::Result<AlarmMetricsSnapshot> try_read_all_sync() noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously reset.
  void reset_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously reset.
  void reset_sync();
  /// @return The requested value.
  /// Attempts to reset sync without throwing.
  [[nodiscard]] ua::VoidResult try_reset_sync() noexcept;

private:
  friend class AlarmConditionTracker;
  friend struct detail::AlarmMetricsViewFactory;

  AlarmMetricsView(std::weak_ptr<detail::AlarmConditionTrackerImpl> tracker, ua::NodeId metricsObject)
    : mTracker(std::move(tracker)), mMetricsObject(std::move(metricsObject))
  {}

  std::weak_ptr<detail::AlarmConditionTrackerImpl> mTracker;
  ua::NodeId mMetricsObject;
};

/// The tracked state of one condition/branch (section 8.8).
/// @ingroup client
struct TrackedCondition
{
  /// The key.
  TrackedKey key;
  ua::NodeId conditionTypeId;  ///< most-derived EventType
  /// The condition name.
  ua::LocalizedText conditionName;
  ua::NodeId conditionClassId;  ///< mandatory ConditionType class identifier (CL-AC-014)
  ua::LocalizedText conditionClassName;  ///< mandatory human-readable class name (CL-AC-014)
  ua::ByteString lastEventId;  ///< CL-AC-019  -  updated on every inbound event for the key

  /// The severity.
  std::uint16_t severity = 0;
  /// The message.
  ua::LocalizedText message;
  /// The time.
  ua::DateTime time;
  ua::DateTime receiveTime;  ///< CL-AC-005 ordering source
  /// The source node.
  ua::NodeId sourceNode;
  /// The source name.
  ua::String sourceName;

  bool retain = true;  ///< CL-AC-006  -  false  to  removed
  /// The comment.
  std::optional<ua::LocalizedText> comment;

  /// The enabled state.
  TwoStateValue enabledState;
  /// The acked state.
  std::optional<TwoStateValue> ackedState;
  /// The confirmed state.
  std::optional<TwoStateValue> confirmedState;
  /// The active state.
  std::optional<TwoStateValue> activeState;

  /// Typed payload selected from the exact EventType for Discrete/OffNormal/Discrepancy families
  /// (CL-AC-021). `monostate` means the EventType is outside this subtype cluster.
  AlarmSubtypeInfo subtypeInfo;

  // ---- Optional AlarmConditionType sub-states (CL-AC-016) ----
  // The remaining sub-state vector declared on AlarmConditionType: each `TwoStateVariableType` Boolean is
  // carried at the two-segment path `[<State>, "Id"]`, `SuppressedOrShelved` is a plain aggregate Boolean at
  // the single-segment leaf, and `ShelvingState.CurrentState` is the ShelvedStateMachine's current state name
  // (a StateVariable's `LocalizedText` Value) at `["ShelvingState", "CurrentState"]`. Each is present only
  // when the event carried that (server-optional) field  -  absent  to  nullopt, distinct from a present
  // `false` so a consumer can tell "not supported" from "not set".
  /// The suppressed state.
  std::optional<TwoStateValue> suppressedState;
  /// The out of service state.
  std::optional<TwoStateValue> outOfServiceState;
  /// The silence state.
  std::optional<TwoStateValue> silenceState;
  /// The latched state.
  std::optional<TwoStateValue> latchedState;
  /// The suppressed or shelved.
  std::optional<bool> suppressedOrShelved;
  std::optional<ua::LocalizedText> shelvingState;  ///< ShelvingState.CurrentState (surfaced only)

  // ---- Optional AlarmConditionType properties (CL-AC-022) ----
  // These are selected into every condition event so event-reported mutations flow through
  // `condition_changed`. Plain PropertyType values are not guaranteed to generate events; consumers can use
  // the explicit property-read fallback for a current value.
  /// The re alarm time.
  std::optional<ua::Duration> reAlarmTime;
  /// The re alarm repeat count.
  std::optional<std::int16_t> reAlarmRepeatCount;
  /// The on delay.
  std::optional<ua::Duration> onDelay;
  /// The off delay.
  std::optional<ua::Duration> offDelay;
  /// The audible enabled.
  std::optional<bool> audibleEnabled;
  /// The audible sound.
  std::optional<ua::AudioDataType> audibleSound;
  /// The first in group flag.
  std::optional<bool> firstInGroupFlag;
  /// The first in group.
  std::optional<ua::NodeId> firstInGroup;

  // ---- Limit-alarm data surfaced VERBATIM (CL-AC-023 / CL-AC-024 / CL-AC-025) ----
  // The raw values the event carried, surfaced exactly as received  -  the tracker never corrects, coerces,
  // or drops an inconsistent value; it only additionally ADVISES on a detected invariant violation. Each is
  // present only when the event carried that field (absent  to  nullopt).

  /// ExclusiveLimit / LimitAlarm thresholds (CL-AC-023). A valid server orders these
  /// `lowLowLimit <= lowLimit <= highLimit <= highHighLimit`.
  std::optional<double> highHighLimit;
  /// The high limit.
  std::optional<double> highLimit;
  /// The low limit.
  std::optional<double> lowLimit;
  /// The low low limit.
  std::optional<double> lowLowLimit;

  /// NonExclusiveLimitAlarm concurrent limit-state active flags (CL-AC-025). Within-group concurrency
  /// (High+HighHigh, Low+LowLow) is legal; a high-group AND a low-group state active simultaneously is not.
  std::optional<TwoStateValue> lowLowState;
  /// The low state.
  std::optional<TwoStateValue> lowState;
  /// The high state.
  std::optional<TwoStateValue> highState;
  /// The high high state.
  std::optional<TwoStateValue> highHighState;

  /// ExclusiveLimitStateMachine CurrentState (`LimitState`)  -  surfaced only (CL-AC-024).
  std::optional<ua::LocalizedText> exclusiveLimitState;

  /// The alarm's `MaxTimeShelved` (milliseconds) when the event carried it. Used by the tier-2
  /// `timed_shelve_async` local pre-flight: a requested ShelvingTime exceeding a KNOWN MaxTimeShelved is
  /// short-circuited with `Bad_ShelvingTimeOutOfRange` (mirroring the ack/confirm short-circuit on tracked
  /// state); an absent/unknown value proceeds to the server (the authority). Absent  to  nullopt.
  std::optional<double> maxTimeShelved;
};

/// Callback invoked for condition added cb notifications.
using ConditionAddedCb = std::function<void(const TrackedCondition&)>;
/// Callback invoked for condition changed cb notifications.
using ConditionChangedCb = std::function<void(const TrackedCondition&)>;
/// Callback invoked for condition removed cb notifications.
using ConditionRemovedCb = std::function<void(TrackedKey)>;

/// Cross-strand observability snapshot of the tracker (section 8.8.1).
/// @ingroup client
struct AlarmConditionTrackerInfo
{
  /// The tracked condition count.
  std::size_t trackedConditionCount = 0;
  /// The open refresh window count.
  std::size_t openRefreshWindowCount = 0;
  /// The pending follow on refresh.
  bool pendingFollowOnRefresh = false;
  /// The use refresh2.
  bool useRefresh2 = false;
};

/// A per-condition ACTIONABLE handle (T30): callers act on a condition object directly instead of
/// round-tripping an opaque @ref TrackedKey back through the tracker. Move/copy-cheap value handle (weak
/// tracker back-ref, strong-locked per call; `mKey` identifies the branch). Every method forwards to the
/// tracker's strand; refresh + observer registration stay on the tracker.
///
/// **Status codes.** A condition method's Result is its Call's ServiceResult and the Method's statusCode
/// combined (`ua::detail::combined_status`), so a Good subcode or an Uncertain code the server answers
/// reaches the caller. read_property's Result carries the Read's ServiceResult and the value's status
/// combined in the same way. The browse paths the handle resolves first (the Property, the ShelvingState
/// Method) are used only when the server answers them Good: an Uncertain answer is refused with
/// `Bad_InternalError` (`ReferencesAnswerUncertain`).
/// @ingroup client
class AlarmHandle
{
public:
  AlarmHandle() = default;

  /// @return The requested value.
  /// Returns or updates the key.
  [[nodiscard]] TrackedKey key() const
  {
    return mKey;
  }

  // AcknowledgeableConditionType (CL-AC-009/010/019/020).
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously acknowledge.
  void acknowledge_async(
    std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param comment The comment.
  /// Synchronously acknowledge. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void acknowledge_sync(std::optional<ua::LocalizedText> comment);
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to acknowledge sync without throwing.
  ua::VoidResult try_acknowledge_sync(std::optional<ua::LocalizedText> comment) noexcept;
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously confirm.
  void confirm_async(
    std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param comment The comment.
  /// Synchronously confirm. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void confirm_sync(std::optional<ua::LocalizedText> comment);
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to confirm sync without throwing.
  ua::VoidResult try_confirm_sync(std::optional<ua::LocalizedText> comment) noexcept;
  /// @param eventId Event identifier required by the condition method.
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously add comment.
  void add_comment_async(ua::ByteString eventId, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// Synchronously add comment. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void add_comment_sync(ua::ByteString eventId, std::optional<ua::LocalizedText> comment);
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to add comment sync without throwing.
  ua::VoidResult try_add_comment_sync(
    ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept;

  // ConditionType enable/disable.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously enable.
  void enable_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously enable. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void enable_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to enable sync without throwing.
  ua::VoidResult try_enable_sync() noexcept;
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously disable.
  void disable_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously disable. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void disable_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to disable sync without throwing.
  ua::VoidResult try_disable_sync() noexcept;

  // AlarmConditionType + ShelvedStateMachineType.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously silence.
  void silence_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously silence. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void silence_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to silence sync without throwing.
  ua::VoidResult try_silence_sync() noexcept;
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously suppress.
  void suppress_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously suppress. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void suppress_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to suppress sync without throwing.
  ua::VoidResult try_suppress_sync() noexcept;
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously unsuppress.
  void unsuppress_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously unsuppress. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void unsuppress_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to unsuppress sync without throwing.
  ua::VoidResult try_unsuppress_sync() noexcept;
  /// @param shelvingTime The shelving time.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously shelve.
  void shelve_async(
    std::optional<ua::Duration> shelvingTime, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param shelvingTime The shelvingtime.
  /// Synchronously shelve. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void shelve_sync(std::optional<ua::Duration> shelvingTime);
  /// @param shelvingTime The shelvingtime.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to shelve sync without throwing.
  ua::VoidResult try_shelve_sync(std::optional<ua::Duration> shelvingTime) noexcept;
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously unshelve.
  void unshelve_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously unshelve. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void unshelve_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to unshelve sync without throwing.
  ua::VoidResult try_unshelve_sync() noexcept;

  /// @param property Property browse name.
  /// @param callback Completion callback that receives the operation result.
  /// Reads a current child property/value directly from the condition instance. This is the fallback for
  /// plain AlarmConditionType Properties whose mutation is not guaranteed to generate an Event. The value
  /// comes with the Read's code: the ServiceResult and the value's status combined; a Bad code, or a code
  /// that is not Good on a null value, is answered without a value.
  void read_property_async(
    ua::QualifiedName property, std::function<void(ua::Result<ua::Variant>)> callback) noexcept;
  /// @param property Property browse name.
  /// @return The requested value.
  /// Synchronously read property. A Good subcode on the answer is not returned; try_read_property_sync()
  /// returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  [[nodiscard]] ua::Variant read_property_sync(ua::QualifiedName property);
  /// @param property Property browse name.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read property sync without throwing.
  [[nodiscard]] ua::Result<ua::Variant> try_read_property_sync(ua::QualifiedName property) noexcept;

private:
  friend class AlarmConditionTracker;
  friend class detail::AlarmConditionTrackerImpl;

  AlarmHandle(std::weak_ptr<detail::AlarmConditionTrackerImpl> tracker, TrackedKey key) noexcept
    : mTracker(std::move(tracker)), mKey(std::move(key))
  {}

  std::weak_ptr<detail::AlarmConditionTrackerImpl> mTracker;  // strong-locked per call
  TrackedKey mKey;
};

/// The public value handle (move-only shared_ptr pimpl) over the co-owned private sub-object
/// `detail::AlarmConditionTrackerImpl` (T23). Lifecycle (construction, start, close, reconnect) is NOT on
/// this handle  -  it is driven by `detail::EventSubscriberImpl`. This handle exposes only the consumer
/// surface; every method forwards one-hop to the co-owned Impl.
///
/// **Status codes.** A condition method's Result (acknowledge, confirm, add_comment, enable, disable,
/// silence, suppress, unsuppress, shelve, unshelve) is its Call's ServiceResult and the Method's statusCode
/// combined (`ua::detail::combined_status`), so a Good subcode or an Uncertain code the server answers
/// reaches the caller. A ShelvingState Method is called on the node the tracker resolves only when the
/// server answers that lookup Good: an Uncertain answer is refused with `Bad_InternalError`
/// (`ReferencesAnswerUncertain`).
/// @ingroup client
class AlarmConditionTracker
{
public:
  /// Returns or updates the alarm condition tracker.
  AlarmConditionTracker(AlarmConditionTracker&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  AlarmConditionTracker& operator=(AlarmConditionTracker&&) noexcept = default;
  AlarmConditionTracker(const AlarmConditionTracker&) = delete;  // move-only
  AlarmConditionTracker& operator=(const AlarmConditionTracker&) = delete;
  ~AlarmConditionTracker() = default;

  // -------- Snapshot / observers (callbacks fire on the executor) --------

  /// @return An immutable snapshot of the current state.
  /// Returns or updates the info.
  [[nodiscard]] std::shared_ptr<const AlarmConditionTrackerInfo> info() const noexcept;

  /// @param cb Observer callback to register.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously on condition added.
  void on_condition_added_async(ConditionAddedCb cb, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param cb The cb.
  /// Synchronously on condition added. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void on_condition_added_sync(ConditionAddedCb cb);
  /// @param cb The cb.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to on condition added sync without throwing.
  ua::VoidResult try_on_condition_added_sync(ConditionAddedCb cb) noexcept;
  /// @param cb Observer callback to register.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously on condition changed.
  void on_condition_changed_async(
    ConditionChangedCb cb, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param cb The cb.
  /// Synchronously on condition changed. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void on_condition_changed_sync(ConditionChangedCb cb);
  /// @param cb The cb.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to on condition changed sync without throwing.
  ua::VoidResult try_on_condition_changed_sync(ConditionChangedCb cb) noexcept;
  /// @param cb Observer callback to register.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously on condition removed.
  void on_condition_removed_async(
    ConditionRemovedCb cb, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param cb The cb.
  /// Synchronously on condition removed. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void on_condition_removed_sync(ConditionRemovedCb cb);
  /// @param cb The cb.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to on condition removed sync without throwing.
  ua::VoidResult try_on_condition_removed_sync(ConditionRemovedCb cb) noexcept;

  // -------- Snapshot reads --------

  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously list conditions.
  void list_conditions_async(
    std::function<void(ua::Result<std::vector<TrackedCondition>>)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously list conditions. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  std::vector<TrackedCondition> list_conditions_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to list conditions sync without throwing.
  ua::Result<std::vector<TrackedCondition>> try_list_conditions_sync() noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously get condition.
  void get_condition_async(
    TrackedKey key, std::function<void(ua::Result<TrackedCondition>)> callback) noexcept;
  /// @param key The key.
  /// @return The requested value.
  /// Synchronously get condition. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  TrackedCondition get_condition_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to get condition sync without throwing.
  ua::Result<TrackedCondition> try_get_condition_sync(TrackedKey key) noexcept;

  /// @param key Tracked condition and branch key.
  /// @return The requested value.
  /// Allocates an @ref AlarmHandle for a known key (T30).
  [[nodiscard]] AlarmHandle handle(TrackedKey key) const noexcept;

  /// @param metricsObject The metrics object.
  /// @return The requested value.
  /// On-demand typed view over an AlarmMetricsType Object instance (CL-AC-026).
  [[nodiscard]] AlarmMetricsView alarm_metrics(ua::NodeId metricsObject) const noexcept;

  // -------- Refresh (CL-AC-003, -007, -011, -012) --------

  /// @param callback Completion callback that receives the operation result.
  /// Idempotent  -  a call while a window is open queues a follow-on; a call while a client-initiated refresh
  /// is already awaiting its `RefreshEnd` is REJECTED with `Bad_RefreshInProgress` (section 9.6.7
  /// re-entrancy).
  ///
  /// A Good or an Uncertain answer to the ConditionRefresh Call (a Good subcode included) confirms the
  /// refresh, which completes with that code when its `RefreshEnd` arrives. A Bad answer, except the
  /// `Bad_MethodInvalid` to ConditionRefresh2 on which the tracker retries with ConditionRefresh, completes
  /// the refresh at once with the answer's code. An Uncertain answer without a CallResponse (an Uncertain
  /// ServiceFault) does not confirm that a `RefreshEnd` will follow: it completes the refresh at once with
  /// `Bad_InternalError` (`ServiceAnswerUncertain`), the code as its cause.
  void refresh_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously refresh. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void refresh_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to refresh sync without throwing.
  ua::VoidResult try_refresh_sync() noexcept;

  // -------- AcknowledgeableConditionType methods (CL-AC-009/010/019/020) --------

  /// @param key Tracked condition and branch key.
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously acknowledge.
  void acknowledge_async(TrackedKey key, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// @param comment The comment.
  /// Synchronously acknowledge. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void acknowledge_sync(TrackedKey key, std::optional<ua::LocalizedText> comment);
  /// @param key The key.
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to acknowledge sync without throwing.
  ua::VoidResult try_acknowledge_sync(TrackedKey key, std::optional<ua::LocalizedText> comment) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param eventId Event identifier required by the condition method.
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously acknowledge.
  void acknowledge_async(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// Synchronously acknowledge. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void acknowledge_sync(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment);
  /// @param key The key.
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to acknowledge sync without throwing.
  ua::VoidResult try_acknowledge_sync(
    TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously confirm.
  void confirm_async(TrackedKey key, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// @param comment The comment.
  /// Synchronously confirm. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void confirm_sync(TrackedKey key, std::optional<ua::LocalizedText> comment);
  /// @param key The key.
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to confirm sync without throwing.
  ua::VoidResult try_confirm_sync(TrackedKey key, std::optional<ua::LocalizedText> comment) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param eventId Event identifier required by the condition method.
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously confirm.
  void confirm_async(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// Synchronously confirm. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void confirm_sync(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment);
  /// @param key The key.
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to confirm sync without throwing.
  ua::VoidResult try_confirm_sync(
    TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept;

  // -------- ConditionType methods --------

  /// @param key Tracked condition and branch key.
  /// @param eventId Event identifier required by the condition method.
  /// @param comment Optional localized comment to attach to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously add comment.
  void add_comment_async(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// Synchronously add comment. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void add_comment_sync(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment);
  /// @param key The key.
  /// @param eventId The eventid.
  /// @param comment The comment.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to add comment sync without throwing.
  ua::VoidResult try_add_comment_sync(
    TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously enable.
  void enable_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously enable. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void enable_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to enable sync without throwing.
  ua::VoidResult try_enable_sync(TrackedKey key) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously disable.
  void disable_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously disable. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void disable_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to disable sync without throwing.
  ua::VoidResult try_disable_sync(TrackedKey key) noexcept;

  // -------- AlarmConditionType / ShelvedStateMachineType methods --------

  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously silence.
  void silence_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously silence. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void silence_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to silence sync without throwing.
  ua::VoidResult try_silence_sync(TrackedKey key) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously suppress.
  void suppress_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously suppress. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void suppress_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to suppress sync without throwing.
  ua::VoidResult try_suppress_sync(TrackedKey key) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously unsuppress.
  void unsuppress_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously unsuppress. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void unsuppress_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to unsuppress sync without throwing.
  ua::VoidResult try_unsuppress_sync(TrackedKey key) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param shelvingTime The shelving time.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously timed shelve.
  void timed_shelve_async(
    TrackedKey key, ua::Duration shelvingTime, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// @param shelvingTime The shelvingtime.
  /// Synchronously timed shelve. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void timed_shelve_sync(TrackedKey key, ua::Duration shelvingTime);
  /// @param key The key.
  /// @param shelvingTime The shelvingtime.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to timed shelve sync without throwing.
  ua::VoidResult try_timed_shelve_sync(TrackedKey key, ua::Duration shelvingTime) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously one shot shelve.
  void one_shot_shelve_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously one shot shelve. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void one_shot_shelve_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to one shot shelve sync without throwing.
  ua::VoidResult try_one_shot_shelve_sync(TrackedKey key) noexcept;
  /// @param key Tracked condition and branch key.
  /// @param callback Completion callback that receives the operation result.
  /// Asynchronously unshelve.
  void unshelve_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param key The key.
  /// Synchronously unshelve. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void unshelve_sync(TrackedKey key);
  /// @param key The key.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to unshelve sync without throwing.
  ua::VoidResult try_unshelve_sync(TrackedKey key) noexcept;

private:
  friend class Connection;
  friend class detail::EventSubscriberImpl;
  friend struct detail::AlarmConditionTrackerHandleFactory;

  explicit AlarmConditionTracker(std::shared_ptr<detail::AlarmConditionTrackerImpl> impl) noexcept
    : mImpl(std::move(impl))
  {}

  std::shared_ptr<detail::AlarmConditionTrackerImpl> mImpl;  // co-owned with detail::EventSubscriberImpl
};

namespace detail
{

/// Construction interface for @ref AlarmConditionTracker.
/// @ingroup client
struct AlarmConditionTrackerHandleFactory
{
  [[nodiscard]] static AlarmConditionTracker create(
    std::shared_ptr<detail::AlarmConditionTrackerImpl> impl) noexcept
  {
    return AlarmConditionTracker{std::move(impl)};
  }
};

}  // namespace detail

}  // namespace ua::client

#endif  // UA_ALARM_CONDITION_TRACKER_H
