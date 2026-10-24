// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-1 public monitored-item surface (client design section 7.4): the request/notification value
/// types,
///        the unified self-acting @ref ua::client::MonitoredItem handle (T13/T14), the abstract
///        @ref ua::client::detail::MonitoredItemOwner interface its self-actions route through, and the
///        opt-in
///        @ref ua::client::ScopedMonitoredItem RAII wrapper (D-DIAG-1).
/// @ingroup client

#ifndef UA_CLIENT_MONITORED_ITEM_H
#define UA_CLIENT_MONITORED_ITEM_H

#include "ua_aggregate_filter.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_data_change_filter.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_event_filter.h"
#include "ua_integer_id.h"
#include "ua_localized_text.h"
#include "ua_monitoring_mode.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <functional>
#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace ua::client
{

/// The opaque, Connection-unique client handle the SDK assigns each monitored item to demultiplex inbound
/// Publish notifications (CL-MI-003). It is never exposed as a wire value to the user beyond this handle.
using MonitoredItemId = ua::IntegerId;

/// @ingroup client
/// Whether a monitored item observes data changes or events (immutable, set at construction  -  T13). A
/// consumer that must branch on the kind reads @ref ua::client::MonitoredItem::kind.
enum class MonitoredItemKind
{
  DataChange,
  Event
};

/// One decoded data-change notification delivered to a data-change monitor's callback (section 7.4). The
/// @ref nodeId / @ref attribute are pre-decoded from the pipeline's `clientHandle` table so the user never
/// sees the wire handle.
/// @ingroup client
struct DataChangeEvent
{
  /// The item id.
  MonitoredItemId itemId = 0;
  /// The node id.
  ua::NodeId nodeId;
  /// The attribute.
  ua::AttributeId attribute = ua::AttributeId::Value;
  /// The value.
  ua::DataValue value;
};

/// Mandatory Part 5 AuditEventType properties decoded for an audit notification (CL-AUDIT-004).
/// @ingroup client
struct AuditEventFields
{
  /// The action time stamp.
  ua::DateTime actionTimeStamp;
  /// The status.
  bool status = false;
  /// The server id.
  ua::String serverId;
  /// The client audit entry id.
  ua::String clientAuditEntryId;
  /// The client user id.
  ua::String clientUserId;
};

/// The audit event category.
enum class AuditEventCategory
{
  Base,
  Security,
  Channel,
  Session,
  Update,
  UpdateMethod,
  UnknownSubtype,
};

/// Category-specific fields recognised from the standard AuditEventType subtree (CL-AUDIT-006).
/// @ingroup client
struct AuditSubtypeFields
{
  /// The category.
  AuditEventCategory category{AuditEventCategory::Base};
  /// The status code id.
  std::optional<ua::StatusCode> statusCodeId;
  /// The secure channel id.
  std::optional<ua::String> secureChannelId;
  /// The session id.
  std::optional<ua::NodeId> sessionId;
  /// The method id.
  std::optional<ua::NodeId> methodId;
  /// The input arguments.
  std::optional<ua::Variant> inputArguments;
};

/// The progress source kind.
enum class ProgressSourceKind
{
  Service,
  Application,
};

/// Typed ProgressEventType properties (CL-EVT-006). Context is always retained verbatim; Service events
/// additionally expose the decoded RequestHeader.requestHandle.
/// @ingroup client
struct ProgressEventFields
{
  /// The context.
  ua::Variant context;
  /// The progress.
  std::uint16_t progress = 0;
  /// The source kind.
  ProgressSourceKind sourceKind{ProgressSourceKind::Application};
  /// The request handle.
  std::optional<std::uint32_t> requestHandle;
};

/// One event notification delivered to an event consumer's callback (section 7.4 / section 8.13). The decoded
/// `BaseEventType` mandatory fields (CL-EVT-001) are surfaced as named members; @ref fields carries every
/// selected event-field value positionally in the order of the composite `EventFilter.selectClauses`
/// (CL-EVT-002), with a null / unavailable field surfaced as `nullopt` (CL-MI-017). @ref fieldPaths is the
/// parallel `BrowsePath` metadata so callers can resolve a field by NAME (@ref field / @ref field_as, T22)
/// instead of indexing positionally (robust under composite-filter widening).
/// @ingroup client
struct EventNotification
{
  /// The item id.
  MonitoredItemId itemId = 0;

  // ---- BaseEventType mandatory fields (CL-EVT-001), decoded for convenience ----
  /// The event type id.
  ua::NodeId eventTypeId;
  /// The event id.
  ua::ByteString eventId;
  /// The source node.
  ua::NodeId sourceNode;
  /// The source name. A String, as OPC 10000-5 defines `BaseEventType/SourceName`.
  ua::String sourceName;
  /// The time.
  ua::DateTime time;
  /// The receive time.
  ua::DateTime receiveTime;
  /// The message.
  ua::LocalizedText message;
  /// The severity.
  std::uint16_t severity = 0;
  std::optional<AuditEventFields> audit;  ///< engaged for a well-formed AuditEventType notification
  std::optional<AuditSubtypeFields> auditSubtype;  ///< category/runtime subtype fields when audit is engaged
  std::optional<ProgressEventFields> progress;  ///< engaged for a decodable ProgressEventType notification

  // ---- Positional selected fields + their BrowsePath metadata (CL-EVT-002) ----
  /// The fields.
  std::vector<std::optional<ua::Variant>> fields;
  std::vector<std::vector<ua::QualifiedName>> fieldPaths;  ///< fieldPaths[i] is the BrowsePath of fields[i]

  /// @param name The name.
  /// @return The requested value.
  /// The value of the selected field whose (single-segment) BrowseName == @p name, or `nullopt` if that
  /// SelectClause was not requested (T22  -  by-name access correlates `fields[i]` with `fieldPaths[i]`).
  [[nodiscard]] std::optional<ua::Variant> field(std::string_view name) const
  {
    for (std::size_t i = 0; i < fieldPaths.size() && i < fields.size(); ++i)
    {
      if (fieldPaths[i].size() == 1 && static_cast<std::string_view>(fieldPaths[i].front().name()) == name)
      {
        return fields[i];
      }
    }
    return std::nullopt;
  }

  /// The value of the selected field whose FULL BrowsePath equals @p browsePath (each segment compared in
  /// order), or `nullopt` if that SelectClause was not requested. This is the spec-shaped access for the
  /// condition sub-state fields a server carries at a MULTI-segment path  -  e.g. a TwoStateVariable's
  /// Boolean lives at `[<State>, "Id"]` and the ExclusiveLimit state at `["LimitState", "CurrentState"]`, not
  /// at the single-segment display-name node. It is ADDITIVE to the single-segment
  /// `field(std::string_view)`: the match requires `fieldPaths[i].size() == browsePath.size()`, so
  /// `field({"AckedState","Id"})` never cross-matches a single-segment `AckedState` field and vice-versa.
  /// Decode is by-PATH (via the parallel `fieldPaths` metadata), so it is robust under composite-filter
  /// widening  -  the composite EventFilter is a positional list whose slots shift as other hooks'
  /// SelectClauses are prepended/merged, and a fixed slot index would silently mis-decode (T22, section 7.4 /
  /// section 8.13).
  /// @param browsePath Complete browse path of the selected event field.
  /// @return The selected field value, or `nullopt` when the path was not requested.
  [[nodiscard]] std::optional<ua::Variant> field(std::initializer_list<std::string_view> browsePath) const
  {
    for (std::size_t i = 0; i < fieldPaths.size() && i < fields.size(); ++i)
    {
      const std::vector<ua::QualifiedName>& path = fieldPaths[i];
      if (path.size() != browsePath.size())
      {
        continue;
      }
      bool matches = true;
      std::size_t segment = 0;
      for (const std::string_view expected : browsePath)
      {
        if (static_cast<std::string_view>(path[segment].name()) != expected)
        {
          matches = false;
          break;
        }
        ++segment;
      }
      if (matches)
      {
        return fields[i];
      }
    }
    return std::nullopt;
  }

  /// @param name The name.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// @ref field coerced to `T` via `Variant::to<T>()`; `Bad_NoData` if the field was not requested / is null,
  /// or the coercion's `Bad_TypeMismatch` on a type error (T22).
  template<class T>
  [[nodiscard]] ua::Result<T> field_as(std::string_view name) const
  {
    const std::optional<ua::Variant> value = field(name);
    if (!value.has_value())
    {
      return ua::Result<T>{ua::StatusCode{ua::Status::BadNoData}};
    }
    return value->template to<T>();
  }

  /// @param browsePath The browse path.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Multi-segment @ref field({...}) coerced to `T` (see the single-segment @ref field_as overload, T22).
  template<class T>
  [[nodiscard]] ua::Result<T> field_as(std::initializer_list<std::string_view> browsePath) const
  {
    const std::optional<ua::Variant> value = field(browsePath);
    if (!value.has_value())
    {
      return ua::Result<T>{ua::StatusCode{ua::Status::BadNoData}};
    }
    return value->template to<T>();
  }
};

/// A request to attach a DATA-CHANGE monitor (T17).
///
/// The @ref filter is a data-change-only 3-way variant (`monostate` = no filter, @ref ua::DataChangeFilter,
/// or @ref ua::AggregateFilter). There is deliberately NO @ref ua::EventFilter alternative here, so "put an
/// event filter on a data-change monitor" is a COMPILE error rather than a runtime reject  -  the invariant
/// the earlier 4-way variant only claimed is now enforced by the type system. Event monitors use the
/// dedicated @ref EventMonitorRequest.
/// @ingroup client
struct MonitorRequest
{
  /// The node id.
  ua::NodeId nodeId;
  /// The attribute.
  ua::AttributeId attribute = ua::AttributeId::Value;
  /// The index range.
  std::optional<std::string> indexRange;
  /// The queue size.
  std::optional<std::uint32_t> queueSize;
  std::optional<ua::MonitoringMode> monitoringMode;  ///< default Reporting when unset
  /// The filter.
  std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter;
  double samplingIntervalMs = 0.0;  ///< 0 = use the Subscription's publishing interval
  bool discardOldest = true;  ///< queue-overflow policy (CL-MI-020): drop the oldest (true) vs newest (false)
};

/// A request to attach an EVENT monitor (T17)  -  a dedicated shape with a REQUIRED @ref ua::EventFilter (an
/// event monitor with no filter is meaningless).
/// @ingroup client
struct EventMonitorRequest
{
  ua::NodeId nodeId;  ///< the event notifier (e.g. the Server object)
  /// The attribute.
  ua::AttributeId attribute = ua::AttributeId::EventNotifier;
  /// The queue size.
  std::optional<std::uint32_t> queueSize;
  std::optional<ua::MonitoringMode> monitoringMode;  ///< default Reporting when unset
  ua::EventFilter filter;  ///< REQUIRED
  /// The sampling interval ms.
  double samplingIntervalMs = 0.0;
};

/// Compile-time proof of the T17 filter invariant: a data-change @ref MonitorRequest's filter variant does
/// NOT admit an @ref ua::EventFilter alternative (event filters live only on @ref EventMonitorRequest).
namespace detail
{
template<class Variant, class Alternative>
struct variant_has_alternative;

template<class Alternative, class... Alternatives>
struct variant_has_alternative<std::variant<Alternatives...>, Alternative>
  : std::disjunction<std::is_same<Alternative, Alternatives>...>
{};
}  // namespace detail

static_assert(!detail::variant_has_alternative<decltype(MonitorRequest::filter), ua::EventFilter>::value,
  "T17: a data-change MonitorRequest must not admit an EventFilter alternative - use EventMonitorRequest");

/// Callback invoked (on the executor) with each data-change notification for a data-change monitor.
using DataChangeCallback = std::function<void(DataChangeEvent)>;

/// Callback invoked (on the executor) with each event notification for an event monitor.
using EventCallback = std::function<void(EventNotification)>;

/// The section 8.13 name for @ref EventCallback  -  the callback an @ref EventSubscriber consumer registers.
using EventNotificationCallback = EventCallback;

class MonitoredItem;

/// A `Result` carrying a @ref MonitoredItem (the "subscribe and get a handle" return, T13).
using MonitoredItemResult = ua::Result<MonitoredItem>;

namespace detail
{

/// Abstract owner interface (T13 / TR-3)  -  the connection-lifetime component a @ref MonitoredItem routes
/// its self-actions (modify / set-mode / delete) through, resolved by the item's `clientHandle`.
///
/// Implemented by the subscription registry component (data-change items) AND, from Slice 10a, by
/// `EventSubscriberImpl` (event consumers)  -  because those owners are genuinely different objects with
/// different server semantics: a data-change item's delete is a `DeleteMonitoredItems` on its Subscription,
/// whereas an event consumer's delete drops one of N consumers coalesced onto a shared backbone item and
/// recomputes the composite `EventFilter` (it must NOT delete the shared backbone and kill the others). The
/// owner is a CONNECTION-lifetime component, never a per-subscription map value  -  so a `MonitoredItem`'s
/// self-actions keep working after the user drops the parent @ref Subscription handle, for as long as the
/// Connection lives.
/// @ingroup client
class MonitoredItemOwner
{
public:
  MonitoredItemOwner() = default;
  MonitoredItemOwner(const MonitoredItemOwner&) = delete;
  MonitoredItemOwner& operator=(const MonitoredItemOwner&) = delete;
  MonitoredItemOwner(MonitoredItemOwner&&) = delete;
  MonitoredItemOwner& operator=(MonitoredItemOwner&&) = delete;
  virtual ~MonitoredItemOwner() = default;

  /// The executor the owner's operations complete on, which a blocking wrapper must not wait on from
  /// one of its own threads. Empty when the owner has none, and then a wait is never refused.
  /// @return The completion executor, or an empty executor when none is bound.
  [[nodiscard]] virtual boost::asio::any_io_executor executor() const noexcept
  {
    return {};
  }

  /// @param clientHandle The client handle.
  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Modifies the item identified by @p clientHandle with the new data-change @p request; the callback
  /// delivers the answer's code (Good, a Good subcode or Uncertain) or a bad @ref ua::VoidResult (with
  /// @ref ua::ErrorDetail) on the executor.
  virtual void mi_modify_async(MonitoredItemId clientHandle, MonitorRequest request,
    std::function<void(ua::VoidResult)> callback) noexcept = 0;

  /// @param clientHandle The client handle.
  /// @param mode The mode.
  /// @param callback Completion callback that receives the operation result.
  /// Sets the monitoring @p mode of the item identified by @p clientHandle.
  virtual void mi_set_mode_async(MonitoredItemId clientHandle, ua::MonitoringMode mode,
    std::function<void(ua::VoidResult)> callback) noexcept = 0;

  /// @param clientHandle The client handle.
  /// @param callback Completion callback that receives the operation result.
  /// Deletes the item identified by @p clientHandle.
  virtual void mi_delete_async(
    MonitoredItemId clientHandle, std::function<void(ua::VoidResult)> callback) noexcept = 0;
};

/// The small thread-safe MUTABLE state a @ref MonitoredItem handle exposes (D5 / CL-MI-019/020/021). Created
/// by the owner at registration and held by BOTH the owner's routing entry AND every copy of the handle
/// (shared_ptr), so the owner  -  which does the wire op and reads the response  -  is the sole updater, and
/// every handle copy observes the current value. Read via atomic loads from any thread (no strand hop; this
/// is the TR-8-compatible reconciliation of the copyable-value handle with revised-value mutability).
/// @ingroup client
struct MonitoredItemState
{
  std::atomic<double> revisedSamplingIntervalMs{0.0};  ///< server-revised sampling interval (create + modify)
  std::atomic<std::uint32_t> revisedQueueSize{0};  ///< server-revised queue size (create + modify)
  std::atomic<ua::MonitoringMode> mode{ua::MonitoringMode::Reporting};  ///< current mode (create + set_mode)
  std::atomic<bool> discardOldest{true};  ///< queue-overflow policy the item was created / modified with
};

struct MonitoredItemFactory;

}  // namespace detail

/// The single, unified, self-acting MonitoredItem identity (T13 / T14).
///
/// Returned from every "subscribe and get a handle" call (data-change monitor, and  -  from Slice 10a  -
/// event subscriber / state-machine transition / server-diagnostics subscribe). Retires the former
/// `EventSubscriptionHandle` / `MonitoredItemHandle`. A lightweight COPYABLE value type: it carries a
/// `weak_ptr` to its connection-lifetime owner plus an immutable identity/snapshot, no owning resource, so
/// copying and dropping it are cheap and side-effect-free.
///
/// ## Drop lifetime  -  persist-on-drop (D-DIAG-1)
/// Dropping a @ref MonitoredItem is a NO-OP; the item survives on the server, including across reconnect
/// (section 7.4). A caller who wants drop-cancels wraps the item in @ref ScopedMonitoredItem (opt-in RAII)  -
/// one drop-contract per handle.
///
/// ## Self-actions
/// `modify_async` / `set_mode_async` / `delete_async` forward through the weak @ref
/// detail::MonitoredItemOwner interface. The owner is locked per call. If the lock fails the Connection is
/// gone (the owner is a Connection-lifetime component)  to  the call completes `Bad_ConnectionClosed`. If the
/// lock succeeds but the owner's registry no longer knows this item's `clientHandle` (the server item was
/// explicitly closed / is non-recoverable)  to  the call completes `Bad_SubscriptionIdInvalid` (section 7.4
/// -  the two are distinct failure surfaces).
/// @ingroup client
class MonitoredItem
{
public:
  /// Constructs an EMPTY handle (no owner, handle 0). Its self-actions fast-fail `Bad_ConnectionClosed` (the
  /// weak owner lock fails  -  there is no live Connection behind an empty handle).
  MonitoredItem() = default;

  // ============ Immutable identity / snapshot ============

  /// @return The requested value.
  /// The opaque Connection-unique client handle (CL-MI-003). Immutable.
  [[nodiscard]] MonitoredItemId client_handle() const noexcept
  {
    return mClientHandle;
  }

  /// @return A reference to this object.
  /// The monitored node. Immutable.
  [[nodiscard]] const ua::NodeId& node_id() const noexcept
  {
    return mNodeId;
  }

  /// @return The requested value.
  /// The monitored attribute. Immutable.
  [[nodiscard]] ua::AttributeId attribute() const noexcept
  {
    return mAttribute;
  }

  /// @return The requested value.
  /// The kind (DataChange | Event). Immutable  -  for consumers that must branch.
  [[nodiscard]] MonitoredItemKind kind() const noexcept
  {
    return mKind;
  }

  /// The item's current monitoring mode. For a DataChange item it is seeded at create and UPDATED on every
  /// @ref set_mode_async the server answers Good or Uncertain with the item's result (CL-MI-021), so it
  /// reflects the applied mode. For an Event item (@ref kind() ==
  /// `MonitoredItemKind::Event`) the mode reflects the create-time value only  -  the event
  /// subscriber tracks the applied delivery mode in its own consumer table and does not write it back to this
  /// handle (batched follow-up), so a `mode()` read on an event item may lag its `set_mode_async`.
  /// Thread-safe; shared across handle copies.
  /// @return The handle's current monitoring mode.
  [[nodiscard]] ua::MonitoringMode mode() const noexcept
  {
    return mState ? mState->mode.load() : ua::MonitoringMode::Reporting;
  }

  /// The server's REVISED sampling interval (milliseconds) for this item (CL-MI-002 / CL-MI-019). Captured
  /// verbatim from the `CreateMonitoredItems` result's `revisedSamplingInterval` and UPDATED on every
  /// @ref modify_async the server answers Good or Uncertain with the item's result, to the modify's revised
  /// value  -  the server may raise the requested interval to its supported minimum (or otherwise revise it),
  /// and a caller reads this to learn the ACTUAL cadence it will observe. The raw server value is stored
  /// as-is (no normalization), so a spec-violating value the server returns (below the request, negative,
  /// NaN) survives for the caller to inspect. `0.0` on an empty handle. UPDATED on modify only for a
  /// DataChange item; an Event item surfaces the create-time value (events are not re-tuned through this
  /// handle). Thread-safe; shared across handle copies.
  /// @return The revised sampling interval in milliseconds.
  [[nodiscard]] double revised_sampling_interval() const noexcept
  {
    return mState ? mState->revisedSamplingIntervalMs.load() : 0.0;
  }

  /// @return The requested value.
  /// The server's REVISED queue size for this item (CL-MI-019). Captured at create and UPDATED on every
  /// @ref modify_async the server answers Good or Uncertain with the item's result (DataChange items) to the
  /// modify's revised value; an Event item surfaces the
  /// create-time value. `0` on an empty handle. Thread-safe; shared across copies.
  [[nodiscard]] std::uint32_t revised_queue_size() const noexcept
  {
    return mState ? mState->revisedQueueSize.load() : 0;
  }

  /// The queue-overflow policy this item was created / modified with (CL-MI-020): `true` drops the oldest
  /// @return True when the requested condition is satisfied.
  /// queued notification on overflow, `false` drops the newest. `true` on an empty handle. Thread-safe.
  [[nodiscard]] bool discard_oldest() const noexcept
  {
    return mState ? mState->discardOldest.load() : true;
  }

  // ============ Self-actions (forward via the weak owner interface) ============

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Modifies this item with a new data-change @p request. The callback runs on the executor. Never throws.
  void modify_async(MonitorRequest request, std::function<void(ua::VoidResult)> callback) noexcept;

  /// @param mode The mode.
  /// @param callback Completion callback that receives the operation result.
  /// Sets this item's monitoring @p mode. The callback runs on the executor. Never throws.
  void set_mode_async(ua::MonitoringMode mode, std::function<void(ua::VoidResult)> callback) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Deletes this item server-side. The callback runs on the executor. Never throws. The item's notifications
  /// stop being delivered once the server answers Good or Uncertain with the item's result.
  void delete_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// @param request The request.
  /// Blocking `modify`. @throws ua::UaException on a bad Result.
  void modify_sync(MonitorRequest request);
  /// @param request The request.
  /// @return The requested value.
  /// Blocking `modify`. Never throws.
  ua::VoidResult try_modify_sync(MonitorRequest request) noexcept;

  /// @param mode The mode.
  /// Blocking `set_mode`. @throws ua::UaException on a bad Result.
  void set_mode_sync(ua::MonitoringMode mode);
  /// @param mode The mode.
  /// @return The requested value.
  /// Blocking `set_mode`. Never throws.
  ua::VoidResult try_set_mode_sync(ua::MonitoringMode mode) noexcept;

  /// Blocking `delete`. @throws ua::UaException on a bad Result.
  void delete_sync();
  /// @return The requested value.
  /// Blocking `delete`. Never throws.
  ua::VoidResult try_delete_sync() noexcept;

private:
  friend struct detail::MonitoredItemFactory;

  std::weak_ptr<detail::MonitoredItemOwner> mOwner;  // weak  -  connection-lifetime owner (section 2.3)
  MonitoredItemId mClientHandle = 0;
  ua::NodeId mNodeId;
  ua::AttributeId mAttribute = ua::AttributeId::Value;
  MonitoredItemKind mKind = MonitoredItemKind::DataChange;
  // The mutable revised-value state (mode / revised sampling / revised queue / discardOldest), shared with
  // the owner's routing entry so a modify / set_mode updates it for every handle copy (D5,
  // CL-MI-019/020/021). Null on an empty handle -> accessors return defaults.
  std::shared_ptr<detail::MonitoredItemState> mState;
};

namespace detail
{

/// Construction interface for @ref MonitoredItem (the owner component and tests construct handles through it,
/// keeping the public constructor empty-only).
/// @ingroup client
struct MonitoredItemFactory
{
  /// Builds a handle over @p state  -  the SHARED @ref MonitoredItemState the owner also keeps in its routing
  /// entry, so a later modify / set_mode the owner applies is observed through this handle (and its copies).
  /// A null @p state yields a handle whose mutable accessors return defaults (test / empty use).
  [[nodiscard]] static MonitoredItem create(std::weak_ptr<MonitoredItemOwner> owner,
    MonitoredItemId clientHandle, ua::NodeId nodeId, ua::AttributeId attribute, MonitoredItemKind kind,
    std::shared_ptr<MonitoredItemState> state)
  {
    MonitoredItem item;
    item.mOwner = std::move(owner);
    item.mClientHandle = clientHandle;
    item.mNodeId = std::move(nodeId);
    item.mAttribute = attribute;
    item.mKind = kind;
    item.mState = std::move(state);
    return item;
  }

  /// Convenience overload: builds the shared @ref MonitoredItemState from the given snapshot values. Used by
  /// call sites that do not need to retain the state for later updates (event subscriber, tests).
  [[nodiscard]] static MonitoredItem create(std::weak_ptr<MonitoredItemOwner> owner,
    MonitoredItemId clientHandle, ua::NodeId nodeId, ua::AttributeId attribute, MonitoredItemKind kind,
    ua::MonitoringMode mode, double revisedSamplingIntervalMs = 0.0, std::uint32_t revisedQueueSize = 0,
    bool discardOldest = true)
  {
    auto state = std::make_shared<MonitoredItemState>();
    state->mode.store(mode);
    state->revisedSamplingIntervalMs.store(revisedSamplingIntervalMs);
    state->revisedQueueSize.store(revisedQueueSize);
    state->discardOldest.store(discardOldest);
    return create(std::move(owner), clientHandle, std::move(nodeId), attribute, kind, std::move(state));
  }
};

}  // namespace detail

/// Opt-in RAII wrapper that DELETES its wrapped @ref MonitoredItem on destruction (D-DIAG-1).
///
/// The plain @ref MonitoredItem is uniformly persist-on-drop; a caller who wants drop-cancels wraps it here.
/// Move-only (owns the drop-cancel duty). The destructor issues a fire-and-forget @ref
/// MonitoredItem::delete_async (its completion is not awaited  -  the object is going away); @ref release
/// relinquishes the duty (persist-on-drop) and @ref get exposes the wrapped item for its own self-actions.
/// @ingroup client
class ScopedMonitoredItem
{
public:
  /// @param item The item.
  /// Wraps @p item; its destructor will delete @p item unless @ref release is called first.
  explicit ScopedMonitoredItem(MonitoredItem item) noexcept : mItem(std::move(item)), mArmed(true)
  {}

  ScopedMonitoredItem(const ScopedMonitoredItem&) = delete;
  ScopedMonitoredItem& operator=(const ScopedMonitoredItem&) = delete;

  /// @param other The other.
  /// Returns or updates the scoped monitored item.
  ScopedMonitoredItem(ScopedMonitoredItem&& other) noexcept
    : mItem(std::move(other.mItem)), mArmed(other.mArmed)
  {
    other.mArmed = false;
  }

  /// @param other The other.
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  ScopedMonitoredItem& operator=(ScopedMonitoredItem&& other) noexcept
  {
    if (this != &other)
    {
      cancel_on_drop();
      mItem = std::move(other.mItem);
      mArmed = other.mArmed;
      other.mArmed = false;
    }
    return *this;
  }

  /// Issues a fire-and-forget delete of the wrapped item (unless released / moved-from).
  ~ScopedMonitoredItem()
  {
    cancel_on_drop();
  }

  /// @return A reference to this object.
  /// The wrapped item (for its own self-actions / identity queries).
  [[nodiscard]] const MonitoredItem& get() const noexcept
  {
    return mItem;
  }

  /// @return The requested value.
  /// Relinquishes the drop-cancel duty (the wrapped item then persists on drop). Returns the item.
  MonitoredItem release() noexcept
  {
    mArmed = false;
    return std::move(mItem);
  }

private:
  void cancel_on_drop() noexcept
  {
    if (mArmed)
    {
      mArmed = false;
      mItem.delete_async([](ua::VoidResult) {});  // fire-and-forget; the wrapper is going away
    }
  }

  MonitoredItem mItem;
  bool mArmed = false;
};

}  // namespace ua::client

#endif  // UA_CLIENT_MONITORED_ITEM_H
