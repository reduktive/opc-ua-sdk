// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_ROUTER_H
#define UA_EVENT_ROUTER_H

/// @file
/// @brief The per-Connection EventSubscriber to observer/cache routing router (client design section 8.13 /
/// section 8.7 /
///        section 8.18; CL-EVT-003 / CL-EVT-004 / CL-EVT-005). Subscribes the NS0 model, semantic, audit, and
///        system types on the tier-2 @ref ua::client::detail::EventSubscriberImpl and routes each delivered
///        @ref ua::client::EventNotification into the @ref ua::client::detail::ObserverSink fan-out plus the
///        two caches (@ref ua::client::detail::AddressSpaceCache for model changes,
///        @ref ua::client::detail::SemanticChangeCache for semantic changes).
/// @ingroup client
///
/// **Strand model (the design specification).** The router has **no private strand**: the connection strand
/// is injected at construction. The EventSubscriber delivers each event callback on the executor,
/// UNSERIALIZED (any worker thread), so every handler re-marshals onto the connection strand
/// (`post_borrowing`) before it decodes the untrusted `Changes` payload and touches the caches / sink. The
/// router weak-refs
/// @ref ua::client::detail::ConnectionImpl (no ownership cycle) and reaches its collaborators through the
/// orchestrator's public accessors; a lock failing == the Connection is gone (the route is dropped).

#include "ua_address_space_cache.h"  // ModelChangeNotification / ModelChange / ModelChangeVerb
#include "ua_client_monitored_item.h"  // EventNotification / MonitoredItem
#include "ua_client_observers.h"  // ModelChangeStructure / SemanticChangeStructure
#include "ua_logger.h"
#include "ua_node_id.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace ua::client::detail
{

class ConnectionImpl;

// ---- Pure decode module (independently unit-testable; no strand / no ConnectionImpl) ----

/// Expands a `ModelChangeStructureVerbMask` byte (CL-EVT-003) into the internal @ref ModelChangeVerb enums  -
/// one per set bit (the wire field is a bitmask that may name several verbs at once). Unknown / reserved bits
/// are ignored (a forward-compatible server verb the client cannot act on is a best-effort skip, not an
/// error).
///
/// @param mask The wire `ModelChangeStructureDataType.Verb` bitmask.
/// @return The recognised verbs, in mask-bit order (empty when no known bit is set).
[[nodiscard]] std::vector<ModelChangeVerb> model_change_verbs_from_mask(std::uint8_t mask);

/// The two shapes a decoded model-change event fans out into: the @ref ModelChangeNotification the
/// @ref AddressSpaceCache invalidates against (drops `affectedType`; the verb mask is expanded to the
/// internal enums) and the public @ref ua::client::ModelChangeStructure list the @ref AddressSpaceObserver
/// receives (keeps `affectedType` + the raw uint8 verb mask verbatim).
struct ModelChangeDecode
{
  ModelChangeNotification cacheNotification;  ///< AddressSpaceCache input (CL-EVT-003)
  std::vector<ua::client::ModelChangeStructure> observerChanges;  ///< AddressSpaceObserver input
};

/// Decodes a model-change event (client design section 8.7.4 / CL-EVT-003). @p eventKind selects the source
/// type: `Base` = a `BaseModelChangeEventType` (for a View), `General` = a `GeneralModelChangeEventType`.
///
/// A `Base` event, or a `General` event whose `Changes` field is ABSENT / null-Variant, decodes to a FULL
/// FLUSH (@ref ModelChangeNotification::Kind::Base, `view` = the event's `sourceNode`, no per-node changes) -
/// per the design specification section 9.6.19.4 (the null-Variant case is CONSERVATIVE: the client cannot
/// see the enumerated changes, so it over-invalidates rather than miss one). A `General` event with a
/// decodable non-empty `Changes` array decodes to per-node changes.
///
/// A `General` event whose `Changes` array is PRESENT but ZERO-LENGTH is a server protocol violation (Part 5
/// section 6.4.32: "shall contain at least one entry"): per CL-EVT-003
/// (`client_general_model_change_with_empty_changes_dropped`) it is DROPPED  -  @p logger records a
/// source-tagged advisory and this returns `nullopt` (NOT a full flush; the server explicitly enumerated "no
/// changes"). A `General` event whose `Changes` is present but NOT a decodable array of
/// `ModelChangeStructureDataType` is likewise MALFORMED untrusted input: advisory + `nullopt` (the caller
/// SKIPS the event  -  no crash, no cache mutation, no observer fire).
///
/// @param notification The delivered event.
/// @param eventKind    Which model-change type delivered it.
/// @param logger       Logger for the source-tagged empty / malformed-input advisory.
/// @return The decoded fan-out, or `nullopt` when the `Changes` payload was present-but-empty or malformed
///         (skip the event).
[[nodiscard]] std::optional<ModelChangeDecode> decode_model_change_event(
  const ua::client::EventNotification& notification, ModelChangeNotification::Kind eventKind,
  const ua::Logger& logger);

/// The two shapes a decoded semantic-change event fans out into: the affected NodeIds the
/// @ref SemanticChangeCache invalidates (section 8.18, CL-DA-011) and the public @ref
/// ua::client::SemanticChangeStructure list the @ref AddressSpaceObserver receives.
struct SemanticChangeDecode
{
  std::vector<ua::NodeId> affected;  ///< SemanticChangeCache::invalidate_async input
  std::vector<ua::client::SemanticChangeStructure> observerChanges;  ///< AddressSpaceObserver input
};

/// Decodes a `SemanticChangeEventType` event (client design section 8.18 / CL-EVT-004). An absent / empty
/// `Changes` field decodes to empty vectors (nothing to invalidate / report). A `Changes` present but NOT a
/// decodable array of `SemanticChangeStructureDataType` is MALFORMED untrusted input: @p logger records a
/// source-tagged advisory and this returns `nullopt` (the caller SKIPS the event). The address-space cache is
/// NEVER touched on this path (CL-EVT-004): a semantic change alters metadata interpretation only, not the
/// value / attribute caches.
///
/// @param notification The delivered event.
/// @param logger       Logger for the source-tagged malformed-input advisory.
/// @return The decoded fan-out, or `nullopt` when the `Changes` payload was malformed (skip the event).
[[nodiscard]] std::optional<SemanticChangeDecode> decode_semantic_change_event(
  const ua::client::EventNotification& notification, const ua::Logger& logger);

/// The per-Connection event routing router (Slice W8b). Owned by @ref ConnectionImpl; weak-refs it (no
/// cycle).
///
/// At first-reach-Active (@ref start, driven from `ConnectionImpl::on_first_session_active`) it subscribes to
/// the routed NS0 event types  -  GeneralModelChangeEventType, BaseModelChangeEventType,
/// SemanticChangeEventType, AuditEventType, ProgressEventType, and SystemStatusChangeEventType  -  via the
/// tier-2
/// @ref EventSubscriberImpl. The GeneralModelChange, SemanticChange, and SystemStatusChange
/// backbones each subscribe on their OWN dedicated backbone carrying an extra "Changes" SelectClause
/// (Slice 2b) so the per-node `Changes` payload is delivered and the per-type clause stays unambiguous
/// (`EventNotification::field` is browse-name keyed and both types name the field "Changes"); Base + Audit
/// have no Changes field and coalesce onto the shared Server backbone. Each delivered
/// @ref ua::client::EventNotification (executor thread) re-marshals onto the connection strand and routes:
/// model  to  address-space cache flush (CL-EVT-003) then observer; semantic  to  semantic-change cache
/// invalidation + observer (CL-EVT-004; the address-space cache is left untouched); audit  to  observer
/// pass-through.
class EventRouter : public std::enable_shared_from_this<EventRouter>
{
public:
  /// @param strand     `ConnectionImpl`'s strand  -  the router has NO private strand (the injected strand is
  ///                   the single serialization domain the executor to strand re-marshal targets).
  /// @param connection The orchestrator whose accessors (events_impl / observer_sink / address_space_cache /
  ///                   semantic_change_cache) the router reaches (weak  -  locked per route; no cycle).
  /// @param logger     Logger for the guarded async boundaries + the untrusted-input advisories.
  /// @return A shared router.
  [[nodiscard]] static std::shared_ptr<EventRouter> create(
    boost::asio::strand<boost::asio::any_io_executor> strand, std::weak_ptr<ConnectionImpl> connection,
    ua::Logger logger);

  EventRouter(const EventRouter&) = delete;
  EventRouter& operator=(const EventRouter&) = delete;
  EventRouter(EventRouter&&) = delete;
  EventRouter& operator=(EventRouter&&) = delete;
  ~EventRouter() = default;

  /// Subscribes to the routed event types (section 8.13, CL-EVT-003/004/005). Idempotent (a second call is a
  /// no-op). Called on the connection strand from `ConnectionImpl::on_first_session_active`; the resulting
  /// backbone MonitoredItem handles are retained for teardown. J57: eager subscribe at first-active  -  a
  /// subscribe-only-when-a-consumer-exists refinement is a follow-up.
  void start();

  /// Halts routing (Connection close). Flips the stopped latch so any in-flight event re-marshal drops on its
  /// strand turn, and releases the retained backbone handles. The backbone MonitoredItems themselves are torn
  /// down by the SubscriptionsPipeline / session close  -  the router issues no DeleteMonitoredItems on a
  /// closing session (FU-1). Idempotent; called on the connection strand from `ConnectionImpl::begin_close`.
  void stop();

  // ---- Event handlers (executor thread; re-marshal onto the connection strand internally). Exposed for the
  //      W8b routing unit tests, which drive them with a scripted EventNotification on the real code path.
  //      ----

  /// Routes a model-change event (@p eventKind = General or Base)  -  CL-EVT-003.
  void handle_model_event(
    ua::client::EventNotification notification, ModelChangeNotification::Kind eventKind);

  /// Routes a `SemanticChangeEventType` event  -  CL-EVT-004.
  void handle_semantic_event(ua::client::EventNotification notification);

  /// Routes a `SystemStatusChangeEventType`, preserving source identity and classifying its origin.
  void handle_system_status_event(ua::client::EventNotification notification);

  /// Routes a ProgressEventType with typed service/application context and bounded percentage.
  void handle_progress_event(ua::client::EventNotification notification);
  void handle_device_failure_event(ua::client::EventNotification notification);

  /// Routes an `AuditEventType` event (observer pass-through; no decode).
  void handle_audit_event(ua::client::EventNotification notification);

private:
  EventRouter(boost::asio::strand<boost::asio::any_io_executor> strand,
    std::weak_ptr<ConnectionImpl> connection, ua::Logger logger);

  /// True when the router must not route (stopped, or the Connection is terminal / gone). Strand-only.
  [[nodiscard]] static bool routing_suspended(const EventRouter& self, const ConnectionImpl& connection);

  /// True when there is a live consumer for the routed events (J57 subscribe-gate): an AddressSpaceObserver
  /// (model / semantic) or AlarmObserver (audit) is registered, OR the address-space cache is enabled. When
  /// no consumer exists the router does NOT subscribe  -  creating server-side event Subscriptions /
  /// MonitoredItems for events nobody consumes is pure overhead. Re-evaluating the gate on a late observer
  /// registration is a documented follow-up. Strand-only.
  [[nodiscard]] static bool has_routing_consumer(const ConnectionImpl& connection);

  // No private strand: mStrand is ConnectionImpl's, injected at construction.
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::weak_ptr<ConnectionImpl> mConnection;
  ua::Logger mLogger;

  // Strand-only. mStarted latches the one-time subscribe; mStopped halts routing at close. mBackboneItems
  // retains the backbone MonitoredItem handles so they are not dropped (their teardown rides on the
  // pipeline / session close).
  bool mStarted = false;
  bool mStopped = false;
  std::vector<ua::client::MonitoredItem> mBackboneItems;
};

}  // namespace ua::client::detail

#endif  // UA_EVENT_ROUTER_H
