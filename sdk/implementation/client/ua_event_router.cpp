// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_event_router.h"

#include "ua_array.h"
#include "ua_connection_impl.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_subscriber.h"  // EventNotificationCallback / SubscribeResult
#include "ua_event_subscriber_impl.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_objecttype_id.h"
#include "ua_observer_sink.h"
#include "ua_on_strand.h"
#include "ua_ref_structure.h"
#include "ua_semantic_change_cache.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_structure.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>

#include <utility>

namespace ua::client::detail
{

namespace
{

// Source tags for the untrusted-input advisories (the design specification: an ErrorDetail / advisory is
// never silently discarded  -  a malformed server `Changes` payload is logged, then the event is skipped).
constexpr std::string_view modelDecodeSource = "client.tier1.event_router.model_change_decode";
constexpr std::string_view semanticDecodeSource = "client.tier1.event_router.semantic_change_decode";

// A GeneralModelChangeEvent whose `Changes` array is PRESENT but zero-length is a server protocol violation
// (Part 5 section 6.4.32: the array "shall contain at least one entry"). Per CL-EVT-003 the event is DROPPED
// -  a distinct source so `client_general_model_change_with_empty_changes_dropped` can assert the drop
// advisory.
constexpr std::string_view modelEmptyChangesSource = "client.tier1.event_router.model_change_empty_changes";

// The field name the model / semantic change arrays are delivered under (both types name it "Changes").
constexpr std::string_view changesField = "Changes";
constexpr std::string_view systemStateField = "SystemState";
constexpr std::string_view progressContextField = "Context";
constexpr std::string_view progressField = "Progress";

}  // namespace

std::vector<ModelChangeVerb> model_change_verbs_from_mask(std::uint8_t mask)
{
  // The wire `ModelChangeStructureVerbMask` is a bitmask that may name several verbs at once; expand it to
  // the internal per-verb enums (mask-bit order). Unknown / reserved bits are ignored (forward-compatible
  // skip).
  std::vector<ModelChangeVerb> verbs;
  const auto has = [mask](ua::ModelChangeStructureVerbMask bit)
  {
    return (mask & static_cast<std::uint8_t>(bit)) != 0;
  };
  if (has(ua::ModelChangeStructureVerbMask::NodeAdded))
  {
    verbs.push_back(ModelChangeVerb::NodeAdded);
  }
  if (has(ua::ModelChangeStructureVerbMask::NodeDeleted))
  {
    verbs.push_back(ModelChangeVerb::NodeDeleted);
  }
  if (has(ua::ModelChangeStructureVerbMask::ReferenceAdded))
  {
    verbs.push_back(ModelChangeVerb::ReferenceAdded);
  }
  if (has(ua::ModelChangeStructureVerbMask::ReferenceDeleted))
  {
    verbs.push_back(ModelChangeVerb::ReferenceDeleted);
  }
  if (has(ua::ModelChangeStructureVerbMask::DataTypeChanged))
  {
    verbs.push_back(ModelChangeVerb::DataTypeChanged);
  }
  return verbs;
}

std::optional<ModelChangeDecode> decode_model_change_event(const ua::client::EventNotification& notification,
  ModelChangeNotification::Kind eventKind, const ua::Logger& logger)
{
  ModelChangeDecode out;

  // A BaseModelChangeEvent (for a View) carries no per-node Changes: it is a wholesale flush of everything
  // reachable from the View (section 9.6.19.4). The cache lacks a reachable-from-View index, so it drops
  // everything.
  if (eventKind == ModelChangeNotification::Kind::Base)
  {
    out.cacheNotification.kind = ModelChangeNotification::Kind::Base;
    out.cacheNotification.view = notification.sourceNode;
    return out;
  }

  // GeneralModelChangeEvent: the per-node `Changes` array. ABSENT / null-Variant  implies  CONSERVATIVE full
  // flush. The router now subscribes the GeneralModelChange backbone WITH a "Changes" SelectClause (Slice 2b,
  // EventRouter::start / subscribe_to_type_with_field_async), so a conformant server delivers the enumerated
  // per-node changes and the branch below applies them surgically. This null-Changes branch remains the
  // conservative fallback for a server that omits the field anyway: the client cannot see the enumerated
  // changes, so it OVER-invalidates (full flush) rather than miss one (the design specification
  // section 9.6.19). A PRESENT-but-empty array is a DIFFERENT case (handled below): the server explicitly
  // enumerated "no changes", which is a protocol violation and is DROPPED, not flushed.
  const std::optional<ua::Variant> changes = notification.field(changesField);
  if (!changes.has_value() || changes->empty())
  {
    out.cacheNotification.kind = ModelChangeNotification::Kind::Base;
    out.cacheNotification.view = notification.sourceNode;
    return out;
  }

  // Untrusted server input: a `Changes` that is present but not an array of structure is malformed. Advisory,
  // then skip (no crash, no cache mutation, no observer fire).
  if (!changes->is_array_of_structure())
  {
    logger.warning("GeneralModelChangeEvent Changes field is not an array of structure; skipping event [{}]",
      modelDecodeSource);
    return std::nullopt;
  }
  try
  {
    // The array is already decoded to concrete NS0 structures by the wire codec (the registered
    // StructureFactory reconstructs each ExtensionObject)  -  mirror the ua_server_diagnostics_access.cpp /
    // ua_data_access.cpp `Array<RefStructure<Structure>>` + dynamic_cast idiom. The array is fully
    // materialised in memory, bounded by the wire decoder's depth / size caps, so no additional bound is
    // needed here.
    const auto& array = changes->as<ua::Array<ua::RefStructure<ua::Structure>>>();
    // CL-EVT-003: a GeneralModelChangeEvent whose Changes array is PRESENT but zero-length is a server
    // protocol violation (Part 5 section 6.4.32: the array "shall contain at least one entry"). Per
    // `client_general_model_change_with_empty_changes_dropped` the event is DROPPED  -  NOT a full flush: the
    // server explicitly enumerated "no changes", so over-invalidating the whole address space would be wrong.
    // Source-tagged advisory, then skip (no cache mutation, no observer fire). `Variant::empty()` above only
    // detects a null Variant, not a zero-length array, so this is the sole present-but-empty check.
    if (array.payload().empty())
    {
      logger.warning(
        "GeneralModelChangeEvent Changes array is present but empty (server must send >=1 entry); dropping "
        "event [{}]",
        modelEmptyChangesSource);
      return std::nullopt;
    }
    out.cacheNotification.kind = ModelChangeNotification::Kind::General;
    for (const auto& element : array.payload())
    {
      const auto* entry = dynamic_cast<const ua::ModelChangeStructureDataType*>(element.get());
      if (entry == nullptr)
      {
        // Heterogeneous / wrong element type  -  a protocol violation. Advisory, then skip the whole event
        // (consistent with the diagnostics-array decode; do not partially apply an ambiguous payload).
        logger.warning(
          "GeneralModelChangeEvent Changes array holds a non-ModelChangeStructureDataType element; skipping "
          "event [{}]",
          modelDecodeSource);
        return std::nullopt;
      }
      // Public observer struct: keep affectedType + the raw verb mask verbatim.
      ua::client::ModelChangeStructure observerChange;
      observerChange.affected = entry->affected();
      observerChange.affectedType = entry->affected_type();
      observerChange.verb = entry->verb();
      out.observerChanges.push_back(std::move(observerChange));
      // Internal cache change(s): drop affectedType, expand the verb mask to one ModelChange per set bit.
      for (const ModelChangeVerb verb : model_change_verbs_from_mask(entry->verb()))
      {
        out.cacheNotification.changes.push_back(ModelChange{entry->affected(), verb});
      }
    }
    return out;
  }
  catch (...)
  {
    logger.warning(
      "GeneralModelChangeEvent Changes field failed to decode; skipping event [{}]", modelDecodeSource);
    return std::nullopt;
  }
}

std::optional<SemanticChangeDecode> decode_semantic_change_event(
  const ua::client::EventNotification& notification, const ua::Logger& logger)
{
  SemanticChangeDecode out;

  const std::optional<ua::Variant> changes = notification.field(changesField);
  if (!changes.has_value() || changes->empty())
  {
    return out;  // nothing to invalidate / report
  }
  if (!changes->is_array_of_structure())
  {
    logger.warning("SemanticChangeEvent Changes field is not an array of structure; skipping event [{}]",
      semanticDecodeSource);
    return std::nullopt;
  }
  try
  {
    const auto& array = changes->as<ua::Array<ua::RefStructure<ua::Structure>>>();
    for (const auto& element : array.payload())
    {
      const auto* entry = dynamic_cast<const ua::SemanticChangeStructureDataType*>(element.get());
      if (entry == nullptr)
      {
        logger.warning(
          "SemanticChangeEvent Changes array holds a non-SemanticChangeStructureDataType element; skipping "
          "event [{}]",
          semanticDecodeSource);
        return std::nullopt;
      }
      out.affected.push_back(entry->affected());
      ua::client::SemanticChangeStructure observerChange;
      observerChange.affected = entry->affected();
      observerChange.affectedType = entry->affected_type();
      out.observerChanges.push_back(std::move(observerChange));
    }
    return out;
  }
  catch (...)
  {
    logger.warning(
      "SemanticChangeEvent Changes field failed to decode; skipping event [{}]", semanticDecodeSource);
    return std::nullopt;
  }
}

std::shared_ptr<EventRouter> EventRouter::create(boost::asio::strand<boost::asio::any_io_executor> strand,
  std::weak_ptr<ConnectionImpl> connection, ua::Logger logger)
{
  return std::shared_ptr<EventRouter>(
    new EventRouter(std::move(strand), std::move(connection), std::move(logger)));
}

EventRouter::EventRouter(boost::asio::strand<boost::asio::any_io_executor> strand,
  std::weak_ptr<ConnectionImpl> connection, ua::Logger logger)
  : mStrand(std::move(strand)), mConnection(std::move(connection)), mLogger(std::move(logger))
{}

void EventRouter::start()
{
  // Strand-only (driven from ConnectionImpl::on_first_session_active). Idempotent.
  if (mStarted || mStopped)
  {
    return;
  }
  auto connection = mConnection.lock();
  if (!connection)
  {
    return;
  }
  // J57 subscribe-gate: only create server-side event Subscriptions / MonitoredItems when there is a
  // consumer to route to (an AddressSpace / Alarm observer, or the address-space cache enabled). mStarted is
  // NOT latched when the gate fails, so a future re-evaluation hook (late-observer refinement) can subscribe.
  if (!has_routing_consumer(*connection))
  {
    return;
  }
  auto subscriber = connection->events_impl();
  if (!subscriber)
  {
    // Defensive (N): latch mStarted only AFTER a subscriber is in hand, so a (hypothetical) null events_impl
    // does not permanently suppress subscription  -  a later start() (e.g. a late-observer re-eval) retries.
    return;
  }
  mStarted = true;

  // J57: subscribe eagerly to the routed event types at first-active. The GeneralModelChange and
  // SemanticChange backbones carry an extra "Changes" SelectClause (Slice 2b) so a live event delivers its
  // per-node ModelChangeStructure[] / SemanticChangeStructure[] array  -  `handle_model_event` then
  // invalidates the SPECIFIC affected NodeIds (CL-EVT-003 per-node invalidation) instead of conservatively
  // full-flushing, and `handle_semantic_event` sees the affected nodes (CL-EVT-004). Each of those two
  // subscribes on its OWN dedicated backbone (subscribe_to_type_with_field_async) so the per-type "Changes"
  // clause is unambiguous: both types name the field "Changes" but with different types, and
  // `EventNotification::field("Changes")` is browse-name keyed. Base + Audit have no Changes field and stay
  // on the shared Server backbone.
  auto weakSelf = weak_from_this();

  const auto retain = [weakSelf, strand = mStrand, logger = mLogger](SubscribeResult result)
  {
    // Retain the backbone MonitoredItem handle (strand-only) so it is not dropped. A failed subscribe is a
    // best-effort advisory  -  the router simply routes nothing for that type  -  but the failure's
    // ErrorDetail is LOGGED at this boundary before it is dropped (the design specification: never silently
    // discard an ErrorDetail). A backbone created with a Good subcode or an Uncertain code exists, so it is
    // retained.
    if (!result.has_value())
    {
      logger.warning(
        "event routing backbone subscribe failed (0x{:08x}); this event type will not route [{}]",
        result.status_code().as_uint32(),
        modelDecodeSource);
      return;
    }
    // Append the retained handle on the connection strand (mBackboneItems is strand-only). The subscribe
    // completion fires on the executor, so re-marshal; a gone router no-ops.
    ua::async::post_borrowing(weakSelf,
      strand,
      logger,
      [work = [weakSelf, item = result.value()]() mutable
        {
          if (auto self = weakSelf.lock())
          {
            // Defensive (N): a subscribe completion can land on its strand turn AFTER stop() cleared the
            // vector  -  drop the handle rather than re-populate the cleared mBackboneItems.
            if (self->mStopped)
            {
              return;
            }
            self->mBackboneItems.push_back(std::move(item));
          }
        }](auto&) mutable { work(); })();
  };

  subscriber->subscribe_to_type_with_field_async(
    ua::NodeId{ua::ObjectTypeId::GeneralModelChangeEventType},
    changesField,
    [weakSelf](ua::client::EventNotification notification)
    {
      if (auto self = weakSelf.lock())
      {
        self->handle_model_event(std::move(notification), ModelChangeNotification::Kind::General);
      }
    },
    retain);

  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::BaseModelChangeEventType},
    [weakSelf](ua::client::EventNotification notification)
    {
      if (auto self = weakSelf.lock())
      {
        self->handle_model_event(std::move(notification), ModelChangeNotification::Kind::Base);
      }
    },
    retain);

  subscriber->subscribe_to_type_with_field_async(
    ua::NodeId{ua::ObjectTypeId::SemanticChangeEventType},
    changesField,
    [weakSelf](ua::client::EventNotification notification)
    {
      if (auto self = weakSelf.lock())
      {
        self->handle_semantic_event(std::move(notification));
      }
    },
    retain);

  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditEventType},
    [weakSelf](ua::client::EventNotification notification)
    {
      if (auto self = weakSelf.lock())
      {
        self->handle_audit_event(std::move(notification));
      }
    },
    retain);

  subscriber->subscribe_to_type_with_field_async(
    ua::NodeId{ua::ObjectTypeId::SystemStatusChangeEventType},
    systemStateField,
    [weakSelf](ua::client::EventNotification notification)
    {
      if (auto self = weakSelf.lock())
      {
        self->handle_system_status_event(std::move(notification));
      }
    },
    retain);

  subscriber->subscribe_to_type_with_fields_async(
    ua::NodeId{ua::ObjectTypeId::ProgressEventType},
    {progressContextField, progressField},
    [weakSelf](ua::client::EventNotification notification)
    {
      if (auto self = weakSelf.lock())
      {
        self->handle_progress_event(std::move(notification));
      }
    },
    retain);

  // DeviceFailureEventType has exactly one consumer - ServerStateObserver::on_device_failure - and no
  // cache or other internal use, so it is subscribed only when that observer is installed. The other
  // routed types either feed the address-space cache or serve several consumers, which is why they
  // ride the has_routing_consumer gate alone. Claims the optional CU Base Info Client Device Failure.
  if (const auto sink = connection->observer_sink())
  {
    const auto slots = sink->slots();
    if (slots && slots->serverState != nullptr)
    {
      subscriber->subscribe_to_type_async(
        ua::NodeId{ua::ObjectTypeId::DeviceFailureEventType},
        [weakSelf](ua::client::EventNotification notification)
        {
          if (auto self = weakSelf.lock())
          {
            self->handle_device_failure_event(std::move(notification));
          }
        },
        retain);
    }
  }
}

void EventRouter::handle_device_failure_event(ua::client::EventNotification notification)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [notification = std::move(notification)](EventRouter& self) mutable
    {
      auto connection = self.mConnection.lock();
      if (!connection || routing_suspended(self, *connection))
      {
        return;
      }
      if (auto sink = connection->observer_sink())
      {
        sink->fire_device_failure(std::move(notification));
      }
    })();
}

void EventRouter::stop()
{
  // Strand-only (driven from ConnectionImpl::begin_close). Idempotent. The backbone MonitoredItems are torn
  // down by the SubscriptionsPipeline / session close  -  the router issues no DeleteMonitoredItems on a
  // closing session (FU-1). Dropping the retained handles here just releases the router's references.
  mStopped = true;
  mBackboneItems.clear();
}

bool EventRouter::has_routing_consumer(const ConnectionImpl& connection)
{
  if (auto sink = connection.observer_sink())
  {
    if (auto slots = sink->slots())
    {
      // AddressSpaceObserver consumes model + semantic changes; AlarmObserver consumes audit events;
      // ServerStateObserver consumes SystemStatusChange events.
      if (slots->addressSpace != nullptr || slots->alarm != nullptr || slots->serverState != nullptr)
      {
        return true;
      }
    }
  }
  // J57's "or a cache is enabled" arm: the address-space cache is a model-change flush target even without an
  // observer (CL-EVT-003)  -  an enabled cache must receive GeneralModelChange / BaseModelChange
  // invalidations, so the router subscribes the routed NS0 event types at first-active even with no observer.
  // Read the policy via the immutable `address_space_cache_enabled()` accessor, NOT `address_space_cache()`,
  // so this does not force-construct (`call_once`) an inert cache merely to read `enabled()` when disabled
  // (Slice 2a: the ConnectionConfig cache policy is now threaded through  -  the prior W8a "not yet threaded"
  // note is stale).
  return connection.address_space_cache_enabled();
}

bool EventRouter::routing_suspended(const EventRouter& self, const ConnectionImpl& connection)
{
  if (self.mStopped)
  {
    return true;
  }
  const auto info = connection.info();
  if (!info)
  {
    return false;
  }
  switch (info->state)
  {
  case ConnectionState::Closing:
  case ConnectionState::Closed:
  case ConnectionState::Failed:
    return true;
  case ConnectionState::Connecting:
  case ConnectionState::Active:
  case ConnectionState::Reconnecting:
    return false;
  }
  return false;
}

void EventRouter::handle_model_event(
  ua::client::EventNotification notification, ModelChangeNotification::Kind eventKind)
{
  // Executor thread, UNSERIALIZED: re-marshal onto the connection strand before decoding the untrusted
  // payload and touching the caches (post_borrowing weak-locks this router; a gone router no-ops).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [notification = std::move(notification), eventKind](EventRouter& self) mutable
    {
      auto connection = self.mConnection.lock();
      if (!connection || routing_suspended(self, *connection))
      {
        return;
      }
      std::optional<ModelChangeDecode> decoded =
        decode_model_change_event(notification, eventKind, self.mLogger);
      if (!decoded.has_value())
      {
        return;  // malformed untrusted input  -  advisory already logged in the decode
      }
      auto cache = connection->address_space_cache();
      auto sink = connection->observer_sink();
      // CL-EVT-003: invalidate the AddressSpaceCache FIRST (section 8.7.4), THEN fire the observer  -  chain
      // the observer fire on the cache-flush completion so the ordering holds regardless of executor
      // threading.
      auto observerChanges = std::move(decoded->observerChanges);
      if (cache)
      {
        cache->on_model_change_async(std::move(decoded->cacheNotification),
          [sink, observerChanges = std::move(observerChanges)]() mutable
          {
            if (sink)
            {
              sink->fire_model_change(std::move(observerChanges));
            }
          });
      }
      else if (sink)
      {
        sink->fire_model_change(std::move(observerChanges));
      }
    })();
}

void EventRouter::handle_semantic_event(ua::client::EventNotification notification)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [notification = std::move(notification)](EventRouter& self) mutable
    {
      auto connection = self.mConnection.lock();
      if (!connection || routing_suspended(self, *connection))
      {
        return;
      }
      std::optional<SemanticChangeDecode> decoded = decode_semantic_change_event(notification, self.mLogger);
      if (!decoded.has_value())
      {
        return;  // malformed untrusted input  -  advisory already logged
      }
      // CL-EVT-004: route the semantic change to the dedicated DA-property SemanticChangeCache (section 8.18)
      // and DO NOT touch the AddressSpaceCache  -  a semantic change alters metadata interpretation only; the
      // value / attribute caches stay valid.
      if (!decoded->affected.empty())
      {
        if (auto semanticCache = connection->semantic_change_cache())
        {
          semanticCache->invalidate_async(std::move(decoded->affected));
        }
      }
      if (!decoded->observerChanges.empty())
      {
        if (auto sink = connection->observer_sink())
        {
          // CL-EVT-004 + CL-DA-011: a SemanticChangeEvent fires BOTH on_model_change AND on_semantic_change
          // so the DA typed-accessor cache-invalidation path receives the same signal regardless of trigger
          // origin (event flavour vs the in-band `SemanticsChanged` status bit  -  the two routes must not
          // branch on origin). A semantic change carries no structural verb, so each mapped
          // ModelChangeStructure has verb = 0. Build the model-change list BEFORE moving observerChanges into
          // the semantic fire. The AddressSpaceCache is still left untouched (guaranteed by never reaching
          // for it on this path)  -  only the OBSERVER's on_model_change fan-out receives the signal.
          std::vector<ua::client::ModelChangeStructure> modelChanges;
          modelChanges.reserve(decoded->observerChanges.size());
          for (const auto& semanticChange : decoded->observerChanges)
          {
            ua::client::ModelChangeStructure modelChange;
            modelChange.affected = semanticChange.affected;
            modelChange.affectedType = semanticChange.affectedType;
            modelChange.verb = 0;
            modelChanges.push_back(std::move(modelChange));
          }
          sink->fire_model_change(std::move(modelChanges));
          sink->fire_semantic_change(std::move(decoded->observerChanges));
        }
      }
    })();
}

void EventRouter::handle_audit_event(ua::client::EventNotification notification)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [notification = std::move(notification)](EventRouter& self) mutable
    {
      auto connection = self.mConnection.lock();
      if (!connection || routing_suspended(self, *connection))
      {
        return;
      }
      // Audit events are a pass-through to the observer  -  no decode, no cache.
      if (auto sink = connection->observer_sink())
      {
        sink->fire_audit_event(std::move(notification));
      }
    })();
}

void EventRouter::handle_progress_event(ua::client::EventNotification notification)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [notification = std::move(notification)](EventRouter& self) mutable
    {
      auto connection = self.mConnection.lock();
      if (!connection || routing_suspended(self, *connection))
        return;
      auto sink = connection->observer_sink();
      if (!sink)
        return;

      const auto context = notification.field(progressContextField);
      const auto progress = notification.field(progressField);
      if (!context || !progress)
      {
        const std::string_view missing = context ? progressField : progressContextField;
        sink->fire_advisory_diagnostic(ua::ErrorDetail::build("ProgressFieldInvalid",
          "A mandatory ProgressEventType field is absent",
          "client.tier2.event_router.progress_field_invalid")
                                         .context(ua::ContextKeys::fieldName, std::string{missing}));
        sink->fire_progress_event(std::move(notification));
        return;
      }

      const auto decodedProgress = progress->to<std::uint16_t>();
      if (!decodedProgress.has_value())
      {
        sink->fire_advisory_diagnostic(ua::ErrorDetail::build("ProgressFieldInvalid",
          "ProgressEventType.Progress has the wrong type",
          "client.tier2.event_router.progress_field_invalid")
                                         .context(ua::ContextKeys::fieldName, std::string{progressField}));
        sink->fire_progress_event(std::move(notification));
        return;
      }

      ua::client::ProgressEventFields decoded;
      decoded.context = *context;
      decoded.progress = decodedProgress.value();
      const std::string_view sourceName = notification.sourceName;
      decoded.sourceKind = sourceName.starts_with("Service/") ? ua::client::ProgressSourceKind::Service
                                                              : ua::client::ProgressSourceKind::Application;
      if (decoded.sourceKind == ua::client::ProgressSourceKind::Service)
      {
        const auto requestHandle = context->to<std::uint32_t>();
        if (requestHandle.is_good())
          decoded.requestHandle = requestHandle.value();
        else
          sink->fire_advisory_diagnostic(
            ua::ErrorDetail::build("ProgressContextDecodeMismatch",
              "Service ProgressEventType.Context is not a UInt32 requestHandle",
              "client.tier2.event_router.progress_context_decode_mismatch")
              .context(ua::ContextKeys::fieldName, std::string{progressContextField}));
      }
      if (decoded.progress > 100U)
      {
        sink->fire_advisory_diagnostic(ua::ErrorDetail::build("ProgressOutOfRange",
          "ProgressEventType.Progress exceeds the permitted percentage range",
          "client.tier2.event_router.progress_out_of_range")
                                         .context(ua::ContextKeys::sizeActual, decoded.progress)
                                         .context(ua::ContextKeys::sizeMax, 100U));
        decoded.progress = 100U;
      }
      notification.progress = std::move(decoded);
      sink->fire_progress_event(std::move(notification));
    })();
}

void EventRouter::handle_system_status_event(ua::client::EventNotification notification)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [notification = std::move(notification)](EventRouter& self) mutable
    {
      auto connection = self.mConnection.lock();
      if (!connection || routing_suspended(self, *connection))
      {
        return;
      }
      const std::optional<ua::Variant> stateField = notification.field(systemStateField);
      if (!stateField.has_value())
      {
        self.mLogger.warning(
          "SystemStatusChangeEvent missing mandatory SystemState; event dropped [{}]", modelDecodeSource);
        return;
      }
      const ua::Result<std::int32_t> encodedState = stateField->to<std::int32_t>();
      if (!encodedState.has_value())
      {
        self.mLogger.warning(
          "SystemStatusChangeEvent has undecodable SystemState; event dropped [{}]", modelDecodeSource);
        return;
      }
      const auto state = static_cast<ua::ServerState>(encodedState.value());
      if (!ua::is_valid(state))
      {
        self.mLogger.warning(
          "SystemStatusChangeEvent has unknown SystemState; event dropped [{}]", modelDecodeSource);
        return;
      }
      if (auto sink = connection->observer_sink())
      {
        const SystemStatusOrigin origin = notification.sourceNode == ua::NodeId{ua::ObjectId::Server}
                                            ? SystemStatusOrigin::Server
                                            : SystemStatusOrigin::UnderlyingSystem;
        sink->fire_system_status_change(
          std::move(notification.sourceNode), std::move(notification.sourceName), state, origin);
      }
    })();
}

}  // namespace ua::client::detail
