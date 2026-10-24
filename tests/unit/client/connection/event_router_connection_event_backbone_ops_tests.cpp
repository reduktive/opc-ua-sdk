// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::EventRouter (Slice W8b) - the EventSubscriber->observer/cache routing
// router (client design section 8.13 / section 8.7 / section 8.18). Two layers:
//   1. The PURE decode module (decode_model_change_event / decode_semantic_change_event /
//      model_change_verbs_from_mask) - driven with scripted EventNotifications carrying a well-formed /
//      empty / malformed "Changes" Variant. No ConnectionImpl, no strand, no infra.
//   2. The ROUTER, driven through a real ConnectionImpl (TA::create_with_ops + FakeSessionOps) with fake
//      observers + a registered SemanticChangeCache state: handle_model_event / handle_semantic_event /
//      handle_audit_event are driven with scripted notifications on the REAL decode + route code path, and
//      the observable fan-out (observer fires, semantic-cache invalidation, address-space cache NOT touched)
//      is asserted.
//
// @verifies CL-EVT-003 - GeneralModelChange/BaseModelChange route into the AddressSpaceCache flush + the
// @relation(CL-EVT-003, scope=file)
//           AddressSpaceObserver::on_model_change fan-out. A GeneralModelChange with a PRESENT-but-empty
//           Changes array is DROPPED (client_general_model_change_with_empty_changes_dropped), not flushed.
// @verifies CL-EVT-004 / CL-DA-011 - SemanticChange invalidates the SemanticChangeCache and fires BOTH
// @relation(CL-DA-011, CL-EVT-004, scope=file)
//           on_semantic_change AND on_model_change (the DA typed-accessor invalidation path gets the same
//           signal regardless of origin), while the AddressSpaceCache itself is NOT invalidated.

#include "fake_session_ops.h"

#include "ua_address_space_cache.h"
#include "ua_address_space_cache_policy.h"
#include "ua_address_space_cache_test_access.h"
#include "ua_array.h"
#include "ua_client_monitored_item.h"
#include "ua_client_observers.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_connection_event_backbone_ops.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_error_detail.h"
#include "ua_reference_description.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_router.h"
#include "ua_event_subscriber.h"
#include "ua_event_subscriber_impl.h"
#include "ua_event_subscriber_test_access.h"
#include "ua_logger.h"
#include "ua_objecttype_id.h"
#include "ua_simple_attribute_operand.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_ref_structure.h"
#include "ua_semantic_change_cache.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_variant.h"

#include "async_test_runtime.h"

#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::NodeId;
using ua::client::AddressSpaceObserver;
using ua::client::AlarmObserver;
using ua::client::ConnectionObserver;
using ua::client::EventNotification;
using ua::client::ModelChangeStructure;
using ua::client::SemanticChangeStructure;
using ua::client::ServerStateObserver;
using ua::client::SystemStatusOrigin;
using ua::client::detail::AddressSpaceCache;
using ua::client::detail::AddressSpaceCacheTestAccess;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::decode_model_change_event;
using ua::client::detail::decode_semantic_change_event;
using ua::client::detail::EventRouter;
using ua::client::detail::EventSubscriberImpl;
using ua::client::detail::EventSubscriberTestAccess;
using ua::client::detail::model_change_verbs_from_mask;
using ua::client::detail::ModelChangeNotification;
using ua::client::detail::ModelChangeVerb;
using ua::client::detail::TypedPropertiesState;
using ua::client::detail::WireOps;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

NodeId node(std::uint32_t id)
{
  return NodeId{std::uint16_t{1}, id};
}

/// Wraps a decoded array-of-structure into a Variant "Changes" payload (as the wire codec would deliver it).
ua::Variant model_changes_variant(const std::vector<std::tuple<NodeId, NodeId, std::uint8_t>>& changes)
{
  ua::Array<ua::RefStructure<ua::Structure>> array;
  for (const auto& [affected, affectedType, verb] : changes)
  {
    auto entry = std::make_unique<ua::ModelChangeStructureDataType>();
    entry->affected() = affected;
    entry->affected_type() = affectedType;
    entry->verb() = verb;
    array.push_back(ua::RefStructure<ua::Structure>{std::move(entry)});
  }
  return ua::Variant{std::move(array)};
}

ua::Variant semantic_changes_variant(const std::vector<std::pair<NodeId, NodeId>>& changes)
{
  ua::Array<ua::RefStructure<ua::Structure>> array;
  for (const auto& [affected, affectedType] : changes)
  {
    auto entry = std::make_unique<ua::SemanticChangeStructureDataType>();
    entry->affected() = affected;
    entry->affected_type() = affectedType;
    array.push_back(ua::RefStructure<ua::Structure>{std::move(entry)});
  }
  return ua::Variant{std::move(array)};
}

/// A notification whose single selected field is "Changes" = @p changes (positional slot 0, named path).
EventNotification changes_notification(std::optional<ua::Variant> changes, NodeId source = {})
{
  EventNotification notification;
  notification.sourceNode = std::move(source);
  notification.fieldPaths.push_back({ua::QualifiedName{std::uint16_t{0}, ua::String{"Changes"}}});
  notification.fields.push_back(std::move(changes));
  return notification;
}

/// The single-segment browse name of a composite SelectClause, or empty.
std::string_view clause_field_name(const ua::SimpleAttributeOperand& clause)
{
  if (clause.browse_path().size() != 1)
  {
    return {};
  }
  return static_cast<std::string_view>(clause.browse_path()[0].name());
}

/// Build a wire EventFieldList that MATCHES @p composite positionally (one field per SelectClause, so the
/// production decode does not drop it on a field-count mismatch): EventType = @p eventType (slot for demux),
/// the "Changes" slot = @p changes IF the composite carries a Changes clause, every other field null. This is
/// what the server would echo on the router's backbone once the Changes SelectClause is present - and, absent
/// that clause, the Changes value has nowhere to go, so the delivered event carries no Changes -> the router
/// full-flushes (the RED baseline).
ua::EventFieldList composite_event_fields(const ua::EventFilter& composite, std::uint32_t backboneHandle,
  const NodeId& eventType, const ua::Variant& changes)
{
  ua::EventFieldList list;
  list.client_handle() = backboneHandle;
  for (const auto& clause : composite.select_clauses())
  {
    const std::string_view name = clause_field_name(clause);
    if (name == "EventType")
    {
      list.event_fields().push_back(ua::Variant{eventType});
    }
    else if (name == "Changes")
    {
      list.event_fields().push_back(changes);
    }
    else if (name == "EventId")
    {
      // The four BaseEventType fields Part 5 section 6.4.2 guarantees present-as-value - a real server always
      // sends them, so a spec-shaped model/semantic-change event carries them. Slice EV1 (CL-EVT-001)
      // hard-drops an event missing any of these, so they must be present here (not the null placeholder used
      // for the truly optional fields below).
      list.event_fields().push_back(ua::Variant{ua::ByteString{0x01, 0x02, 0x03}});
    }
    else if (name == "Time" || name == "ReceiveTime")
    {
      list.event_fields().push_back(ua::Variant{ua::DateTime{}});  // present-as-value (not the empty Variant)
    }
    else
    {
      list.event_fields().push_back(ua::Variant{});  // null placeholder for the truly optional fields
    }
  }
  return list;
}

template<class Pred>
bool wait_until(Pred pred, std::chrono::milliseconds timeout = 2s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return true;
    }
    std::this_thread::sleep_for(2ms);
  }
  return pred();
}

/// Thread-safe fake AddressSpaceObserver: the sink delivers hooks on its own delivery strand (a runner
/// thread), so the counters are atomic and the captured affected node is mutex-guarded.
class RecordingAddressSpaceObserver : public AddressSpaceObserver
{
public:
  std::atomic<int> modelChangeCalls{0};
  std::atomic<int> semanticChangeCalls{0};
  std::atomic<std::size_t> lastModelCount{0};
  std::atomic<std::size_t> lastSemanticCount{0};

  void on_model_change(const ua::client::Connection&, std::vector<ModelChangeStructure> changes) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastModelChanges = std::move(changes);
    }
    lastModelCount.store(mLastModelChanges.size());
    ++modelChangeCalls;
  }

  void on_semantic_change(
    const ua::client::Connection&, std::vector<SemanticChangeStructure> changes) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastSemanticChanges = std::move(changes);
    }
    lastSemanticCount.store(mLastSemanticChanges.size());
    ++semanticChangeCalls;
  }

  std::vector<ModelChangeStructure> model_changes() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastModelChanges;
  }

private:
  mutable std::mutex mMutex;
  std::vector<ModelChangeStructure> mLastModelChanges;
  std::vector<SemanticChangeStructure> mLastSemanticChanges;
};

/// Thread-safe fake AlarmObserver - only the audit-event hook is exercised here.
class RecordingAlarmObserver : public AlarmObserver
{
public:
  std::atomic<int> auditEventCalls{0};

  void on_audit_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditEventCalls;
  }
};

class RecordingServerStateObserver : public ServerStateObserver
{
public:
  struct Status
  {
    ua::NodeId sourceNode;
    ua::String sourceName;
    ua::ServerState state{ua::ServerState::Unknown};
    SystemStatusOrigin origin{SystemStatusOrigin::Server};
  };

  void on_system_status_change(const ua::client::Connection&, ua::NodeId sourceNode, ua::String sourceName,
    ua::ServerState state, SystemStatusOrigin origin) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mStatuses.push_back(Status{std::move(sourceNode), std::move(sourceName), state, origin});
  }

  void on_progress_event(const ua::client::Connection&, EventNotification event) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mProgressEvents.push_back(std::move(event));
  }

  std::vector<Status> statuses() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mStatuses;
  }

  std::vector<EventNotification> progress_events() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mProgressEvents;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Status> mStatuses;
  std::vector<EventNotification> mProgressEvents;
};

class RecordingAdvisoryObserver : public ConnectionObserver
{
public:
  void on_advisory_diagnostic(
    const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mDetails.push_back(std::move(detail));
  }

  std::vector<std::shared_ptr<const ua::ErrorDetail>> details() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mDetails;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::shared_ptr<const ua::ErrorDetail>> mDetails;
};

EventNotification system_status_notification(
  ua::NodeId sourceNode, std::string_view sourceName, ua::ServerState state)
{
  EventNotification notification;
  notification.eventTypeId = ua::NodeId{ua::ObjectTypeId::SystemStatusChangeEventType};
  notification.sourceNode = std::move(sourceNode);
  notification.sourceName = ua::String{std::string{sourceName}};
  notification.fieldPaths.push_back({ua::QualifiedName{std::uint16_t{0}, ua::String{"SystemState"}}});
  notification.fields.push_back(ua::Variant{static_cast<std::int32_t>(state)});
  return notification;
}

EventNotification progress_notification(
  std::string_view sourceName, ua::Variant context, ua::Variant progress)
{
  EventNotification notification;
  notification.eventTypeId = ua::NodeId{ua::ObjectTypeId::ProgressEventType};
  notification.sourceName = ua::String{std::string{sourceName}};
  notification.fieldPaths.push_back({ua::QualifiedName{0, ua::String{"Context"}}});
  notification.fields.push_back(std::move(context));
  notification.fieldPaths.push_back({ua::QualifiedName{0, ua::String{"Progress"}}});
  notification.fields.push_back(std::move(progress));
  return notification;
}

// ------------------------------- Pure decode tests (no infra) -------------------------------

TEST(EventRouterDecodeTest, VerbMaskExpandsEachSetBit)
{
  EXPECT_TRUE(model_change_verbs_from_mask(0).empty());

  const auto deleted =
    model_change_verbs_from_mask(static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::NodeDeleted));
  ASSERT_EQ(deleted.size(), 1U);
  EXPECT_EQ(deleted.front(), ModelChangeVerb::NodeDeleted);

  // A mask with several bits expands to one verb per bit, in bit order.
  const std::uint8_t both = static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::NodeAdded) |
                            static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::DataTypeChanged);
  const auto expanded = model_change_verbs_from_mask(both);
  ASSERT_EQ(expanded.size(), 2U);
  EXPECT_EQ(expanded[0], ModelChangeVerb::NodeAdded);
  EXPECT_EQ(expanded[1], ModelChangeVerb::DataTypeChanged);

  // Unknown / reserved bits are ignored (forward-compatible skip), not an error.
  EXPECT_TRUE(model_change_verbs_from_mask(static_cast<std::uint8_t>(0x80)).empty());
}

TEST(EventRouterDecodeTest, GeneralModelChangeDecodesPerNodeChanges)
{
  const std::uint8_t deleted = static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::NodeDeleted);
  auto notification =
    changes_notification(model_changes_variant({{node(5), node(58), deleted}}), /*source=*/node(85));

  const auto decoded =
    decode_model_change_event(notification, ModelChangeNotification::Kind::General, Logger{});
  ASSERT_TRUE(decoded.has_value());
  // Cache side: General, one ModelChange{node 5, NodeDeleted}, affectedType dropped.
  EXPECT_EQ(decoded->cacheNotification.kind, ModelChangeNotification::Kind::General);
  ASSERT_EQ(decoded->cacheNotification.changes.size(), 1U);
  EXPECT_EQ(decoded->cacheNotification.changes.front().affected, node(5));
  EXPECT_EQ(decoded->cacheNotification.changes.front().verb, ModelChangeVerb::NodeDeleted);
  // Observer side: keeps affected + affectedType + the raw uint8 verb mask.
  ASSERT_EQ(decoded->observerChanges.size(), 1U);
  EXPECT_EQ(decoded->observerChanges.front().affected, node(5));
  EXPECT_EQ(decoded->observerChanges.front().affectedType, node(58));
  EXPECT_EQ(decoded->observerChanges.front().verb, deleted);
}

TEST(EventRouterDecodeTest, GeneralModelChangeWithAbsentChangesIsFullFlush)
{
  // ABSENT / null-Variant Changes field -> CONSERVATIVE full flush (Kind::Base, view = sourceNode). This is
  // the flagged live-wire follow-up: with no "Changes" SelectClause the client cannot see the enumerated
  // changes, so it over-invalidates rather than miss one. (Distinct from a PRESENT-but-empty array, which is
  // dropped - see GeneralModelChangeWithPresentEmptyChangesIsDropped.)
  auto absent = changes_notification(std::nullopt, /*source=*/node(85));
  const auto decoded = decode_model_change_event(absent, ModelChangeNotification::Kind::General, Logger{});
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->cacheNotification.kind, ModelChangeNotification::Kind::Base);
  EXPECT_EQ(decoded->cacheNotification.view, node(85));
  EXPECT_TRUE(decoded->cacheNotification.changes.empty());
  EXPECT_TRUE(decoded->observerChanges.empty());
}

// @verifies CL-EVT-003 - client_general_model_change_with_empty_changes_dropped: a GeneralModelChangeEvent
// whose Changes array is PRESENT but zero-length is a server protocol violation (Part 5 section 6.4.32) and
// is DROPPED (nullopt) - NOT a full flush; the server explicitly enumerated "no changes".
// @relation(CL-EVT-003, scope=function)
TEST(EventRouterDecodeTest, GeneralModelChangeWithPresentEmptyChangesIsDropped)
{
  auto empty = changes_notification(model_changes_variant({}), /*source=*/node(86));
  const auto decodedEmpty =
    decode_model_change_event(empty, ModelChangeNotification::Kind::General, Logger{});
  EXPECT_FALSE(decodedEmpty.has_value())
    << "a present-but-empty Changes array must be DROPPED (nullopt), not turned into a full flush";
}

TEST(EventRouterDecodeTest, BaseModelChangeIsFullFlushForTheView)
{
  auto notification = changes_notification(std::nullopt, /*source=*/node(85));
  const auto decoded = decode_model_change_event(notification, ModelChangeNotification::Kind::Base, Logger{});
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->cacheNotification.kind, ModelChangeNotification::Kind::Base);
  EXPECT_EQ(decoded->cacheNotification.view, node(85));
  EXPECT_TRUE(decoded->observerChanges.empty());
}

TEST(EventRouterDecodeTest, MalformedModelChangesIsSkipped)
{
  // A "Changes" that is a scalar, not an array of structure -> nullopt (advisory), skip.
  auto scalar = changes_notification(ua::Variant{ua::String{"not-an-array"}});
  EXPECT_FALSE(
    decode_model_change_event(scalar, ModelChangeNotification::Kind::General, Logger{}).has_value());

  // Heterogeneous array (a SemanticChangeStructure element in a model-change decode) -> nullopt.
  auto heterogeneous = changes_notification(semantic_changes_variant({{node(9), node(90)}}));
  EXPECT_FALSE(
    decode_model_change_event(heterogeneous, ModelChangeNotification::Kind::General, Logger{}).has_value());
}

TEST(EventRouterDecodeTest, SemanticChangeDecodesAffectedNodes)
{
  auto notification = changes_notification(semantic_changes_variant({{node(7), node(70)}, {node(8), {}}}));
  const auto decoded = decode_semantic_change_event(notification, Logger{});
  ASSERT_TRUE(decoded.has_value());
  ASSERT_EQ(decoded->affected.size(), 2U);
  EXPECT_EQ(decoded->affected[0], node(7));
  EXPECT_EQ(decoded->affected[1], node(8));
  ASSERT_EQ(decoded->observerChanges.size(), 2U);
  EXPECT_EQ(decoded->observerChanges[0].affected, node(7));
  EXPECT_EQ(decoded->observerChanges[0].affectedType, node(70));
}

TEST(EventRouterDecodeTest, SemanticChangeEmptyIsNoop)
{
  auto notification = changes_notification(std::nullopt);
  const auto decoded = decode_semantic_change_event(notification, Logger{});
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->affected.empty());
  EXPECT_TRUE(decoded->observerChanges.empty());
}

TEST(EventRouterDecodeTest, MalformedSemanticChangesIsSkipped)
{
  auto scalar = changes_notification(ua::Variant{std::int32_t{42}});
  EXPECT_FALSE(decode_semantic_change_event(scalar, Logger{}).has_value());

  // A ModelChangeStructure element in a semantic decode -> heterogeneous -> nullopt.
  auto heterogeneous = changes_notification(model_changes_variant({{node(1), node(2), 1}}));
  EXPECT_FALSE(decode_semantic_change_event(heterogeneous, Logger{}).has_value());
}

// ------------------- Decode -> real AddressSpaceCache invalidation (CL-EVT-003 cache half)
// -------------------

// The router-owned cache is disabled by default (W8a), so this drives the ENABLED cache directly to prove the
// ModelChangeNotification the decode produces actually evicts the affected node from the real cache.
TEST(EventRouterDecodeTest, DecodedNotificationEvictsAffectedNodeFromEnabledCache)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  boost::asio::strand<boost::asio::any_io_executor> strand{runtime.executor()};
  ua::client::AddressSpaceCachePolicy policy;
  policy.enabled = true;
  auto cache = AddressSpaceCache::create(strand, std::weak_ptr<WireOps>{}, policy, Logger{});

  // Populate a static-attribute entry for node 5.
  ua::client::detail::AttributeEntry attributes;
  attributes.accessLevel = std::uint8_t{1};
  cache->install_attributes(node(5), attributes);
  ASSERT_TRUE(wait_until([&] { return AddressSpaceCacheTestAccess::attribute_count(*cache) == 1U; }));

  // Decode a NodeDeleted General model change for node 5, feed its cacheNotification to the real cache.
  const std::uint8_t deleted = static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::NodeDeleted);
  auto notification = changes_notification(model_changes_variant({{node(5), node(58), deleted}}));
  auto decoded = decode_model_change_event(notification, ModelChangeNotification::Kind::General, Logger{});
  ASSERT_TRUE(decoded.has_value());

  std::atomic<bool> done{false};
  cache->on_model_change_async(std::move(decoded->cacheNotification), [&done] { done.store(true); });
  ASSERT_TRUE(wait_until([&] { return done.load(); }));
  EXPECT_EQ(AddressSpaceCacheTestAccess::attribute_count(*cache), 0U)
    << "the decoded NodeDeleted model change must evict node 5 from the attribute cache (CL-EVT-003)";
}

// ----------------------------- Router tests through a real ConnectionImpl -----------------------------

class EventRouterConnectionTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();

  std::shared_ptr<ConnectionImpl> make_active_connection(ConnectionConfig config = {})
  {
    auto connection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      std::move(config),
      Logger{},
      mReopen->as_ops(),
      ua::client::Session::ActivateConfig{},
      ua::client::ReconnectPolicy{});
    std::promise<ua::VoidResult> started;
    auto future = started.get_future();
    connection->start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });
    future.get();
    return connection;
  }
};

TEST_F(EventRouterConnectionTest, StartSubscribesToFiveEventTypes)
{
  // start() gates on a routing consumer (J57): register an AddressSpaceObserver via config so a consumer is
  // present at first-active, when the router auto-subscribes. (Without a consumer the gate correctly
  // suppresses the backbone Subscriptions - that is a separate test.)
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  ConnectionConfig config;
  config.observers.addressSpace = observer;
  auto connection = make_active_connection(std::move(config));
  TA::start_event_routing(*connection);  // idempotent - already started at first-active with the consumer
  // The routed subscribes create/coalesce event backbones -> the tier-0 CreateMonitoredItems is issued
  // (via CreateSubscription). Falsifiable: a router that never subscribed issues no create.
  EXPECT_TRUE(wait_until([&] { return mSession->createMonitoredItems.call_count() >= 1U; }))
    << "start() must subscribe the routed event types (issuing CreateMonitoredItems on the backbone)";
  // The five consumers register on the event-subscriber strand as their backbone creates settle (async), so
  // poll the info snapshot rather than read it once.
  auto subscriber = connection->events_impl();
  EXPECT_TRUE(wait_until(
    [&]
    {
      auto info = subscriber->info();
      return info != nullptr && info->consumerCount == 6U;
    }))
    << "the router must register exactly six event consumers";
}

// @verifies CL-AC-003 - the Finding-2 event-loss interface must be WIRED IN PRODUCTION: wire_pipeline_and_ops must
// pass the loss callback into the pipeline it builds, else the lossy-gap -> ConditionRefresh resync signal
// fires into an empty std::function and condition state silently wedges in a real client (the exact defect
// the section 3.1 re-review caught). This pin drives the REAL construction path (create_with_ops ->
// wire_pipeline_and_ops), so it FAILS if that call reverts to the 5-arg `create` form - an injected-lambda
// pipeline unit test cannot catch that.
// @relation(CL-AC-003, scope=function)
TEST_F(EventRouterConnectionTest, WirePipelineWiresEventLossResyncCallback)
{
  auto connection = make_active_connection();
  EXPECT_TRUE(TA::pipeline_has_event_loss_callback(*connection))
    << "wire_pipeline_and_ops must wire the lossy-gap event-loss resync callback into the pipeline it builds "
       "(else the A&C ConditionRefresh resync is dead in production)";
}

// @verifies CL-EVT-003 - the J57 "or a cache is enabled" arm: an enabled address-space cache is a
// model-change flush target even with NO observer, so the router must subscribe the routed NS0 event types at
// first-active. (Slice 2a lit this arm - before, has_routing_consumer's cache arm was force-disabled and the
// router suppressed the subscribe.) Falsifiable: a router whose cache arm stays dark issues no create here.
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, EnabledCacheWithoutObserverSubscribesFiveEventTypes)
{
  ConnectionConfig config;
  config.addressSpaceCache.enabled = true;  // enable the cache, register NO observer
  auto connection = make_active_connection(std::move(config));
  TA::start_event_routing(
    *connection);  // idempotent - already started at first-active with the cache arm lit
  EXPECT_TRUE(wait_until([&] { return mSession->createMonitoredItems.call_count() >= 1U; }))
    << "an enabled cache (no observer) must still subscribe the routed event types (CL-EVT-003 flush target)";
  auto subscriber = connection->events_impl();
  EXPECT_TRUE(wait_until(
    [&]
    {
      auto info = subscriber->info();
      return info != nullptr && info->consumerCount == 6U;
    }))
    << "the router must register exactly six event consumers for the enabled cache";
}

// @verifies CL-EVT-003 - the gate guard: a DISABLED cache with NO observer has no routing consumer, so the
// router must subscribe NOTHING (creating backbone Subscriptions for events nobody consumes is pure
// overhead). Falsifiable: a gate that returns true unconditionally issues a create and fails here.
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, DisabledCacheWithoutObserverSubscribesNothing)
{
  ConnectionConfig config;
  config.addressSpaceCache.enabled = false;  // default: disabled cache, no observer
  auto connection = make_active_connection(std::move(config));
  TA::snapshot(*connection);  // barrier: first-active (and its gated-off router start) has been processed
  EXPECT_EQ(mSession->createMonitoredItems.call_count(), 0U)
    << "with no observer and a disabled cache the router must NOT subscribe (J57 gate)";
}

TEST_F(EventRouterConnectionTest, GeneralModelEventFiresObserver)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  connection->set_address_space_observer_async(observer);
  TA::snapshot(*connection);  // barrier the setter

  const std::uint8_t deleted = static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::NodeDeleted);
  auto notification = changes_notification(model_changes_variant({{node(5), node(58), deleted}}));
  TA::event_router(*connection)
    ->handle_model_event(std::move(notification), ModelChangeNotification::Kind::General);

  ASSERT_TRUE(wait_until([&] { return observer->modelChangeCalls.load() >= 1; }))
    << "a General model event must fire AddressSpaceObserver::on_model_change (CL-EVT-003)";
  EXPECT_EQ(observer->semanticChangeCalls.load(), 0);
  const auto changes = observer->model_changes();
  ASSERT_EQ(changes.size(), 1U);
  EXPECT_EQ(changes.front().affected, node(5));
  EXPECT_EQ(changes.front().verb, deleted);
}

// @verifies CL-EVT-003 - the router half of the browse read-surface invalidation: a GeneralModelChange with
// an INVALIDATING verb (ReferenceDeleted) delivered THROUGH the router (the real decode + route path, not a
// direct cache drive) flushes the affected node's cached Browse page. The AddressSpaceCache-unit half lives
// in the AddressSpaceCache suite; this proves the wire->router->cache route actually reaches install/erase.
// Falsifier: a router that never routes the model change into the cache leaves the entry present.
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, GeneralModelChangeFlushesBrowseCacheEntryThroughRouter)
{
  ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  auto connection = make_active_connection(std::move(config));

  // Prime a Browse cache entry for node 5. The install happens-before the router flush (the test thread
  // writes the LruMap, then the handle_model_event post carries that write to the strand handler), so no data
  // race.
  auto cache = connection->address_space_cache();
  ua::client::detail::CachedBrowseKey key;
  key.node = node(5);
  ua::client::detail::BrowseEntry entry;
  entry.installedAt = std::chrono::steady_clock::now();
  cache->install_browse(key, entry);
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 1U);

  // Route a ReferenceDeleted General model change for node 5 through the router (browse-only invalidation).
  const std::uint8_t referenceDeleted =
    static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::ReferenceDeleted);
  auto notification = changes_notification(model_changes_variant({{node(5), node(58), referenceDeleted}}));
  TA::event_router(*connection)
    ->handle_model_event(std::move(notification), ModelChangeNotification::Kind::General);

  EXPECT_TRUE(wait_until(
    [&]
    {
      return AddressSpaceCacheTestAccess::on_strand(*cache,
               [](auto& cacheOnStrand)
               { return AddressSpaceCacheTestAccess::browse_count(cacheOnStrand); }) == 0U;
    }))
    << "a ReferenceDeleted General model change routed through the router must flush X's cached browse page";
}

// @verifies CL-EVT-003 - the "Changes" SelectClause wiring (Slice 2b): the router's GeneralModelChange and
// SemanticChange backbones must each subscribe with an extra "Changes" SelectClause (typeDefinitionId = the
// concrete event type) so a live event delivers its per-node Changes payload. Falsifier: a router that
// subscribes with only the BaseEventType mandatory clauses (the pre-Slice-2b state) has no "Changes" clause
// on either backbone -> this fails.
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, RouterModelBackbonesCarryChangesSelectClause)
{
  ConnectionConfig config;
  config.addressSpaceCache.enabled = true;  // an enabled cache lights the router's four backbone subscribes
  auto connection = make_active_connection(std::move(config));
  auto subscriber = connection->events_impl();
  ASSERT_NE(subscriber, nullptr);

  const auto hasTypedChangesClause = [](const ua::EventFilter& filter, const NodeId& typeDefinition)
  {
    for (const auto& clause : filter.select_clauses())
    {
      if (clause_field_name(clause) == "Changes" && clause.type_definition_id() == typeDefinition)
      {
        return true;
      }
    }
    return false;
  };

  // The GeneralModelChange backbone (its own dedicated backbone, keyed by its OfType WhereClause) must carry
  // a Changes clause typed to GeneralModelChangeEventType.
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto index = EventSubscriberTestAccess::backbone_index_for_of_type_thread_safe(
        *subscriber, NodeId{ua::ObjectTypeId::GeneralModelChangeEventType});
      if (!index.has_value())
      {
        return false;
      }
      const auto filter = EventSubscriberTestAccess::last_sent_filter_thread_safe(*subscriber, *index);
      return filter.has_value() &&
             hasTypedChangesClause(*filter, NodeId{ua::ObjectTypeId::GeneralModelChangeEventType});
    }))
    << "the GeneralModelChange backbone must subscribe with a Changes SelectClause (CL-EVT-003)";

  // The SemanticChange backbone must carry a Changes clause typed to SemanticChangeEventType.
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto index = EventSubscriberTestAccess::backbone_index_for_of_type_thread_safe(
        *subscriber, NodeId{ua::ObjectTypeId::SemanticChangeEventType});
      if (!index.has_value())
      {
        return false;
      }
      const auto filter = EventSubscriberTestAccess::last_sent_filter_thread_safe(*subscriber, *index);
      return filter.has_value() &&
             hasTypedChangesClause(*filter, NodeId{ua::ObjectTypeId::SemanticChangeEventType});
    }))
    << "the SemanticChange backbone must subscribe with a Changes SelectClause (CL-EVT-004)";
}

// @verifies CL-EVT-003 - the SelectClause differential END-TO-END through the real subscriber demux: an
// enabled-cache connection primes a Browse page for X AND Y, then a GeneralModelChangeEvent carrying
// Changes=[{ReferenceDeleted, X}] is delivered through the production Publish demux (on_publish_events_async
// against the backbone's composite filter). With the Changes SelectClause present the event carries its
// per-node array -> ONLY X's browse page is invalidated; Y survives. Falsifier / RED baseline (pre-Slice-2b):
// with no Changes clause the composite has no Changes slot, the delivered event carries no Changes, and the
// router CONSERVATIVELY FULL-FLUSHES -> Y is also dropped -> browse_count reaches 0, never 1.
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, GeneralModelChangeThroughDemuxInvalidatesOnlyAffectedNode)
{
  ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  auto connection = make_active_connection(std::move(config));
  auto subscriber = connection->events_impl();
  ASSERT_NE(subscriber, nullptr);

  // Prime a distinct Browse page for X (node 5) and Y (node 6) on the cache's serialization domain.
  auto cache = connection->address_space_cache();
  const auto primeBrowse = [&cache](const NodeId& node)
  {
    AddressSpaceCacheTestAccess::on_strand(*cache,
      [node](auto& strong)
      {
        ua::client::detail::CachedBrowseKey key;
        key.node = node;
        ua::client::detail::BrowseEntry entry;
        entry.installedAt = std::chrono::steady_clock::now();
        strong.install_browse(key, entry);
      });
  };
  primeBrowse(node(5));
  primeBrowse(node(6));
  ASSERT_EQ(AddressSpaceCacheTestAccess::on_strand(
              *cache, [](auto& strong) { return AddressSpaceCacheTestAccess::browse_count(strong); }),
    2U);

  // Find the GeneralModelChange backbone (its dedicated backbone) and its composite filter + client handle.
  std::optional<std::size_t> backboneIndex;
  ASSERT_TRUE(wait_until(
    [&]
    {
      backboneIndex = EventSubscriberTestAccess::backbone_index_for_of_type_thread_safe(
        *subscriber, NodeId{ua::ObjectTypeId::GeneralModelChangeEventType});
      return backboneIndex.has_value();
    }))
    << "the GeneralModelChange backbone must be created";
  const auto composite = EventSubscriberTestAccess::last_sent_filter_thread_safe(*subscriber, *backboneIndex);
  ASSERT_TRUE(composite.has_value());
  const std::uint32_t backboneHandle =
    EventSubscriberTestAccess::backbone_client_handle_thread_safe(*subscriber, *backboneIndex);

  // Deliver a GeneralModelChangeEvent (Changes=[{ReferenceDeleted, X}]) through the REAL demux. The field
  // list matches the composite positionally; the Changes value lands in the composite's Changes slot (present
  // only once the SelectClause is wired).
  const std::uint8_t referenceDeleted =
    static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::ReferenceDeleted);
  ua::EventFieldList fields = composite_event_fields(*composite,
    backboneHandle,
    NodeId{ua::ObjectTypeId::GeneralModelChangeEventType},
    model_changes_variant({{node(5), node(58), referenceDeleted}}));

  std::promise<void> delivered;
  auto deliveredFuture = delivered.get_future();
  std::vector<ua::EventFieldList> notifications;
  notifications.push_back(std::move(fields));
  subscriber->on_publish_events_async(
    backboneHandle, std::move(notifications), [&delivered] { delivered.set_value(); });
  deliveredFuture.get();

  // Only X (node 5) is invalidated; Y (node 6) survives -> browse_count settles at 1, never 0.
  ASSERT_TRUE(wait_until(
    [&]
    {
      return AddressSpaceCacheTestAccess::on_strand(
               *cache, [](auto& strong) { return AddressSpaceCacheTestAccess::browse_count(strong); }) == 1U;
    }))
    << "the per-node Changes payload must invalidate only X - Y's cached browse must survive (CL-EVT-003)";
  ua::client::detail::CachedBrowseKey keyX;
  keyX.node = node(5);
  ua::client::detail::CachedBrowseKey keyY;
  keyY.node = node(6);
  const auto xBrowse = AddressSpaceCacheTestAccess::on_strand(
    *cache, [&keyX](auto& strong) { return strong.lookup_browse(keyX); });
  const auto yBrowse = AddressSpaceCacheTestAccess::on_strand(
    *cache, [&keyY](auto& strong) { return strong.lookup_browse(keyY); });
  EXPECT_FALSE(xBrowse.has_value()) << "X's cached browse must be invalidated";
  EXPECT_TRUE(yBrowse.has_value()) << "Y's cached browse must survive (not full-flushed)";
}

// @verifies CL-EVT-004 / CL-DA-011 - a SemanticChangeEvent invalidates the SemanticChangeCache and fires
// BOTH on_semantic_change AND on_model_change (the DA typed-accessor cache-invalidation path must receive the
// same signal regardless of trigger origin). The AddressSpaceCache is still NOT notified (the semantic path
// never reaches for it); the on_model_change fan-out carries the semantic-mapped change with verb == 0.
// @relation(CL-DA-011, CL-EVT-004, scope=function)
TEST_F(EventRouterConnectionTest, SemanticEventInvalidatesSemanticCacheAndFiresBothObservers)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  connection->set_address_space_observer_async(observer);
  TA::snapshot(*connection);

  // Register a DataAccess Property state for node 7 so we can observe the SemanticChangeCache invalidation.
  auto state = std::make_shared<TypedPropertiesState>();
  auto ticket = connection->semantic_change_cache()->register_state(node(7), state);
  ASSERT_TRUE(wait_until([&] { return ticket.registered(); }));
  ASSERT_FALSE(state->invalidated.load());

  auto notification = changes_notification(semantic_changes_variant({{node(7), node(70)}}));
  TA::event_router(*connection)->handle_semantic_event(std::move(notification));

  // CL-EVT-004: the SemanticChangeCache is invalidated...
  ASSERT_TRUE(wait_until([&] { return state->invalidated.load(); }))
    << "a SemanticChange event must invalidate the SemanticChangeCache entry (section 8.18 / CL-EVT-004)";
  // ...on_semantic_change fires...
  ASSERT_TRUE(wait_until([&] { return observer->semanticChangeCalls.load() >= 1; }))
    << "a SemanticChange event must fire AddressSpaceObserver::on_semantic_change";
  // ...AND on_model_change ALSO fires (CL-DA-011 shared route - corrects the J56 single-fire mistake).
  ASSERT_TRUE(wait_until([&] { return observer->modelChangeCalls.load() >= 1; }))
    << "a SemanticChange event must ALSO fire AddressSpaceObserver::on_model_change (CL-EVT-004 + CL-DA-011)";
  // The mapped model change carries the affected node/type with verb == 0 (a semantic change has no
  // structural verb) - proving it came from the semantic route, not an AddressSpaceCache structural flush.
  const auto modelChanges = observer->model_changes();
  ASSERT_EQ(modelChanges.size(), 1U);
  EXPECT_EQ(modelChanges.front().affected, node(7));
  EXPECT_EQ(modelChanges.front().affectedType, node(70));
  EXPECT_EQ(modelChanges.front().verb, 0);
}

// @verifies CL-AUDIT-003
// @relation(CL-AUDIT-003, scope=function)
TEST_F(EventRouterConnectionTest, AuditEventFiresObserver)
{
  auto connection = make_active_connection();
  auto alarm = std::make_shared<RecordingAlarmObserver>();
  connection->set_alarm_observer_async(alarm);
  TA::snapshot(*connection);

  EventNotification notification;
  notification.eventTypeId = node(2052);
  TA::event_router(*connection)->handle_audit_event(std::move(notification));

  EXPECT_TRUE(wait_until([&] { return alarm->auditEventCalls.load() >= 1; }))
    << "an Audit event must fire AlarmObserver::on_audit_event (pass-through)";
}

// @verifies CL-EVT-005
// @relation(CL-EVT-005, scope=function)
TEST_F(EventRouterConnectionTest, SystemStatusChangeClassifiesServerAndUnderlyingSources)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingServerStateObserver>();
  connection->set_server_state_observer_async(observer);
  TA::snapshot(*connection);

  TA::event_router(*connection)
    ->handle_system_status_event(
      system_status_notification(ua::NodeId{ua::ObjectId::Server}, "Server", ua::ServerState::Shutdown));
  TA::event_router(*connection)
    ->handle_system_status_event(system_status_notification(node(42), "Device42", ua::ServerState::Failed));

  ASSERT_TRUE(wait_until([&] { return observer->statuses().size() == 2U; }));
  const auto statuses = observer->statuses();
  EXPECT_EQ(statuses[0].sourceNode, ua::NodeId{ua::ObjectId::Server});
  EXPECT_EQ(statuses[0].state, ua::ServerState::Shutdown);
  EXPECT_EQ(statuses[0].origin, SystemStatusOrigin::Server);
  EXPECT_EQ(statuses[1].sourceNode, node(42));
  EXPECT_EQ(static_cast<std::string_view>(statuses[1].sourceName), "Device42");
  EXPECT_EQ(statuses[1].state, ua::ServerState::Failed);
  EXPECT_EQ(statuses[1].origin, SystemStatusOrigin::UnderlyingSystem);
}

// @verifies CL-EVT-005
// @relation(CL-EVT-005, scope=function)
TEST_F(EventRouterConnectionTest, SystemStatusChangeDropsMissingAndUnknownState)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingServerStateObserver>();
  connection->set_server_state_observer_async(observer);
  TA::snapshot(*connection);

  EventNotification missing;
  missing.sourceNode = ua::NodeId{ua::ObjectId::Server};
  TA::event_router(*connection)->handle_system_status_event(std::move(missing));

  EventNotification unknown = system_status_notification(node(42), "Device42", ua::ServerState::Failed);
  unknown.fields[0] = ua::Variant{std::int32_t{999}};
  TA::event_router(*connection)->handle_system_status_event(std::move(unknown));

  TA::snapshot(*connection);
  std::this_thread::sleep_for(30ms);
  EXPECT_TRUE(observer->statuses().empty())
    << "missing or unknown mandatory SystemState must not reach the public observer";
}

// @verifies CL-EVT-006
// @relation(CL-EVT-006, scope=function)
TEST_F(EventRouterConnectionTest, ProgressEventDecodesServiceHandleAndPreservesApplicationContext)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingServerStateObserver>();
  connection->set_server_state_observer_async(observer);
  TA::snapshot(*connection);

  TA::event_router(*connection)
    ->handle_progress_event(
      progress_notification("Service/Read", ua::Variant{std::uint32_t{42}}, ua::Variant{std::uint16_t{50}}));
  TA::event_router(*connection)
    ->handle_progress_event(progress_notification(
      "MyApp/LongJob", ua::Variant{ua::String{"opaque-job-7"}}, ua::Variant{std::uint16_t{75}}));

  ASSERT_TRUE(wait_until([&] { return observer->progress_events().size() == 2U; }));
  const auto events = observer->progress_events();
  ASSERT_TRUE(events[0].progress);
  EXPECT_EQ(events[0].progress->sourceKind, ua::client::ProgressSourceKind::Service);
  EXPECT_EQ(events[0].progress->requestHandle, 42U);
  EXPECT_EQ(events[0].progress->progress, 50U);
  ASSERT_TRUE(events[1].progress);
  EXPECT_EQ(events[1].progress->sourceKind, ua::client::ProgressSourceKind::Application);
  EXPECT_FALSE(events[1].progress->requestHandle);
  EXPECT_EQ(events[1].progress->context.as<ua::String>(), ua::String{"opaque-job-7"});
  EXPECT_EQ(events[1].progress->progress, 75U);
}

// @verifies CL-EVT-006
// @relation(CL-EVT-006, scope=function)
TEST_F(EventRouterConnectionTest, ProgressEventClampsRangeAndAdvisesMalformedServiceContext)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingServerStateObserver>();
  auto advisories = std::make_shared<RecordingAdvisoryObserver>();
  connection->set_server_state_observer_async(observer);
  connection->set_connection_observer_async(advisories);
  TA::snapshot(*connection);

  TA::event_router(*connection)
    ->handle_progress_event(progress_notification(
      "Service/Write", ua::Variant{ua::String{"wrong"}}, ua::Variant{std::uint16_t{150}}));

  ASSERT_TRUE(wait_until(
    [&] { return observer->progress_events().size() == 1U && advisories->details().size() == 2U; }));
  const auto event = observer->progress_events().front();
  ASSERT_TRUE(event.progress);
  EXPECT_EQ(event.progress->sourceKind, ua::client::ProgressSourceKind::Service);
  EXPECT_FALSE(event.progress->requestHandle);
  EXPECT_EQ(event.progress->context.as<ua::String>(), ua::String{"wrong"});
  EXPECT_EQ(event.progress->progress, 100U);
  const auto details = advisories->details();
  ASSERT_NE(details[0], nullptr);
  ASSERT_NE(details[1], nullptr);
  EXPECT_EQ(details[0]->code, "ProgressContextDecodeMismatch");
  EXPECT_EQ(details[1]->code, "ProgressOutOfRange");
}

// @verifies CL-EVT-006
// @relation(CL-EVT-006, scope=function)
TEST_F(EventRouterConnectionTest, ProgressEventMissingOrWrongProgressAdvisesAndStillDeliversGenericEvent)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingServerStateObserver>();
  auto advisories = std::make_shared<RecordingAdvisoryObserver>();
  connection->set_server_state_observer_async(observer);
  connection->set_connection_observer_async(advisories);
  TA::snapshot(*connection);

  auto missing =
    progress_notification("Service/Read", ua::Variant{std::uint32_t{1}}, ua::Variant{std::uint16_t{10}});
  missing.fields[1] = std::nullopt;
  auto wrongType = progress_notification(
    "Service/Read", ua::Variant{std::uint32_t{2}}, ua::Variant{ua::String{"not-a-percentage"}});
  TA::event_router(*connection)->handle_progress_event(std::move(missing));
  TA::event_router(*connection)->handle_progress_event(std::move(wrongType));

  ASSERT_TRUE(wait_until(
    [&] { return observer->progress_events().size() == 2U && advisories->details().size() == 2U; }));
  const auto events = observer->progress_events();
  EXPECT_FALSE(events[0].progress);
  EXPECT_FALSE(events[1].progress);
  for (const auto& detail : advisories->details())
  {
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "ProgressFieldInvalid");
  }
}

TEST_F(EventRouterConnectionTest, MalformedModelChangesDoesNotFireObserverOrCrash)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  connection->set_address_space_observer_async(observer);
  TA::snapshot(*connection);

  // A scalar "Changes" is malformed untrusted input -> advisory + skip: no observer fire, no crash.
  auto notification = changes_notification(ua::Variant{ua::String{"not-an-array"}});
  TA::event_router(*connection)
    ->handle_model_event(std::move(notification), ModelChangeNotification::Kind::General);

  // Give the strand a moment; the malformed event must produce no fan-out.
  TA::snapshot(*connection);
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(observer->modelChangeCalls.load(), 0);
  EXPECT_EQ(observer->semanticChangeCalls.load(), 0);
}

// @verifies CL-EVT-003 - router half of client_general_model_change_with_empty_changes_dropped: a General
// model event whose Changes array is PRESENT but empty is DROPPED at the router - no cache flush, no
// on_model_change fire (mirrors MalformedModelChangesDoesNotFireObserverOrCrash's observe-no-fan-out shape).
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, PresentEmptyChangesModelEventIsDroppedNoObserver)
{
  auto connection = make_active_connection();
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  connection->set_address_space_observer_async(observer);
  TA::snapshot(*connection);

  // A GeneralModelChangeEvent with a present-but-zero-length Changes array (server bug) -> dropped: no flush,
  // no fire.
  auto notification = changes_notification(model_changes_variant({}), /*source=*/node(86));
  TA::event_router(*connection)
    ->handle_model_event(std::move(notification), ModelChangeNotification::Kind::General);

  // Barrier the strand + give any (erroneous) fan-out a moment to land; there must be none.
  TA::snapshot(*connection);
  std::this_thread::sleep_for(30ms);
  EXPECT_EQ(observer->modelChangeCalls.load(), 0)
    << "a present-but-empty Changes General event must be dropped - no on_model_change (CL-EVT-003)";
  EXPECT_EQ(observer->semanticChangeCalls.load(), 0);
}

// @verifies CL-EVT-003 - M1: an observer registered AFTER first-active (the common connect-then-observe flow)
// must still trigger the router's backbone event Subscriptions. The eager first-active start gated OFF
// because the connection had no consumer yet; the late set_address_space_observer_async re-evaluates the
// gate.
// @relation(CL-EVT-003, scope=function)
TEST_F(EventRouterConnectionTest, LateRegisteredObserverTriggersSubscription)
{
  // No observer in the config -> the router reaches first-active with no consumer and suppresses the
  // subscribe.
  auto connection = make_active_connection();
  TA::snapshot(*connection);  // barrier: first-active (and its gated-off router start) has been processed
  EXPECT_EQ(mSession->createMonitoredItems.call_count(), 0U)
    << "with no consumer the router must NOT subscribe at first-active (J57 gate)";

  // Register the observer LATE -> the setter re-evaluates the gate and start() now subscribes.
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  connection->set_address_space_observer_async(observer);

  EXPECT_TRUE(wait_until([&] { return mSession->createMonitoredItems.call_count() >= 1U; }))
    << "a late-registered observer must trigger the router's backbone subscribe (M1)";
  auto subscriber = connection->events_impl();
  EXPECT_TRUE(wait_until(
    [&]
    {
      auto info = subscriber->info();
      return info != nullptr && info->consumerCount == 6U;
    }))
    << "the router must register exactly six event consumers after the late observer registration";
}

// ----------------------------- The event-type subtype walk -----------------------------
//
// The event-type closure is built from the References a HasSubtype Browse answers, so the walk does not act
// on an Uncertain answer: an Uncertain ServiceResult or an Uncertain per-node BrowseResult status ends the
// walk with Bad_InternalError (ReferencesAnswerUncertain, whose inner status is the Uncertain code). A Good
// subcode is consumed.

/// A one-node BrowseResponse: ServiceResult @p serviceResult, BrowseResult status @p nodeStatus, and one
/// forward Reference to @p target.
ua::BrowseResponse make_subtype_page(ua::StatusCode serviceResult, ua::StatusCode nodeStatus, NodeId target)
{
  ua::BrowseResult page;
  page.status_code() = std::move(nodeStatus);
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = std::move(target);
  reference.is_forward() = true;
  page.references().push_back(std::move(reference));
  ua::BrowseResponse response;
  response.response_header().service_result() = std::move(serviceResult);
  response.results().push_back(std::move(page));
  return response;
}

/// Runs the subtype walk from @p root over @p connection; nullopt when its callback did not run in time.
std::optional<ua::Result<std::vector<NodeId>>> resolve_subtypes(
  const std::shared_ptr<ConnectionImpl>& connection, NodeId root)
{
  auto done = std::make_shared<std::promise<ua::Result<std::vector<NodeId>>>>();
  auto future = done->get_future();
  ua::client::detail::ConnectionEventBackboneOps::create(connection)
    ->resolve_event_subtypes_async({std::move(root)},
      [done](ua::Result<std::vector<NodeId>> result) { done->set_value(std::move(result)); });
  if (future.wait_for(5s) != std::future_status::ready)
  {
    return std::nullopt;
  }
  return future.get();
}

/// Checks that @p result is the refusal of the server's Uncertain @p answer: Bad_InternalError whose
/// ErrorDetail chain holds ReferencesAnswerUncertain, with its summary and @p answer as its inner status.
void expect_references_answer_refused(const ua::Result<std::vector<NodeId>>& result, ua::Status answer)
{
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  const ua::ErrorDetail* refusal = result.error_detail();
  while (refusal != nullptr && refusal->code != "ReferencesAnswerUncertain")
  {
    refusal = refusal->cause.get();
  }
  ASSERT_NE(refusal, nullptr) << "the refusal must name the Uncertain answer";
  EXPECT_EQ(refusal->summary, "The SDK does not act on an answer the server is uncertain of");
  EXPECT_EQ(refusal->innerStatus, ua::StatusCode{answer}.value());
}

// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EventRouterConnectionTest, SubtypeWalkRefusesAnUncertainServiceResult)
{
  auto connection = make_active_connection();
  mSession->browse.set_result(ua::Result<ua::BrowseResponse>{
    make_subtype_page(ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable},
      ua::StatusCode{ua::Status::Good},
      NodeId{2, 100})});

  const auto result = resolve_subtypes(connection, NodeId{0, 2041});

  ASSERT_TRUE(result.has_value()) << "the walk's callback must run";
  expect_references_answer_refused(*result, ua::Status::UncertainNotAllNodesAvailable);
}

// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EventRouterConnectionTest, SubtypeWalkRefusesAnUncertainNodeAndBrowsesNoFurther)
{
  auto connection = make_active_connection();
  mSession->browse.set_result(
    ua::Result<ua::BrowseResponse>{make_subtype_page(ua::StatusCode{ua::Status::Good},
      ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable},
      NodeId{2, 100})});

  const auto result = resolve_subtypes(connection, NodeId{0, 2041});

  ASSERT_TRUE(result.has_value()) << "the walk's callback must run";
  expect_references_answer_refused(*result, ua::Status::UncertainNotAllNodesAvailable);
  EXPECT_EQ(mSession->browse.call_count(), 1U) << "the References of an Uncertain node must not be walked";
}

// Control for the refusals above: a per-node Good subcode is Good, so its References join the closure.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EventRouterConnectionTest, SubtypeWalkUsesTheReferencesOfAGoodSubcodeNode)
{
  auto connection = make_active_connection();
  mSession->browse.set_result(
    ua::Result<ua::BrowseResponse>{make_subtype_page(ua::StatusCode{ua::Status::Good},
      ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete},
      NodeId{2, 100})});

  const auto result = resolve_subtypes(connection, NodeId{0, 2041});

  ASSERT_TRUE(result.has_value()) << "the walk's callback must run";
  ASSERT_TRUE(result->is_good()) << result->status_code().value();
  EXPECT_EQ(result->value(), (std::vector<NodeId>{NodeId{0, 2041}, NodeId{2, 100}}));
}

}  // namespace
