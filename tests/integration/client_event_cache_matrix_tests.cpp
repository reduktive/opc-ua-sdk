// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientEventCache cluster of the client integration-test matrix (the CL-EVT-003 / CL-EVT-004 rows).
///
/// END-TO-END rows for the EventRouter -> AddressSpaceCache / SemanticChangeCache routing story (client
/// design section 8.7 / section 8.18, Slice 2b). A real client stack (MisbehavingServer-backed
/// `ConnectionImpl` with the AddressSpaceCache ENABLED) auto-subscribes the four NS0 model / semantic / audit
/// event backbones at first-active. The GeneralModelChange and SemanticChange backbones now carry a "Changes"
/// SelectClause (Slice 2b), so a delivered event carries its per-node `Changes` array. These rows inject a
/// real GeneralModelChangeEvent / SemanticChangeEvent into an OUTGOING PublishResponse via the response
/// mutator and let the always-on Publish pump carry it in through `feed_publish_response` ->
/// `route_event_notification_list` -> `EventSubscriberImpl` -> `EventRouter`, and then assert the
/// cache-invalidation differential is observable on the wire (a re-issued Browse vs a cache-served Browse
/// counted by the request observer).
///
///   - CL-EVT-003 - a GeneralModelChange whose `Changes=[{ReferenceDeleted, X}]` invalidates ONLY X's cached
///     Browse: Browse(X) re-issues a wire Browse while Browse(Y) is still served from cache. A present-but-
///     empty `Changes` array is DROPPED (not a full flush), so Y survives that too.
///   - CL-EVT-004 - a SemanticChange for X invalidates the SemanticChangeCache and fires the
///     AddressSpaceObserver's on_semantic_change, but NEVER touches the AddressSpaceCache - X's cached Browse
///     survives (served without a wire Browse).
///
/// The backbone client handle + composite filter are captured off the wire (the CreateMonitoredItems request
/// observer, correlated by the OfType WhereClause) so the injected EventFieldList matches the backbone's
/// composite SelectClauses positionally (the demux drops a field-count mismatch). The injected Publish
/// retains the keep-alive's sequence number: a keep-alive peeks at the next NotificationMessage sequence,
/// so replacing it with a real notification makes that number in-order.

#include "compliance_helpers.h"
#include "requests.h"

#include "access_control_test_support.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_semantic_change_cache.h"
#include "ua_session_attribute_services.h"
#include "ua_browse_direction.h"
#include "ua_session_view_services.h"
#include "ua_typed_access.h"

#include "ua_history_engine_delegate.h"
#include "ua_history_namespace.h"
#include "ua_history_sqlite_store.h"

#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_base_event.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_client.h"
#include "ua_client_observers.h"
#include "ua_continuation_point.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_default_namespace.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_notification_list.h"
#include "ua_event_notifier_type.h"
#include "ua_generic_event.h"
#include "ua_history_event.h"
#include "ua_history_event_field_list.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_history_read_value_id.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_result.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_perform_update_type.h"
#include "ua_publish_response.h"
#include "ua_qualified_name.h"
#include "ua_read_event_details.h"
#include "ua_ref_structure.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_simple_attribute_operand.h"
#include "ua_structure.h"
#include "ua_timestamps_to_return.h"
#include "ua_to_string.h"
#include "ua_update_event_details.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionImpl;
using ua::client::detail::SemanticChangeCache;
using ua::client::detail::TypedPropertiesState;

namespace
{

bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 3000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(5ms);
  }
  return predicate();
}

NodeId node_x()
{
  return NodeId{ObjectId::RootFolder};
}

NodeId node_y()
{
  return NodeId{ObjectId::ObjectsFolder};
}

// Thread-safe fake AddressSpaceObserver: the sink fires on its own delivery strand (a pool thread), so the
// counters are atomic and the captured change arrays are mutex-guarded.
class RecordingAddressSpaceObserver : public AddressSpaceObserver
{
public:
  std::atomic<int> modelChangeCalls{0};
  std::atomic<int> semanticChangeCalls{0};

  void on_model_change(const Connection&, std::vector<ModelChangeStructure> changes) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastModelChanges = std::move(changes);
    }
    ++modelChangeCalls;
  }

  void on_semantic_change(const Connection&, std::vector<SemanticChangeStructure> changes) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastSemanticChanges = std::move(changes);
    }
    ++semanticChangeCalls;
  }

  std::vector<ModelChangeStructure> model_changes() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastModelChanges;
  }

  std::vector<SemanticChangeStructure> semantic_changes() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastSemanticChanges;
  }

private:
  mutable std::mutex mMutex;
  std::vector<ModelChangeStructure> mLastModelChanges;
  std::vector<SemanticChangeStructure> mLastSemanticChanges;
};

// True iff @p filter's WhereClause carries an OfType element whose literal decodes to @p typeId.
bool where_has_of_type(const ua::EventFilter& filter, const ua::NodeId& typeId)
{
  for (const auto& element : filter.where_clause().elements())
  {
    if (element.filter_operator() != ua::FilterOperator::OfType || element.filter_operands().empty())
      continue;
    const auto* literal = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
    if (literal == nullptr)
      continue;
    const ua::Result<ua::NodeId> asNode = literal->value().to<ua::NodeId>();
    if (asNode.is_good() && asNode.value() == typeId)
      return true;
  }
  return false;
}

// Captures the router backbone metadata and Browse targets observed on the wire.
struct EventBackboneCapture
{
  mutable std::mutex mutex;
  std::optional<std::uint32_t> generalHandle;
  std::optional<std::uint32_t> generalSubscriptionId;
  std::optional<ua::EventFilter> generalFilter;
  std::optional<std::uint32_t> semanticHandle;
  std::optional<std::uint32_t> semanticSubscriptionId;
  std::optional<ua::EventFilter> semanticFilter;
  std::atomic<int> nodeXBrowseCount{0};
  std::atomic<int> nodeYBrowseCount{0};

  void observe(const ua::Structure& request)
  {
    if (const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
        create != nullptr && !create->items_to_create().empty())
    {
      const auto& params = create->items_to_create()[0].requested_parameters();
      if (const auto* filter = dynamic_cast<const ua::EventFilter*>(params.filter().get()))
      {
        std::lock_guard lock(mutex);
        if (where_has_of_type(*filter, ua::NodeId{ua::ObjectTypeId::GeneralModelChangeEventType}))
        {
          generalHandle = params.client_handle();
          generalSubscriptionId = create->subscription_id();
          generalFilter = *filter;
        }
        else if (where_has_of_type(*filter, ua::NodeId{ua::ObjectTypeId::SemanticChangeEventType}))
        {
          semanticHandle = params.client_handle();
          semanticSubscriptionId = create->subscription_id();
          semanticFilter = *filter;
        }
      }
    }
    if (const auto* browse = dynamic_cast<const ua::BrowseRequest*>(&request))
    {
      for (const auto& description : browse->nodes_to_browse())
      {
        if (description.node_id() == node_x())
          nodeXBrowseCount.fetch_add(1);
        else if (description.node_id() == node_y())
          nodeYBrowseCount.fetch_add(1);
      }
    }
  }

  std::optional<std::uint32_t> general_handle() const
  {
    std::lock_guard lock(mutex);
    return generalHandle;
  }

  std::optional<ua::EventFilter> general_filter() const
  {
    std::lock_guard lock(mutex);
    return generalFilter;
  }

  std::optional<std::uint32_t> general_subscription_id() const
  {
    std::lock_guard lock(mutex);
    return generalSubscriptionId;
  }

  std::optional<std::uint32_t> semantic_handle() const
  {
    std::lock_guard lock(mutex);
    return semanticFilter.has_value() ? semanticHandle : std::nullopt;
  }

  std::optional<ua::EventFilter> semantic_filter() const
  {
    std::lock_guard lock(mutex);
    return semanticFilter;
  }

  std::optional<std::uint32_t> semantic_subscription_id() const
  {
    std::lock_guard lock(mutex);
    return semanticSubscriptionId;
  }
};

// Builds an injected forward reference to @p target so a mutator-pinned Browse page has an installable entry.
ua::ReferenceDescription make_reference(const ua::NodeId& target, std::string_view name = "CachedChild")
{
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = target;
  reference.is_forward() = true;
  reference.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
  reference.browse_name() = ua::QualifiedName{0, std::string{name}};
  reference.display_name() = ua::LocalizedText{"", std::string{name}};
  reference.node_class() = ua::NodeClass::Object;
  return reference;
}

// Overwrites a BrowseResult page (status Good) with one reference and NO continuation point -> a whole single
// page -> installable into the read-surface cache (single-page-only, v1).
void pin_single_page(ua::BrowseResponse& browse)
{
  if (browse.results().empty())
    return;
  auto& result = browse.results()[0];
  result.status_code() = ua::StatusCode{ua::Status::Good};
  ua::Array<ua::ReferenceDescription> references;
  references.push_back(make_reference(ua::NodeId{ua::ObjectId::ObjectsFolder}));
  result.references() = std::move(references);
  result.continuation_point() = ua::ContinuationPoint{};
}

// A "Changes" Variant carrying ModelChangeStructureDataType[] (the wire codec delivers it as an
// array-of-structure), one entry per {affected, affectedType, verb}.
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

std::string_view clause_field_name(const ua::SimpleAttributeOperand& clause)
{
  if (clause.browse_path().size() != 1)
    return {};
  return static_cast<std::string_view>(clause.browse_path()[0].name());
}

// Build a wire EventFieldList matching @p composite positionally (one field per SelectClause - the demux
// drops a field-count mismatch): EventType = @p eventType (drives the demux), the "Changes" slot = @p
// changes, every other field null. @p backboneHandle keys the inbound demux to the router's per-type
// backbone.
ua::EventFieldList composite_event_fields(const ua::EventFilter& composite, std::uint32_t backboneHandle,
  const NodeId& eventType, const ua::Variant& changes)
{
  ua::EventFieldList list;
  list.client_handle() = backboneHandle;
  const ua::ByteString eventId{0xCA, 0xCE};
  for (const auto& clause : composite.select_clauses())
  {
    const std::string_view name = clause_field_name(clause);
    if (name == "EventId")
      list.event_fields().push_back(ua::Variant{eventId});
    else if (name == "EventType")
      list.event_fields().push_back(ua::Variant{eventType});
    else if (name == "SourceNode")
      list.event_fields().push_back(ua::Variant{ua::NodeId{ua::ObjectId::Server}});
    else if (name == "SourceName")
      list.event_fields().push_back(ua::Variant{ua::String{"src"}});  // SourceName is a String
    else if (name == "Time" || name == "ReceiveTime")
      list.event_fields().push_back(ua::Variant{ua::DateTime{}});
    else if (name == "Message")
      list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "model change"}});
    else if (name == "Severity")
      list.event_fields().push_back(ua::Variant{std::uint16_t{1}});
    else if (name == "Changes")
      list.event_fields().push_back(changes);
    else
      list.event_fields().push_back(ua::Variant{});
  }
  return list;
}

// Replace a keep-alive PublishResponse with one in-order EventNotificationList. A keep-alive carries the
// sequence number of the next NotificationMessage, so retaining it makes the injected message in-order.
void inject_event_publish(ua::PublishResponse& publish, ua::EventFieldList fields)
{
  publish.notification_message().notification_data().clear();
  auto notification = std::make_unique<ua::EventNotificationList>();
  notification->events().push_back(std::move(fields));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// A MisbehavingServer-backed client stack whose ConnectionImpl is built (with @p config) but NOT started -
// the test arms the request observer FIRST (so it captures the router's first-active event CreateMonitored
// items), THEN calls start(). Exposes both the impl (semantic_change_cache / events) and the tier-2
// Connection handle (typed().browse()).
class EventCacheFixture
{
public:
  EventCacheFixture(MisbehavingServer& server, ua::client::detail::ConnectionConfig config)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientEventCacheMatrix"});
    session.activate_sync();

    mImpl = ConnectionImpl::create(mThreadPool.executor(), std::move(session), std::move(config), Logger{});
    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(mImpl));
  }

  ~EventCacheFixture()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
    mConnection.reset();
    mImpl.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  EventCacheFixture(const EventCacheFixture&) = delete;
  EventCacheFixture& operator=(const EventCacheFixture&) = delete;

  VoidResult start()
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    mImpl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  ConnectionImpl& impl()
  {
    return *mImpl;
  }

  Connection& conn()
  {
    return *mConnection;
  }

  // A second, tier-1 Session on the same Client, for a request the tier-2 Connection does not expose.
  ua::client::Session open_tier1_session(MisbehavingServer& server)
  {
    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientEventCacheMatrixTier1"});
    session.activate_sync();
    return session;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mImpl;
  std::optional<Connection> mConnection;
};

// Browse @p node once through the tier-2 managed cursor; returns true iff its first entry is delivered.
bool browse_once(Connection& connection, const NodeId& node)
{
  auto cursor = connection.typed().browse(node);
  auto first = cursor.try_next_sync();
  return first.is_good();
}

class ClientEventCache : public ::testing::Test
{};

// =============================================================================================
// CL-EVT-003 - GeneralModelChangeInvalidatesOnlyAffectedCacheEntries  (MisbehavingServer)
//
// With the AddressSpaceCache enabled, prime the browse cache for X and Y (Browse each once). A
// GeneralModelChangeEvent whose Changes=[{ReferenceDeleted, X}] (ERRATUM vs the matrix's NodeAdded, which
// invalidates nothing) must invalidate ONLY X: a later Browse(X) re-issues a wire Browse while Browse(Y) is
// still served from cache. A present-but-empty Changes array is DROPPED (drop-with-advisory, not a full
// flush), so Y survives that too. [neg: no blanket invalidate - both halves required]
// =============================================================================================
// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=function)
// @relation(AC-CL-EVT-003-A-GENERALMODELCHANGEEVENT-INVALIDATES-ONLY-THE-N, scope=function)
TEST_F(ClientEventCache, GeneralModelChangeInvalidatesOnlyAffectedCacheEntries)
{
  MisbehavingServer server;
  ua::client::detail::ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  config.observers.addressSpace = observer;  // fan-out proof + the "cache flush done" ordering barrier
  EventCacheFixture fixture{server, std::move(config)};

  // Arm the capture BEFORE start so it records the router's first-active GeneralModelChange backbone handle +
  // composite (correlated by OfType) and counts every Browse.
  auto capture = std::make_shared<EventBackboneCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  ASSERT_TRUE(fixture.start().is_good());

  ASSERT_TRUE(wait_until([&] { return capture->general_handle().has_value(); }))
    << "the router's GeneralModelChange backbone (handle + composite) must be captured off the wire";
  const std::uint32_t generalHandle = *capture->general_handle();
  const std::uint32_t generalSubscriptionId = *capture->general_subscription_id();
  const ua::EventFilter composite = *capture->general_filter();

  // Pin every Browse to a clean single page (installable) and inject the model event once, on demand.
  auto injectModel = std::make_shared<std::atomic<bool>>(false);
  auto modelInjected = std::make_shared<std::atomic<bool>>(false);
  auto injectEmpty = std::make_shared<std::atomic<bool>>(false);
  auto emptyInjected = std::make_shared<std::atomic<bool>>(false);
  const std::uint8_t referenceDeleted =
    static_cast<std::uint8_t>(ua::ModelChangeStructureVerbMask::ReferenceDeleted);
  const ua::EventFieldList perNodeEvent = composite_event_fields(composite,
    generalHandle,
    NodeId{ua::ObjectTypeId::GeneralModelChangeEventType},
    model_changes_variant({{node_x(), NodeId{std::uint16_t{0}, std::uint32_t{58}}, referenceDeleted}}));
  const ua::EventFieldList emptyChangesEvent = composite_event_fields(composite,
    generalHandle,
    NodeId{ua::ObjectTypeId::GeneralModelChangeEventType},
    model_changes_variant({}));  // present-but-empty Changes array

  server.set_response_mutator(
    [=](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
        pin_single_page(*browse);
      else if (auto* publish = dynamic_cast<PublishResponse*>(response.second.get()))
      {
        if (publish->subscription_id() == generalSubscriptionId && injectModel->load() &&
            !modelInjected->exchange(true))
          inject_event_publish(*publish, perNodeEvent);
        else if (publish->subscription_id() == generalSubscriptionId && injectEmpty->load() &&
                 !emptyInjected->exchange(true))
          inject_event_publish(*publish, emptyChangesEvent);
      }
    });

  const int xBrowsesBeforePriming = capture->nodeXBrowseCount.load();
  const int yBrowsesBeforePriming = capture->nodeYBrowseCount.load();
  ASSERT_TRUE(browse_once(fixture.conn(), node_x())) << "the first Browse(X) must deliver its entry";
  ASSERT_TRUE(browse_once(fixture.conn(), node_y())) << "the first Browse(Y) must deliver its entry";
  ASSERT_TRUE(wait_until(
    [&]
    {
      return capture->nodeXBrowseCount.load() >= xBrowsesBeforePriming + 1 &&
             capture->nodeYBrowseCount.load() >= yBrowsesBeforePriming + 1;
    }))
    << "priming X and Y issues one wire Browse for each target";

  // Deliver the per-node GeneralModelChange (Changes=[{ReferenceDeleted, X}]). The observer's on_model_change
  // fires only AFTER the cache flush completes, so it is a clean "invalidation done" barrier.
  injectModel->store(true);
  ASSERT_TRUE(wait_until([&] { return observer->modelChangeCalls.load() >= 1; }))
    << "the injected GeneralModelChange must route through to the AddressSpaceObserver";
  const auto modelChanges = observer->model_changes();
  ASSERT_EQ(modelChanges.size(), 1U);
  EXPECT_EQ(modelChanges.front().affected, node_x())
    << "the routed model change must carry the affected node X";

  // Browse(X): X was invalidated -> a fresh wire Browse (+1).
  const int xBrowsesBeforeRefetch = capture->nodeXBrowseCount.load();
  ASSERT_TRUE(browse_once(fixture.conn(), node_x())) << "the re-Browse(X) must deliver its entry";
  ASSERT_TRUE(wait_until([&] { return capture->nodeXBrowseCount.load() >= xBrowsesBeforeRefetch + 1; }))
    << "Browse(X) after a ReferenceDeleted for X must re-issue a wire Browse (CL-EVT-003)";
  EXPECT_EQ(capture->nodeXBrowseCount.load(), xBrowsesBeforeRefetch + 1);

  // Browse(Y): Y was NOT invalidated -> served from cache, NO wire Browse.
  const int yBrowsesBeforeCachedRead = capture->nodeYBrowseCount.load();
  ASSERT_TRUE(browse_once(fixture.conn(), node_y())) << "the cached Browse(Y) must serve its entry";
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(capture->nodeYBrowseCount.load(), yBrowsesBeforeCachedRead)
    << "Browse(Y) must still be served from cache - only X was invalidated (CL-EVT-003, no blanket flush)";

  // A present-but-empty Changes array is DROPPED (drop-with-advisory), NOT a full flush: Y's cached Browse
  // must still survive it. (If it full-flushed, Y would be re-Browsed on the wire.)
  injectEmpty->store(true);
  ASSERT_TRUE(wait_until([&] { return emptyInjected->load(); }))
    << "the empty-Changes event must be injected onto a Publish";
  std::this_thread::sleep_for(150ms);  // let the (dropped) event be processed
  const int yBrowsesBeforeEmptyControl = capture->nodeYBrowseCount.load();
  ASSERT_TRUE(browse_once(fixture.conn(), node_y())) << "the cached Browse(Y) must serve its entry again";
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(capture->nodeYBrowseCount.load(), yBrowsesBeforeEmptyControl)
    << "an empty-Changes GeneralModelChange must be DROPPED (not a full flush) - Y's cache survives it";
}

// =============================================================================================
// CL-EVT-004 - SemanticChangeRoutesToObserverWithoutValueInvalidation  (MisbehavingServer)
//
// A SemanticChangeEvent for X must route to the AddressSpaceObserver (on_semantic_change carrying the
// SemanticChangeStructure array) AND invalidate the DA-property SemanticChangeCache for X, but must NEVER
// touch the AddressSpaceCache (there is no value cache; the matrix's "value cache survives" is reframed as
// "the browse/attribute cache entry survives"): a later Browse(X) is still served from cache - no wire
// Browse. [neg: the semantic path never reaches address_space_cache()]
// =============================================================================================
// @verifies CL-EVT-004
// @relation(CL-EVT-004, scope=function)
TEST_F(ClientEventCache, SemanticChangeRoutesToObserverWithoutValueInvalidation)
{
  MisbehavingServer server;
  ua::client::detail::ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  config.observers.addressSpace = observer;
  EventCacheFixture fixture{server, std::move(config)};

  auto capture = std::make_shared<EventBackboneCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  ASSERT_TRUE(fixture.start().is_good());

  ASSERT_TRUE(wait_until([&] { return capture->semantic_handle().has_value(); }))
    << "the router's SemanticChange backbone (handle + composite) must be captured off the wire";
  const std::uint32_t semanticHandle = *capture->semantic_handle();
  const std::uint32_t semanticSubscriptionId = *capture->semantic_subscription_id();
  const ua::EventFilter composite = *capture->semantic_filter();

  // Register a DA-property state for X so the SemanticChangeCache invalidation is observable.
  auto propertyState = std::make_shared<TypedPropertiesState>();
  auto ticket = fixture.impl().semantic_change_cache()->register_state(node_x(), propertyState);
  ASSERT_TRUE(wait_until([&] { return ticket.registered(); }));
  ASSERT_FALSE(propertyState->invalidated.load());

  auto injectSemantic = std::make_shared<std::atomic<bool>>(false);
  auto semanticInjected = std::make_shared<std::atomic<bool>>(false);
  const ua::EventFieldList semanticEvent = composite_event_fields(composite,
    semanticHandle,
    NodeId{ua::ObjectTypeId::SemanticChangeEventType},
    semantic_changes_variant({{node_x(), NodeId{std::uint16_t{0}, std::uint32_t{70}}}}));

  server.set_response_mutator(
    [=](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
        pin_single_page(*browse);
      else if (auto* publish = dynamic_cast<PublishResponse*>(response.second.get()))
      {
        if (publish->subscription_id() == semanticSubscriptionId && injectSemantic->load() &&
            !semanticInjected->exchange(true))
          inject_event_publish(*publish, semanticEvent);
      }
    });

  const int xBrowsesBeforePriming = capture->nodeXBrowseCount.load();
  ASSERT_TRUE(browse_once(fixture.conn(), node_x())) << "the first Browse(X) must deliver its entry";
  ASSERT_TRUE(wait_until([&] { return capture->nodeXBrowseCount.load() >= xBrowsesBeforePriming + 1; }))
    << "priming X issues a wire Browse for X";

  // Deliver the SemanticChange for X.
  injectSemantic->store(true);
  ASSERT_TRUE(wait_until([&] { return observer->semanticChangeCalls.load() >= 1; }))
    << "a SemanticChange must fire AddressSpaceObserver::on_semantic_change (CL-EVT-004)";
  const auto semanticChanges = observer->semantic_changes();
  ASSERT_EQ(semanticChanges.size(), 1U);
  EXPECT_EQ(semanticChanges.front().affected, node_x())
    << "on_semantic_change must carry the affected node X";

  // The DA-property SemanticChangeCache for X is invalidated (section 8.18).
  ASSERT_TRUE(wait_until([&] { return propertyState->invalidated.load(); }))
    << "a SemanticChange must invalidate the SemanticChangeCache entry for X (CL-EVT-004)";

  // The AddressSpaceCache is NEVER touched by the semantic path -> X's cached Browse survives (no wire
  // Browse).
  const int xBrowsesBeforeCachedRead = capture->nodeXBrowseCount.load();
  ASSERT_TRUE(browse_once(fixture.conn(), node_x())) << "the cached Browse(X) must serve its entry";
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(capture->nodeXBrowseCount.load(), xBrowsesBeforeCachedRead)
    << "the semantic path must NOT invalidate the AddressSpaceCache - Browse(X) stays cache-served "
       "(CL-EVT-004)";
}

// =============================================================================================
// EventNotifier / View topology rows.
//
// `MisbehavingServer` owns a REAL `ua::server::Server`, so `server.server().address_space()` is the
// address space of the server under test. These rows build the model through that address space
// BEFORE the client connects (so the client's namespace table is current), then observe the
// consequence over the same tier-2 `Connection` the rows above use: a Browse walk, an attribute
// Read, and - for the View row - a real event MonitoredItem fed by `Server::emit_event`.
// =============================================================================================

// Registers a fresh writable namespace on the server under test and returns its index.
//
// The grant is not optional. A namespace that has declared no RolePermissions publishes an ENGAGED, EMPTY
// default under the Role model, so every undecorated node it owns is refused Bad_UserAccessDenied - the
// rows below would then browse to nothing and their absence assertions would pass over an empty address
// space instead of a populated one.
std::uint16_t add_test_namespace(ua::AddressSpace& addressSpace, const std::string& uri)
{
  auto testNamespace = ua::default_ns::Namespace::create(uri, addressSpace.executor());
  const auto index = addressSpace.add_namespace_sync(testNamespace);
  ua::test_helpers::grant_namespace_to_test_client(addressSpace, index);
  return index;
}

// Creates a typed Object under the Objects folder carrying @p notifier as its EventNotifier attribute.
void create_event_object(ua::AddressSpace& addressSpace, const NodeId& nodeId, std::uint16_t namespaceIndex,
  const std::string& name, const ua::EventNotifierType& notifier)
{
  auto node = addressSpace.create_node_sync(nodeId, ua::NodeClass::Object);
  // Part 3 section 5.5: every Object sources exactly one HasTypeDefinition - keep the test model conforming.
  node.add_reference_sync(
    NodeId{ua::ReferenceTypeId::HasTypeDefinition}, NodeId{ua::ObjectTypeId::BaseObjectType});
  auto object = node.as<ua::ObjectAccessor>();
  ASSERT_TRUE(object.has_value());
  object->set_browse_name(ua::QualifiedName{namespaceIndex, name});
  object->set_display_name(ua::LocalizedText{"", name});
  object->set_event_notifier(notifier);
  addressSpace.find_node_sync(NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, nodeId);
}

// Drains a tier-2 Browse walk from @p node over @p referenceType (an empty NodeId = every reference
// type) into a vector. The cursor yields a bad Result once the walk is exhausted.
std::vector<BrowseCursor::Entry> browse_references(
  Connection& connection, const NodeId& node, const NodeId& referenceType)
{
  BrowseOptions options;
  options.referenceTypeId = referenceType;
  options.includeSubtypes = false;
  auto cursor = connection.typed().browse(node, options);
  std::vector<BrowseCursor::Entry> entries;
  for (int guard = 0; guard < 1024; ++guard)
  {
    auto next = cursor.try_next_sync();
    if (next.is_bad())
    {
      EXPECT_EQ(next.status_code(), StatusCode{Status::BadNoData})
        << "the Browse walk may end only by exhausting the cursor; a wire failure must not be "
           "mistaken for an empty reference set";
      break;
    }
    entries.push_back(next.value());
  }
  return entries;
}

// Thread-safe sink for an event consumer: the EventSubscriber fires on its own delivery strand.
class EventSourceRecorder
{
public:
  void record(const NodeId& source)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mSources.push_back(source);
  }

  bool saw(const NodeId& source) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return std::find(mSources.begin(), mSources.end(), source) != mSources.end();
  }

private:
  mutable std::mutex mMutex;
  std::vector<NodeId> mSources;
};

// =============================================================================================
// Part 3 section 5.5.1 (Table 11): "HasNotifier References can only be used for Objects having their
// SubscribeToEvents bit set in the EventNotifier Attribute." A plausible implementation treats
// HasNotifier as just another hierarchical reference and lets the address-space mutator materialise it
// from any Object at all. That silently builds a notifier hierarchy whose intermediate nodes can never
// be subscribed to: the reference is visible on the wire, so a client walks it looking for a notifier
// to monitor, and every CreateMonitoredItems against that node is refused.
// =============================================================================================
// @verifies AC-SVR-EVT-ATTR-003-HASNOTIFIER-NOTIFIER-BIT
TEST_F(ClientEventCache, HasNotifierIsUsedOnlyFromObjectsThatCanBeSubscribedTo)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  const std::uint16_t namespaceIndex = add_test_namespace(addressSpace, "urn:test:eventcache:hasnotifier");

  const NodeId areaId{namespaceIndex, std::uint32_t{9100}};
  const NodeId subscribableId{namespaceIndex, std::uint32_t{9101}};
  const NodeId silentId{namespaceIndex, std::uint32_t{9102}};
  const ua::EventNotifierType subscribable{ua::EventNotifierType::Bit::SubscribeToEvents};
  create_event_object(addressSpace, areaId, namespaceIndex, "NotifierArea", subscribable);
  create_event_object(addressSpace, subscribableId, namespaceIndex, "SubscribableSource", subscribable);
  // A zero EventNotifier means "no eventing on this Object" - it may not source a HasNotifier.
  create_event_object(addressSpace, silentId, namespaceIndex, "SilentSource", ua::EventNotifierType{});

  auto subscribableNode = addressSpace.find_node_sync(subscribableId);
  auto silentNode = addressSpace.find_node_sync(silentId);

  // Control: a HasNotifier whose SOURCE carries the bit is legal. This is also what keeps the wire scan
  // below non-vacuous - without it there would be no HasNotifier to assert over at all.
  const VoidResult legal =
    subscribableNode.try_add_reference_sync(NodeId{ua::ReferenceTypeId::HasNotifier}, areaId);
  ASSERT_TRUE(legal.is_good())
    << "a HasNotifier sourced from an Object with SubscribeToEvents set must be accepted";

  // The obligation: the same reference sourced from a zero-EventNotifier Object is illegal. It is not
  // refused by the mutator - Part 3 7.17 binds the address space a server presents, so the server
  // implementer discharges it by calling AddressSpace::validate_event_graph_async once a build is finished, and
  // that is what reports this. The rule and its detail code are unchanged.
  ASSERT_TRUE(silentNode.try_add_reference_sync(NodeId{ua::ReferenceTypeId::HasNotifier}, areaId).is_good());
  const VoidResult refused = addressSpace.try_validate_event_graph_sync();
  EXPECT_TRUE(refused.is_bad())
    << "Part 3 section 5.5.1 Table 11 - HasNotifier may only be used FROM an Object whose EventNotifier has "
       "the SubscribeToEvents bit set; the event-graph check must report one that does not";
  EXPECT_EQ(refused.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(refused.status_code().shared_detail(), nullptr);
  EXPECT_EQ(refused.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");

  // Removed again, so the wire scan below runs against a graph the server would accept.
  silentNode.remove_reference_sync(NodeId{ua::ReferenceTypeId::HasNotifier}, areaId);
  EXPECT_TRUE(addressSpace.try_validate_event_graph_sync().is_good());

  ua::client::detail::ConnectionConfig config;
  EventCacheFixture fixture{server, std::move(config)};
  ASSERT_TRUE(fixture.start().is_good());

  const NodeId hasNotifier{ua::ReferenceTypeId::HasNotifier};
  const auto legalReferences = browse_references(fixture.conn(), subscribableId, hasNotifier);
  ASSERT_FALSE(legalReferences.empty())
    << "the legal HasNotifier must be visible on the wire - otherwise the scan below asserts over nothing";
  const auto refusedReferences = browse_references(fixture.conn(), silentId, hasNotifier);
  EXPECT_TRUE(refusedReferences.empty())
    << "the refused HasNotifier must not exist in the model a client browses";

  // OBSERVATION: for every HasNotifier reference reachable here, the SOURCE Object's EventNotifier must
  // carry SubscribeToEvents. Read it over the wire so the assertion is about the served model.
  int scannedSources = 0;
  for (const NodeId& source : {subscribableId, silentId})
  {
    if (browse_references(fixture.conn(), source, hasNotifier).empty())
      continue;
    ++scannedSources;
    const ua::Result<ua::DataValue> read =
      fixture.conn().typed().try_read_attribute_sync(source, ua::AttributeId::EventNotifier);
    ASSERT_TRUE(read.is_good()) << "EventNotifier must be readable on a node that sources a HasNotifier";
    const ua::Result<std::uint8_t> bits = read.value().value().to<std::uint8_t>();
    ASSERT_TRUE(bits.is_good()) << "EventNotifier must decode as a Byte";
    EXPECT_TRUE(ua::EventNotifierType{bits.value()}.test(ua::EventNotifierType::Bit::SubscribeToEvents))
      << "every source of a HasNotifier must have SubscribeToEvents set (Part 3 section 5.5.1 Table 11)";
  }
  EXPECT_EQ(scannedSources, 1)
    << "exactly the subscribable Object may source a HasNotifier here - a second source means the "
       "zero-EventNotifier Object was allowed to build a notifier hierarchy";
}

// =============================================================================================
// Part 3 section 5.4: "A View that supports Events shall provide all Events that occur in any Object used as
// EventNotifier that is part of the content of the View." A plausible implementation resolves an
// event's notifier set by walking HasNotifier upward from the SourceNode only, so a View that merely
// CONTAINS its notifiers aggregates nothing: a client subscribed to the View sees an empty stream while
// believing it is watching everything the View holds, and has no way to learn the View was incomplete.
// The Server-Object consumer is the control - it proves the events really entered the event pipeline,
// so a failure on the View consumer cannot be blamed on the stimulus.
// =============================================================================================
// @verifies AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS
TEST_F(ClientEventCache, ViewSupportingEventsDeliversEventsOfEveryNotifierItContains)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  const std::uint16_t namespaceIndex = add_test_namespace(addressSpace, "urn:test:eventcache:viewevents");

  const ua::EventNotifierType subscribable{ua::EventNotifierType::Bit::SubscribeToEvents};
  const NodeId notifierAId{namespaceIndex, std::uint32_t{9300}};
  const NodeId notifierBId{namespaceIndex, std::uint32_t{9301}};
  create_event_object(addressSpace, notifierAId, namespaceIndex, "ViewNotifierA", subscribable);
  create_event_object(addressSpace, notifierBId, namespaceIndex, "ViewNotifierB", subscribable);

  // A View that supports Events, whose CONTENT is the two notifier Objects.
  const NodeId viewId{namespaceIndex, std::uint32_t{9302}};
  auto viewNode = addressSpace.create_node_sync(viewId, ua::NodeClass::View);
  auto view = viewNode.as<ua::ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  view->set_browse_name(ua::QualifiedName{namespaceIndex, std::string{"EventAggregatingView"}});
  view->set_display_name(ua::LocalizedText{"", "EventAggregatingView"});
  view->set_event_notifier(subscribable);
  view->set_contains_no_loops(true);
  addressSpace.find_node_sync(NodeId{ua::ObjectId::ViewsFolder})
    .add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, viewId);
  viewNode.add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, notifierAId);
  viewNode.add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, notifierBId);
  // The content of a View is its membership (NR-16, NR-28 rule 1): the two notifiers are members.
  ASSERT_TRUE(view->try_add_node_to_view_sync(notifierAId).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(notifierBId).is_good());

  ua::client::detail::ConnectionConfig config;
  EventCacheFixture fixture{server, std::move(config)};
  ASSERT_TRUE(fixture.start().is_good());

  auto serverRecorder = std::make_shared<EventSourceRecorder>();
  auto viewRecorder = std::make_shared<EventSourceRecorder>();

  auto serverConsumer =
    fixture.conn().events().try_subscribe_sync(EventSubscription{.notifier = NodeId{ua::ObjectId::Server}},
      [serverRecorder](EventNotification notification) { serverRecorder->record(notification.sourceNode); });
  ASSERT_TRUE(serverConsumer.is_good()) << "the Server-Object control consumer must subscribe";

  auto viewConsumer = fixture.conn().events().try_subscribe_sync(EventSubscription{.notifier = viewId},
    [viewRecorder](EventNotification notification) { viewRecorder->record(notification.sourceNode); });
  ASSERT_TRUE(viewConsumer.is_good())
    << "a View whose EventNotifier carries SubscribeToEvents must accept an event MonitoredItem - a View "
       "that cannot be subscribed to can never provide the Events of its content (Part 3 section 5.4)";

  // Raise one event on EACH notifier Object inside the View.
  GenericEvent eventA{NodeId{ua::ObjectTypeId::BaseEventType}};
  eventA.sourceNode = notifierAId;
  eventA.sourceName = "ViewNotifierA";
  eventA.message = ua::LocalizedText{"", "event raised on the first notifier in the View"};
  eventA.severity = 100;
  server.server().emit_event(eventA);

  GenericEvent eventB{NodeId{ua::ObjectTypeId::BaseEventType}};
  eventB.sourceNode = notifierBId;
  eventB.sourceName = "ViewNotifierB";
  eventB.message = ua::LocalizedText{"", "event raised on the second notifier in the View"};
  eventB.severity = 100;
  server.server().emit_event(eventB);

  // Control: both events reached the event pipeline (the Server Object is the root notifier).
  ASSERT_TRUE(
    wait_until([&] { return serverRecorder->saw(notifierAId) && serverRecorder->saw(notifierBId); }))
    << "both raised events must reach the Server Object notifier - otherwise the stimulus never happened "
       "and the View assertions below would be meaningless";

  // OBSERVATION: EVERY one of them is delivered on the View that contains its source.
  EXPECT_TRUE(wait_until([&] { return viewRecorder->saw(notifierAId); }))
    << "the View must provide the Events of the first notifier Object in its content (Part 3 section 5.4)";
  EXPECT_TRUE(wait_until([&] { return viewRecorder->saw(notifierBId); }))
    << "the View must provide the Events of the second notifier Object in its content (Part 3 section 5.4)";
}

// =============================================================================================
// Part 3 section 5.4: "To avoid recursion, the Server Object ... shall never be part of any View since it
// provides all Events of the Server." The specification forbids the membership, not a Reference (NR-41): an
// integrator may organise the Server Object under a View Node and the Reference is stored, while a Browse in
// the context of any View still neither accepts the Server Object as the Node to browse nor returns a
// Reference to it. A server that stores the Reference and then shows the Server Object in the View's content
// is non-conforming, and so is one that shows it in a View it ships.
//
// Tier: the Views are found through the tier-2 typed browse. The browse in each View's context goes through a
// tier-1 Session, because the tier-2 BrowseOptions has no View (`ua_browse_cursor.h`); a View field there
// moves this half to tier 2.
// =============================================================================================
// @relation(AC-SVR-EVT-ATTR-007-SERVER-OBJECT-NOT-IN-VIEW, scope=function)
TEST_F(ClientEventCache, ServerObjectIsNeverPartOfAnyView)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  const std::uint16_t namespaceIndex = add_test_namespace(addressSpace, "urn:test:eventcache:serverinview");

  // A legitimate member of the View, so the content scan below is never vacuous.
  const NodeId memberId{namespaceIndex, std::uint32_t{9400}};
  create_event_object(addressSpace,
    memberId,
    namespaceIndex,
    "ViewMember",
    ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents});

  const NodeId viewId{namespaceIndex, std::uint32_t{9401}};
  auto viewNode = addressSpace.create_node_sync(viewId, ua::NodeClass::View);
  auto view = viewNode.as<ua::ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  view->set_browse_name(ua::QualifiedName{namespaceIndex, std::string{"RecursionGuardView"}});
  view->set_display_name(ua::LocalizedText{"", "RecursionGuardView"});
  view->set_event_notifier(ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents});
  view->set_contains_no_loops(true);
  addressSpace.find_node_sync(NodeId{ua::ObjectId::ViewsFolder})
    .add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, viewId);
  viewNode.add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, memberId);
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberId).is_good());

  // A Reference from a View Node to the Server Object is not membership, and is stored.
  const VoidResult organised =
    viewNode.try_add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, NodeId{ua::ObjectId::Server});
  EXPECT_EQ(organised.status_code().as_status(), Status::Good)
    << "an Organizes Reference from a View Node to the Server Object was refused";

  ua::client::detail::ConnectionConfig config;
  EventCacheFixture fixture{server, std::move(config)};
  ASSERT_TRUE(fixture.start().is_good());

  // Every View under the Views folder.
  const auto viewsFolderEntries =
    browse_references(fixture.conn(), NodeId{ua::ObjectId::ViewsFolder}, NodeId{});
  std::vector<NodeId> views;
  for (const auto& entry : viewsFolderEntries)
  {
    if (entry.isForward && entry.nodeClass == ua::NodeClass::View && entry.targetNodeId.server_index() == 0)
      views.push_back(entry.targetNodeId.node_id());
  }
  ASSERT_FALSE(views.empty()) << "at least one View must be reachable under the Views folder - otherwise "
                                 "the recursion-guard scan asserts over nothing";

  // Each View browsed in its own context: the Server Object is not a Node of it, and no Reference from the
  // View Node reaches it.
  auto session = fixture.open_tier1_session(server);
  int scannedViewReferences = 0;
  for (const NodeId& viewNodeId : views)
  {
    ua::BrowseRequest request;
    request.view().view_id() = viewNodeId;
    request.nodes_to_browse().resize(2);
    request.nodes_to_browse()[0].node_id() = viewNodeId;
    request.nodes_to_browse()[0].browse_direction() = ua::BrowseDirection::Forward;
    request.nodes_to_browse()[0].include_subtypes() = true;
    request.nodes_to_browse()[0].result_mask() = 0x3F;
    request.nodes_to_browse()[1].node_id() = NodeId{ua::ObjectId::Server};
    request.nodes_to_browse()[1].browse_direction() = ua::BrowseDirection::Forward;
    auto response = session.view().browse_sync(std::move(request));
    ASSERT_EQ(response.results().size(), 2u);
    EXPECT_EQ(response.results()[1].status_code().as_status(), Status::BadNodeNotInView)
      << "the Server Object is a Node of a View - Part 3 section 5.4 forbids it to avoid recursion";
    for (const auto& reference : response.results()[0].references())
    {
      if (reference.node_id().server_index() != 0)
        continue;
      ++scannedViewReferences;
      EXPECT_FALSE(reference.node_id().node_id() == NodeId{ua::ObjectId::Server})
        << "a View's content references the Server Object - Part 3 section 5.4 forbids it to avoid recursion";
    }
  }
  EXPECT_GT(scannedViewReferences, 0)
    << "the Views scanned must have content - an empty View proves nothing about the recursion guard";
  (void)session.try_close_sync();
}

// =============================================================================================
// EventNotifier history bits (Part 3 section 8.59 Table 42, bits 2 and 3).
//
// These rows need a notifier whose event history genuinely exists, so they back one namespace with
// the canonical Historical Access reference (`ua::history::HistoryNamespace` over the SQLite store +
// `ua::history::HistoryEngineDelegate`), which supports both historical-event reads and historical-event
// updates. All three notifier Objects live in THAT namespace and are served by THAT delegate, so they
// differ in exactly one thing: the bits of their EventNotifier attribute. Any difference in the
// HistoryRead / HistoryUpdate outcome is therefore attributable to the bit and to nothing else.
//
// The raw HistoryRead / HistoryUpdate services are reached through a tier-1 `Session`, because the
// tier-2 `HistoryFacade` exposes only value history - it has no event-history call at all.
// =============================================================================================

// The select clauses the reference engine keys historical event fields on (browse-path names).
ua::EventFilter historised_event_filter()
{
  auto clause = [](std::string_view name)
  {
    ua::SimpleAttributeOperand operand;
    operand.browse_path().push_back(ua::QualifiedName{0, std::string{name}});
    return operand;
  };
  ua::EventFilter filter;
  filter.select_clauses().push_back(clause("Time"));
  filter.select_clauses().push_back(clause("Severity"));
  filter.select_clauses().push_back(clause("Message"));
  return filter;
}

// A HistoryRead carrying ReadEventDetails for one node over a window that spans every event these
// rows insert (start + end + count, so the bounded-window pre-check is satisfied).
ua::HistoryReadRequest read_event_history(const NodeId& node)
{
  auto details = std::make_unique<ua::ReadEventDetails>();
  details->start_time() = ua::DateTime{2025, 1, 1, 0, 0, 0.0};
  details->end_time() = ua::DateTime{2025, 12, 31, 0, 0, 0.0};
  details->num_values_per_node() = 100;
  details->filter() = historised_event_filter();

  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  request.history_read_details() = std::move(details);
  ua::HistoryReadValueId nodeToRead;
  nodeToRead.node_id() = node;
  request.nodes_to_read().push_back(std::move(nodeToRead));
  return request;
}

// A HistoryUpdate inserting one historical event on @p node.
//
// The insert names every field BaseEventType makes Mandatory, which is more than the three these
// tests read back: OPC 10000-11 6.8.4.2 refuses an insert whose selectClause is short of the
// EventType's Mandatory set, so the wider filter is what makes this a stored Event rather than a
// refusal. The read filter stays narrow, which is what a Client actually asks for.
ua::HistoryUpdateRequest insert_event_history(const NodeId& node, double second, std::uint16_t severity)
{
  const ua::DateTime when{2025, 6, 1, 0, 0, second};

  ua::EventFilter filter;
  for (const auto* name :
    {"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"})
  {
    ua::SimpleAttributeOperand operand;
    operand.type_definition_id() = NodeId{ua::ObjectTypeId::BaseEventType};
    operand.browse_path().push_back(ua::QualifiedName{0, name});
    operand.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    filter.select_clauses().push_back(operand);
  }

  ua::HistoryEventFieldList fields;
  fields.event_fields().push_back(ua::Variant{});  // EventId: the Server generates one
  fields.event_fields().push_back(ua::Variant{NodeId{ua::ObjectTypeId::BaseEventType}});
  fields.event_fields().push_back(ua::Variant{node});
  fields.event_fields().push_back(ua::Variant{ua::String{"client event cache tests"}});
  fields.event_fields().push_back(ua::Variant{when});
  fields.event_fields().push_back(ua::Variant{when});
  fields.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "historised event"}});
  fields.event_fields().push_back(ua::Variant{severity});

  auto details = std::make_unique<ua::UpdateEventDetails>();
  details->node_id() = node;
  details->perform_insert_replace() = ua::PerformUpdateType::Insert;
  details->filter() = std::move(filter);
  details->event_data().push_back(std::move(fields));

  ua::HistoryUpdateRequest request;
  ua::RefStructure<ua::Structure> wrapped;
  wrapped = std::unique_ptr<ua::Structure>(std::move(details));
  request.history_update_details().push_back(std::move(wrapped));
  return request;
}

// Reads @p node's EventNotifier attribute over the wire. Returns nullopt when the attribute cannot be
// read or decoded, so a caller asserts on a real advertisement rather than on a default-constructed one.
std::optional<ua::EventNotifierType> read_event_notifier(Session& session, const NodeId& node)
{
  auto response = session.attributes().try_read_sync(read_value(node, ua::AttributeId::EventNotifier));
  if (response.is_bad())
    return std::nullopt;
  auto& read = response.value();
  if (!read.response_header().service_result().is_good() || read.results().size() != 1)
    return std::nullopt;
  const ua::Result<std::uint8_t> bits = read.results()[0].value().to<std::uint8_t>();
  if (bits.is_bad())
    return std::nullopt;
  return ua::EventNotifierType{bits.value()};
}

// Three notifier Objects in ONE namespace served by ONE event-capable history delegate. They differ
// only in their EventNotifier bits:
//   Historised    - SubscribeToEvents | HistoryRead | HistoryWrite
//   LiveOnly      - SubscribeToEvents                              (bit 2 and bit 3 clear)
//   ReadOnlyHistory - SubscribeToEvents | HistoryRead              (bit 3 clear, bit 2 set)
class ClientEventNotifierHistory : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    // Granted at CREATION, not through grant_namespace_to_test_client: what lands in the namespace
    // array is a HistoryNamespace WRAPPER, and that helper reaches a namespace by
    // dynamic_pointer_cast<default_ns::Namespace>, which a wrapper is not. A namespace declaring no
    // permissions publishes an ENGAGED, EMPTY default and refuses every node it owns, so the
    // EventNotifier read below comes back denied and reads as "the Object has no EventNotifier".
    // The wrapper forwards default_role_permissions() to the namespace it wraps, so granting the
    // inner one here is what the wrapper publishes. Same shape as
    // ComplianceWithReferenceHistory in compliance_history_tests.cpp.
    auto innerNamespace = addressSpace.create_namespace("urn:test:eventcache:eventhistory",
      []
      {
        std::vector<ua::RolePermissionType> grants;
        for (const auto role :
          {ua::ObjectId::WellKnownRole_Anonymous, ua::ObjectId::WellKnownRole_SecurityAdmin})
        {
          ua::RolePermissionType grant;
          grant.role_id() = ua::NodeId{role};
          grant.permissions() = ua::test_helpers::all_permissions();
          grants.push_back(std::move(grant));
        }
        return grants;
      }());
    auto store = std::make_unique<ua::history::SqliteHistoryStore>(
      ":memory:", mServer.server().ua_binary_data_value_codec());
    mDelegate = std::make_shared<ua::history::HistoryEngineDelegate>(std::move(store));
    auto historyNamespace =
      std::make_shared<ua::history::HistoryNamespace>(std::move(innerNamespace), mDelegate);
    mHistoryNsIndex = addressSpace.add_namespace_sync(historyNamespace);

    mHistorisedId = NodeId{mHistoryNsIndex, std::uint32_t{9600}};
    mLiveOnlyId = NodeId{mHistoryNsIndex, std::uint32_t{9601}};
    mReadOnlyHistoryId = NodeId{mHistoryNsIndex, std::uint32_t{9602}};

    create_event_object(addressSpace,
      mHistorisedId,
      mHistoryNsIndex,
      "HistorisedNotifier",
      ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents,
        ua::EventNotifierType::Bit::HistoryRead,
        ua::EventNotifierType::Bit::HistoryWrite});
    create_event_object(addressSpace,
      mLiveOnlyId,
      mHistoryNsIndex,
      "LiveOnlyNotifier",
      ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents});
    create_event_object(addressSpace,
      mReadOnlyHistoryId,
      mHistoryNsIndex,
      "ReadOnlyHistoryNotifier",
      ua::EventNotifierType{
        ua::EventNotifierType::Bit::SubscribeToEvents, ua::EventNotifierType::Bit::HistoryRead});
  }

  std::shared_ptr<ua::history::HistoryEngineDelegate> mDelegate;
  std::uint16_t mHistoryNsIndex{0};
  NodeId mHistorisedId;
  NodeId mLiveOnlyId;
  NodeId mReadOnlyHistoryId;
};

// =============================================================================================
// Part 3 section 8.59 (Table 42), bit 2: "HistoryRead - indicates if the history of the Events is readable."
// A plausible implementation ships the EventNotifier byte as a decorative advertisement and lets the
// HistoryRead service reach the namespace's history delegate for any notifier at all. A client
// consults bit 2 precisely so it does not have to try: a bit that does not predict the outcome sends
// a client that trusted it into a refusal, and keeps a client that trusted it away from history it
// could have read. Both directions have to hold, which is why both notifiers here sit behind the SAME
// event-capable delegate - the only difference between them is the bit.
// =============================================================================================
// @verifies AC-SVR-EVT-ATTR-010-BIT-TWO-HISTORYREAD
TEST_F(ClientEventNotifierHistory, EventNotifierBitTwoPredictsWhetherEventHistoryIsReadable)
{
  const auto historisedBits = read_event_notifier(*mSession, mHistorisedId);
  const auto liveOnlyBits = read_event_notifier(*mSession, mLiveOnlyId);
  ASSERT_TRUE(historisedBits.has_value()) << "EventNotifier must be readable on a notifier Object";
  ASSERT_TRUE(liveOnlyBits.has_value()) << "EventNotifier must be readable on a notifier Object";
  ASSERT_TRUE(historisedBits->test(ua::EventNotifierType::Bit::HistoryRead))
    << "the historised notifier must advertise bit 2 - otherwise this row tests nothing";
  ASSERT_FALSE(liveOnlyBits->test(ua::EventNotifierType::Bit::HistoryRead))
    << "the live-only notifier must NOT advertise bit 2 - otherwise this row tests nothing";

  // Give the historised notifier real event history, so a refusal below cannot be excused as
  // "there was nothing to read".
  auto seeded = mSession->attributes().try_history_update_sync(
    insert_event_history(mHistorisedId, /*second=*/1.0, /*severity=*/300));
  ASSERT_TRUE(seeded.is_good()) << "the seeding HistoryUpdate must not fail at the service interface";
  ASSERT_TRUE(seeded.value().response_header().service_result().is_good());
  ASSERT_EQ(seeded.value().results().size(), 1U);
  ASSERT_TRUE(seeded.value().results()[0].status_code().is_good())
    << "the historised notifier must accept the seed event - without it the read arm is untestable";

  // Bit 2 set: the event history is readable, and reading it returns the stored event.
  auto readable = mSession->attributes().try_history_read_sync(read_event_history(mHistorisedId));
  ASSERT_TRUE(readable.is_good()) << "HistoryRead must not fail at the service interface";
  ASSERT_TRUE(readable.value().response_header().service_result().is_good());
  ASSERT_EQ(readable.value().results().size(), 1U);
  EXPECT_TRUE(readable.value().results()[0].status_code().is_good())
    << "Part 3 section 8.59 bit 2 - a notifier advertising HistoryRead must let its event history be read";
  auto* readableEvents = dynamic_cast<ua::HistoryEvent*>(readable.value().results()[0].history_data().get());
  ASSERT_NE(readableEvents, nullptr) << "an events read must be wrapped in a HistoryEvent";
  EXPECT_EQ(readableEvents->events().size(), 1U) << "the seeded event must come back out of history";

  // Bit 2 clear: the same read against the same delegate is refused, and no events come back with it.
  auto unreadable = mSession->attributes().try_history_read_sync(read_event_history(mLiveOnlyId));
  ASSERT_TRUE(unreadable.is_good()) << "HistoryRead must not fail at the service interface";
  ASSERT_TRUE(unreadable.value().response_header().service_result().is_good());
  ASSERT_EQ(unreadable.value().results().size(), 1U);
  EXPECT_TRUE(unreadable.value().results()[0].status_code().is_bad())
    << "Part 3 section 8.59 bit 2 - a notifier that does not advertise HistoryRead must refuse an event "
       "history read; the bit has to predict the outcome, not decorate it";
  auto* refusedEvents = dynamic_cast<ua::HistoryEvent*>(unreadable.value().results()[0].history_data().get());
  EXPECT_TRUE(refusedEvents == nullptr || refusedEvents->events().empty())
    << "a refused event-history read must also return no events - a refusal that still hands back "
       "history is not a refusal";
}

// =============================================================================================
// Part 3 section 8.59 (Table 42), bit 3: "HistoryWrite - indicates if the history of the Events is writable."
// A plausible implementation checks AccessLevel.HistoryWrite on Variables and then, having no
// AccessLevel to consult on an Object, waves the Object through to the delegate. The advertisement
// then means nothing: a client that read bit 3 as clear and skipped the update was right for the
// wrong reason, and a client that trusted a clear bit is silently overruled by a server that writes
// anyway. The refusal alone is not enough - the refused insert must also leave the history
// untouched, which is what the read-back on the read-only notifier checks.
// =============================================================================================
// @verifies AC-SVR-EVT-ATTR-011-HISTORYWRITE-BIT
TEST_F(ClientEventNotifierHistory, EventNotifierBitThreePredictsWhetherEventHistoryIsWritable)
{
  const auto writableBits = read_event_notifier(*mSession, mHistorisedId);
  const auto readOnlyBits = read_event_notifier(*mSession, mReadOnlyHistoryId);
  ASSERT_TRUE(writableBits.has_value()) << "EventNotifier must be readable on a notifier Object";
  ASSERT_TRUE(readOnlyBits.has_value()) << "EventNotifier must be readable on a notifier Object";
  ASSERT_TRUE(writableBits->test(ua::EventNotifierType::Bit::HistoryWrite))
    << "the writable notifier must advertise bit 3 - otherwise this row tests nothing";
  ASSERT_FALSE(readOnlyBits->test(ua::EventNotifierType::Bit::HistoryWrite))
    << "the read-only notifier must NOT advertise bit 3 - otherwise this row tests nothing";
  ASSERT_TRUE(readOnlyBits->test(ua::EventNotifierType::Bit::HistoryRead))
    << "the read-only notifier must advertise bit 2, so the read-back below can observe whether the "
       "refused insert left a trace";

  // Bit 3 set: the insert is accepted, both at the node level and for the single update value.
  auto accepted = mSession->attributes().try_history_update_sync(
    insert_event_history(mHistorisedId, /*second=*/2.0, /*severity=*/400));
  ASSERT_TRUE(accepted.is_good()) << "HistoryUpdate must not fail at the service interface";
  ASSERT_TRUE(accepted.value().response_header().service_result().is_good());
  ASSERT_EQ(accepted.value().results().size(), 1U);
  EXPECT_TRUE(accepted.value().results()[0].status_code().is_good())
    << "Part 3 section 8.59 bit 3 - a notifier advertising HistoryWrite must accept an event history insert";
  ASSERT_FALSE(accepted.value().results()[0].operation_results().empty())
    << "an accepted HistoryUpdate must report a per-update-value result";
  EXPECT_TRUE(accepted.value().results()[0].operation_results()[0].is_good())
    << "the inserted event itself must be accepted, not merely the node-level operation";

  // Bit 3 clear: the identical insert against the same delegate is refused.
  auto refused = mSession->attributes().try_history_update_sync(
    insert_event_history(mReadOnlyHistoryId, /*second=*/3.0, /*severity=*/500));
  ASSERT_TRUE(refused.is_good()) << "HistoryUpdate must not fail at the service interface";
  ASSERT_TRUE(refused.value().response_header().service_result().is_good());
  ASSERT_EQ(refused.value().results().size(), 1U);
  EXPECT_TRUE(refused.value().results()[0].status_code().is_bad())
    << "Part 3 section 8.59 bit 3 - a notifier that does not advertise HistoryWrite must refuse an event "
       "history insert";

  // Control: the read path really does surface an inserted event, so the emptiness asserted below is
  // an observation about the refusal and not about a read that never returns anything.
  auto writtenBack = mSession->attributes().try_history_read_sync(read_event_history(mHistorisedId));
  ASSERT_TRUE(writtenBack.is_good()) << "HistoryRead must not fail at the service interface";
  ASSERT_EQ(writtenBack.value().results().size(), 1U);
  ASSERT_TRUE(writtenBack.value().results()[0].status_code().is_good());
  auto* writtenEvents =
    dynamic_cast<ua::HistoryEvent*>(writtenBack.value().results()[0].history_data().get());
  ASSERT_NE(writtenEvents, nullptr) << "an events read must be wrapped in a HistoryEvent";
  ASSERT_EQ(writtenEvents->events().size(), 1U)
    << "the accepted insert must be readable back - otherwise the emptiness checked next proves "
       "nothing about the refusal";

  // The other half of the refusal: nothing was written.
  auto untouched = mSession->attributes().try_history_read_sync(read_event_history(mReadOnlyHistoryId));
  ASSERT_TRUE(untouched.is_good()) << "HistoryRead must not fail at the service interface";
  ASSERT_EQ(untouched.value().results().size(), 1U);
  ASSERT_TRUE(untouched.value().results()[0].status_code().is_good())
    << "the read-only notifier advertises bit 2, so its event history must still be readable";
  auto* untouchedEvents =
    dynamic_cast<ua::HistoryEvent*>(untouched.value().results()[0].history_data().get());
  ASSERT_NE(untouchedEvents, nullptr) << "an events read must be wrapped in a HistoryEvent";
  EXPECT_TRUE(untouchedEvents->events().empty())
    << "the refused insert must have written nothing - a refusal that still stores the event makes "
       "bit 3 a lie about what the server did";
}

}  // namespace
