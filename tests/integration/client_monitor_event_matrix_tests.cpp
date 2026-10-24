// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientMonitorEventFilter / ClientMonitorEvent clusters of the client integration-test matrix (8
/// rows
///        that cover EVENT monitored items: the local EventFilter pre-flight, the composite-filter
///        WhereClause operator handling, the event wire shape, and the client-side event decode / demux /
///        advisory surfacing).
///
/// These are END-TO-END integration tests of the TIER-2 event backbone (client design section 8.13) entered
/// through the public `Connection::events()` / `EventSubscriber` handles and backed by the
/// lazily-constructed, co-owned `ua::client::detail::EventSubscriberImpl` (the collapsing per-Connection
/// event subscriber). The harness is the SAME `MisbehavingServer`-backed fixture the committed
/// ClientMonitoredItem / ClientMonitorControl clusters use (a real `Client` bound to a `MisbehavingServer`'s
/// crypto + trusted store over ephemeral TCP, an activated Session wrapped into a started `ConnectionImpl`,
/// the always-on Publish pump). Control is driven through:
///   - the public tier-2 EventSubscriber SUBSCRIBE path (`Connection::events().subscribe_async`), which
///   builds the composite
///     `EventFilter` and issues the backbone `CreateMonitoredItems` / `ModifyMonitoredItems`;
///   - the EventSubscriber DECODE/DEMUX entry point (`events_impl()->on_publish_events_async`) - see the
///     CALIBRATION note (2) below on why this is driven directly rather than through a real inbound Publish;
///   - the EVENT SINK (the per-consumer `EventNotificationCallback`) - what actually reaches the user;
///   - the WIRE OBSERVER (`MisbehavingServer::set_request_observer`) - the DECODED outgoing requests, so a
///   row
///     can assert the event MI wire shape (attributeId == EventNotifier, samplingInterval == 0, the composite
///     EventFilter); and
///   - the RESPONSE MUTATOR (`MisbehavingServer::set_response_mutator`) - to read the server-assigned
///   backbone
///     monitored-item id and to inject an EventFilterResult.
///
/// Falsifiability: every test encodes its matrix row's `[neg: ...]` falsifier and asserts the EXACT
/// observable. Timing is ALWAYS bounded polling on an observable, never a fixed sleep.
///
/// =====================================================================================================
/// CALIBRATION - where a matrix oracle assumes a client-side feature that is NOT built (assert REAL behavior;
/// see the authoring report for the batched write-up). These are the required findings this file pins:
/// =====================================================================================================
///   1. THE EVENT ENTRY POINT NAMED BY THE MATRIX IS DEFERRED. `Subscription::monitor_event_async` /
///      `try_monitor_event_sync` return `Bad_NotSupported`
///      (source `client.tier1.subscription.monitor_event.deferred_s10a`). The BUILT event path is
///      `Connection::events()` -> `EventSubscriber::subscribe_async` -> `EventSubscriberImpl` (the collapsing
///      backbone). Every row here drives that built path. Rows that assert LOCAL validation / wire shape
///      (RejectsEmptySelectClausesLocally, OfTypeAcceptedInvalidOperatorRejectedLocally,
///      TargetsEventNotifierAttribute, ForcesSamplingIntervalZero) are fully end-to-end through subscribe.
///
///   2. [CLOSED - the inbound event delivery hop is now wired.] Both PublishResponse decode sites -
///      `feed_publish_response` and the republish-drain in ua_connection_impl.cpp - now `dynamic_cast` an
///      `EventNotificationList` (in addition to `DataChangeNotification`) and route it through the free
///      helper `route_event_notification_list`, which groups the EventFieldLists by client_handle and calls
///      `EventSubscriberImpl::on_publish_events_async` per group. So a real inbound Publish carrying events
///      DOES reach the user event callback. RealInboundPublishRoutesEventToConsumer is the end-to-end proof:
///      it injects an EventNotificationList into a real outgoing PublishResponse (via the response mutator)
///      and asserts the event reaches the consumer through the production pump. The other DECODE/DEMUX rows
///      drive `on_publish_events_async` directly ON PURPOSE - for deterministic control over event CONTENT
///      (null / status-only fields, extra select clauses) that would be awkward to shape through the wire -
///      but they exercise the same real subscriber method on the real strand/executor. (The
///      malformed-mandatory MissingEventIdEmitsAdvisoryNotDispatched row uses the real inbound-publish
///      interface, not the direct call.)
///
///   3. [CLOSED - event delivery now runs through a dedicated per-subscriber delivery strand.]
///      `EventSubscriberImpl::dispatch_one` posts each consumer callback to `mDeliveryStrand` (a private
///      `boost::asio::strand` created in the ctor), the event analogue of the data-change
///      `SubscriptionsPipeline::mDeliveryStrand` fix, so same-consumer events are delivered in FIFO order and
///      never concurrently under a multi-threaded pool (CL-MI-026). Tracker/Refresh broadcasts deliberately
///      stay on `mStrand`/`mExecutor` (section 8.8). This file still asserts only the stable falsifier (all
///      events delivered, each exactly once) rather than a specific interleaving.
///
///   4. THE OPERATOR ALLOW-LIST IS UNBUILT. `subscribe_async` extracts OfType clauses and rebuilds them into
///      the composite WhereClause; ANY other WhereClause operator (InView / RelatedTo / ...) is SILENTLY
///      DROPPED (never rejected, never sent), and a filter carrying only such an operator makes the consumer
///      match-all with an EMPTY WhereClause. OfTypeAcceptedInvalidOperatorRejectedLocally asserts the REAL
///      behavior (no local reject, a wire request IS sent, the invalid operator is absent from the wire).
///
///   5. [CLOSED - EventFilterResult diagnostics are surfaced (CL-MI-018).]
///      The real create/modify backbone paths carry bad select-clause, where-element, and where-operand
///      statuses to the subscriber, which emits indexed public observer advisories without replacing the
///      successful monitored-item result.
///
///   6. [CLOSED - the mandatory-field guard is now built (Slice EV1, CL-EVT-001/002).]
///      `decode_notification` enforces the four normatively-guaranteed BaseEventType fields - EventId,
///      EventType, Time, ReceiveTime (Part 5 section 6.4.2 "shall always be returned as value") - as
///      present-as-value: a missing (empty Variant) or status-coded one drops the event AND fires
///      `ClientObserver::on_advisory_diagnostic` (source-tag `client.tier2.event_subscriber.*`). The
///      hard-drop is scoped to those four; an OPTIONAL / selected field (SourceName, a user SelectClause)
///      that is absent STILL dispatches (surfacing nullopt, CL-MI-017).
///      MissingEventIdEmitsAdvisoryNotDispatched asserts the REAL, now-built behavior (null EventId -> NOT
///      dispatched + advisory) through the real inbound-publish interface.
///
///   7. THERE IS NO SYNTHETIC-OVERFLOW HANDLING. An EventQueueOverflowEventType event is decoded and demuxed
///      as ORDINARY event data (a match-all consumer receives it); the client raises NO
///      `on_advisory_diagnostic`. QueueOverflowDispatchedToCallbackAndAdvisory asserts the REAL behavior (the
///      callback fires with the overflow type; NO advisory) and reports the missing advisory half.

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection_impl.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl_test_access.h"
#include "ua_event_subscriber.h"
#include "ua_event_subscriber_impl.h"
#include "ua_event_subscriber_test_access.h"
#include "ua_generic_event.h"

#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_monitored_item.h"
#include "ua_client_observers.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_filter_result.h"
#include "ua_event_notification_list.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitoring_parameters.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_publish_response.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_simple_attribute_operand.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionState;
using ua::client::detail::EventSubscriberImpl;
using ua::test_helpers::MisbehavingServer;

namespace
{

// The default event notifier every subscribe targets (the Server Object emits events on its EventNotifier).
const ua::NodeId notifier{ua::ObjectId::Server};

// ---------------------------------------------------------------------------------------------
// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
// ---------------------------------------------------------------------------------------------
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 8000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
    {
      return true;
    }
    std::this_thread::sleep_for(10ms);
  }
  return predicate();
}

// ---------------------------------------------------------------------------------------------
// Thread-safe sink for the EventNotifications delivered to a consumer's event callback.
// ---------------------------------------------------------------------------------------------
class EventNotificationSink
{
public:
  void push(EventNotification notification)
  {
    std::lock_guard lock(mMutex);
    mEvents.push_back(std::move(notification));
  }

  std::size_t size() const
  {
    std::lock_guard lock(mMutex);
    return mEvents.size();
  }

  std::vector<EventNotification> snapshot() const
  {
    std::lock_guard lock(mMutex);
    return mEvents;
  }

  // How many delivered events carry the exact @p eventType (proves dispatch + no collapse / duplication).
  std::size_t count_of_type(const ua::NodeId& eventType) const
  {
    std::lock_guard lock(mMutex);
    std::size_t count = 0;
    for (const auto& event : mEvents)
    {
      if (event.eventTypeId == eventType)
      {
        ++count;
      }
    }
    return count;
  }

private:
  mutable std::mutex mMutex;
  std::vector<EventNotification> mEvents;
};

class RecordingAuditObserver final : public AlarmObserver
{
public:
  void on_audit_event(const Connection&, EventNotification event) override
  {
    std::lock_guard lock(mMutex);
    ++mCalls;
    mLastType = std::move(event.eventTypeId);
    mLastAudit = std::move(event.audit);
  }

  void on_audit_session_event(const Connection&, EventNotification event) override
  {
    std::lock_guard lock(mMutex);
    ++mSessionCalls;
    mLastSessionSubtype = std::move(event.auditSubtype);
  }

  void on_audit_channel_event(const Connection&, EventNotification event) override
  {
    std::lock_guard lock(mMutex);
    ++mChannelCalls;
    mLastChannelSubtype = std::move(event.auditSubtype);
  }

  std::size_t calls() const
  {
    std::lock_guard lock(mMutex);
    return mCalls;
  }

  ua::NodeId last_type() const
  {
    std::lock_guard lock(mMutex);
    return mLastType;
  }

  std::optional<AuditEventFields> last_audit() const
  {
    std::lock_guard lock(mMutex);
    return mLastAudit;
  }

  std::size_t session_calls() const
  {
    std::lock_guard lock(mMutex);
    return mSessionCalls;
  }

  std::optional<AuditSubtypeFields> last_subtype() const
  {
    std::lock_guard lock(mMutex);
    return mLastSessionSubtype;
  }

  std::size_t channel_calls() const
  {
    std::lock_guard lock(mMutex);
    return mChannelCalls;
  }

  std::optional<AuditSubtypeFields> last_channel_subtype() const
  {
    std::lock_guard lock(mMutex);
    return mLastChannelSubtype;
  }

private:
  mutable std::mutex mMutex;
  std::size_t mCalls = 0;
  std::size_t mSessionCalls = 0;
  std::size_t mChannelCalls = 0;
  ua::NodeId mLastType;
  std::optional<AuditEventFields> mLastAudit;
  std::optional<AuditSubtypeFields> mLastSessionSubtype;
  std::optional<AuditSubtypeFields> mLastChannelSubtype;
};

class RecordingSystemStatusObserver final : public ServerStateObserver
{
public:
  struct Status
  {
    ua::NodeId sourceNode;
    ua::String sourceName;
    ua::ServerState state{ua::ServerState::Unknown};
    SystemStatusOrigin origin{SystemStatusOrigin::Server};
  };

  void on_system_status_change(const Connection&, ua::NodeId sourceNode, ua::String sourceName,
    ua::ServerState state, SystemStatusOrigin origin) override
  {
    std::lock_guard lock(mMutex);
    mStatuses.push_back(Status{std::move(sourceNode), std::move(sourceName), state, origin});
  }

  void on_progress_event(const Connection&, EventNotification event) override
  {
    std::lock_guard lock(mMutex);
    mProgressEvents.push_back(std::move(event));
  }

  std::vector<Status> statuses() const
  {
    std::lock_guard lock(mMutex);
    return mStatuses;
  }

  std::vector<EventNotification> progress_events() const
  {
    std::lock_guard lock(mMutex);
    return mProgressEvents;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Status> mStatuses;
  std::vector<EventNotification> mProgressEvents;
};

// ---------------------------------------------------------------------------------------------
// ConnectionObserver that counts on_advisory_diagnostic fires (the section 7.8 advisory channel the matrix's
// "advisory diagnostic" rows key on). Thread-safe: the sink fires on the observer delivery strand while the
// test thread reads the count.
// ---------------------------------------------------------------------------------------------
class AdvisoryCountingObserver : public ConnectionObserver
{
public:
  void on_advisory_diagnostic(
    const Connection& /*connection*/, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    std::lock_guard lock(mMutex);
    ++mCount;
    if (detail)
    {
      mLastSource = detail->source;
      mLastDetail = std::move(detail);
    }
  }

  std::size_t count() const
  {
    std::lock_guard lock(mMutex);
    return mCount;
  }

  std::string last_source() const
  {
    std::lock_guard lock(mMutex);
    return mLastSource;
  }

  std::shared_ptr<const ua::ErrorDetail> last_detail() const
  {
    std::lock_guard lock(mMutex);
    return mLastDetail;
  }

private:
  mutable std::mutex mMutex;
  std::size_t mCount = 0;
  std::string mLastSource;
  std::shared_ptr<const ua::ErrorDetail> mLastDetail;
};

// ---------------------------------------------------------------------------------------------
// EventWireCapture: a read-only snapshot of the DECODED event CreateMonitoredItems the client put on the
// wire, populated on a server strand by the request observer. Guarded by a mutex (observer + test thread
// concurrent).
// ---------------------------------------------------------------------------------------------
struct EventWireCapture
{
  mutable std::mutex mutex;

  std::size_t createCount = 0;
  std::uint32_t lastAttributeId = 0;
  double lastSamplingInterval = -1.0;
  ua::NodeId lastNodeId;
  bool lastHadEventFilter = false;
  std::optional<ua::EventFilter> lastEventFilter;

  void observe(const ua::Structure& request)
  {
    const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
    if (create == nullptr || create->items_to_create().size() < 1)
    {
      return;
    }
    const auto& item = create->items_to_create()[0];
    const auto& params = item.requested_parameters();

    std::lock_guard lock(mutex);
    ++createCount;
    lastAttributeId = item.item_to_monitor().attribute_id();
    lastNodeId = item.item_to_monitor().node_id();
    lastSamplingInterval = params.sampling_interval();
    lastHadEventFilter = false;
    lastEventFilter.reset();
    if (params.filter())
    {
      if (const auto* filter = dynamic_cast<const ua::EventFilter*>(params.filter().get()))
      {
        lastHadEventFilter = true;
        lastEventFilter = *filter;
      }
    }
  }

  std::size_t create_count() const
  {
    std::lock_guard lock(mutex);
    return createCount;
  }

  std::uint32_t last_attribute_id() const
  {
    std::lock_guard lock(mutex);
    return lastAttributeId;
  }

  double last_sampling_interval() const
  {
    std::lock_guard lock(mutex);
    return lastSamplingInterval;
  }

  ua::NodeId last_node_id() const
  {
    std::lock_guard lock(mutex);
    return lastNodeId;
  }

  bool last_had_event_filter() const
  {
    std::lock_guard lock(mutex);
    return lastHadEventFilter;
  }

  std::optional<ua::EventFilter> last_event_filter() const
  {
    std::lock_guard lock(mutex);
    return lastEventFilter;
  }
};

// The response cast used to read the backbone's server-assigned monitored-item id / to inject a filter
// result.
ua::CreateMonitoredItemsResponse* as_create_items(ua::Response& response)
{
  return dynamic_cast<ua::CreateMonitoredItemsResponse*>(response.second.get());
}

// The response cast used to inject an EventNotificationList into an outgoing PublishResponse (the REAL
// inbound wire path that RealInboundPublishRoutesEventToConsumer drives through feed_publish_response).
ua::PublishResponse* as_publish(ua::Response& response)
{
  return dynamic_cast<ua::PublishResponse*>(response.second.get());
}

// Rewrite a PublishResponse's sequence number so every injected notification is classified InOrder (the
// client tracks per-subscription sequence continuity; a monotonic counter keeps each injected Publish
// deliverable rather than being dropped as a duplicate/gap).
void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

// Replace a PublishResponse's notification data with a single EventNotificationList carrying @p fields - the
// event analogue of the by-index tests' set_data_change. Drives the production event demux end-to-end:
// feed_publish_response dynamic_casts the EventNotificationList and routes it to the EventSubscriber.
void set_event_notification(ua::PublishResponse& publish, ua::EventFieldList fields)
{
  publish.notification_message().notification_data().clear();
  auto notification = std::make_unique<ua::EventNotificationList>();
  notification->events().push_back(std::move(fields));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// ----- EventFilter building blocks (mirror EventSubscriberImpl's own construction) -----

ua::SimpleAttributeOperand make_select_clause(std::string_view browseName)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = ua::NodeId{ua::ObjectTypeId::BaseEventType};
  operand.browse_path().push_back(ua::QualifiedName{0, std::string{browseName}});
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return operand;
}

ua::ContentFilterElement make_operator_element(ua::FilterOperator op, const ua::NodeId& literal)
{
  ua::LiteralOperand operand;
  operand.value() = ua::Variant{literal};
  ua::ContentFilterElement element;
  element.filter_operator() = op;
  element.filter_operands().push_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
  return element;
}

// True iff @p filter's WhereClause carries an OfType element whose literal decodes to @p typeId.
bool where_has_of_type(const ua::EventFilter& filter, const ua::NodeId& typeId)
{
  for (const auto& element : filter.where_clause().elements())
  {
    if (element.filter_operator() != ua::FilterOperator::OfType || element.filter_operands().size() == 0)
    {
      continue;
    }
    const auto* literal = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
    if (literal == nullptr)
    {
      continue;
    }
    const ua::Result<ua::NodeId> asNode = literal->value().to<ua::NodeId>();
    if (asNode.is_good() && asNode.value() == typeId)
    {
      return true;
    }
  }
  return false;
}

// One EventFieldList carrying the 8 BaseEventType mandatories in composite order (slots 0..7), plus any @p
// extras appended (slots 8..). @p eventIdField occupies slot 0 verbatim (so a null/empty EventId can be
// injected). @p eventType is decodable at slot 1.
ua::EventFieldList make_event_fields(std::uint32_t backboneHandle, const ua::Variant& eventIdField,
  const ua::NodeId& eventType, const std::vector<ua::Variant>& extras = {})
{
  ua::EventFieldList list;
  list.client_handle() = backboneHandle;
  list.event_fields().push_back(eventIdField);  // slot 0: EventId
  list.event_fields().push_back(ua::Variant{eventType});  // slot 1: EventType
  list.event_fields().push_back(ua::Variant{ua::NodeId{ua::ObjectId::Server}});  // slot 2: SourceNode
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "src"}});  // slot 3: SourceName
  list.event_fields().push_back(ua::Variant{ua::DateTime{}});  // slot 4: Time
  list.event_fields().push_back(ua::Variant{ua::DateTime{}});  // slot 5: ReceiveTime
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "msg"}});  // slot 6: Message
  list.event_fields().push_back(ua::Variant{std::uint16_t{5}});  // slot 7: Severity
  for (const auto& extra : extras)
  {
    list.event_fields().push_back(extra);
  }
  return list;
}

// ---------------------------------------------------------------------------------------------
// MisbehavingEventFixture: the ClientMonitoredItem harness, exposing the tier-2 EventSubscriberImpl and the
// blocking subscribe / feed helpers the event rows drive.
// ---------------------------------------------------------------------------------------------
class MisbehavingEventFixture
{
public:
  explicit MisbehavingEventFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = server.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appConfig.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientMonitorEventMatrix"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingEventFixture()
  {
    if (mConnection)
    {
      (void)close_and_wait(*mConnection);
    }
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingEventFixture(const MisbehavingEventFixture&) = delete;
  MisbehavingEventFixture& operator=(const MisbehavingEventFixture&) = delete;

  ConnectionImpl& conn()
  {
    return *mConnection;
  }

  std::shared_ptr<EventSubscriberImpl> events()
  {
    return mConnection->events_impl();
  }

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  void install_advisory_observer(std::shared_ptr<AdvisoryCountingObserver> observer)
  {
    mConnection->set_connection_observer_async(std::move(observer));
  }

  // Blocking subscribe through the public tier-2 Connection::events() handle. Returns the SubscribeResult
  // (a Result<MonitoredItem> with kind() == Event).
  SubscribeResult subscribe(EventSubscription subscription, EventNotificationCallback onEvent)
  {
    auto connection = ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
    auto subscriber = connection.events();
    std::promise<SubscribeResult> promise;
    auto future = promise.get_future();
    subscriber.subscribe_async(std::move(subscription),
      std::move(onEvent),
      [&promise](SubscribeResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  AlarmConditionTracker alarms()
  {
    auto connection = ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
    return connection.alarms();
  }

  // Every one of these reads EventSubscriberImpl state from the TEST thread while the subscriber's
  // own strand is live, so they all take the `_thread_safe` variants, which read ON that strand.
  // The bare accessors are for a quiesced subscriber. Using one here is what ThreadSanitizer
  // reported in pipeline 2853776712: `backbone_index_for_of_type` walked mBackbones from a
  // wait_until poll while find_or_add_backbone appended to the same vector on the strand. The SDK
  // side was never at fault - EventSubscriberImpl posts every public method to its strand - so the
  // fix belongs here, in the harness that stepped around it.
  std::size_t created_backbone_count()
  {
    return ua::client::detail::EventSubscriberTestAccess::created_backbone_count_thread_safe(*events());
  }

  std::optional<ua::EventFilter> last_sent_filter()
  {
    return ua::client::detail::EventSubscriberTestAccess::last_sent_filter_thread_safe(*events());
  }

  std::uint32_t backbone_client_handle()
  {
    return ua::client::detail::EventSubscriberTestAccess::backbone_client_handle_thread_safe(*events(), 0);
  }

  std::optional<std::size_t> backbone_index_for_type(const ua::NodeId& type)
  {
    return ua::client::detail::EventSubscriberTestAccess::backbone_index_for_of_type_thread_safe(
      *events(), type);
  }

  std::optional<ua::EventFilter> last_sent_filter(std::size_t backboneIndex)
  {
    return ua::client::detail::EventSubscriberTestAccess::last_sent_filter_thread_safe(
      *events(), backboneIndex);
  }

  std::uint32_t backbone_client_handle(std::size_t backboneIndex)
  {
    return ua::client::detail::EventSubscriberTestAccess::backbone_client_handle_thread_safe(
      *events(), backboneIndex);
  }

  void install_alarm_observer(std::shared_ptr<AlarmObserver> observer)
  {
    auto connection = ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
    connection.set_alarm_observer(std::move(observer));
  }

  void install_server_state_observer(std::shared_ptr<ServerStateObserver> observer)
  {
    auto connection = ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
    connection.set_server_state_observer(std::move(observer));
  }

  // Feed one or more decoded EventFieldLists into the REAL subscriber decode/demux entry point (the
  // production pipeline never routes EventNotificationList - see CALIBRATION note 2). Blocks until the demux
  // completion fires; the per-consumer callbacks then land asynchronously on the executor (poll the sink
  // afterwards).
  void feed_events(std::uint32_t backboneMonitoredItemId, std::vector<ua::EventFieldList> notifications)
  {
    std::promise<void> promise;
    auto future = promise.get_future();
    events()->on_publish_events_async(
      backboneMonitoredItemId, std::move(notifications), [&promise] { promise.set_value(); });
    future.get();
  }

  static VoidResult start_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult close_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

// Installs a request observer that records the last event CreateMonitoredItems the client put on the wire.
std::shared_ptr<EventWireCapture> arm_wire_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<EventWireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  return capture;
}

// The public alarm tracker and event subscriber share the default Server notifier backbone. Adding the
// second logical consumer may widen the filter, but must not create a second server MonitoredItem.
// @verifies CL-AC-001
// @relation(CL-AC-001, scope=function)
TEST(ClientMonitorEvent, PublicAlarmAndEventConsumersShareOneBackbone)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  auto alarms = fixture.alarms();
  ASSERT_TRUE(wait_until([&] { return capture->create_count() == 1U; }));
  ASSERT_TRUE(wait_until([&] { return fixture.created_backbone_count() == 1U; }))
    << "wait for the alarm backbone create response before adding the second public consumer";

  ua::EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("Message"));
  filter.where_clause().elements().push_back(
    make_operator_element(ua::FilterOperator::OfType, ua::NodeId{ua::ObjectTypeId::ConditionType}));
  EventSubscription subscription;
  subscription.notifier = notifier;
  subscription.filter = std::move(filter);

  const auto event = fixture.subscribe(std::move(subscription), [](EventNotification) {});
  ASSERT_TRUE(event.is_good()) << to_string(event.status_code());
  EXPECT_FALSE(wait_until([&] { return capture->create_count() > 1U; }, 500ms))
    << "public alarms() and events() consumers on Server must share one event MonitoredItem";
  EXPECT_EQ(capture->create_count(), 1U);
  (void)alarms;
}

// Refresh control events bypass per-consumer matching and broadcast to the attached alarm tracker. Event
// injection is stimulus-only; the observable is the public AlarmConditionTracker snapshot.
// @verifies CL-AC-008
// @relation(CL-AC-008, scope=function)
TEST(ClientMonitorEvent, RefreshStartBroadcastReachesPublicAlarmTracker)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto alarms = fixture.alarms();
  ASSERT_TRUE(wait_until([&] { return fixture.created_backbone_count() == 1U; }));
  const auto composite = fixture.last_sent_filter();
  ASSERT_TRUE(composite.has_value());
  const std::uint32_t backboneHandle = fixture.backbone_client_handle();

  ua::EventFieldList refreshStart;
  refreshStart.client_handle() = backboneHandle;
  for (const auto& clause : composite->select_clauses())
  {
    const std::string_view name = clause.browse_path().size() == 1
                                    ? static_cast<std::string_view>(clause.browse_path()[0].name())
                                    : std::string_view{};
    if (name == "EventType")
      refreshStart.event_fields().push_back(ua::Variant{ua::NodeId{ua::ObjectTypeId::RefreshStartEventType}});
    else if (name == "EventId")
      refreshStart.event_fields().push_back(ua::Variant{ua::ByteString{0x0A, 0x0B}});
    else
      refreshStart.event_fields().push_back(ua::Variant{});
  }

  fixture.feed_events(backboneHandle, {std::move(refreshStart)});
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto info = alarms.info();
      return info && info->openRefreshWindowCount == 1U;
    }));
}

// AuditEventType events are routed through the EventRouter and surfaced on the public AlarmObserver hook.
// @verifies CL-AUDIT-003
// @verifies CL-AUDIT-004
// @verifies CL-AUDIT-005
// @verifies CL-AUDIT-006
// @verifies CL-AUDIT-007
// @verifies CL-AUDIT-008
// @relation(CL-AUDIT-003, scope=function)
// @relation(CL-AUDIT-004, scope=function)
// @relation(CL-AUDIT-005, scope=function)
// @relation(CL-AUDIT-006, scope=function)
// @relation(CL-AUDIT-007, scope=function)
// @relation(CL-AUDIT-008, scope=function)
TEST(ClientMonitorEvent, AuditEventRoutesToPublicAlarmObserver)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto observer = std::make_shared<RecordingAuditObserver>();
  fixture.install_alarm_observer(observer);

  const ua::NodeId auditType{ua::ObjectTypeId::AuditEventType};
  const ua::NodeId channelType{ua::ObjectTypeId::AuditOpenSecureChannelEventType};
  const ua::NodeId sessionType{ua::ObjectTypeId::AuditCreateSessionEventType};
  std::optional<std::size_t> backboneIndex;
  ASSERT_TRUE(wait_until(
    [&]
    {
      backboneIndex = fixture.backbone_index_for_type(auditType);
      return backboneIndex.has_value();
    }));
  const auto composite = fixture.last_sent_filter(*backboneIndex);
  ASSERT_TRUE(composite.has_value());
  EXPECT_TRUE(std::ranges::any_of(composite->select_clauses(),
    [](const auto& clause)
    {
      return clause.browse_path().size() == 1 &&
             static_cast<std::string_view>(clause.browse_path()[0].name()) == "StatusCodeId";
    }));
  const std::uint32_t backboneHandle = fixture.backbone_client_handle(*backboneIndex);

  const auto makeAudit = [&](const ua::NodeId& runtimeType)
  {
    ua::EventFieldList audit;
    audit.client_handle() = backboneHandle;
    for (const auto& clause : composite->select_clauses())
    {
      const std::string_view name = clause.browse_path().size() == 1
                                      ? static_cast<std::string_view>(clause.browse_path()[0].name())
                                      : std::string_view{};
      if (name == "EventType")
        audit.event_fields().push_back(ua::Variant{runtimeType});
      else if (name == "EventId")
        audit.event_fields().push_back(ua::Variant{ua::ByteString{0xAA}});
      else if (name == "Time" || name == "ReceiveTime" || name == "ActionTimeStamp")
        audit.event_fields().push_back(ua::Variant{ua::DateTime{2026, 7, 23, 12, 0, 0.0}});
      else if (name == "Status")
        audit.event_fields().push_back(ua::Variant{true});
      else if (name == "ServerId")
        audit.event_fields().push_back(ua::Variant{ua::String{"server-1"}});
      else if (name == "ClientAuditEntryId")
        audit.event_fields().push_back(ua::Variant{ua::String{"audit-xyz"}});
      else if (name == "ClientUserId")
        audit.event_fields().push_back(ua::Variant{ua::String{"operator"}});
      else if (name == "StatusCodeId")
        audit.event_fields().push_back(ua::Variant{ua::StatusCode{ua::Status::BadUserAccessDenied}});
      else if (name == "SessionId" && runtimeType == sessionType)
        audit.event_fields().push_back(ua::Variant{ua::NodeId{2, 700U}});
      else if (name == "SecureChannelId")
      {
        const bool applicable =
          (runtimeType == channelType &&
            clause.type_definition_id() == ua::NodeId{ua::ObjectTypeId::AuditChannelEventType}) ||
          (runtimeType == sessionType &&
            clause.type_definition_id() == ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType});
        audit.event_fields().push_back(
          applicable ? ua::Variant{ua::String{"shared-channel-42"}} : ua::Variant{});
      }
      else
        audit.event_fields().push_back(ua::Variant{});
    }
    return audit;
  };

  fixture.feed_events(backboneHandle, {makeAudit(channelType), makeAudit(sessionType)});
  ASSERT_TRUE(wait_until([&] { return observer->calls() == 2U; }));
  EXPECT_EQ(observer->last_type(), sessionType);
  const auto decoded = observer->last_audit();
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->status);
  EXPECT_EQ(decoded->serverId, ua::String{"server-1"});
  EXPECT_EQ(decoded->clientAuditEntryId, ua::String{"audit-xyz"});
  EXPECT_EQ(decoded->clientUserId, ua::String{"operator"});
  ASSERT_TRUE(wait_until([&] { return observer->session_calls() == 1U; }));
  const auto subtype = observer->last_subtype();
  ASSERT_TRUE(subtype.has_value());
  EXPECT_EQ(subtype->category, ua::client::AuditEventCategory::Session);
  EXPECT_EQ(subtype->statusCodeId, ua::StatusCode{ua::Status::BadUserAccessDenied});
  EXPECT_EQ(subtype->sessionId, ua::NodeId(2, 700U));
  EXPECT_EQ(subtype->secureChannelId, ua::String{"shared-channel-42"});
  ASSERT_TRUE(wait_until([&] { return observer->channel_calls() == 1U; }));
  const auto channelSubtype = observer->last_channel_subtype();
  ASSERT_TRUE(channelSubtype.has_value());
  EXPECT_EQ(channelSubtype->category, ua::client::AuditEventCategory::Channel);
  EXPECT_EQ(channelSubtype->secureChannelId, subtype->secureChannelId);
}

// SystemStatusChangeEventType preserves the affected system identity and classifies NS0 Server separately
// from application-level underlying systems at the public ServerStateObserver boundary.
// @verifies CL-EVT-005
// @relation(CL-EVT-005, scope=function)
TEST(ClientMonitorEvent, SystemStatusChangeClassifiesPublicObserverSources)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto observer = std::make_shared<RecordingSystemStatusObserver>();
  fixture.install_server_state_observer(observer);

  const ua::NodeId systemStatusType{ua::ObjectTypeId::SystemStatusChangeEventType};
  std::optional<std::size_t> backboneIndex;
  ASSERT_TRUE(wait_until(
    [&]
    {
      backboneIndex = fixture.backbone_index_for_type(systemStatusType);
      return backboneIndex.has_value();
    }));
  const auto composite = fixture.last_sent_filter(*backboneIndex);
  ASSERT_TRUE(composite.has_value());
  const std::uint32_t backboneHandle = fixture.backbone_client_handle(*backboneIndex);

  const auto makeStatus = [&](ua::NodeId sourceNode, std::string_view sourceName, ua::ServerState state)
  {
    ua::EventFieldList event;
    event.client_handle() = backboneHandle;
    for (const auto& clause : composite->select_clauses())
    {
      const std::string_view name = clause.browse_path().size() == 1
                                      ? static_cast<std::string_view>(clause.browse_path()[0].name())
                                      : std::string_view{};
      if (name == "EventType")
        event.event_fields().push_back(ua::Variant{systemStatusType});
      else if (name == "EventId")
        event.event_fields().push_back(ua::Variant{ua::ByteString{0x51}});
      else if (name == "SourceNode")
        event.event_fields().push_back(ua::Variant{sourceNode});
      else if (name == "SourceName")
        // OPC 10000-5 defines SourceName as a String, not a LocalizedText. The stimulus carried a
        // LocalizedText until the decoder was corrected to the declared type, at which point the field
        // stopped decoding - so the wrong stimulus and the wrong observer type had been agreeing.
        event.event_fields().push_back(ua::Variant{ua::String{std::string{sourceName}}});
      else if (name == "Time" || name == "ReceiveTime")
        event.event_fields().push_back(ua::Variant{ua::DateTime{2026, 7, 24, 10, 0, 0.0}});
      else if (name == "SystemState")
        event.event_fields().push_back(ua::Variant{static_cast<std::int32_t>(state)});
      else
        event.event_fields().push_back(ua::Variant{});
    }
    return event;
  };

  fixture.feed_events(backboneHandle,
    {makeStatus(ua::NodeId{ua::ObjectId::Server}, "Server", ua::ServerState::Shutdown),
      makeStatus(ua::NodeId{2, 42}, "Device42", ua::ServerState::Failed)});

  ASSERT_TRUE(wait_until([&] { return observer->statuses().size() == 2U; }));
  const auto statuses = observer->statuses();
  EXPECT_EQ(statuses[0].sourceNode, ua::NodeId{ua::ObjectId::Server});
  EXPECT_EQ(statuses[0].state, ua::ServerState::Shutdown);
  EXPECT_EQ(statuses[0].origin, SystemStatusOrigin::Server);
  EXPECT_EQ(statuses[1].sourceNode, (ua::NodeId{2, 42}));
  EXPECT_EQ(static_cast<std::string_view>(statuses[1].sourceName), "Device42");
  EXPECT_EQ(statuses[1].state, ua::ServerState::Failed);
  EXPECT_EQ(statuses[1].origin, SystemStatusOrigin::UnderlyingSystem);
}

// @verifies CL-EVT-006
// @relation(CL-EVT-006, scope=function)
TEST(ClientMonitorEvent, ProgressEventRoutesTypedServiceCorrelationAndClampAdvisory)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto observer = std::make_shared<RecordingSystemStatusObserver>();
  auto advisory = std::make_shared<AdvisoryCountingObserver>();
  fixture.install_server_state_observer(observer);
  fixture.install_advisory_observer(advisory);

  const ua::NodeId progressType{ua::ObjectTypeId::ProgressEventType};
  std::optional<std::size_t> backboneIndex;
  ASSERT_TRUE(wait_until(
    [&]
    {
      backboneIndex = fixture.backbone_index_for_type(progressType);
      return backboneIndex.has_value();
    }));
  const auto composite = fixture.last_sent_filter(*backboneIndex);
  ASSERT_TRUE(composite.has_value());
  EXPECT_TRUE(std::ranges::any_of(composite->select_clauses(),
    [](const auto& clause)
    {
      return clause.browse_path().size() == 1 &&
             static_cast<std::string_view>(clause.browse_path()[0].name()) == "Context";
    }));
  EXPECT_TRUE(std::ranges::any_of(composite->select_clauses(),
    [](const auto& clause)
    {
      return clause.browse_path().size() == 1 &&
             static_cast<std::string_view>(clause.browse_path()[0].name()) == "Progress";
    }));
  const std::uint32_t backboneHandle = fixture.backbone_client_handle(*backboneIndex);

  ua::EventFieldList progress;
  progress.client_handle() = backboneHandle;
  for (const auto& clause : composite->select_clauses())
  {
    const std::string_view name = clause.browse_path().size() == 1
                                    ? static_cast<std::string_view>(clause.browse_path()[0].name())
                                    : std::string_view{};
    if (name == "EventType")
      progress.event_fields().push_back(ua::Variant{progressType});
    else if (name == "EventId")
      progress.event_fields().push_back(ua::Variant{ua::ByteString{0x61}});
    else if (name == "SourceName")
      // SourceName is a String (OPC 10000-5); the client classifies sourceKind from it, so feeding a
      // LocalizedText leaves the field undecoded and the correlation silently absent.
      progress.event_fields().push_back(ua::Variant{ua::String{"Service/Read"}});
    else if (name == "Time" || name == "ReceiveTime")
      progress.event_fields().push_back(ua::Variant{ua::DateTime{2026, 7, 24, 11, 0, 0.0}});
    else if (name == "Context")
      progress.event_fields().push_back(ua::Variant{std::uint32_t{42}});
    else if (name == "Progress")
      progress.event_fields().push_back(ua::Variant{std::uint16_t{150}});
    else
      progress.event_fields().push_back(ua::Variant{});
  }

  const std::size_t advisoriesBefore = advisory->count();
  fixture.feed_events(backboneHandle, {std::move(progress)});
  ASSERT_TRUE(wait_until(
    [&] { return observer->progress_events().size() == 1U && advisory->count() > advisoriesBefore; }));
  const auto event = observer->progress_events().front();
  ASSERT_TRUE(event.progress);
  EXPECT_EQ(event.progress->sourceKind, ua::client::ProgressSourceKind::Service);
  EXPECT_EQ(event.progress->requestHandle, 42U);
  EXPECT_EQ(event.progress->progress, 100U);
  ASSERT_NE(advisory->last_detail(), nullptr);
  EXPECT_EQ(advisory->last_detail()->code, "ProgressOutOfRange");
}

// Installs a request observer that records the backbone's CLIENT-assigned handle from the
// CreateMonitoredItems REQUEST - the value the server echoes in EventFieldList.client_handle and the
// EventSubscriber's inbound demux key (NOT the server-assigned monitoredItemId; the wire carries no
// monitored-item id). Optionally runs an edit on the create RESPONSE (e.g. inject a filter result) via a
// separate response mutator.
std::shared_ptr<std::atomic<std::uint32_t>> arm_backbone_id_capture(
  MisbehavingServer& server, std::function<void(ua::CreateMonitoredItemsResponse&)> edit = {})
{
  auto backboneHandle = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_request_observer(
    [backboneHandle](const ua::Structure& request)
    {
      const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
      if (create == nullptr || create->items_to_create().empty())
      {
        return;
      }
      backboneHandle->store(create->items_to_create()[0].requested_parameters().client_handle());
    });
  if (edit)
  {
    server.set_response_mutator(
      [edit = std::move(edit)](Response& response)
      {
        if (auto* create = as_create_items(response))
        {
          edit(*create);
        }
      });
  }
  return backboneHandle;
}

}  // namespace

// =============================================================================================
// ClientMonitorEventFilter
// =============================================================================================
class ClientMonitorEventFilter : public ::testing::Test
{};

// Row - RejectsEmptySelectClausesLocally  (MisbehavingServer)  [integration+unit]
// An EventFilter with a present-but-empty SelectClause list must be rejected LOCALLY, before any wire
// request: try_subscribe returns Bad_EventFilterInvalid with a source-tagged ErrorDetail and NO
// CreateMonitoredItems is emitted. subscribe_async performs this check at the entry point, before the strand
// hop. [neg: empty selectClauses rejected before send]
// @verifies CL-MI-016
// @relation(CL-MI-016, scope=function)
TEST_F(ClientMonitorEventFilter, RejectsEmptySelectClausesLocally)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  // A present (non-null) filter whose SelectClause list is EMPTY, with a WhereClause set (matrix stimulus).
  ua::EventFilter emptySelectFilter;
  emptySelectFilter.where_clause().elements().push_back(
    make_operator_element(ua::FilterOperator::OfType, ua::NodeId{ua::ObjectTypeId::BaseEventType}));
  EventSubscription subscription;
  subscription.notifier = notifier;
  subscription.filter = std::move(emptySelectFilter);

  const auto result = fixture.subscribe(std::move(subscription), [](EventNotification) {});

  EXPECT_TRUE(result.is_bad()) << "an empty-SelectClause EventFilter must be rejected locally";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadEventFilterInvalid})
    << "the local pre-flight must surface Bad_EventFilterInvalid (CL-MI-016)";
  ASSERT_TRUE(result.shared_detail()) << "the local reject must carry a source-tagged ErrorDetail";
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.event_subscriber.empty_select_clauses");

  // The reject happens before the strand hop, so NO backbone CreateMonitoredItems reaches the wire. Settle to
  // prove the absence is stable (an in-flight create would appear within the bounded window).
  EXPECT_FALSE(wait_until([&] { return capture->create_count() >= 1; }, 500ms))
    << "a locally-rejected empty filter must emit NO CreateMonitoredItems (no wasted round-trip)";
}

// Row - OfTypeAcceptedInvalidOperatorRejectedLocally  (MisbehavingServer)  [integration+unit]
// (a) A WhereClause with OfType(subtype of BaseEventType) is accepted and encoded onto the wire composite.
// (b) A WhereClause with InView(...) is rejected LOCALLY with source-tagged ErrorDetail and NO wire request.
// The public tier-2 Connection::events() facade is the highest implemented event-monitoring production tier;
// the tier-1 Subscription::monitor_event_* surface remains deferred. [neg: InView/RelatedTo rejected]
// @verifies CL-MI-023
// @relation(CL-MI-023, scope=function)
TEST_F(ClientMonitorEventFilter, OfTypeAcceptedInvalidOperatorRejectedLocally)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  const ua::NodeId ofTypeTarget{ua::ObjectTypeId::AuditEventType};  // a subtype of BaseEventType

  // (a) OfType is accepted and encoded onto the wire composite WhereClause.
  {
    ua::EventFilter ofTypeFilter;
    ofTypeFilter.select_clauses().push_back(make_select_clause("Foo"));  // >=1 clause: passes the empty-check
    ofTypeFilter.where_clause().elements().push_back(
      make_operator_element(ua::FilterOperator::OfType, ofTypeTarget));
    EventSubscription subscription;
    subscription.notifier = notifier;
    subscription.filter = std::move(ofTypeFilter);

    const auto result = fixture.subscribe(std::move(subscription), [](EventNotification) {});
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_TRUE(wait_until([&] { return capture->create_count() >= 1; }));
    const auto wireFilter = capture->last_event_filter();
    ASSERT_TRUE(capture->last_had_event_filter() && wireFilter.has_value())
      << "the event CreateMonitoredItems must carry an EventFilter ExtensionObject";
    EXPECT_TRUE(where_has_of_type(*wireFilter, ofTypeTarget))
      << "the OfType(AuditEventType) clause must be encoded onto the wire composite WhereClause";
  }

  // (b) InView is rejected before the subscriber strand hop and no request reaches the server.
  {
    const std::size_t createsBefore = capture->create_count();
    ua::EventFilter inViewFilter;
    inViewFilter.select_clauses().push_back(make_select_clause("Bar"));  // >=1 clause: passes the empty-check
    inViewFilter.where_clause().elements().push_back(
      make_operator_element(ua::FilterOperator::InView, ua::NodeId{ua::ObjectId::Server}));
    EventSubscription subscription;
    subscription.notifier = notifier;
    subscription.requestDedicatedBackbone =
      true;  // its own backbone -> its own CreateMonitoredItems on the wire
    subscription.filter = std::move(inViewFilter);

    const auto result = fixture.subscribe(std::move(subscription), [](EventNotification) {});

    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadFilterOperatorInvalid});
    ASSERT_TRUE(result.shared_detail());
    EXPECT_EQ(result.shared_detail()->source, "client.tier2.event_subscriber.invalid_where_operator");
    EXPECT_FALSE(wait_until([&] { return capture->create_count() != createsBefore; }, 500ms))
      << "a locally rejected InView filter must emit no CreateMonitoredItems request";
  }
}

// Row - NullAndStatusFieldsPreserved  (MisbehavingServer)
// A decoded event must preserve the three-state distinction: an ABSENT (null / empty Variant) selected field
// surfaces as nullopt, and a StatusCode-carrying Variant surfaces as a Variant (NOT collapsed to null), so
// the unavailability reason is not lost. decode_notification maps `Variant::empty() ? nullopt :
// Variant{value}` positionally. [neg: null vs status-only vs value distinction] CALIBRATION: driven through
// on_publish_events_async on the real subscriber - the production pipeline does not route
// EventNotificationList to the subscriber (CALIBRATION note 2).
// @verifies CL-MI-017
// @relation(CL-MI-017, scope=function)
TEST_F(ClientMonitorEventFilter, NullAndStatusFieldsPreserved)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto backboneId = arm_backbone_id_capture(server);

  // Subscribe with two EXTRA SelectClauses (slots 8 and 9 of the composite): "NullProp" and "StatusProp".
  // No WhereClause -> the consumer is match-all, so a BaseEventType event matches.
  ua::EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("NullProp"));
  filter.select_clauses().push_back(make_select_clause("StatusProp"));
  EventSubscription subscription;
  subscription.notifier = notifier;
  subscription.filter = std::move(filter);

  auto sink = std::make_shared<EventNotificationSink>();
  const auto subscribed = fixture.subscribe(
    std::move(subscription), [sink](EventNotification event) { sink->push(std::move(event)); });
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_NE(backboneId->load(), 0u) << "the backbone client handle must have been captured";

  // Composite SelectClauses = 8 mandatory + [NullProp, StatusProp] = 10. Slot 8 = null (empty Variant),
  // slot 9 = a StatusCode-carrying Variant (unavailable field).
  const std::vector<ua::Variant> extras{ua::Variant{}, ua::Variant{ua::StatusCode{ua::Status::BadNoData}}};
  fixture.feed_events(backboneId->load(),
    {make_event_fields(backboneId->load(),
      ua::Variant{ua::ByteString{0x01, 0x02, 0x03}},
      ua::NodeId{ua::ObjectTypeId::BaseEventType},
      extras)});

  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; })) << "the event must be delivered to the consumer";
  const auto events = sink->snapshot();
  ASSERT_EQ(events.size(), 1u);
  const EventNotification& event = events.front();
  ASSERT_EQ(event.fields.size(), 10u) << "all 10 composite SelectClause slots must be present positionally";

  EXPECT_FALSE(event.fields[8].has_value())
    << "an absent (null / empty Variant) selected field must surface as nullopt";
  ASSERT_TRUE(event.fields[9].has_value())
    << "a StatusCode-carrying field must NOT be collapsed to null (the three-state distinction is preserved)";
  ASSERT_TRUE(event.fields[9]->is_status_code())
    << "the status-only field must surface as a StatusCode Variant, carrying the unavailability reason";
  // Read the raw held StatusCode directly. NOTE: Variant::to<StatusCode>() on a Variant holding a BAD
  // StatusCode yields a BAD Result (the held code becomes the Result's status, no value), so the exact-value
  // check must go through the raw as<>() accessor, not to<>().
  EXPECT_EQ(event.fields[9]->as<ua::StatusCode>(), ua::StatusCode{ua::Status::BadNoData})
    << "the exact StatusCode must survive verbatim to the user";
}

// Row - RealInboundPublishRoutesEventToConsumer  (MisbehavingServer)
// The end-to-end confirmation that the inbound event delivery hop IS wired into the production Publish
// pipeline (CALIBRATION note 2, now closed) - i.e. that a decoded event actually REACHES the user callback
// through the real wire path. This closes the required gap the CL-MI-017 audit named ("delivery is
// unwired - on_publish_events_async has no production caller"): the decode logic was correct but unreachable.
// Unlike the decode-CONTENT rows (NullAndStatusFieldsPreserved / MissingEventId), which drive
// on_publish_events_async directly for deterministic field shaping, this row injects a real
// EventNotificationList into an outgoing PublishResponse via the response mutator and lets the always-on
// Publish pump carry it in: feed_publish_response must dynamic_cast the EventNotificationList, group its
// EventFieldLists by client_handle, and route them to the co-owned EventSubscriberImpl, which decodes and
// dispatches to the consumer callback. If the wire branch were missing (the pre-fix state), the event would
// never reach the sink and this row would time out. [neg: EventNotificationList silently dropped at the
// Publish decode site]
// @verifies CL-MI-017
// @relation(CL-MI-017, scope=function)
TEST_F(ClientMonitorEventFilter, RealInboundPublishRoutesEventToConsumer)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto backboneId = arm_backbone_id_capture(server);

  // Match-all consumer (two extra SelectClauses, NO WhereClause) so a BaseEventType event delivered on the
  // backbone matches. The composite SelectClauses are the 8 mandatory + these 2 = 10, so the injected event
  // must carry 10 fields (make_event_fields with 2 extras below) to avoid a field-count drop.
  ua::EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("ProbeA"));
  filter.select_clauses().push_back(make_select_clause("ProbeB"));
  EventSubscription subscription;
  subscription.notifier = notifier;
  subscription.filter = std::move(filter);

  auto sink = std::make_shared<EventNotificationSink>();
  const auto subscribed = fixture.subscribe(
    std::move(subscription), [sink](EventNotification event) { sink->push(std::move(event)); });
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_NE(backboneId->load(), 0u) << "the backbone client handle must have been captured from the wire";

  // Now inject a real inbound event on every Publish the pump receives. The sequence is rewritten
  // monotonically so each injected Publish is InOrder; the fields carry the captured backbone client_handle
  // so the demux routes them to this consumer.
  const std::uint32_t backboneHandle = backboneId->load();
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  const ua::ByteString eventId{0xAB, 0xCD, 0xEF};
  const std::vector<ua::Variant> extras{ua::Variant{ua::String{"a"}}, ua::Variant{ua::String{"b"}}};
  server.set_response_mutator(
    [sequenceNumber, backboneHandle, eventId, extras](Response& response)
    {
      auto* publish = as_publish(response);
      if (publish == nullptr)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_event_notification(*publish,
        make_event_fields(
          backboneHandle, ua::Variant{eventId}, ua::NodeId{ua::ObjectTypeId::BaseEventType}, extras));
    });

  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "a real inbound Publish carrying an EventNotificationList must reach the consumer through "
       "feed_publish_response - the wire demux hop is wired";
  const auto events = sink->snapshot();
  ASSERT_GE(events.size(), 1u);
  const EventNotification& event = events.front();
  EXPECT_EQ(event.eventTypeId, ua::NodeId{ua::ObjectTypeId::BaseEventType})
    << "the event decoded off the real Publish must carry the BaseEventType EventType from slot 1";
  ASSERT_EQ(event.fields.size(), 10u) << "all 10 composite SelectClause slots must be present";
  ASSERT_TRUE(event.fields[0].has_value()) << "the EventId (slot 0) must survive the wire round-trip";
  EXPECT_EQ(event.fields[0]->as<ua::ByteString>(), eventId)
    << "the injected EventId must reach the consumer byte-exact through the real demux path";
}

// Row - PerClauseBadResultEmitsAdvisory  (MisbehavingServer)
// The matrix injects a Create response whose EventFilterResult carries one selectClauseResult=Bad and proves
// the public tier-2 observer receives its clause index and StatusCode while the otherwise successful
// subscription remains usable. [neg: per-clause filter diagnostic]
// @verifies CL-MI-018
// @relation(CL-MI-018, scope=function)
TEST_F(ClientMonitorEventFilter, PerClauseBadResultEmitsAdvisory)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto advisory = std::make_shared<AdvisoryCountingObserver>();
  fixture.install_advisory_observer(advisory);
  const std::size_t advisoriesBefore = advisory->count();

  // Inject a per-clause bad EventFilterResult onto the real event CreateMonitoredItems response.
  arm_backbone_id_capture(server,
    [](ua::CreateMonitoredItemsResponse& create)
    {
      auto filterResult = std::make_unique<ua::EventFilterResult>();
      filterResult->select_clause_results().push_back(ua::StatusCode{ua::Status::Good});
      filterResult->select_clause_results().push_back(ua::StatusCode{ua::Status::BadTypeDefinitionInvalid});
      create.results()[0].filter_result().inner_unique_ptr() = std::move(filterResult);
    });

  EventSubscription subscription;
  subscription.notifier = notifier;
  const auto subscribed = fixture.subscribe(std::move(subscription), [](EventNotification) {});

  ASSERT_TRUE(subscribed.is_good())
    << "filter diagnostics are advisory and must not replace the successful monitored-item result";
  ASSERT_TRUE(wait_until([&] { return advisory->count() > advisoriesBefore; }, 2s));
  ASSERT_EQ(advisory->count(), advisoriesBefore + 1);
  const auto detail = advisory->last_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->source, "client.tier2.event_subscriber.event_filter_result");
  EXPECT_EQ(detail->innerStatus, ua::StatusCode{ua::Status::BadTypeDefinitionInvalid}.value());
  ASSERT_EQ(detail->context.size(), 2u);
  EXPECT_EQ(detail->context[0].key, ua::ContextKeys::fieldName.value());
  EXPECT_EQ(detail->context[0].value, "selectClauseResults");
  EXPECT_EQ(detail->context[1].key, ua::ContextKeys::operationIndex.value());
  EXPECT_EQ(detail->context[1].value, "1");
}

// Row - MissingEventIdEmitsAdvisoryNotDispatched  (MisbehavingServer)
// An event whose mandatory EventId is null must be DROPPED with an advisory (so downstream ack / condition
// logic keyed on EventId can never break on a repaired-to-empty EventId). This asserts the REAL, now-built
// behavior (Slice EV1, CL-EVT-001): decode_notification enforces the four normatively-guaranteed
// BaseEventType fields (EventId, EventType, Time, ReceiveTime - Part 5 section 6.4.2 "shall always be
// returned as value"); a missing / status-coded one drops the event and fires
// ClientObserver::on_advisory_diagnostic. Driven through the REAL inbound-publish interface (the same
// set_response_mutator path RealInboundPublishRoutesEventToConsumer uses) - the injected
// EventNotificationList is carried in by the always-on Publish pump and decoded on the production path, so
// this row exercises the wired end-to-end drop, not a direct decode call. [neg: malformed mandatory field]
// @verifies CL-EVT-001
// @verifies CL-EVT-002
// @relation(CL-EVT-001, CL-EVT-002, scope=function)
TEST_F(ClientMonitorEventFilter, MissingEventIdEmitsAdvisoryNotDispatched)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto backboneId = arm_backbone_id_capture(server);

  auto advisory = std::make_shared<AdvisoryCountingObserver>();
  fixture.install_advisory_observer(advisory);
  const std::size_t advisoriesBefore = advisory->count();

  // Match-all subscribe (composite = 8 mandatory SelectClauses, empty WhereClause) - no extra SelectClauses,
  // so an 8-field make_event_fields event matches the composite exactly (no field-count drop).
  auto sink = std::make_shared<EventNotificationSink>();
  EventSubscription subscription;
  subscription.notifier = notifier;
  const auto subscribed = fixture.subscribe(
    std::move(subscription), [sink](EventNotification event) { sink->push(std::move(event)); });
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_NE(backboneId->load(), 0u);

  // Inject, on every Publish the pump receives, a real inbound event whose EventId (slot 0) is null (empty
  // Variant) but whose EventType (slot 1) is valid. The sequence is rewritten monotonically so each injected
  // Publish is InOrder; the fields carry the captured backbone client_handle so the demux routes them here.
  const std::uint32_t backboneHandle = backboneId->load();
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [sequenceNumber, backboneHandle](Response& response)
    {
      auto* publish = as_publish(response);
      if (publish == nullptr)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_event_notification(*publish,
        make_event_fields(backboneHandle, ua::Variant{}, ua::NodeId{ua::ObjectTypeId::BaseEventType}));
    });

  // REAL BEHAVIOR (Slice EV1): the null-EventId event is DROPPED on the production decode path and surfaces
  // an advisory. Waiting for the advisory is the positive signal the event was processed-and-dropped.
  ASSERT_TRUE(wait_until([&] { return advisory->count() > advisoriesBefore; }))
    << "a null-EventId event must surface on_advisory_diagnostic (the malformed mandatory field is not "
       "silently dropped) - CL-EVT-001";
  EXPECT_EQ(sink->size(), 0u)
    << "a null-EventId event must NOT be dispatched to the consumer callback (dropped as malformed) - "
       "CL-EVT-001";
}

// =============================================================================================
// ClientMonitorEvent
// =============================================================================================
// Row - TargetsEventNotifierAttribute  (MisbehavingServer)
// An event monitor must target the EventNotifier attribute of its notifier node - never Value (which would
// draw Bad_AttributeIdInvalid and starve the monitor). create_event_monitored_item forces
// itemToMonitor.attributeId = EventNotifier at the wire boundary. [neg: attributeId auto-set to
// EventNotifier]
// @verifies CL-MI-014
// @relation(CL-MI-014, scope=function)
TEST(ClientMonitorEvent, TargetsEventNotifierAttribute)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  EventSubscription subscription;
  subscription.notifier = notifier;
  const auto subscribed = fixture.subscribe(std::move(subscription), [](EventNotification) {});
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->create_count() >= 1; }));

  EXPECT_EQ(capture->last_attribute_id(), static_cast<std::uint32_t>(ua::AttributeId::EventNotifier))
    << "the event MI must monitor the EventNotifier attribute (id 12), not Value";
  EXPECT_EQ(capture->last_node_id(), notifier) << "the event MI must target the notifier node (Server)";
}

// Row - ForcesSamplingIntervalZero  (MisbehavingServer)
// An event monitor's wire samplingInterval must be 0 regardless of any requested cadence (a nonzero value can
// make a server reject or mis-sample an event monitor). create_event_monitored_item hardcodes
// samplingInterval = 0.0. [neg: positive and negative user input both forced to 0]
// CALIBRATION: the BUILT EventSubscriber path exposes NO user event-samplingInterval knob at all
// (EventSubscription has no such field and Subscription::monitor_event is deferred), so 0 on the wire is
// structural - there is no user value to clamp. The matrix's "user passes 250 / -1" is not expressible.
// @verifies CL-MI-013
// @relation(CL-MI-013, scope=function)
TEST(ClientMonitorEvent, ForcesSamplingIntervalZero)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  EventSubscription subscription;
  subscription.notifier = notifier;
  const auto subscribed = fixture.subscribe(std::move(subscription), [](EventNotification) {});
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->create_count() >= 1; }));

  EXPECT_EQ(capture->last_sampling_interval(), 0.0)
    << "the event MI must carry samplingInterval == 0 on the wire (forced at the wire boundary, CL-MI-013)";
}

// Row - QueueOverflowDispatchedToCallbackAndAdvisory  (MisbehavingServer)
// An injected EventQueueOverflowEventType event must (a) reach the public user callback unchanged and (b)
// fire on_advisory_diagnostic so operators learn events were lost. [neg: overflow event is data, not error]
// @verifies CL-MI-015
// @relation(CL-MI-015, scope=function)
TEST(ClientMonitorEvent, QueueOverflowDispatchedToCallbackAndAdvisory)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto backboneId = arm_backbone_id_capture(server);

  auto advisory = std::make_shared<AdvisoryCountingObserver>();
  fixture.install_advisory_observer(advisory);
  const std::size_t advisoriesBefore = advisory->count();

  auto sink = std::make_shared<EventNotificationSink>();
  EventSubscription subscription;  // match-all -> receives every event type, including the overflow synthetic
  subscription.notifier = notifier;
  const auto subscribed = fixture.subscribe(
    std::move(subscription), [sink](EventNotification event) { sink->push(std::move(event)); });
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_NE(backboneId->load(), 0u);

  const ua::NodeId overflowType{ua::ObjectTypeId::EventQueueOverflowEventType};
  fixture.feed_events(backboneId->load(),
    {make_event_fields(backboneId->load(), ua::Variant{ua::ByteString{0x09}}, overflowType)});

  // REAL BEHAVIOR (calibrated): the overflow event is delivered to the callback as ordinary event data.
  ASSERT_TRUE(wait_until([&] { return sink->count_of_type(overflowType) >= 1; }))
    << "the EventQueueOverflowEventType event must reach the user callback (data, not filtered out)";
  EXPECT_EQ(sink->count_of_type(overflowType), 1u)
    << "the overflow event is delivered exactly once (no drop)";

  ASSERT_TRUE(wait_until([&] { return advisory->count() == advisoriesBefore + 1; }))
    << "the overflow loss signal must also reach the public advisory observer";
  EXPECT_EQ(advisory->last_source(), "client.tier2.event_subscriber.queue_overflow");
}

namespace
{

// ---------------------------------------------------------------------------------------------
// Pairs the composite EventFilter the client put on the wire with the EventFilterResult the REAL server
// produced for it, so a test can read the server's `selectClauseResults` directly rather than through the
// client's advisory projection. Written on the server strand (request observer + response mutator), read by
// the test thread; guarded by a mutex.
// ---------------------------------------------------------------------------------------------
struct EventFilterResultCapture
{
  mutable std::mutex mutex;

  std::size_t createRequests = 0;
  std::size_t createResponses = 0;
  std::optional<ua::EventFilter> requestFilter;
  bool sawFilterResult = false;
  std::vector<ua::StatusCode> selectResults;
  ua::StatusCode createStatus{ua::Status::BadInternalError};

  void observe_request(const ua::Structure& request)
  {
    const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
    if (create == nullptr || create->items_to_create().size() < 1)
    {
      return;
    }
    const auto& params = create->items_to_create()[0].requested_parameters();
    if (!params.filter())
    {
      return;
    }
    const auto* filter = dynamic_cast<const ua::EventFilter*>(params.filter().get());
    if (filter == nullptr)
    {
      return;
    }
    std::lock_guard lock(mutex);
    ++createRequests;
    requestFilter = *filter;
  }

  void observe_response(ua::CreateMonitoredItemsResponse& response)
  {
    if (response.results().size() < 1)
    {
      return;
    }
    auto& result = response.results()[0];
    const auto* filterResult = dynamic_cast<const ua::EventFilterResult*>(result.filter_result().get());

    std::lock_guard lock(mutex);
    ++createResponses;
    createStatus = result.status_code();
    sawFilterResult = filterResult != nullptr;
    selectResults.clear();
    if (filterResult != nullptr)
    {
      const auto& statuses = filterResult->select_clause_results();
      for (std::size_t i = 0; i < statuses.size(); ++i)
      {
        selectResults.push_back(statuses[i]);
      }
    }
  }

  std::size_t create_requests() const
  {
    std::lock_guard lock(mutex);
    return createRequests;
  }

  std::size_t create_responses() const
  {
    std::lock_guard lock(mutex);
    return createResponses;
  }

  std::optional<ua::EventFilter> request_filter() const
  {
    std::lock_guard lock(mutex);
    return requestFilter;
  }

  bool saw_filter_result() const
  {
    std::lock_guard lock(mutex);
    return sawFilterResult;
  }

  std::vector<ua::StatusCode> select_clause_results() const
  {
    std::lock_guard lock(mutex);
    return selectResults;
  }

  ua::StatusCode create_status() const
  {
    std::lock_guard lock(mutex);
    return createStatus;
  }
};

// Arms both halves of the pairing on the MisbehavingServer: the DECODED event CreateMonitoredItems request
// and the server's own CreateMonitoredItems response (read, not mutated).
std::shared_ptr<EventFilterResultCapture> arm_filter_result_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<EventFilterResultCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe_request(request); });
  server.set_response_mutator(
    [capture](Response& response)
    {
      if (auto* create = as_create_items(response))
      {
        capture->observe_response(*create);
      }
    });
  return capture;
}

}  // namespace

// Part 4 section 7.22.3: "The Server shall not report errors that might occur depending on the state or the
// Server or type of Event." Filter compilation may only reject what is wrong for EVERY possible Event. A
// SelectClause naming "ActiveState" (a Mandatory component of AlarmConditionType, absent from BaseEventType
// and from every non-alarm subtype) is precisely the type-dependent case: whether it resolves depends on
// which Event arrives. The plausible implementation that gets this wrong resolves each SelectClause browse
// path against its typeDefinitionId while compiling the filter and stamps the clause Bad_NodeIdUnknown /
// Bad_BrowseNameInvalid - rejecting a filter that is correct for the subtypes that will actually be
// delivered, and rejecting it at create time, so the Client never sees the Events that would have matched.
// The absence is a per-Event observation instead: the clause keeps its slot and the field arrives empty.
// @relation(AC-SVR-MI-EVT-009-NO-STATE-ERRORS, scope=function)
TEST_F(ClientMonitorEventFilter, TypeDependentSelectClauseIsNotReportedAsAFilterError)
{
  MisbehavingServer server;
  MisbehavingEventFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_filter_result_capture(server);

  // The field some Event types carry and others do not. Kept as a string_view so the wire-side lookup below
  // matches the clause by the very name that was requested.
  constexpr std::string_view typeDependentField{"ActiveState"};

  ua::EventFilter filter;
  filter.select_clauses().push_back(make_select_clause(typeDependentField));
  EventSubscription subscription;
  subscription.notifier = notifier;
  subscription.filter = std::move(filter);

  auto sink = std::make_shared<EventNotificationSink>();
  const auto subscribed = fixture.subscribe(
    std::move(subscription), [sink](EventNotification event) { sink->push(std::move(event)); });
  ASSERT_TRUE(subscribed.is_good()) << to_string(subscribed.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->create_responses() >= 1; }))
    << "the event CreateMonitoredItems must have reached the real server and been answered";

  // The clause must actually be on the wire, at a known index, or nothing below is a real observation.
  const auto composite = capture->request_filter();
  ASSERT_TRUE(composite.has_value()) << "the event CreateMonitoredItems must carry an EventFilter";
  ASSERT_GT(composite->select_clauses().size(), 0u) << "the composite must carry SelectClauses";
  std::optional<std::size_t> probeIndex;
  for (std::size_t i = 0; i < composite->select_clauses().size(); ++i)
  {
    const auto& clause = composite->select_clauses()[i];
    if (clause.browse_path().size() == 1 &&
        static_cast<std::string_view>(clause.browse_path()[0].name()) == typeDependentField)
    {
      probeIndex = i;
      break;
    }
  }
  ASSERT_TRUE(probeIndex.has_value())
    << "the type-dependent SelectClause must be present in the composite the server compiled - otherwise "
       "the server was never asked the question this row poses";
  EXPECT_EQ(capture->create_requests(), 1u) << "exactly one event create is expected in this window";
  EXPECT_EQ(capture->create_responses(), 1u)
    << "the captured EventFilterResult must belong to the create that carried the probe clause";

  // (1) The MonitoredItem itself must be created: a type-dependent clause is not a filter failure.
  EXPECT_TRUE(capture->create_status().is_good())
    << "a SelectClause whose resolvability depends on the Event type must not fail the MonitoredItem "
       "create: "
    << to_string(capture->create_status());

  // (2) selectClauseResults must report NO error for that clause (the prohibition itself).
  ASSERT_TRUE(capture->saw_filter_result())
    << "the event create must return an EventFilterResult, else there is no selectClauseResults to inspect";
  const auto results = capture->select_clause_results();
  ASSERT_EQ(results.size(), composite->select_clauses().size())
    << "selectClauseResults must carry one status per requested SelectClause";
  ASSERT_LT(*probeIndex, results.size());
  EXPECT_TRUE(results[*probeIndex].is_good()) << "Part 4 section 7.22.3: a SelectClause that only some Event "
                                                 "types can satisfy must not be reported as an "
                                                 "error at filter-compile time; got "
                                              << to_string(results[*probeIndex]);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_TRUE(results[i].is_good())
      << "no clause of a structurally valid composite may be reported bad - selectClauseResults[" << i
      << "] = " << to_string(results[i]);
  }

  // (3) The absence is a PER-EVENT observation instead: emit a real BaseEventType event, which does not
  // carry ActiveState, through the server and Publish pipeline. Driving the decoded demux interface directly
  // would assume the very server-side filter evaluation and wire encoding this server criterion requires.
  ua::GenericEvent event{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
  event.sourceNode = notifier;
  event.sourceName = "TypeDependentSelectClause";
  event.message = ua::LocalizedText{"", "Base event without ActiveState"};
  event.severity = 100;
  server.server().emit_event(event);

  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "the accepted MonitoredItem must keep delivering Events that do not carry the type-dependent field";
  const auto delivered = sink->snapshot();
  ASSERT_EQ(delivered.size(), 1u);
  ASSERT_EQ(delivered.front().fields.size(), composite->select_clauses().size())
    << "the clause keeps its positional slot even for an Event type that cannot supply it";
  EXPECT_FALSE(delivered.front().fields[*probeIndex].has_value())
    << "the missing field is reported per Event as an absent value - not as a create-time SelectClause error";
}
